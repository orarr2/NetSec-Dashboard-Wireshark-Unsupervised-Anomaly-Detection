#!/usr/bin/env bash
# =============================================================================
#  NetSec Analyzer VM - one-shot bootstrap
# =============================================================================
# Turns a fresh Ubuntu 22.04+ box (x86_64 or ARM64) into a running analyzer.
# Assumes:
#   - the box has internet access,
#   - you can sudo (any user, not just ubuntu),
#   - Tailscale is EITHER installed with `tailscale login` already done, OR
#     you have a Tailscale auth key from https://login.tailscale.com/admin/settings/keys
#
# What it does (skips whatever is already in place):
#   1. apt update + install curl, git, chrony (NTP), jq
#   2. install Docker Engine + docker compose plugin
#   3. install Tailscale + `tailscale up` (auth key or interactive)
#   4. clone the repo into ~/netsec (or update it in place)
#   5. write ./deploy/.env from prompts (only asks for missing values)
#   6. write ./deploy/rules.v4 iptables + enable netfilter-persistent so
#      only SSH (22) is public - everything else Tailscale-only
#   7. docker compose build + up
#   8. run deploy/create_sensor.py to print sensor credentials once
#   9. print healthz + next steps
#
# Safe to re-run: every step is idempotent.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/orarr2/NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/main/deploy/bootstrap.sh | bash
#   # or, after clone:
#   bash ~/netsec/deploy/bootstrap.sh
# =============================================================================

set -euo pipefail

# ---------- colour helpers ---------------------------------------------------
if [ -t 1 ]; then
    _B=$(printf '\033[1m'); _R=$(printf '\033[0m')
    _G=$(printf '\033[32m'); _Y=$(printf '\033[33m'); _RE=$(printf '\033[31m')
else
    _B=""; _R=""; _G=""; _Y=""; _RE=""
fi
say() { echo "${_B}${_G}==>${_R} $*"; }
warn() { echo "${_Y}[warn]${_R} $*" >&2; }
die() { echo "${_RE}[fatal]${_R} $*" >&2; exit 1; }

# ---------- config -----------------------------------------------------------
REPO_URL="${NETSEC_REPO_URL:-https://github.com/orarr2/NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection.git}"
REPO_DIR="${NETSEC_REPO_DIR:-$HOME/netsec}"
BRANCH="${NETSEC_BRANCH:-main}"

# ---------- pre-flight -------------------------------------------------------
say "pre-flight"
if ! grep -qE 'ID=(ubuntu|debian)' /etc/os-release 2>/dev/null; then
    warn "this script targets Ubuntu/Debian; other distros may need tweaks"
fi
if ! sudo -n true 2>/dev/null; then
    die "sudo required (run: sudo -v && bash $0)"
fi

# ---------- 1. apt basics ----------------------------------------------------
say "installing baseline apt packages"
sudo apt-get update -qq
sudo apt-get install -y -q \
    curl git jq chrony netfilter-persistent iptables-persistent

# NTP - required by the HMAC replay-window check on ingest_api.
sudo systemctl enable --now chrony >/dev/null 2>&1 || true

# ---------- 2. Docker Engine -------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    say "installing Docker Engine (official convenience script)"
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
    warn "you were added to the docker group - log out + back in later so"
    warn "you can run docker without sudo. For now this script uses sudo."
    DOCKER="sudo docker"
else
    say "docker present ($(docker --version))"
    if docker ps >/dev/null 2>&1; then
        DOCKER="docker"
    else
        DOCKER="sudo docker"
    fi
fi

if ! $DOCKER compose version >/dev/null 2>&1; then
    say "installing docker compose plugin"
    sudo apt-get install -y -q docker-compose-plugin
fi

# ---------- 3. Tailscale -----------------------------------------------------
if ! command -v tailscale >/dev/null 2>&1; then
    say "installing Tailscale"
    curl -fsSL https://tailscale.com/install.sh | sudo sh
fi

if ! sudo tailscale status >/dev/null 2>&1; then
    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        say "joining tailnet with TAILSCALE_AUTHKEY"
        sudo tailscale up --authkey="${TAILSCALE_AUTHKEY}" \
            --hostname="${TAILSCALE_HOSTNAME:-netsec-agent}"
    else
        warn "Tailscale is installed but not logged in"
        warn "run this and re-run the script:"
        echo   "  sudo tailscale up --hostname=netsec-agent"
        echo   "or set TAILSCALE_AUTHKEY=tskey-auth-... and re-run"
        die "Tailscale must be up before we bind services to its IP"
    fi
fi

TS_IP=$(sudo tailscale ip -4 | head -1)
if [ -z "$TS_IP" ]; then
    die "could not resolve Tailscale IPv4 - is tailscale up?"
fi
say "Tailscale IP: $TS_IP"

# ---------- 4. clone or update repo ------------------------------------------
if [ ! -d "$REPO_DIR/.git" ]; then
    say "cloning repo into $REPO_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
else
    say "updating existing checkout in $REPO_DIR"
    git -C "$REPO_DIR" fetch origin "$BRANCH" --depth 1
    git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
fi
cd "$REPO_DIR/deploy"

# ---------- 5. .env fill from prompts ----------------------------------------
if [ ! -f .env ]; then
    say "writing fresh .env from .env.example"
    cp .env.example .env
fi

# Bind services to Tailscale IP so nothing listens on 0.0.0.0.
python3 - "$TS_IP" <<'PY'
import re, sys, pathlib, secrets
p = pathlib.Path(".env")
txt = p.read_text()
ts_ip = sys.argv[1]

def _set(key, val):
    global txt
    pat = re.compile(rf"^{re.escape(key)}=.*$", re.M)
    if pat.search(txt):
        txt = pat.sub(f"{key}={val}", txt)
    else:
        txt += f"\n{key}={val}\n"

_set("TS_BIND", ts_ip)
_set("NETSEC_DATA_ROOT", "/srv/netsec")
_set("NETSEC_INFRA_DSTS", ts_ip)
_set("NETSEC_INGEST_URL", f"http://{ts_ip}:8766")

# Random n8n encryption key if missing
if not re.search(r"^N8N_ENCRYPTION_KEY=.+$", txt, re.M):
    _set("N8N_ENCRYPTION_KEY", secrets.token_hex(32))

p.write_text(txt)
print("wrote .env: TS_BIND, NETSEC_DATA_ROOT, NETSEC_INFRA_DSTS,"
      " NETSEC_INGEST_URL, N8N_ENCRYPTION_KEY")
PY

# Optional prompts - only ask for keys the user has not already set.
_prompt() {
    # $1 = env key, $2 = human prompt, $3 = optional default
    local key="$1" prompt="$2" default="${3:-}"
    local current=$(grep -E "^${key}=" .env | cut -d= -f2- || true)
    if [ -n "$current" ] && [ "$current" != "" ]; then
        say "$key already set (skipping prompt)"
        return
    fi
    if [ ! -t 0 ]; then
        return  # non-interactive; leave blank
    fi
    read -rp "  ${prompt}${default:+ [$default]}: " val
    val="${val:-$default}"
    if [ -n "$val" ]; then
        python3 -c "
import re, pathlib
p = pathlib.Path('.env')
t = p.read_text()
pat = re.compile(r'^${key}=.*\$', re.M)
if pat.search(t): t = pat.sub('${key}=' + '''$val''', t)
else: t += '\n${key}=' + '''$val''' + '\n'
p.write_text(t)
"
    fi
}

echo
say "optional config (press Enter to skip - anything you set later in .env still wins):"
_prompt "GROQ_API_KEY" "Groq API key (free tier - https://console.groq.com/keys)"
_prompt "OPENAI_COMPAT_API_KEY" "OpenAI-compat key (usually same as GROQ_API_KEY)"
_prompt "SMTP_USER" "Gmail address for the report emails"
_prompt "SMTP_PASS" "Gmail app-password (16 chars) - myaccount.google.com/apppasswords"
_prompt "SMTP_FROM" "From: header (defaults to SMTP_USER)"

# Fill OPENAI_COMPAT_API_KEY from GROQ_API_KEY if only one was given.
python3 - <<'PY'
import re, pathlib
p = pathlib.Path(".env")
txt = p.read_text()
groq = re.search(r"^GROQ_API_KEY=(.+)$", txt, re.M)
compat = re.search(r"^OPENAI_COMPAT_API_KEY=(.*)$", txt, re.M)
if groq and (not compat or not compat.group(1).strip()):
    if compat:
        txt = re.sub(r"^OPENAI_COMPAT_API_KEY=.*$",
                     f"OPENAI_COMPAT_API_KEY={groq.group(1)}", txt, flags=re.M)
    else:
        txt += f"\nOPENAI_COMPAT_API_KEY={groq.group(1)}\n"
    p.write_text(txt)
    print("mirrored GROQ_API_KEY into OPENAI_COMPAT_API_KEY")
PY

# ---------- 6. iptables: only 22 (SSH) public, everything else Tailscale-only
say "applying iptables rules (SSH + Tailscale only)"
sudo tee /etc/iptables/rules.v4 >/dev/null <<'IPT'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p udp -m udp --dport 41641 -j ACCEPT
-A INPUT -i tailscale0 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
IPT
sudo netfilter-persistent reload
sudo systemctl enable netfilter-persistent >/dev/null 2>&1 || true

# Match minimal IPv6 stance - drop everything not related/established or on tailscale0
sudo tee /etc/iptables/rules.v6 >/dev/null <<'IPT6'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -i tailscale0 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
IPT6
sudo netfilter-persistent reload

# ---------- 7. data directory ------------------------------------------------
sudo mkdir -p /srv/netsec/{data,db,reports,spool}
sudo chown -R "$USER:$USER" /srv/netsec

# ---------- 8. build + start ------------------------------------------------
say "docker compose build (first run pulls torch/tshark - ~15 min on ARM)"
$DOCKER compose build ingest_api worker retention

say "docker compose up -d"
$DOCKER compose up -d ingest_api worker retention

# ---------- 9. create sensor -------------------------------------------------
SENSOR_NAME="${NETSEC_SENSOR_NAME:-laptop}"
say "creating sensor '$SENSOR_NAME' (credentials printed ONCE - save them)"
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py "$SENSOR_NAME" || \
    warn "sensor may already exist - that is fine; use its saved credentials"

# ---------- 10. smoke test ---------------------------------------------------
sleep 3
say "healthz probe"
if curl -sS --max-time 5 "http://${TS_IP}:8766/healthz" | grep -q '"status":"ok"'; then
    echo "  ${_G}ingest API responds${_R}"
else
    warn "ingest API not answering on ${TS_IP}:8766 (check: sudo ss -tlnp | grep 8766)"
fi

say "done"
cat <<EOF

Next steps:
  1. From your laptop, join the same tailnet and set on that machine:
       NETSEC_INGEST_URL=http://${TS_IP}:8766
       NETSEC_SENSOR_ID=${SENSOR_NAME}
       NETSEC_SENSOR_SECRET=<the secret printed above>
     Then:
       python3 tools/upload_pcap.py capture.pcap --email you@example.com

  2. Watch a live analysis:
       ssh ${USER}@${TS_IP} 'cd ~/netsec/deploy && docker compose logs -f worker'

  3. Enable the LLM judge panel (edit .env, then force-recreate worker):
       cd ${REPO_DIR}/deploy
       nano .env       # set LLM_JUDGE_PANEL=openai_compat:llama-3.1-8b-instant,openai_compat:openai/gpt-oss-20b
       docker compose up -d --force-recreate worker

  4. Optional: install Ollama on this VM for zero-key local judges:
       docker compose up -d ollama
       docker exec deploy-ollama-1 ollama pull llama3.1:8b
       # then add ollama:llama3.1 to LLM_JUDGE_PANEL and force-recreate

  5. Ops cheat sheet: docs/VM_OPS.md
  6. Full Hebrew deep-dive: docs/VM_ARCHITECTURE_HE.md
  7. Bootstrap troubleshooting: docs/VM_BOOTSTRAP_HE.md
EOF

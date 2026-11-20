#!/usr/bin/env bash
# Install or update the NETSEC triage agents on the VM. Idempotent - re-runnable.
#
# Run as a sudo-capable user from a copy of the repository that holds
# agent/ and deploy/ (a checkout, or the output of `git archive`):
#
#     AGENT_COMMIT=<git sha> bash deploy/install-agent.sh
#
# What it does:
#   1. Creates the system user netsec-agent (no login, no home shell).
#   2. Creates /opt/netsec-agent/{repo,venv}, /etc/netsec-agent and
#      /var/lib/netsec-agent.
#   3. Copies the agent/ package into /opt/netsec-agent/repo (root-owned,
#      so the service cannot change its own code) and records the commit.
#   4. Builds the virtualenv from agent/requirements.txt.
#   5. Writes /etc/netsec-agent/env on the first run only.
#   6. Installs netsec-agent.service, enables it and (re)starts it.
#
# What it does NOT do: it does not touch Caddy. The /netsec/ route is in
# deploy/Caddyfile; applying it on the VM needs a restart of the Caddy
# container (its admin API is off), which is a separate, deliberate step.
set -euo pipefail

SRC_DIR="${SRC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APP_DIR=/opt/netsec-agent
ENV_FILE=/etc/netsec-agent/env
DATA_DIR=/var/lib/netsec-agent
SOURCE_DB="${NETSEC_SOURCE_DB:-/srv/netsec/db/netsec.db}"
NETSEC_ENV="${NETSEC_ENV:-/home/ubuntu/netsec/deploy/.env}"
PORT="${NETSEC_AGENT_PORT:-8010}"

[ -f "${SRC_DIR}/agent/api.py" ] || { echo "[agent] ${SRC_DIR} does not hold the agent/ package"; exit 1; }

# The apps of this stack bind the Tailscale address, and the same names are the private hosts.
TS_IP="${TS_IP:-$(tailscale ip -4 2>/dev/null | head -1)}"
[ -n "${TS_IP}" ] || { echo "[agent] no Tailscale IPv4 address found; set TS_IP"; exit 1; }
TS_FQDN="${TS_FQDN:-$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null || true)}"
SHORT_NAME="$(hostname -s)"

echo "[agent] system user and folders..."
if ! id netsec-agent >/dev/null 2>&1; then
    sudo useradd --system --home-dir "${DATA_DIR}" --no-create-home --shell /usr/sbin/nologin netsec-agent
fi
sudo mkdir -p "${APP_DIR}/repo" /etc/netsec-agent "${DATA_DIR}"
sudo chown netsec-agent:netsec-agent "${DATA_DIR}"
sudo chmod 750 "${DATA_DIR}"

echo "[agent] copying the agent package from ${SRC_DIR}..."
sudo rm -rf "${APP_DIR}/repo/agent"
sudo cp -r "${SRC_DIR}/agent" "${APP_DIR}/repo/agent"
sudo find "${APP_DIR}/repo/agent" -name __pycache__ -type d -prune -exec rm -rf {} +
COMMIT="${AGENT_COMMIT:-$(git -C "${SRC_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)}"
echo "${COMMIT}" | sudo tee "${APP_DIR}/repo/COMMIT" >/dev/null
sudo chown -R root:root "${APP_DIR}/repo"
sudo chmod -R a+rX "${APP_DIR}/repo"

echo "[agent] virtualenv and requirements..."
if [ ! -x "${APP_DIR}/venv/bin/python" ]; then
    python3 -m venv --help >/dev/null 2>&1 || sudo apt-get install -y python3-venv
    sudo python3 -m venv "${APP_DIR}/venv"
fi
sudo "${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
sudo "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/repo/agent/requirements.txt"

if [ ! -f "${ENV_FILE}" ]; then
    echo "[agent] writing ${ENV_FILE} (first run only)..."
    PRIVATE_HOSTS="127.0.0.1,localhost,${TS_IP},${SHORT_NAME}"
    [ -n "${TS_FQDN}" ] && PRIVATE_HOSTS="${PRIVATE_HOSTS},${TS_FQDN}"
    # The two asset settings are NETSEC's own; take the values the pipeline already runs with.
    MY_DEVICE_IP="$(sudo grep -E '^NETSEC_MY_DEVICE_IP=' "${NETSEC_ENV}" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    INFRA_DSTS="$(sudo grep -E '^NETSEC_INFRA_DSTS=' "${NETSEC_ENV}" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    sudo tee "${ENV_FILE}" >/dev/null <<EOF
# NETSEC triage agents. Edit and then: sudo systemctl restart netsec-agent.service
NETSEC_AGENT_BIND=${TS_IP}
NETSEC_AGENT_PORT=${PORT}
NETSEC_AGENT_DB_PATH=${DATA_DIR}/netsec-agent.db
NETSEC_AGENT_CHECKPOINT_PATH=${DATA_DIR}/checkpoints.sqlite
# Everything but /health answers only when the request's Host is one of these.
NETSEC_AGENT_PRIVATE_HOSTS=${PRIVATE_HOSTS}
# The poller reads NETSEC's database (read-only) and pulls the candidates of finished sessions.
NETSEC_AGENT_SOURCE_DB=${SOURCE_DB}
NETSEC_AGENT_POLL_SECONDS=30
NETSEC_AGENT_ASYNC_CONCURRENCY=2
# 0 = rule tree only. The model layer arrives in a later phase.
NETSEC_AGENT_USE_LIVE=0
WALL_CLOCK_CAP_SECONDS=360
# Clock shown in the trace lines.
NETSEC_AGENT_DISPLAY_TZ=Asia/Jerusalem
# The asset flags of the urgent preconditions, copied from ${NETSEC_ENV} at install time.
NETSEC_MY_DEVICE_IP=${MY_DEVICE_IP}
NETSEC_INFRA_DSTS=${INFRA_DSTS}
EOF
    sudo chown root:netsec-agent "${ENV_FILE}"
    sudo chmod 640 "${ENV_FILE}"
else
    echo "[agent] ${ENV_FILE} exists - left as it is"
fi

echo "[agent] installing the systemd unit..."
sudo cp "${SRC_DIR}/deploy/netsec-agent.service" /etc/systemd/system/netsec-agent.service
sudo systemctl daemon-reload
sudo systemctl enable netsec-agent.service >/dev/null 2>&1
sudo systemctl restart netsec-agent.service

echo ""
echo "[agent] done (commit ${COMMIT}). Check:"
echo "  systemctl status netsec-agent.service --no-pager | head -5"
echo "  curl -s http://${TS_IP}:${PORT}/health"
echo "  curl -s http://${TS_IP}:${PORT}/status | python3 -c 'import json,sys; print(\"\\n\".join(json.load(sys.stdin)[\"lines\"]))'"
echo "  journalctl -u netsec-agent.service -n 60 --no-pager"

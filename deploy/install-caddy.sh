#!/usr/bin/env bash
# Install Caddy (basicauth reverse proxy) + fail2ban on the VM.
# Idempotent - re-runnable. Expects credentials to be piped in via env:
#
#   BASIC_AUTH_USER=orpsp8 BASIC_AUTH_HASH='$2a$14$...' bash install-caddy.sh
#
# What it does:
#   1. Ensure /etc/default/netsec-caddy holds the creds (root-readable only).
#   2. `docker compose up -d caddy` (recreates n8n too, for N8N_PATH).
#   3. Install and enable fail2ban with a Caddy basic-auth jail.
set -euo pipefail

NETSEC_DIR="${NETSEC_DIR:-/home/ubuntu/netsec}"
DEPLOY_DIR="${NETSEC_DIR}/deploy"

if [ -z "${BASIC_AUTH_USER:-}" ] || [ -z "${BASIC_AUTH_HASH:-}" ]; then
  echo "[caddy] BASIC_AUTH_USER and BASIC_AUTH_HASH must be set." >&2
  echo "  Generate a hash with: docker run --rm caddy:2 caddy hash-password --plaintext '<your-password>'" >&2
  exit 1
fi

echo "[caddy] writing /etc/default/netsec-caddy (root-only)..."
sudo tee /etc/default/netsec-caddy >/dev/null <<EOF
BASIC_AUTH_USER=${BASIC_AUTH_USER}
BASIC_AUTH_HASH=${BASIC_AUTH_HASH}
EOF
sudo chmod 600 /etc/default/netsec-caddy
sudo chown root:root /etc/default/netsec-caddy

echo "[caddy] mirroring creds into deploy/.env (compose reads this)..."
# The compose file reads BASIC_AUTH_* from its adjacent .env. Rewrite
# those two lines in-place, preserving everything else.
#
# ONE gotcha: docker compose interpolates $VAR in .env values, and
# bcrypt hashes are FULL of $. Every literal $ must be doubled ($$)
# in the .env file so compose passes it through unchanged.
ENV="${DEPLOY_DIR}/.env"
HASH_ESCAPED="${BASIC_AUTH_HASH//\$/\$\$}"
sudo touch "${ENV}"
sudo chmod 600 "${ENV}"
if sudo grep -q "^BASIC_AUTH_USER=" "${ENV}"; then
    sudo sed -i "s|^BASIC_AUTH_USER=.*|BASIC_AUTH_USER=${BASIC_AUTH_USER}|" "${ENV}"
else
    echo "BASIC_AUTH_USER=${BASIC_AUTH_USER}" | sudo tee -a "${ENV}" >/dev/null
fi
if sudo grep -q "^BASIC_AUTH_HASH=" "${ENV}"; then
    sudo sed -i "s|^BASIC_AUTH_HASH=.*|BASIC_AUTH_HASH=${HASH_ESCAPED}|" "${ENV}"
else
    echo "BASIC_AUTH_HASH=${HASH_ESCAPED}" | sudo tee -a "${ENV}" >/dev/null
fi

echo "[caddy] docker compose up caddy..."
cd "${DEPLOY_DIR}"
sudo -E BASIC_AUTH_USER="${BASIC_AUTH_USER}" \
     BASIC_AUTH_HASH="${BASIC_AUTH_HASH}" \
     docker compose up -d caddy
sleep 4

echo "[caddy] fail2ban with a Caddy basicauth jail..."
sudo apt-get install -y fail2ban 2>&1 | tail -1
sudo tee /etc/fail2ban/filter.d/caddy-basicauth.conf >/dev/null <<'EOF'
# Match Caddy's console log line for a rejected basicauth attempt.
# Example line (all one line, wrapped for display):
#   {"level":"error","logger":"http.handlers.authentication",...,
#    "msg":"auth provider returned error","user_id":"","...,
#    "remote_ip":"1.2.3.4",...}
[Definition]
failregex = "remote_ip":"<HOST>".*"msg":"auth provider returned error"
            "remote_ip":"<HOST>".*"msg":"no auth provider matched"
ignoreregex =
EOF
sudo tee /etc/fail2ban/jail.d/caddy.conf >/dev/null <<'EOF'
[caddy-basicauth]
enabled  = true
filter   = caddy-basicauth
backend  = systemd
journalmatch = CONTAINER_NAME=deploy-caddy-1
maxretry = 5
findtime = 10m
bantime  = 1h
action   = iptables-allports[name=caddy]
EOF
sudo systemctl enable --now fail2ban
sudo systemctl reload fail2ban 2>/dev/null || sudo systemctl restart fail2ban
sleep 2
sudo fail2ban-client status caddy-basicauth 2>&1 | head -6

echo ""
echo "[caddy] done. Quick checks:"
echo "  # From the tailnet (accept the self-signed cert once):"
echo "  https://netsec-agent/         portal"
echo "  https://netsec-agent/rag/     RAG"
echo "  https://netsec-agent/chat/    Companion"
echo "  http://netsec-agent:5678      n8n (keeps its own owner-account login)"
echo "  # basicauth user: ${BASIC_AUTH_USER}"

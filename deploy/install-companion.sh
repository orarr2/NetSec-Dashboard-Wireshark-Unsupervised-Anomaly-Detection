#!/usr/bin/env bash
# Install the AI Companion on the VM as a systemd service.
# Idempotent - re-runnable.
#
# Prerequisites (same shape as install-rag.sh):
#   - repo at /home/ubuntu/netsec
#   - compose stack up; ollama exposed on 127.0.0.1:11434
#   - dash + dash_bootstrap_components installed in system python3
#
# What it does:
#   1. apt install python3-dash python3-flask (companion deps)
#   2. mkdir /srv/netsec/companion for the chats DB
#   3. Install /etc/default/netsec-companion for overrides
#   4. Install the systemd unit
#   5. Enable + start the service
set -euo pipefail

NETSEC_DIR="${NETSEC_DIR:-/home/ubuntu/netsec}"
DB_DIR="${DB_DIR:-/srv/netsec/companion}"
DEPLOY_DIR="${NETSEC_DIR}/deploy"

echo "[companion] setting up a dedicated venv (no system Python pollution)..."
# Dash pulls newer versions of stdlib-adjacent packages (typing_extensions,
# flask) that conflict with the apt-provided ones on Ubuntu 24.04.
# Isolate in /opt/netsec-companion/venv so the system python stays clean
# and the systemd unit points at THIS interpreter.
# tshark is needed so the file-drop feature can summarize .pcap uploads.
# pypdf + python-docx are the file-drop extractors for PDF and DOCX.
sudo apt-get install -y python3-venv tshark 2>&1 | tail -1
VENV=/opt/netsec-companion/venv
if [ ! -x "${VENV}/bin/python" ]; then
  sudo python3 -m venv "${VENV}"
fi
sudo "${VENV}/bin/pip" install --quiet --upgrade pip
sudo "${VENV}/bin/pip" install --quiet dash dash_bootstrap_components pypdf python-docx

echo "[companion] creating ${DB_DIR}..."
sudo mkdir -p "${DB_DIR}"
sudo chown -R ubuntu:ubuntu "${DB_DIR}"

echo "[companion] writing /etc/default/netsec-companion..."
sudo tee /etc/default/netsec-companion >/dev/null <<EOF
# Override any of the Companion defaults here. Restart with:
#   sudo systemctl restart netsec-companion.service
# NETSEC_OLLAMA_URL=http://127.0.0.1:11434
# NETSEC_COMPANION_DB=/srv/netsec/companion/chats.db
EOF

echo "[companion] installing systemd unit..."
sudo cp "${DEPLOY_DIR}/netsec-companion.service" /etc/systemd/system/
sudo systemctl daemon-reload

echo "[companion] enabling + starting..."
sudo systemctl enable --now netsec-companion.service
sleep 3

echo ""
echo "[companion] done. Quick checks:"
sudo systemctl status netsec-companion.service --no-pager 2>&1 | head -6
echo ""
echo "  # From the tailnet:"
echo "  open http://netsec-agent:5100  (or http://100.68.246.54:5100)"

#!/usr/bin/env bash
# Install the NetSec RAG service on the VM. Idempotent - re-runnable.
#
# Assumes:
#   - The repo is checked out at /home/ubuntu/netsec (adjust NETSEC_DIR)
#   - The compose stack is up (docker compose -f deploy/docker-compose.yml)
#   - ollama container has 127.0.0.1:11434 exposed on the host (the
#     current docker-compose.yml does this; if you have not
#     `docker compose up -d ollama` since 2026-08-02, do that first)
#
# What it does:
#   1. Pull nomic-embed-text into Ollama (once).
#   2. mkdir /srv/netsec/rag and chown to ubuntu.
#   3. Install /etc/default/netsec-rag with tunable env vars.
#   4. Install the three systemd units (service + ingest service + timer).
#   5. Enable and start service and timer.
#   6. Run one initial ingest so the store is populated for the first
#      question you ask.
set -euo pipefail

NETSEC_DIR="${NETSEC_DIR:-/home/ubuntu/netsec}"
STORE_DIR="${STORE_DIR:-/srv/netsec/rag}"
DEPLOY_DIR="${NETSEC_DIR}/deploy"

echo "[rag] installing host Python deps..."
# The engine (netsec_rag.py) needs numpy. The web frontend
# (netsec_rag_web.py) needs dash + dash_bootstrap_components and reuses
# the companion venv (same deps, one install to maintain), so we just
# ensure that venv has numpy too.
sudo apt-get install -y python3-numpy python3-venv
COMPANION_VENV=/opt/netsec-companion/venv
if [ -x "${COMPANION_VENV}/bin/pip" ]; then
    sudo "${COMPANION_VENV}/bin/pip" install --quiet numpy
else
    echo "  ! companion venv not found - run install-companion.sh first"
fi

echo "[rag] pulling nomic-embed-text (idempotent)..."
sudo docker exec deploy-ollama-1 ollama pull nomic-embed-text

echo "[rag] creating ${STORE_DIR}..."
sudo mkdir -p "${STORE_DIR}"
sudo chown -R ubuntu:ubuntu "${STORE_DIR}"

echo "[rag] writing /etc/default/netsec-rag..."
sudo tee /etc/default/netsec-rag >/dev/null <<EOF
# Override any of the RAG defaults here. Restart with:
#   sudo systemctl restart netsec-rag.service
# NETSEC_RAG_GEN_MODEL=qwen2.5:3b
# NETSEC_RAG_EMBED_MODEL=nomic-embed-text
# NETSEC_OLLAMA_URL=http://127.0.0.1:11434
EOF

echo "[rag] installing systemd units..."
sudo cp "${DEPLOY_DIR}/netsec-rag.service"        /etc/systemd/system/
sudo cp "${DEPLOY_DIR}/netsec-rag-ingest.service" /etc/systemd/system/
sudo cp "${DEPLOY_DIR}/netsec-rag-ingest.timer"   /etc/systemd/system/
sudo systemctl daemon-reload

echo "[rag] initial ingest of /srv/netsec/reports..."
NETSEC_RAG_DB="${STORE_DIR}/store.db" \
NETSEC_OLLAMA_URL=http://127.0.0.1:11434 \
    /usr/bin/python3 "${NETSEC_DIR}/tools/netsec_rag.py" \
        ingest-netsec /srv/netsec/reports

echo "[rag] enabling + starting service..."
sudo systemctl enable --now netsec-rag.service
sudo systemctl enable --now netsec-rag-ingest.timer

echo ""
echo "[rag] done. Quick checks:"
echo "  sudo systemctl status netsec-rag.service --no-pager | head"
echo "  curl -sS http://100.68.246.54:5200/ | head -1"
echo "  # From an iPhone on Tailscale: open http://netsec-agent.tail37ac21.ts.net:5200"

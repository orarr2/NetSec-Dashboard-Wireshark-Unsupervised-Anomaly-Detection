#!/usr/bin/env bash
# Switch RAG's embedding model + reindex. embeddings from different
# models have different dimensions and are NOT comparable, so any switch
# means a fresh index.
#
# Usage:
#   bash reindex-rag.sh mxbai-embed-large
#   bash reindex-rag.sh nomic-embed-text     # rollback
#
# Assumes:
#   - Ollama has the new model pulled (docker exec deploy-ollama-1
#     ollama pull <model>)
set -euo pipefail

MODEL="${1:-mxbai-embed-large}"
STORE="${STORE:-/srv/netsec/rag/store.db}"
COMPANION_VENV=/opt/netsec-companion/venv

echo "[reindex-rag] target model: ${MODEL}"

# Confirm the model is loaded in Ollama
if ! sudo docker exec deploy-ollama-1 ollama list | grep -q "^${MODEL}\b\|^${MODEL}:"; then
    echo "  ! model ${MODEL} not present in Ollama - pull it first:"
    echo "    sudo docker exec deploy-ollama-1 ollama pull ${MODEL}"
    exit 1
fi

echo "[reindex-rag] backing up old store to ${STORE}.bak..."
if [ -f "${STORE}" ]; then
    sudo cp "${STORE}" "${STORE}.bak"
fi

echo "[reindex-rag] wiping old store (dimensions do not match new model)..."
sudo rm -f "${STORE}" "${STORE}-shm" "${STORE}-wal"

echo "[reindex-rag] updating /etc/default/netsec-rag..."
if sudo grep -q "^NETSEC_RAG_EMBED_MODEL=" /etc/default/netsec-rag; then
    sudo sed -i "s|^NETSEC_RAG_EMBED_MODEL=.*|NETSEC_RAG_EMBED_MODEL=${MODEL}|" \
        /etc/default/netsec-rag
else
    echo "NETSEC_RAG_EMBED_MODEL=${MODEL}" | \
        sudo tee -a /etc/default/netsec-rag >/dev/null
fi

echo "[reindex-rag] re-ingesting /srv/netsec/reports with ${MODEL}..."
sudo NETSEC_RAG_DB="${STORE}" NETSEC_RAG_EMBED_MODEL="${MODEL}" \
     NETSEC_OLLAMA_URL=http://127.0.0.1:11434 \
     "${COMPANION_VENV}/bin/python" \
     /home/ubuntu/netsec/tools/netsec_rag.py \
     ingest-netsec /srv/netsec/reports 2>&1 | tail -3

echo "[reindex-rag] restarting the RAG service to load the new model..."
sudo systemctl restart netsec-rag.service
sleep 3
sudo systemctl status netsec-rag.service --no-pager 2>&1 | head -6

echo ""
echo "[reindex-rag] done. Verify:"
echo "  NETSEC_RAG_DB=${STORE} /usr/bin/python3 tools/netsec_rag.py stats"

#!/usr/bin/env bash
# Install / refresh the NetSec Portal (Aurora theme) on the VM.
# Idempotent - re-runnable.
#
# What it does:
#   1. Copy the Aurora portal HTML to /srv/portal/index.html.
#   2. Symlink /srv/portal/brand -> repo's deploy/brand/ (CSS + logo).
#   3. Symlink /srv/portal/reports -> /srv/netsec/reports (report browsing).
#   4. Install netsec-portal-latest.service + .timer so /latest.json
#      refreshes every 60s from the DB.
#   5. Reload systemd, restart the portal http.server so it picks up
#      the new files (the portal is a python -m http.server, no cache).
set -euo pipefail

NETSEC_DIR="${NETSEC_DIR:-/home/ubuntu/netsec}"
PORTAL_DIR="${PORTAL_DIR:-/srv/portal}"

echo "[portal] writing ${PORTAL_DIR}/index.html..."
sudo mkdir -p "${PORTAL_DIR}"
sudo cp "${NETSEC_DIR}/deploy/brand/portal.html" "${PORTAL_DIR}/index.html"

echo "[portal] symlinking /brand -> ${NETSEC_DIR}/deploy/brand..."
sudo ln -sfn "${NETSEC_DIR}/deploy/brand" "${PORTAL_DIR}/brand"

echo "[portal] symlinking /reports -> /srv/netsec/reports..."
sudo ln -sfn /srv/netsec/reports "${PORTAL_DIR}/reports"

echo "[portal] installing systemd units..."
sudo cp "${NETSEC_DIR}/deploy/netsec-portal-latest.service" /etc/systemd/system/
sudo cp "${NETSEC_DIR}/deploy/netsec-portal-latest.timer"  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netsec-portal-latest.timer
sudo systemctl start netsec-portal-latest.service
sudo systemctl restart netsec-portal.service

echo ""
echo "[portal] done. Check:"
echo "  curl -sI http://100.68.246.54:8080/                      # HTML"
echo "  curl -sI http://100.68.246.54:8080/brand/netsec-brand.css # CSS"
echo "  curl -s  http://100.68.246.54:8080/latest.json           # session card"

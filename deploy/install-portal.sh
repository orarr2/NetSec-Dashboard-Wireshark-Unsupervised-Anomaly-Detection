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

echo "[portal] writing ${PORTAL_DIR}/index.html + sessions.html..."
sudo mkdir -p "${PORTAL_DIR}"
sudo cp "${NETSEC_DIR}/deploy/brand/portal.html"   "${PORTAL_DIR}/index.html"
sudo cp "${NETSEC_DIR}/deploy/brand/sessions.html" "${PORTAL_DIR}/sessions.html"

echo "[portal] copying brand assets -> ${PORTAL_DIR}/brand/..."
# NOT a symlink: the portal http.server runs as User=nobody and
# /home/ubuntu is 0750, so a symlink target inside there is unreadable.
# One copy is fine - the brand kit is tiny (~170KB with the fonts) and
# refresh is handled by re-running install-portal.sh (idempotent).
sudo rm -rf "${PORTAL_DIR}/brand"
sudo mkdir -p "${PORTAL_DIR}/brand/fonts"
sudo cp "${NETSEC_DIR}/deploy/brand/netsec-brand.css" \
        "${NETSEC_DIR}/deploy/brand/netsec-logo.svg" \
        "${NETSEC_DIR}/deploy/brand/netsec-logo.b64" \
        "${NETSEC_DIR}/deploy/brand/favicon.svg" \
        "${NETSEC_DIR}/deploy/brand/apple-touch-icon.png" \
        "${PORTAL_DIR}/brand/"
# Self-hosted Inter Tight (replaces the Google Fonts pull; see the
# @font-face block in netsec-brand.css).
sudo cp "${NETSEC_DIR}/deploy/brand/fonts/"*.woff2 "${PORTAL_DIR}/brand/fonts/"
sudo chmod -R a+r "${PORTAL_DIR}/brand"

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

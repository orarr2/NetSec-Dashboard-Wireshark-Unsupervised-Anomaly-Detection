# Run your own analysis VM - deployment scaffolding

This directory holds the generic, secret-free deployment templates so
that any fork can stand up the 24/7 analysis stack on its own VM.
Everything a fork needs to run the pipeline + the always-on user
services (RAG, Companion, Portal, Caddy) lives here or under
`../server/`, `../sensor/`, `../tools/`, `../companion/`.

## What ships

| File | Purpose |
|---|---|
| `.env.example` | Every environment variable the stack reads, with its code default. |
| `docker-compose.yml` | The docker services: n8n + ingest_api + worker + retention + ollama + caddy. Each bound to your Tailscale IP; ollama on loopback. |
| `Dockerfile.ingest` | The ingest API image - `server/` + FastAPI, port 8766. |
| `Dockerfile.worker` | The analysis worker image - runs the detection pipeline, writes verdicts + HTML/PDF reports. |
| `Caddyfile` | Reverse proxy config: TLS + basicauth + path routing to Portal / RAG / Companion. |
| `install-caddy.sh` | One-shot installer: writes the basicauth creds, starts Caddy, installs fail2ban with a Caddy jail. Needs BASIC_AUTH_USER + BASIC_AUTH_HASH env vars. |
| `install-rag.sh` | Installs the RAG service (Ollama embed model + systemd unit + ingest timer). |
| `install-companion.sh` | Installs the Companion service (dedicated Python venv with dash + pypdf + python-docx, tshark for PCAP file drop, systemd unit). |
| `netsec-rag.service` + `-ingest.service` + `.timer` | systemd units for RAG. |
| `netsec-companion.service` | systemd unit for Companion. |
| `netsec-tls-renew.service` + `.timer` | Weekly refresh of the Tailscale-issued Let's Encrypt cert. |
| `n8n_workflows/mvp_triage_email.json` | Importable n8n workflow: receives the worker's alert webhook and emails when a verdict is malicious/suspicious. |
| `create_sensor.py` | Registers a sensor in the history DB and prints its credentials once. |
| `../server/` | History DB schema, HMAC upload auth, streaming storage, and the FastAPI ingest layer. |
| `../tools/netsec_rag.py` | RAG engine (retrieval + generation). CLI + Python API. |
| `../tools/netsec_rag_web.py` | RAG Dash web frontend, structured like Companion. |
| `../companion/companion.py` | AI Companion (Dash chat over local Ollama, with file drop). |
| `../tools/upload_pcap.py` | Signed streaming upload from any machine - the no-size-cap replacement for the GitHub 25MB path. |
| `../tools/measure_pipeline_ratios.py` | Re-measures the PCAP-vs-fields size ratios the plan is built on, against your own long capture (the plan's numbers came from a single 135-second sample). |
| `../server/retention.py` | Daily housekeeping (runs as the `retention` compose service): DB backup + prune, 7-day raw purge with the permanent field-index backfilled first, 85% disk watermark, monthly VACUUM. `--once --dry-run` shows what it would do. |
| `../tools/watchdog.py` | Standalone external checker - copy to any always-on machine OUTSIDE the VM, point it at `http://<vm>:8766/healthz`, get one email per outage and one per recovery. No machine monitors itself. |

## Quick start on a fresh VM

```bash
# 1. Clone the repo on the VM
git clone <repo> /home/ubuntu/netsec
cd /home/ubuntu/netsec/deploy

# 2. Write .env with your secrets (SMTP + N8N encryption key + LLM keys)
cp .env.example .env
$EDITOR .env

# 3. Bring up the docker services (does NOT include caddy yet)
sudo docker compose up -d ingest_api worker retention ollama n8n

# 4. Register a sensor (prints its HMAC secret once - save it)
python3 create_sensor.py my-laptop

# 5. Install the user-facing services (systemd)
sudo cp ../deploy/netsec-portal.service /etc/systemd/system/    # (create this from a template if not present)
sudo systemctl enable --now netsec-portal
bash install-rag.sh
bash install-companion.sh

# 6. Get a Tailscale HTTPS cert (requires enabling HTTPS in tailscale admin console once)
sudo mkdir -p /etc/netsec-tls
sudo tailscale cert netsec-agent.<your-tailnet>.ts.net
sudo mv netsec-agent.*.crt netsec-agent.*.key /etc/netsec-tls/

# 7. Bring up Caddy with basicauth
BASIC_AUTH_USER=you \
BASIC_AUTH_HASH="$(sudo docker run --rm caddy:2 caddy hash-password --plaintext 'YOUR-PW')" \
    bash install-caddy.sh

# 8. From any Tailscale device open https://netsec-agent.<your-tailnet>.ts.net/
```

Once the last step returns 200 you have Portal + RAG + Companion + n8n + the pipeline all reachable from any device signed into your Tailscale account. See `../docs/ARCHITECTURE.md` for the routing map and `../docs/SECURITY_MODEL.md` for the auth layers.

## Requirements

- Any Ubuntu 22.04+ VM, x86-64 or ARM (aarch64 is verified - every
  pinned dependency publishes an aarch64 wheel, see
  `docs/VM_DEPLOYMENT.md`). 4GB RAM minimum for the pipeline alone;
  16-24GB recommended if you also want the free local Ollama judge.
- Oracle Always Free (4 OCPU / 24GB RAM / 100GB boot volume) is the
  recommended $0 path; AWS / Azure / Hetzner or any provider work
  identically. **Staying free:** the free tier allows up to 200GB total
  block storage - keep the 100GB boot and DON'T add a volume that pushes
  past 200GB, or you start paying. Retention (below) keeps the disk
  bounded so it never spills onto a paid resource.
- Docker + the compose plugin, Tailscale, and chrony (NTP - required by
  the telemetry-reconciliation protocol, spec section 12).
- Nothing is exposed publicly except SSH: every service binds to the
  Tailscale IP (decision IDX-08).

## Quickstart

1. Install Docker, Tailscale and chrony on the VM; join your tailnet:
   `sudo tailscale up --hostname=netsec-agent`.
2. Apply the firewall notes from `docs/VM_DEPLOYMENT.md` (the
   `tailscale0` ACCEPT rule must precede the cloud image's catch-all
   REJECT, and must be persisted).
3. Create the data root on the boot disk - no extra volume, stays $0:
   `sudo mkdir -p /srv/netsec && sudo chown $USER /srv/netsec`
   (decision IDX-02+03; retention keeps it bounded). Only if you later
   need continuous 24/7 capture, add a block volume of **at most 100GB**
   so boot + volume stays within the free 200GB.
4. `git clone` this repository onto the VM and `cd deploy/`.
5. `cp .env.example .env` and fill in values - at minimum `TS_BIND`
   (the VM's Tailscale IP) and `N8N_ENCRYPTION_KEY`.
6. `docker compose up -d` - starts n8n and the ingest API. Verify from
   a machine on your tailnet (and confirm the public IP answers
   nothing on either port):
   `curl -s -o /dev/null -w "%{http_code}\n" http://$TS_BIND:5678/`
   `curl -s http://$TS_BIND:8766/healthz`
7. Register a sensor and copy the printed credentials into the
   sensor's environment (shown once, not recoverable). Run it from the
   `deploy/` directory; the containers created `db/netsec.db` as root, so
   use `sudo` and point it at the same data root:
   `sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop`
8. Upload a capture from any machine on the tailnet - no size cap
   (run from the repo root, or adjust the path):
   `python3 tools/upload_pcap.py capture.pcapng`
   (needs `NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766` plus the
   sensor credentials in the environment). The session is queued, the
   worker analyses it, and `verdicts.json` / `.md` / `report.html` /
   `report.pdf` are written under `reports/<session_id>/`.
9. (Optional) Wire up n8n alerts: open n8n at `http://<vm>:5678`,
   **Import from File** → `deploy/n8n_workflows/mvp_triage_email.json`,
   attach an SMTP credential to the *Send Email Alert* node, **Activate**
   it, and set `N8N_WEBHOOK_URL` in `.env` to that webhook's URL so the
   worker posts each verdict to it.

## Storage layout (per the approved plan, spec section 8)

```
/srv/netsec/
├── data/pcap/      raw captures - kept 7 days, then auto-purged
├── data/fields/    gzipped field exports - kept forever (IDX-04)
├── reports/        verdicts.json / .md / .html / .pdf - kept forever
└── db/             netsec.db (SQLite history) + nightly backups
```

## Running a sensor (laptop today, Raspberry Pi 5 tomorrow)

The capture agent (`sensor/capture_agent.py`) is Tier 0 - it records raw
PCAP in a tshark ring buffer and uploads each closed chunk to the VM. It
is the same code on a laptop and on a Pi 5 (decision IDX-01, stage J):
only the environment differs.

```bash
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop           # from deploy/create_sensor.py
export NETSEC_SENSOR_SECRET=...           # from deploy/create_sensor.py
export NETSEC_INFRA_DSTS=<vm-tailscale-ip>   # excluded from capture
python3 sensor/capture_agent.py --interface wlan0
```

The `NETSEC_INFRA_DSTS` value is what keeps the agent's own uploads from
being captured and later flagged as an anomaly or as beaconing (spec
section 12.2 layer 0): the agent builds a capture filter that excludes
exactly that destination on the upload port, and nothing else.

**Pi 5 as a drop-in Tier 0 (stage J).** The Pi runs the identical agent;
the architecture does not change. Two Pi-specific notes:

- Give the Pi two paths so the upload never rides the monitored network:
  capture on the Wi-Fi interface, upload over Ethernet. With that split
  the telemetry leaves out-of-band and the capture filter is belt-and-
  suspenders rather than load-bearing.
- A 128GB card holds roughly nine days of raw at the measured rate, so
  set `NETSEC_RING_FILES` to bound the local ring to what the card can
  carry (`files:N x duration:S` seconds of history).

Everything downstream - ingest, worker, history, baselines, reports - is
unchanged: to the VM a Pi chunk and a laptop chunk are the same signed
upload.

## Secrets

`deploy/.env` is gitignored - it is the only place API keys, the n8n
encryption key and sensor secrets live on the VM. Never commit it, and
never put a secret in any file inside this directory.

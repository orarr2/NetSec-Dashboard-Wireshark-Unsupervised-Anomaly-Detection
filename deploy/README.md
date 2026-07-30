# Run your own analysis VM - deployment scaffolding

Stage A of the ecosystem plan (`ARCHITECTURE_HE.md` at the repo root).
This directory holds the generic, secret-free deployment templates so
that any fork can stand up the 24/7 analysis stack on its own VM. The
original local-only `automation/` directory stays untracked; everything
a fork needs lands here instead, stage by stage.

## What ships today (stages A-B)

| File | Purpose |
|---|---|
| `.env.example` | Every environment variable the stack reads, documented. Variables consumed by later stages are included and clearly marked - they are inert until that stage lands. |
| `docker-compose.yml` | n8n + the ingest API, bound to your Tailscale IP only. Slots for `judge_api` and the worker arrive in stage C. |
| `Dockerfile.ingest` | The ingest API image - `server/` + FastAPI, port 8766. |
| `create_sensor.py` | Registers a sensor in the history DB and prints its credentials once. |
| `../server/` | History DB schema, HMAC upload auth, streaming storage, and the FastAPI ingest layer. |
| `../tools/upload_pcap.py` | Signed streaming upload from any machine - the no-size-cap replacement for the GitHub 25MB path. |
| `../tools/measure_pipeline_ratios.py` | Re-measures the PCAP-vs-fields size ratios the plan is built on, against your own long capture (the plan's numbers came from a single 135-second sample). |
| `../server/retention.py` | Daily housekeeping (runs as the `retention` compose service): DB backup + prune, 7-day raw purge with the permanent field-index backfilled first, 85% disk watermark, monthly VACUUM. `--once --dry-run` shows what it would do. |
| `../tools/watchdog.py` | Standalone external checker - copy to any always-on machine OUTSIDE the VM, point it at `http://<vm>:8766/healthz`, get one email per outage and one per recovery. No machine monitors itself. |

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
   sensor's environment (shown once, not recoverable):
   `python3 deploy/create_sensor.py laptop`
8. Upload a capture from any machine on the tailnet - no size cap:
   `python3 tools/upload_pcap.py capture.pcapng`
   (needs `NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766` plus the
   sensor credentials in the environment). The session is queued;
   analysis and the HTML/PDF reports arrive with stage C.

## Storage layout (per the approved plan, spec section 8)

```
/srv/netsec/
├── data/pcap/      raw captures - kept 7 days, then auto-purged
├── data/fields/    gzipped field exports - kept forever (IDX-04)
├── reports/        verdicts.json / .md / .html / .pdf - kept forever
├── db/             netsec.db (SQLite history) + nightly backups
└── incoming/       drop directory polled by the automation
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

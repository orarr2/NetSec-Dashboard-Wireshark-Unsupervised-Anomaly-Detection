# Run your own analysis VM - deployment scaffolding

Stage A of the ecosystem plan (`ARCHITECTURE_HE.md` at the repo root).
This directory holds the generic, secret-free deployment templates so
that any fork can stand up the 24/7 analysis stack on its own VM. The
original local-only `automation/` directory stays untracked; everything
a fork needs lands here instead, stage by stage.

## What ships today (stage A)

| File | Purpose |
|---|---|
| `.env.example` | Every environment variable the stack reads, documented. Variables consumed by later stages are included and clearly marked - they are inert until that stage lands. |
| `docker-compose.yml` | The n8n automation container, bound to your Tailscale IP only. Service slots for `judge_api`, the ingest API and the worker are declared and arrive in stages B-C. |
| `../tools/measure_pipeline_ratios.py` | Re-measures the PCAP-vs-fields size ratios the plan is built on, against your own long capture (the plan's numbers came from a single 135-second sample). |

## Requirements

- Any Ubuntu 22.04+ VM, x86-64 or ARM (aarch64 is verified - every
  pinned dependency publishes an aarch64 wheel, see
  `docs/CLOUD_DEPLOYMENT.md`). 4GB RAM minimum for the pipeline alone;
  16-24GB recommended if you also want the free local Ollama judge.
- Oracle Cloud Always Free (4 OCPU / 24GB RAM / 200GB total block
  storage) is the recommended zero-cost path; AWS / GCP / Azure /
  Hetzner work identically.
- Docker + the compose plugin, Tailscale, and chrony (NTP - required by
  the telemetry-reconciliation protocol, spec section 12).
- Nothing is exposed publicly except SSH: every service binds to the
  Tailscale IP (decision IDX-08).

## Quickstart

1. Install Docker, Tailscale and chrony on the VM; join your tailnet:
   `sudo tailscale up --hostname=netsec-agent`.
2. Apply the firewall notes from `docs/CLOUD_DEPLOYMENT.md` (the
   `tailscale0` ACCEPT rule must precede the cloud image's catch-all
   REJECT, and must be persisted).
3. Attach a dedicated 100-150GB block volume and mount it at
   `/srv/netsec` (decision IDX-02+03). On Oracle Always Free this fits
   inside the 200GB no-cost storage budget. Skip this if you only
   analyze occasional manual sessions.
4. `git clone` this repository onto the VM and `cd deploy/`.
5. `cp .env.example .env` and fill in values - at minimum `TS_BIND`
   (the VM's Tailscale IP) and `N8N_ENCRYPTION_KEY`.
6. `docker compose up -d` - today this starts n8n. Verify:
   `curl -s -o /dev/null -w "%{http_code}\n" http://$TS_BIND:5678/`
   from a machine on your tailnet (expect 200), and confirm the public
   IP answers nothing on 5678.
7. *(Arrives in stage B)* create a per-sensor token, upload a PCAP with
   `tools/upload_pcap.py`, and receive the HTML/PDF report.

## Storage layout (per the approved plan, spec section 8)

```
/srv/netsec/
├── data/pcap/      raw captures - kept 7 days, then auto-purged
├── data/fields/    gzipped field exports - kept forever (IDX-04)
├── reports/        verdicts.json / .md / .html / .pdf - kept forever
├── db/             netsec.db (SQLite history) + nightly backups
└── incoming/       drop directory polled by the automation
```

## Secrets

`deploy/.env` is gitignored - it is the only place API keys, the n8n
encryption key and sensor secrets live on the VM. Never commit it, and
never put a secret in any file inside this directory.

# NetSec Automation Quickstart

The reference deployment runs on a small VM you control (Oracle Always
Free ARM is the recommended $0 path) reached over Tailscale. The
dashboard, the notebook and the CLI can all send a PCAP into it; the
worker analyses each capture, writes verdicts + HTML/PDF reports, and
mails the finished report directly (SMTP) to the address the uploader
provided. An n8n workflow can be wired as a fallback delivery channel
when SMTP fails - see [VM_OPS.md](VM_OPS.md#email-delivery-on-completion).

Everything the VM needs is in `deploy/`. This file walks through the
common questions people hit when standing that up. For the reference
deployment steps, see [deploy/README.md](../deploy/README.md); for the
firewall / Oracle Security-List / iptables details, see
[VM_DEPLOYMENT.md](VM_DEPLOYMENT.md).

The dashboard notebook works without any of this - the VM path is the
"always-on" mode, not a required dependency.

---

## What ships in `deploy/`

Four docker-compose services + one Dockerfile per app image, all bound
to `TS_BIND` (your VM's Tailscale IP) so nothing listens on a public
interface:

| service     | port | what it does                                                    |
|-------------|------|-----------------------------------------------------------------|
| `ingest_api`| 8766 | signed streaming HMAC upload endpoint (`/v1/pcap`), health + reports |
| `worker`    | -    | claims queued sessions, runs the detection pipeline, writes reports, mails the finished PDF via SMTP |
| `retention` | -    | daily housekeeping (7-day raw purge, 85% watermark, DB backup, VACUUM) |
| `n8n`       | 5678 | *optional* - receives the worker's fallback webhook when SMTP itself fails |

Storage layout under `NETSEC_DATA_ROOT` (default `/srv/netsec`):

```
data/pcap/YYYY/MM/DD/<sha8>_<orig>.pcap    raw captures - 7 days, then purged
data/fields/YYYY/MM/<sha8>.tsv.gz          gzipped field export - kept forever
reports/<session_id>/{verdicts.json,verdicts.md,report.html,report.pdf}
db/netsec.db (+ dated backups)             SQLite history
```

Sensor upload → ingest API queues a session → worker analyses → verdicts
+ reports on disk → worker's SMTP delivers the PDF to the address that
was on `X-Notify-Email` (falling back to `NETSEC_NOTIFY_EMAIL`, then to
the n8n webhook, then to a log-only entry).

---

## Prerequisites

Install on the VM:

1. **Docker Engine + Compose plugin** (Ubuntu 22.04+, x86-64 or ARM).
   `sudo apt-get install docker.io docker-compose-plugin`.
2. **Tailscale**. `curl -fsSL https://tailscale.com/install.sh | sh &&
   sudo tailscale up --hostname=<name>`.
3. **chrony** (NTP - required by the telemetry-reconciliation protocol,
   `docs/VM_ARCHITECTURE_HE.md` §13).

Install on any machine that needs to talk to the VM:

- **Tailscale** (join the same tailnet as the VM).
- **Wireshark** including `tshark` - needed only where you capture
  PCAPs, not on the VM itself.

Free-tier LLM API keys are optional. The zero-key path is
`LLM_JUDGE_PROVIDER=ollama` with a local Ollama daemon; every provider
in `deploy/.env.example` is off by default and only turns on when you
paste a key.

---

## Configure once

```bash
git clone <your-fork>
cd <repo>/deploy
cp .env.example .env
```

Open `.env` and set at minimum:

- `TS_BIND` - your VM's Tailscale IP (`tailscale ip -4`).
- `N8N_ENCRYPTION_KEY` - 32 random characters. Any of these work:
  - Linux / Mac:
    `openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32`
  - Windows PowerShell:
    `-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})`
  - **Losing this key wipes every credential you save inside n8n.**
    Back it up outside the repo (a password manager, encrypted file).

Everything else in `.env.example` ships with a working default from the
code. See the file itself for what every variable does; the highlights:

- `NETSEC_DATA_ROOT` - where PCAPs, reports and the DB live
  (`/srv/netsec` default). `retention` keeps this bounded, so it never
  spills onto a paid volume.
- `LLM_JUDGE_PANEL` - the default panel needs Groq + Gemini + local
  Ollama keys. For a zero-key run, use just
  `LLM_JUDGE_PANEL=ollama:qwen2.5:14b,ollama:phi4:14b` or drop the
  panel entirely and set `LLM_JUDGE_PROVIDER=ollama`.
- `NETSEC_NOTIFY_EMAIL` and `N8N_WEBHOOK_URL` - optional per-session
  delivery. Set the one you use; leave the other blank.
- `SMTP_USER` / `SMTP_PASS` - only if you use the direct-email path
  (`llm_judge/send_report.py`) or `NETSEC_NOTIFY_EMAIL`. Gmail App
  Passwords: enable 2FA first, then generate at
  <https://myaccount.google.com/apppasswords>.

`deploy/.env` is gitignored; double-check with `git status` before
pushing.

---

## Bring the stack up

From `deploy/`:

```bash
sudo mkdir -p /srv/netsec && sudo chown $USER /srv/netsec
docker compose up -d
```

**First run** (2-6 min): Docker builds the `ingest_api` and `worker`
images (installs `fastapi`, `numpy`, `pandas`, `scikit-learn`, `torch`,
`scapy`, `weasyprint`), pulls `n8nio/n8n:latest`, and initialises the
n8n SQLite DB.

**Subsequent runs**: seconds - all four services come back up in place.

Verify from any machine on your tailnet:

```bash
# ingest API - should return {"status":"ok","schema":<n>}
curl -s http://<vm-tailscale-ip>:8766/healthz

# n8n UI answers (302 to /setup on first visit, 200 after)
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:5678/
```

Confirm from the public internet that neither port answers - only
Tailscale peers should reach them.

---

## Register a sensor

Every uploader needs its own HMAC secret. Sensor names identify one
uploader (a laptop, a Pi, a CI runner):

```bash
# from deploy/, as the same user that owns /srv/netsec
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop
```

Output (printed once, not recoverable - the token is stored hashed, the
HMAC secret is stored plain because HMAC verification needs the secret
itself):

```
# sensor 'laptop' registered - shown ONCE, store safely
NETSEC_SENSOR_ID=laptop
NETSEC_SENSOR_SECRET=<64 hex chars>
NETSEC_API_TOKEN=<44-char urlsafe>
```

Paste those three lines into the environment of whatever machine will
upload PCAPs. Revoking a compromised sensor is one SQL statement:

```sql
UPDATE sensors SET revoked_at = datetime('now') WHERE name = 'laptop';
```

Cross-sensor authorisation is enforced: a bearer token can read only
its own sessions and reports. Set `NETSEC_ADMIN_SENSOR=<name>` (the
sensor name your central dashboard registers under) if you want that
one sensor's token to read every sensor's sessions.

---

## Wire up the n8n alert workflow

Open `http://<vm-tailscale-ip>:5678` in a browser (the first visit walks
you through creating an owner account - keep that credential safe;
`N8N_BASIC_AUTH_*` is not supported in modern n8n).

1. **Workflows** → **⋮ (import)** → **Import from File** → select
   `deploy/n8n_workflows/mvp_triage_email.json`. This ships as a
   volume mount at `/workflows` inside the container, so you can also
   run:
   ```bash
   docker compose exec n8n n8n import:workflow \
     --input=/workflows/mvp_triage_email.json
   ```
2. Open the imported workflow (**NetSec Triage Alert**). Click the
   **Send Email Alert** node and attach an SMTP credential - **+ Add
   Credential** → **SMTP**:

   | field    | value                                          |
   |----------|------------------------------------------------|
   | Name     | `NetSec SMTP` (any name, but be consistent)    |
   | User     | your full mailbox                              |
   | Password | app password or account password (per provider) |
   | Host     | your SMTP host (e.g. `smtp.gmail.com`)         |
   | Port     | `587`                                          |
   | SSL/TLS  | **off** (STARTTLS on port 587)                 |

3. Set the `fromEmail` and `toEmail` fields on the node to your
   addresses. Toggle **Active** (top-right) so the webhook is live.
4. Copy the **Production URL** of the `Worker Webhook` node (looks like
   `http://<vm-ip>:5678/webhook/netsec-alert`) and paste it into
   `N8N_WEBHOOK_URL` in `deploy/.env`, then
   `docker compose restart worker`.

That's it. The worker POSTs `{session_id, label, kind, sha256, results,
worst}` to the webhook after every session; the workflow's IF node
gates on `worst` matching `malicious|suspicious`; matching sessions
email out.

Credentials only need to be re-entered if the `n8n_data` named volume
is destroyed (`docker compose down -v`) or if you lose the
`N8N_ENCRYPTION_KEY`.

---

## Auto-start on host boot

All four services use `restart: unless-stopped`, so the Docker daemon
brings them back automatically. Enable the daemon itself:

```bash
sudo systemctl enable docker
```

There is one race worth knowing about: `${TS_BIND}` is a `tailscale0`
address, so Docker can start before `tailscaled` assigns the IP and
fail to bind. `restart: unless-stopped` retries with backoff, so it
converges within a minute; add an `After=tailscaled.service`
docker.service drop-in if the delay bothers you.

---

## Verify end-to-end

Three independent ways:

**A. Upload with the CLI** (the simplest smoke test):

```bash
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop
export NETSEC_SENSOR_SECRET=<from create_sensor>
python3 tools/upload_pcap.py attack_tests/pcaps/tcp_syn_scan.pcap
# Prints {"session_id": N, ...}. Wait a moment for the worker.
curl -s -H "Authorization: Bearer <token>" \
  http://<vm-tailscale-ip>:8766/v1/sessions/N
# {..., "status":"done", "n_pkts":2020, ...}
open http://<vm-tailscale-ip>:8766/v1/reports/N.html   # or .pdf, .json, .map
```

If `N8N_WEBHOOK_URL` is configured, an email lands within a few seconds
of the worker finishing.

**B. From the dashboard button.** Load a PCAP in the notebook. In the
sidebar, type the address you want the report mailed to, pick an LLM
panel preset, and click **Send S1 to VM (mail report)**. The button
signs the capture and streams it to the ingest API over Tailscale
(`server/dashboard_client.py`), exactly like `tools/upload_pcap.py`
does from the shell. Set `NETSEC_INGEST_URL` / `NETSEC_SENSOR_ID` /
`NETSEC_SENSOR_SECRET` in the shell that launches the notebook - until
they are set the button reports `set NETSEC_INGEST_URL` and sends
nothing.

A capture the VM has already analysed is deduplicated by SHA-256: the
upload returns the existing session instead of queueing the same work
twice, and the button says so.

**C. GitHub Actions is not an ingest path.** The `analyze-pcap.yml`
workflow that watched an `incoming/` folder was retired - the 25 MB
Actions upload cap made it useless for real captures, and the VM path
covers every case it did. What remains under `.github/` is `ci.yml`:
tests plus the notebook-to-module sync check. Nothing about analysing
your own captures depends on GitHub.

---

## Tuning

Change these in `deploy/.env`, then `docker compose restart worker`
(or `n8n` if the change touches that service):

- `LLM_JUDGE_PANEL` - which judges vote. Every judge you list runs and
  every verdict comes back (there is no automatic fallback that swaps
  models silently; a failing judge is reported).
- `LLM_JUDGE_MAX_CANDIDATES` - flagged candidates judged per PCAP.
  **Default `40`**. Free tiers with tight per-minute token budgets
  need this lower - measured on Groq's free tier 2026-08, the
  per-minute ceiling is 6 000 tokens for `llama-3.1-8b-instant` and
  8 000 for the `gpt-oss` models, so a 30-candidate capture spends
  most of its wall-clock waiting out 429s. Drop to `10` on a bursty
  key.
- `LLM_JUDGE_BATCH_SIZE` - candidates packed into one call.
  **Default `1`.** A request costs `1675 + n x 720` tokens (the system
  prompt is paid once per call; each candidate blob is ~720). On the
  ceilings above, `n=3` costs 3 835 and fits comfortably, while `n=5`
  costs 5 275 - 88 % of llama-8b's whole minute in one request, which
  any concurrent call throttles into the per-candidate fallback it was
  meant to replace.
- `LLM_JUDGE_TIMEOUT_S` - per-request timeout in seconds. **Default
  `300`** in code; raise to `600` when a cold local Ollama model has
  to load before its first answer.
- `NETSEC_MAX_UPLOAD_GB` - single-file ceiling on the ingest endpoint.
  Default `10`.
- `NETSEC_ENABLE_SHODAN=1` (plus `SHODAN_API_KEY`) - external-peer
  reputation lookups. Off by default; when on, activates the judge's
  threat-intel weight (`W_TI`).

Sensor-side tuning lives in the sensor's environment
(`NETSEC_CHUNK_SECONDS`, `NETSEC_RING_FILES`, `NETSEC_SPOOL_CAP_GB`);
see `sensor/capture_agent.py`.

---

## Backup and recovery

**What's persistent:**

- `deploy/.env` - your secrets. Back it up outside the repo (password
  manager, encrypted file in personal storage).
- `${NETSEC_DATA_ROOT}/db/` - the SQLite history + the nightly backups
  the retention service writes. Copy the whole directory to keep
  history.
- `${NETSEC_DATA_ROOT}/reports/` - HTML/PDF/JSON, kept forever.
- Docker named volume `n8n_data` - n8n's SQLite DB, holds the workflow
  and credentials. Back up by exporting from the container:
  ```bash
  docker compose exec n8n \
    tar -czf - -C /home/node/.n8n . > n8n_backup_$(date +%Y%m%d).tgz
  ```

**If the n8n DB is lost** (`docker compose down -v`, disk failure,
volume corruption): re-import `mvp_triage_email.json` and re-create the
SMTP credential. The workflow file ships with the repo so it is always
recoverable; the credential is encrypted with `N8N_ENCRYPTION_KEY` and
cannot ship inside the workflow.

**Nothing to back up:** the built Docker images (`docker compose build`
recreates them), the sensor's local capture ring buffer (source of
truth is the VM once the sensor uploaded), and the LLM judge cache
(`llm_judge/cache/` - regenerates itself on demand).

---

## Troubleshooting

- **`Cannot reach the automation stack on set NETSEC_REMOTE_HOST`
  under the dashboard button.** The button probe couldn't reach
  `:8765` and/or `:5678` because `NETSEC_REMOTE_HOST` is empty. Set
  the three `NETSEC_REMOTE_*` variables plus `NETSEC_SSH_KEY` in the
  environment that starts the dashboard.
- **`sqlite3.OperationalError: unable to open database file` when
  running `create_sensor.py`.** The `ingest_api` container created
  `db/netsec.db` as root; run `create_sensor.py` via `sudo`, or use
  `docker compose exec` to run it as the same user the container uses.
- **First `docker compose up -d` seems stuck for minutes.** Normal -
  the `worker` image is installing torch, pandas, sklearn, weasyprint
  and friends into the built image. Watch it with
  `docker compose logs -f worker`. Only happens on rebuild.
- **Email arrives with `429 Too Many Requests` in the commentary.**
  Free-tier LLM key hit its per-minute limit. Lower
  `LLM_JUDGE_MAX_CANDIDATES` in `.env` or switch to a smaller / local
  model.
- **`HTTP 403 - error code: 1010`.** Cloudflare is blocking Python's
  default User-Agent. `llm_judge/llm_clients.py` already sends a
  custom one; if you patched that file, restore the User-Agent header.
- **The n8n workflow ran but no email.** Open the workflow's
  Executions tab in n8n. The failure is almost always the SMTP
  credential (wrong password, 2FA not enabled, wrong port).
- **Dashboard shows `[Errno 22] Invalid argument` on load.** The
  loader hit a PCAP with a pre-1970 timestamp. Use a capture recorded
  after 1970.

---

## What's out of scope for this quickstart

- **Dify** (RAG + chat agent). Not part of the ecosystem; you can run
  it separately on the same VM if you have RAM to spare (Dify's own
  stack is another 7 containers).
- **Multi-user routing.** Everything currently goes to whoever owns
  the SMTP credential. Add per-sensor routing in the n8n workflow if
  needed - the webhook payload includes `sha256`, `label` and `kind`.
- **Real-time capture triggers.** The design is: sensor pushes on
  every closed ring-buffer chunk; the ingest queue latency is
  seconds, not the 60 s poll cycle the earlier local-only stack used.

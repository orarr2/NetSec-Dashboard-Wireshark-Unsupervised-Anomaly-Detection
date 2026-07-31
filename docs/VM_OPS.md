# Operating your analysis VM

The setup guide is [`docs/VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md); this
document is the ongoing-operations cheat-sheet. Every block below is
paste-ready - substitute `<vm>` (your VM's Tailscale IP or hostname),
`<key>` (the SSH private key you registered with the provider), and
`<sensor>` (the name you used with `create_sensor.py`).

Nothing on the VM listens on the public interface except port 22 (see
[`docs/VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md#firewall) for the iptables
rules). Every command below assumes you connect over Tailscale or SSH.

---

## Connect

```bash
# From any machine on your tailnet:
ssh -i <key> ubuntu@<vm>

# Optional shortcut - add once to ~/.ssh/config:
#   Host netsec-vm
#     HostName <vm>
#     User     ubuntu
#     IdentityFile <key>
#     ServerAliveInterval 60
# then just:  ssh netsec-vm
```

Common blockers when SSH refuses:

- **Tailscale on the client is not up.** `tailscale status` should list
  the VM; if it says `NoState`, start the Tailscale tray app / daemon on
  the client and retry.
- **Wrong key permissions on Windows.** OpenSSH refuses keys world- or
  group-readable. Fix once with:
  `icacls <key> /inheritance:r; icacls <key> /grant:r "$env:USERNAME:(R)"`
- **`Permission denied (publickey)`.** The key file exists but is a
  directory; some providers download the key as a folder named after the
  key. Point `-i` at the file inside that folder, not the folder.

---

## Health snapshot

```bash
ssh -i <key> ubuntu@<vm> '
echo "=== containers ==="
cd ~/netsec/deploy && docker compose ps
echo
echo "=== ports (should all be bound to the Tailscale IP, not 0.0.0.0) ==="
sudo ss -tlnp | grep -E ":(5678|8765|8766)\b" | awk "{print \$4, \$7}"
echo
echo "=== ingest healthz ==="
curl -sS http://<vm>:8766/healthz
echo
echo "=== disk ==="
df -h / | tail -1
echo
echo "=== last analysis timestamp ==="
docker compose exec -T worker sh -c "python3 -c \"
from server import db
c = db.connect()
r = c.execute(\\\"SELECT MAX(finished_at) FROM sessions WHERE status=\\\\\\\"done\\\\\\\"\\\").fetchone()
print(r[0] or \\\"(no completed sessions yet)\\\")
\"" 2>/dev/null
'
```

---

## Watch a live analysis

```bash
# Stream the worker log until the current session finishes; Ctrl+C to stop.
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose logs -f worker'
```

Key markers to look for:

- `[cli] analyzing /srv/netsec/data/pcap/...` - worker claimed a queued job.
- `[<label>] advanced engines: N signal(s) across M device(s)` - the six
  MITRE-mapped detectors ran.
- `[cli] provider=... guardrail=on prompt=v0.3.0` - LLM judge starting.
- `[worker] session <id> done (<K> verdicts)` - success.
- `[worker] session <id> FAILED: <reason>` - error was recorded to the
  session row; the pipeline moves on and the queue keeps flowing.

---

## Redeploy after a `git pull`

Both the ingest_api and worker Dockerfiles `COPY` the repo into the
image at BUILD time - **not** at runtime - so `git pull` on the host is
invisible to the running containers until the image is rebuilt. Always
rebuild, then force-recreate. `force-recreate` alone reuses the same
image, so your new Python code stays outside the container.

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec
git pull --ff-only origin main
cd deploy
docker compose build ingest_api worker retention
docker compose up -d --force-recreate ingest_api worker retention
docker compose ps
'
```

The build is fast on a code-only change: torch, tshark, and every apt
layer are cached; only the final `COPY . .` layer re-runs.

---

## Look at a specific session

```bash
ssh -i <key> ubuntu@<vm> '
SID=${SID:-1}
echo "=== reports on disk ==="
sudo ls /srv/netsec/reports/$SID/
echo
echo "=== verdict summary ==="
sudo cat /srv/netsec/reports/$SID/verdicts.json | python3 -c "
import sys, json
v = json.load(sys.stdin)
s = v.get(\"stats\") or {}
print(f\"model={v.get(\\\"model\\\") or s.get(\\\"model\\\")}  cache_hits={s.get(\\\"cache_hits\\\")}  judged={s.get(\\\"judged\\\")}\")
for r in (v.get(\"results\") or [])[:8]:
    vd = r.get(\"verdict\") or {}
    print(f\"  {r.get(\\\"candidate_id\\\"):22s} -> {vd.get(\\\"verdict\\\"):11s} / {vd.get(\\\"category\\\")}\")
"
' SID=42   # <-- change to the session id you want to inspect
```

Fetch a report from your laptop instead of reading it on the VM:

```bash
scp -i <key> ubuntu@<vm>:/srv/netsec/reports/42/report.html ./
```

---

## Restart / stop / start a service

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose restart worker         # bounce the worker only
docker compose stop worker            # stop it
docker compose start worker           # start it
docker compose down                   # stop the whole stack (n8n stays)
docker compose up -d ingest_api worker retention
'
```

`docker compose restart` reuses the container's baked-in environment; if
you edited `.env`, use `up -d --force-recreate` instead so the new
values take effect.

---

## Back up the history DB

The `retention` service already snapshots the DB nightly to
`/srv/netsec/db/backups/` and prunes to `RETENTION_BACKUP_KEEP` copies
(default 14). Manual dump when you want one outside that schedule:

```bash
ssh -i <key> ubuntu@<vm> '
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/srv/netsec/db/backups/manual_$STAMP.db
sudo mkdir -p /srv/netsec/db/backups
sudo sqlite3 /srv/netsec/db/netsec.db ".backup $OUT"
sudo ls -lh /srv/netsec/db/backups/ | tail -5
'
# Pull it off the VM if you want an off-box copy:
scp -i <key> ubuntu@<vm>:/srv/netsec/db/backups/manual_*.db ./
```

---

## Rotate a compromised sensor

If a sensor's SECRET was pasted somewhere it should not have been:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
# 1. Revoke the old sensor
sudo NETSEC_DATA_ROOT=/srv/netsec python3 -c "
from server import db
c = db.connect()
c.execute(\"UPDATE sensors SET revoked_at=DATETIME(\\\"now\\\") WHERE name=?\", (\"<sensor>\",))
c.commit()
print(\"revoked:\", c.execute(\"SELECT name, revoked_at FROM sensors WHERE name=?\", (\"<sensor>\",)).fetchone())
"
# 2. Create a fresh sensor (any name; e.g. laptop2) - prints new creds ONCE
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py <sensor>2
'
```

Then update the client (dashboard, `tools/upload_pcap.py`, capture agent)
with the new `NETSEC_SENSOR_ID` and `NETSEC_SENSOR_SECRET`.

---

## Email delivery on completion

The worker walks a fallback chain: **SMTP first, n8n webhook as backup**
when SMTP fails. Recipient priority: the `X-Notify-Email` on the upload
wins over `NETSEC_NOTIFY_EMAIL` in `.env` (the solo-operator default).

Fill these lines in `~/netsec/deploy/.env` on the VM:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<your gmail address>
SMTP_PASS=<gmail app-password, 16 chars, NOT the account password>
SMTP_FROM=NetSec Analyzer <your gmail address>
NETSEC_NOTIFY_EMAIL=<optional fallback recipient>
N8N_WEBHOOK_URL=<optional; used only when SMTP itself fails>
```

Generate a Gmail app-password once at
`https://myaccount.google.com/apppasswords` (needs 2-Step Verification
enabled). Then rebuild + force-recreate the worker so the new env is
picked up - `docker compose restart` reuses the old baked-in values:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose up -d --force-recreate worker
'
```

Trigger a fresh upload with the address on the wire:

```bash
python3 tools/upload_pcap.py <capture.pcap> --email you@example.com
```

Confirm delivery from the worker log - one line per attempted mechanism:

```
[worker] notify [smtp]: report sent to you@example.com
```

or on failure with fallback:

```
[worker] notify FAILED [smtp]: SMTP authentication failed (535)...
[worker] notify [n8n_fallback]: n8n accepted (200)
```

## Activate the judge panel (multi-model deliberation)

`LLM_JUDGE_PANEL` in `.env` controls which models judge each capture.
Empty = single-judge mode (only `OPENAI_COMPAT_MODEL` runs). Two or
more judges gives you a real "committee discussion" - each model votes
independently, disagreements trigger a debate round, and the panel
transcript lands in the markdown report the email sends.

A safe Groq-only two-judge panel that survives one model's daily 429:

```
LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,openai_compat:openai/gpt-oss-20b
```

Each model has its own 100k-token/day free quota, so one model burning
out does not block the other. Force-recreate the worker after editing:

```bash
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose up -d --force-recreate worker'
```

## Free-tier LLM quota watch

If you set `LLM_JUDGE_QUOTA_DB=/srv/netsec/db/quota.db` in `.env`, each
judge call increments a counter. Read the current spend:

```bash
ssh -i <key> ubuntu@<vm> '
sudo sqlite3 /srv/netsec/db/quota.db "
SELECT provider, model, DATE(ts) day,
       SUM(tokens_in) tokens_in, SUM(tokens_out) tokens_out,
       COUNT(*) n
FROM llm_calls
WHERE ts >= DATETIME(\"now\", \"-24 hours\")
GROUP BY provider, model, DATE(ts)
ORDER BY day DESC, tokens_in DESC;
"
'
```

Groq's free tier is 100k tokens/day for the 70B family; if you cross it,
the judge returns a 429 that gets logged as a `judge failed` line -
adjust `LLM_JUDGE_PANEL` or switch to a local Ollama fallback rather
than pretending the panel voted.

---

## Uninstall / start over

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose down -v            # kills containers + named volumes
sudo rm -rf /srv/netsec/data /srv/netsec/reports /srv/netsec/db
# keep or drop the code:
# rm -rf ~/netsec
'
```

The `-v` on `down` removes the n8n volume too - back it up first if
you want your workflows and credentials preserved.

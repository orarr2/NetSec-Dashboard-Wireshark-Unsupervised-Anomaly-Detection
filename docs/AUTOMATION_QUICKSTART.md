# NetSec Automation Quickstart

The dashboard has a **Send S1 / S2 to n8n Alert** button in its sidebar
that, when the local `automation/` stack is running, ships the session's
PCAP through a judge (via Groq by default) and emails you an HTML alert
if any verdict is `malicious` or `suspicious`.

The automation is fully containerised. Everything runs inside Docker —
Windows, Mac, and Linux use the exact same commands. Nothing has to be
installed on the host beyond Docker itself and (for the dashboard side)
Python + Wireshark. The dashboard notebook works without any of this —
the button just refuses to copy the file, with a clear warning, when
the stack isn't up.

---

## What it is

Two containers, one docker-compose file:

| service    | port  | what it does                                             |
|------------|-------|----------------------------------------------------------|
| n8n        | 5678  | polls `incoming/` every 60 s, orchestrates, sends emails |
| judge_api  | 8765  | HTTP wrapper around `llm_judge/judge_cli.py`             |

Data flow when you click the button:

```
dashboard button  →  incoming/{SESSION}_{TS}_{name}.pcap
                                   │
                       n8n poll (60 s)
                                   ▼
                     judge_api /analyze
                                   │
                LLM provider (Groq by default)
                                   │
                    HTML email via Gmail
                                   │
                 PCAP moves to processed/
```

Everything under `automation/` is gitignored — secrets, DB volumes,
workflow templates, logs. Nothing there gets committed.

---

## Prerequisites

Install once:

1. **Docker Desktop** (Windows / Mac) or **Docker Engine + Compose plugin**
   (Linux). <https://www.docker.com/products/docker-desktop/>
2. **Wireshark** — only needed for the dashboard notebook side, to capture
   PCAPs. Not needed by the containers. <https://www.wireshark.org/>
3. **A Groq API key** — free tier, no credit card. Sign up at
   <https://console.groq.com>, create an API key that starts with `gsk_`.
4. **A Gmail App Password** — 16 characters. Requires 2FA on your Google
   account first, then generate at
   <https://myaccount.google.com/apppasswords>.

You do **not** need to install Python, Node.js, tshark, or any Python
package on the host to run the automation stack — all of that lives
inside the `judge_api` container.

---

## Configure once

From the repo root:

```bash
cd automation
cp .env.example .env
```

Open `.env` in an editor and fill in:

- `N8N_BASIC_AUTH_PASSWORD` — pick anything strong. This is the n8n admin
  login.
- `N8N_ENCRYPTION_KEY` — 32 random characters. Any of these work:
  - Linux / Mac: `openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32`
  - Windows PowerShell:
    `-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})`
  - **Losing this key wipes every credential you save inside n8n.** Back
    it up outside the repo (a password manager, encrypted file, etc.).
- `OPENAI_COMPAT_API_KEY` — paste the `gsk_...` Groq key.

Do NOT commit `.env`. It's gitignored, but double-check with `git status`
before pushing.

---

## Bring the stack up

One command, same on every OS:

```bash
docker compose up -d
```

**What happens on first run (5–10 min):**

1. Docker builds the `judge_api` image (~1 min).
2. `judge_api` container starts. Its entrypoint installs the project's
   Python dependencies (numpy, pandas, sklearn, torch, scapy, etc.) into
   a named volume so subsequent restarts skip this step.
3. `n8n` container starts and reaches port 5678.

**What happens on every subsequent run (few seconds):**

- Both containers restart in place. The pip install is cached in the
  named volume, so `judge_api` is ready almost immediately.

Verify:

```bash
docker compose ps
# both containers should read "Up ... (healthy)"

curl http://localhost:8765/health
# {"status":"ok", ...}
```

---

## Two manual steps in the n8n UI (one-time)

Open <http://localhost:5678> and log in with `admin` + the password from
`.env`.

### 1. Import and activate the workflow

- **Workflows** → **⋮** → **Import from File** → select
  `automation/n8n_workflows/mvp_triage_email.json`.
- Open the imported workflow. Toggle **Active** (top-right, next to
  Publish). This is what makes the 60-second schedule trigger actually
  fire — without it, the workflow only runs when you click "Execute
  workflow" by hand.

### 2. Add the Gmail SMTP credential

Sidebar → **Credentials** → **+ Add Credential** → search for **SMTP**.

| field    | value                                          |
|----------|------------------------------------------------|
| Name     | `Gmail SMTP` (any name, but be consistent)     |
| User     | your full Gmail address                        |
| Password | the 16-char App Password (spaces are ignored)  |
| Host     | `smtp.gmail.com`                               |
| Port     | `587`                                          |
| SSL/TLS  | **off** (STARTTLS on port 587)                 |

Save. Then open the workflow, click the **Send Gmail alert** node, and
set **Credential to connect with** to `Gmail SMTP`. Save the workflow.

That's it. Everything downstream is automated. Credentials only need to
be re-entered if the `n8n_data` volume is destroyed
(`docker compose down -v`).

---

## Auto-start on host boot

Both containers use `restart: unless-stopped`, so as long as the Docker
daemon is running they come back up on their own. To make Docker itself
start automatically:

- **Windows / Mac**: Docker Desktop → Settings → General → check
  "Start Docker Desktop when you sign in".
- **Linux**: `sudo systemctl enable docker`.

After that, you never need to run any command to bring the stack up. It
just is up.

---

## Verify it works end-to-end

Two independent ways:

**A. From the dashboard button** (the whole point of the stack).

1. Open the dashboard notebook, load any PCAP, click
   **Send S1 to n8n Alert** in the sidebar.
2. Watch the status message under the button. If the stack is up you'll
   see `✅ Copied to incoming/S1_<timestamp>_<filename>`. If it isn't,
   you'll see a `⚠️` block telling you exactly what's missing.
3. Wait ≈90 seconds. If any verdict is malicious or suspicious, an
   HTML alert lands in your inbox.

**B. By dropping a file directly.**

```bash
cp attack_tests/pcaps/xmas_scan.pcap incoming/
```

The workflow's next poll picks it up. Same ~90-second wait. The file
moves to `processed/{ts}_xmas_scan.pcap` on success so the same filename
can be re-analysed later.

---

## Tuning

Everything is env-driven. Change these in `automation/.env`, then
`docker compose restart judge_api`:

- `OPENAI_COMPAT_MODEL` — swap Groq models. `llama-3.3-70b-versatile` is
  strong but hits Groq's 12 000 tokens-per-minute free-tier limit at
  ≥5 candidates. `llama-3.1-8b-instant` is fast and cheap on tokens.
- `LLM_JUDGE_MAX_CANDIDATES` — how many flagged candidates to send to
  the LLM per PCAP. Default `3` keeps well under the Groq free-tier
  TPM ceiling. Raise it if you moved to a paid tier or a self-hosted
  model.
- `LLM_JUDGE_TIMEOUT_S` — per-request timeout in seconds. Default `600`.
- `LLM_JUDGE_PROVIDER` — set to `ollama` to use a local model instead of
  Groq. Requires Ollama running on the host with a pulled model, and
  the `judge_api` container reaches it via `host.docker.internal:11434`
  (already wired in the compose file).

---

## Backup and recovery

**What's persistent:**

- `automation/.env` — your secrets. Back it up outside the repo (a
  password manager, or an encrypted file in your personal cloud drive).
- Docker named volume `n8n_data` — n8n's SQLite DB, holds the workflow
  and credentials. Back up by exporting the DB from the container:

```bash
docker cp netsec-n8n:/home/node/.n8n/.n8n/database.sqlite \
  ./n8n_backup_$(date +%Y%m%d).sqlite
```

- Docker named volume `judge_api_deps` — the installed Python packages.
  Nothing to back up; if it goes, the next `docker compose up -d`
  re-installs from `requirements.txt` (5-10 min).

**If the n8n DB is lost** (`docker compose down -v`, disk failure,
Docker volume corruption): re-import `mvp_triage_email.json` and
re-create the Gmail SMTP credential in the UI. The workflow file ships
with the repo so it's always recoverable; the credential is
encrypted with `N8N_ENCRYPTION_KEY` and can't ship in the workflow.

---

## Troubleshooting

- **`⚠️ n8n automation stack is not running` under the button.** The
  dashboard's health probe couldn't reach `:8765` and/or `:5678`. Run
  `docker compose up -d` in `automation/` and try again.
- **First `docker compose up -d` seems stuck for minutes.** Normal —
  `judge_api` is downloading and installing torch, pandas, sklearn, and
  friends into its named volume. Watch it with
  `docker compose logs -f judge_api`. Only happens once per volume.
- **Email says `Judged: X (dropped: N)` and commentary is a `429` error.**
  You hit Groq's 12 000 TPM free-tier limit. Lower
  `LLM_JUDGE_MAX_CANDIDATES` in `.env` (default `3` is safe) or switch
  to `llama-3.1-8b-instant`.
- **Email arrives with `HTTP Error 403 - error code: 1010`.** Cloudflare
  is blocking Python's default `User-Agent`. `llm_judge/llm_clients.py`
  already sets a custom one; if you edited that file, restore the
  `User-Agent` header.
- **n8n workflow ran but no email.** Open the workflow's Executions tab
  in n8n. The failure is almost always the SMTP credential (wrong
  password, 2FA not enabled, wrong port).
- **Dashboard shows `[Errno 22] Invalid argument` on load.** Not
  related to the automation stack — the dashboard's figure builder
  can't handle PCAPs with pre-1970 timestamps. Use a PCAP captured
  after 1970.

---

## What's NOT automated

- **Dify** (RAG + chat agent). Deferred — the 7-container Dify stack
  needs more RAM than an 8 GB laptop can spare alongside n8n and
  `judge_api`. Revisit on a VPS or a bigger machine.
- **Multi-user Gmail routing.** Everything currently goes to whoever
  owns the SMTP credential.
- **Real-time capture triggers.** The workflow polls `incoming/` on a
  60 s schedule; if you need instantaneous alerting, add a webhook
  trigger and have the dashboard POST to it.

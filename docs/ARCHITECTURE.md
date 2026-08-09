# NetSec architecture

The stack has been redesigned around a single-VM always-on model. The
laptop is now optional: everything lives on a small ARM VM (Oracle
Always Free), fronted by one HTTPS + basic-auth entry point, reached
by all of your devices over Tailscale.

## What is where

```
INTERNET ---(only :22 open, brute-force-hardened)------------ VM public IP
    |
    x    (everything else REJECT'd by iptables + interface-bound)
    |
    v (Tailscale WireGuard, end-to-end encrypted)
                    +--------------------------+
[ iPhone ]  <-----> |                          |  <-----> [ Laptop ]
                    |    netsec-agent (VM)     |
                    |                          |
                    |  Caddy 443 (Let's Encrypt cert)
                    |     |                    |
                    |     +- basicauth (bcrypt)|
                    |     |                    |
                    |     +--> /       -> portal :8080
                    |     +--> /rag/   -> RAG   :5200  (Dash + Flask)
                    |     +--> /chat/  -> Companion :5100 (Dash)
                    |                          |
                    |  Ollama (loopback only :11434)
                    |     +- nomic-embed-text  (RAG's embedder)
                    |     +- qwen2.5:3b        (Companion + RAG default)
                    |     +- granite / gemma / llama / phi
                    |                          |
                    |  NetSec pipeline         |
                    |     +- ingest_api :8766  (HMAC-signed uploads)
                    |     +- worker            (queue -> analyze -> mail)
                    |     +- SQLite /srv/netsec/db/netsec.db
                    |     +- reports /srv/netsec/reports/<sid>/
                    |                          |
                    |  n8n :5678 (own login, workflow automation)
                    +--------------------------+
```

The **only URL you need to remember**: `https://netsec-agent.tail37ac21.ts.net/`.
Everything else is a subpath under it.

## Public exposure surface

Externally reachable from the whole internet:

| Port | Service | Auth | Notes |
|---|---|---|---|
| 22 | SSH | ssh key only, no passwords | 4-5k brute-force attempts a day - all rejected; consider closing to Tailscale only in a future pass |

Everything else is bound to `100.68.246.54` (the Tailscale interface)
or to `127.0.0.1` (loopback) - not routable from the internet.

## Reachable over Tailscale (private, encrypted)

| URL | Service | Auth | Notes |
|---|---|---|---|
| `https://netsec-agent.../` | Portal | Caddy basicauth | Landing page with cards for each service |
| `https://netsec-agent.../rag/` | RAG UI | Caddy basicauth | Dash chat over indexed NetSec reports + arbitrary docs |
| `https://netsec-agent.../chat/` | AI Companion | Caddy basicauth | Dash chat over local Ollama models with file drop |
| `https://netsec-agent.../rag/ask` | RAG REST | Caddy basicauth | POST `{"q":"..."}` for scripts / cron |
| `http://netsec-agent:8766` | Ingest API | HMAC per upload | Only the dashboard client hits it |
| `http://netsec-agent:5678` | n8n | n8n's own login | Workflow automation UI |

## Local-only (127.0.0.1 on the VM)

| Port | Service | Notes |
|---|---|---|
| 11434 | Ollama | Sibling containers (worker) reach it via docker DNS; the host RAG + Companion services reach it on loopback |

## The four apps in five sentences

- **Portal** is a static HTML page that lists every other service with a live status badge.
- **RAG** is retrieval-augmented QA over your NetSec reports plus any files you index (Dash UI matching Companion; streaming answers; sources as expandable cards).
- **Companion** is a chat UI over the local Ollama models with a drag-and-drop file feature (text, PDF, DOCX, PCAP).
- **NetSec pipeline** (ingest + worker) analyzes uploaded PCAPs with detectors + an LLM judge panel and mails the report.
- **n8n** runs alerting workflows (Gmail delivery, Telegram etc) on top of the pipeline output.

## Data flow: uploading a PCAP

1. Dashboard on your laptop signs the file with the sensor HMAC secret.
2. POST to `http://netsec-agent:8766/v1/pcap` (over Tailscale).
3. `ingest_api` verifies the signature, writes to `/srv/netsec/data/pcap/<year>/<month>/<day>/`, creates a `sessions` row.
4. `worker` polls the queue, loads the PCAP, runs feature extraction (tshark), ML (IsolationForest + DBSCAN), rules (scan/flood/amp/ARP/DNS), advanced engines (beacon/DGA/DNS-tunnel/TLS/ARP-DHCP).
5. LLM judge panel scores each candidate. Cache hits are free.
6. Report renderer writes `verdicts.json`, `verdicts.md`, `report.html`, `report.pdf`, `summary.md` under `/srv/netsec/reports/<sid>/`.
7. Mailer sends the summary + PDF attachment to the recipient stored on the session row.
8. RAG's periodic ingester (every 15 min via systemd timer) sees the new session and appends its chunks to the vector store, so questions like "which IPs were flagged in the last run?" become answerable within minutes.

## Data flow: asking the RAG

1. Browser hits `https://netsec-agent.../rag/` -> Caddy validates basicauth -> proxies to the RAG Dash app on 5200.
2. User types a question. The Dash callback creates a query row and spawns a worker thread.
3. Worker embeds the question with `nomic-embed-text` (via Ollama at 127.0.0.1:11434), does a cosine top-K over the SQLite vector store, and streams a token-by-token answer from `qwen2.5:3b`.
4. The UI polls at 300ms while streaming, painting the growing answer.

## Persistence

| Path | Contents |
|---|---|
| `/srv/netsec/db/netsec.db` | Server DB: sensors, pcap_files, sessions, verdicts, panel_audit, compare_jobs |
| `/srv/netsec/data/pcap/**` | Uploaded PCAPs |
| `/srv/netsec/reports/<sid>/` | Per-session reports |
| `/srv/netsec/reports/compare/<jid>/` | Pair-compare reports |
| `/srv/netsec/rag/store.db` | RAG vector store (chunks + embeddings + metadata) |
| `/srv/netsec/rag/queries.db` | RAG query history (for the sidebar) |
| `/srv/netsec/companion/chats.db` | Companion chat history |
| `docker volume ollama_models` | Pulled Ollama models |
| `docker volume n8n_data` | n8n workflows + credentials |
| `docker volume caddy_data` | Caddy internal CA + issued certs |
| `/etc/netsec-tls/*` | Tailscale-issued Let's Encrypt cert (renewed weekly by netsec-tls-renew.timer) |

## Ports

| Port | Bound to | Container / process |
|---|---|---|
| 22 | `0.0.0.0` | sshd |
| 443 | `100.68.246.54` | Caddy (host network, on the VM host) |
| 8766 | `100.68.246.54` | deploy-ingest_api-1 |
| 5678 | `100.68.246.54` | netsec-n8n (legacy container, own login) |
| 5100 | `100.68.246.54` | netsec-companion.service (systemd) |
| 5200 | `100.68.246.54` | netsec-rag.service (systemd) |
| 8080 | `100.68.246.54` | netsec-portal.service (systemd) |
| 11434 | `127.0.0.1` | deploy-ollama-1 (loopback exposure for RAG + Companion) |

## The systemd + Docker split

- **systemd** owns: Caddy (via `docker compose`), Companion, RAG, RAG ingest timer, TLS renewal timer, portal. These are the always-on user-facing services.
- **Docker Compose** owns: ingest_api, worker, retention, ollama, n8n, caddy. These are the data-plane containers.

If everything went dark, `sudo docker compose up -d` + `sudo systemctl start netsec-portal netsec-rag netsec-companion` brings the stack back.

## Auto-recovery

- Every user-facing service has `Restart=on-failure` in its systemd unit.
- The RAG index refresh has `Persistent=true` on its timer, so a missed run catches up on next boot.
- The TLS cert renews weekly (Sun 03:00) via `netsec-tls-renew.timer`; Caddy hot-reloads the new cert without restart.
- Ollama and n8n containers have `restart: unless-stopped` in compose.

The only chain that would silently break is: `Tailscale on the laptop` <-> `Tailscale on the VM` (both must be up for the user to reach the tailnet). The VM Tailscale runs as a system service under systemd, so it comes back with the VM.

## Rebuilding from zero on a fresh Oracle VM

See `deploy/README.md` for the exact commands. Roughly:

```
git clone <repo>
cd deploy
cp .env.example .env   # SMTP creds, N8N_ENCRYPTION_KEY, etc
sudo docker compose up -d ingest_api worker retention ollama caddy
bash install-rag.sh
bash install-companion.sh
sudo systemctl enable --now netsec-portal netsec-tls-renew.timer
BASIC_AUTH_USER=you BASIC_AUTH_HASH="$(docker run --rm caddy:2 caddy hash-password --plaintext YOURPW)" \
    bash install-caddy.sh
```

Then join the VM to your Tailscale account (`sudo tailscale up`) and enable HTTPS certs in the Tailscale admin console (`Enable HTTPS`). Point your iPhone / laptop's Tailscale at the same account. Reach the stack at `https://<hostname>.<your-tailnet>.ts.net/`.

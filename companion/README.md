# AI Companion

Chat with the Ollama models on your NetSec VM. Runs on the VM itself
as a systemd service, reachable at `https://netsec-agent.<tailnet>.ts.net/chat/`
behind Caddy's basic-auth. The same file can also be run on your laptop
in SSH-tunnel mode (the original design) if you prefer.

## What it does

- Sidebar with saved chats grouped by date (Today / Yesterday / …),
  rename + delete per row
- Streaming responses (token-by-token as the model generates), with
  the send button doubling as a stop button mid-stream
- Assistant replies render as markdown (code blocks, lists, tables);
  your own messages stay literal text
- Enter sends on a keyboard (Shift+Enter for a newline); on phones
  Enter stays a newline and the round button sends
- Dark + light theme (shared with the portal and RAG - flip it once,
  it applies across the whole site), mobile hamburger drawer,
  per-chat system prompt and temperature settings, slash commands
- No cloud, no API keys, no data leaves your machine

(The old paperclip file-drop was removed in the UI audit - one job,
chat. Use the RAG at `/rag/` for questions over the indexed reports.)

## Run modes

### On the VM (production - reachable from iPhone via Tailscale)

Handled by `deploy/install-companion.sh`. Creates a dedicated venv
at `/opt/netsec-companion/venv` with dash, drops the systemd unit
`netsec-companion.service`. Direct-mode - no SSH tunnel; talks to
Ollama at `127.0.0.1:11434`.

```
sudo systemctl status netsec-companion.service
```

Reach it at `https://netsec-agent.<tailnet>.ts.net/chat/` (Caddy
adds the login).

### On the laptop (dev / offline)

```
python companion.py
```

Opens an SSH tunnel to the VM's docker-internal Ollama, serves at
`http://127.0.0.1:5100`. Requires `~/.ssh/netsec-agent.key/...` to
exist. See `--help` for all flags.

### Defaults

- Ollama URL: from `--ollama-url` or `NETSEC_OLLAMA_URL` (VM mode)
  or via SSH tunnel (laptop mode).
- Chat DB: from `--db` or `NETSEC_COMPANION_DB` (default
  `~/ai-companion/chats.db`).
- URL base: from `--url-base` or `NETSEC_COMPANION_URL_BASE`
  (default `/`, VM mode uses `/chat/` so Caddy can path-route).
- Default model: **qwen2.5:3b** (multilingual - handles Hebrew,
  English, code).

### Slash commands (typed in the message box)

- `/model qwen2.5:3b` - switch model mid-chat
- `/system אתה מומחה לאבטחת מידע.` - set/replace the system prompt
- `/temp 0.2` - temperature (0-2)
- `/clear` - wipe messages of the current chat (keep the chat itself)
- `/save` - export the current chat to `~/ai-companion/exports/`
- `/help` - list commands

## Model expectations - read this

Local 2-3B-parameter models on a CPU-only ARM VM are useful for
plain chat, file explanation, and single-shot Q&A, but they have real
limits:

- **They do not know today's date.** They have no clock and no web.
  The default system prompt tells them today's date so they stop
  answering "the current date is [insert current date]".
- **They cannot look anything up.** No web, no NetSec data. For
  questions about YOUR captures use the RAG at `/rag/` instead - it
  IS indexed on the report archive.
- **Wall-clock is dominated by the ARM CPU**, not this app. Expect
  first-token latency of a few seconds on a quiet VM, tens of
  seconds when the NetSec worker is running an analysis at the same
  time.
- **They are not equally strong in every language.** For Hebrew /
  mixed English-Hebrew prompts, `qwen2.5:3b` or `gemma2:2b` do
  better than `granite3.3:2b`. The default picks the best available
  for language coverage.
- **Embedding models are filtered out of the picker.** If Ollama
  has `nomic-embed-text` (needed by the RAG) it will not show in
  the Companion model dropdown - it returns numeric vectors, not
  text, and would produce garbage in chat.

## What it does NOT do

- Not connected to NetSec, does not touch its DB or code.
- Does not install models. Pull new ones on the VM: `docker exec
  deploy-ollama-1 ollama pull <name>`.

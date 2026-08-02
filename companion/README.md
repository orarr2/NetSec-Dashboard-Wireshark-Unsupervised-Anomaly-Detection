# AI Companion

Local chat with the Ollama models running on the NetSec VM. Optional
tool in the NetSec repo - the dashboard and the analysis pipeline
run fine without it.

## What it does

Opens a browser UI, styled after llama.ui: sidebar with chat history
grouped by date, model picker at the top, chat panel, composer at
the bottom. Every model already installed on the VM (`ollama list`)
shows up in the picker automatically.

**No cloud, no API keys, no data leaves your machine** - the only
network flow is an SSH tunnel from this host to your own VM.

Mobile-friendly: the sidebar collapses into a hamburger drawer on
small screens, viewport respects iOS notch, `theme-color` and
`apple-mobile-web-app-capable` are set so Safari looks native. There
is a light/dark toggle in the top bar that persists across reloads.

## Run

```
python companion.py
```

Opens the browser at `http://127.0.0.1:5100`. From the Tailnet
(e.g. an iPhone with Tailscale on), reach it as
`http://<this-host-tailscale-name>:5100`.

Defaults:
- host: `100.68.246.54` (VM's Tailscale IP)
- user: `ubuntu`
- key: `~/.ssh/netsec-agent.key/ssh-key-2026-07-12.key`
- container: `deploy-ollama-1`
- default model: **qwen2.5:3b** (multilingual, handles Hebrew)

Override any of them via CLI flags or env vars (`NETSEC_VM_HOST`,
`NETSEC_VM_USER`, `NETSEC_SSH_KEY`).

To let devices in your Tailnet reach this instance
(iPhone / another laptop): `python companion.py --bind 0.0.0.0`.

## Model expectations - read this

Local 2-3B-parameter models on a CPU-only ARM VM are useful for
plain chat and single-shot Q&A, but they have real limits:

- **They do not know today's date.** They have no clock and no web.
  The default system prompt tells them today's date so they stop
  answering "the current date is [insert current date]".
- **They cannot look anything up.** No web, no NetSec data.
- **They are not equally strong in every language.** For Hebrew /
  mixed English-Hebrew prompts, `qwen2.5:3b` or `gemma2:2b` do
  better than `granite3.3:2b`. The default picks the best available
  for language coverage, not raw speed.
- **Wall-clock is dominated by the ARM CPU**, not this app. Expect
  first-token latency of a few seconds on a quiet VM, tens of
  seconds when the NetSec worker is running an analysis at the same
  time. The status badge in the top bar shows if the VM is reachable.

## Slash commands (typed in the message box)

- `/model qwen2.5:3b` - switch model mid-chat
- `/system אתה מומחה לאבטחת מידע.` - set/replace the system prompt
- `/temp 0.2` - temperature (0-2)
- `/clear` - wipe messages of the current chat (keep the chat itself)
- `/save` - export the current chat to `~/ai-companion/exports/`
- `/help` - list commands

## Chat storage

`~/ai-companion/chats.db` (SQLite, autocommit + WAL). Never syncs
anywhere. To wipe everything: delete that file.

## What it does NOT do

- Not connected to NetSec, does not touch its DB or code
- Does not open any new port on the VM - the tunnel is one-way SSH
- Does not install models. Pull new ones on the VM: `ollama pull <name>`

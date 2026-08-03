"""AI Companion - local chat over the Ollama models running on the NetSec VM.

Standalone. Not part of NetSec. Zero-config: brings up its own SSH tunnel
to the VM's docker-internal Ollama, discovers models via /api/tags,
streams responses to a browser UI. Chat history lives in a local SQLite.
No cloud, no API keys, no other people can see the port.

Usage:
    python companion.py
    python companion.py --host 100.68.246.54 --user ubuntu --model gemma2:2b

The tunnel goes down cleanly on Ctrl+C or when the browser closes the tab.
"""
import argparse
import atexit
import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone

# Dash only. dash-bootstrap-components is gone: the one dbc.Modal it
# styled is now a plain glass panel, which drops the 200KB SLATE CSS
# pull from a CDN - the app renders with zero internet access.
try:
    import dash
    from dash import Dash, dcc, html, Input, Output, State, no_update
except ImportError as e:
    print(f"[companion] missing UI dep: {e}\n"
          "install with: pip install dash",
          file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------
# VM tunnel
# --------------------------------------------------------------------------
class VMTunnel:
    """ssh -L 127.0.0.1:<local_port>:<container_ip>:11434 <user>@<host>.

    The Ollama container is not on Tailscale - it only listens on the
    docker-internal network - so we ask the VM for its IP first and
    forward TO that address through SSH. Tears down on __exit__ / atexit
    / SIGINT so the tunnel never outlives the process.
    """

    def __init__(self, host, user, key, container="deploy-ollama-1",
                 local_port=11434, ollama_port=11434):
        self.host, self.user, self.key = host, user, key
        self.container = container
        self.local_port = local_port
        self.ollama_port = ollama_port
        self.proc = None
        self.container_ip = None

    def _resolve_container_ip(self):
        """docker inspect on the VM to find the container's docker-internal
        IP. Runs a one-shot ssh; no long-lived connection at this stage."""
        cmd = [
            "ssh", "-i", self.key, "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", f"{self.user}@{self.host}",
            "sudo docker inspect -f "
            "'{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "
            f"{self.container}",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=20)
        except subprocess.TimeoutExpired:
            raise RuntimeError("timed out asking the VM for the Ollama "
                               "container IP - is SSH working with "
                               f"'ssh -i {self.key} {self.user}@"
                               f"{self.host} true' ?")
        if r.returncode != 0:
            raise RuntimeError(
                f"failed to resolve {self.container} on the VM "
                f"(exit {r.returncode}): {(r.stderr or r.stdout).strip()}")
        ip = (r.stdout or "").strip().split()
        if not ip or not ip[0]:
            raise RuntimeError(
                f"no IP for container {self.container!r} on the VM - "
                "is the ollama service up? "
                "check with: docker compose ps ollama")
        return ip[0]

    def open(self):
        self.container_ip = self._resolve_container_ip()
        # -N no remote command, -T no pty, -o ExitOnForwardFailure so we
        # notice immediately if 11434 is already in use locally.
        cmd = [
            "ssh", "-i", self.key, "-N", "-T",
            "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-L", (f"127.0.0.1:{self.local_port}:"
                   f"{self.container_ip}:{self.ollama_port}"),
            f"{self.user}@{self.host}",
        ]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # give ssh a moment to bind the local port before we probe
        for _ in range(30):
            time.sleep(0.2)
            if self._probe_ready():
                atexit.register(self.close)
                return self
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() or b"").decode(
                    "utf-8", errors="replace")
                raise RuntimeError(
                    f"ssh tunnel exited immediately (rc={self.proc.returncode})"
                    f": {err.strip() or '<no stderr>'}")
        self.close()
        raise RuntimeError(
            f"ssh tunnel came up but /api/tags never answered on "
            f"127.0.0.1:{self.local_port} - is Ollama listening on "
            f"{self.container_ip}:{self.ollama_port} inside the VM?")

    def _probe_ready(self):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.local_port}/api/tags",
                headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *a):
        self.close()


# --------------------------------------------------------------------------
# Ollama client (stream-first)
# --------------------------------------------------------------------------
class OllamaClient:
    """Thin urllib client for the two Ollama endpoints we use:
    /api/tags for the model list and /api/chat with stream=True for the
    per-token generator.
    """

    def __init__(self, base_url="http://127.0.0.1:11434"):
        self.base = base_url.rstrip("/")

    # Model families that produce embedding VECTORS, not chat text - if
    # picked in the dropdown they would return numeric garbage. Filter
    # them out. Anything that clearly is an embedder (name contains
    # "embed", or family is one of the known embedding architectures)
    # is hidden from the chat picker.
    _EMBED_FAMILY_HINTS = {"nomic-bert", "bert", "roberta", "mxbai-embed"}
    _EMBED_NAME_HINTS = ("embed", "-e5-", "bge-")

    def _is_chat_model(self, entry):
        name = (entry.get("name") or "").lower()
        if any(h in name for h in self._EMBED_NAME_HINTS):
            return False
        details = entry.get("details") or {}
        family = (details.get("family") or "").lower()
        families = [str(f).lower() for f in (details.get("families") or [])]
        if family in self._EMBED_FAMILY_HINTS:
            return False
        if any(f in self._EMBED_FAMILY_HINTS for f in families):
            return False
        return True

    def list_models(self):
        req = urllib.request.Request(f"{self.base}/api/tags")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        # Filter out embedding-only models (nomic-embed-text etc.); they
        # return vectors, not text, and are useless in a chat dropdown.
        # Sort by name so the dropdown order is stable across restarts.
        return sorted([m.get("name") for m in (data.get("models") or [])
                       if m.get("name") and self._is_chat_model(m)])

    def stream_chat(self, model, messages, options=None):
        """Yield dicts as Ollama emits them: each has 'message.content'
        for the incremental token, and the FINAL dict has 'done': True
        with prompt_eval_count / eval_count / total_duration."""
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "keep_alive": "30m",
            "options": options or {"temperature": 0.7},
        }
        req = urllib.request.Request(
            f"{self.base}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        # 900s: even a slow ARM CPU finishes a normal chat inside 15 min.
        with urllib.request.urlopen(req, timeout=900) as r:
            for raw in r:
                if not raw:
                    continue
                try:
                    yield json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    continue


# --------------------------------------------------------------------------
# Chat store (local SQLite)
# --------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    model TEXT,
    system_prompt TEXT,
    temperature REAL DEFAULT 0.7
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    chat_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    model TEXT,
    latency_ms INTEGER,
    tokens_in INTEGER,
    tokens_out INTEGER,
    FOREIGN KEY (chat_id) REFERENCES chats(id)
);
CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_chats_updated ON chats(updated_at DESC);
"""


# --------------------------------------------------------------------------
class ChatStore:
    def __init__(self, db_path):
        db_path = pathlib.Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None -> autocommit, so every executed statement
        # hits disk immediately. sqlite3's default "" mode wraps DML in an
        # implicit transaction that only commits on explicit .commit()
        # - across two threads that can leave a fresh INSERT invisible to
        # the other side until much later, which is exactly what bit us
        # when the streaming thread's SELECT saw no chats row for the
        # id the Dash thread had just created.
        self._db = sqlite3.connect(str(db_path), check_same_thread=False,
                                   isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def new_chat(self, model, system_prompt=None, title=None):
        cid = uuid.uuid4().hex[:12]
        now = self._now()
        # A fresh chat inherits the default system prompt UNLESS the
        # caller passed one explicitly. Without a prompt the model
        # makes up dates and answers Hebrew in English.
        if system_prompt is None:
            system_prompt = _default_system_prompt()
        with self._lock:
            self._db.execute(
                "INSERT INTO chats VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cid, title or "New chat", now, now, model,
                 system_prompt or "", 0.7))
            pass  # autocommit
        return cid

    def delete_chat(self, chat_id):
        with self._lock:
            self._db.execute("DELETE FROM messages WHERE chat_id=?",
                             (chat_id,))
            self._db.execute("DELETE FROM chats WHERE id=?", (chat_id,))
            pass  # autocommit

    def rename_chat(self, chat_id, title):
        with self._lock:
            self._db.execute(
                "UPDATE chats SET title=?, updated_at=? WHERE id=?",
                (title[:120], self._now(), chat_id))
            pass  # autocommit

    def set_chat_model(self, chat_id, model):
        with self._lock:
            self._db.execute("UPDATE chats SET model=?, updated_at=? "
                             "WHERE id=?",
                             (model, self._now(), chat_id))
            pass  # autocommit

    def set_chat_system(self, chat_id, system_prompt):
        with self._lock:
            self._db.execute(
                "UPDATE chats SET system_prompt=?, updated_at=? WHERE id=?",
                (system_prompt or "", self._now(), chat_id))
            pass  # autocommit

    def set_chat_temperature(self, chat_id, temperature):
        temp = max(0.0, min(2.0, float(temperature)))
        with self._lock:
            self._db.execute(
                "UPDATE chats SET temperature=?, updated_at=? WHERE id=?",
                (temp, self._now(), chat_id))
            pass  # autocommit

    def get_chat(self, chat_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
        return dict(row) if row else None

    def append_message(self, chat_id, role, content, model=None,
                       latency_ms=None, tokens_in=None, tokens_out=None):
        now = self._now()
        with self._lock:
            self._db.execute(
                "INSERT INTO messages (chat_id, role, content, created_at,"
                " model, latency_ms, tokens_in, tokens_out)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (chat_id, role, content, now, model, latency_ms,
                 tokens_in, tokens_out))
            # Set the chat title from the FIRST user message.
            row = self._db.execute(
                "SELECT title, (SELECT COUNT(*) FROM messages WHERE "
                "chat_id=? AND role='user') AS n_user"
                " FROM chats WHERE id=?", (chat_id, chat_id)).fetchone()
            if row and row["n_user"] == 1 and role == "user" \
                    and (row["title"] or "").strip() in ("", "New chat"):
                self._db.execute("UPDATE chats SET title=?, updated_at=? "
                                 "WHERE id=?",
                                 (content.strip().replace("\n", " ")[:60],
                                  now, chat_id))
            else:
                self._db.execute("UPDATE chats SET updated_at=? WHERE id=?",
                                 (now, chat_id))
            pass  # autocommit

    def list_messages(self, chat_id):
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM messages WHERE chat_id=? ORDER BY id",
                (chat_id,)).fetchall()
        return [dict(r) for r in rows]

    def list_chats_by_date_group(self):
        """Return an ordered [(group_label, [chat_dict, ...]), ...] using
        the same buckets llama.ui shows: Today, Yesterday, Previous 7
        Days, Previous 30 Days, then per-month."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM chats ORDER BY updated_at DESC").fetchall()
        buckets = {"Today": [], "Yesterday": [], "Previous 7 Days": [],
                   "Previous 30 Days": [], "Older": []}
        now = datetime.now(timezone.utc)
        for row in rows:
            row = dict(row)
            try:
                ts = datetime.fromisoformat(row["updated_at"])
            except Exception:
                continue
            age = (now - ts).days
            if age <= 0:
                buckets["Today"].append(row)
            elif age == 1:
                buckets["Yesterday"].append(row)
            elif age <= 7:
                buckets["Previous 7 Days"].append(row)
            elif age <= 30:
                buckets["Previous 30 Days"].append(row)
            else:
                buckets["Older"].append(row)
        return [(k, v) for k, v in buckets.items() if v]


# --------------------------------------------------------------------------
# Slash commands
# --------------------------------------------------------------------------
def parse_slash_command(text):
    """Return (verb, argument_str) or (None, text). Supports the small
    set the spec listed: /model /system /temp /save /clear /help."""
    if not text or not text.startswith("/"):
        return None, text
    parts = text.split(None, 1)
    verb = parts[0][1:].lower()
    if verb not in ("model", "system", "temp", "temperature", "save",
                    "clear", "help"):
        return None, text
    arg = parts[1] if len(parts) > 1 else ""
    return verb, arg


# --------------------------------------------------------------------------
# Streaming worker
# --------------------------------------------------------------------------
class StreamState:
    """One in-flight streaming reply. The Dash callback polls .snapshot()
    every ~150ms and paints whatever is there; a worker thread fills it
    token by token via .append() and calls .finish() at the end.
    """

    def __init__(self, chat_id, model):
        self.chat_id = chat_id
        self.model = model
        self._buf = []
        self._lock = threading.Lock()
        self._done = False
        self._error = None
        self._started_at = time.monotonic()
        self._tokens_out = 0
        self._tokens_in = 0
        self._cancelled = False

    def cancel(self):
        """User pressed stop. The worker checks this between chunks;
        breaking out of the read loop closes the connection, which is
        how Ollama learns to stop generating."""
        with self._lock:
            self._cancelled = True

    @property
    def cancelled(self):
        with self._lock:
            return self._cancelled

    def append(self, chunk):
        if not chunk:
            return
        with self._lock:
            self._buf.append(chunk)
            self._tokens_out += 1

    def finish(self, tokens_in=None, tokens_out=None, error=None):
        with self._lock:
            self._done = True
            if tokens_in is not None:
                self._tokens_in = tokens_in
            if tokens_out is not None:
                self._tokens_out = tokens_out
            self._error = error

    def snapshot(self):
        with self._lock:
            return {"content": "".join(self._buf),
                    "done": self._done,
                    "error": self._error,
                    "elapsed_s": time.monotonic() - self._started_at,
                    "tokens_in": self._tokens_in,
                    "tokens_out": self._tokens_out,
                    "model": self.model}


# One StreamState per chat that is currently being served. Cleared once
# the reply lands and the client polls one final "done" tick.
_STREAMS = {}
_STREAMS_LOCK = threading.Lock()


def _run_stream(client, store, chat_id, model, messages, options,
                state):
    try:
        info = {}
        for chunk in client.stream_chat(model, messages, options):
            if state.cancelled:
                break
            piece = ((chunk.get("message") or {}).get("content") or "")
            if piece:
                state.append(piece)
            if chunk.get("done"):
                info = chunk
                break
        # persist the completed assistant message (or whatever had
        # streamed in by the time the user pressed stop)
        content = state.snapshot()["content"]
        if state.cancelled:
            # a stop mid-code-fence leaves the fence open and the
            # marker would render as code; close it first. The marker
            # itself is emphasis, not [brackets] - markdown eats those.
            if content.count("```") % 2 == 1:
                content += "\n```"
            marker = "*(stopped)*"
            content = (content + "\n\n" + marker) if content else marker
        latency_ms = int(state.snapshot()["elapsed_s"] * 1000)
        store.append_message(chat_id, "assistant", content, model=model,
                             latency_ms=latency_ms,
                             tokens_in=info.get("prompt_eval_count"),
                             tokens_out=info.get("eval_count"))
        state.finish(tokens_in=info.get("prompt_eval_count"),
                     tokens_out=info.get("eval_count"))
    except Exception as e:
        state.finish(error=str(e))
        store.append_message(chat_id, "assistant",
                             f"[error: {e}]", model=model)


# --------------------------------------------------------------------------
# Dash UI
# --------------------------------------------------------------------------
_SUGGESTIONS = [
    ("Explain a concept", "Explain how HMAC works, in plain English."),
    ("Summarize a text",
     "Summarize this text into three bullet points: <paste your text>"),
    ("Help write an email",
     "Help me write a short polite email to a client that our meeting "
     "is postponed to next week."),
    ("Debug some code",
     "I'm getting `KeyError: 'session_id'`. Ask me follow-up questions "
     "until you can suggest a fix."),
]

# Default system prompt: teaches the model its own limits so it stops
# making up dates ("The current date is [insert current date]"). The
# model has no clock, no web, no NetSec context. Also nudges it to
# answer in the language the user wrote in - default granite ignored
# Hebrew and answered English on the first try.
def _default_system_prompt():
    from datetime import datetime as _dt
    today = _dt.now().strftime("%A %d %B %Y")
    return (
        "You are a helpful assistant running LOCALLY on the user's VM "
        "with no internet access, no tools, no memory across chats.\n"
        f"For your reference: today's date is {today}. Anything else "
        "time-sensitive is unknown to you - say so plainly, don't guess.\n"
        "Answer in the SAME language the user wrote in. If the user "
        "writes in Hebrew, answer in Hebrew. If English, English.\n"
        "Be concise: one paragraph unless the user asks for detail."
    )

def _load_brand_asset(name):
    """Read a shared brand asset (CSS or base64 data-URL) so all UIs -
    Portal, RAG, Companion - render in the same Aurora language as the
    dashboard notebook."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.path.join(here, "..", "deploy", "brand", name),
                      os.path.join("/home/ubuntu/netsec/deploy/brand", name)):
        try:
            with open(os.path.abspath(candidate), encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            continue
    return ""


_BRAND_CSS = _load_brand_asset("netsec-brand.css")
_LOGO_DATA_URL = _load_brand_asset("netsec-logo.b64").strip()


_APP_CSS = "<style>" + _BRAND_CSS + """
/* -------- Companion-specific overrides on top of the shared tokens ----- */
* { box-sizing: border-box; }
body { overflow: hidden; margin: 0; height: 100%; }
.companion-app { display: flex; height: 100vh; height: 100dvh;
  position: relative; }

/* SIDEBAR */
.sidebar { width: 260px;
  background: var(--bar-bg-strong);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-right: 1px solid var(--glass-border);
  padding: 12px 10px calc(14px + env(safe-area-inset-bottom));
  overflow-y: auto; overscroll-behavior: contain; flex-shrink: 0;
  display: flex; flex-direction: column; }
.sidebar h2 { font-size: 11px; letter-spacing: 0.14em; color: var(--ink-mute);
  text-transform: uppercase; margin: 14px 6px 6px; font-weight: 600;
  font-family: "SF Mono", monospace; }
.sidebar .chat-row { padding: 8px 10px; border-radius: 10px;
  font-size: 13px; color: var(--ink-dim); margin: 2px 0;
  display: flex; align-items: center; gap: 4px; }
.sidebar .chat-row:hover { background: var(--glass-bg-strong);
  color: var(--ink); }
.sidebar .chat-row.active { background: var(--glass-bg-strong);
  color: var(--violet-bright); font-weight: 500;
  border-left: 2px solid var(--violet); padding-left: 8px; }
.sidebar .chat-title { flex: 1; cursor: pointer; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }
.sidebar .chat-actions { display: none; gap: 2px; flex-shrink: 0; }
.sidebar .chat-row:hover .chat-actions { display: flex; }
.sidebar .chat-action { background: transparent; border: none;
  color: var(--ink-mute); cursor: pointer; font-size: 13px;
  padding: 2px 6px; border-radius: 6px; line-height: 1; }
.sidebar .chat-action:hover { color: var(--violet-bright);
  background: rgba(139, 92, 246, 0.15); }
/* Mobile: actions always visible (no hover on touch) */
@media (max-width: 699px) {
  .sidebar .chat-actions { display: flex; }
}
.sidebar .new-btn { display: flex; align-items: center; width: 100%;
  padding: 10px 14px; background: var(--glass-bg-strong); color: var(--ink);
  border: 1px solid var(--glass-border); border-radius: 10px;
  font-size: 13px; cursor: pointer; margin-bottom: 8px;
  font-family: var(--font-sans); }
.sidebar .new-btn:hover { background: var(--glass-bg-strong);
  border-color: var(--violet); color: var(--violet-bright); }
.sidebar .footer-note { margin-top: auto; color: var(--ink-mute);
  font-size: 10.5px; padding: 12px 6px 0;
  border-top: 1px solid var(--glass-border);
  font-family: "SF Mono", monospace; }

/* BACKDROP */
.backdrop { display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,0.5); z-index: 40; }

/* MAIN */
.main { flex: 1; display: flex; flex-direction: column;
  min-width: 0; height: 100vh; height: 100dvh; }
.topbar { padding: calc(12px + env(safe-area-inset-top)) 20px 12px;
  border-bottom: 1px solid var(--glass-border);
  background: var(--bar-bg);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
.topbar .hamburger { display: none; background: none; border: none;
  color: var(--ink); font-size: 22px; cursor: pointer; padding: 4px 8px;
  line-height: 1; }
.topbar .brand-logo { height: 22px; display: block; }
.topbar .brand { font-weight: 600; font-size: 13px;
  letter-spacing: 0.06em; text-transform: uppercase;
  font-family: "SF Mono", monospace; color: var(--ink); }
.topbar .sep { color: var(--ink-mute); }
.topbar .grow { flex: 1; }
.topbar .theme-btn, .topbar .settings-btn {
  background: var(--glass-bg-strong); border: 1px solid var(--glass-border);
  color: var(--ink); cursor: pointer;
  font-size: 15px; padding: 6px 10px; border-radius: 10px; }
.topbar .theme-btn:hover, .topbar .settings-btn:hover {
  border-color: var(--violet); color: var(--violet-bright); }

/* Dash dropdowns - inherit theme + open ABOVE all other content */
.Select-control, .Select-value, .Select-input {
  background: var(--glass-bg-strong) !important; color: var(--ink) !important;
  border-color: var(--glass-border) !important; }
.Select-value-label { color: var(--ink) !important; }
.Select-option { background: var(--bg-panel) !important;
  color: var(--ink) !important; }
.Select-option.is-focused { background: var(--glass-bg-strong) !important; }
/* z-index: 200 so the option menu paints ABOVE the chat area / message
   bubbles / composer (they had no z-index so browser stacked them
   later, hiding the top of the dropdown menu). */
.Select-menu-outer { z-index: 200 !important;
  background: var(--bg-panel) !important;
  color: var(--ink) !important;
  border-color: var(--glass-border) !important;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4); }
/* Give the topbar its own stacking context so the dropdown menu can
   escape it without being clipped by sibling flex containers. */
.topbar { position: relative; z-index: 100; overflow: visible !important; }
/* Model picker sizing lives here (was an inline style, which media
   queries cannot override): flexible on desktop, and on narrow phones
   it gives ground so the theme + settings buttons stay on screen. */
.model-select { min-width: 150px; max-width: 260px; flex: 1 1 200px; }
@media (max-width: 480px) {
  .model-select { min-width: 0; max-width: none; flex: 1 1 140px; }
}

/* CHAT AREA */
.chat-area { flex: 1; overflow-y: auto; padding: 20px 16px 24px;
  -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
@media (min-width: 700px) { .chat-area { padding: 24px 28px; } }
.msg { max-width: 820px; margin: 12px auto; padding: 14px 18px;
  border-radius: 16px; line-height: 1.6; white-space: pre-wrap;
  word-wrap: break-word; font-size: 14.5px; }
/* Assistant replies render as markdown; pre-wrap would double every
   newline of the SOURCE text on top of the <p> margins. */
.msg.assistant { white-space: normal; }
.msg.assistant .msg-body > p:first-child { margin-top: 0; }
.msg.assistant .msg-body > p:last-child { margin-bottom: 0; }
.msg.assistant .msg-body p { margin: 8px 0; }
.msg.assistant .msg-body ul, .msg.assistant .msg-body ol {
  margin: 8px 0; padding-left: 22px; }
/* Code blocks stay dark in BOTH themes (the hljs dark palette needs
   a dark ground); hljs's own background is neutralized so the pre
   rules here govern. */
.msg.assistant .msg-body pre { background: #0c0818;
  border: 1px solid var(--glass-border); border-radius: 10px;
  padding: 10px 12px; overflow-x: auto; font-size: 12.5px;
  white-space: pre; }
.msg.assistant .msg-body pre code, .msg.assistant .msg-body .hljs {
  background: transparent; }
.msg.assistant .msg-body code { font-size: 12.5px; }
.msg.assistant .msg-body :not(pre) > code {
  background: var(--glass-bg-strong); border: 1px solid var(--glass-border);
  border-radius: 5px; padding: 1px 5px; }
.msg.assistant .msg-body table { border-collapse: collapse; margin: 8px 0;
  display: block; overflow-x: auto; }
.msg.assistant .msg-body th, .msg.assistant .msg-body td {
  border: 1px solid var(--glass-border); padding: 4px 10px; font-size: 13px; }
.msg.assistant .msg-body blockquote { margin: 8px 0;
  padding: 2px 12px; border-left: 3px solid var(--violet);
  color: var(--ink-dim); }
.msg.user { background: linear-gradient(135deg,
    rgba(139, 92, 246, 0.18), rgba(139, 92, 246, 0.06));
  border: 1px solid rgba(139, 92, 246, 0.28); color: var(--ink); }
.msg.assistant { background: var(--glass-bg); color: var(--ink);
  border: 1px solid var(--glass-border);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur); }
.msg.error { background: rgba(248, 113, 113, 0.15); color: var(--red-accent);
  border: 1px solid rgba(248, 113, 113, 0.4); }
.msg-body { unicode-bidi: plaintext; }
.meta { font-size: 11px; color: var(--ink-mute); margin-top: 8px;
  font-family: "SF Mono", "JetBrains Mono", Consolas, monospace; }
.role-label { font-size: 10.5px; color: var(--ink-mute);
  letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 6px;
  font-weight: 600; font-family: "SF Mono", monospace; }

/* WELCOME */
.welcome { text-align: center; padding: 48px 12px 20px;
  color: var(--ink); }
.welcome h1 { font-size: 32px; margin: 0 0 8px; color: var(--ink);
  font-weight: 700; letter-spacing: -0.01em; }
.welcome p { color: var(--ink-dim); margin: 0 0 26px; font-size: 14px; }
.suggestions { display: grid; grid-template-columns: 1fr;
  gap: 10px; max-width: 680px; margin: 0 auto; padding: 0 12px; }
@media (min-width: 700px) {
  .suggestions { grid-template-columns: 1fr 1fr; }
}
.suggestion { background: var(--glass-bg); border: 1px solid var(--glass-border);
  border-radius: 12px; padding: 14px 16px; font-size: 13px;
  cursor: pointer; color: var(--ink); text-align: left;
  font-family: var(--font-sans);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur); }
.suggestion:hover { background: var(--glass-bg-strong);
  border-color: var(--violet); }

/* COMPOSER */
.composer { padding: 12px 14px calc(16px + env(safe-area-inset-bottom));
  border-top: 1px solid var(--glass-border);
  background: var(--bar-bg);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  flex-shrink: 0; }
@media (min-width: 700px) {
  .composer { padding: 14px 28px calc(18px + env(safe-area-inset-bottom)); }
}
.composer-inner { max-width: 820px; margin: 0 auto; position: relative; }
.composer textarea { width: 100%; background: var(--glass-bg-strong);
  border: 1px solid var(--glass-border); color: var(--ink);
  border-radius: 14px; padding: 12px 52px 12px 14px;
  font-size: 15px; resize: none; font-family: var(--font-sans); outline: none;
  -webkit-appearance: none; }
/* 16px on touch screens: below that iOS Safari force-zooms the page
   on focus (the old workaround was user-scalable=no, which also broke
   pinch-zoom for people who need it). */
@media (pointer: coarse) { .composer textarea { font-size: 16px; } }
.composer textarea:focus { border-color: var(--violet); }
.composer .send-btn { position: absolute; right: 8px; bottom: 8px;
  width: 36px; height: 36px; border-radius: 50%;
  background: linear-gradient(135deg, var(--violet), var(--violet-bright));
  color: #fff; border: none; cursor: pointer; font-size: 16px;
  box-shadow: 0 4px 16px rgba(139, 92, 246, 0.35); }
.composer .send-btn:hover { filter: brightness(1.1); }
/* While a reply streams the same button reads as STOP. */
.composer .send-btn.stop {
  background: linear-gradient(135deg, var(--red-accent), var(--magenta));
  box-shadow: 0 4px 16px rgba(248, 113, 113, 0.35); }
.footer { text-align: center; color: var(--ink-mute); font-size: 10.5px;
  padding: 8px 8px 0; font-family: "SF Mono", monospace; }
.badge { display: inline-flex; align-items: center; padding: 3px 10px;
  border-radius: 999px; font-size: 10.5px; margin-left: 6px;
  background: var(--glass-bg-strong); color: var(--ink-dim);
  border: 1px solid var(--glass-border);
  font-family: "SF Mono", "JetBrains Mono", monospace; }
.badge.warn { background: rgba(251, 191, 36, 0.15); color: var(--amber);
  border-color: rgba(251, 191, 36, 0.4); }

/* SETTINGS MODAL (plain glass panel; used to be a Bootstrap dbc.Modal) */
.modal-wrap { display: none; position: fixed; inset: 0; z-index: 300; }
.modal-wrap.show { display: block; }
.modal-wrap .modal-backdrop { position: absolute; inset: 0;
  background: rgba(0, 0, 0, 0.5); }
.modal-wrap .modal-panel { position: absolute; left: 50%; top: 50%;
  transform: translate(-50%, -50%);
  width: min(480px, calc(100vw - 32px));
  max-height: min(560px, calc(100dvh - 48px)); overflow-y: auto;
  background: var(--bg-panel); border: 1px solid var(--glass-border-strong);
  border-radius: var(--radius-card); padding: 18px 20px;
  box-shadow: var(--shadow-lift); }
.modal-panel h3 { margin: 0 0 14px; }
.modal-panel label { display: block; font-size: 11.5px;
  color: var(--ink-dim); margin: 12px 0 6px; letter-spacing: 0.06em;
  text-transform: uppercase; font-family: "SF Mono", monospace; }
.modal-panel textarea { width: 100%; }
.modal-panel .modal-actions { display: flex; justify-content: flex-end;
  gap: 10px; margin-top: 16px; }

/* MOBILE */
@media (max-width: 699px) {
  /* Above the topbar (z 100): the drawer used to slide UNDER it,
     hiding the New-chat button behind the bar. */
  .sidebar { position: fixed; left: 0; top: 0; bottom: 0;
    width: 82vw; max-width: 320px; z-index: 150;
    transform: translateX(-100%); transition: transform 0.2s ease; }
  .backdrop { z-index: 140; }
  .sidebar.open { transform: translateX(0); }
  .backdrop.show { display: block; }
  .topbar .hamburger { display: block; }
  .topbar .brand-vm-badge { display: none; }
  .main { width: 100%; }
  .topbar { padding: calc(10px + env(safe-area-inset-top)) 14px 10px; }
}
/* Very narrow phones: the logo alone identifies the app; the wordmark
   made the model dropdown unusably cramped. */
@media (max-width: 480px) {
  .topbar .brand, .topbar .sep { display: none; }
}
</style>
"""


def _render_history(store, active_chat_id):
    """One row per chat: title on the left, hover-visible action icons on
    the right (rename, delete). Same pattern as Claude/ChatGPT sidebars.
    Clicking the title loads the chat; clicking an icon fires its own
    pattern-matching callback and skips the load."""
    rows = []
    for label, chats in store.list_chats_by_date_group():
        rows.append(html.H2(label, className="section-title"))
        for c in chats:
            row = html.Div([
                html.Div(
                    c["title"] or "(untitled)",
                    id={"type": "load-chat", "id": c["id"]},
                    n_clicks=0,
                    className="chat-title",
                    title=(f"{c['updated_at']} · "
                           f"{c.get('model') or '?'}")),
                html.Div([
                    html.Button("✎",
                                id={"type": "rename-chat", "id": c["id"]},
                                n_clicks=0,
                                className="chat-action",
                                title="Rename"),
                    html.Button("🗑",
                                id={"type": "delete-chat", "id": c["id"]},
                                n_clicks=0,
                                className="chat-action",
                                title="Delete"),
                ], className="chat-actions"),
            ], className=("chat-row active"
                          if c["id"] == active_chat_id else "chat-row"))
            rows.append(row)
    if not rows:
        rows.append(html.Div("No chats yet. Say hi!",
                             style={"color": "#55555c", "fontSize": "11.5px",
                                    "padding": "6px"}))
    return rows


def _render_messages(msgs, live_stream=None):
    """Render the message list. If live_stream is not None, append the
    in-flight assistant message with its running content."""
    if not msgs and not live_stream:
        return _welcome_screen()
    def _body(role, content):
        # Assistant text is markdown (models emit headers, lists, code
        # fences); rendering it beats showing raw ``` noise. User and
        # system text stays literal - pasted content must never be
        # reinterpreted as markup.
        if role == "assistant":
            return dcc.Markdown(content, className="msg-body",
                                link_target="_blank",
                                highlight_config={"theme": "dark"})
        return html.Div(content, className="msg-body")

    out = []
    for m in msgs:
        role = m["role"]
        classes = "msg " + role
        meta_bits = []
        if m.get("model"):
            meta_bits.append(m["model"])
        if m.get("latency_ms"):
            meta_bits.append(f"{m['latency_ms']/1000:.1f}s")
        if m.get("tokens_out"):
            tok_s = ""
            if m.get("latency_ms") and m["latency_ms"] > 0:
                tok_s = f" · {m['tokens_out'] * 1000 / m['latency_ms']:.1f} tok/s"
            meta_bits.append(f"{m['tokens_out']} tok" + tok_s)
        meta = " · ".join(meta_bits)
        out.append(html.Div([
            html.Div(role.upper(), className="role-label"),
            _body(role, m["content"]),
            html.Div(meta, className="meta") if meta else None,
        ], className=classes))
    if live_stream is not None:
        s = live_stream.snapshot()
        content = s["content"] or "…"
        if s["error"]:
            out.append(html.Div([
                html.Div("ASSISTANT", className="role-label"),
                html.Div(f"[error: {s['error']}]"),
            ], className="msg error"))
        else:
            meta = (f"{s['model']} · {s['elapsed_s']:.1f}s · "
                    f"{s['tokens_out']} tok"
                    + (" · streaming…" if not s["done"] else ""))
            out.append(html.Div([
                html.Div("ASSISTANT", className="role-label"),
                _body("assistant", content),
                html.Div(meta, className="meta"),
            ], className="msg assistant"))
    return out


def _welcome_screen():
    return html.Div([
        html.Div([
            html.H1("Hi,"),
            html.P("how can I help you?"),
            html.Div([
                html.Button(html.Div([html.Div(label,
                                               style={"fontWeight": 500}),
                                      html.Div(prompt[:60] + ("…" if
                                               len(prompt) > 60 else ""),
                                               style={"color": "#7a7a82",
                                                      "marginTop": "4px",
                                                      "fontSize": "11px"})]),
                            id={"type": "suggestion", "text": prompt},
                            n_clicks=0, className="suggestion")
                for label, prompt in _SUGGESTIONS
            ], className="suggestions"),
        ], className="welcome"),
    ])


def build_app(tunnel, client, store, port, url_base=None):
    """Assemble and return the Dash app. All state (active chat, streams)
    lives in dcc.Store components so a browser refresh finds itself again.

    url_base: when set (e.g. "/chat/"), Dash prefixes every asset URL,
    callback and route so the whole app is reachable at that subpath.
    Needed when the app sits behind a Caddy reverse proxy that uses path
    routing. Must start AND end with "/" per Dash's rules."""
    dash_kwargs = dict(title="AI Companion",
                       update_title=None,
                       suppress_callback_exceptions=True)
    if url_base:
        if not (url_base.startswith("/") and url_base.endswith("/")):
            raise ValueError(f"--url-base must start and end with '/', "
                             f"got {url_base!r}")
        dash_kwargs["url_base_pathname"] = url_base
    app = Dash(__name__, **dash_kwargs)
    # viewport-fit=cover so iOS Safari respects the notch. Zoom stays
    # enabled (a11y); the 16px composer font is what stops the iOS
    # focus-zoom now. Theme-color matches the Aurora background and is
    # re-synced by the theme toggle. Icons come from the portal's
    # /brand/ path; standalone runs 404 them harmlessly.
    _META = ('<meta name="viewport" content="width=device-width,'
             'initial-scale=1,viewport-fit=cover">'
             '<meta name="theme-color" content="#07050f">'
             '<meta name="apple-mobile-web-app-capable" content="yes">'
             '<meta name="apple-mobile-web-app-status-bar-style" '
             'content="black-translucent">'
             '<link rel="icon" href="/brand/favicon.svg" '
             'type="image/svg+xml">'
             '<link rel="apple-touch-icon" '
             'href="/brand/apple-touch-icon.png">')
    # Behaviors React re-renders would otherwise tear down live on
    # document-level listeners: Enter-to-send on pointer-fine devices,
    # keep-scrolled-to-bottom while a reply streams, and the ?prompt=
    # handoff from the portal's latest-session card.
    _BOOT_JS = """<script>
(function () {
  // Enter sends on keyboards; phones keep Enter = newline.
  document.addEventListener("keydown", function (e) {
    if (e.target && e.target.id === "composer-text"
        && e.key === "Enter" && !e.shiftKey && !e.isComposing
        && window.matchMedia("(pointer: fine)").matches) {
      e.preventDefault();
      var btn = document.getElementById("send-btn");
      if (btn) btn.click();
    }
  });

  // Follow the stream: while the user is near the bottom, new tokens
  // keep the view pinned there; scrolling up to read pauses it.
  var follow = true;
  document.addEventListener("scroll", function (e) {
    var a = e.target;
    if (!a || a.id !== "chat-area") return;
    follow = (a.scrollHeight - a.scrollTop - a.clientHeight) < 220;
  }, true);
  new MutationObserver(function () {
    var a = document.getElementById("chat-area");
    if (a && follow) a.scrollTop = a.scrollHeight;
  }).observe(document.body, {childList: true, subtree: true});

  // ?prompt=... pre-fills the composer (used by the portal). The
  // param is stripped from the URL so a refresh does not refill.
  var q = new URLSearchParams(location.search).get("prompt");
  if (q) {
    history.replaceState(null, "", location.pathname);
    var t = setInterval(function () {
      var el = document.getElementById("composer-text");
      if (!el) return;
      clearInterval(t);
      var setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, "value").set;
      setter.call(el, q);
      el.dispatchEvent(new Event("input", {bubbles: true}));
      el.focus();
    }, 100);
  }
})();
</script>"""
    app.index_string = ("<!DOCTYPE html><html><head>{%metas%}"
                        + _META
                        + "<title>{%title%}</title>{%favicon%}{%css%}"
                        + _APP_CSS
                        + "</head><body>{%app_entry%}<footer>{%config%}"
                        "{%scripts%}{%renderer%}</footer>"
                        + _BOOT_JS
                        + "</body></html>")

    try:
        available_models = client.list_models()
    except Exception as e:
        available_models = []
        print(f"[companion] warning: could not list models: {e}",
              file=sys.stderr)
    if not available_models:
        available_models = ["<no models found - install with 'ollama pull'>"]
    # Model default: pick by "best conversation quality for its size",
    # not the fastest one. granite3.3:2b answers in 0.4 s but ignores
    # Hebrew and hallucinates dates. qwen2.5:3b and gemma2:2b are
    # multilingual and better at instruction-following.
    _model_pref = ["qwen2.5:3b", "gemma2:2b", "llama3.2:3b",
                   "phi3.5:latest", "granite3.3:2b"]
    default_model = next((m for m in _model_pref if m in available_models),
                         available_models[0])

    app.layout = html.Div([
        dcc.Store(id="active-chat-id", storage_type="session"),
        dcc.Store(id="stream-token"),           # bumps on send to arm poll
        dcc.Store(id="sidebar-open", data=False),
        # Payload from the sidebar rename/delete icons - the browser
        # runs prompt()/confirm() and drops the result here for the
        # server to apply.
        dcc.Store(id="sidebar-action"),
        # Poll is always on: 300 ms while a stream is live (fast paint),
        # 2 s otherwise (light background refresh so a new chat opened
        # from another window shows up, and so the final assistant frame
        # lands even if the stream-token bump was missed).
        dcc.Interval(id="stream-poll", interval=2000, disabled=False),
        html.Div([
            # backdrop for mobile: taps here close the drawer
            html.Div(id="sidebar-backdrop", className="backdrop",
                     n_clicks=0),
            # ---- sidebar ------------------------------------------------
            html.Div([
                html.Button([html.Span("✎  ", style={"marginRight": "6px"}),
                             "New chat"],
                            id="new-chat-btn", n_clicks=0,
                            className="new-btn"),
                html.Div(id="history-list"),
                html.Div("Chats saved locally in "
                         f"~/ai-companion/chats.db",
                         className="footer-note"),
            ], id="sidebar", className="sidebar"),
            # ---- main ---------------------------------------------------
            html.Div([
                html.Div([
                    html.Button("☰", id="hamburger-btn", n_clicks=0,
                                className="hamburger",
                                title="Open chat list"),
                    html.Img(src=_LOGO_DATA_URL, className="brand-logo",
                             alt="NETSEC") if _LOGO_DATA_URL else None,
                    html.Div("COMPANION", className="brand"),
                    html.Div("·", className="sep"),
                    html.Div(id="vm-status-badge",
                             className="brand-vm-badge"),
                    dcc.Dropdown(id="model-select",
                                 options=[{"label": m, "value": m}
                                          for m in available_models],
                                 value=default_model, clearable=False,
                                 className="model-select"),
                    html.Div(className="grow"),
                    html.Button("🌗", id="theme-toggle-btn", n_clicks=0,
                                className="theme-btn",
                                title="Toggle light/dark"),
                    html.Button("⚙", id="open-settings-btn", n_clicks=0,
                                className="settings-btn",
                                title="Chat settings"),
                ], className="topbar"),
                html.Div(id="chat-area", className="chat-area"),
                html.Div([
                    html.Div([
                        dcc.Textarea(id="composer-text",
                                     placeholder=("Type a message "
                                                  "(Enter sends, / for "
                                                  "commands)"),
                                     rows=3),
                        html.Button("➤", id="send-btn", n_clicks=0,
                                    className="send-btn"),
                    ], className="composer-inner"),
                    html.Div("Content is generated by a local model on your VM"
                             " and may be inaccurate. Not stored anywhere but"
                             " ~/ai-companion/chats.db.",
                             className="footer"),
                ], className="composer"),
                # Settings modal: a plain glass panel. Colors all come
                # from the brand tokens, so it follows light mode too
                # (the old Bootstrap modal was hardcoded dark).
                html.Div([
                    html.Div(id="settings-backdrop",
                             className="modal-backdrop", n_clicks=0),
                    html.Div([
                        html.H3("Chat settings"),
                        html.Label("System prompt",
                                   htmlFor="system-prompt-input"),
                        dcc.Textarea(id="system-prompt-input", rows=4),
                        html.Label("Temperature",
                                   htmlFor="temperature-slider"),
                        dcc.Slider(id="temperature-slider", min=0, max=2,
                                   step=0.1, value=0.7,
                                   marks={0: "0", 0.7: "0.7", 1: "1",
                                          2: "2"}),
                        html.Div(html.Button("Save", id="save-settings-btn",
                                             n_clicks=0,
                                             className="primary"),
                                 className="modal-actions"),
                    ], className="modal-panel"),
                ], id="settings-modal", className="modal-wrap"),
            ], className="main"),
        ], className="companion-app"),
    ])

    # ------------------ callbacks ------------------------------------

    @app.callback(
        Output("active-chat-id", "data"),
        Output("history-list", "children"),
        Input("new-chat-btn", "n_clicks"),
        Input({"type": "load-chat", "id": dash.ALL}, "n_clicks"),
        Input("stream-token", "data"),   # bumped by kick_send after a
                                          # fresh chat is created there;
                                          # this callback just repaints
        State("active-chat-id", "data"),
        State("model-select", "value"),
        prevent_initial_call=False,
    )
    def route_active_chat(new_clicks, load_clicks, _stream_bump, active,
                          model):
        """Owns the sidebar state. NEW-CHAT and LOAD-CHAT set/switch the
        active chat here. Suggestion / send clicks go through kick_send,
        which creates the chat itself when needed and then bumps
        stream-token so we repaint the history list (with the new title).
        This split avoids the double-create race a shared callback had.
        """
        trig = dash.ctx.triggered_id
        if trig == "new-chat-btn":
            active = store.new_chat(model=model)
        elif isinstance(trig, dict) and trig.get("type") == "load-chat":
            active = trig["id"]
        # stream-token bump / initial render: just repaint with current
        return active, _render_history(store, active)

    # -------- sidebar row actions (rename / delete) ----------------------
    # Browser handles the prompt/confirm UX, drops the outcome in a Store.
    app.clientside_callback(
        """function(rename_clicks, delete_clicks) {
            const ctx = window.dash_clientside.callback_context;
            const trg = ctx.triggered_id;
            if (!trg || typeof trg !== 'object') {
                return window.dash_clientside.no_update;
            }
            // Guard against initial-render fake fires (all zero).
            const clicks = trg.type === 'rename-chat'
                ? (rename_clicks || []) : (delete_clicks || []);
            if (!clicks.some(function(n){ return n; })) {
                return window.dash_clientside.no_update;
            }
            if (trg.type === 'rename-chat') {
                const t = window.prompt('New title:');
                if (t === null || !t.trim()) {
                    return window.dash_clientside.no_update;
                }
                return {action: 'rename', id: trg.id, title: t.trim()};
            }
            if (trg.type === 'delete-chat') {
                if (!window.confirm('Delete this chat? This cannot be undone.')) {
                    return window.dash_clientside.no_update;
                }
                return {action: 'delete', id: trg.id};
            }
            return window.dash_clientside.no_update;
        }""",
        Output("sidebar-action", "data"),
        Input({"type": "rename-chat", "id": dash.ALL}, "n_clicks"),
        Input({"type": "delete-chat", "id": dash.ALL}, "n_clicks"),
        prevent_initial_call=True,
    )

    @app.callback(
        Output("history-list", "children", allow_duplicate=True),
        Output("active-chat-id", "data", allow_duplicate=True),
        Input("sidebar-action", "data"),
        State("active-chat-id", "data"),
        prevent_initial_call=True,
    )
    def apply_sidebar_action(action, active):
        if not isinstance(action, dict):
            return no_update, no_update
        cid = action.get("id")
        if not cid:
            return no_update, no_update
        if action.get("action") == "rename":
            title = (action.get("title") or "").strip()
            if title:
                store.rename_chat(cid, title)
            return _render_history(store, active), no_update
        if action.get("action") == "delete":
            store.delete_chat(cid)
            # If the deleted chat was the active one, drop the pointer.
            new_active = None if cid == active else active
            return _render_history(store, new_active), new_active
        return no_update, no_update

    @app.callback(
        Output("chat-area", "children"),
        Output("send-btn", "children"),
        Output("send-btn", "className"),
        Input("active-chat-id", "data"),
        Input("stream-poll", "n_intervals"),
        Input("stream-token", "data"),   # ALSO paint on send/stop,
                                          # not only on interval ticks -
                                          # otherwise the last frame of
                                          # a finished stream is missed
                                          # once the interval disables.
    )
    def paint_chat(chat_id, _tick, _token):
        if not chat_id:
            return _welcome_screen(), "➤", "send-btn"
        msgs = store.list_messages(chat_id)
        with _STREAMS_LOCK:
            stream = _STREAMS.get(chat_id)
        streaming = stream is not None and not stream.snapshot()["done"]
        # While streaming the send button turns into stop (■).
        return (_render_messages(msgs, live_stream=stream),
                "■" if streaming else "➤",
                "send-btn stop" if streaming else "send-btn")

    @app.callback(
        Output("stream-poll", "interval"),      # 300 while streaming, else 2000
        Output("composer-text", "value"),
        Output("stream-token", "data"),
        Output("active-chat-id", "data", allow_duplicate=True),
        Input("send-btn", "n_clicks"),
        Input({"type": "suggestion", "text": dash.ALL}, "n_clicks"),
        Input("stream-poll", "n_intervals"),
        State("composer-text", "value"),
        State("active-chat-id", "data"),
        State("model-select", "value"),
        prevent_initial_call=True,
    )
    def kick_send(send_clicks, sugg_clicks, _tick, composer_text, chat_id,
                  model):
        trig = dash.ctx.triggered_id
        # 1. suggestion clicked -> send its prompt
        if isinstance(trig, dict) and trig.get("type") == "suggestion":
            # Real click check: pattern-match Inputs fire with a null
            # n_clicks list element on the initial render, so only accept
            # this trigger when SOMEONE actually clicked.
            n_now = next((n for n in (sugg_clicks or []) if n), None)
            if not n_now:
                return no_update, no_update, no_update, no_update
            composer_text = trig.get("text", "")
        elif trig == "stream-poll":
            # tick: slow the poll IF nothing is streaming anymore. The
            # poll is always ON (interval either 300 or 2000) so paint
            # runs at least twice a second background - no missed final
            # frames even when the stream-token bump was ignored.
            with _STREAMS_LOCK:
                any_active = any(not s.snapshot()["done"]
                                 for s in _STREAMS.values())
                had_finished = any(s.snapshot()["done"]
                                   for s in _STREAMS.values())
                for cid in list(_STREAMS):
                    if _STREAMS[cid].snapshot()["done"]:
                        _STREAMS.pop(cid, None)
            token_out = time.time() if had_finished else no_update
            new_interval = 300 if any_active else 2000
            return new_interval, no_update, token_out, no_update
        # 2a. streaming already? then this click means STOP. The typed
        # text (if any) stays in the composer for the next send.
        if chat_id:
            with _STREAMS_LOCK:
                live = _STREAMS.get(chat_id)
            if live is not None and not live.snapshot()["done"]:
                live.cancel()
                return no_update, no_update, time.time(), no_update
        # 2b. actual send
        if not composer_text or not composer_text.strip():
            return no_update, no_update, no_update, no_update
        chat_id_out = no_update
        # Session-storage keeps active-chat-id across browser refreshes,
        # so a chat_id from a previous run can survive after the DB was
        # cleared. Verify that it still exists; if not, allocate fresh.
        if not chat_id or store.get_chat(chat_id) is None:
            chat_id = store.new_chat(model=model)
            chat_id_out = chat_id
        text = composer_text.strip()

        # handle slash commands here, in-process
        verb, arg = parse_slash_command(text)
        if verb == "model":
            if arg and arg.strip():
                store.set_chat_model(chat_id, arg.strip())
                store.append_message(chat_id, "system",
                                     f"[model set to {arg.strip()}]")
            return no_update, "", no_update, chat_id_out
        if verb == "system":
            store.set_chat_system(chat_id, arg)
            store.append_message(chat_id, "system",
                                 f"[system prompt updated]")
            return no_update, "", no_update, chat_id_out
        if verb in ("temp", "temperature"):
            try:
                store.set_chat_temperature(chat_id, float(arg))
                store.append_message(chat_id, "system",
                                     f"[temperature = {float(arg):.2f}]")
            except ValueError:
                store.append_message(chat_id, "system",
                                     f"[bad temperature: {arg!r}]")
            return no_update, "", no_update, chat_id_out
        if verb == "clear":
            with _STREAMS_LOCK:
                _STREAMS.pop(chat_id, None)
            # Wipe the messages but keep the chat container
            with store._lock:
                store._db.execute("DELETE FROM messages WHERE chat_id=?",
                                  (chat_id,))
            return no_update, "", no_update, chat_id_out
        if verb == "help":
            store.append_message(chat_id, "system",
                                 "commands: /model <name> · /system <text> "
                                 "· /temp <0.0-2.0> · /clear · /save · /help")
            return no_update, "", no_update, chat_id_out
        if verb == "save":
            path = pathlib.Path.home() / "ai-companion" / "exports"
            path.mkdir(parents=True, exist_ok=True)
            chat = store.get_chat(chat_id)
            msgs = store.list_messages(chat_id)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = path / f"chat_{chat_id}_{stamp}.md"
            body = [f"# {chat['title']}", ""]
            for m in msgs:
                body.append(f"### {m['role']}  \n{m['content']}\n")
            out_path.write_text("\n".join(body), encoding="utf-8")
            store.append_message(chat_id, "system",
                                 f"[saved to {out_path}]")
            return no_update, "", no_update, chat_id_out

        # 3. real chat message.
        # get_chat MUST already see the row we just inserted - autocommit
        # + WAL make that guarantee across threads. If it doesn't (schema
        # mismatch, disk full, whatever), surface it loudly instead of
        # silently AttributeError'ing on chat.get(...).

        store.append_message(chat_id, "user", text)
        chat = store.get_chat(chat_id) or {}
        if not chat:
            print(f"[companion] get_chat({chat_id}) returned None right "
                  "after new_chat/append; storage is misbehaving",
                  file=sys.stderr)
            return no_update, "", no_update, chat_id_out
        chosen_model = chat.get("model") or model
        # build the messages array Ollama wants
        history = []
        sys_prompt = (chat.get("system_prompt") or "").strip()
        if sys_prompt:
            history.append({"role": "system", "content": sys_prompt})
        for m in store.list_messages(chat_id):
            if m["role"] in ("user", "assistant"):
                history.append({"role": m["role"], "content": m["content"]})

        state = StreamState(chat_id, chosen_model)
        with _STREAMS_LOCK:
            _STREAMS[chat_id] = state
        options = {"temperature": float(chat.get("temperature") or 0.7)}
        t = threading.Thread(target=_run_stream,
                             args=(client, store, chat_id, chosen_model,
                                   history, options, state),
                             daemon=True)
        t.start()
        # arm the poll and clear the composer; stream-token bump forces the
        # paint callback to re-render even before the first token lands
        return 300, "", (send_clicks or 0), chat_id_out

    @app.callback(
        Output("settings-modal", "className"),
        Output("system-prompt-input", "value"),
        Output("temperature-slider", "value"),
        Input("open-settings-btn", "n_clicks"),
        Input("save-settings-btn", "n_clicks"),
        Input("settings-backdrop", "n_clicks"),
        State("system-prompt-input", "value"),
        State("temperature-slider", "value"),
        State("active-chat-id", "data"),
        prevent_initial_call=True,
    )
    def toggle_settings(open_clicks, save_clicks, backdrop_clicks,
                        sys_prompt, temp, chat_id):
        trig = dash.ctx.triggered_id
        if trig == "open-settings-btn":
            if chat_id:
                c = store.get_chat(chat_id) or {}
                return "modal-wrap show", c.get("system_prompt") or "", \
                    c.get("temperature") or 0.7
            return "modal-wrap show", "", 0.7
        if trig == "save-settings-btn":
            if chat_id:
                store.set_chat_system(chat_id, sys_prompt or "")
                store.set_chat_temperature(chat_id, float(temp or 0.7))
            return "modal-wrap", no_update, no_update
        # backdrop tap closes without saving
        return "modal-wrap", no_update, no_update

    # Static badge - refreshed only on page load / model change, NOT on
    # the stream-poll tick. A 200 ms poll would probe Ollama 5 times a
    # second and hammer the tunnel.
    @app.callback(
        Output("vm-status-badge", "children"),
        Input("model-select", "value"),
    )
    def render_vm_badge(_model):
        try:
            client.list_models()
            label = tunnel.host if tunnel is not None else "local"
            return html.Span(f"VM: {label}", className="badge")
        except Exception:
            return html.Span("VM: unreachable", className="badge warn")

    # Hamburger: toggle the sidebar drawer on mobile. Backdrop click and
    # any chat-load click close it (feels right on iOS).
    app.clientside_callback(
        """
        function(hamClicks, backdropClicks, loadClicks, current) {
            const ctx = dash_clientside.callback_context;
            if (!ctx || !ctx.triggered || ctx.triggered.length === 0) {
                return window.dash_clientside.no_update;
            }
            const trig = ctx.triggered[0].prop_id;
            if (trig.startsWith("hamburger-btn.")) {
                const open = !current;
                document.getElementById("sidebar").classList.toggle("open", open);
                document.getElementById("sidebar-backdrop")
                        .classList.toggle("show", open);
                return open;
            }
            if (trig.startsWith("sidebar-backdrop.") ||
                    trig.includes("load-chat")) {
                document.getElementById("sidebar").classList.remove("open");
                document.getElementById("sidebar-backdrop").classList.remove("show");
                return false;
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("sidebar-open", "data"),
        Input("hamburger-btn", "n_clicks"),
        Input("sidebar-backdrop", "n_clicks"),
        Input({"type": "load-chat", "id": dash.ALL}, "n_clicks"),
        State("sidebar-open", "data"),
        prevent_initial_call=True,
    )

    # Theme toggle: dark <-> light, persisted in localStorage. The key
    # is shared with the portal and RAG ("netsec-theme"), so flipping
    # the theme anywhere flips it everywhere on this origin; the old
    # per-app key is still read once as a fallback. The meta
    # theme-color follows so the iOS status bar matches.
    app.clientside_callback(
        """
        function(n) {
            const apply = (theme) => {
                if (theme === "light") {
                    document.documentElement.setAttribute("data-theme", "light");
                } else {
                    document.documentElement.removeAttribute("data-theme");
                }
                const meta = document.querySelector('meta[name="theme-color"]');
                if (meta) meta.content =
                    theme === "light" ? "#f4f2fa" : "#07050f";
            };
            if (!n) {
                let saved = null;
                try {
                    saved = localStorage.getItem("netsec-theme")
                        || localStorage.getItem("companion-theme");
                } catch (e) {}
                if (saved === "light") apply("light");
                return window.dash_clientside.no_update;
            }
            const cur = document.documentElement.getAttribute("data-theme");
            const next = cur === "light" ? "dark" : "light";
            apply(next);
            try { localStorage.setItem("netsec-theme", next); } catch (e) {}
            return next;
        }
        """,
        Output("theme-toggle-btn", "title"),
        Input("theme-toggle-btn", "n_clicks"),
        prevent_initial_call=False,
    )

    return app


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    default_key = os.environ.get(
        "NETSEC_SSH_KEY",
        str(pathlib.Path.home() / ".ssh" / "netsec-agent.key"
            / "ssh-key-2026-07-12.key"))
    ap = argparse.ArgumentParser(
        description="Local AI Companion - chat with the Ollama models "
                    "on your NetSec VM through an SSH tunnel.")
    ap.add_argument("--host", default=os.environ.get(
        "NETSEC_VM_HOST", "100.68.246.54"),
                    help="VM host (default: 100.68.246.54 - Tailscale IP)")
    ap.add_argument("--user", default=os.environ.get(
        "NETSEC_VM_USER", "ubuntu"),
                    help="SSH user (default: ubuntu)")
    ap.add_argument("--key", default=default_key,
                    help="SSH private key path")
    ap.add_argument("--container", default="deploy-ollama-1",
                    help="Ollama container name (default: deploy-ollama-1)")
    ap.add_argument("--local-port", type=int, default=11434,
                    help="local port for the tunnel (default: 11434)")
    ap.add_argument("--port", type=int, default=5100,
                    help="web UI port (default: 5100)")
    ap.add_argument("--bind", default="127.0.0.1",
                    help=("interface to bind (default 127.0.0.1). Set to "
                          "0.0.0.0 to accept connections from the local "
                          "network / Tailscale (needed for iPhone access)."))
    ap.add_argument("--no-browser", action="store_true",
                    help="don't auto-open the browser")
    ap.add_argument("--ollama-url",
                    default=os.environ.get("NETSEC_OLLAMA_URL"),
                    help=("Skip the SSH tunnel entirely and use this "
                          "Ollama URL directly. Set on the VM itself, "
                          "where Ollama is already reachable at "
                          "http://127.0.0.1:11434 - no tunnel needed."))
    ap.add_argument("--db",
                    default=os.environ.get("NETSEC_COMPANION_DB"),
                    help=("Chat history DB path (default: "
                          "~/ai-companion/chats.db). Override on the VM "
                          "so state lives under /srv/netsec/companion/."))
    ap.add_argument("--url-base",
                    default=os.environ.get("NETSEC_COMPANION_URL_BASE"),
                    help=("Serve the app under a subpath (e.g. '/chat/'). "
                          "Needed behind a reverse proxy that uses path "
                          "routing. Must start AND end with '/'."))
    args = ap.parse_args()

    if args.ollama_url:
        # Direct mode - the process itself can reach Ollama; no tunnel
        # to open, no ssh, no atexit cleanup. Used by the VM systemd
        # deployment where the container is reachable on loopback.
        print(f"[companion] direct mode: using Ollama at "
              f"{args.ollama_url} (no ssh tunnel)")
        tunnel = None
        client = OllamaClient(args.ollama_url)
    else:
        print(f"[companion] opening ssh tunnel to {args.user}@{args.host} "
              f"-> {args.container}:11434 ...")
        try:
            tunnel = VMTunnel(host=args.host, user=args.user, key=args.key,
                              container=args.container,
                              local_port=args.local_port).open()
        except Exception as e:
            print(f"[companion] tunnel setup failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"[companion] tunnel up: 127.0.0.1:{args.local_port} -> "
              f"{tunnel.container_ip}:11434")
        client = OllamaClient(f"http://127.0.0.1:{args.local_port}")

    db_path = pathlib.Path(args.db) if args.db else \
        pathlib.Path.home() / "ai-companion" / "chats.db"
    store = ChatStore(db_path)
    print(f"[companion] chats DB: {db_path}")

    app = build_app(tunnel, client, store, args.port,
                    url_base=args.url_base)
    url = f"http://127.0.0.1:{args.port}"
    if args.bind == "0.0.0.0":
        print(f"[companion] serving on 0.0.0.0:{args.port} "
              f"(open in browser: {url} , or from Tailscale: "
              f"http://<this-host-tailscale-ip>:{args.port})")
    else:
        print(f"[companion] serving on {url}")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def _stop(*_):
        print("\n[companion] shutting down...")
        if tunnel is not None:
            tunnel.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, _stop)

    try:
        app.run(host=args.bind, port=args.port, debug=False,
                use_reloader=False)
    finally:
        # No-op in direct mode - only tunnel-mode has anything to tear
        # down (tunnel-close is idempotent, safe on already-closed).
        if tunnel is not None:
            tunnel.close()


if __name__ == "__main__":
    main()

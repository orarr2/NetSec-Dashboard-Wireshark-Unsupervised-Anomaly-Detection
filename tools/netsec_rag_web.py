"""NetSec RAG - Dash web frontend, structured after companion/companion.py.

Uses the RagEngine from netsec_rag.py in-process (no HTTP round-trip)
and adds a llama.ui-shaped UI on top: sidebar with query history
grouped by date, streaming token-by-token answers, expandable sources.

Runs behind Caddy on the VM (systemd unit netsec-rag.service) at the
same URL as the previous tiny http.server: /rag/ via basicauth.
Compared to the old page, this one is:

  - stateful:  history persists in a SQLite next to the RAG store,
               so refreshing the browser / opening a new tab lands
               on the same past queries.
  - streaming: tokens appear as Ollama generates them (Companion
               shape - the answer builds up in front of you).
  - filterable: side dropdown scopes retrieval by verdict/category
               using the metadata `where` filter already in RagEngine.

Same auth / TLS / everything as before - Caddy is unchanged, this
just replaces the process behind port 5200 with a Dash app.
"""
import argparse
import json
import os
import pathlib
import queue
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

# Reuse the engine + config from the sibling CLI module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netsec_rag as R  # noqa: E402

try:
    import dash
    from dash import Dash, dcc, html, Input, Output, State, no_update, ALL, ctx
    import dash_bootstrap_components as dbc
except ImportError as e:
    print(f"[rag-web] missing dep: {e}\n"
          "  install with: pip install dash dash_bootstrap_components",
          file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------
# Query history (a tiny SQLite next to the RAG store)
# --------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id TEXT PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT,
    sources_json TEXT,
    generator TEXT,
    scope_json TEXT,
    tokens_out INTEGER,
    total_ms INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_updated ON queries(updated_at DESC);
"""


class QueryHistory:
    def __init__(self, db_path):
        db_path = pathlib.Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # autocommit + WAL, matching Companion (a streaming worker thread
        # writes the answer as it grows; the Dash thread reads it).
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

    def new_query(self, question, generator="local", scope=None):
        qid = uuid.uuid4().hex[:12]
        now = self._now()
        with self._lock:
            self._db.execute(
                "INSERT INTO queries (id, question, generator, scope_json,"
                " created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (qid, question, generator,
                 json.dumps(scope) if scope else None, now, now))
        return qid

    def append_answer_text(self, qid, delta):
        """Append streaming tokens as they arrive. Cheap - one row
        update per token would kill the disk, so callers batch this."""
        now = self._now()
        with self._lock:
            self._db.execute(
                "UPDATE queries SET"
                " answer=COALESCE(answer,'') || ?, updated_at=?"
                " WHERE id=?", (delta, now, qid))

    def finalize(self, qid, sources, tokens_out=None, total_ms=None):
        with self._lock:
            self._db.execute(
                "UPDATE queries SET sources_json=?, tokens_out=?,"
                " total_ms=?, updated_at=? WHERE id=?",
                (json.dumps(sources or []), tokens_out, total_ms,
                 self._now(), qid))

    def get(self, qid):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM queries WHERE id=?", (qid,)).fetchone()
        return dict(row) if row else None

    def delete(self, qid):
        with self._lock:
            self._db.execute("DELETE FROM queries WHERE id=?", (qid,))

    def list_by_date_group(self):
        with self._lock:
            rows = self._db.execute(
                "SELECT id, question, updated_at FROM queries"
                " ORDER BY updated_at DESC").fetchall()
        buckets = {"Today": [], "Yesterday": [],
                   "Previous 7 Days": [], "Previous 30 Days": [],
                   "Older": []}
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
# Streaming state - one background thread per active query
# --------------------------------------------------------------------------
class StreamState:
    """Holds the growing answer, sources, and terminal state for one
    running query. The Dash poll callback reads snapshots; the worker
    thread pushes updates. Same pattern as Companion's stream buffer."""

    def __init__(self, qid):
        self.qid = qid
        self.answer = ""
        self.sources = []
        self.done = False
        self.error = None
        self._lock = threading.Lock()

    def push_token(self, text):
        with self._lock:
            self.answer += text

    def set_sources(self, sources):
        with self._lock:
            self.sources = sources

    def set_done(self, error=None):
        with self._lock:
            self.done = True
            self.error = error

    def snapshot(self):
        with self._lock:
            return {"qid": self.qid, "answer": self.answer,
                    "sources": self.sources, "done": self.done,
                    "error": self.error}


_STREAMS = {}          # qid -> StreamState (in-memory only, cleared on restart)
_STREAMS_LOCK = threading.Lock()


def _stream_worker(engine, history, qid, question, generator, where):
    state = StreamState(qid)
    with _STREAMS_LOCK:
        _STREAMS[qid] = state
    started = time.perf_counter()
    tokens_out = 0
    try:
        if generator == "groq":
            # Groq is not streamable through the engine - do it in one
            # shot, publish the whole answer, then done.
            state.set_sources(engine.retrieve(question, k=6, where=where))
            res = engine.answer(question, generator="groq", where=where)
            state.push_token(res.get("answer") or "")
            history.append_answer_text(qid, res.get("answer") or "")
            state.set_sources(res.get("sources") or [])
        else:
            for kind, payload in engine.stream_answer(question, where=where):
                if kind == "sources":
                    state.set_sources(payload)
                elif kind == "token":
                    state.push_token(payload)
                    history.append_answer_text(qid, payload)
                    tokens_out += 1
                elif kind == "done":
                    tokens_out = payload.get("tokens_out") or tokens_out
                elif kind == "error":
                    state.set_done(error=payload)
                    return
        total_ms = int((time.perf_counter() - started) * 1000)
        history.finalize(qid, state.snapshot()["sources"],
                         tokens_out=tokens_out, total_ms=total_ms)
        state.set_done()
    except Exception as e:
        state.set_done(error=str(e))


# --------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------
def _pretty_source(src):
    """`netsec:session:21:172.10.146.42` -> `session 21 / 172.10.146.42`
    (readable in the UI). Falls through unchanged for other shapes."""
    if not isinstance(src, str):
        return str(src)
    parts = src.split(":")
    if len(parts) == 4 and parts[0] == "netsec" and parts[1] == "session":
        return f"session {parts[2]} · {parts[3]}"
    if len(parts) == 3 and parts[0] == "netsec" and parts[1] == "summary":
        return f"session {parts[2]} summary"
    if len(parts) == 3 and parts[0] == "netsec" and parts[1] == "compare":
        return f"compare {parts[2]}"
    return src


def _source_card(i, hit):
    return html.Details([
        html.Summary(
            f"[{i}] {_pretty_source(hit.get('source'))} "
            f"(cos {float(hit.get('score', 0)):.2f})",
            className="src-summary"),
        html.Pre((hit.get("text") or "")[:900], className="src-body"),
    ], className="src-card")


def _history_group(label, rows):
    return [
        html.H2(label),
        *[html.Div([
            html.Span(row["question"][:60] or "(untitled)",
                      className="q-text"),
        ], id={"type": "hist-row", "id": row["id"]},
            className="q-row", n_clicks=0)
          for row in rows],
    ]


def _default_scope_options(engine):
    """Build the metadata filter dropdown from the actual index. Same
    signal RAG's stats returns, but grouped as select-friendly options."""
    stats = engine.store.stats()
    kinds = stats.get("by_kind") or {}
    opts = [{"label": "All indexed material", "value": "__all__"}]
    if kinds.get("netsec_verdict"):
        opts += [
            {"label": "Verdicts: malicious only",
             "value": json.dumps({"verdict": "malicious"})},
            {"label": "Verdicts: suspicious only",
             "value": json.dumps({"verdict": "suspicious"})},
            {"label": "Verdicts: benign only",
             "value": json.dumps({"verdict": "benign"})},
        ]
    if kinds.get("netsec_summary"):
        opts.append({"label": "Session summaries only",
                     "value": json.dumps({"kind": "netsec_summary"})})
    if kinds.get("netsec_compare"):
        opts.append({"label": "Compare reports only",
                     "value": json.dumps({"kind": "netsec_compare"})})
    return opts


# --------------------------------------------------------------------------
# Dash app
# --------------------------------------------------------------------------
_CSS = """
:root { color-scheme: dark; --bg:#0f0f11; --panel:#17171b; --panel-2:#1c1c22;
  --ink:#e6edf3; --ink-mute:#8b949e; --accent:#79c0ff; --user-bg:#26262e;
  --assistant-bg:#1c1c22; --line:#22222a;}
:root[data-theme="light"] { color-scheme: light;
  --bg:#ffffff; --panel:#f6f8fa; --panel-2:#eaeef2;
  --ink:#1f2328; --ink-mute:#57606a; --accent:#0969da; --user-bg:#e8ecf5;
  --assistant-bg:#f7f8fb; --line:#d0d7de;}
html, body { background: var(--bg); color: var(--ink); margin: 0;
  font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
#app-root { display: flex; height: 100vh; }
.sidebar { width: 260px; background: var(--panel); padding: 14px 10px;
  overflow-y: auto; border-right: 1px solid var(--line);
  display: flex; flex-direction: column; }
.sidebar h2 { font-size: 11px; letter-spacing: 0.14em; color: var(--ink-mute);
  text-transform: uppercase; margin: 14px 4px 6px; font-weight: 600; }
.sidebar .q-row { padding: 8px 10px; border-radius: 8px; cursor: pointer;
  margin: 2px 0; font-size: 13px; color: var(--ink); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; }
.sidebar .q-row:hover { background: var(--panel-2); }
.sidebar .new-btn { display: flex; align-items: center; width: 100%;
  padding: 10px; border: 1px solid var(--line); background: var(--panel-2);
  color: var(--ink); border-radius: 8px; cursor: pointer; font-size: 14px;
  margin-bottom: 4px; }
.sidebar .new-btn:hover { background: var(--panel); }
.sidebar .footer-note { margin-top: auto; color: var(--ink-mute);
  font-size: 11px; padding: 12px 4px; }
.backdrop { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.4);
  z-index: 40; }
.backdrop.show { display: block; }
.main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.topbar { display: flex; align-items: center; padding: 10px 16px;
  border-bottom: 1px solid var(--line); background: var(--panel);
  gap: 10px; }
.topbar .hamburger { display: none; background: none; border: none;
  color: var(--ink); font-size: 22px; cursor: pointer; padding: 0 8px;}
.topbar .title { font-weight: 700; font-size: 15px; }
.topbar .badge { padding: 3px 8px; border-radius: 12px;
  background: var(--panel-2); font-size: 11px; color: var(--ink-mute); }
.topbar .grow { flex: 1; }
.topbar select, .topbar button.icon { background: var(--panel-2);
  color: var(--ink); border: 1px solid var(--line); border-radius: 8px;
  padding: 6px 10px; font-size: 12px; }
.chat { flex: 1; overflow-y: auto; padding: 18px 16px; }
.suggestions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  max-width: 720px; margin: 32px auto; }
.suggestions .card { padding: 12px 14px; border: 1px solid var(--line);
  border-radius: 10px; background: var(--panel); cursor: pointer;
  color: var(--ink); font-size: 13px; }
.suggestions .card:hover { background: var(--panel-2); }
.msg { max-width: 900px; margin: 0 auto 14px; padding: 12px 14px;
  border-radius: 12px; line-height: 1.5; white-space: pre-wrap;
  word-wrap: break-word; }
.msg.user { background: var(--user-bg); }
.msg.assistant { background: var(--assistant-bg);
  border: 1px solid var(--line); }
.msg .meta { margin-top: 8px; font-size: 11px; color: var(--ink-mute); }
.sources-wrap { max-width: 900px; margin: 0 auto 24px; }
.src-card { background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; margin: 6px 0; padding: 6px 12px; font-size: 12px; }
.src-summary { cursor: pointer; color: var(--accent); font-weight: 500; }
.src-body { color: var(--ink-mute); font-size: 11px;
  margin: 8px 0 0; white-space: pre-wrap; background: var(--bg);
  padding: 8px; border-radius: 6px; max-height: 260px; overflow: auto; }
.composer { border-top: 1px solid var(--line); background: var(--panel);
  padding: 12px 16px; display: flex; gap: 8px; align-items: end; }
.composer textarea { flex: 1; background: var(--panel-2); color: var(--ink);
  border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px;
  font-size: 14px; resize: none; min-height: 40px; max-height: 160px;
  font-family: inherit; }
.composer button { background: var(--accent); color: white; border: none;
  border-radius: 999px; width: 42px; height: 42px; font-size: 18px;
  cursor: pointer; }
.composer button:disabled { opacity: 0.4; cursor: not-allowed; }
.footer-line { text-align: center; color: var(--ink-mute); font-size: 11px;
  padding: 6px 0 10px; border-top: 1px solid var(--line); }
@media (max-width: 699px) {
  .sidebar { position: fixed; left: 0; top: 0; bottom: 0;
    transform: translateX(-100%); transition: transform .2s ease; z-index: 50; }
  .sidebar.open { transform: translateX(0); }
  .topbar .hamburger { display: block; }
  .suggestions { grid-template-columns: 1fr; }
}
"""


def build_app(engine, history, url_base=None):
    dash_kwargs = dict(external_stylesheets=[dbc.themes.SLATE],
                       title="NetSec RAG", update_title=None,
                       suppress_callback_exceptions=True)
    if url_base:
        if not (url_base.startswith("/") and url_base.endswith("/")):
            raise ValueError("--url-base must start AND end with '/'")
        dash_kwargs["url_base_pathname"] = url_base
    app = Dash(__name__, **dash_kwargs)
    _META = ('<meta name="viewport" content="width=device-width,'
             'initial-scale=1,viewport-fit=cover,user-scalable=no">'
             '<meta name="theme-color" content="#0f0f11" '
             'media="(prefers-color-scheme: dark)">'
             '<meta name="theme-color" content="#ffffff" '
             'media="(prefers-color-scheme: light)">'
             '<meta name="apple-mobile-web-app-capable" content="yes">')
    app.index_string = ("<!DOCTYPE html><html><head>{%metas%}<title>"
                        "{%title%}</title>" + _META + "<style>" + _CSS
                        + "</style></head><body><div id='app-root'>"
                        "{%app_entry%}</div><footer>{%config%}{%scripts%}"
                        "{%renderer%}</footer></body></html>")

    app.layout = html.Div([
        dcc.Store(id="active-qid", data=None),
        dcc.Store(id="sidebar-open", data=False),
        dcc.Store(id="stream-tick", data=0),
        dcc.Interval(id="poll", interval=2000, disabled=True),
        html.Div(id="sidebar-backdrop", className="backdrop", n_clicks=0),

        # Sidebar
        html.Div([
            html.Button([html.Span("+  ", style={"marginRight": "6px"}),
                         "New query"],
                        id="new-query-btn", n_clicks=0, className="new-btn"),
            html.Div(id="history-list"),
            html.Div("Stored in ~/netsec-rag/queries.db",
                     className="footer-note"),
        ], id="sidebar", className="sidebar"),

        # Main
        html.Div([
            html.Div([
                html.Button("☰", id="hamburger", className="hamburger",
                            n_clicks=0),
                html.Span("NetSec RAG", className="title"),
                html.Span(id="stats-badge", className="badge"),
                html.Div(className="grow"),
                dcc.Dropdown(
                    id="scope-select", clearable=False, searchable=False,
                    options=_default_scope_options(engine),
                    value="__all__",
                    style={"width": "220px", "fontSize": "12px",
                           "color": "black"}),
                dcc.Dropdown(
                    id="gen-select", clearable=False, searchable=False,
                    options=[{"label": "local", "value": "local"},
                             {"label": "groq", "value": "groq"}],
                    value=(R.GEN_MODEL and "local") or "local",
                    style={"width": "100px", "fontSize": "12px",
                           "color": "black"}),
                html.Button("🌙", id="theme-btn", n_clicks=0,
                            className="icon"),
            ], className="topbar"),

            html.Div(id="chat-view", className="chat"),

            html.Div([
                dcc.Textarea(id="q-input",
                             placeholder="Ask about the indexed material...",
                             rows=1),
                html.Button("→", id="ask-btn", n_clicks=0),
            ], className="composer"),

            html.Div(f"Local generation with {R.GEN_MODEL} on the VM. "
                     f"Retrieval always local. Not connected to the "
                     f"internet.",
                     className="footer-line"),
        ], className="main"),
    ])

    # -------- clientside: theme toggle + hamburger + backdrop close ------
    app.clientside_callback(
        """function(n) {
            const cur = document.documentElement.getAttribute('data-theme')
                        || (window.matchMedia('(prefers-color-scheme: dark)')
                            .matches ? 'dark' : 'light');
            const next = cur === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            try { localStorage.setItem('rag-theme', next); } catch(e){}
            return next === 'dark' ? '🌙' : '☀️';
        }""",
        Output("theme-btn", "children"),
        Input("theme-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    app.clientside_callback(
        """function(){ try {
            const t = localStorage.getItem('rag-theme');
            if (t) document.documentElement.setAttribute('data-theme', t);
        } catch(e){} return window.dash_clientside.no_update; }""",
        Output("theme-btn", "className"),
        Input("theme-btn", "id"),
    )

    # -------- sidebar toggle (mobile) ------------------------------------
    @app.callback(
        Output("sidebar", "className"),
        Output("sidebar-backdrop", "className"),
        Output("sidebar-open", "data"),
        Input("hamburger", "n_clicks"),
        Input("sidebar-backdrop", "n_clicks"),
        Input({"type": "hist-row", "id": ALL}, "n_clicks"),
        State("sidebar-open", "data"),
    )
    def toggle_sidebar(_ham, _bd, _rows, is_open):
        trg = ctx.triggered_id
        if trg == "hamburger":
            is_open = not is_open
        else:
            is_open = False
        return ("sidebar open" if is_open else "sidebar",
                "backdrop show" if is_open else "backdrop", is_open)

    # -------- stats badge ------------------------------------------------
    @app.callback(
        Output("stats-badge", "children"),
        Input("poll", "n_intervals"),
        Input("stream-tick", "data"),
    )
    def refresh_stats(_i, _t):
        s = engine.store.stats()
        return f"{s['chunks']} chunks · {s['sources']} sources"

    # -------- history list ------------------------------------------------
    @app.callback(
        Output("history-list", "children"),
        Input("stream-tick", "data"),
        Input("new-query-btn", "n_clicks"),
    )
    def render_history(_t, _n):
        groups = history.list_by_date_group()
        if not groups:
            return html.Div("No queries yet.",
                            style={"padding": "12px",
                                   "color": "var(--ink-mute)",
                                   "fontSize": "12px"})
        out = []
        for label, rows in groups:
            out.extend(_history_group(label, rows))
        return out

    # -------- ask ---------------------------------------------------------
    @app.callback(
        Output("active-qid", "data"),
        Output("q-input", "value"),
        Output("poll", "disabled"),
        Output("stream-tick", "data", allow_duplicate=True),
        Input("ask-btn", "n_clicks"),
        State("q-input", "value"),
        State("gen-select", "value"),
        State("scope-select", "value"),
        State("stream-tick", "data"),
        prevent_initial_call=True,
    )
    def on_ask(_n, q, generator, scope, tick):
        q = (q or "").strip()
        if not q:
            return no_update, no_update, no_update, no_update
        where = None
        if scope and scope != "__all__":
            try:
                where = json.loads(scope)
            except Exception:
                where = None
        qid = history.new_query(q, generator=generator, scope=where)
        threading.Thread(
            target=_stream_worker,
            args=(engine, history, qid, q, generator, where),
            daemon=True,
        ).start()
        return qid, "", False, (tick or 0) + 1

    # -------- history row click loads a past query -----------------------
    @app.callback(
        Output("active-qid", "data", allow_duplicate=True),
        Output("poll", "disabled", allow_duplicate=True),
        Input({"type": "hist-row", "id": ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def on_history_click(all_clicks):
        # ctx.triggered_id is the {"type": "hist-row", "id": <qid>} dict.
        trg = ctx.triggered_id
        if not trg or not isinstance(trg, dict):
            return no_update, no_update
        if all(not c for c in all_clicks):
            return no_update, no_update
        return trg["id"], True   # poll disabled - past query is static

    # -------- chat view (renders the current qid, live or historical) ----
    @app.callback(
        Output("chat-view", "children"),
        Output("stream-tick", "data"),
        Output("poll", "disabled", allow_duplicate=True),
        Input("active-qid", "data"),
        Input("poll", "n_intervals"),
        State("stream-tick", "data"),
        prevent_initial_call="initial_duplicate",
    )
    def render_chat(qid, _tick, prev_tick):
        prev_tick = prev_tick or 0
        if not qid:
            return _placeholder(engine), prev_tick, True
        # If it's a live stream, read from the in-memory buffer.
        with _STREAMS_LOCK:
            live = _STREAMS.get(qid)
        if live is not None and not live.done:
            snap = live.snapshot()
            row = history.get(qid) or {}
            return (_render_qa(row.get("question", ""), snap["answer"],
                               snap["sources"], streaming=True,
                               error=snap["error"]),
                    prev_tick + 1, False)
        # Otherwise pull the finalized record from the DB.
        row = history.get(qid)
        if not row:
            return html.Div("query not found",
                            style={"padding": "40px"}), prev_tick, True
        try:
            sources = json.loads(row.get("sources_json") or "[]")
        except Exception:
            sources = []
        meta = []
        if row.get("tokens_out"):
            meta.append(f"{row['tokens_out']} tokens")
        if row.get("total_ms"):
            meta.append(f"{row['total_ms']} ms")
        return (_render_qa(row["question"], row.get("answer") or "",
                           sources, streaming=False, meta=" · ".join(meta)),
                prev_tick + 1, True)

    return app


# --------------------------------------------------------------------------
# UI helpers (kept simple + inline so the whole module is a single file)
# --------------------------------------------------------------------------
def _placeholder(engine):
    stats = engine.store.stats()
    suggestions = [
        "Which IPs were judged malicious across all sessions?",
        "What did the panel say about 172.10.146.42?",
        "Summarize the most recent comparison report.",
        "Which devices repeatedly show port_scan verdicts?",
    ]
    return html.Div([
        html.Div(
            f"NetSec RAG - {stats['chunks']} chunks from "
            f"{stats['sources']} sources ready.",
            style={"textAlign": "center", "color": "var(--ink-mute)",
                   "marginTop": "40px", "fontSize": "13px"}),
        html.Div([
            html.Div(s, id={"type": "suggest", "text": s},
                     className="card", n_clicks=0)
            for s in suggestions
        ], className="suggestions"),
    ])


def _render_qa(question, answer, sources, streaming=False, error=None,
               meta=""):
    children = [html.Div(question or "(empty question)",
                         className="msg user")]
    if error:
        children.append(html.Div(f"Error: {error}",
                                 className="msg assistant",
                                 style={"color": "var(--accent)"}))
    else:
        cls = "msg assistant" + (" streaming" if streaming else "")
        body = html.Div([
            html.Span(answer or ("..." if streaming else "(no answer)")),
            html.Div(meta, className="meta") if meta and not streaming
            else None,
        ], className=cls)
        children.append(body)
    if sources:
        children.append(html.Div(
            [html.Div("Sources:",
                      style={"marginBottom": "6px",
                             "color": "var(--ink-mute)",
                             "fontSize": "12px",
                             "maxWidth": "900px", "margin": "0 auto"})]
            + [_source_card(i + 1, h) for i, h in enumerate(sources)],
            className="sources-wrap"))
    return children


# --------------------------------------------------------------------------
# Suggest-card click -> fill the composer with the suggestion text
# --------------------------------------------------------------------------
def _wire_suggestions(app):
    app.clientside_callback(
        """function(){
            const el = document.querySelector('[data-dash-is-loading=\"true\"]');
            return window.dash_clientside.no_update;
        }""",
        Output("q-input", "value", allow_duplicate=True),
        Input("q-input", "id"),
        prevent_initial_call=True,
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=os.environ.get(
        "NETSEC_RAG_DB", os.path.expanduser("~/netsec-rag/store.db")))
    ap.add_argument("--history-db",
                    default=os.environ.get(
                        "NETSEC_RAG_HISTORY_DB",
                        os.path.expanduser("~/netsec-rag/queries.db")))
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5200)
    ap.add_argument("--url-base",
                    default=os.environ.get("NETSEC_RAG_URL_BASE"),
                    help="Serve under a subpath (e.g. '/rag/') for a "
                         "reverse proxy. Must start AND end with '/'.")
    args = ap.parse_args(argv)

    engine = R.RagEngine(db_path=args.db)
    history = QueryHistory(args.history_db)
    app = build_app(engine, history, url_base=args.url_base)
    print(f"[rag-web] engine store: {args.db}")
    print(f"[rag-web] history db  : {args.history_db}")
    print(f"[rag-web] serving on http://{args.bind}:{args.port}"
          f"{args.url_base or '/'}")
    app.run(host=args.bind, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

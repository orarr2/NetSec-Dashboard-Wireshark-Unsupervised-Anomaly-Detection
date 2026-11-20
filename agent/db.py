"""The agent's own SQLite store. Tables are created on first use; NETSEC's netsec.db is never written."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DEFAULT_DB_PATH = "/var/lib/netsec-agent/netsec-agent.db"
OPEN_ACTIONS = ("urgent", "standard", "human_review")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    session_id INTEGER,
    candidate_id TEXT NOT NULL,
    kind TEXT,
    pcap_sha256 TEXT,
    pcap_name TEXT,
    submitted_at REAL NOT NULL,
    decided_at REAL,
    input_json TEXT NOT NULL,
    status TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    rationale TEXT NOT NULL DEFAULT '',
    assessment TEXT NOT NULL DEFAULT '',
    technique TEXT,
    score REAL,
    asset_role TEXT,
    engines_json TEXT NOT NULL DEFAULT '{}',
    trace_json TEXT NOT NULL DEFAULT '[]',
    cited_sources_json TEXT NOT NULL DEFAULT '[]',
    agent_value_json TEXT NOT NULL DEFAULT '',
    fallback_reason TEXT,
    policy_version TEXT,
    UNIQUE (session_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    decided_at REAL,
    decided_by TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS work_orders (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technique TEXT,
    asset_role TEXT,
    lesson TEXT NOT NULL,
    approval_id TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    axis TEXT NOT NULL,
    value TEXT NOT NULL,
    by_user TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_cache (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS catalogue (
    id TEXT PRIMARY KEY,
    pcap_sha256 TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    label TEXT,
    action TEXT,
    source TEXT NOT NULL,
    case_id TEXT,
    created_at REAL NOT NULL,
    UNIQUE (pcap_sha256, candidate_id)
);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._shared: sqlite3.Connection | None = None
        self._ready = False

    def _open(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            if self._shared is None:
                self._shared = sqlite3.connect(":memory:", check_same_thread=False)
                self._shared.row_factory = sqlite3.Row
            return self._shared
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._open()
            try:
                if not self._ready:
                    conn.executescript(_SCHEMA)
                    if self.path != ":memory:":
                        conn.execute("PRAGMA journal_mode=WAL")
                    self._ready = True
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                if conn is not self._shared:
                    conn.close()

    def ready(self) -> bool:
        try:
            with self.connect() as conn:
                conn.execute("SELECT 1 FROM cases LIMIT 1")
            return True
        except Exception:
            return False

    # ---- cases ---------------------------------------------------------

    def create_case(self, case_id: str, case: dict, metadata: dict | None = None) -> dict:
        """A new row in status 'queued'. `metadata` is what the engines said, as the trace header shows it."""
        md = metadata or {}
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO cases (id, session_id, candidate_id, kind, pcap_sha256, pcap_name, submitted_at, "
                "input_json, status, technique, score, asset_role, engines_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)",
                (case_id, case.get("session_id"), case.get("candidate_id"), case.get("kind"),
                 case.get("pcap_sha256"), case.get("pcap_name"), time.time(), json.dumps(case, default=str),
                 md.get("technique"), md.get("score"), md.get("asset_role"),
                 json.dumps(md.get("engines") or {}, default=str)),
            )
        return self.get_case(case_id)

    def find_case(self, session_id: Any, candidate_id: str) -> dict | None:
        if session_id is None:
            return None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE session_id = ? AND candidate_id = ?", (session_id, candidate_id)
            ).fetchone()
        return dict(row) if row else None

    def get_case(self, case_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return dict(row) if row else None

    def update_case(self, case_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.connect() as conn:
            conn.execute(f"UPDATE cases SET {cols} WHERE id = ?", (*fields.values(), case_id))

    def list_cases(self, since: float | None = None, limit: int = 500) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cases WHERE submitted_at >= ? ORDER BY submitted_at DESC LIMIT ?",
                (since or 0.0, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def interrupted_cases(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM cases WHERE status IN ('queued', 'processing')").fetchall()
        return [dict(r) for r in rows]

    # ---- approvals -----------------------------------------------------

    def create_approval(self, case_id: str, action: str, priority: int) -> str:
        approval_id = new_id("apr")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO approvals (id, case_id, action, priority, created_at) VALUES (?, ?, ?, ?, ?)",
                (approval_id, case_id, action, int(priority), time.time()),
            )
        return approval_id

    def list_pending_approvals(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def approvals_for_case(self, case_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM approvals WHERE case_id = ? ORDER BY created_at", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- work orders, notes, feedback ----------------------------------

    def create_work_order(self, case_id: str, kind: str, title: str, body: str) -> str:
        order_id = new_id("wo")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO work_orders (id, case_id, kind, title, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (order_id, case_id, kind, title, body, time.time()),
            )
        return order_id

    def work_orders_for_case(self, case_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM work_orders WHERE case_id = ?", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_note(self, technique: str | None, asset_role: str | None, lesson: str, approval_id: str | None = None) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO agent_notes (technique, asset_role, lesson, approval_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (technique, asset_role, lesson, approval_id, time.time()),
            )
            return int(cur.lastrowid)

    def recall_notes(self, technique: str | None, asset_role: str | None = None, limit: int = 5) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_notes WHERE technique IS ? AND (? IS NULL OR asset_role IS ?) "
                "ORDER BY created_at DESC LIMIT ?",
                (technique, asset_role, asset_role, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_feedback(self, case_id: str, axis: str, value: str, by_user: str | None = None) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO agent_feedback (case_id, axis, value, by_user, created_at) VALUES (?, ?, ?, ?, ?)",
                (case_id, axis, value, by_user, time.time()),
            )
            return int(cur.lastrowid)

    # ---- decision cache ------------------------------------------------

    def cache_put(self, key: str, value: dict, ttl_s: float = 120.0) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO decision_cache (key, value_json, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
                (key, json.dumps(value, default=str), time.time() + ttl_s),
            )

    def cache_get(self, key: str) -> dict | None:
        with self.connect() as conn:
            conn.execute("DELETE FROM decision_cache WHERE expires_at < ?", (time.time(),))
            row = conn.execute("SELECT value_json FROM decision_cache WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value_json"]) if row else None

    # ---- catalogue -----------------------------------------------------

    def catalogue_add(self, pcap_sha256: str, candidate_id: str, *, label: str | None, action: str | None,
                      source: str, case_id: str | None = None) -> str:
        entry_id = new_id("cat")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO catalogue (id, pcap_sha256, candidate_id, label, action, source, case_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(pcap_sha256, candidate_id) DO UPDATE SET "
                "label = excluded.label, action = excluded.action, source = excluded.source, case_id = excluded.case_id",
                (entry_id, pcap_sha256.lower(), candidate_id, label, action, source, case_id, time.time()),
            )
            row = conn.execute(
                "SELECT id FROM catalogue WHERE pcap_sha256 = ? AND candidate_id = ?",
                (pcap_sha256.lower(), candidate_id),
            ).fetchone()
        return str(row["id"])

    def catalogue_lookup(self, pcap_sha256: str | None, candidate_id: str | None) -> dict | None:
        if not pcap_sha256 or not candidate_id:
            return None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM catalogue WHERE pcap_sha256 = ? AND candidate_id = ?",
                (pcap_sha256.lower(), candidate_id),
            ).fetchone()
        return dict(row) if row else None


_REGISTRY: dict[str, Database] = {}
_REGISTRY_LOCK = threading.Lock()


def db_path() -> str:
    return os.environ.get("NETSEC_AGENT_DB_PATH") or DEFAULT_DB_PATH


def get_db(path: str | None = None) -> Database:
    key = path or db_path()
    with _REGISTRY_LOCK:
        if key not in _REGISTRY:
            _REGISTRY[key] = Database(key)
        return _REGISTRY[key]


def reset_db_registry() -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.clear()

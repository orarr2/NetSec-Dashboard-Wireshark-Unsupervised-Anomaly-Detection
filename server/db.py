"""SQLite history database - the schema from ARCHITECTURE_HE.md section 7.

Stdlib only. One deliberate deviation from the spec's first draft: the
sensors table stores ``hmac_secret`` itself, not a hash of it - HMAC
verification requires recomputing the signature with the secret, so a
hash cannot work. The secret is protected by the DB file's permissions
on the VM (the spec text was corrected to match).

Migrations run through ``PRAGMA user_version``: ``migrate()`` applies
every version above the file's current one, so calling it on an
existing database is a no-op.
"""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA_VERSION = 1

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS sensors (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
    token_hash TEXT NOT NULL,          -- sha256 of the read/API token
    hmac_secret TEXT NOT NULL,         -- upload-signing secret (see module doc)
    created_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT);

CREATE TABLE IF NOT EXISTS pcap_files (
    id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE NOT NULL,
    orig_name TEXT, size_bytes INTEGER, sensor_id INTEGER,
    received_at TEXT NOT NULL, capture_start REAL, capture_end REAL,
    storage_path TEXT NOT NULL,
    fields_path TEXT,
    deleted_at TEXT);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY, pcap_id INTEGER NOT NULL,
    label TEXT, status TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'prod',
    queued_at TEXT, started_at TEXT, finished_at TEXT, error TEXT,
    n_pkts INTEGER, n_ips INTEGER, duration_s REAL,
    pipeline_version TEXT, prompt_version TEXT,
    tshark_version TEXT, git_commit TEXT);

CREATE TABLE IF NOT EXISTS ip_features (
    session_id INTEGER NOT NULL, ip TEXT NOT NULL,
    mean_len REAL, std_len REAL, count INTEGER, burst_score REAL,
    unique_dsts INTEGER, syn_count INTEGER, rst_count INTEGER,
    fin_count INTEGER, null_count INTEGER, xmas_count INTEGER,
    bytes_src INTEGER, bytes_dst INTEGER,
    iso_score REAL, iso_flag INTEGER,
    dbscan_cluster INTEGER, dbscan_anomaly INTEGER, lstm_flag INTEGER,
    self_telemetry INTEGER DEFAULT 0,
    PRIMARY KEY (session_id, ip));

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    layer TEXT, rule TEXT, ip TEXT, severity TEXT, detail_json TEXT);

CREATE TABLE IF NOT EXISTS adv_signals (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    device TEXT, peer TEXT, signal TEXT, tactic TEXT, technique TEXT,
    score REAL, severity TEXT, count INTEGER,
    first_ts REAL, last_ts REAL, detail TEXT);

CREATE TABLE IF NOT EXISTS fusion_scores (
    session_id INTEGER NOT NULL, device TEXT NOT NULL,
    score REAL, engines_hit INTEGER, window_start REAL,
    PRIMARY KEY (session_id, device));

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    candidate_id TEXT NOT NULL,
    kind TEXT, rank INTEGER, capped INTEGER DEFAULT 0,
    context_json TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY, candidate_row INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    verdict TEXT, category TEXT, confidence REAL, priority_score REAL,
    guardrail_applied INTEGER, needs_human_review INTEGER,
    verdict_json TEXT NOT NULL,
    provider TEXT, model TEXT, latency_ms INTEGER, cached INTEGER,
    tokens_in INTEGER, tokens_out INTEGER);

CREATE TABLE IF NOT EXISTS panel_audit (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    candidate_id TEXT NOT NULL, judge_model TEXT NOT NULL,
    initial_verdict TEXT, final_verdict TEXT,
    debated INTEGER DEFAULT 0, error TEXT);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('json','md','html','pdf')),
    path TEXT NOT NULL, sha256 TEXT, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS device_baselines (
    device_key TEXT NOT NULL,
    window_start TEXT NOT NULL, window_end TEXT,
    features_json TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (device_key, window_start));

CREATE TABLE IF NOT EXISTS gaps (
    id INTEGER PRIMARY KEY, sensor_id INTEGER,
    start_ts REAL, end_ts REAL, reason TEXT);

CREATE TABLE IF NOT EXISTS llm_quota (
    provider TEXT NOT NULL, day TEXT NOT NULL,
    requests INTEGER DEFAULT 0, tokens INTEGER DEFAULT 0,
    last_429_at TEXT,
    PRIMARY KEY (provider, day));

CREATE TABLE IF NOT EXISTS telemetry_log (
    id INTEGER PRIMARY KEY, sensor_id INTEGER NOT NULL,
    started_at REAL, ended_at REAL,
    dst TEXT, dst_port INTEGER, bytes_sent INTEGER, file_sha256 TEXT,
    source TEXT NOT NULL CHECK (source IN ('manifest','ingest_log')),
    matched_session_id INTEGER);

CREATE INDEX IF NOT EXISTS idx_sessions_pcap    ON sessions(pcap_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_session ON verdicts(session_id);
CREATE INDEX IF NOT EXISTS idx_adv_session      ON adv_signals(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_sensors_token    ON sensors(token_hash);
CREATE INDEX IF NOT EXISTS idx_reports_session  ON reports(session_id);
"""


def default_db_path():
    root = os.environ.get("NETSEC_DATA_ROOT", "/srv/netsec")
    return os.environ.get("NETSEC_DB", os.path.join(root, "db", "netsec.db"))


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path=None):
    """Open (creating if needed) the history DB with WAL and migrations
    applied. Returns a sqlite3.Connection with row access by name."""
    path = db_path or default_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    migrate(conn)
    return conn


def migrate(conn):
    """Apply schema versions above the file's current user_version."""
    current, = conn.execute("PRAGMA user_version").fetchone()
    if current < 1:
        conn.executescript(_SCHEMA_V1)
        conn.execute("PRAGMA user_version = 1")
        conn.commit()
    return SCHEMA_VERSION


# ---- sensors -------------------------------------------------------------

def create_sensor(conn, name, token_hash, hmac_secret):
    """Register a sensor. Fails loudly on a duplicate name so a re-run
    never silently rotates credentials."""
    cur = conn.execute(
        "INSERT INTO sensors (name, token_hash, hmac_secret, created_at) "
        "VALUES (?, ?, ?, ?)", (name, token_hash, hmac_secret, _utcnow()))
    conn.commit()
    return cur.lastrowid


def get_sensor(conn, name):
    row = conn.execute("SELECT * FROM sensors WHERE name = ?",
                       (name,)).fetchone()
    return dict(row) if row else None


def get_sensor_by_token_hash(conn, token_hash):
    row = conn.execute("SELECT * FROM sensors WHERE token_hash = ?",
                       (token_hash,)).fetchone()
    return dict(row) if row else None


def touch_sensor(conn, sensor_id):
    conn.execute("UPDATE sensors SET last_seen_at = ? WHERE id = ?",
                 (_utcnow(), sensor_id))
    conn.commit()


# ---- pcaps + sessions ----------------------------------------------------

def register_pcap(conn, sha256, orig_name, size_bytes, sensor_id,
                  storage_path):
    """Idempotent by sha256. Returns (pcap_id, created)."""
    row = conn.execute("SELECT id FROM pcap_files WHERE sha256 = ?",
                       (sha256,)).fetchone()
    if row:
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO pcap_files (sha256, orig_name, size_bytes, sensor_id,"
        " received_at, storage_path) VALUES (?, ?, ?, ?, ?, ?)",
        (sha256, orig_name, size_bytes, sensor_id, _utcnow(), storage_path))
    conn.commit()
    return cur.lastrowid, True


def create_session(conn, pcap_id, label, kind="prod"):
    if kind not in ("prod", "test"):
        raise ValueError(f"kind must be prod|test, got {kind!r}")
    cur = conn.execute(
        "INSERT INTO sessions (pcap_id, label, status, kind, queued_at) "
        "VALUES (?, ?, 'queued', ?, ?)", (pcap_id, label, kind, _utcnow()))
    conn.commit()
    return cur.lastrowid


def latest_session_for_pcap(conn, pcap_id):
    row = conn.execute(
        "SELECT id FROM sessions WHERE pcap_id = ? ORDER BY id DESC LIMIT 1",
        (pcap_id,)).fetchone()
    return row["id"] if row else None


def get_session(conn, session_id):
    row = conn.execute(
        "SELECT s.*, p.sha256, p.orig_name, p.size_bytes"
        " FROM sessions s JOIN pcap_files p ON p.id = s.pcap_id"
        " WHERE s.id = ?", (session_id,)).fetchone()
    return dict(row) if row else None


# ---- reports + telemetry -------------------------------------------------

def add_report(conn, session_id, kind, path, sha256=None):
    cur = conn.execute(
        "INSERT INTO reports (session_id, kind, path, sha256, created_at) "
        "VALUES (?, ?, ?, ?, ?)", (session_id, kind, path, sha256, _utcnow()))
    conn.commit()
    return cur.lastrowid


def get_report(conn, session_id, kind):
    row = conn.execute(
        "SELECT * FROM reports WHERE session_id = ? AND kind = ? "
        "ORDER BY id DESC LIMIT 1", (session_id, kind)).fetchone()
    return dict(row) if row else None


def log_ingest_telemetry(conn, sensor_id, started_at, ended_at, dst,
                         dst_port, bytes_sent, file_sha256, session_id):
    """The VM-side half of the reconciliation protocol (spec 12.2):
    every received upload is recorded with source='ingest_log'."""
    cur = conn.execute(
        "INSERT INTO telemetry_log (sensor_id, started_at, ended_at, dst,"
        " dst_port, bytes_sent, file_sha256, source, matched_session_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 'ingest_log', ?)",
        (sensor_id, started_at, ended_at, dst, dst_port, bytes_sent,
         file_sha256, session_id))
    conn.commit()
    return cur.lastrowid

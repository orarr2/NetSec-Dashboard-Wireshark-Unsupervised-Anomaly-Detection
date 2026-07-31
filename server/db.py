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
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

SCHEMA_VERSION = 3

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

# v2: OSINT enrichment (stage YA). A cache of external lookups (Wigle by
# BSSID, Shodan by IP) so a given key is queried once per TTL, and the
# 'map' report kind. Purely additive - absent API keys, the table simply
# stays empty and nothing else changes.
_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS enrichment (
    source TEXT NOT NULL,          -- 'wigle_bssid' | 'shodan_ip'
    key TEXT NOT NULL,             -- the bssid or ip looked up
    data_json TEXT,                -- provider response subset (NULL if none)
    ok INTEGER NOT NULL DEFAULT 1, -- 0 = queried, no data / error
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source, key));

-- widen reports.kind to include 'map' (SQLite needs a table rebuild for a
-- CHECK change; reports is small and this preserves every existing row)
ALTER TABLE reports RENAME TO reports_v1;
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('json','md','html','pdf','map')),
    path TEXT NOT NULL, sha256 TEXT, created_at TEXT NOT NULL);
INSERT INTO reports (id, session_id, kind, path, sha256, created_at)
    SELECT id, session_id, kind, path, sha256, created_at FROM reports_v1;
DROP TABLE reports_v1;
CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
"""

# v3: per-session email delivery. The uploader can carry an address
# through the ingest header X-Notify-Email; the worker mails the report
# to it when the run finishes. Absent the column the worker fell back to
# a single NETSEC_NOTIFY_EMAIL env var - fine for a solo operator, not
# fine when different people upload against the same VM.
_SCHEMA_V3 = """
ALTER TABLE sessions ADD COLUMN notify_email TEXT;
"""


def default_db_path():
    """Resolve the history DB path. Treats NETSEC_DB set to an EMPTY
    string exactly like an unset variable - this matters because docker
    compose's `env_file: .env` exports every line, and a blank
    `NETSEC_DB=` in .env used to poison the worker (which loads .env)
    while leaving the ingest_api (which only reads `environment:`
    entries) untouched. The .env.example ships that blank line as a
    documentation hint, so removing it there would be a worse fix."""
    root = os.environ.get("NETSEC_DATA_ROOT", "/srv/netsec") \
        or "/srv/netsec"
    override = (os.environ.get("NETSEC_DB") or "").strip()
    return override or os.path.join(root, "db", "netsec.db")


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
    if current < 2:
        conn.executescript(_SCHEMA_V2)
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
    if current < 3:
        conn.executescript(_SCHEMA_V3)
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
    return SCHEMA_VERSION


# ---- enrichment cache (stage YA) -----------------------------------------

def get_enrichment(conn, source, key, max_age_days=None):
    """Cached lookup, or None when absent/stale. max_age_days=None never
    expires."""
    row = conn.execute(
        "SELECT * FROM enrichment WHERE source=? AND key=?",
        (source, key)).fetchone()
    if row is None:
        return None
    if max_age_days is not None:
        try:
            age = (datetime.now(timezone.utc)
                   - datetime.fromisoformat(row["updated_at"])).days
            if age > max_age_days:
                return None
        except Exception:
            pass
    out = dict(row)
    out["data"] = json.loads(row["data_json"]) if row["data_json"] else None
    return out


def put_enrichment(conn, source, key, data, ok=True):
    conn.execute(
        "INSERT OR REPLACE INTO enrichment (source, key, data_json, ok,"
        " updated_at) VALUES (?,?,?,?,?)",
        (source, key, json.dumps(data) if data is not None else None,
         int(ok), _utcnow()))
    conn.commit()


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
    """Idempotent by sha256. Returns (pcap_id, created).

    A row whose raw file was already purged (deleted_at set) is REACTIVATED,
    not treated as a duplicate: its storage_path is repointed at the freshly
    uploaded copy and deleted_at is cleared, and created=True is returned so
    the caller queues a new analysis. Without this, a re-upload after
    retention purged the raw would leave the new file on disk with no live
    DB row - invisible to retention (WHERE deleted_at IS NULL) and never
    re-analysed."""
    row = conn.execute(
        "SELECT id, deleted_at FROM pcap_files WHERE sha256 = ?",
        (sha256,)).fetchone()
    if row:
        if row["deleted_at"] is not None:
            conn.execute(
                "UPDATE pcap_files SET storage_path = ?, size_bytes = ?,"
                " received_at = ?, deleted_at = NULL WHERE id = ?",
                (storage_path, size_bytes, _utcnow(), row["id"]))
            conn.commit()
            return row["id"], True
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO pcap_files (sha256, orig_name, size_bytes, sensor_id,"
        " received_at, storage_path) VALUES (?, ?, ?, ?, ?, ?)",
        (sha256, orig_name, size_bytes, sensor_id, _utcnow(), storage_path))
    conn.commit()
    return cur.lastrowid, True


def create_session(conn, pcap_id, label, kind="prod", notify_email=None):
    if kind not in ("prod", "test"):
        raise ValueError(f"kind must be prod|test, got {kind!r}")
    cur = conn.execute(
        "INSERT INTO sessions (pcap_id, label, status, kind, queued_at,"
        " notify_email) VALUES (?, ?, 'queued', ?, ?, ?)",
        (pcap_id, label, kind, _utcnow(), notify_email))
    conn.commit()
    return cur.lastrowid


def set_session_notify_email(conn, session_id, notify_email):
    """Set a session's notify_email if currently null. Called on a
    duplicate upload that carries an address while the original had none
    - so the requester still gets their mail even when the second upload
    is deduped to the first session. Never overwrites an existing address:
    the first requester's inbox wins."""
    if not notify_email:
        return False
    cur = conn.execute(
        "UPDATE sessions SET notify_email=? WHERE id=? AND notify_email IS NULL",
        (notify_email, session_id))
    conn.commit()
    return cur.rowcount > 0


def latest_session_for_pcap(conn, pcap_id):
    row = conn.execute(
        "SELECT id FROM sessions WHERE pcap_id = ? ORDER BY id DESC LIMIT 1",
        (pcap_id,)).fetchone()
    return row["id"] if row else None


def get_session(conn, session_id):
    row = conn.execute(
        "SELECT s.*, p.sha256, p.orig_name, p.size_bytes, p.storage_path,"
        " p.sensor_id"
        " FROM sessions s JOIN pcap_files p ON p.id = s.pcap_id"
        " WHERE s.id = ?", (session_id,)).fetchone()
    return dict(row) if row else None


# ---- worker queue --------------------------------------------------------

# A session is only ever moved out of 'running' by mark_done/mark_error,
# so a worker killed mid-analysis (OOM, container restart, power loss)
# leaves its row running forever and that PCAP is never analysed again.
# Anything still running after this many seconds is treated as abandoned
# and requeued. The default is generously above the slowest observed
# analysis (a 37k-packet flood capture takes ~75s).
STALE_RUNNING_S = int(os.environ.get("NETSEC_STALE_RUNNING_S", "3600"))


def requeue_stale_jobs(conn, stale_s=None, now=None):
    """Return abandoned 'running' sessions to the queue. Returns the list
    of requeued session ids so the caller can log them - a silent requeue
    would hide a worker that is crash-looping on one capture."""
    stale_s = STALE_RUNNING_S if stale_s is None else stale_s
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(seconds=stale_s)
    # started_at is written by _utcnow(), so compare in the same shape -
    # these are lexically ordered ISO-8601 strings.
    cutoff_s = cutoff.isoformat(timespec="seconds")
    rows = conn.execute(
        "SELECT id FROM sessions WHERE status='running'"
        " AND started_at IS NOT NULL AND started_at < ?",
        (cutoff_s,)).fetchall()
    ids = [r["id"] for r in rows]
    for sid in ids:
        conn.execute(
            "UPDATE sessions SET status='queued', started_at=NULL"
            " WHERE id=? AND status='running'", (sid,))
    if ids:
        conn.commit()
    return ids


def claim_next_job(conn):
    """Atomically move the oldest queued session to running and return it
    (joined with its pcap row), or None when the queue is empty. Uses an
    IMMEDIATE transaction instead of RETURNING so any sqlite3 works.

    Abandoned 'running' rows are requeued first, so a worker death cannot
    strand a capture."""
    stale = requeue_stale_jobs(conn)
    if stale:
        print(f"[db] requeued {len(stale)} stale running session(s): "
              f"{stale}", flush=True)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT id FROM sessions WHERE status='queued' "
            "ORDER BY id LIMIT 1").fetchone()
        if row is None:
            conn.execute("COMMIT")
            return None
        conn.execute(
            "UPDATE sessions SET status='running', started_at=? WHERE id=?",
            (_utcnow(), row["id"]))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return get_session(conn, row["id"])


def mark_done(conn, session_id, **stats):
    """Finish a session. stats may set n_pkts, n_ips, duration_s,
    pipeline_version, prompt_version, tshark_version, git_commit."""
    allowed = ("n_pkts", "n_ips", "duration_s", "pipeline_version",
               "prompt_version", "tshark_version", "git_commit")
    sets, vals = ["status='done'", "finished_at=?"], [_utcnow()]
    for key in allowed:
        if key in stats and stats[key] is not None:
            sets.append(f"{key}=?")
            vals.append(stats[key])
    vals.append(session_id)
    conn.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()


def mark_error(conn, session_id, error):
    conn.execute(
        "UPDATE sessions SET status='error', finished_at=?, error=? "
        "WHERE id=?", (_utcnow(), str(error)[:2000], session_id))
    conn.commit()


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

"""Per-provider quota counters (spec section 6.3). Stdlib only.

Schema matches the history DB's llm_quota table exactly, so the same
code works whether it writes to llm_judge's own sqlite (standalone
default) or to the VM's netsec.db (point LLM_JUDGE_QUOTA_DB at it).

A provider is "exhausted" for the day once it records a 429 AND its
request/token counters reach the profile's declared ceilings - the
counters are advisory and the 429 is authoritative, so a provider that
never 429s is never skipped no matter what the ceiling says.
"""
import os
import sqlite3
from datetime import datetime, timezone

try:
    from . import judge_config
except ImportError:
    import judge_config


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class QuotaStore:
    def __init__(self, db_path=None):
        self.db_path = db_path or judge_config.QUOTA_DB
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)),
                    exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_quota (
                provider TEXT NOT NULL, day TEXT NOT NULL,
                requests INTEGER DEFAULT 0, tokens INTEGER DEFAULT 0,
                last_429_at TEXT,
                PRIMARY KEY (provider, day))""")
        self._conn.commit()

    def record(self, provider, tokens=0, was_429=False):
        day = _today()
        self._conn.execute(
            "INSERT INTO llm_quota (provider, day, requests, tokens) "
            "VALUES (?, ?, 1, ?) ON CONFLICT(provider, day) DO UPDATE SET "
            "requests = requests + 1, tokens = tokens + excluded.tokens",
            (provider, day, int(tokens or 0)))
        if was_429:
            self._conn.execute(
                "UPDATE llm_quota SET last_429_at = ? WHERE provider = ? "
                "AND day = ?",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 provider, day))
        self._conn.commit()

    def stats(self, provider, day=None):
        row = self._conn.execute(
            "SELECT requests, tokens, last_429_at FROM llm_quota WHERE "
            "provider = ? AND day = ?",
            (provider, day or _today())).fetchone()
        if not row:
            return {"requests": 0, "tokens": 0, "last_429_at": None}
        return {"requests": row[0], "tokens": row[1], "last_429_at": row[2]}

    def is_exhausted(self, provider, req_cap=None, token_cap=None):
        """True only when the provider has 429'd today AND has hit a
        declared ceiling. No ceiling + no 429 -> never exhausted."""
        s = self.stats(provider)
        if not s["last_429_at"]:
            return False
        if req_cap and s["requests"] >= req_cap:
            return True
        if token_cap and s["tokens"] >= token_cap:
            return True
        # 429 seen but no ceiling to compare against: treat as exhausted
        # for the day only if neither cap was declared (fail safe - a
        # 429'ing provider with unknown limits should yield to the chain)
        return not (req_cap or token_cap)

    def close(self):
        self._conn.close()

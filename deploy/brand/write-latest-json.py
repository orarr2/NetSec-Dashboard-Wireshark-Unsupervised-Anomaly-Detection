#!/usr/bin/env python3
"""Write /srv/portal/latest.json with a summary of the most-recent
finished NetSec session, so the portal card can show it without going
to email.

Fired every 60s by netsec-portal-latest.timer. Cheap - one DB query
plus one JSON read of the session's verdicts.json.
"""
import json
import os
import pathlib
import sqlite3
import sys
from datetime import datetime


DB = os.environ.get("NETSEC_DB", "/srv/netsec/db/netsec.db")
REPORTS = os.environ.get("NETSEC_REPORTS", "/srv/netsec/reports")
OUT = os.environ.get("NETSEC_LATEST_JSON", "/srv/portal/latest.json")


def _fmt_when(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace(" ", "T"))
        return dt.strftime("%a %d %b %Y, %H:%M")
    except Exception:
        return str(ts)


def _fmt_duration(seconds):
    if not seconds:
        return None
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return None
    if s >= 3600:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    if s >= 60:
        return f"{s // 60}m {s % 60}s"
    return f"{s}s"


def main():
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        print(f"[latest-json] cannot open DB: {e}", file=sys.stderr)
        sys.exit(0)

    row = conn.execute(
        "SELECT s.id, s.label, s.finished_at, s.n_pkts, s.duration_s,"
        " p.orig_name, p.storage_path"
        " FROM sessions s JOIN pcap_files p ON p.id = s.pcap_id"
        " WHERE s.status = 'done'"
        " ORDER BY datetime(s.finished_at) DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        print("[latest-json] no finished sessions yet")
        sys.exit(0)

    sid = row["id"]
    verdicts_path = os.path.join(REPORTS, str(sid), "verdicts.json")
    counts = {"malicious": 0, "suspicious": 0, "benign": 0}
    recorded = None
    if os.path.isfile(verdicts_path):
        try:
            with open(verdicts_path, encoding="utf-8") as f:
                v = json.load(f)
            for r in (v.get("results") or []):
                verdict = ((r.get("verdict") or {}).get("verdict"))
                if verdict in counts:
                    counts[verdict] += 1
            ctx = v.get("context") or {}
            tr = (ctx.get("time_range") or [None])[0]
            recorded = _fmt_when(tr) or _fmt_when(row["finished_at"])
        except Exception as e:
            print(f"[latest-json] parse verdicts.json failed: {e}",
                  file=sys.stderr)

    out = {
        "sid": sid,
        "label": row["label"],
        "file": row["orig_name"],
        "recorded": recorded or _fmt_when(row["finished_at"]),
        "n_packets": f"{row['n_pkts']:,}" if row["n_pkts"] else None,
        "duration": _fmt_duration(row["duration_s"]),
        "counts": counts,
        "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    os.replace(tmp, OUT)
    print(f"[latest-json] wrote {OUT}: session {sid} · {counts}")


if __name__ == "__main__":
    main()

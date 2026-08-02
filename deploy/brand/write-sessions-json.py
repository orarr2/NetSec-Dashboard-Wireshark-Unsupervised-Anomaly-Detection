#!/usr/bin/env python3
"""Write /srv/portal/sessions.json - a compact list of every done
session in the DB with its verdict counts, so the portal's Reports
Browser page can render without hitting the DB directly.

Fired every 60s alongside write-latest-json.py.
"""
import json
import os
import sqlite3
import sys
from datetime import datetime


DB = os.environ.get("NETSEC_DB", "/srv/netsec/db/netsec.db")
REPORTS = os.environ.get("NETSEC_REPORTS", "/srv/netsec/reports")
OUT = os.environ.get("NETSEC_SESSIONS_JSON", "/srv/portal/sessions.json")


def _fmt_when(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace(" ", "T"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)


def _counts_for(sid):
    p = os.path.join(REPORTS, str(sid), "verdicts.json")
    if not os.path.isfile(p):
        return {"malicious": 0, "suspicious": 0, "benign": 0, "total": 0}
    try:
        with open(p, encoding="utf-8") as f:
            v = json.load(f)
    except Exception:
        return {"malicious": 0, "suspicious": 0, "benign": 0, "total": 0}
    c = {"malicious": 0, "suspicious": 0, "benign": 0, "total": 0}
    for r in (v.get("results") or []):
        vv = ((r.get("verdict") or {}).get("verdict"))
        if vv in c:
            c[vv] += 1
        c["total"] += 1
    return c


def main():
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        print(f"[sessions-json] cannot open DB: {e}", file=sys.stderr)
        sys.exit(0)

    rows = conn.execute(
        "SELECT s.id, s.label, s.finished_at, s.n_pkts, s.duration_s,"
        " p.orig_name, sen.name AS sensor_name"
        " FROM sessions s"
        " JOIN pcap_files p ON p.id = s.pcap_id"
        " LEFT JOIN sensors sen ON sen.id = p.sensor_id"
        " WHERE s.status = 'done'"
        " ORDER BY datetime(s.finished_at) DESC").fetchall()
    conn.close()

    sessions = []
    for r in rows:
        sid = r["id"]
        counts = _counts_for(sid)
        # Only expose fields the browser actually renders.
        sessions.append({
            "sid": sid,
            "label": r["label"],
            "file": r["orig_name"],
            "sensor": r["sensor_name"],
            "finished_at": _fmt_when(r["finished_at"]),
            "n_pkts": r["n_pkts"],
            "counts": counts,
            "report_url": f"/reports/{sid}/report.html",
        })

    out = {
        "sessions": sessions,
        "total": len(sessions),
        "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    os.replace(tmp, OUT)
    print(f"[sessions-json] wrote {OUT}: {len(sessions)} sessions")


if __name__ == "__main__":
    main()

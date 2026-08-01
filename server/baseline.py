"""Per-device baselines from history (spec section 3/D3, stage ט).

"What is normal for THIS device" instead of "what is normal in these 135
seconds". Baselines are computed only from prod sessions (decision
IDX-11) - test runs never teach the model that scanning is normal.

Keyed by device: the ip_features table carries an IP today, so device_key
is the IP; MAC enrichment (spec's "MAC when known, else IP") lands when
the worker persists per-IP MAC, and only the key derivation changes here.

Nightly job (spec section 10): `python -m server.baseline` recomputes
from a trailing window and upserts device_baselines. compare_session()
scores a fresh session against the stored baselines so the dashboard and
worker can surface "this device is behaving unlike its own history".
Stdlib only.
"""
import argparse
import json
import math
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import db, storage  # noqa: E402

FEATURE_COLS = ("mean_len", "std_len", "count", "burst_score",
                "unique_dsts", "syn_count", "rst_count", "fin_count",
                "null_count", "xmas_count", "bytes_src", "bytes_dst")


def _mean_std(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return 0.0, 0.0
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n if n > 1 else 0.0
    return mean, math.sqrt(var)


def compute_baselines(conn, days=None, now=None, min_sessions=2):
    """Recompute per-device baselines from prod, done sessions inside the
    trailing window. A device needs >= min_sessions observations (one
    reading is not a baseline). Returns the number of devices written."""
    days = days if days is not None else int(
        os.environ.get("BASELINE_WINDOW_DAYS", "30"))
    now = now or datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).isoformat(timespec="seconds")

    rows = conn.execute(
        f"SELECT f.ip AS ip, {', '.join('f.' + c for c in FEATURE_COLS)}"
        " FROM ip_features f JOIN sessions s ON s.id = f.session_id"
        " WHERE s.kind='prod' AND s.status='done'"
        "   AND (s.finished_at IS NULL OR s.finished_at >= ?)"
        "   AND f.self_telemetry = 0",
        (start,)).fetchall()

    by_device = {}
    for r in rows:
        by_device.setdefault(r["ip"], []).append(r)

    # The stored window must describe the observations the baseline was
    # actually computed from - `start` (now - days), not `now`. Stamping
    # both ends with `now` records every 30-day baseline as a zero-length
    # window, which misreports the provenance to anything that reads it.
    window_start = start
    written = 0
    for device, observations in by_device.items():
        if len(observations) < min_sessions:
            continue
        feats = {}
        for col in FEATURE_COLS:
            mean, std = _mean_std([o[col] for o in observations])
            feats[col] = {"mean": round(mean, 4), "std": round(std, 4)}
        conn.execute(
            "INSERT OR REPLACE INTO device_baselines (device_key,"
            " window_start, window_end, features_json, updated_at)"
            " VALUES (?,?,?,?,?)",
            (device, window_start, now.isoformat(timespec="seconds"),
             json.dumps({"n": len(observations), "features": feats},
                        sort_keys=True),
             now.isoformat(timespec="seconds")))
        written += 1
    conn.commit()
    return written


def get_baseline(conn, device_key):
    row = conn.execute(
        "SELECT * FROM device_baselines WHERE device_key=?"
        " ORDER BY window_start DESC LIMIT 1", (device_key,)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["features"] = json.loads(out["features_json"])
    return out


def lookup_history(conn, ip, exclude_session_id=None, now=None):
    """L5: build a compact history block for one IP: has the pipeline
    judged this IP in any prior finished session, when was it first
    seen, and what was the prior verdict distribution.

    Returns None if the IP has never been seen (or only in the current
    session), so `assemble_candidates` can fall back to the null
    defaults - the SYSTEM_PROMPT teaches null=unknown, which is exactly
    what "we have no prior data on this IP" means.

    Never raises. If the query throws (older schema, malformed row),
    returns None and the candidate lands as historyless.
    """
    try:
        q = ("SELECT v.session_id, v.verdict, s.finished_at "
             "FROM verdicts v JOIN sessions s ON s.id = v.session_id "
             "WHERE v.candidate_id = ? AND s.status = 'done'")
        params = [ip]
        if exclude_session_id is not None:
            q += " AND v.session_id != ?"
            params.append(exclude_session_id)
        q += " ORDER BY s.finished_at ASC"
        rows = conn.execute(q, params).fetchall()
        if not rows:
            return None
        first_at = rows[0]["finished_at"]
        counts = {"benign": 0, "suspicious": 0, "malicious": 0}
        for r in rows:
            v = r["verdict"]
            if v in counts:
                counts[v] += 1
        total = sum(counts.values())
        summary_parts = [f"{n}/{total} {k}" for k, n in counts.items()
                         if n > 0]
        summary = " · ".join(summary_parts) if summary_parts else None
        days = None
        if first_at:
            try:
                first = datetime.fromisoformat(first_at.replace("Z", "+00:00"))
                now = now or datetime.now(timezone.utc)
                days = int((now - first).total_seconds() / 86400)
            except Exception:
                days = None
        return {"seen_before": True,
                "days_since_first_seen": days,
                "prior_verdict_summary": summary}
    except Exception:
        return None


def compare_session(conn, session_id, z_threshold=3.0):
    """Score a session's per-IP features against each device's baseline.
    Returns [{"ip", "feature", "value", "baseline_mean", "z"}] for every
    (device, feature) whose deviation exceeds z_threshold - the raw
    material for a 'behaving unlike its own history' finding. Devices with
    no baseline yet are skipped (nothing to compare against)."""
    deviations = []
    rows = conn.execute(
        f"SELECT ip, {', '.join(FEATURE_COLS)} FROM ip_features"
        " WHERE session_id=? AND self_telemetry=0", (session_id,)).fetchall()
    for r in rows:
        base = get_baseline(conn, r["ip"])
        if not base:
            continue
        feats = base["features"].get("features", {})
        for col in FEATURE_COLS:
            spec = feats.get(col)
            value = r[col]
            if not spec or value is None:
                continue
            std = spec["std"]
            if std <= 1e-9:            # a flat baseline can't yield a z
                continue
            z = (value - spec["mean"]) / std
            if abs(z) >= z_threshold:
                deviations.append({
                    "ip": r["ip"], "feature": col, "value": value,
                    "baseline_mean": spec["mean"], "z": round(z, 2)})
    deviations.sort(key=lambda d: -abs(d["z"]))
    return deviations


def write_baseline_findings(conn, session_id, z_threshold=3.0):
    """Persist the per-device deviations of one session as findings rows
    (layer='baseline'), so 'unlike its own history' shows up in the same
    place as the rule and telemetry findings."""
    devs = compare_session(conn, session_id, z_threshold)
    for d in devs:
        conn.execute(
            "INSERT INTO findings (session_id, layer, rule, ip, severity,"
            " detail_json) VALUES (?,?,?,?,?,?)",
            (session_id, "baseline", f"deviation:{d['feature']}", d["ip"],
             "medium", json.dumps(d, sort_keys=True)))
    conn.commit()
    return len(devs)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recompute per-device baselines from prod history")
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--db", default=None)
    args = ap.parse_args(argv)
    conn = db.connect(args.db)
    try:
        n = compute_baselines(conn, days=args.days)
        print(f"[baseline] wrote {n} device baseline(s)", flush=True)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

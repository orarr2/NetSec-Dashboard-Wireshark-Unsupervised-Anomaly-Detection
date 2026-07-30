"""Telemetry reconciliation - the analyzer-side of spec section 12.2.

Three sources are cross-checked per analyzed session:

    flows in the capture  <->  sensor manifest + VM ingest log
                               (both live in telemetry_log)

- A capture flow toward a declared infrastructure destination that has
  an overlapping telemetry record is tagged self_telemetry (visible,
  excluded from anomaly training) and the record is bound to the
  session via matched_session_id.
- A capture flow toward infrastructure with NO overlapping record is a
  finding: someone else is using the telemetry channel.
- A telemetry record with no matching capture flow is a finding too:
  the capture has a blind spot (filter too wide, or the sensor cannot
  see itself).

The declared destination set comes from NETSEC_INFRA_DSTS (comma-
separated IPs/hostnames) - the same config that generates the capture
filter, so nothing can be excluded without being declared.

This stage matches on (time window, destination). Byte-volume tolerance
(the spec's 15%) needs per-pair byte counts that the aggregate session
dict does not carry yet; it lands with the capture agent stage, where
continuous data makes it meaningful.
"""
import json
import os

WINDOW_SLACK_S = 120


def infra_dsts(env=None):
    env = os.environ if env is None else env
    raw = env.get("NETSEC_INFRA_DSTS", "")
    return {d.strip() for d in raw.split(",") if d.strip()}


def _epoch(dt):
    try:
        return dt.timestamp()
    except Exception:
        return None


def reconcile(conn, session_id, S, dsts=None, slack_s=WINDOW_SLACK_S):
    """Run the three-way match for one session. Returns a summary dict;
    writes ip_features.self_telemetry flags and findings rows."""
    dsts = infra_dsts() if dsts is None else set(dsts)
    summary = {"infra_dsts": sorted(dsts), "matched_ips": [],
               "undeclared": 0, "blind_spots": 0}
    if not dsts:
        return summary

    t0, t1 = _epoch(S.get("t0")), _epoch(S.get("t1"))
    if t0 is None or t1 is None:
        return summary

    rows = conn.execute(
        "SELECT * FROM telemetry_log WHERE started_at <= ? AND"
        " ended_at >= ?", (t1 + slack_s, t0 - slack_s)).fetchall()
    rows = [dict(r) for r in rows]

    pairs = S.get("ip_pairs") or {}
    infra_pairs = [(src, dst, cnt) for (src, dst), cnt in pairs.items()
                   if dst in dsts]

    matched_srcs = set()
    for src, dst, cnt in infra_pairs:
        if rows:
            matched_srcs.add(src)
        else:
            conn.execute(
                "INSERT INTO findings (session_id, layer, rule, ip,"
                " severity, detail_json) VALUES (?,?,?,?,?,?)",
                (session_id, "telemetry", "undeclared_infra_flow", src,
                 "high", json.dumps({"dst": dst, "packets": int(cnt)})))
            summary["undeclared"] += 1

    for src in matched_srcs:
        conn.execute(
            "UPDATE ip_features SET self_telemetry=1 WHERE session_id=?"
            " AND ip=?", (session_id, src))
    for r in rows:
        conn.execute(
            "UPDATE telemetry_log SET matched_session_id=? WHERE id=?"
            " AND matched_session_id IS NULL", (session_id, r["id"]))

    if rows and not infra_pairs:
        for r in rows:
            conn.execute(
                "INSERT INTO findings (session_id, layer, rule, ip,"
                " severity, detail_json) VALUES (?,?,?,?,?,?)",
                (session_id, "telemetry", "capture_blind_spot", None,
                 "medium", json.dumps({"telemetry_row": r["id"],
                                       "dst": r.get("dst"),
                                       "bytes_sent": r.get("bytes_sent")})))
            summary["blind_spots"] += 1

    summary["matched_ips"] = sorted(matched_srcs)
    conn.commit()
    return summary

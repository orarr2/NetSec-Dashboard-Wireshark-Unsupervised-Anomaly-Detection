"""Persist one analysis run into the history DB (spec section 7).

Everything here is defensive by design: the pipeline's dict shapes are
owned by app/ and llm_judge/, and a missing optional key must degrade to
a NULL column, never to a crashed worker. Advanced-engine signals
(adv_signals / fusion_scores) are dashboard-side today and stay empty
until a later stage runs those engines headless - the tables exist so
that wiring them is a pure INSERT.
"""
import json


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _get(row, name):
    """Column from a pandas itertuples() row, or None."""
    val = getattr(row, name, None)
    try:
        import math
        if val is not None and isinstance(val, float) and math.isnan(val):
            return None
    except Exception:
        pass
    return val


def write_ip_features(conn, session_id, S):
    """ip_agg (indexed by IP) -> ip_features rows. No-op without ip_agg."""
    ip_agg = S.get("ip_agg") if isinstance(S, dict) else None
    if ip_agg is None or len(ip_agg) == 0:
        return 0
    bytes_src = S.get("bytes_src") or {}
    bytes_dst = S.get("bytes_dst") or {}
    n = 0
    for row in ip_agg.itertuples():
        ip = str(row.Index)
        conn.execute(
            "INSERT OR REPLACE INTO ip_features (session_id, ip, mean_len,"
            " std_len, count, burst_score, unique_dsts, syn_count,"
            " rst_count, fin_count, null_count, xmas_count, bytes_src,"
            " bytes_dst, iso_score, iso_flag, dbscan_cluster,"
            " dbscan_anomaly, lstm_flag)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, ip, _get(row, "mean_len"), _get(row, "std_len"),
             _get(row, "count"), _get(row, "burst_score"),
             _get(row, "unique_dsts"), _get(row, "syn_count"),
             _get(row, "rst_count"), _get(row, "fin_count"),
             _get(row, "null_count"), _get(row, "xmas_count"),
             int(bytes_src.get(ip, 0)), int(bytes_dst.get(ip, 0)),
             _get(row, "iso_score"), _get(row, "iso_flag"),
             _get(row, "cluster"), _get(row, "anomaly"),
             _get(row, "lstm_flag")))
        n += 1
    conn.commit()
    return n


def write_findings(conn, session_id, findings):
    """run_security_scans() dict -> findings rows: every list-valued key
    becomes one row per entry, keyed by the alert's src IP when present."""
    if not isinstance(findings, dict):
        return 0
    n = 0
    for rule, entries in findings.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            ip = entry.get("src") if isinstance(entry, dict) else None
            conn.execute(
                "INSERT INTO findings (session_id, layer, rule, ip,"
                " severity, detail_json) VALUES (?,?,?,?,?,?)",
                (session_id, "rules", rule, ip, "high", _canonical(entry)))
            n += 1
    conn.commit()
    return n


def write_candidates(conn, session_id, assembled):
    """assemble_candidates() output -> candidates rows. Returns
    {candidate_id: row_id} for the verdict writer."""
    ids = {}
    capped = set(assembled.get("capped") or [])
    for rank, cand in enumerate(assembled.get("candidates") or []):
        cur = conn.execute(
            "INSERT INTO candidates (session_id, candidate_id, kind, rank,"
            " capped, context_json) VALUES (?,?,?,?,?,?)",
            (session_id, cand.get("candidate_id"), cand.get("kind"),
             rank, 0, _canonical(cand)))
        ids[cand.get("candidate_id")] = cur.lastrowid
    for cid in capped:
        conn.execute(
            "INSERT INTO candidates (session_id, candidate_id, kind, rank,"
            " capped, context_json) VALUES (?,?,?,?,1,?)",
            (session_id, cid, "ip", None, _canonical({"capped": True})))
    conn.commit()
    return ids


def write_verdicts(conn, session_id, out, candidate_ids):
    """judge output -> verdicts rows (+ panel_audit when present)."""
    default_model = (out.get("stats") or {}).get("model")
    n = 0
    for r in out.get("results") or []:
        verdict = r.get("verdict") or {}
        panel = r.get("panel") or {}
        needs_review = bool(r.get("needs_human_review")
                            or panel.get("needs_human_review"))
        conn.execute(
            "INSERT INTO verdicts (candidate_row, session_id, verdict,"
            " category, confidence, priority_score, guardrail_applied,"
            " needs_human_review, verdict_json, provider, model,"
            " latency_ms, cached, tokens_in, tokens_out)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (candidate_ids.get(r.get("candidate_id"), 0), session_id,
             verdict.get("verdict"), verdict.get("category"),
             verdict.get("confidence"), r.get("priority"),
             int(bool(r.get("guardrail"))), int(needs_review),
             _canonical(r), None, r.get("model") or default_model,
             r.get("latency_ms"), int(bool(r.get("cached"))),
             r.get("tokens_in"), r.get("tokens_out")))
        n += 1
    _write_panel_audit(conn, session_id,
                       (out.get("stats") or {}).get("panel_report"))
    conn.commit()
    return n


def _write_panel_audit(conn, session_id, report):
    """Best-effort: the panel report's exact shape belongs to judge_core;
    store what is recognizable, never fail the run over its format."""
    entries = []
    if isinstance(report, list):
        entries = [e for e in report if isinstance(e, dict)]
    elif isinstance(report, dict):
        for model, val in report.items():
            entry = dict(val) if isinstance(val, dict) else {"raw": val}
            entry.setdefault("model", model)
            entries.append(entry)
    for e in entries:
        conn.execute(
            "INSERT INTO panel_audit (session_id, candidate_id,"
            " judge_model, initial_verdict, final_verdict, debated, error)"
            " VALUES (?,?,?,?,?,?,?)",
            (session_id, str(e.get("candidate_id") or "*"),
             str(e.get("model") or e.get("judge") or "unknown"),
             e.get("initial_verdict"), e.get("final_verdict"),
             int(bool(e.get("debated"))),
             e.get("error") if e.get("error") is None
             else str(e.get("error"))[:500]))


def write_all(conn, session_id, S, findings, assembled, out):
    """One call from the worker: everything the run produced, in order."""
    counts = {
        "ip_features": write_ip_features(conn, session_id, S),
        "findings": write_findings(conn, session_id, findings),
    }
    candidate_ids = write_candidates(conn, session_id, assembled)
    counts["candidates"] = len(candidate_ids)
    counts["verdicts"] = write_verdicts(conn, session_id, out,
                                        candidate_ids)
    return counts

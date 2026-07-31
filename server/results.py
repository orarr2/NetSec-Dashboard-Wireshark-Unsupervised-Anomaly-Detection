"""Persist one analysis run into the history DB (spec section 7).

Everything here is defensive by design: the pipeline's dict shapes are
owned by app/ and llm_judge/, and a missing optional key must degrade to
a NULL column, never to a crashed worker. Advanced-engine signals
(adv_signals / fusion_scores) are populated the moment
`app/advanced_engines.py` runs on the worker (attack_tests/run_pipeline
leaves them at `S["threats"]`). Absent `S["threats"]` the two tables
stay empty and everything else still writes - that's the graceful
degradation the historical docstring was reserving space for.
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


def write_adv_signals(conn, session_id, S):
    """S['threats'] (from run_advanced_threats) -> adv_signals rows +
    fusion_scores rows. Returns (n_signal_rows, n_fusion_rows).

    No-op when the engines were skipped or the pcap yielded no rows - the
    two tables just stay empty for that session, which is the correct
    signal that the advanced layer did not fire (as opposed to reading
    zero rows and inferring it did fire with nothing to report)."""
    threats = S.get("threats") if isinstance(S, dict) else None
    if not isinstance(threats, dict) or not threats.get("available"):
        return 0, 0
    n_sig = 0
    per_engine = threats.get("per_engine") or {}
    for rows in per_engine.values():
        for row in rows or []:
            if not isinstance(row, dict) or not row.get("device"):
                continue
            conn.execute(
                "INSERT INTO adv_signals (session_id, device, peer,"
                " signal, tactic, technique, score, severity, count,"
                " first_ts, last_ts, detail)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, row.get("device"), row.get("peer"),
                 row.get("signal"), row.get("tactic"),
                 row.get("technique"), row.get("score"),
                 row.get("severity"), row.get("count"),
                 row.get("first_ts"), row.get("last_ts"),
                 row.get("detail")))
            n_sig += 1
    n_fusion = 0
    for row in (threats.get("device_risk") or []):
        if not isinstance(row, dict) or not row.get("device"):
            continue
        # fusion_scores PK = (session_id, device); REPLACE lets a
        # re-analysis of the same session update in place.
        conn.execute(
            "INSERT OR REPLACE INTO fusion_scores (session_id, device,"
            " score, engines_hit, window_start)"
            " VALUES (?,?,?,?,?)",
            (session_id, row.get("device"), row.get("risk"),
             row.get("signal_types") or row.get("signals"), None))
        n_fusion += 1
    conn.commit()
    return n_sig, n_fusion


def write_all(conn, session_id, S, findings, assembled, out):
    """One call from the worker: everything the run produced, in order."""
    counts = {
        "ip_features": write_ip_features(conn, session_id, S),
        "findings": write_findings(conn, session_id, findings),
    }
    n_sig, n_fusion = write_adv_signals(conn, session_id, S)
    counts["adv_signals"] = n_sig
    counts["fusion_scores"] = n_fusion
    candidate_ids = write_candidates(conn, session_id, assembled)
    counts["candidates"] = len(candidate_ids)
    counts["verdicts"] = write_verdicts(conn, session_id, out,
                                        candidate_ids)
    return counts

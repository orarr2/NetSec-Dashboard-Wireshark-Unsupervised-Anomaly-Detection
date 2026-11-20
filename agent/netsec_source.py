"""Read-only access to NETSEC's own database: finished sessions and their candidates, shaped as agent payloads."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def connect(path: str) -> sqlite3.Connection:
    """Open netsec.db for reading only. Nothing the agents do can change a row of it."""
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _json(text: Any, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


def finished_sessions(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    """The newest finished sessions, oldest first, each with the number of candidates it holds."""
    rows = conn.execute(
        "SELECT s.id, s.label, s.status, s.kind, s.n_pkts, s.n_ips, s.duration_s, s.prompt_version, "
        "p.sha256 AS pcap_sha256, p.orig_name, "
        "(SELECT COUNT(*) FROM candidates c WHERE c.session_id = s.id) AS n_candidates "
        "FROM sessions s LEFT JOIN pcap_files p ON p.id = s.pcap_id "
        "WHERE s.status = 'done' ORDER BY s.id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def candidate_payloads(conn: sqlite3.Connection, session: dict) -> list[dict]:
    """One payload per candidate of a session, in rank order: its context plus the rows that belong to it."""
    session_id = session["id"]
    head = {k: session.get(k) for k in ("duration_s", "id", "kind", "label", "n_ips", "n_pkts", "orig_name",
                                        "pcap_sha256", "prompt_version", "status")}
    out = []
    for cand in conn.execute(
        "SELECT id, candidate_id, kind, rank, context_json FROM candidates WHERE session_id = ? ORDER BY rank, id",
        (session_id,),
    ).fetchall():
        candidate, kind = cand["candidate_id"], cand["kind"] or "ip"
        if kind == "session":
            # An aggregate alert has no source address, so its findings rows carry no ip.
            findings = conn.execute(
                "SELECT layer, rule, ip, severity, detail_json FROM findings "
                "WHERE session_id = ? AND ip IS NULL AND layer = 'rules' ORDER BY id", (session_id,)).fetchall()
        else:
            findings = conn.execute(
                "SELECT layer, rule, ip, severity, detail_json FROM findings "
                "WHERE session_id = ? AND ip = ? ORDER BY id", (session_id, candidate)).fetchall()
        signals = conn.execute(
            "SELECT count, detail, device, first_ts, last_ts, peer, score, severity, signal, tactic, technique "
            "FROM adv_signals WHERE session_id = ? AND device = ? ORDER BY id", (session_id, candidate)).fetchall()
        fusion = conn.execute(
            "SELECT device, engines_hit, score, window_start FROM fusion_scores WHERE session_id = ? AND device = ?",
            (session_id, candidate)).fetchall()
        features = conn.execute(
            "SELECT * FROM ip_features WHERE session_id = ? AND ip = ?", (session_id, candidate)).fetchone()
        verdict = conn.execute(
            "SELECT category, confidence, guardrail_applied, needs_human_review, priority_score, verdict "
            "FROM verdicts WHERE candidate_row = ? ORDER BY id DESC LIMIT 1", (cand["id"],)).fetchone()
        out.append({
            "session": dict(head),
            "candidate_id": candidate,
            "kind": kind,
            "rank": cand["rank"],
            "context": _json(cand["context_json"], {}),
            "findings": [{"detail": _json(f["detail_json"], {}), "ip": f["ip"], "layer": f["layer"],
                          "rule": f["rule"], "severity": f["severity"]} for f in findings],
            "adv_signals": [dict(s) for s in signals],
            "fusion": [dict(f) for f in fusion],
            "ip_features": {k: features[k] for k in features.keys() if k != "session_id"} if features else {},
            "judge_verdict": dict(verdict) if verdict else None,
        })
    return out

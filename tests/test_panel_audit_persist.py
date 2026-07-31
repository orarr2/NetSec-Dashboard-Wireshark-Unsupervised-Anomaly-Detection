"""Regression: server.results._write_panel_audit persists per-(candidate,
judge) rows so queries like 'on what did llama disagree with gpt-oss
across 30 sessions' have a data source at the DB layer.

Before F1 the writer stored only per-model summary rows (candidate_id=
'*', initial_verdict=NULL, final_verdict=NULL), which made the audit
table effectively write-only - the rich per-candidate signal existed
in verdicts.verdict_json but nowhere queryable.
"""
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import db, results  # noqa: E402


def _session(tmp_path):
    """Fresh DB + a queued session so write_verdicts has FKs to hit."""
    conn = db.connect(str(tmp_path / "hist.db"))
    conn.execute("INSERT INTO pcap_files (sha256, orig_name, size_bytes,"
                 " sensor_id, received_at, storage_path)"
                 " VALUES (?,?,?,?,?,?)",
                 ("a" * 64, "t.pcap", 1, None, "2026-08-01T12:00:00Z",
                  str(tmp_path / "t.pcap")))
    conn.execute("INSERT INTO sessions (pcap_id, label, kind, queued_at,"
                 " status) VALUES (1, 't', 'prod', '2026-08-01T12:00:00Z',"
                 " 'running')")
    conn.commit()
    return conn


def _panel_verdicts_out(with_debate=True):
    """A judge_candidates_panel-shaped out dict, with two judges - one
    that maintained its round-1 verdict and one that revised after
    seeing the peer analysis."""
    return {
        "results": [{
            "candidate_id": "192.168.1.104",
            "kind": "ip",
            "verdict": {"verdict": "malicious", "category": "port_scan",
                        "confidence": 0.92, "recommended_action": "block",
                        "reasoning": "SYN scan ratio 1.0."},
            "guardrail": None, "priority": 0.808,
            "cached": False, "latency_ms": 42000,
            "panel": {
                "agreement": False,
                "needs_human_review": True,
                "note": "judges disagree after debate",
                "debate": with_debate,
                "judges": [
                    {"model": "llama-3.3-70b-versatile",
                     "initial_verdict": {
                         "verdict": "malicious", "category": "port_scan",
                         "confidence": 0.92,
                         "reasoning": "SYN scan is decisive."},
                     "verdict": {
                         "verdict": "malicious", "category": "port_scan",
                         "confidence": 0.92,
                         "reasoning": "SYN scan is decisive."},
                     "stance": "maintain",
                     "rebuttal": "The scan rule fired; verdict stands.",
                     "revised": False, "failed": False,
                     "cached": False, "latency_ms": 28000,
                     "error": None},
                    {"model": "openai/gpt-oss-20b",
                     "initial_verdict": {
                         "verdict": "benign", "category": "benign_anomaly",
                         "confidence": 0.5,
                         "reasoning": "Only unsupervised anomaly."},
                     "verdict": {
                         "verdict": "suspicious", "category": "port_scan",
                         "confidence": 0.6,
                         "reasoning": "Revised after seeing peer."},
                     "stance": "revise",
                     "rebuttal": "Peer's scan-rule evidence changed my mind.",
                     "revised": True, "failed": False,
                     "cached": False, "latency_ms": 14000,
                     "error": None},
                ],
            },
        }],
        "dropped": [],
        "stats": {
            "total": 1, "judged": 1, "cache_hits": 0, "dropped": 0,
            "panel": True,
            "models": ["llama-3.3-70b-versatile", "openai/gpt-oss-20b"],
            "model": "llama-3.3-70b-versatile",
            "panel_report": {
                "llama-3.3-70b-versatile": {
                    "assigned": 1, "valid_verdicts": 1, "failures": 0,
                    "debates": 1, "revised": 0, "agreed_with_final": 1,
                    "cache_hits": 0, "mean_latency_ms": 28000,
                    "failure_examples": []},
                "openai/gpt-oss-20b": {
                    "assigned": 1, "valid_verdicts": 1, "failures": 0,
                    "debates": 1, "revised": 1, "agreed_with_final": 0,
                    "cache_hits": 0, "mean_latency_ms": 14000,
                    "failure_examples": []},
            },
            "prompt_version": "v0.3.0",
        },
    }


def test_write_verdicts_persists_per_candidate_per_judge_rows(tmp_path):
    conn = _session(tmp_path)
    out = _panel_verdicts_out()
    results.write_verdicts(conn, 1, out, candidate_ids={"192.168.1.104": 1})

    # Real per-candidate rows (candidate_id = the actual IP, not '*').
    rows = list(conn.execute(
        "SELECT judge_model, initial_verdict, final_verdict, stance,"
        " rebuttal, revised, needs_review, debated"
        " FROM panel_audit"
        " WHERE candidate_id='192.168.1.104' ORDER BY judge_model"))
    assert len(rows) == 2  # llama + gpt-oss

    by_model = {r["judge_model"]: dict(r) for r in rows}

    # llama-3.3-70b: initial == final, stance maintain, revised=0
    llama = by_model["llama-3.3-70b-versatile"]
    llama_init = json.loads(llama["initial_verdict"])
    llama_final = json.loads(llama["final_verdict"])
    assert llama_init["verdict"] == "malicious"
    assert llama_final["verdict"] == "malicious"
    assert llama["stance"] == "maintain"
    assert llama["revised"] == 0
    assert "verdict stands" in llama["rebuttal"]
    assert llama["needs_review"] == 1  # panel escalated this candidate
    assert llama["debated"] == 1

    # gpt-oss-20b: initial != final (benign -> suspicious), revised=1
    gpt = by_model["openai/gpt-oss-20b"]
    gpt_init = json.loads(gpt["initial_verdict"])
    gpt_final = json.loads(gpt["final_verdict"])
    assert gpt_init["verdict"] == "benign"
    assert gpt_final["verdict"] == "suspicious"
    assert gpt["stance"] == "revise"
    assert gpt["revised"] == 1
    assert "changed my mind" in gpt["rebuttal"]


def test_write_verdicts_also_keeps_per_model_summary_rows(tmp_path):
    """The summary rows (candidate_id='*') stay too - they carry the
    aggregated participation counts (mean_latency_ms, debates, revised,
    agreed_with_final) that per-candidate rows do not."""
    conn = _session(tmp_path)
    out = _panel_verdicts_out()
    results.write_verdicts(conn, 1, out, candidate_ids={"192.168.1.104": 1})

    summary = list(conn.execute(
        "SELECT judge_model, initial_verdict FROM panel_audit"
        " WHERE candidate_id='*' ORDER BY judge_model"))
    assert len(summary) == 2
    models = [r["judge_model"] for r in summary]
    assert models == ["llama-3.3-70b-versatile", "openai/gpt-oss-20b"]
    # The summary's initial_verdict column carries the aggregated
    # participation blob as JSON (assigned, valid_verdicts, debates ...).
    for row in summary:
        blob = json.loads(row["initial_verdict"])
        assert "assigned" in blob and "valid_verdicts" in blob


def test_write_verdicts_no_panel_writes_no_per_candidate_rows(tmp_path):
    """A single-judge run has no 'panel' block on the result - the
    per-candidate insert path must skip it silently."""
    conn = _session(tmp_path)
    out = {"results": [{
        "candidate_id": "10.0.0.1", "kind": "ip",
        "verdict": {"verdict": "benign", "category": "benign_anomaly",
                    "confidence": 0.5, "recommended_action": "monitor",
                    "reasoning": "ok"},
        "priority": 0.1, "cached": False, "latency_ms": 100,
    }], "stats": {"model": "solo-model"}, "dropped": []}
    results.write_verdicts(conn, 1, out, candidate_ids={"10.0.0.1": 1})
    n = conn.execute("SELECT COUNT(*) FROM panel_audit").fetchone()[0]
    assert n == 0  # no panel -> no audit rows

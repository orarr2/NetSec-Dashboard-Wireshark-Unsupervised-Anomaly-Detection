"""End-to-end tests for the compare_job path: db -> ingest_api ->
worker.process_compare_job -> mail. No LLM, no tshark - everything
scriptable through injected stubs.
"""
import io
import contextlib
import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from server import auth, db, worker  # noqa: E402
from server import compare_report  # noqa: E402


# --------------------------------------------------------------------------
# Helpers - stand up two 'done' sessions with verdicts.json files
# --------------------------------------------------------------------------
def _seed_session(conn, root, sensor_id, sha_prefix, ip_verdicts,
                  label="S"):
    """Register a pcap, create+finish a session, write a fake
    verdicts.json report. ip_verdicts is a list of (ip, verdict,
    category, confidence)."""
    sha = (sha_prefix * 32)[:64]
    pcap_path = os.path.join(root, f"{sha_prefix}.pcap")
    with open(pcap_path, "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1" + b"z" * 128)
    pid, _ = db.register_pcap(conn, sha, f"{sha_prefix}.pcap",
                              os.path.getsize(pcap_path),
                              sensor_id, pcap_path)
    sid = db.create_session(conn, pid, label, "prod")
    db.claim_next_job(conn)
    db.mark_done(conn, sid, n_pkts=100, n_ips=len(ip_verdicts),
                 duration_s=10.0, prompt_version="v0.5.0")
    rep_dir = os.path.join(root, "reports", str(sid))
    os.makedirs(rep_dir, exist_ok=True)
    path = os.path.join(rep_dir, "verdicts.json")
    out = {"results": [
        {"candidate_id": ip, "kind": "ip",
         "verdict": {"verdict": v, "category": cat, "confidence": conf}}
        for (ip, v, cat, conf) in ip_verdicts],
           "stats": {"total": len(ip_verdicts),
                     "judged": len(ip_verdicts),
                     "prompt_version": "v0.5.0"}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    db.add_report(conn, sid, "json", path)
    return sid


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSEC_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("NETSEC_NOTIFY_EMAIL", raising=False)
    monkeypatch.delenv("N8N_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)
    conn = db.connect(str(tmp_path / "netsec.db"))
    db.create_sensor(conn, "laptop", auth.hash_token("t"), "sec")
    sensor = db.get_sensor(conn, "laptop")
    s1 = _seed_session(conn, str(tmp_path), sensor["id"], "aa",
                       [("1.1.1.1", "benign", "benign_anomaly", 0.7),
                        ("2.2.2.2", "suspicious", "benign_anomaly", 0.6)],
                       label="cap1")
    s2 = _seed_session(conn, str(tmp_path), sensor["id"], "bb",
                       [("1.1.1.1", "malicious", "port_scan", 0.9),
                        ("3.3.3.3", "benign", "benign_anomaly", 0.7)],
                       label="cap2")
    yield conn, sensor, s1, s2, str(tmp_path)
    conn.close()


# --------------------------------------------------------------------------
# process_compare_job
# --------------------------------------------------------------------------
def _stub_pair_judge(s1_out, s2_out, clients, s1_label, s2_label,
                     prompt_version):
    """Skips the LLM. Returns a shaped verdict so the report path is
    exercised end to end."""
    from llm_judge import judge_core
    blob = judge_core.build_pair_blob(s1_out, s2_out, s1_label, s2_label)
    return {
        "verdict": {"posture_delta": "escalated",
                    "confidence": 0.82,
                    "headline": "1.1.1.1 flipped from benign to malicious.",
                    "reasoning": ("verdict_flips[0] shows 1.1.1.1 moved "
                                  "from benign in S1 to malicious "
                                  "port_scan in S2 at 0.9 confidence."),
                    "notable_flips": [{"ip": "1.1.1.1",
                                       "from": "benign",
                                       "to": "malicious",
                                       "why": "scan rule fired in S2"}],
                    "recommended_action": "investigate",
                    "panel_agreement": {"picked": "escalated",
                                        "votes": {"escalated": 2},
                                        "answered": 2}},
        "panel_report": {"stub-a": {"answered": True, "error": None,
                                     "raw": {}, "latency_ms": 12},
                         "stub-b": {"answered": True, "error": None,
                                     "raw": {}, "latency_ms": 15}},
        "pair_blob": blob,
        "prompt_version": "v0.5.0-pair-stub",
        "models_answered": ["stub-a", "stub-b"],
        "models_total": 2,
    }


def _stub_clients_ok(entries, verdict_schema=None):
    """Two dummy clients so process_compare_job's client-build step
    passes without hitting a real provider."""
    class _C:
        def __init__(self, name):
            self.model_id = name
    return ([_C("stub-a"), _C("stub-b")], [])


def test_compare_worker_end_to_end(env, monkeypatch):
    conn, sensor, s1, s2, root = env
    # inject panel-spec resolution + client-build so the worker doesn't
    # try to reach Groq / Ollama in a unit test
    monkeypatch.setenv("LLM_JUDGE_PANEL",
                       "openai_compat:stub-a,openai_compat:stub-b")
    from llm_judge import judge_core, llm_clients
    monkeypatch.setattr(llm_clients, "make_panel_clients",
                        _stub_clients_ok)
    monkeypatch.setattr(judge_core, "judge_session_pair",
                        _stub_pair_judge)

    job_id, created = db.create_compare_job(
        conn, s1, s2, notify_email="you@example.com")
    assert created is True

    with contextlib.redirect_stdout(io.StringIO()):
        got = worker.run_once(conn, data_root=root)
    assert got == f"compare:{job_id}"

    row = db.get_compare_job(conn, job_id)
    assert row["status"] == "done"
    assert row["prompt_version"] == "v0.5.0-pair-stub"
    stats = json.loads(row["stats_json"])
    assert stats["flip_count_total"] == 1
    assert stats["models_answered"] == ["stub-a", "stub-b"]

    # reports on disk
    rep_dir = os.path.join(root, "reports", "compare", str(job_id))
    for fname in ("summary.md", "report.md", "report.html",
                  "verdict.json"):
        assert os.path.isfile(os.path.join(rep_dir, fname))
    summary = open(os.path.join(rep_dir, "summary.md"),
                   encoding="utf-8").read()
    assert "ESCALATED" in summary
    assert "1.1.1.1" in summary


def test_compare_worker_stub_analyze_pair_and_drains_before_sessions(
        env, monkeypatch):
    """A queued compare_job MUST be drained before any queued session
    job - a completed comparison depends on already-done sessions,
    so delaying it behind a fresh session upload would grow the mail
    latency for no reason."""
    conn, sensor, s1, s2, root = env
    monkeypatch.setenv("LLM_JUDGE_PANEL",
                       "openai_compat:stub-a,openai_compat:stub-b")
    from llm_judge import judge_core, llm_clients
    monkeypatch.setattr(llm_clients, "make_panel_clients",
                        _stub_clients_ok)
    monkeypatch.setattr(judge_core, "judge_session_pair", _stub_pair_judge)

    # A third fresh session sits in queued state while a compare is queued
    pid, _ = db.register_pcap(conn, "cc" * 32, "c.pcap", 200,
                              sensor["id"], "/x/c.pcap")
    fresh_sid = db.create_session(conn, pid, "cap3", "prod")
    job_id, _ = db.create_compare_job(conn, s1, s2)

    with contextlib.redirect_stdout(io.StringIO()):
        first = worker.run_once(conn, data_root=root)
    assert first == f"compare:{job_id}", (
        "compare_job should drain before the queued session")
    assert db.get_compare_job(conn, job_id)["status"] == "done"
    assert db.get_session(conn, fresh_sid)["status"] == "queued"


def test_compare_worker_error_marks_job_and_moves_on(env, monkeypatch):
    conn, sensor, s1, s2, root = env
    monkeypatch.setenv("LLM_JUDGE_PANEL",
                       "openai_compat:stub-a,openai_compat:stub-b")
    from llm_judge import judge_core, llm_clients
    monkeypatch.setattr(llm_clients, "make_panel_clients",
                        _stub_clients_ok)

    def boom(*a, **kw):
        raise RuntimeError("panel exploded")
    monkeypatch.setattr(judge_core, "judge_session_pair", boom)

    job_id, _ = db.create_compare_job(conn, s1, s2)
    with contextlib.redirect_stdout(io.StringIO()):
        worker.run_once(conn, data_root=root)
    row = db.get_compare_job(conn, job_id)
    assert row["status"] == "error"
    assert "panel exploded" in (row["error"] or "")


def test_compare_worker_refuses_if_a_session_is_not_done(env, monkeypatch):
    """Both sides must be status='done'. A pair posted while S2 is still
    running MUST fail loudly rather than reading a truncated verdict."""
    conn, sensor, s1, s2, root = env
    monkeypatch.setenv("LLM_JUDGE_PANEL",
                       "openai_compat:stub-a,openai_compat:stub-b")
    from llm_judge import judge_core, llm_clients
    monkeypatch.setattr(llm_clients, "make_panel_clients",
                        _stub_clients_ok)
    monkeypatch.setattr(judge_core, "judge_session_pair", _stub_pair_judge)

    # break s2 back to running by hand
    conn.execute("UPDATE sessions SET status='running' WHERE id=?", (s2,))
    conn.commit()
    job_id, _ = db.create_compare_job(conn, s1, s2)
    with contextlib.redirect_stdout(io.StringIO()):
        worker.run_once(conn, data_root=root)
    row = db.get_compare_job(conn, job_id)
    assert row["status"] == "error"
    assert "status" in (row["error"] or "").lower()


# --------------------------------------------------------------------------
# compare_report.render is unit-testable without the worker
# --------------------------------------------------------------------------
def test_compare_report_renders_both_outputs():
    pair = _stub_pair_judge(
        {"results": [{"candidate_id": "1.1.1.1",
                      "verdict": {"verdict": "benign",
                                  "category": "benign_anomaly",
                                  "confidence": 0.7}}]},
        {"results": [{"candidate_id": "1.1.1.1",
                      "verdict": {"verdict": "malicious",
                                  "category": "port_scan",
                                  "confidence": 0.9}}]},
        [], "cap1", "cap2", None)
    summary, full = compare_report.render(
        {"id": 42}, {"id": 1, "label": "cap1"},
        {"id": 2, "label": "cap2"}, pair)
    # summary is the mail body - opens with the exec summary
    assert "Comparison report" in summary
    assert "ESCALATED" in summary
    assert "1.1.1.1" in summary
    assert "attached as PDF" in summary
    # full has the tables the summary omits
    assert "All verdict flips" in full
    assert "IPs unique to one side" in full
    assert "Panel audit" in full


def _v2_out(rows, start=None):
    """Per-session verdict output shaped like report v2 writes it:
    results with evidence projections + persisted context."""
    out = {"results": []}
    for (ip, v, cat, conf, dev) in rows:
        r = {"candidate_id": ip, "kind": "ip",
             "verdict": {"verdict": v, "category": cat,
                         "confidence": conf}}
        if dev:
            r["evidence"] = {"device": {"hostname": dev,
                                        "vendor": "Acme",
                                        "category": "iot"}}
        out["results"].append(r)
    if start:
        out["context"] = {
            "time_range": [start, start], "duration_s": 300.0,
            "n_packets": 5000, "total_ips": 12, "local_ips_count": 8,
            "external_ips_count": 4, "top_protocols": {"TCP": 1},
        }
    return out


def test_compare_report_v2_captures_changes_and_single_judge():
    s1 = _v2_out([("1.1.1.1", "suspicious", "benign_anomaly", 0.6, None),
                  ("2.2.2.2", "benign", "benign_anomaly", 0.7, None)],
                 start="2026-08-01 10:00:00")
    s1["context"]["original_filename"] = "new3.pcapng"
    s2 = _v2_out([("1.1.1.1", "malicious", "port_scan", 0.93, "cam-7"),
                  ("2.2.2.2", "benign", "benign_anomaly", 0.7, None),
                  ("9.9.9.9", "malicious", "dns_amp", 0.88, "nas-1")],
                 start="2026-08-01 13:00:00")
    s2["context"]["original_filename"] = "new4.pcapng"
    from llm_judge import judge_core as jc
    blob = jc.build_pair_blob(s1, s2, "cap1", "cap2")
    pair = {
        "verdict": {"posture_delta": "escalated", "confidence": 0.9,
                    "headline": "New scan and amp traffic in S2.",
                    "reasoning": "1.1.1.1 flipped to malicious.",
                    "recommended_action": "investigate",
                    "notable_flips": [{"ip": "1.1.1.1",
                                       "from": "suspicious",
                                       "to": "malicious",
                                       "why": "port scan"}],
                    "panel_agreement": {"picked": "escalated",
                                        "votes": {"escalated": 1},
                                        "answered": 1}},
        "pair_blob": blob,
        "panel_report": {
            "groq/big": {"answered": True, "latency_ms": 900,
                         "error": None},
            "groq/small": {"answered": False, "latency_ms": 12000,
                           "error": "Rate limit reached ... tokens per "
                                    "day (TPD): quota exhausted"}},
        "models_answered": ["groq/big"], "models_total": 2,
        "prompt_version": "v0.5.0-pair2"}
    summary, full = compare_report.render(
        {"id": 7}, {"id": 1, "label": "cap1"},
        {"id": 2, "label": "cap2"}, pair)

    # Captures at a glance: metadata side by side + the recording gap.
    for md in (summary, full):
        assert "Captures at a glance" in md
        assert "new3.pcapng" in md and "new4.pcapng" in md
        assert "5,000" in md
        assert "S2 was recorded 3h 0m after S1" in md
        # What changed: category flow + new non-benign, in one table.
        assert "What changed" in md
        assert "suspicious → **malicious**" in md
        assert "New in S2" in md and "non-benign" in md
        # Single-judge warning is loud and names the judge.
        assert "Single-judge verdict" in summary
        assert "`big`" in md
    # New non-benign S2 IP surfaces with its device even in the mail.
    assert "9.9.9.9" in summary and "Acme nas-1" in summary
    # Flip rows carry the S2-side device identity.
    assert "cam-7" in full
    # Panel audit classifies the failure - never the raw provider dump.
    assert "daily quota" in full
    assert "Rate limit reached" not in full
    # Run metadata renders votes humanized, not as a python dict.
    assert "escalated x1" in full
    assert "{'escalated': 1}" not in full


def test_compare_report_v2_graceful_without_context():
    """Legacy verdicts.json (no context, no evidence) must render the
    v2 report without the capture table and without crashing."""
    from llm_judge import judge_core as jc
    s1 = {"results": [{"candidate_id": "1.1.1.1",
                       "verdict": {"verdict": "benign",
                                   "category": "benign_anomaly",
                                   "confidence": 0.7}}]}
    s2 = {"results": [{"candidate_id": "1.1.1.1",
                       "verdict": {"verdict": "suspicious",
                                   "category": "benign_anomaly",
                                   "confidence": 0.6}}]}
    blob = jc.build_pair_blob(s1, s2, "a", "b")
    pair = {"verdict": {"posture_delta": "mixed", "confidence": 0.4,
                        "headline": "h", "reasoning": "r",
                        "recommended_action": "monitor",
                        "notable_flips": []},
            "pair_blob": blob, "panel_report": {},
            "models_answered": ["m1", "m2"], "models_total": 2,
            "prompt_version": "v"}
    summary, full = compare_report.render(
        {"id": 8}, {"id": 3, "label": "a"}, {"id": 4, "label": "b"}, pair)
    assert "Captures at a glance" not in summary
    assert "What changed" in full          # flips still exist
    assert "Single-judge" not in summary   # two judges answered

"""Stage C regression: the worker loop, result writers, telemetry
reconciliation and report rendering - all through the injectable
pipeline, so no tshark, torch or LLM is needed.
"""
import collections
import json
import os
import sys
from datetime import datetime, timedelta

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import auth, db, reconcile, report_html, report_pdf  # noqa: E402
from server import results, worker  # noqa: E402

T0 = datetime(2026, 7, 30, 10, 0, 0)
INFRA = "100.100.100.100"


def _fake_S(with_infra_pair=True):
    pairs = collections.Counter({("192.168.1.7", "8.8.8.8"): 40})
    if with_infra_pair:
        pairs[("192.168.1.7", INFRA)] = 900
    return {
        "label": "S1", "n_pkts": 1234,
        "ips_src": collections.Counter({"192.168.1.7": 1000,
                                        "192.168.1.9": 234}),
        "bytes_src": collections.Counter({"192.168.1.7": 50000}),
        "bytes_dst": collections.Counter({"8.8.8.8": 1000}),
        "t0": T0, "t1": T0 + timedelta(seconds=300),
        "ip_pairs": pairs,
        "ip_agg": None,
    }


def _stub_out():
    return {
        "results": [{
            "candidate_id": "192.168.1.7", "kind": "ip",
            "verdict": {"verdict": "suspicious", "category": "port_scan",
                        "confidence": 0.83},
            "guardrail": {"applied": True}, "priority": 0.7,
            "cached": False, "latency_ms": 42,
        }],
        "dropped": [],
        "stats": {"model": "stub-model", "prompt_version": "v0.3.0"},
        "analyst_commentary": "stub commentary",
    }


def _stub_assembled():
    return {"candidates": [{"candidate_id": "192.168.1.7", "kind": "ip",
                            "rule_signals": {}, "ml_signals": {}}],
            "capped": ["10.0.0.99"]}


def _stub_analyze(S=None):
    S = S or _fake_S()

    def fn(pcap_path, label):
        return (_stub_out(), _stub_assembled(), None, {"stub": True},
                S, {"scan_alerts": [{"src": "192.168.1.7", "type": "SYN",
                                     "count": 900}],
                    "flood_alerts": [], "amp_alerts": []})
    return fn


def _stub_md(pcap_path, out, assembled, client, context):
    return "# Verdicts\n\n| IP | verdict |\n|---|---|\n| 192.168.1.7 | suspicious |\n"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSEC_INFRA_DSTS", INFRA)
    monkeypatch.delenv("NETSEC_NOTIFY_EMAIL", raising=False)
    monkeypatch.delenv("N8N_WEBHOOK_URL", raising=False)
    conn = db.connect(str(tmp_path / "netsec.db"))
    db.create_sensor(conn, "s", auth.hash_token("t"), "sec")
    sensor = db.get_sensor(conn, "s")
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"z" * 256)
    pcap_id, _ = db.register_pcap(conn, "aa" * 32, "cap.pcap",
                                  pcap.stat().st_size, sensor["id"],
                                  str(pcap))
    sid = db.create_session(conn, pcap_id, "S1", "prod")
    yield conn, sid, sensor, tmp_path
    conn.close()


def test_worker_happy_path(env):
    conn, sid, sensor, root = env
    got = worker.run_once(conn, analyze_fn=_stub_analyze(),
                          md_fn=_stub_md, data_root=str(root))
    assert got == sid

    session = db.get_session(conn, sid)
    assert session["status"] == "done"
    assert session["n_pkts"] == 1234
    assert session["n_ips"] == 2
    assert session["duration_s"] == 300.0
    assert session["prompt_version"] == "v0.3.0"

    v = conn.execute("SELECT * FROM verdicts").fetchone()
    assert v["verdict"] == "suspicious"
    assert v["category"] == "port_scan"
    assert v["confidence"] == 0.83
    assert v["guardrail_applied"] == 1
    assert v["model"] == "stub-model"

    cands = conn.execute(
        "SELECT candidate_id, capped FROM candidates ORDER BY id").fetchall()
    assert [(c["candidate_id"], c["capped"]) for c in cands] == [
        ("192.168.1.7", 0), ("10.0.0.99", 1)]

    f = conn.execute("SELECT * FROM findings WHERE layer='rules'").fetchone()
    assert f["rule"] == "scan_alerts" and f["ip"] == "192.168.1.7"

    for kind in ("json", "md", "html"):
        rep = db.get_report(conn, sid, kind)
        assert rep and os.path.isfile(rep["path"]), kind
    assert db.get_report(conn, sid, "pdf") is None  # weasyprint absent

    html = open(db.get_report(conn, sid, "html")["path"],
                encoding="utf-8").read()
    assert "Session provenance" in html
    assert "aa" * 32 in html            # pcap sha in the header
    assert "suspicious" in html         # markdown table rendered

    # queue drained
    assert worker.run_once(conn, analyze_fn=_stub_analyze(),
                           md_fn=_stub_md, data_root=str(root)) is None


def test_worker_error_path(env):
    conn, sid, _, root = env

    def boom(pcap_path, label):
        raise RuntimeError("pipeline exploded")

    assert worker.run_once(conn, analyze_fn=boom, md_fn=_stub_md,
                           data_root=str(root)) == sid
    session = db.get_session(conn, sid)
    assert session["status"] == "error"
    assert "pipeline exploded" in session["error"]


def test_reconcile_undeclared_flow_is_a_finding(env):
    conn, sid, _, _ = env
    # a flow to the declared infra dst with NO telemetry record at all
    summary = reconcile.reconcile(conn, sid, _fake_S(), dsts={INFRA})
    assert summary["undeclared"] == 1 and summary["matched_ips"] == []
    f = conn.execute(
        "SELECT * FROM findings WHERE rule='undeclared_infra_flow'"
    ).fetchone()
    assert f["ip"] == "192.168.1.7" and f["severity"] == "high"


def test_reconcile_matched_and_blind_spot(env):
    conn, sid, sensor, _ = env
    t0 = T0.timestamp()
    db.log_ingest_telemetry(conn, sensor["id"], t0 + 10, t0 + 60, INFRA,
                            8766, 5000, "aa" * 32, sid)

    matched = reconcile.reconcile(conn, sid, _fake_S(), dsts={INFRA})
    assert matched["matched_ips"] == ["192.168.1.7"]
    assert matched["undeclared"] == 0
    row = conn.execute("SELECT matched_session_id FROM telemetry_log"
                       ).fetchone()
    assert row["matched_session_id"] == sid

    # same telemetry record but a capture that never saw the flow
    sid2 = db.create_session(
        conn, conn.execute("SELECT pcap_id FROM sessions WHERE id=?",
                           (sid,)).fetchone()["pcap_id"], "S2", "prod")
    blind = reconcile.reconcile(conn, sid2, _fake_S(with_infra_pair=False),
                                dsts={INFRA})
    assert blind["blind_spots"] == 1
    f = conn.execute("SELECT * FROM findings WHERE rule='capture_blind_spot'"
                     ).fetchone()
    assert f is not None and f["severity"] == "medium"


def test_reconcile_marks_self_telemetry_column(env):
    conn, sid, sensor, _ = env
    conn.execute(
        "INSERT INTO ip_features (session_id, ip, count) VALUES (?,?,?)",
        (sid, "192.168.1.7", 900))
    t0 = T0.timestamp()
    db.log_ingest_telemetry(conn, sensor["id"], t0, t0 + 30, INFRA, 8766,
                            5000, "aa" * 32, sid)
    reconcile.reconcile(conn, sid, _fake_S(), dsts={INFRA})
    flag = conn.execute(
        "SELECT self_telemetry FROM ip_features WHERE ip='192.168.1.7'"
    ).fetchone()[0]
    assert flag == 1


def test_ip_features_writer_with_dataframe(env):
    pd = pytest.importorskip("pandas")
    conn, sid, _, _ = env
    ip_agg = pd.DataFrame(
        {"mean_len": [100.5], "std_len": [12.0], "count": [900],
         "burst_score": [69.2], "unique_dsts": [55], "syn_count": [800],
         "rst_count": [1], "fin_count": [0], "null_count": [0],
         "xmas_count": [0], "iso_score": [-0.12], "iso_flag": [1],
         "cluster": [-1], "anomaly": [1]},
        index=["192.168.1.7"])
    S = dict(_fake_S(), ip_agg=ip_agg)
    assert results.write_ip_features(conn, sid, S) == 1
    row = conn.execute("SELECT * FROM ip_features").fetchone()
    assert row["iso_score"] == -0.12 and row["dbscan_anomaly"] == 1
    assert row["bytes_src"] == 50000


def test_report_pdf_degrades_without_weasyprint(tmp_path):
    if "weasyprint" in sys.modules:
        pytest.skip("weasyprint installed - degrade path not applicable")
    out = report_pdf.render("<html><body>x</body></html>",
                            str(tmp_path / "r.pdf"))
    assert out is None
    assert not (tmp_path / "r.pdf").exists()


def test_report_html_injects_header():
    session = {"id": 5, "label": "S1", "kind": "prod", "sha256": "ff" * 32,
               "orig_name": "c.pcap", "size_bytes": 10,
               "queued_at": "2026-07-30", "prompt_version": "v0.3.0"}
    html = report_html.render(session, "# T\n\nbody text")
    assert html.index("Session provenance") < html.index("body text")
    assert "ff" * 32 in html
    assert html.count("<body") == 1

"""The chain, not the links.

Every stage of the distributed pipeline has unit tests, but each one
stubs its neighbours: worker tests pass `analyze_fn=_stub_analyze`,
ingest tests never reach the worker, results tests hand-build an S-dict.
Nothing proved the parts compose - which is exactly where integrations
break.

This module runs the real chain on a real capture:

    sign -> ingest API -> storage -> queue -> worker -> REAL detection
    pipeline -> DB rows -> reconcile -> baseline -> HTML report

Only the LLM judge is substituted, because a real verdict needs a
provider and a network. Everything else is the production code path.

Skips cleanly when tshark or fastapi is absent so the suite still runs on
a machine without them.
"""
import hashlib
import io
import contextlib
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "attack_tests"))

pytest.importorskip("fastapi", reason="server extras not installed")
# httpx too: TestClient raises at import time without it, and a raised
# import in a test module is a collection error that aborts the whole
# suite rather than skipping this one file.
pytest.importorskip("httpx", reason="server extras not installed")
from fastapi.testclient import TestClient  # noqa: E402

from server import auth, db, ingest_api, storage, worker  # noqa: E402

PCAP = os.path.join(ROOT, "attack_tests", "pcaps", "tcp_syn_scan.pcap")


def _tshark_available():
    import shutil
    if shutil.which("tshark"):
        return True
    # llm_judge/__init__ extends PATH with the standard Wireshark dirs.
    try:
        import llm_judge  # noqa: F401
    except Exception:
        return False
    return bool(shutil.which("tshark"))


pytestmark = pytest.mark.skipif(
    not _tshark_available(), reason="tshark not installed")


@pytest.fixture
def stack(tmp_path, monkeypatch):
    """A whole NetSec server rooted in tmp_path: DB, storage, API."""
    root = tmp_path / "srv"
    root.mkdir()
    monkeypatch.setenv("NETSEC_DATA_ROOT", str(root))
    monkeypatch.setenv("NETSEC_DB_PATH", str(root / "netsec.db"))

    conn = db.connect(str(root / "netsec.db"))
    secret, token = "test-hmac-secret", "test-bearer-token"
    sensor_id = db.create_sensor(conn, "sensor-e2e",
                                 auth.hash_token(token), secret)
    conn.commit()

    app = ingest_api.create_app(db_path=str(root / "netsec.db"),
                               data_root=str(root))
    return {"conn": conn, "root": str(root), "app": app,
            "sensor_id": sensor_id, "secret": secret, "token": token}


def _upload(stack, pcap_path, name=None):
    """Sign and POST a capture exactly the way tools/upload_pcap.py does."""
    with open(pcap_path, "rb") as f:
        payload = f.read()
    sha = hashlib.sha256(payload).hexdigest()
    ts = int(time.time())
    sig = auth.upload_signature(stack["secret"], sha, "sensor-e2e", ts)
    with TestClient(stack["app"]) as client:
        return client.post(
            "/v1/pcap", content=payload,
            headers={
                "X-Sensor-Id": "sensor-e2e",
                "X-Sha256": sha,
                "X-Timestamp": str(ts),
                "X-Signature": sig,
                "X-Filename": name or os.path.basename(pcap_path),
                "Authorization": f"Bearer {stack['token']}",
            }), sha


def _fake_judge(pcap_path, label):
    """Stand in for the LLM judge only. Runs the REAL detection pipeline,
    then returns a verdict batch shaped like judge_cli.analyze_and_judge."""
    import run_pipeline as rp
    from llm_judge import judge_core, judge_cli

    with contextlib.redirect_stdout(io.StringIO()):
        S = rp.analyze_pcap(pcap_path, label or "S1")
        rp.run_ml_on_session(S)
        findings = rp.run_security_scans(S)
        assembled = judge_core.assemble_candidates(S, findings)
        # The real context builder, not a hand-rolled dict: the report
        # renderer reads it directly, so a thin stub would only prove the
        # stub is self-consistent.
        context = judge_cli.build_context(S, findings, assembled)

    results = [{
        "candidate_id": c["candidate_id"], "kind": c["kind"],
        "verdict": {"verdict": "malicious", "category": "port_scan",
                    "confidence": 0.9,
                    "evidence_features": ["rule_signals.scan_alerts"],
                    "reasoning": "stub verdict for the integration test",
                    "recommended_action": "investigate"},
        "guardrail": None, "priority": 0.8, "cached": False,
        "latency_ms": 1,
    } for c in assembled["candidates"]]

    out = {"results": results, "dropped": [],
           "stats": {"total": len(results), "judged": len(results),
                     "cache_hits": 0, "dropped": 0,
                     "model": "stub-model", "models": ["stub-model"],
                     "prompt_version": "test"},
           "analyst_commentary": "Integration test commentary."}

    class _Client:
        model_id = "stub-model"

    return out, assembled, _Client(), context, S, findings


def _stub_md(*a, **kw):
    return "# Judge verdicts\n\nIntegration test report.\n"


# --------------------------------------------------------------------------
def test_signed_upload_is_accepted_and_queued(stack):
    resp, sha = _upload(stack, PCAP)
    assert resp.status_code in (200, 202), resp.text

    conn = stack["conn"]
    pcap = conn.execute("SELECT * FROM pcap_files WHERE sha256=?",
                        (sha,)).fetchone()
    assert pcap is not None, "the upload never reached pcap_files"
    assert os.path.isfile(pcap["storage_path"]), "the bytes are not on disk"
    assert os.path.getsize(pcap["storage_path"]) == os.path.getsize(PCAP)

    session = conn.execute(
        "SELECT * FROM sessions WHERE pcap_id=?", (pcap["id"],)).fetchone()
    assert session is not None and session["status"] == "queued"


def test_tampered_signature_is_rejected_and_stores_nothing(stack):
    """The security boundary: a bad signature must not create a session
    and must not leave bytes on disk."""
    with open(PCAP, "rb") as f:
        payload = f.read()
    sha = hashlib.sha256(payload).hexdigest()
    ts = int(time.time())
    with TestClient(stack["app"]) as client:
        resp = client.post(
            "/v1/pcap", content=payload,
            headers={"X-Sensor-Id": "sensor-e2e", "X-Sha256": sha,
                     "X-Timestamp": str(ts),
                     "X-Signature": "0" * 64,
                     "X-Filename": "evil.pcap",
                     "Authorization": f"Bearer {stack['token']}"})
    assert resp.status_code == 401, resp.text
    conn = stack["conn"]
    assert conn.execute("SELECT COUNT(*) c FROM pcap_files"
                        ).fetchone()["c"] == 0
    assert conn.execute("SELECT COUNT(*) c FROM sessions"
                        ).fetchone()["c"] == 0
    spool = os.path.join(stack["root"], "spool")
    leftovers = os.listdir(spool) if os.path.isdir(spool) else []
    assert leftovers == [], f"rejected upload left files behind: {leftovers}"


def test_declared_digest_must_match_the_bytes(stack):
    """Signature and digest agree with each other, but not with the body -
    the server must recompute rather than trust the header."""
    payload = b"not a pcap at all"
    lie = hashlib.sha256(b"something else entirely").hexdigest()
    ts = int(time.time())
    sig = auth.upload_signature(stack["secret"], lie, "sensor-e2e", ts)
    with TestClient(stack["app"]) as client:
        resp = client.post(
            "/v1/pcap", content=payload,
            headers={"X-Sensor-Id": "sensor-e2e", "X-Sha256": lie,
                     "X-Timestamp": str(ts), "X-Signature": sig,
                     "X-Filename": "lie.pcap",
                     "Authorization": f"Bearer {stack['token']}"})
    # Tight: 400 is what the digest-mismatch path raises, and its message
    # must mention the hash. A bare ">= 400" would be satisfied by a schema
    # rejection or an off-by-one in another header check, which would leave
    # the whole digest verification silently gone.
    assert resp.status_code == 400, resp.text
    assert "sha" in resp.text.lower() or "digest" in resp.text.lower(), (
        f"400 came from something other than the digest check: {resp.text}")
    conn = stack["conn"]
    assert conn.execute("SELECT COUNT(*) c FROM pcap_files"
                        ).fetchone()["c"] == 0


def test_full_chain_upload_to_report(stack):
    """The whole point: upload -> worker -> real pipeline -> DB -> report."""
    resp, sha = _upload(stack, PCAP)
    assert resp.status_code in (200, 202)

    conn = stack["conn"]
    # No md_fn override here: the worker must build the report with its own
    # renderer, otherwise "the host appears in the HTML" proves nothing.
    with contextlib.redirect_stdout(io.StringIO()):
        sid = worker.run_once(conn, analyze_fn=_fake_judge,
                              data_root=stack["root"])
    assert sid is not None, "the worker did not pick up the queued session"

    session = conn.execute("SELECT * FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    assert session["status"] == "done", (
        f"session ended as {session['status']}: {session['error']}")
    assert session["n_pkts"] == 2020, (
        "the real pipeline should report the capture's packet count")

    # The detection layer's output actually landed.
    feats = conn.execute(
        "SELECT * FROM ip_features WHERE session_id=?", (sid,)).fetchall()
    assert feats, "no per-IP features were persisted"
    assert any(f["ip"] == "192.168.1.10" for f in feats), (
        "the scanning host is missing from ip_features")

    verdicts = conn.execute(
        "SELECT * FROM verdicts WHERE session_id=?", (sid,)).fetchall()
    assert verdicts, "no verdicts were persisted"

    # Reports exist on disk.
    rep_dir = os.path.join(stack["root"], "reports", str(sid))
    for name in ("verdicts.json", "verdicts.md", "report.html"):
        path = os.path.join(rep_dir, name)
        assert os.path.isfile(path), f"{name} was not written"
        assert os.path.getsize(path) > 0, f"{name} is empty"

    with open(os.path.join(rep_dir, "report.html"), encoding="utf-8") as f:
        html = f.read()
    assert "192.168.1.10" in html, (
        "the flagged host does not appear in the rendered report")


def test_queue_drains_and_a_second_run_is_a_no_op(stack):
    _upload(stack, PCAP)
    conn = stack["conn"]
    with contextlib.redirect_stdout(io.StringIO()):
        first = worker.run_once(conn, analyze_fn=_fake_judge,
                                md_fn=_stub_md, data_root=stack["root"])
        second = worker.run_once(conn, analyze_fn=_fake_judge,
                                 md_fn=_stub_md, data_root=stack["root"])
    assert first is not None
    assert second is None, "the worker re-ran an already finished session"


def test_duplicate_upload_is_idempotent(stack):
    """Re-uploading the same capture must not create a second session or a
    second copy on disk."""
    r1, sha = _upload(stack, PCAP)
    r2, _ = _upload(stack, PCAP)
    assert r1.status_code in (200, 202) and r2.status_code in (200, 202)

    conn = stack["conn"]
    assert conn.execute("SELECT COUNT(*) c FROM pcap_files WHERE sha256=?",
                        (sha,)).fetchone()["c"] == 1
    import glob
    stored = glob.glob(os.path.join(stack["root"], "data", "pcap",
                                    "*", "*", "*", "*"))
    assert len(stored) == 1, f"duplicate left extra files: {stored}"


def test_duplicate_upload_still_logs_ingest_telemetry(stack):
    """A duplicate upload is a real sensor->VM flow too. It must be recorded
    in telemetry_log, or the reconciler later flags the sensor's own
    re-uploaded chunk (spool drain / ring replay) as a rogue
    undeclared_infra_flow. Before the fix the dup path skipped logging."""
    _upload(stack, PCAP)
    _upload(stack, PCAP)
    conn = stack["conn"]
    n = conn.execute(
        "SELECT COUNT(*) c FROM telemetry_log WHERE source='ingest_log'"
    ).fetchone()["c"]
    assert n == 2, f"expected an ingest_log row per upload, got {n}"


def test_worker_failure_marks_the_session_and_frees_the_queue(stack):
    """A crash inside analysis must land in sessions.error, not wedge the
    queue - the failure mode the stale-job requeue also guards."""
    _upload(stack, PCAP)
    conn = stack["conn"]

    def boom(*a, **kw):
        raise RuntimeError("analysis exploded")

    with contextlib.redirect_stdout(io.StringIO()):
        sid = worker.run_once(conn, analyze_fn=boom, md_fn=_stub_md,
                              data_root=stack["root"])
    assert sid is not None
    row = conn.execute("SELECT status, error FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["status"] == "error"
    assert "analysis exploded" in (row["error"] or "")

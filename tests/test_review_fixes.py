"""Regressions for the eight defects an adversarial review confirmed.

Each test fails against the pre-fix code and states the failure mode it
locks down, so the reason the guard exists survives the next refactor.
No network, no LLM provider, no real sensor.
"""
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "llm_judge"))

from server import auth, db, reconcile, retention, storage  # noqa: E402


# --------------------------------------------------------------------------
# 1. reconcile: the three-way match must compare destinations.
# --------------------------------------------------------------------------
def _conn(tmp_path):
    c = db.connect(str(tmp_path / "netsec.db"))
    return c


def _new_pcap(conn, sensor_id, sha, path, size=100):
    pcap_id, _created = db.register_pcap(
        conn, sha256=sha, orig_name=os.path.basename(path),
        size_bytes=size, sensor_id=sensor_id, storage_path=path)
    return pcap_id


def _session_with_features(conn, ips):
    sensor_id = db.create_sensor(conn, "s1", "tokenhash", "secret")
    pcap_id = _new_pcap(conn, sensor_id, "a" * 64, "/tmp/x.pcap", 1)
    sid = db.create_session(conn, pcap_id, label="S1", kind="prod")
    for ip in ips:
        conn.execute(
            "INSERT INTO ip_features (session_id, ip, self_telemetry)"
            " VALUES (?,?,0)", (sid, ip))
    conn.commit()
    return sensor_id, sid


def _S(t0, t1, pairs):
    return {"t0": t0, "t1": t1, "ip_pairs": pairs}


def test_flow_to_undeclared_infra_dst_is_reported(tmp_path, monkeypatch):
    """The exfiltration case. A telemetry row exists (every upload writes
    one and it always overlaps the capture window), but it went somewhere
    else. Testing `if rows:` would excuse this flow and the rule could
    never fire on a live server."""
    conn = _conn(tmp_path)
    sensor_id, sid = _session_with_features(conn, ["192.168.1.77"])
    t0 = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    # The sensor's own upload, to the real infra host.
    db.log_ingest_telemetry(conn, sensor_id=sensor_id,
                            started_at=t0.timestamp(),
                            ended_at=t1.timestamp(),
                            dst="100.64.0.3", dst_port=8766,
                            bytes_sent=1000, file_sha256="a" * 64,
                            session_id=None)
    # A rogue host sending to a DIFFERENT declared infra address.
    S = _S(t0, t1, {("192.168.1.77", "100.64.0.9"): 500})
    out = reconcile.reconcile(conn, sid, S,
                              dsts={"100.64.0.3", "100.64.0.9"})
    assert out["undeclared"] == 1, (
        "a flow to an infra address with no matching telemetry row must "
        "be reported, not excused by an unrelated upload")
    assert "192.168.1.77" not in out["matched_ips"]
    row = conn.execute(
        "SELECT self_telemetry FROM ip_features WHERE session_id=? AND ip=?",
        (sid, "192.168.1.77")).fetchone()
    assert row["self_telemetry"] == 0, (
        "the rogue host must not be marked self-telemetry - that would "
        "exclude it from every future baseline and comparison")


def test_flow_matching_a_declared_dst_is_accepted(tmp_path):
    """The normal case still works: the sensor's own upload is recognised
    and not reported as a finding."""
    conn = _conn(tmp_path)
    sensor_id, sid = _session_with_features(conn, ["192.168.1.50"])
    t0 = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    db.log_ingest_telemetry(conn, sensor_id=sensor_id,
                            started_at=t0.timestamp(),
                            ended_at=t1.timestamp(),
                            dst="100.64.0.3", dst_port=8766,
                            bytes_sent=1000, file_sha256="a" * 64,
                            session_id=None)
    S = _S(t0, t1, {("192.168.1.50", "100.64.0.3"): 500})
    out = reconcile.reconcile(conn, sid, S, dsts={"100.64.0.3"})
    assert out["undeclared"] == 0
    assert out["matched_ips"] == ["192.168.1.50"]


def test_unexplained_telemetry_row_is_a_blind_spot(tmp_path):
    """The sensor says it uploaded but the capture shows no such flow -
    the capture has a hole. Must be reported even when other flows in the
    same session did match."""
    conn = _conn(tmp_path)
    sensor_id, sid = _session_with_features(conn, ["192.168.1.50"])
    t0 = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    for dst in ("100.64.0.3", "100.64.0.4"):
        db.log_ingest_telemetry(conn, sensor_id=sensor_id,
                                started_at=t0.timestamp(),
                                ended_at=t1.timestamp(),
                                dst=dst, dst_port=8766, bytes_sent=1,
                                file_sha256="a" * 64, session_id=None)
    # Only the .3 upload is visible in the packets.
    S = _S(t0, t1, {("192.168.1.50", "100.64.0.3"): 500})
    out = reconcile.reconcile(conn, sid, S,
                              dsts={"100.64.0.3", "100.64.0.4"})
    assert out["blind_spots"] == 1


# --------------------------------------------------------------------------
# 2. retention: one unpurgeable file must not wedge the watermark valve.
# --------------------------------------------------------------------------
def test_watermark_skips_a_failing_row_and_keeps_reclaiming(tmp_path):
    """Pre-fix this broke out of the loop on the first failure, and since
    the row keeps deleted_at NULL it was re-selected first on every later
    cycle - the emergency valve was disabled permanently."""
    conn = _conn(tmp_path)
    sensor_id = db.create_sensor(conn, "s1", "tokenhash", "secret")
    ids = []
    for i in range(3):
        path = tmp_path / f"p{i}.pcap"
        path.write_bytes(b"x" * 100)
        ids.append(_new_pcap(conn, sensor_id, chr(97 + i) * 64, str(path)))
    conn.commit()

    # The oldest file cannot be exported; the others can.
    def export_fn(pcap_path, out_path):
        return "p0.pcap" not in str(pcap_path)

    calls = {"n": 0}

    def usage_fn(_root):
        # Stay above the watermark for the first few checks, then drop.
        calls["n"] += 1
        return 99.0 if calls["n"] <= 4 else 10.0

    purged = retention.purge_by_watermark(
        conn, str(tmp_path), pct=85, export_fn=export_fn, usage_fn=usage_fn)
    assert purged >= 1, (
        "the failing oldest row must be skipped so newer rows can still "
        "be reclaimed")
    stuck = conn.execute(
        "SELECT deleted_at FROM pcap_files WHERE id=?", (ids[0],)).fetchone()
    assert stuck["deleted_at"] is None, (
        "a row that failed to purge must not be marked deleted")


# --------------------------------------------------------------------------
# 3. db: a dead worker must not strand a session in 'running'.
# --------------------------------------------------------------------------
def test_stale_running_session_is_requeued(tmp_path):
    conn = _conn(tmp_path)
    sensor_id = db.create_sensor(conn, "s1", "tokenhash", "secret")
    pcap_id = _new_pcap(conn, sensor_id, "a" * 64, "/tmp/x.pcap", 1)
    sid = db.create_session(conn, pcap_id, label="S1", kind="prod")
    claimed = db.claim_next_job(conn)
    assert claimed["id"] == sid
    assert db.claim_next_job(conn) is None      # nothing else queued

    # Simulate the worker dying: started_at is now far in the past.
    old = (datetime.now(timezone.utc) - timedelta(hours=3)) \
        .isoformat(timespec="seconds")
    conn.execute("UPDATE sessions SET started_at=? WHERE id=?", (old, sid))
    conn.commit()

    again = db.claim_next_job(conn)
    assert again is not None and again["id"] == sid, (
        "an abandoned running session must return to the queue instead of "
        "being stranded forever")


def test_running_session_within_the_window_is_left_alone(tmp_path):
    """A worker that is merely slow must not have its job stolen."""
    conn = _conn(tmp_path)
    sensor_id = db.create_sensor(conn, "s1", "tokenhash", "secret")
    pcap_id = _new_pcap(conn, sensor_id, "b" * 64, "/tmp/y.pcap", 1)
    db.create_session(conn, pcap_id, label="S1", kind="prod")
    db.claim_next_job(conn)
    assert db.claim_next_job(conn) is None


# --------------------------------------------------------------------------
# 4. storage: concurrent uploads of one digest must not share a spool file.
# --------------------------------------------------------------------------
def test_concurrent_writers_use_separate_spool_files(tmp_path):
    """Pre-fix both writers opened <sha>.part with O_TRUNC and interleaved
    their bytes, so each hashed only its own stream, both verified, and
    the file on disk was a mix of the two."""
    sha = "c" * 64
    w1 = storage.SpoolWriter(str(tmp_path), sha)
    w2 = storage.SpoolWriter(str(tmp_path), sha)
    assert w1.part_path != w2.part_path
    w1.write(b"aaaa")
    w2.write(b"bbbb")
    assert w1.close()[1] == 4 and w2.close()[1] == 4
    with open(w1.part_path, "rb") as f:
        assert f.read() == b"aaaa", "the other writer corrupted this stream"
    w1.discard()
    w2.discard()


def test_duplicate_upload_on_a_later_day_does_not_orphan_a_copy(tmp_path):
    """A re-upload landing in a different date directory used to create a
    second copy with no pcap_files row, invisible to every retention
    path."""
    payload = b"pcap-bytes"
    import hashlib
    sha = hashlib.sha256(payload).hexdigest()

    w1 = storage.SpoolWriter(str(tmp_path), sha)
    w1.write(payload)
    day1 = datetime(2026, 7, 1, tzinfo=timezone.utc)
    p1 = storage.finalize(w1, sha, "capture.pcap", when=day1)

    w2 = storage.SpoolWriter(str(tmp_path), sha)
    w2.write(payload)
    day2 = datetime(2026, 7, 20, tzinfo=timezone.utc)
    p2 = storage.finalize(w2, sha, "capture.pcap", when=day2)

    assert p1 == p2, "the duplicate must resolve to the existing file"
    import glob
    stored = glob.glob(os.path.join(str(tmp_path), "data", "pcap",
                                    "*", "*", "*", "*"))
    assert len(stored) == 1, f"a second copy was left on disk: {stored}"


# --------------------------------------------------------------------------
# 5. auth: a malformed signature is 401, not 500.
# --------------------------------------------------------------------------
def test_non_ascii_signature_is_rejected_not_crashed():
    """hmac.compare_digest raises TypeError on non-ASCII str, and the API
    only maps AuthError to 401 - so this used to surface as an unhandled
    500 and leaked the difference between malformed and merely wrong."""
    row = {"hmac_secret": "s3cret", "name": "sensor-1", "revoked_at": None}
    now = 1700000000
    with pytest.raises(auth.AuthError) as exc:
        auth.verify_upload(row, "a" * 64, now, "signature-with-emoji-\U0001F600",
                           now=now)
    assert exc.value.reason == "bad signature"


def test_correct_signature_still_verifies():
    row = {"hmac_secret": "s3cret", "name": "sensor-1", "revoked_at": None}
    now = 1700000000
    sig = auth.upload_signature("s3cret", "a" * 64, "sensor-1", now)
    assert auth.verify_upload(row, "a" * 64, now, sig, now=now) is None


# --------------------------------------------------------------------------
# 6/7. llm_judge: endpoint profiles must not borrow global defaults, and
#      the commentary must come from a judge that is actually in the panel.
# --------------------------------------------------------------------------
def test_profile_without_a_model_does_not_borrow_the_global_model(
        monkeypatch):
    """Same class of leak as the API key: the global model name belongs to
    the default host and names a model the profile's host never heard of."""
    import judge_config
    import llm_clients
    monkeypatch.setattr(judge_config, "OPENAI_COMPAT_MODEL",
                        "llama-3.3-70b-versatile")
    with pytest.raises(llm_clients.JudgeClientError) as exc:
        llm_clients.OpenAICompatClient(
            base_url="https://generativelanguage.googleapis.com/v1beta/openai")
    assert "model" in str(exc.value).lower()


def test_default_host_still_uses_the_global_model(monkeypatch):
    import judge_config
    import llm_clients
    monkeypatch.setattr(judge_config, "OPENAI_COMPAT_MODEL", "some-model")
    monkeypatch.setattr(judge_config, "OPENAI_COMPAT_BASE_URL",
                        "https://api.groq.com/openai/v1")
    c = llm_clients.OpenAICompatClient()
    assert c.model_id == "some-model"


# --------------------------------------------------------------------------
# 9. re-upload after retention purge must reactivate the row, not orphan
#    the new file (permanent disk leak) and skip re-analysis.
# --------------------------------------------------------------------------
def test_reupload_after_purge_reactivates_pcap_row(tmp_path):
    conn = _conn(tmp_path)
    sensor_id = db.create_sensor(conn, "s1", "tokenhash", "secret")
    sha = "cc" * 32
    pid, created = db.register_pcap(conn, sha, "c.pcap", 100, sensor_id,
                                    "/data/pcap/2026/01/01/cc_c.pcap")
    assert created is True
    db.create_session(conn, pid, label="S1", kind="prod")

    # retention purged the raw file: deleted_at stamped, storage_path stale
    conn.execute("UPDATE pcap_files SET deleted_at=? WHERE id=?",
                 (datetime.now(timezone.utc).isoformat(), pid))
    conn.commit()

    # the same capture is uploaded again; it lands at a fresh path
    new_path = "/data/pcap/2026/03/03/cc_c.pcap"
    pid2, created2 = db.register_pcap(conn, sha, "c.pcap", 100, sensor_id,
                                      new_path)
    # same row, but reactivated -> created True so the API queues analysis
    assert pid2 == pid
    assert created2 is True
    row = conn.execute(
        "SELECT storage_path, deleted_at FROM pcap_files WHERE id=?",
        (pid,)).fetchone()
    # deleted_at cleared (retention can manage it again) and repointed at
    # the new file (no orphan on disk)
    assert row["deleted_at"] is None
    assert row["storage_path"] == new_path
    # a still-live duplicate (no deleted_at) is NOT reactivated
    pid3, created3 = db.register_pcap(conn, sha, "c.pcap", 100, sensor_id,
                                      "/somewhere/else.pcap")
    assert pid3 == pid and created3 is False
    conn.close()

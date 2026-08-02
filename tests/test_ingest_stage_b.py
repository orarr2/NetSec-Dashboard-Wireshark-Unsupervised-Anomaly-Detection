"""Stage B regression: history DB schema, HMAC upload auth, streaming
storage, the ingest API, and the upload CLI.

Layered to match server/'s design: everything except the API tests is
stdlib-pure and always runs; the API tests skip cleanly when fastapi is
not installed (it is a server-side dependency, deliberately absent from
the dashboard's requirements.txt).
"""
import http.server
import json
import os
import subprocess
import sys
import threading

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import auth, db, storage  # noqa: E402


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "netsec.db"))
    yield c
    c.close()


# ---- schema --------------------------------------------------------------

def test_schema_version_and_tables(conn):
    version, = conn.execute("PRAGMA user_version").fetchone()
    assert version == db.SCHEMA_VERSION == 6
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    expected = {"sensors", "pcap_files", "sessions", "ip_features",
                "findings", "adv_signals", "fusion_scores", "candidates",
                "verdicts", "panel_audit", "reports", "device_baselines",
                "gaps", "llm_quota", "telemetry_log", "compare_jobs"}
    assert expected <= tables
    # v3 adds sessions.notify_email so the ingest header can survive
    # into the worker's fallback chain.
    session_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(sessions)")}
    assert "notify_email" in session_cols
    # v6 adds compare_jobs with per-pair uniqueness (except errored rows).
    cj_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(compare_jobs)")}
    assert {"s1_session_id", "s2_session_id", "status", "verdict_json",
            "stats_json", "notify_email"} <= cj_cols


def test_migrate_is_idempotent(conn):
    before = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    db.migrate(conn)
    after = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    assert before == after


# ---- auth ----------------------------------------------------------------

SHA = "ab" * 32


def _sensor(conn, name="laptop"):
    token = "tok-" + name
    db.create_sensor(conn, name, auth.hash_token(token), "sec-" + name)
    return db.get_sensor(conn, name), token


def test_hmac_roundtrip_and_failures(conn):
    sensor, _ = _sensor(conn)
    now = 1_800_000_000
    sig = auth.upload_signature(sensor["hmac_secret"], SHA,
                                sensor["name"], now)
    auth.verify_upload(sensor, SHA, str(now), sig, now=now)  # no raise

    with pytest.raises(auth.AuthError) as e:
        auth.verify_upload(sensor, SHA, str(now), "0" * 64, now=now)
    assert e.value.reason == "bad signature"

    with pytest.raises(auth.AuthError) as e:  # signature from wrong secret
        bad = auth.upload_signature("other-secret", SHA, sensor["name"], now)
        auth.verify_upload(sensor, SHA, str(now), bad, now=now)
    assert e.value.reason == "bad signature"

    with pytest.raises(auth.AuthError) as e:  # replayed outside the window
        auth.verify_upload(sensor, SHA, str(now), sig, now=now + 301)
    assert e.value.reason == "timestamp outside window"

    with pytest.raises(auth.AuthError) as e:
        auth.verify_upload(None, SHA, str(now), sig, now=now)
    assert e.value.reason == "unknown sensor"

    conn.execute("UPDATE sensors SET revoked_at='2026-07-30' WHERE id=?",
                 (sensor["id"],))
    revoked = db.get_sensor(conn, sensor["name"])
    with pytest.raises(auth.AuthError) as e:
        auth.verify_upload(revoked, SHA, str(now), sig, now=now)
    assert e.value.reason == "sensor revoked"


def test_bearer_lookup(conn):
    sensor, token = _sensor(conn, "pi5")
    found = auth.verify_bearer(conn, f"Bearer {token}")
    assert found["id"] == sensor["id"]
    for bad in (None, "", "Bearer ", "Bearer nope", "Basic abc"):
        with pytest.raises(auth.AuthError):
            auth.verify_bearer(conn, bad)


# ---- pcaps + sessions ----------------------------------------------------

def test_register_pcap_idempotent_and_session_flow(conn):
    sensor, _ = _sensor(conn)
    pcap_id, created = db.register_pcap(conn, SHA, "a.pcap", 123,
                                        sensor["id"], "/x/a.pcap")
    assert created
    again, created2 = db.register_pcap(conn, SHA, "a.pcap", 123,
                                       sensor["id"], "/x/a.pcap")
    assert (again, created2) == (pcap_id, False)

    assert db.latest_session_for_pcap(conn, pcap_id) is None
    sid = db.create_session(conn, pcap_id, "S1", "test")
    assert db.latest_session_for_pcap(conn, pcap_id) == sid
    session = db.get_session(conn, sid)
    assert session["status"] == "queued"
    assert session["kind"] == "test"
    assert session["sha256"] == SHA

    with pytest.raises(ValueError):
        db.create_session(conn, pcap_id, "S1", "staging")


def test_errored_session_is_not_reused_for_dedup(conn):
    """A re-upload must not be deduplicated onto a session that already
    failed: that session will never produce a report, so the requester
    would wait forever for an email nobody is going to send."""
    sensor, _ = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, SHA, "a.pcap", 123,
                                  sensor["id"], "/x/a.pcap")
    dead = db.create_session(conn, pcap_id, "S1", "prod")
    db.claim_next_job(conn)
    db.mark_error(conn, dead, "worker died")
    assert db.get_session(conn, dead)["status"] == "error"

    # nothing reusable left -> the caller queues a fresh session
    assert db.latest_session_for_pcap(conn, pcap_id) is None

    fresh = db.create_session(conn, pcap_id, "S1-retry", "prod")
    assert db.latest_session_for_pcap(conn, pcap_id) == fresh
    # a healthy session still wins over a newer errored one
    newer_dead = db.create_session(conn, pcap_id, "S1-retry2", "prod")
    db.claim_next_job(conn)
    db.mark_error(conn, newer_dead, "died again")
    assert db.latest_session_for_pcap(conn, pcap_id) == fresh


# ---- compare_jobs (schema v6, dual-session S1 vs S2 report) -------------

def test_compare_job_create_and_dedup(conn):
    """A repeat click on Compare S1 & S2 must not re-queue the same pair
    - the mail box would fill with duplicates - but a job that failed
    must NOT block a fresh attempt (mirrors the errored-session fix)."""
    sensor, _ = _sensor(conn)
    p1, _ = db.register_pcap(conn, "a" * 64, "a.pcap", 1,
                             sensor["id"], "/x/a")
    p2, _ = db.register_pcap(conn, "b" * 64, "b.pcap", 1,
                             sensor["id"], "/x/b")
    s1 = db.create_session(conn, p1, "S1", "prod")
    s2 = db.create_session(conn, p2, "S2", "prod")

    job1, created1 = db.create_compare_job(conn, s1, s2,
                                           notify_email="me@x")
    assert created1 is True
    dup, created2 = db.create_compare_job(conn, s1, s2)
    assert dup == job1 and created2 is False

    # a blank second call still adopts a fresh email if the first was blank
    p3, _ = db.register_pcap(conn, "c" * 64, "c.pcap", 1,
                             sensor["id"], "/x/c")
    p4, _ = db.register_pcap(conn, "d" * 64, "d.pcap", 1,
                             sensor["id"], "/x/d")
    sa = db.create_session(conn, p3, "S1b", "prod")
    sb = db.create_session(conn, p4, "S2b", "prod")
    j, _ = db.create_compare_job(conn, sa, sb)          # no email
    db.create_compare_job(conn, sa, sb, notify_email="late@x")
    assert db.get_compare_job(conn, j)["notify_email"] == "late@x"

    # an errored job unlocks the pair for a fresh queue
    db.mark_compare_error(conn, job1, "worker died")
    fresh, created3 = db.create_compare_job(conn, s1, s2)
    assert fresh != job1 and created3 is True


def test_claim_next_compare_job_atomic(conn):
    sensor, _ = _sensor(conn)
    p1, _ = db.register_pcap(conn, "a" * 64, "a.pcap", 1,
                             sensor["id"], "/x/a")
    p2, _ = db.register_pcap(conn, "b" * 64, "b.pcap", 1,
                             sensor["id"], "/x/b")
    s1 = db.create_session(conn, p1, "S1", "prod")
    s2 = db.create_session(conn, p2, "S2", "prod")
    job, _ = db.create_compare_job(conn, s1, s2)
    assert db.claim_next_compare_job(conn)["id"] == job
    # once claimed it is running and no longer picked
    assert db.get_compare_job(conn, job)["status"] == "running"
    assert db.claim_next_compare_job(conn) is None

    db.mark_compare_done(conn, job,
                         verdict_json='{"summary":"escalated"}',
                         stats_json='{"total":5}',
                         prompt_version="v0.5.0")
    row = db.get_compare_job(conn, job)
    assert row["status"] == "done"
    assert row["verdict_json"] == '{"summary":"escalated"}'
    assert row["prompt_version"] == "v0.5.0"


# ---- storage -------------------------------------------------------------

def test_storage_stream_and_finalize(tmp_path):
    payload = b"pcap-bytes" * 1000
    import hashlib
    digest = hashlib.sha256(payload).hexdigest()

    w = storage.SpoolWriter(str(tmp_path), digest)
    for i in range(0, len(payload), 512):
        w.write(payload[i:i + 512])
    final = storage.finalize(w, digest, "my capture!.pcapng")
    assert os.path.isfile(final)
    assert not os.path.exists(w.part_path)
    assert os.path.basename(final).startswith(digest[:8] + "_")
    assert "!" not in final  # sanitized
    assert f"{os.sep}data{os.sep}pcap{os.sep}" in final


def test_storage_mismatch_discards(tmp_path):
    w = storage.SpoolWriter(str(tmp_path), "ff" * 32)
    w.write(b"not the declared content")
    with pytest.raises(ValueError):
        storage.finalize(w, "ff" * 32, "x.pcap")
    assert not os.path.exists(w.part_path)


# ---- ingest API (skips when fastapi is absent) ---------------------------

@pytest.fixture
def api(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from server.ingest_api import create_app

    app = create_app(db_path=str(tmp_path / "netsec.db"),
                     data_root=str(tmp_path))
    conn = db.connect(str(tmp_path / "netsec.db"))
    sensor, token = _sensor(conn, "apitest")
    conn.close()
    with TestClient(app) as client:
        yield client, sensor, token


def _upload_headers(sensor, payload):
    import hashlib
    import time as _t
    digest = hashlib.sha256(payload).hexdigest()
    ts = int(_t.time())
    return digest, {
        "X-Sensor-Id": sensor["name"],
        "X-Sha256": digest,
        "X-Timestamp": str(ts),
        "X-Signature": auth.upload_signature(sensor["hmac_secret"],
                                             digest, sensor["name"], ts),
        "X-Filename": "t.pcap",
    }


def test_api_upload_flow(api):
    client, sensor, token = api
    assert client.get("/healthz").json() == {"status": "ok",
                                              "schema": db.SCHEMA_VERSION}

    payload = b"\xd4\xc3\xb2\xa1" + b"x" * 4096
    digest, headers = _upload_headers(sensor, payload)

    r = client.post("/v1/pcap", content=payload, headers=headers)
    assert r.status_code == 202, r.text
    sid = r.json()["session_id"]
    assert r.json()["duplicate"] is False

    dup = client.post("/v1/pcap", content=payload, headers=headers)
    assert dup.status_code == 200
    assert dup.json() == {"session_id": sid,
                          "pcap_id": r.json()["pcap_id"],
                          "duplicate": True}

    bad = dict(headers, **{"X-Signature": "0" * 64})
    assert client.post("/v1/pcap", content=payload,
                       headers=bad).status_code == 401

    tampered = client.post("/v1/pcap", content=payload + b"!",
                           headers=headers)
    assert tampered.status_code == 400  # digest mismatch

    auth_hdr = {"Authorization": f"Bearer {token}"}
    session = client.get(f"/v1/sessions/{sid}", headers=auth_hdr)
    assert session.status_code == 200
    assert session.json()["sha256"] == digest
    assert client.get(f"/v1/sessions/{sid}").status_code == 401
    assert client.get("/v1/sessions/999999",
                      headers=auth_hdr).status_code == 404
    assert client.get(f"/v1/reports/{sid}.html",
                      headers=auth_hdr).status_code == 404


def test_api_records_ingest_telemetry(api, tmp_path):
    client, sensor, _ = api
    payload = b"\xd4\xc3\xb2\xa1" + b"y" * 100
    _, headers = _upload_headers(sensor, payload)
    assert client.post("/v1/pcap", content=payload,
                       headers=headers).status_code == 202
    conn = db.connect(str(tmp_path / "netsec.db"))
    try:
        row = conn.execute("SELECT * FROM telemetry_log").fetchone()
    finally:
        conn.close()
    assert row["source"] == "ingest_log"
    assert row["bytes_sent"] == len(payload)


# ---- /v1/compare endpoint (dual-session report) --------------------------

def _seed_done_session(tmp_path, sensor_name="apitest", sha_prefix="cc",
                       label="cap"):
    """Helper: register a pcap + finish a session on the api-owned DB."""
    conn = db.connect(str(tmp_path / "netsec.db"))
    try:
        sensor = db.get_sensor(conn, sensor_name)
        sha = (sha_prefix * 32)[:64]
        pid, _ = db.register_pcap(conn, sha, f"{sha_prefix}.pcap", 200,
                                  sensor["id"], f"/x/{sha_prefix}.pcap")
        sid = db.create_session(conn, pid, label, "prod")
        db.claim_next_job(conn)
        db.mark_done(conn, sid, n_pkts=1, n_ips=1)
    finally:
        conn.close()
    return sid


def test_compare_endpoint_creates_and_deduplicates(api, tmp_path):
    client, sensor, token = api
    s1 = _seed_done_session(tmp_path, sha_prefix="ea", label="cap1")
    s2 = _seed_done_session(tmp_path, sha_prefix="eb", label="cap2")
    auth_hdr = {"Authorization": f"Bearer {token}"}

    r = client.post("/v1/compare",
                    json={"s1_session_id": s1, "s2_session_id": s2},
                    headers={**auth_hdr, "X-Notify-Email": "me@x.com"})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["duplicate"] is False
    job_id = body["compare_job_id"]

    dup = client.post("/v1/compare",
                      json={"s1_session_id": s1, "s2_session_id": s2},
                      headers=auth_hdr)
    assert dup.status_code == 200
    assert dup.json()["compare_job_id"] == job_id
    assert dup.json()["duplicate"] is True


def test_compare_endpoint_requires_both_done(api, tmp_path):
    """A pair posted while one side is still queued MUST fail with 409
    - a partial-verdict pair would mislead the LLM into 'de-escalated'."""
    client, sensor, token = api
    s1 = _seed_done_session(tmp_path, sha_prefix="fa")
    # s2 is queued (never claimed / done)
    conn = db.connect(str(tmp_path / "netsec.db"))
    try:
        sens = db.get_sensor(conn, "apitest")
        pid, _ = db.register_pcap(conn, "fb" * 32, "fb.pcap", 200,
                                  sens["id"], "/x/fb.pcap")
        s2 = db.create_session(conn, pid, "still-queued", "prod")
    finally:
        conn.close()
    auth_hdr = {"Authorization": f"Bearer {token}"}
    r = client.post("/v1/compare",
                    json={"s1_session_id": s1, "s2_session_id": s2},
                    headers=auth_hdr)
    assert r.status_code == 409
    assert "status" in r.text


def test_compare_endpoint_rejects_bad_body_and_same_session(api, tmp_path):
    client, sensor, token = api
    s1 = _seed_done_session(tmp_path, sha_prefix="1a")
    auth_hdr = {"Authorization": f"Bearer {token}"}

    assert client.post("/v1/compare", data="not-json",
                       headers=auth_hdr).status_code == 400
    assert client.post("/v1/compare", json={"s1_session_id": "one",
                                            "s2_session_id": 2},
                       headers=auth_hdr).status_code == 400
    r = client.post("/v1/compare",
                    json={"s1_session_id": s1, "s2_session_id": s1},
                    headers=auth_hdr)
    assert r.status_code == 400
    # bearer required
    assert client.post("/v1/compare",
                       json={"s1_session_id": s1,
                             "s2_session_id": s1 + 1}).status_code == 401


def test_compare_endpoint_status_returns_job(api, tmp_path):
    client, sensor, token = api
    s1 = _seed_done_session(tmp_path, sha_prefix="2a")
    s2 = _seed_done_session(tmp_path, sha_prefix="2b")
    auth_hdr = {"Authorization": f"Bearer {token}"}
    r = client.post("/v1/compare",
                    json={"s1_session_id": s1, "s2_session_id": s2},
                    headers=auth_hdr)
    jid = r.json()["compare_job_id"]

    status = client.get(f"/v1/compare/{jid}", headers=auth_hdr)
    assert status.status_code == 200
    body = status.json()
    assert body["id"] == jid
    assert body["status"] == "queued"

    assert client.get(f"/v1/compare/{jid}").status_code == 401
    assert client.get("/v1/compare/999999",
                      headers=auth_hdr).status_code == 404


# ---- upload CLI against a stdlib stub server -----------------------------

def test_upload_cli_end_to_end(tmp_path):
    secret, sensor_name = "cli-secret", "cli-sensor"
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            import hashlib
            seen["digest_ok"] = (hashlib.sha256(body).hexdigest()
                                 == self.headers["X-Sha256"])
            seen["sig_ok"] = (auth.upload_signature(
                secret, self.headers["X-Sha256"],
                self.headers["X-Sensor-Id"],
                self.headers["X-Timestamp"])
                == self.headers["X-Signature"])
            seen["kind"] = self.headers["X-Session-Kind"]
            out = json.dumps({"session_id": 7,
                              "duplicate": False}).encode()
            self.send_response(202)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(2048))
        manifest = tmp_path / "telemetry.jsonl"
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "tools", "upload_pcap.py"),
             str(pcap), "--kind", "test",
             "--url", f"http://127.0.0.1:{server.server_address[1]}",
             "--sensor", sensor_name, "--secret", secret,
             "--manifest", str(manifest)],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        assert "session_id=7" in r.stdout
        assert seen == {"digest_ok": True, "sig_ok": True, "kind": "test"}

        record = json.loads(manifest.read_text().strip())
        assert record["bytes_sent"] == pcap.stat().st_size
        assert record["dst"] == "127.0.0.1"
    finally:
        server.shutdown()


def test_bearer_cannot_read_another_sensors_session(tmp_path):
    """Cross-sensor authz. Sensor A uploads a capture; sensor B has a valid
    bearer of its own. B must NOT be able to read A's session or reports.
    404 (not 403) so the presence of A's session id is not confirmed."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from server.ingest_api import create_app

    app = create_app(db_path=str(tmp_path / "netsec.db"),
                     data_root=str(tmp_path))
    conn = db.connect(str(tmp_path / "netsec.db"))
    a_sensor, a_token = _sensor(conn, "sensor-a")
    b_sensor, b_token = _sensor(conn, "sensor-b")
    conn.close()

    with TestClient(app) as client:
        payload = b"\xd4\xc3\xb2\xa1" + b"z" * 200
        _, headers = _upload_headers(a_sensor, payload)
        r = client.post("/v1/pcap", content=payload, headers=headers)
        assert r.status_code == 202, r.text
        sid = r.json()["session_id"]

        # A can read its own session
        ok = client.get(f"/v1/sessions/{sid}",
                        headers={"Authorization": f"Bearer {a_token}"})
        assert ok.status_code == 200

        # B (a real, valid sensor) cannot - and gets 404, not 403,
        # so the id's existence is not disclosed.
        forbidden = client.get(
            f"/v1/sessions/{sid}",
            headers={"Authorization": f"Bearer {b_token}"})
        assert forbidden.status_code == 404

        # Report endpoint is subject to the same rule (before 404 for the
        # report itself, which isn't generated yet).
        forbidden_r = client.get(
            f"/v1/reports/{sid}.html",
            headers={"Authorization": f"Bearer {b_token}"})
        assert forbidden_r.status_code == 404

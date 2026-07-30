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
    assert version == db.SCHEMA_VERSION == 1
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    expected = {"sensors", "pcap_files", "sessions", "ip_features",
                "findings", "adv_signals", "fusion_scores", "candidates",
                "verdicts", "panel_audit", "reports", "device_baselines",
                "gaps", "llm_quota", "telemetry_log"}
    assert expected <= tables


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
    assert client.get("/healthz").json() == {"status": "ok", "schema": 1}

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

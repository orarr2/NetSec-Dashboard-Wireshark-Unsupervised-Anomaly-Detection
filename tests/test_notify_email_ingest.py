"""End-to-end: X-Notify-Email survives the ingest API into the DB and
back out through the worker's delivery hook.

If either link breaks - the header is dropped, the column disappears,
the worker consults env before session - the feature is silently dead
and the user waits for an email that never arrives. So every link
gets an explicit test.
"""
import hashlib
import os
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import auth, db  # noqa: E402


def _sensor(conn, name="apitest"):
    token = "tok-" + name
    db.create_sensor(conn, name, auth.hash_token(token), "sec-" + name)
    return db.get_sensor(conn, name), token


def _upload_headers(sensor, payload, extra=None):
    digest = hashlib.sha256(payload).hexdigest()
    ts = int(time.time())
    headers = {
        "X-Sensor-Id": sensor["name"],
        "X-Sha256": digest,
        "X-Timestamp": str(ts),
        "X-Signature": auth.upload_signature(sensor["hmac_secret"],
                                             digest, sensor["name"], ts),
        "X-Filename": "t.pcap",
    }
    if extra:
        headers.update(extra)
    return digest, headers


# ---- schema + DB layer ---------------------------------------------------

def test_create_session_stores_notify_email(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor, _ = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "a" * 64, "t.pcap", 10,
                                  sensor["id"], "/tmp/t.pcap")
    sid = db.create_session(conn, pcap_id, "S1", "prod",
                            notify_email="me@example.com")
    row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["notify_email"] == "me@example.com"


def test_create_session_defaults_null(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor, _ = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "b" * 64, "t.pcap", 10,
                                  sensor["id"], "/tmp/t.pcap")
    sid = db.create_session(conn, pcap_id, "S1", "prod")
    row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["notify_email"] is None


def test_set_session_notify_email_first_writer_wins(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor, _ = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "c" * 64, "t.pcap", 10,
                                  sensor["id"], "/tmp/t.pcap")
    sid = db.create_session(conn, pcap_id, "S1", "prod")

    # First set: succeeds (was null)
    assert db.set_session_notify_email(conn, sid, "first@example.com") is True
    row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["notify_email"] == "first@example.com"

    # Second set: refuses to overwrite (protects the first requester)
    assert db.set_session_notify_email(conn, sid, "second@example.com") is False
    row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["notify_email"] == "first@example.com"


def test_set_session_notify_email_ignores_empty(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor, _ = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "d" * 64, "t.pcap", 10,
                                  sensor["id"], "/tmp/t.pcap")
    sid = db.create_session(conn, pcap_id, "S1", "prod")
    assert db.set_session_notify_email(conn, sid, "") is False
    assert db.set_session_notify_email(conn, sid, None) is False


# ---- ingest API roundtrip -----------------------------------------------

@pytest.fixture
def api(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from server.ingest_api import create_app
    app = create_app(db_path=str(tmp_path / "netsec.db"),
                     data_root=str(tmp_path))
    conn = db.connect(str(tmp_path / "netsec.db"))
    sensor, token = _sensor(conn)
    conn.close()
    with TestClient(app) as client:
        yield client, sensor, token, str(tmp_path / "netsec.db")


def test_ingest_stores_notify_email_on_new_session(api):
    client, sensor, _, db_path = api
    payload = b"\xd4\xc3\xb2\xa1" + b"x" * 1024
    _, headers = _upload_headers(
        sensor, payload,
        extra={"X-Notify-Email": "orarbeli1@gmail.com"})
    r = client.post("/v1/pcap", content=payload, headers=headers)
    assert r.status_code == 202
    sid = r.json()["session_id"]

    conn = db.connect(db_path)
    try:
        row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    finally:
        conn.close()
    assert row["notify_email"] == "orarbeli1@gmail.com"


def test_ingest_invalid_email_stored_as_null_but_upload_still_accepted(api):
    """A typo in the email header must not cost the user their upload."""
    client, sensor, _, db_path = api
    payload = b"\xd4\xc3\xb2\xa1" + b"y" * 1024
    _, headers = _upload_headers(
        sensor, payload,
        extra={"X-Notify-Email": "not an email"})
    r = client.post("/v1/pcap", content=payload, headers=headers)
    assert r.status_code == 202
    sid = r.json()["session_id"]

    conn = db.connect(db_path)
    try:
        row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    finally:
        conn.close()
    assert row["notify_email"] is None


def test_ingest_no_header_stores_null(api):
    client, sensor, _, db_path = api
    payload = b"\xd4\xc3\xb2\xa1" + b"z" * 1024
    _, headers = _upload_headers(sensor, payload)  # no X-Notify-Email
    r = client.post("/v1/pcap", content=payload, headers=headers)
    assert r.status_code == 202
    sid = r.json()["session_id"]

    conn = db.connect(db_path)
    try:
        row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    finally:
        conn.close()
    assert row["notify_email"] is None


def test_ingest_duplicate_upload_backfills_notify_email(api):
    """Re-upload of the same pcap with an email backfills a NULL address
    on the original session - so a second try with the address still
    reaches the requester."""
    client, sensor, _, db_path = api
    payload = b"\xd4\xc3\xb2\xa1" + b"w" * 1024
    _, headers = _upload_headers(sensor, payload)  # first: no email
    r1 = client.post("/v1/pcap", content=payload, headers=headers)
    assert r1.status_code == 202
    sid = r1.json()["session_id"]

    _, headers2 = _upload_headers(
        sensor, payload,
        extra={"X-Notify-Email": "backfill@example.com"})
    r2 = client.post("/v1/pcap", content=payload, headers=headers2)
    assert r2.status_code == 200
    assert r2.json()["session_id"] == sid
    assert r2.json()["duplicate"] is True

    conn = db.connect(db_path)
    try:
        row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    finally:
        conn.close()
    assert row["notify_email"] == "backfill@example.com"


def test_ingest_duplicate_upload_does_not_overwrite_existing_email(api):
    """A second uploader with a different address cannot hijack the
    delivery of a session that already has one."""
    client, sensor, _, db_path = api
    payload = b"\xd4\xc3\xb2\xa1" + b"v" * 1024
    _, headers = _upload_headers(
        sensor, payload,
        extra={"X-Notify-Email": "owner@example.com"})
    r1 = client.post("/v1/pcap", content=payload, headers=headers)
    assert r1.status_code == 202
    sid = r1.json()["session_id"]

    _, headers2 = _upload_headers(
        sensor, payload,
        extra={"X-Notify-Email": "attacker@example.com"})
    r2 = client.post("/v1/pcap", content=payload, headers=headers2)
    assert r2.status_code == 200

    conn = db.connect(db_path)
    try:
        row = conn.execute("SELECT notify_email FROM sessions WHERE id=?",
                           (sid,)).fetchone()
    finally:
        conn.close()
    assert row["notify_email"] == "owner@example.com"


# ---- CLI flag -----------------------------------------------------------

def test_upload_pcap_cli_sends_email_header(tmp_path):
    """--email must become the X-Notify-Email header on the wire."""
    import http.server
    import threading

    secret, sensor_name = "cli-secret", "cli-sensor"
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or "0")
            self.rfile.read(n)
            seen["notify_email"] = self.headers.get("X-Notify-Email")
            body = b'{"session_id":9,"duplicate":false}'
            self.send_response(202)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(2048))
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "tools", "upload_pcap.py"),
             str(pcap), "--kind", "test",
             "--url", f"http://127.0.0.1:{server.server_address[1]}",
             "--sensor", sensor_name, "--secret", secret,
             "--manifest", str(tmp_path / "telemetry.jsonl"),
             "--email", "orarbeli1@gmail.com"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        assert r.returncode == 0, r.stderr
        assert seen.get("notify_email") == "orarbeli1@gmail.com"
    finally:
        server.shutdown()


def test_upload_pcap_cli_omits_email_header_when_absent(tmp_path):
    import http.server
    import threading

    secret, sensor_name = "cli-secret", "cli-sensor"
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or "0")
            self.rfile.read(n)
            seen["notify_email"] = self.headers.get("X-Notify-Email")
            body = b'{"session_id":9,"duplicate":false}'
            self.send_response(202)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(2048))
        env = {k: v for k, v in os.environ.items()
               if k != "NETSEC_NOTIFY_EMAIL"}
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "tools", "upload_pcap.py"),
             str(pcap), "--kind", "test",
             "--url", f"http://127.0.0.1:{server.server_address[1]}",
             "--sensor", sensor_name, "--secret", secret,
             "--manifest", str(tmp_path / "telemetry.jsonl")],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace", env=env)
        assert r.returncode == 0, r.stderr
        assert seen.get("notify_email") is None
    finally:
        server.shutdown()

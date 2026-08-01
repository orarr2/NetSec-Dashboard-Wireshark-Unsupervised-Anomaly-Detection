"""Ingest API - the HTTP layer over db/auth/storage (spec section 5.1).

The only module in server/ that imports FastAPI. Endpoints:

    GET  /healthz                       liveness for the watchdog, no auth
    POST /v1/pcap                       signed streaming upload, 202/200
    GET  /v1/sessions/{id}              session status, bearer auth
    GET  /v1/reports/{id}.{kind}        json|md|html|pdf, bearer auth

Upload protocol (see server/auth.py for the signature):
    X-Sensor-Id       sensor name from deploy/create_sensor.py
    X-Sha256          hex digest of the file being sent
    X-Timestamp       unix seconds, must be inside the replay window
    X-Signature       HMAC-SHA256 over "<sha256>:<sensor>:<timestamp>"
    X-Session-Kind    optional: prod (default) | test   (decision IDX-11)
    X-Session-Label   optional: display label, defaults to the filename
    X-Notify-Email    optional: mail the report here when analysis is done
                      (silently ignored if not a plausible address so a bad
                      value never blocks the upload)

Duplicate uploads (same sha256) are idempotent: the existing session is
returned with 200 and {"duplicate": true} instead of a new 202.

Run:  uvicorn server.ingest_api:app --host 0.0.0.0 --port 8766
"""
import os
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from . import auth, db, storage

MAX_UPLOAD_BYTES = int(float(os.environ.get("NETSEC_MAX_UPLOAD_GB", "10"))
                       * 1024 ** 3)
HMAC_WINDOW_S = int(os.environ.get("NETSEC_HMAC_WINDOW_S",
                                   str(auth.DEFAULT_WINDOW_S)))

_REPORT_MEDIA = {"json": "application/json",
                 "md": "text/markdown",
                 "html": "text/html",
                 "pdf": "application/pdf",
                 "map": "text/html"}


def create_app(db_path=None, data_root=None):
    """App factory - tests build isolated instances on temp dirs; the
    module-level ``app`` below serves the real deployment."""
    app = FastAPI(title="netsec-ingest", docs_url=None, redoc_url=None)
    app.state.db_path = db_path or db.default_db_path()
    app.state.data_root = storage.data_root(data_root)

    def _conn():
        # one short-lived connection per request: SQLite in WAL mode
        # handles this pattern well and it sidesteps cross-thread reuse
        return db.connect(app.state.db_path)

    @app.get("/healthz")
    def healthz():
        conn = _conn()
        try:
            version, = conn.execute("PRAGMA user_version").fetchone()
        finally:
            conn.close()
        return {"status": "ok", "schema": version}

    @app.post("/v1/pcap")
    async def upload_pcap(request: Request,
                          x_sensor_id: str = Header(...),
                          x_sha256: str = Header(...),
                          x_timestamp: str = Header(...),
                          x_signature: str = Header(...),
                          x_session_kind: str = Header("prod"),
                          x_session_label: str = Header(None),
                          x_filename: str = Header("capture.pcap"),
                          x_notify_email: str = Header(None),
                          x_judge_panel: str = Header(None)):
        started = time.time()
        sha = x_sha256.strip().lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise HTTPException(400, "X-Sha256 must be a hex sha256")
        if x_session_kind not in ("prod", "test"):
            raise HTTPException(400, "X-Session-Kind must be prod|test")

        notify_email = None
        if x_notify_email:
            # Validate but don't reject the upload on a bad address - the
            # analysis is more valuable than the notification, and a typo
            # in a header should not lose a large PCAP. Uses the
            # server/notify validator (llm_judge is not on ingest's PYTHONPATH).
            from .notify import valid_address
            if valid_address(x_notify_email):
                notify_email = x_notify_email.strip()

        # N1: per-upload judge panel override. Store the raw header
        # value (preset id like "fast_cloud_3" or a raw LLM_JUDGE_PANEL
        # spec). The worker resolves preset id -> spec at dequeue via
        # llm_judge.panel_presets - ingest_api's image does not carry
        # llm_judge on PYTHONPATH by design (small image, no PyTorch).
        # A UI typo (unrecognised id / junk spec) silently falls back
        # to the .env default LLM_JUDGE_PANEL - never lose a PCAP.
        judge_panel_override = None
        if x_judge_panel:
            candidate = x_judge_panel.strip()
            # cheap sanity cap: reject nothing plausible, drop clearly
            # abusive lengths so a malicious header can't bloat the DB
            if 0 < len(candidate) <= 512:
                judge_panel_override = candidate

        conn = _conn()
        try:
            sensor = db.get_sensor(conn, x_sensor_id)
            try:
                # signature covers the declared sha - verified before a
                # single byte is stored, so junk is rejected cheaply
                auth.verify_upload(sensor, sha, x_timestamp, x_signature,
                                   window_s=HMAC_WINDOW_S)
            except auth.AuthError as e:
                raise HTTPException(401, e.reason)

            writer = storage.SpoolWriter(app.state.data_root, sha)
            try:
                async for chunk in request.stream():
                    writer.write(chunk)
                    if writer.nbytes > MAX_UPLOAD_BYTES:
                        writer.discard()
                        raise HTTPException(413, "upload exceeds "
                                                 "NETSEC_MAX_UPLOAD_GB")
                final_path = storage.finalize(writer, sha, x_filename)
            except ValueError as e:          # digest mismatch
                raise HTTPException(400, str(e))
            except HTTPException:
                raise
            except Exception:
                writer.discard()
                raise

            size = os.path.getsize(final_path)
            pcap_id, created = db.register_pcap(
                conn, sha, storage.sanitize_name(x_filename), size,
                sensor["id"], final_path)
            label = x_session_label or storage.sanitize_name(x_filename)

            if not created:
                existing = db.latest_session_for_pcap(conn, pcap_id)
                if existing is not None:
                    # A duplicate upload is still a real sensor->VM flow. Log
                    # it so the reconciler recognises the sensor's own
                    # (frequently re-uploaded, e.g. spool drain / ring
                    # replay) traffic as declared infra telemetry instead of
                    # emitting a false undeclared_infra_flow finding.
                    db.log_ingest_telemetry(
                        conn, sensor["id"], started, time.time(),
                        request.url.hostname or "", request.url.port or 0,
                        size, sha, existing)
                    # If the original session had no notify_email and this
                    # duplicate upload carries one, adopt it - the requester
                    # who typed a real address still gets their mail. The
                    # first-writer-wins rule inside set_session_notify_email
                    # protects against a re-upload with a DIFFERENT address
                    # silently hijacking the delivery.
                    if notify_email:
                        db.set_session_notify_email(conn, existing,
                                                    notify_email)
                    db.touch_sensor(conn, sensor["id"])
                    return JSONResponse(
                        {"session_id": existing, "pcap_id": pcap_id,
                         "duplicate": True}, status_code=200)

            session_id = db.create_session(conn, pcap_id, label,
                                           x_session_kind,
                                           notify_email=notify_email,
                                           judge_panel_override=judge_panel_override)
            db.log_ingest_telemetry(
                conn, sensor["id"], started, time.time(),
                request.url.hostname or "", request.url.port or 0,
                size, sha, session_id)
            db.touch_sensor(conn, sensor["id"])
            return JSONResponse(
                {"session_id": session_id, "pcap_id": pcap_id,
                 "duplicate": False}, status_code=202)
        finally:
            conn.close()

    def _bearer(conn, authorization):
        try:
            return auth.verify_bearer(conn, authorization)
        except auth.AuthError as e:
            raise HTTPException(401, e.reason)

    def _authorize_session(conn, sensor, session):
        """A sensor may read only its own sessions unless it is the admin
        sensor (NETSEC_ADMIN_SENSOR - the dashboard's read-all account).
        Returning 404 (not 403) for a foreign session so the presence of
        a session id owned by another sensor is not confirmed."""
        if session is None:
            raise HTTPException(404, "no such session")
        admin = os.environ.get("NETSEC_ADMIN_SENSOR", "").strip()
        if admin and sensor.get("name") == admin:
            return
        if session.get("sensor_id") != sensor.get("id"):
            raise HTTPException(404, "no such session")

    @app.get("/v1/sessions/{session_id}")
    def get_session(session_id: int, authorization: str = Header(None)):
        conn = _conn()
        try:
            sensor = _bearer(conn, authorization)
            session = db.get_session(conn, session_id)
            _authorize_session(conn, sensor, session)
            return session
        finally:
            conn.close()

    @app.get("/v1/reports/{session_id}.{kind}")
    def get_report(session_id: int, kind: str,
                   authorization: str = Header(None)):
        if kind not in _REPORT_MEDIA:
            raise HTTPException(
                404, "kind must be " + "|".join(_REPORT_MEDIA))
        conn = _conn()
        try:
            sensor = _bearer(conn, authorization)
            session = db.get_session(conn, session_id)
            _authorize_session(conn, sensor, session)
            report = db.get_report(conn, session_id, kind)
        finally:
            conn.close()
        if report is None or not os.path.isfile(report["path"]):
            raise HTTPException(404, "report not generated yet")
        return FileResponse(report["path"],
                            media_type=_REPORT_MEDIA[kind])

    return app


app = create_app()

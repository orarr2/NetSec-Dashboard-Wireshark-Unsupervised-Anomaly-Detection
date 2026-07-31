"""Per-sensor authentication (spec sections 5.1 and 12.2). Stdlib only.

Two credentials per sensor, with different jobs:

- ``hmac_secret`` signs uploads. The signature covers the file's sha256,
  the sensor name and a unix timestamp, so a captured request cannot be
  replayed outside the time window and cannot be re-pointed at another
  file:  HMAC-SHA256(secret, "<sha256>:<sensor>:<timestamp>").
- ``token`` is a bearer credential for read endpoints; only its sha256
  is stored, and lookups compare hashes.

Nothing here raises bare strings at the HTTP layer: every failure is an
AuthError with a stable ``reason`` so the API can log precisely and the
tests can assert precisely.
"""
import hashlib
import hmac
import time

DEFAULT_WINDOW_S = 300


class AuthError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def upload_signature(hmac_secret, file_sha256, sensor_name, timestamp):
    msg = f"{file_sha256}:{sensor_name}:{int(timestamp)}"
    return hmac.new(hmac_secret.encode("utf-8"), msg.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def verify_upload(sensor_row, file_sha256, timestamp, signature,
                  now=None, window_s=DEFAULT_WINDOW_S):
    """Validate an upload's auth headers against the sensor row.
    Raises AuthError(reason) on any failure; returns None on success.

    Order matters: revocation first (a revoked sensor learns nothing
    about window or signature validity), then the replay window, then
    the constant-time signature comparison.
    """
    if sensor_row is None:
        raise AuthError("unknown sensor")
    if sensor_row.get("revoked_at"):
        raise AuthError("sensor revoked")
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        raise AuthError("bad timestamp")
    now = int(time.time()) if now is None else int(now)
    if abs(now - ts) > window_s:
        raise AuthError("timestamp outside window")
    expected = upload_signature(sensor_row["hmac_secret"], file_sha256,
                                sensor_row["name"], ts)
    # compare_digest raises TypeError on a str containing non-ASCII, and
    # the API layer only maps AuthError to 401 - so an emoji in the header
    # would surface as an unhandled 500 and hand an attacker a way to tell
    # malformed input apart from a wrong signature. A signature is hex, so
    # anything outside ASCII is simply wrong.
    sig = signature or ""
    if not sig.isascii():
        raise AuthError("bad signature")
    if not hmac.compare_digest(expected, sig):
        raise AuthError("bad signature")


def verify_bearer(conn, authorization):
    """Resolve an ``Authorization: Bearer <token>`` header to a sensor
    row via hashed lookup. Raises AuthError on any failure."""
    from . import db  # local import keeps auth importable standalone

    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing bearer token")
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise AuthError("missing bearer token")
    sensor = db.get_sensor_by_token_hash(conn, hash_token(token))
    if sensor is None:
        raise AuthError("unknown token")
    if sensor.get("revoked_at"):
        raise AuthError("sensor revoked")
    return sensor

"""Upload a PCAP straight to the VM's ingest API - no GitHub, no size
cap (spec sections 3.2 and 5.1). Stdlib only, streams in 1MB chunks.

    python tools/upload_pcap.py capture.pcapng
    python tools/upload_pcap.py capture.pcapng --kind test --label "nmap run"

Configuration (flags override env):
    NETSEC_INGEST_URL      e.g. http://<vm-tailscale-ip>:8766
    NETSEC_SENSOR_ID       from deploy/create_sensor.py
    NETSEC_SENSOR_SECRET   from deploy/create_sensor.py
    NETSEC_MANIFEST        telemetry manifest path
                           (default ~/.netsec/telemetry.jsonl)

Every completed upload appends one JSON line to the local telemetry
manifest - the sensor-side half of the reconciliation protocol (spec
section 12.2): started_at, ended_at, dst, dst_port, bytes_sent,
file_sha256. Network errors and 5xx retry with 2s/4s/8s/16s backoff;
4xx never retries (the request is wrong, not the network).
"""
import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

CHUNK = 1024 * 1024


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _signature(secret, file_sha256, sensor_id, timestamp):
    # mirror of server/auth.py upload_signature - kept dependency-free
    # so this script can be copied to a sensor without the repo
    import hmac
    msg = f"{file_sha256}:{sensor_id}:{int(timestamp)}"
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _post_stream(url, path, headers, timeout):
    """Stream the file as one POST via http.client (urllib buffers)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(
            u.hostname, u.port or 443, timeout=timeout,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80,
                                          timeout=timeout)
    try:
        conn.putrequest("POST", (u.path or "") + "/v1/pcap")
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(os.path.getsize(path)))
        conn.putheader("Content-Type", "application/octet-stream")
        conn.endheaders()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                conn.send(chunk)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body
    finally:
        conn.close()


def _append_manifest(manifest_path, record):
    os.makedirs(os.path.dirname(os.path.abspath(manifest_path)),
                exist_ok=True)
    with open(manifest_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def upload_file(path, url, sensor, secret, kind="prod", label=None,
                manifest=None, timeout=600.0, retries=4, sleep_fn=time.sleep):
    """Sign and stream one PCAP to the ingest API. Shared by the CLI and
    the capture agent. Returns a dict:
        {"ok": bool, "status": int|None, "session_id": ..., "duplicate":
         bool, "error": str|None}
    On success (and only then) appends a telemetry-manifest line when a
    manifest path is given. Raises nothing - callers branch on ok."""
    digest = sha256_of(path)
    started_at = time.time()
    u = urllib.parse.urlsplit(url)
    delay, attempt = 2.0, 0
    status, body = None, ""
    while True:
        attempt += 1
        ts = int(time.time())
        headers = {
            "X-Sensor-Id": sensor,
            "X-Sha256": digest,
            "X-Timestamp": str(ts),
            "X-Signature": _signature(secret, digest, sensor, ts),
            "X-Session-Kind": kind,
            "X-Filename": os.path.basename(path),
            "User-Agent": "netsec-upload/0.1",
        }
        if label:
            headers["X-Session-Label"] = label
        try:
            status, body = _post_stream(url, path, headers, timeout)
        except OSError as e:
            status, body = None, str(e)
        if status in (200, 202):
            out = json.loads(body)
            if manifest:
                _append_manifest(manifest, {
                    "started_at": round(started_at, 3),
                    "ended_at": round(time.time(), 3),
                    "dst": u.hostname,
                    "dst_port": u.port or (443 if u.scheme == "https"
                                           else 80),
                    "bytes_sent": os.path.getsize(path),
                    "file_sha256": digest, "sensor_id": sensor})
            return {"ok": True, "status": status,
                    "session_id": out.get("session_id"),
                    "duplicate": bool(out.get("duplicate")), "error": None}
        if status is not None and 400 <= status < 500:
            return {"ok": False, "status": status, "session_id": None,
                    "duplicate": False,
                    "error": f"server rejected ({status}): {body}"}
        if attempt > retries:
            return {"ok": False, "status": status, "session_id": None,
                    "duplicate": False,
                    "error": f"failed after {retries} retries "
                             f"({status}): {body}"}
        print(f"  transient failure ({status}): retrying in {delay:.0f}s",
              file=sys.stderr)
        sleep_fn(delay)
        delay *= 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Upload a PCAP to the ingest API (signed, streamed)")
    ap.add_argument("pcap", help=".pcap/.pcapng file to upload")
    ap.add_argument("--url", default=os.environ.get("NETSEC_INGEST_URL"))
    ap.add_argument("--sensor", default=os.environ.get("NETSEC_SENSOR_ID"))
    ap.add_argument("--secret",
                    default=os.environ.get("NETSEC_SENSOR_SECRET"))
    ap.add_argument("--kind", choices=("prod", "test"), default="prod",
                    help="test sessions are excluded from baselines "
                         "(decision IDX-11)")
    ap.add_argument("--label", default=None)
    ap.add_argument("--manifest",
                    default=os.environ.get(
                        "NETSEC_MANIFEST",
                        os.path.expanduser("~/.netsec/telemetry.jsonl")))
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--retries", type=int, default=4)
    args = ap.parse_args(argv)

    if not args.url or not args.sensor or not args.secret:
        print("error: --url/--sensor/--secret (or NETSEC_INGEST_URL / "
              "NETSEC_SENSOR_ID / NETSEC_SENSOR_SECRET) are required",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.pcap):
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 2

    result = upload_file(args.pcap, args.url, args.sensor, args.secret,
                         kind=args.kind, label=args.label,
                         manifest=args.manifest, timeout=args.timeout,
                         retries=args.retries)
    if not result["ok"]:
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    dup = " (duplicate - existing session returned)" if result[
        "duplicate"] else ""
    print(f"session_id={result['session_id']}{dup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

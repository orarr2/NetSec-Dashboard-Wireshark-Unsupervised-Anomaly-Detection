"""Dashboard <-> VM client helpers (stage G, spec section 5.4).

Two functions the notebook wires in so the dashboard becomes a CLIENT of
the analysis VM, keeping the local path as an independent fallback:

- upload_session_via_api(): the HTTP replacement for the scp button.
  Streams the session's source PCAP to the ingest API (signed, no size
  cap). scp stays available as the documented fallback.
- load_session_from_api(): pulls a finished analysis back for remote
  viewing - session metadata plus the stored verdicts.json.

Boundary note (honest): the 52 dashboard charts consume the full raw
S-dict (per-IP counters, timelines, the ip_agg frame). The API persists
the verdict/feature view, not that whole structure, so this returns the
remote-viewing contract. Full chart parity from the API needs the worker
to also persist an S-dict snapshot; that is a documented follow-up and
does not block the local analysis path, which is unchanged.

Stdlib only, so importing it from the notebook adds no dependency.
"""
import json
import os
import sys
import urllib.request


def _tools_on_path():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for p in (root, os.path.join(root, "tools")):
        if p not in sys.path:
            sys.path.insert(0, p)


def upload_session_via_api(pcap_path, url=None, sensor=None, secret=None,
                           kind="prod", label=None, manifest=None):
    """Upload one PCAP to the ingest API. Returns the upload_file result
    dict ({ok, session_id, duplicate, error, status}). Config falls back
    to NETSEC_INGEST_URL / NETSEC_SENSOR_ID / NETSEC_SENSOR_SECRET."""
    _tools_on_path()
    import upload_pcap

    url = url or os.environ.get("NETSEC_INGEST_URL")
    sensor = sensor or os.environ.get("NETSEC_SENSOR_ID")
    secret = secret or os.environ.get("NETSEC_SENSOR_SECRET")
    if not (url and sensor and secret):
        return {"ok": False, "error": "NETSEC_INGEST_URL / NETSEC_SENSOR_ID "
                "/ NETSEC_SENSOR_SECRET not set - use the scp fallback or "
                "configure the ingest API", "session_id": None,
                "duplicate": False, "status": None}
    if not os.path.isfile(pcap_path):
        return {"ok": False, "error": f"no such PCAP: {pcap_path}",
                "session_id": None, "duplicate": False, "status": None}
    return upload_pcap.upload_file(pcap_path, url, sensor, secret, kind=kind,
                                   label=label, manifest=manifest)


def _get(api_url, path, token, timeout=30):
    req = urllib.request.Request(api_url.rstrip("/") + path)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def load_session_from_api(session_id, api_url=None, token=None,
                          get_fn=None):
    """Fetch a finished analysis for remote viewing. Returns
    {"session": {...meta...}, "verdicts": {...verdicts.json...}}.
    Raises RuntimeError with an actionable message on failure.

    get_fn is injectable for tests: get_fn(path) -> parsed JSON."""
    api_url = api_url or os.environ.get("NETSEC_INGEST_URL")
    token = token or os.environ.get("NETSEC_API_TOKEN")
    if not api_url:
        raise RuntimeError("NETSEC_INGEST_URL not set")
    getter = get_fn or (lambda path: _get(api_url, path, token))
    try:
        session = getter(f"/v1/sessions/{session_id}")
    except Exception as e:
        raise RuntimeError(f"could not fetch session {session_id}: {e}")
    if session.get("status") != "done":
        return {"session": session, "verdicts": None,
                "note": f"session status is {session.get('status')!r} - "
                        "no verdicts yet"}
    try:
        verdicts = getter(f"/v1/reports/{session_id}.json")
    except Exception as e:
        verdicts = None
        session["_verdicts_error"] = str(e)
    return {"session": session, "verdicts": verdicts}

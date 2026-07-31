"""server.notify: recipient resolution, SMTP send, n8n fallback chain.

The delivery loop is the last thing between a finished analysis and the
user's inbox, and its own side effects (SMTP round-trip, HTTP webhook)
are exactly what a unit test should not perform. Everything below
injects fakes for the two side-effect boundaries (send_report,
urllib.request.urlopen) and exercises the routing.
"""
import io
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import notify  # noqa: E402


def _paths(tmp_path, md_body="# report\n\nOK\n"):
    md = tmp_path / "verdicts.md"
    md.write_text(md_body, encoding="utf-8")
    js = tmp_path / "verdicts.json"
    js.write_text('{"results": []}', encoding="utf-8")
    return {"md": str(md), "json": str(js)}


class _FakeResponse:
    def __init__(self, code=200, body=b"ok"):
        self.status = code
        self._body = body

    def read(self, n=None):
        return self._body if n is None else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


# ---- resolve_recipient ---------------------------------------------------

def test_recipient_prefers_session_over_env():
    assert notify.resolve_recipient(
        {"notify_email": "sess@example.com"},
        env={"NETSEC_NOTIFY_EMAIL": "env@example.com"}) == "sess@example.com"


def test_recipient_falls_back_to_env():
    assert notify.resolve_recipient(
        {"notify_email": None},
        env={"NETSEC_NOTIFY_EMAIL": " env@example.com "}) == "env@example.com"


def test_recipient_empty_string_is_treated_as_missing():
    assert notify.resolve_recipient(
        {"notify_email": ""},
        env={"NETSEC_NOTIFY_EMAIL": "env@example.com"}) == "env@example.com"


def test_recipient_none_when_neither_set():
    assert notify.resolve_recipient(
        {"notify_email": None}, env={}) is None
    assert notify.resolve_recipient(None, env={}) is None
    assert notify.resolve_recipient("not-a-dict", env={}) is None


# ---- deliver: happy path -------------------------------------------------

def test_deliver_smtp_success_short_circuits_the_chain(tmp_path):
    sent = {}

    def fake_send(to, body, subject=None, attachments=None):
        sent["to"] = to
        sent["subject"] = subject
        sent["body"] = body
        sent["attachments"] = list((attachments or {}).keys())
        return True, f"report sent to {to}"

    def n8n_should_not_be_called(*_a, **_kw):
        raise AssertionError("n8n must not be invoked when SMTP succeeded")

    log = notify.deliver(
        {"id": 42, "label": "capture.pcap",
         "notify_email": "user@example.com"},
        out={"results": [{"verdict": {"verdict": "malicious"}}],
             "stats": {"model": "llama-3.3-70b"}},
        report_paths=_paths(tmp_path),
        env={"N8N_WEBHOOK_URL": "https://n8n.example/hook"},
        send_fn=fake_send,
        n8n_fn=n8n_should_not_be_called)
    assert log == [("smtp", True, "report sent to user@example.com")]
    assert sent["to"] == "user@example.com"
    assert "session 42" in sent["subject"]
    assert "capture.pcap" in sent["subject"]
    assert sent["attachments"] == ["verdicts.json"]


# ---- deliver: SMTP -> n8n fallback ---------------------------------------

def test_deliver_falls_back_to_n8n_when_smtp_fails(tmp_path):
    calls = []

    def fake_send(*a, **kw):
        calls.append(("smtp", a, kw))
        return False, "SMTP authentication failed (535)"

    def fake_n8n(url, payload):
        calls.append(("n8n", url, payload))
        return True, "n8n accepted (200)"

    session = {"id": 7, "label": "arpspoof.pcap",
               "notify_email": "user@example.com",
               "kind": "prod", "sha256": "a" * 64}
    log = notify.deliver(
        session,
        out={"results": [{"verdict": {"verdict": "suspicious"}}],
             "stats": {"provider": "openai_compat",
                       "model": "llama-3.3-70b"}},
        report_paths=_paths(tmp_path, "# panel\n\ndiscussion here"),
        env={"N8N_WEBHOOK_URL": "https://n8n.example/hook"},
        send_fn=fake_send, n8n_fn=fake_n8n)
    modes = [entry[0] for entry in log]
    assert modes == ["smtp", "n8n_fallback"]
    assert log[0][1] is False
    assert log[1][1] is True

    # The webhook payload has to carry enough context for a workflow to
    # actually email the user - address, subject, body, session id.
    payload = calls[1][2]
    assert payload["session_id"] == 7
    assert payload["notify_email"] == "user@example.com"
    assert payload["subject"].startswith("NetSec verdicts - session 7")
    assert "panel" in payload["markdown_body"]
    assert payload["worst_verdict"] == "suspicious"
    assert payload["stats"]["model"] == "llama-3.3-70b"
    # And it must record WHY SMTP fell through, so the workflow can
    # log or surface the reason instead of silently retrying.
    assert "SMTP authentication failed" in payload["smtp_error"]


def test_deliver_smtp_failed_and_no_n8n_configured(tmp_path):
    def fake_send(*a, **kw):
        return False, "connection refused"
    log = notify.deliver(
        {"id": 1, "notify_email": "u@example.com"},
        out={}, report_paths=_paths(tmp_path),
        env={},  # no N8N_WEBHOOK_URL
        send_fn=fake_send)
    modes = [entry[0] for entry in log]
    assert modes == ["smtp", "n8n_skipped"]
    assert log[0][1] is False
    assert log[1][1] is True  # skipped path is not an error


# ---- deliver: no SMTP recipient ------------------------------------------

def test_deliver_n8n_only_when_no_smtp_recipient(tmp_path):
    def n8n(url, payload):
        return True, "n8n accepted (200)"
    log = notify.deliver(
        {"id": 3},  # no notify_email
        out={"results": []},
        report_paths=_paths(tmp_path),
        env={"N8N_WEBHOOK_URL": "https://x/hook"},  # no NETSEC_NOTIFY_EMAIL
        send_fn=None,  # must not be called
        n8n_fn=n8n)
    assert log == [("n8n_only", True, "n8n accepted (200)")]


def test_deliver_noop_when_nothing_configured(tmp_path):
    log = notify.deliver(
        {"id": 1}, out={}, report_paths=_paths(tmp_path), env={})
    assert log == [("noop", True, "no recipient configured")]


# ---- send_via_n8n --------------------------------------------------------

def test_send_via_n8n_success_and_non_2xx():
    ok, msg = notify.send_via_n8n(
        "https://hook", {"a": 1},
        opener=lambda req, timeout=None: _FakeResponse(200, b"queued"))
    assert (ok, msg) == (True, "n8n accepted (200)")

    ok, msg = notify.send_via_n8n(
        "https://hook", {"a": 1},
        opener=lambda req, timeout=None: _FakeResponse(500, b"boom"))
    assert ok is False
    assert "500" in msg and "boom" in msg


def test_send_via_n8n_transport_error_never_raises():
    def broken(_req, timeout=None):
        raise OSError("host down")
    ok, msg = notify.send_via_n8n("https://hook", {"a": 1}, opener=broken)
    assert (ok, "host down" in msg) == (False, True)


def test_send_via_n8n_empty_url_is_a_config_error():
    ok, msg = notify.send_via_n8n("", {})
    assert (ok, msg) == (False, "n8n webhook URL is empty")


def test_send_via_n8n_payload_encoded_as_utf8_json():
    seen = {}

    def opener(req, timeout=None):
        seen["headers"] = dict(req.header_items())
        seen["body"] = req.data
        return _FakeResponse(200, b"ok")

    notify.send_via_n8n(
        "https://hook",
        {"session_id": 1, "note": "hebrew - שלום"},
        opener=opener)
    assert seen["headers"]["Content-type"] == "application/json"
    decoded = json.loads(seen["body"].decode("utf-8"))
    # ensure_ascii is False in json.dumps so the string survives untouched
    # if send_via_n8n starts round-tripping; but even the default is fine
    # (the payload is still valid JSON on the wire).
    assert decoded["session_id"] == 1

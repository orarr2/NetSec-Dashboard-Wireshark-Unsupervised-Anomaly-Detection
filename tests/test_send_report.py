"""Unit tests for llm_judge/send_report.py.

Everything runs against a fake SMTP object injected through
smtp_factory, so there is no network, no mailbox and no credentials.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import send_report as sr  # noqa: E402


GOOD_ENV = {"SMTP_USER": "sender@example.com", "SMTP_PASS": "app-password"}

SAMPLE_MD = """# Judge verdicts - `tcp_syn_scan.pcap`

| | |
|---|---|
| **Model** | `llama3.2` |

## Top verdict

**`192.168.1.10`** - **MALICIOUS** (port_scan, confidence 0.95)

> The deterministic scan rule fired: 1002 of 1007 packets are SYNs.

- Verdict: `benign`, `suspicious`, `malicious`.
- Priority: ensemble rank score.
"""


class FakeSMTP:
    """Minimal stand-in for smtplib.SMTP used as a context manager."""

    def __init__(self, host, port, fail_on=None):
        self.host = host
        self.port = port
        self.fail_on = fail_on
        self.logged_in = None
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, **kw):
        pass

    def login(self, user, password):
        if self.fail_on == "login":
            import smtplib
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.logged_in = (user, password)

    def send_message(self, msg):
        if self.fail_on == "send":
            raise OSError("connection reset")
        self.sent.append(msg)


def factory(**kw):
    """Return (smtp_factory, holder) so a test can inspect the server."""
    holder = {}

    def _make(host, port):
        holder["server"] = FakeSMTP(host, port, **kw)
        return holder["server"]

    return _make, holder


# --------------------------------------------------------------------------
# Address validation
# --------------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    "user@example.com", "first.last+tag@sub.domain.co.uk", " padded@x.io ",
])
def test_valid_addresses(addr):
    assert sr.valid_address(addr)


@pytest.mark.parametrize("addr", [
    "", None, "no-at-sign", "two@@example.com", "user@nodot",
    "a@b.c", "user@example.com\nBcc: attacker@evil.com",
    "user@example.com\r\nSubject: injected", "a b@example.com",
])
def test_invalid_addresses(addr):
    assert not sr.valid_address(addr)


def test_header_injection_is_rejected_before_send():
    """An address carrying CRLF must never reach the SMTP layer."""
    make, holder = factory()
    ok, msg = sr.send_report("a@b.com\nBcc: x@y.com", SAMPLE_MD,
                             env=GOOD_ENV, smtp_factory=make)
    assert not ok
    assert "invalid email address" in msg
    assert "server" not in holder, "no connection should be attempted"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def test_smtp_settings_defaults():
    cfg = sr.smtp_settings(GOOD_ENV)
    assert cfg["host"] == sr.DEFAULT_HOST
    assert cfg["port"] == sr.DEFAULT_PORT
    assert cfg["sender"] == "sender@example.com"  # falls back to SMTP_USER


def test_smtp_settings_overrides():
    cfg = sr.smtp_settings({**GOOD_ENV, "SMTP_HOST": "smtp.mailbox.org",
                            "SMTP_PORT": "465",
                            "SMTP_FROM": "alerts@example.com"})
    assert (cfg["host"], cfg["port"]) == ("smtp.mailbox.org", 465)
    assert cfg["sender"] == "alerts@example.com"


def test_smtp_settings_bad_port_falls_back():
    cfg = sr.smtp_settings({**GOOD_ENV, "SMTP_PORT": "not-a-number"})
    assert cfg["port"] == sr.DEFAULT_PORT


@pytest.mark.parametrize("env", [
    {}, {"SMTP_USER": "a@b.com"}, {"SMTP_PASS": "x"},
])
def test_smtp_settings_missing_credentials(env):
    with pytest.raises(sr.SMTPConfigError):
        sr.smtp_settings(env)


def test_send_report_without_credentials_explains_itself():
    """The 'not configured' path must be distinguishable from a failure."""
    make, holder = factory()
    ok, msg = sr.send_report("user@example.com", SAMPLE_MD, env={},
                             smtp_factory=make)
    assert not ok
    assert "SMTP_USER" in msg and "SMTP_PASS" in msg
    assert "server" not in holder


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------
def test_markdown_renders_expected_structures():
    html = sr.markdown_to_html(SAMPLE_MD)
    assert "<h1" in html            # heading
    assert "<table" in html         # metadata table
    assert "<th " in html           # first table row becomes a header
    assert "<blockquote" in html    # reasoning quote
    assert "<ul" in html and "<li>" in html
    assert "<code>tcp_syn_scan.pcap</code>" in html
    assert "<strong>MALICIOUS</strong>" in html


def test_markdown_escapes_html():
    html = sr.markdown_to_html("A <script>alert(1)</script> & more")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html


def test_build_message_attachments_mime_by_extension():
    """Attachments must be typed by extension so a mail client offers the
    right action (Open in PDF viewer for report.pdf, Open in browser for
    report.html). Before this fix everything was forced to
    application/json, which turned report.pdf into a broken .json file
    in the recipient's inbox."""
    msg = sr.build_message(
        "to@example.com", "subject", "# body", "from@example.com",
        attachments={
            "report.pdf": b"%PDF-1.4\ntest",
            "report.html": "<html><body>hello</body></html>",
            "verdicts.json": '{"x": 1}',
            "whatever.dat": b"\x00\x01\x02",
        })
    by_name = {p.get_filename(): (p.get_content_type(),
                                  p.get_content_maintype())
               for p in msg.iter_attachments()}
    assert by_name["report.pdf"]      == ("application/pdf",  "application")
    assert by_name["report.html"]     == ("text/html",        "text")
    assert by_name["verdicts.json"]   == ("application/json", "application")
    assert by_name["whatever.dat"]    == ("application/octet-stream",
                                          "application")


def test_markdown_handles_empty_input():
    html = sr.markdown_to_html("")
    assert html.startswith("<html>") and html.endswith("</html>")


# --------------------------------------------------------------------------
# Message construction
# --------------------------------------------------------------------------
def test_build_message_is_multipart_with_attachment():
    msg = sr.build_message("to@example.com", "Subject line", SAMPLE_MD,
                           "from@example.com",
                           attachments={"verdicts.json": '{"a": 1}'})
    assert msg["To"] == "to@example.com"
    assert msg["From"] == "from@example.com"
    assert msg["Subject"] == "Subject line"
    types = {p.get_content_type() for p in msg.walk()}
    assert "text/plain" in types and "text/html" in types
    names = [p.get_filename() for p in msg.iter_attachments()
             if p.get_filename()]
    assert "verdicts.json" in names


# --------------------------------------------------------------------------
# Send paths
# --------------------------------------------------------------------------
def test_send_report_happy_path():
    make, holder = factory()
    ok, msg = sr.send_report("user@example.com", SAMPLE_MD, env=GOOD_ENV,
                             smtp_factory=make)
    assert ok, msg
    server = holder["server"]
    assert server.logged_in == ("sender@example.com", "app-password")
    assert len(server.sent) == 1
    assert server.sent[0]["To"] == "user@example.com"


def test_send_report_uses_configured_host_and_port():
    make, holder = factory()
    sr.send_report("user@example.com", SAMPLE_MD,
                   env={**GOOD_ENV, "SMTP_HOST": "smtp.example.net",
                        "SMTP_PORT": "2525"},
                   smtp_factory=make)
    assert (holder["server"].host, holder["server"].port) == (
        "smtp.example.net", 2525)


def test_send_report_reports_auth_failure_with_guidance():
    make, _ = factory(fail_on="login")
    ok, msg = sr.send_report("user@example.com", SAMPLE_MD, env=GOOD_ENV,
                             smtp_factory=make)
    assert not ok
    assert "app password" in msg.lower()


def test_send_report_survives_transport_failure():
    """A dead connection returns False - it must not raise, or a finished
    analysis would be lost to a mail problem."""
    make, _ = factory(fail_on="send")
    ok, msg = sr.send_report("user@example.com", SAMPLE_MD, env=GOOD_ENV,
                             smtp_factory=make)
    assert not ok
    assert "SMTP send failed" in msg


def test_main_cli_sends_and_returns_zero(tmp_path, monkeypatch):
    report = tmp_path / "verdicts.md"
    report.write_text(SAMPLE_MD, encoding="utf-8")
    verdicts = tmp_path / "verdicts.json"
    verdicts.write_text('{"stats": {}}', encoding="utf-8")

    captured = {}

    def fake_send(addr, body, subject=None, attachments=None):
        captured.update(addr=addr, body=body, subject=subject,
                        attachments=attachments)
        return True, f"report sent to {addr}"

    monkeypatch.setattr(sr, "send_report", fake_send)
    rc = sr.main([str(report), "user@example.com", "--subject", "Hi",
                  "--json", str(verdicts)])
    assert rc == 0
    assert captured["addr"] == "user@example.com"
    assert captured["subject"] == "Hi"
    assert "verdicts.json" in captured["attachments"]


def test_main_cli_returns_nonzero_on_failure(tmp_path, monkeypatch):
    report = tmp_path / "verdicts.md"
    report.write_text(SAMPLE_MD, encoding="utf-8")
    monkeypatch.setattr(sr, "send_report",
                        lambda *a, **kw: (False, "nope"))
    assert sr.main([str(report), "user@example.com"]) == 1

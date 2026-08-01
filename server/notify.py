"""Deliver a completed analysis to whoever asked for it, and validate
the recipient at ingest time (see valid_address).

The uploader picks the recipient at submit time (X-Notify-Email header
on the ingest API, --email flag on tools/upload_pcap.py). That address
is stored on the session row; when the worker finishes it calls this
module, which walks a fallback chain:

    1. SMTP  - via llm_judge.send_report (Gmail app-password by default).
       This is the primary delivery: the report is a rendered HTML mail
       that opens directly in any inbox, no dependencies on the VM.

    2. n8n webhook - if N8N_WEBHOOK_URL is set, a JSON payload is POST'd
       so a user-owned workflow (Gmail node with OAuth, Discord, Slack,
       PagerDuty, whatever) can pick the analysis up. Used as a *fallback*
       when SMTP fails (bad app-password, Gmail 5xx, unreachable relay) -
       not as a duplicate delivery. First writer wins.

    3. Nothing - if no recipient and no webhook are configured, we log
       'no recipient configured' and move on. Never raises: a broken
       mailbox must not lose an analysis that already cost minutes of
       compute.

The per-session address wins over the legacy single-recipient
NETSEC_NOTIFY_EMAIL env var. That legacy is intentionally kept: the
solo-operator setup ("everything I upload should hit MY inbox") is a
real use case and the header just makes it optional.
"""
import json
import os
import re
import urllib.request

# Deliberately permissive: this only guards against obvious typos and
# header injection, not against every address RFC 5321 permits. Kept in
# this module (not llm_judge.send_report, which the ingest image does
# NOT copy) so the ingest endpoint can validate X-Notify-Email before
# storing it, without pulling llm_judge in as a runtime dependency.
_ADDR_RE = re.compile(r"^[^@\s,;:<>]+@[^@\s,;:<>]+\.[A-Za-z]{2,}$")


def valid_address(addr):
    """True when `addr` looks like a single deliverable address.

    Newlines are rejected explicitly: an address carrying CR/LF could
    inject extra headers into the outgoing message.
    """
    if not isinstance(addr, str):
        return False
    addr = addr.strip()
    if not addr or "\n" in addr or "\r" in addr:
        return False
    return bool(_ADDR_RE.match(addr))


def resolve_recipient(session, env=None):
    """Pick who gets the mail. Priority:

        session['notify_email']       set by X-Notify-Email at upload time
        NETSEC_NOTIFY_EMAIL env       fallback for the solo-operator setup

    Returns the resolved address (stripped) or None when neither is set.
    """
    env = os.environ if env is None else env
    if isinstance(session, dict):
        per_session = session.get("notify_email")
        if isinstance(per_session, str) and per_session.strip():
            return per_session.strip()
    fallback = (env.get("NETSEC_NOTIFY_EMAIL") or "").strip()
    return fallback or None


def _subject_for(session):
    if not isinstance(session, dict):
        return "NetSec verdicts"
    sid = session.get("id")
    label = session.get("label") or "capture"
    return f"NetSec verdicts - session {sid} ({label})"


def _attachments_for(report_paths):
    """Human-readable report as a single attachment: PDF when the worker
    managed to render one (weasyprint present), HTML otherwise. Returns
    {filename: bytes|str} for llm_judge.send_report to attach.

    Deliberately NOT including verdicts.json - it is the machine-readable
    exchange format, not a report a person opens. Anyone who needs it can
    fetch it from GET /v1/reports/{id}.json with their bearer token."""
    attachments = {}
    if not isinstance(report_paths, dict):
        return attachments
    for kind in ("pdf", "html"):
        path = report_paths.get(kind)
        if not path or not os.path.isfile(path):
            continue
        try:
            mode = "rb" if kind == "pdf" else "r"
            with open(path, mode, **({"encoding": "utf-8"}
                                     if kind != "pdf" else {})) as f:
                attachments[os.path.basename(path)] = f.read()
        except Exception:
            continue
        break  # one human-readable copy is enough; stop at the first
    return attachments


def _webhook_payload(session, out, report_paths, recipient=None,
                     subject=None, markdown_body=None, smtp_error=None):
    """Everything an n8n workflow needs to email a report on its own.

    The full markdown is embedded (n8n's Gmail node can render it) and
    the recipient is echoed so the workflow does not need to guess. Keep
    this stable - existing user workflows depend on the key names.
    """
    stats = {}
    results = []
    worst = None
    if isinstance(out, dict):
        stats = out.get("stats") or {}
        results = out.get("results") or []
        if results:
            worst = ((results[0].get("verdict") or {})
                     .get("verdict"))
    return {
        "session_id": (session or {}).get("id"),
        "label": (session or {}).get("label"),
        "kind": (session or {}).get("kind"),
        "sha256": (session or {}).get("sha256"),
        "notify_email": recipient,
        "subject": subject,
        "markdown_body": markdown_body,
        "smtp_error": smtp_error,
        "stats": {"provider": stats.get("provider"),
                  "model": stats.get("model")},
        "results_count": len(results),
        "worst_verdict": worst,
    }


def send_smtp(recipient, subject, markdown_body, attachments=None,
              send_fn=None):
    """SMTP delivery via llm_judge.send_report. send_fn is a test seam."""
    if send_fn is None:
        from llm_judge.send_report import send_report as _send
        send_fn = _send
    return send_fn(recipient, markdown_body, subject=subject,
                   attachments=attachments)


def send_via_n8n(webhook_url, payload, timeout=15, opener=None):
    """POST JSON to n8n. Returns (ok, message). opener is a test seam."""
    if not webhook_url or not isinstance(webhook_url, str):
        return False, "n8n webhook URL is empty"
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"})
        _opener = opener or urllib.request.urlopen
        with _opener(req, timeout=timeout) as r:
            code = getattr(r, "status", None) or r.getcode()
            body = r.read(300).decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"n8n POST failed: {type(e).__name__}: {e}"
    if 200 <= code < 300:
        return True, f"n8n accepted ({code})"
    return False, f"n8n returned {code}: {body}"


def deliver(session, out, report_paths, env=None, send_fn=None,
            n8n_fn=None):
    """Run the fallback chain and return a log of what happened as a
    list of (mode, ok, message). The caller (worker._notify) formats
    each line to stdout - one log entry per attempted mechanism, so a
    reader can see 'SMTP failed with X, n8n picked it up' at a glance.

    Modes emitted:
        'noop'         no recipient AND no n8n webhook - nothing to try
        'smtp'         primary SMTP attempt (ok or failed)
        'n8n_only'     no SMTP recipient, n8n as the sole channel
        'n8n_fallback' SMTP failed, n8n stepped in
        'n8n_skipped'  SMTP failed, no webhook configured
    """
    env = os.environ if env is None else env
    log = []
    recipient = resolve_recipient(session, env)
    subject = _subject_for(session)
    hook = (env.get("N8N_WEBHOOK_URL") or "").strip()

    # Email body = the executive summary when the worker rendered one
    # (summary.md); the full report rides ONLY as the PDF attachment.
    # Falls back to the full markdown for old sessions that predate the
    # summary file - an email with too much text beats an empty one.
    body_md = None
    rp = report_paths if isinstance(report_paths, dict) else {}
    for key in ("summary", "md"):
        p = rp.get(key)
        if p and os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    body_md = f.read()
                break
            except Exception as e:
                body_md = f"(could not read markdown report: {e})"

    if not recipient:
        # No SMTP recipient - offer n8n as the sole channel, or noop.
        if hook:
            payload = _webhook_payload(session, out, report_paths,
                                       recipient=None, subject=subject,
                                       markdown_body=body_md)
            ok, msg = send_via_n8n(hook, payload) if n8n_fn is None \
                else n8n_fn(hook, payload)
            log.append(("n8n_only", ok, msg))
        else:
            log.append(("noop", True, "no recipient configured"))
        return log

    # Primary: SMTP
    attachments = _attachments_for(report_paths)
    ok, msg = send_smtp(recipient, subject, body_md or "",
                        attachments=attachments, send_fn=send_fn)
    log.append(("smtp", ok, msg))
    if ok:
        return log

    # SMTP failed - try n8n as the fallback channel.
    if not hook:
        log.append(("n8n_skipped", True, "no N8N_WEBHOOK_URL to fall back to"))
        return log
    payload = _webhook_payload(session, out, report_paths,
                               recipient=recipient, subject=subject,
                               markdown_body=body_md, smtp_error=msg)
    ok2, msg2 = send_via_n8n(hook, payload) if n8n_fn is None \
        else n8n_fn(hook, payload)
    log.append(("n8n_fallback", ok2, msg2))
    return log

"""HTML report for a session - the markdown the judge already renders,
wrapped with a provenance footer (spec section 8).

Reuses llm_judge.send_report.markdown_to_html so the emailed report and
the stored one are pixel-identical; the only addition is the metadata
table (file identity, capture window, versions), which is what makes
the stored report auditable years later. It renders at the BOTTOM: the
first thing a reader sees must be the executive summary, not a sha256.
"""
import html as _html


def _row(k, v):
    return (f"<tr><td style='padding:2px 10px 2px 0;color:#57606a'>{k}"
            f"</td><td><code>{_html.escape(str(v))}</code></td></tr>")


def render(session, markdown_body, extra=None):
    """session: the db.get_session() dict; markdown_body: the judge's
    verdicts.md text; extra: optional dict appended to the footer."""
    from llm_judge import send_report

    body = send_report.markdown_to_html(markdown_body)
    meta = {
        "session": session.get("id"),
        "label": session.get("label"),
        "kind": session.get("kind"),
        "pcap sha256": session.get("sha256"),
        "original file": session.get("orig_name"),
        "size (bytes)": session.get("size_bytes"),
        "queued": session.get("queued_at"),
        "prompt version": session.get("prompt_version"),
    }
    meta.update(extra or {})
    rows = "".join(_row(k, v) for k, v in meta.items() if v is not None)
    footer = (
        "<div style='border:1px solid #d0d7de;border-radius:6px;"
        "padding:10px 14px;margin:18px 0 0;background:#f6f8fa'>"
        "<div style='font-weight:600;margin-bottom:6px'>Session "
        "provenance</div>"
        f"<table style='font-size:12px;border-collapse:collapse'>{rows}"
        "</table></div>")
    # markdown_to_html returns a full <html> document; inject the footer
    # right before </body> so the result stays a single valid document.
    marker = body.rfind("</body>")
    if marker == -1:
        return body + footer
    return body[:marker] + footer + body[marker:]

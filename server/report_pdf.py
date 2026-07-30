"""PDF report via WeasyPrint (decision IDX-07). Optional by design:
weasyprint pulls system libraries (pango/cairo) that only the VM needs,
so a missing import degrades to "no PDF this run" - never to a failed
analysis. The HTML report is the same content.

VM setup:  apt-get install -y libpango-1.0-0 libpangocairo-1.0-0
           pip install weasyprint
"""


def render(html_text, out_path):
    """Write the PDF and return out_path, or return None (with a printed
    reason) when weasyprint is unavailable or rendering fails."""
    try:
        from weasyprint import HTML
    except Exception as e:
        print(f"[report_pdf] weasyprint unavailable - skipping PDF: {e}",
              flush=True)
        return None
    try:
        HTML(string=html_text).write_pdf(out_path)
        return out_path
    except Exception as e:
        print(f"[report_pdf] PDF rendering failed - skipping: {e}",
              flush=True)
        return None

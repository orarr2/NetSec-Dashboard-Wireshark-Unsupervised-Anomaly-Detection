"""Render the S1 vs S2 comparison report (v2, 2026-08-02).

Turns the pair-level verdict + v2 pair blob into two markdown outputs:

  summary_md  - the mail body. Posture, headline, captures at a glance,
                what changed, notable flips, one action.
  full_md     - the PDF/HTML source. Adds the full flip table (with
                device identity), the annotated new/gone lists, and the
                panel audit with classified failure causes.

Both are rendered from the same inputs so nothing said in the mail
disagrees with the attached PDF. Everything degrades gracefully when
the per-session verdicts.json predates report v2 (no capture context,
no evidence projections): those cells render "-" instead of lying.
"""


def _posture_word(delta):
    return {"escalated": "ESCALATED",
            "de-escalated": "DE-ESCALATED",
            "stable": "STABLE",
            "mixed": "MIXED"}.get(delta, str(delta or "unknown").upper())


def _fmt_counts(c):
    c = c or {}
    return (f"{c.get('malicious', 0)} malicious · "
            f"{c.get('suspicious', 0)} suspicious · "
            f"{c.get('benign', 0)} benign")


def _fmt_when(ts):
    """'2026-08-01 14:03:22' -> 'Fri 01 Aug 2026, 14:03'. Falls back to
    the raw string when unparseable, '-' when absent."""
    if not ts:
        return "-"
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(str(ts).replace(" ", "T"))
        return dt.strftime("%a %d %b %Y, %H:%M")
    except Exception:
        return str(ts)


def _fmt_gap(seconds):
    """3600 -> '1h 0m'; 90000 -> '1d 1h'. None -> None."""
    if not isinstance(seconds, (int, float)):
        return None
    s = abs(int(seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _fmt_duration(seconds):
    if not isinstance(seconds, (int, float)):
        return "-"
    s = int(seconds)
    if s >= 3600:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    if s >= 60:
        return f"{s // 60}m {s % 60}s"
    return f"{s}s"


def _failure_causes(examples):
    """Classified failure causes for the panel audit - reuse the single-
    session classifier so 'daily quota' reads the same in both reports.
    Falls back to a one-line trim if llm_judge is not importable."""
    try:
        from llm_judge.judge_cli import _failure_causes as _fc
        return _fc(examples)
    except Exception:
        first = str(examples[0]) if examples else ""
        return [first[:60]] if first else []


def _capture_table(blob, s1_label, s2_label):
    """Side-by-side capture metadata table. Returns [] when NEITHER
    session carries capture context (both predate report v2)."""
    cap = blob.get("capture") or {}
    c1, c2 = cap.get("s1"), cap.get("s2")
    if not c1 and not c2:
        return []

    def _cell(c, key, fmt=None):
        if not c or c.get(key) is None:
            return "-"
        return fmt(c[key]) if fmt else str(c[key])

    def _pkts(v):
        return f"{int(v):,}"

    def _ips(c):
        if not c or c.get("total_ips") is None:
            return "-"
        s = str(c["total_ips"])
        if c.get("local_ips") is not None:
            s += f" ({c['local_ips']} local)"
        return s

    def _protos(c):
        p = (c or {}).get("top_protocols") or []
        return ", ".join(str(x) for x in p[:3]) or "-"

    lines = [
        "## Captures at a glance",
        "",
        f"| | S1 ({s1_label}) | S2 ({s2_label}) |",
        "|---|---|---|",
        f"| Recorded | {_fmt_when((c1 or {}).get('recorded_start'))} "
        f"| {_fmt_when((c2 or {}).get('recorded_start'))} |",
        f"| Duration | {_cell(c1, 'duration_s', _fmt_duration)} "
        f"| {_cell(c2, 'duration_s', _fmt_duration)} |",
        f"| Packets | {_cell(c1, 'n_packets', _pkts)} "
        f"| {_cell(c2, 'n_packets', _pkts)} |",
        f"| IPs seen | {_ips(c1)} | {_ips(c2)} |",
        f"| Top protocols | {_protos(c1)} | {_protos(c2)} |",
        f"| Source file | {_cell(c1, 'file')} | {_cell(c2, 'file')} |",
    ]
    if (c1 or {}).get("sensor") or (c2 or {}).get("sensor"):
        lines.append(f"| Sensor | {_cell(c1, 'sensor')} "
                     f"| {_cell(c2, 'sensor')} |")
    if (c1 or {}).get("cleared_ips") or (c2 or {}).get("cleared_ips"):
        lines.append(f"| Analyzed clean (not flagged) | "
                     f"{_cell(c1, 'cleared_ips')} "
                     f"| {_cell(c2, 'cleared_ips')} |")
    lines.append("")
    gap = _fmt_gap(cap.get("gap_seconds"))
    if gap:
        direction = ("after" if (cap.get("gap_seconds") or 0) >= 0
                     else "BEFORE")
        lines += [f"_S2 was recorded {gap} {direction} S1._", ""]
    if not c1 or not c2:
        missing = s1_label if not c1 else s2_label
        lines += [f"_No capture metadata for {missing} - that session "
                  f"was analyzed before metadata persistence existed; "
                  f"re-run it to fill this column._", ""]
    return lines


def _change_table(blob):
    """The story of the pair in a handful of rows: which verdicts moved
    where, what is new, what is gone, what held still."""
    flow = blob.get("category_flow") or {}
    new_rows = blob.get("unique_s2_detail")
    gone_rows = blob.get("unique_s1_detail")
    n_new = (len(new_rows) if new_rows is not None
             else len(blob.get("unique_ips_s2_only") or []))
    n_gone = (len(gone_rows) if gone_rows is not None
              else len(blob.get("unique_ips_s1_only") or []))
    unchanged = blob.get("unchanged_verdicts")
    if not flow and not n_new and not n_gone and unchanged is None:
        return []
    lines = ["## What changed", "",
             "| Change | IPs |", "|---|--:|"]
    sev = {"malicious": 0, "suspicious": 1, "benign": 2}

    def _flow_key(item):
        frm, to = item[0].split(" -> ")
        return (sev.get(to, 3), sev.get(frm, 3))

    for key, n in sorted(flow.items(), key=_flow_key):
        frm, to = key.split(" -> ")
        lines.append(f"| {frm} → **{to}** | {n} |")
    if n_new:
        bad_new = len(blob.get("new_non_benign_s2") or [])
        label = "New in S2"
        if bad_new:
            label += f" (**{bad_new} non-benign**)"
        lines.append(f"| {label} | {n_new} |")
    if n_gone:
        lines.append(f"| Gone after S1 | {n_gone} |")
    if unchanged is not None:
        lines.append(f"| Same verdict both sides | {unchanged} |")
    lines.append("")
    return lines


def _ip_cell(row):
    """'`ip`' plus the device one-liner when the evidence had one."""
    dev = row.get("device")
    return f"`{row['ip']}`" + (f" ({dev})" if dev else "")


def _annotated_unique_table(rows, side_label, fallback_ips):
    """Annotated new/gone table; falls back to the bare-IP line when the
    blob predates v2 (no *_detail lists)."""
    lines = []
    if rows is None:
        ips = fallback_ips or []
        lines.append(", ".join(f"`{ip}`" for ip in ips) if ips
                     else "_none_")
        lines.append("")
        return lines
    if not rows:
        return ["_none_", ""]
    lines += ["| IP | Device | Verdict | Category | Conf |",
              "|---|---|---|---|--:|"]
    for r in rows:
        conf = r.get("confidence")
        conf_s = f"{float(conf):.2f}" if conf is not None else "-"
        verdict = r.get("verdict") or "-"
        v_cell = f"**{verdict}**" if verdict in ("malicious",
                                                 "suspicious") else verdict
        lines.append(f"| `{r['ip']}` | {r.get('device') or '-'} "
                     f"| {v_cell} | {r.get('category') or '-'} "
                     f"| {conf_s} |")
    lines.append("")
    return lines


def _panel_lines(pair):
    """Panel participation for the exec summary: who answered, and a
    loud warning when the verdict rests on a single judge."""
    answered = pair.get("models_answered") or []
    total = pair.get("models_total") or len(answered)
    short = [m.split("/")[-1] for m in answered]
    lines = []
    if not answered:
        lines.append("**Panel: 0/%d answered** - the counts below are "
                     "real (from the two per-session verdict files) but "
                     "the posture/headline are the degraded fallback." %
                     total)
    elif len(answered) == 1:
        lines.append(f"⚠ **Single-judge verdict**: only `{short[0]}` "
                     f"answered ({len(answered)}/{total}); the other "
                     f"judges failed - treat the confidence accordingly. "
                     f"Causes in the panel audit.")
    else:
        lines.append(f"**Panel**: {len(answered)}/{total} answered "
                     f"({', '.join(f'`{s}`' for s in short)}).")
    return lines


def _panel_audit_table(pair):
    lines = ["| Judge | Answered | Latency | Issue |",
             "|---|:-:|---:|---|"]
    for model, row in (pair.get("panel_report") or {}).items():
        ok = "✅" if row.get("answered") else "⚠"
        lat = f"{row.get('latency_ms', 0)} ms"
        if row.get("answered"):
            issue = "-"
        else:
            causes = _failure_causes([row.get("error") or ""])
            issue = ", ".join(causes) if causes else "failed"
        lines.append(f"| `{model.split('/')[-1]}` | {ok} | {lat} "
                     f"| {issue} |")
    return lines


def render(job, s1_session, s2_session, pair):
    """Return (summary_md, full_md). Both are self-contained markdown."""
    verdict = pair.get("verdict") or {}
    blob = pair.get("pair_blob") or {}
    posture = _posture_word(verdict.get("posture_delta"))
    headline = (verdict.get("headline")
                or "The panel produced no headline.").strip()
    reasoning = (verdict.get("reasoning") or "").strip()
    action = (verdict.get("recommended_action") or "monitor").strip()
    conf = float(verdict.get("confidence") or 0)

    s1_label = s1_session.get("label") or f"S{s1_session.get('id')}"
    s2_label = s2_session.get("label") or f"S{s2_session.get('id')}"
    s1_totals = (blob.get("counts") or {}).get("s1") or {}
    s2_totals = (blob.get("counts") or {}).get("s2") or {}
    flips = verdict.get("notable_flips") or []
    all_flips = blob.get("verdict_flips") or []
    flip_total = int(blob.get("flip_count_total") or len(all_flips))
    flip_dev = {f.get("ip"): f.get("device") for f in all_flips}

    # ---------- summary (mail body) ----------------------------------------
    s = []
    s.append(f"# Comparison report - `{s1_label}` vs `{s2_label}`")
    s.append("")
    s.append("## Executive summary")
    s.append("")
    s.append(f"**Posture: {posture}** · confidence {conf:.2f} · "
             f"**action: {action}**.")
    s.append("")
    s.append(f"**Headline:** {headline}")
    s.append("")
    if reasoning:
        s.append(f"> {reasoning}")
        s.append("")
    s.extend(_panel_lines(pair))
    s.append("")
    s.extend(_capture_table(blob, s1_label, s2_label))
    s.append(f"**S1 ({s1_label})**: {_fmt_counts(s1_totals)} · "
             f"{blob.get('totals', {}).get('s1', 0)} judged candidates.")
    s.append(f"**S2 ({s2_label})**: {_fmt_counts(s2_totals)} · "
             f"{blob.get('totals', {}).get('s2', 0)} judged candidates.")
    s.append("")
    s.extend(_change_table(blob))
    if flips:
        s.append("**Notable flips highlighted by the panel:**")
        for f in flips[:5]:
            dev = flip_dev.get(f.get("ip"))
            dev_s = f" ({dev})" if dev else ""
            why = f.get("why")
            tail = f" - {why}" if why else ""
            s.append(f"- `{f['ip']}`{dev_s} : "
                     f"**{f['from']}** → **{f['to']}**{tail}")
        s.append("")
    bad_new = blob.get("new_non_benign_s2") or []
    if bad_new:
        s.append("**New non-benign IPs in S2 (not present in S1):**")
        for r in bad_new[:5]:
            conf_r = r.get("confidence")
            conf_rs = (f", confidence {float(conf_r):.2f}"
                       if conf_r is not None else "")
            s.append(f"- {_ip_cell(r)} : **{r.get('verdict')}** "
                     f"({r.get('category') or '-'}{conf_rs})")
        s.append("")
    s.append("---")
    s.append("")
    s.append("The full comparison - every flip, the new/gone lists with "
             "verdicts, and the panel audit - is attached as PDF.")
    summary_md = "\n".join(s) + "\n"

    # ---------- full report (PDF / HTML source) ----------------------------
    f = []
    f.extend(s[:-3])  # everything above the '---' mail footer

    # Flip table (full - up to 20, as the pair blob already caps to 20)
    f.append("## All verdict flips (S1 → S2)")
    f.append("")
    if all_flips:
        f.append("| IP | Device | From | Conf | To | Conf | S2 category |")
        f.append("|---|---|---|--:|---|--:|---|")
        for row in all_flips:
            fc = row.get("from_confidence")
            tc = row.get("to_confidence")
            fc_s = f"{float(fc):.2f}" if fc is not None else "-"
            tc_s = f"{float(tc):.2f}" if tc is not None else "-"
            to_v = row["to"]
            to_cell = f"**{to_v}**" if to_v in ("malicious",
                                                "suspicious") else to_v
            f.append(f"| `{row['ip']}` | {row.get('device') or '-'} "
                     f"| {row['from']} | {fc_s} | {to_cell} | {tc_s} | "
                     f"{row.get('s2_category') or '-'} |")
        f.append("")
        if flip_total > len(all_flips):
            f.append(f"_{flip_total - len(all_flips)} more flip(s) in "
                     f"`verdict.json`._")
            f.append("")
    else:
        f.append("*No IPs flipped their verdict between the two "
                 "sessions.*")
        f.append("")

    # New / gone - annotated with verdicts and devices
    f.append("## IPs unique to one side")
    f.append("")
    new_rows = blob.get("unique_s2_detail")
    gone_rows = blob.get("unique_s1_detail")
    n_new = (len(new_rows) if new_rows is not None
             else len(blob.get("unique_ips_s2_only") or []))
    n_gone = (len(gone_rows) if gone_rows is not None
              else len(blob.get("unique_ips_s1_only") or []))
    f.append(f"**New in S2 ({s2_label})** ({n_new}, first 20, "
             f"non-benign first):")
    f.append("")
    f.extend(_annotated_unique_table(new_rows, s2_label,
                                     blob.get("unique_ips_s2_only")))
    f.append(f"**Gone after S1 ({s1_label})** ({n_gone}, first 20, "
             f"non-benign first):")
    f.append("")
    f.extend(_annotated_unique_table(gone_rows, s1_label,
                                     blob.get("unique_ips_s1_only")))

    # Top non-benign on each side (context for a reader who did NOT
    # read the per-session reports)
    f.append("## Top non-benign IPs on each side")
    f.append("")
    for label, key in ((s1_label, "top_non_benign_s1"),
                       (s2_label, "top_non_benign_s2")):
        rows = blob.get(key) or []
        f.append(f"**{label}:**")
        if rows:
            for r in rows:
                conf_r = float(r.get("confidence") or 0)
                f.append(f"- {_ip_cell(r)} : **{r['verdict']}** "
                         f"({r.get('category') or '-'}, "
                         f"confidence {conf_r:.2f})")
        else:
            f.append("- _none_")
        f.append("")

    # Panel audit
    f.append("## Panel audit")
    f.append("")
    f.extend(_panel_audit_table(pair))
    f.append("")

    # Metadata footer
    agree = (verdict.get("panel_agreement") or {})
    f.append("## Run metadata")
    f.append("")
    f.append(f"- compare_job: {job.get('id')}")
    f.append(f"- S1 session: {s1_session.get('id')} "
             f"({s1_session.get('label')})")
    f.append(f"- S2 session: {s2_session.get('id')} "
             f"({s2_session.get('label')})")
    f.append(f"- prompt version: `{pair.get('prompt_version')}`")
    if agree:
        votes = agree.get("votes") or {}
        votes_s = ", ".join(f"{k} x{v}" for k, v in votes.items())
        f.append(f"- panel agreement: `{agree.get('picked')}`"
                 + (f" ({votes_s})" if votes_s else ""))
    f.append("")
    full_md = "\n".join(f) + "\n"
    return summary_md, full_md

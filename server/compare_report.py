"""Render the S1 vs S2 comparison report.

Turns the pair-level verdict + raw pair blob into two markdown outputs:

  summary_md  - the mail body. What changed, why, one action.
  full_md     - the PDF/HTML source. Adds the flip table, per-side
                verdict counts, the IPs unique to each side, and the
                panel participation audit.

Both are rendered from the same inputs so nothing said in the mail
disagrees with the attached PDF.
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


def _panel_audit_table(pair):
    lines = ["| Judge | Answered | Latency | Issue |",
             "|---|:-:|---:|---|"]
    for model, row in (pair.get("panel_report") or {}).items():
        ok = "✅" if row.get("answered") else "⚠"
        lat = f"{row.get('latency_ms', 0)} ms"
        err = row.get("error") or "-"
        lines.append(f"| `{model.split('/')[-1]}` | {ok} | {lat} | {err} |")
    return "\n".join(lines)


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
    flip_total = int(blob.get("flip_count_total") or len(flips))
    only_s1 = blob.get("unique_ips_s1_only") or []
    only_s2 = blob.get("unique_ips_s2_only") or []
    answered = pair.get("models_answered") or []
    total_models = pair.get("models_total") or len(answered)

    # ---------- summary (mail body) ----------------------------------------
    s = []
    s.append(f"# Comparison report - `{s1_label}` vs `{s2_label}`")
    s.append("")
    s.append("## Executive summary")
    s.append("")
    s.append(f"**Posture: {posture}** · confidence {conf:.2f} · "
             f"panel {len(answered)}/{total_models} answered.")
    s.append("")
    s.append(f"**Headline:** {headline}")
    s.append("")
    if reasoning:
        s.append(f"> {reasoning}")
        s.append("")
    s.append(f"**Action: {action}.**")
    s.append("")
    s.append(f"**S1 ({s1_label})**: {_fmt_counts(s1_totals)} · "
             f"{blob.get('totals', {}).get('s1', 0)} judged candidates.")
    s.append(f"**S2 ({s2_label})**: {_fmt_counts(s2_totals)} · "
             f"{blob.get('totals', {}).get('s2', 0)} judged candidates.")
    s.append(f"**{flip_total} verdict flip(s)** between the two sessions.")
    s.append("")
    if flips:
        s.append("**Notable flips highlighted by the panel:**")
        for f in flips[:5]:
            why = f.get("why")
            tail = f" - {why}" if why else ""
            s.append(f"- `{f['ip']}` : "
                     f"**{f['from']}** → **{f['to']}**{tail}")
        s.append("")
    if not answered:
        s.append("_Every panel judge failed on this pair - the counts "
                 "above are still real (they come from the two per-"
                 "session verdict files, not the panel), but the "
                 "headline / reasoning / action are the built-in "
                 "degraded fallback. Check the panel table in the "
                 "attached PDF for provider errors._")
        s.append("")
    s.append("---")
    s.append("")
    s.append("The full comparison - every flip, IPs unique to each "
             "side, and the panel audit - is attached as PDF.")
    summary_md = "\n".join(s) + "\n"

    # ---------- full report (PDF / HTML source) ----------------------------
    f = []
    f.append(f"# Comparison report - `{s1_label}` vs `{s2_label}`")
    f.append("")
    f.extend(s[1:-4])  # reuse the executive summary block
    f.append("")

    # Flip table (full - up to 20, as the pair blob already caps to 20)
    f.append("## All verdict flips (S1 → S2)")
    f.append("")
    all_flips = blob.get("verdict_flips") or []
    if all_flips:
        f.append("| IP | From | Conf | To | Conf | S2 category |")
        f.append("|---|---|--:|---|--:|---|")
        for row in all_flips:
            fc = row.get("from_confidence")
            tc = row.get("to_confidence")
            fc_s = f"{float(fc):.2f}" if fc is not None else "-"
            tc_s = f"{float(tc):.2f}" if tc is not None else "-"
            f.append(f"| `{row['ip']}` | {row['from']} | {fc_s} | "
                     f"{row['to']} | {tc_s} | "
                     f"{row.get('s2_category') or '-'} |")
        f.append("")
    else:
        f.append("*No IPs flipped their verdict between the two "
                 "sessions.*")
        f.append("")

    # Unique-to-each-side
    f.append("## IPs unique to one side")
    f.append("")
    f.append(f"**Only in S1 ({s1_label})** ({len(only_s1)}, "
             f"first 20 shown):")
    f.append("")
    if only_s1:
        f.append(", ".join(f"`{ip}`" for ip in only_s1))
    else:
        f.append("_none_")
    f.append("")
    f.append(f"**Only in S2 ({s2_label})** ({len(only_s2)}, "
             f"first 20 shown):")
    f.append("")
    if only_s2:
        f.append(", ".join(f"`{ip}`" for ip in only_s2))
    else:
        f.append("_none_")
    f.append("")

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
                f.append(f"- `{r['ip']}` : **{r['verdict']}** "
                         f"({r.get('category') or '-'}, "
                         f"confidence {float(r.get('confidence') or 0):.2f})")
        else:
            f.append("- _none_")
        f.append("")

    # Panel audit
    f.append("## Panel audit")
    f.append("")
    f.append(_panel_audit_table(pair))
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
        f.append(f"- panel agreement: picked=`{agree.get('picked')}` "
                 f"votes={agree.get('votes')}")
    f.append("")
    full_md = "\n".join(f) + "\n"
    return summary_md, full_md

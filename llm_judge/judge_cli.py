"""Headless CLI wrapper around the LLM-as-Judge (no Jupyter needed).

Runs the exact detection pipeline of the dashboard on a single PCAP,
judges every flagged candidate through the configured provider (see the
LLM_JUDGE_* env vars in llm_judge/judge_config.py), and writes:

- verdicts.json  : machine-readable batch (stats + results + drops + capped)
- verdicts.md    : GitHub-Issue-friendly report with pipeline stats + verdicts

Provider is picked via env vars only; no key is read from argv or written
back to disk. Designed to be the entry point of the GitHub Actions
workflow (.github/workflows/analyze-pcap.yml), but works fine locally too.

usage:
    python llm_judge/judge_cli.py path/to.pcap --output verdicts.json \\
        --markdown verdicts.md [--label S1]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, os.path.join(_ROOT, "attack_tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from llm_judge import judge_config, judge_core                  # noqa: E402
from llm_judge import llm_clients                                   # noqa: E402
from llm_judge.llm_clients import make_client, make_panel_clients  # noqa: E402


def _commentary_provider(client):
    """Provider-name string suitable for make_client(provider=...), derived
    from the actual client instance rather than a stringly-typed hint.

    Fixes a real defect: a panel entry like 'ollama:llama3.2' becomes an
    OllamaClient with no provider_name attribute, so falling back to
    judge_config.LLM_JUDGE_PROVIDER (default 'claude') would build a
    ClaudeClient with the wrong model id for the commentary call. That
    call would then fail, the exception would be swallowed, and the
    report would carry '(Analyst commentary unavailable: ...)' - the
    least-verified text in the pipeline going out over email and Issue.

    Endpoint-profile clients keep their provider_name; every other client
    is classified by its class."""
    name = getattr(client, "provider_name", None)
    if name:
        return name
    if isinstance(client, llm_clients.ClaudeClient):
        return "claude"
    if isinstance(client, llm_clients.OllamaClient):
        return "ollama"
    if isinstance(client, llm_clients.OpenAICompatClient):
        return "openai_compat"
    # A custom client not in the shipped set - honor the configured default.
    return judge_config.LLM_JUDGE_PROVIDER


# --------------------------------------------------------------------------
# Context extraction: turn the raw S / findings dicts into a compact,
# JSON-serializable summary the renderer (and tests) can use without
# touching pandas or the pipeline internals.
# --------------------------------------------------------------------------
def _fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts is not None else ""


def build_context(S, findings, assembled):
    """Extract renderer-ready facts from the pipeline output."""
    ip_agg = S["ip_agg"]
    duration = (S["t1"] - S["t0"]).total_seconds()

    cols = getattr(ip_agg, "columns", [])
    has_ml = "anomaly" in cols
    has_dbscan = "cluster" in cols

    if_anom_count = int(ip_agg["anomaly"].sum()) if has_ml else 0
    dbscan_noise = int((ip_agg["cluster"] == -1).sum()) if has_dbscan else 0
    dbscan_clusters = (len(set(ip_agg["cluster"][ip_agg["cluster"] != -1]))
                       if has_dbscan else 0)

    flagged_ip_ids = {c["candidate_id"] for c in assembled["candidates"]
                      if c["kind"] == "ip"}
    capped_set = set(assembled["capped"])
    all_ips = list(ip_agg.index)
    not_flagged = []
    for ip in all_ips:
        if ip in flagged_ip_ids or ip in capped_set:
            continue
        row = ip_agg.loc[ip]
        not_flagged.append({
            "ip": ip,
            "packets": int(row["count"]),
            "iso_score": round(float(row["iso_score"]), 3) if has_ml
                         else None,
            "cluster": int(row["cluster"]) if has_dbscan else None,
        })
    not_flagged.sort(key=lambda x: -x["packets"])

    scan_alerts = findings.get("scan_alerts") or []
    scan_summary = []
    for a in scan_alerts[:5]:
        scan_summary.append(f"{a['type']} from `{a['src']}` "
                            f"({a['count']} pkts, ratio {a['ratio']})")

    # Local-vs-external counts help a reader place the capture on a
    # network map at a glance: "148 IPs (112 local)" reads very
    # differently from "148 IPs (5 local, 143 external)".
    _ips_all = set(S.get("ips_src") or [])
    _ips_dst = set(S.get("ips_dst") or [])
    all_ips_set = _ips_all | _ips_dst
    local_ips = 0
    for ip in all_ips_set:
        s = str(ip)
        if (s.startswith(("10.", "192.168.", "127.", "169.254.",
                          "fe80:", "fc", "fd"))
                or any(s.startswith(f"172.{i}.")
                       for i in range(16, 32))):
            local_ips += 1

    return {
        "n_packets": int(S["n_pkts"]),
        "duration_s": round(duration, 1),
        "time_range": [_fmt_ts(S["t0"]), _fmt_ts(S["t1"])],
        "total_ips": len(S["ips_src"]),
        "local_ips_count": local_ips,
        "external_ips_count": max(0, len(all_ips_set) - local_ips),
        "total_macs": len(S["macs"]),
        "original_filename": S.get("_source_pcap_name")
                             or S.get("_source_pcap"),
        "sensor_name": S.get("_source_sensor"),
        "top_protocols": dict(S["protocols"].most_common(5)),
        "ml": {
            "isolation_forest_anomalies": if_anom_count,
            "dbscan_noise": dbscan_noise,
            "dbscan_clusters": dbscan_clusters,
            "dbscan_meaningful": dbscan_clusters >= 1,
        },
        "rules": {
            "scan_alerts": len(scan_alerts),
            "scan_alerts_summary": scan_summary,
            "flood_alerts": len(findings.get("flood_alerts") or []),
            "amp_alerts": len(findings.get("amp_alerts") or []),
            "arp_spoofing_ips": len(findings.get("arp_spoofing_ips") or {}),
            "dns_nxdomain": int(findings.get("dns_nxdomain") or 0),
            "dns_long_queries": len(findings.get("dns_long_queries") or []),
        },
        "flagged_ip_ids": sorted(flagged_ip_ids),
        "not_flagged_ips": not_flagged,
        "capped_ips": list(assembled["capped"]),
        # Q1: per-capped-IP stats so the report can triage the tail
        # without a re-run. Capped candidates are statistical-only
        # (rule-triggered ones always survive the cap), so iso_score +
        # volume is the whole picture an analyst needs.
        "capped_details": [
            {"ip": ip,
             "packets": int(ip_agg.loc[ip, "count"]) if ip in ip_agg.index else 0,
             "iso_score": round(float(ip_agg.loc[ip, "iso_score"]), 3)
                          if (has_ml and ip in ip_agg.index) else None,
             "unique_dsts": int(ip_agg.loc[ip, "unique_dsts"]) if ip in ip_agg.index else 0}
            for ip in assembled["capped"]],
    }


# --------------------------------------------------------------------------
# Markdown renderer. Sections, in order (report v2, 2026-08-02):
#   1. Executive summary (same block the email body shows)
#   2. All candidates - ONE consolidated table
#   3. Evidence per finding (device, traffic numbers, triggers, history)
#   4. Appendix: pipeline stats, panel votes (all candidates, named
#      judges), panel health, disputes, dropped/capped, legend, metadata
#
# The report exists to be read once and acted on. Anything a reader would
# skip on the second capture belongs in verdicts.json, not in the email.
# --------------------------------------------------------------------------


def _first_sentence(text, max_chars=160):
    """First sentence of `text`, capped at max_chars. Ends with '.' if
    a period was found, ' ...' if the cap truncated a longer sentence.
    Empty input -> empty string. Used to compact LLM prose (reasoning,
    debate rebuttals, analyst commentary) for the email report - the
    full text stays in verdicts.json."""
    if not isinstance(text, str):
        return ""
    s = text.strip()
    if not s:
        return ""
    # Split at first sentence boundary. Look for '. ' (period + space),
    # '? ' or '! '; also stop at a newline since these are single-para
    # LLM outputs and a newline is effectively a paragraph break.
    import re as _re
    m = _re.search(r"[.!?](?:\s|$)|\n", s)
    if m:
        s = s[:m.end()].rstrip()
    if len(s) > max_chars:
        s = s[:max_chars - 4].rstrip() + " ..."
    elif not s.endswith((".", "!", "?", "...")):
        s += "."
    return s


_TRIGGER_NAMES = {"isolation_forest": "IsolationForest",
                  "dbscan_noise": "DBSCAN noise",
                  "scan_rule": "scan rule",
                  "amp_rule": "DNS-amp rule",
                  "arp_rule": "ARP rule",
                  "flood_rule": "flood rule",
                  "lstm": "LSTM"}


def _fmt_bytes(n):
    """1234567 -> '1.2 MB'. None stays None (unknown, not zero)."""
    if not isinstance(n, (int, float)):
        return None
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _evidence_short(r):
    """One italic sub-line under a Key finding: the handful of concrete
    numbers behind the verdict, so the email reader never has to take
    'port_scan' on faith. Empty string when the result predates the
    evidence projection (old verdicts.json)."""
    ev = r.get("evidence") or {}
    if not ev:
        return ""
    bits = []
    dev = ev.get("device") or {}
    name = " ".join(str(b) for b in (dev.get("vendor"),
                                     dev.get("hostname")) if b)
    if name:
        bits.append(name)
    if ev.get("packets") is not None:
        s = f"{ev['packets']:,} pkts"
        if ev.get("unique_dsts"):
            s += f" to {ev['unique_dsts']} dsts"
        bits.append(s)
    ports = ev.get("top_dst_ports") or []
    if ports:
        bits.append("ports " + ", ".join(p["port"] for p in ports))
    if ev.get("iso_score") is not None:
        bits.append(f"iso {ev['iso_score']}")
    trig = ev.get("trigger_reasons") or []
    if trig:
        bits.append("via " + " + ".join(_TRIGGER_NAMES.get(t, t)
                                        for t in trig))
    hist = ev.get("history") or {}
    if hist.get("seen_before"):
        prior = hist.get("prior_verdict_summary")
        bits.append(f"seen before ({prior})" if prior else "seen before")
    elif hist.get("seen_before") is False:
        bits.append("first appearance")
    return " · ".join(bits)


def _evidence_block(r):
    """3-5 markdown bullets for the full report's Evidence-per-finding
    section: device identity, traffic numbers, detector signals and
    which input fields the judges actually cited."""
    ev = r.get("evidence") or {}
    if not ev:
        return []
    v = r.get("verdict") or {}
    lines = []

    dev = ev.get("device") or {}
    name_bits = [dev.get("vendor"), dev.get("hostname")]
    cat = dev.get("category")
    if cat and cat != "unknown":
        name_bits.append(f"({cat})")
    name = " ".join(str(b) for b in name_bits if b) or "unknown device"
    trig = ", ".join(_TRIGGER_NAMES.get(t, t)
                     for t in ev.get("trigger_reasons") or []) or "-"
    lines.append(f"- **device**: {name} · **triggered by**: {trig}")

    tr_bits = []
    if ev.get("packets") is not None:
        tr_bits.append(f"{ev['packets']:,} packets")
    if ev.get("unique_dsts") is not None:
        tr_bits.append(f"{ev['unique_dsts']} unique destinations")
    if ev.get("syn_count"):
        tr_bits.append(f"{ev['syn_count']:,} SYN")
    ports = ev.get("top_dst_ports") or []
    if ports:
        tr_bits.append("top ports " + ", ".join(
            p["port"] + (f" ({p['count']})" if p.get("count") else "")
            for p in ports))
    bo, bi = ev.get("bytes_out"), ev.get("bytes_in")
    if bo is not None or bi is not None:
        tr_bits.append(f"{_fmt_bytes(bo) or '?'} out / "
                       f"{_fmt_bytes(bi) or '?'} in")
    if tr_bits:
        lines.append("- **traffic**: " + " · ".join(tr_bits))

    sig_bits = []
    if ev.get("iso_score") is not None:
        sig_bits.append(f"iso_score {ev['iso_score']}")
    sites = ev.get("top_sites") or []
    if sites:
        sig_bits.append("sites: " + ", ".join(sites))
    if ev.get("tls_weak"):
        sig_bits.append("**weak TLS**")
    hist = ev.get("history") or {}
    if hist.get("seen_before"):
        prior = hist.get("prior_verdict_summary")
        sig_bits.append("seen in prior sessions"
                        + (f" ({prior})" if prior else ""))
    elif hist.get("seen_before") is False:
        sig_bits.append("first appearance in this environment")
    if sig_bits:
        lines.append("- **signals**: " + " · ".join(sig_bits))

    cited = v.get("evidence_features") or []
    if cited:
        lines.append("- **the judges cited**: "
                     + ", ".join(f"`{c}`" for c in cited[:6]))
    return lines


_VERDICT_ABBR = {"malicious": "mal", "suspicious": "sus", "benign": "ben"}


def _render_panel_votes(results, stats):
    """Appendix table: every candidate x every judge - who voted what.

    Replaces the old aggregate consensus summary (which the 2026-08-01
    overhaul orphaned): "3/3 unanimous" told a reader THAT the panel
    agreed but hid WHO the three were and how sure each was. One cell
    per judge shows the final verdict + confidence, the initial position
    when the judge revised it in debate (sus→mal ↺), and _failed_ when
    the provider errored. Nothing here calls the LLM again - it is a
    projection of the per-result panel block.
    """
    models = stats.get("models") or []
    if not models or not results:
        return []
    short = [m.split("/")[-1] for m in models]

    def _cell(j):
        if j is None or j.get("failed"):
            return "_failed_"
        v = j.get("verdict") or {}
        iv = j.get("initial_verdict") or {}
        final = _VERDICT_ABBR.get(v.get("verdict"), v.get("verdict") or "?")
        conf = v.get("confidence")
        conf_s = f" {float(conf):.2f}" if conf is not None else ""
        if j.get("revised") and iv.get("verdict") \
                and iv["verdict"] != v.get("verdict"):
            first = _VERDICT_ABBR.get(iv["verdict"], iv["verdict"])
            return f"{first}→{final}{conf_s} ↺"
        return f"{final}{conf_s}"

    lines = [
        "### Panel votes",
        "",
        "| # | Candidate | " + " | ".join(f"`{s}`" for s in short)
        + " | Effective |",
        "|--:|---|" + "---|" * len(short) + "---|",
    ]
    shown = results[:25]
    for i, r in enumerate(shown, 1):
        by_model = {j.get("model"): j
                    for j in (r.get("panel") or {}).get("judges") or []}
        cells = [_cell(by_model.get(m)) for m in models]
        eff = (r.get("verdict") or {}).get("verdict")
        lines.append(f"| {i} | `{r.get('candidate_id')}` | "
                     + " | ".join(cells) + f" | **{eff}** |")
    if len(results) > len(shown):
        lines.append(f"| … | {len(results) - len(shown)} more in "
                     f"`verdicts.json` |" + " |" * (len(short) + 1))
    lines.append("")
    lines.append("_mal / sus / ben = malicious / suspicious / benign · "
                 "number = that judge's confidence · sus→mal ↺ = revised "
                 "in debate._")
    lines.append("")
    return lines


def _first_n_sentences(text, n=2, max_chars=380):
    """Up to `n` sentences; cap at max_chars total. For the analyst
    commentary the LLM often runs 5+ sentences and the first 2 already
    cover the finding + recommended action."""
    if not isinstance(text, str) or not text.strip():
        return ""
    import re as _re
    parts, remaining = [], text.strip()
    for _ in range(n):
        first = _first_sentence(remaining, max_chars=10_000)
        if not first:
            break
        parts.append(first)
        remaining = remaining[len(first):].lstrip()
        if not remaining:
            break
    out = " ".join(parts).strip()
    if len(out) > max_chars:
        out = out[:max_chars - 4].rstrip() + " ..."
    return out


# --------------------------------------------------------------------------
def _failure_causes(examples):
    """Collapse raw provider error strings into short human causes.

    The report must NEVER show raw error bodies (org ids, marketing
    links, full JSON) - a manager-facing document classifies, it does
    not dump. Full raw examples stay in verdicts.json for ops."""
    text = " ".join(str(e) for e in examples)
    causes = []
    if "tokens per minute" in text or "(TPM)" in text:
        causes.append("rate throttle (TPM)")
    if "tokens per day" in text or "(TPD)" in text or "quota" in text.lower():
        causes.append("daily quota")
    if "json_validate_failed" in text or "json_schema" in text:
        causes.append("JSON format unsupported")
    if "timeout" in text.lower() or "timed out" in text.lower():
        causes.append("timeout")
    if not causes and examples:
        first = str(examples[0]).split(" - ")[0]
        causes.append(first[:60])
    return causes


def _n_valid_judges(r):
    """Count of judges whose verdict actually landed for this result.

    Used to mark verdicts decided by a single voter with ⚠: on a large
    panel where 5 of 6 judges failed on a candidate, "1 judge" tucked
    inside the Votes cell is easy to skim past - readers were treating
    the effective verdict as if it had a real panel behind it."""
    p = r.get("panel") or {}
    return sum(1 for j in (p.get("judges") or [])
               if j and not j.get("failed"))


def _votes_cell(r):
    """One compact phrase for how the panel arrived at this verdict."""
    p = r.get("panel")
    if not p:
        c = r.get("committee")
        if c:
            return "⚖ split" if c.get("needs_human_review") else "2/2"
        return "-"
    judges = p.get("judges") or []
    valid = [j for j in judges if not j.get("failed")]
    if not valid:
        return "-"
    if len(valid) == 1:
        return "1 judge"
    if p.get("needs_human_review"):
        return f"{len(valid)} split ⚖"
    if any(j.get("revised") for j in valid):
        return f"{len(valid)} agreed in debate"
    return f"{len(valid)}/{len(valid)} unanimous"


def _panel_health_rows(stats):
    """[(model, assigned, valid, mean_latency_str, cause_str, degraded)]"""
    pr = stats.get("panel_report") or {}
    rows = []
    for m in stats.get("models") or []:
        row = pr.get(m) or {}
        assigned = int(row.get("assigned") or 0)
        valid = int(row.get("valid_verdicts") or 0)
        ml = row.get("mean_latency_ms")
        ml_s = f"{ml} ms" if ml is not None else "-"
        causes = _failure_causes(row.get("failure_examples") or [])
        degraded = assigned > 0 and valid < assigned / 2
        rows.append((m, assigned, valid, ml_s,
                     ", ".join(causes) if causes else "-", degraded))
    return rows


def exec_summary_lines(pcap_name, out, ctx=None, for_email=False):
    """The manager-facing read: bottom line, key findings, who judged.

    Shared by the report's first page and the notification email body -
    the email shows ONLY this (for_email=True adds the closing
    'full report attached' line); the PDF continues into the
    consolidated table and appendix."""
    stats = out.get("stats") or {}
    results = out.get("results") or []
    ctx = ctx or {}
    counts = {}
    for r in results:
        v = r["verdict"]["verdict"]
        counts[v] = counts.get(v, 0) + 1
    n_mal = counts.get("malicious", 0)
    n_sus = counts.get("suspicious", 0)
    n_ben = counts.get("benign", 0)

    lines = ["## Executive summary", ""]

    if not results:
        lines += ["**No candidates required judgment** - the detectors "
                  "did not flag anything in this capture.", ""]
    else:
        if n_mal or n_sus:
            headline = (f"**{n_mal} malicious · {n_sus} suspicious · "
                        f"{n_ben} benign** out of {len(results)} "
                        f"analyzed candidates.")
        else:
            headline = (f"**All {len(results)} flagged candidates judged "
                        f"benign** - statistical outliers with no attack "
                        f"pattern.")
        lines += [headline, ""]

        findings = [r for r in results
                    if r["verdict"]["verdict"] in ("malicious",
                                                   "suspicious")]
        if findings:
            lines += ["**Key findings:**", ""]
            for r in findings[:5]:
                v = r["verdict"]
                reason = _first_sentence(v["reasoning"], max_chars=180)
                lines.append(
                    f"- `{r['candidate_id']}` - **{v['verdict'].upper()}**"
                    f" ({v['category']}, confidence {v['confidence']:.2f},"
                    f" {_votes_cell(r)}) - {reason}"
                    f" **Action: {v['recommended_action']}.**")
                ev_line = _evidence_short(r)
                if ev_line:
                    lines.append(f"  - _{ev_line}_")
            if len(findings) > 5:
                lines.append(f"- … and {len(findings) - 5} more - see the "
                             f"candidate table.")
            lines.append("")

    if ctx:
        protos = ", ".join(f"{k}" for k in list(ctx.get(
            "top_protocols") or {})[:3])
        mins = round((ctx.get("duration_s") or 0) / 60)
        # Time metadata: WHEN the capture was recorded matters as much
        # as WHAT it saw. A scan at 03:17 Sunday reads differently
        # from one at 14:00 Wednesday. ctx["time_range"] is
        # [start, end] ISO strings from build_context().
        tr = ctx.get("time_range") or []
        when_bits = []
        if tr and tr[0]:
            try:
                from datetime import datetime as _dt
                start = _dt.fromisoformat(tr[0].replace(" ", "T"))
                when_bits.append(
                    f"recorded {start.strftime('%a %d %b %Y, %H:%M')}")
            except Exception:
                when_bits.append(f"recorded {tr[0]}")
        n_macs = ctx.get("total_macs") or 0
        n_local = (ctx.get("local_ips_count")
                   if ctx.get("local_ips_count") is not None else None)
        lines += [
            f"**Capture**: {ctx.get('n_packets', 0):,} packets over "
            f"~{mins} min · {ctx.get('total_ips', 0)} IPs"
            + (f" ({n_local} local)" if n_local is not None else "")
            + (f" · {n_macs} MACs" if n_macs else "")
            + f" · top protocols: {protos}.",
        ]
        if when_bits:
            lines.append("*" + " · ".join(when_bits) + "*.")
        source_bits = []
        if ctx.get("original_filename"):
            source_bits.append(f"file `{ctx['original_filename']}`")
        if ctx.get("sensor_name"):
            source_bits.append(f"sensor `{ctx['sensor_name']}`")
        if source_bits:
            lines.append("*source: " + ", ".join(source_bits) + "*.")
        lines.append("")

    if stats.get("panel"):
        models = stats.get("models") or []
        short = [m.split("/")[-1] for m in models]
        n_res = len(results)
        unanimous = sum(1 for r in results
                        if _votes_cell(r).endswith("unanimous"))
        agreed = sum(1 for r in results
                     if _votes_cell(r).endswith("debate"))
        single = sum(1 for r in results if _votes_cell(r) == "1 judge")
        parts = [f"{unanimous}/{n_res} unanimous"]
        if agreed:
            parts.append(f"{agreed} agreed in debate")
        if stats.get("needs_review"):
            parts.append(f"{stats['needs_review']} need human review")
        if single:
            parts.append(f"{single} judged by one model")
        lines.append(f"**Panel**: {' + '.join(short)} · "
                     + " · ".join(parts) + ".")
        degraded = [(m, a, vld, cause) for m, a, vld, _, cause, deg
                    in _panel_health_rows(stats) if deg]
        for m, a, vld, cause in degraded:
            lines.append(f"- _{m.split('/')[-1]} degraded: {vld}/{a} "
                         f"valid answers ({cause}) - remaining judges "
                         f"covered._")
        lines.append("")
    elif stats.get("model"):
        lines += [f"**Judge**: {stats['model']}.", ""]

    commentary = out.get("analyst_commentary")
    if commentary and not str(commentary).startswith("("):
        lines += [f"> {_first_n_sentences(commentary, n=2)}", ""]

    if for_email:
        lines += ["---", "",
                  "The full report - every candidate, votes, reasoning "
                  "and pipeline detail - is attached as PDF.", ""]
    return lines


def render_exec_summary(pcap_path, out, context=None):
    """Standalone executive summary (markdown) - the email body."""
    name = os.path.basename(pcap_path)
    lines = [f"# Security report - `{name}`", ""]
    lines += exec_summary_lines(name, out, context, for_email=True)
    return "\n".join(lines) + "\n"


def _render_markdown(pcap_path, out, assembled, client, context=None):
    """Judged batch -> the full report (markdown source for HTML/PDF).

    Structure (rebuilt 2026-08-01 after user feedback that the old
    report was an unreadable salad - same 15 candidates rendered four
    times and three pages of raw 429 dumps):

      1. Executive summary - bottom line, key findings, panel health.
      2. ONE consolidated candidate table - rank, verdict, confidence,
         action, votes, one-line reason. No other per-candidate list.
      3. Appendix - pipeline stats, panel health table, disputes (only
         when any), dropped/capped, run metadata.

    Raw provider errors NEVER appear - _failure_causes classifies them
    ('rate throttle (TPM)', 'daily quota', ...); full bodies stay in
    verdicts.json for ops."""
    stats = out["stats"]
    ctx = context or {}
    results = out.get("results") or []
    lines = [f"# Security report - `{os.path.basename(pcap_path)}`", ""]

    # ----- 1. Executive summary -----------------------------------------
    lines += exec_summary_lines(os.path.basename(pcap_path), out, ctx)

    # ----- 2. The one candidate table -----------------------------------
    if results:
        lines += [
            "## All candidates (ranked by priority)",
            "",
            "| # | Candidate | Verdict | Conf | Action | Votes | ⚑ | Why |",
            "|--:|---|---|--:|---|---|:-:|---|",
        ]
        for i, r in enumerate(results, 1):
            v = r["verdict"]
            # ⚠ marks candidates decided by ≤1 valid judge, so a reader
            # can tell "3/3 unanimous benign" apart from a lone vote in
            # a panel where 5 of 6 failed - both used to look identical
            # once the votes cell was rendered.
            valid_n = _n_valid_judges(r)
            flags = ("⚑" if r.get("guardrail") else "") \
                + ("⚖" if ((r.get("committee") or r.get("panel") or {})
                           .get("needs_human_review")) else "") \
                + ("⚠" if valid_n <= 1 and stats.get("panel") else "")
            # a literal | inside the reasoning would split the table
            # cell - swap for a middot (escaping with \| renders as the
            # backslash in some email clients). Widened from 110 -> 250
            # after production feedback: 110 truncated most "Why" cells
            # mid-clause and buried the action rationale.
            why = _first_sentence(v["reasoning"],
                                  max_chars=250).replace("|", "·")
            lines.append(
                f"| {i} | `{r['candidate_id']}` | **{v['verdict']}** | "
                f"{v['confidence']:.2f} | {v['recommended_action']} | "
                f"{_votes_cell(r)} | {flags} | {why} |")
        lines.append("")

        # ----- 2b. Evidence per finding --------------------------------
        # The verdict table says WHAT the panel decided; this section
        # shows the numbers it decided FROM. Non-benign candidates only,
        # and only when the evidence projection exists (results written
        # before report v2 render the table alone).
        ev_findings = [r for r in results
                       if r["verdict"]["verdict"] in ("malicious",
                                                      "suspicious")
                       and r.get("evidence")]
        if ev_findings:
            lines += ["## Evidence per finding", ""]
            for r in ev_findings[:10]:
                v = r["verdict"]
                lines.append(f"**`{r['candidate_id']}` - {v['verdict']} "
                             f"({v['category']})**")
                lines += _evidence_block(r)
                lines.append("")
            if len(ev_findings) > 10:
                lines += [f"_… and {len(ev_findings) - 10} more findings "
                          f"- full projections in `verdicts.json`._", ""]
    else:
        lines += [
            "## No verdicts",
            "",
            "The pipeline produced no flagged candidates - nothing to judge. "
            "This is either a clean capture or the detectors did not fire; "
            "check `analyze.log` in the artifact for the pipeline output.",
            "",
        ]

    # ----- 3. Appendix ---------------------------------------------------
    lines += ["## Appendix", ""]

    if ctx:
        protos = ", ".join(f"{k} {v:,}"
                           for k, v in ctx["top_protocols"].items())
        ml = ctx["ml"]
        rules = ctx["rules"]
        rule_hits = []
        if rules["scan_alerts"]:
            rule_hits.append(f"**{rules['scan_alerts']} scan alert(s)**")
        if rules["flood_alerts"]:
            rule_hits.append(f"**{rules['flood_alerts']} flood alert(s)**")
        if rules["amp_alerts"]:
            rule_hits.append(f"**{rules['amp_alerts']} DNS-amp alert(s)**")
        if rules["arp_spoofing_ips"]:
            rule_hits.append(
                f"**{rules['arp_spoofing_ips']} ARP-multi-MAC IP(s)**")
        rule_line = " · ".join(rule_hits) if rule_hits \
            else "no deterministic rule fired"
        iso_word = "anomaly" if ml["isolation_forest_anomalies"] == 1 \
            else "anomalies"
        cluster_word = "cluster" if ml["dbscan_clusters"] == 1 \
            else "clusters"
        cluster_note = "" if ml["dbscan_meaningful"] \
            else " (clustering not meaningful)"
        lines += [
            "### Pipeline stats",
            "",
            f"- **Traffic**: {ctx['n_packets']:,} packets over "
            f"{ctx['duration_s']}s · {ctx['total_ips']} IPs · "
            f"{ctx['total_macs']} MACs · top: {protos}",
            f"- **Detectors**: ML: {ml['isolation_forest_anomalies']} IF "
            f"{iso_word} · {ml['dbscan_noise']} DBSCAN noise "
            f"({ml['dbscan_clusters']} {cluster_word}{cluster_note}) · "
            f"Rules: {rule_line}",
        ]
        for s in rules.get("scan_alerts_summary") or []:
            lines.append(f"  - {s}")
        not_flagged = ctx.get("not_flagged_ips") or []
        if not_flagged:
            lines.append(
                f"- {len(not_flagged)} additional IP"
                f"{'' if len(not_flagged) == 1 else 's'} analyzed with no "
                f"flags (full list in `verdicts.json`)")
        lines.append("")

    if stats.get("panel"):
        lines += [
            "### Panel health",
            "",
            "| Judge | Answered | Mean latency | Issues |",
            "|---|---|--:|---|",
        ]
        for m, assigned, valid, ml_s, cause, deg in _panel_health_rows(stats):
            mark = " ⚠" if deg else ""
            lines.append(f"| `{m}` | {valid}/{assigned}{mark} | {ml_s} "
                         f"| {cause} |")
        lines.append("")
        if stats.get("panel_init_failures"):
            excluded = ", ".join(f"`{f['entry']}`"
                                 for f in stats["panel_init_failures"])
            lines += [f"_Excluded at startup: {excluded} (failed to "
                      f"initialize; details in the run log)._", ""]

    # Panel votes: the full who-voted-what grid for EVERY candidate,
    # not only the disputed ones - "3/3 unanimous" in the main table
    # hides who the three were and how confident each was.
    if stats.get("panel"):
        lines += _render_panel_votes(results, stats)

    review = [r for r in results
              if (r.get("committee") or {}).get("needs_human_review")]
    if review:
        lines += [
            "### Committee disputes",
            "",
            "| Candidate | Judge A | Judge B | Effective |",
            "|---|---|---|---|",
        ]
        for r in review:
            c = r["committee"]
            ja = c.get("judge_a") or {}
            jb = c.get("judge_b") or {}
            a_txt = (f"{ja.get('verdict')} ({ja.get('confidence')})"
                     if not ja.get("failed") else "_failed_")
            b_txt = (f"{jb.get('verdict')} ({jb.get('confidence')})"
                     if not jb.get("failed") else "_failed_")
            lines.append(
                f"| `{r['candidate_id']}` | {a_txt} | {b_txt} | "
                f"**{r['verdict']['verdict']}** |")
        lines.append("")

    if out["dropped"]:
        lines += ["### Dropped by the provider (after 1 retry)", ""]
        for d in out["dropped"]:
            causes = _failure_causes([d["error"]])
            lines.append(f"- `{d['candidate_id']}` - "
                         + (", ".join(causes) if causes else "error"))
        lines.append("")

    if assembled["capped"]:
        capped_details = ctx.get("capped_details") or []
        lines += [
            "### Capped (statistical-only outliers over the batch limit)",
            "",
            f"{len(assembled['capped'])} candidate(s) not judged this run. "
            "Rule-triggered candidates always survive the cap, so these "
            "are ML-only outliers ranked below the top "
            f"{judge_config.MAX_CANDIDATES_PER_BATCH}.",
            "",
        ]
        if capped_details:
            lines += ["| IP | Packets | iso_score | Unique dsts |",
                      "|---|---|---|---|"]
            for d in capped_details[:20]:
                iso = d["iso_score"] if d["iso_score"] is not None else "-"
                lines.append(f"| `{d['ip']}` | {d['packets']} | {iso} "
                             f"| {d['unique_dsts']} |")
            if len(capped_details) > 20:
                lines.append(f"| … {len(capped_details) - 20} more | | | |")
            lines.append("")
        else:
            lines += [", ".join(f"`{c}`" for c in assembled["capped"][:20])
                      + ("…" if len(assembled["capped"]) > 20 else ""), ""]
        lines += ["Raise `LLM_JUDGE_MAX_CANDIDATES` to include them.", ""]

    # ----- How to read (one line, replaces the 12-line legend that was
    # cut on 2026-07-31 - definitions live in docs/LLM_JUDGE_SPEC.md) ----
    lines += ["### How to read", "",
              "_Severity: benign < suspicious < malicious · confidence "
              "0-1 · ⚑ = deterministic guardrail overrode a benign model "
              "verdict (raw verdict kept in `verdicts.json`) · ⚖ = panel "
              "split, needs human review · ⚠ = decided by a single judge "
              "· full definitions: `docs/LLM_JUDGE_SPEC.md`._", ""]

    # ----- Run metadata (compact, last) ---------------------------------
    meta = [
        f"generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"prompt {judge_config.PROMPT_VERSION}",
        f"guardrail {'on' if judge_config.RULE_GUARDRAIL else 'off'}",
        f"judged {stats['judged']}",
    ]
    if out["dropped"]:
        meta.append(f"dropped {stats['dropped']}")
    if assembled["capped"]:
        meta.append(f"capped {len(assembled['capped'])}")
    lines += ["### Run metadata", "",
              "_" + " · ".join(meta) + "_", ""]

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Pipeline + judge orchestration
# --------------------------------------------------------------------------
def _validate_committee_config():
    """Fail fast on a committee misconfiguration BEFORE the (expensive)
    pipeline run. The default committee model B is a Groq model; on any
    other provider it would silently fail every Judge B call, flooding
    needs_human_review on 100% of candidates with no visible error."""
    if judge_config.LLM_JUDGE_PANEL or not judge_config.LLM_JUDGE_COMMITTEE:
        return  # panel takes precedence over the legacy committee flag
    provider = judge_config.LLM_JUDGE_PROVIDER.lower()
    explicitly_set = "LLM_JUDGE_COMMITTEE_MODEL_B" in os.environ
    if provider != "openai_compat" and not explicitly_set:
        raise ValueError(
            f"LLM_JUDGE_COMMITTEE=1 with provider '{provider}': the default "
            f"committee model B ({judge_config.COMMITTEE_MODEL_B!r}) is a "
            f"Groq/openai_compat model and every Judge B call would fail on "
            f"this provider. Set LLM_JUDGE_COMMITTEE_MODEL_B to a model that "
            f"exists on '{provider}'.")


def _build_panel(spec_override=None):
    """Parse LLM_JUDGE_PANEL (or the per-upload override) and construct its
    clients.

    Returns (entries, clients, init_failures). Raises ValueError on a spec
    that cannot yield a working panel (bad syntax, duplicates, or fewer
    than two constructible judges) - loudly, BEFORE the expensive pipeline
    run, mirroring _validate_committee_config.

    spec_override (N1): the dashboard's Send-to-VM dropdown puts the
    chosen preset spec here. When set, it wins over the .env default.
    """
    spec = spec_override if spec_override is not None else judge_config.LLM_JUDGE_PANEL
    entries = judge_core.parse_panel_spec(spec)
    clients, init_failures = make_panel_clients(
        entries, verdict_schema=judge_core.VERDICT_SCHEMA)
    for f in init_failures:
        print(f"[cli] WARNING: panel judge {f['entry']} failed to "
              f"initialize and is excluded: {f['error']}", flush=True)
    if len(clients) < 2:
        raise ValueError(
            f"panel spec {spec!r}: only "
            f"{len(clients)} of {len(entries)} judges could be "
            f"constructed - a panel needs at least two. Failures: "
            + "; ".join(f"{f['entry']}: {f['error']}"
                        for f in init_failures))
    return entries, clients, init_failures


def analyze_and_judge(pcap_path, label="S1", verbose=True,
                      return_session=False, baseline_conn=None,
                      current_session_id=None, panel_spec_override=None):
    """Run the pipeline + judge; returns (out, assembled, client, context).

    return_session=True appends the raw session dict and the rule
    findings to the tuple - (out, assembled, client, context, S,
    findings) - so the VM worker can persist them without re-running
    the pipeline. The default stays the 4-tuple for existing callers.

    baseline_conn: optional sqlite3 connection to the history DB. When
    passed (the worker path), assemble_candidates gets a per-IP
    baseline_history block ("has this IP been seen? how long ago?
    prior verdict summary"). Not passed on the CLI / dashboard path,
    where every candidate's history stays at the null defaults.
    current_session_id: the session_id currently being analysed, so
    history lookup excludes it (a candidate is not its own history).
    """
    _validate_committee_config()
    panel = None
    # N1: the dashboard drop-down sends its picked spec (or a preset
    # id) as panel_spec_override. Ingest stores the raw header value
    # (see server/ingest_api.py) because ingest's image has no
    # llm_judge; the worker path resolves preset id -> spec here.
    # A stringified id ("fast_cloud_3") without a colon is treated as
    # a preset name; a spec ("groq:..." / "ollama:...") wins as-is.
    # Bad id / bad spec silently falls back to .env - never lose a run.
    from . import panel_presets as _pp
    resolved_override = panel_spec_override
    if isinstance(resolved_override, str) and resolved_override and ":" not in resolved_override:
        preset = _pp.preset_by_id(resolved_override.strip())
        if preset is not None:
            resolved_override = preset["spec"]
        else:
            resolved_override = None  # unknown id -> fall through to env
    elif isinstance(resolved_override, str) and resolved_override and not _pp.valid_spec(resolved_override):
        resolved_override = None
    effective_spec = (resolved_override
                      if resolved_override is not None
                      else judge_config.LLM_JUDGE_PANEL)
    if effective_spec:
        panel = _build_panel(spec_override=effective_spec)  # fail fast
    import run_pipeline as rp  # imports tshark - keep lazy for tests

    if verbose:
        print(f"[cli] analyzing {pcap_path} (label={label})...", flush=True)
    S = rp.analyze_pcap(pcap_path, label)
    rp.run_ml_on_session(S)
    findings = rp.run_security_scans(S)

    if verbose:
        print("[cli] assembling candidates...", flush=True)
    # Advanced signals + device context for `assemble_candidates`.
    # `run_pipeline.analyze_pcap` now runs the six MITRE-mapped engines
    # from `app/advanced_engines.py` and leaves them at S["threats"], so
    # the CLI and the VM worker judge with the same beaconing / DNS
    # tunnelling / DGA / TLS / fusion evidence the dashboard shows. A
    # caller that also attaches a `build_local_inventory(S)` DataFrame at
    # S["_local_inv"] (the dashboard does) gets device context too;
    # absent it, every candidate keeps the schema's default block.
    adv_signals = judge_core.threats_to_advanced_signals(S.get("threats"))
    device_ctx = judge_core.local_inv_to_device_context(
        S.get("_local_inv") or S.get("local_inv"))
    # L5: attach baseline_history so the LLM sees "have we judged this
    # IP before, and what did we call it". Only when a DB conn was
    # passed (worker path). Never raises: a failed lookup lands as
    # historyless for that IP.
    if baseline_conn is not None:
        try:
            from server import baseline as _bl
            ips = set(S.get("ips_src") or {})
            S["baseline_history"] = {
                ip: _bl.lookup_history(baseline_conn, ip,
                                        exclude_session_id=current_session_id)
                for ip in ips}
            # Drop the None entries so downstream code doesn't have to
            # distinguish "we looked and found nothing" from "we didn't
            # look" - both map to the null-default block via _history_for.
            S["baseline_history"] = {k: v for k, v in
                                      S["baseline_history"].items() if v}
        except Exception as e:
            if verbose:
                print(f"[cli] baseline_history lookup skipped: {e}",
                      flush=True)
    assembled = judge_core.assemble_candidates(
        S, findings, advanced_signals=adv_signals, device_context=device_ctx)
    context = build_context(S, findings, assembled)
    if verbose:
        print(f"[cli] provider={judge_config.LLM_JUDGE_PROVIDER} "
              f"guardrail={'on' if judge_config.RULE_GUARDRAIL else 'off'} "
              f"prompt={judge_config.PROMPT_VERSION}", flush=True)
        print(f"[cli] {len(assembled['candidates'])} candidate(s) "
              f"({len(assembled['capped'])} capped, "
              f"{len(context['not_flagged_ips'])} not-flagged)", flush=True)

    commentary_provider, commentary_model = None, None
    if panel is not None:
        entries, clients, init_failures = panel
        client = clients[0]
        # Take the commentary provider from the client that was actually
        # constructed, not from entries[0]. When the first entry fails to
        # initialize (missing key, unknown model) make_panel_clients drops
        # it, so clients[0] is the second entry - and reading entries[0]
        # here would generate the commentary through the judge that was
        # just excluded from the panel.
        commentary_provider = _commentary_provider(client)
        commentary_model = client.model_id
        if verbose:
            print(f"[cli] panel: {' + '.join(c.model_id for c in clients)} "
                  f"(debate {'on' if judge_config.LLM_JUDGE_DEBATE else 'off'})"
                  f" - judging...", flush=True)
        out = judge_core.judge_candidates_panel(
            assembled["candidates"], clients=clients, verbose=verbose)
        if init_failures:
            out["stats"]["panel_init_failures"] = init_failures
    elif judge_config.LLM_JUDGE_COMMITTEE:
        client = make_client(verdict_schema=judge_core.VERDICT_SCHEMA)
        client_b = make_client(verdict_schema=judge_core.VERDICT_SCHEMA,
                               model=judge_config.COMMITTEE_MODEL_B)
        if verbose:
            print(f"[cli] committee: A={client.model_id} "
                  f"B={client_b.model_id} - judging...", flush=True)
        out = judge_core.judge_candidates_committee(
            assembled["candidates"], clients=[client, client_b],
            verbose=verbose)
    else:
        client = make_client(verdict_schema=judge_core.VERDICT_SCHEMA)
        if verbose:
            print(f"[cli] model={client.model_id} - judging...", flush=True)
        out = judge_core.judge_candidates(assembled["candidates"],
                                          client=client, verbose=verbose)
    if verbose:
        print("[cli] generating analyst commentary...", flush=True)
    out["analyst_commentary"] = judge_core.analyst_commentary(
        client, context, out, session_label=label,
        provider=commentary_provider, model=commentary_model)
    # Persist the capture context INSIDE the verdict output. verdicts.json
    # is the only artifact the pair-compare path reads - without this the
    # comparison report cannot say when either capture was recorded.
    out["context"] = context
    if return_session:
        return out, assembled, client, context, S, findings
    return out, assembled, client, context


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Analyze a PCAP and judge every flagged candidate "
                    "(headless; no Jupyter required)")
    ap.add_argument("pcap", help="Path to the .pcap or .pcapng file")
    ap.add_argument("--output", "-o", default="verdicts.json",
                    help="Path for the JSON batch (default: verdicts.json)")
    ap.add_argument("--markdown", "-m", default=None,
                    help="Path for a Markdown report suitable for a "
                         "GitHub Issue body (optional)")
    ap.add_argument("--label", default="S1",
                    help="Session label used inside the pipeline "
                         "(default: S1)")
    ap.add_argument("--email", default=None,
                    help="Email the report to this address. SMTP settings "
                         "come from the environment (SMTP_USER, SMTP_PASS, "
                         "optionally SMTP_HOST/PORT/FROM). A send failure "
                         "is reported but never fails the run.")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.pcap):
        print(f"ERROR: PCAP file not found: {args.pcap}", file=sys.stderr)
        return 2

    out, assembled, client, context = analyze_and_judge(args.pcap,
                                                        label=args.label)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({
            "pcap": os.path.basename(args.pcap),
            "generated_at": datetime.now(timezone.utc)
                                    .isoformat(timespec="seconds"),
            "provider": judge_config.LLM_JUDGE_PROVIDER,
            "model": client.model_id,
            "models": out["stats"].get("models", [client.model_id]),
            "prompt_version": judge_config.PROMPT_VERSION,
            "guardrail": bool(judge_config.RULE_GUARDRAIL),
            "analyst_commentary": out.get("analyst_commentary"),
            "stats": out["stats"],
            "results": out["results"],
            "dropped": out["dropped"],
            "capped": assembled["capped"],
            "context": context,
        }, f, indent=2)
    print(f"[cli] wrote {args.output}", flush=True)

    md = None
    if args.markdown:
        md = _render_markdown(args.pcap, out, assembled, client,
                              context=context)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[cli] wrote {args.markdown}", flush=True)

    if args.email:
        # Render on demand when --markdown was not requested, so --email
        # works on its own.
        if md is None:
            md = _render_markdown(args.pcap, out, assembled, client,
                                  context=context)
        from llm_judge.send_report import send_report  # noqa: E402
        with open(args.output, encoding="utf-8") as f:
            verdict_json = f.read()
        ok, message = send_report(
            args.email, md,
            subject=f"NetSec Judge verdicts - {os.path.basename(args.pcap)}",
            attachments={os.path.basename(args.output): verdict_json})
        print(f"[cli] email: {message}", flush=True)
        # A delivery failure must not discard an analysis that already ran.

    return 0


if __name__ == "__main__":
    sys.exit(main())

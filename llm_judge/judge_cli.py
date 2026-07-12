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

from llm_judge import judge_config, judge_core        # noqa: E402
from llm_judge.llm_clients import make_client         # noqa: E402


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

    return {
        "n_packets": int(S["n_pkts"]),
        "duration_s": round(duration, 1),
        "time_range": [_fmt_ts(S["t0"]), _fmt_ts(S["t1"])],
        "total_ips": len(S["ips_src"]),
        "total_macs": len(S["macs"]),
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
    }


# --------------------------------------------------------------------------
# Markdown renderer. Sections, in order:
#   1. Metadata table (PCAP, model, prompt, guardrail)
#   2. Pipeline stats (packets, IPs, detections)
#   3. Top verdict (highest priority row)
#   4. Triaged queue (full verdict table)
#   5. Not queued for judgment (IPs the pipeline analyzed and cleared)
#   6. Dropped / Capped (only if non-empty)
#   7. How to interpret
# --------------------------------------------------------------------------
def _render_markdown(pcap_path, out, assembled, client, context=None):
    """Turn a judged batch into a GitHub-Issue-ready markdown report."""
    stats = out["stats"]
    ctx = context or {}
    commentary = out.get("analyst_commentary")
    lines = [
        f"# Judge verdicts — `{os.path.basename(pcap_path)}`",
        "",
        "| | |",
        "|---|---|",
        f"| **PCAP** | `{pcap_path}` |",
        f"| **Generated** | {datetime.now(timezone.utc).isoformat(timespec='seconds')} |",
        f"| **Provider** | `{judge_config.LLM_JUDGE_PROVIDER}` |",
        f"| **Model** | `{client.model_id}` |",
        f"| **Prompt version** | `{judge_config.PROMPT_VERSION}` |",
        f"| **Rule guardrail** | {'on' if judge_config.RULE_GUARDRAIL else 'off'} |",
        f"| **Candidates judged** | {stats['judged']} · dropped: {stats['dropped']} · capped: {len(assembled['capped'])} |",
        "",
    ]

    # ----- 0. Analyst commentary (top of report - the human read) --------
    if commentary:
        lines += [
            "## Analyst commentary",
            "",
            f"> {commentary}",
            "",
        ]

    # ----- 2. Pipeline stats ---------------------------------------------
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

        lines += [
            "## Pipeline stats",
            "",
            f"- **Duration**: {ctx['duration_s']} seconds "
            f"({ctx['time_range'][0]} → {ctx['time_range'][1]})",
            f"- **Packets analyzed**: {ctx['n_packets']:,}",
            f"- **Source IPs**: {ctx['total_ips']} · "
            f"**MACs**: {ctx['total_macs']}",
            f"- **Top protocols**: {protos}",
            f"- **ML layer**: "
            f"{ml['isolation_forest_anomalies']} IsolationForest anomal"
            f"{'y' if ml['isolation_forest_anomalies'] == 1 else 'ies'} · "
            f"{ml['dbscan_noise']} DBSCAN noise "
            f"({ml['dbscan_clusters']} cluster"
            f"{'' if ml['dbscan_clusters'] == 1 else 's'} found"
            f"{'' if ml['dbscan_meaningful'] else ', clustering not meaningful'})",
            f"- **Deterministic rules**: {rule_line}",
        ]
        for s in rules.get("scan_alerts_summary") or []:
            lines.append(f"  - {s}")
        lines.append("")

    # ----- 3. Top verdict -----------------------------------------------
    if out["results"]:
        top = out["results"][0]
        v = top["verdict"]
        lines += [
            "## Top verdict",
            "",
            f"**`{top['candidate_id']}`** — **{v['verdict'].upper()}** "
            f"({v['category']}, confidence {v['confidence']:.2f})",
            "",
            f"> {v['reasoning']}",
            "",
        ]

    # ----- 4. Triaged queue ---------------------------------------------
    if out["results"]:
        lines += [
            "## Triaged queue (ranked by ensemble priority)",
            "",
            "| # | Candidate | Verdict | Category | Confidence | Priority | ⚑ | Action | Reasoning |",
            "|--:|---|---|---|--:|--:|:-:|---|---|",
        ]
        for i, r in enumerate(out["results"], 1):
            v = r["verdict"]
            gr = "⚑" if r.get("guardrail") else ""
            reasoning = v["reasoning"].replace("|", "\\|")
            lines.append(
                f"| {i} | `{r['candidate_id']}` | **{v['verdict']}** | "
                f"{v['category']} | {v['confidence']:.2f} | {r['priority']:.3f} | "
                f"{gr} | {v['recommended_action']} | {reasoning} |"
            )
        lines.append("")
        if any(r.get("guardrail") for r in out["results"]):
            lines += [
                "> ⚑ = rule guardrail overrode a benign model verdict "
                "on a candidate whose deterministic rule fired. Raw model "
                "verdict is preserved in `verdicts.json`.",
                "",
            ]
    else:
        lines += [
            "## No verdicts",
            "",
            "The pipeline produced no flagged candidates — nothing to judge. "
            "This is either a clean capture or the detectors did not fire; "
            "check `analyze.log` in the artifact for the pipeline output.",
            "",
        ]

    # ----- 5. Not queued for judgment (the honest "we looked at these") -
    not_flagged = (ctx.get("not_flagged_ips") or []) if ctx else []
    if not_flagged:
        lines += [
            "## Not queued for judgment (traffic considered normal)",
            "",
            f"The pipeline analyzed **{len(not_flagged)} additional IP"
            f"{'' if len(not_flagged) == 1 else 's'}** but did not flag "
            f"{'it' if len(not_flagged) == 1 else 'them'} — no ML anomaly "
            "and no deterministic rule fired. Included here so you can see "
            "the full traffic set the pipeline reasoned about.",
            "",
            "| IP | Packets | iso_score |",
            "|---|--:|--:|",
        ]
        MAX_ROWS = 20
        for entry in not_flagged[:MAX_ROWS]:
            iso = "—" if entry["iso_score"] is None \
                else f"{entry['iso_score']:+.3f}"
            lines.append(
                f"| `{entry['ip']}` | {entry['packets']:,} | {iso} |")
        if len(not_flagged) > MAX_ROWS:
            lines.append(
                f"| _(+ {len(not_flagged) - MAX_ROWS} more, "
                f"see `verdicts.json`)_ | | |")
        lines.append("")

    # ----- 6. Dropped / Capped ------------------------------------------
    if out["dropped"]:
        lines += ["## Dropped by the provider (after 1 retry)", ""]
        for d in out["dropped"]:
            lines.append(f"- `{d['candidate_id']}` — {d['error']}")
        lines.append("")

    if assembled["capped"]:
        lines += [
            "## Capped (statistical-only outliers over the batch limit)",
            "",
            f"{len(assembled['capped'])} candidate(s) not judged this run: "
            + ", ".join(f"`{c}`" for c in assembled["capped"][:20])
            + ("…" if len(assembled["capped"]) > 20 else ""),
            "",
            "Raise `LLM_JUDGE_MAX_CANDIDATES` to include them.",
            "",
        ]

    # ----- 7. How to interpret ------------------------------------------
    lines += [
        "## How to interpret",
        "",
        "- **Verdict**: `benign` (no attack pattern), `suspicious` (weak or "
        "ambiguous signal), `malicious` (strong, unambiguous evidence).",
        "- **Category**: the attack shape — `port_scan`, `syn_flood`, "
        "`dns_amp`, `arp_mitm`, `beaconing_c2`, `dns_tunnel`, or "
        "`benign_anomaly` (statistical outlier that isn't an attack).",
        "- **Priority**: ensemble rank score, "
        "`0.20·anomaly + 0.40·confidence + 0.30·category_severity`. "
        "Higher = more urgent for the analyst.",
        "- **⚑ Rule guardrail**: a candidate whose deterministic rule fired "
        "(scan / flood / amp / ARP) can never be judged `benign` by the "
        "model. When the model tries to, the guardrail overrides to "
        "`suspicious` with the rule-implied category; the raw model verdict "
        "stays in `verdicts.json` for auditing.",
        "",
        "---",
        "",
        "*Full machine-readable batch: `verdicts.json` in the run's "
        "artifacts. Design: [docs/LLM_JUDGE_SPEC.md]"
        "(../blob/main/docs/LLM_JUDGE_SPEC.md).*",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Pipeline + judge orchestration
# --------------------------------------------------------------------------
def analyze_and_judge(pcap_path, label="S1", verbose=True):
    """Run the pipeline + judge; returns (out, assembled, client, context)."""
    import run_pipeline as rp  # imports tshark - keep lazy for tests

    if verbose:
        print(f"[cli] analyzing {pcap_path} (label={label})...", flush=True)
    S = rp.analyze_pcap(pcap_path, label)
    rp.run_ml_on_session(S)
    findings = rp.run_security_scans(S)

    if verbose:
        print("[cli] assembling candidates...", flush=True)
    assembled = judge_core.assemble_candidates(S, findings)
    context = build_context(S, findings, assembled)
    if verbose:
        print(f"[cli] provider={judge_config.LLM_JUDGE_PROVIDER} "
              f"guardrail={'on' if judge_config.RULE_GUARDRAIL else 'off'} "
              f"prompt={judge_config.PROMPT_VERSION}", flush=True)
        print(f"[cli] {len(assembled['candidates'])} candidate(s) "
              f"({len(assembled['capped'])} capped, "
              f"{len(context['not_flagged_ips'])} not-flagged)", flush=True)

    client = make_client(verdict_schema=judge_core.VERDICT_SCHEMA)
    if verbose:
        print(f"[cli] model={client.model_id} - judging...", flush=True)
    out = judge_core.judge_candidates(assembled["candidates"], client=client,
                                      verbose=verbose)
    if verbose:
        print("[cli] generating analyst commentary...", flush=True)
    out["analyst_commentary"] = judge_core.analyst_commentary(
        client, context, out, session_label=label)
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

    if args.markdown:
        md = _render_markdown(args.pcap, out, assembled, client,
                              context=context)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[cli] wrote {args.markdown}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())

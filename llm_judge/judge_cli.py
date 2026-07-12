"""Headless CLI wrapper around the LLM-as-Judge (no Jupyter needed).

Runs the exact detection pipeline of the dashboard on a single PCAP,
judges every flagged candidate through the configured provider (see the
LLM_JUDGE_* env vars in llm_judge/judge_config.py), and writes:

- verdicts.json  : machine-readable batch (stats + results + drops + capped)
- verdicts.md    : GitHub-Issue-friendly report with a verdict table

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


def _render_markdown(pcap_path, out, assembled, client):
    """Turn a judged batch into a GitHub-Issue-ready markdown report."""
    stats = out["stats"]
    top = out["results"][0] if out["results"] else None
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
    if top:
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
    lines += [
        "---",
        "",
        "*Full machine-readable batch: `verdicts.json` in the run's "
        "artifacts. Design: [docs/LLM_JUDGE_SPEC.md]"
        "(../blob/main/docs/LLM_JUDGE_SPEC.md).*",
    ]
    return "\n".join(lines) + "\n"


def analyze_and_judge(pcap_path, label="S1", verbose=True):
    """Run the pipeline + judge; returns (out, assembled, client)."""
    import run_pipeline as rp  # imports tshark - keep lazy for tests

    if verbose:
        print(f"[cli] analyzing {pcap_path} (label={label})...", flush=True)
    S = rp.analyze_pcap(pcap_path, label)
    rp.run_ml_on_session(S)
    findings = rp.run_security_scans(S)

    if verbose:
        print("[cli] assembling candidates...", flush=True)
    assembled = judge_core.assemble_candidates(S, findings)
    if verbose:
        print(f"[cli] provider={judge_config.LLM_JUDGE_PROVIDER} "
              f"guardrail={'on' if judge_config.RULE_GUARDRAIL else 'off'} "
              f"prompt={judge_config.PROMPT_VERSION}", flush=True)
        print(f"[cli] {len(assembled['candidates'])} candidate(s) "
              f"({len(assembled['capped'])} capped)", flush=True)

    client = make_client(verdict_schema=judge_core.VERDICT_SCHEMA)
    if verbose:
        print(f"[cli] model={client.model_id} - judging...", flush=True)
    out = judge_core.judge_candidates(assembled["candidates"], client=client,
                                      verbose=verbose)
    return out, assembled, client


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

    out, assembled, client = analyze_and_judge(args.pcap, label=args.label)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({
            "pcap": os.path.basename(args.pcap),
            "generated_at": datetime.now(timezone.utc)
                                    .isoformat(timespec="seconds"),
            "provider": judge_config.LLM_JUDGE_PROVIDER,
            "model": client.model_id,
            "prompt_version": judge_config.PROMPT_VERSION,
            "guardrail": bool(judge_config.RULE_GUARDRAIL),
            "stats": out["stats"],
            "results": out["results"],
            "dropped": out["dropped"],
            "capped": assembled["capped"],
        }, f, indent=2)
    print(f"[cli] wrote {args.output}", flush=True)

    if args.markdown:
        md = _render_markdown(args.pcap, out, assembled, client)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[cli] wrote {args.markdown}", flush=True)

    # exit 0 unless the pipeline itself failed (handled above by exception)
    return 0


if __name__ == "__main__":
    sys.exit(main())

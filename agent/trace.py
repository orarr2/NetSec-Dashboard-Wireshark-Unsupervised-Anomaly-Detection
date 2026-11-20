"""One formatter for a run's trace. The same lines go to stdout (journald), to GET /report/{id} and to the trace page."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from agent.state import cost_usd

BAR = 40
_LABELS = {
    "sanitize": "SANITIZE",
    "signal_extractor": "SIGNAL",
    "supervisor": "SUPERVIS",
    "profile_builder": "PROFILE",
    "rag_retriever": "RAG",
    "decision": "DECISION",
    "approval_gate": "GATE",
    "budget_guard": "GUARD",
    "pipeline": "PIPELINE",
    "engines": "ENGINES",
}
_INDENT = " " * 11  # width of "[XXXXXXXX] "
AGENTS = ("sanitize", "signal_extractor", "supervisor", "profile_builder", "rag_retriever", "decision")


def _lbl(speaker: str) -> str:
    return f"[{_LABELS.get(speaker, str(speaker).upper()[:8]):<8}]"


def _clock(ts: Any) -> str:
    """YYYY-MM-DD HH:MM:SS in NETSEC_AGENT_DISPLAY_TZ (local time when unset or unknown)."""
    tz = os.environ.get("NETSEC_AGENT_DISPLAY_TZ")
    try:
        dt = datetime.fromtimestamp(float(ts), ZoneInfo(tz)) if tz else datetime.fromtimestamp(float(ts))
    except Exception:
        dt = datetime.fromtimestamp(float(ts))
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _short(value: Any, limit: int = 160) -> str:
    s = str(value)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _join(values: Any) -> str:
    return ",".join(str(v) for v in values or []) or "none"


def _header(case_id: str, metadata: dict | None, extra: str) -> list[str]:
    md = metadata or {}
    head = f"AGENT RUN  {case_id}"
    if md.get("technique"):
        head += f"  {md['technique']}"
    if md.get("score") is not None:
        head += f" score={float(md['score']):.2f}"
    if md.get("asset_role"):
        head += f"  asset={md['asset_role']}"
    if md.get("candidate_id"):
        head += f"  device={md['candidate_id']}"
    if extra:
        head += f"  {extra}"
    lines = ["=" * BAR, head]
    if md.get("session_id") is not None or md.get("pcap_name"):
        lines.append(f"{_INDENT}source: session {md.get('session_id')} ({_short(md.get('pcap_name') or 'unknown capture', 80)})")
    lines.append("=" * BAR)
    return lines


def _engines_line(md: dict) -> str | None:
    engines = md.get("engines")
    if not isinstance(engines, dict) or not engines:
        return None
    return (
        f"{_lbl('engines')} rules={_join(engines.get('rules'))}  ml={_join(engines.get('ml'))}  "
        f"advanced={_join(engines.get('advanced'))}  source=netsec_pipeline"
    )


def _skip(c: dict) -> list[str]:
    return [f"{_INDENT}llm skipped: {c['llm_skipped_reason']}"] if c.get("llm_skipped_reason") else []


def _llm_line(llm: dict) -> str:
    line = (
        f"{_INDENT}llm: {llm.get('model')}  {llm.get('calls')} call(s)  "
        f"{llm.get('latency_s')}s  tokens in={llm.get('tokens_in')} out={llm.get('tokens_out')}"
    )
    return line + ("  (offline stub)" if llm.get("mode") == "offline-stub" else "")


def _entry_lines(entry: dict, tool_ids: list[str]) -> list[str]:
    speaker = str(entry.get("speaker") or "?")
    kind = str(entry.get("kind") or "?")
    raw = entry.get("content")
    c: dict = raw if isinstance(raw, dict) else {"content": raw}
    lbl = _lbl(speaker)
    out: list[str] = []

    if speaker == "sanitize":
        out.append(
            f"{lbl} boundary defence  strings_checked={c.get('strings_checked')}  "
            f"traffic_strings_suspicious={c.get('traffic_suspicious')}  "
            f"analyst_note_suspicious={c.get('note_suspicious')}"
        )
        for hit in c.get("hits") or []:
            kept = "string withheld" if hit.get("withheld", True) else "identifier kept"
            out.append(
                f"{_INDENT}suspicious: channel={hit.get('channel')}  patterns={_join(hit.get('patterns'))}  "
                f"({kept}, {hit.get('length')} chars)"
            )
        if c.get("pii_redacted"):
            out.append(f"{_INDENT}personal details were redacted in the analyst note")
    elif speaker == "signal_extractor":
        out.append(
            f"{lbl} analyst note  has_text={c.get('has_text')}  source={c.get('source')}  llm_used={c.get('llm_used')}"
        )
        out.extend(_skip(c))
        if c.get("has_text") and not c.get("suspicious"):
            out.append(
                f"{_INDENT}mentioned: technique={_join(c.get('mentioned'))}  devices={_join(c.get('devices'))}  "
                f"engines_reported={_join(c.get('reported_by_engines'))}"
            )
            out.append(
                f"{_INDENT}urgency_claimed={c.get('urgency_claimed')}  contradictions={c.get('contradictions') or []}"
            )
        if c.get("suspicious"):
            out.append(f"{_INDENT}suspicious pattern in the analyst note; it was not interpreted")
    elif kind == "supervisor_plan":
        force = c.get("force_action")
        out.append(
            f"{lbl} supervisor_plan  pipeline_concern={c.get('pipeline_concern')}  "
            f"expected_difficulty={c.get('expected_difficulty')}  force_action={force if force is not None else 'none'}"
        )
        out.extend(_skip(c))
        if c.get("note"):
            out.append(f"{_INDENT}note: {_short(c['note'], 300)}")
    elif speaker == "profile_builder":
        others = f"  others={_join(c.get('others'))}" if c.get("others") else ""
        out.append(
            f"{lbl} technique={c.get('primary_technique') or 'none'}  severity={c.get('severity')}  "
            f"confidence={c.get('confidence')}  llm_used={c.get('llm_used')}{others}"
        )
        out.extend(_skip(c))
        engines = c.get("engines") or {}
        details = c.get("rule_details") or {}
        rules = ", ".join(f"{r} ({details.get(r, 'fired')})" for r in engines.get("rules") or []) or "none"
        fusion = c.get("fusion_score")
        out.append(
            f"{_INDENT}engines: rules={rules}  ml={_join(engines.get('ml'))}  "
            f"advanced={_join(engines.get('advanced'))}  iso_score={c.get('iso_score')}  "
            f"fusion={fusion if fusion is not None else '-'}  score={c.get('score')}"
        )
        asset = c.get("asset") or {}
        out.append(
            f"{_INDENT}asset: role={asset.get('role')}  my_device={asset.get('is_my_device')}  "
            f"declared_infra={asset.get('is_declared_infra')}  targets_infra={asset.get('targets_infra')}  "
            f"critical={asset.get('critical')}"
        )
        cat = c.get("catalogue") or {}
        if cat.get("match"):
            out.append(
                f"{_INDENT}catalogue: KNOWN PATTERN id={cat.get('id')}  source={cat.get('source')}  "
                f"label={cat.get('label') or 'none'}  (sha256: identical capture, same candidate)"
            )
        else:
            out.append(f"{_INDENT}catalogue: new case ({cat.get('reason')})")
        if c.get("quality_warnings"):
            out.append(f"{_INDENT}quality: {_join(c['quality_warnings'])}")
        out.append(f"{_INDENT}handoff -> {c.get('to') or 'rag_retriever'}")
    elif speaker == "rag_retriever":
        ids = [str(x) for x in (c.get("tool_result_ids") or [])]
        tool_ids[:] = ids
        if c.get("skipped"):
            out.append(
                f"{lbl} skipped  reason=no_technique (no rule and no advanced engine named a technique)  "
                f"llm_used={c.get('llm_used')}"
            )
        else:
            dc = c.get("decision_coverage") or {}
            sufficient = "yes" if dc.get("sufficiency") == "sufficient_coverage" else "no"
            out.append(
                f"{lbl} query_security_standards -> {c.get('n_procedures', len(ids))} passages  "
                f"topic={c.get('coverage')}  sufficient={sufficient}  answers={_join(dc.get('answered'))}  "
                f"missing={_join(dc.get('missing'))}  sufficiency={dc.get('sufficiency')}  llm_used={c.get('llm_used')}"
            )
            if c.get("rag_query"):
                out.append(f"{_INDENT}rag_query: \"{_short(c['rag_query'], 240)}\"")
            rf = c.get("rag_filter") or {}
            out.append(
                f"{_INDENT}rag_filter: technique={rf.get('technique')}  asset_role={rf.get('asset_role')}  k={rf.get('k')}"
            )
            out.append(f"{_INDENT}tool_result_ids={ids}")
            for pv in (c.get("passage_previews") or [])[:3]:
                out.append(
                    f"{_INDENT}- {pv.get('id')}  dist={float(pv.get('distance') or 0.0):.3f}  support={pv.get('support')}"
                )
                if pv.get("preview"):
                    out.append(f"{_INDENT}  text=\"{_short(pv['preview'], 2000)}\"")
            if c.get("backend") == "static_table":
                out.append(f"{_INDENT}backend: static_table (a stand-in until the corpus of phase P3)")
            out.extend(_skip(c))
        out.append(f"{_INDENT}handoff -> {c.get('to') or 'decision'}")
    elif speaker == "decision":
        action = str(c.get("action") or "?")
        out.append(f"{lbl} action={action.upper()}  priority={c.get('priority')}  source={c.get('source')}")
        out.extend(_skip(c))
        for call in c.get("tool_calls") or []:
            flag = "ok" if call.get("ok") else ("failed" if call.get("executed") else "skipped")
            tail = f"  -> {call.get('result')}" if call.get("ok") and call.get("result") else ""
            out.append(f"{_INDENT}tool called: {call.get('tool')} ({flag}){tail}")
        if c.get("floor_applied"):
            ov = c.get("overridden_llm_verdict") or {}
            out.append(f"{_INDENT}floor applied: {c.get('floor_reason') or 'unnamed_floor'}")
            if c.get("floor_trigger"):
                out.append(f"{_INDENT}  trigger: {_short(c['floor_trigger'], 320)}")
            if ov.get("action"):
                out.append(f"{_INDENT}  verdict_before: {ov.get('action')}  verdict_after: {action}")
        if c.get("fallback_reason"):
            out.append(f"{_INDENT}fallback_reason={c['fallback_reason']}")
        wi = c.get("worker_impact")
        if isinstance(wi, dict):
            out.append(
                f"{_INDENT}worker impact: profile_llm_changed={wi.get('profile_llm_changed')}  "
                f"research_llm_changed={wi.get('research_llm_changed')}  rule_hint without/with worker LLM: "
                f"{wi.get('rule_hint_without_worker_llm')}/{wi.get('rule_hint_with_worker_llm')}"
            )
        out.append(f"{_INDENT}rationale: {_short(c.get('rationale') or '', 500)}")
        cited = [str(x) for x in (c.get("cited_sources") or [])]
        out.append(f"{_INDENT}cited_sources={cited}")
        if cited:
            out.append(
                f"{_INDENT}grounded_per_source: "
                + "  ".join(f"{s}={'rag' if s in tool_ids else 'UNGROUNDED'}" for s in cited)
            )
        if action in ("urgent", "standard"):
            grounded = bool(cited) and all(s in tool_ids for s in cited)
            out.append(f"{_INDENT}grounding check: {'PASS' if grounded else 'FAIL'} (cites in tool_result_ids)")
        bs = c.get("budget_state") or {}
        if bs:
            out.append(
                f"{_INDENT}budget_state: tokens={bs.get('tokens_in', 0)}+{bs.get('tokens_out', 0)}  "
                f"iters={bs.get('iterations', 0)}  wall={float(bs.get('wall_s', 0)):.1f}s / {bs.get('wall_cap_s', '?')}s"
            )
    elif speaker == "approval_gate":
        out.append(
            f"{lbl} approval row id={c.get('approval_id') or '?'}  action={c.get('action')}  "
            f"priority={c.get('priority')}  -> waiting on human"
        )
    elif speaker == "budget_guard":
        out.append(f"{lbl} guard fired: {c.get('reason')}")
        out.append(f"{_INDENT}rationale: {_short(c.get('rationale') or '', 500)}")
    elif speaker == "pipeline":
        if kind == "graph_interrupted":
            out.append(f"{lbl} the service restarted before this case was decided -> routed to a human")
        else:
            out.append(f"{lbl} graph failed: {c.get('error')} -> routed to a human")
    else:
        kv = "  ".join(f"{k}={_short(v, 60)}" for k, v in c.items())
        out.append(f"{lbl} {kind}  {kv}".rstrip())

    llm = c.get("llm")
    if isinstance(llm, dict) and llm.get("calls"):
        out.insert(1, _llm_line(llm))
    ts = entry.get("ts")
    if ts and out:
        out[0] = f"{_clock(ts)} {out[0]}"
        out[1:] = [f"{' ' * 20}{ln}" for ln in out[1:]]
    return out


def _stage_seconds(trace: list[dict]) -> dict[str, float]:
    """Seconds between consecutive entries, attributed to the speaker of the later one."""
    stamped = sorted(
        (float(e["ts"]), str(e.get("speaker") or "?")) for e in trace or [] if isinstance(e, dict) and e.get("ts")
    )
    out: dict[str, float] = {}
    for (t0, _), (t1, speaker) in zip(stamped, stamped[1:]):
        out[speaker] = out.get(speaker, 0.0) + max(0.0, t1 - t0)
    return out


def _contents(trace: list[dict], speaker: str) -> list[dict]:
    return [e["content"] for e in trace or []
            if isinstance(e, dict) and e.get("speaker") == speaker and isinstance(e.get("content"), dict)]


def _justified(reasons: list[str], yes: bool) -> dict:
    return {"justified": yes, "reasons": reasons}


def build_agent_value_summary(trace: list[dict] | None) -> dict | None:
    """Per case: what the tree alone said, what the model proposed, the final verdict, and which agents added a signal."""
    trace = trace or []
    decisions = _contents(trace, "decision")
    guards = _contents(trace, "budget_guard")
    if not decisions and not guards:
        return None
    dec = decisions[-1] if decisions else {}
    final = dec.get("action") or (guards[-1].get("action") if guards else None)

    per: dict[str, dict] = {}
    san = (_contents(trace, "sanitize") or [{}])[-1]
    if san.get("suspicious"):
        per["sanitize"] = _justified(["suspicious_input_caught"], True)
    elif san.get("pii_redacted"):
        per["sanitize"] = _justified(["pii_redacted"], True)
    else:
        per["sanitize"] = _justified(["nothing_to_scrub"], False)

    sig = (_contents(trace, "signal_extractor") or [{}])[-1]
    if not sig.get("has_text"):
        per["signal_extractor"] = _justified(["no_analyst_note"], False)
    elif sig.get("contradictions"):
        per["signal_extractor"] = _justified(["contradiction_found"], True)
    else:
        per["signal_extractor"] = _justified(["note_added_no_signal"], False)

    plan = (_contents(trace, "supervisor") or [{}])[-1]
    if plan.get("force_action"):
        per["supervisor"] = _justified([f"forced_{plan['force_action']}"], True)
    elif plan.get("pipeline_concern") not in (None, "none"):
        per["supervisor"] = _justified([f"concern_{plan['pipeline_concern']}"], True)
    else:
        per["supervisor"] = _justified(["no_concern_raised"], False)

    profiles = _contents(trace, "profile_builder")
    if not profiles:
        per["profile_builder"] = _justified(["not_run"], False)
    elif (profiles[-1].get("catalogue") or {}).get("match"):
        per["profile_builder"] = _justified(["known_pattern_found"], True)
    elif profiles[-1].get("llm_used"):
        per["profile_builder"] = _justified(["llm_refined_profile"], True)
    else:
        per["profile_builder"] = _justified(["no_signal_added"], False)

    rags = _contents(trace, "rag_retriever")
    if not rags:
        per["rag_retriever"] = _justified(["not_run"], False)
    elif rags[-1].get("coverage") in ("direct_match", "partial_match"):
        per["rag_retriever"] = _justified([f"{rags[-1]['coverage']}_retrieved"], True)
    else:
        per["rag_retriever"] = _justified(["no_technique" if rags[-1].get("skipped") else "no_match"], False)

    if not decisions:
        per["decision"] = _justified(["not_reached"], False)
    elif dec.get("floor_applied"):
        per["decision"] = _justified([f"floor_caught_llm:{dec.get('floor_reason')}"], True)
    elif dec.get("source") == "llm_react":
        per["decision"] = _justified(["llm_verdict_stood_on_fact_check"], True)
    else:
        per["decision"] = _justified(["rule_tree_only"], False)

    calls = tok_in = tok_out = 0
    for e in trace:
        llm = (e.get("content") or {}).get("llm") if isinstance(e, dict) and isinstance(e.get("content"), dict) else None
        if isinstance(llm, dict):
            calls += int(llm.get("calls") or 0)
            tok_in += int(llm.get("tokens_in") or 0)
            tok_out += int(llm.get("tokens_out") or 0)
    stamps = [float(e["ts"]) for e in trace if isinstance(e, dict) and e.get("ts")]
    wi = dec.get("worker_impact") or {}
    return {
        "rule_tree_action": dec.get("rule_tree_action"),
        "rule_tree_with_worker_action": wi.get("rule_hint_with_worker_llm") or dec.get("rule_tree_action"),
        "llm_proposed_action": dec.get("llm_proposed_action"),
        "final_action": final,
        "floor_applied": bool(dec.get("floor_applied")),
        "floor_reason": dec.get("floor_reason"),
        "guard_fired": bool(guards),
        "per_agent_justified": per,
        "agents_justified_count": sum(1 for v in per.values() if v["justified"]),
        "agents_total": len(AGENTS),
        "cost": {
            "llm_calls": calls,
            "tokens_in": tok_in,
            "tokens_out": tok_out,
            "wall_seconds": round(max(stamps) - min(stamps), 2) if len(stamps) >= 2 else 0,
            "cost_commercial_equivalent_usd": round(cost_usd(tok_in, tok_out), 6),
        },
    }


def format_trace_lines(
    case_id: str,
    trace: list[dict] | None,
    *,
    metadata: dict | None = None,
    verdict: dict | None = None,
    status: str | None = None,
    header_extra: str = "",
) -> list[str]:
    """Render a run, finished or still in progress, as terminal lines. The footer appears once the run is over."""
    trace = trace or []
    md = metadata or {}
    policy_version = next((e.get("policy") for e in trace if isinstance(e, dict) and e.get("policy")), None)
    extra = "  ".join(x for x in (f"policy={policy_version}" if policy_version else "", header_extra) if x)
    lines = _header(case_id, md, extra)
    engines = _engines_line(md)
    if engines:
        lines.append(engines)
    tool_ids: list[str] = []
    for entry in trace:
        lines.extend(_entry_lines(entry, tool_ids))
    if status in (None, "queued", "processing"):
        return lines

    v = verdict or {}
    lines.append("-" * BAR)
    done = f"[DONE    ] action={str(v.get('action') or '?').upper()}  priority={v.get('priority')}  status={status}"
    stamps = [float(e["ts"]) for e in trace if isinstance(e, dict) and e.get("ts")]
    if len(stamps) >= 2:
        done += f"  elapsed={max(stamps) - min(stamps):.0f}s"
    av = build_agent_value_summary(trace)
    cost = (av or {}).get("cost") or {}
    if cost.get("llm_calls"):
        done += f"  llm calls={cost['llm_calls']}  tokens in={cost['tokens_in']} out={cost['tokens_out']}"
    if stamps:
        done = f"{_clock(max(stamps))} {done}"
    lines.append(done)
    parts = [f"{sp}={secs:.0f}" for sp, secs in _stage_seconds(trace).items() if secs >= 0.5]
    if parts:
        lines.append(f"{_INDENT}stage seconds: " + "  ".join(parts))
    if av:
        flags = []
        if av.get("floor_applied"):
            flags.append(f"floor:{av.get('floor_reason') or 'unnamed'}")
        if av.get("guard_fired"):
            flags.append("guard_fired")
        lines.append(
            f"{_INDENT}agent value: rule_tree={av.get('rule_tree_action') or 'n/a'}  "
            f"with_workers={av.get('rule_tree_with_worker_action') or 'n/a'}  "
            f"llm={av.get('llm_proposed_action') or '-'}  final={av.get('final_action') or 'n/a'}"
            + (f"  flags={','.join(flags)}" if flags else "")
        )
        lines.append(f"{_INDENT}agent justified: {av['agents_justified_count']} of {av['agents_total']} agents")
        for sp in AGENTS:
            row = av["per_agent_justified"].get(sp) or {}
            lines.append(
                f"{_INDENT}  {sp:17s} {'YES' if row.get('justified') else 'NO':3s}  {','.join(row.get('reasons') or []) or '-'}"
            )
        lines.append(
            f"{_INDENT}run cost: llm_calls={cost.get('llm_calls', 0)}  tokens_in={cost.get('tokens_in', 0)}  "
            f"tokens_out={cost.get('tokens_out', 0)}  wall={cost.get('wall_seconds', 0)}s  "
            f"ollama_self_hosted=$0.00  commercial_equivalent=${cost.get('cost_commercial_equivalent_usd', 0):.6f}"
        )
    return lines


def emit_trace(case_id: str, lines: list[str], *, tokens_in: int = 0, tokens_out: int = 0,
               guard_fired: bool = False, elapsed_s: float | None = None) -> None:
    """Print a finished run to stdout in the shape the trace page shows, followed by one metrics line."""
    elapsed = f"elapsed={elapsed_s:.2f}s  " if elapsed_s is not None else ""
    metrics = (
        f"[METRICS ] {elapsed}tokens_in={tokens_in}  tokens_out={tokens_out}  "
        f"cost=${cost_usd(tokens_in, tokens_out):.5f}  guard_fired={guard_fired}"
    )
    for line in ("", *lines, metrics, "=" * BAR, ""):
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            # A console that cannot encode a host or file name still gets the whole block.
            print(line.encode("ascii", "backslashreplace").decode("ascii"), flush=True)

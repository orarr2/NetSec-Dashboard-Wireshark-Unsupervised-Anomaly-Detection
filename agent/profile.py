"""Perception without a model: reads the engines' output into one finding profile."""

from __future__ import annotations

from typing import Any, Mapping

from agent import policy


def _num(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def fired_rules(rule_signals: Mapping[str, Any]) -> list[str]:
    return [r for r in policy.get("engines", "high_precision_rules", default=[]) if rule_signals.get(r)]


def rule_detail(name: str, value: Any) -> str:
    rows = value if isinstance(value, list) else []
    first = rows[0] if rows and isinstance(rows[0], dict) else {}
    if name == "scan_alerts" and first:
        return f"{first.get('type', '?')} x{first.get('count', '?')} to {first.get('unique_dsts', '?')} dst(s)"
    if name == "amp_alerts" and first:
        return f"{first.get('responses', '?')} responses, mean {first.get('mean_size', '?')} B"
    if name == "flood_alerts" and first:
        return (f"{first.get('total_syn', '?')} SYN from {first.get('syn_sources', '?')} source(s), "
                f"{first.get('syn_per_sec', '?')}/s")
    if name == "arp_multi_mac":
        return "one IP claimed by several MACs"
    return "fired"


def own_adv_rows(case: Mapping[str, Any]) -> list[dict]:
    """The candidate's own advanced-engine rows that count as fired. Weaker rows and other devices' rows are not its signals."""
    candidate = str(case.get("candidate_id") or "")
    min_score = float(policy.get("engines", "advanced_fired_min_score"))
    return [r for r in case.get("adv_signals") or []
            if str(r.get("device")) == candidate and (_num(r.get("score")) or 0.0) >= min_score]


def _fusion_score(advanced: Mapping[str, Any], fusion_rows: list[dict], candidate: str) -> float | None:
    block = advanced.get("fusion_score")
    score = _num(block.get("score")) if isinstance(block, dict) else _num(block)
    if score is None:
        scores = [s for s in (_num(r.get("score")) for r in fusion_rows if str(r.get("device")) == candidate)
                  if s is not None]
        score = max(scores) if scores else None
    return score


def _techniques(rules: list[str], fired_rows: list[dict]) -> list[str]:
    out: list[str] = []
    for rule in rules:
        code = policy.get("engines", "rule_technique", rule)
        if code and code not in out:
            out.append(str(code))
    ranked = sorted(fired_rows, key=lambda r: (-(_num(r.get("score")) or 0.0), -int(r.get("count") or 0)))
    for row in ranked:
        code = row.get("technique")
        if code and str(code) not in out:
            out.append(str(code))
    return out


def build_profile(case: Mapping[str, Any]) -> dict:
    context = case.get("context") or {}
    rule_signals = context.get("rule_signals") or {}
    ml = context.get("ml_signals") or {}
    advanced = context.get("advanced_signals") or {}
    asset = dict(case.get("asset") or {})
    quality = case.get("quality") or {}

    rules = fired_rules(rule_signals)
    iso = _num(ml.get("iso_score"))
    ml_flags = []
    if ml.get("anomaly") is True:
        ml_flags.append("isolation_forest")
    if ml.get("cluster") == -1:
        ml_flags.append("dbscan_noise")
    if int(ml.get("lstm_bin_flag_count") or 0) > 0:
        ml_flags.append("lstm")
    ml_agrees = "isolation_forest" in ml_flags
    ml_strong = ml_agrees and iso is not None and iso <= float(policy.get("engines", "ml_strong_iso_score_max"))

    min_adv = float(policy.get("engines", "advanced_fired_min_score"))
    candidate = str(case.get("candidate_id") or "")
    adv_fired = []
    for name in policy.get("engines", "advanced", default=[]):
        block = advanced.get(name)
        score = _num(block.get("score")) if isinstance(block, dict) else None
        if score is not None and score >= min_adv:
            adv_fired.append(name)
    # The per-signal rows carry engines the context block has no slot for (ARP, DHCP, JA3, SNI).
    fired_rows = own_adv_rows(case)
    for row in fired_rows:
        name = str(row.get("signal") or "")
        if name and name not in adv_fired:
            adv_fired.append(name)
    fusion = _fusion_score(advanced, list(case.get("fusion") or []), candidate)
    fusion_strong = fusion is not None and fusion >= float(policy.get("engines", "fusion_strong_min_score"))

    techniques = _techniques(rules, fired_rows)
    primary = techniques[0] if techniques else None

    if fusion is not None:
        score = fusion
    elif rules:
        score = 0.9 if ml_agrees else 0.7
    elif adv_fired:
        score = 0.6
    elif ml_strong:
        score = 0.5
    elif ml_agrees:
        score = 0.3
    elif ml_flags:
        score = 0.15
    else:
        score = 0.0
    band = "strong" if score >= 0.7 else "mid" if score >= 0.4 else "weak" if score > 0 else "none"

    asset["critical"] = bool(
        asset.get("is_my_device") or asset.get("is_declared_infra") or asset.get("targets_infra")
        or asset.get("role") in policy.get("asset", "critical_roles", default=[])
    )
    nothing = not rules and not ml_flags and not adv_fired and (fusion is None or fusion < min_adv)

    scope = str(case.get("kind") or "ip")
    session_rules = policy.get("decision", "urgent", "session_scope_rules", default=[])
    aggregate_event = scope == "session" and any(r in session_rules for r in rules)
    if (rules and ml_agrees and asset["critical"]) or aggregate_event:
        severity = "severe"
    elif rules:
        severity = "high"
    elif adv_fired or ml_strong:
        severity = "moderate"
    elif ml_flags:
        severity = "low"
    else:
        severity = "none"

    if rules:
        confidence = "high" if ml_agrees else "medium"
    elif adv_fired:
        confidence = "medium" if ml_agrees else "low"
    elif ml_agrees:
        confidence = "medium"
    elif ml_flags:
        confidence = "high"
    else:
        confidence = "low"

    warnings = []
    duration = _num(quality.get("duration_s"))
    if duration is not None and duration < 60:
        warnings.append("short_capture")
    packets = _num(quality.get("total_packets"))
    if packets is not None and packets < 1000:
        warnings.append("few_packets")
    if not quality.get("lstm_ran"):
        warnings.append("lstm_not_run")
    if quality.get("self_telemetry"):
        warnings.append("self_telemetry")
    if quality.get("gaps"):
        warnings.append("capture_gaps")

    history = context.get("baseline_history") or {}
    return {
        "scope": scope,
        "primary_technique": primary,
        "other_techniques": techniques[1:],
        "engines_fired": {"rules": rules, "ml": ml_flags, "advanced": adv_fired},
        "rule_details": {r: rule_detail(r, rule_signals.get(r)) for r in rules},
        "iso_score": iso,
        "fusion_score": fusion,
        "fusion_strong": fusion_strong,
        "score": round(float(score), 2),
        "score_band": band,
        "ml_agrees": ml_agrees,
        "ml_strong": ml_strong,
        "asset": asset,
        "recurrence": {
            "seen_before": history.get("seen_before"),
            "days_since_first_seen": history.get("days_since_first_seen"),
            "prior_verdict_summary": history.get("prior_verdict_summary"),
        },
        "quality_warnings": warnings,
        "severity": severity,
        "detector_found_nothing": nothing,
        "confidence": confidence,
    }

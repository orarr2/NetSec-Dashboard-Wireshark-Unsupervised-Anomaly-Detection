"""The deterministic baseline under the model (the rule tree) and the floors applied over a model verdict."""

from __future__ import annotations

from typing import Any, Mapping

from agent import policy


def _verdict(action: str, priority_name: str, reason: str, rationale: str, source: str = "rule_based") -> dict:
    return {
        "action": action,
        "priority": policy.priority(priority_name),
        "reason": reason,
        "rationale": f"{reason}: {rationale}"[:500],
        "source": source,
    }


def urgent_preconditions(profile: Mapping[str, Any]) -> tuple[bool, list[str]]:
    cfg = policy.get("decision", "urgent", default={})
    fired = (profile.get("engines_fired") or {}).get("rules") or []
    missing = []
    if not any(r in cfg.get("rules", []) for r in fired):
        missing.append("rule_in_" + "_or_".join(cfg.get("rules", [])))
    if cfg.get("requires_ml_agreement") and not profile.get("ml_agrees"):
        missing.append("ml_agreement")
    if cfg.get("requires_critical_asset") and not (profile.get("asset") or {}).get("critical"):
        missing.append("critical_asset")
    return (not missing, missing)


def _suspicious_where(sanitized: Mapping[str, Any]) -> str:
    parts = []
    if sanitized.get("traffic_suspicious"):
        parts.append("a traffic string")
    if sanitized.get("note_suspicious"):
        parts.append("the analyst note")
    return " and ".join(parts) or "the input"


def _asset_why(asset: Mapping[str, Any]) -> str:
    if asset.get("is_my_device"):
        return "my device"
    if asset.get("is_declared_infra"):
        return "declared infrastructure"
    if asset.get("targets_infra"):
        return "it targets declared infrastructure"
    return f"role {asset.get('role')}"


def decide_rule_based(
    *,
    profile: Mapping[str, Any] | None,
    research: Mapping[str, Any] | None = None,
    sanitized: Mapping[str, Any] | None = None,
    intake: Mapping[str, Any] | None = None,
    catalogue: Mapping[str, Any] | None = None,
) -> dict:
    """The verdict of the policy alone. The first matching branch wins."""
    profile, research = profile or {}, research or {}
    sanitized, intake, catalogue = sanitized or {}, intake or {}, catalogue or {}

    if sanitized.get("suspicious"):
        return _verdict(
            "human_review", "human_review_suspicious_input", "suspicious_input",
            f"suspicious text in {_suspicious_where(sanitized)}; routed to a human and no model output is trusted.")
    if catalogue.get("match"):
        return _verdict(
            "known_pattern", "known_pattern", "known_pattern",
            f"the same capture and candidate were already judged and approved (catalogue {catalogue.get('id')}); "
            "sealed without running models.", source="catalog_match")
    if intake.get("contradictions"):
        return _verdict(
            "human_review", "human_review", "intake_contradiction",
            f"the analyst note names {', '.join(intake.get('mentioned') or []) or 'a technique'} "
            "but no engine reported it; the contradiction is routed to a human.")
    if not profile:
        return _verdict("human_review", "human_review", "no_profile", "no finding profile was built; routed to a human.")
    if profile.get("detector_found_nothing"):
        return _verdict(
            "human_review", "human_review_nothing", "nothing_to_triage",
            "no engine fired and the score is below the threshold: nothing to triage; routed to a human.")
    technique = profile.get("primary_technique")
    if technique and research.get("coverage") == "no_match":
        return _verdict(
            "human_review", "human_review", "coverage_no_match",
            f"no source was found for technique {technique}; routed to a human.")

    engines = profile.get("engines_fired") or {}
    rules = engines.get("rules") or []
    if rules:
        ok, missing = urgent_preconditions(profile)
        if ok:
            return _verdict(
                "urgent", "urgent", "urgent_preconditions_met",
                f"{', '.join(rules)} fired, IsolationForest agrees and the asset is critical "
                f"({_asset_why(profile.get('asset') or {})}); containment or escalation is proposed and waits for approval.")
        if profile.get("ml_agrees"):
            return _verdict(
                "standard", "standard_rule_with_ml", "rule_fired_with_ml",
                f"deterministic rule(s) {', '.join(rules)} fired and IsolationForest agrees; a ticket is drafted "
                f"(urgent is not met: {', '.join(missing)}).")
        return _verdict(
            "standard", "standard_rule", "rule_fired",
            f"deterministic rule(s) {', '.join(rules)} fired without IsolationForest agreement; a ticket is drafted.")

    advanced = engines.get("advanced") or []
    if advanced:
        if profile.get("fusion_strong") and profile.get("ml_agrees"):
            return _verdict(
                "standard", "standard_advanced", "advanced_with_ml",
                f"advanced engine(s) {', '.join(advanced)} fired with fusion score {profile.get('fusion_score')} "
                "and IsolationForest agrees; a ticket is drafted.")
        lacking = []
        if not profile.get("fusion_strong"):
            lacking.append("a strong fusion score")
        if not profile.get("ml_agrees"):
            lacking.append("IsolationForest agreement")
        return _verdict(
            "human_review", "human_review_advanced_unconfirmed", "advanced_unconfirmed",
            f"advanced engine(s) {', '.join(advanced)} fired without {' and '.join(lacking)}; ambiguous, routed to a human.")

    if profile.get("ml_strong"):
        return _verdict(
            "human_review", "human_review_strong_ml", "strong_ml_anomaly",
            f"a strong IsolationForest outlier (iso_score {profile.get('iso_score')}) with no rule and no advanced "
            "engine; routed to a human.")
    ml = engines.get("ml") or []
    if profile.get("ml_agrees"):
        return _verdict(
            "monitor", "monitor_ml_anomaly", "ml_anomaly_only",
            f"only the ML layer flagged the candidate ({', '.join(ml)}; iso_score {profile.get('iso_score')}), "
            "with no rule and no advanced engine; kept under monitoring without a ticket.")
    if ml:
        return _verdict(
            "monitor", "monitor_noise", "ml_noise_only",
            f"only {', '.join(ml)} flagged the candidate; kept under monitoring without a ticket.")
    return _verdict(
        "human_review", "human_review", "unclassified",
        "the signals fit no branch of the policy; routed to a human.")


def apply_floors(
    llm_verdict: Mapping[str, Any],
    *,
    tree_verdict: Mapping[str, Any],
    profile: Mapping[str, Any] | None,
    research: Mapping[str, Any] | None = None,
    sanitized: Mapping[str, Any] | None = None,
    intake: Mapping[str, Any] | None = None,
    catalogue: Mapping[str, Any] | None = None,
) -> dict:
    """A model verdict after the floors. A floor moves it toward a human or up to the tree's verdict, never down."""
    profile, research = profile or {}, research or {}
    sanitized, intake, catalogue = sanitized or {}, intake or {}, catalogue or {}
    action = str(llm_verdict.get("action") or "")
    rules = (profile.get("engines_fired") or {}).get("rules") or []
    coverage = research.get("coverage")
    sufficiency = (research.get("decision_coverage") or {}).get("sufficiency")
    missing_q = (research.get("decision_coverage") or {}).get("missing") or []
    urgent_ok, urgent_missing = urgent_preconditions(profile)
    human = "human_review"

    checks: list[tuple[str, bool, str, str]] = [
        ("suspicious_input", bool(sanitized.get("suspicious")) and action != human, human,
         _suspicious_where(sanitized)),
        ("intake_contradiction", bool(intake.get("contradictions")) and action != human, human,
         ",".join(intake.get("mentioned") or [])),
        ("nothing_to_triage", bool(profile.get("detector_found_nothing")) and action != human, human,
         "no engine fired"),
        ("known_pattern_without_catalogue_match", action == "known_pattern" and not catalogue.get("match"), human,
         "no catalogue match on pcap sha256 + candidate"),
        ("urgent_preconditions_not_met", action == "urgent" and not urgent_ok, human, ",".join(urgent_missing)),
        ("coverage_no_match", bool(profile.get("primary_technique")) and coverage == "no_match" and action != human,
         human, f"technique {profile.get('primary_technique')}"),
        ("rag_insufficient_coverage",
         action == "standard" and sufficiency == "insufficient_coverage" and not catalogue.get("match"), human,
         ",".join(missing_q)),
        ("rule_fired", bool(rules) and action == "monitor", str(tree_verdict.get("action") or human),
         ",".join(rules)),
    ]
    for name, fired, to_action, trigger in checks:
        if not fired:
            continue
        final = dict(llm_verdict)
        same_as_tree = to_action == tree_verdict.get("action")
        final.update(
            action=to_action,
            priority=int(tree_verdict["priority"]) if same_as_tree else policy.priority("human_review"),
            reason=name,
            rationale=f"{name}: the model proposed {action or 'nothing'} but the floor applies ({trigger}); "
                      f"the verdict is {to_action}."[:500],
            source="rule_based",
            floor_applied=True,
            floor_reason=name,
            floor_trigger=trigger,
            overridden_llm_verdict={"action": action, "priority": llm_verdict.get("priority")},
        )
        return final
    final = dict(llm_verdict)
    final.setdefault("source", "llm_react")
    final["floor_applied"] = False
    return final

"""The model's JSON is repaired, grounded against the retrieved sources and fact-checked against the case."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from agent import policy

_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[\]}])")
_INVENTED_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def repair_json(text: str) -> dict:
    """The model's reply as a dict, after the common repairs: fences, trailing commas, surrounding prose."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty model reply")
    candidate = text.strip()
    match = _FENCE.search(candidate)
    if match:
        candidate = match.group(1).strip()
    # The object may be wrapped by one line of prose on each side; keep what is between the first { and last }.
    first, last = candidate.find("{"), candidate.rfind("}")
    if 0 <= first < last:
        candidate = candidate[first:last + 1]
    candidate = _TRAILING_COMMA.sub(r"\1", candidate)
    parsed = json.loads(candidate)
    if not isinstance(parsed, dict):
        raise ValueError(f"the model reply is not a JSON object (got {type(parsed).__name__})")
    return parsed


def deterministic_rationale(verdict: Mapping[str, Any], profile: Mapping[str, Any] | None = None) -> str:
    """A plain sentence that names the facts behind a verdict, without any phrase the model wrote."""
    profile = profile or {}
    action = str(verdict.get("action") or "?")
    reason = str(verdict.get("reason") or verdict.get("floor_reason") or "")
    engines = profile.get("engines_fired") or {}
    rules = ", ".join(engines.get("rules") or []) or "no rule"
    technique = profile.get("primary_technique") or "no technique"
    severity = profile.get("severity") or "unknown"
    confidence = profile.get("confidence") or "unknown"
    return (
        f"{action}: {reason or 'policy baseline'}. engines rules={rules}, technique={technique}, "
        f"severity={severity}, confidence={confidence}; the model text was replaced because it did not pass "
        f"the fact check."
    )[:500]


def verify(
    verdict: Mapping[str, Any],
    *,
    case: Mapping[str, Any],
    profile: Mapping[str, Any] | None = None,
    research: Mapping[str, Any] | None = None,
    sanitized: Mapping[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Check the model's verdict against what the engines said. Returns (ok, reasons the check failed)."""
    profile, research, sanitized = profile or {}, research or {}, sanitized or {}
    reasons: list[str] = []

    # The action and the priority must be ones the policy knows.
    actions = set(policy.get("actions", default=[]))
    action = str(verdict.get("action") or "")
    if action not in actions:
        reasons.append(f"unknown_action: {action!r}")
    priorities = set(policy.get("priority", default={}).values())
    try:
        priority = int(verdict.get("priority") or 0)
    except (TypeError, ValueError):
        priority = -1
    if priority not in priorities:
        reasons.append(f"priority_outside_policy: {priority}")

    # The rationale must be free of the shapes that mislead a reader.
    rationale = str(verdict.get("rationale") or "")
    if not rationale.strip():
        reasons.append("empty_rationale")
    if len(rationale) > 500:
        reasons.append("rationale_too_long")

    # A claim about the analyst note is false when there is no note.
    note = (sanitized.get("note") or {})
    mentions_note = re.search(r"\b(analyst|reporter|the note)\b", rationale, re.IGNORECASE)
    if mentions_note and not note.get("has_text"):
        reasons.append("rationale_claims_analyst_note_without_one")

    # A claim about a catalogue match is false when there is none.
    if re.search(r"\b(catalog|known pattern|catalogued)\b", rationale, re.IGNORECASE):
        if not (research.get("catalogue") or {}).get("match") and action != "known_pattern":
            reasons.append("rationale_claims_catalogue_without_one")

    # Every technique the rationale names must be one of the engines' techniques or a sub-technique's parent.
    allowed = {profile.get("primary_technique"), *(profile.get("other_techniques") or [])}
    allowed |= {str(t).split(".")[0] for t in allowed if t}
    allowed.discard(None)
    for found in _INVENTED_TECHNIQUE.findall(rationale):
        parent = found.split(".")[0]
        if found not in allowed and parent not in allowed:
            reasons.append(f"invented_technique: {found}")

    # Every cited source must be an id the retrieval step returned, and some actions must cite at least one.
    ids = {str(i) for i in research.get("tool_result_ids") or []}
    cited = [str(c) for c in verdict.get("cited_sources") or []]
    unknown = [c for c in cited if c not in ids]
    if unknown:
        reasons.append("ungrounded_citation: " + ",".join(unknown))
    allow_empty = set(policy.get("grounding", "allow_empty_citations", default=[]))
    if not cited and action and action not in allow_empty:
        reasons.append("no_citation_for_" + action)

    return (not reasons, reasons)

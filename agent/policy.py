"""Loads policy.yaml once; the rule tree and the Decision prompt both read it from here."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_PATH = Path(__file__).with_name("policy.yaml")


def load_policy(path: str | os.PathLike | None = None) -> dict[str, Any]:
    target = Path(path or os.environ.get("NETSEC_AGENT_POLICY_PATH") or _DEFAULT_PATH)
    with target.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not data.get("version"):
        raise ValueError(f"{target} is not a policy file with a version")
    return data


POLICY: dict[str, Any] = load_policy()
POLICY_VERSION: str = str(POLICY["version"])


def get(*keys: str, default: Any = None) -> Any:
    node: Any = POLICY
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def priority(name: str) -> int:
    return int(get("priority", name, default=get("priority", "human_review", default=55)))


def render_policy_rules() -> str:
    """The policy as plain text for the Decision prompt, so the model reads the tree's own rules."""
    urgent = get("decision", "urgent", default={})
    lines = [
        f"POLICY version {POLICY_VERSION}",
        f"Actions: {', '.join(get('actions', default=[]))}.",
        "urgent: one of the rules "
        f"{', '.join(urgent.get('rules', []))} fired"
        + (", IsolationForest agrees" if urgent.get("requires_ml_agreement") else "")
        + (", and the asset is critical (my device, declared infrastructure, or a critical role)"
           if urgent.get("requires_critical_asset") else "")
        + ". On a session-level candidate (an aggregate event with no ML score and no asset) the rule "
        + f"{', '.join(urgent.get('session_scope_rules', []))} is enough. urgent always waits for a human approval.",
        "standard: " + "; or ".join(get("decision", "standard", "when", default=[])) + ".",
        "monitor: " + "; or ".join(get("decision", "monitor", "when", default=[])) + ".",
        "known_pattern: " + str(get("decision", "known_pattern", "requires", default="")) + ".",
        "human_review when any of:",
    ]
    lines += [f"  - {t}" for t in get("decision", "human_review", "triggers", default=[])]
    lines.append("Floors applied over your verdict: " + ", ".join(get("floors", default=[])) + ".")
    return "\n".join(lines)

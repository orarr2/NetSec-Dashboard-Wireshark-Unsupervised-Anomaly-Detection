"""Research tool. Until the corpus is built (phase P3) the backend is a small static technique table."""

from __future__ import annotations

from agent import policy

BACKEND = "static_table"

# One line per ATT&CK technique the NETSEC engines can name. A stand-in for the
# corpus: it tells Decision what the technique is, and deliberately answers none
# of the operational questions (containment, severity, false positives).
_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {
        "title": "Network Service Discovery",
        "tactic": "Discovery",
        "text": "A host probes addresses and ports to learn which services answer on the network.",
    },
    "T1498.001": {
        "title": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "text": "High-volume traffic is sent straight at a target to exhaust its bandwidth or its connection state.",
    },
    "T1498.002": {
        "title": "Network Denial of Service: Reflection Amplification",
        "tactic": "Impact",
        "text": "Small spoofed requests make third-party servers send much larger replies to the victim.",
    },
    "T1557": {
        "title": "Adversary-in-the-Middle",
        "tactic": "Credential Access, Collection",
        "text": "A host places itself between two parties so that their traffic passes through it.",
    },
    "T1557.002": {
        "title": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tactic": "Credential Access, Collection",
        "text": "Forged ARP replies bind another host's IP to the sender's MAC, so the victim's traffic is sent to it.",
    },
    "T1071": {
        "title": "Application Layer Protocol",
        "tactic": "Command and Control",
        "text": "Control traffic is carried inside a common application protocol so that it blends with normal use.",
    },
    "T1071.001": {
        "title": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "text": "Control traffic is carried over HTTP or HTTPS and looks like ordinary web browsing.",
    },
    "T1071.004": {
        "title": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "text": "Control traffic or data is carried inside DNS queries and replies.",
    },
    "T1090": {
        "title": "Proxy",
        "tactic": "Command and Control",
        "text": "Traffic is relayed through an intermediary so that its real destination is hidden.",
    },
    "T1568.002": {
        "title": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "text": "Many algorithmically generated domain names are tried until one resolves to the controller.",
    },
}


def query_security_standards(technique: str | None, asset_role: str | None = None, k: int | None = None) -> dict:
    """Sources about a technique: procedures with ids, topic coverage, and whether they answer the policy's questions."""
    k = int(k or policy.get("research", "top_k", default=3))
    questions = list(policy.get("research", "questions", default=[]))
    query = f"security guidance for technique {technique or 'unknown'} (asset role: {asset_role or 'unknown'}): " \
            f"{', '.join(questions)}"
    out = {
        "backend": BACKEND,
        "rag_query": query,
        "rag_filter": {"technique": technique, "asset_role": asset_role or "unknown", "k": k},
        "procedures": [],
        "tool_result_ids": [],
        "coverage": "no_match",
        "decision_coverage": {"answered": [], "missing": questions, "sufficiency": "insufficient_coverage"},
    }
    if not technique:
        out["coverage"] = "not_applicable"
        return out
    code = str(technique)
    hit, support = (_TECHNIQUES.get(code), "direct")
    if hit is None and "." in code:
        hit, support = (_TECHNIQUES.get(code.split(".")[0]), "parent")
        code = code.split(".")[0] if hit else code
    if hit is None:
        return out
    proc = {
        "id": f"attack:{code}",
        "title": hit["title"],
        "tactic": hit["tactic"],
        "text": hit["text"],
        "distance": 0.0 if support == "direct" else 0.5,
        "support": support,
    }
    out["procedures"] = [proc][:k]
    out["tool_result_ids"] = [proc["id"]]
    out["coverage"] = "direct_match" if support == "direct" else "partial_match"
    return out

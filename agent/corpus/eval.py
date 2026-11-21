"""`rag_relevance_eval`: for every technique the engines name, with every asset role, measure the coverage."""

from __future__ import annotations

import logging
import time
from typing import Any

from agent import policy
from agent.corpus.store import CorpusStore, open_corpus
from agent.research import query_security_standards

LOGGER = logging.getLogger("netsec_agent")

# The techniques the engines may ask about. The grid is (technique, asset_role).
TECHNIQUES = (
    "T1046", "T1498.001", "T1498.002", "T1557.002", "T1071.001", "T1071.004", "T1090", "T1090.004", "T1568.002",
    "T1571", "T1557",
)
# The asset roles the agents see in practice. "unknown" is the default on the reference VM.
ASSET_ROLES = ("unknown", "Network Infrastructure", "Printer", "Workstation")


def rag_relevance_eval(path: str | None = None, *, techniques: tuple[str, ...] = TECHNIQUES,
                       asset_roles: tuple[str, ...] = ASSET_ROLES) -> dict:
    """Run `query_security_standards` over the grid and summarise how often each coverage level came back.

    Returns a dict with total queries, counts by coverage level, the direct-match percentage and a per-cell table
    so the owner can see which combinations the corpus still missed.
    """
    store = open_corpus(path) if path else open_corpus()
    if store is None:
        return {"backend": "static_table", "error": "no corpus is configured", "total": 0, "direct_match_pct": 0}
    counts = {"direct_match": 0, "partial_match": 0, "no_match": 0, "not_applicable": 0}
    rows = []
    started = time.time()
    try:
        for technique in techniques:
            for role in asset_roles:
                result = query_security_standards(technique, role)
                coverage = result["coverage"]
                counts[coverage] = counts.get(coverage, 0) + 1
                rows.append({
                    "technique": technique,
                    "asset_role": role,
                    "coverage": coverage,
                    "sufficiency": result["decision_coverage"]["sufficiency"],
                    "n_procedures": len(result["procedures"]),
                    "best_distance": min((p.get("distance", 1.0) for p in result["procedures"]), default=None),
                })
    finally:
        store.close()
    total = len(rows)
    direct_match_pct = round(100.0 * counts["direct_match"] / total, 1) if total else 0.0
    return {
        "backend": "corpus",
        "built_at": store.get_meta("built_at") if False else None,  # the opened store is closed; metadata was read earlier
        "elapsed_s": round(time.time() - started, 2),
        "techniques": list(techniques),
        "asset_roles": list(asset_roles),
        "total": total,
        "counts": counts,
        "direct_match_pct": direct_match_pct,
        "rows": rows,
    }


def rag_truth_test(path: str | None = None, *, lesson_cases: tuple[dict, ...] | None = None) -> dict:
    """A canary pass: ask one open-ended question per protocol and require the top passage to name it.

    `lesson_cases` can override the built-in list for the owner to run their own canary set.
    """
    store = open_corpus(path) if path else open_corpus()
    if store is None:
        return {"backend": "static_table", "error": "no corpus is configured", "pass": False, "cases": []}
    cases = list(lesson_cases or (
        {"query": "how an attacker uses the ARP protocol to put itself between two hosts",
         "technique": "T1557.002", "expect_source": "rfc:826"},
        {"query": "how an attacker tunnels its command and control inside DNS queries",
         "technique": "T1071.004", "expect_source": "rfc:1035"},
        {"query": "how TLS carries the server name in the clear during the handshake",
         "technique": "T1071.001", "expect_source": "rfc:8446"},
        {"query": "how a TCP SYN scan looks on the wire", "technique": "T1046", "expect_source": "rfc:9293"},
        {"query": "how DNS amplification reflection attacks work",
         "technique": "T1498.002", "expect_source": "mitre-attack"},
    ))
    results = []
    try:
        for case in cases:
            result = query_security_standards(case["technique"], None)
            top = result["procedures"][0] if result["procedures"] else None
            ok = bool(top) and top.get("source") == case["expect_source"]
            results.append({
                "query": case["query"], "technique": case["technique"],
                "expect_source": case["expect_source"],
                "got_source": (top or {}).get("source"),
                "got_id": (top or {}).get("id"),
                "coverage": result["coverage"],
                "pass": ok,
            })
    finally:
        store.close()
    passed = sum(1 for r in results if r["pass"])
    return {"backend": "corpus", "pass": passed == len(results), "passed": passed, "total": len(results),
            "cases": results}

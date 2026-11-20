"""Candidate payloads in the shape NETSEC stores them: a `candidates.context_json` plus the rows around it."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

HERE = Path(__file__).parent
SHA256 = "ab" * 32

# One alert per rule, with the fields the NETSEC rule engine writes.
RULE_SAMPLES: dict[str, Any] = {
    "scan_alerts": [{"type": "SYN", "count": 800, "unique_dsts": 40, "ratio": 0.98}],
    "amp_alerts": [{"responses": 300, "mean_size": 1200.0}],
    "flood_alerts": [{"total_syn": 60000, "syn_sources": 31000, "syn_per_sec": 5200.0,
                      "syn_per_source": 1.9, "spoofed_source_pattern": True}],
    "arp_multi_mac": True,
}


def load_vm_candidates() -> dict[str, dict]:
    """The candidates exported from the reference machine, keyed `<session id>:<candidate id>`."""
    rows = json.loads((HERE / "fixtures" / "vm_candidates.json").read_text(encoding="utf-8"))
    return {f"{r['session']['id']}:{r['candidate_id']}": r for r in rows}


def load_scenarios() -> list[dict]:
    return json.loads((HERE / "eval_scenarios.json").read_text(encoding="utf-8"))


def deep_merge(base: Any, patch: Any) -> Any:
    """Dicts merge key by key; anything else is replaced."""
    if isinstance(base, dict) and isinstance(patch, dict):
        out = dict(base)
        for key, value in patch.items():
            out[key] = deep_merge(base.get(key), value)
        return out
    return copy.deepcopy(patch)


def _hosts(names: Iterable[str]) -> list[dict] | None:
    return [{"count": 3, "host": name} for name in names] or None


def make_payload(
    candidate: str = "10.0.0.5",
    *,
    kind: str = "ip",
    session_id: int | None = 900,
    sha256: str = SHA256,
    pcap_name: str = "synthetic.pcap",
    rules: Iterable[str] = (),
    ml: Mapping[str, Any] | None = None,
    advanced: Mapping[str, float] | None = None,
    adv_rows: Iterable[Mapping[str, Any]] = (),
    fusion: float | None = None,
    note: str = "",
    category: str = "unknown",
    hostname: str | None = None,
    reverse_dns: str | None = None,
    dns: Iterable[str] = (),
    http_hosts: Iterable[str] = (),
    sni: Iterable[str] = (),
    duration_s: float = 600.0,
    packets: int = 20000,
    ips: int = 12,
) -> dict:
    """A quiet candidate by default: no rule, no ML flag, no advanced engine. Arguments switch signals on."""
    rule_signals: dict[str, Any] = {"scan_alerts": [], "flood_alerts": [], "amp_alerts": [], "arp_multi_mac": False}
    for name in rules:
        rule_signals[name] = copy.deepcopy(RULE_SAMPLES[name])
    ml_signals: dict[str, Any] = {"iso_score": 0.05, "iso_stability": 1.0, "anomaly": False, "cluster": 0,
                                  "silhouette": None, "lstm_bin_flag_count": None}
    ml_signals.update(ml or {})
    advanced_signals: dict[str, Any] = {"beaconing": None, "dns_tunneling": None, "dga": None,
                                        "tls_anomaly": None, "fusion_score": None}
    for name, score in (advanced or {}).items():
        advanced_signals[name] = {"score": score, "severity": "medium", "count": 4, "peer": "203.0.113.7"}
    rows = [{"device": candidate, "peer": None, "detail": "", "count": 1, "severity": "medium", "tactic": "",
             **row} for row in adv_rows]
    fusion_rows: list[dict] = []
    if fusion is not None:
        advanced_signals["fusion_score"] = {"score": fusion, "techniques": max(1, len(rows))}
        fusion_rows = [{"device": candidate, "score": fusion, "engines_hit": max(1, len(rows)), "window_start": None}]
    session: dict[str, Any] = {"label": "synthetic", "pcap_sha256": sha256, "orig_name": pcap_name, "kind": "prod",
                               "status": "done", "n_pkts": packets, "n_ips": ips, "duration_s": duration_s}
    if session_id is not None:
        session["id"] = session_id
    return {
        "session": session,
        "candidate_id": candidate,
        "kind": kind,
        "rank": 0,
        "context": {
            "candidate_id": candidate,
            "kind": kind,
            "session_context": {"duration_s": duration_s, "total_packets": packets, "total_ips": ips},
            "features": {},
            "ml_signals": ml_signals,
            "rule_signals": rule_signals,
            "advanced_signals": advanced_signals,
            "device_context": {"category": category, "hostname": hostname, "oui_vendor": None},
            "websites": {"top_dns_queries": _hosts(dns), "top_http_hosts": _hosts(http_hosts),
                         "top_tls_sni": _hosts(sni)},
            "traffic": {},
            "tls": {},
            "baseline_history": {"seen_before": None, "days_since_first_seen": None, "prior_verdict_summary": None},
            "enrichments": {"is_private": True, "reverse_dns": reverse_dns, "asn": None,
                            "baseline_seen_before": None},
            "trigger_reasons": [],
        },
        "findings": [],
        "adv_signals": rows,
        "fusion": fusion_rows,
        "ip_features": {},
        "analyst_note": note,
    }


def scenario_payload(scenario: Mapping[str, Any], vm_candidates: Mapping[str, dict]) -> dict:
    """A scenario starts from a real candidate (`base`), a literal payload (`raw`) or the builder (`build`)."""
    if scenario.get("base"):
        payload = copy.deepcopy(vm_candidates[scenario["base"]])
    elif "raw" in scenario:
        payload = copy.deepcopy(scenario["raw"])
    else:
        payload = make_payload(**scenario.get("build", {}))
    return deep_merge(payload, scenario.get("patch") or {})

"""Turns one NETSEC candidate (context_json plus its findings, signals and scores) into a case the graph can run."""

from __future__ import annotations

import os
from typing import Any, Mapping


def _split(value: str | None) -> set[str]:
    return {x.strip() for x in (value or "").split(",") if x.strip()}


def normalize_case(payload: Mapping[str, Any], env: Mapping[str, str] | None = None) -> dict:
    """Fill every block the nodes read, with one place for every default."""
    env = os.environ if env is None else env
    context = dict(payload.get("context") or {})
    session = dict(payload.get("session") or {})
    session_ctx = context.get("session_context") or {}
    ml = context.get("ml_signals") or {}
    device = context.get("device_context") or {}
    enrich = context.get("enrichments") or {}
    features = dict(payload.get("ip_features") or {})
    adv_rows = [dict(r) for r in payload.get("adv_signals") or [] if isinstance(r, dict)]
    candidate = str(payload.get("candidate_id") or context.get("candidate_id") or "")

    my_device = (env.get("NETSEC_MY_DEVICE_IP") or "").strip()
    infra = _split(env.get("NETSEC_INFRA_DSTS"))
    peers = {str(r.get("peer")) for r in adv_rows if r.get("peer") and str(r.get("device")) == candidate}

    return {
        "session_id": session.get("id", payload.get("session_id")),
        "session_label": session.get("label") or "",
        "pcap_sha256": str(session.get("pcap_sha256") or payload.get("pcap_sha256") or "").lower(),
        "pcap_name": session.get("orig_name") or payload.get("pcap_name") or "",
        "candidate_id": candidate,
        "kind": str(payload.get("kind") or context.get("kind") or "ip"),
        "context": context,
        "findings": [dict(r) for r in payload.get("findings") or [] if isinstance(r, dict)],
        "adv_signals": adv_rows,
        "fusion": [dict(r) for r in payload.get("fusion") or [] if isinstance(r, dict)],
        "ip_features": features,
        "analyst_note": str(payload.get("analyst_note") or ""),
        "asset": {
            "role": str(device.get("category") or "unknown"),
            "oui_vendor": device.get("oui_vendor"),
            "hostname": device.get("hostname"),
            "is_private": enrich.get("is_private"),
            "is_my_device": bool(my_device) and candidate == my_device,
            "is_declared_infra": candidate in infra,
            "targets_infra": bool(infra & peers),
        },
        "quality": {
            "duration_s": session_ctx.get("duration_s", session.get("duration_s")),
            "total_packets": session_ctx.get("total_packets", session.get("n_pkts")),
            "total_ips": session_ctx.get("total_ips", session.get("n_ips")),
            "lstm_ran": ml.get("lstm_bin_flag_count") is not None,
            "self_telemetry": bool(features.get("self_telemetry")),
            "gaps": int(payload.get("gaps") or 0),
        },
    }


def case_metadata(case: Mapping[str, Any], profile: Mapping[str, Any] | None = None) -> dict:
    """The few fields the trace header and the report show about a case."""
    profile = profile or {}
    asset = case.get("asset") or {}
    return {
        "candidate_id": case.get("candidate_id"),
        "kind": case.get("kind"),
        "session_id": case.get("session_id"),
        "pcap_name": case.get("pcap_name"),
        "pcap_sha256": case.get("pcap_sha256"),
        "technique": profile.get("primary_technique"),
        "score": profile.get("score"),
        "asset_role": asset.get("role"),
        "engines": profile.get("engines_fired"),
    }

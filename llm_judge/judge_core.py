"""Core of the LLM-as-Judge triage layer (design: docs/LLM_JUDGE_SPEC.md).

Standalone by design: nothing here imports from app/ or from the main
dashboard notebook. The only upstream contract is the S-dict / findings
shape produced by attack_tests/run_pipeline.py - the same code paths the
dashboard runs - which the judge notebook feeds in.

Flow (one PCAP):
    S = analyze_pcap(...); run_ml_on_session(S); findings = run_security_scans(S)
    candidates = assemble_candidates(S, findings)
    out = judge_candidates(candidates)          # cache -> LLM -> validate
    out["results"]                              # ranked by ensemble priority
"""
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

try:
    from . import judge_config
    from . import llm_clients
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config
    import llm_clients

# --------------------------------------------------------------------------
# Contract enums + verdict schema (spec sections 4.3 / 4.4).
# --------------------------------------------------------------------------
VERDICTS = ["benign", "suspicious", "malicious"]
CATEGORIES = ["beaconing_c2", "dns_tunnel", "dns_amp", "port_scan",
              "arp_mitm", "syn_flood", "benign_anomaly"]
ACTIONS = ["monitor", "investigate", "block"]

# Passed verbatim to the providers' structured-output modes, so it follows
# the structured-outputs subset: enums are enforced server-side; numeric
# range and string length are validated client-side in validate_verdict().
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": VERDICTS},
        "category": {"type": "string", "enum": CATEGORIES},
        "confidence": {
            "type": "number",
            "description": "0.0 to 1.0",
        },
        "evidence_features": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Field names (or dotted paths) from the input blob",
        },
        "reasoning": {
            "type": "string",
            "description": "One paragraph, no newlines, at most 400 characters",
        },
        "recommended_action": {"type": "string", "enum": ACTIONS},
    },
    "required": ["verdict", "category", "confidence", "evidence_features",
                 "reasoning", "recommended_action"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one unsupervised detector or deterministic rule has flagged. Your job:

1. Return a strict JSON object matching the schema below. No prose
   outside the JSON. No markdown fences.
2. Assign a verdict (benign | suspicious | malicious) and a category
   from the fixed enum.
3. Ground every claim in the input blob - cite feature names in
   evidence_features.
4. If the signals are contradictory or thin, prefer "suspicious" over
   "malicious". If they are strong and unambiguous, use "malicious".
5. Never invent facts not in the blob. If a field is null, it is unknown,
   not zero.
6. recommended_action is a suggestion for a human, never an action
   this system will execute.
7. confidence is a number between 0.0 and 1.0. reasoning is a single
   paragraph, no newlines, at most 400 characters.
8. The deterministic rules are HIGH-PRECISION. If any rule has fired -
   rule_signals.scan_alerts / amp_alerts / flood_alerts is non-empty, or
   arp_multi_mac is true - classify into the matching attack category and
   do NOT return "benign". Only override a fired rule if you can name
   concrete evidence in the blob that it misfired.

Schema:
{schema}

Category cheat sheet:
- port_scan: rule_signals.scan_alerts is non-empty (the deterministic scan
  rule fired) OR one TCP flag counter dominates with a high ratio to total
  packets. This covers BOTH shapes: a horizontal scan (high unique_dsts,
  one host touching many destinations) AND a vertical scan (many packets
  of one flag - e.g. a large syn_count - toward one or few destinations,
  so unique_dsts is LOW but the flag-to-packet ratio is high). Low
  unique_dsts does NOT rule out a port scan.
- syn_flood: session-level SYN rate high AND many spoofed sources (see
  session_context and rule_signals.flood_alerts). Candidates of kind
  "session" with a flood alert are this category.
- arp_mitm: rule_signals.arp_multi_mac is true.
- dns_amp: rule_signals.amp_alerts non-empty AND UDP/53 responses
  dominate.
- beaconing_c2: advanced_signals.beaconing non-null and periodic.
- dns_tunnel: advanced_signals.dns_tunneling non-null OR unusually long
  DNS query strings.
- benign_anomaly: a statistical outlier flagged ONLY by the ML detectors
  (isolation_forest / dbscan_noise) with NO deterministic rule fired and
  no matching attack pattern. Do NOT use this when any rule has fired.

Worked examples (abbreviated input -> correct output):

Example 1 - vertical SYN scan. Input has features {"syn_count": 1002,
"count": 1007, "unique_dsts": 1} and rule_signals.scan_alerts
[{"type": "SYN", "count": 1002, "unique_dsts": 1, "ratio": 1.0}].
unique_dsts is LOW but the scan rule fired and nearly every packet is a
SYN - this is a port scan against one host:
{"verdict": "malicious", "category": "port_scan", "confidence": 0.95,
 "evidence_features": ["rule_signals.scan_alerts", "syn_count", "count"],
 "reasoning": "The deterministic scan rule fired: 1002 of 1007 packets are
 SYNs (ratio 1.0) against a single destination - a vertical SYN scan.",
 "recommended_action": "investigate"}

Example 2 - ML-only outlier. Input has ml_signals {"anomaly": true,
"cluster": -1} but every rule_signals list is empty and arp_multi_mac is
false. A statistical outlier with no attack pattern:
{"verdict": "benign", "category": "benign_anomaly", "confidence": 0.6,
 "evidence_features": ["ml_signals.anomaly", "ml_signals.cluster"],
 "reasoning": "Flagged only by the unsupervised detectors; no deterministic
 rule fired and no attack-shaped signal is present in the blob.",
 "recommended_action": "monitor"}
""".replace("{schema}", json.dumps(VERDICT_SCHEMA, indent=2))


class JudgeValidationError(ValueError):
    """The LLM response failed schema validation."""


# --------------------------------------------------------------------------
# Fingerprint + cache (spec sections 6.3 / 7.2).
# --------------------------------------------------------------------------
def canonical_json(obj):
    """Sorted keys, no whitespace - the stable half of the cache key."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def fingerprint(candidate_context, prompt_version, model_id):
    """Cache key. The spec keys on (context, prompt_version); the model id
    is added so switching provider or model never reuses a stale verdict."""
    payload = canonical_json(candidate_context) + prompt_version + model_id
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class JudgeCache:
    """SQLite verdict cache. Only schema-validated verdicts are written.

    Thread-safe: the panel path fans one candidate out to N judges in
    parallel (see judge_candidates_panel), and every worker thread hits
    the same cache. `check_same_thread=False` on the connection lets
    threads share it, and `_lock` serialises the actual reads/writes so
    SQLite never sees interleaved statements. The lock is only held for
    the duration of a single query - the LLM call itself, which is what
    we actually parallelise, stays outside it."""

    def __init__(self, db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS judge_cache (
                    fingerprint TEXT PRIMARY KEY,
                    prompt_version TEXT NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    llm_model TEXT NOT NULL,
                    latency_ms INTEGER
                )""")
            self._conn.commit()

    def get(self, fp):
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict_json FROM judge_cache WHERE fingerprint = ?",
                (fp,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, fp, prompt_version, verdict, model_id, latency_ms):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO judge_cache VALUES (?, ?, ?, ?, ?, ?)",
                (fp, prompt_version, canonical_json(verdict),
                 datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 model_id, int(latency_ms)))
            self._conn.commit()

    def stats(self):
        with self._lock:
            n, = self._conn.execute(
                "SELECT COUNT(*) FROM judge_cache").fetchone()
        return {"entries": int(n)}

    def close(self):
        with self._lock:
            self._conn.close()


# --------------------------------------------------------------------------
# Verdict validation (spec section 4.3): strict on structure and enums,
# soft on evidence_features content; reasoning normalized to one line and
# hard-capped at 400 characters.
# --------------------------------------------------------------------------
def validate_verdict(obj):
    """Return a normalized verdict dict or raise JudgeValidationError."""
    if not isinstance(obj, dict):
        raise JudgeValidationError(f"verdict is {type(obj).__name__}, not object")
    missing = [k for k in VERDICT_SCHEMA["required"] if k not in obj]
    if missing:
        raise JudgeValidationError(f"missing fields: {missing}")
    if obj["verdict"] not in VERDICTS:
        raise JudgeValidationError(f"bad verdict {obj['verdict']!r}")
    if obj["category"] not in CATEGORIES:
        raise JudgeValidationError(f"bad category {obj['category']!r}")
    if obj["recommended_action"] not in ACTIONS:
        raise JudgeValidationError(
            f"bad recommended_action {obj['recommended_action']!r}")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) \
            or not (0.0 <= float(conf) <= 1.0):
        raise JudgeValidationError(f"confidence {conf!r} outside [0, 1]")
    if not isinstance(obj["evidence_features"], list):
        raise JudgeValidationError("evidence_features is not a list")
    if not isinstance(obj["reasoning"], str) or not obj["reasoning"].strip():
        raise JudgeValidationError("reasoning is empty or not a string")
    reasoning = " ".join(obj["reasoning"].split())
    return {
        "verdict": obj["verdict"],
        "category": obj["category"],
        "confidence": round(float(conf), 3),
        "evidence_features": [str(x) for x in obj["evidence_features"]][:12],
        "reasoning": reasoning[:400],
        "recommended_action": obj["recommended_action"],
    }


# --------------------------------------------------------------------------
# Candidate assembly (spec section 4.1 / 4.2).
# --------------------------------------------------------------------------
def _num(x, digits=4):
    """numpy scalar -> plain rounded float (stable fingerprints)."""
    try:
        return round(float(x), digits)
    except (TypeError, ValueError):
        return None


def _is_private(ip):
    try:
        return bool(ipaddress.ip_address(ip).is_private)
    except ValueError:
        return None


FEATURE_COLS = ["mean_len", "std_len", "count", "burst_score", "unique_dsts",
                "syn_count", "rst_count", "fin_count", "null_count",
                "xmas_count"]


_EMPTY_ADV = {"beaconing": None, "dns_tunneling": None,
              "dga": None, "tls_anomaly": None, "fusion_score": None}
_EMPTY_DEV = {"category": "unknown", "hostname": None, "oui_vendor": None}


def threats_to_advanced_signals(threats):
    """Reshape the dict `run_advanced_threats(pcap, label)` returns into the
    per-IP `advanced_signals` blob assemble_candidates puts in each
    candidate. Passes through unchanged if given an already-per-IP dict.

    Input: {available, per_engine{arp_dhcp, dns_tunnel, dga, beaconing, tls},
            all_signals, device_risk}. Output: {ip -> {beaconing, dns_tunneling,
            dga, tls_anomaly, fusion_score}}. Missing engines stay `None`.

    Safe on the {"available": False, "reason": "..."} shape: returns an
    empty dict so a caller can pass this through without checking first."""
    if not isinstance(threats, dict) or not threats.get("available"):
        return {}
    per = threats.get("per_engine") or {}
    device_risk = threats.get("device_risk") or []
    ENGINE_TO_KEY = {"beaconing": "beaconing", "dns_tunnel": "dns_tunneling",
                     "dga": "dga", "tls": "tls_anomaly"}
    per_ip = {}
    for engine, target_key in ENGINE_TO_KEY.items():
        for row in per.get(engine) or []:
            ip = row.get("device")
            if not ip:
                continue
            cur = per_ip.setdefault(ip, dict(_EMPTY_ADV))
            prev = cur.get(target_key)
            score = _num(row.get("score"))
            # keep the worst signal seen for this device+engine
            if (prev is None or (isinstance(prev, dict)
                                 and _num(prev.get("score") or 0) < score)):
                cur[target_key] = {
                    "score": score,
                    "severity": row.get("severity"),
                    "count": int(row.get("count") or 0),
                    "peer": row.get("peer"),
                }
    for row in device_risk:
        ip = row.get("device")
        if not ip:
            continue
        cur = per_ip.setdefault(ip, dict(_EMPTY_ADV))
        cur["fusion_score"] = {
            "score": _num(row.get("risk") or row.get("score")),
            "techniques": int(row.get("techniques_seen")
                              or row.get("engines_hit") or 0),
        }
    return per_ip


def local_inv_to_device_context(inv):
    """Reshape a `build_local_inventory` DataFrame (or list-of-dicts) into
    {ip -> {category, hostname, oui_vendor}}. Returns {} if inv is falsy
    or has no rows."""
    if inv is None:
        return {}
    rows = inv.to_dict("records") if hasattr(inv, "to_dict") else list(inv)
    out = {}
    for r in rows or []:
        ip = r.get("ip")
        if not ip:
            continue
        out[ip] = {
            "category": r.get("category") or "unknown",
            "hostname": r.get("device_name") or r.get("hostname"),
            "oui_vendor": r.get("vendor") or r.get("vendor_oui") or r.get("oui_vendor"),
        }
    return out


def assemble_candidates(S, findings, lstm_flags=None, max_candidates=None,
                        advanced_signals=None, device_context=None):
    """Union of everything any detector flagged, one JSON blob each.

    lstm_flags: optional {ip: bin_flag_count} attribution from the LSTM
    layer (null in the blob when not provided - the standalone pipeline
    treats the LSTM as an optional, slow extra).
    advanced_signals: optional {ip: {beaconing, dns_tunneling, dga,
        tls_anomaly, fusion_score}} - the per-IP output of the dashboard's
        five advanced engines + fusion scorer. Preserved as-is per IP
        (use `threats_to_advanced_signals` to reshape a raw
        run_advanced_threats() output). Absent IPs get the default all-null
        block so the schema is stable.
    device_context: optional {ip: {category, hostname, oui_vendor}} - the
        per-IP output of the device classifier + inventory. Same story:
        absent IPs get the default "unknown/None/None" block.

    Returns {"candidates": [...], "capped": [ids dropped by the batch cap]}.
    Rule-triggered candidates always survive the cap; the statistical-only
    remainder is ranked by iso_score (most anomalous first).
    """
    advanced_signals = advanced_signals or {}
    device_context = device_context or {}
    if max_candidates is None:
        max_candidates = judge_config.MAX_CANDIDATES_PER_BATCH
    ip_agg = S["ip_agg"]
    duration_s = max((S["t1"] - S["t0"]).total_seconds(), 0.0)
    session_context = {
        "duration_s": round(duration_s, 1),
        "total_packets": int(S["n_pkts"]),
        "total_ips": int(len(S["ips_src"])),
    }

    scan_by_src = {}
    for a in findings.get("scan_alerts", []):
        scan_by_src.setdefault(a["src"], []).append(
            {"type": a["type"], "count": int(a["count"]),
             "unique_dsts": int(a["unique_dsts"]), "ratio": float(a["ratio"])})
    amp_by_src = {a["src"]: {"responses": int(a["responses"]),
                             "mean_size": float(a["mean_size"])}
                  for a in findings.get("amp_alerts", [])}
    arp_ips = set(findings.get("arp_spoofing_ips", {}))
    flood_alerts = findings.get("flood_alerts", [])

    has_ml = "anomaly" in getattr(ip_agg, "columns", [])
    # A degenerate DBSCAN (skipped or all-noise, e.g. a spoofed flood) makes
    # "noise" meaningless as a per-IP signal - only use it when at least one
    # real cluster exists.
    dbscan_meaningful = (has_ml and "cluster" in ip_agg.columns
                         and bool((ip_agg["cluster"] != -1).any()))

    reasons = {}

    def _add(ip, reason):
        reasons.setdefault(ip, set()).add(reason)

    if has_ml:
        for ip in ip_agg.index[ip_agg["anomaly"] == True]:  # noqa: E712
            _add(ip, "isolation_forest")
        if dbscan_meaningful:
            for ip in ip_agg.index[ip_agg["cluster"] == -1]:
                _add(ip, "dbscan_noise")
    for src in scan_by_src:
        _add(src, "scan_rule")
    for src in amp_by_src:
        _add(src, "amp_rule")
    for ip in arp_ips:
        _add(ip, "arp_rule")
    for ip in (lstm_flags or {}):
        _add(ip, "lstm")

    rule_reasons = {"scan_rule", "amp_rule", "arp_rule"}

    def _rank_key(ip):
        is_rule = bool(reasons[ip] & rule_reasons)
        if has_ml and ip in ip_agg.index:
            iso = float(ip_agg.loc[ip, "iso_score"])
        else:
            iso = float("inf")  # no score -> after every scored candidate
        return (0 if is_rule else 1, iso)  # rules first, then most anomalous

    ordered = sorted(reasons, key=_rank_key)
    kept, capped = ordered[:max_candidates], ordered[max_candidates:]

    candidates = []
    for ip in kept:
        in_agg = ip in ip_agg.index
        row = ip_agg.loc[ip] if in_agg else None
        features = {c: (_num(row[c]) if in_agg else 0.0) for c in FEATURE_COLS}
        ml = {
            "iso_score": _num(row["iso_score"]) if (in_agg and has_ml) else None,
            "iso_stability": _num(row["iso_stability"]) if (in_agg and has_ml) else None,
            "anomaly": bool(row["anomaly"]) if (in_agg and has_ml) else None,
            "cluster": int(row["cluster"]) if (in_agg and has_ml
                                               and "cluster" in ip_agg.columns) else None,
            "silhouette": None,
            "lstm_bin_flag_count": int(lstm_flags[ip]) if (lstm_flags
                                                           and ip in lstm_flags) else None,
        }
        candidates.append({
            "candidate_id": ip,
            "kind": "ip",
            "session_context": session_context,
            "features": features,
            "ml_signals": ml,
            "rule_signals": {
                "scan_alerts": scan_by_src.get(ip, []),
                "flood_alerts": [],
                "amp_alerts": [amp_by_src[ip]] if ip in amp_by_src else [],
                "arp_multi_mac": ip in arp_ips,
            },
            "advanced_signals": advanced_signals.get(ip, dict(_EMPTY_ADV)),
            "device_context": device_context.get(ip, dict(_EMPTY_DEV)),
            "enrichments": {"is_private": _is_private(ip),
                            "reverse_dns": None, "asn": None,
                            "baseline_seen_before": None},
            "trigger_reasons": sorted(reasons[ip]),
        })

    # Session-level candidate for aggregate floods: thousands of spoofed
    # sources have no meaningful per-IP identity, so the flood is judged
    # once at session scope (kind "session" extends the spec's ip|flow).
    if flood_alerts:
        fa = flood_alerts[0]
        candidates.append({
            "candidate_id": f"session:{S.get('label', 'S1')}",
            "kind": "session",
            "session_context": session_context,
            "features": {
                "total_syn": int(fa["total_syn"]),
                "syn_sources": int(fa["syn_sources"]),
                "syn_per_sec": float(fa["syn_per_sec"]),
                "syn_per_source": float(fa["syn_per_source"]),
                "spoofed_source_pattern": bool(fa["spoofed_source_pattern"]),
            },
            "ml_signals": {"iso_score": None, "iso_stability": None,
                           "anomaly": None, "cluster": None,
                           "silhouette": None, "lstm_bin_flag_count": None},
            "rule_signals": {"scan_alerts": [], "flood_alerts": flood_alerts,
                             "amp_alerts": [], "arp_multi_mac": False},
            # Session-scope candidate: advanced/device context are per-IP
            # concepts, so keep them at the default empty blocks here.
            "advanced_signals": dict(_EMPTY_ADV),
            "device_context": dict(_EMPTY_DEV),
            "enrichments": {"is_private": None, "reverse_dns": None,
                            "asn": None, "baseline_seen_before": None},
            "trigger_reasons": ["flood_rule"],
        })

    return {"candidates": candidates, "capped": capped}


# --------------------------------------------------------------------------
# Ensemble priority (spec section 9).
# --------------------------------------------------------------------------
def _iso_bounds(candidates):
    scores = [c["ml_signals"]["iso_score"] for c in candidates
              if isinstance(c["ml_signals"]["iso_score"], (int, float))]
    return (min(scores), max(scores)) if scores else (None, None)


def priority_score(candidate, verdict, iso_min, iso_max):
    iso = candidate["ml_signals"]["iso_score"]
    if isinstance(iso, (int, float)) and iso_min is not None \
            and iso_max is not None and iso_max > iso_min:
        norm_anom = (iso_max - float(iso)) / (iso_max - iso_min)  # lower = worse
    else:
        norm_anom = 0.0
    # Threat-intel signal (stage YA): a candidate enriched with an
    # external peer's Shodan reputation carries ti_signals.score in [0,1].
    # Absent that key it is 0.0, so an un-enriched candidate scores exactly
    # as before this weight was activated - which keeps every prior test
    # and the kappa calibration unchanged.
    ti = float((candidate.get("ti_signals") or {}).get("score", 0.0) or 0.0)
    return round(
        judge_config.W_ANOM * norm_anom
        + judge_config.W_JUDGE_CONF * verdict["confidence"]
        + judge_config.W_CAT * judge_config.CATEGORY_WEIGHT[verdict["category"]]
        + judge_config.W_TI * ti,
        4)


# --------------------------------------------------------------------------
# Rule guardrail. The deterministic rules are high-precision; a fired rule
# implies its attack category. Small local models were measured overriding
# a fired rule with "benign" (while hallucinating that no rule fired), so
# with the guardrail on such a verdict is raised to "suspicious" with the
# rule-implied category. The model's original verdict stays in the result
# for transparency; the raw model verdict is what gets cached, so toggling
# the guardrail needs no cache invalidation.
# --------------------------------------------------------------------------
def rule_expected_category(candidate):
    """The attack category implied by whichever deterministic rule fired,
    or None when no rule fired (ML-only candidates)."""
    rs = candidate.get("rule_signals", {})
    if rs.get("flood_alerts"):
        return "syn_flood"
    if rs.get("arp_multi_mac"):
        return "arp_mitm"
    if rs.get("amp_alerts"):
        return "dns_amp"
    if rs.get("scan_alerts"):
        return "port_scan"
    return None


COMMENTARY_SYSTEM_PROMPT = """You are a network-security analyst reviewing
one packet capture that has been fully processed by an automated pipeline.
You receive a JSON summary of what the pipeline found and the per-candidate
verdicts. Write a brief analyst commentary in 3-5 sentences that:

1. States what the capture likely shows overall (attack, benign traffic
   with anomalies, or mixed).
2. Names the most concerning finding, if any, and why.
3. Notes any relationships between findings (e.g. the same IP appears
   under multiple detectors, one host explains multiple alerts).
4. Ends with a plain-language suggested next action for the human analyst.

Respond in prose only. No bullet lists, no JSON, no markdown headings, no
code fences. Do not restate numbers verbatim - interpret them. Keep it
under 6 sentences and grounded in the JSON you received; never invent
facts."""


def analyst_commentary(client, context, verdicts, session_label="S1",
                       provider=None, model=None):
    """One extra LLM call at the end of a judge run: turn all findings
    into a free-form analyst-style paragraph. Uses the same provider as
    the judge but with the verdict schema turned off, so the response is
    plain prose. `provider`/`model` override the configured default - the
    panel path passes its first judge so commentary never depends on a
    provider that isn't part of the run.

    Never raises: on any failure, returns a short error notice string so
    the caller can still write out the JSON/Markdown report."""
    try:
        # A fresh, schema-less client of the same provider - the passed-in
        # client is bound to the strict verdict schema and would try to
        # coerce prose into JSON.
        try:
            from . import llm_clients
        except ImportError:
            import llm_clients
        prose_client = llm_clients.make_client(provider=provider,
                                               verdict_schema=None,
                                               model=model)

        payload = {
            "session": session_label,
            "pipeline_stats": {
                "packets": context.get("n_packets"),
                "duration_s": context.get("duration_s"),
                "total_ips": context.get("total_ips"),
                "top_protocols": context.get("top_protocols"),
                "ml": context.get("ml"),
                "rules": context.get("rules"),
            },
            "verdicts": [
                {
                    "candidate": r["candidate_id"],
                    "verdict": r["verdict"]["verdict"],
                    "category": r["verdict"]["category"],
                    "confidence": r["verdict"]["confidence"],
                    "priority": r["priority"],
                    "guardrail_applied": bool(r.get("guardrail")),
                    "needs_human_review": bool(
                        (r.get("committee") or {}).get("needs_human_review")),
                    "reasoning": r["verdict"]["reasoning"],
                }
                for r in verdicts.get("results", [])
            ],
            "not_flagged_sample": [
                e["ip"] for e in
                (context.get("not_flagged_ips") or [])[:10]
            ],
        }
        raw = prose_client.judge(COMMENTARY_SYSTEM_PROMPT,
                                 json.dumps(payload, indent=2))
        # Normalize: single paragraph, trimmed.
        text = " ".join(raw.strip().split())
        return text[:2000]
    except Exception as e:
        return (f"(Analyst commentary unavailable: "
                f"{type(e).__name__}: {e})")


def apply_rule_guardrail(candidate, verdict):
    """Return (effective_verdict, guardrail_info). guardrail_info is None
    when nothing was overridden."""
    expected = rule_expected_category(candidate)
    if expected is None or verdict["verdict"] != "benign":
        return verdict, None
    corrected = dict(verdict)
    corrected["verdict"] = "suspicious"
    corrected["category"] = expected
    corrected["confidence"] = max(float(verdict["confidence"]), 0.6)
    corrected["recommended_action"] = "investigate"
    if "rule_signals" not in " ".join(corrected["evidence_features"]):
        corrected["evidence_features"] = (["rule_signals"]
                                          + corrected["evidence_features"])[:12]
    corrected["reasoning"] = (
        f"[rule guardrail] The deterministic {expected} rule fired for this "
        f"candidate, so a benign verdict is not allowed. Model said: "
        + verdict["reasoning"])[:400]
    return corrected, {"applied": True,
                       "rule_category": expected,
                       "model_verdict": verdict["verdict"],
                       "model_category": verdict["category"]}


# --------------------------------------------------------------------------
# The judge loop (spec section 5): cache -> LLM -> validate -> retry once ->
# drop-and-log. A single bad response never poisons the batch.
# --------------------------------------------------------------------------
def _verdict_from_client(cand, client, cache, prompt_version):
    """One candidate through one client: cache -> LLM -> validate -> retry
    once. Returns (verdict|None, latency_ms, was_cached, error|None). Never
    raises - a failure comes back as (None, latency, False, exception)."""
    fp = fingerprint(cand, prompt_version, client.model_id)
    cached = cache.get(fp)
    if cached is not None:
        return cached, 0, True, None
    last_err, latency_ms, verdict = None, 0, None
    for _attempt in (1, 2):  # retry once on any failure
        try:
            t0 = time.perf_counter()
            raw = client.judge(SYSTEM_PROMPT, json.dumps(cand, indent=2))
            latency_ms = int((time.perf_counter() - t0) * 1000)
            verdict = validate_verdict(json.loads(raw))
            break
        except Exception as e:
            last_err, verdict = e, None
    if verdict is None:
        return None, latency_ms, False, last_err
    # The cache write stays OUTSIDE the retry loop and is best-effort: a
    # locked/broken cache DB (e.g. sqlite "database is locked" when the
    # judge_api container and a notebook share the file) must not trigger
    # a duplicate LLM call or discard a validly-judged verdict.
    try:
        cache.put(fp, prompt_version, verdict, client.model_id, latency_ms)
    except Exception as e:
        print(f"[judge] WARNING: cache write failed ({e}) - "
              f"continuing with the uncached verdict", flush=True)
    return verdict, latency_ms, False, None


def judge_candidates(candidates, client=None, cache_db=None,
                     prompt_version=None, verbose=True):
    """Judge a candidate batch. Returns
    {"results": [ranked verdicts], "dropped": [failures], "stats": {...}}."""
    prompt_version = prompt_version or judge_config.PROMPT_VERSION
    if not judge_config.LLM_JUDGE_ENABLED:
        if verbose:
            print("[judge] LLM_JUDGE_ENABLED=0 - skipping all candidates")
        return {"results": [], "dropped": [],
                "stats": {"total": len(candidates), "judged": 0,
                          "cache_hits": 0, "dropped": 0, "disabled": True}}
    if client is None:
        client = llm_clients.make_client(verdict_schema=VERDICT_SCHEMA)
    cache = JudgeCache(cache_db or judge_config.CACHE_DB)

    iso_min, iso_max = _iso_bounds(candidates)
    results, dropped, cache_hits = [], [], 0
    try:
        for i, cand in enumerate(candidates, 1):
            verdict, latency_ms, was_cached, err = _verdict_from_client(
                cand, client, cache, prompt_version)
            if verdict is None:
                dropped.append({"candidate_id": cand["candidate_id"],
                                "error": str(err)})
                if verbose:
                    print(f"[judge] {i}/{len(candidates)} "
                          f"{cand['candidate_id']}: DROPPED ({err})")
                continue
            if was_cached:
                cache_hits += 1
            guardrail_info = None
            if judge_config.RULE_GUARDRAIL:
                verdict, guardrail_info = apply_rule_guardrail(cand, verdict)
            results.append({
                "candidate_id": cand["candidate_id"],
                "kind": cand["kind"],
                "verdict": verdict,
                "guardrail": guardrail_info,
                "priority": priority_score(cand, verdict, iso_min, iso_max),
                "cached": was_cached,
                "latency_ms": latency_ms,
            })
            if verbose:
                tag = "cache" if was_cached else f"{latency_ms} ms"
                if guardrail_info:
                    tag += ", guardrail"
                v = verdict
                print(f"[judge] {i}/{len(candidates)} "
                      f"{cand['candidate_id']:<24} {v['verdict']:<10} "
                      f"{v['category']:<15} conf={v['confidence']:.2f} ({tag})")
    finally:
        cache.close()

    results.sort(key=lambda r: -r["priority"])
    return {"results": results, "dropped": dropped,
            "stats": {"total": len(candidates), "judged": len(results),
                      "cache_hits": cache_hits, "dropped": len(dropped),
                      "prompt_version": prompt_version,
                      "model": client.model_id}}


# --------------------------------------------------------------------------
# Committee mode (opt-in): two models judge every candidate; verdicts are
# combined. On agreement the higher-confidence verdict wins; on disagreement
# the more-severe verdict is used (fail-safe) and needs_human_review is set.
# --------------------------------------------------------------------------
SEVERITY = {"benign": 0, "suspicious": 1, "malicious": 2}


def _slim_verdict(v):
    """The subset of a verdict shown per-judge in committee metadata."""
    if v is None:
        return None
    return {"verdict": v["verdict"], "category": v["category"],
            "confidence": v["confidence"]}


def combine_committee(verdict_a, verdict_b, model_a, model_b):
    """Combine two judges' verdicts into (effective_verdict, committee_info).

    Either verdict may be None if that judge failed. Returns
    (None, info) only when BOTH failed. Policy:
      - both valid & same verdict label -> higher-confidence wins, no review
      - both valid & different label    -> more-severe wins, needs review
      - only one valid                  -> use it, needs review (uncorroborated)
    """
    a_ok, b_ok = verdict_a is not None, verdict_b is not None
    info = {"judge_a": {"model": model_a, **(_slim_verdict(verdict_a) or {})}
            if a_ok else {"model": model_a, "failed": True},
            "judge_b": {"model": model_b, **(_slim_verdict(verdict_b) or {})}
            if b_ok else {"model": model_b, "failed": True}}
    if not a_ok and not b_ok:
        info.update(agreement=False, needs_human_review=True,
                    note="both judges failed")
        return None, info
    if a_ok and not b_ok:
        info.update(agreement=False, needs_human_review=True,
                    note="only judge A returned a valid verdict")
        return dict(verdict_a), info
    if b_ok and not a_ok:
        info.update(agreement=False, needs_human_review=True,
                    note="only judge B returned a valid verdict")
        return dict(verdict_b), info
    # Both valid.
    if verdict_a["verdict"] == verdict_b["verdict"]:
        eff = (verdict_a if verdict_a["confidence"] >= verdict_b["confidence"]
               else verdict_b)
        info.update(agreement=True, needs_human_review=False)
        return dict(eff), info
    eff = (verdict_a if SEVERITY[verdict_a["verdict"]]
           >= SEVERITY[verdict_b["verdict"]] else verdict_b)
    info.update(agreement=False, needs_human_review=True,
                note="judges disagree; using the more severe verdict")
    return dict(eff), info


def judge_candidates_committee(candidates, clients, cache_db=None,
                               prompt_version=None, verbose=True):
    """Committee variant of judge_candidates: judge every candidate with each
    client in `clients` (expects exactly two), combine, and flag disputes.

    Same return shape as judge_candidates, with each result carrying a
    `committee` block and stats carrying `needs_review` + both model ids."""
    prompt_version = prompt_version or judge_config.PROMPT_VERSION
    if not judge_config.LLM_JUDGE_ENABLED:
        if verbose:
            print("[committee] LLM_JUDGE_ENABLED=0 - skipping all candidates")
        return {"results": [], "dropped": [],
                "stats": {"total": len(candidates), "judged": 0,
                          "cache_hits": 0, "dropped": 0, "disabled": True}}
    if not clients or len(clients) != 2:
        raise ValueError("committee needs exactly two clients")
    client_a, client_b = clients[0], clients[1]
    if client_a.model_id == client_b.model_id:
        # The verdict cache keys on model_id: with identical ids, judge B
        # would be served judge A's freshly-cached verdict instead of an
        # independent call, so every candidate would falsely "agree" and
        # disagreement flagging could never fire. Refuse loudly.
        raise ValueError(
            f"committee clients must use two different models - both are "
            f"'{client_a.model_id}'. Set LLM_JUDGE_COMMITTEE_MODEL_B to a "
            f"model different from the primary judge's.")
    cache = JudgeCache(cache_db or judge_config.CACHE_DB)

    iso_min, iso_max = _iso_bounds(candidates)
    results, dropped, cache_hits, needs_review = [], [], 0, 0
    try:
        for i, cand in enumerate(candidates, 1):
            va, la, ca, ea = _verdict_from_client(
                cand, client_a, cache, prompt_version)
            vb, lb, cb, eb = _verdict_from_client(
                cand, client_b, cache, prompt_version)
            eff, committee = combine_committee(
                va, vb, client_a.model_id, client_b.model_id)
            if eff is None:
                dropped.append({"candidate_id": cand["candidate_id"],
                                "error": f"A: {ea}; B: {eb}"})
                if verbose:
                    print(f"[committee] {i}/{len(candidates)} "
                          f"{cand['candidate_id']}: DROPPED (both failed)")
                continue
            cache_hits += int(ca) + int(cb)
            guardrail_info = None
            if judge_config.RULE_GUARDRAIL:
                eff, guardrail_info = apply_rule_guardrail(cand, eff)
                if guardrail_info:
                    # The guardrail only fires when the committee's effective
                    # verdict was "benign" on a fired-rule candidate - i.e.
                    # BOTH judges (or the lone survivor) missed a
                    # high-precision deterministic signal. That is exactly
                    # the failure mode committee mode exists to surface, so
                    # it always escalates to human review, even though the
                    # judges nominally "agreed".
                    committee["needs_human_review"] = True
                    note = "rule guardrail overrode a benign committee verdict"
                    committee["note"] = (committee["note"] + "; " + note
                                         if committee.get("note") else note)
            if committee["needs_human_review"]:
                needs_review += 1
            results.append({
                "candidate_id": cand["candidate_id"],
                "kind": cand["kind"],
                "verdict": eff,
                "guardrail": guardrail_info,
                "committee": committee,
                "priority": priority_score(cand, eff, iso_min, iso_max),
                "cached": bool(ca and cb),
                "latency_ms": la + lb,
            })
            if verbose:
                flag = " ⚖ REVIEW" if committee["needs_human_review"] else ""
                print(f"[committee] {i}/{len(candidates)} "
                      f"{cand['candidate_id']:<24} {eff['verdict']:<10} "
                      f"A={_slim_verdict(va)['verdict'] if va else 'X':<10} "
                      f"B={_slim_verdict(vb)['verdict'] if vb else 'X':<10}"
                      f"{flag}")
    finally:
        cache.close()

    results.sort(key=lambda r: -r["priority"])
    return {"results": results, "dropped": dropped,
            "stats": {"total": len(candidates), "judged": len(results),
                      "cache_hits": cache_hits, "dropped": len(dropped),
                      "needs_review": needs_review,
                      "prompt_version": prompt_version,
                      "committee": True,
                      "model": client_a.model_id,
                      "model_b": client_b.model_id}}


# --------------------------------------------------------------------------
# Expert panel (opt-in): N models judge every candidate independently; on
# disagreement each judge sees the peers' analyses and must revise or defend
# (one debate round), then a deterministic resolver produces the effective
# verdict. Disputes that survive the debate are flagged needs_human_review.
# The 2-model committee above remains as the legacy fixed-shape mode.
# --------------------------------------------------------------------------
PANEL_PROVIDERS = ("claude", "ollama", "openai_compat")


def parse_panel_spec(spec, default_provider=None):
    """Parse LLM_JUDGE_PANEL into [(provider, model), ...].

    Each comma-separated entry is "model" (configured/default provider) or
    "provider:model". A colon prefix counts as a provider only when it is
    one of PANEL_PROVIDERS - Ollama model names themselves contain colons
    ("gemma3:4b"), so "gemma3:4b" is a model and "ollama:gemma3:4b" is
    provider + model. Raises ValueError on an empty spec, on fewer than
    two judges, and on duplicate model names - the verdict cache keys on
    the model id, so two judges with the same model would be served each
    other's cached verdicts and could never genuinely disagree.
    """
    default_provider = (default_provider
                        or judge_config.LLM_JUDGE_PROVIDER).lower()
    # built-ins plus any endpoint profiles defined in the environment
    # (spec 6.1), so "gemini:gemini-2.5-flash" resolves the GEMINI profile
    known = set(PANEL_PROVIDERS) | set(judge_config.endpoint_profiles())
    entries = []
    for raw in (spec or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        head, _, tail = raw.partition(":")
        if head.strip().lower() in known:
            provider, model = head.strip().lower(), tail.strip()
        else:
            provider, model = default_provider, raw
        if not model:
            raise ValueError(f"panel entry {raw!r} has no model name")
        entries.append((provider, model))
    if len(entries) < 2:
        raise ValueError(
            "LLM_JUDGE_PANEL needs at least two judges "
            f"(got {len(entries)}); for a single judge leave the panel off")
    models = [m for _, m in entries]
    dupes = sorted({m for m in models if models.count(m) > 1})
    if dupes:
        raise ValueError(
            f"panel has duplicate model name(s) {dupes} - verdicts are "
            "cached per model id, so duplicate judges would fake agreement")
    return entries


DEBATE_SCHEMA = {
    "type": "object",
    "properties": {
        "stance": {"type": "string", "enum": ["maintain", "revise"]},
        "verdict": {"type": "string", "enum": VERDICTS},
        "category": {"type": "string", "enum": CATEGORIES},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "evidence_features": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Field names (or dotted paths) from the input blob",
        },
        "reasoning": {
            "type": "string",
            "description": "One paragraph, no newlines, at most 400 characters",
        },
        "recommended_action": {"type": "string", "enum": ACTIONS},
        "rebuttal": {
            "type": "string",
            "description": "One paragraph addressing the strongest opposing "
                           "point, at most 300 characters",
        },
    },
    "required": ["stance", "verdict", "category", "confidence",
                 "evidence_features", "reasoning", "recommended_action",
                 "rebuttal"],
    "additionalProperties": False,
}

DEBATE_SYSTEM_PROMPT = """You are one analyst on a network-security triage
panel. You already issued a verdict for this candidate. Other analysts
reviewed the SAME input blob and reached different conclusions; their
analyses are included below yours, anonymized.

Re-examine the candidate blob against the peer analyses:

1. If a peer cites concrete evidence in the blob that you missed or
   misread, REVISE: set stance "revise" and return your corrected verdict
   fields.
2. If your original verdict still fits the evidence best, DEFEND it: set
   stance "maintain", keep your verdict (you may adjust confidence), and
   use "rebuttal" to address the strongest opposing point directly, citing
   field names from the blob.
3. Ground every claim in the candidate blob. Never invent facts. The
   deterministic rules remain HIGH-PRECISION: if a rule fired, "benign"
   is wrong unless the blob itself shows the rule misfired.
4. Return one strict JSON object matching the schema. No prose outside
   the JSON. No markdown fences. "reasoning" is your full post-debate
   justification; "rebuttal" speaks to the peers' strongest argument.

Schema:
{schema}
""".replace("{schema}", json.dumps(DEBATE_SCHEMA, indent=2))


def validate_debate_response(obj):
    """Validate a debate-round response: the verdict subset goes through
    validate_verdict; stance and rebuttal are checked here. Returns
    (verdict_dict, stance, rebuttal) or raises JudgeValidationError."""
    if not isinstance(obj, dict):
        raise JudgeValidationError(
            f"debate response is {type(obj).__name__}, not object")
    stance = obj.get("stance")
    if stance not in ("maintain", "revise"):
        raise JudgeValidationError(f"bad stance {stance!r}")
    rebuttal = obj.get("rebuttal")
    if not isinstance(rebuttal, str) or not rebuttal.strip():
        raise JudgeValidationError("rebuttal is empty or not a string")
    verdict = validate_verdict({k: obj[k] for k in VERDICT_SCHEMA["required"]
                                if k in obj})
    return verdict, stance, " ".join(rebuttal.split())[:300]


def _panel_disagrees(verdicts):
    """True when valid round-1 verdicts differ on label OR category."""
    labels = {v["verdict"] for v in verdicts}
    cats = {v["category"] for v in verdicts}
    return len(labels) > 1 or len(cats) > 1


def _debate_payload(candidate, own_verdict, peers):
    """User-content blob for one judge's debate turn. Deterministic (peers
    in panel order, slim verdicts + reasoning) so it doubles as the cache
    fingerprint payload: same dispute -> same blob -> cache hit on re-runs."""
    return {
        "debate": {
            "candidate": candidate,
            "your_previous_verdict": {
                "verdict": own_verdict["verdict"],
                "category": own_verdict["category"],
                "confidence": own_verdict["confidence"],
                "reasoning": own_verdict["reasoning"],
            },
            "peer_analyses": peers,
        }
    }


def _debate_from_client(cand, own_verdict, peers, client, cache,
                        prompt_version):
    """One judge's debate turn: cache -> LLM -> validate -> retry once.
    Returns (verdict, stance, rebuttal, latency_ms, was_cached, error).
    On failure the judge's round-1 verdict stands (stance "maintain") and
    the error is reported - a broken judge must not sink the debate."""
    payload = _debate_payload(cand, own_verdict, peers)
    fp = fingerprint(payload, prompt_version + ":debate", client.model_id)
    cached = cache.get(fp)
    if cached is not None:
        return (cached["verdict"], cached["stance"], cached["rebuttal"],
                0, True, None)
    last_err = None
    latency_ms = 0
    for _attempt in (1, 2):
        try:
            t0 = time.perf_counter()
            # The debate turn needs the debate schema (stance + rebuttal),
            # not the verdict schema the client was built with - a strict
            # provider constrained to VERDICT_SCHEMA cannot emit 'stance'.
            raw = client.judge(DEBATE_SYSTEM_PROMPT,
                               json.dumps(payload, indent=2),
                               schema=DEBATE_SCHEMA)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            verdict, stance, rebuttal = validate_debate_response(
                json.loads(raw))
            try:
                cache.put(fp, prompt_version + ":debate",
                          {"verdict": verdict, "stance": stance,
                           "rebuttal": rebuttal},
                          client.model_id, latency_ms)
            except Exception as e:
                print(f"[panel] WARNING: debate cache write failed ({e}) - "
                      f"continuing with the uncached position", flush=True)
            return verdict, stance, rebuttal, latency_ms, False, None
        except Exception as e:
            last_err = e
    return dict(own_verdict), "maintain", None, latency_ms, False, last_err


def resolve_panel(positions):
    """Deterministic resolution of post-debate positions (no LLM call).

    positions: [{"model": id, "verdict": dict|None, ...}] - one per panel
    judge, verdict None when that judge failed both rounds.

    Policy (fail-safe, mirrors the committee):
      - one valid verdict            -> use it, needs review (uncorroborated)
      - all agree on label+category  -> consensus, highest confidence wins
      - same label, category split   -> highest confidence wins, needs review
      - label split                  -> most severe label wins (highest
                                        confidence within it), needs review
    Returns (effective_verdict|None, info). None only when every judge
    failed.
    """
    valid = [p for p in positions if p["verdict"] is not None]
    if not valid:
        return None, {"agreement": False, "needs_human_review": True,
                      "note": "every panel judge failed"}
    if len(valid) == 1:
        return dict(valid[0]["verdict"]), {
            "agreement": False, "needs_human_review": True,
            "note": "only one panel judge returned a valid verdict"}
    labels = {p["verdict"]["verdict"] for p in valid}
    cats = {p["verdict"]["category"] for p in valid}
    if len(labels) == 1 and len(cats) == 1:
        eff = max(valid, key=lambda p: p["verdict"]["confidence"])
        return dict(eff["verdict"]), {
            "agreement": True, "needs_human_review": False,
            "note": None}
    if len(labels) == 1:
        eff = max(valid, key=lambda p: p["verdict"]["confidence"])
        return dict(eff["verdict"]), {
            "agreement": False, "needs_human_review": True,
            "note": "judges agree on the verdict but dispute the category"}
    worst = max(labels, key=lambda v: SEVERITY[v])
    side = [p for p in valid if p["verdict"]["verdict"] == worst]
    eff = max(side, key=lambda p: p["verdict"]["confidence"])
    return dict(eff["verdict"]), {
        "agreement": False, "needs_human_review": True,
        "note": "judges disagree after debate; using the more severe "
                "verdict"}


def judge_candidates_panel(candidates, clients, cache_db=None,
                           prompt_version=None, verbose=True, debate=None):
    """Panel variant of judge_candidates: every candidate is judged by all
    `clients` independently; disputes go through one debate round (when
    `debate`); a deterministic resolver picks the effective verdict.

    Same return shape as judge_candidates, plus per-result `panel` blocks
    and a per-model `panel_report` in stats (the participation audit: what
    each judge received, answered, revised and got wrong-or-right)."""
    prompt_version = prompt_version or judge_config.PROMPT_VERSION
    if debate is None:
        debate = judge_config.LLM_JUDGE_DEBATE
    if not judge_config.LLM_JUDGE_ENABLED:
        if verbose:
            print("[panel] LLM_JUDGE_ENABLED=0 - skipping all candidates")
        return {"results": [], "dropped": [],
                "stats": {"total": len(candidates), "judged": 0,
                          "cache_hits": 0, "dropped": 0, "disabled": True}}
    if not clients or len(clients) < 2:
        raise ValueError("panel needs at least two clients")
    ids = [c.model_id for c in clients]
    dupes = sorted({m for m in ids if ids.count(m) > 1})
    if dupes:
        raise ValueError(
            f"panel clients must use distinct models - duplicated: {dupes}")
    cache = JudgeCache(cache_db or judge_config.CACHE_DB)

    report = {c.model_id: {"assigned": 0, "valid_verdicts": 0,
                           "failures": 0, "failure_examples": [],
                           "debates": 0, "revised": 0,
                           "agreed_with_final": 0, "cache_hits": 0,
                           "latency_ms_total": 0}
              for c in clients}
    iso_min, iso_max = _iso_bounds(candidates)
    results, dropped = [], []
    cache_hits = needs_review = debated_candidates = 0
    # Initial verdicts run in parallel per candidate - one thread per
    # judge, so wall-clock for a 2-judge panel is ~max(A, B) instead of
    # A + B. Results come back in `clients` order regardless of finish
    # order (executor.map preserves input order), so the participation
    # audit and debate framing stay stable.
    _pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(len(clients), 1),
        thread_name_prefix="panel-judge")
    try:
        for i, cand in enumerate(candidates, 1):
            positions = []
            client_results = list(_pool.map(
                lambda cl: _verdict_from_client(cand, cl, cache,
                                                prompt_version),
                clients))
            for cl, (verdict, latency, was_cached, err) in zip(
                    clients, client_results):
                r = report[cl.model_id]
                r["assigned"] += 1
                r["latency_ms_total"] += latency
                if was_cached:
                    r["cache_hits"] += 1
                    cache_hits += 1
                if verdict is None:
                    r["failures"] += 1
                    if len(r["failure_examples"]) < 3:
                        r["failure_examples"].append(str(err))
                else:
                    r["valid_verdicts"] += 1
                positions.append({"model": cl.model_id, "client": cl,
                                  "verdict": verdict,
                                  # initial_verdict is what round-1 returned.
                                  # `verdict` gets rewritten below in the
                                  # debate loop when a judge revises, so
                                  # holding a copy here is what lets the
                                  # panel_audit table answer 'what did
                                  # llama say BEFORE it heard the peers'.
                                  "initial_verdict": (dict(verdict)
                                                       if verdict else None),
                                  "stance": None,
                                  "rebuttal": None, "revised": False,
                                  "failed": verdict is None,
                                  "cached": was_cached,
                                  "latency_ms": latency,
                                  "error": str(err) if err else None})

            valid = [p for p in positions if p["verdict"] is not None]
            did_debate = False
            if (debate and len(valid) >= 2
                    and _panel_disagrees([p["verdict"] for p in valid])):
                did_debate = True
                debated_candidates += 1
                # Peers are anonymized by panel position, in config order,
                # so every judge sees the identical dispute framing.
                pre_debate = {p["model"]: dict(p["verdict"]) for p in valid}

                def _one_debate(p):
                    peers = [{"analyst": f"Analyst {k + 1}",
                              "verdict": pre_debate[q["model"]]["verdict"],
                              "category": pre_debate[q["model"]]["category"],
                              "confidence":
                                  pre_debate[q["model"]]["confidence"],
                              "reasoning":
                                  pre_debate[q["model"]]["reasoning"]}
                             for k, q in enumerate(positions)
                             if q["verdict"] is not None
                             and q["model"] != p["model"]]
                    return p, _debate_from_client(
                        cand, pre_debate[p["model"]], peers, p["client"],
                        cache, prompt_version)

                # Debate round also parallelises per judge - same
                # rationale as the initial verdicts, wall-clock ~max
                # instead of sum.
                debate_results = list(_pool.map(_one_debate, valid))
                for p, (verdict, stance, rebuttal, latency, was_cached,
                        err) in debate_results:
                    r = report[p["model"]]
                    r["debates"] += 1
                    r["latency_ms_total"] += latency
                    if was_cached:
                        r["cache_hits"] += 1
                        cache_hits += 1
                    if err is not None:
                        # Round-1 verdict stands; the failure is recorded
                        # but does not discard an already-valid judgment.
                        r["failures"] += 1
                        if len(r["failure_examples"]) < 3:
                            r["failure_examples"].append(
                                f"debate: {err}")
                    before = pre_debate[p["model"]]
                    revised = (stance == "revise"
                               or verdict["verdict"] != before["verdict"]
                               or verdict["category"] != before["category"])
                    if revised:
                        r["revised"] += 1
                    p.update(verdict=verdict, stance=stance,
                             rebuttal=rebuttal, revised=revised,
                             latency_ms=p["latency_ms"] + latency)

            effective, info = resolve_panel(positions)
            if effective is None:
                dropped.append({
                    "candidate_id": cand["candidate_id"],
                    "error": "; ".join(
                        f"{p['model']}: {p['error']}" for p in positions)})
                if verbose:
                    print(f"[panel] {i}/{len(candidates)} "
                          f"{cand['candidate_id']}: DROPPED (all failed)")
                continue

            guardrail_info = None
            if judge_config.RULE_GUARDRAIL:
                effective, guardrail_info = apply_rule_guardrail(cand,
                                                                 effective)
                if guardrail_info:
                    # Every judge (or the lone survivor) called a
                    # fired-rule candidate benign - the exact failure mode
                    # the panel exists to catch, so always escalate.
                    info["needs_human_review"] = True
                    note = ("rule guardrail overrode a benign panel "
                            "verdict")
                    info["note"] = (f"{info['note']}; {note}"
                                    if info.get("note") else note)
            for p in positions:
                if (p["verdict"] is not None and p["verdict"]["verdict"]
                        == effective["verdict"]):
                    report[p["model"]]["agreed_with_final"] += 1
            if info["needs_human_review"]:
                needs_review += 1

            results.append({
                "candidate_id": cand["candidate_id"],
                "kind": cand["kind"],
                "verdict": effective,
                "guardrail": guardrail_info,
                "panel": {
                    "judges": [{k: p[k] for k in
                                ("model", "stance", "rebuttal", "revised",
                                 "failed", "cached", "latency_ms", "error")}
                               | {"verdict": _slim_verdict(p["verdict"]),
                                  "initial_verdict": _slim_verdict(
                                      p.get("initial_verdict"))}
                               for p in positions],
                    "debate": did_debate,
                    **info,
                },
                "priority": priority_score(cand, effective, iso_min,
                                           iso_max),
                "cached": all(p["cached"] for p in positions),
                "latency_ms": sum(p["latency_ms"] for p in positions),
            })
            if verbose:
                flag = " ⚖ REVIEW" if info["needs_human_review"] else ""
                votes = " ".join(
                    f"{p['model'].split('/')[-1][:18]}="
                    f"{p['verdict']['verdict'] if p['verdict'] else 'X'}"
                    for p in positions)
                print(f"[panel] {i}/{len(candidates)} "
                      f"{cand['candidate_id']:<24} "
                      f"{effective['verdict']:<10} {votes}"
                      f"{' (debated)' if did_debate else ''}{flag}")
    finally:
        _pool.shutdown(wait=True)
        cache.close()

    for model_id, r in report.items():
        calls = r["valid_verdicts"] + r["failures"]
        r["mean_latency_ms"] = (int(r["latency_ms_total"] / calls)
                                if calls else None)
        del r["latency_ms_total"]

    results.sort(key=lambda r: -r["priority"])
    return {"results": results, "dropped": dropped,
            "stats": {"total": len(candidates), "judged": len(results),
                      "cache_hits": cache_hits, "dropped": len(dropped),
                      "needs_review": needs_review,
                      "debated_candidates": debated_candidates,
                      "debate_enabled": bool(debate),
                      "panel": True,
                      "models": ids,
                      "model": ids[0],
                      "panel_report": report,
                      "prompt_version": prompt_version}}


def save_verdicts(out, pcap_name, output_dir=None):
    """Write the judged batch to llm_judge/output/ as JSON; returns the path."""
    output_dir = output_dir or judge_config.OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.splitext(os.path.basename(pcap_name))[0]
    path = os.path.join(output_dir, f"verdicts_{base}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pcap": os.path.basename(pcap_name),
                   "generated_at": datetime.now(timezone.utc)
                                          .isoformat(timespec="seconds"),
                   **out}, f, indent=2)
    return path

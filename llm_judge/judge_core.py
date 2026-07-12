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
import hashlib
import ipaddress
import json
import os
import sqlite3
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
    """SQLite verdict cache. Only schema-validated verdicts are written."""

    def __init__(self, db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
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
        row = self._conn.execute(
            "SELECT verdict_json FROM judge_cache WHERE fingerprint = ?",
            (fp,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, fp, prompt_version, verdict, model_id, latency_ms):
        self._conn.execute(
            "INSERT OR REPLACE INTO judge_cache VALUES (?, ?, ?, ?, ?, ?)",
            (fp, prompt_version, canonical_json(verdict),
             datetime.now(timezone.utc).isoformat(timespec="seconds"),
             model_id, int(latency_ms)))
        self._conn.commit()

    def stats(self):
        n, = self._conn.execute("SELECT COUNT(*) FROM judge_cache").fetchone()
        return {"entries": int(n)}

    def close(self):
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


def assemble_candidates(S, findings, lstm_flags=None, max_candidates=None):
    """Union of everything any detector flagged, one JSON blob each.

    lstm_flags: optional {ip: bin_flag_count} attribution from the LSTM
    layer (null in the blob when not provided - the standalone pipeline
    treats the LSTM as an optional, slow extra).

    Returns {"candidates": [...], "capped": [ids dropped by the batch cap]}.
    Rule-triggered candidates always survive the cap; the statistical-only
    remainder is ranked by iso_score (most anomalous first).
    """
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
            "advanced_signals": {"beaconing": None, "dns_tunneling": None,
                                 "dga": None, "tls_anomaly": None,
                                 "fusion_score": None},
            "device_context": {"category": "unknown", "hostname": None,
                               "oui_vendor": None},
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
            "advanced_signals": {"beaconing": None, "dns_tunneling": None,
                                 "dga": None, "tls_anomaly": None,
                                 "fusion_score": None},
            "device_context": {"category": "unknown", "hostname": None,
                               "oui_vendor": None},
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
    return round(
        judge_config.W_ANOM * norm_anom
        + judge_config.W_JUDGE_CONF * verdict["confidence"]
        + judge_config.W_CAT * judge_config.CATEGORY_WEIGHT[verdict["category"]]
        + judge_config.W_TI * 0.0,
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


def analyst_commentary(client, context, verdicts, session_label="S1"):
    """One extra LLM call at the end of a judge run: turn all findings
    into a free-form analyst-style paragraph. Uses the same provider as
    the judge but with the verdict schema turned off, so the response is
    plain prose.

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
        prose_client = llm_clients.make_client(verdict_schema=None)

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
            fp = fingerprint(cand, prompt_version, client.model_id)
            verdict = cache.get(fp)
            latency_ms, was_cached = 0, verdict is not None
            if was_cached:
                cache_hits += 1
            else:
                last_err = None
                for attempt in (1, 2):  # retry once on any failure
                    try:
                        t0 = time.perf_counter()
                        raw = client.judge(SYSTEM_PROMPT,
                                           json.dumps(cand, indent=2))
                        latency_ms = int((time.perf_counter() - t0) * 1000)
                        verdict = validate_verdict(json.loads(raw))
                        break
                    except Exception as e:
                        last_err, verdict = e, None
                if verdict is None:
                    dropped.append({"candidate_id": cand["candidate_id"],
                                    "error": str(last_err)})
                    if verbose:
                        print(f"[judge] {i}/{len(candidates)} "
                              f"{cand['candidate_id']}: DROPPED ({last_err})")
                    continue
                cache.put(fp, prompt_version, verdict, client.model_id,
                          latency_ms)
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

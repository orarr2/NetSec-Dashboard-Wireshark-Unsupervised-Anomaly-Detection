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

# Q3 (scale): response schema for a batched call - one verdict object
# per candidate, each echoing its candidate_id so responses map back
# even when the model reorders or drops entries.
BATCH_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    **VERDICT_SCHEMA["properties"],
                },
                "required": ["candidate_id"] + VERDICT_SCHEMA["required"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}

BATCH_PROMPT_SUFFIX = """

## Batch mode
This request carries SEVERAL candidates as {"candidates": [...]}. Judge
each candidate INDEPENDENTLY, exactly as if it were the only one in the
request - never let one candidate's signals bleed into another's
verdict. Return {"verdicts": [...]} with EXACTLY one entry per
candidate, each echoing that candidate's candidate_id verbatim, in the
same order as the input."""

SYSTEM_PROMPT = """You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one detector flagged. Reply with ONE JSON object matching the
schema. No prose outside the JSON, no markdown fences.

Rules:
1. verdict in {benign, suspicious, malicious}; category from the schema
   enum; recommended_action is a suggestion for a human, never executed.
2. Ground every claim in the blob - cite the field names you used in
   evidence_features. null means unknown, not zero.
3. Contradictory or thin evidence -> "suspicious". Strong and unambiguous
   -> "malicious".
4. confidence in [0.0, 1.0]. reasoning is ONE paragraph, no newlines,
   at most 400 characters.
5. Deterministic rules are HIGH-PRECISION. If any of rule_signals
   .scan_alerts / .amp_alerts / .flood_alerts is non-empty, or
   .arp_multi_mac is true, classify into the matching attack category
   and do NOT return "benign". Override a fired rule only when you can
   name concrete counter-evidence in the blob.

Schema:
{schema}

Categories:
- port_scan: rule_signals.scan_alerts non-empty, OR one TCP flag
  dominates with a high ratio to total packets. Applies to horizontal
  (many unique_dsts) AND vertical (low unique_dsts, one flag near 100%
  of packets) scans - low unique_dsts does NOT rule this out.
- syn_flood: session-level SYN rate high with many spoofed sources
  (rule_signals.flood_alerts on a candidate of kind "session").
- arp_mitm: rule_signals.arp_multi_mac is true.
- dns_amp: rule_signals.amp_alerts non-empty AND UDP/53 responses
  dominate.
- beaconing_c2: advanced_signals.beaconing non-null and periodic.
- dns_tunnel: advanced_signals.dns_tunneling non-null OR unusually
  long DNS queries.
- benign_anomaly: outlier flagged ONLY by isolation_forest or
  dbscan_noise with NO rule fired and no attack shape. Never use this
  when any rule has fired.

Enrichment fields (each may be null=unknown):
- session_context: hour_of_day, day_of_week, iso_timestamp. Off-hours
  activity from a workstation is worth a note.
- device_context: oui_vendor, hostname, category. Workstation with SMB
  fanout reads as lateral movement; the same traffic from a printer
  does not.
- websites: top_http_hosts, top_tls_sni, top_dns_queries (up to 5
  each). Random / high-entropy names corroborate advanced_signals.dga
  and .beaconing; familiar CDNs corroborate benign.
- traffic: top_dst_ports (22/tcp, 445/tcp, 3389/tcp, 5985/tcp on an
  internal host = lateral-movement signal); bytes_in / bytes_out /
  upload_ratio - upload_ratio near 1.0 with meaningful bytes_out to a
  public destination = exfiltration shape.
- tls: versions, has_weak_version, weak_cipher_count. A modern device
  on only TLS 1.0 / SSLv3 corroborates advanced_signals.tls_anomaly.
- baseline_history: seen_before, days_since_first_seen,
  prior_verdict_summary. A familiar IP that was benign for 20 sessions
  and now looks malicious is more alarming than one that always
  looked suspicious; a first-time malicious IP is more alarming than
  a familiar one.

Examples:

1. Vertical SYN scan. features {"syn_count": 1002, "count": 1007,
"unique_dsts": 1}; rule_signals.scan_alerts [{"type": "SYN", "ratio":
1.0}]. Low unique_dsts but the rule fired and nearly every packet is
a SYN:
{"verdict":"malicious","category":"port_scan","confidence":0.95,
 "evidence_features":["rule_signals.scan_alerts","syn_count","count"],
 "reasoning":"Scan rule fired: 1002/1007 packets are SYNs (ratio 1.0)
 to one destination - vertical SYN scan.",
 "recommended_action":"investigate"}

2. ML-only outlier. ml_signals {"anomaly": true, "cluster": -1};
every rule_signals list empty; arp_multi_mac false:
{"verdict":"benign","category":"benign_anomaly","confidence":0.6,
 "evidence_features":["ml_signals.anomaly","ml_signals.cluster"],
 "reasoning":"Flagged only by unsupervised detectors; no rule fired
 and no attack shape in the blob.",
 "recommended_action":"monitor"}
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


def _resolve_evidence_path(candidate, path):
    """Walk a dotted path (e.g. "rule_signals.scan_alerts[0].count") over
    the candidate blob. Returns True if the path resolves to a non-None
    value, False otherwise. Never raises - a malformed path is just
    invalid evidence.
    """
    import re
    if not path or not isinstance(candidate, dict):
        return False
    node = candidate
    # Split on dots but keep [N] indices attached
    for part in path.split("."):
        m = re.match(r"^([^\[]+)(\[(\d+)\])?$", part.strip())
        if not m:
            return False
        key = m.group(1)
        idx = m.group(3)
        if isinstance(node, dict):
            if key not in node:
                return False
            node = node[key]
        else:
            return False
        if idx is not None:
            try:
                i = int(idx)
                if not isinstance(node, list) or i >= len(node):
                    return False
                node = node[i]
            except (ValueError, TypeError):
                return False
    return node is not None


def evaluate_evidence(verdict, candidate):
    """SCIENTIFIC_AUDIT 3.7: check that every evidence_features citation
    resolves to a field that exists (and is non-None) in the candidate
    blob. Diagnostic only - never rejects a verdict. Returns a dict:

        {"evidence_valid": bool,
         "evidence_invalid_features": [list of paths that did not resolve]}

    Attach this to the verdict (or the panel judge row) so a CI job can
    trend "how often does the model cite made-up feature names".
    """
    if not verdict or "evidence_features" not in verdict:
        return {"evidence_valid": True, "evidence_invalid_features": []}
    invalid = []
    for path in verdict["evidence_features"]:
        if not _resolve_evidence_path(candidate, str(path)):
            invalid.append(str(path))
    return {"evidence_valid": len(invalid) == 0,
            "evidence_invalid_features": invalid}


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
# I2 blob enrichments: websites the IP reached, top destination ports,
# directional byte totals. All three blocks are always present in the
# candidate but any of their fields may be null (unknown), following the
# SYSTEM_PROMPT rule "null = unknown, not zero".
_EMPTY_WEB = {"top_http_hosts": None, "top_tls_sni": None,
              "top_dns_queries": None}
_EMPTY_TRAFFIC = {"top_dst_ports": None, "bytes_in": None, "bytes_out": None,
                  "upload_ratio": None}

# The manuf parser (OUI -> vendor) is instantiated at most once per process
# and hidden behind a getter so the import cost is paid only when the worker
# actually needs an OUI lookup (the dashboard already has its own parser).
_MANUF_PARSER = None
_MANUF_TRIED = False


def _oui_vendor(mac):
    """Best-effort OUI -> vendor string. Returns None on any failure
    (manuf missing, unparseable MAC, unknown prefix). No exceptions
    propagate: an enrichment miss must never break judgment."""
    global _MANUF_PARSER, _MANUF_TRIED
    if not mac:
        return None
    if _MANUF_PARSER is None and not _MANUF_TRIED:
        _MANUF_TRIED = True
        try:
            from manuf import manuf as _manuf_mod
            _MANUF_PARSER = _manuf_mod.MacParser()
        except Exception:
            _MANUF_PARSER = None
    if _MANUF_PARSER is None:
        return None
    try:
        return (_MANUF_PARSER.get_manuf_long(mac)
                or _MANUF_PARSER.get_manuf(mac)
                or None)
    except Exception:
        return None


def _lightweight_device_category(vendor, ports, dns_names):
    """L6: best-effort device category from a small heuristic table when
    no dashboard-produced inventory is attached. Returns one of:
    Mobile / Desktop / IoT / Camera / Printer / VoIP Phone / Router /
    Streaming / Server / unknown. Kept intentionally small; the full
    classifier lives in app/dashboard_module.py and takes 380 LOC.
    """
    v = (vendor or "").lower()
    dns_str = " ".join(dns_names or []).lower()
    port_set = set(ports or [])
    # Port-based signals - strong indicators, checked first
    if 62078 in port_set:
        return "Mobile"           # iOS lockdown service
    if 5228 in port_set:
        return "Mobile"           # Google GCM push
    if port_set & {9100, 631, 515}:
        return "Printer"
    if port_set & {5060, 5061, 2000}:
        return "VoIP Phone"
    if 554 in port_set:
        return "Camera"           # RTSP
    if port_set & {8008, 8009, 8443} and "google" in v:
        return "Streaming"        # Chromecast
    # Vendor / DNS name signals
    if "apple" in v:
        return "Mobile" if "iphone" in dns_str or "ipad" in dns_str else "Desktop"
    if "samsung" in v:
        return "Mobile" if "galaxy" in dns_str else "Consumer"
    if "google" in v and "nest" in dns_str:
        return "IoT"
    if any(k in v for k in ("cisco", "meraki", "juniper", "aruba", "mikrotik")):
        return "Router"
    if any(k in v for k in ("netgear", "tp-link", "asus", "linksys", "d-link")):
        return "Router"
    if any(k in v for k in ("raspberry", "espressif", "arduino")):
        return "IoT"
    if "roku" in v or "amazon" in v and "fire" in dns_str:
        return "Streaming"
    if "microsoft" in v or "xbox" in dns_str:
        return "Desktop"
    if "sony" in v and "playstation" in dns_str:
        return "Streaming"
    # Ubiquitous but weak - only DNS names left
    if any(k in dns_str for k in ("iphone", "ipad", "-mobile")):
        return "Mobile"
    if any(k in dns_str for k in ("macbook", "-pc", "-laptop", "-desktop")):
        return "Desktop"
    if any(k in dns_str for k in ("printer", "hp-", "canon-")):
        return "Printer"
    return "unknown"


def _lightweight_device_context(S, ip):
    """Fallback device_context derived from just S['ip_to_mac'],
    S['dns_per_ip'] and S['dst_ports_per_ip'] - no dashboard-module
    dependency. Used when the caller did not build a full local
    inventory (the worker path). Returns the empty default block if we
    can't derive anything useful."""
    out = dict(_EMPTY_DEV)
    mac_counter = (S.get("ip_to_mac") or {}).get(ip)
    if mac_counter:
        try:
            mac = mac_counter.most_common(1)[0][0]
            vendor = _oui_vendor(mac)
            if vendor:
                out["oui_vendor"] = vendor
        except Exception:
            pass
    # Prefer mDNS-style hostname (.local without a leading '_' for a
    # service record). No printable hostname? Leave null - the LLM is
    # taught to read null as unknown.
    dns = (S.get("dns_per_ip") or {}).get(ip)
    dns_names = []
    if dns:
        try:
            for q, _ in dns.most_common(20):
                dns_names.append(q)
                if (out["hostname"] is None and q.endswith(".local")
                        and not q.startswith("_")):
                    out["hostname"] = q
        except Exception:
            pass
    # L6: try to derive category from OUI + top dst ports + DNS names.
    ports_counter = (S.get("dst_ports_per_ip") or {}).get(ip)
    port_ints = []
    if ports_counter:
        try:
            for k, _ in ports_counter.most_common(10):
                # keys are "port/proto" strings from run_pipeline
                port_str = str(k).split("/")[0]
                if port_str.isdigit():
                    port_ints.append(int(port_str))
        except Exception:
            pass
    try:
        cat = _lightweight_device_category(out["oui_vendor"], port_ints,
                                            dns_names)
        if cat and cat != "unknown":
            out["category"] = cat
    except Exception:
        pass
    return out


def _top_n_from_counter(counter, n=5, key_label="host"):
    """{item: count} Counter/dict -> [{key_label: item, count: int}] top-N.
    Returns None (not []) on empty input so the blob field carries
    'unknown' semantics rather than 'observed zero'."""
    if not counter:
        return None
    try:
        items = counter.most_common(n)
    except AttributeError:
        # plain dict: sort by value desc, take top n
        items = sorted(counter.items(), key=lambda kv: -kv[1])[:n]
    if not items:
        return None
    return [{key_label: str(k), "count": int(v)} for k, v in items
            if k and v > 0] or None


def _websites_for(S, ip):
    """Build the 'websites' block for one candidate IP from S maps."""
    http_c = (S.get("http_host_per_ip") or {}).get(ip)
    sni_c  = (S.get("tls_sni_per_ip") or {}).get(ip)
    dns_c  = (S.get("dns_per_ip") or {}).get(ip)
    # Drop mDNS/.arpa noise from top DNS queries - the LLM cares about
    # external browsing, not local service discovery.
    if dns_c:
        dns_c = {k: v for k, v in dns_c.items()
                 if k and not k.endswith(".local")
                 and not k.endswith(".arpa")
                 and not k.endswith(".in-addr.arpa")
                 and not k.startswith("_")}
    return {
        "top_http_hosts": _top_n_from_counter(http_c, 5, "host"),
        "top_tls_sni": _top_n_from_counter(sni_c, 5, "host"),
        "top_dns_queries": _top_n_from_counter(dns_c, 5, "host"),
    }


_EMPTY_TLS = {"versions": None, "weak_cipher_count": None,
              "has_weak_version": None}


def _tls_for(S, ip):
    """Return the TLS summary block for one candidate IP - which TLS
    versions the IP negotiated + any weak-cipher count. Consumed from
    S['threats']['tls_versions_by_ip'] (populated by run_advanced_threats).
    Returns all-null defaults when the pipeline observed no TLS traffic
    for this IP (SYSTEM_PROMPT teaches null = unknown)."""
    threats = S.get("threats") or {}
    if not isinstance(threats, dict) or not threats.get("available"):
        return dict(_EMPTY_TLS)
    by_ip = threats.get("tls_versions_by_ip") or {}
    entry = by_ip.get(ip)
    if not entry:
        return dict(_EMPTY_TLS)
    return {
        "versions": entry.get("versions") or None,
        "weak_cipher_count": (entry.get("weak_cipher_count")
                              if entry.get("weak_cipher_count") is not None
                              else None),
        "has_weak_version": bool(entry.get("has_weak_version")),
    }


_EMPTY_HISTORY = {"seen_before": None, "days_since_first_seen": None,
                  "prior_verdict_summary": None}


def _history_for(S, ip):
    """Return the baseline_history block for one candidate IP: has this
    IP been seen in any prior session? If so, how long ago and what was
    the panel's summary verdict last time? Consumed from
    S['baseline_history'][ip] which the worker populates from the DB
    at analyze time (see server/worker.py::_attach_baseline_history).
    Returns null defaults when no history is attached."""
    hist_map = S.get("baseline_history") or {}
    entry = hist_map.get(ip)
    if not entry:
        return dict(_EMPTY_HISTORY)
    return {
        "seen_before": bool(entry.get("seen_before")),
        "days_since_first_seen": entry.get("days_since_first_seen"),
        "prior_verdict_summary": entry.get("prior_verdict_summary"),
    }


def _traffic_for(S, ip):
    """Build the 'traffic' block: top dst ports + directional byte
    totals for one candidate IP. bytes_src/bytes_dst come from the
    pipeline unchanged; if either is missing, the field is null."""
    ports_c = (S.get("dst_ports_per_ip") or {}).get(ip)
    ports = _top_n_from_counter(ports_c, 5, "port_proto")
    bytes_out = None
    bytes_in = None
    bs = S.get("bytes_src") or {}
    bd = S.get("bytes_dst") or {}
    if ip in bs:
        try:
            bytes_out = int(bs[ip])
        except Exception:
            bytes_out = None
    if ip in bd:
        try:
            bytes_in = int(bd[ip])
        except Exception:
            bytes_in = None
    upload_ratio = None
    if isinstance(bytes_in, int) and isinstance(bytes_out, int):
        total = bytes_in + bytes_out
        if total > 0:
            upload_ratio = round(bytes_out / total, 3)
    return {"top_dst_ports": ports, "bytes_in": bytes_in,
            "bytes_out": bytes_out, "upload_ratio": upload_ratio}


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
    t0 = S.get("t0")
    t1 = S.get("t1")
    duration_s = max((t1 - t0).total_seconds(), 0.0) if (t0 and t1) else 0.0
    # Time context: an operator judging a candidate benefits from knowing
    # WHEN the capture ran (a scan at 03:17 Sunday is worth more attention
    # than one at 14:00 Wednesday). The LLM prompt teaches null=unknown, so
    # a synthetic test session without a real timestamp lands as three nulls.
    if t0 is not None:
        _wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][t0.weekday()]
        time_ctx = {"iso_timestamp": t0.isoformat(timespec="seconds"),
                    "hour_of_day": int(t0.hour),
                    "day_of_week": _wd}
    else:
        time_ctx = {"iso_timestamp": None, "hour_of_day": None,
                    "day_of_week": None}
    session_context = {
        "duration_s": round(duration_s, 1),
        "total_packets": int(S["n_pkts"]),
        "total_ips": int(len(S["ips_src"])),
        **time_ctx,
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
        # device_context: prefer the caller-supplied inventory (dashboard
        # path); fall back to lightweight OUI+hostname derived from S maps
        # so the worker path is no longer 100% "unknown/null/null".
        dev_ctx = device_context.get(ip)
        if not dev_ctx or dev_ctx == _EMPTY_DEV:
            dev_ctx = _lightweight_device_context(S, ip)
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
            "device_context": dev_ctx,
            # I2: what this IP reached on the network (top HTTP hosts,
            # TLS SNIs, DNS queries) and its traffic profile (top dst
            # ports, directional bytes). All fields default to null when
            # the pipeline collected nothing for this IP.
            "websites": _websites_for(S, ip),
            "traffic": _traffic_for(S, ip),
            # L4: TLS versions + weak cipher summary. Populated from the
            # advanced-engines TLS pass. All null when the IP had no
            # TLS traffic.
            "tls": _tls_for(S, ip),
            # L5: baseline history - has the pipeline judged this IP in a
            # prior session? Empty when the worker did not attach
            # S['baseline_history'] (dashboard path or first-time IP).
            "baseline_history": _history_for(S, ip),
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
            # I2 enrichments: browsing and directional bytes are per-IP;
            # a session-scope candidate (aggregate flood) has no single
            # owner, so both blocks are the null defaults.
            "websites": dict(_EMPTY_WEB),
            "traffic": dict(_EMPTY_TRAFFIC),
            "tls": dict(_EMPTY_TLS),
            "baseline_history": dict(_EMPTY_HISTORY),
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


_GUARDRAIL_ESCAPE_PATTERNS = {
    # SCIENTIFIC_AUDIT 3.1: whitelist of specific evidence patterns that
    # justify letting a "benign" verdict past the guardrail on a
    # fired-rule candidate. Every entry is (rule_category, allowed
    # evidence_features prefix). If a benign verdict at >= 0.85 confidence
    # cites at least one of these AND the reasoning contains the trigger
    # phrase, the guardrail lets it through with a `guardrail_bypassed`
    # audit trail. Grow this list conservatively - a false permissive
    # here silences real attacks.
    #
    # dns_amp: benign public resolver caught by the amp rule. Only
    # accept the escape if the model cites the resolver identity.
    "dns_amp": [
        {"prefix": "rule_signals.amp_alerts", "phrase": "public resolver"},
        {"prefix": "enrichments.reverse_dns",  "phrase": "public resolver"},
        {"prefix": "enrichments.reverse_dns",  "phrase": "anycast"},
        {"prefix": "device_context.oui_vendor", "phrase": "cloud provider"},
    ],
}


def _guardrail_escape_allowed(candidate, verdict, expected):
    """SCIENTIFIC_AUDIT 3.1: return (allowed: bool, note: str) - True
    when the model's benign verdict cites concrete evidence that the
    rule misfired, per the whitelist above. Confidence threshold: 0.85
    (proposal). All other cases: guardrail overrides as before.
    """
    if not judge_config.LLM_JUDGE_GUARDRAIL_ESCAPE:
        return False, ""
    if float(verdict.get("confidence") or 0.0) < 0.85:
        return False, ""
    patterns = _GUARDRAIL_ESCAPE_PATTERNS.get(expected) or []
    if not patterns:
        return False, ""
    cited = verdict.get("evidence_features") or []
    reasoning = (verdict.get("reasoning") or "").lower()
    for pat in patterns:
        cited_ok = any(str(c).startswith(pat["prefix"]) for c in cited)
        phrase_ok = pat["phrase"].lower() in reasoning
        if cited_ok and phrase_ok:
            return True, (f"escape: cited '{pat['prefix']}' + reasoning "
                          f"contains '{pat['phrase']}'")
    return False, ""


def apply_rule_guardrail(candidate, verdict):
    """Return (effective_verdict, guardrail_info). guardrail_info is None
    when nothing was overridden."""
    expected = rule_expected_category(candidate)
    if expected is None or verdict["verdict"] != "benign":
        return verdict, None
    # SCIENTIFIC_AUDIT 3.1 escape hatch - allow narrow, evidence-backed
    # benigns to pass. Every bypass is audited in `guardrail_bypassed`
    # so a permissive drift is visible in the panel report.
    escape_ok, escape_note = _guardrail_escape_allowed(
        candidate, verdict, expected)
    if escape_ok:
        return verdict, {"applied": False,
                         "guardrail_bypassed": True,
                         "rule_category": expected,
                         "model_verdict": verdict["verdict"],
                         "model_category": verdict["category"],
                         "note": escape_note}
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
    raises - a failure comes back as (None, latency, False, exception).

    Retry only helps transient errors (network blip, one-off bad JSON from
    the model). A permanent failure (4xx from the server: unsupported
    schema, bad key, malformed body) will fail identically on the second
    try - and on rate-limited providers the extra call triggers a 429 that
    stalls a parallel panel. `JudgeClientError.permanent=True` short-
    circuits the retry for exactly that reason.
    """
    fp = fingerprint(cand, prompt_version, client.model_id)
    cached = cache.get(fp)
    if cached is not None:
        return cached, 0, True, None
    last_err, latency_ms, verdict = None, 0, None
    for _attempt in (1, 2):  # retry once on transient failures
        try:
            t0 = time.perf_counter()
            raw = client.judge(SYSTEM_PROMPT, json.dumps(cand, indent=2))
            latency_ms = int((time.perf_counter() - t0) * 1000)
            verdict = validate_verdict(json.loads(raw))
            # SCIENTIFIC_AUDIT 3.7: attach evidence-faithfulness diagnostic
            # (never rejects; a CI job can trend the rate of hallucinated
            # citations over time)
            verdict.update(evaluate_evidence(verdict, cand))
            break
        except Exception as e:
            last_err, verdict = e, None
            if getattr(e, "permanent", False):
                break  # 4xx from the server - a retry would fail the same
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


def _too_large_error(err):
    """Heuristic: did the provider reject the request for SIZE, where a
    SMALLER batch can still succeed? Two flavors seen in production
    (session 13, Groq free tier):
    - HTTP 413 "Request too large": the payload exceeds the model's
      per-request cap outright (llama-8b, 6k TPM vs ~7.3k batch).
    - HTTP 429 "tokens per minute (TPM)": the payload doesn't fit the
      REMAINING minute window (gpt-oss, 8k TPM) - a half-size batch
      usually does.
    A 429 on the DAILY pool ("tokens per day"/TPD) is explicitly NOT
    size - nothing fits until the pool resets, so bisecting would just
    burn attempts; that one flows to the permanent-skip path instead."""
    text = str(err or "")
    if "tokens per day" in text or "(TPD)" in text:
        return False
    return ("413" in text or "Payload Too Large" in text
            or "Request too large" in text
            or "tokens per minute" in text or "(TPM)" in text)


def _batched_verdicts_from_client(cands, client, cache, prompt_version):
    """Q3: several candidates through ONE LLM call. Returns
    (verdicts, permanently_failed) where verdicts is
    {candidate_id: (verdict, latency_ms_share, False, None)} for the
    fresh, successfully-validated subset ONLY, and permanently_failed
    is True when the provider says no batch will EVER succeed for this
    judge right now (quota exhausted, schema rejected) - the prefetch
    loop uses it to stop burning calls on that judge's remaining
    slices.

    The batch is a pure accelerator with graceful degradation baked
    into the contract: cached candidates are skipped here (the panel
    loop serves them from cache), and every possible miss - the whole
    call failing, the response not parsing, an element failing
    validation, the model dropping or hallucinating a candidate_id -
    just leaves that candidate OUT of the returned dict, so the panel
    loop falls back to the ordinary per-candidate call for exactly the
    affected candidates. Worst case equals batching off, never worse.

    One size-specific rescue: a 413 / request-too-large rejection (a
    TPM cap smaller than the batch, measured on Groq's llama-8b: 6k
    TPM vs ~7.3k for a 5-candidate payload) bisects the batch and
    retries each half - the halves recurse further if still too big,
    so any TPM limit finds its own largest fitting size.

    Verdicts are cached under the same per-candidate fingerprint the
    single path uses, so a later re-run hits cache identically either
    way. Latency is attributed as an equal share of the one call."""
    fresh = []
    for cand in cands:
        fp = fingerprint(cand, prompt_version, client.model_id)
        if cache.get(fp) is None:
            fresh.append(cand)
    if len(fresh) < 2:
        return {}, False  # nothing to gain from a batched call
    items, latency_ms, last_err = None, 0, None
    for _attempt in (1, 2):  # same retry contract as the single path
        try:
            t0 = time.perf_counter()
            raw = client.judge(SYSTEM_PROMPT + BATCH_PROMPT_SUFFIX,
                               json.dumps({"candidates": fresh}, indent=2),
                               schema=BATCH_VERDICT_SCHEMA)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            parsed = json.loads(raw)
            items = parsed["verdicts"]
            if not isinstance(items, list):
                raise JudgeValidationError("verdicts is not a list")
            break
        except Exception as e:
            last_err, items = e, None
            if getattr(e, "permanent", False):
                break
    if items is None:
        if _too_large_error(last_err) and len(fresh) >= 3:
            # Payload exceeded a per-request/TPM cap - bisect and let
            # each half find its own fitting size. A half that shrinks
            # to one candidate skips the batch (the <2 guard above)
            # and rides the ordinary per-candidate path instead.
            mid = len(fresh) // 2
            out_a, perm_a = _batched_verdicts_from_client(
                fresh[:mid], client, cache, prompt_version)
            out_b, perm_b = _batched_verdicts_from_client(
                fresh[mid:], client, cache, prompt_version)
            out_a.update(out_b)
            return out_a, (perm_a and perm_b)
        permanent = bool(getattr(last_err, "permanent", False)
                         and not _too_large_error(last_err))
        print(f"[panel] batch call failed on {client.model_id} "
              f"({last_err}) - those candidates fall back to "
              f"per-candidate calls"
              + (" (skipping this judge's remaining batches)"
                 if permanent else ""), flush=True)
        return {}, permanent
    share = max(latency_ms // len(fresh), 1)
    by_id = {c.get("candidate_id"): c for c in fresh}
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        cid = item.pop("candidate_id", None)
        cand = by_id.get(cid)
        if cand is None or cid in out:
            continue  # hallucinated or duplicated id -> single-call fallback
        try:
            verdict = validate_verdict(item)
        except Exception:
            continue  # this one falls back to a per-candidate call
        verdict.update(evaluate_evidence(verdict, cand))
        try:
            cache.put(fingerprint(cand, prompt_version, client.model_id),
                      prompt_version, verdict, client.model_id, share)
        except Exception as e:
            print(f"[judge] WARNING: cache write failed ({e}) - "
                  f"continuing with the uncached verdict", flush=True)
        out[cid] = (verdict, share, False, None)
    return out, False


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


def resolve_panel(positions, quorum=None):
    """Deterministic resolution of post-debate positions (no LLM call).

    positions: [{"model": id, "verdict": dict|None, ...}] - one per panel
    judge, verdict None when that judge failed both rounds.
    quorum: "majority" (default) or "fail-safe". Overrides
        judge_config.LLM_JUDGE_PANEL_QUORUM when set.

    Policy:
      - one valid verdict          -> use it, needs review (uncorroborated)
      - all agree on label+category -> consensus, highest confidence wins
      - same label, category split -> highest confidence wins, needs review
      - label split + majority mode + strict majority (>50%) agrees on a
        label -> use majority's label, highest confidence within it
      - label split + fail-safe mode OR no majority -> most severe label
        wins, needs review (SCIENTIFIC_AUDIT 3.2: one hallucinating judge
        should NOT outvote two peers in a 3+ panel)
    Returns (effective_verdict|None, info). None only when every judge
    failed.
    """
    if quorum is None:
        quorum = judge_config.LLM_JUDGE_PANEL_QUORUM
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
    # Labels split. Majority mode (SCIENTIFIC_AUDIT 3.2) tries strict
    # majority first before the fail-safe: with 3+ judges, one
    # hallucinating "malicious" should not outvote two "benign" peers.
    if quorum == "majority":
        from collections import Counter
        counts = Counter(p["verdict"]["verdict"] for p in valid)
        top_label, top_n = counts.most_common(1)[0]
        # Strict majority = more than half of the valid judges
        if top_n * 2 > len(valid):
            side = [p for p in valid if p["verdict"]["verdict"] == top_label]
            eff = max(side, key=lambda p: p["verdict"]["confidence"])
            return dict(eff["verdict"]), {
                "agreement": False, "needs_human_review": False,
                "note": f"panel resolved by majority ({top_n}/{len(valid)} "
                        f"chose '{top_label}')"}
    # No majority OR quorum=fail-safe: most severe label wins with
    # human review flagged.
    worst = max(labels, key=lambda v: SEVERITY[v])
    side = [p for p in valid if p["verdict"]["verdict"] == worst]
    eff = max(side, key=lambda p: p["verdict"]["confidence"])
    return dict(eff["verdict"]), {
        "agreement": False, "needs_human_review": True,
        "note": "judges disagree after debate; using the more severe "
                "verdict"}


def judge_candidates_panel(candidates, clients, cache_db=None,
                           prompt_version=None, verbose=True, debate=None,
                           batch_size=None):
    """Panel variant of judge_candidates: every candidate is judged by all
    `clients` independently; disputes go through one debate round (when
    `debate`); a deterministic resolver picks the effective verdict.

    Same return shape as judge_candidates, plus per-result `panel` blocks
    and a per-model `panel_report` in stats (the participation audit: what
    each judge received, answered, revised and got wrong-or-right).

    batch_size (Q3): when > 1, the initial-verdict round prefetches
    verdicts in batched calls of that many candidates per call (default
    from LLM_JUDGE_BATCH_SIZE). Any batch miss falls back to the
    per-candidate path - see _batched_verdicts_from_client."""
    prompt_version = prompt_version or judge_config.PROMPT_VERSION
    if debate is None:
        debate = judge_config.LLM_JUDGE_DEBATE
    if batch_size is None:
        batch_size = judge_config.LLM_JUDGE_BATCH_SIZE
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
        # Q3: batched prefetch of initial verdicts. One worker per judge,
        # each walking its slices sequentially - wall-clock is the
        # slowest judge's ceil(N/batch) calls instead of N. The main
        # loop below consumes prefetched entries lookup-first; anything
        # missing (cache hit, batch failure, dropped element) flows
        # through _verdict_from_client exactly as before.
        prefetched = {}
        if batch_size > 1 and len(candidates) > 1:
            def _prefetch_for(cl):
                got = {}
                for j in range(0, len(candidates), batch_size):
                    out, permanent = _batched_verdicts_from_client(
                        candidates[j:j + batch_size], cl, cache,
                        prompt_version)
                    for cid, tup in out.items():
                        got[(cl.model_id, cid)] = tup
                    if permanent:
                        # Quota exhausted / schema rejected - every
                        # remaining batch would fail identically. Stop
                        # burning calls; the per-candidate path (which
                        # short-circuits permanent errors itself) takes
                        # over for the rest.
                        break
                return got
            for got in _pool.map(_prefetch_for, clients):
                prefetched.update(got)
            if verbose and prefetched:
                print(f"[panel] batch prefetch: {len(prefetched)} "
                      f"verdicts ({batch_size}/call) across "
                      f"{len(clients)} judges", flush=True)

        for i, cand in enumerate(candidates, 1):
            positions = []

            def _get_verdict(cl, _cand=cand):
                hit = prefetched.get((cl.model_id,
                                      _cand.get("candidate_id")))
                if hit is not None:
                    return hit
                return _verdict_from_client(_cand, cl, cache,
                                            prompt_version)

            client_results = list(_pool.map(_get_verdict, clients))
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


# --------------------------------------------------------------------------
# Session-pair comparison (dual-session S1 vs S2 report).
#
# The dashboard already produces a per-session verdicts.json on the VM. When
# BOTH sessions exist and were analysed, the "Compare S1 & S2" button asks
# for a SECOND-ORDER read: what changed between the two captures.
#
# This does NOT re-judge individual candidates - those verdicts are cached
# per (candidate, prompt_version, model) and re-running them would double
# the free-tier spend for the same answers. Instead we compute a compact
# pair-summary (per-session counts, IPs new/gone, verdict flips for IPs
# that appear in both, per-device delta) and send it as ONE prompt to the
# panel with a smaller pair-verdict schema.
# --------------------------------------------------------------------------
PAIR_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "posture_delta": {"type": "string",
                          "enum": ["escalated", "stable", "de-escalated",
                                   "mixed"]},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "headline": {"type": "string",
                     "description": "One sentence, at most 240 chars."},
        "reasoning": {"type": "string",
                      "description": "One paragraph, no newlines, "
                                     "at most 500 characters. Cite pair "
                                     "features by dotted path."},
        "notable_flips": {
            "type": "array",
            "description": "IPs whose verdict changed between S1 and S2. "
                           "Each item: {ip, from, to, why}",
            "items": {"type": "object",
                      "properties": {"ip": {"type": "string"},
                                     "from": {"type": "string"},
                                     "to": {"type": "string"},
                                     "why": {"type": "string"}},
                      "required": ["ip", "from", "to"]},
        },
        "recommended_action": {"type": "string",
                               "enum": ["no_change", "monitor",
                                        "investigate", "escalate"]},
    },
    "required": ["posture_delta", "confidence", "headline", "reasoning",
                 "recommended_action"],
    "additionalProperties": False,
}


PAIR_SYSTEM_PROMPT = """You are a network-security triage analyst comparing two
captures from the same environment (S1 = earlier, S2 = later). You receive
a JSON blob summarising what changed. Reply with ONE JSON object matching
the schema. No prose outside the JSON, no markdown fences.

Rules:
1. posture_delta in {escalated, stable, de-escalated, mixed}:
   - "escalated" - new malicious verdicts OR benign->malicious flips.
   - "de-escalated" - previously malicious IPs disappeared or dropped to
     benign in S2.
   - "stable" - roughly the same picture in both.
   - "mixed" - some IPs escalated AND some de-escalated.
2. confidence in [0.0, 1.0]. headline is ONE sentence, at most 240 chars.
   reasoning is ONE paragraph, no newlines, at most 500 characters.
3. Ground every claim in the pair blob - cite fields by dotted path
   (e.g. "verdict_flips[0].ip", "counts.s2.malicious").
4. notable_flips: pull the 1-5 most important verdict changes for
   individual IPs from the input's verdict_flips list. Leave [] when
   nothing flipped.
5. recommended_action:
   - "no_change" - stable, benign both sides.
   - "monitor" - stable but with unresolved suspicious signals.
   - "investigate" - concrete new malicious verdicts or troubling flips.
   - "escalate" - multiple new malicious verdicts OR a clean environment
     that turned actively hostile.

Schema:
{schema}
""".replace("{schema}", json.dumps(PAIR_VERDICT_SCHEMA, indent=2))


def _verdict_counts(results):
    counts = {"malicious": 0, "suspicious": 0, "benign": 0}
    for r in results or []:
        v = ((r.get("verdict") or {}).get("verdict"))
        if v in counts:
            counts[v] += 1
    return counts


def build_pair_blob(s1_out, s2_out, s1_label="S1", s2_label="S2"):
    """Turn two per-session verdict outputs into ONE compact pair blob
    the panel judges as a single unit. Everything the LLM sees comes
    from cached per-session data - no capture is re-parsed here."""
    s1_res = (s1_out or {}).get("results") or []
    s2_res = (s2_out or {}).get("results") or []
    s1_by_ip = {r.get("candidate_id"): r for r in s1_res
                if r.get("candidate_id")}
    s2_by_ip = {r.get("candidate_id"): r for r in s2_res
                if r.get("candidate_id")}
    ips_s1, ips_s2 = set(s1_by_ip), set(s2_by_ip)
    only_s1 = sorted(ips_s1 - ips_s2)[:20]
    only_s2 = sorted(ips_s2 - ips_s1)[:20]
    flips = []
    for ip in sorted(ips_s1 & ips_s2):
        v1 = ((s1_by_ip[ip].get("verdict") or {}).get("verdict"))
        v2 = ((s2_by_ip[ip].get("verdict") or {}).get("verdict"))
        if v1 and v2 and v1 != v2:
            flips.append({"ip": ip, "from": v1, "to": v2,
                          "from_confidence":
                              (s1_by_ip[ip].get("verdict") or {})
                                  .get("confidence"),
                          "to_confidence":
                              (s2_by_ip[ip].get("verdict") or {})
                                  .get("confidence"),
                          "s2_category":
                              (s2_by_ip[ip].get("verdict") or {})
                                  .get("category")})
    # Pull the top-3 non-benign verdicts from each side so the model has
    # concrete examples to cite even when nothing flipped.
    def _top_bad(by_ip):
        bad = [(ip, r) for ip, r in by_ip.items()
               if ((r.get("verdict") or {}).get("verdict"))
               in ("malicious", "suspicious")]
        bad.sort(key=lambda t: -float(
            (t[1].get("verdict") or {}).get("confidence") or 0))
        return [{"ip": ip,
                 "verdict": (r.get("verdict") or {}).get("verdict"),
                 "category": (r.get("verdict") or {}).get("category"),
                 "confidence": (r.get("verdict") or {}).get("confidence")}
                for ip, r in bad[:3]]
    return {
        "labels": {"s1": s1_label, "s2": s2_label},
        "counts": {"s1": _verdict_counts(s1_res),
                   "s2": _verdict_counts(s2_res)},
        "totals": {"s1": len(s1_res), "s2": len(s2_res)},
        "unique_ips_s1_only": only_s1,
        "unique_ips_s2_only": only_s2,
        "verdict_flips": flips[:20],
        "flip_count_total": len(flips),
        "top_non_benign_s1": _top_bad(s1_by_ip),
        "top_non_benign_s2": _top_bad(s2_by_ip),
    }


def validate_pair_verdict(obj):
    """Normalize the pair verdict or raise JudgeValidationError."""
    if not isinstance(obj, dict):
        raise JudgeValidationError(
            f"pair verdict is {type(obj).__name__}, not object")
    missing = [k for k in PAIR_VERDICT_SCHEMA["required"] if k not in obj]
    if missing:
        raise JudgeValidationError(f"missing fields: {missing}")
    if obj["posture_delta"] not in ("escalated", "stable",
                                    "de-escalated", "mixed"):
        raise JudgeValidationError(
            f"bad posture_delta {obj['posture_delta']!r}")
    if obj["recommended_action"] not in ("no_change", "monitor",
                                         "investigate", "escalate"):
        raise JudgeValidationError(
            f"bad recommended_action {obj['recommended_action']!r}")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) \
            or not (0.0 <= float(conf) <= 1.0):
        raise JudgeValidationError(f"confidence {conf!r} outside [0, 1]")
    # Fold newlines out of the free-text fields so a stray \n cannot
    # break the emailed markdown; cap lengths per schema.
    out = dict(obj)
    out["headline"] = " ".join(str(obj["headline"]).split())[:240]
    out["reasoning"] = " ".join(str(obj["reasoning"]).split())[:500]
    flips = obj.get("notable_flips") or []
    if not isinstance(flips, list):
        flips = []
    clean_flips = []
    for f in flips[:10]:
        if not isinstance(f, dict):
            continue
        if not {"ip", "from", "to"} <= set(f):
            continue
        clean_flips.append({
            "ip": str(f["ip"])[:60],
            "from": str(f["from"])[:30],
            "to": str(f["to"])[:30],
            "why": " ".join(str(f.get("why") or "").split())[:200],
        })
    out["notable_flips"] = clean_flips
    out["confidence"] = float(conf)
    return out


def judge_session_pair(s1_out, s2_out, clients, s1_label="S1",
                       s2_label="S2", prompt_version=None):
    """Ask the LLM panel ONE pair-level question and return the resolver's
    effective verdict. Every client gets the same pair blob; failures on
    individual judges do not abort the call - the resolver picks a
    majority posture_delta and reports which judges answered.

    Return shape:
        {"verdict": {...validated PAIR_VERDICT_SCHEMA...},
         "panel_report": {model_id: {"answered": bool, "error": str|None,
                                     "raw": dict|None, "latency_ms": int}},
         "pair_blob": {...},
         "prompt_version": "v0.5.0-pair"}

    Never raises; if every judge fails we return a verdict shaped like
    {"posture_delta": "mixed", "confidence": 0.0,
     "headline": "no judge succeeded"} so the caller can still mail a
    report that explains what happened.
    """
    prompt_version = prompt_version or (
        judge_config.PROMPT_VERSION + "-pair")
    blob = build_pair_blob(s1_out, s2_out, s1_label, s2_label)
    user_content = json.dumps(blob, indent=2)
    per_model = {}
    answers = []
    for client in clients:
        t0 = time.perf_counter()
        try:
            raw = client.judge(PAIR_SYSTEM_PROMPT, user_content,
                               schema=PAIR_VERDICT_SCHEMA)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            data = validate_pair_verdict(json.loads(raw))
            per_model[client.model_id] = {"answered": True, "error": None,
                                          "raw": data,
                                          "latency_ms": latency_ms}
            answers.append((client.model_id, data))
        except Exception as e:
            # trim the provider dump to one sentence for the report -
            # judge_cli._first_sentence lives in the CLI module, so an
            # inline strip is cleaner than a circular import
            msg = " ".join(str(e).split())
            for sep in (". ", " - "):
                if sep in msg:
                    msg = msg.split(sep, 1)[0]
                    break
            per_model[client.model_id] = {
                "answered": False,
                "error": msg[:180],
                "raw": None,
                "latency_ms": int((time.perf_counter() - t0) * 1000)}

    if not answers:
        verdict = {"posture_delta": "mixed", "confidence": 0.0,
                   "headline": ("Every panel judge failed on the compare "
                                "call - see panel_report for details."),
                   "reasoning": ("No judge produced a valid pair verdict; "
                                 "the mail summary falls back to raw "
                                 "counters from build_pair_blob."),
                   "notable_flips": [],
                   "recommended_action": "monitor"}
    else:
        verdict = _resolve_pair_verdict([a for _, a in answers])
    return {"verdict": verdict, "panel_report": per_model,
            "pair_blob": blob, "prompt_version": prompt_version,
            "models_answered": [m for m, _ in answers],
            "models_total": len(clients)}


_POSTURE_ORDER = {"stable": 0, "de-escalated": 1,
                  "mixed": 2, "escalated": 3}


def _resolve_pair_verdict(answers):
    """Majority-vote posture_delta; on a tie pick the more severe side.
    The headline / reasoning / notable_flips come from the highest-
    confidence answer inside the winning group so we keep concrete text."""
    from collections import Counter
    votes = Counter(a["posture_delta"] for a in answers)
    top = votes.most_common()
    top_count = top[0][1]
    winners = [p for p, n in top if n == top_count]
    picked = max(winners, key=lambda p: _POSTURE_ORDER.get(p, 0))
    group = [a for a in answers if a["posture_delta"] == picked]
    group.sort(key=lambda a: -float(a.get("confidence") or 0))
    best = dict(group[0])
    # Union of the notable_flips the winners listed - dedup on ip, keep
    # the first mention (highest confidence in that group).
    seen, merged = set(), []
    for a in group:
        for f in (a.get("notable_flips") or []):
            if f["ip"] in seen:
                continue
            seen.add(f["ip"])
            merged.append(f)
            if len(merged) >= 5:
                break
        if len(merged) >= 5:
            break
    best["notable_flips"] = merged
    best["panel_agreement"] = {"picked": picked,
                               "votes": dict(votes),
                               "answered": len(answers)}
    return best


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

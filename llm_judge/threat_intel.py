"""Threat-intel scoring - activates the judge's reserved W_TI weight.

Stage YA. Pure functions (no network, no state): given a Shodan record
for an external host a local device talked to, produce a threat score in
[0, 1] and human-readable reasons. The networked lookup itself lives in
server/enrich.py (Tier 1); this module only scores, so it stays offline
and unit-testable, and the judge tier keeps no external dependency.

priority_score() in judge_core reads candidate["ti_signals"]["score"];
absent that key it is 0.0, so a candidate with no threat-intel behaves
exactly as before this stage - which is why every existing judge test is
unaffected.
"""

# Shodan tags that indicate the host is itself hostile or anonymizing.
_MALICIOUS_TAGS = {"malware", "compromised", "botnet", "c2",
                   "honeypot", "tor", "proxy", "vpn", "scanner",
                   "self-signed"}


def ti_score(shodan_data):
    """Map a Shodan record to a threat score in [0, 1]. None / empty -> 0.0.

    Weighting (capped at 1.0):
        known CVEs on the host   -> up to 0.6 (0.2 each)
        malicious/anonymizing tag-> 0.4
        many exposed ports (>10) -> 0.15
    """
    if not shodan_data:
        return 0.0
    score = 0.0
    vulns = shodan_data.get("vulns") or []
    score += min(len(vulns) * 0.2, 0.6)
    tags = {str(t).lower() for t in (shodan_data.get("tags") or [])}
    if tags & _MALICIOUS_TAGS:
        score += 0.4
    if len(shodan_data.get("ports") or []) > 10:
        score += 0.15
    return round(min(score, 1.0), 4)


def classify(shodan_data):
    """Return {"score", "reasons": [...]} for transparency in the report."""
    if not shodan_data:
        return {"score": 0.0, "reasons": []}
    reasons = []
    vulns = shodan_data.get("vulns") or []
    if vulns:
        reasons.append(f"{len(vulns)} known CVE(s): "
                       + ", ".join(sorted(vulns)[:5]))
    tags = {str(t).lower() for t in (shodan_data.get("tags") or [])}
    hostile = sorted(tags & _MALICIOUS_TAGS)
    if hostile:
        reasons.append("tags: " + ", ".join(hostile))
    ports = shodan_data.get("ports") or []
    if len(ports) > 10:
        reasons.append(f"{len(ports)} exposed ports")
    return {"score": ti_score(shodan_data), "reasons": reasons,
            "org": shodan_data.get("org")}

"""OSINT enrichment - Wigle (BSSID) and Shodan (IP). Stdlib only.

Stage YA. Two passive lookups that add context to what the capture
already saw, both OPTIONAL and OFF without credentials:

- Wigle: a BSSID observed in the capture -> its public location
  (trilaterated lat/lon), SSID and country, from the community wardriving
  database. Enables the geo map (server/report_map.py).
- Shodan: an external IP a local device talked to -> open ports, tags,
  and known CVEs, feeding the judge's threat-intel weight
  (llm_judge/threat_intel.py, spec weight W_TI).

Every result is cached in the enrichment table so a key is queried once
per TTL. Nothing here raises into the caller and nothing runs without a
key: no key -> return None -> the map and the TI weight simply stay
empty, exactly as before this stage. This is inspired by WireTapper's
use of these same public services, but shares no code with it (that
project is CC BY-NC; this is an independent implementation).

Credentials (env):
    WIGLE_API_NAME + WIGLE_API_TOKEN   (or WIGLE_API_KEY as "name:token")
    SHODAN_API_KEY
"""
import base64
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import db

WIGLE_TTL_DAYS = int(os.environ.get("WIGLE_TTL_DAYS", "30"))
SHODAN_TTL_DAYS = int(os.environ.get("SHODAN_TTL_DAYS", "7"))


def _get_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ---- Wigle ---------------------------------------------------------------

def _wigle_auth():
    name = os.environ.get("WIGLE_API_NAME", "").strip()
    token = os.environ.get("WIGLE_API_TOKEN", "").strip()
    if not (name and token):
        combined = os.environ.get("WIGLE_API_KEY", "").strip()
        if ":" in combined:
            name, token = combined.split(":", 1)
    if not (name and token):
        return None
    return base64.b64encode(f"{name}:{token}".encode()).decode()


def wigle_bssid(conn, bssid, fetch_fn=None, ttl_days=WIGLE_TTL_DAYS):
    """Locate a BSSID via Wigle. Returns {ssid, lat, lon, country,
    lastupdt} or None (no key / not found / error). Cached."""
    bssid = (bssid or "").strip().lower()
    if not bssid:
        return None
    cached = db.get_enrichment(conn, "wigle_bssid", bssid, ttl_days)
    if cached is not None:
        return cached["data"]

    def default_fetch(b):
        auth = _wigle_auth()
        if not auth:
            return None
        url = ("https://api.wigle.net/api/v2/network/search?netid="
               + urllib.parse.quote(b))
        data = _get_json(url, headers={"Authorization": f"Basic {auth}"})
        results = data.get("results") or []
        if not results:
            return None
        r0 = results[0]
        return {"ssid": r0.get("ssid"),
                "lat": r0.get("trilat"), "lon": r0.get("trilong"),
                "country": r0.get("country"),
                "lastupdt": r0.get("lastupdt")}

    fetch = fetch_fn or default_fetch
    try:
        found = fetch(bssid)
    except Exception as e:
        print(f"[enrich] wigle {bssid}: {e}", flush=True)
        return None
    db.put_enrichment(conn, "wigle_bssid", bssid, found, ok=found is not None)
    return found


# ---- Shodan --------------------------------------------------------------

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def shodan_ip(conn, ip, fetch_fn=None, ttl_days=SHODAN_TTL_DAYS):
    """Look up an external IP via Shodan. Returns {ports, tags, vulns,
    org, os} or None. Only public IPs are queried. Cached."""
    ip = (ip or "").strip()
    if not is_public_ip(ip):
        return None
    cached = db.get_enrichment(conn, "shodan_ip", ip, ttl_days)
    if cached is not None:
        return cached["data"]

    def default_fetch(addr):
        key = os.environ.get("SHODAN_API_KEY", "").strip()
        if not key:
            return None
        url = (f"https://api.shodan.io/shodan/host/{urllib.parse.quote(addr)}"
               f"?key={urllib.parse.quote(key)}")
        try:
            data = _get_json(url)
        except urllib.error.HTTPError as e:
            if e.code == 404:       # Shodan has nothing on this host
                return None
            raise
        return {"ports": data.get("ports") or [],
                "tags": data.get("tags") or [],
                "vulns": list(data.get("vulns") or []),
                "org": data.get("org"), "os": data.get("os")}

    fetch = fetch_fn or default_fetch
    try:
        found = fetch(ip)
    except Exception as e:
        print(f"[enrich] shodan {ip}: {e}", flush=True)
        return None
    db.put_enrichment(conn, "shodan_ip", ip, found, ok=found is not None)
    return found

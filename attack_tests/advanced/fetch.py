#!/usr/bin/env python3
"""Fetch the real advanced-engine test captures that are too large or too
research-licensed to commit into the repo.

Every capture the advanced-engine test suite uses is declared in
`sources.json`. Small, redistributable ones live committed under
`pcaps/`. The rest carry `"action": "fetch"` and are downloaded here,
on demand, into the gitignored `_cache/` directory - each verified
against the SHA-256 recorded in the registry so a mirror swapping the
file out is caught.

Sources are reputable, named research datasets only (Wireshark
SampleCaptures, Stratosphere IPS / CTU-13, malware-traffic-analysis.net,
NETRESEC). A PCAP is data parsed by tshark, never executed; the
malware-traffic zips are password-protected ("infected") by the
publisher as a handling convention, not because the pcap runs.

Usage:
    python attack_tests/advanced/fetch.py            # fetch all missing
    python attack_tests/advanced/fetch.py beaconing_c2   # one family
    python attack_tests/advanced/fetch.py --list     # show registry
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "sources.json")
CACHE = os.path.join(HERE, "_cache")
PCAPS = os.path.join(HERE, "pcaps")
UA = {"User-Agent": "netsec-advanced-tests/1.0 (defensive security research)"}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _download(url, timeout=120):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def resolve_path(entry):
    """Where this capture lives once available: committed pcaps/ for
    action=commit, the fetch cache for action=fetch."""
    base = PCAPS if entry.get("action") == "commit" else CACHE
    return os.path.join(base, entry["file"])


def fetch_one(entry, force=False):
    """Return (ok, message). Downloads action=fetch entries, verifies
    sha256, extracts a zip member when the URL is a zip."""
    dest = resolve_path(entry)
    if entry.get("action") == "commit":
        return (os.path.isfile(dest),
                "committed" if os.path.isfile(dest) else "MISSING committed file")
    if os.path.isfile(dest) and not force:
        return True, "cached"
    os.makedirs(CACHE, exist_ok=True)
    try:
        raw = _download(entry["url"])
    except Exception as e:
        return False, f"download failed: {type(e).__name__}: {e}"

    # a gzip wrapper (weberblog serves the Ultimate PCAP as .pcapng.gz)
    if entry.get("url", "").endswith(".gz") and not entry.get("url", "").endswith((".zip.gz",)):
        try:
            raw = gzip.decompress(raw)
        except Exception as e:
            return False, f"gunzip failed: {type(e).__name__}: {e}"

    # a zip wrapper (malware-traffic zips, or a bundle) -> pull one member
    if entry.get("url", "").endswith(".zip") or entry.get("zip_member"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            pwd = entry.get("zip_password") or None
            member = entry.get("zip_member")
            if not member:
                cands = [n for n in zf.namelist()
                         if n.lower().endswith((".pcap", ".pcapng", ".cap"))]
                if not cands:
                    return False, f"no pcap inside zip: {zf.namelist()[:5]}"
                member = cands[0]
            raw = zf.read(member, pwd=pwd.encode() if pwd else None)
        except Exception as e:
            return False, f"zip extract failed: {type(e).__name__}: {e}"

    want = entry.get("sha256")
    got = _sha256(raw)
    if want and want != got:
        return False, f"sha256 mismatch: want {want[:12]}.. got {got[:12]}.."
    with open(dest, "wb") as f:
        f.write(raw)
    tag = "verified" if want else f"downloaded (sha256 {got[:12]}..)"
    return True, f"{tag} -> {os.path.relpath(dest, HERE)}"


def load_registry():
    if not os.path.isfile(REGISTRY):
        print(f"no registry at {REGISTRY}", file=sys.stderr)
        return []
    return json.load(open(REGISTRY, encoding="utf-8")).get("captures", [])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("family", nargs="?", help="fetch only this signal family")
    ap.add_argument("--list", action="store_true", help="show the registry")
    ap.add_argument("--force", action="store_true", help="re-download cached")
    args = ap.parse_args(argv)

    caps = load_registry()
    if args.list:
        for e in caps:
            print(f"{e['family']:20s} {e.get('action','?'):6s} "
                  f"{e['file']:36s} {e.get('source','')}")
        return
    caps = [e for e in caps if not args.family or e["family"] == args.family]
    if not caps:
        print("nothing to fetch (registry empty or family not found)")
        return
    ok = 0
    for e in caps:
        good, msg = fetch_one(e, force=args.force)
        ok += int(good)
        print(f"[{'OK ' if good else 'ERR'}] {e['family']:20s} {msg}")
    print(f"\n{ok}/{len(caps)} capture(s) available.")


if __name__ == "__main__":
    main()

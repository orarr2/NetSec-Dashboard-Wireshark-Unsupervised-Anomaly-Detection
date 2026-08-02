# Advanced-engine sims from real captures

The parent `attack_tests/` folder covers the DETECTORS in the pipeline
(IsolationForest, DBSCAN, and the scan / flood / amp / ARP rules). This
sub-folder covers the six **advanced-threat engines** in
`app/advanced_engines.py`: ARP/DHCP, DNS tunneling, DGA, beaconing, TLS.
Their thresholds were originally set by reasoning; this suite proves
they fire on real captures that exhibit the target behaviour, and stay
quiet on `benign_home.pcapng` (the false-positive guard).

Every capture is real, from a named reputable dataset, and verified with
tshark before its expected signals were written into `sources.json`.
Nothing here is synthetic.

## What is where

| Capture | Home | Signals it fires |
|---|---|---|
| `arp-storm.pcap` | committed (`pcaps/`, 47 KB, Wireshark wiki, public domain) | `arp_mac_many_ips` |
| `dns-tunnel-iodine.pcap` | committed (`pcaps/`, 77 KB, elastic/examples, Apache-2.0) | `dns_tunneling` |
| `The-Ultimate-PCAP.pcapng` | fetch (`_cache/`, 15 MB, Johannes Weber) | `rogue_dhcp`, `arp_mac_many_ips`, `arp_ip_multi_mac`, `nxdomain_storm` |
| `ctu-botnet-91-conficker.pcap` | fetch (`_cache/`, 26 MB, Stratosphere/CTU) | `nxdomain_storm`, `beaconing`, `rogue_dhcp` |
| `hancitor-cobaltstrike.pcap` | fetch (`_cache/`, 10 MB from a 9 MB zip, malware-traffic-analysis.net) | `sni_ip_mismatch`, `tls_no_sni_external` |

## Usage

```
# fetch the ones not committed (verifies sha256, extracts .gz / password-zip):
python attack_tests/advanced/fetch.py

# see what each capture actually produces (eyeball-friendly):
python attack_tests/advanced/verify_advanced.py

# assert it (skips fetch-only captures if you have not fetched them):
python -m pytest tests/test_advanced_engines_real.py
```

Pytest skips when tshark is not on PATH (the engines shell out to it) or
when a fetch-only capture is absent - so CI stays green without the
research downloads.

## Two documented engine gaps found during verification

Findings measured on the actual pcaps, not something to hide:

- **`dga_domain` did not fire on Conficker.** Conficker's DGA labels are
  8 characters and often carry vowels (`vowel_ratio >= 0.25` fails the
  engine's guard, which requires `< 0.25`). The `nxdomain_storm` engine
  DOES fire on the same capture (155 NXDOMAINs to one host is the same
  DGA symptom seen from the response side), so a Conficker infection
  still lights up - just via a different engine.
- **`beaconing` did not fire on the Hancitor / Cobalt Strike capture.**
  The Hancitor C2 in this sample is HTTP over port 80, not periodic
  TCP-SYN, and falls outside the beaconing engine's TCP-start filter.
  `sni_ip_mismatch` fires 5x on the same capture (domain-fronting-style
  SNIs pointing at AWS IPs), so the C2 is still detected.

Both are honest gaps in the engines, exposed by the test suite - not
failures to hide. They belong in a future engine-tuning pass, not here.

## Adding a new capture

1. Add an entry to `sources.json` with `family`, `action` (`commit` or
   `fetch`), `url`, `sha256`, and `expected_signals`.
2. `python attack_tests/advanced/fetch.py <family>` to download it.
3. `python attack_tests/advanced/verify_advanced.py` to see what fires,
   then set `expected_signals` to match reality.
4. `pytest tests/test_advanced_engines_real.py` locks it in.

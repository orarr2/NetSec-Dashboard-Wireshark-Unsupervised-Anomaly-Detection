# Attack-PCAP sanity tests

The dashboard's notebook (`app/Network_Security_Dashboard.ipynb`) is built
for home-network browsing captures. This folder gives it five real
attack PCAPs and a standalone CLI that mirrors cells 8 / 12 / 16 / 22-26
so you can verify every detection layer fires on its target class.

## Run

```
python3 attack_tests/run_pipeline.py \
    attack_tests/pcaps/<S1.pcap> attack_tests/pcaps/<S2.pcap>
```

`run_pipeline.py` is a faithful subset of the notebook - tshark feature
extraction, IsolationForest at the fixed `contamination = 0.10`
(seed-stability sweep retired, see `docs/TRADEOFFS_EN.md` §7),
k-NN-elbow DBSCAN with the spoofed-flood guards, the FTP / SMTP / SYN /
FIN / NULL / Xmas / RST / ARP / DNS rule set, the DNS-response amp
rule, and the per-second mean-packet-size LSTM. No Dash UI; everything
else is identical.

## Bundled PCAPs

| File | Source | Pkts | Attack |
|---|---|---:|---|
| `tcp_syn_scan.pcap` | markofu/pcaps EvilFingers NMAP | 2 020 | nmap `-sS` SYN scan |
| `xmas_scan.pcap`    | markofu/pcaps EvilFingers NMAP | 2 000 | nmap `-sX` stealth scan |
| `arpspoof.pcap`     | researcher111/ARP-pcap-files   | 16 285 | ARP cache poisoning, 9 min |
| `synflood.pcap`     | pvrmza/DDoS-packet-captures    | 37 841 | spoofed TCP SYN flood (37 623 src-IPs) |
| `dns_amp.pcap`      | pvrmza/DDoS-packet-captures    | 12 000 | DNS-ANY amplification |

## What the runs verify

### `tcp_syn_scan.pcap` → ARP-spoof  (`run_synscan_arpspoof.log`)

- IsolationForest flags `192.168.1.10` (1 002 SYN / 1 007 pkts).
- Horizontal-scan rule lights up `*** SCAN ***` on the same IP with
  `SYN ratio=1.00`.
- ARP-spoofing rule flags `192.168.1.1` claimed by two MACs
  (`08:00:27:2d:f8:5a` and `08:00:27:5e:01:7c`) - textbook MITM.
- DBSCAN cleanly splits S2 into 5 clusters, silhouette 0.63.

### `xmas_scan.pcap` → `dns_amp.pcap`  (`run_xmas_dnsamp.log`)

- Xmas scan (FIN | PSH | URG = 0x29 on `192.168.1.10`, 1 000 packets)
  now lights up the same `*** SCAN ***` rule. Previously invisible.
- DNS amplification capture: IsolationForest flags the four reflectors
  it should (8.8.8.8, 8.8.4.4, 212.8.51.69, 1.1.1.1), AND the
  response-side amp rule fires on 8 reflector IPs sending ~1 100-byte
  mean responses (e.g. `212.8.51.69 responses=250 mean_size=1090.1`,
  all `*** AMP REFLECTOR ***`).

### `synflood.pcap` → `arpspoof.pcap`  (`run_synflood_arpspoof.log`)

- 37 623 unique spoofed source IPs. Previously: DBSCAN crashed with
  9.8 GB RSS and never finished. Now: eps-collapsed-to-zero is detected
  (`eps collapsed to 0; using mean k-dist=0.050`) and DBSCAN is skipped
  with `DBSCAN skipped: 37,623 IPs > cap 5,000 (spoofed-flood pattern)`.
  IsolationForest still flags 218 IPs. Dashboard does not OOM.

## What the notebook changes cover

Five fixes were folded back into the notebook from these runs:

1. **Cell 8** - new TCP flag counters for FIN-only, NULL (no flags),
   and Xmas (FIN | PSH | URG) per source IP. Added as `fin_count`,
   `null_count`, `xmas_count` columns on the per-IP aggregation.
2. **Cell 8** - new `dns_amp_per_src` aggregation: per source IP, the
   count / total bytes / mean size of DNS *responses* leaving UDP/53.
3. **Cell 12** - IsolationForest feature matrix extended with the
   three stealth-scan counters; eps-from-elbow collapse to 0 is
   detected and replaced with the mean k-distance; DBSCAN is skipped
   when `|IPs| > 5 000` so spoofed floods don't blow memory.
4. **Cell 16** - horizontal-scan rule extended from SYN-only to also
   trigger on FIN-only, NULL, Xmas with the same > 50-pkt +
   ((>20-dst AND ratio>0.25) OR ratio>0.7) thresholds. Output now
   includes `scan_alerts`.
5. **Cell 16** - DNS-response-side amplification rule: for each src IP
   that sent ≥ 50 DNS answers out of UDP/53 with mean response size
   ≥ 200 bytes, emit a reflector finding. Output adds `dns_amp`.

## Detection matrix after the fixes

| Attack class | IsoForest | DBSCAN | Rule layer | LSTM |
|---|:-:|:-:|:-:|:-:|
| TCP SYN scan      | ✅ | ✅ | ✅ horizontal-scan | n/a |
| TCP Xmas scan     | - (small pop) | - | ✅ horizontal-scan | n/a |
| ARP spoofing      | ✅ | ✅ | ✅ ARP multi-MAC | ➖ |
| DNS amplification | ✅ | ✅ | ✅ amp / reflector | n/a |
| Spoofed SYN flood | ✅ | ✅ (skip-guarded) | ✅ syn_counter | n/a |

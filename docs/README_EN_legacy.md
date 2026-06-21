# Network Security Analysis Dashboard

**Wireshark PCAPNG + Live Capture + Three-tier Device Classification + Interactive Dashboard**

A network-intelligence framework that turns Wireshark captures into structured security insight without any labelled data. Three-tier device classification, unsupervised machine learning, RSSI-aware proximity analysis, and an Aurora-themed dashboard with a CRT-terminal splash.

The core question answered: *Which devices are on this network, what are they, how do they behave - and is any of that behaviour a security concern?*

---

## Quickstart

```bash
pip install dash dash-bootstrap-components scapy torch scikit-learn plotly pandas numpy
```

Install **Wireshark** (provides `tshark` and the OUI database):

| OS | Install |
|---|---|
| Windows | https://www.wireshark.org → installs `C:\Program Files\Wireshark\tshark.exe` |
| macOS | `brew install wireshark` |
| Linux | `sudo apt install tshark` |

Then:
1. Place all four files in the same folder:
   - `Network_Security_Dashboard.ipynb`
   - `cloud_ranges.json`
   - `dns_fingerprints.json`
   - `device_rules.json`
2. Set `MY_DEVICE_IP` in cell 6 to your local IP address (e.g. `192.168.1.50`).
3. `Kernel → Restart & Run All`.
4. Open `http://127.0.0.1:8050` when the CRT splash appears.
5. Choose either **Upload PCAP** (load one or two PCAPs from disk) or **Live Capture** (pick an interface, press Start, capture, press Save).

Python 3.9+. No GPU required. The notebook auto-detects `tshark` and falls back to `scapy` if not found.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INTAKE                                     │
│   tshark (preferred) - 25 fields including 8 WLAN fields            │
│   scapy fallback     - IP/TCP/UDP/DNS/ARP only                      │
│                       OR                                            │
│   Live capture       - background tshark subprocess + polling       │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                  CLASSIFICATION ENGINE                              │
│   • OUI database (Wireshark manuf or `tshark -G manuf`)             │
│   • Tier 1: rule-based (device_rules.json - 261 rules)              │
│   • Tier 2: DNS fingerprints (dns_fingerprints.json - 217 fps)      │
│   • Tier 3: behavioural port analysis (always returns a category)   │
│   + External IP classification (cloud_ranges.json: 247 CIDR/334 r)  │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                          ANALYSIS                                   │
│   • Feature engineering: 9 features per IP                          │
│   • IsolationForest: 20-point contamination sweep, data-driven      │
│   • DBSCAN: k-distance elbow for eps; Hopkins for clusterability    │
│   • LSTM: time-binned packet sizes, early stopping, 2σ threshold    │
│   • Security scans: FTP/SMTP creds, SYN flood, ARP spoof, DNS NX    │
│   • Browsing analysis by category + hour of day                     │
│   • Session comparison: new/gone/changed IPs                        │
│   • Auto-generated Intelligence Insights (8 findings)               │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                         DASHBOARD                                   │
│   Aurora theme + Bloomberg typography + CRT splash                  │
│   Sidebar: Overview · Sessions · Device Inventory ·                 │
│            Browsing · Security · Comparison · Insights              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Files

| File | Purpose |
|---|---|
| `Network_Security_Dashboard.ipynb` | The notebook itself |
| `cloud_ranges.json` | External IP / rDNS identification (27 static + 247 CIDR + 334 rDNS) |
| `dns_fingerprints.json` | DNS-based device identification (217 fingerprints) |
| `device_rules.json` | Rule-based device identification (261 rules, 12 categories) |
| `README.md` | This file |
| `CELL_BY_CELL.md` | Walkthrough of every notebook cell |
| `QA.md` | Likely exam questions with model answers |
| `TRADEOFFS.md` | Design decisions and rationale |

---

## Key Features

### Three-tier device classification
Every local IP is classified through three stages, the first match winning:

1. **Rule-based** - vendor + mDNS + ports + DNS regex match. Priority 800+ = high confidence, 500–799 = medium, 200–499 = low.
2. **DNS fingerprint** - substring/regex match of DNS queries against 217 device fingerprints; each fingerprint requires `match_threshold` signature domains.
3. **Behavioural fallback** - port-pattern recognition (554 → camera, 9100 → printer, 5060 → VoIP, 8008 → Chromecast, 62078 → iPhone, etc.). Always returns a specific category.

The engine **never returns Unknown** - even with zero signals, it returns `Generic Endpoint / Network endpoint`.

### Live capture
`tshark` runs as a background subprocess. The dashboard polls a thread-safe worker for live KPIs (packet count, bytes/sec, top talkers). Capture for any duration, press Save, and the same intake pipeline processes the saved PCAP.

### Proximity Map (dual mode)

**RSSI mode** (real 802.11 monitor capture): plots `log₁₀(distance)` vs RSSI variance, with marker size proportional to sample count and colour indicating proximity bucket. Distance from the **indoor log-distance path-loss model**:
```
d = 10^((Tx_power − RSSI − PL₀) / (10 · n))
```
with defaults Tx=20 dBm, n=2.5 (indoor office), PL₀=40 dB (2.4 GHz at 1 m). Realistic results: RSSI −20 → ~1 m, −50 → ~16 m, −70 → ~100 m.

**Behavioural mode** (no RSSI in PCAP): bin each IP's activity into 30-second windows, compute Pearson correlation between every pair of top-30 talkers, add a +0.25 similarity bonus for same /24 subnet, run MDS on the dissimilarity matrix, bucket by mean correlation.

### Three external JSON config files
All device-identification and provider-identification logic lives in editable JSON. New device types or cloud providers can be added without touching code.

---

## Dashboard Sections

The sidebar groups 28 figures across 7 sections:

- **Overview** - top talkers, protocol distribution, bytes timeline, DNS top domains
- **Sessions** - per-session packet summary, capture metadata, intelligence insights
- **Device Inventory** - classified device table, device map (PCA), proximity map (RSSI)
- **Browsing** - by category, by hour-of-day, S1/S2 comparisons
- **Security** - SYN flood / ARP spoof / DNS NX / DNS tunnelling, model agreement matrix, contamination sweep
- **Comparison** - new/gone/changed IPs, traffic delta, mDNS churn
- **Insights** - 8 auto-generated narrative findings

---

## Methodological Principles

1. **No labels in the data** - no `is_suspicious`, no `device_role` columns. The pipeline infers everything from packet behaviour.
2. **Behaviour over identity** - anomalies are detected from temporal, structural, and statistical signals.
3. **Three-tier graceful degradation** - high-confidence rule → DNS fingerprint → behavioural fallback. Never returns Unknown.
4. **Data-driven hyperparameters** - IsolationForest contamination from sensitivity sweep; DBSCAN `eps` from k-distance elbow; LSTM threshold from validation errors.
5. **Leakage prevention** - chronological train/val split for LSTM; no feature directly encodes the anomaly label.
6. **Local-peer comparison** - Z-scores computed against private-IP peers only, so CDN/cloud IPs don't pollute the baseline.
7. **Configurable identity** - all device and service identification lives in three external JSON files.

---

## Security Notes

- All processing is local - no data leaves the machine.
- Dashboard binds to `127.0.0.1:8050` only - not accessible externally.
- FTP/SMTP credential output is sensitive - treat accordingly.
- `.local` hostnames and OUI vendor strings may reveal device names and manufacturers.
- Live capture requires admin/root privileges on most systems.

---

## Acknowledgements

- **Scikit-learn** - IsolationForest, DBSCAN, NearestNeighbors, MDS, StandardScaler
- **PyTorch** - LSTM with early stopping
- **Plotly + Dash** - interactive web dashboard
- **Wireshark / tshark** - packet capture and OUI database
- **Ester, Kriegel, Sander, Xu (1996)** - k-distance elbow method for DBSCAN
- **Hopkins (1954)** - clusterability statistic

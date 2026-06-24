# NetSec - Wireshark + ML Forensic Dashboard

A Wireshark PCAPNG forensic dashboard built on Dash + scikit-learn + PyTorch.
Loads up to two capture sessions (S1 / S2), runs IsolationForest, DBSCAN, an
LSTM, and two deterministic rule layers in parallel, then renders dozens of
figures across 9 navigation sections (analysis, device profile, browsing
analysis, security, comparison, inventory, external traffic, coverage).

## What it does

- Reads `.pcapng` captures from disk OR records live traffic via `tshark`.
- Extracts per-IP features (packet count, byte volume, mean packet size,
  unique destinations, SYN / RST counts, burst score, dominance).
- Runs three ML models in parallel:
  - **IsolationForest** - single-IP outlier detection, contamination tuned
    by sensitivity sweep over [0.05, 0.10, 0.15].
  - **DBSCAN** - behavioural clustering, IPs not in any cluster are flagged.
  - **LSTM** - temporal anomaly detection on 1-second packet-size bins,
    flagged when prediction error exceeds val_mean + 2 σ.
- Runs two deterministic rule layers: TCP SYN scan / flood detection and
  ARP-spoofing / DNS-tunneling signals.
- Classifies every observed device into one of 12 categories using a
  3-tier engine (hostname / OUI / port rules → DNS fingerprints → behavioural
  heuristics).
- Renders a side-by-side S1-vs-S2 comparison the moment a second session is
  loaded.

## Files in this repo

| Path | Purpose |
|---|---|
| `Network_Security_Dashboard.ipynb` | Single-file dashboard - 48 cells, the only thing you need to run |
| `cloud_ranges.json` | CIDR ranges → cloud provider lookup |
| `device_rules.json` | 261 hostname / OUI / port rules for device classification |
| `dns_fingerprints.json` | 217 DNS fingerprints for behavioural device-type inference |
| `docs/` | English + Hebrew deep-dive documentation (cell-by-cell walkthrough, Q&A, design trade-offs) |
| `legacy/Network_Security_Dashboard_V5_baseline.ipynb` | The V5 baseline notebook the current version was built from - kept for diff / reference |

## How to run on a laptop

1. Install Wireshark (provides `tshark` and `mergecap`):
   - Windows: <https://www.wireshark.org/download.html>
2. Python deps: the notebook auto-pip-installs `dash`,
   `dash-bootstrap-components`, `plotly`, `manuf` on first run; you also need
   `pandas`, `numpy`, `scikit-learn`, `torch`, `scapy`.
3. Open `Network_Security_Dashboard.ipynb` in Jupyter.
4. **Kernel → Restart Kernel → Run All**.
5. Open the URL the last cell prints (auto-picks first free port from
   8050–8056).
6. Welcome → tick acknowledgement → Continue → drop a PCAPNG (or paste a
   full path) → Analyze → Dashboard.
7. From the dashboard, **+ Load second PCAP** in the sidebar adds the
   comparison S2 session.

## Folder layout

```
NetSec_Wireshark-ML-Dashboard/
├── Network_Security_Dashboard.ipynb   ← main notebook
├── cloud_ranges.json                  ← supporting data
├── device_rules.json
├── dns_fingerprints.json
└── README.md
```

## License

Private - research / educational use only.

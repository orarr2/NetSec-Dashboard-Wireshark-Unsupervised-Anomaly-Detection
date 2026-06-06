# NetSec Dashboard V5 — Working Copy

A Wireshark PCAPNG forensic dashboard built on Dash + scikit-learn + PyTorch.
Loads up to two capture sessions (S1 / S2), runs IsolationForest, DBSCAN, an
LSTM, and two deterministic rule layers in parallel, then renders 37 figures
across 9 navigation sections.

## Files in this repo

| Path | Purpose |
|---|---|
| `Network_Security_Dashboard_V5_claude.ipynb` | The single source of truth — 48 cells, ~6500 lines |
| `cloud_ranges.json` | CIDR ranges → cloud provider lookup |
| `device_rules.json` | 261 hostname / OUI / port rules for device classification |
| `dns_fingerprints.json` | 217 DNS fingerprints for behavioural device-type inference |

## Patches in this working copy (vs upstream V5)

| # | Patch | Cell |
|---|---|---|
| 1  | Move §1–§6 educational content from welcome to file-loading view | 47 |
| 2  | Welcome minimalism (logo + 5-paragraph notice + ack only) | 47 |
| 3  | Back-to-welcome nav from file-loading screen | 47 |
| 4  | Prominent "Upload successful" banner on staged card | 47 |
| 6  | S2-loaded toast notification | 47 |
| 7  | Persistent floating Restart pill (intro / choice / dashboard) | 47 |
| 8  | NETSEC logo → intro mode; "Resume dashboard" smart continue | 47 |
| 11 | Profile / Z-score / Proximity Map blank-chart fix | 45 |
| 12 | Clickable scroll-cue anchor + "Learn while you load" banner | 47 |
| 13 | NaN-safe profile/zbar fallback — fixes `post-processing failed: nan` | 45 |
| 14 | `_risk_line` flat-children fix — fixes React error #31 | 47 |

## How to run on a laptop

1. Install Wireshark (provides `tshark` and `mergecap`):
   - Windows: <https://www.wireshark.org/download.html>
2. Python deps: the notebook auto-pip-installs `dash`, `dash-bootstrap-components`, `plotly`, `manuf` on first run; you also need `pandas`, `numpy`, `scikit-learn`, `torch`, `scapy`.
3. Open `Network_Security_Dashboard_V5_claude.ipynb` in Jupyter.
4. **Kernel → Restart Kernel → Run All**.
5. Open the URL the last cell prints (auto-picks first free port from 8050–8056).
6. Welcome → ack → Continue → drop a PCAPNG → Analyze → Dashboard.

## How to continue work from a phone

1. **GitHub mobile app** (iOS / Android) → sign in → open this repo → tap any file to read or edit.
2. **Claude mobile app** → start a new chat → paste the file path or the snippet you want help with → ask Claude for an edit.
3. Copy Claude's reply back into the GitHub mobile app's file editor → commit on the spot, or open a PR.
4. Back at the laptop: `git pull` and **Kernel → Restart Kernel → Run All**.

## License

Private — research / educational use only.

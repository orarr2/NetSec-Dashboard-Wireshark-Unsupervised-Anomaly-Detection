# Cell-by-Cell Guide - Network Security Dashboard

The notebook contains 50 cells (25 code, 25 markdown). This document explains what each code cell does.

## Overall Architecture

The notebook is structured so that up to (but not including) cell 47, only **function definitions and library imports** run. No data analysis happens automatically on cell execution. Real analysis only starts when the user clicks "Load PCAP" or records live in the dashboard (cell 47).

```
Cells 0-3:   Markdown - title, intro, TCP/IP layer explanations
Cell 4:      Imports - auto-install libraries, locate tshark
Cell 5:      Markdown - explains PCAP paths
Cell 6:      Empty PCAP slots + PySide6 picker function
Cell 7:      Markdown - explains the analysis engine
Cell 8:      _analyze_pcap_tshark / _analyze_pcap_scapy - fast loaders
Cell 9:      Markdown
Cell 10:     Empty state init + load_session_from_pcap
Cell 11:     Markdown
Cell 12:     run_ml_on_session - IsolationForest + DBSCAN
Cell 13:     Markdown
Cell 14:     compute_z_scores
Cell 15:     Markdown
Cell 16:     run_security_scans
Cell 17:     Markdown
Cell 18:     compute_session_compare
Cell 19:     Markdown
Cell 20:     generate_insights_lines + process_session + compute_pair_state
Cell 21:     Markdown
Cell 22:     LSTMModel class
Cell 23:     Markdown
Cell 24:     run_lstm_on_session - training loop with early stopping
Cell 25:     Markdown
Cell 26:     evaluate_lstm
Cell 27:     Markdown
Cells 28-36: Markdown + empty cells (sections moved into other cells)
Cell 37:     Classification engine - OUI lookup + 3-tier classify_local_device
Cell 38:     Markdown
Cell 39:     Device inventory builder + coverage metrics
Cell 40:     Markdown
Cell 41:     LiveCaptureWorker - background tshark subprocess
Cell 42:     Markdown
Cell 43:     Browsing analysis (category + hour) + device map (PCA)
Cell 44:     Markdown
Cell 45:     make_figures + _build_proximity_map_figure - 34 Plotly figures
Cell 46:     Markdown
Cell 47:     Dash app - Aurora theme + CRT splash + 7 nav sections
```

---

## Cell 4 - Imports & Environment

**Purpose:** Ensure every required library is installed; locate `tshark` on disk.

Loops over a `PKGS` dict mapping pip names → import names. For each pair, tries `import`; if it fails, runs `pip install --quiet`. Then locates `tshark` by searching:

1. `shutil.which('tshark')`
2. Common install paths: `/usr/bin/tshark`, `/usr/local/bin/tshark`, `/Applications/Wireshark.app/Contents/MacOS/tshark`, `C:\Program Files\Wireshark\tshark.exe`, `C:\Program Files (x86)\Wireshark\tshark.exe`

The found path is stored in `TSHARK_PATH`; if nothing is found, `TSHARK_PATH = None` and the notebook falls back to `scapy`.

**Side effects:** `scapy.conf.verb = 0` (silences scapy), `warnings.filterwarnings('ignore')` (hides deprecation noise).

---

## Cell 6 - Empty PCAP slots + file picker

**Purpose:** Initialise placeholder variables and define the PySide6-based file picker that the dashboard's Upload button calls.

Variables: `PCAP1 = None`, `PCAP2 = None`, `CSV1 = None`, `CSV2 = None`, `MY_DEVICE_IP = "192.168.1.50"` (placeholder - user changes this).

`pick_pcap_files()` writes a small PySide6 script to a tempfile and runs it via `subprocess.run`. The script displays a native file picker and prints the chosen paths to stdout. The function reads stdout and returns a list of paths. This indirection avoids loading PySide6 into the notebook process itself (which can crash Jupyter on some setups).

---

## Cell 8 - Intake Engine

**Purpose:** The most important cell. Parses a PCAP into a structured dict that the rest of the pipeline consumes.

### `_find_tshark()`
Returns the path stored in cell 4, or `None`.

### `_analyze_pcap_tshark(path, label)`
Builds a tshark command with 25 fields:

```
frame.time_epoch, frame.len,
eth.src, eth.dst, ip.src, ip.dst,
_ws.col.Protocol,
tcp.srcport, tcp.dstport, tcp.flags,
udp.srcport, udp.dstport,
dns.qry.name, dns.flags.rcode, dns.flags.response,
arp.src.proto_ipv4, arp.src.hw_mac,
wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.da,
wlan.fc.retry, wlan.duration,
wlan_radio.signal_dbm, radiotap.dbm_antsignal
```

Output is captured as a pandas DataFrame via `pd.read_csv(StringIO(out), sep='\t')`. Then a single pass through the DataFrame builds:

| Structure | Content |
|---|---|
| `ips_src` | Counter of packet count per source IP |
| `bytes_src / bytes_dst` | Byte volume per IP |
| `protocols` | Counter of last-layer protocol name |
| `macs` | Counter of packet count per MAC |
| `dns_real` | DNS query name frequencies (Counter) |
| `dns_timeline` | List of `(ts, src_ip, query)` per DNS packet |
| `df_pkts` | DataFrame of `(ts, src, dst, size, proto)` per IP packet |
| `arp_ip_to_macs` | dict of IP → set of MACs seen |
| `syn_counter / rst_counter` | Per-source SYN/RST counters |
| `ports_per_ip / dns_per_ip / mdns_per_ip` | Per-IP signal collections for classifier |
| `wlan_features` | Per-MAC RSSI samples, probe req, assoc, retry counts |

`wlan_features` is the basis for RSSI-mode proximity analysis. If no `wlan.*` fields are populated (typical for Windows Wi-Fi captures presenting already-deframed Ethernet), this stays an empty dict and `wlan_available = False`.

### `_analyze_pcap_scapy(path, label)`
Fallback for when tshark is unavailable. Uses `scapy.rdpcap` and iterates packets. Slower but no dependency. Returns the same dict schema with `wlan_features = {}` and `wlan_available = False` (scapy can't reach the radio layer without a monitor-mode capable adapter).

### `load_session_from_pcap(path, label)`
Dispatcher: calls `_analyze_pcap_tshark` if `TSHARK_PATH` is set, else `_analyze_pcap_scapy`.

---

## Cell 10 - Empty session slots

Initialises `S1 = None`, `S2 = None`. The dashboard mutates these when the user loads a PCAP.

---

## Cell 12 - Unsupervised ML

`run_ml_on_session(S)` builds a 7-feature matrix from `ip_agg` (`mean_len`, `std_len`, `count`, `burst_score`, `unique_dsts`, `syn_count`, `rst_count`), runs `StandardScaler` on it, then:

**IsolationForest** with a 20-point contamination sweep from 0.02 to 0.30. For each value, fits the model and records the mean anomaly score of the flagged group. Selects the contamination whose flagged group has the **lowest mean score** (most extreme - points isolated fastest by the trees). Stores the chosen value in `ip_agg.attrs['chosen_contamination']`.

**DBSCAN** with `eps` from k-distance elbow: `NearestNeighbors(n_neighbors=2)`, sort the 2-NN distances descending, find the maximum second derivative - that's the elbow. Use `min_samples=2` because in 7-dim space with 50–150 points, density is naturally low.

**Hopkins statistic H** computed alongside. H ≈ 0.5 = data is random; H > 0.65 = real cluster structure exists.

Writes `iso_flag`, `iso_score`, `dbscan_label` columns into `ip_agg`.

---

## Cell 14 - Z-Scores Against Local Peers

`compute_z_scores(S, my_ip)` filters `ip_agg` to private IPs only (via `is_private`), computes mean and std per feature, then `(value − mean) / std` for the row matching `my_ip`. Returns a Series.

The local-peer filter is critical: without it, the baseline includes CDN/cloud IPs that talk to your device, which inflates `mean_len` and dwarfs your device's Z-score for any normal metric.

---

## Cell 16 - Rule-Based Security Scans

`run_security_scans(S)` runs 5 scans against `df_pkts` and the raw packet list:

1. **FTP/SMTP credentials** - searches packet payloads for `USER`, `PASS`, `MAIL FROM`, `RCPT TO` lines on the appropriate ports.
2. **TCP SYN flood/scan** - flags IPs with `syn_count > 100`.
3. **ARP spoofing** - flags IPs that appear with more than one MAC in `arp_ip_to_macs`.
4. **DNS NXDOMAIN spike** - flags sessions with >50 NXDOMAIN responses.
5. **DNS tunnelling** - flags queries longer than 60 characters or on non-standard DNS ports.

Returns a dict of scan name → list of flagged items.

---

## Cell 18 - Session Comparison

`compute_session_compare(S1, S2)` does set arithmetic: `new = ips2 − ips1`, `gone = ips1 − ips2`, `both = ips1 ∩ ips2`. Builds a comparison DataFrame with per-IP byte volumes for both sessions and status labels.

---

## Cell 20 - Intelligence Insights + Pipeline Glue

`generate_insights_lines(s1, s2, local_ip_agg_df, compare_df_arg, my_ip)` produces 8 auto-generated findings from runtime data:

1. Dominant local node (highest byte volume)
2. Largest external source (CDN/cloud destination)
3. DNS environment fingerprint (top 8 services via `classify_external_ip`)
4. ARP health (any IP with >1 MAC?)
5. DNS long-query count
6. IP churn (new/gone counts)
7. FTP/SMTP credential status
8. IoT VLAN recommendation (based on classified device categories)

`process_session(session, my_ip)` runs the full per-session pipeline: ML + Z-scores + security scans + classification + insights.

`compute_pair_state(s1, s2, my_ip)` runs the pair-level pipeline: comparison + cross-session insights.

---

## Cell 22 - LSTM Architecture

`class LSTMModel(nn.Module)` - a small LSTM with:
- Input dim 1 (packet size only)
- Hidden dim 32
- 1 layer
- Linear output to 1 (next packet size prediction)

---

## Cell 24 - LSTM Training

`SEQ_LEN = 10`, `BATCH = 64`, `EPOCHS = 30`, `PATIENCE = 2`.

`run_lstm_on_session(S, label)` builds time-binned sequences (1-second bins, mean packet size), splits 80/20 chronologically (no random shuffling - that would leak future into past), trains with MSE loss + Adam, monitors val loss every epoch, stops early if val loss doesn't improve for `PATIENCE` consecutive epochs. Restores best weights at end.

Anomaly threshold = `mean(val_err) + 2 * std(val_err)` - uses validation errors not training errors (so it reflects generalisation, not memorisation).

---

## Cell 26 - LSTM Evaluation

`evaluate_lstm(...)` runs the trained model over the full sequence, computes per-prediction error, returns the error array and threshold for the histogram plot.

---

## Cell 37 - Classification Engine

The most complex non-dashboard cell. Loads three JSON files via `_find_config(name)` (searches cwd, parent, `/mnt/data`, `~/`):

1. `device_rules.json` → `DEVICE_RULES` (261 rules, 12 hierarchy categories)
2. `cloud_ranges.json` → `CLOUD_RANGES` (27 static + 247 CIDR + 334 rDNS)
3. `dns_fingerprints.json` → `DNS_FINGERPRINTS` (217 fingerprints)

Builds `OUI_DB` from one of (in priority order):
1. Wireshark `manuf` file (Linux/macOS/Windows installations)
2. `tshark -G manuf` output
3. `manuf` Python package
4. 30-vendor embedded fallback

### `oui_lookup(mac)`
Strips colons/dashes, takes first 6 hex chars, returns vendor string from `OUI_DB`.

### `is_random_mac(mac)`
Checks the U/L bit of the first octet. Set = locally administered (random privacy MAC), unset = globally unique (real vendor).

### `_match_dns_fingerprint(dns_queries)`
Iterates the 217 fingerprints. For each, counts how many of its `signature_domains` appear as substrings (or regex matches) of any DNS query. If the count reaches `match_threshold`, records that fingerprint as a match. Returns the best-matching fingerprint and its score (or `None, 0`).

### `_behavioral_classify(port_set, dns_queries, vendor_from_oui, mac_random)`
Final fallback. Chains port-pattern checks:
- 554 → IP camera (RTSP)
- 9100/631/515 → printer
- 5060/5061/2000 → VoIP phone (SIP)
- 8008/8009/8443 + Google vendor → Chromecast
- 62078 → iPhone
- 1900 → UPnP device
- 1883/8883 → MQTT IoT hub
- Web-only with random MAC → "phone or laptop"
- Web-only with known vendor → "vendor computer"
- Known vendor with no clear ports → "generic vendor endpoint"
- Nothing → "Network endpoint (no signals available)"

Always returns a tuple `(classification_dict, confidence_str)`.

### `classify_local_device(mac, mdns_names, ports, dns_queries)`
The three-tier dispatcher. Returns a dict with `category`, `subcategory`, `vendor`, `model`, `rule_id`, `vendor_from_oui`, `mac`, `confidence`, `mac_privacy_random`.

### External-IP classification
`classify_external_ip(ip, do_rdns=True)`:
1. Lookup in `STATIC_IPS` dict (exact match)
2. Iterate `NETWORKS` (parsed `ip_network` objects from `cidr_ranges`) for membership
3. If `do_rdns`, do reverse DNS lookup with 0.6s timeout (cached per session) and regex-match against `_RDNS_REGEXES`
4. Otherwise return `{provider: 'Unknown', service: '', type: 'Unclassified', ...}`

---

## Cell 39 - Device Inventory & Coverage Metrics

`_is_private(ip)` - checks RFC 1918 ranges via `ipaddress.ip_address(ip).is_private`.

`build_device_inventory(session, my_ip)` - iterates `session['ip_agg']`, classifies every private IP via `classify_local_device(...)`, attaches the result to each row. Builds a DataFrame with columns: IP, MAC, vendor, category, subcategory, model, confidence, total_bytes, packet_count.

Coverage metrics computed: how many devices got Tier-1 vs Tier-2 vs Tier-3 classification; how many have known vendor; how many use random MAC.

---

## Cell 41 - Live Capture Worker

`LiveCaptureWorker` is a thread-safe accumulator:

```python
class LiveCaptureWorker:
    def __init__(self):
        self.MIN_SECONDS = 30
        self.lock = threading.Lock()
        self.data = {}
        self.stop_event = threading.Event()
        self.thread = None

    def start(self, interface):
        self.reset()
        self.stop_event.clear()
        cmd = [TSHARK_PATH, '-i', interface, '-l', '-T', 'fields', ...]
        self.thread = threading.Thread(target=self._capture_loop, args=(cmd,))
        self.thread.start()

    def _capture_loop(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, ...)
        while not self.stop_event.is_set():
            line = proc.stdout.readline()
            with self.lock:
                # update counters atomically
                ...

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def stop_and_save(self):
        self.stop_event.set()
        # write captured frames to a tempfile PCAP
        ...
```

`LIVE_SESSIONS = {'S1': LiveCaptureWorker(), 'S2': LiveCaptureWorker()}` - one worker per session slot.

`list_capture_interfaces()` runs `tshark -D` and parses the output into `[(name, description), ...]` for the dashboard dropdown.

---

## Cell 43 - Browsing Analysis + Device Map

`CATEGORY_RULES` is a list of regex patterns mapping DNS queries to categories (Streaming, Work, Google/Cloud, Cloud Infra, Social, Security/Update, News/Media, CDN/Infra).

`categorize_dns_query(q)` returns the first matching category, or "Other".

`build_browse_by_category(s)` - for each device with mDNS name, computes the percentage of its DNS queries per category. Returns a DataFrame for the stacked bar chart.

`build_browse_by_hour(s)` - for each device, bins its DNS timeline by hour-of-day. Returns a DataFrame for the heatmap.

`_build_device_map_figure(session, label)` - runs PCA on the classified device feature matrix (one-hot category + numeric features) and produces a 2D scatter coloured by category.

---

## Cell 45 - Build All Figures

```python
import plotly.io as _pio
_pio.templates.default = "none"
```

The first lines set Plotly's default template to "none". This bypasses Plotly's `apply_default_cascade` machinery entirely, which prevents a template-corruption crash that can occur after many rebuilds.

`make_figures(s1, s2, compare_df, z_scores, my_ip)` builds 26 base figures using `plotly.express` and `plotly.graph_objects`. Topics:

- talkers, burst, proto, dns, devices, timeline, lstm
- profile (radar), zbar (signed bar)
- browse_cat, browse_hour, browse_cat_s1, browse_hour_s1
- syn, confusion, sensitivity
- cmp_traffic, cmp_new_gone, cmp_delta

Then per-session calls to `_build_device_map_figure()` and `_build_proximity_map_figure()` add 4 more (`device_map`, `device_map_s2`, `proximity`, `proximity_s2`).

`_apply_aurora_layout(figs)` applies the Aurora theme to every figure: transparent backgrounds, Inter Tight + Newsreader font pair, muted axis colours, glass-panel hover labels.

`_estimate_distance_m(rssi, tx=20, n=2.5, pl_d0=40)` implements the indoor log-distance path-loss model.

`_build_proximity_map_figure(session, title_label)` chooses between RSSI mode (if `wlan_features` has any RSSI samples) and behavioural mode (else). The behavioural path runs MDS on `1 − Pearson_correlation` of 30-second activity bins.

`rebuild_figures()` is the orchestrator the dashboard calls when a new PCAP is loaded.

---

## Cell 47 - Dashboard (Aurora theme + CRT splash)

The largest cell in the notebook. Defines:

- Colour palette: `INK`, `INK_DIM`, `INK_MUTE`, `VIOLET`, `CYAN`, `MAGENTA`, etc.
- CSS in `AURORA_INDEX_STRING` (typography, animations, glass-panel utility classes)
- `_NETSEC_LETTERS` - pixel-grid coordinates for N, E, T, S, C
- `_build_netsec_crt_logo()` - returns Base64 SVG data URL for the pink pixel-art logo
- `_build_intro_splash()` - assembles the CRT terminal splash (green CLI prompt, pink NETSEC logo, fake directory tree, blinking cursor, scanline overlay)
- `build_intro_view()` - the educational/welcome view that contains the splash
- `build_choice_view()` - the upload/capture chooser
- `build_main_view()` - the analysis dashboard with sidebar + topbar + chart panel
- `_build_second_pcap_modal()` - the "Load Second PCAP" modal
- Topbar with 6 live KPIs + Load Second PCAP button
- Sidebar with `NAV_ITEMS` (28 entries across 7 sections)
- Dash callbacks: `splash_to_choice`, `choice_to_main`, `click_nav`, `render_chart`, `brand_to_home`, `restart_app`, `open_second_pcap_modal`, plus the live-capture callback chain

The dashboard uses `dcc.Store` for client-side state because Dash callbacks cannot share Python global variables across browser sessions.

The app is launched via `app.run(host='127.0.0.1', port=8050, jupyter_mode='external')`.

---

## Cells 48-49 - Empty

Reserved for future extensions.

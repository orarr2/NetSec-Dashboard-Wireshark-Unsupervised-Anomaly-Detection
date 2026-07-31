# Cell-by-Cell Guide - Network Security Dashboard

The notebook contains 50 cells (25 code, 25 markdown). This document
walks through every code cell in the order it appears in
`app/Network_Security_Dashboard.ipynb`. The narrative matches the code
that ships today; when values matter (feature counts, thresholds,
hyperparameters) they are the ones the code actually uses.

## Overall Architecture

Import order: the notebook first defines everything (constants, helpers,
detectors, figure builders, callbacks) and only launches the Dash app in
the last real code cell (48). Cells 28/29/31/33/35 are `pass` stubs left
in place so cell numbering stays stable with the older markdown
headings; cell 49 is a client-side integration block that imports the
VM-side helpers when they are present.

```
Cell  0..3   Markdown  title, intro, TCP/IP layer explanations
Cell  4      Imports    pip auto-install, banner, tshark discovery
Cell  5      Markdown   file paths guidance
Cell  6      Code       upload constants, MY_DEVICE_IP, upload decode + path validation
Cell  7      Markdown   PCAP analysis engine intro
Cell  8      Code       analyze_pcap  (tshark fast loader + scapy fallback)
Cell  9      Markdown   session state intro
Cell 10      Code       S1 / S2 / SESSION_PCAPS + load_session_from_pcap
Cell 11      Markdown   data quality intro
Cell 12      Code       run_ml_on_session  (IsolationForest + DBSCAN)
Cell 13      Markdown   feature engineering intro
Cell 14      Code       compute_z_scores  (device vs local peers)
Cell 15      Markdown   ML model selection
Cell 16      Code       run_security_scans  (deterministic rule engine)
Cell 17      Markdown   ML training / hyperparameters
Cell 18      Code       compute_session_compare  (S1 vs S2 set diff)
Cell 19      Markdown   ML evaluation
Cell 20      Code       generate_insights_lines + process_session + compute_pair_state
Cell 21      Markdown   LSTM architecture intro
Cell 22      Code       LSTMModel  class
Cell 23      Markdown   LSTM training intro
Cell 24      Code       train_lstm_for_session  (SEQ_LEN=10, MAX_EPOCHS=15)
Cell 25      Markdown   LSTM evaluation intro
Cell 26      Code       evaluate_lstm
Cell 27      Markdown   device profiling intro
Cells 28-35  Mostly `pass`  (old sections moved into other cells;
                             markdown headers survive for chapter numbering)
Cell 36      Markdown   classification engine intro
Cell 37      Code       classification engine (JSON configs, OUI DB, 3-tier classifier)
Cell 38      Markdown   inventory intro
Cell 39      Code       inventory + threat score + coverage
Cell 40      Markdown   live-capture intro
Cell 41      Code       LiveCaptureWorker (tshark ring reader + snapshot + merge)
Cell 42      Markdown   browsing analysis intro
Cell 43      Code       browsing category / hour, confusion matrix, sensitivity sweep chart
Cell 44      Markdown   visualisation intro
Cell 45      Code       make_figures + _build_device_map_figure + _build_proximity_map_figure
Cell 46      Markdown   dashboard launch intro
Cell 47      Code       Advanced Threat Detection engines (beaconing, DNS tunneling, DGA, ARP/DHCP, TLS, fusion)
Cell 48      Code       Dash app - Aurora theme, layout, 38 server + 12 clientside callbacks, app.run()
Cell 49      Code       VM client integration shim (server.dashboard_client import)
```

The single-source-of-truth pair is `app/Network_Security_Dashboard.ipynb`
(authoritative) and `app/dashboard_module.py` (byte-exact export). The
exporter is `tools/export_dashboard_module.py` and CI runs it with
`--check` on every push so the two cannot silently drift.

---

## Cell 4 - Imports & Environment

**Purpose:** ensure every required library is installed; locate `tshark`
and the Wireshark `manuf` file on disk.

Iterates a `PKGS` list mapping pip names to import names. For each, tries
`import`; if it fails, runs `pip install --quiet`. Imports the runtime
stack: numpy, pandas, torch, scikit-learn, plotly, dash,
dash_bootstrap_components, scapy, `manuf` (best-effort).

Prints a version banner naming every pinned package. Then locates
`tshark`:

1. `shutil.which("tshark")`
2. Common install paths: `/usr/bin/tshark`, `/usr/local/bin/tshark`,
   `/Applications/Wireshark.app/Contents/MacOS/tshark`,
   `C:\Program Files\Wireshark\tshark.exe`,
   `C:\Program Files (x86)\Wireshark\tshark.exe`

The result is cached as `_TSHARK_PATH_FOR_LOADER`. The Wireshark `manuf`
file is discovered in the same manner into `MANUF_PATH`. A missing
tshark is not fatal - the scapy fallback in cell 8 takes over.

**Side effects:** `scapy.conf.verb = 0`, `warnings.filterwarnings("ignore")`.

---

## Cell 6 - Upload constants + validators

**Purpose:** the constants and helpers the dashboard's file input calls.

Constants: `PCAP1 = None`, `PCAP2 = None`, `CSV1 = None`, `CSV2 = None`,
`MY_DEVICE_IP = os.environ.get("NETSEC_MY_DEVICE_IP", "")` (empty by
default; blank means the profile view auto-picks the busiest local
device). `MAX_UPLOAD_BYTES = 100 * 1024 * 1024` and
`MAX_UPLOAD_HUMAN = "100 MB"` cap the drag-and-drop path; the
paste-path input has no size cap.

Functions:

- `decode_uploaded_pcap(contents, filename)` splits the data URL,
  base64-decodes, enforces `MAX_UPLOAD_BYTES`, sanitises the filename to
  `[alnum._-]`, forces the suffix to `.pcap` / `.pcapng`, and writes to
  a `tempfile.mkstemp(prefix="netsec_upload_")` path. Returns
  `(path, error)`.
- `validate_pcap_path(text)` strips quotes, checks `exists` /
  `isfile`, enforces the `{.pcap, .pcapng, .cap}` extension whitelist,
  and rejects zero-byte files.

Neither validator magic-byte-checks the file - a mis-named non-PCAP
reaches tshark and fails deeper with a "tshark returned 0 rows"
`RuntimeError`.

---

## Cell 8 - PCAP intake engine

**Purpose:** parse a PCAP into the structured session dict every
downstream stage consumes.

### Helpers
- `_safe_epoch(dt)` / `_safe_fromtimestamp(ts)` avoid Windows'
  negative-epoch crash on captures whose timestamps predate 1970.
- `_find_tshark()` returns the cached loader path.
- `_extract_wifi_ssid_bssid(path)` runs `tshark -Y wlan.fc.type==0 ...`
  to pull Beacon / Probe-Response SSID+BSSID pairs; used by the Wigle
  map on the VM side. Skipped when the capture has no WLAN frames.

### `_analyze_pcap_tshark(path, label)`
Builds a tshark command with **25 fields**, `sep="|"`, no header row:

```
frame.time_epoch, frame.len,
eth.src, eth.dst, ip.src, ip.dst, ipv6.src, ipv6.dst,
_ws.col.Protocol,
tcp.srcport, tcp.dstport, tcp.flags,
udp.srcport, udp.dstport,
dns.qry.name, dns.flags.rcode, dns.flags.response,
arp.src.proto_ipv4, arp.src.hw_mac,
wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.da,
wlan.fc.retry, wlan.duration
```

The full tshark output is captured into memory
(`subprocess.check_output(...)`), parsed via
`pd.read_csv(io.StringIO(out), sep="|")`, then a single pass builds:

| Structure | Content |
|---|---|
| `ips_src` / `ips_dst` | packet counts per source / destination IP (v4 or v6, coalesced) |
| `bytes_src` / `bytes_dst` | byte volumes per IP |
| `protocols` | protocol counter (last-layer name) |
| `macs` | packet count per MAC |
| `dns_real`, `dns_timeline`, `dns_per_ip`, `mdns_per_ip`, `dns_nxdomain`, `dns_nonstandard`, `dns_long_queries`, `nxdomain_per_dst` | DNS aggregates |
| `dns_amp_per_src` | reflector candidates for the amp rule |
| `arp_ip_to_macs` | dict of `ip -> set(macs)` for ARP-spoof detection |
| `syn_counter`, `rst_counter`, `fin_counter`, `null_counter`, `xmas_counter` | per-source TCP flag counters (masked with `0x3F` so ECE/CWR are ignored) |
| `ports_per_ip` | per-IP union of tcp/udp src+dst ports (for classification) |
| `ip_agg` | per-IP feature frame (see cell 12) |
| `timeline_df`, `pkt_sizes` | for the timeline and burst figures |
| `wlan_features` | per-MAC RSSI samples, probe request count, association count, retry count |
| `wifi_bssid` | seen BSSIDs (used by the Wigle geo map on the VM) |
| `t0`, `t1` | earliest / latest packet timestamp |

`wlan_features` populates only when the capture actually contains
`wlan.*` fields (802.11 monitor mode). Windows Wi-Fi captures usually
present deframed Ethernet, so this stays empty and `wlan_available`
falls to `False`.

### `_analyze_pcap_scapy(path, label)`
Fallback for when tshark is unavailable. Uses `scapy.rdpcap` and
iterates packets, producing the same dict schema with
`wlan_features = {}` and `wlan_available = False` (scapy without
monitor-mode does not see the radio layer).

### `analyze_pcap(path, label)` (dispatcher)
Calls `_analyze_pcap_tshark` first; on any exception falls back to
`_analyze_pcap_scapy` (with a warning printed to stdout).

---

## Cell 10 - Session slots

Initialises the module-level session state the dashboard mutates as the
user loads captures:

```
S1 = None
S2 = None
ip_agg = None                              # last session's per-IP frame
z_scores = None                            # last session's Z-scores
local_ip_agg = None
extern_ip_agg = None
compare_df = None                          # S1 vs S2 delta frame
new_n = 0
gone_n = 0
SESSION_PCAPS = {"S1": None, "S2": None}   # source PCAP path per slot
INSIGHTS_LINES = []
```

`load_session_from_pcap(path, label)` is a thin wrapper around
`analyze_pcap` that also records the source path in `SESSION_PCAPS`.
Security findings are stashed on `S["_security_findings"]` at analysis
time, not on a module-level dict, so every consumer reads them off the
same session dict the ML columns live on.

---

## Cell 12 - Unsupervised ML

`run_ml_on_session(S)` builds the **10-feature** matrix from
`S["ip_agg"]`, `StandardScaler`-normalises it, and runs:

**IsolationForest** at the fixed `contamination = 0.10`,
`n_estimators = 200`, `random_state = 42`. A prior 20-point sweep
was retired after measuring no improvement over fixed 0.10
(mean F1 0.247 vs 0.250 across 5 seeds against the labelled
`attack_tests` ground truth, at 15× the fitting cost). See
`docs/TRADEOFFS_EN.md` §7 for the full argument. Writes
`iso_score` (decision_function), `iso_flag`, `anomaly` (`==-1`) and
`iso_stability` columns onto `ip_agg`.

**DBSCAN** with `eps` from a k-distance elbow (`k=2`
`NearestNeighbors`, sort distances descending, take the argmin of the
diff-of-diff as the elbow), plus two guards:

- **eps collapse**: when the elbow reads `eps <= 0` (spoofed-source
  floods where every point sits on the same feature vector),
  `eps = max(mean(k_dist), 0.05)`.
- **volume cap**: when `len(ip_agg) > 5000`
  (`DBSCAN_MAX_IPS = 5000`), DBSCAN is skipped entirely - every row is
  labelled `cluster = -1` - to avoid an O(n²) neighbourhood blow-up on
  captures with tens of thousands of source IPs.

`min_samples = 2`. Silhouette is computed on the non-noise points only
when there are ≥ 2 clusters, else stored as `None`. `dbscan_meaningful`
records whether at least one real cluster was found.

Values stashed on `ip_agg.attrs` for the Model Diagnostics view:
`_chosen_contamination`, `_eps_auto`, `_min_samples`, `_silhouette`,
`_n_clusters`, `_n_noise`.

The 10 feature columns are:

```
mean_len, std_len, count, burst_score, unique_dsts,
syn_count, rst_count, fin_count, null_count, xmas_count
```

---

## Cell 14 - Z-scores against local peers

`compute_z_scores(S, my_ip)` filters `ip_agg` to private IPs only via
the module-level `_is_private` (cell 39), computes `mean` and `std`
per feature over the peer set, then returns
`(value - mean) / std` for the row matching `my_ip` as a `pd.Series`.

The local-peer filter is critical: without it, the baseline would
include CDN/cloud endpoints whose feature values would inflate the mean
and dwarf your device's Z-score for any normal metric.

---

## Cell 16 - Deterministic rule engine

`run_security_scans(S)` is the detection **workhorse**. On the labelled
attack captures the rules catch 100% of the labelled attackers; the ML
layer's job is to find what the rules missed. Runs the following
scans and returns a dict with the exact keys shown:

- `scan_alerts` - per-flag horizontal scan detection (SYN / FIN / NULL /
  Xmas). A source qualifies when `count > 50` AND
  (`unique_dsts > 20` OR the flag-to-packets ratio exceeds 0.7).
- `dns_amp` - reflectors (built from `dns_amp_per_src`): DNS response
  senders with `count >= 50` AND `mean_size >= 200` bytes.
- `flood` - aggregate SYN flood: `total_syn >= 1000` AND
  `n_syn_srcs >= 100` AND `syn_rate >= 100/s`. Also reports the
  `spoofed_source_pattern` boolean (`total_syn / n_srcs <= 3`).
- `arp_spoofing` - IPs that map to more than one MAC in
  `arp_ip_to_macs`.
- `ftp` / `smtp` - plaintext credential heuristics scanning the packet
  list for `USER|PASS|RETR|STOR` (ports 21 / 25 / 587). These require
  packets to be available in `S["pkts"]`, which is populated only on
  the scapy path today - the tshark fast loader keeps `pkts=[]`.
- `syn_top`, `rst_top`, `fin_top`, `null_top`, `xmas_top` - top per-flag
  senders (for the security tables).
- `dns_long` - DNS queries longer than 60 characters.

The distinct key names matter: the LLM-judge candidate assembly
(`llm_judge/judge_core.assemble_candidates`) reads only
`scan_alerts`, `amp_alerts`, `flood_alerts`, `arp_spoofing_ips` from
the dict `attack_tests/run_pipeline.py` produces, which is a separate
implementation of these same rules kept structurally identical.

---

## Cell 18 - Session comparison

`compute_session_compare(S1, S2)` runs set arithmetic over the IPs
present in each session:

```
new  = ips2 - ips1
gone = ips1 - ips2
both = ips1 & ips2
```

Returns a DataFrame with columns `ip`, `bytes_s1`, `bytes_s2`,
`change`, `status ∈ {both, new, gone}`. The comparison views
(`cmp_traffic`, `cmp_new_gone`, `cmp_delta`) all read from this frame,
so they render an empty state until a second session is loaded.

---

## Cell 20 - Insights + pipeline glue

`generate_insights_lines(s1, s2, local_ip_agg_df, compare_df_arg, my_ip)`
produces the 8 auto-generated one-liners the Insights panel shows:

1. dominant local talker (highest byte volume)
2. largest external destination
3. DNS environment fingerprint (top 8 services via
   `classify_external_ip`)
4. ARP health (any IP with >1 MAC?)
5. long-DNS-query count
6. IP churn (new / gone counts)
7. FTP / SMTP credential exposure
8. IoT VLAN recommendation (based on classified device categories)

`process_session(session, my_ip)` is the per-session driver: ML +
Z-scores + rules + classification + insights.

`compute_pair_state(s1, s2, my_ip)` is the pair-level driver:
comparison + cross-session insights.

---

## Cell 22 - LSTM architecture

```python
class LSTMModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=64, batch_first=True)
        self.head = nn.Linear(64, 1)
```

A small next-value regressor on the last hidden state.

---

## Cell 24 - LSTM training

Constants: `SEQ_LEN = 10`, `MAX_BINS = 20000`. Runtime hyperparameters
inside `train_lstm_for_session`: `MAX_EPOCHS = 15`, `PATIENCE = 2`,
`batch_size = 512`, `Adam(lr=1e-3)`, MSE loss.

Signal: **mean packet size per 1-second bin**, zero-filled for idle
seconds (wall-clock seconds - not seconds-with-traffic - so long gaps
show up as bursts on either side). If more than `MAX_BINS` bins are
present, the series is stride-decimated to `MAX_BINS`.

Training gate: needs at least 20 usable bins (`SEQ_LEN=10` + a
10-sequence floor). Shorter captures skip LSTM silently - the
deterministic rules cover them.

Split: chronological 80/20 (random shuffling would leak future into
past). Best-val checkpoint saved to
`tempfile.gettempdir()/lstm_best_<label>.pt` and reloaded at end.

---

## Cell 26 - LSTM evaluation

`evaluate_lstm(...)` runs the trained model over the full sequence and
computes per-sequence prediction error. The anomaly **threshold** is
`val_errors.mean() + 2 * val_errors.std()` - measured on the held-out
validation slice, not on the training set, so the threshold reflects
generalisation. Stores `lstm_errors` (all sequences) and
`lstm_threshold` on the session dict.

---

## Cells 28, 29, 31, 33, 35 - Stubs

Each contains a single `pass`. They exist because the section numbering
in the markdown was historically tied to code-cell indices, and the
content of these sections was later merged into cells 12 / 16 / 18 / 20.
Removing them would renumber every cell and every reference to a cell
index across the codebase. They compile to nothing.

---

## Cell 37 - Classification engine

Loads three JSON data files via `_find_config(name)`, which searches
`NETSEC_APP_DIR`, the notebook's directory, its parent, and `~/`:

1. `device_rules.json` → `DEVICE_RULES` (261 rules sorted by descending
   `priority`; 12 hierarchy categories)
2. `cloud_ranges.json` → 27 static IPs + 247 CIDR ranges + 332 rDNS
   regex patterns
3. `dns_fingerprints.json` → 217 fingerprints

`_load_oui_db()` builds `OUI_DB` from one of, in order:

1. the Wireshark `manuf` file (Linux / macOS / Windows install paths
   discovered in cell 4)
2. `tshark -G manuf` output
3. the `manuf` Python package
4. a 30-vendor embedded fallback

Public helpers:

- `oui_lookup(mac)` strips separators, takes the first 6 hex chars,
  returns the vendor string.
- `is_random_mac(mac)` checks the U/L bit of the first octet
  (`first & 0b10`); set = locally administered privacy MAC.
- `_match_dns_fingerprint(dns_queries)` iterates the 217 fingerprints,
  substring-matching each signature domain against the query set (and
  regex-matching if the signature contains regex metacharacters). The
  best-scoring fingerprint above its `match_threshold` wins.
- `_behavioral_classify(port_set, dns_queries, vendor, mac_random)` is
  the final fallback. Port heuristics: 554→IP camera; {9100,631,515}→
  printer; {5060,5061,2000}→VoIP phone; {8008,8009,8443}+Google
  vendor→Chromecast; 62078→iPhone; 1900→UPnP; {1883,8883}→MQTT;
  web-only with random MAC→"phone or laptop"; web-only with known
  vendor→"vendor computer"; known vendor with no clear ports→
  "generic vendor endpoint"; nothing→"Network endpoint".

`classify_local_device(mac, mdns_names, ports, dns_queries)` is the
three-tier dispatcher. Tier 1 rules `device_rules.json`
(condition types: `vendor_match`, `mdns_regex`, `ports_any`,
`dns_regex`; confidence from the rule's `priority` - ≥800 high, ≥500
medium, ≥200 low, else very-low). Tier 2 DNS fingerprints. Tier 3 the
behavioural fallback. Returns a dict with
`category, subcategory, vendor, model, rule_id, vendor_from_oui,
confidence, mac_privacy_random`.

External-IP classification lives in the same cell:
`classify_external_ip(ip, do_rdns=None)`. Order:

1. exact match in the 27 static IPs
2. linear scan of the 247 CIDR `ip_network` objects for membership
3. reverse-DNS lookup (**opt-in via `NETSEC_ENABLE_RDNS=1`**, off by
   default because it generates PTR queries on the monitored network;
   0.6 s per lookup, up to 20 workers, capped at 200 IPs by bytes)
   matched against the 332 rDNS regexes
4. return `{provider: "Unknown", service: "", type: "Unclassified", ...}`

---

## Cell 39 - Inventory, threat score, coverage

`_is_private(ip)` uses `ipaddress.ip_address(ip).is_private` (RFC 1918
+ link-local + loopback).

`_pick_dominant_mac(mac_counter)` picks the most common MAC seen for an
IP (a device that changed MAC mid-capture yields the majority MAC).

`_derive_device_name(ip, mdns_names, model)` produces a friendly name -
mDNS hostname when present (with the `.local` suffix correctly
stripped as a suffix, not a character set - see the regression at
`tests/test_device_name_derivation.py`), else `<model>-<last_octet>`.

`compute_threat_score(ip, session)` is a rule-only additive score
capped at 100, with tiers CRITICAL ≥75 / HIGH ≥50 / MEDIUM ≥25 / LOW
otherwise. Signals contribute:

| Signal | Points |
|---|---|
| SYN ≥ 1000 / ≥ 200 / ≥ 50 | 30 / 15..30 / up to 10 |
| unique_dsts ≥ 200 / ≥ 100 / ≥ 50 | 20 / up to 15 / 5 |
| RST ≥ 100 | up to 10 |
| distinct ports ≥ 100 / ≥ 30 | 10 / 5 |
| ARP IP-to-MAC inconsistency | +25 |
| long DNS queries (>60 chars, per-IP) | up to 15 |
| NXDOMAIN to this IP ≥ 50 | up to 10 |
| ≥ 3 independent signals | +10 |

`build_local_inventory(session)` iterates `ips_src`, keeps only
private IPs, classifies each, and returns a DataFrame with `ip`, `mac`,
`category`, `subcategory`, `vendor`, `model`, `confidence`,
`mac_privacy_random`, `threat_score`, `threat_tier`, `threat_reasons`,
`packets`, `bytes`, `ports`, `rule_id`, `vendor_oui`, `device_name`.

`build_external_inventory(session, do_rdns=None, max_rdns=200)` mirrors
the private path for external IPs. `compute_coverage(local_inv,
external_inv)` returns per-tier classification counts for the coverage
gauges.

The inventories live in module globals (`LOCAL_INV_S1`, `LOCAL_INV_S2`,
`EXTERNAL_INV_S1`, `EXTERNAL_INV_S2`, `COVERAGE_S1`, `COVERAGE_S2`),
refreshed by `rebuild_inventories()` in cell 45.

---

## Cell 41 - Live capture

`LiveCaptureWorker` runs `tshark -i <iface> -w chunk -l -T fields
-E separator=|` with 18 fields under a lock, reading each line into
per-IP counters. Interface collision is guarded across workers. State
machine: `idle → recording ⇄ paused → saved`, with a
`threading.Timer` enforcing the min/max session length
(`MIN_SECONDS = 120`, `MAX_SECONDS = 3600`). `stderr` is redirected to
`DEVNULL` on purpose - a pipe would deadlock on tshark's packet-count
line.

`stop_and_save()` merges the recorded chunks with `mergecap`; if
`mergecap` is missing it keeps just the first chunk and reports the
data loss in `error_msg`.

`LIVE_SESSIONS = {"S1": LiveCaptureWorker(), "S2": LiveCaptureWorker()}`
- one worker per session slot.

`list_capture_interfaces()` runs `tshark -D` and parses
`[(name, description), ...]` for the interface dropdown; the result is
cached in `_INTERFACE_LIST_CACHE`. Errors are deliberately not cached
so a broken tshark re-spawns the probe subprocess only when the panel
re-renders.

The **analyze path** for a live recording ignores the in-memory
`snapshot()` and re-ingests the merged PCAP through the standard
`_ingest_pcap_from_path` path, so a live session gets the same
`threats` / advanced-engine outputs as a loaded PCAP.

---

## Cell 43 - Browsing analysis, confusion, sensitivity

`CATEGORY_RULES` is a list of `(name, regex)` tuples mapping DNS
queries to browsing categories (Streaming, Work / Productivity,
Google / Cloud, Cloud Infra, Social, Security / Update,
News / Media, CDN / Infra). `classify_domain(q)` returns the first
matching category or `"Other"`.

`make_browsing_category_fig(s, label, device_names_map)` and
`make_browsing_hour_fig(s, label, device_names_map)` render the
stacked-category bar and per-hour heatmap for each named device.

`make_confusion_matrix_fig(s1, s2)` renders a 2×2 IsolationForest ×
DBSCAN agreement matrix per session, so a reader can see how often the
two ML models point at the same IP.

`make_sensitivity_sweep_fig(ip_agg_or_features)` fits 20 IsolationForest
models across `linspace(0.02, 0.30, 20)` (`n_estimators=100` -
deliberately cheaper than the production `200`) and plots the flagged-
count trade-off, drawing the vertical "Chosen" line at
`_chosen_contamination` (0.10 today). This is a **visualisation only**;
the production model always uses the fixed 0.10 from cell 12.

`build_browse_figures(S1, S2)` orchestrates the per-session browsing
figures and stashes them in module globals (`FIG_BROWSE_CAT_S1`,
`FIG_BROWSE_CAT_S2`, `FIG_BROWSE_HOUR_S1`, `FIG_BROWSE_HOUR_S2`,
`FIG_CONFUSION`, `FIG_SENSITIVITY`).

---

## Cell 45 - Figure factory

`make_figures(s1, s2, cdf, z_scores_df, my_ip)` is the ~30-figure
factory that populates `FIGS`. Topics: top talkers, burst timeline vs.
scan, protocols, DNS, devices, timeline, LSTM error histogram and
threshold line, per-device profile radar, signed Z-score bar,
per-hour DNS activity, TCP flag distributions, S1↔S2 comparison
(traffic delta, new / gone, byte delta), and the per-figure S1 / S2
twins.

Every figure passes through `_apply_aurora_layout(fig)` which sets the
Aurora theme: transparent backgrounds, Inter Tight + Newsreader font
pair, muted axis colours, glass-panel hover labels.

`_build_device_map_figure(session_dict, title_label, inv=None)` runs
PCA on the ML feature matrix, colours each point by the device's real
category from the inventory (previously mis-coloured every point as
"External" - regression fixed and locked in
`rebuild_figures`). Missing/empty inventories fall back to "External".

`_estimate_distance_m(rssi, tx=20, n=2.5, pl_d0=40)` is the indoor
log-distance path-loss model used by the RSSI-mode proximity map.

`_build_proximity_map_figure(session_dict, title_label)` chooses
between:

- **RSSI mode** when `wlan_features` has RSSI samples: MDS on the
  distance matrix built from `_estimate_distance_m`, bucketed at
  2 m / 5 m / 15 m.
- **Behavioural mode** otherwise: MDS on `1 - Pearson_correlation` of
  30-second activity bins for the top-30 talkers, with a
  same-`/24`-subnet bonus of `+0.25` and buckets 0.6 / 0.3 / 0.0.

`rebuild_figures()` orchestrates a full FIGS rebuild after a session
change: `rebuild_inventories()` first, then `make_figures(...)`,
`build_browse_figures(...)`, per-session hierarchy / external-provider /
service-type / coverage tables, and finally the device / proximity
maps. It is called from ~12 UI callbacks (`click_nav`, `click_tab`,
navigation, session switching, brand link, live-analyze completion, …).

---

## Cell 47 - Advanced Threat Detection engines

Threshold constants:

```
ADV_BEACON_MIN_EVENTS  = 16
ADV_BEACON_SCORE_FLAG  = 0.80
ADV_DNS_UNIQUE_MIN     = 20
ADV_DNS_UNIQUE_RATIO   = 0.90
ADV_DNS_ENTROPY_FLAG   = 3.8
ADV_DNS_LABEL_LEN_FLAG = 40
ADV_NX_STORM_MIN       = 30
ADV_DGA_MIN_LABEL_LEN  = 7
ADV_DGA_LOGPROB_FLAG   = None   # -> adaptive: mean(logprobs) - std
ADV_FUSION_WINDOW_MIN  = 15
```

`_adv_load_pk(path)` is a **second** tshark parse with 26 fields
(`_ADV_TSHARK_FIELDS`) - adds `dns.qry.type`, `arp.opcode`,
`arp.dst.proto_ipv4`, `tls.handshake.extensions_server_name`,
`tls.handshake.ja3`, `tls.handshake.ja4`,
`dhcp.option.dhcp_server_id`. This is a separate pass from cell 8's
loader because the fast path was tuned for the base features and adding
seven extra fields to every packet in a large capture is measurably
slower.

The five engines produce a common `_adv_sig` row shape (`device`,
`peer`, `signal`, `tactic`, `technique`, `score`, `severity`, `count`,
`first_ts`, `last_ts`, `detail`):

| Engine | Detection logic | MITRE technique |
|---|---|---|
| `_adv_detect_arp_dhcp` | IP → >1 MAC; MAC → ≥4 IPs; gratuitous ARP flood; >1 DHCP server id | T1557 / T1557.002 |
| `_adv_detect_dns_tunnel` | per registrable domain: unique ≥ 20 AND ratio ≥ 0.90 AND (mean entropy ≥ 3.8 OR mean qlen ≥ 40); NXDOMAIN storms ≥ 30 per `ip_dst` | T1071.004 / T1568.002 |
| `_adv_detect_dga` | char-bigram model (Laplace, `^…$`) trained on *resolved* domains in this capture; when <30 distinct bases, augments with the 49 hardcoded common domains. Flags labels whose log-probability is < `mean - std` AND (entropy ≥ 3.2 OR vowel_ratio < 0.25) | T1568.002 |
| `_adv_detect_beaconing` | (src, dst) pairs, TCP-SYN-only or UDP, ≥16 events, private→public only, NTP/123 excluded, median interval ≥ 1 s. Regularity is the mean of three sub-scores: IQR-skew, MAD/median dispersion, packet-size MAD. Flags at ≥ 0.80, "high" at ≥ 0.90 | T1071 |
| `_adv_detect_tls` | rare JA3 (single device with ≤3 occurrences → 0.5/low); TLS to external IP without SNI (0.45/low); SNI-provider ≠ dst-IP-provider via `_AdvCloudDB` (0.6/medium, domain fronting) | T1071.001 / T1090 |

`_adv_fuse(all_signals)` is the fusion / kill-chain scorer: per device,
`base = max(signal_score)`, `best = max distinct techniques inside the
15-minute sliding window`, `boost = 1 + 0.5·(best − 1)`,
**`risk = min(1.0, base × boost)`**.

`run_advanced_threats(pcap_path)` returns
`{available, n_packets, per_engine{5 keys}, all_signals, device_risk}`.
It **never raises** - on any failure returns
`{"available": False, "reason": ...}`.

Note: today the advanced signals live only on the dashboard side. The
LLM-judge candidate context (`llm_judge/judge_core.assemble_candidates`)
records them as `None`; feeding them into the judge is a planned
enhancement.

---

## Cell 48 - Dashboard (Aurora theme + navigation + callbacks)

The largest cell (~5400 lines). Defines the full Dash app:

**Theme.** Palette constants (`INK`, `INK_DIM`, `INK_MUTE`, `VIOLET`,
`CYAN`, `MAGENTA`, `WARM_PALETTE`, `PIE_PALETTE` …). `AURORA_INDEX_STRING`
is a custom `index_string` that ships the Aurora CSS (Google-Fonts
`Newsreader` + `JetBrains Mono` + `Inter Tight`, glass-panel utility
classes, animations).

**Views.** Three top-level views, switched by `render_main` from the
`app-mode` store: `intro` / `choice` / `dashboard`.

- `build_intro_view()` - the pink pixel-art NETSEC splash on a green
  CRT terminal, the "welcome" narrative, the acknowledgement checkbox
  (`intro-ack`) that gates the Continue button (`intro-continue-btn`).
- `build_choice_view()` - drag-and-drop `dcc.Upload` +
  `#pcap-path-input` + `#pcap-path-btn` + `#record-live-btn`, the
  staging card (`#staged-analyze-btn` / `#staged-clear-btn`), an
  education panel with the deep-dive content and a "Back to welcome"
  link. Every path staged here is analysed only after the user clicks
  ▶ Analyze on the staging card - a mis-typed path cannot launch a
  long run.
- `build_dashboard_view()` - the sidebar + topbar + tab strip +
  chart-picker strip + chart area + floating Restart button.

**Tabs and navigation.** Two top-level tabs (`analyze` 📊 and `security`
🛡️) each hosting a subset of the **52 `NAV_ITEMS`** grouped into **9
sections** (live, analysis, device, browsing, security, compare,
inventory, external, coverage). Session sub-tabs (S1 / S2 pills) are
locked until a second session loads. `SESSION_TWIN` maps each item to
its S1↔S2 counterpart. `NEEDS_S2_IDS` gates every S2-scope item so
clicking one while S2 is empty shows a "load a second capture" banner
instead of erroring.

**State store.** 13 `dcc.Store`s (`app-mode`, `active-chart`,
`active-session`, `active-tab`, `trigger-rebuild`, `staged-pcap`,
`staged-second-pcap`, `s2-loaded-tick`, `live-rec-tick`,
`live-stats-store`, `scroll-helper`, `last-chart-per-tab`,
`replacing-s1`) + one `dcc.Interval` (`live-recording-tick`, 3000 ms,
gated by `toggle_live_tick`).

**Callbacks.** 38 server-side + 12 clientside. Highlights:

- `handle_first_action` / `handle_second_first_action` - stage a PCAP
  from either input path.
- `handle_analyze_staged` / `handle_second_analyze_staged` - the
  ▶ Analyze click that actually runs the pipeline.
- `handle_live_analyze` - the ▶ Analyze on a saved live recording.
- `click_nav`, `click_tab`, `click_session_tab` - navigation between
  the 52 charts / 2 tabs / S1|S2 pills.
- `update_sidebar`, `render_chart`, `update_chart_picker_strip`,
  `render_tab_strip` - render the derived UI.
- `send_session_to_n8n` - **scp** the source PCAP to
  `NETSEC_REMOTE_HOST` over Tailscale (defaults to empty; the caption
  reads "set NETSEC_REMOTE_HOST" until configured, so a fresh fork
  cannot silently target somebody else's VM). Blocks the callback up
  to 7 s while probing `:8765/health` and `:5678` before the copy.
- Clientside: scroll-to-top, analyze-button spinner,
  live-stat DOM updates on the 3 s tick (deliberately no re-render
  so the chart area does not flicker).

**Ports.** `_find_free_port(8050, 8100)` picks the first free port in
`[8050, 8099]`; falls back to an OS-assigned port. The app is launched
with `app.run(debug=False, port=PORT, use_reloader=False,
jupyter_mode="external")`.

The button to send a session to the LLM judge on GitHub Actions
(`_render_ai_judge_link`) points at `<repo>/upload/main/incoming`
derived from `git remote get-url origin`, so a fork automatically
targets its own repo.

---

## Cell 49 - VM client integration shim

Optional import block. When `server/dashboard_client.py` is on the
path, it exposes `load_session_from_api` and `upload_session_via_api`
in the module namespace so a future dashboard control can pull a
session dict from the VM's `/v1/sessions/{id}` endpoint or push a
PCAP to `/v1/pcap`. Today the UI still routes uploads through the
scp button in cell 48; wiring the HTTP path into a callback is on the
follow-up list.

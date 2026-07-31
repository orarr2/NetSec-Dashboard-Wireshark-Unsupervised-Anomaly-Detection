# Q&A - Network Security Dashboard

## Professor questions & model answers

---

## Part 1 - Architecture & design decisions

**Q: Why do you use two intake paths (tshark and scapy) instead of one?**

A: `tshark` is dramatically faster than `scapy.rdpcap` - it streams the file once, applies a single dissector pass, and emits already-decoded text fields. On a 200K-packet PCAP, `tshark -T fields` runs in ~5 seconds; `rdpcap` takes ~30. `tshark` also exposes 802.11 fields (RSSI, frame type/subtype, retry flag) that scapy can't reach for monitor-mode captures. The trade-off is the dependency on a Wireshark install. The notebook tries `tshark` first; if it isn't found, it falls back to `scapy.rdpcap`, which has no external dependency. Schema parity is preserved: both loaders return the same dict keys.

---

**Q: Why is the intake function written as a single pass over the packets?**

A: A 200K-packet PCAP takes 5-30 seconds to parse. If each feature (DNS, ARP, TCP flags, timeline, WLAN, classification inputs) required its own loop, a pipeline with 6 features would take 30 seconds to 3 minutes just in IO. The single-pass design collects all data structures simultaneously at the cost of a longer, more complex function. For a notebook that users run interactively, this is meaningful.

---

**Q: Why do you separate device classification into its own engine instead of inlining the logic?**

A: Three reasons. (1) Classification rules change as new devices come to market; an external JSON file is editable without touching code. (2) The same engine is used both for offline PCAP analysis and for live capture - pulling it into a standalone function means both call sites stay consistent. (3) Testing - the classifier takes a `(mac, mdns, ports, dns)` tuple and returns a dict, which is easy to unit-test with synthetic inputs.

---

**Q: Why three JSON files instead of one?**

A: Different lifetimes and different responsibilities. `cloud_ranges.json` is about *external* IPs - "is this destination AWS or Cloudflare?". `dns_fingerprints.json` and `device_rules.json` are about *local* devices - "is this endpoint a Roomba?". External-IP data is updated by cloud-provider IP announcements; device data is updated by reverse-engineering new product DNS telemetry. Mixing them would force every update to touch one big file.

---

**Q: Why `encoding="latin1"` when reading CSVs?**

A: Wireshark sometimes writes non-ASCII bytes in the Info column when it includes protocol payload text - byte values 0x80-0xFF that are not valid UTF-8 sequences. `latin1` accepts all byte values 0-255 without raising `UnicodeDecodeError`. Some multi-byte Unicode characters will be decoded incorrectly, but the Info column is used only for filtering and display - not for precise byte-level parsing - so this is acceptable.

---

## Part 2 - Three-tier device classification

**Q: Why three tiers - wouldn't a single rule engine be simpler?**

A: Rules and DNS fingerprints answer different questions with different data. A rule like "vendor=Apple AND mDNS matches `watch`" needs the device to broadcast mDNS - that's a high-quality signal but it's only available some of the time. A DNS fingerprint like "queries `findmy.icloud.com` AND `gsa.apple.com`" needs the device to be actively talking to its cloud - also only available some of the time. The behavioural fallback ("uses port 554 → IP camera") works when neither of the others did. Each tier covers a different failure mode of the others.

---

**Q: How do you avoid Unknown returns?**

A: The behavioural fallback is constructed to *always* match. It checks a chain of port patterns (554 → camera, 9100 → printer, 5060 → VoIP, etc) and then falls through to two more permissive cases: if the device made web traffic on a small set of basic ports, classify it as "phone or laptop"; if not, but it has a known OUI vendor, classify it as "generic vendor endpoint"; otherwise, "Network endpoint (no signals available)" with `very-low` confidence. The confidence field is the honest signal - `Unknown` would lie because we *do* have at least some weak information from the OUI.

---

**Q: A device gets classified twice when both the rule engine and the DNS fingerprint match - which wins?**

A: The rule engine. The three tiers are evaluated in order and the first match wins. Within the rule engine, rules are sorted by priority descending, so a 900-priority rule like `apple-watch-mdns` beats a 600-priority rule like `apple-vendor`. The priority encodes our confidence in the signal: vendor+mDNS+specific name → 900; just vendor → 500-700; just port pattern → behavioural fallback. Rule-based identification is more constrained than DNS fingerprinting (a rule requires *all* its conditions to match; a DNS fingerprint just needs `match_threshold` signature domains), so a rule-engine match is stronger evidence.

---

**Q: What happens when a device has random MAC privacy enabled?**

A: The rule with `"mac_is_random": true` is *skipped* by the engine - random MACs can't be trusted to identify a vendor, so OUI-based rules don't fire. The DNS fingerprint tier and behavioural fallback still run as normal. The returned dict includes `mac_privacy_random: true` so downstream displays can flag the device with a "MAC randomised" badge. iOS, Android 10+, and Windows 10+ all use random MACs by default on Wi-Fi for privacy, so this is the common case in modern networks.

---

**Q: The DNS fingerprint match uses substring matching. Doesn't that cause false positives?**

A: It can. A known case: the Schneider Electric fingerprint contains the substring `se.com`, which also matches `coinbase.com`. The mitigation is the priority system: rule-based matches beat DNS fingerprints, so any device that *also* has a vendor or mDNS signal would be correctly classified. For pure-DNS-only devices, the user sees the offending classification with `confidence: medium` and a `(DNS-matched, N signals)` suffix - the suffix tells them to verify. A proper fix is to switch the matcher to suffix-anchored matching (`endswith` instead of `in`).

---

## Part 3 - Live capture & tshark integration

**Q: Why a background thread for live capture and not async?**

A: The capture thread runs `tshark` as a subprocess and reads lines via blocking IO from its stdout pipe. Python's `asyncio` doesn't play well with blocking subprocess pipes - you'd need `asyncio.subprocess` with non-blocking pipes, plus an event loop running in the Dash worker thread, plus thread-safe queues. A regular `threading.Thread` with a `threading.Lock` on the shared counters is dramatically simpler and Python's GIL ensures atomic dict updates. The trade-off is that a stuck `tshark` process blocks the thread forever - handled with a `stop_event` that the thread polls every iteration.

---

**Q: How do you avoid the dashboard freezing while live capture runs?**

A: The Dash callbacks never touch `tshark` directly. They read snapshots from `LiveCaptureWorker.snapshot()`, which returns a defensive copy of the worker's internal counters under a lock. The lock holding time is O(1) - copying a few hundred dict entries. The actual capture happens in a separate OS thread doing IO. From Dash's perspective, the worker is a passive data source that takes < 1 ms per read.

---

**Q: tshark needs admin/root. How does the notebook handle that?**

A: It doesn't try to elevate. If `tshark` returns "you don't have permission" on stderr, the worker captures that and surfaces it in the live KPI panel. The user has to relaunch Jupyter as admin (Windows) or with `sudo` (macOS/Linux). The PCAP-from-file path doesn't need any privileges and is always available as a fallback.

---

## Part 4 - JSON config files

**Q: Why JSON and not YAML or TOML?**

A: JSON is parsed by the Python standard library; YAML and TOML require third-party packages. The user is already installing six packages - minimising additional dependencies matters. JSON is also widely supported by editors with native autocomplete and validation. The trade-off is JSON's verbosity (no comments, no trailing commas), but for ~80 KB files that's acceptable.

---

**Q: A device fingerprint with `match_threshold: 2` needs two signature domains to match. Why 2?**

A: 1 is too permissive - many devices share a single domain. "apple.com" appears in DNS queries from every Apple device; alone, it can't distinguish an iPhone from an Apple Watch. 2 forces the matcher to see at least two device-specific signals, which is enough to discriminate device families. 3+ becomes too restrictive: short PCAP captures may not collect three matches even when the device is genuinely there. The threshold is per-fingerprint so it can be overridden: unique signals like `pi-hole.net` use `threshold: 1`; common cloud signals use `threshold: 2`.

---

**Q: What's the difference between `cidr_ranges` and `rdns_patterns` in `cloud_ranges.json`?**

A: CIDR matching is fast and works from raw IP alone - no DNS lookup needed. It's correct for static cloud infrastructure where IP space is announced. But it fails for anycast hosts (Cloudflare's `1.1.1.1` backed by hundreds of locations), CNAME chains (a destination like `disney-plus.net` resolves to a different cloud per region), and shared CDN tenants (a domain on Fastly may share IP space with thousands of unrelated services). rDNS pattern matching uses reverse DNS to get the hostname, then regex-matches against known patterns. This catches the cases CIDR misses. The trade-off is latency (each rDNS lookup is a DNS round-trip), mitigated by per-session caching.

---

## Part 5 - Proximity Map (RSSI + behavioural)

**Q: Walk me through the RSSI distance estimate. Why path loss n=2.5 and PL_d0=40 dB?**

A: The indoor log-distance path-loss model is:
```
PL(d) = PL(d0) + 10 · n · log₁₀(d / d0)
```
where PL is the path loss in dB, n is the path-loss exponent, and d0 is a reference distance. RSSI = Tx_power − PL, so:
```
d = 10^((Tx − RSSI − PL(d0)) / (10 · n))
```

- **n = 2.5** is the industry-standard value for typical office/residential indoor environments. n = 2 (free space) underestimates indoor walls; n = 3.5 (heavy obstruction) overestimates them. 2.5 splits the difference.
- **PL(d0=1m) = 40 dB** is the standard reference for 2.4 GHz Wi-Fi at 1 metre from the AP.
- **Tx_power = 20 dBm** (= 100 mW) is the typical max consumer-grade Wi-Fi AP transmit power.

The formula gives realistic results: RSSI −30 dBm → ~2.5 m, RSSI −50 → ~16 m, RSSI −70 → ~100 m. The user should treat distances as order-of-magnitude estimates, not measurements.

---

**Q: Why does the behavioural fallback use MDS instead of t-SNE or UMAP?**

A: MDS is deterministic given a fixed `random_state` - t-SNE and UMAP have local-minima jitter. A user comparing two consecutive analyses of the same data should see the same chart layout; t-SNE wouldn't guarantee that. MDS is also linear in interpretation: "distance in the chart corresponds to dissimilarity in the data" with no warping. The trade-off is that MDS can't preserve complex non-linear neighborhood structure the way t-SNE can - but for 30 endpoints in a low-dimensional similarity space, MDS produces a perfectly readable layout.

---

**Q: Why temporal correlation specifically for the behavioural mode?**

A: Subnet alone is too weak. Every home network has all devices on the same /24, so subnet membership clusters everyone together. Temporal correlation is much richer: if device A consistently makes web requests at the same 30-second windows as device B, they're probably co-located or co-triggered (a hub broadcasting to its peripherals). Adding subnet as a +0.25 similarity bonus is a hybrid - primary signal is timing, with subnet as a small tiebreaker for ambiguous cases.

---

## Part 6 - Machine learning choices

**Q: Why unsupervised ML and not supervised?**

A: Supervised models require labelled training examples - a list of IPs or sessions known to be malicious. This network has no such list. Even if a public labelled dataset existed, it would not generalise: what is "normal" on a corporate SaaS environment is different from a home network, a hospital, or a retail store. Unsupervised models learn the structure of *this* network's data without external labels.

---

**Q: Why IsolationForest and not Local Outlier Factor (LOF)?**

A: Both detect anomalies without labels. IsolationForest is O(n log n) - fast even on large datasets. LOF is O(n²) for exact computation and sensitive to the `k` parameter, requiring additional tuning. IsolationForest also produces a continuous anomaly score (`decision_function`) that allows ranking IPs by suspiciousness, not just binary flagging. LOF also produces a score but it represents a local density ratio rather than an isolation depth, which is harder to interpret.

---

**Q: Why DBSCAN and not k-means?**

A: k-means requires specifying the number of clusters k in advance - which is unknown. More importantly, k-means forces every point into a cluster, giving no "outlier" label. DBSCAN naturally produces noise points (label `-1`) - IPs with no density-reachable neighbours - which is exactly the anomaly signal we want.

---

**Q: Why is contamination fixed at 0.10, and how was that value chosen?**

A: An adaptive sweep used to pick it per-capture. It was retired because a seed-stability measurement against the labelled attack_tests ground truth showed the sweep's mean F1 (0.247, [0.05, 0.10, 0.15] × 5 seeds) matched fixed 0.10 (F1 = 0.250) while doing 15× more forest fits. The rules layer catches 100% of labelled attackers; IsolationForest is there to find *what the rules missed*, and its output is dominated by the feature set, not by ±0.05 in contamination. Fixing the value also makes the pipeline byte-for-byte reproducible on the same PCAP. The Contamination Sensitivity chart still fits 20 forests across [0.02, 0.30] and marks 0.10 on it, so the trade-off is visible without changing the production value. See `docs/TRADEOFFS_EN.md` §7 for the numbers.

---

**Q: How did you choose `eps` for DBSCAN?**

A: Via the k-distance elbow method from the original DBSCAN paper (Ester et al., 1996). For each point, the 2-nearest-neighbour distance is computed. These distances are sorted in descending order. The point of sharpest curvature (maximum second derivative of the sorted curve) is the "elbow" - above this distance, density drops sharply, making it the natural cluster boundary. The code takes the index of minimum second derivative and reads the distance at that index as `eps`. This removes the arbitrary hardcoded value and replaces it with a data-driven estimate.

---

**Q: What does the Hopkins statistic tell you?**

A: The Hopkins statistic H measures whether the data has any cluster structure. H ≈ 0.5 means the data is indistinguishable from uniform random noise - no meaningful clusters exist and DBSCAN labels would be arbitrary. H > 0.65 indicates genuine cluster tendency. If H is low, the notebook recommends using IsolationForest scores as the primary anomaly signal rather than DBSCAN noise labels.

---

## Part 7 - LSTM

**Q: Why LSTM and not a simpler statistical method like ARIMA?**

A: ARIMA assumes stationarity - the statistical properties of the time series do not change over time. Network traffic is inherently non-stationary: activity patterns differ by time of day, day of week, and application usage. A simple z-score on packet size over the full session treats an unusual burst at 3 am the same as an unusual burst during peak hours. The LSTM learns the conditional distribution of the next packet size given the previous 10 - it captures temporal context that simpler methods miss. The trade-off is interpretability: a z-score is easy to explain; an LSTM's prediction error requires understanding the architecture.

---

**Q: Why time-bin aggregation instead of using every packet?**

A: Step-sampling (`data[::k]`) takes every k-th packet regardless of timing. Two consecutive elements in the sampled sequence could be 0.001 seconds apart or 30 seconds apart - the LSTM cannot distinguish these cases. Time-bin aggregation (mean packet size per second) ensures that consecutive sequence elements are genuinely 1 second apart, so the LSTM learns real temporal rhythm. The cost: aggregation loses intra-second variation.

---

**Q: Why a chronological 80/20 split instead of random?**

A: Network traffic is a time series. Random splitting would allow the model to see future time-bins during training and past bins during validation - "data leakage". Chronological splitting (first 80% = train, last 20% = validation) mimics real deployment: the model is trained on historical data and evaluated on unseen future data.

---

**Q: The anomaly threshold is `mean + 2·std`. Why 2 standard deviations?**

A: Under a normal distribution, ~95% of values fall within 2 standard deviations of the mean. The remaining ~5% are in the tails - statistically unusual events. Using 2σ as the threshold means roughly 5% of *validation* sequences will be flagged as anomalous. A lower multiplier (e.g. 1σ) flags ~32% of sequences (too many false positives); a higher multiplier (3σ) flags ~0.3% (may miss real anomalies). The threshold is derived from validation errors - not training errors - so it reflects generalisation rather than memorisation. It is intentionally not tied to IsolationForest's `contamination = 0.10`: the LSTM lives on a different signal (per-second packet-size bins) and rewards its own error distribution.

---

**Q: How would you know if the LSTM is overfitting?**

A: By comparing training loss vs validation loss per epoch - exactly what the early stopping monitors. If training loss continues to decrease while validation loss increases (or plateaus), the model is memorising training sequences rather than learning general patterns. The training history printed at the end of LSTM training shows both `train` and `val` loss per epoch. A well-fitted model shows both losses decreasing together and then stabilising. Early stopping halts training when validation loss stops improving (`PATIENCE=2` epochs), restoring the best weights.

---

## Part 8 - Chart trade-offs

**Q: Why a scatter plot for burst_score vs dominance?**

A: The scatter encodes three dimensions simultaneously: burst_score (x), dominance (y), and anomaly flag (colour). A bar chart can show only one continuous variable per category - choosing either burst or dominance discards the other. A table shows numbers but makes it impossible to visually identify clusters or separation between normal and anomalous IPs. The trade-off: scatter plots require the viewer to understand both axes; a bar chart is more immediately intuitive for a single metric.

---

**Q: Why percentage (not raw counts) in the browsing-by-category chart?**

A: Normalising allows comparing devices with vastly different activity levels. A laptop making 5,000 DNS queries and a printer making 20 are incomparable on a raw-count axis - the printer would be invisible. Percentages show the *composition* of each device's DNS traffic. The trade-off: absolute volume is lost. The hover tooltip shows raw counts to compensate.

---

**Q: Why a heatmap for browsing activity by hour?**

A: With 10+ devices, a multi-line chart overlaps into unreadable noise. A grouped bar chart with 24 groups × N devices produces cognitive overload. The heatmap encodes two categorical axes (device, hour) plus magnitude (query count) in a compact grid where the eye immediately finds "hot" cells - a device active at 3 am stands out as a dark square. Trade-off: heatmaps require reading a colour scale, which is less precise than reading a bar height, and they are less accessible to colour-blind viewers (mitigated by choosing a perceptually uniform colour scale).

---

**Q: Why a histogram for LSTM errors and not a box plot?**

A: The histogram reveals the *shape* of the error distribution - is it approximately normal? Is there a long right tail? Are there two distinct modes? A box plot shows median, IQR, and outliers but hides the shape. The threshold line drawn on the histogram lets the viewer visually verify that it falls at a sensible point - not buried in the main mass of errors, not so far right that nothing is flagged. Trade-off: histograms depend on bin width.

---

**Q: The radar chart for device profiling - what is its limitation?**

A: Radar charts are good for multidimensional gestalt ("is this device's shape unusual?") but have two known limitations. First, the visual area enclosed depends on the order of axes - the same data looks different if `syn_count` and `burst_score` are adjacent versus opposite. Second, precise value reading is difficult - the Z-score bar chart provides the exact numbers. The radar is here for visual pattern recognition; the bar chart is for precise comparison.

---

## Part 9 - Model agreement matrix

**Q: You have unsupervised models. How can you have a confusion matrix?**

A: Strictly, a classic confusion matrix (TP/FP/TN/FN) requires known true labels. Since we have none, what the notebook shows is a **model agreement matrix** - a 2×2 table where the two "classifiers" are IsolationForest and DBSCAN. Each IP falls into one of four cells:

|  | DBSCAN: Noise | DBSCAN: Clustered |
|---|---|---|
| **IF: Anomaly** | 🔴 Both flag - high confidence | 🟡 IF only |
| **IF: Normal** | 🟡 DBSCAN only | 🟢 Neither - likely normal |

The two models use completely different algorithmic principles - tree isolation vs density clustering. Agreement between independent methods is stronger evidence than either model alone. The chart title explicitly states the unsupervised disclaimer.

---

**Q: What would you need to turn this into a real confusion matrix?**

A: Three approaches, in increasing rigour:
1. **Manual labelling** - inspect the top 20 most anomalous IPs and classify each as genuinely suspicious or false positive.
2. **Threat intelligence cross-reference** - check flagged IPs against a public blacklist (AbuseIPDB, VirusTotal).
3. **Synthetic injection** - run a known attack on a test machine (e.g. nmap port scan), capture the PCAP, re-run the pipeline, verify the scanning IP is flagged.

---

## Part 10 - Results interpretation

**Q: A high `syn_count` Z-score - does that definitely mean a port scan?**

A: No. High syn_count means the device sent significantly more SYN packets than the average *local* device. Legitimate explanations: a browser opening many tabs (each HTTPS connection starts with SYN), a cloud-sync client maintaining many persistent connections, a developer running automated tests. It becomes more suspicious when combined with: many unique destinations, high RST count (connections refused), very uniform packet sizes, and activity at unusual hours. IsolationForest considers all features together - a single-feature Z-score should never be interpreted in isolation.

---

**Q: 157 IPs disappeared between sessions. Is that alarming?**

A: Not necessarily. Most are ephemeral external IPs - CDN edge nodes, cloud service endpoints, advertisement servers - that change with each browsing session. A single YouTube video can involve 5-10 distinct CDN IPs that appear only while the stream is active. The more meaningful question is: are the *new* IPs in S2 generating unusual traffic volumes, or are they communicating with devices that were not previously active? The comparison charts and intelligence insights section highlight the largest changes rather than the raw count.

---

**Q: A device classified by behavioural fallback as "Generic IP camera (RTSP-detected)" - how confident are you?**

A: `confidence: low`. The behavioural fallback fires when neither the rule engine nor the DNS fingerprint matched, which usually means the device didn't broadcast mDNS and didn't query its cloud during the capture. Port 554 (RTSP) is a strong signal - almost only IP cameras and a few media-server applications use it - but it's a single-feature classification, and the cloud-side identification ("which brand of camera?") is missing. The classifier returns the OUI vendor (if any) as the vendor, and the model string includes "(RTSP-detected)" so the user knows this came from port-pattern recognition. In a SIEM workflow, this is a "review me" signal - not a confirmed identification.

---

**Q: The model flagged X IPs as anomalies. How do you know which are true positives?**

A: Without ground truth labels, we cannot compute precision or recall on a live capture. We use three proxies for confidence: (1) **model agreement** - IPs flagged by both IsolationForest and DBSCAN are more credible; (2) **anomaly score magnitude** - IPs with very low iso_score are more extreme; (3) **corroborating signals** - an IP flagged by ML AND appearing in the security scan results (high SYN count, ARP anomaly, DNS long queries) is a stronger finding. The Contamination Sensitivity chart shows what would be flagged at other contamination values, so the reader can see the trade-off between flagging more IPs and keeping the flagged group extreme. For actual measurement we rely on the labelled `attack_tests/` fixtures, `attack_tests/evaluate.py` and the CI regression suite.

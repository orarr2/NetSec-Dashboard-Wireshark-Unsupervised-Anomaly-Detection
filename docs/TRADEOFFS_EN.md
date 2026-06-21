# Design Decisions and Trade-offs - Network Security Dashboard

This document summarises the substantive design decisions, what options were considered, and why the chosen option was selected.

---

## 1. File picker: PySide6 in a child process

**The decision:** Use PySide6 via `subprocess.run([sys.executable, picker_script])` instead of direct import.

**What was considered:**
- **tkinter** - built into Python, no installation needed. But the UX is ugly and not suited to modern platforms, particularly poorly handled on macOS Retina.
- **PyQt5/PyQt6** - high-quality and available, but GPL-licensed. If imported directly into the notebook, the resulting code becomes "infected" with GPL.
- **PySide6 direct import** - high-quality and LGPL. But direct import still burdens the notebook process memory and can cause crashes in some Jupyter configurations.
- **PySide6 in a child process** ← chosen.

**Advantages:**
- Under LGPL, the license doesn't "infect" when used in a separate process.
- The notebook doesn't load PySide6 into its own memory - lighter.
- Any PySide6 issue doesn't crash Jupyter.

**Disadvantages:**
- Subprocess overhead each time the user clicks "Load PCAP" (~150 ms).
- Need to save the script to a tempfile (created/deleted each time).

**When to consider an alternative:** If targeting an environment without PySide6 at all, fall back to tkinter via a manual fallback path.

---

## 2. Device classification: 3 tiers (rules → DNS → behavioural)

**The decision:** Every device passes through 3 classification stages sequentially. The first successful stage stops the process.

**What was considered:**
- **Single rule table with many rules** - simple to maintain but requires huge regex coverage of every possible signal; brittle when device DNS patterns change.
- **Pure DNS fingerprinting** - works without OUI but requires DNS traffic to be present, which is not always captured.
- **Pure OUI vendor lookup** - fast and offline, but vendor name alone doesn't distinguish iPhone from iPad from Apple Watch.
- **Three-tier waterfall** ← chosen. Rules first (high confidence when conditions are specific), then DNS fingerprints (medium confidence), then behavioural port patterns (low confidence - never returns Unknown).

**Advantages:**
- Graceful degradation: even devices with no DNS traffic still get a meaningful classification from ports + OUI.
- Clear confidence levels: the user knows how much to trust each label.
- No `Unknown` returns - every device gets categorised.

**Disadvantages:**
- More code paths to maintain.
- A behavioural false positive (e.g. "port 554 = camera") is reported with `low` confidence; users must read the confidence field.

**When to consider an alternative:** In an environment where every device has known OUI and broadcasts mDNS (e.g. tightly managed enterprise networks), the behavioural fallback can be disabled to reduce noise.

---

## 3. JSON configs: three separate files vs one big file

**The decision:** Split into `cloud_ranges.json`, `dns_fingerprints.json`, `device_rules.json`.

**What was considered:**
- **Single mega-config** - one source of truth, one file to load. But mixes lifetimes (cloud IP ranges update monthly; device fingerprints update with new product releases).
- **One file per category** (e.g. one per device category) - too many files; index lookups complicated.
- **Three files by concern** ← chosen.

**Advantages:**
- Each file has an independent update lifetime.
- Editors can validate each schema independently.
- A bug in one file doesn't block the loader from using the other two.

**Disadvantages:**
- Three `_find_config()` calls instead of one.
- Slight risk of schema drift between files.

**When to consider an alternative:** If the project ever consumes these via API instead of disk files, merging makes sense (one HTTP call vs three).

---

## 4. Live capture: blocking thread vs async

**The decision:** Use `threading.Thread` with `threading.Lock` for the live capture worker. Dash callbacks poll via `worker.snapshot()`.

**What was considered:**
- **asyncio** - modern Python pattern; but `asyncio.subprocess` with blocking IO pipes is awkward, and Dash callbacks run in worker threads without an event loop.
- **multiprocessing** - isolates the capture from the notebook process completely; but inter-process communication overhead would slow snapshots.
- **threading + Lock** ← chosen.

**Advantages:**
- Python's GIL makes dict updates atomic; `Lock` only protects multi-step counter updates.
- The capture thread does blocking IO (reading stdout from tshark) which threads handle natively.
- Snapshot copy under lock is O(1) - Dash callbacks never wait.

**Disadvantages:**
- A stuck tshark process blocks the thread; handled with `stop_event` polled every iteration.
- Cannot easily run live capture across multiple machines.

**When to consider an alternative:** If the dashboard needs to capture from a remote machine over SSH, refactor to `multiprocessing` or a network protocol.

---

## 5. Plotly template: bypass via `default = "none"`

**The decision:** Set `pio.templates.default = "none"` at the top of the figure-building cell.

**What was considered:**
- **Keep Plotly's default template** (`plotly_dark` or `plotly`) - gives "free" styling but the template's internal state can become corrupted after many figure rebuilds, causing crashes deep inside `apply_default_cascade`.
- **Use a custom template** - registers a clean copy. But Plotly's express layer still mutates template internals during chart construction.
- **Bypass all templates** ← chosen. `_apply_aurora_layout(figs)` then applies all styling explicitly via `update_layout`.

**Advantages:**
- Completely deterministic output - no internal Plotly state can corrupt the figures.
- Aurora styling is explicit and version-controlled in source.

**Disadvantages:**
- More verbose: every styling rule must be in `_apply_aurora_layout`.
- Loses out-of-the-box Plotly themes (acceptable since we have our own).

**When to consider an alternative:** If a future Plotly version fixes the template-corruption bug, the bypass can be removed for slightly cleaner code.

---

## 6. Anomaly detection: IsolationForest + DBSCAN + LSTM (three models)

**The decision:** Run three different unsupervised models and let the dashboard show their agreement.

**What was considered:**
- **One model only** - simpler, less compute. But every model has blind spots; a single result is hard to trust.
- **Ensemble vote** - average the anomaly scores from multiple models. But the scores are on different scales, requiring normalisation that obscures the underlying disagreements.
- **Independent models with agreement visualisation** ← chosen.

**Advantages:**
- The model agreement matrix lets the user see which IPs both models flag (high confidence) vs only one model flags (investigate).
- Each model has different theoretical assumptions - agreement between independent assumptions is stronger evidence.
- The LSTM operates on time-series, not static features, catching anomalies the static models miss.

**Disadvantages:**
- 3× the training time.
- More complex documentation; users must understand each model.

**When to consider an alternative:** In real-time alerting where latency matters, a single fast model (IsolationForest) suffices.

---

## 7. IsolationForest contamination: 20-point sweep vs fixed value

**The decision:** Sweep contamination from 0.02 to 0.30 (20 values), pick the value whose flagged group has the lowest mean anomaly score.

**What was considered:**
- **Fixed contamination = 0.10** (Scikit-learn default) - works but arbitrary; some networks have 1% anomalies, others 25%.
- **Manual tuning per dataset** - accurate but requires expertise; defeats the purpose of an automated pipeline.
- **Data-driven sweep** ← chosen.

**Advantages:**
- The notebook adapts to each network's actual anomaly density.
- The sensitivity sweep chart visualises *why* the chosen contamination is reasonable.
- Removes a hardcoded value with no justification.

**Disadvantages:**
- 20× the contamination-related training time.
- Self-referential: uses the model's own output to evaluate its parameter. Without ground truth labels, this is a heuristic, not a proof.

**When to consider an alternative:** If real labels become available (e.g. via threat intelligence), use precision-at-k to choose contamination.

---

## 8. DBSCAN eps: k-distance elbow vs fixed value

**The decision:** Compute eps from the maximum of the second derivative of sorted 2-NN distances.

**What was considered:**
- **Fixed eps = 0.5 (or 1.0, or 1.3)** - works on some datasets, fails completely on others.
- **Silhouette-based grid search** - accurate but requires labeled data or assumes balanced clusters.
- **k-distance elbow** ← chosen (from the original DBSCAN paper, Ester et al., 1996).

**Advantages:**
- Data-driven and parameter-free.
- The same algorithm scales from 50 IPs to 5000 without retuning.
- Theoretical grounding in the paper.

**Disadvantages:**
- Requires the data to have a visible "elbow" in the 2-NN distance plot; flat distributions give arbitrary results.
- The Hopkins statistic is used as a sanity check on whether clustering is meaningful at all.

**When to consider an alternative:** For very small datasets (<30 points), the elbow is unreliable; revert to a fixed eps and document the choice.

---

## 9. LSTM input: time-binned packet sizes vs every packet

**The decision:** Aggregate packets into 1-second time bins, take the mean size per bin, then train on sequences of 10 consecutive bins.

**What was considered:**
- **Every packet as a sequence element** - finest granularity; but consecutive packets can be 1 µs or 30 s apart, so the LSTM can't learn real temporal rhythm.
- **Step-sampling (every k-th packet)** - reduces sequence length but breaks temporal continuity for the same reason.
- **Time-bin aggregation** ← chosen.

**Advantages:**
- Each sequence element is genuinely 1 second apart - the LSTM learns real time patterns.
- Reduces sequence length dramatically (10K packets → 100 bins of 100 packets each).
- Robust to variable packet arrival rates.

**Disadvantages:**
- Intra-second variation is lost (a burst of 100 packets in one second is represented as one average).
- Choice of bin width affects model behaviour; 1 second was chosen as a compromise.

**When to consider an alternative:** For high-frequency trading or other µs-scale analysis, larger bins lose too much information; revert to per-packet with timestamp deltas as an input feature.

---

## 10. LSTM threshold: validation 2σ vs fixed percentile

**The decision:** Compute the anomaly threshold as `mean(val_err) + 2 * std(val_err)`, where val_err is the prediction error on the validation set.

**What was considered:**
- **Fixed percentile (e.g. 95th of training errors)** - simple but uses training data, which the model has memorised.
- **Validation-based percentile (95th of val errors)** - uses unseen data but is sensitive to validation-set size.
- **Validation 2σ** ← chosen.

**Advantages:**
- Under a normal distribution, 2σ corresponds to the 97.5th percentile - flagging roughly 2.5% of sequences as anomalous.
- Uses validation errors, so the threshold reflects generalisation, not memorisation.
- Threshold is reported on the histogram for visual verification.

**Disadvantages:**
- Assumes errors are approximately normal; for very skewed error distributions, the 2σ threshold may be too lenient or too strict.

**When to consider an alternative:** If the LSTM is over-fitting (training/validation gap), the 2σ threshold becomes meaningless; first fix the model.

---

## 11. Z-scores: local peers only vs all IPs

**The decision:** Compute Z-scores against only private-IP peers (RFC 1918 ranges).

**What was considered:**
- **All IPs as baseline** - large sample size but includes CDN/cloud destinations with very different traffic profiles than local devices.
- **Local peers only** ← chosen.
- **Curated reference set** - would be ideal but requires labelled data.

**Advantages:**
- The baseline reflects actual peer devices, not Internet traffic.
- Z-scores become interpretable: "this device is unusual *for a local device*", not "this device is unusual *compared to a YouTube CDN*".

**Disadvantages:**
- Small sample size (10–30 local devices) means Z-scores are noisy.
- IPv6-only local devices (if not in `is_private` ranges) get excluded.

**When to consider an alternative:** On networks with very few local devices, augment with cross-network reference data.

---

## 12. Proximity Map: dual-mode (RSSI + behavioural fallback)

**The decision:** When 802.11 RSSI is in the PCAP, use the log-distance path-loss model. Otherwise, fall back to temporal correlation + subnet similarity + MDS embedding.

**What was considered:**
- **RSSI-only** - accurate but requires monitor-mode capture, which Windows Wi-Fi typically can't provide.
- **Behavioural-only** - works on any capture but provides only relative proximity, no metres.
- **Dual-mode with explicit indicator** ← chosen.

**Advantages:**
- Works on every PCAP regardless of capture mode.
- The chart title tells the user which mode is active.
- An annotation directs the user to monitor-mode capture if they want real RSSI.

**Disadvantages:**
- Two code paths to maintain.
- Behavioural mode produces a layout that's harder to interpret than the RSSI mode (no unit on the axes).

**When to consider an alternative:** In a deployment that always uses monitor-mode captures (security ops centre with AirPcap hardware), the behavioural fallback can be removed.

---

## 13. Path-loss model: log-distance with n=2.5 vs free-space (n=2)

**The decision:** Use `d = 10^((Tx − RSSI − PL₀) / (10 · n))` with `Tx = 20 dBm`, `n = 2.5`, `PL₀ = 40 dB`.

**What was considered:**
- **Free-space (n=2)** - accurate outdoors with line-of-sight; underestimates indoor walls.
- **Heavy obstruction (n=3.5–4)** - accurate in dense buildings; overestimates open-plan offices.
- **Indoor average (n=2.5)** ← chosen.

**Advantages:**
- Industry-standard value for typical office/residential indoor environments.
- Gives realistic distance estimates: RSSI −30 → ~2.5 m, RSSI −70 → ~100 m.
- The function accepts custom `n` for users who know their environment.

**Disadvantages:**
- No single n is universally correct - walls, furniture, and other transmitters all affect the actual loss.
- Distances should be treated as order-of-magnitude estimates, not measurements.

**When to consider an alternative:** Calibrate n by measuring RSSI at known distances in the specific deployment environment.

---

## 14. MDS over t-SNE/UMAP for proximity embedding

**The decision:** Use scikit-learn MDS with `random_state=42` for the behavioural-mode 2D embedding.

**What was considered:**
- **t-SNE** - better at preserving local structure; non-deterministic between runs.
- **UMAP** - fast and effective; also non-deterministic.
- **PCA** - deterministic but assumes linear structure.
- **MDS with fixed random_state** ← chosen.

**Advantages:**
- Deterministic - the same input produces the same chart every time.
- Linear interpretation - distance in the chart maps directly to dissimilarity in the data.
- Robust on small data (≤30 points), where t-SNE/UMAP can degenerate.

**Disadvantages:**
- Cannot capture complex non-linear neighbourhood structure as well as t-SNE.

**When to consider an alternative:** For >100 points with complex structure, UMAP with a fixed seed.

---

## 15. Dashboard state: dcc.Store vs global variables

**The decision:** Use `dcc.Store` for per-browser-session state. Use Python globals (`S1`, `S2`, `FIGS`) for cross-callback shared data.

**What was considered:**
- **All state in Python globals** - simple but breaks when multiple browser tabs are open.
- **All state in dcc.Store** - clean separation but every callback must read/write JSON.
- **Hybrid** ← chosen.

**Advantages:**
- UI state (current view, selected chart, modal open) lives in `dcc.Store` and is per-browser-tab.
- Heavy data (the session dicts and figures) lives in Python globals because every tab sees the same PCAP analysis.
- Best of both worlds: lightweight UI state, no JSON serialisation of large objects.

**Disadvantages:**
- Multiple tabs analysing different PCAPs simultaneously is unsupported (would require renaming globals per session).
- Globals persist between page reloads, which can be confusing during development.

**When to consider an alternative:** For multi-tenant deployments, refactor everything into `dcc.Store` + a session-id mechanism.

---

## 16. CSV encoding: latin1 vs UTF-8

**The decision:** Read Wireshark CSVs with `encoding="latin1"`.

**What was considered:**
- **UTF-8** - strict, fails on non-UTF-8 bytes in the Info column.
- **UTF-8 with errors="replace"** - survives but corrupts byte sequences.
- **latin1** ← chosen.

**Advantages:**
- Accepts all byte values 0–255 without raising `UnicodeDecodeError`.
- The Info column is only used for filtering and display, not byte-level analysis.

**Disadvantages:**
- Multi-byte Unicode (Hebrew, Chinese, etc.) in the Info column displays as mojibake.

**When to consider an alternative:** For non-ASCII payload analysis, switch to `cp1252` or `utf-8-sig` depending on the source.

---

## 17. Chart: scatter for burst vs dominance

**The decision:** Use a scatter plot with colour-coded anomaly flag, not a bar chart.

**What was considered:**
- **Bar chart by IP, separate for burst and dominance** - two charts, but cannot show the joint distribution.
- **Table of values** - precise but doesn't show clusters or separations visually.
- **Scatter with colour** ← chosen.

**Advantages:**
- Three dimensions encoded simultaneously: burst (x), dominance (y), anomaly flag (colour).
- Eye immediately spots outliers far from the main cluster.

**Disadvantages:**
- Requires the viewer to understand both axes.

**When to consider an alternative:** For a single-metric ranking, a bar chart is more intuitive.

---

## 18. Browsing chart: stacked bar (percentage) vs raw counts

**The decision:** Show browsing-by-category as a stacked bar chart with percentages per device.

**What was considered:**
- **Raw counts** - accurate but makes low-volume devices invisible.
- **Heatmap of count** - shows volume but hides composition.
- **Stacked percentage** ← chosen.

**Advantages:**
- Devices with vastly different activity levels become comparable.
- Composition (% Streaming, % Work, % Social) is the relevant question.

**Disadvantages:**
- Absolute volume is lost; recovered via hover tooltips and a separate Top Talkers chart.

**When to consider an alternative:** For "which device uses the most bandwidth" analysis, use the Top Talkers chart.

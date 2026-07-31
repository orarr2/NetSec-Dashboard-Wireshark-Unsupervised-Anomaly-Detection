# Model Diagnostics

Per-session values the three unsupervised models produce. These are the
numbers surfaced in the Analysis Insights views and stashed on the
session dict for later inspection (`ip_agg.attrs`).

## What is fixed vs. what adapts

| Model | Field | Value / how it is chosen |
|---|---|---|
| IsolationForest | `contamination` | **fixed at 0.10** (`n_estimators=200`, `random_state=42`). A prior seed-stability sweep over `[0.05, 0.10, 0.15]` × 5 seeds against labelled ground truth matched fixed-0.10 F1 (0.250 vs 0.247) while doing 15× more forest fits, so the sweep was retired. See `docs/TRADEOFFS_EN.md`. |
| IsolationForest | `#anomalies / #IPs` | count where `predict() == -1` over the per-IP feature matrix |
| DBSCAN | `eps` | k-distance (k=2) elbow at the second-derivative minimum. Fallbacks: `1.3` when fewer than 4 IPs, and `max(mean(k_dist), 0.05)` when the elbow collapses to 0 (spoofed-source floods). |
| DBSCAN | `min_samples` | fixed at 2 |
| DBSCAN | `clusters / noise` | non-noise label count / count of label `-1` |
| DBSCAN | `silhouette` | silhouette on non-noise points when there are ≥ 2 clusters, else `n/a` |
| DBSCAN | `>5000 IPs` | **skipped entirely** (all `cluster = -1`) to avoid the O(n²) neighbourhood blow-up seen on spoofed floods |
| LSTM | `threshold` | `val_mean + 2·val_std` of the per-sequence prediction error on the held-out val split |
| LSTM | `#flagged / #sequences` | sequences whose error exceeds the threshold |
| LSTM | training gate | needs ≥ 20 usable 1-second bins (SEQ_LEN=10 leaves 10 sliding windows). Shorter captures skip LSTM silently; the deterministic rules cover them. |

## Feature matrix

IsolationForest and DBSCAN share a 10-feature per-IP matrix
(`StandardScaler`-normalised):

```
mean_len, std_len, count, burst_score, unique_dsts,
syn_count, rst_count, fin_count, null_count, xmas_count
```

LSTM runs on a separate temporal signal: mean packet size per 1-second
bin (zero-filled for idle seconds), sequenced and scored by prediction
error. Wall-clock seconds - not "seconds with traffic" - which is what
makes long idle gaps show up as anomalous bursts on either side.

## Attrs stashed on `ip_agg`

Set by `run_ml_on_session`, available on `S['ip_agg'].attrs` for the
dashboard's Model Diagnostics view:

```
_chosen_contamination   0.10 today (fixed)
_eps_auto               chosen eps (elbow / fallback / floor)
_min_samples            2
_silhouette             float or None
_n_clusters             int
_n_noise                int
```

## Contamination sensitivity chart

The dashboard's `sensitivity_sweep` chart still fits 20 IsolationForest
models across `contamination = 0.02 .. 0.30` and draws a vertical line
at the value actually in use (`0.10`). It is a visualization of the
trade-off, not a selector - the production model always uses 0.10.

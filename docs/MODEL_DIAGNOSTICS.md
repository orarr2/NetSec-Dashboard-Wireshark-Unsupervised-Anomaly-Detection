# Model Diagnostics

The dashboard exposes a **Model Diagnostics** card on the **Analysis Insights**
page (sidebar item) that reports, per session and recomputed on every capture,
the hyperparameters and scores chosen by the three unsupervised anomaly models.
None of these values are hard-coded; they are selected from the data at load
time, so they change with each capture.

## What the card reports

| Model | Field | How it is chosen | Source cell |
|---|---|---|---|
| IsolationForest | `contamination` | sweep over [0.05, 0.10, 0.15]; picks the value that minimises the mean anomaly score of the flagged points | `run_ml_on_session` |
| IsolationForest | `#anomalies / #IPs` | `predict() == -1` over the per-IP feature matrix | `run_ml_on_session` |
| DBSCAN | `eps` | k-distance (k=2) curve, elbow at the second-derivative minimum, rounded to 2 dp; **fallback = 1.3** only when fewer than 4 IPs are present | `run_ml_on_session` |
| DBSCAN | `min_samples` | fixed at 2 | `run_ml_on_session` |
| DBSCAN | `clusters` / `noise` | non-noise label count / count of label `-1` | `run_ml_on_session` |
| DBSCAN | `silhouette` | silhouette score over the non-noise points; reported only when there are >= 2 clusters, otherwise `n/a` | `run_ml_on_session` |
| LSTM | `threshold` | `val_mean + 2 * val_std` of the per-sequence prediction error | `evaluate_lstm` |
| LSTM | `#flagged / #sequences` | sequences whose error exceeds the threshold | `evaluate_lstm` |

## Feature matrix

The IsolationForest / DBSCAN feature matrix is built from 7 per-IP features,
`StandardScaler`-normalised:

```
mean_len, std_len, count, burst_score, unique_dsts, syn_count, rst_count
```

The LSTM runs on a separate temporal signal: packet-size totals binned into
1-second windows, sequenced and scored by prediction error.

## Validated example run (two real captures)

Running the full pipeline on two real Wireshark captures (loaded as S1 and S2,
then compared) produced:

| | S1 | S2 |
|---|---|---|
| packets | 40,958 | 112,911 |
| IPs | 123 | - |
| IsolationForest contamination | 0.05 | 0.05 |
| DBSCAN eps (k-distance elbow) | **0.78** | **4.86** |
| DBSCAN clusters / noise | 1 / 6 | 1 / 3 |
| Silhouette | n/a | n/a |
| LSTM threshold | 0.314 | 0.338 |

Session comparison (S1 -> S2): 275 IPs compared, 152 new in S2, 55 gone.

### Reading the example

- **`eps` differs per session (0.78 vs 4.86).** The k-distance elbow is
  recomputed for each capture, so the neighbourhood radius adapts to the
  density of that session. This is the intended behaviour and is the reason
  the value is surfaced rather than fixed.
- **`Silhouette = n/a` is expected here, not an error.** On these captures
  DBSCAN forms a single dense cluster plus a few noise points. The silhouette
  score is only defined for >= 2 clusters, so it is reported as `n/a`. A single
  dominant cluster is itself an informative result about the feature space.

## Where to find it in the notebook

These values are also printed to the cell output when the notebook runs
(`run_ml_on_session` and `evaluate_lstm`), in addition to being shown on the
dashboard's Analysis Insights page.

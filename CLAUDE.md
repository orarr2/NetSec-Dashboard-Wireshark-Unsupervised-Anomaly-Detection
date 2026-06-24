# Project workflow notes

## Git / merge workflow (standing preference)

- **Always merge approved feature branches into `main`** — it is the default
  branch. Do not leave finished, approved changes living only on a feature
  branch.
- If a direct `git push` to `main` is blocked by branch policy, merge by
  opening a pull request and merging it via the API instead.
- **Delete `claude/*` feature branches after they are merged** (remote and
  local). If branch deletion is blocked by policy, say so and ask the user to
  delete it from GitHub.

## Project facts

- Despite the legacy repo name, this project uses **unsupervised** learning,
  not Random Forest / XGBoost:
  - **IsolationForest** — per-IP anomaly detection (`n_estimators=200`,
    `contamination` auto-tuned over [0.05, 0.10, 0.15], `random_state=42`).
  - **DBSCAN** — behavioural clustering (`min_samples=2`, `eps` auto-derived
    from the k-distance elbow; StandardScaler-normalised 7-feature matrix).
  - **LSTM** (PyTorch) — temporal anomaly detection on 1-second packet-size
    bins (`hidden_size=64`, Adam lr=0.001, MSELoss, early stopping).

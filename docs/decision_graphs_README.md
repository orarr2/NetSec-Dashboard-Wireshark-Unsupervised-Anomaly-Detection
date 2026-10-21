# NetSec - Project Decisions & Dilemmas

These graphs show the decisions and dilemmas made during the project, in two
Mermaid formats and one Graphviz format.

| File | Format | Style |
|------|--------|-------|
| `decisions_pipeline_en.mmd` | Mermaid | Annotated pipeline (like the attached screenshot) |
| `decisions_dilemmas_en.mmd` | Mermaid | Decision tree (rejected vs chosen) |
| `decisions_en.dot` | Graphviz | Decision DAG |

## How to render

**Mermaid (.mmd):**
- Paste into <https://mermaid.live> - instant preview.
- Or GitHub renders ```mermaid fenced blocks automatically.
- Or CLI: `npx @mermaid-js/mermaid-cli -i decisions_pipeline_en.mmd -o out.png`

**Graphviz (.dot):**
- `dot -Tpng decisions_en.dot -o decisions_en.png`
- Or paste into <https://dreampuf.github.io/GraphvizOnline>

## Decisions captured

1. Supervised vs unsupervised → unsupervised (no labels; RF/XGBoost/SVM rejected)
2. Single model vs ensemble → IsolationForest + DBSCAN + LSTM + deterministic rules
3. IsolationForest contamination → fixed 0.10 (seed-stability sweep matched fixed 0.10 F1 at 15× the cost; retired). See `docs/TRADEOFFS_EN.md` §7.
4. DBSCAN eps → auto k-distance elbow, per-capture (illustrative measurements varied 0.78 / 4.86 on two real captures); fallbacks documented in `docs/MODEL_DIAGNOSTICS.md`
5. DBSCAN min_samples → 2 (raising it collapses the 10-D feature space to noise)
6. LSTM sequence sampling → contiguous (not step-sampling)
7. LSTM error baseline → held-out validation (not training set), flag > mean+2σ
8. Evaluation with labelled ground truth → `attack_tests/` fixtures + regression suite

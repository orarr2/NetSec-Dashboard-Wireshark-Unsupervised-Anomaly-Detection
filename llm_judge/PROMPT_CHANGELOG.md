# Judge Prompt Changelog

Every prompt change bumps `PROMPT_VERSION` in `judge_config.py` (which also
invalidates the verdict cache), gets a calibration run from the notebook's
calibration section, and lands here with its kappa. Commit a prompt change
only if category kappa did not regress versus the previous version.

| Version | Date | Change | Category kappa (linear) |
|---|---|---|---|
| v0.1.0 | 2026-07-10 | Initial system prompt from docs/LLM_JUDGE_SPEC.md section 10.1, extended with the session-kind flood rule and explicit confidence/reasoning constraints. | superseded |
| v0.2.0 | 2026-07-11 | Fix: the port_scan cheat sheet described only horizontal scans (high unique_dsts), so a vertical SYN scan (unique_dsts=1, high syn ratio - the real tcp_syn_scan.pcap) was mislabeled benign. Now covers both shapes and keys on scan_alerts firing. Added rule 8: a fired deterministic rule is high-precision and must not be overridden to benign without justification. Tightened benign_anomaly to ML-only outliers. | superseded |
| v0.3.0 | 2026-07-12 | Added two worked examples (vertical SYN scan -> port_scan; ML-only outlier -> benign_anomaly) - measured that a small local model still ignored rule 8 without them. Note: from this version the prompt is complemented by the code-level rule guardrail (judge_config.RULE_GUARDRAIL), which enforces rule 8 deterministically regardless of model quality. | pending calibration run |

## Iteration loop

1. Edit `SYSTEM_PROMPT` in `judge_core.py`.
2. Bump `PROMPT_VERSION` in `judge_config.py`.
3. Run the calibration section of `LLM_Judge_Notebook.ipynb`
   (writes `calibration/results/<version>.json`).
4. Compare kappa with the previous version's row below.
5. Commit only if kappa did not regress; add the row here.

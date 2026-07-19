# Judge Prompt Changelog

Every prompt change bumps `PROMPT_VERSION` in `judge_config.py` (which also
invalidates the verdict cache), gets a calibration run from the notebook's
calibration section, and lands here with its kappa. Commit a prompt change
only if category kappa did not regress versus the previous version.

| Version | Date | Change | Category kappa (linear) |
|---|---|---|---|
| v0.1.0 | 2026-07-10 | Initial system prompt from docs/LLM_JUDGE_SPEC.md section 10.1, extended with the session-kind flood rule and explicit confidence/reasoning constraints. | superseded |
| v0.2.0 | 2026-07-11 | Fix: the port_scan cheat sheet described only horizontal scans (high unique_dsts), so a vertical SYN scan (unique_dsts=1, high syn ratio - the real tcp_syn_scan.pcap) was mislabeled benign. Now covers both shapes and keys on scan_alerts firing. Added rule 8: a fired deterministic rule is high-precision and must not be overridden to benign without justification. Tightened benign_anomaly to ML-only outliers. | superseded |
| v0.3.0 | 2026-07-12 | Added two worked examples (vertical SYN scan -> port_scan; ML-only outlier -> benign_anomaly) - measured that a small local model still ignored rule 8 without them. Note: from this version the prompt is complemented by the code-level rule guardrail (judge_config.RULE_GUARDRAIL), which enforces rule 8 deterministically regardless of model quality. | **0.7911** |

First committed calibration: 2026-07-19, model `openai/gpt-oss-120b` (Groq),
guardrail on, 33 scored candidates, 0 dropped. category kappa (linear)
**0.7911** · unweighted 0.7925 · verdict kappa 0.7556 — well above the 0.60
CI gate. Per-PCAP category kappa: tcp_syn_scan 1.0, xmas_scan 1.0, arpspoof
0.878, synflood 1.0 (session candidate only), dns_amp 0.675. The report is
`calibration/results/v0.3.0.json`; `tests/test_judge_kappa_regression.py`
now enforces it (it skipped until this run existed).

## Iteration loop

1. Edit `SYSTEM_PROMPT` in `judge_core.py`.
2. Bump `PROMPT_VERSION` in `judge_config.py`.
3. Run the calibration section of `LLM_Judge_Notebook.ipynb`
   (writes `calibration/results/<version>.json`).
4. Compare kappa with the previous version's row below.
5. Commit only if kappa did not regress; add the row here.

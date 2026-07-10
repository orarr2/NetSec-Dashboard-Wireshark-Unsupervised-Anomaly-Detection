# Judge Prompt Changelog

Every prompt change bumps `PROMPT_VERSION` in `judge_config.py` (which also
invalidates the verdict cache), gets a calibration run from the notebook's
calibration section, and lands here with its kappa. Commit a prompt change
only if category kappa did not regress versus the previous version.

| Version | Date | Change | Category kappa (linear) |
|---|---|---|---|
| v0.1.0 | 2026-07-10 | Initial system prompt from docs/LLM_JUDGE_SPEC.md section 10.1, extended with the session-kind flood rule and explicit confidence/reasoning constraints. | pending first calibration run |

## Iteration loop

1. Edit `SYSTEM_PROMPT` in `judge_core.py`.
2. Bump `PROMPT_VERSION` in `judge_config.py`.
3. Run the calibration section of `LLM_Judge_Notebook.ipynb`
   (writes `calibration/results/<version>.json`).
4. Compare kappa with the previous version's row below.
5. Commit only if kappa did not regress; add the row here.

"""CI gate on judge calibration quality (spec section 8.4).

Reads the newest committed calibration report under
llm_judge/calibration/results/ and asserts category kappa meets the
threshold. Deliberately never calls an LLM - calibration itself is a
manual step run from the notebook's calibration section; this test only
guards against committing a prompt change without a healthy report.

Skips (does not fail) while no calibration report has been produced yet.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import judge_config  # noqa: E402
from llm_judge.calibration import latest_calibration_result  # noqa: E402


def test_judge_category_kappa_meets_threshold():
    report = latest_calibration_result()
    if report is None:
        pytest.skip("no calibration report yet - run the calibration "
                    "section of llm_judge/LLM_Judge_Notebook.ipynb first")
    kappa = report["overall"]["category_kappa_linear"]
    assert kappa is not None, "calibration report has no category kappa"
    assert kappa >= judge_config.KAPPA_THRESHOLD, (
        f"category kappa {kappa:.3f} < threshold "
        f"{judge_config.KAPPA_THRESHOLD} (prompt_version "
        f"{report['prompt_version']}, model {report['model']})")

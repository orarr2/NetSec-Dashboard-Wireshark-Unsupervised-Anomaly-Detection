"""Notebook integrity: every code cell compiles and the .py export is fresh."""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NB_PATH = os.path.join(ROOT, "app", "Network_Security_Dashboard.ipynb")


def test_all_code_cells_compile():
    nb = json.load(open(NB_PATH, encoding="utf-8"))
    errors = []
    for i, cell in enumerate(nb["cells"]):
        if cell["cell_type"] != "code":
            continue
        src = "".join(cell["source"])
        try:
            compile(src, f"cell{i}", "exec")
        except SyntaxError as e:
            errors.append(f"cell {i}: {e}")
    assert not errors, "\n".join(errors)


def test_dashboard_module_in_sync():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "export_dashboard_module.py"),
         "--check"],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_feature_extraction_contract():
    """The live worker must produce every per-IP feature column the ML layer
    consumes - a missing column crashes analysis of a live recording."""
    nb = json.load(open(NB_PATH, encoding="utf-8"))
    src = "".join("".join(c["source"]) for c in nb["cells"]
                  if c["cell_type"] == "code")
    for col in ["mean_len", "std_len", "count", "burst_score", "unique_dsts",
                "syn_count", "rst_count", "fin_count", "null_count",
                "xmas_count"]:
        assert f'"{col}"' in src or f"'{col}'" in src, f"missing feature col {col}"

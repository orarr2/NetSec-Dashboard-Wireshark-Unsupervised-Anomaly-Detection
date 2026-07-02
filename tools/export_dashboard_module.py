#!/usr/bin/env python3
"""Regenerate app/dashboard_module.py from the notebook's code cells.

The module is a plain concatenation of every code cell, in order, separated
by cell markers. It exists so tests and CLIs can import the engines without
Jupyter. It must never be edited by hand - run this tool after changing the
notebook.

Usage:
    python3 tools/export_dashboard_module.py           # regenerate
    python3 tools/export_dashboard_module.py --check   # exit 1 if stale (CI)
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NB_PATH = os.path.join(ROOT, "app", "Network_Security_Dashboard.ipynb")
MODULE_PATH = os.path.join(ROOT, "app", "dashboard_module.py")

HEADER = '''\
# =========================================================================
# AUTO-GENERATED from app/Network_Security_Dashboard.ipynb
# by tools/export_dashboard_module.py - DO NOT EDIT BY HAND.
# Regenerate with:  python3 tools/export_dashboard_module.py
#
# Importing this module executes the full notebook INCLUDING the final
# app.run() call. For tests, stub dash.Dash.run to a no-op before import.
# =========================================================================
'''


def render() -> str:
    with open(NB_PATH, encoding="utf-8") as f:
        nb = json.load(f)
    parts = [HEADER]
    for i, cell in enumerate(nb["cells"]):
        if cell["cell_type"] != "code":
            continue
        src = "".join(cell["source"]).rstrip("\n")
        if not src.strip():
            continue
        parts.append(f"\n\n# ==== notebook cell {i} ====\n\n{src}\n")
    return "".join(parts)


def main() -> int:
    rendered = render()
    if "--check" in sys.argv:
        try:
            with open(MODULE_PATH, encoding="utf-8") as f:
                current = f.read()
        except FileNotFoundError:
            print("dashboard_module.py missing - regenerate it.")
            return 1
        if current != rendered:
            print("dashboard_module.py is STALE vs the notebook.")
            print("Run: python3 tools/export_dashboard_module.py")
            return 1
        print("dashboard_module.py is in sync with the notebook.")
        return 0
    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Wrote {MODULE_PATH} ({len(rendered.splitlines()):,} lines).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

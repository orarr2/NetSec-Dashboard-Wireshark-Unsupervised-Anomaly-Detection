"""Shared test bootstrap.

attack_tests/run_pipeline.py asserts that tshark is on PATH at import
time, so on a clean shell (fresh terminal, CI image without the Wireshark
folder exported) test collection dies before a single test runs.
Importing llm_judge fixes that: its package __init__ extends this
process's PATH with the standard Wireshark install folders when tshark
does not already resolve. On systems where tshark is already on PATH (or
absent entirely) the import is a harmless no-op.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llm_judge  # noqa: F401,E402  (side effect: tshark PATH resolution)

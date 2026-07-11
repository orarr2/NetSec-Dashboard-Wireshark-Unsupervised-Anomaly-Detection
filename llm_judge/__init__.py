"""Standalone LLM-as-Judge triage layer for the NetSec Dashboard.

Optional add-on: the main dashboard runs without this package. See
llm_judge/README.md and docs/LLM_JUDGE_SPEC.md.
"""
import os as _os
import shutil as _shutil


def _ensure_tshark_on_path():
    """The detection pipeline shells out to tshark, but the Wireshark
    installer does not always add itself to PATH (and Jupyter kernels can
    inherit a minimal one). Look in the standard install locations and
    extend this process's PATH so `import run_pipeline` just works.
    No-op when tshark already resolves or Wireshark is not found."""
    if _shutil.which("tshark"):
        return
    for base in (_os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                 _os.environ.get("PROGRAMFILES(X86)",
                                 r"C:\Program Files (x86)")):
        wireshark_dir = _os.path.join(base, "Wireshark")
        if _os.path.isfile(_os.path.join(wireshark_dir, "tshark.exe")):
            _os.environ["PATH"] = (_os.environ.get("PATH", "")
                                   + _os.pathsep + wireshark_dir)
            return


_ensure_tshark_on_path()

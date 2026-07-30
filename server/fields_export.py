"""Compressed field export - the permanent historical index (IDX-04).

One field list, one exporter. The list itself lives in
tools/measure_pipeline_ratios.py (the standalone measurement tool);
importing it here keeps a single source of truth, and the stage-A test
guards that list against the dashboard's two loader field sets.
"""
import gzip
import os
import subprocess
import sys

_TOOLS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

from measure_pipeline_ratios import UNION_FIELDS, find_tshark  # noqa: E402


def export_fields(pcap_path, out_path, tshark=None):
    """Stream the union field export of pcap_path into out_path (.tsv.gz).
    Returns True on success, False when tshark is unavailable or fails -
    callers treat False as 'index not available', never as fatal."""
    tshark = tshark or find_tshark()
    if not tshark or not os.path.isfile(pcap_path):
        return False
    cmd = [tshark, "-r", pcap_path, "-n", "-T", "fields",
           "-E", "header=n", "-E", "separator=\t",
           "-E", "occurrence=f", "-E", "quote=n"]
    for f in UNION_FIELDS:
        cmd += ["-e", f]
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    tmp = out_path + ".part"
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        with gzip.open(tmp, "wb", compresslevel=6) as gz:
            for chunk in iter(lambda: proc.stdout.read(1 << 20), b""):
                gz.write(chunk)
        if proc.wait() != 0:
            raise RuntimeError(f"tshark exited {proc.returncode}")
        os.replace(tmp, out_path)
        return True
    except Exception as e:
        print(f"[fields_export] {pcap_path}: {e}", flush=True)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        return False

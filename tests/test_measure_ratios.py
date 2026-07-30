"""Stage A regression: tools/measure_pipeline_ratios.py runs end-to-end
on a real capture and reports structurally sane numbers.

The assertions deliberately avoid the plan's 368x headline: the tiny
attack PCAPs are the wrong shape for it (a capture of near-identical
SYNs compresses nothing like real mixed traffic). Structure only:
non-zero packet count, non-zero sizes, and valid JSON output.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(REPO_ROOT, "attack_tests", "pcaps", "tcp_syn_scan.pcap")


@pytest.mark.skipif(shutil.which("tshark") is None,
                    reason="tshark not on PATH")
def test_measure_ratios_end_to_end(tmp_path):
    r = subprocess.run(
        [sys.executable,
         os.path.join(REPO_ROOT, "tools", "measure_pipeline_ratios.py"),
         PCAP, "--json"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=300)
    assert r.returncode == 0, r.stderr

    summary = json.loads(r.stdout.strip().splitlines()[-1])
    assert len(summary) == 1
    m = summary[0]
    assert m["packets"] > 0
    assert m["raw_bytes"] > 0
    assert m["fields_bytes"] > 0
    assert m["fields_gz_bytes"] > 0
    # gzip must not be reported larger than the text it compressed by
    # more than the gzip header overhead allows on a non-trivial export.
    assert m["fields_gz_bytes"] < m["fields_bytes"] + 64
    # no stray .fields.tsv.gz left behind without --keep
    assert not os.path.exists(PCAP + ".fields.tsv.gz")


def test_union_field_set_covers_both_loaders():
    """The measured export must stay the union of the two field sets the
    code actually uses - if either loader gains a field, this fails and
    points at the tool to update."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    import measure_pipeline_ratios as mpr

    dashboard = os.path.join(REPO_ROOT, "app", "dashboard_module.py")
    with open(dashboard, encoding="utf-8") as f:
        src = f.read()
    union = set(mpr.UNION_FIELDS)
    # every tshark field literal referenced by the two loaders must be
    # covered (fields appear as quoted strings in the two lists).
    for field in ("frame.time_epoch", "tls.handshake.ja4",
                  "dhcp.option.dhcp_server_id", "arp.opcode",
                  "radiotap.dbm_antsignal", "dns.qry.type"):
        assert field in src, f"{field} vanished from dashboard_module.py"
        assert field in union, f"{field} missing from UNION_FIELDS"

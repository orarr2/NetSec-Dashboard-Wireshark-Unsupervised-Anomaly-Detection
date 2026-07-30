"""Stage F regression: the capture agent's per-chunk policy and BPF
generation. No tshark, no network - the uploader is injected.
"""
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from sensor.capture_agent import CaptureAgent, build_capture_filter  # noqa


# ---- capture filter (self-telemetry exclusion, spec 12.2 layer 0) --------

def test_bpf_excludes_declared_dst_with_port():
    bpf = build_capture_filter(["100.68.246.54"], upload_port=8766)
    assert bpf == "not ((host 100.68.246.54 and port 8766))"


def test_bpf_multiple_dsts_and_empty():
    bpf = build_capture_filter(["10.0.0.1", "10.0.0.2"], upload_port=443)
    assert "host 10.0.0.1 and port 443" in bpf
    assert "host 10.0.0.2 and port 443" in bpf
    assert bpf.startswith("not (") and " or " in bpf
    # nothing declared -> capture everything
    assert build_capture_filter([], upload_port=8766) == ""
    assert build_capture_filter(None) == ""


# ---- per-chunk policy ----------------------------------------------------

def _agent(tmp_path, upload_fn, **kw):
    return CaptureAgent(
        url="http://vm:8766", sensor="s", secret="sec",
        capture_dir=str(tmp_path), infra_dsts=["100.100.100.100"],
        upload_fn=upload_fn, **kw)


def _ok(*a, **k):
    return {"ok": True, "session_id": 3, "duplicate": False, "error": None,
            "status": 202}


def _fail(*a, **k):
    return {"ok": False, "session_id": None, "duplicate": False,
            "error": "link down", "status": None}


def _chunk(tmp_path, name, size=2048):
    p = tmp_path / name
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"x" * size)
    return str(p)


def test_chunk_uploaded_on_success(tmp_path):
    agent = _agent(tmp_path, _ok)
    out = agent.handle_chunk(_chunk(tmp_path, "chunk_1.pcap"))
    assert out["action"] == "uploaded" and out["session_id"] == 3
    # the ring file belongs to tshark - the agent must not remove it
    assert os.path.exists(tmp_path / "chunk_1.pcap")


def test_chunk_spooled_on_failure(tmp_path):
    agent = _agent(tmp_path, _fail)
    out = agent.handle_chunk(_chunk(tmp_path, "chunk_1.pcap"))
    assert out["action"] == "spooled"
    # spool holds a copy; the ring original is left untouched
    assert os.path.exists(os.path.join(agent.spool_dir, "chunk_1.pcap"))
    assert os.path.exists(tmp_path / "chunk_1.pcap")


def test_spool_drains_when_link_returns(tmp_path):
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        return _fail() if calls["n"] == 1 else _ok()

    agent = _agent(tmp_path, flaky)
    # first chunk fails -> spooled
    agent.handle_chunk(_chunk(tmp_path, "chunk_1.pcap"))
    assert len(os.listdir(agent.spool_dir)) == 1
    # second chunk succeeds -> its success drains the spooled one too
    out = agent.handle_chunk(_chunk(tmp_path, "chunk_2.pcap"))
    assert out["action"] == "uploaded"
    assert os.listdir(agent.spool_dir) == []


def test_spool_cap_drops_oldest_and_records_gap(tmp_path):
    agent = _agent(tmp_path, _fail, spool_cap_gb=None)
    agent.spool_cap = 5000        # tiny cap to force overflow
    for i in range(4):
        agent.handle_chunk(_chunk(tmp_path, f"chunk_{i}.pcap", size=2048))
    total = sum(os.path.getsize(os.path.join(agent.spool_dir, f))
                for f in os.listdir(agent.spool_dir))
    assert total <= agent.spool_cap
    assert os.path.exists(agent.gaps_path)
    gaps = [json.loads(x) for x in open(agent.gaps_path)]
    assert gaps and all(g["reason"] == "spool_overflow" for g in gaps)


def test_missing_chunk_is_noop(tmp_path):
    agent = _agent(tmp_path, _ok)
    assert agent.handle_chunk(str(tmp_path / "nope.pcap"))["action"] == \
        "missing"


def test_uploader_exception_is_caught_as_spool(tmp_path):
    def boom(*a, **k):
        raise RuntimeError("uploader crashed")

    agent = _agent(tmp_path, boom)
    out = agent.handle_chunk(_chunk(tmp_path, "chunk_1.pcap"))
    assert out["action"] == "spooled"
    assert "uploader crashed" in out["error"]


def test_tshark_cmd_includes_filter(tmp_path):
    agent = _agent(tmp_path, _ok)
    cmd = agent.tshark_cmd("eth0", 900, 96)
    assert "-f" in cmd
    bpf = cmd[cmd.index("-f") + 1]
    assert "host 100.100.100.100 and port 8766" in bpf
    assert "duration:900" in cmd and "files:96" in cmd

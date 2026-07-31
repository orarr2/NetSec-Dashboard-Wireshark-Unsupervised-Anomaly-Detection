"""IPv6 must reach the per-IP layer, not just IPv4.

Every tshark loader used to export ip.src/ip.dst only. Because the masks
that build the feature matrix key on ip_src being non-empty, IPv6 packets
were parsed and then dropped: the ML models, the scan and flood rules,
the device inventory and the advanced engines all analysed whatever IPv4
remnant happened to be present and reported it as the whole network.

Measured on a real 24,241-packet home capture before the fix: 98.2% of
packets were IPv6 and 21 of the 36 endpoints were invisible.

These tests build a tiny synthetic IPv6 capture with tshark's own text
format so they need no fixture file and no network.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "attack_tests"))
sys.path.insert(0, os.path.join(ROOT, "tools"))


# --------------------------------------------------------------------------
# The field lists themselves. A loader that does not request the v6 fields
# cannot possibly see v6 traffic, so assert on the declared contract.
# --------------------------------------------------------------------------
def test_cli_pipeline_requests_ipv6_fields():
    import run_pipeline as rp
    assert "ipv6.src" in rp.FIELDS and "ipv6.dst" in rp.FIELDS
    # The column list must stay aligned with the field list, or every
    # column after the insertion point silently shifts.
    assert len(rp.FIELDS) == len(rp.COLS), (
        f"{len(rp.FIELDS)} tshark fields but {len(rp.COLS)} column names")
    assert rp.COLS[rp.FIELDS.index("ipv6.src")] == "ip6_src"
    assert rp.COLS[rp.FIELDS.index("ipv6.dst")] == "ip6_dst"


def test_union_export_requests_ipv6_fields():
    """The sensor -> analyzer export feeds the same pipeline, so a
    missing field there would reintroduce the blind spot on the VM."""
    from measure_pipeline_ratios import UNION_FIELDS
    assert "ipv6.src" in UNION_FIELDS and "ipv6.dst" in UNION_FIELDS


def test_dashboard_loaders_request_ipv6_fields():
    """All three tshark loaders (dashboard fast path, advanced engines,
    live worker) must ask for the v6 fields. The advanced engines moved
    to `app/advanced_engines.py` so the field lists now live across two
    files; count occurrences in both, not the dashboard alone.
    """
    total = 0
    for rel in ("app/dashboard_module.py", "app/advanced_engines.py"):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            src = f.read()
        total += src.count('"ipv6.src"')
        assert src.count('"ipv6.src"') == src.count('"ipv6.dst"'), (
            f"{rel}: ipv6.src count != ipv6.dst count")
    assert total >= 3, (
        f"only {total} of the 3 field lists request ipv6.src")


def test_advanced_loader_columns_stay_aligned():
    """_ADV_COLS names the columns of _ADV_TSHARK_FIELDS positionally.
    The lists moved to app/advanced_engines.py in the extraction; import
    them directly (the module is Dash-free)."""
    sys.path.insert(0, os.path.join(ROOT, "app"))
    import advanced_engines as ae
    assert len(ae._ADV_TSHARK_FIELDS) == len(ae._ADV_COLS), (
        f"{len(ae._ADV_TSHARK_FIELDS)} fields vs "
        f"{len(ae._ADV_COLS)} column names - they must move together")
    i = ae._ADV_TSHARK_FIELDS.index("ipv6.src")
    assert ae._ADV_COLS[i] == "ip6_src"


# --------------------------------------------------------------------------
# The coalesce itself, exercised through the real parser.
# --------------------------------------------------------------------------
def _tshark_text(rows):
    """Render rows in the pipe-separated shape run_pipeline expects."""
    return "\n".join("|".join(r) for r in rows) + "\n"


def _parse_with_cli_pipeline(raw, monkeypatch):
    """Drive run_pipeline.analyze_pcap with canned tshark output."""
    import run_pipeline as rp
    monkeypatch.setattr(rp.subprocess, "check_output",
                        lambda *a, **kw: raw)
    return rp.analyze_pcap("fake.pcap", "S1")


def _row(ts, length, eth, v4s, v4d, v6s, v6d, proto="TCP"):
    import run_pipeline as rp
    cells = {"ts": ts, "len": length, "eth_src": eth, "eth_dst": "",
             "ip_src": v4s, "ip_dst": v4d, "ip6_src": v6s, "ip6_dst": v6d,
             "proto": proto}
    return [str(cells.get(c, "")) for c in rp.COLS]


def test_ipv6_only_capture_produces_a_feature_matrix(monkeypatch, capsys):
    """The regression that mattered: a capture with no IPv4 at all used
    to yield an empty ip_agg, so every detector saw nothing."""
    rows = [
        _row(1700000000 + i, 500, "aa:bb:cc:dd:ee:01", "", "",
             "2001:db8::1", "2001:db8::2")
        for i in range(10)
    ]
    S = _parse_with_cli_pipeline(_tshark_text(rows), monkeypatch)
    capsys.readouterr()
    assert S["n_pkts"] == 10
    assert "2001:db8::1" in S["ips_src"]
    assert len(S["ip_agg"]) == 1, "IPv6-only traffic produced no ML rows"
    assert int(S["ip_agg"].loc["2001:db8::1", "count"]) == 10
    assert S["ip_agg"].loc["2001:db8::1", "unique_dsts"] == 1


def test_mixed_capture_counts_both_families(monkeypatch, capsys):
    rows = [_row(1700000000, 100, "aa:bb:cc:dd:ee:01",
                 "192.168.1.10", "192.168.1.1", "", "")]
    rows += [_row(1700000001 + i, 200, "aa:bb:cc:dd:ee:02", "", "",
                  "fd00::a", "fd00::b") for i in range(3)]
    S = _parse_with_cli_pipeline(_tshark_text(rows), monkeypatch)
    capsys.readouterr()
    agg = S["ip_agg"]
    assert set(agg.index) == {"192.168.1.10", "fd00::a"}
    assert int(agg.loc["192.168.1.10", "count"]) == 1
    assert int(agg.loc["fd00::a", "count"]) == 3


def test_ipv4_takes_precedence_when_both_are_present(monkeypatch, capsys):
    """A row carrying both (tunnelled or malformed) keeps its v4 identity
    rather than being silently rewritten to the v6 address."""
    rows = [_row(1700000000, 100, "aa:bb:cc:dd:ee:01",
                 "10.0.0.5", "10.0.0.6", "2001:db8::9", "2001:db8::a")]
    S = _parse_with_cli_pipeline(_tshark_text(rows), monkeypatch)
    capsys.readouterr()
    assert list(S["ip_agg"].index) == ["10.0.0.5"]


def test_ipv6_traffic_reaches_the_tcp_flag_counters(monkeypatch, capsys):
    """Scan and flood rules read the flag counters, which are keyed by
    ip_src - so they only work for v6 once the coalesce has run."""
    import run_pipeline as rp
    rows = []
    for i in range(60):
        cells = dict(zip(rp.COLS, [""] * len(rp.COLS)))
        cells.update(ts=str(1700000000 + i), len="60",
                     eth_src="aa:bb:cc:dd:ee:03",
                     ip6_src="2001:db8::66", ip6_dst="2001:db8::99",
                     proto="TCP", tcp_flags="0x0002")
        rows.append([cells[c] for c in rp.COLS])
    S = _parse_with_cli_pipeline(_tshark_text(rows), monkeypatch)
    capsys.readouterr()
    assert S["syn_counter"]["2001:db8::66"] == 60
    assert int(S["ip_agg"].loc["2001:db8::66", "syn_count"]) == 60

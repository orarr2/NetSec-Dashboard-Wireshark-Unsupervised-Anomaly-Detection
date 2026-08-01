"""Advanced threat detection engines - MITRE ATT&CK aligned, Dash-free.

Six detectors (ARP/rogue-DHCP, DNS tunnelling, DGA, beaconing, TLS
anomalies, and the kill-chain fusion over all five) that re-parse a PCAP
with a wider tshark field set than the dashboard's fast loader: TLS
SNI/JA3/JA4, DHCP server-id, ARP opcode, DNS rcode.

This module holds the detection logic ONLY. It imports no Dash, no
plotly and no notebook state, so every consumer runs the same code:

    app/Network_Security_Dashboard.ipynb   the dashboard (SECURITY views)
    attack_tests/run_pipeline.py           the CLI / VM worker pipeline
    tools/measure_adv_engines.py           the FP/TP measurement harness

Before the extraction these ~440 lines lived inside notebook cell 47,
which meant importing them also started the Dash server - so the CLI and
the VM worker judged without any advanced signal at all. Anything that
renders the findings (cards, tables, colours) stays in the notebook;
this module returns plain dicts and DataFrames.

All identifiers keep their historical `_adv_` / `ADV_` prefixes so the
notebook's own names cannot collide with them (the dashboard has its own
`is_private` heuristic, for a different feature).
"""
import collections as _adv_collections
import io as _adv_io
import ipaddress as _adv_ipaddress
import json as _adv_json
import math as _math
import os as _adv_os
import re as _adv_re
import shutil as _adv_shutil
import subprocess as _adv_subprocess

import numpy as _adv_np
import pandas as _adv_pd

# ---- Thresholds (tune for your environment) ----
ADV_BEACON_MIN_EVENTS  = 16
ADV_BEACON_SCORE_FLAG  = 0.80
ADV_DNS_UNIQUE_MIN     = 20
ADV_DNS_UNIQUE_RATIO   = 0.90
ADV_DNS_ENTROPY_FLAG   = 3.8
ADV_DNS_LABEL_LEN_FLAG = 40
ADV_NX_STORM_MIN       = 30
ADV_DGA_MIN_LABEL_LEN  = 7
ADV_DGA_LOGPROB_FLAG   = None
ADV_FUSION_WINDOW_MIN  = 15

_ADV_RFC1918 = [_adv_ipaddress.ip_network(n) for n in
                ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]

_ADV_HERE = _adv_os.path.dirname(_adv_os.path.abspath(__file__))


def _adv_find_tshark():
    """Locate tshark on the host - same search order as the dashboard."""
    cand = _adv_shutil.which("tshark")
    if cand: return cand
    for p in ["/usr/bin/tshark", "/usr/local/bin/tshark",
              "/Applications/Wireshark.app/Contents/MacOS/tshark",
              r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if _adv_os.path.exists(p):
            return p
    return None


def _adv_find_config(name):
    """Resolve a JSON config shipped next to this module.

    Anchored on the module's own directory rather than the process cwd,
    so a caller in attack_tests/ or server/ resolves it the same way the
    dashboard does. NETSEC_APP_DIR overrides for unusual layouts.
    """
    override = _adv_os.environ.get("NETSEC_APP_DIR", "").strip()
    for d in ([override] if override else []) + [_ADV_HERE,
              _adv_os.path.join(_ADV_HERE, "app"),
              _adv_os.path.join(_adv_os.path.dirname(_ADV_HERE), "app")]:
        cand = _adv_os.path.join(d, name)
        if _adv_os.path.exists(cand):
            return cand
    return None


def _adv_is_private(ip):
    if not ip: return False
    try: a = _adv_ipaddress.ip_address(ip)
    except Exception: return False
    return a.is_private or a.is_link_local or a.is_loopback or a.is_multicast or a.is_unspecified

# ---- Tshark loader (wider field set than the main dashboard) ----
_ADV_TSHARK_FIELDS = [
    "frame.time_epoch", "frame.len",
    "eth.src", "eth.dst",
    "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst",
    "_ws.col.Protocol",
    "tcp.srcport", "tcp.dstport", "tcp.flags",
    "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.flags.response",
    "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4",
    "tls.handshake.extensions_server_name", "tls.handshake.ja3", "tls.handshake.ja4",
    "dhcp.option.dhcp_server_id",
]
_ADV_COLS = [
    "ts", "len", "eth_src", "eth_dst", "ip_src", "ip_dst",
    "ip6_src", "ip6_dst", "proto",
    "tcp_sport", "tcp_dport", "tcp_flags", "udp_sport", "udp_dport",
    "dns_qname", "dns_qtype", "dns_rcode", "dns_response",
    "arp_opcode", "arp_psrc", "arp_hwsrc", "arp_pdst",
    "tls_sni", "tls_ja3", "tls_ja4", "dhcp_sid",
]

def _adv_load_pk(pcap_path, label, tshark_path=None):
    tsh = tshark_path if tshark_path is not None else _adv_find_tshark()
    if not tsh: return None
    cmd = [tsh, "-r", str(pcap_path), "-n", "-T", "fields",
           "-E", "header=n", "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]
    for f in _ADV_TSHARK_FIELDS: cmd += ["-e", f]
    raw = _adv_subprocess.check_output(cmd, encoding="utf-8", errors="replace",
                                       stderr=_adv_subprocess.DEVNULL)
    df = _adv_pd.read_csv(_adv_io.StringIO(raw), sep="\t", header=None,
                          names=_ADV_COLS, dtype=str, na_filter=False, low_memory=False)
    if not len(df): return df
    df["ts"]  = _adv_pd.to_numeric(df["ts"],  errors="coerce")
    df["len"] = _adv_pd.to_numeric(df["len"], errors="coerce").fillna(0).astype(int)
    df = df.dropna(subset=["ts"]).reset_index(drop=True)
    # Same coalesce as the fast loader: the beaconing, DGA and TLS
    # engines all group by ip_src/ip_dst, so without this they would only
    # ever see the IPv4 slice of the capture.
    _m = (df["ip_src"] == "") & (df["ip6_src"] != "")
    df.loc[_m, "ip_src"] = df.loc[_m, "ip6_src"]
    _m = (df["ip_dst"] == "") & (df["ip6_dst"] != "")
    df.loc[_m, "ip_dst"] = df.loc[_m, "ip6_dst"]
    df["session"] = label
    df["dns_response"] = df["dns_response"].astype(str).map(
        lambda v: "1" if v in ("1", "True", "true") else
                  ("0" if v in ("0", "False", "false", "") else v))
    return df

# ---- Helpers (signal schema, info-theoretic scores, bigram model) ----
_ADV_SIGNAL_COLS = ["device","peer","signal","tactic","technique","score","severity",
                    "count","first_ts","last_ts","detail"]
def _adv_sig(**kw):
    return {k: kw.get(k) for k in _ADV_SIGNAL_COLS}

def _adv_shannon(s):
    if not s: return 0.0
    n = len(s)
    return -sum((c/n)*_math.log2(c/n) for c in _adv_collections.Counter(s).values())

def _adv_vowel_ratio(s):
    s = s.lower()
    return (sum(c in "aeiou" for c in s)/len(s)) if s else 0.0

_ADV_MULTI_SLD = {"co.uk","org.uk","ac.uk","gov.uk","co.il","org.il","ac.il","net.il","gov.il",
                  "com.au","net.au","org.au","co.jp","com.br","co.in","com.cn","co.kr","co.za"}
def _adv_registrable(name):
    name = (name or "").strip(".").lower()
    parts = name.split(".")
    if len(parts) < 2: return name
    if ".".join(parts[-2:]) in _ADV_MULTI_SLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
def _adv_leftmost_label(name):
    name = (name or "").strip(".")
    return name.split(".")[0] if name else ""

_ADV_BG_VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-_."
def _adv_train_bigram(labels):
    cnt = _adv_collections.defaultdict(lambda: _adv_collections.defaultdict(int))
    for lab in labels:
        t = "^" + (lab or "").lower() + "$"
        for a, b in zip(t, t[1:]):
            cnt[a][b] += 1
    V = len(_ADV_BG_VOCAB) + 2
    model = {}
    for a, nxt in cnt.items():
        tot = sum(nxt.values()) + V
        row = {b: _math.log((c+1)/tot) for b, c in nxt.items()}
        row["__default__"] = _math.log(1/tot)
        model[a] = row
    model["__global_default__"] = _math.log(1.0/V)
    return model
def _adv_score_label(model, lab):
    t = "^" + (lab or "").lower() + "$"; lp = 0.0; n = 0
    for a, b in zip(t, t[1:]):
        row = model.get(a)
        lp += (model["__global_default__"] if row is None else row.get(b, row["__default__"]))
        n += 1
    return lp/max(n, 1)

_ADV_COMMON_DOMAINS = ["google","youtube","facebook","amazon","microsoft","apple","netflix",
    "instagram","whatsapp","wikipedia","linkedin","github","cloudflare","akamai","fastly",
    "office","windowsupdate","icloud","gmail","outlook","spotify","twitch","reddit","yahoo",
    "bing","dropbox","adobe","zoom","slack","tiktok","snapchat","pinterest","ebay","paypal",
    "samsung","intel","nvidia","mozilla","ubuntu","debian","android","googleapis","gstatic",
    "doubleclick","cdn","edgekey","edgesuite","amazonaws","azure","digitalocean"]

def _adv_beacon_scores(ts, sizes):
    ts = _adv_np.sort(_adv_np.asarray(ts, dtype=float))
    if len(ts) < 3: return None
    d = _adv_np.diff(ts); d = d[d >= 0]
    if len(d) < 2: return None
    q1, q2, q3 = _adv_np.percentile(d, [25, 50, 75])
    iqr = q3 - q1
    skew = 1.0 if iqr == 0 else max(0.0, 1 - abs((q3 + q1 - 2*q2)/iqr))
    mad  = _adv_np.median(_adv_np.abs(d - q2))
    disp = 1.0 if q2 == 0 else max(0.0, 1 - min(mad/q2, 1))
    s = _adv_np.asarray(sizes, dtype=float)
    smed = _adv_np.median(s); smad = _adv_np.median(_adv_np.abs(s - smed))
    size = 1.0 if smed == 0 else max(0.0, 1 - min(smad/smed, 1))
    return dict(score=(skew+disp+size)/3, median_interval=float(q2),
                n=int(len(ts)), skew=skew, disp=disp, size=size)

def _adv_max_distinct_in_window(times, keys, window_s):
    if len(times) == 0: return 0
    order = _adv_np.argsort(times); t = _adv_np.asarray(times)[order]; k = _adv_np.asarray(keys)[order]
    cnt = _adv_collections.defaultdict(int); distinct = 0; best = 0; left = 0
    for right in range(len(t)):
        if cnt[k[right]] == 0: distinct += 1
        cnt[k[right]] += 1
        while t[right] - t[left] > window_s:
            cnt[k[left]] -= 1
            if cnt[k[left]] == 0: distinct -= 1
            left += 1
        best = max(best, distinct)
    return best

class _AdvCloudDB:
    def __init__(self, path):
        self.static = {}; self.cidrs = []; self.rdns = []; self.ok = False; self.err = None
        try:
            d = _adv_json.load(open(path, encoding="utf-8"))
            self.static = d.get("static_ips", {}) or {}
            for e in d.get("cidr_ranges", []):
                try: self.cidrs.append((_adv_ipaddress.ip_network(e["cidr"]), e))
                except Exception: pass
            for e in d.get("rdns_patterns", []):
                try: self.rdns.append((_adv_re.compile(e["pattern"]), e))
                except Exception: pass
            self.ok = True
        except Exception as ex:
            self.err = str(ex)
    def by_ip(self, ip):
        e = self.static.get(ip)
        if e: return e.get("provider")
        try: a = _adv_ipaddress.ip_address(ip)
        except Exception: return None
        for net, e in self.cidrs:
            if a in net: return e.get("provider")
        return None
    def by_host(self, host):
        for rx, e in self.rdns:
            if rx.search(host or ""): return e.get("provider")
        return None

# ---- The six engines ----
def _adv_detect_arp_dhcp(PK):
    rows = []
    if not len(PK): return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    arp = PK[PK["arp_hwsrc"] != ""]
    bad_mac = {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
    if len(arp):
        a = arp[arp["arp_psrc"] != ""]
        # SCIENTIFIC_AUDIT 3.5 - "multi-MAC on IP" alone is not enough to
        # flag ARP spoofing: a phone reassociating, a NAT restart, or a
        # DHCP lease turnover during capture all satisfy it. The actual
        # spoofing signature is a gratuitous reply (opcode 2 without a
        # preceding opcode 1 from a peer). We now require both:
        #   n_macs > 1 AND at least one MAC issued a gratuitous reply
        # If only the multi-MAC part is present, we still emit a signal
        # but with a lower score (0.5, "possible" tier) and mark low
        # severity so the guardrail does not escalate.
        mac_gratuitous = set()
        for _mac, _grp in arp.groupby("arp_hwsrc"):
            if _mac in bad_mac:
                continue
            _reps = int((_grp["arp_opcode"] == "2").sum())
            _reqs = int((_grp["arp_opcode"] == "1").sum())
            if _reps > 0 and _reps > _reqs:
                mac_gratuitous.add(_mac)
        for ip, grp in a.groupby("arp_psrc"):
            macs = {m for m in grp["arp_hwsrc"].unique() if m not in bad_mac}
            if ip in ("0.0.0.0", "") or len(macs) <= 1: continue
            gratuitous_seen = bool(macs & mac_gratuitous)
            if gratuitous_seen:
                score = min(1.0, 0.6 + 0.15 * len(macs))
                severity = "high"
                detail_suffix = " + gratuitous reply signature"
            else:
                score = 0.5
                severity = "low"
                detail_suffix = " (no gratuitous reply - could be DHCP churn/NAT restart)"
            rows.append(_adv_sig(device=ip, peer=";".join(sorted(macs)),
                signal="arp_ip_multi_mac", tactic="Collection / MITM",
                technique="T1557.002", score=score,
                severity=severity, count=len(grp),
                first_ts=grp["ts"].min(), last_ts=grp["ts"].max(),
                detail=f"IP {ip} claimed by {len(macs)} MACs: {sorted(macs)}"
                       f"{detail_suffix}"))
        for mac, grp in a.groupby("arp_hwsrc"):
            if mac in bad_mac: continue
            ips = {i for i in grp["arp_psrc"].unique() if i not in ("0.0.0.0", "")}
            if len(ips) < 4: continue
            rows.append(_adv_sig(device=mac, peer=";".join(sorted(ips)[:8]),
                signal="arp_mac_many_ips", tactic="Collection / MITM",
                technique="T1557.002", score=min(1.0, 0.5 + 0.08*len(ips)),
                severity="high", count=len(grp),
                first_ts=grp["ts"].min(), last_ts=grp["ts"].max(),
                detail=f"MAC {mac} announced {len(ips)} distinct IPs"))
        rep = arp[arp["arp_opcode"] == "2"]; req = arp[arp["arp_opcode"] == "1"]
        rc = rep.groupby("arp_hwsrc").size(); qc = req.groupby("arp_hwsrc").size()
        for mac, n in rc.items():
            if mac in bad_mac: continue
            q = int(qc.get(mac, 0))
            if n >= 10 and n > 3*max(q, 1):
                sub = rep[rep["arp_hwsrc"] == mac]
                rows.append(_adv_sig(device=mac, peer="", signal="arp_gratuitous_flood",
                    tactic="Collection / MITM", technique="T1557.002",
                    score=min(1.0, 0.4 + n/120.0), severity="medium", count=int(n),
                    first_ts=sub["ts"].min(), last_ts=sub["ts"].max(),
                    detail=f"{n} ARP replies vs {q} requests (unsolicited)"))
    srv = [s for s in PK["dhcp_sid"].unique() if s] if "dhcp_sid" in PK.columns else []
    if len(srv) > 1:
        for s in srv:
            sub = PK[PK["dhcp_sid"] == s]
            rows.append(_adv_sig(device=s, peer=";".join(srv), signal="rogue_dhcp",
                tactic="Collection / MITM", technique="T1557",
                score=0.7, severity="high", count=len(sub),
                first_ts=sub["ts"].min(), last_ts=sub["ts"].max(),
                detail=f"{len(srv)} DHCP servers offering leases: {srv}"))
    return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)

def _adv_detect_dns_tunnel(PK):
    rows = []
    if not len(PK) or "dns_qname" not in PK.columns:
        return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    q = PK[(PK["dns_qname"] != "") & (PK["dns_response"] != "1")].copy()
    if len(q):
        q["reg"]  = q["dns_qname"].map(_adv_registrable)
        q["lbl"]  = q["dns_qname"].map(_adv_leftmost_label)
        q["ent"]  = q["lbl"].map(_adv_shannon)
        q["qlen"] = q["dns_qname"].str.len()
        for reg, g in q.groupby("reg"):
            if not reg: continue
            total = len(g); uniq = g["dns_qname"].nunique(); ratio = uniq/max(total, 1)
            max_ent = float(g["ent"].max()); mean_len = float(g["qlen"].mean())
            if uniq >= ADV_DNS_UNIQUE_MIN and ratio >= ADV_DNS_UNIQUE_RATIO and \
               (max_ent >= ADV_DNS_ENTROPY_FLAG or mean_len >= ADV_DNS_LABEL_LEN_FLAG):
                asker = g["ip_src"].value_counts()
                dev = asker.index[0] if len(asker) else ""
                score = min(1.0, 0.4 + 0.3*(max_ent/4.5) + 0.3*min(uniq/200.0, 1))
                rows.append(_adv_sig(device=dev, peer=reg, signal="dns_tunneling",
                    tactic="Exfiltration / C2", technique="T1071.004",
                    score=score, severity="high", count=int(uniq),
                    first_ts=g["ts"].min(), last_ts=g["ts"].max(),
                    detail=f"{uniq} unique subdomains under {reg} (uniq_ratio={ratio:.2f}, max_entropy={max_ent:.2f}, mean_len={mean_len:.0f})"))
    r = PK[(PK["dns_qname"] != "") & (PK["dns_response"] == "1") & (PK["dns_rcode"] == "3")]
    if len(r):
        for dev, g in r.groupby("ip_dst"):
            if dev == "" or len(g) < ADV_NX_STORM_MIN: continue
            rows.append(_adv_sig(device=dev, peer="", signal="nxdomain_storm",
                tactic="Command and Control", technique="T1568.002",
                score=min(1.0, 0.3 + len(g)/300.0), severity="medium", count=len(g),
                first_ts=g["ts"].min(), last_ts=g["ts"].max(),
                detail=f"{len(g)} NXDOMAIN responses (failed lookups - DGA/tunnel symptom)"))
    return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)

def _adv_detect_dga(PK):
    rows = []
    if not len(PK) or "dns_qname" not in PK.columns:
        return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    q = PK[(PK["dns_qname"] != "") & (PK["dns_response"] != "1")]
    if not len(q): return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    resolved = PK[(PK["dns_response"] == "1") & (PK["dns_rcode"] == "0") & (PK["dns_qname"] != "")]
    base = [_adv_registrable(x).split(".")[0] for x in resolved["dns_qname"].unique()]
    base = [b for b in base if b and len(b) >= 3]
    if len(set(base)) < 30:
        base = base + _ADV_COMMON_DOMAINS
    model = _adv_train_bigram(base)
    labels = {_adv_registrable(x).split(".")[0] for x in q["dns_qname"].unique()}
    scored = [(lab, _adv_score_label(model, lab), _adv_shannon(lab), _adv_vowel_ratio(lab))
              for lab in labels if lab and len(lab) >= ADV_DGA_MIN_LABEL_LEN]
    if not scored: return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    arr = _adv_np.array([s[1] for s in scored], dtype=float)
    thr = ADV_DGA_LOGPROB_FLAG if ADV_DGA_LOGPROB_FLAG is not None else float(arr.mean() - arr.std())
    # SCIENTIFIC_AUDIT 3.3: anchor the adaptive threshold to a
    # capture-independent baseline (5th percentile of _ADV_COMMON_DOMAINS'
    # log-probs). Prevents "16% of a normal capture is 'unusually random'
    # by construction" - the adaptive threshold on the capture's own
    # domains can drift arbitrarily on small captures.
    if ADV_DGA_LOGPROB_FLAG is None:
        baseline_scored = [_adv_score_label(model, w) for w in _ADV_COMMON_DOMAINS
                           if w and len(w) >= 3]
        if baseline_scored:
            _baseline_arr = _adv_np.array(baseline_scored, dtype=float)
            _baseline_thr = float(_adv_np.percentile(_baseline_arr, 5))
            thr = min(thr, _baseline_thr)
    qreg = q.assign(_lab=q["dns_qname"].map(lambda x: _adv_registrable(x).split(".")[0]))
    for lab, lp, ent, vw in scored:
        # SCIENTIFIC_AUDIT 3.3: require BOTH high entropy AND low vowel
        # ratio (was OR). Also raise the entropy floor to 3.6 (was 3.2).
        # A "random-looking" label needs to look random on both axes.
        if lp < thr and ent >= 3.6 and vw < 0.25:
            full = qreg[qreg["_lab"] == lab]
            asker = full["ip_src"].value_counts()
            dev = asker.index[0] if len(asker) else ""
            score = min(1.0, 0.4 + min(thr-lp, 3.0)/6.0 + (0.2 if vw < 0.25 else 0.0))
            rows.append(_adv_sig(device=dev, peer=lab, signal="dga_domain",
                tactic="Command and Control", technique="T1568.002",
                score=score, severity="medium", count=int(full["dns_qname"].nunique()),
                first_ts=full["ts"].min(), last_ts=full["ts"].max(),
                detail=f"label '{lab}' logprob={lp:.2f} (thr={thr:.2f}), entropy={ent:.2f}, vowel_ratio={vw:.2f}"))
    return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)

def _adv_detect_beaconing(PK):
    rows = []
    if not len(PK): return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    df = PK[(PK["ip_src"] != "") & (PK["ip_dst"] != "")]
    _is_tcp_start = (df["proto"] == "TCP") & df["tcp_flags"].astype(str).isin(
        ["0x02", "0x0002", "0x00000002", "2"])
    _is_udp = df["proto"] == "UDP"
    df = df[_is_tcp_start | _is_udp]
    for (src, dst), g in df.groupby(["ip_src", "ip_dst"]):
        if len(g) < ADV_BEACON_MIN_EVENTS: continue
        if not _adv_is_private(src) or _adv_is_private(dst): continue
        dports = set(g["tcp_dport"]) | set(g["udp_dport"])
        if "123" in dports: continue
        r = _adv_beacon_scores(g["ts"].values, g["len"].values)
        if not r or r["median_interval"] < 1: continue
        if r["score"] >= ADV_BEACON_SCORE_FLAG:
            rows.append(_adv_sig(device=src, peer=dst, signal="beaconing",
                tactic="Command and Control", technique="T1071",
                score=r["score"], severity=("high" if r["score"] >= 0.9 else "medium"),
                count=r["n"], first_ts=g["ts"].min(), last_ts=g["ts"].max(),
                detail=f"{r['n']} conns, median interval {r['median_interval']:.1f}s, regularity {r['score']:.2f} (skew {r['skew']:.2f} / disp {r['disp']:.2f} / size {r['size']:.2f})"))
    return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)

def _adv_detect_tls(PK, cloud=None):
    rows = []
    if not len(PK) or "tls_ja3" not in PK.columns:
        return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)
    tls = PK[PK["tls_ja3"] != ""]
    if len(tls):
        ndev = tls.groupby("tls_ja3")["ip_src"].nunique()
        ncnt = tls.groupby("tls_ja3").size()
        for ja3, nd in ndev.items():
            # SCIENTIFIC_AUDIT 3.4: tighten from "<=3 handshakes on one
            # device" to "exactly 1 handshake AND peer is external".
            # Short captures where a single browser sees one JA3 aren't
            # suspicious; a lone rare handshake to a public IP is.
            if nd == 1 and int(ncnt[ja3]) == 1:
                sub = tls[tls["tls_ja3"] == ja3]; dev = sub["ip_src"].iloc[0]
                # peer must be a non-private IP to fire the alert
                external_dsts = [d for d in sub["ip_dst"].unique()
                                 if d and not _adv_is_private(d)]
                if not external_dsts:
                    continue
                rows.append(_adv_sig(device=dev, peer=ja3[:16], signal="rare_ja3",
                    tactic="Command and Control", technique="T1071.001",
                    score=0.5, severity="low", count=int(ncnt[ja3]),
                    first_ts=sub["ts"].min(), last_ts=sub["ts"].max(),
                    detail=f"JA3 {ja3} seen once on {dev} to external "
                           f"{external_dsts[0]} (new/unusual client)"))
    hs = PK[(PK["tls_ja3"] != "") | (PK["tls_sni"] != "")]
    nosni = hs[(hs["tls_sni"] == "") & (hs["ip_dst"] != "")]
    nosni = nosni[~nosni["ip_dst"].map(_adv_is_private)]
    if len(nosni):
        for dev, g in nosni.groupby("ip_src"):
            if dev == "": continue
            rows.append(_adv_sig(device=dev, peer=";".join(sorted(g["ip_dst"].unique())[:5]),
                signal="tls_no_sni_external", tactic="Command and Control", technique="T1071.001",
                score=0.45, severity="low", count=len(g),
                first_ts=g["ts"].min(), last_ts=g["ts"].max(),
                detail=f"{len(g)} TLS handshakes to external IPs without SNI"))
    if cloud and cloud.ok:
        m = PK[(PK["tls_sni"] != "") & (PK["ip_dst"] != "")]
        m = m[~m["ip_dst"].map(_adv_is_private)].drop_duplicates(["ip_src","ip_dst","tls_sni"])
        for _, r in m.iterrows():
            ps = cloud.by_host(r["tls_sni"]); pi = cloud.by_ip(r["ip_dst"])
            if ps and pi and ps != pi:
                rows.append(_adv_sig(device=r["ip_src"], peer=r["tls_sni"],
                    signal="sni_ip_mismatch", tactic="Command and Control", technique="T1090",
                    score=0.6, severity="medium", count=1,
                    first_ts=r["ts"], last_ts=r["ts"],
                    detail=f"SNI {r['tls_sni']} -> {ps}, but dst {r['ip_dst']} -> {pi} (possible domain fronting)"))
    return _adv_pd.DataFrame(rows, columns=_ADV_SIGNAL_COLS)

def _adv_fuse(signals):
    cols = ["device","signals","signal_types","max_score","kill_chain_boost",
            "risk","techniques","detail"]
    if not len(signals):
        return signals, _adv_pd.DataFrame(columns=cols)
    s = signals.copy()
    s["first_ts"] = _adv_pd.to_numeric(s["first_ts"], errors="coerce")
    win = ADV_FUSION_WINDOW_MIN*60
    out = []
    for dev, g in s.groupby("device"):
        base = float(g["score"].max())
        t = g["first_ts"].dropna().values
        best = _adv_max_distinct_in_window(t,
            g.loc[g["first_ts"].notna(), "technique"].values, win) if len(t) else 1
        boost = 1.0 + 0.5*max(best-1, 0)
        out.append(dict(device=dev, signals=len(g), signal_types=int(g["signal"].nunique()),
            max_score=round(base, 3), kill_chain_boost=round(boost, 2),
            risk=round(min(1.0, base*boost), 3),
            techniques=";".join(sorted(g["technique"].dropna().unique())),
            detail="; ".join(list(dict.fromkeys(g["signal"]))[:6])))
    dev = _adv_pd.DataFrame(out).sort_values("risk", ascending=False).reset_index(drop=True)
    return s, dev

# ---- Public entry point: re-parse pcap, run all 6 detectors, return findings ----
def run_advanced_threats(pcap_path, label, tshark_path=None,
                         cloud_ranges_path=None):
    """Run the 6 MITRE-mapped detectors on a single pcap and return a dict
    with all signals + per-device kill-chain fusion. Safe: returns
    {"available": False, "reason": "..."} on any failure.

    tshark_path and cloud_ranges_path let a caller that already resolved
    them (the dashboard) pass its own values; both are auto-discovered
    when omitted, which is what the CLI and the VM worker rely on."""
    try:
        PK = _adv_load_pk(pcap_path, label, tshark_path=tshark_path)
        if PK is None or len(PK) == 0:
            return {"available": False, "reason": "pcap empty or tshark missing"}
        cloud_path = cloud_ranges_path if cloud_ranges_path is not None \
            else _adv_find_config("cloud_ranges.json")
        cloud = _AdvCloudDB(cloud_path) if cloud_path else None
        per_engine = {
            "arp_dhcp":   _adv_detect_arp_dhcp(PK),
            "dns_tunnel": _adv_detect_dns_tunnel(PK),
            "dga":        _adv_detect_dga(PK),
            "beaconing":  _adv_detect_beaconing(PK),
            "tls":        _adv_detect_tls(PK, cloud),
        }
        all_signals = _adv_pd.concat(list(per_engine.values()), ignore_index=True)
        signals_fused, device_risk = _adv_fuse(all_signals)
        return {
            "available": True,
            "n_packets":  int(len(PK)),
            "per_engine": {k: v.to_dict("records") for k, v in per_engine.items()},
            "all_signals": signals_fused.to_dict("records") if len(signals_fused) else [],
            "device_risk": device_risk.to_dict("records"),
        }
    except Exception as e:
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}

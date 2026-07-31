#!/usr/bin/env python3
"""Run the dashboard's PCAP analysis pipeline against arbitrary captures.

Lifts cells 8 (feature extraction), 12 (IsolationForest + DBSCAN), 16
(security rules) and 22-26 (LSTM) out of the dashboard notebook into a
single CLI. Same code paths as the dashboard, no Dash UI.

usage: run_pipeline.py <S1.pcap> <S2.pcap>
"""
import sys, os, re, io, math, json, shutil, collections, subprocess, ipaddress, tempfile
from datetime import datetime

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import silhouette_score

TSHARK = shutil.which("tshark")
assert TSHARK, "tshark not found on PATH"

FIELDS = [
    "frame.time_epoch", "frame.len",
    "eth.src", "eth.dst",
    "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst",
    "_ws.col.Protocol",
    "tcp.srcport", "tcp.dstport", "tcp.flags",
    "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.flags.rcode", "dns.flags.response",
    "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.opcode",
]
COLS = ["ts","len","eth_src","eth_dst","ip_src","ip_dst",
        "ip6_src","ip6_dst","proto",
        "tcp_sport","tcp_dport","tcp_flags","udp_sport","udp_dport",
        "dns_qname","dns_rcode","dns_response",
        "arp_psrc","arp_hwsrc","arp_opcode"]


sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))
from advanced_engines import run_advanced_threats          # noqa: E402


def analyze_pcap(path, label):
    cmd = [TSHARK, "-r", str(path), "-n", "-T", "fields",
           "-E", "header=n", "-E", "separator=|",
           "-E", "occurrence=f", "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]
    raw = subprocess.check_output(cmd, encoding="utf-8", errors="replace",
                                  stderr=subprocess.DEVNULL)
    df = pd.read_csv(io.StringIO(raw), sep="|", header=None, names=COLS,
                     dtype=str, na_filter=False, low_memory=False)
    df["ts"]  = pd.to_numeric(df["ts"], errors="coerce")
    df["len"] = pd.to_numeric(df["len"], errors="coerce").fillna(0).astype(int)
    df = df.dropna(subset=["ts"])
    # Fold IPv6 into the v4 columns so the per-IP layer sees the whole
    # capture; on a modern network most of it is v6.
    _m = (df["ip_src"] == "") & (df["ip6_src"] != "")
    df.loc[_m, "ip_src"] = df.loc[_m, "ip6_src"]
    _m = (df["ip_dst"] == "") & (df["ip6_dst"] != "")
    df.loc[_m, "ip_dst"] = df.loc[_m, "ip6_dst"]
    t0 = datetime.fromtimestamp(df["ts"].min())
    t1 = datetime.fromtimestamp(df["ts"].max())

    ips_src   = collections.Counter(df[df["ip_src"] != ""]["ip_src"].tolist())
    macs      = collections.Counter(df[df["eth_src"] != ""]["eth_src"].tolist())
    protocols = collections.Counter(df[df["proto"] != ""]["proto"].tolist())
    bs = df[df["ip_src"] != ""].groupby("ip_src")["len"].sum()
    bd = df[df["ip_dst"] != ""].groupby("ip_dst")["len"].sum()
    bytes_src = collections.Counter(bs.to_dict())
    bytes_dst = collections.Counter(bd.to_dict())

    pair_mask = (df["ip_src"] != "") & (df["ip_dst"] != "")
    pair_df   = df[pair_mask][["ip_src","ip_dst"]]
    ip_pairs  = collections.Counter(zip(pair_df["ip_src"], pair_df["ip_dst"]))

    # ----- TCP flag counters: SYN, RST, FIN-only, NULL, Xmas -----
    syn_counter  = collections.Counter()
    rst_counter  = collections.Counter()
    fin_counter  = collections.Counter()
    null_counter = collections.Counter()
    xmas_counter = collections.Counter()
    tcp_mask = (df["tcp_flags"] != "") & (df["ip_src"] != "")
    if tcp_mask.any():
        tdf = df[tcp_mask][["ip_src","tcp_flags"]].copy()
        def _fi(s):
            try: return int(s, 16)
            except: return 0
        tdf["fi"] = tdf["tcp_flags"].map(_fi)
        # Mask against 0x3F so ECN bits (ECE/CWR) do not hide the SYN.
        syn_counter  = collections.Counter(tdf[(tdf["fi"] & 0x3F) == 0x02]["ip_src"].tolist())
        rst_counter  = collections.Counter(tdf[(tdf["fi"] & 0x04) != 0]["ip_src"].tolist())
        fin_counter  = collections.Counter(tdf[(tdf["fi"] & 0x3F) == 0x01]["ip_src"].tolist())
        null_counter = collections.Counter(tdf[(tdf["fi"] & 0x3F) == 0x00]["ip_src"].tolist())
        xmas_counter = collections.Counter(tdf[(tdf["fi"] & 0x3F) == 0x29]["ip_src"].tolist())

    # ----- ARP per IP / MAC -----
    arp_ip_to_macs = collections.defaultdict(set)
    arp_mac_to_ips = collections.defaultdict(set)
    arp_mask = (df["arp_psrc"] != "") & (df["arp_hwsrc"] != "")
    if arp_mask.any():
        for ip, mac in zip(df[arp_mask]["arp_psrc"], df[arp_mask]["arp_hwsrc"]):
            if ip and ip != "0.0.0.0":
                arp_ip_to_macs[ip].add(mac)
                arp_mac_to_ips[mac].add(ip)
    arp_spoofing_ips  = {ip:m for ip,m in arp_ip_to_macs.items() if len(m) > 1}
    arp_spoofing_macs = {mac:i for mac,i in arp_mac_to_ips.items() if len(i) > 1}

    # ----- DNS amp (response side, UDP/53) -----
    dns_amp_per_src = {}
    _dns_is_resp = df["dns_response"].isin(("1", "True"))
    amp_mask = _dns_is_resp & (df["udp_sport"] == "53") & (df["ip_src"] != "")
    if amp_mask.any():
        sub = df[amp_mask][["ip_src","len"]]
        g = sub.groupby("ip_src")["len"].agg(["count","sum","mean"])
        for ip, row in g.iterrows():
            dns_amp_per_src[ip] = {
                "count":       int(row["count"]),
                "total_bytes": int(row["sum"]),
                "mean_size":   float(row["mean"]),
            }

    # ----- DNS query stats -----
    dns_q = collections.Counter()
    dns_mask = (df["dns_qname"] != "") & (df["dns_qname"].str.len() > 3)
    if dns_mask.any():
        for q in df[dns_mask]["dns_qname"]:
            q = q.rstrip(".")
            if len(q) > 3: dns_q[q] += 1
    dns_nxdomain = int(((df["dns_rcode"] == "3") & (df["dns_response"] == "True")).sum()
                     + ((df["dns_rcode"] == "3") & (df["dns_response"] == "1")).sum())
    dns_long_queries = [k for k in dns_q if len(k) > 60]

    # ----- per-IP aggregation -----
    timeline_df = df[pair_mask][["ts","ip_src","ip_dst","len"]].rename(
        columns={"ts":"time","ip_src":"src","ip_dst":"dst","len":"size"}).reset_index(drop=True)
    ip_agg = timeline_df.groupby("src").agg(
        count=("size","count"), total_bytes=("size","sum"),
        mean_len=("size","mean"), std_len=("size","std"),
        unique_dsts=("dst","nunique"),
    ).fillna(0)
    ip_agg["burst_score"] = ip_agg["count"] / (ip_agg["std_len"] + 1)
    ip_agg["dominance"]   = ip_agg["count"] + ip_agg["total_bytes"] / 1000
    ip_agg["syn_count"]   = ip_agg.index.map(lambda x: syn_counter.get(x, 0))
    ip_agg["rst_count"]   = ip_agg.index.map(lambda x: rst_counter.get(x, 0))
    ip_agg["fin_count"]   = ip_agg.index.map(lambda x: fin_counter.get(x, 0))
    ip_agg["null_count"]  = ip_agg.index.map(lambda x: null_counter.get(x, 0))
    ip_agg["xmas_count"]  = ip_agg.index.map(lambda x: xmas_counter.get(x, 0))

    print(f"[{label}] {os.path.basename(path)} | "
          f"{t0:%H:%M:%S}->{t1:%H:%M:%S} | "
          f"{len(df):,} packets | {len(ips_src)} src-IPs | "
          f"{len(macs)} MACs | protos={dict(protocols.most_common(5))}")

    # Second, wider tshark pass for the six MITRE-mapped engines - the
    # same call the dashboard makes in _ingest_pcap_from_path. Without it
    # the judge receives an all-null advanced_signals block and reasons
    # with strictly less than the pipeline knows. Never raises: the module
    # reports {"available": False, "reason": ...} on any failure.
    threats = run_advanced_threats(path, label)
    if threats.get("available"):
        n_sig = sum(len(v) for v in (threats.get("per_engine") or {}).values())
        print(f"[{label}] advanced engines: {n_sig} signal(s) across "
              f"{len(threats.get('device_risk') or [])} device(s)")
    else:
        print(f"[{label}] advanced engines unavailable: "
              f"{threats.get('reason')}")

    return {
        "label": label, "df": df, "df_pkts": timeline_df, "n_pkts": len(df),
        "t0": t0, "t1": t1, "ip_agg": ip_agg, "threats": threats,
        "ips_src": ips_src, "bytes_src": bytes_src, "bytes_dst": bytes_dst,
        "protocols": protocols, "macs": macs,
        "ip_pairs": ip_pairs,
        "syn_counter": syn_counter, "rst_counter": rst_counter,
        "fin_counter": fin_counter, "null_counter": null_counter,
        "xmas_counter": xmas_counter,
        "dns_amp_per_src": dns_amp_per_src,
        "arp_spoofing_ips": arp_spoofing_ips,
        "arp_spoofing_macs": arp_spoofing_macs,
        "dns_q": dns_q, "dns_nxdomain": dns_nxdomain,
        "dns_long_queries": dns_long_queries,
    }


def run_ml_on_session(S):
    ip_agg = S["ip_agg"]
    if len(ip_agg) == 0:
        print(f"[{S['label']}] no source IPs, skipping ML"); return
    FEATURE_COLS = ["mean_len","std_len","count","burst_score",
                    "unique_dsts","syn_count","rst_count",
                    "fin_count","null_count","xmas_count"]
    X_raw = ip_agg[FEATURE_COLS].fillna(0).values
    X = StandardScaler().fit_transform(X_raw)
    print(f"[{S['label']}] feature matrix: {X.shape[0]} IPs x {X.shape[1]} features")

    if len(ip_agg) < 2:
        print(f"[{S['label']}] only {len(ip_agg)} IP -> skipping clustering"); return
    # Fixed contamination=0.10. Measured mean F1 on the ground-truth
    # PCAPs: 0.247 (5-seeds x 3-contams sweep) vs 0.250 (fixed=0.10).
    # The sweep never beat fixed and it did 15 forest fits per session;
    # keep a single fit and expose iso_stability as a compatibility
    # column so downstream consumers keep working.
    CONTAMINATION = 0.10
    print(f"[{S['label']}] IsolationForest contamination={CONTAMINATION:.2f} "
          f"(fixed, n_estimators=200, seed=42)")
    iso = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                          random_state=42).fit(X)
    ip_agg["iso_score"] = iso.decision_function(X)
    ip_agg["iso_flag"]  = iso.predict(X)
    ip_agg["anomaly"]   = ip_agg["iso_flag"] == -1
    ip_agg["iso_stability"] = ip_agg["anomaly"].astype(float)

    k = 2
    nbrs = NearestNeighbors(n_neighbors=k).fit(X)
    distances, _ = nbrs.kneighbors(X)
    k_dist = np.sort(distances[:, k-1])[::-1]
    if len(k_dist) >= 4:
        eps_auto = float(round(k_dist[int(np.argmin(np.diff(np.diff(k_dist)))) + 1], 2))
    else:
        eps_auto = 1.3
    if eps_auto <= 0:
        eps_auto = max(float(round(k_dist.mean(), 3)), 0.05)
        print(f"[{S['label']}] eps collapsed to 0; using mean k-dist={eps_auto:.3f}")
    print(f"[{S['label']}] DBSCAN eps={eps_auto:.2f} (min_samples=2)")
    DBSCAN_MAX_IPS = 5000
    if len(ip_agg) > DBSCAN_MAX_IPS:
        print(f"[{S['label']}] DBSCAN skipped: {len(ip_agg):,} IPs > cap "
              f"{DBSCAN_MAX_IPS:,} (spoofed-flood pattern). cluster=-1.")
        ip_agg["cluster"] = -1
        n_clusters = 0; n_noise = len(ip_agg); sil = None
    else:
        ip_agg["cluster"] = DBSCAN(eps=eps_auto, min_samples=2).fit_predict(X)
        labels = ip_agg["cluster"].values
        nn = labels != -1
        n_clusters = len(set(labels[nn]))
        n_noise    = int((labels == -1).sum())
        sil = None
        try:
            if nn.sum() >= 2 and n_clusters >= 2:
                sil = float(silhouette_score(X[nn], labels[nn]))
        except Exception:
            sil = None
    print(f"[{S['label']}] DBSCAN clusters={n_clusters} noise={n_noise} "
          f"silhouette={'n/a' if sil is None else round(sil, 3)}")
    n_anom = int(ip_agg["anomaly"].sum())
    print(f"[{S['label']}] anomalies: {n_anom} / {len(ip_agg)}")

    if n_anom:
        flagged = ip_agg[ip_agg["anomaly"]].sort_values("iso_score").head(10)
        print(f"[{S['label']}] top anomaly IPs (lowest iso_score):")
        for ip, row in flagged.iterrows():
            print(f"    {ip:<22} score={row['iso_score']:+.4f} "
                  f"pkts={int(row['count']):>6} syn={int(row['syn_count']):>5} "
                  f"fin={int(row['fin_count']):>5} xmas={int(row['xmas_count']):>5} "
                  f"unique_dsts={int(row['unique_dsts']):>5}")


def run_security_scans(S):
    print(f"\n[{S['label']}] security scan (deterministic rules):")
    syn_top  = S["syn_counter"].most_common(5)
    rst_top  = S["rst_counter"].most_common(5)
    fin_top  = (S.get("fin_counter")  or collections.Counter()).most_common(5)
    null_top = (S.get("null_counter") or collections.Counter()).most_common(5)
    xmas_top = (S.get("xmas_counter") or collections.Counter()).most_common(5)

    print(f"  top SYN  : {syn_top}")
    if fin_top:  print(f"  top FIN  : {fin_top}")
    if null_top: print(f"  top NULL : {null_top}")
    if xmas_top: print(f"  top XMAS : {xmas_top}")
    print(f"  top RST  : {rst_top}")

    arp = S["arp_spoofing_ips"]
    print(f"  ARP IP->multi-MAC : {len(arp)} ip(s)")
    for ip, macs in list(arp.items())[:5]:
        print(f"      {ip} -> {sorted(macs)}")
    arp_mac = S["arp_spoofing_macs"]
    print(f"  ARP MAC->multi-IP : {len(arp_mac)} mac(s)")
    for mac, ips in list(arp_mac.items())[:5]:
        print(f"      {mac} -> claimed {len(ips)} IPs e.g. {sorted(ips)[:5]}")
    print(f"  DNS NXDOMAIN      : {S['dns_nxdomain']}")
    print(f"  DNS long (>60ch)  : {len(S['dns_long_queries'])}")

    # Horizontal-scan rule across SYN, FIN, NULL, XMAS.
    print(f"  --- horizontal-scan rule (SYN + FIN + NULL + XMAS) ---")
    scan_alerts = []
    for name, cnt in (("SYN", S["syn_counter"]),
                      ("FIN", S.get("fin_counter") or collections.Counter()),
                      ("NULL", S.get("null_counter") or collections.Counter()),
                      ("XMAS", S.get("xmas_counter") or collections.Counter())):
        # No top-5 truncation: walk every source above the 50-packet floor.
        for src, n in sorted(cnt.items(), key=lambda kv: -kv[1]):
            if n <= 50: break
            if not src or src not in S["ip_agg"].index: continue
            row = S["ip_agg"].loc[src]
            n_pkt = int(row["count"]); n_dst = int(row["unique_dsts"])
            ratio = n / max(n_pkt, 1)
            if n_dst > 20 or ratio > 0.7:
                scan_alerts.append({"src":src,"type":name,"count":int(n),
                                    "unique_dsts":n_dst,"ratio":round(ratio,2)})
    if scan_alerts:
        for a in scan_alerts:
            print(f"      {a['src']:<22} {a['type']:<5} count={a['count']:>5} "
                  f"unique_dsts={a['unique_dsts']:>4} ratio={a['ratio']}  *** SCAN ***")
    else:
        print(f"      (no scanner-like sources)")

    # Aggregate spoofed-flood rule: thousands of spoofed sources sending ~1
    # SYN each never trip the per-source rule above, so detect the flood
    # from session-level aggregates.
    print(f"  --- aggregate SYN-flood rule ---")
    total_syn  = sum(S["syn_counter"].values())
    n_syn_srcs = len(S["syn_counter"])
    duration_s = max((S["t1"] - S["t0"]).total_seconds(), 1.0)
    syn_rate   = total_syn / duration_s
    flood_alerts = []
    if total_syn >= 1000 and n_syn_srcs >= 100 and syn_rate >= 100:
        per_src = total_syn / n_syn_srcs
        flood_alerts.append({
            "type": "SYN_FLOOD", "total_syn": int(total_syn),
            "syn_sources": int(n_syn_srcs), "syn_per_sec": round(syn_rate, 1),
            "syn_per_source": round(per_src, 2),
            "spoofed_source_pattern": bool(per_src <= 3),
        })
    if flood_alerts:
        for a in flood_alerts:
            tag = "spoofed-source" if a["spoofed_source_pattern"] else "concentrated"
            print(f"      {a['total_syn']:,} SYNs from {a['syn_sources']:,} sources "
                  f"@ {a['syn_per_sec']}/s ({tag})  *** SYN FLOOD ***")
    else:
        print(f"      (no aggregate flood pattern)")

    # DNS amp rule.
    print(f"  --- DNS amplification rule (response side) ---")
    amp_alerts = []
    for ip, stats in (S.get("dns_amp_per_src") or {}).items():
        if stats["count"] >= 50 and stats["mean_size"] >= 200:
            amp_alerts.append({"src":ip, "responses":stats["count"],
                              "mean_size":round(stats["mean_size"],1)})
    if amp_alerts:
        for a in sorted(amp_alerts, key=lambda x: -x["responses"])[:8]:
            print(f"      {a['src']:<22} responses={a['responses']:>5} "
                  f"mean_size={a['mean_size']} bytes  *** AMP REFLECTOR ***")
    else:
        print(f"      (no reflector pattern)")

    # Returned so tests / the evaluation harness can assert on findings
    # instead of scraping stdout.
    return {
        "scan_alerts": scan_alerts,
        "flood_alerts": flood_alerts,
        "amp_alerts": amp_alerts,
        "arp_spoofing_ips": dict(S["arp_spoofing_ips"]),
        "arp_spoofing_macs": dict(S["arp_spoofing_macs"]),
        "dns_nxdomain": S["dns_nxdomain"],
        "dns_long_queries": list(S["dns_long_queries"]),
    }


class LSTMModel(nn.Module):
    def __init__(self, input_size=1, hidden_size=64):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc   = nn.Linear(hidden_size, 1)
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])


SEQ_LEN = 10
MAX_BINS = 20000


def train_and_eval_lstm(S, max_epochs=8):
    label = S["label"]
    df = S["df_pkts"].sort_values("time").copy()
    if len(df) == 0:
        print(f"[{label}] no packets, skipping LSTM"); return
    df["second"] = (df["time"] - df["time"].min()).astype(int)
    # Zero-fill idle seconds (mirrors the notebook): a bare groupby drops
    # empty seconds and hides silence-then-burst transitions.
    per_sec = df.groupby("second")["size"].mean()
    n_secs  = int(df["second"].max()) + 1
    binned  = per_sec.reindex(range(n_secs), fill_value=0.0).values.astype(float)
    if len(binned) > MAX_BINS:
        stride = len(binned) // MAX_BINS
        binned = binned[::stride][:MAX_BINS]
    print(f"\n[{label}] LSTM | time bins: {len(binned)}")
    if len(binned) < SEQ_LEN + 10:
        print(f"[{label}] too few bins ({len(binned)}) -> skipping LSTM"); return

    seq = MinMaxScaler().fit_transform(binned.reshape(-1, 1))
    Xn = np.array([seq[i:i+SEQ_LEN] for i in range(len(seq) - SEQ_LEN)])
    yn = np.array([seq[i+SEQ_LEN]   for i in range(len(seq) - SEQ_LEN)])
    split = int(len(Xn) * 0.8)
    Xt_tr  = torch.tensor(Xn[:split], dtype=torch.float32)
    yt_tr  = torch.tensor(yn[:split], dtype=torch.float32)
    Xt_val = torch.tensor(Xn[split:], dtype=torch.float32)
    yt_val = torch.tensor(yn[split:], dtype=torch.float32)
    Xt_all = torch.tensor(Xn,         dtype=torch.float32)
    yt_all = torch.tensor(yn,         dtype=torch.float32)
    m = LSTMModel(); opt = torch.optim.Adam(m.parameters(), lr=0.001); crit = nn.MSELoss()
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(Xt_tr, yt_tr), batch_size=512, shuffle=True)
    best_val = math.inf; patience = 2
    save = os.path.join(tempfile.gettempdir(), f"lstm_{label}.pt")
    print(f"[{label}] training on {len(Xt_tr):,} seq | val on {len(Xt_val):,}")
    for ep in range(max_epochs):
        m.train(); tot = 0
        for xb, yb in loader:
            opt.zero_grad(); l = crit(m(xb).squeeze(), yb.squeeze())
            l.backward(); opt.step(); tot += l.item()
        m.eval()
        with torch.no_grad():
            vl = crit(m(Xt_val).squeeze(), yt_val.squeeze()).item()
        mark = " *" if vl < best_val else ""
        print(f"  ep {ep+1}/{max_epochs} train={tot/len(loader):.6f} val={vl:.6f}{mark}")
        if vl < best_val:
            best_val = vl; patience = 2; torch.save(m.state_dict(), save)
        else:
            patience -= 1
            if patience == 0: print(f"  early stop at epoch {ep+1}"); break
    m.load_state_dict(torch.load(save)); m.eval()
    with torch.no_grad():
        val_err = torch.abs(m(Xt_val).squeeze() - yt_val.squeeze()).numpy()
        all_err = torch.abs(m(Xt_all).squeeze() - yt_all.squeeze()).numpy()
    thr = val_err.mean() + 2*val_err.std()
    n_anom = int((all_err > thr).sum())
    print(f"[{label}] LSTM val MAE={val_err.mean():.5f} std={val_err.std():.5f} thr={thr:.5f}")
    print(f"[{label}] anomalous time bins: {n_anom} / {len(all_err)} "
          f"({100*n_anom/len(all_err):.1f}%)")


def compute_session_compare(S1, S2):
    ips1, ips2 = set(S1["ips_src"]), set(S2["ips_src"])
    n_new  = len(ips2 - ips1)
    n_gone = len(ips1 - ips2)
    print(f"\n=== S1 vs S2 compare === |S1|={len(ips1)} |S2|={len(ips2)} | "
          f"new={n_new} gone={n_gone} shared={len(ips1 & ips2)}")
    print(f"  S1 top talkers (bytes): {S1['bytes_src'].most_common(5)}")
    print(f"  S2 top talkers (bytes): {S2['bytes_src'].most_common(5)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: run_pipeline.py <S1.pcap> <S2.pcap>", file=sys.stderr)
        sys.exit(2)
    p1, p2 = sys.argv[1], sys.argv[2]
    print("=" * 70 + f"\n# Loading S1 = {p1}\n" + "=" * 70)
    S1 = analyze_pcap(p1, "S1")
    print("=" * 70 + f"\n# Loading S2 = {p2}\n" + "=" * 70)
    S2 = analyze_pcap(p2, "S2")
    for S in (S1, S2):
        print("\n" + "-" * 70)
        run_ml_on_session(S)
        run_security_scans(S)
        train_and_eval_lstm(S)
    compute_session_compare(S1, S2)

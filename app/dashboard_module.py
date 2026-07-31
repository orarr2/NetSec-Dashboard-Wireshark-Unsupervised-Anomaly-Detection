# =========================================================================
# AUTO-GENERATED from app/Network_Security_Dashboard.ipynb
# by tools/export_dashboard_module.py - DO NOT EDIT BY HAND.
# Regenerate with:  python3 tools/export_dashboard_module.py
#
# Importing this module executes the full notebook INCLUDING the final
# app.run() call. For tests, stub dash.Dash.run to a no-op before import.
# =========================================================================


# ==== notebook cell 4 ====

import subprocess, sys, os

PKGS = {
    'numpy':                    'numpy',
    'pandas':                   'pandas',
    'torch':                    'torch',
    'scikit-learn':             'sklearn',
    'scapy':                    'scapy',
    'plotly':                   'plotly',
    'dash':                     'dash',
    'dash-bootstrap-components':'dash_bootstrap_components',
    'manuf':                    'manuf',
}
for pkg, imp in PKGS.items():
    try:
        __import__(imp)
    except ImportError:
        print(f'Installing {pkg}...')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '-q'])

import re, warnings, datetime, collections, shutil
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import sklearn
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score
import scapy
from scapy.all import rdpcap, conf as scapy_conf
import plotly
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import dash
from dash import dcc, html, Input, Output, State, ctx
import dash_bootstrap_components as dbc
import manuf

scapy_conf.verb = 0
warnings.filterwarnings("ignore")

print('─' * 56)
print(f'  {"Library":<28} {"Version":<14}')
print('─' * 56)
LIBS = [
    ('numpy', np), ('pandas', pd), ('torch', torch),
    ('scikit-learn', sklearn), ('scapy', scapy),
    ('plotly', plotly), ('dash', dash),
    ('dash-bootstrap-components', dbc), ('manuf', manuf),
]
for name, mod in LIBS:
    ver = getattr(mod, '__version__', None) or getattr(mod, 'version', '-')
    print(f'  {name:<28} {str(ver):<14}')
print('─' * 56)
print()
print('System dependencies (Wireshark / tshark / OUI database):')
print('─' * 56)

tshark = shutil.which('tshark')
if not tshark:
    for p in ['/usr/bin/tshark', '/usr/local/bin/tshark',
              '/Applications/Wireshark.app/Contents/MacOS/tshark',
              r'C:\Program Files\Wireshark\tshark.exe',
              r'C:\Program Files (x86)\Wireshark\tshark.exe']:
        if os.path.exists(p):
            tshark = p
            break

if tshark:
    try:
        out = subprocess.check_output([tshark, '-v'], stderr=subprocess.STDOUT,
                                       encoding='utf-8', errors='replace', timeout=5).splitlines()[0]
        print(f'  ✓ tshark         {tshark}')
        print(f'                   {out}')
    except Exception:
        print(f'  ✓ tshark         {tshark}')
else:
    print('  ✗ tshark         NOT FOUND on PATH or in standard locations.')
    print('                   Static PCAP analysis still works (via scapy).')
    print('                   For LIVE capture install Wireshark from:')
    print('                     https://www.wireshark.org/download.html')
    print('                   Windows users: tick "Install Npcap" in the installer.')

manuf_paths = [
    '/usr/share/wireshark/manuf',
    '/usr/share/wireshark/wireshark/manuf',
    '/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf',
    r'C:\Program Files\Wireshark\manuf',
    r'C:\Program Files (x86)\Wireshark\manuf',
]
mfile = next((p for p in manuf_paths if os.path.exists(p)), None)
if mfile:
    sz = os.path.getsize(mfile)
    print(f'  ✓ Wireshark OUI  {mfile}  ({sz:,} bytes)')
elif tshark:


    try:
        probe = subprocess.check_output([tshark, '-G', 'manuf'],
                                         stderr=subprocess.DEVNULL,
                                         encoding='utf-8', errors='replace', timeout=15)
        n_lines = probe.count('\n')
        if n_lines > 100:
            print(f'  ✓ Wireshark OUI  via `tshark -G manuf`  (~{n_lines:,} lines)')
        else:
            print('  ✗ Wireshark OUI  tshark -G manuf returned no usable data')
            print('                   Will fall back to `manuf` PyPI package.')
    except Exception as _e:
        print(f'  ✗ Wireshark OUI  tshark -G manuf failed: {_e}')
        print('                   Will fall back to `manuf` PyPI package.')
else:
    print('  ✗ Wireshark OUI  Not found - will fall back to `manuf` PyPI package.')

print('─' * 56)
print()
print('All libraries loaded successfully')


# ==== notebook cell 6 ====

import base64, tempfile

PCAP1 = None
CSV1  = None
PCAP2 = None
CSV2  = None

MY_DEVICE_IP = os.environ.get("NETSEC_MY_DEVICE_IP", "")

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_UPLOAD_HUMAN = "100 MB"


def decode_uploaded_pcap(contents, filename):
    """Convert a dcc.Upload `contents` data URL into a temp file path. Returns
    (path, error). On success error is None. On failure path is None."""
    if not contents:
        return None, "No file content received"
    try:
        header, b64 = contents.split(",", 1)
    except ValueError:
        return None, "Malformed upload payload"
    try:
        raw = base64.b64decode(b64)
    except Exception as e:
        return None, f"Base64 decode failed: {e}"
    if len(raw) > MAX_UPLOAD_BYTES:
        return None, (f"File too large for drag-and-drop: {len(raw)/1e6:.1f} MB "
                      f"(limit {MAX_UPLOAD_HUMAN}). Paste the path instead.")
    if not filename:
        filename = "upload.pcap"
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in filename)
    suffix = ".pcapng" if safe_name.lower().endswith(".pcapng") else ".pcap"
    fd, tmp_path = tempfile.mkstemp(prefix="netsec_upload_", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
    except Exception as e:
        return None, f"Could not write temp file: {e}"
    return tmp_path, None


def validate_pcap_path(path):
    """Verify a path the user typed/pasted. Returns (resolved_path, error)."""
    if not path or not str(path).strip():
        return None, "Path is empty"
    path = str(path).strip().strip('"').strip("'")
    if not os.path.exists(path):
        return None, f"File not found: {path}"
    if not os.path.isfile(path):
        return None, f"Not a file: {path}"
    low = path.lower()
    if not (low.endswith(".pcap") or low.endswith(".pcapng") or low.endswith(".cap")):
        return None, f"Not a PCAP file (expected .pcap / .pcapng / .cap): {path}"
    try:
        size = os.path.getsize(path)
    except Exception as e:
        return None, f"Could not stat file: {e}"
    if size == 0:
        return None, "File is empty"
    return path, None


print("PCAP slots empty. Use the dashboard splash screen to load files or record live.")
print(f"Upload limit (drag-and-drop): {MAX_UPLOAD_HUMAN}. "
      f"Larger files: paste the path directly.")


# ==== notebook cell 8 ====

from datetime import datetime, timedelta

# Local UTC offset at the epoch, in seconds, computed once without touching
# the platform mktime (which is exactly what crashes near 1970 on Windows).
# datetime.fromtimestamp(0) succeeds - it is .timestamp() on the RESULT that
# raises - so this reference is safe to build. Used by the _safe_* helpers to
# convert between naive-local datetimes and TRUE epoch seconds so the value
# stays on the same time base as the raw-epoch event timestamps it is
# compared against. Falls back to 0 (old behaviour) if even this crashes.
_EPOCH_NAIVE = datetime(1970, 1, 1)
try:
    _LOCAL_EPOCH_OFFSET_S = (datetime.fromtimestamp(0) - _EPOCH_NAIVE).total_seconds()
except (OSError, OverflowError, ValueError):
    _LOCAL_EPOCH_OFFSET_S = 0.0


def _safe_epoch(dt):
    """TRUE epoch seconds for a naive-local datetime, without crashing.

    `datetime.timestamp()` raises OSError [Errno 22] on Windows for naive
    datetimes at or just after 1970-01-01 (the C runtime's mktime can't
    represent them once the local UTC offset is applied). PCAPs with
    synthetic capture times (e.g. attack fixtures starting at epoch 0) hit
    this. The fallback recovers the true epoch by subtracting the local UTC
    offset instead of calling mktime, so the result stays on the SAME time
    base as the raw-epoch packet timestamps it is bucketed against (an
    earlier version treated the local tuple as UTC, shifting every bin by
    the offset and silently emptying the browsing-hour chart).
    """
    try:
        return dt.timestamp()
    except (OSError, OverflowError, ValueError):
        return (dt - _EPOCH_NAIVE).total_seconds() - _LOCAL_EPOCH_OFFSET_S


def _safe_fromtimestamp(ts):
    """`datetime.fromtimestamp()` that degrades instead of crashing near the
    epoch on Windows. Returns a naive-LOCAL datetime consistent with the
    try-branch (adds the local offset back), so HH:MM labels match what
    datetime.fromtimestamp would have produced."""
    try:
        return datetime.fromtimestamp(ts)
    except (OSError, OverflowError, ValueError):
        return _EPOCH_NAIVE + timedelta(seconds=float(ts) + _LOCAL_EPOCH_OFFSET_S)


def _find_tshark():
    """Locate tshark on the host."""
    cand = shutil.which("tshark")
    if cand: return cand
    for p in ["/usr/bin/tshark", "/usr/local/bin/tshark",
              "/Applications/Wireshark.app/Contents/MacOS/tshark",
              r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if os.path.exists(p):
            return p
    return None

_TSHARK_PATH_FOR_LOADER = _find_tshark()

def _extract_wifi_ssid_bssid(pcap_path, tshark_path):
    """Pull the dominant SSID + BSSID from beacon and probe-response frames.
    Returns (ssid, bssid). Either may be None when the PCAP contains no
    802.11 management frames (the common case for Windows captures that
    were already deframed to Ethernet, or for wired captures)."""
    from collections import Counter
    if not tshark_path:
        return None, None
    try:
        raw = subprocess.check_output(
            [tshark_path, "-r", str(pcap_path), "-n",
             "-Y", "wlan.fc.type==0 && (wlan.fc.subtype==8 || wlan.fc.subtype==5)",
             "-T", "fields", "-e", "wlan.bssid", "-e", "wlan.ssid",
             "-E", "header=n", "-E", "separator=|", "-E", "occurrence=f",
             "-E", "quote=n"],
            encoding="utf-8", errors="replace", stderr=subprocess.DEVNULL,
            timeout=30)
    except Exception:
        return None, None
    bssid_c, ssid_c = Counter(), Counter()
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue
        bssid, ssid = parts[0].strip(), parts[1].strip()
        # tshark sometimes emits non-printable / hex-decoded SSIDs.
        # Filter both: BSSID must look like xx:xx:xx:xx:xx:xx, SSID must be
        # printable and non-empty.
        if bssid and bssid.count(":") == 5:
            bssid_c[bssid.lower()] += 1
        if ssid and all(32 <= ord(ch) < 127 for ch in ssid):
            ssid_c[ssid] += 1
    ssid_top  = ssid_c.most_common(1)[0][0]  if ssid_c  else None
    bssid_top = bssid_c.most_common(1)[0][0] if bssid_c else None
    return ssid_top, bssid_top


def _analyze_pcap_tshark(path, label, tshark_path):
    """Fast PCAP loader using tshark -T fields. ~5-7x faster than scapy.rdpcap. Produces the exact same dict structure as _analyze_pcap_scapy below."""
    import io
    fields = [
        "frame.time_epoch", "frame.len",
        "eth.src", "eth.dst",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "_ws.col.Protocol",
        "tcp.srcport", "tcp.dstport", "tcp.flags",
        "udp.srcport", "udp.dstport",
        "dns.qry.name", "dns.flags.rcode", "dns.flags.response",
        "arp.src.proto_ipv4", "arp.src.hw_mac",
        "wlan.fc.type", "wlan.fc.subtype", "wlan.sa", "wlan.fc.retry",
        "radiotap.dbm_antsignal", "wlan_radio.signal_dbm",
    ]
    cmd = [tshark_path, "-r", str(path), "-n", "-T", "fields",
           "-E", "header=n", "-E", "separator=|",
           "-E", "occurrence=f", "-E", "quote=n"]
    for f in fields:
        cmd += ["-e", f]

    raw = subprocess.check_output(cmd, encoding="utf-8", errors="replace",
                                   stderr=subprocess.DEVNULL)
    df = pd.read_csv(io.StringIO(raw), sep="|", header=None,
        names=["ts","len","eth_src","eth_dst","ip_src","ip_dst",
               "ip6_src","ip6_dst","proto",
               "tcp_sport","tcp_dport","tcp_flags","udp_sport","udp_dport",
               "dns_qname","dns_rcode","dns_response","arp_psrc","arp_hwsrc",
               "wlan_type","wlan_subtype","wlan_sa","wlan_retry",
               "rssi_radiotap","rssi_wlanradio"],
        dtype=str, na_filter=False, low_memory=False)
    if len(df) == 0:
        raise RuntimeError(f"tshark returned 0 rows from {path}")

    df["ts"]  = pd.to_numeric(df["ts"],  errors="coerce")
    df["len"] = pd.to_numeric(df["len"], errors="coerce").fillna(0).astype(int)
    df = df.dropna(subset=["ts"])

    # Coalesce v6 into the v4 columns. On a modern home network most
    # traffic is IPv6, and every mask below keys on ip_src/ip_dst being
    # non-empty - without this the per-IP layer would silently analyse a
    # small IPv4 remnant and report it as the whole network.
    _v6s = df["ip6_src"] != ""
    if _v6s.any():
        df.loc[_v6s & (df["ip_src"] == ""), "ip_src"] = df.loc[
            _v6s & (df["ip_src"] == ""), "ip6_src"]
    _v6d = df["ip6_dst"] != ""
    if _v6d.any():
        df.loc[_v6d & (df["ip_dst"] == ""), "ip_dst"] = df.loc[
            _v6d & (df["ip_dst"] == ""), "ip6_dst"]

    t0 = _safe_fromtimestamp(df["ts"].min())
    t1 = _safe_fromtimestamp(df["ts"].max())

    ips_src   = collections.Counter(df[df["ip_src"]!=""]["ip_src"].tolist())
    macs      = collections.Counter(df[df["eth_src"]!=""]["eth_src"].tolist())
    protocols = collections.Counter(df["proto"][df["proto"]!=""].tolist())

    bs = df[df["ip_src"]!=""].groupby("ip_src")["len"].sum()
    bd = df[df["ip_dst"]!=""].groupby("ip_dst")["len"].sum()
    bytes_src = collections.Counter(bs.to_dict())
    bytes_dst = collections.Counter(bd.to_dict())

    pair_mask = (df["ip_src"]!="") & (df["ip_dst"]!="")
    pair_df   = df[pair_mask][["ip_src","ip_dst"]]
    ip_pairs  = collections.Counter(zip(pair_df["ip_src"], pair_df["ip_dst"]))

    syn_counter  = collections.Counter()
    rst_counter  = collections.Counter()
    fin_counter  = collections.Counter()
    null_counter = collections.Counter()
    xmas_counter = collections.Counter()
    tcp_mask    = (df["tcp_flags"]!="") & (df["ip_src"]!="")
    if tcp_mask.any():
        tcp_df = df[tcp_mask][["ip_src","tcp_flags"]].copy()
        def _flag_int(s):
            try: return int(s, 16)
            except: return 0
        tcp_df["fi"] = tcp_df["tcp_flags"].map(_flag_int)
        # SYN scan: SYN flag only (0x02), masked against 0x3F so the ECN
        # bits (ECE/CWR - e.g. 0xC2 SYNs from ECN-enabled Linux stacks) do
        # not hide the SYN from the counter.
        syn_counter = collections.Counter(tcp_df[(tcp_df["fi"] & 0x3F) == 0x02]["ip_src"].tolist())
        # RST: any RST flag (0x04).
        rst_counter = collections.Counter(tcp_df[(tcp_df["fi"] & 0x04) != 0]["ip_src"].tolist())
        # Stealth scans - FIN-only, NULL (no flags), Xmas (FIN|PSH|URG = 0x29).
        # Mask against 0x3F so ECE/CWR bits do not perturb the match.
        fin_counter  = collections.Counter(tcp_df[(tcp_df["fi"] & 0x3F) == 0x01]["ip_src"].tolist())
        null_counter = collections.Counter(tcp_df[(tcp_df["fi"] & 0x3F) == 0x00]["ip_src"].tolist())
        xmas_counter = collections.Counter(tcp_df[(tcp_df["fi"] & 0x3F) == 0x29]["ip_src"].tolist())

    ip_to_mac = collections.defaultdict(collections.Counter)
    eth_mask  = (df["eth_src"]!="") & (df["ip_src"]!="")
    if eth_mask.any():
        for ipx, macx in zip(df[eth_mask]["ip_src"], df[eth_mask]["eth_src"]):
            ip_to_mac[ipx][macx] += 1

    ports_per_ip = collections.defaultdict(set)
    for col_port in ("tcp_sport","tcp_dport","udp_sport","udp_dport"):
        m = (df[col_port]!="") & (df["ip_src"]!="")
        if not m.any(): continue
        for ipx, px in zip(df[m]["ip_src"], df[m][col_port]):
            try: ports_per_ip[ipx].add(int(px))
            except ValueError: pass

    dns_q          = collections.Counter()
    dns_timeline   = []
    dns_per_ip     = collections.defaultdict(collections.Counter)
    mdns_per_ip    = collections.defaultdict(set)
    dns_mask       = (df["dns_qname"]!="") & (df["dns_qname"].str.len() > 3)
    SKIP = re.compile(r"^_|^wpad$|^KMD|^BRW|^v1$|^server|^HP$", re.I)
    if dns_mask.any():
        ddf = df[dns_mask][["ts","ip_src","dns_qname"]]
        for ts, ip, q in zip(ddf["ts"], ddf["ip_src"], ddf["dns_qname"]):
            q = q.rstrip(".")
            if len(q) <= 3: continue
            dns_q[q] += 1
            if ip:
                dns_timeline.append((float(ts), ip, q))
                dns_per_ip[ip][q] += 1
                if q.endswith(".local"):
                    mdns_per_ip[ip].add(q)
    real_dns = {k:v for k,v in dns_q.items()
                if "." in k and not k.endswith(".local")
                and not SKIP.search(k.split(".")[0])}
    device_names = sorted(set(
        k for k in dns_q
        if k.endswith(".local") and not k.startswith("_")
        and not re.match(r"^[0-9a-f\-]{8,}", k) and len(k) > 8
    ))

    arp_ip_to_macs = collections.defaultdict(set)
    arp_mac_to_ips = collections.defaultdict(set)
    arp_mask = (df["arp_psrc"]!="") & (df["arp_hwsrc"]!="")
    if arp_mask.any():
        for ip, mac in zip(df[arp_mask]["arp_psrc"], df[arp_mask]["arp_hwsrc"]):
            if ip and ip != "0.0.0.0":
                arp_ip_to_macs[ip].add(mac)
                arp_mac_to_ips[mac].add(ip)
    arp_spoofing_ips  = {ip:macs2 for ip,macs2 in arp_ip_to_macs.items() if len(macs2)>1}
    arp_spoofing_macs = {mac:ips for mac,ips in arp_mac_to_ips.items() if len(ips)>1}

    # DNS amplification on the response side: per source-IP, how many DNS
    # answers came out of UDP/53 and how big they were on average. Used by
    # the security-scan rule layer to flag reflectors / amp participants.
    dns_amp_per_src = {}
    _dns_is_resp = df["dns_response"].isin(("1", "True"))
    amp_mask = _dns_is_resp & (df["udp_sport"]=="53") & (df["ip_src"]!="")
    if amp_mask.any():
        sub = df[amp_mask][["ip_src","len"]]
        g = sub.groupby("ip_src")["len"].agg(["count","sum","mean"])
        for ip, row in g.iterrows():
            dns_amp_per_src[ip] = {
                "count":       int(row["count"]),
                "total_bytes": int(row["sum"]),
                "mean_size":   float(row["mean"]),
            }

    # tshark renders boolean fields as "1"/"0" or "True"/"False" depending
    # on version - reuse the same normalised mask as the amp rule above.
    _nx_mask = (df["dns_rcode"]=="3") & _dns_is_resp
    dns_nxdomain = int(_nx_mask.sum())
    # Attribute NXDOMAIN storms to the host that *received* the responses
    # (the querier), so threat scoring can blame the right device instead
    # of the whole session.
    nxdomain_per_dst = collections.Counter(
        df[_nx_mask & (df["ip_dst"]!="")]["ip_dst"].tolist())
    # Queries only: a DNS response travels TO the client's ephemeral
    # port, so counting every non-53/5353 dstport double-counts each
    # (query, response) pair as "unusual".
    nonstd_mask  = ((df["dns_qname"]!="") & (df["udp_dport"]!="")
                    & (df["dns_response"] != "1"))
    if nonstd_mask.any():
        ports_int = pd.to_numeric(df.loc[nonstd_mask,"udp_dport"], errors="coerce")
        dns_nonstandard = int(((ports_int != 53) & (ports_int != 5353)).sum())
    else:
        dns_nonstandard = 0
    dns_long_queries = [k for k in dns_q if len(k) > 60]

    timeline_df = df[pair_mask][["ts","ip_src","ip_dst","len"]].rename(
        columns={"ts":"time","ip_src":"src","ip_dst":"dst","len":"size"}
    ).reset_index(drop=True)
    pkt_sizes   = df["len"].tolist()

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

    
    # ===== 802.11 / WLAN feature extraction (monitor-mode only) =====
    # Most Windows Wi-Fi captures present already-deframed Ethernet and will
    # have no wlan.* fields. In that case wlan_features stays empty and the
    # proximity analysis falls back to a behavioural proxy.
    wlan_features = {}
    wlan_available = False
    try:
        wlan_type_col   = df.get("wlan_type")
        wlan_sub_col    = df.get("wlan_subtype")
        wlan_sa_col     = df.get("wlan_sa")
        wlan_retry_col  = df.get("wlan_retry")
        rssi_a_col      = df.get("rssi_radiotap")
        rssi_b_col      = df.get("rssi_wlanradio")

        def _to_int(v):
            try:
                if v is None or (isinstance(v, float) and pd.isna(v)) or v == "":
                    return None
                return int(float(v))
            except (TypeError, ValueError):
                return None

        def _to_float(v):
            try:
                if v is None or (isinstance(v, float) and pd.isna(v)) or v == "":
                    return None
                s = str(v).split(",")[0]
                return float(s)
            except (TypeError, ValueError):
                return None

        has_any_rssi = False
        # Skip the per-row loop entirely for wired/deframed captures - the
        # wlan_sa column exists but is empty there.
        if wlan_sa_col is not None and (wlan_sa_col != "").any():
            for i in range(len(df)):
                sa = wlan_sa_col.iloc[i]
                if not sa or pd.isna(sa) or sa == "":
                    continue
                sa = str(sa).lower()
                entry = wlan_features.setdefault(sa, {
                    "rssi_samples": [], "frame_types": {}, "subtypes": {},
                    "retry_count": 0, "total_frames": 0,
                    "probe_requests": 0, "association_frames": 0,
                    "deauth_frames": 0, "first_seen": None, "last_seen": None,
                })
                entry["total_frames"] += 1

                ftype = _to_int(wlan_type_col.iloc[i]) if wlan_type_col is not None else None
                stype = _to_int(wlan_sub_col.iloc[i])  if wlan_sub_col is not None else None
                if ftype is not None:
                    entry["frame_types"][ftype] = entry["frame_types"].get(ftype, 0) + 1
                if stype is not None:
                    entry["subtypes"][stype] = entry["subtypes"].get(stype, 0) + 1
                if ftype == 0 and stype == 4:
                    entry["probe_requests"] += 1
                if ftype == 0 and stype in (0, 1, 2, 3):
                    entry["association_frames"] += 1
                if ftype == 0 and stype in (10, 12):
                    entry["deauth_frames"] += 1

                retry = _to_int(wlan_retry_col.iloc[i]) if wlan_retry_col is not None else None
                if retry == 1:
                    entry["retry_count"] += 1

                rssi = None
                if rssi_a_col is not None:
                    rssi = _to_float(rssi_a_col.iloc[i])
                if rssi is None and rssi_b_col is not None:
                    rssi = _to_float(rssi_b_col.iloc[i])
                if rssi is not None:
                    entry["rssi_samples"].append(rssi)
                    has_any_rssi = True

                ts = df["ts"].iloc[i]
                try:
                    ts_f = float(ts)
                    if entry["first_seen"] is None or ts_f < entry["first_seen"]:
                        entry["first_seen"] = ts_f
                    if entry["last_seen"] is None or ts_f > entry["last_seen"]:
                        entry["last_seen"] = ts_f
                except (TypeError, ValueError):
                    pass

        wlan_available = has_any_rssi
        if wlan_available:
            n_macs_with_rssi = sum(1 for v in wlan_features.values() if v["rssi_samples"])
            print(f"  WLAN: {n_macs_with_rssi} MACs with RSSI data captured (monitor-mode PCAP)")
        else:
            wlan_features = {}
            print(f"  WLAN: no 802.11 management frames or RSSI in PCAP (using behavioural fallback)")
    except Exception as e:
        print(f"  WLAN extraction skipped: {e}")
        wlan_features = {}
        wlan_available = False

    _wifi_ssid, _wifi_bssid = _extract_wifi_ssid_bssid(path, _TSHARK_PATH_FOR_LOADER)
    return {
        "label": label, "pkts": [], "dns_timeline": dns_timeline,
        "t0": t0, "t1": t1, "n_pkts": len(df),
        "wifi_ssid": _wifi_ssid, "wifi_bssid": _wifi_bssid,
        "pkt_sizes": pkt_sizes, "ips_src": ips_src,
        "bytes_src": bytes_src, "bytes_dst": bytes_dst,
        "protocols": protocols, "macs": macs,
        "dns_real": real_dns, "device_names": device_names,
        "ip_agg": ip_agg, "df_pkts": timeline_df, "ip_pairs": ip_pairs,
        "syn_counter": syn_counter, "rst_counter": rst_counter,
        "fin_counter": fin_counter, "null_counter": null_counter,
        "xmas_counter": xmas_counter,
        "dns_amp_per_src": dns_amp_per_src,
        "arp_spoofing_ips": arp_spoofing_ips,
        "arp_spoofing_macs": arp_spoofing_macs,
        "dns_nxdomain": dns_nxdomain,
        "nxdomain_per_dst": nxdomain_per_dst,
        "dns_nonstandard": dns_nonstandard,
        "dns_long_queries": dns_long_queries,
        "ip_to_mac": ip_to_mac,
        "ports_per_ip": ports_per_ip,
        "dns_per_ip": dns_per_ip,
        "mdns_per_ip": mdns_per_ip,
        "wlan_features": wlan_features,
        "wlan_available": wlan_available,
    }


def _analyze_pcap_scapy(path, label="Session"):
    """Legacy scapy loader - kept as fallback when tshark is unavailable.
    Does not attempt SSID/BSSID extraction - returns None for both fields."""
    pkts = rdpcap(str(path))
    times = [float(p.time) for p in pkts]
    t0 = _safe_fromtimestamp(min(times))
    t1 = _safe_fromtimestamp(max(times))

    ips_src   = collections.Counter()
    bytes_src = collections.Counter()
    bytes_dst = collections.Counter()
    protocols = collections.Counter()
    macs      = collections.Counter()
    dns_q     = collections.Counter()
    pkt_sizes = []
    ip_pairs  = collections.Counter()
    arp_ip_to_macs = collections.defaultdict(set)
    arp_mac_to_ips = collections.defaultdict(set)
    syn_counter    = collections.Counter()
    rst_counter    = collections.Counter()
    fin_counter    = collections.Counter()
    null_counter   = collections.Counter()
    xmas_counter   = collections.Counter()
    timeline       = []
    dns_timeline   = []
    ip_to_mac      = collections.defaultdict(collections.Counter)
    ports_per_ip   = collections.defaultdict(set)
    dns_per_ip     = collections.defaultdict(collections.Counter)
    mdns_per_ip    = collections.defaultdict(set)

    for p in pkts:
        sz, ts = len(p), float(p.time)
        pkt_sizes.append(sz)
        protocols[p.lastlayer().name] += 1

        if p.haslayer("Ether"):
            macs[p["Ether"].src] += 1
        if p.haslayer("IP"):
            src, dst = p["IP"].src, p["IP"].dst
            ips_src[src]   += 1
            bytes_src[src] += sz
            bytes_dst[dst] += sz
            ip_pairs[(src, dst)] += 1
            timeline.append((ts, src, dst, sz))
            if p.haslayer("Ether"):
                ip_to_mac[src][p["Ether"].src] += 1
        if p.haslayer("TCP"):
            flags = int(p["TCP"].flags)
            if p.haslayer("IP"):
                src = p["IP"].src
                if (flags & 0x3F) == 0x02: syn_counter[src] += 1
                if flags & 0x04:  rst_counter[src] += 1
                masked = flags & 0x3F
                if masked == 0x01: fin_counter[src]  += 1
                if masked == 0x00: null_counter[src] += 1
                if masked == 0x29: xmas_counter[src] += 1
                try:
                    ports_per_ip[src].add(int(p["TCP"].sport))
                    ports_per_ip[src].add(int(p["TCP"].dport))
                except Exception:
                    pass
        if p.haslayer("UDP") and p.haslayer("IP"):
            src = p["IP"].src
            try:
                ports_per_ip[src].add(int(p["UDP"].sport))
                ports_per_ip[src].add(int(p["UDP"].dport))
            except Exception:
                pass
        if p.haslayer("ARP") and p.haslayer("Ether"):
            ip, mac = p["ARP"].psrc, p["Ether"].src
            if ip and ip != "0.0.0.0":
                arp_ip_to_macs[ip].add(mac)
                arp_mac_to_ips[mac].add(ip)
        if p.haslayer("DNS") and p["DNS"].qd:
            try:
                q = p["DNS"].qd.qname.decode(errors="ignore").rstrip(".")
                if q and len(q) > 3:
                    dns_q[q] += 1
                    if p.haslayer("IP"):
                        src_ip = p["IP"].src
                        dns_timeline.append((ts, src_ip, q))
                        dns_per_ip[src_ip][q] += 1
                        if q.endswith(".local"):
                            mdns_per_ip[src_ip].add(q)
            except:
                pass

    df_pkts = pd.DataFrame(timeline, columns=["time","src","dst","size"])
    ip_agg  = df_pkts.groupby("src").agg(
        count       = ("size","count"),
        total_bytes = ("size","sum"),
        mean_len    = ("size","mean"),
        std_len     = ("size","std"),
        unique_dsts = ("dst","nunique"),
    ).fillna(0)
    ip_agg["burst_score"] = ip_agg["count"] / (ip_agg["std_len"] + 1)
    ip_agg["dominance"]   = ip_agg["count"] + ip_agg["total_bytes"] / 1000
    ip_agg["syn_count"]   = ip_agg.index.map(lambda x: syn_counter.get(x,0))
    ip_agg["rst_count"]   = ip_agg.index.map(lambda x: rst_counter.get(x,0))
    ip_agg["fin_count"]   = ip_agg.index.map(lambda x: fin_counter.get(x,0))
    ip_agg["null_count"]  = ip_agg.index.map(lambda x: null_counter.get(x,0))
    ip_agg["xmas_count"]  = ip_agg.index.map(lambda x: xmas_counter.get(x,0))

    SKIP = re.compile(r"^_|^wpad$|^KMD|^BRW|^v1$|^server|^HP$", re.I)
    real_dns = {k:v for k,v in dns_q.items()
                if "." in k and not k.endswith(".local")
                and not SKIP.search(k.split(".")[0])}
    device_names = sorted(set(
        k for k in dns_q
        if k.endswith(".local") and not k.startswith("_")
        and not re.match(r"^[0-9a-f\-]{8,}", k) and len(k) > 8
    ))
    arp_spoofing_ips  = {ip:m for ip,m in arp_ip_to_macs.items() if len(m)>1}
    arp_spoofing_macs = {mac:ips for mac,ips in arp_mac_to_ips.items() if len(ips)>1}

    dns_nxdomain = sum(1 for p in pkts if p.haslayer("DNS")
                       and p["DNS"].qr==1 and p["DNS"].rcode==3)
    nxdomain_per_dst = collections.Counter(
        p["IP"].dst for p in pkts
        if p.haslayer("DNS") and p.haslayer("IP")
        and p["DNS"].qr==1 and p["DNS"].rcode==3)
    dns_nonstandard = sum(1 for p in pkts if p.haslayer("DNS")
                          and p.haslayer("UDP")
                          and p["UDP"].dport not in (53,5353))
    dns_long_queries = [k for k in dns_q if len(k)>60]

    return {
        "label":label, "pkts":pkts, "dns_timeline":dns_timeline,
        "wlan_features": {}, "wlan_available": False,
        "wifi_ssid": None, "wifi_bssid": None,
        "t0":t0, "t1":t1, "n_pkts":len(pkts),
        "pkt_sizes":pkt_sizes, "ips_src":ips_src,
        "bytes_src":bytes_src, "bytes_dst":bytes_dst,
        "protocols":protocols, "macs":macs,
        "dns_real":real_dns, "device_names":device_names,
        "ip_agg":ip_agg, "df_pkts":df_pkts, "ip_pairs":ip_pairs,
        "syn_counter":syn_counter, "rst_counter":rst_counter,
        "fin_counter":fin_counter, "null_counter":null_counter,
        "xmas_counter":xmas_counter,
        "dns_amp_per_src": {},
        "arp_spoofing_ips":arp_spoofing_ips,
        "arp_spoofing_macs":arp_spoofing_macs,
        "dns_nxdomain":dns_nxdomain,
        "nxdomain_per_dst":nxdomain_per_dst,
        "dns_nonstandard":dns_nonstandard,
        "dns_long_queries":dns_long_queries,
        "ip_to_mac":ip_to_mac,
        "ports_per_ip":ports_per_ip,
        "dns_per_ip":dns_per_ip,
        "mdns_per_ip":mdns_per_ip,
    }


def analyze_pcap(path, label="Session"):
    """Analyze a PCAP file. Uses tshark when available (5-7x faster), falls back to scapy.rdpcap otherwise. Produces the same dict in both paths. """
    if _TSHARK_PATH_FOR_LOADER:
        try:
            return _analyze_pcap_tshark(path, label, _TSHARK_PATH_FOR_LOADER)
        except Exception as e:
            print(f"  (tshark loader failed: {e}; falling back to scapy)")
    return _analyze_pcap_scapy(path, label)


print("analyze_pcap() ready  -  loader:",
      ("tshark @ " + _TSHARK_PATH_FOR_LOADER) if _TSHARK_PATH_FOR_LOADER else "scapy (slower)")


# ==== notebook cell 10 ====

S1 = None
S2 = None
ip_agg = None
z_scores = None
local_ip_agg = None
extern_ip_agg = None
compare_df = None
new_n = 0
gone_n = 0
SESSION_PCAPS = {"S1": None, "S2": None}
INSIGHTS_LINES = []


def load_session_from_pcap(pcap_path, label, csv_path=None):
    """Analyze a PCAP file and return the raw session dict. Optional CSV is attached under session['_csv'] for downstream reference."""
    print(f"Loading {label} from {os.path.basename(pcap_path)}...")
    session = analyze_pcap(pcap_path, label)
    session["_source_pcap"] = str(pcap_path)
    print(f"  {session['t0'].strftime('%Y-%m-%d %H:%M:%S')} -> "
          f"{session['t1'].strftime('%H:%M:%S')} | "
          f"{session['n_pkts']:,} packets | {len(session['ips_src'])} IPs")
    if csv_path and os.path.exists(csv_path):
        df = pd.read_csv(csv_path, encoding="latin1")
        df["Info"]   = df["Info"].fillna("").astype(str)
        df["Length"] = pd.to_numeric(df["Length"], errors="coerce").fillna(0)
        df["Time"]   = pd.to_numeric(df["Time"],   errors="coerce").fillna(0)
        session["_csv"] = df
        print(f"  CSV: {len(df):,} rows")
    return session


print("Empty state initialized. Sessions will be loaded via the dashboard.")


# ==== notebook cell 12 ====

def run_ml_on_session(S):
    """Run IsolationForest + DBSCAN on a session's per-IP feature matrix. Mutates S['ip_agg'] in-place to add columns: iso_score, iso_flag, anomaly, cluster."""
    if S is None or S.get("ip_agg") is None or len(S["ip_agg"]) == 0:
        print("  (no ip_agg available - skipping ML)")
        return

    import numpy as np
    from sklearn.neighbors import NearestNeighbors
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler

    ip_agg = S["ip_agg"]
    FEATURE_COLS = ["mean_len","std_len","count","burst_score",
                    "unique_dsts","syn_count","rst_count",
                    "fin_count","null_count","xmas_count"]
    X_raw = ip_agg[FEATURE_COLS].fillna(0).values
    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    print(f"[{S['label']}] Feature matrix: {X.shape[0]} IPs x {X.shape[1]} features")

    # Fixed contamination=0.10. A prior version swept [0.05, 0.10, 0.15]
    # with five seeds each and picked the most seed-stable value; we
    # measured that against the labeled ground-truth PCAPs and got mean
    # F1 = 0.247 (sweep) vs 0.250 (fixed=0.10) - the sweep never beat
    # fixed, and it did 15 forest fits per session. The stability column
    # stays as a compatibility field (all 1.0) so downstream views that
    # bind to it keep working.
    CONTAMINATION = 0.10
    print(f"[{S['label']}] IsolationForest contamination={CONTAMINATION:.2f} "
          f"(fixed, n_estimators=200, seed=42)")
    iso = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                          random_state=42)
    iso.fit(X)
    ip_agg["iso_score"] = iso.decision_function(X)
    ip_agg["iso_flag"]  = iso.predict(X)
    ip_agg["anomaly"]   = ip_agg["iso_flag"] == -1
    ip_agg["iso_stability"] = ip_agg["anomaly"].astype(float)

    k = 2
    nbrs = NearestNeighbors(n_neighbors=k).fit(X)
    distances, _ = nbrs.kneighbors(X)
    k_dist = np.sort(distances[:, k-1])[::-1]
    if len(k_dist) >= 4:
        d1 = np.diff(k_dist)
        d2 = np.diff(d1)
        elbow_idx = int(np.argmin(d2)) + 1
        eps_auto  = float(round(k_dist[elbow_idx], 2))
    else:
        eps_auto = 1.3

    # Two attack-traffic safety guards observed on real PCAPs:
    #   (a) eps from the k-NN elbow collapses to 0 when most rows are
    #       near-identical (e.g. 37k spoofed source IPs sending one SYN
    #       each) - DBSCAN then rejects eps=0 as invalid;
    #   (b) DBSCAN's neighbour graph is O(n^2) memory, so a 37k-IP
    #       spoofed flood blows the process past 10 GB. Both cases are
    #       caught below; the dashboard still runs and degrades to
    #       cluster=-1 (noise) for the affected session.
    if eps_auto <= 0:
        eps_auto = max(float(round(k_dist.mean(), 3)), 0.05)
        print(f"[{S['label']}] eps collapsed to 0 (near-identical rows); "
              f"using mean k-dist={eps_auto:.3f}")
    print(f"[{S['label']}] DBSCAN eps={eps_auto:.2f} (min_samples=2)")
    DBSCAN_MAX_IPS = 5000
    if len(ip_agg) > DBSCAN_MAX_IPS:
        print(f"[{S['label']}] DBSCAN skipped: {len(ip_agg):,} IPs > cap "
              f"{DBSCAN_MAX_IPS:,} (spoofed-flood pattern). All flagged "
              f"as noise (cluster=-1).")
        ip_agg["cluster"] = -1
    else:
        dbscan = DBSCAN(eps=eps_auto, min_samples=2)
        ip_agg["cluster"] = dbscan.fit_predict(X)

    # Cluster-quality diagnostics - stored so the dashboard can display them.
    from sklearn.metrics import silhouette_score
    _labels   = ip_agg["cluster"].values
    _nonnoise = _labels != -1
    _n_clusters = int(len(set(_labels[_nonnoise])))
    _n_noise    = int((_labels == -1).sum())
    try:
        if _nonnoise.sum() >= 2 and _n_clusters >= 2:
            _sil = float(silhouette_score(X[_nonnoise], _labels[_nonnoise]))
        else:
            _sil = None
    except Exception:
        _sil = None

    S["ip_agg"] = ip_agg
    S["_X"] = X
    S["_chosen_contamination"] = CONTAMINATION
    S["_eps_auto"]    = eps_auto
    S["_min_samples"] = 2
    S["_silhouette"]  = _sil
    S["_n_clusters"]  = _n_clusters
    S["_n_noise"]     = _n_noise
    print(f"[{S['label']}] DBSCAN clusters={_n_clusters} noise={_n_noise} "
          f"silhouette={('n/a' if _sil is None else round(_sil,3))}")
    print(f"[{S['label']}] Anomalies: {ip_agg['anomaly'].sum()} / {len(ip_agg)} | "
          f"Clusters: {ip_agg['cluster'].nunique()}")


# ==== notebook cell 14 ====

def compute_z_scores(S, my_ip):
    """Compute z-scores of local devices vs the local-network mean. Returns (z_scores_df, local_ip_agg, extern_ip_agg). my_ip used only for printout."""
    import ipaddress
    def _is_priv(ip):
        try: return ipaddress.ip_address(ip).is_private
        except ValueError: return False

    ip_agg = S["ip_agg"]
    FEATURE_COLS_PROFILE = ["count","total_bytes","mean_len","std_len",
                            "unique_dsts","burst_score","syn_count","rst_count"]

    local_mask    = pd.Series(ip_agg.index).apply(_is_priv).values
    local_ip_agg  = ip_agg[local_mask]
    extern_ip_agg = ip_agg[~local_mask]

    print(f"[{S['label']}] Local IPs: {local_mask.sum()} | External: {(~local_mask).sum()}")

    profile_df = local_ip_agg[FEATURE_COLS_PROFILE].copy()
    means = profile_df.mean()
    stds  = profile_df.std().replace(0, 1)
    z_scores = (profile_df - means) / stds

    if my_ip in z_scores.index:
        my_z   = z_scores.loc[my_ip]
        my_raw = profile_df.loc[my_ip]
        print(f"\n[{S['label']}] Device Profile: {my_ip} (vs {len(local_ip_agg)} local peers)")
        for feat in FEATURE_COLS_PROFILE:
            z   = my_z[feat]
            raw = my_raw[feat]
            avg = means[feat]
            flag = "EXTREME" if abs(z)>3 else ("HIGH" if abs(z)>2 else
                   ("above" if z>1 else "normal"))
            print(f"  {feat:<18} {raw:>14,.1f} {avg:>12,.1f} {z:>10.2f} {flag:>8}")

    return z_scores, local_ip_agg, extern_ip_agg


# ==== notebook cell 16 ====

def run_security_scans(S):
    """Run FTP/SMTP/SYN/ARP/DNS security scans on a single session. Returns a findings dict (also printed to stdout)."""
    findings = {"ftp": [], "smtp": [], "syn_top": [], "rst_top": [],
                "arp_spoofing": {}, "dns_long": [],
                "fin_top": [], "null_top": [], "xmas_top": [],
                "scan_alerts": [], "dns_amp": [], "flood": []}

    pkts = S.get("pkts") or []
    ftp_creds, smtp_lines = [], []
    for p in pkts:
        if not hasattr(p, "haslayer"): continue
        if not p.haslayer("TCP") or not p.haslayer("Raw"): continue
        try:
            payload = bytes(p["Raw"].load).decode("utf-8", errors="ignore")
            dport, sport = p["TCP"].dport, p["TCP"].sport
            if 21 in (dport, sport):
                for kw in ["USER", "PASS", "RETR", "STOR"]:
                    if payload.strip().startswith(kw):
                        ftp_creds.append(payload.strip()[:80])
            if 25 in (dport, sport) or 587 in (dport, sport):
                for kw in ["MAIL FROM", "RCPT TO", "DATA"]:
                    if kw in payload:
                        smtp_lines.append(payload.strip()[:80])
        except Exception:
            pass
    findings["ftp"]  = ftp_creds
    findings["smtp"] = smtp_lines

    findings["syn_top"]  = S["syn_counter"].most_common(5)
    findings["rst_top"]  = S["rst_counter"].most_common(5)
    findings["fin_top"]  = (S.get("fin_counter")  or collections.Counter()).most_common(5)
    findings["null_top"] = (S.get("null_counter") or collections.Counter()).most_common(5)
    findings["xmas_top"] = (S.get("xmas_counter") or collections.Counter()).most_common(5)
    findings["arp_spoofing"] = dict(S.get("arp_spoofing_ips", {}))
    findings["dns_long"]     = list(S.get("dns_long_queries", []))

    # Horizontal scan rule: any of {SYN, FIN, NULL, XMAS} flag counters with
    # > 50 hits and either many unique dsts or near-total flag-share is
    # treated as a scanner. Catches stealth scans the SYN-only rule misses.
    ip_agg_for_scan = S.get("ip_agg")
    if ip_agg_for_scan is not None:
        for name, cnt in (("SYN",  S["syn_counter"]),
                          ("FIN",  S.get("fin_counter")  or collections.Counter()),
                          ("NULL", S.get("null_counter") or collections.Counter()),
                          ("XMAS", S.get("xmas_counter") or collections.Counter())):
            # No top-5 truncation: walk every source above the 50-packet
            # floor, so a 6th+ scanner is not hidden behind heavier talkers.
            for src, n in sorted(cnt.items(), key=lambda kv: -kv[1]):
                if n <= 50:
                    break
                if not src or src not in ip_agg_for_scan.index:
                    continue
                row = ip_agg_for_scan.loc[src]
                n_pkt = int(row["count"])
                n_dst = int(row["unique_dsts"])
                ratio = n / max(n_pkt, 1)
                if n_dst > 20 or ratio > 0.7:
                    findings["scan_alerts"].append({
                        "src": src, "type": name, "count": int(n),
                        "unique_dsts": n_dst, "ratio": round(ratio, 2),
                    })

    # DNS amplification rule: any source IP that answered many DNS queries
    # out of UDP/53 with a large mean response size is flagged as a
    # reflector / amplification participant. Catches the response side that
    # the original DNS-tunneling rule (queries-only) misses.
    for ip, stats in (S.get("dns_amp_per_src") or {}).items():
        if stats["count"] >= 50 and stats["mean_size"] >= 200:
            findings["dns_amp"].append({
                "src": ip,
                "responses": stats["count"],
                "total_bytes": stats["total_bytes"],
                "mean_size": round(stats["mean_size"], 1),
            })

    # Aggregate spoofed-flood rule: a SYN flood from thousands of spoofed
    # sources leaves every per-IP counter at ~1 SYN, so the per-source scan
    # rule above can never fire and IsolationForest inverts (the flood rows
    # become the dense majority). Detect it from session-level aggregates.
    total_syn  = sum(S["syn_counter"].values())
    n_syn_srcs = len(S["syn_counter"])
    try:
        duration_s = max((S["t1"] - S["t0"]).total_seconds(), 1.0)
    except Exception:
        duration_s = 1.0
    syn_rate = total_syn / duration_s
    if total_syn >= 1000 and n_syn_srcs >= 100 and syn_rate >= 100:
        per_src = total_syn / n_syn_srcs
        findings["flood"].append({
            "type": "SYN_FLOOD",
            "total_syn": int(total_syn),
            "syn_sources": int(n_syn_srcs),
            "syn_per_sec": round(syn_rate, 1),
            "syn_per_source": round(per_src, 2),
            "spoofed_source_pattern": bool(per_src <= 3),
        })

    print(f"\n[{S['label']}] Security scan:")
    print(f"  FTP lines: {len(ftp_creds)} | SMTP lines: {len(smtp_lines)}")
    print(f"  Top SYN : {findings['syn_top']}")
    if findings['fin_top']:  print(f"  Top FIN : {findings['fin_top']}")
    if findings['null_top']: print(f"  Top NULL: {findings['null_top']}")
    if findings['xmas_top']: print(f"  Top XMAS: {findings['xmas_top']}")
    if findings['scan_alerts']:
        print(f"  Scanner alerts ({len(findings['scan_alerts'])}):")
        for a in findings['scan_alerts'][:8]:
            print(f"    {a['src']:<22} {a['type']:<5} count={a['count']:>5} "
                  f"unique_dsts={a['unique_dsts']:>4} ratio={a['ratio']}")
    if findings['dns_amp']:
        print(f"  DNS amp reflectors ({len(findings['dns_amp'])}):")
        for a in findings['dns_amp'][:8]:
            print(f"    {a['src']:<22} responses={a['responses']:>5} "
                  f"mean_size={a['mean_size']} bytes")
    if findings['flood']:
        for a in findings['flood']:
            tag = "spoofed-source" if a["spoofed_source_pattern"] else "concentrated"
            print(f"  FLOOD: {a['total_syn']:,} SYNs from {a['syn_sources']:,} sources "
                  f"@ {a['syn_per_sec']}/s ({tag})  *** SYN FLOOD ***")
    print(f"  ARP spoofing IPs: {len(findings['arp_spoofing'])}")
    print(f"  NXDOMAIN: {S['dns_nxdomain']} | Long DNS queries: {len(findings['dns_long'])}")
    return findings


# ==== notebook cell 18 ====

def compute_session_compare(S1, S2):
    """Build the comparison dataframe between two sessions. Returns (compare_df, new_n, gone_n)."""
    if S1 is None or S2 is None or S2.get("ips_src") is None:
        return (pd.DataFrame({
            "ip":       pd.Series(dtype="object"),
            "bytes_s1": pd.Series(dtype="int64"),
            "bytes_s2": pd.Series(dtype="int64"),
            "change":   pd.Series(dtype="int64"),
            "status":   pd.Series(dtype="object"),
        }), 0, 0)

    ips1, ips2 = set(S1["ips_src"]), set(S2["ips_src"])
    rows = []
    for ip in sorted(ips1 | ips2):
        b1 = S1["bytes_src"].get(ip, 0)
        b2 = S2["bytes_src"].get(ip, 0)
        if ip in ips1 and ip in ips2: status = "both"
        elif ip in ips2:              status = "new"
        else:                         status = "gone"
        rows.append({"ip":ip, "bytes_s1":b1, "bytes_s2":b2,
                     "change":b2-b1, "status":status})
    df = pd.DataFrame(rows)
    n_new  = int((df["status"]=="new").sum())
    n_gone = int((df["status"]=="gone").sum())
    print(f"Session compare: |S1|={len(ips1)} |S2|={len(ips2)} | "
          f"new={n_new} gone={n_gone}")
    return df, n_new, n_gone


# ==== notebook cell 20 ====

def generate_insights_lines(s1, s2, local_ip_agg_df, compare_df_arg, my_ip):
    """Build a list of one-line insights describing what is interesting in the captured traffic. Returns a list of strings."""
    lines = []
    if local_ip_agg_df is None or len(local_ip_agg_df) == 0:
        return lines

    dom_local = local_ip_agg_df["dominance"].idxmax()
    dom_b1 = s1["bytes_src"].get(dom_local, 0) / 1e6 if s1 else 0
    dom_b2 = s2["bytes_src"].get(dom_local, 0) / 1e6 if s2 else 0
    lines.append(f"Dominant LOCAL node: {dom_local} | "
                 f"S1={dom_b1:.1f}MB · S2={dom_b2:.1f}MB")

    if s2:
        import ipaddress
        def _is_priv(ip):
            try: return ipaddress.ip_address(ip).is_private
            except ValueError: return False
        ext_b = {ip:b for ip,b in s2["bytes_src"].items() if not _is_priv(ip)}
        if ext_b:
            top = max(ext_b, key=ext_b.get)
            lines.append(f"Largest external source (S2): {top} "
                         f"({ext_b[top]/1e6:.1f}MB)")

    total_spoof = 0
    if s1: total_spoof += len(s1.get("arp_spoofing_ips", {}))
    if s2: total_spoof += len(s2.get("arp_spoofing_ips", {}))
    lines.append("ARP: CLEAN - no spoofing detected" if total_spoof == 0
                 else f"ARP: WARNING - {total_spoof} suspicious IP-MAC mappings")

    if s1 and s2 and compare_df_arg is not None and len(compare_df_arg) > 0:
        nn  = int((compare_df_arg["status"]=="new").sum())
        ng  = int((compare_df_arg["status"]=="gone").sum())
        nb_ = int((compare_df_arg["status"]=="both").sum())
        lines.append(f"IP churn between sessions: {ng} gone, {nn} new, {nb_} persistent")

    if s2:
        top_dns = sorted(s2["dns_real"].items(), key=lambda x: x[1], reverse=True)[:3]
        if top_dns:
            lines.append("Top DNS services (S2): " +
                         ", ".join(f"{d} ({c}x)" for d,c in top_dns))
    return lines


def process_session(S, my_ip):
    """Run the full per-session pipeline: ML + LSTM + scans. Mutates S."""
    print(f"\n=== Processing {S['label']} ===")
    run_ml_on_session(S)
    try:
        m, Xt_all, yt_all, Xt_val, yt_val, hist = train_lstm_for_session(S, S['label'])
        evaluate_lstm(m, Xt_all, yt_all, Xt_val, yt_val, S, S['label'])
    except Exception as e:
        print(f"  LSTM skipped: {e}")
        S["lstm_errors"]    = [0.0] * 10
        S["lstm_threshold"] = 0.0
    S["_security_findings"] = run_security_scans(S)
    return S


def compute_pair_state(S1, S2, my_ip):
    """Compute dual-session state. Returns a dict that the dashboard reads."""
    global ip_agg, z_scores, local_ip_agg, extern_ip_agg
    global compare_df, new_n, gone_n, INSIGHTS_LINES

    primary = S2 if S2 is not None else S1
    ip_agg = primary["ip_agg"] if primary is not None else pd.DataFrame()

    if primary is not None:
        z_scores, local_ip_agg, extern_ip_agg = compute_z_scores(primary, my_ip)
    else:
        z_scores      = pd.DataFrame()
        local_ip_agg  = pd.DataFrame()
        extern_ip_agg = pd.DataFrame()

    compare_df, new_n, gone_n = compute_session_compare(S1, S2)
    INSIGHTS_LINES = generate_insights_lines(S1, S2, local_ip_agg, compare_df, my_ip)

    return {
        "ip_agg":      ip_agg,
        "z_scores":    z_scores,
        "local_ip_agg":local_ip_agg,
        "compare_df":  compare_df,
        "new_n":       new_n,
        "gone_n":      gone_n,
        "insights":    INSIGHTS_LINES,
    }


# ==== notebook cell 22 ====

class LSTMModel(nn.Module):
    def __init__(self, input_size=1, hidden_size=64):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc   = nn.Linear(hidden_size, 1)
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

print(f"LSTMModel class defined")


# ==== notebook cell 24 ====

import math
import tempfile

SEQ_LEN  = 10
MAX_BINS = 20000

def train_lstm_for_session(session, session_label):
    """Train an LSTM on per-second mean packet size for one session."""
    df_sorted = session["df_pkts"].sort_values("time").copy()
    df_sorted["second"] = ((df_sorted["time"] - df_sorted["time"].min()).astype(int))

    # Zero-fill idle seconds: a bare groupby drops seconds with no packets,
    # which stitches gaps together and hides silence-then-burst transitions
    # from the model. A second with no traffic is a real observation (0).
    per_sec = df_sorted.groupby("second")["size"].mean()
    n_secs  = int(df_sorted["second"].max()) + 1
    binned  = (per_sec.reindex(range(n_secs), fill_value=0.0)
               .values.astype(float))

    if len(binned) > MAX_BINS:
        stride = len(binned) // MAX_BINS
        binned = binned[::stride][:MAX_BINS]

    print(f"[{session_label}] Time bins used: {len(binned)} (each = ~1 second of traffic)")

    s_scaler = MinMaxScaler()
    seq_data = s_scaler.fit_transform(binned.reshape(-1, 1))

    def make_seqs(d, L):
        Xs = np.array([d[i:i+L] for i in range(len(d) - L)])
        ys = np.array([d[i+L]   for i in range(len(d) - L)])
        return Xs, ys

    Xn, yn = make_seqs(seq_data, SEQ_LEN)
    if len(Xn) < 10:
        raise ValueError(f"Too few sequences ({len(Xn)}) - need more data to train LSTM")

    split        = int(len(Xn) * 0.8)
    Xn_tr, Xn_val = Xn[:split], Xn[split:]
    yn_tr, yn_val = yn[:split], yn[split:]

    Xt_tr  = torch.tensor(Xn_tr,  dtype=torch.float32)
    yt_tr  = torch.tensor(yn_tr,  dtype=torch.float32)
    Xt_val = torch.tensor(Xn_val, dtype=torch.float32)
    yt_val = torch.tensor(yn_val, dtype=torch.float32)
    Xt_all = torch.tensor(Xn,     dtype=torch.float32)
    yt_all = torch.tensor(yn,     dtype=torch.float32)

    m = LSTMModel()
    opt  = torch.optim.Adam(m.parameters(), lr=0.001)
    crit = nn.MSELoss()
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(Xt_tr, yt_tr),
        batch_size=512, shuffle=True)

    MAX_EPOCHS, PATIENCE = 15, 2
    best_val   = math.inf
    patience   = PATIENCE
    hist       = []
    save_path  = os.path.join(tempfile.gettempdir(), f"lstm_best_{session_label}.pt")

    print(f"[{session_label}] Training on {len(Xn_tr):,} sequences | "
          f"val on {len(Xn_val):,} | batch=512 | max_epochs={MAX_EPOCHS}")

    for ep in range(MAX_EPOCHS):
        m.train()
        total = 0
        for xb, yb in loader:
            opt.zero_grad()
            l = crit(m(xb).squeeze(), yb.squeeze())
            l.backward(); opt.step()
            total += l.item()
        train_avg = total / len(loader)

        m.eval()
        with torch.no_grad():
            val_loss = crit(m(Xt_val).squeeze(), yt_val.squeeze()).item()

        hist.append((train_avg, val_loss))
        marker = " *" if val_loss < best_val else ""
        print(f"  Epoch {ep+1:02d}/{MAX_EPOCHS} | train={train_avg:.6f} | val={val_loss:.6f}{marker}")

        if val_loss < best_val:
            best_val = val_loss
            patience = PATIENCE
            torch.save(m.state_dict(), save_path)
        else:
            patience -= 1
            if patience == 0:
                print(f"  Early stop at epoch {ep+1}")
                break

    m.load_state_dict(torch.load(save_path))
    print(f"[{session_label}] Best val loss: {best_val:.6f}")
    return m, Xt_all, yt_all, Xt_val, yt_val, hist

print("train_lstm_for_session defined")


# ==== notebook cell 26 ====

def evaluate_lstm(m, Xt_all, yt_all, Xt_val, yt_val, session, label):
    m.eval()
    with torch.no_grad():
        val_preds  = m(Xt_val).squeeze()
        val_errors = torch.abs(val_preds - yt_val.squeeze()).numpy()
        all_preds  = m(Xt_all).squeeze()
        all_errors = torch.abs(all_preds - yt_all.squeeze()).numpy()

    threshold = val_errors.mean() + 2 * val_errors.std()
    anomalous = int((all_errors > threshold).sum())

    session["lstm_errors"]    = all_errors
    session["lstm_threshold"] = threshold

    print(f"[{label}] LSTM evaluation:")
    print(f"  Val MAE            : {val_errors.mean():.5f}")
    print(f"  Val std            : {val_errors.std():.5f}")
    print(f"  Anomaly threshold  : {threshold:.5f}")
    print(f"  Anomalous sequences: {anomalous:,} / {len(all_errors):,} "
          f"({anomalous/len(all_errors)*100:.1f}%)")

print("evaluate_lstm defined")


# ==== notebook cell 28 ====

pass


# ==== notebook cell 29 ====

pass


# ==== notebook cell 31 ====

pass


# ==== notebook cell 33 ====

pass


# ==== notebook cell 35 ====

pass


# ==== notebook cell 37 ====

import json, ipaddress, re, os, socket
from pathlib import Path
from collections import Counter, defaultdict


def _find_config(name):
    here = Path.cwd()
    for cand in [here / name, here.parent / name,
                 here / "app" / name, here.parent / "app" / name,
                 Path("/mnt/data") / name, Path.home() / name]:
        if cand.exists():
            return str(cand)
    raise FileNotFoundError(f"{name} not found. Place it next to the notebook.")

with open(_find_config("device_rules.json"), encoding="utf-8") as f:
    DEVICE_RULES = json.load(f)
with open(_find_config("cloud_ranges.json"), encoding="utf-8") as f:
    CLOUD_RANGES = json.load(f)
with open(_find_config("dns_fingerprints.json"), encoding="utf-8") as f:
    DNS_FINGERPRINTS = json.load(f)

print(f"Loaded {len(DEVICE_RULES['rules'])} device rules, "
      f"{len(CLOUD_RANGES['cidr_ranges'])} CIDR ranges, "
      f"{len(CLOUD_RANGES['rdns_patterns'])} rDNS patterns, "
      f"{len(DNS_FINGERPRINTS['fingerprints'])} DNS fingerprints")


_SORTED_RULES = sorted(DEVICE_RULES["rules"], key=lambda r: -r["priority"])
_FINGERPRINTS = DNS_FINGERPRINTS["fingerprints"]


def _load_oui_db():
    wireshark_paths = [
        "/usr/share/wireshark/manuf",
        "/usr/share/wireshark/wireshark/manuf",
        "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
        r"C:\Program Files\Wireshark\manuf",
        r"C:\Program Files (x86)\Wireshark\manuf",
    ]
    db = {}
    for path in wireshark_paths:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t") if "\t" in line else line.split(None, 2)
                        if len(parts) >= 2:
                            mac_pref = parts[0].upper().replace(":", "").replace("-", "")[:6]
                            vendor   = parts[-1].strip() if len(parts) > 2 else parts[1].strip()
                            if len(mac_pref) == 6:
                                db[mac_pref] = vendor
                print(f"OUI database loaded from {path}: {len(db):,} entries")
                return db
            except Exception as e:
                print(f"  ({path} failed: {e})")


    import shutil as _sh, subprocess as _sp
    tshark_cand = _sh.which('tshark')
    if not tshark_cand:
        for p in ['/usr/bin/tshark', '/usr/local/bin/tshark',
                  '/Applications/Wireshark.app/Contents/MacOS/tshark',
                  r'C:\Program Files\Wireshark\tshark.exe',
                  r'C:\Program Files (x86)\Wireshark\tshark.exe']:
            if os.path.exists(p):
                tshark_cand = p
                break
    if tshark_cand:
        try:
            out = _sp.check_output([tshark_cand, '-G', 'manuf'],
                                    stderr=_sp.DEVNULL,
                                    encoding='utf-8', errors='replace', timeout=20)
            db = {}
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                mac_field = parts[0].strip().split('/')[0]
                clean = mac_field.upper().replace(':', '').replace('-', '')
                if len(clean) != 6 or not all(c in '0123456789ABCDEF' for c in clean):
                    continue
                vendor = parts[-1].strip() if len(parts) >= 3 else parts[1].strip()
                if not vendor:
                    continue
                if clean not in db:
                    db[clean] = vendor
            if len(db) > 100:
                print(f"OUI database loaded from `tshark -G manuf`: {len(db):,} entries  ({tshark_cand})")
                return db
            else:
                print(f"  (tshark -G manuf returned only {len(db)} entries - falling through)")
        except Exception as e:
            print(f"  (tshark -G manuf failed: {e})")

    try:
        from manuf import manuf as _manuf
        parser = _manuf.MacParser()
        print("OUI database: using `manuf` Python package")

        class _PkgWrapper:
            def get(self, prefix, default=""):

                mac = ":".join(prefix[i:i+2] for i in range(0, 6, 2)) + ":00:00:00"
                return parser.get_manuf_long(mac) or default
            def __len__(self): return -1
            def __contains__(self, k): return True
        return _PkgWrapper()
    except ImportError:
        pass

    print("OUI database: using minimal embedded fallback (~30 vendors)")
    return {
        "001CB3":"Apple, Inc.", "0017F2":"Apple, Inc.", "F0DBF8":"Apple, Inc.",
        "B8FF61":"Apple, Inc.", "78CA39":"Apple, Inc.",
        "001632":"Samsung Electronics", "BCD0E9":"Samsung Electronics",
        "001A11":"Google, Inc.", "6CADF8":"Google, Inc.", "F4F5D8":"Google, Inc.",
        "00FC8B":"Amazon Technologies", "18742E":"Amazon Technologies",
        "001485":"Hewlett-Packard", "0017A4":"Hewlett-Packard",
        "001D60":"ASUSTek Computer", "BC305B":"Dell Inc",
        "00146C":"Netgear", "001A2B":"TP-Link Technologies",
        "00040D":"Avaya", "00132F":"Cisco Systems",
        "001CC0":"Intel Corporate", "8C8590":"Intel Corporate",
        "00078E":"Sony Corporation", "FCF152":"Sony Corporation",
        "00037A":"Microsoft Corporation", "9C4FDA":"Microsoft Corporation",
        "0CF346":"Nintendo Co", "B889E9":"Roku",
        "1894EF":"Polycom", "001565":"Yealink",
        "B827EB":"Raspberry Pi Foundation",
    }

OUI_DB = _load_oui_db()

def oui_lookup(mac):
    """Return vendor for a MAC. Empty string if unknown."""
    if not mac: return ""
    clean = mac.upper().replace(":", "").replace("-", "")
    if len(clean) < 6: return ""
    return OUI_DB.get(clean[:6], "")

def is_random_mac(mac):
    """U/L bit of first octet set = locally administered (randomized)."""
    if not mac: return False
    try:
        first = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first & 0b00000010)
    except Exception:
        return False


def _match_dns_fingerprint(dns_queries):
    """Match a device's DNS history against the fingerprint database. Returns (fp_dict, n_matches) or (None, 0) if no fingerprint hits its threshold. A signature domain matches if it appears as a substring of any DNS query (case-insensitive). Patterns containing regex metacharacters are also tried as regex. """
    if not dns_queries: return None, 0
    queries_lower = [q.lower() for q in dns_queries]
    best_fp, best_score = None, 0
    for fp in _FINGERPRINTS:
        thresh = fp.get("match_threshold", 1)
        matched_domains = 0
        for sig in fp.get("signature_domains", []):
            sig_l = sig.lower()

            if any(sig_l in q for q in queries_lower):
                matched_domains += 1
                continue

            if any(c in sig_l for c in "[](){}*+?|\\^$"):
                try:
                    rx = re.compile(sig_l, re.I)
                    if any(rx.search(q) for q in queries_lower):
                        matched_domains += 1
                except re.error:
                    pass
        if matched_domains >= thresh and matched_domains > best_score:
            best_fp, best_score = fp, matched_domains
    return best_fp, best_score


def _behavioral_classify(port_set, dns_queries, vendor_from_oui, mac_random):
    """When no rule and no DNS fingerprint matches, classify by what ports the device used. Always returns a specific category - never 'Unknown'. """
    has_web   = bool(port_set & {80, 443, 8080, 8443})
    has_dns   = bool(port_set & {53, 5353})
    only_basic = port_set.issubset({80, 443, 53, 5353, 67, 68, 123, 5060, 5061})


    if 554 in port_set:
        return ({"category":"Security & Cameras", "subcategory":"IP Camera",
                 "vendor": vendor_from_oui or "Generic",
                 "model": f"{vendor_from_oui or 'Generic'} IP camera (RTSP-detected)",
                 "rule_id":"behav-rtsp"}, "low")
    if {9100, 631, 515} & port_set:
        return ({"category":"Office", "subcategory":"Printer",
                 "vendor": vendor_from_oui or "Generic",
                 "model": f"{vendor_from_oui or 'Generic'} network printer (port-detected)",
                 "rule_id":"behav-printer"}, "low")
    if {5060, 5061, 2000} & port_set:
        return ({"category":"Office", "subcategory":"VoIP Phone",
                 "vendor": vendor_from_oui or "Generic",
                 "model": f"{vendor_from_oui or 'Generic'} VoIP phone (SIP-detected)",
                 "rule_id":"behav-voip"}, "low")
    if {8008, 8009, 8443} & port_set and "Google" in (vendor_from_oui or ""):
        return ({"category":"Entertainment", "subcategory":"Chromecast",
                 "vendor":"Google","model":"Chromecast (port-detected)",
                 "rule_id":"behav-cast"}, "low")
    if {62078} & port_set:
        return ({"category":"Mobile", "subcategory":"iPhone",
                 "vendor":"Apple","model":"iPhone (port 62078 detected)",
                 "rule_id":"behav-iphone"}, "medium")
    if 1900 in port_set:
        return ({"category":"Smart Home", "subcategory":"UPnP Device",
                 "vendor": vendor_from_oui or "Generic",
                 "model": f"{vendor_from_oui or 'Generic'} UPnP/SSDP device",
                 "rule_id":"behav-ssdp"}, "low")
    if {1883, 8883} & port_set:
        return ({"category":"Smart Home", "subcategory":"IoT Hub",
                 "vendor": vendor_from_oui or "Generic",
                 "model":"MQTT IoT device","rule_id":"behav-mqtt"}, "medium")


    if has_web and only_basic:
        if mac_random or not vendor_from_oui:
            return ({"category":"Mobile", "subcategory":"Generic phone/laptop",
                     "vendor": vendor_from_oui or "Generic",
                     "model":"Web client (likely phone or laptop)",
                     "rule_id":"behav-web-mobile"}, "very-low")
        else:
            return ({"category":"Computers", "subcategory":"Laptop",
                     "vendor": vendor_from_oui,
                     "model": f"{vendor_from_oui} computer (web traffic only)",
                     "rule_id":"behav-web-computer"}, "very-low")


    if vendor_from_oui:
        return ({"category":"Generic Endpoint",
                 "subcategory": vendor_from_oui.split(",")[0] or "Endpoint",
                 "vendor": vendor_from_oui,
                 "model": f"{vendor_from_oui} device (unspecified type)",
                 "rule_id":"behav-vendor-only"}, "very-low")


    return ({"category":"Generic Endpoint", "subcategory":"Network Endpoint",
             "vendor":"Generic",
             "model":"Network endpoint (no signals available)",
             "rule_id":"behav-default"}, "very-low")


def classify_local_device(mac, mdns_names, ports, dns_queries):
    """Three-tier classification. NEVER returns Unknown - every device gets a specific category and subtype. The confidence field tells you how sure. Tier 1: rule-based (OUI + mDNS + ports + DNS regex) - confidence: high Tier 2: DNS fingerprint database - confidence: medium Tier 3: behavioural port analysis - confidence: low/very-low Returns dict with: category, subcategory, vendor, model, rule_id, vendor_from_oui, mac, confidence, mac_privacy_random """
    vendor_from_oui = oui_lookup(mac) if mac else ""
    mac_random      = is_random_mac(mac)
    mdns_blob       = " ".join(mdns_names).lower() if mdns_names else ""
    dns_blob        = " ".join(dns_queries).lower() if dns_queries else ""
    port_set        = set(ports) if ports else set()


    for rule in _SORTED_RULES:
        c = rule["conditions"]


        if c.get("mac_is_random") is True:
            continue
        ok = True
        if "vendor_match" in c:
            if c["vendor_match"].lower() not in vendor_from_oui.lower():
                ok = False
        if ok and "mdns_regex" in c:
            if not re.search(c["mdns_regex"], mdns_blob, re.I):
                ok = False
        if ok and "ports_any" in c:
            if not any(p in port_set for p in c["ports_any"]):
                ok = False
        if ok and "dns_regex" in c:
            if not re.search(c["dns_regex"], dns_blob, re.I):
                ok = False
        if ok:

            pri = rule.get("priority", 100)
            if pri >= 800:   tier1_conf = "high"
            elif pri >= 500: tier1_conf = "medium"
            elif pri >= 200: tier1_conf = "low"
            else:            tier1_conf = "very-low"
            return {
                **rule["classification"],
                "rule_id":            rule["id"],
                "vendor_from_oui":    vendor_from_oui,
                "mac":                mac or "",
                "confidence":         tier1_conf,
                "mac_privacy_random": mac_random,
            }


    fp, n_matched = _match_dns_fingerprint(dns_queries)
    if fp:
        return {
            "category":           fp["device_type"],
            "subcategory":        fp["subtype"],
            "vendor":             fp["vendor"],
            "model":              f"{fp['model']} (DNS-matched, {n_matched} signals)",
            "rule_id":            f"dns-fp:{fp['id']}",
            "vendor_from_oui":    vendor_from_oui,
            "mac":                mac or "",
            "confidence":         fp.get("confidence", "medium"),
            "mac_privacy_random": mac_random,
        }


    behav, conf = _behavioral_classify(port_set, dns_queries,
                                        vendor_from_oui, mac_random)
    return {
        **behav,
        "vendor_from_oui":    vendor_from_oui,
        "mac":                mac or "",
        "confidence":         conf,
        "mac_privacy_random": mac_random,
    }


_NETWORKS = []
for entry in CLOUD_RANGES["cidr_ranges"]:
    try:
        _NETWORKS.append((ipaddress.ip_network(entry["cidr"], strict=False), entry))
    except Exception:
        pass
_RDNS_REGEXES = [(re.compile(p["pattern"], re.I), p) for p in CLOUD_RANGES["rdns_patterns"]]
_STATIC_IPS   = CLOUD_RANGES["static_ips"]


# Reverse-DNS resolution.
#
# The naive implementation used socket.setdefaulttimeout(0.6) before
# gethostbyaddr, but on Windows gethostbyaddr goes through the Windows
# DNS API which IGNORES the socket default timeout - each miss blocks
# for the OS retry cycle (~3-4s). Measured on the labeled ground truth:
# rDNS was 88-94% of ingest wall time on captures with external IPs
# (see docs/PERFORMANCE_AUDIT_HE.md, local-only). Two fixes together:
#
#   1) Hard timeout via a worker thread we cut off on our schedule -
#      the socket call still hangs in the OS, but nothing we do waits
#      for it beyond the timeout.
#   2) A parallel batch resolver (ThreadPoolExecutor) so N lookups
#      run concurrently. 20 workers x 0.6s = ~1s for the first batch.
#
# rDNS is OFF by default from this version. Set NETSEC_ENABLE_RDNS=1
# in the environment to re-enable it; the CIDR-based provider lookup
# still runs regardless, so most cloud IPs are still identified.
import concurrent.futures
import threading

_RDNS_CACHE = {}
_RDNS_LOCK  = threading.Lock()
RDNS_ENABLED = os.environ.get("NETSEC_ENABLE_RDNS", "0").lower() \
    not in ("0", "false", "")


def _rdns_lookup_blocking(ip):
    """Raw call; runs in a worker thread, may hang for the OS DNS
    retry cycle. Do not call directly - use _rdns_lookup."""
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""


def _rdns_lookup(ip, timeout=0.6):
    """Bounded rDNS: returns the reverse hostname or "" within
    `timeout` seconds regardless of what the OS is doing. Reads and
    writes _RDNS_CACHE under a lock so parallel callers stay coherent."""
    with _RDNS_LOCK:
        if ip in _RDNS_CACHE:
            return _RDNS_CACHE[ip]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            host = ex.submit(_rdns_lookup_blocking, ip).result(
                timeout=timeout)
    except concurrent.futures.TimeoutError:
        host = ""
    except Exception:
        host = ""
    with _RDNS_LOCK:
        _RDNS_CACHE[ip] = host
    return host


def _rdns_lookup_batch(ips, timeout=0.6, max_workers=20):
    """Resolve `ips` concurrently, returning {ip: host}. Each individual
    lookup is bounded by `timeout`; the whole batch is bounded by
    len(ips) * timeout / max_workers in the worst case (all miss)."""
    ips = list(ips)
    result = {}
    # Serve cached hits without spawning threads.
    to_do = []
    with _RDNS_LOCK:
        for ip in ips:
            if ip in _RDNS_CACHE:
                result[ip] = _RDNS_CACHE[ip]
            else:
                to_do.append(ip)
    if not to_do:
        return result
    total_deadline = max(1.0, timeout * len(to_do) / max_workers
                         + timeout)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers) as ex:
        futures = {ex.submit(_rdns_lookup_blocking, ip): ip
                   for ip in to_do}
        try:
            for fut in concurrent.futures.as_completed(
                    futures, timeout=total_deadline):
                ip = futures[fut]
                try:
                    host = fut.result(timeout=timeout)
                except Exception:
                    host = ""
                result[ip] = host
        except concurrent.futures.TimeoutError:
            # Batch deadline hit: some workers are still blocked in the
            # OS DNS retry cycle. Whatever we did resolve stays in
            # `result`; the rest fall back to "" below. Cancel queued
            # (not-yet-started) work so shutdown does not wait on it.
            for fut in futures:
                fut.cancel()
    # Anything that never returned falls back to "" so a slow DNS
    # server never poisons the caller.
    for ip in to_do:
        result.setdefault(ip, "")
    with _RDNS_LOCK:
        _RDNS_CACHE.update(result)
    return result


def classify_external_ip(ip, do_rdns=None):
    """Identify provider/service for a non-local IP. Returns dict."""

    if ip in _STATIC_IPS:
        s = _STATIC_IPS[ip]
        return {**s, "rule_id":"static", "ip":ip, "rdns":""}

    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return {"provider":"Invalid", "service":"", "type":"", "rule_id":"none", "ip":ip, "rdns":""}
    for net, entry in _NETWORKS:
        if ip_obj in net:
            return {**entry, "rule_id":"cidr", "ip":ip, "rdns":""}

    _do = RDNS_ENABLED if do_rdns is None else bool(do_rdns)
    if _do:
        host = _rdns_lookup(ip)
        if host:
            for rx, p in _RDNS_REGEXES:
                if rx.search(host):
                    return {**p, "rule_id":"rdns", "ip":ip, "rdns":host}

            return {"provider":"Unknown", "service":host, "type":"Unclassified",
                    "rule_id":"rdns-only", "ip":ip, "rdns":host}
    return {"provider":"Unknown", "service":"", "type":"Unclassified",
            "rule_id":"none", "ip":ip, "rdns":""}

print("Device classification engine ready.")


# ==== notebook cell 39 ====

import pandas as pd
import ipaddress as _ipa
from collections import Counter as _Counter

def _is_private(ip):
    try:
        return _ipa.ip_address(ip).is_private
    except Exception:
        return False

def _pick_dominant_mac(mac_counter):
    """For an IP that appeared with several MACs, pick the most common one."""
    if not mac_counter:
        return ""
    return mac_counter.most_common(1)[0][0]

def _derive_device_name(ip, mdns_names, model):
    """Pick a friendly device name. Prefer mDNS hostname, else model+last-octet."""
    for n in mdns_names:

        clean = n.split("._")[0].rstrip(".")
        if clean.endswith(".local"):
            clean = clean[:-6].rstrip(".")
        if 3 <= len(clean) <= 40 and not clean.startswith("_"):
            return clean

    last = ip.split(".")[-1] if ip.count(".") == 3 else "?"
    base = model.split("(")[0].strip().replace(" ", "-")
    return f"{base}-{last}"


def compute_threat_score(ip, session):
    """Return (score, tier, reasons) for one IP. Pure heuristic - no ML required. Signals (weighted, capped): • TCP SYN burst (0-30 pts) • Unique destinations (0-20 pts) - port-scan signature • TCP RST flood (0-10 pts) • Many ports used (0-10 pts) - additional scan signal • ARP spoofing (+25 pts) • DNS tunneling (0-15 pts) • NXDOMAIN burst (0-10 pts) • Multi-signal bonus (+10 if ≥3 independent signals) """
    score, reasons = 0, []
    n_signals = 0
    ip_agg = session.get("ip_agg")
    if ip_agg is not None and ip in ip_agg.index:
        row = ip_agg.loc[ip]

        syn = int(row.get("syn_count", 0))
        if syn >= 1000:
            score += 30; n_signals += 1
            reasons.append(f"Severe SYN burst - {syn} packets")
        elif syn >= 200:
            score += 15 + min(15, (syn - 200) // 50); n_signals += 1
            reasons.append(f"TCP SYN burst - {syn} packets")
        elif syn >= 50:
            score += min(10, syn // 20); n_signals += 1
            reasons.append(f"Elevated SYN count - {syn} packets")

        u = int(row.get("unique_dsts", 0))
        if u >= 200:
            score += 20; n_signals += 1
            reasons.append(f"{u} unique destinations - heavy port scan")
        elif u >= 100:
            score += 10 + (u - 100) // 20; n_signals += 1
            reasons.append(f"{u} unique destinations - scan-like")
        elif u >= 50:
            score += 5; n_signals += 1
            reasons.append(f"{u} unique destinations")

        rst = int(row.get("rst_count", 0))
        if rst >= 100:
            score += min(10, rst // 30); n_signals += 1
            reasons.append(f"TCP RST flood - {rst} packets")

    port_set = session.get("ports_per_ip", {}).get(ip, set())
    n_ports = len(port_set)
    if n_ports >= 100:
        score += 10; n_signals += 1
        reasons.append(f"{n_ports} distinct ports - likely port-scan footprint")
    elif n_ports >= 30:
        score += 5; n_signals += 1
        reasons.append(f"{n_ports} distinct ports - broad port usage")

    if ip in session.get("arp_spoofing_ips", {}):
        score += 25; n_signals += 1
        reasons.append("ARP IP↔MAC inconsistency - possible spoofing")

    # Long-query and NXDOMAIN signals are attributed per-IP: one infected
    # machine's DNS storm must not raise the threat tier of every device
    # in the inventory.
    dns_per_ip = session.get("dns_per_ip", {}).get(ip, _Counter())
    n_dns_long = sum(1 for q in dns_per_ip if len(q) > 60)
    if n_dns_long > 0:
        score += min(15, n_dns_long * 3); n_signals += 1
        reasons.append(f"{n_dns_long} long DNS queries from this IP (tunneling-like)")

    nxd = session.get("nxdomain_per_dst", {}).get(ip, 0)
    if nxd >= 50:
        score += min(10, nxd // 50); n_signals += 1
        reasons.append(f"{nxd} NXDOMAIN responses to this IP")

    if n_signals >= 3:
        score += 10
        reasons.append(f"Compound risk - {n_signals} independent signals")
    score = min(100, score)
    if   score >= 75: tier = "CRITICAL"
    elif score >= 50: tier = "HIGH"
    elif score >= 25: tier = "MEDIUM"
    else:             tier = "LOW"
    return score, tier, reasons


def build_local_inventory(s):
    """Inventory of local devices (RFC-1918 IPs) with classification + threat. Output columns: device_name, ip, mac, category, subcategory, vendor, model, confidence, mac_privacy_random, threat_score, threat_tier, threat_reasons, packets, bytes, ports, rule_id, vendor_oui """
    rows = []
    ip_to_mac    = s.get("ip_to_mac", {})
    ports_per_ip = s.get("ports_per_ip", {})
    mdns_per_ip  = s.get("mdns_per_ip", {})
    dns_per_ip   = s.get("dns_per_ip", {})

    for ip in s["ips_src"]:
        if not _is_private(ip):
            continue
        mac     = _pick_dominant_mac(ip_to_mac.get(ip, _Counter()))
        mdns_l  = list(mdns_per_ip.get(ip, set()))
        ports_l = list(ports_per_ip.get(ip, set()))
        dns_l   = list(dns_per_ip.get(ip, _Counter()).keys())
        cls     = classify_local_device(mac, mdns_l, ports_l, dns_l)

        n_pkts  = s["ips_src"][ip]
        n_bytes = s["bytes_src"].get(ip, 0) + s["bytes_dst"].get(ip, 0)
        score, tier, reasons = compute_threat_score(ip, s)
        dev_name = _derive_device_name(ip, mdns_l, cls["model"])

        rows.append({
            "device_name":        dev_name,
            "ip":                 ip,
            "mac":                mac,
            "category":           cls["category"],
            "subcategory":        cls["subcategory"],
            "vendor":             cls["vendor"],
            "model":              cls["model"],
            "confidence":         cls.get("confidence", "low"),
            "mac_privacy_random": cls.get("mac_privacy_random", False),
            "threat_score":       score,
            "threat_tier":        tier,
            "threat_reasons":     "; ".join(reasons) if reasons else "-",
            "packets":            n_pkts,
            "bytes":              n_bytes,
            "ports":              len(ports_l),
            "rule_id":            cls["rule_id"],
            "vendor_oui":         cls.get("vendor_from_oui", ""),
        })
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)


    df["identified"] = df["confidence"].isin(["high","medium"])

    tier_order = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3}
    df["__tier_rank"] = df["threat_tier"].map(tier_order)
    df = df.sort_values(["__tier_rank","threat_score","bytes"],
                        ascending=[True, False, False]).drop(columns="__tier_rank")
    return df.reset_index(drop=True)

def build_external_inventory(s, do_rdns=None, max_rdns=200):
    """Inventory of external IPs. rDNS lookups are limited to top-`max_rdns`
    by bytes AND are resolved in parallel (concurrent.futures) with a hard
    timeout - a hanging DNS query cannot stall ingest. do_rdns=None honors
    RDNS_ENABLED (env-var NETSEC_ENABLE_RDNS)."""
    rows = []

    external_bytes = _Counter()
    for ip, b in s["bytes_src"].items():
        if not _is_private(ip):
            external_bytes[ip] += b
    for ip, b in s["bytes_dst"].items():
        if not _is_private(ip):
            external_bytes[ip] += b


    _do = RDNS_ENABLED if do_rdns is None else bool(do_rdns)
    top_n = set(ip for ip, _ in external_bytes.most_common(max_rdns))
    # Warm the rDNS cache in parallel so classify_external_ip below only
    # hits the cache. Without this, each classify_external_ip call would
    # sequentially block on socket.gethostbyaddr - measured at 88-94% of
    # ingest wall time on captures with many external IPs.
    if _do and top_n:
        _rdns_lookup_batch(top_n)
    for ip, total_b in external_bytes.most_common():
        cls = classify_external_ip(ip, do_rdns=(_do and ip in top_n))
        rows.append({
            "ip":       ip,
            "bytes":    total_b,
            "provider": cls.get("provider", "Unknown"),
            "service":  cls.get("service", ""),
            "type":     cls.get("type", "Unclassified"),
            "rule_id":  cls.get("rule_id", "none"),
            "rdns":     cls.get("rdns", ""),
            "identified": cls.get("provider", "Unknown") != "Unknown",
        })
    df = pd.DataFrame(rows).sort_values("bytes", ascending=False) if rows else pd.DataFrame()
    return df


LOCAL_INV_S1    = pd.DataFrame()
LOCAL_INV_S2    = pd.DataFrame()
EXTERNAL_INV_S1 = pd.DataFrame()
EXTERNAL_INV_S2 = pd.DataFrame()

print()
print(f"S1 local devices: {len(LOCAL_INV_S1)}  | external IPs: {len(EXTERNAL_INV_S1)}")
print(f"S2 local devices: {len(LOCAL_INV_S2)}  | external IPs: {len(EXTERNAL_INV_S2)}")


def compute_coverage(local_df, external_df):
    """Return a dict of coverage stats."""
    def _stats(df, label):
        if df is None or len(df) == 0:
            return {f"{label}_total_ips":0, f"{label}_identified_ips":0,
                    f"{label}_total_bytes":0, f"{label}_identified_bytes":0,
                    f"{label}_pct_ips":0.0, f"{label}_pct_bytes":0.0}
        total_ips    = len(df)
        ident_ips    = int(df["identified"].sum())
        total_bytes  = int(df["bytes"].sum())
        ident_bytes  = int(df.loc[df["identified"], "bytes"].sum())
        return {
            f"{label}_total_ips":      total_ips,
            f"{label}_identified_ips": ident_ips,
            f"{label}_total_bytes":    total_bytes,
            f"{label}_identified_bytes": ident_bytes,
            f"{label}_pct_ips":        (ident_ips/total_ips*100) if total_ips else 0.0,
            f"{label}_pct_bytes":      (ident_bytes/total_bytes*100) if total_bytes else 0.0,
        }
    out = {}
    out.update(_stats(local_df,    "local"))
    out.update(_stats(external_df, "external"))
    return out

COVERAGE_S1 = {"local_total_ips":0,"local_identified_ips":0,
               "local_total_bytes":0,"local_identified_bytes":0,
               "local_pct_ips":0,"local_pct_bytes":0,
               "external_total_ips":0,"external_identified_ips":0,
               "external_total_bytes":0,"external_identified_bytes":0,
               "external_pct_ips":0,"external_pct_bytes":0}
COVERAGE_S2 = dict(COVERAGE_S1)

print("Inventory & coverage scaffolding ready. Empty until a session is loaded.")


# ==== notebook cell 41 ====

""" - : Streaming live capture with dual-session UI support. Architecture: LiveCaptureWorker manages ONE session: tshark subprocess + reader thread - tshark writes raw pcap to disk AND outputs parsed fields to stdout - Reader thread parses each stdout line and updates in-memory Counters - Pause = kill subprocess (its pcap chunk closes cleanly) - Resume = relaunch tshark to a NEW pcap chunk (data in memory persists) - Stop&Save = pause + merge all chunks via mergecap into a single .pcap - LIVE_SESSIONS = {"S1": worker, "S2": worker} - global, refresh-safe Browser refresh does NOT lose state because all data lives in Python globals,
NOT in Dash component state. Dash callbacks only read snapshots.
"""
import os, time, threading, subprocess, shutil
from collections import Counter, defaultdict
from datetime import datetime


def _find_tool(name):
    cand = shutil.which(name)
    if cand: return cand
    for p in (rf"C:\Program Files\Wireshark\{name}.exe",
              rf"C:\Program Files (x86)\Wireshark\{name}.exe",
              f"/usr/bin/{name}", f"/usr/local/bin/{name}",
              f"/Applications/Wireshark.app/Contents/MacOS/{name}"):
        if os.path.exists(p):
            return p
    return None

TSHARK_PATH   = _find_tool("tshark")
MERGECAP_PATH = _find_tool("mergecap")


_INTERFACE_LIST_CACHE = None    # cache for list_capture_interfaces() (tshark -D is slow)


def _default_project_save_dir():
    """Where live recordings get saved by default.
    Walks up from the notebook's cwd looking for a marker that identifies
    the project root (an 'app/' subdir or a README.md sibling), and returns
    <project_root>/netsec_sessions. Recordings therefore travel with the
    project rather than leaking into the user's home directory.

    Falls back to <cwd>/netsec_sessions if nothing is recognisable - the
    folder is still created on first access by __init__."""
    from pathlib import Path as _Path
    here = _Path.cwd().resolve()
    # candidates in priority order: cwd, parent (if cwd is app/), grandparent
    for cand in (here, here.parent, here.parent.parent):
        try:
            if (cand / "app").is_dir() or (cand / "README.md").is_file():
                return str(cand / "netsec_sessions")
        except Exception:
            pass
    return str(here / "netsec_sessions")


def list_capture_interfaces():
    """Return [(id, friendly_name), ...] for available capture interfaces.
    Results are cached in a module-global so the tshark -D subprocess
    (which takes 1-3 seconds on Windows) runs once per kernel, NOT on every
    Live Recording panel rebuild. Eliminates the multi-second freeze the
    user hit on every click. Call list_capture_interfaces.cache_clear() to
    force a re-scan if a new NIC is plugged in mid-session."""
    global _INTERFACE_LIST_CACHE
    if _INTERFACE_LIST_CACHE is not None:
        return _INTERFACE_LIST_CACHE
    if not TSHARK_PATH:
        _INTERFACE_LIST_CACHE = [("0", "(tshark not available - install Wireshark)")]
        return _INTERFACE_LIST_CACHE
    try:
        out = subprocess.check_output([TSHARK_PATH, "-D"],
            encoding="utf-8", errors="replace", timeout=10,
            stderr=subprocess.STDOUT)
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line or "." not in line: continue
            num, rest = line.split(".", 1)
            rows.append((num.strip(), rest.strip()))
        _INTERFACE_LIST_CACHE = rows or [("?", "(no interfaces - may need admin / sudo)")]
        return _INTERFACE_LIST_CACHE
    except Exception as e:
        # do NOT cache an error - retry next time
        return [("?", f"error listing: {e}")]

class LiveCaptureWorker:
    """Single live capture session. Thread-safe. Persists across browser refresh."""

    TSHARK_FIELDS = [
        "frame.time_epoch", "frame.len",
        "eth.src", "ip.src", "ip.dst",
        "_ws.col.Protocol",
        "tcp.srcport", "tcp.dstport", "tcp.flags",
        "udp.srcport", "udp.dstport",
        "dns.qry.name", "dns.flags.rcode", "dns.flags.response",
        "arp.src.proto_ipv4", "arp.src.hw_mac",
        # Appended, not inserted: _process_line indexes positionally.
        "ipv6.src", "ipv6.dst",
    ]

    MIN_SECONDS = 120
    MAX_SECONDS = 3600
    _LIVE_FEATURE_COLS = ["mean_len", "std_len", "count", "burst_score",
                          "unique_dsts", "syn_count", "rst_count",
                          "fin_count", "null_count", "xmas_count"]

    def __init__(self, label, save_dir=None):
        self.label    = label
        # Save recordings INSIDE the project root (not in the user home).
        # _default_project_save_dir() finds the project by walking up from
        # cwd looking for an "app/" subdir or README.md.
        self.save_dir = save_dir or _default_project_save_dir()
        os.makedirs(self.save_dir, exist_ok=True)

        self.status      = "idle"
        self.error_msg   = None
        self.interface   = None

        self._proc        = None
        self._reader_thr  = None
        self._stop_reader = False
        self._lock        = threading.Lock()         # protects self.data (FIX old)
        self._state_lock  = threading.RLock()
        self._saving      = False
        self._pending_snapshot = None                # initialised so reset() can clear it cleanly


        self.start_time           = None
        self._last_resume_time    = None
        self.total_recorded_secs  = 0.0
        self._auto_stop_timer     = None


        self.pcap_chunks      = []
        self.final_pcap_path  = None

        self._reset_data()
        # sweep stale chunk files (older than 6h) left by crashed
        # sessions so netsec_sessions/ does not accumulate indefinitely.
        try:
            import time as _time
            _cutoff = _time.time() - 6 * 3600
            for fn in os.listdir(self.save_dir):
                if "_chunk_" in fn and fn.endswith(".pcap"):
                    fp = os.path.join(self.save_dir, fn)
                    try:
                        if os.path.getmtime(fp) < _cutoff:
                            os.remove(fp)
                    except Exception: pass
        except Exception: pass

    def _reset_data(self):
        self.data = {
            "n_pkts": 0,
            "first_ts": None, "last_ts": None,
            "ips_src":   Counter(), "bytes_src": Counter(), "bytes_dst": Counter(),
            "protocols": Counter(), "macs":      Counter(),
            "dns_q":     Counter(),
            "ip_pairs":  Counter(),
            "syn_counter": Counter(), "rst_counter": Counter(),
            "fin_counter": Counter(), "null_counter": Counter(),
            "xmas_counter": Counter(),
            "ip_to_mac":   defaultdict(Counter),
            "ports_per_ip":defaultdict(set),
            "dns_per_ip":  defaultdict(Counter),
            "mdns_per_ip": defaultdict(set),
            "arp_ip_to_macs": defaultdict(set),
            "arp_mac_to_ips": defaultdict(set),
            "dns_nxdomain":     0,
            "dns_nonstandard":  0,
            "timeline":     [],
            "dns_timeline": [],
            "pkt_sizes":    [],
        }


    def start(self, interface):
        """Begin recording (or resume after pause) on the given interface."""
        with self._state_lock:
            if self.status == "recording":
                return False, "Already recording"
            if self.status == "saved":
                return False, "Already saved. Press Reset to record again."
            if self.status == "error":
                self.reset()
            if not TSHARK_PATH:
                self.status, self.error_msg = "error", "tshark not found"
                return False, "tshark not installed"

            try:
                live_sessions = LIVE_SESSIONS  # name-resolve from module globals
            except NameError:
                live_sessions = {}
            for _sid, _w in (live_sessions or {}).items():
                if _w is self: continue
                try:
                    if _w.status == "recording" and _w.interface == interface:
                        self.error_msg = f"Interface {interface} already in use by {_sid}"
                        return False, self.error_msg
                except Exception: pass

            self.interface = interface
            chunk = os.path.join(self.save_dir,
                f"{self.label}_chunk_{int(time.time())}_{len(self.pcap_chunks)}.pcap")

            cmd = [TSHARK_PATH, "-i", interface, "-w", chunk,
                   "-l",
                   "-T", "fields", "-E", "header=n", "-E", "separator=|",
                   "-E", "occurrence=f", "-E", "quote=n"]
            for f in self.TSHARK_FIELDS:
                cmd += ["-e", f]
            try:
                # stderr must NOT be a pipe: tshark writes a running
                # packet-count there and nothing drains it, so a long or
                # busy capture fills the ~64KB OS buffer and tshark blocks
                # - the capture silently stalls.
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    encoding="utf-8", errors="replace", bufsize=1)
            except Exception as e:
                self.status, self.error_msg = "error", str(e)
                return False, f"Failed to spawn tshark: {e}"

            self.pcap_chunks.append(chunk)

            self._stop_reader = False
            self._reader_thr  = threading.Thread(target=self._read_loop, daemon=True)
            self._reader_thr.start()

            now = time.time()
            if self.start_time is None:
                self.start_time = now
            self._last_resume_time = now
            self.status, self.error_msg = "recording", None

            if self._auto_stop_timer:
                self._auto_stop_timer.cancel()
            remaining = self.MAX_SECONDS - self.total_recorded_secs
            self._auto_stop_timer = threading.Timer(remaining, self._auto_stop)
            self._auto_stop_timer.daemon = True
            self._auto_stop_timer.start()
            return True, "Recording started"

    def pause(self):
        """Stop tshark; in-memory data is preserved for the next resume."""
        with self._state_lock:
            if self.status != "recording":
                return False, "Not recording"

            if self._last_resume_time:
                self.total_recorded_secs += time.time() - self._last_resume_time
                self._last_resume_time = None

            self._stop_reader = True
            if self._proc:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=3)
                except Exception:
                    try: self._proc.kill()
                    except Exception: pass
                self._proc = None
            if self._reader_thr and self._reader_thr.is_alive():
                try: self._reader_thr.join(timeout=2)
                except Exception: pass
            self._reader_thr = None
            if self._auto_stop_timer:
                self._auto_stop_timer.cancel()
                self._auto_stop_timer = None
            self.status = "paused"
            return True, "Paused"

    def stop_and_save(self):
        """Finalize. Merges pcap chunks into one file, returns final path."""
        with self._state_lock:
            if self._saving:
                return False, "Save in progress"
            self._saving = True
        try:
            if self.status == "recording":
                self.pause()
            if self.total_recorded_secs < self.MIN_SECONDS:
                need = self.MIN_SECONDS - self.total_recorded_secs
                return False, (f"Only {self.total_recorded_secs:.0f}s recorded. "
                               f"Minimum is {self.MIN_SECONDS}s. Record {need:.0f}s more.")
            if not self.pcap_chunks:
                return False, "No data to save"

            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            self.final_pcap_path = os.path.join(self.save_dir,
                f"{self.label}_{ts}.pcap")
            try:
                if MERGECAP_PATH and len(self.pcap_chunks) > 1:
                    subprocess.run([MERGECAP_PATH, "-w", self.final_pcap_path]
                                   + self.pcap_chunks, check=True, timeout=60)
                    for c in self.pcap_chunks:
                        try: os.remove(c)
                        except Exception: pass
                elif (not MERGECAP_PATH) and len(self.pcap_chunks) > 1:
                    # mergecap missing but user recorded across
                    # pause/resume - save only the first chunk and warn.
                    shutil.copy2(self.pcap_chunks[0], self.final_pcap_path)
                    dropped = len(self.pcap_chunks) - 1
                    self.error_msg = (f"mergecap not installed - only the first chunk was saved. "
                                      f"{dropped} additional chunk(s) were discarded. "
                                      f"Install Wireshark's mergecap.exe to keep all chunks.")
                    for c in self.pcap_chunks:
                        try: os.remove(c)
                        except Exception: pass
                elif len(self.pcap_chunks) == 1:
                    shutil.copy2(self.pcap_chunks[0], self.final_pcap_path)
                    try: os.remove(self.pcap_chunks[0])
                    except Exception: pass
                # NOTE: dead else-branch removed (was attempting to access
                # pcap_chunks[0] after just checking it is empty - would have
                # raised IndexError; the guard at top of method already covers it).
            except Exception as e:
                self.status, self.error_msg = "error", f"merge failed: {e}"
                return False, f"Save failed: {e}"

            self.status = "saved"
            return True, self.final_pcap_path
        finally:
            self._saving = False

    def reset(self):
        """Clear everything; back to idle."""
        with self._state_lock:
            if self.status == "recording":
                self.pause()
            if self._auto_stop_timer:
                try: self._auto_stop_timer.cancel()
                except Exception: pass
                self._auto_stop_timer = None
            for c in self.pcap_chunks:
                try: os.remove(c)
                except Exception: pass
            self.pcap_chunks      = []
            if self.final_pcap_path:
                try: os.remove(self.final_pcap_path)
                except Exception: pass
            self.final_pcap_path  = None
            self.start_time       = None
            self._last_resume_time= None
            self.total_recorded_secs = 0.0
            self.status, self.error_msg = "idle", None
            self.interface = None
            self._pending_snapshot = None
            self._reset_data()
            return True, "Reset"

    def _auto_stop(self):
        """Triggered by MAX_SECONDS timer. Auto-saves."""
        if self.status == "recording":
            self.error_msg = f"Auto-saved at {self.MAX_SECONDS//60}-minute limit"
            ok, _ = self.stop_and_save()
            # also stage the pending snapshot so the UI shows the
            # Analyze button - otherwise a 1-hour recording lands in
            # status='saved' with no way to reach it from the UI.
            if ok:
                try:
                    snap = self.snapshot()
                    snap["label"] = self.label
                    snap["pkts"] = []
                    self._pending_snapshot = snap
                    _n = snap.get("n_pkts", 0)
                    print(f"[{self.label}] auto-stop staged pending snapshot ({_n} pkts)", flush=True)
                except Exception as e:
                    print(f"[{self.label}] auto-stop could not stage snapshot: {e}", flush=True)


    def get_elapsed_seconds(self):
        e = self.total_recorded_secs
        if self.status == "recording" and self._last_resume_time:
            e += time.time() - self._last_resume_time
        return e

    def quick_stats(self):
        """Lightweight snapshot for live UI display."""
        with self._lock:
            return {
                "status":      self.status,
                "elapsed":     self.get_elapsed_seconds(),
                "n_pkts":      self.data["n_pkts"],
                "n_devices":   len(self.data["ips_src"]),
                "n_macs":      len(self.data["macs"]),
                "n_protos":    len(self.data["protocols"]),
                "top_talkers": self.data["bytes_src"].most_common(5),
                "top_protos":  self.data["protocols"].most_common(5),
                "error":       self.error_msg,
                "interface":   self.interface,
                "saved_path":  self.final_pcap_path,
                "chunks":      len(self.pcap_chunks),
            }

    def snapshot(self):
        """Convert live state to an analyze_pcap-compatible dict for the rest of the pipeline (inventory, ML, charts)."""
        import pandas as _pd
        import re as _re
        with self._lock:
            d = self.data
            SKIP = _re.compile(r"^_|^wpad$|^KMD|^BRW|^v1$|^server|^HP$", _re.I)
            dns_real = {k:v for k,v in d["dns_q"].items()
                        if "." in k and not k.endswith(".local")
                        and not SKIP.search(k.split(".")[0])}
            device_names = sorted(set(
                k for k in d["dns_q"]
                if k.endswith(".local") and not k.startswith("_")
                and not _re.match(r"^[0-9a-f\-]{8,}", k) and len(k) > 8
            ))
            arp_spoofing_ips  = {ip:m for ip,m in d["arp_ip_to_macs"].items() if len(m)>1}
            arp_spoofing_macs = {m:ips for m,ips in d["arp_mac_to_ips"].items() if len(ips)>1}
            dns_long_queries  = [k for k in d["dns_q"] if len(k) > 60]

            df_pkts = _pd.DataFrame(d["timeline"], columns=["time","src","dst","size"])
            if len(df_pkts) > 0:
                ip_agg = df_pkts.groupby("src").agg(
                    count=("size","count"), total_bytes=("size","sum"),
                    mean_len=("size","mean"), std_len=("size","std"),
                    unique_dsts=("dst","nunique")).fillna(0)
                ip_agg["burst_score"] = ip_agg["count"] / (ip_agg["std_len"] + 1)
                ip_agg["dominance"]   = ip_agg["count"] + ip_agg["total_bytes"]/1000
                ip_agg["syn_count"]   = ip_agg.index.map(lambda x: d["syn_counter"].get(x,0))
                ip_agg["rst_count"]   = ip_agg.index.map(lambda x: d["rst_counter"].get(x,0))
                ip_agg["fin_count"]   = ip_agg.index.map(lambda x: d["fin_counter"].get(x,0))
                ip_agg["null_count"]  = ip_agg.index.map(lambda x: d["null_counter"].get(x,0))
                ip_agg["xmas_count"]  = ip_agg.index.map(lambda x: d["xmas_counter"].get(x,0))
                missing = set(self._LIVE_FEATURE_COLS) - set(ip_agg.columns)
                assert not missing, (
                    f"LiveCaptureWorker.snapshot() missing required columns: "
                    f"{missing}. Update _reset_data() and _process_line() to "
                    f"track these features.")
            else:
                ip_agg = _pd.DataFrame()

            t0 = _safe_fromtimestamp(d["first_ts"]) if d["first_ts"] else datetime.now()
            t1 = _safe_fromtimestamp(d["last_ts"])  if d["last_ts"]  else datetime.now()

            return {
                "label": self.label, "pkts": [],
                "n_pkts": d["n_pkts"], "pkt_sizes": list(d["pkt_sizes"]),
                "t0": t0, "t1": t1,
                "wifi_ssid": None, "wifi_bssid": None,
                "wlan_features": {}, "wlan_available": False,
                "ips_src":  Counter(d["ips_src"]),
                "bytes_src":Counter(d["bytes_src"]),
                "bytes_dst":Counter(d["bytes_dst"]),
                "protocols":Counter(d["protocols"]),
                "macs":     Counter(d["macs"]),
                "dns_real": dns_real,
                "device_names": device_names,
                "ip_agg":   ip_agg, "df_pkts": df_pkts,
                "ip_pairs": Counter(d["ip_pairs"]),
                "syn_counter":Counter(d["syn_counter"]),
                "rst_counter":Counter(d["rst_counter"]),
                "fin_counter":Counter(d["fin_counter"]),
                "null_counter":Counter(d["null_counter"]),
                "xmas_counter":Counter(d["xmas_counter"]),
                "arp_spoofing_ips":  dict(arp_spoofing_ips),
                "arp_spoofing_macs": dict(arp_spoofing_macs),
                "dns_nxdomain":      d["dns_nxdomain"],
                "dns_nonstandard":   d["dns_nonstandard"],
                "dns_long_queries":  dns_long_queries,
                "ip_to_mac":   dict(d["ip_to_mac"]),
                "ports_per_ip":dict(d["ports_per_ip"]),
                "dns_per_ip":  dict(d["dns_per_ip"]),
                "mdns_per_ip": dict(d["mdns_per_ip"]),
                "dns_timeline":list(d["dns_timeline"]),
            }


    def _read_loop(self):
        if not self._proc: return
        try:
            for line in iter(self._proc.stdout.readline, ""):
                if self._stop_reader:
                    break
                if not line.strip(): continue
                self._process_line(line.rstrip("\n"))
        except Exception as exc:
            try:
                self.status    = "error"
                self.error_msg = f"Reader crashed: {type(exc).__name__}: {exc}"
            except Exception:
                pass
            # reader crash left tshark orphaned - terminate it AND
            # cancel the auto-stop timer so the crashed session is fully torn down.
            try:
                if self._proc is not None:
                    try: self._proc.terminate()
                    except Exception: pass
                    try: self._proc.wait(timeout=3)
                    except Exception:
                        try: self._proc.kill()
                        except Exception: pass
                if self._auto_stop_timer is not None:
                    try: self._auto_stop_timer.cancel()
                    except Exception: pass
                    self._auto_stop_timer = None
                self._proc = None
                print(f"[{self.label}] reader-crash cleanup: tshark terminated, timer cancelled", flush=True)
            except Exception:
                pass

    def _process_line(self, line):
        parts = line.split("|")
        if len(parts) < 16: return
        try:
            ts_s, len_s = parts[0], parts[1]
            eth_src, ip_src, ip_dst = parts[2], parts[3], parts[4]
            proto = parts[5]
            tcp_sp, tcp_dp, tcp_fl = parts[6], parts[7], parts[8]
            udp_sp, udp_dp = parts[9], parts[10]
            dns_q, dns_rc, dns_rsp = parts[11], parts[12], parts[13]
            arp_p, arp_h = parts[14], parts[15]
            # Live capture on a modern network is mostly IPv6; fold it
            # into the same columns the rest of this method uses.
            if not ip_src and len(parts) > 16:
                ip_src = parts[16]
            if not ip_dst and len(parts) > 17:
                ip_dst = parts[17]
        except IndexError:
            return
        try:    ts = float(ts_s)
        except: return
        try:    length = int(len_s)
        except: length = 0

        with self._lock:
            d = self.data
            d["n_pkts"] += 1
            d["pkt_sizes"].append(length)
            if d["first_ts"] is None: d["first_ts"] = ts
            d["last_ts"] = ts

            if proto:    d["protocols"][proto] += 1
            if eth_src:  d["macs"][eth_src]     += 1
            if ip_src:
                d["ips_src"][ip_src]   += 1
                d["bytes_src"][ip_src] += length
                if eth_src:
                    d["ip_to_mac"][ip_src][eth_src] += 1
            if ip_dst:
                d["bytes_dst"][ip_dst] += length
            if ip_src and ip_dst:
                d["ip_pairs"][(ip_src, ip_dst)] += 1
                d["timeline"].append((ts, ip_src, ip_dst, length))

            if tcp_fl and ip_src:
                try:
                    fi = int(tcp_fl, 16)
                    if (fi & 0x3F) == 0x02: d["syn_counter"][ip_src] += 1
                    if fi & 0x04:    d["rst_counter"][ip_src] += 1
                    masked = fi & 0x3F
                    if masked == 0x01: d["fin_counter"][ip_src]  += 1
                    if masked == 0x00: d["null_counter"][ip_src] += 1
                    if masked == 0x29: d["xmas_counter"][ip_src] += 1
                except: pass
            if ip_src:
                for ps in (tcp_sp, tcp_dp, udp_sp, udp_dp):
                    if ps:
                        try: d["ports_per_ip"][ip_src].add(int(ps))
                        except: pass

            if dns_q and len(dns_q) > 3:
                q = dns_q.rstrip(".")
                d["dns_q"][q] += 1
                if ip_src:
                    d["dns_timeline"].append((ts, ip_src, q))
                    d["dns_per_ip"][ip_src][q] += 1
                    if q.endswith(".local"):
                        d["mdns_per_ip"][ip_src].add(q)
            if dns_rc == "3" and dns_rsp in ("1", "True"):
                d["dns_nxdomain"] += 1
            # Queries only - see the loader's note (B17). A response
            # goes to the querier's ephemeral port and is not "unusual".
            if dns_q and udp_dp and dns_rsp not in ("1", "True"):
                try:
                    if int(udp_dp) not in (53, 5353):
                        d["dns_nonstandard"] += 1
                except: pass

            if arp_p and arp_h and arp_p != "0.0.0.0":
                d["arp_ip_to_macs"][arp_p].add(arp_h)
                d["arp_mac_to_ips"][arp_h].add(arp_p)


LIVE_SESSIONS = {
    "S1": LiveCaptureWorker("S1"),
    "S2": LiveCaptureWorker("S2"),
}


def pick_default_wifi_interface():
    """Return the interface ID most likely to be a Wi-Fi adapter; fall back to
    the first non-loopback interface or '1' if none are visible."""
    ifs = list_capture_interfaces()
    wifi_keywords = ("wi-fi", "wifi", "wlan", "wireless", "airport", "en0")
    for nid, name in ifs:
        if any(kw in name.lower() for kw in wifi_keywords):
            return nid
    for nid, name in ifs:
        lname = name.lower()
        if "loopback" not in lname and lname.strip() != "lo":
            return nid
    return ifs[0][0] if ifs else "1"


print(f"Live capture ready.")
print(f"  tshark:   {TSHARK_PATH or '(not found - install Wireshark)'}")
print(f"  mergecap: {MERGECAP_PATH or '(not found - chunks wont merge)'}")
print(f"  Sessions: {list(LIVE_SESSIONS.keys())}")
print(f"  Save dir: {LIVE_SESSIONS['S1'].save_dir}")
ifs = list_capture_interfaces()
print(f"  Interfaces visible: {len(ifs)}")
for num, name in ifs[:6]:
    print(f"    {num}: {name}")


# ==== notebook cell 43 ====

import re as _re


CATEGORY_RULES = [
    ("Streaming",       [r"netflix", r"youtube", r"spotify", r"twitch", r"hulu",
                          r"disneyplus", r"vimeo", r"soundcloud", r"tidal"]),
    ("Work/Enterprise", [r"service-now", r"sas\.com", r"salesforce", r"slack",
                          r"zoom", r"teams\.microsoft", r"office365", r"sharepoint",
                          r"confluence", r"jira", r"workday", r"okta"]),
    ("Google/Cloud",    [r"google", r"gmail", r"gstatic", r"googleapis",
                          r"googleusercontent", r"gvt[12]", r"ggpht"]),
    ("Cloud Infra",     [r"amazonaws", r"azure", r"cloudfront", r"akamai",
                          r"fastly", r"cloudflare", r"digitalocean", r"heroku"]),
    ("Social",          [r"facebook", r"instagram", r"twitter", r"tiktok",
                          r"linkedin", r"pinterest", r"reddit", r"snapchat"]),
    ("Security/Update", [r"ocsp", r"crl", r"certificate", r"update", r"telemetry",
                          r"safebrowsing", r"malware", r"avast", r"norton",
                          r"windowsupdate", r"microsoft\.com"]),
    ("News/Media",      [r"bbc", r"cnn", r"nytimes", r"reuters", r"apnews",
                          r"theguardian", r"ynet", r"haaretz", r"maariv",
                          r"walla", r"n12", r"kan\.org"]),
    ("CDN/Infra",       [r"cdn", r"static", r"edge", r"cache", r"d[0-9a-z]+\.net",
                          r"doubleclick", r"2mdn", r"chartbeat"]),
]

def classify_domain(domain):
    d = domain.lower()
    for cat, patterns in CATEGORY_RULES:
        if any(_re.search(p, d) for p in patterns):
            return cat
    return "Other"


def build_device_names(s):
    ip_to_name = {}
    for dname in s["device_names"]:
        base = dname.replace(".local", "").lower()
        for ip in s["ips_src"]:
            if base in ip.lower():
                ip_to_name[ip] = dname
    return ip_to_name

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np

BLUE, DBLUE, RED, GREEN, WHITE = "#1565C0", "#0d47a1", "#E53935", "#2e7d32", "#ffffff"


WARM_PALETTE = [
    [0.00, "#FFF5EB"],
    [0.15, "#FED8B1"],
    [0.35, "#FDAE61"],
    [0.60, "#F46D43"],
    [0.85, "#D73027"],
    [1.00, "#8B0000"],
]


def make_browsing_category_fig(s):
    ip_to_name = build_device_names(s)

    rows = []
    for ts, ip, query in s["dns_timeline"]:
        if query.endswith(".local") or query.endswith(".arpa"):
            continue
        cat   = classify_domain(query)
        label = ip_to_name.get(ip, ip)
        rows.append({"device": label, "category": cat})

    if not rows:
        fig = go.Figure()
        fig.update_layout(title="No DNS data available", plot_bgcolor=WHITE, paper_bgcolor=WHITE)
        return fig

    df    = pd.DataFrame(rows)
    pivot = df.groupby(["device", "category"]).size().reset_index(name="count")

    active = pivot.groupby("device")["count"].sum()
    active = active[active >= 5].index
    pivot  = pivot[pivot["device"].isin(active)]

    totals       = pivot.groupby("device")["count"].transform("sum")
    pivot["pct"] = pivot["count"] / totals * 100

    CATS      = [c for c, _ in CATEGORY_RULES] + ["Other"]
    COLORS    = px.colors.qualitative.Safe[:len(CATS)]
    cat_color = dict(zip(CATS, COLORS))

    fig = go.Figure()
    for cat in CATS:
        sub = pivot[pivot["category"] == cat]
        if sub.empty:
            continue
        fig.add_trace(go.Bar(
            name=cat,
            y=sub["device"],
            x=sub["pct"],
            orientation="h",
            marker_color=cat_color.get(cat, "#aaaaaa"),
            text=sub["pct"].apply(lambda v: f"{v:.0f}%" if v > 4 else ""),
            textposition="inside",
            hovertemplate="<b>%{y}</b><br>" + cat + ": %{x:.1f}%<br>Queries: %{customdata}<extra></extra>",
            customdata=sub["count"],
        ))

    fig.update_layout(
        barmode="stack",
        title=dict(text=f"Browsing Profile by Site Category - {s['label']}",
                   x=0.5, xanchor="center", y=0.97, yanchor="top"),
        xaxis_title="% of DNS queries",
        yaxis=dict(automargin=True),
        legend=dict(orientation="h", yanchor="top", y=-0.18,
                    xanchor="center", x=0.5),
        height=max(460, len(active) * 50 + 180),
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=20, r=20, t=70, b=120),
    )
    return fig


def make_browsing_hour_fig(s):
    ip_to_name = build_device_names(s)

    BUCKET_SEC = 5 * 60

    t0_ts = _safe_epoch(s["t0"])
    t1_ts = _safe_epoch(s["t1"])

    bin_start = int(t0_ts // BUCKET_SEC) * BUCKET_SEC
    bin_end   = (int(t1_ts // BUCKET_SEC) + 1) * BUCKET_SEC
    n_bins    = max(1, (bin_end - bin_start) // BUCKET_SEC)

    bin_labels = [_safe_fromtimestamp(bin_start + i * BUCKET_SEC).strftime("%H:%M")
                  for i in range(n_bins)]

    rows = []
    for ts, ip, query in s["dns_timeline"]:
        if query.endswith(".local") or query.endswith(".arpa"):
            continue
        label = ip_to_name.get(ip, ip)
        bidx  = int((ts - bin_start) // BUCKET_SEC)
        if 0 <= bidx < n_bins:
            rows.append({"device": label, "bin": bidx})

    if not rows:
        fig = go.Figure()
        fig.update_layout(title=f"No DNS timeline data - {s['label']}",
                          plot_bgcolor=WHITE, paper_bgcolor=WHITE)
        return fig

    df     = pd.DataFrame(rows)
    active = df.groupby("device").size()
    active = active[active >= 5].index
    df     = df[df["device"].isin(active)]

    pivot = df.groupby(["device", "bin"]).size().unstack(fill_value=0)
    for b in range(n_bins):
        if b not in pivot.columns:
            pivot[b] = 0
    pivot = pivot[list(range(n_bins))]

    z        = pivot.values.astype(float)
    all_zero = (z.sum() == 0)

    fig = go.Figure(go.Heatmap(
        z=z,
        x=bin_labels,
        y=pivot.index.tolist(),
        colorscale=WARM_PALETTE,
        text=z.astype(int),
        texttemplate="%{text}" if (not all_zero and n_bins <= 60) else "",
        hovertemplate="Device: %{y}<br>Time: %{x}<br>Queries: %{z}<extra></extra>",
        showscale=True,
        colorbar=dict(title="DNS queries"),
    ))

    if all_zero:
        fig.add_annotation(
            text="No external DNS queries recorded in this session",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="gray"),
        )


    tick_step = max(1, n_bins // 24)
    tickvals  = list(range(0, n_bins, tick_step))
    ticktext  = [bin_labels[i] for i in tickvals]

    fig.update_layout(
        title=(f"Browsing Activity by 5-min Window - {s['label']} "
               f"({s['t0'].strftime('%H:%M')}-{s['t1'].strftime('%H:%M')})"),
        xaxis=dict(title="Time (5-min buckets)", tickmode="array",
                   tickvals=tickvals, ticktext=ticktext, tickangle=-45),
        yaxis=dict(automargin=True, title="Device"),
        height=max(360, len(pivot) * 45 + 140),
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=20, r=20, t=80, b=90),
    )
    return fig


def make_confusion_matrix_fig(ip_agg_df):
    df = ip_agg_df.copy()

    quad = {
        ("Anomaly (IF)", "Noise (DBSCAN)"):     df[(df["anomaly"] == True)  & (df["cluster"] == -1)],
        ("Anomaly (IF)", "Clustered (DBSCAN)"): df[(df["anomaly"] == True)  & (df["cluster"] != -1)],
        ("Normal (IF)",  "Noise (DBSCAN)"):     df[(df["anomaly"] == False) & (df["cluster"] == -1)],
        ("Normal (IF)",  "Clustered (DBSCAN)"): df[(df["anomaly"] == False) & (df["cluster"] != -1)],
    }

    rows = ["Anomaly (IF)", "Normal (IF)"]
    cols = ["Noise (DBSCAN)", "Clustered (DBSCAN)"]
    z    = [[len(quad[(r, c)]) for c in cols] for r in rows]

    max_v = max(max(r) for r in z) or 1

    fig = go.Figure(go.Heatmap(
        z=z, x=cols, y=rows,
        colorscale=WARM_PALETTE,
        showscale=False,
        hovertemplate="<b>%{y}</b> ∩ <b>%{x}</b><br>IPs: %{z}<extra></extra>",
    ))

    quad_labels = {
        (0, 0): "🔴 HIGH CONFIDENCE",
        (0, 1): "🟡 IF only",
        (1, 0): "🟡 DBSCAN only",
        (1, 1): "🟢 BOTH normal",
    }


    for ri in range(2):
        for ci in range(2):
            sub      = quad[(rows[ri], cols[ci])]
            count_n  = len(sub)
            ips      = sub.index.tolist()[:3]
            suffix   = f"<br>+{len(sub)-3} more" if len(sub) > 3 else ""
            ips_text = ("<br>".join(ips) + suffix) if ips else "-"


            dark_bg = count_n > max_v * 0.55
            text_color = "white" if dark_bg else "#1a1a1a"


            fig.add_annotation(
                x=ci, y=ri, yshift=60,
                text=f"<b>{count_n}</b>",
                xref="x", yref="y", showarrow=False,
                font=dict(size=42, color=text_color),
            )

            fig.add_annotation(
                x=ci, y=ri, yshift=0,
                text=quad_labels[(ri, ci)],
                xref="x", yref="y", showarrow=False,
                font=dict(size=13, color=text_color),
            )

            fig.add_annotation(
                x=ci, y=ri, yshift=-55,
                text=ips_text,
                xref="x", yref="y", showarrow=False,
                font=dict(size=10, color=text_color),
                align="center",
            )

    fig.update_layout(
        title=("Model Agreement Matrix - IsolationForest vs DBSCAN<br>"
               "<sup>⚠ Unsupervised: no true labels. Diagonal = both models agree. "
               "Off-diagonal = investigate further.</sup>"),
        xaxis=dict(side="bottom", tickfont=dict(size=13), title=""),
        yaxis=dict(tickfont=dict(size=13), title=""),
        height=560, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=80, r=80, t=110, b=60),
    )
    return fig


def make_sensitivity_sweep_fig(X_scaled, ip_agg_df):
    from sklearn.ensemble import IsolationForest as _IF
    import numpy as _np

    sweep                  = _np.linspace(0.02, 0.30, 20)
    n_flagged, mean_scores = [], []

    for cont in sweep:
        iso_tmp        = _IF(n_estimators=100, contamination=float(cont), random_state=42)
        iso_tmp.fit(X_scaled)
        preds          = iso_tmp.predict(X_scaled)
        scores         = iso_tmp.decision_function(X_scaled)
        flagged_scores = scores[preds == -1]
        n_flagged.append(int((preds == -1).sum()))
        mean_scores.append(float(flagged_scores.mean()) if len(flagged_scores) else 0.0)

    chosen = float(ip_agg_df.attrs.get("chosen_contamination", 0.10))

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=sweep * 100, y=n_flagged,
        name="IPs flagged",
        mode="lines+markers",
        line=dict(color=BLUE, width=2), marker=dict(size=5),
        yaxis="y1",
        hovertemplate="contamination=%{x:.1f}%<br>flagged=%{y}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=sweep * 100, y=mean_scores,
        name="Mean score of flagged group",
        mode="lines+markers",
        line=dict(color=RED, width=2, dash="dot"), marker=dict(size=5),
        yaxis="y2",
        hovertemplate="contamination=%{x:.1f}%<br>mean_score=%{y:.4f}<extra></extra>",
    ))
    fig.add_vline(
        x=chosen * 100,
        line_width=2, line_dash="dash", line_color=GREEN,
        annotation_text=f"Chosen: {chosen*100:.0f}%",
        annotation_position="top right",
        annotation_font_color=GREEN,
    )
    fig.update_layout(
        title=dict(
            text=("IsolationForest Contamination Sensitivity Sweep<br>"
                  "<sup>Left axis: # IPs flagged - Right axis: mean anomaly score "
                  "(more negative = more extreme)</sup>"),
            x=0.5, xanchor="center", y=0.97, yanchor="top",
        ),
        xaxis=dict(title="contamination (%)"),
        yaxis=dict(
            title=dict(text="# IPs flagged", font=dict(color=BLUE)),
            tickfont=dict(color=BLUE),
        ),
        yaxis2=dict(
            title=dict(text="mean anomaly score (flagged)", font=dict(color=RED)),
            tickfont=dict(color=RED),
            overlaying="y", side="right",
        ),
        legend=dict(orientation="h", yanchor="top", y=-0.20,
                    xanchor="center", x=0.5),
        height=460, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=60, r=60, t=90, b=110),
    )
    return fig

FIG_BROWSE_CAT_S1  = go.Figure()
FIG_BROWSE_CAT_S2  = go.Figure()
FIG_BROWSE_HOUR_S1 = go.Figure()
FIG_BROWSE_HOUR_S2 = go.Figure()
FIG_CONFUSION      = go.Figure()
FIG_SENSITIVITY    = go.Figure()


def build_browse_figures(s1, s2):
    """Build the browsing + ML-diagnostic figures from one or two sessions. Updates global FIG_* placeholders."""
    global FIG_BROWSE_CAT_S1, FIG_BROWSE_CAT_S2
    global FIG_BROWSE_HOUR_S1, FIG_BROWSE_HOUR_S2
    global FIG_CONFUSION, FIG_SENSITIVITY

    if s2 is not None:
        FIG_BROWSE_CAT_S2  = make_browsing_category_fig(s2)
        FIG_BROWSE_HOUR_S2 = make_browsing_hour_fig(s2)
    if s1 is not None:
        FIG_BROWSE_CAT_S1  = make_browsing_category_fig(s1)
        FIG_BROWSE_HOUR_S1 = make_browsing_hour_fig(s1)

    primary = s2 if s2 is not None else s1
    if primary is not None and primary.get("ip_agg") is not None:
        ip_agg_local = primary["ip_agg"]
        FIG_CONFUSION = make_confusion_matrix_fig(ip_agg_local)
        X_local = primary.get("_X")
        if X_local is not None and "iso_score" in ip_agg_local.columns:
            ip_agg_local.attrs["chosen_contamination"] = primary.get(
                "_chosen_contamination", 0.10)
            FIG_SENSITIVITY = make_sensitivity_sweep_fig(X_local, ip_agg_local)
    return {
        "FIG_BROWSE_CAT_S1":  FIG_BROWSE_CAT_S1,
        "FIG_BROWSE_CAT_S2":  FIG_BROWSE_CAT_S2,
        "FIG_BROWSE_HOUR_S1": FIG_BROWSE_HOUR_S1,
        "FIG_BROWSE_HOUR_S2": FIG_BROWSE_HOUR_S2,
        "FIG_CONFUSION":      FIG_CONFUSION,
        "FIG_SENSITIVITY":    FIG_SENSITIVITY,
    }


print("Browse-figure builders ready (call build_browse_figures(S1, S2) on demand)")


# ==== notebook cell 45 ====

import plotly.io as _pio
# CRITICAL: plotly's default template carries bar.marker.pattern objects that
# can lose their parent-chain after many rebuilds, causing "Invalid value"
# crashes deep inside apply_default_cascade. By setting default="none" we
# bypass the cascade entirely; _apply_aurora_layout below handles all styling.
_pio.templates.default = "none"

BLUE,DBLUE,RED,GREEN,WHITE = "#1565C0","#0d47a1","#E53935","#2e7d32","#ffffff"


WARM_PALETTE_LOCAL = [
    [0.00, "#FFF5EB"], [0.15, "#FED8B1"], [0.35, "#FDAE61"],
    [0.60, "#F46D43"], [0.85, "#D73027"], [1.00, "#8B0000"],
]


PIE_PALETTE = px.colors.qualitative.Bold + px.colors.qualitative.Pastel

def _pie_top10_others(byte_counter, title):
    """Build a donut chart of bytes per IP - Top 10 + everything else aggregated."""
    if not byte_counter:
        fig = go.Figure()
        fig.update_layout(title=title + " - no data",
                          plot_bgcolor=WHITE, paper_bgcolor=WHITE)
        return fig

    items  = sorted(byte_counter.items(), key=lambda x: -x[1])
    top10  = items[:10]
    others = sum(v for _, v in items[10:])

    labels = [ip for ip, _ in top10]
    values = [v  for _,  v in top10]
    if others > 0:
        labels.append(f"Others ({len(items)-10} IPs)")
        values.append(others)

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.42,
        textposition="inside",
        textinfo="percent",
        insidetextorientation="radial",
        hovertemplate=("<b>%{label}</b><br>"
                       "Bytes: %{value:,.0f}<br>"
                       "Share: %{percent}<extra></extra>"),
        marker=dict(colors=PIE_PALETTE[:len(labels)],
                    line=dict(color="white", width=2)),
        sort=False,
    ))
    fig.update_layout(
        title=title,
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        height=560,
        legend=dict(orientation="v", yanchor="middle", y=0.5,
                    xanchor="left", x=1.02, font=dict(size=11)),
        margin=dict(l=20, r=180, t=80, b=30),
    )
    return fig


def _burst_anomaly_tag(row, q95_burst, q95_dom):
    """Compact reason string for the Burst-vs-Scan hover."""
    tags = []
    if row.get("syn_count", 0) > 100:        tags.append("High SYN")
    if row.get("rst_count", 0) > 50:         tags.append("High RST")
    if row.get("burst_score", 0) > q95_burst: tags.append("High Burst")
    if row.get("dominance", 0)  > q95_dom:    tags.append("High Dominance")
    if row.get("anomaly", False):             tags.append("ML-flagged")
    return ", ".join(tags) if tags else "Within normal range"




def _build_device_map_figure(session_dict, title_label, inv=None):
    """Project per-IP behavioural features to 2D via PCA and render a scatter
    plot. Each point = one IP. Color = device category. Size = log(bytes).
    Returns a Plotly figure (may be empty if no data)."""
    import plotly.graph_objects as go
    from sklearn.decomposition import PCA
    from sklearn.preprocessing import StandardScaler

    if session_dict is None:
        fig = go.Figure()
        fig.update_layout(title=f"Device Map · {title_label}",
                          annotations=[dict(text="No session loaded",
                                            xref="paper", yref="paper",
                                            x=0.5, y=0.5, showarrow=False,
                                            font=dict(size=14))])
        return fig

    ip_agg = session_dict.get("ip_agg")
    if ip_agg is None or len(ip_agg) < 2:
        fig = go.Figure()
        fig.update_layout(title=f"Device Map · {title_label}",
                          annotations=[dict(text="Not enough IPs for PCA",
                                            xref="paper", yref="paper",
                                            x=0.5, y=0.5, showarrow=False,
                                            font=dict(size=14))])
        return fig

    feature_cols = [c for c in ["count","total_bytes","mean_len","std_len",
                                 "unique_dsts","syn_count","rst_count"]
                    if c in ip_agg.columns]
    if len(feature_cols) < 2:
        fig = go.Figure()
        fig.update_layout(title=f"Device Map · {title_label}",
                          annotations=[dict(text="Missing feature columns",
                                            xref="paper", yref="paper",
                                            x=0.5, y=0.5, showarrow=False,
                                            font=dict(size=14))])
        return fig

    X = ip_agg[feature_cols].fillna(0).values
    try:
        Xs = StandardScaler().fit_transform(X)
        pca = PCA(n_components=2, random_state=42)
        coords = pca.fit_transform(Xs)
    except Exception as e:
        fig = go.Figure()
        fig.update_layout(title=f"Device Map · {title_label}",
                          annotations=[dict(text=f"PCA failed: {e}",
                                            xref="paper", yref="paper",
                                            x=0.5, y=0.5, showarrow=False,
                                            font=dict(size=14))])
        return fig

    ips = list(ip_agg.index)
    bytes_per_ip = ip_agg["total_bytes"].values if "total_bytes" in ip_agg.columns else [0]*len(ips)
    pkts_per_ip  = ip_agg["count"].values       if "count" in ip_agg.columns       else [0]*len(ips)
    import math
    sizes = [max(8, min(40, 8 + math.log1p(b) * 2.2)) for b in bytes_per_ip]

    if inv is None:
        inv = session_dict.get("local_inv", None)
    cat_map  = {}
    vendor_map = {}
    mac_map = {}
    if inv is not None and hasattr(inv, "iterrows"):
        for _, row in inv.iterrows():
            ip = row.get("ip")
            if ip is None: continue
            cat_map[ip]    = row.get("category","Unknown") or "Unknown"
            vendor_map[ip] = row.get("vendor","-") or "-"
            mac_map[ip]    = row.get("mac","-") or "-"

    CATEGORY_PALETTE = {
        "Computer":          "#a78bfa",
        "Mobile":            "#67e8f9",
        "Smart Home":        "#a3e635",
        "Security & Camera": "#f87171",
        "Entertainment":     "#f472b6",
        "Network Infra":     "#fbbf24",
        "Office":            "#c4b5fd",
        "Generic Endpoint":  "#9b94b8",
        "Unknown":           "#5a536f",
        "External":          "#67e8f9",
    }

    categories = []
    for ip in ips:
        if ip in cat_map: categories.append(cat_map[ip])
        else:             categories.append("External")

    fig = go.Figure()
    by_cat = {}
    for i, cat in enumerate(categories):
        by_cat.setdefault(cat, []).append(i)

    for cat, idxs in by_cat.items():
        color = CATEGORY_PALETTE.get(cat, "#9b94b8")
        hover = [
            f"<b>{ips[i]}</b><br>"
            f"category: {categories[i]}<br>"
            f"vendor: {vendor_map.get(ips[i], '-')}<br>"
            f"MAC: {mac_map.get(ips[i], '-')}<br>"
            f"packets: {int(pkts_per_ip[i]):,}<br>"
            f"bytes: {int(bytes_per_ip[i]):,}"
            for i in idxs
        ]
        fig.add_trace(go.Scatter(
            x=[coords[i][0] for i in idxs],
            y=[coords[i][1] for i in idxs],
            mode="markers",
            name=cat,
            marker=dict(
                size=[sizes[i] for i in idxs],
                color=color,
                line=dict(color="rgba(255,255,255,0.3)", width=1),
                opacity=0.85,
            ),
            text=[ips[i] for i in idxs],
            hoverinfo="text",
            hovertext=hover,
        ))

    var_pct = pca.explained_variance_ratio_ * 100
    fig.update_layout(
        title=dict(
            text=f"Device Map · {title_label} · {len(ips)} IPs in behaviour space",
        ),
        xaxis=dict(title=f"PC1 ({var_pct[0]:.1f}% variance)",
                    zeroline=False, showgrid=True),
        yaxis=dict(title=f"PC2 ({var_pct[1]:.1f}% variance)",
                    zeroline=False, showgrid=True),
        height=560,
        showlegend=True,
        hovermode="closest",
    )
    return fig



def _estimate_distance_m(mean_rssi, tx_power_dbm=20.0,
                          path_loss_n=2.5, pl_d0_db=40.0):
    """Indoor log-distance path-loss model for distance estimation from RSSI.

    PL(d) = PL(d0) + 10*n*log10(d/d0)
    With d0 = 1m, PL(d0) ≈ 40 dB at 2.4 GHz (free-space + indoor reference).
    Tx_power - RSSI = PL(d), so:
        d = 10^((Tx - RSSI - PL_d0) / (10 * n))

    Defaults: tx_power=20 dBm (consumer AP), n=2.5 (typical office),
    pl_d0=40 dB (2.4 GHz at 1m). For real-world calibration, change pl_d0_db.
    Returns metres. None if rssi is None.
    """
    if mean_rssi is None:
        return None
    try:
        d = 10.0 ** ((tx_power_dbm - mean_rssi - pl_d0_db) / (10.0 * path_loss_n))
        return max(0.1, d)
    except Exception:
        return None


def _build_proximity_map_figure(session_dict, title_label):
    """Two modes:
       - RSSI: x = log(distance_m), y = RSSI variance (signal stability),
               size = activity, color = proximity bucket.
       - Behavioural: MDS-style embedding from temporal-correlation + subnet
               + vendor similarity, color = proximity cluster."""
    import plotly.graph_objects as go
    import numpy as np

    if session_dict is None:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="No session loaded",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
                font=dict(size=14))])
        return fig

    wlan = session_dict.get("wlan_features", {}) or {}
    wlan_avail = bool(session_dict.get("wlan_available", False)) and bool(wlan)

    # ---------- MODE 1: real RSSI ----------
    if wlan_avail:
        macs, mean_rssi, std_rssi, n_samples, n_probe, n_assoc, retries = (
            [], [], [], [], [], [], [])
        for mac, f in wlan.items():
            rs = f.get("rssi_samples") or []
            if not rs:
                continue
            macs.append(mac)
            mean_rssi.append(float(np.mean(rs)))
            std_rssi.append(float(np.std(rs)) if len(rs) > 1 else 0.0)
            n_samples.append(len(rs))
            n_probe.append(f.get("probe_requests", 0))
            n_assoc.append(f.get("association_frames", 0))
            retries.append(f.get("retry_count", 0))

        if not macs:
            fig = go.Figure()
            fig.update_layout(title=f"Proximity Map · {title_label}",
                annotations=[dict(text="WLAN frames captured but RSSI samples empty",
                    xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
            return fig

        distances_m = [_estimate_distance_m(m) for m in mean_rssi]

        def _bucket(d):
            if d is None: return "Unknown"
            if d < 2:   return "Same desk (< 2m)"
            if d < 5:   return "Same room (2-5m)"
            if d < 15:  return "Adjacent room (5-15m)"
            return "Far / different floor (> 15m)"
        buckets = [_bucket(d) for d in distances_m]

        BUCKET_COLOR = {
            "Same desk (< 2m)":              "#f87171",
            "Same room (2-5m)":              "#fbbf24",
            "Adjacent room (5-15m)":         "#67e8f9",
            "Far / different floor (> 15m)": "#5a536f",
            "Unknown":                        "#9b94b8",
        }

        # log-x for distance (helps visualise the wide range)
        import math
        log_d = [math.log10(d) if d and d > 0 else 0 for d in distances_m]
        sizes = [max(8, min(40, 8 + math.log1p(s) * 4)) for s in n_samples]

        fig = go.Figure()
        for b in set(buckets):
            idxs = [i for i, bb in enumerate(buckets) if bb == b]
            fig.add_trace(go.Scatter(
                x=[log_d[i] for i in idxs],
                y=[std_rssi[i] for i in idxs],
                mode="markers",
                name=b,
                marker=dict(
                    size=[sizes[i] for i in idxs],
                    color=BUCKET_COLOR.get(b, "#9b94b8"),
                    line=dict(color="rgba(255,255,255,0.3)", width=1),
                    opacity=0.85,
                ),
                hovertext=[
                    f"<b>{macs[i]}</b><br>"
                    f"mean RSSI: {mean_rssi[i]:.1f} dBm<br>"
                    f"σ RSSI: {std_rssi[i]:.2f} dBm<br>"
                    f"~distance: {distances_m[i]:.1f} m<br>"
                    f"samples: {n_samples[i]}<br>"
                    f"probe requests: {n_probe[i]}<br>"
                    f"association frames: {n_assoc[i]}<br>"
                    f"retries: {retries[i]}"
                    for i in idxs
                ],
                hoverinfo="text",
            ))

        fig.update_layout(
            title=dict(text=(f"Proximity Map · {title_label} · "
                f"{len(macs)} devices · 🔵 RSSI mode (monitor capture)")),
            xaxis=dict(title="log₁₀(distance estimate) - left = closer",
                zeroline=False),
            yaxis=dict(title="RSSI variance σ (dB) - high = unstable signal",
                zeroline=False),
            height=560, showlegend=True, hovermode="closest",
        )
        return fig

    # ---------- MODE 2: behavioural proxy ----------
    ip_agg = session_dict.get("ip_agg")
    if ip_agg is None or len(ip_agg) < 3:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="Not enough endpoints for behavioural proximity",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    timeline = session_dict.get("df_pkts")
    if timeline is None or len(timeline) == 0:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="No timeline data for temporal correlation",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    import pandas as pd
    tl = timeline.copy()
    # Resolve the time column. analyze_pcap emits "time"; some upstream
    # paths emit "frame.time_epoch"; tolerate either, and gracefully bail
    # if neither is present rather than KeyError on dropna.
    if "ts" not in tl.columns:
        if "time" in tl.columns:
            tl["ts"] = pd.to_numeric(tl["time"], errors="coerce")
        elif "frame.time_epoch" in tl.columns:
            tl["ts"] = pd.to_numeric(tl["frame.time_epoch"], errors="coerce")
        else:
            fig = go.Figure()
            fig.update_layout(title=f"Proximity Map · {title_label}",
                annotations=[dict(text=("Timeline missing time column "
                    "(need 'time', 'ts', or 'frame.time_epoch')"),
                    xref="paper", yref="paper", x=0.5, y=0.5,
                    showarrow=False, font=dict(size=14))])
            return fig
    if "src" not in tl.columns and "ip.src" in tl.columns:
        tl["src"] = tl["ip.src"]
    if "src" not in tl.columns:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="Timeline missing src column",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
                font=dict(size=14))])
        return fig
    tl = tl.dropna(subset=["ts","src"])
    if len(tl) == 0:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="Timeline has no usable (ts, src) pairs",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    t0 = tl["ts"].min()
    tl["bin"] = ((tl["ts"] - t0) // 30).astype("int64")
    activity = tl.groupby(["src","bin"]).size().unstack(fill_value=0)
    if len(activity) < 3:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="Too few endpoints with timeline activity",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    # Restrict to the top-30 talkers to keep MDS fast and the chart readable
    top_ips = activity.sum(axis=1).sort_values(ascending=False).head(30).index
    activity = activity.loc[top_ips]
    ips = list(activity.index)

    # Pearson correlation between every pair of IP timelines = "are they active
    # together?" Higher correlation = closer behaviourally.
    A = activity.values.astype(float)
    if A.shape[1] < 2:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text="Only one time bin - cannot compute correlation",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    A_mean = A.mean(axis=1, keepdims=True)
    A_std  = A.std(axis=1, keepdims=True)
    A_norm = (A - A_mean) / (A_std + 1e-9)
    corr = (A_norm @ A_norm.T) / A.shape[1]
    corr = np.clip(corr, -1.0, 1.0)

    # OUI / subnet bonus: same /24 subnet → +0.25 similarity boost
    def _subnet24(ip):
        try:
            return ".".join(str(ip).split(".")[:3])
        except Exception:
            return ""
    subs = [_subnet24(ip) for ip in ips]
    for i in range(len(ips)):
        for j in range(len(ips)):
            if i != j and subs[i] == subs[j] and subs[i]:
                corr[i,j] = min(1.0, corr[i,j] + 0.25)

    # Distance = 1 - similarity (clamped to [0, 2])
    D = np.clip(1.0 - corr, 0.0, 2.0)
    np.fill_diagonal(D, 0.0)

    # MDS embedding to 2D
    try:
        from sklearn.manifold import MDS
        mds = MDS(n_components=2, dissimilarity="precomputed",
                  random_state=42, n_init=2, max_iter=200)
        coords = mds.fit_transform(D)
    except Exception as e:
        fig = go.Figure()
        fig.update_layout(title=f"Proximity Map · {title_label}",
            annotations=[dict(text=f"MDS failed: {e}",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])
        return fig

    # Bucket each IP by mean correlation to others (how socially connected)
    mean_corr_per_ip = (corr.sum(axis=1) - 1.0) / max(len(ips) - 1, 1)
    def _b_bucket(mc):
        if mc > 0.6:  return "Tight cluster (same room)"
        if mc > 0.3:  return "Loose cluster (adjacent)"
        if mc > 0.0:  return "Isolated talker"
        return "Anti-correlated"
    buckets = [_b_bucket(mc) for mc in mean_corr_per_ip]

    BUCKET_COLOR = {
        "Tight cluster (same room)":  "#f87171",
        "Loose cluster (adjacent)":   "#fbbf24",
        "Isolated talker":            "#67e8f9",
        "Anti-correlated":            "#9b94b8",
    }

    bytes_per_ip = (ip_agg["total_bytes"] if "total_bytes" in ip_agg.columns
                    else pd.Series(0, index=ip_agg.index))
    import math
    sizes = [max(8, min(36, 8 + math.log1p(int(bytes_per_ip.get(ip, 0))) * 2.2))
             for ip in ips]

    fig = go.Figure()
    for b in set(buckets):
        idxs = [i for i, bb in enumerate(buckets) if bb == b]
        fig.add_trace(go.Scatter(
            x=[coords[i,0] for i in idxs],
            y=[coords[i,1] for i in idxs],
            mode="markers+text" if len(idxs) < 8 else "markers",
            name=b,
            marker=dict(
                size=[sizes[i] for i in idxs],
                color=BUCKET_COLOR.get(b, "#9b94b8"),
                line=dict(color="rgba(255,255,255,0.3)", width=1),
                opacity=0.85,
            ),
            text=[ips[i] for i in idxs] if len(idxs) < 8 else None,
            textposition="top center",
            textfont=dict(size=9, color="#9b94b8"),
            hovertext=[
                f"<b>{ips[i]}</b><br>"
                f"subnet: {subs[i]}.0/24<br>"
                f"mean corr to others: {mean_corr_per_ip[i]:+.2f}<br>"
                f"total bytes: {int(bytes_per_ip.get(ips[i], 0)):,}<br>"
                f"bucket: {buckets[i]}"
                for i in idxs
            ],
            hoverinfo="text",
        ))

    fig.update_layout(
        title=dict(text=(f"Proximity Map · {title_label} · "
            f"{len(ips)} top talkers · 🟡 Behavioural mode "
            f"(no RSSI; uses temporal correlation + subnet)")),
        xaxis=dict(title="MDS-1 (proximity space)",
            zeroline=False, showticklabels=False),
        yaxis=dict(title="MDS-2",
            zeroline=False, showticklabels=False),
        height=560, showlegend=True, hovermode="closest",
        annotations=[dict(
            xref="paper", yref="paper", x=0.99, y=0.01,
            text=("ⓘ No 802.11 management frames in this PCAP. "
                  "Switch to a monitor-mode capture (AirPcap or Linux + "
                  "airmon-ng) to see real RSSI distance estimates."),
            showarrow=False, align="right",
            font=dict(size=10, color="#5a536f"),
            xanchor="right", yanchor="bottom",
        )],
    )
    return fig


def make_figures(s1, s2, cdf, z_scores_df, my_ip):
    figs = {}


    agg = s2["ip_agg"].sort_values("dominance",ascending=False).head(15).reset_index()
    figs["talkers"] = px.bar(agg, x="src", y="total_bytes", color="total_bytes",
        color_continuous_scale="Blues", text="total_bytes",
        title="Top Talkers - Total Bytes (Session 2)",
        labels={"src":"IP","total_bytes":"Bytes"})
    figs["talkers"].update_traces(texttemplate="%{text:.2s}", textposition="outside",
                                  textfont=dict(size=11), cliponaxis=False)
    figs["talkers"].update_layout(xaxis_tickangle=-40, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        yaxis=dict(showticklabels=False),
        margin=dict(l=40, r=40, t=70, b=120))

    # Top Talkers - Session 1 (parallel structure, teal palette to differentiate)
    agg_s1 = s1["ip_agg"].sort_values("dominance",ascending=False).head(15).reset_index()
    figs["talkers_s1"] = px.bar(agg_s1, x="src", y="total_bytes", color="total_bytes",
        color_continuous_scale="Teal", text="total_bytes",
        title="Top Talkers - Total Bytes (Session 1)",
        labels={"src":"IP","total_bytes":"Bytes"})
    figs["talkers_s1"].update_traces(texttemplate="%{text:.2s}", textposition="outside",
                                     textfont=dict(size=11), cliponaxis=False)
    figs["talkers_s1"].update_layout(xaxis_tickangle=-40, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        yaxis=dict(showticklabels=False),
        margin=dict(l=40, r=40, t=70, b=120))


    agg2 = s2["ip_agg"].reset_index()
    q95_burst = agg2["burst_score"].quantile(0.95) if len(agg2) else 0
    q95_dom   = agg2["dominance"].quantile(0.95)   if len(agg2) else 0
    agg2["anomaly_type"] = agg2.apply(lambda r: _burst_anomaly_tag(r, q95_burst, q95_dom), axis=1)

    figs["burst"] = px.scatter(
        agg2, x="burst_score", y="dominance",
        color="anomaly", color_discrete_map={True:RED, False:BLUE},
        hover_name="src",
        size="total_bytes", size_max=35,
        custom_data=["anomaly_type", "count", "syn_count", "rst_count", "unique_dsts"],
        title="Burst Score vs Dominance - Session 2 (Anomaly Detection)",
        labels={"burst_score":"Burst Score","dominance":"Dominance","anomaly":"Suspicious"}
    )
    figs["burst"].update_traces(
        hovertemplate=(
            "<b>%{hovertext}</b><br>"
            "Session: 2<br>"
            "Anomaly type: %{customdata[0]}<br>"
            "Packets: %{customdata[1]:,}<br>"
            "SYN-only: %{customdata[2]:,}  ·  RST: %{customdata[3]:,}<br>"
            "Unique destinations: %{customdata[4]:,}<br>"
            "Burst score: %{x:.2f}  ·  Dominance: %{y:.2f}"
            "<extra></extra>"
        )
    )
    figs["burst"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))

    # Burst vs Scan - Session 1 (parallel structure)
    agg2_s1 = s1["ip_agg"].reset_index()
    q95_burst_s1 = agg2_s1["burst_score"].quantile(0.95) if len(agg2_s1) else 0
    q95_dom_s1   = agg2_s1["dominance"].quantile(0.95)   if len(agg2_s1) else 0
    agg2_s1["anomaly_type"] = agg2_s1.apply(
        lambda r: _burst_anomaly_tag(r, q95_burst_s1, q95_dom_s1), axis=1)
    figs["burst_s1"] = px.scatter(
        agg2_s1, x="burst_score", y="dominance",
        color="anomaly", color_discrete_map={True:RED, False:GREEN},
        hover_name="src",
        size="total_bytes", size_max=35,
        custom_data=["anomaly_type", "count", "syn_count", "rst_count", "unique_dsts"],
        title="Burst Score vs Dominance - Session 1 (Anomaly Detection)",
        labels={"burst_score":"Burst Score","dominance":"Dominance","anomaly":"Suspicious"}
    )
    figs["burst_s1"].update_traces(
        hovertemplate=(
            "<b>%{hovertext}</b><br>"
            "Session: 1<br>"
            "Anomaly type: %{customdata[0]}<br>"
            "Packets: %{customdata[1]:,}<br>"
            "SYN-only: %{customdata[2]:,}  ·  RST: %{customdata[3]:,}<br>"
            "Unique destinations: %{customdata[4]:,}<br>"
            "Burst score: %{x:.2f}  ·  Dominance: %{y:.2f}"
            "<extra></extra>"
        )
    )
    figs["burst_s1"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))


    p1 = pd.DataFrame(s1["protocols"].most_common(10), columns=["proto","count"])
    p1["session"] = "Session 1"
    p2 = pd.DataFrame(s2["protocols"].most_common(10), columns=["proto","count"])
    p2["session"] = "Session 2"
    figs["proto"] = px.bar(pd.concat([p1,p2]), x="proto", y="count", color="session",
        barmode="group", color_discrete_map={"Session 1":BLUE,"Session 2":RED},
        text="count",
        title="Protocol Distribution - Session 1 vs Session 2")
    figs["proto"].update_traces(texttemplate="%{text:,}", textposition="outside",
                                textfont=dict(size=11), cliponaxis=False)
    figs["proto"].update_layout(xaxis_tickangle=-30, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        legend=dict(orientation="h", yanchor="bottom", y=-0.32, xanchor="center", x=0.5),
        margin=dict(l=60, r=40, t=70, b=140), bargap=0.25, bargroupgap=0.12)


    def _build_dns_fig(session_obj, session_label, color_scale):
        dns_df = pd.DataFrame(session_obj["dns_real"].items(), columns=["domain","count"])
        dns_df = dns_df.sort_values("count", ascending=False).head(25)
        dns_df["display"] = dns_df["domain"].str.lower().apply(
            lambda d: ("www." + d) if not d.startswith("www.") else d)
        f = px.bar(dns_df.sort_values("count"), x="count", y="display",
            orientation="h", color="count", color_continuous_scale=color_scale, text="count",
            title=f"Internet Services Accessed - DNS Queries ({session_label})",
            labels={"count":"Requests","display":"Domain"})
        f.update_layout(height=700, yaxis=dict(automargin=True),
            plot_bgcolor=WHITE, paper_bgcolor=WHITE,
            margin=dict(l=10, r=120, t=70, b=40),
            xaxis=dict(automargin=True))
        f.update_traces(textposition="outside", cliponaxis=False)
        return f

    figs["dns"]    = _build_dns_fig(s2, "Session 2", "Teal")
    figs["dns_s1"] = _build_dns_fig(s1, "Session 1", "Blues")


    devs = sorted(set(s1["device_names"]) | set(s2["device_names"]))
    dev_rows = []
    for d in devs:
        base = d.replace(".local","")
        sc = sum(v for k,v in s2["bytes_src"].items() if base.lower() in k.lower())
        dev_rows.append({"device":d,"dominance":sc})
    dev_df = (pd.DataFrame(dev_rows).sort_values("dominance")
              if dev_rows else pd.DataFrame(columns=["device","dominance"]))


    figs["devices"] = go.Figure(go.Bar(
        y=dev_df["device"], x=dev_df["dominance"], orientation="h",
        marker=dict(
            color=dev_df["dominance"],
            colorscale=WARM_PALETTE_LOCAL,
            showscale=True,
            colorbar=dict(title="Dominance<br>level", thickness=18, x=1.04),
        ),
        text=[f"{v:,.0f}" for v in dev_df["dominance"]],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="<b>%{y}</b><br>Dominance score: %{x:,.0f}<extra></extra>",
    ))
    figs["devices"].update_layout(
        title="Network Device Dominance (Session 2) - colour intensity = activity level",
        height=max(420, len(dev_df) * 46),
        xaxis_title="Dominance Score (packets + bytes/1k)",
        yaxis=dict(automargin=True),
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=40, r=160, t=70, b=40),
    )

    # Devices - Session 1 (parallel structure, cool palette to differentiate)
    dev_rows_s1 = []
    for d in devs:
        base = d.replace(".local","")
        sc = sum(v for k,v in s1["bytes_src"].items() if base.lower() in k.lower())
        dev_rows_s1.append({"device":d,"dominance":sc})
    dev_df_s1 = (pd.DataFrame(dev_rows_s1).sort_values("dominance")
                 if dev_rows_s1 else pd.DataFrame(columns=["device","dominance"]))
    figs["devices_s1"] = go.Figure(go.Bar(
        y=dev_df_s1["device"], x=dev_df_s1["dominance"], orientation="h",
        marker=dict(
            color=dev_df_s1["dominance"],
            colorscale="Teal",
            showscale=True,
            colorbar=dict(title="Dominance<br>level", thickness=18, x=1.04),
        ),
        text=[f"{v:,.0f}" for v in dev_df_s1["dominance"]],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="<b>%{y}</b><br>Dominance score: %{x:,.0f}<extra></extra>",
    ))
    figs["devices_s1"].update_layout(
        title="Network Device Dominance (Session 1) - colour intensity = activity level",
        height=max(420, len(dev_df_s1) * 46),
        xaxis_title="Dominance Score (packets + bytes/1k)",
        yaxis=dict(automargin=True),
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=40, r=160, t=70, b=40),
    )


    figs["lstm"] = px.histogram(pd.DataFrame({"error":s2["lstm_errors"]}),
        x="error", nbins=60, color_discrete_sequence=[RED],
        title="LSTM Prediction Error Distribution (Session 2)")
    figs["lstm"].add_vline(x=s2["lstm_threshold"], line_dash="dash", line_color="#333",
        annotation_text=f"Threshold ({s2['lstm_threshold']:.4f})",
        annotation_position="top right")
    figs["lstm"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        xaxis_title="Prediction error (|actual − predicted|, scaled)",
        yaxis_title="Number of 10-second sequences")


    figs["lstm_s1"] = px.histogram(pd.DataFrame({"error":s1["lstm_errors"]}),
        x="error", nbins=60, color_discrete_sequence=[BLUE],
        title="LSTM Prediction Error Distribution (Session 1)")
    figs["lstm_s1"].add_vline(x=s1["lstm_threshold"], line_dash="dash", line_color="#333",
        annotation_text=f"Threshold ({s1['lstm_threshold']:.4f})",
        annotation_position="top right")
    figs["lstm_s1"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        xaxis_title="Prediction error (|actual − predicted|, scaled)",
        yaxis_title="Number of 10-second sequences")


    # Pick which IP to profile. Prefer the user-configured MY_DEVICE_IP
    # if it appears in the capture; otherwise fall back to the busiest LOCAL
    # IP so the chart actually shows something rather than rendering blank.
    # NaN guards: idxmax() on a Series whose values are all NaN returns NaN
    # itself (a single local IP gives std=0 -> z=NaN for every feature), so
    # we must explicitly reject NaN here or .loc[NaN] later would KeyError.
    _profile_ip = None
    _profile_note = ""
    if len(z_scores_df.index) > 0:
        if my_ip in z_scores_df.index:
            _profile_ip = my_ip
        else:
            try:
                cand = None
                if "total_bytes" in z_scores_df.columns:
                    s = z_scores_df["total_bytes"]
                    if s.notna().any():
                        cand = s.idxmax()
                if cand is None or pd.isna(cand):
                    cand = z_scores_df.index[0]
                if cand is not None and not pd.isna(cand):
                    _profile_ip = cand
                    if my_ip:
                        _profile_note = (f" - fallback (MY_DEVICE_IP "
                                         f"{my_ip} not observed in this "
                                         f"capture)")
            except Exception:
                _profile_ip = (z_scores_df.index[0]
                               if len(z_scores_df.index) else None)
                if _profile_ip is not None and pd.isna(_profile_ip):
                    _profile_ip = None

    if _profile_ip is not None:
        feats = ["count","total_bytes","mean_len","unique_dsts","burst_score","syn_count","rst_count"]
        try:
            row = z_scores_df.loc[_profile_ip, feats]
        except KeyError:
            row = None
        if row is None:
            figs["profile"] = go.Figure()
            figs["profile"].update_layout(
                title="Device Profile",
                annotations=[dict(text="Profile target unavailable in this capture",
                    xref="paper", yref="paper", x=0.5, y=0.5,
                    showarrow=False, font=dict(size=14))],
                plot_bgcolor=WHITE, paper_bgcolor=WHITE)
        else:
            # Replace NaN with 0 so the radar chart renders. NaN z-scores happen
            # whenever the LOCAL peer group has only 1 device (std = 0).
            my_z  = np.nan_to_num(row.values, nan=0.0).tolist()
            all_z = np.nan_to_num(z_scores_df[feats].values, nan=0.0)
            p75   = np.percentile(all_z, 75, axis=0).tolist()
            p25   = np.percentile(all_z, 25, axis=0).tolist()
            feat_labels = ["Packets","Bytes","Pkt Size","Unique Dsts","Burst","SYN","RST"]
            single_peer_note = ""
            if len(z_scores_df.index) < 2:
                single_peer_note = " (only one local device - z-scores degenerate)"
            figs["profile"] = go.Figure()
            figs["profile"].add_trace(go.Scatterpolar(r=my_z, theta=feat_labels,
                fill="toself", name=f"{_profile_ip}", line_color=RED))
            figs["profile"].add_trace(go.Scatterpolar(r=p75, theta=feat_labels,
                fill="toself", name="75th percentile", line_color=BLUE, opacity=0.4))
            figs["profile"].add_trace(go.Scatterpolar(r=p25, theta=feat_labels,
                fill="toself", name="25th percentile", line_color=GREEN, opacity=0.4))
            figs["profile"].update_layout(
                title=(f"Device Profile: {_profile_ip} vs Network (Z-scores)"
                       f"{_profile_note}{single_peer_note}"),
                polar=dict(radialaxis=dict(visible=True)),
                plot_bgcolor=WHITE, paper_bgcolor=WHITE)
    else:
        # zero local devices - last-resort placeholder figure
        figs["profile"] = go.Figure()
        figs["profile"].update_layout(
            title="Device Profile",
            annotations=[dict(text="No local devices detected in this capture",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False, font=dict(size=14))],
            plot_bgcolor=WHITE, paper_bgcolor=WHITE)


    if _profile_ip is not None:
        feats = ["count","total_bytes","mean_len","unique_dsts","burst_score","syn_count","rst_count"]
        try:
            z_vals = z_scores_df.loc[_profile_ip, feats]
        except KeyError:
            z_vals = None
        if z_vals is None:
            figs["zbar"] = go.Figure()
            figs["zbar"].update_layout(
                title="Z-score Deviation",
                annotations=[dict(text="Profile target unavailable in this capture",
                    xref="paper", yref="paper", x=0.5, y=0.5,
                    showarrow=False, font=dict(size=14))],
                plot_bgcolor=WHITE, paper_bgcolor=WHITE)
        else:
            vals = np.nan_to_num(z_vals.values, nan=0.0)
            figs["zbar"] = go.Figure(go.Bar(
                x=feats, y=vals,
                marker_color=[RED if v>2 else (BLUE if v>0 else GREEN) for v in vals],
                text=[f"{v:+.2f}" for v in vals], textposition="outside"
            ))
            figs["zbar"].add_hline(y=2,  line_dash="dash", line_color="orange", annotation_text="Alert threshold (+2)")
            figs["zbar"].add_hline(y=-2, line_dash="dash", line_color="orange")
            single_peer_note = ""
            if len(z_scores_df.index) < 2:
                single_peer_note = " (only one local device - z-scores degenerate)"
            figs["zbar"].update_layout(
                title=(f"Z-score Deviation: {_profile_ip} vs Network Mean"
                       f"{_profile_note}{single_peer_note}"),
                yaxis_title="Standard Deviations from Mean",
                plot_bgcolor=WHITE, paper_bgcolor=WHITE)
    else:
        figs["zbar"] = go.Figure()
        figs["zbar"].update_layout(
            title="Z-score Deviation",
            annotations=[dict(text="No local devices detected in this capture",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False, font=dict(size=14))],
            plot_bgcolor=WHITE, paper_bgcolor=WHITE)


    # Traffic Timeline - Session 2 (existing)
    df_time = s2["df_pkts"].copy()
    df_time["minute"] = ((df_time["time"] - df_time["time"].min()) // 60).astype(int)
    top_ips_list = s2["ip_agg"].sort_values("total_bytes",ascending=False).head(6).index.tolist()
    tl = df_time[df_time["src"].isin(top_ips_list)].groupby(["minute","src"])["size"].sum().reset_index()
    figs["timeline"] = px.line(tl, x="minute", y="size", color="src",
        title="Top 6 IPs - Traffic Volume Over Time (Session 2)",
        labels={"minute":"Minutes from start","size":"Bytes/min","src":"IP"})
    figs["timeline"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
        margin=dict(l=60, r=40, t=70, b=100))

    # Traffic Timeline - Session 1 (parallel structure)
    df_time_s1 = s1["df_pkts"].copy()
    if len(df_time_s1) > 0:
        df_time_s1["minute"] = ((df_time_s1["time"] - df_time_s1["time"].min()) // 60).astype(int)
        top_ips_list_s1 = s1["ip_agg"].sort_values("total_bytes",ascending=False).head(6).index.tolist()
        tl_s1 = (df_time_s1[df_time_s1["src"].isin(top_ips_list_s1)]
                 .groupby(["minute","src"])["size"].sum().reset_index())
        figs["timeline_s1"] = px.line(tl_s1, x="minute", y="size", color="src",
            title="Top 6 IPs - Traffic Volume Over Time (Session 1)",
            labels={"minute":"Minutes from start","size":"Bytes/min","src":"IP"})
        figs["timeline_s1"].update_layout(plot_bgcolor=WHITE, paper_bgcolor=WHITE,
            legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
            margin=dict(l=60, r=40, t=70, b=100))
    else:
        figs["timeline_s1"] = go.Figure()
        figs["timeline_s1"].update_layout(
            title="Top 6 IPs - Traffic Volume Over Time (Session 1)",
            annotations=[dict(text="No timeline data in Session 1",
                xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)])


    syn_rows = []
    for ip, cnt in s1["syn_counter"].most_common(10):
        syn_rows.append({"ip":ip, "syn":cnt, "session":"Session 1"})
    for ip, cnt in s2["syn_counter"].most_common(10):
        syn_rows.append({"ip":ip, "syn":cnt, "session":"Session 2"})
    syn_df = pd.DataFrame(syn_rows)
    if not syn_df.empty:
        figs["syn"] = px.bar(
            syn_df, x="syn", y="ip", color="session", barmode="group",
            orientation="h", text="syn",
            color_discrete_map={"Session 1":BLUE,"Session 2":RED},
            title="TCP SYN Packets per IP - Both Sessions (potential scan/flood)",
            labels={"ip":"IP","syn":"SYN packet count"},
        )
        figs["syn"].update_traces(textposition="outside", textfont=dict(size=11),
                                  cliponaxis=False)
        figs["syn"].update_layout(
            plot_bgcolor=WHITE, paper_bgcolor=WHITE,
            height=max(520, len(syn_df) * 28 + 140),
            yaxis=dict(automargin=True, categoryorder="total ascending"),
            xaxis=dict(title="SYN packet count"),
            bargap=0.25, bargroupgap=0.12,
            margin=dict(l=120, r=60, t=70, b=50),
        )


    top_b = cdf[cdf["status"]=="both"].nlargest(15,"bytes_s1") if (len(cdf) > 0 and "bytes_s1" in cdf.columns and pd.api.types.is_numeric_dtype(cdf["bytes_s1"]) and (cdf["status"]=="both").any()) else pd.DataFrame(columns=cdf.columns if len(cdf) > 0 else ["ip","bytes_s1","bytes_s2","change","status"])
    figs["cmp_traffic"] = go.Figure()
    figs["cmp_traffic"].add_trace(go.Bar(
        name="Session 1", x=top_b["ip"], y=top_b["bytes_s1"], marker_color=BLUE,
        text=top_b["bytes_s1"], texttemplate="%{text:.2s}",
        textposition="outside", textfont=dict(size=11), cliponaxis=False,
    ))
    figs["cmp_traffic"].add_trace(go.Bar(
        name="Session 2", x=top_b["ip"], y=top_b["bytes_s2"], marker_color=RED,
        text=top_b["bytes_s2"], texttemplate="%{text:.2s}",
        textposition="outside", textfont=dict(size=11), cliponaxis=False,
    ))
    figs["cmp_traffic"].update_layout(barmode="group",
        title="Traffic Volume per IP - Session 1 vs Session 2",
        xaxis_tickangle=-40, plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=60, r=40, t=70, b=110), bargap=0.25, bargroupgap=0.12)


    new_df  = cdf[cdf["status"]=="new"].sort_values("bytes_s2",ascending=False).head(15)
    gone_df = cdf[cdf["status"]=="gone"].sort_values("bytes_s1",ascending=False).head(15)
    new_df["bytes"]  = new_df["bytes_s2"]
    new_df["status_label"] = "new in S2"
    gone_df["bytes"] = gone_df["bytes_s1"]
    gone_df["status_label"] = "gone after S1"
    joined = pd.concat([new_df[["ip","bytes","status_label"]],
                        gone_df[["ip","bytes","status_label"]]])
    figs["cmp_new_gone"] = px.bar(joined, x="bytes", y="ip", orientation="h",
        color="status_label",
        color_discrete_map={"new in S2":GREEN,"gone after S1":RED},
        title="New and Gone IPs Between Sessions",
        labels={"bytes":"Bytes","ip":"IP"})
    figs["cmp_new_gone"].update_layout(yaxis=dict(automargin=True),
        height=700, plot_bgcolor=WHITE, paper_bgcolor=WHITE)


    delta_df = cdf[cdf["status"]=="both"].copy()
    delta_df = delta_df.reindex(delta_df["change"].abs().sort_values(ascending=False).index).head(15)
    figs["cmp_delta"] = go.Figure(go.Bar(
        x=delta_df["ip"], y=delta_df["change"],
        marker_color=delta_df["change"].apply(lambda x: GREEN if x>0 else RED),
        text=[f"{v:+,.0f}" for v in delta_df["change"]], textposition="outside"
    ))
    figs["cmp_delta"].update_layout(title="Biggest Traffic Change Between Sessions",
        xaxis_tickangle=-40, plot_bgcolor=WHITE, paper_bgcolor=WHITE)


    figs["upload_s1"]   = _pie_top10_others(s1["bytes_src"],
                                            "Upload Distribution - bytes sent per IP (Session 1)")
    figs["upload_s2"]   = _pie_top10_others(s2["bytes_src"],
                                            "Upload Distribution - bytes sent per IP (Session 2)")
    figs["download_s1"] = _pie_top10_others(s1["bytes_dst"],
                                            "Download Distribution - bytes received per IP (Session 1)")
    figs["download_s2"] = _pie_top10_others(s2["bytes_dst"],
                                            "Download Distribution - bytes received per IP (Session 2)")

    return figs


def make_device_hierarchy_table(local_df, label="Devices"):
    """: rich device table with threat tier, confidence, MAC privacy. Columns: Device Name | Type › Subtype | Vendor | IP / MAC | Threat | Score | Confidence | MAC Privacy | Bytes Sorted by threat severity descending."""
    if local_df is None or len(local_df) == 0:
        f = go.Figure()
        f.update_layout(title=f"{label} - Device Hierarchy",
            annotations=[dict(text="No local devices observed yet",
                x=0.5, y=0.5, showarrow=False, font=dict(size=14, color="#888"))])
        return f

    df = local_df.copy()

    type_sub = df["category"].astype(str) + " › " + df["subcategory"].astype(str)
    ip_mac   = df["ip"].astype(str) + "<br><span style='color:#888;font-size:0.78em'>"\
               + df["mac"].astype(str) + "</span>"
    tier_emoji = {"LOW":"🟢", "MEDIUM":"🟡", "HIGH":"🟠", "CRITICAL":"🔴"}
    threat_col = df["threat_tier"].map(lambda t: f"{tier_emoji.get(t,'❔')} {t}")
    conf_emoji = {"high":"✓✓✓", "medium":"✓✓", "low":"✓", "very-low":"~"}
    conf_col   = df["confidence"].map(lambda c: conf_emoji.get(c,"?") + "  " + c)
    privacy_col = df["mac_privacy_random"].map(lambda r: "🔒 randomized" if r else "-")


    tier_bg = {"CRITICAL":"#ffebee", "HIGH":"#fff3e0", "MEDIUM":"#fffde7", "LOW":"#f1f8e9"}
    row_colors = [tier_bg.get(t, "white") for t in df["threat_tier"]]

    f = go.Figure(data=[go.Table(
        columnwidth=[140, 200, 120, 180, 100, 60, 110, 110, 90],
        header=dict(
            values=["<b>Device Name</b>", "<b>Type › Subtype</b>", "<b>Vendor</b>",
                    "<b>IP / MAC</b>", "<b>Threat</b>", "<b>Score</b>",
                    "<b>Confidence</b>", "<b>MAC Privacy</b>", "<b>Bytes</b>"],
            fill_color="#1565C0",
            font=dict(color="white", size=12, family="system-ui"),
            align="left", height=34,
        ),
        cells=dict(
            values=[
                df["device_name"], type_sub, df["vendor"], ip_mac,
                threat_col, df["threat_score"],
                conf_col, privacy_col,
                df["bytes"].map("{:,}".format),
            ],
            fill_color=[row_colors] * 9,
            align="left",
            font=dict(size=11, family="system-ui"),
            height=42,
        ),
    )])
    n = len(df)
    crit  = int((df["threat_tier"] == "CRITICAL").sum())
    high  = int((df["threat_tier"] == "HIGH").sum())
    med   = int((df["threat_tier"] == "MEDIUM").sum())
    low   = int((df["threat_tier"] == "LOW").sum())
    f.update_layout(
        title=(f"{label} - {n} devices  ·  "
               f"🔴 {crit} CRITICAL · 🟠 {high} HIGH · "
               f"🟡 {med} MEDIUM · 🟢 {low} LOW"),
        height=max(280, 60 + 42 * min(n, 18) + 50),
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return f

def make_external_provider_pie(ext_df, title="External traffic by provider"):
    if ext_df is None or len(ext_df) == 0:
        return go.Figure().update_layout(title=title)
    g = ext_df.groupby("provider")["bytes"].sum().sort_values(ascending=False)

    if len(g) > 12:
        top, rest = g.head(11), g.tail(len(g)-11)
        g = pd.concat([top, pd.Series({"Other": int(rest.sum())})])
    f = go.Figure(go.Pie(labels=g.index, values=g.values, hole=0.45,
        textinfo="label+percent", textposition="outside",
        hovertemplate="<b>%{label}</b><br>Bytes: %{value:,}<br>%{percent}<extra></extra>"))
    f.update_layout(title=title, height=440, margin=dict(l=10,r=10,t=50,b=10),
                    showlegend=False)
    return f

def make_external_service_type_bar(ext_df, title="External traffic by service type"):
    if ext_df is None or len(ext_df) == 0:
        return go.Figure().update_layout(title=title)
    g = ext_df.groupby("type")["bytes"].sum().sort_values(ascending=True)
    f = go.Figure(go.Bar(x=g.values, y=g.index, orientation="h",
        marker=dict(color=g.values, colorscale="Teal"),
        hovertemplate="<b>%{y}</b><br>Bytes: %{x:,}<extra></extra>"))
    f.update_layout(title=title, height=380, margin=dict(l=10,r=20,t=50,b=10),
                    xaxis_title="Bytes")
    return f

def make_coverage_gauges(cov, label):
    """Two-gauge subplot showing identification coverage by IP count and by bytes."""
    from plotly.subplots import make_subplots
    fig = make_subplots(rows=1, cols=4, specs=[[{"type":"indicator"}]*4],
                        subplot_titles=("Local by IP","Local by bytes",
                                        "External by IP","External by bytes"))
    bar_colour = lambda pct: "#2e7d32" if pct >= 80 else "#f9a825" if pct >= 50 else "#c62828"
    fig.add_trace(go.Indicator(mode="gauge+number",
        value=cov["local_pct_ips"], number={"suffix":"%"},
        gauge={"axis":{"range":[0,100]}, "bar":{"color":bar_colour(cov["local_pct_ips"])}}),
        row=1, col=1)
    fig.add_trace(go.Indicator(mode="gauge+number",
        value=cov["local_pct_bytes"], number={"suffix":"%"},
        gauge={"axis":{"range":[0,100]}, "bar":{"color":bar_colour(cov["local_pct_bytes"])}}),
        row=1, col=2)
    fig.add_trace(go.Indicator(mode="gauge+number",
        value=cov["external_pct_ips"], number={"suffix":"%"},
        gauge={"axis":{"range":[0,100]}, "bar":{"color":bar_colour(cov["external_pct_ips"])}}),
        row=1, col=3)
    fig.add_trace(go.Indicator(mode="gauge+number",
        value=cov["external_pct_bytes"], number={"suffix":"%"},
        gauge={"axis":{"range":[0,100]}, "bar":{"color":bar_colour(cov["external_pct_bytes"])}}),
        row=1, col=4)
    fig.update_layout(title=f"Identification Coverage - {label}",
                      height=320, margin=dict(l=20,r=20,t=80,b=10))
    return fig


FIGS = {}
LOCAL_INV_S1 = pd.DataFrame()
LOCAL_INV_S2 = pd.DataFrame()
EXTERNAL_INV_S1 = pd.DataFrame()
EXTERNAL_INV_S2 = pd.DataFrame()
COVERAGE_S1 = {"local_total_ips":0,"local_identified_ips":0,
               "local_total_bytes":0,"local_identified_bytes":0,
               "local_pct_ips":0,"local_pct_bytes":0,
               "external_total_ips":0,"external_identified_ips":0,
               "external_total_bytes":0,"external_identified_bytes":0,
               "external_pct_ips":0,"external_pct_bytes":0}
COVERAGE_S2 = dict(COVERAGE_S1)


def rebuild_inventories():
    """Recompute LOCAL_INV_* and EXTERNAL_INV_* and COVERAGE_* from current S1/S2."""
    global LOCAL_INV_S1, LOCAL_INV_S2
    global EXTERNAL_INV_S1, EXTERNAL_INV_S2
    global COVERAGE_S1, COVERAGE_S2

    if S1 is not None:
        LOCAL_INV_S1    = build_local_inventory(S1)
        EXTERNAL_INV_S1 = build_external_inventory(S1)
        COVERAGE_S1     = compute_coverage(LOCAL_INV_S1, EXTERNAL_INV_S1)
    else:
        LOCAL_INV_S1    = pd.DataFrame()
        EXTERNAL_INV_S1 = pd.DataFrame()
    if S2 is not None:
        LOCAL_INV_S2    = build_local_inventory(S2)
        EXTERNAL_INV_S2 = build_external_inventory(S2)
        COVERAGE_S2     = compute_coverage(LOCAL_INV_S2, EXTERNAL_INV_S2)
    else:
        LOCAL_INV_S2    = pd.DataFrame()
        EXTERNAL_INV_S2 = pd.DataFrame()



def _apply_aurora_layout(figs_dict):
    """Make every Plotly figure transparent-background, light-text, with the
    Inter Tight + Newsreader font pair so the figures blend into the Aurora
    glass panels."""
    AUR_LAYOUT = dict(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9b94b8", family="Inter Tight, sans-serif", size=12),
        title=dict(font=dict(color="#e8e4f5",
                              family="Newsreader, Georgia, serif", size=18)),
        legend=dict(
            font=dict(color="#9b94b8", family="Inter Tight, sans-serif"),
            bgcolor="rgba(255,255,255,0.04)",
            bordercolor="rgba(255,255,255,0.08)",
            borderwidth=1,
        ),
        hoverlabel=dict(
            bgcolor="rgba(13,10,26,0.92)",
            bordercolor="rgba(139,92,246,0.4)",
            font=dict(color="#e8e4f5", family="Inter Tight, sans-serif"),
        ),
        margin=dict(l=60, r=40, t=70, b=50),
    )
    AUR_AXES = dict(
        gridcolor="rgba(255,255,255,0.06)",
        zerolinecolor="rgba(255,255,255,0.10)",
        linecolor="rgba(255,255,255,0.15)",
        tickfont=dict(color="#9b94b8", family="Inter Tight, sans-serif"),
        title=dict(font=dict(color="#9b94b8", family="Inter Tight, sans-serif")),
    )
    for k, fig in figs_dict.items():
        if not hasattr(fig, "update_layout"):
            continue
        try:
            fig.update_layout(**AUR_LAYOUT)
            fig.update_xaxes(**AUR_AXES)
            fig.update_yaxes(**AUR_AXES)
        except Exception:
            pass


def rebuild_figures():
    """Rebuild the entire FIGS dictionary from current session state."""
    global FIGS

    rebuild_inventories()

    primary = S2 if S2 is not None else S1
    if primary is None:
        FIGS = {}
        print("rebuild_figures: no sessions loaded - FIGS cleared")
        return FIGS

    s1_eff = S1 if S1 is not None else primary
    s2_eff = S2 if S2 is not None else primary

    FIGS = make_figures(s1_eff, s2_eff, compare_df if compare_df is not None
                        else pd.DataFrame({
            "ip":       pd.Series(dtype="object"),
            "bytes_s1": pd.Series(dtype="int64"),
            "bytes_s2": pd.Series(dtype="int64"),
            "change":   pd.Series(dtype="int64"),
            "status":   pd.Series(dtype="object"),
        }),
                        z_scores if z_scores is not None else pd.DataFrame(),
                        MY_DEVICE_IP)

    build_browse_figures(S1, S2)
    FIGS["browse_cat_s1"]   = FIG_BROWSE_CAT_S1
    FIGS["browse_cat"]      = FIG_BROWSE_CAT_S2
    FIGS["browse_hour_s1"]  = FIG_BROWSE_HOUR_S1
    FIGS["browse_hour"]     = FIG_BROWSE_HOUR_S2
    FIGS["confusion"]       = FIG_CONFUSION
    FIGS["sensitivity"]     = FIG_SENSITIVITY

    FIGS["dev_hierarchy_s1"] = make_device_hierarchy_table(LOCAL_INV_S1, "Session 1")
    FIGS["dev_hierarchy_s2"] = make_device_hierarchy_table(LOCAL_INV_S2, "Session 2")
    FIGS["ext_provider_s1"]  = make_external_provider_pie(
        EXTERNAL_INV_S1, "S1 - External traffic by provider")
    FIGS["ext_provider_s2"]  = make_external_provider_pie(
        EXTERNAL_INV_S2, "S2 - External traffic by provider")
    FIGS["ext_type_s1"]      = make_external_service_type_bar(
        EXTERNAL_INV_S1, "S1 - External traffic by service type")
    FIGS["ext_type_s2"]      = make_external_service_type_bar(
        EXTERNAL_INV_S2, "S2 - External traffic by service type")
    FIGS["coverage_s1"]      = make_coverage_gauges(COVERAGE_S1, "Session 1")
    FIGS["coverage_s2"]      = make_coverage_gauges(COVERAGE_S2, "Session 2")


    try:
        inv1_eff = LOCAL_INV_S1 if S1 is not None else LOCAL_INV_S2
        inv2_eff = LOCAL_INV_S2 if S2 is not None else LOCAL_INV_S1
        FIGS["device_map"]    = _build_device_map_figure(
            s1_eff, "S1", inv1_eff)
        FIGS["device_map_s2"] = _build_device_map_figure(
            s2_eff, "S2", inv2_eff)
    except Exception as e:
        print(f"Device map build failed: {e}")
        import traceback; traceback.print_exc()
    try:
        FIGS["proximity"]    = _build_proximity_map_figure(s1_eff, "S1")
        FIGS["proximity_s2"] = _build_proximity_map_figure(s2_eff, "S2")
    except Exception as e:
        print(f"Proximity map build failed: {e}")
        import traceback; traceback.print_exc()
    _apply_aurora_layout(FIGS)

    print(f"rebuild_figures: {len(FIGS)} figures registered")
    return FIGS


print("FIGS empty; call rebuild_figures() after a session loads.")


# ==== notebook cell 47 ====

# === Advanced Threat Detection engines (integrated, MITRE ATT&CK-aligned) ===
# The detectors themselves live in app/advanced_engines.py - a Dash-free
# module - so the CLI pipeline (attack_tests/run_pipeline.py) and the VM
# worker run exactly the same code the SECURITY views render. Importing
# this notebook's module starts the Dash server, which is why the engines
# could not be shared while they lived here.
# All identifiers keep their _adv_ prefix so they cannot collide with the
# main dashboard's existing names (e.g. the main loader has its own
# is_private heuristic for a different feature).

import os as _adv_os_boot
import sys as _adv_sys_boot

_ADV_ENGINES_DIR = (os.path.dirname(os.path.abspath(__file__))
                    if "__file__" in globals() else os.getcwd())
if _ADV_ENGINES_DIR not in _adv_sys_boot.path:
    _adv_sys_boot.path.insert(0, _ADV_ENGINES_DIR)

import advanced_engines as _adv

# Re-export the thresholds and helpers under their historical names so any
# cell (or an analyst poking at the notebook) still finds them here.
ADV_BEACON_MIN_EVENTS  = _adv.ADV_BEACON_MIN_EVENTS
ADV_BEACON_SCORE_FLAG  = _adv.ADV_BEACON_SCORE_FLAG
ADV_DNS_UNIQUE_MIN     = _adv.ADV_DNS_UNIQUE_MIN
ADV_DNS_UNIQUE_RATIO   = _adv.ADV_DNS_UNIQUE_RATIO
ADV_DNS_ENTROPY_FLAG   = _adv.ADV_DNS_ENTROPY_FLAG
ADV_DNS_LABEL_LEN_FLAG = _adv.ADV_DNS_LABEL_LEN_FLAG
ADV_NX_STORM_MIN       = _adv.ADV_NX_STORM_MIN
ADV_DGA_MIN_LABEL_LEN  = _adv.ADV_DGA_MIN_LABEL_LEN
ADV_DGA_LOGPROB_FLAG   = _adv.ADV_DGA_LOGPROB_FLAG
ADV_FUSION_WINDOW_MIN  = _adv.ADV_FUSION_WINDOW_MIN

_ADV_TSHARK_FIELDS = _adv._ADV_TSHARK_FIELDS
_ADV_COLS          = _adv._ADV_COLS
_ADV_SIGNAL_COLS   = _adv._ADV_SIGNAL_COLS
_ADV_COMMON_DOMAINS = _adv._ADV_COMMON_DOMAINS
_AdvCloudDB        = _adv._AdvCloudDB

_adv_is_private          = _adv._adv_is_private
_adv_load_pk             = _adv._adv_load_pk
_adv_sig                 = _adv._adv_sig
_adv_shannon             = _adv._adv_shannon
_adv_vowel_ratio         = _adv._adv_vowel_ratio
_adv_registrable         = _adv._adv_registrable
_adv_leftmost_label      = _adv._adv_leftmost_label
_adv_train_bigram        = _adv._adv_train_bigram
_adv_score_label         = _adv._adv_score_label
_adv_beacon_scores       = _adv._adv_beacon_scores
_adv_max_distinct_in_window = _adv._adv_max_distinct_in_window
_adv_detect_arp_dhcp     = _adv._adv_detect_arp_dhcp
_adv_detect_dns_tunnel   = _adv._adv_detect_dns_tunnel
_adv_detect_dga          = _adv._adv_detect_dga
_adv_detect_beaconing    = _adv._adv_detect_beaconing
_adv_detect_tls          = _adv._adv_detect_tls
_adv_fuse                = _adv._adv_fuse


def run_advanced_threats(pcap_path, label):
    """Run the 6 MITRE-mapped detectors on a single pcap and return a dict
    with all signals + per-device kill-chain fusion. Safe: returns
    {"available": False, "reason": "..."} on any failure.

    Passes the notebook's already-resolved tshark path and config location
    so the dashboard keeps using exactly what it discovered at startup."""
    try:
        cloud_path = _find_config("cloud_ranges.json")
    except Exception:
        cloud_path = None
    return _adv.run_advanced_threats(
        pcap_path, label,
        tshark_path=_TSHARK_PATH_FOR_LOADER,
        cloud_ranges_path=cloud_path)


print("Advanced threat engines ready: arp_dhcp, dns_tunnel, dga, beaconing, tls, fusion")


# ==== notebook cell 48 ====

INK            = "#e8e4f5"
INK_DIM        = "#9b94b8"
INK_MUTE       = "#5a536f"
BG_BASE        = "#07050f"
VIOLET         = "#8b5cf6"
VIOLET_BRIGHT  = "#a78bfa"
CYAN           = "#22d3ee"
CYAN_BRIGHT    = "#67e8f9"
MAGENTA        = "#f472b6"
LIME           = "#a3e635"
AMBER          = "#fbbf24"
RED_ACCENT     = "#f87171"
MOSS           = "#84cc16"

BLUE  = VIOLET
DBLUE = VIOLET_BRIGHT
RED   = RED_ACCENT
GREEN = LIME
WHITE = "rgba(0,0,0,0)"

GLASS_BG            = "rgba(255,255,255,0.04)"
GLASS_BG_STRONG     = "rgba(255,255,255,0.07)"
GLASS_BORDER        = "rgba(255,255,255,0.08)"
GLASS_BORDER_STRONG = "rgba(255,255,255,0.14)"

CARD = {"background":GLASS_BG, "padding":"18px", "borderRadius":"18px",
        "border":f"1px solid {GLASS_BORDER}",
        "backdropFilter":"blur(24px) saturate(140%)",
        "WebkitBackdropFilter":"blur(24px) saturate(140%)"}

from dash import MATCH, ALL


NAV_ITEMS = [
    # (nav_id, icon, label, section, scope)
    # scope: "s1" / "s2" - shown only on that session sub-tab;
    #        "any"       - session-agnostic, shown on both sub-tabs.
    ("live_recording",   "\U0001F534", "Live Recording",          "live",      "any"),

    ("talkers_s1",       "\U0001F4E1", "Top Talkers",             "analysis",  "s1"),
    ("burst_s1",         "\u26A0\uFE0F", "Burst vs Scan",           "analysis",  "s1"),
    ("proto",            "\U0001F4CA", "Protocols (S1 vs S2)",    "analysis",  "any"),
    ("dns_s1",           "\U0001F310", "DNS Services",            "analysis",  "s1"),
    ("devices_s1",       "\U0001F4BB", "Devices",                 "analysis",  "s1"),
    ("timeline_s1",      "\U0001F4C8", "Traffic Timeline",        "analysis",  "s1"),
    ("updown_s1",        "\U0001F4E4", "Upload / Download",       "analysis",  "s1"),
    ("lstm_s1",          "\U0001F916", "LSTM Errors",             "analysis",  "s1"),
    ("insights",         "\U0001F9ED", "Analysis Insights",       "analysis",  "any"),

    ("talkers",          "\U0001F4E1", "Top Talkers",             "analysis",  "s2"),
    ("burst",            "\u26A0\uFE0F", "Burst vs Scan",           "analysis",  "s2"),
    ("dns",              "\U0001F310", "DNS Services",            "analysis",  "s2"),
    ("devices",          "\U0001F4BB", "Devices",                 "analysis",  "s2"),
    ("timeline",         "\U0001F4C8", "Traffic Timeline",        "analysis",  "s2"),
    ("updown_s2",        "\U0001F4E4", "Upload / Download",       "analysis",  "s2"),
    ("lstm",             "\U0001F916", "LSTM Errors",             "analysis",  "s2"),

    ("profile",          "\U0001F3AF", "My Device Profile",       "device",    "any"),
    ("zbar",             "\U0001F4CF", "Z-score Deviation",       "device",    "any"),

    ("browse_cat_s1",    "\U0001F50E", "Browsing Categories",     "browsing",  "s1"),
    ("browse_hour_s1",   "\U0001F550", "Browsing by Hour",        "browsing",  "s1"),
    ("browse_cat",       "\U0001F50E", "Browsing Categories",     "browsing",  "s2"),
    ("browse_hour",      "\U0001F550", "Browsing by Hour",        "browsing",  "s2"),
    ("ip_history",       "\U0001F50D", "IP Browsing History",     "browsing",  "any"),

    ("syn",              "\U0001F50D", "TCP SYN Analysis",        "security",  "any"),
    ("confusion",        "\U0001F9E9", "Model Agreement Matrix",  "security",  "any"),
    ("sensitivity",      "\U0001F4D0", "Contamination Sweep",     "security",  "any"),

    ("adv_beaconing_s1", "\U0001F300", "Beaconing (C2)",          "security",  "s1"),
    ("adv_dns_tunnel_s1","\U0001F6A7", "DNS Tunneling",           "security",  "s1"),
    ("adv_dga_s1",       "\U0001F916", "DGA Domains",             "security",  "s1"),
    ("adv_arp_dhcp_s1",  "\U0001F4E1", "ARP / Rogue DHCP",        "security",  "s1"),
    ("adv_tls_s1",       "\U0001F510", "TLS Fingerprint",         "security",  "s1"),
    ("adv_killchain_s1", "\u2694\uFE0F", "Kill-Chain Risk",         "security",  "s1"),
    ("adv_beaconing_s2", "\U0001F300", "Beaconing (C2)",          "security",  "s2"),
    ("adv_dns_tunnel_s2","\U0001F6A7", "DNS Tunneling",           "security",  "s2"),
    ("adv_dga_s2",       "\U0001F916", "DGA Domains",             "security",  "s2"),
    ("adv_arp_dhcp_s2",  "\U0001F4E1", "ARP / Rogue DHCP",        "security",  "s2"),
    ("adv_tls_s2",       "\U0001F510", "TLS Fingerprint",         "security",  "s2"),
    ("adv_killchain_s2", "\u2694\uFE0F", "Kill-Chain Risk",         "security",  "s2"),

    ("cmp_traffic",      "\U0001F504", "Traffic S1 vs S2",        "compare",   "s2"),
    ("cmp_new_gone",     "\U0001F195", "New / Gone IPs",          "compare",   "s2"),
    ("cmp_delta",        "\U0001F4C9", "Traffic Delta",           "compare",   "s2"),

    ("dev_hierarchy_s1", "\U0001F5C2", "Device Hierarchy",        "inventory", "s1"),
    ("device_map",       "\U0001F5FA", "Device Map (PCA)",        "inventory", "s1"),
    ("proximity",        "\U0001F4E1", "Proximity Map (RSSI)",    "inventory", "s1"),
    ("dev_hierarchy_s2", "\U0001F5C2", "Device Hierarchy",        "inventory", "s2"),
    ("device_map_s2",    "\U0001F5FA", "Device Map (PCA)",        "inventory", "s2"),
    ("proximity_s2",     "\U0001F4E1", "Proximity Map (RSSI)",    "inventory", "s2"),

    ("external_s1",      "\U0001F30D", "External Traffic",        "external",  "s1"),
    ("external_s2",      "\U0001F30D", "External Traffic",        "external",  "s2"),

    ("coverage_s1",      "\U0001F3AF", "Identification Coverage", "coverage",  "s1"),
    ("coverage_s2",      "\U0001F3AF", "Identification Coverage", "coverage",  "s2"),
]
LABEL_MAP = {nid:f"{icon}  {lbl}" for nid,icon,lbl,_,_ in NAV_ITEMS}

# Per-chart session scope, plus the set of everything that needs S2 (the
# whole S2 sub-tab stays locked until a second session exists).
SESSION_SCOPE = {nid: scope for nid, _, _, _, scope in NAV_ITEMS}
NEEDS_S2_IDS  = {nid for nid, scope in SESSION_SCOPE.items() if scope == "s2"}

# S1 <-> S2 twin views: switching the session sub-tab keeps the user on the
# equivalent chart of the other session.
SESSION_TWIN = {
    "talkers_s1":"talkers", "burst_s1":"burst", "dns_s1":"dns",
    "devices_s1":"devices", "timeline_s1":"timeline",
    "updown_s1":"updown_s2", "lstm_s1":"lstm",
    "browse_cat_s1":"browse_cat", "browse_hour_s1":"browse_hour",
    "dev_hierarchy_s1":"dev_hierarchy_s2", "device_map":"device_map_s2",
    "proximity":"proximity_s2", "external_s1":"external_s2",
    "coverage_s1":"coverage_s2",
    "adv_beaconing_s1":"adv_beaconing_s2",
    "adv_dns_tunnel_s1":"adv_dns_tunnel_s2",
    "adv_dga_s1":"adv_dga_s2", "adv_arp_dhcp_s1":"adv_arp_dhcp_s2",
    "adv_tls_s1":"adv_tls_s2", "adv_killchain_s1":"adv_killchain_s2",
}
SESSION_TWIN.update({v: k for k, v in list(SESSION_TWIN.items())})


# === Top-level tab structure ============================================
# Replaces the long-scrolling sidebar with two top tabs (Analyze + Security).
# Each tab filters NAV_ITEMS by section_id.
TABS_SPEC = [
    ("analyze",  "📊", "Analyze"),
    ("security", "🛡️", "Security"),
]
SECTION_TO_TAB = {
    "live":      "analyze",
    "analysis":  "analyze",
    "device":    "analyze",
    "browsing":  "analyze",
    "compare":   "analyze",
    "inventory": "analyze",
    "external":  "analyze",
    "coverage":  "analyze",
    "security":  "security",
}
def _default_chart_for_tab(tab_id, session="s1"):
    """First NAV item of this tab that is visible on the given session
    sub-tab - used after a tab / session-tab click."""
    for nid, _, _, sec, scope in NAV_ITEMS:
        if SECTION_TO_TAB.get(sec, "analyze") != tab_id:
            continue
        if scope != "any" and scope != session:
            continue
        return nid
    return NAV_ITEMS[0][0]

def _tab_for_chart(chart_id):
    """Which tab does this chart_id live under? Used to auto-sync the tab
    strip when active-chart changes from outside (e.g. handle_analyze_staged
    sends the user to 'talkers_s1' which is on the Analyze tab)."""
    for nid, _, _, sec, _scope in NAV_ITEMS:
        if nid == chart_id:
            return SECTION_TO_TAB.get(sec, "analyze")
    return "analyze"

def _session_for_chart(chart_id):
    """'s1' / 's2' for session-scoped charts, None for shared views."""
    scope = SESSION_SCOPE.get(chart_id)
    return scope if scope in ("s1", "s2") else None
# ========================================================================



LSTM_EXPLAIN = (
    "The LSTM is trained on the network rhythm - for every second of capture, the average "
    "packet size becomes one data point. The model learns to predict the next second from "
    "the previous 10. A large prediction error means the actual traffic did not match what "
    "the model expected - a burst, sudden silence, or irregular pattern. The dashed line "
    "is the alert threshold (validation mean + 2σ)."
)
ZSCORE_EXPLAIN = (
    "A Z-score tells you how many standard deviations a feature value is above or below "
    "the mean of all LOCAL devices on this network. Z ≈ 0 means typical; Z > +2 is "
    "significantly higher than the local peer group; Z > +3 is extreme. Bars beyond ±2 "
    "warrant a closer look."
)
EXPLANATIONS = {
    "lstm":          LSTM_EXPLAIN,
    "lstm_s1":       LSTM_EXPLAIN,
    "zbar":          ZSCORE_EXPLAIN,
    "profile":       ZSCORE_EXPLAIN,
}


def _section_divider(label):
    """Horizontal divider with a small uppercase label, used between sections of the intro."""
    return html.Div([
        html.Div(style={"flex":"1","height":"1px","background":GLASS_BORDER_STRONG}),
        html.Span(label, style={
            "padding":"0 14px","color":INK_MUTE,
            "fontFamily":"'JetBrains Mono', monospace",
            "fontSize":"10px","letterSpacing":"0.22em",
            "textTransform":"uppercase","fontWeight":"600"}),
        html.Div(style={"flex":"1","height":"1px","background":GLASS_BORDER_STRONG}),
    ], style={"display":"flex","alignItems":"center","margin":"32px 0 22px"})


def _h2(text):
    """Section heading with serif typography, not italic."""
    return html.H2(text, style={
        "color":INK,"fontWeight":"500","fontSize":"1.7rem",
        "fontFamily":"'Newsreader', Georgia, serif",
        "letterSpacing":"-0.015em","marginBottom":"14px","lineHeight":"1.15"})


def _h3(text, color=None):
    return html.H3(text, style={
        "color":color or INK,"fontWeight":"500","fontSize":"1.15rem",
        "fontFamily":"'Newsreader', Georgia, serif",
        "letterSpacing":"-0.01em","marginBottom":"10px","marginTop":"16px"})


def _p(text, color=None):
    """Body paragraph, NOT italic."""
    return html.P(text, style={
        "color":color or INK_DIM,"fontSize":"0.95rem",
        "lineHeight":"1.6","marginBottom":"10px"})


def _code_block(text, color_accent=None):
    """Code block in JetBrains Mono. Used for ARP dialogs, TCP handshake, etc."""
    return html.Pre(text, style={
        "background":"rgba(0,0,0,0.35)",
        "border":f"1px solid {GLASS_BORDER}",
        "borderRadius":"10px","padding":"12px 16px",
        "fontFamily":"'JetBrains Mono', monospace",
        "fontSize":"0.85rem","color":INK,
        "borderLeft":f"3px solid {color_accent or VIOLET_BRIGHT}",
        "marginBottom":"12px","overflow":"auto","lineHeight":"1.55",
        "whiteSpace":"pre-wrap"})


def _bold(text, color=None):
    return html.Strong(text, style={"color":color or INK,"fontWeight":"600"})


def _risk_line(text, color=RED_ACCENT):
    """Single 🚨 risk callout line. Accepts either a string or a list of
    pieces (strings + html.Span etc). Lists are spread into the children
    array instead of being nested as a single list element - nesting a list
    inside a Dash component's children list triggers React error #31 in some
    renderers because the inner array is treated as a non-keyed React child."""
    children = [html.Span("🚨  ", style={"marginRight":"4px"})]
    if isinstance(text, (list, tuple)):
        children.extend(text)
    else:
        children.append(text)
    return html.Div(children, style={"color":color,"fontSize":"0.9rem",
              "marginTop":"8px","marginBottom":"4px",
              "padding":"8px 12px","borderRadius":"8px",
              "background":"rgba(248,113,113,0.06)",
              "border":f"1px solid rgba(248,113,113,0.18)"})


def _layer_card(layer, name, protos, note, color, bg_color):
    """Educational card for one of the four TCP/IP layers on the intro view."""
    return html.Div([
        html.Div(f"{layer} · {name}", style={
            "fontWeight":"700","color":color,"fontSize":"0.78rem",
            "letterSpacing":"0.18em","textTransform":"uppercase",
            "fontFamily":"'JetBrains Mono', ui-monospace, monospace"}),
        html.Div(protos, style={"fontSize":"0.95rem","color":INK,"marginTop":"8px",
                                 "fontWeight":"500"}),
        html.Small(note, style={
            "fontSize":"0.78rem","color":INK_MUTE,"marginTop":"10px",
            "display":"block","lineHeight":"1.5"}),
    ], style={
        "background":f"linear-gradient(135deg, {bg_color}, rgba(255,255,255,0.02))",
        "padding":"16px","borderRadius":"14px",
        "border":f"1px solid {GLASS_BORDER}",
        "borderLeft":f"3px solid {color}",
        "height":"100%",
        "backdropFilter":"blur(20px)",
        "WebkitBackdropFilter":"blur(20px)"})


def _proto_table_row(proto, purpose, risk, is_header=False):
    cells_style_base = {"padding":"10px 14px","borderBottom":f"1px solid {GLASS_BORDER}"}
    if is_header:
        cells_style_base.update({"color":INK_MUTE,"fontSize":"10px",
            "letterSpacing":"0.18em","textTransform":"uppercase","fontWeight":"700",
            "fontFamily":"'JetBrains Mono', monospace",
            "borderBottom":f"1px solid {GLASS_BORDER_STRONG}"})
    return html.Tr([
        html.Td(proto, style={**cells_style_base,
                "color":VIOLET_BRIGHT if not is_header else INK_MUTE,
                "fontFamily":"'JetBrains Mono', monospace" if not is_header
                              else "'JetBrains Mono', monospace",
                "fontWeight":"600" if not is_header else "700",
                "fontSize":"0.92rem" if not is_header else "10px",
                "width":"110px"}),
        html.Td(purpose, style={**cells_style_base,
                "color":INK if not is_header else INK_MUTE,
                "fontSize":"0.9rem" if not is_header else "10px"}),
        html.Td(risk, style={**cells_style_base,
                "color":RED_ACCENT if not is_header else INK_MUTE,
                "fontSize":"0.88rem" if not is_header else "10px"}),
    ])


def _proto_table():
    return html.Div(html.Table([
        html.Thead(html.Tr([
            html.Th("Protocol", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}","width":"110px"}),
            html.Th("Purpose", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}"}),
            html.Th("Security Risk", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}"}),
        ])),
        html.Tbody([
            _proto_table_row("HTTP",  "Unencrypted web",          "Passwords in plaintext"),
            _proto_table_row("HTTPS", "Encrypted web (TLS)",      "Can fingerprint via TLS handshake"),
            _proto_table_row("DNS",   "Domain → IP resolution",   "DNS tunneling = data exfiltration"),
            _proto_table_row("FTP",   "File transfer (unencrypted)","USER/PASS visible in plaintext"),
            _proto_table_row("SMTP",  "Email sending",            "MAIL FROM / RCPT TO visible"),
            _proto_table_row("mDNS",  "Local name resolution (.local)","LLMNR poisoning = MITM"),
            _proto_table_row("SSDP",  "UPnP device discovery",    "SSDP amplification DDoS"),
        ]),
    ], style={"width":"100%","borderCollapse":"collapse"}),
    style={**CARD, "padding":"0","overflow":"hidden"})


def _pcap_only_table():
    rows_data = [
        ("FTP credentials",     "USER / PASS in payload",                "Credential theft"),
        ("HTTP POST data",      "Raw body after headers",                "Credential theft"),
        ("DNS tunneling",       "Long TXT queries, unusual subdomains",  "Data exfiltration"),
        ("TLS fingerprint",     "JA3 hash from ClientHello",             "Malware identification"),
        ("SYN flood",           "SYN with no ACK response",              "DoS attack"),
        ("ARP spoofing",        "Same IP, different MACs",               "Man-in-the-middle"),
        ("Port scanning",       "Sequential SYN to many ports",          "Reconnaissance"),
        ("Packet fragmentation","IP flag MF bit set",                    "Evasion technique"),
    ]
    return html.Div(html.Table([
        html.Thead(html.Tr([
            html.Th("Finding", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}","width":"160px"}),
            html.Th("How", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}"}),
            html.Th("Risk", style={"padding":"10px 14px","textAlign":"left",
                "color":INK_MUTE,"fontSize":"10px","letterSpacing":"0.18em",
                "textTransform":"uppercase","fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace",
                "borderBottom":f"1px solid {GLASS_BORDER_STRONG}","width":"200px"}),
        ])),
        html.Tbody([
            html.Tr([
                html.Td(finding, style={"padding":"10px 14px",
                    "borderBottom":f"1px solid {GLASS_BORDER}",
                    "color":CYAN_BRIGHT,"fontWeight":"600","fontSize":"0.9rem"}),
                html.Td(how, style={"padding":"10px 14px",
                    "borderBottom":f"1px solid {GLASS_BORDER}",
                    "color":INK,"fontSize":"0.88rem",
                    "fontFamily":"'JetBrains Mono', monospace"}),
                html.Td(risk, style={"padding":"10px 14px",
                    "borderBottom":f"1px solid {GLASS_BORDER}",
                    "color":RED_ACCENT,"fontSize":"0.88rem"}),
            ]) for finding, how, risk in rows_data
        ]),
    ], style={"width":"100%","borderCollapse":"collapse"}),
    style={**CARD, "padding":"0","overflow":"hidden"})


_NETSEC_LETTERS = {
    "N": [(0,0),(4,0),(0,1),(4,1),(0,2),(1,2),(4,2),(0,3),(2,3),(4,3),
          (0,4),(3,4),(4,4),(0,5),(4,5),(0,6),(4,6)],
    "E": [(0,0),(1,0),(2,0),(3,0),(4,0),(0,1),(0,2),
          (0,3),(1,3),(2,3),(3,3),(0,4),(0,5),
          (0,6),(1,6),(2,6),(3,6),(4,6)],
    "T": [(0,0),(1,0),(2,0),(3,0),(4,0),(2,1),(2,2),(2,3),(2,4),(2,5),(2,6)],
    "S": [(1,0),(2,0),(3,0),(4,0),(0,1),(0,2),(1,3),(2,3),(3,3),
          (4,4),(4,5),(0,6),(1,6),(2,6),(3,6)],
    "C": [(1,0),(2,0),(3,0),(4,0),(0,1),(0,2),(0,3),(0,4),(0,5),
          (1,6),(2,6),(3,6),(4,6)],
}


def _build_netsec_crt_logo(cell_px=18):
    """Render the NETSEC logo as a Base64 SVG data URL. Letters are 5×7 pixel
    grids drawn with rect elements - each cell has a darker outer stroke and
    a brighter inner highlight stripe, with a vintage CRT phosphor look."""
    import base64
    # NETSEC now renders on ONE row so the "NET / SEC" wrap does not happen.
    rows = ["NETSEC"]
    letter_w, letter_h = 5, 7
    letter_spacing_cells, line_gap_cells = 1.5, 1
    row_w_cells = letter_w * 6 + letter_spacing_cells * 5
    total_h_cells = letter_h
    W = int(row_w_cells * cell_px)
    H = int(total_h_cells * cell_px)

    coral, coral_dim, coral_glow = "#f8a8a8", "#c87878", "#ff9a9a"

    rects = []
    for row_idx, word in enumerate(rows):
        for letter_idx, ch in enumerate(word):
            base_x_cells = letter_idx * (letter_w + letter_spacing_cells)
            base_y_cells = row_idx * (letter_h + line_gap_cells)
            for (cx, cy) in _NETSEC_LETTERS[ch]:
                x = (base_x_cells + cx) * cell_px
                y = (base_y_cells + cy) * cell_px
                rects.append(
                    f'<rect x="{x+1}" y="{y+1}" width="{cell_px-2}" '
                    f'height="{cell_px-2}" fill="{coral}" '
                    f'stroke="{coral_dim}" stroke-width="1"/>')
                rects.append(
                    f'<rect x="{x+2}" y="{y+2}" width="{cell_px-4}" '
                    f'height="2" fill="{coral_glow}" opacity="0.55"/>')

    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" '
           f'viewBox="0 0 {W} {H}" '
           f'style="width:100%;height:auto;display:block;'
           f'filter:drop-shadow(0 0 6px rgba(248,168,168,0.55)) '
           f'drop-shadow(0 0 14px rgba(248,168,168,0.25));">'
           + "".join(rects) + '</svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(
        svg.encode("utf-8")).decode("ascii")



def _build_netsec_mini_badge(height_px=36):
    """Full NETSEC wordmark (all 6 letters on one line) in the coral pixel-art
    style of the splash logo. Rendered as a base64-encoded SVG with
    aspect ratio determined by the letter grid, so the caller only pins
    the height and the width adapts to preserve the pixel-art shape."""
    import base64
    letter_w, letter_h = 5, 7
    letter_spacing_cells = 1.5
    padding_cells = 1
    total_w_cells = letter_w * 6 + letter_spacing_cells * 5 + padding_cells * 2
    total_h_cells = letter_h + padding_cells * 2
    cell = height_px / total_h_cells
    W = total_w_cells * cell
    H = height_px
    off_x = padding_cells * cell
    off_y = padding_cells * cell
    coral, coral_dim, coral_glow = "#f8a8a8", "#c87878", "#ff9a9a"
    rects = []
    word = "NETSEC"
    for letter_idx, ch in enumerate(word):
        base_x = off_x + letter_idx * (letter_w + letter_spacing_cells) * cell
        for (cx, cy) in _NETSEC_LETTERS[ch]:
            x = base_x + cx * cell
            y = off_y + cy * cell
            rects.append(
                f'<rect x="{x+0.5:.2f}" y="{y+0.5:.2f}" '
                f'width="{cell-1:.2f}" height="{cell-1:.2f}" '
                f'fill="{coral}" stroke="{coral_dim}" stroke-width="0.5"/>')
            rects.append(
                f'<rect x="{x+1:.2f}" y="{y+1:.2f}" '
                f'width="{cell-2:.2f}" height="{max(1, cell/6):.2f}" '
                f'fill="{coral_glow}" opacity="0.5"/>')
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" '
           f'viewBox="0 0 {W:.2f} {H:.2f}" '
           f'style="height:100%;width:auto;display:block;'
           f'filter:drop-shadow(0 0 3px rgba(248,168,168,0.6)) '
           f'drop-shadow(0 0 8px rgba(248,168,168,0.3));">'
           + "".join(rects) + '</svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(
        svg.encode("utf-8")).decode("ascii")


def _build_intro_splash():
    """The CRT-terminal splash for the intro view. Mimics a vintage computer
    screen with a phosphor glow, scanlines, a green CLI prompt header, a
    pink NETSEC pixel logo, a fake directory tree to the right, and a
    blinking prompt at the bottom."""
    phosphor_green = "#a3e635"
    phosphor_green_dim = "#84b32a"

    return html.Div([
        html.Div([
            html.Div([
                html.Span("--- ", style={"color":phosphor_green_dim}),
                html.Span("NETSEC v5.0 SPLASH", style={"color":phosphor_green,
                    "fontWeight":"600","letterSpacing":"0.08em"}),
                html.Span(" ---", style={"color":phosphor_green_dim}),
            ], style={"fontFamily":"'JetBrains Mono', monospace",
                      "fontSize":"0.88rem","marginBottom":"6px",
                      "whiteSpace":"nowrap"}),
            html.Div([
                html.Span("> ", style={"color":phosphor_green_dim}),
                html.Span("load_netsec_model.py", style={"color":phosphor_green}),
            ], style={"fontFamily":"'JetBrains Mono', monospace",
                      "fontSize":"0.84rem","marginBottom":"20px"}),
        ]),

        dbc.Row([
            dbc.Col([
                html.Img(src=_build_netsec_crt_logo(),
                    style={"maxWidth":"100%","display":"block",
                           "imageRendering":"pixelated"}),
            ], md=12, style={"display":"flex","alignItems":"center","justifyContent":"center"}),
            dbc.Col([
                html.Div([
                    html.Div("./netsec/", style={"color":phosphor_green,
                        "fontWeight":"600","marginBottom":"3px"}),
                    html.Div("├── config/", style={"color":phosphor_green_dim,
                        "marginLeft":"4px"}),
                    html.Div("│   ├── device_rules.json", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("│   ├── cloud_ranges.json", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("│   └── dns_fingerprints.json", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("├── core/", style={"color":phosphor_green_dim,
                        "marginLeft":"4px"}),
                    html.Div("│   ├── analyzer.py", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("│   ├── live_capture.py", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("│   └── ml_models.py", style={
                        "color":phosphor_green_dim,"marginLeft":"4px"}),
                    html.Div("├── dashboard.py", style={"color":phosphor_green,
                        "marginLeft":"4px"}),
                    html.Div("└── main.sh", style={"color":phosphor_green,
                        "marginLeft":"4px"}),
                ], style={"fontFamily":"'JetBrains Mono', monospace",
                          "fontSize":"0.76rem","lineHeight":"1.55"}),
            ], md=4, style={"display":"flex","alignItems":"center",
                            "paddingLeft":"24px"}),
        ], style={"margin":"0"}),

        html.Div([
            html.Span("netsec@anomaly:~$ ", style={"color":phosphor_green,
                "fontWeight":"600"}),
            html.Span("_", style={"color":phosphor_green,
                "animation":"netsec-blink 1s steps(1) infinite"}),
        ], style={"fontFamily":"'JetBrains Mono', monospace",
                  "fontSize":"0.92rem","marginTop":"22px"}),

    ], style={
        "background":"linear-gradient(180deg, #0a0e0a 0%, #050805 100%)",
        "borderRadius":"14px",
        "padding":"30px 40px 28px",
        "marginBottom":"36px",
        "position":"relative",
        "overflow":"hidden",
        "border":f"1px solid rgba(163,230,53,0.20)",
        "boxShadow":(
            "inset 0 0 60px rgba(163,230,53,0.06), "
            "inset 0 0 12px rgba(163,230,53,0.10), "
            "0 0 28px rgba(0,0,0,0.6), "
            "0 0 80px rgba(163,230,53,0.04)"),
        "backgroundImage":(
            "repeating-linear-gradient(0deg, "
            "rgba(255,255,255,0) 0px, rgba(255,255,255,0) 2px, "
            "rgba(0,0,0,0.18) 2px, rgba(0,0,0,0.18) 3px)"),
    })



def _build_floating_restart_pill():
    """Small Restart pill anchored bottom-right. Distinct id from the
    dashboard's restart-btn so the two pills can coexist briefly during a
    mode swap without Dash raising DuplicateIdError. restart_app listens
    to both ids and routes either click through the same reset path."""
    return html.Div(dbc.Button("↺ Restart", id="restart-btn-welcome", n_clicks=0,
        className="aur-btn-ghost",
        style={"fontSize":"11.5px","fontWeight":"500",
               "padding":"9px 16px","borderRadius":"12px",
               "background":"rgba(13,10,26,0.85)","color":INK_DIM,
               "border":f"1px solid {GLASS_BORDER_STRONG}",
               "backdropFilter":"blur(20px) saturate(140%)",
               "WebkitBackdropFilter":"blur(20px) saturate(140%)",
               "fontFamily":"'JetBrains Mono', monospace",
               "letterSpacing":"0.04em",
               "boxShadow":"0 4px 20px rgba(0,0,0,0.4)"}),
        style={"position":"fixed","bottom":"22px","right":"22px","zIndex":"9999",
               "pointerEvents":"auto"})


def _build_edu_panel(location_key, open_by_default=False):
    """Educational-material panel with a collapse toggle. Multiple instances
    can coexist on the same page - each uses a pattern-matched id keyed by
    location_key so a single Dash callback (toggle_edu_panel) handles all of
    them without conflicts. open_by_default=True renders the material already
    expanded (used on the analysis-wait screen, where reading it is the whole
    point of the panel)."""
    return html.Div([
        html.Div([
            html.Span("▲" if open_by_default else "▼",
                id={"type":"edu-arrow","loc":location_key},
                style={"fontSize":"1.1rem","marginRight":"12px",
                       "color":VIOLET_BRIGHT,
                       "textShadow":f"0 0 14px {VIOLET_BRIGHT}aa"}),
            html.Span("Click to hide the educational material"
                      if open_by_default else
                      "Click to show the educational material",
                id={"type":"edu-label","loc":location_key},
                style={"fontFamily":"'JetBrains Mono', monospace",
                       "fontSize":"12px","color":INK,
                       "letterSpacing":"0.18em","textTransform":"uppercase",
                       "fontWeight":"700"}),
        ], id={"type":"edu-btn","loc":location_key}, n_clicks=0, style={
            "display":"flex","alignItems":"center","justifyContent":"center",
            "textAlign":"center","marginTop":"24px","marginBottom":"4px",
            "padding":"14px 18px","borderRadius":"12px",
            "background":"rgba(139,92,246,0.10)",
            "border":f"1px solid {VIOLET_BRIGHT}66",
            "textDecoration":"none","cursor":"pointer",
            "transition":"all 0.2s ease"}),
        dbc.Collapse(_build_education_content(location_key),
                     id={"type":"edu-collapse","loc":location_key},
                     is_open=open_by_default),
    ])


def _build_education_content(location_key=""):
    """Educational panel shown beneath the file-loading area on the choice view.
    Holds all the protocol background, ML-algorithm explanations, device-classification
    overview, and threat-scoring tables that used to sit on the welcome splash.
    Rendered unconditionally - visible before upload, after upload, while a file is
    being analyzed, and after analysis completes. Numbering and section dividers
    have been removed; thin 32-px spacers preserve visual rhythm between topics."""
    SPACER = html.Div(style={"height":"32px"})
    return html.Div(id=f"edu-card-anchor-{location_key}", children=[

                # Prominent banner header so users cannot miss that this card exists.
                html.Div([
                    html.Div("📚", style={
                        "fontSize":"2rem","marginBottom":"6px"}),
                    html.Div("LEARN WHILE YOU LOAD", style={
                        "fontFamily":"'JetBrains Mono', monospace",
                        "fontSize":"11px","color":VIOLET_BRIGHT,
                        "letterSpacing":"0.28em","textTransform":"uppercase",
                        "fontWeight":"700","marginBottom":"10px"}),
                    html.H2("Network Protocols, ML Models & Threat Scoring", style={
                        "color":INK,"fontWeight":"500","fontSize":"1.85rem",
                        "fontFamily":"'Newsreader', Georgia, serif",
                        "letterSpacing":"-0.015em","marginBottom":"10px",
                        "lineHeight":"1.15"}),
                    html.P("Use the time your capture is loading to read through the "
                           "concepts the analyzer relies on. Everything from layer-by-"
                           "layer protocol background and device classification, to "
                           "the three ML models and two deterministic rule layers, "
                           "lives here.",
                        style={"color":INK_DIM,"fontSize":"0.95rem",
                               "lineHeight":"1.6","marginBottom":"6px",
                               "maxWidth":"720px","marginLeft":"auto",
                               "marginRight":"auto"}),
                ], style={"textAlign":"center","marginBottom":"24px",
                          "paddingBottom":"22px",
                          "borderBottom":f"1px solid {GLASS_BORDER_STRONG}"}),

                _h2("What is a Protocol?"),
                _p("A protocol is a set of rules defining how data is sent, structured, "
                   "verified, and corrected. Like languages between humans "
                   "(Hebrew, English, body language), computers use protocols: "
                   "TCP, HTTP, ARP, DNS, FTP, SMTP."),

                _h3("Network Layer Model"),
                _code_block(
                    "Layer 4 - Application    HTTP, HTTPS, DNS, FTP, SMTP, mDNS, SSDP\n"
                    "Layer 3 - Transport      TCP, UDP\n"
                    "Layer 2 - Network        IP, ICMP\n"
                    "Layer 1 - Link           ARP, Ethernet (MAC)",
                    color_accent=VIOLET_BRIGHT),

                dbc.Row([
                    dbc.Col(_layer_card("L4","APPLICATION",
                        html.Span(["HTTP · HTTPS · DNS · FTP",html.Br(),
                                   "SMTP · mDNS · SSDP"]),
                        "Who is talking to whom and what they say",
                        VIOLET_BRIGHT, "rgba(139,92,246,0.10)"), md=3),
                    dbc.Col(_layer_card("L3","TRANSPORT","TCP · UDP",
                        "Connection patterns, ports, SYN/RST flags - port-scan detection",
                        CYAN_BRIGHT, "rgba(34,211,238,0.10)"), md=3),
                    dbc.Col(_layer_card("L2","NETWORK","IP · ICMP",
                        "Source / destination addresses, packet size, traffic volume",
                        AMBER, "rgba(251,191,36,0.08)"), md=3),
                    dbc.Col(_layer_card("L1","LINK","ARP · Ethernet",
                        "MAC addresses, OUI vendor lookup, ARP spoofing detection",
                        MAGENTA, "rgba(244,114,182,0.08)"), md=3),
                ], style={"marginTop":"6px","marginBottom":"6px"}),

                SPACER,

                _h3("Layer 1 - Link Layer", color=MAGENTA),
                html.P([
                    _bold("ARP - Address Resolution Protocol", color=INK), html.Br(),
                    "Translates IP address → MAC address (physical hardware address).",
                ], style={"color":INK_DIM,"fontSize":"0.95rem","lineHeight":"1.6",
                          "marginBottom":"10px"}),
                _code_block(
                    'Computer: "Who has 192.168.1.1?"   (broadcast)\n'
                    'Router:   "I do. My MAC is AA:BB:CC:DD:EE:FF"',
                    color_accent=MAGENTA),
                _p(["In Wireshark: ", html.Code("ARP Request", style={
                        "background":"rgba(244,114,182,0.10)","padding":"1px 6px",
                        "borderRadius":"4px","color":MAGENTA,
                        "fontFamily":"'JetBrains Mono', monospace","fontSize":"0.85rem"}),
                    " / ", html.Code("ARP Reply", style={
                        "background":"rgba(244,114,182,0.10)","padding":"1px 6px",
                        "borderRadius":"4px","color":MAGENTA,
                        "fontFamily":"'JetBrains Mono', monospace","fontSize":"0.85rem"})]),
                _risk_line([_bold("Excessive ARP", color=RED_ACCENT),
                            " = network scan.  ",
                            _bold("Duplicate MAC-IP", color=RED_ACCENT),
                            " = ARP spoofing (MITM attack)."]),

                _h3("Layer 2 - Network Layer", color=AMBER),
                html.P([
                    _bold("IP - Internet Protocol", color=INK),
                    " - routes packets using Source/Destination IP. No delivery guarantee."
                ], style={"color":INK_DIM,"fontSize":"0.95rem","lineHeight":"1.6",
                          "marginBottom":"6px"}),
                html.P([
                    _bold("ICMP", color=INK),
                    " - control messages. ",
                    html.Code("ping", style={
                        "background":"rgba(251,191,36,0.10)","padding":"1px 6px",
                        "borderRadius":"4px","color":AMBER,
                        "fontFamily":"'JetBrains Mono', monospace","fontSize":"0.85rem"}),
                    " works over ICMP.",
                ], style={"color":INK_DIM,"fontSize":"0.95rem","lineHeight":"1.6",
                          "marginBottom":"6px"}),
                _risk_line([_bold("ICMP flood", color=RED_ACCENT), " = DoS attack."]),

                _h3("Layer 3 - Transport Layer", color=CYAN_BRIGHT),
                html.P([
                    _bold("TCP - Transmission Control Protocol", color=INK), html.Br(),
                    "Reliable - guarantees delivery, ordering, retransmission.",
                ], style={"color":INK_DIM,"fontSize":"0.95rem","lineHeight":"1.6",
                          "marginBottom":"8px"}),
                _code_block("3-way handshake:  SYN → SYN-ACK → ACK",
                            color_accent=CYAN_BRIGHT),
                _p([
                    "Used by: ", _bold("HTTP, HTTPS, SMTP, FTP", color=INK), "."
                ]),
                _risk_line([_bold("Many SYNs with no ACK reply", color=RED_ACCENT),
                            " = SYN flood / port scan."]),

                html.Div(style={"height":"14px"}),
                html.P([
                    _bold("UDP - User Datagram Protocol", color=INK), html.Br(),
                    "Fast but unreliable - no confirmation, no ordering.",
                ], style={"color":INK_DIM,"fontSize":"0.95rem","lineHeight":"1.6",
                          "marginBottom":"6px"}),
                _p([
                    "Used by: ", _bold("DNS, video streaming, games, VoIP", color=INK), "."
                ]),
                _risk_line([_bold("UDP flood", color=RED_ACCENT),
                            " = volumetric DDoS."]),

                _h3("Layer 4 - Application Layer", color=VIOLET_BRIGHT),
                _p("All user-facing protocols. Each has its own security profile:"),
                _proto_table(),

                SPACER,

                _p("Some forensic findings are only visible in raw packet data - not in CSV "
                   "exports or higher-level logs. This is why PCAP capture is essential for "
                   "incident response and threat hunting:"),
                _pcap_only_table(),

                SPACER,

                html.Div([
                    _h2("12 categories · 133 rules · 101 DNS fingerprints"),
                    _p(["Every local device is auto-classified into a specific category "
                       "based on a 3-tier engine: ",
                       _bold("hostname/OUI/port rules", color=VIOLET_BRIGHT),
                       " → ",
                       _bold("DNS fingerprints", color=CYAN_BRIGHT),
                       " → ",
                       _bold("behavioural heuristics", color=AMBER),
                       ". MAC randomization is flagged as a column, not a category."]),
                    html.Div([
                        html.Span("Computers", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Mobile", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Entertainment", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Smart Home", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Security & Cameras", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Network Infra", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Office", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Medical", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Point of Sale", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Industrial IoT", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Vehicle", style={"color":VIOLET_BRIGHT}),
                        html.Span(" · ", style={"color":INK_MUTE}),
                        html.Span("Generic Endpoint", style={"color":INK_MUTE}),
                    ], style={"fontSize":"0.88rem","lineHeight":"1.8","marginTop":"10px"}),
                ], style={**CARD}),

                SPACER,

                dbc.Row([
                    dbc.Col(html.Div([
                        _h3("Threat tiers"),
                        html.Div([
                            html.Div([
                                html.Span("LOW", style={"fontFamily":"'JetBrains Mono', monospace",
                                    "fontSize":"0.78rem","fontWeight":"700",
                                    "color":LIME,"letterSpacing":"0.1em",
                                    "padding":"2px 8px","borderRadius":"4px",
                                    "border":f"1px solid {LIME}66",
                                    "background":"rgba(163,230,53,0.08)",
                                    "marginRight":"10px","minWidth":"56px",
                                    "display":"inline-block","textAlign":"center"}),
                                html.Span("score < 25 - nominal traffic",
                                    style={"fontSize":"0.9rem","color":INK_DIM})
                            ], style={"marginBottom":"8px","display":"flex","alignItems":"center"}),
                            html.Div([
                                html.Span("MED", style={"fontFamily":"'JetBrains Mono', monospace",
                                    "fontSize":"0.78rem","fontWeight":"700",
                                    "color":AMBER,"letterSpacing":"0.1em",
                                    "padding":"2px 8px","borderRadius":"4px",
                                    "border":f"1px solid {AMBER}66",
                                    "background":"rgba(251,191,36,0.08)",
                                    "marginRight":"10px","minWidth":"56px",
                                    "display":"inline-block","textAlign":"center"}),
                                html.Span("score 25-49 - notable anomalies",
                                    style={"fontSize":"0.9rem","color":INK_DIM})
                            ], style={"marginBottom":"8px","display":"flex","alignItems":"center"}),
                            html.Div([
                                html.Span("HIGH", style={"fontFamily":"'JetBrains Mono', monospace",
                                    "fontSize":"0.78rem","fontWeight":"700",
                                    "color":RED_ACCENT,"letterSpacing":"0.1em",
                                    "padding":"2px 8px","borderRadius":"4px",
                                    "border":f"1px solid {RED_ACCENT}66",
                                    "background":"rgba(248,113,113,0.10)",
                                    "marginRight":"10px","minWidth":"56px",
                                    "display":"inline-block","textAlign":"center"}),
                                html.Span("score 50-74 - clear attack pattern",
                                    style={"fontSize":"0.9rem","color":INK_DIM})
                            ], style={"marginBottom":"8px","display":"flex","alignItems":"center"}),
                            html.Div([
                                html.Span("CRIT", style={"fontFamily":"'JetBrains Mono', monospace",
                                    "fontSize":"0.78rem","fontWeight":"700",
                                    "color":"white","letterSpacing":"0.1em",
                                    "padding":"2px 8px","borderRadius":"4px",
                                    "background":f"linear-gradient(135deg, {RED_ACCENT}, {MAGENTA})",
                                    "boxShadow":f"0 0 12px {RED_ACCENT}66",
                                    "marginRight":"10px","minWidth":"56px",
                                    "display":"inline-block","textAlign":"center"}),
                                html.Span("score ≥ 75 - active incident",
                                    style={"fontSize":"0.9rem","color":INK_DIM})
                            ], style={"display":"flex","alignItems":"center"}),
                        ]),
                    ], style={**CARD,"height":"100%"}), md=6),
                    dbc.Col(html.Div([
                        _h3("Eight-signal threat score"),
                        html.Ul([
                            html.Li("TCP SYN burst - port-scan / flood signal (0-30 pts)"),
                            html.Li("Unique destinations - scan breadth (0-20 pts)"),
                            html.Li("TCP RST flood - connection abuse (0-10 pts)"),
                            html.Li("Many distinct ports used (0-10 pts)"),
                            html.Li("ARP spoofing - IP↔MAC inconsistencies (+25 pts)"),
                            html.Li("DNS tunneling - abnormally long queries (0-15 pts)"),
                            html.Li("NXDOMAIN burst - DGA / typo-squatting (0-10 pts)"),
                            html.Li("Multi-signal bonus (+10 if 3+ signals active)"),
                        ], style={"color":INK_DIM,"fontSize":"0.88rem",
                                  "paddingLeft":"20px","marginBottom":"0",
                                  "lineHeight":"1.85"}),
                    ], style={**CARD,"height":"100%"}), md=6),
                ]),

                SPACER,

                _p("Five detection layers run in parallel against the captured traffic. "
                   "Three are machine-learning models; two are deterministic rules."),

                dbc.Row([
                    dbc.Col(html.Div([
                        html.Div([
                            html.Span("ML · 1", style={
                                "fontFamily":"'JetBrains Mono', monospace",
                                "fontSize":"10px","color":VIOLET_BRIGHT,
                                "letterSpacing":"0.18em","fontWeight":"700",
                                "padding":"2px 8px","borderRadius":"4px",
                                "background":"rgba(139,92,246,0.12)",
                                "border":f"1px solid {VIOLET_BRIGHT}55",
                                "marginRight":"10px"}),
                            html.Span("IsolationForest", style={
                                "fontFamily":"'Newsreader', Georgia, serif",
                                "fontSize":"1.15rem","fontWeight":"500"}),
                        ], style={"marginBottom":"10px","display":"flex",
                                  "alignItems":"center"}),
                        _p("Ensemble of 200 random isolation trees. Each tree picks a "
                           "feature and a random split point - anomalous IPs get "
                           "isolated faster (shorter path to leaf). The model is trained "
                           "on per-IP feature vectors: packet count, byte volume, mean "
                           "packet size, unique destinations, SYN count, RST count."),
                        html.Div([
                            html.Strong("Hyperparameters: ", style={"color":INK}),
                            html.Code("n_estimators=200, contamination=0.10",
                                style={"background":"rgba(0,0,0,0.3)","padding":"2px 6px",
                                       "borderRadius":"4px","color":CYAN_BRIGHT,
                                       "fontFamily":"'JetBrains Mono', monospace",
                                       "fontSize":"0.82rem"}),
                        ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"6px"}),
                        html.Div([
                            html.Strong("Catches: ", style={"color":INK}),
                            "single-IP anomalies - port scanners, DoS sources, "
                            "exfiltration hosts.",
                        ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"4px"}),
                    ], style={**CARD, "padding":"18px","height":"100%",
                              "borderLeft":f"3px solid {VIOLET_BRIGHT}"}), md=6),

                    dbc.Col(html.Div([
                        html.Div([
                            html.Span("ML · 2", style={
                                "fontFamily":"'JetBrains Mono', monospace",
                                "fontSize":"10px","color":CYAN_BRIGHT,
                                "letterSpacing":"0.18em","fontWeight":"700",
                                "padding":"2px 8px","borderRadius":"4px",
                                "background":"rgba(34,211,238,0.12)",
                                "border":f"1px solid {CYAN_BRIGHT}55",
                                "marginRight":"10px"}),
                            html.Span("DBSCAN", style={
                                "fontFamily":"'Newsreader', Georgia, serif",
                                "fontSize":"1.15rem","fontWeight":"500"}),
                        ], style={"marginBottom":"10px","display":"flex",
                                  "alignItems":"center"}),
                        _p("Density-Based Spatial Clustering. Groups IPs whose feature "
                           "vectors are close in n-dimensional space. Any IP not "
                           "belonging to a cluster (an isolate) is labelled noise - and "
                           "is exactly the kind of behavioural outlier worth investigating."),
                        html.Div([
                            html.Strong("Hyperparameters: ", style={"color":INK}),
                            html.Code("eps=auto (k-distance elbow), min_samples=2 (StandardScaler-normalised)",
                                style={"background":"rgba(0,0,0,0.3)","padding":"2px 6px",
                                       "borderRadius":"4px","color":CYAN_BRIGHT,
                                       "fontFamily":"'JetBrains Mono', monospace",
                                       "fontSize":"0.82rem"}),
                        ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"6px"}),
                        html.Div([
                            html.Strong("Catches: ", style={"color":INK}),
                            "devices that behave nothing like the rest of the network - "
                            "rogue endpoints, infected hosts, misconfigured equipment.",
                        ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"4px"}),
                    ], style={**CARD, "padding":"18px","height":"100%",
                              "borderLeft":f"3px solid {CYAN_BRIGHT}"}), md=6),
                ], style={"marginBottom":"14px"}),

                html.Div([
                    html.Div([
                        html.Span("ML · 3", style={
                            "fontFamily":"'JetBrains Mono', monospace",
                            "fontSize":"10px","color":MAGENTA,
                            "letterSpacing":"0.18em","fontWeight":"700",
                            "padding":"2px 8px","borderRadius":"4px",
                            "background":"rgba(244,114,182,0.12)",
                            "border":f"1px solid {MAGENTA}55",
                            "marginRight":"10px"}),
                        html.Span("LSTM - Long Short-Term Memory Network", style={
                            "fontFamily":"'Newsreader', Georgia, serif",
                            "fontSize":"1.15rem","fontWeight":"500"}),
                    ], style={"marginBottom":"10px","display":"flex",
                              "alignItems":"center"}),
                    _p("Recurrent neural network specialised in learning temporal "
                       "patterns. The network is sampled at 1-second resolution - for "
                       "every second of the capture, the mean packet size becomes one "
                       "data point. The model is trained to predict the next second's "
                       "value from a sliding window of the previous 10 seconds."),
                    _p("After training, the model is run on the full session. The "
                       "absolute prediction error at each second is the anomaly score. "
                       "Errors above the validation mean + 2σ are flagged as anomalies - "
                       "moments when the actual traffic did not match the rhythm the "
                       "model had learned: a burst, a sudden silence, or an irregular "
                       "spike."),
                    _code_block(
                        "Architecture:\n"
                        "  Input  → LSTM(64) → Dropout(0.2) → Dense(32, ReLU) → Dense(1)\n"
                        "  Loss:  MSE     Optimizer: Adam(lr=0.001)\n"
                        "  Train: 80% of session, sequences of 10 timesteps\n"
                        "  Eval:  full session, threshold = val_mean + 2·val_std",
                        color_accent=MAGENTA),
                    html.Div([
                        html.Strong("Catches: ", style={"color":INK}),
                        "temporal anomalies that single-IP models miss - bursts, "
                        "DoS patterns over time, beaconing, low-and-slow data exfiltration.",
                    ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"6px"}),
                    html.Div([
                        html.Strong("Requires: ", style={"color":INK}),
                        f"≥ {ML_MIN_PACKETS:,} packets in the session, otherwise the "
                        "score is too noisy and the dashboard shows a 'waiting for more "
                        "data' banner.",
                    ], style={"fontSize":"0.85rem","color":INK_DIM,"marginTop":"4px"}),
                ], style={**CARD, "padding":"18px","marginBottom":"14px",
                          "borderLeft":f"3px solid {MAGENTA}"}),

                dbc.Row([
                    dbc.Col(html.Div([
                        html.Div([
                            html.Span("RULE · 1", style={
                                "fontFamily":"'JetBrains Mono', monospace",
                                "fontSize":"10px","color":AMBER,
                                "letterSpacing":"0.18em","fontWeight":"700",
                                "padding":"2px 8px","borderRadius":"4px",
                                "background":"rgba(251,191,36,0.12)",
                                "border":f"1px solid {AMBER}55",
                                "marginRight":"10px"}),
                            html.Span("TCP SYN scan / flood detection", style={
                                "fontFamily":"'Newsreader', Georgia, serif",
                                "fontSize":"1.05rem","fontWeight":"500"}),
                        ], style={"marginBottom":"8px","display":"flex",
                                  "alignItems":"center"}),
                        _p("Counts how many TCP SYN packets each source sent that "
                           "received no SYN-ACK response. ≥50 unanswered SYNs in a "
                           "session = scan/flood pattern. Layered with unique-destination "
                           "count to distinguish a horizontal scan (many hosts, few "
                           "ports) from a vertical scan (one host, many ports)."),
                    ], style={**CARD, "padding":"16px","height":"100%",
                              "borderLeft":f"3px solid {AMBER}"}), md=6),

                    dbc.Col(html.Div([
                        html.Div([
                            html.Span("RULE · 2", style={
                                "fontFamily":"'JetBrains Mono', monospace",
                                "fontSize":"10px","color":RED_ACCENT,
                                "letterSpacing":"0.18em","fontWeight":"700",
                                "padding":"2px 8px","borderRadius":"4px",
                                "background":"rgba(248,113,113,0.12)",
                                "border":f"1px solid {RED_ACCENT}55",
                                "marginRight":"10px"}),
                            html.Span("ARP spoofing / DNS tunneling", style={
                                "fontFamily":"'Newsreader', Georgia, serif",
                                "fontSize":"1.05rem","fontWeight":"500"}),
                        ], style={"marginBottom":"8px","display":"flex",
                                  "alignItems":"center"}),
                        _p("ARP spoofing: same IP reported by ≥2 different MACs in the "
                           "same session = MITM pattern (worth +25 threat points). "
                           "DNS tunneling: any DNS query >60 characters is flagged; "
                           "≥3 long queries in a session triggers the DNS tunneling "
                           "signal. NXDOMAIN bursts (≥30 NXDOMAINs) suggest DGA "
                           "malware or typo-squatting."),
                    ], style={**CARD, "padding":"16px","height":"100%",
                              "borderLeft":f"3px solid {RED_ACCENT}"}), md=6),
                ], style={"marginBottom":"6px"}),

    ], style={**CARD, "padding":"40px 44px","borderRadius":"24px","marginTop":"24px"})


def build_intro_view():
    """First view: retro splash + concise overview + acknowledgement checkbox.
    The full protocol education and algorithm reference now live on the
    file-loading screen inside the unconditional `_build_education_content()`
    panel - keep this view short."""
    has_data = (S1 is not None) or (S2 is not None)
    cont_label = "Resume dashboard →" if has_data else "Continue →"
    return html.Div([
      dbc.Container(fluid=True, style={"minHeight":"100vh",
        "padding":"40px 20px","position":"relative","zIndex":"2"}, children=[
        dbc.Row(justify="center", children=[dbc.Col(md=10, lg=9, children=[
            html.Div([

                _build_intro_splash(),

                _h2("Welcome - What This Tool Does"),
                _p("NETSEC v5 is a forensic dashboard for offline analysis of Wireshark "
                   "PCAPNG captures. You feed it one capture - and optionally a second - "
                   "and it returns everything an analyst would otherwise have to dig out by "
                   "hand: per-IP behaviour, protocol mix, threat scoring, device classification, "
                   "and a head-to-head comparison whenever two sessions are loaded."),

                _h3("How the analysis works"),
                _p(["The engine parses every packet down to the link layer, builds per-IP "
                    "feature vectors, then runs ",
                    _bold("three machine-learning models", color=VIOLET_BRIGHT),
                    " in parallel - IsolationForest for outlier detection, DBSCAN for "
                    "behavioural clustering, and an LSTM that learns the temporal rhythm "
                    "of the traffic and flags seconds where reality did not match the "
                    "model. Two deterministic rule layers run alongside them for "
                    "TCP scan / flood detection and ARP-spoof / DNS-tunneling signals."]),

                _h3("What the dashboard shows you"),
                _p("Each session produces a threat-score breakdown, anomaly tables, a device "
                   "inventory auto-classified into twelve categories, per-device browsing "
                   "analysis, and a research-insights panel. Load a second capture and every "
                   "view gains an S1-vs-S2 comparison column - the same network at two points "
                   "in time, or two different networks observed side-by-side."),

                _h3("Two sessions, one comparison"),
                _p(["Session 1 (", _bold("S1", color=CYAN_BRIGHT),
                    ") is the baseline. Session 2 (",
                    _bold("S2", color=MAGENTA),
                    ") is whatever you load next - a recording from the same network on "
                    "a different day, traffic from a different segment, or a capture from "
                    "another site entirely. Threat scores, top talkers, protocol mix, and "
                    "anomaly counts are diffed for you automatically; new findings unique "
                    "to S2 surface as their own panel."]),

                _h3("What you're agreeing to below"),
                _p("This is a research / educational tool. Analysis "
                   "runs entirely on your machine and no capture data "
                   "leaves it during the analysis itself. Two optional "
                   "buttons that appear after a session loads DO send "
                   "data outward when you click them: \"Send to AI "
                   "Judge\" opens the GitHub upload page for this "
                   "repo's incoming/ folder, and \"Send to n8n "
                   "Alert\" uploads the PCAP over Tailscale to the "
                   "cloud VM you provisioned yourself, where it is "
                   "analysed and sent to an LLM provider. Neither is "
                   "automatic. This tool is intended for captures you "
                   "are authorised to inspect. By ticking the box "
                   "below you confirm you have read this notice and "
                   "that you will use the tool only on traffic you "
                   "have permission to analyse. The deeper protocol "
                   "background, ML-algorithm reference, device-"
                   "classification engine, and threat-scoring tables "
                   "live on the next screen - you can read them "
                   "while your capture is loading."),

                _section_divider("Acknowledgement"),

                html.Div([
                    dcc.Checklist(
                        id="intro-ack",
                        options=[{"label":" I have read the introduction and understand the concepts",
                                  "value":"ack"}],
                        value=(["ack"] if has_data else []),
                        inputStyle={"marginRight":"10px","transform":"scale(1.3)",
                                    "accentColor":VIOLET_BRIGHT},
                        labelStyle={"fontSize":"0.95rem","color":INK_DIM,
                                    "fontWeight":"500","cursor":"pointer"},
                    ),
                ], style={"textAlign":"center","marginBottom":"18px","marginTop":"6px"}),

                html.Div(dbc.Button(cont_label, id="intro-continue-btn",
                    disabled=(not has_data),
                    className="aur-btn-primary",
                    style={"padding":"14px 44px","fontSize":"1rem","fontWeight":"600",
                           "borderRadius":"12px","border":"none","color":"white",
                           "fontFamily":"'Inter Tight', sans-serif",
                           "letterSpacing":"-0.005em"}),
                    style={"textAlign":"center"}),
            ], style={**CARD, "padding":"40px 44px","borderRadius":"24px"})
        ])])
      ]),
      _build_floating_restart_pill(),
    ])


def _human_size(n):
    """Format bytes as a short human-readable string."""
    n = float(n or 0)
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024: return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def build_choice_view(staged=None, replacing_s1=False):
    """Second view: pick between PCAP load (drag-drop + path input) and live recording.
    If `staged` is non-None, show the staging confirmation card above the dropzone."""
    back_btn = html.Div(
        dbc.Button("← Back to welcome", id="choice-back-btn", n_clicks=0,
            className="aur-btn-ghost",
            style={"fontSize":"12px","fontWeight":"500",
                   "padding":"8px 16px","borderRadius":"10px",
                   "background":"rgba(255,255,255,0.04)","color":INK_DIM,
                   "border":f"1px solid {GLASS_BORDER_STRONG}",
                   "fontFamily":"'JetBrains Mono', monospace",
                   "letterSpacing":"0.02em"}),
        style={"position":"absolute","top":"24px","left":"24px","zIndex":"30"})
    return html.Div([
      back_btn,
      dbc.Container(fluid=True, style={"minHeight":"100vh",
        "padding":"40px 20px","position":"relative","zIndex":"2"}, children=[
        dbc.Row(justify="center", children=[dbc.Col(md=10, lg=9, children=[
            html.Div([
                html.Div(html.Div(
                    html.Img(src=_build_netsec_mini_badge(height_px=64),
                        style={"height":"64px","width":"auto","display":"block",
                               "margin":"0 auto"}),
                    style={"display":"inline-block","padding":"10px 20px",
                        "borderRadius":"14px",
                        "background":"rgba(248,168,168,0.06)",
                        "border":"1px solid rgba(248,168,168,0.25)",
                        "boxShadow":"0 0 32px rgba(248,168,168,0.20)"}),
                    style={"textAlign":"center","marginBottom":"16px"}),
                html.H2([
                    "Choose how to load ",
                    html.Span("network data", style={
                        "background":f"linear-gradient(135deg, {VIOLET_BRIGHT}, {CYAN_BRIGHT})",
                        "WebkitBackgroundClip":"text","backgroundClip":"text",
                        "WebkitTextFillColor":"transparent","color":"transparent"})
                ], style={"color":INK,"fontWeight":"500","textAlign":"center",
                          "marginBottom":"6px",
                          "fontFamily":"'Newsreader', Georgia, serif",
                          "fontSize":"2.4rem","letterSpacing":"-0.02em"}),
                html.P("Load a PCAP from disk or record live traffic. You can also do "
                       "both - load one PCAP first, then record a second session.",
                    style={"color":INK_DIM,"textAlign":"center","marginBottom":"36px",
                           "fontSize":"0.95rem"}),

                (html.Div([
                    html.Span("⚠  ", style={"color":AMBER,"fontWeight":"700",
                                                  "fontSize":"15px","marginRight":"6px"}),
                    html.B("Replacing S1. "),
                    "Load a PCAP below then click Analyze; the new file will REPLACE the "
                    "currently loaded S1. S2 stays loaded and the comparison view "
                    "will refresh automatically. Click ← Back to welcome to cancel.",
                ], style={"background":"rgba(251,191,36,0.10)",
                          "border":f"1px solid rgba(251,191,36,0.30)",
                          "borderRadius":"12px","padding":"12px 16px","marginBottom":"18px",
                          "fontSize":"0.88rem","color":INK_DIM,
                          "fontFamily":"'Inter Tight', sans-serif","lineHeight":"1.5",
                          "maxWidth":"720px","margin":"0 auto 18px"})
                 if replacing_s1 else None),
                (_build_staged_card(staged) if staged else None),
                (None if staged else dbc.Row([
                    dbc.Col(html.Div([
                        html.Div("📊", style={"fontSize":"3rem","textAlign":"center",
                                              "filter":f"drop-shadow(0 0 20px {VIOLET}66)"}),
                        html.H4("Load PCAP File", style={
                            "color":INK,"fontWeight":"500","textAlign":"center",
                            "fontFamily":"'Newsreader', Georgia, serif","marginTop":"10px",
                            "marginBottom":"16px"}),

                        dcc.Upload(
                            id="pcap-upload",
                            children=html.Div([
                                html.Div("⬇", style={"fontSize":"2rem","opacity":"0.65",
                                                       "marginBottom":"4px"}),
                                html.Div([
                                    html.Strong("Drag and drop", style={"color":INK}),
                                    " a .pcap / .pcapng file here",
                                ], style={"fontSize":"0.92rem","color":INK_DIM}),
                                html.Div("- or click to browse -", style={
                                    "fontSize":"0.82rem","color":INK_MUTE,"marginTop":"6px"}),
                                html.Div(f"Max {MAX_UPLOAD_HUMAN} via drag-and-drop",
                                    style={"fontSize":"0.75rem","color":INK_MUTE,
                                           "marginTop":"8px",
                                           "fontFamily":"'JetBrains Mono', monospace",
                                           "letterSpacing":"0.04em"}),
                            ], style={"textAlign":"center","padding":"22px 16px"}),
                            multiple=False,
                            accept=".pcap,.pcapng,.cap",
                            style={"borderRadius":"12px",
                                "border":f"2px dashed {GLASS_BORDER_STRONG}",
                                "background":"rgba(139,92,246,0.04)",
                                "cursor":"pointer","transition":"all .2s"},
                            style_active={"border":f"2px dashed {VIOLET_BRIGHT}",
                                "background":"rgba(139,92,246,0.12)"},
                            style_reject={"border":f"2px dashed {RED_ACCENT}",
                                "background":"rgba(248,113,113,0.08)"},
                        ),

                        html.Div(style={"height":"14px"}),
                        html.Div("OR paste a full path (no size limit)", style={
                            "fontSize":"10px","color":INK_MUTE,
                            "fontFamily":"'JetBrains Mono', monospace",
                            "letterSpacing":"0.18em","textTransform":"uppercase",
                            "fontWeight":"600","marginBottom":"6px"}),
                        dbc.InputGroup([
                            dbc.Input(id="pcap-path-input", type="text",
                                placeholder=r"e.g. C:\Users\you\Downloads\capture.pcapng",
                                style={"background":"rgba(255,255,255,0.04)",
                                       "color":INK,
                                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                                       "fontFamily":"'JetBrains Mono', monospace",
                                       "fontSize":"12px"}),
                            dbc.Button("Load", id="pcap-path-btn", n_clicks=0,
                                style={"background":f"linear-gradient(135deg, {VIOLET}, {CYAN})",
                                       "border":"none","color":"white",
                                       "fontWeight":"600","fontSize":"12.5px"}),
                        ]),
                        html.Div("Tip: for files > 100 MB this is faster - Python reads "
                                 "the file directly from disk without copying through "
                                 "the browser.",
                            style={"fontSize":"0.75rem","color":INK_MUTE,
                                   "marginTop":"8px","lineHeight":"1.5"}),
                    ], style={**CARD, "padding":"26px","height":"100%",
                              "borderRadius":"20px"}),
                    md=6),

                    dbc.Col(html.Div([
                        html.Div("🔴", style={"fontSize":"3rem","textAlign":"center",
                                              "filter":f"drop-shadow(0 0 20px {RED_ACCENT}66)"}),
                        html.H4("Record Live Capture", style={
                            "color":INK if TSHARK_PATH else INK_MUTE,"fontWeight":"500",
                            "textAlign":"center","marginTop":"10px",
                            "fontFamily":"'Newsreader', Georgia, serif"}),
                        html.P("Record traffic live from a network interface. Defaults to "
                               "Wi-Fi. Min 2 min, max 1 hour per session.",
                            style={"color":INK_DIM,"textAlign":"center",
                                "fontSize":"0.88rem","minHeight":"60px"}),
                        dbc.Button(
                            "Start recording…" if TSHARK_PATH else "tshark not installed",
                            id="record-live-btn", n_clicks=0,
                            disabled=(not TSHARK_PATH),
                            className="aur-btn-danger" if TSHARK_PATH else "aur-btn-disabled",
                            style={"padding":"13px 28px","fontSize":"0.95rem",
                                "fontWeight":"600","borderRadius":"12px","border":"none",
                                "color":"white","width":"100%",
                                "fontFamily":"'Inter Tight', sans-serif"}),
                        html.Div("tshark records to disk in 30-second chunks, merged "
                                 "with mergecap on Stop & Save.",
                            style={"fontSize":"0.75rem","color":INK_MUTE,
                                   "marginTop":"14px","textAlign":"center"}),
                    ], style={**CARD, "padding":"26px","textAlign":"center","height":"100%",
                              "borderRadius":"20px"}),
                    md=6),
                ])),

                html.Div(id="load-status",
                    style={"marginTop":"28px","textAlign":"center","fontSize":"1.05rem",
                        "color":VIOLET_BRIGHT,"minHeight":"30px","lineHeight":"1.55",
                        "padding":"14px 20px","borderRadius":"10px",
                        "fontFamily":"'JetBrains Mono', monospace"}),
            ], style={**CARD, "padding":"40px 44px","borderRadius":"24px"}),

            _build_edu_panel("choice"),
        ])])
      ]),
      _build_floating_restart_pill(),
    ])



def _build_staged_card(staged):
    """The confirmation card shown when a file is staged but not yet analyzed.
    Two buttons: ▶ Analyze (runs analysis) and ✕ Clear (drops the file)."""
    if not staged:
        return None
    return html.Div([
        html.Div([
            html.Span("✓  ", style={"color":LIME,"fontWeight":"700",
                                      "marginRight":"6px","fontSize":"1.05rem"}),
            html.Span("Upload successful - review the file below and click ",
                     style={"color":INK,"fontSize":"0.92rem"}),
            html.Span("ANALYZE", style={"color":LIME,"fontWeight":"700",
                                          "fontFamily":"'JetBrains Mono', monospace",
                                          "letterSpacing":"0.08em",
                                          "fontSize":"0.88rem"}),
            html.Span(" to start.", style={"color":INK,"fontSize":"0.92rem"}),
        ], style={"padding":"10px 14px","marginBottom":"14px",
                  "borderRadius":"10px",
                  "background":"rgba(163,230,53,0.08)",
                  "border":f"1px solid {LIME}55",
                  "fontFamily":"'Inter Tight', sans-serif"}),
        html.Div([
            html.Span("📁", style={"fontSize":"2.5rem","marginRight":"16px"}),
            html.Div([
                html.Div([
                    html.Span("Ready to analyse", style={
                        "fontFamily":"'JetBrains Mono', monospace",
                        "fontSize":"10px","color":LIME,
                        "letterSpacing":"0.22em","textTransform":"uppercase",
                        "fontWeight":"700",
                        "padding":"2px 8px","borderRadius":"4px",
                        "background":"rgba(163,230,53,0.10)",
                        "border":f"1px solid {LIME}55",
                    }),
                ], style={"marginBottom":"6px"}),
                html.Div(staged.get("filename","upload.pcap"), style={
                    "fontFamily":"'Newsreader', Georgia, serif",
                    "fontSize":"1.4rem","fontWeight":"500","color":INK,
                    "letterSpacing":"-0.01em"}),
                html.Div([
                    html.Span(_human_size(staged.get("size_bytes",0))),
                    html.Span("  ·  ", style={"color":INK_MUTE}),
                    html.Span(("uploaded via drag-and-drop"
                               if staged.get("source") == "upload"
                               else "path: " + str(staged.get("path",""))[:60]),
                              style={"color":INK_MUTE}),
                ], style={"fontFamily":"'JetBrains Mono', monospace",
                          "fontSize":"11px","color":INK_DIM,"marginTop":"4px"}),
            ], style={"flex":"1"}),
        ], style={"display":"flex","alignItems":"center","marginBottom":"18px"}),

        dbc.Row([
            dbc.Col(dbc.Button(["▶ ", html.Span("Analyze",
                                                  style={"marginLeft":"4px"})],
                id="staged-analyze-btn", n_clicks=0,
                className="aur-btn-primary",
                style={"width":"100%","padding":"13px","fontSize":"0.95rem",
                       "fontWeight":"600","borderRadius":"12px","border":"none",
                       "color":"white",
                       "fontFamily":"'Inter Tight', sans-serif"}), md=8),
            dbc.Col(dbc.Button(["✕ ", html.Span("Clear",
                                                  style={"marginLeft":"4px"})],
                id="staged-clear-btn", n_clicks=0, className="aur-btn-ghost",
                style={"width":"100%","padding":"13px","fontSize":"0.95rem",
                       "fontWeight":"500","borderRadius":"12px",
                       "background":"rgba(255,255,255,0.04)",
                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                       "color":INK_DIM,
                       "fontFamily":"'Inter Tight', sans-serif"}), md=4),
        ]),
    ], style={**CARD, "padding":"22px 26px","marginBottom":"24px",
              "borderRadius":"16px",
              "borderLeft":f"3px solid {LIME}"})




def _build_second_staged_card(staged):
    """Stage-2 card for the S2 modal: 'READY TO ANALYSE S2' + Analyze + Clear.
    Mirrors _build_staged_card visually but uses staged-second-* IDs and the
    cyan accent for S2 (vs lime for S1)."""
    if not staged:
        return None
    accent = CYAN_BRIGHT
    return html.Div([
        html.Div([
            html.Span("\u2713  ", style={"color":accent,"fontWeight":"700",
                                          "marginRight":"6px","fontSize":"1.05rem"}),
            html.Span("S2 staged - review the file below and click ",
                     style={"color":INK,"fontSize":"0.92rem"}),
            html.Span("ANALYZE S2", style={"color":accent,"fontWeight":"700",
                                            "fontFamily":"'JetBrains Mono', monospace",
                                            "letterSpacing":"0.08em",
                                            "fontSize":"0.88rem"}),
            html.Span(" to start the dual-session comparison.",
                     style={"color":INK,"fontSize":"0.92rem"}),
        ], style={"padding":"10px 14px","marginBottom":"14px",
                  "borderRadius":"10px",
                  "background":"rgba(34,211,238,0.10)",
                  "border":f"1px solid {accent}55",
                  "fontFamily":"'Inter Tight', sans-serif"}),
        html.Div([
            html.Span("\U0001f4c1", style={"fontSize":"2.5rem","marginRight":"16px"}),
            html.Div([
                html.Div([
                    html.Span("Ready to analyse S2", style={
                        "fontFamily":"'JetBrains Mono', monospace",
                        "fontSize":"10px","color":accent,
                        "letterSpacing":"0.22em","textTransform":"uppercase",
                        "fontWeight":"700",
                        "padding":"2px 8px","borderRadius":"4px",
                        "background":"rgba(34,211,238,0.12)",
                        "border":f"1px solid {accent}55",
                    }),
                ], style={"marginBottom":"6px"}),
                html.Div(staged.get("filename","upload.pcap"), style={
                    "fontFamily":"'Newsreader', Georgia, serif",
                    "fontSize":"1.4rem","fontWeight":"500","color":INK,
                    "letterSpacing":"-0.01em"}),
                html.Div([
                    html.Span(_human_size(staged.get("size_bytes",0))),
                    html.Span("  \u00b7  ", style={"color":INK_MUTE}),
                    html.Span(("uploaded via drag-and-drop"
                               if staged.get("source") == "upload"
                               else "path: " + str(staged.get("path",""))[:60]),
                              style={"color":INK_MUTE}),
                ], style={"fontFamily":"'JetBrains Mono', monospace",
                          "fontSize":"11px","color":INK_DIM,"marginTop":"4px"}),
            ], style={"flex":"1"}),
        ], style={"display":"flex","alignItems":"center","marginBottom":"18px"}),

        dbc.Row([
            dbc.Col(dbc.Button(["\u25b6 ", html.Span("Analyze S2",
                                                      style={"marginLeft":"4px"})],
                id="staged-second-analyze-btn", n_clicks=0,
                className="aur-btn-primary",
                style={"width":"100%","padding":"13px","fontSize":"0.95rem",
                       "fontWeight":"600","borderRadius":"12px","border":"none",
                       "color":"white",
                       "fontFamily":"'Inter Tight', sans-serif"}), md=8),
            dbc.Col(dbc.Button(["\u2715 ", html.Span("Clear",
                                                      style={"marginLeft":"4px"})],
                id="staged-second-clear-btn", n_clicks=0, className="aur-btn-ghost",
                style={"width":"100%","padding":"13px","fontSize":"0.95rem",
                       "fontWeight":"500","borderRadius":"12px",
                       "background":"rgba(255,255,255,0.04)",
                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                       "color":INK_DIM,
                       "fontFamily":"'Inter Tight', sans-serif"}), md=4),
        ]),
    ], style={**CARD, "padding":"22px 26px","marginBottom":"8px",
              "borderRadius":"16px",
              "borderLeft":f"3px solid {accent}"})


def build_topbar():
    """Glass topbar: one centered brand block (enlarged NETSEC wordmark +
    subtitle). Session details live in the sidebar cards, so nothing here
    duplicates them."""
    return html.Div([
        html.Div([
            html.Div(
                html.Img(src=_build_netsec_mini_badge(height_px=46),
                    style={"height":"46px","width":"auto","display":"block"}),
                style={
                "padding":"6px 16px","borderRadius":"12px",
                "background":"rgba(248,168,168,0.06)",
                "border":"1px solid rgba(248,168,168,0.25)",
                "boxShadow":"0 0 26px rgba(248,168,168,0.18)",
                "display":"inline-flex","alignItems":"center"}),
            html.Div([
                html.Div("PCAP & Live Analysis", style={
                    "fontWeight":"600","fontSize":"15px","letterSpacing":"-0.015em",
                    "color":INK,"lineHeight":"1.1","whiteSpace":"nowrap"}),
                html.Div("tshark + ML \u00b7 real-time analysis", style={
                    "fontFamily":"'JetBrains Mono', monospace","fontSize":"10.5px",
                    "color":INK_MUTE,"letterSpacing":"0.02em","marginTop":"3px",
                    "whiteSpace":"nowrap"}),
            ], style={"marginLeft":"16px"}),
        ], id="brand-home", n_clicks=0,
           style={"display":"inline-flex","alignItems":"center","cursor":"pointer",
                  "transition":"opacity .2s"},
           title="Click to return to the welcome screen"),
    ], style={"margin":"18px 22px 0","padding":"12px 22px","borderRadius":"18px",
              "background":GLASS_BG,
              "backdropFilter":"blur(28px) saturate(140%)",
              "WebkitBackdropFilter":"blur(28px) saturate(140%)",
              "border":f"1px solid {GLASS_BORDER}",
              "boxShadow":"0 1px 0 rgba(255,255,255,0.04) inset, 0 20px 60px -20px rgba(0,0,0,0.6)",
              "position":"sticky","top":"0","zIndex":"50",
              "display":"flex","justifyContent":"center","alignItems":"center"})


# ---- data-sufficiency layer ---------------------------------------------
# A chart with nothing meaningful to show must SAY WHY instead of rendering
# an empty or flat plot: attack PCAPs have no browsing life, wired captures
# have no RSSI, spoofed floods produce byte-identical "top talkers".
_DEGENERATE_NOTES = {
    "talkers": ("All top sources sent byte-identical traffic - that is not "
                "normal browsing, it is the signature of a spoofed-source "
                "flood or synthetically generated traffic. The phenomenon "
                "itself is captured under Security \u2192 TCP SYN Analysis."),
    "dns":     ("No DNS queries were observed in this capture, so there are "
                "no services to chart. Attack PCAPs and pure-transport "
                "captures contain no name-resolution traffic."),
    "browse":  ("No recognizable browsing (DNS) activity in this capture - "
                "nothing to categorize. This is expected for attack PCAPs "
                "or captures without client web traffic."),
    "proximity": ("No WiFi signal-strength (RSSI) data in this capture - "
                  "wired interfaces and non-monitor-mode recordings do not "
                  "carry radiotap headers."),
    "lstm":    ("The capture is too short or too uniform to train the LSTM "
                "rhythm model - it needs several minutes of varied "
                "per-second traffic."),
    "updown":  ("No upload/download traffic split to chart - this capture "
                "has no bidirectional client flows."),
    "upload":  ("No upload traffic recorded for local devices in this "
                "capture."),
    "download": ("No download traffic recorded for local devices in this "
                 "capture."),
    "ext":     ("No identified external providers in this capture - all "
                 "traffic stayed local, or there were no outbound flows."),
    "external": ("No identified external providers in this capture - all "
                 "traffic stayed local, or there were no outbound flows."),
    "timeline": ("No per-minute traffic variation to plot - the capture is "
                 "too short or carries a single burst."),
    "devices":  ("No local devices could be identified in this capture."),
}

def _degenerate_note_for(chart_id):
    base = chart_id[:-3] if chart_id.endswith(("_s1", "_s2")) else chart_id
    for prefix, note in _DEGENERATE_NOTES.items():
        if base.startswith(prefix):
            return note
    return ("This capture does not contain the kind of traffic this view "
            "visualizes, so there is no meaningful signal to draw.")

def _fig_health(fig):
    """'empty' - nothing to draw; 'uniform' - a single bar trace whose
    values are all identical (a ranking with no information); 'ok'
    otherwise. Indicator gauges and tables are always 'ok' - they carry
    their own empty semantics."""
    try:
        traces = list(fig.data)
    except Exception:
        return "ok"
    if not traces:
        return "empty"
    pts = 0
    for tr in traces:
        ttype = getattr(tr, "type", "") or ""
        if ttype in ("indicator", "table"):
            return "ok"
        for attr in ("x", "y", "values", "z", "r"):
            v = getattr(tr, attr, None)
            if v is None:
                continue
            try:
                pts = max(pts, sum(1 for q in v if q is not None))
            except TypeError:
                pass
    if pts == 0:
        return "empty"
    if len(traces) == 1 and (getattr(traces[0], "type", "") or "") == "bar":
        y = getattr(traces[0], "y", None)
        if y is None:
            y = getattr(traces[0], "x", None)
        try:
            vals = [float(q) for q in y if q is not None]
            if len(vals) >= 8 and len(set(vals)) == 1:
                return "uniform"
        except (TypeError, ValueError):
            pass
    return "ok"

def _empty_state_card(chart_id, kind):
    """Explains WHY a view has no meaningful signal, and where the
    phenomenon (if any) was actually caught."""
    if kind == "uniform":
        icon, headline = "\U0001F6A9", "Uniform values - this is itself a finding"
    else:
        icon, headline = "\U0001FAD9", "No meaningful signal in this capture"
    return html.Div([
        html.Div(icon, style={"fontSize":"2.6rem","textAlign":"center",
                              "marginBottom":"10px","opacity":"0.75"}),
        html.Div(headline, style={"color":INK,"fontWeight":"500",
            "textAlign":"center","fontSize":"1.25rem","marginBottom":"8px",
            "fontFamily":"'Newsreader', Georgia, serif"}),
        html.P(_degenerate_note_for(chart_id),
            style={"color":INK_DIM,"textAlign":"center","fontSize":"0.92rem",
                   "lineHeight":"1.6","maxWidth":"640px","margin":"0 auto"}),
    ], style={"padding":"36px 20px 30px","borderRadius":"14px",
              "background":("rgba(251,191,36,0.05)" if kind == "uniform"
                            else "rgba(255,255,255,0.02)"),
              "border":(f"1px solid rgba(251,191,36,0.25)" if kind == "uniform"
                        else f"1px solid {GLASS_BORDER}"),
              "marginBottom":"16px"})

def _grid_graph(fig_key, height=380):
    """dcc.Graph for one FIGS entry inside a per-session grid, swapping to
    an explanation card when the figure carries no signal."""
    if fig_key not in FIGS:
        return html.Div(f"(chart {fig_key} not built)",
            style={"color":INK_MUTE,"padding":"20px","textAlign":"center"})
    health = _fig_health(FIGS[fig_key])
    if health == "empty":
        return _empty_state_card(fig_key, "empty")
    return dcc.Graph(figure=FIGS[fig_key], style={"height":f"{height}px"},
                     config={"displayModeBar":False, "responsive":True})

def _render_session_grid(chart_id):
    """Multi-figure per-session pages (Upload/Download, External Traffic)."""
    if chart_id == "updown_s1":
        return dbc.Row([dbc.Col(_grid_graph("upload_s1"), md=6),
                        dbc.Col(_grid_graph("download_s1"), md=6)])
    if chart_id == "updown_s2":
        return dbc.Row([dbc.Col(_grid_graph("upload_s2"), md=6),
                        dbc.Col(_grid_graph("download_s2"), md=6)])
    if chart_id == "external_s1":
        return html.Div([
            dbc.Row([dbc.Col(_grid_graph("ext_provider_s1"), md=6),
                     dbc.Col(_grid_graph("ext_type_s1"), md=6)])])
    if chart_id == "external_s2":
        return html.Div([
            dbc.Row([dbc.Col(_grid_graph("ext_provider_s2"), md=6),
                     dbc.Col(_grid_graph("ext_type_s2"), md=6)])])
    return html.Div()


def _get_chart_content(chart_id):
    """Pure function returning the content for chart-area. Called both by
    build_dashboard_view (at construction time, so the area is never empty)
    and by render_chart (on subsequent navigation/state changes)."""
    if chart_id == "live_recording":
        return html.Div([
            html.H4(LABEL_MAP.get(chart_id, "🔴 Live Recording"),
                    style={"color":INK,"fontWeight":"500","marginBottom":"18px",
                           "fontFamily":"'Newsreader', Georgia, serif",
                           "fontSize":"1.8rem","letterSpacing":"-0.02em"}),
            _build_live_recording_page(),
        ])

    has_any_session = (S1 is not None) or (S2 is not None)
    if not has_any_session and chart_id != "insights":
        return html.Div([
            html.H4(LABEL_MAP.get(chart_id, ""),
                    style={"color":INK,"fontWeight":"500","marginBottom":"18px",
                           "fontFamily":"'Newsreader', Georgia, serif",
                           "fontSize":"1.8rem","letterSpacing":"-0.02em"}),
            html.Div([
                html.Div("📭", style={"fontSize":"3.5rem","textAlign":"center",
                                       "marginBottom":"16px","opacity":"0.6"}),
                html.H3("No session loaded yet",
                    style={"color":INK,"fontWeight":"500","textAlign":"center",
                           "fontFamily":"'Newsreader', Georgia, serif",
                           "fontSize":"1.5rem","marginBottom":"8px"}),
                html.P("Choose how to start: load a PCAP from disk, or record live "
                       "traffic from a network interface.",
                       style={"color":INK_DIM,"textAlign":"center",
                              "marginBottom":"24px","fontSize":"0.95rem"}),
                dbc.Row([
                    dbc.Col(html.Div(dbc.Button(
                        ["📊 ", html.Span("Load PCAP File",
                                          style={"marginLeft":"4px"})],
                        id="empty-load-pcap-btn", n_clicks=0,
                        className="aur-btn-primary",
                        style={"width":"100%","padding":"14px",
                               "fontSize":"0.95rem","fontWeight":"600",
                               "borderRadius":"12px","border":"none",
                               "color":"white",
                               "fontFamily":"'Inter Tight', sans-serif"}),
                        style={"padding":"0 10px"}), md=6),
                    dbc.Col(html.Div(dbc.Button(
                        ["🔴 ", html.Span("Start Live Recording",
                                          style={"marginLeft":"4px"})],
                        id="empty-record-live-btn", n_clicks=0,
                        disabled=(not TSHARK_PATH),
                        className="aur-btn-danger" if TSHARK_PATH else "aur-btn-disabled",
                        style={"width":"100%","padding":"14px",
                               "fontSize":"0.95rem","fontWeight":"600",
                               "borderRadius":"12px","border":"none",
                               "color":"white",
                               "fontFamily":"'Inter Tight', sans-serif"}),
                        style={"padding":"0 10px"}), md=6),
                ], style={"maxWidth":"560px","margin":"0 auto"}),
                html.Div("Tip: you can also use the sidebar items below - "
                         "🔴 Live Recording is the very first one.",
                         style={"color":INK_MUTE,"textAlign":"center",
                                "marginTop":"22px","fontSize":"0.85rem",
                                "fontFamily":"'JetBrains Mono', monospace"}),
            ], style={"padding":"40px 20px"})
        ])

    children = [
        html.H4(LABEL_MAP.get(chart_id, ""),
                style={"color":INK,"fontWeight":"500","marginBottom":"18px",
                       "fontFamily":"'Newsreader', Georgia, serif",
                       "fontSize":"1.8rem","letterSpacing":"-0.02em"})
    ]

    if chart_id == "insights":
        children.append(_render_insights())
        children.append(_render_model_diagnostics())
        return html.Div(children)

    if chart_id == "ip_history":
        children.append(_render_ip_browsing_history())
        return html.Div(children)

    _ADV_SPECS = {
        "adv_beaconing":  ("beaconing", "T1071 / T1571 - regular outbound traffic to a single external peer (callback to command-and-control infrastructure)."),
        "adv_dns_tunnel": ("dns_tunnel", "T1071.004 - DNS used as a covert channel: many unique high-entropy subdomains under one apex, plus NXDOMAIN storms."),
        "adv_dga":        ("dga", "T1568.002 - Domain Generation Algorithm: low-likelihood domain labels by a character-bigram model trained on the resolved domains in this capture."),
        "adv_arp_dhcp":   ("arp_dhcp", "T1557 - one IP claimed by multiple MACs, one MAC announcing many IPs, gratuitous ARP floods, or unexpected DHCP servers offering leases."),
        "adv_tls":        ("tls", "T1071.001 / T1090 - rare JA3 client fingerprints, TLS to external IPs with no SNI, or SNI vs destination-IP provider mismatch (domain fronting)."),
    }
    if chart_id.startswith("adv_"):
        _base = chart_id
        _adv_sessions = ("S1", "S2")
        if chart_id.endswith("_s1"):
            _base, _adv_sessions = chart_id[:-3], ("S1",)
        elif chart_id.endswith("_s2"):
            _base, _adv_sessions = chart_id[:-3], ("S2",)
        if _base in _ADV_SPECS:
            _key, _desc = _ADV_SPECS[_base]
            children.append(_render_adv_engine(_key, _base, _desc,
                                               sessions=_adv_sessions))
            return html.Div(children)
        if _base == "adv_killchain":
            children.append(_render_adv_killchain(sessions=_adv_sessions))
            return html.Div(children)

    if chart_id in COMPARE_CHART_IDS:
        b = _needs_s2_banner()
        if b is not None:
            children.append(b)
            children.append(html.Div(
                "Once both sessions exist, this chart will populate automatically.",
                style={"color":INK_MUTE,"textAlign":"center",
                       "padding":"60px 20px","fontSize":"0.95rem"}))
            return html.Div(children)

    if chart_id in ML_CHART_IDS:
        _scope = SESSION_SCOPE.get(chart_id)
        if _scope == "s1":
            b = _ml_banner_for(S1, "Session 1")
            if b is not None: children.append(b)
        elif _scope == "s2":
            b = _ml_banner_for(S2, "Session 2")
            if b is not None: children.append(b)
        else:
            for s, lbl in [(S1, "Session 1"), (S2, "Session 2")]:
                b = _ml_banner_for(s, lbl)
                if b is not None: children.append(b)

    # Per-session multi-figure grids (Upload/Download, External Traffic).
    if chart_id in ("updown_s1", "updown_s2", "external_s1", "external_s2"):
        children.append(_render_session_grid(chart_id))
        return html.Div(children)

    chart_id_for_render = chart_id
    if chart_id_for_render not in FIGS:
        children.append(html.P(
            "Chart not yet available - load a session first.",
            style={"color":INK_MUTE,"textAlign":"center","padding":"40px"}))
        return html.Div(children)

    if chart_id in EXPLANATIONS:
        children.append(html.Div(EXPLANATIONS[chart_id],
            style={"background":"rgba(251,191,36,0.06)",
                   "border":f"1px solid rgba(251,191,36,0.20)",
                   "borderRadius":"12px","padding":"14px 18px","marginBottom":"18px",
                   "fontSize":"0.88rem","color":INK_DIM,"lineHeight":"1.6"}))

    _fig = FIGS[chart_id_for_render]
    _health = _fig_health(_fig)
    if _health == "empty":
        children.append(_empty_state_card(chart_id, "empty"))
        return html.Div(children)
    if _health == "uniform":
        children.append(_empty_state_card(chart_id, "uniform"))

    children.append(dcc.Graph(
        figure=_fig, style={"minHeight":"500px"},
        config={"displayModeBar":False,"scrollZoom":True}))

    return html.Div(children)


def build_tab_strip(active_tab):
    """Two big pill buttons at the top of the dashboard: Analyze | Security.
    Clicking one swaps the sidebar's contents to only that tab's sections
    and navigates the chart-area to the first item of that tab."""
    btns = []
    for tab_id, icon, lbl in TABS_SPEC:
        is_active = (tab_id == active_tab)
        btns.append(html.Div([
                html.Span(icon, style={"marginRight":"10px","fontSize":"1.15rem"}),
                html.Span(lbl, style={"fontWeight":"600",
                                       "letterSpacing":"0.02em"}),
            ],
            id={"type":"tab-btn", "id":tab_id},
            n_clicks=0,
            style={
                "cursor":"pointer",
                "padding":"13px 30px",
                "borderRadius":"14px",
                "background": (f"linear-gradient(135deg, {VIOLET}, {CYAN})"
                               if is_active else "rgba(255,255,255,0.04)"),
                "color":       ("white" if is_active else INK_DIM),
                "fontFamily":  "'Inter Tight', sans-serif",
                "fontSize":    "0.95rem",
                "border": ("none" if is_active
                           else f"1px solid {GLASS_BORDER_STRONG}"),
                "boxShadow":   ("0 6px 24px rgba(139,92,246,0.35)"
                               if is_active else "none"),
                "transition":  "all .2s ease",
                "display":     "inline-flex",
                "alignItems":  "center",
                "userSelect":  "none",
            }))
    return html.Div(btns, id="tab-strip-inner", style={
        "display":"flex","gap":"12px","padding":"0 22px 12px",
        "alignItems":"center"})


def build_chart_picker_strip(active_chart, active_tab, active_session="s1"):
    """Horizontal chip strip for the active top-level tab, filtered by the
    S1 | S2 session sub-tab that leads the strip. The S2 pill stays locked
    (greyed, tooltip) until a second session is loaded, so the strip never
    fills with dead chips. Chips keep the {"type":"nav-item","id":nid}
    pattern so click_nav fires unchanged."""
    has_s2 = S2 is not None
    active_session = active_session if active_session in ("s1", "s2") else "s1"
    if active_session == "s2" and not has_s2:
        active_session = "s1"

    pills = []
    for sid, plabel in (("s1", "Session 1"), ("s2", "Session 2")):
        is_on  = (sid == active_session)
        locked = (sid == "s2" and not has_s2)
        if is_on:
            pstyle = {"padding":"8px 18px","borderRadius":"10px",
                "background":f"linear-gradient(135deg, {VIOLET}, {CYAN})",
                "color":"white","fontWeight":"700","cursor":"pointer",
                "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
                "letterSpacing":"0.14em","textTransform":"uppercase",
                "whiteSpace":"nowrap","flexShrink":"0",
                "boxShadow":"0 6px 20px -8px rgba(139,92,246,0.55)"}
        elif locked:
            pstyle = {"padding":"8px 18px","borderRadius":"10px",
                "background":"rgba(255,255,255,0.02)",
                "border":f"1px solid {GLASS_BORDER}","color":INK_MUTE,
                "opacity":"0.45","cursor":"not-allowed",
                "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
                "letterSpacing":"0.14em","textTransform":"uppercase",
                "whiteSpace":"nowrap","flexShrink":"0"}
        else:
            pstyle = {"padding":"8px 18px","borderRadius":"10px",
                "background":"rgba(255,255,255,0.05)",
                "border":f"1px solid {GLASS_BORDER_STRONG}","color":INK_DIM,
                "cursor":"pointer","fontFamily":"'JetBrains Mono', monospace",
                "fontSize":"11px","letterSpacing":"0.14em",
                "textTransform":"uppercase","whiteSpace":"nowrap",
                "flexShrink":"0","transition":"all .15s ease"}
        pills.append(html.Div(plabel,
            id={"type":"session-tab","id":sid},
            n_clicks=0 if not locked else None,
            title=("Load or record a second session to unlock S2 views"
                   if locked else ""),
            style=pstyle))
    pills.append(html.Div(style={"width":"1px","alignSelf":"stretch",
        "background":GLASS_BORDER_STRONG,"margin":"2px 6px","flexShrink":"0"}))

    chips = []
    for nid, icon, lbl, sec, scope in NAV_ITEMS:
        if SECTION_TO_TAB.get(sec, "analyze") != active_tab:
            continue
        if scope != "any" and scope != active_session:
            continue
        is_active   = (nid == active_chart)
        is_disabled = (nid in NEEDS_S2_IDS and not has_s2)
        # keep the Live Recording chip disabled when tshark is missing so
        # the user cannot land on a page where Record does nothing.
        if nid == "live_recording" and not TSHARK_PATH:
            is_disabled = True
        if is_active:
            style = {"padding":"8px 16px","borderRadius":"999px",
                "background":f"linear-gradient(135deg, rgba(139,92,246,0.22), rgba(34,211,238,0.16))",
                "border":f"1px solid rgba(139,92,246,0.45)","color":INK,
                "fontWeight":"600","cursor":"pointer",
                "fontFamily":"'Inter Tight', sans-serif","fontSize":"12.5px",
                "whiteSpace":"nowrap","flexShrink":"0",
                "display":"inline-flex","alignItems":"center","gap":"7px",
                "boxShadow":"0 6px 20px -8px rgba(139,92,246,0.5)"}
        elif is_disabled:
            style = {"padding":"8px 16px","borderRadius":"999px",
                "background":"rgba(255,255,255,0.02)","border":f"1px solid {GLASS_BORDER}",
                "color":INK_MUTE,"opacity":"0.45","cursor":"not-allowed",
                "fontFamily":"'Inter Tight', sans-serif","fontSize":"12.5px",
                "whiteSpace":"nowrap","flexShrink":"0",
                "display":"inline-flex","alignItems":"center","gap":"7px"}
        else:
            style = {"padding":"8px 16px","borderRadius":"999px",
                "background":"rgba(255,255,255,0.04)",
                "border":f"1px solid {GLASS_BORDER_STRONG}","color":INK_DIM,
                "cursor":"pointer","fontFamily":"'Inter Tight', sans-serif",
                "fontSize":"12.5px","whiteSpace":"nowrap","flexShrink":"0",
                "display":"inline-flex","alignItems":"center","gap":"7px",
                "transition":"all .15s ease"}
        chips.append(html.Div([
            html.Span(icon, style={"fontSize":"13px","opacity":"0.9"}),
            html.Span(lbl),
        ], id={"type":"nav-item","id":nid},
           n_clicks=0 if not is_disabled else None,
           style=style,
           className="aur-chip-active" if is_active else (
               "aur-chip-disabled" if is_disabled else "aur-chip")))
    return html.Div(pills + chips, id="chart-picker-strip-inner", style={
        "display":"flex","gap":"8px","padding":"10px 22px 14px",
        "overflowX":"auto","overflowY":"hidden",
        "alignItems":"center"})


def _build_analysis_wait_panel():
    """Rendered by the chart-area dcc.Loading (custom_spinner) while a long
    callback - Analyze on a staged PCAP, Analyze on a saved live recording,
    or an S2 comparison build - recomputes the dashboard. Carries the same
    educational material as the other loading surfaces, expanded by default,
    so the wait doubles as reading time. Self-scrolls so the tallest sections
    stay reachable inside the loading overlay."""
    return html.Div([
        html.Div([
            html.Span("▮", style={
                "animation":"netsec-blink 1.1s steps(1) infinite",
                "color":VIOLET_BRIGHT,"fontSize":"13px","marginRight":"12px",
                "textShadow":f"0 0 14px {VIOLET_BRIGHT}aa"}),
            html.Span("ANALYZING CAPTURE · EXTRACTING FEATURES · RUNNING MODELS",
                style={"fontFamily":"'JetBrains Mono', monospace",
                       "fontSize":"12px","color":INK,
                       "letterSpacing":"0.18em","fontWeight":"700"}),
        ], style={"display":"flex","alignItems":"center",
                  "justifyContent":"center","marginBottom":"8px"}),
        html.Div("This can take a minute or two on large captures - the "
                 "material below explains exactly what the analyzer is doing "
                 "in the meantime.",
            style={"color":INK_DIM,"fontSize":"0.9rem","textAlign":"center",
                   "marginBottom":"2px"}),
        _build_edu_panel("wait", open_by_default=True),
    ], style={"width":"min(980px, 92vw)","margin":"0 auto",
              "padding":"26px 24px 40px","textAlign":"left",
              "maxHeight":"calc(100vh - 200px)","overflowY":"auto",
              "borderRadius":"20px",
              "background":"rgba(13,10,26,0.92)",
              "border":f"1px solid {GLASS_BORDER_STRONG}",
              "boxShadow":"0 20px 60px -20px rgba(0,0,0,0.7)"})


def build_dashboard_view(active_chart="live_recording", active_tab="analyze", active_session="s1"):
    """Main dashboard layout. CRITICAL: chart-area is pre-populated with the
    right content at construction time so we don't rely on a separate callback
    that may not fire if it loses a Dash callback race."""
    return html.Div([
        build_topbar(),
        html.Div(build_tab_strip(active_tab), id="tab-strip",
                 style={"padding":"6px 0 0"}),
        html.Div(build_chart_picker_strip(active_chart, active_tab, active_session),
                 id="chart-picker-strip",
                 style={"padding":"0"}),
        dbc.Container(fluid=True, style={"padding":"22px","position":"relative","zIndex":"2"}, children=[
            dbc.Row([
                dbc.Col(dcc.Loading(
                    children=html.Div(_build_sidebar(active_chart, active_tab), id="sidebar", style={
                    "borderRadius":"20px","padding":"18px 12px",
                    "background":GLASS_BG,
                    "backdropFilter":"blur(28px) saturate(140%)",
                    "WebkitBackdropFilter":"blur(28px) saturate(140%)",
                    "border":f"1px solid {GLASS_BORDER}",
                    "minHeight":"500px",
                    "maxHeight":"calc(100vh - 130px)","overflowY":"auto",
                    "position":"sticky","top":"100px",
                    "boxShadow":"0 1px 0 rgba(255,255,255,0.04) inset, 0 20px 60px -20px rgba(0,0,0,0.6)"}),
                    type="dot", color=VIOLET_BRIGHT,
                    parent_style={"minHeight":"500px"}),
                    md=3, lg=2),
                dbc.Col(dcc.Loading(
                    children=html.Div(_get_chart_content(active_chart), id="chart-area", style={
                    "padding":"24px","borderRadius":"20px",
                    "background":GLASS_BG,
                    "backdropFilter":"blur(24px) saturate(140%)",
                    "WebkitBackdropFilter":"blur(24px) saturate(140%)",
                    "border":f"1px solid {GLASS_BORDER}",
                    "minHeight":"500px",
                    "boxShadow":"0 1px 0 rgba(255,255,255,0.04) inset, 0 20px 60px -20px rgba(0,0,0,0.6)"}),
                    custom_spinner=_build_analysis_wait_panel(),
                    delay_show=500,
                    parent_style={"minHeight":"500px"}),
                    md=9, lg=10),
            ]),
        ]),
        html.Div(dbc.Button("↺ Restart", id="restart-btn", n_clicks=0,
            className="aur-btn-ghost",
            style={"fontSize":"11.5px","fontWeight":"500",
                   "padding":"9px 16px","borderRadius":"12px",
                   "background":"rgba(13,10,26,0.85)","color":INK_DIM,
                   "border":f"1px solid {GLASS_BORDER_STRONG}",
                   "backdropFilter":"blur(20px) saturate(140%)",
                   "WebkitBackdropFilter":"blur(20px) saturate(140%)",
                   "fontFamily":"'JetBrains Mono', monospace",
                   "letterSpacing":"0.04em",
                   "boxShadow":"0 4px 20px rgba(0,0,0,0.4)"}),
            style={"position":"fixed","bottom":"22px","right":"22px","zIndex":"9999",
                   "pointerEvents":"auto"}),
    ])


def _render_ip_browsing_history():
    """Render the IP Browsing History view: text input + search button + output
    div. The output is populated by the build_ip_history_heatmap callback below
    after the user clicks Search (or presses Enter)."""
    return html.Div([
        html.Div(
            "Enter an internal IP address (e.g. 192.168.1.42) to see which "
            "domains it queried over time, in each loaded session. Heatmap "
            "rows are the top 25 most-queried domains for that IP; columns are "
            "time bins across the capture window.",
            style={"color":INK_DIM,"marginBottom":"14px","fontSize":"0.9rem",
                   "lineHeight":"1.55"}),
        dbc.InputGroup([
            dbc.Input(id="ip-history-input", type="text",
                placeholder="e.g. 8.8.8.8 or 192.168.1.42",
                debounce=True, n_submit=0,
                style={"background":"rgba(255,255,255,0.04)",
                       "color":INK,
                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                       "fontFamily":"'JetBrains Mono', monospace",
                       "fontSize":"12px"}),
            dbc.Button(["\U0001F50D  Search"], id="ip-history-search-btn", n_clicks=0,
                style={"background":f"linear-gradient(135deg, {VIOLET}, {CYAN})",
                       "border":"none","color":"white",
                       "fontWeight":"600","fontSize":"12.5px"}),
        ], style={"marginBottom":"16px","maxWidth":"560px"}),
        dcc.Loading(type="dot", color=VIOLET_BRIGHT,
            children=html.Div(id="ip-history-output",
                children=html.Div(
                    "Enter an IP above and click Search to see its DNS activity.",
                    style={"color":INK_MUTE,"padding":"40px 20px",
                           "textAlign":"center","fontSize":"0.92rem"}))),
    ])


def _build_ip_history_session_fig(session, ip_addr):
    """Build a Plotly heatmap of (time_bin x domain -> query count) for a
    single IP within a single session. Returns (fig, n_queries). If the IP
    has no DNS activity in this session, fig is None and n_queries is 0."""
    from collections import Counter as _Counter_local

    dns_timeline = session.get("dns_timeline") or []
    matching = [(ts, q) for ts, ip, q in dns_timeline
                if ip == ip_addr
                and not q.endswith(".local")
                and not q.endswith(".arpa")]
    if not matching:
        return None, 0

    t0 = session.get("t0")
    t1 = session.get("t1")
    if t0 is None or t1 is None:
        return None, 0
    t0_ts = _safe_epoch(t0)
    t1_ts = _safe_epoch(t1)
    n_bins = 30
    span = max(1.0, t1_ts - t0_ts)
    bucket = span / n_bins

    def _bin_label(i):
        return _safe_fromtimestamp(t0_ts + i * bucket).strftime("%H:%M")

    bin_labels = [_bin_label(i) for i in range(n_bins)]

    def _reg(q):
        parts = q.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return q

    domain_totals = _Counter_local()
    rows = []
    for ts, q in matching:
        d = _reg(q)
        domain_totals[d] += 1
        bidx = int((ts - t0_ts) / bucket)
        if bidx >= n_bins:
            bidx = n_bins - 1
        if bidx < 0:
            bidx = 0
        rows.append((d, bidx))

    top_domains = [d for d, _ in domain_totals.most_common(25)]
    top_set = set(top_domains)

    z = [[0]*n_bins for _ in top_domains]
    d_idx = {d: i for i, d in enumerate(top_domains)}
    for d, bidx in rows:
        if d in top_set:
            z[d_idx[d]][bidx] += 1

    fig = go.Figure(go.Heatmap(
        z=z,
        x=bin_labels,
        y=top_domains,
        colorscale="Viridis",
        hovertemplate="Domain: %{y}<br>Time: %{x}<br>Queries: %{z}<extra></extra>",
        colorbar=dict(title="Queries"),
    ))
    tick_step = max(1, n_bins // 12)
    tickvals = list(range(0, n_bins, tick_step))
    ticktext = [bin_labels[i] for i in tickvals]
    fig.update_layout(
        title=dict(
            text=(f"{session.get('label','Session')} - {ip_addr} "
                  f"- {len(matching):,} DNS queries"),
            x=0.5, xanchor="center", y=0.97, yanchor="top",
        ),
        xaxis=dict(title="Time", tickmode="array",
                   tickvals=tickvals, ticktext=ticktext, tickangle=-45),
        yaxis=dict(automargin=True, title="Domain"),
        height=max(360, len(top_domains)*22 + 160),
        plot_bgcolor=WHITE, paper_bgcolor=WHITE,
        margin=dict(l=20, r=20, t=70, b=80),
    )
    return fig, len(matching)




def _worker_state_summary():
    """peek at both live workers so the sidebar can grey out
    buttons whose click would lose in-flight work.

    Returns dict with keys s1_busy, s2_busy, s2_pending, s1_pending, plus
    per-session raw state ('idle'|'recording'|'paused'|'saved'|'analyzing').
    Never raises; missing workers = 'idle'."""
    def _one(sid):
        w = LIVE_SESSIONS.get(sid)
        if w is None:
            return "idle", False, False
        try:
            status = (w.quick_stats() or {}).get("status", "idle")
            analyzing = bool(getattr(w, "_analyzing", False))
            pending   = getattr(w, "_pending_snapshot", None) is not None
            if analyzing:
                status = "analyzing"
            return status, analyzing, pending
        except Exception:
            return "idle", False, False
    s1_state, _s1a, s1_pending = _one("S1")
    s2_state, _s2a, s2_pending = _one("S2")
    busy_states = {"recording", "paused", "analyzing"}
    return {
        "s1_state":   s1_state,
        "s2_state":   s2_state,
        "s1_busy":    s1_state in busy_states,
        "s2_busy":    s2_state in busy_states,
        "s1_pending": s1_pending,
        "s2_pending": s2_pending,
    }


def _guard_reason(kind, state):
    """User-facing tooltip text explaining why a sidebar button is disabled."""
    if kind == "s1_busy":
        return f"S1 is currently {state} - Stop or Reset the S1 recording first"
    if kind == "s2_busy":
        return f"S2 is currently {state} - Stop or Reset the S2 recording first"
    if kind == "s2_pending":
        return "S2 has an un-analyzed recording - Analyze or Discard it first"
    if kind == "s1_pending":
        return "S1 has an un-analyzed recording - Analyze or Discard it first"
    if kind == "no_tshark":
        return "tshark is not installed - live recording is unavailable"
    return "This action is temporarily disabled"


def _session_info_cards():
    """Per-session detail cards for the sidebar top: source file, capture
    window, packet count and WiFi identity when known. This replaces both
    the old "S1: loaded / S2: not loaded" box and the topbar chips, so the
    information appears exactly once."""
    cards = []
    for lbl, s, color in [("S1", S1, LIME), ("S2", S2, CYAN_BRIGHT)]:
        if s is None:
            cards.append(html.Div([
                html.Span("\u25cf", style={"color":INK_MUTE,"marginRight":"6px"}),
                html.Span(f"{lbl} \u00b7 not loaded",
                          style={"color":INK_MUTE,"fontSize":"11px"}),
            ], style={"padding":"7px 10px",
                      "fontFamily":"'JetBrains Mono', monospace"}))
            continue
        src = SESSION_PCAPS.get(lbl)
        src_name = os.path.basename(str(src)) if src else "live recording"
        _ssid  = s.get("wifi_ssid")  or None
        _bssid = s.get("wifi_bssid") or None
        rows = [
            html.Div([
                html.Span("\u25cf", style={"color":color,"marginRight":"6px",
                    "textShadow":f"0 0 8px {color}"}),
                html.Span(lbl, style={"color":INK,"fontWeight":"700"}),
                html.Span(f" \u00b7 {s['n_pkts']:,} pkts",
                          style={"color":INK_MUTE}),
            ], style={"display":"flex","alignItems":"center"}),
            html.Div(src_name, title=str(src or ""), style={
                "color":INK,"fontSize":"10.5px","paddingLeft":"13px",
                "whiteSpace":"nowrap","overflow":"hidden",
                "textOverflow":"ellipsis","marginTop":"2px"}),
            html.Div(f"{s['t0'].strftime('%H:%M')}\u2013{s['t1'].strftime('%H:%M')}",
                style={"color":INK_MUTE,"fontSize":"10.5px",
                       "paddingLeft":"13px","marginTop":"1px"}),
        ]
        if _ssid or _bssid:
            rows.append(html.Div(
                f"SSID {_ssid or 'n/a'} \u00b7 BSSID {_bssid or 'n/a'}",
                style={"color":INK_MUTE,"fontSize":"10px",
                       "paddingLeft":"13px","marginTop":"1px",
                       "whiteSpace":"nowrap","overflow":"hidden",
                       "textOverflow":"ellipsis"}))
        cards.append(html.Div(rows, style={"padding":"7px 10px",
            "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px"}))
    return html.Div(cards, style={"marginBottom":"12px",
        "borderRadius":"10px","background":"rgba(255,255,255,0.02)",
        "border":f"1px solid {GLASS_BORDER}"})


def _github_upload_url():
    """Best-effort: derive the GitHub 'upload files' URL for incoming/ from
    the current fork's `git remote get-url origin`. Falls back to the
    upstream repo if detection fails."""
    import os as _os, subprocess as _sp
    _default = ("https://github.com/orarr2/"
                "NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection"
                "/upload/main/incoming")
    try:
        _here = _os.path.dirname(_os.path.abspath(
            _os.environ.get("NETSEC_APP_DIR") or __file__)) \
                if "__file__" in globals() else _os.getcwd()
    except Exception:
        _here = _os.getcwd()
    try:
        url = _sp.check_output(
            ["git", "-C", _here, "config", "--get", "remote.origin.url"],
            encoding="utf-8", stderr=_sp.DEVNULL, timeout=3).strip()
    except Exception:
        return _default
    if url.startswith("https://github.com/"):
        path = url[len("https://github.com/"):]
    elif url.startswith("git@github.com:"):
        path = url[len("git@github.com:"):]
    else:
        return _default
    if path.endswith(".git"):
        path = path[:-4]
    return f"https://github.com/{path}/upload/main/incoming"


def _render_ai_judge_link(session, session_key):
    """Render the '🦙 Send to AI Judge' link for one session card. Returns
    an html.A that opens the fork's `incoming/` upload page in a new tab
    (Option B - drag-and-drop, no token required). If the session isn't
    loaded, returns an empty Div so nothing shows."""
    import os as _os
    if session is None:
        return html.Div()
    src_pcap = session.get("_source_pcap") or ""
    src_name = _os.path.basename(src_pcap) if src_pcap else ""
    caption = (f"Drag `{src_name}` into the page and click Commit - the "
               f"GitHub Actions judge runs automatically, and a new "
               f"Issue with the verdict and analyst commentary is opened.")
    return html.Div([
        html.A(
            [html.Span("\U0001F999", style={"marginRight":"8px",
                                             "fontSize":"1.05rem"}),
             html.Span(f"Send {session_key.upper()} to AI Judge",
                       style={"fontWeight":"600"})],
            href=_github_upload_url(),
            target="_blank", rel="noopener",
            id={"type":"ai-judge-link","session":session_key},
            style={
                "display":"flex","alignItems":"center","width":"100%",
                "padding":"8px 10px","borderRadius":"10px",
                "background":"rgba(59,130,246,0.10)",
                "border":"1px solid rgba(59,130,246,0.30)",
                "color":CYAN,
                "textDecoration":"none",
                "fontSize":"11.5px",
                "fontFamily":"'Inter Tight', sans-serif",
                "cursor":"pointer",
                "marginTop":"6px",
            }),
        html.Div(caption,
            style={"fontSize":"10px","color":INK_MUTE,"marginTop":"6px",
                   "padding":"0 4px","lineHeight":"1.5",
                   "fontFamily":"'Inter Tight', sans-serif"}),
    ], style={"marginTop":"8px"})


def _render_n8n_send_button(session, session_key):
    """Render the 'Send to VM' block for one session card.

    Uses the HTTP ingest API (spec 5.1): the click signs the PCAP with
    the sensor's HMAC secret, streams it to /v1/pcap on the VM, and the
    worker mails the finished report to whatever address the user typed
    into the email field. n8n is no longer in the path - the VM's own
    worker sends the email directly via SMTP.

    Silent no-op if the session is not loaded, so S2 shows nothing until
    a second capture exists.
    """
    import os as _os
    if session is None:
        return html.Div()
    src_pcap = session.get("_source_pcap") or ""
    src_name = _os.path.basename(src_pcap) if src_pcap else ""
    _host_label = N8N_REMOTE_HOST or "set NETSEC_INGEST_URL"
    caption = (f"Upload `{src_name}` to the VM ({_host_label}) over "
               f"Tailscale. The worker analyzes it end to end and mails "
               f"the finished report (PDF) to the address you enter here. "
               f"Nothing runs on this machine.")
    default_email = _os.environ.get("NETSEC_NOTIFY_EMAIL", "")
    return html.Div([
        html.Div([
            html.Div("Email for the report",
                style={"fontSize":"9.5px","color":INK_MUTE,
                       "letterSpacing":"0.14em","textTransform":"uppercase",
                       "fontWeight":"600","marginBottom":"4px",
                       "fontFamily":"'JetBrains Mono', monospace"}),
            dcc.Input(
                id={"type":"n8n-email","session":session_key},
                type="email",
                value=default_email,
                placeholder="you@example.com",
                debounce=False,
                style={"width":"100%","padding":"6px 8px",
                       "background":"rgba(255,255,255,0.05)",
                       "border":f"1px solid {GLASS_BORDER}",
                       "borderRadius":"8px","color":INK,"fontSize":"11.5px",
                       "fontFamily":"'JetBrains Mono', monospace",
                       "outline":"none"}),
        ], style={"marginBottom":"8px"}),
        html.Button(
            [html.Span("\U0001F4E7", style={"marginRight":"8px",
                                             "fontSize":"1.05rem"}),
             html.Span(f"Send {session_key.upper()} to VM (mail report)",
                       style={"fontWeight":"600"})],
            id={"type":"n8n-send-btn","session":session_key},
            n_clicks=0,
            style={
                "display":"flex","alignItems":"center","width":"100%",
                "padding":"8px 10px","borderRadius":"10px",
                "background":"rgba(34,197,94,0.10)",
                "border":"1px solid rgba(34,197,94,0.30)",
                "color":"#22c55e",
                "fontSize":"11.5px",
                "fontFamily":"'Inter Tight', sans-serif",
                "cursor":"pointer",
                "marginTop":"6px",
                "textAlign":"left",
            }),
        html.Div(caption,
            style={"fontSize":"10px","color":INK_MUTE,"marginTop":"6px",
                   "padding":"0 4px","lineHeight":"1.5",
                   "fontFamily":"'Inter Tight', sans-serif"}),
        html.Div(id={"type":"n8n-send-status","session":session_key},
                 style={"fontSize":"10.5px","marginTop":"6px",
                        "padding":"0 4px","lineHeight":"1.5",
                        "fontFamily":"'Inter Tight', sans-serif"}),
    ], style={"marginTop":"8px"})


def _build_sidebar(active_chart, active_tab="analyze", active_session="s1"):
    """Sidebar with grouped nav items, filtered by the active top-level tab
    AND the active S1/S2 session sub-tab (mirrors the chip strip)."""
    if active_session == "s2" and S2 is None:
        active_session = "s1"

    children = []
    has_s1 = S1 is not None
    has_s2 = S2 is not None
    # gather worker states once for the whole sidebar
    _wsum = _worker_state_summary()

    children.append(_session_info_cards())
    if has_s1:
        # disable both S1 replaces if S1 worker is busy
        _s1_disabled = _wsum["s1_busy"]
        _s1_disabled_reason = _guard_reason("s1_busy", _wsum["s1_state"]) if _s1_disabled else None
        _s1_live_disabled = (not TSHARK_PATH) or _s1_disabled
        _s1_live_reason = (
            _guard_reason("no_tshark", None) if not TSHARK_PATH else
            _s1_disabled_reason if _s1_disabled else None
        )
        children.append(html.Div([
            html.Div("Replace first session",
                style={"fontSize":"9.5px","color":INK_MUTE,"textTransform":"uppercase",
                       "letterSpacing":"0.18em","fontWeight":"600","marginBottom":"8px",
                       "padding":"0 12px",
                       "fontFamily":"'JetBrains Mono', monospace"}),
            dbc.Button("↻  Replace S1 PCAP", id="replace-s1-btn",
                size="sm", n_clicks=0,
                disabled=_s1_disabled,
                className="aur-btn-secondary",
                title=_s1_disabled_reason or "",
                style={"width":"100%","marginBottom":"6px","fontSize":"11.5px",
                       "fontWeight":"500","borderRadius":"10px",
                       "background":"rgba(163,230,53,0.10)" if not _s1_disabled else "rgba(120,120,120,0.06)",
                       "border":f"1px solid rgba(163,230,53,0.30)" if not _s1_disabled else f"1px solid {GLASS_BORDER}",
                       "color":LIME if not _s1_disabled else INK_MUTE,
                       "cursor":"pointer" if not _s1_disabled else "not-allowed",
                       "opacity":"1.0" if not _s1_disabled else "0.55",
                       "fontFamily":"'Inter Tight', sans-serif",
                       "padding":"8px 10px"}),
            dbc.Button("↻  Replace S1 recording", id="replace-s1-live-btn",
                size="sm", n_clicks=0,
                disabled=_s1_live_disabled,
                className="aur-btn-secondary",
                title=_s1_live_reason or "",
                style={"width":"100%","fontSize":"11.5px","fontWeight":"500",
                       "borderRadius":"10px",
                       "background":"rgba(248,113,113,0.08)" if not _s1_live_disabled else "rgba(120,120,120,0.06)",
                       "border":f"1px solid rgba(248,113,113,0.25)" if not _s1_live_disabled else f"1px solid {GLASS_BORDER}",
                       "color":RED_ACCENT if (TSHARK_PATH and not _s1_disabled) else INK_MUTE,
                       "cursor":"pointer" if not _s1_live_disabled else "not-allowed",
                       "opacity":"1.0" if not _s1_live_disabled else "0.55",
                       "fontFamily":"'Inter Tight', sans-serif",
                       "padding":"8px 10px"}),
            html.Div(_s1_disabled_reason,
                     style={"fontSize":"10.5px","color":AMBER,
                            "padding":"6px 4px 0","fontStyle":"italic",
                            "display":"block" if _s1_disabled_reason else "none",
                            "fontFamily":"'Inter Tight', sans-serif"}),
        ], style={"marginBottom":"16px","paddingBottom":"12px",
                  "borderBottom":f"1px solid {GLASS_BORDER}"}))
        children.append(_render_ai_judge_link(S1, "s1"))
        children.append(_render_n8n_send_button(S1, "s1"))

        # Header + button labels swap based on whether S2 is already loaded;
        # this gives the user a path to replace S2 with a fresh PCAP/recording.
        _header_text   = "Replace second session" if has_s2 else "Add a second session"
        _pcap_btn_text = "↻  Replace S2 PCAP"    if has_s2 else "➕  Load second PCAP"
        _live_btn_text = "↻  Replace S2 recording" if has_s2 else "➕  Record second session"
        # disable S2 replace if S2 worker is busy OR has an
        # un-analyzed pending snapshot (that we would otherwise silently lose).
        _s2_disabled = _wsum["s2_busy"] or _wsum["s2_pending"]
        _s2_reason = (
            _guard_reason("s2_busy", _wsum["s2_state"]) if _wsum["s2_busy"] else
            _guard_reason("s2_pending", None) if _wsum["s2_pending"] else None
        )
        _s2_live_disabled = (not TSHARK_PATH) or _s2_disabled
        _s2_live_reason = (
            _guard_reason("no_tshark", None) if not TSHARK_PATH else _s2_reason
        )
        children.append(html.Div([
            html.Div(_header_text,
                style={"fontSize":"9.5px","color":INK_MUTE,"textTransform":"uppercase",
                       "letterSpacing":"0.18em","fontWeight":"600","marginBottom":"8px",
                       "padding":"0 12px",
                       "fontFamily":"'JetBrains Mono', monospace"}),
            dbc.Button(_pcap_btn_text, id="add-second-pcap-btn",
                size="sm", n_clicks=0,
                disabled=_s2_disabled,
                title=_s2_reason or "",
                className="aur-btn-secondary",
                style={"width":"100%","marginBottom":"6px","fontSize":"11.5px",
                       "fontWeight":"500","borderRadius":"10px",
                       "background":"rgba(139,92,246,0.10)" if not _s2_disabled else "rgba(120,120,120,0.06)",
                       "border":f"1px solid rgba(139,92,246,0.3)" if not _s2_disabled else f"1px solid {GLASS_BORDER}",
                       "color":VIOLET_BRIGHT if not _s2_disabled else INK_MUTE,
                       "cursor":"pointer" if not _s2_disabled else "not-allowed",
                       "opacity":"1.0" if not _s2_disabled else "0.55",
                       "fontFamily":"'Inter Tight', sans-serif",
                       "padding":"8px 10px"}),
            dbc.Button(_live_btn_text, id="add-second-live-btn",
                size="sm", n_clicks=0,
                disabled=_s2_live_disabled,
                title=_s2_live_reason or "",
                className="aur-btn-secondary",
                style={"width":"100%","fontSize":"11.5px","fontWeight":"500",
                       "borderRadius":"10px",
                       "background":"rgba(248,113,113,0.08)" if not _s2_live_disabled else "rgba(120,120,120,0.06)",
                       "border":f"1px solid rgba(248,113,113,0.25)" if not _s2_live_disabled else f"1px solid {GLASS_BORDER}",
                       "color":RED_ACCENT if (TSHARK_PATH and not _s2_disabled) else INK_MUTE,
                       "cursor":"pointer" if not _s2_live_disabled else "not-allowed",
                       "opacity":"1.0" if not _s2_live_disabled else "0.55",
                       "fontFamily":"'Inter Tight', sans-serif",
                       "padding":"8px 10px"}),
            html.Div(_s2_reason,
                     style={"fontSize":"10.5px","color":AMBER,
                            "padding":"6px 4px 0","fontStyle":"italic",
                            "display":"block" if _s2_reason else "none",
                            "fontFamily":"'Inter Tight', sans-serif"}),
        ], style={"marginBottom":"16px","paddingBottom":"12px",
                  "borderBottom":f"1px solid {GLASS_BORDER}"}))
        if has_s2:
            children.append(_render_ai_judge_link(S2, "s2"))
            children.append(_render_n8n_send_button(S2, "s2"))

    # Chart navigation moved to build_chart_picker_strip (the horizontal
    # chip row right under the Analyze / Security pills). The sidebar now
    # hosts ONLY S1 / S2 status and the replace / add-session controls;
    # the nav-item loop this used to append here was removed with the
    # chip-strip refactor.
    return children


def _state_badge(state, text=None, id=None):
    """Visual indicator of a LiveCaptureWorker state.
    Optional `id` parameter lets the clientside text-update callback
    target the badge directly via document.getElementById."""
    colors = {
        "idle":      (INK_MUTE,    "rgba(155,148,184,0.10)", "● IDLE"),
        "recording": (LIME,        "rgba(163,230,53,0.14)",  "● RECORDING"),
        "paused":    (AMBER,       "rgba(251,191,36,0.14)",  "❚❚ PAUSED"),
        "saved":     (CYAN_BRIGHT, "rgba(34,211,238,0.14)",  "✓ SAVED"),
        "error":     (RED_ACCENT,  "rgba(248,113,113,0.14)", "✗ ERROR"),
    }
    color, bg, default_text = colors.get(state, (INK_MUTE, "rgba(255,255,255,0.04)", state))
    label = text or default_text
    kwargs = {"style": {
        "display":"inline-block","padding":"3px 10px","borderRadius":"6px",
        "background":bg,"color":color,
        "fontFamily":"'JetBrains Mono', monospace","fontSize":"10px",
        "fontWeight":"700","letterSpacing":"0.1em","border":f"1px solid {color}55",
        "textShadow":f"0 0 6px {color}55" if state in ("recording","saved") else "none"}}
    if id: kwargs["id"] = id
    return html.Span(label, **kwargs)


def _live_metric(label, value, color=INK, value_id=None):
    """Metric card. value_id (optional) sets a stable DOM id on the value
    Div so the clientside refresh can write straight to its textContent
    without rebuilding the surrounding card (zero flicker)."""
    value_kwargs = {"style": {
        "fontFamily":"'Newsreader', Georgia, serif","fontWeight":"500",
        "fontSize":"1.4rem","color":color,"lineHeight":"1.05","letterSpacing":"-0.015em"}}
    if value_id: value_kwargs["id"] = value_id
    return html.Div([
        html.Div(label, style={
            "fontFamily":"'JetBrains Mono', monospace","fontSize":"9.5px",
            "color":INK_MUTE,"letterSpacing":"0.15em","textTransform":"uppercase",
            "marginBottom":"3px","fontWeight":"600"}),
        html.Div(value, **value_kwargs),
    ], style={"padding":"10px 12px","borderRadius":"10px",
              "background":"rgba(255,255,255,0.02)",
              "border":f"1px solid {GLASS_BORDER}"})


def _live_btn(action, session_id, label, color, disabled=False):
    """One control button (Record/Pause/Stop/Reset) in a live-capture panel.
    Any button whose action would start / restart tshark is
    forced-disabled when TSHARK_PATH is missing, so the user gets the same
    grey-out visual on all entry points (sidebar AND per-panel), not only
    the sidebar."""
    if action in ("record", "pause", "stop", "reset") and not TSHARK_PATH:
        disabled = True
    return dbc.Button(label,
        id={"type":"live-btn","action":action,"session":session_id},
        n_clicks=0, disabled=disabled,
        title=("tshark is not installed - live recording is unavailable" if (not TSHARK_PATH) else ""),
        style={"fontFamily":"'Inter Tight', sans-serif","fontSize":"12.5px",
               "fontWeight":"600","borderRadius":"10px","padding":"9px 14px",
               "background":f"rgba({color[0]},{color[1]},{color[2]},0.12)" if not disabled
                             else "rgba(255,255,255,0.03)",
               "border":f"1px solid rgba({color[0]},{color[1]},{color[2]},0.4)" if not disabled
                         else f"1px solid {GLASS_BORDER}",
               "color":f"rgb({color[0]},{color[1]},{color[2]})" if not disabled else INK_MUTE,
               "letterSpacing":"-0.005em","width":"100%"})


def _build_pending_snapshot_block(session_id, worker):
    """the green Recording-saved card with Analyze + Discard.
    Surfaces (a) an in-flight analysis lock so the 3-second interval refresh
    cannot resurrect a clickable Analyze, and (b) an explicit overwrite
    warning when the corresponding global session (S1/S2) is already loaded."""
    is_locked = bool(getattr(worker, "_analyzing", False))
    current_global = S1 if session_id == "S1" else S2
    will_overwrite = current_global is not None
    overwrite_warning = None
    if will_overwrite:
        ov_label = SESSION_PCAPS.get(session_id, "(in-memory session)")
        ov_pkts  = current_global.get("n_pkts", 0)
        overwrite_warning = html.Div([
            html.Span("⚠  ", style={"color":AMBER,"fontWeight":"700",
                                          "fontSize":"14px"}),
            html.Span(f"{session_id} is already loaded with ", style={"color":INK_DIM}),
            html.Span(os.path.basename(str(ov_label)),
                      style={"color":INK,"fontWeight":"600",
                             "fontFamily":"'JetBrains Mono', monospace"}),
            html.Span(f" ({ov_pkts:,} packets). ", style={"color":INK_DIM}),
            html.Span("Clicking Analyze will replace it.",
                      style={"color":AMBER,"fontWeight":"600"}),
        ], style={"fontSize":"11.5px","padding":"8px 12px","marginBottom":"10px",
                  "borderRadius":"8px",
                  "background":"rgba(251,191,36,0.10)",
                  "border":f"1px solid rgba(251,191,36,0.30)",
                  "fontFamily":"'Inter Tight', sans-serif",
                  "lineHeight":"1.45"})
    if is_locked:
        analyze_label   = "⏳ ANALYZING…"
        analyze_disable = True
    else:
        analyze_label   = "▶ Analyze"
        analyze_disable = False
    return html.Div([
        html.Div([
            html.Span("✓ Recording saved · ready to analyse", style={
                "fontFamily":"'JetBrains Mono', monospace",
                "fontSize":"10px","color":LIME,
                "letterSpacing":"0.18em","textTransform":"uppercase",
                "fontWeight":"700","marginBottom":"4px","display":"block"}),
            html.Div([
                html.Span(f"{getattr(worker, '_pending_snapshot', {}).get('n_pkts', 0):,} packets",
                          style={"color":INK,"fontWeight":"500"}),
                html.Span(" captured", style={"color":INK_MUTE}),
            ], style={"fontSize":"12px",
                      "fontFamily":"'JetBrains Mono', monospace",
                      "marginBottom":"10px"}),
        ]),
        overwrite_warning,
        dbc.Row([
            dbc.Col(dbc.Button(
                analyze_label,
                id={"type":"live-btn","action":"analyze","session":session_id},
                n_clicks=0, disabled=analyze_disable, className="aur-btn-primary",
                style={"width":"100%","padding":"10px","fontSize":"12.5px",
                       "fontWeight":"600","borderRadius":"10px","border":"none",
                       "color":"white",
                       "fontFamily":"'Inter Tight', sans-serif"}), width=8),
            dbc.Col(dbc.Button(
                "↺ Discard",
                id={"type":"live-btn","action":"discard","session":session_id},
                n_clicks=0, disabled=is_locked, className="aur-btn-ghost",
                style={"width":"100%","padding":"10px","fontSize":"12.5px",
                       "fontWeight":"500","borderRadius":"10px",
                       "background":"rgba(255,255,255,0.04)",
                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                       "color":INK_DIM,
                       "fontFamily":"'Inter Tight', sans-serif"}), width=4),
        ]),
    ], style={"marginTop":"14px","padding":"14px","borderRadius":"12px",
              "background":"rgba(163,230,53,0.06)",
              "border":f"1px solid {LIME}55",
              "borderLeft":f"3px solid {LIME}"})


def _quick_stats_for(session_id):
    """Read worker.quick_stats() with a sane fallback so the panel helpers
    below never have to defend against missing keys."""
    worker = LIVE_SESSIONS.get(session_id)
    if worker is None:
        return None, None
    try:
        stats = worker.quick_stats()
    except Exception as e:
        stats = {"status":"error","elapsed":0,"n_pkts":0,
                 "error":f"quick_stats failed: {e}",
                 "saved_path":None,"interface":None}
    return worker, stats


def _build_session_live_block(session_id):
    """Header + error box + Packets/Duration/State metric row. This is the
    ONLY portion of a session panel that the 3-second recording tick
    refreshes - no buttons live in here, so swapping it every tick cannot
    tear down the Stop button (which was the root cause of the flicker)."""
    worker, stats = _quick_stats_for(session_id)
    if worker is None:
        return None
    state = stats.get("status", "idle")
    is_recording = state == "recording"
    is_saved     = state == "saved"
    n_pkts   = stats.get("n_pkts", 0) or 0
    duration = stats.get("elapsed", 0) or 0
    saved_to = stats.get("saved_path", None)
    error    = stats.get("error", None)

    if duration < 60:
        dur_str = f"{int(duration)}s"
    elif duration < 3600:
        dur_str = f"{int(duration)//60}m {int(duration)%60}s"
    else:
        dur_str = f"{int(duration)//3600}h {int(duration)%3600//60}m"

    panel_color = LIME if session_id == "S1" else CYAN_BRIGHT
    badge_text = {
        "idle":      "● IDLE",
        "recording": "● RECORDING",
        "paused":    "❚❚ PAUSED",
        "saved":     "✓ SAVED",
        "error":     "✗ ERROR",
    }.get(state, state.upper())

    # FLICKER FIX: every counter / state element gets a stable DOM id.
    # The 3-second tick now writes only to live-stats-store; a clientside
    # callback reads that store and updates textContent of the elements
    # below. The surrounding cards never re-render -> no flicker.
    sid = session_id
    return [
        html.Div([
            html.Div([
                html.Span(sid, style={
                    "fontFamily":"'Newsreader', Georgia, serif","fontSize":"1.7rem",
                    "fontWeight":"500","color":panel_color,"letterSpacing":"-0.02em",
                    "marginRight":"12px"}),
                _state_badge(state, badge_text, id=f"live-state-badge-{sid}"),
            ], style={"display":"flex","alignItems":"center"}),
            html.Div(
                f"saved → {os.path.basename(saved_to)}" if saved_to and is_saved
                else f"chunks of 30s · merged on Stop & Save",
                style={"fontFamily":"'JetBrains Mono', monospace","fontSize":"10.5px",
                       "color":INK_MUTE,"marginTop":"6px"})
        ], style={"marginBottom":"16px"}),

        # Error box always present but hidden when no error; clientside
        # toggles display + writes the message into the inner span.
        html.Div([
            html.Span("✗  ", style={"color":RED_ACCENT,"fontWeight":"700"}),
            html.Span(error or "", id=f"live-error-msg-{sid}"),
        ], id=f"live-error-{sid}", style={
            "color":RED_ACCENT,"padding":"10px 14px","borderRadius":"10px",
            "background":"rgba(248,113,113,0.08)",
            "border":f"1px solid rgba(248,113,113,0.25)",
            "fontFamily":"'JetBrains Mono', monospace","fontSize":"12px",
            "marginBottom":"12px",
            "display":"block" if error else "none"}),

        dbc.Row([
            dbc.Col(_live_metric("Packets",
                f"{n_pkts:,}" if n_pkts else "-",
                color=panel_color if n_pkts else INK_MUTE,
                value_id=f"live-pkts-{sid}"), width=4),
            dbc.Col(_live_metric("Duration",
                dur_str if duration else "-",
                color=INK if duration else INK_MUTE,
                value_id=f"live-duration-{sid}"), width=4),
            dbc.Col(_live_metric("State", badge_text.replace("● ","").replace("❚❚ ","")
                                              .replace("✓ ","").replace("✗ ","")
                                              .title(),
                color=panel_color if is_recording else INK,
                value_id=f"live-state-text-{sid}"), width=4),
        ], style={"marginBottom":"16px"}),
    ]


def _build_session_static_block(session_id):
    """Interface dropdown + Record / Pause / Stop / Reset buttons + pending
    snapshot block. Re-rendered ONLY on a button action - never on a tick -
    so the Stop button DOM is stable while recording."""
    worker, stats = _quick_stats_for(session_id)
    if worker is None:
        return None
    state = stats.get("status", "idle")
    is_recording = state == "recording"
    is_paused    = state == "paused"
    is_saved     = state == "saved"
    is_idle      = state == "idle"

    if_options = [{"label": f"{n}: {name}", "value": n}
                  for n, name in list_capture_interfaces()]
    default_iface = getattr(worker, "interface", None) or pick_default_wifi_interface()

    rec_color   = (163, 230, 53)
    pause_color = (251, 191, 36)
    stop_color  = (248, 113, 113)
    reset_color = (155, 148, 184)

    # block Record / Pause / Stop / Reset while analyzing - clicking
    # any of them during process_session leaves the worker in a bad state.
    _analyzing = bool(getattr(worker, "_analyzing", False))
    # also block Stop when paused-below-min - the worker rejects
    # with "Only Xs recorded. Minimum is 120s" and re-clicking just repeats
    # the same error. Force the user to Resume or Reset first.
    _paused_below_min = (is_paused and stats.get("elapsed", 0) < LiveCaptureWorker.MIN_SECONDS)

    return [
        html.Div([
            html.Div("Network interface", style={
                "fontFamily":"'JetBrains Mono', monospace","fontSize":"9.5px",
                "color":INK_MUTE,"letterSpacing":"0.15em","textTransform":"uppercase",
                "marginBottom":"6px","fontWeight":"600"}),
            dcc.Dropdown(
                id={"type":"live-iface","session":session_id},
                options=if_options,
                value=default_iface,
                clearable=False,
                disabled=is_recording or is_paused,
                style={"background":"rgba(255,255,255,0.04)","color":"#000"},
            ),
        ], style={"marginBottom":"16px"}),

        dbc.Row([
            dbc.Col(_live_btn("record", session_id,
                              "⏵ Resume" if is_paused else "⏺ Record",
                              rec_color, disabled=is_recording or _analyzing), width=6),
            dbc.Col(_live_btn("pause", session_id, "⏸ Pause",
                              pause_color, disabled=(not is_recording) or _analyzing), width=6),
        ], style={"marginBottom":"8px"}),
        dbc.Row([
            dbc.Col(_live_btn("stop", session_id, "⏹ Stop & Save",
                              stop_color, disabled=is_idle or is_saved or _analyzing or _paused_below_min),
                    width=6),
            dbc.Col(_live_btn("reset", session_id, "↺ Reset",
                              reset_color, disabled=is_recording or _analyzing),
                    width=6),
        ]),

        (_build_pending_snapshot_block(session_id, worker)
         if getattr(worker, "_pending_snapshot", None) is not None else None),
    ]


def _build_session_panel(session_id):
    """Live-capture panel. Composed of two sibling sub-divs with stable IDs:
       * {"type":"live-metrics","session":sid} - header + error + counters,
         refreshed by the 3-second recording tick.
       * {"type":"live-static","session":sid}  - dropdown + control buttons
         + pending-snapshot block, rebuilt ONLY on a button click.
    Splitting the DOM means the tick no longer tears down the Stop button,
    fixing the flicker storm that previously made Stop unreachable."""
    worker = LIVE_SESSIONS.get(session_id)
    if worker is None:
        return html.Div(f"Worker for {session_id} not initialised.",
                        style={"color":INK_MUTE,"padding":"14px"})
    return html.Div([
        html.Div(_build_session_live_block(session_id),
                 id={"type":"live-metrics","session":session_id}),
        html.Div(_build_session_static_block(session_id),
                 id={"type":"live-static","session":session_id}),
    ], style={**CARD, "padding":"22px","borderRadius":"18px","height":"100%"})


def _build_live_recording_page():
    """Page shown when the Live Recording nav item is active. Two parallel
    session panels (S1 + S2) with independent record/pause/stop controls."""
    occupied = []
    for sid, sess in [("S1", S1), ("S2", S2)]:
        if sess is not None:
            src_label = SESSION_PCAPS.get(sid, "(in-memory)")
            occupied.append((sid, os.path.basename(str(src_label)), sess.get("n_pkts", 0)))
    overwrite_banner = None
    if occupied:
        chips = []
        for sid, fname, n_pkts in occupied:
            chips.append(html.Span([
                html.Span(sid + " ", style={"color":AMBER,"fontWeight":"700",
                                              "fontFamily":"'JetBrains Mono', monospace"}),
                html.Span(fname,
                          style={"color":INK,"fontFamily":"'JetBrains Mono', monospace"}),
                html.Span(f" ({n_pkts:,} pkts)",
                          style={"color":INK_MUTE}),
            ], style={"marginRight":"14px"}))
        overwrite_banner = html.Div([
            html.Span("⚠  ", style={"color":AMBER,"fontWeight":"700",
                                          "fontSize":"15px","marginRight":"6px"}),
            html.B("Heads-up: ", style={"color":AMBER}),
            "Pressing Analyze on a panel below will REPLACE that session. ",
            "Currently loaded: ",
            html.Span(chips, style={"marginLeft":"6px"}),
        ], style={"background":"rgba(251,191,36,0.10)",
                  "border":f"1px solid rgba(251,191,36,0.30)",
                  "borderRadius":"12px","padding":"12px 16px","marginBottom":"14px",
                  "fontSize":"0.88rem","color":INK_DIM,
                  "fontFamily":"'Inter Tight', sans-serif","lineHeight":"1.5"})
    intro = html.Div([
        overwrite_banner,
        _p("Record live traffic from a network interface. tshark writes 30-second "
           "chunks to disk and the dashboard processes them as they appear. "
           "Press Stop & Save when done - chunks are merged with mergecap into "
           "a single PCAP and the session is analysed automatically."),
        html.Div([
            html.Span("Save directory: ", style={"color":INK_MUTE,"fontSize":"11px",
                "fontFamily":"'JetBrains Mono', monospace","letterSpacing":"0.06em"}),
            html.Span(
                LIVE_SESSIONS["S1"].save_dir if "S1" in LIVE_SESSIONS else "./netsec_sessions",
                style={"color":INK,"fontSize":"11px",
                "fontFamily":"'JetBrains Mono', monospace"}),
        ], style={"padding":"8px 12px","borderRadius":"8px",
                  "background":"rgba(255,255,255,0.03)",
                  "border":f"1px solid {GLASS_BORDER}",
                  "display":"inline-block","marginBottom":"4px"}),
        # Switch-session CTA so the user can leave Live Recording for the
        # choice view (Load PCAP / Record Live) WITHOUT pressing Restart or
        # doing a kernel restart. S1/S2 globals stay intact.
        html.Div(dbc.Button(["\u2190 ", html.Span("Switch session",
                                                    style={"marginLeft":"4px"})],
            id="switch-session-btn", n_clicks=0, className="aur-btn-ghost",
            style={"fontSize":"11.5px","fontWeight":"500","borderRadius":"10px",
                   "background":"rgba(255,255,255,0.04)",
                   "border":f"1px solid {GLASS_BORDER_STRONG}",
                   "color":INK_DIM,"padding":"7px 14px",
                   "fontFamily":"'Inter Tight', sans-serif",
                   "marginLeft":"10px"}),
            style={"display":"inline-block"}),
    ], style={"marginBottom":"18px"})

    panels = dbc.Row([
        dbc.Col(html.Div(_build_session_panel("S1"),
                         id={"type":"live-panel","session":"S1"}), md=6),
        dbc.Col(html.Div(_build_session_panel("S2"),
                         id={"type":"live-panel","session":"S2"}), md=6),
    ])

    edu = _build_edu_panel("live")
    return html.Div([intro, panels, edu])


ML_MIN_PACKETS = 10_000
ML_CHART_IDS   = {"burst","burst_s1","lstm","lstm_s1","profile","zbar",
                  "confusion","sensitivity"}
COMPARE_CHART_IDS = {"cmp_traffic","cmp_new_gone","cmp_delta"}


def _ml_banner_for(session_obj, label):
    if session_obj is None or session_obj.get("n_pkts",0) >= ML_MIN_PACKETS:
        return None
    return html.Div([
        html.Span("⏳  ", style={"fontSize":"15px","marginRight":"4px"}),
        html.B("ML waiting for more data. "),
        f"{label} has only {session_obj['n_pkts']:,} packets - "
        f"ML methods need ≥ {ML_MIN_PACKETS:,} for reliable detection. "
        "Charts below still show patterns but anomaly scoring is not trustworthy yet.",
    ], style={"background":"rgba(251,191,36,0.10)",
              "border":f"1px solid rgba(251,191,36,0.3)",
              "borderRadius":"12px","padding":"12px 16px","marginBottom":"14px",
              "fontSize":"0.86rem","color":AMBER,
              "fontFamily":"'Inter Tight', sans-serif"})


def _needs_s2_banner():
    if S2 is not None and S2.get("n_pkts",0) > 0:
        return None
    return html.Div([
        html.Span("⏸  ", style={"fontSize":"15px","marginRight":"4px"}),
        html.B("Waiting for Session 2. "),
        "This view requires a second session. Use the sidebar to load another PCAP ",
        "or record one live - the comparison will populate automatically."
    ], style={"background":"rgba(34,211,238,0.08)",
              "border":f"1px solid rgba(34,211,238,0.25)",
              "borderRadius":"12px","padding":"12px 16px","marginBottom":"14px",
              "fontSize":"0.86rem","color":CYAN_BRIGHT,
              "fontFamily":"'Inter Tight', sans-serif"})


def _s2_loaded():
    """True iff S2 is loaded - used to decide between single and dual panel."""
    return S2 is not None


def _render_insights():
    """Aurora-styled insight cards in a grid. NOT italic."""
    if not INSIGHTS_LINES:
        return html.P("No insights yet - load a session to populate.",
            style={"color":INK_MUTE,
                   "fontFamily":"'Newsreader', Georgia, serif",
                   "fontSize":"1rem","textAlign":"center","padding":"40px"})
    return dbc.Row([
        dbc.Col(html.Div([
            html.Div(
                ["i","ii","iii","iv","v","vi","vii","viii","ix","x","xi","xii"][i%12],
                style={"width":"36px","height":"36px","flexShrink":"0",
                       "borderRadius":"10px",
                       "background":f"linear-gradient(135deg, rgba(139,92,246,0.2), rgba(34,211,238,0.15))",
                       "border":f"1px solid rgba(139,92,246,0.25)",
                       "display":"flex","alignItems":"center","justifyContent":"center",
                       "fontFamily":"'Newsreader', Georgia, serif",
                       "fontSize":"16px","color":VIOLET_BRIGHT,"fontWeight":"500"}),
            html.Div(line, style={"fontSize":"13.5px","color":INK_DIM,"lineHeight":"1.55"}),
        ], style={"display":"flex","gap":"14px","alignItems":"start",
                  **CARD, "borderRadius":"14px","padding":"16px","height":"100%"}),
            md=6, style={"marginBottom":"14px"})
        for i, line in enumerate(INSIGHTS_LINES)
    ])


def _render_model_diagnostics():
    """Live, per-session hyperparameters + scores for the three anomaly models.
    Every value is chosen dynamically at load time (IsolationForest contamination
    sweep, DBSCAN eps via k-distance elbow, LSTM threshold = val_mean + 2*val_std),
    so it changes with each capture. Reads values stashed on the session dicts."""
    def _fmt(v, nd=2):
        if v is None: return "n/a"
        if isinstance(v, (int, float)): return f"{v:.{nd}f}"
        return str(v)
    cards = []
    for lbl, s, accent in [("S1", S1, LIME), ("S2", S2, CYAN_BRIGHT)]:
        if s is None:
            continue
        ia     = s.get("ip_agg")
        n_ips  = int(len(ia)) if ia is not None else 0
        n_anom = int(ia["anomaly"].sum()) if (ia is not None and "anomaly" in ia) else 0
        thr, errs = s.get("lstm_threshold"), s.get("lstm_errors")
        if errs is not None and thr is not None:
            try: n_seq, n_lstm = int(len(errs)), int((errs > thr).sum())
            except Exception: n_seq = n_lstm = None
        else:
            n_seq = n_lstm = None

        def _row(model, body):
            return html.Div([
                html.Div(model, style={"fontFamily":"'JetBrains Mono', monospace",
                    "fontSize":"11px","letterSpacing":"0.12em","textTransform":"uppercase",
                    "color":accent,"fontWeight":"700","marginBottom":"3px"}),
                html.Div(body, style={"fontFamily":"'JetBrains Mono', monospace",
                    "fontSize":"12.5px","color":INK_DIM,"lineHeight":"1.65"}),
            ], style={"marginBottom":"12px"})

        cards.append(dbc.Col(html.Div([
            html.Div(f"{lbl} - model diagnostics", style={
                "fontFamily":"'Newsreader', Georgia, serif","fontSize":"1.15rem",
                "color":INK,"fontWeight":"500","marginBottom":"14px"}),
            _row("IsolationForest",
                 f"contamination = {_fmt(s.get('_chosen_contamination'))}  -  "
                 f"anomalies = {n_anom} / {n_ips}"),
            _row("DBSCAN",
                 f"eps = {_fmt(s.get('_eps_auto'))} (k-distance elbow)  -  "
                 f"min_samples = {s.get('_min_samples', 2)}  -  "
                 f"clusters = {s.get('_n_clusters', 'n/a')}  -  "
                 f"noise = {s.get('_n_noise', 'n/a')}  -  "
                 f"silhouette = {_fmt(s.get('_silhouette'), 3)}"),
            _row("LSTM",
                 (f"threshold = {_fmt(thr, 5)} (val_mean + 2*val_std)  -  "
                  f"flagged = {n_lstm} / {n_seq}") if thr is not None
                 else "not trained for this session"),
        ], style={**CARD, "borderRadius":"14px","padding":"18px 20px","height":"100%",
                  "borderLeft":f"3px solid {accent}"}),
            md=6, style={"marginBottom":"14px"}))

    if not cards:
        return html.Div()
    return html.Div([
        html.Div("Model Diagnostics  -  dynamic, recomputed per capture", style={
            "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
            "letterSpacing":"0.2em","textTransform":"uppercase","color":VIOLET_BRIGHT,
            "fontWeight":"700","margin":"28px 0 12px"}),
        dbc.Row(cards),
    ])



# ---- Advanced-threat render helpers ----
ADV_SEVERITY_COLOR = {"high": "#f87171", "medium": "#fbbf24", "low": "#60a5fa"}

def _adv_findings_for(engine_key, session_label):
    """Pull the list-of-dicts for the given engine from S1 / S2 threats."""
    sess = {"S1": S1, "S2": S2}.get(session_label)
    if sess is None: return None, "not_loaded"
    threats = sess.get("threats") or {}
    if not threats.get("available", False):
        return None, threats.get("reason", "n/a")
    per = threats.get("per_engine") or {}
    return per.get(engine_key, []), None

def _adv_signals_table(rows):
    """Build a Dash DataTable from a list of signal dicts."""
    if not rows:
        return html.Div("No findings.",
            style={"color":INK_MUTE,"fontSize":"0.92rem","padding":"24px",
                   "textAlign":"center"})
    cols = [
        {"name":"Device",    "id":"device"},
        {"name":"Peer",      "id":"peer"},
        {"name":"Signal",    "id":"signal"},
        {"name":"Score",     "id":"score",    "type":"numeric",
         "format":dash.dash_table.FormatTemplate.percentage(0)},
        {"name":"Severity",  "id":"severity"},
        {"name":"Count",     "id":"count",    "type":"numeric"},
        {"name":"Technique", "id":"technique"},
        {"name":"Detail",    "id":"detail"},
    ]
    return dash.dash_table.DataTable(
        columns=cols,
        data=[{k: r.get(k) for k in ("device","peer","signal","score","severity",
                                       "count","technique","detail")} for r in rows],
        page_size=15, sort_action="native", filter_action="native",
        style_cell={"fontFamily":"'JetBrains Mono', monospace","fontSize":"11.5px",
                    "backgroundColor":"rgba(255,255,255,0.02)","color":INK,
                    "padding":"8px","whiteSpace":"normal","height":"auto",
                    "maxWidth":"360px","border":f"1px solid {GLASS_BORDER}"},
        style_header={"backgroundColor":"rgba(139,92,246,0.15)","fontWeight":"600",
                      "color":INK,"border":f"1px solid {GLASS_BORDER_STRONG}"},
        style_data_conditional=[
            {"if":{"filter_query":'{severity} = "high"',   "column_id":"severity"},
             "backgroundColor":"rgba(248,113,113,0.18)","color":"#f87171","fontWeight":"600"},
            {"if":{"filter_query":'{severity} = "medium"',"column_id":"severity"},
             "backgroundColor":"rgba(251,191,36,0.15)","color":"#fbbf24","fontWeight":"600"},
            {"if":{"filter_query":'{severity} = "low"',   "column_id":"severity"},
             "backgroundColor":"rgba(96,165,250,0.12)","color":"#60a5fa","fontWeight":"600"},
        ],
    )

def _adv_engine_card(engine_key, session_label, accent, md=6):
    rows, err = _adv_findings_for(engine_key, session_label)
    title = f"{session_label}"
    header = html.Div(title, style={"color":accent,"fontWeight":"700",
        "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
        "letterSpacing":"0.18em","textTransform":"uppercase","marginBottom":"10px"})
    if rows is None:
        body = html.Div(
            "Session not loaded." if err == "not_loaded" else f"Threat scan unavailable: {err}",
            style={"color":INK_MUTE,"fontSize":"0.92rem","padding":"24px","textAlign":"center"})
    else:
        n = len(rows)
        summary = html.Div([
            html.Span(f"{n}", style={"fontSize":"2rem","fontWeight":"700","color":accent}),
            html.Span(" finding" + ("s" if n != 1 else ""),
                style={"color":INK_DIM,"fontSize":"0.95rem","marginLeft":"6px"}),
        ], style={"marginBottom":"12px"})
        body = html.Div([summary, _adv_signals_table(rows)])
    return dbc.Col(html.Div([header, body],
        style={**CARD,"borderRadius":"14px","padding":"18px",
               "borderLeft":f"3px solid {accent}","height":"100%"}), md=md)

def _render_adv_engine(engine_key, display_name, description, sessions=("S1", "S2")):
    """Render one of the 5 engine views (beaconing / dns_tunnel / dga /
    arp_dhcp / tls). The S1 / S2 sub-tabs pass a single session, which
    renders one full-width card."""
    _accent = {"S1": LIME, "S2": CYAN_BRIGHT}
    _md = 12 if len(sessions) == 1 else 6
    return html.Div([
        html.Div(description, style={"color":INK_DIM,"fontSize":"0.92rem",
            "lineHeight":"1.55","marginBottom":"18px"}),
        dbc.Row([_adv_engine_card(engine_key, s, _accent[s], md=_md)
                 for s in sessions]),
    ])

def _render_adv_killchain(sessions=("S1", "S2")):
    """Per-device kill-chain risk from fusing the 5 engines + multi-technique boost."""
    intro = html.Div(
        "Each device's signals are fused inside a 15-minute window. The risk score "
        "is the device's max single-signal score multiplied by a kill-chain boost "
        "(+0.5 per additional distinct ATT&CK technique seen in the same window). "
        "Devices touching multiple stages of the kill chain rank highest.",
        style={"color":INK_DIM,"fontSize":"0.92rem","lineHeight":"1.55",
               "marginBottom":"18px"})
    cols = []
    _kc_md = 12 if len(sessions) == 1 else 6
    for label, sess, accent in [("S1", S1, LIME), ("S2", S2, CYAN_BRIGHT)]:
        if label not in sessions:
            continue
        if sess is None:
            cols.append(dbc.Col(html.Div([
                html.Div(label, style={"color":accent,"fontWeight":"700",
                    "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
                    "letterSpacing":"0.18em","textTransform":"uppercase","marginBottom":"10px"}),
                html.Div("Session not loaded.",
                    style={"color":INK_MUTE,"fontSize":"0.92rem",
                           "padding":"24px","textAlign":"center"}),
            ], style={**CARD,"borderRadius":"14px","padding":"18px",
                      "borderLeft":f"3px solid {accent}"}), md=_kc_md))
            continue
        threats = sess.get("threats") or {}
        if not threats.get("available", False):
            cols.append(dbc.Col(html.Div([
                html.Div(label, style={"color":accent,"fontWeight":"700",
                    "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
                    "letterSpacing":"0.18em","textTransform":"uppercase","marginBottom":"10px"}),
                html.Div(f"Threat scan unavailable: {threats.get('reason','n/a')}",
                    style={"color":INK_MUTE,"fontSize":"0.92rem","padding":"24px","textAlign":"center"}),
            ], style={**CARD,"borderRadius":"14px","padding":"18px",
                      "borderLeft":f"3px solid {accent}"}), md=_kc_md))
            continue
        risk_rows = threats.get("device_risk") or []
        n_dev = len(risk_rows)
        n_sig = len(threats.get("all_signals") or [])
        header = html.Div([
            html.Div(label, style={"color":accent,"fontWeight":"700",
                "fontFamily":"'JetBrains Mono', monospace","fontSize":"11px",
                "letterSpacing":"0.18em","textTransform":"uppercase","marginBottom":"10px"}),
            html.Div([
                html.Span(f"{n_sig}", style={"fontSize":"1.7rem","fontWeight":"700","color":accent}),
                html.Span(" signals across ", style={"color":INK_DIM,"fontSize":"0.92rem","marginLeft":"4px"}),
                html.Span(f"{n_dev}", style={"fontSize":"1.7rem","fontWeight":"700","color":accent,"marginLeft":"4px"}),
                html.Span(" devices", style={"color":INK_DIM,"fontSize":"0.92rem","marginLeft":"4px"}),
            ], style={"marginBottom":"14px"}),
        ])
        if not risk_rows:
            body = html.Div("No threats detected in this session.",
                style={"color":INK_MUTE,"fontSize":"0.92rem","padding":"24px","textAlign":"center"})
        else:
            top = sorted(risk_rows, key=lambda r: r.get("risk", 0), reverse=True)[:20]
            # bar chart of top devices by risk
            import plotly.graph_objects as _go
            fig = _go.Figure(data=_go.Bar(
                x=[r["risk"] for r in reversed(top)],
                y=[str(r["device"])[:42] for r in reversed(top)],
                orientation="h",
                marker_color=accent,
                text=[f'{r["risk"]:.2f}' for r in reversed(top)],
                textposition="outside",
                hovertemplate="device: %{y}<br>risk: %{x:.2f}<br>techniques: %{customdata}<extra></extra>",
                customdata=[r.get("techniques","") for r in reversed(top)],
            ))
            fig.update_layout(
                title=dict(text=f"Top devices by kill-chain risk - {label}",
                           x=0.5, xanchor="center", y=0.97, yanchor="top"),
                xaxis_title="risk (0-1)", yaxis_title=None,
                height=max(280, len(top)*26 + 100),
                plot_bgcolor=WHITE, paper_bgcolor=WHITE,
                margin=dict(l=40, r=80, t=70, b=50),
            )
            table = dash.dash_table.DataTable(
                columns=[
                    {"name":"Device",         "id":"device"},
                    {"name":"Risk",           "id":"risk",
                     "type":"numeric", "format":dash.dash_table.FormatTemplate.percentage(0)},
                    {"name":"# signals",      "id":"signals",       "type":"numeric"},
                    {"name":"# signal types", "id":"signal_types",  "type":"numeric"},
                    {"name":"Max single",     "id":"max_score",     "type":"numeric"},
                    {"name":"K-C boost",      "id":"kill_chain_boost", "type":"numeric"},
                    {"name":"Techniques",     "id":"techniques"},
                ],
                data=top,
                page_size=20, sort_action="native",
                style_cell={"fontFamily":"'JetBrains Mono', monospace","fontSize":"11.5px",
                            "backgroundColor":"rgba(255,255,255,0.02)","color":INK,
                            "padding":"8px","whiteSpace":"normal","height":"auto",
                            "border":f"1px solid {GLASS_BORDER}"},
                style_header={"backgroundColor":"rgba(139,92,246,0.15)","fontWeight":"600",
                              "color":INK,"border":f"1px solid {GLASS_BORDER_STRONG}"},
            )
            body = html.Div([
                dcc.Graph(figure=fig, config={"displayModeBar": False}),
                html.Div(table, style={"marginTop":"16px"}),
            ])
        cols.append(dbc.Col(html.Div([header, body],
            style={**CARD,"borderRadius":"14px","padding":"18px",
                   "borderLeft":f"3px solid {accent}"}), md=_kc_md))
    return html.Div([intro, dbc.Row(cols)])


AURORA_INDEX_STRING = '''
<!DOCTYPE html>
<html>
<head>
{%metas%}
<title>{%title%}</title>
{%favicon%}
{%css%}
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Newsreader:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500;1,600&family=JetBrains+Mono:wght@400;500;600&family=Inter+Tight:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg-base:#07050f;
  --ink:#e8e4f5;
  --ink-dim:#9b94b8;
  --ink-mute:#5a536f;
  --violet:#8b5cf6;
  --violet-bright:#a78bfa;
  --cyan:#22d3ee;
  --cyan-bright:#67e8f9;
  --magenta:#f472b6;
  --lime:#a3e635;
  --amber:#fbbf24;
  --red:#f87171;
  --glass-bg:rgba(255,255,255,0.04);
  --glass-bg-strong:rgba(255,255,255,0.07);
  --glass-border:rgba(255,255,255,0.08);
  --glass-border-strong:rgba(255,255,255,0.14);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
input.form-control{color:var(--ink)!important}
input.form-control::placeholder{color:#b8b2d4!important;opacity:1!important}
#pcap-path-input,#second-pcap-path-input{color:var(--ink)!important;font-weight:500;background:rgba(255,255,255,0.06)!important}
#pcap-path-input::placeholder,#second-pcap-path-input::placeholder{color:#b8b2d4!important;opacity:1!important}
html,body{
  margin:0;padding:0;
  background:var(--bg-base);
  color:var(--ink);
  font-family:'Inter Tight',system-ui,sans-serif;
  font-size:13.5px;line-height:1.5;
  -webkit-font-smoothing:antialiased;
  letter-spacing:-0.005em;
}
body{
  min-height:100vh;
  background:
    radial-gradient(ellipse 1200px 800px at 12% 8%, rgba(139,92,246,0.18) 0%, transparent 50%),
    radial-gradient(ellipse 900px 600px at 88% 22%, rgba(34,211,238,0.14) 0%, transparent 55%),
    radial-gradient(ellipse 700px 500px at 60% 95%, rgba(244,114,182,0.10) 0%, transparent 50%),
    radial-gradient(ellipse 500px 400px at 5% 80%, rgba(163,230,53,0.06) 0%, transparent 50%),
    var(--bg-base);
  background-attachment:fixed;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:1;opacity:0.7;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160' viewBox='0 0 160 160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2'/%3E%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0.04 0'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)'/%3E%3C/svg%3E");
}
h1,h2,h3,h4,h5,h6{
  font-family:'Newsreader',Georgia,serif;
  font-weight:500;letter-spacing:-0.01em;color:var(--ink);
  font-style:normal;
}
em,i{font-style:normal}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}
::-webkit-scrollbar-track{background:transparent}
.aur-nav{transition:all .2s cubic-bezier(.4,0,.2,1)}
.aur-nav:hover{background:var(--glass-bg)!important;color:var(--ink)!important}
.aur-nav-active::before{
  content:"";position:absolute;left:-1px;top:8px;bottom:8px;width:3px;
  background:linear-gradient(180deg,var(--violet-bright),var(--cyan-bright));
  border-radius:0 3px 3px 0;
}
.aur-btn-primary{
  background:linear-gradient(135deg,var(--violet),var(--cyan))!important;
  border:none!important;
  box-shadow:0 4px 20px -4px rgba(139,92,246,0.4);
  transition:all .2s;
}
.aur-btn-primary:hover:not(:disabled){
  transform:translateY(-1px);
  box-shadow:0 8px 30px -4px rgba(139,92,246,0.6);
}
.aur-btn-primary:disabled{
  opacity:0.4;cursor:not-allowed;
  background:var(--glass-bg-strong)!important;
}
.aur-btn-danger{
  background:linear-gradient(135deg,var(--red),var(--magenta))!important;
  border:none!important;
  box-shadow:0 4px 20px -4px rgba(248,113,113,0.4);
  transition:all .2s;
}
.aur-btn-danger:hover:not(:disabled){
  transform:translateY(-1px);
  box-shadow:0 8px 30px -4px rgba(248,113,113,0.6);
}
.aur-btn-ghost{
  transition:all .2s;
}
.aur-btn-ghost:hover{
  color:var(--violet-bright)!important;
  border-color:rgba(139,92,246,0.4)!important;
  box-shadow:0 0 20px rgba(139,92,246,0.2);
}
.aur-btn-secondary{transition:all .2s}
.aur-btn-secondary:hover:not(:disabled){
  background:rgba(139,92,246,0.18)!important;
  border-color:rgba(139,92,246,0.5)!important;
}
.js-plotly-plot,.plotly{background:transparent!important}
.js-plotly-plot .main-svg{background:transparent!important}
.js-plotly-plot .bg{fill:transparent!important}
.modebar{background:transparent!important}
.modebar-btn path{fill:rgba(255,255,255,0.4)!important}
.modebar-btn:hover path{fill:rgba(255,255,255,0.9)!important}
input[type=checkbox]{accent-color:var(--violet-bright)}
.form-check-input:checked{
  background-color:var(--violet)!important;
  border-color:var(--violet-bright)!important;
}
#_dash-app-content{position:relative;z-index:2}
@keyframes netsec-blink{0%,50%{opacity:1}51%,100%{opacity:0}}@keyframes auroraPulse{0%,100%{opacity:1}50%{opacity:0.5}}
.aur-pulse{animation:auroraPulse 1.6s ease-in-out infinite}
.Select-control,.Select-menu-outer,.is-open .Select-control,
.Select.is-focused>.Select-control{
  background-color:rgba(255,255,255,0.06)!important;
  border-color:var(--glass-border-strong)!important;
  color:var(--ink)!important;
  border-radius:10px!important;
}
.Select-value-label,.Select-placeholder{color:var(--ink)!important}
.Select-arrow{border-color:var(--ink-dim) transparent transparent!important}
.VirtualizedSelectOption{background:rgba(13,10,26,0.95)!important;color:var(--ink)!important}
.VirtualizedSelectFocusedOption{background:rgba(139,92,246,0.2)!important;color:var(--ink)!important}
</style>
</head>
<body>
{%app_entry%}
<footer>
{%config%}
{%scripts%}
{%renderer%}
</footer>
</body>
</html>
'''


app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP],
                suppress_callback_exceptions=True)
app.title = "NetSec Dashboard"
app.index_string = AURORA_INDEX_STRING

def _build_second_pcap_modal():
    """Modal for loading a second PCAP (S2) from the dashboard sidebar.
    Contains the same drag-drop + path input UI as the choice view, but
    stages directly into S2 and closes itself on success."""
    return dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle("Load second PCAP into S2",
                style={"color":INK,
                       "fontFamily":"'Newsreader', Georgia, serif",
                       "fontSize":"1.4rem","fontWeight":"500"}),
            close_button=True,
            style={"borderBottom":f"1px solid {GLASS_BORDER_STRONG}",
                   "background":"rgba(13,10,26,0.6)"}),
        dbc.ModalBody([
            html.P("Drag a PCAP file or paste a full path. The file will be "
                   "loaded into the second session slot (S2) - your existing "
                   "S1 stays loaded.",
                style={"color":INK_DIM,"fontSize":"0.9rem","marginBottom":"18px"}),

            dcc.Upload(
                id="second-pcap-upload",
                children=html.Div([
                    html.Div("⬇", style={"fontSize":"1.8rem","opacity":"0.65",
                                          "marginBottom":"2px"}),
                    html.Div([html.Strong("Drag and drop", style={"color":INK}),
                              " a .pcap / .pcapng here"],
                              style={"fontSize":"0.9rem","color":INK_DIM}),
                    html.Div("- or click to browse -",
                            style={"fontSize":"0.78rem","color":INK_MUTE,
                                   "marginTop":"4px"}),
                    html.Div(f"Max {MAX_UPLOAD_HUMAN} via drag-and-drop",
                            style={"fontSize":"0.72rem","color":INK_MUTE,
                                   "marginTop":"6px",
                                   "fontFamily":"'JetBrains Mono', monospace"}),
                ], style={"textAlign":"center","padding":"18px 12px"}),
                multiple=False,
                accept=".pcap,.pcapng,.cap",
                style={"borderRadius":"12px",
                    "border":f"2px dashed {GLASS_BORDER_STRONG}",
                    "background":"rgba(34,211,238,0.04)",
                    "cursor":"pointer"},
                style_active={"border":f"2px dashed {CYAN_BRIGHT}",
                    "background":"rgba(34,211,238,0.12)"},
            ),

            html.Div(style={"height":"12px"}),
            html.Div("OR paste a full path (no size limit)", style={
                "fontSize":"10px","color":INK_MUTE,
                "fontFamily":"'JetBrains Mono', monospace",
                "letterSpacing":"0.18em","textTransform":"uppercase",
                "fontWeight":"600","marginBottom":"6px"}),
            # --- Stage 1 (upload UI) shown when nothing is staged ---
            # Mirrors the S1 welcome screen: small inline "Load" button next
            # to the input. The BIG gradient "Analyze S2" button only appears
            # AFTER a file is staged (Stage 2), exactly like the S1 staged card.
            html.Div(id="second-pcap-stage1", children=[
                dbc.InputGroup([
                    dbc.Input(id="second-pcap-path-input", type="text",
                        placeholder=r"e.g. C:\Users\you\Downloads\capture2.pcapng",
                        debounce=False, n_submit=0,
                        style={"background":"rgba(255,255,255,0.04)",
                                "color":INK,
                                "border":f"1px solid {GLASS_BORDER_STRONG}",
                                "fontFamily":"'JetBrains Mono', monospace",
                                "fontSize":"13px","padding":"11px 14px",
                                "borderRadius":"10px 0 0 10px"}),
                    dbc.Button("Load", id="second-pcap-path-btn", n_clicks=0,
                        style={"background":f"linear-gradient(135deg, {VIOLET}, {CYAN})",
                                "border":"none","color":"white",
                                "fontWeight":"600","fontSize":"13px",
                                "padding":"0 22px","borderRadius":"0 10px 10px 0"}),
                ]),
                html.Div("Tip: paste a full PCAP path or drag the file into the box above, "
                         "then press Load (or Enter). You will see a confirmation "
                         "card with an ANALYZE S2 button before any analysis runs.",
                    style={"color":INK_MUTE,"fontSize":"0.82rem","marginTop":"10px",
                           "fontFamily":"'Inter Tight', sans-serif",
                           "lineHeight":"1.5"}),
            ]),
            # --- Stage 2 (staged card with Analyze + Clear) shown when staged ---
            html.Div(id="second-pcap-stage2", children=None,
                style={"display":"none"}),

            html.Div(id="second-load-status",
                style={"marginTop":"14px","fontSize":"0.85rem","color":INK_DIM,
                       "minHeight":"24px",
                       "fontFamily":"'JetBrains Mono', monospace"}),
            _build_edu_panel("modal"),
        ], style={"background":"rgba(13,10,26,0.55)","color":INK}),
        dbc.ModalFooter(
            dbc.Button("Cancel", id="second-pcap-cancel-btn", n_clicks=0,
                className="aur-btn-ghost",
                style={"fontSize":"12.5px","fontWeight":"500",
                       "borderRadius":"10px",
                       "background":"rgba(255,255,255,0.04)",
                       "border":f"1px solid {GLASS_BORDER_STRONG}",
                       "color":INK_DIM}),
            style={"borderTop":f"1px solid {GLASS_BORDER_STRONG}",
                   "background":"rgba(13,10,26,0.6)"}),
    ], id="second-pcap-modal", is_open=False, size="lg", centered=True,
       backdrop=True, scrollable=True,
       style={"--bs-modal-bg":"rgba(13,10,26,0.92)"})


# register an atexit handler that terminates any running tshark
# subprocess when the kernel shuts down. Prevents orphaned processes when the
# user closes Jupyter without hitting Restart first.
import atexit as _atexit
def _cleanup_all_workers_on_exit():
    try:
        for _sid, _w in (LIVE_SESSIONS or {}).items():
            try:
                if _w is None: continue
                _p = getattr(_w, "_proc", None)
                if _p is not None:
                    try: _p.terminate()
                    except Exception: pass
                    try: _p.wait(timeout=3)
                    except Exception:
                        try: _p.kill()
                        except Exception: pass
                _t = getattr(_w, "_auto_stop_timer", None)
                if _t is not None:
                    try: _t.cancel()
                    except Exception: pass
                print(f"[atexit] cleaned up {_sid} worker", flush=True)
            except Exception: pass
    except Exception: pass
_atexit.register(_cleanup_all_workers_on_exit)


app.layout = html.Div([
    dcc.Store(id="app-mode",     data="intro"),
    dcc.Store(id="active-chart", data="talkers_s1"),
    dcc.Store(id="active-session", data="s1"),
    dcc.Store(id="active-tab",   data="analyze"),
    dcc.Store(id="trigger-rebuild", data=0),
    dcc.Store(id="staged-pcap",    data=None),
    dcc.Store(id="staged-second-pcap", data=None),
    dcc.Store(id="s2-loaded-tick", data=0),
    dcc.Store(id="live-rec-tick",  data=0),
    # FLICKER FIX: tick now writes stats here; clientside reads + updates DOM textContent
    dcc.Store(id="live-stats-store", data={}),
    html.Div(id="live-stats-bridge", style={"display":"none"}),
    dcc.Store(id="scroll-helper", data=0),
    dcc.Store(id="last-chart-per-tab", data={"analyze":"talkers_s1","security":"syn"}),
    dcc.Store(id="replacing-s1", data=False),
    dcc.Interval(id="live-recording-tick", interval=3000, disabled=False, n_intervals=0),
    html.Div(id="main-container"),
    _build_second_pcap_modal(),
    dbc.Toast(
        id="s2-loaded-toast",
        header="Session 2 loaded",
        is_open=False,
        dismissable=True,
        duration=6000,
        icon="success",
        style={"position":"fixed","top":"24px","right":"24px","zIndex":"10000",
               "minWidth":"360px",
               "background":"rgba(13,10,26,0.92)",
               "color":INK,
               "border":f"1px solid {LIME}66",
               "boxShadow":"0 12px 40px rgba(0,0,0,0.6)",
               "fontFamily":"'Inter Tight', sans-serif"},
        children=[
            html.Div("S2 is now available - the comparison views in the sidebar "
                     "have unlocked. Click any item starting with “Compare …” to see "
                     "S1 vs S2 side-by-side.",
                     style={"fontSize":"0.9rem","lineHeight":"1.55","color":INK_DIM}),
        ]),
])


@app.callback(Output("main-container","children"),
              Input("app-mode","data"),
              Input("trigger-rebuild","data"),
              Input("staged-pcap","data"),
              State("active-chart","data"),
              State("active-tab","data"),
              State("active-session","data"),
              State("replacing-s1","data"))
def render_main(mode, _rebuild_counter, staged_pcap, active_chart, active_tab, active_session, replacing_s1):
    """forwards replacing-s1 flag to the choice view so it can render
    a "Replacing S1" banner without requiring the user to remember the
    sidebar button they pressed."""
    if mode == "intro":     return build_intro_view()
    if mode == "choice":    return build_choice_view(staged=staged_pcap, replacing_s1=replacing_s1)
    if mode == "dashboard": return build_dashboard_view(active_chart or "live_recording", active_tab or "analyze", active_session or "s1")
    return build_intro_view()


# Scroll window to top whenever the main view changes (intro -> choice ->
# dashboard) so the new screen always starts at its title, not mid-page.
app.clientside_callback(
    "function(mode){ setTimeout(function(){ try{ window.scrollTo({top:0,left:0,behavior:'auto'}); }catch(e){ window.scrollTo(0,0); } }, 30); return mode; }",
    Output("scroll-helper","data"),
    Input("app-mode","data"),
    prevent_initial_call=False,
)

# Educational-material banner: toggle (show / hide) the whole edu section.
@app.callback(Output({"type":"edu-collapse","loc":MATCH}, "is_open"),
              Output({"type":"edu-label","loc":MATCH}, "children"),
              Output({"type":"edu-arrow","loc":MATCH}, "children"),
              Input({"type":"edu-btn","loc":MATCH}, "n_clicks"),
              State({"type":"edu-collapse","loc":MATCH}, "is_open"),
              prevent_initial_call=True)
def toggle_edu_panel(n, is_open):
    """One pattern-match callback drives every _build_edu_panel instance."""
    if not n:
        return dash.no_update, dash.no_update, dash.no_update
    new_open = not is_open
    label = ("Click to hide the educational material" if new_open
             else "Click to show the educational material")
    return new_open, label, ("▲" if new_open else "▼")


@app.callback(Output("intro-continue-btn","disabled"),
              Input("intro-ack","value"))
def toggle_continue(value):
    return "ack" not in (value or [])


# Instant visual feedback when the user clicks Analyze: disable the button,
# change its label, and immediately show a status message. The actual analysis
# (handle_analyze_staged) is synchronous and can take 30-60 seconds (LSTM +
# 41 figures); without this clientside hook the button looked frozen and the
# user had no way to know work was in progress.
app.clientside_callback(
    """
    function(n) {
        if (!n) {
            return [window.dash_clientside.no_update,
                    window.dash_clientside.no_update,
                    window.dash_clientside.no_update];
        }
        return [
            true,
            "⏳  ANALYZING... PLEASE WAIT",
            "⏳  Running IsolationForest + DBSCAN + LSTM + security scans on your capture. " +
            "This typically takes 30-60 seconds depending on file size. " +
            "The page will switch to the dashboard automatically when done - please do not close this tab."
        ];
    }
    """,
    Output("staged-analyze-btn", "disabled", allow_duplicate=True),
    Output("staged-analyze-btn", "children", allow_duplicate=True),
    Output("load-status", "children", allow_duplicate=True),
    Input("staged-analyze-btn", "n_clicks"),
    prevent_initial_call=True,
)

# Same pattern for the path-Load button so the staging step also gives instant
# feedback (loading a large PCAP via scapy can take a few seconds).
app.clientside_callback(
    """
    function(n) {
        if (!n) {
            return [window.dash_clientside.no_update,
                    window.dash_clientside.no_update];
        }
        return [
            true,
            "⏳  Reading the file from disk..."
        ];
    }
    """,
    Output("pcap-path-btn", "disabled", allow_duplicate=True),
    Output("load-status", "children", allow_duplicate=True),
    Input("pcap-path-btn", "n_clicks"),
    prevent_initial_call=True,
)

# And for the S2 modal's Load button.
app.clientside_callback(
    """
    function(n) {
        if (!n) {
            return [window.dash_clientside.no_update,
                    window.dash_clientside.no_update,
                    window.dash_clientside.no_update];
        }
        return [
            true,
            "⏳  ANALYZING... PLEASE WAIT",
            "⏳  Loading S2 and running IsolationForest + DBSCAN + LSTM + " +
            "security scans on the second capture, then diffing against S1. " +
            "This typically takes 30-60 seconds depending on file size. " +
            "The modal will close and the page will switch to the S1-vs-S2 " +
            "comparison automatically when done - please do not close this tab."
        ];
    }
    """,
    Output("staged-second-analyze-btn", "disabled", allow_duplicate=True),
    Output("staged-second-analyze-btn", "children", allow_duplicate=True),
    Output("second-load-status", "children", allow_duplicate=True),
    Input("staged-second-analyze-btn", "n_clicks"),
    prevent_initial_call=True,
)

# Pattern-matched clientside feedback for the live-recording panel's
# Analyze button (one per session). When the user clicks "Analyze" inside
# the live recording panel (after a Stop & Save), the per-session button
# is instantly disabled and re-labelled so the user sees that work has
# started; otherwise process_session runs for 30-60s with no feedback.
app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        return [true, "⏳ ANALYZING RECORDED CAPTURE..."];
    }
    """,
    Output({"type":"live-btn","action":"analyze","session":MATCH},
           "disabled", allow_duplicate=True),
    Output({"type":"live-btn","action":"analyze","session":MATCH},
           "children", allow_duplicate=True),
    Input({"type":"live-btn","action":"analyze","session":MATCH},
          "n_clicks"),
    prevent_initial_call=True,
)

app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        return [true, "⏳ Opening live recording..."];
    }
    """,
    Output("record-live-btn", "disabled", allow_duplicate=True),
    Output("record-live-btn", "children", allow_duplicate=True),
    Input("record-live-btn", "n_clicks"),
    prevent_initial_call=True,
)

app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        return [true, "⏳ Loading..."];
    }
    """,
    Output("intro-continue-btn", "disabled", allow_duplicate=True),
    Output("intro-continue-btn", "children", allow_duplicate=True),
    Input("intro-continue-btn", "n_clicks"),
    prevent_initial_call=True,
)

app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        return [true, "⏳ Switching..."];
    }
    """,
    Output("switch-session-btn", "disabled", allow_duplicate=True),
    Output("switch-session-btn", "children", allow_duplicate=True),
    Input("switch-session-btn", "n_clicks"),
    prevent_initial_call=True,
)

app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        // after 5 seconds, if the click did not clear the page,
        // revert the button so it does not look permanently stuck. This
        // catches the analyze-blocked branch where the server returns
        // no_update and the button would otherwise stay at "Resetting...".
        setTimeout(function() {
            try {
                var b = document.getElementById("restart-btn");
                if (b) { b.disabled = false; b.innerText = "↺ Restart"; }
            } catch(e) {}
        }, 5000);
        return [true, "⏳ Resetting..."];
    }
    """,
    Output("restart-btn", "disabled", allow_duplicate=True),
    Output("restart-btn", "children", allow_duplicate=True),
    Input("restart-btn", "n_clicks"),
    prevent_initial_call=True,
)

app.clientside_callback(
    """
    function(n) {
        if (!n) { return [window.dash_clientside.no_update,
                          window.dash_clientside.no_update]; }
        return [true, "⏳ Resetting..."];
    }
    """,
    Output("restart-btn-welcome", "disabled", allow_duplicate=True),
    Output("restart-btn-welcome", "children", allow_duplicate=True),
    Input("restart-btn-welcome", "n_clicks"),
    prevent_initial_call=True,
)


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Input("intro-continue-btn","n_clicks"),
              prevent_initial_call=True)
def go_to_choice(n):
    """If a session is already loaded, Continue resumes the dashboard;
    otherwise it advances to the file-loading screen."""
    if n:
        if S1 is not None or S2 is not None:
            return "dashboard"
        return "choice"
    return dash.no_update


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("choice-back-btn","n_clicks"),
              prevent_initial_call=True)
def choice_back_to_intro(n):
    """← Back to welcome from the file-loading screen.
    also clear the replacing-s1 flag."""
    if n:
        return "intro", False
    return dash.no_update, dash.no_update


@app.callback(Output("s2-loaded-toast","is_open"),
              Input("s2-loaded-tick","data"),
              prevent_initial_call=True)
def show_s2_toast(tick):
    """Open the S2-loaded toast whenever the tick increments."""
    if tick and tick > 0:
        return True
    return dash.no_update


def _ingest_pcap_from_path(path, label):
    """Common path-based ingestion. Used by both the path input and dcc.Upload
    (which writes to a temp file first). Returns (ok, message).
    defer assignment to S1/S2 globals until post-processing succeeds,
    so that a mid-pipeline failure does not leave the dashboard with an
    incompletely-processed session in the global slot."""
    global S1, S2
    try:
        new_session = load_session_from_pcap(path, label)
        process_session(new_session, MY_DEVICE_IP)
    except Exception as e:
        import traceback; traceback.print_exc()
        return False, f"Analysis failed: {e}"
    try:
        new_session["threats"] = run_advanced_threats(path, label)
    except Exception as _e:
        new_session["threats"] = {"available": False, "reason": f"{type(_e).__name__}: {_e}"}
    # Run post-processing with a candidate pair (old globals + new_session in `label` slot).
    # Only commit to the globals if it succeeds.
    candidate_S1 = new_session if label == "S1" else S1
    candidate_S2 = new_session if label == "S2" else S2
    try:
        compute_pair_state(candidate_S1, candidate_S2, MY_DEVICE_IP)
    except Exception as e:
        import traceback; traceback.print_exc()
        return False, f"Loaded but post-processing failed: {e}"
    # Post-processing passed - commit globals, then rebuild figures.
    # snapshot the old globals + FIGS BEFORE assignment so we can
    # roll them back if rebuild_figures raises. Prevents "loaded chip" +
    # broken FIGS inconsistency.
    _old_S1, _old_S2 = S1, S2
    try:
        _old_FIGS = dict(FIGS) if isinstance(FIGS, dict) else None
    except Exception:
        _old_FIGS = None
    if label == "S1":  S1 = new_session
    else:              S2 = new_session
    try:
        rebuild_figures()
    except Exception as e:
        import traceback; traceback.print_exc()
        # rollback both S1/S2 and FIGS on failure.
        S1, S2 = _old_S1, _old_S2
        try:
            if _old_FIGS is not None:
                FIGS.clear(); FIGS.update(_old_FIGS)
        except Exception: pass
        return False, f"Loaded but figure rebuild failed - rolled back: {e}"
    try: SESSION_PCAPS[label] = path
    except Exception: pass
    return True, (f"{label} loaded: {os.path.basename(path)} "
                  f"({new_session['n_pkts']:,} packets)")


def _err_box(msg):
    return html.Div([
        html.Span("✗  ", style={"color":RED_ACCENT,"fontWeight":"700"}),
        msg
    ], style={"color":RED_ACCENT,"padding":"10px 14px","borderRadius":"10px",
              "background":"rgba(248,113,113,0.08)",
              "border":f"1px solid rgba(248,113,113,0.25)",
              "fontFamily":"'JetBrains Mono', monospace","fontSize":"12px"})


def _info_box(msg, color=None):
    color = color or LIME
    return html.Div([
        html.Span("⏳ ", style={"marginRight":"4px"}),
        msg
    ], style={"color":color,"padding":"10px 14px","borderRadius":"10px",
              "background":f"rgba(163,230,53,0.08)" if color == LIME
                            else f"rgba(167,139,250,0.10)",
              "border":f"1px solid {color}55",
              "fontFamily":"'JetBrains Mono', monospace","fontSize":"12px"})


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("load-status","children"),
              Output("staged-pcap","data", allow_duplicate=True),
              Output("pcap-path-btn","disabled", allow_duplicate=True),
              Input("pcap-upload","contents"),
              Input("pcap-path-btn","n_clicks"),
              Input("record-live-btn","n_clicks"),
              State("pcap-upload","filename"),
              State("pcap-path-input","value"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def handle_first_action(upload_contents, n_path, n_record,
                        upload_filename, path_value, rebuild_count):
    """Step 1: drag-drop, paste-path, or live-record button.
    For upload/path: STAGES the file (does not analyze yet - user must click
    ▶ Analyze afterwards). For live record: routes to the recording UI."""
    trig = ctx.triggered_id

    if trig == "record-live-btn":
        if not n_record:
            return (dash.no_update, dash.no_update, dash.no_update,
                    dash.no_update, dash.no_update, False)
        return ("dashboard", "live_recording", (rebuild_count or 0)+1,
                dash.no_update, dash.no_update, False)

    if trig == "pcap-upload":
        if not upload_contents:
            return (dash.no_update, dash.no_update, dash.no_update,
                    dash.no_update, dash.no_update, False)
        tmp_path, err = decode_uploaded_pcap(upload_contents,
                                              upload_filename or "upload.pcap")
        if err:
            return (dash.no_update, dash.no_update, dash.no_update,
                    _err_box(err), dash.no_update, False)
        try: size_bytes = os.path.getsize(tmp_path)
        except Exception: size_bytes = 0
        return (dash.no_update, dash.no_update, dash.no_update,
                dash.no_update,
                {"path":tmp_path,"source":"upload",
                 "filename":upload_filename or os.path.basename(tmp_path),
                 "size_bytes":size_bytes}, False)

    if trig == "pcap-path-btn":
        if not n_path:
            return (dash.no_update, dash.no_update, dash.no_update,
                    dash.no_update, dash.no_update, False)
        resolved, err = validate_pcap_path(path_value)
        if err:
            return (dash.no_update, dash.no_update, dash.no_update,
                    _err_box(err), dash.no_update, False)
        try: size_bytes = os.path.getsize(resolved)
        except Exception: size_bytes = 0
        return (dash.no_update, dash.no_update, dash.no_update,
                dash.no_update,
                {"path":resolved,"source":"path",
                 "filename":os.path.basename(resolved),
                 "size_bytes":size_bytes}, False)

    return (dash.no_update, dash.no_update, dash.no_update,
            dash.no_update, dash.no_update, False)


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("load-status","children", allow_duplicate=True),
              Output("staged-pcap","data", allow_duplicate=True),
              Output("staged-analyze-btn","disabled", allow_duplicate=True),
              Output("staged-analyze-btn","children", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("staged-analyze-btn","n_clicks"),
              State("staged-pcap","data"),
              State("trigger-rebuild","data"),
              State("replacing-s1","data"),
              prevent_initial_call=True)
def handle_analyze_staged(n_click, staged, rebuild_count, replacing_s1):
    """Step 2: user clicks ▶ Analyze in the staging card → run analysis.
    Always re-enables the button on error/no-op so the user can retry.
    if this was a "Replace S1" workflow, navigate back to the
    comparison view (since S2 is presumably still loaded), and clear the flag."""
    _orig = ["▶ ", html.Span("Analyze", style={"marginLeft":"4px"})]
    if not n_click or not staged or not staged.get("path"):
        return (dash.no_update, dash.no_update, dash.no_update,
                dash.no_update, dash.no_update, False, _orig, dash.no_update)
    ok, msg = _ingest_pcap_from_path(staged["path"], "S1")
    if ok:
        # delete tmp upload + clear stale live pending for S1 so
        # freshly-loaded PCAP cannot be overwritten by an old "Analyze" click.
        if staged and staged.get("source") == "upload" and staged.get("path"):
            try: os.remove(staged["path"])
            except Exception: pass
        try:
            w = LIVE_SESSIONS.get("S1")
            if w is not None and getattr(w, "_pending_snapshot", None) is not None:
                w._pending_snapshot = None
                print("[analyze-staged] cleared stale S1 live pending snapshot")
        except Exception: pass
        next_chart = "cmp_traffic" if (replacing_s1 and S2 is not None) else "talkers_s1"
        return ("dashboard", next_chart, (rebuild_count or 0)+1,
                "", None, dash.no_update, dash.no_update, False)
    return (dash.no_update, dash.no_update, dash.no_update,
            _err_box(msg), dash.no_update, False, _orig, dash.no_update)


@app.callback(Output("staged-pcap","data", allow_duplicate=True),
              Output("load-status","children", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("staged-clear-btn","n_clicks"),
              State("staged-pcap","data"),
              prevent_initial_call=True)
def handle_clear_staged(n_click, staged):
    """Step 2-alt: user clicks ✕ Clear → drop the staged file.
    also clear the replacing-s1 flag - otherwise a later Analyze on a
    re-uploaded file would route to the comparison view with stale state."""
    if not n_click:
        return dash.no_update, dash.no_update, dash.no_update
    if staged and staged.get("source") == "upload" and staged.get("path"):
        try: os.remove(staged["path"])
        except Exception: pass
    return None, "", False


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Input("empty-load-pcap-btn","n_clicks"),
              Input("empty-record-live-btn","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def handle_empty_state_action(n_load, n_record, rebuild_count):
    """The 'Get Started' buttons in the empty-state CTA: empty-load-pcap-btn
    routes back to the choice view so the user can drag-drop / paste path;
    empty-record-live-btn jumps straight to the live recording chart."""
    trig = ctx.triggered_id
    if trig == "empty-record-live-btn":
        return dash.no_update, "live_recording", (rebuild_count or 0)+1
    if trig == "empty-load-pcap-btn":
        return "choice", dash.no_update, (rebuild_count or 0)+1
    return dash.no_update, dash.no_update, dash.no_update


@app.callback(Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Input("add-second-live-btn","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def handle_second_live_session(n_rec2, rebuild_count):
    """Sidebar 'Record second session' → navigate to the live recording chart.
    also reset the S2 worker first so a previously-saved live capture
    on S2 does not block the next Record click with \"Already saved. Press
    Reset to record again.\""""
    if not n_rec2:
        return dash.no_update, dash.no_update
    if ctx.triggered_id == "add-second-live-btn":
        try:
            w = LIVE_SESSIONS.get("S2")
            if w is not None and w.quick_stats().get("status") == "saved":
                w.reset()
                print("[nav] reset S2 live worker before re-record")
        except Exception as e:
            print(f"[nav] could not pre-reset S2 worker: {e}")
        # pause S1 too so its tshark does not silently
        # keep recording while user is focused on S2.
        _pause_active_live_workers(except_for="S2")
        return "live_recording", (rebuild_count or 0)+1
    return dash.no_update, dash.no_update


@app.callback(Output("second-pcap-modal","is_open"),
              Output("second-load-status","children", allow_duplicate=True),
              Output("second-pcap-path-input","value", allow_duplicate=True),
              Output("second-pcap-path-btn","disabled", allow_duplicate=True),
              Output("second-pcap-path-btn","children", allow_duplicate=True),
              Output("staged-second-pcap","data", allow_duplicate=True),
              Input("add-second-pcap-btn","n_clicks"),
              Input("second-pcap-cancel-btn","n_clicks"),
              State("second-pcap-modal","is_open"),
              State("staged-second-pcap","data"),
              prevent_initial_call=True)
def toggle_second_pcap_modal(n_open, n_cancel, is_open, staged):
    """Sidebar 'Load second PCAP' opens the modal; Cancel closes it.
    also clear staged-second-pcap on cancel so a previously staged
    file does not surface on the next open of the modal. If the staged
    file is an upload temp file, remove it from disk too."""
    trig = ctx.triggered_id
    if trig == "add-second-pcap-btn" and n_open:
        return True, "", "", False, "Load", dash.no_update
    if trig == "second-pcap-cancel-btn":
        if staged and staged.get("source") == "upload" and staged.get("path"):
            try: os.remove(staged["path"])
            except Exception: pass
        return False, "", "", False, "Load", None
    return is_open, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update


# catch modal closes that bypass toggle_second_pcap_modal (X button
# in ModalHeader, Escape key, backdrop click) so staged-second-pcap and its
# tmp upload file get cleaned up regardless of how the modal was dismissed.
@app.callback(
    Output("staged-second-pcap","data", allow_duplicate=True),
    Input("second-pcap-modal","is_open"),
    State("staged-second-pcap","data"),
    prevent_initial_call=True,
)
def cleanup_on_modal_close(is_open, staged):
    if is_open:
        return dash.no_update
    if staged and staged.get("source") == "upload" and staged.get("path"):
        try:
            os.remove(staged["path"])
            print("[modal] cleaned up tmp upload after modal close", flush=True)
        except Exception: pass
    return None


@app.callback(Output("second-load-status","children", allow_duplicate=True),
              Output("staged-second-pcap","data", allow_duplicate=True),
              Output("second-pcap-path-btn","disabled", allow_duplicate=True),
              Input("second-pcap-upload","contents"),
              Input("second-pcap-path-btn","n_clicks"),
              Input("second-pcap-path-input","n_submit"),
              State("second-pcap-upload","filename"),
              State("second-pcap-path-input","value"),
              prevent_initial_call=True)
def handle_second_first_action(upload_contents, n_path, n_submit,
                                upload_filename, path_value):
    """S2 Stage 1: drop file OR paste path -> STAGE the file (no analysis yet).
    The staged file goes into staged-second-pcap; a callback then renders the
    Stage-2 card with the big Analyze button. Errors go to second-load-status."""
    trig = ctx.triggered_id

    if trig == "second-pcap-upload":
        if not upload_contents:
            return (dash.no_update, dash.no_update, False)
        tmp_path, err = decode_uploaded_pcap(upload_contents,
                                              upload_filename or "upload.pcap")
        if err:
            return (_err_box(err + "  -  Tip: use a .pcap or .pcapng file under 100 MB."), dash.no_update, False)
        try: size_bytes = os.path.getsize(tmp_path)
        except Exception: size_bytes = 0
        return ("", {"path":tmp_path,"source":"upload",
                     "filename":upload_filename or os.path.basename(tmp_path),
                     "size_bytes":size_bytes}, False)

    if trig in ("second-pcap-path-btn", "second-pcap-path-input"):
        # Either the user clicked Load or pressed Enter in the input.
        if trig == "second-pcap-path-btn" and not n_path: return (dash.no_update, dash.no_update, False)
        if trig == "second-pcap-path-input" and not n_submit: return (dash.no_update, dash.no_update, False)
        if not path_value or not str(path_value).strip():
            return (_err_box("Path is empty  -  Tip: paste a full path like C:\\Users\\OR\\Downloads\\capture2.pcapng."), dash.no_update, False)
        resolved, err = validate_pcap_path(path_value)
        if err:
            return (_err_box(err + "  -  Tip: paste the FULL path including .pcapng (right-click the file in Explorer \u2192 'Copy as path')."), dash.no_update, False)
        try: size_bytes = os.path.getsize(resolved)
        except Exception: size_bytes = 0
        return ("", {"path":resolved,"source":"path",
                     "filename":os.path.basename(resolved),
                     "size_bytes":size_bytes}, False)

    return (dash.no_update, dash.no_update, False)


@app.callback(Output("second-pcap-stage1", "style"),
              Output("second-pcap-stage2", "children"),
              Output("second-pcap-stage2", "style"),
              Input("staged-second-pcap", "data"),
              prevent_initial_call=False)
def render_second_stage(staged):
    """Toggle between Stage 1 (upload UI) and Stage 2 (staged card)."""
    if staged and staged.get("path"):
        return ({"display":"none"}, _build_second_staged_card(staged), {"display":"block"})
    return ({"display":"block"}, None, {"display":"none"})


@app.callback(Output("second-pcap-modal","is_open", allow_duplicate=True),
              Output("second-load-status","children", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("s2-loaded-tick","data", allow_duplicate=True),
              Output("staged-second-pcap","data", allow_duplicate=True),
              Output("staged-second-analyze-btn","disabled", allow_duplicate=True),
              Output("staged-second-analyze-btn","children", allow_duplicate=True),
              Input("staged-second-analyze-btn","n_clicks"),
              State("staged-second-pcap","data"),
              State("trigger-rebuild","data"),
              State("s2-loaded-tick","data"),
              prevent_initial_call=True)
def handle_second_analyze_staged(n_click, staged, rebuild_count, s2_tick):
    """S2 Stage 2: user clicks Analyze S2 -> run the pipeline on the staged
    file. On success: close the modal, navigate to cmp_traffic (S1-vs-S2),
    bump trigger-rebuild + s2-loaded-tick. On error: show an actionable
    error box and re-enable the button."""
    _orig = ["\u25b6 ", html.Span("Analyze S2", style={"marginLeft":"4px"})]
    if not n_click or not staged or not staged.get("path"):
        return (dash.no_update, dash.no_update, dash.no_update, dash.no_update,
                dash.no_update, dash.no_update, False, _orig)
    ok, msg = _ingest_pcap_from_path(staged["path"], "S2")
    if ok:
        # delete tmp upload + clear stale live pending for S2 so
        # freshly-loaded PCAP cannot be overwritten by an old "Analyze" click.
        if staged and staged.get("source") == "upload" and staged.get("path"):
            try: os.remove(staged["path"])
            except Exception: pass
        try:
            w = LIVE_SESSIONS.get("S2")
            if w is not None and getattr(w, "_pending_snapshot", None) is not None:
                w._pending_snapshot = None
                print("[analyze-staged-S2] cleared stale S2 live pending snapshot")
        except Exception: pass
        # success: close modal, navigate to comparison view, clear staging
        return (False, "", "cmp_traffic", (rebuild_count or 0)+1,
                (s2_tick or 0)+1, None, False, _orig)
    # also drop staged-second-pcap so a vanished/invalid path is
    # not remembered on the next open of the modal.
    return (dash.no_update, _err_box(msg + "  -  Tip: confirm the file is a valid PCAP/PCAPNG and that tshark is on PATH."),
            dash.no_update, dash.no_update, dash.no_update,
            None, False, _orig)


@app.callback(Output("staged-second-pcap","data", allow_duplicate=True),
              Output("second-load-status","children", allow_duplicate=True),
              Input("staged-second-clear-btn","n_clicks"),
              State("staged-second-pcap","data"),
              prevent_initial_call=True)
def handle_second_clear_staged(n_click, staged):
    """S2 Stage 2-alt: user clicks Clear -> drop the staged file."""
    if not n_click:
        return dash.no_update, dash.no_update
    if staged and staged.get("source") == "upload" and staged.get("path"):
        try: os.remove(staged["path"])
        except Exception: pass
    return None, ""


def _do_restart(rebuild_count, staged, staged_s2):
    """Shared restart logic. Returns the 5-tuple that restart_app_*
    server callbacks send back to the Store outputs. Splitting the dual-
    Input callback into two single-Input callbacks is required for Dash 4
    to actually dispatch the reset: a multi-Input callback is silently
    skipped when one of the Inputs is absent from the current DOM, and
    restart-btn / restart-btn-welcome are never both present at once."""
    if staged_s2 and staged_s2.get("source") == "upload" and staged_s2.get("path"):
        try: os.remove(staged_s2["path"])
        except Exception: pass
    global S1, S2, FIGS, ip_agg, z_scores, local_ip_agg, extern_ip_agg
    global compare_df, new_n, gone_n, INSIGHTS_LINES
    S1 = None
    S2 = None
    try:    FIGS.clear()
    except Exception: FIGS = {}
    ip_agg = None
    z_scores = None
    local_ip_agg = None
    extern_ip_agg = None
    compare_df = None
    new_n = 0
    gone_n = 0
    INSIGHTS_LINES = []
    for sid in ("S1","S2"):
        try:
            w = LIVE_SESSIONS[sid]
            w.reset()
            if hasattr(w, "_pending_snapshot"):
                w._pending_snapshot = None
        except Exception as e:
            print(f"  [restart] {sid} reset failed: {e}")
    if staged and staged.get("source") == "upload" and staged.get("path"):
        try:
            os.remove(staged["path"])
        except Exception:
            pass
    return "intro", "live_recording", (rebuild_count or 0)+1, None, False


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("staged-pcap","data", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("restart-btn","n_clicks"),
              State("trigger-rebuild","data"),
              State("staged-pcap","data"),
              State("staged-second-pcap","data"),
              prevent_initial_call=True)
def restart_app_from_dashboard(n, rebuild_count, staged, staged_s2):
    if not n:
        return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    # block Restart while analyzing AND surface why the
    # click did nothing by writing worker.error_msg so the live panel banner
    # shows the reason.
    for _sid in ("S1", "S2"):
        try:
            _w = LIVE_SESSIONS.get(_sid)
            if _w is not None and getattr(_w, "_analyzing", False):
                try: _w.error_msg = f"Restart blocked: {_sid} is still analyzing. Please wait for it to finish."
                except Exception: pass
                return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
        except Exception: pass
    return _do_restart(rebuild_count, staged, staged_s2)


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("staged-pcap","data", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("restart-btn-welcome","n_clicks"),
              State("trigger-rebuild","data"),
              State("staged-pcap","data"),
              State("staged-second-pcap","data"),
              prevent_initial_call=True)
def restart_app_from_welcome(n, rebuild_count, staged, staged_s2):
    if not n:
        return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    # same guard, with visible feedback via error_msg.
    for _sid in ("S1", "S2"):
        try:
            _w = LIVE_SESSIONS.get(_sid)
            if _w is not None and getattr(_w, "_analyzing", False):
                try: _w.error_msg = f"Restart blocked: {_sid} is still analyzing. Please wait."
                except Exception: pass
                return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
        except Exception: pass
    return _do_restart(rebuild_count, staged, staged_s2)





def _pause_active_live_workers(except_for=None):
    """any LiveCaptureWorker currently in 'recording' state has tshark
    still writing chunks to disk. When the user navigates away from the live
    recording page (sidebar nav, tab switch, brand-home, switch-session), the
    UI no longer shows the worker, but the subprocess keeps running silently
    until MAX_SECONDS or a kernel restart. Call this at the top of every
    navigation handler that leaves the live page. Returns the list of session
    ids that were auto-paused for logging."""
    paused = []
    for sid, worker in (LIVE_SESSIONS or {}).items():
        if except_for and sid == except_for:
            continue
        try:
            if worker.quick_stats().get("status") == "recording":
                worker.pause()
                paused.append(sid)
        except Exception:
            pass
    if paused:
        print(f"[nav] auto-paused live recording for: {paused}")
    return paused


@app.callback(Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("last-chart-per-tab","data", allow_duplicate=True),
              Input({"type":"nav-item","id":ALL}, "n_clicks"),
              State("trigger-rebuild","data"),
              State("active-tab","data"),
              State("last-chart-per-tab","data"),
              prevent_initial_call=True)
def click_nav(_clicks, rebuild_count, active_tab, last_chart_per_tab):
    """Fire only on real user clicks. When the sidebar rebuilds, each
    nav-item is recreated with n_clicks=0 - Dash sees this as a change
    from the previous value and would re-fire this callback, defaulting
    ctx.triggered_id to the first pattern match. Guard against that by
    requiring the triggered n_clicks value to be a real positive integer.
    also remember the chosen chart per top-level tab."""
    trig = ctx.triggered_id
    if not isinstance(trig, dict):
        return dash.no_update, dash.no_update, dash.no_update
    triggered = ctx.triggered or []
    if not triggered:
        return dash.no_update, dash.no_update, dash.no_update
    val = triggered[0].get("value")
    if val is None or not isinstance(val, (int, float)) or val <= 0:
        return dash.no_update, dash.no_update, dash.no_update
    new_chart = trig.get("id")
    # hard-reject clicks on chips that require S2 when S2 is missing.
    # The visual disabled state uses n_clicks=None but Dash still tracks pattern
    # clicks; without this guard the callback would navigate to a placeholder.
    _needs_s2 = NEEDS_S2_IDS
    if new_chart in _needs_s2 and S2 is None:
        print(f"[nav] blocked click on {new_chart} - S2 not loaded", flush=True)
        return dash.no_update, dash.no_update, dash.no_update
    if new_chart != "live_recording":
        _pause_active_live_workers()
    # update the per-tab memory for the active tab
    memory = dict(last_chart_per_tab or {})
    tab_of_chart = _tab_for_chart(new_chart)
    if tab_of_chart:
        memory[tab_of_chart] = new_chart
    return new_chart, (rebuild_count or 0)+1, memory


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Input("switch-session-btn","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def switch_session_to_choice(n, rebuild_count):
    """User clicked Switch session on Live Recording page.
    Goes back to the choice view (Load PCAP / Record Live) but does NOT
    reset S1/S2 globals.
    if S1 is already loaded, set the replacing-s1 flag so the
    choice view renders the warning banner and the next Analyze knows to
    route to the comparison view."""
    if not n: return dash.no_update, dash.no_update, dash.no_update
    _pause_active_live_workers()
    flag = (S1 is not None)
    return "choice", (rebuild_count or 0)+1, flag


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Input("brand-home","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def brand_to_home(n, rebuild_count):
    """Click on the brand logo → return to the welcome (intro) screen.
    Session data (S1/S2/FIGS) is preserved; Continue on the welcome screen
    routes back to the dashboard directly when data is already loaded."""
    if not n:
        return dash.no_update, dash.no_update
    _pause_active_live_workers()
    return "intro", (rebuild_count or 0)+1


@app.callback(Output("app-mode","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("replacing-s1","data", allow_duplicate=True),
              Output("staged-pcap","data", allow_duplicate=True),
              Input("replace-s1-btn","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def handle_replace_s1(n, rebuild_count):
    if not n:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    # stop tshark for any live worker still recording so it does not
    # keep writing chunks silently while the user is on the choice screen.
    _pause_active_live_workers()
    # the staged-pcap Store is cleared here (returned None below);
    # if it currently references a tmp upload file, also delete the file so
    # a stale netsec_upload_*.pcap does not linger. (State is not part of
    # this callback signature, so we broadcast a request to the
    # cleanup-on-modal-close-style callback via the store; the simple
    # approach here is to also sweep old tmp uploads.)
    try:
        import glob, time as _t
        for _p in glob.glob(os.path.join(tempfile.gettempdir(), "netsec_upload_*.pcap*")):
            try:
                if _t.time() - os.path.getmtime(_p) > 60:
                    os.remove(_p)
            except Exception: pass
    except Exception: pass
    return "choice", (rebuild_count or 0)+1, True, None


@app.callback(Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Input("replace-s1-live-btn","n_clicks"),
              State("trigger-rebuild","data"),
              prevent_initial_call=True)
def handle_replace_s1_live(n, rebuild_count):
    """Sidebar 'Replace S1 recording' -> navigate to the live recording chart.
    Reset the S1 worker first so a previously-saved live capture on S1
    does not block the next Record click with \"Already saved. Press Reset
    to record again.\""""
    if not n:
        return dash.no_update, dash.no_update
    if ctx.triggered_id == "replace-s1-live-btn":
        try:
            w = LIVE_SESSIONS.get("S1")
            if w is not None:
                _st = w.quick_stats().get("status")
                # previously only status=='saved' triggered reset,
                # so an in-flight recording continued silently. Now cover
                # recording, paused, and saved uniformly.
                if _st in ("recording", "paused", "saved"):
                    w.reset()
                    print(f"[nav] reset S1 live worker (was {_st}) before re-record")
        except Exception as e:
            print(f"[nav] could not pre-reset S1 worker: {e}")
        # also pause S2 so its tshark does not keep running
        # while the user is focused on replacing S1.
        _pause_active_live_workers(except_for="S1")
        return "live_recording", (rebuild_count or 0)+1
    return dash.no_update, dash.no_update


@app.callback(Output("sidebar","children"),
              Input("active-chart","data"),
              Input("active-tab","data"),
              Input("active-session","data"),
              Input("trigger-rebuild","data"),
              Input("live-rec-tick","data"))
def update_sidebar(active_chart, active_tab, active_session, _rebuild, _tick):
    # live-rec-tick bumps on every worker action AND
    # every 3s while on the live page, so the sidebar guard state
    # stays fresh and buttons enable/disable in real time.
    return _build_sidebar(active_chart, active_tab or "analyze", active_session or "s1")


import os as _os_n8n

# Where the analyzer VM lives. The dashboard talks to /v1/pcap on it
# (spec 5.1) - not to any local Docker daemon. NETSEC_REMOTE_HOST is kept
# as the human-facing hostname/IP for messages; NETSEC_INGEST_URL is the
# actual HTTP endpoint (defaults to :8766 on that host).
# See docs/VM_DEPLOYMENT.md.
N8N_REMOTE_HOST = _os_n8n.environ.get("NETSEC_REMOTE_HOST", "")
N8N_INGEST_URL = _os_n8n.environ.get(
    "NETSEC_INGEST_URL",
    (f"http://{N8N_REMOTE_HOST}:8766" if N8N_REMOTE_HOST else ""))
N8N_SENSOR_ID = _os_n8n.environ.get("NETSEC_SENSOR_ID", "")
N8N_SENSOR_SECRET = _os_n8n.environ.get("NETSEC_SENSOR_SECRET", "")


def _n8n_stack_status():
    """Best-effort probe of the ingest API on the VM. Returns
    {ingest: bool, detail: str}. Never raises. Only succeeds while
    Tailscale is up on this machine (or a public route exists)."""
    import urllib.request as _urlreq
    out = {"ingest": False, "detail": ""}
    if not N8N_INGEST_URL:
        out["detail"] = ("NETSEC_INGEST_URL not set "
                         "(and NETSEC_REMOTE_HOST unset)")
        return out
    try:
        with _urlreq.urlopen(
                f"{N8N_INGEST_URL.rstrip('/')}/healthz", timeout=4) as r:
            out["ingest"] = (r.status == 200)
    except Exception as exc:
        out["detail"] = f"{N8N_INGEST_URL}/healthz: {exc}"
    return out


def _n8n_stack_down_message(status):
    """Rendered when the button is clicked but ingest is not reachable."""
    return html.Div([
        html.Div([
            html.Span("\u26a0\ufe0f", style={"marginRight":"6px"}),
            html.Span(f"Cannot reach the analyzer VM at "
                      f"{N8N_INGEST_URL or 'NETSEC_INGEST_URL unset'}",
                      style={"color":"#f59e0b","fontWeight":"600"}),
        ]),
        html.Div(
            status.get("detail") or "Not sending - the report would never "
            "arrive. Check Tailscale + the VM before clicking again:",
            style={"marginTop":"4px","color":INK_MUTE,"fontSize":"10px"}),
        html.Pre(
            "tailscale status         # this machine must be connected\n"
            f"curl {N8N_INGEST_URL or '<url>'}/healthz",
            style={"marginTop":"6px","padding":"6px 8px",
                   "background":"#1e1e2e","color":"#e5e7eb",
                   "fontSize":"10px","borderRadius":"6px",
                   "fontFamily":"'JetBrains Mono', monospace",
                   "whiteSpace":"pre","overflow":"auto",
                   "border":"1px solid rgba(245,158,11,0.30)"}),
    ])


@app.callback(
    Output({"type":"n8n-send-status","session":MATCH}, "children"),
    Input({"type":"n8n-send-btn","session":MATCH}, "n_clicks"),
    State({"type":"n8n-send-btn","session":MATCH}, "id"),
    State({"type":"n8n-email","session":MATCH}, "value"),
    prevent_initial_call=True,
)
def send_session_to_n8n(n_clicks, btn_id, email):
    """Sign and stream the session's PCAP to /v1/pcap on the VM, with
    X-Notify-Email so the worker mails the finished report to whatever
    address the user typed. Never scp's a file anywhere - the HTTP ingest
    path replaces the older folder-poll flow."""
    import os as _os
    import re as _re
    if not n_clicks:
        return dash.no_update
    session_key = (btn_id or {}).get("session")
    S_obj = S1 if session_key == "s1" else (S2 if session_key == "s2" else None)
    if S_obj is None:
        return html.Div([
            html.Span("\u274c", style={"marginRight":"6px"}),
            html.Span(f"No {(session_key or '').upper()} session loaded",
                      style={"color":"#ef4444"})
        ])
    src_pcap = S_obj.get("_source_pcap") or ""
    if not src_pcap or not _os.path.isfile(src_pcap):
        return html.Div([
            html.Span("\u274c", style={"marginRight":"6px"}),
            html.Span(
                f"Source PCAP not on disk anymore ({src_pcap or 'unknown'})",
                style={"color":"#ef4444"})
        ])

    # Email is optional - without it the worker falls back to
    # NETSEC_NOTIFY_EMAIL on the VM, or logs 'no recipient' and skips.
    # But if the user typed *something* that is not a valid address,
    # tell them - a typo is silent otherwise.
    addr = (email or "").strip()
    if addr and not _re.match(r"^[^@\s,;:<>]+@[^@\s,;:<>]+\.[A-Za-z]{2,}$", addr):
        return html.Div([
            html.Span("\u274c", style={"marginRight":"6px"}),
            html.Span(f"That does not look like an email: {addr!r}",
                      style={"color":"#ef4444"})
        ])

    if not (N8N_INGEST_URL and N8N_SENSOR_ID and N8N_SENSOR_SECRET):
        return html.Div([
            html.Span("\u274c", style={"marginRight":"6px"}),
            html.Span(
                "Set NETSEC_INGEST_URL, NETSEC_SENSOR_ID and "
                "NETSEC_SENSOR_SECRET (see docs/VM_OPS.md). Without them "
                "the dashboard cannot sign the upload.",
                style={"color":"#ef4444"})
        ])

    stack = _n8n_stack_status()
    if not stack["ingest"]:
        return _n8n_stack_down_message(stack)

    # tools/upload_pcap.upload_file is the same signing + streaming code
    # the CLI uses, so the dashboard path is byte-identical over the wire.
    import sys as _sys
    _here = _os.path.dirname(_os.path.abspath(__file__))
    _tools = _os.path.abspath(_os.path.join(_here, "..", "tools"))
    if _tools not in _sys.path:
        _sys.path.insert(0, _tools)
    from upload_pcap import upload_file as _upload_file

    result = _upload_file(
        src_pcap, N8N_INGEST_URL, N8N_SENSOR_ID, N8N_SENSOR_SECRET,
        kind="prod",
        label=f"{session_key.upper()}_{_os.path.basename(src_pcap)}",
        notify_email=addr or None,
        timeout=300.0, retries=2)

    if not result.get("ok"):
        return html.Div([
            html.Span("\u274c", style={"marginRight":"6px"}),
            html.Span(f"Upload failed: {result.get('error') or 'unknown'}",
                      style={"color":"#ef4444"})
        ])

    sid = result.get("session_id")
    dup = " (duplicate - existing session returned)" if result.get(
        "duplicate") else ""
    mail_line = (f"Report will be mailed to {addr}." if addr
                 else "No email provided - the report stays on the VM at "
                      f"{N8N_INGEST_URL}/v1/reports/{sid}.html")
    return html.Div([
        html.Div([
            html.Span("\u2705", style={"marginRight":"6px"}),
            html.Span(f"Uploaded as session {sid}{dup}",
                      style={"color":"#22c55e","fontWeight":"600"}),
        ]),
        html.Div(
            mail_line,
            style={"marginTop":"4px","color":INK_MUTE,"fontSize":"10px"}),
        html.Div(
            "The worker picks the queued job within ~10 seconds and takes "
            "roughly one minute per 20k packets. Silent otherwise; check "
            "the worker log on the VM if nothing arrives.",
            style={"marginTop":"4px","color":INK_MUTE,"fontSize":"10px"}),
    ])


@app.callback(Output("chart-picker-strip","children"),
              Input("active-chart","data"),
              Input("active-tab","data"),
              Input("active-session","data"),
              Input("trigger-rebuild","data"))
def update_chart_picker_strip(active_chart, active_tab, active_session, _rebuild):
    """Keep the horizontal chip strip in sync with the active chart / tab.
    Mirrors the sidebar refresh path so the highlighted chip follows the
    user's selection (incl. programmatic navigation after Analyze)."""
    return build_chart_picker_strip(active_chart, active_tab or "analyze", active_session or "s1")

# ---- Top-tab callbacks -------------------------------------------------
@app.callback(Output("tab-strip","children"),
              Input("active-tab","data"))
def render_tab_strip(active_tab):
    """Rebuild the tab strip whenever the active tab changes (so the
    highlighted pill follows the user's selection)."""
    return build_tab_strip(active_tab or "analyze")


@app.callback(Output("active-tab","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Input({"type":"tab-btn","id":ALL}, "n_clicks"),
              State("trigger-rebuild","data"),
              State("last-chart-per-tab","data"),
              State("active-session","data"),
              prevent_initial_call=True)
def click_tab(_clicks, rebuild_count, last_chart_per_tab, active_session):
    """User clicked one of the Analyze / Security pills.
    if a chart was previously selected on the target tab, restore it
    instead of falling back to the first item."""
    trig = ctx.triggered_id
    if not isinstance(trig, dict):
        return dash.no_update, dash.no_update, dash.no_update
    triggered = ctx.triggered or []
    if not triggered:
        return dash.no_update, dash.no_update, dash.no_update
    val = triggered[0].get("value")
    if val is None or not isinstance(val, (int, float)) or val <= 0:
        return dash.no_update, dash.no_update, dash.no_update
    tab_id = trig.get("id")
    target_chart = ((last_chart_per_tab or {}).get(tab_id)
                    or _default_chart_for_tab(tab_id, active_session or "s1"))
    if target_chart in NEEDS_S2_IDS and S2 is None:
        target_chart = _default_chart_for_tab(tab_id, "s1")
    if target_chart != "live_recording":
        _pause_active_live_workers()
    return tab_id, target_chart, (rebuild_count or 0)+1


@app.callback(Output("active-tab","data", allow_duplicate=True),
              Input("active-chart","data"),
              State("active-tab","data"),
              prevent_initial_call=True)
def sync_tab_to_chart(chart_id, current_tab):
    """If something programmatically changes active-chart to a chart that
    belongs to a different tab (e.g. handle_second_analyze_staged jumps to
    cmp_traffic), keep the tab strip in sync."""
    if not chart_id:
        return dash.no_update
    expected = _tab_for_chart(chart_id)
    if expected and expected != current_tab:
        return expected
    return dash.no_update


@app.callback(Output("active-session","data", allow_duplicate=True),
              Output("active-chart","data", allow_duplicate=True),
              Output("trigger-rebuild","data", allow_duplicate=True),
              Output("last-chart-per-tab","data", allow_duplicate=True),
              Input({"type":"session-tab","id":ALL}, "n_clicks"),
              State("active-session","data"),
              State("active-chart","data"),
              State("active-tab","data"),
              State("trigger-rebuild","data"),
              State("last-chart-per-tab","data"),
              prevent_initial_call=True)
def click_session_tab(_clicks, cur_session, cur_chart, cur_tab, rebuild_count, memory):
    """S1 | S2 sub-tab click: keep the user on the twin view of the other
    session when one exists, otherwise land on the sub-tab's first chart.
    Uses the same real-click guard as click_nav (strip rebuilds recreate
    the pills with n_clicks=0)."""
    trig = ctx.triggered_id
    if not isinstance(trig, dict):
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    triggered = ctx.triggered or []
    if not triggered:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    val = triggered[0].get("value")
    if val is None or not isinstance(val, (int, float)) or val <= 0:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    new_session = trig.get("id")
    if new_session not in ("s1", "s2") or new_session == (cur_session or "s1"):
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    if new_session == "s2" and S2 is None:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    tab = cur_tab or "analyze"
    if SESSION_SCOPE.get(cur_chart) == "any":
        new_chart = cur_chart
    else:
        new_chart = (SESSION_TWIN.get(cur_chart)
                     or _default_chart_for_tab(tab, new_session))
    if new_chart != "live_recording":
        _pause_active_live_workers()
    mem = dict(memory or {})
    mem[tab] = new_chart
    return new_session, new_chart, (rebuild_count or 0)+1, mem


@app.callback(Output("active-session","data", allow_duplicate=True),
              Input("active-chart","data"),
              State("active-session","data"),
              prevent_initial_call=True)
def sync_session_to_chart(chart_id, current_session):
    """Programmatic navigation (e.g. the jump to cmp_traffic after an S2
    analyze) must move the session sub-tab with it, exactly like
    sync_tab_to_chart does for the top-level tabs."""
    scope = _session_for_chart(chart_id)
    if scope and scope != (current_session or "s1"):
        return scope
    return dash.no_update
# ------------------------------------------------------------------------

# Clientside: bump live-rec-tick whenever any live-recording action button
# is clicked. Reason: manage_live_panel's MATCH callback occasionally
# re-renders the panel before worker.status has fully committed, so the
# badge stays "IDLE" until the next 3-second interval tick. By bumping
# this Store on every click, we cause manage_live_panel to fire AGAIN
# (this time reading the now-committed worker.status -> RECORDING).
app.clientside_callback(
    """
    function(n_clicks_array, current) {
        // only bump on a REAL user click (any value > 0).
        // When manage_live_panel rebuilds the panel, all live-btns are
        // recreated with n_clicks=0. The Input value changes (e.g. [1,0,0,...]
        // -> [0,0,0,...]) but it is NOT a user click. Without this guard,
        // every rebuild re-triggered this bump -> toggle_live_tick fires ->
        // manage_live_panel via tick fires -> rebuild -> loop = visible UI
        // flicker. The guard breaks the cycle.
        var any_real_click = (n_clicks_array || []).some(function(v) {
            return typeof v === "number" && v > 0;
        });
        if (!any_real_click) {
            return window.dash_clientside.no_update;
        }
        return (current || 0) + 1;
    }
    """,
    Output("live-rec-tick", "data"),
    Input({"type":"live-btn","action": ALL, "session": ALL}, "n_clicks"),
    State("live-rec-tick", "data"),
    prevent_initial_call=True,
)






@app.callback(Output("chart-area","children"),
              Input("active-chart","data"),
              Input("trigger-rebuild","data"),
              prevent_initial_call=True)
def render_chart(chart_id, _rebuild):
    """Called only when active-chart or trigger-rebuild change. The initial
    chart-area content is built inside build_dashboard_view so this callback
    is only a refresh path. The live-recording-tick interval no longer fires
    this callback - manage_live_panel handles per-session updates instead."""
    return _get_chart_content(chart_id)


@app.callback(
    Output({"type":"live-static","session": MATCH}, "children"),
    Output({"type":"live-metrics","session": MATCH}, "children"),
    Input({"type":"live-btn","action": ALL, "session": MATCH}, "n_clicks"),
    State({"type":"live-iface","session": MATCH}, "value"),
    prevent_initial_call=True,
)
def manage_live_action(action_clicks, iface):
    """Button-only callback. Executes the worker action then rebuilds BOTH
    sub-divs of the panel (live + static). The 3-second recording tick is
    NO LONGER an input here - that responsibility moved to
    update_live_metrics_tick below, which never touches the static block.
    This is the fix for the recording-time flicker storm."""
    trig = ctx.triggered_id
    if not isinstance(trig, dict):
        return dash.no_update, dash.no_update
    session_id = trig.get("session")
    action     = trig.get("action")
    if not session_id:
        return dash.no_update, dash.no_update
    worker = LIVE_SESSIONS.get(session_id)
    if worker is None:
        return dash.no_update, dash.no_update
    if not action_clicks or not any(c for c in action_clicks if c):
        return dash.no_update, dash.no_update

    try:
        if action == "record":
            iface_to_use = iface or pick_default_wifi_interface()
            # sanity-check the interface still exists before spawning
            # tshark - the NIC may have been unplugged since the dropdown was
            # rendered, and tshark's own error is unreadable jargon.
            try:
                _valid = {i[0] for i in list_capture_interfaces()}
                if iface_to_use is not None and str(iface_to_use) not in _valid:
                    worker.error_msg = (f"Interface {iface_to_use} is no longer available. "
                                        f"Choose another one from the dropdown.")
                    return (_build_session_static_block(session_id),
                            _build_session_live_block(session_id))
            except Exception: pass
            ok, msg = worker.start(iface_to_use)
            print(f"[{session_id}] start({iface_to_use!r}) -> ok={ok}, msg={msg}")
            if not ok: worker.error_msg = msg
        elif action == "pause":
            ok, msg = worker.pause()
            print(f"[{session_id}] pause() -> ok={ok}, msg={msg}")
            if not ok: worker.error_msg = msg
        elif action == "stop":
            ok, msg = worker.stop_and_save()
            print(f"[{session_id}] stop_and_save() -> ok={ok}, msg={msg}")
            if ok:
                try:
                    worker._pending_snapshot = worker.snapshot()
                    worker._pending_snapshot["label"] = session_id
                    worker._pending_snapshot["pkts"]  = []
                    print(f"[{session_id}] snapshot staged - waiting for user to "
                          f"click ▶ Analyze in the panel")
                except Exception as e:
                    print(f"[{session_id}] snapshot prep failed: {e}")
                    import traceback; traceback.print_exc()
                    worker.error_msg = f"saved but snapshot failed: {e}"
            else:
                worker.error_msg = msg
        elif action == "analyze":
            # handle_live_analyze owns the entire analyze flow. Bail
            # out NOW (before the rebuild at the bottom of this function)
            # so we cannot race with it for control of the panel DOM.
            return dash.no_update, dash.no_update
        elif action == "discard":
            worker.reset()
            print(f"[{session_id}] discarded pending snapshot + full reset")
        elif action == "reset":
            ok, msg = worker.reset()
            print(f"[{session_id}] reset() -> ok={ok}, msg={msg}")
    except Exception as e:
        import traceback; traceback.print_exc()
        try: worker.error_msg = f"action {action!r} crashed: {e}"
        except Exception: pass

    return (_build_session_static_block(session_id),
            _build_session_live_block(session_id))


@app.callback(
    Output("live-stats-store", "data"),
    Input("live-recording-tick", "n_intervals"),
    prevent_initial_call=False,
)
def update_live_stats_store(_n):
    """FLICKER FIX: the 3-second tick no longer rebuilds HTML. It only
    publishes a small dict (status + n_pkts + duration + error) for both
    sessions to a dcc.Store. A clientside callback (registered below)
    reads the store and updates ONLY the textContent of specific span
    elements that already exist in the DOM. No tear-down, no re-paint."""
    out = {}
    for sid in ("S1", "S2"):
        worker = LIVE_SESSIONS.get(sid)
        if worker is None: continue
        try:
            s = worker.quick_stats()
            elapsed = s.get("elapsed", 0) or 0
            if elapsed < 60:    dur_str = f"{int(elapsed)}s"
            elif elapsed < 3600: dur_str = f"{int(elapsed)//60}m {int(elapsed)%60}s"
            else:               dur_str = f"{int(elapsed)//3600}h {(int(elapsed)%3600)//60}m"
            n_pkts = int(s.get("n_pkts", 0) or 0)
            out[sid] = {
                "status":   s.get("status", "idle"),
                "n_pkts":   n_pkts,
                "pkts_str": f"{n_pkts:,}" if n_pkts else "-",
                "duration": dur_str if elapsed else "-",
                "error":    s.get("error") or "",
            }
        except Exception:
            pass
    return out


# FLICKER FIX: clientside DOM textContent updates. Fires whenever
# live-stats-store changes (every ~3 seconds while on Live Recording).
# This is where the actual counter / badge / error text changes happen.
# The browser only mutates text nodes - NO element tear-down, NO re-paint
# of surrounding cards, NO Plotly re-render. Visually invisible refresh.
app.clientside_callback(
    """
    function(data) {
        if (!data) return window.dash_clientside.no_update;
        var badgeText = {
            idle:      "\u25cf IDLE",
            recording: "\u25cf RECORDING",
            paused:    "\u275a\u275a PAUSED",
            saved:     "\u2713 SAVED",
            error:     "\u2717 ERROR"
        };
        var stateColor = {
            idle:      ["#9b94b8", "rgba(155,148,184,0.10)"],
            recording: ["#a3e635", "rgba(163,230,53,0.14)"],
            paused:    ["#fbbf24", "rgba(251,191,36,0.14)"],
            saved:     ["#22d3ee", "rgba(34,211,238,0.14)"],
            error:     ["#f87171", "rgba(248,113,113,0.14)"]
        };
        var sessions = ["S1", "S2"];
        for (var i = 0; i < sessions.length; i++) {
            var sid = sessions[i];
            var s = data[sid];
            if (!s) continue;
            var pktsEl     = document.getElementById("live-pkts-"     + sid);
            var durEl      = document.getElementById("live-duration-" + sid);
            var stateTxtEl = document.getElementById("live-state-text-" + sid);
            var badgeEl    = document.getElementById("live-state-badge-"+ sid);
            var errBox     = document.getElementById("live-error-"    + sid);
            var errMsg     = document.getElementById("live-error-msg-"+ sid);
            if (pktsEl)     pktsEl.textContent     = s.pkts_str || "-";
            if (durEl)      durEl.textContent      = s.duration || "-";
            if (stateTxtEl) stateTxtEl.textContent =
                (s.status || "idle").replace(/^[a-z]/, function(c){return c.toUpperCase();});
            if (badgeEl) {
                badgeEl.textContent = badgeText[s.status] || (s.status||"").toUpperCase();
                var col = stateColor[s.status] || stateColor.idle;
                badgeEl.style.color = col[0];
                badgeEl.style.background = col[1];
                badgeEl.style.border = "1px solid " + col[0] + "55";
                badgeEl.style.textShadow =
                    (s.status === "recording" || s.status === "saved")
                    ? "0 0 6px " + col[0] + "55" : "none";
            }
            if (errBox && errMsg) {
                errMsg.textContent = s.error || "";
                errBox.style.display = s.error ? "block" : "none";
            }
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output("live-stats-bridge", "children"),
    Input("live-stats-store", "data"),
    prevent_initial_call=False,
)


# Dedicated callback for the live-recording panel's Analyze button. Split
# out of manage_live_panel so it can update active-chart + trigger-rebuild
# + s2-loaded-tick in one shot - which was the missing piece that left
# users stranded on the live-recording page after a successful analyse.
@app.callback(
    Output({"type":"live-panel","session": MATCH}, "children", allow_duplicate=True),
    Output("active-chart", "data", allow_duplicate=True),
    Output("trigger-rebuild", "data", allow_duplicate=True),
    Output("s2-loaded-tick", "data", allow_duplicate=True),
    Output("app-mode", "data", allow_duplicate=True),
    Input({"type":"live-btn","action":"analyze","session": MATCH}, "n_clicks"),
    State("trigger-rebuild", "data"),
    State("s2-loaded-tick", "data"),
    prevent_initial_call=True,
)
def handle_live_analyze(n_click, rebuild_count, s2_tick):
    trig = ctx.triggered_id
    if not isinstance(trig, dict) or not n_click:
        return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    session_id = trig.get("session")
    worker = LIVE_SESSIONS.get(session_id)
    if worker is None:
        return (dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    pending = getattr(worker, "_pending_snapshot", None)
    if pending is None:
        worker.error_msg = "Nothing staged to analyse"
        return (_build_session_panel(session_id),
                dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    if getattr(worker, "_analyzing", False):
        return (_build_session_panel(session_id),
                dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    worker._analyzing = True
    import time as _time
    _t_start = _time.time()
    try:
        _n_pkts = (pending or {}).get("n_pkts", "?")
        final_pcap = getattr(worker, "final_pcap_path", None)
        if not final_pcap or not os.path.exists(final_pcap):
            raise RuntimeError(f"saved PCAP missing on disk: {final_pcap}")
        print(f"[{session_id}] analyse START - {_n_pkts} packets, ingesting {os.path.basename(final_pcap)} via the PCAP pipeline...", flush=True)
        # Route the live recording through the SAME ingest path PCAP-upload
        # uses, so the live session ends up with run_advanced_threats output
        # (sess["threats"]), the full pkts list, and dns_amp_per_src - none
        # of which the LiveCaptureWorker snapshot dict provides.
        ok, msg = _ingest_pcap_from_path(final_pcap, session_id)
        print(f"[{session_id}] _ingest_pcap_from_path -> ok={ok}, msg={msg}, took {_time.time()-_t_start:.1f}s", flush=True)
        if not ok:
            raise RuntimeError(msg)
        worker._pending_snapshot = None
        worker._analyzing = False
        print(f"[{session_id}] analyse COMPLETE in {_time.time()-_t_start:.1f}s - FIGS now has {len(FIGS)} figures", flush=True)
    except Exception as e:
        print(f"[{session_id}] analyse failed: {e}")
        import traceback; traceback.print_exc()
        worker.error_msg = f"analysis failed: {e}"
        worker._analyzing = False
        return (_build_session_panel(session_id),
                dash.no_update, dash.no_update, dash.no_update, dash.no_update)
    # Success path: leave the live-recording page so the user actually
    # SEES the new session. Comparison view if S2 is now populated,
    # otherwise the talkers view of S1.
    next_chart = "cmp_traffic" if (S1 is not None and S2 is not None) else "talkers_s1"
    next_s2_tick = (s2_tick or 0) + 1 if session_id == "S2" else (s2_tick or 0)
    return (_build_session_panel(session_id),
            next_chart,
            (rebuild_count or 0) + 1,
            next_s2_tick,
            "dashboard")


# UI-5: live-recording-tick only needs to fire when the live recording
# page is the active chart. Letting it run on every other page wastes
# ~20 callbacks/min and can briefly flicker plotly figures during
# scroll. The Interval is disabled whenever active-chart isn't
# live_recording so the dashboard is silent on every other view.
@app.callback(
    Output("live-recording-tick", "disabled"),
    Input("active-chart", "data"),
    prevent_initial_call=False,
)
def toggle_live_tick(active_chart):
    """Run the 3-second refresh interval whenever the user is on
    the Live Recording page. The old version ALSO depended on live-rec-tick
    (bumped clientside on every button click) and re-checked worker.status
    to short-circuit when nothing was actively recording. That created a
    race: the bump arrived BEFORE manage_live_action had updated
    worker.status, so the gate read "idle" and disabled the tick - then
    never woke up again because its only Inputs were active-chart and
    live-rec-tick, neither of which moved as a result of the action. Net
    effect: counters froze at 0s/0 packets after clicking Record. The
    simpler gate below has zero races; cost is ~20 idle ticks/minute on
    the Live Recording page when no worker is recording (negligible)."""
    return active_chart != "live_recording"


import socket



@app.callback(Output("ip-history-output","children"),
              Input("ip-history-search-btn","n_clicks"),
              Input("ip-history-input","n_submit"),
              State("ip-history-input","value"),
              prevent_initial_call=True)
def build_ip_history_heatmap(_n_clicks, _n_submit, ip_value):
    """Render per-session heatmaps for the requested IP. Triggered either by
    the Search button click or by Enter in the input."""
    if not ip_value or not isinstance(ip_value, str):
        return html.Div("Please enter an IP address.",
            style={"color":INK_MUTE,"padding":"30px 10px","textAlign":"center"})
    ip_addr = ip_value.strip()
    if not ip_addr:
        return html.Div("Please enter an IP address.",
            style={"color":INK_MUTE,"padding":"30px 10px","textAlign":"center"})
    # reject invalid IP formats up-front so the user gets a real
    # error instead of a misleading "No DNS activity for <garbage>" per-session.
    import ipaddress as _ipa
    try:
        _ipa.ip_address(ip_addr)
    except ValueError:
        return html.Div([
            html.Span("Invalid IP format: ", style={"color":INK_DIM}),
            html.Span(ip_addr, style={"color":AMBER,"fontFamily":"'JetBrains Mono', monospace"}),
            html.Div("Enter an IPv4 (e.g. 192.168.1.10) or IPv6 (e.g. fe80::1) address.",
                     style={"color":INK_MUTE,"fontSize":"11.5px","marginTop":"8px"}),
        ], style={"color":INK_DIM,"padding":"30px 20px","textAlign":"center",
                  "background":"rgba(251,191,36,0.06)","borderRadius":"10px",
                  "border":f"1px solid rgba(251,191,36,0.25)"})

    cols = []
    for label_text, session in [("Session 1", S1), ("Session 2", S2)]:
        if session is None:
            continue
        fig, n_queries = _build_ip_history_session_fig(session, ip_addr)
        if fig is None:
            cols.append(dbc.Col(html.Div([
                html.Div(label_text,
                    style={"color":INK_MUTE,"fontSize":"11px",
                           "fontFamily":"'JetBrains Mono', monospace",
                           "marginBottom":"6px","textTransform":"uppercase",
                           "letterSpacing":"0.18em"}),
                html.Div(f"No DNS activity for {ip_addr} in {label_text}.",
                    style={"color":INK_DIM,"padding":"30px 10px",
                           "background":"rgba(255,255,255,0.02)",
                           "border":f"1px solid {GLASS_BORDER}",
                           "borderRadius":"10px","textAlign":"center",
                           "fontSize":"0.9rem"}),
            ]), md=6))
        else:
            cols.append(dbc.Col(html.Div([
                html.Div(label_text,
                    style={"color":INK_MUTE,"fontSize":"11px",
                           "fontFamily":"'JetBrains Mono', monospace",
                           "marginBottom":"6px","textTransform":"uppercase",
                           "letterSpacing":"0.18em"}),
                dcc.Graph(figure=fig, config={"displayModeBar":False}),
            ]), md=6))

    if not cols:
        return html.Div(
            f"No sessions loaded. Load a PCAP first, then look up {ip_addr}.",
            style={"color":INK_MUTE,"padding":"40px 10px","textAlign":"center"})

    return dbc.Row(cols)


def _find_free_port(start=8050, end=8100):
    for p in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("No free port in range")


# if all preferred ports are busy (another Jupyter/Dash app running
# on the same machine), let the OS pick any free port instead of crashing.
try:
    PORT = _find_free_port()
except RuntimeError:
    print("WARN: ports 8050-8099 all busy - letting OS pick a free one", flush=True)
    _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _s.bind(("127.0.0.1", 0))
    PORT = _s.getsockname()[1]
    _s.close()
print("=" * 52)
print(f"  Dashboard -> http://127.0.0.1:{PORT}")
print("  Stop: press Interrupt (square button) in Jupyter")
print("=" * 52)
app.run(debug=False, port=PORT, use_reloader=False, jupyter_mode="external")


# ==== notebook cell 49 ====

# ==== VM client integration (stage G) ====
# The dashboard can act as a client of the analysis VM: upload the
# source PCAP over HTTP (scp remains the fallback) and load a finished
# analysis back for remote viewing. The logic lives in
# server/dashboard_client.py so this auto-generated module stays a thin,
# in-sync wrapper. Optional add-on - the local analysis path never
# depends on it.
import os as _os_vmclient, sys as _sys_vmclient
try:
    _base_vmclient = _os_vmclient.path.dirname(_os_vmclient.path.abspath(__file__))
except NameError:
    _base_vmclient = _os_vmclient.getcwd()
for _cand_vmclient in (_base_vmclient, _os_vmclient.path.dirname(_base_vmclient),
                       _os_vmclient.getcwd(),
                       _os_vmclient.path.dirname(_os_vmclient.getcwd())):
    if _os_vmclient.path.isdir(_os_vmclient.path.join(_cand_vmclient, 'server')) \
            and _cand_vmclient not in _sys_vmclient.path:
        _sys_vmclient.path.insert(0, _cand_vmclient)
try:
    from server.dashboard_client import (load_session_from_api,
                                          upload_session_via_api)
    print('VM client helpers ready (upload_session_via_api, load_session_from_api)')
except Exception as _e_vmclient:
    load_session_from_api = None
    upload_session_via_api = None
    print(f'VM client helpers unavailable ({_e_vmclient}); local + scp paths unaffected')

"""Re-measure the size ratios the ecosystem plan is built on.

Stage A task from ARCHITECTURE_HE.md (sections 1, 2.9, 10): the plan's
headline numbers - ~590 MB/hour of raw PCAP, ~368x reduction for the
gzipped field export - were measured on a single 135-second capture.
Run this against a long capture of your own network to confirm or
correct them:

    python tools/measure_pipeline_ratios.py path/to/long_capture.pcapng

The export is the UNION of the dashboard loader's field set and the
advanced engines' field set (~30 fields), i.e. exactly the text the VM
keeps forever as the historical index (decision IDX-04). Standard
library only; tshark must be resolvable (PATH, or the TSHARK env var,
or the Wireshark folders that llm_judge already knows how to find).

Options:
    --keep    also write <capture>.fields.tsv.gz next to the input
    --json    print a machine-readable summary as the last line
"""
import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile

# The dashboard loader's field set (app/dashboard_module.py,
# _analyze_pcap_tshark) followed by the advanced engines' additions
# (_ADV_TSHARK_FIELDS). Keep both in sync with the code if they evolve.
BASE_FIELDS = [
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
ADV_EXTRA_FIELDS = [
    "dns.qry.type",
    "arp.opcode", "arp.dst.proto_ipv4",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3", "tls.handshake.ja4",
    "dhcp.option.dhcp_server_id",
]
UNION_FIELDS = BASE_FIELDS + ADV_EXTRA_FIELDS


def find_tshark():
    """TSHARK env var, PATH, then the Wireshark folders llm_judge adds."""
    explicit = os.environ.get("TSHARK")
    if explicit and os.path.isfile(explicit):
        return explicit
    found = shutil.which("tshark")
    if found:
        return found
    try:  # side effect: extends PATH with standard Wireshark locations
        sys.path.insert(0, os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        import llm_judge  # noqa: F401
        found = shutil.which("tshark")
    except Exception:
        found = None
    return found


def measure(pcap_path, tshark, keep=False):
    """Stream the union field export, gzip it, and return the numbers."""
    cmd = [tshark, "-r", pcap_path, "-n", "-T", "fields",
           "-E", "header=n", "-E", "separator=\t",
           "-E", "occurrence=f", "-E", "quote=n"]
    for f in UNION_FIELDS:
        cmd += ["-e", f]

    raw_bytes = os.path.getsize(pcap_path)
    n_lines = 0
    fields_bytes = 0
    first_ts = last_ts = None

    gz_path = (pcap_path + ".fields.tsv.gz") if keep else None
    tmp = None
    if gz_path is None:
        tmp = tempfile.NamedTemporaryFile(
            suffix=".tsv.gz", delete=False,
            dir=os.path.dirname(os.path.abspath(pcap_path)) or ".")
        gz_path = tmp.name
        tmp.close()

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True,
                            encoding="utf-8", errors="replace")
    try:
        # compresslevel=6 matches the plain `gzip` CLI default the plan
        # was measured with.
        with gzip.open(gz_path, "wt", encoding="utf-8",
                       compresslevel=6) as gz:
            for line in proc.stdout:
                n_lines += 1
                fields_bytes += len(line.encode("utf-8", errors="replace"))
                gz.write(line)
                ts_str = line.split("\t", 1)[0]
                try:
                    ts = float(ts_str)
                except ValueError:
                    continue
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
        rc = proc.wait()
    finally:
        if proc.poll() is None:
            proc.kill()
    if rc != 0:
        raise RuntimeError(f"tshark exited {rc} on {pcap_path}")
    if n_lines == 0:
        raise RuntimeError(f"tshark returned 0 rows from {pcap_path}")

    gz_bytes = os.path.getsize(gz_path)
    if tmp is not None:
        os.unlink(gz_path)
        gz_path = None

    duration = (last_ts - first_ts) if (first_ts is not None
                                        and last_ts is not None) else 0.0
    return {
        "pcap": pcap_path,
        "packets": n_lines,
        "duration_s": round(duration, 3),
        "raw_bytes": raw_bytes,
        "fields_bytes": fields_bytes,
        "fields_gz_bytes": gz_bytes,
        "ratio_raw_over_fields": round(raw_bytes / fields_bytes, 2),
        "ratio_raw_over_fields_gz": round(raw_bytes / gz_bytes, 2),
        "kept_gz": gz_path,
    }


def _mb(n):
    return n / (1024 * 1024)


def report(m):
    print(f"\n{m['pcap']}")
    print(f"  packets            {m['packets']:,}")
    print(f"  duration           {m['duration_s']:,.1f} s")
    print(f"  raw pcap           {_mb(m['raw_bytes']):10.2f} MB")
    print(f"  fields (tsv)       {_mb(m['fields_bytes']):10.2f} MB   "
          f"({m['ratio_raw_over_fields']}x smaller than raw)")
    print(f"  fields gzipped     {_mb(m['fields_gz_bytes']):10.2f} MB   "
          f"({m['ratio_raw_over_fields_gz']}x smaller than raw)")
    if m["duration_s"] >= 60:
        per_h = 3600.0 / m["duration_s"]
        print(f"  per hour of capture: raw {_mb(m['raw_bytes']) * per_h:,.1f} MB"
              f" | fields.gz {_mb(m['fields_gz_bytes']) * per_h:,.2f} MB")
    else:
        print("  (capture shorter than 60s - per-hour extrapolation "
              "skipped; the plan's numbers need a LONG capture)")
    if m["kept_gz"]:
        print(f"  kept: {m['kept_gz']}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Measure raw-PCAP vs field-export sizes (spec stage A)")
    ap.add_argument("pcaps", nargs="+", help=".pcap/.pcapng files")
    ap.add_argument("--keep", action="store_true",
                    help="write <capture>.fields.tsv.gz next to the input")
    ap.add_argument("--json", action="store_true",
                    help="print a JSON summary as the last line")
    args = ap.parse_args(argv)

    tshark = find_tshark()
    if not tshark:
        print("error: tshark not found (install Wireshark, or set the "
              "TSHARK env var)", file=sys.stderr)
        return 2

    results = []
    for p in args.pcaps:
        if not os.path.isfile(p):
            print(f"error: no such file: {p}", file=sys.stderr)
            return 2
        m = measure(p, tshark, keep=args.keep)
        results.append(m)
        report(m)
    if args.json:
        print(json.dumps(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())

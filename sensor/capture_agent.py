"""Capture agent - Tier 0 (spec sections 5.1, 11, 12). Stdlib only.

The capture loop (tshark) is isolated behind ``run()``; everything that
decides what happens to a chunk - upload, spool, overflow, gap - lives
in pure methods driven by ``handle_chunk()``, so the whole policy is
unit-tested without tshark or a network.

Config (env, all overridable on the constructor):
    NETSEC_INGEST_URL          upload target, e.g. http://<vm>:8766
    NETSEC_SENSOR_ID / _SECRET credentials (deploy/create_sensor.py)
    NETSEC_CAPTURE_IFACE       interface to capture on
    NETSEC_CAPTURE_DIR         where chunks + spool live
    NETSEC_CHUNK_SECONDS       ring-buffer chunk duration (default 900)
    NETSEC_RING_FILES          ring-buffer file count (default 96 = ~24h)
    NETSEC_SPOOL_CAP_GB        spool ceiling before oldest is dropped
    NETSEC_INFRA_DSTS          telemetry dsts to exclude from capture
    NETSEC_SESSION_KIND        prod | test  (decision IDX-11)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "tools"))

import upload_pcap  # noqa: E402

GB = 1024 ** 3


def build_capture_filter(infra_dsts, upload_port=None, extra=None):
    """A tcpdump/BPF filter that EXCLUDES the agent's own telemetry flow
    (spec 12.2 layer 0). Each declared destination is excluded only in
    conjunction with the upload port, so ordinary traffic to that host on
    other ports is still captured - the exclusion is narrow and explicit.
    Returns "" (capture everything) when nothing is declared."""
    clauses = []
    for dst in sorted({d.strip() for d in (infra_dsts or []) if d.strip()}):
        host = f"host {dst}"
        if upload_port:
            clauses.append(f"({host} and port {int(upload_port)})")
        else:
            clauses.append(host)
    if extra:
        clauses.append(f"({extra})")
    if not clauses:
        return ""
    return "not (" + " or ".join(clauses) + ")"


class CaptureAgent:
    def __init__(self, url=None, sensor=None, secret=None, capture_dir=None,
                 infra_dsts=None, kind=None, spool_cap_gb=None,
                 upload_fn=None, manifest=None, gaps_path=None):
        e = os.environ
        self.url = url or e.get("NETSEC_INGEST_URL")
        self.sensor = sensor or e.get("NETSEC_SENSOR_ID")
        self.secret = secret or e.get("NETSEC_SENSOR_SECRET")
        self.capture_dir = capture_dir or e.get(
            "NETSEC_CAPTURE_DIR",
            os.path.expanduser("~/.netsec/capture"))
        self.kind = kind or e.get("NETSEC_SESSION_KIND", "prod")
        if infra_dsts is None:
            infra_dsts = [d for d in e.get("NETSEC_INFRA_DSTS", "").split(",")
                          if d.strip()]
        self.infra_dsts = infra_dsts
        self.spool_cap = int(float(spool_cap_gb
                                   or e.get("NETSEC_SPOOL_CAP_GB", "20")) * GB)
        self.spool_dir = os.path.join(self.capture_dir, "spool")
        self.manifest = manifest or e.get(
            "NETSEC_MANIFEST",
            os.path.join(self.capture_dir, "telemetry.jsonl"))
        self.gaps_path = gaps_path or os.path.join(self.capture_dir,
                                                   "gaps.jsonl")
        self._upload_fn = upload_fn or upload_pcap.upload_file
        os.makedirs(self.spool_dir, exist_ok=True)

    # ---- per-chunk policy (pure, tested) --------------------------------

    def handle_chunk(self, path):
        """Upload a freshly closed chunk; spool a COPY on failure. Returns
        a dict describing the outcome.

        The chunk file itself belongs to tshark's ring buffer (it holds
        the raw locally for N days and recycles it), so the agent never
        moves or deletes it - on failure it copies the bytes into its own
        spool, which it does own and caps. Re-upload across runs is
        harmless: the ingest API is idempotent by sha256."""
        if not os.path.isfile(path):
            return {"action": "missing", "path": path}
        result = self._try_upload(path)
        if result["ok"]:
            self._drain_spool()             # link is up - flush backlog
            return {"action": "uploaded", "path": path,
                    "session_id": result["session_id"],
                    "duplicate": result["duplicate"]}
        dest = os.path.join(self.spool_dir, os.path.basename(path))
        shutil.copy2(path, dest)
        self._enforce_spool_cap()
        return {"action": "spooled", "path": dest, "error": result["error"]}

    def _try_upload(self, path):
        try:
            return self._upload_fn(
                path, self.url, self.sensor, self.secret, kind=self.kind,
                manifest=self.manifest)
        except Exception as e:      # a broken uploader must never crash
            return {"ok": False, "error": str(e), "session_id": None,
                    "duplicate": False, "status": None}

    def _drain_spool(self):
        drained = 0
        for name in sorted(os.listdir(self.spool_dir)):
            sp = os.path.join(self.spool_dir, name)
            if not os.path.isfile(sp):
                continue
            if self._try_upload(sp)["ok"]:
                os.unlink(sp)
                drained += 1
            else:
                break                # still down - stop, keep order
        return drained

    def _spool_files(self):
        files = [os.path.join(self.spool_dir, n)
                 for n in os.listdir(self.spool_dir)]
        files = [f for f in files if os.path.isfile(f)]
        return sorted(files, key=lambda f: os.path.getmtime(f))

    def _enforce_spool_cap(self):
        """Drop the oldest spooled chunks while over the cap, recording a
        gap for each dropped file so silence and no-data stay distinct
        (spec section 11)."""
        files = self._spool_files()
        total = sum(os.path.getsize(f) for f in files)
        dropped = 0
        while total > self.spool_cap and files:
            victim = files.pop(0)
            size = os.path.getsize(victim)
            self._write_gap(victim, "spool_overflow")
            os.unlink(victim)
            total -= size
            dropped += 1
        return dropped

    def _write_gap(self, path, reason):
        rec = {"path": os.path.basename(path),
               "size_bytes": os.path.getsize(path)
               if os.path.exists(path) else None,
               "reason": reason,
               "at": datetime.now(timezone.utc).isoformat(
                   timespec="seconds")}
        with open(self.gaps_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    # ---- capture loop (tshark) ------------------------------------------

    def tshark_cmd(self, interface, chunk_seconds, ring_files):
        prefix = os.path.join(self.capture_dir, "chunk")
        cmd = ["tshark", "-i", interface, "-w", prefix, "-b",
               f"duration:{int(chunk_seconds)}", "-b",
               f"files:{int(ring_files)}"]
        bpf = build_capture_filter(self.infra_dsts, upload_port=self._port())
        if bpf:
            cmd += ["-f", bpf]
        return cmd

    def _port(self):
        try:
            import urllib.parse
            return urllib.parse.urlsplit(self.url).port
        except Exception:
            return None

    def run(self, interface=None, chunk_seconds=None, ring_files=None,
            poll_s=5):
        """Launch the ring buffer and upload each chunk as it closes.
        A chunk is 'closed' when tshark starts writing the next file, so
        we upload any chunk that is not the newest on each poll."""
        interface = interface or os.environ.get("NETSEC_CAPTURE_IFACE")
        chunk_seconds = chunk_seconds or int(os.environ.get(
            "NETSEC_CHUNK_SECONDS", "900"))
        ring_files = ring_files or int(os.environ.get(
            "NETSEC_RING_FILES", "96"))
        if not interface:
            raise SystemExit("NETSEC_CAPTURE_IFACE (or --interface) required")
        required = {"url": "NETSEC_INGEST_URL", "sensor": "NETSEC_SENSOR_ID",
                    "secret": "NETSEC_SENSOR_SECRET"}
        for attr, env_name in required.items():
            if not getattr(self, attr):
                raise SystemExit(f"{env_name} is required")
        cmd = self.tshark_cmd(interface, chunk_seconds, ring_files)
        print(f"[agent] {' '.join(cmd)}", flush=True)
        proc = subprocess.Popen(cmd)
        seen = set()
        try:
            while proc.poll() is None:
                time.sleep(poll_s)
                chunks = sorted(
                    (os.path.join(self.capture_dir, n)
                     for n in os.listdir(self.capture_dir)
                     if n.startswith("chunk") and "spool" not in n),
                    key=lambda f: os.path.getmtime(f))
                for closed in chunks[:-1]:     # all but the newest (open) one
                    if closed in seen:
                        continue
                    seen.add(closed)
                    print(f"[agent] {self.handle_chunk(closed)}", flush=True)
        except KeyboardInterrupt:
            proc.terminate()
            print("[agent] stopped", flush=True)
        finally:
            if proc.poll() is None:
                proc.terminate()


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetSec capture agent (Tier 0)")
    ap.add_argument("--interface", default=None)
    ap.add_argument("--chunk-seconds", type=int, default=None)
    ap.add_argument("--ring-files", type=int, default=None)
    args = ap.parse_args(argv)
    CaptureAgent().run(interface=args.interface,
                       chunk_seconds=args.chunk_seconds,
                       ring_files=args.ring_files)
    return 0


if __name__ == "__main__":
    sys.exit(main())

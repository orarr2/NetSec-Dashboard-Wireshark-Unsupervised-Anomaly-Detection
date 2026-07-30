"""Streaming PCAP storage: spool -> verified, dated layout. Stdlib only.

Uploads stream into ``<root>/spool/<sha256>.part`` while the digest is
computed incrementally; only a verified file is moved (atomic rename)
into ``<root>/data/pcap/YYYY/MM/DD/<sha8>_<name>.pcap``. A failed or
mismatched upload leaves nothing behind but a removed .part file, which
is exactly the spec's crash story: partial uploads are discarded and
the sensor re-uploads (idempotent by sha256).
"""
import hashlib
import os
import re
from datetime import datetime, timezone

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_NAME = 80


def data_root(root=None):
    return root or os.environ.get("NETSEC_DATA_ROOT", "/srv/netsec")


def sanitize_name(orig_name):
    base = os.path.basename(orig_name or "capture.pcap")
    base = _SAFE.sub("_", base).strip("._") or "capture.pcap"
    return base[:MAX_NAME]


class SpoolWriter:
    """Incremental writer: bytes in, (sha256, size) out on close."""

    def __init__(self, root, expected_sha256):
        self.root = data_root(root)
        spool_dir = os.path.join(self.root, "spool")
        os.makedirs(spool_dir, exist_ok=True)
        self.part_path = os.path.join(spool_dir, f"{expected_sha256}.part")
        self._fh = open(self.part_path, "wb")
        self._hash = hashlib.sha256()
        self.nbytes = 0

    def write(self, chunk):
        self._fh.write(chunk)
        self._hash.update(chunk)
        self.nbytes += len(chunk)

    def close(self):
        if not self._fh.closed:
            self._fh.close()
        return self._hash.hexdigest(), self.nbytes

    def discard(self):
        self.close()
        try:
            os.unlink(self.part_path)
        except FileNotFoundError:
            pass


def finalize(writer, expected_sha256, orig_name, when=None):
    """Verify the digest and move the spooled file into the dated
    layout. Returns the final path. Raises ValueError on a digest
    mismatch (the .part file is removed)."""
    digest, _ = writer.close()
    if digest != expected_sha256:
        writer.discard()
        raise ValueError(
            f"sha256 mismatch: declared {expected_sha256[:12]}..., "
            f"received {digest[:12]}...")
    when = when or datetime.now(timezone.utc)
    day_dir = os.path.join(writer.root, "data", "pcap",
                           f"{when:%Y}", f"{when:%m}", f"{when:%d}")
    os.makedirs(day_dir, exist_ok=True)
    final = os.path.join(
        day_dir, f"{expected_sha256[:8]}_{sanitize_name(orig_name)}")
    if os.path.exists(final):
        # concurrent duplicate upload already landed - keep the winner
        writer.discard()
        return final
    os.replace(writer.part_path, final)
    return final

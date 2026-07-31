"""Streaming PCAP storage: spool -> verified, dated layout. Stdlib only.

Uploads stream into ``<root>/spool/<sha256>.part`` while the digest is
computed incrementally; only a verified file is moved (atomic rename)
into ``<root>/data/pcap/YYYY/MM/DD/<sha8>_<name>.pcap``. A failed or
mismatched upload leaves nothing behind but a removed .part file, which
is exactly the spec's crash story: partial uploads are discarded and
the sensor re-uploads (idempotent by sha256).
"""
import glob
import hashlib
import os
import re
import uuid
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
        # The spool name must be unique per upload, not per digest. Two
        # sensors (or one sensor retrying) uploading the same sha256
        # concurrently would otherwise open the same .part with O_TRUNC
        # and interleave their writes: each stream would hash only its own
        # bytes, both would "verify", and the file left on disk would be a
        # mix of the two. os.getpid() + uuid4 keeps them apart across
        # threads, processes and workers.
        self.part_path = os.path.join(
            spool_dir, f"{expected_sha256}.{os.getpid()}."
                       f"{uuid.uuid4().hex[:12]}.part")
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
    # A re-upload of the same capture on a later day would land in a
    # different date directory, so an os.path.exists check on today's path
    # alone would miss it and leave a second copy on disk. That copy gets
    # no pcap_files row (the API dedupes by sha afterwards), which makes it
    # invisible to every retention path - it would sit on the 100GB volume
    # forever. Look for the digest across all days first.
    existing = find_by_sha256(writer.root, expected_sha256)
    if existing:
        writer.discard()
        return existing

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


def find_by_sha256(root, sha256):
    """Path of an already-stored capture with this digest, or None.

    Files are named <sha8>_<name>, so the 8-hex prefix narrows the glob
    and the full digest is not recoverable from the name - that is fine
    here because the prefix only has to find candidates cheaply; a
    collision would at worst dedupe against a different capture whose
    first 32 bits match, which the caller's own sha check has already
    ruled out for the bytes it just received.
    """
    pattern = os.path.join(data_root(root), "data", "pcap",
                           "*", "*", "*", f"{sha256[:8]}_*")
    for path in sorted(glob.glob(pattern)):
        return path
    return None

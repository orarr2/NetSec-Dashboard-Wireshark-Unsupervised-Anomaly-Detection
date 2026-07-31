"""Retention - the storage tier's daily housekeeping (spec section 3.3,
decisions IDX-01..04). Stdlib only.

What one cycle does, in order:

1. Back up the history DB (sqlite backup API) and prune old backups.
2. Age purge: raw PCAPs older than RETENTION_PCAP_DAYS are deleted from
   disk. Before deleting, the permanent compressed field export is
   backfilled if missing (IDX-04) - the raw file never disappears
   before its historical index exists, unless tshark is unavailable
   (logged, and the purge of that file is SKIPPED rather than losing
   the index silently).
3. Watermark purge: while the data filesystem is above
   RETENTION_WATERMARK_PCT, the oldest remaining raw PCAPs are purged
   the same way, age notwithstanding.
4. On the 1st of the month: VACUUM.

DB rows are never deleted - pcap_files.deleted_at is stamped, so history
always knows what was analyzed and when the raw evidence expired.
Deleting an analyzed file is not a capture gap; no gap rows are written
here (spec section 12/11 distinction).

Run modes:  python -m server.retention --once [--dry-run]   (cron)
            python -m server.retention                      (daemon loop)
"""
import argparse
import os
import shutil
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import db, storage
from .fields_export import export_fields


def _cfg_int(name, default):
    try:
        return int(float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return int(default)


def _fields_out_path(root, row):
    received = (row.get("received_at") or "")[:7]  # YYYY-MM
    ym = received.split("-") if "-" in received else ["0000", "00"]
    return os.path.join(root, "data", "fields", ym[0], ym[1],
                        f"{row['sha256'][:8]}.tsv.gz")


def ensure_fields_index(conn, row, root, dry_run=False, export_fn=None):
    """Make sure the permanent field export exists for this pcap row.
    Returns the fields path, or None when it cannot be produced."""
    if os.environ.get("KEEP_FIELDS_FOREVER", "1").lower() in ("0", "false"):
        return "disabled"
    export_fn = export_fn or export_fields
    out = _fields_out_path(root, row)
    if row.get("fields_path") and os.path.isfile(row["fields_path"]):
        return row["fields_path"]
    if os.path.isfile(out) or (not dry_run
                               and export_fn(row["storage_path"], out)):
        conn.execute("UPDATE pcap_files SET fields_path=? WHERE id=?",
                     (out, row["id"]))
        conn.commit()
        return out
    return out if dry_run else None


def _purge_row(conn, row, root, dry_run, export_fn, reason):
    fields = ensure_fields_index(conn, row, root, dry_run, export_fn)
    if fields is None:
        print(f"[retention] SKIP {row['sha256'][:8]} ({reason}): fields "
              "index not producible - raw kept", flush=True)
        return False
    if dry_run:
        print(f"[retention] would purge {row['sha256'][:8]} ({reason})",
              flush=True)
        return True
    try:
        os.unlink(row["storage_path"])
    except FileNotFoundError:
        pass
    conn.execute("UPDATE pcap_files SET deleted_at=? WHERE id=?",
                 (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  row["id"]))
    conn.commit()
    print(f"[retention] purged {row['sha256'][:8]} ({reason})", flush=True)
    return True


def purge_by_age(conn, root, days=None, dry_run=False, export_fn=None):
    days = days if days is not None else _cfg_int("RETENTION_PCAP_DAYS", 7)
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=days)).isoformat(timespec="seconds")
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM pcap_files WHERE deleted_at IS NULL AND"
        " received_at < ? ORDER BY received_at", (cutoff,))]
    return sum(_purge_row(conn, r, root, dry_run, export_fn,
                          f"age>{days}d") for r in rows)


def disk_used_pct(root):
    usage = shutil.disk_usage(root)
    return usage.used / usage.total * 100.0


def purge_by_watermark(conn, root, pct=None, dry_run=False, export_fn=None,
                       usage_fn=None):
    pct = pct if pct is not None else _cfg_int("RETENTION_WATERMARK_PCT", 85)
    usage_fn = usage_fn or disk_used_pct
    purged = 0
    # A row whose purge fails keeps deleted_at NULL, so it stays the oldest
    # candidate forever. Stopping on it (or retrying it) would let one
    # unexportable pcap - a truncated chunk, a DB restored onto a fresh
    # volume - disable the emergency valve permanently while the disk
    # climbs to ENOSPC. Skip it for this cycle and keep reclaiming; the
    # SKIP line in _purge_row still reports it every run.
    attempted = set()
    while usage_fn(root) > pct:
        if attempted:
            marks = ",".join("?" * len(attempted))
            row = conn.execute(
                "SELECT * FROM pcap_files WHERE deleted_at IS NULL"
                f" AND id NOT IN ({marks})"
                " ORDER BY received_at LIMIT 1", tuple(attempted)).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM pcap_files WHERE deleted_at IS NULL"
                " ORDER BY received_at LIMIT 1").fetchone()
        if row is None:
            if attempted:
                print(f"[retention] disk above {pct}% and every remaining "
                      f"pcap failed to purge ({len(attempted)} skipped) - "
                      "investigate the SKIP lines above", flush=True)
            else:
                print(f"[retention] disk above {pct}% but no raw pcaps left "
                      "to purge - reports/DB are never touched", flush=True)
            break
        row = dict(row)
        if not _purge_row(conn, row, root, dry_run, export_fn,
                          f"disk>{pct}%"):
            attempted.add(row["id"])
            continue
        purged += 1
        if dry_run:      # a dry run frees nothing; one report is enough
            break
    return purged


def backup_db(conn, root, keep=None, dry_run=False, now=None):
    keep = keep if keep is not None else _cfg_int("RETENTION_BACKUP_KEEP", 14)
    now = now or datetime.now(timezone.utc)
    bdir = os.path.join(root, "db", "backups")
    os.makedirs(bdir, exist_ok=True)
    dest_path = os.path.join(bdir, f"netsec-{now:%Y%m%d}.db")
    if not dry_run:
        dest = sqlite3.connect(dest_path)
        try:
            conn.backup(dest)
        finally:
            dest.close()
    backups = sorted(f for f in os.listdir(bdir)
                     if f.startswith("netsec-") and f.endswith(".db"))
    pruned = 0
    for old in backups[:-keep] if keep > 0 else []:
        if not dry_run:
            os.unlink(os.path.join(bdir, old))
        pruned += 1
    return dest_path, pruned


def run_cycle(conn=None, root=None, dry_run=False, export_fn=None,
              usage_fn=None, now=None):
    """One full housekeeping pass. Returns a summary dict."""
    own = conn is None
    conn = conn or db.connect()
    root = storage.data_root(root)
    now = now or datetime.now(timezone.utc)
    try:
        backup_path, pruned = backup_db(conn, root, dry_run=dry_run, now=now)
        summary = {
            "backup": backup_path, "backups_pruned": pruned,
            "purged_age": purge_by_age(conn, root, dry_run=dry_run,
                                       export_fn=export_fn),
            "purged_watermark": purge_by_watermark(
                conn, root, dry_run=dry_run, export_fn=export_fn,
                usage_fn=usage_fn),
            "vacuum": False,
        }
        if not dry_run:
            # nightly baseline recompute from prod history (spec 10, stage
            # ט); best-effort so a baseline error never blocks purging
            try:
                from . import baseline
                summary["baselines"] = baseline.compute_baselines(conn,
                                                                  now=now)
            except Exception as e:
                print(f"[retention] baseline recompute skipped: {e}",
                      flush=True)
        if now.day == 1 and not dry_run:
            conn.execute("VACUUM")
            summary["vacuum"] = True
        hb = os.environ.get("NETSEC_HEARTBEAT_URL", "").strip()
        if hb and not dry_run:
            try:      # dead-man's-switch ping - silence means trouble
                urllib.request.urlopen(hb, timeout=10).read()
            except Exception as e:
                print(f"[retention] heartbeat ping failed: {e}", flush=True)
        print(f"[retention] cycle done: {summary}", flush=True)
        return summary
    finally:
        if own:
            conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Storage retention cycle")
    ap.add_argument("--once", action="store_true",
                    help="run one cycle and exit (for cron)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be purged, delete nothing")
    args = ap.parse_args(argv)
    if args.once or args.dry_run:
        run_cycle(dry_run=args.dry_run)
        return 0
    interval = _cfg_int("RETENTION_INTERVAL_S", 86400)
    print(f"[retention] daemon mode, every {interval}s", flush=True)
    while True:
        try:
            run_cycle()
        except Exception as e:
            print(f"[retention] cycle FAILED (next attempt in {interval}s):"
                  f" {e}", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())

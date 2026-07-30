"""Create a sensor identity in the history DB (spec section 9.2 step 5).

    python deploy/create_sensor.py <name> [--db PATH]

Prints the two credentials ONCE - they are not recoverable later (the
API token is stored only as a hash). Copy them into the sensor's env:

    NETSEC_SENSOR_ID      the name given here
    NETSEC_SENSOR_SECRET  signs uploads (HMAC)
    NETSEC_API_TOKEN      bearer token for read endpoints

Revoking a compromised sensor is one SQL statement, as the spec
promises:  UPDATE sensors SET revoked_at = datetime('now') WHERE name = ?
"""
import argparse
import os
import secrets
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import auth, db  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Register a sensor and print its credentials once")
    ap.add_argument("name", help="Sensor name, e.g. laptop / pi5")
    ap.add_argument("--db", default=None,
                    help="History DB path (default: NETSEC_DB or "
                         "$NETSEC_DATA_ROOT/db/netsec.db)")
    args = ap.parse_args(argv)

    token = secrets.token_urlsafe(32)
    secret = secrets.token_hex(32)

    conn = db.connect(args.db)
    try:
        db.create_sensor(conn, args.name, auth.hash_token(token), secret)
    except sqlite3.IntegrityError:
        print(f"error: sensor '{args.name}' already exists - pick another "
              "name, or revoke and delete the old row first",
              file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(f"# sensor '{args.name}' registered - shown ONCE, store safely")
    print(f"NETSEC_SENSOR_ID={args.name}")
    print(f"NETSEC_SENSOR_SECRET={secret}")
    print(f"NETSEC_API_TOKEN={token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

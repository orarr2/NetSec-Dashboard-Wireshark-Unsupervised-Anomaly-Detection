"""VM-side ingest and history layer (stage B of ARCHITECTURE_HE.md).

Package layout keeps the FastAPI surface thin on purpose:

    db.py          SQLite schema (spec section 7) + helpers - stdlib only
    auth.py        per-sensor HMAC upload auth + bearer read auth - stdlib only
    storage.py     streaming spool -> dated pcap layout - stdlib only
    ingest_api.py  the HTTP layer (the only module that imports FastAPI)

Everything except ingest_api.py runs and tests without any third-party
dependency, so the existing CI exercises the real logic while the API
layer is covered when fastapi is installed (see server/requirements.txt).
"""

"""Pulls new candidates out of NETSEC's database, read-only, and hands each one to the agents."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from agent import netsec_source
from agent.db import Database

LOGGER = logging.getLogger("netsec_agent")


class Poller:
    """Every pass submits the candidates of recent finished sessions that have no case yet, oldest session first.

    The worker that fills netsec.db is not involved: this side only reads, and never holds the file open
    while a case runs.
    """

    def __init__(
        self,
        source_path: str,
        db: Callable[[], Database],
        submit: Callable[[dict], bool],
        *,
        interval_s: float = 30.0,
        lookback: int = 50,
    ):
        self.source_path = source_path
        self.interval_s = float(interval_s)
        self.lookback = int(lookback)
        self._db = db
        self._submit = submit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._rejected: set[tuple[Any, str]] = set()
        self._state: dict[str, Any] = {
            "enabled": True, "source": source_path, "interval_s": self.interval_s, "polls": 0,
            "last_poll_at": None, "last_error": None, "sessions_seen": 0, "submitted_total": 0,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def _update(self, **changes: Any) -> None:
        with self._lock:
            self._state.update(changes)

    def poll_once(self) -> dict[str, Any]:
        error = None
        try:
            conn = netsec_source.connect(self.source_path)
            try:
                sessions = netsec_source.finished_sessions(conn, self.lookback)
                have = self._db().cases_per_session()
                todo = [s for s in sessions if have.get(int(s["id"]), 0) < int(s["n_candidates"])]
                payloads = [p for s in todo for p in netsec_source.candidate_payloads(conn, s)]
            finally:
                conn.close()
            self._update(sessions_seen=len(sessions))
            for payload in payloads:
                if self._stop.is_set():
                    break
                key = (payload["session"].get("id"), payload["candidate_id"])
                if key in self._rejected:
                    continue
                try:
                    if self._submit(payload):
                        # Counted case by case: a pass over many cases can take a long time.
                        self._update(submitted_total=self._state["submitted_total"] + 1)
                except ValueError as exc:
                    # A candidate the service refuses is refused every time; say so once.
                    self._rejected.add(key)
                    LOGGER.warning("poll_candidate_rejected session=%s candidate=%s: %s", key[0], key[1],
                                   type(exc).__name__)
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:120]}"
            LOGGER.warning("poll_failed: %s", error)
        self._update(polls=self._state["polls"] + 1, last_poll_at=time.time(), last_error=error)
        return self.snapshot()

    def _loop(self) -> None:
        self.poll_once()
        while not self._stop.wait(self.interval_s):
            self.poll_once()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="netsec-poller", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

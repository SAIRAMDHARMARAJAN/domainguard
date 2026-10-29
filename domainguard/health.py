"""Health file: a small JSON snapshot an operator (or a monitor) can read."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path


class Health:
    def __init__(self, path, stale_after_s: float = 300, clock=time.time):
        self.path = Path(path)
        self.stale_after_s = stale_after_s
        self._clock = clock
        self._lock = threading.Lock()
        self._started = clock()
        self._collector: dict = {}
        self._last_events = 0
        self._last_event_at: float | None = None
        self._staged: dict[str, dict] = {}
        self._sources: dict[str, dict] = {}

    def on_collector_metrics(self, stats: dict) -> None:
        with self._lock:
            self._collector = dict(stats)
            if stats.get("events_seen", 0) > self._last_events:
                self._last_events = stats["events_seen"]
                self._last_event_at = self._clock()

    def on_staged(self, source: str, rows: int, files: int = 1) -> None:
        with self._lock:
            s = self._staged.setdefault(source, {"rows": 0, "files": 0, "last_at": None})
            s["rows"] += rows
            s["files"] += files
            s["last_at"] = self._clock()

    def source(self, name: str, info: dict) -> None:
        with self._lock:
            self._sources[name] = {**info, "updated_at": self._clock()}

    def status(self) -> str:
        now = self._clock()
        if self._last_event_at is None:
            return "starting" if now - self._started < self.stale_after_s else "stale"
        return "ok" if now - self._last_event_at <= self.stale_after_s else "stale"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status(),
                "written_at": self._clock(),
                "uptime_s": round(self._clock() - self._started, 1),
                "collector": self._collector,
                "staged": self._staged,
                "sources": self._sources,
            }

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.snapshot(), indent=2))
        os.replace(tmp, self.path)

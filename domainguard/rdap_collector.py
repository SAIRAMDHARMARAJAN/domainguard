"""Registration-age enrichment via RDAP: cached, rate-limited, personal data removed."""
from __future__ import annotations

import json
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from . import feeds

TTL_KNOWN_S = 30 * 86400
TTL_UNKNOWN_S = 24 * 3600
TTL_TRANSIENT_S = 15 * 60
COOLDOWN_START_S = 60
COOLDOWN_MAX_S = 3600


class RdapCollector:
    def __init__(self, writer, *, lookup=feeds.lookup_rdap, cache_path, min_interval_s: float = 1.0,
                 sleep=time.sleep, clock=time.time, max_queue: int = 10_000):
        self.writer = writer
        self.lookup = lookup
        self.cache_path = Path(cache_path)
        self.min_interval_s = min_interval_s
        self._sleep = sleep
        self._clock = clock
        self.max_queue = max_queue
        self.queue: deque[str] = deque()
        self._queued: set[str] = set()
        self._last_request = 0.0
        self._cooldown = COOLDOWN_START_S
        self._cooldown_until = 0.0
        self.cache: dict = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}

    def _fresh(self, domain: str) -> bool:
        e = self.cache.get(domain)
        return bool(e) and e["expires"] > self._clock()

    def enqueue(self, domains) -> int:
        added = 0
        for d in domains:
            if d in self._queued or self._fresh(d) or len(self.queue) >= self.max_queue:
                continue
            self.queue.append(d)
            self._queued.add(d)
            added += 1
        return added

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache))
        os.replace(tmp, self.cache_path)

    def drain(self, max_n: int = 20) -> dict:
        out = {"looked_up": 0, "staged": 0, "rate_limited": False, "queued": len(self.queue)}
        if self._clock() < self._cooldown_until:
            out["rate_limited"] = True
            return out
        rows: list[dict] = []
        updates: dict[str, dict] = {}
        taken: list[str] = []
        while self.queue and out["looked_up"] < max_n:
            domain = self.queue.popleft()
            wait = self.min_interval_s - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
            self._last_request = self._clock()
            status, registered_at, payload = self.lookup(domain)
            if status == 429:
                self.queue.appendleft(domain)  # keep it queued
                self._cooldown_until = self._clock() + self._cooldown
                self._cooldown = min(self._cooldown * 2, COOLDOWN_MAX_S)
                out["rate_limited"] = True
                break
            taken.append(domain)
            out["looked_up"] += 1
            self._cooldown = COOLDOWN_START_S
            now = self._clock()
            if status == 0 or status >= 500:  # transient: no row, retry later
                updates[domain] = {"status": status, "registered_at": None, "expires": now + TTL_TRANSIENT_S}
                continue
            ttl = TTL_KNOWN_S if registered_at else TTL_UNKNOWN_S
            updates[domain] = {"status": status, "registered_at": registered_at, "expires": now + ttl}
            rows.append({"domain": domain,
                         "fetched_at": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "http_status": status, "registered_at": registered_at, "payload": payload})
        try:
            self.writer.write_batch("rdap", rows)
        except Exception:
            self.queue.extendleft(reversed(taken))  # nothing lost: retry next time
            raise
        for d in taken:
            self._queued.discard(d)
        self.cache.update(updates)
        if updates:
            self._save_cache()
        out["staged"] = len(rows)
        out["queued"] = len(self.queue)
        return out

"""Certificate-stream collector: filter, de-duplicate, batch. Non-matching domains are discarded in memory."""
from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator

from .matcher import Watchlist, match_brand
from .normalize import clean_host, split_host

DEDUPE_TTL_S = 24 * 3600
DEDUPE_MAX = 100_000
BUFFER_MAX = 50_000


def extract_domains(message) -> list[str]:
    """Domain strings from a CertStream-style message; tolerates any garbage."""
    try:
        if message.get("message_type") != "certificate_update":
            return []
        doms = message["data"]["leaf_cert"]["all_domains"]
        return [d for d in doms if isinstance(d, str)] if isinstance(doms, list) else []
    except (AttributeError, KeyError, TypeError):
        return []


def _seen_at(message, fallback: datetime) -> str:
    try:
        seen = float(message["data"]["seen"])
        return datetime.fromtimestamp(seen, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (KeyError, TypeError, ValueError, OSError, OverflowError):
        return fallback.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                yield {}


class Collector:
    def __init__(
        self,
        watchlist,  # Watchlist or WatchlistLoader (anything with .current())
        sink: Callable[[list[dict]], None],
        *,
        flush_rows: int = 200,
        flush_seconds: float = 60,
        on_metrics: Callable[[dict], None] | None = None,
        on_candidates: Callable[[list[str]], None] | None = None,
        clock=time.monotonic,
    ):
        self._wl = watchlist
        self.sink = sink
        self.flush_rows = flush_rows
        self.flush_seconds = flush_seconds
        self.on_metrics = on_metrics
        self.on_candidates = on_candidates
        self._clock = clock
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._buffer: list[dict] = []
        self._last_flush = clock()
        self._since_metrics = 0
        self.last_error: str | None = None
        self.stats = {"events_seen": 0, "domains_seen": 0, "invalid": 0, "duplicates": 0, "discarded": 0,
                      "candidates": 0, "flushed": 0, "flush_errors": 0, "dropped": 0, "buffered": 0}

    def _watchlist(self) -> Watchlist:
        return self._wl.current() if hasattr(self._wl, "current") else self._wl

    def _is_duplicate(self, host: str) -> bool:
        now = self._clock()
        ts = self._seen.get(host)
        if ts is not None and now - ts < DEDUPE_TTL_S:
            return True
        self._seen[host] = now
        self._seen.move_to_end(host)
        while len(self._seen) > DEDUPE_MAX:
            self._seen.popitem(last=False)
        return False

    def handle(self, message) -> list[dict]:
        self.stats["events_seen"] += 1
        domains = extract_domains(message)
        wl = self._watchlist()
        stamp = _seen_at(message, datetime.now(timezone.utc))
        found: list[dict] = []
        for raw in domains:
            self.stats["domains_seen"] += 1
            host = clean_host(raw)
            if host is None:
                self.stats["invalid"] += 1
                continue
            if self._is_duplicate(host):
                self.stats["duplicates"] += 1
                continue
            m = match_brand(split_host(host), wl)
            if m is None:
                self.stats["discarded"] += 1
                continue
            found.append({"domain": host, "brand": m.brand, "match_type": m.match_type, "similarity": m.similarity,
                          "seen_at": stamp, "raw": {"domains_in_cert": len(domains)}})
        if found:
            self.stats["candidates"] += len(found)
            self._buffer.extend(found)
            if len(self._buffer) > BUFFER_MAX:
                drop = len(self._buffer) - BUFFER_MAX
                del self._buffer[:drop]
                self.stats["dropped"] += drop
            if self.on_candidates:
                self.on_candidates(sorted({split_host(r["domain"]).registrable for r in found}))
        self.maybe_flush()
        self._since_metrics += 1
        if self._since_metrics >= 50:
            self._emit()
        return found

    def _emit(self) -> None:
        self._since_metrics = 0
        self.stats["buffered"] = len(self._buffer)
        if self.on_metrics:
            self.on_metrics(dict(self.stats))

    def maybe_flush(self, force: bool = False) -> int:
        if not self._buffer:
            return 0
        due = force or len(self._buffer) >= self.flush_rows or self._clock() - self._last_flush >= self.flush_seconds
        if not due:
            return 0
        batch = list(self._buffer)
        try:
            self.sink(batch)
        except Exception as e:  # keep the buffer and retry on the next call
            self.stats["flush_errors"] += 1
            self.last_error = f"{type(e).__name__}: {e}"
            return 0
        del self._buffer[: len(batch)]
        self._last_flush = self._clock()
        self.stats["flushed"] += len(batch)
        self.last_error = None
        self._emit()
        return len(batch)

    def run_replay(self, messages: Iterable[dict]) -> dict:
        for msg in messages:
            self.handle(msg)
        self.maybe_flush(force=True)
        self._emit()
        return dict(self.stats)

    async def run_live(self, url: str, stop: asyncio.Event | None = None) -> None:
        """WebSocket loop with exponential reconnect backoff (1 s to 60 s). NOT RUN LIVE in this build."""
        import websockets  # imported here so offline use needs no websocket library

        stop = stop or asyncio.Event()
        backoff = 1.0
        while not stop.is_set():
            try:
                async with websockets.connect(url, ping_interval=20, max_size=2**22) as ws:
                    while not stop.is_set():
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=5)
                        except asyncio.TimeoutError:
                            self.maybe_flush()
                            continue
                        backoff = 1.0
                        try:
                            self.handle(json.loads(raw))
                        except ValueError:
                            self.stats["invalid"] += 1
            except (OSError, websockets.WebSocketException) as e:
                self.last_error = f"{type(e).__name__}: {e}"
                self.maybe_flush(force=True)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60.0)
        self.maybe_flush(force=True)

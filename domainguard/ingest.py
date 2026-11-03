"""Stage 1 runner: certificate stream and feeds -> staged files; the load / score / brief / notify steps follow.

Single-pass commands (used by cron, tests and the demo) and a long-running live loop (certstream, feeds, RDAP,
load, score, notify, health), where a failing part never stops the others."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from . import feeds
from .collector import Collector, read_jsonl
from .feed_collector import FeedCollector, FeedSource
from .health import Health
from .loader import load_stage
from .normalize import clean_host, split_host
from .pipeline import score_all
from .rdap_collector import RdapCollector
from .stage import StageWriter, read_staged
from .watchlist import WarehouseWatchlist

log = logging.getLogger("domainguard.ingest")


def _watchlist_match(row: dict, watchlist) -> bool:
    """Keep only feed rows that match a watched brand; do not persist unrelated feed data."""
    host = clean_host(row.get("domain", ""))
    if not host:
        return False
    from .matcher import match_brand
    return match_brand(split_host(host), watchlist) is not None


class _Observed:
    """Wraps StageWriter so every staged batch is reflected in the health file."""

    def __init__(self, writer, health):
        self.w, self.h = writer, health

    def write_batch(self, source, rows, now=None):
        files = self.w.write_batch(source, rows, now)
        if files:
            self.h.on_staged(source, sum(f.rows for f in files), len(files))
        return files


class Ingest:
    def __init__(self, settings, wh, *, fetch=None, lookup=None, sleep=None, alert=None):
        import time as _t
        self.s, self.wh = settings, wh
        state = Path(settings.state_dir)
        self.health = Health(state / "health.json")
        self.writer = StageWriter(settings.stage_dir)
        self.obs = _Observed(self.writer, self.health)
        self.sleep = sleep or _t.sleep
        self.alert = alert or (lambda m: log.error("OPS ALERT: %s", m))
        self.watchlist = WarehouseWatchlist(wh, ttl_s=settings.watchlist_ttl_s, cache_path=state / "watchlist_cache.json")
        self.rdap = RdapCollector(self.obs, lookup=lookup or feeds.lookup_rdap, cache_path=state / "rdap_cache.json",
                                  min_interval_s=settings.rdap_min_interval_s, sleep=self.sleep)
        self.collector = Collector(self.watchlist, lambda rows: self.obs.write_batch("certstream", rows),
                                   flush_rows=settings.flush_rows, flush_seconds=settings.flush_seconds,
                                   on_metrics=self.health.on_collector_metrics, on_candidates=self.rdap.enqueue)
        sources = [FeedSource("openphish", settings.openphish_url, min_interval_s=6 * 3600)] if settings.openphish_url else []
        if settings.urlhaus_url:
            hdr = {"Auth-Key": settings.urlhaus_auth_key} if settings.urlhaus_auth_key else {}
            sources.append(FeedSource("urlhaus", settings.urlhaus_url, min_interval_s=3600, headers=hdr))
        self.feeds = FeedCollector(
            sources, self.obs, fetch=fetch or feeds.fetch_text, state_dir=state,
            accept=lambda row: _watchlist_match(row, self.watchlist.current()),
        )

    def replay(self, path) -> dict:
        stats = self.collector.run_replay(read_jsonl(path))
        self.health.write()
        return stats

    def feeds_once(self) -> dict:
        r = self.feeds.run_once()
        self.health.source("feeds", r)
        self.health.write()
        return r

    def rdap_once(self, max_n: int = 20) -> dict:
        self.rdap.enqueue(sorted({split_host(r["domain"]).registrable for p in self.writer.files("certstream")
                                  for r in read_staged(p)}))
        out = self.rdap.drain(max_n)
        self.health.source("rdap", out)
        self.health.write()
        return out

    def load(self) -> dict:
        return load_stage(self.s.stage_dir, self.wh, sleep=self.sleep, alert=self.alert)

    def score(self, now=None) -> dict:
        return score_all(self.wh, self.watchlist.per_company(), now=now)

    async def live(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()

        async def every(seconds, name, fn):
            while not stop.is_set():
                try:
                    result = await asyncio.to_thread(fn)
                    self.health.source(name, result if isinstance(result, dict) else {"ok": True})
                except Exception as e:  # one failing loop never stops the others
                    self.health.source(name, {"error": f"{type(e).__name__}: {e}"})
                    log.warning("%s failed: %s", name, e)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=seconds)
                except asyncio.TimeoutError:
                    pass

        await asyncio.gather(
            self.collector.run_live(self.s.certstream_url, stop),
            every(60, "feeds", self.feeds_once),
            every(5, "rdap", lambda: self.rdap.drain(5)),
            every(60, "load", self.load),
            every(120, "score", self.score),
            every(30, "health", self.health.write),
        )

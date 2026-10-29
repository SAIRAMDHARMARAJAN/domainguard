"""Watchlist loaded from Snowflake (REF.PROTECTED_DOMAINS joined to active REF.USERS), reloaded every 30 s.

If Snowflake is unreachable the last known list is kept (in memory and in a local cache file), so protection
continues. The cache is only used when the warehouse cannot answer; it is never treated as newer than Snowflake."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from .matcher import Watchlist
from .normalize import split_host

log = logging.getLogger("domainguard.watchlist")


def brand_rows(rows: list[dict]) -> list[dict]:
    """Protected-domain rows -> matcher brand dicts. The brand name is the registrable label (for example 'abcbank')."""
    out = []
    for r in rows:
        parts = split_host(r["domain"])
        label = parts.label or r["domain"].split(".")[0]
        official = list(dict.fromkeys([r["domain"], *r.get("official_domains", [])]))
        aliases = list(dict.fromkeys([*r.get("brand_aliases", []), label]))
        out.append({"name": label, "aliases": aliases, "official_domains": official})
    return out


class WarehouseWatchlist:
    def __init__(self, wh, ttl_s: float = 30.0, clock=time.monotonic, cache_path=None):
        self.wh = wh
        self.ttl_s = ttl_s
        self._clock = clock
        self.cache_path = Path(cache_path) if cache_path else None
        self._rows: list[dict] = self._read_cache()
        self._loaded_at: float | None = None
        self.last_error: str | None = None
        self.reloads = 0
        self.refresh(force=True)

    def _read_cache(self) -> list[dict]:
        if self.cache_path and self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text())
            except ValueError:
                return []
        return []

    def _write_cache(self) -> None:
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._rows))
            tmp.replace(self.cache_path)

    def refresh(self, force: bool = False) -> None:
        now = self._clock()
        if not force and self._loaded_at is not None and now - self._loaded_at < self.ttl_s:
            return
        self._loaded_at = now
        try:
            rows = self.wh.active_protected_rows()
            self._rows = rows
            self.reloads += 1
            self.last_error = None
            self._write_cache()
        except Exception as e:  # keep the last known list
            self.last_error = f"{type(e).__name__}: {e}"
            log.warning("watchlist reload failed, using last known list (%d domains): %s", len(self._rows), e)

    def rows(self) -> list[dict]:
        self.refresh()
        return list(self._rows)

    def current(self) -> Watchlist:
        """All brands together (used by the certificate collector to decide what is a candidate)."""
        return Watchlist.from_dicts(brand_rows(self.rows()))

    def per_company(self) -> dict[str, Watchlist]:
        """One watchlist per company (used by the scoring job, so a domain is scored for the company it imitates)."""
        grouped: dict[str, list[dict]] = {}
        for r in self.rows():
            grouped.setdefault(r["company_id"], []).append(r)
        return {cid: Watchlist.from_dicts(brand_rows(rs)) for cid, rs in sorted(grouped.items())}

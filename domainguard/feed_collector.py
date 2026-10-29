"""Scheduled blocklist pulls with change detection and exponential backoff."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import feeds

MAX_BACKOFF_S = 6 * 3600


@dataclass
class FeedSource:
    name: str  # "openphish" or "urlhaus"; stored in each staged row's `source`
    url: str
    min_interval_s: float = 3600
    headers: dict = field(default_factory=dict)


class FeedCollector:
    def __init__(self, sources: list[FeedSource], writer, *, fetch=feeds.fetch_text, state_dir, clock=time.time):
        self.sources = sources
        self.writer = writer
        self.fetch = fetch
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._state_path = self.state_dir / "feeds_state.json"
        self.state: dict = json.loads(self._state_path.read_text()) if self._state_path.exists() else {}

    def _seen_path(self, name: str) -> Path:
        return self.state_dir / f"feed_seen_{name}.txt"

    def _load_seen(self, name: str) -> set[str]:
        p = self._seen_path(name)
        return set(p.read_text().split()) if p.exists() else set()

    def _atomic(self, path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, path)

    def run_once(self) -> dict[str, dict]:
        """One scheduling pass. Never raises; a failing source only backs itself off."""
        result: dict[str, dict] = {}
        for src in self.sources:
            st = self.state.setdefault(src.name, {"next_run": 0, "failures": 0})
            now = self._clock()
            if now < st["next_run"]:
                result[src.name] = {"status": "skipped", "next_run_in_s": round(st["next_run"] - now)}
                continue
            try:
                observed = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows = feeds.parse_url_list(self.fetch(src.url, src.headers), src.name, observed_at=observed)
                seen = self._load_seen(src.name)
                new = [r for r in rows if r["domain"] not in seen]
                self.writer.write_batch("blocklist", new)  # stage first, then remember
                self._atomic(self._seen_path(src.name), "\n".join(sorted(seen | {r["domain"] for r in rows})))
                st.update(failures=0, next_run=now + src.min_interval_s, last_ok=now, last_error=None)
                result[src.name] = {"status": "ok", "new": len(new), "total": len(rows)}
            except Exception as e:
                st["failures"] += 1
                st["next_run"] = now + min(src.min_interval_s * 2 ** st["failures"], MAX_BACKOFF_S)
                st["last_error"] = f"{type(e).__name__}: {e}"
                result[src.name] = {"status": "error", "error": st["last_error"], "failures": st["failures"]}
        self._atomic(self._state_path, json.dumps(self.state))
        return result

"""Stage writer: the hand-off contract between Stage 1 and the warehouse.

Layout:  <root>/<source>/dt=YYYY-MM-DD/hh=HH/<source>-<timestamp>-<id>-<part>.jsonl.gz
Each source also has <root>/<source>/_manifest.jsonl with one line per file: path, rows, bytes, sha256.
Files are written atomically (temp file, fsync, rename) so a loader never sees a half-written file.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class StagedFile:
    source: str
    path: str  # relative to the stage root
    rows: int
    bytes: int
    sha256: str


class StageWriter:
    def __init__(self, root, max_rows_per_file: int = 5000):
        self.root = Path(root)
        self.max_rows = max_rows_per_file
        self._lock = threading.Lock()

    def write_batch(self, source: str, rows: list[dict], now: datetime | None = None) -> list[StagedFile]:
        if not rows:
            return []
        now = now or datetime.now(timezone.utc)
        folder = self.root / source / f"dt={now:%Y-%m-%d}" / f"hh={now:%H}"
        batch_id = uuid.uuid4().hex[:8]
        out: list[StagedFile] = []
        with self._lock:
            folder.mkdir(parents=True, exist_ok=True)
            for part, start in enumerate(range(0, len(rows), self.max_rows)):
                chunk = rows[start : start + self.max_rows]
                name = f"{source}-{now:%Y%m%dT%H%M%S}-{batch_id}-{part:03d}.jsonl.gz"
                final = folder / name
                tmp = folder / f".tmp-{name}"
                payload = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in chunk)
                with open(tmp, "wb") as raw:
                    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                        gz.write(payload.encode("utf-8"))
                    raw.flush()
                    os.fsync(raw.fileno())
                os.replace(tmp, final)
                data = final.read_bytes()
                sf = StagedFile(source, str(final.relative_to(self.root)), len(chunk), len(data),
                                hashlib.sha256(data).hexdigest())
                with open(self.root / source / "_manifest.jsonl", "a", encoding="utf-8") as m:
                    m.write(json.dumps(sf.__dict__) + "\n")
                out.append(sf)
        return out

    def files(self, source: str | None = None) -> list[Path]:
        base = self.root / source if source else self.root
        return sorted(p for p in base.rglob("*.jsonl.gz") if not p.name.startswith(".tmp-")) if base.exists() else []

    def prune(self, older_than_days: int, now: datetime | None = None) -> int:
        """Delete staged files whose dt= partition is older than the cutoff. Returns files removed."""
        now = now or datetime.now(timezone.utc)
        cutoff = (now - timedelta(days=older_than_days)).strftime("%Y-%m-%d")
        removed = 0
        for p in self.files():
            part = next((x for x in p.parts if x.startswith("dt=")), None)
            if part and part[3:] < cutoff:
                p.unlink()
                removed += 1
        for d in sorted(self.root.rglob("dt=*"), reverse=True):
            if d.is_dir() and not any(d.rglob("*.jsonl.gz")):
                shutil.rmtree(d, ignore_errors=True)
        return removed


def read_staged(path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

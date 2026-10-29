"""Stage files -> Snowflake Bronze. Idempotent, checksum-verified, retried, and logged to OPS.LOAD_LOG.

Per file:  verify manifest + SHA-256  ->  skip if OPS.LOAD_LOG says SUCCESS  ->  load (COPY or row insert)
           ->  log SUCCESS, or FAILED after retries (FAILED files are retried on the next run).
If Snowflake is down the file simply stays in the local stage folder (it is durable on disk) and the next run
retries it. Ops is alerted after 5 consecutive failures."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .retry import RetriesExhausted, call_with_retry
from .stage import read_staged

log = logging.getLogger("domainguard.loader")
SOURCES = ("certstream", "blocklist", "rdap")


@dataclass
class VerifiedFile:
    rel: str
    source: str
    path: Path
    rows: int
    sha256: str
    bytes: int


def verify_stage(root) -> tuple[list[VerifiedFile], list[str]]:
    root = Path(root)
    ok: list[VerifiedFile] = []
    errors: list[str] = []
    for source in SOURCES:
        base = root / source
        entries: dict[str, dict] = {}
        m = base / "_manifest.jsonl"
        if m.exists():
            for line in m.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                    entries[e["path"]] = e
                except (ValueError, KeyError):
                    continue
        files = sorted(p for p in base.rglob("*.jsonl.gz") if not p.name.startswith(".tmp-")) if base.exists() else []
        for p in files:
            rel = str(p.relative_to(root))
            e = entries.get(rel)
            if e is None:
                errors.append(f"{rel}: no manifest entry")
                continue
            data = p.read_bytes()
            if hashlib.sha256(data).hexdigest() != e.get("sha256"):
                errors.append(f"{rel}: checksum mismatch")
                continue
            ok.append(VerifiedFile(rel, source, p, int(e["rows"]), e["sha256"], len(data)))
    return ok, errors


def load_stage(root, wh, *, sleep=None, alert=None, use_copy: bool | None = None) -> dict:
    import time as _time

    sleep = sleep or _time.sleep
    alert = alert or (lambda msg: log.error("OPS ALERT: %s", msg))
    ok, errors = verify_stage(root)
    report = {"files_loaded": 0, "files_skipped": 0, "files_failed": 0, "rows_loaded": 0, "errors": list(errors)}
    copy_ok = hasattr(wh, "copy_file") if use_copy is None else use_copy
    for f in ok:
        prior = wh.loaded_file(f.rel)
        if prior and prior.get("status") == "SUCCESS":
            report["files_skipped"] += 1
            continue
        try:
            rows = read_staged(f.path)
            if len(rows) != f.rows:
                raise ValueError(f"file has {len(rows)} rows, manifest says {f.rows}")

            def attempt():
                try:
                    if copy_ok:
                        return wh.copy_file(f.source, str(f.path), f.rel)
                    return wh.write_bronze(f.source, rows, f.rel)
                except Exception:
                    if hasattr(wh, "reset"):
                        wh.reset()  # reconnect on the next try
                    raise

            n = call_with_retry(attempt, what=f"load {f.rel}", sleep=sleep, alert=alert)
            wh.log_load({"file_name": f.rel, "source": f.source, "row_count": f.rows, "bytes": f.bytes,
                         "sha256": f.sha256, "status": "SUCCESS"})
            report["files_loaded"] += 1
            report["rows_loaded"] += n if isinstance(n, int) else f.rows
        except (RetriesExhausted, ValueError, OSError) as e:
            report["files_failed"] += 1
            report["errors"].append(f"{f.rel}: {e}")
            try:
                wh.log_load({"file_name": f.rel, "source": f.source, "row_count": f.rows, "bytes": f.bytes,
                             "sha256": f.sha256, "status": "FAILED"})
            except Exception:
                pass  # warehouse still down; the file stays on disk and will be retried
    return report

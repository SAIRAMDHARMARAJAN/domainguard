"""Command line. Production needs Snowflake (see .env.example). Run with --help for the list.

  python -m domainguard.cli check              verify the environment and the Snowflake tables
  python -m domainguard.cli replay FILE        offline: run saved certificate events through the collector
  python -m domainguard.cli feeds-once         pull OpenPhish (and URLhaus if configured)
  python -m domainguard.cli rdap-once          registration-age lookups for staged candidates
  python -m domainguard.cli live               stream + feeds + RDAP + load + score + notify, until Ctrl+C
  python -m domainguard.cli load               load staged files into Snowflake Bronze (idempotent)
  python -m domainguard.cli score              scoring job: Silver -> Gold verdicts, prints newly flagged
  python -m domainguard.cli briefs             explanations (LLM if configured, else template)
  python -m domainguard.cli notify             send alerts for new detections and due digests
  python -m domainguard.cli evaluate           precision, recall, lead time, hours saved
  python -m domainguard.cli health             print the health file
  python -m domainguard.cli stage-prune --days 14
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings


def _load_dotenv(path=".env") -> None:
    p = Path(path)
    if not p.is_file():
        return

    import os
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))


def main(argv=None) -> int:
    _load_dotenv()
    ap = argparse.ArgumentParser(prog="domainguard.cli", description="DomainGuard v7 (Snowflake)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    r = sub.add_parser("replay"); r.add_argument("path")
    sub.add_parser("feeds-once")
    d = sub.add_parser("rdap-once"); d.add_argument("--max", type=int, default=20)
    sub.add_parser("live")
    sub.add_parser("load")
    sub.add_parser("score")
    b = sub.add_parser("briefs"); b.add_argument("--languages", default="English")
    sub.add_parser("notify")
    sub.add_parser("evaluate")
    sub.add_parser("health")
    p = sub.add_parser("stage-prune"); p.add_argument("--days", type=int, default=14)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    s = Settings.from_env()
    if a.cmd == "health":
        path = Path(s.state_dir) / "health.json"
        print(path.read_text() if path.exists() else "no health file yet")
        return 0
    from .factory import make_warehouse
    from .notifier import SMTPSender, flush_digests, notify_new
    from .ingest import Ingest

    try:
        wh = make_warehouse(s)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.cmd == "check":
        from .setup_check import check_environment
        report = check_environment(s, wh)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    ing = Ingest(s, wh)
    if a.cmd == "replay":
        print(json.dumps(ing.replay(a.path), indent=2))
    elif a.cmd == "feeds-once":
        print(json.dumps(ing.feeds_once(), indent=2))
    elif a.cmd == "rdap-once":
        print(json.dumps(ing.rdap_once(a.max), indent=2))
    elif a.cmd == "load":
        rep = ing.load()
        print(json.dumps(rep, indent=2))
        return 1 if rep["errors"] else 0
    elif a.cmd == "score":
        rep = ing.score()
        print(json.dumps({k: v for k, v in rep.items() if k != "newly_flagged"} | {
            "newly_flagged": [(x["company_id"], x["domain"], x["classification"], x["score"]) for x in rep["newly_flagged"]]},
            indent=2))
    elif a.cmd == "briefs":
        from .worker import run_briefs
        langs = tuple(x.strip() for x in a.languages.split(",") if x.strip())
        print(json.dumps(run_briefs(wh, s, languages=langs), indent=2))
    elif a.cmd == "notify":
        now = datetime.now(timezone.utc)
        sender = SMTPSender(s.smtp_host, s.smtp_port, s.smtp_user, s.smtp_password, s.smtp_from) if s.smtp_host else None
        if sender is None:
            print("error: SMTP_HOST is not set", file=sys.stderr)
            return 2
        result = {"immediate": notify_new(wh, sender, s, wh_newly(wh, now), now),
                  "digests": flush_digests(wh, sender, s, now)}
        print(json.dumps(result, indent=2))
    elif a.cmd == "evaluate":
        from .evaluation import full_report, persist
        from .watchlist import WarehouseWatchlist
        wl = WarehouseWatchlist(wh).current()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out = {}
        for user in wh.list_users("ACTIVE"):
            rep = full_report(wh, wl, user["company_id"])
            persist(wh, user["company_id"], rep, today)
            out[user["company_id"]] = rep
        print(json.dumps(out, indent=2))
    elif a.cmd == "stage-prune":
        print(f"removed {ing.writer.prune(a.days)} staged file(s)")
    elif a.cmd == "live":
        try:
            asyncio.run(ing.live())
        except KeyboardInterrupt:
            ing.health.write()
    return 0


def wh_newly(wh, now):
    """Verdicts first flagged in the last hour that have not been alerted yet (used by `notify`)."""
    out = []
    for v in wh.verdicts():
        if v.get("first_flagged_at") and v["classification"] in ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS"):
            age = now - datetime.fromisoformat(v["first_flagged_at"].replace("Z", "+00:00"))
            if age.total_seconds() <= 3600:
                out.append(v)
    return out


if __name__ == "__main__":
    sys.exit(main())

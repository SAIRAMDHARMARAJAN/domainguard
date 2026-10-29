"""One-time: import the old data/watchlist.json into REF.USERS and REF.PROTECTED_DOMAINS.

Each entry becomes a company (status ACTIVE, notifications off until the company opts in). Brand names become
the company name; official_domains become the protected domains. Re-running is safe (MERGE).

  python scripts/migrate_from_json.py data/watchlist.json [--dry-run]"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from domainguard.normalize import split_host  # noqa: E402


def plan(rows: list[dict]) -> list[dict]:
    """Companies and protected-domain rows that the JSON file implies. Company ids are stable (uuid5 of the name)."""
    out = []
    for r in rows:
        cid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "domainguard:" + r["name"]))
        domains = [d for d in r.get("official_domains", [])]
        out.append({"company": {"company_id": cid, "name": r["name"], "email": f"{r['name']}@migrated.invalid",
                                "status": "ACTIVE", "email_notifications": False},
                    "protected": [{"company_id": cid, "domain": split_host(d).registrable,
                                   "brand_aliases": r.get("aliases", []), "official_domains": [split_host(d).registrable]}
                                  for d in domains]})
    return out


if __name__ == "__main__":
    path = Path(next((a for a in sys.argv[1:] if not a.startswith("--")), "data/watchlist.json"))
    items = plan(json.loads(path.read_text()))
    if "--dry-run" in sys.argv:
        print(json.dumps(items, indent=2))
        sys.exit(0)
    from domainguard.config import Settings
    from domainguard.factory import make_warehouse
    wh = make_warehouse(Settings.from_env())
    for item in items:
        if wh.get_user(item["company"]["company_id"]) is None:
            wh.create_user(item["company"])
        for p in item["protected"]:
            wh.upsert_protected(p)
    print(f"migrated {len(items)} companies")

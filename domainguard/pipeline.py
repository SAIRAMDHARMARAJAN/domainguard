"""The scoring job. Reads Silver (through the warehouse), scores every candidate for every company whose brands it
resembles, and writes features, breakdown and Gold verdicts. Returns the verdicts that were newly flagged, so the
notifier can alert on them.

Rules (unchanged from v1): the seven-factor score, the classes, official domains are never flagged, and
first_flagged_at is set once and never overwritten."""
from __future__ import annotations

from datetime import datetime, timezone

from . import feeds
from .normalize import split_host
from .scoring import score_domain
from .warehouse import FLAGGED


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def score_all(wh, companies: dict, now: datetime | None = None) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    stamp = _iso(now)
    cands = wh.candidates()
    blocklist = wh.blocklist_index()
    rdap = wh.rdap_index()
    summary = {"candidates": len(cands), "stored": 0, "newly_flagged": [], "skipped_invalid": 0, "by_class": {}}
    for c in cands:
        host = c["domain"]
        parts = split_host(host)
        reg = parts.registrable
        reg_at = rdap.get(reg) or rdap.get(host)
        age = feeds.age_days(reg_at, now)
        hits = [blocklist[x] for x in (host, reg) if x in blocklist]
        listed = min((h["first_listed_at"] for h in hits if h["first_listed_at"]), default=None)
        sources = sorted({s for h in hits for s in h["sources"]})
        for company_id, wl in companies.items():
            try:
                res = score_domain(host, wl, age_days=age, on_blocklist=bool(hits), now=now)
            except ValueError:
                summary["skipped_invalid"] += 1
                break
            if res.matched_brand is None or res.classification == "ALLOWLISTED":
                continue  # not related to this company's brands (or it is the company's own domain)
            before = wh.get_verdict(host, company_id)
            verdict = {
                "domain": host, "company_id": company_id, "score": res.score, "classification": res.classification,
                "matched_brand": res.matched_brand, "match_type": res.match_type, "similarity": res.similarity,
                "evidence": res.evidence, "breakdown": res.breakdown, "is_on_blocklist": bool(hits),
                "blocklist_sources": sources, "first_seen_at": c["first_seen_at"], "first_listed_at": listed,
                "registered_at": reg_at, "age_days": res.age_days, "last_evaluated_at": stamp,
                "scoring_version": res.scoring_version,
            }
            after = wh.write_score(verdict)
            summary["stored"] += 1
            summary["by_class"][res.classification] = summary["by_class"].get(res.classification, 0) + 1
            was_flagged = bool(before and before.get("first_flagged_at"))
            if after.get("first_flagged_at") and not was_flagged and res.classification in FLAGGED:
                summary["newly_flagged"].append(after)
    return summary

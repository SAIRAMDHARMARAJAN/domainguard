"""Evaluation harness: precision, recall, lead time (median, p25, p75), weight sensitivity, analyst hours saved.

Reads stored data and returns numbers. Nothing here changes a score, a weight or a verdict.

Precision (specification formula, corrected): the flagged domains that are a confirmed threat OR on a blocklist,
divided by all flagged domains. A domain counted twice (confirmed and listed) is counted once, so the result
never exceeds 1.0. `precision_score_only` excludes blocklist listings so it is not circular.
Recall (approximate): flagged-before-listing divided by blocklisted lookalikes of watched brands.
Analyst hours saved: auto-triaged domains times minutes per manual check (default 5, as in the specification)."""
from __future__ import annotations

import hashlib
import statistics
from datetime import datetime

from .matcher import Watchlist, match_brand
from .normalize import split_host
from .scoring import BAND_SUSPICIOUS, WEIGHTS

FLAG_CLASSES = ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS")
MINUTES_PER_CHECK = 5.0


def _flagged(verdicts: list[dict]) -> list[dict]:
    return [v for v in verdicts if v["classification"] in FLAG_CLASSES and v["score"] >= BAND_SUSPICIOUS]


def _label(wh, v) -> str | None:
    hist = wh.feedback_history(v["domain"], v["company_id"])
    return hist[-1]["label"] if hist else None


def precision(wh, company_id: str | None = None) -> dict:
    flagged = _flagged(wh.verdicts(company_id))
    confirmed = blocklisted = union = score_only_tp = labeled_score_only = 0
    for v in flagged:
        lab = _label(wh, v)
        is_conf = lab == "CONFIRMED_THREAT"
        is_bl = bool(v.get("is_on_blocklist"))
        confirmed += is_conf
        blocklisted += is_bl
        union += is_conf or is_bl
        if lab is not None:
            labeled_score_only += 1
            score_only_tp += lab == "CONFIRMED_THREAT"
    n = len(flagged)
    return {"flagged": n, "confirmed_threats": confirmed, "blocklisted_matches": blocklisted,
            "precision": round(union / n, 3) if n else None,
            "precision_score_only": round(score_only_tp / labeled_score_only, 3) if labeled_score_only else None,
            "false_positives": sum(1 for v in flagged if _label(wh, v) == "FALSE_POSITIVE")}


def recall(wh, watchlist: Watchlist, company_id: str | None = None) -> dict:
    verdicts = {}
    for v in wh.verdicts(company_id):
        verdicts.setdefault(v["domain"], v)
    early = late = missed = 0
    for dom, entry in wh.blocklist_index().items():
        if match_brand(split_host(dom), watchlist) is None:
            continue
        v = verdicts.get(dom) or verdicts.get(split_host(dom).registrable)
        ff = v.get("first_flagged_at") if v else None
        if not ff:
            missed += 1
        elif entry.get("first_listed_at") and ff <= entry["first_listed_at"]:
            early += 1
        else:
            late += 1
    total = early + late + missed
    return {"blocklisted_lookalikes": total, "flagged_before_listing": early, "flagged_after_listing": late,
            "missed": missed, "recall": round(early / total, 3) if total else None}


def lead_time(wh, company_id: str | None = None) -> dict:
    hours = []
    not_listed = listed_before = 0
    for v in _flagged(wh.verdicts(company_id)):
        if not v.get("first_flagged_at"):
            continue
        if not v.get("first_listed_at"):
            not_listed += 1
            continue
        f = datetime.fromisoformat(v["first_flagged_at"].replace("Z", "+00:00"))
        li = datetime.fromisoformat(v["first_listed_at"].replace("Z", "+00:00"))
        h = (li - f).total_seconds() / 3600
        if h > 0:
            hours.append(h)
        else:
            listed_before += 1
    out = {"flagged_before_listing": len(hours), "listed_before_flag": listed_before, "not_listed_yet": not_listed,
           "median": None, "p25": None, "p75": None}
    if len(hours) >= 2:
        q = statistics.quantiles(hours, n=4, method="inclusive")
        out.update(median=round(statistics.median(hours), 2), p25=round(q[0], 2), p75=round(q[2], 2))
    elif hours:
        out.update(median=round(hours[0], 2), p25=round(hours[0], 2), p75=round(hours[0], 2))
    return out


def analyst_hours_saved(wh, company_id: str | None = None, minutes: float = MINUTES_PER_CHECK) -> dict:
    verdicts = wh.verdicts(company_id)
    needing = len(_flagged(verdicts))
    triaged = max(0, len(verdicts) - needing)
    return {"scored": len(verdicts), "needing_review": needing, "auto_triaged": triaged,
            "minutes_per_check": minutes, "hours_saved": round(triaged * minutes / 60, 2)}


def compare_weights(rows: list[dict], candidate: dict, band: int = BAND_SUSPICIOUS) -> dict:
    """Current weights vs a candidate on held-out labelled rows. Reports only; never adopts anything."""
    def hold(dom):
        return int(hashlib.sha256(dom.encode()).hexdigest(), 16) % 1000 < 300
    test = [r for r in rows if hold(r["domain"])]

    def rescore(bd, w):
        return max(0, min(100, int(sum(p * w[f] / WEIGHTS[f] for f, p in bd.items() if f in WEIGHTS) + 0.5)))

    def metrics(w):
        tp = fp = fn = 0
        for r in test:
            flagged = rescore(r["breakdown"], w) >= band
            tp += flagged and r["label"] == 1
            fp += flagged and r["label"] == 0
            fn += (not flagged) and r["label"] == 1
        p = tp / (tp + fp) if tp + fp else None
        rc = tp / (tp + fn) if tp + fn else None
        return {"tp": tp, "fp": fp, "fn": fn, "precision": None if p is None else round(p, 3),
                "recall": None if rc is None else round(rc, 3)}

    merged = {**WEIGHTS, **candidate}
    return {"holdout_rows": len(test), "current": metrics(dict(WEIGHTS)), "candidate": metrics(merged),
            "candidate_weights": merged, "adopted": False,
            "note": "Reporting only. Adopting weights needs human approval, a scoring.py change and a new SCORING_VERSION."}


def weight_rows(wh, company_id: str | None = None) -> list[dict]:
    out = []
    for v in wh.verdicts(company_id):
        if v["classification"] == "ALLOWLISTED":
            continue
        hist = wh.feedback_history(v["domain"], v["company_id"])
        if hist:
            out.append({"domain": v["domain"], "label": 1 if hist[-1]["label"] == "CONFIRMED_THREAT" else 0,
                        "breakdown": v["breakdown"]})
    return out


def full_report(wh, watchlist: Watchlist, company_id: str | None = None, minutes: float = MINUTES_PER_CHECK) -> dict:
    return {"precision": precision(wh, company_id), "recall": recall(wh, watchlist, company_id),
            "lead_time": lead_time(wh, company_id), "analyst_hours": analyst_hours_saved(wh, company_id, minutes)}


def persist(wh, company_id: str, report: dict, metric_date: str) -> None:
    lt, p = report["lead_time"], report["precision"]
    wh.put_metrics({"metric_date": metric_date, "company_id": company_id, "precision": p["precision"],
                    "recall": report["recall"]["recall"], "lead_time_median": lt["median"], "lead_time_p25": lt["p25"],
                    "lead_time_p75": lt["p75"], "domains_flagged": p["flagged"], "confirmed_threats": p["confirmed_threats"],
                    "false_positives": p["false_positives"], "analyst_hours": report["analyst_hours"]["hours_saved"]})

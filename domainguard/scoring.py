"""Deterministic seven-factor risk score. Plain arithmetic: no ML, no LLM, same input -> same score."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import SCORING_VERSION
from .matcher import BrandMatch, Watchlist, match_brand
from .normalize import clean_host, split_host

WEIGHTS = {
    "name_similarity": 25,
    "brand_in_domain": 15,
    "keywords": 10,
    "domain_age": 20,
    "deceptive_chars": 15,
    "risky_tld": 5,
    "structure": 10,
}
assert sum(WEIGHTS.values()) == 100

BAND_SUSPICIOUS = 40
BAND_HIGH = 70

KEYWORDS = (
    "login signin secure verify verification account update support kyc wallet payment confirm "
    "password billing helpdesk suspend unlock refund"
).split()
RISKY_TLDS = frozenset(
    "xyz top click icu buzz gq cf tk ml ga work zip mov cam rest monster country kim loan men date download racing".split()
)


@dataclass
class ScoreResult:
    domain: str
    score: int
    classification: str  # ALLOWLISTED | LOW | SUSPICIOUS | HIGH_RISK | DANGEROUS
    breakdown: dict[str, int]
    matched_brand: str | None = None
    match_type: str | None = None
    similarity: int | None = None
    evidence: list[str] = field(default_factory=list)
    on_blocklist: bool = False
    age_days: float | None = None
    evaluated_at: str = ""
    scoring_version: str = SCORING_VERSION

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _age_points(age_days: float | None) -> int:
    if age_days is None:
        return 10  # unknown is explicit, never guessed
    if age_days < 1:
        return 20
    if age_days < 7:
        return 14
    if age_days < 30:
        return 8
    return 0


def _keywords(parts, match: BrandMatch | None) -> list[str]:
    labels = [*parts.unicode_host.split(".")[: -(parts.suffix.count(".") + 1)]]
    text = " ".join(labels).lower()
    if match:
        if match.match_type == "exact_token":
            text = text.replace(match.token.lower(), " ")
        else:
            text = text.replace(match.raw_key, " ")
    return sorted(k for k in KEYWORDS if k in text)


def score_domain(
    raw_host: str,
    watchlist: Watchlist,
    *,
    age_days: float | None = None,
    on_blocklist: bool = False,
    now: datetime | None = None,
) -> ScoreResult:
    host = clean_host(raw_host)
    if host is None:
        raise ValueError(f"invalid hostname: {raw_host!r}")
    now = now or datetime.now(timezone.utc)
    parts = split_host(host)
    zero = {k: 0 for k in WEIGHTS}

    if watchlist.is_official(parts):
        ev = ["official domain of a protected brand"]
        if on_blocklist:
            ev.append("also listed on a blocklist: analyst review recommended")
        return ScoreResult(host, 0, "ALLOWLISTED", zero, evidence=ev, on_blocklist=on_blocklist,
                           age_days=age_days, evaluated_at=now.isoformat())

    match = match_brand(parts, watchlist)
    b = dict(zero)
    ev: list[str] = []

    if match:
        b["name_similarity"] = max(0, min(25, int(25 * (match.similarity - 70) / 30 + 0.5)))
        ev.append(f"name is {match.similarity}% similar to '{match.brand}' ({match.match_type})")
        if match.match_type in ("exact_token", "contains"):
            b["brand_in_domain"] = 15
            ev.append(f"brand text '{match.brand}' appears in a non-official domain")

    kws = _keywords(parts, match)
    b["keywords"] = min(10, 5 * len(kws))
    if kws:
        ev.append("suspicious keywords: " + ", ".join(kws))

    b["domain_age"] = _age_points(age_days)
    if age_days is None:
        ev.append("domain age unknown (RDAP missing or redacted); treated as medium risk")
    elif b["domain_age"]:
        ev.append(f"newly registered domain ({age_days:.1f} days old)")

    dec = 0
    if parts.has_punycode:
        dec += 8
        ev.append("internationalised (punycode) name can hide look-alike letters")
    if match and match.obfuscated:
        dec += 10
        ev.append("look-alike characters reveal the brand match")
    b["deceptive_chars"] = min(15, dec)

    if parts.tld in RISKY_TLDS:
        b["risky_tld"] = 5
        ev.append(f"frequently abused ending '.{parts.tld}'")

    st = 0
    ulabel = parts.unicode_host.split(".")[-(parts.suffix.count(".") + 2)]  # decoded, so punycode's own hyphen is ignored
    hyphens = ulabel.count("-")
    if hyphens >= 3:
        st += 5
    elif hyphens == 2:
        st += 3
    if len(ulabel) > 25:
        st += 3
    depth = len(parts.subdomains)
    if depth >= 3:
        st += 3
    elif depth == 2:
        st += 2
    b["structure"] = min(10, st)
    if st:
        why = []
        if hyphens >= 2:
            why.append(f"{hyphens} hyphens")
        if len(ulabel) > 25:
            why.append("very long name")
        if depth >= 2:
            why.append(f"{depth} subdomain levels")
        ev.append("unusual structure: " + ", ".join(why))

    score = min(100, sum(b.values()))
    if on_blocklist:
        cls = "DANGEROUS"
        ev.append("listed on a public blocklist")
    elif score >= BAND_HIGH:
        cls = "HIGH_RISK"
    elif score >= BAND_SUSPICIOUS:
        cls = "SUSPICIOUS"
    else:
        cls = "LOW"
    return ScoreResult(
        host, score, cls, b,
        matched_brand=match.brand if match else None,
        match_type=match.match_type if match else None,
        similarity=match.similarity if match else None,
        evidence=ev, on_blocklist=on_blocklist, age_days=age_days, evaluated_at=now.isoformat(),
    )

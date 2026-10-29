"""Brand matching: does this hostname imitate a brand on the watchlist?"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property

from .normalize import HostParts, clean_host, fold, raw_form, split_host, tokens

try:  # optional, faster
    from rapidfuzz import fuzz as _fuzz

    def _ratio(a: str, b: str) -> float:
        return _fuzz.ratio(a, b)

except ImportError:  # pragma: no cover - exercised when rapidfuzz is absent
    from difflib import SequenceMatcher

    def _ratio(a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio() * 100

SHORT_BRAND_LEN = 5
DEFAULT_THRESHOLD = 85
_RANK = {"exact_token": 3, "contains": 2, "fuzzy": 1}


@dataclass
class Brand:
    name: str
    aliases: list[str] = field(default_factory=list)
    official_domains: list[str] = field(default_factory=list)

    @cached_property
    def keys(self) -> list[tuple[str, str]]:
        """(raw_key, folded_key) for the name and every alias; keys under 3 characters are ignored."""
        out: list[tuple[str, str]] = []
        for text in [self.name, *self.aliases]:
            pair = (raw_form(text), fold(text))
            if len(pair[0]) >= 3 and pair not in out:
                out.append(pair)
        return out


@dataclass
class BrandMatch:
    brand: str
    match_type: str  # exact_token | contains | fuzzy
    similarity: int  # 0-100, on folded text
    raw_similarity: int  # 0-100, on unfolded text
    token: str  # the token that matched
    obfuscated: bool  # folding was needed to reveal the match
    raw_key: str  # the brand spelling that matched


class Watchlist:
    def __init__(self, brands: list[Brand]):
        self.brands = brands
        self.official_domains: set[str] = set()
        for b in brands:
            for d in b.official_domains:
                host = clean_host(d)
                if host:
                    self.official_domains.add(split_host(host).registrable)

    @classmethod
    def from_dicts(cls, rows: list[dict]) -> "Watchlist":
        return cls([Brand(r["name"], list(r.get("aliases", [])), list(r.get("official_domains", []))) for r in rows])

    def is_official(self, parts: HostParts) -> bool:
        return parts.registrable in self.official_domains

    def brand_by_name(self, name: str) -> Brand | None:
        return next((b for b in self.brands if b.name == name), None)


def _best_similarity(token: str, key: str) -> int:
    """Similarity of key against token; long tokens are scanned with a sliding window only if length is comparable."""
    if len(token) <= len(key) + 2:
        return int(round(_ratio(token, key)))
    # If the token is significantly longer than the brand key (e.g. 'caldodeosso' vs 'icloud'),
    # sliding sub-windows match accidental substrings. Require sub-window match to be at least 92%.
    best = 0.0
    for size in (len(key) - 1, len(key), len(key) + 1):
        for i in range(0, len(token) - size + 1):
            sub = token[i : i + size]
            r = _ratio(sub, key)
            # Only consider sliding window substring if it matches with high precision (>= 92%)
            if r >= 92:
                best = max(best, r)
    return int(round(best))


def match_brand(parts: HostParts, watchlist: Watchlist, threshold: int = DEFAULT_THRESHOLD) -> BrandMatch | None:
    if watchlist.is_official(parts):
        return None
    best: BrandMatch | None = None
    toks = [(t, raw_form(t), fold(t)) for t in tokens(parts)]
    for brand in watchlist.brands:
        for raw_key, fkey in brand.keys:
            short = len(fkey) < SHORT_BRAND_LEN
            for tok, rtok, ftok in toks:
                if ftok == fkey:
                    mtype, sim = "exact_token", 100
                elif not short and fkey in ftok:
                    mtype, sim = "contains", 100
                elif not short and len(ftok) >= 4:
                    sim = _best_similarity(ftok, fkey)
                    if sim < threshold:
                        continue
                    mtype = "fuzzy"
                else:
                    continue
                if mtype == "fuzzy":
                    raw_sim, obf = _best_similarity(rtok, raw_key), False
                else:
                    raw_sim = 100 if (rtok == raw_key or raw_key in rtok) else _best_similarity(rtok, raw_key)
                    obf = not (rtok == raw_key or raw_key in rtok)
                cand = BrandMatch(brand.name, mtype, sim, raw_sim, tok, obf, raw_key)
                if best is None or (_RANK[mtype], sim) > (_RANK[best.match_type], best.similarity):
                    best = cand
    return best


def match_host(host: str, watchlist: Watchlist, threshold: int = DEFAULT_THRESHOLD) -> BrandMatch | None:
    clean = clean_host(host)
    return match_brand(split_host(clean), watchlist, threshold) if clean else None

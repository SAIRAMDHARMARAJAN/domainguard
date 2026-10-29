"""Hostname parsing and look-alike folding. Pure functions, no I/O, nothing is ever fetched."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

# Small built-in public-suffix list (multi-part suffixes only). Single-label TLDs are the default.
# Limitation: no private suffixes (vercel.app, github.io ...). Use the real Public Suffix List in production.
MULTI_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "firm.in", "gen.in", "ind.in",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp",
        "co.nz", "org.nz", "net.nz",
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.my", "com.hk", "com.tw", "com.pk", "com.bd", "com.ng",
        "co.za", "co.kr", "co.id", "co.th", "com.ph", "com.vn", "com.ua", "com.ru",
    }
)

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Common look-alike letters (Cyrillic, Greek) mapped to Latin.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ԛ": "q", "ԝ": "w", "ѵ": "v",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x",
}
# Single-character substitutions applied after multi-character ones (rn->m, vv->w, cl->d).
_CHARMAP = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "4": "a", "@": "a", "$": "s"})


@dataclass
class HostParts:
    host: str  # ascii (punycode) form
    unicode_host: str  # decoded form
    subdomains: list[str]
    label: str  # registrable label, e.g. "abcbank"
    suffix: str  # e.g. "com" or "co.uk"
    has_punycode: bool
    has_non_ascii: bool

    @property
    def registrable(self) -> str:
        return f"{self.label}.{self.suffix}" if self.label else self.host

    @property
    def tld(self) -> str:
        return self.suffix.rsplit(".", 1)[-1]


def clean_host(raw) -> str | None:
    """Extract a valid ASCII hostname from a URL or domain string, or None. Never touches the network."""
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s or len(s) > 2048:
        return None
    s = s.replace("[.]", ".")
    s = re.sub(r"^hxxp", "http", s)
    s = _SCHEME.sub("", s).lstrip("/")
    s = re.split(r"[/?#\\]", s, maxsplit=1)[0]
    if "@" in s:  # http://abcbank.com@evil.net/ -> evil.net
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):  # IPv6 literal
        return None
    s = re.sub(r":\d*$", "", s).rstrip(".")
    while s.startswith("*."):
        s = s[2:]
    if not s or len(s) > 253:
        return None
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = s.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        return None
    if len(labels[-1]) < 2 or not re.search(r"[a-z]", labels[-1]):  # rejects 999.1.1.1 and "e.g"
        return None
    return s


def split_host(host: str) -> HostParts:
    labels = host.split(".")
    n = 1
    if len(labels) >= 3 and ".".join(labels[-3:]) in MULTI_SUFFIXES:
        n = 3
    elif len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        n = 2
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_host = host
    if len(labels) <= n:
        label, subs = "", []
    else:
        label, subs = labels[-n - 1], labels[: -n - 1]
    return HostParts(
        host=host,
        unicode_host=unicode_host,
        subdomains=subs,
        label=label,
        suffix=".".join(labels[len(labels) - n:]),
        has_punycode=any(x.startswith("xn--") for x in labels),
        has_non_ascii=not unicode_host.isascii(),
    )


def _strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def raw_form(s: str) -> str:
    """Lowercase, accent-stripped, with hyphens, dots, underscores and spaces removed."""
    return re.sub(r"[\s\-_.]+", "", _strip_accents(s.lower()))


def fold(s: str) -> str:
    """Fold look-alike characters so 'paypa1' == 'paypal' and 'rnicrosoft' == 'microsoft'."""
    s = "".join(_CONFUSABLES.get(c, c) for c in raw_form(s))
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return s.translate(_CHARMAP)


def tokens(parts: HostParts) -> list[str]:
    """Whole label (hyphens removed) plus hyphen-separated parts, for every label left of the suffix."""
    ulabels = parts.unicode_host.split(".")
    ulabels = ulabels[: max(0, len(ulabels) - (parts.suffix.count(".") + 1))]
    out: list[str] = []
    for lab in ulabels:
        whole = lab.replace("-", "")
        for t in [whole, *lab.split("-")]:
            if t and t not in out:
                out.append(t)
    return out


def defang(domain: str) -> str:
    return domain.replace(".", "[.]")


def extract_hosts(text: str, limit: int = 10) -> list[str]:
    """Pull hostnames out of free text (an SMS, an email). Text is only parsed, nothing is fetched."""
    found: list[str] = []
    for piece in re.split(r"\s+", text or ""):
        piece = piece.strip(".,;:!?()<>\"'`")
        if "." not in piece and "://" not in piece:
            continue
        host = clean_host(piece)
        if host and host not in found:
            found.append(host)
            if len(found) >= limit:
                break
    return found

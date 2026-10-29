"""Blocklist parsing and RDAP helpers. Network access happens only in fetch_text and lookup_rdap,
and only toward the configured feed URLs and rdap.org: never toward any domain found in data."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .normalize import clean_host

USER_AGENT = "DomainGuard/1.0 (research project; set a real contact here)"
MAX_LINES = 300_000


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_url_list(text: str, source: str, listed_at: str | None = None, observed_at: str | None = None) -> list[dict]:
    """One URL or domain per line; comments ignored; de-duplicated by host; capped at MAX_LINES."""
    observed_at = observed_at or _iso(datetime.now(timezone.utc))
    seen: set[str] = set()
    rows: list[dict] = []
    for n, line in enumerate(text.splitlines()):
        if n >= MAX_LINES:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url_candidate = line
        if line.startswith('"') and '","' in line:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 3 and parts[2].startswith("http"):
                url_candidate = parts[2]
        host = clean_host(url_candidate)
        if host is None or host in seen:
            continue
        seen.add(host)
        rows.append({"domain": host, "source": source, "url": url_candidate[:512],
                     "listed_at": listed_at, "observed_at": observed_at})
    return rows


def fetch_text(url: str, headers: dict | None = None, timeout: float = 30, max_bytes: int = 50_000_000) -> str:
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError("only http(s) feed URLs are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("feed larger than size cap")
    return data.decode("utf-8", errors="replace")


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_rdap(payload) -> str | None:
    """Registration timestamp (UTC ISO) or None when missing/redacted."""
    if not isinstance(payload, dict):
        return None
    for ev in payload.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
            dt = _parse_dt(ev.get("eventDate"))
            if dt:
                return _iso(dt)
    return None


def reduce_rdap(payload) -> dict:
    """Keep only non-personal fields. Entities (registrant, contacts) are dropped."""
    if not isinstance(payload, dict):
        return {}
    events = [{"eventAction": e.get("eventAction"), "eventDate": e.get("eventDate")}
              for e in payload.get("events") or [] if isinstance(e, dict)]
    ns = [n.get("ldhName") for n in payload.get("nameservers") or [] if isinstance(n, dict) and n.get("ldhName")]
    return {"ldhName": payload.get("ldhName"), "status": payload.get("status") or [], "events": events, "nameservers": ns}


def lookup_rdap(domain: str, timeout: float = 10) -> tuple[int, str | None, dict]:
    """(http_status, registered_at, reduced_payload). Status 0 means a network error."""
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read(2_000_000).decode("utf-8", errors="replace"))
            return resp.status, parse_rdap(payload), reduce_rdap(payload)
    except urllib.error.HTTPError as e:
        return e.code, None, {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, None, {}


def age_days(registered_at: str | None, now: datetime | None = None) -> float | None:
    dt = _parse_dt(registered_at)
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400)

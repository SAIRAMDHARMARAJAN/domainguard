"""Trusted public safety-news feeds used by the public Safety Center."""
from __future__ import annotations

import logging
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

log = logging.getLogger("domainguard.news")

DEFAULT_FEEDS = (
    ("CISA Cybersecurity Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("FTC Consumer Alerts", "https://consumer.ftc.gov/consumer-alerts/rss.xml"),
)


def _text(element, name: str) -> str:
    value = element.findtext(name) or ""
    return " ".join(value.split())


def fetch_articles(feeds=DEFAULT_FEEDS, *, fetch=None, limit: int = 8) -> list[dict]:
    """Fetch a small, sanitized list of articles. A failed feed is skipped."""
    fetch = fetch or _fetch
    articles: list[dict] = []
    for source, url in feeds:
        try:
            root = ET.fromstring(fetch(url))
            for item in root.findall(".//item"):
                title, link = _text(item, "title"), _text(item, "link")
                if not title or not link or not link.startswith(("https://", "http://")):
                    continue
                articles.append({"source": source, "title": title, "url": link,
                                 "published_at": _text(item, "pubDate")})
                if len(articles) >= limit:
                    return articles
        except (OSError, ET.ParseError, ValueError) as exc:
            log.warning("safety-news feed unavailable (%s): %s", source, exc)
    return articles


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "DomainGuard/1.0 safety-news"})
    with urllib.request.urlopen(request, timeout=8) as response:
        return response.read(512_000)

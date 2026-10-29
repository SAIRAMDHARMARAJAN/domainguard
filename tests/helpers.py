"""Shared builders for the v7 tests (no network, no Snowflake)."""
import os
from datetime import datetime, timedelta, timezone

from domainguard.config import Settings
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.registration import Registrar

T0 = datetime(2026, 10, 25, 6, 0, tzinfo=timezone.utc)
ISO = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
SECRET = "test-secret-key-0123456789abcdefghij"


def settings(tmp_path, **kw):
    base = dict(stage_dir=str(tmp_path / "stage"), state_dir=str(tmp_path / "state"), secret_key=SECRET,
                web_domain="https://dg.example.test", smtp_from="alerts@dg.example.test", smtp_host="",
                watchlist_ttl_s=30)
    base.update(kw)
    return Settings(**base)


def company(wh, name, domain, email=None, notify=True, freq="IMMEDIATE", aliases=None):
    """Create an ACTIVE company protecting `domain` directly (faster than the registration flow)."""
    cid = f"cid-{name}"
    wh.create_user({"company_id": cid, "name": name, "email": email or f"sec@{name}.test", "status": "ACTIVE",
                    "email_notifications": notify, "notification_email": email or f"sec@{name}.test"})
    wh.update_user(cid, {"api_key_hash": None})
    wh.upsert_protected({"company_id": cid, "domain": domain, "brand_aliases": aliases or [],
                         "official_domains": [domain]})
    if freq != "IMMEDIATE":
        wh.set_prefs(cid, {"notification_frequency": freq})
    return cid


def seed_bronze(wh, certs=(), blocklist=(), rdap=()):
    if certs:
        wh.write_bronze("certstream", list(certs), "t.jsonl.gz")
    if blocklist:
        wh.write_bronze("blocklist", list(blocklist), "t.jsonl.gz")
    if rdap:
        wh.write_bronze("rdap", list(rdap), "t.jsonl.gz")


def cert_row(domain, seen=None, brand="abcbank", match_type="fuzzy", similarity=93):
    return {"domain": domain, "brand": brand, "match_type": match_type, "similarity": similarity,
            "seen_at": ISO(seen or T0 - timedelta(minutes=5)), "raw": {"domains_in_cert": 1}}


def rdap_row(domain, registered, status=200):
    return {"domain": domain, "fetched_at": ISO(T0), "http_status": status, "registered_at": registered,
            "payload": {"ldhName": domain}}


def block_row(domain, observed, listed=None, source="openphish"):
    return {"domain": domain, "source": source, "url": f"http://{domain}/x", "listed_at": listed,
            "observed_at": observed}


def memory_env(tmp_path, monkeypatch=None):
    os.environ.setdefault("DG_ALLOW_MEMORY_WAREHOUSE", "1")
    return MemoryWarehouse(), settings(tmp_path)

import gzip
import json
from datetime import timedelta
from pathlib import Path

import pytest

from domainguard import feeds
from domainguard.loader import load_stage, verify_stage
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.pipeline import score_all
from domainguard.stage import StageWriter
from domainguard.watchlist import WarehouseWatchlist, brand_rows
from tests.helpers import T0, ISO, block_row, cert_row, company, rdap_row

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# ---- watchlist -----------------------------------------------------------------
def test_brand_rows_use_registrable_label_and_all_official_domains():
    rows = [{"domain": "abcbank.com", "brand_aliases": ["abc bank"], "official_domains": ["abcbank.co.in"]}]
    b = brand_rows(rows)[0]
    assert b["name"] == "abcbank" and "abc bank" in b["aliases"] and "abcbank" in b["aliases"]
    assert b["official_domains"] == ["abcbank.com", "abcbank.co.in"]


def test_watchlist_reloads_after_ttl_and_keeps_last_good_list_on_failure(tmp_path):
    wh, clk = MemoryWarehouse(), Clock()
    company(wh, "abcbank", "abcbank.com")
    wl = WarehouseWatchlist(wh, ttl_s=30, clock=clk, cache_path=tmp_path / "c.json")
    assert set(wl.per_company()) == {"cid-abcbank"}
    company(wh, "acme", "acme.com")
    clk.t = 10
    assert set(wl.per_company()) == {"cid-abcbank"}  # inside the TTL: no reload yet
    clk.t = 31
    assert set(wl.per_company()) == {"cid-abcbank", "cid-acme"}
    wh.active_protected_rows = lambda: (_ for _ in ()).throw(OSError("snowflake down"))
    clk.t = 70
    assert set(wl.per_company()) == {"cid-abcbank", "cid-acme"} and "snowflake down" in wl.last_error


def test_watchlist_uses_cache_file_when_warehouse_is_down_at_startup(tmp_path):
    wh, clk = MemoryWarehouse(), Clock()
    company(wh, "abcbank", "abcbank.com")
    WarehouseWatchlist(wh, clock=clk, cache_path=tmp_path / "c.json")
    down = MemoryWarehouse()
    down.active_protected_rows = lambda: (_ for _ in ()).throw(OSError("no route"))
    wl = WarehouseWatchlist(down, clock=clk, cache_path=tmp_path / "c.json")
    assert [b.name for b in wl.current().brands] == ["abcbank"]


def test_watchlist_per_company_split():
    wh, clk = MemoryWarehouse(), Clock()
    company(wh, "abcbank", "abcbank.com")
    company(wh, "paypal", "paypal.com")
    wl = WarehouseWatchlist(wh, clock=clk)
    assert set(wl.per_company()) == {"cid-abcbank", "cid-paypal"}
    assert wl.per_company()["cid-paypal"].brands[0].name == "paypal"


# ---- loader --------------------------------------------------------------------------
def stage_with(tmp_path, rows_by_source):
    w = StageWriter(tmp_path / "stage")
    for src, rows in rows_by_source.items():
        w.write_batch(src, rows)
    return tmp_path / "stage"


def test_load_is_checksum_verified_idempotent_and_logged(tmp_path):
    stage = stage_with(tmp_path, {"certstream": [cert_row("a.com")], "blocklist": [block_row("a.com", ISO(T0))],
                                  "rdap": [rdap_row("a.com", "2026-10-01T00:00:00Z")]})
    wh = MemoryWarehouse()
    r1 = load_stage(stage, wh, sleep=lambda s: None)
    assert (r1["files_loaded"], r1["files_skipped"], r1["errors"]) == (3, 0, [])
    assert len(wh.load_log()) == 3 and all(e["status"] == "SUCCESS" for e in wh.load_log())
    assert len(wh.bronze["certstream"]) == 1
    r2 = load_stage(stage, wh, sleep=lambda s: None)
    assert (r2["files_loaded"], r2["files_skipped"]) == (0, 3) and len(wh.bronze["certstream"]) == 1


def test_tampered_file_is_refused_and_nothing_loaded(tmp_path):
    stage = stage_with(tmp_path, {"certstream": [cert_row("a.com")]})
    f = next((stage / "certstream").rglob("*.jsonl.gz"))
    f.write_bytes(gzip.compress(b'{"domain":"evil.com"}\n'))
    wh = MemoryWarehouse()
    rep = load_stage(stage, wh, sleep=lambda s: None)
    assert rep["files_loaded"] == 0 and any("checksum mismatch" in e for e in rep["errors"])
    assert wh.bronze["certstream"] == []


def test_file_without_manifest_entry_is_refused(tmp_path):
    stage = stage_with(tmp_path, {"rdap": [rdap_row("a.com", None)]})
    (stage / "rdap" / "_manifest.jsonl").unlink()
    ok, errors = verify_stage(stage)
    assert ok == [] and any("no manifest entry" in e for e in errors)


def test_outage_marks_failed_then_next_run_loads_it(tmp_path):
    stage = stage_with(tmp_path, {"certstream": [cert_row("a.com")]})
    wh = MemoryWarehouse()
    calls = {"n": 0}
    real = wh.write_bronze

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] <= 11:  # more than the 10 retries: this run fails
            raise OSError("snowflake unreachable")
        return real(*a, **k)

    wh.write_bronze = flaky
    alerts, waits = [], []
    rep = load_stage(stage, wh, sleep=waits.append, alert=alerts.append)
    assert rep["files_failed"] == 1 and wh.load_log()[0]["status"] == "FAILED"
    assert len(alerts) == 1 and waits[:5] == [1, 2, 4, 8, 16]
    rep2 = load_stage(stage, wh, sleep=lambda s: None)
    assert rep2["files_loaded"] == 1 and wh.load_log()[-1]["status"] == "SUCCESS"


def test_copy_path_is_used_when_available(tmp_path):
    stage = stage_with(tmp_path, {"blocklist": [block_row("a.com", ISO(T0))]})
    wh = MemoryWarehouse()
    used = []
    wh.copy_file = lambda src, path, name: used.append((src, name)) or 1
    rep = load_stage(stage, wh, sleep=lambda s: None)
    assert rep["files_loaded"] == 1 and used[0][0] == "blocklist"


# ---- pipeline (the v1 worked examples through the warehouse) --------------------------------
def scenario():
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com", aliases=["abc bank"])
    company(wh, "paypal", "paypal.com")
    wh.write_bronze("certstream", [cert_row("abcbannk-login.com"), cert_row("pizza-shop.com", brand="x"),
                                   cert_row("abcbank.com", brand="abcbank"), cert_row("paypa1-secure-login.xyz", brand="paypal")], "f")
    wh.write_bronze("rdap", [rdap_row("abcbannk-login.com", ISO(T0 - timedelta(hours=2)))], "r")
    return wh


def companies(wh):
    return WarehouseWatchlist(wh, clock=Clock()).per_company()


def test_worked_examples_match_version_one():
    wh = scenario()
    summary = score_all(wh, companies(wh), now=T0)
    v = wh.get_verdict("abcbannk-login.com", "cid-abcbank")
    assert (v["score"], v["classification"]) == (44, "SUSPICIOUS")  # 2 h old: age 20 pts
    assert v["breakdown"]["domain_age"] == 20 and v["first_flagged_at"] == ISO(T0)
    assert wh.get_verdict("paypa1-secure-login.xyz", "cid-paypal")["score"] == 78  # unknown age: 78, as in v1 docs
    assert summary["stored"] >= 2


def test_domains_are_attributed_to_the_company_they_imitate_only():
    wh = scenario()
    score_all(wh, companies(wh), now=T0)
    assert wh.get_verdict("abcbannk-login.com", "cid-paypal") is None
    assert wh.get_verdict("paypa1-secure-login.xyz", "cid-abcbank") is None
    assert wh.get_verdict("pizza-shop.com") is None  # unrelated to any company: never stored


def test_official_domain_is_never_flagged():
    wh = scenario()
    score_all(wh, companies(wh), now=T0)
    assert wh.get_verdict("abcbank.com", "cid-abcbank") is None  # official domains are not stored as threats


def test_blocklist_only_matters_for_related_domains():
    wh = scenario()
    wh.write_bronze("blocklist", [block_row("pizza-shop.com", ISO(T0)), block_row("abcbannk-login.com", ISO(T0))], "b")
    score_all(wh, companies(wh), now=T0 + timedelta(hours=1))
    assert wh.get_verdict("pizza-shop.com") is None
    v = wh.get_verdict("abcbannk-login.com", "cid-abcbank")
    assert v["classification"] == "DANGEROUS" and v["is_on_blocklist"] and v["score"] == 44


def test_newly_flagged_is_reported_once_and_first_flag_never_moves():
    wh = scenario()
    first = score_all(wh, companies(wh), now=T0)
    assert {x["domain"] for x in first["newly_flagged"]} == {"abcbannk-login.com", "paypa1-secure-login.xyz"}
    again = score_all(wh, companies(wh), now=T0 + timedelta(hours=3))
    assert again["newly_flagged"] == []
    assert wh.get_verdict("abcbannk-login.com", "cid-abcbank")["first_flagged_at"] == ISO(T0)


def test_first_listing_time_flows_into_verdict():
    wh = scenario()
    wh.write_bronze("blocklist", [block_row("paypa1-secure-login.xyz", ISO(T0 + timedelta(hours=4)))], "b")
    score_all(wh, companies(wh), now=T0 + timedelta(hours=5))
    v = wh.get_verdict("paypa1-secure-login.xyz", "cid-paypal")
    assert v["first_listed_at"] == ISO(T0 + timedelta(hours=4))



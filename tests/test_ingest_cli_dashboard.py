import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import domainguard.factory as factory
from domainguard.cli import main as cli_main
from domainguard.ingest import Ingest
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.pipeline import score_all
from domainguard.watchlist import WarehouseWatchlist
from tests.helpers import T0, ISO, company, cert_row, rdap_row, seed_bronze, settings

ROOT = Path(__file__).resolve().parents[1]


# ---- ingestion runner (offline fakes for the network) ----------------------------------
def test_replay_feeds_rdap_load_score_end_to_end(tmp_path):
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com")
    s = settings(tmp_path, openphish_url="http://feed.invalid/x")
    rdap_dates = json.loads((ROOT / "data/sample_rdap.json").read_text())
    ing = Ingest(s, wh, fetch=lambda u, h=None: (ROOT / "data/sample_blocklist.txt").read_text(),
                 lookup=lambda d: (200, rdap_dates[d], {}) if d in rdap_dates else (404, None, {}), sleep=lambda x: None)
    stats = ing.replay(ROOT / "data/sample_events.jsonl")
    assert stats["candidates"] >= 5 and stats["flush_errors"] == 0
    feed_report = ing.feeds_once()["openphish"]
    assert feed_report["new"] == 1 and feed_report["watchlist_matches"] == 1
    assert ing.rdap_once(50)["staged"] >= 1
    assert ing.load()["files_loaded"] >= 3
    assert ing.load()["files_loaded"] == 0  # idempotent
    rep = ing.score(now=T0 + timedelta(days=1))
    assert rep["stored"] > 0 and wh.verdicts()


def test_health_file_is_written(tmp_path):
    wh = MemoryWarehouse()
    s = settings(tmp_path)
    ing = Ingest(s, wh, sleep=lambda x: None)
    ing.replay(ROOT / "data/sample_events.jsonl")
    health = json.loads((tmp_path / "state" / "health.json").read_text())
    assert health["status"] in ("starting", "ok", "stale") and "collector" in health


def test_watchlist_cache_survives_a_snowflake_outage(tmp_path):
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com")
    s = settings(tmp_path)
    Ingest(s, wh, sleep=lambda x: None)  # writes the cache on startup
    wh.active_protected_rows = lambda: (_ for _ in ()).throw(OSError("down"))
    ing = Ingest(s, wh, sleep=lambda x: None)
    assert [b.name for b in ing.watchlist.current().brands] == ["abcbank"]


# ---- CLI -----------------------------------------------------------------------------------
def test_cli_refuses_to_run_without_snowflake(monkeypatch, tmp_path):
    monkeypatch.delenv("DG_ALLOW_MEMORY_WAREHOUSE", raising=False)
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.chdir(tmp_path)
    assert cli_main(["score"]) == 2


def test_cli_health_without_snowflake(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("DG_ALLOW_MEMORY_WAREHOUSE", raising=False)
    monkeypatch.setenv("DG_STATE_DIR", str(tmp_path))
    assert cli_main(["health"]) == 0
    assert "no health file" in capsys.readouterr().out


def test_cli_check_reports_missing_settings(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
    monkeypatch.delenv("SNOWFLAKE_USER", raising=False)
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.setenv("DG_ALLOW_MEMORY_WAREHOUSE", "1")
    monkeypatch.setenv("DG_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("DG_STAGE_DIR", str(tmp_path / "stage"))
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["check"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and any(c["check"] == "snowflake settings" and not c["ok"] for c in out["checks"])


def test_setup_check_lists_every_required_table():
    from domainguard.setup_check import REQUIRED_TABLES
    sql = "\n".join(p.read_text() for p in (ROOT / "sql").glob("*.sql")).upper()
    missing = [t for t in REQUIRED_TABLES if t.upper() not in sql]
    assert missing == [], missing


# ---- scripts --------------------------------------------------------------------------------
def test_demo_runs_end_to_end():
    env = {**os.environ, "DG_ALLOW_MEMORY_WAREHOUSE": "1"}
    out = subprocess.run([sys.executable, str(ROOT / "scripts/demo.py")], capture_output=True, text=True, env=env,
                         timeout=120)
    assert out.returncode == 0, out.stderr[-800:]
    for needle in ("registered", "threat inbox", "notify_new", "public API", "takedown", "Nothing is sent"):
        assert needle.lower() in out.stdout.lower() or needle in out.stdout
    assert "401" in out.stdout  # analyst endpoint refuses callers without a key


def test_migrate_script_plans_one_company_per_brand():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from migrate_from_json import plan
        items = plan(json.loads((ROOT / "data/watchlist.json").read_text()))
    finally:
        sys.path.pop(0)
    names = {i["company"]["name"] for i in items}
    source = {r["name"] for r in json.loads((ROOT / "data/watchlist.json").read_text())}
    assert names == source and {"abcbank", "paypal"} <= names
    assert all(i["company"]["email_notifications"] is False for i in items)  # opt-in only
    assert all(p["domain"] for i in items for p in i["protected"])


def test_setup_script_splits_statements_including_procedures():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from setup_snowflake import split_statements
        stmts = split_statements((ROOT / "sql/06_roles_and_maintenance.sql").read_text())
    finally:
        sys.path.pop(0)
    procs = [s for s in stmts if "PROCEDURE" in s]
    assert len(procs) == 1 and procs[0].count("$$") == 2  # the ';' inside the body did not split the procedure


# ---- dashboard (headless) ------------------------------------------------------------------------
@pytest.fixture
def dash(tmp_path, monkeypatch):
    import streamlit as st
    st.cache_resource.clear()
    wh = MemoryWarehouse()
    company(wh, "paypal", "paypal.com")
    seed_bronze(wh, certs=[cert_row("paypa1-secure-login.xyz", brand="paypal")],
                rdap=[rdap_row("paypa1-secure-login.xyz", ISO(T0 - timedelta(hours=2)))])
    score_all(wh, WarehouseWatchlist(wh).per_company(), now=T0)
    monkeypatch.setattr(factory, "make_warehouse", lambda *a, **k: wh)
    monkeypatch.setenv("DG_WATCHLIST", str(ROOT / "data/watchlist.json"))
    monkeypatch.delenv("DG_ANALYST_TOKEN", raising=False)
    return wh


def test_dashboard_overview_shows_campaign_summary(dash):
    at = AppTest.from_file(str(ROOT / "domainguard/dashboard.py"), default_timeout=60).run()
    assert not at.exception
    df = at.dataframe[0].value
    assert "campaign" in df.columns and "paypal" in set(df["campaign"])


def test_dashboard_token_gate(dash, monkeypatch):
    monkeypatch.setenv("DG_ANALYST_TOKEN", "s3cret-token")
    at = AppTest.from_file(str(ROOT / "domainguard/dashboard.py"), default_timeout=60).run()
    assert not at.dataframe
    at.text_input(key="token_input").set_value("wrong").run()
    assert at.error and not at.dataframe
    at.text_input(key="token_input").set_value("s3cret-token").run()
    assert at.dataframe


def test_dashboard_investigation_renders_evidence(dash):
    at = AppTest.from_file(str(ROOT / "domainguard/dashboard.py"), default_timeout=60).run()
    at.sidebar.radio(key="page").set_value("Investigate").run()
    assert not at.exception
    assert any("Evidence timeline" in h.value for h in at.subheader)


@pytest.mark.parametrize("page", ["Overview", "Investigate", "Cases", "Watchlist"])
def test_every_dashboard_page_renders_without_error(dash, page):
    at = AppTest.from_file(str(ROOT / "domainguard/dashboard.py"), default_timeout=60).run()
    at.sidebar.radio(key="page").set_value(page).run()
    assert not at.exception, [e.value for e in at.exception]

import pytest

from domainguard.config import Settings
from domainguard.factory import make_warehouse
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.retry import ALERT_AFTER, MAX_RETRIES, RetriesExhausted, call_with_retry, delay_for
from domainguard.warehouse import SnowflakeWarehouse, Warehouse


# ---- config ------------------------------------------------------------------
def test_settings_from_env_and_defaults():
    s = Settings.from_env({"SNOWFLAKE_ACCOUNT": "a", "SNOWFLAKE_USER": "u", "SNOWFLAKE_PASSWORD": "p",
                           "OPENROUTER_MODELS": "m1, m2", "API_RATE_LIMIT_PER_MIN": "7", "DG_SECRET_KEY": "k"})
    assert (s.sf_account, s.sf_warehouse, s.sf_database) == ("a", "DG_WH", "DOMAINGUARD")
    assert s.openrouter_models == ("m1", "m2") and s.api_rate_limit_per_min == 7 and s.secret_key == "k"
    assert s.missing_snowflake() == []


def test_missing_snowflake_is_reported():
    assert Settings.from_env({}).missing_snowflake() == ["SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD"]


def test_factory_refuses_memory_in_production_and_requires_snowflake(monkeypatch):
    monkeypatch.delenv("DG_ALLOW_MEMORY_WAREHOUSE", raising=False)
    with pytest.raises(RuntimeError, match="Snowflake is required"):
        make_warehouse(Settings.from_env({}))
    monkeypatch.setenv("DG_ALLOW_MEMORY_WAREHOUSE", "1")
    assert isinstance(make_warehouse(Settings.from_env({})), MemoryWarehouse)


def test_factory_returns_snowflake_when_configured(monkeypatch):
    monkeypatch.delenv("DG_ALLOW_MEMORY_WAREHOUSE", raising=False)
    s = Settings(sf_account="a", sf_user="u", sf_password="p")
    assert isinstance(make_warehouse(s), SnowflakeWarehouse)


# ---- retry -----------------------------------------------------------------------
def test_backoff_sequence_and_cap():
    assert [delay_for(i) for i in range(1, 9)] == [1, 2, 4, 8, 16, 32, 60, 60]


def test_retry_succeeds_after_transient_failures():
    calls, waits = [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("down")
        return "ok"

    assert call_with_retry(flaky, what="x", sleep=waits.append) == "ok"
    assert waits == [1, 2]


def test_alert_fires_at_five_failures_then_gives_up_after_ten_retries():
    alerts, waits = [], []

    def always():
        raise OSError("snowflake unreachable")

    with pytest.raises(RetriesExhausted) as info:
        call_with_retry(always, what="load", sleep=waits.append, alert=alerts.append)
    assert info.value.attempts == MAX_RETRIES + 1
    assert len(alerts) == 1 and "5 consecutive failures" in alerts[0]
    assert len(waits) == MAX_RETRIES and ALERT_AFTER == 5


# ---- warehouse contract -------------------------------------------------------------
def test_both_implementations_provide_the_full_interface():
    names = {n for n in dir(Warehouse) if not n.startswith("_") and callable(getattr(Warehouse, n))}
    assert names - set(dir(MemoryWarehouse)) == set()
    assert names - set(dir(SnowflakeWarehouse)) == set()



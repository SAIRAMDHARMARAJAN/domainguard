"""Checks the Snowflake adapter's statements with a recording connection (no account needed).
What this proves: parameters are bound, transactions wrap multi-row writes, rollback happens on failure, and an
injection attempt stays inside the bound parameter. What it does NOT prove: that Snowflake accepts the SQL. That
needs a real trial account (see README)."""
import pytest

from domainguard.warehouse import SnowflakeWarehouse

INJECTION = "x'; DROP TABLE REF.USERS; --"


class Rec:
    def __init__(self, fail_on=None, rows=None):
        self.log, self.fail_on, self.rows = [], fail_on, rows or []

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.log.append((sql, tuple(params or ())))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("boom")

    def executemany(self, sql, seq):
        for p in seq:
            self.execute(sql, p)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def close(self):
        pass


def wh_with(conn):
    return SnowflakeWarehouse(connect=lambda: conn)


def test_every_placeholder_has_a_parameter():
    conn = Rec(rows=[])
    wh = wh_with(conn)
    wh.get_user("c1")
    wh.update_user("c1", {"status": "ACTIVE"})
    wh.upsert_protected({"company_id": "c1", "domain": "abcbank.com", "brand_aliases": ["abc"], "official_domains": []})
    wh.set_prefs("c1", {"notification_frequency": "DAILY"})
    wh.get_verdict("abcbank.com", "c1")
    for sql, params in conn.log:
        assert sql.count("%s") == len(params), sql[:120]


def test_injection_text_stays_in_parameters_not_sql():
    conn = Rec(rows=[])
    wh_with(conn).get_user_by_email(INJECTION)
    wh_with(conn).get_verdict(INJECTION, INJECTION)
    for sql, params in conn.log:
        assert INJECTION not in sql
    assert conn.log[0][1] == (INJECTION,)


def test_bronze_write_is_one_transaction():
    conn = Rec()
    n = wh_with(conn).write_bronze("certstream", [{"domain": "a.com", "brand": "x", "match_type": "fuzzy",
                                                   "similarity": 90, "seen_at": "2026-10-25T06:00:00Z", "raw": {}}] * 3,
                                   "file.jsonl.gz")
    assert n == 3
    kinds = [s.split()[0] for s, _ in conn.log]
    assert kinds[0] == "BEGIN" and kinds[-1] == "COMMIT" and kinds.count("INSERT") == 3


def test_failed_bronze_write_rolls_back():
    conn = Rec(fail_on="INSERT INTO BRONZE.CERTSTREAM_EVENTS")
    with pytest.raises(RuntimeError):
        wh_with(conn).write_bronze("certstream", [{"domain": "a.com", "raw": {}, "seen_at": "2026-10-25T06:00:00Z"}], "f")
    assert conn.log[-1][0] == "ROLLBACK" and "COMMIT" not in [s for s, _ in conn.log]


def test_write_score_is_transactional_and_keeps_first_flag_in_sql():
    conn = Rec(rows=[])
    wh = wh_with(conn)
    wh.write_score({"domain": "a.com", "company_id": "c", "score": 50, "classification": "SUSPICIOUS",
                    "evidence": ["e"], "breakdown": {"keywords": 5}, "is_on_blocklist": False,
                    "last_evaluated_at": "2026-10-25T06:00:00Z", "scoring_version": "1.0"})
    stmts = [s for s, _ in conn.log]
    assert stmts[0] == "BEGIN" and "COMMIT" in stmts and stmts.index("COMMIT") > stmts.index(next(x for x in stmts if x.startswith("MERGE")))
    merge = next(s for s, _ in conn.log if s.startswith("MERGE INTO GOLD.DOMAIN_VERDICT"))
    assert "COALESCE(t.FIRST_FLAGGED_AT" in merge


def test_takedown_update_rejects_unknown_fields_and_stamps_times():
    conn = Rec()
    wh = wh_with(conn)
    with pytest.raises(ValueError):
        wh.update_takedown("d1", {"status": "SENT", "approver_signature; DROP": "x"})
    wh.update_takedown("d1", {"status": "APPROVED", "approved_at": "ignored"})
    sql, params = conn.log[-1]
    assert "APPROVED_AT = SYSDATE()" in sql and "ignored" not in params


def test_copy_file_uses_put_then_copy_with_abort_on_error(tmp_path):
    f = tmp_path / "x.jsonl.gz"
    f.write_bytes(b"")
    conn = Rec(rows=[])
    wh_with(conn).copy_file("blocklist", str(f), "blocklist/dt=1/hh=00/x.jsonl.gz")
    sqls = [s for s, _ in conn.log]
    assert sqls[0].startswith("PUT 'file://") and "AUTO_COMPRESS = FALSE" in sqls[0]
    assert any("COPY INTO BRONZE.BLOCKLIST_FEED" in s and "ON_ERROR = ABORT_STATEMENT" in s for s in sqls)

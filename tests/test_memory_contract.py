"""The in-memory double must follow the same rules as Snowflake. These tests pin those rules."""
from datetime import timedelta

from domainguard.memory_warehouse import MemoryWarehouse
from tests.helpers import T0, ISO, block_row, cert_row, company, rdap_row, seed_bronze


def verdict(**kw):
    base = {"domain": "a.com", "company_id": "c1", "score": 50, "classification": "SUSPICIOUS", "evidence": ["e"],
            "breakdown": {"keywords": 5}, "is_on_blocklist": False, "last_evaluated_at": ISO(T0),
            "scoring_version": "1.0", "matched_brand": "abcbank"}
    base.update(kw)
    return base


def test_first_flag_is_set_once_and_never_overwritten():
    wh = MemoryWarehouse()
    first = wh.write_score(verdict())
    assert first["first_flagged_at"] == ISO(T0)
    later = wh.write_score(verdict(score=80, classification="HIGH_RISK", last_evaluated_at=ISO(T0 + timedelta(hours=5))))
    assert later["first_flagged_at"] == ISO(T0) and later["score"] == 80


def test_low_verdicts_are_not_flagged():
    wh = MemoryWarehouse()
    v = wh.write_score(verdict(score=20, classification="LOW"))
    assert v["first_flagged_at"] is None


def test_one_verdict_per_domain_and_company():
    wh = MemoryWarehouse()
    wh.write_score(verdict(company_id="c1", score=40))
    wh.write_score(verdict(company_id="c2", score=70, classification="HIGH_RISK"))
    assert len(wh.verdicts()) == 2
    assert wh.get_verdict("a.com")["score"] == 70  # public lookup returns the worst case
    assert wh.get_verdict("a.com", "c1")["score"] == 40


def test_candidates_aggregate_and_blocklist_takes_earliest_listing():
    wh = MemoryWarehouse()
    seed_bronze(wh, certs=[cert_row("a.com", seen=T0), cert_row("a.com", seen=T0 + timedelta(hours=1))],
                blocklist=[block_row("a.com", ISO(T0 + timedelta(hours=3))),
                           block_row("a.com", ISO(T0 + timedelta(hours=2)), listed=ISO(T0 + timedelta(hours=1)),
                                     source="urlhaus")])
    c = wh.candidates()[0]
    assert (c["cert_count"], c["first_seen_at"], c["last_seen_at"]) == (2, ISO(T0), ISO(T0 + timedelta(hours=1)))
    b = wh.blocklist_index()["a.com"]
    assert b["first_listed_at"] == ISO(T0 + timedelta(hours=1)) and b["sources"] == ["openphish", "urlhaus"]


def test_rdap_index_uses_only_successful_fetches_with_a_date():
    wh = MemoryWarehouse()
    seed_bronze(wh, rdap=[rdap_row("a.com", "2026-10-01T00:00:00Z", 200), rdap_row("b.com", None, 200),
                          rdap_row("c.com", "2026-10-01T00:00:00Z", 404)])
    assert wh.rdap_index() == {"a.com": "2026-10-01T00:00:00Z"}


def test_inbox_orders_by_score_then_oldest_flag_and_respects_company_and_since():
    wh = MemoryWarehouse()
    wh.write_score(verdict(domain="x.com", company_id="c1", score=80, classification="HIGH_RISK", last_evaluated_at=ISO(T0)))
    wh.write_score(verdict(domain="y.com", company_id="c1", score=80, classification="HIGH_RISK",
                           last_evaluated_at=ISO(T0 + timedelta(hours=1))))
    wh.write_score(verdict(domain="z.com", company_id="c2", score=90, classification="DANGEROUS"))
    assert [v["domain"] for v in wh.inbox("c1")] == ["x.com", "y.com"]
    assert [v["domain"] for v in wh.inbox()][0] == "z.com"
    assert [v["domain"] for v in wh.inbox("c1", since=ISO(T0 + timedelta(minutes=30)))] == ["y.com"]  # flagged after the cutoff


def test_feedback_is_append_only_and_latest_label_wins():
    wh = MemoryWarehouse()
    wh.write_score(verdict())
    wh.add_feedback({"domain": "a.com", "company_id": "c1", "analyst_email": "a@x.test", "label": "FALSE_POSITIVE"})
    wh.add_feedback({"domain": "a.com", "company_id": "c1", "analyst_email": "b@x.test", "label": "CONFIRMED_THREAT"})
    assert len(wh.feedback_history("a.com")) == 2
    assert wh.inbox("c1")[0]["analyst_label"] == "CONFIRMED_THREAT"


def test_load_log_and_idempotent_bookkeeping():
    wh = MemoryWarehouse()
    assert wh.loaded_file("f") is None
    wh.log_load({"file_name": "f", "source": "rdap", "row_count": 1, "sha256": "h", "status": "FAILED"})
    assert wh.loaded_file("f")["status"] == "FAILED"


def test_active_protected_rows_hide_suspended_companies_and_removed_domains():
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com")
    company(wh, "acme", "acme.com")
    wh.update_user("cid-acme", {"status": "SUSPENDED"})
    assert [r["domain"] for r in wh.active_protected_rows()] == ["abcbank.com"]
    wh.remove_protected("cid-abcbank", "abcbank.com")
    assert wh.active_protected_rows() == []


def test_duplicate_email_refused():
    import pytest
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com", email="same@x.test")
    with pytest.raises(ValueError):
        wh.create_user({"company_id": "other", "name": "n", "email": "SAME@x.test"})


def test_email_log_and_alert_dedupe_and_prefs_defaults():
    wh = MemoryWarehouse()
    assert wh.get_prefs("c1") == {"email_notifications": True, "notification_frequency": "IMMEDIATE",
                                  "min_score_threshold": 70, "notification_email": None, "frequency_last_sent_at": None}
    wh.log_email({"company_id": "c1", "domain": "a.com", "recipient_email": "x", "status": "SENT", "kind": "ALERT"})
    assert wh.alert_sent("c1", "a.com") and not wh.alert_sent("c1", "b.com")

import ast
from datetime import timedelta
from pathlib import Path

import pytest

import domainguard.takedown as takedown_module
from domainguard import evaluation
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.pipeline import score_all
from domainguard.takedown import SIGNATURE, approve, draft, export_text, mark_sent_manually, reject
from domainguard.watchlist import WarehouseWatchlist
from domainguard.matcher import Watchlist
from tests.helpers import T0, ISO, block_row, cert_row, company, rdap_row, seed_bronze

SIG = SIGNATURE


def flagged_wh():
    wh = MemoryWarehouse()
    company(wh, "paypal", "paypal.com")
    seed_bronze(wh, certs=[cert_row("paypa1-secure-login.xyz", brand="paypal"), cert_row("paypa2-login.xyz", brand="paypal")],
                rdap=[rdap_row("paypa1-secure-login.xyz", ISO(T0 - timedelta(hours=3)))])
    score_all(wh, WarehouseWatchlist(wh).per_company(), now=T0)
    return wh, wh.get_verdict("paypa1-secure-login.xyz", "cid-paypal")


# ---- takedown ----------------------------------------------------------------------
def test_draft_needs_named_analyst_and_is_pending():
    wh, v = flagged_wh()
    with pytest.raises(ValueError):
        draft(wh, v, analyst_name="", analyst_email="a@b.test")
    with pytest.raises(ValueError):
        draft(wh, v, analyst_name="Ravi", analyst_email="not-an-email")
    did = draft(wh, v, analyst_name="Ravi", analyst_email="ravi@x.test")
    t = wh.get_takedown(did)
    assert t["status"] == "DRAFT" and "Ravi <ravi@x.test>" in t["draft_text"]
    assert "paypa1-secure-login[.]xyz" in t["draft_text"]  # defanged inside the draft


def test_approval_needs_exact_signature_and_a_name():
    wh, v = flagged_wh()
    did = draft(wh, v, analyst_name="Ravi", analyst_email="ravi@x.test")
    with pytest.raises(ValueError, match="type exactly"):
        approve(wh, did, analyst_name="Ravi", analyst_email="ravi@x.test", signature="yes")
    with pytest.raises(ValueError):
        approve(wh, did, analyst_name="", analyst_email="ravi@x.test", signature=SIG)
    t = approve(wh, did, analyst_name="Ravi", analyst_email="ravi@x.test", signature=f"  {SIG}  ")
    assert t["status"] == "APPROVED" and SIG in t["approver_signature"] and t["approved_at"]


def test_only_approved_drafts_export_and_export_is_recorded():
    wh, v = flagged_wh()
    did = draft(wh, v, analyst_name="Ravi", analyst_email="ravi@x.test")
    with pytest.raises(ValueError, match="expected one of"):
        export_text(wh, did)
    approve(wh, did, analyst_name="Ravi", analyst_email="ravi@x.test", signature=SIG)
    text = export_text(wh, did)
    assert "paypa1-secure-login.xyz" in text and "[.]" not in text  # real name for the provider's form
    assert wh.get_takedown(did)["status"] == "EXPORTED" and wh.get_takedown(did)["exported_at"]
    assert mark_sent_manually(wh, did, analyst_name="Ravi")["status"] == "SENT"


def test_rejected_draft_cannot_be_approved_later():
    wh, v = flagged_wh()
    did = draft(wh, v, analyst_name="Ravi", analyst_email="ravi@x.test")
    assert reject(wh, did, analyst_name="Ravi")["status"] == "REJECTED"
    with pytest.raises(ValueError):
        approve(wh, did, analyst_name="Ravi", analyst_email="ravi@x.test", signature=SIG)


def test_takedown_module_cannot_send_anything():
    src = Path(takedown_module.__file__).read_text()
    tree = ast.parse(src)
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"smtplib", "email", "socket", "urllib", "http", "requests", "httpx", "ftplib", "subprocess"}
    assert not [n for n in dir(takedown_module) if n.startswith(("send", "submit", "post"))]


# ---- evaluation ----------------------------------------------------------------------
def test_precision_counts_union_of_confirmed_and_blocklisted_without_double_counting():
    wh, v = flagged_wh()
    wh.write_bronze("blocklist", [block_row("paypa1-secure-login.xyz", ISO(T0 + timedelta(hours=1)))], "b")
    score_all(wh, WarehouseWatchlist(wh).per_company(), now=T0 + timedelta(hours=2))
    wh.add_feedback({"domain": "paypa1-secure-login.xyz", "company_id": "cid-paypal", "analyst_email": "a@x.test",
                     "label": "CONFIRMED_THREAT"})  # confirmed AND listed: counted once
    p = evaluation.precision(wh)
    assert p["flagged"] == 1 and p["confirmed_threats"] == 1 and p["blocklisted_matches"] == 1
    assert p["precision"] == 1.0  # confirmed AND listed, counted once: double counting would give 2.0
    assert p["precision_score_only"] == 1.0


def test_precision_empty_is_none():
    assert evaluation.precision(MemoryWarehouse())["precision"] is None


def test_recall_counts_early_flags_against_blocklisted_lookalikes():
    wh, v = flagged_wh()
    wh.write_bronze("blocklist", [block_row("paypa1-secure-login.xyz", ISO(T0 + timedelta(hours=6))),
                                  block_row("unknown-paypal-clone.top", ISO(T0))], "b")
    wl = Watchlist.from_dicts([{"name": "paypal", "aliases": [], "official_domains": ["paypal.com"]}])
    r = evaluation.recall(wh, wl)
    assert r["flagged_before_listing"] == 1 and r["missed"] == 1 and r["recall"] == 0.5


def test_lead_time_quartiles():
    wh = MemoryWarehouse()
    for i, h in enumerate([1, 2, 3, 4, 5]):
        wh.write_score({"domain": f"d{i}.com", "company_id": "c", "score": 80, "classification": "HIGH_RISK",
                        "evidence": [], "breakdown": {}, "is_on_blocklist": True, "last_evaluated_at": ISO(T0),
                        "scoring_version": "1.0", "first_listed_at": ISO(T0 + timedelta(hours=h))})
    lt = evaluation.lead_time(wh)
    assert lt["median"] == 3.0 and lt["p25"] == 2.0 and lt["p75"] == 4.0 and lt["flagged_before_listing"] == 5


def test_hours_saved_uses_five_minutes_by_default():
    wh, _ = flagged_wh()
    h = evaluation.analyst_hours_saved(wh)
    assert h["minutes_per_check"] == 5.0 and h["hours_saved"] == round(h["auto_triaged"] * 5 / 60, 2)


def test_weight_comparison_reports_and_never_adopts():
    from domainguard.scoring import WEIGHTS
    before = dict(WEIGHTS)
    rows = [{"domain": f"x{i}.com", "label": i % 2, "breakdown": {"keywords": 10 if i % 2 else 0, "name_similarity": 20}}
            for i in range(60)]
    r = evaluation.compare_weights(rows, {"keywords": 20})
    assert WEIGHTS == before and r["adopted"] is False and r["candidate_weights"]["keywords"] == 20


def test_persisted_metrics_per_company():
    wh, _ = flagged_wh()
    rep = evaluation.full_report(wh, WarehouseWatchlist(wh).current(), "cid-paypal")
    evaluation.persist(wh, "cid-paypal", rep, "2026-10-25")
    assert wh.metrics[0]["company_id"] == "cid-paypal" and wh.metrics[0]["domains_flagged"] == 1

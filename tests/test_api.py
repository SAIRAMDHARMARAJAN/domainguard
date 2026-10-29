from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domainguard.api import create_app
from domainguard.auth import unsubscribe_token
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.notifier import RecordingSender
from domainguard.pipeline import score_all
from domainguard.registration import Registrar
from domainguard.watchlist import WarehouseWatchlist
from tests.helpers import SECRET, T0, ISO, cert_row, company, rdap_row, seed_bronze, settings

MSG = "URGENT: your account will be blocked today. Verify KYC at http://paypa1-secure-login.xyz/login now"


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    wh = MemoryWarehouse()
    company(wh, "paypal", "paypal.com", email="sec@paypal.test")
    seed_bronze(wh, certs=[cert_row("paypa1-secure-login.xyz", brand="paypal")],
                rdap=[rdap_row("paypa1-secure-login.xyz", ISO(T0 - timedelta(hours=2)))])
    wl = WarehouseWatchlist(wh)
    score_all(wh, wl.per_company(), now=T0)
    clock, sender = Clock(), RecordingSender()
    s = settings(tmp_path, public_origin="https://checker.example.test")
    app = create_app(wh, s, sender=sender, clock=clock, watchlist=wl)
    return {"wh": wh, "client": TestClient(app), "sender": sender, "clock": clock, "s": s}


def key_for(env, email="owner@acme.example", name="Acme"):
    """Register and verify directly through the registrar (the API hides the token; it is only in the email)."""
    reg = Registrar(env["wh"], clock=lambda: env["clock"]())
    out = reg.register(name=name, email=email, contact_person=None, domains=["acme.example"])
    return out, reg.verify(out["token"])["api_key"]


def bearer(k):
    return {"Authorization": f"Bearer {k}"}


# ---- public endpoints --------------------------------------------------------------------
def test_health_and_config(env):
    h = env["client"].get("/health").json()
    assert h["status"] == "ok" and h["timestamp"].endswith("Z")
    assert "Hindi" in env["client"].get("/config").json()["languages"]


def test_check_observed_domain_returns_stored_verdict_without_company_name(env):
    stored = env["wh"].get_verdict("paypa1-secure-login.xyz", "cid-paypal")
    r = env["client"].post("/check", json={"input": "https://paypa1-secure-login.xyz/verify"}).json()
    assert r["score"] == stored["score"] == 88 and r["verdict"] == "high_risk" and r["basis"] == "observed_in_stream"
    assert r["domain"] == "paypa1-secure-login[.]xyz" and r["matched_brand"] == "paypal"
    assert "cid-paypal" not in str(r) and "paypal@" not in str(r)  # which company is never revealed
    assert r["explanation"]["source"] == "template" and "not a confirmed verdict" in r["disclaimer"].lower()


def test_check_unseen_domain_is_name_only_with_caution_for_lookalikes(env):
    r = env["client"].post("/check", json={"input": "paypal-verify-now.xyz"}).json()
    assert r["basis"] == "name_only_analysis" and r["age_known"] is False
    assert r["verdict"] in ("suspicious", "high_risk", "low_risk")


def test_check_official_domain(env):
    r = env["client"].post("/check", json={"input": "www.paypal.com"}).json()
    assert r["verdict"] == "official" and r["score"] == 0


@pytest.mark.parametrize("payload", [{"input": ""}, {"input": "x" * 2049}, {"input": "not a domain"},
                                     {"input": "1.2.3.4"}, {"input": "a.com", "language": "Klingon"},
                                     {"input": "x'; DROP TABLE REF.USERS; --"}])
def test_invalid_check_input_rejected(env, payload):
    assert env["client"].post("/check", json=payload).status_code == 422


def test_sql_injection_text_is_never_executed_and_leaves_store_intact(env):
    before = env["wh"].verdicts()
    env["client"].post("/check", json={"input": "x'; DROP TABLE REF.USERS; --"})
    env["client"].post("/scan-message", json={"text": "'; DELETE FROM GOLD.DOMAIN_VERDICT; -- hello there"})
    assert env["wh"].verdicts() == before and env["wh"].get_user("cid-paypal") is not None


def test_scan_message_extracts_and_scores_links(env):
    r = env["client"].post("/scan-message", json={"text": MSG}).json()
    assert r["links_found"] == 1 and r["worst_verdict"] == "high_risk" or r["worst_verdict"] == "dangerous"
    assert r["links"][0]["domain"] == "paypa1-secure-login[.]xyz"
    assert "credential request" in r["message_analysis"]["tactics"]
    assert env["client"].post("/scan-message", json={"text": "lunch at one?"}).json()["worst_verdict"] == "no_links"


@pytest.mark.parametrize("text", ["abc", "x" * 10001])
def test_scan_message_length_limits(env, text):
    assert env["client"].post("/scan-message", json={"text": text}).status_code == 422


def test_scan_message_caps_links_at_ten(env):
    text = "visit " + " ".join(f"site{i}.example" for i in range(25))
    assert env["client"].post("/scan-message", json={"text": text}).json()["links_found"] == 10


def test_security_headers_cors_and_no_docs(env):
    r = env["client"].get("/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert env["client"].get("/docs").status_code == 404 and env["client"].get("/openapi.json").status_code == 404
    pre = env["client"].options("/check", headers={"Origin": "https://checker.example.test",
                                                   "Access-Control-Request-Method": "POST"})
    assert pre.headers.get("access-control-allow-origin") == "https://checker.example.test"
    other = env["client"].options("/check", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in other.headers


def test_public_rate_limit_returns_429(tmp_path):
    wh = MemoryWarehouse()
    app = create_app(wh, settings(tmp_path, api_rate_limit_per_min=3), clock=Clock(), watchlist=WarehouseWatchlist(wh))
    c = TestClient(app)
    codes = [c.post("/check", json={"input": "a-thing.example"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_pages_are_served(env):
    assert "Is this link safe?" in env["client"].get("/").text
    assert "Protect your brand" in env["client"].get("/register").text
    assert env["client"].get("/static/app.js").status_code == 200


# ---- registration ------------------------------------------------------------------------------
def test_register_returns_pending_and_emails_link_without_revealing_status(env):
    r = env["client"].post("/register", json={"company_name": "Acme Retail", "email": "owner@acme.example",
                                              "domains": ["acme.example"]})
    assert r.status_code == 202 and r.json()["status"] == "PENDING"
    assert "verify" in env["sender"].sent[-1].get_content()


def test_register_duplicate_email_and_bad_input(env):
    body = {"company_name": "Acme", "email": "dup@acme.example", "domains": ["acme.example"]}
    assert env["client"].post("/register", json=body).status_code == 202
    assert env["client"].post("/register", json=body).status_code == 422
    assert env["client"].post("/register", json={**body, "email": "bad", "domains": []}).status_code == 422


def test_verify_emails_key_and_settings_require_auth(env):
    reg = Registrar(env["wh"], clock=lambda: env["clock"]())
    out = reg.register(name="Acme", email="owner@acme.example", contact_person=None, domains=["acme.example"])
    assert env["client"].get("/verify/not-a-real-token").status_code == 400
    ok = env["client"].get(f"/verify/{out['token']}")
    assert ok.status_code == 200 and ok.json()["status"] == "ACTIVE"
    body = env["sender"].sent[-1].get_content()
    key = next(w for w in body.split() if w.startswith("dg_"))
    assert key.startswith("dg_") and len(key) > 30
    assert env["client"].get(f"/verify/{out['token']}").status_code == 400  # link works once
    s = env["client"].get("/company/settings", headers=bearer(key)).json()
    assert s["name"] == "Acme" and s["domains"][0]["domain"] == "acme[.]example" and "api_key_hash" not in str(s)  # displayed defanged
    assert env["client"].get("/company/settings").status_code == 401


def test_company_can_manage_domains_and_preferences(env):
    out, key = key_for(env)
    assert env["client"].post("/company/domains/add", headers=bearer(key),
                              json={"domain": "acme-retail.in"}).status_code == 201
    assert env["client"].delete("/company/domains/acme-retail.in", headers=bearer(key)).status_code == 200
    assert env["client"].delete("/company/domains/nope.example", headers=bearer(key)).status_code == 404
    r = env["client"].put("/company/settings", headers=bearer(key),
                          json={"notification_frequency": "DAILY", "min_score_threshold": 60, "email_notifications": False})
    assert r.status_code == 200
    prefs = env["client"].get("/company/settings", headers=bearer(key)).json()["preferences"]
    assert prefs["notification_frequency"] == "DAILY" and prefs["min_score_threshold"] == 60 and prefs["email_notifications"] is False
    assert env["client"].put("/company/settings", headers=bearer(key), json={"notification_frequency": "HOURLY"}).status_code == 422


def test_key_rotation_returns_new_key_and_retires_old(env):
    out, key = key_for(env)
    new = env["client"].post("/company/api-key/rotate", headers=bearer(key)).json()["api_key"]
    assert env["client"].get("/company/settings", headers=bearer(key)).status_code == 401
    assert env["client"].get("/company/settings", headers=bearer(new)).status_code == 200


def test_inbox_is_scoped_to_the_callers_company(env):
    out, key = key_for(env)
    rows = env["client"].get("/analyst/inbox?min_score=0", headers=bearer(key)).json()
    assert rows["count"] == 0  # Acme has no detections; PayPal's are not visible to Acme
    paypal_key = "dg_" + "p" * 40
    env["wh"].update_user("cid-paypal", {"api_key_hash": __import__("domainguard.auth", fromlist=["hash_key"]).hash_key(paypal_key)})
    shown = env["client"].get("/analyst/inbox?min_score=0&hours=48", headers=bearer(paypal_key)).json()
    assert shown["count"] >= 1 and all("paypa1" in d["domain"] for d in shown["domains"])
    assert env["client"].get("/analyst/inbox", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_unsubscribe_link_turns_alerts_off(env):
    tok = unsubscribe_token(SECRET, "cid-paypal")
    assert env["client"].get(f"/unsubscribe/{tok}").status_code == 200
    assert env["wh"].get_prefs("cid-paypal")["email_notifications"] is False
    assert env["client"].get("/unsubscribe/forged.token").status_code == 400


def test_dispute_is_acknowledged_by_email(env):
    r = env["client"].post("/dispute", json={"domain": "acme.example", "email": "owner@acme.example"})
    assert r.status_code == 202 and "dispute" in env["sender"].sent[-1]["Subject"].lower()


def test_api_needs_a_signing_secret(tmp_path):
    with pytest.raises(RuntimeError, match="DG_SECRET_KEY"):
        create_app(MemoryWarehouse(), settings(tmp_path, secret_key=""))


def test_api_module_has_no_outbound_network_code():
    import re
    src = Path(__import__("domainguard.api", fromlist=["x"]).__file__).read_text()
    assert not re.search(r"^\s*(import|from)\s+(urllib|requests|socket|httpx|smtplib)", src, re.M)

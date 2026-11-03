from datetime import timedelta

import pytest

from domainguard.auth import AuthError, RateLimiter, authenticate, hash_key, new_api_key, unsubscribe_token, verify_unsubscribe
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.registration import MAX_DOMAINS, Registrar, RegistrationError, normalize_domain, suggest_aliases
from tests.helpers import SECRET, T0

REG = dict(name="Acme Retail", email="security@acme-retail.example", contact_person="Priya", domains=["www.acme-retail.example"])


def test_domains_are_reduced_to_registrable_and_ips_refused():
    assert normalize_domain("https://WWW.Acme-Retail.example/login") == "acme-retail.example"
    assert normalize_domain("abcbank.co.in") == "abcbank.co.in"
    with pytest.raises(RegistrationError):
        normalize_domain("192.168.1.1")
    with pytest.raises(RegistrationError):
        normalize_domain("not a domain")


def test_aliases_are_suggested_from_domain_and_name():
    a = suggest_aliases("acme-retail.example", "Acme Retail")
    assert "acme-retail" in a and "acme retail" in a and "acmeretail" in a


def test_register_creates_pending_account_with_verification_otp():
    wh = MemoryWarehouse()
    out = Registrar(wh, clock=lambda: T0).register(**REG)
    u = wh.get_user(out["company_id"])
    assert u["status"] == "PENDING" and out["domains"] == ["acme-retail.example"]
    assert wh.protected_for(out["company_id"])[0]["brand_aliases"]  # aliases suggested
    assert len(out["otp"]) == 6 and out["otp"].isdigit()


@pytest.mark.parametrize("bad", [
    {"email": "not-an-email"}, {"name": "A"}, {"domains": []}, {"domains": [f"d{i}.example" for i in range(MAX_DOMAINS + 1)]},
])
def test_registration_validation(bad):
    wh = MemoryWarehouse()
    with pytest.raises(RegistrationError):
        Registrar(wh).register(**{**REG, **bad})


def test_duplicate_email_refused():
    wh = MemoryWarehouse()
    r = Registrar(wh)
    r.register(**REG)
    with pytest.raises(RegistrationError, match="already registered"):
        r.register(**{**REG, "domains": ["other.example"]})


def test_duplicate_company_name_is_allowed():
    wh = MemoryWarehouse()
    r = Registrar(wh)
    r.register(**REG)
    second = r.register(**{**REG, "email": "different@example.com", "domains": ["other.example"]})
    assert second["company_id"] != wh.get_user_by_email("security@acme-retail.example")["company_id"]


def test_duplicate_domain_refused():
    wh = MemoryWarehouse()
    r = Registrar(wh)
    r.register(**REG)
    with pytest.raises(RegistrationError, match="domain"):
        r.register(**{**REG, "name": "Another Company", "email": "different@example.com"})


def test_duplicate_domains_in_one_registration_refused():
    with pytest.raises(RegistrationError, match="duplicate domains"):
        Registrar(MemoryWarehouse()).register(**{**REG, "domains": ["www.acme-retail.example", "acme-retail.example"]})


def test_verify_activates_issues_key_once_and_link_cannot_be_reused():
    wh = MemoryWarehouse()
    r = Registrar(wh, clock=lambda: T0)
    out = r.register(**REG)
    res = r.verify(out["token"])
    assert wh.get_user(out["company_id"])["status"] == "ACTIVE"
    assert res["api_key"].startswith("dg_") and wh.get_user(out["company_id"])["api_key_hash"] == hash_key(res["api_key"])
    assert res["api_key"] not in str(wh.get_user(out["company_id"]))  # only the hash is stored
    with pytest.raises(RegistrationError, match="already been used"):
        r.verify(out["token"])


def test_resend_otp_creates_new_pending_registration_code():
    wh = MemoryWarehouse()
    r = Registrar(wh, clock=lambda: T0)
    out = r.register(**REG)
    resent = r.resend_otp(REG["email"])
    assert resent["otp"] != out["otp"]
    assert r.verify_otp(resent["otp"], REG["email"])["email"] == REG["email"]


def test_admin_approval_activates_pending_registration_without_email():
    wh = MemoryWarehouse()
    r = Registrar(wh, clock=lambda: T0)
    out = r.register(**REG)
    approved = r.approve_pending(out["company_id"])
    user = wh.get_user(out["company_id"])
    assert user["status"] == "ACTIVE"
    assert approved["api_key"].startswith("dg_")
    with pytest.raises(RegistrationError, match="already been approved"):
        r.verify(out["token"])


def test_expired_and_unknown_otps_refused():
    wh = MemoryWarehouse()
    out = Registrar(wh, clock=lambda: T0).register(**REG)
    with pytest.raises(RegistrationError, match="expired"):
        Registrar(wh, clock=lambda: T0 + timedelta(hours=25)).verify(out["token"])
    with pytest.raises(RegistrationError, match="6-digit"):
        Registrar(wh).verify("123")


def test_verify_handles_naive_clock():
    wh = MemoryWarehouse()
    out = Registrar(wh, clock=lambda: T0.replace(tzinfo=None)).register(**REG)
    assert Registrar(wh, clock=lambda: T0.replace(tzinfo=None)).verify(out["token"])["api_key"].startswith("dg_")


def test_add_remove_domain_and_key_rotation_invalidates_old_key():
    wh = MemoryWarehouse()
    r = Registrar(wh, clock=lambda: T0)
    out = r.register(**REG)
    key = r.verify(out["token"])["api_key"]
    r.add_domain(out["company_id"], "acme-retail.in")
    assert {d["domain"] for d in wh.protected_for(out["company_id"])} == {"acme-retail.example", "acme-retail.in"}
    r.remove_domain(out["company_id"], "acme-retail.in")
    assert [d["domain"] for d in wh.protected_for(out["company_id"])] == ["acme-retail.example"]
    with pytest.raises(RegistrationError):
        r.remove_domain(out["company_id"], "never-added.example")
    new = r.rotate_key(out["company_id"])
    with pytest.raises(AuthError):
        authenticate(wh, f"Bearer {key}")
    assert authenticate(wh, f"Bearer {new}")["company_id"] == out["company_id"]


# ---- auth -----------------------------------------------------------------------------
def test_bearer_parsing_and_suspended_accounts():
    wh = MemoryWarehouse()
    out = Registrar(wh, clock=lambda: T0).register(**REG)
    key = Registrar(wh, clock=lambda: T0).verify(out["token"])["api_key"]
    for header in (None, "Basic xyz", "Bearer short", "Bearer dg_" + "x" * 30):
        with pytest.raises(AuthError) as e:
            authenticate(wh, header)
        assert e.value.status == 401
    wh.update_user(out["company_id"], {"status": "SUSPENDED"})
    with pytest.raises(AuthError) as e:
        authenticate(wh, f"Bearer {key}")
    assert e.value.status == 403


def test_api_key_format():
    k = new_api_key()
    assert k.startswith("dg_") and len(k) >= 40 and hash_key(k) != k


def test_key_rate_limiter_window():
    t = {"now": 0.0}
    rl = RateLimiter(2, 60, clock=lambda: t["now"])
    assert rl.check("k") is None and rl.check("k") is None
    assert rl.check("k") is not None
    t["now"] = 61
    assert rl.check("k") is None


def test_rate_limiter_can_validate_without_consuming_quota():
    t = {"now": 0.0}
    rl = RateLimiter(1, 60, clock=lambda: t["now"])
    assert rl.check("k", consume=False) is None
    assert rl.check("k", consume=False) is None
    rl.hit("k")
    assert rl.check("k", consume=False) is not None


def test_unsubscribe_token_is_signed():
    tok = unsubscribe_token(SECRET, "cid-1")
    assert verify_unsubscribe(SECRET, tok) == "cid-1"
    assert verify_unsubscribe("another-secret-0123456789012345678", tok) is None
    assert verify_unsubscribe(SECRET, tok.replace("cid-1", "cid-2")) is None
    assert verify_unsubscribe(SECRET, "garbage") is None

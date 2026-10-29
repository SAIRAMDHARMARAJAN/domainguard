import pytest

from domainguard.matcher import match_host
from domainguard.normalize import clean_host, defang, extract_hosts, fold, split_host, tokens
from domainguard.scoring import BAND_SUSPICIOUS, KEYWORDS, WEIGHTS, score_domain


# ---- normalize --------------------------------------------------------------
def test_clean_host_variants():
    assert clean_host("HTTPS://Login.ABCBank.com:8443/a?b#c") == "login.abcbank.com"
    assert clean_host("*.example.com") == "example.com"
    assert clean_host("hxxp://evil[.]com/x") == "evil.com"


def test_userinfo_trick_resolves_to_real_host():
    assert clean_host("http://abcbank.com@evil.net/") == "evil.net"


@pytest.mark.parametrize("bad", ["", None, "1.2.3.4", "999.1.1.1", "localhost", "a b.com", "-x.com", "[::1]", 5])
def test_clean_host_rejects(bad):
    assert clean_host(bad) is None


def test_split_host_multipart_suffix_and_punycode():
    p = split_host("a.b.abcbank.co.in")
    assert (p.subdomains, p.label, p.suffix, p.registrable) == (["a", "b"], "abcbank", "co.in", "abcbank.co.in")
    q = split_host(clean_host("pаypal.com"))  # Cyrillic a
    assert q.has_punycode and q.has_non_ascii and q.unicode_host == "pаypal.com"


def test_fold_and_defang_and_extract():
    assert fold("paypa1") == fold("paypal") and fold("rnicrosoft") == fold("microsoft")
    assert fold("pаypal") == fold("paypal")  # Cyrillic a
    assert defang("a.com") == "a[.]com"
    hosts = extract_hosts("Your account is blocked! Login at http://abcb4nk-secure.xyz/x or evil[.]com. e.g. now")
    assert hosts == ["abcb4nk-secure.xyz", "evil.com"]
    assert len(extract_hosts(" ".join(f"h{i}.com" for i in range(30)), limit=5)) == 5


def test_tokens():
    assert tokens(split_host("abc-bank.login.xyz")) == ["abcbank", "abc", "bank", "login"]


# ---- matcher ----------------------------------------------------------------
def test_typo_is_fuzzy(wl):
    m = match_host("abcbannk-login.com", wl)
    assert (m.brand, m.match_type) == ("abcbank", "fuzzy") and 90 <= m.similarity <= 95 and not m.obfuscated


def test_brand_in_domain_and_subdomain_trick(wl):
    assert match_host("abcbank-help.in", wl).match_type == "exact_token"
    assert match_host("abcbankhelp.com", wl).match_type == "contains"
    assert match_host("abcbank.com.evil-host.top", wl).match_type == "exact_token"


def test_official_and_subdomains_never_match(wl):
    assert match_host("abcbank.com", wl) is None
    assert match_host("login.abcbank.in", wl) is None


def test_unrelated_and_digit_substitution(wl):
    assert match_host("pizza-shop.com", wl) is None
    m = match_host("paypa1-secure.xyz", wl)
    assert m.match_type == "exact_token" and m.obfuscated


def test_short_brand_only_exact(wl):
    assert match_host("olive-garden.com", wl) is None  # fuzzy would wrongly match 'ola'
    assert match_host("ola-offers.com", wl).brand == "ola"


# ---- scoring ----------------------------------------------------------------
def test_weights_total_100():
    assert sum(WEIGHTS.values()) == 100 and "login" in KEYWORDS


def test_worked_examples(wl):
    assert score_domain("abcbank.com", wl).classification == "ALLOWLISTED"
    r = score_domain("abcbannk-login.com", wl, age_days=0.1)
    assert (r.score, r.classification) == (44, "SUSPICIOUS")
    assert (r.breakdown["name_similarity"], r.breakdown["keywords"], r.breakdown["domain_age"]) == (19, 5, 20)
    u = score_domain("abcbannk-login.com", wl)  # unknown age
    assert (u.score, u.classification) == (34, "LOW") and u.score < BAND_SUSPICIOUS
    p = score_domain("paypa1-secure-login.xyz", wl, age_days=5 / 24)
    assert (p.score, p.classification) == (88, "HIGH_RISK")
    assert score_domain("pizza-shop.com", wl, age_days=900).score == 0


def test_blocklist_override_keeps_score(wl):
    r = score_domain("abcbannk-login.com", wl, age_days=0.1, on_blocklist=True)
    assert r.classification == "DANGEROUS" and r.score == 44
    a = score_domain("abcbank.com", wl, on_blocklist=True)
    assert a.classification == "ALLOWLISTED" and any("analyst review" in e for e in a.evidence)


@pytest.mark.parametrize("age,pts", [(None, 10), (0.5, 20), (3, 14), (20, 8), (400, 0)])
def test_age_bands(wl, age, pts):
    assert score_domain("pizza-shop.com", wl, age_days=age).breakdown["domain_age"] == pts


def test_deterministic_and_capped_and_invalid(wl):
    from datetime import datetime, timezone
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    a = score_domain("paypa1-secure-login-verify-account.xyz", wl, age_days=0, now=now)
    assert a.to_dict() == score_domain("paypa1-secure-login-verify-account.xyz", wl, age_days=0, now=now).to_dict()
    assert a.score <= 100 and a.breakdown["keywords"] == 10 and a.breakdown["structure"] <= 10
    with pytest.raises(ValueError):
        score_domain("not a host", wl)

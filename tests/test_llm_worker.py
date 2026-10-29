import json

import pytest

from domainguard.config import Settings
from domainguard.llm import MAX_ADVICE, MAX_REASON, MAX_SUMMARY, explain, message_tactics, template_explanation, validate_brief
from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.worker import run_briefs
from tests.helpers import T0, ISO, company, cert_row, rdap_row, seed_bronze
from domainguard.pipeline import score_all
from domainguard.watchlist import WarehouseWatchlist

V = {"domain": "paypa1-secure-login.xyz", "score": 88, "classification": "HIGH_RISK", "matched_brand": "paypal",
     "evidence": ["name is 100% similar to 'paypal' (exact_token)", "suspicious keywords: login, secure"]}
GOOD = {"summary": "paypa1-secure-login[.]xyz looks like an imitation of paypal (risk score 88/100).",
        "reasons": ["The name is almost the same as the real brand.", "It asks you to log in."],
        "advice": "Do not enter passwords or personal details."}


def caller(*answers):
    calls = []

    def fn(model, prompt, *rest):
        calls.append((model, prompt))
        a = answers[min(len(calls) - 1, len(answers) - 1)]
        if isinstance(a, Exception):
            raise a
        return a if isinstance(a, str) else json.dumps(a)

    fn.calls = calls
    return fn


def test_limits_come_from_the_specification():
    assert (MAX_SUMMARY, MAX_REASON, MAX_ADVICE) == (150, 100, 100)


def test_valid_output_is_accepted_and_numbers_must_be_in_facts():
    assert validate_brief(GOOD, V) is not None
    assert validate_brief({**GOOD, "summary": "risk score is 12/100"}, V) is None


@pytest.mark.parametrize("bad", [
    {**GOOD, "summary": "see http://x.example"}, {**GOOD, "advice": "go to www.x.example"},
    {**GOOD, "reasons": ["<b>bold</b>"]}, {**GOOD, "summary": "s" * 151}, {**GOOD, "reasons": ["r" * 101]},
    {**GOOD, "advice": "a" * 101}, {**GOOD, "extra": 1}, {"summary": "only"}, {**GOOD, "reasons": []},
    {**GOOD, "reasons": ["r"] * 9}, "not json",
])
def test_invalid_output_rejected(bad):
    assert validate_brief(bad, V) is None


def test_prompt_is_the_specified_prompt_with_defanged_facts():
    c = caller(GOOD)
    explain(V, "Hindi", models=["m1"], caller=c)
    _, prompt = c.calls[0]
    assert "paypa1-secure-login[.]xyz" in prompt and "paypa1-secure-login.xyz" not in prompt
    assert "Write the text in Hindi." in prompt and "Return ONLY valid JSON" in prompt


def test_fallback_order_then_template():
    c = caller("junk", {"summary": "x"}, GOOD)
    e = explain(V, models=["a", "b", "c"], caller=c)
    assert e["source"] == "llm" and e["model_name"] == "c" and len(c.calls) == 3
    c2 = caller(RuntimeError("429"))
    e2 = explain(V, models=["a", "b"], caller=c2)
    assert e2["source"] == "template" and len(c2.calls) == 2


def test_no_key_and_no_caller_means_template_without_network(monkeypatch):
    import domainguard.llm as llm
    monkeypatch.setattr(llm, "call_openrouter", lambda *a, **k: pytest.fail("no network allowed"))
    assert explain(V, models=["m"])["source"] == "template"


def test_template_is_english_and_defanged():
    t = template_explanation(V, "Hindi")
    assert t["language"] == "English" and t["source"] == "template" and "[.]" in t["summary"]


def test_message_tactics_are_detected_not_executed():
    t = message_tactics("URGENT: account blocked. Verify KYC at http://x.example, cashback waiting")
    assert {"urgent action request", "account threat", "credential request", "money offer"} <= set(t)
    assert message_tactics("lunch at one?") == []


# ---- worker ------------------------------------------------------------------------
def flagged_wh():
    wh = MemoryWarehouse()
    company(wh, "abcbank", "abcbank.com")
    seed_bronze(wh, certs=[cert_row("abcbannk-login.com")], rdap=[rdap_row("abcbannk-login.com", ISO(T0))])
    score_all(wh, WarehouseWatchlist(wh).per_company(), now=T0)
    return wh


def settings(**kw):
    return Settings(secret_key="x" * 40, **kw)


def test_worker_writes_once_then_reuses_and_regenerates_on_score_change():
    wh = flagged_wh()
    s = settings()
    r1 = run_briefs(wh, s)
    assert r1["written"] == 1 and r1["template"] == 1
    assert run_briefs(wh, s)["skipped"] == 1
    wh.write_score({**wh.get_verdict("abcbannk-login.com", "cid-abcbank"), "score": 60, "classification": "SUSPICIOUS"})
    assert run_briefs(wh, s)["written"] == 1  # verdict score changed: brief regenerated


def test_worker_uses_llm_when_configured_and_rejects_bad_output():
    wh = flagged_wh()
    s = settings(openrouter_models=("m1",), openrouter_api_key="")
    out = run_briefs(wh, s, caller=caller({"summary": "bad http://x.example", "reasons": ["r"], "advice": "a"}))
    assert out["template"] == 1 and out["llm"] == 0
    b = wh.get_brief("abcbannk-login.com", "cid-abcbank", "English")
    assert b["source"] == "template" and "http" not in json.dumps(b)


def test_worker_respects_call_cap():
    wh = flagged_wh()
    s = settings(openrouter_models=("m1",), llm_max_calls_per_run=0)
    out = run_briefs(wh, s, caller=caller(GOOD), languages=("English",))
    assert out["capped"] is True and out["written"] == 0


def test_worker_never_changes_verdicts():
    wh = flagged_wh()
    before = wh.verdicts()
    run_briefs(wh, settings(), languages=("English", "Hindi", "Malayalam"))
    assert wh.verdicts() == before

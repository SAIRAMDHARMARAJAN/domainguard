"""Explanation worker (run every 5 minutes by cron or the live loop). Writes one brief per company, domain and
language. A brief is regenerated only when the verdict score it explains has changed. Capped per run to limit spend."""
from __future__ import annotations

from .llm import explain
from .warehouse import FLAGGED


def run_briefs(wh, settings, *, languages=("English",), caller=None, max_calls: int | None = None) -> dict:
    cap = settings.llm_max_calls_per_run if max_calls is None else max_calls
    out = {"written": 0, "llm": 0, "template": 0, "skipped": 0, "capped": False}
    calls = 0
    for v in wh.verdicts():
        if v["classification"] not in FLAGGED:
            continue
        for lang in languages:
            cur = wh.get_brief(v["domain"], v["company_id"], lang)
            if cur and cur.get("verdict_score") == v["score"]:
                out["skipped"] += 1
                continue
            if calls >= cap:
                out["capped"] = True
                return out
            llm_on = caller is not None or bool(settings.openrouter_api_key)
            if llm_on:
                calls += 1
            brief = explain(v, lang, models=settings.openrouter_models if llm_on else (),
                            api_key=settings.openrouter_api_key, caller=caller)
            wh.put_brief({"domain": v["domain"], "company_id": v["company_id"], "language": lang,
                          "summary": brief["summary"], "reasons": brief["reasons"], "advice": brief["advice"],
                          "source": brief["source"], "model_name": brief.get("model_name"), "verdict_score": v["score"]})
            out["written"] += 1
            out[brief["source"]] += 1
    return out

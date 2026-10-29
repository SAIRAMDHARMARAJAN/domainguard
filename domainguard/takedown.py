"""Abuse-report drafts with mandatory human approval. THIS MODULE CANNOT SEND ANYTHING.

Lifecycle: DRAFT -> APPROVED (needs the exact signature sentence and a named analyst) or REJECTED;
APPROVED -> EXPORTED (text copied out by hand); the analyst may then record SENT ("I submitted it myself").
A test checks that no mail, HTTP or socket library is imported here."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .llm import _digits, _json_from, _text_ok, call_openrouter
from .normalize import defang
from .warehouse import new_id

SIGNATURE = "I confirm this is accurate and I approve sending"
MAX_BODY = 2500


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def template_draft(verdict: dict, analyst_name: str, analyst_email: str) -> dict:
    d = defang(verdict["domain"])
    brand = verdict.get("matched_brand") or "a protected brand"
    body = "\n".join([
        "Hello,", "",
        f"I am reporting a domain that appears to imitate the brand '{brand}' and may be used for phishing.", "",
        f"Domain: {d}",
        f"Automated risk score: {verdict['score']}/100 ({verdict['classification']})",
        "Observed indicators:", *[f"- {e}" for e in (verdict.get("evidence") or [])],
        f"First flagged by our monitoring: {verdict.get('first_flagged_at') or 'n/a'}", "",
        "This is an automated assessment based on public data. Please review the domain and act under your abuse policy.",
        "", f"Reported by: {analyst_name} <{analyst_email}>",
    ])
    return {"subject": f"Report of suspected phishing domain imitating {brand}: {d}", "body": body, "source": "template",
            "model_name": None}


def validate_draft(obj, verdict: dict, analyst_name: str, analyst_email: str) -> dict | None:
    if not isinstance(obj, dict) or set(obj) != {"subject", "body"}:
        return None
    subject = _text_ok(obj["subject"], 150)
    body = obj["body"].strip() if isinstance(obj["body"], str) else None
    if subject is None or not body or len(body) > MAX_BODY or re.search(r"https?:|://|www\.", body + subject, re.I):
        return None
    if analyst_email not in body or analyst_name not in body:
        return None
    from .llm import facts
    allowed = _digits(json.dumps(facts(verdict), ensure_ascii=False)) | {"100"}
    if not _digits(subject + " " + body) <= allowed:
        return None
    return {"subject": subject, "body": body, "source": "llm"}


def draft(wh, verdict: dict, *, analyst_name: str, analyst_email: str, provider: str = "registrar",
          models=(), api_key: str = "", caller=None) -> str:
    if not analyst_name.strip() or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", analyst_email.strip()):
        raise ValueError("analyst name and a valid email are required")
    analyst_name, analyst_email = analyst_name.strip(), analyst_email.strip()
    result = None
    caller = caller or (call_openrouter if api_key else None)
    if caller is not None and models:
        from .llm import facts
        prompt = ("Write a short, polite abuse report about a suspected phishing domain. Use ONLY these facts. "
                  "No links, no invented numbers. End with 'Reported by: " + analyst_name + " <" + analyst_email + ">'. "
                  "Reply with JSON only: {\"subject\": string, \"body\": string}.\nFACTS:\n"
                  + json.dumps(facts(verdict), ensure_ascii=False))
        for model in models:
            try:
                raw = caller(model, prompt, api_key) if caller is call_openrouter else caller(model, prompt)
                result = validate_draft(_json_from(raw), verdict, analyst_name, analyst_email)
            except Exception:
                result = None
            if result:
                result["model_name"] = model
                break
    result = result or template_draft(verdict, analyst_name, analyst_email)
    draft_id = new_id()
    wh.add_takedown({"draft_id": draft_id, "domain": verdict["domain"], "company_id": verdict["company_id"],
                     "analyst_email": analyst_email, "analyst_name": analyst_name, "draft_text": result["body"],
                     "subject": result["subject"], "abuse_provider": provider, "source": result["source"]})
    return draft_id


def _need(wh, draft_id, *statuses):
    t = wh.get_takedown(draft_id)
    if t is None:
        raise KeyError(draft_id)
    if t["status"] not in statuses:
        raise ValueError(f"draft is {t['status']}; expected one of {statuses}")
    return t


def approve(wh, draft_id: str, *, analyst_name: str, analyst_email: str, signature: str) -> dict:
    _need(wh, draft_id, "DRAFT")
    if not analyst_name.strip() or not analyst_email.strip():
        raise ValueError("a named analyst and email are required to approve")
    if signature.strip() != SIGNATURE:
        raise ValueError(f"type exactly: {SIGNATURE}")
    wh.update_takedown(draft_id, {"status": "APPROVED", "approved_at": _now(),
                                  "approver_signature": f"{analyst_name.strip()} <{analyst_email.strip()}>: {SIGNATURE}"})
    return wh.get_takedown(draft_id)


def reject(wh, draft_id: str, *, analyst_name: str) -> dict:
    _need(wh, draft_id, "DRAFT")
    if not analyst_name.strip():
        raise ValueError("a named analyst is required")
    wh.update_takedown(draft_id, {"status": "REJECTED", "approver_signature": f"rejected by {analyst_name.strip()}"})
    return wh.get_takedown(draft_id)


def export_text(wh, draft_id: str) -> str:
    t = _need(wh, draft_id, "APPROVED", "EXPORTED")
    if t["status"] == "APPROVED":
        wh.update_takedown(draft_id, {"status": "EXPORTED", "exported_at": _now()})
    return f"Subject: {t['subject']}\n\n{t['draft_text']}\n\nApproved by: {t['approver_signature']}".replace("[.]", ".")


def mark_sent_manually(wh, draft_id: str, *, analyst_name: str) -> dict:
    """Recorded only after a person submitted the report through the provider's own form."""
    _need(wh, draft_id, "EXPORTED")
    wh.update_takedown(draft_id, {"status": "SENT"})
    return wh.get_takedown(draft_id)

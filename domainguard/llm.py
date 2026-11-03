"""Plain-language explanations through OpenRouter, validated, with a deterministic template fallback.

The model explains a computed verdict; it never sets or changes a score. Limits from the specification:
summary <= 150 characters, each reason <= 100, advice <= 100. Numbers in the answer must already appear in the facts
(the evidence and the score). No links, no code. Any failure moves to the next model, then to the template."""
from __future__ import annotations

import json
import os
import re
import unicodedata
import urllib.request

from .config import LANGUAGES
from .normalize import defang

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MAX_SUMMARY, MAX_REASON, MAX_ADVICE, MAX_REASONS = 150, 100, 100, 8
TEMPLATE_ADVICE = "Do not enter passwords or personal details. This is an automated risk estimate, not a confirmed verdict."

# ---------------------------------------------------------------------------
# Per-language template strings for deterministic (no-LLM) explanations.
# Keys must match LANGUAGES in config.py exactly.
# ---------------------------------------------------------------------------
_LANG_TEMPLATES: dict[str, dict[str, str]] = {
    "English": {
        "summary": "{d} shows warning signs of imitating {brand} (risk score {score}/100).",
        "advice": "Do not enter passwords or personal details. This is an automated risk estimate, not a confirmed verdict.",
    },
    "Hindi": {
        "summary": "{d} डोमेन {brand} की नकल करने के संकेत दिखाता है (जोखिम स्कोर {score}/100)।",
        "advice": "पासवर्ड या व्यक्तिगत विवरण न डालें। यह एक स्वचालित जोखिम मूल्यांकन है, पुष्टि किया गया निर्णय नहीं।",
    },
    "Tamil": {
        "summary": "{d} என்ற டொமைன் {brand} நிறுவனத்தை போல் காட்சியளிக்கிறது (ஆபத்து மதிப்பெண் {score}/100).",
        "advice": "கடவுச்சொற்கள் அல்லது தனிப்பட்ட விவரங்களை உள்ளிட வேண்டாம். இது ஒரு தானியங்கி மதிப்பீடு மட்டுமே, உறுதிப்படுத்தப்பட்ட தீர்ப்பு அல்ல.",
    },
    "Malayalam": {
        "summary": "{d} എന്ന ഡൊമൈൻ {brand} ആണെന്ന് തോന്നിക്കുന്ന അപകട സൂചനകൾ കാണിക്കുന്നു (റിസ്ക് സ്കോർ {score}/100).",
        "advice": "പാസ്‌വേഡുകളോ വ്യക്തിഗത വിവരങ്ങളോ നൽകരുത്. ഇത് ഒരു സ്വയംചാലിത റിസ്ക് വിലയിരുത്തൽ മാത്രമാണ്, സ്ഥിരീകരിച്ച വിധി അല്ല.",
    },
    "Telugu": {
        "summary": "{d} డొమైన్ {brand}ని అనుకరిస్తున్న హెచ్చరిక సూచనలు చూపుతోంది (రిస్క్ స్కోర్ {score}/100).",
        "advice": "పాస్‌వర్డ్‌లు లేదా వ్యక్తిగత వివరాలు నమోదు చేయవద్దు. ఇది స్వయంచాలక రిస్క్ అంచనా మాత్రమే, ధృవీకరించిన తీర్పు కాదు.",
    },
    "Bengali": {
        "summary": "{d} ডোমেইনটি {brand}-এর অনুকরণ করার সতর্কতামূলক লক্ষণ দেখাচ্ছে (ঝুঁকির স্কোর {score}/100)।",
        "advice": "পাসওয়ার্ড বা ব্যক্তিগত তথ্য প্রবেশ করবেন না। এটি একটি স্বয়ংক্রিয় ঝুঁকি মূল্যায়ন, নিশ্চিত রায় নয়।",
    },
    "Marathi": {
        "summary": "{d} डोमेन {brand}ची नक्कल करण्याची चेतावणी चिन्हे दाखवतो (जोखीम गुण {score}/100).",
        "advice": "पासवर्ड किंवा वैयक्तिक माहिती टाकू नका. हे एक स्वयंचलित जोखीम मूल्यांकन आहे, पुष्टी केलेला निर्णय नाही.",
    },
}
PROMPT = """You are a security analyst explaining domain risk scores to non-technical users.

Domain: {domain}
Risk Score: {score}/100
Classification: {classification}
Brand: {brand}

Evidence:
{reasons}

Return ONLY valid JSON (no markdown, no code):
{{
  "summary": "one sentence, under 150 characters, naming the risk and the imitated brand",
  "reasons": [
    "reason 1: one sentence under 100 characters",
    "reason 2: ..."
  ],
  "advice": "one sentence, under 100 characters, what to do"
}}

Rules:
- No links or code.
- No invented numbers; only state facts from the evidence.
- Defang domains: a.com becomes a[.]com.
- Language: simple, no jargon.
Write the text in {language}."""

_LINK = re.compile(r"https?:|://|www\.|[a-z0-9-]\.(?:com|net|org|in|xyz|top|click|icu|info|io|co|app|site|tk|ml|ga|cf|gq|us|ru)\b", re.I)
_CODE = re.compile(r"[`<>{}]")


def template_explanation(verdict: dict, language: str = "English") -> dict:
    d = defang(verdict["domain"])
    brand = verdict.get("matched_brand") or "a protected brand"
    # Use the language-specific template; fall back to English if somehow unsupported.
    tmpl = _LANG_TEMPLATES.get(language, _LANG_TEMPLATES["English"])
    summary = tmpl["summary"].format(d=d, brand=brand, score=verdict["score"])
    advice = tmpl["advice"]
    return {"summary": summary,
            "reasons": [r[:MAX_REASON] for r in (verdict.get("evidence") or [])][:MAX_REASONS],
            "advice": advice, "source": "template", "model_name": None, "language": language}


def facts(verdict: dict) -> dict:
    return {"domain": defang(verdict["domain"]), "score": verdict["score"], "classification": verdict["classification"],
            "brand": verdict.get("matched_brand"), "evidence": list(verdict.get("evidence") or [])}


def _digits(s: str) -> set[str]:
    norm = "".join(str(unicodedata.decimal(c)) if c.isdigit() else c for c in s)
    return set(re.findall(r"\d+(?:\.\d+)?", norm))


def _text_ok(s, limit: int) -> str | None:
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s or len(s) > limit or _LINK.search(s) or _CODE.search(s):
        return None
    return s


def validate_brief(obj, verdict: dict) -> dict | None:
    if not isinstance(obj, dict) or set(obj) != {"summary", "reasons", "advice"}:
        return None
    summary = _text_ok(obj["summary"], MAX_SUMMARY)
    advice = _text_ok(obj["advice"], MAX_ADVICE)
    reasons = obj["reasons"]
    if summary is None or advice is None or not isinstance(reasons, list) or not 0 < len(reasons) <= MAX_REASONS:
        return None
    cleaned = [_text_ok(r, MAX_REASON) for r in reasons]
    if any(r is None for r in cleaned):
        return None
    allowed = _digits(json.dumps(facts(verdict), ensure_ascii=False)) | {"100"}
    if not _digits(" ".join([summary, advice, *cleaned])) <= allowed:
        return None
    return {"summary": summary, "reasons": cleaned, "advice": advice}


def call_openrouter(model: str, prompt: str, api_key: str, timeout: float = 30) -> str:
    """POST to OpenRouter. NOT RUN LIVE in this build; tests inject a fake caller."""
    body = json.dumps({"model": model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(OPENROUTER_URL, data=body, headers={"Authorization": f"Bearer {api_key}",
                                                                     "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(1_000_000))["choices"][0]["message"]["content"]


def _json_from(text: str):
    t = text.strip()
    m = re.match(r"^```(?:json)?\s*(.*?)\s*```$", t, re.S)
    try:
        return json.loads(m.group(1) if m else t)
    except (ValueError, AttributeError):
        return None


def explain(verdict: dict, language: str = "English", *, models=(), api_key: str = "", caller=None) -> dict:
    if language not in LANGUAGES:
        raise ValueError(f"unsupported language {language!r}")
    caller = caller or (call_openrouter if api_key else None)
    if caller is not None and models:
        reasons = "\n".join(f"- {r}" for r in verdict.get("evidence") or [])
        prompt = PROMPT.format(domain=defang(verdict["domain"]), score=verdict["score"],
                               classification=verdict["classification"], brand=verdict.get("matched_brand") or "unknown",
                               reasons=reasons, language=language)
        for model in models:
            try:
                brief = validate_brief(_json_from(caller(model, prompt, api_key) if caller is call_openrouter
                                                  else caller(model, prompt)), verdict)
            except Exception:
                continue
            if brief:
                return {**brief, "source": "llm", "model_name": model, "language": language}
    return template_explanation(verdict, language)


# ---- scam-message tactics (deterministic; the same words are searched, nothing is fetched or executed) -----------
TACTICS = {
    "urgent action request": ["urgent", "immediately", "within 24", "today only", "act now", "right now", "expires"],
    "account threat": ["blocked", "suspended", "deactivated", "locked", "will be terminated", "disabled", "freeze"],
    "credential request": ["password", "otp", "login", "log in", "verify your", "kyc", "card number", "cvv", "pin"],
    "money offer": ["refund", "cashback", "prize", "reward", "lottery", "bonus", "gift"],
    "impersonated authority": ["bank", "police", "income tax", "government", "customs", "rbi", "support team"],
}


def message_tactics(text: str) -> list[str]:
    low = (text or "").lower()
    return [name for name, words in TACTICS.items() if any(w in low for w in words)]

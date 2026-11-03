"""Public API (FastAPI). Every endpoint from the specification.

Security: no secrets in URLs or logs; parameterised queries only (all data access goes through the warehouse
interface); defanged output; input length limits; rate limits (per IP for public endpoints, per key for company
endpoints); security headers; CORS only for PUBLIC_ORIGIN; API docs switched off; links that carry a domain are
always defanged. The public checker never opens a suspicious URL and never shows which company a domain targets."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .auth import AuthError, RateLimiter, authenticate, verify_unsubscribe
from .captcha import CaptchaError, verify_turnstile
from .config import LANGUAGES, Settings
from .domain_validation import validate_registered_domain
from .llm import explain, message_tactics, template_explanation
from .normalize import clean_host, defang, extract_hosts, split_host
from .news import fetch_articles
from .notifier import EMAIL_DELIVERY_ERRORS, send_dispute_ack, send_verification
from .registration import Registrar, RegistrationError
from .reputation import infrastructure_checks, virustotal_lookup
from .scoring import score_domain
from .watchlist import WarehouseWatchlist

log = logging.getLogger("domainguard.api")
WEB = Path(__file__).resolve().parents[1] / "web"
DISCLAIMER = "Automated risk estimate based on public data. Not a confirmed verdict."
CAUTION = ("Low score, but this name resembles a protected brand. Registration data may be missing, "
           "so stay cautious and check the address carefully.")
VERDICT = {"ALLOWLISTED": "official", "LOW": "low_risk", "SUSPICIOUS": "suspicious", "HIGH_RISK": "high_risk",
           "DANGEROUS": "dangerous"}
SEVERITY = ["official", "low_risk", "suspicious", "high_risk", "dangerous", "no_links"]
HEADERS = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
           "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
           "Strict-Transport-Security": "max-age=31536000"}


def _url_quote(s: str) -> str:
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~")
    return "".join(c if c in safe else f"%{ord(c):02X}" for c in s)


class CheckIn(BaseModel):
    input: str = Field(min_length=1, max_length=2048)
    language: str = "English"


class ScanIn(BaseModel):
    text: str = Field(min_length=5, max_length=10000)
    language: str = "English"


class RegisterIn(BaseModel):
    company_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    contact_person: str | None = Field(default=None, max_length=120)
    domains: list[str] = Field(min_length=1, max_length=20)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    captcha_token: str | None = Field(default=None, max_length=4096)


class VerifyOtpIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    captcha_token: str | None = Field(default=None, max_length=4096)


class SettingsIn(BaseModel):
    contact_person: str | None = Field(default=None, max_length=120)
    notification_email: str | None = Field(default=None, max_length=254)
    email_notifications: bool | None = None
    notification_frequency: str | None = Field(default=None, pattern="^(IMMEDIATE|DAILY|WEEKLY)$")
    min_score_threshold: int | None = Field(default=None, ge=0, le=100)


class DomainIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    aliases: list[str] = Field(default_factory=list, max_length=20)


class DisputeIn(BaseModel):
    domain: str = Field(min_length=3, max_length=2048)
    email: str = Field(min_length=3, max_length=254)


def create_app(wh, settings: Settings, *, sender=None, clock=lambda: datetime.now(timezone.utc),
               llm_caller=None, watchlist=None, domain_checker=None) -> FastAPI:
    if not settings.secret_key:
        raise RuntimeError("DG_SECRET_KEY must be set (it signs unsubscribe links)")
    app = FastAPI(title="DomainGuard", docs_url=None, redoc_url=None, openapi_url=None)
    wl_cache = watchlist or WarehouseWatchlist(wh, ttl_s=settings.watchlist_ttl_s)
    public = RateLimiter(settings.api_rate_limit_per_min)
    keyed = RateLimiter(settings.api_key_rate_limit_per_min)
    registrations = RateLimiter(settings.registration_rate_limit_per_hour, 3600)
    otp_checks = RateLimiter(settings.otp_rate_limit_per_hour, 3600)
    registrar = Registrar(wh, clock=clock, domain_checker=domain_checker)
    if settings.public_origin:
        app.add_middleware(CORSMiddleware, allow_origins=[settings.public_origin], allow_methods=["GET", "POST", "PUT", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"], allow_credentials=False)

    @app.middleware("http")
    async def harden(request: Request, call_next):
        resp = await call_next(request)
        for k, v in HEADERS.items():
            resp.headers.setdefault(k, v)
        if not request.url.path.startswith("/static"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    def ip_limit(request: Request):
        wait = public.check(request.client.host if request.client else "unknown")
        if wait is not None:
            raise HTTPException(429, "too many requests", headers={"Retry-After": str(int(wait) + 1)})

    def auth(authorization: str | None):
        try:
            user = authenticate(wh, authorization)
        except AuthError as e:
            raise HTTPException(e.status, e.detail)
        wait = keyed.check(user["company_id"])
        if wait is not None:
            raise HTTPException(429, "too many requests for this key", headers={"Retry-After": str(int(wait) + 1)})
        return user

    def language(lang: str) -> str:
        if lang not in LANGUAGES:
            raise HTTPException(422, f"language must be one of: {', '.join(LANGUAGES)}")
        return lang

    def deliver(send, unavailable_message: str):
        try:
            send()
        except EMAIL_DELIVERY_ERRORS:
            log.exception("email delivery failed")
            raise HTTPException(503, unavailable_message)

    def now_iso() -> str:
        return clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def assess(host: str, lang: str) -> dict:
        registrable = split_host(host).registrable
        stored = wh.get_verdict(host) or wh.get_verdict(registrable)
        infra = {"points": 0, "evidence": []}
        reputation = {"status": "not_checked", "points": 0, "evidence": []}
        if stored:
            brief = wh.get_brief(stored["domain"], stored["company_id"], lang)
            brief = brief if brief and brief.get("verdict_score") == stored["score"] else None  # stale briefs are ignored
            expl = ({k: brief[k] for k in ("summary", "reasons", "advice", "source", "model_name")} | {"language": lang}
                    if brief else template_explanation(stored, lang))
            v, basis, age_known = stored, "observed_in_stream", stored.get("age_days") is not None
        else:
            infra = infrastructure_checks(host)
            reputation = virustotal_lookup(
                f"https://{host}", settings.virustotal_api_key, settings.reputation_timeout_s
            )
            v = score_domain(
                host, wl_cache.current(), age_days=None, on_blocklist=False, now=clock(),
                reputation_points=infra["points"] + reputation["points"],
                reputation_evidence=infra["evidence"] + reputation["evidence"],
            ).to_dict()
            expl = explain(v, lang, models=(), caller=llm_caller)
            basis, age_known = "name_and_reputation_analysis", False
        label = VERDICT[v["classification"]]
        note = CAUTION if label == "low_risk" and v.get("matched_brand") else None
        return {"domain": defang(v["domain"]), "verdict": label, "score": v["score"],
                "matched_brand": v.get("matched_brand"), "reasons": v.get("evidence") or [], "explanation": expl,
                "basis": basis, "age_known": age_known,
                "validation": {"infrastructure_points": infra["points"],
                               "reputation_status": reputation["status"],
                               "reputation_points": reputation["points"]},
                "note": note, "disclaimer": DISCLAIMER}

    # ---- public -------------------------------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok", "timestamp": now_iso()}

    @app.get("/config")
    def config():
        return {"languages": list(LANGUAGES), "dispute_url": settings.dispute_url}

    @app.get("/safety/feed")
    def safety_feed(request: Request, limit: int = 8):
        ip_limit(request)
        limit = max(1, min(limit, 12))
        rows = wh.inbox(min_score=70, limit=50)
        threats = [{"domain": defang(r["domain"]), "verdict": VERDICT.get(r["classification"], "suspicious"),
                    "score": r["score"], "first_flagged_at": r.get("first_flagged_at")}
                   for r in rows if r.get("classification") in ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS")]
        return {"threats": threats, "articles": fetch_articles(limit=limit),
                "precautions": [
                    "Never sign in through a link received unexpectedly by email or SMS.",
                    "Check the full domain spelling before entering credentials or payment details.",
                    "Use a password manager and multi-factor authentication where available.",
                    "Do not share one-time passwords, recovery codes, or card PINs with anyone.",
                    "Report suspected fraud to your bank and the relevant official authority.",
                ]}

    @app.get("/safety", response_class=HTMLResponse)
    def safety_page():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=307)

    @app.post("/check")
    def check(body: CheckIn, request: Request):
        ip_limit(request)
        lang = language(body.language)
        host = clean_host(body.input)
        if host is None:
            raise HTTPException(422, "that does not look like a valid domain or link")
        return assess(host, lang)

    @app.get("/check")
    def check_get(request: Request, domain: str | None = None, input: str | None = None, language_name: str = "English"):
        ip_limit(request)
        target = domain or input
        if not target:
            raise HTTPException(422, "missing domain or input parameter")
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url=f"/?check={_url_quote(target)}", status_code=303)
        lang = language(language_name)
        host = clean_host(target)
        if host is None:
            raise HTTPException(422, "that does not look like a valid domain or link")
        return assess(host, lang)

    @app.post("/scan-message")
    def scan(body: ScanIn, request: Request):
        ip_limit(request)
        lang = language(body.language)
        links = [assess(h, lang) for h in extract_hosts(body.text, limit=10)]
        worst = max((l["verdict"] for l in links), key=SEVERITY.index, default="no_links")
        return {"links_found": len(links), "links": links, "worst_verdict": worst,
                "message_analysis": {"tactics": message_tactics(body.text)}, "disclaimer": DISCLAIMER}

    @app.post("/register", status_code=202)
    def register(body: RegisterIn, request: Request):
        ip_limit(request)
        client_ip = request.client.host if request.client else "unknown"
        wait = registrations.check(client_ip, consume=False)
        if wait is not None:
            raise HTTPException(429, "registration temporarily unavailable", headers={"Retry-After": str(int(wait) + 1)})
        try:
            verify_turnstile(body.captcha_token or "", settings.turnstile_secret_key, client_ip, settings.captcha_timeout_s)
        except CaptchaError as e:
            raise HTTPException(400, str(e))
        try:
            out = registrar.register(name=body.company_name, email=body.email, contact_person=body.contact_person,
                                     domains=body.domains, aliases=body.aliases)
        except RegistrationError as e:
            if "already registered" in str(e):
                existing = wh.get_user_by_email(body.email)
                if existing and existing["status"] == "PENDING" and sender is not None:
                    out = registrar.resend_otp(body.email)
                    try:
                        send_verification(sender, settings, out["email"], existing["name"], out["otp"])
                    except EMAIL_DELIVERY_ERRORS:
                        log.exception("registration verification resend failed for %s", out["email"])
                        return {"status": "PENDING", "verification_email_sent": False,
                                "message": "A new verification code could not be sent. Please try again later."}
                    registrations.hit(client_ip)
                    return {"status": "PENDING", "verification_email_sent": True,
                            "message": "A new verification code was sent. Check your email and enter it within 10 minutes."}
                return {"status": "PENDING", "verification_email_sent": False,
                        "message": "This email is already registered. Use the existing verification code or contact support."}
            raise HTTPException(422, str(e))
        if sender is not None:
            try:
                send_verification(sender, settings, out["email"], body.company_name, out["otp"])
            except EMAIL_DELIVERY_ERRORS:
                log.exception("registration verification email failed for %s", out["email"])
                return {
                    "status": "PENDING",
                    "verification_email_sent": False,
                    "message": (
                        "Registration received, but the verification email could not be sent. "
                        "An administrator can approve your registration from the dashboard."
                    ),
                }
        registrations.hit(client_ip)
        return {
            "status": "PENDING",
            "verification_email_sent": True,
            "message": "Check your email for the 6-digit verification code, then enter it within 10 minutes.",
        }

    @app.get("/register", response_class=HTMLResponse)
    def register_page():
        path = WEB / "register.html"
        if not path.exists():
            return HTMLResponse("<p>page not found</p>", status_code=404)
        return HTMLResponse(path.read_text(encoding="utf-8").replace("__TURNSTILE_SITE_KEY__", settings.turnstile_site_key))

    @app.post("/verify-otp")
    def verify_otp(body: VerifyOtpIn, request: Request):
        ip_limit(request)
        client_ip = request.client.host if request.client else "unknown"
        wait = otp_checks.check(client_ip)
        if wait is not None:
            raise HTTPException(429, "verification temporarily unavailable", headers={"Retry-After": str(int(wait) + 1)})
        try:
            verify_turnstile(body.captcha_token or "", settings.turnstile_secret_key, client_ip, settings.captcha_timeout_s)
        except CaptchaError as e:
            raise HTTPException(400, str(e))
        try:
            out = registrar.verify_otp(body.otp, body.email)
        except RegistrationError as e:
            raise HTTPException(400, str(e))
        return {"status": "ACTIVE", "message": "Your account is active. Copy your API key now; it will not be shown again.",
                "company_id": out["company_id"], "api_key": out["api_key"]}

    @app.get("/verify/{token}")
    def retired_verify_link():
        raise HTTPException(410, "Verification links are disabled. Use the one-time code sent by email.")

    @app.get("/unsubscribe/{token}", response_class=HTMLResponse)
    def unsubscribe(token: str):
        company_id = verify_unsubscribe(settings.secret_key, token)
        if company_id is None or wh.get_user(company_id) is None:
            raise HTTPException(400, "this unsubscribe link is not valid")
        wh.set_prefs(company_id, {"email_notifications": False})
        wh.update_user(company_id, {"email_notifications": False})
        return HTMLResponse("<p>You are unsubscribed from DomainGuard alerts. You can turn them back on in your settings.</p>")

    @app.post("/dispute", status_code=202)
    def dispute(body: DisputeIn, request: Request):
        ip_limit(request)
        host = clean_host(body.domain)
        if host is None:
            raise HTTPException(422, "that does not look like a valid domain or link")
        if sender is not None:
            deliver(lambda: send_dispute_ack(sender, settings, body.email, host),
                    "Your dispute was received, but the confirmation email could not be sent. Please try again later.")
        return {"status": "RECEIVED", "message": "Thank you. An analyst will review your dispute."}

    # ---- company (API key) --------------------------------------------------------------------------
    @app.get("/analyst/inbox")
    def inbox(hours: int = 24, min_score: int = 70, limit: int = 50, authorization: str | None = Header(default=None)):
        user = auth(authorization)
        hours, limit = max(1, min(hours, 24 * 30)), max(1, min(limit, 200))
        since = (clock() - timedelta(hours=hours)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = wh.inbox(company_id=user["company_id"], min_score=max(0, min(min_score, 100)), since=since, limit=limit)
        domains = []
        for r in rows:
            age_h = round(r["age_days"] * 24, 1) if r.get("age_days") is not None else None
            domains.append({"domain": defang(r["domain"]), "score": r["score"], "classification": r["classification"],
                            "matched_brand": r.get("matched_brand"), "first_flagged_at": r.get("first_flagged_at"),
                            "age_hours": age_h, "on_blocklist": r.get("is_on_blocklist", False),
                            "analyst_label": r.get("analyst_label", "UNREVIEWED")})
        return {"count": len(domains), "domains": domains}

    @app.get("/company/settings")
    def get_settings(authorization: str | None = Header(default=None)):
        user = auth(authorization)
        prefs = wh.get_prefs(user["company_id"])
        return {"company_id": user["company_id"], "name": user["name"], "email": user["email"],
                "contact_person": user.get("contact_person"), "status": user["status"],
                "domains": [{"domain": defang(r["domain"]), "aliases": r["brand_aliases"]}
                            for r in wh.protected_for(user["company_id"])],
                "preferences": prefs}

    @app.put("/company/settings")
    def put_settings(body: SettingsIn, authorization: str | None = Header(default=None)):
        user = auth(authorization)
        uid = user["company_id"]
        if body.contact_person is not None:
            wh.update_user(uid, {"contact_person": body.contact_person.strip() or None})
        if body.notification_email is not None:
            wh.update_user(uid, {"notification_email": body.notification_email.strip() or None})
            wh.set_prefs(uid, {"notification_email": body.notification_email.strip() or None})
        if body.email_notifications is not None:
            wh.update_user(uid, {"email_notifications": body.email_notifications})
            wh.set_prefs(uid, {"email_notifications": body.email_notifications})
        prefs = {k: v for k, v in {"notification_frequency": body.notification_frequency,
                                   "min_score_threshold": body.min_score_threshold}.items() if v is not None}
        if prefs:
            wh.set_prefs(uid, prefs)
        return {"status": "saved"}

    @app.post("/company/domains/add", status_code=201)
    def add_domain(body: DomainIn, authorization: str | None = Header(default=None)):
        user = auth(authorization)
        try:
            out = registrar.add_domain(user["company_id"], body.domain, body.aliases)
        except RegistrationError as e:
            raise HTTPException(422, str(e))
        return {"status": "added", "domain": defang(out["domain"])}

    @app.delete("/company/domains/{domain}")
    def remove_domain(domain: str, authorization: str | None = Header(default=None)):
        user = auth(authorization)
        try:
            registrar.remove_domain(user["company_id"], domain)
        except RegistrationError as e:
            raise HTTPException(404, str(e))
        return {"status": "removed"}

    @app.post("/company/api-key/rotate")
    def rotate(authorization: str | None = Header(default=None)):
        user = auth(authorization)
        key = registrar.rotate_key(user["company_id"])
        return {"api_key": key, "message": "Store this key now. It will not be shown again. The old key no longer works."}

    if WEB.exists():
        app.mount("/static", StaticFiles(directory=WEB), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _page(WEB / "index.html")

    return app


def _page(path: Path) -> HTMLResponse:
    if not path.exists():
        return HTMLResponse("<p>page not found</p>", status_code=404)
    return HTMLResponse(path.read_text(encoding="utf-8"))


def build_default_app() -> FastAPI:
    """Factory for `uvicorn domainguard.api:build_default_app --factory`. Reads the environment; needs Snowflake."""
    from .cli import _load_dotenv
    _load_dotenv()
    from .factory import make_warehouse
    from .notifier import SMTPSender

    s = Settings.from_env()
    wh = make_warehouse(s)
    sender = SMTPSender(s.smtp_host, s.smtp_port, s.smtp_user, s.smtp_password, s.smtp_from) if s.smtp_host else None
    return create_app(wh, s, sender=sender, domain_checker=validate_registered_domain)

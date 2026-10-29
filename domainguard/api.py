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
from .config import LANGUAGES, Settings
from .llm import explain, message_tactics, template_explanation
from .normalize import clean_host, defang, extract_hosts, split_host
from .notifier import send_api_key, send_dispute_ack, send_verification
from .registration import Registrar, RegistrationError
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
               llm_caller=None, watchlist=None) -> FastAPI:
    if not settings.secret_key:
        raise RuntimeError("DG_SECRET_KEY must be set (it signs unsubscribe links)")
    app = FastAPI(title="DomainGuard", docs_url=None, redoc_url=None, openapi_url=None)
    wl_cache = watchlist or WarehouseWatchlist(wh, ttl_s=settings.watchlist_ttl_s)
    public = RateLimiter(settings.api_rate_limit_per_min)
    keyed = RateLimiter(settings.api_key_rate_limit_per_min)
    registrar = Registrar(wh, clock=clock)
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

    def now_iso() -> str:
        return clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def assess(host: str, lang: str) -> dict:
        registrable = split_host(host).registrable
        stored = wh.get_verdict(host) or wh.get_verdict(registrable)
        if stored:
            brief = wh.get_brief(stored["domain"], stored["company_id"], lang)
            brief = brief if brief and brief.get("verdict_score") == stored["score"] else None  # stale briefs are ignored
            expl = ({k: brief[k] for k in ("summary", "reasons", "advice", "source", "model_name")} | {"language": lang}
                    if brief else template_explanation(stored, lang))
            v, basis, age_known = stored, "observed_in_stream", stored.get("age_days") is not None
        else:
            v = score_domain(host, wl_cache.current(), age_days=None, on_blocklist=False, now=clock()).to_dict()
            expl = explain(v, lang, models=(), caller=llm_caller)
            basis, age_known = "name_only_analysis", False
        label = VERDICT[v["classification"]]
        note = CAUTION if label == "low_risk" and v.get("matched_brand") else None
        return {"domain": defang(v["domain"]), "verdict": label, "score": v["score"],
                "matched_brand": v.get("matched_brand"), "reasons": v.get("evidence") or [], "explanation": expl,
                "basis": basis, "age_known": age_known, "note": note, "disclaimer": DISCLAIMER}

    # ---- public -------------------------------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok", "timestamp": now_iso()}

    @app.get("/config")
    def config():
        return {"languages": list(LANGUAGES), "dispute_url": settings.dispute_url}

    @app.post("/check")
    def check(body: CheckIn, request: Request):
        ip_limit(request)
        lang = language(body.language)
        host = clean_host(body.input)
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
        try:
            out = registrar.register(name=body.company_name, email=body.email, contact_person=body.contact_person,
                                     domains=body.domains, aliases=body.aliases)
        except RegistrationError as e:
            raise HTTPException(422, str(e))
        if sender is not None:
            send_verification(sender, settings, out["email"], body.company_name, out["token"])
        return {"status": "PENDING", "message": "Check your email for a verification link (valid 24 hours)."}

    @app.get("/register", response_class=HTMLResponse)
    def register_page():
        return _page(WEB / "register.html")

    @app.get("/verify/{token}")
    def verify(token: str, request: Request):
        ip_limit(request)
        try:
            out = registrar.verify(token)
        except RegistrationError as e:
            raise HTTPException(400, str(e))
        if sender is not None:
            send_api_key(sender, settings, out["email"], out["name"], out["api_key"])
        return {"status": "ACTIVE", "message": "Your account is active. Your API key was emailed to you."}

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
            send_dispute_ack(sender, settings, body.email, host)
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
    from .factory import make_warehouse
    from .notifier import SMTPSender

    s = Settings.from_env()
    wh = make_warehouse(s)
    sender = SMTPSender(s.smtp_host, s.smtp_port, s.smtp_user, s.smtp_password, s.smtp_from) if s.smtp_host else None
    return create_app(wh, s, sender=sender)

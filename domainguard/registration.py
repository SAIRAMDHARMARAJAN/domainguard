"""Company self-registration: validate, create a PENDING account, email-verify, then issue an API key.

Account enumeration: registering an email that already exists is refused, as the specification requires.
Verification links expire after 24 hours and can be used once. The API key is shown once to the caller and
emailed; only its hash is stored."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from .auth import hash_key, new_api_key
from .normalize import clean_host, split_host

MAX_DOMAINS = 20
TOKEN_TTL = timedelta(hours=24)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class RegistrationError(ValueError):
    pass


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_domain(raw: str) -> str:
    host = clean_host(raw or "")
    if host is None:
        raise RegistrationError(f"not a valid domain: {raw!r}")
    try:
        ipaddress.ip_address(host)
        raise RegistrationError("IP addresses cannot be registered")
    except ValueError as e:
        if "IP addresses" in str(e):
            raise
    parts = split_host(host)
    if not parts.label:
        raise RegistrationError(f"not a registrable domain: {raw!r}")
    return parts.registrable


def suggest_aliases(domain: str, company_name: str = "") -> list[str]:
    label = split_host(domain).label
    words = [w for w in label.replace("-", " ").split() if w]
    out = [label, " ".join(words), "".join(words)]
    if company_name.strip():
        out.append(company_name.strip().lower())
    return [a for a in dict.fromkeys(x.lower() for x in out if x and len(x) >= 3)]


def validate_email(email: str) -> str:
    email = (email or "").strip()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise RegistrationError("enter a valid email address")
    return email


class Registrar:
    def __init__(self, wh, clock=lambda: datetime.now(timezone.utc)):
        self.wh = wh
        self._now = clock

    def register(self, *, name: str, email: str, contact_person: str | None, domains: list[str],
                 aliases: list[str] | None = None) -> dict:
        name = (name or "").strip()
        if not (2 <= len(name) <= 120):
            raise RegistrationError("company name must be 2 to 120 characters")
        email = validate_email(email)
        if not domains:
            raise RegistrationError("add at least one domain to protect")
        normal = list(dict.fromkeys(normalize_domain(d) for d in domains))
        if len(normal) > MAX_DOMAINS:
            raise RegistrationError(f"at most {MAX_DOMAINS} domains per company")
        if self.wh.get_user_by_email(email):
            raise RegistrationError("this email is already registered")
        company_id = str(uuid.uuid4())
        self.wh.create_user({"company_id": company_id, "name": name, "email": email,
                             "contact_person": (contact_person or "").strip() or None, "status": "PENDING",
                             "notification_email": email})
        given = [a.strip().lower() for a in (aliases or []) if a and a.strip()]
        for d in normal:
            self.wh.upsert_protected({"company_id": company_id, "domain": d,
                                      "brand_aliases": given or suggest_aliases(d, name),
                                      "official_domains": [d]})
        token = secrets.token_urlsafe(32)
        expires = self._now() + TOKEN_TTL
        self.wh.put_verification({"company_id": company_id, "email": email,
                                  "token_hash": hashlib.sha256(token.encode()).hexdigest(), "expires_at": _iso(expires)})
        return {"company_id": company_id, "email": email, "token": token, "expires_at": _iso(expires),
                "domains": normal, "status": "PENDING"}

    def verify(self, token: str) -> dict:
        h = hashlib.sha256((token or "").encode()).hexdigest()
        v = self.wh.get_verification(h)
        if v is None:
            raise RegistrationError("this verification link is not valid")
        if v.get("verified_at"):
            raise RegistrationError("this verification link has already been used")
        if datetime.fromisoformat(v["expires_at"].replace("Z", "+00:00")) < self._now():
            raise RegistrationError("this verification link has expired; register again")
        user = self.wh.get_user(v["company_id"])
        if user is None:
            raise RegistrationError("account not found")
        key = new_api_key()
        self.wh.update_user(v["company_id"], {"status": "ACTIVE", "api_key_hash": hash_key(key),
                                              "api_key_created_at": _iso(self._now())})
        self.wh.update_verification(h, {"verified_at": _iso(self._now())})
        return {"company_id": v["company_id"], "email": user["email"], "name": user["name"], "api_key": key}

    def add_domain(self, company_id: str, raw: str, aliases: list[str] | None = None) -> dict:
        d = normalize_domain(raw)
        current = self.wh.protected_for(company_id)
        if all(r["domain"] != d for r in current) and len(current) >= MAX_DOMAINS:
            raise RegistrationError(f"at most {MAX_DOMAINS} domains per company")
        user = self.wh.get_user(company_id)
        given = [a.strip().lower() for a in (aliases or []) if a and a.strip()]
        self.wh.upsert_protected({"company_id": company_id, "domain": d,
                                  "brand_aliases": given or suggest_aliases(d, user["name"] if user else ""),
                                  "official_domains": [d]})
        return {"domain": d}

    def remove_domain(self, company_id: str, raw: str) -> None:
        d = normalize_domain(raw)
        if not any(r["domain"] == d for r in self.wh.protected_for(company_id)):
            raise RegistrationError("that domain is not on your list")
        self.wh.remove_protected(company_id, d)

    def rotate_key(self, company_id: str) -> str:
        key = new_api_key()
        self.wh.update_user(company_id, {"api_key_hash": hash_key(key), "api_key_created_at": _iso(self._now())})
        return key

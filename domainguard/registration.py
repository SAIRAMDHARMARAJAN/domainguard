"""Company self-registration: validate, create a PENDING account, OTP-verify, then issue an API key.

Account enumeration: registering an email that already exists is refused, as the specification requires.
OTP codes expire quickly, are single-use, and are never stored in plaintext. The API key is returned once
over the HTTPS verification response; it is never sent by email and only its hash is stored."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from email_validator import EmailNotValidError, validate_email as validate_email_address

from .auth import hash_key, new_api_key
from .normalize import clean_host, split_host

MAX_DOMAINS = 20
OTP_TTL = timedelta(minutes=10)
MAX_OTP_ATTEMPTS = 5
class RegistrationError(ValueError):
    pass


def _iso(dt: datetime) -> str:
    return _utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


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
    try:
        return validate_email_address(email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise RegistrationError("enter a valid email address") from exc


class Registrar:
    def __init__(self, wh, clock=lambda: datetime.now(timezone.utc), domain_checker=None):
        self.wh, self.domain_checker = wh, domain_checker
        self._now = clock

    def register(self, *, name: str, email: str, contact_person: str | None, domains: list[str],
                 aliases: list[str] | None = None) -> dict:
        name = (name or "").strip()
        if not (2 <= len(name) <= 120):
            raise RegistrationError("company name must be 2 to 120 characters")
        email = validate_email(email)
        if not domains:
            raise RegistrationError("add at least one domain to protect")
        normalized_domains = [normalize_domain(d) for d in domains]
        if len(set(normalized_domains)) != len(normalized_domains):
            raise RegistrationError("duplicate domains are not allowed")
        normal = normalized_domains
        if len(normal) > MAX_DOMAINS:
            raise RegistrationError(f"at most {MAX_DOMAINS} domains per company")
        if self.domain_checker:
            for domain in normal:
                try:
                    self.domain_checker(domain)
                except ValueError as exc:
                    raise RegistrationError(f"domain validation failed for {domain}: {exc}") from exc
        if self.wh.get_user_by_email(email):
            raise RegistrationError("this email is already registered")
        duplicate = next((domain for domain in normal if self.wh.domain_registered(domain)), None)
        if duplicate:
            raise RegistrationError(f"this domain is already registered: {duplicate}")
        company_id = str(uuid.uuid4())
        self.wh.create_user({"company_id": company_id, "name": name, "email": email,
                             "contact_person": (contact_person or "").strip() or None, "status": "PENDING",
                             "notification_email": email})
        given = [a.strip().lower() for a in (aliases or []) if a and a.strip()]
        for d in normal:
            self.wh.upsert_protected({"company_id": company_id, "domain": d,
                                      "brand_aliases": given or suggest_aliases(d, name),
                                      "official_domains": [d]})
        otp = f"{secrets.randbelow(1_000_000):06d}"
        expires = self._now() + OTP_TTL
        self.wh.put_verification({"company_id": company_id, "email": email,
                                  "token_hash": hashlib.sha256(otp.encode()).hexdigest(), "expires_at": _iso(expires),
                                  "otp_attempts": 0})
        return {"company_id": company_id, "email": email, "otp": otp, "token": otp, "expires_at": _iso(expires),
                "domains": normal, "status": "PENDING"}

    def verify_otp(self, otp: str, email: str | None = None) -> dict:
        otp = (otp or "").strip()
        if not re.fullmatch(r"\d{6}", otp):
            raise RegistrationError("enter the 6-digit verification code")
        h = hashlib.sha256(otp.encode()).hexdigest()
        v = self.wh.get_verification(h)
        if v is None:
            raise RegistrationError("the verification code is not valid")
        if v.get("verified_at"):
            raise RegistrationError("this verification code has already been used")
        if int(v.get("otp_attempts") or 0) >= MAX_OTP_ATTEMPTS:
            raise RegistrationError("too many incorrect verification attempts; register again")
        if email and email.strip().lower() != v["email"].strip().lower():
            self.wh.update_verification(h, {"otp_attempts": int(v.get("otp_attempts") or 0) + 1})
            raise RegistrationError("the verification code is not valid")
        expires_at = datetime.fromisoformat(v["expires_at"].replace("Z", "+00:00"))
        if _utc(expires_at) < _utc(self._now()):
            raise RegistrationError("this verification code has expired; register again")
        user = self.wh.get_user(v["company_id"])
        if user is None:
            raise RegistrationError("account not found")
        if user["status"] != "PENDING":
            raise RegistrationError("this registration has already been approved")
        key = new_api_key()
        self.wh.update_user(v["company_id"], {"status": "ACTIVE", "api_key_hash": hash_key(key),
                                              "api_key_created_at": _iso(self._now())})
        self.wh.update_verification(h, {"verified_at": _iso(self._now())})
        return {"company_id": v["company_id"], "email": user["email"], "name": user["name"], "api_key": key}

    def verify(self, token: str) -> dict:
        """Backward-compatible internal alias; public clients must use the OTP endpoint."""
        return self.verify_otp(token)

    def resend_otp(self, email: str) -> dict:
        user = self.wh.get_user_by_email(validate_email(email))
        if user is None or user["status"] != "PENDING":
            raise RegistrationError("this registration is not eligible for a new verification code")
        otp = f"{secrets.randbelow(1_000_000):06d}"
        expires = self._now() + OTP_TTL
        self.wh.put_verification({"company_id": user["company_id"], "email": user["email"],
                                  "token_hash": hashlib.sha256(otp.encode()).hexdigest(),
                                  "expires_at": _iso(expires), "otp_attempts": 0})
        return {"company_id": user["company_id"], "email": user["email"], "otp": otp,
                "expires_at": _iso(expires), "status": "PENDING"}

    def approve_pending(self, company_id: str) -> dict:
        """Approve a pending registration without email and return its API key once."""
        user = self.wh.get_user(company_id)
        if user is None:
            raise RegistrationError("account not found")
        if user["status"] != "PENDING":
            raise RegistrationError("only pending registrations can be approved")
        key = new_api_key()
        self.wh.update_user(company_id, {"status": "ACTIVE", "api_key_hash": hash_key(key),
                                         "api_key_created_at": _iso(self._now())})
        return {"company_id": company_id, "email": user["email"], "name": user["name"], "api_key": key}

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

"""Email: threat alerts (immediate or digest), verification and API-key emails, dispute acknowledgements.

Every alert: defanged domain, score, reasons, a check link to OUR checker (the suspicious site is never linked or
opened), settings and signed unsubscribe links. Each (company, domain) is alerted once; each send is logged to
OPS.EMAIL_LOG. Sending uses SMTP (SES is not implemented in this build)."""
from __future__ import annotations

import html
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from string import Template
from urllib.parse import quote

from .auth import unsubscribe_token
from .normalize import defang

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
SUBJECT = "⚠️ ALERT: Suspicious domain resembling your brand detected"
FREQUENCY_DAYS = {"DAILY": 1, "WEEKLY": 7}
MAX_AGE_FOR_IMMEDIATE = timedelta(hours=1)
EMAIL_DELIVERY_ERRORS = (OSError, smtplib.SMTPException)


class SMTPSender:
    def __init__(self, host: str, port: int, user: str, password: str, from_addr: str, timeout: float = 30):
        self.host, self.port, self.user, self.password, self.from_addr, self.timeout = host, port, user, password, from_addr, timeout

    def send(self, msg: EmailMessage) -> None:  # pragma: no cover - needs a real SMTP server
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            s.starttls()
            if self.user:
                s.login(self.user, self.password)
            s.send_message(msg)


class RecordingSender:
    """Test double: keeps messages in a list instead of sending them."""

    def __init__(self, fail: bool = False):
        self.sent: list[EmailMessage] = []
        self.fail = fail

    def send(self, msg: EmailMessage) -> None:
        if self.fail:
            raise OSError("smtp unavailable")
        self.sent.append(msg)


def _render(name: str, values: dict) -> str:
    """Fill an HTML template. Values are escaped, except keys ending in _html, which the caller has already escaped."""
    safe = {k: (str(v) if k.endswith("_html") else html.escape(str(v), quote=True)) for k, v in values.items()}
    return Template((TEMPLATES / name).read_text()).substitute(safe)


def _message(to: str, subject: str, text: str, html_body: str | None, from_addr: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    return msg


def _branded(body: str) -> str:
    return _render("email_shell.html", {"body_html": body})


def _age_text(age_days: float | None) -> str:
    if age_days is None:
        return "unknown (registration data not available)"
    if age_days < 1:
        return f"{round(age_days * 24)} hours"
    return f"{round(age_days)} days"


def check_url(settings, domain: str) -> str:
    # the defanged form goes in the link; our checker re-fangs it when parsing (clean_host)
    return f"{settings.web_domain.rstrip('/')}/check?domain={quote(defang(domain))}"


def alert_message(settings, user: dict, v: dict, to: str, now: datetime) -> EmailMessage:
    token = unsubscribe_token(settings.secret_key, user["company_id"])
    reasons = v.get("evidence") or []
    values = {
        "company_name": user["name"], "domain": defang(v["domain"]), "classification": v["classification"],
        "score": v["score"], "detected_at": now.strftime("%Y-%m-%d %H:%M UTC"), "age": _age_text(v.get("age_days")),
        "reasons_html": "".join(f"<li>{html.escape(r)}</li>" for r in reasons),
        "check_url": check_url(settings, v["domain"]), "protected_domain": defang(v.get("protected_domain") or v.get("matched_brand") or ""),
        "settings_url": f"{settings.web_domain.rstrip('/')}/company/settings",
        "unsubscribe_url": f"{settings.web_domain.rstrip('/')}/unsubscribe/{token}",
    }
    text = (f"Hello {user['name']},\n\nA domain matching your protected brand has been detected:\n\n"
            f"Domain: {values['domain']}\nRisk Level: {v['classification']} (Score: {v['score']}/100)\n"
            f"Detected At: {values['detected_at']}\nAge: {values['age']}\n\nWarning Signs:\n"
            + "".join(f"- {r}\n" for r in reasons)
            + "\nWhat you should do:\n1. Do NOT click the link or enter credentials.\n2. Monitor for phishing reports.\n"
              "3. Consider filing an abuse report with the registrar.\n4. Notify your security team.\n\n"
            f"More details: {values['check_url']}\nSettings: {values['settings_url']}\n"
            f"Unsubscribe from alerts: {values['unsubscribe_url']}\n\n"
            "This is an automated risk estimate, not a confirmed verdict. Do not reply to this email.\n")
    return _message(to, SUBJECT, text, _branded(_render("threat_alert.html", values)), settings.smtp_from)


def _log(wh, user_id, domain, to, v, status, kind, error=None):
    wh.log_email({"company_id": user_id, "domain": domain, "recipient_email": to,
                  "score": v.get("score") if v else None, "classification": v.get("classification") if v else None,
                  "status": status, "kind": kind, "error": error})


def notify_new(wh, sender, settings, newly: list[dict], now: datetime | None = None) -> dict:
    """Immediate alerts for newly flagged verdicts. Respects opt-out, threshold, frequency and the 1-hour rule."""
    now = now or datetime.now(timezone.utc)
    out = {"sent": 0, "skipped": 0, "failed": 0, "queued_for_digest": 0}
    for v in newly:
        user = wh.get_user(v["company_id"])
        prefs = wh.get_prefs(v["company_id"])
        if not user or user["status"] != "ACTIVE" or not prefs["email_notifications"] or not user["email_notifications"]:
            out["skipped"] += 1
            continue
        if v["score"] < prefs["min_score_threshold"]:
            out["skipped"] += 1
            continue
        flagged_at = datetime.fromisoformat(v["first_flagged_at"].replace("Z", "+00:00"))
        if now - flagged_at > MAX_AGE_FOR_IMMEDIATE:
            out["skipped"] += 1  # only recent detections are alerted immediately; older ones go to digests
            continue
        if wh.alert_sent(v["company_id"], v["domain"]):
            out["skipped"] += 1
            continue
        if prefs["notification_frequency"] in FREQUENCY_DAYS:
            out["queued_for_digest"] += 1
            continue
        to = prefs.get("notification_email") or user.get("notification_email") or user["email"]
        try:
            sender.send(alert_message(settings, user, {**v, "protected_domain": v.get("matched_brand")}, to, now))
            _log(wh, v["company_id"], v["domain"], to, v, "SENT", "ALERT")
            out["sent"] += 1
        except EMAIL_DELIVERY_ERRORS as e:
            _log(wh, v["company_id"], v["domain"], to, v, "FAILED", "ALERT", error=str(e)[:500])
            out["failed"] += 1
    return out


def flush_digests(wh, sender, settings, now: datetime | None = None) -> dict:
    """DAILY / WEEKLY: one email per company listing the detections not yet alerted."""
    now = now or datetime.now(timezone.utc)
    out = {"digests_sent": 0, "domains": 0}
    for user in wh.list_users("ACTIVE"):
        prefs = wh.get_prefs(user["company_id"])
        days = FREQUENCY_DAYS.get(prefs["notification_frequency"])
        if not days or not prefs["email_notifications"]:
            continue
        last = prefs.get("frequency_last_sent_at")
        if last and now - datetime.fromisoformat(last.replace("Z", "+00:00")) < timedelta(days=days):
            continue
        items = [v for v in wh.verdicts(user["company_id"])
                 if v["classification"] in ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS")
                 and v["score"] >= prefs["min_score_threshold"] and v.get("first_flagged_at")
                 and not wh.alert_sent(user["company_id"], v["domain"])]
        if not items:
            continue
        to = prefs.get("notification_email") or user.get("notification_email") or user["email"]
        lines = "".join(f"- {defang(v['domain'])}: {v['classification']} ({v['score']}/100), "
                        f"first flagged {v['first_flagged_at']}\n" for v in items)
        text = (f"Hello {user['name']},\n\nYour {prefs['notification_frequency'].lower()} summary of suspicious domains:\n\n"
                f"{lines}\nThis is an automated risk estimate, not a confirmed verdict.\n")
        msg = _message(to, SUBJECT, text, _branded(
            "<h2 style=\"margin-top:0;color:#102a43\">Your threat summary</h2>"
            f"<p>Hello {html.escape(user['name'])},</p>"
            f"<p>Your {html.escape(prefs['notification_frequency'].lower())} summary of suspicious domains:</p>"
            f"<pre style=\"background:#f4f7fb;padding:16px;border-radius:8px;white-space:pre-wrap\">{html.escape(lines)}</pre>"
            "<p style=\"color:#68788c;font-size:13px\">This is an automated risk estimate, not a confirmed verdict.</p>"
        ), settings.smtp_from)
        try:
            sender.send(msg)
        except OSError as e:
            for v in items:
                _log(wh, user["company_id"], v["domain"], to, v, "FAILED", "DIGEST", error=str(e)[:500])
            continue
        for v in items:
            _log(wh, user["company_id"], v["domain"], to, v, "SENT", "DIGEST")
        wh.set_prefs(user["company_id"], {"frequency_last_sent_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")})
        out["digests_sent"] += 1
        out["domains"] += len(items)
    return out


def send_verification(sender, settings, email: str, name: str, otp: str) -> None:
    text = (f"Hello {name},\n\nYour DomainGuard verification code is: {otp}\n\n"
            "Enter this code on the DomainGuard registration page within 10 minutes. "
            "It works once. If you did not register, ignore this email.\n")
    body = (f"<h2 style=\"margin-top:0;color:#102a43\">Confirm your registration</h2>"
            f"<p>Hello {html.escape(name)},</p>"
            "<p>Enter this one-time code on the DomainGuard registration page:</p>"
            f"<div style=\"background:#102a43;color:#ffffff;padding:16px;border-radius:8px;font-family:monospace;font-size:24px;letter-spacing:5px;text-align:center\">"
            f"{html.escape(otp)}</div>"
            "<p style=\"color:#68788c;font-size:13px\">This code expires in 10 minutes and works once. "
            "If you did not register, you can safely ignore this email.</p>")
    sender.send(_message(email, "Your DomainGuard verification code", text, _branded(body), settings.smtp_from))


def _legacy_send_api_key(sender, settings, email: str, name: str, api_key: str) -> None:
    return send_api_key(sender, settings, email, name, api_key)

    text = (f"Hello {name},\n\nYour DomainGuard account is active. Your API key (shown only once; store it safely):\n\n"
            f"{api_key}\n\nUse it as:  Authorization: Bearer <key>\n\nIf you did not request this, rotate the key from "
            "your settings page right away.\n")
    body = (f"<h2 style=\"margin-top:0;color:#102a43\">Your account is active</h2>"
            f"<p>Hello {html.escape(name)},</p>"
            "<p>Your DomainGuard API key is shown below. Store it safely; it will not be shown again.</p>"
            f"<div style=\"background:#102a43;color:#ffffff;padding:16px;border-radius:8px;font-family:monospace;font-size:15px;word-break:break-all\">"
            f"{html.escape(api_key)}</div>"
            "<p style=\"font-size:13px;color:#68788c\">Use it as "
            "<code>Authorization: Bearer &lt;your-api-key&gt;</code> when calling the company API.</p>"
            "<p style=\"color:#a33b2f;font-size:13px\"><b>Security:</b> Never share this key publicly. "
            "If you believe it was exposed, rotate it from your company settings.</p>")
    sender.send(_message(email, "Your DomainGuard API key", text, _branded(body), settings.smtp_from))


def send_api_key(sender, settings, email: str, name: str, api_key: str) -> None:
    """Send an activation notice without placing the API secret in email."""
    text = (f"Hello {name},\n\nYour DomainGuard account is active. "
            "For your protection, your API key is never sent by email. "
            "It is shown once in the secure HTTPS verification response.\n")
    body = (f"<h2 style=\"margin-top:0;color:#102a43\">Your account is active</h2>"
            f"<p>Hello {html.escape(name)},</p>"
            "<p>For your protection, the API key is never included in email. "
            "It is shown once in the secure HTTPS verification response.</p>")
    sender.send(_message(email, "Your DomainGuard account is active", text, _branded(body), settings.smtp_from))


def send_dispute_ack(sender, settings, email: str, domain: str) -> None:
    body = _branded(_render("dispute_notification.html", {"domain": defang(domain)}))
    text = f"We received a dispute about the result for {defang(domain)}. An analyst will review it.\n"
    sender.send(_message(email, "We received your dispute", text, body, settings.smtp_from))

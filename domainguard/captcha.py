"""Provider-neutral CAPTCHA verification. Turnstile is the supported provider."""
from __future__ import annotations

import httpx


class CaptchaError(ValueError):
    pass


def verify_turnstile(token: str, secret: str, remote_ip: str | None, timeout: float = 5.0) -> None:
    if not secret:
        return
    if not token:
        raise CaptchaError("captcha verification is required")
    try:
        response = httpx.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": secret, "response": token, "remoteip": remote_ip or ""},
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CaptchaError("captcha verification is temporarily unavailable") from exc
    if not result.get("success"):
        raise CaptchaError("captcha verification failed")

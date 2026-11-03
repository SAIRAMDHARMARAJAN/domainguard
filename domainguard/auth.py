"""API keys, bearer authentication, sliding-window rate limits and signed unsubscribe links."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def new_api_key() -> str:
    return "dg_" + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    """Only the hash is stored (REF.USERS.API_KEY_HASH). The key itself is shown once."""
    return hashlib.sha256(key.encode()).hexdigest()


def authenticate(wh, authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError(401, "missing bearer token")
    key = authorization[len("Bearer "):].strip()
    if not key.startswith("dg_") or len(key) < 20:
        raise AuthError(401, "invalid API key")
    user = wh.user_by_key_hash(hash_key(key))
    if user is None:
        raise AuthError(401, "invalid API key")
    if user["status"] != "ACTIVE":
        raise AuthError(403, "account is not active")
    return user


class RateLimiter:
    """Sliding window per key. In memory and per process: use a shared store behind several workers."""

    def __init__(self, limit: int, window_s: float = 60.0, clock=time.monotonic):
        self.limit, self.window, self._clock = limit, window_s, clock
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, consume: bool = True) -> float | None:
        """None if allowed, otherwise the number of seconds to wait.

        Callers that need to validate an input before charging the quota can
        use ``consume=False`` and call ``hit`` after the operation succeeds.
        """
        now = self._clock()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(0.1, self.window - (now - q[0]))
            if consume:
                q.append(now)
            return None

    def hit(self, key: str) -> None:
        """Record one operation after it has passed validation."""
        now = self._clock()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            q.append(now)


def unsubscribe_token(secret: str, company_id: str) -> str:
    sig = hmac.new(secret.encode(), company_id.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{company_id}.{sig}"


def verify_unsubscribe(secret: str, token: str) -> str | None:
    if not secret or "." not in token:
        return None
    company_id, sig = token.rsplit(".", 1)
    expected = hmac.new(secret.encode(), company_id.encode(), hashlib.sha256).hexdigest()[:32]
    return company_id if hmac.compare_digest(sig, expected) else None

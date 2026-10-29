"""Retry with exponential backoff (1, 2, 4, 8, 16, 32, 60 s ...), max 10 attempts, with an ops alert after 5 failures."""
from __future__ import annotations

import logging
import time
from typing import Callable, TypeVar

log = logging.getLogger("domainguard.retry")
T = TypeVar("T")

BACKOFF = (1, 2, 4, 8, 16, 32, 60)
MAX_RETRIES = 10
ALERT_AFTER = 5


class RetriesExhausted(RuntimeError):
    def __init__(self, what: str, attempts: int, last: Exception):
        super().__init__(f"{what} failed after {attempts} attempts: {type(last).__name__}: {last}")
        self.attempts, self.last = attempts, last


def delay_for(attempt: int) -> float:
    """Delay before retry number `attempt` (1-based)."""
    return BACKOFF[min(attempt - 1, len(BACKOFF) - 1)]


def call_with_retry(fn: Callable[[], T], *, what: str, sleep=time.sleep, alert: Callable[[str], None] | None = None,
                    max_retries: int = MAX_RETRIES, retry_on: tuple = (Exception,)) -> T:
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except retry_on as e:
            if attempt == ALERT_AFTER and alert:
                alert(f"{what}: {ALERT_AFTER} consecutive failures ({type(e).__name__}: {e})")
            if attempt > max_retries:
                raise RetriesExhausted(what, attempt, e) from e
            wait = delay_for(attempt)
            log.warning("%s failed (attempt %d): %s; retrying in %ss", what, attempt, e, wait)
            sleep(wait)

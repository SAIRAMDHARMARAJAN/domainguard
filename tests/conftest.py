import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROWS = [  # matcher-level rows used by the v1 tests
    {"name": "abcbank", "aliases": ["abc bank"], "official_domains": ["abcbank.com", "abcbank.in"]},
    {"name": "paypal", "aliases": ["PayPal"], "official_domains": ["paypal.com"]},
    {"name": "ola", "aliases": [], "official_domains": ["olacabs.com"]},
]


@pytest.fixture
def wl():
    from domainguard.matcher import Watchlist
    return Watchlist.from_dicts(ROWS)


def cert(domains, seen=1761350000):
    return {"message_type": "certificate_update", "data": {"seen": seen, "leaf_cert": {"all_domains": domains}}}

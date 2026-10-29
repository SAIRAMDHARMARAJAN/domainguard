"""Chooses the warehouse. Production always means Snowflake; the in-memory double is refused unless a demo or test
explicitly sets DG_ALLOW_MEMORY_WAREHOUSE=1."""
from __future__ import annotations

import os

from .config import Settings


def make_warehouse(settings: Settings | None = None):
    from .memory_warehouse import MemoryWarehouse
    from .warehouse import SnowflakeWarehouse

    s = settings or Settings.from_env()
    if os.environ.get("DG_ALLOW_MEMORY_WAREHOUSE") == "1":
        return MemoryWarehouse()
    missing = s.missing_snowflake()
    if missing:
        raise RuntimeError("Snowflake is required. Missing: " + ", ".join(missing))
    return SnowflakeWarehouse(s)

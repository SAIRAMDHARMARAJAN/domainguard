"""All settings come from environment variables (12-factor). Nothing is hard-coded and nothing is read from files
except the optional .env that the CLI loads explicitly."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

LANGUAGES = ("English", "Hindi", "Malayalam", "Tamil", "Telugu", "Bengali", "Marathi")


def _bool(v: str | None, default: bool) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    # Snowflake (required for every warehouse operation; there is no SQLite fallback)
    sf_account: str = ""
    sf_user: str = ""
    sf_password: str = ""
    sf_warehouse: str = "DG_WH"
    sf_database: str = "DOMAINGUARD"
    sf_role: str = "DG_PIPELINE"
    sf_timeout_s: float = 30.0
    # CertStream / feeds / RDAP
    certstream_url: str = "ws://localhost:8080"
    openphish_url: str = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
    urlhaus_url: str = ""
    urlhaus_auth_key: str = ""
    rdap_min_interval_s: float = 1.0
    # ingestion
    stage_dir: str = "stage"
    state_dir: str = "state"
    flush_rows: int = 200
    flush_seconds: float = 60.0
    watchlist_ttl_s: float = 30.0
    # LLM (optional)
    openrouter_api_key: str = ""
    openrouter_models: tuple[str, ...] = ("meta-llama/llama-2-7b-chat:free", "mistralai/mistral-7b-instruct:free")
    llm_max_calls_per_run: int = 20
    # email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "alerts@domainguard.example.com"
    # API and web
    api_rate_limit_per_min: int = 60
    api_key_rate_limit_per_min: int = 1000
    web_domain: str = "http://127.0.0.1:8000"
    public_origin: str = ""          # the only origin allowed by CORS; empty = no CORS
    dispute_url: str = ""
    analyst_token: str = ""          # placeholder for dashboard / analyst access
    secret_key: str = ""             # signs unsubscribe links; required in production
    log_level: str = "INFO"
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls, env=None) -> "Settings":
        e = env if env is not None else os.environ
        g = lambda k, d="": e.get(k, d)
        models = tuple(m.strip() for m in g("OPENROUTER_MODELS", "").split(",") if m.strip()) or cls.openrouter_models
        return cls(
            sf_account=g("SNOWFLAKE_ACCOUNT"), sf_user=g("SNOWFLAKE_USER"), sf_password=g("SNOWFLAKE_PASSWORD"),
            sf_warehouse=g("SNOWFLAKE_WAREHOUSE", "DG_WH"), sf_database=g("SNOWFLAKE_DATABASE", "DOMAINGUARD"),
            sf_role=g("SNOWFLAKE_ROLE", "DG_PIPELINE"), sf_timeout_s=float(g("SNOWFLAKE_TIMEOUT_S", "30")),
            certstream_url=g("CERTSTREAM_URL", "ws://localhost:8080"),
            openphish_url=g("OPENPHISH_URL", cls.openphish_url), urlhaus_url=g("URLHAUS_URL"),
            urlhaus_auth_key=g("URLHAUS_AUTH_KEY"), rdap_min_interval_s=float(g("RDAP_MIN_INTERVAL_S", "1.0")),
            stage_dir=g("DG_STAGE_DIR", "stage"), state_dir=g("DG_STATE_DIR", "state"),
            flush_rows=int(g("DG_FLUSH_ROWS", "200")), flush_seconds=float(g("DG_FLUSH_SECONDS", "60")),
            watchlist_ttl_s=float(g("DG_WATCHLIST_TTL_S", "30")),
            openrouter_api_key=g("OPENROUTER_API_KEY"), openrouter_models=models,
            llm_max_calls_per_run=int(g("LLM_MAX_CALLS_PER_RUN", "20")),
            smtp_host=g("SMTP_HOST"), smtp_port=int(g("SMTP_PORT", "587")), smtp_user=g("SMTP_USER"),
            smtp_password=g("SMTP_PASSWORD"), smtp_from=g("SMTP_FROM", cls.smtp_from),
            api_rate_limit_per_min=int(g("API_RATE_LIMIT_PER_MIN", "60")),
            api_key_rate_limit_per_min=int(g("API_KEY_RATE_LIMIT_PER_MIN", "1000")),
            web_domain=g("WEB_DOMAIN", cls.web_domain), public_origin=g("PUBLIC_ORIGIN"),
            dispute_url=g("DG_DISPUTE_URL"), analyst_token=g("DG_ANALYST_TOKEN"), secret_key=g("DG_SECRET_KEY"),
            log_level=g("LOG_LEVEL", "INFO"),
        )

    def missing_snowflake(self) -> list[str]:
        return [n for n, v in (("SNOWFLAKE_ACCOUNT", self.sf_account), ("SNOWFLAKE_USER", self.sf_user),
                               ("SNOWFLAKE_PASSWORD", self.sf_password)) if not v]

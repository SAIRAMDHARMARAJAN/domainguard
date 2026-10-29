"""Environment check used by `cli check` and the setup script: settings present, Snowflake reachable, tables exist."""
from __future__ import annotations

REQUIRED_TABLES = [
    "REF.USERS", "REF.PROTECTED_DOMAINS", "BRONZE.CERTSTREAM_EVENTS", "BRONZE.BLOCKLIST_FEED", "BRONZE.RDAP_RESPONSES",
    "OPS.LOAD_LOG", "SILVER.PARSED_DOMAINS", "SILVER.CLEAN_BLOCKLIST", "SILVER.RDAP_AGE", "GOLD.DOMAIN_VERDICT",
    "GOLD.DOMAIN_BRIEFS", "GOLD.TAKEDOWN_DRAFTS", "OPS.EMAIL_LOG", "OPS.EMAIL_PREFERENCES", "OPS.EVALUATION_METRICS",
    "OPS.REGISTRATION_VERIFICATION", "SILVER.ANALYST_FEEDBACK",
]


def check_environment(settings, wh) -> dict:
    checks = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    missing = settings.missing_snowflake()
    add("snowflake settings", not missing, "missing: " + ", ".join(missing) if missing else "present")
    add("secret key (unsubscribe links)", bool(settings.secret_key), "" if settings.secret_key else "set DG_SECRET_KEY")
    add("smtp settings", bool(settings.smtp_host), "" if settings.smtp_host else "alerts disabled until SMTP_HOST is set")
    add("llm settings", bool(settings.openrouter_api_key), "template explanations only" if not settings.openrouter_api_key else "")
    if not missing:
        try:
            wh.active_protected_rows()
            add("snowflake connection", True)
            for t in REQUIRED_TABLES:
                try:
                    wh._rows(f"SELECT 1 FROM {t} LIMIT 1")  # type: ignore[attr-defined]
                    add(f"table {t}", True)
                except Exception as e:
                    add(f"table {t}", False, f"{type(e).__name__}: {str(e)[:120]}")
        except Exception as e:
            add("snowflake connection", False, f"{type(e).__name__}: {str(e)[:200]}")
    return {"ok": all(c["ok"] for c in checks if not c["check"].startswith(("llm", "smtp"))), "checks": checks}

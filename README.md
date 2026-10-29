# DomainGuard v7: Snowflake-only brand protection, company registration and email alerts

This is the complete system from `DOMAINGUARD_COMPLETE_PROMPT.md`. It replaces the SQLite-based v1 to v6 for production use
(those versions stay untouched in their own folders).

- **Storage:** Snowflake only (Bronze, Silver, Gold, REF, OPS). No SQLite. Production refuses to start without Snowflake.
- **Companies** self-register, verify their email, receive an API key, and manage their domains.
- **Email alerts** go to each company when a lookalike of its brand is detected (immediate, daily or weekly).
- **Public checker**, **company API**, **analyst dashboard**, **evaluation**, **takedown drafts with a signature**.

Read `UNDERSTANDING.md` for the full process, the decisions made, and the honest gaps. Start with the setup below.

## 1. What you need (checklist)

| Item | Why | Where to get it |
|---|---|---|
| Python 3.11+ | runtime | python.org |
| Docker (Docker Desktop) | runs your own CertStream server | docker.com |
| Snowflake trial account | all storage | signup.snowflake.com (note the account identifier) |
| SMTP account | sends alerts and verification emails | your mail provider (for Gmail: an app password) |
| OpenRouter key (optional) | LLM explanations; templates are used without it | openrouter.ai |

## 2. Setup, step by step

```bash
cd v7-snowflake-full
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

**2a. Snowflake.** In `.env` set `SNOWFLAKE_ACCOUNT` (for example `xy12345.ap-south-1.aws`), `SNOWFLAKE_USER` and
`SNOWFLAKE_PASSWORD` for a user that can create objects. Then create the objects (this needs an admin role):

```bash
python3 scripts/setup_snowflake.py --dry-run     # shows the 6 SQL files and their statement counts
SNOWFLAKE_SETUP_ROLE=ACCOUNTADMIN python3 scripts/setup_snowflake.py
```

Then give the pipeline its role and test the connection:

```bash
python3 -m domainguard.cli check                 # every line should say ok; fix anything marked FAILED
```

**2b. Secrets.** Generate a signing key (unsubscribe links need it) and an analyst token for the dashboard:

```bash
python3 -c "import secrets;print(secrets.token_urlsafe(48))"   # paste into DG_SECRET_KEY
python3 -c "import secrets;print(secrets.token_urlsafe(24))"   # paste into DG_ANALYST_TOKEN
```

**2c. Email.** Set `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`. SES is not built in v7.

**2d. CertStream (optional for a first run).** `scripts/certstream.sh start` then `scripts/certstream.sh check`.
It is the same one-command setup as v1 (the public server is unreliable).

**2e. Import your existing brands (one time).** Companies from the old `data/watchlist.json` become ACTIVE companies
with email notifications off until they opt in:

```bash
python3 scripts/migrate_from_json.py data/watchlist.json --dry-run   # look first
python3 scripts/migrate_from_json.py data/watchlist.json
```

## 3. Run it

```bash
python3 -m domainguard.cli live                  # stream + feeds + RDAP + load + score + notify, until Ctrl+C
# or run the steps yourself, e.g. from cron every few minutes:
python3 -m domainguard.cli load
python3 -m domainguard.cli score
python3 -m domainguard.cli briefs --languages English,Hindi
python3 -m domainguard.cli notify
python3 -m domainguard.cli evaluate
```

Public API and company endpoints:

```bash
uvicorn domainguard.api:build_default_app --factory --port 8000    # needs the environment above
```

Analyst dashboard (open http://localhost:8501; enter DG_ANALYST_TOKEN):

```bash
streamlit run domainguard/dashboard.py
```

## 4. Offline demo (no Snowflake, no network, no SMTP)

```bash
python3 scripts/demo.py
```

The demo uses an in-memory test double that exists only for tests and demos. The CLI and API refuse it unless
`DG_ALLOW_MEMORY_WAREHOUSE=1` is set, and the demo sets that itself.

## 5. Tests

```bash
python3 -m pytest -q        # 173 tests, offline (fakes for Snowflake, SMTP, OpenRouter, the network)
```

What the tests prove and what they do not: see UNDERSTANDING.md, section 9.

## 6. Layout

```
domainguard/   config, warehouse (Snowflake + test double), watchlist, loader, pipeline (scoring job), llm, worker,
               registration, auth, notifier, takedown, evaluation, api, dashboard, ingest, cli, + v1 modules
sql/           01_setup 02_bronze 03_silver 04_gold 05_ref_and_ops 06_roles_and_maintenance
templates/     threat_alert.html, dispute_notification.html
web/           index.html (checker), register.html, style.css, app.js, register.js
scripts/       demo.py, setup_snowflake.py, migrate_from_json.py, certstream.sh
data/          sample events, blocklist, RDAP, watchlist.json (used only by the migration and the demo)
tests/         one file per area
```

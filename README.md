# DomainGuard

DomainGuard is a Snowflake-backed brand-protection system for detecting
lookalike domains, investigating impersonation campaigns, and preparing
evidence-backed takedown cases.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env` with your own Snowflake, SMTP, and optional reputation/LLM
credentials. Never commit `.env`; only `.env.example` is intended for source
control.

Create the Snowflake objects and verify the configuration:

```bash
python scripts/setup_snowflake.py --dry-run
python -m domainguard.cli check
```

Run the API and analyst dashboard from this directory:

```bash
uvicorn domainguard.api:build_default_app --factory --host 127.0.0.1 --port 8000
streamlit run domainguard/dashboard.py --server.port 8502
```

See [UNDERSTANDING.md](UNDERSTANDING.md) for the architecture, data flow,
operational commands, and security considerations.

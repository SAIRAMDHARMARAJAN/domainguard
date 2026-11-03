# DomainGuard v7: complete guide (Snowflake, registration, email)

This guide explains the whole process, why each part is built the way it is, what the specification asked for that was
changed (and why), what was tested and what was not, and how to answer the doubts that come up. Read sections 1 to 3
once. Use the rest as reference.

---

## 1. The process, end to end

```
 Certificate Transparency (your self-hosted CertStream)      OpenPhish / URLhaus          RDAP (rdap.org)
              │                                                     │                         │
              ▼                                                     ▼                         ▼
   Collector: keep names that resemble a protected brand      Feed collector: new domains only   RDAP collector: age
              │  (watchlist loaded from Snowflake every 30 s)        │                         │  (1 request/second)
              └──────────────────────────────┬──────────────────────┴─────────────────────────┘
                                             ▼
                              Stage files on disk: gzip JSONL + SHA-256 manifest   (durable hand-off)
                                             │
                         Loader: verify checksum → skip if OPS.LOAD_LOG says SUCCESS → load → log
                                             │   (retry with backoff 1…60 s, alert after 5 failures, max 10 retries)
                                             ▼
                              Snowflake Bronze  (raw, with source file and load time)
                                             │
                                             ▼  views and dynamic tables, refresh every 15 min
                              Snowflake Silver  (first/last seen, earliest listing, registration date)
                                             │
                                             ▼  scoring job: the 7-factor rules from v1, per company
                              Snowflake Gold    (verdicts, briefs, takedown drafts)  +  OPS (email log, metrics)
                                 │                 │                          │
                                 ▼                 ▼                          ▼
                       Explanation worker     Notifier (email)          FastAPI + web page
                       (LLM or template)      alerts, digests           checker, company API
                                                                             │
                                                                             ▼
                                                                    Streamlit analyst dashboard
                                                                    (review, takedown approval, metrics)
```

What happens to one domain, `paypa1-secure-login.xyz`, for a PayPal customer:

1. A certificate for it is published. Your CertStream server streams it within seconds.
2. The collector sees `paypa1` folds to `paypal` (a look-alike), so it is kept. Unrelated names are dropped in memory.
3. The stage file is written, with its checksum in the manifest.
4. The loader checks the checksum, loads the rows into Bronze in one transaction, and logs the file in `OPS.LOAD_LOG`.
5. RDAP says the domain was registered 2 hours ago (age points 20).
6. The scoring job scores it against PayPal's brands only, because the domain resembles PayPal. Score: 88, HIGH_RISK.
   `FIRST_FLAGGED_AT` is set once, now.
7. The notifier emails PayPal's security contact, with the defanged domain and reasons. The link goes to our checker,
   not to the suspicious site. The email is logged in `OPS.EMAIL_LOG`, so the same domain is not alerted twice.
8. The explanation worker writes a plain-language brief (LLM if configured, otherwise the template).
9. A visitor pastes the link into the checker and sees "High risk" with the reasons. No company is named.
10. An analyst opens the dashboard, confirms the threat, drafts an abuse report, and a named person approves it with the
    signature sentence. The text is exported for the provider's own form. Nothing is sent by the software.
11. Later, the feed lists the domain. Lead time = listing time minus first flag, reported on the evaluation page.

### Who calls what

| Command | What it does | Run it |
|---|---|---|
| `cli live` | streams certificates, pulls feeds, looks up RDAP, and loads, scores and notifies on schedules | as a long-running service |
| `cli load` | verifies and loads staged files into Bronze | every 1–5 minutes, or by `live` |
| `cli score` | scoring job (Silver to Gold) and prints the newly flagged domains | every 1–5 minutes, or by `live` |
| `cli briefs` | explanations for flagged domains, capped per run | every 5 minutes |
| `cli notify` | immediate alerts for recent detections, and due digests | every few minutes |
| `cli evaluate` | precision, recall, lead time, hours saved, stored per company per day | daily |
| `cli check` | checks settings and every required table | after setup, and when something looks wrong |

---

## 2. The decisions, and why

| Decision | Reason |
|---|---|
| **Snowflake is the only storage at runtime.** The factory refuses to start without Snowflake. | The specification says so explicitly. |
| **The in-memory warehouse exists only for tests and the demo.** It is named `MemoryWarehouse`, and `DG_ALLOW_MEMORY_WAREHOUSE=1` is required to use it. | Offline tests need a stand-in. Making it impossible to use in production keeps it from becoming a silent fallback. |
| **Every data access goes through one interface** (`warehouse.py`), with two implementations. | The same logic runs against both, so the tests check the real pipeline, API and emails. The Snowflake side is checked by its statements (section 9). |
| **Bind parameters everywhere.** There is a test that an injection attempt stays inside a parameter. | SQL injection, as the specification requires. |
| **Scores are unchanged from v1.** The pipeline reuses the same scoring code. | "Scoring job produces identical scores to Stage 1 for the same inputs." The v1 worked examples are tests here too. |
| **One watchlist per company, and each domain is scored only for the companies whose brands it resembles.** | Without this, an alert could tell company A about a domain that only imitates company B. |
| **Verdicts are keyed by (domain, company).** | Two companies can both be targeted by the same name. The specification's single-column key would overwrite one with the other. |
| **Brand names are the registrable label** (for example `abcbank` from `abcbank.com`), with aliases on top. | Matching on full names like `company_id::domain` would never match a domain. |
| **First flag is kept once** (`COALESCE` in SQL, a check in Python). | Specification rule. Makes lead time meaningful. |
| **Unknown age scores 10 points**, never a guess. | v1 rule; the public checker adds a caution note for lookalikes. |
| **Alerts only for detections flagged in the last hour** (immediate mode). | Specification: "if first_flagged_at is recent (< 1 hour), send email". Stops old detections flooding inboxes after a restart. Older detections are not lost: they remain in the inbox and digests. |
| **Each (company, domain) is alerted once.** | Prevents repeats. The email log is the record. |
| **Digests** for DAILY and WEEKLY frequency. | Specification option; implemented. |
| **Unsubscribe links are signed with HMAC** (`DG_SECRET_KEY`). The API refuses to start without the key. | A link cannot be forged to switch someone off; a missing key cannot be silently replaced. |
| **Verification OTPs expire after 10 minutes and work once.** Only their SHA-256 hash is stored, with a five-attempt limit. | Email links are not used because OTP entry avoids link forwarding and scanner issues. |
| **API keys are stored as SHA-256 hashes** and shown once over the HTTPS OTP response. They are never sent by email or stored in the database. | Email is not a secure channel for bearer secrets, even when the message body is encrypted by the provider. |
| **Dispute and takedown drafts never send.** The takedown module imports no mail or network library; a test checks this. | Specification: "no automatic sending", "human approval". |
| **Approval needs the exact sentence** "I confirm this is accurate and I approve sending", a named analyst, and an email. | Specification: "Signature required". |
| **The explanation worker only sees facts.** Output is validated: length, no links, no code, numbers only from the facts. | Specification limits: summary ≤ 150, reasons ≤ 100, advice ≤ 100. |
| **Retries follow the specification:** 1, 2, 4, 8, 16, 32, 60 seconds, at most 10 retries; ops alert after 5 failures. | Specification's retry policy. |
| **Stage files stay on disk until loaded.** A FAILED load is retried on the next run. | "If Snowflake is unavailable, batch files are queued locally. No data loss." |
| **The watchlist keeps working if Snowflake is down**: in memory and in a cache file. | Specification: "If Snowflake is unavailable, use last known cache". |
| **Least-privilege roles:** pipeline, API, analyst and admin. | Specification's role model, with the one change below. |

---

## 3. Setup, step by step

The full checklist is in `README.md`, section 2. The short version:

1. **Snowflake trial.** Sign up, note the account identifier, and create a user with a password (for example
   `DG_PIPELINE`). Put the values in `.env`.
2. **Create the objects.** `python3 scripts/setup_snowflake.py --dry-run`, then run it with `SNOWFLAKE_SETUP_ROLE=ACCOUNTADMIN`.
   It runs `sql/01` to `sql/06` in order. Every statement is safe to rerun.
3. **Check.** `python3 -m domainguard.cli check`. Every line should say ok. If a table line fails, the message shows the
   error; fix it and rerun `setup_snowflake.py`.
4. **Secrets.** Generate `DG_SECRET_KEY` and `DG_ANALYST_TOKEN` (commands in the README). Never commit `.env`.
5. **Email.** Fill `SMTP_*`. Send a test: register a company with your own address, click the link, and check the key email.
6. **OpenRouter (optional).** Set `OPENROUTER_API_KEY`. Check that the two models in `OPENROUTER_MODELS` are still available
   on openrouter.ai. Free models change, so keep a fallback list.
7. **Import the brands** with `scripts/migrate_from_json.py`, or let companies self-register.
8. **Run** `cli live` as a service, or schedule the individual commands.

### Running it as a service (example)

Use your platform's service manager (launchd on macOS, systemd on Linux). The command is
`python3 -m domainguard.cli live` from the project folder, with `.env` present. Restart it on failure. Put the API behind
a TLS proxy (for example nginx or Cloudflare) and run it with
`uvicorn domainguard.api:build_default_app --factory --host 127.0.0.1 --port 8000`.

---

## 4. The company journey (registration to alerts)

1. **Register** at `/register`: company name, email, optional contact, one or more domains, optional brand names.
   The email is normalized and syntax-checked with `email-validator`. In production, each domain must also have
   resolvable nameservers and WHOIS registration evidence using `dnspython` and `python-whois`; this is an
   ownership/infrastructure check, not a guarantee that the domain is safe. Aliases are suggested from the domain
   and the name if you leave them out. Up to 20 domains per company.
2. **Verify.** A six-digit OTP is emailed. Entering it at `/verify-otp` activates the account and returns the API key once over HTTPS. The key must be copied into a secure secret manager immediately.
3. **Manage** domains and alert settings with the API key (`/company/...`). Rotating the key invalidates the old one.
4. **Receive alerts** at the notification address (default: the account email). Settings: on or off, immediate or daily or
   weekly, minimum score (default 70). Every alert has an unsubscribe link.
5. **Use the API** for your own tools: `GET /analyst/inbox?hours=24&min_score=70` with `Authorization: Bearer <key>`
   returns only your company's detections.

---

## 5. The specification, and what changed

| Specification said | v7 does | Why |
|---|---|---|
| `REF.PROTECTED_DOMAINS` and `GOLD.DOMAIN_VERDICT` keyed by domain | keyed by (domain, company) | A name can imitate more than one company's brand |
| `DG_API` read-only on Gold | read Gold, plus write on REF and OPS for registration and settings | `/register`, `/verify`, and settings must write. Nothing else is granted |
| Roles described as `GRANT ALL` on schemas | separate, least-privilege grants, with FUTURE grants | Safer, and works for tables created later |
| SQL file numbers `01`, `02`, `03_ops`, `05`, `06_ref` | `01` setup, `02` bronze, `03` silver, `04` gold, `05` ref and ops, `06` roles and retention | Keeps each file after the objects it refers to |
| Verification with OTP | six-digit code, valid 10 minutes, five attempts, works once | The code is entered on the registration page; no verification link is generated |
| Email alert links to `/check?domain=<domain>` | link carries the defanged domain | The raw name never appears in the email; the link still opens our checker |
| `precision = (confirmed + blocklisted) / flagged` | counted as a union (a domain both confirmed and listed counts once) | The plain sum can exceed 1.0. The score-only precision is also reported |
| `recall = (flagged_before + blocklisted_matches) / blocklisted_lookalikes` | `flagged_before_listing / blocklisted_lookalikes` | The specification's formula counts blocklisted matches twice |
| Analyst hours: minutes per check, default 5 | default 5, adjustable on the page | As specified |
| Dashboard reports: lead-time trend, attackers by registrar | detections per day, precision by brand, FP rate | Registrar data is not collected (see section 8) |
| Snowflake PUT and COPY INTO from `@~/domainguard_stage/` | PUT to `@BRONZE.DG_STAGE` and COPY INTO when the adapter supports it (production); row inserts in one transaction otherwise | COPY is faster; both are idempotent through the load log |
| Email via SMTP or SES | SMTP | SES is not built |
| `DG_API` public checker shows `matched_brand` | yes, the brand label | The specification's example shows it; no company is named |

---

## 6. Snowflake objects

| Schema | Objects | Written by | Read by |
|---|---|---|---|
| REF | `USERS`, `PROTECTED_DOMAINS` | registration, migration, admin | watchlist, API, dashboard |
| BRONZE | `CERTSTREAM_EVENTS`, `BLOCKLIST_FEED`, `RDAP_RESPONSES` (transient, no time travel) | loader | Silver |
| SILVER | `PARSED_DOMAINS`, `CLEAN_BLOCKLIST`, `RDAP_AGE` (dynamic tables); `SCORE_BREAKDOWN`, `ANALYST_FEEDBACK` | Silver refresh; scoring job; analysts (append only) | scoring job, evaluation |
| GOLD | `DOMAIN_VERDICT`, `DOMAIN_BRIEFS`, `TAKEDOWN_DRAFTS`; views `THREAT_INBOX`, `LEAD_TIME` | scoring job, worker, dashboard | API, dashboard |
| OPS | `LOAD_LOG`, `EMAIL_LOG`, `EMAIL_PREFERENCES`, `REGISTRATION_VERIFICATION`, `EVALUATION_METRICS` | loader, notifier, registration, evaluation | notifier, registration |

Retention: a daily task purges Bronze after 30 days (RDAP: 90). The load log is never purged, so a file is never loaded twice.

---

## 7. The API (summary)

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | status and time |
| `POST /check` | none (per-IP limit 60/min) | verdict for a link or domain |
| `POST /scan-message` | none | scores each link (up to 10) and lists the tactics. Text up to 10,000 characters |
| `POST /register` | none | starts registration; returns 202 `PENDING` |
| `GET /verify/{token}` | the token itself | activates; emails the API key |
| `GET /unsubscribe/{token}` | the signed token | turns alerts off |
| `POST /dispute` | none | acknowledges a dispute by email; an analyst reviews it |
| `GET /analyst/inbox` | Bearer key (per-key limit 1000/min) | the company's own detections |
| `GET /company/settings`, `PUT /company/settings` | Bearer key | read and update |
| `POST /company/domains/add`, `DELETE /company/domains/{domain}` | Bearer key | manage protected domains |
| `POST /company/api-key/rotate` | Bearer key | new key, shown once |

Input limits: link or domain 2,048 characters; message 10,000 characters; company name 2 to 120. Responses carry
`Content-Security-Policy`, `nosniff`, `no-referrer`, and `no-store`. `/docs` is off. CORS allows only `PUBLIC_ORIGIN`.

---

## 8. Honest gaps (not built, or built differently)

- **Real authentication for analysts:** the dashboard uses a shared token. Put SSO or a proxy with identity in front before
  any shared deployment. Analysts' names are typed in, not verified.
- **DNS verification** of domain ownership: not built. `verified` stays false. The specification lists it as optional.
- **Registrar and attacker reporting:** not built. The RDAP payload is reduced to remove personal data, and registrar
  names are not kept. Adding it means deciding whether registrar data counts as personal data first.
- **Dashboard:** the lead-time trend chart and editing email settings in the dashboard are not built (the settings are
  read-only there; use the company settings endpoint).
- **Full Public Suffix List:** the built-in list is small. Shared-hosting suffixes such as `vercel.app` are not treated as
  suffixes, so those domains inherit the hosting site's age.
- **SES** email: not built. SMTP only.
- **A dispute workflow:** `/dispute` sends an acknowledgement. The review happens by hand.
- **Scale:** the scoring job rescores every candidate on each run. Fine for thousands; for millions, add an incremental filter.
- **Rate limits** are in memory, per process. Several workers need a shared store.
- **Two companies with the same domain** get separate verdicts and separate alerts, which is intended, but it means more
  alerts for the same lookalike.

---

**Snowflake does not enforce primary keys.** The `PRIMARY KEY` clauses in `sql/` document the intent. The MERGE
statements in `warehouse.py` keep one row per key, but a bug or a manual insert could create a duplicate. Check with
`SELECT DOMAIN, COMPANY_ID, COUNT(*) FROM GOLD.DOMAIN_VERDICT GROUP BY 1, 2 HAVING COUNT(*) > 1`.

## 9. What was verified, and how

| Area | How | Result |
|---|---|---|
| Scoring rules and worked examples (v1) | `test_normalize_matcher_scoring.py`, `test_watchlist_loader_pipeline.py` | pass; `paypa1-secure-login.xyz` = 78 with unknown age, 44 for the typo domain at 2 h |
| Warehouse contract | both implementations provide every method; first-flag rule; idempotent loads | pass |
| Snowflake statements | recording connection: bind parameters, transactions, rollback, injection stays in parameters, COPY options | pass; **Snowflake itself has not accepted these statements** |
| Loader | checksums, manifest, idempotency, outage retry, alert after 5, FAILED then SUCCESS | pass |
| Watchlist | per-company split, TTL reload, last known list kept on failure, cache file at startup | pass |
| Explanations | limits, link and code rejection, invented numbers rejected, fallback order, call cap | pass; **the OpenRouter call has not run** |
| Registration and auth | validation, pending, verify once, expiry, key hashing, rotation, bearer rules, rate limit, signed unsubscribe | pass |
| Notifications | defanged content, no raw name in email, HTML escaping, opt-out, threshold, 1-hour rule, once per domain, failures logged, digests | pass; **SMTP has not sent a message in this build** |
| Takedown | named analyst, exact signature, export only when approved, no sending imports | pass |
| Evaluation | union precision, recall, quartiles, hours saved, weight comparison (no adoption), persistence | pass |
| API | every endpoint, auth scoping, 422, 401, 403, 429, headers, CORS, SQL-injection text, no network imports | 28 tests pass |
| Dashboard | Streamlit `AppTest`: every page renders, token gate, label needs a name | pass; not clicked in a browser |
| Ingestion and CLI | replay, feeds, RDAP, load, score, health file, cache during outage, `cli check`, demo | pass |
| **Live ingestion** | your self-hosted CertStream server, 25 seconds, memory warehouse | 60,594 events, 2,088 candidates, 40 stage files, all loaded with checksums verified |

Total: **173 automated tests, offline**. Command: `python3 -m pytest -q`.

**Not run in this build:** a real Snowflake account (the SQL and the COPY path), SMTP delivery, the OpenRouter LLM, a browser
session against the live API, and the full live pipeline with real companies and Snowflake (the live check used a memory
warehouse and a broad test watchlist).

---

## 10. Frequently asked doubts

**Why is there a memory warehouse if Snowflake is required?** Tests and the demo need a stand-in that runs offline. It is
named as a test double, and the CLI and API refuse it unless an environment variable is set. Production never uses it.

**Will the same domain alert two companies?** Only if both companies' brands match it. Each gets its own verdict and
its own alert. This is intended.

**Why did a detection not produce an email?** Check, in order: is the company active; are email notifications on; is the
score at or above the threshold; was the detection flagged in the last hour (immediate mode); was it already alerted.
`OPS.EMAIL_LOG` shows what was sent, and `cli notify` prints the counts.

**Can DomainGuard send an abuse report?** No. Nothing in the code sends one. An analyst exports the text and submits it
through the provider's own form. Then they can record "SENT" manually.

**What if Snowflake is down for a day?** Stage files stay on disk. The loader retries with backoff, and ops is alerted
after five failures. The watchlist keeps the last known list. When Snowflake returns, the next load catches up, and
nothing is loaded twice.

**Is the first-flag time reliable for lead time?** It is the time this system first flagged the domain. Lead time is only
as precise as how often `score` runs, so run it every minute or two for useful numbers.

**Why do alerts show the defanged domain but the export shows the real one?** The provider needs the real name to act. The
draft and the email show the defanged form, so nothing clickable is produced by accident. The export is a plain-text
block for a human to copy.

**How do I rotate a key that leaked?** The company calls `POST /company/api-key/rotate` with the old key. The old key stops
working immediately. An admin can also issue a key from the dashboard's Admin page.

**What if the explanation model says something wrong but in valid form?** The validator checks form, not truth. The brief
is a convenience. The evidence list is shown beside it, and the analyst decides.

**Why are two free models named, and what if they are gone?** The specification names them. Free models change. If both
fail, the template is used, so nothing breaks. Update `OPENROUTER_MODELS` when they change.

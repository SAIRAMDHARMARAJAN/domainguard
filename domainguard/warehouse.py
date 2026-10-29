"""The data-access contract. Everything in DomainGuard reads and writes through this interface.

  * SnowflakeWarehouse  - the real implementation (snowflake-connector-python). The only runtime storage.
  * MemoryWarehouse     - a TEST DOUBLE in memory (domainguard/memory_warehouse.py). It exists so the logic can be
                          tested offline. It is never used as storage, and the CLI refuses to run without Snowflake.

Each method is one unit of work. Multi-row writes run inside BEGIN / COMMIT so a failure leaves no partial data.
Every SQL statement uses bind parameters (%s); no values are ever concatenated into SQL.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

FLAGGED = ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS")
FEEDBACK_LABELS = ("CONFIRMED_THREAT", "FALSE_POSITIVE")
TAKEDOWN_STATUSES = ("DRAFT", "APPROVED", "REJECTED", "EXPORTED", "SENT")
TS = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'"  # format of the ISO-8601 'Z' strings DomainGuard uses


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return uuid.uuid4().hex


class Warehouse:
    """Interface. Methods raise NotImplementedError here; the two implementations provide them."""

    # reference: watchlist, users, protected domains, verification
    def active_protected_rows(self) -> list[dict]: raise NotImplementedError
    def get_user(self, company_id: str) -> dict | None: raise NotImplementedError
    def get_user_by_email(self, email: str) -> dict | None: raise NotImplementedError
    def user_by_key_hash(self, key_hash: str) -> dict | None: raise NotImplementedError
    def create_user(self, user: dict) -> None: raise NotImplementedError
    def update_user(self, company_id: str, fields: dict) -> None: raise NotImplementedError
    def list_users(self, status: str | None = None) -> list[dict]: raise NotImplementedError
    def upsert_protected(self, row: dict) -> None: raise NotImplementedError
    def protected_for(self, company_id: str, include_removed: bool = False) -> list[dict]: raise NotImplementedError
    def remove_protected(self, company_id: str, domain: str) -> None: raise NotImplementedError
    def put_verification(self, row: dict) -> None: raise NotImplementedError
    def get_verification(self, token_hash: str) -> dict | None: raise NotImplementedError
    def update_verification(self, token_hash: str, fields: dict) -> None: raise NotImplementedError

    # bronze and load log
    def write_bronze(self, source: str, rows: list[dict], source_file: str) -> int: raise NotImplementedError
    # SnowflakeWarehouse also offers copy_file(source, local_path, file_name) for the PUT + COPY INTO path
    def loaded_file(self, file_name: str) -> dict | None: raise NotImplementedError
    def log_load(self, entry: dict) -> None: raise NotImplementedError
    def load_log(self) -> list[dict]: raise NotImplementedError
    def put_metrics(self, row: dict) -> None: raise NotImplementedError

    # silver and gold
    def candidates(self) -> list[dict]: raise NotImplementedError
    def blocklist_index(self) -> dict[str, dict]: raise NotImplementedError
    def rdap_index(self) -> dict[str, str]: raise NotImplementedError
    def write_score(self, verdict: dict) -> dict: raise NotImplementedError
    def get_verdict(self, domain: str, company_id: str | None = None) -> dict | None: raise NotImplementedError
    def verdicts(self, company_id: str | None = None) -> list[dict]: raise NotImplementedError
    def inbox(self, company_id: str | None = None, min_score: int = 0, since: str | None = None,
              limit: int = 50) -> list[dict]: raise NotImplementedError
    def add_feedback(self, row: dict) -> None: raise NotImplementedError
    def feedback_history(self, domain: str, company_id: str | None = None) -> list[dict]: raise NotImplementedError
    def put_brief(self, brief: dict) -> None: raise NotImplementedError
    def get_brief(self, domain: str, company_id: str, language: str) -> dict | None: raise NotImplementedError
    def add_takedown(self, row: dict) -> None: raise NotImplementedError
    def get_takedown(self, draft_id: str) -> dict | None: raise NotImplementedError
    def update_takedown(self, draft_id: str, fields: dict) -> None: raise NotImplementedError
    def list_takedowns(self, company_id: str | None = None, status: str | None = None,
                       domain: str | None = None) -> list[dict]: raise NotImplementedError
    def log_email(self, row: dict) -> None: raise NotImplementedError
    def email_log(self, company_id: str | None = None) -> list[dict]: raise NotImplementedError
    def alert_sent(self, company_id: str, domain: str) -> bool: raise NotImplementedError
    def get_prefs(self, company_id: str) -> dict: raise NotImplementedError
    def set_prefs(self, company_id: str, fields: dict) -> None: raise NotImplementedError


# --------------------------------------------------------------------------------------------------------------
class SnowflakeWarehouse(Warehouse):
    """Snowflake implementation. Connection is opened lazily and re-opened after a failure.

    NOT RUN AGAINST A REAL ACCOUNT IN THIS BUILD. The SQL follows the specification; run sql/01..07 first and
    expect small fixes on first use. Tests check the statements and parameters with a recording connection.
    """

    def __init__(self, settings=None, connect=None):
        self._settings = settings
        self._connect = connect
        self._conn = None

    # --- connection -----------------------------------------------------------------------------------
    def _connection(self):
        if self._conn is None:
            if self._connect is not None:
                self._conn = self._connect()
            else:
                try:
                    import snowflake.connector  # type: ignore
                except ImportError as e:  # pragma: no cover
                    raise RuntimeError("pip install snowflake-connector-python") from e
                s = self._settings
                missing = s.missing_snowflake()
                if missing:
                    raise RuntimeError("missing environment variables: " + ", ".join(missing))
                self._conn = snowflake.connector.connect(
                    account=s.sf_account, user=s.sf_user, password=s.sf_password, role=s.sf_role,
                    warehouse=s.sf_warehouse, database=s.sf_database, login_timeout=int(s.sf_timeout_s),
                    network_timeout=int(s.sf_timeout_s), client_session_keep_alive=False)
        return self._conn

    def reset(self) -> None:
        """Drop the connection so the next call reconnects (used by the retry layer after an error)."""
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def _rows(self, sql: str, params=()) -> list[tuple]:
        cur = self._connection().cursor()
        try:
            cur.execute(sql, tuple(params))
            return cur.fetchall()
        finally:
            cur.close()

    def _run(self, sql: str, params=()) -> None:
        self._rows(sql, params)

    def _tx(self, statements: list[tuple[str, tuple]]) -> None:
        """Run several statements atomically."""
        cur = self._connection().cursor()
        try:
            cur.execute("BEGIN")
            for sql, params in statements:
                cur.execute(sql, tuple(params))
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    @staticmethod
    def _dict(cols: list[str], row) -> dict:
        return {c.lower(): v for c, v in zip(cols, row)}

    @staticmethod
    def _j(v):
        return json.dumps(v, ensure_ascii=False) if v is not None else None

    @staticmethod
    def _unj(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except ValueError:
                return v
        return v

    # --- reference ----------------------------------------------------------------------------------------
    def active_protected_rows(self) -> list[dict]:
        sql = ("SELECT p.COMPANY_ID, p.DOMAIN, p.BRAND_ALIASES, p.OFFICIAL_DOMAIN_1, p.OFFICIAL_DOMAIN_2, "
               "p.OFFICIAL_DOMAIN_3, p.VERIFIED FROM REF.PROTECTED_DOMAINS p JOIN REF.USERS u "
               "ON u.COMPANY_ID = p.COMPANY_ID WHERE u.STATUS = 'ACTIVE' AND p.STATUS = 'ACTIVE' ORDER BY p.COMPANY_ID, p.DOMAIN")
        out = []
        for r in self._rows(sql):
            out.append({"company_id": r[0], "domain": r[1],
                        "brand_aliases": [a.strip() for a in (r[2] or "").split(",") if a.strip()],
                        "official_domains": [d for d in (r[3], r[4], r[5]) if d], "verified": bool(r[6])})
        return out

    _USER_COLS = ["COMPANY_ID", "NAME", "EMAIL", "CONTACT_PERSON", "CREATED_AT", "STATUS", "API_KEY_HASH",
                  "API_KEY_CREATED_AT", "DISPUTE_CONTACT", "EMAIL_NOTIFICATIONS", "NOTIFICATION_EMAIL", "LAST_LOGIN_AT"]
    _USER_SQL = "SELECT " + ", ".join(_USER_COLS) + " FROM REF.USERS "

    def _user(self, r) -> dict:
        d = self._dict(self._USER_COLS, r)
        d["email_notifications"] = bool(d["email_notifications"])
        return d

    def get_user(self, company_id):
        r = self._rows(self._USER_SQL + "WHERE COMPANY_ID = %s", (company_id,))
        return self._user(r[0]) if r else None

    def get_user_by_email(self, email):
        r = self._rows(self._USER_SQL + "WHERE LOWER(EMAIL) = LOWER(%s)", (email,))
        return self._user(r[0]) if r else None

    def user_by_key_hash(self, key_hash):
        r = self._rows(self._USER_SQL + "WHERE API_KEY_HASH = %s", (key_hash,))
        return self._user(r[0]) if r else None

    def create_user(self, u):
        self._run("INSERT INTO REF.USERS (COMPANY_ID, NAME, EMAIL, CONTACT_PERSON, STATUS, EMAIL_NOTIFICATIONS, "
                  "NOTIFICATION_EMAIL, CREATED_AT) SELECT %s, %s, %s, %s, %s, %s, %s, SYSDATE()",
                  (u["company_id"], u["name"], u["email"], u.get("contact_person"), u.get("status", "PENDING"),
                   bool(u.get("email_notifications", True)), u.get("notification_email")))

    _USER_UPDATABLE = {"name", "contact_person", "status", "api_key_hash", "api_key_created_at", "dispute_contact",
                       "email_notifications", "notification_email", "last_login_at"}

    def update_user(self, company_id, fields):
        bad = set(fields) - self._USER_UPDATABLE
        if bad:
            raise ValueError(f"cannot update {sorted(bad)}")
        sets = ", ".join(f"{k.upper()} = %s" for k in fields)
        self._run(f"UPDATE REF.USERS SET {sets} WHERE COMPANY_ID = %s", (*fields.values(), company_id))

    def list_users(self, status=None):
        if status:
            return [self._user(r) for r in self._rows(self._USER_SQL + "WHERE STATUS = %s ORDER BY CREATED_AT", (status,))]
        return [self._user(r) for r in self._rows(self._USER_SQL + "ORDER BY CREATED_AT")]

    def upsert_protected(self, row):
        self._run(
            "MERGE INTO REF.PROTECTED_DOMAINS t USING (SELECT %s AS COMPANY_ID, %s AS DOMAIN, %s AS BRAND_ALIASES, "
            "%s AS D1, %s AS D2, %s AS D3) s ON t.COMPANY_ID = s.COMPANY_ID AND t.DOMAIN = s.DOMAIN "
            "WHEN MATCHED THEN UPDATE SET BRAND_ALIASES = s.BRAND_ALIASES, OFFICIAL_DOMAIN_1 = s.D1, "
            "OFFICIAL_DOMAIN_2 = s.D2, OFFICIAL_DOMAIN_3 = s.D3, STATUS = 'ACTIVE' "
            "WHEN NOT MATCHED THEN INSERT (COMPANY_ID, DOMAIN, BRAND_ALIASES, OFFICIAL_DOMAIN_1, OFFICIAL_DOMAIN_2, "
            "OFFICIAL_DOMAIN_3, ADDED_AT, VERIFIED, STATUS) VALUES (s.COMPANY_ID, s.DOMAIN, s.BRAND_ALIASES, s.D1, s.D2, "
            "s.D3, SYSDATE(), FALSE, 'ACTIVE')",
            (row["company_id"], row["domain"], ",".join(row.get("brand_aliases", [])),
             *(list(row.get("official_domains", [])) + [None, None, None])[:3]))

    def protected_for(self, company_id, include_removed=False):
        sql = ("SELECT COMPANY_ID, DOMAIN, BRAND_ALIASES, OFFICIAL_DOMAIN_1, OFFICIAL_DOMAIN_2, OFFICIAL_DOMAIN_3, "
               "VERIFIED, STATUS FROM REF.PROTECTED_DOMAINS WHERE COMPANY_ID = %s")
        if not include_removed:
            sql += " AND STATUS = 'ACTIVE'"
        out = []
        for r in self._rows(sql + " ORDER BY DOMAIN", (company_id,)):
            out.append({"company_id": r[0], "domain": r[1],
                        "brand_aliases": [a.strip() for a in (r[2] or "").split(",") if a.strip()],
                        "official_domains": [d for d in (r[3], r[4], r[5]) if d], "verified": bool(r[6]), "status": r[7]})
        return out

    def remove_protected(self, company_id: str, domain: str) -> None:
        self._run("UPDATE REF.PROTECTED_DOMAINS SET STATUS = 'REMOVED' WHERE COMPANY_ID = %s AND DOMAIN = %s",
                  (company_id, domain))

    def put_verification(self, row):
        self._run("INSERT INTO OPS.REGISTRATION_VERIFICATION (COMPANY_ID, EMAIL, VERIFICATION_TOKEN, CREATED_AT, EXPIRES_AT) "
                  "SELECT %s, %s, %s, SYSDATE(), TO_TIMESTAMP_NTZ(%s, " + TS + ")",
                  (row["company_id"], row["email"], row["token_hash"], row["expires_at"]))

    def get_verification(self, token_hash):
        r = self._rows("SELECT COMPANY_ID, EMAIL, EXPIRES_AT, VERIFIED_AT FROM OPS.REGISTRATION_VERIFICATION "
                       "WHERE VERIFICATION_TOKEN = %s", (token_hash,))
        if not r:
            return None
        return {"company_id": r[0][0], "email": r[0][1], "expires_at": str(r[0][2]), "verified_at": r[0][3]}

    def update_verification(self, token_hash, fields):
        if set(fields) - {"verified_at"}:
            raise ValueError("only verified_at can be updated")
        self._run("UPDATE OPS.REGISTRATION_VERIFICATION SET VERIFIED_AT = SYSDATE() WHERE VERIFICATION_TOKEN = %s",
                  (token_hash,))

    # --- bronze and load log --------------------------------------------------------------------------------
    _BRONZE = {
        "certstream": ("BRONZE.CERTSTREAM_EVENTS", ["domain", "brand", "match_type", "similarity", "seen_at", "raw"]),
        "blocklist": ("BRONZE.BLOCKLIST_FEED", ["domain", "source", "url", "listed_at", "observed_at"]),
        "rdap": ("BRONZE.RDAP_RESPONSES", ["domain", "fetched_at", "http_status", "registered_at", "payload"]),
    }

    def write_bronze(self, source, rows, source_file):
        table, cols = self._BRONZE[source]
        ts = {"seen_at", "listed_at", "observed_at", "fetched_at", "registered_at"}
        vals = []
        for c in cols:
            vals.append(f"TO_TIMESTAMP_NTZ(%s, {TS})" if c in ts else ("PARSE_JSON(%s)" if c in ("raw", "payload") else "%s"))
        sql = (f"INSERT INTO {table} ({', '.join(c.upper() for c in cols)}, SOURCE_FILE, LOADED_AT) "
               f"SELECT {', '.join(vals)}, %s, SYSDATE()")
        stmts = []
        for r in rows:
            params = []
            for c in cols:
                v = r.get(c)
                if c in ("raw", "payload"):
                    v = self._j(v or {})
                elif c == "domain" and source == "certstream":
                    v = r["domain"]
                params.append(v)
            stmts.append((sql, (*params, source_file)))
        if stmts:
            self._tx(stmts)
        return len(rows)

    _COPY_EXPR = {"seen_at": "TO_TIMESTAMP_NTZ($1:seen_at::STRING)", "listed_at": "TRY_TO_TIMESTAMP_NTZ($1:listed_at::STRING)",
                  "observed_at": "TRY_TO_TIMESTAMP_NTZ($1:observed_at::STRING)", "fetched_at": "TRY_TO_TIMESTAMP_NTZ($1:fetched_at::STRING)",
                  "registered_at": "TRY_TO_TIMESTAMP_NTZ($1:registered_at::STRING)", "raw": "$1:raw",
                  "payload": "$1:payload", "similarity": "$1:similarity::NUMBER", "http_status": "$1:http_status::NUMBER"}

    def copy_file(self, source, local_path, file_name):
        """PUT a local .jsonl.gz to @DG_STAGE and COPY INTO the Bronze table. Returns rows loaded.
        ON_ERROR = ABORT_STATEMENT: a bad file loads nothing."""
        table, cols = self._BRONZE[source]
        folder = file_name.rsplit("/", 1)[0]
        self._rows(f"PUT 'file://{local_path}' @BRONZE.DG_STAGE/{folder}/ AUTO_COMPRESS = FALSE OVERWRITE = FALSE")
        exprs = ", ".join(self._COPY_EXPR.get(c, f"$1:{c}::STRING") for c in cols)
        staged = f"@BRONZE.DG_STAGE/{file_name}"
        cur = self._connection().cursor()
        try:
            cur.execute(f"COPY INTO {table} ({', '.join(c.upper() for c in cols)}, SOURCE_FILE, LOADED_AT) "
                        f"FROM (SELECT {exprs}, METADATA$FILENAME, SYSDATE() FROM {staged}) "
                        "FILE_FORMAT = (FORMAT_NAME = 'BRONZE.DG_JSON') ON_ERROR = ABORT_STATEMENT")
            loaded = 0
            for row in cur.fetchall():
                loaded += int(row[3]) if len(row) > 3 and str(row[3]).isdigit() else 0
            return loaded
        finally:
            cur.close()

    def loaded_file(self, file_name):
        r = self._rows("SELECT FILE_NAME, SOURCE, ROW_COUNT, SHA256, STATUS, LOADED_AT FROM OPS.LOAD_LOG WHERE FILE_NAME = %s",
                       (file_name,))
        return {"file_name": r[0][0], "source": r[0][1], "row_count": r[0][2], "sha256": r[0][3], "status": r[0][4],
                "loaded_at": str(r[0][5])} if r else None

    def log_load(self, entry):
        self._run("MERGE INTO OPS.LOAD_LOG t USING (SELECT %s AS FILE_NAME, %s AS SOURCE, %s AS ROW_COUNT, %s AS BYTES, "
                  "%s AS SHA256, %s AS STATUS) s ON t.FILE_NAME = s.FILE_NAME WHEN MATCHED THEN UPDATE SET STATUS = s.STATUS, "
                  "LOADED_AT = SYSDATE() WHEN NOT MATCHED THEN INSERT (FILE_NAME, SOURCE, ROW_COUNT, BYTES, SHA256, LOADED_AT, "
                  "STATUS) VALUES (s.FILE_NAME, s.SOURCE, s.ROW_COUNT, s.BYTES, s.SHA256, SYSDATE(), s.STATUS)",
                  (entry["file_name"], entry["source"], entry["row_count"], entry.get("bytes", 0), entry["sha256"],
                   entry["status"]))

    def load_log(self):
        return [{"file_name": r[0], "source": r[1], "row_count": r[2], "sha256": r[3], "status": r[4]}
                for r in self._rows("SELECT FILE_NAME, SOURCE, ROW_COUNT, SHA256, STATUS FROM OPS.LOAD_LOG ORDER BY FILE_NAME")]

    def put_metrics(self, row):
        self._run("INSERT INTO OPS.EVALUATION_METRICS (METRIC_DATE, COMPANY_ID, PRECISION, RECALL, LEAD_TIME_MEDIAN, "
                  "LEAD_TIME_P25, LEAD_TIME_P75, DOMAINS_FLAGGED, CONFIRMED_THREATS, FALSE_POSITIVES, ANALYST_HOURS) "
                  "SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
                  (row["metric_date"], row["company_id"], row.get("precision"), row.get("recall"),
                   row.get("lead_time_median"), row.get("lead_time_p25"), row.get("lead_time_p75"),
                   row.get("domains_flagged", 0), row.get("confirmed_threats", 0), row.get("false_positives", 0),
                   row.get("analyst_hours", 0.0)))

    # --- silver and gold ------------------------------------------------------------------------------------
    def candidates(self):
        r = self._rows("SELECT DOMAIN, FIRST_SEEN, LAST_SEEN, CERT_COUNT FROM SILVER.PARSED_DOMAINS ORDER BY DOMAIN")
        return [{"domain": a, "first_seen_at": str(b), "last_seen_at": str(c), "cert_count": d} for a, b, c, d in r]

    def blocklist_index(self):
        r = self._rows("SELECT DOMAIN, LISTED_AT, SOURCES FROM SILVER.CLEAN_BLOCKLIST")
        return {a: {"first_listed_at": str(b), "sources": [s for s in (c or "").split(",") if s]} for a, b, c in r}

    def rdap_index(self):
        return {a: str(b) for a, b in self._rows("SELECT DOMAIN, REGISTERED_AT FROM SILVER.RDAP_AGE")}

    _VCOLS = ["DOMAIN", "COMPANY_ID", "SCORE", "CLASSIFICATION", "MATCHED_BRAND", "MATCH_TYPE", "SIMILARITY", "EVIDENCE",
              "BREAKDOWN", "IS_ON_BLOCKLIST", "BLOCKLIST_SOURCES", "FIRST_SEEN_AT", "FIRST_LISTED_AT", "REGISTERED_AT",
              "AGE_DAYS", "FIRST_FLAGGED_AT", "LAST_EVALUATED_AT", "SCORING_VERSION"]

    def _verdict(self, r) -> dict:
        d = self._dict(self._VCOLS, r)
        d["evidence"] = self._unj(d["evidence"]) or []
        d["breakdown"] = self._unj(d["breakdown"]) or {}
        d["is_on_blocklist"] = bool(d["is_on_blocklist"])
        for k in ("first_seen_at", "first_listed_at", "registered_at", "first_flagged_at", "last_evaluated_at"):
            d[k] = str(d[k]) if d[k] is not None else None
        d["age_days"] = float(d["age_days"]) if d["age_days"] is not None else None
        return d

    def write_score(self, v):
        """Breakdown + verdict in one transaction. first_flagged_at is kept once set (COALESCE)."""
        flagged = v["classification"] in FLAGGED
        stmts = [
            ("DELETE FROM SILVER.SCORE_BREAKDOWN WHERE DOMAIN = %s AND COMPANY_ID = %s", (v["domain"], v["company_id"])),
        ]
        for factor, pts in v["breakdown"].items():
            stmts.append(("INSERT INTO SILVER.SCORE_BREAKDOWN (DOMAIN, COMPANY_ID, FACTOR, POINTS, EVALUATED_AT, SCORING_VERSION) "
                          "SELECT %s, %s, %s, %s, TO_TIMESTAMP_NTZ(%s, " + TS + "), %s",
                          (v["domain"], v["company_id"], factor, pts, v["last_evaluated_at"], v["scoring_version"])))
        stmts.append((
            "MERGE INTO GOLD.DOMAIN_VERDICT t USING (SELECT %s AS DOMAIN, %s AS COMPANY_ID, %s AS SCORE, %s AS CLASSIFICATION, "
            "%s AS MATCHED_BRAND, %s AS MATCH_TYPE, %s AS SIMILARITY, PARSE_JSON(%s) AS EVIDENCE, PARSE_JSON(%s) AS BREAKDOWN, "
            "%s AS IS_ON_BLOCKLIST, PARSE_JSON(%s) AS BLOCKLIST_SOURCES, %s AS AGE_DAYS, TO_TIMESTAMP_NTZ(%s, " + TS + ") AS EVALUATED, "
            "TRY_TO_TIMESTAMP_NTZ(%s, " + TS + ") AS FIRST_SEEN, TRY_TO_TIMESTAMP_NTZ(%s, " + TS + ") AS FIRST_LISTED, "
            "TRY_TO_TIMESTAMP_NTZ(%s, " + TS + ") AS REGISTERED, %s AS SCORING_VERSION, %s AS FLAGGED) s "
            "ON t.DOMAIN = s.DOMAIN AND t.COMPANY_ID = s.COMPANY_ID "
            "WHEN MATCHED THEN UPDATE SET SCORE = s.SCORE, CLASSIFICATION = s.CLASSIFICATION, MATCHED_BRAND = s.MATCHED_BRAND, "
            "MATCH_TYPE = s.MATCH_TYPE, SIMILARITY = s.SIMILARITY, EVIDENCE = s.EVIDENCE, BREAKDOWN = s.BREAKDOWN, "
            "IS_ON_BLOCKLIST = s.IS_ON_BLOCKLIST, BLOCKLIST_SOURCES = s.BLOCKLIST_SOURCES, AGE_DAYS = s.AGE_DAYS, "
            "LAST_EVALUATED_AT = s.EVALUATED, FIRST_SEEN_AT = s.FIRST_SEEN, FIRST_LISTED_AT = s.FIRST_LISTED, "
            "REGISTERED_AT = s.REGISTERED, SCORING_VERSION = s.SCORING_VERSION, "
            "FIRST_FLAGGED_AT = COALESCE(t.FIRST_FLAGGED_AT, IFF(s.FLAGGED, s.EVALUATED, NULL)) "
            "WHEN NOT MATCHED THEN INSERT (DOMAIN, COMPANY_ID, SCORE, CLASSIFICATION, MATCHED_BRAND, MATCH_TYPE, SIMILARITY, "
            "EVIDENCE, BREAKDOWN, IS_ON_BLOCKLIST, BLOCKLIST_SOURCES, AGE_DAYS, LAST_EVALUATED_AT, FIRST_SEEN_AT, "
            "FIRST_LISTED_AT, REGISTERED_AT, SCORING_VERSION, FIRST_FLAGGED_AT) VALUES (s.DOMAIN, s.COMPANY_ID, s.SCORE, "
            "s.CLASSIFICATION, s.MATCHED_BRAND, s.MATCH_TYPE, s.SIMILARITY, s.EVIDENCE, s.BREAKDOWN, s.IS_ON_BLOCKLIST, "
            "s.BLOCKLIST_SOURCES, s.AGE_DAYS, s.EVALUATED, s.FIRST_SEEN, s.FIRST_LISTED, s.REGISTERED, s.SCORING_VERSION, "
            "IFF(s.FLAGGED, s.EVALUATED, NULL))",
            (v["domain"], v["company_id"], v["score"], v["classification"], v.get("matched_brand"), v.get("match_type"),
             v.get("similarity"), self._j(v["evidence"]), self._j(v["breakdown"]), bool(v["is_on_blocklist"]),
             self._j(v.get("blocklist_sources") or []), v.get("age_days"), v["last_evaluated_at"], v.get("first_seen_at"),
             v.get("first_listed_at"), v.get("registered_at"), v["scoring_version"], flagged)))
        self._tx(stmts)
        return self.get_verdict(v["domain"], v["company_id"])

    def get_verdict(self, domain, company_id=None):
        if company_id:
            r = self._rows(f"SELECT {', '.join(self._VCOLS)} FROM GOLD.DOMAIN_VERDICT WHERE DOMAIN = %s AND COMPANY_ID = %s",
                           (domain, company_id))
        else:
            r = self._rows(f"SELECT {', '.join(self._VCOLS)} FROM GOLD.DOMAIN_VERDICT WHERE DOMAIN = %s ORDER BY SCORE DESC LIMIT 1",
                           (domain,))
        return self._verdict(r[0]) if r else None

    def verdicts(self, company_id=None):
        sql = f"SELECT {', '.join(self._VCOLS)} FROM GOLD.DOMAIN_VERDICT"
        params = ()
        if company_id:
            sql += " WHERE COMPANY_ID = %s"
            params = (company_id,)
        return [self._verdict(r) for r in self._rows(sql + " ORDER BY DOMAIN, COMPANY_ID", params)]

    def inbox(self, company_id=None, min_score=0, since=None, limit=50):
        where = ["v.CLASSIFICATION IN ('SUSPICIOUS', 'HIGH_RISK', 'DANGEROUS')", "v.SCORE >= %s"]
        params: list = [min_score]
        if company_id:
            where.append("v.COMPANY_ID = %s")
            params.append(company_id)
        if since:
            where.append("v.FIRST_FLAGGED_AT >= TO_TIMESTAMP_NTZ(%s, " + TS + ")")
            params.append(since)
        select = ", ".join("v." + c for c in self._VCOLS)
        sql = (f"SELECT {select}, COALESCE(f.LABEL, 'UNREVIEWED') AS ANALYST_LABEL FROM GOLD.DOMAIN_VERDICT v "
               "LEFT JOIN (SELECT DOMAIN, COMPANY_ID, LABEL FROM SILVER.ANALYST_FEEDBACK "
               "QUALIFY ROW_NUMBER() OVER (PARTITION BY DOMAIN, COMPANY_ID ORDER BY FEEDBACK_AT DESC) = 1) f "
               "ON f.DOMAIN = v.DOMAIN AND f.COMPANY_ID = v.COMPANY_ID WHERE " + " AND ".join(where) +
               " ORDER BY v.SCORE DESC, v.FIRST_FLAGGED_AT ASC LIMIT %s")
        params.append(int(limit))
        out = []
        for r in self._rows(sql, params):
            d = self._verdict(r[:-1])
            d["analyst_label"] = r[-1]
            out.append(d)
        return out

    def add_feedback(self, row):
        if row["label"] not in FEEDBACK_LABELS:
            raise ValueError(f"label must be one of {FEEDBACK_LABELS}")
        self._run("INSERT INTO SILVER.ANALYST_FEEDBACK (DOMAIN, COMPANY_ID, ANALYST_EMAIL, LABEL, NOTE, FEEDBACK_AT) "
                  "SELECT %s, %s, %s, %s, %s, SYSDATE()",
                  (row["domain"], row.get("company_id"), row["analyst_email"], row["label"], row.get("note", "")))

    def feedback_history(self, domain, company_id=None):
        sql = "SELECT DOMAIN, COMPANY_ID, ANALYST_EMAIL, LABEL, NOTE, FEEDBACK_AT FROM SILVER.ANALYST_FEEDBACK WHERE DOMAIN = %s"
        params: list = [domain]
        if company_id:
            sql += " AND COMPANY_ID = %s"
            params.append(company_id)
        return [{"domain": a, "company_id": b, "analyst_email": c, "label": d, "note": e, "feedback_at": str(f)}
                for a, b, c, d, e, f in self._rows(sql + " ORDER BY FEEDBACK_AT", params)]

    def put_brief(self, b):
        self._run(
            "MERGE INTO GOLD.DOMAIN_BRIEFS t USING (SELECT %s AS DOMAIN, %s AS COMPANY_ID, %s AS LANGUAGE, %s AS SUMMARY, "
            "PARSE_JSON(%s) AS REASONS, %s AS ADVICE, %s AS SOURCE, %s AS MODEL_NAME, %s AS VERDICT_SCORE) s "
            "ON t.DOMAIN = s.DOMAIN AND t.COMPANY_ID = s.COMPANY_ID AND t.LANGUAGE = s.LANGUAGE "
            "WHEN MATCHED THEN UPDATE SET SUMMARY = s.SUMMARY, REASONS = s.REASONS, ADVICE = s.ADVICE, SOURCE = s.SOURCE, "
            "MODEL_NAME = s.MODEL_NAME, VERDICT_SCORE = s.VERDICT_SCORE, CREATED_AT = SYSDATE() WHEN NOT MATCHED THEN INSERT "
            "(DOMAIN, COMPANY_ID, LANGUAGE, SUMMARY, REASONS, ADVICE, SOURCE, MODEL_NAME, VERDICT_SCORE, CREATED_AT) VALUES "
            "(s.DOMAIN, s.COMPANY_ID, s.LANGUAGE, s.SUMMARY, s.REASONS, s.ADVICE, s.SOURCE, s.MODEL_NAME, s.VERDICT_SCORE, SYSDATE())",
            (b["domain"], b["company_id"], b["language"], b["summary"], self._j(b["reasons"]), b["advice"], b["source"],
             b.get("model_name"), b.get("verdict_score")))

    def get_brief(self, domain, company_id, language):
        r = self._rows("SELECT SUMMARY, REASONS, ADVICE, SOURCE, MODEL_NAME, CREATED_AT, VERDICT_SCORE FROM GOLD.DOMAIN_BRIEFS "
                       "WHERE DOMAIN = %s AND COMPANY_ID = %s AND LANGUAGE = %s", (domain, company_id, language))
        if not r:
            return None
        return {"summary": r[0][0], "reasons": self._unj(r[0][1]), "advice": r[0][2], "source": r[0][3],
                "model_name": r[0][4], "created_at": str(r[0][5]), "verdict_score": r[0][6]}

    _TD = ["DRAFT_ID", "DOMAIN", "COMPANY_ID", "ANALYST_EMAIL", "ANALYST_NAME", "DRAFT_TEXT", "SUBJECT", "ABUSE_PROVIDER",
           "STATUS", "CREATED_AT", "APPROVED_AT", "EXPORTED_AT", "APPROVER_SIGNATURE", "SOURCE"]

    def _td(self, r):
        d = self._dict(self._TD, r)
        for k in ("created_at", "approved_at", "exported_at"):
            d[k] = str(d[k]) if d[k] is not None else None
        return d

    def add_takedown(self, row):
        self._run("INSERT INTO GOLD.TAKEDOWN_DRAFTS (DRAFT_ID, DOMAIN, COMPANY_ID, ANALYST_EMAIL, ANALYST_NAME, DRAFT_TEXT, "
                  "SUBJECT, ABUSE_PROVIDER, STATUS, CREATED_AT, SOURCE) SELECT %s, %s, %s, %s, %s, %s, %s, %s, 'DRAFT', SYSDATE(), %s",
                  (row["draft_id"], row["domain"], row["company_id"], row["analyst_email"], row["analyst_name"],
                   row["draft_text"], row["subject"], row.get("abuse_provider", "registrar"), row["source"]))

    def get_takedown(self, draft_id):
        r = self._rows(f"SELECT {', '.join(self._TD)} FROM GOLD.TAKEDOWN_DRAFTS WHERE DRAFT_ID = %s", (draft_id,))
        return self._td(r[0]) if r else None

    _TD_FIELDS = {"status": "STATUS", "approved_at": "APPROVED_AT", "exported_at": "EXPORTED_AT",
                  "approver_signature": "APPROVER_SIGNATURE", "draft_text": "DRAFT_TEXT", "subject": "SUBJECT"}

    def update_takedown(self, draft_id, fields):
        assignments, params = [], []
        for key, value in fields.items():
            col = self._TD_FIELDS.get(key)
            if col is None:
                raise ValueError(f"cannot update {key!r}")
            if col in ("APPROVED_AT", "EXPORTED_AT"):
                assignments.append(f"{col} = SYSDATE()")  # value is ignored: the database stamps the time
            else:
                assignments.append(f"{col} = %s")
                params.append(value)
        if assignments:
            self._run(f"UPDATE GOLD.TAKEDOWN_DRAFTS SET {', '.join(assignments)} WHERE DRAFT_ID = %s", (*params, draft_id))

    def list_takedowns(self, company_id=None, status=None, domain=None):
        sql = f"SELECT {', '.join(self._TD)} FROM GOLD.TAKEDOWN_DRAFTS WHERE 1 = 1"
        params: list = []
        for col, val in (("COMPANY_ID", company_id), ("STATUS", status), ("DOMAIN", domain)):
            if val:
                sql += f" AND {col} = %s"
                params.append(val)
        return [self._td(r) for r in self._rows(sql + " ORDER BY CREATED_AT DESC", params)]

    def log_email(self, row):
        self._run("INSERT INTO OPS.EMAIL_LOG (EMAIL_ID, COMPANY_ID, DOMAIN, RECIPIENT_EMAIL, VERDICT_SCORE, CLASSIFICATION, "
                  "SENT_AT, STATUS, ERROR_MESSAGE, KIND) SELECT %s, %s, %s, %s, %s, %s, SYSDATE(), %s, %s, %s",
                  (row.get("email_id") or new_id(), row["company_id"], row.get("domain"), row["recipient_email"],
                   row.get("score"), row.get("classification"), row["status"], row.get("error"), row["kind"]))

    def email_log(self, company_id=None):
        sql = ("SELECT EMAIL_ID, COMPANY_ID, DOMAIN, RECIPIENT_EMAIL, VERDICT_SCORE, CLASSIFICATION, SENT_AT, STATUS, "
               "ERROR_MESSAGE, KIND FROM OPS.EMAIL_LOG")
        params: tuple = ()
        if company_id:
            sql += " WHERE COMPANY_ID = %s"
            params = (company_id,)
        cols = ["email_id", "company_id", "domain", "recipient_email", "score", "classification", "sent_at", "status",
                "error", "kind"]
        return [dict(zip(cols, (r[0], r[1], r[2], r[3], r[4], r[5], str(r[6]), r[7], r[8], r[9])))
                for r in self._rows(sql + " ORDER BY SENT_AT", params)]

    def alert_sent(self, company_id, domain):
        return bool(self._rows("SELECT 1 FROM OPS.EMAIL_LOG WHERE COMPANY_ID = %s AND DOMAIN = %s AND STATUS = 'SENT' LIMIT 1",
                               (company_id, domain)))

    _PREF_COLS = ["email_notifications", "notification_frequency", "min_score_threshold", "notification_email",
                  "frequency_last_sent_at"]

    def get_prefs(self, company_id):
        r = self._rows("SELECT EMAIL_NOTIFICATIONS, NOTIFICATION_FREQUENCY, MIN_SCORE_THRESHOLD, NOTIFICATION_EMAIL, "
                       "FREQUENCY_LAST_SENT_AT FROM OPS.EMAIL_PREFERENCES WHERE COMPANY_ID = %s", (company_id,))
        if not r:
            return {"email_notifications": True, "notification_frequency": "IMMEDIATE", "min_score_threshold": 70,
                    "notification_email": None, "frequency_last_sent_at": None}
        return {"email_notifications": bool(r[0][0]), "notification_frequency": r[0][1], "min_score_threshold": r[0][2],
                "notification_email": r[0][3], "frequency_last_sent_at": str(r[0][4]) if r[0][4] else None}

    def set_prefs(self, company_id, fields):
        cur = self.get_prefs(company_id)
        cur.update(fields)
        self._run(
            "MERGE INTO OPS.EMAIL_PREFERENCES t USING (SELECT %s AS COMPANY_ID, %s AS EN, %s AS FREQ, %s AS MIN_SCORE, "
            "%s AS NEMAIL, TRY_TO_TIMESTAMP_NTZ(%s, " + TS + ") AS LAST_SENT) s ON t.COMPANY_ID = s.COMPANY_ID "
            "WHEN MATCHED THEN UPDATE SET EMAIL_NOTIFICATIONS = s.EN, NOTIFICATION_FREQUENCY = s.FREQ, "
            "MIN_SCORE_THRESHOLD = s.MIN_SCORE, NOTIFICATION_EMAIL = s.NEMAIL, FREQUENCY_LAST_SENT_AT = s.LAST_SENT "
            "WHEN NOT MATCHED THEN INSERT (COMPANY_ID, EMAIL_NOTIFICATIONS, NOTIFICATION_FREQUENCY, MIN_SCORE_THRESHOLD, "
            "NOTIFICATION_EMAIL, FREQUENCY_LAST_SENT_AT) VALUES (s.COMPANY_ID, s.EN, s.FREQ, s.MIN_SCORE, s.NEMAIL, s.LAST_SENT)",
            (company_id, cur["email_notifications"], cur["notification_frequency"], cur["min_score_threshold"],
             cur["notification_email"], cur.get("frequency_last_sent_at")))

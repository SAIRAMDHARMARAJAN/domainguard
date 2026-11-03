"""TEST DOUBLE for the warehouse interface. Plain Python dicts, no database.

Purpose: run the real pipeline, loader, API, notifier and dashboard logic offline in tests and in scripts/demo.py.
It must mirror SnowflakeWarehouse's rules (first-flag kept once, one verdict per domain and company, idempotent
loads). It is NOT storage: the CLI and API refuse to start with it unless DG_ALLOW_MEMORY_WAREHOUSE=1 is set
for a demo, and it is never used in production.
"""
from __future__ import annotations

import copy
from collections import defaultdict

from .warehouse import FEEDBACK_LABELS, FLAGGED, Warehouse, new_id


class MemoryWarehouse(Warehouse):
    def __init__(self):
        self.users: dict[str, dict] = {}
        self.protected: dict[tuple, dict] = {}
        self.verifications: dict[str, dict] = {}
        self.bronze: dict[str, list[dict]] = {"certstream": [], "blocklist": [], "rdap": []}
        self.loads: dict[str, dict] = {}
        self.metrics: list[dict] = []
        self.verdicts_: dict[tuple, dict] = {}
        self.breakdown: dict[tuple, dict] = {}
        self.feedback: list[dict] = []
        self.briefs: dict[tuple, dict] = {}
        self.takedowns: dict[str, dict] = {}
        self.emails: list[dict] = []
        self.prefs: dict[str, dict] = {}

    # ---- reference --------------------------------------------------------------------------------------
    def active_protected_rows(self):
        out = []
        for (cid, dom), r in sorted(self.protected.items()):
            u = self.users.get(cid)
            if u and u["status"] == "ACTIVE" and r["status"] == "ACTIVE":
                out.append(copy.deepcopy({k: r[k] for k in ("company_id", "domain", "brand_aliases", "official_domains", "verified")}))
        return out

    def get_user(self, company_id):
        return copy.deepcopy(self.users.get(company_id))

    def get_user_by_email(self, email):
        for u in self.users.values():
            if u["email"].lower() == email.lower():
                return copy.deepcopy(u)
        return None

    def get_user_by_name(self, name):
        for u in self.users.values():
            if u["name"].strip().lower() == name.strip().lower():
                return copy.deepcopy(u)
        return None

    def domain_registered(self, domain):
        domain = domain.lower()
        return any(r["domain"].lower() == domain for r in self.protected.values())

    def user_by_key_hash(self, key_hash):
        for u in self.users.values():
            if u.get("api_key_hash") == key_hash:
                return copy.deepcopy(u)
        return None

    def create_user(self, user):
        u = {"company_id": user["company_id"], "name": user["name"], "email": user["email"],
             "contact_person": user.get("contact_person"), "created_at": user.get("created_at", "now"),
             "status": user.get("status", "PENDING"), "api_key_hash": None, "api_key_created_at": None,
             "dispute_contact": None, "email_notifications": bool(user.get("email_notifications", True)),
             "notification_email": user.get("notification_email"), "last_login_at": None}
        if any(x["email"].lower() == u["email"].lower() for x in self.users.values()):
            raise ValueError("email already registered")
        self.users[u["company_id"]] = u

    _UPDATABLE = {"name", "contact_person", "status", "api_key_hash", "api_key_created_at", "dispute_contact",
                  "email_notifications", "notification_email", "last_login_at"}

    def update_user(self, company_id, fields):
        if set(fields) - self._UPDATABLE:
            raise ValueError(f"cannot update {sorted(set(fields) - self._UPDATABLE)}")
        self.users[company_id].update(fields)

    def list_users(self, status=None):
        return [copy.deepcopy(u) for u in self.users.values() if status is None or u["status"] == status]

    def upsert_protected(self, row):
        key = (row["company_id"], row["domain"])
        cur = self.protected.get(key, {"verified": False, "status": "ACTIVE"})
        cur.update(company_id=row["company_id"], domain=row["domain"], brand_aliases=list(row.get("brand_aliases", [])),
                   official_domains=list(row.get("official_domains", [])), status="ACTIVE")
        self.protected[key] = cur

    def protected_for(self, company_id, include_removed=False):
        return [copy.deepcopy(r) for (c, _), r in sorted(self.protected.items())
                if c == company_id and (include_removed or r["status"] == "ACTIVE")]

    def remove_protected(self, company_id, domain):
        if (company_id, domain) in self.protected:
            self.protected[(company_id, domain)]["status"] = "REMOVED"

    def put_verification(self, row):
        self.verifications[row["token_hash"]] = {"company_id": row["company_id"], "email": row["email"],
                                                 "expires_at": row["expires_at"], "verified_at": None,
                                                 "otp_attempts": row.get("otp_attempts", 0)}

    def pending_verification(self, company_id):
        rows = [v for v in self.verifications.values()
                if v["company_id"] == company_id and v.get("verified_at") is None]
        return copy.deepcopy(rows[-1]) if rows else None

    def get_verification(self, token_hash):
        v = self.verifications.get(token_hash)
        return copy.deepcopy(v) if v else None

    def update_verification(self, token_hash, fields):
        self.verifications[token_hash].update(fields)

    # ---- bronze and load log ------------------------------------------------------------------------------
    def write_bronze(self, source, rows, source_file):
        for r in rows:
            self.bronze[source].append({**copy.deepcopy(r), "source_file": source_file})
        return len(rows)

    def loaded_file(self, file_name):
        e = self.loads.get(file_name)
        return copy.deepcopy(e) if e else None

    def log_load(self, entry):
        self.loads[entry["file_name"]] = dict(entry)

    def load_log(self):
        return [dict(v) for k, v in sorted(self.loads.items())]

    def put_metrics(self, row):
        self.metrics.append(dict(row))

    # ---- silver and gold ----------------------------------------------------------------------------------
    def candidates(self):
        seen: dict[str, dict] = {}
        for r in self.bronze["certstream"]:
            c = seen.setdefault(r["domain"], {"domain": r["domain"], "first_seen_at": r["seen_at"],
                                              "last_seen_at": r["seen_at"], "cert_count": 0})
            c["first_seen_at"] = min(c["first_seen_at"], r["seen_at"])
            c["last_seen_at"] = max(c["last_seen_at"], r["seen_at"])
            c["cert_count"] += 1
        return [seen[k] for k in sorted(seen)]

    def blocklist_index(self):
        idx: dict[str, dict] = {}
        for r in self.bronze["blocklist"]:
            when = r.get("listed_at") or r.get("observed_at")
            e = idx.setdefault(r["domain"], {"first_listed_at": when, "sources": set()})
            if when and (e["first_listed_at"] is None or when < e["first_listed_at"]):
                e["first_listed_at"] = when
            e["sources"].add(r["source"])
        return {d: {"first_listed_at": e["first_listed_at"], "sources": sorted(e["sources"])} for d, e in idx.items()}

    def rdap_index(self):
        idx: dict[str, str] = {}
        for r in self.bronze["rdap"]:
            if r.get("http_status") == 200 and r.get("registered_at"):
                idx[r["domain"]] = max(idx.get(r["domain"], ""), r["registered_at"])
        return idx

    def write_score(self, v):
        key = (v["domain"], v["company_id"])
        cur = self.verdicts_.get(key, {})
        stored = {**copy.deepcopy(v)}
        flagged = v["classification"] in FLAGGED
        stored["first_flagged_at"] = cur.get("first_flagged_at") or (v["last_evaluated_at"] if flagged else None)
        self.verdicts_[key] = stored
        self.breakdown[key] = dict(v["breakdown"])
        return copy.deepcopy(stored)

    def get_verdict(self, domain, company_id=None):
        if company_id:
            v = self.verdicts_.get((domain, company_id))
            return copy.deepcopy(v) if v else None
        matches = [v for (d, _), v in self.verdicts_.items() if d == domain]
        return copy.deepcopy(max(matches, key=lambda x: x["score"])) if matches else None

    def verdicts(self, company_id=None):
        return [copy.deepcopy(v) for k, v in sorted(self.verdicts_.items())
                if company_id is None or k[1] == company_id]

    def _label(self, domain, company_id):
        hist = [f for f in self.feedback if f["domain"] == domain and f["company_id"] == company_id]
        return hist[-1]["label"] if hist else "UNREVIEWED"

    def inbox(self, company_id=None, min_score=0, since=None, limit=50):
        rows = []
        for v in self.verdicts(company_id):
            if v["classification"] not in FLAGGED or v["score"] < min_score:
                continue
            if since and (v["first_flagged_at"] is None or v["first_flagged_at"] < since):
                continue
            v["analyst_label"] = self._label(v["domain"], v["company_id"])
            rows.append(v)
        rows.sort(key=lambda x: (-x["score"], x["first_flagged_at"] or ""))
        return rows[:limit]

    def add_feedback(self, row):
        if row["label"] not in FEEDBACK_LABELS:
            raise ValueError(f"label must be one of {FEEDBACK_LABELS}")
        self.feedback.append({**row, "company_id": row.get("company_id"), "feedback_at": row.get("feedback_at", "now")})

    def feedback_history(self, domain, company_id=None):
        return [copy.deepcopy(f) for f in self.feedback
                if f["domain"] == domain and (company_id is None or f["company_id"] == company_id)]

    def put_brief(self, b):
        self.briefs[(b["domain"], b["company_id"], b["language"])] = dict(b)

    def get_brief(self, domain, company_id, language):
        b = self.briefs.get((domain, company_id, language))
        return copy.deepcopy(b) if b else None

    def add_takedown(self, row):
        self.takedowns[row["draft_id"]] = {**copy.deepcopy(row), "status": "DRAFT", "approved_at": None,
                                           "exported_at": None, "approver_signature": None}

    def get_takedown(self, draft_id):
        t = self.takedowns.get(draft_id)
        return copy.deepcopy(t) if t else None

    def update_takedown(self, draft_id, fields):
        allowed = {"status", "approved_at", "exported_at", "approver_signature", "draft_text", "subject"}
        if set(fields) - allowed:
            raise ValueError(f"cannot update {sorted(set(fields) - allowed)}")
        self.takedowns[draft_id].update(fields)

    def list_takedowns(self, company_id=None, status=None, domain=None):
        return [copy.deepcopy(t) for t in sorted(self.takedowns.values(), key=lambda t: t["draft_id"])
                if (company_id is None or t["company_id"] == company_id)
                and (status is None or t["status"] == status) and (domain is None or t["domain"] == domain)]

    def log_email(self, row):
        self.emails.append({"email_id": row.get("email_id") or new_id(), **copy.deepcopy(row),
                            "sent_at": row.get("sent_at", "now")})

    def email_log(self, company_id=None):
        return [copy.deepcopy(e) for e in self.emails if company_id is None or e["company_id"] == company_id]

    def alert_sent(self, company_id, domain):
        return any(e["company_id"] == company_id and e.get("domain") == domain and e["status"] == "SENT" for e in self.emails)

    def get_prefs(self, company_id):
        base = {"email_notifications": True, "notification_frequency": "IMMEDIATE", "min_score_threshold": 70,
                "notification_email": None, "frequency_last_sent_at": None}
        return {**base, **self.prefs.get(company_id, {})}

    def set_prefs(self, company_id, fields):
        self.prefs.setdefault(company_id, {}).update(fields)

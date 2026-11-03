"""Analyst dashboard (Streamlit).  streamlit run domainguard/dashboard.py

Primary workflow: Overview, Investigate, Watchlist, and Cases. Investigations group related lookalike domains into
campaigns using the existing verdict, evidence, feedback, and takedown records. Legacy evaluation/report helpers
remain available in code for operational checks but are not part of the analyst navigation.
Access: DG_ANALYST_TOKEN gates the whole page (placeholder; put real SSO in front before any deployment)."""
from __future__ import annotations

import hmac
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

# Streamlit may execute this file with its parent directory as the working
# directory, so ensure the repository root is importable.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from domainguard import evaluation, takedown
from domainguard.auth import new_api_key, hash_key
from domainguard.config import Settings
from domainguard.factory import make_warehouse
from domainguard.normalize import defang
from domainguard.registration import Registrar, RegistrationError
from domainguard.watchlist import WarehouseWatchlist

if "PYTEST_CURRENT_TEST" not in os.environ:
    from domainguard.cli import _load_dotenv
    _load_dotenv()

st.set_page_config(page_title="DomainGuard analyst", layout="wide")


@st.cache_resource
def _store():
    return make_warehouse(Settings.from_env())


def _gate() -> bool:
    token = os.environ.get("DG_ANALYST_TOKEN", "")
    if not token:
        st.warning("DG_ANALYST_TOKEN is not set: the dashboard is open. Run it on localhost only.")
        return True
    if st.session_state.get("authed"):
        return True
    entered = st.text_input("Analyst access token", type="password", key="token_input")
    if entered:
        if hmac.compare_digest(entered, token):
            st.session_state["authed"] = True
            st.rerun()
        st.error("Invalid token.")
    return False


def _rows_df(rows):
    return pd.DataFrame([{"domain": defang(r["domain"]), "company": r["company_id"][:8], "class": r["classification"],
                          "score": r["score"], "brand": r.get("matched_brand"),
                          "review": r.get("analyst_label", "UNREVIEWED"), "first flagged": r.get("first_flagged_at"),
                          "on blocklist": r.get("is_on_blocklist", False)} for r in rows])


def inbox_page(wh):
    st.header("Threat inbox")
    c1, c2, c3 = st.columns(3)
    cls = c1.multiselect("Classification", ["SUSPICIOUS", "HIGH_RISK", "DANGEROUS"], key="f_cls")
    review = c2.selectbox("Review", ["All", "UNREVIEWED", "CONFIRMED_THREAT", "FALSE_POSITIVE"], key="f_rev")
    days = c3.number_input("Flagged in the last N days", 1, 365, 30, key="f_days")
    since = (datetime.now(timezone.utc) - timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = wh.inbox(limit=500, since=since)
    if cls:
        rows = [r for r in rows if r["classification"] in cls]
    if review != "All":
        rows = [r for r in rows if r.get("analyst_label", "UNREVIEWED") == review]
    if not rows:
        st.info("Nothing matches these filters.")
        return
    st.dataframe(_rows_df(rows), width="stretch", hide_index=True)


def overview_page(wh):
    st.header("Brand impersonation command center")
    rows = wh.inbox(limit=500)
    active = wh.active_protected_rows()
    drafts = wh.list_takedowns()
    unreviewed = [r for r in rows if r.get("analyst_label", "UNREVIEWED") == "UNREVIEWED"]
    high_risk = [r for r in rows if r["classification"] in ("HIGH_RISK", "DANGEROUS")]
    campaigns = {r.get("matched_brand") or r["company_id"] for r in rows}
    c = st.columns(4)
    c[0].metric("Open threats", len(unreviewed))
    c[1].metric("High-risk domains", len(high_risk))
    c[2].metric("Protected domains", len(active))
    c[3].metric("Open cases", sum(d["status"] in ("DRAFT", "APPROVED") for d in drafts))
    st.subheader("What needs attention")
    if not rows:
        st.info("No impersonation activity is available yet.")
        return
    summary = {}
    for row in rows:
        key = row.get("matched_brand") or "Unattributed"
        item = summary.setdefault(key, {"campaign": key, "domains": 0, "max score": 0, "unreviewed": 0})
        item["domains"] += 1
        item["max score"] = max(item["max score"], row["score"])
        item["unreviewed"] += row.get("analyst_label", "UNREVIEWED") == "UNREVIEWED"
    st.dataframe(pd.DataFrame(sorted(summary.values(), key=lambda x: (x["unreviewed"], x["max score"]),
                                     reverse=True)), hide_index=True, width="stretch")
    st.caption(f"{len(campaigns)} active campaign groups. Open Investigate to review evidence and create a case.")


def investigate_page(wh):
    st.header("Investigate campaigns")
    rows = wh.inbox(limit=500)
    if not rows:
        st.info("No flagged domains yet.")
        return
    groups = {}
    for row in rows:
        key = row.get("matched_brand") or f"Company {row['company_id'][:8]}"
        groups.setdefault(key, []).append(row)
    campaign = st.selectbox("Campaign / brand cluster",
                            sorted(groups, key=lambda k: max(r["score"] for r in groups[k]), reverse=True),
                            key="campaign_choice")
    members = sorted(groups[campaign], key=lambda r: (r["score"], r.get("first_flagged_at", "")), reverse=True)
    st.caption(f"{len(members)} related domains. Review the shared evidence before opening a case.")
    st.dataframe(_rows_df(members), hide_index=True, width="stretch")
    selected = {f"{defang(r['domain'])} — {r['classification']} ({r['score']}/100)": r for r in members}
    choice = st.selectbox("Domain evidence", list(selected), key="campaign_domain")
    v = selected[choice]
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{v['score']}/100")
    c2.metric("Classification", v["classification"])
    c3.metric("First flagged", str(v.get("first_flagged_at") or "unknown"))
    st.subheader("Evidence timeline")
    for evidence in v.get("evidence", []):
        st.write(f"- {evidence}")
    st.caption(f"First listed: {v.get('first_listed_at') or 'not listed yet'}")
    name = st.text_input("Analyst name", key="campaign_analyst_name")
    email = st.text_input("Analyst email", key="campaign_analyst_email")
    if st.button("Create takedown case", key="campaign_create_case"):
        try:
            did = takedown.draft(wh, v, analyst_name=name, analyst_email=email)
            st.success(f"Case {did} created. Continue approval and export in Cases.")
        except ValueError as e:
            st.error(str(e))


def domain_page(wh):
    st.header("Domain details")
    rows = wh.inbox(limit=500)
    if not rows:
        st.info("No flagged domains yet.")
        return
    options = {f"{defang(r['domain'])}  ({r['company_id'][:8]})": r for r in rows}
    v = options[st.selectbox("Domain", list(options), key="d_choice")]
    c1, c2, c3 = st.columns(3)
    c1.metric("Score", f"{v['score']}/100")
    c2.metric("Class", v["classification"])
    c3.metric("Brand", v.get("matched_brand") or "-")
    st.subheader("Why (every point is a rule)")
    st.bar_chart(pd.DataFrame({"points": v["breakdown"]}))
    for e in v["evidence"]:
        st.write("- " + e)
    brief = wh.get_brief(v["domain"], v["company_id"], "English")
    if brief:
        st.subheader("Explanation")
        st.caption(f"source: {brief['source']} {brief.get('model_name') or ''}. Check it against the evidence above.")
        st.write(brief["summary"])
    lead = v.get("first_listed_at")
    st.caption(f"First flagged: {v.get('first_flagged_at')} | First listed: {lead or 'not listed yet'}")
    st.subheader("Feedback history")
    hist = wh.feedback_history(v["domain"], v["company_id"])
    st.dataframe(pd.DataFrame(hist) if hist else pd.DataFrame([{"info": "no labels yet"}]), hide_index=True)
    st.subheader("Decide")
    name = st.text_input("Your name", key="an_name")
    email = st.text_input("Your email", key="an_email")
    note = st.text_input("Note (optional)", key="an_note")
    col1, col2, col3 = st.columns(3)
    for col, label, text in ((col1, "CONFIRMED_THREAT", "Confirm threat"), (col2, "FALSE_POSITIVE", "False positive")):
        if col.button(text, key=f"btn_{label}"):
            if not name.strip() or not email.strip():
                st.error("Enter your name and email first.")
            else:
                wh.add_feedback({"domain": v["domain"], "company_id": v["company_id"], "analyst_email": email.strip(),
                                 "label": label, "note": note})
                st.success(f"Recorded {label} by {name.strip()}.")
    if col3.button("Draft takedown report", key="btn_draft"):
        try:
            did = takedown.draft(wh, v, analyst_name=name, analyst_email=email)
            st.success(f"Draft created: {did}. Review it on the Takedowns page.")
        except ValueError as e:
            st.error(str(e))


def takedown_page(wh):
    st.header("Takedown drafts")
    st.caption("Nothing here is sent by DomainGuard. Approving needs the exact signature sentence; export is manual.")
    drafts = wh.list_takedowns()
    if not drafts:
        st.info("No drafts yet. Create one from the Domain details page.")
        return
    for d in drafts:
        with st.expander(f"{d['status']}: {d['subject'][:90]}  [{d['draft_id'][:8]}]", expanded=d["status"] == "DRAFT"):
            st.caption(f"source: {d['source']} | created {d['created_at']} | analyst {d['analyst_name']} <{d['analyst_email']}>")
            st.text_area("Draft", d["draft_text"], height=220, key=f"txt_{d['draft_id']}", disabled=True)
            if d["status"] == "DRAFT":
                name = st.text_input("Approver name", key=f"apn_{d['draft_id']}")
                email = st.text_input("Approver email", key=f"ape_{d['draft_id']}")
                sig = st.text_input(f"Type exactly: {takedown.SIGNATURE}", key=f"sig_{d['draft_id']}")
                a, r = st.columns(2)
                if a.button("Approve", key=f"ok_{d['draft_id']}"):
                    try:
                        takedown.approve(wh, d["draft_id"], analyst_name=name, analyst_email=email, signature=sig)
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
                if r.button("Reject", key=f"no_{d['draft_id']}"):
                    try:
                        takedown.reject(wh, d["draft_id"], analyst_name=name)
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
            elif d["status"] == "APPROVED":
                if st.button("Export text for manual submission", key=f"ex_{d['draft_id']}"):
                    st.code(takedown.export_text(wh, d["draft_id"]))
            elif d["status"] == "EXPORTED":
                if st.button("I submitted it myself (mark SENT)", key=f"sent_{d['draft_id']}"):
                    takedown.mark_sent_manually(wh, d["draft_id"], analyst_name=d["analyst_name"])
                    st.rerun()


def evaluation_page(wh):
    st.header("Evaluation")
    wl = WarehouseWatchlist(wh).current()
    rep = evaluation.full_report(wh, wl, minutes=st.number_input("Minutes per manual check", 0.5, 60.0, 5.0, key="mins"))
    p, r, lt, h = rep["precision"], rep["recall"], rep["lead_time"], rep["analyst_hours"]
    c = st.columns(4)
    c[0].metric("Precision", "n/a" if p["precision"] is None else p["precision"], help="(confirmed or blocklisted) / flagged")
    c[1].metric("Recall (before listing)", "n/a" if r["recall"] is None else r["recall"])
    c[2].metric("Median lead time (h)", "n/a" if lt["median"] is None else lt["median"])
    c[3].metric("Analyst hours saved", h["hours_saved"])
    st.caption(f"Lead time p25 {lt['p25']}h, p75 {lt['p75']}h. Score-only precision (no blocklist): {p['precision_score_only']}.")
    st.subheader("Weight sensitivity (reporting only)")
    rows = evaluation.weight_rows(wh)
    st.caption(f"{len(rows)} labelled domains.")
    cand = {}
    from domainguard.scoring import WEIGHTS
    for f, w in WEIGHTS.items():
        m = st.number_input(f"{f} (current {w})", 0.0, 3.0, 1.0, 0.1, key=f"w_{f}")
        cand[f] = round(w * m, 2)
    st.json(evaluation.compare_weights(rows, cand))


def reports_page(wh):
    st.header("Reports")
    flagged = wh.inbox(limit=5000)
    if not flagged:
        st.info("No data yet.")
        return
    df = _rows_df(flagged)
    df["day"] = pd.to_datetime(df["first flagged"]).dt.date
    st.subheader("Detections per day")
    st.bar_chart(df.groupby("day").size())
    st.subheader("Precision by brand (flagged domains with a label)")
    labelled = df[df["review"] != "UNREVIEWED"]
    if len(labelled):
        by = labelled.groupby("brand")["review"].apply(lambda s: round((s == "CONFIRMED_THREAT").mean(), 3))
        st.dataframe(by.rename("precision").reset_index(), hide_index=True)
    else:
        st.caption("No labelled detections yet.")
    st.subheader("False positive rate")
    fp = (df["review"] == "FALSE_POSITIVE").sum()
    st.metric("FP rate (of labelled)", round(fp / max(1, (df["review"] != "UNREVIEWED").sum()), 3))


def admin_page(wh):
    st.header("Admin")
    users = wh.list_users()
    pending = [u for u in users if u["status"] == "PENDING"]
    if pending:
        st.subheader("Pending registrations")
        st.caption("Approve only registrations you have verified through a trusted channel. The API key is shown once.")
        pending_options = {f"{u['name']} — {u['email']} ({u['company_id'][:8]})": u["company_id"] for u in pending}
        pending_id = pending_options[st.selectbox("Registration", list(pending_options), key="pending_registration")]
        if st.button("Approve registration", key="approve_registration"):
            try:
                approved = Registrar(wh).approve_pending(pending_id)
                st.success(f"{approved['name']} is active.")
                st.warning("Copy this API key now. It will not be shown again.")
                st.code(approved["api_key"])
            except RegistrationError as e:
                st.error(str(e))
    st.subheader("Companies")
    st.dataframe(pd.DataFrame([{"company": u["company_id"], "name": u["name"], "status": u["status"],
                                "notifications": u["email_notifications"]} for u in users]), hide_index=True)
    st.subheader("Protected domains")
    options = {f"{u['name']} ({u['company_id'][:8]})": u["company_id"] for u in users}
    if options:
        cid = options[st.selectbox("Company", list(options), key="adm_company")]
        protected = wh.protected_for(cid)
        st.dataframe(pd.DataFrame([{"domain": defang(r["domain"]), "aliases": ", ".join(r["brand_aliases"]),
                                    "verified": r["verified"]} for r in protected]), hide_index=True)
        new = st.text_input("Add domain", key="adm_new")
        if st.button("Add", key="adm_add"):
            try:
                Registrar(wh).add_domain(cid, new)
                st.success("Added.")
            except RegistrationError as e:
                st.error(str(e))
        if protected:
            domain_options = {defang(r["domain"]): r["domain"] for r in protected}
            rm_label = st.selectbox("Remove domain", list(domain_options), key="adm_rm")
            if st.button("Remove", key="adm_rm_btn"):
                try:
                    Registrar(wh).remove_domain(cid, domain_options[rm_label])
                    st.success("Removed.")
                except RegistrationError as e:
                    st.error(str(e))
        else:
            st.info("No registered domains for this company.")
        if st.button("Issue a new API key (shown once)", key="adm_key"):
            st.code(Registrar(wh).rotate_key(cid))
        st.subheader("Email preferences")
        st.json(wh.get_prefs(cid))
    st.subheader("Export")
    flagged = wh.inbox(limit=5000)
    st.download_button("Download threat inbox (CSV)", _rows_df(flagged).to_csv(index=False), "threat_inbox.csv", "text/csv")


def main():
    st.title("DomainGuard analyst dashboard")
    if not _gate():
        return
    wh = _store()
    page = st.sidebar.radio("Workflow", ["Overview", "Investigate", "Watchlist", "Cases"], key="page")
    {"Overview": overview_page, "Investigate": investigate_page, "Watchlist": admin_page,
     "Cases": takedown_page}[page](wh)


main()

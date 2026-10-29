"""End-to-end offline demo of v7. Uses the in-memory test double, so NO Snowflake and NO network are needed.
Everything else is the real code: registration, watchlist, collector, loader, scoring, explanations, alerts, API,
takedown review and evaluation.   python scripts/demo.py"""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

os.environ["DG_ALLOW_MEMORY_WAREHOUSE"] = "1"  # demo only: production refuses this (see factory.py)
os.environ.setdefault("DG_SECRET_KEY", "demo-secret-key-change-me-0123456789")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from domainguard.config import Settings  # noqa: E402
from domainguard.evaluation import full_report  # noqa: E402
from domainguard.factory import make_warehouse  # noqa: E402
from domainguard.ingest import Ingest  # noqa: E402
from domainguard.normalize import defang  # noqa: E402
from domainguard.notifier import RecordingSender, flush_digests, notify_new  # noqa: E402
from domainguard.registration import Registrar  # noqa: E402
from domainguard.takedown import approve, draft, export_text  # noqa: E402
from domainguard.worker import run_briefs  # noqa: E402
from domainguard.watchlist import WarehouseWatchlist  # noqa: E402
from migrate_from_json import plan  # noqa: E402

work = Path(tempfile.mkdtemp(prefix="dg-v7-demo-"))
s = Settings(stage_dir=str(work / "stage"), state_dir=str(work / "state"), web_domain="https://domainguard.example.com",
             secret_key=os.environ["DG_SECRET_KEY"], smtp_from="alerts@domainguard.example.com")
wh = make_warehouse(s)
sender = RecordingSender()
NOW = datetime.now(timezone.utc)  # one clock for the whole run, so lead times are coherent
print("== 1. companies: migrated from data/watchlist.json, plus one self-registration ==")
for item in plan(json.loads((ROOT / "data/watchlist.json").read_text())):
    wh.create_user({**item["company"], "email_notifications": True, "notification_email": item["company"]["email"]})
    for p in item["protected"]:
        wh.upsert_protected(p)
reg = Registrar(wh, clock=lambda: NOW)
out = reg.register(name="Acme Retail", email="security@acme-retail.example", contact_person="Priya",
                   domains=["https://www.acme-retail.example/"])
wh.set_prefs(out["company_id"], {"notification_email": "security@acme-retail.example"})
key = reg.verify(out["token"])["api_key"]
print(f"  registered {out['domains']} -> verified; API key issued ({key[:6]}...), stored hashed only")
print("  companies:", [(u["name"], u["status"]) for u in wh.list_users()])

print("\n== 2. ingest: replay certificate events, pull blocklist, RDAP ages (sample data, offline) ==")
ing = Ingest(s, wh, fetch=lambda u, h=None: (ROOT / "data/sample_blocklist.txt").read_text(),
             lookup=lambda d: (200, json.loads((ROOT / "data/sample_rdap.json").read_text()).get(d), {}) if d in
             json.loads((ROOT / "data/sample_rdap.json").read_text()) else (404, None, {}), sleep=lambda x: None)
print(" replay:", {k: v for k, v in ing.replay(ROOT / "data/sample_events.jsonl").items() if k in ("candidates", "discarded")})
print(" feeds :", ing.feeds_once())
print(" rdap  :", ing.rdap_once(50))

print("\n== 3. load into Bronze (checksums verified, idempotent) and score per company ==")
print(" load  :", {k: v for k, v in ing.load().items() if k != "errors"})
print(" load again:", {k: v for k, v in ing.load().items() if k in ("files_loaded", "files_skipped")})
rep = ing.score(now=NOW)
print(f" score : candidates={rep['candidates']} stored={rep['stored']} newly flagged={len(rep['newly_flagged'])}")

print("\n== 4. threat inbox ==")
for v in wh.inbox(limit=10):
    print(f"  {defang(v['domain']):40} {v['classification']:10} {v['score']:>3}  company={v['company_id'][:8]} "
          f"brand={v['matched_brand']} listed={'yes' if v['is_on_blocklist'] else 'no'}")

print("\n== 5. alerts: immediate for fresh detections, opt-out respected ==")
newly = [v for v in wh.verdicts() if v.get("first_flagged_at") and v["classification"] in ("SUSPICIOUS", "HIGH_RISK", "DANGEROUS")]
now = NOW
res = notify_new(wh, sender, s, newly, NOW)
print("  (only detections flagged in the last hour are alerted at once)")
print("  notify_new:", res, "| emails in outbox:", len(sender.sent))
if sender.sent:
    msg = sender.sent[0]
    body = msg.get_body(preferencelist=("plain",)).get_content()
    print("  sample email to:", msg["To"], "| subject:", msg["Subject"])
    print("  domain shown defanged:", "paypa1-secure-login[.]xyz" in body, "| raw domain anywhere in email:",
          "paypa1-secure-login.xyz" in body or "paypa1-secure-login.xyz" in msg.as_string())

print("\n== 6. explanations (template; set OPENROUTER_API_KEY to use the LLM) ==")
print(" briefs:", run_briefs(wh, s))
top = wh.inbox(limit=1)[0]
b = wh.get_brief(top["domain"], top["company_id"], "English")
print(f"  {b['summary']}")
print(f"  reasons: {b['reasons'][:2]}")

print("\n== 7. public API, in process (no network) ==")
from fastapi.testclient import TestClient  # noqa: E402
from domainguard.api import create_app  # noqa: E402
api = TestClient(create_app(wh, s, sender=sender, clock=lambda: NOW))
for text in ("paypa1-secure-login.xyz", "https://login.abcbank.com/", "brand-new-lookalike-abcbannk.com", "not a link"):
    r = api.post("/check", json={"input": text})
    j = r.json()
    print(f"  /check {text!r:38} -> {r.status_code} " + (f"{j['verdict']} {j['score']} basis={j['basis']}" if r.status_code == 200 else j["detail"]))
scan = api.post("/scan-message", json={"text": "URGENT: your account will be blocked. Verify KYC at http://abcbannk-login.com now"}).json()
print("  /scan-message:", scan["links_found"], "link(s), worst =", scan["worst_verdict"], "tactics =", scan["message_analysis"]["tactics"])
inbox = api.get("/analyst/inbox?min_score=0", headers={"Authorization": f"Bearer {key}"}).json()
print("  /analyst/inbox (Acme key, min_score=0):", inbox["count"], "domain(s):", [d["domain"] for d in inbox["domains"]])
print("  /analyst/inbox without an API key ->", api.get("/analyst/inbox").status_code)

print("\n== 8. evaluation ==")
ev = full_report(wh, WarehouseWatchlist(wh).current())
print("  (lead time is empty here: the blocklist was pulled in the same run as the scoring; v3 showed a timeline)")
print("  precision:", ev["precision"]["precision"], "| recall:", ev["recall"]["recall"],
      "| lead time median h:", ev["lead_time"]["median"], "| analyst hours saved:", ev["analyst_hours"]["hours_saved"])

print("\n== 9. takedown: draft -> approve (exact signature) -> export. Nothing is sent. ==")
did = draft(wh, top, analyst_name="Ravi Kumar", analyst_email="ravi@example.test")
print("  draft status:", wh.get_takedown(did)["status"])
approve(wh, did, analyst_name="Ravi Kumar", analyst_email="ravi@example.test",
        signature="I confirm this is accurate and I approve sending")
print("  after approval:", wh.get_takedown(did)["status"])
print("  export preview:", export_text(wh, did).splitlines()[0][:90], "...")
print(f"\nFiles written under: {work}")

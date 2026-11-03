from datetime import timedelta

from domainguard.memory_warehouse import MemoryWarehouse
from domainguard.notifier import RecordingSender, alert_message, check_url, flush_digests, notify_new, send_api_key, send_verification
from domainguard.pipeline import score_all
from domainguard.watchlist import WarehouseWatchlist
from tests.helpers import T0, ISO, company, cert_row, rdap_row, seed_bronze, settings

RAW = "paypa1-secure-login.xyz"  # scores 88 with a 2 h age: above the default alert threshold of 70


def flagged(tmp_path, *, notify=True, freq="IMMEDIATE", now=T0):
    wh = MemoryWarehouse()
    company(wh, "paypal", "paypal.com", email="sec@paypal.test", notify=notify, freq=freq)
    seed_bronze(wh, certs=[cert_row(RAW, brand="paypal")], rdap=[rdap_row(RAW, ISO(now - timedelta(hours=2)))])
    score_all(wh, WarehouseWatchlist(wh).per_company(), now=now)
    newly = [v for v in wh.verdicts() if v.get("first_flagged_at")]
    return wh, newly, settings(tmp_path)


def test_alert_format_is_defanged_and_never_links_the_suspicious_site(tmp_path):
    wh, newly, s = flagged(tmp_path)
    sender = RecordingSender()
    notify_new(wh, sender, s, newly, T0)
    msg = sender.sent[0]
    body = msg.get_body(preferencelist=("plain",)).get_content()
    assert msg["Subject"].startswith("⚠️ ALERT: Suspicious domain resembling your brand detected")
    assert "paypa1-secure-login[.]xyz" in body and RAW not in msg.as_string()  # raw name appears nowhere
    assert "https://dg.example.test/check?domain=" in body               # link goes to OUR checker
    assert "Do NOT click the link" in body and "unsubscribe" in body.lower()


def test_html_alternative_is_escaped(tmp_path):
    wh, newly, s = flagged(tmp_path)
    v = {**newly[0], "evidence": ["<script>alert(1)</script>"]}
    msg = alert_message(s, wh.get_user("cid-paypal"), v, "x@y.test", T0)
    html_part = msg.get_body(preferencelist=("html",)).get_content()
    assert "<script>" not in html_part and "&lt;script&gt;" in html_part


def test_check_link_carries_defanged_domain(tmp_path):
    s = settings(tmp_path)
    assert check_url(s, RAW).endswith("check?domain=paypa1-secure-login%5B.%5Dxyz")


def test_opt_out_threshold_and_stale_detections_are_skipped(tmp_path):
    wh, newly, s = flagged(tmp_path, notify=False)
    assert notify_new(wh, RecordingSender(), s, newly, T0)["sent"] == 0
    wh2, newly2, s2 = flagged(tmp_path)
    wh2.set_prefs("cid-paypal", {"min_score_threshold": 99})
    assert notify_new(wh2, RecordingSender(), s2, newly2, T0)["skipped"] == 1
    wh3, newly3, s3 = flagged(tmp_path)
    assert notify_new(wh3, RecordingSender(), s3, newly3, T0 + timedelta(hours=3))["skipped"] == 1  # older than 1 hour


def test_each_domain_alerted_once_and_every_send_is_logged(tmp_path):
    wh, newly, s = flagged(tmp_path)
    sender = RecordingSender()
    notify_new(wh, sender, s, newly, T0)
    again = notify_new(wh, sender, s, newly, T0)
    assert len(sender.sent) == 1 and again["skipped"] == 1
    log = wh.email_log("cid-paypal")
    assert len(log) == 1 and log[0]["status"] == "SENT" and log[0]["kind"] == "ALERT" and log[0]["score"] == 88


def test_send_failure_is_logged_not_raised(tmp_path):
    wh, newly, s = flagged(tmp_path)
    res = notify_new(wh, RecordingSender(fail=True), s, newly, T0)
    assert res["failed"] == 1 and wh.email_log()[0]["status"] == "FAILED" and "unavailable" in wh.email_log()[0]["error"]


def test_digest_sent_once_per_interval(tmp_path):
    wh, newly, s = flagged(tmp_path, freq="DAILY")
    sender = RecordingSender()
    assert notify_new(wh, sender, s, newly, T0)["queued_for_digest"] == 1 and sender.sent == []
    out = flush_digests(wh, sender, s, T0)
    assert out["digests_sent"] == 1 and "Your daily summary" in sender.sent[0].get_body(preferencelist=("plain",)).get_content()
    assert flush_digests(wh, sender, s, T0 + timedelta(hours=5))["digests_sent"] == 0
    assert flush_digests(wh, sender, s, T0 + timedelta(days=1, minutes=1))["digests_sent"] == 0  # all already alerted


def test_account_emails_carry_otp_and_never_api_key(tmp_path):
    s = settings(tmp_path)
    sender = RecordingSender()
    send_verification(sender, s, "a@b.test", "Acme", "123456")
    assert "123456" in sender.sent[0].get_body(preferencelist=("plain",)).get_content()
    send_api_key(sender, s, "a@b.test", "Acme", "dg_secretvalue")
    body = sender.sent[1].get_body(preferencelist=("plain",)).get_content()
    assert "dg_secretvalue" not in body and "never sent by email" in body

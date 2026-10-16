"""Offline billing tests — Stripe's API is mocked. Run with:  python tests/test_billing.py

Example from a real product (a domain-monitoring SaaS): "domains" are the plan-limited unit and
`jobs.run_scan` is the engine being faked. Rename those to your product's unit/engine when adapting.
"""
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["MyProduct_DB"] = os.path.join(tempfile.mkdtemp(), "billing.db")
os.environ["DISABLE_SCHEDULER"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app import billing, config, db, jobs, main  # noqa: E402
from app.scoring import score_findings  # noqa: E402

WHSEC = "whsec_test_secret"
PRICES = {"pro": "price_pro_123", "msp": "price_msp_456"}


async def _fake_scan(domain, verified=False):
    s, g = score_findings([])
    return {"domain": domain, "verified": verified, "score": s, "grade": g, "findings": [], "facts": {},
            "incomplete": [], "started_at": "2026-10-16T10:00:00+00:00", "duration_s": 0.1}

jobs.run_scan = _fake_scan
db.init()


def stripe_on():
    config.STRIPE_SECRET_KEY = "sk_test_fake"
    config.STRIPE_WEBHOOK_SECRET = WHSEC
    config.STRIPE_PRICES.update(PRICES)


def stripe_off():
    config.STRIPE_SECRET_KEY = ""
    config.STRIPE_WEBHOOK_SECRET = ""
    config.STRIPE_PRICES.update({"pro": "", "msp": ""})


def sign(payload: bytes, secret=WHSEC, ts=None):
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def subscription(sub_id, customer, price, status="active"):
    return {"id": sub_id, "object": "subscription", "customer": customer, "status": status,
            "metadata": {}, "items": {"data": [{"price": {"id": price}}]}}


def event(evt_id, typ, obj):
    return json.dumps({"id": evt_id, "type": typ, "data": {"object": obj}}).encode()


_n = 0


def new_user(plan="free"):
    global _n
    _n += 1
    uid = db.create_user(f"user{_n}@example.com", "x")
    db.set_plan(uid, plan)
    return uid


def csrf_of(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def logged_in_client(c, email):
    token = csrf_of(c.get("/register").text)
    c.post("/register", data={"email": email, "password": "correct-horse-1", "csrf": token})
    return csrf_of(c.get("/dashboard").text), db.get_user_by_email(email)


# ---------------------------------------------------------------- signature

def test_signature_verification():
    body = b'{"id":"evt_1"}'
    assert billing.verify_signature(body, sign(body), WHSEC)["id"] == "evt_1"
    for header in [sign(body, secret="whsec_wrong"), sign(body, ts=int(time.time()) - 3600), "garbage", ""]:
        try:
            billing.verify_signature(body, header, WHSEC)
            raise AssertionError(f"accepted bad signature: {header}")
        except billing.BillingError:
            pass
    # tampered payload with a valid-looking header
    try:
        billing.verify_signature(b'{"id":"evt_2"}', sign(body), WHSEC)
        raise AssertionError("accepted tampered payload")
    except billing.BillingError:
        pass


def test_form_encoding():
    flat = dict(billing._flatten({"line_items": [{"price": "p", "quantity": 1}], "metadata": {"plan": "pro"},
                                   "allow_promotion_codes": True, "skip": None}))
    assert flat == {"line_items[0][price]": "p", "line_items[0][quantity]": "1",
                    "metadata[plan]": "pro", "allow_promotion_codes": "true"}


# ---------------------------------------------------------------- webhooks

def test_webhook_lifecycle():
    stripe_on()
    uid = new_user()
    db.set_billing(uid, customer_id="cus_A")
    with TestClient(main.app) as c:
        def post(body, header=None):
            return c.post("/stripe/webhook", content=body,
                          headers={"stripe-signature": header or sign(body), "content-type": "application/json"})

        assert post(b"{}", header="t=1,v1=bad").status_code == 400

        body = event("evt_A1", "customer.subscription.created", subscription("sub_A", "cus_A", PRICES["pro"]))
        assert post(body).json() == {"status": "ok"}
        u = db.get_user(uid)
        assert (u["plan"], u["stripe_subscription_id"], u["subscription_status"]) == ("pro", "sub_A", "active")

        # Stripe retries deliveries: the same event must be processed only once
        assert post(body).json() == {"status": "duplicate"}

        # upgrade via portal
        post(event("evt_A2", "customer.subscription.updated", subscription("sub_A", "cus_A", PRICES["msp"])))
        assert db.get_user(uid)["plan"] == "msp"

        # failed payment -> past_due keeps the plan during Stripe's retry period
        post(event("evt_A3", "customer.subscription.updated", subscription("sub_A", "cus_A", PRICES["msp"], "past_due")))
        assert (db.get_user(uid)["plan"], db.get_user(uid)["subscription_status"]) == ("msp", "past_due")

        # cancellation -> free
        post(event("evt_A4", "customer.subscription.deleted", subscription("sub_A", "cus_A", PRICES["msp"], "canceled")))
        u = db.get_user(uid)
        assert (u["plan"], u["stripe_subscription_id"]) == ("free", None)


def test_old_subscription_cancel_does_not_downgrade():
    stripe_on()
    uid = new_user()
    db.set_billing(uid, customer_id="cus_B")
    billing.handle_event(json.loads(event("evt_B1", "customer.subscription.created", subscription("sub_new", "cus_B", PRICES["pro"]))))
    billing.handle_event(json.loads(event("evt_B2", "customer.subscription.deleted",
                                          subscription("sub_old", "cus_B", PRICES["pro"], "canceled"))))
    assert db.get_user(uid)["plan"] == "pro"


def test_unknown_price_is_not_granted():
    stripe_on()
    uid = new_user()
    db.set_billing(uid, customer_id="cus_C")
    billing.handle_event(json.loads(event("evt_C1", "customer.subscription.created",
                                          subscription("sub_C", "cus_C", "price_someone_elses"))))
    assert db.get_user(uid)["plan"] == "free"


# ---------------------------------------------------------------- checkout routes

def test_checkout_and_success_sync():
    stripe_on()
    calls = []

    async def fake_stripe(method, path, data=None, idempotency_key=None):
        calls.append((method, path, data))
        if path == "/customers":
            return {"id": "cus_D"}
        if path == "/checkout/sessions":
            return {"url": "https://checkout.stripe.com/c/pay/cs_test_D"}
        if path.startswith("/checkout/sessions/cs_test_D"):
            return {"status": "complete", "client_reference_id": str(fake_stripe.uid),
                    "subscription": subscription("sub_D", "cus_D", PRICES["msp"])}
        if path.startswith("/checkout/sessions/cs_test_other"):
            return {"status": "complete", "client_reference_id": "999999",
                    "subscription": subscription("sub_X", "cus_X", PRICES["msp"])}
        if path == "/billing_portal/sessions":
            return {"url": "https://billing.stripe.com/p/session/test"}
        raise AssertionError(path)

    billing.stripe_request = fake_stripe
    with TestClient(main.app) as c:
        token, user = logged_in_client(c, "buyer@example.com")
        fake_stripe.uid = user["id"]

        # demo switch is disabled once Stripe is configured
        assert c.post("/billing/plan", data={"plan": "msp", "csrf": token}).status_code == 404
        assert "Upgrade to Pro" in c.get("/pricing").text

        r = c.post("/billing/checkout", data={"plan": "msp", "csrf": token}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("https://checkout.stripe.com/")
        session_data = next(d for m, p, d in calls if p == "/checkout/sessions")
        assert session_data["line_items"][0]["price"] == PRICES["msp"]
        assert session_data["client_reference_id"] == user["id"]
        assert db.get_user(user["id"])["stripe_customer_id"] == "cus_D"

        # a session belonging to another user must not upgrade this account
        c.get("/billing/success?session_id=cs_test_other")
        assert db.get_user(user["id"])["plan"] == "free"

        r = c.get("/billing/success?session_id=cs_test_D")
        assert "Thank you" in r.text and db.get_user(user["id"])["plan"] == "msp"

        # subscribers are sent to the portal instead of a second checkout
        r = c.post("/billing/checkout", data={"plan": "pro", "csrf": token}, follow_redirects=False)
        assert r.headers["location"].startswith("https://billing.stripe.com/")


def test_downgrade_pauses_extra_domains():
    stripe_off()
    with TestClient(main.app) as c:
        token, user = logged_in_client(c, "downgrade@example.com")
        db.set_plan(user["id"], "pro")
        for name in ["a1.com", "a2.com", "a3.com"]:
            c.post("/domains", data={"domain": name, "csrf": token})
        time.sleep(0.3)
        db.set_plan(user["id"], "free")
        ids = [d["id"] for d in sorted(db.list_domains(user["id"]), key=lambda d: d["id"])]
        assert db.paused_domain_ids(user["id"], "free") == set(ids[1:])
        with db.conn() as conn:
            conn.execute("UPDATE domains SET last_scan_at='2000-01-01T00:00:00+00:00' WHERE user_id=?", (user["id"],))
        due = {d["id"] for d in db.domains_due_for_scan() if d["user_id"] == user["id"]}
        assert due == {ids[0]}
        assert "2 domain(s) are paused" in c.get("/dashboard").text
        r = c.post(f"/domains/{ids[2]}/scan", data={"csrf": token})
        assert "paused" in r.text


def test_security_headers_and_production_guard():
    with TestClient(main.app) as c:
        h = c.get("/").headers
        assert "script-src 'self'" in h["content-security-policy"]
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert c.get("/docs").status_code == 404
    saved = config.IS_PRODUCTION
    config.IS_PRODUCTION = True
    try:
        config.check_production()
        raise AssertionError("production started without secrets")
    except RuntimeError as e:
        assert "SESSION_SECRET" in str(e)
    finally:
        config.IS_PRODUCTION = saved


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)

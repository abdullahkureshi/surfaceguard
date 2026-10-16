"""Stripe subscriptions via the REST API (no SDK needed).

Flow: pricing page -> /billing/checkout -> Stripe Checkout -> /billing/success.
Stripe webhooks are the source of truth for the user's plan; the success page also
syncs immediately so the user doesn't wait for the webhook.
"""
import hashlib
import hmac
import json
import logging
import time

import httpx

from . import config, db

log = logging.getLogger("MyProduct.billing")
API = "https://api.stripe.com/v1"
ACTIVE_STATUSES = {"active", "trialing", "past_due"}  # past_due = grace period while Stripe retries


class BillingError(Exception):
    pass


def _flatten(data, prefix=""):
    """Stripe expects form encoding with bracket notation: line_items[0][price]=..."""
    out = []
    items = data.items() if isinstance(data, dict) else enumerate(data)
    for k, v in items:
        key = f"{prefix}[{k}]" if prefix else str(k)
        if isinstance(v, (dict, list)):
            out += _flatten(v, key)
        elif isinstance(v, bool):
            out.append((key, "true" if v else "false"))
        elif v is not None:
            out.append((key, str(v)))
    return out


async def stripe_request(method, path, data=None, idempotency_key=None):
    headers = {"Authorization": f"Bearer {config.STRIPE_SECRET_KEY}", "Stripe-Version": "2024-06-20"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.request(method, API + path, data=_flatten(data) if data else None, headers=headers)
    body = r.json()
    if r.status_code >= 400:
        msg = body.get("error", {}).get("message", r.text)
        log.error("Stripe %s %s failed: %s", method, path, msg)
        raise BillingError(msg)
    return body


def plan_for_price(price_id):
    return next((plan for plan, pid in config.STRIPE_PRICES.items() if pid and pid == price_id), None)


# ---------------------------------------------------------------- checkout & portal

async def ensure_customer(user):
    if user["stripe_customer_id"]:
        return user["stripe_customer_id"]
    cust = await stripe_request("POST", "/customers", {"email": user["email"], "metadata": {"user_id": user["id"]}},
                                idempotency_key=f"customer-{user['id']}")
    db.set_billing(user["id"], customer_id=cust["id"])
    return cust["id"]


async def create_checkout(user, plan):
    if plan not in config.STRIPE_PRICES:
        raise BillingError("Unknown plan")
    customer = await ensure_customer(user)
    session = await stripe_request("POST", "/checkout/sessions", {
        "mode": "subscription",
        "customer": customer,
        "client_reference_id": user["id"],
        "line_items": [{"price": config.STRIPE_PRICES[plan], "quantity": 1}],
        "success_url": f"{config.BASE_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{config.BASE_URL}/pricing",
        "allow_promotion_codes": True,
        "billing_address_collection": "required",  # needed for EU VAT invoices
        "tax_id_collection": {"enabled": True},
        "customer_update": {"name": "auto", "address": "auto"},
        "metadata": {"user_id": user["id"], "plan": plan},
        "subscription_data": {"metadata": {"user_id": user["id"], "plan": plan}},
    })
    return session["url"]


async def create_portal(user):
    if not user["stripe_customer_id"]:
        raise BillingError("No billing account yet")
    session = await stripe_request("POST", "/billing_portal/sessions",
                                   {"customer": user["stripe_customer_id"], "return_url": f"{config.BASE_URL}/dashboard"})
    return session["url"]


async def sync_checkout_session(user, session_id):
    """Called from the success page. Only trusts sessions that belong to this user."""
    s = await stripe_request("GET", f"/checkout/sessions/{session_id}?expand[]=subscription")
    if str(s.get("client_reference_id")) != str(user["id"]) or s.get("status") != "complete":
        return None
    sub = s.get("subscription")
    if isinstance(sub, dict):
        apply_subscription(sub)
    return db.get_user(user["id"])["plan"]


# ---------------------------------------------------------------- webhooks

def verify_signature(payload: bytes, header: str, secret: str, tolerance=300):
    """Stripe-Signature: t=<ts>,v1=<hmac>[,v1=...]  with  hmac = HMAC_SHA256(secret, f"{t}.{payload}")."""
    try:
        parts = [p.split("=", 1) for p in header.split(",")]
        ts = int(next(v for k, v in parts if k == "t"))
        sigs = [v for k, v in parts if k == "v1"]
    except (StopIteration, ValueError):
        raise BillingError("Malformed signature header")
    if abs(time.time() - ts) > tolerance:
        raise BillingError("Signature timestamp outside tolerance")
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise BillingError("Signature mismatch")
    return json.loads(payload)


def apply_subscription(sub):
    """Set the user's plan from a Stripe subscription object."""
    user = db.get_user_by_customer(sub["customer"])
    if not user:
        uid = (sub.get("metadata") or {}).get("user_id")
        user = db.get_user(int(uid)) if uid and uid.isdigit() else None
        if not user:
            log.warning("subscription %s for unknown customer %s", sub["id"], sub["customer"])
            return
        db.set_billing(user["id"], customer_id=sub["customer"])
    items = (sub.get("items") or {}).get("data") or []
    plan = plan_for_price(items[0]["price"]["id"]) if items else None
    status = sub["status"]
    if status in ACTIVE_STATUSES and plan:
        db.set_billing(user["id"], plan=plan, subscription_id=sub["id"], status=status)
    elif user["stripe_subscription_id"] in (None, sub["id"]):
        # Only downgrade if this is the user's current subscription (not an old, replaced one).
        db.set_billing(user["id"], plan="free", subscription_id=None, status=status)
    log.info("subscription %s (%s): user %s is now on plan %s", sub["id"], status, user["id"],
             db.get_user(user["id"])["plan"])


def handle_event(event):
    if not db.record_stripe_event(event["id"], event["type"]):
        return "duplicate"
    obj = event["data"]["object"]
    t = event["type"]
    if t in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
        apply_subscription(obj)
    elif t == "checkout.session.completed":
        uid = obj.get("client_reference_id")
        if uid and str(uid).isdigit() and obj.get("customer"):
            db.set_billing(int(uid), customer_id=obj["customer"])
        # The plan itself is set by customer.subscription.created, which Stripe sends as well.
    elif t == "invoice.payment_failed":
        log.warning("payment failed for customer %s", obj.get("customer"))
    return "ok"

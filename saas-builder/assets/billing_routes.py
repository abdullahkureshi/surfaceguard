"""Billing routes and security middleware for app/main.py — paste in and adapt.

Assumes these helpers already exist in main.py (see stack-blueprint.md): render, flash, redirect,
require_user, require_csrf, plus `templates`, `app`, and imports of `billing`, `config`, `db`, `re`,
`HTTPException`, `JSONResponse`, `Form`, `Request`.
"""

# ---------------------------------------------------------------- startup guard + app
config.check_production()  # at import time, before the app object is created
app = FastAPI(title="MyProduct", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

# ---------------------------------------------------------------- security headers (strict CSP: no inline JS)
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self' https://checkout.stripe.com https://billing.stripe.com")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if config.BASE_URL.startswith("https://"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


app.add_middleware(SessionMiddleware, secret_key=auth.secret_key(), same_site="lax",
                   https_only=config.BASE_URL.startswith("https://"), max_age=60 * 60 * 24 * 14)
templates.env.globals["billing_mode"] = config.billing_mode


def _asset_version():
    """Hash of static files, used as ?v= on asset URLs so browsers fetch fresh copies after deploys."""
    h = hashlib.sha256()
    for name in sorted(os.listdir(os.path.join(HERE, "static"))):
        with open(os.path.join(HERE, "static", name), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:10]


templates.env.globals["asset_version"] = _asset_version()


def client_ip(request):
    """Real visitor IP behind the hosting proxy (CLIENT_IP_HEADER=Fly-Client-IP), for rate limiting."""
    if config.CLIENT_IP_HEADER and request.headers.get(config.CLIENT_IP_HEADER):
        return request.headers[config.CLIENT_IP_HEADER]
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- billing routes

@app.post("/billing/plan")
def change_plan(request: Request, plan: str = Form(...), csrf: str = Form("")):
    """Demo plan switch for local development only (DEMO_BILLING=1, no Stripe keys, not production)."""
    require_csrf(request, csrf)
    user = require_user(request)
    if config.billing_mode() != "demo":
        raise HTTPException(404)
    if plan not in db.PLANS:
        raise HTTPException(400, "Unknown plan")
    db.set_plan(user["id"], plan)
    flash(request, f"You're now on the {db.PLANS[plan]['name']} plan (demo — no payment taken).")
    return redirect("/dashboard")


@app.post("/billing/checkout")
async def billing_checkout(request: Request, plan: str = Form(...), csrf: str = Form("")):
    require_csrf(request, csrf)
    user = require_user(request)
    if config.billing_mode() != "stripe":
        raise HTTPException(404)
    try:
        if user["subscription_status"] in billing.ACTIVE_STATUSES:
            # Already subscribed: plan changes and cancellation happen in the Stripe customer portal.
            return redirect(await billing.create_portal(user))
        return redirect(await billing.create_checkout(user, plan))
    except billing.BillingError:
        flash(request, "We couldn't start checkout. Please try again in a minute.", "error")
        return redirect("/pricing")


@app.get("/billing/success")
async def billing_success(request: Request, session_id: str = ""):
    user = require_user(request)
    plan = None
    if config.billing_mode() == "stripe" and re.fullmatch(r"cs_[A-Za-z0-9_]+", session_id):
        try:
            plan = await billing.sync_checkout_session(user, session_id)
        except billing.BillingError:
            pass
    if plan and plan != "free":
        flash(request, f"Thank you! You're now on the {db.PLANS[plan]['name']} plan.")
    else:
        flash(request, "Payment received — your plan will update in a few seconds.")
    return redirect("/dashboard")


@app.post("/billing/portal")
async def billing_portal(request: Request, csrf: str = Form("")):
    require_csrf(request, csrf)
    user = require_user(request)
    try:
        return redirect(await billing.create_portal(user))
    except billing.BillingError:
        flash(request, "No billing account found yet.", "error")
        return redirect("/pricing")


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not config.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(404)
    payload = await request.body()  # raw bytes: the signature is over the exact body
    try:
        event = billing.verify_signature(payload, request.headers.get("stripe-signature", ""),
                                         config.STRIPE_WEBHOOK_SECRET)
    except (billing.BillingError, ValueError):
        return JSONResponse({"error": "invalid signature"}, status_code=400)
    return {"status": billing.handle_event(event)}


@app.get("/healthz")
def healthz():
    return {"ok": True}

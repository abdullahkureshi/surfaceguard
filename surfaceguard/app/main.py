import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.sessions import SessionMiddleware

from . import auth, billing, config, db, jobs
from .scanner import ScanError, dns_txt, normalize_domain, run_scan
from .scoring import severity_counts

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # don't log every scanner request
HERE = os.path.dirname(__file__)
VERIFY_PREFIX = "surfaceguard-verify="
config.check_production()


@asynccontextmanager
async def lifespan(app):
    db.init()
    task = None
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        task = asyncio.create_task(jobs.scheduler_loop())
    yield
    if task:
        task.cancel()


app = FastAPI(title="SurfaceGuard", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

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
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))
templates.env.globals["PLANS"] = db.PLANS
templates.env.globals["billing_mode"] = config.billing_mode


def _asset_version():
    """Hash of the static files, appended to their URLs so browsers fetch fresh copies after each deploy."""
    h = hashlib.sha256()
    for name in sorted(os.listdir(os.path.join(HERE, "static"))):
        with open(os.path.join(HERE, "static", name), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:10]


templates.env.globals["asset_version"] = _asset_version()


def inline_code(text):
    """Escape text, then render `backticks` as <code> (finding fixes use them for DNS records/headers)."""
    return Markup(re.sub(r"`([^`]+)`", r"<code>\1</code>", str(escape(text or ""))))


templates.env.filters["md"] = inline_code


# ---------------------------------------------------------------- helpers

def render(request, name, **ctx):
    ctx.setdefault("user", current_user(request))
    ctx["csrf"] = auth.csrf_token(request.session)
    ctx["flash"] = request.session.pop("flash", None)
    return templates.TemplateResponse(request, name, ctx)


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def redirect(url):
    return RedirectResponse(url, status_code=303)


def current_user(request):
    uid = request.session.get("uid")
    return db.get_user(uid) if uid else None


def require_user(request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_csrf(request, token):
    if not auth.check_csrf(request.session, token):
        raise HTTPException(status_code=400, detail="Form expired, please go back and try again.")


def owned_domain(request, domain_id):
    user = require_user(request)
    d = db.get_domain(domain_id, user["id"])
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    return user, d


def parse_result(scan_row):
    if not scan_row or not scan_row["result_json"]:
        return None
    r = json.loads(scan_row["result_json"])
    r["counts"] = severity_counts(r["findings"])
    return r


_free_checks = defaultdict(deque)


def client_ip(request):
    if config.CLIENT_IP_HEADER and request.headers.get(config.CLIENT_IP_HEADER):
        return request.headers[config.CLIENT_IP_HEADER]
    return request.client.host if request.client else "unknown"


def rate_limited(ip, limit=5, window=3600):
    q = _free_checks[ip]
    while q and q[0] < time.time() - window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(time.time())
    return False


# ---------------------------------------------------------------- public pages

@app.get("/")
def landing(request: Request):
    return render(request, "landing.html")


@app.get("/pricing")
def pricing(request: Request):
    return render(request, "pricing.html")


@app.post("/check")
async def free_check(request: Request, domain: str = Form(...), csrf: str = Form("")):
    require_csrf(request, csrf)
    if rate_limited(client_ip(request)):
        return render(request, "landing.html", error="You've run several free checks recently. "
                      "Create a free account to keep monitoring.", domain=domain)
    try:
        result = await asyncio.wait_for(run_scan(domain, verified=False), timeout=90)
    except ScanError as e:
        return render(request, "landing.html", error=str(e), domain=domain)
    except asyncio.TimeoutError:
        return render(request, "landing.html", error="The scan took too long. Please try again.", domain=domain)
    result["counts"] = severity_counts(result["findings"])
    return render(request, "check_result.html", r=result)


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------------------------------------------------------- accounts

@app.get("/register")
def register_form(request: Request, domain: str = ""):
    return render(request, "auth.html", mode="register", domain=domain)


@app.post("/register")
async def register(request: Request, email: str = Form(...), password: str = Form(...),
                   domain: str = Form(""), csrf: str = Form("")):
    require_csrf(request, csrf)
    email = email.strip().lower()
    if not auth.EMAIL_RE.match(email):
        return render(request, "auth.html", mode="register", error="Please enter a valid email.", email=email, domain=domain)
    if len(password) < 10:
        return render(request, "auth.html", mode="register", error="Password must be at least 10 characters.",
                      email=email, domain=domain)
    try:
        uid = db.create_user(email, auth.hash_password(password))
    except sqlite3.IntegrityError:
        return render(request, "auth.html", mode="register", error="An account with this email already exists.",
                      email=email, domain=domain)
    request.session.clear()
    request.session["uid"] = uid
    if domain:
        return await _add_domain(request, db.get_user(uid), domain)
    flash(request, "Welcome to SurfaceGuard! Add your first domain to start monitoring.")
    return redirect("/dashboard")


@app.get("/login")
def login_form(request: Request):
    return render(request, "auth.html", mode="login")


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), csrf: str = Form("")):
    require_csrf(request, csrf)
    user = db.get_user_by_email(email.strip().lower())
    if not user or not auth.verify_password(password, user["pw_hash"]):
        return render(request, "auth.html", mode="login", error="Wrong email or password.", email=email)
    request.session.clear()
    request.session["uid"] = user["id"]
    return redirect("/dashboard")


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    require_csrf(request, csrf)
    request.session.clear()
    return redirect("/")


# ---------------------------------------------------------------- billing

@app.post("/billing/plan")
def change_plan(request: Request, plan: str = Form(...), csrf: str = Form("")):
    """Demo plan switch for local development only (no Stripe keys configured)."""
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
    if user["subscription_status"] in billing.ACTIVE_STATUSES:
        # Already subscribed: plan changes and cancellation happen in the Stripe customer portal.
        return redirect(await billing.create_portal(user))
    try:
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
    payload = await request.body()
    try:
        event = billing.verify_signature(payload, request.headers.get("stripe-signature", ""),
                                         config.STRIPE_WEBHOOK_SECRET)
    except (billing.BillingError, ValueError):
        return JSONResponse({"error": "invalid signature"}, status_code=400)
    return {"status": billing.handle_event(event)}


# ---------------------------------------------------------------- dashboard & domains

@app.get("/dashboard")
def dashboard(request: Request):
    user = require_user(request)
    paused = db.paused_domain_ids(user["id"], user["plan"])
    rows = []
    for d in db.list_domains(user["id"]):
        counts = severity_counts(json.loads(d["last_result"])["findings"]) if d["last_result"] else None
        rows.append({**dict(d), "counts": counts, "paused": d["id"] in paused})
    plan = db.PLANS[user["plan"]]
    return render(request, "dashboard.html", user=user, domains=rows, plan=plan, paused_count=len(paused))


async def _add_domain(request, user, raw):
    try:
        name = normalize_domain(raw)
    except ScanError as e:
        flash(request, str(e), "error")
        return redirect("/dashboard")
    plan = db.PLANS[user["plan"]]
    if len(db.list_domains(user["id"])) >= plan["domains"]:
        flash(request, f"Your {plan['name']} plan includes {plan['domains']} domain(s). Upgrade to add more.", "error")
        return redirect("/pricing")
    try:
        did = db.add_domain(user["id"], name, secrets.token_hex(12))
    except sqlite3.IntegrityError:
        flash(request, f"{name} is already in your account.", "error")
        return redirect("/dashboard")
    jobs.launch_scan(db.get_domain(did))
    flash(request, f"Added {name}. First scan is running…")
    return redirect(f"/domains/{did}")


@app.post("/domains")
async def add_domain(request: Request, domain: str = Form(...), csrf: str = Form("")):
    require_csrf(request, csrf)
    return await _add_domain(request, require_user(request), domain)


@app.get("/domains/{domain_id}")
def domain_page(request: Request, domain_id: int):
    user, d = owned_domain(request, domain_id)
    last = db.latest_scan(domain_id)
    result = parse_result(db.latest_done_scan(domain_id))
    return render(request, "domain.html", user=user, d=d, last=last, r=result,
                  running=bool(db.running_scan(domain_id)), history=db.scan_history(domain_id),
                  verify_record=VERIFY_PREFIX + d["verify_token"],
                  paused=domain_id in db.paused_domain_ids(user["id"], user["plan"]))


@app.get("/domains/{domain_id}/report")
def domain_report(request: Request, domain_id: int):
    user, d = owned_domain(request, domain_id)
    result = parse_result(db.latest_done_scan(domain_id))
    if not result:
        flash(request, "No completed scan yet.", "error")
        return redirect(f"/domains/{domain_id}")
    return render(request, "report.html", user=user, d=d, r=result)


@app.get("/api/domains/{domain_id}/status")
def domain_status(request: Request, domain_id: int):
    _, d = owned_domain(request, domain_id)
    last = db.latest_scan(domain_id)
    return JSONResponse({"running": bool(db.running_scan(domain_id)),
                         "last_scan_id": last["id"] if last else None})


@app.post("/domains/{domain_id}/scan")
async def rescan(request: Request, domain_id: int, csrf: str = Form("")):
    require_csrf(request, csrf)
    user, d = owned_domain(request, domain_id)
    if domain_id in db.paused_domain_ids(user["id"], user["plan"]):
        flash(request, "This domain is paused because it's over your plan's limit. Upgrade to resume it.", "error")
    elif db.running_scan(domain_id):
        pass
    elif d["last_scan_at"] and (time.time() - datetime.fromisoformat(d["last_scan_at"]).timestamp()) < 120:
        flash(request, "This domain was just scanned. Please wait a couple of minutes before rescanning.", "error")
    else:
        jobs.launch_scan(d)
    return redirect(f"/domains/{domain_id}")


@app.post("/domains/{domain_id}/verify")
async def verify(request: Request, domain_id: int, csrf: str = Form("")):
    require_csrf(request, csrf)
    _, d = owned_domain(request, domain_id)
    expected = VERIFY_PREFIX + d["verify_token"]
    records = await asyncio.to_thread(dns_txt, d["name"])
    if expected in records:
        db.mark_verified(domain_id)
        jobs.launch_scan(db.get_domain(domain_id))
        flash(request, "Ownership verified! Deep checks (exposed files, open ports) are now enabled. Rescanning…")
    else:
        flash(request, "We couldn't find the TXT record yet. DNS changes can take up to an hour — try again soon.", "error")
    return redirect(f"/domains/{domain_id}")


@app.post("/domains/{domain_id}/alerts")
def toggle_alerts(request: Request, domain_id: int, csrf: str = Form("")):
    require_csrf(request, csrf)
    user, d = owned_domain(request, domain_id)
    db.set_alerts(domain_id, user["id"], not d["alerts"])
    return redirect(f"/domains/{domain_id}")


@app.post("/domains/{domain_id}/delete")
def remove_domain(request: Request, domain_id: int, csrf: str = Form("")):
    require_csrf(request, csrf)
    user, d = owned_domain(request, domain_id)
    db.delete_domain(domain_id, user["id"])
    flash(request, f"Removed {d['name']}.")
    return redirect("/dashboard")

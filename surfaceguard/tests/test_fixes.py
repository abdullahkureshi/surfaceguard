"""Offline regression tests for the review fixes (run 20261030-1702). Run with:  python tests/test_fixes.py"""
import asyncio
import json
import os
import re
import smtplib
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["SURFACEGUARD_DB"] = os.path.join(tempfile.mkdtemp(), "fixes.db")
os.environ["DISABLE_SCHEDULER"] = "1"
os.environ.pop("SMTP_HOST", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, billing, config, db, jobs, main, scanner  # noqa: E402
from app.scoring import score_findings  # noqa: E402

PRICES = {"pro": "price_pro_123", "msp": "price_msp_456"}
config.STRIPE_PRICES.update(PRICES)
db.init()


def F(check, sev, title="t"):
    return scanner.finding(check, sev, title, "d", "fix")


def fake_result(domain, findings, incomplete=(), facts=None, started_at="2026-10-16T10:00:00+00:00"):
    s, g = score_findings(findings)
    return {"domain": domain, "verified": False, "score": s, "grade": g, "findings": findings,
            "facts": facts or {"http": {}, "email": {}}, "incomplete": list(incomplete),
            "started_at": started_at, "duration_s": 1.0}


async def _fake_run_scan(domain, verified=False):
    _fake_run_scan.calls.append((domain, verified))
    return fake_result(domain, [F("email", "high", "No DMARC policy")])

_fake_run_scan.calls = []
_orig_run_scan = jobs.run_scan
jobs.run_scan = _fake_run_scan

_n = [0]


def new_user(plan="free", email=None):
    _n[0] += 1
    uid = db.create_user(email or f"fix{_n[0]}@example.com", auth.hash_password("correct-horse-1"))
    db.set_plan(uid, plan)
    return uid


def new_domain(uid, name=None, verified=False):
    _n[0] += 1
    did = db.add_domain(uid, name or f"d{_n[0]}.example.com", "tok")
    if verified:
        db.mark_verified(did)
    return did


def csrf_of(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(c, email, password="correct-horse-1"):
    token = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"email": email, "password": password, "csrf": token})
    return r, csrf_of(r.text)  # the session (and its CSRF token) is renewed on login


def wait_idle(domain_id, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if not db.running_scan(domain_id):
            return
        time.sleep(0.05)
    raise AssertionError("scan still running")


def sub(sub_id, customer, price, status="active"):
    return {"id": sub_id, "object": "subscription", "customer": customer, "status": status,
            "metadata": {}, "items": {"data": [{"price": {"id": price}}]}}


def evt(evt_id, typ, obj, created=None):
    e = {"id": evt_id, "type": typ, "data": {"object": obj}}
    if created is not None:
        e["created"] = created
    return e


# ---------------------------------------------------------------- H4: webhook failure, then retry

def test_webhook_failure_then_retry_is_processed():
    uid = new_user()
    db.set_billing(uid, customer_id="cus_H4")
    e = evt("evt_H4", "customer.subscription.created", sub("sub_H4", "cus_H4", PRICES["pro"]), created=1000)
    orig = db.set_billing
    calls = [0]

    def flaky(*a, **kw):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("database is locked")
        return orig(*a, **kw)

    db.set_billing = flaky
    try:
        billing.handle_event(e)
        raise AssertionError("handler error was swallowed")
    except RuntimeError:
        pass
    finally:
        db.set_billing = orig
    assert db.get_user(uid)["plan"] == "free"
    # Stripe retries the same event: it must be processed, not answered "duplicate"
    assert billing.handle_event(e) == "ok"
    assert db.get_user(uid)["plan"] == "pro"
    assert billing.handle_event(e) == "duplicate"


def test_webhook_failure_returns_500_then_retry_ok_over_http():
    import hashlib
    import hmac
    secret = "whsec_fix"
    saved = config.STRIPE_WEBHOOK_SECRET
    config.STRIPE_WEBHOOK_SECRET = secret
    uid = new_user()
    db.set_billing(uid, customer_id="cus_H4b")
    body = json.dumps(evt("evt_H4b", "customer.subscription.created",
                          sub("sub_H4b", "cus_H4b", PRICES["msp"]), created=1000)).encode()

    def post(c):
        ts = int(time.time())
        sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        return c.post("/stripe/webhook", content=body,
                      headers={"stripe-signature": f"t={ts},v1={sig}", "content-type": "application/json"})

    orig = billing.apply_subscription
    billing.apply_subscription = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        with TestClient(main.app, raise_server_exceptions=False) as c:
            assert post(c).status_code == 500
            billing.apply_subscription = orig
            r = post(c)
            assert r.status_code == 200 and r.json() == {"status": "ok"}, r.text
        assert db.get_user(uid)["plan"] == "msp"
    finally:
        billing.apply_subscription = orig
        config.STRIPE_WEBHOOK_SECRET = saved


# ---------------------------------------------------------------- M1: stale / out-of-order events

def test_out_of_order_event_is_ignored():
    uid = new_user()
    db.set_billing(uid, customer_id="cus_M1")
    billing.handle_event(evt("evt_M1a", "customer.subscription.created", sub("sub_M1", "cus_M1", PRICES["pro"]), 100))
    billing.handle_event(evt("evt_M1c", "customer.subscription.deleted",
                             sub("sub_M1", "cus_M1", PRICES["pro"], "canceled"), 300))
    assert db.get_user(uid)["plan"] == "free"
    # an older "updated (active, msp)" arrives late: must not give the paid plan back
    billing.handle_event(evt("evt_M1b", "customer.subscription.updated", sub("sub_M1", "cus_M1", PRICES["msp"]), 200))
    u = db.get_user(uid)
    assert (u["plan"], u["stripe_subscription_id"]) == ("free", None)


def test_canceled_subscription_is_never_revived():
    uid = new_user()
    db.set_billing(uid, customer_id="cus_M1b")
    billing.handle_event(evt("evt_M1d", "customer.subscription.created", sub("sub_M1b", "cus_M1b", PRICES["pro"]), 100))
    billing.handle_event(evt("evt_M1e", "customer.subscription.deleted",
                             sub("sub_M1b", "cus_M1b", PRICES["pro"], "canceled"), 200))
    # same timestamp or no timestamp (e.g. the success-page sync): still terminal
    billing.handle_event(evt("evt_M1f", "customer.subscription.updated", sub("sub_M1b", "cus_M1b", PRICES["pro"]), 200))
    billing.apply_subscription(sub("sub_M1b", "cus_M1b", PRICES["pro"]))
    assert db.get_user(uid)["plan"] == "free"
    # a newer, different subscription still works
    billing.handle_event(evt("evt_M1g", "customer.subscription.created", sub("sub_M1c", "cus_M1b", PRICES["msp"]), 300))
    assert db.get_user(uid)["plan"] == "msp"


# ---------------------------------------------------------------- L6: Stripe transport errors

def test_stripe_network_and_non_json_errors_become_billing_errors():
    import httpx
    config.STRIPE_SECRET_KEY = "sk_test_fake"

    def run(handler):
        transport = httpx.MockTransport(handler)
        orig = httpx.AsyncClient

        class Client(orig):
            def __init__(self, *a, **kw):
                kw["transport"] = transport
                super().__init__(*a, **kw)

        httpx.AsyncClient = Client
        try:
            asyncio.run(billing.stripe_request("GET", "/customers/cus_x"))
            raise AssertionError("no BillingError")
        except billing.BillingError:
            pass
        finally:
            httpx.AsyncClient = orig

    def boom(request):
        raise httpx.ConnectError("down", request=request)

    run(boom)
    run(lambda request: httpx.Response(502, text="<html>Bad gateway</html>"))
    run(lambda request: httpx.Response(200, text="not json"))


# ---------------------------------------------------------------- M9: scheduler skips running scans

def test_due_for_scan_skips_domain_with_running_scan():
    uid = new_user()
    d1, d2 = new_domain(uid), new_domain(uid)
    db.set_plan(uid, "pro")
    with db.conn() as c:
        c.execute("UPDATE domains SET last_scan_at='2000-01-01T00:00:00+00:00' WHERE user_id=?", (uid,))
        # a running scan for d1 (inserted directly so last_scan_at stays old)
        c.execute("INSERT INTO scans(domain_id, status, started_at) VALUES (?, 'running', ?)", (d1, db.now()))
    due = {r["id"] for r in db.domains_due_for_scan() if r["user_id"] == uid}
    assert due == {d2}, due
    with db.conn() as c:
        c.execute("UPDATE scans SET status='failed' WHERE domain_id=?", (d1,))


# ---------------------------------------------------------------- M8: carry_forward over two timeouts

def test_carry_forward_over_two_timeouts_and_age_limit():
    s1 = fake_result("x.com", [F("http", "medium", "HSTS missing"), F("email", "high", "No DMARC")],
                     facts={"http": {"server": "nginx"}, "email": {}}, started_at="2026-10-01T10:00:00+00:00")
    s2 = fake_result("x.com", [F("email", "high", "No DMARC")], incomplete=["http"],
                     facts={"http": {"error": "ReadTimeout"}, "email": {}}, started_at="2026-10-02T10:00:00+00:00")
    jobs.carry_forward(s2, s1)
    s3 = fake_result("x.com", [F("email", "high", "No DMARC")], incomplete=["http"],
                     facts={"http": {"error": "ReadTimeout"}, "email": {}}, started_at="2026-10-03T10:00:00+00:00")
    jobs.carry_forward(s3, json.loads(json.dumps(s2)))
    assert s3["score"] == s1["score"]
    assert [f["title"] for f in s3["findings"] if f.get("carried")] == ["HSTS missing"]
    assert s3["facts"]["http"]["carried_since"] == "2026-10-01T10:00:00+00:00"
    # more than 7 days after the data was really collected: stop carrying
    s4 = fake_result("x.com", [F("email", "high", "No DMARC")], incomplete=["http"],
                     facts={"http": {"error": "ReadTimeout"}, "email": {}}, started_at="2026-10-09T10:00:01+00:00")
    jobs.carry_forward(s4, json.loads(json.dumps(s3)))
    assert not [f for f in s4["findings"] if f.get("carried")]
    assert "carried" not in s4["facts"]["http"]


# ---------------------------------------------------------------- M7: post-processing failure

def test_post_processing_exception_marks_scan_failed():
    uid = new_user()
    did = new_domain(uid)
    # a malformed previous result makes carry_forward / diff blow up
    with db.conn() as c:
        c.execute("INSERT INTO scans(domain_id, status, started_at, result_json) VALUES (?, 'done', ?, ?)",
                  (did, db.now(), json.dumps({"no": "findings"})))
    scan_id = db.start_scan(did)
    asyncio.run(jobs._execute(scan_id, dict(db.get_domain(did))))
    with db.conn() as c:
        row = c.execute("SELECT status, error FROM scans WHERE id=?", (scan_id,)).fetchone()
    assert row["status"] == "failed" and "Unexpected error" in row["error"], dict(row)


def test_alert_failure_does_not_break_scan():
    uid = new_user()
    did = new_domain(uid)
    with db.conn() as c:
        c.execute("INSERT INTO scans(domain_id, status, started_at, result_json) VALUES (?, 'done', ?, ?)",
                  (did, db.now(), json.dumps(fake_result("x", []))))
    orig = jobs.send_alert
    jobs.send_alert = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("smtp down"))
    try:
        scan_id = db.start_scan(did)
        asyncio.run(jobs._execute(scan_id, dict(db.get_domain(did))))
    finally:
        jobs.send_alert = orig
    with db.conn() as c:
        assert c.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()["status"] == "done"


# ---------------------------------------------------------------- L7: verification re-checked before active checks

def test_active_checks_need_txt_record_still_present():
    uid = new_user()
    did = new_domain(uid, verified=True)
    orig = jobs.dns_txt_strict
    try:
        jobs.dns_txt_strict = lambda name: [jobs.VERIFY_PREFIX + "tok"]
        _fake_run_scan.calls.clear()
        asyncio.run(jobs._execute(db.start_scan(did), dict(db.get_domain(did))))
        assert _fake_run_scan.calls[-1][1] is True
        jobs.dns_txt_strict = lambda name: ["v=spf1 -all"]
        asyncio.run(jobs._execute(db.start_scan(did), dict(db.get_domain(did))))
        assert _fake_run_scan.calls[-1][1] is False
        assert db.get_domain(did)["verified_at"] is None
    finally:
        jobs.dns_txt_strict = orig


def _txt_raising(exc):
    def f(*args, **kwargs):
        raise exc
    return f


def test_txt_timeout_keeps_verification():
    import dns.exception
    import dns.resolver
    for exc in (dns.exception.Timeout(), dns.resolver.NoNameservers()):
        uid = new_user()
        did = new_domain(uid, verified=True)
        orig = scanner._resolver
        scanner._resolver = lambda: type("R", (), {"resolve": staticmethod(_txt_raising(exc))})()
        try:
            _fake_run_scan.calls.clear()
            asyncio.run(jobs._execute(db.start_scan(did), dict(db.get_domain(did))))
            assert db.get_domain(did)["verified_at"] is not None, type(exc).__name__
            assert _fake_run_scan.calls[-1][1] is True  # existing verification trusted for this scan
            # dns_txt (used by /verify and the passive checks) still returns [] on failure
            assert scanner.dns_txt("x.example.com") == []
        finally:
            scanner._resolver = orig


def test_txt_nxdomain_or_empty_answer_clears_verification():
    import dns.resolver
    for exc in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
        uid = new_user()
        did = new_domain(uid, verified=True)
        orig = scanner._resolver
        scanner._resolver = lambda: type("R", (), {"resolve": staticmethod(_txt_raising(exc))})()
        try:
            _fake_run_scan.calls.clear()
            asyncio.run(jobs._execute(db.start_scan(did), dict(db.get_domain(did))))
            assert db.get_domain(did)["verified_at"] is None, type(exc).__name__
            assert _fake_run_scan.calls[-1][1] is False
        finally:
            scanner._resolver = orig


# ---------------------------------------------------------------- M3 / L8: SMTP

def test_smtp_uses_verified_tls_and_port_465():
    seen = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            seen.append(("init", type(self).__name__, port, context))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            seen.append(("starttls", context))

        def login(self, *a):
            pass

        def send_message(self, msg):
            seen.append(("send", msg["To"]))

    class FakeSSL(FakeSMTP):
        pass

    orig = smtplib.SMTP, smtplib.SMTP_SSL
    smtplib.SMTP, smtplib.SMTP_SSL = FakeSMTP, FakeSSL
    os.environ["SMTP_HOST"] = "smtp.example.com"
    try:
        r = fake_result("x.com", [])
        os.environ["SMTP_PORT"] = "587"
        jobs.send_alert("a@example.com", "x.com", r, [F("http", "high", "t")], 1)
        tls = [s for s in seen if s[0] == "starttls"]
        assert tls and tls[0][1] is not None and tls[0][1].verify_mode == 2  # ssl.CERT_REQUIRED
        assert tls[0][1].check_hostname is True
        seen.clear()
        os.environ["SMTP_PORT"] = "465"
        jobs.send_alert("a@example.com", "x.com", r, [F("http", "high", "t")], 1)
        assert seen[0][1] == "FakeSSL" and seen[0][3] is not None and seen[0][3].verify_mode == 2
        assert not [s for s in seen if s[0] == "starttls"] and ("send", "a@example.com") in seen
    finally:
        smtplib.SMTP, smtplib.SMTP_SSL = orig
        os.environ.pop("SMTP_HOST", None)
        os.environ.pop("SMTP_PORT", None)


def test_production_alert_log_has_no_email_or_findings():
    import logging
    records = []

    class H(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    h = H()
    jobs.log.addHandler(h)
    saved = config.IS_PRODUCTION
    config.IS_PRODUCTION = True
    try:
        jobs.send_alert("victim@example.com", "x.com", fake_result("x.com", []), [F("http", "high", "Secret title")], 42)
    finally:
        config.IS_PRODUCTION = saved
        jobs.log.removeHandler(h)
    text = "\n".join(records)
    assert "user id 42" in text and "victim@example.com" not in text and "Secret title" not in text


# ---------------------------------------------------------------- L3: CSRF

def test_non_ascii_csrf_gives_400():
    assert auth.check_csrf({"csrf": "abc"}, "é") is False
    with TestClient(main.app) as c:
        c.get("/login")
        r = c.post("/login", data={"email": "x@example.com", "password": "x", "csrf": "é"})
        assert r.status_code == 400


# ---------------------------------------------------------------- L11: iterations + rehash

def test_password_rehash_on_login():
    assert auth.ITERATIONS >= 600_000
    saved = auth.ITERATIONS
    auth.ITERATIONS = 1000
    old_hash = auth.hash_password("correct-horse-1")
    auth.ITERATIONS = saved
    uid = db.create_user("rehash@example.com", old_hash)
    assert auth.needs_rehash(old_hash)
    with TestClient(main.app) as c:
        r, _ = login(c, "rehash@example.com")
        assert "Your domains" in r.text
    stored = db.get_user(uid)["pw_hash"]
    assert stored != old_hash and not auth.needs_rehash(stored) and auth.verify_password("correct-horse-1", stored)


# ---------------------------------------------------------------- M6: login rate limit

def _login_from(c, ip, email, password, token):
    return c.post("/login", data={"email": email, "password": password, "csrf": token},
                  headers={"X-Test-Client-IP": ip})


def _with_ip_header(fn):
    orig = config.CLIENT_IP_HEADER
    config.CLIENT_IP_HEADER = "X-Test-Client-IP"
    main._rate_hits.clear()
    try:
        fn()
    finally:
        config.CLIENT_IP_HEADER = orig
        main._rate_hits.clear()


def test_login_rate_limit_by_ip_and_email():
    def run():
        new_user(email="brute@example.com")
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/login").text)
            for _ in range(main.LOGIN_LIMIT):
                r = _login_from(c, "203.0.113.5", "brute@example.com", "wrong", token)
                assert "Wrong email or password" in r.text
            # even the right password is refused from the attacking IP while limited
            r = _login_from(c, "203.0.113.5", "brute@example.com", "correct-horse-1", token)
            assert "Too many failed login attempts" in r.text
            # the per-IP limit stops guessing across many emails from one client
            for i in range(main.LOGIN_IP_LIMIT - main.LOGIN_LIMIT):
                _login_from(c, "203.0.113.5", f"spray{i}@example.com", "x", token)
            r = _login_from(c, "203.0.113.5", "fresh@example.com", "x", token)
            assert "Too many failed login attempts" in r.text
    _with_ip_header(run)


def test_attacker_on_other_ip_cannot_lock_out_user():
    def run():
        new_user(email="victim@example.com")
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/login").text)
            for _ in range(main.LOGIN_LIMIT + 5):
                _login_from(c, "198.51.100.66", "victim@example.com", "wrong", token)
            assert "Too many failed" in _login_from(c, "198.51.100.66", "victim@example.com", "wrong", token).text
            r = _login_from(c, "192.0.2.10", "victim@example.com", "correct-horse-1", token)
            assert r.status_code in (302, 303) or "Too many failed" not in r.text
            assert c.get("/dashboard", follow_redirects=False).status_code == 200
    _with_ip_header(run)


def test_per_email_limit_is_high_and_success_is_not_counted():
    def run():
        new_user(email="spread@example.com")
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/login").text)
            # failures spread over many IPs stop only at the high per-email limit
            for i in range(main.LOGIN_EMAIL_LIMIT):
                main.rate_reserve(((f"login-email:spread@example.com", main.LOGIN_EMAIL_LIMIT),), main.LOGIN_WINDOW)
            r = _login_from(c, "192.0.2.20", "spread@example.com", "correct-horse-1", token)
            assert "Too many failed login attempts" in r.text
        main._rate_hits.clear()
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/login").text)
            r = _login_from(c, "192.0.2.21", "spread@example.com", "correct-horse-1", token)
            assert "Too many failed" not in r.text
            assert not main._rate_hits  # a successful login leaves no hits behind
    _with_ip_header(run)


def test_login_limit_reserve_is_atomic_under_parallel_requests():
    import threading
    main._rate_hits.clear()
    limits = (("race-key", 10),)
    passed = []
    barrier = threading.Barrier(40)

    def worker():
        barrier.wait()
        if main.rate_reserve(limits, 60) is not None:
            passed.append(1)

    threads = [threading.Thread(target=worker) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(passed) == 10
    main._rate_hits.clear()


# ---------------------------------------------------------------- N3: /register rate limit

def test_register_is_rate_limited_per_ip():
    def run():
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/register").text)
            for i in range(main.REGISTER_LIMIT):
                r = c.post("/register", data={"email": f"reg{i}-{time.time_ns()}@example.com",
                                              "password": "correct-horse-1", "csrf": token},
                           headers={"X-Test-Client-IP": "203.0.113.77"}, follow_redirects=False)
                assert r.status_code in (302, 303), r.status_code
                token = csrf_of(c.get("/register").text)
            email = f"reg-blocked-{time.time_ns()}@example.com"
            r = c.post("/register", data={"email": email, "password": "correct-horse-1", "csrf": token},
                       headers={"X-Test-Client-IP": "203.0.113.77"})
            assert "Too many accounts" in r.text and db.get_user_by_email(email) is None
            # another IP can still register
            r = c.post("/register", data={"email": f"reg-other-{time.time_ns()}@example.com",
                                          "password": "correct-horse-1", "csrf": token},
                       headers={"X-Test-Client-IP": "203.0.113.78"}, follow_redirects=False)
            assert r.status_code in (302, 303)
    _with_ip_header(run)


def test_unknown_email_still_runs_a_hash():
    calls = []
    orig = auth.verify_password
    auth.verify_password = lambda p, s: calls.append(s) or orig(p, s)
    try:
        main._rate_hits.clear()
        with TestClient(main.app) as c:
            token = csrf_of(c.get("/login").text)
            c.post("/login", data={"email": "nobody@example.com", "password": "x", "csrf": token})
        assert len(calls) == 1 and calls[0].startswith("pbkdf2$")
    finally:
        auth.verify_password = orig
        main._rate_hits.clear()


# ---------------------------------------------------------------- L9: rate-limit keys are removed

def test_empty_rate_limit_keys_removed():
    main._rate_hits.clear()
    assert main.rate_limited("k1", limit=5, window=1) is False
    assert "k1" in main._rate_hits
    main._rate_hits["k1"][0] -= 10  # make the hit old
    assert main.rate_limited("k1", limit=5, window=1, record=False) is False
    assert "k1" not in main._rate_hits
    # idle keys that are never touched again are swept
    main._rate_hits["idle"] = __import__("collections").deque([time.time() - 2 * main._RATE_MAX_WINDOW])
    main._rate_last_sweep[0] = 0
    main.rate_limited("k2")
    assert "idle" not in main._rate_hits and "k2" in main._rate_hits
    main._rate_hits.clear()


# ---------------------------------------------------------------- M4: /verify

def test_verify_already_verified_does_not_scan_and_respects_checks():
    email = "verifier@example.com"
    uid = new_user(email=email)
    did = new_domain(uid, name="verify-me.example.com")
    orig = main.dns_txt
    main.dns_txt = lambda name: [main.VERIFY_PREFIX + "tok"]
    try:
        with TestClient(main.app) as c:
            _, token = login(c, email)
            # fresh scan < 2 minutes ago: verification succeeds but no new scan (cooldown)
            db.start_scan(did)
            with db.conn() as conn:
                conn.execute("UPDATE scans SET status='done' WHERE domain_id=?", (did,))
            before = len(db.scan_history(did))
            r = c.post(f"/domains/{did}/verify", data={"csrf": token})
            assert "will run on the next scan" in r.text
            assert db.get_domain(did)["verified_at"] and len(db.scan_history(did)) == before
            # already verified: never launches a scan, even after the cooldown
            with db.conn() as conn:
                conn.execute("UPDATE domains SET last_scan_at='2000-01-01T00:00:00+00:00' WHERE id=?", (did,))
            r = c.post(f"/domains/{did}/verify", data={"csrf": token})
            assert "already verified" in r.text and len(db.scan_history(did)) == before
    finally:
        main.dns_txt = orig


def test_verify_launches_scan_when_allowed():
    email = "verifier2@example.com"
    uid = new_user(email=email)
    did = new_domain(uid, name="verify-ok.example.com")
    orig_main, orig_jobs = main.dns_txt, jobs.dns_txt_strict
    main.dns_txt = jobs.dns_txt_strict = lambda name: [main.VERIFY_PREFIX + "tok"]
    try:
        with TestClient(main.app) as c:
            _, token = login(c, email)
            r = c.post(f"/domains/{did}/verify", data={"csrf": token})
            assert "Rescanning" in r.text
            wait_idle(did)
            assert len(db.scan_history(did)) == 1
    finally:
        main.dns_txt, jobs.dns_txt_strict = orig_main, orig_jobs


# ---------------------------------------------------------------- M5: scan budget and /check concurrency

def test_scan_launch_limit_survives_domain_deletion():
    email = "budget@example.com"
    uid = new_user(email=email)
    limit = db.PLANS["free"]["scans_per_hour"]
    with TestClient(main.app) as c:
        _, token = login(c, email)
        for i in range(limit):
            r = c.post("/domains", data={"domain": f"loop{i}.example.com", "csrf": token})
            assert r.url.path.startswith("/domains/"), r.url
            did = int(r.url.path.rsplit("/", 1)[1])
            wait_idle(did)
            c.post(f"/domains/{did}/delete", data={"csrf": token})
        r = c.post("/domains", data={"domain": "one-too-many.example.com", "csrf": token})
        assert "a lot of scans" in r.text and not db.list_domains(uid)
    assert db.scan_launches_since(uid) == limit


def test_rescan_respects_scan_budget():
    email = "budget2@example.com"
    uid = new_user(email=email)
    did = new_domain(uid)
    for _ in range(db.PLANS["free"]["scans_per_hour"]):
        db.record_scan_launch(uid)
    with TestClient(main.app) as c:
        _, token = login(c, email)
        r = c.post(f"/domains/{did}/scan", data={"csrf": token})
        assert "a lot of scans" in r.text and not db.scan_history(did)


def test_check_busy_when_slots_full():
    main._rate_hits.clear()
    with TestClient(main.app) as c:
        token = csrf_of(c.get("/").text)
        main._checks_running[0] = main.MAX_CONCURRENT_CHECKS
        try:
            r = c.post("/check", data={"domain": "example.com", "csrf": token})
            assert "busy" in r.text
        finally:
            main._checks_running[0] = 0
        # a busy answer doesn't use up the visitor's free checks
        assert not main._rate_hits


# ---------------------------------------------------------------- L4 / L2

def test_demo_billing_needs_explicit_flag():
    saved = config.DEMO_BILLING, config.IS_PRODUCTION, config.STRIPE_SECRET_KEY
    try:
        config.STRIPE_SECRET_KEY = ""
        config.DEMO_BILLING, config.IS_PRODUCTION = False, False
        assert config.billing_mode() == "disabled"
        config.DEMO_BILLING = True
        assert config.billing_mode() == "demo"
        config.IS_PRODUCTION = True
        assert config.billing_mode() == "disabled"
    finally:
        config.DEMO_BILLING, config.IS_PRODUCTION, config.STRIPE_SECRET_KEY = saved


def test_dashboard_does_not_reload_after_failed_scan():
    email = "reload@example.com"
    uid = new_user(email=email)
    did = new_domain(uid)
    with TestClient(main.app) as c:
        login(c, email)
        db.fail_scan(db.start_scan(did), "boom")
        assert "data-reload-after" not in c.get("/dashboard").text
        with db.conn() as conn:
            conn.execute("INSERT INTO scans(domain_id, status, started_at) VALUES (?, 'running', ?)", (did, db.now()))
        assert "data-reload-after" in c.get("/dashboard").text
        with db.conn() as conn:
            conn.execute("UPDATE scans SET status='failed' WHERE domain_id=?", (did,))


# ---------------------------------------------------------------- L10

def test_sqlite_wal_and_busy_timeout():
    with db.conn() as c:
        assert c.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert c.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
                print("PASS", name)
            except Exception:
                failed += 1
                import traceback
                traceback.print_exc()
                print("FAIL", name)
    sys.exit(1 if failed else 0)

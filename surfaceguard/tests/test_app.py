"""Offline tests: no network access needed. Run with:  python -m pytest tests  (or python tests/test_app.py)"""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["SURFACEGUARD_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["DISABLE_SCHEDULER"] = "1"
os.environ["DEMO_BILLING"] = "1"  # the flow below upgrades through the demo plan switch

from fastapi.testclient import TestClient  # noqa: E402

from app import db, jobs, main, scanner  # noqa: E402
from app.scoring import diff_findings, score_findings  # noqa: E402


def F(check, sev, title="t"):
    return scanner.finding(check, sev, title, "d", "fix")


def fake_result(domain, findings, incomplete=(), facts=None):
    s, g = score_findings(findings)
    return {"domain": domain, "verified": False, "score": s, "grade": g, "findings": findings,
            "facts": facts or {"http": {}, "email": {}}, "incomplete": list(incomplete),
            "started_at": "2026-10-16T10:00:00+00:00", "duration_s": 1.0}


# ---------------------------------------------------------------- unit tests

def test_normalize_domain():
    assert scanner.normalize_domain("https://WWW.Example.com/path?q=1") == "example.com"
    assert scanner.normalize_domain("sub.example.co.uk:8080") == "sub.example.co.uk"
    for bad in ["localhost", "not a domain", "", "127.0.0.1", "a.b"]:
        try:
            scanner.normalize_domain(bad)
            raise AssertionError(f"accepted {bad!r}")
        except scanner.ScanError:
            pass


def test_scoring():
    assert score_findings([]) == (100, "A")
    assert score_findings([F("x", "low")] * 3) == (94, "A")
    assert score_findings([F("x", "high"), F("x", "medium")]) == (82, "B")
    # one critical caps the grade at F even if the rest is clean
    assert score_findings([F("x", "critical")])[1] == "F"
    assert score_findings([F("x", "info")] * 10) == (100, "A")


def test_diff_ignores_info_and_existing():
    old = [F("email", "high", "No DMARC")]
    new = [F("email", "high", "No DMARC"), F("tls", "medium", "Expiring"), F("subdomains", "info", "12 found")]
    assert [f["title"] for f in diff_findings(old, new)] == ["Expiring"]


def test_carry_forward_keeps_score_stable_on_timeout():
    prev = fake_result("x.com", [F("http", "medium", "HSTS missing"), F("email", "high", "No DMARC")],
                       facts={"http": {"server": "nginx"}, "email": {}})
    cur = fake_result("x.com", [F("email", "high", "No DMARC")], incomplete=["http"],
                      facts={"http": {"error": "ReadTimeout"}, "email": {}})
    assert cur["score"] > prev["score"]  # without carry-forward the timeout "improves" the score
    jobs.carry_forward(cur, prev)
    assert cur["score"] == prev["score"]
    carried = [f for f in cur["findings"] if f.get("carried")]
    assert [f["title"] for f in carried] == ["HSTS missing"]
    assert cur["facts"]["http"]["carried"] is True


def test_private_ip_rejected(monkeypatch=None):
    orig = scanner.dns_records
    scanner.dns_records = lambda name, rtype: {"A": ["10.0.0.5"], "NS": ["ns1.x."]}.get(rtype, [])
    try:
        scanner.check_dns("internal.example.com")
        raise AssertionError("private IP accepted")
    except scanner.ScanError as e:
        assert "private" in str(e)
    finally:
        scanner.dns_records = orig


# ---------------------------------------------------------------- route tests

async def _fake_run_scan(domain, verified=False):
    return fake_result(domain, [F("email", "high", "No DMARC policy"), F("http", "low", "No CSP")])

jobs.run_scan = _fake_run_scan


def csrf_of(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def register(client, email):
    token = csrf_of(client.get("/register").text)
    return client.post("/register", data={"email": email, "password": "correct-horse-1", "csrf": token})


def wait_for_scan(domain_id, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if not db.running_scan(domain_id):
            return
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_full_flow():
    with TestClient(main.app) as c:
        assert c.get("/").status_code == 200
        assert c.get("/pricing").status_code == 200
        assert c.get("/dashboard", follow_redirects=False).headers["location"] == "/login"

        r = register(c, "owner@example.com")
        assert r.status_code == 200 and "Your domains" in r.text

        token = csrf_of(r.text)
        # CSRF protection
        assert c.post("/domains", data={"domain": "example.com", "csrf": "wrong"}).status_code == 400
        # invalid domain is rejected with a message
        r = c.post("/domains", data={"domain": "not a domain", "csrf": token})
        assert "valid domain" in r.text

        r = c.post("/domains", data={"domain": "https://www.Example.com/", "csrf": token})
        assert r.url.path == "/domains/1"
        wait_for_scan(1)
        page = c.get("/domains/1").text
        assert "example.com" in page and "No DMARC policy" in page and "surfaceguard-verify=" in page

        # free plan allows only one domain
        r = c.post("/domains", data={"domain": "second.com", "csrf": token})
        assert r.url.path == "/pricing"

        # an immediate rescan is blocked by the 2-minute cooldown
        assert "just scanned" in c.post("/domains/1/scan", data={"csrf": token}).text
        with db.conn() as conn:
            conn.execute("UPDATE domains SET last_scan_at='2000-01-01T00:00:00+00:00' WHERE id=1")
        # rescan works (this used to crash: no running event loop) and records history
        assert c.post("/domains/1/scan", data={"csrf": token}).status_code == 200
        wait_for_scan(1)
        assert len([s for s in db.scan_history(1) if s["status"] == "done"]) == 2

        assert "External security assessment" in c.get("/domains/1/report").text
        assert c.get("/api/domains/1/status").json()["running"] is False

        # plan upgrade raises the domain limit
        c.post("/billing/plan", data={"plan": "pro", "csrf": token})
        r = c.post("/domains", data={"domain": "second.com", "csrf": token})
        assert r.url.path.startswith("/domains/")

        c.post("/logout", data={"csrf": token})
        # a different user cannot see someone else's domain
        register(c, "attacker@example.com")
        assert c.get("/domains/1").status_code == 404
        assert c.get("/domains/1/report").status_code == 404


def test_login():
    with TestClient(main.app) as c:
        register(c, "login@example.com")
        c.cookies.clear()
        token = csrf_of(c.get("/login").text)
        bad = c.post("/login", data={"email": "login@example.com", "password": "nope", "csrf": token})
        assert "Wrong email or password" in bad.text
        ok = c.post("/login", data={"email": "LOGIN@example.com", "password": "correct-horse-1", "csrf": token})
        assert "Your domains" in ok.text


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)

"""Integration tests across the two fix tracks (run 20261030-1702): scanner results with stable
finding ids (Track A) going through jobs post-processing / alert diff (Track B), plus page
rendering with the new result fields. Offline. Run with:  python tests/test_integration.py"""
import asyncio
import json
import os
import re
import ssl
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["SURFACEGUARD_DB"] = os.path.join(tempfile.mkdtemp(), "integration.db")
os.environ["DISABLE_SCHEDULER"] = "1"
os.environ.pop("SMTP_HOST", None)

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, jobs, main, scanner  # noqa: E402
from app.scoring import diff_findings, score_findings  # noqa: E402

db.init()
PUBLIC_IP = "93.184.216.34"
V6_IP = "2606:2800:220:1:248:1893:25c8:1946"


class patched:
    def __init__(self, obj, **attrs):
        self.obj, self.attrs, self.saved = obj, attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(self.obj, k)
            setattr(self.obj, k, v)

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            setattr(self.obj, k, v)


def _http_handler(request):
    if request.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{request.headers['host']}/"})
    # HTTPS root redirects to an internal address: must not be followed (H1) and is reported.
    return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/", "server": "nginx/1.25.3"})


def _crtsh_handler(request):
    entries = ",".join('{"name_value":"%s.example.com"}' % n for n in ("a", "b", "c", "www"))
    return httpx.Response(200, content=("[" + entries * 50 + "]").encode())


def real_scan(days_left=10, http_times_out=False, ips=(PUBLIC_IP,)):
    """Run the real scanner.run_scan with the network faked at the lowest level, so the result has
    exactly the shape (ids, titles, facts) production produces."""
    a = [ip for ip in ips if ":" not in ip]
    aaaa = [ip for ip in ips if ":" in ip]
    table = {("example.com", "A"): a, ("example.com", "AAAA"): aaaa, ("example.com", "NS"): ["ns1.example.com."],
             ("example.com", "MX"): ["10 mx.example.com."]}
    exp = datetime.now(timezone.utc) + timedelta(days=days_left, hours=1)
    cert = {"notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT"), "issuer": ((("organizationName", "Test CA"),),)}

    def fake_tls(host, ips, legacy=False):
        if legacy:
            return cert, "TLSv1.0"  # legacy accepted -> tls.legacy_protocol
        return cert, "TLSv1.3"

    orig_http, orig_subs = scanner.check_http, scanner.check_subdomains

    async def http(domain, https_ok, ips=None):
        if http_times_out:
            return [], {"error": "ReadTimeout"}
        return await orig_http(domain, https_ok, ips, transport=httpx.MockTransport(_http_handler))

    async def subs(domain):
        return await orig_subs(domain, transport=httpx.MockTransport(_crtsh_handler))

    with patched(scanner, dns_records=lambda n, t: table.get((n, t), []), dns_txt=lambda n: [],
                 _tls_connect=fake_tls, check_http=http, check_subdomains=subs, CRTSH_MAX_BYTES=300,
                 _probe_subdomain=lambda n: {"name": n, "cname": None, "live": True}):
        return asyncio.run(scanner.run_scan("example.com"))


def legacy(result):
    """The same result as stored before this run: no ids, TLS titles with the day count."""
    old = json.loads(json.dumps(result))
    for f in old["findings"]:
        f.pop("id", None)
        if f["title"].startswith("SSL certificate expires within"):
            f["title"] = f"SSL certificate expires in {old['facts']['tls']['days_left']} days"
        if f["title"].startswith("Outdated encryption protocol"):
            f["title"] = "Outdated encryption protocol accepted (TLSv1.0)"
    for k in ("ips",):
        old["facts"]["dns"].pop(k, None)
    for cat in ("http", "subdomains"):
        old["facts"].get(cat, {}).pop("redirect_not_followed", None)
        old["facts"].get(cat, {}).pop("truncated", None)
    return old


# ---------------------------------------------------------------- shape produced by the scanner

def test_real_scan_has_ids_and_new_facts():
    r = real_scan()
    assert all(f.get("id") for f in r["findings"]), [f for f in r["findings"] if not f.get("id")]
    ids = {f["id"] for f in r["findings"]}
    assert {"tls.expiry_21d", "tls.legacy_protocol", "http.missing.strict-transport-security",
            "email.spf_missing", "subdomains.inventory"} <= ids, ids
    assert r["facts"]["dns"]["ips"] == [PUBLIC_IP]
    assert r["facts"]["http"]["redirect_not_followed"] and r["facts"]["http"]["status"] == 302
    assert r["facts"]["subdomains"]["truncated"] is True
    assert r["incomplete"] == []


def test_ipv6_only_target_is_pinned_and_scans():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers["host"]))
        return _http_handler(request)
    orig = scanner.check_http
    with patched(scanner, dns_records=lambda n, t: []):
        f, facts = asyncio.run(orig("example.com", True, [V6_IP], transport=httpx.MockTransport(handler)))
    assert seen and all(h == V6_IP and host == "example.com" for h, host in seen), seen
    assert facts["status"] == 302 and facts.get("redirect_not_followed")
    r = real_scan(ips=(V6_IP,))
    assert r["facts"]["dns"]["ips"] == [V6_IP]


def test_check_http_does_not_read_endless_body():
    """H3: the main HTTPS fetch needs headers only; an endless body must not be buffered."""
    sent = {"bytes": 0}

    async def endless():
        while True:
            sent["bytes"] += 65536
            if sent["bytes"] > 20 * 1024 * 1024:
                raise AssertionError("body was read")
            yield b"x" * 65536

    def handler(request):
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"}, content=endless())
        return httpx.Response(200, headers={"x-frame-options": "DENY"}, content=endless())
    f, facts = asyncio.run(scanner.check_http("example.com", True, [PUBLIC_IP],
                                              transport=httpx.MockTransport(handler)))
    assert facts["status"] == 200 and sent["bytes"] < 1024 * 1024, (facts, sent)


# ---------------------------------------------------------------- jobs post-processing (A + B)

def test_new_shape_daily_scans_do_not_realert_on_day_count():
    s1 = real_scan(days_left=15)
    s2 = real_scan(days_left=14)
    jobs.carry_forward(s2, s1)
    assert diff_findings(s1["findings"], s2["findings"]) == []


def test_new_shape_carry_forward_two_timeouts_keeps_ids_and_no_alert():
    s1 = real_scan()
    s1["started_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="seconds")
    s2 = real_scan(http_times_out=True)
    assert s2["incomplete"] == ["http"]
    jobs.carry_forward(s2, s1)
    s3 = real_scan(http_times_out=True)
    jobs.carry_forward(s3, json.loads(json.dumps(s2)))
    http1 = sorted(f["id"] for f in s1["findings"] if f["check"] == "http")
    http3 = sorted(f["id"] for f in s3["findings"] if f["check"] == "http")
    assert http1 and http1 == http3, (http1, http3)
    assert all(f.get("carried") for f in s3["findings"] if f["check"] == "http")
    assert s3["facts"]["http"]["carried"] and s3["facts"]["http"].get("redirect_not_followed")
    assert s3["score"] == s1["score"], (s1["score"], s3["score"])
    assert diff_findings(s2["findings"], s3["findings"]) == []
    # http comes back: same ids, so nothing new
    s4 = real_scan()
    jobs.carry_forward(s4, s3)
    assert diff_findings(s3["findings"], s4["findings"]) == []


def test_old_idless_prev_against_new_shape():
    s1 = real_scan(days_left=12)
    old = legacy(s1)
    s2 = real_scan(days_left=11)
    jobs.carry_forward(s2, old)
    new = diff_findings(old["findings"], s2["findings"])
    # Only the documented one-off: TLS titles changed, so they look new once. Nothing else.
    assert sorted(f["id"] for f in new) == ["tls.expiry_21d", "tls.legacy_protocol"], [f["id"] for f in new]
    # And the scan after that is quiet again.
    s3 = real_scan(days_left=10)
    jobs.carry_forward(s3, s2)
    assert diff_findings(s2["findings"], s3["findings"]) == []


def test_old_idless_prev_carried_into_new_scan_then_diffed():
    old = legacy(real_scan())
    s2 = real_scan(http_times_out=True)
    jobs.carry_forward(s2, old)
    carried = [f for f in s2["findings"] if f.get("carried")]
    assert carried and all("id" not in f for f in carried)  # carried as stored
    s3 = real_scan()
    jobs.carry_forward(s3, s2)
    new = diff_findings(s2["findings"], s3["findings"])
    assert all(f["check"] == "tls" for f in new), [f["id"] for f in new]  # http matched by title fallback


def _domain_with_prev(prev_result, alerts=True):
    uid = db.create_user(f"int{time.time_ns()}@example.com", auth.hash_password("correct-horse-1"))
    did = db.add_domain(uid, "example.com", "tok")
    if alerts is not None:
        with db.conn() as c:
            c.execute("UPDATE domains SET alerts=? WHERE id=?", (1 if alerts else 0, did))
    sid = db.start_scan(did)
    db.finish_scan(sid, prev_result, 0)
    return uid, did


def _execute(did, next_result):
    sent = []

    async def fake_run(domain, verified=False):
        return json.loads(json.dumps(next_result))
    with patched(jobs, run_scan=fake_run,
                 send_alert=lambda to, dom, res, new, uid=None: sent.append([f.get("id") for f in new])):
        sid = db.start_scan(did)
        asyncio.run(jobs._execute(sid, dict(db.get_domain(did))))
    row = db.latest_scan(did)
    return row, sent


def test_execute_end_to_end_new_and_old_prev():
    # old (id-less) stored result -> new scan: completes, alerts only the TLS one-off
    _, did = _domain_with_prev(legacy(real_scan(days_left=12)))
    row, sent = _execute(did, real_scan(days_left=11))
    assert row["status"] == "done", dict(row)
    assert row["new_issues"] == 2 and len(sent) == 1, (row["new_issues"], sent)
    assert sorted(sent[0]) == ["tls.expiry_21d", "tls.legacy_protocol"], sent
    stored = json.loads(row["result_json"])
    assert stored["facts"]["dns"]["ips"] and all(f.get("id") for f in stored["findings"])
    # new stored result -> new scan with http timeout: done, carried, no alert
    row2, sent2 = _execute(did, real_scan(days_left=10, http_times_out=True))
    assert row2["status"] == "done" and row2["new_issues"] == 0 and sent2 == [], (dict(row2), sent2)
    assert any(f.get("carried") and f["check"] == "http" for f in json.loads(row2["result_json"])["findings"])


# ---------------------------------------------------------------- templates with the new fields

def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_pages_render_with_new_fields():
    rich = real_scan(days_left=5)  # tls.expiry_7d, redirect_not_followed, truncated, dns.ips
    rich["facts"]["ports"] = {"ip": PUBLIC_IP, "open": [22], "checked": [21, 22, 3306]}
    timed_out = real_scan(http_times_out=True)

    async def fake_run(domain, verified=False):
        return json.loads(json.dumps(rich))
    with TestClient(main.app) as c, patched(jobs, run_scan=fake_run), patched(main, run_scan=fake_run):
        token = _csrf(c.get("/register").text)
        r = c.post("/register", data={"email": f"render{time.time_ns()}@example.com",
                                      "password": "correct-horse-1", "csrf": token})
        assert r.status_code == 200, r.status_code
        token = _csrf(r.text)
        r = c.post("/domains", data={"domain": "example.com", "csrf": token})
        assert r.status_code == 200 and r.url.path.startswith("/domains/"), (r.status_code, r.url)
        did = int(r.url.path.rsplit("/", 1)[1])
        end = time.time() + 5
        while db.running_scan(did) and time.time() < end:
            time.sleep(0.05)
        assert db.latest_scan(did)["status"] == "done"
        page = c.get(f"/domains/{did}")
        assert page.status_code == 200 and "SSL certificate expires within a week" in page.text
        assert "Test CA" in page.text
        rep = c.get(f"/domains/{did}/report")
        assert rep.status_code == 200 and "SSL certificate expires within a week" in rep.text
        dash = c.get("/dashboard")
        assert dash.status_code == 200 and "example.com" in dash.text
        assert c.get(f"/api/domains/{did}/status").status_code == 200
        # carried + id-less legacy data on the pages too
        sid = db.start_scan(did)
        jobs.carry_forward(timed_out, legacy(rich))
        db.finish_scan(sid, timed_out, 0)
        for url in (f"/domains/{did}", f"/domains/{did}/report", "/dashboard"):
            resp = c.get(url)
            assert resp.status_code == 200, (url, resp.status_code)
        # anonymous free check result page
        c.post("/logout", data={"csrf": token})
        token = _csrf(c.get("/").text)
        chk = c.post("/check", data={"domain": "example.com", "csrf": token})
        assert chk.status_code == 200 and "example.com" in chk.text, chk.status_code


if __name__ == "__main__":
    tests = [(n, fn) for n, fn in globals().items() if n.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:
            failed += 1
            import traceback
            traceback.print_exc()
            print(f"FAIL {name}: {e!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)

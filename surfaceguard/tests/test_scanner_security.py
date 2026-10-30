"""Offline tests for scanner SSRF / resource limits and stable finding ids. No network access.
Run with:  python tests/test_scanner_security.py"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx  # noqa: E402

from app import scanner  # noqa: E402
from app.scoring import diff_findings  # noqa: E402

PUBLIC_IP = "93.184.216.34"
WWW_IP = "93.184.216.35"


class patched:
    """Temporarily replace module attributes."""
    def __init__(self, obj, **attrs):
        self.obj, self.attrs, self.saved = obj, attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(self.obj, k)
            setattr(self.obj, k, v)

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            setattr(self.obj, k, v)


def fake_dns(table):
    """dns_records replacement: table maps (name, rtype) -> list of answers."""
    return lambda name, rtype: table.get((name, rtype), [])


# ---------------------------------------------------------------- L5: is_global

def test_is_public_ip():
    for ip in ["8.8.8.8", PUBLIC_IP, "2606:4700:4700::1111"]:
        assert scanner._is_public_ip(ip), ip
    for ip in ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1",
               "100.64.0.1", "100.127.255.254",          # CGNAT
               "0.0.0.0", "255.255.255.255", "224.0.0.1", "198.18.0.1", "192.0.2.1",
               "::1", "::", "fe80::1", "fdaa::3", "fc00::1", "ff0e::1",
               "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:100.64.0.1",  # IPv4-mapped
               "2002:7f00:1::1", "2002:a00:1::1",        # 6to4 wrapping 127.0.0.1 / 10.0.0.1
               "2001:0:4136:e378:8000:63bf:3fff:fdd2",    # Teredo
               "64:ff9b::7f00:1", "64:ff9b::a00:1",       # NAT64 wrapping private v4
               "not-an-ip", ""]:
        assert not scanner._is_public_ip(ip), ip
    assert scanner._is_public_ip("::ffff:8.8.8.8")
    # The stdlib treats all of 6to4 (2002::/16) as non-global, so even a public embedded v4
    # is refused. Stricter than needed, and 6to4 is effectively unused for websites.
    assert not scanner._is_public_ip("2002:808:808::1")


def test_check_dns_rejects_cgnat_and_keeps_validated_ips():
    with patched(scanner, dns_records=fake_dns({("x.example.com", "A"): ["100.64.1.2"],
                                                ("x.example.com", "NS"): ["ns1.x."]})):
        try:
            scanner.check_dns("x.example.com")
            raise AssertionError("CGNAT accepted")
        except scanner.ScanError:
            pass
    with patched(scanner, dns_records=fake_dns({("ok.example.com", "A"): [PUBLIC_IP]})):
        _, facts = scanner.check_dns("ok.example.com")
    assert facts["ips"] == [PUBLIC_IP]


def test_resolve_public():
    with patched(scanner, dns_records=fake_dns({("a.example.com", "A"): [PUBLIC_IP],
                                                ("a.example.com", "AAAA"): ["::1"]})):
        try:
            scanner.resolve_public("a.example.com")  # one private answer poisons the whole set
            raise AssertionError("mixed public/private accepted")
        except scanner.ScanError:
            pass
    assert scanner.resolve_public(PUBLIC_IP) == [PUBLIC_IP]
    for ip in ("127.0.0.1", "169.254.169.254"):
        try:
            scanner.resolve_public(ip)
            raise AssertionError(f"{ip} accepted")
        except scanner.ScanError:
            pass


# ---------------------------------------------------------------- H1: redirect validation

def test_redirect_target_rules():
    ok = scanner._redirect_target("https://example.com/", "https://www.example.com/a?b=1")
    assert ok == "https://www.example.com/a?b=1"
    assert scanner._redirect_target("https://example.com/x", "/login") == "https://example.com/login"
    assert scanner._redirect_target("https://example.com/", "http://example.com:80/") .startswith("http://example.com")
    for loc in ["ftp://example.com/", "file:///etc/passwd", "gopher://x.com/", "https://example.com:8443/",
                "http://example.com:6379/", "http://[::1]:8080/", ""]:
        try:
            scanner._redirect_target("https://example.com/", loc)
            raise AssertionError(f"accepted {loc!r}")
        except scanner.ScanError:
            pass


def _http_transport(routes, log):
    """MockTransport: routes maps (pinned_ip, Host header, path) -> Response. Every request
    is logged so tests can check which IP it was really sent to."""
    def handler(request):
        key = (request.url.host, request.headers["host"], request.url.path)
        log.append(key)
        if key in routes:
            return routes[key]
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _run_http(routes, dns_table):
    log = []
    with patched(scanner, dns_records=fake_dns(dns_table)):
        f, facts = asyncio.run(scanner.check_http("example.com", True, [PUBLIC_IP],
                                                  transport=_http_transport(routes, log)))
    return f, facts, log


def test_redirect_to_private_ip_is_not_followed():
    for target in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
                   "http://[fdaa::3]/", "http://[::ffff:10.0.0.1]/", "http://100.64.0.1/"]:
        routes = {(PUBLIC_IP, "example.com", "/"): httpx.Response(302, headers={"location": target})}
        f, facts, log = _run_http(routes, {})
        hosts = {h for h, _, _ in log}
        assert hosts == {PUBLIC_IP}, (target, log)
        assert "redirect_not_followed" in facts, (target, facts)
        assert facts["status"] == 302


def test_redirect_to_host_resolving_private_is_not_followed():
    routes = {(PUBLIC_IP, "example.com", "/"): httpx.Response(301, headers={"location": "https://evil.test/"})}
    f, facts, log = _run_http(routes, {("evil.test", "A"): ["10.1.2.3"]})
    assert all(h == PUBLIC_IP for h, _, _ in log), log
    assert "private" in facts["redirect_not_followed"]


def test_redirect_to_bad_port_is_not_followed():
    routes = {(PUBLIC_IP, "example.com", "/"): httpx.Response(301, headers={"location": "http://www.example.com:8080/"})}
    f, facts, log = _run_http(routes, {("www.example.com", "A"): [WWW_IP]})
    assert all(h == PUBLIC_IP for h, _, _ in log), log
    assert "port" in facts["redirect_not_followed"]


def test_valid_redirect_is_followed_pinned_with_host_header():
    routes = {
        (PUBLIC_IP, "example.com", "/"): httpx.Response(301, headers={"location": "https://www.example.com/home"}),
        (WWW_IP, "www.example.com", "/home"): httpx.Response(200, headers={
            "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY"}),
    }
    f, facts, log = _run_http(routes, {("www.example.com", "A"): [WWW_IP]})
    assert (WWW_IP, "www.example.com", "/home") in log, log
    assert facts["status"] == 200 and facts["final_url"] == "https://www.example.com/home"
    assert "redirect_not_followed" not in facts
    # headers were read from the final page, so no missing-header findings
    assert not [x for x in f if x["id"].startswith("http.missing.")], f


def test_redirect_loop_is_capped():
    routes = {(PUBLIC_IP, "example.com", "/"): httpx.Response(302, headers={"location": "/"})}
    f, facts, log = _run_http(routes, {})
    https_hits = [x for x in log if x[2] == "/"]
    assert len(https_hits) <= scanner.MAX_REDIRECTS + 2, log  # +1 plain-http probe
    assert "redirects" in facts["redirect_not_followed"]


# ---------------------------------------------------------------- H2: pinning

def test_tls_connects_to_validated_ip_only():
    calls = []

    def fake_connect(addr, timeout=None):
        calls.append(addr)
        raise OSError("refused")
    with patched(scanner.socket, create_connection=fake_connect):
        f, facts = scanner.check_tls("example.com", [PUBLIC_IP, WWW_IP])
    assert calls == [(PUBLIC_IP, 443), (WWW_IP, 443)], calls
    assert facts.get("error") and f[0]["id"] == "tls.unavailable"


def test_exposed_files_pinned_and_body_capped():
    sent = {"bytes": 0}

    async def endless():
        while True:
            sent["bytes"] += 1024
            yield b"[core]" + b"A" * 1018
            if sent["bytes"] > 50 * 1024 * 1024:
                raise AssertionError("body was not capped")

    log = []

    def handler(request):
        log.append((request.url.host, request.headers["host"], request.extensions.get("sni_hostname")))
        if request.url.path == "/.git/config":
            return httpx.Response(200, content=endless())
        return httpx.Response(404)
    f, _ = asyncio.run(scanner.check_exposed_files("example.com", [PUBLIC_IP],
                                                   transport=httpx.MockTransport(handler)))
    assert {h for h, _, _ in log} == {PUBLIC_IP}
    assert {h for _, h, _ in log} == {"example.com"}
    assert {s for _, _, s in log} == {"example.com"}  # SNI is the real hostname
    assert sent["bytes"] < 64 * 1024, sent
    assert [x["id"] for x in f] == ["exposure..git/config"]


# ---------------------------------------------------------------- H3: crt.sh byte cap

def test_crtsh_body_is_capped_and_partial_json_used():
    sent = {"bytes": 0}
    entry = b'{"issuer_name":"x","name_value":"a.example.com\\nb.example.com"},'
    seen = {}

    async def huge():
        yield b"["
        while True:
            sent["bytes"] += len(entry) * 100
            yield entry * 100
            if sent["bytes"] > 50 * 1024 * 1024:
                raise AssertionError("crt.sh body was not capped")

    def handler(request):
        seen.update(request.url.params)
        return httpx.Response(200, content=huge())

    probe = lambda n: {"name": n, "cname": None, "live": True}
    with patched(scanner, _probe_subdomain=probe):
        f, facts = asyncio.run(scanner.check_subdomains("example.com", transport=httpx.MockTransport(handler)))
    assert sent["bytes"] < scanner.CRTSH_MAX_BYTES + 256 * 1024, sent
    assert facts.get("truncated") is True and "error" not in facts
    assert [s["name"] for s in facts["subdomains"]] == ["a.example.com", "b.example.com"]
    assert seen.get("exclude") == "expired" and seen.get("deduplicate") == "Y"


def test_crtsh_error_status_degrades():
    t = httpx.MockTransport(lambda r: httpx.Response(502, text="<html>bad gateway</html>"))
    f, facts = asyncio.run(scanner.check_subdomains("example.com", transport=t))
    assert f == [] and facts["error"]


def test_crtsh_names_parser():
    body = b'[{"name_value":"*.x.example.com\\nother.org"},{"name_value":"y.example.com"},{"name_value":"trunc'
    assert scanner._crtsh_names(body, "example.com") == {"x.example.com", "y.example.com"}


# ---------------------------------------------------------------- M10: DKIM in parallel

def test_dkim_selectors_concurrent():
    def txt(name):
        if name == "google._domainkey.example.com":
            return ["v=DKIM1; k=rsa; p=MIIB"]
        return []
    with patched(scanner, dns_txt=txt):
        f, facts = asyncio.run(scanner.check_email_async("example.com", True))
    assert facts["dkim_selectors"] == ["google"]
    assert "email.dkim_missing" not in [x["id"] for x in f]
    with patched(scanner, dns_txt=lambda name: []):
        f, facts = asyncio.run(scanner.check_email_async("example.com", True))
    assert facts["dkim_selectors"] == [] and "email.dkim_missing" in [x["id"] for x in f]


# ---------------------------------------------------------------- L1: stable ids

def _F(id, title, sev="medium", check="tls"):
    return scanner.finding(check, sev, title, "d", "fix", id=id)


def test_diff_uses_stable_id():
    old = [_F("tls.expiry_21d", "SSL certificate expires within 3 weeks")]
    new = [_F("tls.expiry_21d", "Some reworded title"), _F("http.missing.x", "X missing", check="http")]
    assert [f["id"] for f in diff_findings(old, new)] == ["http.missing.x"]


def test_diff_falls_back_to_title_for_old_results():
    legacy = {"check": "email", "severity": "high", "title": "No DMARC policy", "detail": "d", "fix": "f"}
    new = [_F("email.dmarc_missing", "No DMARC policy", "high", "email"), _F("email.spf_missing", "No SPF", "high", "email")]
    assert [f["id"] for f in diff_findings([legacy], new)] == ["email.spf_missing"]
    # a new result without ids also diffs fine
    assert diff_findings([legacy], [dict(legacy)]) == []


def test_tls_expiry_finding_title_has_no_day_count():
    import ssl
    from datetime import datetime, timedelta, timezone
    exp = datetime.now(timezone.utc) + timedelta(days=10, hours=1)
    cert = {"notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT"), "issuer": ((("organizationName", "CA"),),)}

    def fake_tls(host, ips, legacy=False):
        if legacy:
            raise ssl.SSLError("no legacy")
        return cert, "TLSv1.3"
    with patched(scanner, _tls_connect=fake_tls):
        f, facts = scanner.check_tls("example.com", [PUBLIC_IP])
    assert [x["id"] for x in f] == ["tls.expiry_21d"]
    assert "10" not in f[0]["title"] and "10 days" in f[0]["detail"]


def test_every_finding_has_id():
    assert scanner.finding("x", "low", "t", "d", "f")["id"] == "x.t"


if __name__ == "__main__":
    tests = [(n, fn) for n, fn in sorted(globals().items()) if n.startswith("test_") and callable(fn)]
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

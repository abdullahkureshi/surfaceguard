"""Attack-surface checks.

Passive checks (DNS, email security, TLS, HTTP headers, public subdomains) run for
any domain. Active probing (exposed files, risky open ports) only runs for domains
whose ownership the user has verified via a DNS TXT record.

SSRF safety: the domain is resolved once in `check_dns`, every IP must be globally
routable, and every later connection (TLS, HTTP, exposed-file probes, ports) goes to one
of those validated IPs instead of re-resolving the name. Redirects are followed by hand
and each hop is validated the same way. Response bodies are never read in full.
"""
import asyncio
import functools
import ipaddress
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from .scoring import score_findings

USER_AGENT = "SurfaceGuard-Scanner/0.1 (+attack surface monitoring)"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DNS_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
              dns.exception.Timeout, dns.resolver.YXDOMAIN)

# Limits that keep one hostile target from exhausting memory or threads.
CRTSH_MAX_BYTES = 5 * 1024 * 1024   # crt.sh JSON is cut off here and parsed as far as it got
PROBE_MAX_BYTES = 4096              # exposed-file probes only need the first few KB
MAX_REDIRECTS = 5
ALLOWED_PORTS = {"http": 80, "https": 443}
DNS_CONCURRENCY = 10                # per-scan cap on parallel blocking lookups

# Blocking DNS/TLS work runs on this bounded pool instead of the loop's default executor,
# so scans cannot starve other asyncio.to_thread users (e.g. /verify).
_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="surfaceguard-scan")


async def _blocking(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(_POOL, functools.partial(fn, *args))


class ScanError(Exception):
    pass


def finding(check, severity, title, detail, fix, evidence=None, id=None):
    """`id` is a stable key (e.g. "tls.expiry_7d") used to diff scans for alerts. Titles and
    details may contain changing numbers; ids must not."""
    return {"id": id or f"{check}.{title}", "check": check, "severity": severity, "title": title,
            "detail": detail, "fix": fix, "evidence": evidence}


def normalize_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split("?")[0].split(":")[0].strip(".")
    if d.startswith("www."):
        d = d[4:]
    try:
        d = d.encode("idna").decode()
    except UnicodeError:
        raise ScanError("That doesn't look like a valid domain.")
    if not DOMAIN_RE.match(d):
        raise ScanError("That doesn't look like a valid domain (example: yourcompany.com).")
    return d


# ---------------------------------------------------------------- DNS helpers

def _resolver():
    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = 3, 6
    return r


def dns_records(name, rtype):
    try:
        return [r.to_text() for r in _resolver().resolve(name, rtype)]
    except DNS_ERRORS:
        return []


def dns_txt(name):
    try:
        return [b"".join(r.strings).decode(errors="replace") for r in _resolver().resolve(name, "TXT")]
    except DNS_ERRORS:
        return []


class DNSLookupUnknown(Exception):
    """The lookup failed (timeout, SERVFAIL, no nameservers): we don't know whether the record exists."""


def dns_txt_strict(name):
    """Like dns_txt, but only an authoritative "no such name" or "no TXT records" answer gives [].
    A timeout or server failure raises DNSLookupUnknown instead of looking like an empty answer."""
    try:
        return [b"".join(r.strings).decode(errors="replace") for r in _resolver().resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN) as e:
        raise DNSLookupUnknown(type(e).__name__) from e


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _is_public_ip(ip):
    """True only for globally routable unicast addresses. IPv6 forms that embed an IPv4
    address (IPv4-mapped, 6to4, Teredo, NAT64) are judged by the embedded address too."""
    try:
        a = ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return False
    if a.version == 6:
        if a.ipv4_mapped:
            return _is_public_ip(a.ipv4_mapped)
        embedded = []
        if a.sixtofour:
            embedded.append(a.sixtofour)
        if a.teredo:
            embedded.extend(a.teredo)
        if a in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
        if not all(_is_public_ip(e) for e in embedded):
            return False
    return a.is_global and not a.is_multicast


def resolve_public(host):
    """Resolve `host` once and return its IPs (IPv4 first). Raises ScanError if any of them
    is not public. Callers connect to these exact IPs, never to the name (DNS rebinding)."""
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = dns_records(host, "A") + dns_records(host, "AAAA")
    if ips and not all(_is_public_ip(ip) for ip in ips):
        raise ScanError("This domain points to a private/internal IP address and can't be scanned.")
    return ips


# ---------------------------------------------------------------- checks

def check_dns(domain):
    facts = {"a": dns_records(domain, "A"), "aaaa": dns_records(domain, "AAAA"),
             "mx": dns_records(domain, "MX"), "ns": dns_records(domain, "NS"),
             "caa": dns_records(domain, "CAA")}
    findings = []
    if not facts["ns"] and not facts["a"] and not facts["aaaa"]:
        raise ScanError(f"{domain} does not exist in DNS.")
    ips = facts["a"] + facts["aaaa"]
    if ips and not all(_is_public_ip(ip) for ip in ips):
        raise ScanError("This domain points to a private/internal IP address and can't be scanned.")
    # The validated IPs: every later connection to the domain is pinned to these.
    facts["ips"] = ips
    if not ips:
        findings.append(finding("dns", "medium", "Domain has no website address (A/AAAA record)",
                                f"{domain} has no A or AAAA record, so web checks were skipped.",
                                "If you expect a website here, add an A record pointing to your web server.",
                                id="dns.no_address"))
    if not facts["caa"]:
        findings.append(finding("dns", "low", "No CAA record",
                                "Any certificate authority is allowed to issue SSL certificates for your domain.",
                                'Add a CAA record listing the CA you use, e.g. `0 issue "letsencrypt.org"`.',
                                id="dns.no_caa"))
    return findings, facts


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail",
                  "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "zoho"]


def _has_dkim(domain, selector):
    return any("p=" in t for t in dns_txt(f"{selector}._domainkey.{domain}"))


def _dkim_findings(found):
    if found:
        return []
    return [finding(
        "email", "low", "No DKIM key found on common selectors",
        "DKIM cryptographically signs your outgoing email. We checked common selector names and "
        "found none (you may use a custom selector).",
        "Enable DKIM signing in your email provider's admin console and publish the DNS record it gives you.",
        id="email.dkim_missing")]


def check_email(domain, has_mx, include_dkim=True):
    findings, facts = [], {}
    txt = dns_txt(domain)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    facts["spf"] = spf[0] if spf else None
    if not spf:
        findings.append(finding(
            "email", "high" if has_mx else "medium", "No SPF record — anyone can send email as you",
            "SPF tells receiving mail servers which servers may send email for your domain. Without it, "
            "attackers can more easily spoof your address in phishing emails.",
            "Add a TXT record on your domain. If you use Google Workspace: `v=spf1 include:_spf.google.com -all`. "
            "Microsoft 365: `v=spf1 include:spf.protection.outlook.com -all`. "
            "If this domain never sends email: `v=spf1 -all`.", id="email.spf_missing"))
    elif len(spf) > 1:
        findings.append(finding("email", "medium", "Multiple SPF records (invalid)",
                                "Having more than one SPF record makes SPF fail completely.",
                                "Merge them into a single `v=spf1 ...` TXT record.", evidence=" | ".join(spf),
                                id="email.spf_multiple"))
    else:
        rec = spf[0].lower()
        if "+all" in rec:
            findings.append(finding("email", "critical", "SPF allows the entire internet to send as you",
                                    "Your SPF record ends in `+all`, which authorizes every server in the world.",
                                    "Change `+all` to `-all` (or `~all` while testing).", evidence=spf[0],
                                    id="email.spf_plus_all"))
        elif "?all" in rec:
            findings.append(finding("email", "medium", "SPF policy is neutral (?all)",
                                    "`?all` gives no protection against spoofed mail.",
                                    "Change `?all` to `-all` (or `~all`).", evidence=spf[0],
                                    id="email.spf_neutral"))
        elif not re.search(r"[-~]all", rec) and "redirect=" not in rec:
            findings.append(finding("email", "medium", "SPF record has no 'all' rule",
                                    "Without a final `-all`/`~all`, unlisted servers aren't rejected.",
                                    "End your SPF record with `-all`.", evidence=spf[0],
                                    id="email.spf_no_all"))

    dmarc = [t for t in dns_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    facts["dmarc"] = dmarc[0] if dmarc else None
    if not dmarc:
        findings.append(finding(
            "email", "high", "No DMARC policy",
            "DMARC tells mail providers what to do with emails that fail SPF/DKIM. Without it, spoofed "
            "emails from your domain are usually delivered.",
            f"Add a TXT record at `_dmarc.{domain}`: `v=DMARC1; p=none; rua=mailto:dmarc@{domain}` to start "
            "monitoring, then move to `p=quarantine` and finally `p=reject`.", id="email.dmarc_missing"))
    else:
        tags = dict(kv.strip().split("=", 1) for kv in dmarc[0].split(";") if "=" in kv)
        tags = {k.strip().lower(): v.strip().lower() for k, v in tags.items()}
        if tags.get("p") == "none":
            findings.append(finding("email", "medium", "DMARC is in monitor-only mode (p=none)",
                                    "Spoofed emails are still delivered; DMARC is only reporting.",
                                    "Once your reports look clean, change to `p=quarantine`, then `p=reject`.",
                                    evidence=dmarc[0], id="email.dmarc_p_none"))
        if "rua" not in tags:
            findings.append(finding("email", "low", "DMARC reports are not collected",
                                    "Without `rua=`, you never see who is sending email as your domain.",
                                    f"Add `rua=mailto:dmarc@{domain}` to your DMARC record.", evidence=dmarc[0],
                                    id="email.dmarc_no_rua"))

    if has_mx and include_dkim:
        facts["dkim_selectors"] = [s for s in DKIM_SELECTORS if _has_dkim(domain, s)]
        findings += _dkim_findings(facts["dkim_selectors"])
    return findings, facts


async def check_email_async(domain, has_mx):
    """check_email with the DKIM selectors looked up in parallel on the scanner pool."""
    sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def lookup(fn, *args):
        async with sem:
            return await _blocking(fn, *args)
    base = lookup(check_email, domain, has_mx, False)
    if not has_mx:
        return await base
    (findings, facts), *hits = await asyncio.gather(
        base, *(lookup(_has_dkim, domain, s) for s in DKIM_SELECTORS))
    facts["dkim_selectors"] = [s for s, hit in zip(DKIM_SELECTORS, hits) if hit]
    return findings + _dkim_findings(facts["dkim_selectors"]), facts


def _tls_connect(host, ips, legacy=False):
    """TLS handshake with `host` (SNI and certificate name), connecting only to the
    pre-validated `ips` so a second DNS answer cannot send us somewhere else."""
    if legacy:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.minimum_version, ctx.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    else:
        ctx = ssl.create_default_context()
    if not ips:
        raise OSError(f"no validated address for {host}")
    last = None
    for ip in ips[:3]:
        try:
            sock = socket.create_connection((ip, 443), timeout=6)
        except OSError as e:  # try the next address, as a name-based connect would
            last = e
            continue
        with sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(), ss.version()
    raise last


def check_tls(domain, ips=None):
    findings, facts = [], {}
    ips = resolve_public(domain) if ips is None else ips
    try:
        cert, version = _tls_connect(domain, ips)
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        facts["error"] = msg
        findings.append(finding("tls", "critical", "Invalid SSL certificate",
                                f"Browsers will show a security warning for https://{domain}: {msg}.",
                                "Install a valid certificate for this exact hostname (free via Let's Encrypt, "
                                "or enable it in your hosting panel).", id="tls.invalid_cert"))
        return findings, facts
    except (OSError, ssl.SSLError) as e:
        facts["error"] = str(e)
        findings.append(finding("tls", "high", "HTTPS is not available",
                                f"Could not establish an HTTPS connection to {domain} on port 443.",
                                "Enable HTTPS on your web server/hosting. Let's Encrypt certificates are free.",
                                id="tls.unavailable"))
        return findings, facts

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    facts.update(protocol=version, expires=expires.date().isoformat(), days_left=days,
                 issuer=issuer.get("organizationName") or issuer.get("commonName"))
    # Titles stay constant; the day count lives in `detail` so daily scans don't re-alert.
    if days <= 7:
        findings.append(finding("tls", "high", "SSL certificate expires within a week",
                                f"Your certificate expires in {days} days, on {expires.date()}. "
                                "After that visitors see a full-page warning.",
                                "Renew the certificate now and enable automatic renewal.", id="tls.expiry_7d"))
    elif days <= 21:
        findings.append(finding("tls", "medium", "SSL certificate expires within 3 weeks",
                                f"Your certificate expires in {days} days, on {expires.date()}.",
                                "Renew soon, and check that automatic renewal is working.", id="tls.expiry_21d"))
    try:
        _, legacy_version = _tls_connect(domain, ips, legacy=True)
        findings.append(finding("tls", "medium", "Outdated encryption protocol accepted (TLS 1.0/1.1)",
                                "TLS 1.0/1.1 are deprecated and have known weaknesses. PCI-DSS forbids them.",
                                "Disable TLS 1.0 and 1.1 in your web server / CDN settings; allow only TLS 1.2+.",
                                evidence=f"Server accepted {legacy_version}", id="tls.legacy_protocol"))
    except Exception:
        pass
    return findings, facts


SECURITY_HEADERS = [
    ("strict-transport-security", "medium", "HSTS header missing",
     "Without HSTS, a visitor on public Wi-Fi can be downgraded to unencrypted HTTP.",
     "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
    ("content-security-policy", "low", "Content-Security-Policy header missing",
     "CSP is a strong defense against cross-site scripting (XSS) and injected scripts.",
     "Add a Content-Security-Policy header. Start with `default-src 'self'` in report-only mode and tighten."),
    ("x-content-type-options", "low", "X-Content-Type-Options header missing",
     "Browsers may 'guess' file types, which can enable some attacks.",
     "Add `X-Content-Type-Options: nosniff`."),
    ("referrer-policy", "low", "Referrer-Policy header missing",
     "Full URLs (which may contain tokens) can leak to third-party sites.",
     "Add `Referrer-Policy: strict-origin-when-cross-origin`."),
]


def _client(timeout, transport=None):
    # trust_env=False: no proxy from the environment may re-resolve our pinned hosts.
    # identity encoding: we never ask the target for something we would have to decompress.
    # Connection: close: pooled connections are keyed by IP, so reusing one could send a
    # request for host B over a TLS session negotiated with SNI for host A.
    return httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False, trust_env=False,
                             transport=transport,
                             headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                                      "Connection": "close"})


async def _pinned_send(client, url, ips, timeout=None):
    """GET `url` from one of the validated `ips` (the name is never re-resolved) with the
    Host header and TLS SNI set to the real hostname. Returns a *streamed* response whose
    body has not been read; the caller must close it."""
    url = httpx.URL(url)
    host = url.host
    try:
        ipaddress.ip_address(host)
        sni = {}  # no SNI for IP literals
    except ValueError:
        sni = {"sni_hostname": host} if url.scheme == "https" else {}
    kw = {} if timeout is None else {"timeout": timeout}
    last = None
    for ip in ips[:3]:
        req = client.build_request("GET", url.copy_with(host=ip), headers={"Host": url.netloc.decode("ascii")},
                                   extensions=sni, **kw)
        try:
            return await client.send(req, stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:  # try the next validated address
            last = e
    raise last or httpx.ConnectError(f"no validated address for {host}")


def _redirect_target(current, location):
    """Validate one redirect hop and return the absolute next URL, or raise ScanError.
    Only http/https on ports 80/443 are followed; the host is checked by the caller."""
    if not location:
        raise ScanError("redirect without a Location header")
    try:
        nxt = httpx.URL(current).join(location)
    except Exception:
        raise ScanError("redirect to an invalid URL")
    if nxt.scheme not in ALLOWED_PORTS:
        raise ScanError(f"redirect to unsupported scheme {nxt.scheme!r}")
    if (nxt.port or ALLOWED_PORTS[nxt.scheme]) not in ALLOWED_PORTS.values():
        raise ScanError(f"redirect to non-standard port {nxt.port}")
    if not nxt.host:
        raise ScanError("redirect without a host")
    return str(nxt)


async def fetch_headers(client, url, ips, timeout=None, max_redirects=MAX_REDIRECTS):
    """GET `url` (whose host resolves to the validated `ips`) and follow redirects by hand.
    Each hop is checked by `_redirect_target`, a new host is resolved once with every IP
    required to be public, and the connection is pinned to those IPs. Bodies are never
    read. Returns (response, final_url, reason_redirect_was_not_followed_or_None)."""
    host_ips = {httpx.URL(url).host: ips}
    for hop in range(max_redirects + 1):
        r = await _pinned_send(client, url, host_ips[httpx.URL(url).host], timeout)
        await r.aclose()  # headers only: the body is never downloaded
        if not r.is_redirect:
            return r, url, None
        if hop == max_redirects:
            return r, url, f"more than {max_redirects} redirects"
        try:
            nxt = _redirect_target(url, r.headers.get("location", ""))
            nhost = httpx.URL(nxt).host
            if nhost not in host_ips:
                host_ips[nhost] = await _blocking(resolve_public, nhost)
            if not host_ips[nhost]:
                raise ScanError(f"redirect host {nhost} does not resolve")
        except ScanError as e:
            return r, url, str(e)
        url = nxt


async def check_http(domain, https_ok, ips=None, transport=None):
    findings, facts = [], {}
    ips = await _blocking(resolve_public, domain) if ips is None else ips
    async with _client(10, transport) as c:
        try:
            r = await _pinned_send(c, f"http://{domain}/", ips)
            await r.aclose()
            loc = r.headers.get("location", "")
            facts["http_redirects_to_https"] = r.is_redirect and loc.startswith("https://")
            if https_ok and not facts["http_redirects_to_https"]:
                findings.append(finding("http", "medium", "HTTP does not redirect to HTTPS",
                                        f"http://{domain} serves content without forcing encryption.",
                                        "Configure a permanent (301) redirect from HTTP to HTTPS.",
                                        id="http.no_https_redirect"))
        except httpx.HTTPError:
            pass
        if not https_ok:
            return findings, facts
        r = None
        for attempt_timeout in (10, 20):  # slow sites get one retry with a longer timeout
            try:
                r, final_url, blocked = await fetch_headers(c, f"https://{domain}/", ips, timeout=attempt_timeout)
                break
            except httpx.HTTPError as e:
                facts["error"] = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        if r is None:
            return findings, facts
        facts.pop("error", None)
        if blocked:
            facts["redirect_not_followed"] = blocked

    h = r.headers
    facts.update(status=r.status_code, final_url=final_url, server=h.get("server"))
    csp = h.get("content-security-policy", "")
    for name, sev, title, detail, fix in SECURITY_HEADERS:
        if name not in h:
            findings.append(finding("http", sev, title, detail, fix, id=f"http.missing.{name}"))
    hsts = h.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            findings.append(finding("http", "low", "HSTS max-age is short",
                                    "HSTS protection expires quickly (less than 6 months).",
                                    "Use `max-age=31536000` (1 year).", evidence=hsts, id="http.hsts_short"))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        findings.append(finding("http", "low", "Clickjacking protection missing",
                                "Your site can be embedded in an invisible frame on a malicious page.",
                                "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'self'`.",
                                id="http.no_clickjacking_protection"))
    server = h.get("server", "")
    if re.search(r"\d", server):
        findings.append(finding("http", "low", "Server software version is disclosed",
                                "Revealing exact versions helps attackers find matching exploits.",
                                "Hide the version (nginx: `server_tokens off;`, Apache: `ServerTokens Prod`).",
                                evidence=f"Server: {server}", id="http.server_version"))
    if "x-powered-by" in h:
        findings.append(finding("http", "low", "Technology stack disclosed (X-Powered-By)",
                                "The X-Powered-By header reveals your framework and often its version.",
                                "Remove the X-Powered-By header in your app/server config.",
                                evidence=f"X-Powered-By: {h['x-powered-by']}", id="http.x_powered_by"))
    weak = []
    for cookie in h.get_list("set-cookie"):
        low = cookie.lower()
        if "secure" not in low or "httponly" not in low:
            weak.append(cookie.split("=", 1)[0])
    if weak:
        findings.append(finding("http", "low", "Cookies without Secure/HttpOnly flags",
                                "Session cookies without these flags can be stolen via XSS or unencrypted connections.",
                                "Set `Secure; HttpOnly; SameSite=Lax` on all session cookies.",
                                evidence=", ".join(sorted(set(weak))), id="http.weak_cookies"))
    return findings, facts


TAKEOVER_SUFFIXES = (".herokuapp.com", ".herokudns.com", ".github.io", ".s3.amazonaws.com",
                     ".s3-website", ".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net",
                     ".blob.core.windows.net", ".myshopify.com", ".pantheonsite.io", ".ghost.io",
                     ".surge.sh", ".netlify.app", ".bitbucket.io", ".wordpress.com", ".zendesk.com",
                     ".readme.io", ".helpscoutdocs.com", ".cloudfront.net", ".fly.dev")


def _probe_subdomain(name):
    cnames = dns_records(name, "CNAME")
    ips = dns_records(name, "A")
    info = {"name": name, "cname": cnames[0].rstrip(".") if cnames else None, "live": bool(ips)}
    target = info["cname"]
    if target and not ips and any(s in target + "." for s in TAKEOVER_SUFFIXES):
        try:
            _resolver().resolve(target, "A")
        except dns.resolver.NXDOMAIN:
            info["dangling"] = True
        except DNS_ERRORS:
            pass
    return info


_NAME_VALUE_RE = re.compile(rb'"name_value"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _crtsh_names(body, domain):
    """Pull subdomain names out of crt.sh JSON. Works on a truncated body too, which is what
    we have when the response hit CRTSH_MAX_BYTES."""
    names = set()
    for m in _NAME_VALUE_RE.finditer(body):
        try:
            value = json.loads(b'"' + m.group(1) + b'"')
        except ValueError:
            continue
        for n in str(value).lower().split("\n"):
            n = n.strip().lstrip("*.")
            if n.endswith("." + domain) and DOMAIN_RE.match(n):
                names.add(n)
    return names


async def _fetch_capped(client, url, params, cap):
    """Stream a response body and stop at `cap` bytes. Returns (status, body, truncated)."""
    async with client.stream("GET", url, params=params) as r:
        if r.status_code != 200:
            return r.status_code, b"", False
        body = bytearray()
        async for chunk in r.aiter_bytes():
            body += chunk
            if len(body) >= cap:
                return r.status_code, bytes(body[:cap]), True
        return r.status_code, bytes(body), False


async def check_subdomains(domain, transport=None):
    findings, facts = [], {"subdomains": [], "source": "certificate transparency logs (crt.sh)"}
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False, transport=transport,
                                     headers={"User-Agent": USER_AGENT}) as c:
            status, body, truncated = await _fetch_capped(
                c, "https://crt.sh/",
                {"q": f"%.{domain}", "output": "json", "exclude": "expired", "deduplicate": "Y"},
                CRTSH_MAX_BYTES)
        if status != 200:
            raise ValueError(f"crt.sh returned HTTP {status}")
    except Exception:
        facts["error"] = "Certificate transparency lookup timed out; will retry next scan."
        return findings, facts
    if truncated:
        facts["truncated"] = True  # very large log: only the first CRTSH_MAX_BYTES were used
    names = sorted(_crtsh_names(body, domain))[:60]
    sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def probe(n):
        async with sem:
            return await _blocking(_probe_subdomain, n)
    results = await asyncio.gather(*(probe(n) for n in names))
    facts["subdomains"] = results
    if results:
        live = sum(1 for s in results if s["live"])
        findings.append(finding("subdomains", "info", f"{len(results)} subdomains found in public records",
                                f"{live} of them currently resolve. Every live subdomain is part of your attack surface.",
                                "Review the list and remove DNS records for anything you no longer use.",
                                id="subdomains.inventory"))
    for s in results:
        if s.get("dangling"):
            findings.append(finding(
                "subdomains", "high", f"Possible subdomain takeover: {s['name']}",
                f"{s['name']} points to {s['cname']}, which no longer exists. An attacker may be able to "
                "claim that resource and serve content on your subdomain.",
                f"Delete the CNAME record for {s['name']}, or re-create the resource it points to.",
                evidence=f"CNAME → {s['cname']} (NXDOMAIN)", id=f"subdomains.takeover.{s['name']}"))
    return findings, facts


EXPOSED_PATHS = [
    ("/.git/config", "critical", "Git repository is publicly downloadable",
     lambda b: b"[core]" in b, "Your source code (and possibly secrets in its history) can be downloaded.",
     "Block access to `/.git` in your web server and move the repo outside the web root."),
    ("/.env", "critical", "Environment file (.env) is publicly accessible",
     lambda b: re.search(rb"^[A-Z][A-Z0-9_]{2,}=", b, re.M) is not None and b"<html" not in b.lower(),
     "`.env` files usually contain database passwords and API keys.",
     "Delete it from the web root or block it, then rotate every secret it contained."),
    ("/.aws/credentials", "critical", "AWS credentials file exposed",
     lambda b: b"aws_access_key_id" in b.lower(), "Anyone can take over your AWS account.",
     "Remove the file and immediately rotate the keys in the AWS console."),
    ("/backup.sql", "critical", "Database dump publicly accessible",
     lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b, "Your database contents can be downloaded.",
     "Remove the file from the web server and treat the data as leaked."),
    ("/backup.zip", "high", "Backup archive publicly accessible",
     lambda b: b.startswith(b"PK\x03\x04"), "A downloadable backup archive was found.",
     "Remove backups from the web root."),
    ("/server-status", "medium", "Apache server-status page exposed",
     lambda b: b"Apache Server Status" in b, "Reveals internal URLs, client IPs and server details.",
     "Restrict `/server-status` to localhost in your Apache config."),
    ("/phpinfo.php", "medium", "phpinfo() page exposed",
     lambda b: b"phpinfo()" in b or b"PHP Version" in b, "Reveals detailed server configuration.",
     "Delete phpinfo.php from the server."),
    ("/.DS_Store", "low", ".DS_Store file exposed",
     lambda b: b[4:8] == b"Bud1", "Reveals the names of files and folders on your server.",
     "Delete .DS_Store files and block them in your server config."),
]


async def check_exposed_files(domain, ips=None, transport=None):
    findings = []
    ips = await _blocking(resolve_public, domain) if ips is None else ips
    async with _client(8, transport) as c:
        async def probe(item):
            path, sev, title, matcher, detail, fix = item
            try:
                r = await _pinned_send(c, f"https://{domain}{path}", ips)
                try:
                    if r.status_code != 200:
                        return None
                    body = bytearray()
                    async for chunk in r.aiter_raw():  # raw: never decompress hostile data
                        body += chunk
                        if len(body) >= PROBE_MAX_BYTES:
                            break
                finally:
                    await r.aclose()
                if matcher(bytes(body[:PROBE_MAX_BYTES])):
                    return finding("exposure", sev, title, detail, fix, evidence=f"https://{domain}{path}",
                                   id=f"exposure.{path.lstrip('/')}")
            except httpx.HTTPError:
                return None
        for f in await asyncio.gather(*(probe(i) for i in EXPOSED_PATHS)):
            if f:
                findings.append(f)
    return findings, {"paths_checked": len(EXPOSED_PATHS)}


RISKY_PORTS = {
    21: ("FTP", "medium"), 23: ("Telnet", "high"), 445: ("SMB file sharing", "critical"),
    3389: ("Remote Desktop (RDP)", "high"), 5900: ("VNC remote desktop", "high"),
    3306: ("MySQL database", "high"), 5432: ("PostgreSQL database", "high"),
    1433: ("Microsoft SQL Server", "high"), 6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "critical"), 27017: ("MongoDB", "critical"), 11211: ("Memcached", "high"),
}


async def check_ports(ip):
    async def is_open(port):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
            w.close()
            return True
        except (OSError, asyncio.TimeoutError):
            return False
    ports = list(RISKY_PORTS)
    states = await asyncio.gather(*(is_open(p) for p in ports))
    open_ports = [p for p, s in zip(ports, states) if s]
    findings = []
    for p in open_ports:
        svc, sev = RISKY_PORTS[p]
        findings.append(finding("ports", sev, f"{svc} is exposed to the internet (port {p})",
                                f"Port {p} ({svc}) on {ip} accepts connections from anywhere. These services are "
                                "constantly targeted by automated attacks and ransomware groups.",
                                f"Close port {p} in your firewall / cloud security group, or restrict it to your "
                                "office IP or VPN only.", evidence=f"{ip}:{p} open", id=f"ports.open.{p}"))
    return findings, {"ip": ip, "open": open_ports, "checked": ports}


# ---------------------------------------------------------------- orchestration

async def run_scan(raw_domain, verified=False):
    domain = normalize_domain(raw_domain)
    started = time.time()
    findings, facts = [], {}

    dns_f, facts["dns"] = await _blocking(check_dns, domain)
    findings += dns_f
    ips = facts["dns"]["ips"]  # validated once; every connection below is pinned to these
    has_web = bool(ips)

    async def safe(name, coro):
        try:
            f, fx = await coro
        except Exception as e:  # one failing check must not kill the scan
            f, fx = [], {"error": f"{type(e).__name__}: {e}"}
        findings.extend(f)
        facts[name] = fx

    await asyncio.gather(
        safe("email", check_email_async(domain, bool(facts["dns"]["mx"]))),
        safe("tls", _blocking(check_tls, domain, ips) if has_web else _empty()),
        safe("subdomains", check_subdomains(domain)),
    )
    https_ok = has_web and not facts.get("tls", {}).get("error")
    tasks = [safe("http", check_http(domain, https_ok, ips) if has_web else _empty())]
    if verified and has_web:
        if https_ok:
            tasks.append(safe("exposure", check_exposed_files(domain, ips)))
        tasks.append(safe("ports", check_ports(ips[0])))
    await asyncio.gather(*tasks)

    if not verified:
        findings.append(finding("account", "info", "Deep checks skipped (domain not verified)",
                                "Exposed-file and open-port checks only run on domains you've proven you own.",
                                "Verify ownership by adding the DNS TXT record shown on your domain page.",
                                id="account.not_verified"))
    # Categories that couldn't complete (timeouts etc.). TLS errors are findings, not failures.
    incomplete = sorted(k for k in ("email", "http", "subdomains", "exposure", "ports")
                        if isinstance(facts.get(k), dict) and facts[k].get("error"))
    score, grade = score_findings(findings)
    return {"domain": domain, "verified": verified, "score": score, "grade": grade,
            "findings": sort_findings(findings), "facts": facts, "incomplete": incomplete,
            "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds"),
            "duration_s": round(time.time() - started, 1)}


async def _empty():
    return [], {}


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["check"], f["title"]))

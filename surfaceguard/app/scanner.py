"""Attack-surface checks.

Passive checks (DNS, email security, TLS, HTTP headers, public subdomains) run for
any domain. Active probing (exposed files, risky open ports) only runs for domains
whose ownership the user has verified via a DNS TXT record.
"""
import asyncio
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from .scoring import score_findings

USER_AGENT = "SurfaceGuard-Scanner/0.1 (+attack surface monitoring)"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DNS_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
              dns.exception.Timeout, dns.resolver.YXDOMAIN)


class ScanError(Exception):
    pass


def finding(check, severity, title, detail, fix, evidence=None):
    return {"check": check, "severity": severity, "title": title,
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


def _is_public_ip(ip):
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_loopback or a.is_reserved or a.is_link_local
                or a.is_multicast or a.is_unspecified)


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
    if not ips:
        findings.append(finding("dns", "medium", "Domain has no website address (A/AAAA record)",
                                f"{domain} has no A or AAAA record, so web checks were skipped.",
                                "If you expect a website here, add an A record pointing to your web server."))
    if not facts["caa"]:
        findings.append(finding("dns", "low", "No CAA record",
                                "Any certificate authority is allowed to issue SSL certificates for your domain.",
                                'Add a CAA record listing the CA you use, e.g. `0 issue "letsencrypt.org"`.'))
    return findings, facts


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail",
                  "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "zoho"]


def check_email(domain, has_mx):
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
            "If this domain never sends email: `v=spf1 -all`."))
    elif len(spf) > 1:
        findings.append(finding("email", "medium", "Multiple SPF records (invalid)",
                                "Having more than one SPF record makes SPF fail completely.",
                                "Merge them into a single `v=spf1 ...` TXT record.", evidence=" | ".join(spf)))
    else:
        rec = spf[0].lower()
        if "+all" in rec:
            findings.append(finding("email", "critical", "SPF allows the entire internet to send as you",
                                    "Your SPF record ends in `+all`, which authorizes every server in the world.",
                                    "Change `+all` to `-all` (or `~all` while testing).", evidence=spf[0]))
        elif "?all" in rec:
            findings.append(finding("email", "medium", "SPF policy is neutral (?all)",
                                    "`?all` gives no protection against spoofed mail.",
                                    "Change `?all` to `-all` (or `~all`).", evidence=spf[0]))
        elif not re.search(r"[-~]all", rec) and "redirect=" not in rec:
            findings.append(finding("email", "medium", "SPF record has no 'all' rule",
                                    "Without a final `-all`/`~all`, unlisted servers aren't rejected.",
                                    "End your SPF record with `-all`.", evidence=spf[0]))

    dmarc = [t for t in dns_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    facts["dmarc"] = dmarc[0] if dmarc else None
    if not dmarc:
        findings.append(finding(
            "email", "high", "No DMARC policy",
            "DMARC tells mail providers what to do with emails that fail SPF/DKIM. Without it, spoofed "
            "emails from your domain are usually delivered.",
            f"Add a TXT record at `_dmarc.{domain}`: `v=DMARC1; p=none; rua=mailto:dmarc@{domain}` to start "
            "monitoring, then move to `p=quarantine` and finally `p=reject`."))
    else:
        tags = dict(kv.strip().split("=", 1) for kv in dmarc[0].split(";") if "=" in kv)
        tags = {k.strip().lower(): v.strip().lower() for k, v in tags.items()}
        if tags.get("p") == "none":
            findings.append(finding("email", "medium", "DMARC is in monitor-only mode (p=none)",
                                    "Spoofed emails are still delivered; DMARC is only reporting.",
                                    "Once your reports look clean, change to `p=quarantine`, then `p=reject`.",
                                    evidence=dmarc[0]))
        if "rua" not in tags:
            findings.append(finding("email", "low", "DMARC reports are not collected",
                                    "Without `rua=`, you never see who is sending email as your domain.",
                                    f"Add `rua=mailto:dmarc@{domain}` to your DMARC record.", evidence=dmarc[0]))

    if has_mx:
        found = [s for s in DKIM_SELECTORS if any("p=" in t for t in dns_txt(f"{s}._domainkey.{domain}"))]
        facts["dkim_selectors"] = found
        if not found:
            findings.append(finding(
                "email", "low", "No DKIM key found on common selectors",
                "DKIM cryptographically signs your outgoing email. We checked common selector names and "
                "found none (you may use a custom selector).",
                "Enable DKIM signing in your email provider's admin console and publish the DNS record it gives you."))
    return findings, facts


def _tls_connect(host, legacy=False):
    if legacy:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.minimum_version, ctx.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    else:
        ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(), ss.version()


def check_tls(domain):
    findings, facts = [], {}
    try:
        cert, version = _tls_connect(domain)
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        facts["error"] = msg
        findings.append(finding("tls", "critical", "Invalid SSL certificate",
                                f"Browsers will show a security warning for https://{domain}: {msg}.",
                                "Install a valid certificate for this exact hostname (free via Let's Encrypt, "
                                "or enable it in your hosting panel)."))
        return findings, facts
    except (OSError, ssl.SSLError) as e:
        facts["error"] = str(e)
        findings.append(finding("tls", "high", "HTTPS is not available",
                                f"Could not establish an HTTPS connection to {domain} on port 443.",
                                "Enable HTTPS on your web server/hosting. Let's Encrypt certificates are free."))
        return findings, facts

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    facts.update(protocol=version, expires=expires.date().isoformat(), days_left=days,
                 issuer=issuer.get("organizationName") or issuer.get("commonName"))
    if days <= 7:
        findings.append(finding("tls", "high", f"SSL certificate expires in {days} days",
                                f"Your certificate expires on {expires.date()}. After that visitors see a full-page warning.",
                                "Renew the certificate now and enable automatic renewal."))
    elif days <= 21:
        findings.append(finding("tls", "medium", f"SSL certificate expires in {days} days",
                                f"Your certificate expires on {expires.date()}.",
                                "Renew soon, and check that automatic renewal is working."))
    try:
        _, legacy_version = _tls_connect(domain, legacy=True)
        findings.append(finding("tls", "medium", f"Outdated encryption protocol accepted ({legacy_version})",
                                "TLS 1.0/1.1 are deprecated and have known weaknesses. PCI-DSS forbids them.",
                                "Disable TLS 1.0 and 1.1 in your web server / CDN settings; allow only TLS 1.2+."))
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


async def check_http(domain, https_ok):
    findings, facts = [], {}
    async with httpx.AsyncClient(timeout=10, verify=False, headers={"User-Agent": USER_AGENT}) as c:
        try:
            r = await c.get(f"http://{domain}/", follow_redirects=False)
            loc = r.headers.get("location", "")
            facts["http_redirects_to_https"] = r.is_redirect and loc.startswith("https://")
            if https_ok and not facts["http_redirects_to_https"]:
                findings.append(finding("http", "medium", "HTTP does not redirect to HTTPS",
                                        f"http://{domain} serves content without forcing encryption.",
                                        "Configure a permanent (301) redirect from HTTP to HTTPS."))
        except httpx.HTTPError:
            pass
        if not https_ok:
            return findings, facts
        r = None
        for attempt_timeout in (10, 20):  # slow sites get one retry with a longer timeout
            try:
                r = await c.get(f"https://{domain}/", follow_redirects=True, timeout=attempt_timeout)
                break
            except httpx.HTTPError as e:
                facts["error"] = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        if r is None:
            return findings, facts
        facts.pop("error", None)

    h = r.headers
    facts.update(status=r.status_code, final_url=str(r.url), server=h.get("server"))
    csp = h.get("content-security-policy", "")
    for name, sev, title, detail, fix in SECURITY_HEADERS:
        if name not in h:
            findings.append(finding("http", sev, title, detail, fix))
    hsts = h.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            findings.append(finding("http", "low", "HSTS max-age is short",
                                    "HSTS protection expires quickly (less than 6 months).",
                                    "Use `max-age=31536000` (1 year).", evidence=hsts))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        findings.append(finding("http", "low", "Clickjacking protection missing",
                                "Your site can be embedded in an invisible frame on a malicious page.",
                                "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'self'`."))
    server = h.get("server", "")
    if re.search(r"\d", server):
        findings.append(finding("http", "low", "Server software version is disclosed",
                                "Revealing exact versions helps attackers find matching exploits.",
                                "Hide the version (nginx: `server_tokens off;`, Apache: `ServerTokens Prod`).",
                                evidence=f"Server: {server}"))
    if "x-powered-by" in h:
        findings.append(finding("http", "low", "Technology stack disclosed (X-Powered-By)",
                                "The X-Powered-By header reveals your framework and often its version.",
                                "Remove the X-Powered-By header in your app/server config.",
                                evidence=f"X-Powered-By: {h['x-powered-by']}"))
    weak = []
    for cookie in h.get_list("set-cookie"):
        low = cookie.lower()
        if "secure" not in low or "httponly" not in low:
            weak.append(cookie.split("=", 1)[0])
    if weak:
        findings.append(finding("http", "low", "Cookies without Secure/HttpOnly flags",
                                "Session cookies without these flags can be stolen via XSS or unencrypted connections.",
                                "Set `Secure; HttpOnly; SameSite=Lax` on all session cookies.",
                                evidence=", ".join(sorted(set(weak)))))
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


async def check_subdomains(domain):
    findings, facts = [], {"subdomains": [], "source": "certificate transparency logs (crt.sh)"}
    try:
        async with httpx.AsyncClient(timeout=25, headers={"User-Agent": USER_AGENT}) as c:
            r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            entries = r.json()
    except Exception:
        facts["error"] = "Certificate transparency lookup timed out; will retry next scan."
        return findings, facts
    names = set()
    for e in entries:
        for n in str(e.get("name_value", "")).lower().split("\n"):
            n = n.strip().lstrip("*.")
            if n.endswith("." + domain) and DOMAIN_RE.match(n):
                names.add(n)
    names = sorted(names)[:60]
    results = await asyncio.gather(*(asyncio.to_thread(_probe_subdomain, n) for n in names))
    facts["subdomains"] = results
    if results:
        live = sum(1 for s in results if s["live"])
        findings.append(finding("subdomains", "info", f"{len(results)} subdomains found in public records",
                                f"{live} of them currently resolve. Every live subdomain is part of your attack surface.",
                                "Review the list and remove DNS records for anything you no longer use."))
    for s in results:
        if s.get("dangling"):
            findings.append(finding(
                "subdomains", "high", f"Possible subdomain takeover: {s['name']}",
                f"{s['name']} points to {s['cname']}, which no longer exists. An attacker may be able to "
                "claim that resource and serve content on your subdomain.",
                f"Delete the CNAME record for {s['name']}, or re-create the resource it points to.",
                evidence=f"CNAME → {s['cname']} (NXDOMAIN)"))
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


async def check_exposed_files(domain):
    findings = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT}) as c:
        async def probe(item):
            path, sev, title, matcher, detail, fix = item
            try:
                async with c.stream("GET", f"https://{domain}{path}") as r:
                    if r.status_code != 200:
                        return None
                    body = b""
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) > 4096:
                            break
                    if matcher(body):
                        return finding("exposure", sev, title, detail, fix, evidence=f"https://{domain}{path}")
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
                                "office IP or VPN only.", evidence=f"{ip}:{p} open"))
    return findings, {"ip": ip, "open": open_ports, "checked": ports}


# ---------------------------------------------------------------- orchestration

async def run_scan(raw_domain, verified=False):
    domain = normalize_domain(raw_domain)
    started = time.time()
    findings, facts = [], {}

    dns_f, facts["dns"] = await asyncio.to_thread(check_dns, domain)
    findings += dns_f
    has_web = bool(facts["dns"]["a"] or facts["dns"]["aaaa"])

    async def safe(name, coro):
        try:
            f, fx = await coro
        except Exception as e:  # one failing check must not kill the scan
            f, fx = [], {"error": f"{type(e).__name__}: {e}"}
        findings.extend(f)
        facts[name] = fx

    await asyncio.gather(
        safe("email", asyncio.to_thread(check_email, domain, bool(facts["dns"]["mx"]))),
        safe("tls", asyncio.to_thread(check_tls, domain) if has_web else _empty()),
        safe("subdomains", check_subdomains(domain)),
    )
    https_ok = has_web and not facts.get("tls", {}).get("error")
    tasks = [safe("http", check_http(domain, https_ok) if has_web else _empty())]
    if verified and has_web:
        if https_ok:
            tasks.append(safe("exposure", check_exposed_files(domain)))
        ip = (facts["dns"]["a"] or facts["dns"]["aaaa"])[0]
        tasks.append(safe("ports", check_ports(ip)))
    await asyncio.gather(*tasks)

    if not verified:
        findings.append(finding("account", "info", "Deep checks skipped (domain not verified)",
                                "Exposed-file and open-port checks only run on domains you've proven you own.",
                                "Verify ownership by adding the DNS TXT record shown on your domain page."))
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

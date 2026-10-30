# SurfaceGuard

Attack-surface monitoring for small businesses and MSPs. Enter a domain and SurfaceGuard checks it the way an
attacker would, scores it A–F, explains each issue in plain English with a concrete fix, rescans automatically
and emails you when something new appears.

## What it checks

| Category | Checks | Runs on |
|---|---|---|
| DNS | A/AAAA, MX, NS, CAA | all domains |
| Email | SPF (missing, `+all`, `?all`, duplicates), DMARC (missing, `p=none`, no reports), DKIM (common selectors) | all domains |
| TLS | invalid/expired cert, expiry countdown, TLS 1.0/1.1 accepted | all domains |
| HTTP | HTTPS redirect, HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, version disclosure, cookie flags | all domains |
| Subdomains | discovery via certificate-transparency logs, dangling-CNAME takeover detection | all domains |
| Exposed files | `.git`, `.env`, AWS credentials, SQL dumps, backups, `server-status`, `phpinfo` | **verified domains only** |
| Open ports | RDP, SMB, Telnet, FTP, VNC, MySQL, Postgres, MSSQL, Redis, Elasticsearch, MongoDB, Memcached | **verified domains only** |

Active probing only runs after the owner proves control with a DNS TXT record. The record is checked again before
each verified scan; if it is gone, verification is cleared and only passive checks run. If that DNS lookup itself
fails (timeout or server failure), verification is kept and the scan runs as before. If a check times out, the
previous scan's results for that category are carried forward and flagged, so a flaky server never makes a domain
look safer than it is. Carried data expires after 7 days; after that the category shows as incomplete.

### Scanner safety

- **SSRF protection.** A domain is resolved once and every address must be public (`is_global` and not
  multicast; IPv4-mapped, 6to4, Teredo and NAT64 addresses are unwrapped and checked too). Domains that resolve
  to private, loopback, link-local or CGNAT addresses are refused.
- **IP pinning.** TLS, HTTP and port checks connect to the validated IPs and send the domain as `Host` and TLS
  SNI, so the DNS answer cannot change between the check and the connection (DNS rebinding).
- **Redirects are followed by hand**, at most 5 hops. Each hop must be `http`/`https` on port 80 or 443, and the
  new host is resolved and validated the same way. A rejected hop is not followed: the last response is used and
  the reason is stored in `facts.http.redirect_not_followed`.
- **Body size caps.** The HTTP check reads headers only. Exposed-file probes read at most 4 KB. The crt.sh
  response is capped at 5 MB; for very large logs the names found so far are used and the subdomain result is
  marked `truncated`.

### Limits

| Limit | Value |
|---|---|
| User-started scans (add domain, rescan, verify) per rolling hour | Free 5, Pro 30, MSP 150 (`scans_per_hour` in `app/db.py`). Scheduled rescans don't count, and deleting a domain does not reset the budget |
| Rescan cooldown | 120 seconds per domain |
| Anonymous free checks | 5 per hour per IP, and at most `MAX_CONCURRENT_CHECKS` running at once. A "busy, try again" answer does not use up a free check |
| Failed logins | Per 15 minutes: 10 per IP and email address together, 30 per IP (any email) and 100 per email address (any IP). Only failed attempts count. Someone guessing a password from their own network cannot lock the real user out from another network |
| Sign-ups | 5 new accounts per hour per IP |

## Run locally

From this `surfaceguard` folder:

```bash
python -m venv .venv
```

```bash
.venv\Scripts\pip install -r requirements.txt
```

```bash
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Open http://localhost:8000. The tests run offline (no network); run each file as a script:

```bash
.venv\Scripts\python tests\test_app.py
.venv\Scripts\python tests\test_billing.py
.venv\Scripts\python tests\test_fixes.py
.venv\Scripts\python tests\test_scanner_security.py
.venv\Scripts\python tests\test_integration.py
```

Without Stripe keys, billing is **disabled** (paid plans cannot be bought). For local development you can turn on
**demo billing mode** (free plan switching) with `DEMO_BILLING=1`, for example in PowerShell:

```powershell
$env:DEMO_BILLING = "1"; .venv\Scripts\python -m uvicorn app.main:app --port 8000
```

`DEMO_BILLING` is ignored when `ENVIRONMENT=production`, so demo mode is never on in production.
To deploy with real payments, follow **[DEPLOY.md](DEPLOY.md)** (Stripe + Fly.io, Frankfurt). Recent changes are
listed in **[CHANGELOG.md](CHANGELOG.md)**.

## Configuration (environment variables)

See `.env.example` for the full list. Production (`ENVIRONMENT=production`) refuses to start without
`SESSION_SECRET`, an `https://` `BASE_URL`, and all four Stripe settings. Without `SMTP_HOST` it still starts but
prints a warning, because alert emails are then suppressed.


| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Cookie signing key (otherwise generated into `.secret_key`) |
| `HTTPS_ONLY=1` | Mark session cookies Secure (set in production) |
| `SURFACEGUARD_DB` | SQLite file path (default `surfaceguard.db`) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Alert emails. Without `SMTP_HOST`, development logs the alert to the console; production logs only "alert suppressed for user id N" |
| `SMTP_PORT` | `587` (default) uses STARTTLS; `465` uses implicit TLS (`SMTP_SSL`). The server certificate and hostname are verified in both cases |
| `MAX_CONCURRENT_SCANS` | Parallel scan limit (default 4) |
| `MAX_CONCURRENT_CHECKS` | Anonymous free checks running at once (default 2) |
| `DEMO_BILLING=1` | Local development only: free plan switching without Stripe keys. Ignored in production |
| `DISABLE_SCHEDULER=1` | Turn off automatic rescans |

## Project layout

```
app/scanner.py   all security checks + orchestration
app/scoring.py   score, grade, finding diff for alerts
app/jobs.py      background scans, scheduler, carry-forward, email alerts
app/db.py        SQLite schema + queries, plan limits (PLANS)
app/auth.py      PBKDF2 passwords, CSRF tokens
app/main.py      FastAPI routes
app/templates/   Jinja pages (landing, free check, dashboard, domain, report, pricing)
tests/           offline test suite
```

## Roadmap to launch

1. ~~Payments~~ — done: Stripe Checkout, customer portal, signed webhooks.
2. ~~Deploy~~ — done: Dockerfile + Fly.io config (see DEPLOY.md). Later: Postgres + separate scan worker.
3. **Legal pages** — Impressum, Terms, Privacy Policy (required before taking real payments in the EU).
4. **Breach monitoring** — leaked employee credentials via Have I Been Pwned's domain search API.
5. **MSP features** — client workspaces, white-label PDF reports with the MSP's logo, team members.
6. **More checks** — DNSSEC, WordPress/plugin versions, known-CVE matching on server banners, blacklist (RBL) status.
7. Password reset, email verification, 2FA.

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

Active probing only runs after the owner proves control with a DNS TXT record. Domains that resolve to
private/internal IPs are refused (SSRF protection). If a check times out, the previous scan's results for that
category are carried forward and flagged, so a flaky server never makes a domain look safer than it is.

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

Open http://localhost:8000. Run the tests (offline, no network) with `.venv\Scripts\python tests\test_app.py`.

Without Stripe keys the app runs in **demo billing mode** (free plan switching), which is disabled in production.
To deploy with real payments, follow **[DEPLOY.md](DEPLOY.md)** (Stripe + Fly.io, Frankfurt).

## Configuration (environment variables)

See `.env.example` for the full list. Production (`ENVIRONMENT=production`) refuses to start without
`SESSION_SECRET`, an `https://` `BASE_URL`, and all four Stripe settings.


| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Cookie signing key (otherwise generated into `.secret_key`) |
| `HTTPS_ONLY=1` | Mark session cookies Secure (set in production) |
| `SURFACEGUARD_DB` | SQLite file path (default `surfaceguard.db`) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Alert emails. Without `SMTP_HOST`, alerts are logged to the console |
| `MAX_CONCURRENT_SCANS` | Parallel scan limit (default 4) |
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

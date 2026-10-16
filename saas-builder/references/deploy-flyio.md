# Phases 6–7 — Production hardening, Fly.io deploy, guided walkthrough

## Contents
1. Production hardening checklist
2. Deploy files
3. Why Fly.io (and alternatives)
4. The guided walkthrough (talk the user through it)
5. Troubleshooting

## 1. Production hardening checklist

- **Security headers middleware** on every response: CSP
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
  frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://checkout.stripe.com https://billing.stripe.com`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy`, and HSTS when `BASE_URL` is https.
- Strict CSP means **no inline scripts or `on*=` handlers**; move them to `static/app.js` (`assets/app.js`).
  Grep templates for `onclick|onsubmit|<script|style="` before shipping.
- **Versioned static URLs**: hash the static folder at startup, expose `asset_version` to templates, link
  `/static/app.js?v={{ asset_version }}`. Otherwise users run stale JS after deploys.
- Disable FastAPI docs in production (`docs_url=None, redoc_url=None, openapi_url=None`).
- `config.check_production()` at import: refuse to boot if `SESSION_SECRET`, an `https://` `BASE_URL` or Stripe
  settings are missing; warn on `sk_test_` in production.
- Session cookie `https_only` when `BASE_URL` is https.
- Real client IP from a configurable header (`CLIENT_IP_HEADER=Fly-Client-IP`) for rate limiting.
- Quiet noisy loggers (`httpx` → WARNING) so logs stay readable.
- `uvicorn --workers 1 --no-server-header`; one machine only while the scheduler is in-process and the DB is SQLite.

## 2. Deploy files (copy from assets/ and rename the app)

- `assets/Dockerfile` — `python:3.13-slim`, installs requirements, copies `app/`, strips CRLF from the entrypoint,
  creates `appuser` (uid 10001), healthcheck on `/healthz`.
- `assets/docker-entrypoint.sh` — as root: `chown` the data dir, then `exec setpriv --reuid=10001 ...` the command.
- `assets/fly.toml` — region `fra` by default (EU), `[env]` for non-secret settings, `auto_stop_machines = "off"`
  and `min_machines_running = 1` (the scheduler must keep running), a `[[mounts]]` volume at `/data`, health check.
- `assets/env.example` → save as `.env.example` — every setting with a comment; secrets go in `fly secrets`.
- `.dockerignore`: `.venv`, `__pycache__`, `*.db`, `.secret_key`, `.env`, `tests`, dev credential files.
- `DEPLOY.md` in the project: the walkthrough below, written for the user, with each command in its own block.

Pick the app name: `<product>-<short-suffix>`, must be globally unique on Fly. Set `BASE_URL` to
`https://<app>.fly.dev` to match.

## 3. Why Fly.io (and alternatives)

Fly.io is the default: deploys from a folder with `fly deploy` (remote builder — no local Docker or git needed),
persistent volumes with daily snapshots, EU regions, ~€5/month for one small machine. If the user prefers:
- **Railway**: similar, deploy with its npm CLI; add a volume for `/data`.
- **Hetzner VPS** (~€4.50): cheapest; Docker + docker-compose with Caddy for automatic HTTPS; more manual.
- Avoid hosts without persistent disks for SQLite (data would be lost on redeploy).

## 4. The guided walkthrough

The user does the account work; you guide, check and debug. Give one or two steps per message, wait for them to
report back, and read their terminal output when you have access. Open a terminal tab in the project folder for
them if you can. Remind them once, clearly: secret keys (`sk_...`, `whsec_...`) are typed only into their
terminal, never into chat. Price IDs and app names are fine to share.

**Step 0 — permanent folder.** If the project is in a temporary or session-scoped folder, move it to a
permanent one first (e.g. `Documents\<Product>`). They need this code for every future update.

**Step 1 — Stripe test mode** (browser). Test mode on. Product catalog → add one product per paid plan,
recurring monthly price in EUR → copy each Price ID. Settings → Billing → Customer portal: allow updating payment
methods, switching between the products, cancelling at period end → save. Note where the secret key is
(Developers → API keys) but don't copy it yet.

**Step 2 — Fly CLI** (terminal). They run the official installer themselves:
`iwr https://fly.io/install.ps1 -useb | iex` (Windows) / `curl -L https://fly.io/install.sh | sh` (macOS/Linux).
Then open a **new** terminal (so PATH updates) and `fly auth login` (or `fly auth signup`). Fly requires a card.

**Step 3 — create the app and volume** (in the project folder):
`fly launch --copy-config --no-deploy` (accept the existing config; say no to databases/Redis it offers), then
`fly volumes create <product>_data --region fra --size 1`. If the name is taken, change `app` and `BASE_URL` in
`fly.toml` and retry.

**Step 4 — Stripe webhook** (browser). Developers → Webhooks → Add endpoint →
`https://<app>.fly.dev/stripe/webhook`, select the five events from stripe.md → reveal the signing secret.

**Step 5 — secrets and deploy.** Generate a session secret:
`python -c "import secrets; print(secrets.token_hex(32))"`. Then one command they fill in themselves:
`fly secrets set SESSION_SECRET=... STRIPE_SECRET_KEY=sk_test_... STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_PRICE_PRO=price_... STRIPE_PRICE_MSP=price_...`
then `fly deploy`. Watch with `fly logs`.

**Step 6 — test with real Stripe (test mode).** Open the site: free tool → sign up → Upgrade → card
`4242 4242 4242 4242`, any future date, any CVC → back on dashboard with the paid plan. In Stripe → Webhooks the
deliveries should show 200. Test "manage billing" → cancel → plan returns to Free after the period (or immediately
if configured).

**Step 7 — optional email.** SMTP provider (Brevo, Postmark, Resend, Mailgun) → `fly secrets set SMTP_HOST=...
SMTP_USER=... SMTP_PASSWORD=... SMTP_FROM=...`.

Then go to `references/go-live.md`.

## 5. Troubleshooting

| What they see | Likely cause | Fix |
|---|---|---|
| `fly` is not recognized | Terminal opened before install | Open a new terminal tab; on Windows check `%USERPROFILE%\.fly\bin` is on PATH |
| `fly launch` says name taken | App names are global | New name in `fly.toml` (`app` and `BASE_URL`) |
| Deploy succeeds, app crash-loops; logs say `Missing required production settings` | Secrets not set or typo | `fly secrets list`, set the missing ones |
| `BASE_URL must start with https://` | Wrong env value | Fix `[env]` in `fly.toml`, `fly deploy` |
| `exec format error` / entrypoint not found | CRLF line endings | Dockerfile must `sed -i 's/\r$//'` the script |
| `sqlite3.OperationalError: unable to open database file` | Volume missing or not writable | `fly volumes list`; mount `destination = "/data"`, `DATA_DIR=/data`; entrypoint chown |
| Health check failing | Wrong port | `internal_port` = `PORT` = 8080 |
| Stripe webhook deliveries 400 | Wrong `whsec_` (each endpoint and mode has its own) | Copy the signing secret of *this* endpoint, `fly secrets set STRIPE_WEBHOOK_SECRET=...` |
| Webhook 404 | `STRIPE_WEBHOOK_SECRET` unset (route disabled) or wrong URL path | Set secret; URL must end in `/stripe/webhook` |
| Paid but plan didn't change | Price ID mismatch (test vs live, or wrong env var) | Compare `STRIPE_PRICE_*` with the Price IDs in the same Stripe mode |
| Checkout button gives "couldn't start checkout" | Bad secret key or portal/price not in this mode | `fly logs` shows Stripe's error message |
| Login drops after deploy | `SESSION_SECRET` changed | Set it once and keep it |
| Free check rate-limits everyone together | Real-IP header not configured | `CLIENT_IP_HEADER=Fly-Client-IP` in `[env]` |

---
name: saas-builder
description: End-to-end workflow for turning "I want to build a SaaS" into a working, paid, deployed product — brainstorming in-demand ideas, picking one, building the MVP (Python/FastAPI + SQLite, accounts, dashboard, background jobs, tests), adding Stripe subscriptions, hardening for production, and walking the user step by step through deploying to Fly.io and going live. Use this skill whenever someone wants SaaS or startup product ideas, wants to build/launch a micro-SaaS or MVP, asks to add Stripe subscriptions/billing/pricing plans to a web app, or wants to deploy a small web app with payments to production — even if they only mention one phase (e.g. "give me SaaS ideas", "add payments to my app", "help me get this online").
---

# SaaS Builder

Take a user from "I want to build a SaaS" to a product that real customers can pay for. The workflow has
seven phases. Users often enter in the middle ("add Stripe to my app", "help me deploy"), so first figure out
which phase they're in, then start there.

| Phase | Output | Reference |
|---|---|---|
| 1. Ideas | 6–10 scored ideas, user picks one | `references/ideation.md` |
| 2. MVP plan | Feature list, stack, plans/pricing | `references/stack-blueprint.md` |
| 3. Build | Working app + offline test suite | `references/stack-blueprint.md` |
| 4. Verify | App run in a browser, real flows clicked | (this file) |
| 5. Payments | Stripe Checkout, portal, signed webhooks, plan limits | `references/stripe.md` |
| 6. Production | Security headers, config guard, Docker, Fly.io | `references/deploy-flyio.md` |
| 7. Go live | Guided deploy walkthrough, live keys, legal | `references/deploy-flyio.md`, `references/go-live.md` |

Read only the reference you need for the current phase. `assets/` holds proven, tested files to copy and adapt
(billing, config, auth, Dockerfile, entrypoint, fly.toml, front-end JS) — adapting a working file is faster and
safer than rewriting it.

Many users of this skill are not professional developers. Explain what you're doing in plain words, keep jargon
light (or define it in a few words), and prefer one clear recommendation over a menu of options.

## Phase 1 — Ideas

Read `references/ideation.md`. Give 6–10 ideas, each with problem, product, who pays, price, why now, and the
user's edge, followed by a comparison table and **one** recommendation with a reason. Look at what you know about
the user (their job, skills, country) — an idea that uses their unfair advantage (domain expertise, language,
local regulation) beats a generic one. Stop and let them choose; don't start building an idea they didn't pick.

## Phase 2 — MVP plan

Decide the smallest version that someone would pay for. Every MVP should have:
- a **free, no-signup tool on the landing page** that delivers real value in seconds (lead generation — this is
  how the product gets its first users), with a call-to-action to sign up;
- accounts, a dashboard, and the core feature;
- **plans** (Free / Pro / higher tier) with limits enforced in code from day one;
- whatever recurring value justifies a subscription (monitoring, scheduled jobs, alerts, reports).

Default stack (single language, runs anywhere, cheap to host): Python + FastAPI + Jinja templates + SQLite +
in-process background scheduler + plain CSS/JS. Details and patterns are in `references/stack-blueprint.md`.
Pick a working name and say it can be changed later.

## Phase 3 — Build

Follow the blueprint. A few things matter more than they look:

- **Safety and abuse.** If the product touches third-party systems (scanning, scraping, sending), make it safe to
  offer publicly: verify ownership before anything active, refuse private/internal IPs (SSRF), rate-limit free
  tools, add cooldowns on expensive actions.
- **Honest results.** If a check, job or integration fails or times out, it must never make the result look
  *better*. Carry forward the last known result and label it, rather than silently dropping data.
- **Tests that run offline.** Mock the network/external services so the suite runs in seconds with no keys.
  Cover the full user flow (register → core action → limits → another user can't see your data).

## Phase 4 — Verify in a real browser

Start the app (preview/dev server) and actually click through the main flows: landing tool, sign-up, core
feature, dashboard, pricing. Read the server logs while doing it. In the SurfaceGuard build this step found a
crash that the code review missed (see Pitfalls). Use test accounts on localhost only and store their
credentials in a dev file in the project, not in chat.

## Phase 5 — Payments

Read `references/stripe.md` and adapt `assets/billing.py` + `assets/config.py`. Key decisions already made:
Stripe Checkout (hosted) for new subscriptions, Customer Portal for changes/cancellation, signed webhooks as the
source of truth with event de-duplication, immediate sync on the success page, a demo billing mode for local
development (opt-in with `DEMO_BILLING=1`, never available in production), and paused (not deleted) resources when a user downgrades.

## Phase 6 — Production hardening + deploy config

Read `references/deploy-flyio.md`. Add security headers with a strict CSP (move inline JS into a static file),
versioned static asset URLs, a startup guard that refuses to boot in production with missing secrets, Docker
with a non-root user, and a `fly.toml`. If the product is a security product, it should pass its own checks.

## Phase 7 — Guided deploy and go-live

Before the walkthrough, check the project is ready: tests pass, a Dockerfile/`fly.toml`/`.env.example` exist,
production settings are guarded, and — if they want to take payments — Stripe is wired in. Whatever is missing,
do that phase first (5 or 6) and tell the user why in one sentence.

Walk the user through deployment **one step at a time** — they own the accounts, the money and the secrets.
The walkthrough script, troubleshooting table and go-live checklist are in `references/deploy-flyio.md` and
`references/go-live.md`. Ground rules:

- The user creates accounts, enters payment details and types secret keys themselves. Tell them plainly never to
  paste `sk_...` / `whsec_...` values into the chat; they go straight into `fly secrets set` in their terminal.
  Non-secret identifiers (price IDs, app names) are fine to share.
- Give 1–2 steps per message, each with exact clicks or a single copy-paste command, then ask them to report back.
  Read their terminal output yourself when you can, and diagnose errors from it.
- Before deploying, make sure the code lives in a permanent folder (not a temporary/session scratch folder) — they
  will need it for every future update.
- Always test in Stripe **test mode** with card `4242 4242 4242 4242` before switching to live keys.

## Pitfalls we've already hit (avoid them)

These came from building a real product with this workflow. Each cost time once; don't pay for them again.

| Symptom | Cause | Fix |
|---|---|---|
| `RuntimeError: no running event loop` when a button starts a background job | FastAPI runs plain `def` routes in a thread pool; `asyncio.create_task` needs the event loop | Make every route that launches a task `async def`; in the launcher call `asyncio.get_running_loop()` *before* writing a "running" DB row so a failure can't leave a job stuck |
| Score/grade improves when a target server is slow | A timed-out check returned no findings | Retry once with a longer timeout; if still failing, carry forward the previous result for that category and flag it in the UI |
| `pip install stripe` fails on Windows with "No such file or directory" | Windows path-length limit in deep folders | Call Stripe's REST API with `httpx` instead (see `assets/billing.py`) — fewer dependencies anyway |
| Copy/create fails with "Could not find a part of the path" on Windows | Full path over 260 characters | Keep project and test folder names short and shallow; prefer a short permanent folder like `Documents\<Product>` |
| Container exits immediately: `exec format error` / `not found` on entrypoint | Windows CRLF line endings in the shell script | `sed -i 's/\r$//'` the script in the Dockerfile |
| App can't write its database on Fly | Volume mounted owned by root, app runs as non-root | Entrypoint runs as root, `chown`s the data dir, then drops privileges with `setpriv` |
| New JS/CSS doesn't take effect after a change/deploy | Browser cached the old static file | Append a content hash: `/static/app.js?v={{ asset_version }}` |
| Buttons stop working after adding CSP | Inline `onclick`/`<script>` blocked by `script-src 'self'` | Declare behaviour with `data-*` attributes handled in one static JS file (`assets/app.js`) |
| "Copy" button does nothing in some browsers | Clipboard permission denied | Fall back to selecting the text and showing "Press Ctrl+C" |
| Users can't delete an item whose jobs all failed | Delete button rendered only inside the "has results" block | Render destructive/management actions outside conditional result sections |
| Rescans run on stale schedule or double-run | Scheduler in multiple workers | Exactly one process/machine, one worker, while the scheduler lives in-app |
| Users hammer "rescan" | No cooldown | Per-resource cooldown (e.g. 2 minutes) with a friendly message |
| Free-tool rate limit is useless in production | Behind a proxy every request has the proxy's IP | Read the platform's real-client-IP header (`Fly-Client-IP`), configurable via env |

## Finishing each phase

At the end of each phase: run the test suite, say what is done and what is *not* verified (e.g. "Stripe was
tested against a mock, not real Stripe"), update the README/roadmap, and recommend the next phase. When the
first product is live, offer to reuse this workflow for the next idea on their list.

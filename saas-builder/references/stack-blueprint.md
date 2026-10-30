# Phases 2–3 — Stack blueprint and build patterns

## Contents
1. Project layout
2. Setup
3. Data layer (SQLite)
4. Accounts, sessions, CSRF
5. Background jobs and the scheduler
6. Templates and front-end
7. The free landing-page tool
8. Plans and limits
9. Tests
10. Running it locally

## 1. Project layout

```
<product>/
  app/
    main.py        FastAPI routes, middleware, template setup
    config.py      settings from env (copy assets/config.py)
    db.py          SQLite schema, migrations, queries, PLANS dict
    auth.py        password hashing, CSRF (copy assets/auth.py)
    jobs.py        background tasks, scheduler, alerts
    billing.py     Stripe (copy assets/billing.py, phase 5)
    <core>.py      the product's core engine (scanner, extractor, generator...)
    templates/     base.html, _macros.html, landing, auth, dashboard, item page, pricing, report
    static/        style.css, app.js (copy assets/app.js)
  tests/           test_app.py, test_billing.py — offline, mocked
  requirements.txt  README.md  DEPLOY.md  Dockerfile  docker-entrypoint.sh  fly.toml  .env.example  .dockerignore
```

Keep the core engine pure (input → result dict) so it can be called from the free tool, background jobs and tests.

## 2. Setup

```
python -m venv .venv
.venv\Scripts\pip install fastapi "uvicorn[standard]" jinja2 httpx itsdangerous python-multipart
```
(add domain libraries, e.g. `dnspython`). Check the Python version first; pin minimum versions in
`requirements.txt`. No Stripe SDK — billing uses `httpx` (see stripe.md).

## 3. Data layer (SQLite)

- `DB_PATH` from env, defaulting to `DATA_DIR/<product>.db` so production can point at a mounted volume.
- One short-lived connection per call via a context manager (`row_factory = sqlite3.Row`,
  `PRAGMA foreign_keys = ON`, commit on success). Simple and thread-safe for one process.
- Schema as `CREATE TABLE IF NOT EXISTS ...` run in `init()` on startup, plus a `MIGRATIONS` dict of
  `table -> [(column, type)]` applied with `PRAGMA table_info` + `ALTER TABLE ADD COLUMN`. Never require the user
  to delete their database.
- On startup, mark any job rows still `running` as `failed` ("interrupted by restart"), or they stay stuck forever.
- Store rich results as a JSON column alongside a few queryable columns (score, status, timestamps).
- `PLANS` dict lives here: `{"free": {"name", "price", "<unit>_limit", "interval_hours"}, "pro": ..., ...}`.

## 4. Accounts, sessions, CSRF

Copy `assets/auth.py`: PBKDF2-SHA256 (stdlib, 600k iterations, per-user salt, constant-time compare), session
secret from `SESSION_SECRET` or a generated file in `DATA_DIR`, per-session CSRF token checked on every POST.
Starlette `SessionMiddleware` with `same_site="lax"` and `https_only` when `BASE_URL` is https.
- Normalise emails to lowercase; minimum password length 10.
- `request.session.clear()` on login/register (prevents session fixation).
- Every query for a user-owned object filters by `user_id` and returns 404 otherwise. Test this explicitly with a
  second user.

## 5. Background jobs and the scheduler

```python
_tasks = set()
SEM = asyncio.Semaphore(int(os.environ.get("MAX_CONCURRENT_JOBS", "4")))

def launch_job(row):
    loop = asyncio.get_running_loop()      # fail BEFORE writing a 'running' row
    job_id = db.start_job(row["id"])
    task = loop.create_task(_execute(job_id, dict(row)))
    _tasks.add(task); task.add_done_callback(_tasks.discard)   # keep a reference
    return job_id
```
- Any route that calls `launch_job` must be `async def` (plain `def` routes run in a thread with no event loop).
- `_execute` wraps the engine in `asyncio.wait_for(..., timeout=...)`, records failures with a friendly error, and
  never lets one failing sub-check kill the whole job.
- Scheduler: `asyncio.create_task(scheduler_loop())` in the FastAPI lifespan; every few minutes pick items whose
  last run is older than the owner's plan interval, skipping paused items and ones already running. Allow
  `DISABLE_SCHEDULER=1` for tests.
- Change alerts: diff the new result against the previous one; email only *new* problems. Without SMTP settings,
  log the alert instead so development works without email; in production log only "alert suppressed for user id
  N" (no address or findings in logs) and warn at startup. Send through `asyncio.to_thread`, and verify the SMTP
  certificate (`ssl.create_default_context()` for STARTTLS on 587, `SMTP_SSL` on 465).
- Carry forward: if a category of the job failed this run, copy that category's previous results into the new
  result with a `carried: true` flag, recompute the score, and show a notice in the UI.

## 6. Templates and front-end

- Jinja `base.html` with top bar, flash messages, footer; `_macros.html` for repeated UI (badges, finding lists).
- A small `md` filter: escape the text, then turn `` `code` `` into `<code>` — lets engine messages contain
  copy-paste values safely.
- Plain CSS with variables and a `prefers-color-scheme: dark` block; mobile breakpoints; print CSS for reports.
- No inline JS (CSP). Use `assets/app.js`: `data-loading`, `data-confirm`, `data-copy`, `data-print`,
  `data-reload-after`, `data-poll` attributes. Long-running jobs: the page sets `data-poll="/api/.../status"` and
  reloads when the job finishes.
- Destructive or management actions (delete, settings) go outside conditional "has results" blocks.

## 7. The free landing-page tool

The landing page does one thing well: enter one value, get a useful result in seconds, no signup. Run only the
safe/passive part of the engine, show the score and top 5 issues, then a strong CTA ("Monitor this free") that
pre-fills the sign-up with the value they entered. Rate-limit per client IP (in-memory deque is fine for one
instance; use the platform's real-IP header in production) and add a timeout.

## 8. Plans and limits

- Enforce limits on create ("Your Free plan includes 1 domain — upgrade to add more" → pricing page).
- On downgrade, don't delete anything: items beyond the limit become **paused** (oldest stay active), the
  scheduler skips them, manual runs are refused with an upgrade link, and the dashboard explains why.
- Expensive manual actions get a cooldown.

## 9. Tests

Plain functions runnable with `python tests/test_x.py` (and pytest-compatible). At the top: point the DB env var
at a temp file, set `DISABLE_SCHEDULER=1`, call `db.init()` if a test touches the DB before the app starts, and
replace network-touching functions (engine, Stripe) with fakes. Use FastAPI `TestClient` for flows. Minimum:
- input normalisation/validation and SSRF refusal;
- scoring rules and diffs;
- full flow: register, add item, wait for job, see result, plan limit, rescan, report, a second user gets 404;
- login success/failure; CSRF rejection;
- billing tests (see stripe.md).

## 10. Running it locally

Use a preview/launch config so the user can see it in a browser, e.g.
`.venv\Scripts\python -m uvicorn app.main:app --app-dir <product> --port 8000`. Restart the server after Python
changes (no autoreload by default). Tell the user the address and how to log in with the dev test account.

# SurfaceGuard

Attack-surface monitoring SaaS for small businesses and MSPs.

| Folder | What it is |
|---|---|
| [`surfaceguard/`](surfaceguard/) | The web app (FastAPI + SQLite, Stripe billing, Fly.io deploy). Start with its [README](surfaceguard/README.md); deploy steps are in [DEPLOY.md](surfaceguard/DEPLOY.md). |
| [`saas-builder/`](saas-builder/) | The Claude skill that captures how this product was built, for reuse on the next SaaS idea. |

## Quick start

```bash
cd surfaceguard
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Secrets (Stripe keys, session secret, SMTP) are never committed. Locally the app runs without them in demo
billing mode; in production they are set with `fly secrets set`.

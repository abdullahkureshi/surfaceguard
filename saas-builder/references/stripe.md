# Phase 5 — Stripe subscriptions

Four assets fit together — copy all of them, then adapt plan names, prices, the logger name and the plan-limit key:

| Asset | Goes into | Provides |
|---|---|---|
| `assets/billing.py` | `app/billing.py` | Stripe REST calls, checkout/portal, signature check, event handling |
| `assets/config.py` | `app/config.py` | env settings, `billing_mode()`, `check_production()` |
| `assets/db_billing.py` | merge into `app/db.py` | `stripe_events` table, user billing columns + migration, `set_billing`, `get_user_by_customer`, `record_stripe_event`, `paused_ids` |
| `assets/billing_routes.py` | merge into `app/main.py` | `/billing/*` and `/stripe/webhook` routes, security headers, asset versioning, `client_ip` |

`billing.py` also needs `db.get_user(id)` returning a row with `id`, `email`, `plan` and the billing columns.

The keys of `config.STRIPE_PRICES` must equal the paid keys in `db.PLANS` (default `pro` and `msp`, read from
`STRIPE_PRICE_PRO` / `STRIPE_PRICE_MSP`). If the product calls its top tier "Agency" or "Business", either keep the
internal key `msp` and change only the display `name` in `PLANS` (simplest), or rename the key and the env var
together everywhere (config, `.env.example`, DEPLOY.md, `fly secrets` command).
They call Stripe's REST API with `httpx` (no SDK: smaller image, and the SDK can fail to install on Windows
because of path-length limits).

## Design

```
Pricing page ──POST /billing/checkout──► Stripe Checkout (hosted) ──► /billing/success?session_id=...
                                                                     │ syncs plan immediately (only if the
                                                                     │ session's client_reference_id == user)
Stripe ──POST /stripe/webhook (signed)──► handle_event ──► users.plan / subscription_status
Dashboard "manage billing" ──POST /billing/portal──► Stripe Customer Portal (change plan, card, cancel)
```

- **Webhooks are the source of truth.** The success-page sync is just for instant UX.
- **Billing modes** (`config.billing_mode()`): `stripe` when the secret key and all price IDs are set; `demo`
  (free plan switching, for local development) only when there are no keys, `DEMO_BILLING=1` is set and the app is
  not in production; `disabled` otherwise. Demo mode is opt-in so a deployment that forgets
  `ENVIRONMENT=production` cannot hand out paid plans. The demo route returns 404 unless in demo mode.
- **Existing subscribers never get a second Checkout**; send them to the portal for any change.
- `customer` is created once per user (idempotency key `customer-<user_id>`) and stored.
- Checkout session: `mode=subscription`, `client_reference_id=user_id`, metadata `user_id`/`plan` on both the
  session and `subscription_data`, `allow_promotion_codes`, `billing_address_collection=required` and
  `tax_id_collection` (EU VAT invoices), success/cancel URLs from `BASE_URL`.

## DB columns (added via migration)

`users.stripe_customer_id` (unique index), `users.stripe_subscription_id`, `users.subscription_status`, and a
`stripe_events(id PRIMARY KEY, type, received_at)` table for de-duplication, and a
`stripe_subscriptions(id PRIMARY KEY, user_id, status, last_event_created)` table holding the last known state of
each subscription. Turn on SQLite WAL mode and a busy timeout (see the note at the top of `assets/db_billing.py`):
webhooks and background jobs write at the same time.

## Webhook handling

Verify the signature yourself: header `Stripe-Signature: t=<ts>,v1=<sig>[,v1=...]`, where
`sig = HMAC_SHA256(webhook_secret, f"{t}." + raw_body)`. Compare in constant time with any `v1`, reject if the
timestamp is more than 300 s off. Use the **raw** request body (`await request.body()`), not parsed JSON. Return
400 on a bad signature, and 200 for everything else (including events you ignore), otherwise Stripe retries.

Record `event.id` first; if it's already recorded, return `duplicate` (Stripe retries deliveries). If handling
then raises, delete the record again (`forget_stripe_event`) and re-raise, so the endpoint returns 500 and Stripe's
retry is processed instead of being dropped as a duplicate.

Stripe does not guarantee event order. `apply_subscription` ignores an event whose `created` is older than the
newest one already applied to that subscription, and never moves a `canceled` or `incomplete_expired`
subscription back to active (this also covers the success-page sync, which has no event timestamp).

`stripe_request` turns network errors, non-JSON and non-object responses into `BillingError`; routes catch it
(including the portal call inside `/billing/checkout`) and show a friendly message.

| Event | Action |
|---|---|
| `customer.subscription.created` / `.updated` | Map `items.data[0].price.id` → plan via `STRIPE_PRICES`. Status `active`, `trialing`, `past_due` → grant plan (past_due = grace while Stripe retries the card). Otherwise → free. |
| `customer.subscription.deleted` | → free, clear subscription id — **only if it is the user's current subscription** (an old replaced subscription being cancelled must not downgrade them). |
| `checkout.session.completed` | Link `customer` to `client_reference_id` user. The plan comes from the subscription event. |
| `invoice.payment_failed` | Log; the dashboard shows a "payment failed — update card" banner when status is `past_due`. |

Unknown price IDs grant nothing (someone else's price must not unlock your plan).

## Webhook events to subscribe in the Stripe dashboard

`checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`,
`customer.subscription.deleted`, `invoice.payment_failed`

## Pricing page logic

- Not logged in → "Get started" (register).
- Current plan → disabled "Current plan".
- Demo mode → "Switch to X" (POST /billing/plan).
- Stripe mode, already subscribed → "Switch to X" / "Cancel subscription" via POST /billing/portal.
- Stripe mode, not subscribed, paid plan → "Upgrade to X" (POST /billing/checkout).
- Footer: "Prices exclude VAT. Cancel anytime. Secure payment by Stripe." (demo mode: say no charge is taken).

CSP must allow the redirect targets: `form-action 'self' https://checkout.stripe.com https://billing.stripe.com`.

## Tests (offline — see `assets/test_billing_example.py`)

- Signature: valid accepted; wrong secret, stale timestamp, garbage header, tampered body rejected.
- Form encoding of nested params (`line_items[0][price]`).
- Lifecycle through the real webhook endpoint with signed payloads: created → pro, duplicate ignored,
  updated → msp, past_due keeps plan, deleted → free.
- Old subscription cancel doesn't downgrade; unknown price grants nothing.
- Checkout route with `billing.stripe_request` replaced by a fake: redirects to checkout URL, sends the right
  price, demo route 404s, success page with **another user's** session doesn't upgrade, subscribers are sent to
  the portal.
- Downgrade pauses extra items; scheduler skips them.

Be honest in the summary: these tests prove the logic against a mock, not against real Stripe. Real Stripe is
tested in test mode during the deploy walkthrough.

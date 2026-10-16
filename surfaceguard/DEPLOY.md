# Deploying SurfaceGuard (Stripe + Fly.io)

About 30–45 minutes. Everything below uses **test mode** first, so no real money moves until you switch to live keys
in step 5. You need: a Stripe account, a Fly.io account (credit card required, ~€5/month), and PowerShell.

---

## 1. Stripe (test mode)

Sign up at https://dashboard.stripe.com and make sure the **Test mode** toggle (top right) is on.

1. **Products** → *Add product*
   - `SurfaceGuard Pro`: recurring, **€29.00 / month** → save, then copy the **Price ID** (`price_...`)
   - `SurfaceGuard MSP`: recurring, **€149.00 / month** → copy its Price ID
2. **Developers → API keys** → copy the **Secret key** (`sk_test_...`). Never paste it anywhere public.
3. **Settings → Billing → Customer portal** → turn on:
   - *Customers can update payment methods*
   - *Customers can switch plans* → add both products
   - *Customers can cancel subscriptions* (at end of billing period)
4. The webhook comes in step 3, once your app has a URL.

## 2. Install Fly and create the app

```bash
iwr https://fly.io/install.ps1 -useb | iex
```

Close and reopen PowerShell, then from the `surfaceguard` folder:

```bash
fly auth signup
```

Open `fly.toml` and change `app = "surfaceguard"` to a unique name (e.g. `surfaceguard-abdul`), and set `BASE_URL`
to `https://<that-name>.fly.dev`. Then:

```bash
fly launch --copy-config --no-deploy
```

```bash
fly volumes create surfaceguard_data --region fra --size 1
```

## 3. Stripe webhook

In Stripe: **Developers → Webhooks → Add endpoint**
- URL: `https://<your-app>.fly.dev/stripe/webhook`
- Events: `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`,
  `customer.subscription.deleted`, `invoice.payment_failed`
- Save, then reveal and copy the **Signing secret** (`whsec_...`)

## 4. Secrets and first deploy

Generate a session secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set all secrets in one command (replace each value):

```bash
fly secrets set SESSION_SECRET=paste_generated_value STRIPE_SECRET_KEY=sk_test_xxx STRIPE_WEBHOOK_SECRET=whsec_xxx STRIPE_PRICE_PRO=price_xxx STRIPE_PRICE_MSP=price_xxx
```

```bash
fly deploy
```

The app refuses to start if a required production setting is missing, and `fly logs` will tell you which one.

**Test it:** open `https://<your-app>.fly.dev`, run a free check, create an account, click *Upgrade to Pro*, and pay
with Stripe's test card `4242 4242 4242 4242` (any future date, any CVC). You should land on the dashboard on the
Pro plan. In Stripe → Webhooks, every delivery should show `200`.

Optional, for alert emails: create an account with an SMTP provider (Brevo, Postmark, Resend, Mailgun) and
`fly secrets set SMTP_HOST=... SMTP_USER=... SMTP_PASSWORD=... SMTP_FROM=alerts@yourdomain.com`.

## 5. Going live (real payments)

Before you charge real customers in Austria/the EU you need, at a minimum (get proper legal advice):
- **Impressum** (company/owner details): required in Austria
- **Terms of Service** and **Privacy Policy** (GDPR: you store emails and scan data)
- A business registration (Gewerbe) and correct VAT handling. Consider enabling **Stripe Tax**.

Then:
1. In Stripe, switch off Test mode, recreate the two products/prices and the webhook in **live** mode.
2. `fly secrets set STRIPE_SECRET_KEY=sk_live_... STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_PRICE_PRO=price_... STRIPE_PRICE_MSP=price_...`
   (setting secrets redeploys automatically)
3. Custom domain: `fly certs add app.yourdomain.com`, add the DNS records it prints, then update `BASE_URL` in
   `fly.toml`, the Stripe webhook URL, and run `fly deploy`.

## Operations

| Task | Command |
|---|---|
| Live logs | `fly logs` |
| Status / health | `fly status` |
| Shell inside the server | `fly ssh console` |
| Database backups | Fly snapshots volumes daily automatically: `fly volumes snapshots list <volume-id>` |
| Redeploy after code changes | `fly deploy` |

Run exactly **one** machine: the rescan scheduler runs inside the app and SQLite has one writer.
To scale beyond a few thousand domains, move to Postgres and a separate scan worker.

# Phase 7 — Going live (real payments)

Only after the test-mode walkthrough works end to end.

## Legal and business basics (EU-focused — always recommend proper legal/tax advice)

Before charging real customers:
- **Imprint / Impressum** — mandatory in Austria and Germany for commercial sites (name, address, contact, company
  register / trade licence details, VAT ID if any).
- **Terms of Service** — plans, cancellation, liability limits (important for security/compliance tools: results
  are automated and not a guarantee), acceptable use (e.g. only scan domains you own).
- **Privacy Policy (GDPR)** — what data is stored (emails, results, payment handled by Stripe), where (hosting
  region), retention, processors (hosting, Stripe, email provider), user rights.
- **Business registration and VAT** — e.g. a Gewerbe in Austria; consider **Stripe Tax** for EU VAT. B2B prices
  shown excluding VAT.
- Consumers in the EU have a 14-day withdrawal right; B2B-only products should say so clearly.

Offer to add these as pages (footer links) with placeholders for the user's details — don't invent their address
or company data.

## Switching Stripe to live

1. In Stripe, turn **Test mode off**, complete account activation (business details, bank account).
2. Recreate the products/prices in live mode → new live Price IDs.
3. Configure the Customer Portal again (live mode has its own settings).
4. Create the live webhook endpoint (same URL and events) → new `whsec_...`.
5. `fly secrets set STRIPE_SECRET_KEY=sk_live_... STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_PRICE_PRO=price_... STRIPE_PRICE_MSP=price_...`
   (setting secrets redeploys).
6. Make one real purchase with their own card, check the plan updates, then refund it in Stripe.

## Custom domain

`fly certs add app.<theirdomain>` → add the DNS records it prints → wait for the certificate → update `BASE_URL`
in `fly.toml`, the Stripe webhook URL (both modes if used), then `fly deploy`.

## After launch

- Backups: Fly snapshots volumes daily; show `fly volumes snapshots list <id>`. For anything important, also a
  periodic off-site copy of the SQLite file.
- Monitoring: `fly logs`, `fly status`; an uptime monitor on `/healthz`.
- Scaling path: Postgres + separate worker process when one machine is no longer enough.
- Growth: the free tool is the top of the funnel — suggest a few distribution moves fitting the product (reseller
  partners, LinkedIn posts with anonymised findings, local business associations, directories).

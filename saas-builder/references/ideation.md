# Phase 1 — Finding an in-demand SaaS idea

## What makes an idea worth building

Score each candidate on these. The best ideas are strong on the first three.

1. **Painful, recurring problem with budget.** Someone already loses money or time on it every month, and a
   business (not a consumer) would expense the fix. Recurring pain justifies recurring billing.
2. **A forcing function ("why now").** A regulation deadline (EU NIS2, AI Act, e-invoicing mandates, PCI-DSS),
   insurer requirements, a platform shift (AI adoption, new APIs), or a price gap left by enterprise tools.
3. **The user's unfair advantage.** Their profession, domain knowledge, language, country or network. A
   cybersecurity person building security tooling, a German speaker serving DACH SMEs, an accountant building
   for accountants — this beats a generic idea every time, especially for sales.
4. **Small enough to ship an MVP in 1–4 weeks** by one person with Claude.
5. **Distribution path.** A free tool that delivers value without signup, resellers (MSPs, consultants, agencies),
   marketplaces/app stores, or a community the user is already in.
6. **Competition is a signal, not a blocker.** Existing tools prove demand. Win by serving a segment they price out
   or ignore (SMEs, one country/language, one vertical).

Avoid as defaults: consumer apps with ad models, two-sided marketplaces (cold-start problem), anything needing
large datasets or heavy compliance before the first sale (e.g. medical devices), and crowded generic categories
(another to-do app) unless the user has a sharp niche.

## Format for presenting ideas

For each idea (6–10):

```
### N. <Short name>
**Problem:** one or two sentences, concrete.
**Product:** what it does, in plain words.
**Who pays:** specific buyer. **Price:** €X–Y/mo (per user/domain/seat if relevant).
**Why now:** the forcing function.
**Your edge:** (only if the user has one for this idea)
```

Then a comparison table:

| Idea | Demand | Competition | Build effort | Fit for you |
|---|---|---|---|---|

End with **one** recommendation (or two ranked) and why, then ask which they want to build. Mention that the
others can be built later with the same workflow.

## Idea families that reliably have demand (2025–2026)

Use these as starting points, adapted to the user's background — don't copy them verbatim.

- **Security for small businesses / MSPs:** external attack-surface monitoring, phishing simulation, security
  questionnaire autopilot, shadow-AI usage monitoring, cyber-insurance readiness reports.
- **Compliance for SMEs:** NIS2 / DORA / AI Act / GDPR self-assessment + evidence tracking, policy generators,
  supplier risk questionnaires.
- **AI-automated back office:** receipt/invoice extraction with accountant-ready exports, e-invoicing compliance,
  contract renewal tracking.
- **Local-business AI:** AI receptionist / booking agents for one vertical and one language.
- **Product/feedback tooling:** feedback aggregation to roadmap, changelog/status pages, uptime + SSL monitoring.
- **Vertical SaaS:** scheduling/billing for a specific profession the user knows (physio clinics, driving schools,
  tutoring centres).

## Pricing defaults

Three tiers anchor well: **Free** (enough to feel the value, very limited), **Pro** (~€19–49/mo, the plan most
people should buy, mark it "most popular"), **Agency/MSP/Business** (~€99–199/mo, for resellers or multiple
clients). Limit by the unit of value (domains, seats, documents, scans), not by features nobody understands.
Show prices excluding VAT for B2B in the EU.

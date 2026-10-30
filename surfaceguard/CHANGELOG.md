# Changelog

## Unreleased – security and reliability fixes

Fixes from the full code review of 2026-10-30. IDs (H = high, M = medium, L = low) refer to that review.

- Follow-up fixes from the fix verification (N = new): a DNS timeout or server failure during the TXT re-check no
  longer clears verification; only NXDOMAIN or an answer without the token does (N1). The tight login limit is now
  per IP and email together (10 per 15 minutes), with 30 per IP and 100 per email, so a user can no longer be
  locked out from someone else's network; the check and the counting are now atomic (N2, N8). `/register` allows
  5 new accounts per hour per IP (N3).

### Security

- Scanner redirects are followed by hand (max 5 hops, `http`/`https` on ports 80/443 only), and every hop's host
  must resolve to public IPs. Redirects to internal addresses are no longer followed (H1).
- The scanner resolves a domain once and pins TLS, HTTP and port connections to the validated IPs, sending the
  domain as `Host` and SNI. This closes the DNS-rebinding gap (H2).
- Response bodies are capped: the HTTP check reads headers only, exposed-file probes read at most 4 KB, and
  crt.sh is capped at 5 MB (partial results are marked `truncated`) (H3).
- `_is_public_ip` now requires `is_global`, so CGNAT, NAT64, 6to4, Teredo and IPv4-mapped private addresses are
  refused (L5).
- SMTP STARTTLS verifies the server certificate. `SMTP_PORT=465` is supported with implicit TLS (M3).
- `/login` limits failed attempts (see N2 above for the current limits). Unknown emails are checked against a
  dummy hash, so response time no longer reveals which accounts exist (M6).
- A non-ASCII CSRF token now returns 400 instead of 500 (L3).
- Before each verified scan the DNS TXT record is checked again; if it is gone, verification is cleared and only
  passive checks run (L7).
- In production without `SMTP_HOST`, logs no longer contain alert bodies or email addresses (L8).
- PBKDF2 uses 600,000 iterations. Older hashes are upgraded on the next successful login (L11).

### Billing

- A webhook event that fails during handling is un-recorded and returns 500, so Stripe's retry is processed
  (H4).
- Out-of-order or stale subscription events are ignored, and a canceled subscription can never become active
  again (new `stripe_subscriptions` table) (M1).
- Demo plan switching now requires `DEMO_BILLING=1` and is never available in production. Without Stripe keys
  and without this flag, billing is disabled (L4).
- Stripe network errors and malformed responses show a friendly message instead of a 500 (L6).

### Reliability

- Per-plan scan budget: user-started scans (add domain, rescan, verify) are limited per rolling hour to Free 5,
  Pro 30, MSP 150. Deleting a domain does not reset the budget. Anonymous `/check` runs at most
  `MAX_CONCURRENT_CHECKS` at once (default 2) (M5).
- `/verify` respects the paused state, a running scan, the 120-second cooldown and the scan budget (M4).
- A scan that fails during post-processing is marked failed instead of staying "running" forever (M7).
- Carried-forward results survive repeated timeouts and expire after 7 days (M8).
- The scheduler no longer starts a second scan for a domain that is already being scanned (M9).
- Scanner DNS/TLS work uses its own thread pool, and per-scan DNS concurrency is capped at 10 (M10).
- SMTP sending and password hashing no longer block the event loop (M2).
- The dashboard only auto-refreshes while a scan is running (L2).
- Rate-limit memory is pruned (L9). SQLite uses WAL mode and a 10-second busy timeout (L10).
- Findings have stable IDs, and TLS expiry titles no longer include the day count, so expiry alerts are not
  repeated every day (L1).

### Operations

- New environment variables: `DEMO_BILLING` (local development only) and `MAX_CONCURRENT_CHECKS` (default 2).
- Production prints a startup warning when `SMTP_HOST` is missing.
- `requirements.txt` is pinned to exact versions, and the Docker image uses `python:3.13.18-slim-bookworm` (M11).
- New tables (`scan_launches`, `stripe_subscriptions`) are created automatically on startup; no manual migration
  is needed.
- **One-time effect after deploy:** a certificate that is already inside the 21-day (or 7-day) expiry window
  will trigger one more alert on the first scan after deploy, because its finding title changed. The same applies
  to domains that accept TLS 1.0/1.1 (the version moved from the title to the evidence). Later scans match on the
  new stable ID and do not repeat the alert.

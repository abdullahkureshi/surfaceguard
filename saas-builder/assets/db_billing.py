"""Billing additions for app/db.py — paste into your db module (needs `conn()`, `now()` and `sqlite3`).

billing.py calls: get_user, get_user_by_customer, set_billing, record_stripe_event, forget_stripe_event,
get_stripe_subscription, save_stripe_subscription.

Also add to conn(), after connecting:  PRAGMA busy_timeout = 10000  and  PRAGMA synchronous = NORMAL,
and run  PRAGMA journal_mode = WAL  once in init(). Webhooks and background jobs write at the same time;
without WAL, "database is locked" errors are much more likely.
"""

# 1. Add to SCHEMA:
STRIPE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS stripe_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at TEXT NOT NULL);
-- Last known state of each Stripe subscription, to ignore stale or out-of-order webhook events.
CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, status TEXT NOT NULL, last_event_created INTEGER);
"""

# 2. Columns added to an existing users table; apply in init():
MIGRATIONS = {
    "users": [("stripe_customer_id", "TEXT"), ("stripe_subscription_id", "TEXT"), ("subscription_status", "TEXT")],
}


def init():
    with conn() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for name, sqltype in cols:
                if name not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_customer ON users(stripe_customer_id)")


# 3. Helpers
_UNSET = object()


def set_billing(user_id, plan=_UNSET, customer_id=_UNSET, subscription_id=_UNSET, status=_UNSET):
    """Update only the fields passed (None is a real value: it clears the column)."""
    fields = {"plan": plan, "stripe_customer_id": customer_id,
              "stripe_subscription_id": subscription_id, "subscription_status": status}
    fields = {k: v for k, v in fields.items() if v is not _UNSET}
    if not fields:
        return
    with conn() as c:
        c.execute(f"UPDATE users SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), user_id))


def get_user_by_customer(customer_id):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE stripe_customer_id=?", (customer_id,)).fetchone()


def record_stripe_event(event_id, event_type):
    """Returns False if this webhook event was already processed (Stripe retries deliveries)."""
    try:
        with conn() as c:
            c.execute("INSERT INTO stripe_events(id, type, received_at) VALUES (?,?,?)", (event_id, event_type, now()))
        return True
    except sqlite3.IntegrityError:
        return False


def forget_stripe_event(event_id):
    """Undo record_stripe_event when handling failed, so Stripe's retry is processed instead of skipped."""
    with conn() as c:
        c.execute("DELETE FROM stripe_events WHERE id=?", (event_id,))


def get_stripe_subscription(sub_id):
    with conn() as c:
        return c.execute("SELECT * FROM stripe_subscriptions WHERE id=?", (sub_id,)).fetchone()


def save_stripe_subscription(sub_id, user_id, status, event_created=None):
    """Remember a subscription's latest status and the newest event timestamp seen for it."""
    with conn() as c:
        c.execute("""INSERT INTO stripe_subscriptions(id, user_id, status, last_event_created) VALUES (?,?,?,?)
                     ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, status=excluded.status,
                       last_event_created=MAX(COALESCE(last_event_created, 0), COALESCE(excluded.last_event_created, 0))""",
                  (sub_id, user_id, status, event_created))


# 4. Downgrades: resources beyond the plan limit are paused, not deleted (oldest stay active).
#    `table` is formatted into the SQL: only ever pass a constant, never user input.
def paused_ids(user_id, plan, table="domains"):
    with conn() as c:
        ids = [r["id"] for r in c.execute(f"SELECT id FROM {table} WHERE user_id=? ORDER BY id", (user_id,))]
    return set(ids[PLANS[plan]["domains"]:])  # rename "domains" to your plan's limit key

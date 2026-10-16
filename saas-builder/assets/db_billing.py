"""Billing additions for app/db.py — paste into your db module (needs `conn()`, `now()` and `sqlite3`).

billing.py calls: get_user, get_user_by_customer, set_billing, record_stripe_event.
"""

# 1. Add to SCHEMA:
STRIPE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS stripe_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at TEXT NOT NULL);
"""

# 2. Columns added to an existing users table; apply in init():
MIGRATIONS = {
    "users": [("stripe_customer_id", "TEXT"), ("stripe_subscription_id", "TEXT"), ("subscription_status", "TEXT")],
}


def init():
    with conn() as c:
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


# 4. Downgrades: resources beyond the plan limit are paused, not deleted (oldest stay active).
def paused_ids(user_id, plan, table="domains"):
    with conn() as c:
        ids = [r["id"] for r in c.execute(f"SELECT id FROM {table} WHERE user_id=? ORDER BY id", (user_id,))]
    return set(ids[PLANS[plan]["domains"]:])  # rename "domains" to your plan's limit key

"""SQLite storage. One short-lived connection per call keeps things thread-safe."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from . import config

DB_PATH = os.environ.get("SURFACEGUARD_DB", os.path.join(config.DATA_DIR, "surfaceguard.db"))

# scans_per_hour: user-started scans (add domain, rescan, verify) per rolling hour. Scheduled scans don't count.
PLANS = {
    "free": {"name": "Free", "price": 0, "domains": 1, "interval_hours": 24 * 7, "scans_per_hour": 5},
    "pro": {"name": "Pro", "price": 29, "domains": 10, "interval_hours": 24, "scans_per_hour": 30},
    "msp": {"name": "MSP", "price": 149, "domains": 100, "interval_hours": 24, "scans_per_hour": 150},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, verify_token TEXT NOT NULL, verified_at TEXT, alerts INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, last_scan_at TEXT, UNIQUE(user_id, name));
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, score INTEGER, grade TEXT,
    result_json TEXT, error TEXT, new_issues INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id, id DESC);
CREATE TABLE IF NOT EXISTS stripe_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at TEXT NOT NULL);
-- Last known state of each Stripe subscription, to ignore stale or out-of-order webhook events.
CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, status TEXT NOT NULL, last_event_created INTEGER);
-- User-started scan launches. Kept apart from `scans` so deleting a domain doesn't reset the budget.
CREATE TABLE IF NOT EXISTS scan_launches (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, launched_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_scan_launches_user ON scan_launches(user_id, launched_at);
"""

# Columns added after the first release; applied to existing databases on startup.
MIGRATIONS = {
    "users": [("stripe_customer_id", "TEXT"), ("stripe_subscription_id", "TEXT"), ("subscription_status", "TEXT")],
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA busy_timeout = 10000")
    c.execute("PRAGMA synchronous = NORMAL")  # safe with WAL, far fewer fsyncs
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        # WAL lets readers and the single writer work at the same time (fewer "database is locked" errors).
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for name, sqltype in cols:
                if name not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_customer ON users(stripe_customer_id)")
        # Scans interrupted by a restart would otherwise stay "running" forever.
        c.execute("UPDATE scans SET status='failed', error='Interrupted by server restart' WHERE status='running'")


# ---- users

def create_user(email, pw_hash):
    with conn() as c:
        cur = c.execute("INSERT INTO users(email, pw_hash, created_at) VALUES (?,?,?)", (email, pw_hash, now()))
        return cur.lastrowid


def get_user_by_email(email):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()


def get_user(user_id):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def set_password_hash(user_id, pw_hash):
    with conn() as c:
        c.execute("UPDATE users SET pw_hash=? WHERE id=?", (pw_hash, user_id))


def set_plan(user_id, plan):
    with conn() as c:
        c.execute("UPDATE users SET plan=? WHERE id=?", (plan, user_id))


_UNSET = object()


def set_billing(user_id, plan=_UNSET, customer_id=_UNSET, subscription_id=_UNSET, status=_UNSET):
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


# ---- domains

def add_domain(user_id, name, token):
    with conn() as c:
        cur = c.execute("INSERT INTO domains(user_id, name, verify_token, created_at) VALUES (?,?,?,?)",
                        (user_id, name, token, now()))
        return cur.lastrowid


def list_domains(user_id):
    with conn() as c:
        return c.execute("""
            SELECT d.*, s.score, s.grade, s.status AS scan_status, s.result_json AS last_result
            FROM domains d
            LEFT JOIN scans s ON s.id = (SELECT id FROM scans WHERE domain_id=d.id ORDER BY id DESC LIMIT 1)
            WHERE d.user_id=? ORDER BY d.name""", (user_id,)).fetchall()


def get_domain(domain_id, user_id=None):
    with conn() as c:
        if user_id is None:
            return c.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
        return c.execute("SELECT * FROM domains WHERE id=? AND user_id=?", (domain_id, user_id)).fetchone()


def delete_domain(domain_id, user_id):
    with conn() as c:
        c.execute("DELETE FROM domains WHERE id=? AND user_id=?", (domain_id, user_id))


def mark_verified(domain_id):
    with conn() as c:
        c.execute("UPDATE domains SET verified_at=? WHERE id=?", (now(), domain_id))


def clear_verified(domain_id):
    with conn() as c:
        c.execute("UPDATE domains SET verified_at=NULL WHERE id=?", (domain_id,))


def set_alerts(domain_id, user_id, on):
    with conn() as c:
        c.execute("UPDATE domains SET alerts=? WHERE id=? AND user_id=?", (1 if on else 0, domain_id, user_id))


def paused_domain_ids(user_id, plan):
    """After a downgrade, domains beyond the plan's limit are kept but paused (oldest stay active)."""
    with conn() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM domains WHERE user_id=? ORDER BY id", (user_id,))]
    return set(ids[PLANS[plan]["domains"]:])


def domains_due_for_scan():
    """Active (non-paused) domains whose last scan is older than their owner's plan interval."""
    with conn() as c:
        rows = c.execute("""SELECT * FROM (
                                SELECT d.*, u.plan, u.email,
                                       ROW_NUMBER() OVER (PARTITION BY d.user_id ORDER BY d.id) AS rank
                                FROM domains d JOIN users u ON u.id=d.user_id) AS x
                            WHERE NOT EXISTS (SELECT 1 FROM scans s WHERE s.domain_id=x.id AND s.status='running')""").fetchall()
    due = []
    for r in rows:
        if r["rank"] > PLANS[r["plan"]]["domains"]:
            continue
        if not r["last_scan_at"]:
            due.append(r)
            continue
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(r["last_scan_at"])).total_seconds() / 3600
        if age_h >= PLANS[r["plan"]]["interval_hours"]:
            due.append(r)
    return due


# ---- scans

def record_scan_launch(user_id):
    with conn() as c:
        c.execute("INSERT INTO scan_launches(user_id, launched_at) VALUES (?,?)", (user_id, now()))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        c.execute("DELETE FROM scan_launches WHERE launched_at < ?", (cutoff,))


def scan_launches_since(user_id, hours=1):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with conn() as c:
        return c.execute("SELECT COUNT(*) FROM scan_launches WHERE user_id=? AND launched_at >= ?",
                         (user_id, cutoff)).fetchone()[0]


def start_scan(domain_id):
    with conn() as c:
        cur = c.execute("INSERT INTO scans(domain_id, status, started_at) VALUES (?, 'running', ?)", (domain_id, now()))
        c.execute("UPDATE domains SET last_scan_at=? WHERE id=?", (now(), domain_id))
        return cur.lastrowid


def finish_scan(scan_id, result, new_issues):
    with conn() as c:
        c.execute("""UPDATE scans SET status='done', finished_at=?, score=?, grade=?, result_json=?, new_issues=?
                     WHERE id=?""", (now(), result["score"], result["grade"], json.dumps(result), new_issues, scan_id))


def fail_scan(scan_id, error):
    with conn() as c:
        c.execute("UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?", (now(), error, scan_id))


def running_scan(domain_id):
    with conn() as c:
        return c.execute("SELECT * FROM scans WHERE domain_id=? AND status='running'", (domain_id,)).fetchone()


def scan_history(domain_id, limit=30):
    with conn() as c:
        return c.execute("SELECT id, status, started_at, finished_at, score, grade, error, new_issues FROM scans "
                         "WHERE domain_id=? ORDER BY id DESC LIMIT ?", (domain_id, limit)).fetchall()


def latest_done_scan(domain_id, before_id=None):
    with conn() as c:
        if before_id:
            return c.execute("SELECT * FROM scans WHERE domain_id=? AND status='done' AND id<? ORDER BY id DESC LIMIT 1",
                             (domain_id, before_id)).fetchone()
        return c.execute("SELECT * FROM scans WHERE domain_id=? AND status='done' ORDER BY id DESC LIMIT 1",
                         (domain_id,)).fetchone()


def latest_scan(domain_id):
    with conn() as c:
        return c.execute("SELECT * FROM scans WHERE domain_id=? ORDER BY id DESC LIMIT 1", (domain_id,)).fetchone()

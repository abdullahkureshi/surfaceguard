"""Password hashing (PBKDF2, stdlib only) and session helpers."""
import hashlib
import hmac
import os
import re
import secrets

ITERATIONS = 310_000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
    except ValueError:
        return False
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
    return hmac.compare_digest(test.hex(), digest)


def secret_key() -> str:
    """SESSION_SECRET env var in production; otherwise a key persisted next to the app."""
    if os.environ.get("SESSION_SECRET"):
        return os.environ["SESSION_SECRET"]
    from .config import DATA_DIR
    path = os.path.join(DATA_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def csrf_token(session) -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf(session, token) -> bool:
    return bool(token) and hmac.compare_digest(session.get("csrf", ""), token)

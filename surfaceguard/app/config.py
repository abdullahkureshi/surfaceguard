"""Settings from environment variables (see .env.example)."""
import os


def env(name, default=""):
    return os.environ.get(name, default).strip()


ENVIRONMENT = env("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT == "production"
BASE_URL = env("BASE_URL", "http://localhost:8000").rstrip("/")
DATA_DIR = env("DATA_DIR", os.path.join(os.path.dirname(__file__), ".."))
# Header set by the hosting proxy with the real visitor IP (e.g. Fly-Client-IP). Only trust it behind that proxy.
CLIENT_IP_HEADER = env("CLIENT_IP_HEADER").lower()

STRIPE_SECRET_KEY = env("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = env("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICES = {"pro": env("STRIPE_PRICE_PRO"), "msp": env("STRIPE_PRICE_MSP")}


def billing_mode():
    """'stripe' when keys are configured; 'demo' (free plan switching) only outside production."""
    if STRIPE_SECRET_KEY and all(STRIPE_PRICES.values()):
        return "stripe"
    return "disabled" if IS_PRODUCTION else "demo"


def check_production():
    """Refuse to boot in production with settings that would be insecure or broken."""
    if not IS_PRODUCTION:
        return
    missing = [k for k in ("SESSION_SECRET", "BASE_URL", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
                           "STRIPE_PRICE_PRO", "STRIPE_PRICE_MSP") if not env(k)]
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
    if not BASE_URL.startswith("https://"):
        raise RuntimeError("BASE_URL must start with https:// in production")
    if STRIPE_SECRET_KEY.startswith("sk_test_"):
        print("WARNING: production is using a Stripe TEST key — no real payments will be taken.")

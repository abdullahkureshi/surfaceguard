"""Running scans in the background, scheduled rescans, and change alerts."""
import asyncio
import json
import logging
import os
import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage

from . import config, db
from .scanner import ScanError, dns_txt_strict, run_scan, sort_findings
from .scoring import diff_findings, score_findings

log = logging.getLogger("surfaceguard")
_tasks = set()  # keep references so background tasks aren't garbage-collected
MAX_CONCURRENT = asyncio.Semaphore(int(os.environ.get("MAX_CONCURRENT_SCANS", "4")))
VERIFY_PREFIX = "surfaceguard-verify="
CARRY_MAX_AGE = timedelta(days=7)  # after this, a check that keeps timing out shows as incomplete, not stale data


def launch_scan(domain_row):
    """Create a scan row and run it in the background. Must be called from the event loop."""
    loop = asyncio.get_running_loop()  # fail before writing a scan row that would never finish
    scan_id = db.start_scan(domain_row["id"])
    task = loop.create_task(_execute(scan_id, dict(domain_row)))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return scan_id


def _fail(scan_id, error):
    try:
        db.fail_scan(scan_id, error)
    except Exception:
        log.exception("could not mark scan %s as failed", scan_id)


async def _still_verified(domain):
    """Active checks only run while the ownership TXT record is still there. If the owner removed it
    (or the domain changed hands), verification is withdrawn.

    Only a definite answer (NXDOMAIN, no TXT records, or TXT records without our token) clears
    verification. If the lookup fails (timeout, SERVFAIL, no nameservers) we can't tell, so the
    existing verification is trusted for this scan: dropping the deep checks for one scan would make
    their findings vanish and then come back as "new" (a spurious alert) on the next scan."""
    if not domain.get("verified_at"):
        return False
    try:
        records = await asyncio.to_thread(dns_txt_strict, domain["name"])
    except Exception as e:
        log.warning("TXT re-check for domain %s was inconclusive (%s); keeping verification for this scan",
                    domain["id"], type(e).__name__)
        return True
    if VERIFY_PREFIX + domain["verify_token"] in records:
        return True
    log.info("verification TXT record for domain %s is gone; clearing verification", domain["id"])
    db.clear_verified(domain["id"])
    return False


async def _execute(scan_id, domain):
    try:
        async with MAX_CONCURRENT:
            verified = await _still_verified(domain)
            try:
                result = await asyncio.wait_for(run_scan(domain["name"], verified=verified), timeout=180)
            except ScanError as e:
                _fail(scan_id, str(e))
                return
            except Exception as e:
                log.exception("scan %s failed", scan_id)
                _fail(scan_id, f"Unexpected error: {type(e).__name__}")
                return
        prev = db.latest_done_scan(domain["id"], before_id=scan_id)
        prev_result = json.loads(prev["result_json"]) if prev else None
        if prev_result:
            carry_forward(result, prev_result)
        new = diff_findings(prev_result["findings"], result["findings"]) if prev_result else []
        db.finish_scan(scan_id, result, len(new))
    except Exception as e:
        # Never leave a scan "running" forever: that blocks rescans and makes the page poll endlessly.
        log.exception("post-processing of scan %s failed", scan_id)
        _fail(scan_id, f"Unexpected error: {type(e).__name__}")
        return
    if new and domain.get("alerts"):
        try:
            user = db.get_user(domain["user_id"])
            await asyncio.to_thread(send_alert, user["email"], domain["name"], result, new, user["id"])
        except Exception:
            log.exception("alert for scan %s failed", scan_id)


def _parse_time(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def carry_forward(result, prev):
    """A check that timed out must not make the domain look safer: reuse the previous
    scan's findings and facts for that category, flagged as carried over.

    Data that was itself carried keeps being carried across consecutive timeouts, until it is
    older than CARRY_MAX_AGE (measured from the scan that really collected it)."""
    for cat in result.get("incomplete", []):
        prev_facts = prev.get("facts", {}).get(cat)
        if prev_facts is None:
            continue
        if cat in prev.get("incomplete", []) and not prev_facts.get("carried"):
            continue  # the previous scan timed out too and had nothing to carry
        since = prev_facts.get("carried_since") or prev.get("started_at")
        t_since, t_now = _parse_time(since), _parse_time(result.get("started_at"))
        if t_since and t_now and t_now - t_since > CARRY_MAX_AGE:
            continue
        for f in prev["findings"]:
            if f["check"] == cat:
                result["findings"].append({**f, "carried": True})
        result["facts"][cat] = {**prev_facts, "carried": True, "carried_since": since}
    result["findings"] = sort_findings(result["findings"])
    result["score"], result["grade"] = score_findings(result["findings"])


def send_alert(to, domain, result, new_findings, user_id=None):
    """Blocking (smtplib): call it through asyncio.to_thread from async code."""
    lines = [f"SurfaceGuard found {len(new_findings)} new issue(s) on {domain}.",
             f"Current score: {result['score']}/100 (grade {result['grade']})", ""]
    for f in new_findings:
        lines += [f"[{f['severity'].upper()}] {f['title']}", f"  How to fix: {f['fix']}", ""]
    body = "\n".join(lines)
    host = os.environ.get("SMTP_HOST")
    if not host:
        if config.IS_PRODUCTION:
            # No recipient address or findings in production logs.
            log.warning("alert suppressed for user id %s (SMTP not configured)", user_id)
        else:
            log.warning("ALERT for user id %s (SMTP not configured):\n%s", user_id, body)
        return
    msg = EmailMessage()
    msg["Subject"] = f"[SurfaceGuard] {len(new_findings)} new security issue(s) on {domain}"
    msg["From"] = os.environ.get("SMTP_FROM", "alerts@surfaceguard.local")
    msg["To"] = to
    msg.set_content(body)
    port = int(os.environ.get("SMTP_PORT") or "587")
    context = ssl.create_default_context()  # verifies the server certificate and hostname
    try:
        if port == 465:  # implicit TLS
            smtp = smtplib.SMTP_SSL(host, port, timeout=15, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=15)
        with smtp as s:
            if port != 465:
                s.starttls(context=context)
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            s.send_message(msg)
    except Exception:
        log.exception("failed to send alert for user id %s", user_id)


async def scheduler_loop(every_seconds=300):
    """Every few minutes, rescan domains whose plan interval has elapsed."""
    while True:
        try:
            for d in db.domains_due_for_scan():
                launch_scan(d)
        except Exception:
            log.exception("scheduler tick failed")
        await asyncio.sleep(every_seconds)

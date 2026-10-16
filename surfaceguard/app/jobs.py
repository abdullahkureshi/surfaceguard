"""Running scans in the background, scheduled rescans, and change alerts."""
import asyncio
import json
import logging
import os
import smtplib
from email.message import EmailMessage

from . import db
from .scanner import ScanError, run_scan, sort_findings
from .scoring import diff_findings, score_findings

log = logging.getLogger("surfaceguard")
_tasks = set()  # keep references so background tasks aren't garbage-collected
MAX_CONCURRENT = asyncio.Semaphore(int(os.environ.get("MAX_CONCURRENT_SCANS", "4")))


def launch_scan(domain_row):
    """Create a scan row and run it in the background. Must be called from the event loop."""
    loop = asyncio.get_running_loop()  # fail before writing a scan row that would never finish
    scan_id = db.start_scan(domain_row["id"])
    task = loop.create_task(_execute(scan_id, dict(domain_row)))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return scan_id


async def _execute(scan_id, domain):
    async with MAX_CONCURRENT:
        try:
            result = await asyncio.wait_for(run_scan(domain["name"], verified=bool(domain["verified_at"])), timeout=180)
        except ScanError as e:
            db.fail_scan(scan_id, str(e))
            return
        except Exception as e:
            log.exception("scan %s failed", scan_id)
            db.fail_scan(scan_id, f"Unexpected error: {type(e).__name__}")
            return
    prev = db.latest_done_scan(domain["id"], before_id=scan_id)
    prev_result = json.loads(prev["result_json"]) if prev else None
    if prev_result:
        carry_forward(result, prev_result)
    new = diff_findings(prev_result["findings"], result["findings"]) if prev_result else []
    db.finish_scan(scan_id, result, len(new))
    if new and domain.get("alerts"):
        user = db.get_user(domain["user_id"])
        send_alert(user["email"], domain["name"], result, new)


def carry_forward(result, prev):
    """A check that timed out must not make the domain look safer: reuse the previous
    scan's findings and facts for that category, flagged as carried over."""
    for cat in result.get("incomplete", []):
        if cat in prev.get("incomplete", []) or cat not in prev["facts"]:
            continue
        for f in prev["findings"]:
            if f["check"] == cat:
                result["findings"].append({**f, "carried": True})
        result["facts"][cat] = {**prev["facts"][cat], "carried": True}
    result["findings"] = sort_findings(result["findings"])
    result["score"], result["grade"] = score_findings(result["findings"])


def send_alert(to, domain, result, new_findings):
    lines = [f"SurfaceGuard found {len(new_findings)} new issue(s) on {domain}.",
             f"Current score: {result['score']}/100 (grade {result['grade']})", ""]
    for f in new_findings:
        lines += [f"[{f['severity'].upper()}] {f['title']}", f"  How to fix: {f['fix']}", ""]
    body = "\n".join(lines)
    host = os.environ.get("SMTP_HOST")
    if not host:
        log.warning("ALERT (SMTP not configured) to %s:\n%s", to, body)
        return
    msg = EmailMessage()
    msg["Subject"] = f"[SurfaceGuard] {len(new_findings)} new security issue(s) on {domain}"
    msg["From"] = os.environ.get("SMTP_FROM", "alerts@surfaceguard.local")
    msg["To"] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            s.send_message(msg)
    except Exception:
        log.exception("failed to send alert to %s", to)


async def scheduler_loop(every_seconds=300):
    """Every few minutes, rescan domains whose plan interval has elapsed."""
    while True:
        try:
            for d in db.domains_due_for_scan():
                launch_scan(d)
        except Exception:
            log.exception("scheduler tick failed")
        await asyncio.sleep(every_seconds)

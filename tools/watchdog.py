"""External watchdog for the analysis VM (spec section 4/D6: no machine
monitors itself). Standalone stdlib file - copy it to ANY always-on box
outside the VM (a second Oracle Always Free micro instance, a Raspberry
Pi, a shell account) and run it under cron or as a loop:

    python3 watchdog.py --url http://<vm-tailscale-ip>:8766/healthz

Behavior: polls the health endpoint every --interval seconds; after
--failures consecutive misses it sends ONE alert email, then stays
quiet until the VM recovers, when it sends one recovery note. SMTP
settings come from the same env vars the project already uses
(SMTP_USER / SMTP_PASS / SMTP_HOST / SMTP_PORT, alert goes to
--email or WATCHDOG_EMAIL).

Optionally --heartbeat-url is pinged after every healthy check, so a
dead-man's-switch service (e.g. healthchecks.io) covers the watchdog
itself - the answer to "who watches the watchdog".
"""
import argparse
import os
import smtplib
import ssl
import sys
import time
import urllib.request
from email.message import EmailMessage


def check(url, timeout=10, opener=None):
    opener = opener or urllib.request.urlopen
    try:
        with opener(url, timeout=timeout) as r:
            return 200 <= getattr(r, "status", 200) < 300
    except Exception:
        return False


def send_alert(subject, body, to_addr, env=None, smtp_factory=None):
    """Minimal, dependency-free mailer. Returns (ok, message)."""
    env = os.environ if env is None else env
    user = (env.get("SMTP_USER") or "").strip()
    password = env.get("SMTP_PASS") or ""
    if not to_addr or not user or not password:
        return False, "SMTP_USER/SMTP_PASS/recipient not configured"
    host = (env.get("SMTP_HOST") or "smtp.gmail.com").strip()
    try:
        port = int(env.get("SMTP_PORT") or 587)
    except ValueError:
        port = 587
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = (env.get("SMTP_FROM") or user).strip()
    msg["To"] = to_addr
    msg.set_content(body)
    try:
        if smtp_factory is not None:
            with smtp_factory(host, port) as server:
                server.login(user, password)
                server.send_message(msg)
        elif port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30,
                                  context=ssl.create_default_context()) as s:
                s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.starttls(context=ssl.create_default_context())
                s.login(user, password)
                s.send_message(msg)
    except Exception as e:
        return False, f"SMTP send failed: {e}"
    return True, f"alert sent to {to_addr}"


def run_loop(url, email, interval=300, failures=3, heartbeat_url=None,
             check_fn=None, alert_fn=None, sleep_fn=time.sleep,
             max_cycles=None):
    """The state machine. Injectable everywhere for tests. Alerts fire
    exactly once per outage and once per recovery."""
    check_fn = check_fn or (lambda: check(url))
    alert_fn = alert_fn or (lambda subj, body: send_alert(subj, body, email))
    misses, alerted, cycles = 0, False, 0
    while max_cycles is None or cycles < max_cycles:
        cycles += 1
        if check_fn():
            if alerted:
                alert_fn(f"RECOVERED: {url} is answering again",
                         f"The VM health endpoint {url} responded after "
                         f"{misses} consecutive failures.")
            misses, alerted = 0, False
            if heartbeat_url:
                try:
                    urllib.request.urlopen(heartbeat_url, timeout=10).read()
                except Exception:
                    pass
        else:
            misses += 1
            print(f"[watchdog] miss {misses}/{failures} for {url}",
                  flush=True)
            if misses >= failures and not alerted:
                ok, msg = alert_fn(
                    f"DOWN: {url} failed {misses} consecutive checks",
                    f"The VM health endpoint {url} has not answered for "
                    f"{misses} checks ({interval}s apart). The sensor "
                    "keeps recording locally; analysis is paused until "
                    "the VM returns.")
                print(f"[watchdog] {msg}", flush=True)
                alerted = True
        sleep_fn(interval)
    return {"misses": misses, "alerted": alerted, "cycles": cycles}


def main(argv=None):
    ap = argparse.ArgumentParser(description="External VM watchdog")
    ap.add_argument("--url", default=os.environ.get("WATCHDOG_URL"),
                    help="health endpoint, e.g. http://<vm>:8766/healthz")
    ap.add_argument("--email", default=os.environ.get("WATCHDOG_EMAIL"))
    ap.add_argument("--interval", type=int,
                    default=int(os.environ.get("WATCHDOG_INTERVAL_S", 300)))
    ap.add_argument("--failures", type=int,
                    default=int(os.environ.get("WATCHDOG_FAILURES", 3)))
    ap.add_argument("--heartbeat-url",
                    default=os.environ.get("WATCHDOG_HEARTBEAT_URL"))
    ap.add_argument("--once", action="store_true",
                    help="single check: exit 0 healthy / 1 down (for cron"
                         " chaining)")
    args = ap.parse_args(argv)
    if not args.url:
        print("error: --url (or WATCHDOG_URL) is required", file=sys.stderr)
        return 2
    if args.once:
        healthy = check(args.url)
        print("healthy" if healthy else "DOWN")
        return 0 if healthy else 1
    run_loop(args.url, args.email, args.interval, args.failures,
             args.heartbeat_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())

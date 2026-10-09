#!/usr/bin/env python3
"""Health check, every 5 minutes from cron.

- Accounts are discovered from /etc/whatsapp-mcp/<account>.env (ADMIN_ADDR),
  so nothing is hardcoded.
- Each account's loopback GET /healthz must return 200 (WhatsApp connected);
  the cloudflared service must be active.
- An e-mail goes out when something goes down or comes back. If that e-mail
  can't be sent, the old state is kept so the alert is retried next run.
- If HEARTBEAT_URL is set in mail.env (for example a free healthchecks.io
  check), it is fetched while everything is healthy. That service alerts you
  when the pings stop, which is how a dead VPS gets noticed: nothing on the
  VPS can report its own death. The daily digest e-mail is a second,
  slower signal.
"""
import glob
import json
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_todo import load_env, mail_configured, smtp_send  # noqa: E402

CONF_DIR = os.environ.get("WA_CONF_DIR", "/etc/whatsapp-mcp")
STATE = os.environ.get("WA_HEALTH_STATE", "/var/lib/wa-todo/health.json")


def discover(conf_dir):
    accounts = {}
    for path in sorted(glob.glob(os.path.join(conf_dir, "*.env"))):
        name = os.path.basename(path)[:-4]
        if name == "mail":
            continue
        env = load_env(path)
        if env.get("ADMIN_ADDR"):
            accounts[name] = env["ADMIN_ADDR"]
    return accounts


def http_ok(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def service_active(name):
    return subprocess.run(["systemctl", "is-active", "--quiet", name]).returncode == 0


def check(accounts, http=http_ok, active=service_active):
    now = {"tunnel (cloudflared)": active("cloudflared")}
    for name, addr in accounts.items():
        now["whatsapp " + name] = http("http://%s/healthz" % addr)
    return now


def transitions(prev, now):
    out = []
    for k, up in sorted(now.items()):
        if prev.get(k, True) != up:
            out.append((k, up))
    return out


def run(conf_dir, state_path, http=http_ok, active=service_active, send=None, env=None):
    env = env if env is not None else load_env(os.path.join(conf_dir, "mail.env"))
    try:
        with open(state_path) as f:
            prev = json.load(f)
    except (FileNotFoundError, ValueError):
        prev = {}
    now = check(discover(conf_dir), http, active)
    changes = transitions(prev, now)
    saved = now
    if changes and mail_configured(env):
        lines = ["%s: %s" % (k, "back up" if up else "DOWN") for k, up in changes]
        hint = ("\n\nOn the VPS: journalctl -u whatsapp-mcp@<account> -n 50 (or -u cloudflared).\n"
                "If an account was logged out, re-pair it with pair-code (see the runbook).")
        subject = "WhatsApp MCP: " + ", ".join(lines)
        try:
            (send or (lambda s, b, ok: smtp_send(env, s, b, ok)))(subject, "\n".join(lines) + hint, lambda: None)
        except Exception as e:
            print("alert mail failed, will retry: %s" % e, file=sys.stderr)
            saved = prev  # keep old state so the same transition alerts again
    elif changes:
        saved = prev  # mail not configured yet: don't swallow the alert
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f)
    os.replace(tmp, state_path)
    if env.get("HEARTBEAT_URL") and all(now.values()):
        http(env["HEARTBEAT_URL"])
    return now


if __name__ == "__main__":
    run(CONF_DIR, STATE)

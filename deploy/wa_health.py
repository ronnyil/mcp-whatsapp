#!/usr/bin/env python3
"""Every 5 minutes from cron: e-mail when an account disconnects or recovers.
Uses each instance's loopback /healthz; no external monitoring service."""
import json, os, sys, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_todo import load_env, load_json, save_json, send_mail

ACCOUNTS = {"personal": "127.0.0.1:8865", "second": "127.0.0.1:8866"}  # name -> admin addr
STATE = "/var/lib/wa-todo/health.json"

env = load_env("/etc/whatsapp-mcp/mail.env")
prev = load_json(STATE, {})
now = {}
for name, addr in ACCOUNTS.items():
    try:
        with urllib.request.urlopen("http://%s/healthz" % addr, timeout=10) as r:
            now[name] = r.status == 200
    except Exception:
        now[name] = False
    if prev.get(name, True) != now[name]:
        state = "back online" if now[name] else "DISCONNECTED"
        hint = "" if now[name] else ("\n\nSSH in and check: journalctl -u whatsapp-mcp@%s -n 50\n"
                                     "If it was logged out, re-pair with pair-code (see the runbook)." % name)
        send_mail(env, "WhatsApp %s: %s" % (name, state), "Account %s is %s.%s\n" % (name, state, hint))
save_json(STATE, now)

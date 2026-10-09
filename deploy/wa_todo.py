#!/usr/bin/env python3
"""Daily WhatsApp to-do digest. Read-only: opens each account's messages.db
in SQLite read-only mode, never talks to the WhatsApp daemon, and delivers by
e-mail. Config: /etc/whatsapp-mcp/todo.json. Secrets: /etc/whatsapp-mcp/mail.env.

Cursor: SQLite rowid, not timestamps. Sealjay writes messages with
INSERT OR REPLACE, so a message that arrives late via history sync, or is
re-delivered after an edit, gets a new, higher rowid and is picked up on the
next run even if its timestamp is days old. A (chat, id, content-hash) seen
set stops unchanged re-deliveries from being re-processed.

Tasks are reconciled, not deduplicated by message ID: the model sees the
current open tasks and returns add / update / done / cancel operations, so
one message can create several tasks and later messages can change or
cancel earlier ones.
"""
import hashlib
import json
import os
import smtplib
import sqlite3
import sys
import time
import urllib.request
from email.message import EmailMessage

CONFIG = os.environ.get("WA_TODO_CONFIG", "/etc/whatsapp-mcp/todo.json")
MAX_MESSAGES = 400  # per account per run; the rest waits for the next run
SEEN_KEEP_DAYS = 30

PROMPT = """You maintain a personal to-do list extracted from WhatsApp chats.
The user is {me_names}. Their own messages are marked FROM_ME.

A task belongs on the list only if it is the user's to do:
- someone directly asks or tells the user to do something,
- the user is @mentioned or replied to with a request,
- the user commits to something themselves ("I'll ...", "אני אביא ...").
Ignore general group discussion, requests aimed at others, jokes and
rhetorical questions. Hebrew and English both occur; write task text in the
language of the source message.

Current open tasks (JSON):
{open_tasks}

New or edited messages:
{messages}

Return ONLY a JSON object: {{"ops": [...]}} where each op is one of
{{"op":"add","text":"...","due":"YYYY-MM-DD or null","chat":"<chat name>","source_ids":["<msg id>"]}}
{{"op":"update","task_id":"t12","text":"...","due":"YYYY-MM-DD or null"}}
{{"op":"done","task_id":"t12","reason":"..."}}
{{"op":"cancel","task_id":"t12","reason":"..."}}
One message may produce several adds. Use update/done/cancel when a new
message changes, completes or cancels an existing task. Return {{"ops":[]}}
if nothing changes."""


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def fetch_new(db_path, chats, cursor, seen):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    names = {r["jid"]: r["name"] or r["jid"] for r in con.execute("SELECT jid, name FROM chats")}
    q = ("SELECT rowid, id, chat_jid, sender, content, timestamp, is_from_me FROM messages "
         "WHERE rowid > ? AND content IS NOT NULL AND content != ''")
    args = [cursor]
    if chats:
        q += " AND chat_jid IN (%s)" % ",".join("?" * len(chats))
        args += chats
    q += " ORDER BY rowid LIMIT ?"
    args.append(MAX_MESSAGES)
    out, max_rowid = [], cursor
    for r in con.execute(q, args):
        max_rowid = max(max_rowid, r["rowid"])
        key = "%s|%s|%s" % (r["chat_jid"], r["id"], hashlib.sha256(r["content"].encode()).hexdigest()[:16])
        if key in seen:
            continue
        seen[key] = int(time.time())
        out.append({
            "id": r["id"],
            "chat": names.get(r["chat_jid"], r["chat_jid"]),
            "from": "FROM_ME" if r["is_from_me"] else (names.get(r["sender"]) or r["sender"]),
            "time": str(r["timestamp"])[:16],
            "text": r["content"][:2000],
        })
    con.close()
    return out, max_rowid


def ask_claude(api_key, model, prompt):
    body = json.dumps({
        "model": model,
        "max_tokens": 4000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    text = "".join(b.get("text", "") for b in data.get("content", []))
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])["ops"]


def apply_ops(state, account, ops):
    changes = []
    tasks = state["tasks"]
    for op in ops:
        kind = op.get("op")
        if kind == "add":
            state["next_id"] += 1
            tid = "t%d" % state["next_id"]
            tasks[tid] = {"account": account, "text": op.get("text", ""), "due": op.get("due"),
                          "chat": op.get("chat", ""), "sources": op.get("source_ids", []),
                          "status": "open", "updated": time.strftime("%Y-%m-%d")}
            changes.append("NEW  %s: %s" % (tid, tasks[tid]["text"]))
        elif kind in ("update", "done", "cancel"):
            t = tasks.get(op.get("task_id"))
            if not t or t["account"] != account or t["status"] != "open":
                continue
            if kind == "update":
                t["text"] = op.get("text", t["text"])
                t["due"] = op.get("due", t["due"])
                changes.append("EDIT %s: %s" % (op["task_id"], t["text"]))
            else:
                t["status"] = kind
                changes.append("%s %s: %s (%s)" % ("DONE" if kind == "done" else "DROP",
                                                   op["task_id"], t["text"], op.get("reason", "")))
            t["updated"] = time.strftime("%Y-%m-%d")
    return changes


def send_mail(env, subject, text):
    msg = EmailMessage()
    msg["From"] = env["SMTP_USER"]
    msg["To"] = env["MAIL_TO"]
    msg["Subject"] = subject
    msg.set_content(text)
    with smtplib.SMTP(env.get("SMTP_HOST", "smtp.gmail.com"), int(env.get("SMTP_PORT", "587")), timeout=60) as s:
        s.starttls()
        s.login(env["SMTP_USER"], env["SMTP_PASS"])
        s.send_message(msg)


def main():
    cfg = load_json(CONFIG, None)
    if not cfg:
        sys.exit("missing " + CONFIG)
    env = load_env(cfg.get("mail_env", "/etc/whatsapp-mcp/mail.env"))
    state_path = cfg.get("state", "/var/lib/wa-todo/state.json")
    state = load_json(state_path, {"cursors": {}, "seen": {}, "tasks": {}, "next_id": 0})

    cutoff = time.time() - SEEN_KEEP_DAYS * 86400
    state["seen"] = {k: v for k, v in state["seen"].items() if v > cutoff}

    all_changes = []
    for acct in cfg["accounts"]:
        name = acct["name"]
        msgs, new_cursor = fetch_new(acct["messages_db"], acct.get("chats", []),
                                     state["cursors"].get(name, 0), state["seen"])
        if msgs:
            open_tasks = {k: {"text": v["text"], "due": v["due"], "chat": v["chat"]}
                          for k, v in state["tasks"].items() if v["status"] == "open" and v["account"] == name}
            prompt = PROMPT.format(me_names=", ".join(cfg["me_names"]),
                                   open_tasks=json.dumps(open_tasks, ensure_ascii=False),
                                   messages=json.dumps(msgs, ensure_ascii=False))
            ops = ask_claude(env["ANTHROPIC_API_KEY"], env.get("CLAUDE_MODEL", "claude-haiku-5-5"), prompt)
            all_changes += ["[%s] %s" % (name, c) for c in apply_ops(state, name, ops)]
        # Only advance the cursor after a successful model call.
        state["cursors"][name] = new_cursor
        save_json(state_path, state)

    open_lines = ["- [%s] %s%s (%s, %s)" % (v["account"], v["text"], " — due " + v["due"] if v.get("due") else "",
                                           v["chat"], k)
                  for k, v in sorted(state["tasks"].items(), key=lambda kv: (kv[1].get("due") or "9999", kv[0]))
                  if v["status"] == "open"]
    body = "Changes since last digest:\n" + ("\n".join(all_changes) or "(none)") + \
           "\n\nOpen tasks:\n" + ("\n".join(open_lines) or "(none)") + "\n"
    if all_changes or cfg.get("send_empty", True):
        send_mail(env, "WhatsApp to-dos %s (%d open)" % (time.strftime("%a %d %b"), len(open_lines)), body)


if __name__ == "__main__":
    main()

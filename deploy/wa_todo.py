#!/usr/bin/env python3
"""Daily WhatsApp to-do digest, delivered by e-mail.

Read-only towards WhatsApp: each account's messages.db is opened with
SQLite's read-only mode, and nothing here talks to the WhatsApp daemon, so
this script has no way to send a WhatsApp message.

Which messages get processed
----------------------------
No cursor. Every run looks at all messages whose timestamp falls inside the
last LOOKBACK_DAYS (default 14), and processes the ones whose key
(account, chat, message id, content hash) is not yet in the `seen` table.
That holds regardless of how Sealjay writes rows: ROWID reuse after a
delete, INSERT OR REPLACE re-deliveries, and history sync that arrives days
late with an old timestamp are all handled the same way. An edited message
has new content, so a new key, so it is processed again.

Guarantee: a message that is in messages.db with a timestamp inside the
window when a run happens is processed exactly once per distinct content,
provided the model call succeeds; seen keys and the resulting task changes
are committed together, after the model call, in one SQLite transaction.
Limits: a message that arrives (or is backfilled) with a timestamp older than
the window is ignored; a message deleted from messages.db before any run saw
it is never processed; at most MAX_MESSAGES per account per run (the rest
wait for the next run).

Delivery
--------
Task changes go into a `changes` table (the outbox) in the same transaction.
A digest contains every undelivered change plus the current open tasks. A
change is marked delivered only after the SMTP server has accepted the
message. If sending fails, nothing is lost and the next run includes the
changes again; the model is not called again for them. If the connection
fails after the server accepted the message but before we saw the reply, the
next digest repeats those changes: delivery is at-least-once, duplicates are
possible, loss is not.

Delivery: "deliver": "whatsapp" sends the digest to your own "Message
yourself" chat through the account's loopback /self-note endpoint (needs
auto_send_to_self and WHATSAPP_SELF_NOTE_TOKEN); "email" (default) uses SMTP.

Config: /etc/whatsapp-mcp/todo.json (override with WA_TODO_CONFIG).
Secrets: /etc/whatsapp-mcp/mail.env (ANTHROPIC_API_KEY, SMTP_* for e-mail).
"""
import contextlib
import fcntl
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
MAX_MESSAGES = 400
DEFAULT_LOOKBACK_DAYS = 14

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

PLACEHOLDERS = ("sk-ant-...", "gmail-app-password", "you@gmail.com", "")


# ---------------------------------------------------------------- config

def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def mail_configured(env):
    need = ("SMTP_USER", "SMTP_PASS", "MAIL_TO")
    return all(env.get(k, "") not in PLACEHOLDERS for k in need)


# ---------------------------------------------------------------- state

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, seen_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, account TEXT NOT NULL, text TEXT NOT NULL, due TEXT,
  chat TEXT NOT NULL DEFAULT '', sources TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL,
  line TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
"""


def open_state(path):
    con = sqlite3.connect(path, timeout=30, isolation_level=None)  # explicit transactions
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    os.chmod(path, 0o600)
    return con


@contextlib.contextmanager
def transaction(con):
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
    except BaseException:
        con.execute("ROLLBACK")
        raise
    else:
        con.execute("COMMIT")


# ---------------------------------------------------------------- reading

def message_key(account, chat, mid, content):
    return "%s|%s|%s|%s" % (account, chat, mid, hashlib.sha256(content.encode()).hexdigest()[:16])


def fetch_unseen(db_path, account, chats, lookback_days, state, limit=MAX_MESSAGES):
    """Unseen messages inside the window, oldest first."""
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        names = {r["jid"]: r["name"] or r["jid"] for r in con.execute("SELECT jid, name FROM chats")}
        # julianday() parses Sealjay's "YYYY-MM-DD HH:MM:SS.nnnnnnnnn+03:00".
        # A timestamp it cannot parse is included rather than silently dropped.
        q = ("SELECT id, chat_jid, sender, content, timestamp, is_from_me FROM messages "
             "WHERE content IS NOT NULL AND content != '' "
             "AND (julianday(timestamp) IS NULL OR julianday(timestamp) >= julianday('now', ?))")
        args = ["-%d days" % lookback_days]
        if chats:
            q += " AND chat_jid IN (%s)" % ",".join("?" * len(chats))
            args += chats
        q += " ORDER BY julianday(timestamp), id"
        rows = con.execute(q, args).fetchall()
    finally:
        con.close()
    out = []
    for r in rows:
        key = message_key(account, r["chat_jid"], r["id"], r["content"])
        if state.execute("SELECT 1 FROM seen WHERE key=?", (key,)).fetchone():
            continue
        out.append({
            "key": key,
            "id": r["id"],
            "chat": names.get(r["chat_jid"], r["chat_jid"]),
            "from": "FROM_ME" if r["is_from_me"] else (names.get(r["sender"]) or r["sender"]),
            "time": str(r["timestamp"])[:16],
            "text": r["content"][:2000],
        })
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- model

def ask_claude(env, prompt):
    body = json.dumps({
        "model": env.get("CLAUDE_MODEL", "claude-haiku-5-5"),
        "max_tokens": 4000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"x-api-key": env["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    text = "".join(b.get("text", "") for b in data.get("content", []))
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])["ops"]


# ---------------------------------------------------------------- tasks

def open_tasks(state, account=None):
    q = "SELECT id, account, text, due, chat FROM tasks WHERE status='open'"
    args = []
    if account:
        q += " AND account=?"
        args.append(account)
    return state.execute(q, args).fetchall()


def apply_ops(state, account, ops, now):
    """Apply model ops inside the caller's transaction; returns change lines."""
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    lines = []
    for op in ops if isinstance(ops, list) else []:
        kind = op.get("op") if isinstance(op, dict) else None
        if kind == "add" and op.get("text"):
            row = state.execute("SELECT v FROM meta WHERE k='next_id'").fetchone()
            n = int(row[0]) + 1 if row else 1
            state.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('next_id', ?)", (str(n),))
            tid = "t%d" % n
            state.execute("INSERT INTO tasks (id, account, text, due, chat, sources, status, updated) "
                          "VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
                          (tid, account, op["text"], op.get("due"), op.get("chat", ""),
                           json.dumps(op.get("source_ids", [])), today))
            lines.append("[%s] NEW  %s: %s" % (account, tid, op["text"]))
        elif kind in ("update", "done", "cancel"):
            tid = op.get("task_id")
            row = state.execute("SELECT text, due FROM tasks WHERE id=? AND account=? AND status='open'",
                                (tid, account)).fetchone()
            if not row:
                continue
            if kind == "update":
                text, due = op.get("text") or row[0], op.get("due", row[1])
                state.execute("UPDATE tasks SET text=?, due=?, updated=? WHERE id=?", (text, due, today, tid))
                lines.append("[%s] EDIT %s: %s" % (account, tid, text))
            else:
                state.execute("UPDATE tasks SET status=?, updated=? WHERE id=?", (kind, today, tid))
                lines.append("[%s] %s %s: %s (%s)" % (account, "DONE" if kind == "done" else "DROP",
                                                      tid, row[0], op.get("reason", "")))
    for line in lines:
        state.execute("INSERT INTO changes (created, line) VALUES (?, ?)", (int(now), line))
    return lines


def process_account(state, acct, me_names, lookback_days, ask, now):
    msgs = fetch_unseen(acct["messages_db"], acct["name"], acct.get("chats", []), lookback_days, state)
    if not msgs:
        return 0
    tasks = {r[0]: {"text": r[2], "due": r[3], "chat": r[4]} for r in open_tasks(state, acct["name"])}
    prompt = PROMPT.format(me_names=", ".join(me_names),
                           open_tasks=json.dumps(tasks, ensure_ascii=False),
                           messages=json.dumps([{k: v for k, v in m.items() if k != "key"} for m in msgs],
                                               ensure_ascii=False))
    ops = ask(prompt)  # outside the transaction; a failure here changes nothing
    with transaction(state):
        state.executemany("INSERT OR IGNORE INTO seen (key, seen_at) VALUES (?, ?)",
                          [(m["key"], int(now)) for m in msgs])
        apply_ops(state, acct["name"], ops, now)
    return len(msgs)


# ---------------------------------------------------------------- delivery

def build_digest(state, now):
    pending = state.execute("SELECT seq, line FROM changes WHERE delivered=0 ORDER BY seq").fetchall()
    tasks = sorted(open_tasks(state), key=lambda r: (r[3] or "9999", int(r[0][1:])))
    open_lines = ["- [%s] %s%s (%s, %s)" % (r[1], r[2], " — due %s" % r[3] if r[3] else "", r[4], r[0])
                  for r in tasks]
    body = ("Changes since last digest:\n" + ("\n".join(l for _, l in pending) or "(none)") +
            "\n\nOpen tasks:\n" + ("\n".join(open_lines) or "(none)") + "\n")
    subject = "WhatsApp to-dos %s (%d open)" % (time.strftime("%a %d %b", time.localtime(now)), len(tasks))
    return [seq for seq, _ in pending], subject, body


def smtp_send(env, subject, body, on_accepted):
    """Send; call on_accepted as soon as the server has accepted the message
    (before QUIT), so a failure while closing can't cause a duplicate."""
    msg = EmailMessage()
    msg["From"] = env["SMTP_USER"]
    msg["To"] = env["MAIL_TO"]
    msg["Subject"] = subject
    msg.set_content(body)
    s = smtplib.SMTP(env.get("SMTP_HOST", "smtp.gmail.com"), int(env.get("SMTP_PORT", "587")), timeout=60)
    try:
        s.starttls()
        s.login(env["SMTP_USER"], env["SMTP_PASS"])
        refused = s.send_message(msg)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
        on_accepted()
    finally:
        with contextlib.suppress(Exception):
            s.quit()


WA_PART_LIMIT = 3500  # characters per WhatsApp note; the server accepts up to 4096


def split_message(text, limit=WA_PART_LIMIT):
    """Split on line boundaries into parts of at most limit characters."""
    parts, cur = [], ""
    for line in text.splitlines(keepends=True):
        while len(line) > limit:  # a single over-long line
            if cur:
                parts.append(cur)
                cur = ""
            parts.append(line[:limit])
            line = line[limit:]
        if len(cur) + len(line) > limit:
            parts.append(cur)
            cur = ""
        cur += line
    if cur.strip():
        parts.append(cur)
    return [p.rstrip("\n") for p in parts] or [""]


def whatsapp_send(admin_addr, token, subject, body, on_accepted, timeout=60):
    """Deliver to your own "Message yourself" chat through the account's
    loopback /self-note endpoint. on_accepted runs only after every part was
    sent. If a later part fails, the next run resends the whole digest, so a
    part can arrive twice; nothing is lost."""
    parts = split_message("%s\n\n%s" % (subject, body))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for i, part in enumerate(parts, 1):
        text = ("(%d/%d) " % (i, len(parts)) if len(parts) > 1 else "") + part
        req = urllib.request.Request("http://%s/self-note" % admin_addr, data=text.encode(), method="POST",
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "text/plain; charset=utf-8"})
        with opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise RuntimeError("self-note returned %d" % resp.status)
    on_accepted()


def make_sender(cfg, env, conf_dir="/etc/whatsapp-mcp"):
    """Returns (send, problem). send is None when delivery isn't configured."""
    if cfg.get("deliver", "email") == "whatsapp":
        acct = cfg.get("whatsapp_account", "personal")
        try:
            acct_env = load_env(os.path.join(conf_dir, acct + ".env"))
        except FileNotFoundError:
            return None, "no %s.env" % acct
        addr, token = acct_env.get("ADMIN_ADDR"), acct_env.get("WHATSAPP_SELF_NOTE_TOKEN")
        if not addr or not token:
            return None, "%s.env has no ADMIN_ADDR or WHATSAPP_SELF_NOTE_TOKEN" % acct
        return (lambda subj, body, ok: whatsapp_send(addr, token, subj, body, ok)), None
    if not mail_configured(env):
        return None, "mail.env not configured"
    return (lambda subj, body, ok: smtp_send(env, subj, body, ok)), None


def deliver(state, send, now, send_empty=True):
    seqs, subject, body = build_digest(state, now)
    if not seqs and not send_empty:
        return False

    def mark():
        with transaction(state):
            state.executemany("UPDATE changes SET delivered=1 WHERE seq=?", [(s,) for s in seqs])

    send(subject, body, mark)
    return True


def prune(state, lookback_days, now):
    with transaction(state):
        state.execute("DELETE FROM seen WHERE seen_at < ?", (int(now) - (lookback_days + 7) * 86400,))
        state.execute("DELETE FROM changes WHERE delivered=1 AND created < ?", (int(now) - 30 * 86400,))


# ---------------------------------------------------------------- main

def run(cfg, env, ask, send, now=None):
    """One run. Returns a process exit code."""
    now = now or time.time()
    lookback = int(cfg.get("lookback_days", DEFAULT_LOOKBACK_DAYS))
    state = open_state(cfg.get("state", "/var/lib/wa-todo/state.db"))
    code = 0
    try:
        for acct in cfg["accounts"]:
            try:
                process_account(state, acct, cfg["me_names"], lookback, ask, now)
            except Exception as e:  # keep going with the other accounts
                print("account %s: %s" % (acct["name"], e), file=sys.stderr)
                code = 1
        try:
            deliver(state, send, now, cfg.get("send_empty", True))
        except Exception as e:
            print("delivery failed, will retry next run: %s" % e, file=sys.stderr)
            code = 1
        prune(state, lookback, now)
    finally:
        state.close()
    return code


def main():
    with open(CONFIG) as f:
        cfg = json.load(f)
    env = load_env(cfg.get("mail_env", "/etc/whatsapp-mcp/mail.env"))
    send, problem = make_sender(cfg, env, cfg.get("conf_dir", "/etc/whatsapp-mcp"))
    if send is None or env.get("ANTHROPIC_API_KEY", "") in PLACEHOLDERS:
        print("wa_todo: not configured yet (%s); skipping" % (problem or "ANTHROPIC_API_KEY missing"), file=sys.stderr)
        return 0
    state_path = cfg.get("state", "/var/lib/wa-todo/state.db")
    with open(state_path + ".lock", "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("wa_todo: another run is in progress", file=sys.stderr)
            return 0
        return run(cfg, env, lambda p: ask_claude(env, p), send)


if __name__ == "__main__":
    sys.exit(main())

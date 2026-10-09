# WhatsApp MCP runbook (Android + Termius)

Everything below is typed in Termius as `root` on the VPS unless it says
"phone browser". `<domain>` is your Cloudflare domain, `<COMMIT>` the full
40-character commit SHA you are deploying, `<you>` your GitHub user.

## 0. One-time accounts (phone browser)

1. Termius: Keychain > Generate key (Ed25519); copy the public key.
2. Hetzner Cloud: create the smallest x86 server, Ubuntu 24.04, EU location,
   with that SSH key. Note its IP.
3. Cloudflare: register `<domain>`; open Zero Trust (Free plan).
4. claude.ai > Customize > Connectors: confirm "Add custom connector" exists.

## 1. Install (no WhatsApp yet)

```bash
ssh root@<VPS-IP>
curl -fsSLO https://raw.githubusercontent.com/<you>/mcp-whatsapp/<COMMIT>/deploy/setup.sh
bash setup.sh https://github.com/<you>/mcp-whatsapp.git <COMMIT> personal second
```

The script stops before installing anything if a test fails; send the output.
Services start unpaired, which is expected.

## 2. Tunnel and Access

```bash
cloudflared tunnel login        # open the printed URL on the phone, pick <domain>
cloudflared tunnel create wa
for h in mcp-personal approve-personal mcp-second approve-second; do
  cloudflared tunnel route dns wa "$h.<domain>"
done
install -d -m700 /etc/cloudflared
mv ~/.cloudflared/*.json /etc/cloudflared/
cp /var/lib/wabuild/src/deploy/cloudflared-config.example.yml /etc/cloudflared/config.yml
nano /etc/cloudflared/config.yml   # tunnel UUID (ls /etc/cloudflared), <domain>; keep the httpHostHeader lines
cloudflared service install
```

Zero Trust dashboard (phone browser):

| Application | Hostnames | Policy | Advanced settings |
| --- | --- | --- | --- |
| WhatsApp MCP | `mcp-personal.<domain>`, `mcp-second.<domain>` | Allow: your e-mail | **Managed OAuth: on** |
| WhatsApp approvals | `approve-personal.<domain>`, `approve-second.<domain>` | Allow: your e-mail | Managed OAuth: off |

Copy each application's **AUD tag** and your team domain into every
`/etc/whatsapp-mcp/<account>.json`: `mcp_aud`, `approve_aud`, `team_domain`,
`allowed_emails`, `public_url`. Then `systemctl restart whatsapp-mcp@personal`.

## 3. Gate: Claude mobile reaches the unpaired server

claude.ai (phone browser) > Customize > Connectors > Add custom connector:
URL `https://mcp-personal.<domain>/mcp`, sign in with the e-mail code.
In the Claude app ask "what is my WhatsApp status?".

- Pass: Claude reports "not paired" via `get_status`.
- 403 in `journalctl -u whatsapp-mcp@personal`: Access did not forward a JWT
  the server accepts. Check `mcp_aud` and `team_domain`. Do not remove the
  check; see "request-header fallback" below.
- Sign-in never completes: Managed OAuth is off or the hostname is wrong.

## 4. Pair (same phone)

```bash
systemctl stop whatsapp-mcp@personal
sudo -u wa-personal whatsapp-mcp -store /var/lib/wa-personal pair-code 9725XXXXXXXX
#   WhatsApp > Linked devices > Link a device > Link with phone number instead
systemctl start whatsapp-mcp@personal
curl -s 127.0.0.1:8865/healthz       # "ok" once connected
```

Add recipients to `/etc/whatsapp-mcp/personal.json` (ask Claude to
`list_groups` for group JIDs), then restart the service. Repeat for `second`
(admin port 8866).

## 5. Mail, digest, heartbeat

```bash
nano /etc/whatsapp-mcp/mail.env     # API key, Gmail + app password, HEARTBEAT_URL (optional)
nano /etc/whatsapp-mcp/todo.json    # your names; chat JIDs or [] for all
python3 /opt/wa-tools/wa_todo.py    # sends a digest now; cron: daily 07:00
python3 /opt/wa-tools/wa_health.py  # silent when healthy; cron: every 5 min
```

## Updates and rollback

```bash
bash /var/lib/wabuild/src/deploy/setup.sh https://github.com/<you>/mcp-whatsapp.git <NEW-COMMIT> personal second
```

Tests run first; on failure nothing changes. If a running service fails to
come back, the previous binary is restored automatically. Manual rollback:
`mv /usr/local/bin/whatsapp-mcp.prev /usr/local/bin/whatsapp-mcp` and restart.

## Re-pairing

```bash
systemctl stop whatsapp-mcp@personal
mkdir -p /var/lib/wa-personal/old && mv /var/lib/wa-personal/whatsapp.db* /var/lib/wa-personal/old/
sudo -u wa-personal whatsapp-mcp -store /var/lib/wa-personal pair-code 9725XXXXXXXX
systemctl start whatsapp-mcp@personal
```

## Revoking access fast

- WhatsApp > Linked devices: log out the VPS device (kills the session).
- Zero Trust: disable either Access application (cuts Claude or approvals off).
- `systemctl stop whatsapp-mcp@personal`.

## Backups (optional)

On the phone, generate an age key pair (for example with an age app) and
keep the private key there. On the VPS:

```bash
bash /opt/wa-tools/backup.sh age1...public-key
```

It writes `/var/backups/wa/wa-*.tar.age` with consistent snapshots of
`messages.db` and the digest state. It never includes `whatsapp.db` (the
session) or `approvals.db`. Copy the files off with Termius SFTP.

## Request-header fallback (only if Managed OAuth fails at step 3)

If claude.ai shows "Request headers" when adding a connector: generate a
token (`openssl rand -hex 32`), add `WHATSAPP_MCP_TOKEN=<token>` to
`/etc/whatsapp-mcp/<account>.env`, set `"mcp_aud": ""` in the policy, remove
the "WhatsApp MCP" Access app for that hostname, add a Cloudflare WAF rule
allowing it only from 160.79.104.0/21, and add the connector with No sign-in
and header `authorization: Bearer <token>`. The approvals app stays as is.

## Notes

- Files: the unit sets `UMask=0077` and each store is `0700`, so SQLite's
  `-wal`/`-shm` files are private too. Don't run the service outside systemd
  on the VPS.
- Approvals: links expire after `ttl_minutes`; message text is wiped 24 hours
  after a decision; rows are deleted after 7 days.

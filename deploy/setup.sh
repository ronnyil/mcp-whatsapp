#!/usr/bin/env bash
# Provision the WhatsApp MCP box. Run as root on a fresh Ubuntu 24.04 VPS.
# Safe to re-run (it also rebuilds and redeploys after a git pull).
#
#   bash setup.sh https://github.com/YOU/mcp-whatsapp.git personal second
#
# Account names map to ports in order: 1st -> 8765 / admin 8865 / approve 9765,
# 2nd -> 8766 / 8866 / 9766. Keep the order stable.
set -euo pipefail

REPO="${1:?usage: setup.sh <your-fork-git-url> <account> [account...]}"
shift
ACCOUNTS=("$@")
[ ${#ACCOUNTS[@]} -gt 0 ] || ACCOUNTS=(personal)
GO_VERSION=1.26.0
SRC=/opt/mcp-whatsapp

echo "== packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential git sqlite3 curl ufw unattended-upgrades python3
timedatectl set-timezone Asia/Jerusalem

echo "== ssh keys only + firewall (only SSH inbound; the tunnel is outbound)"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd
ufw allow OpenSSH
ufw --force enable

echo "== go $GO_VERSION"
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VERSION "; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH

echo "== cloudflared"
if ! command -v cloudflared >/dev/null; then
  install -d -m755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -q && apt-get install -yq cloudflared
fi

echo "== build"
if [ -d "$SRC/.git" ]; then git -C "$SRC" pull --ff-only; else git clone "$REPO" "$SRC"; fi
cd "$SRC"
go mod tidy
go vet ./...
go test ./internal/policy/ ./internal/mcp/ ./internal/daemon/
CGO_ENABLED=1 go build -o /usr/local/bin/whatsapp-mcp.new ./cmd/whatsapp-mcp
mv /usr/local/bin/whatsapp-mcp.new /usr/local/bin/whatsapp-mcp

echo "== install units and tools"
install -m644 deploy/whatsapp-mcp@.service /etc/systemd/system/
install -d -m755 /etc/whatsapp-mcp /opt/wa-tools
install -m755 deploy/wa_todo.py deploy/wa_health.py /opt/wa-tools/
install -d -m700 /var/lib/wa-todo
[ -f /etc/whatsapp-mcp/todo.json ] || install -m600 deploy/todo.example.json /etc/whatsapp-mcp/todo.json
[ -f /etc/whatsapp-mcp/mail.env ] || install -m600 deploy/mail.env.example /etc/whatsapp-mcp/mail.env

i=0
for a in "${ACCOUNTS[@]}"; do
  echo "== account $a"
  id -u "wa-$a" >/dev/null 2>&1 || useradd --system --home "/var/lib/wa-$a" --shell /usr/sbin/nologin "wa-$a"
  install -d -m700 -o "wa-$a" -g "wa-$a" "/var/lib/wa-$a"
  envf=/etc/whatsapp-mcp/$a.env
  [ -f "$envf" ] || printf 'MCP_ADDR=127.0.0.1:%d\nADMIN_ADDR=127.0.0.1:%d\nWHATSAPP_MCP_MEDIA_ROOT=/var/lib/wa-%s/uploads\n' \
    $((8765 + i)) $((8865 + i)) "$a" > "$envf"
  pol=/etc/whatsapp-mcp/$a.json
  [ -f "$pol" ] || sed -e "s/127.0.0.1:9765/127.0.0.1:$((9765 + i))/" \
                       -e "s/approve-personal/approve-$a/" \
                       -e "s/\"Personal\"/\"$a\"/" deploy/policy.example.json > "$pol"
  chown "root:wa-$a" "$envf" "$pol"
  chmod 640 "$envf" "$pol"
  i=$((i + 1))
done

cat > /etc/cron.d/whatsapp-mcp <<'EOF'
*/5 * * * * root /usr/bin/python3 /opt/wa-tools/wa_health.py >/dev/null 2>&1
0 7 * * * root /usr/bin/python3 /opt/wa-tools/wa_todo.py >>/var/lib/wa-todo/run.log 2>&1
EOF

systemctl daemon-reload
for a in "${ACCOUNTS[@]}"; do
  if [ -s "/var/lib/wa-$a/whatsapp.db" ]; then systemctl enable --now "whatsapp-mcp@$a"; systemctl restart "whatsapp-mcp@$a"; fi
done

cat <<EOF

Done. Next:
  1. Edit /etc/whatsapp-mcp/<account>.json (recipients, URLs, Access AUD tags).
  2. Pair each account (see the runbook):
       sudo -u wa-<account> whatsapp-mcp -store /var/lib/wa-<account> pair-code 9725XXXXXXXX
       systemctl enable --now whatsapp-mcp@<account>
  3. Fill /etc/whatsapp-mcp/mail.env and todo.json.
EOF

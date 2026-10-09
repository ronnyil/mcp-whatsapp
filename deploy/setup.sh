#!/usr/bin/env bash
# Provision or update the WhatsApp MCP box. Run as root on Ubuntu 24.04.
# Safe to re-run; an update is the same command with a new commit.
#
#   bash setup.sh <fork-git-url> <commit-sha> <account> [account...]
#   bash setup.sh https://github.com/YOU/mcp-whatsapp.git 3f2a...c9 personal second
#
# What it guarantees:
# - Builds exactly <commit-sha> (40 hex chars), checked after checkout.
# - Go comes from Ubuntu's signed package; it then fetches the 1.26.0 toolchain
#   itself, verified against the Go checksum database. Modules are verified
#   against go.sum and the checksum database; go.mod/go.sum are never changed.
# - Source checkout, tests and build run as the unprivileged user "wabuild".
# - Nothing is installed unless vet, all Go tests, the Python tests and shell
#   syntax checks pass. Running services keep running if anything fails.
# - After a restart, a service that was running before but fails to come back
#   triggers a rollback to the previous binary.
# - The SSH change is validated with "sshd -t" before reload, and skipped if
#   root has no authorized key (so you can't be locked out).
#
# Account order fixes ports: 1st -> MCP 8765 / admin 8865 / approvals 9765,
# 2nd -> 8766 / 8866 / 9766. Keep the order stable.
set -euo pipefail

REPO="${1:?usage: setup.sh <fork-git-url> <commit-sha> <account> [account...]}"
COMMIT="${2:?usage: setup.sh <fork-git-url> <commit-sha> <account> [account...]}"
shift 2
ACCOUNTS=("$@")
[ ${#ACCOUNTS[@]} -gt 0 ] || { echo "name at least one account" >&2; exit 2; }
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "commit must be a full 40-character SHA" >&2; exit 2; }
for a in "${ACCOUNTS[@]}"; do
  [[ "$a" =~ ^[a-z][a-z0-9]{0,15}$ ]] || { echo "bad account name '$a' (lowercase letters/digits)" >&2; exit 2; }
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

GO_TOOLCHAIN=go1.26.0
BUILD_HOME=/var/lib/wabuild
SRC=$BUILD_HOME/src
OUT=$BUILD_HOME/out
BIN=/usr/local/bin/whatsapp-mcp

step() { echo; echo "== $*"; }
as_build() { runuser -u wabuild -- env -i HOME=$BUILD_HOME PATH=/usr/local/bin:/usr/bin:/bin \
  GOTOOLCHAIN=$GO_TOOLCHAIN GOFLAGS=-mod=readonly CGO_ENABLED=1 PYTHONDONTWRITEBYTECODE=1 "$@"; }

step "packages (signed apt repositories)"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -yq \
  build-essential git sqlite3 curl ufw unattended-upgrades python3 golang-go age
timedatectl set-timezone Asia/Jerusalem

step "ssh: keys only (validated before reload)"
if grep -qE '^(ssh-|ecdsa-|sk-)' /root/.ssh/authorized_keys 2>/dev/null; then
  cat > /etc/ssh/sshd_config.d/10-keys-only.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
  if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
  else
    rm -f /etc/ssh/sshd_config.d/10-keys-only.conf
    echo "sshd -t failed; left SSH settings unchanged" >&2
  fi
else
  echo "no key in /root/.ssh/authorized_keys: NOT disabling password login" >&2
fi
ufw allow OpenSSH >/dev/null
ufw --force enable >/dev/null

step "cloudflared (Cloudflare's signed apt repository)"
if ! command -v cloudflared >/dev/null; then
  install -d -m755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -q && apt-get install -yq cloudflared
fi

step "build user and pinned source"
id -u wabuild >/dev/null 2>&1 || useradd --system --create-home --home-dir $BUILD_HOME --shell /usr/sbin/nologin wabuild
if [ ! -d "$SRC/.git" ]; then
  as_build git clone --quiet "$REPO" "$SRC"
fi
as_build git -C "$SRC" fetch --quiet origin
as_build git -C "$SRC" -c advice.detachedHead=false checkout --quiet --detach "$COMMIT"
HEAD=$(as_build git -C "$SRC" rev-parse HEAD)
[ "$HEAD" = "$COMMIT" ] || { echo "checkout is $HEAD, expected $COMMIT" >&2; exit 1; }
[ -z "$(as_build git -C "$SRC" status --porcelain)" ] || { echo "source tree is dirty" >&2; exit 1; }

step "verify: vet, Go tests, Python tests, shell syntax (as wabuild)"
cd "$SRC"
as_build go version
as_build go vet ./...
as_build go test -count=1 ./...
as_build python3 -m unittest discover -s deploy/tests
for f in deploy/*.sh; do bash -n "$f"; done

step "build"
as_build mkdir -p "$OUT"
as_build go build -trimpath -ldflags "-X main.Version=$COMMIT" -o "$OUT/whatsapp-mcp" ./cmd/whatsapp-mcp
"$OUT/whatsapp-mcp" -version | grep -q "$COMMIT" || { echo "built binary does not report $COMMIT" >&2; exit 1; }

step "install"
was_active=()
for a in "${ACCOUNTS[@]}"; do
  systemctl is-active --quiet "whatsapp-mcp@$a" && was_active+=("$a")
done
install -m755 "$OUT/whatsapp-mcp" "$BIN.new"
[ -f "$BIN" ] && cp -p "$BIN" "$BIN.prev"
mv "$BIN.new" "$BIN"

install -m644 deploy/whatsapp-mcp@.service /etc/systemd/system/
install -d -m755 /etc/whatsapp-mcp /opt/wa-tools
install -m755 deploy/wa_todo.py deploy/wa_health.py deploy/backup.sh /opt/wa-tools/
install -d -m700 /var/lib/wa-todo /var/backups/wa
[ -f /etc/whatsapp-mcp/todo.json ] || install -m600 deploy/todo.example.json /etc/whatsapp-mcp/todo.json
[ -f /etc/whatsapp-mcp/mail.env ] || install -m600 deploy/mail.env.example /etc/whatsapp-mcp/mail.env

i=0
for a in "${ACCOUNTS[@]}"; do
  id -u "wa-$a" >/dev/null 2>&1 || useradd --system --home-dir "/var/lib/wa-$a" --shell /usr/sbin/nologin "wa-$a"
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

# The scripts skip themselves until mail.env is filled in.
cat > /etc/cron.d/whatsapp-mcp <<'EOF'
*/5 * * * * root /usr/bin/python3 /opt/wa-tools/wa_health.py >>/var/lib/wa-todo/health.log 2>&1
0 7 * * * root /usr/bin/python3 /opt/wa-tools/wa_todo.py >>/var/lib/wa-todo/run.log 2>&1
EOF

step "restart"
systemctl daemon-reload
failed=()
for a in "${ACCOUNTS[@]}"; do
  systemctl enable --quiet "whatsapp-mcp@$a"
  systemctl restart "whatsapp-mcp@$a" || true
done
sleep 5
for a in "${was_active[@]}"; do
  systemctl is-active --quiet "whatsapp-mcp@$a" || failed+=("$a")
done
if [ ${#failed[@]} -gt 0 ] && [ -f "$BIN.prev" ]; then
  echo "services that were running failed to restart: ${failed[*]}; rolling back the binary" >&2
  mv "$BIN.prev" "$BIN"
  for a in "${ACCOUNTS[@]}"; do systemctl restart "whatsapp-mcp@$a" || true; done
  exit 1
fi
for a in "${ACCOUNTS[@]}"; do
  if systemctl is-active --quiet "whatsapp-mcp@$a"; then echo "whatsapp-mcp@$a: running"
  else echo "whatsapp-mcp@$a: NOT running (check /etc/whatsapp-mcp/$a.json; journalctl -u whatsapp-mcp@$a -n 30)"; fi
done
echo
echo "Deployed $COMMIT."

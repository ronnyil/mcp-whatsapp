#!/usr/bin/env bash
# Optional encrypted backup of message history and extracted tasks.
#
#   bash /opt/wa-tools/backup.sh age1...your-public-key
#
# - Uses SQLite's online backup API (".backup"), which gives a consistent
#   snapshot even while the services are writing (WAL mode).
# - Never includes whatsapp.db: that is the session credential, and re-pairing
#   is the recovery path. Never includes approvals.db (pending message text).
# - Encrypts to an age public key; the private key never touches the VPS.
#   Copy /var/backups/wa/*.age off the box with Termius SFTP.
set -euo pipefail
RECIPIENT="${1:?usage: backup.sh <age-public-key>}"
OUT="${WA_BACKUP_DIR:-/var/backups/wa}"
SRC_ROOT="${WA_DATA_ROOT:-/var/lib}"
umask 077
mkdir -p "$OUT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

n=0
for dir in "$SRC_ROOT"/wa-*/; do
  name=$(basename "$dir")
  for db in messages.db state.db; do
    [ -f "$dir$db" ] || continue
    sqlite3 "$dir$db" ".backup '$tmp/$name-$db'"
    [ "$(sqlite3 "$tmp/$name-$db" 'PRAGMA integrity_check;')" = ok ] || { echo "integrity check failed: $name/$db" >&2; exit 1; }
    n=$((n + 1))
  done
done
[ "$n" -gt 0 ] || { echo "nothing to back up under $SRC_ROOT/wa-*" >&2; exit 1; }
file="$OUT/wa-$(date +%Y%m%d-%H%M%S).tar.age"
tar -C "$tmp" -cf - . | age -r "$RECIPIENT" -o "$file"
echo "wrote $file ($n databases)"
# Keep the newest 14.
find "$OUT" -maxdepth 1 -name 'wa-*.tar.age' -printf '%T@ %p\n' | sort -rn | tail -n +15 | cut -d' ' -f2- | xargs -r rm -f

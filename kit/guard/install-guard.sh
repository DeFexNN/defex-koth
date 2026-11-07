#!/usr/bin/env bash
# install-guard.sh — install the hold kit on a target we already own (root).
#
# usage:
#   install-guard.sh <ip> <king-string> <pubkey-file> [ssh-key]
#
# env: KING_PATH (default /root/king.txt), SUID_STRIP (space-separated list)
# After install it validates with a tamper test: write "tampered" -> run guard
# -> expect exact king bytes + immutable (or the best the OS supports).
set -u
IP="${1:?usage: install-guard.sh <ip> <king> <pubkey-file> [ssh-key]}"
KING="${2:?king string required}"
PUB="${3:?pubkey file required}"
KEY="${4:-$HOME/Projects/KOTH-OPS/keys/id_ed25519}"
HERE="$(cd "$(dirname "$0")" && pwd)"
KP="${KING_PATH:-/root/king.txt}"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o ConnectTimeout=10 root@$IP"

$SSH 'mkdir -p /etc/koth && chmod 700 /etc/koth'
$SSH "printf 'KING=%q\nKING_PATH=%q\nPUBKEY=%q\n' '$KING' '$KP' \"$(cat "$PUB")\" > /etc/koth/guard.conf && chmod 600 /etc/koth/guard.conf"
scp -q -i "$KEY" -o StrictHostKeyChecking=no -o IdentitiesOnly=yes "$HERE/koth-guard.sh" "root@$IP:/usr/local/sbin/koth-guard.sh"
$SSH 'chmod 755 /usr/local/sbin/koth-guard.sh; bash /usr/local/sbin/koth-guard.sh'

# validate (portable: immutability is best-effort)
$SSH "KING_PATH='$KP' bash -s" <<'EOS'
set -e
KP="${KING_PATH:-/root/king.txt}"
orig=$(cat "$KP")
chattr -i "$KP" 2>/dev/null || true
printf tampered > "$KP"
bash /usr/local/sbin/koth-guard.sh
now=$(cat "$KP")
[ "$now" = "$orig" ] && echo "RESTORE_OK ($now)" || { echo "RESTORE_FAIL ($now)"; exit 1; }
if command -v lsattr >/dev/null 2>&1; then
  lsattr "$KP" | grep -q "i" && echo "IMMUTABLE_OK" || echo "IMMUTABLE_UNSUPPORTED (guard loop still active)"
fi
systemctl is-active koth-guard.service 2>/dev/null || echo "service: not running (check init system)"
EOS

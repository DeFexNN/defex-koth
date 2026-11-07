#!/usr/bin/env bash
# quickstart.sh — the first 90 seconds, codified (KotH/CTF, one host).
# usage: quickstart.sh <IP> [outdir] [--no-full] [--no-ffuf]
#
# Does: preflight -> quick bounded scan -> parallel probe of every open port
#       -> immediate artifact triage -> background full TCP scan.
# Prints the next actions (cred matrix, delegation) and leaves raw data in outdir.
set -u
IP="${1:-}"; [ -n "$IP" ] || { echo "usage: quickstart.sh <IP> [outdir] [--no-full]" >&2; exit 2; }
OUT="${2:-$HOME/Projects/KOTH-OPS/state/$IP}"
[ "${2:-}" = "--no-full" ] && OUT="$HOME/Projects/KOTH-OPS/state/$IP"
FULL=1; FFUF=1
for a in "$@"; do
  [ "$a" = "--no-full" ] && FULL=0
  [ "$a" = "--no-ffuf" ] && FFUF=0
done
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"/{loot,recon,logs}
echo "[*] target $IP -> $OUT"
KING=$(cat "$HOME/.codex/koth-user" 2>/dev/null); [ -n "$KING" ] && echo "[*] king string (from ~/.codex/koth-user): $KING"

bash "$HERE/check-env.sh" | sed -n '1,40p'

echo "[*] quick scan (top 2000, 45 s cap)"
nmap -Pn -n --top-ports 2000 -T4 --min-rate 500 --max-retries 1 --host-timeout 45s \
     -oN "$OUT/recon/quick.txt" "$IP" >/dev/null 2>&1 || true
# A scan timeout is NOT an unreachable host: retry with a bounded connect scan.
if ! grep -qE '^[0-9]+/tcp[[:space:]]+open' "$OUT/recon/quick.txt" 2>/dev/null; then
  echo "[!] quick scan returned no ports (timeout/rate-limit, not proof of unreachability)"
  nmap -Pn -n -sT --top-ports 1000 -T4 --max-retries 1 --host-timeout 20s \
       -oN "$OUT/recon/quick.retry.txt" "$IP" >/dev/null 2>&1 || true
  grep -qE '^[0-9]+/tcp[[:space:]]+open' "$OUT/recon/quick.retry.txt" 2>/dev/null && \
    grep -oE '^[0-9]+/tcp' "$OUT/recon/quick.retry.txt" | cut -d/ -f1 | sort -un | \
    sed 's/$/\/tcp open (retry)/' >> "$OUT/recon/quick.txt"
fi
PORTS=$(grep -oE '^[0-9]+/tcp[[:space:]]+open' "$OUT/recon/quick.txt" 2>/dev/null | cut -d/ -f1 | sort -n | paste -sd' ')
# seed probe: cheap TCP checks for common service ports outside the top-2000 set.
# Override with KOTH_SEED_PORTS="22 80 ..." for an unusual target.
SEEDS="${KOTH_SEED_PORTS:-21 22 23 25 53 80 110 111 139 143 443 445 1433 1521 2049 3000 3306 3389 5432 5900 5985 6379 8000 8080 8081 8443 8888 9000 9090 9200 9999 10000 11211 27017}"
: > "$OUT/recon/seed.txt"
for p in $SEEDS; do ( nc -z -w1 "$IP" "$p" 2>/dev/null && echo "$p" >> "$OUT/recon/seed.txt" ) & done; wait
if [ -s "$OUT/recon/seed.txt" ]; then
  PORTS=$(printf '%s\n%s\n' $PORTS $(sort -un "$OUT/recon/seed.txt") | sed '/^$/d' | sort -un | paste -sd' ')
fi
echo "[*] quick open: ${PORTS:-none}"

echo "[*] probing ${PORTS:-0} ports in parallel (HTTP + raw banner)"
: > "$OUT/loot/probe.txt"
for p in $PORTS; do
  ( curl -sS -m 5 -o "$OUT/loot/b$p.bin" -D "$OUT/loot/h$p.txt" \
      -w "$p http %{http_code} %{size_download} %{content_type}\n" \
      "http://$IP:$p/" >> "$OUT/loot/probe.txt" 2>/dev/null ) &
  ( printf '\r\n' | timeout 4 nc "$IP" "$p" 2>/dev/null | head -c 512 \
      > "$OUT/loot/raw$p.bin" ) &
done; wait
sort -u "$OUT/loot/probe.txt" -o "$OUT/loot/probe.txt" 2>/dev/null
cat "$OUT/loot/probe.txt"

echo "[*] immediate artifact triage"
"$HERE/triage.sh" -q --dir "$OUT/loot" | sed 's/^/    /'

# reachability gate: only now may you even think about VPN/scope
REACH=0
ping -c1 -W1 "$IP" >/dev/null 2>&1 && REACH=1
for p in 22 80 443; do nc -z -w1 "$IP" "$p" 2>/dev/null && REACH=1; done
if [ "$REACH" = 0 ]; then
  echo "[!] no ICMP and no TCP on 22/80/443 — VPN is down or target out of scope."
  echo "    STOP: tell the user to start the VPN. Do NOT start/stop VPN yourself; T0 stays the prompt time."
fi

if [ "$FULL" = 1 ]; then
  echo "[*] full TCP scan in background -> $OUT/recon/full.txt"
  nohup nmap -Pn -n -p- --min-rate "${KOTH_MINRATE:-1500}" -T3 --max-retries 1 \
        --host-timeout 240s -oN "$OUT/recon/full.txt" "$IP" \
        >"$OUT/logs/nmap-full.log" 2>&1 &
  echo "    pid $! (do NOT wait on it)"
fi

cat <<EOF

[*] next (in this order):
    1. cred-first matrix, <=3 attempts/service:
         mysql --connect-timeout=4 -h $IP -u root -proot -Nse 'select 1'
         python3 $HERE/sshp.py $IP <user> <password> --check
         python3 $HERE/telnet_probe.py $IP <port> [--user u --pass p]
    2. read anything triage printed above BEFORE deeper web work.
    3. delegate orthogonal fronts only; never re-run recon.
    4. after any foothold: id; sudo -n -l; find / -perm -4000 -type f; getcap -r /
EOF

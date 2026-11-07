# KotH kit — ready-made tools and rules

Built from a 2026 KotH postmortem; everything here
exists so a mistake is not repeated twice.

## Files

| File | Purpose |
|---|---|
| `quickstart.sh` | The first 90 seconds in one command: preflight → quick scan → parallel probes → triage → background full scan. |
| `triage.sh` | Immediate artifact triage: binwalk, exiftool, strings, steghide, appended gzip/zip/tar carving. **Run on every file that lands on disk.** |
| `sshp.py` | Non-interactive SSH runner via paramiko (no `sshpass` needed), supports password/key, `--check`, `--upload`, `--download`. |
| `telnet_probe.py` | IAC-aware telnet client (answers WILL/DO so the prompt becomes readable), optional login and command. |
| `NMAP-PROFILES.md` | Bounded nmap profiles; why aggressive rates produce a fatal false negative. |
| `VECTOR-LADDER.md` | Universal order of work: fingerprint → artifacts → creds → app → local root → hold. Works for any box/OS. |
| `delegate/mission.py` | Generates the A–H relay brief: one decision, one artifact, deadline, exclusive ports, board protocol, JSON result. |
| `delegate/board.py` | Shared BOARD.md + per-front INBOX.md: claim (deconfliction), log, questions, polling, metrics. |
| `delegate/swarm.py` | Plans/launches 4–5 exclusive codex lanes (extractor/web/identity/privesc/verifier) with inputs, deadlines and artifact contracts. |
| `check-env.sh` | One-shot preflight (binaries, python modules, wordlists). |
| `guard/koth-guard.sh` | Target-side hold loop: king.txt exact+immutable, root key, strip SUID escalators, self-reinstall. |
| `guard/install-guard.sh` | Installs + tamper-tests the guard over SSH. |
| `pk/` | Locally built PwnKit (CVE-2021-4034) launcher + source. |

## The five invariants (learned the hard way)

1. **Artifact-first.** A file on disk is triaged immediately and in parallel
   with scans. `binwalk` on an image is 6 ms; waiting 150 s cost 40 % of a run.
2. **Scans never block.** Quick scan first (`--top-ports 2000`, 25 s cap), full
   scan in background, service scan bounded (`--version-light`, 90 s cap).
3. **Cred-first.** After port discovery, run the cheap credential matrix
   (≤3 attempts/service) before deep web work.
4. **Consume the team.** Poll the shared workspace every 30–60 s
   (`find <state> -newermt '-2 minutes'`); a teammate's artifact is faster
   than your duplicate work.
5. **First 60 s after root.** king.txt → `chattr +i` → `lsattr` verify →
   5 s guard loop → tamper test. A guard installed later is a rental.

## First 90 seconds

```sh
koth quickstart <IP>          # codified runbook, no thinking required
```
or manually (port list is generic — quickstart derives it from the scan):

```sh
IP=<IP>; S=~/Projects/KOTH-OPS/state/$IP; mkdir -p $S/{loot,recon,logs}
bash ~/Projects/KOTH-OPS/kit/check-env.sh
nmap -Pn -n --top-ports 2000 -T4 --max-retries 1 --host-timeout 25s -oN $S/recon/quick.txt $IP
for p in $(grep -oE '^[0-9]+/tcp' $S/recon/quick.txt | cut -d/ -f1); do
  (curl -sS -m 5 -o $S/loot/b$p.bin -D $S/loot/h$p.txt http://$IP:$p/ 2>/dev/null) &
done; wait
~/Projects/KOTH-OPS/kit/triage.sh -q --dir $S/loot
nohup nmap -Pn -n -p- --min-rate 1500 -T3 --max-retries 1 --host-timeout 240s -oN $S/recon/full.txt $IP >/dev/null 2>&1 &
```

Tunables (all optional, no box-specific defaults):
`KOTH_MINRATE` (full-scan rate), `KOTH_SEED_PORTS` (extra TCP probes),
`KOTH_HTTP_SEED` (HTTP seed ports), `KOTH_WEB_WORDLIST`, `KOTH_KIT`,
`KING_PATH`/`SUID_STRIP` (guard).

## Delegation contract (paste into every relay prompt)

- Scope: only `<IP>`; never reset; keep services alive; never write `/root/king.txt`.
- **Do not run `koth kickoff` / `recon` again — ports are known: `<list>`.** Duplicate recon is banned.
- Write artifacts to `<state>/<front>/` and name the exact paths in your report.
- Download a service artifact **once**, then work on the local copy (no parallel streams).
- Credential attempts: max 3 per service (SSH/DB/telnet), then stop and report.
- Read-only unless explicitly told otherwise; no writes to databases.
- End with: findings, evidence table, commands actually run, uncertainties, JSON.

## SLOs

| Gate | Target |
|---|---|
| quick scan | ≤15 s |
| first artifact triage | ≤30 s |
| first cred/foothold | ≤60 s |
| root | ≤120 s |
| king + immutable + 5 s guard | ≤60 s after root |
| full flag set | ≤3 min after root |

## Fast root (T0)

- `FASTROOT.md` — the T0 plan: lanes at T0, pre-staged exploit, credential-first.
- `koth-fastroot.sh <IP> [--spawn relay|cli|none] [--dry-run]` — quick scan +
  board init + exploit staging + `swarm.py plan` (LANE-1..5) + relay calls.
- `exploits/` — prebuilt `PwnKit` (CVE-2021-4034) + `deploy.sh` (scp + run, no
  compile on target) + `build.sh`. Add static binaries here.

```sh
bash kit/koth-fastroot.sh <IP> --spawn relay     # prints relay calls
bash kit/exploits/deploy.sh <IP> <key> <user> kit/exploits/PwnKit 'id'
```

## Legacy files (kept, not part of the generic kit)

- `hillboot.sh` — per-engagement re-arm script from a previous box (10.10.163.46).
  Host-specific paths (`/home/serv3/...`) and enemy-supervisor handling; do not
  reuse blindly.
- `pwnkit.c` / `pwnkit.so` — earlier PwnKit build; `pk/PwnKit` + `pk/build.sh`
  is the current self-contained copy.

## E2E check

```sh
koth quickstart 127.0.0.1 /tmp/opencode/qs-test --no-full   # smoke test, no target traffic
koth triage <image-or-blob>                                 # expect [HIT] lines on real artifacts
```

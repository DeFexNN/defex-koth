# Universal vector ladder (any box, any OS)

The point is **order**, not a checklist of this week's machine. Stop at the first
rung that works; each rung has a time budget.

## 0. Fingerprint before touching anything
```sh
nmap -Pn -n --top-ports 2000 -T4 --max-retries 1 --host-timeout 25s TARGET
curl -sS -m5 -D- -o- http://TARGET:PORT/ | head -40     # headers, tech, title
nc -w3 TARGET PORT | head -c 400                          # raw banner
mysql --connect-timeout=4 -h TARGET -u x 2>&1 | head -2   # handshake version
nmap -Pn -sV --version-light --host-timeout 90s -p <open> TARGET
```
Decide: OS family, service class, and whether the box is Linux/Windows/embedded.
Never assume `/root`, `sudo`, or `bash`.

## 1. Artifacts before exploits (fastest wins)
- Any image/archive/blob → `kit/triage.sh` (stego, appended archives, embedded creds, metadata).
- Any exposed file (FTP/web/DB dump) → read it: creds, keys, configs, version pins.
- Anonymous/empty logins: FTP, SMB, Redis, Mongo, Memcached, Elasticsearch, Docker API.

## 2. Credentials before vulns
- Reuse every credential found anywhere (app → SSH → DB → service) — one image, many doors.
- Bounded matrix per service: empty, `root:root`, service-name-as-password, common lab creds. **≤3 attempts**, then stop.
- Keys > passwords: try keys before cracking; `ssh -i key` tells you if the key is authorized.

## 3. Application-level (web/db/service)
- Exact version → known CVE only if version is verified on the host.
- Unauthenticated state-changing endpoints, upload filters, path traversal, LFI/RFI, template injection.
- DB: enumerate schemas/tables for credentials and flags; do not write.

## 4. Local → root ladder (Linux/Unix)
1. `id; sudo -n -l` (and chained `sudo -u X sudo -l`).
2. `find / -perm -4000 -type f` + `getcap -r /` → GTFObins for each.
3. Cron/systemd timers and writable root-owned scripts/configs.
4. Writable service files, PATH/ld.so.preload/LD_LIBRARY_PATH, library dirs.
5. Group memberships (docker/lxd/disk/adm), mounted secrets, readable histories.
6. Credentials in configs/DB → reuse as root or another user.
7. Kernel/OS exploit — last resort; verify build and do not crash the box.
Windows equivalent: `whoami /priv`, unquoted service paths, weak ACLs, AlwaysInstallElevated, saved creds.

## 5. Hold (KotH)
- Write the king file from the checker's convention, exact bytes.
- Immutable if supported (`chattr +i`), verify (`lsattr`); otherwise rely on the 5 s guard loop.
- `kit/guard/` (5 s loop + cron) → tamper test → root key → close entry vector and SUID/sudo escalators.
- Keep every scored service alive; never reset.

## Anti-patterns (each has cost a real run)
- Waiting on a blocking scan while an artifact sits untriaged.
- Re-running recon another agent already did.
- Guessing 50 passwords instead of reading one config.
- Assuming the write-up's ports/paths apply to this instance.
- Celebrating root before the guard and the king file are actually in place.

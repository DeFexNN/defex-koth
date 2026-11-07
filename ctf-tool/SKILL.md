# CTF-Tool — Skill for AI agents (codex / opencode / agy / any shell agent)

This repo folder `ctf-tool/` lets you view TryHackMe tasks and submit flags
WITHOUT a browser. The user joins the room in their browser once, you work via CLI.

## 0. Platform routing — read this first

The URL host decides the platform. A `thm:` / `htb:` prefix is only a hint and
must agree with the host; a mismatch is rejected (exit 4), never guessed.

| Prompt starts with / contains | Platform | Command |
|---|---|---|
| `tryhackme.com` URL, `thm:` prefix, or bare room slug | TryHackMe (default) | `ctf.py show ... --only-unsolved --json` → `task` → `download --task N` → `submit` (flow below) |
| `hackthebox.com` URL or `htb:` prefix (no THM host) | HackTheBox | `ctf.py show htb:<url> --json` → `ctf.py htb machines\|challenges --json` → `ctf.py htb submit --id N --flag ... --json` (needs `HTB_API_TOKEN`) |
| prefix contradicts the URL host (e.g. `htb:` + tryhackme URL) | conflict | exit 4 `platform prefix conflicts with URL host` — ask the user / use the URL's host |
| anything else (paths, IPs, files, questions) | neither | DO NOT call htb/thm tools at all. Use local tooling (koth playbook, web/re/pwn). The CLI itself refuses: exit 4 `not a platform room URL`. |

Rules: never submit a THM answer through `htb submit` and never an HTB flag
through THM `submit` (the CLI blocks this, exit 4). Never brute-force:
max ~3 tries per question.

## 0a. Auth (do once, then reuse)

Session lives in `~/.config/ctf-tool/config.json` as `connect_sid`.
On the user's own machine prefer auto-extract (no need to ask the user):

```bash
python3 ctf-tool/ctf.py auth --from-chrome --json   # linux local chrome only
```

If that fails, ask the user for ONE of:

- `connect.sid` cookie value for tryhackme.com (DevTools → Application → Cookies), or
- a `cookies.txt` export (extension "Get cookies.txt LOCALLY")

Then run ONE of:

```bash
python3 ctf-tool/ctf.py auth --sid "<connect.sid>" --json
python3 ctf-tool/ctf.py auth --cookies /path/to/cookies.txt --json
python3 ctf-tool/ctf.py auth --from-chrome --json   # linux local chrome only
python3 ctf-tool/ctf.py auth --status --json
```

Never print the session cookie. Never commit it.

## 1. Core workflow — user drops a link

User message will be just a link like `https://tryhackme.com/room/ctfcollectionvol1`.
Viewing tasks works even WITHOUT auth (public room structure). You ALWAYS start with:

```bash
python3 ctf-tool/ctf.py show https://tryhackme.com/room/ctfcollectionvol1 --only-unsolved --json
```

That prints: title, tasks, each task's description, questions, hints, solved/open state.
Slug or full URL both work.

One task deep-dive:

```bash
python3 ctf-tool/ctf.py task --room ctfcollectionvol1 --task 2 --json
```

## 2. Files

Tasks with an attachment show `"has_file": true` (and `upload_id`) in `show --json`.
List real filenames, or download by task number / the whole room:

```bash
python3 ctf-tool/ctf.py show ctfcollectionvol1 --files --json
python3 ctf-tool/ctf.py download --room ctfcollectionvol1 --task 3 --json
python3 ctf-tool/ctf.py download --room ctfcollectionvol1 --all --json
```

Files land in `ctf-tool/assets/<room>/`. A direct `--url` still works for odd cases.
Inspect files locally (`strings`, `binwalk`, `exiftool`, `unzip -l`, ...); never
execute unknown binaries on the host — analyze statically or in a disposable VM.
Then submit.

## 3. Results and submission (coordinator only)

Agents do **not** submit. They return a JSON array:

```json
[{"q":4,"flag":"THM{...}","how":"sqlmap time-based dump","owner":"muse","seconds":300}]
```

The coordinator verifies and submits centrally, which avoids duplicate submits,
rate-limit storms and false `submit_ok` claims:

```bash
python3 ctf-tool/ctf.py verify-results --room ctfcollectionvol2 --task 2 \
  --file results.json --json
```

- Proof contract: an item without `how`/`evidence` is `unverified` and is NOT submitted.
- Already-solved `(task,q)` pairs are skipped (`already_solved`).
- `--dry-run` shows what would be submitted; `--delay` spaces submissions (default 20 s).
- Writes `run-report.json` with per-owner counts (`found/correct/wrong/unverified/seconds`).
- Exit 0 only when there is no `wrong`, `error`, `rate_limited` or `unverified`.

Manual single submit is still available for spot checks:

```bash
python3 ctf-tool/ctf.py submit --room ctfcollectionvol1 --task 2 --q 1 --answer "THM{...}" --json
```

`verdict`: `correct`, `wrong`, `already_solved`, `rate_limited`, `error`. Only `wrong`
burns an attempt; `rate_limited` retries with backoff (`--retries`, `--gap`).
Do NOT brute-force: max ~3 tries per question, then report and stop.

## 3a. Claims queue (avoid duplicate work)

```bash
python3 ctf-tool/ctf.py claims take --dir .claims --task 2 --q 4 --owner muse --json
python3 ctf-tool/ctf.py claims list --dir .claims --json
python3 ctf-tool/ctf.py claims drop --dir .claims --task 2 --q 4 --owner muse --json
```

`take` is atomic (`O_EXCL`); a second agent gets `ok:false` and should pick another
open question. Release the claim after the result is reported.

## 4. HTB (optional)

```bash
export HTB_API_TOKEN=...
python3 ctf-tool/ctf.py htb machines --json
python3 ctf-tool/ctf.py htb submit --id <machine_id> --flag "<flag>" --json
```

## 5. MCP alternative

If the host supports MCP stdio: `python3 ctf-tool/mcp_server.py`
tools: `thm_show_room`, `thm_show_task`, `thm_submit`, `thm_download`, `thm_auth_status`.
Same data as CLI `--json`. Prefer CLI when in doubt — it works everywhere.

## Rules for agents

- Always pass `--json`, parse stdout as JSON.
- Exit codes: 0 ok / 1 wrong flag / 2 no auth / 3 network. On 2 → ask user for session.
- Work from repo root or use absolute path to `ctf-tool/ctf.py`.
- Keep answers private: never paste correct flags into docs, only submit them.

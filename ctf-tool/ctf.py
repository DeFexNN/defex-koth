#!/usr/bin/env python3
"""ctf — AI-agent friendly CLI for TryHackMe (+ minimal HackTheBox).

Usage for agents (codex / opencode / any shell-capable agent):
  python3 ctf.py auth --sid "connect.sid value"        # one-time, from browser cookies
  python3 ctf.py auth --cookies cookies.txt            # or netscape cookies.txt import
  python3 ctf.py auth --from-chrome                    # auto-read local Chrome (linux peanuts)
  python3 ctf.py auth status
  python3 ctf.py show https://tryhackme.com/room/ctfcollectionvol1 --json
  python3 ctf.py show ctfcollectionvol1 --only-unsolved --json
  python3 ctf.py task --room ctfcollectionvol1 --task 2 --json
  python3 ctf.py submit --room ctfcollectionvol1 --task 2 --q 1 --answer "THM{...}" --json
  python3 ctf.py download --room ctfcollectionvol1 --task 3 --json
  python3 ctf.py download --room ctfcollectionvol1 --all --json
  python3 ctf.py download --room ctfcollectionvol1 --url "<file-url>" --json
  python3 ctf.py submit-batch --room ctfcollectionvol1 --file results.json --json
  python3 ctf.py join --room ctfcollectionvol1 --json

King of the Hill (wraps the local KOTH-OPS kit; --config is required):
  python3 ctf.py koth discover --config koth.conf --json
  python3 ctf.py koth capture  --config koth.conf --dry-run --json
  python3 ctf.py koth retake   --config koth.conf --timeout 90 --json
  python3 ctf.py koth watch    --config koth.conf --interval 5 --json
  python3 ctf.py koth verify   --config koth.conf --json
  python3 ctf.py koth report   --config koth.conf --out report.md --json

Autonomous KotH (no config needed; state under ~/.local/state/defex-ctf/koth/<ip>/):
  python3 ctf.py koth auto 10.0.0.1 --json
  python3 ctf.py koth koth:10.0.0.1 --json          # shorthand for auto
  python3 ctf.py koth auto koth: 10.0.0.1 --dry-run  # plan only, no network

Every command supports --json (machine readable, for agents) and
human-readable default. Exit code 0 = ok, 2 = auth missing, 3 = request failed.
koth additionally returns 4 for a missing/invalid config and 3 when the kit
script is not installed; otherwise the kit script's own exit code is propagated.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import koth
import thm

OUT_DIR = Path(__file__).parent / "assets"


def emit(obj: dict, as_json: bool):
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print_human(obj)


def print_human(o: dict):
    t = o.get("type", "")
    if t == "room":
        print(f"== {o.get('title')} [{o.get('room')}] via {o.get('source')} ==")
        print(f"tasks: {o.get('total_tasks')}  unsolved: {o.get('unsolved_task_nos')}")
        for task in o.get("tasks", []):
            flag = "✓" if task["solved"] else "○"
            att = " [file]" if task.get("has_file") else ""
            print(f"\n[{flag}] Task {task['task_no']}: {task['title']}{att}")
            if task.get("description"):
                print(f"    {task['description'][:800]}")
            for q in task.get("questions", []):
                qf = "✓" if q["solved"] else "?"
                print(f"    ({qf}) Q{q['q_no']}: {q['question'][:300]}")
                if q.get("hint"):
                    print(f"        hint: {q['hint'][:200]}")
    elif t == "task":
        task = o["task"]
        print(f"== Task {task['task_no']}: {task['title']} ==")
        print(task.get("description", "")[:2000])
        for q in task.get("questions", []):
            print(f"  Q{q['q_no']} [{'solved' if q['solved'] else 'open'}]: {q['question']}")
    elif t.startswith("koth"):
        print(f"== {t} ==")
        for key in ("ok", "pass", "rc", "script", "config", "out", "error"):
            if key in o:
                print(f"{key}: {o[key]}")
        if t == "koth_auto":
            print(f"target: {o.get('target')}  exit: {o.get('exit_code')}  "
                  f"dry_run: {o.get('dry_run')}")
            if o.get("state_dir"):
                print(f"state: {o['state_dir']}")
            recon = o.get("recon") or {}
            if recon.get("open"):
                print("ports: " + ",".join(str(p) for p in recon["open"]))
            plan = o.get("plan") or {}
            if plan:
                print("plan ports: " + ",".join(str(p) for p in plan.get("ports", [])))
                for item in plan.get("footholds", []):
                    print(f"  foothold: {item.get('kind')}  {item.get('detail')}")
                for item in plan.get("steps", []):
                    print(f"  step: {item.get('name')}")
            foothold = o.get("foothold") or {}
            if foothold.get("ok"):
                print(f"foothold: {foothold.get('kind')} "
                      f"({foothold.get('user')}, uid {foothold.get('uid')})")
            elif foothold:
                print("foothold: none")
            for step in o.get("steps") or []:
                state = "skipped" if step.get("skipped") else f"rc={step.get('rc')}"
                print(f"  {step.get('name', ''):<12} {state}")
            if o.get("report"):
                print(f"report: {o['report']}")
            if o.get("next_action"):
                print(f"next: {o['next_action']}")
        if o.get("vectors"):
            for v in o["vectors"]:
                print(f"  {v.get('rank')}. {v.get('vector')}  {v.get('path')}  "
                      f"({v.get('why')}, ~{v.get('est_time_sec')}s)")
        if o.get("stdout"):
            print(o["stdout"], end="" if o["stdout"].endswith("\n") else "\n")
        if o.get("stderr"):
            print(o["stderr"], end="" if o["stderr"].endswith("\n") else "\n", file=sys.stderr)
    else:
        print(json.dumps(o, ensure_ascii=False, indent=2))


def cmd_auth(args) -> int:
    if args.sid:
        sid = args.sid.strip()
        # cookies.txt paste may contain full line; extract value
        if "\t" in sid or "connect.sid" in sid and len(sid) > 200:
            sid = extract_sid_blob(sid)
        thm.save_session({"connect_sid": sid})
        s = thm.make_http(sid)
        ok, info = thm.auth_check(s)
        emit({"type": "auth", "ok": ok, "info": info}, args.json)
        return 0 if ok else 3
    if args.cookies:
        sid = sid_from_netscape(Path(args.cookies))
        if not sid:
            emit({"type": "auth", "ok": False, "error": "connect.sid not found in file"}, args.json)
            return 3
        thm.save_session({"connect_sid": sid})
        s = thm.make_http(sid)
        ok, info = thm.auth_check(s)
        emit({"type": "auth", "ok": ok, "info": info}, args.json)
        return 0 if ok else 3
    if args.from_chrome:
        sid = sid_from_chrome()
        if not sid:
            emit({"type": "auth", "ok": False,
                  "error": "connect.sid not found in Chrome profile; export cookies.txt instead"}, args.json)
            return 3
        thm.save_session({"connect_sid": sid})
        s = thm.make_http(sid)
        ok, info = thm.auth_check(s)
        emit({"type": "auth", "ok": ok, "info": info}, args.json)
        return 0 if ok else 3
    if args.status or True:
        cfg = thm.load_session()
        sid = cfg.get("connect_sid", "")
        if not sid:
            emit({"type": "auth", "ok": False, "error": "no session. Run: ctf.py auth --sid ..."}, args.json)
            return 2
        s = thm.make_http(sid)
        ok, info = thm.auth_check(s)
        emit({"type": "auth", "ok": ok, "info": info}, args.json)
        return 0 if ok else 3


def extract_sid_blob(blob: str) -> str:
    import re
    m = re.search(r"connect\.sid\s+([^\s;]+)", blob)
    if m:
        return m.group(1).strip()
    lines = [l for l in blob.splitlines() if "connect.sid" in l]
    if lines:
        parts = lines[0].split()
        return parts[-1].strip()
    return blob.strip()


def sid_from_netscape(fp: Path) -> str:
    try:
        for line in fp.read_text(errors="ignore").splitlines():
            if "connect.sid" in line:
                parts = line.strip().split("\t")
                return parts[-1].strip()
    except Exception:
        pass
    return ""


def sid_from_chrome(host_filter: str = "tryhackme.com") -> str:
    """Best-effort Linux Chrome cookie read (DPAPI peanuts fallback)."""
    candidates = [Path.home() / ".config" / "google-chrome" / "Default" / "Cookies",
                  Path.home() / ".config" / "google-chrome" / "Default" / "Network" / "Cookies",
                  Path.home() / ".config" / "chromium" / "Default" / "Cookies"]
    for db in candidates:
        if not db.exists():
            continue
        try:
            tmp = tempfile.mktemp(suffix=".db")
            shutil.copy2(db, tmp)
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            cur.execute("SELECT host_key,name,value,encrypted_value FROM cookies WHERE host_key LIKE ?",
                        (f"%{host_filter}%",))
            for host, name, value, enc in cur.fetchall():
                if name == "connect.sid":
                    if value:
                        return value
                    dec = decrypt_chrome_value(enc)
                    if dec:
                        return dec
            con.close()
            try:
                os.unlink(tmp)
            except Exception:
                pass
        except Exception:
            continue
    return ""


def decrypt_chrome_value(blob: bytes) -> str:
    if not blob:
        return ""
    try:
        # Linux: v10/v11 = AES-128-CBC, key=PBKDF1(peanuts), iv=16 spaces
        if blob[:3] in (b"v10", b"v11"):
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            import hashlib as hl
            key = hl.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)
            c = Cipher(algorithms.AES(key), modes.CBC(b" " * 16))
            pt = c.decryptor().update(blob[3:]) + c.decryptor().finalize() if False else None
            d = c.decryptor()
            pt = d.update(blob[3:]) + d.finalize()
            # strip PKCS7
            pad = pt[-1]
            if 1 <= pad <= 16:
                pt = pt[:-pad]
            return pt.decode(errors="ignore")
    except Exception:
        pass
    return ""


def require_sess(optional: bool = False):
    cfg = thm.load_session()
    sid = cfg.get("connect_sid", "")
    if not sid:
        if optional:
            return thm.make_http(""), None  # anonymous: public room structure only
        return None, {"type": "error", "error": "no session",
                      "fix": "python3 ctf.py auth --sid '<connect.sid>'  (copy from browser cookies for tryhackme.com)"}
    return thm.make_http(sid), None


def detect_platform(arg: str) -> str:
    """Resolve the platform. A URL host always wins over a prefix.

    Returns thm | htb | conflict | other.
    A prefix that contradicts the URL host (e.g. `htb:https://tryhackme.com/...`)
    is a conflict, never silently routed to the wrong platform.
    """
    s = arg.strip()
    low = s.lower()
    pref = ""
    if low.startswith("htb:"):
        pref = "htb"
    elif low.startswith("thm:"):
        pref = "thm"
    body = s.split(":", 1)[1] if pref else s
    body_low = body.lower()

    host = ""
    if "tryhackme.com" in body_low:
        host = "thm"
    elif "hackthebox.com" in body_low or "hackthebox.eu" in body_low:
        host = "htb"

    if host:
        return "conflict" if pref and pref != host else host
    if pref:
        return pref
    if re.fullmatch(r"[A-Za-z0-9_-]+", s):
        return "thm"  # bare room slug, backward compatible
    return "other"


def cmd_show(args) -> int:
    platform = detect_platform(args.room)
    if platform == "conflict":
        emit({"type": "error", "error": "platform prefix conflicts with URL host",
              "input": args.room,
              "fix": "TryHackMe: thm:<tryhackme-url> or just the URL. HackTheBox: htb:<hackthebox-url>."},
             args.json)
        return 4
    if platform == "htb":
        import htb as H
        res = H.find(args.room)
        emit({"type": "htb_show", **res,
              "howto": "htb: URL -> ctf.py show htb:<url> (find) -> ctf.py htb machines|challenges -> ctf.py htb submit --id N --flag ... (needs HTB_API_TOKEN). For lab work you also need VPN (.ovpn from HTB) + target IP from the box page."},
             args.json)
        return 0 if res.get("ok") else 2
    if platform == "other":
        emit({"type": "error", "error": "not a platform room URL",
              "input": args.room,
              "guidance": "Do NOT use htb/thm platform tools for this input. Handle it as a local/other task (files, KotH playbook, web/re/pwn tooling)."},
             args.json)
        return 4
    room = thm.parse_room_slug(args.room.split(":", 1)[1] if args.room.lower().startswith("thm:") else args.room)
    sess, err = require_sess(optional=True)
    if err:
        emit(err, args.json)
        return 2
    data, src = thm.fetch_tasks(sess, room)
    if data is None:
        emit({"type": "error", "room": room, "error": src}, args.json)
        return 3
    if args.only_unsolved:
        tasks = [t for t in data["tasks"] if not t["solved"]]
        data = {**data, "tasks": tasks, "type": "room", "filter": "only-unsolved"}
    else:
        data["type"] = "room"
    if args.files:
        data["files"] = thm.list_task_files(sess, room)
    emit(data, args.json)
    return 0


def cmd_task(args) -> int:
    room = thm.parse_room_slug(args.room)
    sess, err = require_sess(optional=True)
    if err:
        emit(err, args.json)
        return 2
    data, src = thm.fetch_tasks(sess, room)
    if data is None:
        emit({"type": "error", "room": room, "error": src}, args.json)
        return 3
    for t in data["tasks"]:
        if int(t["task_no"]) == int(args.task):
            emit({"type": "task", "room": room, "source": src, "task": t}, args.json)
            return 0
    emit({"type": "error", "error": f"task {args.task} not found", "have": [t['task_no'] for t in data["tasks"]]}, args.json)
    return 3


def cmd_submit(args) -> int:
    platform = detect_platform(args.room)
    if platform == "conflict":
        emit({"type": "error", "error": "platform prefix conflicts with URL host",
              "input": args.room,
              "fix": "TryHackMe: thm:<tryhackme-url>. HackTheBox: htb:<hackthebox-url>."},
             args.json)
        return 4
    if platform == "htb":
        emit({"type": "error", "error": "HTB flags go through the htb flow, not thm submit",
              "fix": "python3 ctf.py show htb:<url> --json  ->  python3 ctf.py htb submit --id <machine_id> --flag ... --json"},
             args.json)
        return 4
    room = thm.parse_room_slug(args.room)
    sess, err = require_sess()
    if err:
        emit(err, args.json)
        return 2
    data, _ = thm.fetch_tasks(sess, room)
    for t in (data or {}).get("tasks", []):
        if int(t.get("task_no", -1)) == int(args.task) and t.get("solved"):
            emit({"type": "submit", "room": room, "task": args.task, "q": args.q,
                  "ok": True, "verdict": "already_solved", "attempt": 0}, args.json)
            return 0
    res = thm.submit_with_retry(sess, room, int(args.task), int(args.q), args.answer,
                                retries=args.retries, gap=args.gap)
    ok = res.get("verdict") == "correct"
    emit({"type": "submit", "room": room, "task": args.task, "q": args.q,
          "ok": ok, "verdict": res.get("verdict"), "attempt": res.get("attempt"),
          "response": res.get("response")}, args.json)
    return 0 if ok else 1


def _batch_actions(items: list, solved: set, default_task):
    """Normalize result items into actions; solved is a set of (task, q)."""
    actions = []
    for it in items:
        if not isinstance(it, dict):
            actions.append({"action": "skipped", "error": "item is not an object"})
            continue
        raw_task = it.get("task")
        if raw_task is None:
            raw_task = it.get("task_no")
        if raw_task is None:
            raw_task = default_task
        try:
            n = int(raw_task)
        except (TypeError, ValueError):
            actions.append({"action": "skipped", "error": "no task number in item and no --task"})
            continue
        try:
            q = int(it.get("q") or it.get("question") or it.get("q_no") or 1)
        except (TypeError, ValueError):
            actions.append({"task": n, "action": "skipped", "error": "bad question number"})
            continue
        owner = str(it.get("owner") or it.get("agent") or "")
        ans = str(it.get("flag") or it.get("answer") or "").strip()
        how = str(it.get("how") or it.get("evidence") or "").strip()
        seconds = it.get("seconds") or 0
        if not ans:
            actions.append({"task": n, "q": q, "owner": owner, "action": "skipped",
                            "error": "no flag in input"})
            continue
        if (n, q) in solved:
            actions.append({"task": n, "q": q, "owner": owner, "flag": ans,
                            "seconds": seconds, "action": "already_solved"})
            continue
        actions.append({"task": n, "q": q, "owner": owner, "flag": ans,
                        "how": how, "seconds": seconds, "action": "submit"})
    return actions


def cmd_submit_batch(args) -> int:
    platform = detect_platform(args.room)
    if platform in ("conflict", "htb"):
        emit({"type": "error", "error": "submit-batch is THM-only",
              "input": args.room,
              "fix": "Use a TryHackMe room slug/URL; HTB flags go through the htb flow."}, args.json)
        return 4
    room = thm.parse_room_slug(args.room)
    sess, err = require_sess()
    if err:
        emit(err, args.json)
        return 2
    try:
        items = json.loads(Path(args.file).read_text())
    except Exception as e:
        emit({"type": "error", "error": f"cannot read {args.file}: {e}"}, args.json)
        return 4
    if isinstance(items, dict):
        items = items.get("results") or items.get("tasks") or []
    if not isinstance(items, list):
        emit({"type": "error", "error": "results file must be a JSON array"}, args.json)
        return 4

    data, _ = thm.fetch_tasks(sess, room)
    solved = {(int(t["task_no"]), int(q["q_no"]))
              for t in (data or {}).get("tasks", []) for q in t.get("questions", []) if q.get("solved")}
    out = []
    for a in _batch_actions(items, solved, args.task):
        if a["action"] == "skipped":
            out.append({"task": a.get("task"), "q": a.get("q"), "verdict": "skipped",
                        "error": a.get("error")})
            continue
        if a["action"] == "already_solved":
            out.append({"task": a["task"], "q": a["q"], "owner": a["owner"],
                        "flag": a["flag"], "verdict": "already_solved"})
            continue
        n, q, ans = a["task"], a["q"], a["flag"]
        res = thm.submit_with_retry(sess, room, n, q, ans,
                                    retries=args.retries, gap=args.gap)
        verdict = res.get("verdict")
        out.append({"task": n, "q": q, "owner": a["owner"], "flag": ans, "verdict": verdict,
                    "attempt": res.get("attempt"), "response": res.get("response")})
        if verdict == "correct":
            solved.add((n, q))
        if args.delay > 0:
            time.sleep(args.delay)
    summary = {v: sum(1 for r in out if r.get("verdict") == v)
               for v in ("correct", "wrong", "rate_limited", "error", "skipped", "already_solved")}
    ok = summary["wrong"] == 0 and summary["error"] == 0 and summary["rate_limited"] == 0
    emit({"type": "submit_batch", "room": room, "ok": ok,
          "summary": summary, "results": out}, args.json)
    return 0 if ok else 1


def _claim_key(task, q) -> str:
    return f"t{int(task)}_q{int(q)}" if task is not None else f"q{int(q)}"


def _claims_root(args) -> Path:
    root = Path(args.dir)
    root.mkdir(parents=True, exist_ok=True)
    return root


def cmd_claims(args) -> int:
    root = _claims_root(args)
    action = args.claims_cmd
    if action == "list":
        items = []
        for p in sorted(root.glob("*.claim")):
            try:
                info = json.loads(p.read_text())
            except Exception:
                info = {}
            items.append({"key": p.stem, **info})
        emit({"type": "claims", "dir": str(root), "count": len(items), "claims": items}, args.json)
        return 0
    key = _claim_key(getattr(args, "task", None), args.q)
    path = root / (key + ".claim")
    if action == "take":
        owner = args.owner or os.environ.get("USER", "agent")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            try:
                info = json.loads(path.read_text())
            except Exception:
                info = {}
            emit({"type": "claim", "ok": False, "key": key,
                  "owner": info.get("owner"), "since": info.get("ts")}, args.json)
            return 1
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"owner": owner, "ts": time.time(),
                                "task": getattr(args, "task", None), "q": args.q}))
        emit({"type": "claim", "ok": True, "key": key, "owner": owner, "path": str(path)}, args.json)
        return 0
    # drop
    if not path.exists():
        emit({"type": "claim", "ok": True, "key": key, "released": False}, args.json)
        return 0
    if not args.force:
        try:
            info = json.loads(path.read_text())
        except Exception:
            info = {}
        owner = args.owner or os.environ.get("USER", "agent")
        if info.get("owner") and info.get("owner") != owner:
            emit({"type": "claim", "ok": False, "key": key, "error": "owned by someone else",
                  "owner": info.get("owner")}, args.json)
            return 1
    path.unlink()
    emit({"type": "claim", "ok": True, "key": key, "released": True}, args.json)
    return 0


def cmd_verify_results(args) -> int:
    """Proof-contract verification + centralized submission + telemetry."""
    platform = detect_platform(args.room)
    if platform in ("conflict", "htb"):
        emit({"type": "error", "error": "verify-results is THM-only", "input": args.room}, args.json)
        return 4
    room = thm.parse_room_slug(args.room)
    sess, err = require_sess()
    if err:
        emit(err, args.json)
        return 2
    try:
        items = json.loads(Path(args.file).read_text())
    except Exception as e:
        emit({"type": "error", "error": f"cannot read {args.file}: {e}"}, args.json)
        return 4
    if isinstance(items, dict):
        items = items.get("results") or items.get("tasks") or []
    if not isinstance(items, list):
        emit({"type": "error", "error": "results file must be a JSON array"}, args.json)
        return 4

    task = int(args.task)
    data, _ = thm.fetch_tasks(sess, room)
    solved = {(int(t["task_no"]), int(q["q_no"]))
              for t in (data or {}).get("tasks", []) for q in t.get("questions", []) if q.get("solved")}

    results = []
    for a in _batch_actions(items, solved, task):
        if a["action"] == "skipped":
            results.append({**a, "verdict": "skipped"})
            continue
        if a["action"] == "already_solved":
            results.append({**a, "verdict": "already_solved"})
            continue
        if args.require_evidence and not a.get("how"):
            results.append({**a, "verdict": "unverified",
                            "error": "proof contract: no how/evidence"})
            continue
        if args.dry_run:
            results.append({**a, "verdict": "would_submit"})
            continue
        res = thm.submit_with_retry(sess, room, a["task"], a["q"], a["flag"],
                                    retries=args.retries, gap=args.gap)
        verdict = res.get("verdict")
        results.append({**a, "verdict": verdict, "attempt": res.get("attempt"),
                        "response": res.get("response")})
        if verdict == "correct":
            solved.add((a["task"], a["q"]))
        if args.delay > 0:
            time.sleep(args.delay)

    owners: dict = {}
    for r in results:
        o = r.get("owner") or "unknown"
        s = owners.setdefault(o, {"found": 0, "correct": 0, "wrong": 0, "already_solved": 0,
                                  "unverified": 0, "skipped": 0, "rate_limited": 0,
                                  "error": 0, "seconds": 0.0})
        s["found"] += 1
        v = r.get("verdict")
        if v in s:
            s[v] += 1
        try:
            s["seconds"] += float(r.get("seconds") or 0)
        except (TypeError, ValueError):
            pass
    summary = {v: sum(1 for r in results if r.get("verdict") == v)
               for v in ("correct", "wrong", "already_solved", "unverified", "skipped",
                         "rate_limited", "error", "would_submit")}
    report = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "room": room, "task": task, "summary": summary,
              "owners": owners, "results": results}
    report_path = Path(args.report) if args.report else Path(args.file).with_name("run-report.json")
    try:
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    except Exception:
        pass
    ok = summary["wrong"] == 0 and summary["error"] == 0 and summary["rate_limited"] == 0 \
        and summary["unverified"] == 0
    emit({"type": "verify_results", "ok": ok, "report_path": str(report_path), **report}, args.json)
    return 0 if ok else 1


def cmd_download(args) -> int:
    if not args.all and args.task is None and not args.url:
        emit({"type": "download", "ok": False,
              "error": "nothing to download: pass --all, --task N, or --url <file-url>"},
             args.json)
        return 4
    sess, err = require_sess()
    if err:
        emit(err, args.json)
        return 2
    if args.all:
        if not args.room:
            emit({"type": "download", "ok": False, "error": "--all requires --room <slug|url>"},
                 args.json)
            return 4
        room = thm.parse_room_slug(args.room)
        files = thm.list_task_files(sess, room)
        results = []
        for f in files:
            if not f.get("ok"):
                results.append({"task": f["task_no"], "ok": False,
                                "error": f.get("error", "no url")})
                continue
            res = thm.download_task(sess, room, f["task_no"], dest_dir=args.out)
            results.append({"task": f["task_no"], "filename": f.get("filename"), **res})
        ok = all(r.get("ok") for r in results) if results else False
        emit({"type": "download_all", "room": room, "ok": ok,
              "count": len(results), "files": results}, args.json)
        return 0 if ok else 3
    if args.task is not None:
        if not args.room:
            emit({"type": "download", "ok": False, "error": "--task requires --room <slug|url>"},
                 args.json)
            return 4
        room = thm.parse_room_slug(args.room)
        res = thm.download_task(sess, room, int(args.task), dest=args.out)
        emit({"type": "download", "room": room, "task": int(args.task), **res}, args.json)
        return 0 if res.get("ok") else 3
    room = thm.parse_room_slug(args.room) if args.room else "shared"
    dest = Path(args.out) if args.out else (OUT_DIR / room / Path(args.url.split("?")[0]).name)
    if dest.is_dir():
        dest = dest / Path(args.url.split("?")[0]).name
    res = thm.download_file(sess, args.url, dest)
    emit({"type": "download", **res}, args.json)
    return 0 if res.get("ok") else 3


def cmd_join(args) -> int:
    room = thm.parse_room_slug(args.room)
    sess, err = require_sess()
    if err:
        emit(err, args.json)
        return 2
    emit({"type": "join", "room": room, **thm.join_room(sess, room)}, args.json)
    return 0


def cmd_htb(args) -> int:
    import htb as H
    if not H.token():
        emit({"type": "error", "error": "no HTB token",
              "fix": "export HTB_API_TOKEN=... or store htb_token in ~/.config/ctf-tool/config.json"}, args.json)
        return 2
    if args.htb_cmd == "machines":
        emit({"type": "htb_machines", **H.machines()}, args.json)
    elif args.htb_cmd == "challenges":
        emit({"type": "htb_challenges", **H.challenges()}, args.json)
    elif args.htb_cmd == "submit":
        emit({"type": "htb_submit", **H.submit_flag(args.id, args.flag)}, args.json)
    return 0


def cmd_koth(args) -> int:
    """Dispatch a koth subcommand to the local KOTH-OPS kit."""
    action = args.koth_cmd
    if action == "auto":
        return cmd_koth_auto(args)

    cfg = Path(args.config).expanduser()
    if not cfg.is_file():
        emit({"type": "koth_error", "ok": False,
              "error": f"config file not found: {cfg}",
              "fix": "create koth.conf from koth.conf.example and pass --config"},
             args.json)
        return koth.EXIT_USAGE
    # Absolute path: the kit scripts are run without changing the caller's cwd.
    cfg = cfg.resolve()

    if action == "report":
        return cmd_koth_report(args, cfg)

    script_name = koth.SCRIPT_NAMES[action]
    script = koth.find_script(script_name, args.kit_dir or None)
    if script is None:
        searched = [str(p) for p in koth.kit_candidates(args.kit_dir or None)]
        emit({"type": f"koth_{action}", "ok": False,
              "error": f"kit not installed: {script_name} not found",
              "searched": searched,
              "fix": "set CTF_KOTH_KIT / KOTH_KIT_DIR / KOTH_OPS_DIR or pass --kit-dir"},
             args.json)
        return koth.EXIT_ENV

    timeout = koth.subprocess_timeout(action, args)
    res = koth.run_script(script, koth.script_argv(action, cfg, args, script), timeout,
                          env_extra=koth.script_env(action, args))
    payload = {
        "type": f"koth_{action}",
        "ok": res["rc"] == 0,
        "rc": res["rc"],
        "script": str(script),
        "config": str(cfg),
        "cmd": res["cmd"],
        "timeout": timeout,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
    }
    if res.get("timed_out"):
        payload["timed_out"] = True
    if action == "discover":
        payload["vectors"] = koth.parse_discover(res["stdout"])
    elif action == "verify":
        payload["pass"] = res["rc"] == 0
    emit(payload, args.json)
    return res["rc"]


def cmd_koth_auto(args) -> int:
    """Autonomous KotH entrypoint: recon → foothold → capture → verify."""
    rc, payload = koth.run_auto(args)
    emit(payload, getattr(args, "json", False))
    return rc


def cmd_koth_report(args, cfg: Path) -> int:
    try:
        markdown, fields = koth.build_report(cfg)
    except Exception as e:  # noqa: BLE001 - report must fail cleanly
        emit({"type": "koth_report", "ok": False,
              "error": f"cannot build report from {cfg}: {e}"}, args.json)
        return koth.EXIT_ENV
    out = Path(args.out).expanduser()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown)
    except OSError as e:
        emit({"type": "koth_report", "ok": False,
              "error": f"cannot write {out}: {e}"}, args.json)
        return koth.EXIT_ENV
    payload = {"type": "koth_report", "ok": True, "config": str(cfg),
               "out": str(out), "fields": fields}
    if args.json:
        emit(payload, True)
    else:
        print(markdown, end="")
    return 0


def build() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ctf", description="AI-agent CTF tool: TryHackMe + HackTheBox")
    p.add_argument("--json", action="store_true", help="machine-readable JSON (for agents)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("auth", help="login / status")
    a.add_argument("--json", action="store_true")
    a.add_argument("--sid", default="", help="connect.sid cookie value")
    a.add_argument("--cookies", default="", help="netscape cookies.txt path")
    a.add_argument("--from-chrome", action="store_true")
    a.add_argument("--status", action="store_true")
    a.set_defaults(fn=cmd_auth)

    s = sub.add_parser("show", help="show room tasks: THM slug/URL or thm:<url> (HTB: htb:<url>)")
    s.add_argument("--json", action="store_true")
    s.add_argument("room")
    s.add_argument("--only-unsolved", action="store_true")
    s.add_argument("--files", action="store_true", help="resolve attachment filenames per task")
    s.set_defaults(fn=cmd_show)

    t = sub.add_parser("task", help="show one task detail")
    t.add_argument("--json", action="store_true")
    t.add_argument("--room", required=True)
    t.add_argument("--task", required=True)
    t.set_defaults(fn=cmd_task)

    u = sub.add_parser("submit", help="submit flag/answer")
    u.add_argument("--json", action="store_true")
    u.add_argument("--room", required=True)
    u.add_argument("--task", required=True)
    u.add_argument("--q", default="1")
    u.add_argument("--answer", required=True)
    u.add_argument("--retries", type=int, default=3, help="attempts on rate limit/transient errors")
    u.add_argument("--gap", type=float, default=60.0, help="seconds between retries")
    u.set_defaults(fn=cmd_submit)

    ub = sub.add_parser("submit-batch", help="submit many flags from a JSON file, serialized")
    ub.add_argument("--json", action="store_true")
    ub.add_argument("--room", required=True)
    ub.add_argument("--file", required=True,
                    help='JSON array: [{"task":3,"flag":"THM{...}","q":1}]')
    ub.add_argument("--task", type=int, default=None, help="default task number when items omit it")
    ub.add_argument("--retries", type=int, default=3)
    ub.add_argument("--gap", type=float, default=60.0, help="seconds between retries of one flag")
    ub.add_argument("--delay", type=float, default=75.0, help="seconds between different tasks")
    ub.set_defaults(fn=cmd_submit_batch)

    vr = sub.add_parser("verify-results", help="verify agent results and submit open flags centrally")
    vr.add_argument("--json", action="store_true")
    vr.add_argument("--room", required=True)
    vr.add_argument("--task", type=int, required=True)
    vr.add_argument("--file", required=True, help="JSON array from agents: q/flag/how/owner")
    vr.add_argument("--delay", type=float, default=20.0, help="seconds between submissions")
    vr.add_argument("--retries", type=int, default=3)
    vr.add_argument("--gap", type=float, default=45.0)
    vr.add_argument("--dry-run", action="store_true")
    vr.add_argument("--allow-no-evidence", dest="require_evidence", action="store_false",
                    help="do not enforce the proof contract")
    vr.add_argument("--report", default="", help="run-report.json path")
    vr.set_defaults(fn=cmd_verify_results, require_evidence=True)

    cl = sub.add_parser("claims", help="file-based claim queue for (task,q) work items")
    cl.add_argument("--json", action="store_true")
    cl_sub = cl.add_subparsers(dest="claims_cmd", required=True)
    cl_list = cl_sub.add_parser("list", help="list active claims")
    cl_list.add_argument("--dir", required=True)
    cl_list.add_argument("--json", action="store_true")
    cl_list.set_defaults(fn=cmd_claims)
    for name, helptext in (("take", "claim a question"), ("drop", "release a question")):
        c = cl_sub.add_parser(name, help=helptext)
        c.add_argument("--dir", required=True)
        c.add_argument("--q", type=int, required=True)
        c.add_argument("--task", type=int, default=None)
        c.add_argument("--owner", default="")
        c.add_argument("--json", action="store_true")
        if name == "drop":
            c.add_argument("--force", action="store_true")
        c.set_defaults(fn=cmd_claims)

    d = sub.add_parser("download", help="download task attachments (--task/--all) or a file URL (--url)")
    d.add_argument("--json", action="store_true")
    d.add_argument("--url", default="", help="direct file URL (rarely needed)")
    d.add_argument("--task", type=int, default=None, help="task number whose attachment to download")
    d.add_argument("--all", action="store_true", help="download every attachment in the room")
    d.add_argument("--room", default="", help="room slug/URL (required with --task/--all)")
    d.add_argument("--out", default="", help="file or directory (default assets/<room>/)")
    d.set_defaults(fn=cmd_download)

    j = sub.add_parser("join", help="join room")
    j.add_argument("--json", action="store_true")
    j.add_argument("--room", required=True)
    j.set_defaults(fn=cmd_join)

    h = sub.add_parser("htb", help="hackthebox passthrough")
    h.add_argument("--json", action="store_true")
    h.add_argument("htb_cmd", choices=["machines", "challenges", "submit"])
    h.add_argument("--id", type=int, default=0)
    h.add_argument("--flag", default="")
    h.set_defaults(fn=cmd_htb)

    k = sub.add_parser("koth", help="King of the Hill kit wrappers (discover/capture/retake/watch/verify/report)")
    k.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    k_sub = k.add_subparsers(dest="koth_cmd", required=True)

    def koth_common(sp):
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        sp.add_argument("--config", required=True, help="koth.conf path (sourced by the kit)")
        sp.add_argument("--kit-dir", default="",
                        help="kit directory (else CTF_KOTH_KIT / KOTH_KIT_DIR / KOTH_OPS_DIR)")
        sp.set_defaults(fn=cmd_koth)

    kd = k_sub.add_parser("discover", help="run discover.sh: ranked root vectors")
    koth_common(kd)
    kd.add_argument("--timeout", type=int, default=None, help="subprocess timeout (default 120s)")

    kc = k_sub.add_parser("capture", help="run capture.sh")
    koth_common(kc)
    kc.add_argument("--dry-run", action="store_true", help="plan + local syntax checks only")
    kc.add_argument("--timeout", type=int, default=None, help="subprocess timeout (default 900s)")

    kr = k_sub.add_parser("retake", help="run retake.sh")
    koth_common(kr)
    kr.add_argument("--timeout", type=int, default=90,
                    help="retake.sh wait per cycle in seconds (default 90)")

    kw = k_sub.add_parser("watch", help="run watch.sh (long-running sentry loop)")
    koth_common(kw)
    kw.add_argument("--interval", type=float, default=5, help="WATCH_INTERVAL seconds")
    kw.add_argument("--timeout", type=int, default=None, help="subprocess timeout (default 3600s)")

    kv = k_sub.add_parser("verify", help="run verify.sh; exit code is pass/fail")
    koth_common(kv)
    kv.add_argument("--timeout", type=int, default=None, help="subprocess timeout (default 120s)")

    kp = k_sub.add_parser("report", help="collect king/checker/key/sentries/ports into markdown")
    koth_common(kp)
    kp.add_argument("--out", required=True, help="markdown report path")

    ka = k_sub.add_parser("auto", help="autonomous: recon → foothold → capture → verify")
    ka.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    ka.add_argument("target", help="bare host, koth:<host>, or http://<host>")
    ka.add_argument("--king", default="", help="expected king content (else KOTH_KING, else default)")
    ka.add_argument("--key", default="", help="ssh private key path (else KOTH_KEY, else ~/.ssh/id_ed25519)")
    ka.add_argument("--dry-run", action="store_true", help="plan only; no network calls")
    ka.add_argument("--timeout", type=int, default=None, help="per-step timeout override in seconds")
    ka.add_argument("--vector", default="", help="force a discovery vector")
    ka.add_argument("--kit-dir", default="", help="kit directory (else env / ~/Projects/KOTH-OPS)")
    ka.set_defaults(fn=cmd_koth)
    return p


KOTH_SUBCOMMANDS = {"discover", "capture", "retake", "watch", "verify",
                    "report", "auto"}


def _normalize_koth_argv(argv: list[str]) -> list[str]:
    """Make `ctf.py koth TARGET` and `ctf.py koth:<target>` mean `koth auto`."""
    argv = list(argv)
    # `ctf.py koth: 10.0.0.1` as two shell words.
    if len(argv) >= 2 and argv[0].lower() == "koth:":
        return ["koth", "auto", "koth: " + argv[1], *argv[2:]]
    # `ctf.py koth koth: 10.0.0.1` as three shell words.
    if len(argv) >= 3 and argv[0] == "koth" and argv[1].lower() == "koth:":
        return ["koth", "auto", "koth: " + argv[2], *argv[3:]]
    # `ctf.py koth auto koth: 10.0.0.1` as four shell words.
    if (len(argv) >= 4 and argv[0] == "koth" and argv[1] == "auto"
            and argv[2].lower() == "koth:"):
        return ["koth", "auto", "koth: " + argv[3], *argv[4:]]
    # `ctf.py "koth: 10.0.0.1"` / `ctf.py koth:10.0.0.1` (no `koth` token).
    if argv and argv[0].lower().startswith("koth:") and argv[0] != "koth":
        return ["koth", "auto", *argv]

    try:
        index = argv.index("koth")
    except ValueError:
        return argv
    if index + 1 >= len(argv):
        return argv

    for token in argv[index + 1:]:
        if token in ("-h", "--help"):
            return argv
        if token.startswith("-"):
            continue
        if token not in KOTH_SUBCOMMANDS:
            return argv[:index + 1] + ["auto"] + argv[index + 1:]
        return argv
    return argv


def main() -> int:
    p = build()
    args = p.parse_args(_normalize_koth_argv(sys.argv[1:]))
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

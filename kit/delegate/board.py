#!/usr/bin/env python3
"""board — shared blackboard + inbox for multi-agent CTF runs.

One append-only BOARD.md per state dir; one INBOX.md per front. Agents read the
board before claiming work (deconfliction), log progress as they go, and drop
incremental findings so the parent never waits for a final report.

usage:
  board.py init  STATE [--scope "IP"]
  board.py read  STATE [-n 40] [--front F] [--type T]
  board.py log   STATE FRONT TYPE TEXT...        # TYPE: CLAIM TRIED FOUND NEGATIVE ARTIFACT DONE VERIFIED METRIC
  board.py inbox STATE FRONT TEXT...             # writes STATE/FRONT/INBOX.md and a BOARD ARTIFACT line
  board.py claim STATE FRONT "scope"             # exit 1 if scope already claimed by another front
  board.py ask   STATE FRONT TEXT...             # QUESTION line
  board.py answer STATE FRONT TEXT...            # ANSWER line
  board.py questions STATE                       # unanswered QUESTION lines
  board.py poll  STATE [-m 2] [--json]           # board lines + files changed in the last N minutes
  board.py metrics STATE                         # per-front timings, duplicates, verified ratio
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

TYPES = ("START", "CLAIM", "TRIED", "FOUND", "NEGATIVE", "ARTIFACT",
         "QUESTION", "ANSWER", "DONE", "VERIFIED", "METRIC")
LINE_RE = re.compile(r"^- \[(?P<ts>[0-9T:Z-]+)\] (?P<front>[^|]+?) \| (?P<type>[A-Z]+) \| (?P<text>.*)$")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def bp(state: str) -> str:
    return os.path.join(state, "BOARD.md")


def ensure(state: str, scope: str = "") -> str:
    os.makedirs(state, exist_ok=True)
    p = bp(state)
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"# BOARD — {os.path.basename(os.path.abspath(state))}\n\n")
            f.write(f"- [{now()}] parent | START | scope {scope or '(see brief)'}\n")
    return p


def append(state: str, front: str, typ: str, text: str) -> None:
    typ = typ.upper()
    if typ not in TYPES:
        sys.exit(f"board: unknown type {typ!r}; use one of {', '.join(TYPES)}")
    with open(ensure(state), "a", encoding="utf-8") as f:
        f.write(f"- [{now()}] {front} | {typ} | {text.strip()}\n")


def entries(state: str):
    out = []
    try:
        for line in open(bp(state), encoding="utf-8", errors="replace"):
            m = LINE_RE.match(line.rstrip("\n"))
            if m:
                out.append(m.groupdict())
    except OSError:
        pass
    return out


def cmd_init(a):
    p = ensure(a.state, a.scope)
    for d in ("loot", "recon", "logs"):
        os.makedirs(os.path.join(a.state, d), exist_ok=True)
    print(p)


def cmd_read(a):
    rows = entries(a.state)
    if a.front:
        rows = [r for r in rows if r["front"] == a.front]
    if a.type:
        rows = [r for r in rows if r["type"] == a.type.upper()]
    for r in rows[-a.n:]:
        print(f"[{r['ts']}] {r['front']:14} {r['type']:9} {r['text']}")


def cmd_log(a):
    append(a.state, a.front, a.type, " ".join(a.text))
    print("logged")


def cmd_inbox(a):
    text = " ".join(a.text).strip()
    d = os.path.join(a.state, a.front)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "INBOX.md")
    with open(p, "a", encoding="utf-8") as f:
        f.write(f"- [{now()}] {text}\n")
    append(a.state, a.front, "ARTIFACT", f"INBOX {text[:120]}")
    print(p)


def cmd_claim(a):
    scope = a.scope.strip().lower()
    for r in entries(a.state):
        if r["type"] == "CLAIM" and r["front"] != a.front and \
           scope and scope in r["text"].lower():
            print(f"CONFLICT: {scope!r} already claimed by {r['front']} at {r['ts']}: {r['text']}")
            return 1
    append(a.state, a.front, "CLAIM", a.scope)
    print(f"CLAIMED {a.scope}")
    return 0


def cmd_ask(a):
    append(a.state, a.front, "QUESTION", " ".join(a.text))
    print("question logged (do not block; continue with best assumption)")


def cmd_answer(a):
    append(a.state, a.front, "ANSWER", " ".join(a.text))
    print("answer logged")


def cmd_questions(a):
    answered = {r["text"].split("::")[0] for r in entries(a.state) if r["type"] == "ANSWER"}
    for r in entries(a.state):
        if r["type"] != "QUESTION":
            continue
        if r["text"].split("::")[0] in answered:
            continue
        print(f"[{r['ts']}] {r['front']}: {r['text']}")


def cmd_poll(a):
    rows = entries(a.state)
    cutoff = datetime.now(timezone.utc).timestamp() - a.minutes * 60
    recent = []
    for r in rows:
        try:
            ts = datetime.strptime(r["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts.timestamp() >= cutoff:
            recent.append(r)
    files = []
    try:
        out = subprocess.run(
            ["find", a.state, "-type", "f", "-newermt", f"-{int(a.minutes)} minutes"],
            capture_output=True, text=True, timeout=20).stdout
        files = [l for l in out.splitlines() if l and not l.endswith("BOARD.md")]
    except Exception:  # noqa: BLE001
        pass
    if a.json:
        print(json.dumps({"board": recent, "files": files}, indent=1))
        return
    print(f"== board (last {a.minutes} min) ==")
    for r in recent:
        print(f"[{r['ts']}] {r['front']:14} {r['type']:9} {r['text']}")
    if files:
        print("== new/changed files ==")
        for f in files[:40]:
            print("  " + f)


def cmd_metrics(a):
    rows = entries(a.state)
    start = next((r["ts"] for r in rows if r["type"] == "START"), rows[0]["ts"] if rows else None)
    if not start:
        print("no data")
        return
    t0 = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()

    def dt(ts):
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() - t0
        except ValueError:
            return None

    fronts = {}
    for r in rows:
        if r["type"] == "START":
            continue
        f = fronts.setdefault(r["front"], {"first": None, "first_artifact": None,
                                           "first_found": None, "last": None,
                                           "counts": {}, "found": []})
        d = dt(r["ts"])
        if d is None:
            continue
        f["first"] = d if f["first"] is None else min(f["first"], d)
        f["last"] = d if f["last"] is None else max(f["last"], d)
        if r["type"] == "ARTIFACT" and f["first_artifact"] is None:
            f["first_artifact"] = d
        if r["type"] == "FOUND":
            f["first_found"] = d if f["first_found"] is None else min(f["first_found"], d)
            f["found"].append(r["text"].strip().lower())
        f["counts"][r["type"]] = f["counts"].get(r["type"], 0) + 1

    all_found = {}
    for f, v in fronts.items():
        for t in v["found"]:
            all_found.setdefault(t, []).append(f)
    dups = {t: fs for t, fs in all_found.items() if len(fs) > 1}

    print(f"T0 = {start}")
    print(f"{'front':16} {'first':>7} {'1st_art':>8} {'1st_found':>10} {'last':>7}  counts")
    for f, v in sorted(fronts.items()):
        def s(x):
            return "-" if x is None else f"{x:.0f}s"
        print(f"{f:16} {s(v['first']):>7} {s(v['first_artifact']):>8} "
              f"{s(v['first_found']):>10} {s(v['last']):>7}  {v['counts']}")
    if dups:
        print("\nduplicate FOUND across fronts:")
        for t, fs in dups.items():
            print(f"  {t[:80]} -> {', '.join(fs)}")
    verified = sum(1 for r in rows if r["type"] == "VERIFIED")
    found = sum(1 for r in rows if r["type"] == "FOUND")
    if found:
        print(f"\nverified/found ratio: {verified}/{found}")


def main():
    p = argparse.ArgumentParser(prog="board.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("init"); q.add_argument("state"); q.add_argument("--scope", default="")
    q.set_defaults(fn=cmd_init)

    q = sub.add_parser("read"); q.add_argument("state"); q.add_argument("-n", type=int, default=40)
    q.add_argument("--front"); q.add_argument("--type"); q.set_defaults(fn=cmd_read)

    q = sub.add_parser("log"); q.add_argument("state"); q.add_argument("front")
    q.add_argument("type"); q.add_argument("text", nargs=argparse.REMAINDER); q.set_defaults(fn=cmd_log)

    q = sub.add_parser("inbox"); q.add_argument("state"); q.add_argument("front")
    q.add_argument("text", nargs=argparse.REMAINDER); q.set_defaults(fn=cmd_inbox)

    q = sub.add_parser("claim"); q.add_argument("state"); q.add_argument("front")
    q.add_argument("scope"); q.set_defaults(fn=cmd_claim)

    q = sub.add_parser("ask"); q.add_argument("state"); q.add_argument("front")
    q.add_argument("text", nargs=argparse.REMAINDER); q.set_defaults(fn=cmd_ask)

    q = sub.add_parser("answer"); q.add_argument("state"); q.add_argument("front")
    q.add_argument("text", nargs=argparse.REMAINDER); q.set_defaults(fn=cmd_answer)

    q = sub.add_parser("questions"); q.add_argument("state"); q.set_defaults(fn=cmd_questions)

    q = sub.add_parser("poll"); q.add_argument("state"); q.add_argument("-m", "--minutes", type=float, default=2)
    q.add_argument("--json", action="store_true"); q.set_defaults(fn=cmd_poll)

    q = sub.add_parser("metrics"); q.add_argument("state"); q.set_defaults(fn=cmd_metrics)

    a = p.parse_args()
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())

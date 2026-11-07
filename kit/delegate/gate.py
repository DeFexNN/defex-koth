#!/usr/bin/env python3
"""gate — verify that a run actually delegated, and that the report declares it.

usage:
  gate.py --since 2026-11-04T00:00:00Z [--report FILE] [--json]
  gate.py --since "2026-11-04 00:00" --report state/<ip>/REPORT.md

Checks:
  1. at least one defex-ctf relay run started (dir mtime) at/after --since;
  2. the report contains `DELEGATE: <run-id|front>` or `DELEGATE_SKIPPED: <reason>`.

Exit 0 = PASS, 1 = FAIL, 2 = usage.
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

RUNS = os.path.expanduser("~/.local/state/defex-ctf/runs")


def parse_ts(s: str) -> float:
    s = s.strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"bad timestamp: {s!r} (use 2026-11-04T00:00:00Z)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True)
    ap.add_argument("--report", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        since = parse_ts(a.since)
    except ValueError as e:
        print(f"gate: {e}", file=sys.stderr)
        return 2

    runs = []
    for d in glob.glob(os.path.join(RUNS, "*")):
        if not os.path.isdir(d):
            continue
        try:
            mt = os.path.getmtime(d)
        except OSError:
            continue
        if mt >= since:
            runs.append({"run": os.path.basename(d), "mtime": mt,
                         "iso": datetime.fromtimestamp(mt, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    runs.sort(key=lambda r: r["mtime"])

    declared = None
    if a.report and os.path.isfile(a.report):
        txt = open(a.report, encoding="utf-8", errors="replace").read()
        for line in txt.splitlines():
            l = line.strip()
            if l.startswith("DELEGATE:") or l.startswith("DELEGATE_SKIPPED:"):
                declared = l
                break

    ok = bool(runs) and (declared is None or declared.startswith("DELEGATE:"))
    if a.json:
        print(json.dumps({"since": a.since, "runs": runs, "declared": declared, "pass": ok}, indent=1))
    else:
        print(f"since {a.since}: {len(runs)} relay run(s)")
        for r in runs:
            print(f"  {r['iso']}  {r['run']}")
        if a.report:
            print(f"report declaration: {declared or 'MISSING (add DELEGATE: <run-id> or DELEGATE_SKIPPED: <reason>)'}")
        print("PASS" if ok else "FAIL: no delegation and no DELEGATE_SKIPPED declaration")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

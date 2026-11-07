#!/usr/bin/env python3
"""swarm — plan and launch 4-5 exclusive codex lanes for a KotH target.

Why: broad "test everything" briefs return not_achieved. A useful lane has
ONE falsifiable hypothesis, EXCLUSIVE scope, the inputs the parent already has
(ports/creds/artifacts/negatives), an exact first command, a deadline, and an
artifact-or-NEGATIVE contract.

usage:
  swarm.py plan   --ip IP --state DIR [--ports "80,81,88,445"] [--creds "u:p"]
                  [--artifacts "loot/x.jpg"] [--negatives "upload bypass dead"]
                  [--out DIR]                       # writes LANE-*.md + LAUNCH.md
  swarm.py brief  --state DIR --lane 2 [--out DIR]  # print one brief
  swarm.py launch --ip IP --state DIR --lane 2 [--out DIR]  # defex-ctf delegate codex (bg)
  swarm.py status --state DIR [--out DIR]           # board + runs summary

Lanes:
  1 extractor  local artifacts -> creds/keys (no target traffic)
  2 web        one app/port, one injection/upload hypothesis -> RCE/creds
  3 identity   LDAP/Kerberos/SMB (AD boxes) -> creds/roastables
  4 privesc    local shell -> root vector (before foothold: version->CVE mapping)
  5 verifier   independent check of parent's claims (king/flags/creds)
"""
import argparse
import os
import subprocess
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)

BRIEF = """CTF KotH swarm lane — {ip} ONLY. Never reset. Keep every service alive. Do not write the king file.

LANE {lane} / ROLE: {role}
DEADLINE: {deadline}s to ARTIFACT or FOUND (hard stop {hard}s). No work after that.

HYPOTHESIS (your only job: prove or disprove it)
  {hypothesis}

EXCLUSIVE SCOPE (do not leave it): {scope}
INPUTS (already established — do NOT re-derive)
{inputs}
BOARD PROTOCOL (do this first, then log as you go)
  python3 {board} read {state} -n 40
  python3 {board} claim {state} lane{lane} "{scope}"
  python3 {board} inbox {state} lane{lane} "<one-line finding, immediately>"
  python3 {board} log {state} lane{lane} TRIED "<what you checked>"
  python3 {board} log {state} lane{lane} FOUND "<finding + path>"
  If claim prints CONFLICT: stop, report the conflict, do not duplicate.

FIRST COMMAND (run it now; do not plan, do not read files first)
  {first_cmd}

RULES
- Read-only unless the parent explicitly authorized otherwise; no DB/config writes.
- Max 3 credential attempts per service, then stop.
- One download per artifact; heavy work in `nohup ... &` + poll.
- Do not run `koth kickoff`/`recon`; no full-range `-p-` scans.
- If you need a decision, write it with `board.py ask` and continue with your best assumption.

DELIVERABLE
- Write proof to {state}/lane{lane}/ (files) and push the one-liner via `board.py inbox`.
- No artifact by the deadline -> `board.py log ... NEGATIVE "<what you ruled out>"` and exit.
- Last line must be one JSON object:
  {{"lane":{lane},"status":"found|negative|blocked","verified":true|false,"artifacts":[],"creds":null,"next_best_action":"...","seconds":N}}
Never print raw secrets in prose; reference the artifact path.
"""

LANES = {
    1: dict(role="extractor", deadline=90, scope="local files under the state dir only",
            hypothesis="An already-downloaded artifact (image/archive/dump/body) contains credentials, a key, or a flag.",
            first_cmd="python3 {kit}/triage.sh -q --dir {state}/loot"),
    2: dict(role="web", deadline=150, scope="the web ports listed below ONLY",
            hypothesis="A parameter on the target web app is injectable (SQLi/command/upload) and yields RCE or credentials.",
            first_cmd="curl -s -m 8 -D- -o- http://{ip}:{webport}/ | head -40"),
    3: dict(role="identity", deadline=180, scope="88/389/636/445/3268 ONLY (AD)",
            hypothesis="Anonymous LDAP or a roastable Kerberos account yields a usable credential.",
            first_cmd="ldapsearch -x -H ldap://{ip}:389 -s base namingContexts 2>&1 | head -20"),
    4: dict(role="privesc", deadline=180, scope="the foothold shell/user only",
            hypothesis="The current low-priv user can reach root/admin via sudo/SUID/caps/timers/creds reuse.",
            first_cmd="id; sudo -n -l 2>&1; find / -perm -4000 -type f 2>/dev/null | head -30"),
    5: dict(role="verifier", deadline=120, scope="read-only verification of the parent's claims",
            hypothesis="The parent's 'held' claim is accurate: king bytes, immutability, guard, flags.",
            first_cmd="curl -s -m 5 http://{ip}:9999/"),
}


def lane_ctx(a, n):
    webport = "80"
    webports = []
    ports = [p.strip() for p in (a.ports or "").split(",") if p.strip()]
    if n == 2:
        webports = [p for p in ports if p.isdigit() and int(p) in (80, 81, 82, 443, 8000, 8080, 8081, 8443)] or ["80"]
        webport = webports[0]
    inputs = []
    inputs.append(f"  - known open ports: {a.ports or '(use only what you see)'}")
    if a.creds:
        inputs.append(f"  - credentials already found: {a.creds}")
    if a.artifacts:
        inputs.append(f"  - artifacts on disk (triage these first): {a.artifacts}")
    if a.negatives:
        inputs.append(f"  - ALREADY TESTED / DEAD (do not repeat): {a.negatives}")
    if not inputs:
        inputs.append("  - none beyond the scope above")
    return dict(webport=webport, websports=",".join(webports)), "\n".join(inputs)


def render(a, n):
    extra, inputs = lane_ctx(a, n)
    L = dict(LANES[n])
    if n == 2 and extra.get("websports"):
        L["scope"] = "web ports " + extra["websports"] + " ONLY"
        L["first_cmd"] = L["first_cmd"].replace("http://{ip}:{webport}/", "http://{ip}:" + extra["websports"].split(",")[0] + "/")
    return BRIEF.format(
        ip=a.ip, lane=n, role=L["role"], deadline=L["deadline"], hard=L["deadline"] * 2,
        hypothesis=L["hypothesis"], scope=L["scope"], inputs=inputs,
        board=os.path.join(HERE, "board.py"), state=a.state, kit=KIT,
        first_cmd=L["first_cmd"].format(ip=a.ip, state=a.state, kit=KIT, **extra),
    )


def outdir(a):
    return a.out or os.path.join(a.state, "swarm")


def cmd_plan(a):
    od = outdir(a)
    os.makedirs(od, exist_ok=True)
    lanes = [1, 2, 3, 4, 5]
    for n in lanes:
        p = os.path.join(od, f"LANE-{n}.md")
        open(p, "w", encoding="utf-8").write(render(a, n))
    launch = ["# LAUNCH — paste one relay call per lane (codex; agy only for neutral research)", ""]
    for n in lanes:
        p = os.path.join(od, f"LANE-{n}.md")
        launch.append(f"## lane {n} ({LANES[n]['role']}, {LANES[n]['deadline']}s)")
        launch.append("```")
        launch.append(f"cat {p}   # -> pass as the relay task text")
        launch.append("```")
    launch.append("\n## Or launch from the shell (fallback):")
    launch.append("```")
    for n in lanes:
        launch.append(f"python3 {HERE}/swarm.py launch --ip {a.ip} --state {a.state} --lane {n}")
    launch.append("```")
    open(os.path.join(od, "LAUNCH.md"), "w", encoding="utf-8").write("\n".join(launch) + "\n")
    print(f"planned 5 lanes in {od}")
    for n in lanes:
        print(f"  lane {n}: {LANES[n]['role']:9} {LANES[n]['deadline']}s  {os.path.join(od, f'LANE-{n}.md')}")


def cmd_brief(a):
    print(render(a, a.lane))


def cmd_launch(a):
    od = outdir(a)
    os.makedirs(os.path.join(od, "logs"), exist_ok=True)
    ws = os.path.join(od, f"lane{a.lane}")
    os.makedirs(ws, exist_ok=True)
    brief = render(a, a.lane)
    log = os.path.join(od, "logs", f"lane{a.lane}.log")
    cmd = ["defex-ctf", "delegate", "codex", "--workspace", ws]
    with open(log, "ab") as fh:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=fh, stderr=subprocess.STDOUT)
        p.communicate(brief.encode())
    print(f"lane {a.lane} -> log {log}")
    return 0


def cmd_status(a):
    od = outdir(a)
    board = os.path.join(HERE, "board.py")
    try:
        subprocess.run([sys.executable, board, "read", a.state, "-n", "80"])
    except Exception:  # noqa: BLE001
        pass
    logs = os.path.join(od, "logs")
    if os.path.isdir(logs):
        print("== lane logs ==")
        for f in sorted(os.listdir(logs)):
            p = os.path.join(logs, f)
            print(f"  {f}: {os.path.getsize(p)}B  {p}")
    print("== runs ==")
    try:
        subprocess.run(["teamctl", "relay", "latest", "-n", "3"])
    except Exception:  # noqa: BLE001
        pass


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("plan", cmd_plan), ("brief", cmd_brief),
                     ("launch", cmd_launch), ("status", cmd_status)):
        q = sub.add_parser(name)
        q.add_argument("--ip", required=(name != "status"))
        q.add_argument("--state", required=True)
        q.add_argument("--ports", default="")
        q.add_argument("--creds", default="")
        q.add_argument("--artifacts", default="")
        q.add_argument("--negatives", default="")
        q.add_argument("--out", default="")
        if name in ("brief", "launch"):
            q.add_argument("--lane", type=int, required=True, choices=[1, 2, 3, 4, 5])
        q.set_defaults(fn=fn)
    a = p.parse_args()
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())

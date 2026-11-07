#!/usr/bin/env python3
"""mission — generate a self-contained, time-boxed relay mission brief.

Implements the delegation contract: one decision, one artifact, one deadline,
explicit port deconfliction, board protocol, incremental delivery, result JSON.

usage:
  mission.py --ip 10.0.0.5 --state ~/Projects/KOTH-OPS/state/10.0.0.5 \
             --front creds-db --role prober --ports 3306 \
             --goal "enumerate MySQL users/tables; report creds + flags" \
             --deadline 120 [--artifacts "loot/dump.sql"] [--extra "note"]

roles: extractor | prober | researcher | verifier
Prints the prompt to stdout; pipe it into the relay call.
"""
import argparse
import os

KIT = os.path.dirname(os.path.abspath(__file__))

TEMPLATE = """CTF King-of-the-Hill / lab task. Authorized scope: {ip} ONLY.

ROLE: {role}
FRONT: {front}
GOAL (one decision, nothing else): {goal}
DEADLINE: {deadline}s to a first artifact; hard stop at {hard}s. If nothing is found, log NEGATIVE and stop — do not widen the scope. Time is measured from the user's prompt (T0), not from when you personally started; state seconds-from-T0 in your JSON.

KNOWLEDGE
- Known open ports: {ports}
- Your exclusive scope: {scope_only}. Do not work outside it.
- Parent state dir: {state}
{artifacts_block}{extra_block}
FORBIDDEN
- Never reset/reboot the target; keep every service alive; never touch other hosts.
- Do NOT run `koth kickoff` or `koth recon`; no full-range `-p-` scans (recon is done).
- Max 3 credential attempts per service, then stop.
- No writes to databases/configs; read-only unless the parent explicitly authorized otherwise.
- Do not write the king file. Do not run the target's unknown binaries.

RESOURCE RULES
- Download any service artifact ONCE, then work on the local copy (no parallel streams).
- Heavy commands on the target (grep -r, dumps) run as `nohup nice ionice ... > file &` and are polled.
- Every external command gets a timeout (20-30 s interactive, <=120 s per tool).

BOARD PROTOCOL (do this before any work, then as you go)
  python3 {kit}/board.py read {state} -n 40
  python3 {kit}/board.py claim {state} {front} "{scope_only}"
  python3 {kit}/board.py log {state} {front} TRIED "<what you checked>"
  python3 {kit}/board.py log {state} {front} FOUND "<finding with path>"
  python3 {kit}/board.py log {state} {front} NEGATIVE "<what failed>"
  python3 {kit}/board.py inbox {state} {front} "<one-line finding, immediately>"
If `claim` prints CONFLICT: stop and report the conflict instead of duplicating.

DELIVERY
- Write findings to {state}/{front}/INBOX.md the moment you have them (board.py inbox does this) — never wait for the final report.
- If you need a parent decision, write `QUESTION: ...` via `board.py ask` and CONTINUE with your best assumption. Do not block.
{verify_block}
KILL CRITERIA
- If the board shows DONE/root/king already achieved by the parent, stop your attack work and either do the requested verification or exit.

RESULT (last line must be a single-line JSON)
{{"front":"{front}","status":"found|negative|blocked","verified":true|false,"artifacts":["path",...],"creds":{{"user":"pass"}} or null,"next_best_action":"...","seconds":N}}
Never print raw secrets in prose; reference the artifact path instead.
"""

VERIFY_BLOCK = """
VERIFIER MODE
- Re-check the parent's claims independently: exact bytes, exact paths, live output.
- Report mismatches loudly (`FOUND` only for verified, `NEGATIVE` for failed checks).
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--state", default="")
    ap.add_argument("--front", required=True)
    ap.add_argument("--role", default="extractor",
                    choices=["extractor", "prober", "researcher", "verifier"])
    ap.add_argument("--ports", default="(none yet)")
    ap.add_argument("--goal", required=True)
    ap.add_argument("--deadline", type=int, default=120)
    ap.add_argument("--artifacts", default="")
    ap.add_argument("--extra", default="")
    a = ap.parse_args()

    state = os.path.abspath(os.path.expanduser(a.state or
                          os.path.join(os.path.expanduser("~/Projects/KOTH-OPS/state"), a.ip)))
    arts = [x.strip() for x in a.artifacts.split(",") if x.strip()]
    artifacts_block = ""
    if arts:
        artifacts_block = ("- ARTIFACTS ALREADY ON DISK — triage these FIRST with "
                           f"`{os.path.dirname(KIT)}/triage.sh -q <file>`:\n" +
                           "".join(f"    * {x}\n" for x in arts))
    extra_block = f"- Parent note: {a.extra}\n" if a.extra else ""
    scope_only = a.ports if a.role in ("prober",) else "the front above only"

    out = TEMPLATE.format(
        ip=a.ip, role=a.role, front=a.front, goal=a.goal,
        deadline=a.deadline, hard=a.deadline * 2, ports=a.ports,
        scope_only=scope_only, state=state, kit=KIT,
        artifacts_block=artifacts_block, extra_block=extra_block,
        verify_block=VERIFY_BLOCK if a.role == "verifier" else "",
    )
    print(out)


if __name__ == "__main__":
    main()

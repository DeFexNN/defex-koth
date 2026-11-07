# Delegation kit — A–H contract in practice

Files:
- `mission.py` — generates the full mission brief (one decision, one artifact, deadline, deconfliction, board protocol, JSON result).
- `board.py` — the shared blackboard: BOARD.md (append-only) + per-front INBOX.md, claims, questions, polling, metrics.

## Quick start

```sh
IP=10.10.205.72
S=~/Projects/KOTH-OPS/state/$IP

python3 kit/delegate/board.py init "$S" --scope "$IP"
python3 kit/delegate/board.py log "$S" parent TRIED "quick scan + probes done; ports 22,3306,9999,15065"

# generate a brief and paste it as the relay task text:
python3 kit/delegate/mission.py --ip "$IP" --state "$S" \
  --front creds-db --role prober --ports 3306 --deadline 120 \
  --goal "enumerate MySQL users/tables; report credentials and flags" \
  --artifacts "$S/loot/b16109.bin"

# parent side, every 30-60 s:
python3 kit/delegate/board.py poll "$S" -m 2
python3 kit/delegate/board.py questions "$S"
```

## A. Mission contract
One decision + one artifact + deadline. `mission.py` fills scope, known ports,
artifact list, deadline and hard-stop automatically.

## B. Shared board + incremental delivery
- `BOARD.md`: append-only, one line per event (`CLAIM/TRIED/FOUND/NEGATIVE/ARTIFACT/QUESTION/ANSWER/DONE/VERIFIED`).
- `state/<front>/INBOX.md`: findings written the moment they exist.
- Parent polls (`board.py poll`) instead of waiting for final reports.

## C. Deconfliction
`board.py claim <state> <front> "<scope>"` returns exit 1 and prints `CONFLICT`
if another front already claimed the same scope. Agents must claim before work
and stop on conflict.

## D. Time and roles
Roles: `extractor` (artifact → creds), `prober` (one service), `researcher`
(intel/CVE), `verifier` (independent checks). Deadline 90–120 s for
extract/probe, ≤5 min for research; hard stop at 2×. Critical path stays with
the parent — never delegate what decides the run.

## E. Steering and lifecycle
- Relay steering: always `session=` **and** `workspace=`; one call at a time.
- No blocking on parent input: `board.py ask ...` then continue.
- Kill criteria baked into the brief: if the board shows DONE/root/king, stop
  attack work and verify or exit.

## F. Result format
Last line is one JSON object:
```json
{"front":"creds-db","status":"found","verified":true,"artifacts":["..."],"creds":{"u":"p"},"next_best_action":"...","seconds":93}
```
Evidence: one line per fact (command → output). No raw secrets in prose.

## G. Resource hygiene
One download per artifact, local copy afterwards; no `-p-` scans from agents;
one port set per prober; heavy target commands in `nohup ... &`.

## H. Metrics
`board.py metrics <state>` prints per front: first event, first artifact, first
FOUND, last event, event counts, duplicate FOUND across fronts, and
verified/found ratio. Use it to grade the run, not the prose.

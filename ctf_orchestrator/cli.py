from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
import tempfile
import uuid
import socket
import yaml
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .core import (RunResult, WORKSPACE_SKIP_NAMES, AGY_BRIEF_FILE,
                   _sync_max_file_bytes, _sync_total_bytes, _zcode_environment, artifact_allowed,
                   check_disk_headroom, check_thread_resumable,
                   client_available, execute_tasks, isolated_invoke, koth_route, load_config, load_task_file,
                   parse_koth_prompt, preflight_agent, prompt_style_for, prune_run_workspaces, render_markdown,
                   summarize)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="defex-ctf", description="CTF agent utilities")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--config", default="config/agents.yaml", help="agent YAML configuration")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("agents", help="show configured models and local availability")
    zcode = sub.add_parser("zcode", help="prepare or inspect the configured ZCode CLI")
    zcode.add_argument("action", choices=("login", "tui", "doctor"))
    zcode.add_argument("--workspace", default=".", help="workspace for the ZCode TUI")
    delegate = sub.add_parser("delegate", help="run a configured external client; task is read from stdin")
    delegate.add_argument("client", choices=("codex", "agy", "zcode"))
    delegate.add_argument("--workspace",
                          help="directory the client runs in DIRECTLY (no copy, no size checks; never the home directory or a filesystem root). Omit for an empty per-run scratch dir")
    delegate.add_argument("--direct", action="store_true",
                          help="accepted no-op: direct is the default since 2026-11-05 (kept for older relay plugins)")
    delegate.add_argument("--no-create", action="store_true", help="require the workspace directory to exist")
    delegate.add_argument("--deadline", type=int, help="maximum total client runtime in seconds")
    delegate.add_argument("--front", default=None, help="structured delegation front label")
    delegate.add_argument("--role", default=None, help="structured delegation role")
    delegate.add_argument("--ports", default=None, help="structured port scope, e.g. 80,443")
    delegate.add_argument("--direction", choices=("web", "reversing_pwn", "network_traffic", "memory_forensics", "general"), default="general")
    delegate.add_argument("--no-retry", action="store_true", help="do not retry with a different client")
    delegate.add_argument("--new-task", action="store_true",
                          help="with --resume: explicitly start a new full run in a finished thread (resuming a finished success thread is refused otherwise)")
    delegate.add_argument("--keep-workspaces", action="store_true",
                          help="keep this run's private workspace copies instead of pruning them when the delegate finishes")
    delegate.add_argument("--no-koth-route", action="store_true",
                          help="never reroute a koth-looking task to the koth auto tool; the relay passes this because agent tasks are not koth directives")
    delegate.add_argument("--prompt-style", default="auto",
                          choices=("auto", "standard", "casual", "lab_review", "lab_minimal"),
                          help="prompt framing; auto uses casual for AGY and standard elsewhere")
    sync = delegate.add_mutually_exclusive_group()
    sync.add_argument("--sync-artifacts", dest="sync_artifacts", action="store_true",
                          help="copy artifacts the client wrote in its private workspace back to --workspace")
    sync.add_argument("--no-sync-artifacts", dest="sync_artifacts", action="store_false",
                      help="disable artifact copy-back (artifacts may be pruned with the private workspace)")
    delegate.set_defaults(sync_artifacts=True)
    delegate.add_argument("--events-jsonl", default=None,
                          help="append normalized live client events (one JSON per line) to this file while the client runs")
    delegate.add_argument("--resume", default=None,
                          help="continue the same client thread (codex session/thread id, agy conversation_id, zcode sessionId)")
    receipt = sub.add_parser("receipt", help="inspect the recorded delegate invocation")
    receipt.add_argument("run_id")
    receipt.add_argument("--summary", action="store_true", help="print a compact one-screen summary")
    receipt.add_argument("--json", action="store_true", help="print full receipt JSON")
    runs = sub.add_parser("runs", help="list delegate runs since an ISO-8601 timestamp")
    runs.add_argument("--since", required=True)
    runs.add_argument("--json", action="store_true")
    watch = sub.add_parser("hold-watch", help="sample a local file or explicitly scoped host:port")
    watch.add_argument("--file")
    watch.add_argument("--port", help="loopback HOST:PORT only; remote checks/scanning are out of scope")
    watch.add_argument("--interval", type=float, default=2)
    watch.add_argument("--log", required=True)
    watch.add_argument("--count", "--samples", dest="count", type=int)
    prune_cmd = sub.add_parser("prune", help="delete delegate workspace copies and aged-out run receipts")
    prune_cmd.add_argument("--keep-days", type=float, default=30.0,
                           help="remove whole run directories (receipts included) older than this many days; workspaces are always pruned")
    preflight = sub.add_parser("preflight", help="test model inference and an actual command")
    preflight.add_argument("client", choices=("agy",))
    preflight.add_argument("--workspace", default=".")
    preflight.add_argument("--force", action="store_true", help="ignore the cached result")
    preflight.add_argument("--fallback", action="store_true", help="also test the configured fallback model")
    learn = sub.add_parser("learn", help="derive routing metrics from manually scored benchmark reports")
    learn.add_argument("reports", nargs="+")
    learn.add_argument("--output", help="metrics YAML path; defaults to metrics_file next to config")
    for name, help_text in (("run", "route each task to one eligible agent"), ("batch", "route each task to one eligible agent"), ("benchmark", "run every eligible agent on the same task set")):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("task_file")
        cmd.add_argument("--workspace", required=True, help="challenge working directory (copied per attempt)")
        cmd.add_argument("--out", default="runs", help="report directory root")
        cmd.add_argument("--dry-run", action="store_true", help="show exact client commands without invoking models")
        if name != "benchmark":
            cmd.add_argument("--verify", action="store_true", help="also schedule an independent agent for each task")
    score = sub.add_parser("score", help="record human benchmark scoring for one result")
    score.add_argument("report", help="path to report.json")
    score.add_argument("--task", required=True)
    score.add_argument("--agent", required=True)
    score.add_argument("--correctness", required=True, choices=("correct", "partial", "incorrect", "unscored"))
    score.add_argument("--useful-seconds", type=float)
    score.add_argument("--false-findings", type=int, default=0)
    score.add_argument("--note", default="")
    return p


def summarize_from_dicts(results):
    from .core import RunResult
    return summarize([RunResult(**{k: v for k, v in result.items() if k in RunResult.__dataclass_fields__})
                     for result in results])


def _sync_artifacts(result, target: Path) -> list[str]:
    """Copy new or changed files, plus whitelisted reports, back to target."""
    source = Path(getattr(result, "workspace", "") or "")
    if not source.is_dir():
        return []
    copied: list[str] = []
    baseline = getattr(result, "sync_baseline", None)
    max_file_bytes = _sync_max_file_bytes()
    total_bytes = _sync_total_bytes()
    source_root = source.resolve()

    def candidates():
        if baseline is None:
            for item in getattr(result, "artifacts", []) or []:
                rel = str(item.get("path") or "")
                if rel and not rel.startswith("../") and not Path(rel).is_absolute():
                    yield Path(rel)
            return
        for root, dirs, files in os.walk(source, followlinks=False):
            current = Path(root)
            dirs[:] = [name for name in dirs
                       if name not in WORKSPACE_SKIP_NAMES and not (current / name).is_symlink()]
            for name in sorted(files):
                yield (current / name).relative_to(source)

    synced_bytes = 0
    seen: set[str] = set()
    for relative in candidates():
        rel = relative.as_posix()
        if (not rel or rel in seen or relative.is_absolute()
                or rel == AGY_BRIEF_FILE
                or any(part in WORKSPACE_SKIP_NAMES for part in relative.parts)):
            continue
        seen.add(rel)
        src = source / relative
        if src.is_symlink():
            continue
        try:
            resolved = src.resolve(strict=True)
            resolved.relative_to(source_root)
            stat = src.stat(follow_symlinks=False)
        except (OSError, ValueError):
            continue
        if not src.is_file():
            continue
        if baseline is not None:
            if baseline.get(rel) == (stat.st_size, stat.st_mtime_ns) and not artifact_allowed(rel):
                continue
        elif not artifact_allowed(rel):
            continue
        if stat.st_size > max_file_bytes or synced_bytes + stat.st_size > total_bytes:
            continue
        dest = target / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(str(dest))
        synced_bytes += stat.st_size
    return copied


def receipt_summary(run_id: str, record: dict, receipt_path: Path) -> dict:
    attempts = record.get("attempts") or [{}]
    last = attempts[-1]
    return {"run_id": run_id, "status": last.get("status", record.get("status", "")),
            "client": last.get("client", record.get("requested_client", "")),
            "model": last.get("model", ""), "duration_seconds": last.get("duration_seconds", 0),
            "front": record.get("front") or last.get("front") or last.get("agent_id", ""),
            "artifacts": last.get("artifacts", []), "receipt_path": str(receipt_path)}


def _list_runs(state_dir: Path, since: str) -> list[dict]:
    cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    rows = []
    for receipt in state_dir.glob("*/receipt.json"):
        try:
            record = json.loads(receipt.read_text(encoding="utf-8"))
            attempts = record.get("attempts") or [{}]
            for attempt in attempts:
                stamp = attempt.get("started_at") or record.get("started_at") or record.get("finished_at")
                try:
                    started = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")) if stamp else datetime.fromtimestamp(receipt.stat().st_mtime, timezone.utc)
                except ValueError:
                    started = datetime.fromtimestamp(receipt.stat().st_mtime, timezone.utc)
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if started < cutoff:
                    continue
                rows.append({"front": record.get("front") or attempt.get("front") or attempt.get("agent_id", ""),
                             "client": attempt.get("client", ""), "status": attempt.get("status", ""),
                             "duration_seconds": attempt.get("duration_seconds", 0),
                             "workspace": attempt.get("workspace", ""), "artifacts": attempt.get("artifacts", []),
                             "receipt": record.get("run_id", receipt.parent.name)})
        except (OSError, ValueError, TypeError):
            continue
    return sorted(rows, key=lambda row: row["receipt"], reverse=True)


def _workspace_arg(value: str, create: bool = True, check_size: bool = True) -> Path:
    path = Path(value).expanduser().resolve()
    home = Path.home().resolve()
    if path == Path("/") or path == home or path == Path.cwd().resolve() and value == ".":
        raise ValueError(f"refusing unsafe workspace: {path}")
    if not path.exists() and create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        hint = " Use --no-create to require an existing directory." if create else f" Create it with: mkdir -p {path}"
        raise ValueError(f"workspace directory does not exist: {path}.{hint}")
    # Direct mode works in the real directory however big it is; the copy path
    # keeps the size guard.
    if check_size:
        size = sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())
        if size > 1024 ** 3:
            raise ValueError(f"workspace exceeds 1 GB limit: {path}")
    return path


def wait_for_client_slot(locks, client: str, events_jsonl: str | None = None,
                         deadline: float | None = None, note_interval: float = 60.0,
                         poll: float = 0.2, clock=time.monotonic, sleep=time.sleep):
    """Block until one of ``locks`` takes a non-blocking exclusive flock.

    A queued delegation is otherwise invisible: the relay transcript stays
    empty while every client slot is busy, which reads exactly like a dead
    subagent in the Subagents panel. Emit status events when the wait starts
    and periodically while it continues (plus an acquisition note) so the
    queue is visible. Returns the acquired file object, or "deadline".
    """
    started = None
    last_note = None
    while True:
        for lock in locks:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if started is not None and events_jsonl:
                    from .core import append_relay_event
                    append_relay_event(events_jsonl, "status",
                                       f"slot acquired after {int(clock() - started)}s")
                return lock
            except BlockingIOError:
                continue
        if deadline is not None and clock() >= deadline:
            return "deadline"
        if events_jsonl:
            from .core import append_relay_event
            now = clock()
            if started is None:
                started = now
                last_note = now
                append_relay_event(events_jsonl, "status",
                                   f"slot wait: all {len(locks)} {client} slots busy - queued")
            elif now - last_note >= note_interval:
                last_note = now
                append_relay_event(events_jsonl, "status",
                                   f"slot wait: still queued for {client} ({int(now - started)}s)")
        sleep(poll)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = load_config(args.config)
        state_dir = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "defex-ctf" / "runs"
        if args.command == "learn":
            grouped = {}
            for report_file in args.reports:
                report = json.loads(Path(report_file).read_text(encoding="utf-8"))
                if not report.get("benchmark"):
                    raise ValueError(f"not a benchmark report: {report_file}")
                for r in report.get("results", []):
                    evaluation = r.get("evaluation") or {}
                    correctness = evaluation.get("correctness")
                    if correctness not in {"correct", "partial", "incorrect"}:
                        continue
                    key = (r.get("agent_id"), r.get("model"), r.get("direction"))
                    bucket = grouped.setdefault(key, {"scores": [], "times": []})
                    bucket["scores"].append({"correct": 1.0, "partial": 0.5, "incorrect": 0.0}[correctness])
                    if r.get("status") == "success" and isinstance(r.get("duration_seconds"), (int, float)):
                        bucket["times"].append(r["duration_seconds"])
            if not grouped:
                raise ValueError("no manually scored benchmark results; use defex-ctf score first")
            learned = {}
            for (agent_id, model, direction), bucket in grouped.items():
                profile = learned.setdefault(agent_id, {"model": model, "directions": {}})
                if profile["model"] != model:
                    raise ValueError(f"multiple models for {agent_id}; learn from one model at a time")
                profile["directions"][direction] = {"quality": sum(bucket["scores"]) / len(bucket["scores"]),
                                                    "samples": len(bucket["scores"]),
                                                    "median_seconds": statistics.median(bucket["times"]) if bucket["times"] else 120}
            output = Path(args.output) if args.output else Path(args.config).resolve().parent / config.get("metrics_file", "metrics.yaml")
            output.parent.mkdir(parents=True, exist_ok=True)
            existing = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else {}
            existing = existing or {}
            for agent_id, profile in learned.items():
                old = existing.get(agent_id, {})
                if old.get("model") == profile["model"]:
                    profile["directions"] = {**old.get("directions", {}), **profile["directions"]}
                existing[agent_id] = profile
            output.write_text(yaml.safe_dump(existing, allow_unicode=True, sort_keys=True), encoding="utf-8")
            print(f"Recorded scored benchmark metrics in {output}")
            return 0
        if args.command == "receipt":
            if not re.fullmatch(r"[0-9a-f]{32}", args.run_id):
                raise ValueError("invalid receipt ID")
            receipt_path = state_dir / args.run_id / "receipt.json"
            record = json.loads(receipt_path.read_text(encoding="utf-8"))
            if args.summary:
                print(json.dumps(receipt_summary(args.run_id, record, receipt_path), ensure_ascii=False))
            else:
                print(json.dumps(record, ensure_ascii=False, indent=2))
            return 0
        if args.command == "runs":
            rows = _list_runs(state_dir, args.since)
            if args.json:
                print(json.dumps(rows, ensure_ascii=False))
            else:
                print("FRONT\tCLIENT\tSTATUS\tSECONDS\tRECEIPT\tARTIFACTS")
                for row in rows:
                    print(f"{row['front']}\t{row['client']}\t{row['status']}\t{row['duration_seconds']}\t{row['receipt']}\t{', '.join(row['artifacts'])}")
            return 0
        if args.command == "hold-watch":
            if bool(args.file) == bool(args.port):
                raise ValueError("choose exactly one of --file or --port")
            if args.interval <= 0 or (args.count is not None and args.count <= 0):
                raise ValueError("interval and count must be positive")
            target_file = Path(args.file).expanduser() if args.file else None
            endpoint = None
            if args.port:
                host, sep, raw_port = args.port.rpartition(":")
                if not sep or not host or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                    raise ValueError("--port must be HOST:PORT")
                if host not in {"127.0.0.1", "localhost", "::1", "[::1]"}:
                    raise ValueError("hold-watch is local only; --port host must be loopback")
                endpoint = host.strip("[]"), int(raw_port)
            log = Path(args.log).expanduser()
            log.parent.mkdir(parents=True, exist_ok=True)
            index = 0
            with log.open("a", encoding="utf-8") as stream:
                while args.count is None or index < args.count:
                    if target_file:
                        try:
                            value = target_file.read_text(encoding="utf-8", errors="replace").strip().replace("\n", " ")
                        except OSError as exc:
                            value = f"error:{exc.__class__.__name__}"
                    else:
                        try:
                            with socket.create_connection(endpoint, timeout=1):
                                value = "open"
                        except OSError:
                            value = "closed_or_filtered"
                    stream.write(f"{datetime.now(timezone.utc).isoformat()} {value}\n")
                    stream.flush()
                    index += 1
                    if args.count is None or index < args.count:
                        time.sleep(args.interval)
            return 0
        if args.command == "prune":
            summary = prune_run_workspaces(state_dir, keep_days=args.keep_days)
            stale_streams = 0
            for stale in Path(tempfile.gettempdir()).glob("defex-*-relay-*.jsonl"):
                try:
                    stale.unlink()
                    stale_streams += 1
                except OSError:
                    pass
            print(json.dumps({**summary, "stale_event_streams": stale_streams,
                              "runs_dir": str(state_dir)}, ensure_ascii=False))
            return 0
        if args.command == "preflight":
            agent = next((a for a in config["agents"] if a.get("client") == args.client), None)
            if agent is None:
                raise ValueError(f"no {args.client} client is configured")
            workspace = _workspace_arg(args.workspace)
            result = preflight_agent(agent, force=args.force)
            fallback = agent.get("fallback")
            if args.fallback and isinstance(fallback, dict):
                fb_result = preflight_agent({**agent, **fallback}, force=args.force)
                combined = {"primary": result, "fallback": fb_result}
                print(json.dumps(combined, ensure_ascii=False))
                return 0 if result["available"] and fb_result["available"] else 1
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["available"] else 1
        if args.command == "delegate":
            agent = next((a for a in config["agents"] if a.get("client") == args.client), None)
            if agent is None:
                raise ValueError(f"no {args.client} client is configured")
            # 2026-11-05: NO private copies on the delegate path, per user
            # decision. A passed workspace IS the client's working directory
            # (direct); no workspace = empty per-attempt scratch dir. The copy
            # mode stays available to run/batch/benchmark only. --direct is
            # kept as an accepted no-op for older relay plugins.
            workspace = _workspace_arg(args.workspace, create=not args.no_create,
                                       check_size=False) if args.workspace else None
            workspace_mode = "direct" if workspace is not None else "scratch"
            prompt = sys.stdin.read().strip()
            if not prompt:
                raise ValueError("task is empty; provide the task on stdin")
            if parse_koth_prompt(prompt) and not args.no_koth_route:
                routed = koth_route(prompt)
                print(json.dumps(routed, ensure_ascii=False))
                return 0 if routed.get("returncode") == 0 else 1
            if args.new_task and not args.resume:
                raise ValueError("--new-task only makes sense together with --resume")
            if args.resume:
                # Resuming a thread that already finished successfully is a fresh
                # full turn plus another workspace copy — refuse it unless it is
                # a QUESTION answer or an explicit --new-task.
                thread_state = check_thread_resumable(state_dir, args.resume, new_task=args.new_task)
            if args.resume and args.client == "codex":
                # The thread's rollout lives in the CODEX_HOME that created it
                # (a codexctl aggregated account or the default ~/.codex); pin
                # the resume there instead of rebalancing to another account.
                # An unknown thread balances normally.
                from .core import _thread_state
                ts = _thread_state(state_dir, args.resume)
                if ts is not None:
                    agent = dict(agent, codex_account_dir=ts.get("account") or "")
            # Refuse early, before any run directory or workspace copy exists.
            check_disk_headroom(state_dir)
            # Separate processes share these per-client slots, including background subagents.
            lock_dir = Path(tempfile.gettempdir()) / f"defex-ctf-{os.getuid()}"
            lock_dir.mkdir(mode=0o700, exist_ok=True)
            run_id = uuid.uuid4().hex
            run_dir = state_dir / run_id
            state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_dir.chmod(0o700)
            run_dir.mkdir(mode=0o700)
            task = {"id": run_id, "direction": args.direction, "prompt": prompt}
            if args.prompt_style != "auto":
                task["prompt_style"] = args.prompt_style
            scope = "Only the scope explicitly specified in the task is authorized; if none is specified, local artifacts only and no active network targets."
            candidates = [agent]
            if args.events_jsonl:
                from .core import append_relay_event
                append_relay_event(args.events_jsonl, "status",
                                   f"delegate start: requested client {args.client}, direction {args.direction}")
            if not args.no_retry:
                candidates += [a for a in config["agents"] if a["id"] != agent["id"]
                               and a.get("client") != agent.get("client")
                               and args.direction in a.get("directions", []) and client_available(a)[0]]
            if args.resume:
                # The resume id belongs to the requested client's thread only, and
                # only to its first attempt; retries start a fresh thread.
                candidates[0] = dict(candidates[0], resume=args.resume)
            attempts = []
            absolute_deadline = time.monotonic() + args.deadline if args.deadline is not None else None
            for candidate in candidates:
                candidate_client = candidate["client"]
                if absolute_deadline is not None and time.monotonic() >= absolute_deadline:
                    result = RunResult(task_id=run_id, agent_id=candidate["id"], client=candidate_client, model=candidate.get("model") or "", direction=args.direction, status="timeout", duration_seconds=float(args.deadline), error="absolute deadline exceeded", refusal="technical_failure")
                    attempts.append(asdict(result))
                    break
                budget = args.deadline if args.deadline is not None else int(config.get("timeout_seconds", 900))
                if budget <= 0:
                    raise ValueError("--deadline must be positive")
                deadline = absolute_deadline
                locks = []
                slot = None
                try:
                    for index in range(max(1, int(candidate.get("max_parallel", 1)))):
                        locks.append(open(lock_dir / f"{candidate_client}-{index}.lock", "a+"))
                    slot = wait_for_client_slot(locks, candidate_client,
                                                events_jsonl=args.events_jsonl, deadline=deadline)
                    if slot == "deadline":
                        result = RunResult(task_id=run_id, agent_id=candidate["id"], client=candidate_client, model=candidate.get("model") or "", direction=args.direction, status="timeout", duration_seconds=float(args.deadline), error="absolute deadline exceeded while waiting for client slot", refusal="technical_failure")
                    if slot == "deadline":
                        preflight_result = None
                    else:
                        preflight_result = preflight_agent(candidate) if candidate.get("preflight") else None
                    if slot == "deadline":
                        pass
                    elif preflight_result and not preflight_result["available"]:
                        result = RunResult(task_id=run_id, agent_id=candidate["id"], client=candidate_client,
                                           model=candidate.get("model") or "", direction=args.direction,
                                           status="unavailable", duration_seconds=0,
                                           error="preflight failed: " + preflight_result["reason"],
                                           refusal="technical_failure")
                    else:
                        remaining = max(1, int(deadline-time.monotonic())) if deadline is not None else budget
                        result = isolated_invoke(dict(candidate, timeout_seconds=min(int(candidate.get("timeout_seconds", budget)), remaining)), task, workspace, run_dir / f"attempt-{len(attempts) + 1}",
                                                 min(budget, remaining), scope,
                                                 events_path=args.events_jsonl, absolute_deadline=deadline,
                                                 workspace_mode=workspace_mode)
                        candidate = {k: v for k, v in candidate.items() if k != "resume"}
                        # AGY policy blocks are phrasing-sensitive and probabilistic.
                        # Record the blocked turn, then retry once with the most neutral framing.
                        if (candidate_client == "agy" and result.status == "blocked_policy"
                                and not args.no_retry and args.prompt_style == "auto"
                                and prompt_style_for(candidate, task) != "standard"):
                            attempts.append(asdict(result))
                            result = isolated_invoke(candidate, dict(task, prompt_style="casual"), workspace,
                                                     run_dir / f"attempt-{len(attempts) + 1}",
                                                     max(1, int(deadline-time.monotonic())) if deadline is not None else int(config.get("timeout_seconds", 900)), scope,
                                                     events_path=args.events_jsonl, absolute_deadline=deadline,
                                                     workspace_mode=workspace_mode)
                        # Explicit, configured fallback model on the same client. Gemini's
                        # prompt filter is provider-specific, so a non-Gemini model on the
                        # same CLI usually completes the task. The fallback is never silent:
                        # both attempts and the final model are recorded in the receipt.
                        fallback = candidate.get("fallback")
                        if (result.status == "blocked_policy" and isinstance(fallback, dict)
                                and not args.no_retry):
                            alt = {**candidate, **fallback}
                            if client_available(alt)[0]:
                                attempts.append(asdict(result))
                                alt_task = dict(task, prompt_style="standard")
                                result = isolated_invoke(alt, alt_task, workspace,
                                                         run_dir / f"attempt-{len(attempts) + 1}",
                                                         max(1, int(deadline-time.monotonic())) if deadline is not None else int(config.get("timeout_seconds", 900)), scope,
                                                         events_path=args.events_jsonl, absolute_deadline=deadline,
                                                         workspace_mode=workspace_mode)
                finally:
                    for lock in locks:
                        lock.close()
                attempts.append(asdict(result))
                if result.status not in {"error", "timeout", "hung", "blocked_permissions",
                                         "blocked_policy", "unavailable"}:
                    break
                # Deterministic failures must not burn another candidate: the
                # same source workspace fails for every agent, and a policy
                # block is provider-level — rerouting is the coordinator's call.
                if str(result.error).startswith("workspace setup failed"):
                    break
                if result.status == "blocked_policy":
                    break
                if len(attempts) >= 2:
                    break
            front = args.front or os.environ.get("DEFEX_CTF_FRONT") or result.agent_id
            role = args.role or os.environ.get("DEFEX_CTF_ROLE") or ""
            ports = args.ports or os.environ.get("DEFEX_CTF_PORTS") or ""
            for attempt in attempts:
                attempt.update({"front": front, "role": role, "ports": ports})
            record = {"run_id": run_id, "status": result.status, "front": front, "role": role, "ports": ports, "requested_client": args.client, "input_prompt": prompt,
                      "workspace_mode": workspace_mode,
                      "prompt_transformation": "workspace and client-specific framing, scope, and output contract are prepended/appended; AGY briefs are neutralized outside code spans",
                      "manifest_truncated": bool(getattr(result, "manifest_truncated", False)),
                      "attempts": attempts,
                      "attribution_note": "Client invocation recorded locally; model ID is configured and is not provider-attested."}
            receipt_file = run_dir / "receipt.json"
            if args.events_jsonl:
                append_relay_event(args.events_jsonl, "status", f"delegate finished: {result.status}")
            receipt_file.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            receipt_file.chmod(0o600)
            output = asdict(result)
            # Sync-back only makes sense with a private copy: direct mode already
            # writes the real directory, scratch has no source dir to sync to.
            synced = _sync_artifacts(result, workspace) if args.sync_artifacts and workspace_mode == "copy" else []
            if workspace_mode != "direct" and not args.sync_artifacts and result.artifacts:
                print("WARNING: artifacts remain in the private workspace and may be pruned", file=sys.stderr)
            pruned = None
            if not args.keep_workspaces and os.environ.get("DEFEX_AUTO_PRUNE", "1") != "0":
                pruned = prune_run_workspaces(state_dir, only_run_ids={run_id})
            output.update({"receipt": run_id, "receipt_path": str(receipt_file), "attempts": attempts,
                           "requested_client": args.client, "synced_artifacts": synced,
                           "workspaces_pruned": pruned,
                           "manifest_truncated": bool(getattr(result, "manifest_truncated", False))})
            print(json.dumps(output, ensure_ascii=False))
            return 0 if result.status == "success" else 1
        if args.command == "zcode":
            agent = next((a for a in config["agents"] if a.get("client") == "zcode"), None)
            if agent is None:
                raise ValueError("no ZCode client is configured")
            binary = agent.get("command", "node")
            entrypoint = agent.get("entrypoint")
            if not shutil.which(binary) or (entrypoint and not Path(entrypoint).is_file()):
                raise ValueError(f"ZCode CLI is unavailable: {binary} {entrypoint}")
            args_tail = {"login": ["login", "zai"], "tui": ["tui"], "doctor": ["doctor", "--json"]}[args.action]
            if args.action == "tui":
                workspace = Path(args.workspace).resolve()
                if not workspace.is_dir():
                    raise ValueError(f"workspace directory does not exist: {workspace}")
                args_tail += ["--cwd", str(workspace)]
            env = os.environ.copy()
            env.update(_zcode_environment(agent))
            completed = subprocess.run([binary, *([entrypoint] if entrypoint else []), *args_tail], env=env, check=False)
            return completed.returncode
        if args.command == "score":
            report_path = Path(args.report).resolve()
            report = json.loads(report_path.read_text(encoding="utf-8"))
            matches = [r for r in report.get("results", [])
                       if r.get("task_id", "").removesuffix(".retry") == args.task and r.get("agent_id") == args.agent]
            if len(matches) != 1:
                raise ValueError(f"expected one result for task={args.task!r}, agent={args.agent!r}; found {len(matches)}")
            if args.false_findings < 0 or (args.useful_seconds is not None and args.useful_seconds < 0):
                raise ValueError("scoring counts and durations must be non-negative")
            matches[0]["evaluation"] = {"correctness": args.correctness, "useful_seconds": args.useful_seconds,
                                         "false_findings": args.false_findings, "note": args.note}
            report["summary"] = summarize_from_dicts(report["results"])
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            report_path.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8")
            print(f"Updated benchmark scoring in {report_path}")
            return 0
        if args.command == "agents":
            for agent in config["agents"]:
                available, reason = client_available(agent)
                model = agent.get("model")
                if agent.get("client") == "zcode":
                    from .core import zcode_selection
                    model, selection_error = zcode_selection(agent)
                    reason = reason or selection_error
                verified = bool(model) if agent.get("client") == "zcode" else agent.get("model_verified", False)
                print(json.dumps({"id": agent["id"], "client": agent["client"], "model": model,
                                  "model_verified": agent.get("model_verified", False) if agent.get("client") == "zcode" else verified,
                                  "model_selected": bool(model) if agent.get("client") == "zcode" else None,
                                  "headless_available": available,
                                  "auth_status": agent.get("auth_status", "unknown"),
                                  "reason": reason or ""}, ensure_ascii=False))
            return 0
        tasks = load_task_file(args.task_file)
        workspace = Path(args.workspace).resolve()
        if not workspace.is_dir():
            raise ValueError(f"workspace directory does not exist: {workspace}")
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        outdir = Path(args.out).resolve() / run_id
        report = execute_tasks(config, tasks, outdir, workspace, args.dry_run, args.command == "benchmark",
                               getattr(args, "verify", False))
        print(f"Run: {outdir}")
        print(f"Results: {json.dumps(report['summary'], ensure_ascii=False)}")
        print(f"Report: {outdir / 'report.md'}")
        return 0
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

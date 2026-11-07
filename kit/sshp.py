#!/usr/bin/env python3
"""sshp — non-interactive SSH command runner (no sshpass needed).

usage:
  sshp host user password -- 'cmd'
  sshp host user --key ~/.ssh/id_ed25519 -- 'cmd'
  sshp host user password --check          # auth only
  sshp host user password --upload local:/remote
  sshp host user password --download /remote:local

Env: KOTH_SSH_PORT (default 22), KOTH_SSH_TIMEOUT (default 15).
Exit codes: 0 ok, 2 auth/connect failure, 3 remote command error.
"""
import os
import sys
import argparse

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.stderr.write("sshp: paramiko is required (pip install paramiko)\n")
    sys.exit(2)


def connect(host, user, password=None, key=None, port=22, timeout=15):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=host, port=port, username=user, timeout=timeout,
              allow_agent=False, look_for_keys=False,
              banner_timeout=timeout, auth_timeout=timeout)
    if key:
        kw["key_filename"] = os.path.expanduser(key)
    else:
        kw["password"] = password or ""
    c.connect(**kw)
    return c


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("password", nargs="?", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--port", type=int, default=int(os.environ.get("KOTH_SSH_PORT", 22)))
    ap.add_argument("--timeout", type=float, default=float(os.environ.get("KOTH_SSH_TIMEOUT", 15)))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--upload", default=None, help="local:/remote")
    ap.add_argument("--download", default=None, help="/remote:local")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    cmd = " ".join(a.cmd).strip()
    if cmd.startswith("--"):
        cmd = cmd[2:].strip()

    try:
        c = connect(a.host, a.user, a.password, a.key, a.port, a.timeout)
    except Exception as e:
        print(f"AUTH_FAIL: {e!r}", file=sys.stderr)
        return 2

    try:
        if a.check:
            print("AUTH_OK")
            return 0
        if a.upload:
            local, _, remote = a.upload.partition(":")
            sftp = c.open_sftp()
            sftp.put(os.path.expanduser(local), remote)
            sftp.close()
            print(f"UPLOADED {local} -> {remote}")
            return 0
        if a.download:
            remote, _, local = a.download.rpartition(":")
            sftp = c.open_sftp()
            sftp.get(remote, os.path.expanduser(local))
            sftp.close()
            print(f"DOWNLOADED {remote} -> {local}")
            return 0
        if not cmd:
            cmd = "id"
        _in, out, err = c.exec_command(cmd, timeout=max(30, a.timeout))
        sys.stdout.write(out.read().decode(errors="replace"))
        e = err.read().decode(errors="replace")
        if e.strip():
            sys.stderr.write(e)
        return 0
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())

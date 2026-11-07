#!/usr/bin/env python3
"""telnet_probe — IAC-aware telnet client for CTF service probing.

Handles option negotiation so the banner/login prompt becomes readable, then
optionally authenticates and runs commands.

usage:
  telnet_probe.py HOST PORT                    # banner only (8s)
  telnet_probe.py HOST PORT --user u --pass p  # login + `id; hostname`
  telnet_probe.py HOST PORT --user u --pass p --cmd 'uname -a'
  telnet_probe.py HOST PORT --raw              # dump raw bytes hex

Read-only by design: sends only the commands you pass (default `id`).
"""
import argparse
import socket
import sys
import time

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


def negotiate(sock, data):
    """Answer telnet negotiation; return (clean_text, reply_bytes)."""
    reply = bytearray()
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= len(data):
            break
        cmd = data[i + 1]
        if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
            opt = data[i + 2]
            if cmd == DO:
                reply += bytes([IAC, WONT, opt])
            elif cmd == WILL:
                reply += bytes([IAC, DONT, opt])
            i += 3
        elif cmd == SB:
            j = i + 2
            while j + 1 < len(data) and not (data[j] == IAC and data[j + 1] == SE):
                j += 1
            i = j + 2
        else:
            i += 2
    return bytes(out), bytes(reply)


def recv_until(sock, needles, timeout=8.0, hard_deadline=None):
    """Read until any needle appears, timeout, or hard deadline."""
    buf = bytearray()
    end = time.time() + timeout if hard_deadline is None else hard_deadline
    sock.settimeout(0.4)
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        clean, reply = negotiate(sock, chunk)
        if reply:
            try:
                sock.sendall(reply)
            except OSError:
                pass
        buf += clean
        low = bytes(buf).lower()
        if any(n.lower() in low for n in needles):
            break
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--user", default=None)
    ap.add_argument("--pass", dest="password", default=None)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--raw", action="store_true")
    a = ap.parse_args()

    s = socket.create_connection((a.host, a.port), timeout=a.timeout)
    banner = recv_until(s, [b"login:", b"username:", b"Password:", b"#", b"$"],
                        timeout=a.timeout)
    if a.raw:
        print(banner.hex(" "))
        s.close()
        return 0
    sys.stdout.write("--- banner ---\n" + banner.decode(errors="replace") + "\n")

    if not a.user:
        s.close()
        return 0

    low = banner.lower()
    if b"login:" in low or b"username:" in low:
        s.sendall(a.user.encode() + b"\r\n")
    else:
        s.sendall(a.user.encode() + b"\r\n")
    recv_until(s, [b"password:"], timeout=a.timeout)
    s.sendall((a.password or "").encode() + b"\r\n")
    after = recv_until(s, [b"$", b"#", b">", b"denied", b"incorrect"], timeout=a.timeout)
    sys.stdout.write("--- after login ---\n" + after.decode(errors="replace") + "\n")
    s.sendall(a.cmd.encode() + b"\r\n")
    out = recv_until(s, [b"$", b"#", b"EOF"], timeout=6.0)
    sys.stdout.write("--- command ---\n" + out.decode(errors="replace") + "\n")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

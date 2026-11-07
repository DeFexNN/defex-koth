#!/usr/bin/env python3
"""Minimal MCP server (stdio, stdlib only) wrapping ctf.py functions.

Lets opencode / codex-with-mcp / any MCP client call THM tools natively.
If your agent has no MCP support — just use `ctf.py ... --json` via shell,
it returns the same data.

Run:  python3 mcp_server.py
Config (opencode.json / codex): {"mcpServers": {"ctf": {"command": "python3", "args": ["/abs/path/mcp_server.py"]}}}
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
CTF = str(HERE / "ctf.py")

TOOLS = [
    {"name": "thm_show_room", "description": "Show all tasks/questions of a TryHackMe room. Input: room URL or slug.",
     "inputSchema": {"type": "object", "properties": {"room": {"type": "string"}, "only_unsolved": {"type": "boolean"}}, "required": ["room"]}},
    {"name": "thm_show_task", "description": "Show one task detail.",
     "inputSchema": {"type": "object", "properties": {"room": {"type": "string"}, "task": {"type": "integer"}}, "required": ["room", "task"]}},
    {"name": "thm_submit", "description": "Submit a flag/answer to TryHackMe.",
     "inputSchema": {"type": "object", "properties": {"room": {"type": "string"}, "task": {"type": "integer"}, "q": {"type": "integer"}, "answer": {"type": "string"}}, "required": ["room", "task", "answer"]}},
    {"name": "thm_download", "description": "Download a room task attachment (task) or a direct file URL (url).",
     "inputSchema": {"type": "object", "properties": {"room": {"type": "string"}, "task": {"type": "integer"}, "url": {"type": "string"}}, "required": ["room"]}},
    {"name": "thm_auth_status", "description": "Check TryHackMe session validity.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def run_ctf(*argv) -> dict:
    try:
        r = subprocess.run([sys.executable, CTF, *argv, "--json"],
                           capture_output=True, text=True, timeout=90)
        try:
            return json.loads(r.stdout or "{}")
        except Exception:
            return {"raw": (r.stdout or "")[-2000:], "stderr": (r.stderr or "")[-2000:], "code": r.returncode}
    except Exception as e:
        return {"error": str(e)}


def handle(req: dict) -> dict | None:
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "ctf-tool", "version": "1.0"}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = req.get("params", {})
        name, a = p.get("name"), p.get("arguments", {}) or {}
        if name == "thm_show_room":
            args = ["show", str(a.get("room", ""))]
            if a.get("only_unsolved"):
                args.append("--only-unsolved")
            data = run_ctf(*args)
        elif name == "thm_show_task":
            data = run_ctf("task", "--room", str(a.get("room")), "--task", str(a.get("task")))
        elif name == "thm_submit":
            data = run_ctf("submit", "--room", str(a.get("room")), "--task", str(a.get("task", 1)),
                            "--q", str(a.get("q", 1)), "--answer", str(a.get("answer", "")))
        elif name == "thm_download":
            args = ["download", "--room", str(a.get("room", ""))]
            if a.get("task") is not None:
                args += ["--task", str(a["task"])]
            if a.get("url"):
                args += ["--url", str(a["url"])]
            data = run_ctf(*args)
        elif name == "thm_auth_status":
            data = run_ctf("auth", "--status")
        else:
            data = {"error": f"unknown tool {name}"}
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)[:12000]}]}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"no method {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

"""HackTheBox client (official API v4, token based). Minimal for agents."""
from __future__ import annotations
import os
import re
import requests

BASE = "https://labs.hackthebox.com/api/v4"


def parse_input(s: str) -> tuple[str, str]:
    """('machine'|'challenge'|'unknown', slug). Accepts htb: prefix, full URLs, bare slugs."""
    raw = s.strip()
    low = raw.lower()
    if low.startswith("htb:"):
        raw = raw[4:]
        low = raw.lower()
    kind = "unknown"
    if "challenge" in low:
        kind = "challenge"
    elif "machine" in low:
        kind = "machine"
    m = re.search(r"hackthebox\.com/(?:machines|challenges?)/([A-Za-z0-9_-]+)", raw, re.I)
    if m:
        return kind if kind != "unknown" else "machine", m.group(1)
    m = re.search(r"hackthebox\.com/\S*?([A-Za-z0-9_-]{2,})\s*$", raw)
    if "hackthebox" in low and m:
        return kind, m.group(1)
    return kind, raw.strip("/")


def token() -> str:
    return os.environ.get("HTB_API_TOKEN", "") or _from_config()


def _from_config() -> str:
    try:
        import json
        from pathlib import Path
        fp = Path.home() / ".config" / "ctf-tool" / "config.json"
        if fp.exists():
            return json.loads(fp.read_text()).get("htb_token", "")
    except Exception:
        pass
    return ""


def _h() -> dict:
    return {"Authorization": f"Bearer {token()}", "Accept": "application/json"}


def _items(resp_key: str, data: dict) -> list:
    info = data.get("info") if isinstance(data, dict) else None
    if isinstance(info, list):
        return info
    d = data.get("data") if isinstance(data, dict) else None
    if isinstance(d, list):
        return d
    return data if isinstance(data, list) else []


def machines(limit=20) -> dict:
    r = requests.get(f"{BASE}/machine/list", headers=_h(), timeout=25)
    return {"http": r.status_code, "data": r.json() if "application/json" in r.headers.get("Content-Type", "") else r.text[:500]}


def challenges(limit=20) -> dict:
    r = requests.get(f"{BASE}/challenge/list", headers=_h(), timeout=25)
    return {"http": r.status_code, "data": r.json() if "application/json" in r.headers.get("Content-Type", "") else r.text[:500]}


def find(url_or_slug: str) -> dict:
    """Match an htb: URL/slug against machines+challenges lists. Needs token."""
    if not token():
        return {"ok": False, "error": "no HTB token",
                "fix": "export HTB_API_TOKEN=<app.hackthebox.com API token>  (Profile Settings -> API)"}
    kind, slug = parse_input(url_or_slug)
    out = {"ok": True, "kind_hint": kind, "slug": slug, "match": None}
    if slug.isdigit():
        out["match"] = {"id": int(slug)}
        return out
    seen = []
    for name, fn in (("machines", machines), ("challenges", challenges)):
        try:
            items = _items(name, fn().get("data", {}))
        except Exception:
            continue
        for it in items:
            nm = str(it.get("name", ""))
            if nm.lower() == slug.lower().replace("-", " ") or nm.lower().replace(" ", "-") == slug.lower():
                out["match"] = {"list": name, "id": it.get("id"), "name": nm}
                return out
            seen.append(nm)
    out["match"] = None
    out["hint"] = f"no exact match for '{slug}'"
    out["available_sample"] = seen[:30]
    return out


def submit_flag(machine_id: int, flag: str, difficulty_id: int = 1) -> dict:
    # HTB v4: POST /machine/own with {"id":..,"flag":..,"difficulty_id":..}
    r = requests.post(f"{BASE}/machine/own", headers={**_h(), "Content-Type": "application/json"},
                      json={"id": machine_id, "flag": flag, "difficulty_id": difficulty_id}, timeout=25)
    try:
        return {"http": r.status_code, "data": r.json()}
    except Exception:
        return {"http": r.status_code, "data": r.text[:500]}

"""THM client — TryHackMe rooms for AI agents.

Auth: connect.sid session cookie (user joins room in browser once,
then exports session via `ctf auth`).
Endpoints (observed / historical, with v2 first, v1 fallback):
  GET  /api/v2/rooms/tasks?roomCode=X
  GET  /api/v2/rooms/details?roomCode=X
  POST /api/v2/rooms/join | POST /api/v2/rooms/answer | POST /api/v2/check
  GET  /api/tasks/<room>  (legacy, needs connect.sid)
  POST /api/<room>/answer (legacy form: answer, questionNo, taskNo + CSRF-Token)
  GET  /api/room/details?codes=X&loadUser=true
  GET  /jr/<room> (join)
Only stdlib + requests.
"""
from __future__ import annotations
import json
import os
import re
import time
import urllib.parse
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://tryhackme.com"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ctf-tool/1.0"}

CSRF_INPUT = re.compile(r'name="_csrf"\s+value="(.{36})"')
CSRF_INPUT2 = re.compile(r'value="([a-f0-9-]{36})"[^>]*name="_csrf"|name="_csrf"[^>]*value="([a-f0-9-]{36})"')
CSRF_SCRIPT = re.compile(r'csrfToken\s*=\s*["\'](.{36})["\']')
ATTACH_RE = re.compile(r'href="([^"]*(?:/api/[^\"]*download[^\"]*|/assets/[^\"]*|/room/[^\"]*/files/[^\"]*|https?://[^"]*\.zip[^"]*|https?://[^"]*\.pcap[^"]*|https?://[^"]*\.txt[^"]*))"', re.I)
TASK_HDR_RE = re.compile(r'Task\s+(\d+)\s*[—\-–:]*\s*(.*?)\s*(?:<|$)', re.I | re.S)


def parse_room_slug(url_or_slug: str) -> str:
    s = url_or_slug.strip()
    if "tryhackme.com" in s:
        m = re.search(r"/room(?:s)?/([A-Za-z0-9_-]+)", s)
        if m:
            return m.group(1)
    s = s.strip("/")
    m = re.search(r"([A-Za-z0-9_-]+)$", s)
    return m.group(1) if m else s


def config_path() -> Path:
    p = os.environ.get("CTF_TOOL_CONFIG")
    if p:
        return Path(p)
    return Path.home() / ".config" / "ctf-tool" / "config.json"


def load_session() -> dict:
    fp = config_path()
    if fp.exists():
        try:
            return json.loads(fp.read_text())
        except Exception:
            return {}
    return {}


def save_session(d: dict) -> Path:
    fp = config_path()
    fp.parent.mkdir(parents=True, exist_ok=True)
    cur = load_session()
    cur.update(d)
    fp.write_text(json.dumps(cur, indent=2))
    try:
        os.chmod(fp, 0o600)
    except Exception:
        pass
    return fp


def make_http(connect_sid: str = "") -> requests.Session:
    s = requests.Session()
    retry = Retry(total=4, backoff_factor=1.0, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update(UA)
    s.headers.update({"Accept": "application/json"})
    if connect_sid:
        # connect.sid may be raw or URL-encoded (s%3A...)
        s.cookies.set("connect.sid", connect_sid, domain="tryhackme.com", path="/")
    return s


def auth_check(sess: requests.Session) -> tuple[bool, dict]:
    """Validate session via lightweight endpoint."""
    try:
        r = sess.get(f"{BASE}/message/unseen", headers={"Accept": "application/json"}, timeout=20)
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            try:
                j = r.json()
                if isinstance(j, dict) and j.get("success"):
                    return True, j
            except Exception:
                pass
        # fallback: v2 self
        r2 = sess.get(f"{BASE}/api/v2/users/self", timeout=20)
        if r2.status_code == 200 and "application/json" in r2.headers.get("Content-Type", ""):
            try:
                return True, r2.json()
            except Exception:
                return True, {}
        return False, {"http": r.status_code}
    except Exception as e:
        return False, {"error": str(e)}


def get_csrf(sess: requests.Session, room: str) -> str:
    try:
        r = sess.get(f"{BASE}/room/{room}", headers={"Accept": "text/html"}, timeout=25)
        html = r.text or ""
        m = CSRF_SCRIPT.search(html)
        if m:
            return m.group(1)
        m = CSRF_INPUT.search(html)
        if m:
            return m.group(1)
        m = CSRF_INPUT2.search(html)
        if m:
            return m.group(1) or m.group(2)
    except Exception:
        pass
    return ""


def _jget(sess: requests.Session, url: str, timeout=25):
    r = sess.get(url, timeout=timeout)
    ct = r.headers.get("Content-Type", "")
    if r.status_code == 200 and "application/json" in ct:
        try:
            return r.json(), None
        except Exception as e:
            return None, f"bad-json: {e}"
    return None, f"http-{r.status_code}: {r.text[:300]}"


def fetch_tasks(sess: requests.Session, room: str) -> tuple[dict | None, str]:
    """Try v2 -> v1 -> details. Returns (normalized, source)."""
    # 1. v2 tasks
    j, _ = _jget(sess, f"{BASE}/api/v2/rooms/tasks?roomCode={urllib.parse.quote(room)}")
    if isinstance(j, dict):
        data = j.get("data", j)
        if isinstance(data, list):
            return normalize_v2(room, {"data": {"tasks": data}}), "v2/tasks"
        tasks = data.get("tasks") or data.get("roomTasks") or j.get("tasks")
        if tasks:
            return normalize_v2(room, j), "v2/tasks"
    # 2. legacy tasks
    j, _ = _jget(sess, f"{BASE}/api/tasks/{urllib.parse.quote(room)}")
    if isinstance(j, dict) and ("data" in j or "tasks" in j):
        return normalize_v1(room, j), "v1/tasks"
    # 3. room details (may embed tasks)
    j, _ = _jget(sess, f"{BASE}/api/room/details?codes={urllib.parse.quote(room)}&loadUser=true")
    if isinstance(j, dict) and room in j:
        return normalize_v1(room, {"data": j[room].get("tasks", []), "_room": j[room]}), "v1/details"
    j, _ = _jget(sess, f"{BASE}/api/v2/rooms/details?roomCode={urllib.parse.quote(room)}")
    if isinstance(j, dict):
        return normalize_v2(room, j), "v2/details"
    return None, "no-endpoint-worked (need valid connect.sid / joined room)"


def normalize_v1(room: str, j: dict) -> dict:
    raw = j.get("data", [])
    out_tasks = []
    if isinstance(raw, list):
        for i, t in enumerate(raw, 1):
            infos = t.get("tasksInfo") or t.get("questions") or []
            qs = []
            for k, q in enumerate(infos, 1):
                qs.append({
                    "q_no": q.get("questionNo", k),
                    "question": q.get("question", q.get("title", "")),
                    "hint": q.get("hint", ""),
                    "solved": bool(q.get("correct", False)),
                    "answer_format": q.get("answerFormat", q.get("format", "")),
                })
            out_tasks.append({
                "task_no": t.get("taskNo", i),
                "title": t.get("taskTitle", t.get("title", f"Task {i}")),
                "description": t.get("task", t.get("description", "")),
                "upload_id": t.get("uploadId", "") or "",
                "has_file": bool(t.get("uploadId")),
                "solved": all(x["solved"] for x in qs) if qs else bool(t.get("completed", False)),
                "questions": qs,
            })
    elif isinstance(raw, dict):
        pass
    meta = j.get("_room", {}) if isinstance(j.get("_room"), dict) else {}
    total = j.get("totalTasks", len(out_tasks))
    unsolved = [t for t in out_tasks if not t["solved"]]
    return {"room": room, "title": meta.get("title", room), "source": "v1",
            "total_tasks": total, "tasks": out_tasks,
            "unsolved_task_nos": [t["task_no"] for t in unsolved]}


def normalize_v2(room: str, j: dict) -> dict:
    data = j.get("data", j) if isinstance(j, dict) else {}
    if isinstance(data, list):
        data = {"tasks": data}
    tasks_raw = data.get("tasks") or data.get("roomTasks") or []
    out_tasks = []
    for i, t in enumerate(tasks_raw, 1):
        qs_raw = t.get("questions") or t.get("tasksInfo") or []
        qs = []
        for k, q in enumerate(qs_raw, 1):
            prog = q.get("progress", {}) if isinstance(q.get("progress"), dict) else {}
            solved = q.get("correct", prog.get("correct", q.get("completed", q.get("solved", False))))
            qs.append({
                "q_no": q.get("questionNo", q.get("no", k)),
                "question": q.get("question", q.get("title", "")),
                "hint": q.get("hint", ""),
                "solved": bool(solved),
                "answer_format": q.get("answerFormat", q.get("format", "")),
            })
        out_tasks.append({
            "task_no": t.get("taskNo", t.get("taskNumber", i)),
            "_id": t.get("_id", ""),
            "title": t.get("title", t.get("taskTitle", f"Task {i}")),
            "description": t.get("description", t.get("task", "")),
            "upload_id": t.get("uploadId", "") or "",
            "has_file": bool(t.get("uploadId")),
            "solved": all(x["solved"] for x in qs) if qs else bool(t.get("completed", False)),
            "questions": qs,
        })
    title = data.get("title", data.get("roomTitle", room))
    unsolved = [t for t in out_tasks if not t["solved"]]
    return {"room": room, "title": title, "source": "v2",
            "total_tasks": len(out_tasks), "tasks": out_tasks,
            "unsolved_task_nos": [t["task_no"] for t in unsolved]}


def _browser_headers(sess: requests.Session, room: str) -> dict:
    """Browser-like headers required by the v2 answer endpoint."""
    h = {"Content-Type": "application/json",
         "Origin": BASE, "Referer": f"{BASE}/room/{room}"}
    try:
        r = sess.get(f"{BASE}/api/v2/auth/csrf", timeout=20)
        tok = r.json().get("data", {}).get("token", "")
        if tok:
            h["CSRF-Token"] = tok
            h["X-CSRF-Token"] = tok
    except Exception:
        pass
    return h


def task_object_id(sess: requests.Session, room: str, task_no: int) -> str:
    data, _ = fetch_tasks(sess, room)
    if data:
        for t in data.get("tasks", []):
            if int(t.get("task_no", -1)) == int(task_no) and t.get("_id"):
                return t["_id"]
    # fallback: raw lookup
    try:
        r = sess.get(f"{BASE}/api/v2/rooms/tasks?roomCode={urllib.parse.quote(room)}", timeout=25)
        d = r.json().get("data", {})
        ts = d.get("tasks", []) if isinstance(d, dict) else d
        for t in ts:
            if int(t.get("taskNo", t.get("id", -1))) == int(task_no):
                return t.get("_id", "")
    except Exception:
        pass
    return ""


def submit_answer(sess: requests.Session, room: str, task_no: int, q_no: int,
                  answer: str, csrf: str = "") -> dict:
    answer = answer.strip()
    attempts = []
    H = _browser_headers(sess, room)
    # Primary: v2 answer with task ObjectId (what the web client sends)
    tid = task_object_id(sess, room, task_no)
    if tid:
        p = {"roomCode": room, "taskId": tid, "questionNo": int(q_no), "answer": answer}
        try:
            r = sess.post(f"{BASE}/api/v2/rooms/answer", json=p, headers=H, timeout=25)
            ct = r.headers.get("Content-Type", "")
            if "application/json" in ct:
                j = r.json()
                if isinstance(j, dict):
                    attempts.append({"via": "v2/rooms/answer+oid", "resp": j})
                    data = j.get("data", {}) if isinstance(j.get("data"), dict) else {}
                    if data.get("isCorrect") is True or j.get("correct") is True:
                        j["_via"] = "v2/rooms/answer"
                        return j
                    if j.get("status") == "success" and data.get("isCorrect") is False:
                        j["_via"] = "v2/rooms/answer"  # wrong flag, definitive
                        return j
        except Exception as e:
            attempts.append({"via": "v2/rooms/answer+oid", "error": str(e)})
    else:
        attempts.append({"via": "task_object_id", "error": "no _id found"})
    # Fallbacks: v2 JSON first
    payloads_v2 = [
        (f"{BASE}/api/v2/rooms/answer",
         {"roomCode": room, "taskId": task_no, "questionNo": q_no, "answer": answer}),
        (f"{BASE}/api/v2/rooms/answer",
         {"roomCode": room, "taskNo": task_no, "questionNo": q_no, "answer": answer}),
        (f"{BASE}/api/v2/check",
         {"roomCode": room, "taskNo": task_no, "questionNo": q_no, "answer": answer}),
    ]
    for url, payload in payloads_v2:
        try:
            h = dict(H)
            if csrf:
                h["CSRF-Token"] = csrf
                payload = dict(payload, _csrf=csrf)
            r = sess.post(url, json=payload, headers=h, timeout=25)
            ct = r.headers.get("Content-Type", "")
            if "application/json" in ct:
                try:
                    j = r.json()
                except Exception:
                    continue
                if not isinstance(j, dict):
                    continue
                attempts.append({"via": url, "payload_keys": sorted(payload.keys()), "resp": j})
                if j.get("correct") is True or j.get("status") == "success" or j.get("success") is True:
                    j["_via"] = url
                    j["_attempts"] = attempts
                    return j
                # error -> try next method
                continue
        except Exception as e:
            attempts.append({"via": url, "error": str(e)})
            continue
    # Legacy form endpoint
    try:
        if not csrf:
            csrf = get_csrf(sess, room)
        h = {"CSRF-Token": csrf} if csrf else {}
        # legacy uses form data
        r = sess.post(f"{BASE}/api/{room}/answer",
                      data={"answer": answer, "questionNo": str(q_no), "taskNo": str(task_no)},
                      headers=h, timeout=25)
        ct = r.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                j = r.json()
                j["_via"] = "v1/answer"
                return j
            except Exception:
                pass
        return {"success": False, "correct": False, "_via": "v1/answer",
                "_attempts": attempts, "http": r.status_code, "body": r.text[:500]}
    except Exception as e:
        return {"success": False, "error": str(e), "_attempts": attempts}


RATE_LIMIT_MARKERS = ("going too fast", "too many requests", "rate limit", "slow down", "try again later")


def classify_submit(res: dict) -> str:
    """correct | wrong | rate_limited | error.

    THM answers with HTTP 200 + status/error text when throttled, so the
    distinction matters: `error` is not a wrong answer and must be retried.
    """
    if not isinstance(res, dict):
        return "error"
    data = res.get("data", {}) if isinstance(res.get("data"), dict) else {}
    if data.get("isCorrect") is True or res.get("correct") is True:
        return "correct"
    if data.get("isCorrect") is False or res.get("correct") is False:
        return "wrong"
    blob = json.dumps(res, ensure_ascii=False).lower()
    if res.get("http") == 429 or any(m in blob for m in RATE_LIMIT_MARKERS):
        return "rate_limited"
    if res.get("status") == "success" or res.get("success") is True:
        return "correct"
    return "error"


def submit_with_retry(sess: requests.Session, room: str, task_no: int, q_no: int,
                      answer: str, retries: int = 3, gap: float = 60.0) -> dict:
    """Submit with backoff on rate limiting / transient errors."""
    retries = max(1, int(retries))
    last: dict = {}
    for attempt in range(1, retries + 1):
        res = submit_answer(sess, room, task_no, q_no, answer)
        verdict = classify_submit(res)
        last = {"verdict": verdict, "response": res, "attempt": attempt}
        if verdict in ("correct", "wrong"):
            return last
        if attempt < retries:
            time.sleep(max(1.0, float(gap)))
    return last


def list_task_files(sess: requests.Session, room: str) -> list[dict]:
    """All task attachments with their real filenames (resolves signed URLs)."""
    data, _ = fetch_tasks(sess, room)
    out: list[dict] = []
    for t in (data or {}).get("tasks", []):
        if not t.get("has_file"):
            continue
        info = task_download_url(sess, room, t["task_no"],
                                 task_id=t.get("_id", ""), upload_id=t.get("upload_id", ""))
        out.append({"task_no": t["task_no"], "title": t["title"],
                    "filename": info.get("filename", ""), "ok": bool(info.get("ok")),
                    "error": info.get("error", "")})
    return out


def room_object_id(sess: requests.Session, room: str) -> str:
    """Room _id (not the roomCode slug) — required by the download endpoint."""
    j, _ = _jget(sess, f"{BASE}/api/v2/rooms/details?roomCode={urllib.parse.quote(room)}")
    if isinstance(j, dict):
        d = j.get("data", j)
        if isinstance(d, dict):
            return d.get("_id", "") or ""
    return ""


def task_download_url(sess: requests.Session, room: str, task_no: int,
                      task_id: str = "", upload_id: str = "") -> dict:
    """Resolve a task attachment to a signed S3 URL.

    Observed endpoint (v2):
      GET /api/v2/rooms/tasks/download?roomId=<room _id>&taskId=<task _id>&downloadId=<uploadId>
      -> {"status":"success","data":{"url":"https://...s3.../name.ext?X-Amz-..."}}
    """
    if not task_id or not upload_id:
        data, _ = fetch_tasks(sess, room)
        for t in (data or {}).get("tasks", []):
            if int(t.get("task_no", -1)) == int(task_no):
                task_id = task_id or t.get("_id", "")
                upload_id = upload_id or t.get("upload_id", "")
                break
    if not (task_id and upload_id):
        return {"ok": False, "error": f"task {task_no} has no attachment", "task_no": task_no}
    rid = room_object_id(sess, room)
    if not rid:
        return {"ok": False, "error": "room _id not found (not enrolled / bad slug)", "task_no": task_no}
    q = urllib.parse.urlencode({"roomId": rid, "taskId": task_id, "downloadId": upload_id})
    try:
        r = sess.get(f"{BASE}/api/v2/rooms/tasks/download?{q}",
                     headers={"Accept": "application/json"}, timeout=30)
        j = r.json()
    except Exception as e:
        return {"ok": False, "error": f"resolve failed: {e}", "task_no": task_no}
    data = j.get("data", {}) if isinstance(j, dict) else {}
    url = data.get("url", "") if isinstance(data, dict) else ""
    if not url:
        return {"ok": False, "error": "no url in download response",
                "task_no": task_no, "response": j if isinstance(j, dict) else str(j)[:300]}
    name = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]) or f"task{task_no}"
    return {"ok": True, "task_no": task_no, "url": url, "filename": name,
            "task_id": task_id, "upload_id": upload_id, "room_id": rid}


def download_task(sess: requests.Session, room: str, task_no: int,
                  dest: str = "", dest_dir: str = "") -> dict:
    """Download one task attachment; default dir assets/<room>/."""
    info = task_download_url(sess, room, task_no)
    if not info.get("ok"):
        return info
    if dest:
        target = Path(dest)
        if target.is_dir() or str(dest).endswith(("/", os.sep)):
            target = target / info["filename"]
    else:
        base = Path(dest_dir) if dest_dir else (Path(__file__).parent / "assets" / room)
        target = base / info["filename"]
    res = download_file(sess, info["url"], target)
    return {**info, **res}


def download_file(sess: requests.Session, url: str, dest: Path) -> dict:
    if not url.startswith("http"):
        url = BASE + (url if url.startswith("/") else "/" + url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sess.get(url, stream=True, timeout=60, headers={"Accept": "*/*"}) as r:
            if r.status_code != 200:
                return {"ok": False, "http": r.status_code, "url": url}
            total = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(65536):
                    if chunk:
                        f.write(chunk)
                        total += len(chunk)
        return {"ok": True, "path": str(dest), "bytes": total, "url": url}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}


def join_room(sess: requests.Session, room: str) -> dict:
    out = {}
    try:
        r = sess.get(f"{BASE}/jr/{room}", timeout=25, allow_redirects=False)
        out["jr_status"] = r.status_code
    except Exception as e:
        out["jr_error"] = str(e)
    try:
        r = sess.post(f"{BASE}/api/v2/rooms/join", json={"roomCode": room},
                      headers={"Content-Type": "application/json"}, timeout=25)
        try:
            out["v2_join"] = r.json()
        except Exception:
            out["v2_join_http"] = r.status_code
    except Exception as e:
        out["v2_error"] = str(e)
    return out

# ctf-tool — дивись таски THM і сабміть флаги без браузера

Зроблено для ШІ-агентів (codex, opencode, будь-який shell-агент) + для людини.
Ти один раз приєднуєшся до руми в браузері, тул один раз забирає сесію —
далі агент працює тільки по посиланню.

## Швидкий старт (ти, людина)

```bash
cd ~/defex-koth/ctf-tool

# 1. Сесія — один з варіантів:
python3 ctf.py auth --from-chrome --json        # якщо цей же ПК і Chrome
python3 ctf.py auth --cookies ~/cookies.txt --json
python3 ctf.py auth --sid "<connect.sid з DevTools>" --json

# 2. Перевірка:
python3 ctf.py auth --status --json

# 3. Далі агент сам, приклад:
python3 ctf.py show https://tryhackme.com/room/ctfcollectionvol1 --only-unsolved --json
python3 ctf.py task --room ctfcollectionvol1 --task 2 --json
python3 ctf.py download --room ctfcollectionvol1 --task 3 --json
python3 ctf.py download --room ctfcollectionvol1 --all --json
python3 ctf.py submit --room ctfcollectionvol1 --task 2 --q 1 --answer "THM{...}" --json
python3 ctf.py submit-batch --room ctfcollectionvol1 --file results.json --json
python3 ctf.py verify-results --room ctfcollectionvol1 --task 2 --file results.json --json
python3 ctf.py claims take --dir .claims --task 2 --q 4 --owner muse --json
```

## Платформа

- TryHackMe — основна: URL `tryhackme.com`, префікс `thm:` або голий slug.
- HackTheBox — лише явно: URL `hackthebox.com` або префікс `htb:`.
- Якщо префікс суперечить URL (наприклад `htb:https://tryhackme.com/...`),
  тул повертає `platform prefix conflicts with URL host` (exit 4) і НЕ вгадує платформу.

## Як агент має це юзати

Читай `SKILL.md` — там готовий інструктаж для codex/opencode.
Коротко: `show <url> --only-unsolved --json` → `task` → `download` →
розв'язати локально → `submit`. MCP-сервер (`mcp_server.py`) — опція,
CLI з `--json` працює всюди і є основним.

## King of the Hill (`koth`)

Тонкі обгортки над локальним KOTH-OPS kit. Шлях до kit не зашитий:
`--kit-dir` → `CTF_KOTH_KIT`/`KOTH_KIT_DIR` → `KOTH_OPS_DIR`/`CTF_KOTH_OPS`
→ `~/Projects/KOTH-OPS` (підкаталоги `kit`, `kit-capture`, `kit-guard`, `kit-retake`).

```bash
cp koth.conf.example koth.conf && $EDITOR koth.conf
python3 ctf.py koth discover --config koth.conf --json
python3 ctf.py koth capture  --config koth.conf --dry-run --json
python3 ctf.py koth retake   --config koth.conf --timeout 90 --json
python3 ctf.py koth watch    --config koth.conf --interval 5 --json
python3 ctf.py koth verify   --config koth.conf --json
python3 ctf.py koth report   --config koth.conf --out report.md --json
```

`--config` обов'язковий; без нього команда відмовляється працювати (exit 4).
Якщо скрипт kit відсутній — `kit not installed` (exit 3). Інакше повертається
exit-код самого скрипта. `retake --timeout` передається в `retake.sh`
(очікування на цикл), а не обмежує процес.

## Файли

- `ctf.py` — CLI (точка входу, argparse, людський + `--json` вивід)
- `thm.py` — TryHackMe API клієнт (v2 → v1 fallback, CSRF, ретраї)
- `htb.py` — HackTheBox API v4 (токен `HTB_API_TOKEN`, машини/чалленджі/сабміт)
- `mcp_server.py` — MCP stdio-обгортка без залежностей
- `SKILL.md` — інструкція для агентів
- `assets/` — сюди качаються файли румів

## Залежності

Тільки `requests`. `pip install -r requirements.txt`

# defex-koth

Оркестратор для **King of the Hill** (TryHackMe / HackTheBox lab battle): делегує
AI-клієнти (codex, agy, zcode CLI) як паралельні фронти, автоматично проводить
кік-оф (`koth auto`), тримає пагорб гардом і веде чек-ріпорти (receipts) на кожен
запуск. Все призначено **тільки для авторизованих лабораторій** — CTF/KotH
змагання, де ти маєш явний дозвіл на ціль.

Репозиторій зібрано «під ноль» з бойового defex-ctf: рушій оркестрації
(`ctf_orchestrator/`), пайплайн авто-кік-офу (`ctf-tool/`), оперативний кіт
(`kit/`) і плейбуки (`docs/`).

## З чого це складається

| Частина | Що це |
|---|---|
| `ctf_orchestrator/` | Ядро: `delegate` (запуск клієнта як субагента з relay-потоком подій), `koth`-routing (`koth:<ip>` → авто-кік-оф), `hold-watch` (гард пагорба), receipts, слоти паралельності, milestone-детектор |
| `ctf-tool/` | Пайплайн `koth auto <ip>`: рекона, фінгерпринт, вектори, захват, фікс, гарди, звіт — все як JSON-степи |
| `kit/` | Оперативні скрипти: check-env, triage артефактів, sshp/telnet_probe, fastroot, guard-петля, делегаційна дошка (board/mission/swarm) |
| `docs/` | PLAYBOOK (бойова доктрина) і PLAYBOOK-V2 (повний оперативний плейбук) |
| `config/` | Приклади конфігурації: `agents.example.yaml`, `opencode.example.json` |

## Встановлення

```bash
git clone https://github.com/DeFexNN/defex-koth.git
cd defex-koth
pip install -e .          # або просто тримай PYTHONPATH на корені репо
cp config/agents.example.yaml config/agents.yaml   # і підлаштуй під себе
```

Потреби: Python ≥3.11, `PyYAML`. Обов'язковий набір інструменту цілі — nmap,
curl, ssh, стандартний pentest-мінімум (`kit/check-env.sh` перевірить).

### AI-клієнти (обери свої)

- **codex** — CLI `codex` (OpenAI), залогінений (`codex login`). Головний
  атакувальний/аналітичний фронт.
- **agy** — CLI `agy` (Gemini). Аналітик/верифікатор; фільтр провайдера чутливий
  до «жорстких» формулювань — оркестратор сам переформулює бриф (casual style).
- **zcode** — CLI `zcode-cli`. Опційний третій фронт.

У `config/agents.yaml` для кожного агента задається `client`, `model`,
`reasoning_effort`, `max_parallel` (скільки паралельних делегацій тримає агент),
`idle_timeout_seconds` (watchdog на завислі запуски) тощо.

## Швидкий старт

### 1. Авторизація цілі

Тільки тиж target, який тобі належить у змаганні. KotH-режим вмикається
тригером `koth`:

```bash
echo "koth: 10.10.153.63" | ./defex-ctf delegate codex
# або напряму пайплайном:
python3 ctf-tool/ctf.py koth auto 10.10.153.63 --json
# або кіт-врапером:
./kit/koth 10.10.153.63
```

`koth auto` виконує повний цикл: preflight → скан → тріаж сервісів →
делегація фронтів (web/pwn/cred) → фіксація флагів → утримання. Кожен степ
пише JSON, фінальний звіт — у `~/.local/state/defex-ctf/` та state-дереві цілі.

### 2. Делегування фронтів вручну

```bash
# Задача на stdin; workspace = каталог, де клієнт працює НАПРЯМУ (копій нема);
# без --workspace клієнт отримає порожній scratch-каталог.
echo "TASK: ..." | ./defex-ctf delegate codex --workspace ~/state/10.10.153.63/web --front web

# Живий потік подій (reasoning/команди/майлстоуни) у JSONL:
echo "TASK: ..." | ./defex-ctf delegate codex --events-jsonl /tmp/front.jsonl

# Фонова паралельність: слоти визначає max_parallel (за замовч. 8 для codex);
# коли слоти зайняті, делегат пише в потік "slot wait: ..." — черга видима.
```

Кожен запуск повертає **receipt JSON** (stdout): статус, спроби, модель,
команди, артефакти, `client_thread` (для продовження), `question` (якщо клієнт
запитав рішення). Receipt зберігається як
`~/.local/state/defex-ctf/runs/<id>/receipt.json`.

### 3. Продовження треду і питання

```bash
# Клієнт закінчив з "QUESTION:"? Дай відповідь у тому ж треді:
echo "Plan B" | ./defex-ctf delegate codex --resume <client_thread>

# Успішний закритий тред продовжується лише з явним --new-task:
echo "Write FINDINGS.md" | ./defex-ctf delegate codex --resume <thread> --new-task
```

### 4. Утримання пагорба

```bash
# Гард: перевіряє king-файл щосекунди, відновлює при зміні (тamper-test).
./defex-ctf hold-watch --file /root/king --log ~/state/10.10.153.63/hold.log --interval 5
```

Сценарій повного циклу утримання — `kit/guard/` (install-guard.sh +
koth-guard.sh: 5-секундна петля + cron) і розділ «After root» у docs/PLAYBOOK.md.

### 5. Receipts і прибирання

```bash
./defex-ctf receipt <run-id>          # повний звіт запуску
./defex-ctf receipt <run-id> --summary
./defex-ctf runs --since 2026-11-05T00:00 --json
./defex-ctf prune --keep-days 7       # прибрати робочі каталоги старих ранів
```

## Milestones і доктрина

Оркестратор сканує потік клієнта на сигнали (root/foothold, initial shell,
credentials, flag) і емітить `milestone`-події. Це **невереніфіковані leads** —
перевіряй по receipt/live-доказах перш ніж діяти. KotH-правило: як тільки
foothold підтверджено, атака/рекон на той вектор припиняється — тримай і
зачhardни вектор, інших агентів зганяй на нейтралізацію конкурентів.

Повна доктрина: `docs/PLAYBOOK.md` (тригер-послідовність, SLO, делегаційний
протокол A–H) та `docs/PLAYBOOK-V2.md` (детальний оперативний цикл).

## Балансування акаунтів codex (необов'язково)

Якщо користуєшся агрегатором [codexctl], додай агенту codex поле
`account_aggregator: codexctl`: кожна НОВА делегація обере акаунт з найменш
витраченим 5-годинним лімітом (`CODEX_HOME` на процес — паралельнобезпечно).
Тред продовжується на тому акаунті, що його створив (айдіішник акаунта пишеться
в receipt).

## Інтеграція з OpenCode (необов'язково)

`config/opencode.example.json` — приклад командного агента (defex), який кличе
клієнтів через relay-тулки як нативних субагентів. Це частина бойового сетапу
автора; без OpenCode репозиторій повноцінно працює як CLI.

## Тести

```bash
TMPDIR=$(mktemp -d) python3 -m unittest discover -s tests -v
```

## Безпека і межі

- **Тільки авторизовані цілі.** Один хост на змагання; жодних DoS, жодного
  втручання в скоринг. Артефакти вважай недовіреними, не запускай невідомі
  бінарники на хості.
- Ніколи не коміть `koth-user`, токени платформ (THM/HTB), приватні ключі,
  receipts з реальних боїв. Усі креденшели — через env/локальні конфіги,
  які git ігнорує.

[codexctl]: https://github.com/DeFexNN

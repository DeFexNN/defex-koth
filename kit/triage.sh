#!/usr/bin/env bash
# triage.sh — immediate artifact triage (KotH / CTF).
# Use on ANY file that lands on disk (image, archive, binary, blob) BEFORE
# deeper recon. Read-only: extracts into a temp dir, never modifies the input.
#
# usage: triage.sh FILE [FILE...]
#        triage.sh --dir DIR        (triage every file < 8 MB, max 200)
#        triage.sh -q FILE          (quiet: only hits)
#
# Exit: 0 always unless usage error. Hits are printed with [HIT] / [CRED].
set -u

QUIET=0
FILES=()
if [ "${1:-}" = "-q" ] || [ "${1:-}" = "--quiet" ]; then QUIET=1; shift; fi
if [ "${1:-}" = "--dir" ]; then
  [ -n "${2:-}" ] || { echo "usage: triage.sh --dir DIR" >&2; exit 2; }
  while IFS= read -r f; do FILES+=("$f"); done < <(find "$2" -maxdepth 4 -type f -size -8M 2>/dev/null | head -200)
elif [ $# -gt 0 ]; then
  FILES=("$@")
else
  echo "usage: triage.sh [-q] FILE... | --dir DIR" >&2
  exit 2
fi

say() { [ "$QUIET" = 1 ] || echo "$@"; }

carve() {
  # appended gzip/tar/zip/7z payloads at the tail of a file
  python3 - "$1" <<'PY'
import sys, gzip, io, tarfile, zipfile
p = sys.argv[1]
try:
    d = open(p, "rb").read()
except OSError:
    sys.exit(0)
lo = max(0, len(d) - 262144)
found = False
for off in range(lo, len(d) - 1):
    sig = d[off:off+4]
    if sig[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(d[off:])
        except Exception:
            continue
        print(f"[HIT] gzip @ {off} ({len(raw)}B)")
        print("      " + repr(raw[:240]))
        try:
            t = tarfile.open(fileobj=io.BytesIO(raw))
            for m in t.getmembers():
                print(f"      tar member: {m.name} ({m.size}B)")
                if m.isfile() and m.size < 8192:
                    body = t.extractfile(m).read()
                    print("      " + repr(body[:300]))
                    found = True
        except Exception:
            pass
        found = True
        break
    if sig[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(d[off:]))
            print("[HIT] zip @ %d: %s" % (off, ", ".join(z.namelist())[:200]))
            found = True
        except Exception:
            pass
if not found:
    pass
PY
}

for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  kind=$(file -b "$f" 2>/dev/null | cut -c1-100)
  say "== $f (${sz}B) :: $kind"

  # 1) signatures
  if command -v binwalk >/dev/null 2>&1; then
    bw=$(binwalk "$f" 2>/dev/null | grep -vE '^DECIMAL|^----|^$' | head -8)
    [ -n "$bw" ] && say "$bw"
  fi

  # 2) metadata
  if command -v exiftool >/dev/null 2>&1; then
    exiftool -q -Comment -Description -Author -Software -Title -UserComment "$f" 2>/dev/null | head -8
  fi

  # 3) printable strings with security-relevant words
  strings -n 6 "$f" 2>/dev/null | grep -aiE 'passw|creden|user(name)?[:=]|thm\{|flag\{|htb\{|api[_-]?key|token|secret|BEGIN .*PRIVATE KEY' | head -10

  # 4) steghide (non-interactive, empty passphrase)
  if command -v steghide >/dev/null 2>&1; then
    si=$(steghide info -sf "$f" -p '' 2>&1 | grep -aiE 'embedded|file|capacity' | head -3)
    [ -n "$si" ] && say "$si"
    tmp=$(mktemp -d)
    if steghide extract -sf "$f" -p '' -xf "$tmp/x" -f >/dev/null 2>&1 && [ -s "$tmp/x" ]; then
      echo "[HIT] steghide payload:"; head -c 300 "$tmp/x"; echo
      file -b "$tmp/x"
    fi
    rm -rf "$tmp"
  fi

  # 5) appended payloads
  carve "$f"
done

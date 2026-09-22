---
title: "LogJammer — Windows Event-Log Reconstruction of Interactive Access, Scheduled-Task Persistence, and Firewall Log Clearing"
seoTitle: "LogJammer — Windows Event-Log Reconstruction and Persistence"
description: "HTB Sherlock case study reconstructing a single-host Windows event-log timeline with Chainsaw: interactive logon, discovery-tool detection, audit-policy tampering, scheduled-task persistence, and Firewall log clearing."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-14"
tags:
  - dfir
  - windows-event-logs
  - incident-response
objective: "Reconstruct a defensible single-host incident timeline from Windows event-log artifacts and identify initial access, persistence, command-and-control, and defense-evasion activity."
tools:
  - chainsaw
  - grep
skill: "Windows event-log forensic correlation with Chainsaw"
outcome: "Confirmed single-host defense-evasion chain: interactive logon, discovery-tool detection and quarantine, outbound C2 firewall rule, audit-policy change, scheduled-task persistence, and Firewall log clearing."
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Single Windows endpoint; supplied evidence limited to Windows event logs |
| Starting position | Provided evidence: Security, System, Windows Firewall, Windows Defender-Operational, and PowerShell-Operational event logs |
| Objective | Reconstruct a defensible single-host incident timeline from Windows event-log artifacts and identify initial access, persistence, command-and-control, and defense-evasion activity |
| Outcome | Confirmed single-host chain from interactive logon to Firewall log clearing |

## One host, twenty-five minutes, five log sources

LogJammer is a Hack The Box Sherlock that reconstructs a single-host Windows incident from Security, System, Windows Firewall, Windows Defender, and PowerShell event logs analyzed with Chainsaw. Correlating an interactive logon, a Defender detection-and-remediation pair, an outbound firewall rule, an audit-policy change, scheduled-task creation, a PowerShell hash computation, and a channel-clear event yields one bounded timeline. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Interactive logon (4624) → discovery-tool detection and quarantine (Defender 1116/1117) → outbound C2 firewall rule (2004) → audit-policy change (4719) → scheduled-task persistence (4698) → PowerShell hash computation (4104) → Firewall log cleared (System 104)**

## Provided logs and the incident question

- **Target environment:** a single Windows endpoint; the supplied evidence is limited to Windows event logs.
- **Provided evidence:** Security, System, Windows Firewall, Windows Defender-Operational, and PowerShell-Operational `.evtx` logs.
- **Tooling:** Chainsaw for EVTX searches with `grep` text filtering.
- **Objective:** reconstruct a defensible incident timeline and identify initial access, persistence, command-and-control, and defense-evasion activity.
- **Constraints:** analysis is confined to the supplied artifacts. All timestamps are recorded as they appear in the logs, in UTC (`Z` suffix).

## Evidence: one timeline from five event logs

### 1. Interactive Logon Anchor

Observation: Security event ID 4624 records successful logons; the first matching record is an interactive logon from a local console.

Action: searched the Security log for 4624 records and filtered for the account.

```bash
chainsaw search -t 'Event.System.EventID: =4624' Security.evtx --skip-errors | grep -i '<ACCOUNT>' -A 20 -B 20
```

```text
SystemTime: 2023-03-27T14:37:09.879891Z
TargetUserName: <ACCOUNT>
LogonType: 2
LogonProcessName: 'User32 '
```

Significance: logon type 2 identifies an interactive session and `User32` a local-console logon, anchoring the start of the incident so later activity can be correlated to that session.

Result: the first successful interactive logon occurred at `2023-03-27 14:37:09 UTC`. The filter returned four records, two logons each logged twice, at `14:37:09` and `14:38:32`.

### 2. Discovery-Tool Detection and Quarantine

Observation: Defender operational events separate detection (ID 1116) from the action taken (ID 1117).

Action: searched the Defender log for detection events, then for remediation events.

```bash
chainsaw search -t 'Event.System.EventID: =1116' "Windows Defender-Operational.evtx" --skip-errors -q | grep -E 'SystemTime:|Threat Name:|Path:'
```

```text
SystemTime: 2023-03-27T14:42:34.290935Z
Threat Name: HackTool:PowerShell/SharpHound.B
SystemTime: 2023-03-27T14:42:34.292716Z
Threat Name: HackTool:MSIL/SharpHound!MSR
Path: file:_C:\Users\<ACCOUNT>\Downloads\SharpHound-v1.1.0.zip->SharpHound.exe
```

```bash
chainsaw search -t 'Event.System.EventID: =1117' "Windows Defender-Operational.evtx" --skip-errors -q | grep -E 'SystemTime:|Threat Name:|Action Name:'
```

```text
SystemTime: 2023-03-27T14:42:48.352659Z
Threat Name: HackTool:MSIL/SharpHound!MSR
Action Name: Quarantine
```

Significance: ID 1116 records detection only, while ID 1117 records the resulting action, so keeping them distinct prevents a detection from being read as remediation. The recorded detection path tied the alert to a SharpHound archive under the account's Downloads folder.

Result: Defender detected a SharpHound package at `2023-03-27 14:42:34 UTC` and quarantined the executable 14 seconds later at `14:42:48 UTC`.

### 3. Outbound C2 Firewall Rule

Observation: Windows Firewall event ID 2004 records a rule addition whose remote port and direction describe the permitted traffic.

Action: searched the Firewall log for 2004 records and filtered on the remote port.

```bash
chainsaw search -t 'Event.System.EventID: =2004' "Windows Firewall-Firewall.evtx" --skip-errors | grep '4444' -A 20 -B 20
```

```text
SystemTime: 2023-03-27T14:44:43.415702Z
RuleName: Metasploit C2 Bypass
RemotePorts: '4444'
Direction: 2
ModifyingApplication: C:\Windows\System32\mmc.exe
```

Significance: direction value 2 indicates outbound traffic in the recorded event semantics (`1` inbound, `2` outbound). An outbound rule for port 4444 created through the management console (`mmc.exe`) is consistent with a command-and-control bypass.

Result: the outbound rule `Metasploit C2 Bypass` for port 4444 was added at `2023-03-27 14:44:43 UTC` through `mmc.exe`.

### 4. Audit-Policy Tampering

Observation: Security event ID 4719 records an audit-policy change together with the affected subcategory.

Action: searched all supplied event logs for 4719 records.

```bash
chainsaw search -t 'Event.System.EventID: =4719' <EVENT_LOG_DIRECTORY> --skip-errors
```

```text
EventID: 4719
SystemTime: 2023-03-27T14:50:03.721835Z
SubcategoryId: '%%12804'
AuditPolicyChanges: '%%8449'
```

Significance: the subcategory code `%%12804` maps to Other Object Access Events in Microsoft's audit configuration protocol documentation, so the change modified auditing for that subcategory.

Result: the audit policy was changed at `2023-03-27 14:50:03 UTC` for the Other Object Access Events subcategory.

### 5. Scheduled-Task Persistence

Observation: Security event ID 4698 records scheduled-task creation, and the event's task content carries the command and arguments to be executed.

Action: searched all supplied event logs for 4698 records and reviewed the task content.

```bash
chainsaw search -t 'Event.System.EventID: =4698' <EVENT_LOG_DIRECTORY> --skip-errors
```

```text
EventID: 4698
SystemTime: 2023-03-27T14:51:21.481720Z
SubjectUserName: <ACCOUNT>
TaskName: \HTB-AUTOMATION
```

The same event's task-content XML recorded the command and arguments:

```text
<Command>C:\Users\<ACCOUNT>\Desktop\Automation-HTB.ps1</Command>
<Arguments>-A <ACCOUNT>@<DOMAIN></Arguments>
```

Significance: a scheduled task that invokes a PowerShell script from a user-desktop path is durable persistence that survives the interactive session, matching MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task).

Result: the task `\HTB-AUTOMATION` was created at `2023-03-27 14:51:21 UTC`, running `Automation-HTB.ps1` from the account's Desktop with an email-style argument.

### 6. PowerShell Execution Record

Observation: PowerShell script-block logging (event ID 4104) records the file-hash command executed against the scheduled-task script; module script blocks add substantial noise.

Action: filtered 4104 events for the incident window and excluded known module noise.

```bash
chainsaw search -t 'Event.System.EventID: =4104' Powershell-Operational.evtx --skip-errors -q | grep -E 'SystemTime:|ScriptBlockText:' | grep -v 'cmdletization'
```

```text
SystemTime: 2023-03-27T14:58:33.364769Z
ScriptBlockText: Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
```

Significance: script-block logging supplies the execution context for the command, and the recorded block computes a file hash over the scheduled-task script.

Result: a hash computation over the task script is recorded at `2023-03-27 14:58:33 UTC`.

### 7. Firewall Log Clearing

Observation: System event ID 104 records a channel-clear event, and the channel field identifies which log was cleared.

Action: searched the System log for 104 records.

```bash
chainsaw search -t 'Event.System.EventID: =104' System.evtx --skip-errors -q | grep -E 'SystemTime:|Channel:|SubjectUserName'
```

```text
SystemTime: 2023-03-27T15:01:56.515836Z
SubjectUserName: <ACCOUNT>
Channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
```

Significance: event ID 104 is a generic channel-clear event, so the channel field is required before assigning the affected log; here it identifies the Firewall channel. A Security log-clear event (ID 1102) at `14:36` predates the first logon and is unrelated.

Result: the Firewall log channel was cleared at `2023-03-27 15:01:56 UTC` by `<ACCOUNT>`.

### 8. Incident Timeline Correlation

Observation: each artifact places its records on a shared UTC clock, so the events can be ordered into a single sequence.

Action: correlated the identified records across the Security, Defender, Firewall, PowerShell, and System logs by timestamp.

| Time (UTC) | Artifact | Event |
|---|---|---|
| 2023-03-27 14:37:09 | Security 4624 | First interactive logon for `<ACCOUNT>` (`LogonType 2`) |
| 2023-03-27 14:38:32 | Security 4624 | Second logon |
| 2023-03-27 14:42:34 | Defender 1116 | SharpHound package detected |
| 2023-03-27 14:42:48 | Defender 1117 | Action: `Quarantine` |
| 2023-03-27 14:44:43 | Firewall 2004 | Outbound rule `Metasploit C2 Bypass` for port 4444 added |
| 2023-03-27 14:50:03 | Security 4719 | Audit policy changed to Other Object Access Events |
| 2023-03-27 14:51:21 | Security 4698 | Task `\HTB-AUTOMATION` created |
| 2023-03-27 14:58:33 | PowerShell 4104 | `Get-FileHash` over the task script |
| 2023-03-27 15:01:56 | System 104 | Firewall log channel cleared by `<ACCOUNT>` |

Significance: the events chain within roughly 25 minutes on a single host, spanning an interactive logon, discovery tooling, an outbound command-and-control rule, persistence, and anti-forensics.

Result: the supplied artifacts support a single ordered incident sequence on `2023-03-27`.

## Noise, detection versus remediation, and a pre-logon clear

- Module-generated PowerShell script blocks produced substantial noise, so I dropped known module noise before reviewing the incident window.
- Defender event ID 1116 was treated as detection only; the separate 1117 event supplied the recorded quarantine action, avoiding a false remediation claim.
- A Security log-clear event (ID 1102) at `14:36` preceded the first logon, so I excluded it from the incident chain as pre-logon noise.

## Outcome: a confirmed defense-evasion chain

The logs document a confirmed single-host defense-evasion sequence on `2023-03-27`. Limitations: I could not verify the SharpHound output or any exfiltration, the effects of the scheduled-task script, or whether other channels were cleared.

## Recommendations: user-path tooling, firewall changes, audit tampering, persistence, and response

The actions are recommendations; none was validated.

1. **Untrusted tooling executed from a user profile.** A SharpHound package ran from the account's Downloads folder, and Defender quarantined it 14 seconds after detection. *Recommendation:* restrict execution from user download and desktop paths through application control. *Detection:* correlate Defender detections with execution from user-writable paths. *Validation:* confirm the archive, executable, and script are all quarantined.
2. **Unmonitored local firewall changes.** An outbound rule for port 4444 was added through `mmc.exe` from an interactive session. *Recommendation:* restrict local firewall-rule creation and remove the added rule. *Detection:* review event 2004 rules with outbound direction and external ports, then hunt egress on that port.
3. **Audit-policy and log tampering.** An audit subcategory was changed and the Firewall channel was cleared, degrading the available evidence. *Recommendation:* protect audit policy through Group Policy and restrict channel clearing. *Detection:* correlate event 4719 with channel-clear events 104 and 1102. *Validation:* recover cleared telemetry from centralized logging or backups.
4. **Durable scheduled-task persistence.** A scheduled task invoked a PowerShell script from a user-desktop path. *Recommendation:* restrict task creation and review existing tasks. *Detection:* watch event 4698 for tasks that reference user-profile scripts.
5. **Response readiness.** *Recommendation:* isolate the host, remove the task and outbound rule, restore the approved audit policy, rotate the affected account credentials, and review directory activity for follow-on discovery.

## References

- [Hack The Box — LogJammer Sherlock](https://app.hackthebox.com/sherlocks/LogJammer) (retired Sherlock)
- [MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1562.002 — Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)
- [Group Policy: Audit Configuration Protocol (Microsoft)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [Chainsaw — EVTX detection and hunting tool (project repository)](https://github.com/WithSecureLabs/chainsaw)
- [GNU grep](https://www.gnu.org/software/grep/)

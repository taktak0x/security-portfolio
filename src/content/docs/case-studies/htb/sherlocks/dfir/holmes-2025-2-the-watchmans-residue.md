---
title: "HTB Sherlock: Holmes 2025 2: The Watchman's Residue"
description: "DFIR and SOC notes for the HTB Sherlock Holmes 2025 2 case, covering chat-based credential elicitation, TeamViewer access, tool staging, credential access, Winlogon persistence, and sensitive-file exfiltration."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-26"
tags:
  - dfir
  - soc
  - windows
  - credential-access
  - persistence
objective: "Walk through the forensic evidence in the Watchman's Residue Sherlock and answer its case questions."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
skill: "SOC analysis and DFIR investigation"
outcome: "Confirmed compromise with credential access, persistence, and sensitive-file exfiltration."
---

## At a glance

- Date: 2025-08-19 to 2025-08-20
- Difficulty: Medium
- Category: SOC / DFIR
- OS: Mixed
- Artifacts: `TRIAGE_IMAGE_COGWORK-CENTRAL`, `acquired file (critical).kdbx`, `msp-helpdesk-ai day 5982  section 5 traffic.pcapng`
- Tools: Wireshark, Timesketch, `keepass2john`, Hashcat

## Executive summary

The attacker used decommissioned host `WATSON-ALPHA-2` (`10.0.69.45`) to start a chat session with `MSP-HELPDESK-AI` at `10.128.0.3`. Prompt injection exposed RMM information, including credentials for `Central-WS`. The attacker then used TeamViewer to access CogWork Central Workstation, staged tools, harvested browser credentials, executed Mimikatz, created Winlogon persistence, and exfiltrated sensitive files.

Malicious RMM account was `James Moriarty`. Session source was `192.168.69.213`. Staged tools included `JM.exe`, Mimikatz, Everything, and WebBrowserPassView.

## Investigation

### Initial anomaly / triage

I examined the supplied packet capture to identify the chat session and find the high-volume endpoint.

```text
Address: 10.0.69.45
Packets: 1057
Bytes: 2326379
Tx Packets: 578
Tx Bytes: 86907
Rx Packets: 479
Rx Bytes: 2239472
```

Endpoint communicated with `10.128.0.3` over stream `19`. HTTP/JSON traffic exposed an OpenAI-compatible endpoint and attacker/AI conversation.

```text
ip.addr==10.0.69.45 && ip.addr==10.128.0.3 && http && json
```

Conclusion: decommissioned machine IP was `10.0.69.45`.

### Initial access / successful compromise

I checked the SMB host announcement against the chat session to link the host with the chat traffic.

```text
ip.addr==10.0.69.45 && smb
2025-08-19 11:45:20.985106249  10.0.69.45  10.255.255.255
BROWSER  Host Announcement WATSON-ALPHA-2, Workstation, Server, NT Workstation
```

Chat timeline showed the attacker identifying as WATSON, requesting RMM credentials, and eliciting credentials. First message was `Hello Old Friend`; last was `JM WILL BE BACK`.

The prompt injection timestamp was `2025-08-19T12:02:06.129Z`, formatted for the answer as `2025-08-19 12:02:06`.

Conclusion: compromised/decommissioned hostname: `WATSON-ALPHA-2`.

### Persistence / privilege escalation

I looked for persistence created after the TeamViewer session.

```text
datetime 2025-08-20T10:13:57+00:00
key_path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
command Userinit.exe, JM.exe
message ... Application: Userinit Command: Userinit.exe, JM.exe Trigger: Logon
```

MITRE mapping: `T1547.004: Winlogon Helper DLL`

Conclusion: `JM.exe` was configured to execute at logon at `2025-08-20 10:13:57`.

### Post-compromise activity (C2 / tooling / lateral movement)

TeamViewer connection records showed the attacker session:

```text
514162531  James Moriarty  20-08-2025 09:58:25  20-08-2025 10:14:27
Cogwork_Admin  RemoteControl  {7ca6431e-30f6-45e9-9ac6-0ef1e0cecb6a}
```

The TeamViewer log recorded local time as UTC+1. At the corresponding local time, the connection source was:

```text
2025/08/20 10:58:36.813  UDPv4: punch received a=192.168.69.213:55408
```

Tools were staged under `C:\Windows\Temp\safe\`:

```text
Everything-1.4.1.1028.x86.zip
JM.exe
mimikatz.exe
webbrowserpassview.zip
```

WebBrowserPassView application focus duration was `8125` ms, rounded to `8000` ms. Mimikatz execution was anchored by Prefetch creation at `2025-08-20T10:07:08.174475+00:00`. `dump.txt` was created, extended, and closed at `2025-08-20T10:08:06.370303+00:00`.

Sensitive files were sent from `C:\Windows\Temp\flyover\` beginning at local `2025/08/20 11:12:07.902`; normalized UTC start was `2025-08-20 10:12:07`. The Heisen-9 backup database was moved into the staged folder at `2025-08-20 10:11:09`.

### Defense evasion / anti-forensics

The supplied evidence did not establish any anti-forensics activity. I could not verify log clearing or timestomping, and the evidence points to credential access, tooling, persistence, and exfiltration.

## Timeline (UTC)

| Time (UTC) | Source | Event |
|---|---|---|
| `2025-08-19 11:39` | pcap | IT admin / Borock interaction begins |
| `2025-08-19 11:45:20` | SMB | Host announcement identifies `WATSON-ALPHA-2` |
| `2025-08-19 11:53` | pcap | Attacker sends `Hello Old Friend` |
| `2025-08-19 11:54` | pcap | User probes bot memory |
| `2025-08-19 11:56` | pcap | User identifies as WATSON |
| `2025-08-19 11:57` | pcap | `Its time for a revolution`; RMM credentials requested |
| `2025-08-19 12:00` | pcap | RMM troubleshooting requested |
| `2025-08-19 12:01` | pcap | Credentials successfully elicited |
| `2025-08-19 12:02:06` | pcap JSON | Prompt injection leaks remote management tool information |
| `2025-08-19 12:04` | pcap | `Revolution wont forget` |
| `2025-08-19 12:05` | pcap | `JM WILL BE BACK` |
| `2025-08-20 09:58:25` | `Connections_incoming.txt` | James Moriarty RMM session starts |
| `2025-08-20 10:07:08` | USN | Mimikatz Prefetch created |
| `2025-08-20 10:08:06` | USN | `dump.txt` created, extended, and closed |
| `2025-08-20 10:09:14` | UserAssist | WebBrowserPassView focus event |
| `2025-08-20 10:11:09` | USN | Heisen-9 backup database moved into staging |
| `2025-08-20 10:12:07` | TeamViewer | Sensitive-file exfiltration starts |
| `2025-08-20 10:13:57` | Registry | Winlogon persistence created |
| `2025-08-20 10:14:27` | `Connections_incoming.txt` | Malicious RMM session ends |

Note: `Connections_incoming.txt` uses UTC. Only `TeamViewer15_Logfile.log` uses host local time, UTC+1.

## Indicators / key evidence

| Type | Value | Context |
|---|---|---|
| IP | `10.0.69.45` | Decommissioned attacker machine |
| IP | `10.128.0.3` | MSP-HELPDESK-AI endpoint |
| IP | `192.168.69.213` | TeamViewer connection source |
| Host | `WATSON-ALPHA-2` | Decommissioned machine hostname |
| User | `James Moriarty` | RMM account used by attacker |
| File | `C:\Windows\Temp\safe\` | Tool staging path |
| File | `C:\Windows\Temp\flyover\` | Exfiltration staging path |
| File | `JM.exe` | Payload and Winlogon persistence |
| File | `mimikatz.exe` | OS credential dumping tool |
| File | `webbrowserpassview\WebBrowserPassView.exe` | Browser credential harvesting |
| Session | `19` | HTTP/JSON chat stream |

## MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | `T1547.004: Winlogon Helper DLL` | `Userinit.exe, JM.exe` |

## Assessment

Classification: Confirmed compromise

Severity: High: credential access, persistence, lateral-movement credentials, and sensitive-file exfiltration.

Affected account(s): `James Moriarty`; `Cogwork_Admin`; `Heisen-9-WS-6` credentials exposed.

Affected host(s): `WATSON-ALPHA-2`; CogWork Central Workstation; MSP-HELPDESK-AI.

Source: `10.0.69.45` for chat activity; `192.168.69.213` for TeamViewer activity.

Scope: Proven activity covers chat-based credential elicitation, TeamViewer access, tool staging, credential access, persistence, and exfiltration. Further lateral movement into CogWork-1 infrastructure is inferred from recovered credentials, but no additional host activity is established here.

## Recommended response

- Isolate CogWork Central Workstation and affected systems.
- Remove `JM.exe` Winlogon persistence.
- Rotate RMM, workstation, and recovered Heisen-9 credentials.
- Block and hunt `10.0.69.45` and `192.168.69.213`.
- Review sibling hosts and domain logs for lateral movement.
- Preserve packet capture, triage image, TeamViewer logs, registry evidence, USN records, and KeePass database.

## Detection opportunities

- Alert on OpenAI-compatible chat traffic from decommissioned hosts.
- Alert on TeamViewer access followed by writes to `C:\Windows\Temp\`.
- Hunt `mimikatz.exe`, `webbrowserpassview`, `JM.exe`, and `dump.txt`.
- Monitor Winlogon `Userinit` changes.
- Detect rapid file sends from temporary staging directories.

## Technical notes

- Wireshark endpoint statistics identified `10.0.69.45`; SMB host announcement supplied the hostname.
- `Connections_incoming.txt` timestamps are UTC; `TeamViewer15_Logfile.log` timestamps are local UTC+1.
- UserAssist reported `application_focus_duration 8125`; the answer is `8000` milliseconds, rounded to the nearest thousand.
- `keepass2john "acquired file (critical).kdbx" > kdbx.hash` extracted the KeePass hash. Hashcat mode `13400` cracked it with master password `cutiepie14`; entry `Heisen-9-WS-6` yielded `Werni:Quantum1!`.

## Sherlock answers

1. `10.0.69.45`
2. `WATSON-ALPHA-2`
3. `Hello Old Friend`
4. `2025-08-19 12:02:06`
5. `565963039:CogWork_Central_97&65`
6. `JM WILL BE BACK`
7. `2025-08-20 09:58:25`
8. `James Moriarty`
9. `192.168.69.213`
10. `C:\Windows\temp\safe\`
11. `8000` milliseconds
12. `2025-08-20 10:07:08`
13. `2025-08-20 10:12:07`
14. `2025-08-20 10:11:09`
15. `2025-08-20 10:08:06`
16. `2025-08-20 10:13:57`
17. `T1547.004`
18. `2025-08-20 10:14:27`
19. `Werni:Quantum1!`

## References

- `github:taktak0x/Study@main:Study/HTB/Sherlocks/Holmes-2025-2-The-Watchmans-Residue.md`
- HTB Sherlock: Holmes 2025 2: The Watchman's Residue
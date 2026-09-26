---
title: "HTB Sherlock: Holmes 2025 2: The Watchman's Residue"
description: "A chat-based prompt injection exposed RMM credentials, which led to a TeamViewer intrusion with credential theft, Winlogon persistence, and file exfiltration."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-26"
tags:
  - dfir
  - soc
  - windows
  - network-forensics
  - persistence
objective: "Analyse a packet capture and endpoint artifacts to reconstruct a prompt-injection intrusion from the first chat through credential access, persistence, and exfiltration."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
skill: "DFIR and SOC investigation across packet capture, registry, USN, and remote-management logs."
outcome: "Confirmed compromise."
---

## At a glance

Holmes 2025 2: The Watchman's Residue is a medium-difficulty Sherlock in the SOC / DFIR category, run on a mixed operating system environment. Activity spans 2025-08-19 to 2025-08-20. The supplied artifacts are a triage image, a KeePass database, and a packet capture. The tools I used were Wireshark, Timesketch, `keepass2john`, and Hashcat.

## Orientation

Target and attacker addresses are replaced with role-based placeholders; command syntax is preserved.

The attacker worked from `WATSON-ALPHA-2`, a decommissioned host, seen in the capture as `<TARGET_IP>`. It opened a chat session with `MSP-HELPDESK-AI`, a helpdesk AI endpoint at `<ATTACKER_IP>`. Prompt injection in that chat exposed remote management information, including credentials for the Central workstation. The attacker then used TeamViewer to reach the CogWork Central Workstation, staged tools, harvested browser credentials, ran Mimikatz, created Winlogon persistence, and moved sensitive files out.

The malicious RMM account was `James Moriarty`, and the TeamViewer connection source was `<TARGET_IP>`. Staged tools included `JM.exe`, Mimikatz, Everything, and WebBrowserPassView. The activity shows compromise, credential access, persistence, and exfiltration.

## Investigation

### Initial triage

I checked the supplied packet capture to find the chat session and the busiest endpoint.

```text
Address: <TARGET_IP>
Packets: 1057
Bytes: 2326379
Tx Packets: 578
Tx Bytes: 86907
Rx Packets: 479
Rx Bytes: 2239472
```

The endpoint talked with the helpdesk AI over stream `19`. HTTP/JSON traffic exposed an OpenAI-compatible endpoint and the conversation between the attacker and the AI.

```text
ip.addr==<ATTACKER_IP> && ip.addr==<TARGET_IP> && http && json
```

Conclusion: the decommissioned machine was `<TARGET_IP>`.

### Initial access

I correlated the SMB host announcement with the chat traffic.

```text
ip.addr==<TARGET_IP> && smb
```

An SMB host announcement at `2025-08-19 11:45:20.985106249` identified `WATSON-ALPHA-2` as a Workstation, Server, NT Workstation.

The chat timeline showed the attacker identifying as WATSON, asking for RMM credentials, and getting them. The first message was `Hello Old Friend`; the last was `JM WILL BE BACK`.

The prompt injection timestamp was `2025-08-19T12:02:06.129Z`, normalized as `2025-08-19 12:02:06`.

Conclusion: the compromised, decommissioned hostname was `WATSON-ALPHA-2`.

### Persistence

I looked for persistence created after the TeamViewer session.

```text
datetime 2025-08-20T10:13:57+00:00
key_path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
command Userinit.exe, JM.exe
message ... Application: Userinit Command: Userinit.exe, JM.exe Trigger: Logon
```

MITRE mapping: `T1547.004: Winlogon Helper DLL`.

Conclusion: `JM.exe` was set to run at logon at `2025-08-20 10:13:57`.

### Post-compromise activity

TeamViewer connection records showed the attacker session:

```text
514162531  James Moriarty  20-08-2025 09:58:25  20-08-2025 10:14:27
Cogwork_Admin  RemoteControl  {7ca6431e-30f6-45e9-9ac6-0ef1e0cecb6a}
```

The TeamViewer log recorded local time as UTC+1. At the matching local time, the connection source was:

```text
2025/08/20 10:58:36.813  UDPv4: punch received a=<TARGET_IP>:55408
```

Tools were staged under `C:\Windows\Temp\safe\`:

```text
Everything-1.4.1.1028.x86.zip
JM.exe
mimikatz.exe
webbrowserpassview.zip
```

WebBrowserPassView held application focus for `8125` ms, rounded to `8000` ms. Mimikatz execution was anchored by Prefetch creation at `2025-08-20T10:07:08.174475+00:00`. `dump.txt` was created, extended, and closed at `2025-08-20T10:08:06.370303+00:00`.

Sensitive files were sent from `C:\Windows\Temp\flyover\` starting at local `2025/08/20 11:12:07.902`; the UTC start was `2025-08-20 10:12:07`. The Heisen-9 backup database was moved into the staged folder at `2025-08-20 10:11:09`.

### Defense evasion

I could not verify any anti-forensics activity from the supplied evidence. The evidence supports credential access, tooling, persistence, and exfiltration. It does not show log clearing or timestomping.

## Evidence

### Timeline (UTC)

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

### Indicators

| Type | Value | Context |
|---|---|---|
| IP | `<TARGET_IP>` | Decommissioned attacker machine |
| IP | `<ATTACKER_IP>` | MSP-HELPDESK-AI endpoint |
| IP | `<TARGET_IP>` | TeamViewer connection source |
| Host | `WATSON-ALPHA-2` | Decommissioned machine hostname |
| User | `James Moriarty` | RMM account used by attacker |
| File | `C:\Windows\Temp\safe\` | Tool staging path |
| File | `C:\Windows\Temp\flyover\` | Exfiltration staging path |
| File | `JM.exe` | Payload and Winlogon persistence |
| File | `mimikatz.exe` | OS credential dumping tool |
| File | `webbrowserpassview\WebBrowserPassView.exe` | Browser credential harvesting |
| Session | `19` | HTTP/JSON chat stream |

### MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | `T1547.004: Winlogon Helper DLL` | `Userinit.exe, JM.exe` |

## Outcome

Classification: Confirmed compromise.

Severity: High. Credential access, persistence, lateral-movement credentials, and sensitive-file exfiltration.

Affected accounts: `James Moriarty`, `Cogwork_Admin`, and the exposed `Heisen-9-WS-6` credentials.

Affected hosts: `WATSON-ALPHA-2`, the CogWork Central Workstation, and `MSP-HELPDESK-AI`.

Scope: Proven activity covers chat-based credential elicitation, TeamViewer access, tool staging, credential access, persistence, and exfiltration. Recovered credentials point to further lateral movement into CogWork-1 infrastructure, but I could not verify any additional host activity in this evidence.

Recommended response:

- Isolate the CogWork Central Workstation and affected systems.
- Remove the `JM.exe` Winlogon persistence.
- Rotate RMM, workstation, and recovered Heisen-9 credentials.
- Block and hunt the two addresses involved.
- Review sibling hosts and domain logs for lateral movement.
- Preserve the packet capture, triage image, TeamViewer logs, registry evidence, USN records, and KeePass database.

Detection opportunities:

- Alert on OpenAI-compatible chat traffic from decommissioned hosts.
- Alert on TeamViewer access followed by writes to `C:\Windows\Temp\`.
- Hunt for `mimikatz.exe`, `webbrowserpassview`, `JM.exe`, and `dump.txt`.
- Monitor Winlogon `Userinit` changes.
- Detect rapid file sends from temporary staging directories.

Technical notes:

- Wireshark endpoint statistics identified `<TARGET_IP>`; the SMB host announcement supplied the hostname.
- `Connections_incoming.txt` timestamps are UTC; `TeamViewer15_Logfile.log` timestamps are local UTC+1.
- UserAssist reported `application_focus_duration 8125`, rounded to `8000` milliseconds.
- `keepass2john "acquired file (critical).kdbx" > kdbx.hash` extracted the KeePass hash. Hashcat mode `13400` cracked it with master password `<REDACTED_PASSWORD>`; the entry `Heisen-9-WS-6` yielded `<LAB_USER>:<REDACTED_PASSWORD>`.

## References

- MITRE ATT&CK T1547.004, Winlogon Helper DLL: https://attack.mitre.org/techniques/T1547/004/
- Wireshark: https://www.wireshark.org/
- Timesketch: https://timesketch.org/
- Hashcat: https://hashcat.net/hashcat/
- John the Ripper (`keepass2john`): https://www.openwall.com/john/

---
title: "HTB Sherlock: Holmes 2025 2: The Watchman's Residue"
description: "SOC and DFIR notes on a Sherlock about a decommissioned host used to prompt-inject a helpdesk AI, followed by remote access, credential dumping, persistence, and exfiltration."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-26"
tags:
  - dfir
  - soc
  - windows
  - threat-hunting
  - incident-response
  - teamviewer
  - mitre-attack
  - htb-sherlock
objective: "Trace a mixed-OS intrusion from a prompt-injection chat session through remote access to confirmed credential access and exfiltration."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
skill: Intermediate
outcome: "Confirmed compromise with credential access, persistence, and sensitive-file exfiltration."
---

## At a glance

| Field | Value |
|---|---|
| Platform | Hack The Box (Sherlock) |
| Category | SOC / DFIR |
| Difficulty | Medium |
| OS | Mixed |
| Window | 2025-08-19 to 2025-08-20 |
| Tools | Wireshark, Timesketch, keepass2john, Hashcat |
| Outcome | Confirmed compromise |

## Overview

Target and attacker addresses are replaced with role-based placeholders; command syntax is preserved.

A decommissioned workstation was used to open a chat session with an internal helpdesk AI service. A prompt injection made the assistant disclose remote monitoring and management details, including credentials for the CogWork Central workstation. The operator then reached that workstation through TeamViewer, staged tooling, harvested browser credentials, ran Mimikatz, added Winlogon persistence, and moved sensitive files out. The remote management account in use was `James Moriarty`, and the session source was the decommissioned host.

I checked the packet capture first so the host and chat evidence would line up with the endpoint telemetry before I opened the triage image.

## Evidence

### Initial anomaly and triage

The decommissioned host was the busiest endpoint in the capture.

```text
Packets: 1057
Bytes: 2326379
Tx Packets: 578
Tx Bytes: 86907
Rx Packets: 479
Rx Bytes: 2239472
```

It communicated with the helpdesk endpoint over stream `19`. The HTTP/JSON traffic exposed an OpenAI-compatible endpoint and the conversation between the operator and the assistant.

```text
ip.addr==<ATTACKER_IP> && ip.addr==<TARGET_IP> && http && json
```

The decommissioned machine was the high-volume endpoint tied to the chat stream.

### Initial access

The SMB host announcement matched the chat traffic to a hostname.

```text
ip.addr==<TARGET_IP> && smb
2025-08-19 11:45:20.985106249
BROWSER  Host Announcement WATSON-ALPHA-2, Workstation, Server, NT Workstation
```

The chat showed the operator presenting as WATSON, asking for remote management credentials, and getting them. The first message was a greeting to an old friend, and the last said the account would return.

The prompt injection timestamp was `2025-08-19T12:02:06.129Z`, normalised to `2025-08-19 12:02:06`.

The compromised decommissioned hostname was `WATSON-ALPHA-2`.

### Persistence and privilege escalation

The operator added persistence through Winlogon.

```text
datetime 2025-08-20T10:13:57+00:00
key_path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
command Userinit.exe, JM.exe
message ... Application: Userinit Command: Userinit.exe, JM.exe Trigger: Logon
```

MITRE mapping: `T1547.004: Winlogon Helper DLL`.

`JM.exe` was configured to run at logon at `2025-08-20 10:13:57`.

### Post-compromise activity

TeamViewer connection records showed the operator session.

```text
514162531  James Moriarty  20-08-2025 09:58:25  20-08-2025 10:14:27
Cogwork_Admin  RemoteControl  {7ca6431e-30f6-45e9-9ac6-0ef1e0cecb6a}
```

The TeamViewer log records local time at UTC+1. At the matching local time the connection source was:

```text
2025/08/20 10:58:36.813  UDPv4: punch received a=<TARGET_IP>:55408
```

I assumed at first that every log in the triage image shared one clock, then the TeamViewer logfile showed a one-hour offset from the connection records. Keeping the two time bases separate prevented a timeline error.

Tools were staged under `C:\Windows\Temp\safe\`:

```text
Everything-1.4.1.1028.x86.zip
JM.exe
mimikatz.exe
webbrowserpassview.zip
```

WebBrowserPassView held application focus for `8125` ms, rounded to `8000` ms. Mimikatz execution was anchored by Prefetch creation at `2025-08-20T10:07:08.174475+00:00`. `dump.txt` was created, extended, and closed at `2025-08-20T10:08:06.370303+00:00`.

Sensitive files left `C:\Windows\Temp\flyover\` starting at local `2025/08/20 11:12:07.902`; the normalised UTC start was `2025-08-20 10:12:07`. The Heisen-9 backup database was moved into the staging folder at `2025-08-20 10:11:09`.

### Defense evasion

The supplied evidence did not establish any anti-forensics activity. Nothing supported log clearing or timestomping. I dropped that line of inquiry once the USN and registry records came back consistent.

## Timeline (UTC)

| Time (UTC) | Source | Event |
|---|---|---|
| `2025-08-19 11:39` | pcap | IT admin / Borock interaction begins |
| `2025-08-19 11:45:20` | SMB | Host announcement identifies `WATSON-ALPHA-2` |
| `2025-08-19 11:53` | pcap | Operator's opening greeting |
| `2025-08-19 11:54` | pcap | User probes bot memory |
| `2025-08-19 11:56` | pcap | User identifies as WATSON |
| `2025-08-19 11:57` | pcap | RMM credentials requested |
| `2025-08-19 12:00` | pcap | RMM troubleshooting requested |
| `2025-08-19 12:01` | pcap | Credentials elicited |
| `2025-08-19 12:02:06` | pcap JSON | Prompt injection leaks remote management tool information |
| `2025-08-19 12:04` | pcap | Follow-up message |
| `2025-08-19 12:05` | pcap | Final chat message |
| `2025-08-20 09:58:25` | `Connections_incoming.txt` | `James Moriarty` RMM session starts |
| `2025-08-20 10:07:08` | USN | Mimikatz Prefetch created |
| `2025-08-20 10:08:06` | USN | `dump.txt` created, extended, and closed |
| `2025-08-20 10:09:14` | UserAssist | WebBrowserPassView focus event |
| `2025-08-20 10:11:09` | USN | Heisen-9 backup database moved into staging |
| `2025-08-20 10:12:07` | TeamViewer | Sensitive-file exfiltration starts |
| `2025-08-20 10:13:57` | Registry | Winlogon persistence created |
| `2025-08-20 10:14:27` | `Connections_incoming.txt` | Malicious RMM session ends |

Note: `Connections_incoming.txt` uses UTC. Only `TeamViewer15_Logfile.log` uses host local time, UTC+1.

## Indicators

| Type | Value | Context |
|---|---|---|
| IP | attacker host | Decommissioned machine used by the operator |
| IP | helpdesk endpoint | MSP-HELPDESK-AI service |
| IP | RMM source host | Origin of the TeamViewer connection |
| Host | `WATSON-ALPHA-2` | Decommissioned machine hostname |
| User | `James Moriarty` | RMM account used by the operator |
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

## Outcome

Classification: Confirmed compromise.

Severity: High, from credential access, persistence, lateral-movement credentials, and sensitive-file exfiltration.

Affected accounts: the RMM account `James Moriarty`, `Cogwork_Admin`, and Heisen-9-WS-6 credentials exposed.

Affected hosts: `WATSON-ALPHA-2`, the CogWork Central workstation, and MSP-HELPDESK-AI.

Source: the decommissioned host for chat activity and the RMM source host for TeamViewer activity.

Scope: Proven activity covers chat-based credential elicitation, TeamViewer access, tool staging, credential access, persistence, and exfiltration. Recovered credentials point to further movement into CogWork-1 infrastructure, but no additional host activity is established here.

## Recommended response

- Isolate the CogWork Central workstation and affected systems.
- Remove the `JM.exe` Winlogon persistence.
- Rotate the RMM, workstation, and recovered Heisen-9 credentials.
- Block and hunt the decommissioned host and the RMM source host.
- Review sibling hosts and domain logs for lateral movement.
- Preserve the packet capture, triage image, TeamViewer logs, registry evidence, USN records, and KeePass database.

## Detection opportunities

- Alert on OpenAI-compatible chat traffic from decommissioned hosts.
- Alert on TeamViewer access followed by writes to `C:\Windows\Temp\`.
- Hunt for `mimikatz.exe`, `webbrowserpassview`, `JM.exe`, and `dump.txt`.
- Monitor Winlogon `Userinit` changes.
- Detect rapid file sends from temporary staging directories.

## Technical notes

Wireshark endpoint statistics identified the decommissioned host, and the SMB host announcement supplied the hostname.

`Connections_incoming.txt` timestamps are UTC. `TeamViewer15_Logfile.log` timestamps are local UTC+1.

UserAssist reported an application focus duration of `8125`, rounded to the nearest thousand as `8000` milliseconds.

The KeePass database was converted to a hash with `keepass2john acquired.kdbx > kdbx.hash`, and Hashcat mode `13400` recovered the master password. The `Heisen-9-WS-6` entry held a username and password pair. I kept the hash and the recovered values out of this writeup because a reader does not need them. The master password is `<REDACTED_PASSWORD>`, the hash is `<REDACTED_HASH>`, and the recovered pair is `<LAB_USER>` with `<REDACTED_PASSWORD>`.

## References

- MITRE ATT&CK T1547.004: https://attack.mitre.org/techniques/T1547/004/
- Wireshark: https://www.wireshark.org/
- Hashcat: https://hashcat.net/hashcat/
- John the Ripper, which ships keepass2john: https://www.openwall.com/john/
- Timesketch: https://timesketch.org/

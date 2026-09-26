---
title: "HTB Sherlock: Holmes 2025 2: The Watchman's Residue"
description: "DFIR notes from a medium-difficulty Sherlock where a decommissioned host was used to prompt-inject an MSP helpdesk AI, then remotely access a workstation to dump credentials, add persistence, and exfiltrate files."
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
  - prompt-injection
objective: "Reconstruct a prompt-injection driven intrusion from packet capture, endpoint triage, registry, and remote-access evidence, then map the observed activity to MITRE ATT&CK."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
skill: "Network forensics, endpoint triage, and ATT&CK mapping."
outcome: "Confirmed compromise with credential access, logon persistence, and sensitive-file exfiltration."
---

## At a glance

Holmes 2025 2: The Watchman's Residue is a medium-difficulty SOC and DFIR Sherlock set across a mixed Windows environment on 19 and 20 August 2025. A decommissioned host, WATSON-ALPHA-2, ran a chat session against the MSP-HELPDESK-AI endpoint. A prompt injection leaked remote management details and credentials for the central workstation. The attacker then used TeamViewer to reach the CogWork Central workstation, staged tools, harvested browser credentials, ran Mimikatz, added a Winlogon helper, and exfiltrated files.

- Difficulty: Medium
- Category: SOC / DFIR
- Dates: 2025-08-19 to 2025-08-20
- Attacker host: WATSON-ALPHA-2
- Helpdesk endpoint: MSP-HELPDESK-AI
- Workstation: CogWork Central

## Overview

Target and attacker addresses are replaced with role-based placeholders; command syntax is preserved.

The packet capture and the endpoint triage image carried most of the investigation. On 19 August 2025, WATSON-ALPHA-2, a host that should have been decommissioned, opened an OpenAI-compatible chat session with the MSP-HELPDESK-AI endpoint. The conversation tests the bot's memory and identity checks, then steers it toward remote management details. At 2025-08-19 12:02:06 a prompt injection leaked remote monitoring and management information, including credentials for the central workstation.

Two role labels are used throughout. `<ATTACKER_HOST_IP>` is the decommissioned attacker host, and `<HELPDESK_ENDPOINT_IP>` is the MSP helpdesk AI endpoint.

I checked the endpoint statistics first and expected the workstation to dominate the capture, so the decommissioned host standing out by volume was the first real signal. The next day's remote-access records tied tool staging, credential access, persistence, and file theft to the same intrusion.

## Evidence: the chat session and first access

The endpoint statistics named the busiest talker. The decommissioned host accounted for 1057 packets and 2,326,379 bytes, with 578 transmitted packets and 479 received. It communicated over stream 19, and an HTTP and JSON filter on the pair exposed an OpenAI-compatible API and the full conversation.

```text
ip.addr==<ATTACKER_HOST_IP> && ip.addr==<HELPDESK_ENDPOINT_IP> && http && json
```

An SMB host announcement tied the address to a name at 2025-08-19 11:45:20.985106249 and identified WATSON-ALPHA-2 as a workstation and server.

```text
BROWSER  Host Announcement WATSON-ALPHA-2, Workstation, Server, NT Workstation
```

The chat ran from 11:53 to 12:05 and opened with "Hello Old Friend". In between, the attacker probed the bot's memory at 11:54, identified as WATSON at 11:56, called for a revolution and asked for RMM credentials at 11:57, requested remote management troubleshooting at 12:00, and got the credentials at 12:01. The prompt injection that leaked the remote management tool information is timestamped 2025-08-19 12:02:06. The attacker left two closing lines, "Revolution wont forget" at 12:04 and "JM WILL BE BACK" at 12:05.

## Staging, credential access, and exfiltration

The TeamViewer records put the attacker session on 20 August 2025. A connection from the malicious RMM account ran from 09:58:25 to 10:14:27 UTC and was listed as a RemoteControl session tied to Cogwork_Admin. The TeamViewer log file records host local time, UTC+1, and at the matching local time the peer address on the punch message was the attacker host:

```text
2025/08/20 10:58:36.813  UDPv4: punch received a=<ATTACKER_HOST_IP>:55408
```

Tools were staged under a temporary folder:

```text
C:\Windows\Temp\safe\
Everything-1.4.1.1028.x86.zip
JM.exe
mimikatz.exe
webbrowserpassview.zip
```

Browser credential harvesting showed up in UserAssist with an application focus event at 10:09:14 and a focus duration of 8125 milliseconds, roughly eight seconds. Mimikatz execution is anchored by Prefetch creation at 2025-08-20 10:07:08. The output file dump.txt was created, extended, and closed at 2025-08-20 10:08:06.

Sensitive files left the host from a second staging folder starting at local 2025/08/20 11:12:07.902, which normalizes to 2025-08-20 10:12:07 UTC. The Heisen-9 backup database had been moved into the staged folder at 2025-08-20 10:11:09.

Persistence came through the Winlogon helper. A registry write at 2025-08-20 10:13:57 set the Userinit value to run JM.exe at logon:

```text
key_path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
command  Userinit.exe, JM.exe
message  Application: Userinit  Command: Userinit.exe, JM.exe  Trigger: Logon
```

That maps to T1547.004, Winlogon Helper DLL.

I could not verify any anti-forensics activity. The supplied evidence supports credential access, tooling, persistence, and exfiltration, and no log clearing or timestomping appeared in the available records. I treated the absence as a limit of the evidence, not proof that none occurred.

## Outcome

The activity is a confirmed compromise. Severity is high because it combined credential access, logon persistence, recovered lateral-movement credentials, and sensitive-file exfiltration.

Affected accounts were the malicious RMM account, the admin account tied to the remote-control session, and credentials for a Heisen-9 workstation exposed through the recovered KeePass entry, redacted as <LAB_USER>:<REDACTED_PASSWORD>. The credentials exposed in the chat are likewise redacted. Affected systems were WATSON-ALPHA-2, the CogWork Central workstation, and the MSP-HELPDESK-AI service.

Scope: proven activity covers chat-based credential elicitation, remote access, tool staging, credential access, persistence, and exfiltration. Recovered credentials point toward further movement into CogWork-1 infrastructure, but no additional host activity is established here.

I kept the TeamViewer session as the fixed point for converting host local time to UTC. The connection log and the TeamViewer logfile disagree by an hour because one uses UTC and the other uses UTC+1, and mixing them without correction would misplace several events.

The KeePass database was cracked offline with keepass2john and Hashcat mode 13400. The master password is redacted as <REDACTED_PASSWORD>, and the recovered entry's credentials are redacted as <LAB_USER>:<REDACTED_PASSWORD>.

Recommended response:

- Isolate the CogWork Central workstation and any other affected systems.
- Remove the Winlogon helper entry that runs JM.exe.
- Rotate RMM, workstation, and recovered Heisen-9 credentials.
- Block and hunt the attacker host and helpdesk endpoint addresses.
- Review sibling hosts and domain logs for lateral movement.
- Preserve the packet capture, triage image, TeamViewer logs, registry evidence, USN records, and KeePass database.

Detection opportunities:

- Alert on OpenAI-compatible chat traffic from decommissioned hosts.
- Alert on TeamViewer access followed by writes to the Windows Temp directory.
- Hunt for mimikatz.exe, webbrowserpassview, JM.exe, and dump.txt.
- Monitor Winlogon Userinit changes.
- Watch for rapid file sends out of temporary staging directories.

## References

- Wireshark: https://www.wireshark.org/
- Timesketch: https://timesketch.org/
- KeePass: https://keepass.info/
- Hashcat: https://hashcat.net/hashcat/
- MITRE ATT&CK T1547.004, Winlogon Helper DLL: https://attack.mitre.org/techniques/T1547/004/
- TeamViewer: https://www.teamviewer.com/

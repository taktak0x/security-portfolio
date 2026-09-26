---
title: "HTB Sherlock: The Watchman's Residue"
description: "SOC and DFIR writeup for the HTB Sherlock The Watchman's Residue: a prompt-injected helpdesk AI, a TeamViewer intrusion, credential theft, Winlogon persistence, and file exfiltration."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-26"
tags:
  - dfir
  - soc
  - windows
  - prompt-injection
  - teamviewer
  - credential-access
  - persistence
  - exfiltration
objective: "Trace a prompt-injection attack against a helpdesk AI from a packet capture and endpoint triage image, then reconstruct the remote-management access, credential theft, persistence, and exfiltration that followed."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
  - TeamViewer logs
skill: "SOC analysis and DFIR timeline reconstruction"
outcome: "Confirmed compromise. An attacker used a decommissioned host to elicit remote-management credentials from a helpdesk AI, staged tooling, dumped credentials, added Winlogon persistence, and moved sensitive files."
---

## At a glance

| Field | Value |
|---|---|
| Platform | Hack The Box, Sherlock |
| Window | 2025-08-19 to 2025-08-20 |
| Difficulty | Medium |
| Category | SOC / DFIR |
| OS | Mixed |
| Evidence | Endpoint triage image, network capture, KeePass database |
| Tools | Wireshark, Timesketch, keepass2john, Hashcat |

## Scenario and scope

Target and attacker addresses are replaced with role-based placeholders; command syntax is preserved.

Four roles appear in the evidence. A decommissioned machine named WATSON-ALPHA-2 served as the attacker host. It opened a chat session with MSP-HELPDESK-AI, the helpdesk endpoint. A prompt injection in that conversation exposed remote-management details and credentials for the CogWork Central workstation. The attacker reached that workstation through TeamViewer under the RMM account James Moriarty.

The capture ran across two days and produced one intrusion chain: credential elicitation from the bot, remote access, tool staging, credential dumping, logon persistence, and file exfiltration.

## Evidence

### Chat session and initial access

I checked the packet-capture endpoint statistics to find the busiest conversation. The decommissioned host and the helpdesk endpoint exchanged HTTP/JSON traffic over TCP stream 19. The payload was an OpenAI-compatible API request and response pair, so the whole conversation with the bot was readable.

An SMB host announcement in the same capture named the source. At 2025-08-19 11:45:20 UTC the frame announced WATSON-ALPHA-2 as a workstation running NT Workstation. That settled the identity of the decommissioned machine.

The chat ran from a familiar opener, "Hello Old Friend", through a sequence where the attacker identified as WATSON and asked for remote-management help. At 2025-08-19 12:02:06 UTC the exchange produced a prompt injection that leaked remote-management tooling information and credentials for the Central workstation. The session ended with "JM WILL BE BACK".

### Persistence

Registry evidence after the TeamViewer session showed a Winlogon change at 2025-08-20 10:13:57 UTC.

```text
key_path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
command Userinit.exe, JM.exe
```

The Userinit value was set so JM.exe would run at logon. The change matches T1547.004, Winlogon Helper DLL. I inferred that JM.exe was the same binary staged earlier in the attacker's tool folder, since the name and timing line up.

### Post-compromise activity

TeamViewer incoming-connection records show the remote session. The account was James Moriarty, running from 2025-08-20 09:58:25 to 2025-08-20 10:14:27.

```text
514162531  James Moriarty  20-08-2025 09:58:25  20-08-2025 10:14:27
Cogwork_Admin  RemoteControl  7ca6431e-30f6-45e9-9ac6-0ef1e0cecb6a
```

The TeamViewer logfile records host local time, one hour ahead of UTC. At the matching local time the connection source was the attacker host, seen as a UDPv4 punch from that machine.

Tools were staged under `C:\Windows\Temp\safe\`:

```text
Everything-1.4.1.1028.x86.zip
JM.exe
mimikatz.exe
webbrowserpassview.zip
```

Mimikatz execution is anchored by a Prefetch creation at 2025-08-20 10:07:08 UTC. A dump file was created, extended, and closed at 2025-08-20 10:08:06 UTC. UserAssist recorded WebBrowserPassView with an application focus duration of 8125 ms.

Sensitive files left from `C:\Windows\Temp\flyover\`, starting at local 2025/08/20 11:12:07.902, or 2025-08-20 10:12:07 UTC. The Heisen-9 backup database had been moved into the staged folder at 2025-08-20 10:11:09 UTC.

The recovered KeePass database `acquired file (critical).kdbx` was converted with keepass2john:

```text
keepass2john "acquired file (critical).kdbx" > kdbx.hash
```

Hashcat mode 13400 cracked the resulting hash. The master password is redacted as <REDACTED_PASSWORD>. One entry held a user:password pair for Heisen-9-WS-6, redacted as <LAB_USER>:<REDACTED_PASSWORD>, which points toward later movement into the CogWork-1 infrastructure.

### Anti-forensics check

No anti-forensics activity was established by the supplied evidence. I could not verify log clearing or timestomping from the artifacts. The actions in the record are credential access, tooling, persistence, and exfiltration.

## Outcome

Classification: confirmed compromise.

Severity is high. The attacker gained credentials, established logon persistence, obtained lateral-movement credentials, and exfiltrated sensitive files.

Affected accounts: James Moriarty (RMM), Cogwork_Admin, and the Heisen-9-WS-6 entry.

Affected hosts: WATSON-ALPHA-2, the CogWork Central workstation, and the MSP-HELPDESK-AI endpoint.

The proven scope covers chat-based credential elicitation, TeamViewer access, tool staging, credential access, persistence, and exfiltration. Recovered credentials indicate further movement into CogWork-1, but no additional host activity is established by this evidence.

Recommended response:

- Isolate the CogWork Central workstation and the other affected systems.
- Remove the JM.exe Winlogon persistence.
- Rotate the RMM, workstation, and Heisen-9 credentials.
- Block and hunt the attacker host.
- Review sibling hosts and domain logs for lateral movement.
- Preserve the packet capture, triage image, TeamViewer logs, registry evidence, USN records, and the KeePass database.

Detection opportunities:

- Alert on OpenAI-compatible chat traffic from decommissioned hosts.
- Alert on TeamViewer access followed by writes to `C:\Windows\Temp\`.
- Hunt for `mimikatz.exe`, `webbrowserpassview`, `JM.exe`, and `dump.txt`.
- Monitor Winlogon Userinit changes.
- Detect rapid file sends from temporary staging directories.

## References

- [Wireshark](https://www.wireshark.org/)
- [Timesketch](https://timesketch.org/)
- [Hashcat](https://hashcat.net/hashcat/)
- [John the Ripper, keepass2john](https://www.openwall.com/john/)
- [MITRE ATT&CK T1547.004: Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004/)

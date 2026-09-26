---
title: "HTB Sherlock: Holmes 2025 2: The Watchman's Residue: DFIR/SOC Notes"
description: "DFIR/SOC writeup for HTB Sherlock Holmes 2025 2: The Watchman's Residue, covering chat-based prompt injection, TeamViewer access, credential access, Winlogon persistence, and data exfiltration."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: 2026-09-26
tags:
  - HTB
  - Sherlock
  - DFIR
  - SOC
  - Wireshark
  - Timesketch
  - KeePass
  - TeamViewer
  - Mimikatz
  - Prompt Injection
objective: "Investigate a packet capture, triage image, TeamViewer logs, and a KeePass database to reconstruct how a decommissioned host was abused to elicit credentials from an MSP helpdesk AI, then accessed a CogWork workstation for credential harvesting, persistence, and exfiltration."
tools:
  - Wireshark
  - Timesketch
  - keepass2john
  - Hashcat
skill: "SOC analysis / digital forensics and incident response (DFIR)"
outcome: "Confirmed compromise with credential access, Winlogon persistence, and sensitive-file exfiltration; recommendation to isolate affected hosts, remove persistence, rotate credentials, and hunt the identified infrastructure."
---

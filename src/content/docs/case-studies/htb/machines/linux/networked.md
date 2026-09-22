---
title: "Networked — Web Shell Upload, Filename Command Injection, and sudo Network-Script Abuse"
seoTitle: "Networked — Web Shell Upload, Command Injection, and sudo Abuse"
description: "A leaked backup exposes upload source with weak MIME and extension checks, enabling a double-extension PHP web shell; command injection through filenames in a cron script and input validation gaps in a sudo network script lead to privileged access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - centos
  - web
  - command-injection
  - privilege-escalation
  - cron
  - sudo
objective: "Move from a reachable web-source backup to privileged access by bypassing an image-upload check, injecting commands through an attacker-controlled filename, and abusing a sudo-run network script."
tools:
  - rustscan
  - nmap
  - feroxbuster
  - curl
  - netcat
skill: "Linux web-shell upload bypass and local privilege escalation through unsanitized filenames and a sudo interface-file write"
outcome: "Command execution as <WEB_SERVICE_ACCOUNT>, a <CRON_OWNER_ACCOUNT> shell via filename command injection, and <PRIVILEGED_ACCOUNT> command execution through the sudo network script."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | CentOS Linux; Apache httpd 2.4.6 with PHP 5.4.16 |
| Starting position | Unauthenticated network access |
| Objective | Reach privileged access by bypassing the image-upload check, injecting through a cron-managed filename, and abusing a sudo network script |
| Outcome | `<WEB_SERVICE_ACCOUNT>` command execution, a `<CRON_OWNER_ACCOUNT>` shell, and `<PRIVILEGED_ACCOUNT>` command execution |

## From leaked backup to sudo interface injection

Networked is an Easy-rated Hack The Box Linux (CentOS) lab with a flawed image-upload workflow. A web-application source backup left reachable at `/backup` exposes the upload-handling code, whose extension and MIME checks accept a double-extension file named `shell.php.gif`. The upload is stored with `.php` retained in the name, Apache executes it, and the resulting web shell runs commands as the Apache service account. A cron-executed cleanup script then passes attacker-controlled filenames into a shell command, and a sudo-run network configuration script writes unescaped input into an interface file that `ifup` later sources. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). The uploaded payload, reverse-shell requests, and malicious filename are shown only as placeholder patterns.

**Attack path:** **Leaked `/backup` source → double-extension PHP upload → `<WEB_SERVICE_ACCOUNT>` web shell → cron filename command injection → `<CRON_OWNER_ACCOUNT>` shell → sudo `changename.sh` interface-file injection → `<PRIVILEGED_ACCOUNT>`**

## CentOS Apache and PHP host from unauthenticated access

- **Target:** a CentOS host exposing SSH (OpenSSH 7.4) and Apache httpd 2.4.6 running PHP 5.4.16.
- **Starting position:** unauthenticated network access.
- **Objective:** exploit the web application's upload handling for code execution, then escalate through a scheduled cleanup script and a sudo-delegated network script.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: leaked backup to sudo interface write

### 1. Service Enumeration

Observation: a full TCP scan exposes two services, one of them a PHP-capable web server.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Networked-TCP
```

Truncated scan output:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```

Significance: the version banner identifies an Apache server configured to execute PHP, so any file the server treats as a PHP script is directly valuable.

Result: SSH and a PHP-serving Apache instance are the reachable surface.

### 2. Web Content Discovery

Observation: directory enumeration surfaces a backup path and an upload path.

```bash
feroxbuster --url http://<TARGET_IP> --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

Truncated discovery output:

```text
/backup
/uploads
```

The `/backup` path serves the web-application source: `index.php`, `lib.php`, `photos.php`, and `upload.php`.

Significance: an exposed source archive removes the guesswork from the upload bypass, because the exact validation logic is readable before any payload is crafted.

Result: the upload-handling source is recoverable without authentication.

### 3. Upload Source Review

Observation: the leaked `upload.php` delegates validation to `check_file_type()` in `lib.php` and enforces a small set of image extensions.

```php
$validext = array('.jpg', '.png', '.gif', '.jpeg');
```

The stored name is rebuilt from the client address and the text after the first dot:

```php
$name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;
```

Significance: validation inspects the MIME type and the trailing extension only, so a file named `shell.php.gif` is stored as `<ATTACKER_IP_UNDERSCORES>.php.gif`; because Apache executes PHP for any filename containing `.php`, the double extension turns an accepted image upload into code execution.

Result: the check can be satisfied by an image extension while a `.php` token remains in the executed filename.

### 4. PHP Web Shell Upload and Execution

Observation: an image-valid file that also carries PHP executes when requested through the uploads path.

Action: build a GIF-header PHP payload and upload it through `/upload.php`:

```bash
printf 'GIF89a\n<PHP_WEBSHELL_PAYLOAD>' > shell.php.gif
```

I checked the stored name through `/photos.php`:

```text
<ATTACKER_IP_UNDERSCORES>.php.gif
```

Action: request the shell parameter, then establish a callback session:

```bash
curl 'http://<TARGET_IP>/uploads/<ATTACKER_IP_UNDERSCORES>.php.gif?cmd=<REVERSE_SHELL_REQUEST>'
```

```bash
nc -lvnp <WEB_SHELL_PORT>
```

The session returns as the web service account:

```text
bash-4.2$ whoami
<WEB_SERVICE_ACCOUNT>
```

Significance: the `GIF89a` header satisfies the image check while the `.php` token in the stored filename is handed to Apache's PHP handler, so the double extension alone yields unauthenticated code execution with no separate vulnerability.

Result: command execution as `<WEB_SERVICE_ACCOUNT>` is established.

### 5. Privilege Escalation to `<CRON_OWNER_ACCOUNT>` via Filename Injection

Observation: a readable home directory holds a cron entry that runs a PHP cleanup script every three minutes.

```bash
cat /home/<CRON_OWNER_ACCOUNT>/crontab.<CRON_OWNER_ACCOUNT>
```

```text
*/3 * * * * php /home/<CRON_OWNER_ACCOUNT>/check_attack.php
```

The script scans the upload directory and passes each filename into a shell command:

```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

Action: create a file whose name carries shell syntax, then catch the callback scheduled to run as the script owner:

```bash
cd /var/www/html/uploads
touch -- '<MALICIOUS_FILENAME_PATTERN>'
```

```bash
nc -lvnp <CRON_INJECTION_PORT>
```

When the cron job runs, the shell returns as the script owner:

```text
$ whoami
<CRON_OWNER_ACCOUNT>
```

Significance: the filename is interpolated unquoted into `exec()`, so the shell treats part of the name as a command; because the cron job runs as `<CRON_OWNER_ACCOUNT>`, the injected command executes with that account's privileges.

Result: a `<CRON_OWNER_ACCOUNT>` shell is obtained through the cron-managed script.

### 6. Privilege Escalation to `<PRIVILEGED_ACCOUNT>` via `changename.sh`

Observation: sudo enumeration shows a passwordless rule for a network-naming script owned by the privileged context.

```bash
sudo -l
```

```text
(root) NOPASSWD: /usr/local/sbin/changename.sh
```

The script validates input with a regular expression that permits spaces and slashes:

```bash
regexp="^[a-zA-Z0-9_\ /-]+$"
```

It writes the supplied values into `/etc/sysconfig/network-scripts/ifcfg-<CRON_OWNER_ACCOUNT>` and then runs `ifup <CRON_OWNER_INTERFACE>`. Because the network scripts source that generated file, a value containing a command path can be interpreted as shell syntax.

Action: stage a reverse-shell script, then pass a value that appends its path to the name field:

```bash
cat > /tmp/<STAGING_SCRIPT> << 'EOF'
<REVERSE_SHELL_SCRIPT>
EOF
chmod +x /tmp/<STAGING_SCRIPT>
```

```bash
sudo /usr/local/sbin/changename.sh
# NAME:       <COMMAND_PATH_INJECTION_PATTERN>
# remaining prompts: none / no / dhcp
```

```bash
nc -lvnp <PRIVILEGED_PORT>
```

The privileged listener returns a shell:

```text
# whoami
<PRIVILEGED_ACCOUNT>
```

Significance: allowing spaces in the validated value lets the input be split into a name plus a command path; sourcing the generated interface file then executes that path as the privileged account, so a `sudo` delegation that consumes untrusted input yields full command execution.

Result: command execution as `<PRIVILEGED_ACCOUNT>` is confirmed by the returned `whoami` output.

## The upload check gap and injection placement

- **Upload check versus execution behavior.** The handler accepted image extensions while Apache executed any `.php`-bearing filename, so the payload combined a `GIF89a` header, an allowed `.gif` extension, and an embedded `.php` token to satisfy the check and still run as PHP.
- **Injection value placement in `changename.sh`.** I placed the injected value in the `NAME` field and answered the remaining prompts with neutral values (`none`, `no`, `dhcp`) so the script continued through to `ifup`.

## Outcome: privileged account via the sudo network script

The source records unauthenticated access escalating to privileged `<PRIVILEGED_ACCOUNT>` command execution through the sudo network script. Limitation: the payloads and injected values appear only as placeholders, so the chain is not reproduced here and is not reproducible from this writeup.

## Recommendations: upload checks, exposed source, filenames, and sudo delegation

The lab notes do not record validation of these recommendations.

1. **Extension- and MIME-only upload validation.** The upload handler trusted the MIME type and trailing extension, so a `.gif` file containing a `.php` token was stored and executed. *Recommendation:* validate the actual content, re-encode or strip images before storage, store uploads outside the web root, and disable script execution in upload directories. *Detection:* alert when executable files are written to upload or media paths.
2. **Web-application source exposed in the web root.** A reachable source archive disclosed the exact validation logic and reduced the bypass to a read. *Recommendation:* keep backups, archives, and source control artifacts out of any web-served directory. *Detection:* monitor web paths for archive and source-file retrieval.
3. **Filenames passed unescaped into a shell command.** The cron cleanup script interpolated each filename into `exec()`, so shell metacharacters in a name became commands. *Recommendation:* avoid the shell for file operations, quote and pass names as discrete arguments, and reject filenames containing shell metacharacters. *Detection:* alert when files with command separators in their names appear in scheduled directories.
4. **Sudo delegation that writes untrusted input into sourced configuration.** A passwordless `sudo` rule fed user input into a generated interface file that `ifup` sourced, and the permissive regex allowed spaces. *Recommendation:* apply a strict allowlist to naming input, never write user-controlled values into sourced configuration, and remove `sudo` delegation that consumes untrusted input. *Detection:* review `sudoers` for script-based rules and monitor changes to network-script configuration files.

## References

- [Hack The Box — Networked](https://app.hackthebox.com/machines/Networked) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content-discovery scanner)
- [curl — command-line tool and library](https://curl.se/docs/manpage.html) (HTTP requests to the uploaded shell)
- [netcat](https://nc110.sourceforge.io/) (TCP listener for callback shells)
- [Apache HTTP Server 2.4 Documentation](https://httpd.apache.org/docs/2.4/) (handler and script-execution behavior)

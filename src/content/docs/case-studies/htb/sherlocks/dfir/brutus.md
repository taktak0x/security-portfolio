---
title: "Brutus — SSH Brute-Force, Interactive Root Access, and a Persistent Sudo Account"
description: "Sanitized HTB Sherlock case study correlating authentication logs and session records to reconstruct an SSH brute-force, interactive root access, and a persistent sudo account."
type: case-study
platform: Hack The Box
content_type: sherlock
status: published-ready
addedAt: "2026-09-14"
tags:
  - dfir
  - soc
  - linux
  - ssh
objective: "Reconstruct a defensible incident timeline from SSH authentication and session-accounting artifacts and identify persistence and post-compromise activity."
tools:
  - grep
  - awk
  - cut
  - sort
  - uniq
  - wtmpdb
  - last
skill: "Linux authentication-log and session-accounting forensic correlation"
outcome: "Confirmed compromise with a bounded incident timeline: SSH password brute-force to interactive root access, a sudo-enabled local account, and post-compromise credential and discovery activity."
---

## At a glance

| Field | Value |
|---|---|
| Target environment | Linux host; supplied evidence limited to authentication logs and session-accounting data |
| Starting position | Provided evidence: `auth.log` and a legacy session record (`wtmp.legacy`) |
| Objective | Reconstruct a defensible incident timeline from SSH authentication and session-accounting artifacts and identify persistence and post-compromise activity |
| Outcome | Interactive root access followed by a sudo-enabled local account; confirmed compromise |

## From an authentication burst to a sudo-enabled account

Brutus is a Hack The Box Sherlock that reconstructs a Linux SSH compromise from authentication and session-accounting artifacts. Correlating an authentication burst, successful privileged logins, terminal-session records, and account-management events yields one defensible timeline: a password brute-force against SSH opened interactive root access, the attacker created a local account in the `sudo` group, and that account read the credential store and fetched an enumeration script. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** `SSH password brute-force → interactive root session → local account creation + sudo group → privileged /etc/shadow read and enumeration-script retrieval`

## Provided artifacts and the question

- **Provided evidence:** the Sherlock supplies `auth.log` and a legacy `wtmp` session-accounting file (`wtmp.legacy`).
- **Environment:** a Linux host reachable over SSH; the artifacts are authentication and session records only.
- **Objective:** build a defensible incident timeline and determine what the evidence does and does not establish about compromise, persistence, and follow-on activity.
- **Constraints:** analysis is confined to the supplied artifacts. Timestamps are recorded as they appear in each artifact; the session-accounting query was run with `TZ=UTC`.

## Evidence: auth.log and wtmp on one timeline

### 1. Authentication Volume Triage

Observation: raw authentication records are dominated by one service, so event volume indicates where to focus.

Action: count events by service name.

```bash
awk '{print $5}' auth.log | cut -d'[' -f1 | cut -d: -f1 | sort | uniq -c | sort -nr
```

```text
257 sshd
104 CRON
  8 systemd-logind
  6 sudo:
  3 groupadd
  2 usermod
  2 systemd:
  1 useradd
  1 passwd
  1 chfn
```

Significance: `sshd` accounts for most events in a 385-line log; a distribution this skewed points to automated authentication attempts.

Result: SSH authentication activity is the anomaly to investigate.

### 2. Source Attribution

Observation: I expected one external address to dominate the authentication events if the activity was a brute-force campaign.

Action: extract and rank source addresses.

```bash
grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' auth.log | sort | uniq -c | sort -nr
```

```text
214 <EXTERNAL_SOURCE>
  1 <SECONDARY_SOURCE>
  1 <INTERNAL_SOURCE>
```

Significance: a single address produced 214 references against one each from the others, consistent with one automated source.

Result: `<EXTERNAL_SOURCE>` is the source of the authentication volume.

### 3. Successful Access and Session Correlation

Observation: accepted-password events from the dominant address date the successful logins, and a session record independently bounds the interactive window.

Action: filter accepted logins from that source, then query the converted session database.

```bash
grep 'Accepted.*<EXTERNAL_SOURCE>' auth.log
```

```text
<DATE> 06:31:40 ... Accepted password for <PRIVILEGED_ACCOUNT> from <EXTERNAL_SOURCE> port <SOURCE_PORT_1> ssh2
<DATE> 06:32:44 ... Accepted password for <PRIVILEGED_ACCOUNT> from <EXTERNAL_SOURCE> port <SOURCE_PORT_2> ssh2
<DATE> 06:37:34 ... Accepted password for <PERSISTENCE_ACCOUNT> from <EXTERNAL_SOURCE> port <SOURCE_PORT_3> ssh2
```

```bash
TZ=UTC wtmpdb last -F -f ./wtmp
```

```text
<PRIVILEGED_ACCOUNT> pts/1 <EXTERNAL_SOURCE> Wed Mar  6 06:32:45 2024 - Wed Mar  6 06:37:24 2024 (00:04)
```

```bash
grep '06:32:44.*New session' auth.log
```

```text
<DATE> 06:32:44 ... New session <SESSION_ID> of user <PRIVILEGED_ACCOUNT>.
```

Significance: the first accepted event (`06:31:40`) has no matching terminal session, while the second (`06:32:44`) is followed one second later by a session start and a recorded session identifier, separating a transient authentication from sustained interactive access.

Result: interactive privileged access began at `2024-03-06 06:32:45` in session `<SESSION_ID>`, authenticated from `<EXTERNAL_SOURCE>`.

### 4. Persistence: Local Account Creation

Observation: account-management events appear within the same window as the compromise.

Action: extract account-creation and group-modification records.

```bash
grep -E 'useradd.*new user|usermod.*sudo' auth.log
```

```text
useradd[<PID>]: new user: name=<PERSISTENCE_ACCOUNT>, UID=<UID>, ...
usermod[<PID>]: add '<PERSISTENCE_ACCOUNT>' to group 'sudo'
```

Significance: a freshly created local account added to the `sudo` group is durable persistence: it survives the original session and can regain root at will. This matches MITRE ATT&CK T1136.001, Create Account: Local Account.

Result: `<PERSISTENCE_ACCOUNT>` was created and granted administrative-group membership.

### 5. Post-Compromise Activity

Observation: privileged command records show what the compromised access was used for after the first session.

Action: list recorded `sudo` commands.

```bash
grep 'COMMAND=' auth.log
```

```text
sudo: <PERSISTENCE_ACCOUNT> : ... COMMAND=/usr/bin/cat /etc/shadow
sudo: <PERSISTENCE_ACCOUNT> : ... COMMAND=/usr/bin/curl <REMOTE_SCRIPT_URL>
```

Significance: reading `/etc/shadow` through `sudo` is credential-store access (T1003, OS Credential Dumping); fetching a remote enumeration script prepares for discovery.

Result: credential-store access and enumeration-tool retrieval are recorded under the persistence account.

### 6. Incident Timeline Correlation

Observation: each artifact places events on a partial clock; together they order the incident.

Action: bound the first session's end, then align the account, command, and persistence events.

```bash
grep 'session closed for user' auth.log
grep 'Removed session' auth.log
```

```text
<DATE> 06:37:24 ... session closed for user <PRIVILEGED_ACCOUNT>
<DATE> 06:37:24 ... Removed session <SESSION_ID>.
```

| Time | Artifact | Event |
|---|---|---|
| 2024-03-06 06:31:40 | auth.log | First `Accepted password` for `<PRIVILEGED_ACCOUNT>` from `<EXTERNAL_SOURCE>` (transient; no session record) |
| 2024-03-06 06:32:44 | auth.log | Second `Accepted password` for `<PRIVILEGED_ACCOUNT>`; `New session <SESSION_ID>` |
| 2024-03-06 06:32:45 | wtmp (UTC) | Interactive session starts: `<PRIVILEGED_ACCOUNT> pts/1 <EXTERNAL_SOURCE>` |
| 2024-03-06 06:37:24 | auth.log + wtmp | Session `<SESSION_ID>` closes; duration 279 s |
| after 06:37:24 | auth.log | `useradd <PERSISTENCE_ACCOUNT>`, `usermod → sudo`, `/etc/shadow` read, enumeration-script fetch |
| 2024-03-06 06:37:34 | auth.log | `Accepted password` for `<PERSISTENCE_ACCOUNT>` (persistence login) |

Significance: the authenticated login, terminal start, and session identifier align within one second, and the session close agrees across both artifacts; cross-artifact agreement strengthens the timeline.

Result: the evidence supports a single, ordered compromise sequence on `2024-03-06`; the ordering of the post-session account and command events follows the full log sort.

## A legacy session file and no evasion stage

The legacy session file was not directly readable: `last -f ./wtmp.legacy` returned `file is not a database`, because the artifact is a legacy binary `wtmp` while the `wtmpdb` reader expects SQLite. Converting it once with `wtmpdb import` produced a queryable database while the original artifact was preserved. The supplied artifacts show no audit-policy change or log-clearing activity, so no defense-evasion stage is included.

## Outcome: a confirmed compromise on 2024-03-06

The available records confirm a compromise on the target host. Limitations: I could not verify the enumeration script's execution or output, additional persistence mechanisms, credential reuse, or activity on other hosts.

## Recommendations: SSH password auth, local accounts, /etc/shadow reads, and response

Each finding pairs the observed root cause with its demonstrated impact and a prioritized action. The actions are recommendations; none was validated.

1. **Password authentication on SSH.** A single external source produced hundreds of authentication events and eventually succeeded against a privileged account. *Recommendation:* prefer key-based SSH, disable password authentication for privileged accounts, and rate-limit or block repeated failures. *Detection:* flag bursts of authentication failures followed by a success from the same source.
2. **Unmonitored privileged local accounts.** The compromise added a new local account to the `sudo` group, granting durable root-equivalent access. *Recommendation:* restrict account creation and `sudo` group changes, and generate alerts for them. *Detection:* review `useradd`/`usermod` events together with `sudo` group membership changes, and raise an alert for resulting changes.
3. **Sensitive-file reads and remote tooling from a privileged shell.** The persistence account read `/etc/shadow` and fetched remote enumeration tooling. *Recommendation:* enforce least privilege so routine access does not require reading the credential store, and restrict outbound script retrieval from servers. *Detection:* investigate non-baseline `sudo` reads of `/etc/shadow` and outbound fetches of remote scripts.
4. **Response readiness.** *Recommendation:* on confirmation, isolate the host, disable unauthorized accounts, rotate `root` and local credentials, review `authorized_keys`, `sudoers`, and scheduled tasks, and preserve `auth.log` and the session artifacts for further analysis.

## References

- [Hack The Box — Sherlock Brutus](https://app.hackthebox.com/sherlocks/Brutus) (retired Sherlock)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [wtmpdb — Y2038-safe wtmp implementation (project repository)](https://github.com/thkukuk/wtmpdb)
- [`last`/`wtmpdb` manual page (Debian manpages)](https://manpages.debian.org/testing/wtmpdb/last.1.en.html)
- [GNU Coreutils — `cut`, `sort`, `uniq`](https://www.gnu.org/software/coreutils/)
- [GNU grep](https://www.gnu.org/software/grep/)
- [GNU Awk (gawk)](https://www.gnu.org/software/gawk/)

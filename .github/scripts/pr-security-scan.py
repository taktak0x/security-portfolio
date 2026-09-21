#!/usr/bin/env python3
"""Fail-closed, read-only security scan for one PR head."""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
REPO = "taktak0x/security-portfolio"
API_VERSION = "2022-11-28"
MAX_FILE = 2 * 1024 * 1024
MAX_PATCH = 512 * 1024
MAX_PAGES = 1000
SHA = re.compile(r"[0-9a-f]{40}\Z")
CODE_PATH = re.compile(r"(?i)\.(?:c|cc|cpp|cs|go|java|js|jsx|mjs|php|py|rb|rs|sh|sql|swift|ts|tsx|xml|yaml|yml|json|toml|ini|cfg|conf|properties|gradle|tf)\Z")
MARKDOWN_PATH = re.compile(r"(?i)\.(?:md|markdown|mdx)\Z")

SECRET_RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), "Private key material"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "GitHub token"),
    ("cloud-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "Cloud access key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JWT-like token"),
    ("secret-assignment", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth(?:entication)?[_-]?token|password|secret)\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{16,})"), "Credential assignment"),
)

UNSAFE_RULES = (
    ("shell-eval-input", re.compile(r"\beval\s*\([^\n)]*(?:request|input|argv|param|user|query|body|form)", re.I), "Shell evaluation of user-controlled input"),
    ("subprocess-shell-input", re.compile(r"\b(?:subprocess\.)?(?:run|Popen|call|check_call|check_output)\s*\(\s*(?:[A-Za-z_]\w*|f?[\"'][^\n\"']*\{)[^\n]*\bshell\s*=\s*True", re.I), "Shell execution of variable input"),
    ("unsafe-deserialization", re.compile(r"\b(?:pickle|dill)\.loads?\s*\(|\byaml\.load\s*\(", re.I), "Unsafe deserialization"),
)


class ScanError(Exception):
    pass


class GitHub:
    def __init__(self, token):
        self.token = token

    def get(self, path):
        request = urllib.request.Request(API + path, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "portfolio-pr-security-scan",
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read()), dict(response.headers)
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
            raise ScanError("GitHub API request failed") from exc


def links(headers):
    value = headers.get("Link", "")
    result = {}
    for part in value.split(",") if value else []:
        match = re.match(r"\s*<([^>]+)>;\s*rel=\"([^\"]+)\"", part)
        if match:
            result[match.group(2)] = match.group(1)
    return result


def paginated(api, path):
    items = []
    for page in range(1, MAX_PAGES + 1):
        payload, headers = api.get(path + ("&" if "?" in path else "?") + "page=" + str(page) + "&per_page=100")
        if not isinstance(payload, list):
            raise ScanError("GitHub pagination response invalid")
        items.extend(payload)
        relation = links(headers)
        if len(payload) == 100 and "next" not in relation:
            raise ScanError("GitHub pagination ambiguous")
        if "next" not in relation:
            return items
        if page == MAX_PAGES:
            raise ScanError("GitHub pagination limit exceeded")
    raise ScanError("GitHub pagination failed")


def line_number(text, offset):
    return text.count("\n", 0, offset) + 1


def finding(path, line, rule, message):
    return {"path": path, "line": line, "rule": rule, "severity": "high", "message": message}


def scan_text(path, text, include_unsafe):
    findings = []
    for rule, pattern, message in SECRET_RULES:
        for match in pattern.finditer(text):
            findings.append(finding(path, line_number(text, match.start()), rule, message + " (value redacted)"))
    if include_unsafe:
        for rule, pattern, message in UNSAFE_RULES:
            for match in pattern.finditer(text):
                findings.append(finding(path, line_number(text, match.start()), rule, message))
    return findings


def patch_text(patch):
    lines = []
    current = 0
    for raw in patch.splitlines():
        header = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if header:
            current = int(header.group(1))
        elif current and raw.startswith("+") and not raw.startswith("+++"):
            lines.append((current, raw[1:]))
            current += 1
        elif current and not raw.startswith("-"):
            current += 1
    return lines


def scan_pr(api, number):
    pr, _ = api.get("/repos/{0}/pulls/{1}".format(REPO, number))
    head = (pr.get("head") or {}).get("sha", "")
    if not SHA.fullmatch(head):
        raise ScanError("PR head SHA invalid")
    files = paginated(api, "/repos/{0}/pulls/{1}/files".format(REPO, number))
    findings = []
    for item in files:
        path = item.get("filename") if isinstance(item, dict) else None
        patch = item.get("patch") if isinstance(item, dict) else None
        if not isinstance(path, str) or not path or ".." in path.split("/"):
            raise ScanError("changed file path invalid")
        if not isinstance(patch, str) or len(patch.encode()) > MAX_PATCH:
            raise ScanError("changed patch oversized or unavailable")
        secret_only = bool(MARKDOWN_PATH.fullmatch(path))
        include_unsafe = not secret_only and (bool(CODE_PATH.fullmatch(path)) or path.rsplit("/", 1)[-1] in ("Dockerfile", "Makefile"))
        for line, text in patch_text(patch):
            for result in scan_text(path, text, include_unsafe):
                result["line"] = line
                findings.append(result)
        if item.get("status") == "removed":
            continue
        encoded, _ = api.get("/repos/{0}/contents/{1}?ref={2}".format(REPO, urllib.parse.quote(path, safe="/"), head))
        if not isinstance(encoded, dict) or encoded.get("encoding") != "base64":
            raise ScanError("changed file content unavailable")
        try:
            content = base64.b64decode(re.sub(r"\s+", "", encoded.get("content", "")), validate=True)
        except (ValueError, TypeError):
            raise ScanError("changed file content invalid")
        if len(content) > MAX_FILE:
            raise ScanError("changed file oversized")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(path, text, include_unsafe))
    current, _ = api.get("/repos/{0}/pulls/{1}".format(REPO, number))
    if (current.get("head") or {}).get("sha") != head:
        raise ScanError("PR head changed during scan")
    return {"head_sha": head, "findings": dedupe(findings)}


def dedupe(findings):
    return list({json.dumps(item, sort_keys=True): item for item in findings}.values())


def self_test():
    assert scan_text("x.py", "app_id = 123456789\ninstallation_id = 987654321", True) == []
    real_fixtures = (
        "gh" + "p_" + "A" * 20,
        "-----BEGIN " + "PRIVATE KEY-----",
        "password = " + "x" * 16,
    )
    assert all(scan_text("x.py", fixture, True) for fixture in real_fixtures)
    assert scan_text("x.md", "eval(request.args['x'])", False) == []
    assert scan_text("x.py", "pickle.loads(data)", True)[0]["rule"] == "unsafe-deserialization"
    assert patch_text("@@ -1 +1 @@\n+token = 'placeholder-token'")
    print(json.dumps({"self_test": "ok"}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pr", type=int, nargs="?")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not isinstance(args.pr, int) or args.pr <= 0:
        raise ScanError("PR number must be positive")
    if not args.token.strip():
        raise ScanError("GitHub token missing")
    result = scan_pr(GitHub(args.token.strip()), args.pr)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScanError as exc:
        print(json.dumps({"error": str(exc), "findings": []}), file=sys.stdout)
        raise SystemExit(2)

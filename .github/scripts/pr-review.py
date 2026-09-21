#!/usr/bin/env python3
"""Review one trusted feature PR using only GitHub's API."""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
API_VERSION = "2022-11-28"
REPO = "taktak0x/security-portfolio"
BASE = "main"
PUBLISHER = "taktak-portfolio-publisher[bot]"
REVIEWER = "taktak-portfolio-manager[bot]"
BRANCH = re.compile(r"publish-[0-9a-f]{24}\Z")
TRUSTED_BRANCH = re.compile(r"(?:dev|publish-[0-9a-f]{24})\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_FILE = re.compile(
    r"src/content/docs/case-studies(?:/[a-z0-9][a-z0-9._-]*)+\.(?:md|markdown|mdx)\Z"
)
DEV_FILE = re.compile(
    r"(?:\.github/(?:workflows|scripts)/|scripts/|src/|docs/|config/)"
    r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z"
)
UNSAFE_FILE = re.compile(r"(?:^|/)(?:__pycache__|node_modules|dist|build|coverage)(?:/|$)|\.(?:pyc|log|sqlite3?)\Z")
SENSITIVE_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[^/]*)?|\.git(?:/.*)?|"
    r"[^/]*(?:secret|credential|private[_-]?key|authorized[_-]?keys?)[^/]*)$"
)
APPROVE_BODY = "portfolio-review-bot: deterministic publisher PR gate passed."
CHANGES_BODY = "portfolio-review-bot: deterministic publisher PR gate failed."
REQUIRED_CHECKS = frozenset(("quality", "Analyze"))
MAX_FINDINGS = 20
MAX_REVIEW_BODY = 4000
MAX_PAGES = 1000
CHECK_POLL_SECONDS = 10
CHECK_TIMEOUT_SECONDS = 600
MAX_HEAD_RETRIES = 3


class ReviewError(Exception):
    pass


class HeadChangedError(ReviewError):
    pass


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def app_token():
    app_id = os.environ.get("PORTFOLIO_BOT_APP_ID", "").strip()
    installation = os.environ.get("PORTFOLIO_BOT_INSTALLATION_ID", "").strip()
    key = os.environ.get("PORTFOLIO_BOT_APP_PRIVATE_KEY", "")
    if not app_id.isdigit() or not installation.isdigit() or not key.strip():
        raise ReviewError("GitHub App credentials are missing")
    now = int(time.time())
    header = b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64(json.dumps({"iat": now - 60, "exp": now + 540, "iss": int(app_id)}, separators=(",", ":")).encode())
    unsigned = (header + "." + claims).encode()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as pem:
        pem.write(key)
        pem.flush()
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", pem.name],
            input=unsigned,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
    jwt = (unsigned.decode() + "." + b64(signed)).encode()
    request = urllib.request.Request(
        API + "/app/installations/" + installation + "/access_tokens",
        data=b"{}",
        headers={
            "Authorization": "Bearer " + jwt.decode(),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": "portfolio-pr-review",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            token = json.loads(response.read()).get("token")
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
        raise ReviewError("GitHub App token mint failed") from exc
    if not token:
        raise ReviewError("GitHub App token missing")
    return token


class GitHub:
    def __init__(self, token):
        self.token = token
        self.writes = []

    def request(self, method, path, body=None):
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "portfolio-pr-review",
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if method != "GET":
            self.writes.append((method, path, body))
        request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
            raise ReviewError("GitHub API request failed") from exc

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body):
        return self.request("POST", path, body)


def publisher_pr(pr):
    head, base, author = pr.get("head") or {}, pr.get("base") or {}, pr.get("user") or {}
    return (
        pr.get("state") == "open"
        and pr.get("draft") is not True
        and base.get("ref") == BASE
        and (base.get("repo") or {}).get("full_name") == REPO
        and TRUSTED_BRANCH.fullmatch(head.get("ref", ""))
        and (head.get("repo") or {}).get("full_name") == REPO
        and author.get("login") != REVIEWER
    )


def paginated(api, path, key=None):
    items = []
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in path else "?"
        payload = api.get(path + separator + "page=" + str(page))
        page_items = payload.get(key) if key else payload
        if not isinstance(page_items, list):
            raise ReviewError("GitHub API pagination response invalid")
        items.extend(page_items)
        if len(page_items) < 100:
            return items
    raise ReviewError("GitHub API pagination limit exceeded")


def valid_files(files, branch=None):
    # Content validation stays separate from security scanning; Markdown prose is not code.
    allowed = DEV_FILE if branch == "dev" else ALLOWED_FILE
    return bool(files) and all(
        isinstance(item, dict)
        and isinstance(item.get("filename"), str)
        and allowed.fullmatch(item.get("filename", ""))
        and ".." not in item["filename"].split("/")
        and not SENSITIVE_FILE.search(item["filename"])
        and not UNSAFE_FILE.search(item["filename"])
        for item in files
    )


def successful_checks(checks, head):
    latest = {}
    for index, item in enumerate(checks):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        if item.get("head_sha") != head:
            continue
        timestamp = next(
            (item.get(field) for field in ("created_at", "started_at", "completed_at")
             if isinstance(item.get(field), str)),
            None,
        )
        if timestamp is None:
            continue
        previous = latest.get(item["name"])
        key = (timestamp, item.get("id", 0), index)
        if previous is None or key > previous[0]:
            latest[item["name"]] = (key, item)
    if not REQUIRED_CHECKS.issubset(latest):
        return False
    latest = {name: item for name, (_, item) in latest.items()}
    return all(
        latest[name].get("status") == "completed"
        and latest[name].get("conclusion") == "success"
        for name in REQUIRED_CHECKS
    )


def wait_for_quality(api, number, head):
    deadline = time.monotonic() + CHECK_TIMEOUT_SECONDS
    while True:
        pr = api.get("/repos/{0}/pulls/{1}".format(REPO, number))
        current_head = (pr.get("head") or {}).get("sha", "")
        if not publisher_pr(pr) or current_head != head:
            raise HeadChangedError("PR head changed while waiting for quality")
        checks = paginated(
            api,
            "/repos/{0}/commits/{1}/check-runs?per_page=100".format(REPO, head),
            "check_runs",
        )
        if successful_checks(checks, head):
            return checks
        required = [
            item for item in checks
            if isinstance(item, dict)
            and item.get("head_sha") == head
            and item.get("name") in REQUIRED_CHECKS
        ]
        latest_required = max(
            required,
            key=lambda item: next(
                (item.get(field) for field in ("created_at", "started_at", "completed_at")
                 if isinstance(item.get(field), str)),
                "",
            ),
            default=None,
        )
        if latest_required and latest_required.get("status") == "completed" and all(
            item.get("status") == "completed" for item in required
        ):
            return checks
        if time.monotonic() >= deadline:
            raise ReviewError("required checks did not complete")
        time.sleep(CHECK_POLL_SECONDS)


def run_security_scan(number, head):
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise ReviewError("security scanner token missing")
    script = os.path.join(os.path.dirname(__file__), "pr-security-scan.py")
    try:
        process = subprocess.run(
            [sys.executable, script, str(number)],
            env=dict(os.environ, GITHUB_TOKEN=token),
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewError("security scanner unavailable") from exc
    try:
        result = json.loads(process.stdout)
    except (TypeError, ValueError) as exc:
        raise ReviewError("security scanner output invalid") from exc
    if process.returncode not in (0, 1) or result.get("head_sha") != head:
        raise ReviewError("security scanner failed")
    findings = result.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ReviewError("security scanner output invalid")
    return findings


def findings_body(findings):
    rows = []
    for item in sorted(findings, key=lambda value: (
        str(value.get("path", "")), value.get("line", 0), str(value.get("rule", "")),
        str(value.get("message", "")),
    ))[:MAX_FINDINGS]:
        path = str(item.get("path", "?"))[:200]
        line = str(item.get("line", "?"))[:20]
        rule = str(item.get("rule", "?"))[:80]
        message = str(item.get("message", "?"))[:240]
        rows.append("- {0}:{1} {2}: {3}".format(path, line, rule, message))
    body = "portfolio-review-bot: security findings detected.\n" + "\n".join(rows)
    return body[:MAX_REVIEW_BODY]


def prior_review(reviews, head):
    return any(
        item.get("user", {}).get("login") == REVIEWER
        and item.get("commit_id") == head
        and item.get("state") == "APPROVED"
        for item in reviews
    )


def review_pr(api, number, write=True):
    if not isinstance(number, int) or number <= 0:
        raise ReviewError("PR number must be positive")
    pr = api.get("/repos/{0}/pulls/{1}".format(REPO, number))
    if not publisher_pr(pr):
        return {"decision": "SKIP", "reason": "not an eligible trusted PR"}
    head = (pr.get("head") or {}).get("sha", "")
    result = {"decision": "REQUEST_CHANGES", "head_sha": head}
    if not SHA.fullmatch(head):
        result["reason"] = "invalid head SHA"
        return result
    if BRANCH.fullmatch((pr.get("head") or {}).get("ref", "")):
        commit = api.get("/repos/{0}/commits/{1}".format(REPO, head))
        identities = [commit.get(role) for role in ("author", "committer")]
        if commit.get("sha") != head or any(
            not isinstance(identity, dict)
            or identity.get("login") != PUBLISHER
            or identity.get("type") != "Bot"
            for identity in identities
        ):
            result["reason"] = "tip commit is not publisher-authored"
            return submit(api, number, result, write)
    reviews = paginated(api, "/repos/{0}/pulls/{1}/reviews?per_page=100".format(REPO, number))
    if prior_review(reviews, head):
        return {"decision": "SKIP", "head_sha": head, "reason": "bot already reviewed head"}
    files = paginated(api, "/repos/{0}/pulls/{1}/files?per_page=100".format(REPO, number))
    checks = wait_for_quality(api, number, head)
    failures = []
    try:
        findings = run_security_scan(number, head)
    except ReviewError as exc:
        failures.append(str(exc))
        findings = []
    if not valid_files(files if isinstance(files, list) else [], (pr.get("head") or {}).get("ref", "")):
        failures.append("changed files outside allowlist")
    if not successful_checks(checks, head):
        failures.append("CI checks not all successful")
    if findings:
        result["findings"] = findings
        failures.append("security findings detected")
    if failures:
        result["reason"] = "; ".join(failures)
        if findings:
            result["body"] = findings_body(findings)
        return submit(api, number, result, write)
    result.update(decision="APPROVE", reason="all deterministic gates passed")
    return submit(api, number, result, write)


def submit(api, number, result, write):
    if write:
        current = api.get("/repos/{0}/pulls/{1}".format(REPO, number))
        current_head = (current.get("head") or {}).get("sha", "")
        if not publisher_pr(current) or current_head != result.get("head_sha"):
            raise HeadChangedError("PR head changed before review")
        event = result["decision"]
        body = result.get("body", (APPROVE_BODY if event == "APPROVE" else CHANGES_BODY)
                         + "\n\nReason: " + result.get("reason", "unspecified"))
        api.post(
            "/repos/{0}/pulls/{1}/reviews".format(REPO, number),
            {"body": body, "event": event, "commit_id": result["head_sha"]},
        )
        result["written"] = True
    else:
        result["written"] = False
    return result


class Fixture(GitHub):
    def __init__(self, values):
        super().__init__("fixture")
        self.values = values

    def get(self, path):
        return self.values[path]

    def post(self, path, body):
        self.writes.append(("POST", path, body))
        return {}


def self_test():
    global CHECK_TIMEOUT_SECONDS
    global run_security_scan
    head = "a" * 40
    pr = {
        "state": "open", "draft": False, "user": {"login": PUBLISHER, "type": "Bot"},
        "base": {"ref": BASE, "repo": {"full_name": REPO}},
        "head": {"ref": "publish-" + "b" * 24, "sha": head, "repo": {"full_name": REPO}},
    }
    prefix = "/repos/{0}".format(REPO)
    values = {
        prefix + "/pulls/7": pr,
        prefix + "/commits/" + head: {
            "sha": head,
            "author": {"login": PUBLISHER, "type": "Bot"},
            "committer": {"login": PUBLISHER, "type": "Bot"},
        },
        prefix + "/pulls/7/reviews?per_page=100&page=1": [],
        prefix + "/pulls/7/files?per_page=100&page=1": [{"filename": "src/content/docs/case-studies/htb/machines/linux/foo.md"}],
        prefix + "/commits/" + head + "/check-runs?per_page=100&page=1": {
            "check_runs": [
                {"name": "quality", "head_sha": head, "status": "completed", "conclusion": "success", "completed_at": "2026-09-20T00:00:00Z"},
                {"name": "Analyze", "head_sha": head, "status": "completed", "conclusion": "success", "completed_at": "2026-09-20T00:00:01Z"},
                {"name": "portfolio-security-gate", "head_sha": head, "status": "in_progress", "conclusion": None, "started_at": "2026-09-20T00:00:02Z"},
            ]
        },
    }
    api = Fixture(values)
    run_security_scan = lambda number, current_head: []
    assert review_pr(api, 7, write=False)["decision"] == "APPROVE"
    assert valid_files([{"filename": "src/content/docs/case-studies/htb/machines/linux/foo.md"}])
    assert not valid_files([{"filename": "src/content/docs/case-studies/../../.env"}])
    assert not valid_files([{"filename": "src/content/docs/prolabs/foo.md"}])
    assert not valid_files([{"filename": "src/content/docs/case-studies/secrets.md"}])
    assert valid_files([{"filename": ".github/workflows/pr-review.yml"}], "dev")
    assert valid_files([{"filename": ".github/scripts/pr-review.py"}], "dev")
    assert not valid_files([{"filename": ".env"}], "dev")
    assert review_pr(api, 7, write=True)["written"] is True
    assert api.writes[-1][2]["event"] == "APPROVE"
    assert "Reason: all deterministic gates passed" in api.writes[-1][2]["body"]
    assert api.writes[-1][2]["commit_id"] == head
    values[prefix + "/commits/" + head + "/check-runs?per_page=100&page=1"] = {"check_runs": []}
    timeout = CHECK_TIMEOUT_SECONDS
    CHECK_TIMEOUT_SECONDS = 0
    try:
        try:
            review_pr(api, 7, write=True)
        except ReviewError as exc:
            assert str(exc) == "required checks did not complete"
        else:
            raise AssertionError("pending quality check was reviewed")
    finally:
        CHECK_TIMEOUT_SECONDS = timeout
    values[prefix + "/commits/" + head + "/check-runs?per_page=100&page=1"] = {
        "check_runs": [
            {"name": "quality", "head_sha": head, "status": "completed", "conclusion": "success", "completed_at": "2026-09-20T00:00:00Z"},
            {"name": "Analyze", "head_sha": head, "status": "completed", "conclusion": "success", "completed_at": "2026-09-20T00:00:01Z"},
        ]
    }
    checks = values[prefix + "/commits/" + head + "/check-runs?per_page=100&page=1"]["check_runs"]
    checks.append({
        "name": "Analyze", "head_sha": head, "status": "completed", "conclusion": "failure",
        "completed_at": "2026-09-20T00:00:02Z",
    })
    assert not successful_checks(checks, head)
    checks.pop()
    checks.append({
        "name": "Analyze", "head_sha": "c" * 40, "status": "completed", "conclusion": "failure",
        "completed_at": "2026-09-20T00:00:03Z",
    })
    assert successful_checks(checks, head)
    checks.pop()
    def changed_head(number, current_head):
        pr["head"]["sha"] = "c" * 40
        return []
    run_security_scan = changed_head
    try:
        review_pr(api, 7, write=True)
    except HeadChangedError:
        pass
    else:
        raise AssertionError("changed head was reviewed")
    pr["head"]["sha"] = head
    run_security_scan = lambda number, current_head: [{"path": "src/content/docs/case-studies/htb/x.md", "line": 4, "rule": "github-token", "message": "GitHub token (value redacted)"}]
    finding_result = review_pr(api, 7, write=False)
    assert finding_result["decision"] == "REQUEST_CHANGES"
    assert "github-token" in finding_result["body"]
    run_security_scan = lambda number, current_head: (_ for _ in ()).throw(ReviewError("security scanner failed"))
    assert review_pr(api, 7, write=False)["decision"] == "REQUEST_CHANGES"
    run_security_scan = lambda number, current_head: []
    values[prefix + "/pulls/7/reviews?per_page=100&page=1"] = [{"user": {"login": REVIEWER}, "commit_id": head, "state": "APPROVED"}]
    assert review_pr(api, 7, write=False)["decision"] == "SKIP"
    pr["head"]["repo"] = {"full_name": "fork/example"}
    assert review_pr(api, 7, write=False)["decision"] == "SKIP"
    pr["head"]["repo"] = {"full_name": REPO}
    pr["head"]["ref"] = "dev"
    pr["user"] = {"login": "feature-author", "type": "User"}
    values[prefix + "/pulls/7/reviews?per_page=100&page=1"] = []
    values[prefix + "/commits/" + head] = {
        "sha": head,
        "author": {"login": "feature-author", "type": "User"},
        "committer": {"login": "feature-author", "type": "User"},
    }
    assert review_pr(api, 7, write=False)["decision"] == "APPROVE"
    pr["head"]["ref"] = "feature"
    assert review_pr(api, 7, write=False)["decision"] == "SKIP"
    pr["head"]["ref"] = "dev"
    pr["user"] = {"login": REVIEWER, "type": "Bot"}
    assert review_pr(api, 7, write=False)["decision"] == "SKIP"
    print("self-test: OK")


def review_with_retries(api, number):
    for attempt in range(MAX_HEAD_RETRIES):
        try:
            return review_pr(api, number)
        except HeadChangedError:
            if attempt + 1 == MAX_HEAD_RETRIES:
                raise
    raise ReviewError("review retry limit exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.pr_number is None:
        parser.error("--pr-number is required")
    try:
        result = review_with_retries(GitHub(app_token()), args.pr_number)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("decision") in ("APPROVE", "SKIP") else 1
    except (ReviewError, OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write("pr-review: {0}\n".format(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())

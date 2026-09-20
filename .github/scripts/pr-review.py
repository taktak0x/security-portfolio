#!/usr/bin/env python3
"""Review one publisher PR using only GitHub's API."""

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
REVIEWER = "taktak-portfolio-bot[bot]"
BRANCH = re.compile(r"publish-[0-9a-f]{24}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_FILE = re.compile(
    r"src/content/docs/case-studies(?:/[a-z0-9][a-z0-9._-]*)+\.(?:md|markdown|mdx)\Z"
)
SENSITIVE_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[^/]*)?|\.git(?:/.*)?|"
    r"[^/]*(?:secret|credential|private[_-]?key|authorized[_-]?keys?)[^/]*)$"
)
APPROVE_BODY = "portfolio-review-bot: deterministic publisher PR gate passed."
CHANGES_BODY = "portfolio-review-bot: deterministic publisher PR gate failed."
REQUIRED_CHECKS = frozenset(("quality",))
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
        and BRANCH.fullmatch(head.get("ref", ""))
        and (head.get("repo") or {}).get("full_name") == REPO
        and author.get("login") == PUBLISHER
        and author.get("type") == "Bot"
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


def valid_files(files):
    return bool(files) and all(
        isinstance(item, dict)
        and isinstance(item.get("filename"), str)
        and ALLOWED_FILE.fullmatch(item.get("filename", ""))
        and not SENSITIVE_FILE.search(item["filename"])
        for item in files
    )


def successful_checks(checks, head):
    latest = {}
    for index, item in enumerate(checks):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            return False
        timestamp = next(
            (item.get(field) for field in ("created_at", "started_at", "completed_at")
             if isinstance(item.get(field), str)),
            None,
        )
        if timestamp is None:
            return False
        previous = latest.get(item["name"])
        key = (timestamp, item.get("id", 0), index)
        if previous is None or key > previous[0]:
            latest[item["name"]] = (key, item)
    if not REQUIRED_CHECKS.issubset(latest):
        return False
    latest = {name: item for name, (_, item) in latest.items()}
    return all(
        item.get("status") == "completed"
        and item.get("head_sha") == head
        and item.get("conclusion") in ("success", "neutral", "skipped")
        for item in latest.values()
    ) and latest["quality"].get("conclusion") == "success"


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
        quality = [item for item in checks if isinstance(item, dict) and item.get("name") == "quality"]
        if quality and successful_checks(quality, head):
            return checks
        latest_quality = max(
            quality,
            key=lambda item: next(
                (item.get(field) for field in ("created_at", "started_at", "completed_at")
                 if isinstance(item.get(field), str)),
                "",
            ),
            default=None,
        )
        if latest_quality and latest_quality.get("status") == "completed":
            return checks
        if time.monotonic() >= deadline:
            raise ReviewError("required quality check did not complete")
        time.sleep(CHECK_POLL_SECONDS)


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
        return {"decision": "SKIP", "reason": "not an eligible publisher PR"}
    head = (pr.get("head") or {}).get("sha", "")
    result = {"decision": "REQUEST_CHANGES", "head_sha": head}
    if not SHA.fullmatch(head):
        result["reason"] = "invalid head SHA"
        return result
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
    if not valid_files(files if isinstance(files, list) else []):
        failures.append("changed files outside allowlist")
    if not successful_checks(checks, head):
        failures.append("CI checks not all successful")
    if failures:
        result["reason"] = "; ".join(failures)
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
        body = APPROVE_BODY if event == "APPROVE" else CHANGES_BODY
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
            "check_runs": [{"name": "quality", "head_sha": head, "status": "completed", "conclusion": "success", "completed_at": "2026-09-20T00:00:00Z"}]
        },
    }
    api = Fixture(values)
    assert review_pr(api, 7, write=False)["decision"] == "APPROVE"
    assert valid_files([{"filename": "src/content/docs/case-studies/htb/machines/linux/foo.md"}])
    assert not valid_files([{"filename": "src/content/docs/case-studies/../../.env"}])
    assert not valid_files([{"filename": "src/content/docs/prolabs/foo.md"}])
    assert not valid_files([{"filename": "src/content/docs/case-studies/secrets.md"}])
    assert review_pr(api, 7, write=True)["written"] is True
    assert api.writes[-1][2]["event"] == "APPROVE"
    assert api.writes[-1][2]["commit_id"] == head
    values[prefix + "/commits/" + head + "/check-runs?per_page=100&page=1"] = {"check_runs": []}
    timeout = CHECK_TIMEOUT_SECONDS
    CHECK_TIMEOUT_SECONDS = 0
    try:
        try:
            review_pr(api, 7, write=True)
        except ReviewError as exc:
            assert str(exc) == "required quality check did not complete"
        else:
            raise AssertionError("pending quality check was reviewed")
    finally:
        CHECK_TIMEOUT_SECONDS = timeout
    values[prefix + "/pulls/7/reviews?per_page=100&page=1"] = [{"user": {"login": REVIEWER}, "commit_id": head, "state": "APPROVED"}]
    assert review_pr(api, 7, write=False)["decision"] == "SKIP"
    pr["head"]["repo"] = {"full_name": "fork/example"}
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
        return 0
    except (ReviewError, OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write("pr-review: {0}\n".format(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())

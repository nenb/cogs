"""Bounded first-created guard for the sole no-KVM static-control event."""
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-local-static-control-candidate.yml"
WORKFLOW_PATH = f".github/workflows/{WORKFLOW_NAME}"
REVIEWED_IMPLEMENTATION_HEAD = "79493b08aaded62fd4017ab2eb224b3bf30be07b"
RUN_TITLE = f"Non-authoritative Stage 2 static control H={REVIEWED_IMPLEMENTATION_HEAD}"
MAX_EVENT_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
MAX_RUNS = 100
SHA1 = re.compile(r"[0-9a-f]{40}")
POSITIVE = re.compile(r"[1-9][0-9]*")
DENIED_ENVIRONMENT = frozenset((
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "PYTHONPATH", "PYTHONHOME",
    "PYTHONOPTIMIZE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
))


class GuardError(Exception):
    pass


def _require(condition, message="static-control dispatch guard rejected"):
    if not condition:
        raise GuardError(message)


def _required(environ, name):
    value = environ.get(name)
    _require(type(value) is str and value != "", f"missing {name}")
    return value


def _read_event(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(0 < before.st_size <= MAX_EVENT_BYTES, "event byte bound failed")
        raw = os.read(descriptor, MAX_EVENT_BYTES + 1)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)
        _require(len(raw) == before.st_size and identity(before) == identity(after),
                 "event changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("event JSON failed") from error
    _require(type(value) is dict, "event shape failed")
    return value


def _link_header(response):
    if hasattr(response, "getheader"):
        return response.getheader("Link")
    headers = getattr(response, "headers", None)
    return None if headers is None else headers.get("Link")


def _history(workflow_head, urlopen=urllib.request.urlopen):
    query = urllib.parse.urlencode({
        "event": "workflow_dispatch", "per_page": MAX_RUNS, "page": 1,
    })
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{WORKFLOW_NAME}/runs?{query}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "cogs-stage2-static-first-created-guard",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        response = urlopen(request, timeout=20)
        try:
            raw = response.read(MAX_API_BYTES + 1)
            status = response.status
            link = _link_header(response)
        finally:
            response.close()
    except Exception as error:
        raise GuardError("Actions history API failed") from error
    _require(status == 200 and 0 < len(raw) <= MAX_API_BYTES,
             "Actions history response failed")
    _require(not link, "Actions history is paginated")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("Actions history JSON failed") from error
    _require(type(value) is dict and set(value) >= {"total_count", "workflow_runs"},
             "Actions history shape failed")
    total, runs = value["total_count"], value["workflow_runs"]
    _require(type(total) is int and type(runs) is list and 1 <= total <= MAX_RUNS
             and len(runs) == total, "Actions history is over-bound or incomplete")
    identities = []
    for run in runs:
        _require(type(run) is dict and type(run.get("id")) is int and run["id"] > 0
                 and type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
                 "run identity or attempt failed")
        _require(run.get("event") == "workflow_dispatch"
                 and run.get("head_sha") == workflow_head
                 and run.get("path") == WORKFLOW_PATH
                 and run.get("display_title") == RUN_TITLE,
                 "run event, workflow, title, or head failed")
        repository = run.get("repository")
        head_repository = run.get("head_repository")
        _require(type(repository) is dict and repository.get("full_name") == REPOSITORY
                 and type(head_repository) is dict
                 and head_repository.get("full_name") == REPOSITORY,
                 "run repository failed")
        identities.append(run["id"])
    _require(len(identities) == len(set(identities)), "duplicate run ID")
    return min(identities)


def guard(environ=os.environ, event=None, urlopen=urllib.request.urlopen):
    _require(not (DENIED_ENVIRONMENT & set(environ)),
             "token, credential, proxy, or Python override present")
    _require(_required(environ, "GITHUB_EVENT_NAME") == "workflow_dispatch", "wrong event")
    _require(_required(environ, "GITHUB_REPOSITORY") == REPOSITORY, "wrong repository")
    _require(_required(environ, "GITHUB_REF") == "refs/heads/main"
             and _required(environ, "GITHUB_REF_PROTECTED") == "true", "wrong control ref")
    _require(_required(environ, "GITHUB_RUN_ATTEMPT") == "1", "reruns are forbidden")
    run_id = _required(environ, "GITHUB_RUN_ID")
    _require(POSITIVE.fullmatch(run_id) is not None, "invalid run ID")
    workflow_head = _required(environ, "GITHUB_SHA")
    _require(SHA1.fullmatch(workflow_head) is not None, "invalid workflow head")
    workflow_ref = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
    _require(_required(environ, "GITHUB_WORKFLOW_REF") == workflow_ref, "wrong workflow ref")
    reviewed_head = _required(environ, "EXACT_IMPLEMENTATION_HEAD")
    _require(reviewed_head == REVIEWED_IMPLEMENTATION_HEAD, "wrong reviewed H")
    if event is None:
        event = _read_event(_required(environ, "GITHUB_EVENT_PATH"))
    _require(event.get("ref") == "main"
             and event.get("repository", {}).get("full_name") == REPOSITORY,
             "event ref or repository failed")
    _require(event.get("inputs") == {"exact_implementation_head": reviewed_head},
             "event inputs failed")
    earliest = _history(workflow_head, urlopen=urlopen)
    _require(earliest == int(run_id), "this is not the exact earliest created run ID")


def main():
    _require(len(sys.argv) == 1, "guard takes no arguments")
    guard()


if __name__ == "__main__":
    try:
        main()
    except (GuardError, OSError):
        raise SystemExit(2)

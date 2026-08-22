#!/usr/bin/env python3
"""Fail-closed H/G and first-created guard for the sole local Kata workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/stage2-local-kata-qualification.yml"
CONTROL_PACKAGE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v2"
CONTROL = CONTROL_PACKAGE / "stage2-local-static-control-v1.json"
REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-local-kata-qualification.yml"
# Reviewed directional binding: this data revision G describes the earlier H;
# environment or dispatch values are never defaults.
REVIEWED_IMPLEMENTATION_HEAD = "59d992b305cfd243f2d7b9c770fe24b0a36cc053"
REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "09b566a522a3d97983227b679b15f80ead189271617dbcbc70e5e1639250294d"
REVIEWED_CONTROL_SHA256 = "388618877fab7343e687db88dde5b47326a424810fb1493927381951c7c8c45e"
REVIEWED_WORKFLOW_SHA256 = "a3b332f2dd951afe380ea9fe80589780e0dff841320c36422d0af3f52805d092"
REVIEWED_RESULT_SCHEMA_SHA256 = "27d60133f202d9c32381d2b3dc8fe281334dc67d59dc8d72b402e6b7ca825375"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]*")
DENIED_ENVIRONMENT = frozenset((
    "GITHUB_TOKEN", "GH_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "TF_TOKEN_app_terraform_io", "TF_VAR_credentials",
    "GOOGLE_APPLICATION_CREDENTIALS", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
    "ARM_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE",
))
MAX_EVENT_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
MAX_RUNS = 100
MAX_TOKEN_BYTES = 1024
MAX_VISIBILITY_OBSERVATIONS = 6
VISIBILITY_INTERVAL_SECONDS = 2


class GuardError(Exception):
    pass


def _require(condition, message="guard condition failed"):
    if not condition:
        raise GuardError(message)


def _required(environ, name):
    value = environ.get(name)
    _require(type(value) is str and value != "", f"missing {name}")
    return value


def _read_json(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(0 < before.st_size <= maximum, "JSON byte bound failed")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_mtime_ns,
                 before.st_size) == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size),
                 "JSON changed while reading")
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("invalid JSON") from error


def _digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(0 < before.st_size <= MAX_API_BYTES, "reviewed file byte bound failed")
        raw = os.read(descriptor, MAX_API_BYTES + 1)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and (before.st_dev, before.st_ino,
                 before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns), "reviewed file changed")
        return hashlib.sha256(raw).hexdigest()
    finally:
        os.close(descriptor)


def _reviewed_constants():
    values = (
        (REVIEWED_IMPLEMENTATION_HEAD, SHA1),
        (REVIEWED_IMPLEMENTATION_MANIFEST_SHA256, SHA256),
        (REVIEWED_CONTROL_SHA256, SHA256),
        (REVIEWED_WORKFLOW_SHA256, SHA256),
        (REVIEWED_RESULT_SCHEMA_SHA256, SHA256),
    )
    _require(all(type(value) is str and pattern.fullmatch(value) is not None
                 for value, pattern in values), "review constants remain blocked")


def _actions_read_token(environ):
    token = environ.get("ACTIONS_READ_TOKEN")
    _require(type(token) is str and token != "", "missing actions-read token")
    try:
        raw = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise GuardError("invalid actions-read token") from error
    _require(1 <= len(raw) <= MAX_TOKEN_BYTES and all(0x21 <= byte <= 0x7e for byte in raw),
             "invalid actions-read token")
    return token


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _file, _code, _message, _headers, _url):
        raise GuardError("first-created API redirect rejected")


def _api_snapshot(token, urlopen=None):
    query = urllib.parse.urlencode({"event": "workflow_dispatch", "per_page": MAX_RUNS, "page": 1})
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{WORKFLOW_NAME}/runs?{query}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "cogs-stage2-local-first-created-guard",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect())
    call = opener.open if urlopen is None else urlopen
    try:
        response = call(request, timeout=20)
        try:
            raw = response.read(MAX_API_BYTES + 1)
            status = response.status
        finally:
            response.close()
    except GuardError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise GuardError("first-created API observation failed") from error
    _require(status == 200 and 0 < len(raw) <= MAX_API_BYTES, "first-created API response failed")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("first-created API JSON failed") from error
    _require(type(value) is dict and set(value) >= {"total_count", "workflow_runs"},
             "first-created API shape failed")
    runs = value["workflow_runs"]
    _require(type(value["total_count"]) is int and type(runs) is list
             and value["total_count"] == len(runs) and len(runs) <= MAX_RUNS,
             "first-created history is unbounded or incomplete")
    identities = []
    for run in runs:
        _require(type(run) is dict and run.get("event") == "workflow_dispatch"
                 and type(run.get("id")) is int and run["id"] > 0
                 and type(run.get("run_attempt")) is int and run["run_attempt"] >= 1,
                 "first-created run identity failed")
        identities.append(run["id"])
    _require(len(identities) == len(set(identities)), "duplicate run identity")
    return tuple(sorted(identities))


def _api_runs(token, current_run_id, urlopen=None, sleeper=time.sleep):
    previous = None
    for observation in range(MAX_VISIBILITY_OBSERVATIONS):
        identities = _api_snapshot(token, urlopen)
        if current_run_id in identities and identities == previous:
            return min(identities)
        previous = identities if current_run_id in identities else None
        if observation + 1 < MAX_VISIBILITY_OBSERVATIONS:
            sleeper(VISIBILITY_INTERVAL_SECONDS)
    raise GuardError("current run did not reach a stable API observation")


def guard(environ=os.environ, event=None, first_created=None):
    _reviewed_constants()
    _require(not (DENIED_ENVIRONMENT & set(environ)), "credential, provider, proxy, or Python override present")
    _require(_required(environ, "GITHUB_EVENT_NAME") == "workflow_dispatch", "wrong event")
    _require(_required(environ, "GITHUB_REPOSITORY") == REPOSITORY, "wrong repository")
    _require(_required(environ, "GITHUB_REF") == "refs/heads/main"
             and _required(environ, "GITHUB_REF_PROTECTED") == "true", "unprotected control ref")
    _require(_required(environ, "GITHUB_RUN_ATTEMPT") == "1", "only attempt 1 is allowed")
    run_id = _required(environ, "GITHUB_RUN_ID")
    _require(POSITIVE.fullmatch(run_id) is not None, "invalid run id")
    token = _actions_read_token(environ)
    implementation = _required(environ, "EXACT_IMPLEMENTATION_HEAD")
    control = _required(environ, "EXACT_CONTROL_HEAD")
    _require(implementation == REVIEWED_IMPLEMENTATION_HEAD
             and implementation == _required(environ, "CONFIGURED_IMPLEMENTATION_HEAD"),
             "implementation H differs")
    _require(control == _required(environ, "GITHUB_SHA")
             and control == _required(environ, "CONFIGURED_CONTROL_HEAD"), "control G differs")
    _require(_required(environ, "GITHUB_ACTOR") == _required(environ, "CONFIGURED_AUTHORIZED_ACTOR"),
             "actor differs")
    workflow_ref = f"{REPOSITORY}/.github/workflows/{WORKFLOW_NAME}@refs/heads/main"
    _require(_required(environ, "GITHUB_WORKFLOW_REF") == workflow_ref, "workflow ref differs")
    if event is None:
        event = _read_json(_required(environ, "GITHUB_EVENT_PATH"), MAX_EVENT_BYTES)
    _require(type(event) is dict and event.get("repository", {}).get("full_name") == REPOSITORY,
             "event repository differs")
    inputs = event.get("inputs")
    _require(type(inputs) is dict and inputs.get("reviewed_implementation_head") == implementation
             and inputs.get("reviewed_control_head") == control, "event H/G inputs differ")
    _require(CONTROL.is_file() and _digest(CONTROL) == REVIEWED_CONTROL_SHA256,
             "reviewed control bytes differ")
    _require(_digest(WORKFLOW) == REVIEWED_WORKFLOW_SHA256, "reviewed workflow bytes differ")
    observed_first = _api_runs(token, int(run_id)) if first_created is None else first_created
    _require(observed_first == int(run_id), "this is not the first-created dispatch")
    return {
        "control_head": control,
        "control_sha256": REVIEWED_CONTROL_SHA256,
        "implementation_head": implementation,
        "implementation_manifest_sha256": REVIEWED_IMPLEMENTATION_MANIFEST_SHA256,
        "result_schema_sha256": REVIEWED_RESULT_SCHEMA_SHA256,
        "workflow_sha256": REVIEWED_WORKFLOW_SHA256,
    }


def main():
    _require(len(sys.argv) == 1, "guard takes no arguments")
    value = guard()
    raw = "".join(f"{name}={value[name]}\n" for name in sorted(value)).encode("ascii")
    _require(sys.stdout.buffer.write(raw) == len(raw), "guard output failed")


if __name__ == "__main__":
    try:
        main()
    except (GuardError, OSError):
        raise SystemExit(2)

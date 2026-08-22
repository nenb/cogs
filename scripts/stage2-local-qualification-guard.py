#!/usr/bin/env python3
"""Fail-closed H/G and first-created guard for the sole local Kata workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/stage2-local-kata-qualification.yml"
CONTROL_PACKAGE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v2"
CONTROL = CONTROL_PACKAGE / "stage2-local-static-control-v1.json"
REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-local-kata-qualification.yml"
# Reviewed directional binding: this data revision G describes the earlier H;
# environment or dispatch values are never defaults.
REVIEWED_IMPLEMENTATION_HEAD = "a2c25f34c35d778965ab7b125fd3b8b4460b0617"
REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "0b2600579ff88d29f6670d75cd354ea8bfb03fed7697f19e7552bfc0083cc094"
REVIEWED_CONTROL_SHA256 = "c20534f05f4bc1a4a31965ef5fc220bda20263024ad06b6f798f3f13bbfdbdf9"
REVIEWED_WORKFLOW_SHA256 = "108e0782daf7100d7fe7dd9354afa377f182cc2257e2927c142201b32c8834af"
REVIEWED_RESULT_SCHEMA_SHA256 = "27d60133f202d9c32381d2b3dc8fe281334dc67d59dc8d72b402e6b7ca825375"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]*")
DENIED_ENVIRONMENT = frozenset((
    "GITHUB_TOKEN", "GH_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "TF_TOKEN_app_terraform_io", "TF_VAR_credentials",
    "GOOGLE_APPLICATION_CREDENTIALS", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
    "ARM_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_READ_TOKEN",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE",
))
MAX_EVENT_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024


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
    observed_first = (_required(environ, "PRE_EFFECT_ADMITTED_RUN_ID")
                      if first_created is None else str(first_created))
    _require(observed_first == run_id, "pre-effect admission identity differs")
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

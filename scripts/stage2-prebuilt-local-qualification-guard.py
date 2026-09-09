#!/usr/bin/env python3
"""Fail-closed H/G/Q and first-created guard for the sole local Kata workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import runpy
retirement = runpy.run_path(str(Path(__file__).with_name("stage2-revision-retirement.py")))

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/stage2-prebuilt-local-kata-qualification.yml"
CONTROL_PACKAGE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v5"
CONTROL = CONTROL_PACKAGE / "stage2-local-static-control-v2.json"
REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-prebuilt-local-kata-qualification.yml"
# Reviewed directional binding: this data revision G describes the earlier H;
# environment or dispatch values are never defaults.
REVIEWED_IMPLEMENTATION_HEAD = "c10fc103532f3e3a8b746727bd0f48c6d8498148"
REVIEWED_CONTROL_HEAD = "eb59cae18e0f041a243f35f253d46713f7e87142"
REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "ee96c1cfae2ffb1a2d8e8fc69c94d6bd792576c8885a20a78379ecfb52d2661c"
REVIEWED_CONTROL_SHA256 = "cfbd0e786fb530846235d85178965527250b6d8ad97def3053287c31af3f9783"
REVIEWED_WORKFLOW_SHA256 = "57dd3c09ea16bee5599c6f3e8517b9d4449f9dd1004143e221c1c4e3955b2ba5"
REVIEWED_RESULT_SCHEMA_SHA256 = "57ff30b4adb601a7775dbefc9002c983152974ba3244aa449656c7e8a5f7dc27"
# No dispatch value can supply the independently reviewed static custody.
REVIEWED_ROOTFS_DESCRIPTOR_SHA256 = "47dc9e90914a29f2e9aa83319faa16257727716650851a10017f9fc0671098e5"
REVIEWED_STATIC_CONTROL_RUN_ID = 34293986674
REVIEWED_STATIC_CONTROL_ARTIFACT_ID = 10082440691
REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST = "sha256:5b294cb46261e4b36b4a7893a507ec353e585109c899f5344e643b61839f4a4f"
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
        (REVIEWED_CONTROL_HEAD, SHA1),
        (REVIEWED_IMPLEMENTATION_MANIFEST_SHA256, SHA256),
        (REVIEWED_CONTROL_SHA256, SHA256),
        (REVIEWED_WORKFLOW_SHA256, SHA256),
        (REVIEWED_RESULT_SCHEMA_SHA256, SHA256),
        (REVIEWED_ROOTFS_DESCRIPTOR_SHA256, SHA256),
    )
    _require(all(type(value) is str and pattern.fullmatch(value) is not None
                 for value, pattern in values), "review constants remain blocked")
    _require(type(REVIEWED_STATIC_CONTROL_RUN_ID) is int
             and type(REVIEWED_STATIC_CONTROL_ARTIFACT_ID) is int
             and REVIEWED_STATIC_CONTROL_RUN_ID > 0 and REVIEWED_STATIC_CONTROL_ARTIFACT_ID > 0
             and type(REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST) is str
             and re.fullmatch(r"sha256:[0-9a-f]{64}",
                              REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST) is not None,
             "static observation custody remains blocked")
    retirement["select"]((REVIEWED_IMPLEMENTATION_HEAD, REVIEWED_CONTROL_HEAD),
        runs=(str(REVIEWED_STATIC_CONTROL_RUN_ID),), artifacts=(str(REVIEWED_STATIC_CONTROL_ARTIFACT_ID),))


def guard(environ=os.environ, event=None, first_created=None):
    retirement["select"](tuple(environ.get(name, "") for name in (
        "EXACT_IMPLEMENTATION_HEAD", "EXACT_CONTROL_HEAD", "EXACT_QUALIFICATION_HEAD", "GITHUB_SHA")))
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
    qualification = _required(environ, "EXACT_QUALIFICATION_HEAD")
    _require(implementation == REVIEWED_IMPLEMENTATION_HEAD
             and implementation == _required(environ, "CONFIGURED_IMPLEMENTATION_HEAD"),
             "implementation H differs")
    _require(control == REVIEWED_CONTROL_HEAD
             and control == _required(environ, "CONFIGURED_CONTROL_HEAD"), "control G differs")
    _require(qualification == _required(environ, "GITHUB_SHA")
             and qualification == _required(environ, "CONFIGURED_QUALIFICATION_HEAD"),
             "qualification Q differs")
    _require(control != qualification, "control G and qualification Q must differ")
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
             and inputs.get("reviewed_control_head") == control
             and inputs.get("reviewed_qualification_head") == qualification,
             "event H/G/Q inputs differ")
    _require(CONTROL.is_file() and _digest(CONTROL) == REVIEWED_CONTROL_SHA256,
             "reviewed control bytes differ")
    control_value = _read_json(CONTROL, MAX_API_BYTES)
    _require(type(control_value) is dict
             and type(control_value.get("producer")) is dict
             and control_value["producer"].get("control_revision") == control,
             "reviewed control revision differs")
    _require(_digest(WORKFLOW) == REVIEWED_WORKFLOW_SHA256, "reviewed workflow bytes differ")
    observed_first = (_required(environ, "PRE_EFFECT_ADMITTED_RUN_ID")
                      if first_created is None else str(first_created))
    _require(observed_first == run_id, "pre-effect admission identity differs")
    return {
        "control_head": control,
        "control_sha256": REVIEWED_CONTROL_SHA256,
        "implementation_head": implementation,
        "qualification_head": qualification,
        "implementation_manifest_sha256": REVIEWED_IMPLEMENTATION_MANIFEST_SHA256,
        "result_schema_sha256": REVIEWED_RESULT_SCHEMA_SHA256,
        "rootfs_descriptor_sha256": REVIEWED_ROOTFS_DESCRIPTOR_SHA256,
        "static_control_run_id": REVIEWED_STATIC_CONTROL_RUN_ID,
        "static_control_artifact_id": REVIEWED_STATIC_CONTROL_ARTIFACT_ID,
        "static_control_artifact_digest": REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST,
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
    except (GuardError, OSError, retirement["RetirementError"]):
        raise SystemExit(2)

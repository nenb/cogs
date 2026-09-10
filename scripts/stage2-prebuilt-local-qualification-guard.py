#!/usr/bin/env python3
"""Fail-closed H/G/Q and first-created guard for the sole local Kata workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/stage2-prebuilt-local-kata-qualification.yml"
RESULT_SCHEMA = ROOT / "schemas/stage2-formal-local-cycle-receipt-v2.json"
CONTROL_PACKAGE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v7"
CONTROL = CONTROL_PACKAGE / "stage2-local-static-control-v2.json"
# The guard alone is Q's reviewed binding adapter. All H-owned consumers,
# including the qualifier and control stager, must remain byte-identical at Q.
Q_BINDING_ADAPTER = "scripts/stage2-prebuilt-local-qualification-guard.py"
REQUIRED_CONSUMERS = frozenset({
    ".github/workflows/stage2-prebuilt-local-kata-qualification.yml",
    "scripts/stage2-formal-local-qualification.py",
    "scripts/stage2-hosted-opt-mode.py",
    "scripts/stage2-stage-prebuilt-control.py",
    "scripts/stage2-local-settlement.py",
    "scripts/stage2-native-settlement.py",
    "scripts/stage2-revision-retirement.py",
    "scripts/prepare-stage2-fixed-source.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
    "deploy/aws-feasibility/remote/completion_formal_cycle_authority.py",
    "deploy/aws-feasibility/remote/completion_formal_cycle_full.py",
    "deploy/aws-feasibility/remote/completion_formal_cycle_readiness.py",
    "schemas/stage2-formal-local-cycle-receipt-v2.json",
    "schemas/stage2-formal-local-cycle-status-v2.json",
    "schemas/stage2-formal-local-artifact-custody-v2.json",
    "schemas/stage2-pre-aws-qualification-package-v5.json",
})
REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-prebuilt-local-kata-qualification.yml"
# Reviewed directional binding: this data revision G describes the earlier H;
# environment or dispatch values are never defaults.
REVIEWED_IMPLEMENTATION_HEAD = None
REVIEWED_CONTROL_HEAD = None
REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = None
REVIEWED_CONTROL_SHA256 = None
REVIEWED_WORKFLOW_SHA256 = "9c4575c9b0f63863d50b45e6461855704a053e04fefe420881936ac74227bf7f"
# Self-contained formal receipt v2 contract, not the ordinary local report schema.
REVIEWED_RESULT_SCHEMA_SHA256 = "20d11acd19655cd1fc424aea710d98334d2deeff98db1942e0f4fe53807a4e1f"
# No dispatch value can supply the independently reviewed static custody.
REVIEWED_ROOTFS_DESCRIPTOR_SHA256 = None
REVIEWED_STATIC_CONTROL_RUN_ID = None
REVIEWED_STATIC_CONTROL_ARTIFACT_ID = None
REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST = None
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
# Bootstrap veto code must be authenticated before it executes, even when v6
# does not exist yet. This is a source seal, not successor H/G/Q authority.
RETIREMENT_SOURCE_SHA256 = "51c8b12ed68648d736834b13a28601660a43c7a689dbc0f8853ed444441c33b5"


class GuardError(Exception):
    pass


def _require(condition, message="guard condition failed"):
    if not condition:
        raise GuardError(message)


def _required(environ, name):
    value = environ.get(name)
    _require(type(value) is str and value != "", f"missing {name}")
    return value


def _identity(value):
    return tuple(getattr(value, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid",
        "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _read_bytes(path, maximum, directory=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= maximum, "file byte bound failed")
        raw = os.read(descriptor, maximum + 1)
        _require(len(raw) == before.st_size and _identity(before) == _identity(os.fstat(descriptor)),
                 "file changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(key not in value, "duplicate JSON member"); value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _x: (_ for _ in ()).throw(GuardError("invalid JSON")))


def _read_json(path, maximum):
    return _json(_read_bytes(path, maximum))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii") + b"\n"


def _selected_bytes(relative):
    _require(type(relative) is str and len(relative) <= 4096 and "\\" not in relative
             and all(part not in {"", ".", ".."} for part in relative.split("/")), "unsafe source path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(ROOT, flags)
    try:
        for part in relative.split("/")[:-1]:
            child = os.open(part, flags, dir_fd=parent); os.close(parent); parent = child
        return _read_bytes(relative.split("/")[-1], 2 * 1024 * 1024, parent)
    finally: os.close(parent)


def _authenticate_control():
    # Decode exactly the held bytes whose digest was checked; never hash then reopen.
    raw = _read_bytes(CONTROL, MAX_API_BYTES)
    _require(_sha(raw) == REVIEWED_CONTROL_SHA256, "reviewed control bytes differ")
    control = _json(raw)
    _require(_canonical(control) == raw and control["version"] == "cogs.stage2-local-static-control-package/v2")
    implementation = control["implementation"]
    _require(control["producer"]["control_revision"] == REVIEWED_CONTROL_HEAD
             and control["producer"]["implementation_revision"] == implementation["revision"] == REVIEWED_IMPLEMENTATION_HEAD
             and control["producer"]["source_manifest_sha256"] == implementation["source_manifest_sha256"]
             == REVIEWED_IMPLEMENTATION_MANIFEST_SHA256, "reviewed implementation differs")
    held = {}
    for kind, name in (("envelope", "stage2-local-execution-envelope-v3.json"),
                       ("runtime-manifest", "stage2-local-runtime-manifest-v3.json")):
        rows = [row for row in control["members"] if row["kind"] == kind]
        _require(len(rows) == 1 and rows[0]["name"] == name, "control member differs")
        member_raw = _read_bytes(CONTROL.parent / name, MAX_API_BYTES)
        _require(type(rows[0]["size"]) is int and len(member_raw) == rows[0]["size"]
                 and _sha(member_raw) == rows[0]["sha256"], "control member bytes differ")
        value = _json(member_raw); _require(_canonical(value) == member_raw)
        held[kind] = (value, _sha(member_raw))
    envelope, _ = held["envelope"]; runtime, runtime_sha = held["runtime-manifest"]
    _require(envelope["version"] == "cogs.stage2-local-execution-envelope/v3"
             and runtime["version"] == "cogs.stage2-local-runtime-manifest/v3"
             and envelope["control_revision"] == REVIEWED_CONTROL_HEAD
             and envelope["implementation"] == implementation
             and envelope["runtime"]["manifest_member"] == "stage2-local-runtime-manifest-v3.json"
             and envelope["runtime"]["manifest_sha256"] == runtime_sha
             and envelope["runtime"]["executable_set_sha256"] == _sha(_canonical(runtime["executables"]))
             and envelope["rootfs"]["prebuilt_descriptor_sha256"] == REVIEWED_ROOTFS_DESCRIPTOR_SHA256,
             "control envelope/runtime binding differs")
    rows = implementation["selected_sources"]
    _require(type(rows) is list and 1 <= len(rows) <= 128
             and implementation["selected_sources_sha256"] == _sha(_canonical(rows)))
    paths = []
    for row in rows:
        _require(type(row) is dict and set(row) == {"path", "size", "sha256"})
        relative = row["path"]; paths.append(relative)
        _require(type(relative) is str and type(row["size"]) is int and 0 < row["size"] <= 2 * 1024 * 1024
                 and type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]) is not None)
        if relative == Q_BINDING_ADAPTER: continue  # H snapshot, not an H-owned consumer.
        source_raw = _selected_bytes(relative)
        _require(len(source_raw) == row["size"] and _sha(source_raw) == row["sha256"], "selected H source differs at Q")
    _require(paths == sorted(set(paths)) and REQUIRED_CONSUMERS <= set(paths), "required consumer coverage differs")
    _require(_sha(_read_bytes(WORKFLOW, MAX_API_BYTES)) == REVIEWED_WORKFLOW_SHA256, "reviewed workflow bytes differ")
    _require(_sha(_read_bytes(RESULT_SCHEMA, MAX_API_BYTES)) == REVIEWED_RESULT_SCHEMA_SHA256, "receipt.schema")


def _load_retirement():
    path = Path(__file__).with_name("stage2-revision-retirement.py")
    raw = _read_bytes(path, MAX_API_BYTES)
    _require(_sha(raw) == RETIREMENT_SOURCE_SHA256, "retirement source differs")
    namespace = {"__file__": str(path), "__name__": "stage2_authenticated_retirement"}
    exec(compile(raw, str(path), "exec"), namespace)  # Only the exact held, sealed bytes.
    return namespace


try:
    retirement = _load_retirement()
except Exception:
    print("stage2-prebuilt-local-qualification-guard: guard.rejected", file=sys.stderr)
    raise SystemExit(2) from None


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
    _authenticate_control()
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


def cli():
    try:
        main()
    except Exception as error:
        # Fixed categories only: never print caller values, paths, or exception data.
        code = ("authority.retired" if isinstance(error, retirement["RetirementError"]) else
                "io.failed" if isinstance(error, OSError) else
                "receipt.schema" if isinstance(error, GuardError) and str(error) == "receipt.schema" else
                "guard.rejected")
        print(f"stage2-prebuilt-local-qualification-guard: {code}", file=sys.stderr)
        raise SystemExit(2) from None

if __name__ == "__main__":
    cli()

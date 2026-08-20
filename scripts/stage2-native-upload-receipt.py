#!/usr/bin/env python3
"""Canonical bounded codec for the native candidate upload binding receipt."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
from completion_runtime_contract import canonical_json, validate_native_candidate_result

MAX_CANDIDATE_BYTES = 4096
MAX_RECEIPT_BYTES = 4096
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
POSITIVE = re.compile(r"[1-9][0-9]*")
VERSION = "cogs.stage2-native-package-upload-receipt/v1"


class ReceiptError(Exception):
    pass


@dataclass(frozen=True)
class Context:
    revision: str
    manifest: str
    run_id: int
    run_attempt: int
    candidate_name: str
    receipt_name: str
    artifact_id: int
    artifact_digest: str
    candidate_sha256: str
    candidate_bytes: int


def _required(environ, name):
    value = environ.get(name)
    if not value:
        raise ReceiptError(f"missing {name}")
    return value


def _positive(value, name):
    if POSITIVE.fullmatch(value) is None:
        raise ReceiptError(f"invalid {name}")
    return int(value)


def context(environ=os.environ):
    revision = _required(environ, "EXPECTED_SOURCE_REVISION")
    manifest = _required(environ, "EXPECTED_SOURCE_MANIFEST_SHA256")
    reviewed = _required(environ, "EXACT_REVIEWED_HEAD")
    if REVISION.fullmatch(revision) is None or revision != reviewed:
        raise ReceiptError("source revision differs")
    if SHA256.fullmatch(manifest) is None:
        raise ReceiptError("source manifest is invalid")
    run_id = _positive(_required(environ, "GITHUB_RUN_ID"), "run id")
    attempt = _positive(_required(environ, "GITHUB_RUN_ATTEMPT"), "run attempt")
    candidate_name = _required(environ, "CANDIDATE_ARTIFACT_NAME")
    receipt_name = _required(environ, "RECEIPT_ARTIFACT_NAME")
    if candidate_name != f"stage2-native-package-candidate-{revision}-{run_id}-{attempt}":
        raise ReceiptError("candidate artifact name is not run-unique")
    if receipt_name != f"stage2-native-package-candidate-receipt-{revision}-{run_id}-{attempt}":
        raise ReceiptError("receipt artifact name is not run-unique")
    artifact_id = _positive(_required(environ, "CANDIDATE_ARTIFACT_ID"), "artifact id")
    artifact_digest = _required(environ, "CANDIDATE_ARTIFACT_DIGEST")
    candidate_sha256 = _required(environ, "CANDIDATE_SHA256")
    if SHA256.fullmatch(artifact_digest) is None or SHA256.fullmatch(candidate_sha256) is None:
        raise ReceiptError("upload or candidate digest is invalid")
    candidate_bytes = _positive(_required(environ, "CANDIDATE_BYTES"), "candidate bytes")
    if candidate_bytes > MAX_CANDIDATE_BYTES:
        raise ReceiptError("candidate is too large")
    return Context(revision, manifest, run_id, attempt, candidate_name, receipt_name,
                   artifact_id, artifact_digest, candidate_sha256, candidate_bytes)


def _pairs(rows):
    value = {}
    for key, item in rows:
        if key in value:
            raise ReceiptError("duplicate JSON key")
        value[key] = item
    return value


def _decode(raw, maximum):
    if not 0 < len(raw) <= maximum:
        raise ReceiptError("JSON byte bound failed")
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError("invalid JSON") from error


def _generation(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_rdev, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _read_regular(path, maximum, after_read=None):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReceiptError("input is not one regular link")
        raw = os.read(descriptor, maximum + 1)
        if after_read is not None:
            after_read()
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if _generation(after) != _generation(before) or _generation(named) != _generation(after):
            raise ReceiptError("input generation changed")
    finally:
        os.close(descriptor)
    if not 0 < len(raw) <= maximum:
        raise ReceiptError("input byte bound failed")
    return raw


def candidate_value(raw, expected):
    value = _decode(raw, MAX_CANDIDATE_BYTES)
    try:
        validate_native_candidate_result(value, expected.revision, expected.manifest)
    except Exception as error:
        raise ReceiptError("candidate/source contract differs") from error
    if raw != canonical_json(value):
        raise ReceiptError("candidate is not canonical")
    if hashlib.sha256(raw).hexdigest() != expected.candidate_sha256 or len(raw) != expected.candidate_bytes:
        raise ReceiptError("candidate upload identity differs")
    return value


def value(expected, candidate_raw):
    candidate = candidate_value(candidate_raw, expected)
    source = candidate["execution_binding"]
    return {
        "artifact": {"digest": expected.artifact_digest, "id": expected.artifact_id,
                     "name": expected.candidate_name},
        "authority": "non-authoritative-upload-binding-only",
        "candidate": {"bytes": expected.candidate_bytes, "sha256": expected.candidate_sha256},
        "outcomes": {
            "candidate_attempt": "success", "candidate_upload": "success",
            "candidate_upload_readback": "success", "candidate_validation": "success",
            "post_upload_local_identity": "success", "runtime_cleanup": "success",
        },
        "promotion_authorized": False,
        "repeat_dispatch_policy": "each-dispatch-is-a-distinct-observation-and-must-not-be-merged",
        "reviewed_head": expected.revision,
        "run": {"attempt": expected.run_attempt, "id": expected.run_id},
        "source": {"manifest_sha256": source["source_manifest_sha256"],
                   "revision": source["source_revision"]},
        "version": VERSION,
    }


def encode(expected, candidate_raw):
    raw = json.dumps(value(expected, candidate_raw), ensure_ascii=False,
                     separators=(",", ":"), sort_keys=True).encode() + b"\n"
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt is too large")
    validate(raw, expected, candidate_raw)
    return raw


def validate(raw, expected, candidate_raw):
    observed = _decode(raw, MAX_RECEIPT_BYTES)
    if raw != json.dumps(observed, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True).encode() + b"\n":
        raise ReceiptError("receipt is not canonical")
    if observed != value(expected, candidate_raw):
        raise ReceiptError("receipt fields differ")
    return observed


def _paths(expected, environ=os.environ):
    staging = Path(_required(environ, "CANDIDATE_STAGING"))
    required = Path(f"/var/tmp/cogs-stage2-native-package-candidate-{expected.run_id}-{expected.run_attempt}")
    if staging != required:
        raise ReceiptError("staging identity is not run-unique")
    return staging, staging / "candidate.json", staging / "receipt.json"


def _readback_path(expected, environ=os.environ):
    staging = Path(_required(environ, "UPLOAD_READBACK_STAGING"))
    required = Path(f"/var/tmp/cogs-stage2-native-package-upload-{expected.run_id}-{expected.run_attempt}")
    if staging != required:
        raise ReceiptError("upload readback staging is not run-unique")
    try:
        entries = os.listdir(staging)
    except OSError as error:
        raise ReceiptError("upload readback inventory failed") from error
    if entries != ["candidate.json"]:
        raise ReceiptError("upload readback does not contain the sole candidate")
    return staging / "candidate.json"


def validate_readback(expected, environ=os.environ):
    _staging, local_path, _receipt_path = _paths(expected, environ)
    uploaded_path = _readback_path(expected, environ)
    local_raw = _read_regular(local_path, MAX_CANDIDATE_BYTES)
    uploaded_raw = _read_regular(uploaded_path, MAX_CANDIDATE_BYTES)
    candidate_value(local_raw, expected)
    candidate_value(uploaded_raw, expected)
    if uploaded_raw != local_raw:
        raise ReceiptError("uploaded candidate member differs from published candidate")
    return uploaded_raw


def _write_atomic(staging, final, raw):
    partial = staging / "receipt.partial"
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReceiptError("receipt write did not progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(partial, final)
    directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"readback", "create", "validate"}:
        raise ReceiptError("usage: stage2-native-upload-receipt.py readback|create|validate")
    expected = context()
    if sys.argv[1] == "readback":
        validate_readback(expected)
        return
    if _required(os.environ, "UPLOAD_READBACK_OUTCOME") != "success":
        raise ReceiptError("upload readback success is required")
    staging, _candidate_path, receipt_path = _paths(expected)
    candidate_raw = validate_readback(expected)
    if sys.argv[1] == "create":
        if receipt_path.exists():
            raise ReceiptError("receipt already exists")
        _write_atomic(staging, receipt_path, encode(expected, candidate_raw))
    validate(_read_regular(receipt_path, MAX_RECEIPT_BYTES), expected, candidate_raw)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ReceiptError):
        raise SystemExit(2)

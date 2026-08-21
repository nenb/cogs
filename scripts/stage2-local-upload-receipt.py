#!/usr/bin/env python3
"""Exact report readback and canonical separate upload-binding receipt custody."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_REPORT_BYTES = 32 * 1024
MAX_RECEIPT_BYTES = 8 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]*")
VERSION = "cogs.stage2-local-kata-upload-receipt/v1"


class LocalReceiptError(Exception):
    pass


@dataclass(frozen=True)
class Context:
    implementation: str
    manifest: str
    control: str
    control_sha256: str
    workflow_sha256: str
    schema_sha256: str
    run_id: int
    attempt: int
    report_name: str
    receipt_name: str
    artifact_id: int
    artifact_digest: str
    report_sha256: str
    report_bytes: int
    report_result: str
    failure_code: object
    entry_outcome: str


def _require(condition, message="local receipt failed"):
    if not condition:
        raise LocalReceiptError(message)


def _required(environ, name):
    value = environ.get(name)
    _require(type(value) is str and value != "", f"missing {name}")
    return value


def _positive(value, name):
    _require(POSITIVE.fullmatch(value) is not None, f"invalid {name}")
    return int(value)


def context(environ=os.environ):
    implementation = _required(environ, "EXPECTED_IMPLEMENTATION_HEAD")
    manifest = _required(environ, "EXPECTED_SOURCE_MANIFEST_SHA256")
    control = _required(environ, "EXPECTED_CONTROL_HEAD")
    control_digest = _required(environ, "EXPECTED_CONTROL_SHA256")
    workflow = _required(environ, "EXPECTED_WORKFLOW_SHA256")
    schema = _required(environ, "EXPECTED_RESULT_SCHEMA_SHA256")
    _require(SHA1.fullmatch(implementation) is not None and SHA1.fullmatch(control) is not None,
             "invalid H/G identity")
    _require(all(SHA256.fullmatch(value) is not None
                 for value in (manifest, control_digest, workflow, schema)), "invalid reviewed digest")
    run_id = _positive(_required(environ, "GITHUB_RUN_ID"), "run id")
    attempt = _positive(_required(environ, "GITHUB_RUN_ATTEMPT"), "run attempt")
    _require(attempt == 1, "only attempt 1 is allowed")
    report_name = _required(environ, "REPORT_ARTIFACT_NAME")
    receipt_name = _required(environ, "RECEIPT_ARTIFACT_NAME")
    suffix = f"{implementation}-{control}-{run_id}-1"
    _require(report_name == f"stage2-local-kata-report-{suffix}", "report artifact name differs")
    _require(receipt_name == f"stage2-local-kata-upload-receipt-{suffix}",
             "receipt artifact name differs")
    artifact_id = _positive(_required(environ, "REPORT_ARTIFACT_ID"), "artifact id")
    artifact_digest = _required(environ, "REPORT_ARTIFACT_DIGEST")
    report_digest = _required(environ, "REPORT_SHA256")
    _require(SHA256.fullmatch(artifact_digest) is not None
             and SHA256.fullmatch(report_digest) is not None, "report digest differs")
    report_bytes = _positive(_required(environ, "REPORT_BYTES"), "report bytes")
    _require(report_bytes <= MAX_REPORT_BYTES, "report byte bound failed")
    report_result = _required(environ, "REPORT_RESULT")
    failure = _required(environ, "FAILURE_CODE")
    entry = _required(environ, "ENTRY_OUTCOME")
    _require((report_result == "pass" and failure == "none" and entry == "success")
             or (report_result == "failure" and failure != "none" and entry == "failure"),
             "entry outcome and report result differ")
    return Context(implementation, manifest, control, control_digest, workflow, schema,
                   run_id, attempt, report_name, receipt_name, artifact_id, artifact_digest,
                   report_digest, report_bytes, report_result,
                   None if failure == "none" else failure, entry)


def _generation(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_regular(path, maximum, frozen=False):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= maximum, "input regular-file bound failed")
        if frozen:
            _require(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o444,
                     "input is not root-owned frozen data")
        raw = os.read(descriptor, maximum + 1)
        os.lseek(descriptor, 0, os.SEEK_SET)
        repeated = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        _require(len(raw) == before.st_size and raw == repeated
                 and _generation(before) == _generation(after) == _generation(named),
                 "input changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _paths(expected, environ=os.environ, frozen=True):
    staging = Path(_required(environ, "REPORT_STAGING"))
    _require(staging == Path(f"/var/tmp/cogs-stage2-local-result-{expected.run_id}-1"),
             "report staging identity differs")
    if frozen:
        status = staging.stat()
        _require(status.st_uid == status.st_gid == 0 and stat.S_IMODE(status.st_mode) == 0o555,
                 "report staging is not frozen")
    return staging, staging / "report.json", staging / "receipt.json"


def _sole(path, member, message):
    path = Path(path)
    try:
        names = os.listdir(path)
    except OSError as error:
        raise LocalReceiptError(message) from error
    _require(names == [member], message)
    return path / member


def _readback_path(expected, environ=os.environ):
    path = Path(_required(environ, "REPORT_READBACK_STAGING"))
    required = Path(f"/var/tmp/cogs-stage2-local-result-upload-{expected.run_id}-1")
    _require(path == required, "report readback staging identity differs")
    return _sole(path, "report.json", "report readback is not the sole member")


def validate_report(raw, expected):
    _require(len(raw) == expected.report_bytes
             and hashlib.sha256(raw).hexdigest() == expected.report_sha256,
             "report member identity differs")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LocalReceiptError("report JSON differs") from error
    _require(type(value) is dict and value.get("result") == expected.report_result
             and value.get("failure_code") == expected.failure_code
             and value.get("bindings", {}).get("source_head") == expected.implementation
             and value.get("bindings", {}).get("source_manifest_sha256") == expected.manifest,
             "report binding differs")
    return value


def validate_readback(expected, environ=os.environ):
    _staging, local, _receipt = _paths(expected, environ)
    local_raw = _read_regular(local, MAX_REPORT_BYTES, frozen=True)
    uploaded = _read_regular(_readback_path(expected, environ), MAX_REPORT_BYTES)
    validate_report(local_raw, expected)
    validate_report(uploaded, expected)
    _require(uploaded == local_raw, "exact-ID report readback differs from frozen report")
    return local_raw


def receipt_value(expected, report_raw):
    report = validate_report(report_raw, expected)
    return {
        "artifact": {"digest": expected.artifact_digest, "id": expected.artifact_id,
                     "name": expected.report_name},
        "authority": "non-authoritative-local-upload-binding-only",
        "control": {"head": expected.control, "sha256": expected.control_sha256,
                    "workflow_sha256": expected.workflow_sha256},
        "outcomes": {"fixed_root_cleanup": "success", "independent_residue": "success",
                     "local_entry": expected.entry_outcome, "private_receipt_consumed": "success",
                     "publication": "success", "recovery": "success",
                     "report_upload": "success", "report_upload_readback": "success"},
        "promotion_authorized": False,
        "repeat_policy": "first-created-dispatch-consumed-no-retry-rerun-or-replacement",
        "report": {"bytes": expected.report_bytes, "failure_code": expected.failure_code,
                   "result": report["result"], "sha256": expected.report_sha256},
        "result_schema_sha256": expected.schema_sha256,
        "run": {"attempt": expected.attempt, "first_created": True, "id": expected.run_id},
        "source": {"head": expected.implementation, "manifest_sha256": expected.manifest},
        "version": VERSION,
    }


def encode(expected, report_raw):
    raw = json.dumps(receipt_value(expected, report_raw), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    _require(len(raw) <= MAX_RECEIPT_BYTES, "receipt byte bound failed")
    validate_receipt(raw, expected, report_raw)
    return raw


def validate_receipt(raw, expected, report_raw):
    _require(0 < len(raw) <= MAX_RECEIPT_BYTES, "receipt byte bound failed")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LocalReceiptError("receipt JSON differs") from error
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False).encode("ascii") + b"\n"
    _require(raw == canonical and value == receipt_value(expected, report_raw),
             "receipt canonical fields differ")
    return value


def _write_receipt(staging, path, raw):
    directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        _require(set(os.listdir(directory)) == {"report.json"}, "frozen report inventory differs")
        descriptor = os.open("receipt.partial", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, "receipt write did not progress")
            view = view[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        os.rename("receipt.partial", path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def validate_receipt_readback(expected, environ=os.environ):
    report_raw = validate_readback(expected, environ)
    _staging, _report, local = _paths(expected, environ)
    readback = Path(_required(environ, "RECEIPT_READBACK_STAGING"))
    required = Path(f"/var/tmp/cogs-stage2-local-receipt-upload-{expected.run_id}-1")
    _require(readback == required, "receipt readback staging identity differs")
    uploaded = _sole(readback, "receipt.json", "receipt readback is not the sole member")
    local_raw = _read_regular(local, MAX_RECEIPT_BYTES, frozen=True)
    uploaded_raw = _read_regular(uploaded, MAX_RECEIPT_BYTES)
    validate_receipt(local_raw, expected, report_raw)
    validate_receipt(uploaded_raw, expected, report_raw)
    _require(local_raw == uploaded_raw, "exact-ID receipt readback differs")


def main():
    _require(len(sys.argv) == 2 and sys.argv[1] in {"readback", "create", "receipt-readback"},
             "invalid local receipt command")
    expected = context()
    if sys.argv[1] == "readback":
        validate_readback(expected)
        return
    if sys.argv[1] == "receipt-readback":
        _positive(_required(os.environ, "RECEIPT_ARTIFACT_ID"), "receipt artifact id")
        _require(SHA256.fullmatch(_required(os.environ, "RECEIPT_ARTIFACT_DIGEST")) is not None,
                 "receipt artifact digest differs")
        validate_receipt_readback(expected)
        return
    report_raw = validate_readback(expected)
    staging, _report, receipt = _paths(expected)
    _require(not receipt.exists(), "receipt already exists")
    _write_receipt(staging, receipt, encode(expected, report_raw))
    validate_receipt(_read_regular(receipt, MAX_RECEIPT_BYTES, frozen=True), expected, report_raw)


if __name__ == "__main__":
    try:
        main()
    except (LocalReceiptError, OSError):
        raise SystemExit(2)

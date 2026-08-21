#!/usr/bin/env python3
"""Validate private-receipt output, freeze it, and publish one exact local report."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_SOURCE = ROOT / "stage2-implementation-H"
MAX_REPORT_BYTES = 32 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]*")


class LocalPublicationError(Exception):
    pass


def _require(condition, message="local publication failed"):
    if not condition:
        raise LocalPublicationError(message)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None, "validator import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(descriptor, maximum):
    before = os.fstat(descriptor)
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= maximum, "report byte bound failed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, maximum + 1)
    os.lseek(descriptor, 0, os.SEEK_SET)
    repeated = os.read(descriptor, maximum + 1)
    after = os.fstat(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                              value.st_uid, value.st_gid, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    _require(len(raw) == before.st_size and raw == repeated
             and identity(before) == identity(after), "report changed while reading")
    return raw, after


def _validate(raw, implementation, manifest, schema_sha256):
    module = _load("completion_local_full_publication", IMPLEMENTATION_SOURCE /
                   "deploy/aws-feasibility/remote/completion_local_full.py")
    try:
        value = module.load_result(raw)
    except Exception as error:
        raise LocalPublicationError("local report semantic validation failed") from error
    _require(value["bindings"]["source_head"] == implementation
             and value["bindings"]["source_manifest_sha256"] == manifest,
             "local report source binding differs")
    registry = dict(module.SCHEMA_REGISTRY)
    _require(value["version"] in registry, "local report schema registry differs")
    schema = IMPLEMENTATION_SOURCE / registry[value["version"]]
    _require(schema.is_file() and hashlib.sha256(schema.read_bytes()).hexdigest() == schema_sha256,
             "local report reviewed schema differs")
    _require(raw == module.canonical_result(value), "local report canonical bytes differ")
    return value


def publish(staging, implementation, manifest, schema_sha256, runner_uid,
            proc_root=Path("/proc"), frozen_uid=0, frozen_gid=0):
    native = _load("stage2_native_publication_for_local", ROOT / "scripts/stage2-native-publication.py")
    staging = Path(staging)
    directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    source = fresh = final = None
    try:
        _require(set(os.listdir(directory)) == {"report.partial"},
                 "staging does not contain exactly report.partial")
        source = os.open("report.partial", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
        source_status, directory_status = os.fstat(source), os.fstat(directory)
        _require(source_status.st_uid == runner_uid and directory_status.st_uid == runner_uid,
                 "report staging ownership differs")
        raw, source_generation = _read(source, MAX_REPORT_BYTES)
        value = _validate(raw, implementation, manifest, schema_sha256)
        os.fchown(directory, frozen_uid, frozen_gid)
        os.fchmod(directory, 0o700)
        _require((os.fstat(directory).st_uid, os.fstat(directory).st_gid) ==
                 (frozen_uid, frozen_gid), "report directory authority transition failed")
        _require(native._generation(os.fstat(source)) == native._generation(source_generation),
                 "report source changed after validation")
        fresh = os.open("report.fresh", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            written = os.write(fresh, view)
            _require(written > 0, "report copy did not progress")
            view = view[written:]
        os.fchown(fresh, frozen_uid, frozen_gid)
        os.fchmod(fresh, 0o444)
        os.fsync(fresh)
        frozen = os.fstat(fresh)
        _require(frozen.st_uid == frozen_uid and frozen.st_gid == frozen_gid
                 and stat.S_IMODE(frozen.st_mode) == 0o444 and frozen.st_nlink == 1,
                 "report did not freeze")
        os.close(fresh)
        fresh = None
        os.unlink("report.partial", dir_fd=directory)
        os.rename("report.fresh", "report.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fchmod(directory, 0o555)
        os.fsync(directory)
        final = os.open("report.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory)
        readback, status = _read(final, MAX_REPORT_BYTES)
        _require(readback == raw and status.st_uid == frozen_uid
                 and stat.S_IMODE(status.st_mode) == 0o444
                 and set(os.listdir(directory)) == {"report.json"},
                 "published report readback differs")
        _validate(readback, implementation, manifest, schema_sha256)
        native.prove_no_writable_aliases(final, runner_uid, proc_root)
        return hashlib.sha256(raw).hexdigest(), len(raw), value["result"], value["failure_code"]
    finally:
        for descriptor in (final, fresh, source):
            if descriptor is not None:
                os.close(descriptor)
        os.close(directory)


def _required(name):
    value = os.environ.get(name)
    _require(type(value) is str and value != "", f"missing {name}")
    return value


def main():
    _require(sys.argv[1:] == ["publish"], "invalid publication command")
    run_id, attempt = _required("GITHUB_RUN_ID"), _required("GITHUB_RUN_ATTEMPT")
    _require(POSITIVE.fullmatch(run_id) is not None and attempt == "1", "invalid run identity")
    staging = _required("REPORT_STAGING")
    _require(staging == f"/var/tmp/cogs-stage2-local-result-{run_id}-1",
             "report staging identity differs")
    implementation, manifest = _required("EXPECTED_IMPLEMENTATION_HEAD"), _required("EXPECTED_SOURCE_MANIFEST_SHA256")
    schema = _required("EXPECTED_RESULT_SCHEMA_SHA256")
    _require(SHA1.fullmatch(implementation) is not None and SHA256.fullmatch(manifest) is not None
             and SHA256.fullmatch(schema) is not None, "reviewed publication identity invalid")
    runner_uid = _required("TRUSTED_RUNNER_UID")
    _require(runner_uid.isdecimal() and int(runner_uid) > 0 and os.geteuid() == 0,
             "root publication for a non-root runner is required")
    digest, size, result, failure = publish(staging, implementation, manifest, schema, int(runner_uid))
    print(f"report_sha256={digest}")
    print(f"report_bytes={size}")
    print(f"report_result={result}")
    print(f"failure_code={failure if failure is not None else 'none'}")


if __name__ == "__main__":
    try:
        main()
    except (LocalPublicationError, OSError):
        raise SystemExit(2)

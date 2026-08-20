#!/usr/bin/env python3
"""Freeze, validate, and atomically publish the native candidate bytes."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
from completion_runtime_contract import canonical_json, validate_native_candidate_result

MAX_CANDIDATE_BYTES = 4096
MAX_ALIAS_PASSES = 12
REQUIRED_ALIAS_PASSES = 2
VANISHED = frozenset((errno.ENOENT, errno.ESRCH))
POSITIVE = re.compile(r"[1-9][0-9]*")


class PublicationError(Exception):
    pass


def _generation(value):
    """Security-relevant inode generation; atime is excluded because this owner reads it."""
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_rdev, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _rename_generation(before, after):
    left, right = list(_generation(before)), list(_generation(after))
    before_ctime, after_ctime = left.pop(), right.pop()
    return left == right and after_ctime >= before_ctime


def _read_bounded(descriptor, maximum, after_read=None):
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, maximum + 1)
    if after_read is not None:
        after_read()
    after = os.fstat(descriptor)
    if _generation(after) != _generation(before):
        raise PublicationError("candidate generation changed while reading")
    if not 0 < len(raw) <= maximum:
        raise PublicationError("candidate byte bound failed")
    return raw, after


def _starttime(proc_root, name):
    try:
        raw = (proc_root / name / "stat").read_bytes()
    except OSError as error:
        if error.errno in VANISHED:
            return None
        raise PublicationError("process generation inspection failed") from error
    close = raw.rfind(b")")
    fields = raw[close + 2:].split() if close >= 0 else ()
    if len(fields) < 20 or not fields[19].isdigit():
        raise PublicationError("invalid process generation")
    return int(fields[19])


def _process_uid(proc_root, name):
    try:
        rows = (proc_root / name / "status").read_bytes().splitlines()
    except OSError as error:
        if error.errno in VANISHED:
            return None
        raise PublicationError("process ownership inspection failed") from error
    values = [row.split() for row in rows if row.startswith(b"Uid:")]
    if len(values) != 1 or len(values[0]) != 5 or not values[0][2].isdigit():
        raise PublicationError("invalid process ownership")
    return int(values[0][2])


def _inventory(proc_root):
    try:
        names = os.listdir(proc_root)
    except OSError as error:
        raise PublicationError("process inventory failed") from error
    result = {}
    complete = True
    effective_uid = os.geteuid()
    for name in names:
        if not name.isdecimal():
            continue
        uid = _process_uid(proc_root, name)
        if uid is None:
            complete = False
            continue
        # The 0700 staging directory and 0400 candidate exclude other unprivileged
        # UIDs. Privileged host processes are trusted by this workflow's host model.
        if uid != effective_uid:
            continue
        identity = _starttime(proc_root, name)
        if identity is None:
            complete = False
        else:
            result[name] = identity
    return result, complete


def _fd_names(path):
    try:
        return os.listdir(path)
    except OSError as error:
        if error.errno in VANISHED:
            return None
        raise PublicationError("descriptor inventory failed") from error


def _writable_alias_sweep(proc_root, expected, inventory):
    stable = True
    for name, starttime in inventory.items():
        if _starttime(proc_root, name) != starttime:
            stable = False
            continue
        base = proc_root / name
        descriptors = _fd_names(base / "fd")
        if descriptors is None:
            stable = False
            continue
        for descriptor in descriptors:
            path = base / "fd" / descriptor
            try:
                observed = os.stat(path)
            except OSError as error:
                if error.errno in VANISHED:
                    stable = False
                    continue
                raise PublicationError("descriptor identity inspection failed") from error
            if (observed.st_dev, observed.st_ino) != expected:
                continue
            try:
                info = (base / "fdinfo" / descriptor).read_bytes()
            except OSError as error:
                if error.errno in VANISHED:
                    stable = False
                    continue
                raise PublicationError("descriptor mode inspection failed") from error
            flags = [line.split()[1] for line in info.splitlines()
                     if line.startswith(b"flags:") and len(line.split()) == 2]
            if len(flags) != 1:
                raise PublicationError("descriptor mode is invalid")
            try:
                access = int(flags[0], 8) & os.O_ACCMODE
            except ValueError as error:
                raise PublicationError("descriptor mode is invalid") from error
            if access != os.O_RDONLY:
                raise PublicationError(f"candidate has writable descriptor alias: {name}/{descriptor}")
        if _starttime(proc_root, name) != starttime:
            stable = False
    return stable


def prove_no_writable_aliases(descriptor, proc_root=Path("/proc")):
    expected = os.fstat(descriptor)
    identity = expected.st_dev, expected.st_ino
    signature = None
    consecutive = 0
    for _ in range(MAX_ALIAS_PASSES):
        before, complete = _inventory(proc_root)
        stable = complete and _writable_alias_sweep(proc_root, identity, before)
        after, final_complete = _inventory(proc_root)
        stable = stable and final_complete and before == after
        current = tuple(sorted(after.items())) if stable else None
        if stable and current == signature:
            consecutive += 1
        elif stable:
            signature, consecutive = current, 1
        else:
            signature, consecutive = None, 0
        if consecutive >= REQUIRED_ALIAS_PASSES:
            if _generation(os.fstat(descriptor)) != _generation(expected):
                raise PublicationError("candidate changed during alias proof")
            return
        time.sleep(0.01)
    raise PublicationError("writable-alias absence did not stabilize")


def _validate(raw, revision, manifest):
    try:
        value = json.loads(raw)
        validate_native_candidate_result(value, revision, manifest)
    except Exception as error:
        raise PublicationError("candidate/source contract differs") from error
    launcher = (ROOT / "scripts/run-stage2-package-native-candidate.py").read_bytes()
    if value["execution_binding"]["launcher_implementation_sha256"] != hashlib.sha256(launcher).hexdigest():
        raise PublicationError("candidate launcher binding differs")
    if raw != canonical_json(value):
        raise PublicationError("candidate is not canonical")
    identity = value["package_identity"]
    required = {"deb_sha256", "deb_bytes", "installed_tree_sha256", "installed_entries",
                "installed_bytes", "package", "version", "architecture"}
    if set(identity) != required:
        raise PublicationError("candidate package identity differs")


def publish(staging, revision, manifest, proc_root=Path("/proc")):
    staging = Path(staging)
    directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    readback = None
    try:
        if set(os.listdir(directory)) != {"candidate.partial"}:
            raise PublicationError("staging does not contain exactly candidate.partial")
        descriptor = os.open("candidate.partial", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory)
        os.fchmod(descriptor, 0o400)
        frozen = os.fstat(descriptor)
        if (not stat.S_ISREG(frozen.st_mode) or stat.S_IMODE(frozen.st_mode) != 0o400
                or frozen.st_nlink != 1):
            raise PublicationError("candidate is not one readonly regular link")
        prove_no_writable_aliases(descriptor, proc_root)
        raw, generation = _read_bounded(descriptor, MAX_CANDIDATE_BYTES)
        _validate(raw, revision, manifest)
        prove_no_writable_aliases(descriptor, proc_root)
        if _generation(os.fstat(descriptor)) != _generation(generation):
            raise PublicationError("candidate changed after validation")
        named = os.stat("candidate.partial", dir_fd=directory, follow_symlinks=False)
        if _generation(named) != _generation(generation):
            raise PublicationError("candidate name differs from validated generation")
        try:
            os.stat("candidate.json", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PublicationError("published candidate already exists")
        os.fsync(descriptor)
        os.rename("candidate.partial", "candidate.json", src_dir_fd=directory, dst_dir_fd=directory)
        renamed = os.fstat(descriptor)
        if not _rename_generation(generation, renamed):
            raise PublicationError("candidate generation changed unexpectedly across rename")
        os.fsync(directory)
        readback = os.open("candidate.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=directory)
        readback_raw, readback_generation = _read_bounded(readback, MAX_CANDIDATE_BYTES)
        if readback_raw != raw or _generation(readback_generation) != _generation(renamed):
            raise PublicationError("published candidate readback differs")
        prove_no_writable_aliases(readback, proc_root)
        return hashlib.sha256(raw).hexdigest(), len(raw)
    finally:
        if readback is not None:
            os.close(readback)
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _required(name):
    value = os.environ.get(name)
    if not value:
        raise PublicationError(f"missing {name}")
    return value


def main():
    if sys.argv[1:] != ["publish"]:
        raise PublicationError("usage: stage2-native-publication.py publish")
    run_id = _required("GITHUB_RUN_ID")
    attempt = _required("GITHUB_RUN_ATTEMPT")
    if POSITIVE.fullmatch(run_id) is None or POSITIVE.fullmatch(attempt) is None:
        raise PublicationError("invalid run identity")
    staging = _required("CANDIDATE_STAGING")
    if staging != f"/var/tmp/cogs-stage2-native-package-candidate-{run_id}-{attempt}":
        raise PublicationError("staging identity is not run-unique")
    digest, size = publish(staging, _required("EXPECTED_SOURCE_REVISION"),
                           _required("EXPECTED_SOURCE_MANIFEST_SHA256"))
    print(f"candidate_sha256={digest}")
    print(f"candidate_bytes={size}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PublicationError):
        raise SystemExit(2)

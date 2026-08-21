#!/usr/bin/env python3
"""Freeze, validate, and atomically publish the native candidate bytes."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
from completion_package_native_codec import validate_native_candidate_result
from completion_runtime_contract import canonical_json

MAX_CANDIDATE_BYTES = 4096
MAX_ALIAS_PASSES = 120
REQUIRED_ALIAS_PASSES = 2
MAX_PROC_ENTRIES = 32768
MAX_FD_ENTRIES = 65536
MAX_SMALL_PROC_BYTES = 1024 * 1024
MAX_LARGE_PROC_BYTES = 8 * 1024 * 1024
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
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise PublicationError("candidate byte bound failed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, maximum + 1)
    if after_read is not None:
        after_read()
    os.lseek(descriptor, 0, os.SEEK_SET)
    repeated = os.read(descriptor, maximum + 1)
    after = os.fstat(descriptor)
    if _generation(after) != _generation(before) or repeated != raw:
        raise PublicationError("candidate generation or bytes changed while reading")
    if len(raw) != before.st_size:
        raise PublicationError("candidate byte read was incomplete")
    return raw, after


def _proc_bytes(path, maximum, message):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                return bytes(raw)
            raw.extend(chunk)
        raise PublicationError(message)
    except OSError as error:
        if error.errno in VANISHED:
            return None
        raise PublicationError(message) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bounded_names(path, maximum, message, vanished=False):
    try:
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= maximum:
                    raise PublicationError(message)
                names.append(entry.name)
        return names
    except OSError as error:
        if vanished and error.errno in VANISHED:
            return None
        raise PublicationError(message) from error


def _starttime(proc_root, name):
    raw = _proc_bytes(proc_root / name / "stat", MAX_SMALL_PROC_BYTES,
                      "process generation inspection failed")
    if raw is None:
        return None
    close = raw.rfind(b")")
    fields = raw[close + 2:].split() if close >= 0 else ()
    if len(fields) < 20 or not fields[19].isdigit():
        raise PublicationError("invalid process generation")
    return int(fields[19])


def _process_uid(proc_root, name):
    raw = _proc_bytes(proc_root / name / "status", MAX_SMALL_PROC_BYTES,
                      "process ownership inspection failed")
    if raw is None:
        return None
    rows = raw.splitlines()
    values = [row.split() for row in rows if row.startswith(b"Uid:")]
    if len(values) != 1 or len(values[0]) != 5 or not values[0][2].isdigit():
        raise PublicationError("invalid process ownership")
    return int(values[0][2])


def _owned_generation(proc_root, name, owner_uid):
    descriptor = None
    try:
        if proc_root == Path("/proc"):
            descriptor = os.pidfd_open(int(name), 0)
        before = _starttime(proc_root, name)
        poller = None
        if descriptor is not None:
            poller = select.poll()
            poller.register(descriptor, select.POLLIN)
            if poller.poll(0):
                return "absent", False, None
        if before is None:
            return (("unstable", False, None) if descriptor is not None
                    else ("absent", False, None))
        uid = _process_uid(proc_root, name)
        after = _starttime(proc_root, name)
        if poller is not None and poller.poll(0):
            return "absent", False, None
        if uid is None or after is None or after != before:
            return "unstable", False, None
        # Root/other host services are trusted; the untrusted publication adversary
        # is every surviving process in the runner UID's generation inventory.
        return "stable", uid == owner_uid, after
    except ProcessLookupError:
        return "absent", False, None
    except (AttributeError, OSError) as error:
        raise PublicationError("process identity inspection failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _inventory(proc_root, owner_uid):
    names = _bounded_names(proc_root, MAX_PROC_ENTRIES, "process inventory failed")
    result = {}
    complete = True
    for name in names:
        if not name.isdecimal():
            continue
        state, owned, identity = _owned_generation(proc_root, name, owner_uid)
        if state == "unstable":
            state, owned, identity = _owned_generation(proc_root, name, owner_uid)
        if state == "stable" and owned:
            result[name] = identity
        elif state == "unstable":
            complete = False
    return result, complete


def _fd_names(path):
    return _bounded_names(path, MAX_FD_ENTRIES, "descriptor inventory failed", vanished=True)


def _writable_alias_sweep(proc_root, expected, inventory):
    inspected = set()
    device = os.major(expected[0]), os.minor(expected[0])
    for name, starttime in inventory.items():
        generation_complete = True
        if _starttime(proc_root, name) != starttime:
            continue
        base = proc_root / name
        mapping_bytes = _proc_bytes(base / "maps", MAX_LARGE_PROC_BYTES,
                                    "mapping inventory failed")
        if mapping_bytes is None:
            continue
        for row in mapping_bytes.splitlines():
            fields = row.split(None, 5)
            try:
                mapped_device = tuple(int(item, 16) for item in fields[3].split(b":"))
                mapped_inode = int(fields[4])
                permissions = fields[1]
                if len(mapped_device) != 2 or len(permissions) != 4:
                    raise ValueError
            except (IndexError, ValueError) as error:
                raise PublicationError("mapping identity is invalid") from error
            if (mapped_device == device and mapped_inode == expected[1]
                    and permissions[3:4] == b"s"):
                raise PublicationError(f"candidate has writable shared mapping: {name}")
        descriptors = _fd_names(base / "fd")
        if descriptors is None:
            continue
        for descriptor in descriptors:
            path = base / "fd" / descriptor
            try:
                observed = os.stat(path)
            except OSError as error:
                if error.errno in VANISHED:
                    generation_complete = False
                    continue
                raise PublicationError("descriptor identity inspection failed") from error
            if (observed.st_dev, observed.st_ino) != expected:
                continue
            info = _proc_bytes(base / "fdinfo" / descriptor, MAX_SMALL_PROC_BYTES,
                               "descriptor mode inspection failed")
            if info is None:
                generation_complete = False
                continue
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
            generation_complete = False
        if generation_complete:
            inspected.add((name, starttime))
    return inspected


def prove_no_writable_aliases(descriptor, owner_uid, proc_root=Path("/proc")):
    expected = os.fstat(descriptor)
    identity = expected.st_dev, expected.st_ino
    empty_coverage = 0
    coverage = {}
    for _ in range(MAX_ALIAS_PASSES):
        before, complete = _inventory(proc_root, owner_uid)
        inspected = _writable_alias_sweep(proc_root, identity, before)
        after, final_complete = _inventory(proc_root, owner_uid)
        current = set(after.items())
        if complete and final_complete:
            coverage = {
                generation: min(REQUIRED_ALIAS_PASSES,
                                coverage.get(generation, 0) + 1)
                if generation in inspected else 0
                for generation in current
            }
            empty_coverage = empty_coverage + 1 if not current else 0
            covered = ((current and all(count >= REQUIRED_ALIAS_PASSES
                                        for count in coverage.values()))
                       or (not current and empty_coverage >= REQUIRED_ALIAS_PASSES))
            if covered:
                if _generation(os.fstat(descriptor)) != _generation(expected):
                    raise PublicationError("candidate changed during alias proof")
                return
        else:
            empty_coverage, coverage = 0, {}
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


def publish(staging, revision, manifest, runner_uid, proc_root=Path("/proc"),
            frozen_uid=0, frozen_gid=0, after_copy=None):
    staging = Path(staging)
    directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    source = fresh = readback = None
    try:
        if set(os.listdir(directory)) != {"candidate.partial"}:
            raise PublicationError("staging does not contain exactly candidate.partial")
        source = os.open("candidate.partial", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
        initial, initial_directory = os.fstat(source), os.fstat(directory)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1
                or initial.st_uid != runner_uid or not stat.S_ISDIR(initial_directory.st_mode)
                or initial_directory.st_uid != runner_uid):
            raise PublicationError("candidate staging ownership differs")
        raw, source_generation = _read_bounded(source, MAX_CANDIDATE_BYTES)
        _validate(raw, revision, manifest)
        if _generation(os.fstat(source)) != _generation(source_generation):
            raise PublicationError("candidate source changed after validation")
        os.fchown(directory, frozen_uid, frozen_gid)
        os.fchmod(directory, 0o700)
        frozen_directory = os.fstat(directory)
        if (frozen_directory.st_uid != frozen_uid or frozen_directory.st_gid != frozen_gid
                or stat.S_IMODE(frozen_directory.st_mode) != 0o700
                or _generation(os.stat(staging, follow_symlinks=False)) != _generation(frozen_directory)
                or _generation(os.stat("candidate.partial", dir_fd=directory,
                                       follow_symlinks=False)) != _generation(source_generation)):
            raise PublicationError("candidate source authority transition differs")
        fresh = os.open("candidate.fresh", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            written = os.write(fresh, view)
            if written <= 0:
                raise PublicationError("fresh candidate write did not progress")
            view = view[written:]
        os.fchown(fresh, frozen_uid, frozen_gid)
        os.fchmod(fresh, 0o444)
        os.fsync(fresh)
        fresh_generation = os.fstat(fresh)
        if (not stat.S_ISREG(fresh_generation.st_mode) or fresh_generation.st_nlink != 1
                or fresh_generation.st_uid != frozen_uid or fresh_generation.st_gid != frozen_gid
                or stat.S_IMODE(fresh_generation.st_mode) != 0o444):
            raise PublicationError("fresh candidate generation did not freeze")
        os.close(fresh)
        fresh = None
        fresh = os.open("candidate.fresh", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory)
        copied_raw, fresh_generation = _read_bounded(fresh, MAX_CANDIDATE_BYTES)
        _validate(copied_raw, revision, manifest)
        if copied_raw != raw:
            raise PublicationError("fresh candidate differs from validated source bytes")
        if after_copy is not None:
            after_copy()
        os.unlink("candidate.partial", dir_fd=directory)
        os.rename("candidate.fresh", "candidate.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fchmod(directory, 0o555)
        renamed = os.fstat(fresh)
        if not _rename_generation(fresh_generation, renamed):
            raise PublicationError("fresh candidate changed unexpectedly across rename")
        final_directory = os.fstat(directory)
        if (set(os.listdir(directory)) != {"candidate.json"}
                or stat.S_IMODE(final_directory.st_mode) != 0o555
                or _generation(os.stat(staging, follow_symlinks=False)) != _generation(final_directory)):
            raise PublicationError("published staging is not root-owned readonly and traversable")
        os.fsync(directory)
        readback = os.open("candidate.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=directory)
        readback_raw, readback_generation = _read_bounded(readback, MAX_CANDIDATE_BYTES)
        if readback_raw != raw or _generation(readback_generation) != _generation(renamed):
            raise PublicationError("published fresh candidate readback differs")
        prove_no_writable_aliases(readback, runner_uid, proc_root)
        return hashlib.sha256(raw).hexdigest(), len(raw)
    finally:
        if readback is not None:
            os.close(readback)
        if fresh is not None:
            os.close(fresh)
        if source is not None:
            os.close(source)
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
    runner_uid = _required("TRUSTED_RUNNER_UID")
    if not runner_uid.isdecimal() or int(runner_uid) == 0 or os.geteuid() != 0:
        raise PublicationError("root publication for a non-root runner is required")
    digest, size = publish(staging, _required("EXPECTED_SOURCE_REVISION"),
                           _required("EXPECTED_SOURCE_MANIFEST_SHA256"), int(runner_uid))
    print(f"candidate_sha256={digest}")
    print(f"candidate_bytes={size}")


def _failure_token(error):
    message = str(error)
    categories = (
        ("writable-alias absence did not stabilize", "alias-nonconvergence"),
        ("candidate has writable shared mapping", "writable-shared-mapping"),
        ("candidate has writable descriptor alias", "writable-descriptor"),
        ("candidate changed", "candidate-mutation"),
        ("candidate generation", "candidate-mutation"),
        ("candidate byte read", "candidate-mutation"),
        ("source candidate changed", "candidate-mutation"),
        ("fresh candidate", "candidate-mutation"),
        ("published fresh candidate readback", "candidate-mutation"),
        ("process ", "alias-inspection"),
        ("invalid process ", "alias-inspection"),
        ("mapping ", "alias-inspection"),
        ("descriptor ", "alias-inspection"),
        ("candidate/source contract", "candidate-contract"),
        ("usage:", "request-error"),
        ("missing ", "request-error"),
        ("invalid run identity", "request-error"),
        ("staging identity", "request-error"),
        ("root publication", "request-error"),
    )
    return next((token for prefix, token in categories if message.startswith(prefix)),
                "publication-error")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PublicationError) as error:
        print(f"native publication failed:{_failure_token(error)}", file=sys.stderr)
        raise SystemExit(2)

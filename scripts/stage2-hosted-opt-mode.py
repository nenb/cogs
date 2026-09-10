#!/usr/bin/env python3
"""Durable held-directory custody for hosted Stage2 /opt mode transitions."""
import json
import os
from pathlib import Path
import re
import stat
import sys

OPT = Path("/opt")
STATE = Path("/run/cogs-stage2-hosted-opt-v1.json")
VERSION = "cogs.stage2-hosted-opt-custody/v1"
POSITIVE = re.compile(r"[1-9][0-9]*")
MAX_STATE = 1024


class OptModeError(Exception):
    pass


def _require(value):
    if not value:
        raise OptModeError("hosted opt custody refused")


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_nlink)


def _generation(value):
    return (_identity(value), value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _absent(directory, name="kata"):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise OptModeError("hosted scaffold absence uncertain") from error
    raise OptModeError("hosted scaffold descendant remains")


def _stable_absent(directory, name="kata"):
    before = os.fstat(directory)
    _absent(directory, name)
    _require(_generation(before) == _generation(os.fstat(directory)))


def _path_generation(path, expected_uid, expected_gid):
    try:
        seen = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise OptModeError("hosted opt identity unavailable") from error
    _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid
             and seen.st_gid == expected_gid)
    return _generation(seen)


def _open_opt(path, expected_uid, expected_gid):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory = os.open(path, flags)
    except OSError as error:
        raise OptModeError("hosted opt open refused") from error
    try:
        seen = os.fstat(directory)
        _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid
                 and seen.st_gid == expected_gid and stat.S_IMODE(seen.st_mode) in {0o755, 0o777}
                 and _generation(seen) == _path_generation(path, expected_uid, expected_gid))
        return directory, seen
    except BaseException:
        os.close(directory)
        raise


def _state_parent(path, expected_uid, expected_gid):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(path.parent, flags)
    try:
        seen = os.fstat(parent)
        _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid
                 and seen.st_gid == expected_gid and not stat.S_IMODE(seen.st_mode) & 0o022)
        return parent
    except BaseException:
        os.close(parent)
        raise


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def _write_state(path, value, expected_uid, expected_gid):
    raw = _canonical(value)
    _require(0 < len(raw) <= MAX_STATE)
    parent = _state_parent(path, expected_uid, expected_gid)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o400, dir_fd=parent)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(type(written) is int and written > 0)
            view = view[written:]
        os.fchown(descriptor, expected_uid, expected_gid)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        seen = os.fstat(descriptor)
        _require(stat.S_ISREG(seen.st_mode) and seen.st_nlink == 1
                 and seen.st_uid == expected_uid and seen.st_gid == expected_gid
                 and stat.S_IMODE(seen.st_mode) == 0o400 and seen.st_size == len(raw))
        os.fsync(parent)
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(parent)


def _read_state(path, expected_uid, expected_gid):
    parent = _state_parent(path, expected_uid, expected_gid)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == expected_uid and before.st_gid == expected_gid
                 and stat.S_IMODE(before.st_mode) == 0o400 and 0 < before.st_size <= MAX_STATE)
        chunks, total = [], 0
        while total < before.st_size:
            part = os.read(descriptor, before.st_size - total)
            _require(part)
            chunks.append(part); total += len(part)
        _require(not os.read(descriptor, 1))
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and _generation(before) == _generation(after))
        value = json.loads(raw)
        _require(type(value) is dict and _canonical(value) == raw
                 and set(value) == {"attempt", "device", "inode", "nlink", "original_mode",
                                    "run_id", "uid", "gid", "version"})
        return parent, descriptor, before, value
    except (OSError, UnicodeError, ValueError) as error:
        if descriptor is not None: os.close(descriptor)
        os.close(parent)
        raise OptModeError("hosted opt custody unavailable") from error
    except BaseException:
        if descriptor is not None: os.close(descriptor)
        os.close(parent)
        raise


def _fixed_absent(path, expected_uid, expected_gid):
    _require(path.is_absolute() and len(path.parts) >= 3)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=parent)
            try:
                seen = os.fstat(child)
                _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid
                         and seen.st_gid == expected_gid and not stat.S_IMODE(seen.st_mode) & 0o022)
            except BaseException:
                os.close(child)
                raise
            os.close(parent); parent = child
        _stable_absent(parent, path.name)
    finally:
        os.close(parent)


def baseline(path=OPT, expected_uid=0, expected_gid=0):
    for fixed in ("/var/lib/cogs", "/run/netns", "/run/cogs-stage2-local-private-v2",
                  "/run/cogs-stage2-native-preflight-source-v1",
                  "/run/cogs-stage2-native-private-v1",
                  "/run/cogs-stage2-mixed-hg-owner-v1",
                  "/run/cogs-stage2-mixed-hg-source-v1"):
        _fixed_absent(Path(fixed), expected_uid, expected_gid)
    directory, _ = _open_opt(path, expected_uid, expected_gid)
    try: _stable_absent(directory)
    finally: os.close(directory)


def normalize(run_id, attempt, path=OPT, state=STATE, expected_uid=0, expected_gid=0):
    _require(type(run_id) is str and type(attempt) is str
             and len(run_id) <= 32 and len(attempt) <= 32
             and POSITIVE.fullmatch(run_id) is not None and POSITIVE.fullmatch(attempt) is not None)
    directory, before = _open_opt(path, expected_uid, expected_gid)
    original = stat.S_IMODE(before.st_mode)
    receipt = {"attempt": attempt, "device": before.st_dev, "gid": before.st_gid,
               "inode": before.st_ino, "nlink": before.st_nlink, "original_mode": original,
               "run_id": run_id, "uid": before.st_uid, "version": VERSION}
    state_written = False
    try:
        _stable_absent(directory)
        _write_state(state, receipt, expected_uid, expected_gid); state_written = True
        try:
            if original != 0o755: os.fchmod(directory, 0o755)
            os.fsync(directory)
            post_mode = os.fstat(directory)
            _stable_absent(directory)
            after = os.fstat(directory)
            _require(_generation(post_mode) == _generation(after)
                     and _identity(after) == _identity(before) and stat.S_IMODE(after.st_mode) == 0o755
                     and _path_generation(path, expected_uid, expected_gid) == _generation(after))
        except BaseException:
            if state_written:
                try:
                    os.fchmod(directory, original); os.fsync(directory)
                except OSError:
                    pass
            raise
    finally:
        os.close(directory)


def restore(run_id, attempt, path=OPT, state=STATE, expected_uid=0, expected_gid=0):
    _require(type(run_id) is str and type(attempt) is str
             and len(run_id) <= 32 and len(attempt) <= 32
             and POSITIVE.fullmatch(run_id) is not None and POSITIVE.fullmatch(attempt) is not None)
    parent, receipt_fd, receipt_seen, receipt = _read_state(state, expected_uid, expected_gid)
    directory = None
    try:
        integer_fields = ("device", "inode", "uid", "gid", "nlink", "original_mode")
        _require(receipt["version"] == VERSION and type(receipt["version"]) is str
                 and receipt["run_id"] == run_id and type(receipt["run_id"]) is str
                 and receipt["attempt"] == attempt and type(receipt["attempt"]) is str
                 and all(type(receipt[name]) is int and receipt[name] >= 0 for name in integer_fields)
                 and receipt["inode"] > 0 and receipt["nlink"] > 0
                 and receipt["original_mode"] in {0o755, 0o777})
        directory, current = _open_opt(path, expected_uid, expected_gid)
        expected_identity = (receipt["device"], receipt["inode"], receipt["uid"],
                             receipt["gid"], receipt["nlink"])
        entry_mode = stat.S_IMODE(current.st_mode)
        _require(_identity(current) == expected_identity
                 and entry_mode in {0o755, receipt["original_mode"]})
        _stable_absent(directory)
        consumed = False
        try:
            if entry_mode != receipt["original_mode"]:
                os.fchmod(directory, receipt["original_mode"])
            os.fsync(directory)
            post_mode = os.fstat(directory)
            _stable_absent(directory)
            after = os.fstat(directory)
            _require(_generation(post_mode) == _generation(after)
                     and _identity(after) == expected_identity
                     and stat.S_IMODE(after.st_mode) == receipt["original_mode"]
                     and _path_generation(path, expected_uid, expected_gid) == _generation(after))
            named = os.stat(state.name, dir_fd=parent, follow_symlinks=False)
            _require(_generation(named) == _generation(receipt_seen)
                     and _generation(os.fstat(receipt_fd)) == _generation(receipt_seen))
            os.unlink(state.name, dir_fd=parent); consumed = True
            os.fsync(parent)
        except BaseException:
            if not consumed:
                try:
                    os.fchmod(directory, entry_mode); os.fsync(directory)
                except OSError:
                    pass
            raise
    finally:
        if directory is not None: os.close(directory)
        os.close(receipt_fd); os.close(parent)


def main():
    _require(os.geteuid() == 0 and len(sys.argv) in {2, 4})
    action = sys.argv[1]
    if action == "baseline" and len(sys.argv) == 2:
        baseline(); raw = b"hosted_scaffold_absent=true\n"
    elif action == "normalize" and len(sys.argv) == 4:
        normalize(sys.argv[2], sys.argv[3]); raw = b"hosted_opt_normalized=true\n"
    elif action == "restore" and len(sys.argv) == 4:
        restore(sys.argv[2], sys.argv[3]); raw = b"hosted_opt_restored=true\n"
    else:
        raise OptModeError("hosted opt action refused")
    written = os.write(1, raw)
    _require(written == len(raw))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(2) from None

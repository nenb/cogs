#!/usr/bin/env python3
"""Validate reviewed G control bytes with H's V2 codec and freeze fixed staging."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v2"
PROVISIONAL_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/control-observation-v1/candidate")
H_PREPARATION = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_kata_preparation.py")
DESTINATION = Path("/var/lib/cogs/stage2-completion-v1/control")
CONTROL_MEMBER = "stage2-local-static-control-v1.json"
PROVISIONAL_CONTROL_MEMBER = "stage2-local-static-control-v2.json"
MAX_MEMBERS = 16


class ControlStagingError(Exception):
    pass


def _require(condition, message="reviewed control staging failed"):
    if not condition:
        raise ControlStagingError(message)


def _load_preparation():
    spec = importlib.util.spec_from_file_location("completion_kata_preparation_staging", H_PREPARATION)
    _require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_regular(directory, relative, maximum):
    _require(type(relative) is str and relative
             and all(part not in {"", ".", ".."} for part in relative.split("/")))
    parent = os.dup(directory)
    descriptor = None
    try:
        components = relative.split("/")
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= maximum)
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and (before.st_dev, before.st_ino,
                 before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns), "control source changed")
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _write_frozen(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(type(written) is int and written > 0)
            view = view[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        seen = os.fstat(descriptor)
        _require(seen.st_uid == seen.st_gid == 0 and stat.S_IMODE(seen.st_mode) == 0o400
                 and seen.st_nlink == 1 and seen.st_size == len(raw))
    finally:
        os.close(descriptor)


def _stage(source_path, source_control_member):
    _require(os.geteuid() == 0 and not DESTINATION.exists())
    _require((source_path, source_control_member) in {
        (SOURCE, CONTROL_MEMBER), (PROVISIONAL_SOURCE, PROVISIONAL_CONTROL_MEMBER)})
    preparation = _load_preparation()
    source = os.open(source_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        source_identity = os.fstat(source)
        control_raw = _read_regular(source, source_control_member, preparation.MAX_CONTROL_BYTES)
        control = preparation.load_control(control_raw)
        rows = control.value["members"]
        _require(type(rows) is list and 1 <= len(rows) <= MAX_MEMBERS)
        members = {}
        for row in rows:
            name = row["name"]
            _require(type(name) is str and name not in members)
            members[name] = _read_regular(source, name, row["size"])
        preparation.validate_control_members(control, members)
        _require(os.fstat(source) == source_identity, "control package directory changed")
    finally:
        os.close(source)
    created_files, created_directories = [], []
    try:
        DESTINATION.mkdir(mode=0o500)
        created_directories.append(DESTINATION)
        for name, raw in [(CONTROL_MEMBER, control_raw), *sorted(members.items())]:
            target = DESTINATION / name
            missing = []
            parent = target.parent
            while parent != DESTINATION and not parent.exists():
                missing.append(parent)
                parent = parent.parent
            _require(parent == DESTINATION or parent.is_dir())
            for directory in reversed(missing):
                directory.mkdir(mode=0o500)
                os.chown(directory, 0, 0)
                created_directories.append(directory)
            _write_frozen(target, raw)
            created_files.append(target)
        for directory in reversed(created_directories):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return hashlib.sha256(control_raw).hexdigest()
    except BaseException:
        for path in reversed(created_files):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for path in reversed(created_directories):
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
        raise


def stage():
    return _stage(SOURCE, CONTROL_MEMBER)


def stage_provisional():
    return _stage(PROVISIONAL_SOURCE, PROVISIONAL_CONTROL_MEMBER)


def main():
    _require(len(sys.argv) in {1, 2})
    _require(len(sys.argv) == 1 or sys.argv[1] == "provisional")
    digest = stage() if len(sys.argv) == 1 else stage_provisional()
    raw = f"control_sha256={digest}\n".encode("ascii")
    _require(sys.stdout.buffer.write(raw) == len(raw))


if __name__ == "__main__":
    try:
        main()
    except (ControlStagingError, OSError):
        raise SystemExit(2)

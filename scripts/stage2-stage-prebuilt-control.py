#!/usr/bin/env python3
"""Validate prebuilt G control bytes with H's V3 codec and freeze staging."""
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import runpy
retirement = runpy.run_path(str(Path(__file__).with_name("stage2-revision-retirement.py")))

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v7"
QUALIFICATION_SOURCE = Path(
    "/root/cogs-stage2-bootstrap/Q/deploy/aws-feasibility/remote/stage2-completion-local-control-v7")
CHECKOUT_PREPARATION = ROOT / "deploy/aws-feasibility/remote/completion_kata_preparation.py"
CHECKOUT_ADMISSION = ROOT / "deploy/aws-feasibility/remote/completion_kata_admission.py"
PROVISIONAL_SOURCE = Path(
    "/var/lib/cogs/stage2-completion-v1/control-observation-v1/candidate")
H_PREPARATION = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_kata_preparation.py")
DIAGNOSTIC_CONTROL = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_kata_diagnostic_control.py")
DESTINATION = Path("/var/lib/cogs/stage2-completion-v1/control")
CONTROL_MEMBER = "stage2-local-static-control-v2.json"
DIAGNOSTIC_VERSION = "cogs.stage2-current-source-prebuilt-diagnostic-control/v1"
DIAGNOSTIC_MEMBER = "stage2-current-source-prebuilt-diagnostic-control-v1.json"
MAX_MEMBERS = 16


class ControlStagingError(Exception):
    pass


def _require(condition, message="reviewed control staging failed"):
    if not condition:
        raise ControlStagingError(message)


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_admission():
    module = importlib.import_module("completion_kata_admission")
    _require(Path(module.__file__).resolve() == CHECKOUT_ADMISSION.resolve())
    return module


def _read_complete(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        part = os.read(descriptor, min(65_536, remaining))
        _require(part, "control member was truncated")
        chunks.append(part); remaining -= len(part)
    _require(not os.read(descriptor, 1))
    return b"".join(chunks)


def _read_regular(directory, relative, maximum, private=False):
    _require(type(relative) is str and relative
             and all(part not in {"", ".", ".."} for part in relative.split("/")))
    parent = os.dup(directory)
    descriptor = child = None
    try:
        components = relative.split("/")
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            seen = os.fstat(child)
            valid = not private or (seen.st_uid == seen.st_gid == 0
                     and stat.S_IMODE(seen.st_mode) == 0o700)
            _require(valid)
            previous = parent; parent = child; child = None
            os.close(previous)
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and (not private or (before.st_uid == before.st_gid == 0
                      and stat.S_IMODE(before.st_mode) == 0o600))
                 and 0 < before.st_size <= maximum)
        raw = _read_complete(descriptor, before.st_size)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and (before.st_dev, before.st_ino,
                 before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns), "control source changed")
        return raw
    finally:
        if child is not None:
            os.close(child)
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_frozen(directory, relative, maximum, held):
    _require(type(relative) is str and type(held) is list and relative
             and all(part not in {"", ".", ".."} for part in relative.split("/")))
    parent, descriptor, child = os.dup(directory), None, None
    try:
        for component in relative.split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            seen = os.fstat(child)
            _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                     and stat.S_IMODE(seen.st_mode) == 0o500)
            held.append((parent, _identity(os.fstat(parent)))); parent = child; child = None
        descriptor = os.open(relative.split("/")[-1], os.O_RDONLY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1
                 and 0 < before.st_size <= maximum)
        raw = _read_complete(descriptor, before.st_size)
        _require(len(raw) == before.st_size and _identity(before) == _identity(os.fstat(descriptor)),
                 "frozen control member changed")
        held.extend(((parent, _identity(os.fstat(parent))), (descriptor, _identity(before))))
        parent = descriptor = None
        return raw
    finally:
        if child is not None: os.close(child)
        if descriptor is not None: os.close(descriptor)
        if parent is not None: os.close(parent)


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


def _open_source(source_path):
    if source_path != QUALIFICATION_SOURCE:
        return os.open(source_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    child = None
    try:
        seen = os.fstat(parent)
        _require(seen.st_uid == seen.st_gid == 0 and stat.S_IMODE(seen.st_mode) == 0o755)
        for component in source_path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            seen = os.fstat(child); expected = 0o700
            valid = seen.st_uid == seen.st_gid == 0 and stat.S_IMODE(seen.st_mode) == expected
            _require(valid)
            previous = parent; parent = child; child = None
            os.close(previous)
        return parent
    except BaseException:
        if child is not None: os.close(child)
        os.close(parent); raise


def _select_prebuilt_custody(control, envelope):
    rootfs = envelope.value["rootfs"]
    custody = rootfs["custody"]
    publication = custody["publication_receipt"]
    implementation = control.value["implementation"]["revision"]
    control_revision = control.value["producer"]["control_revision"]
    retirement["select"]((implementation, control_revision, publication["control_revision"],
        rootfs["prebuilt_descriptor"]["producer"]["revision"],
        custody["provenance"]["builder"]["implementation_revision"],
        custody["qualification_receipt"]["implementation_revision"], publication["implementation_revision"]),
        runs=(str(publication["producer_run_id"]), str(publication["publisher_run_id"]),
              str(custody["provenance"]["builder"]["run_id"]), str(custody["qualification_receipt"]["run_id"])),
        artifacts=(str(publication["producer_artifact_id"]),))
    return implementation, control_revision, rootfs


def _stage(source_path, diagnostic_version=None):
    _require(os.geteuid() == 0 and not DESTINATION.exists())
    _require(source_path in {SOURCE, QUALIFICATION_SOURCE, PROVISIONAL_SOURCE})
    _require(diagnostic_version is None or (
        source_path == PROVISIONAL_SOURCE and diagnostic_version == DIAGNOSTIC_VERSION))
    codec = (_load_module(DIAGNOSTIC_CONTROL, "completion_kata_diagnostic_control_staging")
             if diagnostic_version is not None else
             _load_module(H_PREPARATION, "completion_kata_preparation_staging"))
    control_member = DIAGNOSTIC_MEMBER if diagnostic_version is not None else CONTROL_MEMBER
    maximum = codec.MAX_BYTES if diagnostic_version is not None else codec.MAX_CONTROL_BYTES
    source = _open_source(source_path)
    try:
        source_identity = os.fstat(source)
        private = source_path == QUALIFICATION_SOURCE
        control_raw = _read_regular(source, control_member, maximum, private)
        control = codec.load_control(control_raw)
        rows = control.value["members"]
        _require(type(rows) is list and 1 <= len(rows) <= MAX_MEMBERS)
        members = {}
        for row in rows:
            name = row["name"]
            _require(type(name) is str and name not in members)
            members[name] = _read_regular(
                source, name, _member_maximum(codec, row, diagnostic_version is not None), private)
        validated = codec.validate_control_members(control, members)
        if diagnostic_version is None:
            implementation, control_revision, rootfs = _select_prebuilt_custody(control, validated[0])
        else:
            implementation = control.value["runtime_implementation"]["revision"]
            control_revision = control.value["publication_producer"]["control_revision"]
            rootfs = control.value["rootfs"]
            custody = rootfs["custody"]
            publication = custody["publication_receipt"]
            retirement["select"]((implementation, control_revision, publication["control_revision"],
                rootfs["prebuilt_descriptor"]["producer"]["revision"],
                custody["provenance"]["builder"]["implementation_revision"],
                custody["qualification_receipt"]["implementation_revision"], publication["implementation_revision"]),
                runs=(str(publication["producer_run_id"]), str(publication["publisher_run_id"]),
                      str(custody["provenance"]["builder"]["run_id"]), str(custody["qualification_receipt"]["run_id"])),
                artifacts=(str(publication["producer_artifact_id"]),))
        _require(os.fstat(source) == source_identity, "control package directory changed")
    finally:
        os.close(source)
    created_files, created_directories = [], []
    try:
        DESTINATION.mkdir(mode=0o500)
        created_directories.append(DESTINATION)
        for name, raw in [(control_member, control_raw), *sorted(members.items())]:
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
    return _stage(SOURCE)


def stage_qualification():
    return _stage(QUALIFICATION_SOURCE)


def _member_maximum(codec, row, diagnostic):
    base = codec.preparation if diagnostic else codec
    maximum = {"envelope": base.MAX_ENVELOPE_BYTES,
               "runtime-manifest": base.MAX_RUNTIME_BYTES,
               "executable-closure": base.MAX_CONTRACT_BYTES}.get(row.get("kind"))
    _require(type(row.get("size")) is int and maximum is not None
             and 0 < row["size"] <= maximum)
    return maximum


def verify_staged(expected_descriptor, diagnostic=False):
    _require(os.geteuid() == 0 and type(diagnostic) is bool and type(expected_descriptor) is str
             and re.fullmatch(r"[0-9a-f]{64}", expected_descriptor) is not None)
    codec = _load_module(DIAGNOSTIC_CONTROL if diagnostic else H_PREPARATION,
                         "completion_kata_control_verification")
    control_member = DIAGNOSTIC_MEMBER if diagnostic else CONTROL_MEMBER
    maximum = codec.MAX_BYTES if diagnostic else codec.MAX_CONTROL_BYTES
    directory = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    held = [(directory, None)]
    try:
        before = os.fstat(directory)
        held[0] = (directory, _identity(before))
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) == 0o500)
        control = codec.load_control(_read_frozen(directory, control_member, maximum, held))
        members = {row["name"]: _read_frozen(
            directory, row["name"], _member_maximum(codec, row, diagnostic), held)
                   for row in control.value["members"]}
        if diagnostic:
            runtime, _ = codec.validate_control_members(control, members)
            envelope = codec.normalized_envelope(control, runtime)
        else:
            envelope, _, _ = codec.validate_control_members(control, members)
        top = {control_member, "contracts", *(name for name in members if "/" not in name)}
        contracts = {name.split("/", 1)[1] for name in members if name.startswith("contracts/")}
        _require(set(os.listdir(directory)) == top)
        contract_fd = os.open("contracts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=directory)
        held.append((contract_fd, None))
        seen = os.fstat(contract_fd); held[-1] = (contract_fd, _identity(seen))
        _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                 and stat.S_IMODE(seen.st_mode) == 0o500
                 and set(os.listdir(contract_fd)) == contracts)
        _require(all(_identity(os.fstat(fd)) == identity for fd, identity in held))
        observed = envelope.value["rootfs"]["prebuilt_descriptor_sha256"]
        _require(observed == expected_descriptor)
        return observed
    finally:
        while held: os.close(held.pop()[0])


def stage_provisional(diagnostic_version=None):
    return _stage(PROVISIONAL_SOURCE, diagnostic_version)


def verify_host_closures(expected_h, expected_g, expected_control):
    """Compare held trusted host closures before any preparation mutation."""
    _require(os.geteuid() != 0 and SOURCE.is_dir()
             and re.fullmatch(r"[0-9a-f]{40}", expected_h) is not None
             and re.fullmatch(r"[0-9a-f]{40}", expected_g) is not None
             and re.fullmatch(r"[0-9a-f]{64}", expected_control) is not None)
    codec = _load_module(CHECKOUT_PREPARATION, "completion_kata_preparation_host_check")
    admission = _load_admission()
    source = _open_source(SOURCE)
    descriptors, retained = [], []
    try:
        source_identity = os.fstat(source)
        control_raw = _read_regular(source, CONTROL_MEMBER, codec.MAX_CONTROL_BYTES)
        control = codec.load_control(control_raw)
        members = {row["name"]: _read_regular(
            source, row["name"], _member_maximum(codec, row, False))
                   for row in control.value["members"]}
        envelope, runtime, contracts = codec.validate_control_members(control, members)
        implementation, control_revision, _ = _select_prebuilt_custody(control, envelope)
        _require(hashlib.sha256(control_raw).hexdigest() == expected_control
                 and implementation == expected_h and control_revision == expected_g,
                 "reviewed host closure binding differs")
        rows = [row for row in runtime.value["executables"] if row["source_class"] == "host-path"]
        _require([row["role"] for row in rows] == ["ip", "tc", "nft", "ssh", "ssh-keygen"])
        for row in rows:
            retained.extend(admission._retain_contract_objects(
                contracts[row["role"]].value, descriptors, row["role"]))
        for item in retained:
            seen = os.fstat(item.descriptor)
            _require((seen.st_dev, seen.st_ino, stat.S_IMODE(seen.st_mode), seen.st_uid,
                      seen.st_gid, seen.st_nlink, seen.st_size) ==
                     (item.device, item.inode, item.mode, item.uid, item.gid, item.nlink, item.size)
                     and admission._read_held(item.descriptor, seen, item.size) == item.sha256,
                     "ambient executable generation differs")
        _require(os.fstat(source) == source_identity, "control package directory changed")
    finally:
        for descriptor in reversed(descriptors):
            try: os.close(descriptor)
            except OSError: pass
        os.close(source)


def main():
    _require(len(sys.argv) in {1, 2, 3, 5})
    if len(sys.argv) == 5 and sys.argv[1] == "verify-host":
        verify_host_closures(*sys.argv[2:])
        raw = b"host_closure_verified=true\n"
    elif len(sys.argv) == 3 and sys.argv[1] in {"verify", "verify-diagnostic"}:
        observed = verify_staged(sys.argv[2], sys.argv[1].endswith("-diagnostic"))
        raw = f"rootfs_descriptor_sha256={observed}\n".encode("ascii")
    else:
        _require(len(sys.argv) == 1 or sys.argv[1] in {"provisional", "stage-qualification"})
        _require(len(sys.argv) < 3 or (sys.argv[1] == "provisional"
                 and sys.argv[2] == DIAGNOSTIC_VERSION))
        digest = (stage() if len(sys.argv) == 1 else stage_qualification()
                  if sys.argv[1] == "stage-qualification" else
                  stage_provisional(None if len(sys.argv) == 2 else sys.argv[2]))
        raw = f"control_sha256={digest}\n".encode("ascii")
    _require(sys.stdout.buffer.write(raw) == len(raw))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(2) from None

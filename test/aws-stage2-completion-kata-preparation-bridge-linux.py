#!/usr/bin/env python3
"""Real Linux descriptor integration/fault test for the no-KVM V2 bridge seam."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_kata_admission as admission
import completion_kata_preparation_bridge as bridge
import completion_kata_process as process
import completion_kata_prestage_runtime as prestage
import completion_rootfs_fs as rootfs_fs


def no_kvm_descriptor():
    for entry in Path("/proc/self/fd").iterdir():
        try:
            if os.readlink(entry) == "/dev/kvm":
                return False
        except FileNotFoundError:
            pass
    return True


def digest(descriptor):
    seen = os.fstat(descriptor)
    value = hashlib.sha256()
    offset = 0
    while offset < seen.st_size:
        raw = os.pread(descriptor, min(1_048_576, seen.st_size - offset), offset)
        assert raw
        value.update(raw)
        offset += len(raw)
    return value.hexdigest()


def retained_set():
    source = "/usr/bin/true"
    assert Path(source).is_file()
    values = []
    for expected in admission.EXECUTABLES:
        role, _source_class, path = expected
        descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        seen = os.fstat(descriptor)
        retained = admission.RetainedObject(
            role, "executable", path, descriptor, seen.st_dev, seen.st_ino,
            seen.st_mode & 0o7777, seen.st_uid, seen.st_gid, seen.st_nlink,
            seen.st_size, digest(descriptor), None, None, ())
        description = admission.ExecutableRoleDescription(
            role, path, "a" * 64, (retained,))
        values.append(bridge._duplicate_role(description, expected))
        os.close(descriptor)
    return values


assert sys.platform.startswith("linux") and no_kvm_descriptor()

# A real closed descriptor must fail before owner or policy issuance.
hostile = retained_set()
os.close(hostile[0].descriptor)
try:
    process._issue_retained_executable_owner(tuple(hostile))
except BaseException:
    pass
else:
    raise AssertionError("closed retained executable issued an owner")
for value in hostile[1:]:
    os.close(value.descriptor)

# Ten real retained descriptors become ten role-associated claims consumed by
# the existing process owner API. No KVM descriptor appears at any point.
values = retained_set()
owner = process._issue_retained_executable_owner(tuple(values))
claimed = []
for role, _source_class, path in admission.EXECUTABLES:
    value = process._claim_attested_executable(owner, role)
    assert (value.role, value.path) == (role, path)
    assert os.fstat(value.descriptor).st_size > 0
    claimed.append(value)
assert no_kvm_descriptor()
for value in claimed:
    process._release_attested_executable(value)
process._abort_attested_executable_owner(owner)
for value in values:
    try:
        os.fstat(value.descriptor)
    except OSError:
        pass
    else:
        raise AssertionError("retained executable descriptor leaked")
assert no_kvm_descriptor()

# Real descriptor-relative crash cuts converge from every static-tree unlink;
# a same-name replacement after the first cut is preserved.
def generation(descriptor):
    seen = os.fstat(descriptor)
    return rootfs_fs.HostGeneration(rootfs_fs.HostKey(
        1, seen.st_dev, seen.st_ino, "directory" if stat.S_ISDIR(seen.st_mode) else "file"),
        stat.S_IMODE(seen.st_mode), seen.st_uid, seen.st_gid, seen.st_nlink,
        seen.st_size, seen.st_mtime_ns, seen.st_ctime_ns)
def node(descriptor): return SimpleNamespace(operation_fd=SimpleNamespace(number=descriptor), generation=generation(descriptor))
def make_tree(base):
    runtime = base / "kata-runtime-v1"; binary = runtime / "bin"
    binary.mkdir(parents=True, mode=0o700)
    (binary / "containerd").write_bytes(b"containerd")
    (binary / "ctr").write_bytes(b"ctr")
    os.chmod(binary / "containerd", 0o500); os.chmod(binary / "ctr", 0o500)
    os.chmod(binary, 0o500); os.chmod(runtime, 0o700)
    parent_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    runtime_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    bin_fd = os.open(binary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    file_fds = [os.open(binary / name, os.O_RDONLY | os.O_CLOEXEC) for name in ("containerd", "ctr")]
    values = [generation(value) for value in (runtime_fd, bin_fd, *file_fds)]
    for value in (*file_fds, bin_fd, runtime_fd): os.close(value)
    body = {name: __import__("completion_kata_operation")._generation_value(value)
            for name, value in zip(("runtime_generation", "bin_generation", "containerd_generation", "ctr_generation"), values)}
    body.update({"containerd_size": 10, "containerd_sha256": hashlib.sha256(b"containerd").hexdigest(),
                 "ctr_size": 3, "ctr_sha256": hashlib.sha256(b"ctr").hexdigest()})
    return node(parent_fd), body
def open_node(parent, name, kind, _control):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if kind == "directory": flags |= os.O_DIRECTORY
    return node(os.open(name.raw, flags, dir_fd=parent.operation_fd.number))
def close_node(value): os.close(value.operation_fd.number)
def enumerate_node(parent, _control):
    rows = []
    for text in sorted(os.listdir(parent.operation_fd.number)):
        name = rootfs_fs._name(text); child = open_node(parent, name, "directory", None)
        rows.append((name, child.generation)); close_node(child)
    return SimpleNamespace(children=tuple(rows))
def observe_child(parent, name, _control):
    try: child = open_node(parent, name, "directory" if name.text in {"kata-runtime-v1", "bin"} else "file", None)
    except FileNotFoundError: return None
    try: return child.generation
    finally: close_node(child)
def read_regular(value, maximum, _control): return os.pread(value.operation_fd.number, maximum + 1, 0)
with patch.object(prestage.fs, "_open_path_node", side_effect=open_node), \
     patch.object(prestage.fs, "_close_node", side_effect=close_node), \
     patch.object(prestage.fs, "_enumerate_stable", side_effect=enumerate_node), \
     patch.object(prestage.fs, "_observe_child", side_effect=observe_child), \
     patch.object(prestage.fs, "_read_regular", side_effect=read_regular), \
     patch("completion_kata_runtime._runtime_alias", return_value=False):
    for cut in range(1, 5):
        with tempfile.TemporaryDirectory() as temporary:
            completion, body = make_tree(Path(temporary)); custody = prestage._PreparedCleanup(prestage._seal)
            prestage._states[custody] = (completion, body, None); calls = [0]
            def crash(_descriptor):
                calls[0] += 1
                if calls[0] == cut: raise OSError("crash cut")
            with patch.object(prestage.os, "fsync", side_effect=crash):
                try: prestage.cleanup(custody)
                except OSError: pass
                else: raise AssertionError("crash cut was not reached")
            prestage.cleanup(custody)
            assert not (Path(temporary) / "kata-runtime-v1").exists()
            os.close(completion.operation_fd.number)
    with tempfile.TemporaryDirectory() as temporary:
        completion, body = make_tree(Path(temporary)); custody = prestage._PreparedCleanup(prestage._seal)
        prestage._states[custody] = (completion, body, None); binary = Path(temporary) / "kata-runtime-v1/bin"
        def replace(_descriptor):
            os.chmod(binary, 0o700); (binary / "containerd").write_bytes(b"replacement")
            os.chmod(binary / "containerd", 0o500); os.chmod(binary, 0o500); raise OSError("cut")
        with patch.object(prestage.os, "fsync", side_effect=replace):
            try: prestage.cleanup(custody)
            except OSError: pass
        try: prestage.cleanup(custody)
        except prestage.PreparedRuntimeError: pass
        else: raise AssertionError("same-name replacement was deleted")
        assert (binary / "containerd").read_bytes() == b"replacement"
        prestage._states.pop(custody); os.close(completion.operation_fd.number)
assert no_kvm_descriptor()

# The production bridge itself remains zero-selection and binds the real lease
# and source APIs rather than test facades.
source = (REMOTE / "completion_kata_preparation_bridge.py").read_text()
for signature in (
    "def _claim_fixed_static_preparation():",
    "def _fixed_source_approval(custody):",
    "def _acquire_fixed_rootfs(custody):",
    "def _claim_fixed_executable_owner(custody):",
    "def _claim_fixed_prepared_runtime(custody):",
):
    assert signature in source
assert "rootfs_lease._acquire(_fixed_source_approval(custody), _control())" in source
assert "rootfs_lease._abandon(lease, _control())" in source
print("real Linux no-KVM V2 preparation bridge descriptor/fault matrix passed")

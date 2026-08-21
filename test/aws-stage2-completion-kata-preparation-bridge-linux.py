#!/usr/bin/env python3
"""Real Linux descriptor integration/fault test for the no-KVM V2 bridge seam."""
import hashlib
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_kata_admission as admission
import completion_kata_preparation_bridge as bridge
import completion_kata_process as process


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

# The production bridge itself remains zero-selection and binds the real lease
# and source APIs rather than test facades.
source = (REMOTE / "completion_kata_preparation_bridge.py").read_text()
for signature in (
    "def _claim_fixed_static_preparation():",
    "def _fixed_source_approval(custody):",
    "def _acquire_fixed_rootfs(custody):",
    "def _claim_fixed_executable_owner(custody):",
):
    assert signature in source
assert "rootfs_lease._acquire(_fixed_source_approval(custody), _control())" in source
assert "rootfs_lease._abandon(lease, _control())" in source
print("real Linux no-KVM V2 preparation bridge descriptor/fault matrix passed")

#!/usr/bin/env python3
"""Strict pin and publication-boundary tests."""

import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fs = load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
publish = load("completion_rootfs_publish", REMOTE / "completion_rootfs_publish.py")
raw = (REMOTE / "stage2-completion-rootfs-v1.json").read_bytes()
pins = publish._parse_pins(raw)
assert pins.entry_count == 4353
assert pins.manifest_size == 1049443 and pins.ustar_size == 136905728
assert publish._load_pins() == pins
for hostile in (
    raw[:-1],
    raw.replace(b'"entry_count": 4353', b'"entry_count": 4354'),
    raw.replace(b'"entry_count": 4353', b'"entry_count": true'),
    raw.replace(b'"version":', b'"extra":0,"version":', 1),
    raw.replace(b'"version":', b'"version":"duplicate","version":', 1),
    raw.replace(b'"manifest":', b'"manifest": ', 1),
):
    try:
        publish._parse_pins(hostile)
    except publish.PublicationError:
        pass
    else:
        raise AssertionError("hostile rootfs pins accepted")
names = tuple(name.text for name, _content in publish._contents(b"manifest", b"ustar", pins))
identity = {"mount_id": 1, "device": 1, "inode": 2, "kind": "directory", "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2, "size": 4096, "mtime_ns": 1, "ctime_ns": 1}
generation = {"mount_id": 1, "device": 1, "inode": 3, "kind": "file", "mode": 0o400, "uid": 0, "gid": 0, "nlink": 1, "size": 1, "mtime_ns": 1, "ctime_ns": 1}
values = []
previous = publish.ZERO_SHA256
events = [("intent", None, None), ("candidate-intent", None, None), ("candidate", None, identity)]
for index, name in enumerate(names, 2):
    next_identity = {**identity, "mtime_ns": index, "ctime_ns": index}
    events.extend((("file-intent", name, None), ("file", name, generation), ("candidate-generation", None, next_identity)))
    identity = next_identity
accepted_identity = {**identity, "ctime_ns": identity["ctime_ns"] + 1}
events.extend((("prepared", None, None), ("rename", None, None), ("accepted", None, accepted_identity)))
for phase, name, item_identity in events:
    value = publish._record(len(values), previous, phase, name, item_identity)
    line = publish._canonical(value)
    values.append(line)
    previous = hashlib.sha256(line).hexdigest()
    assert len(publish._parse_transaction(b"".join(values), names)) == len(values)
abort_values = []
previous = publish.ZERO_SHA256
abort_identity = {**identity, "mtime_ns": identity["mtime_ns"] + 1, "ctime_ns": identity["ctime_ns"] + 1}
for phase, name, item_identity in (("intent", None, None), ("candidate-intent", None, None), ("candidate", None, identity), ("file-intent", names[0], None), ("file-abort", names[0], abort_identity), ("file-intent", names[0], None)):
    value = publish._record(len(abort_values), previous, phase, name, item_identity)
    line = publish._canonical(value)
    abort_values.append(line)
    previous = hashlib.sha256(line).hexdigest()
publish._parse_transaction(b"".join(abort_values), names)
try:
    publish._parse_transaction(b"".join(values).replace(b'"phase":"rename"', b'"phase":"accepted"'), names)
except publish.PublicationError:
    pass
else:
    raise AssertionError("hostile publication transaction accepted")
reuse_identity_read, reuse_identity_write = os.pipe()
reuse_operation_read, reuse_operation_write = os.pipe()
os.close(reuse_identity_write)
os.close(reuse_operation_write)
reuse_key = fs.HostKey(1, 1, 44, "directory")
recorded_directory = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4096, 10, 10)
reused_directory = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4096, 10, 11)
reuse_node = fs.HeldNode(fs.CheckedFd(reuse_identity_read, "reuse-identity"), fs.CheckedFd(reuse_operation_read, "reuse-operation"), reused_directory)
real_observe = fs._observe_node
fs._observe_node = lambda _identity, _operation, _control: reused_directory
assert publish._require_rename_generation(reuse_node, publish._generation_value(recorded_directory), object()) == reused_directory
try:
    publish._require_directory_generation(reuse_node, publish._generation_value(recorded_directory), object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("same-inode candidate replacement accepted")
finally:
    fs._observe_node = real_observe
replacement_after_rename = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4097, 10, 12)
fs._observe_node = lambda _identity, _operation, _control: replacement_after_rename
try:
    publish._require_rename_generation(reuse_node, publish._generation_value(recorded_directory), object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("same-inode accepted replacement authorized as rename")
finally:
    fs._observe_node = real_observe
    fs._close_node(reuse_node)
if sys.platform == "linux":
    with tempfile.TemporaryDirectory() as temporary:
        candidate_path = Path(temporary) / "candidate"
        candidate_path.mkdir()
        first = candidate_path.stat()
        candidate_path.rmdir()
        reused_stat = None
        for _attempt in range(4096):
            candidate_path.mkdir()
            current = candidate_path.stat()
            if current.st_ino == first.st_ino:
                reused_stat = current
                candidate_path.rmdir()
                break
            candidate_path.rmdir()
        assert reused_stat is not None, "approved Linux fixture did not reuse the candidate inode"
        assert (reused_stat.st_mode, reused_stat.st_uid, reused_stat.st_gid, reused_stat.st_nlink, reused_stat.st_size, reused_stat.st_mtime_ns, reused_stat.st_ctime_ns) != (first.st_mode, first.st_uid, first.st_gid, first.st_nlink, first.st_size, first.st_mtime_ns, first.st_ctime_ns)
identity_read, identity_write = os.pipe()
operation_read, operation_write = os.pipe()
os.close(identity_write)
os.close(operation_write)
key = fs.HostKey(1, 1, 1, "file")
opened_generation = fs.HostGeneration(key, 0o400, 0, 0, 1, 1, 1, 1)
opened = fs.HeldNode(fs.CheckedFd(identity_read, "test-identity"), fs.CheckedFd(operation_read, "test-operation"), opened_generation)
recorded_generation = fs.HostGeneration(fs.HostKey(1, 1, 2, "file"), 0o400, 0, 0, 1, 1, 1, 1)
real_file = publish._file
real_enumerate = fs._enumerate_stable
publish._file = lambda _directory, _name, _raw, _control: opened
fs._enumerate_stable = lambda _directory, _control: SimpleNamespace(raw_names=(publish.SENTINEL_NAME.raw,))
try:
    publish._verify_inventory(object(), ((publish.SENTINEL_NAME, b"x"),), ({"identity": publish._generation_value(recorded_generation)},), False, object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("replacement publication identity accepted")
finally:
    publish._file = real_file
    fs._enumerate_stable = real_enumerate
assert opened.identity_fd.disposition == opened.operation_fd.disposition == "closed"
source = (REMOTE / "completion_rootfs_publish.py").read_text()
assert "O_CREAT | os.O_EXCL" in source and "renameat2" in source and "_rename_noreplace" in source
assert "rootfs.metadata.json" in source and "_parse_transaction" in source and "_transition_control" in source
assert b"qualification" not in raw and b"functional_test_image" in raw
for forbidden in ("argparse", "sys.argv", "if __name__", "rmtree", "os.walk", "glob", "subprocess", "socket"):
    assert forbidden not in source
print("completion rootfs publication tests passed")

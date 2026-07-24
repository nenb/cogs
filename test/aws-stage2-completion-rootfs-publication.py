#!/usr/bin/env python3
"""Strict pin and publication-boundary tests."""

import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import sys

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
identity = {"mount_id": 1, "device": 1, "inode": 2, "kind": "directory"}
generation = {"mount_id": 1, "device": 1, "inode": 3, "kind": "file", "mode": 0o400, "uid": 0, "gid": 0, "nlink": 1, "size": 1, "mtime_ns": 1, "ctime_ns": 1}
values = []
previous = publish.ZERO_SHA256
events = [("intent", None, None), ("candidate-intent", None, None), ("candidate", None, identity)]
for name in names:
    events.extend((("file-intent", name, None), ("file", name, generation)))
events.extend((("prepared", None, None), ("rename", None, None), ("accepted", None, None)))
for phase, name, item_identity in events:
    value = publish._record(len(values), previous, phase, name, item_identity)
    line = publish._canonical(value)
    values.append(line)
    previous = hashlib.sha256(line).hexdigest()
    assert len(publish._parse_transaction(b"".join(values), names)) == len(values)
try:
    publish._parse_transaction(b"".join(values).replace(b'"phase":"rename"', b'"phase":"accepted"'), names)
except publish.PublicationError:
    pass
else:
    raise AssertionError("hostile publication transaction accepted")
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

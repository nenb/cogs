#!/usr/bin/env python3
"""Portable hostile tests and Linux syscall qualification for D-R2.2a."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_rootfs_fs.py"
spec = importlib.util.spec_from_file_location("completion_rootfs_fs_test", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def rejected(function):
    try:
        function()
    except module.RootfsFsError:
        return
    raise AssertionError("hostile input accepted")


def control(seconds=30):
    return module.OperationControl(time.monotonic_ns() + seconds * 1_000_000_000, lambda: False)


def generation(inode=1, ctime=1):
    key = module.HostKey(1, 1, inode, "directory")
    return module.HostGeneration(key, 0o700, 0, 0, 2, 0, 1, ctime)


def snapshot(names, value=None):
    value = value or generation()
    checked = tuple(module._name(name) for name in sorted(names))
    return module.DirectorySnapshot(value, checked, tuple((name, generation(index + 2)) for index, name in enumerate(checked)))


def manifest_bytes(revision, entries):
    value = {"version": module.SOURCE_MANIFEST_VERSION, "revision": revision, "entries": entries}
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def pure_tests():
    raw = b"pos:\t0\nflags:\t" + module.FDINFO_FLAGS + b"\nmnt_id:\t42\nino:\t9\n"
    assert module._parse_fdinfo(raw, 9) == 42
    hostile_fdinfo = (
        raw.replace(b"mnt_id:\t42", b"mnt_id:\t042"),
        raw.replace(b"mnt_id:\t42", b"mnt_id:\t0"),
        raw.replace(b"ino:\t9", b"ino:\t8"),
        raw.replace(b"flags:\t", b"unknown:\t"),
        raw.replace(b"ino:\t9\n", b"ino:\t9\nlock:\t1\n"),
        raw.replace(b"pos:\t0", b"pos:\t1"),
        raw[:-1],
        raw + b"\x00",
        b"x" * (module.MAX_FDINFO_BYTES + 1),
    )
    for value in hostile_fdinfo:
        rejected(lambda value=value: module._parse_fdinfo(value, 9))

    assert module._name("é").raw == "é".encode()
    for value in (b"\xff", "e\u0301", ".", "..", "a/b", "a\x00b", "line\n", "x" * 256):
        rejected(lambda value=value: module._name(value))
    assert unicodedata.normalize("NFC", module._name("é").text) == "é"

    before = snapshot((b"a",))
    after = snapshot((b"a", b"b"), generation(1, 2))
    module.ParentDelta("create", module._name(b"b"), before, after)
    module.ParentDelta("metadata", module._name(b"a"), before, snapshot((b"a",), generation(1, 2)))
    rejected(lambda: module.ParentDelta("unlink", module._name(b"b"), before, after))
    rejected(lambda: module.ParentDelta("create", module._name(b"b"), before, snapshot((b"a", b"b", b"c"))))

    fake_fd = module.CheckedFd(100, "fake")
    fake_node = module.HeldNode(fake_fd, fake_fd, generation())
    real_listdir = module.os.listdir
    real_observe = module._observe_node
    real_child = module._observe_child
    try:
        values = iter((["b", "a"], ["a", "b"], ["b", "a"]))
        module.os.listdir = lambda _fd: next(values)
        module._observe_node = lambda *_args: generation()
        module._observe_child = lambda _parent, _name, _control: generation(2)
        assert module._enumerate_stable(fake_node, control()).raw_names == (b"a", b"b")
        values = iter((["a"], ["a", "b"]))
        rejected(lambda: module._enumerate_stable(fake_node, control()))
    finally:
        module.os.listdir = real_listdir
        module._observe_node = real_observe
        module._observe_child = real_child
    module._zero_xattrs(lambda *_args: 0, 1, control())
    rejected(lambda: module._zero_xattrs(lambda *_args: 1, 1, control()))
    rejected(lambda: module._zero_xattrs(lambda *_args: -1, 1, control()))

    revision = "a" * 40
    rows = [
        {"path": ".cogs-stage2-source-v1", "kind": "file", "mode": 0o400, "size": len(module.SOURCE_SENTINEL), "sha256": hashlib.sha256(module.SOURCE_SENTINEL).hexdigest()},
        {"path": "deploy", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
    ]
    encoded = manifest_bytes(revision, rows)
    approval = module.SourceApproval(revision, hashlib.sha256(encoded).hexdigest())
    parsed = module._parse_source_manifest(encoded, approval)
    assert parsed.revision == revision and len(parsed.entries) == 2
    mutations = (
        encoded.replace(b'"version"', b'"unknown"', 1),
        encoded.replace(b'"revision":"', b'"revision": "', 1),
        encoded.replace(b'"mode":256', b'"mode":true', 1),
        encoded.replace(b'"path":"deploy"', b'"path":".git"', 1),
        encoded.replace(b'"path":"deploy"', b'"path":"deploy/aws-feasibility/.state"', 1),
        encoded.replace(b'"sha256":null', b'"sha256":"' + b"0" * 64 + b'"', 1),
    )
    for value in mutations:
        hostile = module.SourceApproval(revision, hashlib.sha256(value).hexdigest())
        rejected(lambda value=value, hostile=hostile: module._parse_source_manifest(value, hostile))
    rejected(lambda: module._parse_source_manifest(encoded, module.SourceApproval(revision, "0" * 64)))

    cancelled = module.OperationControl(time.monotonic_ns() + 1_000_000_000, lambda: True)
    expired = module.OperationControl(1, lambda: False)
    rejected(cancelled.check)
    rejected(expired.check)
    rejected(lambda: module.OperationControl(time.monotonic_ns() + 1_000_000, lambda: 0).check())

    descriptor = os.open(os.devnull, os.O_RDONLY)
    owned = module.CheckedFd(descriptor, "test")
    calls = []
    real_close = module.os.close
    try:
        def interrupted(number):
            calls.append(number)
            raise InterruptedError()
        module.os.close = interrupted
        rejected(owned.close)
        assert calls == [descriptor] and owned.disposition == "uncertain"
    finally:
        module.os.close = real_close
        real_close(descriptor)
    rejected(owned.close)

    source = MODULE_PATH.read_text()
    tree = ast.parse(source)
    banned = {"mkdir", "makedirs", "unlink", "remove", "rmdir", "rename", "replace", "link", "symlink", "write", "pwrite", "fsync", "fdatasync", "flock", "chmod", "chown"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            assert not (node.func.value.id == "os" and node.func.attr in banned), node.func.attr
    assert "if __name__" not in source and "argparse" not in source and "subprocess" not in source
    assert "O_CREAT" not in source and "O_TRUNC" not in source and "O_WRONLY" not in source and "O_RDWR" not in source
    assert module.PRIVILEGED_MUTATOR_EXCLUSION.startswith("Concurrent EUID-0")


def write_source_fixture(source):
    (source / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache").mkdir(parents=True, mode=0o700)
    (source / ".cogs-stage2-source-v1").write_bytes(module.SOURCE_SENTINEL)
    (source / "module.py").write_bytes(b"value = 1\n")
    for path in (source, source / "deploy", source / "deploy/aws-feasibility", source / "deploy/aws-feasibility/.state", source / "deploy/aws-feasibility/.state/completion-v1", source / "deploy/aws-feasibility/.state/completion-v1/artifacts", source / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"):
        path.chmod(0o700)
    for path in (source / ".cogs-stage2-source-v1", source / "module.py"):
        path.chmod(0o400)
    entries = []
    for relative, kind, mode, content in (
        (".cogs-stage2-source-v1", "file", 0o400, module.SOURCE_SENTINEL),
        ("deploy", "directory", 0o700, None),
        ("deploy/aws-feasibility", "directory", 0o700, None),
        ("module.py", "file", 0o400, b"value = 1\n"),
    ):
        entries.append({"path": relative, "kind": kind, "mode": mode, "size": 0 if content is None else len(content), "sha256": None if content is None else hashlib.sha256(content).hexdigest()})
    revision = "b" * 40
    raw = manifest_bytes(revision, entries)
    manifest = source / ".cogs-stage2-source-manifest-v1.json"
    manifest.write_bytes(raw)
    manifest.chmod(0o400)
    return module.SourceApproval(revision, hashlib.sha256(raw).hexdigest())


def linux_tests():
    if sys.platform != "linux":
        return
    assert os.geteuid() == 0
    active = control()
    with tempfile.TemporaryDirectory(prefix="cogs-fs-linux-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        source = root / "source"
        source.mkdir(mode=0o700)
        approval = write_source_fixture(source)
        (root / "regular").write_bytes(b"content")
        (root / "regular").chmod(0o400)
        (root / "link").symlink_to("regular")

        anchor = module._open_root_node(active)
        components = []
        parent = anchor
        for part in Path(temporary).parts[1:]:
            node = module._open_path_node(parent, part, "directory", active)
            components.append(module.ChainComponent(module._name(part), node))
            parent = node
        chain = module.HeldChain(anchor, tuple(components))
        directory = chain.components[-1].node
        try:
            snapshot_value = module._enumerate_stable(directory, active)
            assert snapshot_value.raw_names == tuple(sorted(snapshot_value.raw_names))
            assert b"regular" in snapshot_value.raw_names and b"link" in snapshot_value.raw_names

            regular = module._open_path_node(directory, b"regular", "file", active)
            try:
                module._require_empty_fd_xattrs(regular, active)
            finally:
                module._close_node(regular)

            child = module._open_path_node(directory, b"link", "symlink", active)
            try:
                module._require_empty_symlink_xattrs(chain, directory, b"link", child, active)
            finally:
                module._close_node(child)

            source_node = module._open_path_node(directory, b"source", "directory", active)
            try:
                verified = module._verify_source_bundle(source_node, approval, active)
                assert verified.digest == approval.manifest_sha256
            finally:
                module._close_node(source_node)
        finally:
            module._close_chain(chain)


pure_tests()
linux_tests()
print("completion rootfs filesystem tests passed")

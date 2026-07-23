#!/usr/bin/env python3
"""Small synthetic direct-writer tests and Linux qualification for D-R2.3."""

import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
FIXED = Path("/var/lib/cogs/stage2-completion-v1/source")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def portable():
    source = (REMOTE / "completion_rootfs_materializer.py").read_text()
    assert "def _materialize(" in source and "revalidate_build_inputs" in source and "def _postwalk(" in source
    assert "if __name__" not in source and "sys.argv" not in source
    for forbidden in ("rmtree", "os.walk", "glob", "subprocess", "socket", "tarfile", "extractall", "rename"):
        assert forbidden not in source
    print("completion rootfs materializer portable tests passed")


def prepare():
    if Path("/var/lib/cogs").exists():
        shutil.rmtree("/var/lib/cogs")
    remote = FIXED / "deploy/aws-feasibility/remote"
    cache = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    remote.mkdir(parents=True, mode=0o700)
    cache.mkdir(parents=True, mode=0o700)
    paths = [Path("/var/lib/cogs"), Path("/var/lib/cogs/stage2-completion-v1"), FIXED, FIXED / "deploy", FIXED / "deploy/aws-feasibility", remote, FIXED / "deploy/aws-feasibility/.state", FIXED / "deploy/aws-feasibility/.state/completion-v1", cache.parent, cache]
    for path in paths:
        path.chmod(0o700)
    copied = []
    names = (
        "completion_archive_preflight.py",
        "completion_rootfs_plan.py",
        "completion_rootfs_fs.py",
        "completion_rootfs_ledger.py",
        "completion_rootfs_builder.py",
        "completion_rootfs_materializer.py",
    )
    for name in names:
        content = (REMOTE / name).read_bytes()
        target = remote / name
        target.write_bytes(content)
        target.chmod(0o400)
        copied.append((f"deploy/aws-feasibility/remote/{name}", content))
    sentinel_raw = b"cogs-stage2-source-v1\n"
    sentinel = FIXED / ".cogs-stage2-source-v1"
    sentinel.write_bytes(sentinel_raw)
    sentinel.chmod(0o400)
    artifact = cache / "immutable.bin"
    artifact.write_bytes(b"immutable\n")
    artifact.chmod(0o400)
    entries = [
        {"path": ".cogs-stage2-source-v1", "kind": "file", "mode": 0o400, "size": len(sentinel_raw), "sha256": hashlib.sha256(sentinel_raw).hexdigest()},
        {"path": "deploy", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility/remote", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
    ]
    for path, content in copied:
        entries.append({"path": path, "kind": "file", "mode": 0o400, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    entries.sort(key=lambda item: item["path"].encode())
    revision = "f" * 40
    raw = json.dumps({"version": "cogs.stage2-source-manifest/v1", "revision": revision, "entries": entries}, separators=(",", ":")).encode() + b"\n"
    manifest = FIXED / ".cogs-stage2-source-manifest-v1.json"
    manifest.write_bytes(raw)
    manifest.chmod(0o400)
    return revision, hashlib.sha256(raw).hexdigest(), hashlib.sha256(artifact.read_bytes()).hexdigest()


def patch_overlay(fs):
    original_xattrs = fs._require_empty_fd_xattrs
    ancestors = {(os.lstat(path).st_dev, os.lstat(path).st_ino) for path in ("/", "/var", "/var/lib")}
    fs._open_workspace_anchor = lambda control: fs._open_root_node(control)

    def policy(node, expected, root_key):
        generation = node.generation
        assert generation.key.kind == expected.kind and generation.mode == expected.mode
        assert generation.uid == expected.uid and generation.gid == expected.gid
        assert generation.key.mount_id == root_key.mount_id and generation.key.device == root_key.device
        if expected.kind == "file":
            assert generation.nlink == 1

    def xattrs(node, control):
        if (node.generation.key.device, node.generation.key.inode) not in ancestors:
            original_xattrs(node, control)

    fs._require_policy = policy
    fs._require_empty_fd_xattrs = xattrs


def synthetic(plan_module, preflight):
    content = b"hello rootfs\n"
    records = (
        preflight.MaterialRecord("bin", "directory", 0o755, 0, 0, 7, 0, None, None, None, None, -1),
        preflight.MaterialRecord("bin/tool", "file", 0o755, 0, 0, 8, len(content), None, None, None, hashlib.sha256(content).hexdigest(), 0),
        preflight.MaterialRecord("bin/tool-copy", "hardlink", 0o755, 0, 0, 8, 0, None, None, "bin/tool", None, -1),
        preflight.MaterialRecord("etc", "directory", 0o755, 0, 0, 9, 0, None, None, None, None, -1),
        preflight.MaterialRecord("etc/message", "symlink", 0o777, 0, 0, 10, 0, "/bin/tool", "bin/tool", None, None, -1),
    )
    owner = preflight.PreflightedTar(content, plan_module.ROOT_POLICY, records, ())
    entries = tuple(plan_module.PlannedEntry("synthetic", owner, record) for record in records)
    rootfs_plan = plan_module.RootfsPlan(plan_module.ROOT_POLICY, ("synthetic",), entries, ())
    return plan_module.RootfsBuildInputs("1" * 64, (), (), rootfs_plan)


def linux():
    revision, digest, artifact_digest = prepare()
    remote = FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(remote))
    preflight = load("completion_archive_preflight", remote / "completion_archive_preflight.py")
    plan_module = load("completion_rootfs_plan", remote / "completion_rootfs_plan.py")
    fs = load("completion_rootfs_fs", remote / "completion_rootfs_fs.py")
    load("completion_rootfs_ledger", remote / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", remote / "completion_rootfs_builder.py")
    materializer = load("completion_rootfs_materializer", remote / "completion_rootfs_materializer.py")
    patch_overlay(fs)
    approval = fs.SourceApproval(revision, digest)
    control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
    chain = builder._open_base_chain(control)
    state = builder._bootstrap(chain, approval, control)
    fs._close_node(state)
    fs._close_chain(chain)
    chain = builder._open_base_chain(control)
    authority = synthetic(plan_module, preflight)
    materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(authority)

    owned = builder._begin_operation(chain, approval, "1" * 64, control)
    real_write = builder.os.write
    builder.os.write = lambda fd, raw: real_write(fd, raw[:5])
    try:
        result = materializer._materialize(authority, owned, control)
    finally:
        builder.os.write = real_write
    assert result.entry_count == 5
    root_path = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1" / owned.operation_name / "rootfs"
    assert (root_path / "bin/tool").read_bytes() == b"hello rootfs\n"
    assert os.lstat(root_path / "bin/tool").st_ino == os.lstat(root_path / "bin/tool-copy").st_ino
    assert os.readlink(root_path / "etc/message") == "/bin/tool"
    builder._cleanup_owned(result.owned, result.active, control)
    assert sorted(path.name for path in root_path.parents[1].iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    owned = builder._begin_operation(chain, approval, "2" * 64, control)
    bad = synthetic(plan_module, preflight)
    bad_entry = dataclasses.replace(bad.plan.entries[1].record, content_sha256="0" * 64)
    bad_entries = list(bad.plan.entries)
    bad_entries[1] = dataclasses.replace(bad_entries[1], record=bad_entry)
    bad = dataclasses.replace(bad, plan=dataclasses.replace(bad.plan, entries=tuple(bad_entries)))
    materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(bad)
    try:
        materializer._materialize(bad, owned, control)
    except BaseException:
        pass
    else:
        raise AssertionError("hostile content accepted")
    state_path = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
    assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    owned = builder._begin_operation(chain, approval, "3" * 64, control)
    materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(authority)
    cancelled = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: True)
    try:
        materializer._materialize(authority, owned, cancelled)
    except BaseException:
        pass
    else:
        raise AssertionError("cancelled materialization accepted")
    assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
    artifact = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache/immutable.bin"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest
    fs._close_chain(chain)
    print("completion rootfs materializer Linux qualification passed")


if len(sys.argv) == 2 and sys.argv[1] == "--linux":
    linux()
else:
    portable()

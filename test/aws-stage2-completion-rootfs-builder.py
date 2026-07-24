#!/usr/bin/env python3
"""Portable policy tests and non-authoritative Docker functional tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
FIXED = Path("/var/lib/cogs/stage2-completion-v1/source")
CONTAINER_SENTINEL = Path("/var/lib/cogs/.cogs-rootfs-functional-test-v1")
CONTAINER_SENTINEL_RAW = b"cogs-rootfs-functional-test-v1\n"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile builder case accepted")


def portable_tests():
    sys.path.insert(0, str(REMOTE))
    fs = load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
    load("completion_rootfs_ledger", REMOTE / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder_portable", REMOTE / "completion_rootfs_builder.py")
    assert builder.main([]) == 1
    assert builder.main(["recover-owned", "extra"]) == 1
    latch = builder.CancellationLatch()
    control = fs.OperationControl(time.monotonic_ns() + 1_000_000_000, lambda: latch.cancelled)
    control.check()
    latch.cancelled = True
    rejected(control.check)
    source = (REMOTE / "completion_rootfs_builder.py").read_text()
    for forbidden in ("rmtree", "os.walk", "glob", "subprocess", "socket", "os.environ", "os.getenv", "argparse"):
        assert forbidden not in source
    assert 'argv != ["recover-owned"]' in source
    assert "FIXED_MODULE" in source and "RECOVER_SECONDS = 120" in source
    assert "def _bootstrap(" in source and "_bootstrap(" not in source.split("def main", 1)[1]
    assert "alias_opened + target_opened" in source and "transferred or operation is None" in source
    build_source = (REMOTE / "completion_rootfs_build.py").read_text()
    assert "observed = operation = None" in build_source and "fs._close_node(observed)" in build_source
    locked = builder.LockedState(None, None, object())
    primary = RuntimeError("primary")
    real_close = builder._close
    try:
        builder._close = lambda _node: (_ for _ in ()).throw(OSError("close"))
        try:
            builder._release_lock(locked, primary)
        except fs.RootfsFsError as error:
            assert error.primary is primary and isinstance(error.close_error, OSError)
        else:
            raise AssertionError("close uncertainty accepted")
    finally:
        builder._close = real_close
    original_umask = os.umask(0o027)
    try:
        def fixed_boundary():
            observed = os.umask(0o077)
            os.umask(observed)
            assert observed == 0o077

        builder._fixed_umask(fixed_boundary)
        rejected(lambda: builder._fixed_umask(lambda: (_ for _ in ()).throw(RuntimeError("stop"))))
        restored = os.umask(0o027)
        os.umask(restored)
        assert restored == 0o027
    finally:
        os.umask(original_umask)


def canonical_manifest(entries, revision):
    value = {"version": "cogs.stage2-source-manifest/v1", "revision": revision, "entries": entries}
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def require_disposable_container():
    def require(condition):
        if not condition:
            raise RuntimeError("unsafe Docker functional environment")

    require(sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file())
    mount = Path("/var/lib/cogs")
    mount_stat = mount.stat(follow_symlinks=False)
    require(stat.S_ISDIR(mount_stat.st_mode) and stat.S_IMODE(mount_stat.st_mode) == 0o700)
    require(mount_stat.st_uid == mount_stat.st_gid == 0 and mount_stat.st_dev != Path("/var/lib").stat().st_dev)
    lines = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines() if line.split()[4] == str(mount)]
    require(len(lines) == 1 and "-" in lines[0])
    separator = lines[0].index("-")
    require(lines[0][separator + 1] == "tmpfs" and set(("rw", "nosuid", "nodev", "noexec")) <= set(lines[0][5].split(",")))
    observed = CONTAINER_SENTINEL.stat(follow_symlinks=False)
    require(stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o400)
    require(observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 1 and observed.st_dev == mount_stat.st_dev)
    require(CONTAINER_SENTINEL.read_bytes() == CONTAINER_SENTINEL_RAW)
    require(tuple(path.name for path in mount.iterdir()) == (CONTAINER_SENTINEL.name,) and not FIXED.parent.exists())


def prepare_fixed_workspace():
    require_disposable_container()
    remote = FIXED / "deploy/aws-feasibility/remote"
    cache = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    remote.mkdir(parents=True, mode=0o700)
    cache.mkdir(parents=True, mode=0o700)
    for path in (
        Path("/var/lib/cogs/stage2-completion-v1"),
        FIXED,
        FIXED / "deploy",
        FIXED / "deploy/aws-feasibility",
        FIXED / "deploy/aws-feasibility/remote",
        FIXED / "deploy/aws-feasibility/.state",
        FIXED / "deploy/aws-feasibility/.state/completion-v1",
        FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts",
        cache,
    ):
        path.chmod(0o700)
    copied = []
    for name in ("completion_rootfs_fs.py", "completion_rootfs_ledger.py", "completion_rootfs_builder.py"):
        content = (REMOTE / name).read_bytes()
        target = remote / name
        target.write_bytes(content)
        target.chmod(0o400)
        copied.append((f"deploy/aws-feasibility/remote/{name}", content))
    sentinel = FIXED / ".cogs-stage2-source-v1"
    sentinel.write_bytes(b"cogs-stage2-source-v1\n")
    sentinel.chmod(0o400)
    artifact = cache / "immutable.bin"
    artifact.write_bytes(b"immutable-artifact\n")
    artifact.chmod(0o400)
    entries = [
        {"path": ".cogs-stage2-source-v1", "kind": "file", "mode": 0o400, "size": 22, "sha256": hashlib.sha256(b"cogs-stage2-source-v1\n").hexdigest()},
        {"path": "deploy", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility/remote", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
    ]
    for path, content in copied:
        entries.append({"path": path, "kind": "file", "mode": 0o400, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    entries.sort(key=lambda item: item["path"].encode())
    revision = "d" * 40
    raw = canonical_manifest(entries, revision)
    manifest = FIXED / ".cogs-stage2-source-manifest-v1.json"
    manifest.write_bytes(raw)
    manifest.chmod(0o400)
    return revision, hashlib.sha256(raw).hexdigest(), hashlib.sha256(artifact.read_bytes()).hexdigest()


def accommodate_docker_overlay(fs, builder):
    def check(condition):
        if not condition:
            raise RuntimeError("Docker functional policy mismatch")

    def anchor(control):
        check(sys.platform == "linux" and os.geteuid() == 0)
        return fs._open_root_node(control)

    original = fs._require_policy
    original_xattrs = fs._require_empty_fd_xattrs
    overlay_ancestors = {(os.lstat(path).st_dev, os.lstat(path).st_ino) for path in ("/", "/var", "/var/lib")}
    functional_device = os.lstat("/var/lib/cogs").st_dev

    def policy(node, expected, root_key):
        generation = node.generation
        check(generation.key.kind == expected.kind and generation.mode == expected.mode)
        check(generation.uid == expected.uid and generation.gid == expected.gid)
        check((generation.key.mount_id, generation.key.device) == (root_key.mount_id, root_key.device) or generation.key.device == functional_device)
        if expected.kind == "file":
            check(generation.nlink == 1)

    def xattrs(node, control):
        key = (node.generation.key.device, node.generation.key.inode)
        if key not in overlay_ancestors:
            original_xattrs(node, control)

    fs._open_workspace_anchor = anchor
    fs._require_policy = policy
    fs._require_empty_fd_xattrs = xattrs
    return original


def linux_functional_test():
    revision, digest, artifact_digest = prepare_fixed_workspace()
    fixed_remote = FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(fixed_remote))
    fs = load("completion_rootfs_fs", fixed_remote / "completion_rootfs_fs.py")
    load("completion_rootfs_ledger", fixed_remote / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", fixed_remote / "completion_rootfs_builder.py")
    accommodate_docker_overlay(fs, builder)
    approval = fs.SourceApproval(revision, digest)
    control = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: False)
    state_path = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
    assert builder.main(["recover-owned"]) == 0
    assert not state_path.exists()

    chain = builder._open_base_chain(control)
    state = builder._bootstrap(chain, approval, control)
    fs._close_node(state)
    fs._close_chain(chain)

    chain = builder._open_base_chain(control)
    operation_name = builder._start_operation(chain, approval, "e" * 64, control)
    fs._close_chain(chain)
    assert (state_path / operation_name).is_dir()
    assert (state_path / builder.LEDGER_NAME.text).is_file()

    assert builder.main(["recover-owned"]) == 0
    assert sorted(item.name for item in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
    artifact = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache/immutable.bin"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest

    chain = builder._open_base_chain(control)
    state = builder._open_state(chain, control)
    locked = builder._acquire_lock(chain, state, control)
    rejected(lambda: builder._acquire_lock(chain, state, control))
    builder._release_lock(locked)
    real_observe = fs._observe_child
    try:
        def replaced(parent, name, current_control):
            value = real_observe(parent, name, current_control)
            if name == builder.LOCK_NAME:
                key = fs.HostKey(value.key.mount_id, value.key.device, value.key.inode + 1, value.key.kind)
                return fs.HostGeneration(key, value.mode, value.uid, value.gid, value.nlink, value.size, value.mtime_ns, value.ctime_ns)
            return value
        fs._observe_child = replaced
        rejected(lambda: builder._acquire_lock(chain, state, control))
    finally:
        fs._observe_child = real_observe
    fs._close_node(state)
    fs._close_chain(chain)

    for name in ("operation-one", "operation-two"):
        (state_path / name).mkdir(mode=0o700)
    assert builder.main(["recover-owned"]) == 1
    assert all((state_path / name).is_dir() for name in ("operation-one", "operation-two"))
    for name in ("operation-one", "operation-two"):
        (state_path / name).rmdir()

    unknown = state_path / "unknown"
    unknown.write_bytes(b"preserve")
    unknown.chmod(0o600)
    assert builder.main(["recover-owned"]) == 1
    assert unknown.read_bytes() == b"preserve"
    unknown.unlink()

    (state_path / builder.STATE_SENTINEL_NAME.text).unlink()
    (state_path / builder.LOCK_NAME.text).unlink()
    state_path.rmdir()
    state_path.mkdir(mode=0o700)
    assert builder.main(["recover-owned"]) == 1
    assert state_path.is_dir() and not any(state_path.iterdir())
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest
    print("completion rootfs builder Docker functional test passed")


if len(sys.argv) == 2 and sys.argv[1] == "--linux":
    linux_functional_test()
else:
    portable_tests()
    print("completion rootfs builder portable tests passed")

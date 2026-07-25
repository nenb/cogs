#!/usr/bin/env python3
"""Portable policy tests and non-authoritative Docker functional tests."""

import dataclasses
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
    ledger = load("completion_rootfs_ledger", REMOTE / "completion_rootfs_ledger.py")
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
    assert "FIXED_MODULE" in source and "RECOVER_SECONDS = 600" in source
    assert "def _bootstrap(" in source and "_bootstrap(" not in source.split("def main", 1)[1]
    assert "alias_opened + target_opened" in source and "transferred or operation is None" in source
    assert "def _stable_active(" in source and "def _mark_leased(" in source
    assert 'record_type not in {"leased", "release-authorized"}' in source
    assert "_append_mechanical" not in source and source.count("ledger._append_record(") == 1
    assert source.count("ledger._append_leased_record(") == 1
    assert "active.records + (record,)" not in source
    assert source.count("ledger._advance_history(active.records, record)") == 2
    assert "return fs._enumerate_names_stable(node, control)" in source
    assert source.count("fs._revalidate_chain(parent_chain") >= 4
    for function_name in ("_finish_remove", "_finish_hardlink_remove", "_retire", "_unlink_ledger"):
        function_source = source.split(f"def {function_name}(", 1)[1].split("\ndef ", 1)[0]
        assert "fs._revalidate_chain(" in function_source, function_name
    assert 'fs._structural_increment("complete_walks")' in source
    assert "class CleanupSession:" in source
    assert all(name not in source for name in ("def _fresh_cleanup(", "def _cleanup_append(", "def _fresh_cleanup_authority("))
    session_append = source.split("def _session_append(", 1)[1].split("\ndef ", 1)[0]
    assert "os.pread(" in session_append and session_append.count("_append(") == 1
    assert all(name not in session_append for name in ("_parse_ledger", "_walk_entries", "_reconcile_ledger"))
    walker = source.split("def _walk_entries(", 1)[1].split("\ndef ", 1)[0]
    assert "parents[prefix] = ledger.LedgerParent(snapshot.generation" in walker
    assert "current = _parent(directory" not in walker
    entrance = source.split("def _open_cleanup_session(", 1)[1].split("\ndef ", 1)[0]
    assert entrance.count("_stable_active(") == entrance.count("_walk_entries(") == entrance.count("_reconcile_ledger(") == 1
    assert "_require_cleanup_model(" in entrance
    for helper_name in ("_finish_remove", "_finish_hardlink_remove"):
        scalar = source.split(f"def {helper_name}(", 1)[1].split("\ndef ", 1)[0]
        assert scalar.count("_session_append(") == 3
        assert all(record in scalar for record in ("remove-intent", "remove-observed", "remove-settled"))
        pre_index = scalar.index("pre_snapshot =")
        assert pre_index < scalar.index("fs._revalidate_chain(", pre_index) < scalar.index('"remove-intent"', pre_index)
        if helper_name == "_finish_hardlink_remove":
            assert scalar.count("fs._revalidate_chain(alias_node_chain") == 3
            assert scalar.count("fs._revalidate_chain(target_node_chain") == 3
            assert scalar.count("fs._revalidate_chain(current_alias_chain") == 3
            assert scalar.count("fs._revalidate_chain(current_target_chain") == 4
    absent_remove = source.split("def _finish_absent_remove(", 1)[1].split("\ndef ", 1)[0]
    assert absent_remove.index("post = _parent(") < absent_remove.index("fs._revalidate_chain(", absent_remove.index("post = _parent(")) < absent_remove.index('"remove-observed"')
    retire = source.split("def _retire(", 1)[1].split("\ndef ", 1)[0]
    assert retire.index("pre_snapshot =") < retire.index("fs._revalidate_chain(", retire.index("pre_snapshot =")) < retire.index('"operation-remove-intent"')
    cleanup_loop = source.split("def _cleanup_active(", 1)[1].split("\ndef ", 1)[0]
    assert cleanup_loop.count("_open_cleanup_session(") == 1
    assert all(name not in cleanup_loop for name in ("_stable_active", "_walk_entries", "_reconcile_ledger"))
    retirement = source.split("def _retire_absent(", 1)[1].split("\ndef ", 1)[0]
    assert retirement.count("_open_cleanup_session(") == 2
    resumed = source.split("def _resume_observed(", 1)[1].split("\ndef ", 1)[0]
    assert resumed.count("_relative_parent_chain(") == resumed.count("_chain_with_child(") == 3
    final_zero = source.split("def _unlink_ledger(", 1)[1].split("\ndef ", 1)[0]
    assert final_zero.index('_session_require(session, "retired")') < final_zero.index("_remove_name(")
    assert "_enumerate_stable(session.locked.state" in final_zero and "STATE_SENTINEL_NAME" in final_zero
    poisoned = {"_session_append", "_finish_remove", "_finish_absent_remove", "_finish_hardlink_remove",
                "_cleanup_active", "_resume_entry_remove", "_resume_observed", "_resume_absent_create",
                "_unlink_ledger", "_retire_absent", "_retire", "_finish_operation_absent", "_abort", "_settle_startup"}
    assert all(f"@_poisoned\ndef {name}(" in source for name in poisoned)
    assert '_fail(session.disposition == "active")' in source.split("def _poisoned(", 1)[1].split("\ndef ", 1)[0]
    for helper_name in ("_create_directory", "_create_file"):
        helper_source = source.split(f"def {helper_name}(", 1)[1].split("\ndef ", 1)[0]
        assert "parent_chain" in helper_source and "fs._revalidate_chain(" in helper_source
    assert "state_snapshot = fs._enumerate_stable(locked.state, control)" in source
    materializer_source = (REMOTE / "completion_rootfs_materializer.py").read_text()
    assert "return fs._enumerate_names_stable(node, control)" in materializer_source
    assert "return fs._enumerate_stable(node, control)" in materializer_source
    assert 'alias_node = fs._open_path_node(parent, alias_name, "file", transition)' in materializer_source
    assert 'child = fs._open_path_node(parent, name, "symlink", transition)' in materializer_source
    assert "for name, generation in snapshot.children:" in materializer_source
    assert materializer_source.count("fs._revalidate_chain(parent_chain") >= 4
    metadata_source = materializer_source.split("def _metadata(", 1)[1].split("\ndef ", 1)[0]
    assert metadata_source.index("fs._revalidate_chain(node_chain, control)") < metadata_source.index(
        'active = _append(active, "metadata-intent"'
    )
    assert metadata_source.index("fs._revalidate_chain(node_chain, transition)", metadata_source.index("metadata-observed")) < metadata_source.index(
        'active = _append(active, "metadata-settled"'
    )
    assert "root_chain" in materializer_source and "def _finalize_directory(active, owned" in materializer_source
    assert materializer_source.count("fs._revalidate_chain(alias_chain") >= 4
    assert "target_chain" in materializer_source and "_chain_after_parent(" in materializer_source
    assert "target_parent.generation.key ==" not in materializer_source
    assert "builder._delta_for_chain(target_chain, delta)" in materializer_source
    assert "_delta_for_chain(target_chain, delta)" in source
    assert 'fs._structural_increment("complete_walks")' in materializer_source
    assert "def _authorize" not in source
    rejected(lambda: builder._append(None, "leased", {}, control))
    rejected(lambda: builder._append(None, "release-authorized", {}, control))
    rejected(lambda: ledger._settled_record(0, 1, "a" * 64, 1))
    build_source = (REMOTE / "completion_rootfs_build.py").read_text()
    assert "observed = operation = None" in build_source and "fs._close_node(observed)" in build_source
    assert "class RetainedBuild" in build_source and "def _build_once_retained(" in build_source
    assert "def _require_equal_builds(" in build_source and "def _require_pinned(" in build_source
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
    fake_fd = fs.CheckedFd(999, "chain-test")

    def directory_generation(inode, ctime=1):
        return fs.HostGeneration(fs.HostKey(1, 1, inode, "directory"), 0o700, 0, 0, 2, 0, 1, ctime)

    def chain(*generations):
        anchor = fs.HeldNode(fake_fd, fake_fd, directory_generation(900))
        components = tuple(
            fs.ChainComponent(fs._name(f"part-{index}"), fs.HeldNode(fake_fd, fake_fd, value))
            for index, value in enumerate(generations)
        )
        return fs.HeldChain(anchor, components)

    alias_parent = directory_generation(901)
    target_parent = directory_generation(902)
    disjoint_parent = directory_generation(903)
    for action in ("hardlink", "unlink"):
        if action == "hardlink":
            before_names, after_names = (), (fs._name("alias"),)
        else:
            before_names, after_names = (fs._name("alias"),), ()
        delta = fs.ParentDelta(
            action, fs._name("alias"),
            fs.DirectoryNamesSnapshot(alias_parent, before_names),
            fs.DirectoryNamesSnapshot(dataclasses.replace(alias_parent, ctime_ns=2), after_names),
        )
        assert builder._delta_for_chain(chain(alias_parent), delta) is delta
        assert builder._delta_for_chain(chain(disjoint_parent), delta) is None
        assert builder._delta_for_chain(chain(alias_parent, target_parent), delta) is delta
        assert builder._delta_for_chain(chain(target_parent), delta) is None
        reciprocal = fs.ParentDelta(
            action, fs._name("alias"),
            fs.DirectoryNamesSnapshot(target_parent, before_names),
            fs.DirectoryNamesSnapshot(dataclasses.replace(target_parent, ctime_ns=2), after_names),
        )
        assert builder._delta_for_chain(chain(target_parent, alias_parent), reciprocal) is reciprocal
        rejected(lambda: builder._delta_for_chain(chain(alias_parent, alias_parent), delta))

    detached_chain = chain(alias_parent)
    detached_parent = detached_chain.components[-1].node
    detached_events = []
    real_revalidate = fs._revalidate_chain
    real_mkdir = builder.os.mkdir
    real_open = builder.os.open
    try:
        fs._revalidate_chain = lambda *_args: (
            detached_events.append("detached"), (_ for _ in ()).throw(fs.RootfsFsError()),
        )[1]
        builder.os.mkdir = lambda *_args, **_kwargs: detached_events.append("mkdir")
        builder.os.open = lambda *_args, **_kwargs: detached_events.append("open")
        rejected(lambda: builder._create_directory(
            detached_parent, fs._name("directory"), control, detached_chain,
        ))
        rejected(lambda: builder._create_file(
            detached_parent, fs._name("file"), b"content", control, detached_chain,
        ))
        assert detached_events == ["detached", "detached"]
    finally:
        fs._revalidate_chain = real_revalidate
        builder.os.mkdir = real_mkdir
        builder.os.open = real_open

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

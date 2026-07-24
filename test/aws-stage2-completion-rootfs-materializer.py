#!/usr/bin/env python3
"""Small direct-writer tests and non-authoritative Docker functional tests."""

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


def portable():
    source = (REMOTE / "completion_rootfs_materializer.py").read_text()
    assert "def _materialize(" in source and "revalidate_build_inputs" in source and "def _postwalk(" in source
    assert "if __name__" not in source and "sys.argv" not in source
    assert "target_opened + (() if target is None" in source and "(active.node,) +" in source
    for forbidden in ("rmtree", "os.walk", "glob", "subprocess", "socket", "tarfile", "extractall", "rename"):
        assert forbidden not in source
    print("completion rootfs materializer portable tests passed")


def prepare():
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
    require(lines[0][separator + 1] == "tmpfs" and {"rw", "nosuid", "nodev", "noexec"} <= set(lines[0][5].split(",")))
    observed = CONTAINER_SENTINEL.stat(follow_symlinks=False)
    require(stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o400)
    require(observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 1 and observed.st_dev == mount_stat.st_dev)
    require(CONTAINER_SENTINEL.read_bytes() == CONTAINER_SENTINEL_RAW)
    require(tuple(path.name for path in mount.iterdir()) == (CONTAINER_SENTINEL.name,) and not FIXED.parent.exists())
    remote = FIXED / "deploy/aws-feasibility/remote"
    cache = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    remote.mkdir(parents=True, mode=0o700)
    cache.mkdir(parents=True, mode=0o700)
    paths = [Path("/var/lib/cogs/stage2-completion-v1"), FIXED, FIXED / "deploy", FIXED / "deploy/aws-feasibility", remote, FIXED / "deploy/aws-feasibility/.state", FIXED / "deploy/aws-feasibility/.state/completion-v1", cache.parent, cache]
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


def accommodate_docker_overlay(fs):
    def check(condition):
        if not condition:
            raise RuntimeError("Docker functional policy mismatch")

    original_xattrs = fs._require_empty_fd_xattrs
    ancestors = {(os.lstat(path).st_dev, os.lstat(path).st_ino) for path in ("/", "/var", "/var/lib")}
    functional_device = os.lstat("/var/lib/cogs").st_dev
    fs._open_workspace_anchor = lambda control: fs._open_root_node(control)

    def policy(node, expected, root_key):
        generation = node.generation
        check(generation.key.kind == expected.kind and generation.mode == expected.mode)
        check(generation.uid == expected.uid and generation.gid == expected.gid)
        check((generation.key.mount_id, generation.key.device) == (root_key.mount_id, root_key.device) or generation.key.device == functional_device)
        if expected.kind == "file":
            check(generation.nlink == 1)

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
    accommodate_docker_overlay(fs)
    approval = fs.SourceApproval(revision, digest)
    control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
    chain = builder._open_base_chain(control)
    state = builder._bootstrap(chain, approval, control)
    fs._close_node(state)
    fs._close_chain(chain)
    state_path = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"

    def recover_absent_intent(token, hardlink):
        pending_chain = builder._open_base_chain(control)
        owned = builder._begin_operation(pending_chain, approval, token * 64, control)
        parent = builder._parent(owned.root, control)
        if hardlink:
            target = fs._open_path_node(owned.operation, builder.OPERATION_SENTINEL_NAME, "file", control)
            group = {
                "token": builder._token(owned.active),
                "target_path": builder.OPERATION_SENTINEL_NAME.text,
                "aliases": ["rootfs/alias"],
                "content_sha256": hashlib.sha256(builder.OPERATION_SENTINEL).hexdigest(),
                "target": builder._g(target.generation),
            }
            active = builder._append(owned.active, "hardlink-group", group, control)
            body = {
                "token": builder._token(active),
                "target_path": builder.OPERATION_SENTINEL_NAME.text,
                "alias": "rootfs/alias",
                "index": 0,
                "target": builder._g(target.generation),
                "parent": builder._p(parent),
            }
            fs._close_node(target)
            active = builder._append(active, "hardlink-create-intent", body, control)
        else:
            body = {"token": builder._token(owned.active), "path": "rootfs/absent", "kind": "file", "parent": builder._p(parent)}
            active = builder._append(owned.active, "create-intent", body, control)
        for node in (owned.root, owned.operation, active.node):
            fs._close_node(node)
        builder._release_lock(owned.locked)
        fs._close_node(owned.locked.state)
        fs._close_chain(pending_chain)
        builder._recover_fixed(control)
        assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    recover_absent_intent("7", False)
    recover_absent_intent("8", True)
    chain = builder._open_base_chain(control)
    authority = synthetic(plan_module, preflight)
    materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(authority)

    def startup_fault(token_number, record_type, occurrence=1):
        real_append = builder._append
        seen = {"count": 0}

        def append(active, kind, body, current_control):
            value = real_append(active, kind, body, current_control)
            if kind == record_type:
                seen["count"] += 1
                if seen["count"] == occurrence:
                    raise RuntimeError("startup fault")
            return value

        builder._append = append
        try:
            builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        except BaseException:
            pass
        else:
            raise AssertionError("startup fault was not observed")
        finally:
            builder._append = real_append
        assert seen["count"] == occurrence
        observed_state = sorted(path.name for path in state_path.iterdir())
        assert observed_state == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text)), (record_type, occurrence, observed_state)

    def genesis_fault(token_number, stage):
        real_write = builder.os.write
        real_fsync = builder.os.fsync
        real_fstat = builder.os.fstat
        calls = {"value": 0}

        def write_then_fail(descriptor, raw):
            calls["value"] += 1
            if calls["value"] == 1:
                return real_write(descriptor, raw[: max(1, len(raw) // 2)])
            raise OSError("genesis write fault")

        def fsync_then_fail(descriptor):
            calls["value"] += 1
            if calls["value"] == (1 if stage == "ledger-fsync" else 2):
                raise OSError("genesis fsync fault")
            return real_fsync(descriptor)

        def fstat_then_fail(descriptor):
            if calls["value"] == 0:
                calls["value"] = 1
                raise OSError("genesis post-open fault")
            return real_fstat(descriptor)

        if stage == "write":
            builder.os.write = write_then_fail
        elif stage in {"ledger-fsync", "parent-fsync"}:
            builder.os.fsync = fsync_then_fail
        else:
            builder.os.fstat = fstat_then_fail
        try:
            builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        except BaseException:
            pass
        else:
            raise AssertionError("genesis fault was not observed")
        finally:
            builder.os.write = real_write
            builder.os.fsync = real_fsync
            builder.os.fstat = real_fstat
        assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    for index, stage in enumerate(("post-open", "write", "ledger-fsync", "parent-fsync"), 10):
        genesis_fault(index, stage)

    startup_cases = (
        ("genesis-settled", 1),
        ("operation-create-intent", 1),
        ("operation-create-observed", 1),
        ("operation-create-settled", 1),
        ("create-intent", 1),
        ("create-observed", 1),
        ("create-settled", 1),
        ("create-intent", 2),
        ("create-observed", 2),
        ("create-settled", 2),
    )
    for index, (record_type, occurrence) in enumerate(startup_cases, 20):
        startup_fault(index, record_type, occurrence)

    hostile_umask = os.umask(0o777)
    owned = builder._begin_operation(chain, approval, "1" * 64, control)
    real_write = builder.os.write
    builder.os.write = lambda fd, raw: real_write(fd, raw[:5])
    try:
        result = materializer._materialize(authority, owned, control)
    finally:
        builder.os.write = real_write
        os.umask(hostile_umask)
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
    assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(authority)

    def fail_after_record(token, record_type, expire=False):
        owned = builder._begin_operation(chain, approval, token * 64, control)
        latch = {"cancelled": False}
        deadline = time.monotonic_ns() + (30_000_000 if expire else 60_000_000_000)
        interrupted = fs.OperationControl(deadline, lambda: latch["cancelled"])
        real_append = builder._append

        def append(active, kind, body, current_control):
            result = real_append(active, kind, body, current_control)
            if kind == record_type:
                if expire:
                    time.sleep(0.04)
                else:
                    latch["cancelled"] = True
            return result

        builder._append = append
        try:
            materializer._materialize(authority, owned, interrupted)
        except BaseException:
            pass
        else:
            raise AssertionError("interrupted materialization accepted")
        finally:
            builder._append = real_append
        assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    fail_after_record("3", "create-intent", True)
    fail_after_record("4", "create-observed")
    fail_after_record("5", "metadata-observed")
    fail_after_record("6", "hardlink-group")
    fail_after_record("9", "hardlink-create-intent")
    fail_after_record("a", "hardlink-create-observed")
    fail_after_record("b", "hardlink-create-settled")

    def cancel_inside_named(token_number, syscall_name):
        owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        latch = {"cancelled": False}
        interrupted = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: latch["cancelled"])
        module = materializer.os if syscall_name in {"link", "symlink"} else builder.os
        original = getattr(module, syscall_name)

        def mutate_then_cancel(*args, **kwargs):
            result = original(*args, **kwargs)
            if syscall_name != "open" or args[1] & os.O_CREAT:
                latch["cancelled"] = True
            return result

        setattr(module, syscall_name, mutate_then_cancel)
        try:
            materializer._materialize(authority, owned, interrupted)
        except BaseException:
            pass
        else:
            raise AssertionError("named mutation cancellation was not observed")
        finally:
            setattr(module, syscall_name, original)
        assert latch["cancelled"]
        assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    for index, syscall_name in enumerate(("mkdir", "open", "link", "symlink"), 100):
        cancel_inside_named(index, syscall_name)

    def fault_after_named_create(token_number, seam):
        owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        real_open = fs._open_path_node
        real_xattrs = fs._require_empty_fd_xattrs
        real_observe = fs._observe_child
        tripped = {"value": False}

        def open_fault(parent, name, kind, current_control):
            if not tripped["value"] and ((seam == "directory-open" and name.text == "bin" and kind == "directory") or (seam == "symlink-open" and name.text == "message" and kind == "symlink")):
                tripped["value"] = True
                raise OSError("post-create open fault")
            return real_open(parent, name, kind, current_control)

        def xattr_fault(node, current_control):
            if seam == "file-xattr" and not tripped["value"] and node.generation.key.kind == "file" and node.generation.mode == 0o600:
                tripped["value"] = True
                raise OSError("post-create xattr fault")
            return real_xattrs(node, current_control)

        def observe_fault(parent, name, current_control):
            if seam == "hardlink-observe" and not tripped["value"] and name.text == "tool-copy":
                tripped["value"] = True
                raise OSError("post-link observe fault")
            return real_observe(parent, name, current_control)

        fs._open_path_node = open_fault
        fs._require_empty_fd_xattrs = xattr_fault
        fs._observe_child = observe_fault
        try:
            materializer._materialize(authority, owned, control)
        except BaseException:
            pass
        else:
            raise AssertionError("post-create fault was not observed")
        finally:
            fs._open_path_node = real_open
            fs._require_empty_fd_xattrs = real_xattrs
            fs._observe_child = real_observe
        assert tripped["value"]
        observed_state = sorted(path.name for path in state_path.iterdir())
        assert observed_state == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text)), (seam, observed_state)

    for index, seam in enumerate(("directory-open", "file-xattr", "hardlink-observe", "symlink-open"), 130):
        fault_after_named_create(index, seam)

    def interrupt_inside_metadata(token_number, target_path, syscall_name, raise_after):
        owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        latch = {"cancelled": False}
        current = {"path": None}
        tripped = {"value": False}
        interrupted = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: latch["cancelled"])
        real_metadata = materializer._metadata
        original = getattr(materializer.os, syscall_name)

        def tracked_metadata(active, node, path, record, parent, current_control, symlink_name=None):
            current["path"] = path
            try:
                return real_metadata(active, node, path, record, parent, current_control, symlink_name)
            finally:
                current["path"] = None

        def mutate_then_interrupt(*args, **kwargs):
            result = original(*args, **kwargs)
            if current["path"] == target_path and not tripped["value"]:
                tripped["value"] = True
                if raise_after:
                    raise OSError("metadata syscall fault")
                latch["cancelled"] = True
            return result

        materializer._metadata = tracked_metadata
        setattr(materializer.os, syscall_name, mutate_then_interrupt)
        try:
            materializer._materialize(authority, owned, interrupted)
        except BaseException:
            pass
        else:
            raise AssertionError("metadata interruption was not observed")
        finally:
            materializer._metadata = real_metadata
            setattr(materializer.os, syscall_name, original)
        assert latch["cancelled"] or raise_after
        observed_state = sorted(path.name for path in state_path.iterdir())
        assert observed_state == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text)), (target_path, syscall_name, raise_after, observed_state)

    metadata_cases = (
        ("rootfs/bin/tool", "fchown"),
        ("rootfs/bin", "fchmod"),
        ("rootfs", "utime"),
        ("rootfs/etc/message", "chown"),
        ("rootfs/etc/message", "utime"),
    )
    for index, (target_path, syscall_name) in enumerate(metadata_cases, 120):
        interrupt_inside_metadata(index, target_path, syscall_name, False)
    for index, (target_path, syscall_name) in enumerate(metadata_cases, 140):
        interrupt_inside_metadata(index, target_path, syscall_name, True)

    owned = builder._begin_operation(chain, approval, "c" * 64, control)
    result = materializer._materialize(authority, owned, control)
    real_append = builder._append
    tripped = {"value": False}

    def fail_remove_observed(active, kind, body, current_control):
        value = real_append(active, kind, body, current_control)
        if kind == "remove-observed" and not tripped["value"]:
            tripped["value"] = True
            raise RuntimeError("remove observed fault")
        return value

    builder._append = fail_remove_observed
    try:
        builder._cleanup_owned(result.owned, result.active, control)
    except RuntimeError:
        pass
    else:
        raise AssertionError("remove observed fault was not observed")
    finally:
        builder._append = real_append
    for node in (result.owned.operation, result.active.node):
        if node.identity_fd.disposition == "open":
            fs._close_node(node)
    builder._release_lock(result.owned.locked)
    fs._close_node(result.owned.locked.state)
    builder._recover_fixed(builder._fresh_recovery_control())
    assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    def cancel_inside_removal(token_number, syscall_name):
        owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        result = materializer._materialize(authority, owned, control)
        latch = {"cancelled": False}
        interrupted = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: latch["cancelled"])
        original = getattr(builder.os, syscall_name)

        def mutate_then_cancel(*args, **kwargs):
            value = original(*args, **kwargs)
            latch["cancelled"] = True
            return value

        setattr(builder.os, syscall_name, mutate_then_cancel)
        try:
            builder._cleanup_owned(result.owned, result.active, interrupted)
        except BaseException:
            pass
        else:
            raise AssertionError("removal cancellation was not observed")
        finally:
            setattr(builder.os, syscall_name, original)
        for node in (result.owned.operation, result.active.node):
            if node.identity_fd.disposition == "open":
                fs._close_node(node)
        if result.owned.locked.lock.identity_fd.disposition == "open":
            builder._release_lock(result.owned.locked)
        if result.owned.locked.state.identity_fd.disposition == "open":
            fs._close_node(result.owned.locked.state)
        builder._recover_fixed(builder._fresh_recovery_control())
        assert latch["cancelled"]
        assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))

    cancel_inside_removal(110, "unlink")
    cancel_inside_removal(111, "rmdir")

    owned = builder._begin_operation(chain, approval, f"{112:064x}", control)
    result = materializer._materialize(authority, owned, control)
    real_append = builder._append
    tripped = {"value": False}

    def fail_before_remove_observed(active, kind, body, current_control):
        if kind == "remove-observed" and not tripped["value"]:
            tripped["value"] = True
            raise RuntimeError("pre-observed remove fault")
        return real_append(active, kind, body, current_control)

    builder._append = fail_before_remove_observed
    try:
        builder._cleanup_owned(result.owned, result.active, control)
    except RuntimeError:
        pass
    finally:
        builder._append = real_append
    for node in (result.owned.operation, result.active.node):
        if node.identity_fd.disposition == "open":
            fs._close_node(node)
    builder._release_lock(result.owned.locked)
    fs._close_node(result.owned.locked.state)
    builder._recover_fixed(builder._fresh_recovery_control())
    assert tripped["value"]
    assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
    artifact = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache/immutable.bin"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest
    fs._close_chain(chain)
    print("completion rootfs materializer Docker functional test passed")


if len(sys.argv) == 2 and sys.argv[1] == "--linux":
    linux()
else:
    portable()

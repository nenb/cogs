#!/usr/bin/env python3
"""Portable policy tests and non-authoritative Docker functional tests."""

import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
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
    assert "object.__setattr__" not in source
    new_ledger_source = source.split("def _new_active_ledger(", 1)[1].split("\ndef ", 1)[0]
    assert "rebound = _rebound_locked_state(" in new_ledger_source
    assert "return active, rebound" in new_ledger_source
    begin_source = source.split("def _begin_operation_unmasked(", 1)[1].split("\ndef ", 1)[0]
    transition_limited = begin_source.split("establishment_start =", 1)[1].split("transition =", 1)[0]
    assert "active, locked = _new_active_ledger(" in transition_limited
    assert "state = locked.state" in transition_limited
    assert "_state_chain(" not in transition_limited
    assert transition_limited.index("active, locked =") < transition_limited.index('"genesis-settled"')
    assert transition_limited.index('"operation-create-intent"') < transition_limited.index(
        "_operation_establishment_checkpoint("
    )
    checkpoint_source = source.split("def _operation_establishment_checkpoint(", 1)[1].split("\ndef ", 1)[0]
    assert 'checkpoint.parent_snapshots == 3' in checkpoint_source
    assert 'checkpoint.incremental_records == 2' in checkpoint_source
    assert 'checkpoint.complete_walks == 0' in checkpoint_source
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
    assert "candidate_tar._create_candidate(active, owned, authority, manifest, control)" in build_source
    assert "active = candidate.active" in build_source and "ustar = candidate.raw" in build_source
    assert all(stale not in build_source for stale in (
        "def _writable_file", "def _candidate_record", "EMPTY_TAR", "materializer._metadata(",
    ))
    assert "class RetainedBuild" in build_source and "def _build_once_retained(" in build_source
    assert "def _require_equal_builds(" in build_source and "def _require_pinned(" in build_source
    assert "for path in sorted(tuple(session.owned)" in source

    def candidate_generation(inode, kind="directory", mode=0o700, nlink=2, size=0, ctime=1):
        key = fs.HostKey(1, 1, inode, kind)
        return fs.HostGeneration(key, mode, 0, 0, nlink, size, 1, ctime)

    def candidate_fixture(terminal):
        token = "a" * 64
        operation_name = ledger._operation_name(token)
        state_before = ledger.LedgerParent(candidate_generation(1), ("active-ledger", "lock", "sentinel"))
        state_names = ("active-ledger", "lock", operation_name, "sentinel")
        state_after = ledger.LedgerParent(dataclasses.replace(state_before.generation, ctime_ns=2), state_names)
        operation = candidate_generation(2)
        pre_parent = ledger.LedgerParent(operation, ())
        post_parent = ledger.LedgerParent(dataclasses.replace(operation, ctime_ns=2), (ledger.CANDIDATE_TAR_PATH,))
        anonymous = candidate_generation(70, "file", 0o600, 0, ledger.CANDIDATE_TAR_SIZE, 10)
        linked = dataclasses.replace(anonymous, nlink=1, ctime_ns=11)
        state_value = ledger._parent_value(state_before)
        operation_value = {
            "token": token, "operation_name": operation_name,
            "state_parent": ledger._parent_value(state_after), "operation": ledger._generation_value(operation),
        }
        create_intent = dict(operation_value)
        create_intent.pop("operation")
        create_intent["state_parent"] = state_value
        proposals = [
            ledger.LedgerProposal.create("genesis", {
                "token": token, "source_revision": "b" * 40, "source_manifest_sha256": "c" * 64,
                "state_parent": state_value,
                "ledger_key": {"mount_id": 1, "device": 1, "inode": 99, "kind": "file"},
            }),
            ledger.LedgerProposal.create("genesis-settled", {"token": token, "state_parent": state_value}),
            ledger.LedgerProposal.create("operation-create-intent", create_intent),
            ledger.LedgerProposal.create("operation-create-observed", operation_value),
            ledger.LedgerProposal.create("operation-create-settled", operation_value),
        ]
        intent = {
            "token": token, "path": ledger.CANDIDATE_TAR_PATH,
            "parent": ledger._parent_value(pre_parent), "anonymous": ledger._generation_value(anonymous),
            "size": ledger.CANDIDATE_TAR_SIZE, "sha256": "7" * 64,
        }
        observed = {
            "token": token, "path": ledger.CANDIDATE_TAR_PATH,
            "parent": ledger._parent_value(post_parent),
            "anonymous": ledger._generation_value(anonymous), "linked": ledger._generation_value(linked),
            "size": ledger.CANDIDATE_TAR_SIZE, "sha256": "7" * 64,
        }
        proposals.append(ledger.LedgerProposal.create("candidate-tar-intent", intent))
        if terminal == "observed":
            proposals.append(ledger.LedgerProposal.create("candidate-tar-observed", observed))
        settled_bytes, chunks = ledger.INITIAL_BYTES, []
        for proposal in proposals:
            line = ledger._encode_proposal(proposal, settled_bytes)
            chunks.append(line)
            settled_bytes = ledger.SettledBytes(
                settled_bytes.sequence + 1, settled_bytes.offset + len(line), hashlib.sha256(line).hexdigest(),
            )
        raw = b"".join(chunks)
        history = ledger._parse_ledger_history(raw)
        ledger_file = candidate_generation(99, "file", 0o600, 1, len(raw))
        observations = ledger.ReconcileObservations(
            state_after,
            ((operation_name, operation if terminal == "absent" else post_parent.generation),),
            () if terminal == "absent" else ((ledger.CANDIDATE_TAR_PATH, linked),),
            ledger_file, (("", pre_parent if terminal == "absent" else post_parent),),
            None if terminal == "absent" else (ledger.CANDIDATE_TAR_SIZE, "7" * 64),
        )
        state = ledger._reconcile_ledger(ledger._history_records(history), observations)
        return history, state, state_after, operation, post_parent, linked

    appended = []
    real_candidate_helpers = (
        builder._session_require, builder._session_binding, builder._session_append,
        builder._cleanup_active, fs._open_path_node, builder._fsync, builder._close,)
    no_descriptor_work = lambda *_args: None
    builder._session_require = builder._session_binding = no_descriptor_work
    builder._fsync = no_descriptor_work
    builder._session_append = lambda _session, record, body, _control: (
        ledger.LedgerProposal.create(record, body), appended.append(record),
    )
    builder._cleanup_active = lambda session, _control: setattr(session, "disposition", "finished")
    try:
        for terminal, expected_status, expected_records in (
            ("absent", "candidate-tar-abortable", ("candidate-tar-abort",)),
            ("intent", "candidate-tar-observeable", ("candidate-tar-observed", "candidate-tar-settled")),
            ("observed", "candidate-tar-settleable", ("candidate-tar-settled",)),):
            history, state, state_parent, operation, post_parent, linked = candidate_fixture(terminal)
            assert state.status == expected_status and not state.owned
            descriptor = fs.CheckedFd(998, "candidate-dispatch")
            node = fs.HeldNode(descriptor, descriptor, linked)
            fs._open_path_node = lambda *_args, node=node: node
            builder._close = lambda value, *_args: setattr(value.identity_fd, "disposition", "closed")
            session = builder.CleanupSession(
                builder.ActiveLedger(None, history, None), object(), node, "prelease", state.status,
                {} if terminal == "absent" else {ledger.CANDIDATE_TAR_PATH: linked},
                {"": post_parent}, {}, operation, state_parent,
                None if terminal == "absent" else (ledger.CANDIDATE_TAR_SIZE, "7" * 64),
            )
            before = len(appended)
            builder._resume_candidate_tar(session, control)
            assert tuple(appended[before:]) == expected_records and session.disposition == "finished"
    finally:
        (builder._session_require, builder._session_binding, builder._session_append,
         builder._cleanup_active, fs._open_path_node, builder._fsync, builder._close) = real_candidate_helpers

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

    state_before = directory_generation(904)
    state_after = dataclasses.replace(state_before, ctime_ns=2)
    anchor = fs.HeldNode(fake_fd, fake_fd, directory_generation(900))
    prefix = fs.ChainComponent(fs._name("prefix"), fs.HeldNode(fake_fd, fake_fd, directory_generation(905)))
    state_node = fs.HeldNode(fake_fd, fake_fd, state_before)
    state_component = fs.ChainComponent(builder.STATE_NAME, state_node)
    locked_chain = fs.HeldChain(anchor, (prefix, state_component))
    lock = object()
    locked = builder.LockedState(locked_chain, state_node, lock)
    observed_state = fs.HeldNode(state_node.identity_fd, state_node.operation_fd, state_before)
    observed_chain = fs.HeldChain(anchor, (prefix, fs.ChainComponent(builder.STATE_NAME, observed_state)))
    rebound = builder._rebound_locked_state(locked, observed_chain, state_before, state_after)
    assert rebound is not locked and rebound.chain is not locked.chain
    assert rebound.state is rebound.chain.components[-1].node
    assert rebound.state.generation == state_after and rebound.lock is lock
    assert rebound.state.identity_fd is locked.state.identity_fd
    assert rebound.state.operation_fd is locked.state.operation_fd
    assert locked.state.generation == state_before and locked.chain.components[-1].node is state_node
    rejected(lambda: builder._rebound_locked_state(locked, observed_chain, directory_generation(999), state_after))
    duplicate = fs.HeldChain(anchor, (
        fs.ChainComponent(fs._name("hostile"), fs.HeldNode(fake_fd, fake_fd, state_before)),
        fs.ChainComponent(builder.STATE_NAME, observed_state),
    ))
    duplicate_locked = builder.LockedState(duplicate, observed_state, lock)
    rejected(lambda: builder._rebound_locked_state(duplicate_locked, duplicate, state_before, state_after))
    wrong_anchor = fs.HeldNode(fake_fd, fake_fd, directory_generation(999))
    hostile_chain = fs.HeldChain(wrong_anchor, observed_chain.components)
    rejected(lambda: builder._rebound_locked_state(locked, hostile_chain, state_before, state_after))

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


def require_native_linux_host():
    def require(condition, message):
        if not condition:
            raise RuntimeError(f"native Linux C1 preflight: {message}")

    require(sys.platform == "linux" and os.geteuid() == 0, "requires Linux EUID 0")
    for namespace in ("mnt", "user", "pid"):
        current = os.stat(f"/proc/self/ns/{namespace}")
        initial = os.stat(f"/proc/1/ns/{namespace}")
        require((current.st_dev, current.st_ino) == (initial.st_dev, initial.st_ino),
                f"does not share PID 1 {namespace} namespace")
    markers = ("/.dockerenv", "/.containerenv", "/run/.containerenv", "/run/systemd/container")
    require(not any(Path(path).exists() for path in markers), "container marker present")
    container_tokens = (b"docker", b"kubepods", b"containerd", b"libpod", b"podman", b"lxc")
    cgroups = Path("/proc/self/cgroup").read_bytes() + Path("/proc/1/cgroup").read_bytes()
    require(not any(token in cgroups.lower() for token in container_tokens), "container cgroup present")
    init_environment = Path("/proc/1/environ").read_bytes().split(b"\0")
    require(not any(value.lower().startswith(b"container=") for value in init_environment),
            "PID 1 container environment present")
    root_rows = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[4] == "/" and "-" in fields:
            separator = fields.index("-")
            root_rows.append((fields, separator))
    require(len(root_rows) == 1, "root mount is not unique")
    fields, separator = root_rows[0]
    require(fields[3] == "/" and fields[separator + 1] not in {"overlay", "aufs"},
            "root is overlay-backed or not the filesystem root")
    require("rw" in fields[5].split(","), "root mount is not writable")

    mount_ids = set()
    for path, mode in (("/", 0o755), ("/var", 0o755), ("/var/lib", 0o755)):
        observed = os.lstat(path)
        require(stat.S_ISDIR(observed.st_mode) and stat.S_IMODE(observed.st_mode) == mode,
                f"{path} does not have production directory policy")
        require(observed.st_uid == observed.st_gid == 0 and not os.listxattr(path, follow_symlinks=False),
                f"{path} does not have production ownership/xattr policy")
        descriptor = os.open(path, getattr(os, "O_PATH", 0o10000000) | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            rows = dict(line.split(":\t", 1) for line in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines())
            mount_ids.add(int(rows["mnt_id"]))
        finally:
            os.close(descriptor)
    require(mount_ids == {int(fields[0])}, "production path is not on the native root mount")
    require(not Path("/var/lib/cogs").exists(), "requires absent /var/lib/cogs")


def prepare_fixed_workspace(native=False):
    if native:
        require_native_linux_host()
        Path("/var/lib/cogs").mkdir(mode=0o700)
    else:
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
    revision = os.environ.get("COGS_C1_EXPECTED_HEAD_SHA", "") if native else "d" * 40
    assert len(revision) == 40 and all(value in "0123456789abcdef" for value in revision)
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


def native_linux_c1_test():
    revision = digest = None
    owned_root = not Path("/var/lib/cogs").exists()
    try:
        revision, digest, _artifact_digest = prepare_fixed_workspace(True)
        fixed_remote = FIXED / "deploy/aws-feasibility/remote"
        sys.path.insert(0, str(fixed_remote))
        fs = load("completion_rootfs_fs", fixed_remote / "completion_rootfs_fs.py")
        load("completion_rootfs_ledger", fixed_remote / "completion_rootfs_ledger.py")
        builder = load("completion_rootfs_builder", fixed_remote / "completion_rootfs_builder.py")
        approval = fs.SourceApproval(revision, digest)
        control = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: False)
        state_path = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
        idle = tuple(sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text)))

        def inventory():
            values = []
            for path in sorted(state_path.iterdir(), key=lambda item: item.name.encode()):
                descriptor = os.open(path, getattr(os, "O_PATH", 0o10000000) | os.O_NOFOLLOW)
                try:
                    observed = os.fstat(descriptor)
                    rows = dict(line.split(":\t", 1) for line in Path(
                        f"/proc/self/fdinfo/{descriptor}"
                    ).read_text().splitlines())
                finally:
                    os.close(descriptor)
                kind = ("file" if stat.S_ISREG(observed.st_mode) else
                        "directory" if stat.S_ISDIR(observed.st_mode) else
                        "symlink" if stat.S_ISLNK(observed.st_mode) else "other")
                xattrs = tuple((name, os.getxattr(path, name, follow_symlinks=False))
                               for name in sorted(os.listxattr(path, follow_symlinks=False)))
                content = path.read_bytes() if kind == "file" else None
                generation = (int(rows["mnt_id"]), observed.st_dev, observed.st_ino, kind,
                              stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid,
                              observed.st_nlink, observed.st_size, observed.st_mtime_ns,
                              observed.st_ctime_ns)
                values.append((path.name, generation, xattrs, content))
            return tuple(values)

        def reset_state():
            if state_path.exists():
                shutil.rmtree(state_path)
            chain = builder._open_base_chain(control)
            state = builder._bootstrap(chain, approval, control)
            fs._close_node(state)
            fs._close_chain(chain)
            baseline = inventory()
            assert tuple(item[0] for item in baseline) == idle
            assert dict((item[0], item[3]) for item in baseline)[builder.STATE_SENTINEL_NAME.text] == builder.STATE_SENTINEL
            return baseline

        policy_chain = builder._open_base_chain(control)
        assert len(policy_chain.components) == len(fs._fixed_policies())
        assert all(component.node.generation.key.mount_id == policy_chain.anchor.generation.key.mount_id
                   and component.node.generation.key.device == policy_chain.anchor.generation.key.device
                   for component in policy_chain.components)
        fs._close_chain(policy_chain)

        baseline = reset_state()
        reports = []
        real_checkpoint = builder._operation_establishment_checkpoint

        def capture_checkpoint(*args):
            report = real_checkpoint(*args)
            reports.append(report)
            return report

        builder._operation_establishment_checkpoint = capture_checkpoint
        chain = builder._open_base_chain(control)
        owned = builder._begin_operation(chain, approval, "a" * 64, control)
        builder._operation_establishment_checkpoint = real_checkpoint
        assert len(reports) == 1
        report = reports[0]
        assert (report.parent_snapshots, report.incremental_records, report.complete_walks) == (3, 2, 0)
        genesis_parent = builder.ledger._parse_parent(builder._first_record(owned.active).body_value()["state_parent"])
        assert report.ledger_state_generation == genesis_parent.generation
        assert owned.locked.state is owned.locked.chain.components[-1].node
        assert owned.locked.state.generation == report.ledger_state_generation
        builder._cleanup_owned(owned, owned.active, control)
        fs._close_chain(chain)
        assert inventory() == baseline

        def crash_at(seam, token_number):
            pid = os.fork()
            if pid == 0:
                try:
                    child_chain = builder._open_base_chain(control)
                    real_new = builder._new_active_ledger
                    real_rebound = builder._rebound_locked_state
                    real_append = builder._append
                    real_revalidate = fs._revalidate_chain
                    real_open = builder.os.open
                    armed = {"proof": False}

                    def cut():
                        os._exit(91)

                    def new_ledger(*args):
                        if seam == "ledger-before":
                            cut()
                        value = real_new(*args)
                        if seam == "ledger-after":
                            cut()
                        return value

                    def rebound(*args):
                        if seam == "rebound-before":
                            cut()
                        value = real_rebound(*args)
                        if seam == "rebound-after":
                            cut()
                        return value

                    def append(active, kind, body, current_control):
                        if seam == f"{kind}-before":
                            cut()
                        value = real_append(active, kind, body, current_control)
                        if kind == "genesis-settled":
                            armed["proof"] = True
                        if seam == f"{kind}-after":
                            cut()
                        return value

                    def revalidate(*args, **kwargs):
                        if armed["proof"] and seam == "next-proof-before":
                            cut()
                        value = real_revalidate(*args, **kwargs)
                        if armed["proof"] and seam == "next-proof-after":
                            cut()
                        return value

                    def open_name(name, flags, *args, **kwargs):
                        if name == builder.LEDGER_NAME.raw and flags & os.O_CREAT:
                            if seam == "ledger-name-before":
                                cut()
                            value = real_open(name, flags, *args, **kwargs)
                            if seam == "ledger-name-after":
                                cut()
                            return value
                        return real_open(name, flags, *args, **kwargs)

                    builder._new_active_ledger = new_ledger
                    builder._rebound_locked_state = rebound
                    builder._append = append
                    fs._revalidate_chain = revalidate
                    builder.os.open = open_name
                    builder._begin_operation(child_chain, approval, f"{token_number:064x}", control)
                except BaseException:
                    os._exit(92)
                os._exit(93)
            _pid, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 91, seam

        recoverable = (
            "ledger-name-before", "ledger-before", "ledger-after",
            "rebound-before", "rebound-after",
            "genesis-settled-before", "genesis-settled-after",
            "next-proof-before", "next-proof-after",
            "operation-create-intent-before", "operation-create-intent-after",
        )
        for token_number, seam in enumerate(recoverable, 100):
            baseline = reset_state()
            crash_at(seam, token_number)
            builder._recover_fixed(builder._fresh_recovery_control())
            assert inventory() == baseline, seam

        baseline = reset_state()
        crash_at("ledger-name-after", 200)
        uncertain = inventory()
        assert uncertain != baseline
        rejected(lambda: builder._recover_fixed(builder._fresh_recovery_control()))
        assert inventory() == uncertain
        print(json.dumps({
            "classification": "observation-only",
            "source_sha": revision,
            "observations": [
                "counter-3-2-0",
                "descriptor-continuity",
                "exact-baseline-recovery",
                "uncertain-state-preservation",
            ],
        }, sort_keys=True, separators=(",", ":")))
    finally:
        if owned_root and Path("/var/lib/cogs").exists():
            shutil.rmtree("/var/lib/cogs")


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

    def state_inventory():
        values = []
        for path in sorted(state_path.rglob("*"), key=lambda item: str(item).encode()):
            descriptor = os.open(path, getattr(os, "O_PATH", 0o10000000) | os.O_NOFOLLOW)
            try:
                observed = os.fstat(descriptor)
                rows = dict(line.split(":\t", 1) for line in Path(
                    f"/proc/self/fdinfo/{descriptor}"
                ).read_text().splitlines())
            finally:
                os.close(descriptor)
            kind = ("file" if stat.S_ISREG(observed.st_mode) else
                    "directory" if stat.S_ISDIR(observed.st_mode) else
                    "symlink" if stat.S_ISLNK(observed.st_mode) else "other")
            xattrs = tuple((name, os.getxattr(path, name, follow_symlinks=False))
                           for name in sorted(os.listxattr(path, follow_symlinks=False)))
            values.append((
                str(path.relative_to(state_path)), int(rows["mnt_id"]), observed.st_dev,
                observed.st_ino, kind, stat.S_IMODE(observed.st_mode), observed.st_uid,
                observed.st_gid, observed.st_nlink, observed.st_size, observed.st_mtime_ns,
                observed.st_ctime_ns, xattrs, path.read_bytes() if kind == "file" else None,
                os.readlink(path) if kind == "symlink" else None,
            ))
        return tuple(values)

    def reset_preserved_state():
        shutil.rmtree(state_path)
        reset_chain = builder._open_base_chain(control)
        reset = builder._bootstrap(reset_chain, approval, control)
        fs._close_node(reset)
        fs._close_chain(reset_chain)

    def rollback_cut(token_number, kind, route, seam):
        baseline = state_inventory()
        owner_chain = builder._open_base_chain(control)
        owned = builder._begin_operation(owner_chain, approval, f"{token_number:064x}", control)
        operation_chain = builder._held_operation_chain(
            owned.active, owned.locked, owned.operation, control,
        )
        root = fs.HeldNode(
            owned.root.identity_fd, owned.root.operation_fd,
            fs._observe_node(owned.root.identity_fd, owned.root.operation_fd, control),
        )
        root_chain = builder._chain_with_child(operation_chain, builder.ROOT_NAME, root)
        name = fs._name(f"rollback-{kind}-{route}")
        content = b"rollback-file" if kind == "file" else None
        gate = {"primary": False, "returned": False, "removed": False, "removal": None,
                "rebound": False, "final_chain": None, "target": None, "closed": False,
                "abort": False, "abort_observations": 0, "absence": 0,
                "tripped": False, "authority": None}
        originals = (
            fs._open_path_node, fs._require_empty_fd_xattrs, builder._close, builder.os.rmdir,
            builder.os.unlink, builder._parent_snapshot, fs.ParentDelta.__init__, fs._revalidate_chain,
            builder._chain_after_parent, builder._CreateRollbackError, builder._append,
            builder.ledger._observe_node, builder.ledger.os.fsync, builder._create_directory,
            builder._create_file, builder.os.mkdir, builder._absence_abort_body,
        )

        def cut(label):
            if seam == label:
                gate["tripped"] = True
                raise OSError(label)

        def absence(*args):
            gate["absence"] += 1
            return originals[16](*args)

        def mkdir(*args, **kwargs):
            return originals[15](*args, **kwargs)

        def open_node(parent, selected, selected_kind, current_control):
            value = originals[0](parent, selected, selected_kind, current_control)
            if selected == name and gate["target"] is None:
                gate["target"] = value
            return value

        def xattrs(node, current_control):
            if node is gate["target"] and route == "helper-error" and not gate["primary"]:
                gate["primary"] = True
                raise OSError(f"{kind}-helper-error")
            return originals[1](node, current_control)

        def close(node, primary=None):
            if node is gate["target"]:
                cut("close-before")
                value = originals[2](node, primary)
                gate["closed"] = True
                cut("close-after")
                return value
            return originals[2](node, primary)

        def remove(original, *args, **kwargs):
            if gate["primary"] and args and args[0] == name.raw:
                cut("remove-before")
            value = original(*args, **kwargs)
            if gate["primary"] and args and args[0] == name.raw:
                gate["removed"] = True
                cut("remove-after")
            return value

        def rmdir(*args, **kwargs):
            return remove(originals[3], *args, **kwargs)

        def unlink(*args, **kwargs):
            return remove(originals[4], *args, **kwargs)

        def snapshot(*args):
            if gate["removed"]:
                cut("post-snapshot-before")
            value = originals[5](*args)
            if gate["removed"]:
                cut("post-snapshot-after")
            return value

        def parent_delta(self, action, selected, before, after):
            if action in {"rmdir", "unlink"}:
                cut("remove-delta-before")
            originals[6](self, action, selected, before, after)
            if action in {"rmdir", "unlink"}:
                gate["removal"] = self
                cut("remove-delta-after")

        def revalidate(chain_value, current_control, parent_delta_value=None):
            if (route == "post-return" and gate["returned"] and not gate["primary"] and
                    parent_delta_value is not None and parent_delta_value.action == "create"):
                gate["primary"] = True
                raise OSError(f"{kind}-post-return-error")
            if parent_delta_value is not None and parent_delta_value.action in {"rmdir", "unlink"}:
                gate["removal"] = parent_delta_value
                cut("remove-proof-before")
            if gate["rebound"] and parent_delta_value is None:
                cut("final-proof-before")
            value = originals[7](chain_value, current_control, parent_delta_value)
            if parent_delta_value is not None and parent_delta_value.action in {"rmdir", "unlink"}:
                cut("remove-proof-after")
            if gate["rebound"] and parent_delta_value is None:
                cut("final-proof-after")
            return value

        def chain_after(chain_value, before, after):
            removal = gate["removal"]
            is_rebind = removal is not None and before == removal.before.generation and after == removal.after.generation
            if is_rebind:
                cut("rebind-before")
            value = originals[8](chain_value, before, after)
            if is_rebind:
                gate["rebound"] = True
                gate["final_chain"] = value
                cut("rebind-after")
            return value

        def create_helper(original, *args):
            try:
                value = original(*args)
                gate["returned"] = True
                return value
            except BaseException as error:
                if type(error) is originals[9]:
                    gate["authority"] = error
                raise

        def create_directory(*args):
            return create_helper(originals[13], *args)

        def create_file(*args):
            return create_helper(originals[14], *args)

        def append(active, kind, body, current_control):
            if kind == "create-abort":
                removal = gate["removal"]
                final_chain = gate["final_chain"]
                if gate["authority"] is not None:
                    assert gate["authority"].removal == removal
                    assert gate["authority"].chain == final_chain
                assert removal.after.generation == builder.ledger._parse_parent(body["parent"]).generation
                assert final_chain.components[-1].node.generation == removal.after.generation
                assert gate["closed"] and gate["target"].identity_fd.disposition == "closed"
                cut("abort-before")
                gate["abort"] = True
            value = originals[10](active, kind, body, current_control)
            if kind == "create-abort":
                cut("abort-after")
            return value

        def observe(*args):
            if gate["abort"]:
                gate["abort_observations"] += 1
                if gate["abort_observations"] == 2:
                    cut("abort-readback-before")
            value = originals[11](*args)
            if gate["abort"] and gate["abort_observations"] == 2:
                cut("abort-readback-after")
            return value

        def fsync(descriptor):
            if gate["removed"] and gate["removal"] is None:
                cut("remove-sync-before")
            if gate["abort"]:
                cut("abort-sync-before")
            value = originals[12](descriptor)
            if gate["removed"] and gate["removal"] is None:
                cut("remove-sync-after")
            if gate["abort"]:
                cut("abort-sync-after")
            return value

        fs._open_path_node, fs._require_empty_fd_xattrs = open_node, xattrs
        fs.ParentDelta.__init__ = parent_delta
        builder._close, builder.os.rmdir, builder.os.unlink, builder.os.mkdir = close, rmdir, unlink, mkdir
        builder._parent_snapshot = snapshot
        fs._revalidate_chain = revalidate
        builder._chain_after_parent = chain_after
        builder._create_directory, builder._create_file = create_directory, create_file
        builder._append, builder._absence_abort_body = append, absence
        builder.ledger._observe_node, builder.ledger.os.fsync = observe, fsync
        failure = None
        try:
            builder._create_ledger_entry(
                owned.active, root_chain, "rootfs/" + name.text, name, kind, content, control,
            )
        except BaseException as caught:
            failure = caught
        else:
            raise AssertionError("rollback cut accepted")
        finally:
            (fs._open_path_node, fs._require_empty_fd_xattrs, builder._close, builder.os.rmdir,
             builder.os.unlink, builder._parent_snapshot, fs.ParentDelta.__init__, fs._revalidate_chain,
             builder._chain_after_parent, _rollback_type_unused, builder._append,
             builder.ledger._observe_node, builder.ledger.os.fsync,
             builder._create_directory, builder._create_file, builder.os.mkdir,
             builder._absence_abort_body) = originals
        label = (kind, route, seam)
        if seam == "success":
            assert gate["abort"] and gate["removed"] and gate["closed"], (
                repr(failure), repr(getattr(failure, "primary", None)), gate,
            )
            assert (gate["authority"] is not None) == (route == "helper-error"), label
        else:
            assert gate["tripped"], label
            if not seam.startswith("abort-"):
                assert not gate["abort"], label
        if route == "post-return" and seam in {"close-before", "close-after"}:
            assert gate["removed"] and not gate["abort"], label
        assert gate["absence"] == 0, label
        for node in (owned.root, owned.operation, owned.active.node):
            if node.identity_fd.disposition == "open":
                fs._close_node(node)
        if owned.locked.lock.identity_fd.disposition == "open":
            builder._release_lock(owned.locked)
        if owned.locked.state.identity_fd.disposition == "open":
            fs._close_node(owned.locked.state)
        fs._close_chain(owner_chain)
        before_recovery = state_inventory()
        try:
            builder._recover_fixed(builder._fresh_recovery_control())
        except BaseException:
            assert state_inventory() == before_recovery and before_recovery != baseline, label
            reset_preserved_state()
        else:
            assert state_inventory() == baseline, label

    rollback_cases = (
        "success", "close-before", "close-after", "remove-before", "remove-after",
        "remove-sync-before", "remove-sync-after", "post-snapshot-before", "post-snapshot-after",
        "remove-delta-before", "remove-delta-after", "remove-proof-before", "remove-proof-after",
        "rebind-before", "rebind-after", "final-proof-before", "final-proof-after",
        "abort-before", "abort-after", "abort-sync-before", "abort-sync-after",
        "abort-readback-before", "abort-readback-after",
    )
    matrix = ((kind, route, seam) for kind in ("directory", "file")
              for route in ("helper-error", "post-return") for seam in rollback_cases)
    for index, (kind, route, seam) in enumerate(matrix, 300):
        rollback_cut(index, kind, route, seam)

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
elif len(sys.argv) == 2 and sys.argv[1] == "--native-linux-c1":
    native_linux_c1_test()
else:
    portable_tests()
    print("completion rootfs builder portable tests passed")

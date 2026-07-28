#!/usr/bin/env python3
"""Small direct-writer tests and non-authoritative Docker functional tests."""

import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace
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

    sys.path.insert(0, str(REMOTE))
    fs = load("completion_rootfs_fs_metadata_probe", REMOTE / "completion_rootfs_fs.py")
    sys.modules["completion_rootfs_fs"] = fs
    load("completion_rootfs_ledger", REMOTE / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", REMOTE / "completion_rootfs_builder.py")
    materializer = load("completion_rootfs_materializer_probe", REMOTE / "completion_rootfs_materializer.py")
    fake_fd = fs.CheckedFd(999, "detached-probe")

    def generation(inode, kind, mode):
        return fs.HostGeneration(fs.HostKey(1, 1, inode, kind), mode, 0, 0, 1 if kind != "directory" else 2, 0, 1, 1)

    parent = fs.HeldNode(fake_fd, fake_fd, generation(10, "directory", 0o700))
    original_revalidate = fs._revalidate_chain
    original_append = materializer._append
    try:
        for label, kind, mode, symlink in (
            ("regular", "file", 0o600, None),
            ("directory", "directory", 0o700, None),
            ("root", "directory", 0o755, None),
            ("symlink", "symlink", 0o777, fs._name("link")),
        ):
            node = fs.HeldNode(fake_fd, None if kind == "symlink" else fake_fd, generation(20, kind, mode))
            chain = fs.HeldChain(parent, (fs.ChainComponent(fs._name(label), node),))
            events = []

            def detached(*_args):
                events.append("detached")
                raise fs.RootfsFsError()

            fs._revalidate_chain = detached
            materializer._append = lambda *_args: events.append("append")
            record = SimpleNamespace(kind=kind, archive_size=0, mode=mode, uid=0, gid=0, mtime=1)
            try:
                materializer._metadata(None, node, label, record, parent, object(), chain, symlink)
            except fs.RootfsFsError:
                pass
            else:
                raise AssertionError(f"detached {label} metadata accepted")
            assert events == ["detached"]
    finally:
        fs._revalidate_chain = original_revalidate
        materializer._append = original_append
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


def accommodate_docker_overlay(fs, builder):
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


def synthetic_many(plan_module, preflight, regular_count):
    records = [
        preflight.MaterialRecord("a", "directory", 0o755, 0, 0, 7, 0, None, None, None, None, -1),
        preflight.MaterialRecord("b", "directory", 0o755, 0, 0, 8, 0, None, None, None, None, -1),
    ]
    content = bytearray()
    values = [("a/000-target", b"hardlink-target\n")]
    values.extend((f"a/file-{index:03d}", f"file-{index:03d}\n".encode()) for index in range(regular_count))
    for index, (path, raw) in enumerate(values, 8):
        offset = len(content)
        content.extend(raw)
        records.append(preflight.MaterialRecord(path, "file", 0o644, 0, 0, index, len(raw), None, None, None, hashlib.sha256(raw).hexdigest(), offset))
    target = records[2]
    for index, path in enumerate(("a/zz-alias-one", "b/zz-alias-two"), 9 + len(values)):
        records.append(preflight.MaterialRecord(path, "hardlink", target.mode, 0, 0, target.mtime, 0, None, None, target.path, None, -1))
    records.sort(key=lambda record: record.path.encode())
    owner = preflight.PreflightedTar(bytes(content), plan_module.ROOT_POLICY, tuple(records), ())
    entries = tuple(plan_module.PlannedEntry("synthetic-many", owner, record) for record in records)
    return plan_module.RootfsBuildInputs(
        "3" * 64, (), (), plan_module.RootfsPlan(plan_module.ROOT_POLICY, ("synthetic-many",), entries, ()),
    )


def linux():
    revision, digest, artifact_digest = prepare()
    remote = FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(remote))
    preflight = load("completion_archive_preflight", remote / "completion_archive_preflight.py")
    plan_module = load("completion_rootfs_plan", remote / "completion_rootfs_plan.py")
    fs = load("completion_rootfs_fs", remote / "completion_rootfs_fs.py")
    ledger_module = load("completion_rootfs_ledger", remote / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", remote / "completion_rootfs_builder.py")
    materializer = load("completion_rootfs_materializer", remote / "completion_rootfs_materializer.py")
    accommodate_docker_overlay(fs, builder)
    approval = fs.SourceApproval(revision, digest)
    control = fs.OperationControl(time.monotonic_ns() + 3_600_000_000_000, lambda: False)
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
    def d3_cleanup_fault_matrix():
        nonlocal chain

        def inventory():
            values = []
            ledger_raw = None
            for path in sorted(state_path.rglob("*"), key=lambda value: str(value).encode()):
                relative = str(path.relative_to(state_path))
                first = os.lstat(path)
                content = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(first.st_mode) else None
                target = os.readlink(path) if stat.S_ISLNK(first.st_mode) else None
                try:
                    xattrs = tuple((name, os.getxattr(path, name, follow_symlinks=False))
                                   for name in sorted(os.listxattr(path, follow_symlinks=False)))
                except OSError as error:
                    if error.errno not in {getattr(os, "ENOTSUP", 95), 95}:
                        raise
                    xattrs = None
                observed = os.lstat(path)
                values.append((relative, observed.st_dev, observed.st_ino, observed.st_mode,
                               observed.st_uid, observed.st_gid, observed.st_nlink, observed.st_size,
                               observed.st_mtime_ns, observed.st_ctime_ns, xattrs, target, content))
                if relative == builder.LEDGER_NAME.text:
                    ledger_raw = path.read_bytes()
            return tuple(values), ledger_raw

        def fresh_process_recovery(expect_preserve=False):
            before = inventory()
            counter_path = Path(f"/tmp/cogs-d3-recovery-{os.getpid()}-{time.monotonic_ns()}.json")
            pid = os.fork()
            if pid == 0:
                if expect_preserve:
                    sink = os.open("/dev/null", os.O_WRONLY)
                    os.dup2(sink, 1)
                    os.dup2(sink, 2)
                    os.close(sink)
                environment = dict(os.environ)
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                environment["COGS_D3_RECOVERY_COUNTERS"] = str(counter_path)
                os.execve(sys.executable, (sys.executable, str(Path(__file__).resolve()), "--recover-only"), environment)
            _pid, status = os.waitpid(pid, 0)
            code = os.waitstatus_to_exitcode(status)
            counters = json.loads(counter_path.read_text())
            counter_path.unlink()
            assert set(counters) == {"status", "active_history_record_copies", "listed_names", "parent_snapshots",
                                     "complete_legal_folds", "complete_walks", "incremental_records",
                                     "group_node_copies", "group_lookup_steps"}
            if expect_preserve:
                assert code == 1 and counters["status"] == "rejected" and inventory() == before, (seam, code)
            else:
                assert code == 0 and counters["status"] == "recovered", (seam, code, counters)
                assert sorted(path.name for path in state_path.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
            return counters

        def exact_counter_case(owned_count, token_number):
            owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
            active = owned.active
            for index in range(owned_count - 2):
                name = fs._name(f"flat-{index:03d}")
                operation_chain = builder._held_operation_chain(active, owned.locked, owned.operation, control)
                active, child = builder._create_ledger_entry(
                    active, operation_chain, name.text, name, "file", f"flat-{index:03d}\n".encode(), control,
                )
                fs._close_node(child)
            owned = builder.OwnedOperation(owned.locked, active, owned.operation, owned.root, owned.operation_name)
            trace = {"listed_names": 0, "parent_snapshots": 0, "complete_walks": 0,
                     "complete_legal_folds": 0, "incremental_records": 0}
            real_list, real_enumerate = fs._list_names, fs._enumerate_names_stable
            real_walk = builder._walk_entries
            real_validate, real_advance = ledger_module._validated_history, ledger_module._advance_history

            def traced_list(*args):
                value = real_list(*args)
                trace["listed_names"] += len(value)
                return value

            def traced_enumerate(*args):
                trace["parent_snapshots"] += 1
                return real_enumerate(*args)

            def traced_walk(*args):
                trace["complete_walks"] += 1
                return real_walk(*args)

            def traced_validate(*args):
                trace["complete_legal_folds"] += 1
                return real_validate(*args)

            def traced_advance(*args, **kwargs):
                count_incremental = kwargs.get("count_incremental", args[2] if len(args) > 2 else True)
                trace["incremental_records"] += int(count_incremental)
                return real_advance(*args, **kwargs)

            fs._list_names, fs._enumerate_names_stable = traced_list, traced_enumerate
            builder._walk_entries = traced_walk
            ledger_module._validated_history, ledger_module._advance_history = traced_validate, traced_advance
            counter_before = fs.structural_counter_snapshot()
            try:
                builder._cleanup_owned(owned, active, control)
            finally:
                fs._list_names, fs._enumerate_names_stable = real_list, real_enumerate
                builder._walk_entries = real_walk
                ledger_module._validated_history, ledger_module._advance_history = real_validate, real_advance
            counters = fs.structural_counter_delta(counter_before, fs.structural_counter_snapshot())
            assert counters == {
                "active_history_record_copies": 0,
                "listed_names": (9 * owned_count * owned_count + 33 * owned_count + 270) // 2,
                "parent_snapshots": 4 * owned_count + 13,
                "complete_legal_folds": 8,
                "complete_walks": 2,
                "incremental_records": 3 * owned_count + 3,
                "group_node_copies": 0,
                "group_lookup_steps": 0,
            }, (owned_count, counters)
            assert trace == {key: counters[key] for key in trace}, (owned_count, trace, counters)

        exact_counter_case(64, 200)
        exact_counter_case(128, 201)

        fault_authority = synthetic_many(plan_module, preflight, 4)
        materializer.plan.revalidate_build_inputs = lambda _value: dataclasses.replace(fault_authority)
        def close_failed(result):
            for node in (result.owned.root, result.owned.operation, result.active.node):
                if node.identity_fd.disposition == "open":
                    fs._close_node(node)
            if result.owned.locked.lock.identity_fd.disposition == "open":
                builder._release_lock(result.owned.locked)
            if result.owned.locked.state.identity_fd.disposition == "open":
                fs._close_node(result.owned.locked.state)

        def reset_workspace():
            nonlocal chain
            fs._close_chain(chain)
            shutil.rmtree(state_path)
            chain = builder._open_base_chain(control)
            state = builder._bootstrap(chain, approval, control)
            fs._close_node(state)
            fs._close_chain(chain)
            chain = builder._open_base_chain(control)

        def released_owner(token_number):
            owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
            result = materializer._materialize(fault_authority, owned, control)
            leased = builder._mark_leased(result.owned, "4" * 64, 1, "5" * 64, 512, result.entry_count, control)
            terminal = leased.active.records.terminal
            body = {
                "token": builder._token(leased.active), "operation_name": leased.operation_name,
                "lease_sequence": terminal.sequence, "lease_offset": terminal.next_offset,
                "lease_sha256": terminal.line_sha256, "kata_operation_token": "6" * 64,
                "kata_ledger_key": builder._key_body(leased.active.writer.stable_key),
                "kata_release_sequence": 1, "kata_release_offset": 1, "kata_release_sha256": "7" * 64,
            }
            proposal = ledger_module.LedgerProposal.create("release-authorized", body)
            raw = ledger_module._encode_proposal(proposal, leased.active.writer.settled)
            record = ledger_module.LedgerRecord(
                leased.active.writer.settled.sequence + 1, leased.active.writer.settled.sequence,
                leased.active.writer.settled.offset, leased.active.writer.settled.line_sha256,
                leased.active.writer.settled.offset + len(raw), "release-authorized", proposal.body,
                hashlib.sha256(raw).hexdigest(),
            )
            history = ledger_module._advance_history(leased.active.records, record)
            written = ledger_module._append_release_authorized_record(
                leased.active.writer, body["token"], leased.operation_name,
                ledger_module.SettledBytes(terminal.sequence, terminal.next_offset, terminal.line_sha256),
                body["kata_operation_token"], leased.active.writer.stable_key,
                ledger_module.SettledBytes(1, 1, "7" * 64), control,
            )
            node = fs.HeldNode(leased.active.node.identity_fd, leased.active.node.operation_fd, written.generation)
            writer = ledger_module.LedgerWriterState(node, written.stable_key, written.settled, written.generation)
            active = builder.ActiveLedger(node, history, writer)
            return builder.OwnedOperation(leased.locked, active, leased.operation, leased.root, leased.operation_name), active

        def operation_result(token_number, origin):
            if origin == "prelease":
                owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
                return materializer._materialize(fault_authority, owned, control)
            released, active = released_owner(token_number)
            return SimpleNamespace(owned=released, active=active)

        def invoke_cleanup(result, origin, passed):
            if origin == "prelease":
                return builder._cleanup_owned(result.owned, result.active, passed)
            session = builder._open_cleanup_session(
                result.active, result.owned.locked, result.owned.operation, "release-authorized", passed,
            )
            fs._close_node(result.owned.root)
            return builder._cleanup_active(session, passed)

        scalar_cases = (
            # Regular-file namespace proof and barrier seams.
            ("regular-child-identity", "regular", "rootfs/a/file-002", "child-identity", False),
            ("regular-unlink-before", "regular", "rootfs/a/file-002", "remove-before", False),
            ("regular-unlink-after", "regular", "rootfs/a/file-002", "remove-after", False),
            ("regular-parent-fsync-before", "regular", "rootfs/a/file-002", "parent-fsync-before", False),
            ("regular-parent-fsync-after", "regular", "rootfs/a/file-002", "parent-fsync-after", False),
            ("regular-post-snapshot", "regular", "rootfs/a/file-002", "post-snapshot", False),
            ("regular-post-delta", "regular", "rootfs/a/file-002", "post-delta", False),
            ("regular-post-absence", "regular", "rootfs/a/file-002", "post-absence", False),
            ("regular-parent-close", "regular", "rootfs/a/file-002", "parent-close", False),
            # Empty-directory-specific seams; hostile shapes preserve.
            ("directory-child-identity", "directory", "rootfs/a", "child-identity", False),
            ("directory-rmdir-before", "directory", "rootfs/a", "remove-before", False),
            ("directory-rmdir-after", "directory", "rootfs/a", "remove-after", False),
            ("directory-parent-fsync-before", "directory", "rootfs/a", "parent-fsync-before", False),
            ("directory-parent-fsync-after", "directory", "rootfs/a", "parent-fsync-after", False),
            ("directory-post-snapshot", "directory", "rootfs/a", "post-snapshot", False),
            ("directory-post-delta", "directory", "rootfs/a", "post-delta", False),
            ("directory-child-absence", "directory", "rootfs/a", "post-absence", False),
            ("directory-parent-close", "directory", "rootfs/a", "parent-close", False),
            ("directory-nonempty", "directory", "rootfs/a", "directory-nonempty", True),
            ("directory-replacement", "directory", "rootfs/a", "directory-replacement", True),
        )

        scalar_matrix = tuple((origin,) + case for origin in ("prelease", "release-authorized") for case in scalar_cases)
        for token_number, (origin, seam, scalar, selected_path, event, preserve) in enumerate(scalar_matrix, 1000):
            seam = origin + "-" + seam
            result = operation_result(token_number, origin)
            gate = {"armed": False, "tripped": False, "selector_hits": 0,
                    "session": None, "parent": None, "name": None, "parent_fsync": 0,
                    "snapshots": 0, "mutations": 0, "before_owner": None, "counter": None,
                    "at_fault": None, "hostile": False, "selected_node": None}
            originals = {
                "append": builder._session_append, "session_parent": builder._session_parent,
                "observe_child": fs._observe_child, "unlink": builder.os.unlink, "rmdir": builder.os.rmdir,
                "fsync": builder._fsync, "snapshot": builder._parent_snapshot,
                "parent_value": builder._parent_value, "enumerate": fs._enumerate_stable,
                "revalidate": fs._revalidate_chain,
                "close": builder._close, "open_session": builder._open_cleanup_session,
                "open_path": fs._open_path_node,
            }

            def trip():
                gate["selector_hits"] += 1
                assert gate["selector_hits"] == 1
                if not gate["tripped"]:
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)

            def open_session(*args):
                session = originals["open_session"](*args)
                if gate["session"] is None:
                    gate["session"] = session
                return session

            def session_parent(session, path, expected, passed):
                value = originals["session_parent"](session, path, expected, passed)
                if path == selected_path:
                    gate.update(parent=value[0], name=value[2])
                return value

            def append(session, record_type, body, passed):
                if record_type == "remove-intent" and body.get("path") == selected_path:
                    gate["armed"] = True
                    gate["counter"] = fs.structural_counter_snapshot()
                return originals["append"](session, record_type, body, passed)

            def observe_child(parent, name, passed):
                exact = gate["armed"] and gate["parent"] is parent and gate["name"] == name
                if exact and event == "child-identity":
                    trip()
                if exact and event == "directory-replacement" and not gate["hostile"]:
                    os.rename(name.raw, b"hostile-original", src_dir_fd=parent.operation_fd.number,
                              dst_dir_fd=parent.operation_fd.number)
                    os.mkdir(name.raw, 0o755, dir_fd=parent.operation_fd.number)
                    gate["hostile"] = True
                    gate["before_owner"] = inventory()
                    gate["selector_hits"] = 1
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    try:
                        return originals["observe_child"](parent, name, passed)
                    except BaseException:
                        gate["tripped"] = True
                        gate["at_fault"] = gate["mutations"]
                        raise
                return originals["observe_child"](parent, name, passed)

            def open_path(parent, name, kind, passed):
                node = originals["open_path"](parent, name, kind, passed)
                if (gate["armed"] and event == "directory-nonempty" and gate["parent"] is parent and
                        gate["name"] == name and not gate["hostile"]):
                    os.mkdir(b"hostile-child", 0o700, dir_fd=node.operation_fd.number)
                    gate["hostile"] = True
                    gate["selected_node"] = node
                    gate["before_owner"] = inventory()
                return node

            def namespace(function, parent, name, *args, **kwargs):
                exact = (gate["armed"] and gate["parent"] is not None and
                         kwargs.get("dir_fd") == gate["parent"].operation_fd.number and
                         name == gate["name"].raw)
                if exact and event == "remove-before":
                    trip()
                try:
                    value = function(name, *args, **kwargs)
                except BaseException:
                    if exact and event in {"directory-nonempty", "directory-replacement"}:
                        gate["tripped"] = True
                        gate["at_fault"] = gate["mutations"]
                    raise
                if exact:
                    gate["mutations"] += 1
                    if event == "remove-after":
                        trip()
                return value

            def fsync_checked(descriptor, passed):
                exact = gate["parent"] is not None and descriptor is gate["parent"].operation_fd
                if exact and gate["armed"]:
                    gate["parent_fsync"] += 1
                    if event == "parent-fsync-before":
                        trip()
                value = originals["fsync"](descriptor, passed)
                if exact and gate["armed"] and event == "parent-fsync-after":
                    trip()
                return value

            def snapshot(parent, passed):
                exact = gate["parent"] is parent and gate["armed"]
                value = originals["snapshot"](parent, passed)
                if exact:
                    gate["snapshots"] += 1
                    if event == "post-snapshot" and gate["snapshots"] == 1:
                        trip()
                return value

            def parent_value(snapshot_value):
                value = originals["parent_value"](snapshot_value)
                if event == "post-absence" and gate["armed"] and gate["mutations"] and not gate["tripped"]:
                    trip()
                return value

            def enumerate_stable(parent, passed):
                if event == "directory-nonempty" and parent is gate["selected_node"]:
                    try:
                        return originals["enumerate"](parent, passed)
                    finally:
                        gate["selector_hits"] = 1
                        gate["tripped"] = True
                        gate["at_fault"] = gate["mutations"]
                return originals["enumerate"](parent, passed)

            def revalidate(chain_value, passed, delta=None):
                exact = False
                if gate["armed"] and gate["parent"] is not None:
                    try:
                        exact = chain_value.components[-1].node.generation.key == gate["parent"].generation.key
                    except (AttributeError, IndexError):
                        pass
                value = originals["revalidate"](chain_value, passed, delta)
                if exact and event == "post-delta" and delta is not None:
                    trip()
                return value

            def close_node(node, primary=None):
                exact = gate["parent"] is node and gate["armed"]
                value = originals["close"](node, primary)
                if exact and event == "parent-close":
                    trip()
                return value

            builder._session_append = append
            builder._session_parent = session_parent
            fs._observe_child = observe_child
            fs._open_path_node = open_path
            builder.os.unlink = lambda name, *args, **kwargs: namespace(originals["unlink"], gate["parent"], name, *args, **kwargs)
            builder.os.rmdir = lambda name, *args, **kwargs: namespace(originals["rmdir"], gate["parent"], name, *args, **kwargs)
            builder._fsync = fsync_checked
            builder._parent_snapshot = snapshot
            builder._parent_value = parent_value
            fs._enumerate_stable = enumerate_stable
            fs._revalidate_chain = revalidate
            builder._close = close_node
            builder._open_cleanup_session = open_session
            try:
                try:
                    invoke_cleanup(result, origin, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "fault not observed", gate))
                assert gate["tripped"] and gate["selector_hits"] == 1
                assert gate["session"] is not None and gate["session"].disposition == "invalid", (seam, gate)
                assert gate["session"].origin == origin
                count = gate["mutations"]
                try:
                    builder._cleanup_active(gate["session"], control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "poisoned session reused"))
                assert gate["mutations"] == count == gate["at_fault"]
                interval = fs.structural_counter_delta(gate["counter"], fs.structural_counter_snapshot())
                assert interval["complete_walks"] == interval["complete_legal_folds"] == 0
            finally:
                builder._session_append = originals["append"]
                builder._session_parent = originals["session_parent"]
                fs._observe_child = originals["observe_child"]
                fs._open_path_node = originals["open_path"]
                builder.os.unlink, builder.os.rmdir = originals["unlink"], originals["rmdir"]
                builder._fsync = originals["fsync"]
                builder._parent_snapshot = originals["snapshot"]
                builder._parent_value = originals["parent_value"]
                fs._enumerate_stable = originals["enumerate"]
                fs._revalidate_chain = originals["revalidate"]
                builder._close = originals["close"]
                builder._open_cleanup_session = originals["open_session"]
            after_fault = inventory()
            close_failed(result)
            fresh_process_recovery(preserve)
            if preserve:
                assert gate["before_owner"] is not None and gate["before_owner"] == after_fault
                assert inventory() == after_fault
                reset_workspace()

        hardlink_cases = (
            "pre-intent-alias-chain", "pre-intent-target-chain",
            "post-intent-alias-chain", "post-intent-target-chain",
            "hardlink-unlink-before", "hardlink-unlink-after",
            "refreshed-target-count", "target-fsync-before", "target-fsync-after",
            "alias-parent-fsync-before", "alias-parent-fsync-after", "post-parent-delta",
            "target-before-observed", "target-before-settled", "target-after-settled",
            "alias-close", "target-close",
        )
        alias_path, target_path = "rootfs/b/zz-alias-two", "rootfs/a/000-target"
        hardlink_matrix = tuple((origin, case) for origin in ("prelease", "release-authorized") for case in hardlink_cases)
        for token_number, (origin, fault) in enumerate(hardlink_matrix, 1100):
            seam = origin + "-" + fault
            result = operation_result(token_number, origin)
            gate = {"armed": False, "tripped": False, "selector_hits": 0, "phase": "pre-intent",
                    "session": None, "alias_parent": None,
                    "alias_name": None, "target_parent": None, "target_name": None,
                    "alias_node": None, "target_node": None, "mutations": 0, "at_fault": None,
                    "child_checks": {"alias": 0, "target": 0}, "counter": None}
            originals = {
                "append": builder._session_append, "session_parent": builder._session_parent,
                "open_parent": builder._open_relative_parent, "open_path": fs._open_path_node,
                "revalidate": fs._revalidate_chain, "unlink": builder.os.unlink,
                "fsync": builder._fsync, "change": ledger_module._hardlink_generation_change,
                "close": builder._close, "open_session": builder._open_cleanup_session,
            }

            def trip():
                gate["selector_hits"] += 1
                assert gate["selector_hits"] == 1
                if not gate["tripped"]:
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)

            def open_session(*args):
                session = originals["open_session"](*args)
                if gate["session"] is None:
                    gate["session"] = session
                    gate["counter"] = fs.structural_counter_snapshot()
                return session

            def session_parent(session, path, expected, passed):
                value = originals["session_parent"](session, path, expected, passed)
                if path == alias_path:
                    gate.update(alias_parent=value[0], alias_name=value[2])
                return value

            def open_parent(operation, path, passed):
                value = originals["open_parent"](operation, path, passed)
                if path == target_path:
                    gate.update(target_parent=value[0], target_name=value[2])
                return value

            def open_path(parent, name, kind, passed):
                node = originals["open_path"](parent, name, kind, passed)
                if parent is gate["target_parent"] and name == gate["target_name"]:
                    gate["target_node"] = node
                if parent is gate["alias_parent"] and name == gate["alias_name"]:
                    gate["alias_node"] = node
                return node

            def append(session, record_type, body, passed):
                value = originals["append"](session, record_type, body, passed)
                if body.get("path") == alias_path:
                    if record_type == "remove-intent":
                        gate["armed"] = True
                        gate["phase"] = "post-intent"
                    elif record_type == "remove-observed":
                        gate["phase"] = "post-observed"
                    elif record_type == "remove-settled":
                        gate["phase"] = "post-settled"
                return value

            def chain_kind(chain_value):
                try:
                    name = chain_value.components[-1].name.text
                except (AttributeError, IndexError):
                    return None
                if gate["alias_name"] is not None and name == gate["alias_name"].text:
                    return "alias"
                if gate["target_name"] is not None and name == gate["target_name"].text:
                    return "target"
                return None

            def revalidate(chain_value, passed, delta=None):
                kind = chain_kind(chain_value)
                if kind is not None:
                    gate["child_checks"][kind] += 1
                    occurrence = gate["child_checks"][kind]
                    wanted = {
                        "pre-intent-alias-chain": ("alias", 1, "pre-intent"),
                        "pre-intent-target-chain": ("target", 1, "pre-intent"),
                        "post-intent-alias-chain": ("alias", 3, "post-intent"),
                        "post-intent-target-chain": ("target", 3, "post-intent"),
                        "target-before-observed": ("target", 4, "post-unlink"),
                        "target-before-settled": ("target", 6, "post-observed"),
                        "target-after-settled": ("target", 7, "post-settled"),
                    }.get(fault)
                    if wanted == (kind, occurrence, gate["phase"]):
                        trip()
                value = originals["revalidate"](chain_value, passed, delta)
                if fault == "post-parent-delta" and delta is not None:
                    if getattr(getattr(delta, "name", None), "text", None) == gate["alias_name"].text:
                        trip()
                return value

            def unlink(name, *args, **kwargs):
                exact = (gate["alias_parent"] is not None and name == gate["alias_name"].raw and
                         kwargs.get("dir_fd") == gate["alias_parent"].operation_fd.number)
                if exact and fault == "hardlink-unlink-before":
                    trip()
                value = originals["unlink"](name, *args, **kwargs)
                if exact:
                    gate["mutations"] += 1
                    gate["phase"] = "post-unlink"
                    if fault == "hardlink-unlink-after":
                        trip()
                return value

            def generation_change(*args):
                if fault == "refreshed-target-count" and gate["armed"] and gate["mutations"]:
                    trip()
                return originals["change"](*args)

            def fsync_checked(descriptor, passed):
                target_fd = None if gate["target_node"] is None else gate["target_node"].operation_fd
                parent_fd = None if gate["alias_parent"] is None else gate["alias_parent"].operation_fd
                label = "target" if descriptor is target_fd else "alias-parent" if descriptor is parent_fd else None
                if label is not None and fault == f"{label}-fsync-before":
                    trip()
                value = originals["fsync"](descriptor, passed)
                if label is not None and fault == f"{label}-fsync-after":
                    trip()
                return value

            def close_node(node, primary=None):
                value = originals["close"](node, primary)
                if fault == "alias-close" and node is gate["alias_node"]:
                    trip()
                if fault == "target-close" and node is gate["target_node"]:
                    trip()
                return value

            builder._session_append = append
            builder._session_parent = session_parent
            builder._open_relative_parent = open_parent
            fs._open_path_node = open_path
            fs._revalidate_chain = revalidate
            builder.os.unlink = unlink
            builder._fsync = fsync_checked
            ledger_module._hardlink_generation_change = generation_change
            builder._close = close_node
            builder._open_cleanup_session = open_session
            try:
                try:
                    invoke_cleanup(result, origin, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "fault not observed", gate))
                assert gate["tripped"] and gate["selector_hits"] == 1
                assert gate["session"] is not None and gate["session"].disposition == "invalid", (seam, gate)
                assert gate["session"].origin == origin
                count = gate["mutations"]
                try:
                    builder._cleanup_active(gate["session"], control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "poisoned session reused"))
                assert gate["mutations"] == count == gate["at_fault"]
                interval = fs.structural_counter_delta(gate["counter"], fs.structural_counter_snapshot())
                assert interval["complete_walks"] == interval["complete_legal_folds"] == 0
            finally:
                builder._session_append = originals["append"]
                builder._session_parent = originals["session_parent"]
                builder._open_relative_parent = originals["open_parent"]
                fs._open_path_node = originals["open_path"]
                fs._revalidate_chain = originals["revalidate"]
                builder.os.unlink = originals["unlink"]
                builder._fsync = originals["fsync"]
                ledger_module._hardlink_generation_change = originals["change"]
                builder._close = originals["close"]
                builder._open_cleanup_session = originals["open_session"]
            close_failed(result)
            fresh_process_recovery()

        # A successful first alias settlement must publish one exact refreshed
        # generation to the target and every remaining alias in the session model.
        owned = builder._begin_operation(chain, approval, f"{299:064x}", control)
        result = materializer._materialize(fault_authority, owned, control)
        session = builder._open_cleanup_session(result.active, result.owned.locked, result.owned.operation, "prelease", control)
        fs._close_node(result.owned.root)
        builder._finish_hardlink_remove(session, alias_path, target_path, session.owned[target_path], control)
        refreshed = session.owned[target_path]
        assert session.owned["rootfs/a/zz-alias-one"] == refreshed
        assert session.groups[target_path] == ["rootfs/a/zz-alias-one"]
        builder._cleanup_active(session, control)
        builder._release_lock(result.owned.locked)
        fs._close_node(result.owned.locked.state)

        def absent_session(token_number, hardlink, origin):
            result = operation_result(token_number, origin)
            session = builder._open_cleanup_session(result.active, result.owned.locked, result.owned.operation, origin, control)
            fs._close_node(result.owned.root)
            selected = alias_path if hardlink else "rootfs/a/file-001"
            real_append = builder._session_append

            def stop_before_observed(current, record_type, body, passed):
                if record_type == "remove-observed" and body.get("path") == selected:
                    raise OSError("prepare durable absent intent")
                return real_append(current, record_type, body, passed)

            builder._session_append = stop_before_observed
            try:
                if hardlink:
                    builder._finish_hardlink_remove(session, selected, target_path, session.owned[target_path], control)
                else:
                    builder._finish_remove(session, selected, session.owned[selected], False, control)
            except BaseException:
                pass
            else:
                raise AssertionError("absent fixture fault not observed")
            finally:
                builder._session_append = real_append
            assert session.disposition == "invalid"
            fresh = builder._open_cleanup_session(session.active, result.owned.locked, result.owned.operation, origin, control)
            expected = "hardlink-remove-absence-settleable" if hardlink else "remove-absence-settleable"
            assert fresh.status == expected and fresh.origin == origin
            assert fresh.active.records.legal.return_phase == ("active" if origin == "prelease" else "release-authorized")
            return result, fresh

        absent_cases = (
            (False, "parent-chain"), (False, "absence-listing"),
            (False, "parent-fsync-before"), (False, "parent-fsync-after"),
            (False, "observed-durable"), (False, "observed-suffix"), (False, "observed-binding"),
            (False, "settled-durable"), (False, "settled-suffix"), (False, "settled-binding"),
            (False, "parent-close"),
            (True, "target-generation"), (True, "target-chain"),
            (True, "target-fsync-before"), (True, "target-fsync-after"),
            (True, "parent-fsync-before"), (True, "parent-fsync-after"),
            (True, "observed-durable"), (True, "observed-suffix"), (True, "observed-binding"),
            (True, "settled-durable"), (True, "settled-suffix"), (True, "settled-binding"),
            (True, "parent-close"),
        )
        absent_matrix = tuple((origin,) + case for origin in ("prelease", "release-authorized") for case in absent_cases)
        for token_number, (origin, hardlink, event) in enumerate(absent_matrix, 1200):
            seam = origin + "-" + ("absent-hardlink-" if hardlink else "absent-regular-") + event
            result, session = absent_session(token_number, hardlink, origin)
            before_owner = inventory()
            intent = builder._terminal_record(session.active).body_value()
            selected = intent["path"]
            gate = {"tripped": False, "selector_hits": 0, "parent": None, "target": None,
                    "ledger_identity": session.active.node.identity_fd,
                    "ledger_operation": session.active.node.operation_fd, "mutations": 0,
                    "at_fault": None, "record": None, "counter": fs.structural_counter_snapshot()}
            originals = {
                "open_parent": builder._open_relative_parent, "open_path": fs._open_path_node,
                "revalidate": fs._revalidate_chain, "enumerate": fs._enumerate_stable,
                "fsync": builder._fsync, "change": ledger_module._hardlink_generation_change,
                "append": builder._session_append, "close": builder._close,
                "write": ledger_module.os.write, "pread": ledger_module.os.pread,
                "current": builder._current_ledger, "unlink": builder.os.unlink, "rmdir": builder.os.rmdir,
            }

            def trip():
                gate["selector_hits"] += 1
                assert gate["selector_hits"] == 1
                if not gate["tripped"]:
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)

            def open_parent(operation, path, passed):
                value = originals["open_parent"](operation, path, passed)
                if path == selected:
                    gate["parent"] = value[0]
                return value

            def open_path(parent, name, kind, passed):
                node = originals["open_path"](parent, name, kind, passed)
                if hardlink and name.text == target_path.rpartition("/")[2]:
                    gate["target"] = node
                return node

            def revalidate(chain_value, passed, delta=None):
                try:
                    final_name = chain_value.components[-1].name.text
                except (AttributeError, IndexError):
                    final_name = None
                if event == "parent-chain" and gate["parent"] is not None:
                    try:
                        exact = chain_value.components[-1].node.generation.key == gate["parent"].generation.key
                    except (AttributeError, IndexError):
                        exact = False
                    if exact:
                        trip()
                if event == "target-chain" and final_name == target_path.rpartition("/")[2]:
                    trip()
                return originals["revalidate"](chain_value, passed, delta)

            def enumerate_stable(parent, passed):
                if event == "absence-listing" and parent is gate["parent"]:
                    trip()
                return originals["enumerate"](parent, passed)

            def fsync_checked(descriptor, passed):
                target_fd = None if gate["target"] is None else gate["target"].operation_fd
                parent_fd = None if gate["parent"] is None else gate["parent"].operation_fd
                label = "target" if descriptor is target_fd else "parent" if descriptor is parent_fd else None
                if label is not None and event == f"{label}-fsync-before":
                    trip()
                value = originals["fsync"](descriptor, passed)
                if label is not None and event == f"{label}-fsync-after":
                    trip()
                return value

            def generation_change(*args):
                if event == "target-generation":
                    trip()
                return originals["change"](*args)

            def append(current, record_type, body, passed):
                if body.get("path") == selected:
                    gate["record"] = record_type
                    gate["wrote"] = False
                value = originals["append"](current, record_type, body, passed)
                if body.get("path") == selected:
                    if event == "observed-durable" and record_type == "remove-observed":
                        trip()
                    if event == "settled-durable" and record_type == "remove-settled":
                        trip()
                return value

            def write(fd, raw):
                value = originals["write"](fd, raw)
                if fd == session.active.node.operation_fd.number and gate["record"] in {"remove-observed", "remove-settled"}:
                    gate["wrote"] = True
                return value

            def pread(fd, size, offset):
                label = "observed" if gate["record"] == "remove-observed" else "settled" if gate["record"] == "remove-settled" else None
                if (fd == session.active.node.operation_fd.number and gate.get("wrote") and
                        event == f"{label}-suffix" and not gate["tripped"]):
                    trip()
                return originals["pread"](fd, size, offset)

            def current_ledger(*args):
                value = originals["current"](*args)
                exact = (args[0].node.identity_fd is gate["ledger_identity"] and
                         args[0].node.operation_fd is gate["ledger_operation"])
                label = "observed" if gate["record"] == "remove-observed" else "settled" if gate["record"] == "remove-settled" else None
                if exact and gate.get("wrote") and event == f"{label}-binding" and not gate["tripped"]:
                    trip()
                return value

            def close_node(node, primary=None):
                value = originals["close"](node, primary)
                if event == "parent-close" and node is gate["parent"]:
                    trip()
                return value

            def forbidden_mutation(function, *args, **kwargs):
                gate["mutations"] += 1
                return function(*args, **kwargs)

            builder._open_relative_parent = open_parent
            fs._open_path_node = open_path
            fs._revalidate_chain = revalidate
            fs._enumerate_stable = enumerate_stable
            builder._fsync = fsync_checked
            ledger_module._hardlink_generation_change = generation_change
            builder._session_append = append
            ledger_module.os.write = write
            ledger_module.os.pread = pread
            builder._current_ledger = current_ledger
            builder._close = close_node
            builder.os.unlink = lambda *args, **kwargs: forbidden_mutation(originals["unlink"], *args, **kwargs)
            builder.os.rmdir = lambda *args, **kwargs: forbidden_mutation(originals["rmdir"], *args, **kwargs)
            try:
                try:
                    builder._finish_absent_remove(session, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "fault not observed", gate))
                assert gate["tripped"] and gate["selector_hits"] == 1
                assert session.disposition == "invalid", (seam, gate)
                try:
                    builder._cleanup_active(session, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "poisoned session reused"))
                assert gate["mutations"] == 0 == gate["at_fault"]
                interval = fs.structural_counter_delta(gate["counter"], fs.structural_counter_snapshot())
                assert interval["complete_walks"] == interval["complete_legal_folds"] == 0
            finally:
                builder._open_relative_parent = originals["open_parent"]
                fs._open_path_node = originals["open_path"]
                fs._revalidate_chain = originals["revalidate"]
                fs._enumerate_stable = originals["enumerate"]
                builder._fsync = originals["fsync"]
                ledger_module._hardlink_generation_change = originals["change"]
                builder._session_append = originals["append"]
                ledger_module.os.write = originals["write"]
                ledger_module.os.pread = originals["pread"]
                builder._current_ledger = originals["current"]
                builder._close = originals["close"]
                builder.os.unlink, builder.os.rmdir = originals["unlink"], originals["rmdir"]
            assert inventory() != before_owner or event not in {"observed-durable", "settled-durable"}
            close_failed(result)
            fresh_process_recovery()

        retirement_cases = (
            ("retirement-operation-close", "operation-close"),
            ("retirement-rmdir-before", "operation-rmdir-before"),
            ("retirement-rmdir-after", "operation-rmdir-after"),
            ("retirement-state-fsync-before", "operation-state-fsync-before"),
            ("retirement-state-fsync-after", "operation-state-fsync-after"),
            ("retirement-post-state-delta", "operation-post-delta"),
        )
        finalization_cases = (
            ("finalization-ledger-close", "ledger-close"),
            ("finalization-ledger-unlink-before", "ledger-unlink-before"),
            ("finalization-ledger-unlink-after", "ledger-unlink-after"),
        )
        boundary_d_cases = (
            ("boundary-D-state-fsync-before", "final-state-fsync-before"),
            ("boundary-D-state-fsync-after", "final-state-fsync-after"),
            ("boundary-D-post-state-delta", "final-post-delta"),
            ("boundary-D-sentinel", "final-sentinel"),
            ("boundary-D-lock", "final-lock"),
            ("boundary-D-final-inventory", "final-inventory"),
            ("boundary-D-contradictory-inventory", "final-contradiction"),
        )
        lifecycle_cases = retirement_cases + finalization_cases + boundary_d_cases
        lifecycle_matrix = tuple((origin,) + case for origin in ("prelease", "release-authorized")
                                 for case in lifecycle_cases)
        for token_number, (origin, label, fault) in enumerate(lifecycle_matrix, 1300):
            seam = origin + "-" + label
            result = operation_result(token_number, origin)
            operation_key = result.owned.operation.generation.key
            state_fd = result.owned.locked.state.operation_fd.number
            operation_name = fs._name(result.owned.operation_name)
            gate = {"tripped": False, "selector_hits": 0, "sessions": [], "mutations": 0, "at_fault": None,
                    "retired": 0, "ledger_unlinks": 0, "contradiction": False, "before_owner": None}
            originals = {
                "open": builder._open_cleanup_session, "close": builder._close,
                "rmdir": builder.os.rmdir, "unlink": builder.os.unlink, "fsync": builder._fsync,
                "revalidate": fs._revalidate_chain, "append": builder._session_append,
                "verify": builder._verify_fixed_file, "observe_child": fs._observe_child,
                "enumerate": fs._enumerate_stable,
            }

            def trip():
                gate["selector_hits"] += 1
                assert gate["selector_hits"] == 1
                if not gate["tripped"]:
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)

            def open_session(*args):
                session = originals["open"](*args)
                gate["sessions"].append(session)
                return session

            def append(session, record_type, body, passed):
                if record_type == "retired":
                    gate["retired"] += 1
                return originals["append"](session, record_type, body, passed)

            def close_node(node, primary=None):
                is_operation = node.generation.key == operation_key
                is_ledger = node.generation.key == gate["sessions"][-1].active.node.generation.key if gate["sessions"] else False
                value = originals["close"](node, primary)
                if fault == "operation-close" and is_operation:
                    trip()
                if fault == "ledger-close" and is_ledger and any(session.status == "retired" for session in gate["sessions"]):
                    trip()
                return value

            def rmdir(name, *args, **kwargs):
                exact = name == operation_name.raw and kwargs.get("dir_fd") == state_fd
                if exact and fault == "operation-rmdir-before":
                    trip()
                value = originals["rmdir"](name, *args, **kwargs)
                if exact:
                    gate["mutations"] += 1
                    if fault == "operation-rmdir-after":
                        trip()
                return value

            def unlink(name, *args, **kwargs):
                exact = name == builder.LEDGER_NAME.raw and kwargs.get("dir_fd") == state_fd
                if exact and fault == "ledger-unlink-before":
                    trip()
                value = originals["unlink"](name, *args, **kwargs)
                if exact:
                    gate["mutations"] += 1
                    gate["ledger_unlinks"] += 1
                    if fault == "ledger-unlink-after":
                        trip()
                return value

            def fsync_checked(descriptor, passed):
                if descriptor is result.owned.locked.state.operation_fd:
                    operation_present = not gate["ledger_unlinks"] and not any(s.status == "retired" for s in gate["sessions"])
                    label = "operation" if operation_present else "final"
                    if fault == f"{label}-state-fsync-before":
                        trip()
                    value = originals["fsync"](descriptor, passed)
                    if fault == f"{label}-state-fsync-after":
                        trip()
                    return value
                return originals["fsync"](descriptor, passed)

            def revalidate(chain_value, passed, delta=None):
                value = originals["revalidate"](chain_value, passed, delta)
                if delta is not None:
                    name = getattr(getattr(delta, "name", None), "text", None)
                    if fault == "operation-post-delta" and name == operation_name.text:
                        trip()
                    if fault == "final-post-delta" and name == builder.LEDGER_NAME.text:
                        trip()
                return value

            def verify(*args):
                if fault == "final-sentinel" and gate["ledger_unlinks"]:
                    trip()
                return originals["verify"](*args)

            def observe_child(parent, name, passed):
                if fault == "final-lock" and gate["ledger_unlinks"] and name == builder.LOCK_NAME:
                    trip()
                return originals["observe_child"](parent, name, passed)

            def enumerate_stable(parent, passed):
                if gate["ledger_unlinks"] and parent.operation_fd.number == state_fd:
                    if fault == "final-contradiction" and not gate["contradiction"]:
                        descriptor = os.open(b"hostile-final", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                                             dir_fd=state_fd)
                        os.close(descriptor)
                        gate["before_owner"] = inventory()
                        gate["contradiction"] = True
                        gate["selector_hits"] = 1
                        gate["tripped"] = True
                        gate["at_fault"] = gate["mutations"]
                    if fault in {"final-inventory", "final-contradiction"}:
                        try:
                            value = originals["enumerate"](parent, passed)
                        except BaseException:
                            gate["tripped"] = True
                            gate["at_fault"] = gate["mutations"]
                            raise
                        if fault == "final-inventory":
                            trip()
                        return value
                return originals["enumerate"](parent, passed)

            builder._open_cleanup_session = open_session
            builder._close = close_node
            builder.os.rmdir, builder.os.unlink = rmdir, unlink
            builder._fsync = fsync_checked
            fs._revalidate_chain = revalidate
            builder._session_append = append
            builder._verify_fixed_file = verify
            fs._observe_child = observe_child
            fs._enumerate_stable = enumerate_stable
            try:
                try:
                    invoke_cleanup(result, origin, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "fault not observed"))
                invalid = [session for session in gate["sessions"] if session.disposition == "invalid"]
                assert gate["tripped"] and gate["selector_hits"] == 1 and invalid, (seam, gate)
                owner = invalid[-1]
                assert owner.origin == origin
                count = gate["mutations"]
                retired = gate["retired"]
                ledger_unlinks = gate["ledger_unlinks"]
                try:
                    builder._cleanup_active(owner, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "poisoned session reused"))
                assert (gate["mutations"], gate["retired"], gate["ledger_unlinks"]) == (count, retired, ledger_unlinks)
                assert gate["at_fault"] == count
                if fault.startswith("operation-"):
                    assert gate["retired"] == 0 and gate["ledger_unlinks"] == 0
            finally:
                builder._open_cleanup_session = originals["open"]
                builder._close = originals["close"]
                builder.os.rmdir, builder.os.unlink = originals["rmdir"], originals["unlink"]
                builder._fsync = originals["fsync"]
                fs._revalidate_chain = originals["revalidate"]
                builder._session_append = originals["append"]
                builder._verify_fixed_file = originals["verify"]
                fs._observe_child = originals["observe_child"]
                fs._enumerate_stable = originals["enumerate"]
            after_fault = inventory()
            close_failed(result)
            preserve = fault == "final-contradiction"
            fresh_process_recovery(preserve)
            if preserve:
                assert gate["before_owner"] is not None and gate["before_owner"] == after_fault
                assert inventory() == after_fault
                reset_workspace()

        boundary_cases = (
            *(("A", stage) for stage in ("parse", "walk", "reconcile", "binding")),
            *((boundary, stage) for boundary in ("B", "C")
              for stage in ("parse", "state-observation", "reconcile", "binding")),
        )
        boundary_matrix = tuple((origin,) + case for origin in ("prelease", "release-authorized") for case in boundary_cases)
        for token_number, (origin, boundary, stage) in enumerate(boundary_matrix, 1400):
            seam = f"{origin}-boundary-{boundary}-{stage}"
            result = operation_result(token_number, origin)
            gate = {"context": None, "tripped": False, "selector_hits": 0, "sessions": [], "mutations": 0, "at_fault": None}
            originals = {
                "open": builder._open_cleanup_session, "parse": ledger_module._parse_ledger_history,
                "walk": builder._walk_entries, "reconcile": ledger_module._reconcile_ledger,
                "binding": builder._session_binding, "revalidate": fs._revalidate_chain,
                "unlink": builder.os.unlink, "rmdir": builder.os.rmdir,
            }

            def classify(active, operation):
                record_type = active.records.terminal.record_type
                if operation is not None and record_type == "remove-settled":
                    return "A"
                if operation is None and record_type == "operation-absent":
                    return "B"
                if operation is None and record_type == "retired":
                    return "C"
                return None

            def open_session(active, locked, operation, origin, passed):
                gate["context"] = classify(active, operation)
                try:
                    session = originals["open"](active, locked, operation, origin, passed)
                finally:
                    gate["context"] = None
                gate["sessions"].append(session)
                return session

            def inject(label, function, *args):
                if gate["context"] == boundary and stage == label and not gate["tripped"]:
                    gate["selector_hits"] += 1
                    assert gate["selector_hits"] == 1
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                return function(*args)

            def completed_state_observation(*args):
                value = originals["revalidate"](*args)
                if (gate["context"] == boundary and boundary in {"B", "C"} and
                        stage == "state-observation" and not gate["tripped"]):
                    gate["selector_hits"] += 1
                    assert gate["selector_hits"] == 1
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                return value

            def mutation(function, *args, **kwargs):
                value = function(*args, **kwargs)
                gate["mutations"] += 1
                return value

            builder._open_cleanup_session = open_session
            ledger_module._parse_ledger_history = lambda *args: inject("parse", originals["parse"], *args)
            builder._walk_entries = lambda *args: inject("walk", originals["walk"], *args)
            fs._revalidate_chain = completed_state_observation
            ledger_module._reconcile_ledger = lambda *args: inject("reconcile", originals["reconcile"], *args)
            builder._session_binding = lambda *args: inject("binding", originals["binding"], *args)
            builder.os.unlink = lambda *args, **kwargs: mutation(originals["unlink"], *args, **kwargs)
            builder.os.rmdir = lambda *args, **kwargs: mutation(originals["rmdir"], *args, **kwargs)
            try:
                try:
                    invoke_cleanup(result, origin, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "fault not observed"))
                invalid = [session for session in gate["sessions"] if session.disposition == "invalid"]
                assert gate["tripped"] and gate["selector_hits"] == 1 and invalid, (seam, gate)
                owner = invalid[-1]
                assert owner.origin == origin
                count = gate["mutations"]
                try:
                    builder._cleanup_active(owner, control)
                except BaseException:
                    pass
                else:
                    raise AssertionError((seam, "poisoned session reused"))
                assert gate["mutations"] == count == gate["at_fault"]
            finally:
                builder._open_cleanup_session = originals["open"]
                ledger_module._parse_ledger_history = originals["parse"]
                builder._walk_entries = originals["walk"]
                fs._revalidate_chain = originals["revalidate"]
                ledger_module._reconcile_ledger = originals["reconcile"]
                builder._session_binding = originals["binding"]
                builder.os.unlink, builder.os.rmdir = originals["unlink"], originals["rmdir"]
            close_failed(result)
            counters = fresh_process_recovery()
            assert counters["complete_legal_folds"] >= 2
            if boundary == "A":
                assert counters["complete_walks"] >= 1

        regular_path = "rootfs/a/file-003"
        directory_path = "rootfs/a"
        append_family = (
            ("pre-write-lseek", False), ("write-error", False), ("partial-write", False),
            ("pre-fsync-control", False), ("ledger-fsync", False), ("ledger-fsync-after", False),
            ("post-write-identity", False), ("rollback-fsync-exact", False),
            ("rollback-readback", True), ("suffix-readback", False),
            ("post-readback-binding", False), ("selected-ledger-close", False),
            ("rollback-truncate", True),
        )
        append_targets = (
            ("regular", "remove-intent", regular_path),
            ("regular", "remove-observed", regular_path),
            ("regular", "remove-settled", regular_path),
            ("directory", "remove-intent", directory_path),
            ("directory", "remove-observed", directory_path),
            ("directory", "remove-settled", directory_path),
            ("hardlink", "remove-intent", alias_path),
            ("hardlink", "remove-observed", alias_path),
            ("hardlink", "remove-settled", alias_path),
            ("lifecycle", "operation-remove-intent", None),
            ("lifecycle", "operation-absent", None),
            ("lifecycle", "retired", None),
        )
        append_cases = tuple(
            (origin, scalar, record, path, seam, preserve)
            for origin in ("prelease", "release-authorized")
            for scalar, record, path in append_targets
            for seam, preserve in append_family
        )
        for offset, (origin, scalar, selected_record, selected_path, fault, preserve) in enumerate(append_cases, 1500):
            seam = f"{origin}-{scalar}-{selected_record}-{fault}"
            result = operation_result(offset, origin)
            before_owner = None
            gate = {"armed": False, "record": None, "ledger_fd": None,
                    "ledger_identity": None, "ledger_operation": None, "writes": 0, "wrote": False,
                    "rollback": False, "tripped": False, "fault_injected": False,
                    "selector_hits": 0, "rollback_fsync_hit": 0, "session": None, "mutations": 0, "preads": 0, "at_fault": None}
            originals = {
                "session_append": builder._session_append, "write": ledger_module.os.write,
                "fsync": ledger_module.os.fsync, "ftruncate": ledger_module.os.ftruncate,
                "pread": ledger_module.os.pread, "lseek": ledger_module.os.lseek,
                "observe": ledger_module._observe_node, "current_ledger": builder._current_ledger,
                "unlink": builder.os.unlink, "rmdir": builder.os.rmdir,
                "open_session": builder._open_cleanup_session,
            }
            sessions = []

            def open_session(*args):
                session = originals["open_session"](*args)
                sessions.append(session)
                return session

            def selected(record_type, body):
                return record_type == selected_record and (selected_path is None or body.get("path") == selected_path)

            def hit():
                gate["selector_hits"] += 1
                assert gate["selector_hits"] == 1

            def session_append(session, record_type, body, passed):
                nonlocal before_owner
                chosen = not gate["tripped"] and selected(record_type, body)
                if chosen:
                    if before_owner is None:
                        before_owner = inventory()
                    expected_return = "active" if origin == "prelease" else "release-authorized"
                    assert session.origin == origin
                    if scalar == "regular":
                        assert body["path"] == selected_path and body["kind"] == "infrastructure" and body["target_path"] is None
                    elif scalar == "directory":
                        assert body["path"] == selected_path and body["kind"] == "directory" and body["target_path"] is None
                    elif scalar == "hardlink":
                        assert body["path"] == selected_path and body["kind"] == "hardlink" and body["target_path"] == target_path
                    else:
                        assert body["token"] == builder._token(session.active) and "path" not in body
                    legal = session.active.records.legal
                    expected_before = {
                        "remove-intent": expected_return,
                        "remove-observed": "remove-intent",
                        "remove-settled": "remove-observed",
                        "operation-remove-intent": expected_return,
                        "operation-absent": "operation-remove",
                        "retired": "operation-absent",
                    }[record_type]
                    assert legal.phase == expected_before
                    assert legal.return_phase in {None, expected_return}
                    gate.update(armed=True, record=record_type,
                                ledger_fd=session.active.node.operation_fd.number,
                                ledger_identity=session.active.node.identity_fd,
                                ledger_operation=session.active.node.operation_fd, session=session)
                value = originals["session_append"](session, record_type, body, passed)
                if chosen and fault == "selected-ledger-close":
                    assert session.active.node.identity_fd is gate["ledger_identity"]
                    assert session.active.node.operation_fd is gate["ledger_operation"]
                    session.active.node.operation_fd.close()
                    session.active.node.identity_fd.close()
                    hit()
                    gate["tripped"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                return value

            def write(fd, raw):
                if not gate["armed"] or fd != gate["ledger_fd"]:
                    return originals["write"](fd, raw)
                gate["writes"] += 1
                if fault == "write-error" and gate["writes"] == 1:
                    hit()
                    gate["tripped"] = True; gate["at_fault"] = gate["mutations"]; raise OSError(seam)
                if fault in {"partial-write", "rollback-truncate", "rollback-fsync-exact", "rollback-readback"}:
                    if gate["writes"] == 1:
                        gate["wrote"] = True
                        return originals["write"](fd, raw[:max(1, len(raw) // 2)])
                    gate["rollback"] = True
                    if fault == "partial-write":
                        hit()
                    gate["tripped"] = True; gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                value = originals["write"](fd, raw)
                gate["wrote"] = True
                return value

            def fsync_fd(fd):
                if gate["armed"] and fd == gate["ledger_fd"]:
                    if not gate["rollback"] and fault == "pre-fsync-control" and not gate["fault_injected"]:
                        hit()
                        gate["fault_injected"] = True
                        gate["tripped"] = True
                        gate["at_fault"] = gate["mutations"]
                        raise OSError(seam)
                    if gate["rollback"] and fault == "rollback-fsync-exact":
                        value = originals["fsync"](fd)
                        gate["rollback_fsync_hit"] += 1
                        assert gate["rollback_fsync_hit"] == 1
                        hit()
                        gate["at_fault"] = gate["mutations"]
                        raise OSError(seam)
                    if not gate["rollback"] and fault == "ledger-fsync" and not gate["fault_injected"]:
                        hit()
                        gate["tripped"] = gate["fault_injected"] = True
                        gate["at_fault"] = gate["mutations"]
                        raise OSError(seam)
                    value = originals["fsync"](fd)
                    if not gate["rollback"] and fault == "ledger-fsync-after" and not gate["fault_injected"]:
                        hit()
                        gate["tripped"] = gate["fault_injected"] = True
                        gate["at_fault"] = gate["mutations"]
                        raise OSError(seam)
                    return value
                return originals["fsync"](fd)

            def ftruncate(fd, size):
                nonlocal before_owner
                if gate["rollback"] and fault == "rollback-truncate":
                    before_owner = inventory()
                    hit()
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                return originals["ftruncate"](fd, size)

            def pread(fd, size, offset):
                nonlocal before_owner
                if gate["armed"] and fd == gate["ledger_fd"]:
                    if gate["rollback"] and fault == "rollback-readback":
                        gate["preads"] += 1
                        if gate["preads"] == 1:
                            before_owner = inventory()
                            hit()
                            gate["at_fault"] = gate["mutations"]
                            raise OSError(seam)
                    if not gate["rollback"] and gate["wrote"] and fault == "suffix-readback":
                        hit()
                        gate["tripped"] = True; gate["at_fault"] = gate["mutations"]; raise OSError(seam)
                return originals["pread"](fd, size, offset)

            def lseek(fd, offset, whence):
                if gate["armed"] and fd == gate["ledger_fd"] and fault == "pre-write-lseek" and not gate["wrote"]:
                    hit()
                    gate["tripped"] = True; gate["at_fault"] = gate["mutations"]; raise OSError(seam)
                return originals["lseek"](fd, offset, whence)

            def observe(identity, operation, passed):
                if (gate["armed"] and identity is gate["ledger_identity"] and
                        operation is gate["ledger_operation"] and gate["wrote"] and not gate["rollback"] and
                        fault == "post-write-identity" and not gate["fault_injected"]):
                    hit()
                    gate["tripped"] = gate["fault_injected"] = True
                    gate["at_fault"] = gate["mutations"]
                    raise OSError(seam)
                return originals["observe"](identity, operation, passed)

            def current_ledger(*args):
                value = originals["current_ledger"](*args)
                exact = (gate["session"] is not None and args[0].node.identity_fd is gate["ledger_identity"] and
                         args[0].node.operation_fd is gate["ledger_operation"])
                if gate["armed"] and exact and gate["wrote"] and fault == "post-readback-binding" and not gate["tripped"]:
                    hit()
                    gate["tripped"] = True; gate["at_fault"] = gate["mutations"]; raise OSError(seam)
                return value

            def mutation(function, *args, **kwargs):
                value = function(*args, **kwargs)
                gate["mutations"] += 1
                return value

            ledger_module.os.write = write
            ledger_module.os.fsync = fsync_fd
            ledger_module.os.ftruncate = ftruncate
            ledger_module.os.pread = pread
            ledger_module.os.lseek = lseek
            ledger_module._observe_node = observe
            builder._current_ledger = current_ledger
            builder.os.unlink = lambda *args, **kwargs: mutation(originals["unlink"], *args, **kwargs)
            builder.os.rmdir = lambda *args, **kwargs: mutation(originals["rmdir"], *args, **kwargs)
            builder._session_append = session_append
            builder._open_cleanup_session = open_session
            fault_control = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: False)
            try:
                try:
                    invoke_cleanup(result, origin, fault_control)
                except BaseException as error:
                    gate["caught"] = (type(error).__name__, str(error))
                else:
                    raise AssertionError((seam, selected_record, "fault not observed"))
                invalid = [session for session in sessions if session.disposition == "invalid"]
                if gate["session"] is not None and gate["session"].disposition == "invalid":
                    invalid.append(gate["session"])
                assert gate["tripped"] and gate["selector_hits"] == 1, (seam, gate)
                assert gate["rollback_fsync_hit"] == (1 if fault == "rollback-fsync-exact" else 0)
                assert gate["session"] is not None and invalid, (seam, selected_record, gate)
                owner = invalid[-1]
                assert owner.origin == origin
                mutation_count = gate["mutations"]
                try:
                    builder._cleanup_active(owner, fault_control)
                except BaseException:
                    pass
                else:
                    raise AssertionError("poisoned session reused")
                assert gate["mutations"] == mutation_count == gate["at_fault"]
            finally:
                builder._session_append = originals["session_append"]
                builder._open_cleanup_session = originals["open_session"]
                builder.os.unlink = originals["unlink"]
                builder.os.rmdir = originals["rmdir"]
                ledger_module.os.write = originals["write"]
                ledger_module.os.fsync = originals["fsync"]
                ledger_module.os.ftruncate = originals["ftruncate"]
                ledger_module.os.pread = originals["pread"]
                ledger_module.os.lseek = originals["lseek"]
                ledger_module._observe_node = originals["observe"]
                builder._current_ledger = originals["current_ledger"]
            after_fault = inventory()
            if preserve:
                assert before_owner is not None and before_owner == after_fault
            for node in (result.owned.root, result.owned.operation, result.active.node):
                if node.identity_fd.disposition == "open":
                    fs._close_node(node)
            if result.owned.locked.lock.identity_fd.disposition == "open":
                builder._release_lock(result.owned.locked)
            if result.owned.locked.state.identity_fd.disposition == "open":
                fs._close_node(result.owned.locked.state)
            fresh_process_recovery(preserve)
            if preserve:
                reset_workspace()

        # Hostile generation preservation uses an independent disposable state tree.
        reset_workspace()
        seam = "hardlink-post-intent-target-drift"
        owned = builder._begin_operation(chain, approval, f"{500:064x}", control)
        result = materializer._materialize(fault_authority, owned, control)
        real_append = builder._session_append
        real_revalidate = builder.fs._revalidate_chain
        real_unlink, real_rmdir = builder.os.unlink, builder.os.rmdir
        gate = {"armed": False, "drifted": False, "session": None, "mutations": 0, "before_owner": None}

        def arm_drift(session, record_type, body, passed):
            value = real_append(session, record_type, body, passed)
            if record_type == "remove-intent" and body.get("path") == "rootfs/b/zz-alias-two":
                gate.update(armed=True, session=session)
            return value

        def drift_then_revalidate(*args):
            if gate["armed"] and not gate["drifted"]:
                os.utime("rootfs/a/zz-alias-one", ns=(1_000_000_000, 1_000_000_000),
                         dir_fd=result.owned.operation.operation_fd.number, follow_symlinks=False)
                gate["drifted"] = True
                gate["before_owner"] = inventory()
            return real_revalidate(*args)

        def count_mutation(function, *args, **kwargs):
            value = function(*args, **kwargs)
            gate["mutations"] += 1
            return value

        builder._session_append = arm_drift
        builder.fs._revalidate_chain = drift_then_revalidate
        builder.os.unlink = lambda *args, **kwargs: count_mutation(real_unlink, *args, **kwargs)
        builder.os.rmdir = lambda *args, **kwargs: count_mutation(real_rmdir, *args, **kwargs)
        try:
            try:
                builder._cleanup_owned(result.owned, result.active, control)
            except BaseException:
                pass
            else:
                raise AssertionError((seam, "fault not observed"))
            assert gate["drifted"] and gate["mutations"] == 0 and gate["session"].disposition == "invalid"
            try:
                builder._cleanup_active(gate["session"], control)
            except BaseException:
                pass
            else:
                raise AssertionError("poisoned session reused")
            assert gate["mutations"] == 0
        finally:
            builder._session_append = real_append
            builder.fs._revalidate_chain = real_revalidate
            builder.os.unlink, builder.os.rmdir = real_unlink, real_rmdir
        assert gate["before_owner"] is not None and gate["before_owner"] == inventory()
        for node in (result.owned.root, result.owned.operation, result.active.node):
            if node.identity_fd.disposition == "open":
                fs._close_node(node)
        if result.owned.locked.lock.identity_fd.disposition == "open":
            builder._release_lock(result.owned.locked)
        if result.owned.locked.state.identity_fd.disposition == "open":
            fs._close_node(result.owned.locked.state)
        assert gate["before_owner"] == inventory()
        fresh_process_recovery(True)

        # Boundary-A operation-generation hostility uses its own disposable
        # state tree, independent from the hardlink preservation case.
        fs._close_chain(chain)
        shutil.rmtree(state_path)
        chain = builder._open_base_chain(control)
        state = builder._bootstrap(chain, approval, control)
        fs._close_node(state)
        fs._close_chain(chain)
        chain = builder._open_base_chain(control)
        seam = "operation-child-drift"
        owned = builder._begin_operation(chain, approval, f"{501:064x}", control)
        result = materializer._materialize(fault_authority, owned, control)
        real_open = builder._open_cleanup_session
        real_append = builder._session_append
        real_unlink, real_rmdir = builder.os.unlink, builder.os.rmdir
        gate = {"drifted": False, "session": None, "operation_intents": 0,
                "mutations": 0, "at_fault": None, "before_owner": None}

        def drift_operation(*args):
            session = real_open(*args)
            if session.operation is not None and not session.owned and not gate["drifted"]:
                gate["at_fault"] = gate["mutations"]
                os.mkdir(b".hostile-generation", 0o700, dir_fd=session.operation.operation_fd.number)
                real_rmdir(b".hostile-generation", dir_fd=session.operation.operation_fd.number)
                gate.update(drifted=True, session=session, before_owner=inventory())
            return session

        def count_operation_intent(session, record_type, body, passed):
            if record_type == "operation-remove-intent":
                gate["operation_intents"] += 1
            return real_append(session, record_type, body, passed)

        def count_namespace(function, *args, **kwargs):
            value = function(*args, **kwargs)
            gate["mutations"] += 1
            return value

        builder._open_cleanup_session = drift_operation
        builder._session_append = count_operation_intent
        builder.os.unlink = lambda *args, **kwargs: count_namespace(real_unlink, *args, **kwargs)
        builder.os.rmdir = lambda *args, **kwargs: count_namespace(real_rmdir, *args, **kwargs)
        try:
            try:
                builder._cleanup_owned(result.owned, result.active, control)
            except BaseException:
                pass
            else:
                raise AssertionError((seam, "fault not observed"))
            assert gate["drifted"] and gate["operation_intents"] == 0
            assert gate["mutations"] == gate["at_fault"]
            assert gate["session"].disposition == "invalid"
            try:
                builder._cleanup_active(gate["session"], control)
            except BaseException:
                pass
            else:
                raise AssertionError("poisoned session reused")
            assert gate["operation_intents"] == 0 and gate["mutations"] == gate["at_fault"]
        finally:
            builder._open_cleanup_session = real_open
            builder._session_append = real_append
            builder.os.unlink, builder.os.rmdir = real_unlink, real_rmdir
        assert gate["before_owner"] is not None and gate["before_owner"] == inventory()
        for node in (result.owned.root, result.owned.operation, result.active.node):
            if node.identity_fd.disposition == "open":
                fs._close_node(node)
        if result.owned.locked.lock.identity_fd.disposition == "open":
            builder._release_lock(result.owned.locked)
        if result.owned.locked.state.identity_fd.disposition == "open":
            fs._close_node(result.owned.locked.state)
        assert gate["before_owner"] == inventory()
        fresh_process_recovery(True)

    if os.environ.get("COGS_D3_ONLY") == "1":
        d3_cleanup_fault_matrix()
        artifact = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache/immutable.bin"
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest
        fs._close_chain(chain)
        print("completion rootfs D3 Linux fault matrix passed")
        return

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

    def retained_inventory():
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

    def fault_after_named_create(token_number, seam):
        nonlocal chain
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
        idle = sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
        if seam == "symlink-open":
            preserved = retained_inventory()
            builder._release_lock(owned.locked)
            fs._close_node(owned.locked.state)
            rejected = False
            try:
                builder._recover_fixed(builder._fresh_recovery_control())
            except BaseException:
                rejected = True
            assert rejected and preserved == retained_inventory()
            fs._close_chain(chain)
            shutil.rmtree(state_path)
            chain = builder._open_base_chain(control)
            state = builder._bootstrap(chain, approval, control)
            fs._close_node(state)
            fs._close_chain(chain)
            chain = builder._open_base_chain(control)
            assert sorted(path.name for path in state_path.iterdir()) == idle
        else:
            assert observed_state == idle, (seam, observed_state)

    for index, seam in enumerate(("directory-open", "file-xattr", "hardlink-observe", "symlink-open"), 130):
        fault_after_named_create(index, seam)

    def interrupt_inside_metadata(token_number, target_path, syscall_name, raise_after):
        nonlocal chain
        owned = builder._begin_operation(chain, approval, f"{token_number:064x}", control)
        latch = {"cancelled": False}
        current = {"path": None}
        tripped = {"value": False}
        interrupted = fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: latch["cancelled"])
        real_metadata = materializer._metadata
        original = getattr(materializer.os, syscall_name)

        def tracked_metadata(active, node, path, record, parent, current_control, node_chain, symlink_name=None):
            current["path"] = path
            try:
                return real_metadata(active, node, path, record, parent, current_control, node_chain, symlink_name)
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
        failure = None
        try:
            materializer._materialize(authority, owned, interrupted)
        except BaseException as caught:
            failure = caught
        else:
            raise AssertionError("metadata interruption was not observed")
        finally:
            materializer._metadata = real_metadata
            setattr(materializer.os, syscall_name, original)
        assert latch["cancelled"] or raise_after, (target_path, syscall_name, repr(failure), repr(failure.__cause__))
        observed_state = sorted(path.name for path in state_path.iterdir())
        idle = sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
        if raise_after:
            preserved = retained_inventory()
            builder._release_lock(owned.locked)
            fs._close_node(owned.locked.state)
            try:
                builder._recover_fixed(builder._fresh_recovery_control())
            except BaseException:
                pass
            else:
                raise AssertionError("uncertain metadata syscall was adopted")
            assert preserved == retained_inventory()
            fs._close_chain(chain)
            shutil.rmtree(state_path)
            chain = builder._open_base_chain(control)
            state = builder._bootstrap(chain, approval, control)
            fs._close_node(state)
            fs._close_chain(chain)
            chain = builder._open_base_chain(control)
        else:
            assert observed_state == idle, (target_path, syscall_name, raise_after, observed_state)

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

    d3_cleanup_fault_matrix()

    artifact = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache/immutable.bin"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == artifact_digest
    fs._close_chain(chain)
    print("completion rootfs materializer Docker functional test passed")


def recover_only():
    remote = FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(remote))
    fs = load("completion_rootfs_fs", remote / "completion_rootfs_fs.py")
    load("completion_rootfs_ledger", remote / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", remote / "completion_rootfs_builder.py")
    accommodate_docker_overlay(fs, builder)
    error = None
    try:
        builder._recover_fixed(builder._fresh_recovery_control())
    except BaseException as caught:
        error = caught
    counter_path = os.environ.get("COGS_D3_RECOVERY_COUNTERS")
    if counter_path is not None:
        Path(counter_path).write_text(json.dumps({"status": "rejected" if error else "recovered", **fs.structural_counter_snapshot()}))
    if error is not None:
        raise error


if len(sys.argv) == 2 and sys.argv[1] == "--linux":
    linux()
elif len(sys.argv) == 2 and sys.argv[1] == "--recover-only":
    recover_only()
else:
    portable()

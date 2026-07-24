#!/usr/bin/env python3
"""Portable strict-model and source tests for the private Stage A lease."""

import ast
from contextlib import contextmanager
import dataclasses
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

if sys.argv[1:] != ["--real"]:
    import completion_rootfs_build as build
    import completion_rootfs_builder as builder
    import completion_rootfs_canonical as canonical
    import completion_rootfs_fs as fs
    import completion_rootfs_ledger as ledger
    import completion_rootfs_lease as lease
    import completion_rootfs_materializer as materializer
    import completion_rootfs_plan as plan
    import completion_rootfs_publish as publication


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile lease case accepted")


def generation(inode, kind="directory", mode=0o700, nlink=2, size=0, ctime=1):
    return fs.HostGeneration(fs.HostKey(1, 1, inode, kind), mode, 0, 0, nlink, size, 1, ctime)


MATRIX_CASES = 0


def matrix_case(count=1):
    global MATRIX_CASES
    MATRIX_CASES += count


def checked(role):
    return fs.CheckedFd(os.open(os.devnull, os.O_RDONLY), role)


def held_node(inode, role, kind="directory", mode=0o700, nlink=2, size=0):
    return fs.HeldNode(checked(role + "-identity"), checked(role + "-operation"), generation(inode, kind, mode, nlink, size))


def close_if_open(node):
    if node is not None and any(value is not None and value.disposition == "open" for value in (node.operation_fd, node.identity_fd)):
        fs._close_node(node)


def close_graph_nodes(retained):
    owned = retained.owned
    for node in (owned.root, owned.operation, owned.active.node, owned.locked.lock, owned.locked.state):
        close_if_open(node)
    if any(component.node.identity_fd.disposition == "open" for component in retained.base_chain.components) or retained.base_chain.anchor.identity_fd.disposition == "open":
        fs._close_chain(retained.base_chain)


@contextmanager
def patched(*changes):
    originals = [(owner, name, getattr(owner, name)) for owner, name, _value in changes]
    try:
        for owner, name, value in changes:
            setattr(owner, name, value)
        yield
    finally:
        for owner, name, value in reversed(originals):
            setattr(owner, name, value)


def behavioral_fault_tests():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    for fault_stage in (1, 2, 3):
        matrix_case()

        def allocated_node():
            return SimpleNamespace(descriptors=(object(), object()))

        anchor = allocated_node()
        base = fs.HeldChain(anchor, ())
        opened = []
        closes = {}
        appends = {"count": 0}

        def open_node(_parent, _name, _kind, _control):
            node = allocated_node()
            opened.append(node)
            return node

        def append(chain, name, node):
            appends["count"] += 1
            if appends["count"] == fault_stage:
                raise MemoryError("transfer")
            return fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))

        def close_node(node):
            for descriptor in node.descriptors:
                closes[id(descriptor)] = closes.get(id(descriptor), 0) + 1

        def close_chain(chain):
            for node in tuple(component.node for component in chain.components) + (chain.anchor,):
                close_node(node)

        with patched(
            (builder, "_open_base_chain", lambda _control: base),
            (builder, "_completion", lambda chain: chain.anchor),
            (builder, "_append_component", append),
            (fs, "_open_path_node", open_node),
            (fs, "_close_node", close_node),
            (fs, "_close_chain", close_chain),
        ):
            rejected(lambda: lease._fresh_fixed_chain("operation-" + "a" * 64, control))
        assert len(opened) == fault_stage
        descriptors = tuple(descriptor for node in (anchor, *opened) for descriptor in node.descriptors)
        assert all(closes.get(id(descriptor)) == 1 for descriptor in descriptors)
        assert len(closes) == 2 * (fault_stage + 1)

    ledger_name = builder.LEDGER_NAME.text
    authorized = ledger.LedgerParent(generation(10), tuple(sorted((ledger_name, "lock"))))
    drifted = ledger.LedgerParent(dataclasses.replace(authorized.generation, ctime_ns=2), tuple(sorted((*authorized.names, "drift"))))
    hostile_after = ledger.LedgerParent(dataclasses.replace(authorized.generation, ctime_ns=3), ("drift", "lock"))
    active = SimpleNamespace(node=SimpleNamespace(identity_fd=object(), operation_fd=object()), records=())
    locked = SimpleNamespace(state=object())
    observations = SimpleNamespace(state_parent=authorized)
    transitions = []

    def run_unlink(parents):
        values = iter(parents)
        transitions.clear()
        with patched(
            (builder, "_fresh_cleanup_authority", lambda *_args: (object(), observations)),
            (builder.fs, "_observe_node", lambda *_args: generation(20, "file", 0o600, 1)),
            (builder, "_parent", lambda *_args: next(values)),
            (builder, "_close", lambda _node: transitions.append("close")),
            (builder, "_remove_name", lambda *_args: transitions.append("unlink")),
        ):
            rejected(lambda: builder._unlink_ledger(active, locked, "prelease", control))

    matrix_case(2)
    run_unlink((drifted,))
    assert transitions == []
    run_unlink((authorized, hostile_after))
    assert transitions == ["close", "unlink"]


def graph_fixture():
    token = "6" * 64
    operation_name = ledger._operation_name(token)
    anchor = held_node(100, "base-anchor")
    prefix = held_node(101, "base-prefix")
    base = fs.HeldChain(anchor, (fs.ChainComponent(fs._name("base"), prefix),))
    state = held_node(102, "state")
    lock = held_node(103, "lock", "file", 0o600, 1)
    operation = held_node(104, "operation")
    root = held_node(105, "root", mode=0o755)
    settled = ledger._settled_record(7, 11, "a" * 64)
    ledger_node = held_node(106, "ledger", "file", 0o600, 1, settled.offset)
    writer = ledger.LedgerWriterState(ledger_node, ledger_node.generation.key, settled, ledger_node.generation)
    terminal = SimpleNamespace(
        record_type="leased",
        body_value=lambda: {
            "token": token,
            "manifest_sha256": "b" * 64,
            "manifest_size": 17,
            "ustar_sha256": "c" * 64,
            "ustar_size": 512,
            "entry_count": 1,
        },
    )
    active = builder.ActiveLedger(ledger_node, (terminal,), writer)
    locked_chain = fs.HeldChain(anchor, base.components + (fs.ChainComponent(builder.STATE_NAME, state),))
    locked = builder.LockedState(locked_chain, state, lock)
    owned = builder.OwnedOperation(locked, active, operation, root, operation_name)
    retained = build.RetainedBuild(owned, base)
    retained.disposition = "transferred"
    state_parent = ledger.LedgerParent(
        state.generation,
        tuple(sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text, builder.LEDGER_NAME.text, operation_name))),
    )
    reference = lease.RuntimeRootfsReference(
        lease.FIXED_PREFIX + operation_name + "/rootfs", token, operation_name,
        ledger_node.generation.key, settled, state.generation, operation.generation, root.generation,
        "b" * 64, 17, "c" * 64, 512, 1,
    )
    return retained, reference, state_parent


def successful_behavior_tests():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)

    def probe_node(file_object, inode):
        identity = fs.CheckedFd(os.dup(file_object.fileno()), "probe-identity")
        operation = fs.CheckedFd(os.dup(file_object.fileno()), "probe-operation")
        return fs.HeldNode(identity, operation, generation(inode, "file", 0o600, 1))

    with tempfile.TemporaryFile() as file_object:
        matrix_case()
        probe = probe_node(file_object, 30)
        with patched(
            (builder, "_verify_fixed_file", lambda *_args: probe),
            (lease.fcntl, "flock", lambda *_args: (_ for _ in ()).throw(OSError(errno.EAGAIN, "held"))),
        ):
            lease._probe_lock(object(), probe.generation, (), control)
        assert probe.identity_fd.disposition == probe.operation_fd.disposition == "closed"

    token = "6" * 64
    operation_name = ledger._operation_name(token)
    state_parent = ledger.LedgerParent(generation(40), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text, operation_name))
    operation_generation = generation(41)
    root_generation = generation(42, mode=0o755)
    ledger_generation = generation(43, "file", 0o600, 1, 1)
    settled = ledger._settled_record(0, 1, "3" * 64)
    with tempfile.TemporaryFile() as file_object:
        node = fs.HeldNode(
            fs.CheckedFd(os.dup(file_object.fileno()), "mark-identity"),
            fs.CheckedFd(os.dup(file_object.fileno()), "mark-operation"),
            ledger_generation,
        )
        writer = ledger.LedgerWriterState(node, ledger_generation.key, settled, ledger_generation)
        active = builder.ActiveLedger(node, (SimpleNamespace(body_value=lambda: {"token": token}),), writer)
        locked = SimpleNamespace(state=object())
        operation = SimpleNamespace(identity_fd=object(), operation_fd=object())
        root = SimpleNamespace(identity_fd=object(), operation_fd=object())
        owned = builder.OwnedOperation(locked, active, operation, root, operation_name)
        reconciliations = iter((
            SimpleNamespace(status="active", cleanup_allowed=True, cleanup_origin="prelease", owned=((builder.ROOT_NAME.text, root_generation),)),
            SimpleNamespace(status="leased", lease_seen=True, cleanup_allowed=False),
        ))
        appended = []

        def observe(identity, *_args):
            return operation_generation if identity is operation.identity_fd else root_generation

        def append_leased(writer_state, *args):
            appended.append(args)
            assert writer_state is writer and len(args) == 11 and args[-1] is control
            next_settled = ledger._settled_record(1, 2, "4" * 64)
            next_generation = dataclasses.replace(ledger_generation, size=2, mtime_ns=2, ctime_ns=2)
            return ledger.LedgerWriterState(node, ledger_generation.key, next_settled, next_generation)

        with patched(
            (builder, "_stable_active", lambda current, *_args: current),
            (builder, "_walk_entries", lambda *_args: (((builder.ROOT_NAME.text, root_generation),), ())),
            (builder, "_parent", lambda *_args: state_parent),
            (builder, "_current_ledger", lambda *_args: ledger_generation),
            (fs, "_observe_node", observe),
            (ledger, "_reconcile_ledger", lambda *_args: next(reconciliations)),
            (ledger, "_validate_legal_records", lambda *_args: "leased"),
            (ledger, "_append_leased_record", append_leased),
        ):
            marked = builder._mark_leased(owned, "5" * 64, 7, "7" * 64, 512, 1, control)
        matrix_case()
        assert marked.active.records[-1].record_type == "leased" and len(appended) == 1
        assert appended[0] == (
            token, operation_name, state_parent, operation_generation, root_generation,
            "5" * 64, 7, "7" * 64, 512, 1, control,
        )
        fs._close_node(node)

    reference = lease.RuntimeRootfsReference(
        lease.FIXED_PREFIX + operation_name + "/rootfs", token, operation_name,
        ledger_generation.key, settled, generation(40), operation_generation, root_generation,
        "5" * 64, 7, "7" * 64, 512, 1,
    )
    retained = build.RetainedBuild(builder.OwnedOperation(None, None, None, None, operation_name), None)
    retained.disposition = "transferred"
    held = lease.RetainedRootfsLease(reference, retained)
    calls = []
    with patched((lease, "_stable_graph", lambda *args: calls.append(args))):
        assert lease._stable_lease_pass(held, control) is reference
    matrix_case()
    assert len(calls) == 1 and calls[0][3] == "leased"


def probe_outcome_tests():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)

    def one(outcome, close_fault=False):
        node = held_node(120, "probe", "file", 0o600, 1)
        descriptors = (node.identity_fd, node.operation_fd)
        closes = []

        def flock(_fd, _flags):
            if outcome == "success":
                return None
            code = {"eagain": errno.EAGAIN, "eacces": errno.EACCES, "error": errno.EIO}[outcome]
            raise OSError(code, outcome)

        def close(probe):
            for descriptor in (probe.operation_fd, probe.identity_fd):
                assert descriptor.disposition == "open"
                descriptor.disposition = "closed"
                os.close(descriptor.number)
                closes.append(descriptor.role)
            if close_fault:
                raise OSError("probe close")

        with patched(
            (builder, "_verify_fixed_file", lambda *_args: node),
            (lease.fcntl, "flock", flock),
            (fs, "_close_node", close),
        ):
            if outcome in {"eagain", "eacces"} and not close_fault:
                lease._probe_lock(object(), node.generation, (), control)
            else:
                rejected(lambda: lease._probe_lock(object(), node.generation, (), control))
        assert len(closes) == 2 and len(set(closes)) == 2
        assert all(descriptor.disposition == "closed" for descriptor in descriptors)

    for outcome, close_fault in (
        ("eagain", False), ("eacces", False), ("success", False),
        ("error", False), ("error", True), ("eagain", True),
    ):
        matrix_case()
        one(outcome, close_fault)


def stable_graph_success_test():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    retained, reference, state_parent = graph_fixture()
    owned = retained.owned
    temporary_anchor = held_node(130, "temporary-anchor")
    temporary_state = held_node(102, "temporary-state")
    temporary_operation = held_node(104, "temporary-operation")
    temporary_root = held_node(105, "temporary-root", mode=0o755)
    temporary = fs.HeldChain(temporary_anchor, (
        fs.ChainComponent(builder.STATE_NAME, temporary_state),
        fs.ChainComponent(fs._name(owned.operation_name), temporary_operation),
        fs.ChainComponent(builder.ROOT_NAME, temporary_root),
    ))
    sentinel = held_node(131, "sentinel", "file", 0o600, 1)
    events = []
    temporary_closes = []
    observations_seen = []

    def observe(identity, _operation, _control):
        events.append("observe")
        for node in (owned.locked.state, owned.operation, owned.root, owned.locked.lock):
            if identity is node.identity_fd:
                return node.generation
        raise AssertionError("unknown retained observation")

    def observe_child(parent, name, _control):
        events.append("child:" + name.text)
        assert parent is owned.locked.state
        return owned.locked.lock.generation if name == builder.LOCK_NAME else owned.active.writer.generation

    def policy(node, kind, mode, root_key):
        events.append("policy:" + kind)
        assert node.generation.key.kind == kind and node.generation.mode == mode
        assert (node.generation.key.mount_id, node.generation.key.device) == (root_key.mount_id, root_key.device)

    def descriptors_probe(state, expected, descriptors, passed_control):
        events.append("probe")
        assert state is owned.locked.state and expected == owned.locked.lock.generation and passed_control is control
        owner_nodes = tuple(component.node for component in retained.base_chain.components) + (
            retained.base_chain.anchor, owned.locked.state, owned.locked.lock, owned.active.node, owned.operation, owned.root,
        )
        expected_descriptors = tuple(value for node in owner_nodes for value in (node.identity_fd, node.operation_fd))
        assert descriptors == expected_descriptors and len({id(value) for value in descriptors}) == len(descriptors)

    def reconcile(records, observations):
        events.append("reconcile")
        observations_seen.append(observations)
        assert records is owned.active.records
        assert observations.state_parent == state_parent
        assert observations.operations == ((owned.operation_name, owned.operation.generation),)
        assert observations.entries == ((builder.ROOT_NAME.text, owned.root.generation),)
        assert observations.ledger_generation == owned.active.writer.generation
        snapshot = ledger.LeaseSnapshot(
            state_parent, owned.operation.generation, owned.root.generation,
            ((builder.ROOT_NAME.text, owned.root.generation),), owned.active.writer.stable_key, owned.active.writer.settled,
        )
        return ledger.LedgerState(
            "leased", reference.token, reference.operation_name, snapshot.owned,
            False, "none", True, False, "leased", snapshot,
        )

    def close_node(node):
        assert node is sentinel
        events.append("close-sentinel")
        for descriptor in (node.operation_fd, node.identity_fd):
            descriptor.close()

    def close_chain(chain):
        assert chain is temporary
        events.append("close-temporary")
        for node in tuple(component.node for component in reversed(chain.components)) + (chain.anchor,):
            for descriptor in (node.operation_fd, node.identity_fd):
                assert descriptor.disposition == "open"
                temporary_closes.append(descriptor.role)
                descriptor.close()

    with patched(
        (builder, "_verify_fixed_file", lambda *_args: (events.append("sentinel") or sentinel)),
        (fs, "_close_node", close_node),
        (fs, "_observe_node", observe),
        (builder, "_policy", policy),
        (fs, "_require_empty_fd_xattrs", lambda node, _control: events.append("xattr:" + node.identity_fd.role)),
        (fs, "_observe_child", observe_child),
        (lease, "_probe_lock", descriptors_probe),
        (lease, "_fresh_fixed_chain", lambda *_args: (events.append("fresh-chain") or (temporary, temporary_state, temporary_operation, temporary_root))),
        (builder, "_stable_active", lambda active, state, passed: (events.append("stable-active") or active)),
        (builder, "_walk_entries", lambda operation, passed: (events.append("walk") or (((builder.ROOT_NAME.text, owned.root.generation),), (("", ledger.LedgerParent(owned.operation.generation, (builder.ROOT_NAME.text,))),)))),
        (builder, "_parent", lambda state, passed: (events.append("parent") or state_parent)),
        (builder, "_current_ledger", lambda active, passed: (events.append("ledger") or owned.active.writer.generation)),
        (ledger, "_reconcile_ledger", reconcile),
        (fs, "_revalidate_chain", lambda chain, passed: events.append("revalidate")),
        (fs, "_close_chain", close_chain),
    ):
        active, reconciled = lease._stable_graph(retained, reference, control, "leased")
    matrix_case()
    assert active is owned.active and reconciled.status == "leased" and len(observations_seen) == 1
    assert events.index("probe") < events.index("fresh-chain") < events.index("stable-active")
    assert events.index("reconcile") < events.index("revalidate") < events.index("close-temporary")
    assert len(temporary_closes) == 8 and len(set(temporary_closes)) == 8
    close_graph_nodes(retained)


def stable_terminal_replacement_test():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)

    def node(inode, kind="directory", mode=0o700, nlink=2):
        return SimpleNamespace(identity_fd=object(), operation_fd=object(), generation=generation(inode, kind, mode, nlink))

    base = fs.HeldChain(node(1), (fs.ChainComponent(fs._name("base"), node(2)),))
    state, lock, ledger_node, operation, root = node(3), node(4, "file", 0o600, 1), node(5, "file", 0o600, 1), node(6), node(7, mode=0o755)
    active = SimpleNamespace(node=ledger_node, records=(object(),), writer=SimpleNamespace(generation=ledger_node.generation, settled=object()))
    owned = SimpleNamespace(
        locked=SimpleNamespace(state=state, lock=lock), active=active, operation=operation, root=root,
        operation_name="operation-" + "a" * 64,
    )
    retained = SimpleNamespace(base_chain=base)
    fresh_state, fresh_operation, fresh_root = node(3), node(6), node(7, mode=0o755)
    temporary = fs.HeldChain(node(8), (
        fs.ChainComponent(builder.STATE_NAME, fresh_state),
        fs.ChainComponent(fs._name(owned.operation_name), fresh_operation),
        fs.ChainComponent(builder.ROOT_NAME, fresh_root),
    ))
    parent = ledger.LedgerParent(state.generation, tuple(sorted((builder.LEDGER_NAME.text, builder.LOCK_NAME.text, owned.operation_name))))
    terminal = {"reconciled": False, "revalidated": False, "closed": False}

    def reconcile(_records, _observations):
        terminal["reconciled"] = True
        return SimpleNamespace(status="active", cleanup_allowed=True, cleanup_origin="prelease")

    replacement_nodes = iter((node(3), node(6), node(70, mode=0o755)))

    def open_replacement(_parent, _name, _kind, _control):
        assert terminal["reconciled"]
        terminal["revalidated"] = True
        return next(replacement_nodes)

    def observe_child(_parent, name, _control):
        return lock.generation if name == builder.LOCK_NAME else ledger_node.generation

    with patched(
        (lease, "_topology", lambda *_args: owned),
        (lease, "_descriptors", lambda _node: (object(),)),
        (lease, "_probe_lock", lambda *_args: None),
        (lease, "_fresh_fixed_chain", lambda *_args: (temporary, fresh_state, fresh_operation, fresh_root)),
        (builder, "_verify_fixed_file", lambda *_args: node(9, "file", 0o600, 1)),
        (builder, "_policy", lambda *_args: None),
        (builder, "_stable_active", lambda *_args: active),
        (builder, "_walk_entries", lambda *_args: ((("rootfs", root.generation),), ())),
        (builder, "_parent", lambda *_args: parent),
        (builder, "_current_ledger", lambda *_args: ledger_node.generation),
        (fs, "_close_node", lambda *_args: None),
        (fs, "_require_empty_fd_xattrs", lambda *_args: None),
        (fs, "_observe_node", lambda identity, *_args: next(item.generation for item in (state, operation, root, lock) if item.identity_fd is identity)),
        (fs, "_observe_child", observe_child),
        (fs, "_open_root_node", lambda _control: node(8)),
        (fs, "_open_path_node", open_replacement),
        (fs, "_close_chain", lambda _chain: terminal.__setitem__("closed", True)),
        (ledger, "_reconcile_ledger", reconcile),
    ):
        rejected(lambda: lease._stable_graph(retained, None, control, "active"))
    matrix_case()
    assert terminal == {"reconciled": True, "revalidated": True, "closed": True}


def alias_and_close_tests():
    retained, reference, _state_parent = graph_fixture()
    owned = retained.owned
    duplicate_node = held_node(140, "duplicate-ledger", "file", 0o600, 1, owned.active.writer.settled.offset)
    duplicate_writer = ledger.LedgerWriterState(
        duplicate_node, duplicate_node.generation.key, owned.active.writer.settled, duplicate_node.generation,
    )
    reconstructed = builder.ActiveLedger(owned.active.node, owned.active.records, duplicate_writer)
    hostile = build.RetainedBuild(
        builder.OwnedOperation(owned.locked, reconstructed, owned.operation, owned.root, owned.operation_name),
        retained.base_chain,
    )
    hostile.disposition = "transferred"
    matrix_case()
    rejected(lambda: lease._topology(hostile, reference))
    close_if_open(duplicate_node)

    alias_root = fs.HeldNode(owned.operation.identity_fd, checked("alias-root-operation"), owned.root.generation)
    aliased = build.RetainedBuild(
        builder.OwnedOperation(owned.locked, owned.active, owned.operation, alias_root, owned.operation_name), retained.base_chain,
    )
    aliased.disposition = "transferred"
    matrix_case()
    rejected(lambda: lease._topology(aliased, reference))
    alias_root.operation_fd.close()
    close_graph_nodes(retained)

    for injected_role in (None, "root-identity", "base-prefix-operation"):
        retained, _reference, _parent = graph_fixture()
        roles = tuple(
            descriptor.role
            for node in (
                retained.owned.root, retained.owned.operation, retained.owned.active.node,
                retained.owned.locked.lock, retained.owned.locked.state,
                *tuple(component.node for component in retained.base_chain.components), retained.base_chain.anchor,
            )
            for descriptor in (node.operation_fd, node.identity_fd)
        )
        counts = {}
        original_close = fs.CheckedFd.close

        def counted_close(descriptor, primary_error=None):
            counts[descriptor.role] = counts.get(descriptor.role, 0) + 1
            if descriptor.role == injected_role:
                assert descriptor.disposition == "open"
                os.close(descriptor.number)
                descriptor.disposition = "uncertain"
                raise fs.RootfsFsError(primary_error, OSError("injected per-fd close"))
            return original_close(descriptor, primary_error)

        with patched((fs.CheckedFd, "close", counted_close)):
            if injected_role is None:
                lease._close_preserving(retained)
            else:
                rejected(lambda: lease._close_preserving(retained))
        matrix_case()
        assert counts == {role: 1 for role in roles}
        assert retained.disposition == "uncertain"
        assert all(count == 1 for count in counts.values())


def acquisition_boundary_tests():
    approval = fs.SourceApproval("1" * 40, "2" * 64)
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    cache = tuple((str(index), (index,), "3" * 64) for index in range(16))
    candidate = build.BuildCandidate(b"manifest", b"tar", "4" * 64, "5" * 64, 512, 1, cache)
    pins = publication.RootfsPins(b"pins", "4" * 64, len(candidate.manifest), "5" * 64, 512, 1)
    # The fixture used only for its immutable reference is not retained here.
    # Close its independently allocated authorities immediately.
    fixture_retained, reference, _fixture_parent = graph_fixture()
    close_graph_nodes(fixture_retained)

    def run(fault):
        retained = build.RetainedBuild(SimpleNamespace(name="owned-before"), SimpleNamespace(name="base"))
        refreshed = SimpleNamespace(name="owned-after", active=object())
        events = []

        def abandon(bundle, primary):
            events.append(("abandon", bundle.disposition, primary.args[0]))
            raise primary

        def preserve(bundle, primary=None):
            events.append(("preserve", bundle.disposition, primary.args[0]))
            bundle.disposition = "uncertain"
            raise primary

        def topology(bundle, _reference=None):
            events.append(("topology", bundle.disposition, bundle.owned.name))
            if fault == "active-stable" and bundle.disposition == "owned":
                raise RuntimeError(fault)
            if fault == "post-mark-topology" and bundle.owned is refreshed:
                raise RuntimeError(fault)
            return bundle.owned

        def stable(bundle, _reference, _control, status):
            events.append(("stable", bundle.disposition, status))
            if fault == "active-stable":
                raise RuntimeError(fault)
            return None

        def mark(owned, *args):
            events.append(("mark", retained.disposition, owned.name, args))
            assert retained.disposition == "uncertain"
            if fault is not None and fault.startswith("mark-"):
                raise RuntimeError(fault)
            return refreshed

        stable_passes = {"count": 0}

        def stable_pass(value, _control):
            stable_passes["count"] += 1
            events.append(("lease-pass", value.retained.disposition))
            if fault == "post-mark-pass":
                raise RuntimeError(fault)
            return value.reference

        def equal(_first, _second):
            events.append(("equal", retained.disposition))
            if fault == "equal":
                raise RuntimeError(fault)

        token_values = iter(("6" * 64, "7" * 64))
        with patched(
            (publication, "_load_pins", lambda: pins),
            (lease.secrets, "token_hex", lambda _size: next(token_values)),
            (build, "_build_once", lambda *_args: (events.append(("build-one",)) or candidate)),
            (build, "_build_once_retained", lambda *_args: (events.append(("build-two",)) or (candidate, retained))),
            (build, "_require_equal_builds", equal),
            (build, "_require_pinned", lambda *_args: events.append(("pin", retained.disposition))),
            (lease, "_topology", topology),
            (lease, "_stable_graph", stable),
            (builder, "_mark_leased", mark),
            (lease, "_reference", lambda *_args: reference),
            (lease, "_stable_lease_pass", stable_pass),
            (lease, "_close_preserving", preserve),
            (lease, "_abandon_active", abandon),
        ):
            if fault is None:
                result = lease._acquire(approval, control)
                assert result.reference is reference and result.retained is retained
            else:
                rejected(lambda: lease._acquire(approval, control))
        return events, retained

    for fault in ("equal", "active-stable"):
        events, retained = run(fault)
        matrix_case()
        assert sum(event[0] == "abandon" and event[1] == "owned" for event in events) == 1, (fault, events)
        assert not any(event[0] == "preserve" for event in events)
        assert retained.disposition == "owned"
    for fault in ("mark-prevalidation", "mark-append", "mark-readback", "post-mark-topology", "post-mark-pass"):
        events, retained = run(fault)
        matrix_case()
        mark_index = next(index for index, event in enumerate(events) if event[0] == "mark")
        assert events[mark_index][1] == "uncertain"
        assert sum(event[0] == "preserve" and event[1] in {"uncertain", "transferred"} for event in events) == 1, (fault, events)
        assert not any(event[0] == "abandon" for event in events)
        assert retained.disposition == "uncertain"
    events, retained = run(None)
    matrix_case()
    assert [event[0] for event in events].count("pin") == 2
    assert next(event for event in events if event[0] == "mark")[1] == "uncertain"
    assert retained.disposition == "transferred"


def verify_order_and_drift_tests():
    retained, reference, _parent = graph_fixture()
    held = lease.RetainedRootfsLease(reference, retained)
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    manifest = b"bounded-manifest"
    reference = dataclasses.replace(
        reference, manifest_sha256=hashlib.sha256(manifest).hexdigest(), manifest_size=len(manifest), entry_count=1,
    )
    held.reference = reference
    root_plan = plan.RootfsPlan(object(), (), (object(),), ())
    authority = plan.RootfsBuildInputs("authority", (), (), root_plan)
    fresh = plan.RootfsBuildInputs("fresh", (), (), root_plan)
    exact_pins = publication.RootfsPins(
        b"pins", reference.manifest_sha256, reference.manifest_size,
        reference.ustar_sha256, reference.ustar_size, reference.entry_count,
    )

    def run(fault=None):
        events = []
        passes = {"count": 0}

        def stable_pass(value, passed_control):
            passes["count"] += 1
            label = "A" if passes["count"] == 1 else "B"
            events.append(label)
            if fault == label:
                raise RuntimeError(label)
            return value.reference

        def load_inputs():
            events.append("load")
            return authority

        def postwalk(owned, root, loaded, passed_control):
            events.append("postwalk")
            assert loaded is authority and root is retained.owned.root
            return 2 if fault == "postwalk" else 1

        def revalidate(loaded):
            events.append("revalidate")
            return authority if fault == "revalidate" else fresh

        def make_manifest(value):
            events.append("manifest")
            return b"drift" if fault == "manifest" else manifest

        def load_pins():
            events.append("pins")
            if fault == "pins":
                return dataclasses.replace(exact_pins, entry_count=2)
            return exact_pins

        replacement_plan = plan.RootfsPlan(object(), (), (object(), object()), ())
        replacement_fresh = plan.RootfsBuildInputs("fresh", (), (), replacement_plan)
        with patched(
            (lease, "_stable_lease_pass", stable_pass),
            (plan, "load_verified_build_inputs", load_inputs),
            (materializer, "_postwalk", postwalk),
            (plan, "revalidate_build_inputs", revalidate if fault != "entries" else lambda loaded: (events.append("revalidate") or replacement_fresh)),
            (canonical, "_manifest", make_manifest),
            (publication, "_load_pins", load_pins),
        ):
            if fault is None:
                assert lease._verify(held, control) is reference
            else:
                rejected(lambda: lease._verify(held, control))
        return events

    assert run() == ["A", "load", "postwalk", "revalidate", "manifest", "pins", "B"]
    matrix_case()
    expected_stops = {
        "A": ["A"],
        "postwalk": ["A", "load", "postwalk"],
        "revalidate": ["A", "load", "postwalk", "revalidate"],
        "manifest": ["A", "load", "postwalk", "revalidate", "manifest"],
        "entries": ["A", "load", "postwalk", "revalidate", "manifest"],
        "pins": ["A", "load", "postwalk", "revalidate", "manifest", "pins"],
        "B": ["A", "load", "postwalk", "revalidate", "manifest", "pins", "B"],
    }
    for fault, expected in expected_stops.items():
        matrix_case()
        assert run(fault) == expected
    close_graph_nodes(retained)


def preservation_route_tests():
    approval = fs.SourceApproval("8" * 40, "9" * 64)
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    durable = {
        "ledger": b"exact-canonical-leased-ledger\n",
        "ledger_key": fs.HostKey(1, 1, 900, "file"),
        "root": generation(901, mode=0o755),
    }
    exact = (durable["ledger"], durable["ledger_key"], durable["root"])

    def attempt():
        state = held_node(150, "recovery-state")
        lock = held_node(151, "recovery-lock", "file", 0o600, 1)
        active_node = held_node(152, "recovery-ledger", "file", 0o600, 1, 1)
        operation = held_node(153, "recovery-operation")
        locked = SimpleNamespace(state=state, lock=lock)
        active = SimpleNamespace(node=active_node, records=(SimpleNamespace(body_value=lambda: {
            "token": "a" * 64, "source_revision": approval.revision, "source_manifest_sha256": approval.manifest_sha256,
        }),))
        leased_state = SimpleNamespace(status="leased", release_authorized=False)
        mutations = []

        def forbidden(*_args):
            mutations.append("mutation")
            raise AssertionError("leased recovery mutated durable state")

        def close(node):
            close_if_open(node)

        def release(_locked, primary=None):
            close_if_open(lock)
            close_if_open(state)
            if primary is not None:
                raise primary

        caught = None
        with patched(
            (builder, "_acquire_lock", lambda *_args: locked),
            (builder.fs, "_enumerate_stable", lambda *_args: SimpleNamespace(raw_names=(builder.LEDGER_NAME.raw,))),
            (builder, "_read_active_ledger", lambda *_args: active),
            (builder.fs, "_verify_source_bundle", lambda *_args: None),
            (builder, "_source", lambda *_args: object()),
            (builder, "_current_ledger", lambda *_args: generation(900, "file", 0o600, 1, 1)),
            (builder, "_observations", lambda *_args: (object(), operation)),
            (ledger, "_reconcile_ledger", lambda *_args: leased_state),
            (builder, "_close", close),
            (builder, "_release_lock", release),
            (builder, "_cleanup_active", forbidden),
            (builder, "_resume_observed", forbidden),
            (builder, "_resume_entry_remove", forbidden),
            (builder, "_retire", forbidden),
            (builder, "_finish_operation_absent", forbidden),
            (builder, "_unlink_ledger", forbidden),
            (builder, "_cleanup_append", forbidden),
        ):
            try:
                builder._recover_locked(object(), state, control)
            except BaseException as error:
                caught = error
        assert caught is not None and not mutations
        assert exact == (durable["ledger"], durable["ledger_key"], durable["root"])
        raise caught

    with patched((builder, "_run_recovery", attempt)):
        assert builder.main(["recover-owned"]) == 1
    matrix_case()
    with patched(
        (builder, "_fixed_umask", lambda function, *args: function(*args)),
        (builder, "_recover_fixed_unmasked", lambda _control: attempt()),
    ):
        rejected(lambda: builder._recover_fixed(control))
    matrix_case()
    authority = SimpleNamespace(cache=())
    chain = SimpleNamespace(name="later-build-chain")
    with patched(
        (plan, "load_verified_build_inputs", lambda: authority),
        (builder, "_open_base_chain", lambda _control: chain),
        (builder, "_begin_operation", lambda *_args: attempt()),
        (builder, "_fixed_umask", lambda function, *args: function(*args)),
        (fs, "_close_chain", lambda current: None),
    ):
        rejected(lambda: build._build_once(approval, "b" * 64, control))
    matrix_case()
    assert exact == (durable["ledger"], durable["ledger_key"], durable["root"])


def authorized_cleanup_boundary_tests():
    classes = (
        ("startup", "genesis-settled", "prelease"),
        ("create", "create-settled", "prelease"),
        ("metadata", "metadata-settled", "prelease"),
        ("hardlink-create", "hardlink-create-settled", "prelease"),
        ("ordinary-remove", "remove-settled", "prelease"),
        ("authorized-remove", "remove-settled", "release-authorized"),
        ("operation-remove", "operation-absent", "release-authorized"),
        ("retire", "retired", "release-authorized"),
    )
    boundaries = ("before-write", "partial-write", "after-write-before-sync", "after-sync", "rollback-success", "rollback-failure", "observed", "settled")
    for transition_class, record_type, origin in classes:
        for boundary in boundaries:
            events = []
            active = SimpleNamespace(prefix=(transition_class,))
            appended = SimpleNamespace(prefix=(transition_class, record_type))

            def append(current, kind, body, passed_control):
                events.append(("append", kind, origin, boundary))
                if boundary not in {"observed", "settled"}:
                    raise OSError(boundary)
                return appended

            def fresh(current, locked, operation, expected_origin, passed_control):
                events.append(("fresh", expected_origin, current.prefix))
                assert current is appended and expected_origin == origin
                if boundary == "observed":
                    raise OSError("crash after durable append")
                return SimpleNamespace(cleanup_allowed=True, cleanup_origin=origin)

            with patched((builder, "_append", append), (builder, "_fresh_cleanup", fresh)):
                if boundary == "settled":
                    assert builder._cleanup_append(active, object(), object(), record_type, {}, origin, object()) is appended
                else:
                    rejected(lambda: builder._cleanup_append(active, object(), object(), record_type, {}, origin, object()))
            if boundary in {"observed", "settled"}:
                assert events[0][0] == "append" and events[1][0] == "fresh" and events[1][1] == origin
            else:
                assert events == [("append", record_type, origin, boundary)]
            matrix_case()


def model_tests():
    token = "a" * 64
    name = ledger._operation_name(token)
    settled = ledger._settled_record(9, 1000, "b" * 64)
    reference = lease.RuntimeRootfsReference(
        lease.FIXED_PREFIX + name + "/rootfs",
        token,
        name,
        fs.HostKey(1, 1, 99, "file"),
        settled,
        generation(1),
        generation(2),
        generation(3),
        "c" * 64,
        7,
        "d" * 64,
        512,
        1,
    )
    assert reference.path == (
        "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/"
        "completion-v1/rootfs-v1/operation-" + token + "/rootfs"
    )
    rejected(lambda: dataclasses.replace(reference, path="/tmp/rootfs"))
    rejected(lambda: dataclasses.replace(reference, token="A" * 64))
    rejected(lambda: dataclasses.replace(reference, ustar_size=513))
    rejected(lambda: dataclasses.replace(reference, entry_count=True))

    cache = tuple((str(index), (index,), "e" * 64) for index in range(16))
    first = build.BuildCandidate(b"manifest", b"tar", "f" * 64, "1" * 64, 512, 1, cache)
    second = dataclasses.replace(first)
    build._require_equal_builds(first, second)
    rejected(lambda: build._require_equal_builds(first, dataclasses.replace(second, ustar=b"other")))
    rejected(lambda: build._require_equal_builds(first, object()))
    pins = publication.RootfsPins(b"pins", first.manifest_sha256, len(first.manifest), first.ustar_sha256, 512, 1)
    build._require_pinned(first, pins)
    rejected(lambda: build._require_pinned(first, dataclasses.replace(pins, entry_count=2)))


def source_tests():
    source = (REMOTE / "completion_rootfs_lease.py").read_text()
    builder_source = (REMOTE / "completion_rootfs_builder.py").read_text()
    assert "def _acquire(" in source and "def _verify(" in source
    verify_source = source.split("def _verify(", 1)[1]
    assert verify_source.count("_stable_lease_pass(lease, control)") == 2
    assert "retained.disposition = \"uncertain\"" in source
    assert source.index("retained.disposition = \"uncertain\"") < source.index("builder._mark_leased(")
    assert "publication._load_pins()" in source and "publication._publish" not in source
    assert "release-authorized" not in source
    assert "def release" not in source and "def _authorize" not in source
    for forbidden in (
        "subprocess", "os.system", "tarfile", "shutil", "copyfile", "rename(", "replace(",
        "chmod", "chown", "os.mount", "/proc/self/fd", "__del__", "__enter__", "__exit__",
    ):
        assert forbidden not in source
    assert "resolve()" not in source and "destination" not in source
    assert "_append_mechanical" not in builder_source
    assert 'record_type not in {"leased", "release-authorized"}' in builder_source
    assert "def _mark_leased(" in builder_source and "def _stable_active(" in builder_source
    writer_calls = []
    control_owners = []
    for path in (ROOT / "deploy").rglob("*.py"):
        tree = ast.parse(path.read_text())
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            owner = node
            while owner in parents and not isinstance(parents[owner], (ast.FunctionDef, ast.ClassDef)):
                owner = parents[owner]
            owner_name = getattr(parents.get(owner), "name", "<module>")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"_append_record", "_append_leased_record"}:
                writer_calls.append((path.name, owner_name, node.func.attr))
            if isinstance(node, ast.Constant) and node.value in {"leased", "release-authorized"}:
                control_owners.append((path.name, owner_name))
    assert sorted(writer_calls) == [
        ("completion_rootfs_builder.py", "_append", "_append_record"),
        ("completion_rootfs_builder.py", "_mark_leased", "_append_leased_record"),
    ]
    allowed = {
        "completion_rootfs_ledger.py": {"<module>", "__post_init__", "_validate_body", "_lease_history", "_validate_legal_records", "_reconcile_ledger", "_write_record", "_append_record", "_append_leased_record"},
        "completion_rootfs_builder.py": {"_append", "_mark_leased", "_unlink_ledger", "_resume_entry_remove", "_resume_observed", "_recover_locked"},
        "completion_rootfs_lease.py": {"_stable_graph", "_stable_lease_pass", "_reference", "rootfs_route"},
    }
    assert all(owner in allowed.get(path, set()) for path, owner in control_owners)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def docker_real_lease_test():
    harness = load("completion_rootfs_canonical_harness", ROOT / "test/aws-stage2-completion-rootfs-canonical.py")
    revision, source_digest, cache_before = harness.prepare_real_workspace()
    fixed_remote = harness.FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(fixed_remote))
    load("completion_archive_preflight", fixed_remote / "completion_archive_preflight.py")
    plan_module = load("completion_rootfs_plan", fixed_remote / "completion_rootfs_plan.py")
    fs_module = load("completion_rootfs_fs", fixed_remote / "completion_rootfs_fs.py")
    ledger_module = load("completion_rootfs_ledger", fixed_remote / "completion_rootfs_ledger.py")
    builder_module = load("completion_rootfs_builder", fixed_remote / "completion_rootfs_builder.py")
    load("completion_rootfs_materializer", fixed_remote / "completion_rootfs_materializer.py")
    load("completion_rootfs_canonical", fixed_remote / "completion_rootfs_canonical.py")
    publication_module = load("completion_rootfs_publish", fixed_remote / "completion_rootfs_publish.py")
    build_module = load("completion_rootfs_build", fixed_remote / "completion_rootfs_build.py")
    operation_module = load("completion_kata_operation", fixed_remote / "completion_kata_operation.py")
    lease_module = load("completion_rootfs_lease", fixed_remote / "completion_rootfs_lease.py")
    assert Path(operation_module.__file__).parent == Path(lease_module.__file__).parent == fixed_remote
    assert lease_module.kata_operation is operation_module
    harness.accommodate_docker_overlay(fs_module)
    assert build_module.BUILD_SECONDS == 300

    approval = fs_module.SourceApproval(revision, source_digest)
    control = fs_module.OperationControl(time.monotonic_ns() + 3600 * 1_000_000_000, lambda: False)
    chain = builder_module._open_base_chain(control)
    state = builder_module._bootstrap(chain, approval, control)
    fs_module._close_node(state)
    fs_module._close_chain(chain)

    held = lease_module._acquire(approval, control)
    reference = held.reference
    pins = publication_module._load_pins()
    assert reference.entry_count == len(plan_module.load_verified_build_inputs().plan.entries) == 4353
    assert (reference.manifest_sha256, reference.manifest_size, reference.ustar_sha256, reference.ustar_size, reference.entry_count) == (
        pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256, pins.ustar_size, pins.entry_count,
    )
    assert reference.path == lease_module.FIXED_PREFIX + reference.operation_name + "/rootfs"
    assert Path(reference.path).is_dir()
    assert lease_module._verify(held, control) == reference

    ledger_path = harness.FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1" / builder_module.LEDGER_NAME.text
    root_path = Path(reference.path)
    initial_ledger = ledger_path.read_bytes()
    ledger_stat = ledger_path.stat()
    root_stat = root_path.stat()
    initial_identity = (ledger_stat.st_dev, ledger_stat.st_ino, hashlib.sha256(initial_ledger).hexdigest())
    initial_root_identity = (root_stat.st_dev, root_stat.st_ino)

    def preserved():
        current = ledger_path.read_bytes()
        observed = ledger_path.stat()
        root_observed = root_path.stat()
        assert (observed.st_dev, observed.st_ino, hashlib.sha256(current).hexdigest()) == initial_identity
        assert (root_observed.st_dev, root_observed.st_ino) == initial_root_identity and root_path.is_dir()

    # Simulate owner death: every preservation attempt below is unlocked and
    # therefore must decide from the durable leased ledger, not flock contention.
    lease_module._close_preserving(held.retained)
    preserved()

    # Compose the real fixed operation owner with the real durable rootfs owner.
    def operation_journal(include_leased=False, mismatch=False):
        # Test-only fixed filesystem fixture. Production exposes no generic owner.
        state_path = harness.FIXED / "deploy/aws-feasibility/.state/completion-v1" / operation_module.STATE_NAME.text
        state_path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(state_path, 0o700)
        sentinel_path = state_path / operation_module.SENTINEL_NAME.text
        lock_path = state_path / operation_module.LOCK_NAME.text
        journal_path = state_path / operation_module.JOURNAL_NAME.text
        sentinel_path.write_bytes(operation_module.SENTINEL)
        lock_path.touch(exist_ok=True)
        os.chmod(sentinel_path, 0o600)
        os.chmod(lock_path, 0o600)
        if journal_path.exists():
            journal_path.unlink()
        journal_path.touch(mode=0o600)
        os.chmod(journal_path, 0o600)

        fixture_control = fs_module.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
        chain = builder_module._open_base_chain(fixture_control)
        state = journal = None
        try:
            state = fs_module._open_path_node(
                chain.components[-1].node, operation_module.STATE_NAME, "directory", fixture_control,
            )
            journal = fs_module._open_path_node(
                state, operation_module.JOURNAL_NAME, "file", fixture_control,
            )
            journal_key = operation_module._key_value(journal.generation.key)
            state_generation = operation_module._generation_value(state.generation)
        finally:
            if journal is not None:
                fs_module._close_node(journal)
            if state is not None:
                fs_module._close_node(state)
            fs_module._close_chain(chain)

        genesis = {
            **operation_module.FIXED, "operation_token": "8" * 64,
            "rootfs_token": reference.token,
            "host_boot_id": "11111111-1111-1111-1111-111111111111",
            "source_revision": revision, "source_manifest_sha256": source_digest,
            "journal_key": journal_key, "rootfs_pin": operation_module.ROOTFS_PIN,
            "mount_list_sha256": operation_module.MOUNT_SHA,
        }
        records = ()
        raw = b""
        bodies = [("GENESIS", genesis), ("GENESIS_SETTLED", {
            "operation_token": "8" * 64, "journal_key": journal_key,
            "state_parent": state_generation,
        }), ("ROOTFS_ACQUIRE_INTENT", {
            "operation_token": "8" * 64, "rootfs_token": reference.token,
            "rootfs_baseline_sha256": "7" * 64,
        })]
        if include_leased:
            digest = reference.leased_settled.line_sha256
            if mismatch:
                digest = ("0" if digest[0] != "0" else "1") + digest[1:]
            bodies.append(("ROOTFS_LEASED", {
                "operation_token": "8" * 64, "rootfs_token": reference.token,
                "rootfs_ledger_key": operation_module._key_value(reference.ledger_key),
                "leased_sequence": reference.leased_settled.sequence,
                "leased_offset": f"{reference.leased_settled.offset:016x}",
                "leased_sha256": digest,
                "state_generation": operation_module._generation_value(reference.state_generation),
                "operation_generation": operation_module._generation_value(reference.operation_generation),
                "root_generation": operation_module._generation_value(reference.root_generation),
                "rootfs_pin": operation_module.ROOTFS_PIN,
            }))
        for kind, value in bodies:
            line = operation_module._encode(kind, value, records)
            raw += line
            records = operation_module._parse(raw)
        descriptor = os.open(journal_path, os.O_WRONLY | os.O_TRUNC)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(state_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return journal_path

    bad_journal = operation_journal(True, True)
    authority = operation_module._open_fixed_operation()
    rejected(lambda: lease_module._reopen_kata_reserved(authority.reserve_rootfs(), control))
    authority.close()
    bad_journal.unlink()
    operation_journal()
    authority = operation_module._open_fixed_operation()
    reopened = lease_module._reopen_kata_reserved(authority.reserve_rootfs(), control)
    lease_module._close_preserving(reopened.retained)
    authority.close()
    authority = operation_module._open_fixed_operation()
    reopened = lease_module._reopen_kata_reserved(authority.reserve_rootfs(), control)
    lease_module._close_preserving(reopened.retained)
    authority.close()
    preserved()

    assert builder_module.main(["recover-owned"]) == 1
    preserved()
    rejected(lambda: builder_module._recover_fixed(fs_module.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)))
    preserved()
    rejected(lambda: build_module._build_once(
        approval, "9" * 64,
        fs_module.OperationControl(time.monotonic_ns() + 300_000_000_000, lambda: False),
    ))
    preserved()

    body = {
        "token": reference.token,
        "operation_name": reference.operation_name,
        "lease_sequence": reference.leased_settled.sequence,
        "lease_offset": reference.leased_settled.offset,
        "lease_sha256": reference.leased_settled.line_sha256,
        "kata_operation_token": "8" * 64,
        "kata_ledger_key": {
            "mount_id": reference.ledger_key.mount_id,
            "device": reference.ledger_key.device,
            "inode": reference.ledger_key.inode,
            "kind": "file",
        },
        "kata_release_sequence": 1,
        "kata_release_offset": 1,
        "kata_release_sha256": "7" * 64,
    }
    proposal = ledger_module.LedgerProposal.create("release-authorized", body)
    raw = ledger_module._encode_proposal(proposal, reference.leased_settled)
    # Test-only exact reopen after owner death. Production intentionally has no
    # authorization appender or pathname-adoption API.
    flags = os.O_RDWR | fs_module._O_NOFOLLOW | fs_module._O_CLOEXEC
    directory_descriptor = os.open(ledger_path.parent, os.O_RDONLY | os.O_DIRECTORY | fs_module._O_CLOEXEC)
    descriptor = None
    try:
        descriptor = os.open(ledger_path.name, flags, dir_fd=directory_descriptor)
        observed = os.fstat(descriptor)
        assert (observed.st_dev, observed.st_ino) == (reference.ledger_key.device, reference.ledger_key.inode)
        assert observed.st_size == reference.leased_settled.offset == len(initial_ledger)
        assert os.lseek(descriptor, reference.leased_settled.offset, os.SEEK_SET) == reference.leased_settled.offset
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            assert 0 < written <= len(raw) - offset
            offset += written
        os.fsync(descriptor)
        records = ledger_module._parse_ledger(os.pread(descriptor, reference.leased_settled.offset + len(raw), 0))
        assert records[-1].record_type == "release-authorized"
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)

    builder_module._recover_fixed(fs_module.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False))
    state_root = harness.FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
    assert sorted(path.name for path in state_root.iterdir()) == sorted((builder_module.STATE_SENTINEL_NAME.text, builder_module.LOCK_NAME.text))
    cache = harness.FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    cache_after = tuple((path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(cache.iterdir()))
    assert cache_after == cache_before and len(cache_after) == 16
    print("completion rootfs lease Docker real test passed")


def main(argv):
    if argv == ["--real"]:
        docker_real_lease_test()
    elif not argv:
        model_tests()
        behavioral_fault_tests()
        successful_behavior_tests()
        probe_outcome_tests()
        stable_graph_success_test()
        stable_terminal_replacement_test()
        alias_and_close_tests()
        acquisition_boundary_tests()
        verify_order_and_drift_tests()
        preservation_route_tests()
        authorized_cleanup_boundary_tests()
        source_tests()
        assert MATRIX_CASES > 0
        print(f"completion rootfs lease portable behavioral matrix: {MATRIX_CASES} finite cases")
        print("completion rootfs lease portable tests passed")
    else:
        raise SystemExit("usage: aws-stage2-completion-rootfs-lease.py [--real]")


if __name__ == "__main__":
    main(sys.argv[1:])

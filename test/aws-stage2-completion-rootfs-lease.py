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
from unittest.mock import patch

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
    active = SimpleNamespace(node=SimpleNamespace(identity_fd=object(), operation_fd=object()))
    locked = SimpleNamespace(state=object(), lock=SimpleNamespace(generation=generation(21, "file", 0o600, 1)))
    transitions = []

    def run_unlink(parents):
        values = iter(parents)
        transitions.clear()
        session = SimpleNamespace(disposition="active", active=active, locked=locked, state_parent=authorized)

        def parent_snapshot(*_args):
            value = next(values)
            return fs.DirectoryNamesSnapshot(value.generation, tuple(fs._name(name) for name in value.names))

        with patched(
            (builder, "_session_require", lambda *_args: None),
            (builder, "_session_binding", lambda *_args: None),
            (builder, "_state_chain", lambda *_args: object()),
            (builder.fs, "_revalidate_chain", lambda *_args: None),
            (builder.fs, "_observe_node", lambda *_args: generation(20, "file", 0o600, 1)),
            (builder, "_parent_snapshot", parent_snapshot),
            (builder, "_close", lambda _node: transitions.append("close")),
            (builder, "_remove_name", lambda *_args: transitions.append("unlink")),
        ):
            rejected(lambda: builder._unlink_ledger(session, control))
        assert session.disposition == "invalid"

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
    state_before = ledger.LedgerParent(
        generation(40), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text),
    )
    state_parent = ledger.LedgerParent(
        generation(40, ctime=2), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text, operation_name),
    )
    operation_generation = generation(41, ctime=2)
    operation_before = ledger.LedgerParent(operation_generation, ())
    operation_after = ledger.LedgerParent(operation_generation, (builder.ROOT_NAME.text,))
    root_generation = generation(42, mode=0o755)
    ledger_key = fs.HostKey(1, 1, 43, "file")
    bodies = (
        ("genesis", {
            "token": token, "source_revision": "1" * 40, "source_manifest_sha256": "2" * 64,
            "state_parent": ledger._parent_value(state_before),
            "ledger_key": {"mount_id": 1, "device": 1, "inode": 43, "kind": "file"},
        }),
        ("genesis-settled", {"token": token, "state_parent": ledger._parent_value(state_before)}),
        ("operation-create-intent", {
            "token": token, "operation_name": operation_name,
            "state_parent": ledger._parent_value(state_before),
        }),
        ("operation-create-observed", {
            "token": token, "operation_name": operation_name,
            "state_parent": ledger._parent_value(state_parent),
            "operation": ledger._generation_value(operation_generation),
        }),
        ("operation-create-settled", {
            "token": token, "operation_name": operation_name,
            "state_parent": ledger._parent_value(state_parent),
            "operation": ledger._generation_value(operation_generation),
        }),
        ("create-intent", {
            "token": token, "path": builder.ROOT_NAME.text, "kind": "directory",
            "parent": ledger._parent_value(operation_before),
        }),
        ("create-observed", {
            "token": token, "path": builder.ROOT_NAME.text, "kind": "directory",
            "parent": ledger._parent_value(operation_after), "child": ledger._generation_value(root_generation),
        }),
        ("create-settled", {
            "token": token, "path": builder.ROOT_NAME.text, "kind": "directory",
            "parent": ledger._parent_value(operation_after), "child": ledger._generation_value(root_generation),
        }),
    )
    raw = b""
    settled = ledger.INITIAL_BYTES
    for record_type, body in bodies:
        line = ledger._encode_proposal(ledger.LedgerProposal.create(record_type, body), settled)
        raw += line
        settled = ledger.SettledBytes(
            settled.sequence + 1, settled.offset + len(line), hashlib.sha256(line).hexdigest(),
        )
    history = ledger._parse_ledger_history(raw)
    ledger_generation = fs.HostGeneration(ledger_key, 0o600, 0, 0, 1, settled.offset, 1, 1)
    with tempfile.TemporaryFile() as file_object:
        node = fs.HeldNode(
            fs.CheckedFd(os.dup(file_object.fileno()), "mark-identity"),
            fs.CheckedFd(os.dup(file_object.fileno()), "mark-operation"),
            ledger_generation,
        )
        writer = ledger.LedgerWriterState(node, ledger_generation.key, settled, ledger_generation)
        active = builder.ActiveLedger(node, history, writer)
        locked = SimpleNamespace(state=SimpleNamespace(generation=generation(39)), chain=object())
        refreshed_locked = object()
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
            body = {
                "token": args[0], "operation_name": args[1],
                "state_parent": ledger._parent_value(args[2]), "operation": ledger._generation_value(args[3]),
                "root": ledger._generation_value(args[4]),
                "ledger_key": {"mount_id": 1, "device": 1, "inode": 43, "kind": "file"},
                "manifest_sha256": args[5], "manifest_size": args[6],
                "ustar_sha256": args[7], "ustar_size": args[8], "entry_count": args[9],
            }
            line = ledger._encode_proposal(ledger.LedgerProposal.create("leased", body), writer_state.settled)
            next_settled = ledger.SettledBytes(
                writer_state.settled.sequence + 1, writer_state.settled.offset + len(line), hashlib.sha256(line).hexdigest(),
            )
            next_generation = dataclasses.replace(
                ledger_generation, size=next_settled.offset, mtime_ns=2, ctime_ns=2,
            )
            return ledger.LedgerWriterState(node, ledger_generation.key, next_settled, next_generation)

        with patched(
            (builder, "_stable_active", lambda current, *_args: current),
            (builder, "_walk_entries", lambda *_args: (((builder.ROOT_NAME.text, root_generation),), ())),
            (builder, "_parent", lambda *_args: state_parent),
            (builder, "_current_ledger", lambda *_args: ledger_generation),
            (builder, "_rebound_locked_state", lambda *_args: refreshed_locked),
            (fs, "_observe_node", observe),
            (ledger, "_reconcile_ledger", lambda *_args: next(reconciliations)),
            (ledger, "_append_leased_record", append_leased),
        ):
            marked = builder._mark_leased(owned, "5" * 64, 7, "7" * 64, 512, 1, control)
        matrix_case()
        assert marked.locked is refreshed_locked
        assert builder._terminal_record(marked.active).record_type == "leased" and len(appended) == 1
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
    active = builder.ActiveLedger(
        ledger_node, (object(),), SimpleNamespace(generation=ledger_node.generation, settled=object()),
    )
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


def operation_parent_transition_tests():
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    retained, reference, _parent = graph_fixture()
    held = lease.RetainedRootfsLease(reference, retained)
    old_prefix = retained.base_chain.components[0].node
    nodes = tuple(held_node(200 + index, f"prefix-{index}") for index in range(9))
    base = fs.HeldChain(retained.base_chain.anchor, tuple(
        fs.ChainComponent(fs._name(f"p{index}"), node) for index, node in enumerate(nodes)))
    owned = retained.owned
    locked_chain = fs.HeldChain(base.anchor, base.components + (
        fs.ChainComponent(builder.STATE_NAME, owned.locked.state),))
    retained.base_chain = base
    retained.owned = builder.OwnedOperation(
        builder.LockedState(locked_chain, owned.locked.state, owned.locked.lock),
        owned.active, owned.operation, owned.root, owned.operation_name)
    fs._close_node(old_prefix)
    before = nodes[builder.COMPLETION_INDEX].generation
    expected_names = tuple(sorted(name.raw for name in (
        lease.kata_operation.ARTIFACTS_NAME, lease.kata_operation.ROOTFS_NAME,
        lease.kata_operation.IMMUTABLE_PREPARATION_NAME,
        lease.kata_operation.RUNTIME_NAME, lease.kata_operation.STATE_NAME)))
    def snapshot(nlink):
        return SimpleNamespace(raw_names=expected_names, generation=fs.HostGeneration(
            before.key, before.mode, before.uid, before.gid, nlink,
            before.size, before.mtime_ns, before.ctime_ns + 1))
    with patched((fs, "_enumerate_stable", lambda *_args: snapshot(before.nlink))):
        rejected(lambda: lease._admit_operation_parent_transition(held, control))
    with patched(
        (fs, "_enumerate_stable", lambda *_args: snapshot(before.nlink + 1)),
        (fs, "_revalidate_chain", lambda *_args: None),
    ):
        lease._admit_operation_parent_transition(held, control)
    assert retained.base_chain.components[builder.COMPLETION_INDEX].node.generation.nlink == before.nlink + 1
    assert retained.owned.locked.chain.components[-1].node is retained.owned.locked.state
    close_graph_nodes(retained)
    matrix_case(2)


def alias_and_close_tests():
    retained, reference, _state_parent = graph_fixture()
    refreshed_base = fs.HeldChain(retained.base_chain.anchor, tuple(
        fs.ChainComponent(component.name, component.node)
        for component in retained.base_chain.components))
    refreshed = build.RetainedBuild(retained.owned, refreshed_base)
    refreshed.disposition = retained.disposition
    assert lease._topology(refreshed, reference) is retained.owned
    close_graph_nodes(refreshed)
    matrix_case()

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
        primaries = {}

        def inject(name):
            error = RuntimeError(name)
            primaries[name] = error
            raise error

        def abandon(bundle, primary):
            events.append(("abandon", bundle.disposition, primary.args[0]))
            if fault in {"abandon-return", "preserve-return"}: return None
            if fault == "abandon-secondary":
                secondary = RuntimeError("abandon-secondary")
                secondary.__cause__ = primary
                raise secondary
            raise primary

        def preserve(bundle, primary=None):
            events.append(("preserve", bundle.disposition, primary.args[0]))
            bundle.disposition = "uncertain"
            if fault == "preserve-return": return None
            if fault == "preserve-secondary":
                secondary = RuntimeError("preserve-secondary")
                secondary.__cause__ = primary
                raise secondary
            raise primary

        def topology(bundle, _reference=None):
            events.append(("topology", bundle.disposition, bundle.owned.name))
            if fault == "active-stable" and bundle.disposition == "owned": inject(fault)
            if fault == "post-mark-topology" and bundle.owned is refreshed: inject(fault)
            return bundle.owned

        def stable(bundle, _reference, _control, status):
            events.append(("stable", bundle.disposition, status))
            if fault == "active-stable": inject(fault)
            return None

        def mark(owned, *args):
            events.append(("mark", retained.disposition, owned.name, args))
            assert retained.disposition == "uncertain"
            if fault is not None and (fault.startswith("mark-") or fault.startswith("preserve-")):
                inject(fault)
            return refreshed

        stable_passes = {"count": 0}

        def stable_pass(value, _control):
            stable_passes["count"] += 1
            events.append(("lease-pass", value.retained.disposition))
            if fault == "post-mark-pass": inject(fault)
            return value.reference

        def equal(_first, _second):
            events.append(("equal", retained.disposition))
            if fault in {"equal", "abandon-secondary", "abandon-return"}: inject(fault)

        def bootstrap(*_args):
            events.append(("bootstrap",))
            if fault == "bootstrap": inject(fault)
        def load_pins():
            if fault == "pins": inject(fault)
            return pins
        def build_one(*_args):
            events.append(("build-one",))
            if fault == "build-first": inject(fault)
            if type(fault) is str and fault.startswith("build-first-outcome-"):
                outcome = fault.removeprefix("build-first-outcome-")
                stage = "files" if outcome == "failed-files" else "internal"
                outcome = "failed" if outcome == "failed-files" else outcome
                error = build.BuildAttemptError(outcome, stage)
                primaries[fault] = error
                raise error
            return candidate
        def build_two(*_args):
            events.append(("build-two",))
            if fault == "build-second": inject(fault)
            if type(fault) is str and fault.startswith("build-second-outcome-"):
                outcome = fault.removeprefix("build-second-outcome-")
                error = build.BuildAttemptError(outcome)
                primaries[fault] = error
                raise error
            return candidate, retained
        def pinned(*_args):
            events.append(("pin", retained.disposition))
            if fault == "pin-check": inject(fault)
        token_values = iter(("6" * 64, "7" * 64))
        with patched(
            (lease, "_bootstrap_state", bootstrap),
            (publication, "_load_pins", load_pins),
            (lease.secrets, "token_hex", lambda _size: next(token_values)),
            (build, "_build_once", build_one),
            (build, "_build_once_retained", build_two),
            (build, "_require_equal_builds", equal),
            (build, "_require_pinned", pinned),
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
                try: lease._acquire(approval, control)
                except lease.RootfsAcquireError as error:
                    expected = {
                        "bootstrap": "bootstrap", "pins": "pins",
                        "build-first": "build-first", "build-second": "build-second",
                        **{
                            f"build-{ordinal}-outcome-{outcome}": f"build-{ordinal}-{detail}"
                            for ordinal in ("first", "second")
                            for outcome, detail in lease.ROOTFS_BUILD_OUTCOMES.items()
                        },
                        "build-first-outcome-failed-files": "build-first-files",
                        "equal": "equality", "pin-check": "pin-check", "active-stable": "topology",
                        "mark-prevalidation": "lease-mark", "mark-append": "lease-mark",
                        "mark-readback": "lease-mark", "post-mark-topology": "lease-mark",
                        "post-mark-pass": "lease-verify", "abandon-secondary": "equality",
                        "abandon-return": "equality", "preserve-secondary": "lease-mark",
                        "preserve-return": "lease-mark",
                    }
                    assert error.stage == expected[fault] and error.__cause__ is not None
                    if fault.endswith(("secondary", "return")):
                        if fault.endswith("secondary"):
                            assert error.__cause__.__cause__ is primaries[fault]
                        else:
                            assert error.__cause__ is primaries[fault]
                    else:
                        assert error.__cause__ is primaries[fault]
                else: raise AssertionError("rootfs acquisition fault was accepted")
        return events, retained

    outcome_faults = tuple(
        f"build-{ordinal}-outcome-{outcome}"
        for ordinal in ("first", "second") for outcome in lease.ROOTFS_BUILD_OUTCOMES)
    for fault in ("bootstrap", "pins", "build-first", "build-second", *outcome_faults,
                  "build-first-outcome-failed-files"):
        events, retained = run(fault)
        matrix_case()
        assert not any(event[0] in {"abandon", "preserve"} for event in events)
    for fault in ("equal", "pin-check", "active-stable", "abandon-secondary", "abandon-return"):
        events, retained = run(fault)
        matrix_case()
        assert sum(event[0] == "abandon" and event[1] == "owned" for event in events) == 1, (fault, events)
        assert not any(event[0] == "preserve" for event in events)
        assert retained.disposition == "owned"
    for fault in ("mark-prevalidation", "mark-append", "mark-readback", "post-mark-topology",
                  "post-mark-pass", "preserve-secondary", "preserve-return"):
        events, retained = run(fault)
        matrix_case()
        mark_index = next(index for index, event in enumerate(events) if event[0] == "mark")
        assert events[mark_index][1] == "uncertain"
        assert sum(event[0] == "preserve" and event[1] in {"uncertain", "transferred"} for event in events) == 1, (fault, events)
        assert sum(event[0] == "abandon" for event in events) == (fault == "preserve-return")
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

    # A freshly reopened durable authorization receives the same full content
    # verification, but both graph passes require the authorized phase.
    active = retained.owned.active
    authorized_terminal = SimpleNamespace(record_type="release-authorized")
    retained.owned = dataclasses.replace(
        retained.owned, active=dataclasses.replace(active, records=(authorized_terminal,)),
    )
    phases = []
    with patched(
        (lease, "_stable_graph", lambda value, ref, passed_control, status: phases.append(status)),
        (lease, "_stable_lease_pass", lambda *_args: (_ for _ in ()).throw(AssertionError("leased-only pass"))),
        (plan, "load_verified_build_inputs", lambda: authority),
        (materializer, "_postwalk", lambda *_args: 1),
        (plan, "revalidate_build_inputs", lambda loaded: fresh),
        (canonical, "_manifest", lambda value: manifest),
        (publication, "_load_pins", lambda: exact_pins),
    ):
        assert lease._verify(held, control) is reference
    assert phases == ["release-authorized", "release-authorized"]
    matrix_case()
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
        active = SimpleNamespace(
            node=active_node,
            records=SimpleNamespace(legal=SimpleNamespace(phase="leased", return_phase=None, lease_snapshot=object())),
        )
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
            (builder, "_first_record", lambda *_args: SimpleNamespace(body_value=lambda: {
                "source_revision": approval.revision, "source_manifest_sha256": approval.manifest_sha256,
            })),
            (builder.fs, "_verify_source_bundle", lambda *_args: None),
            (builder, "_source", lambda *_args: object()),
            (builder, "_open_cleanup_session", lambda *_args: (_ for _ in ()).throw(builder.BuilderError())),
            (builder, "_close", close),
            (builder, "_release_lock", release),
            (builder, "_cleanup_active", forbidden),
            (builder, "_resume_observed", forbidden),
            (builder, "_resume_entry_remove", forbidden),
            (builder, "_retire", forbidden),
            (builder, "_finish_operation_absent", forbidden),
            (builder, "_unlink_ledger", forbidden),
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


def assert_fresh_recovery_route(status):
    operation_name = ledger._operation_name("a" * 64)
    state = object()
    operation = SimpleNamespace(identity_fd=SimpleNamespace(disposition="open"))
    locked = SimpleNamespace(state=state)
    active = SimpleNamespace(
        records=SimpleNamespace(legal=SimpleNamespace(phase="active", return_phase=None, lease_snapshot=None)),
    )
    session = SimpleNamespace(status=status, active=active)
    state_names = [builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text, builder.LEDGER_NAME.text]
    if status not in {"operation-absence-settleable", "retirable", "retired"}:
        state_names.append(operation_name)
    names = tuple(fs._name(name) for name in state_names)
    snapshot = SimpleNamespace(raw_names=tuple(name.raw for name in names), names=names)
    routes = []

    def route(name):
        return lambda *_args: routes.append(name)

    with patched(
        (builder, "_acquire_lock", lambda *_args: locked),
        (builder.fs, "_enumerate_stable", lambda *_args: snapshot),
        (builder, "_read_active_ledger", lambda *_args: active),
        (builder, "_first_record", lambda *_args: SimpleNamespace(body_value=lambda: {
            "source_revision": "b" * 40, "source_manifest_sha256": "c" * 64,
        })),
        (builder.fs, "_verify_source_bundle", lambda *_args: None), (builder, "_source", lambda *_args: object()),
        (builder, "_token", lambda *_args: "a" * 64), (builder.fs, "_open_path_node", lambda *_args: operation),
        (builder, "_open_cleanup_session", lambda *_args: (routes.append("fresh-open") or session)),
        (builder, "_cleanup_active", route("active")), (builder, "_resume_absent_create", route("entry-absent")),
        (builder, "_resume_observed", route("observed")), (builder, "_resume_entry_remove", route("remove")),
        (builder, "_retire", route("operation-remove")),
        (builder, "_finish_operation_absent", route("operation-absent")),
        (builder, "_retire_absent", route("retirable")), (builder, "_unlink_ledger", route("retired")),
        (builder, "_release_lock", lambda *_args: None),
    ):
        builder._recover_locked(object(), state, object())
    expected = "active" if status in {"active", "release-authorized"} else (
        "entry-absent" if status == "entry-absent" else "observed" if status.endswith("settleable") and not status.startswith(("remove-absence", "hardlink-remove-absence", "operation-absence")) else
        "remove" if status in {"remove-retry", "remove-absence-settleable", "hardlink-remove-absence-settleable"} else
        "operation-remove" if status == "operation-remove-retry" else "operation-absent" if status == "operation-absence-settleable" else status
    )
    assert routes == ["fresh-open", expected]


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
        ("create-abort", "create-abort", "prelease"),
        ("operation-abort", "operation-abort", "prelease"),
    )
    boundaries = (
        "identity-before", "before-write", "partial-write", "after-write-before-fsync",
        "fsync", "rollback-success", "rollback-failure", "readback", "identity-after", "success",
    )
    for transition_class, record_type, origin in classes:
        for boundary in boundaries:
            events = []
            previous = ledger.SettledBytes(2, 10, "a" * 64)
            following = ledger.SettledBytes(3, 16, "b" * 64)
            active = SimpleNamespace(writer=SimpleNamespace(settled=previous), node=SimpleNamespace(operation_fd=SimpleNamespace(number=7)))
            appended = SimpleNamespace(writer=SimpleNamespace(settled=following), node=active.node)
            session = SimpleNamespace(disposition="active", active=active, origin=origin)
            fake_control = SimpleNamespace(check=lambda: None)
            bindings = {"count": 0}

            def binding(current, _control, _phase=None):
                assert current is session and current.disposition == "active"
                bindings["count"] += 1
                events.append(("identity", bindings["count"]))
                if boundary == "identity-before" and bindings["count"] == 1:
                    raise OSError(boundary)
                if boundary == "identity-after" and bindings["count"] == 2:
                    raise OSError(boundary)

            def append(current, kind, _body, _control):
                events.append(("append", kind))
                if boundary in {"before-write", "partial-write", "after-write-before-fsync", "fsync", "rollback-success", "rollback-failure"}:
                    raise OSError(boundary)
                return appended

            def pread(*_args):
                events.append(("readback", boundary))
                return b"bad" if boundary == "readback" else b"record"

            counter_before = fs.structural_counter_snapshot()
            with patched(
                (builder, "_ledger_binding", binding),
                (builder, "_append", append),
                (builder.ledger.LedgerProposal, "create", lambda *_args: object()),
                (builder.ledger, "_encode_proposal", lambda *_args: b"record"),
                (builder.os, "pread", pread),
            ):
                if boundary == "success":
                    builder._session_append(session, record_type, {}, fake_control)
                    assert session.active is appended and session.disposition == "active"
                else:
                    rejected(lambda: builder._session_append(session, record_type, {}, fake_control))
                    assert session.disposition == "invalid"
                    assert session.active is (appended if boundary == "identity-after" else active)
                    rejected(lambda: builder._session_append(session, record_type, {}, fake_control))
            delta = fs.structural_counter_delta(counter_before, fs.structural_counter_snapshot())
            assert delta["complete_legal_folds"] == delta["complete_walks"] == 0
            matrix_case()

def cleanup_regular_fault_tests():
    seams = (
        "identity", "deadline", "cancellation", "pre-snapshot-chain", "intent", "mutation",
        "parent-fsync", "post-snapshot-chain", "observed", "settled", "close",
    )
    for seam in seams:
        child = generation(260, "file", 0o600, 1)
        operation = generation(261)
        names = {"child"}
        session = SimpleNamespace(
            disposition="active", origin="prelease", active=object(), locked=object(), operation=object(),
            owned={"child": child}, parents={"": ledger.LedgerParent(operation, ("child",))},
            groups={}, operation_generation=operation,
        )
        events = []
        revalidations = {"count": 0}

        def require(current, _phase=None):
            assert current.disposition == "active"

        def session_parent(*_args):
            events.append("identity")
            if seam in {"identity", "deadline", "cancellation"}:
                raise OSError(seam)
            return object(), (object(),), fs._name("child"), object()

        def snapshot(*_args):
            return fs.DirectoryNamesSnapshot(
                session.operation_generation, tuple(fs._name(name) for name in sorted(names)),
            )

        def revalidate(*_args):
            revalidations["count"] += 1
            label = "pre-snapshot-chain" if revalidations["count"] == 1 else "post-snapshot-chain" if revalidations["count"] == 3 else None
            if seam == label:
                raise OSError(seam)

        def append(_session, record_type, _body, _control):
            events.append("attempt-" + record_type)
            if seam == {"remove-intent": "intent", "remove-observed": "observed", "remove-settled": "settled"}[record_type]:
                raise OSError(seam)
            events.append(record_type)

        def remove(_parent, _name, _expected, _control):
            events.append("mutation")
            names.remove("child")
            session.operation_generation = dataclasses.replace(operation, ctime_ns=2)
            if seam in {"mutation", "parent-fsync"}:
                events.append("parent-fsync")
                raise OSError(seam)

        def close(_node):
            events.append("close")
            if seam == "close":
                raise OSError(seam)

        with patched(
            (builder, "_session_require", require), (builder, "_session_parent", session_parent),
            (builder, "_parent_snapshot", snapshot), (builder.fs, "_revalidate_chain", revalidate),
            (builder, "_session_append", append), (builder, "_remove_name", remove),
            (builder, "_chain_after_parent", lambda chain, *_args: chain),
            (builder, "_token", lambda *_args: "a" * 64), (builder, "_close", close),
        ):
            rejected(lambda: builder._finish_remove(session, "child", child, False, SimpleNamespace(check=lambda: None)))
            mutations = events.count("mutation")
            rejected(lambda: builder._finish_remove(session, "child", child, False, SimpleNamespace(check=lambda: None)))
        assert session.disposition == "invalid" and events.count("mutation") == mutations <= 1
        durable = [event for event in events if event in {"remove-intent", "remove-observed", "remove-settled"}]
        fresh = "active"
        if "remove-settled" in durable:
            fresh = "active-absent"
        elif "remove-observed" in durable:
            fresh = "remove-settleable"
        elif "remove-intent" in durable:
            fresh = "remove-absence-settleable" if "child" not in names else "remove-retry"
        assert fresh in {"active", "active-absent", "remove-settleable", "remove-absence-settleable", "remove-retry"}
        assert_fresh_recovery_route("active" if fresh == "active-absent" else fresh)
        matrix_case()


def cleanup_hardlink_fault_tests():
    for seam in ("identity", "intent", "post-intent-alias-drift", "post-intent-target-drift", "mutation", "target-fsync", "parent-fsync", "observed", "settled", "close"):
        operation = generation(270)
        linked = generation(271, "file", 0o600, 3)
        reduced = dataclasses.replace(linked, nlink=2, ctime_ns=2)
        names = {"alias-one", "alias-two", "target"}
        parent_node = SimpleNamespace(operation_fd=SimpleNamespace(role="parent", number=8))
        target_parent_node = SimpleNamespace(operation_fd=SimpleNamespace(role="target-parent", number=9))
        target_node = SimpleNamespace(generation=linked, identity_fd=object(), operation_fd=SimpleNamespace(role="target"))
        alias_node = SimpleNamespace(generation=linked, identity_fd=object(), operation_fd=SimpleNamespace(role="alias"))
        session = SimpleNamespace(
            disposition="active", origin="prelease", active=object(), locked=object(), operation=object(),
            owned={name: linked for name in names}, parents={"": ledger.LedgerParent(operation, tuple(sorted(names)))},
            groups={"target": ["alias-one", "alias-two"]}, operation_generation=operation,
        )
        events = []

        def require(current, _phase=None):
            assert current.disposition == "active"

        def session_parent(*_args):
            if seam == "identity":
                raise OSError(seam)
            return parent_node, (object(),), fs._name("alias-two"), "alias-parent-chain"

        def snapshot(*_args):
            return fs.DirectoryNamesSnapshot(session.operation_generation, tuple(fs._name(name) for name in sorted(names)))

        def append(_session, record_type, _body, _control):
            events.append("attempt-" + record_type)
            if seam == {"remove-intent": "intent", "remove-observed": "observed", "remove-settled": "settled"}[record_type]:
                raise OSError(seam)
            events.append(record_type)

        def unlink(*_args, **_kwargs):
            events.append("mutation")
            names.remove("alias-two")
            session.operation_generation = dataclasses.replace(operation, ctime_ns=2)
            if seam == "mutation":
                raise OSError(seam)

        def fsync(descriptor, _control):
            events.append(descriptor.role + "-fsync")
            if seam == descriptor.role + "-fsync":
                raise OSError(seam)

        def open_node(_parent, name, _kind, _control):
            return target_node if name.text == "target" else alias_node

        child_checks = {"alias-two": 0, "target": 0}

        def revalidate(chain, *_args):
            if type(chain) is tuple and chain[0] == "child":
                child_checks[chain[1]] += 1
                expected = "post-intent-alias-drift" if chain[1] == "alias-two" else "post-intent-target-drift"
                if seam == expected and child_checks[chain[1]] == 3:
                    raise OSError(seam)

        def close(_node):
            events.append("close")
            if seam == "close":
                raise OSError(seam)

        caught = []
        with patched(
            (builder, "_session_require", require), (builder, "_session_parent", session_parent),
            (builder, "_open_relative_parent", lambda *_args: (target_parent_node, (), fs._name("target"))),
            (builder, "_relative_parent_chain", lambda *_args: "target-parent-chain"),
            (builder, "_parent_snapshot", snapshot), (builder, "_session_append", append),
            (builder.fs, "_revalidate_chain", revalidate),
            (builder.fs, "_open_path_node", open_node), (builder.fs, "_observe_node", lambda *_args: reduced),
            (builder, "_fsync", fsync), (builder.os, "unlink", unlink),
            (builder, "_delta_for_chain", lambda *_args: None),
            (builder, "_chain_after_parent", lambda chain, *_args: chain),
            (builder, "_chain_with_child", lambda chain, name, _node: ("child", name.text, chain)),
            (builder, "_token", lambda *_args: "a" * 64), (builder, "_close", close),
        ):
            try:
                builder._finish_hardlink_remove(session, "alias-two", "target", linked, SimpleNamespace(check=lambda: None))
            except BaseException as error:
                caught.append(error)
            else:
                raise AssertionError("hardlink fault accepted")
            mutations = events.count("mutation")
            rejected(lambda: builder._finish_hardlink_remove(
                session, "alias-two", "target", linked, SimpleNamespace(check=lambda: None),
            ))
        assert session.disposition == "invalid" and events.count("mutation") == mutations <= 1
        if seam in {"post-intent-alias-drift", "post-intent-target-drift"}:
            assert mutations == 0 and "remove-intent" in events
        if "remove-observed" in events or "remove-settled" in events or seam == "close":
            assert session.owned.get("alias-one") == session.owned.get("target") == reduced, (seam, session.owned, events, caught, getattr(caught[0], "primary", None))
        durable = [event for event in events if event in {"remove-intent", "remove-observed", "remove-settled"}]
        recovered = "active" if "remove-settled" in durable else "remove-settleable" if "remove-observed" in durable else "hardlink-remove-absence-settleable" if "mutation" in events and "remove-intent" in durable else "remove-retry" if "remove-intent" in durable else "active"
        assert_fresh_recovery_route(recovered)
        matrix_case()


def cleanup_absent_fault_tests():
    for seam in ("identity", "post-snapshot-chain", "target-fsync", "parent-fsync", "observed", "settled", "close"):
        operation = generation(280)
        linked = generation(281, "file", 0o600, 2)
        target_generation = dataclasses.replace(linked, nlink=1, ctime_ns=2)
        post = ledger.LedgerParent(operation, ("target",))
        parent_node = SimpleNamespace(operation_fd=SimpleNamespace(role="parent"))
        target = SimpleNamespace(generation=target_generation, identity_fd=object(), operation_fd=SimpleNamespace(role="target"))
        intent = {
            "token": "a" * 64, "path": "alias", "kind": "hardlink",
            "parent": ledger._parent_value(ledger.LedgerParent(dataclasses.replace(operation, ctime_ns=0), ("alias", "target"))),
            "child": ledger._generation_value(linked), "target_path": "target",
        }
        session = SimpleNamespace(
            disposition="active", origin="prelease", active=object(), locked=object(), operation=object(),
            owned={"target": target_generation}, parents={"": post}, groups={"target": ["alias"]},
            operation_generation=operation,
        )
        events = []
        revalidations = {"count": 0}

        def require(current, _phase=None):
            assert current.disposition == "active"

        def binding(*_args):
            if seam == "identity":
                raise OSError(seam)

        def revalidate(*_args):
            revalidations["count"] += 1
            if seam == "post-snapshot-chain" and revalidations["count"] == 2:
                raise OSError(seam)

        def fsync(descriptor, _control):
            events.append(descriptor.role + "-fsync")
            if seam == descriptor.role + "-fsync":
                raise OSError(seam)

        def append(_session, record_type, _body, _control):
            events.append("attempt-" + record_type)
            if seam == {"remove-observed": "observed", "remove-settled": "settled"}[record_type]:
                raise OSError(seam)
            events.append(record_type)

        def close(_node):
            events.append("close")
            if seam == "close":
                raise OSError(seam)

        with patched(
            (builder, "_session_require", require), (builder, "_session_binding", binding),
            (builder, "_terminal_record", lambda *_args: SimpleNamespace(body_value=lambda: intent)),
            (builder, "_open_relative_parent", lambda _operation, path, _control: (
                parent_node, (), fs._name(path.rpartition("/")[2]),
            )),
            (builder, "_relative_parent_chain", lambda *_args: object()),
            (builder.fs, "_revalidate_chain", revalidate),
            (builder.fs, "_enumerate_stable", lambda *_args: SimpleNamespace(raw_names=(b"target",))),
            (builder, "_parent", lambda *_args: post),
            (builder.fs, "_open_path_node", lambda *_args: target),
            (builder.fs, "_observe_node", lambda *_args: target_generation),
            (builder, "_chain_with_child", lambda *_args: object()),
            (builder, "_fsync", fsync), (builder, "_session_append", append),
            (builder, "_token", lambda *_args: "a" * 64), (builder, "_close", close),
        ):
            rejected(lambda: builder._finish_absent_remove(session, SimpleNamespace(check=lambda: None)))
            appends = tuple(event for event in events if event.startswith("attempt-"))
            rejected(lambda: builder._finish_absent_remove(session, SimpleNamespace(check=lambda: None)))
        assert session.disposition == "invalid"
        assert tuple(event for event in events if event.startswith("attempt-")) == appends
        recovered = "active" if "remove-settled" in events else "remove-settleable" if "remove-observed" in events else "hardlink-remove-absence-settleable"
        assert_fresh_recovery_route(recovered)
        matrix_case()


def cleanup_retirement_fault_tests():
    for seam in ("operation-child-drift", "pre-snapshot-chain", "intent", "close", "mutation", "parent-fsync", "post-snapshot-chain", "operation-absent", "boundary-B"):
        operation_generation = generation(290)
        state_generation = generation(291)
        operation_name = ledger._operation_name("a" * 64)
        names = {builder.LEDGER_NAME.text, builder.LOCK_NAME.text, builder.STATE_SENTINEL_NAME.text, operation_name}
        operation = SimpleNamespace(identity_fd=object(), operation_fd=SimpleNamespace(role="operation"))
        locked = SimpleNamespace(state=SimpleNamespace(operation_fd=SimpleNamespace(role="state")))
        session = SimpleNamespace(
            disposition="active", origin="prelease", active=object(), locked=locked, operation=operation,
            owned={}, groups={}, operation_generation=operation_generation,
            state_parent=ledger.LedgerParent(state_generation, tuple(sorted(names))),
        )
        events = []
        revalidations = {"count": 0}
        chain_generation = dataclasses.replace(operation_generation, ctime_ns=2) if seam == "operation-child-drift" else operation_generation
        operation_chain = SimpleNamespace(components=(SimpleNamespace(node=SimpleNamespace(generation=chain_generation)),))

        def require(current, _phase=None):
            assert current.disposition == "active"

        def snapshot(*_args):
            return fs.DirectoryNamesSnapshot(state_generation, tuple(fs._name(name) for name in sorted(names)))

        def revalidate(*_args):
            revalidations["count"] += 1
            label = "pre-snapshot-chain" if revalidations["count"] == 3 else "post-snapshot-chain" if revalidations["count"] == 6 else None
            if seam == label:
                raise OSError(seam)

        def append(_session, record_type, _body, _control):
            events.append("attempt-" + record_type)
            label = "intent" if record_type == "operation-remove-intent" else "operation-absent"
            if seam == label:
                raise OSError(seam)
            events.append(record_type)

        def close(_node):
            events.append("close")
            if seam == "close":
                raise OSError(seam)

        def remove(*_args):
            events.append("mutation")
            names.remove(operation_name)
            if seam in {"mutation", "parent-fsync"}:
                raise OSError(seam)

        def boundary(*_args):
            events.append("boundary-B")
            if seam == "boundary-B":
                raise OSError(seam)

        with patched(
            (builder, "_session_require", require), (builder, "_held_operation_chain", lambda *_args: operation_chain),
            (builder, "_state_chain", lambda *_args: object()),
            (builder.fs, "_revalidate_chain", revalidate),
            (builder.fs, "_enumerate_stable", lambda *_args: SimpleNamespace(names=())),
            (builder, "_parent_snapshot", snapshot), (builder, "_session_append", append),
            (builder.fs, "_observe_node", lambda *_args: operation_generation),
            (builder, "_close", close), (builder, "_remove_name", remove),
            (builder, "_retire_absent", boundary), (builder, "_token", lambda *_args: "a" * 64),
        ):
            rejected(lambda: builder._retire(session, SimpleNamespace(check=lambda: None)))
            mutations = events.count("mutation")
            rejected(lambda: builder._retire(session, SimpleNamespace(check=lambda: None)))
        assert session.disposition == "invalid" and events.count("mutation") == mutations <= 1
        if seam == "operation-child-drift":
            assert mutations == 0 and "attempt-operation-remove-intent" not in events
        recovered = "retirable" if "operation-absent" in events else "operation-absence-settleable" if "mutation" in events and "operation-remove-intent" in events else "operation-remove-retry" if "operation-remove-intent" in events else "active"
        assert_fresh_recovery_route(recovered)
        matrix_case()

    for seam in ("boundary-B", "retired", "boundary-C", "ledger-close", "ledger-unlink", "final-zero"):
        incoming = SimpleNamespace(disposition="active", active=object(), locked=object(), origin="prelease")
        events = []
        opens = {"count": 0}

        def opening(*_args):
            opens["count"] += 1
            label = "boundary-B" if opens["count"] == 1 else "boundary-C"
            events.append(label)
            if seam == label:
                raise OSError(seam)
            return SimpleNamespace(
                disposition="active", active=object(), locked=object(), origin="prelease",
                status="retirable" if opens["count"] == 1 else "retired", state_parent=object(),
            )

        def append(*_args):
            events.append("retired")
            if seam == "retired":
                raise OSError(seam)

        def unlink(*_args):
            for label in ("ledger-close", "ledger-unlink", "final-zero"):
                events.append(label)
                if seam == label:
                    raise OSError(seam)

        with patched(
            (builder, "_open_cleanup_session", opening), (builder, "_session_append", append),
            (builder, "_unlink_ledger", unlink), (builder, "_token", lambda *_args: "a" * 64),
            (builder, "_p", lambda *_args: {}),
        ):
            rejected(lambda: builder._retire_absent(incoming, object()))
            previous = tuple(events)
            rejected(lambda: builder._retire_absent(incoming, object()))
        assert incoming.disposition == "invalid" and tuple(events) == previous
        assert_fresh_recovery_route("retired" if "retired" in events else "retirable")
        matrix_case()

def cleanup_model_tests():
    operation = generation(300)
    directory = generation(301)
    child = generation(302, "file", 0o600, 1)
    changed_directory = dataclasses.replace(directory, ctime_ns=2)
    post = ledger.LedgerParent(changed_directory, ())
    session = SimpleNamespace(
        owned={"dir": directory, "dir/child": child},
        parents={"": ledger.LedgerParent(operation, ("dir",)), "dir": ledger.LedgerParent(directory, ("child",))},
        operation_generation=operation,
    )
    builder._settle_removed_model(session, "dir/child", post)
    assert session.owned == {"dir": changed_directory} and session.parents["dir"] == post
    assert session.operation_generation == operation

    linked = generation(303, "file", 0o600, 3)
    target = dataclasses.replace(linked, nlink=2, ctime_ns=2)
    changed_operation = dataclasses.replace(operation, ctime_ns=2)
    top = SimpleNamespace(
        owned={"alias": linked, "alias-two": linked, "target": linked},
        parents={"": ledger.LedgerParent(operation, ("alias", "alias-two", "target"))},
        groups={"target": ["alias", "alias-two"]},
        operation_generation=operation,
    )
    top_post = ledger.LedgerParent(changed_operation, ("alias", "target"))
    builder._settle_removed_model(top, "alias-two", top_post, "target", target)
    assert top.groups["target"].pop() == "alias-two"
    assert top.owned == {"alias": target, "target": target} and top.parents == {"": top_post}
    final_target = dataclasses.replace(target, nlink=1, ctime_ns=3)
    final_operation = dataclasses.replace(changed_operation, ctime_ns=3)
    final_parent = ledger.LedgerParent(final_operation, ("target",))
    builder._settle_removed_model(top, "alias", final_parent, "target", final_target)
    assert top.groups["target"].pop() == "alias"
    assert top.owned == {"target": final_target} and top.parents == {"": final_parent}
    assert top.operation_generation == final_operation
    matrix_case(3)


def cleanup_phase_truth_table_tests():
    token = "7" * 64
    operation_name = ledger._operation_name(token)
    before = ledger.LedgerParent(generation(360), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text))
    state_parent = ledger.LedgerParent(generation(360, ctime=2), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text, operation_name))
    absent_parent = ledger.LedgerParent(generation(360, ctime=3), (builder.LEDGER_NAME.text, builder.LOCK_NAME.text))
    operation = generation(361)
    operation_parent = ledger.LedgerParent(operation, ())
    genesis = ("genesis", {
        "token": token, "source_revision": "1" * 40, "source_manifest_sha256": "2" * 64,
        "state_parent": ledger._parent_value(before),
        "ledger_key": {"mount_id": 1, "device": 1, "inode": 362, "kind": "file"},
    })
    ready = ("genesis-settled", {"token": token, "state_parent": ledger._parent_value(before)})
    active_bodies = (
        genesis, ready,
        ("operation-create-intent", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(before)}),
        ("operation-create-observed", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(state_parent), "operation": ledger._generation_value(operation)}),
        ("operation-create-settled", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(state_parent), "operation": ledger._generation_value(operation)}),
    )
    cases = {
        "active": active_bodies,
        "intent": active_bodies + (("create-intent", {"token": token, "path": "child", "kind": "file", "parent": ledger._parent_value(operation_parent)}),),
        "operation-remove": active_bodies + (("operation-remove-intent", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(state_parent), "operation": ledger._generation_value(operation)}),),
        "operation-absent": active_bodies + (
            ("operation-remove-intent", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(state_parent), "operation": ledger._generation_value(operation)}),
            ("operation-absent", {"token": token, "operation_name": operation_name, "state_parent": ledger._parent_value(absent_parent)}),
        ),
        "aborted": (genesis, ready, ("genesis-abort", {"token": token, "state_parent": ledger._parent_value(before)})),
        "retired": (genesis, ready, ("genesis-abort", {"token": token, "state_parent": ledger._parent_value(before)}),
                    ("retired", {"token": token, "state_parent": ledger._parent_value(before)})),
    }
    sessions = {}
    for name, bodies in cases.items():
        raw = b""
        settled = ledger.INITIAL_BYTES
        for record_type, body in bodies:
            line = ledger._encode_proposal(ledger.LedgerProposal.create(record_type, body), settled)
            raw += line
            settled = ledger.SettledBytes(settled.sequence + 1, settled.offset + len(line), hashlib.sha256(line).hexdigest())
        history = ledger._parse_ledger_history(raw)
        node = held_node(700 + len(sessions), "phase-" + name, "file", 0o600, 1, settled.offset)
        writer = ledger.LedgerWriterState(node, node.generation.key, settled, node.generation)
        sessions[name] = builder.CleanupSession(
            builder.ActiveLedger(node, history, writer), None, None, "prelease", name, {}, {}, {}, None, before,
        )
    builder._session_require(sessions["active"])
    builder._session_require(sessions["intent"])
    builder._session_require(sessions["operation-remove"])
    for name in ("operation-absent", "aborted", "retired"):
        rejected(lambda name=name: builder._session_require(sessions[name]))
    builder._session_require(sessions["operation-absent"], "operation-absent")
    builder._session_require(sessions["aborted"], ("aborted", "operation-absent"))
    builder._session_require(sessions["retired"], "retired")
    released = dataclasses.replace(sessions["active"], origin="release-authorized")
    rejected(lambda: builder._session_require(released))
    for session in sessions.values():
        close_if_open(session.active.node)
    matrix_case(10)


def cleanup_session_entrance_tests():
    operation = generation(320)
    child = generation(321, "file", 0o600, 1)
    root_parent = ledger.LedgerParent(operation, ("child",))
    state_parent = ledger.LedgerParent(generation(319), tuple(sorted((builder.LEDGER_NAME.text, builder.LOCK_NAME.text, ledger._operation_name("a" * 64)))))
    observations = ledger.ReconcileObservations(
        state_parent, ((ledger._operation_name("a" * 64), operation),), (("child", child),),
        generation(322, "file", 0o600, 1, 1), (("", root_parent),),
    )
    terminal = SimpleNamespace(record_type="fixture", body_value=lambda: {})
    legal = SimpleNamespace(phase="active", pending=None, operation_parent=root_parent,
                            parents=ledger._EMPTY_MAP, groups=ledger._EMPTY_MAP)
    history = SimpleNamespace(legal=legal, terminal=terminal)
    state = ledger.LedgerState(
        "active", "a" * 64, ledger._operation_name("a" * 64), (("child", child),),
        True, "prelease", False, False, "fixture",
    )
    builder._require_cleanup_model(state, observations, history, {})
    hostile_parent = ledger.LedgerParent(operation, ("foreign",))
    rejected(lambda: builder._require_cleanup_model(
        state, dataclasses.replace(observations, parents=(("", hostile_parent),)), history, {},
    ))
    hostile_state = dataclasses.replace(state, owned=())
    rejected(lambda: builder._require_cleanup_model(hostile_state, observations, history, {}))

    created_operation = dataclasses.replace(operation, ctime_ns=2)
    created_parent = ledger.LedgerParent(created_operation, ("child",))
    observed_terminal = SimpleNamespace(record_type="create-observed", body_value=lambda: {
        "token": "a" * 64, "path": "child", "kind": "file",
        "parent": ledger._parent_value(created_parent), "child": ledger._generation_value(child),
    })
    observed_history = SimpleNamespace(
        terminal=observed_terminal,
        legal=SimpleNamespace(phase="create-observed", pending=observed_terminal,
                              operation_parent=ledger.LedgerParent(operation, ()),
                              parents=ledger._EMPTY_MAP, groups=ledger._EMPTY_MAP),
    )
    observed_state = ledger.LedgerState(
        "create-settleable", "a" * 64, ledger._operation_name("a" * 64), (),
        True, "prelease", False, False, "create-observed",
    )
    observed = dataclasses.replace(
        observations, operations=((ledger._operation_name("a" * 64), created_operation),),
        parents=(("", created_parent),),
    )
    builder._require_cleanup_model(observed_state, observed, observed_history, {})
    observed_history.legal.pending = None
    rejected(lambda: builder._require_cleanup_model(observed_state, observed, observed_history, {}))

    snapshot = fs.DirectorySnapshot(operation, (fs._name("child"),), ((fs._name("child"), child),))
    with patched(
        (builder.fs, "_enumerate_stable", lambda *_args: snapshot),
        (builder, "_parent", lambda *_args: (_ for _ in ()).throw(AssertionError("second parent snapshot"))),
    ):
        entries, parents = builder._walk_entries(object(), object())
    assert entries == (("child", child),) and parents == (("", root_parent),)
    matrix_case(4)


def cleanup_complexity_tests():
    count = 128
    names = {f"entry-{index:03d}" for index in range(count)}
    operation = generation(340)
    children = {name: generation(400 + index, "file", 0o600, 1) for index, name in enumerate(sorted(names))}
    session = SimpleNamespace(
        disposition="active", origin="prelease", active=object(), locked=object(), operation=object(),
        groups={}, owned=dict(children), parents={"": ledger.LedgerParent(operation, tuple(sorted(names)))},
        operation_generation=operation,
    )
    events = []
    parent_node = object()

    def require(current, _phase=None):
        assert current.disposition == "active"

    def session_parent(current, path, expected, _control):
        assert path in names and children[path] == expected == current.owned[path]
        return parent_node, (), fs._name(path), object()

    def snapshot(_parent, _control):
        return fs.DirectoryNamesSnapshot(
            session.operation_generation, tuple(fs._name(name) for name in sorted(names)),
        )

    def remove_name(_parent, name, expected, _control):
        assert name.text in names and children[name.text] == expected
        names.remove(name.text)
        session.operation_generation = dataclasses.replace(
            session.operation_generation, ctime_ns=session.operation_generation.ctime_ns + 1,
        )
        events.append(("mutation", name.text))

    def append(_session, record_type, _body, _control):
        events.append(("append", record_type))

    boundaries = {"count": 0}

    def boundary(*_args):
        boundaries["count"] += 1
        return SimpleNamespace(disposition="active", status="active", owned={})

    before = fs.structural_counter_snapshot()
    with patched(
        (builder, "_session_require", require), (builder, "_session_parent", session_parent),
        (builder, "_parent_snapshot", snapshot), (builder, "_session_append", append),
        (builder, "_remove_name", remove_name), (builder, "_chain_after_parent", lambda chain, *_args: chain),
        (builder, "_token", lambda *_args: "a" * 64),
        (builder.fs, "_revalidate_chain", lambda *_args: None),
        (builder, "_open_cleanup_session", boundary),
        (builder, "_retire", lambda *_args: events.append(("retire", None))),
    ):
        builder._cleanup_active(session, SimpleNamespace(check=lambda: None))
    delta = fs.structural_counter_delta(before, fs.structural_counter_snapshot())
    assert sum(event[0] == "mutation" for event in events) == count
    assert [event[1] for event in events if event[0] == "append"] == [
        record for _index in range(count) for record in ("remove-intent", "remove-observed", "remove-settled")
    ]
    assert delta["complete_legal_folds"] == delta["complete_walks"] == 0
    complexity_source = Path(__file__).read_text().split("def cleanup_complexity_tests()", 1)[1].split("\ndef ", 1)[0]
    assert "_structural_" + "increment" not in complexity_source
    assert boundaries["count"] == 1 and events[-1] == ("retire", None)
    assert session.disposition == "finished" and not names and not session.owned
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


def retired_prelease_recovery_test():
    approval = fs.SourceApproval("a" * 40, "b" * 64)
    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    binding, grant = {"kind": "journal-absent"}, object()
    genesis = SimpleNamespace(record_type="genesis", body_value=lambda: {
        "source_revision": approval.revision,
        "source_manifest_sha256": approval.manifest_sha256,
    })
    retired = SimpleNamespace(record_type="retired")
    records = (genesis, retired)
    active = SimpleNamespace(records=SimpleNamespace(legal=SimpleNamespace(phase="retired")))
    fixed_idle = tuple(sorted((builder.STATE_SENTINEL_NAME.raw, builder.LOCK_NAME.raw)))
    names = tuple(sorted((*fixed_idle, builder.LEDGER_NAME.raw)))
    events = []
    patches = (
        patch.object(lease.kata_operation, "_claim_prestage_rootfs", return_value=grant),
        patch.object(lease.kata_operation, "_prestage_rootfs_binding", return_value=binding),
        patch.object(lease.kata_operation, "_prestage_rootfs_coordinates", return_value=None),
        patch.object(builder, "_token", return_value="c" * 64),
        patch.object(builder, "_operation_name", return_value=fs._name(b"operation-c")),
        patch.object(builder, "_open_base_chain", return_value=object()),
        patch.object(builder, "_open_state", return_value=object()),
        patch.object(fs, "_enumerate_stable", return_value=SimpleNamespace(raw_names=names)),
        patch.object(builder, "_acquire_lock", return_value=object()),
        patch.object(builder, "_read_active_ledger", return_value=active),
        patch.object(builder, "_records", return_value=records),
        patch.object(builder, "_source", return_value=object()),
        patch.object(fs, "_verify_source_bundle", return_value=None),
        patch.object(lease, "_close_prestage_nodes", side_effect=lambda *_args: events.append("closed")),
        patch.object(builder, "_recover_fixed", side_effect=lambda _control: events.append("recovered")),
        patch.object(lease.kata_operation, "_settle_prestage_rootfs",
                     side_effect=lambda *_args: events.append("settled")),
        patch.object(lease, "_prestage_rootfs_absent", return_value=True),
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
            patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], \
            patches[12], patches[13], patches[14], patches[15], patches[16]:
        receipt = lease._recover_unadmitted_kata_operation(object(), approval, control)
    assert lease._is_prestage_cleanup_receipt(receipt)
    assert events == ["closed", "recovered", "settled"]


def source_tests():
    source = (REMOTE / "completion_rootfs_lease.py").read_text()
    builder_source = (REMOTE / "completion_rootfs_builder.py").read_text()
    assert "def _acquire(" in source and "def _verify(" in source
    verify_source = source.split("def _verify(", 1)[1]
    assert verify_source.count("_stable_lease_pass(lease, control)") == 2
    assert "retained.disposition = \"uncertain\"" in source
    assert source.index("retained.disposition = \"uncertain\"") < source.index("builder._mark_leased(")
    assert "publication._load_pins()" in source and "publication._publish" not in source
    assert "def _authorize_kata_release(" in source
    assert "def _recover_kata_release(" in source
    assert "authority.reserve_rootfs()" in source and "authority.reserve_rootfs_release()" in source
    assert "_append_release_authorized_record(" in source
    release_route = source.split("def _authorize_kata_release(", 1)[1].split("def _recover_kata_release(", 1)[0]
    assert release_route.index("prospective = ledger._advance_history(active.records, record)") < release_route.index(
        "written = ledger._append_release_authorized_record("
    ) < release_route.index("history = ledger._parse_ledger_history(raw)")
    assert "_fail(history.legal == prospective.legal)" in release_route
    for forbidden in (
        "subprocess", "os.system", "tarfile", "shutil", "copyfile", "rename(", "replace(",
        "chmod", "chown", "os.mount", "/proc/self/fd", "__del__", "__enter__", "__exit__",
    ):
        assert forbidden not in source
    assert "resolve()" not in source and "destination" not in source
    assert "_append_mechanical" not in builder_source
    assert 'record_type not in {"leased", "release-authorized", "prestage-release-authorized"}' in builder_source
    assert "def _recover_unadmitted_kata_operation(" in source
    assert "_append_prestage_authorized_record(" in source
    assert 'cleanup_origin == "prestage-authorized"' in source
    assert "builder._recover_prestage_fixed(control)" in source
    assert "_fail(recovery_key is _PRESTAGE_RECOVERY)" in builder_source
    assert "def _mark_leased(" in builder_source and "def _stable_active(" in builder_source
    writer_calls = []
    control_owners = []
    prestage_recovery_calls = []
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
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"_append_record", "_append_leased_record", "_append_release_authorized_record", "_append_prestage_authorized_record"}:
                writer_calls.append((path.name, owner_name, node.func.attr))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_recover_prestage_fixed"):
                prestage_recovery_calls.append((path.name, owner_name))
            if isinstance(node, ast.Constant) and node.value in {"leased", "release-authorized", "prestage-release-authorized"}:
                control_owners.append((path.name, owner_name))
    assert prestage_recovery_calls == [
        ("completion_rootfs_lease.py", "_recover_unadmitted_kata_operation")]
    assert sorted(writer_calls) == [
        ("completion_rootfs_builder.py", "_append", "_append_record"),
        ("completion_rootfs_builder.py", "_mark_leased", "_append_leased_record"),
        ("completion_rootfs_lease.py", "_recover_unadmitted_kata_operation", "_append_prestage_authorized_record"),
        ("completion_rootfs_lease.py", "route", "_append_release_authorized_record"),
    ]
    assert set(control_owners) == {
        ("completion_rootfs_builder.py", "_append"),
        ("completion_rootfs_builder.py", "_cleanup_active"),
        ("completion_rootfs_builder.py", "_mark_leased"),
        ("completion_rootfs_builder.py", "_recover_locked"),
        ("completion_rootfs_builder.py", "_cleanup_active"),
        ("completion_rootfs_builder.py", "_require_cleanup_model"),
        ("completion_rootfs_builder.py", "_session_require"),
        ("completion_rootfs_lease.py", "_classify_release_crash_for_tests"),
        ("completion_rootfs_lease.py", "_recover_unadmitted_kata_operation"),
        ("completion_rootfs_lease.py", "_reference"),
        ("completion_rootfs_lease.py", "_stable_graph"),
        ("completion_rootfs_lease.py", "_stable_lease_pass"),
        ("completion_rootfs_lease.py", "_verify"),
        ("completion_rootfs_lease.py", "rootfs_route"),
        ("completion_rootfs_lease.py", "route"),
        ("completion_rootfs_ledger.py", "<module>"),
        ("completion_rootfs_ledger.py", "__post_init__"),
        ("completion_rootfs_ledger.py", "_append_leased_record"),
        ("completion_rootfs_ledger.py", "_append_prestage_authorized_record"),
        ("completion_rootfs_ledger.py", "_append_record"),
        ("completion_rootfs_ledger.py", "_append_release_authorized_record"),
        ("completion_rootfs_ledger.py", "_lease_history"),
        ("completion_rootfs_ledger.py", "_reconcile_ledger"),
        ("completion_rootfs_ledger.py", "_validate_body"),
        ("completion_rootfs_ledger.py", "_advance_history"),
        ("completion_rootfs_ledger.py", "_write_record"),
    }


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
    assert build_module.BUILD_SECONDS == 900

    approval = fs_module.SourceApproval(revision, source_digest)
    control = fs_module.OperationControl(time.monotonic_ns() + 3600 * 1_000_000_000, lambda: False)
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

    # A real child faults one retained descriptor before the abandonment API.
    # It must fail without mutating the durable lease. The parent then performs
    # the successful no-KVM abandonment used by the preparation bridge.
    assert all("/dev/kvm" not in os.readlink(path) for path in
               Path("/proc/self/fd").iterdir() if path.exists())
    child = os.fork()
    if child == 0:
        try:
            descriptor = held.retained.owned.root.operation_fd.number
            os.close(descriptor)
            try:
                lease_module._abandon(held, control)
            except BaseException:
                os._exit(0)
            os._exit(91)
        except BaseException:
            os._exit(92)
    waited, status = os.waitpid(child, 0)
    assert waited == child and os.waitstatus_to_exitcode(status) == 0
    preserved()
    lease_module._abandon(held, control)
    assert held.disposition == "abandoned"
    preserved()

    # Compose the real fixed operation owner with the real durable rootfs owner.
    def operation_journal(include_leased=False, mismatch=False, input_removed=False):
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
        if input_removed:
            token = "8" * 64; proof = lambda value: {"operation_token": token, "proof_sha256": value * 64}
            bodies.extend((("LIFECYCLE_DEADLINE_V1", {"operation_token": token, "admission_boottime_ns": 1,
                "ssh_start_deadline_boottime_ns": 1 + operation_module.JOURNAL_SETUP_MARGIN_NS,
                "journal_deadline_boottime_ns": 1 + operation_module.JOURNAL_TOTAL_NS}),
                ("PRODUCTION_ADMISSION_V2", {"operation_token": token,
                 "admission_version": operation_module.PRODUCTION_ADMISSION_VERSION,
                 "policy_version": operation_module.command_policy.POLICY_VERSION,
                 "parser_source_sha256": operation_module.SSH_PARSER_SHA256}),
                ("BASELINES_CAPTURED", proof("1")), ("NETWORK_READY", proof("2")),
                ("RUNTIME_READY", proof("3")), ("READINESS_REVOKED", {"operation_token": token}),
                ("OWNERSHIP_OBSERVED", {**proof("4"), "task": "exact-owned", "container": "exact-owned",
                 "runtime": "exact-owned", "share": "exact-owned"}), ("TASK_STOPPED", proof("5")),
                ("NETWORK_ABSENT", proof("6")), ("TASK_ABSENT", proof("7")),
                ("CONTAINER_ABSENT", proof("8")), ("RUNTIME_ABSENT", proof("9")),
                ("SHARE_ABSENT", proof("a")), ("FIREWALL_ABSENT", proof("b")),
                ("INPUT_REMOVED", proof("c"))))
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

    completion_root = harness.FIXED / "deploy/aws-feasibility/.state/completion-v1"
    for fixed_name in (operation_module.IMMUTABLE_PREPARATION_NAME.text,
                       operation_module.RUNTIME_NAME.text):
        path = completion_root / fixed_name
        path.mkdir(mode=0o700, exist_ok=True); os.chmod(path, 0o700)

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

    # The distinct prestage event is durable before either journal unlink or
    # rootfs removal. Every restart consumes only fresh sealed cleanup custody.
    journal_path = operation_journal(True)
    authority = operation_module._open_fixed_operation_recovery()
    prestage = operation_module._claim_pre_admission_cleanup(authority, approval)
    with patch.object(operation_module, "_settle_prestage_rootfs",
                      side_effect=RuntimeError("post-authorization cut")):
        rejected(lambda: lease_module._recover_unadmitted_kata_operation(
            prestage.reserve_prestage_rootfs_release(), approval, control))
    root_records = ledger_module._parse_ledger(ledger_path.read_bytes())
    assert root_records[-1].record_type == "prestage-release-authorized"
    assert journal_path.exists() and root_path.exists()
    prestage.close()

    authority = operation_module._open_fixed_operation_recovery()
    prestage = operation_module._claim_pre_admission_cleanup(authority, approval)
    receipt = lease_module._recover_unadmitted_kata_operation(
        prestage.reserve_prestage_rootfs_release(), approval, control)
    assert lease_module._is_prestage_cleanup_receipt(receipt)
    assert not journal_path.exists() and not root_path.exists()
    prestage.close()
    authority = operation_module._open_fixed_operation_recovery()
    prestage = operation_module._claim_pre_admission_cleanup(authority, approval)
    assert lease_module._recover_unadmitted_kata_operation(
        prestage.reserve_prestage_rootfs_release(), approval, control) is None
    prestage.close()
    journal_path.write_bytes(b"replacement\n"); os.chmod(journal_path, 0o600)
    replacement = operation_module._open_fixed_operation_recovery()
    assert replacement.status() == "preserve"
    replacement.close()
    assert journal_path.read_bytes() == b"replacement\n" and not root_path.exists()
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
        operation_parent_transition_tests()
        alias_and_close_tests()
        acquisition_boundary_tests()
        verify_order_and_drift_tests()
        preservation_route_tests()
        authorized_cleanup_boundary_tests()
        cleanup_regular_fault_tests()
        cleanup_hardlink_fault_tests()
        cleanup_absent_fault_tests()
        cleanup_retirement_fault_tests()
        cleanup_model_tests()
        cleanup_phase_truth_table_tests()
        cleanup_session_entrance_tests()
        cleanup_complexity_tests()
        retired_prelease_recovery_test()
        source_tests()
        assert MATRIX_CASES > 0
        print(f"completion rootfs lease portable behavioral matrix: {MATRIX_CASES} finite cases")
        print("completion rootfs lease portable tests passed")
    else:
        raise SystemExit("usage: aws-stage2-completion-rootfs-lease.py [--real]")


if __name__ == "__main__":
    main(sys.argv[1:])

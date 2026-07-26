"""Fixed rootfs ownership lifecycle and exact recover-owned command for ADR 0040."""

from contextlib import contextmanager
from dataclasses import dataclass, replace
import fcntl
import hashlib
import os
import signal
import stat
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

import completion_rootfs_fs as fs
import completion_rootfs_ledger as ledger

STATE_NAME = fs._name(b"rootfs-v1")
STATE_SENTINEL_NAME = fs._name(b".cogs-stage2-rootfs-state-v1")
STATE_SENTINEL = b"cogs-stage2-rootfs-state-v1\n"
LOCK_NAME = fs._name(b".cogs-stage2-rootfs-lock-v1")
LEDGER_NAME = fs._name(b".cogs-stage2-rootfs-ledger-v1")
OPERATION_SENTINEL_NAME = fs._name(b".cogs-stage2-rootfs-operation-v1")
OPERATION_SENTINEL = b"cogs-stage2-rootfs-operation-v1\n"
ROOT_NAME = fs._name(b"rootfs")
CANDIDATE_TAR_NAME = fs._name(b".cogs-rootfs-candidate-v1.tar")
RECOVER_SECONDS = 600
FIXED_MODULE = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_rootfs_builder.py")
SOURCE_INDEX = 4
COMPLETION_INDEX = 8
_start_phase_structural_counters, _read_phase_structural_counters = fs._phase_structural_counter_provider((
    "recovery-attempt-1",
))


class BuilderError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise BuilderError()


def _fixed_umask(function, *args):
    # os.umask is process-wide: coordinators require a single-threaded process.
    previous = os.umask(0o077)
    try:
        return function(*args)
    finally:
        _fail(os.umask(previous) == 0o077)


def _fresh_recovery_control():
    return fs.OperationControl(time.monotonic_ns() + RECOVER_SECONDS * 1_000_000_000, lambda: False)


def _transition_control():
    return _fresh_recovery_control()


@dataclass
class CancellationLatch:
    cancelled: bool = False


@dataclass(frozen=True)
class LockedState:
    chain: fs.HeldChain
    state: fs.HeldNode
    lock: fs.HeldNode


@dataclass(frozen=True)
class ActiveLedger:
    node: fs.HeldNode
    records: ledger.LedgerHistory | tuple
    writer: ledger.LedgerWriterState


@dataclass(frozen=True)
class OperationEstablishmentCheckpoint:
    ledger_state_generation: fs.HostGeneration
    parent_snapshots: int
    incremental_records: int
    complete_walks: int


class _CreateRollbackError(Exception):
    def __init__(self, primary, chain=None, removal=None, child=None):
        self.primary = primary
        self.chain = chain
        self.removal = removal
        self.child = child
        super().__init__()


def _records(active):
    _fail(type(active) is ActiveLedger)
    if type(active.records) is ledger.LedgerHistory:
        return ledger._history_records(active.records)
    _fail(type(active.records) is tuple)
    return active.records


def _first_record(active):
    return active.records.first if type(active.records) is ledger.LedgerHistory else _records(active)[0]


def _terminal_record(active):
    return active.records.terminal if type(active.records) is ledger.LedgerHistory else _records(active)[-1]


def _reverse_records(active):
    return reversed(active.records) if type(active.records) is ledger.LedgerHistory else reversed(_records(active))


@dataclass(frozen=True)
class OwnedOperation:
    locked: LockedState
    active: ActiveLedger
    operation: fs.HeldNode
    root: fs.HeldNode
    operation_name: str


@dataclass
class CleanupSession:
    active: ActiveLedger
    locked: LockedState
    operation: fs.HeldNode | None
    origin: str
    status: str
    owned: dict
    parents: dict
    groups: dict
    operation_generation: fs.HostGeneration | None
    state_parent: ledger.LedgerParent
    candidate_tar: tuple[int, str] | None = None
    disposition: str = "active"


def _check(control):
    control.check()


def _fsync(descriptor, control):
    _check(control)
    os.fsync(descriptor.number)
    _check(control)


def _write_all(descriptor, content, control):
    offset = 0
    while offset < len(content):
        _check(control)
        count = os.write(descriptor.number, content[offset:])
        _check(control)
        _fail(type(count) is int and 0 < count <= len(content) - offset)
        offset += count


def _parent_snapshot(node, control):
    return fs._enumerate_names_stable(node, control)


def _parent_value(snapshot):
    return ledger.LedgerParent(snapshot.generation, tuple(item.text for item in snapshot.names))


def _parent(node, control):
    return _parent_value(_parent_snapshot(node, control))


def _policy(node, kind, mode, root_key):
    generation = node.generation
    _fail(generation.key.kind == kind and generation.mode == mode)
    _fail(generation.uid == generation.gid == 0)
    _fail(generation.key.mount_id == root_key.mount_id and generation.key.device == root_key.device)
    _fail(generation.nlink == 1 if kind == "file" else generation.nlink >= 2)


def _close(node, primary=None):
    fs._close_node(node, primary)


def _close_nodes(nodes, primary=None):
    error = primary
    for node in reversed(tuple(node for node in nodes if node is not None)):
        try:
            _close(node)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


@contextmanager
def _owned_nodes(nodes):
    try:
        yield
    except BaseException as error:
        _close_nodes(nodes(), error)
    else:
        _close_nodes(nodes())


def _create_directory(parent, name, control, parent_chain):
    node = None
    delta = None
    rollback = None
    created = False
    try:
        fs._revalidate_chain(parent_chain, control)
        before = _parent_snapshot(parent, control)
        fs._revalidate_chain(parent_chain, control)
        _check(control)
        created = True
        os.mkdir(name.raw, 0o700, dir_fd=parent.operation_fd.number)
        after = _parent_snapshot(parent, control)
        delta = fs.ParentDelta("create", name, before, after)
        fs._revalidate_chain(parent_chain, control, delta)
        _check(control)
        node = fs._open_path_node(parent, name, "directory", control)
        _policy(node, "directory", 0o700, parent.generation.key)
        fs._require_empty_fd_xattrs(node, control)
        return node
    except BaseException as error:
        if delta is not None:
            cleanup = _transition_control()
            try:
                current_chain = _chain_after_parent(parent_chain, delta.before.generation, delta.after.generation)
                fs._revalidate_chain(current_chain, cleanup)
                current = fs._observe_child(parent, name, cleanup)
                if node is not None:
                    _fail(current.key == node.generation.key)
                    _close(node)
                before_remove = _parent_snapshot(parent, cleanup)
                _fail(before_remove == delta.after)
                fs._revalidate_chain(current_chain, cleanup)
                _remove_name(parent, name, current, cleanup)
                after_remove = _parent_snapshot(parent, cleanup)
                remove_delta = fs.ParentDelta("rmdir", name, before_remove, after_remove)
                fs._revalidate_chain(current_chain, cleanup, remove_delta)
                final_chain = _chain_after_parent(
                    current_chain, before_remove.generation, after_remove.generation,
                )
                fs._revalidate_chain(final_chain, cleanup)
                rollback = _CreateRollbackError(error, final_chain, remove_delta, current)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        if node is not None and node.identity_fd.disposition == "open":
            try:
                _close(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if rollback is not None:
            raise rollback
        if created:
            raise _CreateRollbackError(error)
        raise error


def _create_file(parent, name, content, control, parent_chain):
    _fail(type(content) is bytes)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    descriptor = node = None
    key = delta = rollback = None
    created = close_uncertain = False
    try:
        fs._revalidate_chain(parent_chain, control)
        before = _parent_snapshot(parent, control)
        fs._revalidate_chain(parent_chain, control)
        _check(control)
        created = True
        descriptor = fs.CheckedFd(os.open(name.raw, flags, 0o600, dir_fd=parent.operation_fd.number), "created-file")
        key_stat = os.fstat(descriptor.number)
        key = (key_stat.st_dev, key_stat.st_ino)
        after = _parent_snapshot(parent, control)
        delta = fs.ParentDelta("create", name, before, after)
        fs._revalidate_chain(parent_chain, control, delta)
        _check(control)
        _write_all(descriptor, content, control)
        _fsync(descriptor, control)
        descriptor.close()
        descriptor = None
        node = fs._open_path_node(parent, name, "file", control)
        _fail((node.generation.key.device, node.generation.key.inode) == key)
        _policy(node, "file", 0o600, parent.generation.key)
        fs._require_empty_fd_xattrs(node, control)
        _fail(fs._read_regular(node, max(1, len(content)), control) == content)
        return node
    except BaseException as error:
        for owned in (node, descriptor):
            try:
                if type(owned) is fs.HeldNode and owned.identity_fd.disposition == "open":
                    _close(owned)
                elif type(owned) is fs.CheckedFd and owned.disposition == "open":
                    owned.close()
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
                close_uncertain = True
        if delta is not None and not close_uncertain:
            cleanup = _transition_control()
            try:
                current_chain = _chain_after_parent(parent_chain, delta.before.generation, delta.after.generation)
                fs._revalidate_chain(current_chain, cleanup)
                current = fs._observe_child(parent, name, cleanup)
                _fail(current.key.kind == "file" and (key is None or (current.key.device, current.key.inode) == key))
                before_remove = _parent_snapshot(parent, cleanup)
                _fail(before_remove == delta.after)
                fs._revalidate_chain(current_chain, cleanup)
                os.unlink(name.raw, dir_fd=parent.operation_fd.number)
                _fsync(parent.operation_fd, cleanup)
                after_remove = _parent_snapshot(parent, cleanup)
                remove_delta = fs.ParentDelta("unlink", name, before_remove, after_remove)
                fs._revalidate_chain(current_chain, cleanup, remove_delta)
                final_chain = _chain_after_parent(
                    current_chain, before_remove.generation, after_remove.generation,
                )
                fs._revalidate_chain(final_chain, cleanup)
                rollback = _CreateRollbackError(error, final_chain, remove_delta, current)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        if rollback is not None:
            raise rollback
        if created:
            raise _CreateRollbackError(error)
        raise error


def _remove_name(parent, name, expected, control):
    observed = fs._observe_child(parent, name, control)
    _fail(observed == expected)
    if expected.key.kind == "directory":
        child = fs._open_path_node(parent, name, "directory", control)
        try:
            _fail(not fs._enumerate_stable(child, control).names)
            _close(child)
        except BaseException as error:
            if child.identity_fd.disposition == "open":
                _close(child, error)
            raise
        _check(control)
        os.rmdir(name.raw, dir_fd=parent.operation_fd.number)
    else:
        _check(control)
        os.unlink(name.raw, dir_fd=parent.operation_fd.number)
    _check(control)
    _fsync(parent.operation_fd, control)


def _append_component(chain, name, node):
    return fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))


def _open_base_chain(control):
    root = fs._open_workspace_anchor(control)
    try:
        return fs._open_anchored_chain(root, fs._fixed_policies(), control)
    except BaseException as error:
        if root.identity_fd.disposition == "open":
            _close(root, error)
        raise


def _completion(chain):
    return chain.components[COMPLETION_INDEX].node


def _source(chain):
    return chain.components[SOURCE_INDEX].node


def _bootstrap_unmasked(chain, approval, control):
    _fail(type(approval) is fs.SourceApproval)
    fs._verify_source_bundle(_source(chain), approval, control)
    completion = _completion(chain)
    completion_chain = fs.HeldChain(chain.anchor, chain.components[:COMPLETION_INDEX + 1])
    fs._revalidate_chain(completion_chain, control)
    before = fs._enumerate_stable(completion, control)
    _fail(STATE_NAME.raw not in before.raw_names)
    state = _create_directory(completion, STATE_NAME, control, completion_chain)
    try:
        _fsync(state.operation_fd, control)
        _fsync(completion.operation_fd, control)
        current_completion = fs._observe_node(completion.identity_fd, completion.operation_fd, control)
        current_completion_chain = _chain_after_parent(
            completion_chain, completion_chain.components[-1].node.generation, current_completion,
        )
        state_chain = _chain_with_child(current_completion_chain, STATE_NAME, state)
        sentinel = _create_file(state, STATE_SENTINEL_NAME, STATE_SENTINEL, control, state_chain)
        _close(sentinel)
        _fsync(state.operation_fd, control)
        current_state = fs._observe_node(state.identity_fd, state.operation_fd, control)
        state_chain = _chain_after_parent(state_chain, state_chain.components[-1].node.generation, current_state)
        lock = _create_file(state, LOCK_NAME, b"", control, state_chain)
        _close(lock)
        _fsync(state.operation_fd, control)
        snapshot = fs._enumerate_stable(state, control)
        _fail(snapshot.raw_names == tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw))))
        return state
    except BaseException as error:
        if state.identity_fd.disposition == "open":
            _close(state, error)
        raise


def _bootstrap(chain, approval, control):
    return _fixed_umask(_bootstrap_unmasked, chain, approval, control)


def _open_state(chain, control):
    completion = _completion(chain)
    snapshot = fs._enumerate_stable(completion, control)
    if STATE_NAME.raw not in snapshot.raw_names:
        return None
    state = fs._open_path_node(completion, STATE_NAME, "directory", control)
    transferred = False
    with _owned_nodes(lambda: () if transferred else (state,)):
        _policy(state, "directory", 0o700, completion.generation.key)
        fs._require_empty_fd_xattrs(state, control)
        transferred = True
        return state


def _verify_fixed_file(parent, name, content, control):
    node = fs._open_path_node(parent, name, "file", control)
    try:
        _policy(node, "file", 0o600, parent.generation.key)
        fs._require_empty_fd_xattrs(node, control)
        _fail(fs._read_regular(node, max(1, len(content)), control) == content)
        return node
    except BaseException as error:
        _close(node, error)


def _acquire_lock(chain, state, control):
    sentinel = _verify_fixed_file(state, STATE_SENTINEL_NAME, STATE_SENTINEL, control)
    _close(sentinel)
    lock = _verify_fixed_file(state, LOCK_NAME, b"", control)
    try:
        _fail(lock.generation.size == 0)
        _check(control)
        fcntl.flock(lock.operation_fd.number, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _check(control)
        rebound = fs._observe_child(state, LOCK_NAME, control)
        _fail(rebound == lock.generation)
        state_chain = _append_component(chain, STATE_NAME, state)
        fs._revalidate_chain(state_chain, control)
        return LockedState(state_chain, state, lock)
    except BaseException as error:
        if lock.identity_fd.disposition == "open":
            _close(lock, error)
        raise


def _release_lock(locked, primary=None):
    error = primary
    try:
        _close(locked.lock)
    except BaseException as close_error:
        error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _ledger_node(state, control):
    identity = None
    operation = None
    try:
        identity = fs._open_path_node(state, LEDGER_NAME, "file", control)
        identity.operation_fd.close()
        flags = os.O_RDWR | fs._O_NOFOLLOW | fs._O_CLOEXEC
        _check(control)
        operation = fs.CheckedFd(os.open(LEDGER_NAME.raw, flags, dir_fd=state.operation_fd.number), "ledger-writer")
        _check(control)
        generation = fs._observe_node(identity.identity_fd, operation, control)
        node = fs.HeldNode(identity.identity_fd, operation, generation)
        _policy(node, "file", 0o600, state.generation.key)
        fs._require_empty_fd_xattrs(node, control)
        return node
    except BaseException as error:
        for descriptor in (operation, None if identity is None else identity.identity_fd):
            if descriptor is not None and descriptor.disposition == "open":
                try:
                    descriptor.close()
                except BaseException as close_error:
                    error = fs.RootfsFsError(error, close_error)
        raise error


def _rebound_locked_state(locked, state_chain, before_generation, after_generation):
    _fail(type(locked) is LockedState and type(state_chain) is fs.HeldChain)
    _fail(type(before_generation) is fs.HostGeneration and type(after_generation) is fs.HostGeneration)
    _fail(state_chain.anchor is locked.chain.anchor)
    _fail(len(state_chain.components) == len(locked.chain.components) and state_chain.components)
    _fail(state_chain.components[-1].name == STATE_NAME)
    _fail(state_chain.components[-1].node.identity_fd is locked.state.identity_fd)
    _fail(state_chain.components[-1].node.operation_fd is locked.state.operation_fd)
    rebound_chain = _chain_after_parent(state_chain, before_generation, after_generation)
    rebound_state = rebound_chain.components[-1].node
    _fail(rebound_state.generation == after_generation)
    _fail(rebound_state.identity_fd is locked.state.identity_fd)
    _fail(rebound_state.operation_fd is locked.state.operation_fd)
    rebound = LockedState(rebound_chain, rebound_state, locked.lock)
    _fail(rebound is not locked and rebound.chain is rebound_chain)
    _fail(rebound.state is rebound.chain.components[-1].node and rebound.lock is locked.lock)
    return rebound


def _operation_establishment_start():
    before = fs.structural_counter_snapshot()
    _fail(type(before) is dict and tuple(before) == fs.ROOTFS_STRUCTURAL_COUNTER_KEYS)
    _fail(all(type(value) is int and 0 <= value <= (1 << 63) - 1 for value in before.values()))
    return before


def _operation_establishment_checkpoint(before, active, locked):
    _fail(type(active) is ActiveLedger and type(locked) is LockedState)
    genesis_parent = ledger._parse_parent(_first_record(active).body_value()["state_parent"])
    retained_generation = locked.chain.components[-1].node.generation
    _fail(locked.state is locked.chain.components[-1].node)
    _fail(retained_generation == genesis_parent.generation)
    after = fs.structural_counter_snapshot()
    values = fs.structural_counter_delta(before, after)
    checkpoint = OperationEstablishmentCheckpoint(
        genesis_parent.generation,
        values["parent_snapshots"],
        values["incremental_records"],
        values["complete_walks"],
    )
    _fail(checkpoint.parent_snapshots == 3)
    _fail(checkpoint.incremental_records == 2)
    _fail(checkpoint.complete_walks == 0)
    _fail(checkpoint.ledger_state_generation == retained_generation)
    return checkpoint


def _new_active_ledger(locked, approval, token, work_control):
    _fail(type(locked) is LockedState)
    state = locked.state
    work_control.check()
    control = _transition_control()
    state_chain = _state_chain(locked, control)
    fs._revalidate_chain(state_chain, control)
    before_snapshot = _parent_snapshot(state, control)
    fs._revalidate_chain(state_chain, control)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    descriptor = None
    identity = None
    node = None
    key = None
    parent_delta = None
    error = None
    try:
        descriptor = fs.CheckedFd(os.open(LEDGER_NAME.raw, flags, 0o600, dir_fd=state.operation_fd.number), "ledger-create")
        descriptor_stat = os.fstat(descriptor.number)
        key = (descriptor_stat.st_dev, descriptor_stat.st_ino)
        identity = fs.CheckedFd(os.open(LEDGER_NAME.raw, fs.IDENTITY_FLAGS, dir_fd=state.operation_fd.number), "ledger-identity")
        generation = fs._observe_node(identity, descriptor, control)
        _fail((generation.key.device, generation.key.inode) == key)
        node = fs.HeldNode(identity, descriptor, generation)
        identity = descriptor = None
        _policy(node, "file", 0o600, state.generation.key)
        fs._require_empty_fd_xattrs(node, control)
        after_snapshot = _parent_snapshot(state, control)
        parent_delta = fs.ParentDelta("create", LEDGER_NAME, before_snapshot, after_snapshot)
        fs._revalidate_chain(state_chain, control, parent_delta)
        state_parent = _parent_value(after_snapshot)
        body = {
            "token": token,
            "source_revision": approval.revision,
            "source_manifest_sha256": approval.manifest_sha256,
            "state_parent": _p(state_parent),
            "ledger_key": _key_body(node.generation.key),
        }
        proposal = ledger.LedgerProposal.create("genesis", body)
        raw = ledger._encode_proposal(proposal, ledger.INITIAL_BYTES)
        _write_all(node.operation_fd, raw, control)
        _fsync(node.operation_fd, control)
        _fsync(state.operation_fd, control)
        history = ledger._parse_ledger_history(fs._read_regular(node, ledger.MAX_LEDGER_BYTES, control))
        _fail(history.count == 1 and history.terminal.record_type == "genesis")
        current = fs._observe_node(node.identity_fd, node.operation_fd, control)
        writer = ledger.LedgerWriterState(node, current.key, ledger.SettledBytes(0, len(raw), hashlib.sha256(raw).hexdigest()), current)
        work_control.check()
        active = ActiveLedger(node, history, writer)
        rebound = _rebound_locked_state(
            locked, state_chain, before_snapshot.generation, after_snapshot.generation,
        )
        return active, rebound
    except BaseException as primary:
        error = primary
    if key is None and descriptor is not None and descriptor.disposition == "open":
        try:
            observed = os.fstat(descriptor.number)
            key = (observed.st_dev, observed.st_ino)
        except BaseException as identity_error:
            error = fs.RootfsFsError(error, identity_error)
    for owned in (node, identity, descriptor):
        if owned is None:
            continue
        try:
            if type(owned) is fs.HeldNode:
                if owned.identity_fd.disposition == "open":
                    _close(owned)
            elif owned.disposition == "open":
                owned.close()
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    if key is not None:
        try:
            _fail(type(parent_delta) is fs.ParentDelta)
            current_chain = _chain_after_parent(
                state_chain, parent_delta.before.generation, parent_delta.after.generation,
            )
            fs._revalidate_chain(current_chain, control)
            current = fs._observe_child(state, LEDGER_NAME, control)
            _fail((current.key.device, current.key.inode) == key)
            os.unlink(LEDGER_NAME.raw, dir_fd=state.operation_fd.number)
            after_cleanup = _parent_snapshot(state, control)
            cleanup_delta = fs.ParentDelta("unlink", LEDGER_NAME, parent_delta.after, after_cleanup)
            fs._revalidate_chain(current_chain, control, cleanup_delta)
            _fsync(state.operation_fd, control)
        except BaseException as cleanup_error:
            error = fs.RootfsFsError(error, cleanup_error)
    raise error


def _read_active_ledger(state, control):
    node = _ledger_node(state, control)
    try:
        raw = fs._read_regular(node, ledger.MAX_LEDGER_BYTES, control)
        history = ledger._parse_ledger_history(raw)
        last = history.terminal
        settled = ledger.SettledBytes(last.sequence, last.next_offset, last.line_sha256)
        _check(control)
        os.lseek(node.operation_fd.number, settled.offset, os.SEEK_SET)
        _check(control)
        current = fs._observe_node(node.identity_fd, node.operation_fd, control)
        writer = ledger.LedgerWriterState(node, node.generation.key, settled, current)
        return ActiveLedger(node, history, writer)
    except BaseException as error:
        if node.identity_fd.disposition == "open":
            _close(node, error)
        raise


def _g(value):
    return ledger._generation_value(value)


def _p(value):
    return ledger._parent_value(value)


def _key_body(key):
    return {"mount_id": key.mount_id, "device": key.device, "inode": key.inode, "kind": key.kind}


def _operation_name(token):
    return fs._name(ledger._operation_name(token))


def _stable_active(active, state, control):
    _fail(type(active) is ActiveLedger and type(active.writer) is ledger.LedgerWriterState)
    _fail(type(active.records) is ledger.LedgerHistory)
    _fail(type(state) is fs.HeldNode and type(control) is fs.OperationControl)
    _fail(type(state.identity_fd) is fs.CheckedFd and type(state.operation_fd) is fs.CheckedFd)
    _fail(state.identity_fd.disposition == state.operation_fd.disposition == "open")
    node = active.node
    _fail(type(node) is fs.HeldNode and node is active.writer.node)
    _fail(type(node.identity_fd) is fs.CheckedFd and type(node.operation_fd) is fs.CheckedFd)
    _fail(node.identity_fd.disposition == node.operation_fd.disposition == "open")
    before = fs._observe_node(node.identity_fd, node.operation_fd, control)
    _policy(node, "file", 0o600, state.generation.key)
    fs._require_empty_fd_xattrs(node, control)
    _fail(before == active.writer.generation and before.key == active.writer.stable_key)
    _fail(fs._observe_child(state, LEDGER_NAME, control) == before)
    raw = fs._read_regular(node, ledger.MAX_LEDGER_BYTES, control)
    history = ledger._parse_ledger_history(raw)
    _fail(ledger._history_records(history) == _records(active) and history.legal == active.records.legal)
    last = history.terminal
    settled = ledger._settled_record(last.sequence, last.next_offset, last.line_sha256)
    _fail(settled == active.writer.settled)
    after = fs._observe_node(node.identity_fd, node.operation_fd, control)
    _fail(after == before == active.writer.generation)
    _fail(fs._observe_child(state, LEDGER_NAME, control) == before)
    os.lseek(node.operation_fd.number, settled.offset, os.SEEK_SET)
    refreshed = fs.HeldNode(node.identity_fd, node.operation_fd, after)
    return ActiveLedger(refreshed, history, ledger.LedgerWriterState(refreshed, active.writer.stable_key, settled, after))


def _durable_records(active, control):
    control.check()
    observed = os.fstat(active.node.operation_fd.number)
    _fail((observed.st_dev, observed.st_ino) == (active.writer.stable_key.device, active.writer.stable_key.inode))
    _fail(0 < observed.st_size <= ledger.MAX_LEDGER_BYTES)
    raw = os.pread(active.node.operation_fd.number, observed.st_size, 0)
    control.check()
    _fail(len(raw) == observed.st_size)
    return ledger._parse_ledger(raw)


def _refresh_active(active, control):
    control.check()
    observed = os.fstat(active.node.operation_fd.number)
    _fail((observed.st_dev, observed.st_ino) == (active.writer.stable_key.device, active.writer.stable_key.inode))
    _fail(0 < observed.st_size <= ledger.MAX_LEDGER_BYTES)
    raw = os.pread(active.node.operation_fd.number, observed.st_size, 0)
    control.check()
    _fail(len(raw) == observed.st_size)
    history = ledger._parse_ledger_history(raw)
    last = history.terminal
    settled = ledger.SettledBytes(last.sequence, last.next_offset, last.line_sha256)
    current = fs._observe_node(active.node.identity_fd, active.node.operation_fd, control)
    os.lseek(active.node.operation_fd.number, settled.offset, os.SEEK_SET)
    node = fs.HeldNode(active.node.identity_fd, active.node.operation_fd, current)
    writer = ledger.LedgerWriterState(node, active.writer.stable_key, settled, current)
    return ActiveLedger(node, history, writer)


def _durable_terminal(active, control):
    return _durable_records(active, control)[-1]


def _chain_after_parent(chain, before, after):
    components = []
    matched = 0
    for component in chain.components:
        node = component.node
        if node.generation == before:
            node = fs.HeldNode(node.identity_fd, node.operation_fd, after)
            matched += 1
        components.append(fs.ChainComponent(component.name, node))
    _fail(matched == 1)
    return fs.HeldChain(chain.anchor, tuple(components))


def _delta_for_chain(chain, delta):
    _fail(type(chain) is fs.HeldChain and type(delta) is fs.ParentDelta)
    matches = sum(component.node.generation.key == delta.before.generation.key for component in chain.components)
    _fail(matches <= 1)
    return delta if matches == 1 else None


def _chain_with_child(chain, name, node):
    return fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))


def _abort_body_from_snapshot(intent, name, snapshot):
    before = ledger._parse_parent(intent["parent"])
    after = _parent_value(snapshot)
    _fail(name.text not in after.names and ledger._valid_abort_parent(before, after))
    body = dict(intent)
    body["parent"] = _p(after)
    return body


def _absence_abort_body(intent, parent_chain, name, control):
    parent = parent_chain.components[-1].node
    fs._revalidate_chain(parent_chain, control)
    first = _parent_snapshot(parent, control)
    fs._revalidate_chain(parent_chain, control)
    second = _parent_snapshot(parent, control)
    fs._revalidate_chain(parent_chain, control)
    _fail(second == first)
    return _abort_body_from_snapshot(intent, name, first)


def _state_chain(locked, control):
    state = fs.HeldNode(
        locked.state.identity_fd, locked.state.operation_fd,
        fs._observe_node(locked.state.identity_fd, locked.state.operation_fd, control),
    )
    return fs.HeldChain(
        locked.chain.anchor,
        locked.chain.components[:-1] + (fs.ChainComponent(STATE_NAME, state),),
    )


def _held_operation_chain(active, locked, operation, control):
    state_chain = _state_chain(locked, control)
    retained = fs.HeldNode(
        operation.identity_fd, operation.operation_fd,
        fs._observe_node(operation.identity_fd, operation.operation_fd, control),
    )
    return fs.HeldChain(
        state_chain.anchor,
        state_chain.components + (fs.ChainComponent(_operation_name(_token(active)), retained),),
    )


def _operation_chain(owned, control):
    _fail(type(owned) is OwnedOperation)
    return _held_operation_chain(owned.active, owned.locked, owned.operation, control)


def _create_ledger_entry(active, parent_chain, path, name, kind, content, control):
    _fail(type(parent_chain) is fs.HeldChain and parent_chain.components)
    parent = parent_chain.components[-1].node
    child = None
    delta = None
    try:
        fs._revalidate_chain(parent_chain, control)
        pre_snapshot = _parent_snapshot(parent, control)
        fs._revalidate_chain(parent_chain, control)
        pre = _parent_value(pre_snapshot)
        active = _append(active, "create-intent", {"token": _token(active), "path": path, "kind": kind, "parent": _p(pre)}, control)
        transition = _transition_control()
        fs._revalidate_chain(parent_chain, transition)
        child = _create_directory(parent, name, transition, parent_chain) if kind == "directory" else _create_file(parent, name, content, transition, parent_chain)
        post_snapshot = _parent_snapshot(parent, transition)
        delta = fs.ParentDelta("create", name, pre_snapshot, post_snapshot)
        fs._revalidate_chain(parent_chain, transition, delta)
        current_parent_chain = _chain_after_parent(
            parent_chain, pre_snapshot.generation, post_snapshot.generation,
        )
        child_chain = _chain_with_child(current_parent_chain, name, child)
        fs._revalidate_chain(child_chain, transition)
        post = _parent_value(post_snapshot)
        observed = {"token": _token(active), "path": path, "kind": kind, "parent": _p(post), "child": _g(child.generation)}
        active = _append(active, "create-observed", observed, transition)
        _fsync(child.operation_fd, transition)
        _fsync(parent.operation_fd, transition)
        fs._revalidate_chain(child_chain, transition)
        active = _append(active, "create-settled", observed, transition)
        fs._revalidate_chain(child_chain, transition)
        control.check()
        return active, child
    except BaseException as error:
        rollback = error if type(error) is _CreateRollbackError else None
        if rollback is not None:
            error = rollback.primary
        if child is None:
            cleanup_control = _transition_control()
            try:
                terminal = _durable_terminal(active, cleanup_control)
                if terminal.record_type == "create-intent" and terminal.body_value()["path"] == path:
                    abort = None
                    if rollback is None:
                        abort = _absence_abort_body(terminal.body_value(), parent_chain, name, cleanup_control)
                        fs._revalidate_chain(parent_chain, cleanup_control)
                    elif rollback.chain is not None:
                        _fail(rollback.child.key.kind == kind)
                        _fail(rollback.removal.action == ("rmdir" if kind == "directory" else "unlink") and
                              rollback.removal.name == name)
                        _fail(rollback.chain.anchor is parent_chain.anchor)
                        _fail(len(rollback.chain.components) == len(parent_chain.components) and all(
                            actual.name == prior.name and actual.node.identity_fd is prior.node.identity_fd and
                            actual.node.operation_fd is prior.node.operation_fd
                            for actual, prior in zip(rollback.chain.components, parent_chain.components)
                        ))
                        _fail(all(
                            actual.node.generation == prior.node.generation
                            for actual, prior in zip(rollback.chain.components[:-1], parent_chain.components[:-1])
                        ))
                        _fail(parent_chain.components[-1].node.generation == pre_snapshot.generation)
                        _fail(rollback.chain.components[-1].node.generation == rollback.removal.after.generation)
                        abort = _abort_body_from_snapshot(terminal.body_value(), name, rollback.removal.after)
                        fs._revalidate_chain(rollback.chain, cleanup_control)
                    else:
                        _fail(rollback.removal is rollback.child is None)
                    if abort is not None:
                        active = _append(active, "create-abort", abort, cleanup_control)
                        if rollback is not None:
                            fs._revalidate_chain(rollback.chain, cleanup_control)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        if child is not None and child.identity_fd.disposition == "open":
            cleanup_control = _transition_control()
            try:
                terminal = _durable_terminal(active, cleanup_control)
                body = terminal.body_value()
                durable = terminal.record_type in {"create-observed", "create-settled"} and body["path"] == path and ledger._parse_generation(body["child"]).key == child.generation.key
                if durable:
                    _close(child)
                else:
                    _fail(type(delta) is fs.ParentDelta)
                    current_chain = _chain_after_parent(
                        parent_chain, delta.before.generation, delta.after.generation,
                    )
                    fs._revalidate_chain(current_chain, cleanup_control)
                    before_remove = _parent_snapshot(parent, cleanup_control)
                    _fail(before_remove == delta.after)
                    fs._revalidate_chain(current_chain, cleanup_control)
                    _remove_name(parent, name, fs._observe_node(child.identity_fd, child.operation_fd, cleanup_control), cleanup_control)
                    after_remove = _parent_snapshot(parent, cleanup_control)
                    remove_delta = fs.ParentDelta(
                        "rmdir" if kind == "directory" else "unlink", name, before_remove, after_remove,
                    )
                    fs._revalidate_chain(current_chain, cleanup_control, remove_delta)
                    final_chain = _chain_after_parent(
                        current_chain, before_remove.generation, after_remove.generation,
                    )
                    abort = _abort_body_from_snapshot(terminal.body_value(), name, after_remove)
                    fs._revalidate_chain(final_chain, cleanup_control)
                    _close(child)
                    active = _append(active, "create-abort", abort, cleanup_control)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
                if child.identity_fd.disposition == "open":
                    try:
                        _close(child)
                    except BaseException as close_error:
                        error = fs.RootfsFsError(error, close_error)
        raise error


def _token(active):
    return _first_record(active).body_value()["token"]


def _begin_operation_unmasked(chain, approval, token, control):
    _fail(type(approval) is fs.SourceApproval)
    ledger._token(token)
    fs._verify_source_bundle(_source(chain), approval, control)
    state = None
    locked = None
    active = None
    operation = None
    root = None
    try:
        state = _open_state(chain, control)
        _fail(state is not None)
        locked = _acquire_lock(chain, state, control)
        names = fs._enumerate_stable(state, control).raw_names
        _fail(names == tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw))))
        establishment_start = _operation_establishment_start()
        active, locked = _new_active_ledger(locked, approval, token, control)
        state = locked.state
        state_parent = ledger._parse_parent(_first_record(active).body_value()["state_parent"])
        active = _append(active, "genesis-settled", {"token": token, "state_parent": _p(state_parent)}, control)
        operation_name = _operation_name(token)
        fs._revalidate_chain(locked.chain, control)
        pre_snapshot = _parent_snapshot(state, control)
        fs._revalidate_chain(locked.chain, control)
        pre = _parent_value(pre_snapshot)
        active = _append(active, "operation-create-intent", {"token": token, "operation_name": operation_name.text, "state_parent": _p(pre)}, control)
        _operation_establishment_checkpoint(establishment_start, active, locked)
        transition = _transition_control()
        fs._revalidate_chain(locked.chain, transition)
        operation = _create_directory(state, operation_name, transition, locked.chain)
        post_snapshot = _parent_snapshot(state, transition)
        state_delta = fs.ParentDelta("create", operation_name, pre_snapshot, post_snapshot)
        fs._revalidate_chain(locked.chain, transition, state_delta)
        post = _parent_value(post_snapshot)
        current_state = fs.HeldNode(state.identity_fd, state.operation_fd, post_snapshot.generation)
        operation_chain = fs.HeldChain(
            locked.chain.anchor,
            locked.chain.components[:-1] + (fs.ChainComponent(STATE_NAME, current_state), fs.ChainComponent(operation_name, operation)),
        )
        fs._revalidate_chain(operation_chain, transition)
        observed = {"token": token, "operation_name": operation_name.text, "state_parent": _p(post), "operation": _g(operation.generation)}
        active = _append(active, "operation-create-observed", observed, transition)
        _fsync(operation.operation_fd, transition)
        _fsync(state.operation_fd, transition)
        fs._revalidate_chain(operation_chain, transition)
        active = _append(active, "operation-create-settled", observed, transition)
        fs._revalidate_chain(operation_chain, transition)
        control.check()
        active, sentinel = _create_ledger_entry(active, operation_chain, OPERATION_SENTINEL_NAME.text, OPERATION_SENTINEL_NAME, "file", OPERATION_SENTINEL, control)
        _close(sentinel)
        refreshed_operation = fs.HeldNode(
            operation.identity_fd, operation.operation_fd, fs._observe_node(operation.identity_fd, operation.operation_fd, control),
        )
        operation_chain = fs.HeldChain(
            operation_chain.anchor, operation_chain.components[:-1] + (fs.ChainComponent(operation_name, refreshed_operation),),
        )
        active, root = _create_ledger_entry(active, operation_chain, ROOT_NAME.text, ROOT_NAME, "directory", None, control)
        return OwnedOperation(locked, active, operation, root, operation_name.text)
    except BaseException as error:
        if operation is not None and active is not None and operation.identity_fd.disposition == "open":
            cleanup_control = _transition_control()
            try:
                terminal = _durable_terminal(active, cleanup_control)
                if terminal.record_type == "operation-create-intent":
                    _fail(not fs._enumerate_stable(operation, cleanup_control).names)
                    expected = fs._observe_node(operation.identity_fd, operation.operation_fd, cleanup_control)
                    _close(operation)
                    _remove_name(state, _operation_name(token), expected, cleanup_control)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        for node in (root, operation, None if active is None else active.node):
            if node is not None and node.identity_fd.disposition == "open":
                try:
                    _close(node)
                except BaseException as close_error:
                    error = fs.RootfsFsError(error, close_error)
        if locked is not None:
            try:
                _release_lock(locked)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if state is not None and state.identity_fd.disposition == "open":
            try:
                _close(state)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        try:
            _recover_fixed(_fresh_recovery_control())
        except BaseException as cleanup_error:
            error = fs.RootfsFsError(error, cleanup_error)
        raise error


def _begin_operation(chain, approval, token, control):
    return _fixed_umask(_begin_operation_unmasked, chain, approval, token, control)


def _start_operation(chain, approval, token, control):
    owned = _begin_operation(chain, approval, token, control)
    error = None
    for node in (owned.root, owned.operation, owned.active.node):
        try:
            _close(node)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    try:
        _release_lock(owned.locked)
    except BaseException as close_error:
        error = fs.RootfsFsError(error, close_error)
    try:
        _close(owned.locked.state)
    except BaseException as close_error:
        error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error
    return owned.operation_name


def _walk_entries(operation, control):
    fs._structural_increment("complete_walks")
    entries = {}
    parents = {}

    def visit(directory, prefix):
        snapshot = fs._enumerate_stable(directory, control)
        parents[prefix] = ledger.LedgerParent(snapshot.generation, tuple(name.text for name in snapshot.names))
        for name, generation in snapshot.children:
            path = name.text if not prefix else prefix + "/" + name.text
            entries[path] = generation
            if generation.key.kind == "directory":
                child = fs._open_path_node(directory, name, "directory", control)
                try:
                    visit(child, path)
                    _close(child)
                except BaseException as error:
                    if child.identity_fd.disposition == "open":
                        _close(child, error)
                    raise

    visit(operation, "")
    return tuple(entries.items()), tuple(parents.items())


def _current_ledger(active, control):
    return fs._observe_node(active.node.identity_fd, active.node.operation_fd, control)


def _append_capabilities():
    def _append(active, record_type, body, control):
        _fail(record_type not in {"leased", "release-authorized"})
        proposal = ledger.LedgerProposal.create(record_type, body)
        raw = ledger._encode_proposal(proposal, active.writer.settled)
        record = ledger.LedgerRecord(
            active.writer.settled.sequence + 1, active.writer.settled.sequence, active.writer.settled.offset,
            active.writer.settled.line_sha256, active.writer.settled.offset + len(raw), record_type,
            proposal.body, hashlib.sha256(raw).hexdigest(),
        )
        history = ledger._advance_history(active.records, record)
        written = ledger._append_record(active.writer, proposal, control)
        node = fs.HeldNode(active.node.identity_fd, active.node.operation_fd, written.generation)
        writer = ledger.LedgerWriterState(node, written.stable_key, written.settled, written.generation)
        _fail(history.legal.settled == written.settled)
        return ActiveLedger(node, history, writer)

    def _append_candidate(active, record_type, body, control):
        _fail(record_type in ledger.CANDIDATE_RECORD_TYPES)
        result = _append(active, record_type, body, control)
        terminal = _durable_terminal(result, control)
        _fail(terminal.record_type == record_type and terminal.body_value() == body)
        return result

    def _mark_leased(owned, manifest_sha256, manifest_size, ustar_sha256, ustar_size, entry_count, control):
        _fail(type(owned) is OwnedOperation and type(control) is fs.OperationControl)
        _fail(all(type(value) is int and value > 0 for value in (manifest_size, ustar_size, entry_count)))
        active = _stable_active(owned.active, owned.locked.state, control)
        entries, parents = _walk_entries(owned.operation, control)
        operation = fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)
        observations = ledger.ReconcileObservations(
            _parent(owned.locked.state, control), ((owned.operation_name, operation),), entries,
            _current_ledger(active, control), parents,
        )
        reconciled = ledger._reconcile_ledger(_records(active), observations)
        _fail(reconciled.status == "active" and reconciled.cleanup_allowed and reconciled.cleanup_origin == "prelease")
        root = fs._observe_node(owned.root.identity_fd, owned.root.operation_fd, control)
        _fail(dict(reconciled.owned).get(ROOT_NAME.text) == root)
        body = {
            "token": _token(active), "operation_name": owned.operation_name, "state_parent": _p(observations.state_parent),
            "operation": _g(operation), "root": _g(root), "ledger_key": _key_body(active.writer.stable_key),
            "manifest_sha256": manifest_sha256, "manifest_size": manifest_size,
            "ustar_sha256": ustar_sha256, "ustar_size": ustar_size, "entry_count": entry_count,
        }
        proposal = ledger.LedgerProposal.create("leased", body)
        raw = ledger._encode_proposal(proposal, active.writer.settled)
        record = ledger.LedgerRecord(
            active.writer.settled.sequence + 1, active.writer.settled.sequence, active.writer.settled.offset,
            active.writer.settled.line_sha256, active.writer.settled.offset + len(raw), "leased",
            proposal.body, hashlib.sha256(raw).hexdigest(),
        )
        history = ledger._advance_history(active.records, record)
        written = ledger._append_leased_record(
            active.writer, body["token"], body["operation_name"], observations.state_parent, operation, root,
            manifest_sha256, manifest_size, ustar_sha256, ustar_size, entry_count, control,
        )
        node = fs.HeldNode(active.node.identity_fd, active.node.operation_fd, written.generation)
        writer = ledger.LedgerWriterState(node, written.stable_key, written.settled, written.generation)
        _fail(history.legal.settled == written.settled)
        active = _stable_active(ActiveLedger(node, history, writer), owned.locked.state, control)
        entries, parents = _walk_entries(owned.operation, control)
        observations = ledger.ReconcileObservations(
            _parent(owned.locked.state, control), ((owned.operation_name, fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)),),
            entries, _current_ledger(active, control), parents,
        )
        reconciled = ledger._reconcile_ledger(_records(active), observations)
        _fail(reconciled.status == "leased" and reconciled.lease_seen and not reconciled.cleanup_allowed)
        return OwnedOperation(owned.locked, active, owned.operation, owned.root, owned.operation_name)

    return _append, _append_candidate, _mark_leased


_append, _append_candidate, _mark_leased = _append_capabilities()
del _append_capabilities


def _observations(locked, records, ledger_generation, control):
    token = records[0].body_value()["token"]
    operation_name = _operation_name(token)
    state_snapshot = fs._enumerate_stable(locked.state, control)
    fixed = {STATE_SENTINEL_NAME.raw, LOCK_NAME.raw, LEDGER_NAME.raw}
    operation_names = [item for item in state_snapshot.names if item.raw not in fixed]
    if not operation_names:
        return ledger.ReconcileObservations(_parent(locked.state, control), (), (), ledger_generation), None
    _fail(len(operation_names) == 1 and operation_names[0] == operation_name)
    operation = None
    transferred = False
    with _owned_nodes(lambda: () if transferred or operation is None else (operation,)):
        operation = fs._open_path_node(locked.state, operation_name, "directory", control)
        entries, parents = _walk_entries(operation, control)
        value = ledger.ReconcileObservations(
            _parent(locked.state, control),
            ((operation_name.text, operation.generation),),
            entries,
            ledger_generation,
            parents,
        )
        transferred = True
        return value, operation


def _relative_parent_chain(active, locked, operation, path, opened, control):
    operation_chain = _held_operation_chain(active, locked, operation, control)
    components = operation_chain.components
    names = path.split("/")[:-1]
    _fail(len(names) == len(opened))
    components += tuple(fs.ChainComponent(fs._name(name), node) for name, node in zip(names, opened))
    return fs.HeldChain(operation_chain.anchor, components)


def _open_relative_parent(operation, path, control):
    parts = path.split("/")
    parent = operation
    opened = []
    try:
        for part in parts[:-1]:
            node = fs._open_path_node(parent, fs._name(part), "directory", control)
            opened.append(node)
            parent = node
        return parent, tuple(opened), fs._name(parts[-1])
    except BaseException as error:
        for node in reversed(opened):
            try:
                fs._close_node(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        raise error


def _poisoned(function):
    def guarded(session, *args, **kwargs):
        _fail(session.disposition == "active")
        try:
            return function(session, *args, **kwargs)
        except BaseException:
            session.disposition = "invalid"; raise
    return guarded

def _session_require(session, phase=None):
    _fail(type(session) is CleanupSession and session.disposition == "active")
    _fail(session.origin in {"prelease", "release-authorized"})
    _fail(type(session.active) is ActiveLedger and type(session.active.records) is ledger.LedgerHistory)
    legal = session.active.records.legal
    _fail(session.active.node is session.active.writer.node and legal.settled == session.active.writer.settled)
    if phase is None:
        origin_phase = "active" if session.origin == "prelease" else "release-authorized"
        _fail(legal.phase == origin_phase or legal.return_phase == origin_phase)
    else:
        phases = phase if type(phase) is tuple else (phase,)
        _fail(legal.phase in phases)

def _ledger_binding(session, control, phase=None):
    _session_require(session, phase)
    state_chain = _state_chain(session.locked, control)
    fs._revalidate_chain(state_chain, control)
    active = session.active
    current = _current_ledger(active, control)
    _fail(current == active.writer.generation)
    _fail(fs._observe_child(session.locked.state, LEDGER_NAME, control) == current)
    _fail(os.lseek(active.node.operation_fd.number, 0, os.SEEK_CUR) == active.writer.settled.offset)
    fs._revalidate_chain(state_chain, control)

def _session_binding(session, control, phase=None):
    _ledger_binding(session, control, phase)
    _fail(_parent(session.locked.state, control) == session.state_parent)
    if session.operation is not None:
        _fail(fs._observe_node(session.operation.identity_fd, session.operation.operation_fd, control) == session.operation_generation)

def _settled_hardlink_groups(records):
    groups = {}
    for record in records:
        body = record.body_value()
        if record.record_type == "hardlink-group":
            groups[body["target_path"]] = []
        elif record.record_type == "hardlink-create-settled":
            groups[body["target_path"]].append(body["alias"])
        elif record.record_type == "remove-settled" and body["target_path"] is not None:
            _fail(groups[body["target_path"]].pop() == body["path"])
    return tuple((target, tuple(aliases)) for target, aliases in groups.items())

def _require_cleanup_model(state, observations, history, groups):
    entries = dict(observations.entries)
    parents = dict(observations.parents)
    operations = dict(observations.operations)
    legal = history.legal
    _fail(state.terminal_record == history.terminal.record_type)
    phases = {
        "genesis-settleable": {"genesis"}, "genesis-abortable": {"ready"},
        "operation-abortable": {"operation-intent"}, "operation-create-settleable": {"operation-observed"},
        "entry-absent": {"create-intent", "hardlink-create-intent"},
        "create-settleable": {"create-observed"}, "metadata-settleable": {"metadata-observed"},
        "hardlink-create-settleable": {"hardlink-create-observed"},
        "candidate-tar-abortable": {"candidate-tar-intent"},
        "candidate-tar-observeable": {"candidate-tar-intent"},
        "candidate-tar-settleable": {"candidate-tar-observed"},
        "active": {"active"}, "release-authorized": {"release-authorized"},
        "remove-retry": {"remove-intent"}, "remove-absence-settleable": {"remove-intent"},
        "hardlink-remove-absence-settleable": {"remove-intent"}, "remove-settleable": {"remove-observed"},
        "operation-remove-retry": {"operation-remove"}, "operation-absence-settleable": {"operation-remove"},
        "retirable": {"aborted", "operation-absent"}, "retired": {"retired"},
    }
    _fail(legal.phase in phases[state.status])
    entry_phases = {"create-intent", "create-observed", "metadata-intent", "metadata-observed", "hardlink-create-intent", "hardlink-create-observed", "remove-intent", "remove-observed", "candidate-tar-intent", "candidate-tar-observed"}
    if legal.phase in entry_phases:
        _fail(legal.pending is history.terminal)
    else:
        _fail(legal.pending is None)
    if operations:
        _fail(len(operations) == 1 and "" in parents)
        _fail(next(iter(operations.values())) == parents[""].generation)
    else:
        _fail(not entries and not parents)
    for path, parent in parents.items():
        names = tuple(sorted((name.rpartition("/")[2] for name in entries if name.rpartition("/")[0] == path), key=lambda value: value.encode("utf-8")))
        _fail(parent.names == names)
        if path:
            _fail(entries.get(path) == parent.generation and parent.generation.key.kind == "directory")
    stable = {"active", "release-authorized", "entry-absent", "remove-retry", "operation-remove-retry", "candidate-tar-abortable"}
    if state.status in stable:
        _fail(entries == dict(state.owned))
    body = history.terminal.body_value()
    affected = set()
    if legal.phase.startswith(("create-", "metadata-", "hardlink-create-", "remove-", "candidate-tar-")):
        path = body.get("path", body.get("alias"))
        if legal.phase == "metadata-observed":
            affected.add(path)
        elif legal.phase.startswith("candidate-tar-"):
            affected.add("")
        else:
            affected.add(path.rpartition("/")[0])
            if legal.phase == "create-observed" and body["kind"] == "directory":
                affected.add(path)
    for path, parent in parents.items():
        if path not in affected:
            expected = legal.operation_parent if path == "" else ledger._map_get(legal.parents, path)
            _fail(expected == parent)
    pending_removed = body.get("path") if state.status in {"hardlink-remove-absence-settleable", "remove-settleable"} and body.get("target_path") is not None else None
    for target, aliases in groups.items():
        cursor = ledger._group_get(legal.groups, target)
        _fail(cursor is not None and tuple(aliases) == cursor.aliases[:cursor.next_index])
        _fail(not aliases or target in entries)
        for alias in aliases:
            _fail(alias == pending_removed and alias not in entries or entries.get(alias) == entries[target])


def _candidate_tar_observation(operation, entries, legal, control):
    if legal.phase not in {"candidate-tar-intent", "candidate-tar-observed"}:
        return None
    generation = dict(entries).get(CANDIDATE_TAR_NAME.text)
    if generation is None:
        return None
    expected_size = legal.pending.body_value()["size"]
    _fail(generation.key.kind == "file")
    node = fs._open_path_node(operation, CANDIDATE_TAR_NAME, "file", control)
    try:
        _fail(node.generation == generation)
        if generation.size != expected_size:
            value = (generation.size, None)
        else:
            raw = fs._read_regular(node, expected_size, control)
            value = (len(raw), hashlib.sha256(raw).hexdigest())
        _close(node)
        return value
    except BaseException as error:
        if node.identity_fd.disposition == "open":
            _close(node, error)
        raise


def _open_cleanup_session(active, locked, operation, origin, control):
    stable = _stable_active(active, locked.state, control)
    state_chain = _state_chain(locked, control)
    fs._revalidate_chain(state_chain, control)
    operation_chain = None if operation is None else _held_operation_chain(stable, locked, operation, control)
    if operation_chain is not None:
        fs._revalidate_chain(operation_chain, control)
    entries, parents = ((), ()) if operation is None else _walk_entries(operation, control)
    operation_generation = None if operation is None else fs._observe_node(operation.identity_fd, operation.operation_fd, control)
    operations = () if operation is None else ((_operation_name(_token(stable)).text, operation_generation),)
    candidate_tar = None if operation is None else _candidate_tar_observation(
        operation, entries, stable.records.legal, control,
    )
    observations = ledger.ReconcileObservations(
        _parent(locked.state, control), operations, entries, _current_ledger(stable, control),
        parents, candidate_tar,
    )
    if operation_chain is not None:
        fs._revalidate_chain(operation_chain, control)
    fs._revalidate_chain(state_chain, control)
    state = ledger._reconcile_ledger(_records(stable), observations)
    _fail(state.cleanup_allowed and state.cleanup_origin == origin)
    groups = {target: list(aliases) for target, aliases in _settled_hardlink_groups(_records(stable))}
    _require_cleanup_model(state, observations, stable.records, groups)
    session = CleanupSession(
        stable, locked, operation, origin, state.status, dict(entries), dict(parents), groups,
        operation_generation, observations.state_parent, candidate_tar,
    )
    named_boundary = {"genesis-settleable", "genesis-abortable", "operation-abortable", "operation-create-settleable", "retirable", "retired"}
    boundary_phase = stable.records.legal.phase if state.status in named_boundary else None
    _session_binding(session, control, boundary_phase)
    return session

@_poisoned
def _session_append(session, record_type, body, control):
    boundaries = {
        "genesis-settled": ("genesis", "ready"), "genesis-abort": ("ready", "aborted"),
        "operation-abort": ("operation-intent", "aborted"),
        "operation-create-settled": ("operation-observed", "active"),
        "candidate-tar-abort": ("candidate-tar-intent", "active"),
        "candidate-tar-observed": ("candidate-tar-intent", "candidate-tar-observed"),
        "candidate-tar-settled": ("candidate-tar-observed", "active"),
        "operation-absent": ("operation-remove", "operation-absent"),
        "retired": (("aborted", "operation-absent"), "retired"),
    }
    before_phase, after_phase = boundaries.get(record_type, (None, None))
    _ledger_binding(session, control, before_phase)
    previous = session.active.writer.settled
    proposal = ledger.LedgerProposal.create(record_type, body)
    raw = ledger._encode_proposal(proposal, previous)
    active = _append(session.active, record_type, body, control)
    _fail(active.writer.settled.offset == previous.offset + len(raw))
    control.check()
    _fail(os.pread(active.node.operation_fd.number, len(raw), previous.offset) == raw)
    control.check()
    session.active = active
    _ledger_binding(session, control, after_phase)

def _session_parent(session, path, expected, control):
    _session_binding(session, control)
    parent, opened, name = _open_relative_parent(session.operation, path, control)
    chain = _relative_parent_chain(session.active, session.locked, session.operation, path, opened, control)
    fs._revalidate_chain(chain, control)
    _fail(chain.components[-len(opened) - 1].node.generation == session.operation_generation)
    _fail(_parent(parent, control) == session.parents[path.rpartition("/")[0]])
    _fail(fs._observe_child(parent, name, control) == expected)
    fs._revalidate_chain(chain, control)
    return parent, opened, name, chain

def _settle_removed_model(session, path, post, target_path=None, target=None):
    _fail(session.owned.pop(path) is not None)
    parent_path = path.rpartition("/")[0]
    session.parents[parent_path] = post
    if parent_path:
        _fail(parent_path in session.owned)
        session.owned[parent_path] = post.generation
    else:
        session.operation_generation = post.generation
    session.parents.pop(path, None)
    if target_path is not None:
        _fail(target_path in session.owned and type(target) is fs.HostGeneration)
        session.owned[target_path] = target
        for alias in session.groups[target_path]:
            if alias in session.owned:
                session.owned[alias] = target

@_poisoned
def _finish_remove(session, path, expected, intent_exists, control):
    _session_require(session, "remove-intent" if intent_exists else None)
    parent, opened, name, parent_chain = _session_parent(session, path, expected, control)
    with _owned_nodes(lambda: opened):
        pre_snapshot = _parent_snapshot(parent, control)
        pre = _parent_value(pre_snapshot)
        _fail(pre == session.parents[path.rpartition("/")[0]])
        fs._revalidate_chain(parent_chain, control)
        if not intent_exists:
            kind = "directory" if expected.key.kind == "directory" else "infrastructure"
            body = {"token": _token(session.active), "path": path, "kind": kind, "parent": _p(pre), "child": _g(expected), "target_path": None}
            _session_append(session, "remove-intent", body, control)
        else:
            intent = _terminal_record(session.active).body_value()
            _fail(intent["path"] == path and ledger._parse_generation(intent["child"]) == expected)
            _fail(ledger._parse_parent(intent["parent"]) == pre)
        transition = _transition_control()
        fs._revalidate_chain(parent_chain, transition)
        _remove_name(parent, name, expected, transition)
        post_snapshot = _parent_snapshot(parent, transition)
        delta = fs.ParentDelta("rmdir" if expected.key.kind == "directory" else "unlink", name, pre_snapshot, post_snapshot)
        fs._revalidate_chain(parent_chain, transition, delta)
        parent_chain = _chain_after_parent(parent_chain, pre_snapshot.generation, post_snapshot.generation)
        fs._revalidate_chain(parent_chain, transition)
        _fail(name.raw not in post_snapshot.raw_names)
        post = _parent_value(post_snapshot)
        kind = "directory" if expected.key.kind == "directory" else "infrastructure"
        observed = {"token": _token(session.active), "path": path, "kind": kind, "parent": _p(post), "target_path": None, "target": None}
        _session_append(session, "remove-observed", observed, transition)
        _settle_removed_model(session, path, post)
        fs._revalidate_chain(parent_chain, transition)
        _session_append(session, "remove-settled", observed, transition)
        fs._revalidate_chain(parent_chain, transition)
        _session_require(session)
        control.check()

@_poisoned
def _finish_absent_remove(session, control):
    _session_require(session, "remove-intent")
    _session_binding(session, control)
    intent = _terminal_record(session.active).body_value()
    path = intent["path"]
    parent, opened, name = _open_relative_parent(session.operation, path, control)
    target = None
    target_opened = ()
    transition = _transition_control()
    with _owned_nodes(lambda: opened + target_opened + (() if target is None else (target,))):
        parent_chain = _relative_parent_chain(session.active, session.locked, session.operation, path, opened, transition)
        fs._revalidate_chain(parent_chain, transition)
        _fail(name.raw not in fs._enumerate_stable(parent, transition).raw_names)
        post = _parent(parent, transition)
        _fail(post == session.parents[path.rpartition("/")[0]])
        fs._revalidate_chain(parent_chain, transition)
        _fail(ledger._valid_parent_delta("rmdir" if intent["kind"] == "directory" else "unlink", name.text, ledger._parse_parent(intent["parent"]), post))
        target_generation = None
        if intent["target_path"] is not None:
            target_parent, target_opened, target_name = _open_relative_parent(session.operation, intent["target_path"], transition)
            target_chain = _relative_parent_chain(session.active, session.locked, session.operation, intent["target_path"], target_opened, transition)
            fs._revalidate_chain(target_chain, transition)
            target = fs._open_path_node(target_parent, target_name, "file", transition)
            target_generation = fs._observe_node(target.identity_fd, target.operation_fd, transition)
            _fail(target.generation == target_generation == session.owned[intent["target_path"]])
            ledger._hardlink_generation_change(ledger._parse_generation(intent["child"]), target_generation, -1)
            _fsync(target.operation_fd, transition)
            fs._revalidate_chain(_chain_with_child(target_chain, target_name, target), transition)
        _fsync(parent.operation_fd, transition)
        fs._revalidate_chain(parent_chain, transition)
        observed = {"token": _token(session.active), "path": path, "kind": intent["kind"], "parent": _p(post), "target_path": intent["target_path"], "target": None if target_generation is None else _g(target_generation)}
        _session_append(session, "remove-observed", observed, transition)
        fs._revalidate_chain(parent_chain, transition)
        if target is not None: fs._revalidate_chain(_chain_with_child(target_chain, target_name, target), transition)
        _session_append(session, "remove-settled", observed, transition)
        fs._revalidate_chain(parent_chain, transition)
        if target is not None: fs._revalidate_chain(_chain_with_child(target_chain, target_name, target), transition)
        if intent["target_path"] is not None:
            aliases = session.groups[intent["target_path"]]
            _fail(aliases.pop() == path)
        _session_require(session)
        control.check()

@_poisoned
def _finish_hardlink_remove(session, alias_path, target_path, target_generation, control, intent_exists=False):
    _session_require(session, "remove-intent" if intent_exists else None)
    alias_parent, alias_opened, alias_name, alias_chain = _session_parent(session, alias_path, target_generation, control)
    target_opened = ()
    target = alias_node = None
    with _owned_nodes(lambda: alias_opened + target_opened + (() if target is None else (target,)) + (() if alias_node is None else (alias_node,))):
        target_parent, target_opened, target_name = _open_relative_parent(session.operation, target_path, control)
        target_chain = _relative_parent_chain(session.active, session.locked, session.operation, target_path, target_opened, control)
        fs._revalidate_chain(target_chain, control)
        target = fs._open_path_node(target_parent, target_name, "file", control)
        alias_node = fs._open_path_node(alias_parent, alias_name, "file", control)
        _fail(alias_node.generation == session.owned[alias_path] == target.generation == target_generation == session.owned[target_path])
        alias_node_chain = _chain_with_child(alias_chain, alias_name, alias_node)
        target_node_chain = _chain_with_child(target_chain, target_name, target)
        fs._revalidate_chain(alias_node_chain, control)
        fs._revalidate_chain(target_node_chain, control)
        pre_snapshot = _parent_snapshot(alias_parent, control)
        pre = _parent_value(pre_snapshot)
        _fail(pre == session.parents[alias_path.rpartition("/")[0]])
        fs._revalidate_chain(alias_node_chain, control)
        fs._revalidate_chain(target_node_chain, control)
        body = {"token": _token(session.active), "path": alias_path, "kind": "hardlink", "parent": _p(pre), "child": _g(target_generation), "target_path": target_path}
        if intent_exists:
            _fail(_terminal_record(session.active).body_value() == body)
        else:
            _session_append(session, "remove-intent", body, control)
        transition = _transition_control()
        fs._revalidate_chain(alias_node_chain, transition)
        fs._revalidate_chain(target_node_chain, transition)
        _check(transition)
        os.unlink(alias_name.raw, dir_fd=alias_parent.operation_fd.number)
        _check(transition)
        current_target = fs._observe_node(target.identity_fd, target.operation_fd, transition)
        ledger._hardlink_generation_change(target_generation, current_target, -1)
        _fsync(target.operation_fd, transition)
        _fsync(alias_parent.operation_fd, transition)
        post_snapshot = _parent_snapshot(alias_parent, transition)
        delta = fs.ParentDelta("unlink", alias_name, pre_snapshot, post_snapshot)
        fs._revalidate_chain(alias_chain, transition, delta)
        current_alias_chain = _chain_after_parent(alias_chain, pre_snapshot.generation, post_snapshot.generation)
        fs._revalidate_chain(current_alias_chain, transition)
        target_delta = _delta_for_chain(target_chain, delta)
        fs._revalidate_chain(target_chain, transition, target_delta)
        current_chain = target_chain if target_delta is None else _chain_after_parent(target_chain, pre_snapshot.generation, post_snapshot.generation)
        current_target_chain = _chain_with_child(current_chain, target_name, fs.HeldNode(target.identity_fd, target.operation_fd, current_target))
        fs._revalidate_chain(current_target_chain, transition)
        post = _parent_value(post_snapshot)
        observed = {"token": _token(session.active), "path": alias_path, "kind": "hardlink", "parent": _p(post), "target_path": target_path, "target": _g(current_target)}
        _session_append(session, "remove-observed", observed, transition)
        fs._revalidate_chain(current_alias_chain, transition)
        fs._revalidate_chain(current_target_chain, transition)
        _settle_removed_model(session, alias_path, post, target_path, current_target)
        fs._revalidate_chain(current_target_chain, transition)
        _session_append(session, "remove-settled", observed, transition)
        fs._revalidate_chain(current_alias_chain, transition)
        fs._revalidate_chain(current_target_chain, transition)
        _fail(session.groups[target_path].pop() == alias_path)
        _session_require(session)
        control.check()

@_poisoned
def _resume_candidate_tar(session, control):
    _session_binding(session, control)
    terminal = _terminal_record(session.active)
    _session_require(session, terminal.record_type)
    _fail(terminal.record_type in {"candidate-tar-intent", "candidate-tar-observed"})
    if session.status == "candidate-tar-abortable":
        _fail(terminal.record_type == "candidate-tar-intent")
        _session_append(session, "candidate-tar-abort", terminal.body_value(), control)
        return _cleanup_active(session, control)
    intent = terminal.body_value()
    if terminal.record_type == "candidate-tar-observed":
        intent = session.active.records.previous.terminal.body_value()
    linked = session.owned[CANDIDATE_TAR_NAME.text]
    _fail(session.candidate_tar == (intent["size"], intent["sha256"]))
    node = fs._open_path_node(session.operation, CANDIDATE_TAR_NAME, "file", control)
    try:
        _fail(node.generation == linked)
        _fsync(node.operation_fd, control)
        _fsync(session.operation.operation_fd, control)
        body = {
            "token": intent["token"], "path": intent["path"],
            "parent": _p(session.parents[""]), "anonymous": intent["anonymous"],
            "linked": _g(linked), "size": intent["size"], "sha256": intent["sha256"],
        }
        if terminal.record_type == "candidate-tar-intent":
            _session_append(session, "candidate-tar-observed", body, control)
        else:
            _fail(terminal.body_value() == body)
        _session_append(session, "candidate-tar-settled", body, control)
        _close(node)
    except BaseException as error:
        if node.identity_fd.disposition == "open":
            _close(node, error)
        raise
    return _cleanup_active(session, control)


@_poisoned
def _cleanup_active(session, control):
    _session_require(session)
    for target_path, aliases in reversed(tuple(session.groups.items())):
        for alias_path in reversed(tuple(aliases)):
            _finish_hardlink_remove(session, alias_path, target_path, session.owned[target_path], control)
    for path in sorted(tuple(session.owned), key=lambda value: (value.count("/"), value.encode("utf-8")), reverse=True):
        _finish_remove(session, path, session.owned[path], False, control)
    _fail(not session.owned and all(not aliases for aliases in session.groups.values()))
    boundary = _open_cleanup_session(session.active, session.locked, session.operation, session.origin, control)
    session.disposition = "finished"
    _fail(boundary.status in {"active", "release-authorized"} and not boundary.owned)
    return _retire(boundary, control)

@_poisoned
def _resume_entry_remove(session, control):
    _session_require(session, "remove-intent")
    intent = _terminal_record(session.active).body_value()
    if session.status == "remove-retry":
        expected = ledger._parse_generation(intent["child"])
        if intent["target_path"] is None:
            _finish_remove(session, intent["path"], expected, True, control)
        else:
            _finish_hardlink_remove(session, intent["path"], intent["target_path"], expected, control, True)
    else:
        _finish_absent_remove(session, control)
    return _cleanup_active(session, control)

@_poisoned
def _resume_observed(session, control):
    _session_binding(session, control)
    record = _terminal_record(session.active)
    body = record.body_value()
    kind = record.record_type
    _session_require(session, kind)
    _fail(kind in {"create-observed", "metadata-observed", "hardlink-create-observed", "remove-observed"})
    path = body.get("path", body.get("alias"))
    parent, opened, name = _open_relative_parent(session.operation, path, control)
    extra_opened, child, child_chain = (), None, None
    with _owned_nodes(lambda: opened + extra_opened + (() if child is None else (child,))):
        chain = _relative_parent_chain(session.active, session.locked, session.operation, path, opened, control)
        fs._revalidate_chain(chain, control)
        _fail(_parent(parent, control) == session.parents[path.rpartition("/")[0]])
        if kind in {"create-observed", "metadata-observed"}:
            expected = ledger._parse_generation(body["child"])
            child = fs._open_path_node(parent, name, expected.key.kind, control)
            _fail(child.generation == expected == session.owned[path])
            child_chain = _chain_with_child(chain, name, child)
            if child.operation_fd is not None:
                _fsync(child.operation_fd, control)
        elif kind == "hardlink-create-observed":
            expected = ledger._parse_generation(body["alias_generation"])
            _fail(fs._observe_child(parent, name, control) == expected == session.owned[path])
            target_parent, extra_opened, target_name = _open_relative_parent(session.operation, body["target_path"], control)
            target_chain = _relative_parent_chain(session.active, session.locked, session.operation, body["target_path"], extra_opened, control)
            fs._revalidate_chain(target_chain, control)
            child = fs._open_path_node(target_parent, target_name, "file", control)
            _fail(child.generation == ledger._parse_generation(body["target_after"]) == session.owned[body["target_path"]])
            child_chain = _chain_with_child(target_chain, target_name, child)
            fs._revalidate_chain(child_chain, control)
            _fsync(child.operation_fd, control)
        else:
            _fail(name.raw not in fs._enumerate_stable(parent, control).raw_names and path not in session.owned)
            if body["target"] is not None:
                target_parent, extra_opened, target_name = _open_relative_parent(session.operation, body["target_path"], control)
                target_chain = _relative_parent_chain(session.active, session.locked, session.operation, body["target_path"], extra_opened, control)
                fs._revalidate_chain(target_chain, control)
                child = fs._open_path_node(target_parent, target_name, "file", control)
                _fail(child.generation == ledger._parse_generation(body["target"]) == session.owned[body["target_path"]])
                child_chain = _chain_with_child(target_chain, target_name, child)
                fs._revalidate_chain(child_chain, control)
                _fsync(child.operation_fd, control)
        _fsync(parent.operation_fd, control)
        fs._revalidate_chain(chain, control)
        if child_chain is not None: fs._revalidate_chain(child_chain, control)
        _session_append(session, kind.removesuffix("observed") + "settled", body, control)
        fs._revalidate_chain(chain, control)
        if child_chain is not None: fs._revalidate_chain(child_chain, control)
        if kind == "hardlink-create-observed":
            session.groups[body["target_path"]].append(path)
        elif kind == "remove-observed" and body["target_path"] is not None:
            _fail(session.groups[body["target_path"]].pop() == path)
    return _cleanup_active(session, control)

@_poisoned
def _resume_absent_create(session, control):
    _session_binding(session, control)
    intent = _terminal_record(session.active)
    _session_require(session, intent.record_type)
    _fail(intent.record_type in {"create-intent", "hardlink-create-intent"})
    body = intent.body_value()
    path = body.get("path", body.get("alias"))
    _parent_node, opened, name = _open_relative_parent(session.operation, path, control)
    with _owned_nodes(lambda: opened):
        chain = _relative_parent_chain(session.active, session.locked, session.operation, path, opened, control)
        body = _absence_abort_body(body, chain, name, control)
    _session_append(session, intent.record_type.removesuffix("intent") + "abort", body, control)
    return _cleanup_active(session, control)

@_poisoned
def _unlink_ledger(session, control):
    _session_require(session, "retired")
    _session_binding(session, control, "retired")
    state_chain = _state_chain(session.locked, control)
    before_snapshot = _parent_snapshot(session.locked.state, control)
    _fail(_parent_value(before_snapshot) == session.state_parent)
    fs._revalidate_chain(state_chain, control)
    expected = fs._observe_node(session.active.node.identity_fd, session.active.node.operation_fd, control)
    _close(session.active.node)
    _remove_name(session.locked.state, LEDGER_NAME, expected, control)
    after_snapshot = _parent_snapshot(session.locked.state, control)
    delta = fs.ParentDelta("unlink", LEDGER_NAME, before_snapshot, after_snapshot)
    fs._revalidate_chain(state_chain, control, delta)
    _fail(after_snapshot.raw_names == tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw))))
    sentinel = _verify_fixed_file(session.locked.state, STATE_SENTINEL_NAME, STATE_SENTINEL, control)
    _close(sentinel)
    _fail(fs._observe_child(session.locked.state, LOCK_NAME, control) == session.locked.lock.generation)
    _fail(fs._enumerate_stable(session.locked.state, control).raw_names == after_snapshot.raw_names)
    session.disposition = "finished"

@_poisoned
def _retire_absent(session, control):
    _session_require(session, ("aborted", "operation-absent"))
    boundary = _open_cleanup_session(session.active, session.locked, None, session.origin, control)
    session.disposition = "finished"
    _fail(boundary.status == "retirable")
    _session_append(boundary, "retired", {"token": _token(boundary.active), "state_parent": _p(boundary.state_parent)}, control)
    final = _open_cleanup_session(boundary.active, boundary.locked, None, boundary.origin, control)
    boundary.disposition = "finished"
    _fail(final.status == "retired")
    return _unlink_ledger(final, control)

@_poisoned
def _retire(session, control, intent_exists=False):
    _session_require(session, "operation-remove" if intent_exists else None)
    _fail(session.operation is not None and not session.owned)
    operation_chain = _held_operation_chain(session.active, session.locked, session.operation, control)
    fs._revalidate_chain(operation_chain, control)
    _fail(operation_chain.components[-1].node.generation == session.operation_generation)
    _fail(not fs._enumerate_stable(session.operation, control).names)
    token = _token(session.active)
    operation_name = _operation_name(token)
    state_chain = _state_chain(session.locked, control)
    fs._revalidate_chain(state_chain, control)
    pre_snapshot = _parent_snapshot(session.locked.state, control)
    pre = _parent_value(pre_snapshot)
    _fail(pre == session.state_parent)
    fs._revalidate_chain(state_chain, control)
    fs._revalidate_chain(operation_chain, control)
    if not intent_exists:
        _session_append(session, "operation-remove-intent", {"token": token, "operation_name": operation_name.text, "state_parent": _p(pre), "operation": _g(session.operation_generation)}, control)
    else:
        intent = _terminal_record(session.active).body_value()
        _fail(ledger._parse_parent(intent["state_parent"]) == pre)
        _fail(ledger._parse_generation(intent["operation"]) == session.operation_generation)
    transition = _transition_control()
    fs._revalidate_chain(operation_chain, transition)
    expected = fs._observe_node(session.operation.identity_fd, session.operation.operation_fd, transition)
    _fail(expected == session.operation_generation)
    _close(session.operation)
    _remove_name(session.locked.state, operation_name, expected, transition)
    post_snapshot = _parent_snapshot(session.locked.state, transition)
    delta = fs.ParentDelta("rmdir", operation_name, pre_snapshot, post_snapshot)
    fs._revalidate_chain(state_chain, transition, delta)
    session.operation = None
    session.operation_generation = None
    session.state_parent = _parent_value(post_snapshot)
    _session_append(session, "operation-absent", {"token": token, "operation_name": operation_name.text, "state_parent": _p(session.state_parent)}, transition)
    control.check()
    return _retire_absent(session, control)

@_poisoned
def _finish_operation_absent(session, control):
    _session_require(session, "operation-remove")
    _fail(session.operation is None)
    transition = _transition_control()
    _fsync(session.locked.state.operation_fd, transition)
    post = _parent(session.locked.state, transition)
    _fail(post == session.state_parent)
    token = _token(session.active)
    _session_append(session, "operation-absent", {"token": token, "operation_name": _operation_name(token).text, "state_parent": _p(post)}, transition)
    control.check()
    return _retire_absent(session, control)

@_poisoned
def _abort(session, record_type, control):
    token = _token(session.active)
    body = {"token": token, "state_parent": _p(session.state_parent)}
    if record_type == "operation-abort":
        body = {"token": token, "operation_name": _operation_name(token).text, "state_parent": _p(session.state_parent)}
    _session_append(session, record_type, body, control)
    return _retire_absent(session, control)

@_poisoned
def _settle_startup(session, control):
    token = _token(session.active)
    if session.status == "genesis-settleable":
        _session_append(session, "genesis-settled", {"token": token, "state_parent": _terminal_record(session.active).body_value()["state_parent"]}, control)
        return _abort(session, "genesis-abort", control)
    _fail(session.status == "operation-create-settleable" and session.operation is not None)
    body = _terminal_record(session.active).body_value()
    _fail(fs._observe_node(session.operation.identity_fd, session.operation.operation_fd, control) == ledger._parse_generation(body["operation"]) == session.operation_generation)
    _fsync(session.operation.operation_fd, control)
    _fsync(session.locked.state.operation_fd, control)
    _session_append(session, "operation-create-settled", body, control)
    return _cleanup_active(session, control)

def _cleanup_owned(owned, active, control):
    _fail(type(owned) is OwnedOperation and type(active) is ActiveLedger)
    session = _open_cleanup_session(active, owned.locked, owned.operation, "prelease", control)
    try:
        _close(owned.root)
    except BaseException:
        session.disposition = "invalid"
        raise
    if session.status == "entry-absent":
        _resume_absent_create(session, control)
    elif session.status in {"candidate-tar-abortable", "candidate-tar-observeable", "candidate-tar-settleable"}:
        _resume_candidate_tar(session, control)
    elif session.status in {"create-settleable", "metadata-settleable", "hardlink-create-settleable", "remove-settleable"}:
        _resume_observed(session, control)
    else:
        _fail(session.status == "active")
        _cleanup_active(session, control)
    _release_lock(owned.locked)
    _close(owned.locked.state)

def _recover_locked(chain, state, control):
    locked = _acquire_lock(chain, state, control)
    active = operation = None
    try:
        names = fs._enumerate_stable(state, control).raw_names
        fixed_idle = tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw)))
        if names == fixed_idle:
            _release_lock(locked)
            return
        _fail(LEDGER_NAME.raw in names)
        active = _read_active_ledger(state, control)
        genesis = _first_record(active).body_value()
        fs._verify_source_bundle(_source(chain), fs.SourceApproval(genesis["source_revision"], genesis["source_manifest_sha256"]), control)
        state_snapshot = fs._enumerate_stable(locked.state, control)
        operation_names = [item for item in state_snapshot.names if item.raw not in {STATE_SENTINEL_NAME.raw, LOCK_NAME.raw, LEDGER_NAME.raw}]
        if operation_names:
            _fail(operation_names == [_operation_name(_token(active))])
            operation = fs._open_path_node(locked.state, operation_names[0], "directory", control)
        session = _open_cleanup_session(active, locked, operation, "release-authorized" if active.records.legal.phase == "release-authorized" or active.records.legal.return_phase == "release-authorized" or active.records.legal.lease_snapshot is not None else "prelease", control)
        active = session.active
        status = session.status
        if status in {"genesis-settleable", "operation-create-settleable"}:
            _settle_startup(session, control)
        elif status == "genesis-abortable":
            _abort(session, "genesis-abort", control)
        elif status == "operation-abortable":
            _abort(session, "operation-abort", control)
        elif status in {"active", "release-authorized"}:
            _fail(operation is not None)
            _cleanup_active(session, control)
        elif status == "entry-absent":
            _resume_absent_create(session, control)
        elif status in {"candidate-tar-abortable", "candidate-tar-observeable", "candidate-tar-settleable"}:
            _resume_candidate_tar(session, control)
        elif status in {"create-settleable", "metadata-settleable", "hardlink-create-settleable", "remove-settleable"}:
            _resume_observed(session, control)
        elif status in {"remove-retry", "remove-absence-settleable", "hardlink-remove-absence-settleable"}:
            _resume_entry_remove(session, control)
        elif status == "operation-remove-retry":
            _retire(session, control, True)
        elif status == "operation-absence-settleable":
            _finish_operation_absent(session, control)
        elif status == "retirable":
            _retire_absent(session, control)
        elif status == "retired":
            _unlink_ledger(session, control)
        else:
            raise BuilderError()
        active = operation = None
        _release_lock(locked)
    except BaseException as error:
        if operation is not None and operation.identity_fd.disposition == "open":
            try:
                _close(operation)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if active is not None and active.node.identity_fd.disposition == "open":
            try:
                _close(active.node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        _release_lock(locked, error)
def _recover_fixed_unmasked(control):
    _fail(Path(__file__).resolve() == FIXED_MODULE)
    chain = _open_base_chain(control)
    try:
        state = _open_state(chain, control)
        if state is None:
            fs._close_chain(chain)
            return
        try:
            _recover_locked(chain, state, control)
            _close(state)
            fs._close_chain(chain)
        except BaseException as error:
            if state.identity_fd.disposition == "open":
                _close(state, error)
            raise
    except BaseException as error:
        if chain.anchor.identity_fd.disposition == "open":
            fs._close_chain(chain, error)
        raise


def _recover_fixed(control):
    return _fixed_umask(_recover_fixed_unmasked, control)


def _run_recovery():
    latch = CancellationLatch()

    def cancel(_signum, _frame):
        latch.cancelled = True

    previous = {}
    error = None
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, cancel)
        control = fs.OperationControl(time.monotonic_ns() + RECOVER_SECONDS * 1_000_000_000, lambda: latch.cancelled)
        _recover_fixed(control)
    except BaseException as caught:
        error = caught
    for signum, handler in previous.items():
        try:
            signal.signal(signum, handler)
        except BaseException as restore_error:
            error = fs.RootfsFsError(error, restore_error)
    if error is not None:
        raise error


def main(argv):
    try:
        if argv != ["recover-owned"]:
            raise BuilderError()
        _run_recovery()
        return 0
    except BaseException:
        print("completion rootfs recovery failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

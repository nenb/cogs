"""Fixed rootfs ownership lifecycle and exact recover-owned command for ADR 0040."""

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
RECOVER_SECONDS = 120
FIXED_MODULE = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_rootfs_builder.py")
SOURCE_INDEX = 4
COMPLETION_INDEX = 8


class BuilderError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise BuilderError()


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
    records: tuple
    writer: ledger.LedgerWriterState


@dataclass(frozen=True)
class OwnedOperation:
    locked: LockedState
    active: ActiveLedger
    operation: fs.HeldNode
    root: fs.HeldNode
    operation_name: str


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


def _parent(node, control):
    snapshot = fs._enumerate_stable(node, control)
    return ledger.LedgerParent(snapshot.generation, tuple(item.text for item in snapshot.names))


def _policy(node, kind, mode, root_key):
    generation = node.generation
    _fail(generation.key.kind == kind and generation.mode == mode)
    _fail(generation.uid == generation.gid == 0)
    _fail(generation.key.mount_id == root_key.mount_id and generation.key.device == root_key.device)
    _fail(generation.nlink == 1 if kind == "file" else generation.nlink >= 2)


def _close(node, primary=None):
    fs._close_node(node, primary)


def _create_directory(parent, name, control):
    _check(control)
    os.mkdir(name.raw, 0o700, dir_fd=parent.operation_fd.number)
    _check(control)
    node = fs._open_path_node(parent, name, "directory", control)
    _policy(node, "directory", 0o700, parent.generation.key)
    fs._require_empty_fd_xattrs(node, control)
    return node


def _create_file(parent, name, content, control):
    _fail(type(content) is bytes)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    _check(control)
    descriptor = fs.CheckedFd(os.open(name.raw, flags, 0o600, dir_fd=parent.operation_fd.number), "created-file")
    try:
        _check(control)
        _write_all(descriptor, content, control)
        _fsync(descriptor, control)
        descriptor.close()
    except BaseException as error:
        if descriptor.disposition == "open":
            descriptor.close(error)
        raise
    node = fs._open_path_node(parent, name, "file", control)
    _policy(node, "file", 0o600, parent.generation.key)
    fs._require_empty_fd_xattrs(node, control)
    _fail(fs._read_regular(node, max(1, len(content)), control) == content)
    return node


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


def _bootstrap(chain, approval, control):
    _fail(type(approval) is fs.SourceApproval)
    fs._verify_source_bundle(_source(chain), approval, control)
    completion = _completion(chain)
    before = fs._enumerate_stable(completion, control)
    _fail(STATE_NAME.raw not in before.raw_names)
    state = _create_directory(completion, STATE_NAME, control)
    try:
        _fsync(state.operation_fd, control)
        _fsync(completion.operation_fd, control)
        sentinel = _create_file(state, STATE_SENTINEL_NAME, STATE_SENTINEL, control)
        _close(sentinel)
        _fsync(state.operation_fd, control)
        lock = _create_file(state, LOCK_NAME, b"", control)
        _close(lock)
        _fsync(state.operation_fd, control)
        snapshot = fs._enumerate_stable(state, control)
        _fail(snapshot.raw_names == tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw))))
        return state
    except BaseException as error:
        if state.identity_fd.disposition == "open":
            _close(state, error)
        raise


def _open_state(chain, control):
    completion = _completion(chain)
    snapshot = fs._enumerate_stable(completion, control)
    if STATE_NAME.raw not in snapshot.raw_names:
        return None
    state = fs._open_path_node(completion, STATE_NAME, "directory", control)
    _policy(state, "directory", 0o700, completion.generation.key)
    fs._require_empty_fd_xattrs(state, control)
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


def _ledger_node(state, control, create=False):
    if create:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
        _check(control)
        created = fs.CheckedFd(os.open(LEDGER_NAME.raw, flags, 0o600, dir_fd=state.operation_fd.number), "ledger-create")
        _check(control)
        created.close()
        _fsync(state.operation_fd, control)
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


def _new_active_ledger(state, control):
    node = _ledger_node(state, control, create=True)
    writer = ledger.LedgerWriterState(node, node.generation.key, ledger.INITIAL_BYTES, node.generation)
    return ActiveLedger(node, (), writer)


def _read_active_ledger(state, control):
    node = _ledger_node(state, control)
    try:
        raw = fs._read_regular(node, ledger.MAX_LEDGER_BYTES, control)
        records = ledger._parse_ledger(raw)
        last = records[-1]
        settled = ledger.SettledBytes(last.sequence, last.next_offset, last.line_sha256)
        _check(control)
        os.lseek(node.operation_fd.number, settled.offset, os.SEEK_SET)
        _check(control)
        current = fs._observe_node(node.identity_fd, node.operation_fd, control)
        writer = ledger.LedgerWriterState(node, node.generation.key, settled, current)
        return ActiveLedger(node, records, writer)
    except BaseException as error:
        if node.identity_fd.disposition == "open":
            _close(node, error)
        raise


def _append(active, record_type, body, control):
    proposal = ledger.LedgerProposal.create(record_type, body)
    raw = ledger._encode_proposal(proposal, active.writer.settled)
    writer = ledger._append_record(active.writer, proposal, control)
    sequence = active.writer.settled.sequence + 1
    digest = hashlib.sha256(raw).hexdigest()
    record = ledger.LedgerRecord(
        sequence,
        active.writer.settled.sequence,
        active.writer.settled.offset,
        active.writer.settled.line_sha256,
        active.writer.settled.offset + len(raw),
        record_type,
        proposal.body,
        digest,
    )
    return ActiveLedger(active.node, active.records + (record,), writer)


def _g(value):
    return ledger._generation_value(value)


def _p(value):
    return ledger._parent_value(value)


def _operation_name(token):
    return fs._name(ledger._operation_name(token))


def _create_ledger_entry(active, operation, path, name, kind, content, control):
    pre = _parent(operation, control)
    active = _append(active, "create-intent", {"token": _token(active), "path": path, "kind": kind, "parent": _p(pre)}, control)
    child = _create_directory(operation, name, control) if kind == "directory" else _create_file(operation, name, content, control)
    post = _parent(operation, control)
    active = _append(active, "create-observed", {"token": _token(active), "path": path, "kind": kind, "parent": _p(post), "child": _g(child.generation)}, control)
    _fsync(operation.operation_fd, control)
    active = _append(active, "create-settled", {"token": _token(active), "path": path, "kind": kind, "parent": _p(post), "child": _g(child.generation)}, control)
    return active, child


def _token(active):
    return active.records[0].body_value()["token"]


def _begin_operation(chain, approval, token, control):
    _fail(type(approval) is fs.SourceApproval)
    ledger._token(token)
    fs._verify_source_bundle(_source(chain), approval, control)
    state = _open_state(chain, control)
    _fail(state is not None)
    locked = _acquire_lock(chain, state, control)
    try:
        names = fs._enumerate_stable(state, control).raw_names
        _fail(names == tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw))))
        active = _new_active_ledger(state, control)
        state_parent = _parent(state, control)
        body = {
            "token": token,
            "source_revision": approval.revision,
            "source_manifest_sha256": approval.manifest_sha256,
            "state_parent": _p(state_parent),
            "ledger_key": {
                "mount_id": active.node.generation.key.mount_id,
                "device": active.node.generation.key.device,
                "inode": active.node.generation.key.inode,
                "kind": "file",
            },
        }
        active = _append(active, "genesis", body, control)
        _fsync(state.operation_fd, control)
        active = _append(active, "genesis-settled", {"token": token, "state_parent": _p(state_parent)}, control)
        operation_name = _operation_name(token)
        pre = _parent(state, control)
        active = _append(active, "operation-create-intent", {"token": token, "operation_name": operation_name.text, "state_parent": _p(pre)}, control)
        operation = _create_directory(state, operation_name, control)
        post = _parent(state, control)
        observed = {"token": token, "operation_name": operation_name.text, "state_parent": _p(post), "operation": _g(operation.generation)}
        active = _append(active, "operation-create-observed", observed, control)
        _fsync(operation.operation_fd, control)
        _fsync(state.operation_fd, control)
        active = _append(active, "operation-create-settled", observed, control)
        active, sentinel = _create_ledger_entry(active, operation, OPERATION_SENTINEL_NAME.text, OPERATION_SENTINEL_NAME, "file", OPERATION_SENTINEL, control)
        _close(sentinel)
        active, root = _create_ledger_entry(active, operation, ROOT_NAME.text, ROOT_NAME, "directory", None, control)
        return OwnedOperation(locked, active, operation, root, operation_name.text)
    except BaseException as error:
        _release_lock(locked, error)


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
    entries = {}
    parents = {}

    def visit(directory, prefix):
        current = _parent(directory, control)
        parents[prefix] = current
        snapshot = fs._enumerate_stable(directory, control)
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


def _observations(locked, records, control):
    token = records[0].body_value()["token"]
    operation_name = _operation_name(token)
    state_snapshot = fs._enumerate_stable(locked.state, control)
    fixed = {STATE_SENTINEL_NAME.raw, LOCK_NAME.raw, LEDGER_NAME.raw}
    operation_names = [item for item in state_snapshot.names if item.raw not in fixed]
    if not operation_names:
        return ledger.ReconcileObservations(_parent(locked.state, control), (), ()), None
    _fail(len(operation_names) == 1 and operation_names[0] == operation_name)
    operation = fs._open_path_node(locked.state, operation_name, "directory", control)
    entries, parents = _walk_entries(operation, control)
    value = ledger.ReconcileObservations(
        _parent(locked.state, control),
        ((operation_name.text, operation.generation),),
        entries,
        parents,
    )
    return value, operation


def _open_relative_parent(operation, path, control):
    parts = path.split("/")
    parent = operation
    opened = []
    for part in parts[:-1]:
        node = fs._open_path_node(parent, fs._name(part), "directory", control)
        opened.append(node)
        parent = node
    return parent, tuple(opened), fs._name(parts[-1])


def _finish_remove(active, operation, path, expected, intent_exists, control):
    parent, opened, name = _open_relative_parent(operation, path, control)
    try:
        pre = _parent(parent, control)
        if not intent_exists:
            kind = "directory" if expected.key.kind == "directory" else "infrastructure"
            body = {"token": _token(active), "path": path, "kind": kind, "parent": _p(pre), "child": _g(expected), "target_path": None}
            active = _append(active, "remove-intent", body, control)
        else:
            intent = active.records[-1].body_value()
            _fail(intent["path"] == path and ledger._parse_generation(intent["child"]) == expected)
            _fail(ledger._parse_parent(intent["parent"]) == pre)
        _remove_name(parent, name, expected, control)
        post = _parent(parent, control)
        kind = "directory" if expected.key.kind == "directory" else "infrastructure"
        observed = {"token": _token(active), "path": path, "kind": kind, "parent": _p(post), "target_path": None, "target": None}
        active = _append(active, "remove-observed", observed, control)
        active = _append(active, "remove-settled", observed, control)
        return active, post.generation
    finally:
        for node in reversed(opened):
            _close(node)


def _finish_absent_remove(active, operation, control):
    intent = active.records[-1].body_value()
    path = intent["path"]
    parent, opened, name = _open_relative_parent(operation, path, control)
    try:
        _fail(name.raw not in fs._enumerate_stable(parent, control).raw_names)
        post = _parent(parent, control)
        kind = intent["kind"]
        observed = {"token": _token(active), "path": path, "kind": kind, "parent": _p(post), "target_path": intent["target_path"], "target": None}
        active = _append(active, "remove-observed", observed, control)
        return _append(active, "remove-settled", observed, control)
    finally:
        for node in reversed(opened):
            _close(node)


def _retire(active, locked, operation, control, intent_exists=False):
    _fail(not fs._enumerate_stable(operation, control).names)
    token = _token(active)
    operation_name = _operation_name(token)
    pre = _parent(locked.state, control)
    if not intent_exists:
        active = _append(
            active,
            "operation-remove-intent",
            {"token": token, "operation_name": operation_name.text, "state_parent": _p(pre), "operation": _g(fs._observe_node(operation.identity_fd, operation.operation_fd, control))},
            control,
        )
    else:
        intent = active.records[-1].body_value()
        _fail(ledger._parse_parent(intent["state_parent"]) == pre)
        _fail(ledger._parse_generation(intent["operation"]) == fs._observe_node(operation.identity_fd, operation.operation_fd, control))
    expected = fs._observe_node(operation.identity_fd, operation.operation_fd, control)
    _close(operation)
    _remove_name(locked.state, operation_name, expected, control)
    post = _parent(locked.state, control)
    active = _append(active, "operation-absent", {"token": token, "operation_name": operation_name.text, "state_parent": _p(post)}, control)
    active = _append(active, "retired", {"token": token, "state_parent": _p(post)}, control)
    return _unlink_ledger(active, locked, control)


def _unlink_ledger(active, locked, control):
    expected = fs._observe_node(active.node.identity_fd, active.node.operation_fd, control)
    _close(active.node)
    _remove_name(locked.state, LEDGER_NAME, expected, control)
    return None


def _finish_hardlink_remove(active, operation, alias_path, target_path, target_generation, control):
    alias_parent, alias_opened, alias_name = _open_relative_parent(operation, alias_path, control)
    target_parent, target_opened, target_name = _open_relative_parent(operation, target_path, control)
    target = fs._open_path_node(target_parent, target_name, "file", control)
    try:
        alias = fs._observe_child(alias_parent, alias_name, control)
        _fail(alias.key == target_generation.key and alias == target_generation)
        pre = _parent(alias_parent, control)
        body = {
            "token": _token(active),
            "path": alias_path,
            "kind": "hardlink",
            "parent": _p(pre),
            "child": _g(alias),
            "target_path": target_path,
        }
        active = _append(active, "remove-intent", body, control)
        _check(control)
        os.unlink(alias_name.raw, dir_fd=alias_parent.operation_fd.number)
        _check(control)
        builder_target = fs._observe_node(target.identity_fd, target.operation_fd, control)
        ledger._hardlink_generation_change(target_generation, builder_target, -1)
        _fsync(target.operation_fd, control)
        _fsync(alias_parent.operation_fd, control)
        post = _parent(alias_parent, control)
        observed = {
            "token": _token(active),
            "path": alias_path,
            "kind": "hardlink",
            "parent": _p(post),
            "target_path": target_path,
            "target": _g(builder_target),
        }
        active = _append(active, "remove-observed", observed, control)
        active = _append(active, "remove-settled", observed, control)
        return active, builder_target, post.generation
    finally:
        fs._close_node(target)
        for node in reversed(alias_opened + target_opened):
            fs._close_node(node)


def _cleanup_active(active, locked, operation, state, control):
    owned = dict(state.owned)
    groups = []
    for record in active.records:
        if record.record_type == "hardlink-group":
            body = record.body_value()
            groups.append((body["target_path"], tuple(body["aliases"])))
    for target_path, aliases in reversed(groups):
        target_generation = owned[target_path]
        for alias_path in reversed(aliases):
            active, target_generation, parent_generation = _finish_hardlink_remove(
                active, operation, alias_path, target_path, target_generation, control
            )
            owned.pop(alias_path)
            parent_path = alias_path.rpartition("/")[0]
            if parent_path in owned:
                owned[parent_path] = parent_generation
        owned[target_path] = target_generation
    for path in sorted(tuple(owned), key=lambda value: (value.count("/"), value.encode("utf-8")), reverse=True):
        active, parent_generation = _finish_remove(active, operation, path, owned[path], False, control)
        parent_path = path.rpartition("/")[0]
        if parent_path in owned:
            owned[parent_path] = parent_generation
    return _retire(active, locked, operation, control)


def _resume_entry_remove(active, locked, operation, reconciled, control):
    intent = active.records[-1].body_value()
    if reconciled.status == "remove-retry":
        expected = ledger._parse_generation(intent["child"])
        active, _parent_generation = _finish_remove(active, operation, intent["path"], expected, True, control)
    else:
        active = _finish_absent_remove(active, operation, control)
    entries, parents = _walk_entries(operation, control)
    observations = ledger.ReconcileObservations(
        _parent(locked.state, control),
        ((_operation_name(_token(active)).text, fs._observe_node(operation.identity_fd, operation.operation_fd, control)),),
        entries,
        parents,
    )
    state = ledger._reconcile_ledger(active.records, observations)
    _fail(state.status == "active")
    return _cleanup_active(active, locked, operation, state, control)


def _finish_operation_absent(active, locked, control):
    token = _token(active)
    post = _parent(locked.state, control)
    body = {"token": token, "operation_name": _operation_name(token).text, "state_parent": _p(post)}
    active = _append(active, "operation-absent", body, control)
    active = _append(active, "retired", {"token": token, "state_parent": _p(post)}, control)
    return _unlink_ledger(active, locked, control)


def _cleanup_owned(owned, active, control):
    _fail(type(owned) is OwnedOperation and type(active) is ActiveLedger)
    _close(owned.root)
    entries, parents = _walk_entries(owned.operation, control)
    observations = ledger.ReconcileObservations(
        _parent(owned.locked.state, control),
        ((owned.operation_name, fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)),),
        entries,
        parents,
    )
    reconciled = ledger._reconcile_ledger(active.records, observations)
    _fail(reconciled.status == "active")
    _cleanup_active(active, owned.locked, owned.operation, reconciled, control)
    _release_lock(owned.locked)
    _close(owned.locked.state)


def _abort(active, locked, record_type, control):
    token = _token(active)
    body = {"token": token, "state_parent": _p(_parent(locked.state, control))}
    if record_type == "operation-abort":
        body = {"token": token, "operation_name": _operation_name(token).text, "state_parent": body["state_parent"]}
    active = _append(active, record_type, body, control)
    active = _append(active, "retired", {"token": token, "state_parent": _p(_parent(locked.state, control))}, control)
    return _unlink_ledger(active, locked, control)


def _recover_locked(chain, state, control):
    locked = _acquire_lock(chain, state, control)
    active = None
    operation = None
    try:
        names = fs._enumerate_stable(state, control).raw_names
        fixed_idle = tuple(sorted((STATE_SENTINEL_NAME.raw, LOCK_NAME.raw)))
        if names == fixed_idle:
            _release_lock(locked)
            return
        _fail(LEDGER_NAME.raw in names)
        active = _read_active_ledger(state, control)
        genesis = active.records[0].body_value()
        approval = fs.SourceApproval(genesis["source_revision"], genesis["source_manifest_sha256"])
        fs._verify_source_bundle(_source(chain), approval, control)
        observations, operation = _observations(locked, active.records, control)
        reconciled = ledger._reconcile_ledger(active.records, observations)
        if reconciled.status == "genesis-abortable":
            _abort(active, locked, "genesis-abort", control)
        elif reconciled.status == "operation-abortable":
            _abort(active, locked, "operation-abort", control)
        elif reconciled.status == "active":
            _fail(operation is not None)
            _cleanup_active(active, locked, operation, reconciled, control)
            operation = None
        elif reconciled.status in {"remove-retry", "remove-absence-settleable"}:
            _fail(operation is not None)
            _resume_entry_remove(active, locked, operation, reconciled, control)
            operation = None
        elif reconciled.status == "operation-remove-retry":
            _fail(operation is not None)
            _retire(active, locked, operation, control, intent_exists=True)
            operation = None
        elif reconciled.status == "operation-absence-settleable":
            _fail(operation is None)
            _finish_operation_absent(active, locked, control)
        elif reconciled.status == "retirable":
            active = _append(active, "retired", {"token": _token(active), "state_parent": _p(_parent(state, control))}, control)
            _unlink_ledger(active, locked, control)
        elif reconciled.status == "retired":
            _unlink_ledger(active, locked, control)
        else:
            raise BuilderError()
        active = None
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


def _recover_fixed(control):
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

"""Private durable retained rootfs lease and verification for ADR 0040."""

from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import os
import secrets
import sys

sys.dont_write_bytecode = True

import completion_kata_operation as kata_operation
import completion_rootfs_build as build
import completion_rootfs_builder as builder
import completion_rootfs_canonical as canonical
import completion_rootfs_fs as fs
import completion_rootfs_ledger as ledger
import completion_rootfs_materializer as materializer
import completion_rootfs_plan as plan
import completion_rootfs_publish as publication

FIXED_PREFIX = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/rootfs-v1/"


class LeaseError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise LeaseError()


@dataclass(frozen=True)
class RuntimeRootfsReference:
    path: str
    token: str
    operation_name: str
    ledger_key: fs.HostKey
    leased_settled: ledger.SettledBytes
    state_generation: fs.HostGeneration
    operation_generation: fs.HostGeneration
    root_generation: fs.HostGeneration
    manifest_sha256: str
    manifest_size: int
    ustar_sha256: str
    ustar_size: int
    entry_count: int

    def __post_init__(self):
        ledger._token(self.token)
        _fail(type(self.path) is str and type(self.operation_name) is str)
        _fail(self.operation_name == ledger._operation_name(self.token))
        _fail(self.path == FIXED_PREFIX + self.operation_name + "/rootfs")
        _fail(type(self.ledger_key) is fs.HostKey and self.ledger_key.kind == "file")
        _fail(type(self.leased_settled) is ledger.SettledBytes)
        ledger._settled_record(self.leased_settled.sequence, self.leased_settled.offset, self.leased_settled.line_sha256)
        for value in (self.state_generation, self.operation_generation, self.root_generation):
            _fail(type(value) is fs.HostGeneration and value.key.kind == "directory")
        ledger._digest(self.manifest_sha256)
        ledger._digest(self.ustar_sha256)
        _fail(type(self.manifest_size) is int and self.manifest_size > 0)
        _fail(type(self.ustar_size) is int and self.ustar_size > 0 and self.ustar_size % 512 == 0)
        _fail(type(self.entry_count) is int and self.entry_count > 0)


@dataclass
class RetainedRootfsLease:
    reference: RuntimeRootfsReference
    retained: build.RetainedBuild = field(repr=False)
    disposition: str = field(default="held", init=False)


def _descriptors(node):
    _fail(type(node) is fs.HeldNode and type(node.identity_fd) is fs.CheckedFd)
    values = (node.identity_fd,) if node.operation_fd is None else (node.identity_fd, node.operation_fd)
    _fail(all(type(value) is fs.CheckedFd and value.disposition == "open" for value in values))
    return values


def _topology(retained, reference=None):
    _fail(type(retained) is build.RetainedBuild and type(retained.base_chain) is fs.HeldChain)
    _fail(type(retained.disposition) is str and retained.disposition in {"owned", "transferred", "uncertain", "retired"})
    owned = retained.owned
    _fail(type(owned) is builder.OwnedOperation and type(owned.locked) is builder.LockedState)
    _fail(type(owned.active) is builder.ActiveLedger and type(owned.active.writer) is ledger.LedgerWriterState)
    base = retained.base_chain
    locked_chain = owned.locked.chain
    _fail(type(locked_chain) is fs.HeldChain and locked_chain.anchor is base.anchor)
    _fail(len(locked_chain.components) == len(base.components) + 1)
    _fail(all(locked_chain.components[index] is component for index, component in enumerate(base.components)))
    _fail(locked_chain.components[-1].name == builder.STATE_NAME and locked_chain.components[-1].node is owned.locked.state)
    active = owned.active
    _fail(active.node is active.writer.node)
    _fail(active.node.identity_fd is active.writer.node.identity_fd and active.node.operation_fd is active.writer.node.operation_fd)
    _fail(active.writer.generation == active.node.generation and active.writer.stable_key == active.node.generation.key)
    owner_nodes = tuple(component.node for component in base.components) + (
        base.anchor, owned.locked.state, owned.locked.lock, active.node, owned.operation, owned.root,
    )
    _fail(len({id(node) for node in owner_nodes}) == len(owner_nodes))
    descriptors = tuple(value for node in owner_nodes for value in _descriptors(node))
    _fail(len({id(value) for value in descriptors}) == len(descriptors))
    token = builder._token(active)
    _fail(owned.operation_name == ledger._operation_name(token))
    if reference is not None:
        _fail(type(reference) is RuntimeRootfsReference)
        _fail((reference.token, reference.operation_name) == (token, owned.operation_name))
    return owned


def _merge(error, addition):
    return addition if error is None else fs.RootfsFsError(error, addition)


def _close_preserving(retained, primary=None):
    error = primary
    owned = retained.owned
    for node in (owned.root, owned.operation, owned.active.node, owned.locked.lock, owned.locked.state):
        if any(value is not None and value.disposition == "open" for value in (node.operation_fd, node.identity_fd)):
            try:
                fs._close_node(node)
            except BaseException as caught:
                error = _merge(error, caught)
    try:
        fs._close_chain(retained.base_chain)
    except BaseException as caught:
        error = _merge(error, caught)
    retained.disposition = "uncertain"
    if error is not None:
        raise error


def _abandon_active(retained, primary):
    error = primary
    try:
        materializer._reload_and_cleanup(retained.owned, materializer._fresh_cleanup_control())
        retained.disposition = "retired"
    except BaseException as caught:
        error = _merge(error, caught)
        owned = retained.owned
        for node in (owned.root, owned.operation, owned.active.node, owned.locked.lock, owned.locked.state):
            if any(value is not None and value.disposition == "open" for value in (node.operation_fd, node.identity_fd)):
                try:
                    fs._close_node(node)
                except BaseException as close_error:
                    error = _merge(error, close_error)
    try:
        fs._close_chain(retained.base_chain)
    except BaseException as caught:
        error = _merge(error, caught)
    raise error


def _probe_lock(state, expected, retained_descriptors, control):
    probe = None
    error = None
    try:
        probe = builder._verify_fixed_file(state, builder.LOCK_NAME, b"", control)
        _fail(probe.generation == expected and probe.operation_fd is not None)
        probe_descriptors = _descriptors(probe)
        _fail(len({id(value) for value in probe_descriptors}) == len(probe_descriptors))
        _fail(not {id(value) for value in probe_descriptors} & {id(value) for value in retained_descriptors})
        try:
            fcntl.flock(probe.operation_fd.number, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as caught:
            if caught.errno not in {errno.EAGAIN, errno.EACCES}:
                raise
        else:
            raise LeaseError()
    except BaseException as caught:
        error = caught
    if probe is not None and any(value is not None and value.disposition == "open" for value in (probe.operation_fd, probe.identity_fd)):
        try:
            fs._close_node(probe)
        except BaseException as caught:
            error = _merge(error, caught)
    if error is not None:
        raise error


def _fresh_fixed_chain(operation_name, control):
    chain = builder._open_base_chain(control)
    state = operation = root = detached = None
    try:
        state = detached = fs._open_path_node(builder._completion(chain), builder.STATE_NAME, "directory", control)
        chain = builder._append_component(chain, builder.STATE_NAME, detached)
        detached = None
        operation = detached = fs._open_path_node(state, fs._name(operation_name), "directory", control)
        chain = builder._append_component(chain, fs._name(operation_name), detached)
        detached = None
        root = detached = fs._open_path_node(operation, builder.ROOT_NAME, "directory", control)
        chain = builder._append_component(chain, builder.ROOT_NAME, detached)
        detached = None
        fs._revalidate_chain(chain, control)
        return chain, state, operation, root
    except BaseException as error:
        if detached is not None:
            try:
                fs._close_node(detached)
            except BaseException as close_error:
                error = _merge(error, close_error)
        try:
            fs._close_chain(chain)
        except BaseException as close_error:
            error = _merge(error, close_error)
        raise error


def _stable_graph(retained, reference, control, expected_status):
    owned = _topology(retained, reference)
    _fail(type(control) is fs.OperationControl and expected_status in {"active", "leased"})
    sentinel = builder._verify_fixed_file(owned.locked.state, builder.STATE_SENTINEL_NAME, builder.STATE_SENTINEL, control)
    fs._close_node(sentinel)
    held_state = fs._observe_node(owned.locked.state.identity_fd, owned.locked.state.operation_fd, control)
    builder._policy(owned.locked.state, "directory", 0o700, retained.base_chain.anchor.generation.key)
    fs._require_empty_fd_xattrs(owned.locked.state, control)
    held_operation = fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)
    builder._policy(owned.operation, "directory", 0o700, held_state.key)
    fs._require_empty_fd_xattrs(owned.operation, control)
    held_root = fs._observe_node(owned.root.identity_fd, owned.root.operation_fd, control)
    _fail(held_root.key.kind == "directory" and held_root.mode == 0o755 and held_root.uid == held_root.gid == 0 and held_root.nlink >= 2)
    _fail((held_root.key.mount_id, held_root.key.device) == (held_operation.key.mount_id, held_operation.key.device))
    fs._require_empty_fd_xattrs(owned.root, control)
    held_lock = fs._observe_node(owned.locked.lock.identity_fd, owned.locked.lock.operation_fd, control)
    _fail(fs._observe_child(owned.locked.state, builder.LOCK_NAME, control) == held_lock)
    builder._policy(owned.locked.lock, "file", 0o600, held_state.key)
    fs._require_empty_fd_xattrs(owned.locked.lock, control)
    owner_nodes = tuple(component.node for component in retained.base_chain.components) + (
        retained.base_chain.anchor, owned.locked.state, owned.locked.lock, owned.active.node, owned.operation, owned.root,
    )
    retained_descriptors = tuple(value for node in owner_nodes for value in _descriptors(node))
    _probe_lock(owned.locked.state, held_lock, retained_descriptors, control)
    temporary = None
    error = None
    try:
        temporary, state, operation, root = _fresh_fixed_chain(owned.operation_name, control)
        builder._policy(state, "directory", 0o700, temporary.anchor.generation.key)
        builder._policy(operation, "directory", 0o700, state.generation.key)
        fs._require_empty_fd_xattrs(state, control)
        fs._require_empty_fd_xattrs(operation, control)
        fs._require_empty_fd_xattrs(root, control)
        _fail(root.generation == held_root)
        temporary_nodes = (temporary.anchor,) + tuple(component.node for component in temporary.components)
        temporary_descriptors = tuple(value for node in temporary_nodes for value in _descriptors(node))
        _fail(len({id(value) for value in temporary_descriptors}) == len(temporary_descriptors))
        _fail(not {id(value) for value in temporary_descriptors} & {id(value) for value in retained_descriptors})
        if reference is not None:
            _fail((state.generation, operation.generation, root.generation) == (
                reference.state_generation, reference.operation_generation, reference.root_generation,
            ))
        active = builder._stable_active(owned.active, owned.locked.state, control)
        _fail(active.records == owned.active.records and active.writer.settled == owned.active.writer.settled)
        entries, parents = builder._walk_entries(owned.operation, control)
        observations = ledger.ReconcileObservations(
            builder._parent(owned.locked.state, control),
            ((owned.operation_name, fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)),),
            entries, builder._current_ledger(active, control), parents,
        )
        reconciled = ledger._reconcile_ledger(active.records, observations)
        _fail(reconciled.status == expected_status)
        if expected_status == "active":
            _fail(reconciled.cleanup_allowed and reconciled.cleanup_origin == "prelease")
        else:
            _fail(reconciled.lease_seen and not reconciled.release_authorized and not reconciled.cleanup_allowed)
            terminal = active.records[-1]
            body = terminal.body_value()
            _fail(terminal.record_type == "leased" and reference is not None)
            snapshot = reconciled.lease_snapshot
            _fail(type(snapshot) is ledger.LeaseSnapshot)
            _fail((snapshot.ledger_key, snapshot.settled, snapshot.state_parent.generation, snapshot.operation, snapshot.root) == (
                reference.ledger_key, reference.leased_settled, reference.state_generation,
                reference.operation_generation, reference.root_generation,
            ))
            _fail((body["manifest_sha256"], body["manifest_size"], body["ustar_sha256"], body["ustar_size"], body["entry_count"]) == (
                reference.manifest_sha256, reference.manifest_size, reference.ustar_sha256, reference.ustar_size, reference.entry_count,
            ))
        _fail(fs._observe_node(owned.locked.state.identity_fd, owned.locked.state.operation_fd, control) == held_state)
        _fail(fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control) == observations.operations[0][1])
        _fail(fs._observe_node(owned.root.identity_fd, owned.root.operation_fd, control) == dict(observations.entries)["rootfs"])
        _fail(fs._observe_child(owned.locked.state, builder.LEDGER_NAME, control) == active.writer.generation)
        _fail(fs._observe_child(owned.locked.state, builder.LOCK_NAME, control) == held_lock)
        fs._revalidate_chain(temporary, control)
        _fail((state.generation, operation.generation, root.generation) == (
            held_state, held_operation, held_root,
        ))
        if reference is not None:
            _fail((state.generation, operation.generation, root.generation) == (
                reference.state_generation, reference.operation_generation, reference.root_generation,
            ))
    except BaseException as caught:
        error = caught
    if temporary is not None:
        try:
            fs._close_chain(temporary)
        except BaseException as caught:
            error = _merge(error, caught)
    if error is not None:
        raise error
    return active, reconciled


def _stable_lease_pass(lease, control):
    _fail(type(lease) is RetainedRootfsLease and lease.disposition == "held")
    _fail(type(lease.reference) is RuntimeRootfsReference and type(lease.retained) is build.RetainedBuild)
    _fail(lease.retained.disposition == "transferred")
    _stable_graph(lease.retained, lease.reference, control, "leased")
    return lease.reference


def _reference(owned, active):
    terminal = active.records[-1]
    body = terminal.body_value()
    _fail(terminal.record_type == "leased")
    snapshot = ledger._lease_from_record(active.records, terminal)
    return RuntimeRootfsReference(
        FIXED_PREFIX + owned.operation_name + "/rootfs", body["token"], owned.operation_name,
        snapshot.ledger_key, snapshot.settled, snapshot.state_parent.generation, snapshot.operation, snapshot.root,
        body["manifest_sha256"], body["manifest_size"], body["ustar_sha256"], body["ustar_size"], body["entry_count"],
    )


def _acquire(approval, outer):
    _fail(type(approval) is fs.SourceApproval and type(outer) is fs.OperationControl)
    pins = publication._load_pins()
    _fail(type(pins) is publication.RootfsPins)
    first_token = secrets.token_hex(32)
    first = build._build_once(approval, first_token, outer)
    second_token = secrets.token_hex(32)
    _fail(second_token != first_token)
    second, retained = build._build_once_retained(approval, second_token, outer)
    boundary = False
    try:
        build._require_equal_builds(first, second)
        build._require_pinned(first, pins)
        build._require_pinned(second, pins)
        _topology(retained)
        _stable_graph(retained, None, outer, "active")
        boundary = True
        retained.disposition = "uncertain"
        refreshed = builder._mark_leased(
            retained.owned, pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256,
            pins.ustar_size, pins.entry_count, outer,
        )
        retained.owned = refreshed
        _topology(retained)
        reference = _reference(refreshed, refreshed.active)
        retained.disposition = "transferred"
        lease = RetainedRootfsLease(reference, retained)
        _stable_lease_pass(lease, outer)
        first = second = None
        return lease
    except BaseException as error:
        if boundary:
            _close_preserving(retained, error)
        _abandon_active(retained, error)


def _reopen_kata_reserved(permit, control):
    grant = kata_operation._claim_rootfs_reopen(permit)
    held = None

    def rootfs_route(token, route_control):
        ledger._token(token)
        chain = builder._open_base_chain(route_control)
        state = locked = active = operation = root = None
        try:
            state = builder._open_state(chain, route_control)
            _fail(state is not None)
            locked = builder._acquire_lock(chain, state, route_control)
            active = builder._read_active_ledger(state, route_control)
            observations, operation = builder._observations(
                locked, active.records, builder._current_ledger(active, route_control), route_control,
            )
            reconciled = ledger._reconcile_ledger(active.records, observations)
            _fail(reconciled.status == "leased" and reconciled.lease_seen and not reconciled.release_authorized)
            _fail(builder._token(active) == token and operation is not None)
            root = fs._open_path_node(operation, builder.ROOT_NAME, "directory", route_control)
            _fail(type(reconciled.lease_snapshot) is ledger.LeaseSnapshot and root.generation == reconciled.lease_snapshot.root)
            owned = builder.OwnedOperation(locked, active, operation, root, ledger._operation_name(token))
            retained = build.RetainedBuild(owned, chain)
            retained.disposition = "transferred"
            routed = RetainedRootfsLease(_reference(owned, active), retained)
            _stable_lease_pass(routed, route_control)
            return routed
        except BaseException as error:
            for node in (root, operation, None if active is None else active.node, None if locked is None else locked.lock, state):
                if node is not None and node.identity_fd.disposition == "open":
                    try: fs._close_node(node)
                    except BaseException as close_error: error = _merge(error, close_error)
            try: fs._close_chain(chain)
            except BaseException as close_error: error = _merge(error, close_error)
            raise error

    try:
        held = kata_operation._invoke_rootfs_reopen_route(grant, rootfs_route, control)
        _verify(held, control)
        kata_operation._settle_rootfs_reopen(grant, held.reference)
        return held
    except BaseException as error:
        if held is not None and held.disposition == "held":
            _close_preserving(held.retained, error)
        raise


def _verify(lease, control):
    _stable_lease_pass(lease, control)
    authority = plan.load_verified_build_inputs()
    count = materializer._postwalk(lease.retained.owned, lease.retained.owned.root, authority, control)
    _fail(count == lease.reference.entry_count)
    fresh = plan.revalidate_build_inputs(authority)
    _fail(type(fresh) is plan.RootfsBuildInputs and fresh is not authority)
    manifest = canonical._manifest(fresh.plan)
    reference = lease.reference
    _fail(len(manifest) == reference.manifest_size and hashlib.sha256(manifest).hexdigest() == reference.manifest_sha256)
    _fail(len(fresh.plan.entries) == reference.entry_count)
    pins = publication._load_pins()
    _fail(type(pins) is publication.RootfsPins)
    _fail((pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256, pins.ustar_size, pins.entry_count) == (
        reference.manifest_sha256, reference.manifest_size, reference.ustar_sha256, reference.ustar_size, reference.entry_count,
    ))
    _stable_lease_pass(lease, control)
    _fail(type(lease.reference) is RuntimeRootfsReference)
    return lease.reference

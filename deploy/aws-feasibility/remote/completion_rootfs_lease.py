"""Private durable retained rootfs lease and verification for ADR 0040."""
from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import json
import os
import secrets
import sys
sys.dont_write_bytecode = True
import completion_kata_operation as kata_operation
import completion_rootfs_builder as builder
import completion_rootfs_fs as fs
import completion_rootfs_ledger as ledger
import completion_rootfs_materializer as materializer
import completion_rootfs_prebuilt as prebuilt
FIXED_PREFIX = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/rootfs-v1/"
class LeaseError(Exception):
    pass
ROOTFS_BUILD_OUTCOMES = {
    "cancelled": "cancel", "deadline": "deadline", "failed": "work",
    "not-started": "setup", "success": "post",
}
ROOTFS_BUILD_DETAILS = (materializer.MATERIALIZE_STAGES - {"internal"}) | set(
    ROOTFS_BUILD_OUTCOMES.values())
ROOTFS_ACQUIRE_STAGES = frozenset({
    "bootstrap", "pins", "build-first", "build-second", "equality", "pin-check", "topology",
    "lease-mark", "lease-verify", "prebuilt-open", "prebuilt-materialize",
    "prebuilt-manifest", "prebuilt-candidate", "prebuilt-pin-check", *(
        f"{build_stage}-{detail}"
        for build_stage in ("build-first", "build-second")
        for detail in ROOTFS_BUILD_DETAILS
    ),
})
class RootfsAcquireError(LeaseError):
    def __init__(self, stage):
        if stage not in ROOTFS_ACQUIRE_STAGES:
            raise LeaseError()
        super().__init__("fixed rootfs acquisition failed")
        self.stage = stage
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
    prebuilt_descriptor_raw: bytes | None = field(default=None, repr=False)
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
        if self.prebuilt_descriptor_raw is not None:
            descriptor = prebuilt.decode_fixed_descriptor(self.prebuilt_descriptor_raw)
            _fail((descriptor.rootfs_manifest_sha256, descriptor.rootfs_manifest_size,
                   descriptor.ustar_sha256, descriptor.ustar_size, descriptor.entry_count) ==
                  (self.manifest_sha256, self.manifest_size, self.ustar_sha256,
                   self.ustar_size, self.entry_count))

@dataclass
class RetainedRootfsLease:
    reference: RuntimeRootfsReference
    retained: builder.RetainedOperation = field(repr=False)
    disposition: str = field(default="held", init=False)

def _descriptors(node):
    _fail(type(node) is fs.HeldNode and type(node.identity_fd) is fs.CheckedFd)
    values = (node.identity_fd,) if node.operation_fd is None else (node.identity_fd, node.operation_fd)
    _fail(all(type(value) is fs.CheckedFd and value.disposition == "open" for value in values))
    return values

def _topology(retained, reference=None):
    _fail(type(retained) is builder.RetainedOperation and type(retained.base_chain) is fs.HeldChain)
    _fail(type(retained.disposition) is str and retained.disposition in {"owned", "transferred", "uncertain", "retired"})
    owned = retained.owned
    _fail(type(owned) is builder.OwnedOperation and type(owned.locked) is builder.LockedState)
    _fail(type(owned.active) is builder.ActiveLedger and type(owned.active.writer) is ledger.LedgerWriterState)
    base = retained.base_chain
    locked_chain = owned.locked.chain
    _fail(type(locked_chain) is fs.HeldChain and locked_chain.anchor is base.anchor)
    _fail(len(locked_chain.components) == len(base.components) + 1)
    _fail(all(locked_chain.components[index].name == component.name
              and locked_chain.components[index].node is component.node
              for index, component in enumerate(base.components)))
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

def _bootstrap_state(approval, control):
    chain = builder._open_base_chain(control)
    try:
        state = builder._bootstrap(chain, approval, control)
        try:
            fs._close_node(state)
        except BaseException as error:
            fs._close_chain(chain, error)
        fs._close_chain(chain)
    except BaseException as error:
        if chain.anchor.identity_fd.disposition == "open":
            fs._close_chain(chain, error)
        raise

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
    _fail(type(control) is fs.OperationControl and expected_status in {"active", "leased", "release-authorized", "prestage-release-authorized"})
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
        records = builder._records(active)
        _fail(records == builder._records(owned.active) and active.writer.settled == owned.active.writer.settled)
        entries, parents = builder._walk_entries(owned.operation, control)
        observations = ledger.ReconcileObservations(
            builder._parent(owned.locked.state, control),
            ((owned.operation_name, fs._observe_node(owned.operation.identity_fd, owned.operation.operation_fd, control)),),
            entries, builder._current_ledger(active, control), parents,
        )
        reconciled = ledger._reconcile_ledger(records, observations)
        _fail(reconciled.status == expected_status)
        if expected_status == "active":
            _fail(reconciled.cleanup_allowed and reconciled.cleanup_origin == "prelease")
        else:
            _fail(reconciled.lease_seen and reference is not None)
            _fail(reconciled.release_authorized == (expected_status == "release-authorized"))
            _fail(reconciled.cleanup_allowed == (expected_status in {"release-authorized", "prestage-release-authorized"}))
            if expected_status == "prestage-release-authorized":
                _fail(reconciled.cleanup_origin == "prestage-authorized")
            terminal = next(item for item in records if item.record_type == "leased")
            body = terminal.body_value()
            _fail(terminal.record_type == "leased")
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
    _fail(type(lease.reference) is RuntimeRootfsReference and type(lease.retained) is builder.RetainedOperation)
    _fail(lease.retained.disposition == "transferred")
    _stable_graph(lease.retained, lease.reference, control, "leased")
    return lease.reference

def _reference(owned, active):
    records = builder._records(active)
    _fail(records[-1].record_type in {"leased", "release-authorized", "prestage-release-authorized"})
    terminal = next(item for item in records if item.record_type == "leased")
    body = terminal.body_value()
    snapshot = ledger._lease_from_record(records, terminal)
    return RuntimeRootfsReference(
        FIXED_PREFIX + owned.operation_name + "/rootfs", body["token"], owned.operation_name,
        snapshot.ledger_key, snapshot.settled, snapshot.state_parent.generation, snapshot.operation, snapshot.root,
        body["manifest_sha256"], body["manifest_size"], body["ustar_sha256"], body["ustar_size"], body["entry_count"],
        (None if "prebuilt_descriptor" not in body else
         prebuilt._canonical(body["prebuilt_descriptor"])),
    )

def _acquire(approval, outer):
    # Historical producer-only route. Production imports no build/input modules.
    import completion_rootfs_build as build
    import completion_rootfs_publish as publication
    _fail(type(approval) is fs.SourceApproval and type(outer) is fs.OperationControl)
    retained = None
    boundary = False
    stage = "bootstrap"
    try:
        _bootstrap_state(approval, outer)
        stage = "pins"
        pins = publication._load_pins()
        _fail(type(pins) is publication.RootfsPins)
        stage = "build-first"
        first_token = secrets.token_hex(32)
        first = build._build_once(approval, first_token, outer)
        stage = "build-second"
        second_token = secrets.token_hex(32)
        _fail(second_token != first_token)
        second, retained = build._build_once_retained(approval, second_token, outer)
        stage = "equality"
        build._require_equal_builds(first, second)
        stage = "pin-check"
        build._require_pinned(first, pins)
        build._require_pinned(second, pins)
        stage = "topology"
        _topology(retained)
        _stable_graph(retained, None, outer, "active")
        boundary = True
        retained.disposition = "uncertain"
        stage = "lease-mark"
        refreshed = builder._mark_leased(
            retained.owned, pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256,
            pins.ustar_size, pins.entry_count, outer,
        )
        retained.owned = refreshed
        _topology(retained)
        reference = _reference(refreshed, refreshed.active)
        retained.disposition = "transferred"
        lease = RetainedRootfsLease(reference, retained)
        stage = "lease-verify"
        _stable_lease_pass(lease, outer)
        first = second = None
        return lease
    except BaseException as error:
        if stage in {"build-first", "build-second"} and type(error) is build.BuildAttemptError:
            detail = (error.work_stage if error.work_stage != "internal"
                      else ROOTFS_BUILD_OUTCOMES[error.work_outcome])
            stage = f"{stage}-{detail}"
        if retained is None:
            raise RootfsAcquireError(stage) from error
        try:
            if boundary:
                _close_preserving(retained, error)
            _abandon_active(retained, error)
        except BaseException as settled:
            raise RootfsAcquireError(stage) from settled
        raise RootfsAcquireError(stage) from error

def _acquire_prebuilt(approval, authority, outer):
    """Import one authenticated prebuilt ustar; never enter the build route."""
    _fail(type(approval) is fs.SourceApproval and type(authority) is prebuilt.PrebuiltRootfsAuthority)
    _fail(type(outer) is fs.OperationControl)
    retained = None
    owned = None
    chain = None
    boundary = False
    stage = "bootstrap"
    try:
        _bootstrap_state(approval, outer)
        stage = "prebuilt-open"
        fresh = prebuilt.revalidate_authority(authority)
        descriptor = fresh.descriptor
        chain = builder._open_base_chain(outer)
        owned = builder._begin_operation(chain, approval, secrets.token_hex(32), outer)
        stage = "prebuilt-import-intent"
        import_intent = {
            "token": builder._token(owned.active),
            "descriptor_sha256": hashlib.sha256(authority.descriptor_raw).hexdigest(),
            "manifest_sha256": descriptor.rootfs_manifest_sha256,
            "manifest_size": descriptor.rootfs_manifest_size,
            "ustar_sha256": descriptor.ustar_sha256,
            "ustar_size": descriptor.ustar_size,
            "entry_count": descriptor.entry_count,
        }
        active = builder._append(
            owned.active, "prebuilt-import-intent", import_intent, outer)
        owned = builder.OwnedOperation(
            owned.locked, active, owned.operation, owned.root, owned.operation_name)
        stage = "prebuilt-materialize"
        try:
            result = materializer._materialize_prebuilt(authority, owned, outer)
        except materializer.MaterializerWorkError:
            owned = None
            raise
        owned = result.owned
        stage = "prebuilt-manifest"
        active, manifest_node = builder._create_ledger_entry(
            result.active, builder._operation_chain(owned, outer),
            builder.MANIFEST_NAME.text, builder.MANIFEST_NAME, "file", fresh.manifest, outer,
        )
        fs._close_node(manifest_node)
        stage = "prebuilt-archive-custody"
        active, candidate_node = builder._create_ledger_entry(
            active, builder._operation_chain(owned, outer),
            builder.CANDIDATE_TAR_NAME.text, builder.CANDIDATE_TAR_NAME,
            "file", authority.ustar, outer,
        )
        fs._close_node(candidate_node)
        refreshed = builder.OwnedOperation(
            owned.locked, active, owned.operation, owned.root, owned.operation_name)
        retained = builder.RetainedOperation(refreshed, chain)
        owned = None; chain = None
        stage = "prebuilt-pin-check"
        _topology(retained)
        _stable_graph(retained, None, outer, "active")
        boundary = True
        retained.disposition = "uncertain"
        stage = "lease-mark"
        refreshed = builder._mark_leased(
            retained.owned, descriptor.rootfs_manifest_sha256, descriptor.rootfs_manifest_size,
            descriptor.ustar_sha256, descriptor.ustar_size, descriptor.entry_count, outer,
            json.loads(authority.descriptor_raw))
        retained.owned = refreshed
        reference = _reference(refreshed, refreshed.active)
        retained.disposition = "transferred"
        lease = RetainedRootfsLease(reference, retained)
        stage = "lease-verify"
        _verify(lease, outer)
        return lease
    except BaseException as error:
        if owned is not None:
            try:
                materializer._reload_and_cleanup(owned, materializer._fresh_cleanup_control())
                owned = None
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        if chain is not None:
            try: fs._close_chain(chain)
            except BaseException as close_error: error = fs.RootfsFsError(error, close_error)
        if retained is None:
            raise RootfsAcquireError(stage) from error
        try:
            if boundary: _close_preserving(retained, error)
            _abandon_active(retained, error)
        except BaseException as settled:
            raise RootfsAcquireError(stage) from settled
        raise RootfsAcquireError(stage) from error


def _abandon(lease, control):
    """Drop live custody of a verified lease without deleting durable state."""
    _fail(type(lease) is RetainedRootfsLease and lease.disposition == "held")
    _fail(type(control) is fs.OperationControl)
    try:
        _verify(lease, control)
    except BaseException as error:
        lease.disposition = "uncertain"
        _close_preserving(lease.retained, error)
    try:
        _close_preserving(lease.retained)
        lease.disposition = "abandoned"
    except BaseException:
        lease.disposition = "uncertain"
        raise

def _admit_operation_parent_transition(held, control):
    """Refresh only the exact completion-parent change made by operation open."""
    retained, index = held.retained, builder.COMPLETION_INDEX
    owned, base = retained.owned, retained.base_chain
    locked = owned.locked
    _fail(locked.chain.anchor is base.anchor
          and locked.chain.components[index].node is base.components[index].node)
    before = base.components[index].node.generation
    snapshot = fs._enumerate_stable(base.components[index].node, control)
    expected = tuple(sorted(name.raw for name in (
        kata_operation.ARTIFACTS_NAME, kata_operation.ROOTFS_NAME,
        kata_operation.IMMUTABLE_PREPARATION_NAME, kata_operation.RUNTIME_NAME,
        kata_operation.STATE_NAME,
    )))
    after = snapshot.generation
    _fail(snapshot.raw_names == expected and after.key == before.key
          and (after.mode, after.uid, after.gid) == (before.mode, before.uid, before.gid)
          and after.nlink == before.nlink + 1
          and after.mtime_ns >= before.mtime_ns and after.ctime_ns >= before.ctime_ns)
    locked_chain = builder._chain_after_parent(locked.chain, before, after)
    base = fs.HeldChain(base.anchor, locked_chain.components[:len(base.components)])
    state = locked_chain.components[-1].node
    _fail(state is locked.state)
    refreshed_locked = builder.LockedState(locked_chain, state, locked.lock)
    retained.base_chain = base
    retained.owned = builder.OwnedOperation(
        refreshed_locked, owned.active, owned.operation, owned.root, owned.operation_name)
    fs._revalidate_chain(base, control)
    fs._revalidate_chain(locked_chain, control)

def _begin_kata_operation(authority, held, approval, control):
    """Derive genesis/lease facts here, then seal them in the operation owner."""
    _fail(type(held) is RetainedRootfsLease and held.disposition == "held"
          and type(approval) is fs.SourceApproval and type(control) is fs.OperationControl)
    _admit_operation_parent_transition(held, control)
    reference = _verify(held, control)
    baseline_value = {
        "entry_count": reference.entry_count,
        "manifest_sha256": reference.manifest_sha256,
        "manifest_size": reference.manifest_size,
        "operation_name": reference.operation_name,
        "rootfs_token": reference.token,
        "ustar_sha256": reference.ustar_sha256,
        "ustar_size": reference.ustar_size,
    }
    if reference.prebuilt_descriptor_raw is not None:
        descriptor = prebuilt.decode_fixed_descriptor(reference.prebuilt_descriptor_raw)
        baseline_value["prebuilt_descriptor_sha256"] = hashlib.sha256(
            reference.prebuilt_descriptor_raw).hexdigest()
        baseline_value["prebuilt_manifest_digest"] = descriptor.manifest_digest
        baseline_value["prebuilt_package_manifest_sha256"] = descriptor.package_manifest_sha256
        baseline_value["prebuilt_provenance_sha256"] = descriptor.provenance_sha256
        baseline_value["prebuilt_publication_receipt_sha256"] = descriptor.publication_receipt_sha256
    baseline = hashlib.sha256(kata_operation._canonical(baseline_value)).hexdigest()
    kata_operation._begin_production_operation(
        authority, approval, reference.token, baseline)
    _attach_kata_operation(authority.reserve_rootfs(), held, control)
    kata_operation._admit_production_v2(authority)
    return authority

def _attach_kata_operation(permit, held, control):
    """Settle one fresh Kata intent against the already-held exact lease."""
    _fail(type(held) is RetainedRootfsLease and held.disposition == "held"
          and type(control) is fs.OperationControl)
    grant = kata_operation._claim_rootfs_reopen(permit)

    def rootfs_route(token, route_control):
        _fail(type(token) is str and token == held.reference.token
              and route_control is control)
        _verify(held, control)
        return held

    routed = kata_operation._invoke_rootfs_reopen_route(grant, rootfs_route, control)
    _fail(routed is held)
    kata_operation._settle_rootfs_reopen(grant, held.reference)
    _verify(held, control)
    return held

def _reopen_kata_reserved(permit, control):
    grant = kata_operation._claim_rootfs_reopen(permit)
    held = None

    def rootfs_route(argument, route_control):
        context = argument if type(argument) is kata_operation.RootfsReleaseContext else None
        token = context.rootfs_token if context is not None else argument
        ledger._token(token)
        chain = builder._open_base_chain(route_control)
        state = locked = active = operation = root = None
        try:
            state = builder._open_state(chain, route_control)
            _fail(state is not None)
            locked = builder._acquire_lock(chain, state, route_control)
            active = builder._read_active_ledger(state, route_control)
            records = builder._records(active)
            observations, operation = builder._observations(
                locked, records, builder._current_ledger(active, route_control), route_control,
            )
            reconciled = ledger._reconcile_ledger(records, observations)
            _fail(reconciled.status in {"leased", "release-authorized"} and reconciled.lease_seen)
            _fail(builder._token(active) == token and operation is not None)
            leased = next(item for item in records if item.record_type == "leased")
            if context is None:
                _fail(not reconciled.release_authorized)
            else:
                leased_body = leased.body_value()
                _fail((context.rootfs_ledger_key, context.leased_sequence,
                       context.leased_offset, context.leased_sha256) ==
                      (leased_body["ledger_key"], leased.sequence,
                       leased.next_offset, leased.line_sha256))
                if reconciled.release_authorized:
                    authorized_record = records[-1]
                    authorized = authorized_record.body_value()
                    _fail((authorized["kata_operation_token"], authorized["kata_ledger_key"],
                           authorized["kata_release_sequence"], authorized["kata_release_offset"],
                           authorized["kata_release_sha256"]) ==
                          (context.operation_token, context.kata_ledger_key,
                           context.kata_release_sequence, context.kata_release_offset,
                           context.kata_release_sha256))
                    if context.operation_phase == "ROOTFS_RELEASE_AUTHORIZED":
                        _fail((authorized_record.sequence, authorized_record.next_offset,
                               authorized_record.line_sha256) ==
                              (context.authorized_sequence, context.authorized_offset,
                               context.authorized_sha256))
                if context.operation_phase == "ROOTFS_RELEASE_AUTHORIZED":
                    _fail(reconciled.release_authorized)
            root = fs._open_path_node(operation, builder.ROOT_NAME, "directory", route_control)
            _fail(type(reconciled.lease_snapshot) is ledger.LeaseSnapshot and root.generation == reconciled.lease_snapshot.root)
            owned = builder.OwnedOperation(locked, active, operation, root, ledger._operation_name(token))
            retained = builder.RetainedOperation(owned, chain)
            retained.disposition = "transferred"
            routed = RetainedRootfsLease(_reference(owned, active), retained)
            if reconciled.release_authorized:
                _stable_graph(retained, routed.reference, route_control, "release-authorized")
            else:
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

def _classify_release_crash_for_tests(operation_raw, rootfs_raw):
    """Pure two-ledger crash matrix; malformed or mismatched suffixes preserve."""
    try:
        operations = kata_operation._parse(operation_raw)
        roots = ledger._parse_ledger(rootfs_raw)
        operation_terminal = operations[-1]
        _fail(operation_terminal.record_type in {"ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED"})
        ready = (operation_terminal if operation_terminal.record_type == "ROOTFS_RELEASE_READY" else
                 operations[-2])
        _fail(ready.record_type == "ROOTFS_RELEASE_READY")
        context = ready.body
        leased = next(item for item in roots if item.record_type == "leased")
        lease_body = leased.body_value()
        _fail((context["rootfs_token"], context["rootfs_ledger_key"], context["leased_sequence"],
               int(context["leased_offset"], 16), context["leased_sha256"]) ==
              (lease_body["token"], lease_body["ledger_key"], leased.sequence,
               leased.next_offset, leased.line_sha256))
        authorized = tuple(item for item in roots if item.record_type == "release-authorized")
        if not authorized:
            _fail(operation_terminal.record_type == "ROOTFS_RELEASE_READY" and roots[-1] is leased)
            return "append-rootfs-authorization"
        _fail(len(authorized) == 1 and roots[-1] is authorized[0])
        body = authorized[0].body_value()
        _fail((body["kata_operation_token"], body["kata_ledger_key"],
               body["kata_release_sequence"], body["kata_release_offset"], body["kata_release_sha256"]) ==
              (operations[0].body["operation_token"], operations[0].body["journal_key"],
               ready.sequence, ready.next_offset, ready.line_sha256))
        if operation_terminal.record_type == "ROOTFS_RELEASE_READY":
            return "settle-operation-authorization"
        _fail((operation_terminal.body["rootfs_authorized_sequence"],
               int(operation_terminal.body["rootfs_authorized_offset"], 16),
               operation_terminal.body["rootfs_authorized_sha256"],
               operation_terminal.body["release_ready_sha256"]) ==
              (authorized[0].sequence, authorized[0].next_offset,
               authorized[0].line_sha256, ready.line_sha256))
        return "authorized"
    except BaseException as error:
        if type(error) is LeaseError:
            raise
        raise LeaseError() from error

def _authorize_kata_release(permit, held, control):
    """Closure-routed Stage B append after the exact Kata release-ready suffix."""
    _fail(type(held) is RetainedRootfsLease and held.disposition == "held")
    _fail(type(control) is fs.OperationControl)
    grant = kata_operation._claim_rootfs_release(permit)

    def route(context):
        _fail(type(context) is kata_operation.RootfsReleaseContext)
        reference = held.reference
        expected_key = {"mount_id": reference.ledger_key.mount_id, "device": reference.ledger_key.device,
                        "inode": reference.ledger_key.inode, "kind": reference.ledger_key.kind}
        _fail((context.operation_token, context.rootfs_token, context.rootfs_ledger_key,
               context.leased_sequence, context.leased_offset, context.leased_sha256) ==
              (context.operation_token, reference.token, expected_key, reference.leased_settled.sequence,
               reference.leased_settled.offset, reference.leased_settled.line_sha256))
        terminal = builder._terminal_record(held.retained.owned.active)
        status = "release-authorized" if terminal.record_type == "release-authorized" else "leased"
        active, reconciled = _stable_graph(held.retained, reference, control, status)
        kata_key = fs.HostKey(context.kata_ledger_key["mount_id"], context.kata_ledger_key["device"],
                             context.kata_ledger_key["inode"], context.kata_ledger_key["kind"])
        kata_settled = ledger.SettledBytes(context.kata_release_sequence,
                                           context.kata_release_offset,
                                           context.kata_release_sha256)
        if reconciled.release_authorized:
            body = terminal.body_value()
            _fail((body["kata_operation_token"], body["kata_ledger_key"],
                   body["kata_release_sequence"], body["kata_release_offset"],
                   body["kata_release_sha256"]) ==
                  (context.operation_token, context.kata_ledger_key,
                   kata_settled.sequence, kata_settled.offset, kata_settled.line_sha256))
            return kata_operation.RootfsAuthorization(reference.token, terminal.sequence,
                                                       terminal.next_offset, terminal.line_sha256)
        _fail(builder._terminal_record(active).record_type == "leased")
        normalized_kata_key = {name: context.kata_ledger_key[name]
                               for name in ("mount_id", "device", "inode", "kind")}
        body = {
            "token": reference.token,
            "operation_name": reference.operation_name,
            "lease_sequence": reference.leased_settled.sequence,
            "lease_offset": reference.leased_settled.offset,
            "lease_sha256": reference.leased_settled.line_sha256,
            "kata_operation_token": context.operation_token,
            "kata_ledger_key": normalized_kata_key,
            "kata_release_sequence": kata_settled.sequence,
            "kata_release_offset": kata_settled.offset,
            "kata_release_sha256": kata_settled.line_sha256,
        }
        proposal = ledger.LedgerProposal.create("release-authorized", body)
        suffix = ledger._encode_proposal(proposal, active.writer.settled)
        record = ledger.LedgerRecord(
            active.writer.settled.sequence + 1, active.writer.settled.sequence,
            active.writer.settled.offset, active.writer.settled.line_sha256,
            active.writer.settled.offset + len(suffix), "release-authorized", proposal.body,
            hashlib.sha256(suffix).hexdigest(),
        )
        prospective = ledger._advance_history(active.records, record)
        written = ledger._append_release_authorized_record(
            active.writer, reference.token, reference.operation_name, reference.leased_settled,
            context.operation_token, kata_key, kata_settled, control,
        )
        _fail(prospective.legal.settled == written.settled)
        raw = os.pread(written.node.operation_fd.number, written.settled.offset, 0)
        history = ledger._parse_ledger_history(raw)
        _fail(history.legal == prospective.legal)
        node = fs.HeldNode(active.node.identity_fd, active.node.operation_fd, written.generation)
        writer = ledger.LedgerWriterState(node, written.stable_key, written.settled, written.generation)
        owned = held.retained.owned
        held.retained.owned = builder.OwnedOperation(
            owned.locked, builder.ActiveLedger(node, history, writer),
            owned.operation, owned.root, owned.operation_name,
        )
        _stable_graph(held.retained, reference, control, "release-authorized")
        return kata_operation.RootfsAuthorization(reference.token, written.settled.sequence,
                                                   written.settled.offset, written.settled.line_sha256)

    authorization = kata_operation._invoke_rootfs_release(grant, route)
    kata_operation._settle_rootfs_release(grant, authorization)
    return authorization

def _prestage_receipt_routes():
    seal = object()
    issued = set()
    class PrestageCleanupReceipt:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            value = super().__new__(cls); issued.add(value); return value
    def issue(): return PrestageCleanupReceipt(seal)
    def valid(value): return type(value) is PrestageCleanupReceipt and value in issued
    return PrestageCleanupReceipt, issue, valid


(PrestageCleanupReceipt, _issue_prestage_cleanup_receipt,
 _is_prestage_cleanup_receipt) = _prestage_receipt_routes()
del _prestage_receipt_routes


def _close_prestage_nodes(chain, state, locked, active, operation, primary=None):
    error = primary
    for node in (operation, None if active is None else active.node,
                 None if locked is None else locked.lock, state):
        if node is not None and node.identity_fd.disposition == "open":
            try: fs._close_node(node)
            except BaseException as caught: error = _merge(error, caught)
    if chain is not None and chain.anchor.identity_fd.disposition == "open":
        try: fs._close_chain(chain)
        except BaseException as caught: error = _merge(error, caught)
    if error is not None: raise error


def _prestage_rootfs_absent(control):
    chain = builder._open_base_chain(control); state = None
    try:
        state = builder._open_state(chain, control)
        if state is None: return True
        names = fs._enumerate_stable(state, control).raw_names
        return names == tuple(sorted((builder.STATE_SENTINEL_NAME.raw, builder.LOCK_NAME.raw)))
    finally:
        if state is not None and state.identity_fd.disposition == "open": fs._close_node(state)
        fs._close_chain(chain)


def _recover_unadmitted_kata_operation(prestage_permit, approval, control):
    """Authorize one fixed unadmitted lease, remove its journal, then remove only it."""
    _fail(type(approval) is fs.SourceApproval and type(control) is fs.OperationControl)
    grant = kata_operation._claim_prestage_rootfs(prestage_permit)
    current_binding = dict(kata_operation._prestage_rootfs_binding(grant))
    coordinates = kata_operation._prestage_rootfs_coordinates(grant)
    chain = state = locked = active = operation = root = held = None
    authorized_binding = None
    try:
        chain = builder._open_base_chain(control)
        state = builder._open_state(chain, control)
        if state is None:
            _fail(current_binding["kind"] == "journal-absent")
            fs._close_chain(chain); chain = None
            return None
        names = fs._enumerate_stable(state, control).raw_names
        fixed_idle = tuple(sorted((builder.STATE_SENTINEL_NAME.raw, builder.LOCK_NAME.raw)))
        if names == fixed_idle:
            _fail(current_binding["kind"] == "journal-absent")
            fs._close_node(state); state = None
            fs._close_chain(chain); chain = None
            return None
        _fail(builder.LEDGER_NAME.raw in names)
        locked = builder._acquire_lock(chain, state, control)
        active = builder._read_active_ledger(state, control)
        records = builder._records(active)
        genesis = records[0].body_value()
        _fail((genesis["source_revision"], genesis["source_manifest_sha256"]) ==
              (approval.revision, approval.manifest_sha256))
        fs._verify_source_bundle(builder._source(chain), approval, control)
        leased_rows = [record for record in records if record.record_type == "leased"]
        ordinary = [record for record in records if record.record_type == "release-authorized"]
        prestage = [record for record in records
                    if record.record_type == "prestage-release-authorized"]
        _fail(not ordinary and len(prestage) <= 1)
        if not leased_rows:
            operation_name = builder._operation_name(builder._token(active)).raw
            allowed_names = {
                tuple(sorted((*fixed_idle, builder.LEDGER_NAME.raw))),
                tuple(sorted((*fixed_idle, builder.LEDGER_NAME.raw, operation_name))),
            }
            _fail(not prestage and coordinates is None
                  and current_binding["kind"] == "journal-absent"
                  and active.records.legal.phase not in
                  {"leased", "release-authorized", "prestage-release-authorized"}
                  and names in allowed_names)
            _close_prestage_nodes(chain, state, locked, active, operation)
            chain = state = locked = active = operation = None
            builder._recover_fixed(control)
            kata_operation._settle_prestage_rootfs(grant, current_binding)
            _fail(_prestage_rootfs_absent(control))
            return _issue_prestage_cleanup_receipt()
        _fail(len(leased_rows) == 1)
        leased_record = leased_rows[0]
        leased_body = leased_record.body_value()
        observations, operation = builder._observations(
            locked, records, builder._current_ledger(active, control), control)
        reconciled = ledger._reconcile_ledger(records, observations)
        if coordinates is not None:
            _fail((coordinates["source_revision"], coordinates["source_manifest_sha256"],
                   coordinates["rootfs_token"]) ==
                  (approval.revision, approval.manifest_sha256, leased_body["token"]))
            kata_lease = coordinates["rootfs_leased"]
            if kata_lease is not None:
                snapshot = reconciled.lease_snapshot
                _fail(type(snapshot) is ledger.LeaseSnapshot)
                expected = (
                    kata_lease["rootfs_ledger_key"], kata_lease["leased_sequence"],
                    int(kata_lease["leased_offset"], 16), kata_lease["leased_sha256"],
                    kata_lease["state_generation"], kata_lease["operation_generation"],
                    kata_lease["root_generation"],
                )
                actual = (
                    kata_operation._key_value(snapshot.ledger_key), snapshot.settled.sequence,
                    snapshot.settled.offset, snapshot.settled.line_sha256,
                    kata_operation._generation_value(snapshot.state_parent.generation),
                    kata_operation._generation_value(snapshot.operation),
                    kata_operation._generation_value(snapshot.root),
                )
                _fail(expected == actual)
        if not prestage:
            _fail(reconciled.status == "leased" and not reconciled.cleanup_allowed
                  and records[-1] is leased_record and operation is not None)
            root = fs._open_path_node(operation, builder.ROOT_NAME, "directory", control)
            _fail(type(reconciled.lease_snapshot) is ledger.LeaseSnapshot
                  and root.generation == reconciled.lease_snapshot.root)
            owned = builder.OwnedOperation(locked, active, operation, root,
                                           ledger._operation_name(leased_body["token"]))
            retained = builder.RetainedOperation(owned, chain); retained.disposition = "transferred"
            held = RetainedRootfsLease(_reference(owned, active), retained)
            _verify(held, control)
            reference = held.reference
            proposal = ledger.LedgerProposal.create("prestage-release-authorized", {
                "token": reference.token, "operation_name": reference.operation_name,
                "lease_sequence": reference.leased_settled.sequence,
                "lease_offset": reference.leased_settled.offset,
                "lease_sha256": reference.leased_settled.line_sha256,
                "operation_binding": current_binding,
            })
            raw = ledger._encode_proposal(proposal, active.writer.settled)
            record = ledger.LedgerRecord(
                active.writer.settled.sequence + 1, active.writer.settled.sequence,
                active.writer.settled.offset, active.writer.settled.line_sha256,
                active.writer.settled.offset + len(raw), "prestage-release-authorized",
                proposal.body, hashlib.sha256(raw).hexdigest())
            prospective = ledger._advance_history(active.records, record)
            written = ledger._append_prestage_authorized_record(
                active.writer, reference.token, reference.operation_name,
                reference.leased_settled, current_binding, control)
            _fail(prospective.legal.settled == written.settled)
            parsed = ledger._parse_ledger_history(
                os.pread(written.node.operation_fd.number, written.settled.offset, 0))
            _fail(parsed.legal == prospective.legal)
            node = fs.HeldNode(active.node.identity_fd, active.node.operation_fd,
                               written.generation)
            writer = ledger.LedgerWriterState(node, written.stable_key,
                                               written.settled, written.generation)
            active = builder.ActiveLedger(node, parsed, writer)
            held.retained.owned = builder.OwnedOperation(
                locked, active, operation, root, owned.operation_name)
            _stable_graph(held.retained, reference, control,
                          "prestage-release-authorized")
            authorized_binding = current_binding
        else:
            _fail(reconciled.cleanup_allowed and
                  reconciled.cleanup_origin == "prestage-authorized")
            authorized_binding = prestage[0].body_value()["operation_binding"]
            _fail(kata_operation._validate_prestage_binding(grant,
                                                             authorized_binding))
        kata_operation._settle_prestage_rootfs(grant, authorized_binding)
        if held is not None:
            _close_preserving(held.retained)
            held = None; chain = state = locked = active = operation = root = None
        else:
            _close_prestage_nodes(chain, state, locked, active, operation)
            chain = state = locked = active = operation = None
        builder._recover_prestage_fixed(control)
        _fail(_prestage_rootfs_absent(control))
        return _issue_prestage_cleanup_receipt()
    except BaseException as error:
        if held is not None and held.disposition == "held":
            _close_preserving(held.retained, error)
        _close_prestage_nodes(chain, state, locked, active, operation, error)


def _recover_kata_release(authority, control):
    """Compose release-ready, authorization, exact owner removal, and operation absence."""
    _fail(type(control) is fs.OperationControl); context = authority.prepare_rootfs_release()
    proof = builder._kata_authorized_absence(context, control) if context.operation_phase == "ROOTFS_RELEASE_AUTHORIZED" else None
    if proof is not None: authority.settle_rootfs_absent(proof); return None, None
    held = None
    try:
        if context.operation_phase == "ROOTFS_RELEASE_READY":
            held = _reopen_kata_reserved(authority.reserve_rootfs(), control)
            authorization = _authorize_kata_release(authority.reserve_rootfs_release(), held, control)
            _close_preserving(held.retained); context = authority.prepare_rootfs_release()
        else: authorization = kata_operation.RootfsAuthorization(context.rootfs_token, context.authorized_sequence, context.authorized_offset, context.authorized_sha256)
        builder._recover_fixed(control); proof = builder._kata_authorized_absence(context, control)
        _fail(proof is not None); authority.settle_rootfs_absent(proof)
        if held is not None: held.disposition = "retired"; held.retained.disposition = "retired"
        return held, authorization
    except BaseException as error:
        if held is not None and held.disposition == "held" and held.retained.disposition == "transferred": _close_preserving(held.retained, error)
        raise

def _verify(lease, control):
    terminal = builder._terminal_record(lease.retained.owned.active).record_type
    _fail(terminal in {"leased", "release-authorized", "prestage-release-authorized"})
    expected_status = terminal if terminal != "leased" else "leased"
    if expected_status == "leased":
        _stable_lease_pass(lease, control)
    else:
        _stable_graph(lease.retained, lease.reference, control, expected_status)
    legacy = lease.reference.prebuilt_descriptor_raw is None
    if legacy:
        import completion_rootfs_canonical as canonical
        import completion_rootfs_plan as plan
        import completion_rootfs_publish as publication
        authority = plan.load_verified_build_inputs()
    else:
        candidate = fs._open_path_node(
            lease.retained.owned.operation, builder.CANDIDATE_TAR_NAME, "file", control)
        try:
            raw = fs._read_regular(candidate, lease.reference.ustar_size, control)
            authority = prebuilt.load_authority(lease.reference.prebuilt_descriptor_raw, raw)
        finally:
            fs._close_node(candidate)
    count = materializer._postwalk(lease.retained.owned, lease.retained.owned.root, authority, control)
    _fail(count == lease.reference.entry_count)
    if legacy:
        fresh = plan.revalidate_build_inputs(authority)
        _fail(type(fresh) is plan.RootfsBuildInputs and fresh is not authority)
        manifest = canonical._manifest(fresh.plan)
    else:
        fresh = prebuilt.revalidate_authority(authority)
        manifest = fresh.manifest
    reference = lease.reference
    _fail(len(manifest) == reference.manifest_size and hashlib.sha256(manifest).hexdigest() == reference.manifest_sha256)
    _fail(len(fresh.plan.entries) == reference.entry_count)
    if legacy:
        pins = publication._load_pins()
        _fail(type(pins) is publication.RootfsPins)
        _fail((pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256,
               pins.ustar_size, pins.entry_count) == (
            reference.manifest_sha256, reference.manifest_size,
            reference.ustar_sha256, reference.ustar_size, reference.entry_count,
        ))
    if expected_status == "leased":
        _stable_lease_pass(lease, control)
    else:
        _stable_graph(lease.retained, lease.reference, control, expected_status)
    _fail(type(lease.reference) is RuntimeRootfsReference)
    return lease.reference

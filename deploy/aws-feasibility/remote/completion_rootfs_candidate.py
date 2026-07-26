"""Fixed straight-line anonymous candidate-tar coordinator for ADR 0057."""

from dataclasses import dataclass
import hashlib
import os
import sys

sys.dont_write_bytecode = True

import completion_rootfs_builder as builder
import completion_rootfs_canonical as canonical
import completion_rootfs_fs as fs
import completion_rootfs_ledger as ledger
import completion_rootfs_plan as plan

CANDIDATE_NAME = fs._name(b".cogs-rootfs-candidate-v1.tar")
EXPECTED_ENTRIES = 4_353
EXPECTED_SIZE = ledger.CANDIDATE_TAR_SIZE
EXPECTED_SHA256 = "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3"
FAULT_BOUNDARIES = frozenset({"anonymous-open", "emission-complete", "intent", "linked", "observed"})


class CandidateError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise CandidateError()


def _fault(boundary):
    """Deterministic qualification cut; production leaves this function unchanged."""
    _fail(boundary in FAULT_BOUNDARIES)


@dataclass(frozen=True)
class CandidateTar:
    active: builder.ActiveLedger
    raw: bytes
    manifest_sha256: str
    ustar_sha256: str
    ustar_size: int
    entry_count: int


def _verified_anonymous(owned, authority, manifest, operation, control):
    metadata = canonical._canonical_metadata(owned.root, authority, operation, control)
    _fail(metadata.manifest == manifest)
    _fail(metadata.entry_count == EXPECTED_ENTRIES)
    _fail(metadata.ustar_size == EXPECTED_SIZE and metadata.ustar_sha256 == EXPECTED_SHA256)
    control.check()
    _fail(os.lseek(operation.number, 0, os.SEEK_CUR) == metadata.ustar_size)
    _fault("emission-complete")
    os.fchown(operation.number, 0, 0)
    os.fchmod(operation.number, 0o600)
    stamp = plan.SOURCE_DATE_EPOCH * 1_000_000_000
    os.utime(operation.number, ns=(stamp, stamp))
    os.fsync(operation.number)
    generation = fs._observe_anonymous(operation, control)
    _fail(generation.key.kind == "file" and generation.mode == 0o600)
    _fail(generation.uid == generation.gid == generation.nlink == 0)
    _fail(generation.size == metadata.ustar_size and generation.mtime_ns == stamp)
    _fail((generation.key.mount_id, generation.key.device) ==
          (owned.operation.generation.key.mount_id, owned.operation.generation.key.device))
    flistxattr, _unused = fs._load_xattrs()
    fs._zero_xattrs(flistxattr, operation.number, control)
    _fail(fs._observe_anonymous(operation, control) == generation)
    raw = fs._read_bounded(operation.number, metadata.ustar_size, control)
    _fail(len(raw) == metadata.ustar_size and hashlib.sha256(raw).hexdigest() == metadata.ustar_sha256)
    _fail(fs._observe_anonymous(operation, control) == generation)
    return metadata, generation, raw


def _create_candidate(active, owned, authority, manifest, control):
    _fail(type(active) is builder.ActiveLedger and type(owned) is builder.OwnedOperation)
    _fail(type(authority) is plan.RootfsBuildInputs and type(manifest) is bytes)
    _fail(type(control) is fs.OperationControl)
    operation = named = None
    try:
        operation = fs._open_anonymous(owned.operation, "candidate-anonymous", 0o600, control)
        _fault("anonymous-open")
        metadata, anonymous, raw = _verified_anonymous(
            owned, authority, manifest, operation, control,
        )
        operation_chain = builder._operation_chain(
            builder.OwnedOperation(owned.locked, active, owned.operation, owned.root, owned.operation_name),
            control,
        )
        fs._revalidate_chain(operation_chain, control)
        pre_snapshot = builder._parent_snapshot(owned.operation, control)
        pre_parent = builder._parent_value(pre_snapshot)
        _fail(CANDIDATE_NAME.raw not in pre_snapshot.raw_names)
        _fail(active.records.legal.phase == "active")
        _fail(active.records.legal.operation_parent == pre_parent)
        intent = {
            "token": builder._token(active), "path": CANDIDATE_NAME.text,
            "parent": builder._p(pre_parent), "anonymous": builder._g(anonymous),
            "size": metadata.ustar_size, "sha256": metadata.ustar_sha256,
        }
        active = builder._append_candidate(active, "candidate-tar-intent", intent, control)
        _fault("intent")
        fs._revalidate_chain(operation_chain, control)
        _fail(builder._parent_snapshot(owned.operation, control) == pre_snapshot)
        fs._link_anonymous(owned.operation, CANDIDATE_NAME, operation, control)
        _fault("linked")
        post_snapshot = builder._parent_snapshot(owned.operation, control)
        delta = fs.ParentDelta("hardlink", CANDIDATE_NAME, pre_snapshot, post_snapshot)
        ledger._candidate_parent_transition(pre_parent, builder._parent_value(post_snapshot))
        fs._revalidate_chain(operation_chain, control, delta)
        current_chain = builder._chain_after_parent(
            operation_chain, pre_snapshot.generation, post_snapshot.generation,
        )
        named = fs._open_path_node(owned.operation, CANDIDATE_NAME, "file", control)
        linked = fs._observe_node(named.identity_fd, named.operation_fd, control)
        ledger._candidate_transition(anonymous, linked)
        _fail(named.generation == linked)
        _fail((linked.key.mount_id, linked.key.device, linked.key.inode) ==
              (anonymous.key.mount_id, anonymous.key.device, anonymous.key.inode))
        reread = fs._read_regular(named, metadata.ustar_size, control)
        _fail(len(reread) == metadata.ustar_size and reread == raw)
        _fail(hashlib.sha256(reread).hexdigest() == metadata.ustar_sha256)
        os.fsync(named.operation_fd.number)
        os.fsync(owned.operation.operation_fd.number)
        fs._revalidate_chain(fs.HeldChain(
            current_chain.anchor,
            current_chain.components + (fs.ChainComponent(CANDIDATE_NAME, named),),
        ), control)
        observed = {
            "token": intent["token"], "path": intent["path"],
            "parent": builder._p(builder._parent_value(post_snapshot)),
            "anonymous": intent["anonymous"], "linked": builder._g(linked),
            "size": intent["size"], "sha256": intent["sha256"],
        }
        active = builder._append_candidate(active, "candidate-tar-observed", observed, control)
        _fault("observed")
        active = builder._append_candidate(active, "candidate-tar-settled", observed, control)
        fs._close_node(named)
        named = None
        fs._close_anonymous(operation)
        operation = None
        return CandidateTar(
            active, raw, metadata.manifest_sha256, metadata.ustar_sha256,
            metadata.ustar_size, metadata.entry_count,
        )
    except BaseException as error:
        if named is not None and named.identity_fd.disposition == "open":
            try:
                fs._close_node(named)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        try:
            fs._close_anonymous(operation)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
        raise error

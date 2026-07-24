"""Two independent fixed rootfs builds and pinned publication coordination."""

from dataclasses import dataclass, field
import hashlib
import os
import secrets
import sys
import time

sys.dont_write_bytecode = True

import completion_rootfs_builder as builder
import completion_rootfs_canonical as canonical
import completion_rootfs_fs as fs
import completion_rootfs_materializer as materializer
import completion_rootfs_plan as plan
import completion_rootfs_publish as publication

BUILD_SECONDS = 300
OUTER_SECONDS = 1200
MANIFEST_NAME = fs._name(b".cogs-rootfs-candidate-manifest-v1.json")
USTAR_NAME = fs._name(b".cogs-rootfs-candidate-v1.tar")


class BuildError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise BuildError()


@dataclass(frozen=True)
class BuildCandidate:
    manifest: bytes
    ustar: bytes
    manifest_sha256: str
    ustar_sha256: str
    ustar_size: int
    entry_count: int
    cache: tuple


@dataclass(frozen=True)
class TwoBuildCandidate:
    manifest_sha256: str
    manifest_size: int
    ustar_sha256: str
    ustar_size: int
    entry_count: int
    cache_count: int


@dataclass
class RetainedBuild:
    owned: builder.OwnedOperation
    base_chain: fs.HeldChain
    disposition: str = field(default="owned", init=False)


def _build_control(outer):
    deadline = min(outer.deadline_ns, time.monotonic_ns() + BUILD_SECONDS * 1_000_000_000)
    return fs.OperationControl(deadline, outer.cancelled)


def _writable_file(parent, name, control):
    observed = None
    operation = None
    try:
        observed = fs._open_path_node(parent, name, "file", control)
        observed.operation_fd.close()
        flags = os.O_RDWR | fs._O_NOFOLLOW | fs._O_CLOEXEC
        control.check()
        operation = fs.CheckedFd(os.open(name.raw, flags, dir_fd=parent.operation_fd.number), "candidate-writer")
        control.check()
        generation = fs._observe_node(observed.identity_fd, operation, control)
        result = fs.HeldNode(observed.identity_fd, operation, generation)
        observed = operation = None
        return result
    except BaseException as error:
        if operation is not None and operation.disposition == "open":
            try:
                operation.close()
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if observed is not None and observed.identity_fd.disposition == "open":
            try:
                fs._close_node(observed)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        raise error


def _candidate_record(preflight_module, path, size, digest):
    return preflight_module.MaterialRecord(
        path,
        "file",
        0o600,
        0,
        0,
        plan.SOURCE_DATE_EPOCH,
        size,
        None,
        None,
        None,
        digest,
        -1,
    )


def _cache_values(authority):
    return tuple((item.name, item.identity, item.sha256) for item in authority.cache)


def _build_once_unmasked(approval, token, outer_control, retain=False):
    _fail(type(approval) is fs.SourceApproval and type(retain) is bool)
    control = _build_control(outer_control)
    authority = plan.load_verified_build_inputs()
    cache_before = _cache_values(authority)
    chain = builder._open_base_chain(control)
    owned = None
    result = None
    try:
        owned = builder._begin_operation(chain, approval, token, control)
        try:
            result = materializer._materialize(authority, owned, control)
        except BaseException:
            owned = None
            raise
        owned = result.owned
        manifest = canonical._manifest(authority.plan)
        active, manifest_node = builder._create_ledger_entry(
            result.active,
            owned.operation,
            MANIFEST_NAME.text,
            MANIFEST_NAME,
            "file",
            manifest,
            control,
        )
        fs._close_node(manifest_node)
        active, empty_tar = builder._create_ledger_entry(
            active,
            owned.operation,
            USTAR_NAME.text,
            USTAR_NAME,
            "file",
            b"",
            control,
        )
        fs._close_node(empty_tar)
        tar_node = _writable_file(owned.operation, USTAR_NAME, control)
        try:
            os.lseek(tar_node.operation_fd.number, 0, os.SEEK_SET)
            metadata = canonical._canonical_metadata(owned.root, authority, tar_node.operation_fd, control)
            _fail(metadata.manifest == manifest)
            record = _candidate_record(plan, USTAR_NAME.text, metadata.ustar_size, metadata.ustar_sha256)
            active, _generation = materializer._metadata(
                active,
                tar_node,
                USTAR_NAME.text,
                record,
                owned.operation,
                control,
            )
            ustar = fs._read_regular(tar_node, metadata.ustar_size, control)
            _fail(hashlib.sha256(ustar).hexdigest() == metadata.ustar_sha256)
            fs._close_node(tar_node)
        except BaseException as error:
            if tar_node.identity_fd.disposition == "open":
                fs._close_node(tar_node, error)
            raise
        cache_after_authority = plan.load_verified_build_inputs()
        cache_after = _cache_values(cache_after_authority)
        _fail(cache_after == cache_before)
        refreshed = builder.OwnedOperation(owned.locked, active, owned.operation, owned.root, owned.operation_name)
        candidate = BuildCandidate(
            manifest, ustar, metadata.manifest_sha256, metadata.ustar_sha256,
            metadata.ustar_size, metadata.entry_count, cache_after,
        )
        if retain:
            retained = RetainedBuild(refreshed, chain)
            transferred = (candidate, retained)
            _fail(transferred[1].owned is refreshed and transferred[1].base_chain is chain)
            owned = None
            return transferred
        builder._cleanup_owned(refreshed, active, control)
        owned = None
        fs._close_chain(chain)
        return candidate
    except BaseException as error:
        if owned is not None:
            try:
                materializer._reload_and_cleanup(owned, materializer._fresh_cleanup_control())
                owned = None
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        try:
            fs._close_chain(chain)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
        raise error


def _build_once(approval, token, outer_control):
    return builder._fixed_umask(_build_once_unmasked, approval, token, outer_control, False)


def _build_once_retained(approval, token, outer_control):
    result = None
    try:
        result = builder._fixed_umask(_build_once_unmasked, approval, token, outer_control, True)
        _fail(type(result) is tuple and len(result) == 2 and type(result[0]) is BuildCandidate)
        _fail(type(result[1]) is RetainedBuild and result[1].disposition == "owned")
        return result
    except BaseException as error:
        if type(result) is tuple and len(result) == 2 and type(result[1]) is RetainedBuild:
            retained = result[1]
            try:
                materializer._reload_and_cleanup(retained.owned, materializer._fresh_cleanup_control())
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
            try:
                fs._close_chain(retained.base_chain)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        raise error


def _require_equal_builds(first, second):
    _fail(type(first) is BuildCandidate and type(second) is BuildCandidate)
    for candidate in (first, second):
        _fail(type(candidate.manifest) is bytes and type(candidate.ustar) is bytes and type(candidate.cache) is tuple)
        _fail(type(candidate.ustar_size) is int and type(candidate.entry_count) is int)
        _fail(all(type(item) is tuple and len(item) == 3 for item in candidate.cache))
    _fail(first.manifest == second.manifest and first.ustar == second.ustar)
    _fail(first.manifest_sha256 == second.manifest_sha256 and first.ustar_sha256 == second.ustar_sha256)
    _fail(first.ustar_size == second.ustar_size and first.entry_count == second.entry_count)
    _fail(first.cache == second.cache and len(first.cache) == 16)


def _require_pinned(candidate, pins):
    _fail(type(candidate) is BuildCandidate and type(pins) is publication.RootfsPins)
    _fail(len(candidate.manifest) == pins.manifest_size and candidate.manifest_sha256 == pins.manifest_sha256)
    _fail(candidate.ustar_size == pins.ustar_size and candidate.ustar_sha256 == pins.ustar_sha256)
    _fail(candidate.entry_count == pins.entry_count)


def _two_build_outputs(approval, outer_control):
    _fail(type(approval) is fs.SourceApproval and type(outer_control) is fs.OperationControl)
    first = _build_once(approval, secrets.token_hex(32), outer_control)
    second = _build_once(approval, secrets.token_hex(32), outer_control)
    _require_equal_builds(first, second)
    return first, second


def _candidate_metadata(first):
    return TwoBuildCandidate(
        first.manifest_sha256,
        len(first.manifest),
        first.ustar_sha256,
        first.ustar_size,
        first.entry_count,
        len(first.cache),
    )


def _two_build_candidate(approval, outer_control):
    first, _second = _two_build_outputs(approval, outer_control)
    return _candidate_metadata(first)


def _pinned_publication(approval, destination_parent, outer_control):
    pins = publication._load_pins()
    first, second = _two_build_outputs(approval, outer_control)
    candidate = _candidate_metadata(first)
    _require_pinned(first, pins)
    published = publication._publish(destination_parent, second.manifest, second.ustar, pins, outer_control)
    _fail(published.entry_count == candidate.entry_count)
    return published

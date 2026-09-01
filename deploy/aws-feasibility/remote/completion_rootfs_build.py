"""Two independent fixed rootfs builds and pinned publication coordination."""

from dataclasses import dataclass
import secrets
import sys
import time

sys.dont_write_bytecode = True

import completion_rootfs_builder as builder
import completion_rootfs_canonical as canonical
import completion_rootfs_candidate as candidate_tar
import completion_rootfs_fs as fs
import completion_rootfs_materializer as materializer
import completion_rootfs_plan as plan
import completion_rootfs_publish as publication

BUILD_SECONDS = 900
NATIVE_PACKAGE_BUILD_SECONDS = 1_200
NATIVE_PACKAGE_CLEANUP_RESERVE_SECONDS = 600
OUTER_SECONDS = 2400
MANIFEST_NAME = builder.MANIFEST_NAME
_start_phase_structural_counters, _read_phase_structural_counters = fs._phase_structural_counter_provider((
    "first-build-work", "first-inline-cleanup", "second-build-work", "second-inline-cleanup",
    "equality", "pin", "post-verification", "settlement",
))


class BuildError(Exception):
    pass


class BuildAttemptError(BuildError):
    def __init__(self, work_outcome, work_stage="internal"):
        _fail(work_outcome in {"cancelled", "deadline", "failed", "not-started", "success"}
              and work_stage in materializer.MATERIALIZE_STAGES)
        self.work_outcome, self.work_stage = work_outcome, work_stage
        super().__init__()


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


# Historical producer name remains an alias; the ownership type is consumer-neutral.
RetainedBuild = builder.RetainedOperation


def _fixed_build_control(outer, seconds):
    _fail(type(outer) is fs.OperationControl and type(seconds) is int and seconds > 0)
    now_ns = time.monotonic_ns()
    deadline_ns = min(outer.deadline_ns, now_ns + seconds * 1_000_000_000)
    return fs.OperationControl(deadline_ns, outer.cancelled)


def _build_control(outer):
    return _fixed_build_control(outer, BUILD_SECONDS)


def _native_package_build_control(outer):
    return _fixed_build_control(outer, NATIVE_PACKAGE_BUILD_SECONDS)


def _native_package_controls(outer):
    _fail(type(outer) is fs.OperationControl)
    work_boundary = outer.deadline_ns - NATIVE_PACKAGE_CLEANUP_RESERVE_SECONDS * 1_000_000_000
    _fail(work_boundary > time.monotonic_ns())
    bounded = fs.OperationControl(work_boundary, outer.cancelled)
    return materializer.NativePackageControls(
        _native_package_build_control(bounded), outer.deadline_ns)


def _cache_values(authority):
    return tuple((item.name, item.identity, item.sha256) for item in authority.cache)


def _cleanup_control(work_control, cleanup_deadline_ns):
    if cleanup_deadline_ns is None:
        return materializer._fresh_cleanup_control()
    return materializer._native_package_cleanup_control(work_control,
                                                        cleanup_deadline_ns)


def _build_once_controlled(approval, token, retain, control, materialize, materialize_control,
                           cleanup_deadline_ns=None):
    _fail(type(approval) is fs.SourceApproval and type(retain) is bool)
    _fail(type(control) is fs.OperationControl and callable(materialize))
    _fail(cleanup_deadline_ns is None or type(cleanup_deadline_ns) is int)
    authority = plan.load_verified_build_inputs()
    cache_before = _cache_values(authority)
    chain = builder._open_base_chain(control)
    owned = None
    result = None
    work_outcome = "not-started"
    work_stage = "internal"
    try:
        owned = builder._begin_operation(chain, approval, token, control)
        try:
            result = materialize(authority, owned, materialize_control)
            work_outcome = "success"
        except materializer.MaterializerWorkError as error:
            work_outcome, work_stage = error.work_outcome, error.work_stage
            owned = None
            raise
        owned = result.owned
        manifest = canonical._manifest(authority.plan)
        active, manifest_node = builder._create_ledger_entry(
            result.active,
            builder._operation_chain(owned, control),
            MANIFEST_NAME.text,
            MANIFEST_NAME,
            "file",
            manifest,
            control,
        )
        fs._close_node(manifest_node)
        candidate = candidate_tar._create_candidate(active, owned, authority, manifest, control)
        active = candidate.active
        metadata = candidate
        ustar = candidate.raw
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
        builder._cleanup_owned(refreshed, active,
                               _cleanup_control(control, cleanup_deadline_ns))
        owned = None
        fs._close_chain(chain)
        return candidate
    except BaseException as error:
        if owned is not None:
            try:
                materializer._reload_and_cleanup(
                    owned, _cleanup_control(control, cleanup_deadline_ns))
                owned = None
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        try:
            fs._close_chain(chain)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
        raise BuildAttemptError(work_outcome, work_stage) from error


def _build_once_unmasked(approval, token, outer_control, retain=False):
    _fail(type(outer_control) is fs.OperationControl)
    control = _build_control(outer_control)
    return _build_once_controlled(
        approval, token, retain, control, materializer._materialize, control)


def _native_package_build_once_unmasked(approval, token, outer_control):
    controls = _native_package_controls(outer_control)
    return _build_once_controlled(
        approval, token, True, controls.work, materializer._native_package_materialize,
        controls, controls.cleanup_deadline_ns)


def _build_once(approval, token, outer_control):
    return builder._fixed_umask(_build_once_unmasked, approval, token, outer_control, False)


def _retained_once(unmasked, approval, token, outer_control, cleanup_deadline_ns=None):
    result = None
    try:
        result = builder._fixed_umask(unmasked, approval, token, outer_control)
        _fail(type(result) is tuple and len(result) == 2 and type(result[0]) is BuildCandidate)
        _fail(type(result[1]) is RetainedBuild and result[1].disposition == "owned")
        return result
    except BaseException as error:
        if type(result) is tuple and len(result) == 2 and type(result[1]) is RetainedBuild:
            retained = result[1]
            try:
                cleanup = (materializer._fresh_cleanup_control()
                           if cleanup_deadline_ns is None else
                           materializer._native_package_cleanup_control(
                               outer_control, cleanup_deadline_ns))
                materializer._reload_and_cleanup(retained.owned, cleanup)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
            try:
                fs._close_chain(retained.base_chain)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        raise error


def _build_once_retained_unmasked(approval, token, outer_control):
    return _build_once_unmasked(approval, token, outer_control, True)


def _build_once_retained(approval, token, outer_control):
    return _retained_once(
        _build_once_retained_unmasked, approval, token, outer_control)


def _native_package_build_once_retained(approval, token, outer_control):
    _fail(type(outer_control) is fs.OperationControl)
    return _retained_once(
        _native_package_build_once_unmasked, approval, token, outer_control,
        outer_control.deadline_ns)


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

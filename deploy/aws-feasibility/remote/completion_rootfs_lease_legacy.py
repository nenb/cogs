"""Producer-only historical dual-build acquisition, excluded from consumer routes."""
import hashlib
import secrets

import completion_rootfs_build as build
import completion_rootfs_builder as builder
import completion_rootfs_canonical as canonical
import completion_rootfs_fs as fs
import completion_rootfs_lease as lease
import completion_rootfs_materializer as materializer
import completion_rootfs_plan as plan
import completion_rootfs_publish as publication


def acquire(approval, outer):
    lease._fail(type(approval) is fs.SourceApproval and type(outer) is fs.OperationControl)
    retained = None
    boundary = False
    stage = "bootstrap"
    try:
        lease._bootstrap_state(approval, outer)
        stage = "pins"
        pins = publication._load_pins()
        lease._fail(type(pins) is publication.RootfsPins)
        stage = "build-first"
        first_token = secrets.token_hex(32)
        first = build._build_once(approval, first_token, outer)
        stage = "build-second"
        second_token = secrets.token_hex(32)
        lease._fail(second_token != first_token)
        second, retained = build._build_once_retained(
            approval, second_token, outer)
        stage = "equality"
        build._require_equal_builds(first, second)
        stage = "pin-check"
        build._require_pinned(first, pins); build._require_pinned(second, pins)
        stage = "topology"
        lease._topology(retained)
        lease._stable_graph(retained, None, outer, "active")
        boundary = True; retained.disposition = "uncertain"
        stage = "lease-mark"
        refreshed = builder._mark_leased(
            retained.owned, pins.manifest_sha256, pins.manifest_size,
            pins.ustar_sha256, pins.ustar_size, pins.entry_count, outer)
        retained.owned = refreshed
        lease._topology(retained)
        reference = lease._reference(refreshed, refreshed.active)
        retained.disposition = "transferred"
        result = lease.RetainedRootfsLease(reference, retained)
        stage = "lease-verify"
        lease._stable_lease_pass(result, outer)
        first = second = None
        return result
    except BaseException as error:
        if stage in {"build-first", "build-second"} and type(error) is build.BuildAttemptError:
            detail = (error.work_stage if error.work_stage != "internal"
                      else lease.ROOTFS_BUILD_OUTCOMES[error.work_outcome])
            stage = f"{stage}-{detail}"
        if retained is None:
            raise lease.RootfsAcquireError(stage) from error
        try:
            if boundary: lease._close_preserving(retained, error)
            lease._abandon_active(retained, error)
        except BaseException as settled:
            raise lease.RootfsAcquireError(stage) from settled
        raise lease.RootfsAcquireError(stage) from error


def verify(value, control):
    """Historical verification retained only for producer qualification tests."""
    lease._fail(value.reference.prebuilt_descriptor_raw is None)
    terminal = builder._terminal_record(value.retained.owned.active).record_type
    lease._fail(terminal in {"leased", "release-authorized",
                             "prestage-release-authorized"})
    if terminal == "leased":
        lease._stable_lease_pass(value, control)
    else:
        lease._stable_graph(value.retained, value.reference, control, terminal)
    authority = plan.load_verified_build_inputs()
    count = materializer._postwalk(
        value.retained.owned, value.retained.owned.root, authority, control)
    lease._fail(count == value.reference.entry_count)
    fresh = plan.revalidate_build_inputs(authority)
    lease._fail(type(fresh) is plan.RootfsBuildInputs and fresh is not authority)
    manifest = canonical._manifest(fresh.plan)
    reference = value.reference
    lease._fail(len(manifest) == reference.manifest_size
                and hashlib.sha256(manifest).hexdigest() == reference.manifest_sha256
                and len(fresh.plan.entries) == reference.entry_count)
    pins = publication._load_pins()
    lease._fail(type(pins) is publication.RootfsPins)
    lease._fail((pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256,
                 pins.ustar_size, pins.entry_count) ==
                (reference.manifest_sha256, reference.manifest_size,
                 reference.ustar_sha256, reference.ustar_size,
                 reference.entry_count))
    if terminal == "leased":
        lease._stable_lease_pass(value, control)
    else:
        lease._stable_graph(value.retained, value.reference, control, terminal)
    return reference

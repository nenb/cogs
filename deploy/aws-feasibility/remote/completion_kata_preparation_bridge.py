"""Package-private V2 static preparation handoffs for the fixed coordinator.

Every choice is fixed by reviewed V2 control bytes.  Callers supply only sealed
custody values returned here; there are no path, environment, command, role, or
selector parameters.  This module neither opens KVM nor composes network,
evidence, operation, runtime, or workflow owners.
"""
import os
import time

import completion_kata_admission as admission
import completion_kata_process as process
import completion_rootfs_fs as rootfs_fs
import completion_rootfs_lease as rootfs_lease

_ROOTFS_DEADLINE_NS = 3_600_000_000_000
_claim_static = admission._take_static_preparation_issuer()
_states = {}


class PreparationBridgeError(Exception):
    pass


def _require(condition):
    if not condition:
        raise PreparationBridgeError("exact fixed V2 preparation custody required")


def _control():
    return rootfs_fs.OperationControl(
        time.monotonic_ns() + _ROOTFS_DEADLINE_NS, lambda: False)


def _claim_fixed_static_preparation():
    """Authenticate the sole fixed V2 package and retain its source files."""
    custody = _claim_static()
    _states[custody] = {
        "approval": None, "lease": None, "mapping": None, "mapping_consumed": False,
        "executables": None, "abandoned": False,
    }
    return custody


def _fixed_source_approval(custody):
    """Return SourceApproval derived from the verified complete source manifest."""
    state = _states.get(custody)
    _require(state is not None)
    if state["approval"] is None:
        approval = admission._fixed_source_approval(custody)
        _require(type(approval) is rootfs_fs.SourceApproval)
        state["approval"] = approval
    return state["approval"]


def _acquire_fixed_rootfs(custody):
    """Acquire the exact two-build pinned rootfs lease for this V2 custody."""
    state = _states.get(custody)
    _require(state is not None and state["lease"] is None and not state["abandoned"])
    lease = rootfs_lease._acquire(_fixed_source_approval(custody), _control())
    _require(type(lease) is rootfs_lease.RetainedRootfsLease
             and lease.disposition == "held")
    state["lease"] = lease
    return lease


def _claim_fixed_live_mapping(custody, lease):
    """Retain and verify all fixed rootfs objects from the held lease."""
    state = _states.get(custody)
    _require(state is not None and state["lease"] is lease
             and state["mapping"] is None and lease.disposition == "held")
    claim = admission._claim_live_rootfs_mapping(custody, lease)
    state["mapping"] = claim
    return claim


def _consume_fixed_live_mapping(custody, claim):
    """Consume the one live mapping description; no mapping bytes come from a caller."""
    state = _states.get(custody)
    _require(state is not None and state["mapping"] is claim
             and not state["mapping_consumed"])
    description = admission._consume_live_rootfs_mapping(custody, claim)
    _require(type(description) is admission.LiveMappingDescription)
    state["mapping_consumed"] = True
    return description


def _duplicate_role(description, expected):
    role, _source_class, path = expected
    _require(type(description) is admission.ExecutableRoleDescription
             and (description.role, description.path) == (role, path)
             and description.objects and description.objects[0].kind == "executable")
    duplicates = []
    try:
        for retained in description.objects:
            duplicate = os.dup(retained.descriptor)
            os.set_inheritable(duplicate, False)
            duplicates.append(duplicate)
        executable = description.objects[0]
        return process.RetainedExecutable(
            role, path, duplicates[0], executable.sha256,
            description.closure_sha256, process._host_generation(duplicates[0]),
            tuple(duplicates[1:]))
    except BaseException as error:
        errors = [error]
        for descriptor in reversed(duplicates):
            try:
                os.close(descriptor)
            except OSError as close_error:
                errors.append(close_error)
        if len(errors) == 1:
            raise
        raise BaseExceptionGroup("retained executable duplication failed", errors)


def _issue_fixed_executable_owner(custody):
    """Issue one owner from descriptors retained by exact static custody."""
    state = _states.get(custody)
    _require(state is not None and state["executables"] is None)
    retained = []
    try:
        for expected in admission.EXECUTABLES:
            role = expected[0]
            claim = admission._claim_executable_role_custody(custody, role)
            description = admission._consume_executable_role_custody(custody, claim, role)
            retained.append(_duplicate_role(description, expected))
        owner = process._issue_retained_executable_owner(tuple(retained))
        state["executables"] = owner
        return owner
    except BaseException as error:
        errors = [error]
        for value in retained:
            for descriptor in (value.descriptor, *value.closure_descriptors):
                try:
                    os.close(descriptor)
                except OSError as close_error:
                    errors.append(close_error)
        if len(errors) == 1:
            raise
        raise BaseExceptionGroup("fixed executable owner issuance failed", errors)


def _claim_fixed_executable_owner(custody):
    """Forward-only executable handoff after live rootfs mapping custody."""
    state = _states.get(custody)
    _require(state is not None and state["mapping_consumed"])
    return _issue_fixed_executable_owner(custody)


def _reconstruct_fixed_executable_owner(custody, journal):
    """Issue lazy cleanup custody after matching the durable source identity.

    Recovery claims a role only when its current cleanup phase needs it.  This
    is essential after the exact containerd tree has been removed: containerd
    and ctr no longer have pathnames, while retained host network tools remain
    claimable for firewall and final-baseline settlement.
    """
    state = _states.get(custody)
    _require(state is not None and state["lease"] is None
             and state["mapping"] is None and state["executables"] is None)
    approval = _fixed_source_approval(custody)
    identity = journal.reconstruction_identity()
    _require(identity["source_revision"] == approval.revision
             and identity["source_manifest_sha256"] == approval.manifest_sha256
             and identity["phase"] != "UNCERTAIN")
    owner = process._open_static_attested_executable_owner(custody)
    state["executables"] = owner
    return owner


def _abandon_fixed_rootfs(custody, lease):
    """Close a verified pre-operation lease while preserving its durable ledger."""
    state = _states.get(custody)
    _require(state is not None and state["lease"] is lease
             and not state["abandoned"] and lease.disposition == "held")
    rootfs_lease._abandon(lease, _control())
    state["abandoned"] = True


def _abort_fixed_static_preparation(custody):
    """Close retained executable and static descriptors after lease settlement."""
    state = _states.get(custody)
    lease = None if state is None else state["lease"]
    _require(state is not None and (lease is None or lease.disposition != "held"
             or lease.retained.disposition == "uncertain"))
    _states.pop(custody)
    errors = []
    if state["executables"] is not None:
        try:
            process._abort_attested_executable_owner(state["executables"])
        except BaseException as error:
            errors.append(error)
    try:
        admission._abort_static_preparation(custody)
    except BaseException as error:
        errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("fixed static preparation abort failed", errors)

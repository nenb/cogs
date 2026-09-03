"""Package-private V3 static preparation handoffs for the fixed coordinator.

Every choice is fixed by reviewed V3 control bytes.  Callers supply only sealed
custody values returned here; there are no path, environment, command, role, or
selector parameters.  This module neither opens KVM nor composes network,
evidence, operation, runtime, or workflow owners.
"""
import os
import time

import completion_cycle_authority as cycle_authority
import completion_formal_cycle_authority as formal_cycle_authority
import completion_kata_admission as admission
import completion_kata_process as process
import completion_rootfs_fs as rootfs_fs
import completion_rootfs_lease as rootfs_lease

_ROOTFS_DEADLINE_NS = 3_600_000_000_000
_claim_static = admission._claim_static_preparation
_claim_recovery_static = admission._claim_recovery_static_preparation
_claim_diagnostic_static = admission._claim_diagnostic_static_preparation
_claim_diagnostic_recovery_static = admission._claim_diagnostic_recovery_static_preparation
_states = {}


class PreparationBridgeError(Exception):
    pass


def _require(condition):
    if not condition:
        raise PreparationBridgeError("exact fixed V3 preparation custody required")


def _control():
    return rootfs_fs.OperationControl(
        time.monotonic_ns() + _ROOTFS_DEADLINE_NS, lambda: False)


def _record_static_custody(custody, recovery, diagnostic=False):
    _states[custody] = {
        "diagnostic": diagnostic,
        "approval": None, "rootfs_authority": None, "cycle_grant": None,
        "lease": None, "mapping": None, "mapping_consumed": False,
        "executables": None, "prepared": None, "abandoned": False,
        "recovery": recovery,
    }
    return custody


def _claim_fixed_static_preparation():
    """Authenticate the sole forward V3 package and retain its source files."""
    return _record_static_custody(_claim_static(), False)


def _claim_fixed_recovery_static_preparation():
    """Authenticate the sole cleanup-only V3 package."""
    return _record_static_custody(_claim_recovery_static(), True)


def _claim_diagnostic_static_preparation():
    """Authenticate the explicit current-source split-lineage profile."""
    return _record_static_custody(_claim_diagnostic_static(), False, True)


def _claim_diagnostic_recovery_static_preparation():
    """Authenticate that profile for cleanup-only reconstruction."""
    return _record_static_custody(_claim_diagnostic_recovery_static(), True, True)


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
    return _acquire_rootfs(custody, False)


def _acquire_diagnostic_rootfs(custody):
    return _acquire_rootfs(custody, True)


def _acquire_rootfs(custody, diagnostic=False):
    """Import only the descriptor-bound rootfs selected by the custody profile."""
    state = _states.get(custody)
    _require(state is not None and state["diagnostic"] is diagnostic
             and state["lease"] is None and not state["abandoned"])
    authority = (admission._diagnostic_prebuilt_rootfs_authority(custody)
                 if diagnostic else admission._fixed_prebuilt_rootfs_authority(custody))
    state["rootfs_authority"] = authority
    lease = rootfs_lease._acquire_prebuilt(
        _fixed_source_approval(custody), authority, _control())
    _require(type(lease) is rootfs_lease.RetainedRootfsLease
             and lease.disposition == "held")
    state["lease"] = lease
    return lease


def _validate_fixed_cycle_grant(custody, grant):
    """Bind controller-issued batch authority to exact H/G control and rootfs."""
    state = _states.get(custody)
    _require(state is not None and not state["diagnostic"])
    binding = admission._cycle_grant_binding(custody)
    _require(type(grant) in {cycle_authority.campaign.CycleLaunchGrant,
                            formal_cycle_authority.FormalCycleGrant}
             and state["cycle_grant"] is None
             and grant.implementation_revision == binding["implementation_revision"]
             and grant.control_revision == binding["control_revision"]
             and grant.static_control_sha256 == binding["static_control_sha256"]
             and grant.rootfs_descriptor_sha256 == binding["rootfs_descriptor_sha256"])
    state["cycle_grant"] = grant
    return grant


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


def _claim_fixed_prepared_runtime(custody):
    """Claim the sole exact static-only runtime without accepting a pathname."""
    state = _states.get(custody)
    _require(state is not None and state["prepared"] is None)
    state["prepared"] = admission._claim_prepared_runtime_custody(custody)
    return state["prepared"]


def _claim_fixed_executable_owner(custody):
    """Forward-only executable handoff after live rootfs mapping custody."""
    state = _states.get(custody)
    _require(state is not None and state["mapping_consumed"])
    return _issue_fixed_executable_owner(custody)


def _claim_fixed_recovery_executable_owner(custody):
    """Install reviewed host-tool policy before parsing an admitted journal.

    The journal's command lineage contains the hashes that this immutable
    policy validates, so recovery must establish the policy from static
    custody first.  The owner grants cleanup tools only after the journal is
    independently parsed and source-bound.
    """
    state = _states.get(custody)
    _require(state is not None and state["lease"] is None
             and state["mapping"] is None and state["executables"] is None)
    owner = process._open_static_attested_executable_owner(custody)
    try:
        for role in ("ssh", "ssh-keygen"):
            retained = process._claim_attested_executable(owner, role)
            process._release_attested_executable(retained)
    except BaseException as error:
        try:
            process._abort_attested_executable_owner(owner)
        except BaseException as close_error:
            raise BaseExceptionGroup("recovery policy owner close", [error, close_error])
        raise
    state["executables"] = owner
    return owner


def _reconstruct_fixed_executable_owner(custody, journal):
    """Issue lazy cleanup custody after matching the durable source identity.

    Recovery claims a role only when its current cleanup phase needs it.  This
    is essential after the exact containerd tree has been removed: containerd
    and ctr no longer have pathnames, while retained host network tools remain
    claimable for firewall and final-baseline settlement.
    """
    state = _states.get(custody)
    _require(state is not None and state["lease"] is None
             and state["mapping"] is None)
    approval = _fixed_source_approval(custody)
    identity = journal.reconstruction_identity()
    _require(identity["source_revision"] == approval.revision
             and identity["source_manifest_sha256"] == approval.manifest_sha256
             and identity["phase"] != "UNCERTAIN")
    owner = state["executables"]
    if owner is None:
        owner = _issue_fixed_executable_owner(custody)
    _require(type(owner) is process.AttestedExecutableOwner)
    return owner


def _retire_fixed_executable_owner(custody, owner):
    """Close the exact executable owner after all command and observer use."""
    state = _states.get(custody)
    _require(state is not None and state["executables"] is owner
             and type(owner) is process.AttestedExecutableOwner)
    process._abort_attested_executable_owner(owner)
    state["executables"] = None
    retire = (admission._retire_recovery_executable_role_custody
              if state["recovery"] else
              admission._retire_consumed_executable_role_custody)
    retire(custody)


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

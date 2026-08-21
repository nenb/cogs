"""Fixed Stage 2 owner composition and cleanup-only recovery.

The two entries in this module are zero argument by construction.  They accept
no paths, commands, reports, selectors, or behavior from a caller.  The owner
facade is package-private: production uses the fixed facade below, while tests
replace the module-held facade with typed recorders.
"""
from dataclasses import dataclass

import completion_kata_admission as admission
import completion_kata_execution_bridge as execution_bridge
import completion_kata_network as network
import completion_kata_operation_bridge as operation_bridge
import completion_kata_process as process
import completion_kata_qualification as qualification
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_local_receipt as local_receipt

_claim_execution_custody = admission._take_execution_custody_issuer()
_issue_owner_receipt = local_receipt._take_local_receipt_issuer()

FORWARD_ORDER = (
    "STATIC_CUSTODY",
    "ROOTFS_ACQUIRED",
    "OPERATION_ADMITTED",
    "LIVE_CUSTODY",
    "EXECUTABLES_RETAINED",
    "INPUTS_CREATED",
    "BASELINES_CAPTURED",
    "NETWORK_READY",
    "NETWORK_CAUSAL_PROOF",
    "RUNTIME_STAGED",
    "EXECUTION_MAPPING_BOUND",
    "TASK_LAUNCHED",
    "RUNTIME_PROVED",
    "SSH_AUTHENTICATED",
)
TEARDOWN_ORDER = (
    "READINESS_REVOKED",
    "TASK_STOPPED",
    "NETWORK_ABSENT",
    "TASK_ABSENT",
    "CONTAINER_ABSENT",
    "RUNTIME_ABSENT",
    "SHARE_ABSENT",
    "FIREWALL_ABSENT",
    "INPUT_REMOVED",
    "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT",
    "FINAL_BASELINES",
    "RETIRED",
)
CLEANUP_ORDER = (
    "READINESS_REVOKED",
    "OWNERSHIP_OBSERVED",
    "TASK_STOPPED",
    "NETWORK_ABSENT",
    "TASK_ABSENT",
    "CONTAINER_ABSENT",
    "RUNTIME_ABSENT",
    "SHARE_ABSENT",
    "CONTAINERD_ABSENT",
    "FIREWALL_ABSENT",
    "INPUT_REMOVED",
    "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT",
    "FINAL_BASELINES",
    "RETIRED",
    "OPERATION_REMOVED",
)
RECOVERY_FORBIDDEN = (
    "acquire_rootfs",
    "open_operation",
    "claim_live_custody",
    "claim_executables",
    "create_inputs",
    "create_network",
    "stage_runtime",
    "bind_execution_mapping",
    "launch_task",
    "authenticate_ssh",
)
BLOCKED_REASON = (
    "exact static admission/live-custody and private owner-evidence bridges required"
)


class CoordinatorError(Exception):
    pass


class CoordinatorBlocked(CoordinatorError):
    """An immutable prerequisite or package-private integration refusal."""


@dataclass
class _Lifecycle:
    recovery: bool = False
    static_custody: object = None
    static_gate: object = None
    rootfs: object = None
    operation: object = None
    live_custody: object = None
    executables: object = None
    inputs: object = None
    baselines: object = None
    network_owner: object = None
    network_proof: object = None
    network_guest_proof: object = None
    staged_runtime: object = None
    execution_mapping: object = None
    task: object = None
    runtime_proof: object = None
    session: object = None
    ownership_proof: object = None
    final_baselines: object = None
    retired: object = None
    primary_failure: BaseException = None
    custody_settled: bool = False


class _AdmissionBoundary:
    """Current immutable admission adapter; it deliberately invents no live facts."""

    def claim_static(self):
        try:
            custody, gate = _claim_execution_custody()
        except admission.AdmissionError as error:
            raise CoordinatorBlocked(BLOCKED_REASON) from error
        return custody, gate

    def claim_live(self, lifecycle):
        # V1 admission currently combines static and live custody.  Treat that
        # exact held pair as one value; never reconstruct it from bindings.
        if lifecycle.static_custody is None or lifecycle.static_gate is None:
            raise CoordinatorBlocked(BLOCKED_REASON)
        return lifecycle.static_custody, lifecycle.static_gate

    def abort(self, lifecycle):
        admission._abort_execution_custody(lifecycle.static_custody)


class _PrivateEvidenceBoundary:
    """No JSON/report adapter exists here; only the future sealed owner issuer fits."""

    def normal(self, lifecycle):
        raise CoordinatorBlocked(BLOCKED_REASON)

    def recovery(self, lifecycle):
        raise CoordinatorBlocked(BLOCKED_REASON)


class _PackagePrivateOwners:
    """Fixed integration facade over package-private owners.

    Mutable methods delegate only to sealed bridge owners. Static custody and
    final evidence remain separate fail-closed prerequisites; public owner
    openers stay closed.
    """

    def __init__(self):
        self.admission = _AdmissionBoundary()
        self.operation = operation_bridge._take_operation_bridge()
        self.execution = execution_bridge._take_execution_bridge()
        self.evidence = _PrivateEvidenceBoundary()

    def claim_static_custody(self, lifecycle):
        return self.admission.claim_static()

    def acquire_rootfs(self, lifecycle):
        return operation_bridge._acquire_rootfs(self.operation, lifecycle)

    def open_operation(self, lifecycle):
        return operation_bridge._open_operation(self.operation, lifecycle)

    def claim_live_custody(self, lifecycle):
        return self.admission.claim_live(lifecycle)

    def claim_executables(self, lifecycle):
        return process._open_static_attested_executable_owner(lifecycle.static_custody)

    def create_inputs(self, lifecycle):
        return operation_bridge._create_inputs(self.operation, lifecycle)

    def capture_baselines(self, lifecycle):
        return execution_bridge._capture_baselines(self.execution, lifecycle)

    def create_network(self, lifecycle):
        return execution_bridge._create_network(self.execution, lifecycle)

    def prove_network_causality(self, lifecycle):
        return execution_bridge._prove_network_causality(self.execution, lifecycle)

    def stage_runtime(self, lifecycle):
        return execution_bridge._stage_runtime(self.execution, lifecycle)

    def bind_execution_mapping(self, lifecycle):
        return execution_bridge._bind_execution_mapping(self.execution, lifecycle)

    def launch_task(self, lifecycle):
        return execution_bridge._launch_task(self.execution, lifecycle)

    def prove_runtime(self, lifecycle):
        return execution_bridge._prove_runtime(self.execution, lifecycle)

    def authenticate_ssh(self, lifecycle):
        return execution_bridge._authenticate_ssh(self.execution, lifecycle)

    def open_existing_operation(self, lifecycle):
        return operation_bridge._open_existing_operation(self.operation, lifecycle)

    def recover_pending(self, lifecycle):
        return operation_bridge._recover_pending(self.operation, lifecycle)

    def revoke_readiness(self, lifecycle):
        return execution_bridge._revoke_readiness(self.execution, lifecycle)

    def observe_ownership(self, lifecycle):
        return execution_bridge._observe_ownership(self.execution, lifecycle)

    def stop_task(self, lifecycle):
        return execution_bridge._stop_task(self.execution, lifecycle)

    def remove_network(self, lifecycle):
        return execution_bridge._remove_network(self.execution, lifecycle)

    def remove_task(self, lifecycle):
        return execution_bridge._remove_task(self.execution, lifecycle)

    def remove_container(self, lifecycle):
        return execution_bridge._remove_container(self.execution, lifecycle)

    def remove_runtime(self, lifecycle):
        return execution_bridge._remove_runtime(self.execution, lifecycle)

    def remove_share(self, lifecycle):
        return execution_bridge._remove_share(self.execution, lifecycle)

    def stop_containerd(self, lifecycle):
        return execution_bridge._stop_containerd(self.execution, lifecycle)

    def remove_firewall(self, lifecycle):
        return execution_bridge._remove_firewall(self.execution, lifecycle)

    def remove_inputs(self, lifecycle):
        return operation_bridge._remove_inputs(self.operation, lifecycle)

    def prepare_rootfs_release(self, lifecycle):
        return operation_bridge._prepare_rootfs_release(self.operation, lifecycle)

    def authorize_rootfs_release(self, lifecycle):
        return operation_bridge._authorize_rootfs_release(self.operation, lifecycle)

    def remove_rootfs(self, lifecycle):
        return operation_bridge._remove_rootfs(self.operation, lifecycle)

    def observe_final_baselines(self, lifecycle):
        return execution_bridge._observe_final_baselines(self.execution, lifecycle)

    def retire_operation(self, lifecycle):
        return operation_bridge._retire_operation(self.operation, lifecycle)

    def remove_operation(self, lifecycle):
        return operation_bridge._remove_operation(self.operation, lifecycle)

    def abandon_prepared_rootfs(self, lifecycle):
        return operation_bridge._abandon_prepared_rootfs(self.operation, lifecycle)

    def owner_evidence(self, lifecycle):
        if lifecycle.recovery:
            return self.evidence.recovery(lifecycle)
        return self.evidence.normal(lifecycle)

    def abort_custody(self, lifecycle):
        self.admission.abort(lifecycle)


_owners = _PackagePrivateOwners()


def preflight_report():
    """Read-only diagnostics remain data and never become coordinator authority."""
    return qualification.committed_report()


def _collect(errors, action):
    try:
        return action()
    except BaseException as error:
        errors.append(error)
        return None


def _cleanup_operation(lifecycle):
    """One pass in historical reverse-settlement order; no action is retried."""
    errors = []
    _collect(errors, lambda: _owners.revoke_readiness(lifecycle))
    lifecycle.ownership_proof = _collect(
        errors, lambda: _owners.observe_ownership(lifecycle))
    _collect(errors, lambda: _owners.stop_task(lifecycle))
    _collect(errors, lambda: _owners.remove_network(lifecycle))
    _collect(errors, lambda: _owners.remove_task(lifecycle))
    _collect(errors, lambda: _owners.remove_container(lifecycle))
    _collect(errors, lambda: _owners.remove_runtime(lifecycle))
    _collect(errors, lambda: _owners.remove_share(lifecycle))
    _collect(errors, lambda: _owners.stop_containerd(lifecycle))
    _collect(errors, lambda: _owners.remove_firewall(lifecycle))
    _collect(errors, lambda: _owners.remove_inputs(lifecycle))
    _collect(errors, lambda: _owners.prepare_rootfs_release(lifecycle))
    _collect(errors, lambda: _owners.authorize_rootfs_release(lifecycle))
    _collect(errors, lambda: _owners.remove_rootfs(lifecycle))
    lifecycle.final_baselines = _collect(
        errors, lambda: _owners.observe_final_baselines(lifecycle))
    lifecycle.retired = _collect(errors, lambda: _owners.retire_operation(lifecycle))
    _collect(errors, lambda: _owners.remove_operation(lifecycle))
    return errors


def _cleanup(lifecycle):
    if lifecycle.operation is not None:
        return _cleanup_operation(lifecycle)
    if lifecycle.rootfs is not None:
        errors = []
        _collect(errors, lambda: _owners.abandon_prepared_rootfs(lifecycle))
        return errors
    return []


def _abort_custody(lifecycle, errors):
    if lifecycle.static_custody is not None and not lifecycle.custody_settled:
        try:
            _owners.abort_custody(lifecycle)
            lifecycle.custody_settled = True
        except BaseException as error:
            errors.append(error)


def _raise_failures(message, errors):
    if len(errors) == 1:
        raise CoordinatorError(message) from errors[0]
    raise BaseExceptionGroup(message, errors)


def _finish(lifecycle):
    evidence = _owners.owner_evidence(lifecycle)
    receipt = _issue_owner_receipt(lifecycle.static_custody, evidence)
    lifecycle.custody_settled = True
    return receipt


def _run_fixed_local_qualification():
    """Compose exactly one fixed lifecycle, then settle it exactly once."""
    lifecycle = _Lifecycle()
    try:
        lifecycle.static_custody, lifecycle.static_gate = _owners.claim_static_custody(lifecycle)
        lifecycle.rootfs = _owners.acquire_rootfs(lifecycle)
        lifecycle.operation = _owners.open_operation(lifecycle)
        lifecycle.live_custody = _owners.claim_live_custody(lifecycle)
        lifecycle.executables = _owners.claim_executables(lifecycle)
        lifecycle.inputs = _owners.create_inputs(lifecycle)
        lifecycle.baselines = _owners.capture_baselines(lifecycle)
        lifecycle.network_owner = _owners.create_network(lifecycle)
        lifecycle.network_proof = _owners.prove_network_causality(lifecycle)
        lifecycle.staged_runtime = _owners.stage_runtime(lifecycle)
        lifecycle.execution_mapping = _owners.bind_execution_mapping(lifecycle)
        lifecycle.task = _owners.launch_task(lifecycle)
        lifecycle.runtime_proof = _owners.prove_runtime(lifecycle)
        lifecycle.session = _owners.authenticate_ssh(lifecycle)
    except BaseException as error:
        lifecycle.primary_failure = error

    errors = _cleanup(lifecycle)
    if errors:
        if lifecycle.primary_failure is not None:
            errors.insert(0, lifecycle.primary_failure)
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed lifecycle cleanup was not exact", errors)

    try:
        return _finish(lifecycle)
    except BaseException as error:
        errors = [error]
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed lifecycle owner evidence was not exact", errors)


def _recover_fixed_local_qualification():
    """Open durable ownership and clean only; work construction is unreachable."""
    lifecycle = _Lifecycle(recovery=True)
    try:
        lifecycle.static_custody, lifecycle.static_gate = _owners.claim_static_custody(lifecycle)
        lifecycle.operation = _owners.open_existing_operation(lifecycle)
        _owners.recover_pending(lifecycle)
    except BaseException as error:
        lifecycle.primary_failure = error

    errors = _cleanup(lifecycle)
    if errors:
        if lifecycle.primary_failure is not None:
            errors.insert(0, lifecycle.primary_failure)
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed recovery cleanup was not exact", errors)
    if lifecycle.operation is None:
        errors = [lifecycle.primary_failure or CoordinatorBlocked(BLOCKED_REASON)]
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed recovery operation was unavailable", errors)

    try:
        return _finish(lifecycle)
    except BaseException as error:
        errors = [error]
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed recovery evidence was not exact", errors)


def _consume_local_receipt(receipt):
    try:
        return local_receipt._consume_local_receipt(receipt)
    except local_receipt.LocalReceiptError as error:
        raise CoordinatorError("exact private local result receipt required") from error


def open_fixed_coordinator():
    """No public production opener exists; only the zero-argument entries compose."""
    raise CoordinatorBlocked(BLOCKED_REASON)


# Historical offline adapter proof retained for the existing owner tests.
@dataclass(frozen=True)
class FixedOwners:
    process_owner: object
    network_owner: object
    runtime_owner: object
    ssh_owner: object
    state: dict = None

    def __post_init__(self):
        if self.state is None:
            object.__setattr__(self, "state", {
                "poisoned": False, "readiness_revoked": False,
                "task_stopped": False,
            })


def authenticate_once(owners, outcome):
    if type(owners) is not FixedOwners:
        raise CoordinatorError("exact fixed owners required")
    try:
        if type(outcome) is not process.ProcessOutcome:
            raise CoordinatorError("exact process outcome required")
        adapted = process.adapt_ssh_process_outcome(outcome)
        return owners.ssh_owner.authenticate_process_outcome(adapted)
    except BaseException:
        owners.state["poisoned"] = True
        owners.ssh_owner.poison_and_ensure_revoked()
        owners.state["readiness_revoked"] = True
        raise


def revoke_before_teardown(owners):
    if type(owners) is not FixedOwners:
        raise CoordinatorError("exact fixed owners required")
    owners.ssh_owner.ensure_revoked()
    owners.state["readiness_revoked"] = True


def stop_task_after_revoke(owners):
    revoke_before_teardown(owners)
    if not owners.state["task_stopped"]:
        owners.process_owner.stop_task()
        owners.state["task_stopped"] = True

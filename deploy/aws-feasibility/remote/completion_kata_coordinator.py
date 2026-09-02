"""Fixed Stage 2 owner composition and cleanup-only recovery.

The two entries in this module are zero argument by construction.  They accept
no paths, commands, reports, selectors, or behavior from a caller.  The owner
facade is package-private: production uses the fixed facade below, while tests
replace the module-held facade with typed recorders.
"""
from dataclasses import dataclass

import completion_cycle_authority as cycle_authority
import completion_formal_cycle_authority as formal_cycle_authority
import completion_kata_admission as admission
import completion_kata_execution_bridge as execution_bridge
import completion_kata_network as network
import completion_kata_operation_bridge as operation_bridge
import completion_kata_preparation_bridge as preparation_bridge
import completion_kata_process as process
import completion_kata_qualification as qualification
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_rootfs_lease as rootfs_lease
import completion_local_evidence as local_evidence
import completion_local_receipt as local_receipt
import completion_cycle_evidence as cycle_evidence

_produce_owner_evidence = local_receipt._take_owner_evidence_producer()
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
    "RUNTIME_STAGED",
    "EXECUTION_MAPPING_BOUND",
    "TASK_LAUNCHED",
    "RUNTIME_NETWORK_OBSERVED",
    "RUNTIME_PROVED",
    "NETWORK_CAUSAL_PROOF",
    "SSH_AUTHENTICATED",
)
TEARDOWN_ORDER = (
    "READINESS_REVOKED",
    "TASK_STOPPED",
    "TASK_ABSENT",
    "RUNTIME_ABSENT",
    "NETWORK_ABSENT",
    "CONTAINER_ABSENT",
    "SHARE_ABSENT",
    "FIREWALL_ABSENT",
    "CONTAINERD_ABSENT",
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
    "TASK_ABSENT",
    "RUNTIME_ABSENT",
    "RUNTIME_NETWORK_RELEASED_V1",
    "NETWORK_ABSENT",
    "CONTAINER_ABSENT",
    "SHARE_ABSENT",
    "FIREWALL_ABSENT",
    "CONTAINERD_ABSENT",
    "INPUT_REMOVED",
    "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT",
    "FINAL_BASELINES",
    "RETIRED",
    "OPERATION_REMOVED",
    "INDEPENDENT_RESIDUE",
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
_FAILURE_STAGES = frozenset({
    "entry", "rootfs-acquire", "operation-open", "operation-live", "internal-contract",
    *("rootfs-" + stage for stage in rootfs_lease.ROOTFS_ACQUIRE_STAGES),
})


class CoordinatorError(Exception):
    pass


class CoordinatorBlocked(CoordinatorError):
    """An immutable prerequisite or package-private integration refusal."""


class CoordinatorTerminal(CoordinatorError):
    """Bounded terminal class retaining private ordered causes without rendering them."""
    def __init__(self, stage, errors):
        if stage not in _FAILURE_STAGES or not errors:
            raise CoordinatorError("invalid fixed terminal failure")
        super().__init__("fixed local qualification terminal failure")
        self.stage, self.errors = stage, tuple(errors)


def _safe_failure_diagnostic(error):
    stage = error.stage if type(error) is CoordinatorTerminal else "internal-contract"
    return f"cogs local qualification failed at {stage}\n"


@dataclass
class _Lifecycle:
    recovery: bool = False
    diagnostic: bool = False
    cycle_route: object = None
    cycle_grant: object = None
    static_custody: object = None
    static_gate: object = None
    source_approval: object = None
    rootfs: object = None
    operation: object = None
    live_custody: object = None
    live_mapping: object = None
    executables: object = None
    inputs: object = None
    baselines: object = None
    network_owner: object = None
    network_proof: object = None
    staged_runtime: object = None
    execution_mapping: object = None
    task: object = None
    runtime_network: object = None
    runtime_observation: object = None
    runtime_proof: object = None
    session: object = None
    ownership_proof: object = None
    final_baselines: object = None
    retired: object = None
    residue: object = None
    primary_failure: BaseException = None
    failure_stage: str = "entry"
    custody_settlement_claimed: bool = False


class _AdmissionBoundary:
    """Exact V2 preparation custody, lease mapping, and executable handoffs."""

    def claim_static(self):
        try:
            custody = preparation_bridge._claim_fixed_static_preparation()
            approval = preparation_bridge._fixed_source_approval(custody)
        except (admission.AdmissionError,
                preparation_bridge.PreparationBridgeError) as error:
            raise CoordinatorBlocked(BLOCKED_REASON) from error
        return custody, approval

    def claim_recovery_static(self):
        try:
            custody = preparation_bridge._claim_fixed_recovery_static_preparation()
            approval = preparation_bridge._fixed_source_approval(custody)
        except (admission.AdmissionError,
                preparation_bridge.PreparationBridgeError) as error:
            raise CoordinatorBlocked(BLOCKED_REASON) from error
        return custody, approval

    def claim_diagnostic_static(self, recovery=False):
        try:
            custody = (preparation_bridge._claim_diagnostic_recovery_static_preparation()
                       if recovery else
                       preparation_bridge._claim_diagnostic_static_preparation())
            approval = preparation_bridge._fixed_source_approval(custody)
        except (admission.AdmissionError,
                preparation_bridge.PreparationBridgeError) as error:
            raise CoordinatorBlocked("sealed diagnostic preparation required") from error
        return custody, approval

    def claim_live(self, lifecycle):
        if (lifecycle.static_custody is None or lifecycle.rootfs is None
                or lifecycle.source_approval is not lifecycle.static_gate):
            raise CoordinatorBlocked(BLOCKED_REASON)
        claim = preparation_bridge._claim_fixed_live_mapping(
            lifecycle.static_custody, lifecycle.rootfs)
        description = preparation_bridge._consume_fixed_live_mapping(
            lifecycle.static_custody, claim)
        lifecycle.live_mapping = description
        return description

    def claim_executables(self, lifecycle):
        if lifecycle.live_mapping is not lifecycle.live_custody:
            raise CoordinatorBlocked("exact live mapping must precede executable custody")
        return preparation_bridge._claim_fixed_executable_owner(
            lifecycle.static_custody)

    def claim_recovery_executables(self, lifecycle):
        if not lifecycle.recovery or lifecycle.source_approval is not lifecycle.static_gate:
            raise CoordinatorBlocked("cleanup-only executable policy admission differs")
        return preparation_bridge._claim_fixed_recovery_executable_owner(
            lifecycle.static_custody)

    def abort(self, lifecycle):
        preparation_bridge._abort_fixed_static_preparation(
            lifecycle.static_custody)


class _PrivateEvidenceBoundary:
    """Translate only exact terminal owner facts into closure-private evidence."""

    def normal(self, lifecycle):
        try:
            if type(lifecycle.retired) is not local_evidence._RetiredJournalOwnerResult:
                raise CoordinatorBlocked("exact retired journal owner result required")
            if type(lifecycle.residue) is not local_evidence._ResidueOwnerResult:
                raise CoordinatorBlocked("exact independent residue owner result required")
            history = local_evidence._typed_durable_history(lifecycle.retired)
            passed = any(row.record_type in ("SSH_READY_V2", "SSH_READY")
                         for row in history.records)
            if passed and lifecycle.primary_failure is not None:
                raise CoordinatorBlocked("non-durable failure forbids pass evidence")
            if passed and type(lifecycle.session) is not ssh.AuthenticatedSession:
                raise CoordinatorBlocked("exact authenticated SSH session required")
            if (lifecycle.runtime_observation is not None
                    and type(lifecycle.runtime_observation) is not local_evidence._PlatformOwnerResult):
                raise CoordinatorBlocked("exact typed platform owner result required")
            if (lifecycle.runtime_proof is not None
                    and type(lifecycle.runtime_proof) is not local_evidence._RuntimeOwnerResult):
                raise CoordinatorBlocked("exact causal runtime owner result required")
            if passed and lifecycle.runtime_proof is None:
                raise CoordinatorBlocked("pass requires causal runtime owner result")
            binding_value = admission._static_custody_binding(
                lifecycle.static_custody)
            if lifecycle.runtime_proof is not None:
                binding_value["runtime_attestation_sha256"] = (
                    local_evidence._runtime_attestation_sha256(
                        lifecycle.runtime_proof))
            bindings = local_evidence._BindingOwnerResult(**binding_value)
            return _produce_owner_evidence(
                lifecycle.static_custody, bindings, lifecycle.retired, history,
                lifecycle.session, lifecycle.runtime_observation,
                lifecycle.runtime_proof, lifecycle.residue)
        except local_evidence.LocalEvidenceError as error:
            raise CoordinatorBlocked("exact terminal owner evidence required") from error

    def recovery(self, lifecycle):
        raise CoordinatorBlocked("cleanup-only recovery cannot produce pass evidence")


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
        if lifecycle.diagnostic:
            return self.admission.claim_diagnostic_static(lifecycle.recovery)
        return (self.admission.claim_recovery_static() if lifecycle.recovery
                else self.admission.claim_static())

    def validate_cycle_grant(self, lifecycle):
        if lifecycle.cycle_grant is None:
            return None
        return preparation_bridge._validate_fixed_cycle_grant(
            lifecycle.static_custody, lifecycle.cycle_grant)

    def acquire_rootfs(self, lifecycle):
        if lifecycle.source_approval is not lifecycle.static_gate:
            raise CoordinatorBlocked("exact preparation SourceApproval required")
        return operation_bridge._acquire_rootfs(self.operation, lifecycle)

    def open_operation(self, lifecycle):
        return operation_bridge._open_operation(self.operation, lifecycle)

    def claim_live_custody(self, lifecycle):
        return self.admission.claim_live(lifecycle)

    def claim_executables(self, lifecycle):
        return self.admission.claim_executables(lifecycle)

    def claim_recovery_executables(self, lifecycle):
        return self.admission.claim_recovery_executables(lifecycle)

    def bind_cycle_route(self, lifecycle):
        if lifecycle.cycle_route is None:
            return None
        return cycle_evidence._bind_operation_route(
            lifecycle.cycle_route, lifecycle.operation, lifecycle.cycle_grant)

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

    def observe_runtime_network(self, lifecycle):
        return execution_bridge._observe_runtime_network(self.execution, lifecycle)

    def prove_runtime(self, lifecycle):
        return execution_bridge._prove_runtime(self.execution, lifecycle)

    def authenticate_ssh(self, lifecycle):
        return execution_bridge._authenticate_ssh(self.execution, lifecycle)

    def authenticate_readiness_ssh(self, lifecycle):
        return execution_bridge._authenticate_readiness_ssh(
            self.execution, lifecycle)

    def open_existing_operation(self, lifecycle):
        return operation_bridge._open_existing_operation(self.operation, lifecycle)

    def recover_pending(self, lifecycle):
        return operation_bridge._recover_pending(self.operation, lifecycle)

    def recover_preproduction(self, lifecycle):
        return operation_bridge._recover_preproduction(self.operation, lifecycle)

    def reconstruct_cleanup(self, lifecycle):
        lifecycle.rootfs = operation_bridge._reconstruct_rootfs(
            self.operation, lifecycle)
        return execution_bridge._reconstruct_execution_cleanup(
            self.execution, lifecycle)

    def revoke_readiness(self, lifecycle):
        return execution_bridge._revoke_readiness(self.execution, lifecycle)

    def observe_ownership(self, lifecycle):
        return execution_bridge._observe_ownership(self.execution, lifecycle)

    def stop_task(self, lifecycle):
        return execution_bridge._stop_task(self.execution, lifecycle)

    def release_network_holds(self, lifecycle):
        return execution_bridge._release_network_holds(self.execution, lifecycle)

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

    def observe_independent_residue(self, lifecycle):
        return execution_bridge._observe_independent_residue(
            self.execution, lifecycle)

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
    _collect(errors, lambda: _owners.remove_task(lifecycle))
    _collect(errors, lambda: _owners.remove_runtime(lifecycle))
    _collect(errors, lambda: _owners.release_network_holds(lifecycle))
    _collect(errors, lambda: _owners.remove_network(lifecycle))
    _collect(errors, lambda: _owners.remove_container(lifecycle))
    _collect(errors, lambda: _owners.remove_share(lifecycle))
    _collect(errors, lambda: _owners.remove_firewall(lifecycle))
    _collect(errors, lambda: _owners.stop_containerd(lifecycle))
    _collect(errors, lambda: _owners.remove_inputs(lifecycle))
    _collect(errors, lambda: _owners.prepare_rootfs_release(lifecycle))
    _collect(errors, lambda: _owners.authorize_rootfs_release(lifecycle))
    _collect(errors, lambda: _owners.remove_rootfs(lifecycle))
    lifecycle.final_baselines = _collect(
        errors, lambda: _owners.observe_final_baselines(lifecycle))
    lifecycle.retired = _collect(errors, lambda: _owners.retire_operation(lifecycle))
    _collect(errors, lambda: _owners.remove_operation(lifecycle))
    lifecycle.residue = _collect(
        errors, lambda: _owners.observe_independent_residue(lifecycle))
    return errors


def _cleanup(lifecycle):
    # A failed fresh reconstruction has no authority to reinterpret an exact
    # retained identity. Preserve every object rather than cascading into
    # path-, PID-, or descriptor-based teardown with an incomplete index.
    if lifecycle.recovery and lifecycle.primary_failure is not None:
        return []
    if lifecycle.operation is not None:
        return _cleanup_operation(lifecycle)
    if lifecycle.rootfs is not None:
        errors = []
        _collect(errors, lambda: _owners.abandon_prepared_rootfs(lifecycle))
        return errors
    return []


def _claim_custody_settlement(lifecycle):
    if lifecycle.static_custody is None or lifecycle.custody_settlement_claimed:
        raise CoordinatorBlocked("static custody settlement is not fresh")
    # The selected facade owns the one and only close attempt from this point,
    # including validation and close failures whose effect may be uncertain.
    lifecycle.custody_settlement_claimed = True


def _abort_custody(lifecycle, errors):
    if lifecycle.static_custody is not None and not lifecycle.custody_settlement_claimed:
        _claim_custody_settlement(lifecycle)
        try:
            _owners.abort_custody(lifecycle)
        except BaseException as error:
            errors.append(error)


def _raise_failures(message, errors):
    if len(errors) == 1:
        raise CoordinatorError(message) from errors[0]
    raise BaseExceptionGroup(message, errors)


def _finish(lifecycle, mint=True):
    if lifecycle.cycle_route is not None:
        if lifecycle.primary_failure is not None:
            raise CoordinatorBlocked("failed cycle cannot mint a receipt")
        _claim_custody_settlement(lifecycle)
        if not mint:
            return cycle_evidence._validate_and_discard_cycle_receipt(
                lifecycle.cycle_route, lifecycle)
        return cycle_evidence._issue_cycle_receipt(lifecycle.cycle_route, lifecycle)
    evidence = _owners.owner_evidence(lifecycle)
    # From this call onward the receipt transaction exclusively owns custody
    # close, including every no-mint failure. The coordinator must never retry
    # an uncertain or already-effective descriptor close.
    _claim_custody_settlement(lifecycle)
    return _issue_owner_receipt(lifecycle.static_custody, evidence)


def _run_cycle(route=None, grant=None, mint=True):
    """Compose one lifecycle; production routes require a consumed batch grant."""
    if type(mint) is not bool:
        raise CoordinatorBlocked("exact receipt policy required")
    diagnostic = route is not None and cycle_evidence._is_diagnostic_route(route)
    if diagnostic and (mint or grant is not None):
        raise CoordinatorBlocked("diagnostic route requires sealed no-mint policy")
    if route is not None:
        cycle_evidence._describe_route(route)
        if not cycle_evidence._cycle_launch_authorized(route, grant):
            raise CoordinatorBlocked("exact cycle batch/ordinal authority required")
    lifecycle = _Lifecycle(diagnostic=diagnostic, cycle_route=route, cycle_grant=grant)
    try:
        lifecycle.static_custody, lifecycle.static_gate = _owners.claim_static_custody(lifecycle)
        lifecycle.source_approval = lifecycle.static_gate
        if lifecycle.cycle_grant is not None:
            _owners.validate_cycle_grant(lifecycle)
        lifecycle.failure_stage = "rootfs-acquire"
        lifecycle.rootfs = _owners.acquire_rootfs(lifecycle)
        lifecycle.failure_stage = "operation-open"
        lifecycle.operation = _owners.open_operation(lifecycle)
        if lifecycle.operation is None:
            raise CoordinatorBlocked("exact operation owner was not established")
        if route is not None:
            _owners.bind_cycle_route(lifecycle)
        lifecycle.failure_stage = "operation-live"
        lifecycle.live_custody = _owners.claim_live_custody(lifecycle)
        lifecycle.executables = _owners.claim_executables(lifecycle)
        lifecycle.inputs = _owners.create_inputs(lifecycle)
        lifecycle.baselines = _owners.capture_baselines(lifecycle)
        lifecycle.network_owner = _owners.create_network(lifecycle)
        lifecycle.staged_runtime = _owners.stage_runtime(lifecycle)
        lifecycle.execution_mapping = _owners.bind_execution_mapping(lifecycle)
        lifecycle.task = _owners.launch_task(lifecycle)
        lifecycle.runtime_network = _owners.observe_runtime_network(lifecycle)
        lifecycle.runtime_observation = _owners.prove_runtime(lifecycle)
        if route is None or type(route) is cycle_evidence._FullRoute:
            lifecycle.network_proof = _owners.prove_network_causality(lifecycle)
            lifecycle.session = _owners.authenticate_ssh(lifecycle)
        else:
            lifecycle.session = _owners.authenticate_readiness_ssh(lifecycle)
    except BaseException as error:
        lifecycle.primary_failure = error
        if type(error) is rootfs_lease.RootfsAcquireError:
            lifecycle.failure_stage = "rootfs-" + error.stage

    errors = _cleanup(lifecycle)
    if lifecycle.static_custody is None and lifecycle.primary_failure is not None:
        if isinstance(lifecycle.primary_failure, CoordinatorBlocked):
            raise lifecycle.primary_failure
        raise CoordinatorBlocked(BLOCKED_REASON) from lifecycle.primary_failure
    if lifecycle.operation is None:
        errors.insert(0, lifecycle.primary_failure or CoordinatorBlocked(
            "exact operation owner was not established"))
        _abort_custody(lifecycle, errors)
        terminal = CoordinatorTerminal(lifecycle.failure_stage, errors)
        raise terminal from errors[0]
    if errors:
        if lifecycle.primary_failure is not None:
            errors.insert(0, lifecycle.primary_failure)
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed lifecycle cleanup was not exact", errors)

    try:
        return _finish(lifecycle, mint)
    except BaseException as error:
        errors = [error]
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed lifecycle owner evidence was not exact", errors)


def _run_fixed_local_qualification():
    """Preserve the existing local V3 owner and receipt semantics."""
    return _run_cycle()


def _run_fixed_full_cycle():
    """Zero-argument full owner consuming one fixed controller grant."""
    return _run_cycle(cycle_evidence._fixed_full_route(), cycle_authority.claim_full())


def _run_fixed_readiness_cycle():
    """Zero-argument readiness owner consuming one fixed controller grant."""
    return _run_cycle(cycle_evidence._fixed_readiness_route(), cycle_authority.claim_readiness())


def _run_formal_local_full_cycle():
    """One non-cloud formal full cycle consuming its fixed ordinal-one grant."""
    return _run_cycle(cycle_evidence._formal_full_route(),
                      formal_cycle_authority.claim_full())


def _run_formal_local_readiness_cycle():
    """One non-cloud formal readiness cycle consuming its fixed ordinal grant."""
    return _run_cycle(cycle_evidence._formal_readiness_route(),
                      formal_cycle_authority.claim_readiness())


def _run_fixed_full_rehearsal():
    """Real full production route with receipt issuance intentionally unreachable."""
    return _run_cycle(cycle_evidence._fixed_full_route(),
                      cycle_authority.claim_full(), False)


def _run_fixed_readiness_rehearsal():
    """Real readiness production route with receipt issuance intentionally unreachable."""
    return _run_cycle(cycle_evidence._fixed_readiness_route(),
                      cycle_authority.claim_readiness(), False)


def _run_current_source_full_diagnostic():
    """Current source plus fixed prior rootfs; receipt issuance is structurally refused."""
    return _run_cycle(cycle_evidence._diagnostic_full_route(), None, False)


def _run_current_source_readiness_diagnostic():
    """Current source readiness plus fixed prior rootfs; never mint evidence."""
    return _run_cycle(cycle_evidence._diagnostic_readiness_route(), None, False)


def _recover(recovery_diagnostic=False):
    """Open durable ownership and clean only; work construction is unreachable."""
    lifecycle = _Lifecycle(recovery=True, diagnostic=recovery_diagnostic)
    try:
        lifecycle.static_custody, lifecycle.static_gate = _owners.claim_static_custody(lifecycle)
        lifecycle.source_approval = lifecycle.static_gate
        # Command records are validated against an identity-sealed policy map.
        # Establish that map from reviewed static custody before the first
        # journal byte is parsed; no cleanup tool is claimed at this boundary.
        lifecycle.executables = _owners.claim_recovery_executables(lifecycle)
        lifecycle.operation = _owners.open_existing_operation(lifecycle)
        if lifecycle.operation is not None:
            _owners.recover_pending(lifecycle)
            _owners.reconstruct_cleanup(lifecycle)
        else:
            _owners.recover_preproduction(lifecycle)
    except BaseException as error:
        lifecycle.primary_failure = error

    errors = _cleanup(lifecycle)
    if lifecycle.primary_failure is not None:
        errors.insert(0, lifecycle.primary_failure)
    if errors:
        _abort_custody(lifecycle, errors)
        _raise_failures("fixed recovery cleanup was not exact", errors)

    # Recovery has cleanup authority only.  Even exact absence cannot mint or
    # consume normal evidence, and therefore can never become a qualification
    # pass.  Close static custody after the final independent observation.
    errors = []
    _abort_custody(lifecycle, errors)
    if errors:
        _raise_failures("fixed recovery custody close was not exact", errors)
    return None


def _recover_fixed_local_qualification():
    return _recover(False)


def _recover_current_source_diagnostic():
    return _recover(True)


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

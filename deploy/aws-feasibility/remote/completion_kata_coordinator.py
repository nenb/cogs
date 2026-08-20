"""Zero-argument Stage 2 local coordinator boundary.

The integrated owners are deliberately package-private.  This module admits no
caller facts, paths, commands, callbacks, or selectors.  The final host/Kata
rootfs-chroot attestation issuer and reviewed package pin are not committed, so
the only currently reachable operation is a read-only, pre-mutation refusal.
"""
from dataclasses import dataclass, field

import completion_kata_network as network
import completion_kata_process as process
import completion_kata_qualification as qualification
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_runtime_contract as workload_contract

TEARDOWN_ORDER = (
    "READINESS_REVOKED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRED",
)
BLOCKED_REASON = (
    "secure exact host/Kata rootfs-chroot attestation and reviewed final package pin required"
)


class CoordinatorError(Exception):
    pass


class CoordinatorBlocked(CoordinatorError):
    """A read-only prerequisite refusal, never a cleanup or execution result."""


@dataclass(frozen=True)
class FixedOwners:
    """Legacy offline adapter fixture; it cannot open a production owner."""
    process_owner: object
    network_owner: object
    runtime_owner: object
    ssh_owner: object
    state: dict = field(default_factory=lambda: {
        "poisoned": False, "readiness_revoked": False, "task_stopped": False,
    }, compare=False, repr=False)


def preflight_report():
    """Read-only blocker report; report bytes are never accepted as a permit."""
    return qualification.committed_report()


def _claim_complete_prerequisites():
    """Claim every immutable prerequisite before opening mutable owner state."""
    try:
        gate = qualification._claim_committed_gate()
        final_pin = workload_contract.load_final_pin()
    except (qualification.QualificationError,
            workload_contract.FinalPinUnavailable,
            workload_contract.WorkloadContractError) as error:
        raise CoordinatorBlocked(BLOCKED_REASON) from error

    # A qualified report alone is not an attestation capability.  The current
    # owner stack intentionally has no secure issuer for the exact host tools,
    # Kata runtime closure, and rootfs/chroot execution binding.  Do not replace
    # that missing capability with fixture contracts, a boolean, or report data.
    del gate, final_pin
    raise CoordinatorBlocked(BLOCKED_REASON)


def _coordinator_routes():
    """Keep result custody private; report bytes can never manufacture a receipt."""
    seal, receipts = object(), {}

    class _LocalReceipt:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise CoordinatorError("sealed local result receipt")
            return super().__new__(cls)

    def finish(value):
        # Lexical-only issuance point for the future exact successful branch.
        receipt = _LocalReceipt(seal)
        receipts[receipt] = value
        return receipt

    def run():
        """One fixed entry; blocked before journal/rootfs/network/runtime mutation."""
        _claim_complete_prerequisites()
        raise CoordinatorError("unreachable prerequisite return")
        return finish(None)

    def recover():
        """Crash entry is cleanup-only; absent attestation forbids journal opening."""
        _claim_complete_prerequisites()
        raise CoordinatorError("unreachable prerequisite return")

    def consume(receipt):
        if type(receipt) is not _LocalReceipt or receipt not in receipts:
            raise CoordinatorError("exact private local result receipt required")
        return receipts.pop(receipt)

    # `finish` is retained only in `run`'s closure; it is never exported as a
    # report-to-receipt API.
    return run, recover, consume


(_run_fixed_local_qualification, _recover_fixed_local_qualification,
 _consume_local_receipt) = _coordinator_routes()
del _coordinator_routes


def open_fixed_coordinator():
    """Public production opener remains closed; only the local entry may coordinate."""
    raise CoordinatorBlocked(BLOCKED_REASON)


def authenticate_once(owners, outcome):
    """Offline adapter proof: poison and revoke once on every failed adaptation."""
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
    """Offline cut proof: readiness revocation precedes task stop."""
    if type(owners) is not FixedOwners:
        raise CoordinatorError("exact fixed owners required")
    owners.ssh_owner.ensure_revoked()
    owners.state["readiness_revoked"] = True


def stop_task_after_revoke(owners):
    """Idempotently prove the composed revoke-before-stop cut with typed fakes."""
    revoke_before_teardown(owners)
    if not owners.state["task_stopped"]:
        owners.process_owner.stop_task()
        owners.state["task_stopped"] = True

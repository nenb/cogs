"""Fixed Stage 2 coordinator composition boundary.

This module performs no action at import.  The committed sealed preflight is
claimed before any owner is opened; current missing attestations make that
claim fail, so no command permit, KVM, network, runtime, or SSH owner exists.
"""
from dataclasses import dataclass, field
import completion_kata_network as network
import completion_kata_process as process
import completion_kata_qualification as qualification
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh

TEARDOWN_ORDER = (
    "READINESS_REVOKED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRED",
)


class CoordinatorError(Exception):
    pass


@dataclass(frozen=True)
class FixedOwners:
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


def open_fixed_coordinator():
    """Fail before mutation until every committed local fact is exact."""
    qualification._claim_committed_gate()
    # These owner loaders are intentionally still unavailable.  Their order is
    # fixed for the future exact gate and no caller booleans reach this route.
    process_owner = process.open_fixed_process_owner()
    network_owner = network._open_production_owner()
    runtime_owner = runtime._open_production_owner()
    ssh_owner = ssh.open_fixed_ssh_owner()
    return FixedOwners(process_owner, network_owner, runtime_owner, ssh_owner)


def authenticate_once(owners, outcome):
    """Poison and durably ensure one revoke for adaptation or authentication failure."""
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
    """Idempotently consume an existing revoke or create the one durable revoke."""
    if type(owners) is not FixedOwners:
        raise CoordinatorError("exact fixed owners required")
    owners.ssh_owner.ensure_revoked()
    owners.state["readiness_revoked"] = True


def stop_task_after_revoke(owners):
    """The composed teardown cut: durable revocation always precedes task stop."""
    revoke_before_teardown(owners)
    if not owners.state["task_stopped"]:
        owners.process_owner.stop_task()
        owners.state["task_stopped"] = True

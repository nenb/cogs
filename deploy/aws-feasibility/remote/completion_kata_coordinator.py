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


def _coordinator_routes():
    """Own fixed opening and one exact reverse close transaction."""
    seal = object()
    states = {}

    class LocalKataCoordinator:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise CoordinatorError("sealed local Kata coordinator")
            return super().__new__(cls)
        @property
        def uncertain(self):
            return states[self]["uncertain"]
        @property
        def closed(self):
            return states[self]["closed"]
        def authenticate_once(self, outcome):
            state = states[self]
            if state["closed"] or state["uncertain"]:
                raise CoordinatorError("coordinator is closed or uncertain")
            try:
                return state["owners"][3].authenticate_process_outcome(outcome)
            except BaseException:
                state["uncertain"] = True
                state["owners"][3].poison_and_ensure_revoked()
                raise
        def close(self):
            state = states[self]
            if state["closed"]:
                if state["uncertain"]:
                    raise CoordinatorError("local Kata cleanup is uncertain")
                return
            # Mark attempted before the first close.  A second call never
            # retries a failed cleanup or chooses a force/fallback route.
            state["closed"] = True
            failures = []
            for name, owner in reversed(tuple(zip(
                    ("process", "network", "runtime", "ssh"), state["owners"], strict=True))):
                try:
                    owner.close()
                except BaseException as error:
                    failures.append(f"{name}:{type(error).__name__}")
            if failures:
                state["uncertain"] = True
                state["failures"] = tuple(failures)
                raise CoordinatorError(";".join(failures))

    def make(owners):
        if (type(owners) is not tuple or len(owners) != 4
                or type(owners[0]) is not process.FixedProcessOwner
                or type(owners[1]) is not network.FixedNetworkOwner
                or type(owners[2]) is not runtime.FixedRuntimeOwner
                or type(owners[3]) is not ssh.FixedSshOwner):
            raise CoordinatorError("exact fixed owner tuple required")
        value = LocalKataCoordinator(seal)
        states[value] = {"owners": owners, "closed": False,
                         "uncertain": False, "failures": ()}
        return value

    return LocalKataCoordinator, make


LocalKataCoordinator, _make_local_coordinator = _coordinator_routes()
del _coordinator_routes


def _close_partial(opened, primary):
    failures = []
    for name, owner in reversed(opened):
        try:
            owner.close()
        except BaseException as error:
            failures.append(f"{name}:{type(error).__name__}")
    detail = f"; cleanup={'/'.join(failures)}" if failures else ""
    raise CoordinatorError(f"fixed owner opening failed:{type(primary).__name__}{detail}") from primary


def open_fixed_coordinator():
    """Open only from the authenticated, one-grant-per-owner contract."""
    gate = qualification._claim_committed_gate()
    opened = []
    try:
        process_owner = process._open_fixed_process_owner(
            qualification._grant_fixed_owner(gate, "process"),
        )
        opened.append(("process", process_owner))
        network_owner = network._open_production_owner(
            qualification._grant_fixed_owner(gate, "network"), process_owner,
        )
        opened.append(("network", network_owner))
        runtime_owner = runtime._open_production_owner(
            qualification._grant_fixed_owner(gate, "runtime"), process_owner, network_owner,
        )
        opened.append(("runtime", runtime_owner))
        ssh_owner = ssh._open_production_owner(
            qualification._grant_fixed_owner(gate, "ssh"), process_owner,
        )
        opened.append(("ssh", ssh_owner))
        return _make_local_coordinator(tuple(owner for _name, owner in opened))
    except BaseException as error:
        _close_partial(opened, error)


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

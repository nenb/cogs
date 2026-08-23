#!/usr/bin/env python3
"""Exhaustive fake-owner cuts for fixed composition and cleanup-only recovery."""
import ast
import io
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_coordinator as coordinator
import completion_local_full as local


def check(condition, message):
    if not condition:
        raise AssertionError(message)

METHOD_EVENT = {
    "claim_static_custody": "STATIC_CUSTODY",
    "acquire_rootfs": "ROOTFS_ACQUIRED",
    "open_operation": "OPERATION_ADMITTED",
    "claim_live_custody": "LIVE_CUSTODY",
    "claim_executables": "EXECUTABLES_RETAINED",
    "create_inputs": "INPUTS_CREATED",
    "capture_baselines": "BASELINES_CAPTURED",
    "create_network": "NETWORK_READY",
    "stage_runtime": "RUNTIME_STAGED",
    "bind_execution_mapping": "EXECUTION_MAPPING_BOUND",
    "launch_task": "TASK_LAUNCHED",
    "prove_runtime": "RUNTIME_PROVED",
    "prove_network_causality": "NETWORK_CAUSAL_PROOF",
    "authenticate_ssh": "SSH_AUTHENTICATED",
    "revoke_readiness": "READINESS_REVOKED",
    "observe_ownership": "OWNERSHIP_OBSERVED",
    "stop_task": "TASK_STOPPED",
    "remove_network": "NETWORK_ABSENT",
    "remove_task": "TASK_ABSENT",
    "remove_container": "CONTAINER_ABSENT",
    "remove_runtime": "RUNTIME_ABSENT",
    "remove_share": "SHARE_ABSENT",
    "stop_containerd": "CONTAINERD_ABSENT",
    "remove_firewall": "FIREWALL_ABSENT",
    "remove_inputs": "INPUT_REMOVED",
    "prepare_rootfs_release": "ROOTFS_RELEASE_READY",
    "authorize_rootfs_release": "ROOTFS_RELEASE_AUTHORIZED",
    "remove_rootfs": "ROOTFS_ABSENT",
    "observe_final_baselines": "FINAL_BASELINES",
    "retire_operation": "RETIRED",
    "remove_operation": "OPERATION_REMOVED",
    "observe_independent_residue": "INDEPENDENT_RESIDUE",
}
FORWARD_METHODS = tuple(name for name, event in METHOD_EVENT.items()
                        if event in coordinator.FORWARD_ORDER)
CLEANUP_METHODS = tuple(name for name, event in METHOD_EVENT.items()
                        if event in coordinator.CLEANUP_ORDER)
assert tuple(METHOD_EVENT[name] for name in FORWARD_METHODS) == coordinator.FORWARD_ORDER
assert tuple(METHOD_EVENT[name] for name in CLEANUP_METHODS) == coordinator.CLEANUP_ORDER


class Cut(Exception):
    pass


class GroupedFailure(BaseException):
    pass


class FakeOwners:
    def __init__(self, cut=None):
        self.cut = cut
        self.events = []

    def step(self, name, value=None):
        event = METHOD_EVENT.get(name, name)
        if self.cut == ("before", event):
            raise Cut(event)
        self.events.append(event)
        if self.cut == ("after", event):
            raise Cut(event)
        return event if value is None else value

    def claim_static_custody(self, _lifecycle):
        self.step("claim_static_custody")
        return "custody", "static-gate"

    def acquire_rootfs(self, _lifecycle): return self.step("acquire_rootfs")
    def open_operation(self, _lifecycle): return self.step("open_operation")
    def claim_live_custody(self, _lifecycle):
        return self.step("claim_live_custody", ("custody", "live-gate"))
    def claim_executables(self, _lifecycle): return self.step("claim_executables")
    def create_inputs(self, _lifecycle): return self.step("create_inputs")
    def capture_baselines(self, _lifecycle): return self.step("capture_baselines")
    def create_network(self, _lifecycle): return self.step("create_network")
    def prove_network_causality(self, lifecycle):
        assert lifecycle.baselines == "BASELINES_CAPTURED"
        assert lifecycle.network_owner == "NETWORK_READY"
        return self.step("prove_network_causality")
    def stage_runtime(self, _lifecycle): return self.step("stage_runtime")
    def bind_execution_mapping(self, _lifecycle): return self.step("bind_execution_mapping")
    def launch_task(self, _lifecycle): return self.step("launch_task")
    def prove_runtime(self, _lifecycle): return self.step("prove_runtime")
    def authenticate_ssh(self, _lifecycle): return self.step("authenticate_ssh")

    def revoke_readiness(self, _lifecycle): return self.step("revoke_readiness")
    def observe_ownership(self, _lifecycle): return self.step("observe_ownership")
    def stop_task(self, _lifecycle): return self.step("stop_task")
    def remove_network(self, _lifecycle): return self.step("remove_network")
    def remove_task(self, _lifecycle): return self.step("remove_task")
    def remove_container(self, _lifecycle): return self.step("remove_container")
    def remove_runtime(self, _lifecycle): return self.step("remove_runtime")
    def remove_share(self, _lifecycle): return self.step("remove_share")
    def stop_containerd(self, _lifecycle): return self.step("stop_containerd")
    def remove_firewall(self, _lifecycle): return self.step("remove_firewall")
    def remove_inputs(self, _lifecycle): return self.step("remove_inputs")
    def prepare_rootfs_release(self, _lifecycle): return self.step("prepare_rootfs_release")
    def authorize_rootfs_release(self, _lifecycle): return self.step("authorize_rootfs_release")
    def remove_rootfs(self, _lifecycle): return self.step("remove_rootfs")
    def observe_final_baselines(self, _lifecycle): return self.step("observe_final_baselines")
    def retire_operation(self, _lifecycle): return self.step("retire_operation")
    def remove_operation(self, _lifecycle): return self.step("remove_operation")
    def observe_independent_residue(self, _lifecycle):
        return self.step("observe_independent_residue")

    def abandon_prepared_rootfs(self, _lifecycle):
        return self.step("ABANDON_PREPARED_ROOTFS")

    def open_existing_operation(self, _lifecycle):
        return self.step("RECOVERY_OPERATION_OPENED")

    def recover_pending(self, _lifecycle):
        return self.step("PENDING_OWNER_RECOVERED")

    def reconstruct_cleanup(self, _lifecycle):
        return self.step("DURABLE_OWNERS_RECONSTRUCTED")

    def owner_evidence(self, lifecycle):
        name = "RECOVERY_EVIDENCE" if lifecycle.recovery else "OWNER_EVIDENCE"
        if lifecycle.operation is None:
            raise Cut("terminal operation evidence absent")
        if lifecycle.recovery:
            assert lifecycle.primary_failure is not None or lifecycle.session is None
        return self.step(name, (name, lifecycle.primary_failure is None))

    def abort_custody(self, _lifecycle):
        return self.step("CUSTODY_ABORTED")


def invoke(entry, fake, receipt_cut=None):
    receipt = object()
    def issue(custody, evidence):
        assert custody == "custody"
        if receipt_cut == "before":
            raise Cut("receipt")
        fake.events.append("RECEIPT_ISSUED")
        if receipt_cut == "after":
            raise Cut("receipt")
        assert evidence[0] in {"OWNER_EVIDENCE", "RECOVERY_EVIDENCE"}
        return receipt
    with patch.object(coordinator, "_owners", fake), patch.object(
            coordinator, "_issue_owner_receipt", side_effect=issue):
        try:
            value = entry()
            if entry is coordinator._recover_fixed_local_qualification:
                return value is None
            return value is receipt
        except BaseException:
            return False


def cleanup_projection(events):
    return tuple(event for event in events if event in coordinator.CLEANUP_ORDER)


# Complete lifecycle is ordinary forward order, exact reverse settlement, then
# private evidence and one receipt. No action is repeated.
fake = FakeOwners()
assert invoke(coordinator._run_fixed_local_qualification, fake)
assert tuple(fake.events) == (*coordinator.FORWARD_ORDER, *coordinator.CLEANUP_ORDER,
                              "OWNER_EVIDENCE", "RECEIPT_ISSUED")
assert len(fake.events) == len(set(fake.events))

# Every before/after forward cut stops forward progress. Once an operation was
# returned, all cleanup phases are attempted in order. Before that, only the
# retained preparation can be abandoned.
for ordinal, event in enumerate(coordinator.FORWARD_ORDER):
    for side in ("before", "after"):
        fake = FakeOwners((side, event))
        invoke(coordinator._run_fixed_local_qualification, fake)
        forward = tuple(item for item in fake.events if item in coordinator.FORWARD_ORDER)
        expected = coordinator.FORWARD_ORDER[:ordinal + (side == "after")]
        assert forward == expected, (side, event, fake.events)
        # A cut raised on return prevents Python from assigning that result.
        operation_returned = ordinal > 2
        if operation_returned:
            assert cleanup_projection(fake.events) == coordinator.CLEANUP_ORDER
        else:
            assert cleanup_projection(fake.events) == ()
            rootfs_returned = ordinal > 1
            assert ("ABANDON_PREPARED_ROOTFS" in fake.events) == rootfs_returned
        assert not any(item in fake.events for item in
                       coordinator.FORWARD_ORDER[ordinal + 1:])

# Assignment-boundary primaries remain the exact cause and never enter normal evidence.
for event, stage in (("ROOTFS_ACQUIRED", "rootfs-acquire"),
                     ("OPERATION_ADMITTED", "operation-open")):
    for side in ("before", "after"):
        fake = FakeOwners((side, event))
        caught = None
        with patch.object(coordinator, "_owners", fake):
            try: coordinator._run_fixed_local_qualification()
            except coordinator.CoordinatorTerminal as error:
                caught = error
                check(isinstance(error.__cause__, Cut), "assignment primary was not retained")
                check(error.errors[0] is error.__cause__, "terminal primary ordering changed")
            else: raise AssertionError("assignment-boundary primary was accepted")
        check(coordinator._safe_failure_diagnostic(caught) ==
              f"cogs local qualification failed at {stage}\n", "bounded stage differs")
        check("OWNER_EVIDENCE" not in fake.events and fake.events.count("CUSTODY_ABORTED") == 1,
              "assignment cut entered evidence or changed custody cardinality")

# Exact rootfs acquisition substages remain bounded and failure-bound.
class RootfsStageOwners(FakeOwners):
    def __init__(self, stage):
        super().__init__()
        self.stage = stage
    def acquire_rootfs(self, _lifecycle):
        raise coordinator.rootfs_lease.RootfsAcquireError(self.stage)
for stage in coordinator.rootfs_lease.ROOTFS_ACQUIRE_STAGES:
    fake = RootfsStageOwners(stage)
    with patch.object(coordinator, "_owners", fake):
        try: coordinator._run_fixed_local_qualification()
        except coordinator.CoordinatorTerminal as error:
            check(error.stage == "rootfs-" + stage, "rootfs substage mapping differs")
            diagnostic = coordinator._safe_failure_diagnostic(error)
            check(diagnostic == f"cogs local qualification failed at rootfs-{stage}\n",
                  "rootfs substage diagnostic differs")
            check(len(diagnostic.encode("ascii")) <= 64, "rootfs diagnostic exceeded byte bound")
        else: raise AssertionError("rootfs substage failure was accepted")

# A malformed successful None owner and grouped terminal causes cannot enter evidence or raw stderr.
class NoneOperationOwners(FakeOwners):
    evidence_attempts = 0
    def open_operation(self, _lifecycle):
        self.events.append("OPERATION_ADMITTED")
        return None
    def owner_evidence(self, lifecycle):
        self.evidence_attempts += 1
        return super().owner_evidence(lifecycle)
fake = NoneOperationOwners()
check(not invoke(coordinator._run_fixed_local_qualification, fake), "None operation was accepted")
check(fake.evidence_attempts == 0, "None operation entered evidence")

class PreOperationSecondaryOwners(FakeOwners):
    def __init__(self, abort_failure=False):
        super().__init__()
        self.abort_failure = abort_failure
    def open_operation(self, _lifecycle):
        self.events.append("OPERATION_ADMITTED")
        raise Cut("primary")
    def abandon_prepared_rootfs(self, _lifecycle):
        self.events.append("ABANDON_PREPARED_ROOTFS")
        raise Cut("abandon")
    def abort_custody(self, lifecycle):
        self.events.append("CUSTODY_ABORTED")
        if self.abort_failure: raise Cut("abort")
for abort_failure, count in ((False, 2), (True, 3)):
    fake = PreOperationSecondaryOwners(abort_failure)
    with patch.object(coordinator, "_owners", fake):
        try: coordinator._run_fixed_local_qualification()
        except coordinator.CoordinatorTerminal as error:
            check(error.stage == "operation-open" and len(error.errors) == count,
                  "grouped pre-operation terminal lost stage or ordered causes")
            check(error.errors[0] is error.__cause__, "grouped primary was not terminal cause")
        else: raise AssertionError("grouped pre-operation failure was accepted")

for error, expected in (
        (coordinator.CoordinatorBlocked(), ""),
        (coordinator.CoordinatorTerminal("operation-open", (Cut("primary"), Cut("abort"))),
         "cogs local qualification failed at operation-open\n"),
        (GroupedFailure("private grouped terminal"),
         "cogs local qualification failed at internal-contract\n")):
    stream = io.StringIO()
    with patch.object(coordinator, "_run_fixed_local_qualification", side_effect=error), \
         patch.object(sys, "stderr", stream):
        try: local.main()
        except local.LocalResultBlocked: pass
        else: raise AssertionError("terminal error was accepted")
    check(stream.getvalue() == expected, "terminal diagnostic was not exact and bounded")

# Every cleanup cut is attempted once, later cleanup still runs in order, no
# evidence is issued from uncertain cleanup, and custody is aborted once.
for event in coordinator.CLEANUP_ORDER:
    for side in ("before", "after"):
        fake = FakeOwners((side, event))
        assert not invoke(coordinator._run_fixed_local_qualification, fake)
        observed = cleanup_projection(fake.events)
        expected = tuple(item for item in coordinator.CLEANUP_ORDER
                         if not (side == "before" and item == event))
        assert observed == expected, (side, event, fake.events)
        assert "OWNER_EVIDENCE" not in fake.events
        assert fake.events.count("CUSTODY_ABORTED") == 1

# Private evidence and receipt cuts occur only after exact cleanup and settle
# custody by receipt or abort, never both successfully.
for event in ("OWNER_EVIDENCE",):
    for side in ("before", "after"):
        fake = FakeOwners((side, event))
        assert not invoke(coordinator._run_fixed_local_qualification, fake)
        assert cleanup_projection(fake.events) == coordinator.CLEANUP_ORDER
        assert fake.events.count("CUSTODY_ABORTED") == 1
for side in ("before", "after"):
    fake = FakeOwners()
    assert not invoke(coordinator._run_fixed_local_qualification, fake, side)
    assert cleanup_projection(fake.events) == coordinator.CLEANUP_ORDER
    # Receipt entry owns the one close on both no-mint and minted outcomes;
    # coordinator cleanup may not retry it.
    assert fake.events.count("CUSTODY_ABORTED") == 0

# Recovery has only immutable custody, exact existing-state opening, pending
# child settlement, cleanup, and custody close. It cannot issue evidence/receipt.
recovery_prefix = ("STATIC_CUSTODY", "RECOVERY_OPERATION_OPENED", "PENDING_OWNER_RECOVERED",
                   "DURABLE_OWNERS_RECONSTRUCTED")
fake = FakeOwners()
assert invoke(coordinator._recover_fixed_local_qualification, fake)
assert tuple(fake.events) == (*recovery_prefix, *coordinator.CLEANUP_ORDER,
                              "CUSTODY_ABORTED")
assert "RECOVERY_EVIDENCE" not in fake.events and "RECEIPT_ISSUED" not in fake.events
for event in (*recovery_prefix, *coordinator.CLEANUP_ORDER):
    for side in ("before", "after"):
        fake = FakeOwners((side, event))
        invoke(coordinator._recover_fixed_local_qualification, fake)
        assert not any(item in fake.events for item in coordinator.FORWARD_ORDER[1:])
        if event in coordinator.CLEANUP_ORDER:
            observed = cleanup_projection(fake.events)
            expected = tuple(item for item in coordinator.CLEANUP_ORDER
                             if not (side == "before" and item == event))
            assert observed == expected
            assert "RECOVERY_EVIDENCE" not in fake.events
            assert "RECEIPT_ISSUED" not in fake.events
        if event in {"STATIC_CUSTODY", "RECOVERY_OPERATION_OPENED"}:
            assert cleanup_projection(fake.events) == ()

# Source shape keeps both production entries zero argument and recovery cannot
# name any work-opening method. Public openers and arbitrary receipts stay shut.
source = (REMOTE / "completion_kata_coordinator.py").read_text()
tree = ast.parse(source)
functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
for name in ("_run_fixed_local_qualification", "_recover_fixed_local_qualification"):
    node = functions[name]
    assert not node.args.args and node.args.vararg is node.args.kwarg is None
recovery = ast.get_source_segment(source, functions["_recover_fixed_local_qualification"])
for forbidden in coordinator.RECOVERY_FORBIDDEN:
    assert f".{forbidden}(" not in recovery
for forbidden in ("getenv", "environ", "argv", "callback", "retry", "fallback", "kvm"):
    assert forbidden not in recovery.lower()
assert "_finish(" not in recovery and "owner_evidence(" not in recovery
normal_evidence = ast.get_source_segment(source, functions["normal"])
for required in ("_BindingOwnerResult", "_RetiredJournalOwnerResult", "AuthenticatedSession",
                 "_PlatformOwnerResult", "_RuntimeOwnerResult", "_ResidueOwnerResult",
                 "_typed_durable_history", "_produce_owner_evidence"):
    assert required in normal_evidence
assert normal_evidence.index("lifecycle.primary_failure") < normal_evidence.index("_produce_owner_evidence")
try:
    coordinator.open_fixed_coordinator()
except coordinator.CoordinatorBlocked:
    pass
else:
    raise AssertionError("public coordinator opener accepted")
try:
    coordinator._consume_local_receipt(object())
except coordinator.CoordinatorError:
    pass
else:
    raise AssertionError("caller-created receipt accepted")

print("completion coordinator exhaustive composition/cut/recovery matrix passed")

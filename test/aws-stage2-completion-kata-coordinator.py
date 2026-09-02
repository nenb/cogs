#!/usr/bin/env python3
"""Exhaustive fake-owner cuts for fixed composition and cleanup-only recovery."""
import ast
import io
from pathlib import Path
import sys
from types import SimpleNamespace
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
    "claim_recovery_executables": "RECOVERY_EXECUTABLE_POLICY",
    "create_inputs": "INPUTS_CREATED",
    "capture_baselines": "BASELINES_CAPTURED",
    "create_network": "NETWORK_READY",
    "stage_runtime": "RUNTIME_STAGED",
    "bind_execution_mapping": "EXECUTION_MAPPING_BOUND",
    "launch_task": "TASK_LAUNCHED",
    "observe_runtime_network": "RUNTIME_NETWORK_OBSERVED",
    "prove_runtime": "RUNTIME_PROVED",
    "prove_network_causality": "NETWORK_CAUSAL_PROOF",
    "authenticate_ssh": "SSH_AUTHENTICATED",
    "revoke_readiness": "READINESS_REVOKED",
    "observe_ownership": "OWNERSHIP_OBSERVED",
    "stop_task": "TASK_STOPPED",
    "remove_task": "TASK_ABSENT",
    "remove_runtime": "RUNTIME_ABSENT",
    "release_network_holds": "RUNTIME_NETWORK_RELEASED_V1",
    "remove_network": "NETWORK_ABSENT",
    "remove_container": "CONTAINER_ABSENT",
    "remove_share": "SHARE_ABSENT",
    "remove_firewall": "FIREWALL_ABSENT",
    "stop_containerd": "CONTAINERD_ABSENT",
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

    def validate_cycle_grant(self, _lifecycle): return self.step("CYCLE_GRANT_VALIDATED")
    def acquire_rootfs(self, _lifecycle): return self.step("acquire_rootfs")
    def open_operation(self, _lifecycle): return self.step("open_operation")
    def bind_cycle_route(self, _lifecycle): return self.step("CYCLE_ROUTE_BOUND")
    def claim_live_custody(self, _lifecycle):
        return self.step("claim_live_custody", ("custody", "live-gate"))
    def claim_executables(self, _lifecycle): return self.step("claim_executables")
    def claim_recovery_executables(self, _lifecycle):
        return self.step("claim_recovery_executables")
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
    def observe_runtime_network(self, lifecycle):
        assert lifecycle.task == "TASK_LAUNCHED"
        return self.step("observe_runtime_network")
    def prove_runtime(self, lifecycle):
        assert lifecycle.runtime_network == "RUNTIME_NETWORK_OBSERVED"
        return self.step("prove_runtime")
    def authenticate_ssh(self, _lifecycle): return self.step("authenticate_ssh")
    def authenticate_readiness_ssh(self, _lifecycle):
        return self.step("READINESS_SSH_AUTHENTICATED")

    def revoke_readiness(self, _lifecycle): return self.step("revoke_readiness")
    def observe_ownership(self, _lifecycle): return self.step("observe_ownership")
    def stop_task(self, _lifecycle): return self.step("stop_task")
    def remove_task(self, _lifecycle): return self.step("remove_task")
    def remove_runtime(self, _lifecycle): return self.step("remove_runtime")
    def release_network_holds(self, _lifecycle): return self.step("release_network_holds")
    def remove_network(self, _lifecycle): return self.step("remove_network")
    def remove_container(self, _lifecycle): return self.step("remove_container")
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

    def recover_preproduction(self, _lifecycle):
        return self.step("PREPRODUCTION_RECOVERED")

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

# The two authentic production route capabilities can each complete exactly one
# lifecycle while the rehearsal policy makes both evidence producers and the
# cycle receipt issuer unreachable. Cleanup, residue, and custody close remain.
def rehearsal_grant(mode, ordinal):
    value = {"batch_commitment": "1" * 64, "ordinal": ordinal, "mode": mode,
             "implementation_revision": "2" * 40, "control_revision": "3" * 40,
             "static_control_sha256": "4" * 64, "rootfs_descriptor_sha256": "5" * 64,
             "ami_commitment": "6" * 64, "plan_sha256": "7" * 64}
    value["grant_commitment"] = coordinator.cycle_authority.campaign._commit(
        b"cogs.stage2-cycle-launch-grant/v1", value)
    return coordinator.cycle_authority.campaign.CycleLaunchGrant(**value)

for route, grant, ssh_event in (
        (coordinator.cycle_evidence._fixed_full_route(), rehearsal_grant("full", 1),
         "SSH_AUTHENTICATED"),
        (coordinator.cycle_evidence._fixed_readiness_route(), rehearsal_grant("readiness", 2),
         "READINESS_SSH_AUTHENTICATED")):
    fake = FakeOwners()
    def validate_and_discard(seen_route, lifecycle):
        assert seen_route is route and lifecycle.cycle_route is route
        fake.events.append("CYCLE_RECEIPT_VALIDATED_DISCARDED")
        fake.abort_custody(lifecycle)
        return None
    with patch.object(coordinator, "_owners", fake), \
         patch.object(coordinator.cycle_evidence, "_validate_and_discard_cycle_receipt",
                      side_effect=validate_and_discard) as validation, \
         patch.object(coordinator.cycle_evidence, "_issue_cycle_receipt",
                      side_effect=AssertionError("rehearsal minted cycle receipt")), \
         patch.object(coordinator, "_produce_owner_evidence",
                      side_effect=AssertionError("rehearsal produced owner evidence")), \
         patch.object(coordinator, "_issue_owner_receipt",
                      side_effect=AssertionError("rehearsal minted local receipt")):
        rehearsal_result = coordinator._run_cycle(route, grant, False)
        check(rehearsal_result is None, "rehearsal returned a receipt")
    validation.assert_called_once()
    assert fake.events.count("CYCLE_GRANT_VALIDATED") == 1
    assert fake.events.count("CYCLE_ROUTE_BOUND") == 1
    assert fake.events.count(ssh_event) == 1
    assert cleanup_projection(fake.events) == coordinator.CLEANUP_ORDER
    assert fake.events[-2:] == ["CYCLE_RECEIPT_VALIDATED_DISCARDED", "CUSTODY_ABORTED"]
    assert "OWNER_EVIDENCE" not in fake.events and "RECEIPT_ISSUED" not in fake.events

# Every failed no-mint cycle cut after operation assignment still reaches exact
# retirement/removal/residue, while cycle receipt issuance remains unreachable.
for route, grant in (
        (coordinator.cycle_evidence._fixed_full_route(), rehearsal_grant("full", 1)),
        (coordinator.cycle_evidence._fixed_readiness_route(),
         rehearsal_grant("readiness", 2))):
    cycle_forward = (coordinator.FORWARD_ORDER[3:] if grant.mode == "full" else
                     (*coordinator.FORWARD_ORDER[3:-2],
                      "READINESS_SSH_AUTHENTICATED"))
    for event in cycle_forward:
        for side in ("before", "after"):
            fake = FakeOwners((side, event))
            with patch.object(coordinator, "_owners", fake), patch.object(
                    coordinator.cycle_evidence, "_issue_cycle_receipt") as issuer:
                try: coordinator._run_cycle(route, grant)
                except BaseException: pass
                else: raise AssertionError("failed cycle minted a receipt")
            issuer.assert_not_called()
            assert cleanup_projection(fake.events) == coordinator.CLEANUP_ORDER
            assert "RETIRED" in fake.events and "OPERATION_REMOVED" in fake.events
            assert fake.events[-1] == "CUSTODY_ABORTED"

# Both sealed cycle transaction facades close once even when exact semantic
# construction fails, and preserve validation before close in ordered causes.
class MalformedCycleLifecycle:
    static_custody = object()
for transaction in (coordinator.cycle_evidence._issue_cycle_receipt,
                    coordinator.cycle_evidence._validate_and_discard_cycle_receipt):
    close_failure = Cut("close-after-validation")
    with patch.object(coordinator.cycle_evidence.preparation,
                      "_abort_fixed_static_preparation",
                      side_effect=close_failure) as close:
        try:
            transaction(coordinator.cycle_evidence._fixed_full_route(),
                        MalformedCycleLifecycle())
        except coordinator.cycle_evidence.CycleEvidenceError as error:
            causes = getattr(error.__cause__, "exceptions",
                             getattr(error.__cause__, "errors", ()))
            check(len(causes) == 2 and isinstance(causes[0], AttributeError)
                  and causes[1] is close_failure,
                  "cycle transaction did not preserve validation-first causes")
        else: raise AssertionError("malformed cycle transaction was accepted")
    close.assert_called_once_with(MalformedCycleLifecycle.static_custody)

# Once the cycle facade claims settlement, issuer-validation and no-mint-close
# failures remain primary and cannot trigger a coordinator abort retry.
for mint, failure_name in ((True, "issuer-validation"), (False, "no-mint-close")):
    route = coordinator.cycle_evidence._fixed_full_route()
    current_grant = rehearsal_grant("full", 1)
    class SettlementFailureOwners(FakeOwners):
        def abort_custody(self, lifecycle):
            self.events.append("CUSTODY_ABORTED")
            if not mint: raise Cut(failure_name)
    fake = SettlementFailureOwners()
    def failed_transaction(_route, lifecycle):
        fake.abort_custody(lifecycle)
        if mint: raise Cut(failure_name)
    patch_name = ("_issue_cycle_receipt" if mint
                  else "_validate_and_discard_cycle_receipt")
    with patch.object(coordinator, "_owners", fake), patch.object(
            coordinator.cycle_evidence, patch_name, side_effect=failed_transaction):
        try: coordinator._run_cycle(route, current_grant, mint)
        except coordinator.CoordinatorError as error:
            assert isinstance(error.__cause__, Cut)
            assert str(error.__cause__) == failure_name
        else: raise AssertionError("failed cycle settlement was accepted")
    assert fake.events.count("CUSTODY_ABORTED") == 1

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
            check(len(diagnostic.encode("ascii")) <= 67, "rootfs diagnostic exceeded byte bound")
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
recovery_prefix = ("STATIC_CUSTODY", "RECOVERY_EXECUTABLE_POLICY",
                   "RECOVERY_OPERATION_OPENED", "PENDING_OWNER_RECOVERED",
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
        if event in {"STATIC_CUSTODY", "RECOVERY_EXECUTABLE_POLICY",
                     "RECOVERY_OPERATION_OPENED"}:
            assert cleanup_projection(fake.events) == ()

# A retained unadmitted prefix is routed exactly once to cleanup-only recovery.
# No production reconstruction, 18-step cleanup, evidence, or receipt is reachable.
class PrestageOwners(FakeOwners):
    def open_existing_operation(self, _lifecycle):
        self.step("RECOVERY_OPERATION_OPENED")
        return None
    def recover_pending(self, _lifecycle):
        raise AssertionError("prestage entered pending-command recovery")
    def reconstruct_cleanup(self, _lifecycle):
        raise AssertionError("prestage entered production reconstruction")

for cut in (None, ("before", "PREPRODUCTION_RECOVERED"),
            ("after", "PREPRODUCTION_RECOVERED")):
    fake = PrestageOwners(cut)
    with patch.object(coordinator, "_owners", fake):
        try: coordinator._recover_fixed_local_qualification()
        except coordinator.CoordinatorNoOperationPath:
            pass
        except BaseException as error:
            if cut is None:
                raise AssertionError("exact no-operation classification changed") from error
        else:
            raise AssertionError("no-operation recovery returned ordinary success")
    expected = ["STATIC_CUSTODY", "RECOVERY_EXECUTABLE_POLICY",
                "RECOVERY_OPERATION_OPENED"]
    if cut is None or cut[0] == "after": expected.append("PREPRODUCTION_RECOVERED")
    expected.append("CUSTODY_ABORTED")
    assert fake.events == expected
    assert cleanup_projection(fake.events) == ()
    assert not any(item in fake.events for item in (
        "PENDING_OWNER_RECOVERED", "DURABLE_OWNERS_RECONSTRUCTED",
        "OWNER_EVIDENCE", "RECOVERY_EVIDENCE", "RECEIPT_ISSUED"))
    assert fake.events.count("CUSTODY_ABORTED") == 1

# Only the fully settled no-operation route requests preparation fallback.
for cut, expected in ((None, coordinator.CoordinatorNoOperationPath),
                      (("after", "PREPRODUCTION_RECOVERED"), coordinator.CoordinatorError),
                      (("after", "CUSTODY_ABORTED"), coordinator.CoordinatorError)):
    fake = PrestageOwners(cut)
    with patch.object(coordinator, "_owners", fake):
        try: coordinator._recover_fixed_local_qualification()
        except BaseException as error:
            assert type(error) is expected
            if cut is not None: assert type(error.__cause__) is Cut
        else: raise AssertionError("no-operation recovery returned without classification")

# The real coordinator-held execution bridge reconstructs an ACTIVE,
# snapshot-free FS_SETTLED owner and routes it to the no-effect baseline abort;
# this is not merely behavior of the fake coordinator facade above.
reconstructed_owner = object(); reconstructed_tools = tuple(object() for _index in range(3))
reconstruction_events = []
reconstruction_journal = SimpleNamespace(
    record_snapshot_free_cleanup=lambda: reconstruction_events.append("projection") or "CLEANUP_ONLY")
reconstruction_lifecycle = SimpleNamespace(
    operation=reconstruction_journal, executables=None, static_custody=object(),
    network_owner=None, staged_runtime=None)
execution = coordinator.execution_bridge
with patch.object(execution.operation, "_durable_phase", return_value="FS_SETTLED"), \
     patch.object(execution.operation, "_network_records", return_value=[]), \
     patch.object(execution.preparation, "_reconstruct_fixed_executable_owner", return_value=object()), \
     patch.object(execution.process, "_claim_attested_executable", side_effect=reconstructed_tools), \
     patch.object(execution.nft_owner, "reopen_cleanup", return_value=reconstructed_owner):
    check(execution._reconstruct_execution_cleanup(
        coordinator._owners.execution, reconstruction_lifecycle) == "FS_SETTLED",
        "real execution reconstruction rejected incomplete baseline")
with patch.object(execution.operation, "_durable_phase", return_value="FS_SETTLED"), \
     patch.object(execution.operation, "_network_records", return_value=[]), \
     patch.object(execution.network, "_abort_incomplete_baseline",
                  side_effect=lambda journal: reconstruction_events.append(journal) or "FREE"):
    check(execution._remove_network(coordinator._owners.execution,
        reconstruction_lifecycle) == "CLEANUP_ONLY", "real coordinator omitted cleanup-only projection")
check(reconstruction_events == [reconstruction_journal, "projection"],
      "real coordinator repeated or changed baseline abort owner")

# NETWORK_ABSENT after a network-only setup abort settles share and containerd
# absence directly. No runtime preparation or reconstruction can be reached.
setup_phase = ["NETWORK_ABSENT"]
def setup_history():
    return {"phase": setup_phase[0], "runtime_prepared": (), "runtime_stage_intents": (),
            "runtime_staged": (), "daemon_retained": (), "daemon_outcomes": (),
            "launches": (), "runtime_ownership": (), "runtime_role_identities": (),
            "runtime_share_identities": (), "runtime_resumes": (), "intents": ()}
def settle_setup(_journal, target):
    setup_phase[0] = "SHARE_ABSENT" if target == "share" else "CONTAINERD_ABSENT"
    return {target: "absent"}
reconstruction_journal.runtime_recovery_history = setup_history
with patch.object(execution.operation, "_durable_phase", side_effect=lambda _journal: setup_phase[0]), \
     patch.object(execution.runtime, "_settle_setup_abort_absence", side_effect=settle_setup), \
     patch.object(execution.runtime, "_reconstruct_fixed_runtime",
                  side_effect=AssertionError("runtime reconstruction reached")), \
     patch.object(execution.preparation, "_claim_fixed_prepared_runtime",
                  side_effect=AssertionError("runtime preparation reached")), \
     patch.object(execution.operation, "_open_base_chain", return_value=SimpleNamespace(
                  components=(SimpleNamespace(node=object()),))), \
     patch.object(execution.fs, "_enumerate_stable",
                  return_value=SimpleNamespace(raw_names=())):
    check(execution._remove_share(coordinator._owners.execution,
        reconstruction_lifecycle) == {"share": "absent"}, "setup-abort share not settled")
    setup_phase[0] = "FIREWALL_ABSENT"
    current = execution._stop_containerd(coordinator._owners.execution,
                                         reconstruction_lifecycle)
    check(current == {"containerd": "absent"}, "setup-abort containerd not settled")

# Source shape keeps both production entries zero argument and recovery cannot
# name any work-opening method. Public openers and arbitrary receipts stay shut.
recovery_shell = (REMOTE / "recover-stage2-completion-remote.sh").read_text()
assert "except BaseException" not in recovery_shell
assert "except c.CoordinatorNoOperationPath" in recovery_shell
assert recovery_shell.count("recover_failed_preparation") == 1
source = (REMOTE / "completion_kata_coordinator.py").read_text()
tree = ast.parse(source)
functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
for name in ("_run_fixed_local_qualification", "_run_fixed_full_rehearsal",
             "_run_fixed_readiness_rehearsal", "_recover_fixed_local_qualification"):
    node = functions[name]
    assert not node.args.args and node.args.vararg is node.args.kwarg is None
for name in ("_run_fixed_full_rehearsal", "_run_fixed_readiness_rehearsal"):
    rehearsal = ast.get_source_segment(source, functions[name])
    assert "_run_cycle(" in rehearsal and ", False)" in rehearsal
    assert "_issue_cycle_receipt" not in rehearsal and "owner_evidence" not in rehearsal
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

#!/usr/bin/env python3
"""Exhaustive fake-only Slice B controller, custody, interruption, and replay matrix."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))

from completion_campaign_contracts import CYCLE_MODES, ControllerEventRecord, Event, Outcome, Uncertainty
from completion_campaign_controller import (
    APPROVAL_PHRASE,
    ApprovalDenied,
    CompletionCampaignController,
    ControllerError,
    FakeApproval,
    FakeCampaignPorts,
    InjectedCrash,
    RecoveryDenied,
)
from completion_campaign_state import HAPPY_PATH, CampaignStateError, reduce_campaign

# The reducer intentionally recomputes exact canonical hashes. Cache only in this
# exhaustive fake matrix so every record is still hashed exactly once.
_original_sha256 = ControllerEventRecord.sha256
_sha256_cache = {}
def _cached_sha256(record):
    if record not in _sha256_cache:
        _sha256_cache[record] = _original_sha256(record)
    return _sha256_cache[record]
ControllerEventRecord.sha256 = _cached_sha256


def require(condition, message="test assertion failed"):
    if not condition:
        raise AssertionError(message)


def expect(kind, function, *args):
    try:
        function(*args)
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


def grouped_action_counts(ports):
    grouped = {}
    for action, ordinal, mode in ports.calls:
        if action in ports.action_counts:
            key = (action, ordinal, mode)
            grouped[key] = grouped.get(key, 0) + 1
    return grouped


def assert_one_shot_effects(ports):
    grouped = grouped_action_counts(ports)
    require(all(count == 1 for count in grouped.values()), grouped)
    require(ports.maximum_active <= 1)


def failure_suffix(records):
    index = next(i for i, row in enumerate(records) if row.event is Event.FAILURE_RECORDED)
    return records[index + 1 :]


def assert_cleanup_only(ports):
    records = ports.records
    state = reduce_campaign(records)
    require(state.terminal and not state.success_possible and not state.success_eligible)
    suffix = failure_suffix(records)
    forbidden = {Event.CYCLE_OPENED, Event.PLAN_INTENT, Event.APPLY_INTENT, Event.REMOTE_INTENT}
    require(not any(row.event in forbidden for row in suffix))
    require(sum(row.event is Event.DESTROY_INTENT for row in suffix) <= 1)
    require(sum(row.event in {Event.ZERO_OBSERVATION_INTENT, Event.FINAL_ZERO_OBSERVATION_INTENT} for row in suffix) <= 1)
    require(sum(row.event is Event.DESTROY_SETTLED for row in suffix) <= 1)
    require(sum(row.event in {Event.ZERO_ACCEPTED, Event.FINAL_ZERO_ACCEPTED} for row in suffix) <= 1)
    assert_one_shot_effects(ports)


def happy_matrix():
    ports = FakeCampaignPorts(FakeApproval.valid("happy"))
    result = CompletionCampaignController(ports).run()
    require(result.status == "sealed" and result.terminal)
    require(result.uncertainty is Uncertainty.CLEAR)
    require(result.verdict is not None)
    require(result.verdict["version"] == "cogs.stage2-completion-fake-verdict/v1")
    require(result.verdict["production_publication_authorized"] is False)
    require(result.verdict["cycle_modes"] == [mode.value for mode in CYCLE_MODES])
    require(len(ports.records) == len(HAPPY_PATH) == 103)
    require(tuple((r.event, r.cycle_ordinal, r.cycle_mode) for r in ports.records) == HAPPY_PATH)
    require(ports.approval_consumed)
    require(ports.action_counts == {
        "plan": 7,
        "apply": 7,
        "running": 7,
        "remote": 7,
        "destroy": 7,
        "inventory": 8,
        "validate": 1,
    })
    assert_one_shot_effects(ports)
    modes = [mode for action, _, mode in ports.calls if action == "remote"]
    require(modes == ["full", *("readiness" for _ in range(6))])
    zero_records = [row for row in ports.records if row.event is Event.ZERO_ACCEPTED]
    final_zero = [row for row in ports.records if row.event is Event.FINAL_ZERO_ACCEPTED]
    require(len(zero_records) == 7 and len(final_zero) == 1)
    require(len({row.payload_sha256 for row in [*zero_records, *final_zero]}) == 8)
    expect(ApprovalDenied, CompletionCampaignController(ports).run)
    expect(RecoveryDenied, CompletionCampaignController(ports).recover)


def admission_matrix():
    valid = FakeApproval.valid("admission")
    invalid = (
        replace(valid, version="wrong"),
        replace(valid, batch_commitment="0" * 64),
        replace(valid, phrase="old-phrase"),
        replace(valid, not_before_wall_ns=2_000_000),
        replace(valid, expires_wall_ns=1_000_000),
        replace(valid, one_attempt=False),
        replace(valid, signatures_valid=False),
        replace(valid, source_clean=False),
        replace(valid, modes=("full",) * 7),
        replace(valid, modes=valid.modes[:-1]),
    )
    for approval in invalid:
        ports = FakeCampaignPorts(approval)
        expect(ApprovalDenied, CompletionCampaignController(ports).run)
        require(not ports.approval_consumed and ports.records == () and ports.calls == [])
    require(valid.phrase == APPROVAL_PHRASE)
    expect(ApprovalDenied, FakeCampaignPorts, object())
    expect(TypeError, type, "OpenPorts", (FakeCampaignPorts,), {})
    ports = FakeCampaignPorts(valid)
    expect(RecoveryDenied, CompletionCampaignController(ports).recover)

    raced = FakeCampaignPorts(FakeApproval.valid("race"), faults={"after:000001:BATCH_ADMITTED": "failure"})
    barrier = threading.Barrier(2)
    outcomes = []
    def invoke():
        barrier.wait()
        try:
            outcomes.append(CompletionCampaignController(raced).run().status)
        except ApprovalDenied:
            outcomes.append("denied")
    threads = [threading.Thread(target=invoke) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    require(sorted(outcomes) == ["denied", "terminal-failure"])
    require(sum(action == "admit" for action, _, _ in raced.calls) == 1)
    assert_cleanup_only(raced)


def action_failure_signal_matrix():
    points = []
    for ordinal in range(1, 8):
        points.extend((kind, ordinal) for kind in ("plan", "apply", "running", "remote", "destroy", "inventory"))
    points.extend((("inventory", None), ("validate", None)))
    for fault in ("failure", "uncertain", "INT", "TERM"):
        for kind, ordinal in points:
            suffix = "final" if ordinal is None else f"{ordinal:02d}"
            ports = FakeCampaignPorts(
                FakeApproval.valid(f"action-{fault}-{kind}-{suffix}"),
                faults={f"call:{kind}:{suffix}": fault},
            )
            result = CompletionCampaignController(ports).run()
            require(result.verdict is None and result.terminal)
            assert_cleanup_only(ports)
            sticky = fault != "failure" or kind in {"destroy", "inventory"}
            require(result.uncertainty is (Uncertainty.STICKY if sticky else Uncertainty.CLEAR))
            if ordinal is not None:
                later = [row for row in ports.records if row.event is Event.CYCLE_OPENED and (row.cycle_ordinal or 0) > ordinal]
                require(not later)


def event_failure_signal_matrix():
    # Admission is one atomic consumption/publication step; only its durable-after edge is injectable.
    edges = [("after", 1, Event.BATCH_ADMITTED)]
    edges.extend((edge, sequence, event) for sequence, (event, _, _) in enumerate(HAPPY_PATH[1:], 2) for edge in ("before", "after"))
    for fault in ("failure", "INT", "TERM"):
        for edge, sequence, event in edges:
            ports = FakeCampaignPorts(
                FakeApproval.valid(f"edge-{fault}-{edge}-{sequence}"),
                faults={f"{edge}:{sequence:06d}:{event.value}": fault},
            )
            result = CompletionCampaignController(ports).run()
            if sequence == len(HAPPY_PATH) and edge == "after":
                require(result.status == "sealed" and result.verdict is None)
                continue
            require(result.verdict is None and result.terminal)
            assert_cleanup_only(ports)
            if fault != "failure":
                require(result.uncertainty is Uncertainty.STICKY)
            seen_sticky = False
            for row in ports.records:
                seen_sticky = seen_sticky or row.uncertainty is Uncertainty.STICKY
                if seen_sticky:
                    require(row.uncertainty is Uncertainty.STICKY)


def crash_recovery_matrix():
    edges = [("after", 1, Event.BATCH_ADMITTED)]
    edges.extend((edge, sequence, event) for sequence, (event, _, _) in enumerate(HAPPY_PATH[1:], 2) for edge in ("before", "after"))
    for edge, sequence, event in edges:
        ports = FakeCampaignPorts(
            FakeApproval.valid(f"crash-{edge}-{sequence}"),
            faults={f"{edge}:{sequence:06d}:{event.value}": "crash"},
        )
        expect(InjectedCrash, CompletionCampaignController(ports).run)
        controller = CompletionCampaignController(ports)
        if reduce_campaign(ports.records).terminal:
            require(ports.records[-1].event is Event.SEALED)
            expect(RecoveryDenied, controller.recover)
            continue
        result = controller.recover()
        require(result.verdict is None and result.terminal and result.uncertainty is Uncertainty.STICKY)
        assert_cleanup_only(ports)
        expect(ApprovalDenied, controller.run)
        expect(RecoveryDenied, controller.recover)

    points = []
    for ordinal in range(1, 8):
        points.extend((kind, ordinal) for kind in ("plan", "apply", "running", "remote", "destroy", "inventory"))
    points.extend((("inventory", None), ("validate", None)))
    for kind, ordinal in points:
        suffix = "final" if ordinal is None else f"{ordinal:02d}"
        ports = FakeCampaignPorts(
            FakeApproval.valid(f"call-crash-{kind}-{suffix}"),
            faults={f"call:{kind}:{suffix}": "crash"},
        )
        expect(InjectedCrash, CompletionCampaignController(ports).run)
        result = CompletionCampaignController(ports).recover()
        require(result.verdict is None and result.uncertainty is Uncertainty.STICKY)
        assert_cleanup_only(ports)


def interrupted_cleanup_matrix():
    # Crash after apply intent, then crash after recovery's destroy intent.
    ports = FakeCampaignPorts(
        FakeApproval.valid("recovery-destroy-intent"),
        faults={
            "after:000005:APPLY_INTENT": "crash",
            "after:000007:DESTROY_INTENT": "crash",
        },
    )
    controller = CompletionCampaignController(ports)
    expect(InjectedCrash, controller.run)
    expect(InjectedCrash, controller.recover)
    require(ports.action_counts["destroy"] == 0)
    result = controller.recover()
    require(result.uncertainty is Uncertainty.STICKY and result.verdict is None)
    require(ports.action_counts["destroy"] == 0, "durable destroy intent was replayed")
    require(ports.action_counts["inventory"] == 1)
    assert_cleanup_only(ports)

    # Crash after the sole destroy invocation but before its outcome is durable.
    ports = FakeCampaignPorts(
        FakeApproval.valid("recovery-destroy-outcome"),
        faults={
            "after:000005:APPLY_INTENT": "crash",
            "before:000008:DESTROY_SETTLED": "crash",
        },
    )
    controller = CompletionCampaignController(ports)
    expect(InjectedCrash, controller.run)
    expect(InjectedCrash, controller.recover)
    require(ports.action_counts["destroy"] == 1)
    result = controller.recover()
    require(result.uncertainty is Uncertainty.STICKY)
    require(ports.action_counts["destroy"] == 1, "destroy invocation was replayed")
    assert_cleanup_only(ports)

    # Crash after the observation intent forbids a replacement observation.
    ports = FakeCampaignPorts(
        FakeApproval.valid("recovery-observation-intent"),
        faults={
            "after:000003:PLAN_INTENT": "crash",
            "after:000005:ZERO_OBSERVATION_INTENT": "crash",
        },
    )
    controller = CompletionCampaignController(ports)
    expect(InjectedCrash, controller.run)
    expect(InjectedCrash, controller.recover)
    require(ports.action_counts["inventory"] == 0)
    result = controller.recover()
    require(result.uncertainty is Uncertainty.STICKY)
    require(ports.action_counts["inventory"] == 0, "observation intent was replayed")
    assert_cleanup_only(ports)


def receipt_and_replay_matrix():
    for kind in ("plan", "apply", "running", "remote", "destroy", "inventory"):
        ports = FakeCampaignPorts(
            FakeApproval.valid(f"receipt-replay-{kind}"),
            receipt_replays={(kind, 2): 1},
        )
        result = CompletionCampaignController(ports).run()
        require(result.verdict is None)
        assert_cleanup_only(ports)
        require(not any(row.event is Event.CYCLE_OPENED and row.cycle_ordinal == 3 for row in ports.records))

    ports = FakeCampaignPorts(FakeApproval.valid("publication-order"))
    ports.admit()
    expect(
        CampaignStateError,
        ports.publish,
        Event.APPLY_INTENT,
        1,
        CYCLE_MODES[0],
        Outcome.INTENDED,
        {"reordered": True},
    )
    require(len(ports.records) == 1)
    expect(ApprovalDenied, CompletionCampaignController(ports).run)
    result = CompletionCampaignController(ports).recover()
    require(result.verdict is None and result.uncertainty is Uncertainty.STICKY)
    assert_cleanup_only(ports)


def static_isolation_matrix():
    source = (ROOT / "deploy/aws-feasibility/completion_campaign_controller.py").read_text()
    for forbidden in (
        "import subprocess",
        "import socket",
        "import boto",
        "import requests",
        "import urllib",
        "os.system(",
        "terraform",
        "opentofu",
        "access_key",
        "secret_key",
    ):
        require(forbidden not in source.lower(), forbidden)
    require("production_publication_authorized\": True" not in source)
    require("def retry" not in source and "def resume" not in source)


def main():
    happy_matrix()
    admission_matrix()
    action_failure_signal_matrix()
    event_failure_signal_matrix()
    crash_recovery_matrix()
    interrupted_cleanup_matrix()
    receipt_and_replay_matrix()
    static_isolation_matrix()
    print("fake-only completion campaign Slice B exhaustive matrix passed")


if __name__ == "__main__":
    main()

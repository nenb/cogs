#!/usr/bin/env python3
"""Pure seven-cycle completion campaign reducer.

The reducer classifies immutable typed records.  It performs no I/O and exposes no
mode, cycle-count, retry, resume, command, provider, or callback selector.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from completion_campaign_contracts import (
    CYCLE_MODES,
    TERMINAL_EVENTS,
    ZERO_SHA256,
    CampaignContractError,
    ControllerEventRecord,
    CycleMode,
    Event,
    Outcome,
    Uncertainty,
    outcome_introduces_uncertainty,
    required_outcomes,
)


class CampaignStateError(ValueError):
    pass


_CYCLE_ORDER = (
    Event.CYCLE_OPENED,
    Event.PLAN_INTENT,
    Event.PLAN_ACCEPTED,
    Event.APPLY_INTENT,
    Event.APPLY_ACCEPTED,
    Event.RUNNING_OBSERVED,
    Event.REMOTE_INTENT,
    Event.REMOTE_ACCEPTED,
    Event.PRE_DESTROY_SEALED,
    Event.DESTROY_INTENT,
    Event.DESTROY_SETTLED,
    Event.ZERO_OBSERVATION_INTENT,
    Event.ZERO_ACCEPTED,
    Event.CYCLE_SEALED,
)


def _happy_path() -> tuple[tuple[Event, int | None, CycleMode | None], ...]:
    rows: list[tuple[Event, int | None, CycleMode | None]] = [(Event.BATCH_ADMITTED, None, None)]
    for ordinal, mode in enumerate(CYCLE_MODES, 1):
        rows.extend((event, ordinal, mode) for event in _CYCLE_ORDER)
    rows.extend(
        (
            (Event.FINAL_ZERO_OBSERVATION_INTENT, None, None),
            (Event.FINAL_ZERO_ACCEPTED, None, None),
            (Event.TERMINAL_CANDIDATE_VALIDATED, None, None),
            (Event.SEALED, None, None),
        )
    )
    return tuple(rows)


HAPPY_PATH = _happy_path()


@dataclass(frozen=True, slots=True)
class CampaignState:
    record_count: int
    status: str
    next_event: Event | None
    next_cycle_ordinal: int | None
    next_cycle_mode: CycleMode | None
    success_possible: bool
    success_eligible: bool
    failure_recorded: bool
    uncertainty: Uncertainty
    terminal: bool

    @property
    def retry_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class _CleanupStep:
    event: Event
    cycle_ordinal: int | None
    cycle_mode: CycleMode | None


def _fail(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignStateError(message)


def _active_cycle(records: Sequence[ControllerEventRecord]) -> tuple[int, CycleMode] | None:
    active: tuple[int, CycleMode] | None = None
    for record in records:
        if record.event is Event.CYCLE_OPENED:
            _fail(record.cycle_ordinal is not None and record.cycle_mode is not None, "opened cycle lacks binding")
            _fail(active is None, "cycle overlap")
            active = (record.cycle_ordinal, record.cycle_mode)
        elif record.event is Event.CYCLE_SEALED:
            _fail(active == (record.cycle_ordinal, record.cycle_mode), "sealed cycle binding mismatch")
            active = None
    return active


def _has(records: Sequence[ControllerEventRecord], event: Event, ordinal: int | None = None) -> bool:
    return any(record.event is event and (ordinal is None or record.cycle_ordinal == ordinal) for record in records)


def _cleanup_steps(prefix: Sequence[ControllerEventRecord]) -> tuple[_CleanupStep, ...]:
    active = _active_cycle(prefix)
    steps: list[_CleanupStep] = []
    if active is None:
        if not _has(prefix, Event.FINAL_ZERO_ACCEPTED):
            if not _has(prefix, Event.FINAL_ZERO_OBSERVATION_INTENT):
                steps.append(_CleanupStep(Event.FINAL_ZERO_OBSERVATION_INTENT, None, None))
            steps.append(_CleanupStep(Event.FINAL_ZERO_ACCEPTED, None, None))
        return tuple(steps)

    ordinal, mode = active
    if _has(prefix, Event.ZERO_ACCEPTED, ordinal):
        return ()
    if _has(prefix, Event.APPLY_INTENT, ordinal) and not _has(prefix, Event.DESTROY_SETTLED, ordinal):
        if not _has(prefix, Event.DESTROY_INTENT, ordinal):
            steps.append(_CleanupStep(Event.DESTROY_INTENT, ordinal, mode))
        steps.append(_CleanupStep(Event.DESTROY_SETTLED, ordinal, mode))
    if not _has(prefix, Event.ZERO_OBSERVATION_INTENT, ordinal):
        steps.append(_CleanupStep(Event.ZERO_OBSERVATION_INTENT, ordinal, mode))
    steps.append(_CleanupStep(Event.ZERO_ACCEPTED, ordinal, mode))
    return tuple(steps)


def _check_common(records: Sequence[ControllerEventRecord]) -> None:
    _fail(type(records) is tuple, "record sequence must be an immutable plain tuple")
    batch: str | None = None
    prior = ZERO_SHA256
    prior_monotonic = -1
    prior_wall = -1
    payloads: set[str] = set()
    record_hashes: set[str] = set()
    for index, record in enumerate(records, 1):
        _fail(type(record) is ControllerEventRecord, "record type is not closed")
        _fail(record.sequence == index, "record sequence gap or duplicate")
        if batch is None:
            batch = record.batch_commitment
            _fail(batch != ZERO_SHA256, "zero batch commitment rejected")
        _fail(record.batch_commitment == batch, "cross-batch record")
        _fail(record.prior_record_sha256 == prior, "prior-record hash chain mismatch")
        _fail(record.monotonic_observation_ns >= prior_monotonic, "monotonic observation regressed")
        _fail(record.wall_observation_unix_ns >= prior_wall, "wall observation regressed")
        _fail(record.payload_sha256 not in payloads, "payload digest replay")
        payloads.add(record.payload_sha256)
        digest = record.sha256()
        _fail(digest not in record_hashes, "record digest replay")
        record_hashes.add(digest)
        prior = digest
        prior_monotonic = record.monotonic_observation_ns
        prior_wall = record.wall_observation_unix_ns


def _check_binding(record: ControllerEventRecord, ordinal: int | None, mode: CycleMode | None) -> None:
    _fail(record.cycle_ordinal == ordinal and record.cycle_mode is mode, "event cycle binding mismatch")


def _check_uncertainty(record: ControllerEventRecord, before: Uncertainty) -> Uncertainty:
    introduced = outcome_introduces_uncertainty(record.event, record.outcome)
    after = Uncertainty.STICKY if before is Uncertainty.STICKY or introduced else Uncertainty.CLEAR
    _fail(record.uncertainty is after, "uncertainty is not an exact sticky projection")
    return after


def _normal_prefix(records: Sequence[ControllerEventRecord]) -> tuple[int, int | None]:
    """Return (happy index, failure index), validating the prefix before failure."""
    happy_index = 0
    failure_index: int | None = None
    uncertainty = Uncertainty.CLEAR
    for index, record in enumerate(records):
        if failure_index is not None:
            break
        _fail(happy_index < len(HAPPY_PATH), "record after success terminal")
        expected_event, ordinal, mode = HAPPY_PATH[happy_index]
        if record.event is Event.FAILURE_RECORDED:
            _fail(happy_index > 0, "failure cannot precede batch admission")
            active = _active_cycle(records[:index])
            expected_binding = (None, None) if active is None else active
            _check_binding(record, *expected_binding)
            _fail(record.outcome in required_outcomes(Event.FAILURE_RECORDED), "failure outcome mismatch")
            uncertainty = _check_uncertainty(record, uncertainty)
            failure_index = index
            continue
        _fail(record.event is expected_event, "normal event skip, reorder, retry, or replay")
        _check_binding(record, ordinal, mode)
        _fail(record.outcome in required_outcomes(record.event), "normal event outcome mismatch")
        uncertainty = _check_uncertainty(record, uncertainty)
        _fail(uncertainty is Uncertainty.CLEAR, "uncertainty entered normal path")
        happy_index += 1
    return happy_index, failure_index


def reduce_campaign(records: Sequence[ControllerEventRecord]) -> CampaignState:
    """Validate and reduce a complete record prefix to its one required next event."""
    _check_common(records)
    happy_index, failure_index = _normal_prefix(records)
    if failure_index is None:
        if happy_index == len(HAPPY_PATH):
            return CampaignState(
                record_count=len(records),
                status="sealed",
                next_event=None,
                next_cycle_ordinal=None,
                next_cycle_mode=None,
                success_possible=True,
                success_eligible=True,
                failure_recorded=False,
                uncertainty=Uncertainty.CLEAR,
                terminal=True,
            )
        event, ordinal, mode = HAPPY_PATH[happy_index]
        return CampaignState(
            record_count=len(records),
            status="normal",
            next_event=event,
            next_cycle_ordinal=ordinal,
            next_cycle_mode=mode,
            success_possible=True,
            success_eligible=False,
            failure_recorded=False,
            uncertainty=Uncertainty.CLEAR,
            terminal=False,
        )

    failure = records[failure_index]
    uncertainty = failure.uncertainty
    prefix = records[:failure_index]
    steps = _cleanup_steps(prefix)
    suffix = records[failure_index + 1 :]
    _fail(len(suffix) <= len(steps) + 1, "record after failure terminal")
    for index, record in enumerate(suffix):
        if index < len(steps):
            step = steps[index]
            _fail(record.event is step.event, "cleanup-only suffix violated")
            _check_binding(record, step.cycle_ordinal, step.cycle_mode)
            _fail(record.outcome in required_outcomes(record.event, cleanup=True), "cleanup outcome mismatch")
            uncertainty = _check_uncertainty(record, uncertainty)
            continue
        terminal = Event.TERMINAL_UNCERTAIN_SEALED if uncertainty is Uncertainty.STICKY else Event.TERMINAL_FAILURE_SEALED
        _fail(record.event is terminal, "wrong failure terminal")
        _check_binding(record, None, None)
        _fail(record.outcome in required_outcomes(record.event), "terminal outcome mismatch")
        uncertainty = _check_uncertainty(record, uncertainty)

    if len(suffix) < len(steps):
        step = steps[len(suffix)]
        return CampaignState(
            record_count=len(records),
            status="cleanup",
            next_event=step.event,
            next_cycle_ordinal=step.cycle_ordinal,
            next_cycle_mode=step.cycle_mode,
            success_possible=False,
            success_eligible=False,
            failure_recorded=True,
            uncertainty=uncertainty,
            terminal=False,
        )
    if len(suffix) == len(steps):
        terminal = Event.TERMINAL_UNCERTAIN_SEALED if uncertainty is Uncertainty.STICKY else Event.TERMINAL_FAILURE_SEALED
        return CampaignState(
            record_count=len(records),
            status="cleanup",
            next_event=terminal,
            next_cycle_ordinal=None,
            next_cycle_mode=None,
            success_possible=False,
            success_eligible=False,
            failure_recorded=True,
            uncertainty=uncertainty,
            terminal=False,
        )
    return CampaignState(
        record_count=len(records),
        status="terminal-uncertain" if uncertainty is Uncertainty.STICKY else "terminal-failure",
        next_event=None,
        next_cycle_ordinal=None,
        next_cycle_mode=None,
        success_possible=False,
        success_eligible=False,
        failure_recorded=True,
        uncertainty=uncertainty,
        terminal=True,
    )


def append_record(
    records: Sequence[ControllerEventRecord], record: ControllerEventRecord
) -> tuple[ControllerEventRecord, ...]:
    """Purely append one legal normal/failure/cleanup record or reject it."""
    state = reduce_campaign(records)
    _fail(not state.terminal, "terminal state has no outgoing transition")
    if state.status == "normal" and record.event is Event.FAILURE_RECORDED:
        pass
    else:
        _fail(record.event is state.next_event, "record is not the required next event")
        _check_binding(record, state.next_cycle_ordinal, state.next_cycle_mode)
    candidate = (*records, record)
    reduce_campaign(candidate)
    return candidate


def is_terminal_event(event: Event) -> bool:
    return event in TERMINAL_EVENTS


# Import-time assertions make the fixed shape reviewable and non-configurable.
assert len(CYCLE_MODES) == 7
assert CYCLE_MODES == (CycleMode.FULL, *(CycleMode.READINESS for _ in range(6)))
assert len(HAPPY_PATH) == 103

#!/usr/bin/env python3
"""Closed immutable contracts for the fake-only completion campaign reducer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Mapping

import completion_campaign_codec as codec

CONTROLLER_EVENT_VERSION = "cogs.aws-stage2-completion/controller-event/v1"
ZERO_SHA256 = "0" * 64
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
MAX_SEQUENCE = 256
MAX_OBSERVATION_NS = 2**64 - 1


class CampaignContractError(ValueError):
    pass


class CycleMode(str, Enum):
    FULL = "full"
    READINESS = "readiness"


CYCLE_MODES = (
    CycleMode.FULL,
    CycleMode.READINESS,
    CycleMode.READINESS,
    CycleMode.READINESS,
    CycleMode.READINESS,
    CycleMode.READINESS,
    CycleMode.READINESS,
)


class Event(str, Enum):
    BATCH_ADMITTED = "BATCH_ADMITTED"
    CYCLE_OPENED = "CYCLE_OPENED"
    PLAN_INTENT = "PLAN_INTENT"
    PLAN_ACCEPTED = "PLAN_ACCEPTED"
    APPLY_INTENT = "APPLY_INTENT"
    APPLY_ACCEPTED = "APPLY_ACCEPTED"
    RUNNING_OBSERVED = "RUNNING_OBSERVED"
    REMOTE_INTENT = "REMOTE_INTENT"
    REMOTE_ACCEPTED = "REMOTE_ACCEPTED"
    PRE_DESTROY_SEALED = "PRE_DESTROY_SEALED"
    DESTROY_INTENT = "DESTROY_INTENT"
    DESTROY_SETTLED = "DESTROY_SETTLED"
    ZERO_OBSERVATION_INTENT = "ZERO_OBSERVATION_INTENT"
    ZERO_ACCEPTED = "ZERO_ACCEPTED"
    CYCLE_SEALED = "CYCLE_SEALED"
    FINAL_ZERO_OBSERVATION_INTENT = "FINAL_ZERO_OBSERVATION_INTENT"
    FINAL_ZERO_ACCEPTED = "FINAL_ZERO_ACCEPTED"
    TERMINAL_CANDIDATE_VALIDATED = "TERMINAL_CANDIDATE_VALIDATED"
    SEALED = "SEALED"
    FAILURE_RECORDED = "FAILURE_RECORDED"
    TERMINAL_FAILURE_SEALED = "TERMINAL_FAILURE_SEALED"
    TERMINAL_UNCERTAIN_SEALED = "TERMINAL_UNCERTAIN_SEALED"


class Outcome(str, Enum):
    INTENDED = "intended"
    ACCEPTED = "accepted"
    OBSERVED = "observed"
    SEALED = "sealed"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    ZERO = "zero"
    NONZERO = "nonzero"


class Uncertainty(str, Enum):
    CLEAR = "clear"
    STICKY = "sticky"


INTENT_EVENTS = frozenset(
    {
        Event.PLAN_INTENT,
        Event.APPLY_INTENT,
        Event.REMOTE_INTENT,
        Event.DESTROY_INTENT,
        Event.ZERO_OBSERVATION_INTENT,
        Event.FINAL_ZERO_OBSERVATION_INTENT,
    }
)
CYCLE_EVENTS = frozenset(
    {
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
    }
)
TERMINAL_EVENTS = frozenset(
    {Event.SEALED, Event.TERMINAL_FAILURE_SEALED, Event.TERMINAL_UNCERTAIN_SEALED}
)
FINAL_EVENTS = frozenset(
    {
        Event.FINAL_ZERO_OBSERVATION_INTENT,
        Event.FINAL_ZERO_ACCEPTED,
        Event.TERMINAL_CANDIDATE_VALIDATED,
        *TERMINAL_EVENTS,
    }
)
_UNCERTAIN_OUTCOMES = frozenset({Outcome.UNCERTAIN, Outcome.NONZERO})


def required_outcomes(event: Event, cleanup: bool = False) -> frozenset[Outcome]:
    if event in INTENT_EVENTS:
        return frozenset({Outcome.INTENDED})
    if event in {Event.BATCH_ADMITTED, Event.CYCLE_OPENED, Event.PLAN_ACCEPTED, Event.APPLY_ACCEPTED, Event.REMOTE_ACCEPTED}:
        return frozenset({Outcome.ACCEPTED})
    if event is Event.RUNNING_OBSERVED:
        return frozenset({Outcome.OBSERVED})
    if event in {
        Event.PRE_DESTROY_SEALED,
        Event.CYCLE_SEALED,
        Event.TERMINAL_CANDIDATE_VALIDATED,
        Event.SEALED,
        Event.TERMINAL_FAILURE_SEALED,
        Event.TERMINAL_UNCERTAIN_SEALED,
    }:
        return frozenset({Outcome.SEALED})
    if event is Event.FAILURE_RECORDED:
        return frozenset({Outcome.FAILED, Outcome.UNCERTAIN})
    if event is Event.DESTROY_SETTLED:
        return frozenset({Outcome.ACCEPTED, Outcome.FAILED, Outcome.UNCERTAIN}) if cleanup else frozenset({Outcome.ACCEPTED})
    if event in {Event.ZERO_ACCEPTED, Event.FINAL_ZERO_ACCEPTED}:
        return frozenset({Outcome.ZERO, Outcome.NONZERO, Outcome.UNCERTAIN}) if cleanup else frozenset({Outcome.ZERO})
    raise CampaignContractError("event has no closed outcome contract")


@dataclass(frozen=True, slots=True)
class ControllerEventRecord:
    version: str
    batch_commitment: str
    sequence: int
    event: Event
    cycle_ordinal: int | None
    cycle_mode: CycleMode | None
    prior_record_sha256: str
    payload_sha256: str
    monotonic_observation_ns: int
    wall_observation_unix_ns: int
    outcome: Outcome
    uncertainty: Uncertainty

    def __post_init__(self) -> None:
        if type(self.version) is not str or self.version != CONTROLLER_EVENT_VERSION:
            raise CampaignContractError("controller-event version mismatch")
        for label, value in (
            ("batch commitment", self.batch_commitment),
            ("prior record digest", self.prior_record_sha256),
            ("payload digest", self.payload_sha256),
        ):
            if type(value) is not str or DIGEST_PATTERN.fullmatch(value) is None:
                raise CampaignContractError(f"{label} mismatch")
        if type(self.sequence) is not int or not 1 <= self.sequence <= MAX_SEQUENCE:
            raise CampaignContractError("sequence bound")
        if type(self.event) is not Event or type(self.outcome) is not Outcome or type(self.uncertainty) is not Uncertainty:
            raise CampaignContractError("open enum value rejected")
        if self.outcome not in required_outcomes(self.event, cleanup=True):
            raise CampaignContractError("event outcome contract mismatch")
        if outcome_introduces_uncertainty(self.event, self.outcome) and self.uncertainty is not Uncertainty.STICKY:
            raise CampaignContractError("uncertain outcome is not sticky")
        if self.event is Event.TERMINAL_UNCERTAIN_SEALED and self.uncertainty is not Uncertainty.STICKY:
            raise CampaignContractError("uncertain terminal is not sticky")
        if self.event in {Event.SEALED, Event.TERMINAL_FAILURE_SEALED} and self.uncertainty is not Uncertainty.CLEAR:
            raise CampaignContractError("clear terminal has uncertainty")
        for value in (self.monotonic_observation_ns, self.wall_observation_unix_ns):
            if type(value) is not int or not 0 <= value <= MAX_OBSERVATION_NS:
                raise CampaignContractError("observation bound")
        if self.event in CYCLE_EVENTS:
            if type(self.cycle_ordinal) is not int or not 1 <= self.cycle_ordinal <= len(CYCLE_MODES):
                raise CampaignContractError("cycle ordinal required")
            expected = CYCLE_MODES[self.cycle_ordinal - 1]
            if type(self.cycle_mode) is not CycleMode or self.cycle_mode is not expected:
                raise CampaignContractError("fixed cycle mode mismatch")
        elif self.event is Event.FAILURE_RECORDED:
            if self.cycle_ordinal is None:
                if self.cycle_mode is not None:
                    raise CampaignContractError("unbound failure has a mode")
            else:
                if type(self.cycle_ordinal) is not int or not 1 <= self.cycle_ordinal <= len(CYCLE_MODES):
                    raise CampaignContractError("failure cycle ordinal mismatch")
                if type(self.cycle_mode) is not CycleMode or self.cycle_mode is not CYCLE_MODES[self.cycle_ordinal - 1]:
                    raise CampaignContractError("failure cycle mode mismatch")
        elif self.cycle_ordinal is not None or self.cycle_mode is not None:
            raise CampaignContractError("non-cycle event has cycle binding")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "batch_commitment": self.batch_commitment,
            "sequence": self.sequence,
            "event": self.event.value,
            "cycle_ordinal": self.cycle_ordinal,
            "cycle_mode": None if self.cycle_mode is None else self.cycle_mode.value,
            "prior_record_sha256": self.prior_record_sha256,
            "payload_sha256": self.payload_sha256,
            "monotonic_observation_ns": self.monotonic_observation_ns,
            "wall_observation_unix_ns": self.wall_observation_unix_ns,
            "outcome": self.outcome.value,
            "uncertainty": self.uncertainty.value,
        }

    def canonical_bytes(self) -> bytes:
        return codec.canonical_bytes(self.as_dict())

    def sha256(self) -> str:
        return codec.sha256_hex(self.canonical_bytes())


_RECORD_KEYS = frozenset(
    {
        "version",
        "batch_commitment",
        "sequence",
        "event",
        "cycle_ordinal",
        "cycle_mode",
        "prior_record_sha256",
        "payload_sha256",
        "monotonic_observation_ns",
        "wall_observation_unix_ns",
        "outcome",
        "uncertainty",
    }
)


def record_from_mapping(value: Mapping[str, Any]) -> ControllerEventRecord:
    """Construct only from a snapshotted plain mapping with an exact key set."""
    if type(value) is not dict or frozenset(value) != _RECORD_KEYS:
        raise CampaignContractError("controller-event key set mismatch")
    try:
        event = Event(value["event"])
        outcome = Outcome(value["outcome"])
        uncertainty = Uncertainty(value["uncertainty"])
        mode_value = value["cycle_mode"]
        mode = None if mode_value is None else CycleMode(mode_value)
    except (ValueError, TypeError) as error:
        raise CampaignContractError("controller-event enum mismatch") from error
    return ControllerEventRecord(
        version=value["version"],
        batch_commitment=value["batch_commitment"],
        sequence=value["sequence"],
        event=event,
        cycle_ordinal=value["cycle_ordinal"],
        cycle_mode=mode,
        prior_record_sha256=value["prior_record_sha256"],
        payload_sha256=value["payload_sha256"],
        monotonic_observation_ns=value["monotonic_observation_ns"],
        wall_observation_unix_ns=value["wall_observation_unix_ns"],
        outcome=outcome,
        uncertainty=uncertainty,
    )


def record_from_canonical_bytes(raw: bytes) -> ControllerEventRecord:
    value = codec.load_canonical_bytes(raw)
    if type(value) is not dict:
        raise CampaignContractError("controller-event must be an object")
    return record_from_mapping(value)


def new_record(
    *,
    batch_commitment: str,
    sequence: int,
    event: Event,
    prior_record_sha256: str,
    payload_sha256: str,
    monotonic_observation_ns: int,
    wall_observation_unix_ns: int,
    outcome: Outcome,
    uncertainty: Uncertainty,
    cycle_ordinal: int | None = None,
    cycle_mode: CycleMode | None = None,
) -> ControllerEventRecord:
    return ControllerEventRecord(
        version=CONTROLLER_EVENT_VERSION,
        batch_commitment=batch_commitment,
        sequence=sequence,
        event=event,
        cycle_ordinal=cycle_ordinal,
        cycle_mode=cycle_mode,
        prior_record_sha256=prior_record_sha256,
        payload_sha256=payload_sha256,
        monotonic_observation_ns=monotonic_observation_ns,
        wall_observation_unix_ns=wall_observation_unix_ns,
        outcome=outcome,
        uncertainty=uncertainty,
    )


def outcome_introduces_uncertainty(event: Event, outcome: Outcome) -> bool:
    return outcome in _UNCERTAIN_OUTCOMES or (event is Event.DESTROY_SETTLED and outcome is Outcome.FAILED)

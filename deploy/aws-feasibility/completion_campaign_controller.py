#!/usr/bin/env python3
"""Fake-only one-shot custody and controller over sealed in-memory ports."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import threading
from typing import Any

import completion_campaign_codec as codec
from completion_campaign_contracts import (
    CYCLE_MODES,
    ZERO_SHA256,
    ControllerEventRecord,
    CycleMode,
    Event,
    Outcome,
    Uncertainty,
    new_record,
)
from completion_campaign_state import CampaignStateError, append_record, reduce_campaign

FAKE_APPROVAL_VERSION = "cogs.stage2-completion-fake-approval/v1"
FAKE_PAYLOAD_VERSION = "cogs.stage2-completion-fake-payload/v1"
FAKE_VERDICT_VERSION = "cogs.stage2-completion-fake-verdict/v1"
APPROVAL_PHRASE = "run-seven-sequential-stage2-completion-launches"


class ControllerError(RuntimeError):
    pass

class ApprovalDenied(ControllerError):
    pass

class RecoveryDenied(ControllerError):
    pass

class InjectedFailure(ControllerError):
    pass

class InjectedUncertainty(InjectedFailure):
    pass

class InjectedSignal(InjectedUncertainty):
    pass

class InjectedCrash(BaseException):
    pass

@dataclass(frozen=True, slots=True)
class FakeApproval:
    version: str
    batch_commitment: str
    phrase: str
    not_before_wall_ns: int
    expires_wall_ns: int
    one_attempt: bool
    signatures_valid: bool
    source_clean: bool
    modes: tuple[str, ...]

    @staticmethod
    def valid(batch_label: str = "batch") -> "FakeApproval":
        return FakeApproval(
            FAKE_APPROVAL_VERSION,
            hashlib.sha256(f"fake:{batch_label}".encode("ascii")).hexdigest(),
            APPROVAL_PHRASE,
            1,
            2**63,
            True,
            True,
            True,
            tuple(mode.value for mode in CYCLE_MODES),
        )

@dataclass(frozen=True, slots=True)
class ControllerResult:
    status: str
    terminal: bool
    uncertainty: Uncertainty
    verdict: dict[str, Any] | None

_FAULTS = {
    "failure": InjectedFailure,
    "uncertain": InjectedUncertainty,
    "INT": InjectedSignal,
    "TERM": InjectedSignal,
    "crash": InjectedCrash,
}
_ACTIONS = {"plan", "apply", "running", "remote", "destroy", "inventory", "validate"}

class FakeCampaignPorts:
    """Final in-memory fake. It has no command, filesystem, or network adapter."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("fake campaign ports are sealed")

    def __init__(
        self,
        approval: FakeApproval,
        *,
        faults: dict[str, str] | None = None,
        receipt_replays: dict[tuple[str, int], int] | None = None,
    ) -> None:
        if type(approval) is not FakeApproval:
            raise ApprovalDenied("approval type is not sealed")
        self.approval = approval
        self.faults = dict(faults or {})
        self.receipt_replays = dict(receipt_replays or {})
        self._records: tuple[ControllerEventRecord, ...] = ()
        self._payloads: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._consumed = False
        self._mono = 0
        self._wall = 1_000_000
        self._active = False
        self.maximum_active = 0
        self.calls: list[tuple[str, int | None, str | None]] = []
        self.action_counts = {name: 0 for name in _ACTIONS}
    @property
    def records(self) -> tuple[ControllerEventRecord, ...]:
        with self._lock:
            return self._records
    @property
    def approval_consumed(self) -> bool:
        with self._lock:
            return self._consumed
    def checkpoint(self, point: str) -> None:
        kind = self.faults.pop(point, None)
        if kind is None:
            return
        exception = _FAULTS.get(kind)
        if exception is None:
            raise ControllerError("unknown fake fault")
        raise exception(point)
    def _validate_approval(self) -> None:
        value = self.approval
        valid_digest = len(value.batch_commitment) == 64 and all(c in "0123456789abcdef" for c in value.batch_commitment)
        if not (
            value.version == FAKE_APPROVAL_VERSION
            and valid_digest
            and value.batch_commitment != ZERO_SHA256
            and value.phrase == APPROVAL_PHRASE
            and value.not_before_wall_ns <= self._wall < value.expires_wall_ns
            and value.one_attempt is True
            and value.signatures_valid is True
            and value.source_clean is True
            and value.modes == tuple(mode.value for mode in CYCLE_MODES)
        ):
            raise ApprovalDenied("fake approval rejected without consumption")

    def admit(self) -> None:
        """Atomically consume the approval and publish the admission record."""
        with self._lock:
            self._validate_approval()
            if self._consumed or self._records:
                raise ApprovalDenied("fake approval already consumed")
            self._consumed = True
            self._publish_locked(Event.BATCH_ADMITTED, None, None, Outcome.ACCEPTED, {"admitted": True})
            self.calls.append(("admit", None, None))

    def _publish_locked(
        self,
        event: Event,
        ordinal: int | None,
        mode: CycleMode | None,
        outcome: Outcome,
        fact: dict[str, Any],
    ) -> ControllerEventRecord:
        sequence = len(self._records) + 1
        payload = {
            "version": FAKE_PAYLOAD_VERSION,
            "sequence": sequence,
            "event": event.value,
            "cycle_ordinal": ordinal,
            "cycle_mode": None if mode is None else mode.value,
            "fact": fact,
            "production_publication_authorized": False,
        }
        payload_digest = codec.canonical_sha256(payload)
        if payload_digest in self._payloads:
            raise CampaignStateError("fake payload replay")
        self._mono += 10
        self._wall += 10
        sticky = reduce_campaign(self._records).uncertainty
        if outcome in {Outcome.UNCERTAIN, Outcome.NONZERO} or (event is Event.DESTROY_SETTLED and outcome is Outcome.FAILED):
            sticky = Uncertainty.STICKY
        record = new_record(
            batch_commitment=self.approval.batch_commitment,
            sequence=sequence,
            event=event,
            cycle_ordinal=ordinal,
            cycle_mode=mode,
            prior_record_sha256=ZERO_SHA256 if not self._records else self._records[-1].sha256(),
            payload_sha256=payload_digest,
            monotonic_observation_ns=self._mono,
            wall_observation_unix_ns=self._wall,
            outcome=outcome,
            uncertainty=sticky,
        )
        self._records = append_record(self._records, record)
        self._payloads[payload_digest] = payload
        self.calls.append((f"event:{event.value}", ordinal, None if mode is None else mode.value))
        return record

    def publish(
        self,
        event: Event,
        ordinal: int | None,
        mode: CycleMode | None,
        outcome: Outcome,
        fact: dict[str, Any],
    ) -> ControllerEventRecord:
        with self._lock:
            return self._publish_locked(event, ordinal, mode, outcome, fact)

    def action(self, kind: str, ordinal: int | None, mode: CycleMode | None) -> dict[str, Any]:
        if kind not in _ACTIONS or (ordinal is not None and mode is not CYCLE_MODES[ordinal - 1]):
            raise ControllerError("unsealed fake action")
        self.action_counts[kind] += 1
        self.calls.append((kind, ordinal, None if mode is None else mode.value))
        point = f"call:{kind}:{'final' if ordinal is None else ordinal:02}" if ordinal is not None else f"call:{kind}:final"
        fault = self.faults.pop(point, None)
        if kind == "apply" and fault not in {"failure"}:
            if self._active:
                raise ControllerError("overlapping fake apply")
            self._active = True
            self.maximum_active = max(self.maximum_active, 1)
        if fault is not None:
            exception = _FAULTS.get(fault)
            if exception is None:
                raise ControllerError("unknown fake action fault")
            raise exception(point)
        if kind == "destroy":
            self._active = False
        if kind == "inventory" and self._active:
            raise InjectedUncertainty("fake inventory is nonzero")
        source = self.receipt_replays.get((kind, ordinal or 0), ordinal or 0)
        return {
            "kind": kind,
            "batch_commitment": self.approval.batch_commitment,
            "cycle_ordinal": source or None,
            "cycle_mode": None if source == 0 else CYCLE_MODES[source - 1].value,
            "identity": hashlib.sha256(f"fake-receipt:{kind}:{source}:{self.action_counts[kind]}".encode("ascii")).hexdigest(),
            "certain": True,
        }

    def verify_receipt(self, receipt: dict[str, Any], kind: str, ordinal: int | None, mode: CycleMode | None) -> None:
        if not (
            type(receipt) is dict
            and set(receipt) == {"kind", "batch_commitment", "cycle_ordinal", "cycle_mode", "identity", "certain"}
            and receipt["kind"] == kind
            and receipt["batch_commitment"] == self.approval.batch_commitment
            and receipt["cycle_ordinal"] == ordinal
            and receipt["cycle_mode"] == (None if mode is None else mode.value)
            and type(receipt["identity"]) is str
            and len(receipt["identity"]) == 64
            and receipt["certain"] is True
        ):
            raise InjectedFailure("fake receipt binding rejected")

    def fake_verdict(self) -> dict[str, Any]:
        return {
            "version": FAKE_VERDICT_VERSION,
            "result": "pass",
            "cycle_modes": [mode.value for mode in CYCLE_MODES],
            "record_count": len(self.records),
            "last_record_sha256": self.records[-1].sha256(),
            "production_publication_authorized": False,
        }

class CompletionCampaignController:
    """One normal attempt or cleanup-only recovery; never a selectable route."""

    def __init__(self, ports: FakeCampaignPorts) -> None:
        if type(ports) is not FakeCampaignPorts:
            raise TypeError("controller accepts only sealed in-memory fake ports")
        self._ports = ports
    def _emit(self, event: Event, ordinal: int | None, mode: CycleMode | None, outcome: Outcome, fact: dict[str, Any]) -> None:
        sequence = len(self._ports.records) + 1
        point = f"{sequence:06d}:{event.value}"
        self._ports.checkpoint(f"before:{point}")
        self._ports.publish(event, ordinal, mode, outcome, fact)
        self._ports.checkpoint(f"after:{point}")

    def _effect(self, intent: Event, settled: Event, kind: str, ordinal: int | None, mode: CycleMode | None, outcome: Outcome = Outcome.ACCEPTED) -> None:
        self._emit(intent, ordinal, mode, Outcome.INTENDED, {"action": kind})
        receipt = self._ports.action(kind, ordinal, mode)
        self._ports.verify_receipt(receipt, kind, ordinal, mode)
        self._emit(settled, ordinal, mode, outcome, {"receipt": receipt})

    def _step(self) -> None:
        state = reduce_campaign(self._ports.records)
        event, ordinal, mode = state.next_event, state.next_cycle_ordinal, state.next_cycle_mode
        if event is Event.PLAN_INTENT:
            self._effect(event, Event.PLAN_ACCEPTED, "plan", ordinal, mode)
        elif event is Event.APPLY_INTENT:
            self._effect(event, Event.APPLY_ACCEPTED, "apply", ordinal, mode)
        elif event is Event.REMOTE_INTENT:
            self._effect(event, Event.REMOTE_ACCEPTED, "remote", ordinal, mode)
        elif event is Event.DESTROY_INTENT:
            self._effect(event, Event.DESTROY_SETTLED, "destroy", ordinal, mode)
        elif event is Event.ZERO_OBSERVATION_INTENT:
            self._effect(event, Event.ZERO_ACCEPTED, "inventory", ordinal, mode, Outcome.ZERO)
        elif event is Event.FINAL_ZERO_OBSERVATION_INTENT:
            self._effect(event, Event.FINAL_ZERO_ACCEPTED, "inventory", None, None, Outcome.ZERO)
        elif event is Event.RUNNING_OBSERVED:
            receipt = self._ports.action("running", ordinal, mode)
            self._ports.verify_receipt(receipt, "running", ordinal, mode)
            self._emit(event, ordinal, mode, Outcome.OBSERVED, {"receipt": receipt})
        elif event is Event.TERMINAL_CANDIDATE_VALIDATED:
            receipt = self._ports.action("validate", None, None)
            self._ports.verify_receipt(receipt, "validate", None, None)
            self._emit(event, None, None, Outcome.SEALED, {"receipt": receipt})
        elif event is not None:
            self._emit(event, ordinal, mode, Outcome.ACCEPTED if event is Event.CYCLE_OPENED else Outcome.SEALED, {"internal": True})

    def _record_failure(self, error: BaseException, force_uncertain: bool = False) -> None:
        state = reduce_campaign(self._ports.records)
        if state.failure_recorded or state.terminal:
            return
        uncertain = force_uncertain or isinstance(error, (InjectedUncertainty, InjectedCrash))
        active = sum(r.event is Event.CYCLE_OPENED for r in self._ports.records) > sum(r.event is Event.CYCLE_SEALED for r in self._ports.records)
        self._emit(
            Event.FAILURE_RECORDED,
            state.next_cycle_ordinal if active else None,
            state.next_cycle_mode if active else None,
            Outcome.UNCERTAIN if uncertain else Outcome.FAILED,
            {"class": type(error).__name__},
        )

    def _cleanup(self) -> ControllerResult:
        while True:
            state = reduce_campaign(self._ports.records)
            if state.terminal:
                return ControllerResult(state.status, True, state.uncertainty, None)
            event, ordinal, mode = state.next_event, state.next_cycle_ordinal, state.next_cycle_mode
            if event is Event.DESTROY_INTENT:
                self._emit(event, ordinal, mode, Outcome.INTENDED, {"cleanup": True})
                try:
                    receipt = self._ports.action("destroy", ordinal, mode)
                    self._ports.verify_receipt(receipt, "destroy", ordinal, mode)
                    self._emit(Event.DESTROY_SETTLED, ordinal, mode, Outcome.ACCEPTED, {"receipt": receipt})
                except InjectedCrash:
                    raise
                except BaseException as error:
                    self._emit(Event.DESTROY_SETTLED, ordinal, mode, Outcome.UNCERTAIN, {"class": type(error).__name__})
            elif event is Event.DESTROY_SETTLED:
                self._emit(event, ordinal, mode, Outcome.UNCERTAIN, {"unreplayed_intent": True})
            elif event in {Event.ZERO_OBSERVATION_INTENT, Event.FINAL_ZERO_OBSERVATION_INTENT}:
                self._emit(event, ordinal, mode, Outcome.INTENDED, {"cleanup": True})
                try:
                    receipt = self._ports.action("inventory", ordinal, mode)
                    self._ports.verify_receipt(receipt, "inventory", ordinal, mode)
                    accepted = Event.ZERO_ACCEPTED if ordinal is not None else Event.FINAL_ZERO_ACCEPTED
                    self._emit(accepted, ordinal, mode, Outcome.ZERO, {"receipt": receipt})
                except InjectedCrash:
                    raise
                except BaseException as error:
                    accepted = Event.ZERO_ACCEPTED if ordinal is not None else Event.FINAL_ZERO_ACCEPTED
                    self._emit(accepted, ordinal, mode, Outcome.UNCERTAIN, {"class": type(error).__name__})
            elif event in {Event.ZERO_ACCEPTED, Event.FINAL_ZERO_ACCEPTED}:
                self._emit(event, ordinal, mode, Outcome.UNCERTAIN, {"unreplayed_intent": True})
            else:
                self._emit(event, ordinal, mode, Outcome.SEALED, {"cleanup_terminal": True})

    def run(self) -> ControllerResult:
        if self._ports.records or self._ports.approval_consumed:
            raise ApprovalDenied("normal invocation cannot resume")
        self._ports.admit()
        try:
            self._ports.checkpoint("after:000001:BATCH_ADMITTED")
            while not reduce_campaign(self._ports.records).terminal:
                self._step()
            state = reduce_campaign(self._ports.records)
            return ControllerResult(state.status, True, state.uncertainty, self._ports.fake_verdict())
        except InjectedCrash:
            raise
        except BaseException as error:
            self._record_failure(error)
            return self._cleanup()

    def recover(self) -> ControllerResult:
        records = self._ports.records
        if not self._ports.approval_consumed or not records:
            raise RecoveryDenied("nothing consumed")
        state = reduce_campaign(records)
        if state.terminal:
            raise RecoveryDenied("terminal custody has no recovery transition")
        if not state.failure_recorded:
            self._record_failure(InjectedCrash("reopened consumed custody"), force_uncertain=True)
        return self._cleanup()

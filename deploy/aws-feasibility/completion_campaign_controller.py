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
import completion_campaign_evidence as private_evidence

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


def _remote_receipt_realm():
    seal, issued = object(), {}
    class _SyntheticFullRemoteReceipt:
        __slots__ = ("batch_commitment", "ordinal", "mode", "commitment", "workload_count")
        def __new__(cls, key=None, **value):
            if key is not seal: raise ControllerError("sealed full remote receipt")
            result = super().__new__(cls)
            for name in cls.__slots__: setattr(result, name, value[name])
            return result
    class _SyntheticReadinessRemoteReceipt:
        __slots__ = ("batch_commitment", "ordinal", "mode", "commitment")
        def __new__(cls, key=None, **value):
            if key is not seal: raise ControllerError("sealed readiness remote receipt")
            result = super().__new__(cls)
            for name in cls.__slots__: setattr(result, name, value[name])
            return result
    def issue(batch, ordinal, mode, nonce):
        source = {"batch_commitment": batch, "ordinal": ordinal,
                  "mode": mode.value, "nonce": nonce,
                  "production_publication_authorized": False,
                  "provider_execution_observed": False}
        commitment = codec.commitment_sha256(
            "cogs.stage2-completion/synthetic-remote-owner/v1", source,
            bytes.fromhex(batch))
        values = {"batch_commitment": batch, "ordinal": ordinal,
                  "mode": mode, "commitment": commitment}
        receipt = (_SyntheticFullRemoteReceipt(seal, **values, workload_count=21)
                   if mode is CycleMode.FULL else
                   _SyntheticReadinessRemoteReceipt(seal, **values))
        issued[id(receipt)] = receipt
        return receipt
    def consume(receipt, batch, ordinal, mode):
        expected = (_SyntheticFullRemoteReceipt if mode is CycleMode.FULL
                    else _SyntheticReadinessRemoteReceipt)
        if (type(receipt) is not expected or issued.get(id(receipt)) is not receipt
                or receipt.batch_commitment != batch or receipt.ordinal != ordinal
                or receipt.mode is not mode):
            raise InjectedFailure("fake remote receipt binding rejected")
        issued.pop(id(receipt))
        return receipt.commitment
    return _SyntheticFullRemoteReceipt, _SyntheticReadinessRemoteReceipt, issue, consume


(_SyntheticFullRemoteReceipt, _SyntheticReadinessRemoteReceipt,
 _issue_synthetic_remote_receipt, _consume_synthetic_remote_receipt) = _remote_receipt_realm()
del _remote_receipt_realm


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
        self._accepted: dict[tuple[str, int], str] = {}
        self._pre_destroy: dict[int, str] = {}
        self._private_issuer = private_evidence.SyntheticPrivateReceiptIssuer(
            approval.batch_commitment, "2030-01-01T00:00:00Z",
            hashlib.sha256(b"fake-deadline-binding-v1").hexdigest(),
            (100, 200, 300, 400))
        self._private_custody = private_evidence.SyntheticPrivateCustodyChain(
            approval.batch_commitment, "2030-01-01T00:00:00Z",
            hashlib.sha256(b"fake-deadline-binding-v1").hexdigest())
        self._custody_verdict: dict[str, Any] | None = None
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
        if kind == "remote":
            if source < 1 or source > 7:
                raise ControllerError("fake remote receipt source")
            return _issue_synthetic_remote_receipt(
                self.approval.batch_commitment, source, CYCLE_MODES[source - 1],
                self.action_counts[kind])
        return {
            "kind": kind,
            "batch_commitment": self.approval.batch_commitment,
            "cycle_ordinal": source or None,
            "cycle_mode": None if source == 0 else CYCLE_MODES[source - 1].value,
            "identity": hashlib.sha256(f"fake-receipt:{kind}:{source}:{self.action_counts[kind]}".encode("ascii")).hexdigest(),
            "certain": True,
        }

    def verify_receipt(self, receipt: Any, kind: str, ordinal: int | None,
                       mode: CycleMode | None) -> str:
        if kind == "remote":
            if ordinal is None or mode is None:
                raise InjectedFailure("unbound fake remote receipt")
            return _consume_synthetic_remote_receipt(
                receipt, self.approval.batch_commitment, ordinal, mode)
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
        return receipt["identity"]

    def fake_verdict(self) -> dict[str, Any]:
        if self._custody_verdict is None:
            raise ControllerError("synthetic private custody is not sealed")
        return dict(self._custody_verdict)

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

    def _effect(self, intent: Event, settled: Event, kind: str, ordinal: int | None, mode: CycleMode | None, outcome: Outcome = Outcome.ACCEPTED) -> str:
        self._emit(intent, ordinal, mode, Outcome.INTENDED, {"action": kind})
        receipt = self._ports.action(kind, ordinal, mode)
        commitment = self._ports.verify_receipt(receipt, kind, ordinal, mode)
        fact = ({"remote_receipt_commitment": commitment}
                if kind == "remote" else {"receipt": receipt})
        self._emit(settled, ordinal, mode, outcome, fact)
        if ordinal is not None:
            self._ports._accepted[(kind, ordinal)] = commitment
        elif kind == "inventory":
            self._ports._accepted[(kind, 0)] = commitment
        return commitment

    def _seal_private_cycle(self, ordinal: int, mode: CycleMode) -> str:
        ports = self._ports
        required = {name: ports._accepted[(name, ordinal)]
                    for name in ("plan", "apply", "running", "remote", "destroy", "inventory")}
        remote = required["remote"]
        pre_destroy = ports._pre_destroy[ordinal]
        receipt_commitment = codec.commitment_sha256(
            "cogs.stage2-completion/synthetic-cycle-owner/v1",
            {"ordinal": ordinal, "mode": mode.value, "remote": remote,
             "pre_destroy": pre_destroy, "destroy": required["destroy"],
             "zero": required["inventory"]}, bytes.fromhex(ports.approval.batch_commitment))
        workloads = ()
        if mode is CycleMode.FULL:
            workloads = tuple(private_evidence.SyntheticWorkloadSample(
                category, sample, 1000 + sample,
                hashlib.sha256(f"fake-workload:{category}:{sample}".encode()).hexdigest(),
                True, receipt_commitment)
                for category in ("git", "build", "install")
                for sample in range(1, 8))
        start = (ordinal - 1) * 1000
        duration = 900
        costs = tuple((duration * rate + private_evidence.BILLING_HOUR_NS - 1)
                      // private_evidence.BILLING_HOUR_NS
                      for rate in ports._private_issuer.rates)
        freshness = tuple(hashlib.sha256(
            f"fake-freshness:{ordinal}:{name}".encode()).hexdigest()
            for name in private_evidence.FRESHNESS_NAMES)
        cycle = ports._private_issuer.issue_cycle(
            previous_custody_sha256=ports._private_custody.custody_root,
            ordinal=ordinal, mode=mode, effect_started_offset_ns=start,
            effect_ended_offset_ns=start + duration, apply_to_running_ns=100,
            kata_launch_to_ssh_ready_ns=200,
            receipt_commitment=receipt_commitment,
            freshness_commitments=freshness, workloads=workloads,
            teardown_phases=private_evidence.TEARDOWN_PHASES,
            destroy_commitment=required["destroy"], costs_micro_usd=costs)
        ports._private_custody.accept_cycle(cycle)
        zero = ports._private_issuer.issue_zero(
            previous_custody_sha256=ports._private_custody.custody_root,
            observation_sequence=ordinal, cycle_ordinal=ordinal,
            zero_commitment=required["inventory"])
        ports._private_custody.accept_zero(zero)
        return receipt_commitment

    def _seal_terminal_custody(self) -> dict[str, Any]:
        ports = self._ports
        final_commitment = ports._accepted[("inventory", 0)]
        zero = ports._private_issuer.issue_zero(
            previous_custody_sha256=ports._private_custody.custody_root,
            observation_sequence=8, cycle_ordinal=None,
            zero_commitment=final_commitment)
        ports._private_custody.accept_zero(zero)
        verdict = ports._private_custody.seal_fake_verdict()
        ports._custody_verdict = verdict
        return verdict

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
            commitment = self._ports.verify_receipt(receipt, "running", ordinal, mode)
            self._ports._accepted[("running", ordinal)] = commitment
            self._emit(event, ordinal, mode, Outcome.OBSERVED, {"receipt": receipt})
        elif event is Event.PRE_DESTROY_SEALED:
            remote = self._ports._accepted[("remote", ordinal)]
            pre_destroy = codec.commitment_sha256(
                "cogs.stage2-completion/synthetic-pre-destroy/v1",
                {"ordinal": ordinal, "mode": mode.value,
                 "remote_receipt_commitment": remote,
                 "running_receipt_commitment": self._ports._accepted[("running", ordinal)]},
                bytes.fromhex(self._ports.approval.batch_commitment))
            self._ports._pre_destroy[ordinal] = pre_destroy
            self._emit(event, ordinal, mode, Outcome.SEALED, {
                "remote_receipt_commitment": remote,
                "pre_destroy_receipt_commitment": pre_destroy})
        elif event is Event.CYCLE_SEALED:
            commitment = self._seal_private_cycle(ordinal, mode)
            self._emit(event, ordinal, mode, Outcome.SEALED, {
                "remote_receipt_commitment": self._ports._accepted[("remote", ordinal)],
                "pre_destroy_receipt_commitment": self._ports._pre_destroy[ordinal],
                "private_cycle_receipt_commitment": commitment})
        elif event is Event.TERMINAL_CANDIDATE_VALIDATED:
            verdict = self._seal_terminal_custody()
            self._emit(event, None, None, Outcome.SEALED, {
                "synthetic_custody_root": verdict["custody_root"],
                "synthetic_custody_version": verdict["version"]})
        elif event is not None:
            self._emit(event, ordinal, mode,
                       Outcome.ACCEPTED if event is Event.CYCLE_OPENED else Outcome.SEALED,
                       {"internal": True})

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

#!/usr/bin/env python3
"""Closed fake-only private receipt and custody-chain evidence model.

It models finalization invariants without commands, files, sockets, providers, or
production publication.  Its only output is an explicitly non-authoritative
synthetic verdict; public AWS authority cannot be minted by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import completion_campaign_codec as codec
from completion_campaign_contracts import CYCLE_MODES, ZERO_SHA256, CycleMode

SYNTHETIC_RECEIPT_VERSION = "cogs.stage2-completion-synthetic-private-receipt/v1"
SYNTHETIC_ZERO_VERSION = "cogs.stage2-completion-synthetic-private-zero/v1"
SYNTHETIC_VERDICT_VERSION = "cogs.stage2-completion-synthetic-custody-verdict/v1"
PRODUCTION_EVIDENCE_VERSION = "cogs.aws-stage2-completion-evidence/v1"
PRODUCTION_AUTHORITY = "aws-stage2-completion"
NORMAL_DEADLINE_NS = 5_400_000_000_000
BILLING_HOUR_NS = 3_600_000_000_000
TEARDOWN_PHASES = (
    "READINESS_REVOKED", "TASK_STOPPED", "TASK_ABSENT", "RUNTIME_PROCESSES_ABSENT",
    "NETWORK_ABSENT", "CONTAINER_ABSENT", "SHARE_AND_MOUNTS_ABSENT",
    "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "INPUTS_ABSENT", "ROOTFS_ABSENT",
    "FINAL_BASELINES", "RETIRED",
)
FRESHNESS_NAMES = (
    "instance", "root_volume", "launch_template_generation", "host_boot",
    "operation", "client_key", "host_key", "pre_destroy_receipt",
)


class SyntheticEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SyntheticEvidenceError(message)


def _digest(value: str) -> None:
    _require(type(value) is str and len(value) == 64
             and all(character in "0123456789abcdef" for character in value),
             "exact lowercase SHA-256 commitment required")


def _positive(value: int, maximum: int = NORMAL_DEADLINE_NS) -> None:
    _require(type(value) is int and 1 <= value <= maximum, "positive nanosecond bound")


def _summary(values: tuple[int, ...]) -> dict[str, Any]:
    _require(type(values) is tuple and len(values) == 7
             and all(type(value) is int and value > 0 for value in values),
             "exact seven positive samples required")
    ordered = sorted(values)
    return {
        "samples_ns": list(values), "min_ns": ordered[0],
        "p50_ns": ordered[3], "p95_ns": ordered[6], "max_ns": ordered[6],
    }


def _ceil_cost(duration_ns: int, rate: int) -> int:
    _require(type(rate) is int and 1 <= rate <= 1_000_000_000, "integer rate bound")
    return (duration_ns * rate + BILLING_HOUR_NS - 1) // BILLING_HOUR_NS


@dataclass(frozen=True, slots=True)
class SyntheticWorkloadSample:
    category: str
    ordinal: int
    duration_ns: int
    output_commitment: str
    deleted: bool
    cycle_receipt_commitment: str

    def __post_init__(self) -> None:
        _require(self.category in {"git", "build", "install"}, "closed workload category")
        _require(type(self.ordinal) is int and 1 <= self.ordinal <= 7, "workload ordinal")
        _positive(self.duration_ns)
        _digest(self.output_commitment)
        _digest(self.cycle_receipt_commitment)
        _require(type(self.deleted) is bool and self.deleted, "sample deletion required")


_RECEIPT_SEAL = object()
_ISSUED_CYCLES: dict[int, object] = {}
_ISSUED_ZEROS: dict[int, object] = {}


@dataclass(frozen=True, slots=True)
class _ValidatedSyntheticCycleReceipt:
    version: str
    batch_commitment: str
    previous_custody_sha256: str
    ordinal: int
    mode: CycleMode
    expiry_at: str
    deadline_binding_commitment: str
    effect_started_offset_ns: int
    effect_ended_offset_ns: int
    apply_to_running_ns: int
    kata_launch_to_ssh_ready_ns: int
    receipt_commitment: str
    freshness_commitments: tuple[str, ...]
    workloads: tuple[SyntheticWorkloadSample, ...]
    teardown_phases: tuple[str, ...]
    destroy_commitment: str
    costs_micro_usd: tuple[int, int, int, int]
    _seal: object

    def __post_init__(self) -> None:
        _require(self._seal is _RECEIPT_SEAL, "unissued synthetic cycle receipt")

    def custody_value(self) -> dict[str, Any]:
        return {
            "version": self.version, "batch_commitment": self.batch_commitment,
            "previous_custody_sha256": self.previous_custody_sha256,
            "ordinal": self.ordinal, "mode": self.mode.value,
            "expiry_at": self.expiry_at,
            "deadline_binding_commitment": self.deadline_binding_commitment,
            "effect_started_offset_ns": self.effect_started_offset_ns,
            "effect_ended_offset_ns": self.effect_ended_offset_ns,
            "apply_to_running_ns": self.apply_to_running_ns,
            "kata_launch_to_ssh_ready_ns": self.kata_launch_to_ssh_ready_ns,
            "receipt_commitment": self.receipt_commitment,
            "freshness_commitments": list(self.freshness_commitments),
            "workloads": [{
                "category": row.category, "ordinal": row.ordinal,
                "duration_ns": row.duration_ns,
                "output_commitment": row.output_commitment,
                "deleted": row.deleted,
                "cycle_receipt_commitment": row.cycle_receipt_commitment,
            } for row in self.workloads],
            "teardown_phases": list(self.teardown_phases),
            "destroy_commitment": self.destroy_commitment,
            "costs_micro_usd": list(self.costs_micro_usd),
        }


@dataclass(frozen=True, slots=True)
class _ValidatedSyntheticZeroReceipt:
    version: str
    batch_commitment: str
    previous_custody_sha256: str
    observation_sequence: int
    cycle_ordinal: int | None
    zero_commitment: str
    _seal: object

    def __post_init__(self) -> None:
        _require(self._seal is _RECEIPT_SEAL, "unissued synthetic zero receipt")

    def custody_value(self) -> dict[str, Any]:
        return {
            "version": self.version, "batch_commitment": self.batch_commitment,
            "previous_custody_sha256": self.previous_custody_sha256,
            "observation_sequence": self.observation_sequence,
            "cycle_ordinal": self.cycle_ordinal,
            "zero_commitment": self.zero_commitment,
        }


class SyntheticPrivateReceiptIssuer:
    """Validate raw synthetic facts into the only receipt types custody accepts."""

    def __init__(self, batch_commitment: str, expiry_at: str,
                 deadline_binding_commitment: str,
                 rates_micro_usd_per_hour: tuple[int, int, int, int]) -> None:
        _digest(batch_commitment)
        _digest(deadline_binding_commitment)
        _require(type(expiry_at) is str and expiry_at.endswith("Z")
                 and len(expiry_at) == 20, "fixed UTC expiry required")
        _require(type(rates_micro_usd_per_hour) is tuple
                 and len(rates_micro_usd_per_hour) == 4, "four exact rates required")
        for rate in rates_micro_usd_per_hour:
            _ceil_cost(1, rate)
        self.batch_commitment = batch_commitment
        self.expiry_at = expiry_at
        self.deadline_binding_commitment = deadline_binding_commitment
        self.rates = rates_micro_usd_per_hour

    def issue_cycle(self, *, previous_custody_sha256: str, ordinal: int,
                    mode: CycleMode, effect_started_offset_ns: int,
                    effect_ended_offset_ns: int, apply_to_running_ns: int,
                    kata_launch_to_ssh_ready_ns: int, receipt_commitment: str,
                    freshness_commitments: tuple[str, ...],
                    workloads: tuple[SyntheticWorkloadSample, ...],
                    teardown_phases: tuple[str, ...], destroy_commitment: str,
                    costs_micro_usd: tuple[int, int, int, int],
                    expiry_at: str | None = None,
                    deadline_binding_commitment: str | None = None,
                    ) -> _ValidatedSyntheticCycleReceipt:
        _digest(previous_custody_sha256)
        _require(type(ordinal) is int and 1 <= ordinal <= 7, "cycle ordinal")
        _require(type(mode) is CycleMode and mode is CYCLE_MODES[ordinal - 1],
                 "fixed seven-cycle mode mismatch")
        _require(type(effect_started_offset_ns) is int
                 and 0 <= effect_started_offset_ns < NORMAL_DEADLINE_NS,
                 "effect start offset bound")
        _require(type(effect_ended_offset_ns) is int
                 and effect_started_offset_ns < effect_ended_offset_ns < NORMAL_DEADLINE_NS,
                 "effect end deadline bound")
        duration = effect_ended_offset_ns - effect_started_offset_ns
        _positive(apply_to_running_ns, duration)
        _positive(kata_launch_to_ssh_ready_ns, duration)
        _digest(receipt_commitment)
        _require(type(freshness_commitments) is tuple
                 and len(freshness_commitments) == len(FRESHNESS_NAMES),
                 "exact freshness vector required")
        for commitment in freshness_commitments:
            _digest(commitment)
        _require(len(set(freshness_commitments)) == len(freshness_commitments),
                 "domain-separated freshness required")
        _require(type(workloads) is tuple
                 and all(type(row) is SyntheticWorkloadSample for row in workloads),
                 "closed validated workload sample type required")
        if ordinal == 1:
            _require(len(workloads) == 21, "full cycle requires 21 workload rows")
            expected = tuple((category, sample_ordinal)
                             for category in ("git", "build", "install")
                             for sample_ordinal in range(1, 8))
            _require(tuple((row.category, row.ordinal) for row in workloads) == expected,
                     "workload order mismatch")
            _require(all(row.cycle_receipt_commitment == receipt_commitment
                         for row in workloads), "workload receipt swap")
        else:
            _require(not workloads, "readiness receipt cannot contain workload fields")
        _require(type(teardown_phases) is tuple
                 and teardown_phases == TEARDOWN_PHASES,
                 "exact 13 teardown phases required")
        _digest(destroy_commitment)
        _require(type(costs_micro_usd) is tuple and len(costs_micro_usd) == 4,
                 "exact component costs required")
        expected_costs = tuple(_ceil_cost(duration, rate) for rate in self.rates)
        _require(costs_micro_usd == expected_costs, "deadline-duration cost binding mismatch")
        _require(expiry_at in {None, self.expiry_at}, "common expiry drift")
        _require(deadline_binding_commitment in {None, self.deadline_binding_commitment},
                 "deadline binding drift")
        receipt = _ValidatedSyntheticCycleReceipt(
            SYNTHETIC_RECEIPT_VERSION, self.batch_commitment,
            previous_custody_sha256, ordinal, mode, self.expiry_at,
            self.deadline_binding_commitment, effect_started_offset_ns,
            effect_ended_offset_ns, apply_to_running_ns,
            kata_launch_to_ssh_ready_ns, receipt_commitment,
            freshness_commitments, workloads, teardown_phases,
            destroy_commitment, costs_micro_usd, _RECEIPT_SEAL)
        _ISSUED_CYCLES[id(receipt)] = receipt
        return receipt

    def issue_zero(self, *, previous_custody_sha256: str,
                   observation_sequence: int, cycle_ordinal: int | None,
                   zero_commitment: str) -> _ValidatedSyntheticZeroReceipt:
        _digest(previous_custody_sha256)
        _require(type(observation_sequence) is int
                 and 1 <= observation_sequence <= 8, "zero observation sequence")
        expected_cycle = observation_sequence if observation_sequence <= 7 else None
        _require(cycle_ordinal == expected_cycle, "zero cycle binding mismatch")
        _digest(zero_commitment)
        receipt = _ValidatedSyntheticZeroReceipt(
            SYNTHETIC_ZERO_VERSION, self.batch_commitment,
            previous_custody_sha256, observation_sequence, cycle_ordinal,
            zero_commitment, _RECEIPT_SEAL)
        _ISSUED_ZEROS[id(receipt)] = receipt
        return receipt


class SyntheticPrivateCustodyChain:
    """Accept only issuer-validated private receipt objects in exact order."""

    def __init__(self, batch_commitment: str, expiry_at: str,
                 deadline_binding_commitment: str) -> None:
        _digest(batch_commitment)
        _digest(deadline_binding_commitment)
        self._batch = batch_commitment
        self._expiry = expiry_at
        self._deadline = deadline_binding_commitment
        self._root = ZERO_SHA256
        self._cycles: list[_ValidatedSyntheticCycleReceipt] = []
        self._zeros: list[_ValidatedSyntheticZeroReceipt] = []
        self._sealed = False

    @property
    def custody_root(self) -> str:
        return self._root

    def _accept(self, receipt: Any) -> None:
        _require(not self._sealed, "sealed synthetic custody")
        _require(receipt.batch_commitment == self._batch
                 and receipt.previous_custody_sha256 == self._root,
                 "cross-batch or spliced synthetic receipt")
        self._root = codec.commitment_sha256(
            "cogs.stage2-completion/synthetic-custody-record/v1",
            receipt.custody_value(), bytes.fromhex(self._batch))

    def accept_cycle(self, receipt: _ValidatedSyntheticCycleReceipt) -> None:
        _require(type(receipt) is _ValidatedSyntheticCycleReceipt
                 and _ISSUED_CYCLES.get(id(receipt)) is receipt,
                 "custody accepts only validated synthetic cycle receipt type")
        ordinal = len(self._cycles) + 1
        _require(len(self._cycles) == len(self._zeros)
                 and receipt.ordinal == ordinal
                 and receipt.mode is CYCLE_MODES[ordinal - 1],
                 "cycle order barrier")
        _require(receipt.expiry_at == self._expiry
                 and receipt.deadline_binding_commitment == self._deadline,
                 "custody common binding mismatch")
        if self._cycles:
            _require(receipt.effect_started_offset_ns
                     >= self._cycles[-1].effect_ended_offset_ns,
                     "synthetic cycle overlap")
        else:
            _require(receipt.effect_started_offset_ns == 0,
                     "first effect must define zero offset")
        self._accept(receipt)
        _ISSUED_CYCLES.pop(id(receipt), None)
        self._cycles.append(receipt)

    def accept_zero(self, receipt: _ValidatedSyntheticZeroReceipt) -> None:
        _require(type(receipt) is _ValidatedSyntheticZeroReceipt
                 and _ISSUED_ZEROS.get(id(receipt)) is receipt,
                 "custody accepts only validated synthetic zero receipt type")
        expected_sequence = len(self._zeros) + 1
        _require(receipt.observation_sequence == expected_sequence,
                 "zero observation order mismatch")
        if expected_sequence <= 7:
            _require(len(self._cycles) == expected_sequence
                     and receipt.cycle_ordinal == expected_sequence,
                     "cycle zero barrier")
        else:
            _require(len(self._cycles) == 7 and len(self._zeros) == 7
                     and receipt.cycle_ordinal is None,
                     "distinct final zero required")
        _require(receipt.zero_commitment not in {
            row.zero_commitment for row in self._zeros}, "zero receipt replay")
        self._accept(receipt)
        _ISSUED_ZEROS.pop(id(receipt), None)
        self._zeros.append(receipt)

    def seal_fake_verdict(self) -> dict[str, Any]:
        _require(not self._sealed and len(self._cycles) == 7
                 and len(self._zeros) == 8, "incomplete synthetic custody")
        all_freshness = [commitment for cycle in self._cycles
                         for commitment in cycle.freshness_commitments]
        _require(len(set(all_freshness)) == len(all_freshness),
                 "cross-cycle freshness replay")
        _require(len({cycle.receipt_commitment for cycle in self._cycles}) == 7,
                 "cycle receipt replay")
        _require(len({cycle.destroy_commitment for cycle in self._cycles}) == 7,
                 "destroy receipt replay")
        self._sealed = True
        full = self._cycles[0]
        groups = {
            category: tuple(row.duration_ns for row in full.workloads
                            if row.category == category)
            for category in ("git", "build", "install")
        }
        verdict = {
            "version": SYNTHETIC_VERDICT_VERSION,
            "authority": "synthetic-private-test-model",
            "result": "pass",
            "cycle_modes": [cycle.mode.value for cycle in self._cycles],
            "launch_summary": _summary(tuple(
                cycle.apply_to_running_ns for cycle in self._cycles)),
            "ssh_ready_summary": _summary(tuple(
                cycle.kata_launch_to_ssh_ready_ns for cycle in self._cycles)),
            "workload_summaries": {
                category: _summary(values) for category, values in groups.items()},
            "workload_count": sum(len(cycle.workloads) for cycle in self._cycles),
            "cycle_zero_commitments": [row.zero_commitment for row in self._zeros[:7]],
            "final_zero_commitment": self._zeros[7].zero_commitment,
            "zero_receipt_count": 8,
            "aggregate_duration_ns": sum(
                cycle.effect_ended_offset_ns - cycle.effect_started_offset_ns
                for cycle in self._cycles),
            "aggregate_cost_micro_usd": sum(
                sum(cycle.costs_micro_usd) for cycle in self._cycles),
            "custody_root": self._root,
            "production_evidence_version": None,
            "production_authority": None,
            "production_publication_authorized": False,
            "provider_execution_observed": False,
        }
        _require(PRODUCTION_EVIDENCE_VERSION not in codec.canonical_bytes(verdict).decode("ascii")
                 and PRODUCTION_AUTHORITY not in codec.canonical_bytes(verdict).decode("ascii"),
                 "synthetic verdict attempted production authority")
        return verdict

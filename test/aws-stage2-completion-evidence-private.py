#!/usr/bin/env python3
"""Hostile fake-only private receipt/custody model tests for Slice E."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))

from completion_campaign_contracts import CYCLE_MODES, CycleMode
from completion_campaign_evidence import (
    BILLING_HOUR_NS,
    NORMAL_DEADLINE_NS,
    SYNTHETIC_VERDICT_VERSION,
    TEARDOWN_PHASES,
    SyntheticEvidenceError,
    SyntheticPrivateCustodyChain,
    SyntheticPrivateReceiptIssuer,
    SyntheticWorkloadSample,
)


def digest(label):
    return hashlib.sha256(f"private-synthetic:{label}".encode("ascii")).hexdigest()


def require(condition, message="test assertion failed"):
    if not condition:
        raise AssertionError(message)


def expect(kind, function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


def costs(duration, rates):
    return tuple((duration * rate + BILLING_HOUR_NS - 1) // BILLING_HOUR_NS
                 for rate in rates)


def workloads(receipt):
    rows = []
    for category_index, category in enumerate(("git", "build", "install")):
        output = digest(f"output-{category}")
        for ordinal in range(1, 8):
            rows.append(SyntheticWorkloadSample(
                category, ordinal, (category_index * 10 + ordinal) * 1_000_000,
                output, True, receipt))
    return tuple(rows)


def issue_cycle(issuer, chain, ordinal, *, freshness_prefix="fresh", mode=None,
                cycle_workloads=None, cycle_costs=None, expiry_at=None,
                deadline_binding=None, freshness_override=None):
    duration = 600_000_000_000
    receipt = digest(f"receipt-{ordinal}")
    selected_workloads = (workloads(receipt) if ordinal == 1 else ())
    if cycle_workloads is not None:
        selected_workloads = cycle_workloads
    return issuer.issue_cycle(
        previous_custody_sha256=chain.custody_root,
        ordinal=ordinal,
        mode=CYCLE_MODES[ordinal - 1] if mode is None else mode,
        effect_started_offset_ns=(ordinal - 1) * duration,
        effect_ended_offset_ns=ordinal * duration,
        apply_to_running_ns=(80 - ordinal * 7) * 1_000_000,
        kata_launch_to_ssh_ready_ns=(100 - ordinal * 8) * 1_000_000,
        receipt_commitment=receipt,
        freshness_commitments=(tuple(
            digest(f"{freshness_prefix}-{ordinal}-{name}") for name in (
                "instance", "volume", "generation", "boot", "operation",
                "client", "host", "pre-destroy"))
            if freshness_override is None else freshness_override),
        workloads=selected_workloads,
        teardown_phases=TEARDOWN_PHASES,
        destroy_commitment=digest(f"destroy-{ordinal}"),
        costs_micro_usd=(costs(duration, issuer.rates)
                         if cycle_costs is None else cycle_costs),
        expiry_at=expiry_at,
        deadline_binding_commitment=deadline_binding,
    )


def build_happy():
    batch = digest("batch")
    deadline = digest("deadline")
    expiry = "2026-08-23T12:00:00Z"
    rates = (90_000, 5_000, 3_000, 20_000)
    issuer = SyntheticPrivateReceiptIssuer(batch, expiry, deadline, rates)
    chain = SyntheticPrivateCustodyChain(batch, expiry, deadline)
    cycle_receipts = []
    zeros = []
    for ordinal in range(1, 8):
        cycle = issue_cycle(issuer, chain, ordinal)
        chain.accept_cycle(cycle)
        cycle_receipts.append(cycle)
        zero = issuer.issue_zero(
            previous_custody_sha256=chain.custody_root,
            observation_sequence=ordinal,
            cycle_ordinal=ordinal,
            zero_commitment=digest(f"zero-{ordinal}"))
        chain.accept_zero(zero)
        zeros.append(zero)
    final = issuer.issue_zero(
        previous_custody_sha256=chain.custody_root,
        observation_sequence=8, cycle_ordinal=None,
        zero_commitment=digest("zero-final"))
    chain.accept_zero(final)
    zeros.append(final)
    return issuer, chain, tuple(cycle_receipts), tuple(zeros)


def happy_matrix():
    _issuer, chain, cycles, zeros = build_happy()
    verdict = chain.seal_fake_verdict()
    require(verdict["version"] == SYNTHETIC_VERDICT_VERSION)
    require(verdict["authority"] == "synthetic-private-test-model")
    require(verdict["production_publication_authorized"] is False)
    require(verdict["production_evidence_version"] is None)
    require(verdict["production_authority"] is None)
    require(verdict["cycle_modes"] == [mode.value for mode in CYCLE_MODES])
    require(verdict["workload_count"] == 21)
    require(verdict["zero_receipt_count"] == 8)
    require(len(set(verdict["cycle_zero_commitments"]
                    + [verdict["final_zero_commitment"]])) == 8)
    require(verdict["launch_summary"]["p50_ns"] ==
            sorted(row.apply_to_running_ns for row in cycles)[3])
    require(verdict["launch_summary"]["p95_ns"] ==
            sorted(row.apply_to_running_ns for row in cycles)[6])
    require(verdict["ssh_ready_summary"]["p50_ns"] ==
            sorted(row.kata_launch_to_ssh_ready_ns for row in cycles)[3])
    require(verdict["workload_summaries"]["git"]["p95_ns"] == 7_000_000)
    require(verdict["aggregate_duration_ns"] == 4_200_000_000_000)
    require(verdict["aggregate_cost_micro_usd"] ==
            sum(sum(row.costs_micro_usd) for row in cycles))
    raw = repr(verdict).lower()
    require("cogs.aws-stage2-completion-evidence/v1" not in raw)
    require("aws-stage2-completion'" not in raw)
    expect(SyntheticEvidenceError, chain.seal_fake_verdict)
    expect(SyntheticEvidenceError, chain.accept_zero, zeros[-1])


def closed_type_and_order_matrix():
    batch, deadline, expiry = digest("closed-batch"), digest("closed-deadline"), "2026-08-23T12:00:00Z"
    issuer = SyntheticPrivateReceiptIssuer(batch, expiry, deadline, (90_000, 5_000, 3_000, 20_000))
    chain = SyntheticPrivateCustodyChain(batch, expiry, deadline)
    expect(SyntheticEvidenceError, chain.accept_cycle, {})
    expect(SyntheticEvidenceError, chain.accept_zero, {})
    expect(SyntheticEvidenceError, issuer.issue_zero,
           previous_custody_sha256=chain.custody_root,
           observation_sequence=1, cycle_ordinal=None,
           zero_commitment=digest("wrong-zero"))
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 1,
           mode=CycleMode.READINESS)
    cycle = issue_cycle(issuer, chain, 1)
    chain.accept_cycle(cycle)
    expect(SyntheticEvidenceError, chain.accept_cycle, cycle)
    spliced = replace(cycle, ordinal=2, mode=CycleMode.READINESS,
                      previous_custody_sha256=digest("splice"), workloads=(),
                      receipt_commitment=digest("receipt-splice"),
                      destroy_commitment=digest("destroy-splice"))
    expect(SyntheticEvidenceError, chain.accept_cycle, spliced)
    zero = issuer.issue_zero(
        previous_custody_sha256=chain.custody_root,
        observation_sequence=1, cycle_ordinal=1,
        zero_commitment=digest("closed-zero-1"))
    chain.accept_zero(zero)
    expect(SyntheticEvidenceError, chain.accept_zero, zero)


def receipt_validation_matrix():
    batch, deadline, expiry = digest("validation-batch"), digest("validation-deadline"), "2026-08-23T12:00:00Z"
    issuer = SyntheticPrivateReceiptIssuer(batch, expiry, deadline, (90_000, 5_000, 3_000, 20_000))
    chain = SyntheticPrivateCustodyChain(batch, expiry, deadline)
    good = issue_cycle(issuer, chain, 1)
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 1,
           cycle_workloads=good.workloads[:-1])
    expect(SyntheticEvidenceError, replace, good.workloads[0], deleted=False)
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 1,
           cycle_costs=(1, 1, 1, 1))
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 1,
           expiry_at="2026-08-23T12:00:01Z")
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 1,
           deadline_binding=digest("changed-deadline"))
    chain.accept_cycle(good)
    zero = issuer.issue_zero(previous_custody_sha256=chain.custody_root,
                             observation_sequence=1, cycle_ordinal=1,
                             zero_commitment=digest("validation-zero-1"))
    chain.accept_zero(zero)
    expect(SyntheticEvidenceError, issue_cycle, issuer, chain, 2,
           cycle_workloads=good.workloads)


def cross_cycle_freshness_matrix():
    issuer, chain, _cycles, _zeros = build_happy()
    # A separate chain proves duplicate private freshness is detected even when
    # each individually issued receipt is internally domain-separated.
    batch, deadline, expiry = digest("fresh-batch"), digest("fresh-deadline"), "2026-08-23T12:00:00Z"
    issuer = SyntheticPrivateReceiptIssuer(batch, expiry, deadline, issuer.rates)
    chain = SyntheticPrivateCustodyChain(batch, expiry, deadline)
    first_values = None
    for ordinal in range(1, 8):
        override = None
        if ordinal == 2:
            require(first_values is not None)
            generated = tuple(digest(f"same-{ordinal}-{name}") for name in (
                "instance", "volume", "generation", "boot", "operation",
                "client", "host", "pre-destroy"))
            override = (first_values[0], *generated[1:])
        cycle = issue_cycle(issuer, chain, ordinal, freshness_prefix="same",
                            freshness_override=override)
        if ordinal == 1:
            first_values = cycle.freshness_commitments
        chain.accept_cycle(cycle)
        zero = issuer.issue_zero(previous_custody_sha256=chain.custody_root,
                                 observation_sequence=ordinal, cycle_ordinal=ordinal,
                                 zero_commitment=digest(f"fresh-zero-{ordinal}"))
        chain.accept_zero(zero)
    final = issuer.issue_zero(previous_custody_sha256=chain.custody_root,
                              observation_sequence=8, cycle_ordinal=None,
                              zero_commitment=digest("fresh-zero-final"))
    chain.accept_zero(final)
    expect(SyntheticEvidenceError, chain.seal_fake_verdict)


def static_isolation_matrix():
    source = (ROOT / "deploy/aws-feasibility/completion_campaign_evidence.py").read_text()
    for forbidden in (
        "import subprocess", "import socket", "import boto", "import requests",
        "import urllib", "os.system(", "terraform", "opentofu", "access_key",
        "secret_key", "production_publication_authorized\": True",
    ):
        require(forbidden.lower() not in source.lower(), forbidden)
    require("PRODUCTION_AUTHORITY" in source and "production_publication_authorized\": False" in source)


def main():
    happy_matrix()
    closed_type_and_order_matrix()
    receipt_validation_matrix()
    cross_cycle_freshness_matrix()
    static_isolation_matrix()
    print("fake-only completion evidence private custody hostile matrix passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Hostile typed-evidence/private-receipt transaction tests."""
import copy
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_kata_operation as operation
import completion_kata_ssh as ssh
import completion_local_evidence as evidence
import completion_local_full as local
import completion_local_receipt as receipt_model

guest = evidence.guest


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def rejected(call, error, message):
    try:
        call()
    except error:
        return
    raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def record(sequence, kind, body):
    return operation.Record(sequence, sequence * 10, (sequence + 1) * 10,
                            sha(f"{sequence}:{kind}".encode()), kind, body)


def owner_fixture(raw=b"retired-owner-journal-A\n", token="a" * 64):
    duration_is_ns = "duration_ns" in guest.GuestSampleResult.__dataclass_fields__
    samples = tuple(guest.GuestSampleResult(
        ordinal, label, (ordinal + 10) * (1_000_000 if duration_is_ns else 1), digest, True)
        for ordinal, (label, digest) in enumerate(guest.GUEST_WORKLOAD_PLAN, 1))
    parsed = guest.GuestWorkloadResult(sha(guest.GUEST_READY_MARKER), samples)
    canonical = guest.canonical_guest_workload_result(parsed)
    session = ssh.AuthenticatedSession(
        7, "e" * 64, guest.GUEST_PROGRAM_SHA256, "f" * 64, sha(canonical), parsed)
    rows = []
    genesis = {
        "operation_token": token, "rootfs_token": "b" * 64,
        "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "1" * 40, "source_manifest_sha256": "2" * 64,
        "journal_key": {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
        "rootfs_pin": {"ustar_sha256": "3" * 64},
    }
    rows.append(record(len(rows), "GENESIS", genesis))
    rows.append(record(len(rows), "PRODUCTION_ADMISSION_V2", {
        "operation_token": token, "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
        "policy_version": operation.command_policy.POLICY_VERSION,
        "parser_source_sha256": operation.SSH_PARSER_SHA256,
    }))
    causal = record(len(rows), "NETWORK_CAUSAL_PROOF_V1", {
        "operation_token": token, "causal_proof_sha256": "a" * 64,
    })
    rows.append(causal)
    mount = record(len(rows), "RUNTIME_MOUNT_V2", {
        "operation_token": token, "manifest_sha256": "4" * 64,
        "mount_generation": {}, "issuance_sha256": "5" * 64,
    })
    rows.append(mount)
    result = record(len(rows), "SSH_RESULT_V2", {
        "operation_token": token, "command_serial": session.command_serial,
        "binding_sha256": session.binding_sha256, "manifest_sha256": "4" * 64,
        "runtime_mount_sha256": mount.line_sha256, "runtime_mount_generation": {},
        "program_sha256": guest.GUEST_PROGRAM_SHA256,
        "parser_sha256": operation.SSH_PARSER_SHA256,
        "stdout_sha256": session.stdout_sha256, "stdout_hex": "",
        "result_sha256": session.result_sha256, "canonical_result_hex": canonical.hex(),
        "proof_sha256": "6" * 64,
    })
    rows.append(result)
    rows.append(record(len(rows), "SSH_READY_V2", {
        "operation_token": token, "result_record_sha256": result.line_sha256,
        "proof_sha256": "7" * 64,
    }))
    for phase in evidence.JOURNAL_TEARDOWN_ORDER:
        body = {"operation_token": token}
        if phase == "FINAL_BASELINES":
            body["final_baselines_sha256"] = "8" * 64
        elif phase in ("RETIRE_INTENT", "RETIRED"):
            body.update(journal_key=genesis["journal_key"], final_baselines_sha256="8" * 64)
        rows.append(record(len(rows), phase, body))
    runtime = evidence._RuntimeOwnerResult(
        token, mount.line_sha256, causal.body["causal_proof_sha256"],
        "9" * 64, "c" * 64, 12, True, True)
    residue = evidence._ResidueOwnerResult(token, "8" * 64, local.RESIDUE_FACTS)
    bindings = {
        "source_head": genesis["source_revision"],
        "source_manifest_sha256": genesis["source_manifest_sha256"],
        "host_attestation_sha256": "d" * 64,
        "runtime_attestation_sha256": evidence._runtime_attestation_sha256(runtime),
        "rootfs_sha256": genesis["rootfs_pin"]["ustar_sha256"],
        "artifact_sha256": "4" * 64, "candidate_sha256": "5" * 64,
        "final_pin_sha256": "6" * 64,
        "guest_program_sha256": guest.GUEST_PROGRAM_SHA256,
        "owner_implementation_sha256": "7" * 64,
    }
    return (raw, tuple(rows), session, runtime, residue, bindings)


class Custody:
    def __init__(self, bindings, fail_close=False):
        self.bindings = copy.deepcopy(bindings)
        self.fail_close = fail_close
        self.closed = False
        self.close_attempts = 0


def binding(custody):
    if type(custody) is not Custody or custody.closed:
        raise RuntimeError("live fake custody required")
    return copy.deepcopy(custody.bindings)


def typed_bindings(values):
    return evidence._BindingOwnerResult(**values)


def close(custody):
    if type(custody) is not Custody or custody.closed:
        raise RuntimeError("fake custody replay")
    custody.close_attempts += 1
    custody.closed = True
    if custody.fail_close:
        raise OSError("injected descriptor close failure")


fixture = owner_fixture()
raw, records, session, runtime, residue, bindings = fixture
original_parse = evidence.operation._parse


def exact_parse(candidate):
    if candidate != raw:
        raise operation.OperationError()
    return records


evidence.operation._parse = exact_parse
try:
    # The only successful path starts with typed facts and emits derived V2 bytes.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    producer = take_producer()
    custody = Custody(bindings)
    owner_result = producer(custody, typed_bindings(bindings),
                            evidence._RetiredJournalOwnerResult(raw), session, runtime, residue)
    issue = take_issuer()
    private_receipt = issue(custody, owner_result)
    check(custody.closed and custody.close_attempts == 1, "custody was not closed before mint")
    report_raw = consume(private_receipt)
    report = local.load_result(report_raw)
    check(report["qualified"] is True and report["authority"] == local.AUTHORITY,
          "derived report meaning changed")
    check([row["duration_ns"] for row in report["timings"]["git"]]
          == [(ordinal + 10) * 1_000_000 for ordinal in range(1, 8)],
          "guest durations were not represented as exact nanoseconds")
    check([row["phase"] for row in report["teardown"]] == list(local.TEARDOWN_PHASES),
          "journal-to-report teardown mapping differs")
    check(evidence.REPORT_TEARDOWN_SOURCES[5] == ("RUNTIME_ABSENT",)
          and evidence.REPORT_TEARDOWN_SOURCES[6] == ("SHARE_ABSENT",)
          and evidence.REPORT_TEARDOWN_SOURCES[8] == ("RESIDUE:containerd_processes",)
          and evidence.REPORT_TEARDOWN_SOURCES[10] == (
              "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT"),
          "historical journal phase mapping was implicit")
    rejected(lambda: consume(private_receipt), receipt_model.LocalReceiptError,
             "private receipt replay succeeded")
    replay_custody = Custody(bindings)
    rejected(lambda: issue(replay_custody, owner_result), receipt_model.LocalReceiptError,
             "owner evidence replay succeeded")
    check(replay_custody.closed, "replay custody was left open")

    # Cross-custody swaps invalidate evidence and close both involved custodies.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    first, second = Custody(bindings), Custody(bindings)
    swapped = take_producer()(first, typed_bindings(bindings),
                              evidence._RetiredJournalOwnerResult(raw), session, runtime, residue)
    rejected(lambda: take_issuer()(second, swapped), receipt_model.LocalReceiptError,
             "same-binding custody swap minted a receipt")
    check(first.closed and second.closed, "swapped custodies were not both settled")
    rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
             "swap failure left a receipt")

    # A replaced journal, changed typed runtime fact, or changed custody binding mints nothing.
    for name, mutate in (
        ("journal", lambda journal, runtime_value, custody_value: (
            evidence._RetiredJournalOwnerResult(b"replaced-journal\n"), runtime_value, custody_value)),
        ("runtime", lambda journal, runtime_value, custody_value: (
            journal, evidence._RuntimeOwnerResult(runtime_value.operation_token,
                runtime_value.runtime_mount_record_sha256,
                runtime_value.network_causal_proof_sha256, "0" * 63 + "1",
                runtime_value.qemu_process_sha256, 12, True, True), custody_value)),
        ("binding", lambda journal, runtime_value, custody_value: (
            journal, runtime_value, {**custody_value, "final_pin_sha256": "0" * 64})),
    ):
        take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
        journal_value, runtime_value, custody_bindings = mutate(
            evidence._RetiredJournalOwnerResult(raw), runtime, copy.deepcopy(bindings))
        hostile_custody = Custody(custody_bindings)
        hostile = take_producer()(hostile_custody, typed_bindings(bindings),
                                  journal_value, session, runtime_value, residue)
        rejected(lambda: take_issuer()(hostile_custody, hostile), receipt_model.LocalReceiptError,
                 f"{name} substitution minted a receipt")
        check(hostile_custody.closed, f"{name} failure left custody open")
        rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
                 f"{name} failure retained minted state")

    # A custody close error happens before receipt allocation and burns the evidence.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    bad_close = Custody(bindings, fail_close=True)
    close_evidence = take_producer()(
        bad_close, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw),
        session, runtime, residue)
    rejected(lambda: take_issuer()(bad_close, close_evidence), receipt_model.LocalReceiptError,
             "custody close failure minted a receipt")
    check(bad_close.closed and bad_close.close_attempts == 1, "close failure was retried")
    rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
             "close failure retained receipt state")

    # Producer and issuer acquisition and production are all exactly one-shot.
    take_producer, take_issuer, _consume = receipt_model._new_local_receipt_routes(binding, close)
    one_producer = take_producer()
    rejected(take_producer, evidence.LocalEvidenceError, "producer was taken twice")
    one_custody = Custody(bindings)
    one_evidence = one_producer(
        one_custody, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw),
        session, runtime, residue)
    rejected(lambda: one_producer(
        one_custody, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw),
        session, runtime, residue),
        evidence.LocalEvidenceError, "producer created replacement evidence")
    one_issuer = take_issuer()
    rejected(take_issuer, receipt_model.LocalReceiptError, "receipt issuer was taken twice")
    one_receipt = one_issuer(one_custody, one_evidence)
    check(local.load_result(_consume(one_receipt))["result"] == "pass", "one-shot route failed")
finally:
    evidence.operation._parse = original_parse

source = (REMOTE / "completion_local_evidence.py").read_text()
receipt_source = (REMOTE / "completion_local_receipt.py").read_text()
for forbidden in ("report_raw", "local.load_result(", "issue(report", "caller_report", "qualified="):
    check(forbidden not in source + receipt_source, f"caller report adapter surface: {forbidden}")
check("operation._parse(journal.raw)" in source, "production operation parser is not journal authority")
check('causal = _one(records, "NETWORK_CAUSAL_PROOF_V1")' in source,
      "causal network proof is not journal-bound")
check('runtime.network_causal_proof_sha256 == causal.body["causal_proof_sha256"]' in source,
      "typed runtime can detach from causal network proof")
check("local.canonical_result(report)" in source, "derived report is not canonicalized exactly once")
check("custody_close(target)" in receipt_source, "custody closure is not transactional")
check("admission._static_custody_binding, admission._abort_static_preparation" in receipt_source,
      "production receipt realm is not bound to exact V2 static custody")
check("_execution_custody_binding" not in receipt_source,
      "historical V1 custody entered the production receipt realm")
print("completion local typed evidence and receipt tests passed")

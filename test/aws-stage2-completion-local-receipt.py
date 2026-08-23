#!/usr/bin/env python3
"""Hostile typed-evidence/private-receipt transaction tests."""
import copy
from dataclasses import replace
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
    parsed = guest.GuestWorkloadResult(
        sha(guest.GUEST_READY_MARKER), samples, guest.GUEST_NETWORK_MARKERS,
        "9" * 64, "9" * 64)
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
    rows.append(record(len(rows), "RUNTIME_READY", {
        "operation_token": token, "proof_sha256": "0" * 64,
    }))
    rows.append(record(len(rows), "COMMAND_INTENT_V2", {
        "operation_token": token, "command_id": "SSH_READY", "command_serial": 7,
    }))
    rows.append(record(len(rows), "COMMAND_OUTCOME_V2", {
        "operation_token": token, "command_id": "SSH_READY", "command_serial": 7,
        "uncertain": False,
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
        "runtime_mount_sha256": mount.body["issuance_sha256"], "runtime_mount_generation": {},
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
    ownership = record(len(rows), "OWNERSHIP_OBSERVED", {
        "operation_token": token, "proof_sha256": "c" * 64,
    })
    rows.append(ownership)
    for phase in evidence.JOURNAL_TEARDOWN_ORDER:
        body = {"operation_token": token}
        if phase == "FINAL_BASELINES":
            body["final_baselines_sha256"] = "8" * 64
        elif phase in ("RETIRE_INTENT", "RETIRED"):
            body.update(journal_key=genesis["journal_key"], final_baselines_sha256="8" * 64)
        rows.append(record(len(rows), phase, body))
    runtime = evidence._RuntimeOwnerResult(
        operation_token=token,
        runtime_mount_record_sha256=mount.body["issuance_sha256"],
        network_causal_proof_sha256=causal.body["causal_proof_sha256"],
        live_mapping_sha256="9" * 64,
        qemu_process_sha256=ownership.body["proof_sha256"],
        qemu_argv_sha256="a" * 64, qemu_pid=101, qemu_starttime=102,
        qemu_executable_device=8, qemu_executable_inode=9,
        observer_qmp_device=10, observer_qmp_inode=11,
        kvm_device=12, kvm_inode=13, kvm_rdev=14,
        kvm_api=12, qmp_present=True, qmp_enabled=True)
    platform = evidence._PlatformOwnerResult(
        operation_token=token, live_mapping_sha256=runtime.live_mapping_sha256,
        qemu_process_sha256=runtime.qemu_process_sha256,
        qemu_argv_sha256=runtime.qemu_argv_sha256,
        qemu_pid=runtime.qemu_pid, qemu_starttime=runtime.qemu_starttime,
        qemu_executable_device=runtime.qemu_executable_device,
        qemu_executable_inode=runtime.qemu_executable_inode,
        observer_qmp_device=runtime.observer_qmp_device,
        observer_qmp_inode=runtime.observer_qmp_inode,
        kvm_device=runtime.kvm_device, kvm_inode=runtime.kvm_inode,
        kvm_rdev=runtime.kvm_rdev, kvm_api=12,
        qmp_present=True, qmp_enabled=True)
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
    return (raw, tuple(rows), session, platform, runtime, residue, bindings)


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
raw, records, session, platform, runtime, residue, bindings = fixture
failure_raw = b"retired-owner-journal-certain-ssh-failure\n"
failure_records = tuple(row for row in records
                        if row.record_type not in ("SSH_RESULT_V2", "SSH_READY_V2"))
parsed_histories = {raw: records, failure_raw: failure_records}
original_parse = evidence.operation._parse


def exact_parse(candidate):
    try:
        return parsed_histories[candidate]
    except KeyError as error:
        raise operation.OperationError() from error


evidence.operation._parse = exact_parse
try:
    history = evidence._typed_durable_history(evidence._RetiredJournalOwnerResult(raw))
    # The only successful path starts with typed facts and emits derived V2 bytes.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    producer = take_producer()
    custody = Custody(bindings)
    owner_result = producer(custody, typed_bindings(bindings),
                            evidence._RetiredJournalOwnerResult(raw), history,
                            session, platform, runtime, residue)
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
    check(evidence.REPORT_TEARDOWN_SOURCES[3] == (
              "RUNTIME_ROLE_IDENTITIES_V1", "RUNTIME_ROLE_ABSENCE_V1", "RUNTIME_ABSENT")
          and evidence.REPORT_TEARDOWN_SOURCES[4] == (
              "RUNTIME_NETWORK_RELEASED_V1", "NETWORK_ABSENT")
          and evidence.REPORT_TEARDOWN_SOURCES[6] == ("SHARE_ABSENT",)
          and evidence.REPORT_TEARDOWN_SOURCES[8] == ("CONTAINERD_ABSENT",)
          and evidence.REPORT_TEARDOWN_SOURCES[10] == (
              "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT"),
          "truthful owner-derived journal phase mapping differs")
    active_binding = report["operation"]["binding_sha256"]
    for mandatory in ("RUNTIME_ROLE_ABSENCE_V1", "RUNTIME_NETWORK_RELEASED_V1",
                      "CONTAINERD_ABSENT"):
        missing = tuple(row for row in records if row.record_type != mandatory)
        rejected(lambda missing=missing: evidence._report_teardown(
            missing, residue, active_binding), evidence.LocalEvidenceError,
            f"residue substituted for applicable {mandatory}")
    ordered = list(records)
    left = next(index for index, row in enumerate(ordered)
                if row.record_type == "RUNTIME_ABSENT")
    right = next(index for index, row in enumerate(ordered)
                 if row.record_type == "RUNTIME_NETWORK_RELEASED_V1")
    ordered[left] = replace(ordered[left], sequence=ordered[right].sequence)
    ordered[right] = replace(ordered[right], sequence=records[left].sequence)
    rejected(lambda: evidence._ordered_phases(tuple(ordered)), evidence.LocalEvidenceError,
             "adjacent runtime release reorder accepted")
    rejected(lambda: consume(private_receipt), receipt_model.LocalReceiptError,
             "private receipt replay succeeded")

    # Exact retired cleanup can transactionally mint a canonical failure, but
    # only the typed durable history—not an exception, status, or report—selects
    # the first failure. Recovery has no route into this receipt realm.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    failure_journal = evidence._RetiredJournalOwnerResult(failure_raw)
    failure_history = evidence._typed_durable_history(failure_journal)
    failure_custody = Custody(bindings)
    failure_evidence = take_producer()(
        failure_custody, typed_bindings(bindings), failure_journal, failure_history,
        None, platform, runtime, residue)
    failure_receipt = take_issuer()(failure_custody, failure_evidence)
    failure_report = local.load_result(consume(failure_receipt))
    check(failure_report["result"] == "failure"
          and failure_report["failure_code"] == "ssh"
          and failure_report["qualified"] is False,
          "typed durable SSH failure did not preserve V2 semantics")
    check(all(row["outcome"] == "pass" for row in failure_report["teardown"])
          and set(failure_report["zero_residue"].values()) == {"absent"},
          "certain failure did not retain exact cleanup proof")

    # Every internal first-failure class is selected by the exact durable rows
    # and exercised through receipt issuance, not merely through a report codec.
    cleanup_kinds = set(evidence.JOURNAL_TEARDOWN_ORDER)
    terminal_rows = tuple(row for row in records if row.record_type in cleanup_kinds)
    genesis_rows = tuple(row for row in records
                         if row.record_type in {"GENESIS", "PRODUCTION_ADMISSION_V2"})

    def normalized(rows):
        return tuple(record(index, row.record_type, row.body)
                     for index, row in enumerate(rows))

    def phase(kind, body=None):
        return record(0, kind, {"operation_token": runtime.operation_token,
                                **({} if body is None else body)})

    def command(command_id, serial, status=0, lifecycle_phase=None):
        intent_body = {"operation_token": runtime.operation_token,
                       "command_id": command_id, "command_serial": serial}
        if lifecycle_phase is not None:
            intent_body["lifecycle_phase"] = lifecycle_phase
        outcome_body = {**intent_body, "outcome": "exited", "status": status,
                        "uncertain": False, "stderr_length": 0,
                        "stdout_truncated": False, "stderr_truncated": False}
        return phase("COMMAND_INTENT_V2", intent_body), phase("COMMAND_OUTCOME_V2", outcome_body)

    staged = phase("RUNTIME_STAGED_V3")
    daemon_intent = phase("COMMAND_INTENT_V2", {
        "command_id": "CONTAINERD_START", "command_serial": 40})
    daemon_retained = phase("DAEMON_RETAINED_V2", {
        "command_id": "CONTAINERD_START", "command_serial": 40})
    ctr_intent, ctr_outcome = command("CTR_RUN", 41, status=1, lifecycle_phase="NETWORK_READY")
    observer = tuple(item for command_id, serial in (
        ("CTR_CONTAINER_INFO", 50), ("CTR_CONTAINER_LIST", 51),
        ("CTR_TASK_LIST", 52))
        for item in command(command_id, serial, lifecycle_phase="RUNTIME_READY"))
    causal_row = next(row for row in records if row.record_type == "NETWORK_CAUSAL_PROOF_V1")
    ownership_row = next(row for row in records if row.record_type == "OWNERSHIP_OBSERVED")
    mount_row = next(row for row in records if row.record_type == "RUNTIME_MOUNT_V2")

    cases = {
        "input": (),
        "baseline": (phase("FS_SETTLED"), phase("INPUT_STEP", {
            "path": "@manifest", "action": "create"})),
        "network": (phase("FS_SETTLED"), phase("BASELINES_CAPTURED")),
        "containerd": (phase("FS_SETTLED"), phase("BASELINES_CAPTURED"),
                       phase("NETWORK_READY")),
        "ctr-run": (phase("FS_SETTLED"), phase("BASELINES_CAPTURED"),
                    phase("NETWORK_READY"), staged, daemon_intent,
                    daemon_retained, ctr_intent, ctr_outcome),
        "post-runtime-ready-pre-qmp": (phase("RUNTIME_READY"),),
        "qmp-kvm": (phase("RUNTIME_READY"), *observer,
                     phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-intent"}),
                     phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-failure"})),
    }

    def direct_failure(name, forward, expected_code, platform_value=None,
                       runtime_value=None):
        direct_raw = f"retired-direct-{name}\n".encode()
        direct_records = normalized((*genesis_rows, *forward, *terminal_rows))
        parsed_histories[direct_raw] = direct_records
        direct_journal = evidence._RetiredJournalOwnerResult(direct_raw)
        direct_history = evidence._typed_durable_history(direct_journal)
        check(direct_history.first_failure.classification == name,
              f"{name} durable classification differs")
        take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
        direct_custody = Custody(bindings)
        direct_evidence = take_producer()(
            direct_custody, typed_bindings(bindings), direct_journal, direct_history,
            None, platform_value, runtime_value, residue)
        direct_receipt = take_issuer()(direct_custody, direct_evidence)
        direct_report = local.load_result(consume(direct_receipt))
        check(direct_report["failure_code"] == expected_code
              and direct_report["result"] == "failure" and direct_custody.closed,
              f"{name} direct receipt differs")
        return direct_report

    for name, forward in cases.items():
        direct_failure(name, forward,
                       "kvm" if name == "qmp-kvm" else "lifecycle-start")
    # QMP itself can pass while the exact post-QMP mapping identity admission
    # fails; without durable platform-pass this remains the same public KVM code.
    identity_report = direct_failure("qmp-identity", (
        phase("RUNTIME_READY"), *observer,
        phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-intent"}),
        phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-pass"})),
        "kvm")
    check(identity_report["platform"]["qmp_present"] is True
          and identity_report["platform"]["qmp_enabled"] is True,
          "post-QMP identity failure erased exact KVM facts")

    empty_qmp_raw = b"retired-direct-empty-qmp-terminals\n"
    parsed_histories[empty_qmp_raw] = normalized((
        *genesis_rows, phase("RUNTIME_READY"),
        phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-intent"}),
        phase("PLATFORM_OBSERVATION_V1", {"observation": "qmp-failure"}),
        *terminal_rows))
    empty_qmp_journal = evidence._RetiredJournalOwnerResult(empty_qmp_raw)
    empty_qmp_history = evidence._typed_durable_history(empty_qmp_journal)
    check(empty_qmp_history.first_failure.classification == "uncertain",
          "empty observer terminals vacuously proved QMP failure")
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    empty_qmp_custody = Custody(bindings)
    empty_qmp_evidence = take_producer()(
        empty_qmp_custody, typed_bindings(bindings), empty_qmp_journal,
        empty_qmp_history, None, None, None, residue)
    rejected(lambda: take_issuer()(empty_qmp_custody, empty_qmp_evidence),
             receipt_model.LocalReceiptError,
             "empty QMP terminals minted a receipt")
    rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
             "empty QMP failure retained receipt state")

    for name in ("rootfs", "operation-open"):
        pre_history = evidence._PreOperationHistoryOwnerResult(
            name, sha((name + ":history").encode()), sha((name + ":cleanup").encode()))
        pre_residue = evidence._PreOperationResidueOwnerResult(
            pre_history.history_sha256, pre_history.cleanup_sha256,
            local.RESIDUE_FACTS)
        take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
        pre_custody = Custody(bindings)
        pre_evidence = take_producer()(
            pre_custody, typed_bindings(bindings), None, pre_history,
            None, None, None, pre_residue)
        pre_receipt = take_issuer()(pre_custody, pre_evidence)
        pre_report = local.load_result(consume(pre_receipt))
        check(pre_report["operation"]["status"] == "not-created"
              and pre_report["failure_code"] == "lifecycle-start"
              and pre_custody.closed,
              f"{name} clean pre-operation receipt differs")

    # Causal QMP success plus the absence/failure of SSH is an SSH failure;
    # platform-object presence alone never selects this class.
    direct_failure("ssh", (phase("RUNTIME_READY"), causal_row, mount_row,
                           ownership_row), "ssh", platform, runtime)

    route_digest = b"4" * 64
    network_lines = []
    for ordinal, marker in enumerate(guest.GUEST_NETWORK_MARKERS, 1):
        if ordinal in {1, len(guest.GUEST_NETWORK_MARKERS)}:
            network_lines.append(
                f"{guest.GUEST_NETWORK_PREFIX}|{ordinal:02d}|{marker}|route_sha256=".encode()
                + route_digest + b"\n")
        else:
            network_lines.append(
                f"{guest.GUEST_NETWORK_PREFIX}|{ordinal:02d}|{marker}\n".encode())

    def sample_line(global_ordinal, deleted=True):
        label, digest = guest.GUEST_WORKLOAD_PLAN[global_ordinal - 1]
        return (f"{guest.GUEST_RESULT_PREFIX}|{global_ordinal:02d}|{label}|"
                f"{1000 + global_ordinal}|{digest}|deleted="
                f"{'true' if deleted else 'false'}\n").encode()

    def workload_case(name, completed, deletion=False):
        ssh_intent, ssh_outcome = command("SSH_READY", 70, status=1,
                                          lifecycle_phase="RUNTIME_READY")
        stdout = (guest.GUEST_READY_MARKER + b"".join(network_lines)
                  + b"".join(sample_line(index) for index in range(1, completed + 1)))
        if deletion:
            stdout += sample_line(completed + 1, False)
        output = phase("COMMAND_OUTPUT_V3", {
            "command_id": "SSH_READY", "command_serial": 70,
            "stdout_hex": stdout.hex(), "stderr_hex": ""})
        forward = (phase("RUNTIME_READY"), causal_row, mount_row,
                   ssh_intent, output, ssh_outcome, ownership_row)
        report = direct_failure(name, forward, name, platform, runtime)
        return report

    git_report = workload_case("git-sample", 0)
    build_report = workload_case("build-sample", 7)
    install_report = workload_case("install-sample", 14)
    deletion_report = workload_case("deletion", 0, True)
    check(git_report["timings"]["git"][0]["outcome"] == "failure"
          and build_report["timings"]["build"][0]["outcome"] == "failure"
          and install_report["timings"]["install"][0]["outcome"] == "failure"
          and deletion_report["timings"]["git"][0]["deletion"] == "not-proved",
          "sample/deletion timing evidence differs")

    uncertain_records = tuple(
        replace(row, body={**row.body, "uncertain": True})
        if row.record_type == "COMMAND_OUTCOME_V2" else row
        for row in failure_records)
    if uncertain_records == failure_records:
        uncertain_records = (*failure_records[:-1], record(
            len(failure_records), "COMMAND_OUTCOME_V2", {
                "uncertain": True}), failure_records[-1])
    uncertain_raw = b"retired-owner-journal-uncertain\n"
    parsed_histories[uncertain_raw] = uncertain_records
    uncertain_journal = evidence._RetiredJournalOwnerResult(uncertain_raw)
    uncertain_history = evidence._typed_durable_history(uncertain_journal)
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    uncertain_custody = Custody(bindings)
    uncertain_evidence = take_producer()(
        uncertain_custody, typed_bindings(bindings), uncertain_journal,
        uncertain_history, None, platform, runtime, residue)
    rejected(lambda: take_issuer()(uncertain_custody, uncertain_evidence),
             receipt_model.LocalReceiptError,
             "uncertain durable history minted a cleanup failure receipt")
    rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
             "uncertain durable history retained receipt state")
    rejected(lambda: evidence._ResidueOwnerResult(
        runtime.operation_token, residue.final_baselines_sha256,
        local.RESIDUE_FACTS[:-1]), evidence.LocalEvidenceError,
        "incomplete residue absence became typed cleanup proof")

    replay_custody = Custody(bindings)
    rejected(lambda: issue(replay_custody, owner_result), receipt_model.LocalReceiptError,
             "owner evidence replay succeeded")
    check(replay_custody.closed, "replay custody was left open")

    # Cross-custody swaps invalidate evidence and close both involved custodies.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    first, second = Custody(bindings), Custody(bindings)
    swapped = take_producer()(first, typed_bindings(bindings),
                              evidence._RetiredJournalOwnerResult(raw), history,
                              session, platform, runtime, residue)
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
            journal, replace(runtime_value, live_mapping_sha256="0" * 63 + "1"),
            custody_value)),
        ("binding", lambda journal, runtime_value, custody_value: (
            journal, runtime_value, {**custody_value, "final_pin_sha256": "0" * 64})),
    ):
        take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
        journal_value, runtime_value, custody_bindings = mutate(
            evidence._RetiredJournalOwnerResult(raw), runtime, copy.deepcopy(bindings))
        hostile_custody = Custody(custody_bindings)
        hostile = take_producer()(hostile_custody, typed_bindings(bindings),
                                  journal_value, history, session, platform,
                                  runtime_value, residue)
        rejected(lambda: take_issuer()(hostile_custody, hostile), receipt_model.LocalReceiptError,
                 f"{name} substitution minted a receipt")
        check(hostile_custody.closed, f"{name} failure left custody open")
        rejected(lambda: consume(object()), receipt_model.LocalReceiptError,
                 f"{name} failure retained minted state")

    # A custody close error happens before receipt allocation and burns the evidence.
    take_producer, take_issuer, consume = receipt_model._new_local_receipt_routes(binding, close)
    bad_close = Custody(bindings, fail_close=True)
    close_evidence = take_producer()(
        bad_close, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw), history,
        session, platform, runtime, residue)
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
        one_custody, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw), history,
        session, platform, runtime, residue)
    rejected(lambda: one_producer(
        one_custody, typed_bindings(bindings), evidence._RetiredJournalOwnerResult(raw), history,
        session, platform, runtime, residue),
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
check("admission._static_custody_binding" in receipt_source
      and "preparation_bridge._abort_fixed_static_preparation" in receipt_source,
      "production receipt realm is not bound to exact V2 preparation custody")
check("_execution_custody_binding" not in receipt_source,
      "historical V1 custody entered the production receipt realm")
print("completion local typed evidence and receipt tests passed")

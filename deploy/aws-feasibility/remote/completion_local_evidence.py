"""Closure-private derivation of local V2 bytes from exact owner facts.

This module has no report-input route.  Its sole production route accepts typed
runtime, residue, SSH, and retired-journal results, reparses the journal with the
production codec, and freezes owner evidence for the private receipt transaction.
"""
from dataclasses import dataclass
import hashlib

import completion_kata_operation as operation
import completion_kata_ssh as ssh
import completion_local_full as local

guest = ssh.guest

RUNTIME_ATTESTATION_VERSION = "cogs.stage2-local-private-runtime-attestation/v1"
OPERATION_BINDING_VERSION = "cogs.stage2-local-private-operation-binding/v1"
JOURNAL_TEARDOWN_ORDER = (
    "READINESS_REVOKED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED",
)
REPORT_TEARDOWN_SOURCES = (
    ("READINESS_REVOKED",), ("TASK_STOPPED",), ("NETWORK_ABSENT",),
    ("TASK_ABSENT",), ("CONTAINER_ABSENT",), ("RUNTIME_ABSENT",),
    ("SHARE_ABSENT",), ("FIREWALL_ABSENT",),
    ("RESIDUE:containerd_processes",), ("INPUT_REMOVED",),
    ("ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT"),
    ("FINAL_BASELINES",), ("RETIRED",),
)


class LocalEvidenceError(Exception):
    pass


def _require(condition, message="exact typed owner evidence required"):
    if not condition:
        raise LocalEvidenceError(message)


def _digest(value):
    _require(type(value) is str and len(value) == 64
             and all(character in "0123456789abcdef" for character in value))


def _token(value):
    _digest(value)


@dataclass(frozen=True)
class _BindingOwnerResult:
    """Typed immutable admission result-binding base held through execution."""
    source_head: str
    source_manifest_sha256: str
    host_attestation_sha256: str
    runtime_attestation_sha256: str
    rootfs_sha256: str
    artifact_sha256: str
    candidate_sha256: str
    final_pin_sha256: str
    guest_program_sha256: str
    owner_implementation_sha256: str

    def __post_init__(self):
        _require(type(self.source_head) is str and len(self.source_head) == 40
                 and all(character in "0123456789abcdef" for character in self.source_head))
        for name in local.DIGEST_FIELDS:
            _digest(getattr(self, name))

    def value(self):
        return {"source_head": self.source_head,
                **{name: getattr(self, name) for name in local.DIGEST_FIELDS}}


@dataclass(frozen=True)
class _RetiredJournalOwnerResult:
    """Exact bytes retained by the operation owner after retirement."""
    raw: bytes

    def __post_init__(self):
        _require(type(self.raw) is bytes and self.raw.endswith(b"\n"))


@dataclass(frozen=True)
class _PreOperationHistoryOwnerResult:
    """Typed durable clean failure before an operation journal existed."""
    classification: str
    history_sha256: str
    cleanup_sha256: str

    def __post_init__(self):
        _require(self.classification in {"rootfs", "operation-open"})
        _digest(self.history_sha256)
        _digest(self.cleanup_sha256)


@dataclass(frozen=True)
class _PreOperationResidueOwnerResult:
    """Independent global absence after a clean pre-operation failure."""
    history_sha256: str
    cleanup_sha256: str
    absent_facts: tuple

    def __post_init__(self):
        _digest(self.history_sha256)
        _digest(self.cleanup_sha256)
        _require(type(self.absent_facts) is tuple
                 and self.absent_facts == local.RESIDUE_FACTS)


@dataclass(frozen=True)
class _DurableFirstFailure:
    """Additive internal classification derived only from durable records."""
    classification: str
    failure_code: str
    completed_samples: tuple = ()
    failed_ordinal: int | None = None
    failed_duration_ns: int | None = None
    deletion_failed: bool = False

    def __post_init__(self):
        _require(self.classification in {
            "input", "baseline", "network", "containerd", "ctr-run",
            "post-runtime-ready-pre-qmp", "qmp-kvm", "qmp-identity", "ssh",
            "git-sample", "build-sample", "install-sample", "deletion",
            "uncertain",
        })
        _require(self.failure_code in local.FAILURE_CODES)
        _require(type(self.completed_samples) is tuple
                 and all(type(row) is guest.GuestSampleResult
                         for row in self.completed_samples))
        _require(self.failed_ordinal is None or
                 type(self.failed_ordinal) is int and 1 <= self.failed_ordinal <= 21)
        _require(self.failed_duration_ns is None or
                 type(self.failed_duration_ns) is int
                 and 1 <= self.failed_duration_ns <= guest.GUEST_DURATION_LIMIT_NS)
        _require(type(self.deletion_failed) is bool)


@dataclass(frozen=True)
class _DurableHistoryOwnerResult:
    """Typed complete production parse of one exact retired journal generation."""
    journal_sha256: str
    records: tuple
    first_failure: _DurableFirstFailure | None

    def __post_init__(self):
        _digest(self.journal_sha256)
        _require(type(self.records) is tuple and self.records
                 and all(type(row) is operation.Record for row in self.records)
                 and self.records[-1].record_type == "RETIRED")
        _require(self.first_failure is None or
                 type(self.first_failure) is _DurableFirstFailure)


@dataclass(frozen=True)
class _PlatformOwnerResult:
    """Typed pre-workload runtime/QMP observation retained through teardown."""
    operation_token: str
    live_mapping_sha256: str
    qemu_process_sha256: str
    kvm_api: int
    qmp_present: bool
    qmp_enabled: bool

    def __post_init__(self):
        _token(self.operation_token)
        _digest(self.live_mapping_sha256)
        _digest(self.qemu_process_sha256)
        _require(type(self.kvm_api) is int and self.kvm_api == 12)
        _require(type(self.qmp_present) is bool and self.qmp_present is True)
        _require(type(self.qmp_enabled) is bool and self.qmp_enabled is True)


@dataclass(frozen=True)
class _RuntimeOwnerResult:
    """Causal network/runtime/QMP fact retained through exact teardown."""
    operation_token: str
    runtime_mount_record_sha256: str
    network_causal_proof_sha256: str
    live_mapping_sha256: str
    qemu_process_sha256: str
    kvm_api: int
    qmp_present: bool
    qmp_enabled: bool

    def __post_init__(self):
        _token(self.operation_token)
        for value in (self.runtime_mount_record_sha256,
                      self.network_causal_proof_sha256, self.live_mapping_sha256,
                      self.qemu_process_sha256):
            _digest(value)
        _require(type(self.kvm_api) is int and self.kvm_api == 12)
        _require(type(self.qmp_present) is bool and self.qmp_present is True)
        _require(type(self.qmp_enabled) is bool and self.qmp_enabled is True)


@dataclass(frozen=True)
class _ResidueOwnerResult:
    """Independent final observation; absence is represented by exact names."""
    operation_token: str
    final_baselines_sha256: str
    absent_facts: tuple

    def __post_init__(self):
        _token(self.operation_token)
        _digest(self.final_baselines_sha256)
        _require(type(self.absent_facts) is tuple
                 and self.absent_facts == local.RESIDUE_FACTS)


def _runtime_attestation_value(result):
    _require(type(result) is _RuntimeOwnerResult)
    return {
        "kvm_api": result.kvm_api,
        "live_mapping_sha256": result.live_mapping_sha256,
        "network_causal_proof_sha256": result.network_causal_proof_sha256,
        "operation_token": result.operation_token,
        "qemu_process_sha256": result.qemu_process_sha256,
        "qmp_enabled": result.qmp_enabled,
        "qmp_present": result.qmp_present,
        "runtime_mount_record_sha256": result.runtime_mount_record_sha256,
        "version": RUNTIME_ATTESTATION_VERSION,
    }


def _runtime_attestation_sha256(result):
    return hashlib.sha256(local._canonical(_runtime_attestation_value(result))).hexdigest()


def _one(records, kind):
    rows = [row for row in records if row.record_type == kind]
    _require(len(rows) == 1, f"one {kind} record required")
    return rows[0]


def _ordered_phases(records):
    positions = []
    for kind in JOURNAL_TEARDOWN_ORDER:
        rows = _records_of(records, kind)
        _require(len(rows) <= 1, "duplicate journal teardown phase")
        if rows:
            positions.append(rows[0].sequence)
    _require(positions == sorted(positions) and len(set(positions)) == len(positions),
             "journal teardown order differs")
    # Retirement and the rootfs/input/final boundaries are mandatory for any
    # receipt. Runtime phases that were never admitted are proved absent by the
    # independent residue owner rather than fabricated as journal work.
    _require(all(len(_records_of(records, kind)) == 1 for kind in (
        "INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
        "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED")),
        "terminal retirement boundaries absent")


def _typed_durable_history(journal):
    _require(type(journal) is _RetiredJournalOwnerResult)
    try:
        records = operation._parse(journal.raw)
    except operation.OperationError as error:
        raise LocalEvidenceError("retired operation journal invalid") from error
    _require(records and records[-1].record_type == "RETIRED")
    return _DurableHistoryOwnerResult(
        hashlib.sha256(journal.raw).hexdigest(), records,
        _durable_first_failure(records))


def _history_records(journal, history):
    _require(type(journal) is _RetiredJournalOwnerResult
             and type(history) is _DurableHistoryOwnerResult)
    _require(history.journal_sha256 == hashlib.sha256(journal.raw).hexdigest())
    reparsed = _typed_durable_history(journal)
    _require(reparsed == history, "typed durable history generation differs")
    return history.records


def _records_of(records, kind):
    return tuple(row for row in records if row.record_type == kind)


def _command_rows(records, command_id):
    intents = tuple(row for row in records
                    if row.record_type == "COMMAND_INTENT_V2"
                    and row.body.get("command_id") == command_id)
    outcomes = tuple(row for row in records
                     if row.record_type == "COMMAND_OUTCOME_V2"
                     and row.body.get("command_id") == command_id)
    return intents, outcomes


def _certain_command_outcome(records, intent):
    rows = tuple(row for row in records
                 if row.record_type == "COMMAND_OUTCOME_V2"
                 and row.body.get("command_serial") == intent.body.get("command_serial")
                 and row.body.get("command_id") == intent.body.get("command_id"))
    if len(rows) != 1 or rows[0].body.get("uncertain") is not False:
        return None
    return rows[0]


def _successful_outcome(row, allow_nonzero=False):
    body = row.body
    return (body.get("outcome") == "exited"
            and type(body.get("status")) is int
            and (allow_nonzero or body["status"] == 0)
            and body.get("uncertain") is False)


def _partial_guest_failure(records, intent, outcome):
    """Classify only an exact, durable authenticated guest-output prefix."""
    body = outcome.body
    if (body.get("outcome") != "exited" or body.get("status") == 0
            or body.get("uncertain") is not False
            or body.get("stderr_length") not in (None, 0)
            or body.get("stdout_truncated") is True
            or body.get("stderr_truncated") is True):
        return _DurableFirstFailure("ssh", "ssh")
    outputs = tuple(row for row in records
                    if row.record_type == "COMMAND_OUTPUT_V3"
                    and row.body.get("command_serial") == intent.body.get("command_serial")
                    and row.body.get("command_id") == "SSH_READY")
    if len(outputs) != 1 or type(outputs[0].body.get("stdout_hex")) is not str:
        return _DurableFirstFailure("ssh", "ssh")
    try:
        raw = bytes.fromhex(outputs[0].body["stdout_hex"])
    except ValueError:
        return _DurableFirstFailure("ssh", "ssh")
    if (not raw.endswith(b"\n") or b"\0" in raw
            or len(raw) > guest.GUEST_OUTPUT_LIMIT
            or any(byte > 127 for byte in raw)):
        return _DurableFirstFailure("ssh", "ssh")
    lines = raw.splitlines(keepends=True)
    network_count = len(guest.GUEST_NETWORK_MARKERS)
    if not lines or lines[0] != guest.GUEST_READY_MARKER:
        return _DurableFirstFailure("ssh", "ssh")
    network_lines = lines[1:1 + network_count]
    if len(network_lines) != network_count:
        return _DurableFirstFailure("ssh", "ssh")
    route_digests = []
    for ordinal, (marker, line) in enumerate(
            zip(guest.GUEST_NETWORK_MARKERS, network_lines, strict=True), 1):
        if ordinal in {1, network_count}:
            match = guest._NETWORK_ROUTE_RE.fullmatch(line[:-1])
            if (match is None or int(match.group(1)) != ordinal
                    or match.group(2).decode("ascii") != marker):
                return _DurableFirstFailure("ssh", "ssh")
            route_digests.append(match.group(3))
        else:
            expected = (f"{guest.GUEST_NETWORK_PREFIX}|{ordinal:02d}|{marker}\n"
                        .encode("ascii"))
            if line != expected:
                return _DurableFirstFailure("ssh", "ssh")
    if len(route_digests) != 2 or route_digests[0] != route_digests[1]:
        return _DurableFirstFailure("ssh", "ssh")

    completed = []
    sample_lines = lines[1 + network_count:]
    for index, line in enumerate(sample_lines):
        if index >= len(guest.GUEST_WORKLOAD_PLAN) or not line.endswith(b"\n"):
            return _DurableFirstFailure("ssh", "ssh")
        label, expected_digest = guest.GUEST_WORKLOAD_PLAN[index]
        match = guest._RESULT_RE.fullmatch(line[:-1])
        if match is None:
            return _DurableFirstFailure("ssh", "ssh")
        ordinal = index + 1
        parsed = (int(match.group(1)), line[:-1].split(b"|", 4)[2].decode("ascii"),
                  int(match.group(3)), match.group(4).decode("ascii"),
                  match.group(5) == b"true")
        if (parsed[:2] != (ordinal, label)
                or not 1 <= parsed[2] <= guest.GUEST_DURATION_LIMIT_NS
                or parsed[3] != expected_digest):
            return _DurableFirstFailure("ssh", "ssh")
        if not parsed[4]:
            return _DurableFirstFailure(
                "deletion", "deletion", tuple(completed), ordinal, parsed[2], True)
        completed.append(guest.GuestSampleResult(
            ordinal, label, parsed[2], expected_digest, True))
    if len(completed) >= len(guest.GUEST_WORKLOAD_PLAN):
        return _DurableFirstFailure("ssh", "ssh")
    failed = len(completed) + 1
    category = guest.GUEST_WORKLOAD_PLAN[failed - 1][0].partition("_")[0].lower()
    return _DurableFirstFailure(
        f"{category}-sample", f"{category}-sample", tuple(completed), failed)


def _durable_first_failure(records):
    """Return the first forward failure from records, never owner-object presence."""
    kinds = tuple(row.record_type for row in records)
    if "SSH_READY_V2" in kinds or "SSH_READY" in kinds:
        return None
    uncertain_terminals = tuple(row for row in records
                                if row.record_type in {
                                    "COMMAND_OUTCOME_V2", "DAEMON_OUTCOME_V2"}
                                and row.body.get("uncertain") is not False)
    if "UNCERTAIN" in kinds or uncertain_terminals:
        return _DurableFirstFailure("uncertain", "uncertain")

    # Work backwards from durable forward settlements.  The production parser
    # has already proved their order and lineage; cleanup records cannot invent
    # a missing forward settlement.
    if "RUNTIME_READY" in kinds:
        causal = _records_of(records, "NETWORK_CAUSAL_PROOF_V1")
        ssh_intents, _ssh_outcomes = _command_rows(records, "SSH_READY")
        if len(causal) > 1 or len(ssh_intents) > 1:
            return _DurableFirstFailure("uncertain", "uncertain")
        # The durable SSH intent can only be issued after the runtime/QMP owner
        # returned successfully. It—not a caller-supplied platform object—is
        # the QMP-to-SSH boundary for failed guest commands.
        if ssh_intents:
            terminal = _certain_command_outcome(records, ssh_intents[0])
            if terminal is None:
                return _DurableFirstFailure("uncertain", "uncertain")
            return _partial_guest_failure(records, ssh_intents[0], terminal)
        if causal:
            return _DurableFirstFailure("ssh", "ssh")

        observations = tuple(row.body.get("observation") for row in records
                             if row.record_type == "PLATFORM_OBSERVATION_V1")
        if not observations:
            return _DurableFirstFailure(
                "post-runtime-ready-pre-qmp", "lifecycle-start")
        if observations == ("qmp-intent",):
            return _DurableFirstFailure("uncertain", "uncertain")
        if observations not in {("qmp-intent", "qmp-failure"),
                                ("qmp-intent", "qmp-pass"),
                                ("qmp-intent", "qmp-pass", "platform-pass")}:
            return _DurableFirstFailure("uncertain", "uncertain")
        observer_ids = ("CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST")
        observer_rows = []
        for command_id in observer_ids:
            intents, _outcomes = _command_rows(records, command_id)
            intents = tuple(row for row in intents
                            if row.body.get("lifecycle_phase") in (None, "RUNTIME_READY"))
            if len(intents) != 1:
                return _DurableFirstFailure("uncertain", "uncertain")
            terminal = _certain_command_outcome(records, intents[0])
            if terminal is None or not _successful_outcome(
                    terminal, allow_nonzero=command_id == "CTR_CONTAINER_INFO"):
                return _DurableFirstFailure("uncertain", "uncertain")
            observer_rows.append(terminal)
        _require(observer_rows, "empty runtime terminals cannot prove QMP admission")
        if observations[-1] == "qmp-failure":
            return _DurableFirstFailure("qmp-kvm", "kvm")
        if observations[-1] != "platform-pass":
            return _DurableFirstFailure("qmp-identity", "kvm")
        return _DurableFirstFailure("ssh", "ssh")

    if "NETWORK_READY" in kinds:
        if "RUNTIME_STAGED_V3" not in kinds:
            return _DurableFirstFailure("containerd", "lifecycle-start")
        daemon_intents, _daemon_outcomes = _command_rows(records, "CONTAINERD_START")
        retained = _records_of(records, "DAEMON_RETAINED_V2")
        if len(daemon_intents) != 1 or len(retained) != 1:
            return _DurableFirstFailure("containerd", "lifecycle-start")
        ctr_intents, _ctr_outcomes = _command_rows(records, "CTR_RUN")
        if not ctr_intents:
            return _DurableFirstFailure("containerd", "lifecycle-start")
        if len(ctr_intents) != 1:
            return _DurableFirstFailure("uncertain", "uncertain")
        terminal = _certain_command_outcome(records, ctr_intents[0])
        if terminal is None:
            return _DurableFirstFailure("uncertain", "uncertain")
        return _DurableFirstFailure("ctr-run", "lifecycle-start")
    if "BASELINES_CAPTURED" in kinds:
        return _DurableFirstFailure("network", "lifecycle-start")
    input_manifest = tuple(row for row in records
                           if row.record_type == "INPUT_STEP"
                           and row.body.get("path") == "@manifest"
                           and row.body.get("action") == "create")
    if len(input_manifest) == 1:
        return _DurableFirstFailure("baseline", "lifecycle-start")
    return _DurableFirstFailure("input", "lifecycle-start")


def _report_teardown(records, residue, binding):
    rows = []
    _require(len(REPORT_TEARDOWN_SOURCES) == len(local.TEARDOWN_PHASES))
    for phase, sources in zip(local.TEARDOWN_PHASES, REPORT_TEARDOWN_SOURCES, strict=True):
        for source in sources:
            if source.startswith("RESIDUE:"):
                _require(source.removeprefix("RESIDUE:") in residue.absent_facts)
            elif not _records_of(records, source):
                # Inapplicable runtime teardown is not a vacuous journal pass:
                # every report domain is independently observed absent below.
                _require(residue.absent_facts == local.RESIDUE_FACTS)
            else:
                _one(records, source)
        rows.append({"phase": phase, "outcome": "pass", "binding_sha256": binding})
    return rows


def _operation_sha256(genesis):
    body = genesis.body
    names = ("operation_token", "rootfs_token", "host_boot_id", "source_revision",
             "source_manifest_sha256", "journal_key", "rootfs_pin")
    _require(all(name in body for name in names))
    view = {"genesis_line_sha256": genesis.line_sha256,
            "version": OPERATION_BINDING_VERSION}
    view.update((name, body[name]) for name in names)
    return hashlib.sha256(local._canonical(view)).hexdigest()


def _validate_bindings(bindings, owner_bindings, genesis, runtime):
    _require(type(owner_bindings) is _BindingOwnerResult)
    _require(type(bindings) is dict and bindings == owner_bindings.value())
    body = genesis.body
    _require(bindings["source_head"] == body["source_revision"])
    _require(bindings["source_manifest_sha256"] == body["source_manifest_sha256"])
    _require(bindings["rootfs_sha256"] == body["rootfs_pin"]["ustar_sha256"])
    _require(bindings["guest_program_sha256"] == guest.GUEST_PROGRAM_SHA256)
    _require(bindings["runtime_attestation_sha256"] == _runtime_attestation_sha256(runtime))


def _validate_session(records, session, runtime):
    _require(type(session) is ssh.AuthenticatedSession)
    mount = _one(records, "RUNTIME_MOUNT_V2")
    causal = _one(records, "NETWORK_CAUSAL_PROOF_V1")
    result = _one(records, "SSH_RESULT_V2")
    ready = _one(records, "SSH_READY_V2")
    body = result.body
    _require(runtime.runtime_mount_record_sha256 == mount.body["issuance_sha256"])
    _require(runtime.network_causal_proof_sha256 == causal.body["causal_proof_sha256"])
    _require(runtime.operation_token == mount.body["operation_token"]
             == causal.body["operation_token"] == body["operation_token"])
    _require(body["runtime_mount_sha256"] == mount.body["issuance_sha256"])
    _require(ready.body["operation_token"] == runtime.operation_token)
    _require(ready.body["result_record_sha256"] == result.line_sha256)
    _require(body["program_sha256"] == session.stdin_sha256 == guest.GUEST_PROGRAM_SHA256)
    _require(body["parser_sha256"] == operation.SSH_PARSER_SHA256)
    _require((body["command_serial"], body["binding_sha256"], body["stdout_sha256"],
              body["result_sha256"]) ==
             (session.command_serial, session.binding_sha256, session.stdout_sha256,
              session.result_sha256))
    canonical = guest.canonical_guest_workload_result(session.parsed_result)
    _require(hashlib.sha256(canonical).hexdigest() == session.result_sha256)
    _require(body["canonical_result_hex"] == canonical.hex())
    return session.parsed_result


def _timings(parsed, binding):
    _require(type(parsed) is guest.GuestWorkloadResult and len(parsed.samples) == 21)
    groups = {name: [] for name in ("git", "build", "install")}
    for row in parsed.samples:
        _require(type(row) is guest.GuestSampleResult and row.deleted is True)
        category, separator, ordinal_text = row.category.partition("_")
        _require(separator == "_" and category in ("GIT", "BUILD", "INSTALL"))
        ordinal = int(ordinal_text)
        fields = guest.GuestSampleResult.__dataclass_fields__
        _require(("duration_ns" in fields) != ("duration_ms" in fields))
        if "duration_ns" in fields:
            duration_ns = row.duration_ns
        else:
            duration_ns = row.duration_ms * 1_000_000
        _require(type(duration_ns) is int and 1 <= duration_ns <= 3_600_000_000_000)
        group = category.lower()
        _require(ordinal == len(groups[group]) + 1)
        groups[group].append({
            "binding_sha256": binding, "deletion": "absent",
            "duration_ns": duration_ns, "ordinal": ordinal, "outcome": "pass",
        })
    _require(all(len(rows) == 7 for rows in groups.values()))
    return groups


def _empty_timings(binding):
    return {
        name: [{"binding_sha256": binding, "deletion": "not-reached",
                "duration_ns": None, "ordinal": ordinal, "outcome": "not-reached"}
               for ordinal in range(1, 8)]
        for name in ("git", "build", "install")
    }


def _failure_timings(failure, binding):
    timings = _empty_timings(binding)
    for sample in failure.completed_samples:
        category, _separator, ordinal_text = sample.category.partition("_")
        group, ordinal = category.lower(), int(ordinal_text)
        timings[group][ordinal - 1] = {
            "binding_sha256": binding, "deletion": "absent",
            "duration_ns": sample.duration_ns, "ordinal": ordinal,
            "outcome": "pass",
        }
    if failure.failed_ordinal is not None:
        global_index = failure.failed_ordinal - 1
        group = ("git", "build", "install")[global_index // 7]
        ordinal = global_index % 7 + 1
        timings[group][ordinal - 1] = {
            "binding_sha256": binding,
            "deletion": "not-proved",
            "duration_ns": failure.failed_duration_ns,
            "ordinal": ordinal,
            "outcome": "pass" if failure.deletion_failed else "failure",
        }
    return timings


def _derive_failure_report(bindings, owner_bindings, journal, history,
                           session, platform, runtime, residue):
    """Derive certainty and first failure only from the typed durable history."""
    records = _history_records(journal, history)
    _require(type(owner_bindings) is _BindingOwnerResult
             and session is None
             and (platform is None or type(platform) is _PlatformOwnerResult)
             and (runtime is None or type(runtime) is _RuntimeOwnerResult)
             and type(residue) is _ResidueOwnerResult)
    kinds = tuple(row.record_type for row in records)
    failure = history.first_failure
    _require("SSH_READY_V2" not in kinds and "SSH_READY" not in kinds
             and type(failure) is _DurableFirstFailure
             and failure.classification != "uncertain")
    terminals = tuple(row for row in records
                      if row.record_type in ("COMMAND_OUTCOME_V2", "DAEMON_OUTCOME_V2"))
    _require(all(row.body.get("uncertain") is False for row in terminals),
             "uncertain command history cannot mint failure evidence")

    genesis = _one(records, "GENESIS")
    _require(genesis.sequence == 0)
    token = genesis.body["operation_token"]
    _one(records, "PRODUCTION_ADMISSION_V2")
    _ordered_phases(records)
    final = _one(records, "FINAL_BASELINES")
    retired = _one(records, "RETIRED")
    _require(residue.operation_token == token
             and residue.final_baselines_sha256 == final.body["final_baselines_sha256"]
             and retired.body["final_baselines_sha256"] == residue.final_baselines_sha256)

    bindings = dict(bindings)
    if runtime is not None:
        _require(runtime.operation_token == token)
        bindings["runtime_attestation_sha256"] = _runtime_attestation_sha256(runtime)
    if platform is not None:
        _require(platform.operation_token == token)
    if runtime is not None and platform is not None:
        _require(runtime.live_mapping_sha256 == platform.live_mapping_sha256)
    _require(bindings == owner_bindings.value())
    _require(bindings["source_head"] == genesis.body["source_revision"]
             and bindings["source_manifest_sha256"] == genesis.body["source_manifest_sha256"]
             and bindings["rootfs_sha256"] == genesis.body["rootfs_pin"]["ustar_sha256"]
             and bindings["guest_program_sha256"] == guest.GUEST_PROGRAM_SHA256)

    operation_sha256 = _operation_sha256(genesis)
    journal_sha256 = history.journal_sha256
    binding = local._binding_digest(bindings, operation_sha256, journal_sha256)
    ssh_intents = tuple(row for row in records
                        if row.record_type == "COMMAND_INTENT_V2"
                        and row.body.get("command_id") == "SSH_READY")
    _require(len(ssh_intents) <= 1)
    early = {"input", "baseline", "network", "containerd", "ctr-run",
             "post-runtime-ready-pre-qmp"}
    samples = {"git-sample", "build-sample", "install-sample", "deletion"}
    admission = {name: "pass" for name in local.ADMISSION_PHASES}
    if failure.classification in early:
        _require(session is platform is runtime is None)
        platform_value = {"kvm_api": None, "observation": "not-reached",
                          "qmp_enabled": False, "qmp_present": False}
        attempted = failure.classification in {"ctr-run", "post-runtime-ready-pre-qmp"}
        lifecycle = {"attempts": int(attempted),
                     "outcome": "failure" if attempted else "not-reached",
                     "ssh_attempts": 0, "ssh_outcome": "not-reached"}
    elif failure.classification in {"qmp-kvm", "qmp-identity"}:
        _require(session is platform is runtime is None and not ssh_intents)
        admission["kvm"] = "failure"
        identity_failure = failure.classification == "qmp-identity"
        platform_value = {"kvm_api": 12, "observation": "failure",
                          "qmp_enabled": identity_failure,
                          "qmp_present": identity_failure}
        lifecycle = {"attempts": 0, "outcome": "not-reached",
                     "ssh_attempts": 0, "ssh_outcome": "not-reached"}
    else:
        _require(failure.classification == "ssh" or
                 failure.classification in samples)
        _require(type(platform) is _PlatformOwnerResult
                 and session is None and platform.operation_token == token)
        if runtime is not None:
            _require(type(runtime) is _RuntimeOwnerResult
                     and runtime.operation_token == token
                     and runtime.live_mapping_sha256 == platform.live_mapping_sha256)
            causal = _one(records, "NETWORK_CAUSAL_PROOF_V1")
            ownership = _one(records, "OWNERSHIP_OBSERVED")
            _require(runtime.network_causal_proof_sha256 == causal.body["causal_proof_sha256"]
                     and runtime.qemu_process_sha256 == ownership.body["proof_sha256"])
        platform_value = {"kvm_api": platform.kvm_api, "observation": "pass",
                          "qmp_enabled": platform.qmp_enabled,
                          "qmp_present": platform.qmp_present}
        workload_failure = failure.classification in samples
        lifecycle = {"attempts": 1, "outcome": "pass",
                     "ssh_attempts": int(bool(ssh_intents)),
                     "ssh_outcome": ("pass" if workload_failure else
                                     "failure" if ssh_intents else "not-reached")}
    failure_code = failure.failure_code
    timings = (_failure_timings(failure, binding)
               if failure.classification in samples else _empty_timings(binding))
    teardown = _report_teardown(records, residue, binding)
    report = {
        "admission": admission, "authority": local.AUTHORITY,
        "bindings": bindings, "failure_code": failure_code,
        "lifecycle": lifecycle, "limitations": list(local.LIMITATIONS),
        "operation": {
            "binding_sha256": binding,
            "final_pin_sha256": bindings["final_pin_sha256"],
            "journal_sha256": journal_sha256,
            "operation_sha256": operation_sha256,
            "source_head": bindings["source_head"],
            "source_manifest_sha256": bindings["source_manifest_sha256"],
            "status": "retired",
        },
        "platform": platform_value, "qualified": False, "result": "failure",
        "teardown": teardown,
        "timing_summaries": {name: local._summary(rows)
                             for name, rows in timings.items()},
        "timings": timings,
        "validation_classification": local.VALIDATION_CLASSIFICATION,
        "version": local.VERSION,
        "zero_residue": {name: "absent" for name in residue.absent_facts},
    }
    return local.canonical_result(report)


def _derive_preoperation_report(bindings, owner_bindings, history,
                                session, platform, runtime, residue):
    _require(type(owner_bindings) is _BindingOwnerResult
             and type(history) is _PreOperationHistoryOwnerResult
             and type(residue) is _PreOperationResidueOwnerResult
             and session is platform is runtime is None
             and residue.history_sha256 == history.history_sha256
             and residue.cleanup_sha256 == history.cleanup_sha256
             and residue.absent_facts == local.RESIDUE_FACTS)
    bindings = dict(bindings)
    _require(bindings == owner_bindings.value())
    timings = _empty_timings(None)
    report = {
        "admission": {name: "pass" for name in local.ADMISSION_PHASES},
        "authority": local.AUTHORITY, "bindings": bindings,
        "failure_code": "lifecycle-start",
        "lifecycle": {"attempts": 0, "outcome": "not-reached",
                      "ssh_attempts": 0, "ssh_outcome": "not-reached"},
        "limitations": list(local.LIMITATIONS),
        "operation": {
            "binding_sha256": None,
            "final_pin_sha256": bindings["final_pin_sha256"],
            "journal_sha256": None, "operation_sha256": None,
            "source_head": bindings["source_head"],
            "source_manifest_sha256": bindings["source_manifest_sha256"],
            "status": "not-created",
        },
        "platform": {"kvm_api": None, "observation": "not-reached",
                     "qmp_enabled": False, "qmp_present": False},
        "qualified": False, "result": "failure",
        "teardown": [{"phase": phase, "outcome": "not-reached",
                      "binding_sha256": None}
                     for phase in local.TEARDOWN_PHASES],
        "timing_summaries": {name: local._summary(rows)
                             for name, rows in timings.items()},
        "timings": timings,
        "validation_classification": local.VALIDATION_CLASSIFICATION,
        "version": local.VERSION,
        "zero_residue": {name: "absent" for name in residue.absent_facts},
    }
    return local.canonical_result(report)


def _derive_report(bindings, owner_bindings, journal, history,
                   session, platform, runtime, residue):
    if journal is None:
        return _derive_preoperation_report(
            bindings, owner_bindings, history, session, platform, runtime, residue)
    records = _history_records(journal, history)
    if not any(row.record_type in ("SSH_READY_V2", "SSH_READY") for row in records):
        return _derive_failure_report(
            bindings, owner_bindings, journal, history,
            session, platform, runtime, residue)
    _require(type(owner_bindings) is _BindingOwnerResult
             and history.first_failure is None)
    _require(type(platform) is _PlatformOwnerResult)
    _require(type(runtime) is _RuntimeOwnerResult)
    _require(runtime.operation_token == platform.operation_token
             and runtime.live_mapping_sha256 == platform.live_mapping_sha256)
    _require(type(residue) is _ResidueOwnerResult)
    _require(operation.guest_workloads is guest, "SSH and journal guest codecs differ")
    genesis = _one(records, "GENESIS")
    _require(genesis.sequence == 0)
    token = genesis.body["operation_token"]
    _require(runtime.operation_token == residue.operation_token == token)
    _one(records, "PRODUCTION_ADMISSION_V2")
    ownership = _one(records, "OWNERSHIP_OBSERVED")
    _require(runtime.qemu_process_sha256 == ownership.body["proof_sha256"])
    _ordered_phases(records)
    final = _one(records, "FINAL_BASELINES")
    retired = _one(records, "RETIRED")
    _require(residue.final_baselines_sha256 == final.body["final_baselines_sha256"])
    _require(retired.body["final_baselines_sha256"] == residue.final_baselines_sha256)
    bindings = dict(bindings)
    bindings["runtime_attestation_sha256"] = _runtime_attestation_sha256(runtime)
    _validate_bindings(bindings, owner_bindings, genesis, runtime)
    parsed = _validate_session(records, session, runtime)
    operation_sha256 = _operation_sha256(genesis)
    journal_sha256 = hashlib.sha256(journal.raw).hexdigest()
    binding = local._binding_digest(bindings, operation_sha256, journal_sha256)
    timings = _timings(parsed, binding)
    teardown = _report_teardown(records, residue, binding)
    report = {
        "admission": {name: "pass" for name in local.ADMISSION_PHASES},
        "authority": local.AUTHORITY,
        "bindings": dict(bindings),
        "failure_code": None,
        "lifecycle": {"attempts": 1, "outcome": "pass", "ssh_attempts": 1,
                      "ssh_outcome": "pass"},
        "limitations": list(local.LIMITATIONS),
        "operation": {
            "binding_sha256": binding, "final_pin_sha256": bindings["final_pin_sha256"],
            "journal_sha256": journal_sha256, "operation_sha256": operation_sha256,
            "source_head": bindings["source_head"],
            "source_manifest_sha256": bindings["source_manifest_sha256"],
            "status": "retired",
        },
        "platform": {"kvm_api": runtime.kvm_api, "observation": "pass",
                     "qmp_enabled": runtime.qmp_enabled, "qmp_present": runtime.qmp_present},
        "qualified": True, "result": "pass", "teardown": teardown,
        "timing_summaries": {name: local._summary(rows) for name, rows in timings.items()},
        "timings": timings,
        "validation_classification": local.VALIDATION_CLASSIFICATION,
        "version": local.VERSION,
        "zero_residue": {name: "absent" for name in residue.absent_facts},
    }
    return local.canonical_result(report)


def _new_owner_evidence_routes():
    """Create one isolated evidence realm; only its receipt realm can inspect it."""
    seal, states = object(), {}
    producer_taken = False

    class _OwnerExecutionEvidence:
        __slots__ = ()

        def __new__(cls, key=None):
            _require(key is seal, "sealed owner execution evidence")
            return super().__new__(cls)

    class _Producer:
        __slots__ = ("_used",)

        def __new__(cls, key=None):
            _require(key is seal, "sealed owner evidence producer")
            value = super().__new__(cls)
            value._used = False
            return value

        def __call__(self, custody, owner_bindings, journal, history,
                     session, platform, runtime, residue):
            _require(not self._used, "owner evidence producer already used")
            self._used = True
            _require(type(owner_bindings) is _BindingOwnerResult)
            preoperation = type(history) is _PreOperationHistoryOwnerResult
            _require((preoperation and journal is None
                      and type(residue) is _PreOperationResidueOwnerResult)
                     or (not preoperation
                         and type(journal) is _RetiredJournalOwnerResult
                         and type(history) is _DurableHistoryOwnerResult
                         and type(residue) is _ResidueOwnerResult))
            _require(session is None or type(session) is ssh.AuthenticatedSession)
            _require(platform is None or type(platform) is _PlatformOwnerResult)
            _require(runtime is None or type(runtime) is _RuntimeOwnerResult)
            evidence = _OwnerExecutionEvidence(seal)
            states[evidence] = (custody, owner_bindings, journal, history,
                                session, platform, runtime, residue)
            return evidence

    def take_producer():
        nonlocal producer_taken
        _require(not producer_taken, "owner evidence producer already taken")
        producer_taken = True
        return _Producer(seal)

    def associated_custody(evidence):
        state = states.get(evidence)
        _require(type(evidence) is _OwnerExecutionEvidence and state is not None)
        return state[0]

    def prepare(custody, evidence, bindings):
        state = states.get(evidence)
        _require(type(evidence) is _OwnerExecutionEvidence and state is not None)
        _require(state[0] is custody, "owner evidence and custody were swapped")
        raw = _derive_report(bindings, *state[1:])
        return raw, hashlib.sha256(raw).hexdigest()

    def commit(evidence):
        state = states.pop(evidence, None)
        _require(type(evidence) is _OwnerExecutionEvidence and state is not None)

    def discard(evidence):
        states.pop(evidence, None)

    return take_producer, associated_custody, prepare, commit, discard

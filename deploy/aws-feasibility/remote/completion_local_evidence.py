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
        row = _one(records, kind)
        positions.append(row.sequence)
    _require(positions == sorted(positions) and len(set(positions)) == len(positions),
             "journal teardown order differs")


def _report_teardown(records, residue, binding):
    rows = []
    _require(len(REPORT_TEARDOWN_SOURCES) == len(local.TEARDOWN_PHASES))
    for phase, sources in zip(local.TEARDOWN_PHASES, REPORT_TEARDOWN_SOURCES, strict=True):
        for source in sources:
            if source.startswith("RESIDUE:"):
                _require(source.removeprefix("RESIDUE:") in residue.absent_facts)
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


def _derive_report(bindings, owner_bindings, journal, session, runtime, residue):
    _require(type(owner_bindings) is _BindingOwnerResult)
    _require(type(journal) is _RetiredJournalOwnerResult)
    _require(type(runtime) is _RuntimeOwnerResult)
    _require(type(residue) is _ResidueOwnerResult)
    _require(operation.guest_workloads is guest, "SSH and journal guest codecs differ")
    try:
        records = operation._parse(journal.raw)
    except operation.OperationError as error:
        raise LocalEvidenceError("retired operation journal invalid") from error
    _require(records and records[-1].record_type == "RETIRED")
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

        def __call__(self, custody, owner_bindings, journal, session, runtime, residue):
            _require(not self._used, "owner evidence producer already used")
            self._used = True
            _require(type(owner_bindings) is _BindingOwnerResult)
            _require(type(journal) is _RetiredJournalOwnerResult)
            _require(type(session) is ssh.AuthenticatedSession)
            _require(type(runtime) is _RuntimeOwnerResult)
            _require(type(residue) is _ResidueOwnerResult)
            evidence = _OwnerExecutionEvidence(seal)
            states[evidence] = (custody, owner_bindings, journal, session, runtime, residue)
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

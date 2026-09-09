"""Closed production campaign contracts and the sole seven-cycle state machine.

This module is provider-neutral, but not synthetic: concrete ports are issued only
by the dormant AWS adapter.  Tests receive a separately labelled test issuer.
No callback may relabel a receipt; every effect carries the complete one-shot
grant and durable intent/settlement identity.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import runpy

APPROVAL_PHRASE = "run-seven-sequential-stage2-completion-launches"
VERSION = "cogs.stage2-completion-production-controller/v2"
CYCLE_MODES = ("full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness")
INVENTORY_CATEGORIES = (
    "ec2_instances", "ebs_volumes", "network_interfaces", "eni_public_associations",
    "elastic_ips", "security_groups", "vpcs", "subnets", "internet_gateways",
    "route_tables", "routes", "launch_templates", "key_pairs", "iam_roles",
    "iam_role_policies", "iam_policy_attachments", "iam_instance_profiles",
    "eventbridge_schedules", "eventbridge_targets", "budgets", "ssm_managed_instances",
)
EFFECT_KINDS = ("plan", "apply", "running", "destroy")
FULL_PROGRAM_SHA256 = "0e62df128ab166344e4a8e20aa9c92b376fbf96ba8454f73cec66ca1b5678406"
FULL_MARKER_SHA256 = "35f125d7914d134854e532a08398153ffcd699426fbeeabcb7c35d7f4ec474f5"
READINESS_PROGRAM_SHA256 = "386f9398688cad05dfc0921ad0e5aa442cf146fd7ff16ddd82a7683244da6bab"
READINESS_MARKER_SHA256 = "b5b71497621037e6b7eada7c581962775625d532cdc06729dfd095e6a6f7c010"
REMOTE_PARSERS = {
    "full": "a134e1b00791b4cccf37206284f36dc685056f8a57aebc13173f09285292a35c",
    "readiness": "500423ea45a3c12da1eaf107281a966e88f21f77701524f2d8617d0456f68e4c",
}
REMOTE_PROGRAMS = {
    "full": (FULL_PROGRAM_SHA256, FULL_MARKER_SHA256),
    "readiness": (READINESS_PROGRAM_SHA256, READINESS_MARKER_SHA256),
}
_DIGEST_CHARS = frozenset("0123456789abcdef")


class ProductionCampaignError(Exception): pass
class ProductionApprovalError(ProductionCampaignError): pass
class ProductionReceiptError(ProductionCampaignError): pass
class ProductionUncertainty(ProductionCampaignError): pass


def _require(condition, error=ProductionCampaignError):
    if not condition: raise error()


def _digest(value):
    _require(type(value) is str and len(value) == 64 and set(value) <= _DIGEST_CHARS)
    return value


def _sha1(value):
    _require(type(value) is str and len(value) == 40 and set(value) <= _DIGEST_CHARS)
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _commit(domain, value):
    return hashlib.sha256(domain + b"\0" + _canonical(value)).hexdigest()


def _runtime_identity(value):
    fields = {name: getattr(value, name) for name in (
        "qemu_argv_sha256", "qemu_pid",
        "qemu_starttime", "qemu_executable_device", "qemu_executable_inode",
        "observer_qmp_device", "observer_qmp_inode", "kvm_device", "kvm_inode",
        "kvm_rdev", "kvm_api", "qmp_present", "qmp_enabled")}
    return hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + _canonical(fields) + b"\n").hexdigest()


def _cycle_capability(mode, program, marker):
    return hashlib.sha256(b"cogs.stage2-cycle-route/v1\0production\0" +
                          mode.encode("ascii") + bytes.fromhex(program) +
                          bytes.fromhex(marker)).hexdigest()


def _approval_fields(value):
    result = asdict(value) if type(value) is ProductionApproval else dict(value)
    for name in ("batch_commitment", "plan_sha256s", "version", "phrase",
                 "rate_source_commitment", "issuer_commitment", "one_attempt"):
        result.pop(name, None)
    return result


FIXED_RATE_MICRO_USD_PER_HOUR = 118_000
RATE_SOURCE_COMMITMENT = _commit(
    b"cogs.stage2-fixed-rate/v1",
    {"micro_usd_per_hour": FIXED_RATE_MICRO_USD_PER_HOUR})


def approval_batch_commitment(value):
    return _commit(b"cogs.stage2-production-approved-batch/v5", _approval_fields(value))


def executor_principal_commitment(partition, account_id, role_name):
    _require(partition in {"aws", "aws-us-gov"}
             and type(account_id) is str and re.fullmatch(r"[0-9]{12}", account_id)
             and type(role_name) is str
             and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role_name),
             ProductionApprovalError)
    return _commit(b"cogs.stage2-executor-principal/v1", {
        "partition": partition, "account_id": account_id, "role_name": role_name})


def resolved_ami_commitment(value):
    fields = {
        "partition": value.partition if hasattr(value, "partition") else value["partition"],
        "owner_id": value.ami_owner_id if hasattr(value, "ami_owner_id") else value["ami_owner_id"],
        "region": value.region if hasattr(value, "region") else value["region"],
        "image_id": value.ami_id if hasattr(value, "ami_id") else value["ami_id"],
        "architecture": value.ami_architecture if hasattr(value, "ami_architecture") else value["ami_architecture"],
        "virtualization_type": (value.ami_virtualization_type if hasattr(value, "ami_virtualization_type")
                                else value["ami_virtualization_type"]),
        "root_device_type": (value.ami_root_device_type if hasattr(value, "ami_root_device_type")
                             else value["ami_root_device_type"]),
        "state": value.ami_state if hasattr(value, "ami_state") else value["ami_state"],
    }
    return _commit(b"cogs.stage2-resolved-ami/v1", fields)


@dataclass(frozen=True)
class ProductionApproval:
    version: str
    phrase: str
    batch_commitment: str
    implementation_revision: str
    control_revision: str
    qualification_revision: str
    source_manifest_sha256: str
    source_bindings_sha256: str
    static_control_sha256: str
    pre_aws_package_sha256: str
    rootfs_descriptor_sha256: str
    rootfs_package_manifest_sha256: str
    rootfs_provenance_sha256: str
    rootfs_qualification_receipt_sha256: str
    rootfs_publication_receipt_sha256: str
    runtime_manifest_sha256: str
    fixture_commitment: str
    provider_binary_sha256: str
    aws_cli_sha256: str
    account_commitment: str
    partition: str
    region: str
    ami_id: str
    ami_owner_id: str
    ami_architecture: str
    ami_virtualization_type: str
    ami_root_device_type: str
    ami_state: str
    ami_commitment: str
    plan_sha256s: tuple[str, ...]
    not_before_unix_ns: int
    effect_deadline_ns: int
    cleanup_reserve_ns: int
    expires_unix_ns: int
    maximum_cycle_duration_ns: int
    maximum_cost_micro_usd: int
    rate_source_commitment: str
    issuer_commitment: str
    executor_principal_commitment: str
    inventory_observer_principal_commitment: str
    one_attempt: bool

    def __post_init__(self):
        _require(self.version == "cogs.stage2-completion-production-approval/v5"
                 and self.phrase == APPROVAL_PHRASE and self.one_attempt is True,
                 ProductionApprovalError)
        _digest(self.batch_commitment); _sha1(self.implementation_revision); _sha1(self.control_revision)
        _sha1(self.qualification_revision)
        _require(len({self.implementation_revision, self.control_revision,
                      self.qualification_revision}) == 3, ProductionApprovalError)
        for item in (
            self.source_manifest_sha256, self.source_bindings_sha256,
            self.static_control_sha256,
            self.pre_aws_package_sha256, self.rootfs_descriptor_sha256,
            self.rootfs_package_manifest_sha256, self.rootfs_provenance_sha256,
            self.rootfs_qualification_receipt_sha256,
            self.rootfs_publication_receipt_sha256, self.runtime_manifest_sha256,
            self.fixture_commitment, self.provider_binary_sha256, self.aws_cli_sha256,
            self.account_commitment,
            self.ami_commitment, self.rate_source_commitment,
            self.issuer_commitment, self.executor_principal_commitment,
            self.inventory_observer_principal_commitment,
        ): _digest(item)
        _require(self.partition in {"aws", "aws-us-gov"}
                 and type(self.region) is str
                 and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9]", self.region)
                 and type(self.ami_id) is str
                 and re.fullmatch(r"ami-[0-9a-f]{17}", self.ami_id)
                 and self.ami_owner_id == "099720109477"
                 and self.ami_architecture == "x86_64"
                 and self.ami_virtualization_type == "hvm"
                 and self.ami_root_device_type == "ebs"
                 and self.ami_state == "available"
                 and self.ami_commitment == resolved_ami_commitment(self),
                 ProductionApprovalError)
        _require(type(self.plan_sha256s) is tuple and len(self.plan_sha256s) == 7
                 and len(set(self.plan_sha256s)) == 7, ProductionApprovalError)
        for item in self.plan_sha256s: _digest(item)
        _require(type(self.not_before_unix_ns) is int and self.not_before_unix_ns > 0
                 and type(self.effect_deadline_ns) is int
                 and type(self.cleanup_reserve_ns) is int
                 and type(self.expires_unix_ns) is int
                 and 0 < self.effect_deadline_ns <= 320 * 60 * 1_000_000_000
                 and 5 * 60 * 1_000_000_000 <= self.cleanup_reserve_ns <= 30 * 60 * 1_000_000_000
                 and self.not_before_unix_ns + self.effect_deadline_ns + self.cleanup_reserve_ns
                     <= self.expires_unix_ns
                 and type(self.maximum_cycle_duration_ns) is int
                 and 0 < self.maximum_cycle_duration_ns <= 150 * 60 * 1_000_000_000
                 and self.maximum_cycle_duration_ns <= self.effect_deadline_ns
                 and type(self.maximum_cost_micro_usd) is int
                 and 0 < self.maximum_cost_micro_usd < 500_000
                 and self.maximum_cost_micro_usd >= (
                    (self.effect_deadline_ns + self.cleanup_reserve_ns)
                    * FIXED_RATE_MICRO_USD_PER_HOUR + 3_600_000_000_000 - 1) // 3_600_000_000_000
                 and self.rate_source_commitment == RATE_SOURCE_COMMITMENT,
                 ProductionApprovalError)
        _require(self.batch_commitment == approval_batch_commitment(self),
                 ProductionApprovalError)


@dataclass(frozen=True)
class ApprovalConsumptionReceipt:
    approval_commitment: str
    authentication_receipt_sha256: str
    durable_record_commitment: str
    consumed_unix_ns: int
    first_created: bool

    def __post_init__(self):
        _digest(self.approval_commitment); _digest(self.authentication_receipt_sha256)
        _digest(self.durable_record_commitment)
        _require(type(self.consumed_unix_ns) is int and self.consumed_unix_ns > 0
                 and self.first_created is True, ProductionReceiptError)


@dataclass(frozen=True)
class CycleLaunchGrant:
    batch_commitment: str
    ordinal: int
    mode: str
    implementation_revision: str
    control_revision: str
    static_control_sha256: str
    rootfs_descriptor_sha256: str
    ami_commitment: str
    plan_sha256: str
    grant_commitment: str

    def __post_init__(self):
        _digest(self.batch_commitment); _sha1(self.implementation_revision); _sha1(self.control_revision)
        for item in (self.static_control_sha256, self.rootfs_descriptor_sha256,
                     self.ami_commitment, self.plan_sha256, self.grant_commitment): _digest(item)
        _require(type(self.ordinal) is int and 1 <= self.ordinal <= 7
                 and self.mode == CYCLE_MODES[self.ordinal - 1])
        fields = asdict(self); fields.pop("grant_commitment")
        _require(self.grant_commitment == _commit(
            b"cogs.stage2-cycle-launch-grant/v1", fields))


@dataclass(frozen=True)
class EffectReceipt:
    kind: str
    grant_commitment: str
    batch_commitment: str
    ordinal: int
    mode: str
    state_commitment: str
    state_bytes_sha256: str
    state_lineage_commitment: str
    identity_commitment: str
    intent_commitment: str
    settlement_commitment: str
    ami_commitment: str
    resource_commitments: tuple[tuple[str, str], ...]
    observed_started_unix_ns: int
    observed_ended_unix_ns: int
    invocation_count: int
    certain: bool

    def __post_init__(self):
        for item in (self.grant_commitment, self.batch_commitment,
                     self.state_commitment, self.state_bytes_sha256, self.state_lineage_commitment,
                     self.identity_commitment, self.intent_commitment,
                     self.settlement_commitment, self.ami_commitment): _digest(item)
        _require(type(self.resource_commitments) is tuple
                 and all(type(row) is tuple and len(row) == 2
                         and type(row[0]) is str and _digest(row[1]) == row[1]
                         for row in self.resource_commitments)
                 and tuple(name for name, _value in self.resource_commitments) ==
                     tuple(sorted({name for name, _value in self.resource_commitments})),
                 ProductionReceiptError)
        expected_resources = ({"instance", "root_volume", "launch_template_generation"}
                              if self.kind == "running" else
                              {"pre_destroy_receipt"} if self.kind == "destroy" else set())
        _require({name for name, _value in self.resource_commitments} == expected_resources,
                 ProductionReceiptError)
        _require(self.kind in EFFECT_KINDS and type(self.ordinal) is int
                 and 1 <= self.ordinal <= 7
                 and self.mode == CYCLE_MODES[self.ordinal - 1]
                 and type(self.observed_started_unix_ns) is int
                 and type(self.observed_ended_unix_ns) is int
                 and 0 < self.observed_started_unix_ns < self.observed_ended_unix_ns
                 and type(self.invocation_count) is int
                 and self.invocation_count == 1 and self.certain is True,
                 ProductionReceiptError)


@dataclass(frozen=True)
class WorkloadMeasurement:
    category: str
    ordinal: int
    duration_ns: int
    commitment: str

    def __post_init__(self):
        _require(self.category in {"git", "build", "install"}
                 and 1 <= self.ordinal <= 7 and type(self.duration_ns) is int
                 and self.duration_ns > 0, ProductionReceiptError)
        _digest(self.commitment)


@dataclass(frozen=True)
class RemoteSourceBindings:
    source_head: str
    source_manifest_sha256: str
    host_attestation_sha256: str
    runtime_manifest_sha256: str
    rootfs_sha256: str
    rootfs_descriptor_sha256: str
    rootfs_package_manifest_sha256: str
    rootfs_provenance_sha256: str
    rootfs_publication_receipt_sha256: str
    artifact_sha256: str
    candidate_sha256: str
    final_pin_sha256: str
    guest_program_sha256: str
    owner_implementation_sha256: str

    def __post_init__(self):
        _sha1(self.source_head)
        for name, item in asdict(self).items():
            if name != "source_head": _digest(item)


QUALIFICATION_PACKAGE_VERSION = "cogs.stage2-pre-aws-qualification-package/v5"
QUALIFICATION_PACKAGE_NAME = "pre-aws-package-v5.json"
QUALIFICATION_RESULT_SCHEMA_SHA256 = "20d11acd19655cd1fc424aea710d98334d2deeff98db1942e0f4fe53807a4e1f"
_QUALIFICATION_ROOT = Path(__file__).resolve().parents[2]


def _qualification_keys(value, names):
    _require(type(value) is dict and value.keys() == set(names), ProductionApprovalError)


def _qualification_positive(value):
    _require(type(value) is int and value > 0, ProductionApprovalError)


def _qualification_archive(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
             ProductionApprovalError)


def qualification_source_bindings(package):
    """Strict, provider-free validation of the complete current v5 prerequisite.

    Only fixed local policy/contract files are read. Recompute every commitment
    represented by this projection; receipt/status/archive bytes themselves are
    authenticated upstream, not recoverable from their hashes here. Consensus
    among substituted rows cannot replace the current workflow/schema contract.
    This check grants neither artifact authenticity nor execution authority.
    """
    _qualification_keys(package, (
        "version", "authority", "implementation_revision", "control_revision",
        "qualification_revision", "source_manifest_sha256", "static_control_sha256",
        "workflow_sha256", "result_schema_sha256", "rootfs_descriptor_sha256",
        "runtime_manifest_sha256", "fixture_commitment", "source_bindings",
        "cycle_artifact_custody", "mixed_preflight_run_id", "static_control_observation",
        "cycle_artifact_custody_sha256", "batch_commitment", "cycle_count",
        "workload_measurements", "cycles", "predecessor_versions", "claims"))
    _require(package.get("version") == QUALIFICATION_PACKAGE_VERSION
             and package.get("authority") == "non-aws-prerequisite-evidence-only"
             and type(package.get("cycle_count")) is int and package["cycle_count"] == 7
             and type(package.get("workload_measurements")) is int
             and package["workload_measurements"] == 21
             and type(package.get("claims")) is dict
             and package["claims"].keys() == {
                 "formal_non_aws_qualification_passed", "aws_authorized", "aws_executed",
                 "provider_executed", "promotion_authorized"}
             and package["claims"]["formal_non_aws_qualification_passed"] is True
             and all(package["claims"][name] is False for name in (
                 "aws_authorized", "aws_executed", "provider_executed", "promotion_authorized"))
             and "runtime_commitment" not in package
             and "runtime_attestation_sha256" not in package,
             ProductionApprovalError)
    bindings = package.get("source_bindings")
    _require(type(bindings) is dict
             and bindings.keys() == RemoteSourceBindings.__dataclass_fields__.keys(),
             ProductionApprovalError)
    source = RemoteSourceBindings(**bindings)
    revisions = tuple(package.get(name) for name in (
        "implementation_revision", "control_revision", "qualification_revision"))
    for revision in revisions: _sha1(revision)
    _require(len(set(revisions)) == 3
             and source.source_head == revisions[0]
             and source.source_manifest_sha256 == package.get("source_manifest_sha256")
             and source.rootfs_descriptor_sha256 == package.get("rootfs_descriptor_sha256")
             and source.runtime_manifest_sha256 == package.get("runtime_manifest_sha256")
             and source.final_pin_sha256 == package.get("fixture_commitment")
             and source.guest_program_sha256 == FULL_PROGRAM_SHA256,
             ProductionApprovalError)
    for name in ("source_manifest_sha256", "static_control_sha256", "workflow_sha256",
                 "result_schema_sha256", "rootfs_descriptor_sha256", "runtime_manifest_sha256",
                 "fixture_commitment", "cycle_artifact_custody_sha256", "batch_commitment"):
        _digest(package[name])
    _require(type(package["predecessor_versions"]) is list and package["predecessor_versions"] == [
        f"cogs.stage2-pre-aws-qualification-package/v{version}" for version in range(1, 5)],
        ProductionApprovalError)
    try:
        workflow_raw = (_QUALIFICATION_ROOT /
            ".github/workflows/stage2-prebuilt-local-kata-qualification.yml").read_bytes()
        schema_raw = (_QUALIFICATION_ROOT /
            "schemas/stage2-formal-local-cycle-receipt-v2.json").read_bytes()
    except OSError as error:
        raise ProductionApprovalError() from error
    _require(package["workflow_sha256"] == hashlib.sha256(workflow_raw).hexdigest()
             and package["result_schema_sha256"] == hashlib.sha256(schema_raw).hexdigest()
             == QUALIFICATION_RESULT_SCHEMA_SHA256, ProductionApprovalError)

    custody = package["cycle_artifact_custody"]
    _qualification_keys(custody, ("version", "authority", "repository", "workflow_run", "artifacts"))
    _require(custody["version"] == "cogs.stage2-formal-local-artifact-custody/v2"
             and custody["authority"] == "authenticated-github-actions-api-cycle-artifact-custody-only"
             and custody["repository"] == "nenb/cogs", ProductionApprovalError)
    run = custody["workflow_run"]
    _qualification_keys(run, ("id", "attempt", "head_sha"))
    _qualification_positive(run["id"])
    _require(type(run["attempt"]) is int and run["attempt"] == 1
             and run["head_sha"] == revisions[2], ProductionApprovalError)
    observation = package["static_control_observation"]
    _qualification_keys(observation, ("run_id", "artifact_id", "artifact_archive_digest"))
    _qualification_positive(observation["run_id"])
    _qualification_positive(observation["artifact_id"])
    _qualification_positive(package["mixed_preflight_run_id"])
    _qualification_archive(observation["artifact_archive_digest"])
    runs = (run["id"], observation["run_id"], package["mixed_preflight_run_id"])
    _require(len(set(runs)) == 3, ProductionApprovalError)
    _require(type(custody["artifacts"]) is list and len(custody["artifacts"]) == 7
             and type(package["cycles"]) is list and len(package["cycles"]) == 7,
             ProductionApprovalError)

    # Same domains and ordinal spelling as FormalCycleGrant, without acquiring
    # (or importing a claim seam for) any formal or production authority.
    batch_fields = {name: package[name] for name in (
        "implementation_revision", "control_revision", "source_manifest_sha256",
        "static_control_sha256", "workflow_sha256", "result_schema_sha256",
        "rootfs_descriptor_sha256")}
    batch_fields.update(authority="non-cloud-formal-qualification-cycle-only",
                        workflow_run_id=run["id"], workflow_run_attempt=1)
    batch = _commit(b"cogs.stage2-formal-local-qualification-batch/v1", batch_fields)
    _require(package["batch_commitment"] == batch, ProductionApprovalError)
    identities = {name: set() for name in (
        "host_boot_id", "operation", "rootfs", "runtime", "client_key", "host_key")}
    artifact_ids = {observation["artifact_id"]}
    archives = {observation["artifact_archive_digest"]}
    receipt_hashes, status_hashes, grants = set(), set(), set()
    for ordinal, (cycle, artifact) in enumerate(zip(package["cycles"], custody["artifacts"]), 1):
        _qualification_keys(cycle, ("ordinal", "mode", "grant_commitment", "receipt_sha256",
            "status_sha256", "artifact_name", "artifact_id", "artifact_archive_digest", "identities"))
        _qualification_keys(artifact, ("ordinal", "name", "artifact_id", "archive_digest"))
        name = f"stage2-formal-cycle-{ordinal}-{revisions[0]}-{revisions[1]}-{run['id']}-1"
        _require(type(cycle["ordinal"]) is type(artifact["ordinal"]) is int
                 and cycle["ordinal"] == artifact["ordinal"] == ordinal
                 and cycle["mode"] == CYCLE_MODES[ordinal - 1]
                 and cycle["artifact_name"] == artifact["name"] == name,
                 ProductionApprovalError)
        _qualification_positive(cycle["artifact_id"])
        _qualification_positive(artifact["artifact_id"])
        _qualification_archive(cycle["artifact_archive_digest"])
        _qualification_archive(artifact["archive_digest"])
        _require(cycle["artifact_id"] == artifact["artifact_id"]
                 and cycle["artifact_archive_digest"] == artifact["archive_digest"],
                 ProductionApprovalError)
        for field in ("grant_commitment", "receipt_sha256", "status_sha256"):
            _digest(cycle[field])
        grant = _commit(b"cogs.stage2-formal-local-cycle-grant/v1", {
            **batch_fields, "batch_commitment": batch, "ordinal": ordinal,
            "mode": CYCLE_MODES[ordinal - 1]})
        _require(cycle["grant_commitment"] == grant, ProductionApprovalError)
        artifact_ids.add(cycle["artifact_id"]); archives.add(cycle["artifact_archive_digest"])
        receipt_hashes.add(cycle["receipt_sha256"]); status_hashes.add(cycle["status_sha256"])
        grants.add(grant)
        _qualification_keys(cycle["identities"], identities)
        for role, seen in identities.items():
            identity = cycle["identities"][role]
            if role == "host_boot_id":
                _require(type(identity) is str and re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", identity)
                    is not None, ProductionApprovalError)
            else: _digest(identity)
            seen.add(identity)
    _require(len(artifact_ids) == len(archives) == 8
             and len(receipt_hashes) == len(status_hashes) == len(grants) == 7
             and len(receipt_hashes | status_hashes) == 14
             and all(len(seen) == 7 for seen in identities.values())
             and len(identities["operation"] | identities["rootfs"]) == 14
             and len(identities["client_key"] | identities["host_key"]) == 14
             and source.runtime_manifest_sha256 not in identities["runtime"]
             and package["cycle_artifact_custody_sha256"] == hashlib.sha256(
                 _canonical(custody) + b"\n").hexdigest(), ProductionApprovalError)
    try:
        retirement = runpy.run_path(str(_QUALIFICATION_ROOT / "scripts/stage2-revision-retirement.py"))
        retirement["select"](revisions, runs=tuple(str(item) for item in runs),
                             artifacts=tuple(str(item) for item in artifact_ids))
    except (OSError, TypeError, ValueError) as error:
        raise ProductionApprovalError() from error
    return source


def validate_approval_package(approval, package, package_sha256):
    """Bind exact prerequisite bytes to the separately authenticated v5 approval.

    Never compare a qualification execution identity to a production cycle.
    Authentication of approval bytes remains the sealed adapter's responsibility.
    """
    _require(type(approval) is ProductionApproval, ProductionApprovalError)
    source = qualification_source_bindings(package)
    _require(package_sha256 == hashlib.sha256(_canonical(package) + b"\n").hexdigest()
             == approval.pre_aws_package_sha256
             and all(package[name] == getattr(approval, name) for name in (
                 "implementation_revision", "control_revision", "qualification_revision",
                 "source_manifest_sha256", "static_control_sha256", "rootfs_descriptor_sha256",
                 "runtime_manifest_sha256", "fixture_commitment"))
             and _commit(b"cogs.stage2-source-bindings/v1", asdict(source)) ==
                 approval.source_bindings_sha256
             and all(getattr(source, name) == getattr(approval, name) for name in (
                 "rootfs_package_manifest_sha256", "rootfs_provenance_sha256",
                 "rootfs_publication_receipt_sha256")), ProductionApprovalError)


@dataclass(frozen=True)
class RemoteQemuBindings:
    operation_token: str
    live_mapping_sha256: str
    runtime_identity_sha256: str
    pre_ssh_runtime_fact_sha256: str
    post_ssh_runtime_fact_sha256: str | None
    qemu_argv_sha256: str
    qemu_pid: int
    qemu_starttime: int
    qemu_executable_device: int
    qemu_executable_inode: int
    observer_qmp_device: int
    observer_qmp_inode: int
    kvm_device: int
    kvm_inode: int
    kvm_rdev: int
    kvm_api: int
    qmp_present: bool
    qmp_enabled: bool

    def __post_init__(self):
        for item in (self.operation_token, self.live_mapping_sha256,
                     self.runtime_identity_sha256, self.pre_ssh_runtime_fact_sha256,
                     self.qemu_argv_sha256): _digest(item)
        if self.post_ssh_runtime_fact_sha256 is not None:
            _digest(self.post_ssh_runtime_fact_sha256)
        integers = (self.qemu_pid, self.qemu_starttime, self.qemu_executable_device,
                    self.qemu_executable_inode, self.observer_qmp_device,
                    self.observer_qmp_inode, self.kvm_device, self.kvm_inode, self.kvm_rdev)
        _require(self.runtime_identity_sha256 == _runtime_identity(self)
                 and all(type(item) is int and item <= 9_007_199_254_740_991 for item in integers)
                 and self.qemu_pid > 1 and self.qemu_starttime > 0
                 and all(type(item) is int and item >= 0 for item in (
                     self.qemu_executable_device, self.observer_qmp_device,
                     self.kvm_device, self.kvm_rdev))
                 and all(type(item) is int and item > 0 for item in (
                     self.qemu_executable_inode, self.observer_qmp_inode, self.kvm_inode))
                 and type(self.kvm_api) is int and self.kvm_api == 12 and self.qmp_present is True
                 and self.qmp_enabled is True, ProductionReceiptError)


@dataclass(frozen=True)
class RemoteBindingProjection:
    source: RemoteSourceBindings
    cycle_capability_sha256: str
    program_sha256: str
    parser_source_sha256: str
    marker_sha256: str
    qemu: RemoteQemuBindings

    def __post_init__(self):
        _require(type(self.source) is RemoteSourceBindings
                 and type(self.qemu) is RemoteQemuBindings, ProductionReceiptError)
        for item in (self.cycle_capability_sha256, self.program_sha256,
                     self.parser_source_sha256, self.marker_sha256): _digest(item)


@dataclass(frozen=True)
class RemoteReceipt:
    grant_commitment: str
    batch_commitment: str
    ordinal: int
    mode: str
    state_commitment: str
    state_lineage_commitment: str
    instance_commitment: str
    host_receipt_commitment: str
    operation_commitment: str
    host_boot_commitment: str
    client_key_commitment: str
    host_key_commitment: str
    rootfs_descriptor_sha256: str
    ami_commitment: str
    provider_launch_started_unix_ns: int
    provider_running_observed_unix_ns: int
    kata_launch_started_boottime_ns: int
    ssh_ready_observed_boottime_ns: int
    workloads: tuple[WorkloadMeasurement, ...]
    bindings: RemoteBindingProjection
    certain: bool

    def __post_init__(self):
        for item in (
            self.grant_commitment, self.batch_commitment, self.state_commitment,
            self.state_lineage_commitment, self.instance_commitment,
            self.host_receipt_commitment, self.operation_commitment,
            self.host_boot_commitment, self.client_key_commitment,
            self.host_key_commitment, self.rootfs_descriptor_sha256,
            self.ami_commitment,
        ): _digest(item)
        _require(1 <= self.ordinal <= 7 and self.mode == CYCLE_MODES[self.ordinal - 1]
                 and self.provider_launch_started_unix_ns < self.provider_running_observed_unix_ns
                 and 0 < self.kata_launch_started_boottime_ns < self.ssh_ready_observed_boottime_ns
                 and self.client_key_commitment != self.host_key_commitment
                 and type(self.workloads) is tuple
                 and len(self.workloads) == (21 if self.mode == "full" else 0)
                 and type(self.bindings) is RemoteBindingProjection
                 and self.bindings.qemu.operation_token == self.operation_commitment
                 and (self.bindings.qemu.post_ssh_runtime_fact_sha256 is not None) ==
                     (self.mode == "readiness")
                 and (self.mode != "readiness" or
                      self.bindings.qemu.post_ssh_runtime_fact_sha256 !=
                      self.bindings.qemu.pre_ssh_runtime_fact_sha256)
                 and self.certain is True, ProductionReceiptError)
        if self.mode == "full":
            _require(tuple((item.category, item.ordinal) for item in self.workloads) ==
                     tuple((category, ordinal) for category in ("git", "build", "install")
                           for ordinal in range(1, 8)), ProductionReceiptError)


@dataclass(frozen=True)
class InventoryResource:
    category: str
    identity_commitment: str
    disposition: str
    public_address_commitment: str | None

    def __post_init__(self):
        _require(self.category in INVENTORY_CATEGORIES
                 and self.disposition in {"absent", "deleted", "unexpected-live"},
                 ProductionReceiptError)
        _digest(self.identity_commitment)
        if self.public_address_commitment is not None: _digest(self.public_address_commitment)
        _require((self.category in {"network_interfaces", "eni_public_associations", "elastic_ips"})
                 or self.public_address_commitment is None, ProductionReceiptError)


@dataclass(frozen=True)
class InventoryPage:
    category: str
    service: str
    operation: str
    query_scope: str
    ordinal: int
    request_token_commitment: str | None
    next_token_commitment: str | None
    response_commitment: str
    resources: tuple[InventoryResource, ...]
    page_commitment: str

    def __post_init__(self):
        _require(self.category in INVENTORY_CATEGORIES and 1 <= self.ordinal <= 32
                 and type(self.service) is str and self.service
                 and type(self.operation) is str and self.operation
                 and self.query_scope in {"campaign-graph", "account-region-wide",
                     "account-region-wide-public-address", "account-wide-campaign-prefix",
                     "account-region-wide-campaign-prefix", "account-region-wide-related-instance"}
                 and type(self.resources) is tuple, ProductionReceiptError)
        for item in (self.request_token_commitment, self.next_token_commitment):
            if item is not None: _digest(item)
        _digest(self.response_commitment); _digest(self.page_commitment)
        _require(all(type(item) is InventoryResource and item.category == self.category
                     for item in self.resources), ProductionReceiptError)
        value = {
            "category": self.category, "service": self.service,
            "operation": self.operation, "query_scope": self.query_scope,
            "ordinal": self.ordinal,
            "request_token_commitment": self.request_token_commitment,
            "next_token_commitment": self.next_token_commitment,
            "response_commitment": self.response_commitment,
            "resources": [asdict(item) for item in self.resources],
        }
        _require(self.page_commitment == _commit(b"cogs.stage2-inventory-page/v2", value),
                 ProductionReceiptError)


@dataclass(frozen=True)
class InventoryReceipt:
    batch_commitment: str
    observation_sequence: int
    cycle_ordinal: int | None
    observer_commitment: str
    session_commitment: str
    run_commitment: str
    account_commitment: str
    region: str
    destroyed_state_commitment: str
    observed_started_unix_ns: int
    observed_ended_unix_ns: int
    pages: tuple[InventoryPage, ...]
    zero_commitment: str
    certain: bool

    def __post_init__(self):
        for item in (self.batch_commitment, self.observer_commitment,
                     self.session_commitment, self.run_commitment,
                     self.account_commitment, self.destroyed_state_commitment,
                     self.zero_commitment): _digest(item)
        _require(1 <= self.observation_sequence <= 8
                 and self.cycle_ordinal == (
                     self.observation_sequence if self.observation_sequence <= 7 else None)
                 and type(self.region) is str and 3 <= len(self.region) <= 32
                 and self.observed_started_unix_ns < self.observed_ended_unix_ns
                 and type(self.pages) is tuple and self.certain is True,
                 ProductionReceiptError)
        by_category = {name: [] for name in INVENTORY_CATEGORIES}
        for page in self.pages: by_category[page.category].append(page)
        _require(all(rows for rows in by_category.values()), ProductionReceiptError)
        for category, rows in by_category.items():
            _require(tuple(page.ordinal for page in rows) == tuple(range(1, len(rows) + 1)),
                     ProductionReceiptError)
            if category in {"network_interfaces", "eni_public_associations", "elastic_ips"}:
                _require(all(page.query_scope in {"account-region-wide",
                    "account-region-wide-public-address"} for page in rows),
                    ProductionReceiptError)
            expected = None
            for page in rows:
                _require(page.request_token_commitment == expected, ProductionReceiptError)
                expected = page.next_token_commitment
            _require(expected is None, ProductionReceiptError)
        resources = tuple(item for page in self.pages for item in page.resources)
        _require(all(item.disposition in {"absent", "deleted"} for item in resources),
                 ProductionReceiptError)
        value = {
            "batch_commitment": self.batch_commitment,
            "observation_sequence": self.observation_sequence,
            "cycle_ordinal": self.cycle_ordinal,
            "observer_commitment": self.observer_commitment,
            "session_commitment": self.session_commitment,
            "run_commitment": self.run_commitment,
            "account_commitment": self.account_commitment,
            "region": self.region,
            "destroyed_state_commitment": self.destroyed_state_commitment,
            "observed_started_unix_ns": self.observed_started_unix_ns,
            "observed_ended_unix_ns": self.observed_ended_unix_ns,
            "page_commitments": [item.page_commitment for item in self.pages],
        }
        _require(self.zero_commitment == _commit(
            b"cogs.stage2-zero-inventory/v2", value), ProductionReceiptError)


@dataclass(frozen=True)
class CostReceipt:
    grant_commitment: str
    cycle_ordinal: int
    rate_source_commitment: str
    usage_commitment: str
    cost_micro_usd: int
    receipt_commitment: str

    def __post_init__(self):
        for item in (self.grant_commitment, self.rate_source_commitment,
                     self.usage_commitment, self.receipt_commitment): _digest(item)
        _require(1 <= self.cycle_ordinal <= 7
                 and type(self.cost_micro_usd) is int and self.cost_micro_usd > 0,
                 ProductionReceiptError)
        fields = asdict(self); fields.pop("receipt_commitment")
        _require(self.receipt_commitment == _commit(
            b"cogs.stage2-cost-receipt/v1", fields), ProductionReceiptError)


@dataclass(frozen=True)
class CleanupReceipt:
    grant_commitment: str
    state_commitment: str
    reconciliation_commitment: str
    inventory: InventoryReceipt | None
    normal_destroy_reissued: bool
    certain_zero: bool

    def __post_init__(self):
        for item in (self.grant_commitment, self.state_commitment,
                     self.reconciliation_commitment): _digest(item)
        _require(self.normal_destroy_reissued is False, ProductionReceiptError)
        if self.certain_zero:
            _require(type(self.inventory) is InventoryReceipt, ProductionReceiptError)
        else:
            _require(self.inventory is None or type(self.inventory) is InventoryReceipt,
                     ProductionReceiptError)


@dataclass(frozen=True)
class CampaignCandidate:
    execution_authority: str
    approval: ProductionApproval
    consumption: ApprovalConsumptionReceipt
    grants: tuple[CycleLaunchGrant, ...]
    effects: tuple[tuple[EffectReceipt, EffectReceipt, EffectReceipt, EffectReceipt], ...]
    remotes: tuple[RemoteReceipt, ...]
    inventories: tuple[InventoryReceipt, ...]
    costs: tuple[CostReceipt, ...]
    cycle_commitments: tuple[str, ...]
    custody_root: str

    def __post_init__(self):
        _require(self.execution_authority in {"authenticated-aws-adapter", "test-only"}
                 and type(self.approval) is ProductionApproval
                 and type(self.consumption) is ApprovalConsumptionReceipt
                 and len(self.grants) == len(self.effects) == len(self.remotes)
                     == len(self.costs) == len(self.cycle_commitments) == 7
                 and len(self.inventories) == 8
                 and tuple(item.ordinal for item in self.grants) == tuple(range(1, 8))
                 and len(set(self.cycle_commitments)) == 7, ProductionReceiptError)
        _digest(self.custody_root)
        approval_commitment = _commit(
            b"cogs.stage2-production-approval/v5", asdict(self.approval))
        expected = _commit(b"cogs.stage2-production-custody/v2", {
            "execution_authority": self.execution_authority,
            "approval": approval_commitment,
            "consumption": self.consumption.durable_record_commitment,
            "cycles": list(self.cycle_commitments),
            "inventories": [item.zero_commitment for item in self.inventories],
            "costs": [item.receipt_commitment for item in self.costs],
        })
        _require(self.custody_root == expected, ProductionReceiptError)

    @property
    def first_apply_unix_ns(self): return self.effects[0][1].observed_started_unix_ns
    @property
    def final_zero_unix_ns(self): return self.inventories[-1].observed_ended_unix_ns
    @property
    def actual_duration_ns(self): return self.final_zero_unix_ns - self.first_apply_unix_ns
    @property
    def total_cost_micro_usd(self): return sum(item.cost_micro_usd for item in self.costs)
    @property
    def launch_ready_samples_ns(self):
        return tuple(item.provider_running_observed_unix_ns - item.provider_launch_started_unix_ns
                     for item in self.remotes)
    @property
    def ssh_ready_samples_ns(self):
        return tuple(item.ssh_ready_observed_boottime_ns - item.kata_launch_started_boottime_ns
                     for item in self.remotes)
    @property
    def workload_measurements(self):
        return tuple(item for remote in self.remotes for item in remote.workloads)


class ProductionPorts:
    """Sealed concrete effect boundary; only the AWS adapter receives its seal."""
    __slots__ = ("approval", "now", "consume", "effect", "remote", "inventory",
                 "cost", "recover", "journal", "classification", "_seal")
    def __init_subclass__(cls, **_kwargs): raise TypeError("production ports are sealed")
    def __init__(self, seal, classification, approval, now, consume, effect,
                 remote, inventory, cost, recover, journal):
        _require(seal is _PORT_SEAL
                 and classification in {"authenticated-aws-adapter", "test-only"}
                 and type(approval) is ProductionApproval)
        for callback in (now, consume, effect, remote, inventory, cost, recover, journal):
            _require(callable(callback))
        self.approval, self.now, self.consume = approval, now, consume
        self.effect, self.remote, self.inventory = effect, remote, inventory
        self.cost, self.recover, self.journal = cost, recover, journal
        self.classification, self._seal = classification, seal


_PORT_SEAL = object()
_TEST_PORT_SEAL = object()


def _issue_adapter_ports(authority, approval, now, consume, effect, remote,
                         inventory, cost, recover, journal):
    # Imported lazily to avoid granting a seal to arbitrary callers.
    import completion_campaign_aws_adapter as adapter
    _require(adapter._validate_port_authority(authority))
    return ProductionPorts(_PORT_SEAL, "authenticated-aws-adapter", approval,
                           now, consume, effect, remote, inventory, cost,
                           recover, journal)


def _issue_test_ports(approval, now, consume, effect, remote, inventory,
                      cost, recover, journal):
    """Explicit non-production issuer used only by the hostile contract suite."""
    _require(__name__ != "__main__")
    return ProductionPorts(_PORT_SEAL, "test-only", approval, now, consume,
                           effect, remote, inventory, cost, recover, journal)


def _grant(approval, ordinal):
    fields = {
        "batch_commitment": approval.batch_commitment,
        "ordinal": ordinal, "mode": CYCLE_MODES[ordinal - 1],
        "implementation_revision": approval.implementation_revision,
        "control_revision": approval.control_revision,
        "static_control_sha256": approval.static_control_sha256,
        "rootfs_descriptor_sha256": approval.rootfs_descriptor_sha256,
        "ami_commitment": approval.ami_commitment,
        "plan_sha256": approval.plan_sha256s[ordinal - 1],
    }
    return CycleLaunchGrant(**fields, grant_commitment=_commit(
        b"cogs.stage2-cycle-launch-grant/v1", fields))


def _validate_remote_bindings(remote, grant, approval):
    bindings = remote.bindings
    source, qemu = bindings.source, bindings.qemu
    program, marker = REMOTE_PROGRAMS[grant.mode]
    _require(type(bindings) is RemoteBindingProjection
             and type(source) is RemoteSourceBindings
             and type(qemu) is RemoteQemuBindings
             and _commit(b"cogs.stage2-source-bindings/v1", asdict(source)) ==
                 approval.source_bindings_sha256
             and source.source_head == grant.implementation_revision
             and source.source_manifest_sha256 == approval.source_manifest_sha256
             and source.runtime_manifest_sha256 == approval.runtime_manifest_sha256
             and source.rootfs_descriptor_sha256 == grant.rootfs_descriptor_sha256
             and source.rootfs_package_manifest_sha256 == approval.rootfs_package_manifest_sha256
             and source.rootfs_provenance_sha256 == approval.rootfs_provenance_sha256
             and source.rootfs_publication_receipt_sha256 ==
                 approval.rootfs_publication_receipt_sha256
             and source.final_pin_sha256 == approval.fixture_commitment
             and source.guest_program_sha256 == FULL_PROGRAM_SHA256
             and bindings.program_sha256 == program
             and bindings.parser_source_sha256 == REMOTE_PARSERS[grant.mode]
             and bindings.marker_sha256 == marker
             and bindings.cycle_capability_sha256 == _cycle_capability(
                 grant.mode, program, marker)
             and qemu.operation_token == remote.operation_commitment
             and qemu.runtime_identity_sha256 == _runtime_identity(qemu)
             and (qemu.post_ssh_runtime_fact_sha256 is not None) ==
                 (grant.mode == "readiness")
             and (grant.mode != "readiness" or qemu.post_ssh_runtime_fact_sha256 !=
                  qemu.pre_ssh_runtime_fact_sha256), ProductionReceiptError)


class ProductionCampaignController:
    def __init__(self, ports):
        _require(type(ports) is ProductionPorts and ports._seal is _PORT_SEAL)
        self.ports = ports
        self.used = False

    def _now(self, approval):
        value = self.ports.now()
        _require(type(value) is int and approval.not_before_unix_ns <= value
                 < approval.expires_unix_ns, ProductionApprovalError)
        return value

    def _effect(self, kind, grant, previous):
        receipt = self.ports.effect(kind, grant, previous)
        _require(type(receipt) is EffectReceipt and receipt.kind == kind
                 and receipt.grant_commitment == grant.grant_commitment
                 and receipt.batch_commitment == grant.batch_commitment
                 and receipt.ordinal == grant.ordinal and receipt.mode == grant.mode
                 and receipt.ami_commitment == self.ports.approval.ami_commitment,
                 ProductionReceiptError)
        self.ports.journal("receipt", kind, grant.ordinal, grant.mode,
                           receipt.settlement_commitment)
        return receipt

    def run(self):
        _require(not self.used); self.used = True
        approval = self.ports.approval
        consumed_at = self._now(approval)
        approval_commitment = _commit(b"cogs.stage2-production-approval/v5", asdict(approval))
        consumption = self.ports.consume(approval, approval_commitment, consumed_at)
        _require(type(consumption) is ApprovalConsumptionReceipt
                 and consumption.approval_commitment == approval_commitment,
                 ProductionApprovalError)
        self.ports.journal("batch", "consumed", None, None,
                           consumption.durable_record_commitment)
        grants = []; effects = []; remotes = []; inventories = []; costs = []; cycles = []
        states = []; lineages = []; instances = []; operations = []; boots = []; runtimes = []
        live_mappings = []; pre_ssh_facts = []; post_ssh_facts = []
        client_keys = []; host_keys = []; instance_resources = []
        previous_zero_end = None
        first_apply_start = None
        active_grant = None
        active_state = None
        last_certain = None
        try:
            for ordinal, mode in enumerate(CYCLE_MODES, 1):
                self._now(approval)
                grant = _grant(approval, ordinal); active_grant = grant
                # The grant commitment is a conservative recovery key until a
                # provider state slot has been certainly observed.  Therefore a
                # plan failure still enters independent cleanup/inventory.
                active_state = grant.grant_commitment
                self.ports.journal("cycle", "opened", ordinal, mode,
                                   grant.grant_commitment)
                plan = self._effect("plan", grant, None)
                _require(plan.identity_commitment == approval.plan_sha256s[ordinal - 1]
                         and (previous_zero_end is None
                              or plan.observed_started_unix_ns > previous_zero_end),
                         ProductionReceiptError)
                active_state = plan.state_commitment
                apply = self._effect("apply", grant, plan); active_state = apply.state_commitment
                _require(apply.state_commitment == plan.state_commitment
                         and apply.state_lineage_commitment == plan.state_lineage_commitment
                         and apply.state_bytes_sha256 != "0" * 64
                         and plan.observed_ended_unix_ns < apply.observed_started_unix_ns,
                         ProductionReceiptError)
                if first_apply_start is None: first_apply_start = apply.observed_started_unix_ns
                effect_deadline = first_apply_start + approval.effect_deadline_ns
                cleanup_deadline = effect_deadline + approval.cleanup_reserve_ns
                cycle_deadline = min(
                    effect_deadline,
                    apply.observed_started_unix_ns + approval.maximum_cycle_duration_ns)
                _require(apply.observed_ended_unix_ns < cycle_deadline
                         and cleanup_deadline <= approval.expires_unix_ns,
                         ProductionApprovalError)
                running = self._effect("running", grant, apply)
                _require(running.state_commitment == apply.state_commitment
                         and running.state_lineage_commitment == apply.state_lineage_commitment
                         and running.state_bytes_sha256 == apply.state_bytes_sha256
                         and apply.observed_ended_unix_ns < running.observed_started_unix_ns
                         and running.observed_ended_unix_ns < cycle_deadline,
                         ProductionReceiptError)
                remote = self.ports.remote(grant, apply, running, cycle_deadline)
                _require(type(remote) is RemoteReceipt
                         and remote.grant_commitment == grant.grant_commitment
                         and remote.batch_commitment == approval.batch_commitment
                         and remote.ordinal == ordinal and remote.mode == mode
                         and remote.state_commitment == apply.state_commitment
                         and remote.state_lineage_commitment == apply.state_lineage_commitment
                         and remote.instance_commitment == running.identity_commitment
                         and remote.provider_launch_started_unix_ns == apply.observed_started_unix_ns
                         and remote.provider_running_observed_unix_ns == running.observed_ended_unix_ns
                         and remote.rootfs_descriptor_sha256 == approval.rootfs_descriptor_sha256
                         and remote.ami_commitment == approval.ami_commitment,
                         ProductionReceiptError)
                _validate_remote_bindings(remote, grant, approval)
                destroy = self._effect("destroy", grant, running)
                _require(destroy.state_commitment == apply.state_commitment
                         and destroy.state_lineage_commitment == apply.state_lineage_commitment
                         and running.observed_ended_unix_ns < destroy.observed_started_unix_ns
                         and destroy.observed_ended_unix_ns < cycle_deadline,
                         ProductionReceiptError)
                last_certain = destroy
                zero = self.ports.inventory(grant, destroy, ordinal)
                _require(type(zero) is InventoryReceipt
                         and zero.batch_commitment == approval.batch_commitment
                         and zero.observation_sequence == ordinal
                         and zero.cycle_ordinal == ordinal
                         and zero.account_commitment == approval.account_commitment
                         and zero.region == approval.region
                         and zero.destroyed_state_commitment == destroy.state_commitment
                         and zero.observed_started_unix_ns > destroy.observed_ended_unix_ns
                         and zero.observed_ended_unix_ns < cleanup_deadline
                         and (previous_zero_end is None
                              or zero.observed_started_unix_ns > previous_zero_end),
                         ProductionReceiptError)
                previous_zero_end = zero.observed_ended_unix_ns
                cost = self.ports.cost(grant, apply, destroy)
                _require(type(cost) is CostReceipt
                         and cost.grant_commitment == grant.grant_commitment
                         and cost.cycle_ordinal == ordinal, ProductionReceiptError)
                _require(sum(item.cost_micro_usd for item in (*costs, cost))
                         <= approval.maximum_cost_micro_usd, ProductionApprovalError)
                cycle = _commit(b"cogs.stage2-production-cycle/v2", {
                    "grant": grant.grant_commitment,
                    "effects": [item.settlement_commitment
                                for item in (plan, apply, running, destroy)],
                    "remote": remote.host_receipt_commitment,
                    "zero": zero.zero_commitment,
                    "cost": cost.receipt_commitment,
                })
                grants.append(grant); effects.append((plan, apply, running, destroy))
                remotes.append(remote); inventories.append(zero); costs.append(cost)
                cycles.append(cycle); states.append(apply.state_commitment)
                lineages.append(apply.state_lineage_commitment)
                instances.append(remote.instance_commitment)
                operations.append(remote.operation_commitment)
                boots.append(remote.host_boot_commitment)
                qmp = remote.bindings.qemu
                runtimes.append(qmp.runtime_identity_sha256)
                live_mappings.append(qmp.live_mapping_sha256)
                pre_ssh_facts.append(qmp.pre_ssh_runtime_fact_sha256)
                if qmp.post_ssh_runtime_fact_sha256 is not None:
                    post_ssh_facts.append(qmp.post_ssh_runtime_fact_sha256)
                client_keys.append(remote.client_key_commitment)
                host_keys.append(remote.host_key_commitment)
                instance_resources.append(dict(running.resource_commitments)["instance"])
                active_grant = active_state = last_certain = None
                self.ports.journal("cycle", "sealed", ordinal, mode, cycle)
            active_grant = grants[-1]
            active_state = effects[-1][-1].state_commitment
            last_certain = effects[-1][-1]
            final = self.ports.inventory(None, effects[-1][-1], 8)
            _require(type(final) is InventoryReceipt
                     and final.batch_commitment == approval.batch_commitment
                     and final.observation_sequence == 8 and final.cycle_ordinal is None
                     and final.account_commitment == approval.account_commitment
                     and final.region == approval.region
                     and final.destroyed_state_commitment == effects[-1][-1].state_commitment
                     and final.observed_started_unix_ns > previous_zero_end
                     and final.observed_ended_unix_ns < cleanup_deadline,
                     ProductionReceiptError)
            inventories.append(final)
            active_grant = active_state = last_certain = None
            _require(all(len(set(values)) == 7 for values in
                         (states, lineages, instances, operations, boots, runtimes,
                          live_mappings, pre_ssh_facts))
                     and len(post_ssh_facts) == len(set(post_ssh_facts)) == 6
                     and len(set(pre_ssh_facts) | set(post_ssh_facts)) == 13
                     and len(set(client_keys)) == len(set(host_keys)) == 7
                     and len(set(client_keys) | set(host_keys)) == 14
                     and len(set(instance_resources)) == 7,
                     ProductionReceiptError)
            for name in ("observer_commitment", "session_commitment",
                         "run_commitment", "zero_commitment"):
                _require(len({getattr(item, name) for item in inventories}) == 8,
                         ProductionReceiptError)
            custody = _commit(b"cogs.stage2-production-custody/v2", {
                "execution_authority": self.ports.classification,
                "approval": approval_commitment,
                "consumption": consumption.durable_record_commitment,
                "cycles": cycles,
                "inventories": [item.zero_commitment for item in inventories],
                "costs": [item.receipt_commitment for item in costs],
            })
            candidate = CampaignCandidate(
                self.ports.classification, approval, consumption, tuple(grants),
                tuple(effects), tuple(remotes), tuple(inventories), tuple(costs),
                tuple(cycles), custody)
            _require(candidate.actual_duration_ns > 0
                     and candidate.total_cost_micro_usd <= approval.maximum_cost_micro_usd
                     and len(candidate.workload_measurements) == 21,
                     ProductionReceiptError)
            self.ports.journal("batch", "candidate", None, None, custody)
            # Transfer only this exact, fully checked object into the closure-private
            # pass-only evidence route.  Reconstructed dataclasses/public JSON never
            # enter that route.
            import completion_campaign_evidence_issuer as evidence_issuer
            evidence_issuer._retain_controller_candidate(candidate)
            return candidate
        except BaseException as primary:
            if active_grant is not None and active_state is not None:
                try:
                    cleanup = self.ports.recover(active_grant, active_state,
                                                 last_certain, primary)
                    _require(type(cleanup) is CleanupReceipt
                             and cleanup.grant_commitment == active_grant.grant_commitment
                             and cleanup.state_commitment == active_state
                             and cleanup.normal_destroy_reissued is False,
                             ProductionReceiptError)
                    self.ports.journal("cleanup", "settled" if cleanup.certain_zero
                                       else "uncertain", active_grant.ordinal,
                                       active_grant.mode,
                                       cleanup.reconciliation_commitment)
                    if not cleanup.certain_zero:
                        raise ProductionUncertainty() from primary
                except ProductionUncertainty:
                    raise
                except BaseException as cleanup_error:
                    raise ProductionUncertainty() from cleanup_error
            raise

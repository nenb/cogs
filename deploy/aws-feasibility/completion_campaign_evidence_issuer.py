#!/usr/bin/env python3
"""Closure-private pass-only Stage 2 completion evidence issuer.

The issuer consumes only the exact ``CampaignCandidate`` object retained by the
production controller.  It has no provider, command, credential, or network
surface.  Public mappings and reconstructed dataclasses are never an issuance
capability.  Publication is one-shot, no-replace, fsync'd, and read back through
held directory custody before a receipt is returned.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
import stat
from typing import Any

import completion_campaign_production as production

VERSION = "cogs.aws-stage2-completion-evidence/v2"
AUTHORITY = "aws-stage2-completion"
PUBLICATION_VERSION = "cogs.aws-stage2-completion-publication/v1"
EVIDENCE_NAME = "aws-stage2-completion-evidence-v2.json"
REPORT_NAME = "aws-stage2-completion-report-v2.md"
RECEIPT_NAME = "aws-stage2-completion-publication-v1.json"
BILLING_HOUR_NS = 3_600_000_000_000
RATE_COMPONENTS = {
    "compute": 90_000,
    "gp3": 3_000,
    "public_ipv4": 5_000,
    "support_allowance": 20_000,
}
AGGREGATE_RATE = sum(RATE_COMPONENTS.values())
LIMITATIONS = (
    "standalone-stage-2-only", "not-eks-or-kubernetes",
    "not-production-release-or-general-availability",
    "not-stage-4-under-30-second-readiness", "not-general-capacity",
    "no-isolation-claim-beyond-measured-sandbox",
    "custody-is-local-tamper-evidence-not-external-worm",
)


class EvidenceIssuanceError(production.ProductionCampaignError):
    pass


class EvidencePublicationUncertain(EvidenceIssuanceError):
    pass


def _require(value: bool, message: str = "completion evidence rejected") -> None:
    if not value: raise EvidenceIssuanceError(message)


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceIssuanceError("canonical projection failed") from error
    _require(len(raw) <= 262_144, "evidence byte bound")
    return raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _ceil_cost(duration_ns: int) -> int:
    return (duration_ns * AGGREGATE_RATE + BILLING_HOUR_NS - 1) // BILLING_HOUR_NS


def _summary(values: tuple[int, ...]) -> dict[str, Any]:
    _require(len(values) == 7 and all(type(item) is int and item > 0 for item in values),
             "summary sample shape")
    ordered = sorted(values)
    return {"samples_ns": list(values), "min_ns": ordered[0], "p50_ns": ordered[3],
            "p95_ns": ordered[6], "max_ns": ordered[6]}


def _candidate_custody_routes():
    # The identity table is closure-private: callers cannot populate it with
    # reconstructed dataclasses or public mappings.
    retained: dict[int, production.CampaignCandidate] = {}

    def retain(candidate: production.CampaignCandidate) -> None:
        """Called once by the controller after its successful terminal journal row."""
        _require(type(candidate) is production.CampaignCandidate, "candidate type")
        _require(id(candidate) not in retained, "candidate already retained")
        retained[id(candidate)] = candidate

    def consume(candidate: production.CampaignCandidate) -> None:
        _require(type(candidate) is production.CampaignCandidate
                 and retained.pop(id(candidate), None) is candidate,
                 "issuer requires exact retained controller candidate")

    return retain, consume


_retain_controller_candidate, _consume_retained_candidate = _candidate_custody_routes()
del _candidate_custody_routes


def _effect(item: production.EffectReceipt) -> dict[str, Any]:
    return {
        "intent_commitment": item.intent_commitment,
        "settlement_commitment": item.settlement_commitment,
        "identity_commitment": item.identity_commitment,
        "state_commitment": item.state_commitment,
        "state_lineage_commitment": item.state_lineage_commitment,
        "observed_started_unix_ns": str(item.observed_started_unix_ns),
        "observed_ended_unix_ns": str(item.observed_ended_unix_ns),
    }


def _remote_bindings(item: production.RemoteReceipt,
                     grant: production.CycleLaunchGrant,
                     approval: production.ProductionApproval) -> dict[str, Any]:
    projection = item.bindings
    _require(type(projection) is production.RemoteBindingProjection
             and type(projection.source) is production.RemoteSourceBindings
             and type(projection.qemu) is production.RemoteQemuBindings,
             "closed remote binding projection")
    source, qemu = asdict(projection.source), asdict(projection.qemu)
    program, marker = production.REMOTE_PROGRAMS[grant.mode]
    _require(production._commit(b"cogs.stage2-source-bindings/v1", source) ==
             approval.source_bindings_sha256
             and source["source_head"] == grant.implementation_revision
             and source["source_manifest_sha256"] == approval.source_manifest_sha256
             and source["runtime_attestation_sha256"] == approval.runtime_commitment
             and source["rootfs_descriptor_sha256"] == grant.rootfs_descriptor_sha256
             and source["final_pin_sha256"] == approval.fixture_commitment
             and projection.program_sha256 == program
             and projection.parser_source_sha256 == production.REMOTE_PARSERS[grant.mode]
             and projection.marker_sha256 == marker
             and projection.cycle_capability_sha256 == production._cycle_capability(
                 grant.mode, program, marker), "remote source/parser binding drift")
    identity_fields = {name: qemu[name] for name in (
        "qemu_argv_sha256", "qemu_pid",
        "qemu_starttime", "qemu_executable_device", "qemu_executable_inode",
        "observer_qmp_device", "observer_qmp_inode", "kvm_device", "kvm_inode",
        "kvm_rdev", "kvm_api", "qmp_present", "qmp_enabled")}
    identity = hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + _canonical(identity_fields)).hexdigest()
    _require(qemu["operation_token"] == item.operation_commitment
             and qemu["runtime_identity_sha256"] == identity
             and (qemu["post_ssh_runtime_fact_sha256"] is not None) ==
                 (grant.mode == "readiness")
             and (grant.mode != "readiness" or qemu["post_ssh_runtime_fact_sha256"] !=
                  qemu["pre_ssh_runtime_fact_sha256"]), "remote QEMU binding drift")
    return {"source_bindings": source,
            "cycle_capability_sha256": projection.cycle_capability_sha256,
            "program_sha256": projection.program_sha256,
            "parser_source_sha256": projection.parser_source_sha256,
            "marker_sha256": projection.marker_sha256, "qemu": qemu}


def _inventory(item: production.InventoryReceipt) -> dict[str, Any]:
    pages = []
    for category in production.INVENTORY_CATEGORIES:
        rows = tuple(page for page in item.pages if page.category == category)
        _require(rows and tuple(page.ordinal for page in rows) == tuple(range(1, len(rows) + 1)),
                 "inventory page coverage/order")
        pages.extend({
            "category": page.category, "ordinal": page.ordinal,
            "request_token_commitment": page.request_token_commitment,
            "next_token_commitment": page.next_token_commitment,
            "page_commitment": page.page_commitment,
            "resources": [{
                "identity_commitment": resource.identity_commitment,
                "disposition": resource.disposition,
                "public_address_commitment": resource.public_address_commitment,
            } for resource in page.resources],
        } for page in rows)
    return {
        "observation_sequence": item.observation_sequence,
        "cycle_ordinal": item.cycle_ordinal,
        "observer_commitment": item.observer_commitment,
        "session_commitment": item.session_commitment,
        "run_commitment": item.run_commitment,
        "account_commitment": item.account_commitment,
        "region_commitment": production._commit(
            b"cogs.stage2-redacted-region/v1", {"region": item.region}),
        "destroyed_state_commitment": item.destroyed_state_commitment,
        "observed_started_unix_ns": str(item.observed_started_unix_ns),
        "observed_ended_unix_ns": str(item.observed_ended_unix_ns),
        "zero_commitment": item.zero_commitment,
        "pages": pages,
    }


def _validate_and_project(candidate: production.CampaignCandidate) -> dict[str, Any]:
    approval = candidate.approval
    _require(candidate.final_zero_unix_ns > candidate.effects[-1][-1].observed_ended_unix_ns,
             "final zero does not follow final destroy")
    _require(candidate.inventories[-1].observed_started_unix_ns
             > candidate.inventories[-2].observed_ended_unix_ns,
             "final zero does not follow cycle-seven zero")
    _require(candidate.first_apply_unix_ns + approval.effect_deadline_ns
             + approval.cleanup_reserve_ns <= approval.expires_unix_ns,
             "cleanup reserve is not approved")
    _require(candidate.final_zero_unix_ns <= approval.expires_unix_ns
             and 0 < candidate.actual_duration_ns
             <= approval.expires_unix_ns - candidate.first_apply_unix_ns,
             "actual duration exceeds approval expiry")
    _require(tuple(item.mode for item in candidate.grants) == production.CYCLE_MODES,
             "seven-cycle mode vector")
    _require(len(candidate.workload_measurements) == 21
             and tuple((row.category, row.ordinal) for row in candidate.workload_measurements)
             == tuple((category, ordinal) for category in ("git", "build", "install")
                      for ordinal in range(1, 8)), "exact 21 workload measurements")

    expected_rate = production._commit(
        b"cogs.stage2-fixed-rate/v1", {"micro_usd_per_hour": AGGREGATE_RATE})
    _require(approval.rate_source_commitment == expected_rate,
             "approval rate source differs")
    cycles = []
    prior_zero_end = None
    for index, (grant, effects, remote, zero, cost, cycle_commitment) in enumerate(zip(
            candidate.grants, candidate.effects, candidate.remotes,
            candidate.inventories[:7], candidate.costs, candidate.cycle_commitments,
            strict=True), 1):
        plan, apply, running, destroy = effects
        _require(grant.ordinal == index and grant.mode == production.CYCLE_MODES[index - 1]
                 and grant.implementation_revision == approval.implementation_revision
                 and grant.control_revision == approval.control_revision
                 and grant.static_control_sha256 == approval.static_control_sha256
                 and grant.rootfs_descriptor_sha256 == approval.rootfs_descriptor_sha256
                 and grant.ami_commitment == approval.ami_commitment
                 and grant.plan_sha256 == approval.plan_sha256s[index - 1],
                 "common grant binding drift")
        _require(tuple(item.kind for item in effects) == production.EFFECT_KINDS
                 and all(item.grant_commitment == grant.grant_commitment
                         and item.batch_commitment == approval.batch_commitment
                         and item.ordinal == index and item.mode == grant.mode
                         and item.ami_commitment == approval.ami_commitment for item in effects),
                 "effect grant binding drift")
        _require(plan.observed_ended_unix_ns < apply.observed_started_unix_ns
                 < apply.observed_ended_unix_ns < running.observed_started_unix_ns
                 < running.observed_ended_unix_ns < destroy.observed_started_unix_ns
                 < destroy.observed_ended_unix_ns
                 < candidate.first_apply_unix_ns + approval.effect_deadline_ns,
                 "effect order/deadline")
        _require(len({item.state_commitment for item in effects}) == 1
                 and len({item.state_lineage_commitment for item in effects}) == 1,
                 "effect state lineage drift")
        _require(remote.grant_commitment == grant.grant_commitment
                 and remote.batch_commitment == approval.batch_commitment
                 and remote.ordinal == index and remote.mode == grant.mode
                 and remote.state_commitment == apply.state_commitment
                 and remote.state_lineage_commitment == apply.state_lineage_commitment
                 and remote.rootfs_descriptor_sha256 == approval.rootfs_descriptor_sha256
                 and remote.ami_commitment == approval.ami_commitment
                 and remote.provider_launch_started_unix_ns == apply.observed_started_unix_ns
                 and remote.provider_running_observed_unix_ns == running.observed_ended_unix_ns,
                 "remote common binding drift")
        _require(zero.observation_sequence == index and zero.cycle_ordinal == index
                 and zero.destroyed_state_commitment == destroy.state_commitment
                 and zero.observed_started_unix_ns > destroy.observed_ended_unix_ns
                 and (prior_zero_end is None or zero.observed_started_unix_ns > prior_zero_end),
                 "cycle zero ordering")
        prior_zero_end = zero.observed_ended_unix_ns
        duration = destroy.observed_ended_unix_ns - apply.observed_started_unix_ns
        _require(cost.grant_commitment == grant.grant_commitment
                 and cost.cycle_ordinal == index
                 and cost.rate_source_commitment == expected_rate
                 and cost.cost_micro_usd == _ceil_cost(duration),
                 "typed cost receipt recomputation")
        running_resources = dict(running.resource_commitments)
        destroy_resources = dict(destroy.resource_commitments)
        _require(set(running_resources) == {"instance", "root_volume",
                                            "launch_template_generation"}
                 and set(destroy_resources) == {"pre_destroy_receipt"},
                 "provider freshness receipt differs")
        freshness = {
            **running_resources,
            "host_boot": remote.host_boot_commitment,
            "operation": remote.operation_commitment,
            "client_key": remote.client_key_commitment,
            "host_key": remote.host_key_commitment,
            **destroy_resources,
        }
        _require(len(freshness) == len(set(freshness.values())) == 8,
                 "within-cycle freshness replay")
        remote_bindings = _remote_bindings(remote, grant, approval)
        workloads = [{"category": row.category, "ordinal": row.ordinal,
                      "duration_ns": row.duration_ns, "commitment": row.commitment}
                     for row in remote.workloads]
        _require((index == 1 and len(workloads) == 21) or (index > 1 and not workloads),
                 "workload cycle placement")
        cycles.append({
            "ordinal": index, "mode": grant.mode,
            "grant_commitment": grant.grant_commitment,
            "cycle_commitment": cycle_commitment,
            "plan_sha256": grant.plan_sha256,
            "effects": {item.kind: _effect(item) for item in effects},
            "freshness": freshness,
            "remote": {
                "host_receipt_commitment": remote.host_receipt_commitment,
                "instance_commitment": remote.instance_commitment,
                "operation_commitment": remote.operation_commitment,
                "host_boot_commitment": remote.host_boot_commitment,
                "apply_to_running_ns": (remote.provider_running_observed_unix_ns
                                        - remote.provider_launch_started_unix_ns),
                "kata_launch_to_ssh_ready_ns": (remote.ssh_ready_observed_boottime_ns
                                                - remote.kata_launch_started_boottime_ns),
                "bindings": remote_bindings,
            },
            **({"workloads": workloads} if workloads else {}),
            "zero_inventory_commitment": zero.zero_commitment,
            "cost": {
                "receipt_commitment": cost.receipt_commitment,
                "rate_source_commitment": cost.rate_source_commitment,
                "usage_commitment": cost.usage_commitment,
                "billable_duration_ns": duration,
                "cost_micro_usd": cost.cost_micro_usd,
            },
        })

    _require(all(len(set(values)) == 7 for values in (
                 tuple(item.grant_commitment for item in candidate.grants),
                 candidate.cycle_commitments,
                 tuple(item.plan_sha256 for item in candidate.grants),
                 tuple(row[1].state_commitment for row in candidate.effects),
                 tuple(row[1].state_lineage_commitment for row in candidate.effects),
                 tuple(item.instance_commitment for item in candidate.remotes),
                 tuple(item.host_receipt_commitment for item in candidate.remotes),
                 tuple(item.operation_commitment for item in candidate.remotes),
                 tuple(item.host_boot_commitment for item in candidate.remotes),
                 tuple(item.client_key_commitment for item in candidate.remotes),
                 tuple(item.host_key_commitment for item in candidate.remotes),
                 tuple(item.bindings.qemu.runtime_identity_sha256
                       for item in candidate.remotes),
                 tuple(dict(row[2].resource_commitments)["root_volume"]
                       for row in candidate.effects),
                 tuple(dict(row[2].resource_commitments)["launch_template_generation"]
                       for row in candidate.effects),
                 tuple(dict(row[3].resource_commitments)["pre_destroy_receipt"]
                       for row in candidate.effects),
             )), "cycle freshness replay")
    _require(len({item.settlement_commitment for row in candidate.effects for item in row}) == 28,
             "effect settlement replay")
    inventories = [_inventory(item) for item in candidate.inventories]
    _require(tuple(item["observation_sequence"] for item in inventories) == tuple(range(1, 9)),
             "eight inventory order")
    _require(len({item.observer_commitment for item in candidate.inventories}) == 8
             and len({item.session_commitment for item in candidate.inventories}) == 8
             and len({item.run_commitment for item in candidate.inventories}) == 8
             and len({item.zero_commitment for item in candidate.inventories}) == 8,
             "inventory custody replay")
    aggregate_duration = sum(row["cost"]["billable_duration_ns"] for row in cycles)
    aggregate_cost = sum(row["cost"]["cost_micro_usd"] for row in cycles)
    _require(aggregate_cost == candidate.total_cost_micro_usd
             and aggregate_cost <= approval.maximum_cost_micro_usd,
             "aggregate cost gate")
    bindings = {
        "source_manifest_commitment": approval.source_manifest_sha256,
        "source_bindings_commitment": approval.source_bindings_sha256,
        "static_control_commitment": approval.static_control_sha256,
        "pre_aws_package_commitment": approval.pre_aws_package_sha256,
        "rootfs_descriptor_commitment": approval.rootfs_descriptor_sha256,
        "rootfs_package_manifest_commitment": approval.rootfs_package_manifest_sha256,
        "rootfs_provenance_commitment": approval.rootfs_provenance_sha256,
        "rootfs_qualification_receipt_commitment": approval.rootfs_qualification_receipt_sha256,
        "rootfs_publication_receipt_commitment": approval.rootfs_publication_receipt_sha256,
        "runtime_commitment": approval.runtime_commitment,
        "fixture_commitment": approval.fixture_commitment,
        "account_commitment": approval.account_commitment,
        "ami_commitment": approval.ami_commitment,
        "approval_authentication_commitment": candidate.consumption.authentication_receipt_sha256,
        "approval_issuer_commitment": approval.issuer_commitment,
    }
    return {
        "version": VERSION, "authority": AUTHORITY, "result": "pass",
        "batch": {
            "commitment": approval.batch_commitment,
            "implementation_revision": approval.implementation_revision,
            "control_revision": approval.control_revision,
            "consumption_commitment": candidate.consumption.durable_record_commitment,
            "custody_root": candidate.custody_root,
            "cycle_count": 7, "modes": list(production.CYCLE_MODES),
        },
        "bindings": bindings,
        "deadlines": {
            "first_apply_unix_ns": str(candidate.first_apply_unix_ns),
            "effect_deadline_unix_ns": str(candidate.first_apply_unix_ns + approval.effect_deadline_ns),
            "cleanup_reserve_ns": approval.cleanup_reserve_ns,
            "expires_unix_ns": str(approval.expires_unix_ns),
            "final_zero_unix_ns": str(candidate.final_zero_unix_ns),
            "actual_campaign_duration_ns": candidate.actual_duration_ns,
        },
        "cycles": cycles,
        "inventories": inventories,
        "launch_summary": _summary(candidate.launch_ready_samples_ns),
        "ssh_ready_summary": _summary(candidate.ssh_ready_samples_ns),
        "workload_summaries": {
            category: _summary(tuple(row.duration_ns for row in candidate.workload_measurements
                                     if row.category == category))
            for category in ("git", "build", "install")
        },
        "cleanup": {
            "destroy_attempts": 7, "inventory_observations": 8,
            "cycle_zero_commitments": [item.zero_commitment for item in candidate.inventories[:7]],
            "final_zero_commitment": candidate.inventories[-1].zero_commitment,
            "inventory_categories": list(production.INVENTORY_CATEGORIES),
        },
        "cost": {
            "currency": "micro-USD", "rate_components_micro_usd_per_hour": RATE_COMPONENTS,
            "aggregate_rate_micro_usd_per_hour": AGGREGATE_RATE,
            "rate_source_commitment": expected_rate,
            "aggregate_effect_duration_ns": aggregate_duration,
            "actual_campaign_duration_ns": candidate.actual_duration_ns,
            "aggregate_cost_micro_usd": aggregate_cost,
            "approved_maximum_micro_usd": approval.maximum_cost_micro_usd,
        },
        "limitations": list(LIMITATIONS),
    }


def _scan_redaction(value: Any) -> None:
    forbidden = ("arn:", "AKIA", "ASIA", "BEGIN PRIVATE", "ssh-ed25519", "/var/", "/tmp/")
    def visit(item: Any) -> None:
        if type(item) is str:
            _require(all(token.lower() not in item.lower() for token in forbidden),
                     "sensitive material in projection")
            _require(all(0x20 <= ord(character) <= 0x7e for character in item),
                     "non-ASCII projection")
        elif type(item) is list:
            for child in item: visit(child)
        elif type(item) is dict:
            for child in item.values(): visit(child)
    visit(value)


class _ValidatedProjection:
    __slots__ = ("value",)
    def __init__(self, value: dict[str, Any]): self.value = value


def _validate(candidate: production.CampaignCandidate) -> _ValidatedProjection:
    value = _validate_and_project(candidate)
    _scan_redaction(value)
    # Round-trip exact canonical bytes before the renderer receives its token.
    _require(json.loads(_canonical(value)) == value, "canonical readback mismatch")
    return _ValidatedProjection(value)


def _render(validated: _ValidatedProjection) -> bytes:
    _require(type(validated) is _ValidatedProjection, "renderer requires validator token")
    value = validated.value
    lines = [
        "# AWS Stage 2 completion report", "",
        "Status: pass-only rendering of validated, redacted completion evidence.", "",
        "## Batch", "",
        f"- Implementation revision: `{value['batch']['implementation_revision']}`",
        f"- Batch commitment: `{value['batch']['commitment']}`",
        "- Cycles: 7 (one full, six readiness)", "",
        "## Measurements", "",
        "| Cycle | Mode | Apply to running | Kata launch to SSH ready | Cost |",
        "| ---: | --- | ---: | ---: | ---: |",
    ]
    for cycle in value["cycles"]:
        lines.append(f"| {cycle['ordinal']} | {cycle['mode']} | {cycle['remote']['apply_to_running_ns']} ns | {cycle['remote']['kata_launch_to_ssh_ready_ns']} ns | {cycle['cost']['cost_micro_usd']} micro-USD |")
    lines += ["", "- Full-cycle workload measurements: 21",
              f"- Actual first-apply through final-zero duration: {value['deadlines']['actual_campaign_duration_ns']} ns",
              "", "## Cleanup and cost", "",
              "- State-bound destroy attempts: 7", "- Detailed inventory observations: 8",
              f"- Final zero commitment: `{value['cleanup']['final_zero_commitment']}`",
              f"- Aggregate cost: {value['cost']['aggregate_cost_micro_usd']} micro-USD",
              "", "## Limitations", ""]
    lines.extend(f"- {item}" for item in value["limitations"])
    return ("\n".join(lines) + "\n").encode("ascii")


_PUBLICATION_SEAL = object()


class PublicationCustody:
    __slots__ = ("parent_fd", "owner_uid", "used", "_seal")
    def __init__(self, parent_fd: int, owner_uid: int, seal: object):
        _require(seal is _PUBLICATION_SEAL and type(parent_fd) is int and parent_fd >= 0)
        self.parent_fd, self.owner_uid, self.used, self._seal = parent_fd, owner_uid, False, seal


def open_publication_custody(parent_fd: int, owner_uid: int | None = None) -> PublicationCustody:
    """Bind issuance to an already-held private directory descriptor."""
    uid = os.geteuid() if owner_uid is None else owner_uid
    seen = os.fstat(parent_fd)
    _require(stat.S_ISDIR(seen.st_mode) and stat.S_IMODE(seen.st_mode) == 0o700
             and seen.st_uid == uid, "publication directory custody")
    return PublicationCustody(parent_fd, uid, _PUBLICATION_SEAL)


def _stage_and_publish(custody: PublicationCustody, values: tuple[tuple[str, bytes], ...]) -> None:
    parent = custody.parent_fd
    staged: list[tuple[str, str]] = []
    try:
        for final, raw in values:
            staging = f".{final}.staging"
            descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=parent)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(descriptor, view)
                    if count <= 0: raise OSError("short publication write")
                    view = view[count:]
                os.fsync(descriptor)
            finally: os.close(descriptor)
            staged.append((staging, final))
        for staging, final in staged:
            os.link(staging, final, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
            os.unlink(staging, dir_fd=parent)
        os.fsync(parent)
    except BaseException as error:
        raise EvidencePublicationUncertain("completion publication may be partial; retry forbidden") from error


def _readback(custody: PublicationCustody, name: str, expected: bytes) -> None:
    named_before = os.stat(name, dir_fd=custody.parent_fd, follow_symlinks=False)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=custody.parent_fd)
    try:
        before = os.fstat(descriptor)
        raw = b""
        while len(raw) <= len(expected):
            chunk = os.read(descriptor, min(65_536, len(expected) + 1 - len(raw)))
            if not chunk: break
            raw += chunk
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=custody.parent_fd, follow_symlinks=False)
    finally: os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    directory = os.fstat(custody.parent_fd)
    _require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
             and directory.st_uid == custody.owner_uid
             and stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400
             and before.st_uid == custody.owner_uid and before.st_nlink == 1
             and identity(named_before) == identity(before) == identity(after)
             == identity(named_after) and raw == expected,
             "exact publication readback failed")


@dataclass(frozen=True)
class IssuedCompletionEvidence:
    evidence_sha256: str
    report_sha256: str
    publication_receipt_sha256: str
    custody_root: str


def _project_test_candidate(candidate: production.CampaignCandidate):
    """Return validator fixtures for tests; this route has no publication authority."""
    _require(type(candidate) is production.CampaignCandidate
             and candidate.execution_authority == "test-only",
             "test projection requires a test-only candidate")
    _consume_retained_candidate(candidate)
    validated = _validate(candidate)
    return _canonical(validated.value), _render(validated)


def issue_completion_evidence(candidate: production.CampaignCandidate,
                              custody: PublicationCustody) -> IssuedCompletionEvidence:
    """Consume one retained provider candidate and publish/read back all artifacts."""
    _require(type(candidate) is production.CampaignCandidate
             and candidate.execution_authority == "authenticated-aws-adapter",
             "only authenticated AWS adapter custody can mint completion evidence")
    _require(type(custody) is PublicationCustody and custody._seal is _PUBLICATION_SEAL
             and not custody.used, "publication custody is not fresh")
    custody.used = True
    _consume_retained_candidate(candidate)  # Consume before I/O: uncertain writes cannot retry.
    validated = _validate(candidate)
    evidence = _canonical(validated.value)
    report = _render(validated)
    receipt_value = {
        "version": PUBLICATION_VERSION, "result": "pass",
        "batch_commitment": candidate.approval.batch_commitment,
        "candidate_custody_root": candidate.custody_root,
        "evidence_name": EVIDENCE_NAME, "evidence_sha256": _sha(evidence),
        "report_name": REPORT_NAME, "report_sha256": _sha(report),
        "readback_required": True,
    }
    receipt = _canonical(receipt_value)
    _stage_and_publish(custody, ((EVIDENCE_NAME, evidence), (REPORT_NAME, report),
                                 (RECEIPT_NAME, receipt)))
    try:
        _readback(custody, EVIDENCE_NAME, evidence)
        _readback(custody, REPORT_NAME, report)
        _readback(custody, RECEIPT_NAME, receipt)
    except BaseException as error:
        raise EvidencePublicationUncertain(
            "published completion artifacts failed exact readback; retry forbidden") from error
    return IssuedCompletionEvidence(_sha(evidence), _sha(report), _sha(receipt),
                                    candidate.custody_root)

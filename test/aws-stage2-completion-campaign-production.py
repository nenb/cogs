#!/usr/bin/env python3
"""Provider-free hostile matrix for the closed production controller."""

from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import json
import os
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production
import completion_campaign_aws_adapter as aws_adapter


def d(value): return hashlib.sha256(value.encode()).hexdigest()


def source_bindings():
    return {
        "source_head": "1" * 40, "source_manifest_sha256": d("source"),
        "host_attestation_sha256": d("host-attestation"),
        "runtime_manifest_sha256": d("runtime-manifest"), "rootfs_sha256": d("rootfs-content"),
        "rootfs_descriptor_sha256": d("rootfs"),
        "rootfs_package_manifest_sha256": d("rootfs-package"),
        "rootfs_provenance_sha256": d("rootfs-provenance"),
        "rootfs_publication_receipt_sha256": d("rootfs-publication"),
        "artifact_sha256": d("artifact"), "candidate_sha256": d("candidate"),
        "final_pin_sha256": d("fixture"),
        "guest_program_sha256": production.FULL_PROGRAM_SHA256,
        "owner_implementation_sha256": d("owner-implementation"),
    }


def approval():
    values = dict(
        version="cogs.stage2-completion-production-approval/v6",
        phrase=production.APPROVAL_PHRASE,
        phase_boundary_ordinal=3, phase_cycle_counts=(3, 4),
        implementation_revision="1" * 40,
        control_revision="2" * 40,
        qualification_revision="3" * 40,
        source_manifest_sha256=d("source"),
        source_bindings_sha256=production._commit(
            b"cogs.stage2-source-bindings/v1", source_bindings()),
        static_control_sha256=d("control"),
        pre_aws_package_sha256=d("preaws"), rootfs_descriptor_sha256=d("rootfs"),
        rootfs_package_manifest_sha256=d("rootfs-package"),
        rootfs_provenance_sha256=d("rootfs-provenance"),
        rootfs_qualification_receipt_sha256=d("rootfs-qualification"),
        rootfs_publication_receipt_sha256=d("rootfs-publication"),
        runtime_manifest_sha256=d("runtime-manifest"), fixture_commitment=d("fixture"),
        provider_binary_sha256=d("provider"), aws_cli_sha256=d("aws"), account_commitment=d("account"), partition="aws", region="us-east-1",
        ami_id="ami-" + "a" * 17, ami_owner_id="099720109477",
        ami_architecture="x86_64", ami_virtualization_type="hvm",
        ami_root_device_type="ebs", ami_state="available",
        plan_sha256s=tuple(d(f"plan-{index}") for index in range(1, 8)),
        not_before_unix_ns=1, effect_deadline_ns=480 * 60 * 10**9,
        cleanup_reserve_ns=30 * 60 * 10**9,
        expires_unix_ns=1 + 10 * 60 * 60 * 10**9,
        maximum_cycle_duration_ns=150 * 60 * 10**9,
        maximum_cost_micro_usd=1_100_000,
        rate_source_commitment=production.RATE_SOURCE_COMMITMENT,
        issuer_commitment=d("issuer"), executor_principal_commitment=d("executor"),
        inventory_observer_principal_commitment=d("observer-principal"),
        one_attempt=True,
    )
    values["ami_commitment"] = production.resolved_ami_commitment(values)
    values["batch_commitment"] = production.approval_batch_commitment(values)
    return production.ProductionApproval(**values)


def pages(sequence):
    result = []
    for category in production.INVENTORY_CATEGORIES:
        public = category in {"network_interfaces", "eni_public_associations", "elastic_ips"}
        value = {"category": category, "service": "fake", "operation": "observe",
                 "query_scope": ("account-region-wide-public-address" if public else "campaign-graph"),
                 "ordinal": 1, "request_token_commitment": None,
                 "next_token_commitment": None, "response_commitment": d(f"response-{category}"),
                 "resources": []}
        constructor = dict(value); constructor["resources"] = ()
        result.append(production.InventoryPage(
            **constructor, page_commitment=production._commit(
                b"cogs.stage2-inventory-page/v2", value)))
    return tuple(result)


class Harness:
    def __init__(self, mutate=None, fail=None, uncertain_cleanup=False, approval_value=None):
        self.approval = approval_value or approval(); self.time = 1_000; self.consumed = False
        self.active = False; self.mutate = mutate; self.fail = fail
        self.uncertain_cleanup = uncertain_cleanup; self.calls = []
        self.journal_rows = []; self.inventory_count = 0; self.cleanup_count = 0

    def now(self): return self.time
    def tick(self): self.time += 10; return self.time

    def consume(self, value, commitment, observed):
        if self.consumed or value is not self.approval: raise production.ProductionApprovalError()
        self.consumed = True
        raw = production._canonical({
            "version": "cogs.stage2-production-approval-consumption/v1",
            "approval_commitment": commitment,
            "batch_commitment": value.batch_commitment,
            "consumed_unix_ns": observed, "first_created": True}) + b"\n"
        return production.ApprovalConsumptionReceipt(
            commitment, d("auth"), hashlib.sha256(raw).hexdigest(), observed, True)

    def effect(self, kind, grant, previous):
        self.calls.append((kind, grant.ordinal, grant.mode))
        if self.fail == (kind, grant.ordinal):
            if kind != "plan": self.active = True
            raise production.ProductionUncertainty()
        if kind == "apply":
            if self.active: raise AssertionError("overlap")
            self.active = True
        if kind == "destroy": self.active = False
        state_ordinal = 1 if self.mutate == "state" and grant.ordinal == 2 else grant.ordinal
        state = production._commit(b"cogs.stage2-provider-state-slot/v1", {
            "batch_commitment": grant.batch_commitment, "ordinal": state_ordinal})
        lineage = production._commit(b"cogs.stage2-provider-state-lineage/v1", {
            "batch_commitment": grant.batch_commitment, "ordinal": state_ordinal,
            "state_slot": f"cycle-{state_ordinal}"})
        state_bytes = ("0" * 64 if kind == "plan" else
                       d(f"state-bytes-{grant.ordinal}") if kind in {"apply", "running"} else
                       d(f"destroyed-state-bytes-{grant.ordinal}"))
        identity = grant.plan_sha256 if kind == "plan" else d(f"{kind}-{grant.ordinal}")
        resource_ordinal = (1 if self.mutate == "instance_resource_replay" and grant.ordinal == 2
                            else grant.ordinal)
        resources = (tuple(sorted((
            ("instance", d(f"instance-resource-{resource_ordinal}")),
            ("root_volume", d(f"root-volume-{grant.ordinal}")),
            ("launch_template_generation", d(f"launch-template-{grant.ordinal}")),
        ))) if kind == "running" else
            (("pre_destroy_receipt", d(f"pre-destroy-{grant.ordinal}")),)
            if kind == "destroy" else ())
        start = self.tick(); end = self.tick()
        fields = dict(kind=kind, grant_commitment=grant.grant_commitment,
            batch_commitment=grant.batch_commitment, ordinal=grant.ordinal, mode=grant.mode,
            state_commitment=state, state_bytes_sha256=state_bytes,
            state_lineage_commitment=lineage, identity_commitment=identity,
            intent_commitment=production._commit(b"cogs.stage2-provider-effect-intent/v1", {
                "kind": kind, "grant": grant.grant_commitment,
                "previous": None if previous is None else previous.settlement_commitment}),
            ami_commitment=grant.ami_commitment,
            resource_commitments=resources, observed_started_unix_ns=start,
            observed_ended_unix_ns=end, invocation_count=1, certain=True)
        receipt = production.EffectReceipt(**fields, settlement_commitment=production._commit(
            b"cogs.stage2-provider-effect-settlement/v1", fields))
        self.journal_rows.extend((("effect", "intent", grant.ordinal, grant.mode,
                                   receipt.intent_commitment),
                                  ("effect", "settled", grant.ordinal, grant.mode,
                                   receipt.settlement_commitment)))
        return receipt

    def remote(self, grant, apply, running, effect_deadline):
        if not (type(effect_deadline) is int and effect_deadline > self.time):
            raise RuntimeError("remote deadline")
        self.calls.append(("remote", grant.ordinal, grant.mode))
        if self.fail == ("remote", grant.ordinal):
            self.active = True; raise production.ProductionUncertainty()
        rootfs = d("other-rootfs") if self.mutate == "rootfs" and grant.ordinal == 2 else grant.rootfs_descriptor_sha256
        instance = ((d("running-1") if self.mutate == "instance" else d("foreign-instance"))
                    if self.mutate in {"instance", "instance_drift"} and grant.ordinal == 2
                    else running.identity_commitment)
        operation_ordinal = 1 if self.mutate == "operation" and grant.ordinal == 2 else grant.ordinal
        workloads = tuple(
            production.WorkloadMeasurement(category, sample, 100 + sample,
                                            d(f"workload-{category}-{sample}"))
            for category in ("git", "build", "install") for sample in range(1, 8)
        ) if grant.mode == "full" else ()
        operation = d(f"operation-{operation_ordinal}")
        runtime_ordinal = (1 if self.mutate == "qemu_replay" and grant.ordinal == 2
                           else grant.ordinal)
        mapping_ordinal = (1 if self.mutate == "mapping_replay" and grant.ordinal == 2
                           else grant.ordinal)
        pre_ordinal = (1 if self.mutate == "pre_fact_replay" and grant.ordinal == 2
                       else grant.ordinal)
        post_ordinal = (2 if self.mutate == "post_fact_replay" and grant.ordinal == 3
                        else grant.ordinal)
        qemu_values = dict(
            operation_token=operation, live_mapping_sha256=d(f"mapping-{mapping_ordinal}"),
            qemu_argv_sha256=d(f"qemu-argv-{runtime_ordinal}"), qemu_pid=100 + runtime_ordinal,
            qemu_starttime=200 + runtime_ordinal, qemu_executable_device=8,
            qemu_executable_inode=300 + runtime_ordinal, observer_qmp_device=9,
            observer_qmp_inode=400 + runtime_ordinal, kvm_device=10,
            kvm_inode=500 + runtime_ordinal, kvm_rdev=11, kvm_api=12,
            qmp_present=True, qmp_enabled=True)
        identity = production._runtime_identity(SimpleNamespace(**qemu_values))
        pre_fact = (d("post-ssh-2") if self.mutate == "cross_pre_from_post"
                    and grant.ordinal == 3 else d(f"pre-ssh-{pre_ordinal}"))
        post_fact = (d("pre-ssh-2") if self.mutate == "cross_post_from_pre"
                     and grant.ordinal == 3 else d(f"post-ssh-{post_ordinal}"))
        qemu = production.RemoteQemuBindings(
            **qemu_values, runtime_identity_sha256=identity,
            pre_ssh_runtime_fact_sha256=pre_fact,
            post_ssh_runtime_fact_sha256=(post_fact if grant.mode == "readiness" else None))
        program, marker = production.REMOTE_PROGRAMS[grant.mode]
        source_values = source_bindings()
        if self.mutate == "remote_source" and grant.ordinal == 2:
            source_values["host_attestation_sha256"] = d("hostile-source")
        parser = (d("hostile-parser") if self.mutate == "remote_parser"
                  and grant.ordinal == 2 else production.REMOTE_PARSERS[grant.mode])
        bindings = production.RemoteBindingProjection(
            production.RemoteSourceBindings(**source_values),
            production._cycle_capability(grant.mode, program, marker), program,
            parser, marker, qemu)
        receipt = production.RemoteReceipt(
            grant.grant_commitment, grant.batch_commitment, grant.ordinal, grant.mode,
            apply.state_commitment, apply.state_lineage_commitment,
            instance, d(f"host-{grant.ordinal}"),
            operation, d(f"boot-{grant.ordinal}"),
            (d("host-key-1") if self.mutate == "cross_key_replay" and grant.ordinal == 2
             else d(f"client-key-{grant.ordinal}")),
            d(f"host-key-{grant.ordinal}"), rootfs,
            grant.ami_commitment, apply.observed_started_unix_ns,
            running.observed_ended_unix_ns, 100, 200, workloads, bindings, True)
        if self.mutate == "remote_qemu" and grant.ordinal == 2:
            object.__setattr__(qemu, "qemu_pid", qemu.qemu_pid + 1)
        return receipt

    def inventory(self, grant, destroyed, sequence):
        self.inventory_count += 1
        if self.fail == ("inventory", sequence):
            raise production.ProductionUncertainty()
        cycle = sequence if sequence <= 7 else None
        source = 1 if self.mutate == "observer" and sequence == 2 else sequence
        start = self.tick(); end = self.tick(); page_rows = pages(sequence)
        fields = {
            "batch_commitment": self.approval.batch_commitment,
            "observation_sequence": sequence, "cycle_ordinal": cycle,
            "observer_commitment": d(f"observer-{source}"),
            "session_commitment": d(f"session-{sequence}"),
            "run_commitment": d(f"run-{sequence}"),
            "account_commitment": self.approval.account_commitment,
            "region": self.approval.region,
            "destroyed_state_commitment": destroyed.state_commitment,
            "observed_started_unix_ns": start, "observed_ended_unix_ns": end,
            "page_commitments": [item.page_commitment for item in page_rows],
        }
        return production.InventoryReceipt(
            self.approval.batch_commitment, sequence, cycle,
            fields["observer_commitment"], fields["session_commitment"],
            fields["run_commitment"], self.approval.account_commitment,
            self.approval.region, destroyed.state_commitment, start, end, page_rows,
            production._commit(b"cogs.stage2-zero-inventory/v2", fields), True)

    def cost(self, grant, apply, destroy):
        duration = destroy.observed_ended_unix_ns - apply.observed_started_unix_ns
        rate = 118_000
        fields = {"grant_commitment": grant.grant_commitment,
                  "cycle_ordinal": grant.ordinal,
                  "rate_source_commitment": production._commit(
                      b"cogs.stage2-fixed-rate/v1", {"micro_usd_per_hour": rate}),
                  "usage_commitment": production._commit(
                      b"cogs.stage2-provider-usage/v1", {"duration_ns": duration}),
                  "cost_micro_usd": (duration * rate + 3_600_000_000_000 - 1) // 3_600_000_000_000}
        return production.CostReceipt(**fields, receipt_commitment=production._commit(
            b"cogs.stage2-cost-receipt/v1", fields))

    def recover(self, grant, state, last_certain, primary):
        self.cleanup_count += 1; self.active = False
        if self.uncertain_cleanup:
            inventory = None
        else:
            class Destroyed: state_commitment = state
            inventory = self.inventory(grant, Destroyed(), grant.ordinal)
        return production.CleanupReceipt(
            grant.grant_commitment, state, d(f"cleanup-{grant.ordinal}"), inventory,
            False, not self.uncertain_cleanup)

    def journal(self, *row): self.journal_rows.append(row)

    def journal_state(self):
        sequence, tip = 0, "0" * 64
        for category, event, ordinal, mode, commitment in self.journal_rows:
            row = {"version": "cogs.stage2-production-campaign-journal/v1",
                   "sequence": sequence, "previous_sha256": tip,
                   "category": category, "event": event, "ordinal": ordinal,
                   "mode": mode, "commitment": commitment}
            tip = hashlib.sha256(production._canonical(row) + b"\n").hexdigest()
            sequence += 1
        return sequence, tip

    def ports(self):
        return production._issue_test_ports(
            self.approval, self.now, self.consume, self.effect, self.remote,
            self.inventory, self.cost, self.recover, self.journal, self.journal_state)


def close_phase(result, approved, run_id):
    revision = "4" * 40
    continuation = production.continuation_for_phase_one(
        result, approved, "test-only", revision, run_id, 20, 10, 11,
        "sha256:" + "5" * 64,
        f"stage2-production-approval-{revision}-10")
    fields = {
        "version": production.CONTINUATION_ADMISSION_VERSION,
        "repository": "nenb/cogs",
        "workflow_path": ".github/workflows/stage2-production-campaign.yml",
        "workflow_revision": revision, "ref": "refs/heads/main",
        "run_id": run_id, "run_attempt": 1,
        "producer_job_name": "cycles_1_3", "producer_job_id": 20,
        "consumer_job_name": "cycles_4_7", "consumer_job_id": 21,
        "continuation_sha256": hashlib.sha256(
            continuation.canonical_bytes()).hexdigest(),
        "continuation_commitment": continuation.continuation_commitment,
        "bundle_sha256": d("bundle"), "trusted_root_sha256": d("root"),
        "signer_identity": "https://github.com/nenb/cogs/.github/workflows/"
            "stage2-production-campaign.yml@refs/heads/main",
        "artifact_id": 22, "artifact_digest": "sha256:" + d("archive"),
        "artifact_name": f"stage2-production-continuation-{revision}-{run_id}-1",
        "approval_commitment": continuation.approval_commitment,
        "authentication_receipt_sha256":
            continuation.consumption.authentication_receipt_sha256,
        "batch_commitment": continuation.batch_commitment,
        "implementation_revision": continuation.implementation_revision,
        "control_revision": continuation.control_revision,
        "qualification_revision": continuation.qualification_revision,
        "journal_sequence": continuation.journal_sequence,
        "journal_tip_sha256": continuation.journal_tip_sha256,
        "cycle3_zero_commitment": continuation.inventories[-1].zero_commitment,
    }
    admission = production.ContinuationAdmission(
        **fields, admission_commitment=production._commit(
            b"cogs.stage2-production-handoff-authentication/v1", fields))
    return continuation, admission


def authenticate(continuation, admission, approved):
    return production._issue_test_authenticated_phase_one(
        continuation, admission, approved)


h = Harness(); controller = production.ProductionCampaignController(h.ports())
phase = controller.run_phase_one()
continuation, admission = close_phase(phase, h.approval, 101)
assert tuple(item.ordinal for item in continuation.grants) == (1, 2, 3)
assert [row[1] for row in h.calls if row[0] == "remote"] == [1, 2, 3]
raw = continuation.canonical_bytes()
schema_output = os.environ.get("COGS_STAGE2_SCHEMA_OUTPUT")
if schema_output is not None:
    output = Path(schema_output); output.mkdir(mode=0o700)
    (output / "continuation.json").write_bytes(raw)
    (output / "admission.json").write_bytes(admission.canonical_bytes())
assert production.continuation_from_bytes(raw, h.approval, 101, 1, "test-only") == continuation
for hostile in (raw[:-2] + b"x\n", raw.replace(b'"github_run_id":101', b'"github_run_id":102')):
    try: production.continuation_from_bytes(hostile, h.approval, 101, 1, "test-only")
    except production.ProductionCampaignError: pass
    else: raise AssertionError("hostile continuation accepted")
try: controller.run_phase_two(authenticate(continuation, admission, h.approval))
except production.ProductionCampaignError: pass
else: raise AssertionError("same controller accepted direct in-memory handoff")
candidate = production.ProductionCampaignController(h.ports()).run_phase_two(
    authenticate(continuation, admission, h.approval))
assert candidate.actual_duration_ns == candidate.final_zero_unix_ns - candidate.first_apply_unix_ns
assert candidate.total_cost_micro_usd == 7 and len(candidate.cycle_commitments) == 7
assert len(candidate.launch_ready_samples_ns) == len(candidate.ssh_ready_samples_ns) == 7
assert len(candidate.workload_measurements) == 21 and len(candidate.inventories) == 8
assert all(item.bindings.source.runtime_manifest_sha256 == candidate.approval.runtime_manifest_sha256
           for item in candidate.remotes)
assert len({item.bindings.qemu.runtime_identity_sha256 for item in candidate.remotes}) == 7
assert all(item.bindings.qemu.runtime_identity_sha256 != candidate.approval.runtime_manifest_sha256
           for item in candidate.remotes)
assert h.inventory_count == 8 and not h.active and h.cleanup_count == 0
assert [row[2] for row in h.calls if row[0] == "remote"] == list(production.CYCLE_MODES)

# A fresh second-job controller resumes without consuming the approval again;
# run/attempt substitution, stale admission, and canonical-byte tampering fail.
first_job = Harness(); first_controller = production.ProductionCampaignController(first_job.ports())
resume, resume_admission = close_phase(first_controller.run_phase_one(), first_job.approval, 202)
second_job = Harness(approval_value=first_job.approval)
second_job.time = resume.inventories[-1].observed_ended_unix_ns + 10
resumed = production.ProductionCampaignController(second_job.ports()).run_phase_two(
    authenticate(resume, resume_admission, first_job.approval))
assert first_job.consumed and not second_job.consumed
assert first_job.inventory_count == 3 and second_job.inventory_count == 5
assert tuple(item.ordinal for item in resumed.grants) == tuple(range(1, 8))
for field, value in (("run_id", 203), ("run_attempt", 2),
                     ("producer_job_id", 99), ("artifact_id", 99)):
    fresh = Harness(approval_value=first_job.approval)
    try:
        hostile = replace(resume_admission, **{field: value})
        authenticated = authenticate(resume, hostile, first_job.approval)
        production.ProductionCampaignController(fresh.ports()).run_phase_two(authenticated)
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"cross-run handoff field accepted: {field}")
stale = Harness(approval_value=first_job.approval)
stale.time = resume.effect_deadline_unix_ns
try: production.ProductionCampaignController(stale.ports()).run_phase_two(
    authenticate(resume, resume_admission, first_job.approval))
except production.ProductionCampaignError: pass
else: raise AssertionError("expired continuation accepted")

# Every durable phase-two import boundary is cleanup-recoverable without
# consuming the approval again or executing a cycle.
class ImportCustodian:
    def __init__(self, approval):
        self.approval = approval; self.first_apply_started = None
    def _append(self, category, event, ordinal, mode, commitment):
        anchor = json.loads(aws_adapter.CONTINUATION_ANCHOR.read_bytes())
        row = {"version": "cogs.stage2-production-campaign-journal/v1",
               "sequence": anchor["sequence"], "previous_sha256": anchor["tip_sha256"],
               "category": category, "event": event, "ordinal": ordinal,
               "mode": mode, "commitment": commitment}
        aws_adapter.JOURNAL.write_bytes(aws_adapter._canonical(row))
        os.chmod(aws_adapter.JOURNAL, 0o600)
    def _journal_state(self, _descriptor, _repair_tail=False): return (1, d("tip"))

original_imports = tuple(getattr(aws_adapter, name) for name in (
    "CONSUMED", "JOURNAL", "ACTIVE", "CLEANUP_COMPLETE", "SEGMENT_COMPLETE",
    "CONTINUATION_ANCHOR", "_continuation", "_read_fixed", "_import_checkpoint"))
try:
    for crashed_at in ("consumption", "anchor", "continued"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, leaf in (("CONSUMED", "consumed"), ("JOURNAL", "journal"),
                               ("ACTIVE", "active"), ("CLEANUP_COMPLETE", "cleanup"),
                               ("SEGMENT_COMPLETE", "segment"),
                               ("CONTINUATION_ANCHOR", "anchor")):
                setattr(aws_adapter, name, root / leaf)
            aws_adapter._continuation = lambda *_args: (resume, resume_admission)
            aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
            aws_adapter._import_checkpoint = lambda name: (_ for _ in ()).throw(
                RuntimeError("crash")) if name == crashed_at else None
            custodian = ImportCustodian(first_job.approval)
            try: aws_adapter._import_continuation(custodian, resume, resume_admission)
            except RuntimeError: pass
            else: raise AssertionError(f"missing injected crash at {crashed_at}")
            aws_adapter._import_checkpoint = lambda _name: None
            aws_adapter._repair_continuation_import(
                custodian, first_job.approval,
                resume.consumption.authentication_receipt_sha256)
            assert all(path.exists() for path in (
                aws_adapter.CONSUMED, aws_adapter.CONTINUATION_ANCHOR,
                aws_adapter.JOURNAL))
            assert custodian.first_apply_started == resume.first_apply_unix_ns
finally:
    for name, value in zip((
            "CONSUMED", "JOURNAL", "ACTIVE", "CLEANUP_COMPLETE", "SEGMENT_COMPLETE",
            "CONTINUATION_ANCHOR", "_continuation", "_read_fixed", "_import_checkpoint"),
            original_imports, strict=True):
        setattr(aws_adapter, name, value)

# Empty and every partial first-record boundary are reconstructible only from
# authenticated continuation/consumption state; no cycle callback is reachable.
original_boundaries = tuple(getattr(aws_adapter, name) for name in (
    "CONSUMED", "JOURNAL", "CONTINUATION_ANCHOR", "_continuation", "_read_fixed"))
continued_line = aws_adapter._canonical({
    "version": "cogs.stage2-production-campaign-journal/v1",
    "sequence": resume.journal_sequence, "previous_sha256": resume.journal_tip_sha256,
    "category": "batch", "event": "continued", "ordinal": None, "mode": None,
    "commitment": resume_admission.admission_commitment})
consumed_raw = aws_adapter._canonical({
    "version": "cogs.stage2-production-approval-consumption/v1",
    "approval_commitment": resume.approval_commitment,
    "batch_commitment": resume.batch_commitment,
    "consumed_unix_ns": resume.consumption.consumed_unix_ns,
    "first_created": True})
anchor_raw = aws_adapter._canonical({
    "version": "cogs.stage2-production-continuation-journal-anchor/v1",
    "sequence": resume.journal_sequence, "tip_sha256": resume.journal_tip_sha256,
    "continuation_commitment": resume.continuation_commitment,
    "admission_commitment": resume_admission.admission_commitment})
try:
    for boundary in range(len(continued_line)):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aws_adapter.CONSUMED = root / "consumed"
            aws_adapter.JOURNAL = root / "journal"
            aws_adapter.CONTINUATION_ANCHOR = root / "anchor"
            aws_adapter.CONSUMED.write_bytes(consumed_raw)
            aws_adapter.CONTINUATION_ANCHOR.write_bytes(anchor_raw)
            aws_adapter.JOURNAL.write_bytes(continued_line[:boundary])
            for path in (aws_adapter.CONSUMED, aws_adapter.CONTINUATION_ANCHOR,
                         aws_adapter.JOURNAL): path.chmod(0o600)
            aws_adapter._continuation = lambda *_args: (resume, resume_admission)
            aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
            custodian = ImportCustodian(first_job.approval)
            custodian._journal_state = aws_adapter.AwsCampaignCustodian._journal_state.__get__(
                custodian, ImportCustodian)
            aws_adapter._repair_continuation_import(
                custodian, first_job.approval,
                resume.consumption.authentication_receipt_sha256)
            assert aws_adapter.JOURNAL.read_bytes() == continued_line
            assert custodian.first_apply_started == resume.first_apply_unix_ns

    consumed_line = aws_adapter._canonical({
        "version": "cogs.stage2-production-campaign-journal/v1",
        "sequence": 0, "previous_sha256": "0" * 64,
        "category": "batch", "event": "consumed", "ordinal": None, "mode": None,
        "commitment": hashlib.sha256(consumed_raw).hexdigest()})
    for boundary in (0, 1, len(consumed_line) // 2, len(consumed_line) - 1):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aws_adapter.CONSUMED = root / "consumed"
            aws_adapter.JOURNAL = root / "journal"
            aws_adapter.CONTINUATION_ANCHOR = root / "absent-anchor"
            aws_adapter.CONSUMED.write_bytes(consumed_raw)
            aws_adapter.JOURNAL.write_bytes(consumed_line[:boundary])
            aws_adapter.CONSUMED.chmod(0o600); aws_adapter.JOURNAL.chmod(0o600)
            aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
            consumption = aws_adapter._phase_one_consumption(
                first_job.approval,
                resume.consumption.authentication_receipt_sha256)
            custodian = ImportCustodian(first_job.approval)
            custodian._journal_state = aws_adapter.AwsCampaignCustodian._journal_state.__get__(
                custodian, ImportCustodian)
            aws_adapter._repair_first_journal_record(
                custodian, "batch", "consumed", consumption.durable_record_commitment)
            assert aws_adapter.JOURNAL.read_bytes() == consumed_line
finally:
    for name, value in zip(("CONSUMED", "JOURNAL", "CONTINUATION_ANCHOR",
                            "_continuation", "_read_fixed"),
                           original_boundaries, strict=True):
        setattr(aws_adapter, name, value)

# Interrupted write-once records recover through an fsynced staging inode and
# atomic no-replace publication for every lifecycle record class.
for leaf in ("approval-consumed.json", "continuation-journal-anchor.json",
             "campaign-journal.jsonl", "cleanup-complete.json"):
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / leaf; payload = (leaf + "\n").encode()
        original_write = aws_adapter.os.write
        def interrupted(descriptor, value):
            original_write(descriptor, value[:max(1, len(value) // 2)])
            raise OSError("injected interrupted write")
        aws_adapter.os.write = interrupted
        try:
            try: aws_adapter._write_once(target, payload)
            except OSError: pass
            else: raise AssertionError("interrupted write unexpectedly completed")
        finally: aws_adapter.os.write = original_write
        assert not target.exists()
        aws_adapter._write_once(target, payload)
        assert target.read_bytes() == payload
        assert not any(path.name.startswith(".write-once-") for path in target.parent.iterdir())

# Recovery receipt mismatches never reach settlement and cannot remove ACTIVE.
grant = resume.grants[0]; state = resume.effects[0][1].state_commitment
valid_cleanup = production.CleanupReceipt(
    grant.grant_commitment, state, d("reconciliation"), resume.inventories[0],
    False, True)
with tempfile.TemporaryDirectory() as directory:
    active = Path(directory) / "cleanup-active.json"; active.write_bytes(b"active\n")
    def hostile_inventory(**changes):
        inventory = valid_cleanup.inventory
        values = {name: getattr(inventory, name) for name in (
            "batch_commitment", "observation_sequence", "cycle_ordinal",
            "observer_commitment", "session_commitment", "run_commitment",
            "account_commitment", "region", "destroyed_state_commitment",
            "observed_started_unix_ns", "observed_ended_unix_ns")}
        values.update(changes)
        preimage = {**values,
                    "page_commitments": [item.page_commitment for item in inventory.pages]}
        return replace(inventory, **changes, zero_commitment=production._commit(
            b"cogs.stage2-zero-inventory/v2", preimage))
    hostile_receipts = (
        replace(valid_cleanup, grant_commitment=d("wrong-grant")),
        replace(valid_cleanup, state_commitment=d("wrong-state")),
        replace(valid_cleanup, certain_zero=False, inventory=None),
        replace(valid_cleanup, inventory=hostile_inventory(
            batch_commitment=d("wrong-batch"))),
        replace(valid_cleanup, inventory=hostile_inventory(
            destroyed_state_commitment=d("wrong-inventory-state"))),
    )
    for receipt in hostile_receipts:
        try: aws_adapter._validated_recovery_receipt(
            receipt, grant, state, first_job.approval)
        except production.ProductionUncertainty: pass
        else: raise AssertionError("hostile cleanup receipt settled")
        assert active.read_bytes() == b"active\n"
    assert aws_adapter._validated_recovery_receipt(
        valid_cleanup, grant, state, first_job.approval) is valid_cleanup

# Cleanup settlement is restartable after proof publication and after journal
# publication; ACTIVE remains until both records are durable.
original_cleanup_paths = tuple(getattr(aws_adapter, name) for name in (
    "ROOT", "ACTIVE", "CLEANUP_COMPLETE", "JOURNAL", "_ensure_cleanup_journal",
    "_read_fixed"))
try:
    for crash_after_journal in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); aws_adapter.ROOT = root
            aws_adapter.ACTIVE = root / "active"
            aws_adapter.CLEANUP_COMPLETE = root / "complete"
            aws_adapter.JOURNAL = root / "journal"
            aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
            aws_adapter.ACTIVE.write_bytes(b"active\n"); aws_adapter.ACTIVE.chmod(0o600)
            custodian = ImportCustodian(first_job.approval)
            custodian._journal_state = aws_adapter.AwsCampaignCustodian._journal_state.__get__(
                custodian, ImportCustodian)
            production_ensure = original_cleanup_paths[-2]
            def original_ensure(*args):
                real_fstat = os.fstat
                def root_fstat(descriptor):
                    values = list(real_fstat(descriptor)); values[4:6] = (0, 0)
                    return os.stat_result(values)
                os.fstat = root_fstat
                try: return production_ensure(*args)
                finally: os.fstat = real_fstat
            def interrupted_settlement(*args):
                if crash_after_journal: original_ensure(*args)
                raise RuntimeError("injected cleanup settlement crash")
            aws_adapter._ensure_cleanup_journal = interrupted_settlement
            try:
                aws_adapter._settle_cleanup_transition(
                    custodian, grant.grant_commitment, state, grant.ordinal,
                    grant.mode, valid_cleanup.reconciliation_commitment)
            except RuntimeError: pass
            else: raise AssertionError("cleanup settlement crash missing")
            assert aws_adapter.CLEANUP_COMPLETE.exists() and aws_adapter.ACTIVE.exists()
            aws_adapter._ensure_cleanup_journal = original_ensure
            aws_adapter._settle_cleanup_transition(
                custodian, grant.grant_commitment, state, grant.ordinal,
                grant.mode, valid_cleanup.reconciliation_commitment)
            assert not aws_adapter.ACTIVE.exists()
            rows = aws_adapter.JOURNAL.read_bytes().splitlines()
            assert len(rows) == 1 and json.loads(rows[0])["event"] == "settled"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); aws_adapter.ROOT = root
        aws_adapter.ACTIVE = root / "active"
        aws_adapter.CLEANUP_COMPLETE = root / "complete"
        aws_adapter.JOURNAL = root / "journal"
        aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
        aws_adapter.ACTIVE.write_bytes(b"active\n"); aws_adapter.ACTIVE.chmod(0o600)
        custodian = ImportCustodian(first_job.approval)
        custodian._journal_state = aws_adapter.AwsCampaignCustodian._journal_state.__get__(
            custodian, ImportCustodian)
        aws_adapter._ensure_cleanup_journal = original_ensure
        real_fsync = os.fsync
        def crash_after_active_retirement(descriptor):
            if not aws_adapter.ACTIVE.exists():
                raise RuntimeError("injected post-ACTIVE crash")
            return real_fsync(descriptor)
        os.fsync = crash_after_active_retirement
        try:
            try:
                aws_adapter._settle_cleanup_transition(
                    custodian, grant.grant_commitment, state, grant.ordinal,
                    grant.mode, valid_cleanup.reconciliation_commitment)
            except RuntimeError: pass
            else: raise AssertionError("post-ACTIVE crash missing")
        finally: os.fsync = real_fsync
        assert (not aws_adapter.ACTIVE.exists()
                and aws_adapter.CLEANUP_COMPLETE.exists()
                and len(aws_adapter.JOURNAL.read_bytes().splitlines()) == 1)
finally:
    for name, value in zip(("ROOT", "ACTIVE", "CLEANUP_COMPLETE", "JOURNAL",
                            "_ensure_cleanup_journal", "_read_fixed"),
                           original_cleanup_paths, strict=True):
        setattr(aws_adapter, name, value)

# A consumed campaign with no ACTIVE record publishes a deterministic terminal
# proof before credential retirement, and replay validates/reuses exact bytes.
no_active_names = (
    "ROOT", "STATE_ROOT", "CONSUMED", "JOURNAL", "ACTIVE", "CLEANUP_COMPLETE",
    "SEGMENT_COMPLETE", "AWS_CREDENTIALS", "CONTINUATION", "CONTINUATION_BUNDLE",
    "CONTINUATION_ADMISSION", "CONTINUATION_ANCHOR", "_admit_root", "_root_lock",
    "_approval", "_drain_stale_command_scope", "_retire_credentials",
    "_phase_one_consumption", "_repair_first_journal_record", "_read_fixed")
no_active_original = tuple(getattr(aws_adapter, name) for name in no_active_names)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); state_root = root / "state"; state_root.mkdir()
    paths = {
        "ROOT": root, "STATE_ROOT": state_root, "CONSUMED": root / "consumed",
        "JOURNAL": root / "journal", "ACTIVE": root / "active",
        "CLEANUP_COMPLETE": root / "complete", "SEGMENT_COMPLETE": root / "segment",
        "AWS_CREDENTIALS": root / "credentials", "CONTINUATION": root / "continuation",
        "CONTINUATION_BUNDLE": root / "bundle", "CONTINUATION_ADMISSION": root / "admission",
        "CONTINUATION_ANCHOR": root / "anchor"}
    for name, value in paths.items(): setattr(aws_adapter, name, value)
    paths["CONSUMED"].write_bytes(b"consumed\n")
    row = {"version": "cogs.stage2-production-campaign-journal/v1",
           "sequence": 0, "previous_sha256": "0" * 64, "category": "batch",
           "event": "consumed", "ordinal": None, "mode": None,
           "commitment": resume.consumption.durable_record_commitment}
    paths["JOURNAL"].write_bytes(aws_adapter._canonical(row)); paths["JOURNAL"].chmod(0o600)
    aws_adapter._admit_root = lambda: None
    aws_adapter._root_lock = lambda: os.open(root / "lock", os.O_RDWR | os.O_CREAT, 0o600)
    approval_requirements = []
    def recovery_approval(required=True):
        approval_requirements.append(required)
        return first_job.approval, resume.consumption.authentication_receipt_sha256
    aws_adapter._approval = recovery_approval
    aws_adapter._drain_stale_command_scope = lambda approval: (
        approval is first_job.approval) or (_ for _ in ()).throw(AssertionError())
    aws_adapter._phase_one_consumption = lambda *_args: resume.consumption
    aws_adapter._repair_first_journal_record = lambda *_args: None
    aws_adapter._read_fixed = lambda path, *_args: path.read_bytes()
    retirements = []
    def retire_after_proof():
        assert paths["CLEANUP_COMPLETE"].exists()
        if paths["AWS_CREDENTIALS"].exists():
            paths["AWS_CREDENTIALS"].unlink()
        retirements.append(paths["CLEANUP_COMPLETE"].read_bytes())
    aws_adapter._retire_credentials = retire_after_proof
    try:
        # Segment one crashed after publishing its zero marker but before
        # credential unlink. Recovery publishes/reuses proof and retires once.
        paths["SEGMENT_COMPLETE"].write_bytes(b"certain zero\n")
        paths["AWS_CREDENTIALS"].write_bytes(b"credentials\n")
        first_receipt = aws_adapter.recover_fixed_campaign()
        first_proof = paths["CLEANUP_COMPLETE"].read_bytes()
        second_receipt = aws_adapter.recover_fixed_campaign()
        assert first_receipt == second_receipt
        assert not paths["AWS_CREDENTIALS"].exists()
        assert paths["SEGMENT_COMPLETE"].exists()
        assert paths["CLEANUP_COMPLETE"].read_bytes() == first_proof

        # Segment two crashed after cleanup proof but before credential unlink.
        paths["SEGMENT_COMPLETE"].unlink()
        inactive_reconciliation = production._commit(
            b"cogs.stage2-inactive-root-retirement/v1", {"root": str(root)})
        phase_two_proof = aws_adapter._canonical({
            "version": "cogs.stage2-cleanup-complete/v1",
            "reconciliation_commitment": inactive_reconciliation,
            "certain_zero": True})
        paths["CLEANUP_COMPLETE"].write_bytes(phase_two_proof)
        paths["AWS_CREDENTIALS"].write_bytes(b"credentials\n")
        third_receipt = aws_adapter.recover_fixed_campaign()
        fourth_receipt = aws_adapter.recover_fixed_campaign()
        assert third_receipt == fourth_receipt
        assert paths["CLEANUP_COMPLETE"].read_bytes() == phase_two_proof
        assert not paths["AWS_CREDENTIALS"].exists()

        # Legacy inverse boundary remains credential-free: unlink+fsync happened
        # before either terminal marker, and repeated recovery is deterministic.
        paths["CLEANUP_COMPLETE"].unlink()
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        fifth_receipt = aws_adapter.recover_fixed_campaign()
        credential_free_proof = paths["CLEANUP_COMPLETE"].read_bytes()
        sixth_receipt = aws_adapter.recover_fixed_campaign()
        assert fifth_receipt == sixth_receipt
        assert json.loads(credential_free_proof)["terminal_state"] == "no-active"
        assert paths["CLEANUP_COMPLETE"].read_bytes() == credential_free_proof
        assert len(retirements) == 6
        assert approval_requirements == [False] * 6
        assert not (root / "evidence-publication").exists() and not paths["SEGMENT_COMPLETE"].exists()
    finally:
        for name, value in zip(no_active_names, no_active_original, strict=True):
            setattr(aws_adapter, name, value)

# Runner-owned pathname swaps during cosign verification cannot split the
# verified bytes from the continuation bytes admitted into root custody.
stager = runpy.run_path(str(ROOT / "scripts/stage2-stage-production-approval.py"))
original_os_routes = (os.geteuid, os.getegid, os.chown, os.fchown)
original_adapter_routes = tuple(getattr(aws_adapter, name) for name in (
    "ROOT", "CONSUMED", "JOURNAL", "CONTINUATION", "CONTINUATION_BUNDLE",
    "CONTINUATION_ADMISSION", "_approval", "_verify_blob"))
with tempfile.TemporaryDirectory() as directory:
    base = Path(directory); source = base / "runner"; custody = base / "root"
    source.mkdir(mode=0o700); custody.mkdir(mode=0o700)
    authoritative_fields = asdict(continuation)
    authoritative_fields["execution_authority"] = "authenticated-aws-adapter"
    authoritative_fields.pop("continuation_commitment")
    authoritative = replace(
        continuation, execution_authority="authenticated-aws-adapter",
        continuation_commitment=production._commit(
            b"cogs.stage2-production-continuation/v1", authoritative_fields))
    continuation_raw = authoritative.canonical_bytes(); bundle_raw = b"bundle"
    (source / aws_adapter.CONTINUATION_NAME).write_bytes(continuation_raw)
    (source / aws_adapter.CONTINUATION_BUNDLE_NAME).write_bytes(bundle_raw)
    for path in source.iterdir(): path.chmod(0o400)
    caller_uid, caller_gid = source.stat().st_uid, source.stat().st_gid
    issuance = base / "issuance"; issuance.mkdir()
    (issuance / aws_adapter.CONTINUATION_NAME).write_bytes(continuation_raw)
    (issuance / aws_adapter.CONTINUATION_BUNDLE_NAME).write_bytes(bundle_raw)
    admission_fields = {
        "version": production.CONTINUATION_ADMISSION_VERSION,
        "repository": "nenb/cogs",
        "workflow_path": ".github/workflows/stage2-production-campaign.yml",
        "workflow_revision": "4" * 40,
        "ref": "refs/heads/main",
        "run_id": 101,
        "run_attempt": 1,
        "producer_job_name": "cycles_1_3",
        "producer_job_id": 20,
        "consumer_job_name": "cycles_4_7",
        "consumer_job_id": 21,
        "continuation_sha256": hashlib.sha256(continuation_raw).hexdigest(),
        "continuation_commitment": authoritative.continuation_commitment,
        "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
        "trusted_root_sha256": aws_adapter.TRUSTED_ROOT_SHA256,
        "signer_identity": aws_adapter.CAMPAIGN_IDENTITY,
        "artifact_id": 22,
        "artifact_digest": "sha256:" + d("archive"),
        "artifact_name": f"stage2-production-continuation-{'4' * 40}-101-1",
        "approval_commitment": authoritative.approval_commitment,
        "authentication_receipt_sha256": authoritative.consumption.authentication_receipt_sha256,
        "batch_commitment": authoritative.batch_commitment,
        "implementation_revision": authoritative.implementation_revision,
        "control_revision": authoritative.control_revision,
        "qualification_revision": authoritative.qualification_revision,
        "journal_sequence": authoritative.journal_sequence,
        "journal_tip_sha256": authoritative.journal_tip_sha256,
        "cycle3_zero_commitment": authoritative.inventories[-1].zero_commitment,
    }
    expected_admission = production.ContinuationAdmission(
        **admission_fields,
        admission_commitment=production._commit(
            b"cogs.stage2-production-handoff-authentication/v1", admission_fields
        ),
    )
    (issuance / aws_adapter.CONTINUATION_ADMISSION_NAME).write_bytes(
        expected_admission.canonical_bytes()
    )
    verified = []
    try:
        stager["stage_continuation"].__globals__["DESTINATION"] = custody
        stager["stage_continuation"].__globals__["ISSUANCE_ROOT"] = issuance
        aws_adapter.ROOT = custody
        aws_adapter.CONSUMED = custody / "consumed"
        aws_adapter.JOURNAL = custody / "journal"
        aws_adapter.CONTINUATION = custody / aws_adapter.CONTINUATION_NAME
        aws_adapter.CONTINUATION_BUNDLE = custody / aws_adapter.CONTINUATION_BUNDLE_NAME
        aws_adapter.CONTINUATION_ADMISSION = custody / aws_adapter.CONTINUATION_ADMISSION_NAME
        aws_adapter._approval = lambda: (
            h.approval, authoritative.consumption.authentication_receipt_sha256)
        def verify_staged(payload, bundle, identity):
            verified.extend((Path(payload), Path(bundle)))
            assert Path(payload).parent != source and Path(bundle).parent != source
            assert Path(payload).read_bytes() == continuation_raw
            assert Path(bundle).read_bytes() == bundle_raw
            (source / aws_adapter.CONTINUATION_NAME).unlink()
            (source / aws_adapter.CONTINUATION_NAME).write_bytes(b"hostile swap\n")
            (source / aws_adapter.CONTINUATION_NAME).chmod(0o400)
        aws_adapter._verify_blob = verify_staged
        os.geteuid = lambda: 0; os.getegid = lambda: 0
        os.chown = lambda *_args, **_kwargs: None
        os.fchown = lambda *_args, **_kwargs: None
        prior_environment = dict(os.environ)
        os.environ.update({"SUDO_UID": str(caller_uid), "SUDO_GID": str(caller_gid)})
        arguments = (
            source, "4" * 40, "101", "20", "21", "22",
            "sha256:" + d("archive"),
            f"stage2-production-continuation-{'4' * 40}-101-1",
            "10", "11", "sha256:" + "5" * 64,
            f"stage2-production-approval-{'4' * 40}-10")
        try:
            # A later alternate signed/valid download cannot diverge from the
            # exact continuation, bundle, or generated admission used by OIDC.
            aws_adapter._verify_blob = lambda *_args: None
            for name in (aws_adapter.CONTINUATION_NAME,
                         aws_adapter.CONTINUATION_BUNDLE_NAME,
                         aws_adapter.CONTINUATION_ADMISSION_NAME):
                path = issuance / name; original = path.read_bytes()
                path.write_bytes(original + b"mismatch")
                try: stager["stage_continuation"](*arguments)
                except stager["StagingError"]: pass
                else: raise AssertionError(f"issuance/execution mismatch accepted: {name}")
                assert not aws_adapter.CONTINUATION.exists()
                path.write_bytes(original)
            aws_adapter._verify_blob = verify_staged
            stager["stage_continuation"](*arguments)
        finally:
            os.environ.clear(); os.environ.update(prior_environment)
        assert len(verified) == 2
        assert aws_adapter.CONTINUATION.read_bytes() == continuation_raw
        assert aws_adapter.CONTINUATION_BUNDLE.read_bytes() == bundle_raw
    finally:
        os.geteuid, os.getegid, os.chown, os.fchown = original_os_routes
        for name, value in zip((
                "ROOT", "CONSUMED", "JOURNAL", "CONTINUATION",
                "CONTINUATION_BUNDLE", "CONTINUATION_ADMISSION", "_approval",
                "_verify_blob"), original_adapter_routes, strict=True):
            setattr(aws_adapter, name, value)

# The closed evidence package is captured through six already-open descriptors;
# a runner pathname replacement at the last-open boundary is rejected, while an
# unchanged source yields root-owned immutable bytes.
with tempfile.TemporaryDirectory() as directory:
    base = Path(directory); source = base / "runner-package"; source.mkdir(mode=0o700)
    expected = {}
    for index, name in enumerate(stager["EVIDENCE_MEMBERS"]):
        raw = f"member-{index}\n".encode(); expected[name] = raw
        path = source / name; path.write_bytes(raw); path.chmod(0o400)
    original_geteuid, original_chown, original_open = os.geteuid, os.chown, os.open
    original_lstat = Path.lstat
    def root_owned_lstat(path):
        info = original_lstat(path)
        if path.name in {"public-hostile", "public"}:
            values = list(info); values[4:6] = (0, 0); return os.stat_result(values)
        return info
    try:
        stager["snapshot_evidence_package"].__globals__["EVIDENCE_SOURCE"] = source
        stager["snapshot_evidence_package"].__globals__["EVIDENCE_SNAPSHOT_ROOT"] = base / "public-hostile"
        os.geteuid = lambda: 0; os.chown = lambda *_args, **_kwargs: None
        Path.lstat = root_owned_lstat
        opens = [0]
        first_name = next(iter(stager["EVIDENCE_MEMBERS"]))
        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if dir_fd is not None and path in stager["EVIDENCE_MEMBERS"]:
                opens[0] += 1
                if opens[0] == len(stager["EVIDENCE_MEMBERS"]):
                    first = source / first_name
                    first.rename(source / "displaced")
                    first.write_bytes(b"hostile replacement\n"); first.chmod(0o400)
            return descriptor
        os.open = swapping_open
        try: stager["snapshot_evidence_package"](source, "first")
        except stager["StagingError"]: pass
        else: raise AssertionError("evidence snapshot accepted a pathname swap")
        os.open = original_open
        (source / first_name).unlink(); (source / "displaced").rename(source / first_name)
        shutil.rmtree(base / "public-hostile")
        stager["snapshot_evidence_package"].__globals__["EVIDENCE_SNAPSHOT_ROOT"] = base / "public"
        snapshot = stager["snapshot_evidence_package"](source, "first")
        assert snapshot.stat().st_mode & 0o777 == 0o555
        assert {path.name: path.read_bytes() for path in snapshot.iterdir()} == expected
        assert all(path.stat().st_mode & 0o777 == 0o444 for path in snapshot.iterdir())
    finally:
        os.open = original_open; os.geteuid = original_geteuid; os.chown = original_chown
        Path.lstat = original_lstat

for field, hostile in (("ordinal", True), ("ordinal", 1.0),
                       ("observed_started_unix_ns", 0),
                       ("observed_ended_unix_ns", 2.5),
                       ("invocation_count", True), ("invocation_count", 1.0)):
    try: replace(candidate.effects[0][0], **{field: hostile})
    except production.ProductionReceiptError: pass
    else: raise AssertionError(f"effect accepted noncanonical scalar {field}={hostile!r}")

# Test-only controller candidates can exercise projection/validation, but the
# publication issuer categorically rejects them as AWS evidence authority.
import completion_campaign_evidence_issuer as issuer
with tempfile.TemporaryDirectory() as directory:
    os.chmod(directory, 0o700)
    parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        custody = issuer.open_publication_custody(parent_fd)
        forged = replace(candidate)
        try: issuer.issue_completion_evidence(forged, custody)
        except issuer.EvidenceIssuanceError: pass
        else: raise AssertionError("reconstructed candidate minted evidence")
        custody = issuer.open_publication_custody(parent_fd)
        try: issuer.issue_completion_evidence(candidate, custody)
        except issuer.EvidenceIssuanceError: pass
        else: raise AssertionError("test-only candidate acquired AWS publication authority")
        evidence_raw, report_raw = issuer._project_test_candidate(candidate)
        evidence = json.loads(evidence_raw)
        assert evidence_raw.endswith(b"\n") and evidence["result"] == "pass"
        assert evidence["version"] == "cogs.aws-stage2-completion-evidence/v4"
        assert evidence["custody"]["handoff"]["phase_boundary_ordinal"] == 3
        assert evidence["bindings"]["runtime_manifest_sha256"] == candidate.approval.runtime_manifest_sha256
        assert "runtime_commitment" not in evidence["bindings"]
        assert evidence["deadlines"]["actual_campaign_duration_ns"] == candidate.actual_duration_ns
        assert len(evidence["cycles"]) == 7 and len(evidence["inventories"]) == 8
        assert len(evidence["cycles"][0]["workloads"]) == 21
        assert evidence["cycles"][0]["remote"]["bindings"]["source_bindings"] == source_bindings()
        assert evidence["cycles"][1]["remote"]["bindings"]["parser_source_sha256"] == production.REMOTE_PARSERS["readiness"]
        qemu_evidence = evidence["cycles"][1]["remote"]["bindings"]["qemu"]
        assert qemu_evidence["pre_ssh_runtime_fact_sha256"] != qemu_evidence["post_ssh_runtime_fact_sha256"]
        assert sum(row["cost"]["cost_micro_usd"] for row in evidence["cycles"]) == 7
        assert not list(Path(directory).iterdir())
        # The committed golden is owned by the stronger formal-byte composition
        # test. This isolated fake-port controller projection remains deliberately
        # distinct and cannot overwrite or authorize that fixture.
    finally: os.close(parent_fd)
try: controller.run_test_campaign()
except production.ProductionCampaignError: pass
else: raise AssertionError("controller replay accepted")

for mutation in ("state", "instance", "instance_drift", "operation", "rootfs", "observer",
                 "remote_source", "remote_parser", "remote_qemu", "qemu_replay",
                 "mapping_replay", "pre_fact_replay", "post_fact_replay",
                 "cross_pre_from_post", "cross_post_from_pre", "cross_key_replay",
                 "instance_resource_replay"):
    h = Harness(mutate=mutation)
    try: production.ProductionCampaignController(h.ports()).run_test_campaign()
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"{mutation} drift accepted")

# Evidence independently reconstructs every typed remote commitment; mutating a
# controller-retained object cannot fall back to trust in the opaque host receipt.
for mutation in ("remote_source", "remote_parser", "remote_qemu", "remote_instance",
                 "remote_mapping", "remote_pre_fact", "remote_post_fact",
                 "remote_cross_pre", "remote_cross_post", "remote_cross_key",
                 "remote_instance_resource"):
    candidate = production.ProductionCampaignController(Harness().ports()).run_test_campaign()
    binding = candidate.remotes[1].bindings
    if mutation == "remote_source":
        object.__setattr__(binding.source, "host_attestation_sha256", d("evidence-hostile-source"))
    elif mutation == "remote_parser":
        object.__setattr__(binding, "parser_source_sha256", d("evidence-hostile-parser"))
    elif mutation == "remote_qemu":
        object.__setattr__(binding.qemu, "qemu_pid", binding.qemu.qemu_pid + 1)
    elif mutation == "remote_instance":
        object.__setattr__(candidate.remotes[1], "instance_commitment", d("foreign-instance"))
    elif mutation == "remote_mapping":
        object.__setattr__(binding.qemu, "live_mapping_sha256",
                           candidate.remotes[0].bindings.qemu.live_mapping_sha256)
    elif mutation == "remote_pre_fact":
        object.__setattr__(binding.qemu, "pre_ssh_runtime_fact_sha256",
                           candidate.remotes[0].bindings.qemu.pre_ssh_runtime_fact_sha256)
    elif mutation == "remote_post_fact":
        object.__setattr__(binding.qemu, "post_ssh_runtime_fact_sha256",
                           candidate.remotes[2].bindings.qemu.post_ssh_runtime_fact_sha256)
    elif mutation == "remote_cross_pre":
        object.__setattr__(binding.qemu, "pre_ssh_runtime_fact_sha256",
                           candidate.remotes[2].bindings.qemu.post_ssh_runtime_fact_sha256)
    elif mutation == "remote_cross_post":
        object.__setattr__(binding.qemu, "post_ssh_runtime_fact_sha256",
                           candidate.remotes[0].bindings.qemu.pre_ssh_runtime_fact_sha256)
    elif mutation == "remote_cross_key":
        object.__setattr__(candidate.remotes[1], "client_key_commitment",
                           candidate.remotes[0].host_key_commitment)
    else:
        running = candidate.effects[1][2]
        resources = dict(running.resource_commitments)
        resources["instance"] = dict(candidate.effects[0][2].resource_commitments)["instance"]
        object.__setattr__(running, "resource_commitments", tuple(sorted(resources.items())))
        fields = dict(running.__dict__); fields.pop("settlement_commitment")
        object.__setattr__(running, "settlement_commitment", production._commit(
            b"cogs.stage2-provider-effect-settlement/v1", fields))
    try: issuer._project_test_candidate(candidate)
    except issuer.EvidenceIssuanceError: pass
    else: raise AssertionError(f"evidence accepted {mutation} drift")

for failure in (("plan", 1), ("apply", 1), ("running", 1), ("remote", 1),
                ("destroy", 1), ("inventory", 8)):
    h = Harness(fail=failure)
    try: production.ProductionCampaignController(h.ports()).run_test_campaign()
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"{failure} unexpectedly passed")
    destroy_calls = [row for row in h.calls if row[:2] == ("destroy", 1)]
    assert len(destroy_calls) <= 1
    assert h.cleanup_count == 1

h = Harness(fail=("remote", 1), uncertain_cleanup=True)
try: production.ProductionCampaignController(h.ports()).run_test_campaign()
except production.ProductionUncertainty: pass
else: raise AssertionError("cleanup uncertainty was suppressed")

base = approval()
for change in ({"version": "cogs.stage2-completion-production-approval/v4"},
               {"phrase": "wrong"}, {"batch_commitment": d("wrong")},
               {"runtime_manifest_sha256": d("substitute-manifest")},
               {"cleanup_reserve_ns": 1}, {"maximum_cost_micro_usd": 1},
               {"maximum_cycle_duration_ns": base.effect_deadline_ns},
               {"region": "not-a-region"}, {"ami_id": "ami-" + "z" * 17}):
    try: replace(base, **change)
    except production.ProductionCampaignError: pass
    else: raise AssertionError("hostile approval accepted")

# The no-replace transaction preserves occupied bytes, while test projection
# custody itself is one-shot and cannot be retried.
h = Harness(); publication_candidate = production.ProductionCampaignController(h.ports()).run_test_campaign()
with tempfile.TemporaryDirectory() as directory:
    os.chmod(directory, 0o700)
    occupied = Path(directory, issuer.EVIDENCE_NAME)
    occupied.write_bytes(b"occupied\n"); occupied.chmod(0o400)
    parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        custody = issuer.open_publication_custody(parent_fd)
        try: issuer._stage_and_publish(custody, ((issuer.EVIDENCE_NAME, b"new\n"),))
        except issuer.EvidencePublicationUncertain: pass
        else: raise AssertionError("no-replace publication overwrote an artifact")
        assert occupied.read_bytes() == b"occupied\n"
        issuer._project_test_candidate(publication_candidate)
        try: issuer._project_test_candidate(publication_candidate)
        except issuer.EvidenceIssuanceError: pass
        else: raise AssertionError("consumed test projection was retried")
    finally: os.close(parent_fd)

# Two controller instances cannot reuse one durable approval consumption.
h = Harness(); production.ProductionCampaignController(h.ports()).run_test_campaign()
try: production.ProductionCampaignController(h.ports()).run_test_campaign()
except production.ProductionApprovalError: pass
else: raise AssertionError("durably consumed approval was reused")

# TERM at Popen return is pending until the child is cgroup-owned.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    command = root / "command"
    command.write_text("#!/bin/sh\nexit 0\n")
    command.chmod(0o700)
    events = []

    class FakeScope:
        def __init__(self, batch):
            assert batch == base.batch_commitment
            events.append("marker-published")

        def child_setup(self, _mask):
            return lambda: events.append("entered")

        def kill(self):
            events.append("killed")

        def populated(self):
            return False

        def wait_empty(self):
            events.append("empty")

        def remove(self):
            events.append("removed")

    class BoundaryPopen:
        def __init__(self, _argv, **kwargs):
            self.returncode = None
            events.append("popen")
            kwargs["preexec_fn"]()
            os.kill(os.getpid(), signal.SIGTERM)

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            assert timeout == 10
            self.returncode = -signal.SIGKILL
            events.append("reaped")
            return b"", b""

        def wait(self, timeout):
            self.returncode = -signal.SIGKILL

    owner = object.__new__(aws_adapter.AwsCampaignCustodian)
    owner.approval = base
    owner.executor = BoundaryPopen
    owner.scope_factory = FakeScope
    old_source, old_effect = aws_adapter.SOURCE, aws_adapter.EFFECT_COMMAND
    aws_adapter.SOURCE, aws_adapter.EFFECT_COMMAND = root, command
    try:
        try:
            owner._run(command, (), 1)
        except aws_adapter.AwsAdapterError:
            pass
        else:
            raise AssertionError("TERM-at-Popen boundary accepted")
        assert events == [
            "marker-published",
            "popen",
            "entered",
            "killed",
            "killed",
            "reaped",
            "empty",
            "removed",
        ]
    finally:
        aws_adapter.SOURCE, aws_adapter.EFFECT_COMMAND = old_source, old_effect

# Recovery grants cgroup.kill only to an approval-bound marker and exact inode.
original_scope_routes = tuple(
    getattr(aws_adapter, name)
    for name in ("ROOT", "COMMAND_CGROUP", "_CommandScope", "_read_fixed")
)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    scope_path = root / "scope"
    marker = root / aws_adapter.COMMAND_SCOPE_NAME
    events, populated = [], [False]
    aws_adapter.ROOT, aws_adapter.COMMAND_CGROUP, aws_adapter._read_fixed = (
        root,
        scope_path,
        lambda path, *_args: path.read_bytes(),
    )

    class AdoptedScope:
        def __init__(self, batch, create=False, marker=False):
            assert batch == base.batch_commitment and not create and not marker
            info = scope_path.lstat()
            self.identity = info.st_dev, info.st_ino

        def populated(self):
            return populated[0]

        def kill(self):
            events.append("kill")

        def wait_empty(self):
            events.append("empty")

        def remove(self):
            events.append("remove")
            scope_path.rmdir()

    aws_adapter._CommandScope = AdoptedScope
    def marked(info, **changes):
        value = {
            "version": "cogs.stage2-provider-command-cgroup/v1",
            "batch_commitment": base.batch_commitment,
            "cgroup": str(scope_path),
            "cgroup_st_dev": info.st_dev,
            "cgroup_st_ino": info.st_ino,
            "supervisor_pid": 123,
        }
        value.update(changes)
        return aws_adapter._canonical(value)
    try:
        scope_path.mkdir()
        populated[0] = True
        try:
            aws_adapter._drain_stale_command_scope(base)
        except aws_adapter.AwsAdapterError:
            pass
        else:
            raise AssertionError("populated unmarked scope accepted")
        assert not events and scope_path.exists()
        populated[0] = False
        info = scope_path.lstat()
        for changes in (
            {"batch_commitment": d("wrong")},
            {"version": "cogs.stage2-provider-command-cgroup/v2"},
            {"cgroup": str(root / "other-scope")},
            {"cgroup_st_dev": info.st_dev + 1},
            {"cgroup_st_ino": info.st_ino + 1},
            {"supervisor_pid": 0},
            {"supervisor_pid": "123"},
        ):
            marker.write_bytes(marked(info, **changes))
            try:
                aws_adapter._drain_stale_command_scope(base)
            except aws_adapter.AwsAdapterError:
                pass
            else:
                raise AssertionError("foreign marked scope accepted")
            assert not events and scope_path.exists()
            marker.unlink()
        marker.write_bytes(marked(info))
        populated[0] = True
        aws_adapter._drain_stale_command_scope(base)
        assert events == ["kill", "empty", "remove"] and not marker.exists()
        scope_path.mkdir()
        events.clear()
        populated[0] = False
        aws_adapter._drain_stale_command_scope(base)
        assert events == ["remove"]
        marker.write_bytes(marked(info))
        events.clear()
        aws_adapter._drain_stale_command_scope(base)
        assert not events and not marker.exists()
    finally:
        for name, value in zip(
            ("ROOT", "COMMAND_CGROUP", "_CommandScope", "_read_fixed"),
            original_scope_routes,
            strict=True,
        ):
            setattr(aws_adapter, name, value)

# Protected Linux CI invokes the same real timeout/provider/detached-child helper.
if sys.platform == "linux" and os.geteuid() == 0 and os.access("/sys/fs/cgroup", os.W_OK):
    aws_adapter.protected_command_scope_self_test()

if os.environ.get("COGS_TEST_EMIT_APPROVAL") == "1":
    sys.stdout.buffer.write(production._canonical(approval().__dict__) + b"\n")
else:
    print("stage2 provider-free production campaign controller checks passed")

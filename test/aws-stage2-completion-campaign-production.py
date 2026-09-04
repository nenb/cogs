#!/usr/bin/env python3
"""Provider-free hostile matrix for the closed production controller."""

from dataclasses import replace
import hashlib
from pathlib import Path
import json
import os
import stat
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production


def d(value): return hashlib.sha256(value.encode()).hexdigest()


def source_bindings():
    return {
        "source_head": "1" * 40, "source_manifest_sha256": d("source"),
        "host_attestation_sha256": d("host-attestation"),
        "runtime_attestation_sha256": d("runtime"), "rootfs_sha256": d("rootfs-content"),
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
        version="cogs.stage2-completion-production-approval/v4",
        phrase=production.APPROVAL_PHRASE,
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
        runtime_commitment=d("runtime"), fixture_commitment=d("fixture"),
        provider_binary_sha256=d("provider"), aws_cli_sha256=d("aws"), account_commitment=d("account"), partition="aws", region="us-east-1",
        ami_id="ami-" + "a" * 17, ami_owner_id="099720109477",
        ami_architecture="x86_64", ami_virtualization_type="hvm",
        ami_root_device_type="ebs", ami_state="available",
        plan_sha256s=tuple(d(f"plan-{index}") for index in range(1, 8)),
        not_before_unix_ns=1, effect_deadline_ns=90 * 60 * 10**9,
        cleanup_reserve_ns=10 * 60 * 10**9,
        expires_unix_ns=101 * 60 * 10**9,
        maximum_cycle_duration_ns=10 * 60 * 10**9,
        maximum_cost_micro_usd=499_999,
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
    def __init__(self, mutate=None, fail=None, uncertain_cleanup=False):
        self.approval = approval(); self.time = 1_000; self.consumed = False
        self.active = False; self.mutate = mutate; self.fail = fail
        self.uncertain_cleanup = uncertain_cleanup; self.calls = []
        self.journal_rows = []; self.inventory_count = 0; self.cleanup_count = 0

    def now(self): return self.time
    def tick(self): self.time += 10; return self.time

    def consume(self, value, commitment, observed):
        if self.consumed or value is not self.approval: raise production.ProductionApprovalError()
        self.consumed = True
        return production.ApprovalConsumptionReceipt(
            commitment, d("auth"), d("consumed"), observed, True)

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
        state = d(f"state-{state_ordinal}"); lineage = d(f"lineage-{state_ordinal}")
        state_bytes = ("0" * 64 if kind == "plan" else
                       d(f"state-bytes-{grant.ordinal}") if kind in {"apply", "running"} else
                       d(f"destroyed-state-bytes-{grant.ordinal}"))
        identity = grant.plan_sha256 if kind == "plan" else d(f"{kind}-{grant.ordinal}")
        resources = (tuple(sorted((
            ("instance", d(f"instance-resource-{grant.ordinal}")),
            ("root_volume", d(f"root-volume-{grant.ordinal}")),
            ("launch_template_generation", d(f"launch-template-{grant.ordinal}")),
        ))) if kind == "running" else
            (("pre_destroy_receipt", d(f"pre-destroy-{grant.ordinal}")),)
            if kind == "destroy" else ())
        start = self.tick(); end = self.tick()
        return production.EffectReceipt(
            kind, grant.grant_commitment, grant.batch_commitment, grant.ordinal,
            grant.mode, state, state_bytes, lineage, identity, d(f"intent-{kind}-{grant.ordinal}"),
            d(f"settle-{kind}-{grant.ordinal}"), grant.ami_commitment,
            resources, start, end, 1, True)

    def remote(self, grant, apply, running, effect_deadline):
        if not (type(effect_deadline) is int and effect_deadline > self.time):
            raise RuntimeError("remote deadline")
        self.calls.append(("remote", grant.ordinal, grant.mode))
        if self.fail == ("remote", grant.ordinal):
            self.active = True; raise production.ProductionUncertainty()
        rootfs = d("other-rootfs") if self.mutate == "rootfs" and grant.ordinal == 2 else grant.rootfs_descriptor_sha256
        instance_ordinal = 1 if self.mutate == "instance" and grant.ordinal == 2 else grant.ordinal
        operation_ordinal = 1 if self.mutate == "operation" and grant.ordinal == 2 else grant.ordinal
        workloads = tuple(
            production.WorkloadMeasurement(category, sample, 100 + sample,
                                            d(f"workload-{category}-{sample}"))
            for category in ("git", "build", "install") for sample in range(1, 8)
        ) if grant.mode == "full" else ()
        operation = d(f"operation-{operation_ordinal}")
        runtime_ordinal = (1 if self.mutate == "qemu_replay" and grant.ordinal == 2
                           else grant.ordinal)
        qemu_values = dict(
            operation_token=operation, live_mapping_sha256=d(f"mapping-{grant.ordinal}"),
            qemu_argv_sha256=d(f"qemu-argv-{runtime_ordinal}"), qemu_pid=100 + runtime_ordinal,
            qemu_starttime=200 + runtime_ordinal, qemu_executable_device=8,
            qemu_executable_inode=300 + runtime_ordinal, observer_qmp_device=9,
            observer_qmp_inode=400 + runtime_ordinal, kvm_device=10,
            kvm_inode=500 + runtime_ordinal, kvm_rdev=11, kvm_api=12,
            qmp_present=True, qmp_enabled=True)
        identity = production._runtime_identity(SimpleNamespace(**qemu_values))
        qemu = production.RemoteQemuBindings(
            **qemu_values, runtime_identity_sha256=identity,
            pre_ssh_runtime_fact_sha256=d(f"pre-ssh-{grant.ordinal}"),
            post_ssh_runtime_fact_sha256=(d(f"post-ssh-{grant.ordinal}")
                                          if grant.mode == "readiness" else None))
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
            d(f"instance-{instance_ordinal}"), d(f"host-{grant.ordinal}"),
            operation, d(f"boot-{grant.ordinal}"),
            d(f"client-key-{grant.ordinal}"), d(f"host-key-{grant.ordinal}"), rootfs,
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
                  "usage_commitment": d(f"usage-{grant.ordinal}"),
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

    def ports(self):
        return production._issue_test_ports(
            self.approval, self.now, self.consume, self.effect, self.remote,
            self.inventory, self.cost, self.recover, self.journal)


h = Harness(); controller = production.ProductionCampaignController(h.ports())
candidate = controller.run()
assert candidate.actual_duration_ns == candidate.final_zero_unix_ns - candidate.first_apply_unix_ns
assert candidate.total_cost_micro_usd == 7 and len(candidate.cycle_commitments) == 7
assert len(candidate.launch_ready_samples_ns) == len(candidate.ssh_ready_samples_ns) == 7
assert len(candidate.workload_measurements) == 21 and len(candidate.inventories) == 8
assert h.inventory_count == 8 and not h.active and h.cleanup_count == 0
assert [row[2] for row in h.calls if row[0] == "remote"] == list(production.CYCLE_MODES)

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
        assert evidence["deadlines"]["actual_campaign_duration_ns"] == candidate.actual_duration_ns
        assert len(evidence["cycles"]) == 7 and len(evidence["inventories"]) == 8
        assert len(evidence["cycles"][0]["workloads"]) == 21
        assert evidence["cycles"][0]["remote"]["bindings"]["source_bindings"] == source_bindings()
        assert evidence["cycles"][1]["remote"]["bindings"]["parser_source_sha256"] == production.REMOTE_PARSERS["readiness"]
        qemu_evidence = evidence["cycles"][1]["remote"]["bindings"]["qemu"]
        assert qemu_evidence["pre_ssh_runtime_fact_sha256"] != qemu_evidence["post_ssh_runtime_fact_sha256"]
        assert sum(row["cost"]["cost_micro_usd"] for row in evidence["cycles"]) == 7
        assert not list(Path(directory).iterdir())
    finally: os.close(parent_fd)
try: controller.run()
except production.ProductionCampaignError: pass
else: raise AssertionError("controller replay accepted")

for mutation in ("state", "instance", "operation", "rootfs", "observer",
                 "remote_source", "remote_parser", "remote_qemu", "qemu_replay"):
    h = Harness(mutate=mutation)
    try: production.ProductionCampaignController(h.ports()).run()
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"{mutation} drift accepted")

# Evidence independently reconstructs every typed remote commitment; mutating a
# controller-retained object cannot fall back to trust in the opaque host receipt.
for mutation in ("remote_source", "remote_parser", "remote_qemu"):
    candidate = production.ProductionCampaignController(Harness().ports()).run()
    binding = candidate.remotes[1].bindings
    if mutation == "remote_source":
        object.__setattr__(binding.source, "host_attestation_sha256", d("evidence-hostile-source"))
    elif mutation == "remote_parser":
        object.__setattr__(binding, "parser_source_sha256", d("evidence-hostile-parser"))
    else:
        object.__setattr__(binding.qemu, "qemu_pid", binding.qemu.qemu_pid + 1)
    try: issuer._project_test_candidate(candidate)
    except issuer.EvidenceIssuanceError: pass
    else: raise AssertionError(f"evidence accepted {mutation} drift")

for failure in (("plan", 1), ("apply", 1), ("running", 1), ("remote", 1),
                ("destroy", 1), ("inventory", 8)):
    h = Harness(fail=failure)
    try: production.ProductionCampaignController(h.ports()).run()
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"{failure} unexpectedly passed")
    destroy_calls = [row for row in h.calls if row[:2] == ("destroy", 1)]
    assert len(destroy_calls) <= 1
    assert h.cleanup_count == 1

h = Harness(fail=("remote", 1), uncertain_cleanup=True)
try: production.ProductionCampaignController(h.ports()).run()
except production.ProductionUncertainty: pass
else: raise AssertionError("cleanup uncertainty was suppressed")

base = approval()
for change in ({"phrase": "wrong"}, {"batch_commitment": d("wrong")},
               {"cleanup_reserve_ns": 1}, {"maximum_cost_micro_usd": 1},
               {"maximum_cycle_duration_ns": base.effect_deadline_ns},
               {"region": "not-a-region"}, {"ami_id": "ami-" + "z" * 17}):
    try: replace(base, **change)
    except production.ProductionCampaignError: pass
    else: raise AssertionError("hostile approval accepted")

# The no-replace transaction preserves occupied bytes, while test projection
# custody itself is one-shot and cannot be retried.
h = Harness(); publication_candidate = production.ProductionCampaignController(h.ports()).run()
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
h = Harness(); production.ProductionCampaignController(h.ports()).run()
try: production.ProductionCampaignController(h.ports()).run()
except production.ProductionApprovalError: pass
else: raise AssertionError("durably consumed approval was reused")

if os.environ.get("COGS_TEST_EMIT_EVIDENCE") == "1":
    sys.stdout.buffer.write(evidence_raw)
elif os.environ.get("COGS_TEST_EMIT_REPORT") == "1":
    sys.stdout.buffer.write(report_raw)
else:
    print("stage2 provider-free production campaign controller checks passed")

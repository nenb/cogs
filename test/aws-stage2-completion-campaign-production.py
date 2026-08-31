#!/usr/bin/env python3
"""Provider-free hostile matrix for the closed production controller."""

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production


def d(value): return hashlib.sha256(value.encode()).hexdigest()


def approval():
    values = dict(
        version="cogs.stage2-completion-production-approval/v2",
        phrase=production.APPROVAL_PHRASE,
        implementation_revision="1" * 40,
        control_revision="2" * 40,
        source_manifest_sha256=d("source"), static_control_sha256=d("control"),
        pre_aws_package_sha256=d("preaws"), rootfs_descriptor_sha256=d("rootfs"),
        runtime_commitment=d("runtime"), fixture_commitment=d("fixture"),
        account_commitment=d("account"), partition="aws", region="us-east-1",
        ami_id="ami-" + "a" * 17, ami_owner_id="099720109477",
        ami_architecture="x86_64", ami_virtualization_type="hvm",
        ami_root_device_type="ebs", ami_state="available",
        plan_sha256s=tuple(d(f"plan-{index}") for index in range(1, 8)),
        not_before_unix_ns=1, effect_deadline_ns=90 * 60 * 10**9,
        cleanup_reserve_ns=10 * 60 * 10**9,
        expires_unix_ns=101 * 60 * 10**9,
        maximum_cost_micro_usd=499_999,
        issuer_commitment=d("issuer"), authentication_receipt_sha256=d("auth"),
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
        return production.ApprovalConsumptionReceipt(commitment, d("consumed"), observed, True)

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
        identity = grant.plan_sha256 if kind == "plan" else d(f"{kind}-{grant.ordinal}")
        start = self.tick(); end = self.tick()
        return production.EffectReceipt(
            kind, grant.grant_commitment, grant.batch_commitment, grant.ordinal,
            grant.mode, state, lineage, identity, d(f"intent-{kind}-{grant.ordinal}"),
            d(f"settle-{kind}-{grant.ordinal}"), grant.ami_commitment,
            start, end, 1, True)

    def remote(self, grant, apply, running):
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
        return production.RemoteReceipt(
            grant.grant_commitment, grant.batch_commitment, grant.ordinal, grant.mode,
            apply.state_commitment, apply.state_lineage_commitment,
            d(f"instance-{instance_ordinal}"), d(f"host-{grant.ordinal}"),
            d(f"operation-{operation_ordinal}"), d(f"boot-{grant.ordinal}"), rootfs,
            grant.ami_commitment, apply.observed_started_unix_ns,
            running.observed_ended_unix_ns, 100, 200, workloads, True)

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
        fields = {"grant_commitment": grant.grant_commitment,
                  "cycle_ordinal": grant.ordinal,
                  "rate_source_commitment": d("rate"),
                  "usage_commitment": d(f"usage-{grant.ordinal}"),
                  "cost_micro_usd": 100}
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
assert candidate.total_cost_micro_usd == 700 and len(candidate.cycle_commitments) == 7
assert len(candidate.launch_ready_samples_ns) == len(candidate.ssh_ready_samples_ns) == 7
assert len(candidate.workload_measurements) == 21 and len(candidate.inventories) == 8
assert h.inventory_count == 8 and not h.active and h.cleanup_count == 0
assert [row[2] for row in h.calls if row[0] == "remote"] == list(production.CYCLE_MODES)
try: controller.run()
except production.ProductionCampaignError: pass
else: raise AssertionError("controller replay accepted")

for mutation in ("state", "instance", "operation", "rootfs", "observer"):
    h = Harness(mutate=mutation)
    try: production.ProductionCampaignController(h.ports()).run()
    except production.ProductionCampaignError: pass
    else: raise AssertionError(f"{mutation} drift accepted")

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
               {"cleanup_reserve_ns": 1}):
    try: replace(base, **change)
    except production.ProductionCampaignError: pass
    else: raise AssertionError("hostile approval accepted")

# Two controller instances cannot reuse one durable approval consumption.
h = Harness(); production.ProductionCampaignController(h.ports()).run()
try: production.ProductionCampaignController(h.ports()).run()
except production.ProductionApprovalError: pass
else: raise AssertionError("durably consumed approval was reused")

print("stage2 provider-free production campaign controller checks passed")

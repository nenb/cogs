"""Closed production campaign contracts and the sole seven-cycle state machine.

This module is provider-neutral, but not synthetic: concrete ports are issued only
by the dormant AWS adapter.  Tests receive a separately labelled test issuer.
No callback may relabel a receipt; every effect carries the complete one-shot
grant and durable intent/settlement identity.
"""

from dataclasses import asdict, dataclass
import hashlib
import json

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


def _approval_fields(value):
    result = asdict(value) if type(value) is ProductionApproval else dict(value)
    result.pop("batch_commitment", None)
    return result


def approval_batch_commitment(value):
    return _commit(b"cogs.stage2-production-approved-batch/v2", _approval_fields(value))


@dataclass(frozen=True)
class ProductionApproval:
    version: str
    phrase: str
    batch_commitment: str
    implementation_revision: str
    control_revision: str
    source_manifest_sha256: str
    static_control_sha256: str
    pre_aws_package_sha256: str
    rootfs_descriptor_sha256: str
    runtime_commitment: str
    fixture_commitment: str
    account_commitment: str
    region: str
    ami_id: str
    ami_commitment: str
    plan_sha256s: tuple[str, ...]
    not_before_unix_ns: int
    effect_deadline_ns: int
    cleanup_reserve_ns: int
    expires_unix_ns: int
    maximum_cost_micro_usd: int
    issuer_commitment: str
    authentication_receipt_sha256: str
    one_attempt: bool

    def __post_init__(self):
        _require(self.version == "cogs.stage2-completion-production-approval/v2"
                 and self.phrase == APPROVAL_PHRASE and self.one_attempt is True,
                 ProductionApprovalError)
        _digest(self.batch_commitment); _sha1(self.implementation_revision); _sha1(self.control_revision)
        for item in (
            self.source_manifest_sha256, self.static_control_sha256,
            self.pre_aws_package_sha256, self.rootfs_descriptor_sha256,
            self.runtime_commitment, self.fixture_commitment, self.account_commitment,
            self.ami_commitment, self.issuer_commitment,
            self.authentication_receipt_sha256,
        ): _digest(item)
        _require(type(self.region) is str and 3 <= len(self.region) <= 32
                 and type(self.ami_id) is str and self.ami_id.startswith("ami-")
                 and len(self.ami_id) == 21, ProductionApprovalError)
        _require(type(self.plan_sha256s) is tuple and len(self.plan_sha256s) == 7
                 and len(set(self.plan_sha256s)) == 7, ProductionApprovalError)
        for item in self.plan_sha256s: _digest(item)
        _require(type(self.not_before_unix_ns) is int
                 and type(self.effect_deadline_ns) is int
                 and type(self.cleanup_reserve_ns) is int
                 and type(self.expires_unix_ns) is int
                 and 0 < self.effect_deadline_ns <= 90 * 60 * 1_000_000_000
                 and 5 * 60 * 1_000_000_000 <= self.cleanup_reserve_ns <= 30 * 60 * 1_000_000_000
                 and self.not_before_unix_ns + self.effect_deadline_ns + self.cleanup_reserve_ns
                     <= self.expires_unix_ns
                 and 0 < self.maximum_cost_micro_usd < 500_000,
                 ProductionApprovalError)
        _require(self.batch_commitment == approval_batch_commitment(self),
                 ProductionApprovalError)


@dataclass(frozen=True)
class ApprovalConsumptionReceipt:
    approval_commitment: str
    durable_record_commitment: str
    consumed_unix_ns: int
    first_created: bool

    def __post_init__(self):
        _digest(self.approval_commitment); _digest(self.durable_record_commitment)
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
    state_lineage_commitment: str
    identity_commitment: str
    intent_commitment: str
    settlement_commitment: str
    ami_commitment: str
    observed_started_unix_ns: int
    observed_ended_unix_ns: int
    invocation_count: int
    certain: bool

    def __post_init__(self):
        for item in (self.grant_commitment, self.batch_commitment,
                     self.state_commitment, self.state_lineage_commitment,
                     self.identity_commitment, self.intent_commitment,
                     self.settlement_commitment, self.ami_commitment): _digest(item)
        _require(self.kind in EFFECT_KINDS and 1 <= self.ordinal <= 7
                 and self.mode == CYCLE_MODES[self.ordinal - 1]
                 and type(self.observed_started_unix_ns) is int
                 and self.observed_started_unix_ns < self.observed_ended_unix_ns
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
    rootfs_descriptor_sha256: str
    ami_commitment: str
    provider_launch_started_unix_ns: int
    provider_running_observed_unix_ns: int
    kata_launch_started_boottime_ns: int
    ssh_ready_observed_boottime_ns: int
    workloads: tuple[WorkloadMeasurement, ...]
    certain: bool

    def __post_init__(self):
        for item in (
            self.grant_commitment, self.batch_commitment, self.state_commitment,
            self.state_lineage_commitment, self.instance_commitment,
            self.host_receipt_commitment, self.operation_commitment,
            self.host_boot_commitment, self.rootfs_descriptor_sha256,
            self.ami_commitment,
        ): _digest(item)
        _require(1 <= self.ordinal <= 7 and self.mode == CYCLE_MODES[self.ordinal - 1]
                 and self.provider_launch_started_unix_ns < self.provider_running_observed_unix_ns
                 and 0 < self.kata_launch_started_boottime_ns < self.ssh_ready_observed_boottime_ns
                 and type(self.workloads) is tuple
                 and len(self.workloads) == (21 if self.mode == "full" else 0)
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
    ordinal: int
    request_token_commitment: str | None
    next_token_commitment: str | None
    resources: tuple[InventoryResource, ...]
    page_commitment: str

    def __post_init__(self):
        _require(self.category in INVENTORY_CATEGORIES and 1 <= self.ordinal <= 32
                 and type(self.resources) is tuple, ProductionReceiptError)
        for item in (self.request_token_commitment, self.next_token_commitment):
            if item is not None: _digest(item)
        _digest(self.page_commitment)
        _require(all(type(item) is InventoryResource and item.category == self.category
                     for item in self.resources), ProductionReceiptError)
        value = {
            "category": self.category, "ordinal": self.ordinal,
            "request_token_commitment": self.request_token_commitment,
            "next_token_commitment": self.next_token_commitment,
            "resources": [asdict(item) for item in self.resources],
        }
        _require(self.page_commitment == _commit(b"cogs.stage2-inventory-page/v1", value),
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
            b"cogs.stage2-production-approval/v2", asdict(self.approval))
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
        approval_commitment = _commit(b"cogs.stage2-production-approval/v2", asdict(approval))
        consumption = self.ports.consume(approval, approval_commitment, consumed_at)
        _require(type(consumption) is ApprovalConsumptionReceipt
                 and consumption.approval_commitment == approval_commitment,
                 ProductionApprovalError)
        self.ports.journal("batch", "consumed", None, None,
                           consumption.durable_record_commitment)
        grants = []; effects = []; remotes = []; inventories = []; costs = []; cycles = []
        states = []; lineages = []; instances = []; operations = []; boots = []
        previous_zero_end = None
        first_apply_start = None
        active_grant = None
        active_state = None
        last_certain = None
        try:
            for ordinal, mode in enumerate(CYCLE_MODES, 1):
                self._now(approval)
                grant = _grant(approval, ordinal); active_grant = grant
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
                         and plan.observed_ended_unix_ns < apply.observed_started_unix_ns,
                         ProductionReceiptError)
                if first_apply_start is None: first_apply_start = apply.observed_started_unix_ns
                effect_deadline = first_apply_start + approval.effect_deadline_ns
                cleanup_deadline = effect_deadline + approval.cleanup_reserve_ns
                _require(apply.observed_ended_unix_ns < effect_deadline
                         and cleanup_deadline <= approval.expires_unix_ns,
                         ProductionApprovalError)
                running = self._effect("running", grant, apply)
                _require(running.state_commitment == apply.state_commitment
                         and running.state_lineage_commitment == apply.state_lineage_commitment
                         and apply.observed_ended_unix_ns < running.observed_started_unix_ns
                         and running.observed_ended_unix_ns < effect_deadline,
                         ProductionReceiptError)
                remote = self.ports.remote(grant, apply, running)
                _require(type(remote) is RemoteReceipt
                         and remote.grant_commitment == grant.grant_commitment
                         and remote.batch_commitment == approval.batch_commitment
                         and remote.ordinal == ordinal and remote.mode == mode
                         and remote.state_commitment == apply.state_commitment
                         and remote.state_lineage_commitment == apply.state_lineage_commitment
                         and remote.provider_launch_started_unix_ns == apply.observed_started_unix_ns
                         and remote.provider_running_observed_unix_ns == running.observed_ended_unix_ns
                         and remote.rootfs_descriptor_sha256 == approval.rootfs_descriptor_sha256
                         and remote.ami_commitment == approval.ami_commitment,
                         ProductionReceiptError)
                destroy = self._effect("destroy", grant, running)
                _require(destroy.state_commitment == apply.state_commitment
                         and destroy.state_lineage_commitment == apply.state_lineage_commitment
                         and running.observed_ended_unix_ns < destroy.observed_started_unix_ns
                         and destroy.observed_ended_unix_ns < effect_deadline,
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
                     and final.observed_ended_unix_ns < approval.expires_unix_ns,
                     ProductionReceiptError)
            inventories.append(final)
            active_grant = active_state = last_certain = None
            _require(all(len(set(values)) == 7 for values in
                         (states, lineages, instances, operations, boots)),
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

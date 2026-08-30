#!/usr/bin/env python3
"""Fake-only completion plan, infrastructure, and inventory receipt checkers.

The interfaces accept only explicitly synthetic canonical fixtures.  They are pure:
there is no command, provider, credential, filesystem, inventory, or network port.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Any, Callable

import completion_campaign_codec as codec
from completion_campaign_contracts import CYCLE_MODES, CycleMode, ZERO_SHA256

SYNTHETIC_AUTHORITY = "cogs.stage2-completion/bounded-synthetic-fixture/v1"
PLAN_RECEIPT_VERSION = "cogs.aws-stage2-completion/cycle-plan-receipt/v1"
INFRASTRUCTURE_RECEIPT_VERSION = "cogs.aws-stage2-completion/cycle-infrastructure-receipt/v1"
INVENTORY_RECEIPT_VERSION = "cogs.aws-stage2-completion/inventory-receipt/v1"
MAX_PAGES_PER_CATEGORY = 8
MAX_INVENTORY_OBJECTS = 96

_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FAKE_ID = re.compile(r"^syn-[a-z][a-z0-9-]{2,95}$", re.ASCII)
_EXPIRY = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", re.ASCII)

RESOURCE_SHAPE = (
    ("aws_vpc.campaign", "aws_vpc"),
    ("aws_internet_gateway.campaign", "aws_internet_gateway"),
    ("aws_subnet.campaign", "aws_subnet"),
    ("aws_route_table.campaign", "aws_route_table"),
    ("aws_route.internet", "aws_route"),
    ("aws_route_table_association.campaign", "aws_route_table_association"),
    ("aws_security_group.host", "aws_security_group"),
    ("aws_iam_role.host", "aws_iam_role"),
    ("aws_iam_role_policy_attachment.ssm", "aws_iam_role_policy_attachment"),
    ("aws_iam_instance_profile.host", "aws_iam_instance_profile"),
    ("aws_launch_template.host", "aws_launch_template"),
    ("aws_instance.host", "aws_instance"),
    ("aws_iam_role.terminator", "aws_iam_role"),
    ("aws_iam_role_policy.terminator", "aws_iam_role_policy"),
    ("aws_scheduler_schedule.terminate", "aws_scheduler_schedule"),
    ("aws_budgets_budget.campaign", "aws_budgets_budget"),
)
RESOURCE_ADDRESSES = tuple(address for address, _ in RESOURCE_SHAPE)

INVENTORY_CATEGORIES = (
    "instance_states",
    "root_volumes",
    "network_interfaces",
    "vpcs",
    "internet_gateway_attachments",
    "subnets",
    "route_tables",
    "routes",
    "route_table_associations",
    "security_group_rules",
    "launch_templates",
    "launch_template_versions",
    "iam_roles",
    "iam_trust_policies",
    "iam_inline_policies",
    "iam_policy_attachments",
    "instance_profiles",
    "instance_profile_memberships",
    "scheduler_schedules",
    "scheduler_groups",
    "scheduler_targets",
    "budgets",
    "budget_notifications",
    "budget_subscribers",
)


class ReceiptContractError(ValueError):
    """A receipt is not a closed, bounded synthetic contract value."""


class InventoryStatus(str, Enum):
    ZERO = "zero"
    NONZERO = "nonzero"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class PlanReceipt:
    canonical: bytes
    batch_commitment: str
    cycle_ordinal: int
    cycle_mode: CycleMode
    fixture_id: str
    common_expiry: str
    semantic_plan_sha256: str
    state_key: str
    state_lineage_commitment: str

    def as_dict(self) -> dict[str, Any]:
        return codec.load_canonical_bytes(self.canonical)

    def sha256(self) -> str:
        return codec.sha256_hex(self.canonical)


@dataclass(frozen=True, slots=True)
class InfrastructureReceipt:
    canonical: bytes
    batch_commitment: str
    cycle_ordinal: int
    cycle_mode: CycleMode
    fixture_id: str
    common_expiry: str
    plan_receipt_sha256: str
    semantic_plan_sha256: str
    state_key: str
    state_lineage_commitment: str
    destroyed_state_sha256: str
    inventory_expectations: tuple[tuple[str, str, str | None, str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return codec.load_canonical_bytes(self.canonical)

    def sha256(self) -> str:
        return codec.sha256_hex(self.canonical)


@dataclass(frozen=True, slots=True)
class InventoryReceipt:
    canonical: bytes
    status: InventoryStatus
    batch_commitment: str
    cycle_ordinal: int
    cycle_mode: CycleMode
    fixture_id: str
    common_expiry: str
    infrastructure_receipt_sha256: str
    state_key: str
    state_lineage_commitment: str
    destroyed_state_sha256: str
    account_commitment: str
    region_scope: str
    operator_commitment: str
    observer_commitment: str
    session_id: str
    run_id: str
    observation_sequence: int
    expected_objects: tuple[tuple[str, str, str | None, str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return codec.load_canonical_bytes(self.canonical)

    def sha256(self) -> str:
        return codec.sha256_hex(self.canonical)


@dataclass(frozen=True, slots=True)
class CycleReceiptSet:
    plan: PlanReceipt
    infrastructure: InfrastructureReceipt
    inventory: InventoryReceipt

    @property
    def zero_proven(self) -> bool:
        return self.inventory.status is InventoryStatus.ZERO


_PLAN_KEYS = {
    "version", "synthetic_fixture", "batch_commitment", "cycle_ordinal", "cycle_mode",
    "source_commitment", "account_commitment", "operator_commitment", "partition_scope",
    "region_scope", "common_expiry", "plan_file_sha256", "semantic_plan_sha256",
    "checker_sha256", "configuration_sha256", "lock_sha256", "variables_sha256",
    "state_lineage", "resource_changes",
}
_INFRASTRUCTURE_KEYS = {
    "version", "synthetic_fixture", "batch_commitment", "cycle_ordinal", "cycle_mode",
    "common_expiry", "plan_receipt_sha256", "semantic_plan_sha256", "state_lineage",
    "apply_invocations", "running_observation", "managed_resources", "attached_graph",
    "destroy_settlement",
}
_INVENTORY_KEYS = {
    "version", "synthetic_fixture", "status", "batch_commitment", "cycle_ordinal",
    "cycle_mode", "common_expiry", "infrastructure_receipt_sha256", "state_lineage",
    "observer", "scope", "pagination", "reconciliation", "uncertainty_reasons",
}
_RELATIONS = {
    "managed", "root-volume", "primary-eni", "gateway-attachment", "security-group-rule",
    "launch-template-version", "role-trust", "inline-policy", "managed-policy-attachment",
    "profile-membership", "schedule-group", "schedule-target", "budget-notification",
    "budget-subscriber",
}
_UNCERTAINTY_REASONS = {
    "category-error", "identity-mismatch", "missing-page", "scope-unsupported",
    "truncated-response", "unexpected-delta", "unknown-disposition",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptContractError(message)


def _object(value: Any, keys: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(keys), f"{label} key set mismatch")
    return value


def _array(value: Any, label: str, *, maximum: int = MAX_INVENTORY_OBJECTS) -> list[Any]:
    _require(type(value) is list and len(value) <= maximum, f"{label} array bound")
    return value


def _text(value: Any, label: str, *, maximum: int = 128) -> str:
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum, f"{label} text bound")
    return value


def _digest(value: Any, label: str, *, nonzero: bool = True) -> str:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None, f"{label} digest")
    _require(not nonzero or value != ZERO_SHA256, f"{label} zero digest")
    return value


def _fake_id(value: Any, label: str) -> str:
    _require(type(value) is str and _FAKE_ID.fullmatch(value) is not None, f"{label} synthetic identity")
    return value


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    _require(type(value) is int and minimum <= value <= maximum, f"{label} integer bound")
    return value


def _closed_fixture(value: Any) -> str:
    fixture = _object(value, {"authority", "fixture_id", "production_authorized"}, "synthetic fixture")
    _require(fixture["authority"] == SYNTHETIC_AUTHORITY, "synthetic fixture authority")
    _require(fixture["production_authorized"] is False, "production authority rejected")
    return _fake_id(fixture["fixture_id"], "fixture")


def _binding(value: dict[str, Any]) -> tuple[str, int, CycleMode]:
    batch = _digest(value["batch_commitment"], "batch commitment")
    ordinal = _integer(value["cycle_ordinal"], "cycle ordinal", 1, 7)
    try:
        mode = CycleMode(value["cycle_mode"])
    except (TypeError, ValueError) as error:
        raise ReceiptContractError("cycle mode") from error
    _require(mode is CYCLE_MODES[ordinal - 1], "fixed cycle mode mismatch")
    return batch, ordinal, mode


def _expiry(value: Any) -> str:
    _require(type(value) is str and _EXPIRY.fullmatch(value) is not None, "common expiry format")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ReceiptContractError("common expiry calendar value") from error
    return value


def _state_before(value: Any) -> tuple[str, str]:
    state = _object(
        value,
        {"state_key", "lineage_commitment", "generation_before", "serial_before", "prior_state_sha256"},
        "plan state lineage",
    )
    key = _fake_id(state["state_key"], "state key")
    lineage = _digest(state["lineage_commitment"], "state lineage")
    _require(state["generation_before"] == 0 and state["serial_before"] == 0, "state is not isolated and fresh")
    _require(state["prior_state_sha256"] == ZERO_SHA256, "plan has prior state")
    return key, lineage


def _semantics(address: str) -> dict[str, Any]:
    common_tags = {
        "owner": "fixture-owner", "purpose": "stage-2-nested-virtualization",
        "source_bound": True, "expiry_bound": True, "batch_bound": True,
        "cycle_bound": True, "managed_by": "fixed-iac",
    }
    values: dict[str, dict[str, Any]] = {
        "aws_vpc.campaign": {"cidr": "fixture-vpc-cidr", "dns_hostnames": True, "dns_support": True},
        "aws_internet_gateway.campaign": {"vpc_ref": "aws_vpc.campaign"},
        "aws_subnet.campaign": {"vpc_ref": "aws_vpc.campaign", "cidr": "fixture-subnet-cidr", "public_ip_on_launch": False},
        "aws_route_table.campaign": {"vpc_ref": "aws_vpc.campaign"},
        "aws_route.internet": {"route_table_ref": "aws_route_table.campaign", "destination": "fixture-default-route", "gateway_ref": "aws_internet_gateway.campaign"},
        "aws_route_table_association.campaign": {"subnet_ref": "aws_subnet.campaign", "route_table_ref": "aws_route_table.campaign"},
        "aws_security_group.host": {
            "vpc_ref": "aws_vpc.campaign", "ingress": [],
            "egress": ["tcp-443-any", "tcp-80-any", "udp-53-resolver", "tcp-53-resolver"],
        },
        "aws_iam_role.host": {"trust_service": "compute-service", "inline_policies": []},
        "aws_iam_role_policy_attachment.ssm": {"role_ref": "aws_iam_role.host", "policy": "managed-instance-core"},
        "aws_iam_instance_profile.host": {"role_ref": "aws_iam_role.host"},
        "aws_launch_template.host": {
            "instance_type": "c8i-flex.large", "vcpu_count": 2, "memory_mib": 4096,
            "nested_virtualization": "enabled", "root_volume_gib": 30, "root_volume_type": "gp3",
            "root_volume_encrypted": True, "root_delete_on_termination": True,
            "public_ip": True, "eni_delete_on_termination": True, "imds_tokens": "required",
            "imds_hop_limit": 1, "instance_profile_ref": "aws_iam_instance_profile.host",
            "subnet_ref": "aws_subnet.campaign", "security_group_ref": "aws_security_group.host",
            "guest_local_termination_minutes": 220,
        },
        "aws_instance.host": {
            "count": 1, "launch_template_ref": "aws_launch_template.host",
            "instance_initiated_shutdown": "terminate", "stop_start_allowed": False,
        },
        "aws_iam_role.terminator": {
            "trust_service": "scheduler-service", "source_account_bound": True,
            "source_schedule_group": "default", "wildcard_source": False,
        },
        "aws_iam_role_policy.terminator": {
            "role_ref": "aws_iam_role.terminator", "action": "terminate-exact-instance",
            "resource_ref": "aws_instance.host", "purpose_tag_bound": True,
            "source_tag_bound": True, "expiry_tag_bound": True,
        },
        "aws_scheduler_schedule.terminate": {
            "one_time": True, "timezone": "UTC", "action_after_completion": "DELETE",
            "direct_target": "terminate-instances", "instance_ref": "aws_instance.host",
            "role_ref": "aws_iam_role.terminator", "maximum_event_age_seconds": 300,
            "maximum_scheduler_attempts": 3,
        },
        "aws_budgets_budget.campaign": {
            "budget_type": "COST", "limit_micro_usd": 20_000_000, "time_unit": "MONTHLY",
            "alert_percentages": [25, 50, 100], "hard_kill": False,
        },
    }
    return {"tags": common_tags, "policy": values[address]}


def _validate_resource_changes(value: Any) -> list[dict[str, Any]]:
    rows = _array(value, "resource changes", maximum=16)
    _require(len(rows) == 16, "exactly sixteen managed resources required")
    for index, ((address, resource_type), row) in enumerate(zip(RESOURCE_SHAPE, rows, strict=True), 1):
        item = _object(row, {"ordinal", "address", "type", "mode", "actions", "values"}, "resource change")
        _require(item["ordinal"] == index and item["address"] == address and item["type"] == resource_type, "resource order or identity")
        _require(item["mode"] == "managed" and item["actions"] == ["create"], "resource is not managed create-only")
        _require(item["values"] == _semantics(address), f"{address} semantic policy")
    return rows


def _snapshot(value: Any) -> tuple[dict[str, Any], bytes]:
    raw = codec.canonical_bytes(value)
    observed = codec.load_canonical_bytes(raw)
    _require(type(observed) is dict, "receipt must be an object")
    return observed, raw


def plan_receipt_from_mapping(value: Any) -> PlanReceipt:
    observed, raw = _snapshot(value)
    _object(observed, _PLAN_KEYS, "plan receipt")
    _require(observed["version"] == PLAN_RECEIPT_VERSION, "plan receipt version")
    fixture_id = _closed_fixture(observed["synthetic_fixture"])
    batch, ordinal, mode = _binding(observed)
    for label in ("source_commitment", "account_commitment", "operator_commitment", "plan_file_sha256", "checker_sha256", "configuration_sha256", "lock_sha256", "variables_sha256"):
        _digest(observed[label], label)
    _require(observed["partition_scope"] == "synthetic-partition", "partition scope")
    _require(observed["region_scope"] == "synthetic-region-1", "region scope")
    expiry = _expiry(observed["common_expiry"])
    state_key, lineage = _state_before(observed["state_lineage"])
    resources = _validate_resource_changes(observed["resource_changes"])
    semantic_digest = _digest(observed["semantic_plan_sha256"], "semantic plan")
    _require(semantic_digest == codec.canonical_sha256(resources), "semantic plan digest mismatch")
    return PlanReceipt(raw, batch, ordinal, mode, fixture_id, expiry, semantic_digest, state_key, lineage)


def _resource_ids(value: Any) -> dict[str, str]:
    rows = _array(value, "managed resources", maximum=16)
    _require(len(rows) == 16, "managed resource count")
    result: dict[str, str] = {}
    for (address, resource_type), row in zip(RESOURCE_SHAPE, rows, strict=True):
        item = _object(row, {"address", "type", "resource_id", "disposition"}, "managed resource")
        _require(item["address"] == address and item["type"] == resource_type, "managed resource identity")
        _require(item["disposition"] == "present", "managed resource disposition")
        result[address] = _fake_id(item["resource_id"], address)
    _require(len(set(result.values())) == 16, "managed resource identity replay")
    return result


def _validate_attached_graph(value: Any, ids: dict[str, str]) -> tuple[tuple[str, str, str | None, str, str], ...]:
    graph = _object(value, {"compute", "network", "identity", "scheduler", "budget"}, "attached graph")
    compute = _object(graph["compute"], {"instance", "root_volume", "primary_eni", "launch_template"}, "compute graph")
    instance = _object(compute["instance"], {"id", "state", "root_volume_id", "primary_eni_id", "launch_template_id", "launch_template_version"}, "instance graph")
    volume = _object(compute["root_volume"], {"id", "attached_to", "size_gib", "type", "encrypted", "delete_on_termination"}, "volume graph")
    eni = _object(compute["primary_eni"], {"id", "attached_to", "subnet_id", "security_group_ids", "delete_on_termination"}, "eni graph")
    template = _object(compute["launch_template"], {"id", "versions", "default_version", "latest_version"}, "template graph")
    _require(instance["id"] == ids["aws_instance.host"] and instance["state"] == "running", "instance graph binding")
    _require(instance["root_volume_id"] == volume["id"] and instance["primary_eni_id"] == eni["id"], "instance attachment binding")
    _require(instance["launch_template_id"] == ids["aws_launch_template.host"] and instance["launch_template_id"] == template["id"], "template binding")
    _require(instance["launch_template_version"] == 1 and template == {"id": template["id"], "versions": [1], "default_version": 1, "latest_version": 1}, "template version policy")
    _fake_id(volume["id"], "root volume")
    _fake_id(eni["id"], "primary eni")
    _require(volume == {"id": volume["id"], "attached_to": instance["id"], "size_gib": 30, "type": "gp3", "encrypted": True, "delete_on_termination": True}, "root volume policy")
    _require(eni["attached_to"] == instance["id"] and eni["subnet_id"] == ids["aws_subnet.campaign"] and eni["security_group_ids"] == [ids["aws_security_group.host"]] and eni["delete_on_termination"] is True, "primary eni policy")

    network = _object(graph["network"], {"vpc_id", "internet_gateway", "subnet_id", "route_table", "security_group"}, "network graph")
    gateway = _object(network["internet_gateway"], {"id", "attached_vpc_id", "attachment_id"}, "gateway graph")
    route_table = _object(network["route_table"], {"id", "routes", "associations"}, "route table graph")
    security_group = _object(network["security_group"], {"id", "ingress_rule_ids", "egress_rules"}, "security group graph")
    _require(network["vpc_id"] == ids["aws_vpc.campaign"] and network["subnet_id"] == ids["aws_subnet.campaign"], "network graph binding")
    _require(gateway["id"] == ids["aws_internet_gateway.campaign"] and gateway["attached_vpc_id"] == network["vpc_id"], "gateway attachment")
    _fake_id(gateway["attachment_id"], "gateway attachment")
    _require(route_table["id"] == ids["aws_route_table.campaign"], "route table binding")
    _require(route_table["routes"] == [{"id": ids["aws_route.internet"], "destination": "fixture-default-route", "gateway_id": gateway["id"]}], "route graph")
    _require(route_table["associations"] == [{"id": ids["aws_route_table_association.campaign"], "subnet_id": network["subnet_id"]}], "association graph")
    _require(security_group["id"] == ids["aws_security_group.host"] and security_group["ingress_rule_ids"] == [], "security group ingress")
    rules = _array(security_group["egress_rules"], "security group egress", maximum=4)
    _require(len(rules) == 4, "security group egress count")
    expected_rules = ("tcp-443-any", "tcp-80-any", "udp-53-resolver", "tcp-53-resolver")
    rule_ids: list[str] = []
    for rule, policy in zip(rules, expected_rules, strict=True):
        item = _object(rule, {"id", "policy"}, "security group rule")
        rule_ids.append(_fake_id(item["id"], "security group rule"))
        _require(item["policy"] == policy, "security group rule policy")
    _require(len(set(rule_ids)) == 4, "security group rule replay")

    identity = _object(graph["identity"], {"host_role", "terminator_role", "instance_profile"}, "identity graph")
    host_role = _object(identity["host_role"], {"id", "trust_digest", "inline_policy_ids", "managed_attachment_ids"}, "host role graph")
    terminator = _object(identity["terminator_role"], {"id", "trust_digest", "inline_policy_ids", "managed_attachment_ids"}, "terminator role graph")
    profile = _object(identity["instance_profile"], {"id", "role_ids", "membership_id"}, "instance profile graph")
    _require(host_role["id"] == ids["aws_iam_role.host"] and host_role["inline_policy_ids"] == [] and host_role["managed_attachment_ids"] == [ids["aws_iam_role_policy_attachment.ssm"]], "host role policy graph")
    _require(terminator["id"] == ids["aws_iam_role.terminator"] and terminator["inline_policy_ids"] == [ids["aws_iam_role_policy.terminator"]] and terminator["managed_attachment_ids"] == [], "terminator role policy graph")
    _digest(host_role["trust_digest"], "host trust")
    _digest(terminator["trust_digest"], "terminator trust")
    _require(host_role["trust_digest"] != terminator["trust_digest"], "role trust identity replay")
    _require(profile["id"] == ids["aws_iam_instance_profile.host"] and profile["role_ids"] == [host_role["id"]], "instance profile graph")
    _fake_id(profile["membership_id"], "instance profile membership")

    scheduler = _object(graph["scheduler"], {"schedule_id", "group_id", "target"}, "scheduler graph")
    target = _object(scheduler["target"], {"id", "action", "instance_ids", "role_id"}, "scheduler target")
    _require(scheduler["schedule_id"] == ids["aws_scheduler_schedule.terminate"], "schedule graph")
    _fake_id(scheduler["group_id"], "schedule group")
    _fake_id(target["id"], "schedule target")
    _require(target["action"] == "terminate-instances" and target["instance_ids"] == [instance["id"]] and target["role_id"] == terminator["id"], "schedule target graph")

    budget = _object(graph["budget"], {"id", "notifications"}, "budget graph")
    _require(budget["id"] == ids["aws_budgets_budget.campaign"], "budget binding")
    notifications = _array(budget["notifications"], "budget notifications", maximum=3)
    _require(len(notifications) == 3, "budget notification count")
    notification_ids: list[str] = []
    subscriber_ids: list[str] = []
    for row, threshold in zip(notifications, (25, 50, 100), strict=True):
        item = _object(row, {"id", "threshold_percent", "subscriber_commitments"}, "budget notification")
        notification_ids.append(_fake_id(item["id"], "budget notification"))
        _require(item["threshold_percent"] == threshold and len(item["subscriber_commitments"]) == 1, "budget notification policy")
        subscriber_ids.append(_fake_id(item["subscriber_commitments"][0], "budget subscriber"))
    _require(len(set(notification_ids)) == 3 and len(set(subscriber_ids)) == 3, "budget nested identity replay")
    all_resource_ids = [
        *ids.values(), volume["id"], eni["id"], gateway["attachment_id"], *rule_ids,
        profile["membership_id"], scheduler["group_id"], target["id"],
        *notification_ids, *subscriber_ids,
    ]
    _require(len(set(all_resource_ids)) == len(all_resource_ids), "managed or attached identity replay")

    entries: list[tuple[str, str, str | None, str, str]] = []
    def add(category: str, identity_value: str, parent: str | None, relation: str, attributes: Any) -> None:
        entries.append((category, identity_value, parent, relation, codec.canonical_sha256(attributes)))
    category_by_address = {
        "aws_vpc.campaign": "vpcs", "aws_internet_gateway.campaign": "internet_gateway_attachments",
        "aws_subnet.campaign": "subnets", "aws_route_table.campaign": "route_tables",
        "aws_route.internet": "routes", "aws_route_table_association.campaign": "route_table_associations",
        "aws_security_group.host": "security_group_rules", "aws_iam_role.host": "iam_roles",
        "aws_iam_role_policy_attachment.ssm": "iam_policy_attachments",
        "aws_iam_instance_profile.host": "instance_profiles", "aws_launch_template.host": "launch_templates",
        "aws_instance.host": "instance_states", "aws_iam_role.terminator": "iam_roles",
        "aws_iam_role_policy.terminator": "iam_inline_policies",
        "aws_scheduler_schedule.terminate": "scheduler_schedules", "aws_budgets_budget.campaign": "budgets",
    }
    for address in RESOURCE_ADDRESSES:
        add(category_by_address[address], ids[address], None, "managed", {"address": address})
    add("root_volumes", volume["id"], instance["id"], "root-volume", volume)
    add("network_interfaces", eni["id"], instance["id"], "primary-eni", eni)
    add("internet_gateway_attachments", gateway["attachment_id"], gateway["id"], "gateway-attachment", gateway)
    for rule in rules:
        add("security_group_rules", rule["id"], security_group["id"], "security-group-rule", rule)
    add("launch_template_versions", f"{template['id']}-version-1", template["id"], "launch-template-version", template)
    add("iam_trust_policies", host_role["trust_digest"], host_role["id"], "role-trust", {"digest": host_role["trust_digest"]})
    add("iam_trust_policies", terminator["trust_digest"], terminator["id"], "role-trust", {"digest": terminator["trust_digest"]})
    add("instance_profile_memberships", profile["membership_id"], profile["id"], "profile-membership", profile)
    add("scheduler_groups", scheduler["group_id"], scheduler["schedule_id"], "schedule-group", {"id": scheduler["group_id"]})
    add("scheduler_targets", target["id"], scheduler["schedule_id"], "schedule-target", target)
    for notification, subscriber in zip(notifications, subscriber_ids, strict=True):
        add("budget_notifications", notification["id"], budget["id"], "budget-notification", notification)
        add("budget_subscribers", subscriber, notification["id"], "budget-subscriber", {"commitment": subscriber})
    _require(len(entries) <= MAX_INVENTORY_OBJECTS and len({(row[0], row[1], row[3]) for row in entries}) == len(entries), "inventory expectation replay")
    return tuple(sorted(entries))


def infrastructure_receipt_from_mapping(value: Any) -> InfrastructureReceipt:
    observed, raw = _snapshot(value)
    _object(observed, _INFRASTRUCTURE_KEYS, "infrastructure receipt")
    _require(observed["version"] == INFRASTRUCTURE_RECEIPT_VERSION, "infrastructure receipt version")
    fixture_id = _closed_fixture(observed["synthetic_fixture"])
    batch, ordinal, mode = _binding(observed)
    expiry = _expiry(observed["common_expiry"])
    plan_digest = _digest(observed["plan_receipt_sha256"], "plan receipt")
    semantic_digest = _digest(observed["semantic_plan_sha256"], "semantic plan")
    state = _object(observed["state_lineage"], {"state_key", "lineage_commitment", "generation_before", "serial_before", "prior_state_sha256", "generation_after_apply", "serial_after_apply", "applied_state_sha256"}, "infrastructure state lineage")
    key = _fake_id(state["state_key"], "state key"); lineage = _digest(state["lineage_commitment"], "state lineage")
    _require(state["generation_before"] == 0 and state["serial_before"] == 0 and state["prior_state_sha256"] == ZERO_SHA256, "infrastructure prior state")
    _require(state["generation_after_apply"] == 1 and state["serial_after_apply"] == 1, "apply state generation")
    _digest(state["applied_state_sha256"], "applied state")
    _require(observed["apply_invocations"] == 1, "apply invocation count")
    running = _object(observed["running_observation"], {"state", "observed_monotonic_ns", "apply_to_running_ns", "certain"}, "running observation")
    _require(running["state"] == "running" and running["certain"] is True, "running observation certainty")
    _integer(running["observed_monotonic_ns"], "running observation", 1)
    _integer(running["apply_to_running_ns"], "apply to running", 1)
    ids = _resource_ids(observed["managed_resources"])
    expectations = _validate_attached_graph(observed["attached_graph"], ids)
    destroy = _object(
        observed["destroy_settlement"],
        {
            "pre_destroy_receipt_sha256", "destroy_invocations", "certainty",
            "generation_before_destroy", "serial_before_destroy", "state_before_destroy_sha256",
            "generation_after_destroy", "serial_after_destroy", "destroyed_state_sha256",
        },
        "destroy settlement",
    )
    _digest(destroy["pre_destroy_receipt_sha256"], "pre-destroy receipt")
    _require(destroy["destroy_invocations"] == 1 and destroy["certainty"] == "certain", "destroy invocation or certainty")
    _require(destroy["generation_before_destroy"] == 1 and destroy["serial_before_destroy"] == 1, "destroy prior generation")
    _require(destroy["state_before_destroy_sha256"] == state["applied_state_sha256"], "destroy applied-state lineage")
    _require(destroy["generation_after_destroy"] == 2 and destroy["serial_after_destroy"] == 2, "destroy state generation")
    destroyed_digest = _digest(destroy["destroyed_state_sha256"], "destroyed state")
    _require(destroyed_digest != state["applied_state_sha256"], "destroy did not advance state identity")
    return InfrastructureReceipt(raw, batch, ordinal, mode, fixture_id, expiry, plan_digest, semantic_digest, key, lineage, destroyed_digest, expectations)


def _expectation_rows(value: Any) -> tuple[tuple[str, str, str | None, str, str], ...]:
    rows = _array(value, "expected objects")
    result: list[tuple[str, str, str | None, str, str]] = []
    for row in rows:
        item = _object(row, {"category", "identity", "parent_identity", "relation", "expected_attributes_sha256"}, "expected object")
        _require(item["category"] in INVENTORY_CATEGORIES and item["relation"] in _RELATIONS, "expected object category or relation")
        identity = _text(item["identity"], "expected identity")
        _require(_FAKE_ID.fullmatch(identity) is not None or _DIGEST.fullmatch(identity) is not None, "expected object is not synthetic")
        parent = item["parent_identity"]
        if parent is not None:
            _text(parent, "expected parent")
            _require(_FAKE_ID.fullmatch(parent) is not None or _DIGEST.fullmatch(parent) is not None, "expected parent is not synthetic")
        result.append((item["category"], identity, parent, item["relation"], _digest(item["expected_attributes_sha256"], "expected attributes")))
    _require(result == sorted(result) and len(set(result)) == len(result), "expected objects not unique and sorted")
    return tuple(result)


def _pagination(value: Any) -> tuple[bool, set[str]]:
    rows = _array(value, "pagination", maximum=len(INVENTORY_CATEGORIES))
    _require(len(rows) == len(INVENTORY_CATEGORIES), "inventory category coverage")
    uncertain: set[str] = set()
    page_digests: set[str] = set()
    for expected_category, row in zip(INVENTORY_CATEGORIES, rows, strict=True):
        item = _object(row, {"category", "pages", "complete", "truncated", "error"}, "pagination category")
        _require(item["category"] == expected_category, "inventory category order")
        pages = _array(item["pages"], "category pages", maximum=MAX_PAGES_PER_CATEGORY)
        _require(len(pages) >= 1, "missing category page")
        prior_token: str | None = None
        tokens: set[str] = set()
        for ordinal, page in enumerate(pages, 1):
            current = _object(page, {"ordinal", "request_token", "next_token", "response_sha256", "item_count"}, "inventory page")
            _require(current["ordinal"] == ordinal and current["request_token"] == prior_token, "pagination chain")
            _integer(current["item_count"], "page item count", 0, MAX_INVENTORY_OBJECTS)
            digest = _digest(current["response_sha256"], "page response")
            _require(digest not in page_digests, "raw response replay")
            page_digests.add(digest)
            next_token = current["next_token"]
            if next_token is not None:
                _fake_id(next_token, "pagination token")
                _require(next_token not in tokens, "pagination token replay")
                tokens.add(next_token)
            prior_token = next_token
        _require(type(item["complete"]) is bool and type(item["truncated"]) is bool, "pagination flags")
        _require(item["error"] is None or item["error"] in {"access-denied", "category-failed", "identity-changed", "unsupported"}, "pagination error")
        if item["complete"]:
            _require(prior_token is None and item["error"] is None and item["truncated"] is False, "contradictory complete pagination")
        else:
            uncertain.add("missing-page")
        if item["truncated"]:
            uncertain.add("truncated-response")
        if item["error"] is not None:
            uncertain.add("identity-mismatch" if item["error"] == "identity-changed" else ("scope-unsupported" if item["error"] == "unsupported" else "category-error"))
    return not uncertain, uncertain


def inventory_receipt_from_mapping(value: Any) -> InventoryReceipt:
    observed, raw = _snapshot(value)
    _object(observed, _INVENTORY_KEYS, "inventory receipt")
    _require(observed["version"] == INVENTORY_RECEIPT_VERSION, "inventory receipt version")
    fixture_id = _closed_fixture(observed["synthetic_fixture"])
    try:
        status = InventoryStatus(observed["status"])
    except (TypeError, ValueError) as error:
        raise ReceiptContractError("inventory status") from error
    batch, ordinal, mode = _binding(observed)
    expiry = _expiry(observed["common_expiry"])
    infrastructure_digest = _digest(observed["infrastructure_receipt_sha256"], "infrastructure receipt")
    state = _object(observed["state_lineage"], {"state_key", "lineage_commitment", "destroyed_generation", "destroyed_serial", "destroyed_state_sha256"}, "inventory state lineage")
    state_key = _fake_id(state["state_key"], "state key"); lineage = _digest(state["lineage_commitment"], "state lineage")
    _require(state["destroyed_generation"] == 2 and state["destroyed_serial"] == 2, "destroy state generation")
    destroyed_digest = _digest(state["destroyed_state_sha256"], "destroyed state")

    observer = _object(observed["observer"], {"identity_commitment", "operator_commitment", "account_commitment", "credential_class", "mutation_capable", "session_id", "run_id", "sequence", "started_monotonic_ns", "ended_monotonic_ns", "procedure_version", "signature_valid"}, "inventory observer")
    observer_id = _digest(observer["identity_commitment"], "observer identity")
    operator_id = _digest(observer["operator_commitment"], "operator identity")
    account_id = _digest(observer["account_commitment"], "observer account")
    _require(observer_id != operator_id, "operator cannot be inventory observer")
    _require(observer["credential_class"] == "read-only-nonmutating" and observer["mutation_capable"] is False, "observer mutation authority")
    session_id = _fake_id(observer["session_id"], "observer session"); run_id = _fake_id(observer["run_id"], "observer run")
    sequence = _integer(observer["sequence"], "observer sequence", 1)
    started = _integer(observer["started_monotonic_ns"], "observer start", 1)
    ended = _integer(observer["ended_monotonic_ns"], "observer end", started + 1)
    _require(observer["procedure_version"] == "synthetic-complete-graph/v1" and observer["signature_valid"] is True, "observer procedure or signature")

    scope = _object(observed["scope"], {"account_commitments", "partitions", "regions", "categories", "tag_filters_used", "name_filters_used"}, "inventory scope")
    _require(scope["account_commitments"] == [account_id] and scope["partitions"] == ["synthetic-partition"] and scope["regions"] == ["synthetic-region-1"], "observer account, partition, or region scope")
    _require(scope["categories"] == list(INVENTORY_CATEGORIES), "observer category scope")
    _require(scope["tag_filters_used"] is False and scope["name_filters_used"] is False, "tag or name is sole observer scope")
    complete, pagination_reasons = _pagination(observed["pagination"])

    reconciliation = _object(observed["reconciliation"], {"expected_objects", "observations", "unexpected_objects", "baseline_delta"}, "inventory reconciliation")
    expected = _expectation_rows(reconciliation["expected_objects"])
    observations = _array(reconciliation["observations"], "inventory observations")
    _require(len(observations) == len(expected), "planned identity reconciliation count")
    dispositions: list[str] = []
    for expected_row, row in zip(expected, observations, strict=True):
        item = _object(row, {"category", "identity", "disposition", "observed_attributes_sha256"}, "inventory observation")
        _require((item["category"], item["identity"]) == expected_row[:2], "planned identity reconciliation order")
        _require(item["disposition"] in {"absent", "present", "unknown"}, "inventory disposition")
        if item["disposition"] == "present":
            _digest(item["observed_attributes_sha256"], "observed attributes")
        else:
            _require(item["observed_attributes_sha256"] is None, "absent or unknown object has attributes")
        dispositions.append(item["disposition"])
    unexpected = _array(reconciliation["unexpected_objects"], "unexpected objects")
    delta = _array(reconciliation["baseline_delta"], "baseline delta")
    for label, rows in (("unexpected object", unexpected), ("baseline delta", delta)):
        for row in rows:
            item = _object(row, {"category", "identity", "attributes_sha256"}, label)
            _require(item["category"] in INVENTORY_CATEGORIES, f"{label} category")
            _fake_id(item["identity"], f"{label} identity")
            _digest(item["attributes_sha256"], f"{label} attributes")
    reasons = _array(observed["uncertainty_reasons"], "uncertainty reasons", maximum=len(_UNCERTAINTY_REASONS))
    _require(all(reason in _UNCERTAINTY_REASONS for reason in reasons) and reasons == sorted(set(reasons)), "uncertainty reason set")
    derived_reasons = set(pagination_reasons)
    if "unknown" in dispositions:
        derived_reasons.add("unknown-disposition")
    if delta:
        derived_reasons.add("unexpected-delta")
    _require(set(reasons) == derived_reasons, "uncertainty reasons do not match observations")
    has_nonzero = "present" in dispositions or bool(unexpected) or bool(delta)
    if status is InventoryStatus.ZERO:
        _require(complete and not reasons and not has_nonzero and all(item == "absent" for item in dispositions), "zero inventory semantics")
    elif status is InventoryStatus.NONZERO:
        _require(complete and not reasons and has_nonzero and "unknown" not in dispositions and not delta, "nonzero inventory semantics")
    else:
        _require(bool(reasons), "uncertain inventory lacks uncertainty")
    return InventoryReceipt(raw, status, batch, ordinal, mode, fixture_id, expiry, infrastructure_digest, state_key, lineage, destroyed_digest, account_id, scope["regions"][0], operator_id, observer_id, session_id, run_id, sequence, expected)


def _from_bytes(raw: bytes, parser: Callable[[Any], Any]) -> Any:
    return parser(codec.load_canonical_bytes(raw))


def plan_receipt_from_canonical_bytes(raw: bytes) -> PlanReceipt:
    return _from_bytes(raw, plan_receipt_from_mapping)


def infrastructure_receipt_from_canonical_bytes(raw: bytes) -> InfrastructureReceipt:
    return _from_bytes(raw, infrastructure_receipt_from_mapping)


def inventory_receipt_from_canonical_bytes(raw: bytes) -> InventoryReceipt:
    return _from_bytes(raw, inventory_receipt_from_mapping)


def validate_cycle_receipts(plan: PlanReceipt, infrastructure: InfrastructureReceipt, inventory: InventoryReceipt) -> CycleReceiptSet:
    """Validate cross-receipt lineage without converting any outcome into authority."""
    _require(type(plan) is PlanReceipt and type(infrastructure) is InfrastructureReceipt and type(inventory) is InventoryReceipt, "receipt type is not closed")
    try:
        _require(plan_receipt_from_canonical_bytes(plan.canonical) == plan, "forged plan receipt")
        _require(infrastructure_receipt_from_canonical_bytes(infrastructure.canonical) == infrastructure, "forged infrastructure receipt")
        _require(inventory_receipt_from_canonical_bytes(inventory.canonical) == inventory, "forged inventory receipt")
    except codec.CampaignCodecError as error:
        raise ReceiptContractError("receipt canonical bytes rejected") from error
    common = (plan.batch_commitment, plan.cycle_ordinal, plan.cycle_mode, plan.fixture_id, plan.common_expiry)
    _require((infrastructure.batch_commitment, infrastructure.cycle_ordinal, infrastructure.cycle_mode, infrastructure.fixture_id, infrastructure.common_expiry) == common, "plan/infrastructure common binding")
    _require((inventory.batch_commitment, inventory.cycle_ordinal, inventory.cycle_mode, inventory.fixture_id, inventory.common_expiry) == common, "inventory common binding")
    _require(infrastructure.plan_receipt_sha256 == plan.sha256(), "infrastructure plan lineage")
    _require(infrastructure.semantic_plan_sha256 == plan.semantic_plan_sha256, "semantic plan lineage")
    _require((infrastructure.state_key, infrastructure.state_lineage_commitment) == (plan.state_key, plan.state_lineage_commitment), "apply state lineage")
    _require(inventory.infrastructure_receipt_sha256 == infrastructure.sha256(), "inventory infrastructure lineage")
    _require((inventory.state_key, inventory.state_lineage_commitment) == (plan.state_key, plan.state_lineage_commitment), "destroy state lineage")
    _require(inventory.destroyed_state_sha256 == infrastructure.destroyed_state_sha256, "inventory destroyed-state lineage")
    plan_value = plan.as_dict()
    _require(inventory.account_commitment == plan_value["account_commitment"] and inventory.region_scope == plan_value["region_scope"], "observer plan scope binding")
    _require(inventory.operator_commitment == plan_value["operator_commitment"] and inventory.observer_commitment != inventory.operator_commitment, "observer role separation")
    _require(inventory.expected_objects == infrastructure.inventory_expectations, "attached-resource reconciliation lineage")
    return CycleReceiptSet(plan, infrastructure, inventory)


def require_zero_inventory(receipts: CycleReceiptSet) -> None:
    _require(type(receipts) is CycleReceiptSet, "cycle receipt set is not closed")
    checked = validate_cycle_receipts(receipts.plan, receipts.infrastructure, receipts.inventory)
    _require(checked.inventory.status is InventoryStatus.ZERO, "fresh zero inventory required")


def validate_seven_cycle_receipts(values: tuple[CycleReceiptSet, ...]) -> tuple[CycleReceiptSet, ...]:
    """Check fixed batch ordering, isolated state, and observer freshness."""
    _require(type(values) is tuple and len(values) == 7, "exactly seven immutable cycle receipt sets required")
    _require(all(type(item) is CycleReceiptSet for item in values), "seven-cycle receipt set type is not closed")
    checked = tuple(validate_cycle_receipts(item.plan, item.infrastructure, item.inventory) for item in values)
    first_plan = checked[0].plan.as_dict()
    common = (
        checked[0].plan.batch_commitment,
        checked[0].plan.fixture_id,
        checked[0].plan.common_expiry,
        first_plan["source_commitment"],
        first_plan["account_commitment"],
        first_plan["operator_commitment"],
        first_plan["partition_scope"],
        first_plan["region_scope"],
        checked[0].plan.semantic_plan_sha256,
        first_plan["checker_sha256"],
        first_plan["configuration_sha256"],
        first_plan["lock_sha256"],
        first_plan["variables_sha256"],
    )
    state_keys: set[str] = set()
    lineages: set[str] = set()
    sessions: set[str] = set()
    runs: set[str] = set()
    receipt_digests: set[str] = set()
    instance_ids: set[str] = set()
    volume_ids: set[str] = set()
    template_ids: set[str] = set()
    prior_observer_sequence = 0
    for ordinal, item in enumerate(checked, 1):
        plan_value = item.plan.as_dict()
        observed_common = (
            item.plan.batch_commitment,
            item.plan.fixture_id,
            item.plan.common_expiry,
            plan_value["source_commitment"],
            plan_value["account_commitment"],
            plan_value["operator_commitment"],
            plan_value["partition_scope"],
            plan_value["region_scope"],
            item.plan.semantic_plan_sha256,
            plan_value["checker_sha256"],
            plan_value["configuration_sha256"],
            plan_value["lock_sha256"],
            plan_value["variables_sha256"],
        )
        _require(item.plan.cycle_ordinal == ordinal and item.plan.cycle_mode is CYCLE_MODES[ordinal - 1], "seven-cycle order or mode")
        _require(observed_common == common, "seven-cycle common binding")
        require_zero_inventory(item)
        _require(item.plan.state_key not in state_keys and item.plan.state_lineage_commitment not in lineages, "state lineage replay")
        state_keys.add(item.plan.state_key)
        lineages.add(item.plan.state_lineage_commitment)
        inventory = item.inventory
        _require(inventory.session_id not in sessions and inventory.run_id not in runs, "observer freshness replay")
        _require(inventory.observation_sequence > prior_observer_sequence, "observer sequence did not advance")
        sessions.add(inventory.session_id)
        runs.add(inventory.run_id)
        prior_observer_sequence = inventory.observation_sequence
        for receipt in (item.plan, item.infrastructure, item.inventory):
            receipt_digest = receipt.sha256()
            _require(receipt_digest not in receipt_digests, "cycle receipt replay")
            receipt_digests.add(receipt_digest)
        for category, identity, _parent, relation, _attributes in item.infrastructure.inventory_expectations:
            target = None
            if category == "instance_states" and relation == "managed":
                target = instance_ids
            elif category == "root_volumes" and relation == "root-volume":
                target = volume_ids
            elif category == "launch_templates" and relation == "managed":
                target = template_ids
            if target is not None:
                _require(identity not in target, "fresh infrastructure identity replay")
                target.add(identity)
    _require(len(instance_ids) == len(volume_ids) == len(template_ids) == 7, "fresh infrastructure identity coverage")
    return checked


assert len(RESOURCE_SHAPE) == 16
assert len(set(RESOURCE_ADDRESSES)) == 16
assert len(set(INVENTORY_CATEGORIES)) == len(INVENTORY_CATEGORIES)

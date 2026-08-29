#!/usr/bin/env python3
"""Hostile bounded-synthetic matrix for fake-only Slice C receipt checkers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))

import completion_campaign_codec as codec
import completion_campaign_receipts as receipts
from completion_campaign_contracts import CYCLE_MODES, ZERO_SHA256


def require(condition, message="test assertion failed"):
    if not condition:
        raise AssertionError(message)


def expect(kind, function, *args):
    try:
        function(*args)
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


def digest(label):
    return hashlib.sha256(f"slice-c-synthetic:{label}".encode("ascii")).hexdigest()


def fixture(identity="syn-fixture-cycle", ordinal=1):
    return {
        "authority": receipts.SYNTHETIC_AUTHORITY,
        "fixture_id": identity,
        "production_authorized": False,
    }


def plan_fixture(ordinal=1, label="base"):
    resources = [
        {
            "ordinal": index,
            "address": address,
            "type": resource_type,
            "mode": "managed",
            "actions": ["create"],
            "values": receipts._semantics(address),
        }
        for index, (address, resource_type) in enumerate(receipts.RESOURCE_SHAPE, 1)
    ]
    return {
        "version": receipts.PLAN_RECEIPT_VERSION,
        "synthetic_fixture": fixture(f"syn-fixture-{label}"),
        "batch_commitment": digest(f"batch:{label}"),
        "cycle_ordinal": ordinal,
        "cycle_mode": CYCLE_MODES[ordinal - 1].value,
        "source_commitment": digest("source"),
        "account_commitment": digest("account"),
        "operator_commitment": digest("operator"),
        "partition_scope": "synthetic-partition",
        "region_scope": "synthetic-region-1",
        "common_expiry": "2030-01-01T04:00:00Z",
        "plan_file_sha256": digest(f"plan-file:{label}:{ordinal}"),
        "semantic_plan_sha256": codec.canonical_sha256(resources),
        "checker_sha256": digest("checker"),
        "configuration_sha256": digest("configuration"),
        "lock_sha256": digest("lock"),
        "variables_sha256": digest("variables"),
        "state_lineage": {
            "state_key": f"syn-state-{label}-c{ordinal:02d}",
            "lineage_commitment": digest(f"lineage:{label}:{ordinal}"),
            "generation_before": 0,
            "serial_before": 0,
            "prior_state_sha256": ZERO_SHA256,
        },
        "resource_changes": resources,
    }


def managed_ids(label="base"):
    names = (
        "vpc", "gateway", "subnet", "route-table", "route", "association", "security-group",
        "host-role", "host-attachment", "profile", "launch-template", "instance",
        "terminator-role", "terminator-policy", "schedule", "budget",
    )
    return {
        address: f"syn-{name}-{label}"
        for (address, _), name in zip(receipts.RESOURCE_SHAPE, names, strict=True)
    }


def infrastructure_fixture(plan_value):
    parsed = receipts.plan_receipt_from_mapping(plan_value)
    ids = managed_ids(f"c{parsed.cycle_ordinal:02d}")
    instance = ids["aws_instance.host"]
    template = ids["aws_launch_template.host"]
    volume = f"syn-root-volume-c{parsed.cycle_ordinal:02d}"
    eni = f"syn-primary-eni-c{parsed.cycle_ordinal:02d}"
    attached = {
        "compute": {
            "instance": {
                "id": instance,
                "state": "running",
                "root_volume_id": volume,
                "primary_eni_id": eni,
                "launch_template_id": template,
                "launch_template_version": 1,
            },
            "root_volume": {
                "id": volume,
                "attached_to": instance,
                "size_gib": 30,
                "type": "gp3",
                "encrypted": True,
                "delete_on_termination": True,
            },
            "primary_eni": {
                "id": eni,
                "attached_to": instance,
                "subnet_id": ids["aws_subnet.campaign"],
                "security_group_ids": [ids["aws_security_group.host"]],
                "delete_on_termination": True,
            },
            "launch_template": {
                "id": template,
                "versions": [1],
                "default_version": 1,
                "latest_version": 1,
            },
        },
        "network": {
            "vpc_id": ids["aws_vpc.campaign"],
            "internet_gateway": {
                "id": ids["aws_internet_gateway.campaign"],
                "attached_vpc_id": ids["aws_vpc.campaign"],
                "attachment_id": f"syn-gateway-attachment-c{parsed.cycle_ordinal:02d}",
            },
            "subnet_id": ids["aws_subnet.campaign"],
            "route_table": {
                "id": ids["aws_route_table.campaign"],
                "routes": [{
                    "id": ids["aws_route.internet"],
                    "destination": "fixture-default-route",
                    "gateway_id": ids["aws_internet_gateway.campaign"],
                }],
                "associations": [{
                    "id": ids["aws_route_table_association.campaign"],
                    "subnet_id": ids["aws_subnet.campaign"],
                }],
            },
            "security_group": {
                "id": ids["aws_security_group.host"],
                "ingress_rule_ids": [],
                "egress_rules": [
                    {"id": f"syn-rule-{index}-c{parsed.cycle_ordinal:02d}", "policy": policy}
                    for index, policy in enumerate(("tcp-443-any", "tcp-80-any", "udp-53-resolver", "tcp-53-resolver"), 1)
                ],
            },
        },
        "identity": {
            "host_role": {
                "id": ids["aws_iam_role.host"],
                "trust_digest": digest("host-trust"),
                "inline_policy_ids": [],
                "managed_attachment_ids": [ids["aws_iam_role_policy_attachment.ssm"]],
            },
            "terminator_role": {
                "id": ids["aws_iam_role.terminator"],
                "trust_digest": digest("terminator-trust"),
                "inline_policy_ids": [ids["aws_iam_role_policy.terminator"]],
                "managed_attachment_ids": [],
            },
            "instance_profile": {
                "id": ids["aws_iam_instance_profile.host"],
                "role_ids": [ids["aws_iam_role.host"]],
                "membership_id": f"syn-profile-membership-c{parsed.cycle_ordinal:02d}",
            },
        },
        "scheduler": {
            "schedule_id": ids["aws_scheduler_schedule.terminate"],
            "group_id": f"syn-schedule-group-c{parsed.cycle_ordinal:02d}",
            "target": {
                "id": f"syn-schedule-target-c{parsed.cycle_ordinal:02d}",
                "action": "terminate-instances",
                "instance_ids": [instance],
                "role_id": ids["aws_iam_role.terminator"],
            },
        },
        "budget": {
            "id": ids["aws_budgets_budget.campaign"],
            "notifications": [
                {
                    "id": f"syn-budget-notification-{threshold}-c{parsed.cycle_ordinal:02d}",
                    "threshold_percent": threshold,
                    "subscriber_commitments": [f"syn-budget-subscriber-{threshold}-c{parsed.cycle_ordinal:02d}"],
                }
                for threshold in (25, 50, 100)
            ],
        },
    }
    return {
        "version": receipts.INFRASTRUCTURE_RECEIPT_VERSION,
        "synthetic_fixture": deepcopy(plan_value["synthetic_fixture"]),
        "batch_commitment": parsed.batch_commitment,
        "cycle_ordinal": parsed.cycle_ordinal,
        "cycle_mode": parsed.cycle_mode.value,
        "common_expiry": parsed.common_expiry,
        "plan_receipt_sha256": parsed.sha256(),
        "semantic_plan_sha256": parsed.semantic_plan_sha256,
        "state_lineage": {
            **deepcopy(plan_value["state_lineage"]),
            "generation_after_apply": 1,
            "serial_after_apply": 1,
            "applied_state_sha256": digest(f"applied-state:{parsed.cycle_ordinal}"),
        },
        "apply_invocations": 1,
        "running_observation": {
            "state": "running",
            "observed_monotonic_ns": 2_000,
            "apply_to_running_ns": 1_000,
            "certain": True,
        },
        "managed_resources": [
            {"address": address, "type": resource_type, "resource_id": ids[address], "disposition": "present"}
            for address, resource_type in receipts.RESOURCE_SHAPE
        ],
        "attached_graph": attached,
        "destroy_settlement": {
            "pre_destroy_receipt_sha256": digest(f"pre-destroy:{parsed.cycle_ordinal}"),
            "destroy_invocations": 1,
            "certainty": "certain",
            "generation_before_destroy": 1,
            "serial_before_destroy": 1,
            "state_before_destroy_sha256": digest(f"applied-state:{parsed.cycle_ordinal}"),
            "generation_after_destroy": 2,
            "serial_after_destroy": 2,
            "destroyed_state_sha256": digest(f"destroyed-state:{parsed.cycle_ordinal}"),
        },
    }


def expected_mappings(infrastructure):
    return [
        {
            "category": category,
            "identity": identity,
            "parent_identity": parent,
            "relation": relation,
            "expected_attributes_sha256": attributes,
        }
        for category, identity, parent, relation, attributes in infrastructure.inventory_expectations
    ]


def inventory_fixture(plan_value, infrastructure_value, status="zero"):
    plan = receipts.plan_receipt_from_mapping(plan_value)
    infrastructure = receipts.infrastructure_receipt_from_mapping(infrastructure_value)
    expected = expected_mappings(infrastructure)
    observations = [
        {
            "category": row["category"],
            "identity": row["identity"],
            "disposition": "absent",
            "observed_attributes_sha256": None,
        }
        for row in expected
    ]
    value = {
        "version": receipts.INVENTORY_RECEIPT_VERSION,
        "synthetic_fixture": deepcopy(plan_value["synthetic_fixture"]),
        "status": status,
        "batch_commitment": plan.batch_commitment,
        "cycle_ordinal": plan.cycle_ordinal,
        "cycle_mode": plan.cycle_mode.value,
        "common_expiry": plan.common_expiry,
        "infrastructure_receipt_sha256": infrastructure.sha256(),
        "state_lineage": {
            "state_key": plan.state_key,
            "lineage_commitment": plan.state_lineage_commitment,
            "destroyed_generation": 2,
            "destroyed_serial": 2,
            "destroyed_state_sha256": digest(f"destroyed-state:{plan.cycle_ordinal}"),
        },
        "observer": {
            "identity_commitment": digest("observer"),
            "operator_commitment": plan_value["operator_commitment"],
            "account_commitment": plan_value["account_commitment"],
            "credential_class": "read-only-nonmutating",
            "mutation_capable": False,
            "session_id": f"syn-observer-session-c{plan.cycle_ordinal:02d}",
            "run_id": f"syn-observer-run-c{plan.cycle_ordinal:02d}",
            "sequence": plan.cycle_ordinal,
            "started_monotonic_ns": 3_000,
            "ended_monotonic_ns": 4_000,
            "procedure_version": "synthetic-complete-graph/v1",
            "signature_valid": True,
        },
        "scope": {
            "account_commitments": [plan_value["account_commitment"]],
            "partitions": ["synthetic-partition"],
            "regions": ["synthetic-region-1"],
            "categories": list(receipts.INVENTORY_CATEGORIES),
            "tag_filters_used": False,
            "name_filters_used": False,
        },
        "pagination": [
            {
                "category": category,
                "pages": [{
                    "ordinal": 1,
                    "request_token": None,
                    "next_token": None,
                    "response_sha256": digest(f"page:{plan.cycle_ordinal}:{category}"),
                    "item_count": 0,
                }],
                "complete": True,
                "truncated": False,
                "error": None,
            }
            for category in receipts.INVENTORY_CATEGORIES
        ],
        "reconciliation": {
            "expected_objects": expected,
            "observations": observations,
            "unexpected_objects": [],
            "baseline_delta": [],
        },
        "uncertainty_reasons": [],
    }
    return value


def valid_set(ordinal=1, label="base"):
    plan_value = plan_fixture(ordinal, label)
    infrastructure_value = infrastructure_fixture(plan_value)
    inventory_value = inventory_fixture(plan_value, infrastructure_value)
    plan = receipts.plan_receipt_from_mapping(plan_value)
    infrastructure = receipts.infrastructure_receipt_from_mapping(infrastructure_value)
    inventory = receipts.inventory_receipt_from_mapping(inventory_value)
    return plan_value, infrastructure_value, inventory_value, plan, infrastructure, inventory


def mutate(value, path, replacement):
    result = deepcopy(value)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result


def closed_codec_matrix():
    for ordinal in range(1, 8):
        values = valid_set(ordinal, f"cycle-{ordinal}")
        plan_value, infrastructure_value, inventory_value, plan, infrastructure, inventory = values
        require(plan.cycle_mode is CYCLE_MODES[ordinal - 1])
        require(receipts.plan_receipt_from_canonical_bytes(codec.canonical_bytes(plan_value)) == plan)
        require(receipts.infrastructure_receipt_from_canonical_bytes(codec.canonical_bytes(infrastructure_value)) == infrastructure)
        require(receipts.inventory_receipt_from_canonical_bytes(codec.canonical_bytes(inventory_value)) == inventory)
        checked = receipts.validate_cycle_receipts(plan, infrastructure, inventory)
        require(checked.zero_proven)
        receipts.require_zero_inventory(checked)
        require(len(infrastructure.inventory_expectations) == 35)
    base = plan_fixture()
    for key in ("version", "synthetic_fixture", "resource_changes"):
        missing = deepcopy(base); del missing[key]
        expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, missing)
    extra = deepcopy(base); extra["extra"] = True
    expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, extra)
    hostile = deepcopy(base); hostile["synthetic_fixture"]["production_authorized"] = True
    expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, hostile)
    hostile = deepcopy(base); hostile["synthetic_fixture"]["authority"] = "production"
    expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, hostile)
    expect(receipts.ReceiptContractError, receipts.plan_receipt_from_canonical_bytes, b'{"version":"x"}\n')
    expect(codec.CampaignCodecError, receipts.plan_receipt_from_canonical_bytes, b'{ "x":1}\n')


def exact_plan_matrix():
    base = plan_fixture()
    for index, (address, _) in enumerate(receipts.RESOURCE_SHAPE):
        changed = deepcopy(base)
        changed["resource_changes"][index]["values"]["tags"]["purpose"] = "other"
        changed["semantic_plan_sha256"] = codec.canonical_sha256(changed["resource_changes"])
        expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, changed)
        changed = deepcopy(base)
        changed["resource_changes"][index]["actions"] = ["update"]
        changed["semantic_plan_sha256"] = codec.canonical_sha256(changed["resource_changes"])
        expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, changed)
        require(base["resource_changes"][index]["address"] == address)
    variants = []
    missing = deepcopy(base); missing["resource_changes"].pop(); variants.append(missing)
    extra = deepcopy(base); extra["resource_changes"].append(deepcopy(extra["resource_changes"][-1])); variants.append(extra)
    reordered = deepcopy(base); reordered["resource_changes"][0:2] = reversed(reordered["resource_changes"][0:2]); variants.append(reordered)
    wrong_type = mutate(base, ["resource_changes", 0, "type"], "other"); variants.append(wrong_type)
    wrong_mode = mutate(base, ["resource_changes", 0, "mode"], "data"); variants.append(wrong_mode)
    for changed in variants:
        changed["semantic_plan_sha256"] = codec.canonical_sha256(changed["resource_changes"])
        expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, changed)
    for path, replacement in (
        (["semantic_plan_sha256"], digest("wrong-semantic")),
        (["cycle_mode"], "readiness"),
        (["common_expiry"], "2030-01-01T04:00:00+00:00"),
        (["common_expiry"], "2030-99-99T04:00:00Z"),
        (["state_lineage", "generation_before"], 1),
        (["state_lineage", "serial_before"], 1),
        (["state_lineage", "prior_state_sha256"], digest("prior")),
        (["partition_scope"], "other"),
        (["region_scope"], "other"),
    ):
        expect(receipts.ReceiptContractError, receipts.plan_receipt_from_mapping, mutate(base, path, replacement))


def infrastructure_graph_matrix():
    plan_value = plan_fixture()
    base = infrastructure_fixture(plan_value)
    paths = (
        (["apply_invocations"], 2),
        (["running_observation", "state"], "pending"),
        (["running_observation", "certain"], False),
        (["state_lineage", "generation_after_apply"], 2),
        (["managed_resources", 0, "disposition"], "absent"),
        (["managed_resources", 1, "resource_id"], base["managed_resources"][0]["resource_id"]),
        (["attached_graph", "compute", "instance", "root_volume_id"], "syn-other-volume"),
        (["attached_graph", "compute", "root_volume", "size_gib"], 31),
        (["attached_graph", "compute", "primary_eni", "delete_on_termination"], False),
        (["attached_graph", "compute", "launch_template", "versions"], [1, 2]),
        (["attached_graph", "network", "internet_gateway", "attached_vpc_id"], "syn-other-vpc"),
        (["attached_graph", "network", "route_table", "routes"], []),
        (["attached_graph", "network", "route_table", "associations"], []),
        (["attached_graph", "network", "security_group", "ingress_rule_ids"], ["syn-rule-ingress"]),
        (["attached_graph", "network", "security_group", "egress_rules", 0, "policy"], "all-traffic"),
        (["attached_graph", "identity", "host_role", "managed_attachment_ids"], []),
        (["attached_graph", "identity", "terminator_role", "inline_policy_ids"], []),
        (["attached_graph", "identity", "instance_profile", "role_ids"], []),
        (["attached_graph", "scheduler", "target", "action"], "other"),
        (["attached_graph", "scheduler", "target", "instance_ids"], []),
        (["attached_graph", "budget", "notifications", 0, "threshold_percent"], 24),
        (["attached_graph", "budget", "notifications", 0, "subscriber_commitments"], []),
        (["destroy_settlement", "destroy_invocations"], 2),
        (["destroy_settlement", "certainty"], "uncertain"),
        (["destroy_settlement", "generation_before_destroy"], 0),
        (["destroy_settlement", "state_before_destroy_sha256"], digest("wrong-applied-state")),
        (["destroy_settlement", "generation_after_destroy"], 3),
        (["destroy_settlement", "destroyed_state_sha256"], digest("applied-state:1")),
    )
    for path, replacement in paths:
        expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, mutate(base, path, replacement))
    changed = deepcopy(base); changed["managed_resources"].pop()
    expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, changed)
    changed = deepcopy(base); changed["attached_graph"]["network"]["security_group"]["egress_rules"].pop()
    expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, changed)
    changed = deepcopy(base); changed["attached_graph"]["budget"]["notifications"].pop()
    expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, changed)
    changed = deepcopy(base)
    duplicate = changed["managed_resources"][7]["resource_id"]
    changed["attached_graph"]["compute"]["instance"]["root_volume_id"] = duplicate
    changed["attached_graph"]["compute"]["root_volume"]["id"] = duplicate
    expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, changed)
    changed = deepcopy(base)
    changed["attached_graph"]["identity"]["terminator_role"]["trust_digest"] = changed["attached_graph"]["identity"]["host_role"]["trust_digest"]
    expect(receipts.ReceiptContractError, receipts.infrastructure_receipt_from_mapping, changed)


def inventory_status_matrix():
    plan_value = plan_fixture()
    infrastructure_value = infrastructure_fixture(plan_value)
    base = inventory_fixture(plan_value, infrastructure_value)
    zero = receipts.inventory_receipt_from_mapping(base)
    require(zero.status is receipts.InventoryStatus.ZERO)

    nonzero_value = deepcopy(base)
    nonzero_value["status"] = "nonzero"
    nonzero_value["reconciliation"]["observations"][0]["disposition"] = "present"
    nonzero_value["reconciliation"]["observations"][0]["observed_attributes_sha256"] = digest("present")
    nonzero = receipts.inventory_receipt_from_mapping(nonzero_value)
    require(nonzero.status is receipts.InventoryStatus.NONZERO)
    checked = receipts.validate_cycle_receipts(
        receipts.plan_receipt_from_mapping(plan_value),
        receipts.infrastructure_receipt_from_mapping(infrastructure_value),
        nonzero,
    )
    require(not checked.zero_proven)
    expect(receipts.ReceiptContractError, receipts.require_zero_inventory, checked)

    uncertain_value = deepcopy(base)
    uncertain_value["status"] = "uncertain"
    uncertain_value["reconciliation"]["observations"][0]["disposition"] = "unknown"
    uncertain_value["uncertainty_reasons"] = ["unknown-disposition"]
    require(receipts.inventory_receipt_from_mapping(uncertain_value).status is receipts.InventoryStatus.UNCERTAIN)

    unexpected_value = deepcopy(base)
    unexpected_value["status"] = "nonzero"
    unexpected_value["reconciliation"]["unexpected_objects"] = [{
        "category": "network_interfaces", "identity": "syn-orphan-eni", "attributes_sha256": digest("orphan-eni"),
    }]
    require(receipts.inventory_receipt_from_mapping(unexpected_value).status is receipts.InventoryStatus.NONZERO)

    delta_value = deepcopy(base)
    delta_value["status"] = "uncertain"
    delta_value["reconciliation"]["baseline_delta"] = [{
        "category": "iam_policy_attachments", "identity": "syn-drift-attachment", "attributes_sha256": digest("drift"),
    }]
    delta_value["uncertainty_reasons"] = ["unexpected-delta"]
    require(receipts.inventory_receipt_from_mapping(delta_value).status is receipts.InventoryStatus.UNCERTAIN)
    wrong_delta = deepcopy(delta_value); wrong_delta["status"] = "nonzero"
    expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, wrong_delta)


def pagination_scope_matrix():
    plan_value = plan_fixture()
    infrastructure_value = infrastructure_fixture(plan_value)
    base = inventory_fixture(plan_value, infrastructure_value)
    for path, replacement in (
        (["observer", "mutation_capable"], True),
        (["observer", "credential_class"], "mutable"),
        (["observer", "identity_commitment"], base["observer"]["operator_commitment"]),
        (["observer", "signature_valid"], False),
        (["scope", "regions"], ["other-region"]),
        (["scope", "partitions"], ["other-partition"]),
        (["scope", "account_commitments"], [digest("other-account")]),
        (["scope", "tag_filters_used"], True),
        (["scope", "name_filters_used"], True),
        (["scope", "categories"], list(receipts.INVENTORY_CATEGORIES[:-1])),
        (["pagination", 0, "category"], "root_volumes"),
        (["pagination", 0, "pages", 0, "ordinal"], 2),
        (["pagination", 0, "pages", 0, "request_token"], "syn-wrong-token"),
        (["pagination", 0, "pages", 0, "response_sha256"], base["pagination"][1]["pages"][0]["response_sha256"]),
        (["pagination", 0, "complete"], False),
        (["pagination", 0, "truncated"], True),
        (["pagination", 0, "error"], "category-failed"),
    ):
        expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, mutate(base, path, replacement))
    missing = deepcopy(base); missing["pagination"].pop()
    expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, missing)
    no_page = deepcopy(base); no_page["pagination"][0]["pages"] = []
    expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, no_page)

    paged = deepcopy(base)
    first = paged["pagination"][0]["pages"][0]
    first["next_token"] = "syn-next-page-token"
    paged["pagination"][0]["pages"].append({
        "ordinal": 2, "request_token": "syn-next-page-token", "next_token": None,
        "response_sha256": digest("second-page"), "item_count": 0,
    })
    receipts.inventory_receipt_from_mapping(paged)
    broken = deepcopy(paged); broken["pagination"][0]["pages"][1]["request_token"] = "syn-other-token"
    expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, broken)

    for error, reasons in (
        ("category-failed", ["category-error", "missing-page"]),
        ("identity-changed", ["identity-mismatch", "missing-page"]),
        ("unsupported", ["missing-page", "scope-unsupported"]),
    ):
        uncertain = deepcopy(base)
        uncertain["status"] = "uncertain"
        uncertain["pagination"][0]["complete"] = False
        uncertain["pagination"][0]["error"] = error
        uncertain["uncertainty_reasons"] = reasons
        receipts.inventory_receipt_from_mapping(uncertain)
    truncated = deepcopy(base)
    truncated["status"] = "uncertain"
    truncated["pagination"][0]["complete"] = False
    truncated["pagination"][0]["truncated"] = True
    truncated["uncertainty_reasons"] = ["missing-page", "truncated-response"]
    receipts.inventory_receipt_from_mapping(truncated)


def reconciliation_matrix():
    plan_value, infrastructure_value, base, plan, infrastructure, _ = valid_set()
    variants = []
    changed = deepcopy(base); changed["reconciliation"]["expected_objects"].pop(); variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["observations"].pop(); variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["expected_objects"][0], changed["reconciliation"]["expected_objects"][1] = changed["reconciliation"]["expected_objects"][1], changed["reconciliation"]["expected_objects"][0]; variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["observations"][0]["identity"] = "syn-other-identity"; variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["observations"][0]["disposition"] = "present"; variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["observations"][0]["observed_attributes_sha256"] = digest("attributes-on-absent"); variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["expected_objects"][0]["parent_identity"] = "not-synthetic"; variants.append(changed)
    changed = deepcopy(base); changed["reconciliation"]["unexpected_objects"] = [{"category": "network_interfaces", "identity": "syn-orphan", "attributes_sha256": digest("orphan")}]; variants.append(changed)
    changed = deepcopy(base); changed["uncertainty_reasons"] = ["missing-page"]; variants.append(changed)
    for changed in variants:
        expect(receipts.ReceiptContractError, receipts.inventory_receipt_from_mapping, changed)

    # A self-consistent but substituted expectation is rejected by cross-receipt lineage.
    changed = deepcopy(base)
    row = changed["reconciliation"]["expected_objects"][0]
    row["expected_attributes_sha256"] = digest("substituted-nested-object")
    substituted = receipts.inventory_receipt_from_mapping(changed)
    expect(receipts.ReceiptContractError, receipts.validate_cycle_receipts, plan, infrastructure, substituted)


def lineage_and_forgery_matrix():
    _, _, _, plan, infrastructure, inventory = valid_set()
    for replacement_value in (
        replace(infrastructure, plan_receipt_sha256=digest("other-plan")),
        replace(infrastructure, semantic_plan_sha256=digest("other-semantic")),
        replace(infrastructure, state_key="syn-other-state"),
    ):
        expect(receipts.ReceiptContractError, receipts.validate_cycle_receipts, plan, replacement_value, inventory)
    for replacement_value in (
        replace(inventory, infrastructure_receipt_sha256=digest("other-infrastructure")),
        replace(inventory, state_lineage_commitment=digest("other-lineage")),
        replace(inventory, destroyed_state_sha256=digest("other-destroyed-state")),
        replace(inventory, observer_commitment=inventory.operator_commitment),
        replace(inventory, canonical=b"{}\n"),
    ):
        expect(receipts.ReceiptContractError, receipts.validate_cycle_receipts, plan, infrastructure, replacement_value)
    expect(receipts.ReceiptContractError, receipts.validate_cycle_receipts, object(), infrastructure, inventory)

    # Cross-cycle, cross-batch, fixture, expiry, and state splices all fail.
    _, _, _, plan2, infrastructure2, inventory2 = valid_set(2, "other-cycle")
    for combination in (
        (plan, infrastructure2, inventory2),
        (plan2, infrastructure, inventory),
        (plan, infrastructure, inventory2),
    ):
        expect(receipts.ReceiptContractError, receipts.validate_cycle_receipts, *combination)


def seven_cycle_freshness_matrix():
    values = []
    mappings = []
    for ordinal in range(1, 8):
        plan_value = plan_fixture(ordinal, "seven-batch")
        infrastructure_value = infrastructure_fixture(plan_value)
        inventory_value = inventory_fixture(plan_value, infrastructure_value)
        plan = receipts.plan_receipt_from_mapping(plan_value)
        infrastructure = receipts.infrastructure_receipt_from_mapping(infrastructure_value)
        inventory = receipts.inventory_receipt_from_mapping(inventory_value)
        values.append(receipts.validate_cycle_receipts(plan, infrastructure, inventory))
        mappings.append((plan_value, infrastructure_value, inventory_value))
    checked = receipts.validate_seven_cycle_receipts(tuple(values))
    require(len(checked) == 7 and all(item.zero_proven for item in checked))
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(values[:-1]))
    reordered = list(values); reordered[0], reordered[1] = reordered[1], reordered[0]
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(reordered))
    replayed = list(values); replayed[1] = replayed[0]
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(replayed))

    plan_value, infrastructure_value, inventory_value = deepcopy(mappings[1])
    inventory_value["observer"]["run_id"] = mappings[0][2]["observer"]["run_id"]
    replayed_inventory = receipts.inventory_receipt_from_mapping(inventory_value)
    replayed_run = list(values)
    replayed_run[1] = receipts.validate_cycle_receipts(values[1].plan, values[1].infrastructure, replayed_inventory)
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(replayed_run))

    duplicate_state_plan = deepcopy(mappings[1][0])
    duplicate_state_plan["state_lineage"]["state_key"] = mappings[0][0]["state_lineage"]["state_key"]
    duplicate_state_plan["state_lineage"]["lineage_commitment"] = mappings[0][0]["state_lineage"]["lineage_commitment"]
    duplicate_state_infrastructure = infrastructure_fixture(duplicate_state_plan)
    duplicate_state_inventory = inventory_fixture(duplicate_state_plan, duplicate_state_infrastructure)
    duplicate_state_set = receipts.validate_cycle_receipts(
        receipts.plan_receipt_from_mapping(duplicate_state_plan),
        receipts.infrastructure_receipt_from_mapping(duplicate_state_infrastructure),
        receipts.inventory_receipt_from_mapping(duplicate_state_inventory),
    )
    replayed_state = list(values); replayed_state[1] = duplicate_state_set
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(replayed_state))

    nonzero_value = deepcopy(mappings[1][2])
    nonzero_value["status"] = "nonzero"
    nonzero_value["reconciliation"]["observations"][0]["disposition"] = "present"
    nonzero_value["reconciliation"]["observations"][0]["observed_attributes_sha256"] = digest("batch-nonzero")
    nonzero_set = receipts.validate_cycle_receipts(
        values[1].plan,
        values[1].infrastructure,
        receipts.inventory_receipt_from_mapping(nonzero_value),
    )
    failed_zero = list(values); failed_zero[1] = nonzero_set
    expect(receipts.ReceiptContractError, receipts.validate_seven_cycle_receipts, tuple(failed_zero))


def static_isolation_matrix():
    source = (ROOT / "deploy/aws-feasibility/completion_campaign_receipts.py").read_text()
    for forbidden in (
        "import subprocess", "import socket", "import boto", "import requests", "import urllib",
        "os.system(", "Popen(", "run_command", "access_key", "secret_key", "provider import",
    ):
        require(forbidden not in source.lower(), forbidden)
    require("production_authorized\"] is False" in source)
    require("def retry" not in source and "def resume" not in source)


def main():
    closed_codec_matrix()
    exact_plan_matrix()
    infrastructure_graph_matrix()
    inventory_status_matrix()
    pagination_scope_matrix()
    reconciliation_matrix()
    lineage_and_forgery_matrix()
    seven_cycle_freshness_matrix()
    static_isolation_matrix()
    print("fake-only completion campaign Slice C exhaustive receipt matrix passed")


if __name__ == "__main__":
    main()

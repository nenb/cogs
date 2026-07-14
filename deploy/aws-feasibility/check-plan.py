#!/usr/bin/env python3
"""Fail-closed structural check for the one-instance Stage 2 saved plan."""

import json
import sys
from collections import Counter
from datetime import datetime, timezone

ALLOWED = {
    "aws_budgets_budget": 1,
    "aws_iam_instance_profile": 1,
    "aws_iam_role": 2,
    "aws_iam_role_policy": 1,
    "aws_iam_role_policy_attachment": 1,
    "aws_instance": 1,
    "aws_internet_gateway": 1,
    "aws_launch_template": 1,
    "aws_route": 1,
    "aws_route_table": 1,
    "aws_route_table_association": 1,
    "aws_scheduler_schedule": 1,
    "aws_security_group": 1,
    "aws_subnet": 1,
    "aws_vpc": 1,
}
FORBIDDEN_WORDS = (
    "autoscaling",
    "eks",
    "eip",
    "elasticache",
    "efs",
    "gpu",
    "lambda",
    "lb",
    "nat_gateway",
    "rds",
    "sagemaker",
    "spot_fleet",
    "vpc_endpoint",
)


def fail(message):
    raise SystemExit(f"unsafe feasibility plan: {message}")


def one(changes, resource_type):
    selected = [change for change in changes if change.get("type") == resource_type]
    if len(selected) != 1:
        fail(f"expected one {resource_type}, found {len(selected)}")
    return selected[0].get("change", {}).get("after") or {}


def main():
    if len(sys.argv) != 2:
        fail("usage: check-plan.py PLAN_JSON")
    with open(sys.argv[1], encoding="utf-8") as source:
        plan = json.load(source)
    expiry_text = plan.get("variables", {}).get("expires_at", {}).get("value", "")
    try:
        expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        fail("expiry is not parseable RFC3339")
    remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
    if not 30 * 60 < remaining < 5 * 60 * 60:
        fail("expiry is not between 30 minutes and five hours from now")

    changes = [change for change in plan.get("resource_changes", []) if change.get("mode") == "managed"]
    counts = Counter(change.get("type") for change in changes)
    if dict(counts) != ALLOWED:
        fail(f"resource counts differ from the exact allowlist: {dict(counts)}")
    for change in changes:
        resource_type = change.get("type", "")
        if any(word in resource_type for word in FORBIDDEN_WORDS):
            fail(f"forbidden resource type {resource_type}")
        actions = change.get("change", {}).get("actions")
        if actions != ["create"]:
            fail(f"{change.get('address')} is not a create-only action")

    launch = one(changes, "aws_launch_template")
    if launch.get("instance_type") != "c8i-flex.large":
        fail("launch template is not c8i-flex.large")
    cpu = launch.get("cpu_options") or []
    if len(cpu) != 1 or cpu[0].get("nested_virtualization") != "enabled":
        fail("launch template does not enable nested virtualization")
    if cpu[0].get("core_count") != 1 or cpu[0].get("threads_per_core") != 2:
        fail("launch template CPU count exceeds the approved two vCPUs")
    interfaces = launch.get("network_interfaces") or []
    if len(interfaces) != 1 or str(interfaces[0].get("associate_public_ip_address")).lower() != "true":
        fail("expected exactly one ephemeral public network interface")
    metadata = launch.get("metadata_options") or []
    if len(metadata) != 1 or metadata[0].get("http_tokens") != "required" or metadata[0].get("http_put_response_hop_limit") != 1:
        fail("IMDSv2 and hop-limit-one are required")
    mappings = launch.get("block_device_mappings") or []
    if len(mappings) != 1:
        fail("expected one root block-device mapping")
    ebs = mappings[0].get("ebs") or []
    if (
        len(ebs) != 1
        or ebs[0].get("volume_size") != 30
        or str(ebs[0].get("encrypted")).lower() != "true"
        or str(ebs[0].get("delete_on_termination")).lower() != "true"
    ):
        fail("root volume is not the approved encrypted disposable 30 GiB volume")

    group = one(changes, "aws_security_group")
    if group.get("ingress") not in (None, []):
        fail("security group contains inbound rules")
    if len(group.get("egress") or []) != 4:
        fail("security group must contain only four declared outbound rules")

    budget = one(changes, "aws_budgets_budget")
    if str(budget.get("limit_amount")) != "20" or budget.get("limit_unit") != "USD":
        fail("campaign budget is not USD 20")
    if len(budget.get("notification") or []) != 3:
        fail("campaign budget does not have three alert thresholds")

    schedule = one(changes, "aws_scheduler_schedule")
    if schedule.get("action_after_completion") != "DELETE" or not str(schedule.get("schedule_expression", "")).startswith("at("):
        fail("independent one-time termination schedule is missing")
    target = schedule.get("target") or []
    if len(target) != 1 or not target[0].get("arn", "").endswith(":ec2:terminateInstances"):
        fail("termination schedule does not target EC2 TerminateInstances")

    print("Verified exact one-instance CPU-only nested-virtualization plan and bounded supporting resources.")


if __name__ == "__main__":
    main()

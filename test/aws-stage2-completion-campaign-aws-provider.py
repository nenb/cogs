#!/usr/bin/env python3
"""Hostile fake-executor checks for the dormant concrete provider boundary."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "deploy/aws-feasibility"))
import completion_campaign_aws_provider as provider
import completion_campaign_production as production


def d(value): return hashlib.sha256(value.encode()).hexdigest()
def raw(value): return provider.canonical(value)


def approval(plan_digests, account):
    value = {
        "version": "cogs.stage2-completion-production-approval/v3",
        "phrase": production.APPROVAL_PHRASE,
        "implementation_revision": "1" * 40, "control_revision": "2" * 40,
        "source_manifest_sha256": d("source"),
        "source_bindings_sha256": d("source-bindings"),
        "static_control_sha256": d("control"),
        "pre_aws_package_sha256": d("preaws"), "rootfs_descriptor_sha256": d("rootfs"),
        "rootfs_package_manifest_sha256": d("rootfs-package"),
        "rootfs_provenance_sha256": d("rootfs-provenance"),
        "rootfs_qualification_receipt_sha256": d("rootfs-qualification"),
        "rootfs_publication_receipt_sha256": d("rootfs-publication"),
        "runtime_commitment": d("runtime"), "fixture_commitment": d("fixture"),
        "provider_binary_sha256": d("provider"), "aws_cli_sha256": d("aws"),
        "account_commitment": hashlib.sha256(account.encode()).hexdigest(),
        "partition": "aws", "region": "us-east-1", "ami_id": "ami-" + "a" * 17,
        "ami_owner_id": "099720109477", "ami_architecture": "x86_64",
        "ami_virtualization_type": "hvm", "ami_root_device_type": "ebs",
        "ami_state": "available", "plan_sha256s": tuple(plan_digests),
        "not_before_unix_ns": 1, "effect_deadline_ns": 90 * 60 * 10**9,
        "cleanup_reserve_ns": 10 * 60 * 10**9,
        "expires_unix_ns": 2_000_000_000_000_000_000,
        "maximum_cycle_duration_ns": 10 * 60 * 10**9,
        "maximum_cost_micro_usd": 499_999,
        "rate_source_commitment": production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": d("issuer"),
        "executor_principal_commitment": production.executor_principal_commitment(
            "aws", account, "executor"),
        "inventory_observer_principal_commitment":
            production.executor_principal_commitment("aws", account, "observer"),
        "one_attempt": True,
    }
    value["ami_commitment"] = production.resolved_ami_commitment(value)
    value["batch_commitment"] = production.approval_batch_commitment(value)
    return production.ProductionApproval(**value)


def grant(current, ordinal):
    fields = {
        "batch_commitment": current.batch_commitment, "ordinal": ordinal,
        "mode": production.CYCLE_MODES[ordinal - 1],
        "implementation_revision": current.implementation_revision,
        "control_revision": current.control_revision,
        "static_control_sha256": current.static_control_sha256,
        "rootfs_descriptor_sha256": current.rootfs_descriptor_sha256,
        "ami_commitment": current.ami_commitment,
        "plan_sha256": current.plan_sha256s[ordinal - 1],
    }
    return production.CycleLaunchGrant(**fields, grant_commitment=production._commit(
        b"cogs.stage2-cycle-launch-grant/v1", fields))


class Fake:
    def __init__(self, account): self.account = account; self.calls = []
    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv[0] == str(provider.TOFU) and "show" in argv:
            return provider.Completed(Path(argv[-1]).with_name("campaign.plan.json").read_bytes())
        if "get-caller-identity" in argv:
            role = "observer" if "observer" in argv else "executor"
            return provider.Completed(raw({"Account": self.account,
                "Arn": f"arn:aws:iam::000000000000:role/{role}",
                "UserId": "session:test"}))
        if argv[0] == str(provider.AWS):
            # Force a real two-page chain for EIP coverage. Both pages contain
            # unrelated account resources, which may not be relabelled campaign residue.
            if "describe-instances" in argv:
                return provider.Completed(raw({"Reservations": [{"Instances": [{
                    "InstanceId": f"i-{1:017x}", "State": {"Name": "terminated"}}]}]}))
            if "describe-addresses" in argv and "--starting-token" not in argv:
                return provider.Completed(raw({"Addresses": [{"AllocationId": "eipalloc-unrelated",
                    "PublicIp": "192.0.2.1", "Tags": []}], "NextToken": "opaque"}))
            if "describe-addresses" in argv:
                return provider.Completed(raw({"Addresses": []}))
            if "describe-network-interfaces" in argv:
                return provider.Completed(raw({"NetworkInterfaces": [{
                    "NetworkInterfaceId": "eni-unrelated", "VpcId": "vpc-unrelated",
                    "Association": {"PublicIp": "198.51.100.2"}, "TagSet": []}]}))
            return provider.Completed(raw({}))
        return provider.Completed(b"checked\n")


os.umask(0o077)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    provider.ROOT = root
    provider.APPROVAL = root / "approval.json"
    provider.BUDGET_EMAIL = root / "budget-alert-email.txt"
    provider.STATE_ROOT = root / "provider-state"
    provider.AWS = root / "aws"
    provider.TOFU = root / "tofu"
    provider.TOFU_PROVIDER = root / "terraform-provider-aws_v6.54.0_x5"
    provider.TOFU_SHA256 = d("tofu")
    root.mkdir(exist_ok=True)
    account = "000000000000"
    provider.AWS.write_bytes(b"aws"); provider.AWS.chmod(0o700)
    provider.TOFU.write_bytes(b"tofu"); provider.TOFU.chmod(0o700)
    provider.TOFU_PROVIDER.write_bytes(b"provider"); provider.TOFU_PROVIDER.chmod(0o700)
    plan_bytes = b"reviewed-plan-bytes"
    plans = [hashlib.sha256(plan_bytes if index == 1 else f"plan-{index}".encode()).hexdigest()
             for index in range(1, 8)]
    current = approval(plans, account)
    provider.APPROVAL.write_bytes(raw({**current.__dict__, "plan_sha256s": list(current.plan_sha256s)}))
    provider.BUDGET_EMAIL.write_text("owner@example.invalid\n")
    fake = Fake(account)
    approval_stat = provider.APPROVAL.stat()
    approval_identity = (stat.S_IMODE(approval_stat.st_mode), approval_stat.st_uid,
                         approval_stat.st_nlink, approval_stat.st_size)
    assert approval_identity == (0o600, os.geteuid(), 1,
                                 approval_stat.st_size), approval_identity
    boundary = provider.FixedProvider(fake)

    grants = {}
    for ordinal in (1, 2, 7):
        cycle = provider.STATE_ROOT / f"cycle-{ordinal}"; cycle.mkdir(parents=True)
        item = grant(current, ordinal); grants[ordinal] = item
        (cycle / "grant.json").write_bytes(raw({"version": "cogs.stage2-cycle-launch-grant/v1",
                                                **item.__dict__}))
        (cycle / "campaign-output.json").write_bytes(raw({
            "region": current.region, "batch_commitment": current.batch_commitment,
            "cycle_ordinal": ordinal, "instance_id": f"i-{ordinal:017x}",
            "ami_id": current.ami_id, "ami_commitment": current.ami_commitment,
            "source_revision": current.implementation_revision,
            "control_revision": current.control_revision,
            "rootfs_descriptor_sha256": current.rootfs_descriptor_sha256,
            "launch_template_id": f"lt-{ordinal:017x}", "launch_template_version": ordinal,
            "root_volume_id": f"vol-{ordinal:017x}", "primary_eni_id": f"eni-{ordinal:017x}"}))
    cycle1 = provider.STATE_ROOT / "cycle-1"
    (cycle1 / "campaign.tfplan").write_bytes(plan_bytes)
    plan_variables = {
        key: {"value": value} for key, value in {
            "ami_id": current.ami_id, "ami_owner_id": current.ami_owner_id,
            "ami_commitment": current.ami_commitment,
            "batch_commitment": current.batch_commitment, "cycle_ordinal": 1,
            "source_revision": current.implementation_revision,
            "control_revision": current.control_revision,
            "rootfs_descriptor_sha256": current.rootfs_descriptor_sha256,
            "account_id_sha256": current.account_commitment,
            "aws_region": current.region,
        }.items()}
    (cycle1 / "campaign.plan.json").write_bytes(raw({
        "variables": plan_variables,
        "resource_changes": [{"address": "aws_launch_template.host",
                              "change": {"after": {"image_id": current.ami_id}}}]}))

    receipt_value = json.loads(boundary.effect(
        "plan", 1, "full", grants[1].grant_commitment, d("intent")))
    receipt_value["resource_commitments"] = tuple(
        tuple(row) for row in receipt_value["resource_commitments"])
    receipt = production.EffectReceipt(**receipt_value)
    assert receipt.kind == "plan" and receipt.identity_commitment == plans[0]
    try:
        boundary.effect("plan", 1, "full", grants[1].grant_commitment, d("second"))
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("effect replay was accepted")

    inventory_call_start = len(fake.calls)
    inventory_value = json.loads(boundary.inventory(1, grants[1].grant_commitment,
                                                     receipt.state_commitment))
    pages = inventory_value["pages"]
    assert {row["category"] for row in pages} == set(production.INVENTORY_CATEGORIES)
    assert len([row for row in pages if row["category"] == "elastic_ips"]) == 2
    for category in ("network_interfaces", "eni_public_associations", "elastic_ips"):
        assert all("account-region-wide" in row["query_scope"]
                   for row in pages if row["category"] == category)
    assert all(row["response_commitment"] != "0" * 64 for row in pages)
    instance_rows = [resource for page in pages if page["category"] == "ec2_instances"
                     for resource in page["resources"]]
    assert len(instance_rows) == 1 and instance_rows[0]["disposition"] == "deleted"
    inventory_aws_calls = [call for call, _ in fake.calls[inventory_call_start:]
                           if call[0] == str(provider.AWS)]
    assert inventory_aws_calls and all("observer" in call for call in inventory_aws_calls)
    calls_after_inventory = len(fake.calls)
    assert json.loads(boundary.inventory(1, grants[1].grant_commitment,
                                         receipt.state_commitment)) == inventory_value
    assert len(fake.calls) == calls_after_inventory

    # A claimed normal destroy is uncertain and may never be reissued by cleanup.
    cycle2 = provider.STATE_ROOT / "cycle-2"
    (cycle2 / "destroy.intent.json").write_bytes(raw({"claimed": True}))
    before = len([call for call, _ in fake.calls if call[0] == str(provider.TOFU)])
    cleanup = json.loads(boundary.recover(2, "readiness", grants[2].grant_commitment,
                                          d("state-2")))
    after = len([call for call, _ in fake.calls if call[0] == str(provider.TOFU)])
    assert cleanup["normal_destroy_reissued"] is False and cleanup["certain_zero"] is True
    assert after == before + 1
    cleanup_commands = [call for call, _ in fake.calls if call[0] == str(provider.TOFU)
                        and "destroy" in call]
    assert len(cleanup_commands) == 1
    second_cleanup = json.loads(boundary.recover(
        2, "readiness", grants[2].grant_commitment, d("state-2")))
    assert second_cleanup["certain_zero"] is True
    assert len([call for call, _ in fake.calls if call[0] == str(provider.TOFU)
                and "destroy" in call]) == 1

    # Cross-cycle and caller-selected authority are rejected before a command.
    try: boundary.inventory(8, grants[1].grant_commitment, d("state"))
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("caller-selected final grant accepted")

print("stage2 provider-free concrete AWS boundary checks passed")

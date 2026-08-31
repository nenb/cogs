#!/usr/bin/env python3
"""Fixed future AWS/OpenTofu boundary for the dormant production campaign.

The module is inert on import.  Its CLI is reachable only through the four fixed
root-owned wrappers beside it.  Tests use ``FixedProvider`` with a fake runner;
no test needs credentials, a provider binary, SSM, or an inventory service.
"""

from __future__ import annotations

from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Callable

import completion_campaign_production as production
import completion_campaign_remote_adapter as remote_adapter

ROOT = Path("/var/lib/cogs/stage2-aws-production-v2")
SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
TOFU = Path("/var/lib/cogs/stage2-completion-v1/tool/opentofu-1.12.4")
AWS = Path("/usr/local/bin/aws")
PYTHON = Path("/usr/bin/python3")
APPROVAL = ROOT / "approval.json"
BUDGET_EMAIL = ROOT / "budget-alert-email.txt"
STATE_ROOT = ROOT / "provider-state"
MAX_OUTPUT = 32 * 1024 * 1024
ZERO = "0" * 64
ENV = {
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "TZ": "UTC",
    "AWS_PROFILE": "nebula",
    "AWS_REGION": "us-east-1",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_PAGER": "",
}


class ProviderBoundaryError(RuntimeError):
    pass


def _require(condition: bool, message: str = "fixed provider boundary rejected input") -> None:
    if not condition:
        raise ProviderBoundaryError(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _pairs(rows):
    result = {}
    for key, value in rows:
        _require(type(key) is str and key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw: bytes, maximum: int = MAX_OUTPUT) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n")
             and b"\r" not in raw, "non-canonical provider JSON")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ProviderBoundaryError("invalid provider JSON") from error
    _require(type(value) is dict and canonical(value) == raw, "non-canonical provider JSON")
    return value


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + b"\0" + canonical(value)[:-1]).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _write_once(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        _require(os.write(descriptor, raw) == len(raw), "short durable write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read(path: Path, maximum: int = MAX_OUTPUT) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= maximum, "unsafe custody file")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns), "custody file changed while read")
        return raw
    finally:
        os.close(descriptor)


class Completed:
    """Small subprocess-compatible result used by provider-free fake runners."""
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


Runner = Callable[[tuple[str, ...], int], Completed]


def subprocess_runner(argv: tuple[str, ...], timeout: int) -> Completed:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=SOURCE, env=ENV,
                            timeout=timeout, check=False)
    return Completed(result.stdout, result.stderr, result.returncode)


INVENTORY_QUERIES = (
    ("ec2_instances", "ec2", "describe-instances", "campaign-graph"),
    ("ebs_volumes", "ec2", "describe-volumes", "campaign-graph"),
    ("network_interfaces", "ec2", "describe-network-interfaces", "account-region-wide"),
    ("eni_public_associations", "ec2", "describe-network-interfaces", "account-region-wide-public-address"),
    ("elastic_ips", "ec2", "describe-addresses", "account-region-wide-public-address"),
    ("security_groups", "ec2", "describe-security-groups", "campaign-graph"),
    ("vpcs", "ec2", "describe-vpcs", "campaign-graph"),
    ("subnets", "ec2", "describe-subnets", "campaign-graph"),
    ("internet_gateways", "ec2", "describe-internet-gateways", "campaign-graph"),
    ("route_tables", "ec2", "describe-route-tables", "campaign-graph"),
    ("routes", "ec2", "describe-route-tables", "campaign-graph"),
    ("launch_templates", "ec2", "describe-launch-templates", "campaign-graph"),
    ("key_pairs", "ec2", "describe-key-pairs", "campaign-graph"),
    ("iam_roles", "iam", "list-roles", "account-wide-campaign-prefix"),
    ("iam_role_policies", "iam", "list-roles", "account-wide-campaign-prefix"),
    ("iam_policy_attachments", "iam", "list-roles", "account-wide-campaign-prefix"),
    ("iam_instance_profiles", "iam", "list-instance-profiles", "account-wide-campaign-prefix"),
    ("eventbridge_schedules", "scheduler", "list-schedules", "account-region-wide-campaign-prefix"),
    ("eventbridge_targets", "scheduler", "list-schedules", "account-region-wide-campaign-prefix"),
    ("budgets", "budgets", "describe-budgets", "account-wide-campaign-prefix"),
    ("ssm_managed_instances", "ssm", "describe-instance-information", "account-region-wide-related-instance"),
)
assert tuple(row[0] for row in INVENTORY_QUERIES) == production.INVENTORY_CATEGORIES


class FixedProvider:
    """Concrete command owner. Paths and command families are compile-time constants."""

    def __init__(self, runner: Runner = subprocess_runner):
        _require(callable(runner))
        self.runner = runner
        self.approval = self._approval()

    def _approval(self) -> production.ProductionApproval:
        value = decode(_read(APPROVAL, 64 * 1024), 64 * 1024)
        value["plan_sha256s"] = tuple(value["plan_sha256s"])
        return production.ProductionApproval(**value)

    def _cycle(self, ordinal: int, mode: str, grant_commitment: str):
        _require(type(ordinal) is int and 1 <= ordinal <= 7
                 and mode == production.CYCLE_MODES[ordinal - 1])
        production._digest(grant_commitment)
        directory = STATE_ROOT / f"cycle-{ordinal}"
        grant = decode(_read(directory / "grant.json", 64 * 1024), 64 * 1024)
        _require(grant.get("version") == "cogs.stage2-cycle-launch-grant/v1")
        grant.pop("version")
        parsed = production.CycleLaunchGrant(**grant)
        _require(parsed.grant_commitment == grant_commitment
                 and parsed.batch_commitment == self.approval.batch_commitment
                 and parsed.mode == mode and parsed.ordinal == ordinal
                 and parsed.ami_commitment == self.approval.ami_commitment
                 and parsed.plan_sha256 == self.approval.plan_sha256s[ordinal - 1])
        return directory, parsed

    def _run(self, argv: tuple[str, ...], timeout: int, json_output: bool = False):
        _require(type(argv) is tuple and argv and all(type(item) is str for item in argv)
                 and argv[0] in {str(TOFU), str(AWS), str(PYTHON)})
        result = self.runner(argv, timeout)
        _require(type(result) is Completed and result.returncode == 0
                 and len(result.stdout) <= MAX_OUTPUT and len(result.stderr) <= 64 * 1024,
                 "fixed provider command failed")
        if json_output:
            raw = result.stdout if result.stdout.endswith(b"\n") else result.stdout + b"\n"
            return decode(raw)
        return result.stdout

    def _claim(self, directory: Path, name: str, intent: str) -> Path:
        production._digest(intent)
        claim = directory / f"{name}.intent.json"
        _write_once(claim, canonical({
            "version": "cogs.stage2-provider-invocation-intent/v1",
            "operation": name, "intent_commitment": intent, "invocation_count": 1,
        }))
        return claim

    def _common(self, directory: Path, grant, kind: str, intent: str,
                started: int, ended: int, identity: str, state_digest: str):
        lineage = _digest(b"cogs.stage2-provider-state-lineage/v1", {
            "batch_commitment": grant.batch_commitment,
            "ordinal": grant.ordinal,
            "state_slot": f"cycle-{grant.ordinal}",
        })
        fields = {
            "kind": kind, "grant_commitment": grant.grant_commitment,
            "batch_commitment": grant.batch_commitment, "ordinal": grant.ordinal,
            "mode": grant.mode,
            "state_commitment": _digest(b"cogs.stage2-provider-state-slot/v1", {
                "batch_commitment": grant.batch_commitment, "ordinal": grant.ordinal}),
            "state_lineage_commitment": lineage, "identity_commitment": identity,
            "intent_commitment": intent, "ami_commitment": grant.ami_commitment,
            "observed_started_unix_ns": started,
            "observed_ended_unix_ns": ended, "invocation_count": 1,
            "certain": True,
        }
        fields["settlement_commitment"] = _digest(
            b"cogs.stage2-provider-effect-settlement/v1",
            {**fields, "state_bytes_sha256": state_digest})
        receipt = production.EffectReceipt(**fields)
        _write_once(directory / f"{kind}.receipt.json", canonical(asdict(receipt)))
        return receipt

    def _validate_plan_bindings(self, path: Path, grant) -> None:
        raw = _read(path)
        try:
            value = json.loads(raw, object_pairs_hook=_pairs,
                               parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise ProviderBoundaryError("invalid approved plan JSON") from error
        variables = value.get("variables", {})
        expected = {
            "ami_id": self.approval.ami_id,
            "ami_owner_id": self.approval.ami_owner_id,
            "ami_commitment": self.approval.ami_commitment,
            "batch_commitment": self.approval.batch_commitment,
            "cycle_ordinal": grant.ordinal,
            "source_revision": self.approval.implementation_revision,
            "control_revision": self.approval.control_revision,
            "rootfs_descriptor_sha256": self.approval.rootfs_descriptor_sha256,
            "account_id_sha256": self.approval.account_commitment,
            "aws_region": self.approval.region,
        }
        _require(all(variables.get(key, {}).get("value") == item
                     for key, item in expected.items()),
                 "approved plan common binding mismatch")
        launch = [row for row in value.get("resource_changes", [])
                  if row.get("address") == "aws_launch_template.host"]
        _require(len(launch) == 1 and
                 launch[0].get("change", {}).get("after", {}).get("image_id") ==
                 self.approval.ami_id, "approved plan AMI mismatch")

    def _tfvars(self, directory: Path, grant) -> None:
        email = _read(BUDGET_EMAIL, 1024).decode("ascii").strip()
        _require(3 <= len(email) <= 254 and "@" in email and "\n" not in email)
        expiry_seconds = self.approval.expires_unix_ns // 1_000_000_000
        expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expiry_seconds))
        value = {
            "aws_profile": "nebula", "aws_region": self.approval.region,
            "ami_id": self.approval.ami_id, "ami_owner_id": self.approval.ami_owner_id,
            "ami_commitment": self.approval.ami_commitment,
            "batch_commitment": self.approval.batch_commitment,
            "cycle_ordinal": grant.ordinal,
            "source_revision": self.approval.implementation_revision,
            "control_revision": self.approval.control_revision,
            "rootfs_descriptor_sha256": self.approval.rootfs_descriptor_sha256,
            "expires_at": expiry, "budget_alert_email": email,
            "account_id_sha256": self.approval.account_commitment,
        }
        path = directory / "campaign.auto.tfvars.json"
        if path.exists():
            _require(decode(_read(path)) == value, "cycle variables changed")
        else:
            _write_once(path, canonical(value))

    def effect(self, kind: str, ordinal: int, mode: str,
               grant_commitment: str, intent: str) -> bytes:
        _require(kind in production.EFFECT_KINDS)
        directory, grant = self._cycle(ordinal, mode, grant_commitment)
        receipt_path = directory / f"{kind}.receipt.json"
        _require(not receipt_path.exists(), "effect receipt replay")
        self._claim(directory, kind, intent)
        self._tfvars(directory, grant)
        state = directory / "terraform.tfstate"
        plan = directory / "campaign.tfplan"
        plan_json = directory / "campaign.plan.json"
        started = time.time_ns()
        if kind == "plan":
            _require(plan.is_file() and plan_json.is_file()
                     and _sha256_file(plan) == grant.plan_sha256,
                     "approved plan bytes missing or changed")
            self._run((str(PYTHON), str(SOURCE / "deploy/aws-feasibility/check-plan.py"),
                       str(plan_json)), 30)
            self._validate_plan_bindings(plan_json, grant)
            identity = grant.plan_sha256
        elif kind == "apply":
            _require((directory / "plan.receipt.json").is_file())
            self._run((str(TOFU), f"-chdir={SOURCE / 'deploy/aws-feasibility'}",
                       "apply", "-input=false", "-lock-timeout=30s",
                       "-auto-approve", str(plan)), 900)
            output = self._run((str(TOFU), f"-chdir={SOURCE / 'deploy/aws-feasibility'}",
                                "output", "-state=" + str(state), "-json", "campaign"),
                               60, True)
            self._validate_campaign_output(output, grant)
            _write_once(directory / "campaign-output.json", canonical(output))
            identity = _digest(b"cogs.stage2-applied-graph/v1", output)
        elif kind == "running":
            output = decode(_read(directory / "campaign-output.json"))
            self._validate_campaign_output(output, grant)
            instance = output["instance_id"]
            self._run((str(AWS), "--region", self.approval.region, "ec2", "wait",
                       "instance-running", "--instance-ids", instance), 660)
            observed = self._run((str(AWS), "--region", self.approval.region, "ec2",
                                  "describe-instances", "--instance-ids", instance,
                                  "--output", "json", "--no-cli-pager"), 60, True)
            row = observed["Reservations"][0]["Instances"][0]
            _require(row.get("InstanceId") == instance and row.get("ImageId") == self.approval.ami_id
                     and row.get("State", {}).get("Name") == "running")
            identity = _digest(b"cogs.stage2-running-instance/v1", {
                "instance_id": instance, "image_id": row["ImageId"],
                "root_device": row.get("RootDeviceName"),
                "primary_eni": row.get("NetworkInterfaces", [{}])[0].get("NetworkInterfaceId"),
                "launch_template": row.get("LaunchTemplate"),
            })
            _write_once(directory / "running-observation.json", canonical(observed))
        else:
            _require((directory / "running.receipt.json").is_file())
            self._run((str(TOFU), f"-chdir={SOURCE / 'deploy/aws-feasibility'}",
                       "destroy", "-state=" + str(state), "-auto-approve",
                       "-input=false", "-lock-timeout=30s",
                       "-var-file=" + str(directory / "campaign.auto.tfvars.json")), 900)
            identity = _digest(b"cogs.stage2-destroyed-state/v1", {
                "state_sha256": _sha256_file(state), "ordinal": ordinal})
        ended = time.time_ns()
        _require(ended > started)
        state_digest = _sha256_file(state) if state.exists() else ZERO
        return canonical(asdict(self._common(directory, grant, kind, intent,
                                             started, ended, identity, state_digest)))

    def _validate_campaign_output(self, value: dict, grant) -> None:
        required = {"region", "batch_commitment", "cycle_ordinal", "instance_id",
                    "ami_id", "ami_commitment", "source_revision", "control_revision",
                    "rootfs_descriptor_sha256", "launch_template_id",
                    "launch_template_version", "root_volume_id", "primary_eni_id"}
        _require(required <= set(value)
                 and value["region"] == self.approval.region
                 and value["batch_commitment"] == grant.batch_commitment
                 and value["cycle_ordinal"] == grant.ordinal
                 and value["ami_id"] == self.approval.ami_id
                 and value["ami_commitment"] == self.approval.ami_commitment
                 and value["source_revision"] == self.approval.implementation_revision
                 and value["control_revision"] == self.approval.control_revision
                 and value["rootfs_descriptor_sha256"] == self.approval.rootfs_descriptor_sha256)

    def remote(self, ordinal: int, mode: str, grant_commitment: str) -> bytes:
        directory, grant = self._cycle(ordinal, mode, grant_commitment)
        output = decode(_read(directory / "campaign-output.json"))
        self._validate_campaign_output(output, grant)
        claim = _digest(b"cogs.stage2-remote-invocation-intent/v1", {
            "grant": grant.grant_commitment, "instance": output["instance_id"]})
        self._claim(directory, "remote", claim)
        grant_raw = _read(directory / "grant.json", 64 * 1024)
        command = remote_adapter.invocation(grant).command
        encoded = base64.b64encode(grant_raw).decode("ascii")
        remote_shell = (
            "set -eu; umask 077; d=/var/lib/cogs/stage2-completion-v1/"
            "cycle-authority-v1; install -d -m 700 \"$d\"; "
            f"printf '%s' '{encoded}' | base64 -d >\"$d/grant.json\"; "
            "chmod 400 \"$d/grant.json\"; " + command)
        parameters = directory / "ssm-parameters.json"
        _write_once(parameters, canonical({"commands": [remote_shell]}))
        sent = self._run((str(AWS), "--region", self.approval.region, "ssm",
                          "send-command", "--instance-ids", output["instance_id"],
                          "--document-name", "AWS-RunShellScript", "--timeout-seconds", "7800",
                          "--parameters", "file://" + str(parameters), "--output", "json",
                          "--no-cli-pager"), 60, True)
        command_id = sent.get("Command", {}).get("CommandId")
        _require(type(command_id) is str and 8 <= len(command_id) <= 128)
        self._run((str(AWS), "--region", self.approval.region, "ssm", "wait",
                   "command-executed", "--command-id", command_id,
                   "--instance-id", output["instance_id"]), 7800)
        observed = self._run((str(AWS), "--region", self.approval.region, "ssm",
                              "get-command-invocation", "--command-id", command_id,
                              "--instance-id", output["instance_id"], "--output", "json",
                              "--no-cli-pager"), 60, True)
        _require(observed.get("Status") == "Success" and not observed.get("StandardErrorContent"))
        raw = observed.get("StandardOutputContent", "").encode("ascii")
        _require(raw.endswith(b"\n") and len(raw) <= remote_adapter.MAX_RECEIPT_BYTES)
        _write_once(directory / "remote-owner-receipt.json", raw, 0o400)
        return raw

    def _api_pages(self, service: str, operation: str, account_id: str):
        token = None
        seen = set()
        while True:
            argv = [str(AWS), "--region", self.approval.region, service, operation,
                    "--output", "json", "--no-cli-pager", "--max-items", "100"]
            if service == "budgets": argv.extend(("--account-id", account_id))
            if token is not None: argv.extend(("--starting-token", token))
            response = self._run(tuple(argv), 120, True)
            returned = response.get("NextToken")
            _require(returned is None or (type(returned) is str and returned and returned not in seen))
            yield token, returned, response
            if returned is None: break
            seen.add(returned); token = returned

    @staticmethod
    def _walk(value):
        if type(value) is dict:
            yield value
            for child in value.values(): yield from FixedProvider._walk(child)
        elif type(value) is list:
            for child in value: yield from FixedProvider._walk(child)

    @staticmethod
    def _tags(row):
        tags = row.get("Tags", row.get("tags", []))
        return {item.get("Key"): item.get("Value") for item in tags
                if type(item) is dict and type(item.get("Key")) is str}

    def _resource_rows(self, category: str, response: dict, grant, graph: dict):
        ids = {value for key, value in graph.items() if key.endswith("_id") and type(value) is str}
        keys = ("InstanceId", "VolumeId", "NetworkInterfaceId", "AllocationId", "GroupId",
                "VpcId", "SubnetId", "InternetGatewayId", "RouteTableId", "LaunchTemplateId",
                "KeyPairId", "RoleId", "InstanceProfileId", "ScheduleArn", "BudgetName")
        rows = []
        for item in self._walk(response):
            identity = next((item.get(key) for key in keys if type(item.get(key)) is str), None)
            name = next((item.get(key) for key in ("RoleName", "InstanceProfileName", "Name")
                         if type(item.get(key)) is str), None)
            tags = self._tags(item)
            related = (tags.get("cogs:batch") == grant.batch_commitment
                       or identity in ids or (name is not None and name.startswith("cogs-s2-")))
            public = None
            if category in {"network_interfaces", "eni_public_associations"}:
                public = item.get("Association", {}).get("PublicIp")
                if category == "eni_public_associations" and public is None: continue
                related = related or any(value in ids for value in (
                    item.get("VpcId"), item.get("SubnetId"), item.get("Attachment", {}).get("InstanceId")))
            elif category == "elastic_ips":
                public = item.get("PublicIp")
                related = related or item.get("InstanceId") in ids or item.get("NetworkInterfaceId") in ids
            if not related: continue
            identity_value = identity or name or _digest(b"cogs.stage2-inventory-row/v1", item)
            rows.append(production.InventoryResource(
                category,
                _digest(b"cogs.stage2-inventory-resource-identity/v1", {"value": identity_value}),
                "unexpected-live",
                None if public is None else _digest(
                    b"cogs.stage2-public-address/v1", {"address": public}),
            ))
        return tuple(rows)

    def inventory(self, sequence: int, grant_commitment: str,
                  destroyed_state_commitment: str) -> bytes:
        _require(type(sequence) is int and 1 <= sequence <= 8)
        production._digest(destroyed_state_commitment)
        ordinal = sequence if sequence <= 7 else 7
        directory, grant = self._cycle(ordinal, production.CYCLE_MODES[ordinal - 1],
                                       (grant_commitment if sequence <= 7 else
                                        decode(_read(STATE_ROOT / "cycle-7/grant.json"))["grant_commitment"]))
        if sequence == 8: _require(grant_commitment == "final")
        claim = _digest(b"cogs.stage2-inventory-intent/v1", {
            "batch": grant.batch_commitment, "sequence": sequence,
            "destroyed_state": destroyed_state_commitment})
        inventory_dir = ROOT / "inventory" / f"observation-{sequence}"
        self._claim(inventory_dir, "inventory", claim)
        started = time.time_ns()
        caller = self._run((str(AWS), "--region", self.approval.region, "sts",
                            "get-caller-identity", "--output", "json", "--no-cli-pager"), 60, True)
        account_id = caller.get("Account"); arn = caller.get("Arn"); user_id = caller.get("UserId")
        _require(type(account_id) is str and len(account_id) == 12 and account_id.isdigit()
                 and hashlib.sha256(account_id.encode()).hexdigest() == self.approval.account_commitment
                 and type(arn) is str and type(user_id) is str)
        graph = decode(_read(directory / "campaign-output.json"))
        pages = []
        response_commitments = []
        for category, service, operation, scope in INVENTORY_QUERIES:
            for page_ordinal, (requested, returned, response) in enumerate(
                    self._api_pages(service, operation, account_id), 1):
                response_commitment = _digest(b"cogs.stage2-inventory-api-response/v1", response)
                resources = self._resource_rows(category, response, grant, graph)
                value = {
                    "category": category, "service": service, "operation": operation,
                    "query_scope": scope, "ordinal": page_ordinal,
                    "request_token_commitment": (None if requested is None else _digest(
                        b"cogs.stage2-inventory-request-token/v1", {"token": requested})),
                    "next_token_commitment": (None if returned is None else _digest(
                        b"cogs.stage2-inventory-request-token/v1", {"token": returned})),
                    "response_commitment": response_commitment,
                    "resources": [asdict(item) for item in resources],
                }
                page_commitment = production._commit(b"cogs.stage2-inventory-page/v2", value)
                constructor = dict(value); constructor["resources"] = resources
                try:
                    pages.append(production.InventoryPage(**constructor,
                                                          page_commitment=page_commitment))
                except production.ProductionCampaignError as error:
                    raise ProviderBoundaryError(f"invalid {category} inventory page") from error
                response_commitments.append(response_commitment)
        ended = time.time_ns(); _require(ended > started)
        fields = {
            "batch_commitment": self.approval.batch_commitment,
            "observation_sequence": sequence,
            "cycle_ordinal": sequence if sequence <= 7 else None,
            "observer_commitment": _digest(b"cogs.stage2-inventory-observer/v1", {"arn": arn}),
            "session_commitment": _digest(b"cogs.stage2-inventory-session/v1", {
                "user_id": user_id, "sequence": sequence, "started": started}),
            "run_commitment": _digest(b"cogs.stage2-inventory-run/v1", {
                "responses": response_commitments, "sequence": sequence}),
            "account_commitment": self.approval.account_commitment,
            "region": self.approval.region,
            "destroyed_state_commitment": destroyed_state_commitment,
            "observed_started_unix_ns": started, "observed_ended_unix_ns": ended,
            "pages": tuple(pages), "certain": True,
        }
        zero_source = {key: value for key, value in fields.items() if key not in {"pages", "certain"}}
        zero_source["page_commitments"] = [item.page_commitment for item in pages]
        fields["zero_commitment"] = production._commit(b"cogs.stage2-zero-inventory/v2", zero_source)
        receipt = production.InventoryReceipt(**fields)
        raw = canonical({**asdict(receipt), "pages": [asdict(item) for item in receipt.pages]})
        _write_once(inventory_dir / "inventory.receipt.json", raw, 0o400)
        return raw

    def recover(self, ordinal: int, mode: str, grant_commitment: str,
                state_commitment: str) -> bytes:
        directory, grant = self._cycle(ordinal, mode, grant_commitment)
        production._digest(state_commitment)
        # Recovery never calls ``effect`` and never reissues a claimed normal destroy.
        destroy_claimed = (directory / "destroy.intent.json").exists()
        reconcile = directory / "cleanup-reconciliation.intent.json"
        _write_once(reconcile, canonical({
            "version": "cogs.stage2-cleanup-reconciliation-intent/v1",
            "grant_commitment": grant.grant_commitment,
            "state_commitment": state_commitment,
            "normal_destroy_reissued": False,
            "destroy_was_previously_claimed": destroy_claimed,
        }))
        certain = False
        inventory = None
        # Cleanup uses its own durable authority and invocation name.  This is
        # not a second normal destroy settlement: even after an ambiguous normal
        # destroy, only this cleanup-only transition may reconcile remaining state.
        cleanup_claim = directory / "cleanup-destroy.invocation.json"
        if not cleanup_claim.exists():
            _write_once(cleanup_claim, canonical({"invocation_count": 1,
                "grant_commitment": grant.grant_commitment,
                "normal_destroy_was_ambiguous": destroy_claimed,
                "cleanup_only": True}))
            state = directory / "terraform.tfstate"
            self._run((str(TOFU), f"-chdir={SOURCE / 'deploy/aws-feasibility'}",
                       "destroy", "-state=" + str(state), "-auto-approve", "-input=false",
                       "-lock-timeout=30s", "-var-file=" +
                       str(directory / "campaign.auto.tfvars.json")), 1200)
        try:
            raw = self.inventory(ordinal, grant.grant_commitment, state_commitment)
            value = decode(raw); page_values = value.pop("pages")
            parsed_pages = []
            for row in page_values:
                resources = tuple(production.InventoryResource(**item) for item in row.pop("resources"))
                parsed_pages.append(production.InventoryPage(**row, resources=resources))
            inventory = production.InventoryReceipt(**value, pages=tuple(parsed_pages))
            certain = True
        except BaseException:
            certain = False
        fields = {
            "grant_commitment": grant.grant_commitment,
            "state_commitment": state_commitment,
            "reconciliation_commitment": _digest(b"cogs.stage2-cleanup-reconciliation/v1", {
                "grant": grant.grant_commitment, "state": state_commitment,
                "destroy_was_previously_claimed": destroy_claimed,
                "inventory": None if inventory is None else inventory.zero_commitment}),
            "inventory": None if inventory is None else asdict(inventory),
            "normal_destroy_reissued": False, "certain_zero": certain,
        }
        return canonical(fields)


def _usage() -> None:
    raise ProviderBoundaryError("fixed wrapper argument mismatch")


def main(argv: tuple[str, ...] | None = None) -> None:
    args = tuple(sys.argv[1:] if argv is None else argv)
    _require(os.geteuid() == 0 and os.getegid() == 0, "root custody required")
    provider = FixedProvider()
    if len(args) == 6 and args[0] == "effect":
        raw = provider.effect(args[1], int(args[2]), args[3], args[4], args[5])
    elif len(args) == 4 and args[0] == "remote":
        raw = provider.remote(int(args[1]), args[2], args[3])
    elif len(args) == 4 and args[0] == "inventory":
        raw = provider.inventory(int(args[1]), args[2], args[3])
    elif len(args) == 5 and args[0] == "recover":
        raw = provider.recover(int(args[1]), args[2], args[3], args[4])
    else:
        _usage()
    _require(os.write(1, raw) == len(raw))


if __name__ == "__main__":
    main()

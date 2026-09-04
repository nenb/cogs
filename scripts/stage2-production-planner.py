#!/usr/bin/env python3
"""Fixed read-only AWS/OpenTofu producer for seven production plan bytes.

This module is inert on import. Its CLI is reserved for the separately authorized
planning workflow; ordinary tests inspect it or use fake subprocess seams only.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production

AWS = Path("/usr/local/bin/aws")
TOFU_SHA256 = "e11e783ab8ee0a029da32c2ab1817952121208d0ae9d6cf2d91fa0687f573a88"
MAX = 32 * 1024 * 1024


class PlanningError(Exception): pass


def require(value):
    if not value: raise PlanningError()


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value); value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def read(path, maximum=MAX):
    raw = Path(path).read_bytes(); require(0 < len(raw) <= maximum)
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PlanningError() from error
    require(type(value) is dict and canonical(value) == raw)
    return raw, value


def run(arguments, timeout, environment, parse=False):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=ROOT / "deploy/aws-feasibility", env=environment,
        close_fds=True, start_new_session=True, timeout=timeout, check=False)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= MAX)
    if not parse: return result.stdout
    raw = result.stdout if result.stdout.endswith(b"\n") else result.stdout + b"\n"
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PlanningError() from error
    require(type(value) is dict); return value


def main(arguments):
    require(len(arguments) == 5 and os.environ.get("COGS_STAGE2_AWS_PLAN_AUTHORIZATION") ==
            "authorize-read-only-stage2-production-planning")
    package_raw, package = read(arguments[0]); control_raw, control = read(arguments[1])
    descriptor_raw, descriptor = read(arguments[2], 8192)
    tofu = Path(arguments[3]); output = Path(arguments[4])
    require(package.get("version") == "cogs.stage2-pre-aws-qualification-package/v4"
            and package.get("authority") == "non-aws-prerequisite-evidence-only"
            and package.get("cycle_count") == 7 and package.get("workload_measurements") == 21
            and package.get("claims", {}).get("formal_non_aws_qualification_passed") is True
            and package.get("claims", {}).get("aws_authorized") is False
            and package.get("claims", {}).get("provider_executed") is False
            and package.get("claims", {}).get("aws_executed") is False
            and package.get("claims", {}).get("promotion_authorized") is False
            and control.get("version") == "cogs.stage2-local-static-control-package/v2"
            and descriptor.get("version") == "cogs.stage2-prebuilt-rootfs-descriptor/v1")
    bindings = package["source_bindings"]; producer = descriptor["producer"]
    require(re.fullmatch(r"[0-9a-f]{40}", package["qualification_revision"]) is not None
            and bindings["rootfs_descriptor_sha256"] == hashlib.sha256(descriptor_raw).hexdigest()
            and producer["revision"] == package["implementation_revision"] == bindings["source_head"]
            and control.get("producer", {}).get("control_revision") == package["control_revision"]
            and producer["source_manifest_sha256"] == bindings["source_manifest_sha256"]
            and producer["package_manifest_sha256"] == bindings["rootfs_package_manifest_sha256"]
            and producer["provenance_sha256"] == bindings["rootfs_provenance_sha256"]
            and producer["publication_receipt_sha256"] ==
                bindings["rootfs_publication_receipt_sha256"]
            and package["source_manifest_sha256"] == bindings["source_manifest_sha256"]
            and package["static_control_sha256"] == hashlib.sha256(control_raw).hexdigest()
            and package["rootfs_descriptor_sha256"] == hashlib.sha256(descriptor_raw).hexdigest()
            and package["cycle_artifact_custody"]["workflow_run"]["head_sha"] ==
                package["qualification_revision"]
            and type(package["static_control_observation"]["run_id"]) is int
            and package["static_control_observation"]["run_id"] > 0
            and type(package["static_control_observation"]["artifact_id"]) is int
            and package["static_control_observation"]["artifact_id"] > 0
            and re.fullmatch(r"sha256:[0-9a-f]{64}", package["static_control_observation"]
                             ["artifact_archive_digest"]) is not None)
    require(hashlib.sha256(tofu.read_bytes()).hexdigest() == TOFU_SHA256)
    environment = {key: os.environ[key] for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN")}
    environment.update({"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/local/bin:/usr/bin:/bin", "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": "",
        "AWS_EC2_METADATA_DISABLED": "true", "TF_IN_AUTOMATION": "1"})
    aws_path = AWS.resolve(); aws_before = aws_path.stat()
    aws_sha256 = hashlib.sha256(aws_path.read_bytes()).hexdigest()
    caller = run((str(AWS), "--region", "us-east-1", "sts", "get-caller-identity",
        "--output", "json", "--no-cli-pager"), 60, environment, True)
    account = caller.get("Account"); arn = caller.get("Arn")
    require(type(account) is str and re.fullmatch(r"[0-9]{12}", account) is not None
            and type(arn) is str)
    match = re.fullmatch(r"arn:aws:sts::[0-9]{12}:assumed-role/([^/]+)/[^/]+", arn)
    require(match is not None)
    role = os.environ.get("COGS_STAGE2_EXECUTOR_ROLE_NAME", "")
    observer_role = os.environ.get("COGS_STAGE2_INVENTORY_OBSERVER_ROLE_NAME", "")
    require(re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role) is not None
            and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", observer_role) is not None
            and len({role, observer_role, match.group(1)}) == 3)
    images = run((str(AWS), "--region", "us-east-1", "ec2", "describe-images",
        "--owners", "099720109477", "--filters",
        "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
        "Name=state,Values=available", "Name=architecture,Values=x86_64",
        "Name=virtualization-type,Values=hvm", "Name=root-device-type,Values=ebs",
        "--output", "json", "--no-cli-pager"), 120, environment, True).get("Images")
    require(type(images) is list and images)
    image = sorted(images, key=lambda row: (row.get("CreationDate", ""), row.get("ImageId", "")))[-1]
    aws_after = aws_path.stat()
    require((aws_before.st_dev, aws_before.st_ino, aws_before.st_size,
             aws_before.st_mtime_ns, aws_before.st_ctime_ns) ==
            (aws_after.st_dev, aws_after.st_ino, aws_after.st_size,
             aws_after.st_mtime_ns, aws_after.st_ctime_ns)
            and hashlib.sha256(aws_path.read_bytes()).hexdigest() == aws_sha256)
    require(type(image.get("ImageId")) is str
            and re.fullmatch(r"ami-[0-9a-f]{17}", image["ImageId"]) is not None
            and image.get("OwnerId") == "099720109477"
            and image.get("Architecture") == "x86_64"
            and image.get("VirtualizationType") == "hvm"
            and image.get("RootDeviceType") == "ebs" and image.get("State") == "available")
    now = time.time_ns()
    draft = {
        "version": "cogs.stage2-production-approval-draft/v2",
        "implementation_revision": bindings["source_head"],
        "control_revision": package["control_revision"],
        "qualification_revision": package["qualification_revision"],
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "source_bindings_sha256": production._commit(
            b"cogs.stage2-source-bindings/v1", bindings),
        "static_control_sha256": package["static_control_sha256"],
        "pre_aws_package_sha256": hashlib.sha256(package_raw).hexdigest(),
        "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
        "rootfs_package_manifest_sha256": producer["package_manifest_sha256"],
        "rootfs_provenance_sha256": producer["provenance_sha256"],
        "rootfs_qualification_receipt_sha256": producer["qualification_receipt_sha256"],
        "rootfs_publication_receipt_sha256": producer["publication_receipt_sha256"],
        "runtime_commitment": bindings["runtime_attestation_sha256"],
        "fixture_commitment": bindings["final_pin_sha256"],
        "account_commitment": hashlib.sha256(account.encode()).hexdigest(),
        "partition": "aws", "region": "us-east-1", "ami_id": image["ImageId"],
        "ami_owner_id": image["OwnerId"], "ami_architecture": image["Architecture"],
        "ami_virtualization_type": image["VirtualizationType"],
        "ami_root_device_type": image["RootDeviceType"], "ami_state": image["State"],
        "not_before_unix_ns": now, "effect_deadline_ns": 220 * 60 * 10**9,
        "cleanup_reserve_ns": 25 * 60 * 10**9, "expires_unix_ns": now + 7 * 60 * 60 * 10**9,
        "maximum_cycle_duration_ns": 150 * 60 * 10**9,
        "maximum_cost_micro_usd": 499_999,
        "executor_principal_commitment": production.executor_principal_commitment("aws", account, role),
        "inventory_observer_principal_commitment":
            production.executor_principal_commitment("aws", account, observer_role),
    }
    draft["ami_commitment"] = production.resolved_ami_commitment(draft)
    email = os.environ.get("COGS_STAGE2_BUDGET_ALERT_EMAIL", "")
    require(3 <= len(email) <= 254 and "@" in email and "\n" not in email)
    output.mkdir(mode=0o700); plans = output / "plans"; plans.mkdir(mode=0o700)
    credentials = output / ".aws-credentials"
    credentials.write_text("[nebula]\naws_access_key_id = " + environment["AWS_ACCESS_KEY_ID"] +
        "\naws_secret_access_key = " + environment["AWS_SECRET_ACCESS_KEY"] +
        "\naws_session_token = " + environment["AWS_SESSION_TOKEN"] + "\n")
    config = output / ".aws-config"; config.write_text("[profile nebula]\nregion = us-east-1\noutput = json\n")
    os.chmod(credentials, 0o600); os.chmod(config, 0o600)
    environment.update({"AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                        "AWS_CONFIG_FILE": str(config), "AWS_PROFILE": "nebula"})
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        environment.pop(name)
    run((str(tofu), "init", "-backend=false", "-input=false", "-lockfile=readonly"),
        300, environment)
    provider_root = ROOT / "deploy/aws-feasibility/.terraform/providers/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
    providers = [path for path in provider_root.iterdir()
                 if path.is_file() and "provider-aws" in path.name]
    require(len(providers) == 1)
    provider_raw = providers[0].read_bytes()
    draft["provider_binary_sha256"] = hashlib.sha256(provider_raw).hexdigest()
    draft["aws_cli_sha256"] = aws_sha256
    batch = production.approval_batch_commitment(draft)
    hashes = []
    for ordinal in range(1, 8):
        variables = {"aws_profile": "nebula", "aws_region": "us-east-1",
            "ami_id": image["ImageId"], "ami_owner_id": image["OwnerId"],
            "ami_commitment": draft["ami_commitment"], "batch_commitment": batch,
            "cycle_ordinal": ordinal, "source_revision": bindings["source_head"],
            "control_revision": package["control_revision"],
            "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(draft["expires_unix_ns"] // 10**9)),
            "budget_alert_email": email, "account_id_sha256": draft["account_commitment"]}
        varfile = plans / f"{ordinal:02d}.tfvars.json"; varfile.write_bytes(canonical(variables))
        plan = plans / f"{ordinal:02d}.tfplan"
        run((str(tofu), "plan", "-input=false", "-lock=false", "-refresh=true",
            "-var-file=" + str(varfile), "-out=" + str(plan)), 900, environment)
        shown = run((str(tofu), "show", "-json", str(plan)), 120, environment, True)
        plan_json = plans / f"{ordinal:02d}.plan.json"
        plan_json.write_bytes(canonical(shown)); varfile.unlink()
        run(("/usr/bin/python3", str(ROOT / "deploy/aws-feasibility/check-plan.py"),
             str(plan_json)), 30, environment)
        hashes.append(hashlib.sha256(plan.read_bytes()).hexdigest())
    credentials.unlink(); config.unlink()
    draft["plan_sha256s"] = hashes
    (output / "approval-draft.json").write_bytes(canonical(draft))
    (output / "tofu").write_bytes(tofu.read_bytes()); os.chmod(output / "tofu", 0o555)
    (output / "tofu-provider-aws").write_bytes(provider_raw)
    os.chmod(output / "tofu-provider-aws", 0o555)


if __name__ == "__main__":
    try: main(sys.argv[1:])
    except (OSError, PlanningError, production.ProductionCampaignError, subprocess.SubprocessError):
        raise SystemExit(2)

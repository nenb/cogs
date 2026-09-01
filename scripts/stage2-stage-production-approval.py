#!/usr/bin/env python3
"""Stage one authenticated approval and seven plans into fixed root custody."""
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_aws_adapter as adapter
import completion_campaign_production as production

DESTINATION = adapter.ROOT
STAGING = DESTINATION.with_name(DESTINATION.name + ".staging")
STATE = adapter.STATE_ROOT
MAX = 64 * 1024 * 1024


class StagingError(Exception): pass


def require(value):
    if not value: raise StagingError()


def read(path, maximum=MAX):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum)
        raw = os.read(fd, maximum + 1); after = os.fstat(fd)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == before.st_size and key(before) == key(after))
        return raw
    finally: os.close(fd)


def write(path, raw, mode=0o400):
    temporary = path.with_name("." + path.name + ".partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); require(count > 0); view = view[count:]
        os.fchown(fd, 0, 0); os.fchmod(fd, mode); os.fsync(fd)
    finally: os.close(fd)
    os.rename(temporary, path); sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def remove_partial(expected):
    seen = STAGING.lstat()
    require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
            and stat.S_IMODE(seen.st_mode) == 0o700)
    files = sorted((path for path in STAGING.rglob("*") if not path.is_dir()),
                   key=lambda path: len(path.parts), reverse=True)
    require(all(not path.is_symlink() for path in STAGING.rglob("*")))
    for path in files:
        relative = str(path.relative_to(STAGING))
        final = path.name[1:-8] if path.name.startswith(".") and path.name.endswith(".partial") else path.name
        expected_relative = str(path.relative_to(STAGING).with_name(final))
        require(expected_relative in expected)
        if relative == expected_relative:
            require(read(path, len(expected[expected_relative])) == expected[expected_relative])
        else:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                before = os.fstat(descriptor); raw = os.read(descriptor, len(expected[expected_relative]) + 1)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                        and before.st_nlink == 1 and len(raw) == before.st_size
                        and expected[expected_relative].startswith(raw))
            finally: os.close(descriptor)
        path.unlink()
    directories = sorted((path for path in STAGING.rglob("*") if path.is_dir()),
                         key=lambda path: len(path.parts), reverse=True)
    allowed = set()
    for name in expected:
        parent = Path(name).parent
        while str(parent) != ".":
            allowed.add(str(parent)); parent = parent.parent
    for path in directories:
        require(str(path.relative_to(STAGING)) in allowed and not any(path.iterdir()))
        path.rmdir()
    require(not any(STAGING.iterdir())); STAGING.rmdir(); sync(STAGING.parent)


def stage(source, budget_email_path, aws_config_path, aws_credentials_path):
    require(os.geteuid() == os.getegid() == 0)
    source = Path(source)
    approval_raw = read(source / "approval.json", 256 * 1024)
    try: value = json.loads(approval_raw)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error: raise StagingError() from error
    require(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False).encode("ascii") + b"\n" == approval_raw)
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    approval = production.ProductionApproval(**value)
    fixed = {
        "approval.json": approval_raw,
        "approval-authentication.json": read(source / "approval-authentication.json", 256 * 1024),
        "approval-authentication.bundle.json": read(
            source / "approval-authentication.bundle.json", 1024 * 1024),
        "sigstore-trusted-root.json": read(source / "sigstore-trusted-root.json", 64 * 1024),
    }
    authentication_raw = fixed["approval-authentication.json"]
    try: authentication = json.loads(authentication_raw)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StagingError() from error
    require(json.dumps(authentication, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n" ==
            authentication_raw)
    require(set(authentication) == {"version", "result", "approval_sha256",
            "issuer_commitment", "workflow_sha256", "workflow_run_id",
            "workflow_run_attempt", "control_revision",
            "approver_principal_commitment", "executor_principal_commitment",
            "inventory_observer_principal_commitment", "first_created"}
            and authentication["version"] ==
                "cogs.stage2-production-approval-authentication/v1"
            and authentication["result"] == "pass"
            and authentication["approval_sha256"] == hashlib.sha256(approval_raw).hexdigest()
            and authentication["issuer_commitment"] == approval.issuer_commitment
            and authentication["control_revision"] == approval.control_revision
            and authentication["executor_principal_commitment"] ==
                approval.executor_principal_commitment
            and authentication["inventory_observer_principal_commitment"] ==
                approval.inventory_observer_principal_commitment
            and authentication["workflow_run_attempt"] == 1
            and authentication["first_created"] is True)
    for name in ("issuer_commitment", "workflow_sha256",
                 "approver_principal_commitment", "executor_principal_commitment",
                 "inventory_observer_principal_commitment"):
        production._digest(authentication[name])
    require(len({authentication["approver_principal_commitment"],
                 authentication["executor_principal_commitment"],
                 authentication["inventory_observer_principal_commitment"]}) == 3
            and type(authentication["workflow_run_id"]) is int
            and authentication["workflow_run_id"] > 0)
    cosign = read(source / "cosign", 160 * 1024 * 1024)
    tofu = read(source / "tofu", 140 * 1024 * 1024)
    provider_binary = read(source / "tofu-provider-aws", 1024 * 1024 * 1024)
    tofu_config = ("provider_installation { dev_overrides { "
                   "\"registry.opentofu.org/hashicorp/aws\" = \"" +
                   str(DESTINATION) + "\" } direct { exclude = "
                   "[\"registry.opentofu.org/hashicorp/aws\"] } }\n").encode("ascii")
    budget_email = read(budget_email_path, 1024)
    aws_config = read(aws_config_path, 4096)
    aws_credentials = read(aws_credentials_path, 16 * 1024)
    try: email = budget_email.decode("ascii").strip()
    except UnicodeError as error: raise StagingError() from error
    require(budget_email == (email + "\n").encode("ascii") and 3 <= len(email) <= 254
            and "@" in email and "\n" not in email)
    require(aws_config == (f"[profile nebula]\nregion = {approval.region}\noutput = json\n"
                           f"[profile observer]\nregion = {approval.region}\noutput = json\n").encode("ascii"))
    require(re.fullmatch(
        rb"\[nebula\]\naws_access_key_id = ASIA[A-Z0-9]{16}\n"
        rb"aws_secret_access_key = [A-Za-z0-9/+=]{40}\n"
        rb"aws_session_token = [A-Za-z0-9/+=]{80,8192}\n"
        rb"\[observer\]\naws_access_key_id = ASIA[A-Z0-9]{16}\n"
        rb"aws_secret_access_key = [A-Za-z0-9/+=]{40}\n"
        rb"aws_session_token = [A-Za-z0-9/+=]{80,8192}\n", aws_credentials) is not None)
    require(hashlib.sha256(cosign).hexdigest() == adapter.COSIGN_SHA256
            and hashlib.sha256(tofu).hexdigest() == adapter.TOFU_SHA256
            and hashlib.sha256(provider_binary).hexdigest() ==
                approval.provider_binary_sha256
            and hashlib.sha256(fixed["sigstore-trusted-root.json"]).hexdigest() ==
                adapter.TRUSTED_ROOT_SHA256)
    plans = []
    for ordinal, digest in enumerate(approval.plan_sha256s, 1):
        binary = read(source / "plans" / f"{ordinal:02d}.tfplan")
        plan_json = read(source / "plans" / f"{ordinal:02d}.plan.json")
        require(hashlib.sha256(binary).hexdigest() == digest)
        plans.append((ordinal, binary, plan_json))
    expected = {**fixed, "cosign": cosign, "tofu": tofu,
                "terraform-provider-aws_v6.54.0_x5": provider_binary,
                "tofu-cli.tfrc": tofu_config,
                "budget-alert-email.txt": budget_email, "aws-config": aws_config,
                "aws-credentials": aws_credentials}
    for ordinal, binary, plan_json in plans:
        expected[f"provider-state/cycle-{ordinal}/campaign.tfplan"] = binary
        expected[f"provider-state/cycle-{ordinal}/campaign.plan.json"] = plan_json
    recovery_only = os.environ.get("COGS_STAGE2_STAGING_RECOVERY_ONLY") == "1"
    if recovery_only and DESTINATION.exists():
        require(not STAGING.exists()
                and not (DESTINATION / "approval-consumed.json").exists()
                and not (DESTINATION / "campaign-journal.jsonl").exists())
        os.rename(DESTINATION, STAGING); sync(STAGING.parent)
        remove_partial(expected)
        return hashlib.sha256(approval_raw).hexdigest()
    if recovery_only and STAGING.exists():
        remove_partial(expected)
        return hashlib.sha256(approval_raw).hexdigest()
    require(not recovery_only)
    if DESTINATION.exists():
        require(not STAGING.exists())
        checked, authentication_sha256 = adapter._approval()
        require(checked == approval and len(authentication_sha256) == 64)
        for name, raw in expected.items():
            require(read(DESTINATION / name, len(raw)) == raw)
        return hashlib.sha256(approval_raw).hexdigest()
    if STAGING.exists(): remove_partial(expected)
    try:
        STAGING.mkdir(mode=0o700); os.chown(STAGING, 0, 0)
        for name, raw in fixed.items(): write(STAGING / name, raw)
        write(STAGING / "cosign", cosign, 0o555)
        write(STAGING / "tofu", tofu, 0o555)
        write(STAGING / "terraform-provider-aws_v6.54.0_x5", provider_binary, 0o555)
        write(STAGING / "tofu-cli.tfrc", tofu_config)
        write(STAGING / "budget-alert-email.txt", budget_email)
        write(STAGING / "aws-config", aws_config)
        write(STAGING / "aws-credentials", aws_credentials)
        state = STAGING / "provider-state"
        state.mkdir(mode=0o700); os.chown(state, 0, 0)
        for ordinal, binary, plan_json in plans:
            directory = state / f"cycle-{ordinal}"
            directory.mkdir(mode=0o700); os.chown(directory, 0, 0)
            write(directory / "campaign.tfplan", binary)
            write(directory / "campaign.plan.json", plan_json)
            sync(directory)
        sync(state); sync(STAGING)
        identity = "https://github.com/nenb/cogs/.github/workflows/stage2-production-approval.yml@refs/heads/main"
        result = subprocess.run(("/usr/bin/unshare", "--net", "--",
            str(STAGING / "cosign"), "verify-blob", "--trusted-root",
            str(STAGING / "sigstore-trusted-root.json"), "--bundle",
            str(STAGING / "approval-authentication.bundle.json"),
            "--certificate-identity", identity, "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            str(STAGING / "approval-authentication.json")), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                 "PATH": "/usr/bin:/bin"}, timeout=30, check=False,
            close_fds=True, start_new_session=True)
        require(result.returncode == 0)
        os.rename(STAGING, DESTINATION); sync(DESTINATION.parent)
        checked, authentication_sha256 = adapter._approval()
        require(checked == approval and len(authentication_sha256) == 64)
        return hashlib.sha256(approval_raw).hexdigest()
    except BaseException:
        # An uncertain or partial staging root is preserved for independent cleanup.
        raise


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 5)
        result = stage(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
        raw = f"approval_sha256={result}\n".encode("ascii")
        require(sys.stdout.buffer.write(raw) == len(raw))
    except (OSError, StagingError, production.ProductionCampaignError):
        raise SystemExit(2)

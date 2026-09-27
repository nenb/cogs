#!/usr/bin/env python3
"""Hostile fake-executor checks for the dormant concrete provider boundary."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "deploy/aws-feasibility"))
import completion_campaign_aws_provider as provider
import completion_campaign_production as production


def d(value): return hashlib.sha256(value.encode()).hexdigest()
def raw(value): return provider.canonical(value)


def approval(plan_digests, account):
    value = {
        "version": "cogs.stage2-completion-production-approval/v6",
        "phrase": production.APPROVAL_PHRASE,
        "phase_boundary_ordinal": 3, "phase_cycle_counts": (3, 4),
        "implementation_revision": "1" * 40, "control_revision": "2" * 40, "qualification_revision": "3" * 40,
        "source_manifest_sha256": d("source"),
        "source_bindings_sha256": d("source-bindings"),
        "static_control_sha256": d("control"),
        "pre_aws_package_sha256": d("preaws"), "rootfs_descriptor_sha256": d("rootfs"),
        "rootfs_package_manifest_sha256": d("rootfs-package"),
        "rootfs_provenance_sha256": d("rootfs-provenance"),
        "rootfs_qualification_receipt_sha256": d("rootfs-qualification"),
        "rootfs_publication_receipt_sha256": d("rootfs-publication"),
        "runtime_manifest_sha256": d("runtime-manifest"), "fixture_commitment": d("fixture"),
        "provider_binary_sha256": d("provider"), "aws_cli_sha256": d("aws"),
        "account_commitment": hashlib.sha256(account.encode()).hexdigest(),
        "partition": "aws", "region": "us-east-1", "ami_id": "ami-" + "a" * 17,
        "ami_owner_id": "099720109477", "ami_architecture": "x86_64",
        "ami_virtualization_type": "hvm", "ami_root_device_type": "ebs",
        "ami_state": "available", "plan_sha256s": tuple(plan_digests),
        "not_before_unix_ns": 1, "effect_deadline_ns": 480 * 60 * 10**9,
        "cleanup_reserve_ns": 30 * 60 * 10**9,
        "expires_unix_ns": 1 + 10 * 60 * 60 * 10**9,
        "maximum_cycle_duration_ns": 150 * 60 * 10**9,
        "maximum_cost_micro_usd": 1_100_000,
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


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def sleep(self, seconds): self.value += seconds


class Fake:
    def __init__(self, account):
        self.account, self.calls, self.ssm_mode, self.ssm_reads = account, [], "missing-command", 0
        self.ssm_rows = None
    def __call__(self, argv, timeout, environment):
        self.calls.append((argv, timeout, environment))
        if argv[0] == str(provider.TOFU) and "init" in argv:
            data = Path(environment["TF_DATA_DIR"])
            assert data.is_dir() and Path(environment["TF_CLI_CONFIG_FILE"]).is_file()
            mirror_root = data.parents[2] / "provider-mirror/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
            assert provider._package_binary() == mirror_root / "terraform-provider-aws_v6.54.0_x5"
            assert (mirror_root / "LICENSE").read_bytes() == b"license\n"
            assert (mirror_root / "terraform-provider-aws_v6.54.0_x5").read_bytes() == b"provider"
            (data / "fake-init-cache").write_text("initialized")
            return provider.Completed(b"initialized\n")
        if argv[0] == str(provider.TOFU) and "show" in argv:
            return provider.Completed(Path(argv[-1]).with_name("campaign.plan.json").read_bytes())
        if "get-caller-identity" in argv:
            role = "observer" if "observer" in argv else "executor"
            return provider.Completed(raw({"Account": self.account,
                "Arn": f"arn:aws:iam::000000000000:role/{role}",
                "UserId": "session:test"}))
        if argv[0] == str(provider.AWS):
            if "describe-instance-information" in argv and any(
                    item.startswith("Key=InstanceIds,Values=") for item in argv):
                instance = next(item.removeprefix("Key=InstanceIds,Values=") for item in argv
                                if item.startswith("Key=InstanceIds,Values="))
                rows = self.ssm_rows.pop(0) if self.ssm_rows else [{
                    "InstanceId": instance, "PingStatus": "Online"}]
                return provider.Completed(raw({"InstanceInformationList": rows}))
            if "send-command" in argv:
                assert environment["AWS_MAX_ATTEMPTS"] == "1" and environment["AWS_RETRY_MODE"] == "standard"
                return provider.Completed(raw({"Command": {"CommandId": "command-12345678"}})
                                          if self.ssm_mode in {"success", "remote-failure"} else raw({}))
            if "get-command-invocation" in argv:
                self.ssm_reads += 1
                if self.ssm_reads == 1:
                    return provider.Completed(b"", b"InvocationDoesNotExist", 255)
                command, instance = argv[argv.index("--command-id") + 1], argv[argv.index("--instance-id") + 1]
                observed_instance = "i-mismatch" if self.ssm_mode == "mismatch" else instance
                remote_failure = self.ssm_mode == "remote-failure"
                return provider.Completed(raw({"CommandId": command, "InstanceId": observed_instance,
                                                "Status": "Failed" if remote_failure else "Success",
                                                "ResponseCode": 126 if remote_failure else 0,
                                                "StandardErrorContent": "",
                                                "StandardOutputContent": "untrusted-receipt\n" if remote_failure else "receipt\n"}))
            # Force a real two-page chain on a pageable operation. Unrelated
            # account resources may not be relabelled campaign residue.
            if "describe-instances" in argv and "--starting-token" not in argv:
                return provider.Completed(raw({"Reservations": [{"Instances": [{
                    "InstanceId": f"i-{1:017x}", "State": {"Name": "terminated"}}]}],
                    "NextToken": "opaque"}))
            if "describe-instances" in argv:
                return provider.Completed(raw({"Reservations": []}))
            if "describe-addresses" in argv:
                return provider.Completed(raw({"Addresses": [{"AllocationId": "eipalloc-unrelated",
                    "PublicIp": "192.0.2.1", "Tags": []}]}))
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
    provider.TOFU_CONFIG = root / "tofu-cli.tfrc"
    provider.TOFU_SHA256 = d("tofu")
    root.mkdir(exist_ok=True)
    account = "000000000000"
    provider.AWS.write_bytes(b"aws"); provider.AWS.chmod(0o700)
    provider.TOFU.write_bytes(b"tofu"); provider.TOFU.chmod(0o700)
    mirror_root = root / "provider-mirror/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
    mirror_root.mkdir(parents=True)
    (mirror_root / "LICENSE").write_bytes(b"license\n"); (mirror_root / "LICENSE").chmod(0o444)
    mirror = mirror_root / "terraform-provider-aws_v6.54.0_x5"
    mirror.write_bytes(b"provider"); mirror.chmod(0o555)
    manifest = {"version": "cogs.stage2-opentofu-provider-package/v1",
                "prefix": provider.PROVIDER_PREFIX, "root_mode": stat.S_IMODE(mirror_root.stat().st_mode),
                "file_count": 2, "total_bytes": 16,
                "files": [{"name": "LICENSE", "mode": 0o444, "size": 8, "sha256": d("license\n")},
                          {"name": mirror.name, "mode": 0o555, "size": 8, "sha256": d("provider")}],
                "provider_path": mirror.name, "provider_binary_sha256": d("provider")}
    (root / "provider-package.json").write_bytes(raw(manifest))
    provider.TOFU_CONFIG.write_text('provider_installation {\n  filesystem_mirror {\n    path = "' + str(root / "provider-mirror") + '"\n  }\n}\n')
    provider.ENV = {**provider.ENV, "TF_CLI_CONFIG_FILE": str(provider.TOFU_CONFIG)}
    plan_bytes = b"reviewed-plan-bytes"
    plans = [hashlib.sha256(plan_bytes if index == 1 else f"plan-{index}".encode()).hexdigest()
             for index in range(1, 8)]
    current = approval(plans, account)
    provider.APPROVAL.write_bytes(raw({**current.__dict__, "plan_sha256s": list(current.plan_sha256s)}))
    provider.BUDGET_EMAIL.write_text("owner@example.invalid\n")
    fake, clock = Fake(account), Clock()
    approval_stat = provider.APPROVAL.stat()
    approval_identity = (stat.S_IMODE(approval_stat.st_mode), approval_stat.st_uid,
                         approval_stat.st_nlink, approval_stat.st_size)
    assert approval_identity == (0o600, os.geteuid(), 1,
                                 approval_stat.st_size), approval_identity
    boundary = provider.FixedProvider(fake, clock=clock, sleeper=clock.sleep)
    license_path = mirror_root / "LICENSE"; original_license = license_path.read_bytes()
    def package_rejected(label, mutate, restore):
        mutate()
        try: provider._package_binary()
        except (OSError, provider.ProviderBoundaryError): pass
        else: raise AssertionError(label + " package closure was accepted")
        restore()
        assert provider._package_binary() == mirror
    package_rejected("missing", license_path.unlink,
                     lambda: (license_path.write_bytes(original_license), license_path.chmod(0o444)))
    extra = mirror_root / "unexpected"
    package_rejected("extra", lambda: extra.write_bytes(b"extra"), extra.unlink)
    package_rejected("replaced", lambda: (license_path.chmod(0o644), license_path.write_bytes(b"replaced")),
                     lambda: (license_path.write_bytes(original_license), license_path.chmod(0o444)))
    package_rejected("hardlink", lambda: (license_path.unlink(), os.link(mirror, license_path)),
                     lambda: (license_path.unlink(), license_path.write_bytes(original_license), license_path.chmod(0o444)))
    package_rejected("symlink", lambda: (license_path.unlink(), license_path.symlink_to(mirror.name)),
                     lambda: (license_path.unlink(), license_path.write_bytes(original_license), license_path.chmod(0o444)))
    # Package identity mutation, even when restored byte-for-byte, requires a
    # fresh owner; the old owner intentionally retains its changed ctime guard.
    boundary = provider.FixedProvider(fake, clock=clock, sleeper=clock.sleep)

    grants = {}
    for ordinal in range(1, 8):
        cycle = provider.STATE_ROOT / f"cycle-{ordinal}"; cycle.mkdir(parents=True)
        (cycle / "campaign.tfplan").write_bytes(plan_bytes)
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
    cross_cycle_package = provider.STATE_ROOT / "cycle-3/tf-data/providers" / provider.PROVIDER_PREFIX
    cross_cycle_package.mkdir(parents=True)
    try: boundary._local_backend(provider.STATE_ROOT / "cycle-3", grants[3])
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("cross-cycle provider package was adopted")
    shutil.rmtree(provider.STATE_ROOT / "cycle-3/tf-data")

    fake.ssm_mode = "mismatch"
    try: boundary.remote(7, grants[7].mode, grants[7].grant_commitment, 60)
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("mismatched SSM command identity accepted")
    sends = [call for call, _, _ in fake.calls if "send-command" in call]
    assert len(sends) == 1 and (provider.STATE_ROOT / "cycle-7/remote-send.intent.json").is_file()
    assert not (provider.STATE_ROOT / "cycle-7/remote-send.receipt.json").exists()
    try: boundary.remote(7, grants[7].mode, grants[7].grant_commitment, 60)
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("SSM send was retried after an identity mismatch")
    assert len([call for call, _, _ in fake.calls if "send-command" in call]) == 1
    fake.ssm_mode, fake.ssm_reads = "success", 0
    fake.ssm_rows = [[{"InstanceId": f"i-{2:017x}", "PingStatus": "ConnectionLost"}],
                     [{"InstanceId": f"i-{2:017x}", "PingStatus": "Online"}]]
    remote = boundary.remote(2, grants[2].mode, grants[2].grant_commitment, 60)
    assert remote == b"receipt\n" and clock.value == 10
    send_calls = [call for call, _, _ in fake.calls if "send-command" in call]
    poll_calls = [call for call, _, _ in fake.calls if "get-command-invocation" in call]
    assert len(send_calls) == 2 and len(poll_calls) == 2
    assert all(call[call.index("--command-id") + 1] == "command-12345678"
               and call[call.index("--instance-id") + 1] == f"i-{2:017x}" for call in poll_calls)
    assert (provider.STATE_ROOT / "cycle-2/remote-send.receipt.json").is_file()
    fake.ssm_mode, fake.ssm_reads = "remote-failure", 1
    try: boundary.remote(1, grants[1].mode, grants[1].grant_commitment, 60)
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("remote restoration failure accepted")
    assert (provider.STATE_ROOT / "cycle-1/remote-send.receipt.json").is_file()
    assert not (provider.STATE_ROOT / "cycle-1/remote-owner-receipt.json").exists()
    fake.ssm_mode = "success"
    # Exact-instance registrations may be offline, but foreign, duplicate, and
    # malformed rows are never propagation candidates and no failure sends.
    before_sends = len([call for call, _, _ in fake.calls if "send-command" in call])
    for ordinal, rows in ((3, [{"InstanceId": "i-foreign", "PingStatus": "Online"}]),
                          (4, [{"InstanceId": f"i-{4:017x}", "PingStatus": "Online"}, {"InstanceId": f"i-{4:017x}", "PingStatus": "Online"}]),
                          (5, [{"InstanceId": f"i-{5:017x}"}])):
        fake.ssm_rows = [rows]
        try: boundary.remote(ordinal, grants[ordinal].mode, grants[ordinal].grant_commitment, 60)
        except provider.ProviderBoundaryError: pass
        else: raise AssertionError("invalid SSM registration accepted")
    fake.ssm_rows = [[{"InstanceId": f"i-{6:017x}", "PingStatus": "Inactive"}]]
    try: boundary.remote(6, grants[6].mode, grants[6].grant_commitment, 1)
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("offline SSM registration exceeded deadline")
    assert len([call for call, _, _ in fake.calls if "send-command" in call]) == before_sends
    ssm_timeouts = [timeout for call, timeout, _ in fake.calls
                    if call[0] == str(provider.AWS) and "ssm" in call]
    assert ssm_timeouts and all(0 < timeout <= 60 for timeout in ssm_timeouts)
    shell = json.loads((provider.STATE_ROOT / "cycle-7/ssm-parameters.json").read_bytes())["commands"][0]
    assert f'origin {current.qualification_revision}' in shell and '$w/G' not in shell
    assert 'w=/root/cogs-stage2-bootstrap; owned=0' in shell
    assert 'umask 022; $g init' in shell and 'checkout -q --detach FETCH_HEAD; umask 077' in shell
    assert 'GIT_CONFIG_SYSTEM=/dev/null' in shell and 'core.hooksPath=/dev/null' in shell
    assert '"$w/H/scripts/stage2-stage-prebuilt-control.py" stage-qualification' in shell
    assert '"$w/Q/scripts/' not in shell and "root:root:700 || rm -rf" in shell
    assert "trap 'exit 125' HUP INT TERM" in shell and 'trap - EXIT HUP INT TERM' in shell
    immutable = (
        "/usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin TZ=UTC "
        "/usr/bin/python3 -I -B /var/lib/cogs/stage2-completion-v1/source/"
        "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py >/dev/null"
    )
    assert shell.count("completion_kata_immutable_preparation.py") == 1
    assert immutable in shell
    fwupd_units = ("fwupd-refresh.timer", "fwupd-refresh.service", "fwupd.service")
    assert all(shell.count(unit) == 1 for unit in fwupd_units)
    assert 'fwupd_systemctl=/usr/bin/systemctl; fwupd_runtime=/run/systemd/system' in shell
    assert 'load_state=$("$fwupd_systemctl" show --property=LoadState --value "$unit"' in shell
    assert 'if test "$load_state" = not-found; then continue; fi' in shell
    assert 'case "$load_state" in loaded|masked) ;; *) exit 126' in shell
    assert '"$fwupd_systemctl" mask --runtime --now "$unit" >/dev/null 2>&1 || exit 126' in shell
    assert 'test -L "$fwupd_runtime/$unit"' in shell
    assert '$(/usr/bin/readlink "$fwupd_runtime/$unit")" = /dev/null' in shell
    assert 'unit_state=$("$fwupd_systemctl" show --property=ActiveState --value "$unit"' in shell
    assert 'case "$unit_state" in inactive|failed) ;; *) exit 126' in shell
    assert shell.index("for unit in fwupd-refresh.timer") < shell.index(immutable)
    assert 'forward_path=/proc/sys/net/ipv4/ip_forward' in shell
    assert 'test "$forward_before" = 0' in shell
    assert "trap 'restore_forwarding \"$?\"' EXIT; trap 'exit 125' HUP INT TERM" in shell
    assert "printf '1\\n' >\"$forward_path\"" in shell
    assert "rc=$1; trap - EXIT; trap '' HUP INT TERM" in shell
    assert 'then rc=126; fi; exit "$rc"' in shell
    assert shell.index('provision-stage2-nft-owner.py') < shell.index('forward_path=')
    assert shell.index('forward_path=') < shell.index(command := provider.remote_adapter.invocation(grants[7]).command)
    syntax = subprocess.run(("/bin/sh", "-n", "-c", shell), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert syntax.returncode == 0, syntax.stderr

    fake_systemctl = Path(temporary) / "systemctl"
    fake_runtime = Path(temporary) / "systemd"
    fake_runtime.mkdir()
    fake_systemctl.write_text("""#!/bin/sh
set -eu
mode=${FAKE_SYSTEMCTL_MODE-success}
if test "$1" = show; then
  test "$mode" != show-failure || exit 9
  case "$2:$mode" in
    --property=LoadState:not-found) printf 'not-found\\n' ;;
    --property=LoadState:bad-load) printf 'error\\n' ;;
    --property=LoadState:*) printf 'loaded\\n' ;;
    --property=ActiveState:active) printf 'active\\n' ;;
    --property=ActiveState:activating) printf 'activating\\n' ;;
    --property=ActiveState:bad-active) printf 'surprise\\n' ;;
    --property=ActiveState:*) printf 'inactive\\n' ;;
  esac
  exit 0
fi
test "$1" = mask
test "$mode" != mask-failure || exit 9
if test "$mode" != no-mask-link; then ln -sf /dev/null "$FAKE_SYSTEMD_RUNTIME/$4"; fi
""")
    fake_systemctl.chmod(0o755)

    def run_fwupd(mode):
        for entry in fake_runtime.iterdir():
            entry.unlink()
        return subprocess.run(
            ("/bin/sh", "-c", "set -eu; " + provider._fwupd_quiescence_guard(
                str(fake_systemctl), str(fake_runtime)) + "printf reached"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "FAKE_SYSTEMCTL_MODE": mode, "FAKE_SYSTEMD_RUNTIME": str(fake_runtime)},
            check=False)

    fwupd_success = run_fwupd("success")
    assert (fwupd_success.returncode, fwupd_success.stdout, fwupd_success.stderr) == (0, "reached", "")
    assert sorted(path.name for path in fake_runtime.iterdir()) == sorted(fwupd_units)
    fwupd_absent = run_fwupd("not-found")
    assert (fwupd_absent.returncode, fwupd_absent.stdout) == (0, "reached")
    assert not tuple(fake_runtime.iterdir())
    for fwupd_failure in ("show-failure", "bad-load", "mask-failure", "no-mask-link",
                          "active", "activating", "bad-active"):
        rejected = run_fwupd(fwupd_failure)
        assert rejected.returncode != 0 and rejected.stdout == "", fwupd_failure

    forwarding_test_path = Path(temporary) / "ip_forward"

    def run_forwarding(body, initial="0\n"):
        if forwarding_test_path.is_symlink() or forwarding_test_path.is_file():
            forwarding_test_path.unlink()
        forwarding_test_path.write_text(initial)
        return subprocess.run(
            ("/bin/sh", "-c", "set -eu; " + provider._forwarding_guard(body, str(forwarding_test_path))),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

    forward_success = run_forwarding('test "$(cat "$forward_path")" = 1; printf receipt')
    assert (forward_success.returncode, forward_success.stdout, forward_success.stderr) == (0, "receipt", "")
    assert forwarding_test_path.read_text() == "0\n"
    forward_failure = run_forwarding('printf untrusted-receipt; exit 7')
    assert forward_failure.returncode == 7 and forwarding_test_path.read_text() == "0\n"
    forward_signal = run_forwarding('kill -TERM "$$"')
    assert forward_signal.returncode == 125 and forwarding_test_path.read_text() == "0\n"
    forward_baseline = run_forwarding('printf should-not-run', "1\n")
    assert forward_baseline.returncode != 0 and forward_baseline.stdout == ""
    assert forwarding_test_path.read_text() == "1\n"
    forward_restore_failure = run_forwarding(
        'rm -f "$forward_path"; ln -s /dev/null "$forward_path"')
    assert forward_restore_failure.returncode == 126 and forwarding_test_path.is_symlink()
    forwarding_test_path.unlink()

    assert shell.index('$w/Q" fetch') < shell.index('stage-qualification') < shell.index(immutable)
    hostile = {
        **os.environ,
        "AWS_SSM_INSTANCE_ID": "i-ssm-ambient",
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "ambient-must-not-cross",
        "HTTPS_PROXY": "http://ambient.invalid",
    }
    clean_probe = subprocess.run((
        "/usr/bin/env", "-i", "HOME=/nonexistent", "LANG=C", "LC_ALL=C",
        "PATH=/usr/bin:/bin", "TZ=UTC", "/usr/bin/python3", "-I", "-B", "-c",
        "import os; assert not any(k.startswith('AWS_') for k in os.environ); "
        "assert 'HTTPS_PROXY' not in os.environ",
    ), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
       close_fds=True, env=hostile, check=False)
    assert clean_probe.returncode == 0, clean_probe.stderr

    receipt_value = json.loads(boundary.effect(
        "plan", 1, "full", grants[1].grant_commitment, d("intent")))
    receipt_value["resource_commitments"] = tuple(
        tuple(row) for row in receipt_value["resource_commitments"])
    receipt = production.EffectReceipt(**receipt_value)
    assert receipt.kind == "plan" and receipt.identity_commitment == plans[0]
    (cycle1 / "campaign.tfplan").write_bytes(b"plan-2")
    before_apply = len([call for call, _, _ in fake.calls if call[0] == str(provider.TOFU) and "apply" in call])
    try: boundary.effect("apply", 1, "full", grants[1].grant_commitment, d("hostile-replacement"))
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("cross-cycle approved plan replacement reached apply")
    assert len([call for call, _, _ in fake.calls if call[0] == str(provider.TOFU) and "apply" in call]) == before_apply
    try:
        boundary.effect("plan", 1, "full", grants[1].grant_commitment, d("second"))
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("effect replay was accepted")

    inventory_call_start = len(fake.calls)
    inventory_value = json.loads(boundary.inventory(1, grants[1].grant_commitment,
                                                     receipt.state_commitment))
    pages = inventory_value["pages"]
    assert {row["category"] for row in pages} == set(production.INVENTORY_CATEGORIES)
    assert len([row for row in pages if row["category"] == "ec2_instances"]) == 2
    assert len([row for row in pages if row["category"] == "elastic_ips"]) == 1
    for category in ("network_interfaces", "eni_public_associations", "elastic_ips"):
        assert all("account-region-wide" in row["query_scope"]
                   for row in pages if row["category"] == category)
    assert all(row["response_commitment"] != "0" * 64 for row in pages)
    instance_rows = [resource for page in pages if page["category"] == "ec2_instances"
                     for resource in page["resources"]]
    assert len(instance_rows) == 1 and instance_rows[0]["disposition"] == "deleted"
    inventory_aws_calls = [call for call, _, _ in fake.calls[inventory_call_start:]
                           if call[0] == str(provider.AWS)]
    assert inventory_aws_calls and all("observer" in call for call in inventory_aws_calls)
    inventory_api_calls = [call for call in inventory_aws_calls
                           if "get-caller-identity" not in call]
    assert all(("--max-items" not in call) == any(
        operation in call for operation in ("describe-addresses", "describe-key-pairs"))
        for call in inventory_api_calls)
    calls_after_inventory = len(fake.calls)
    assert json.loads(boundary.inventory(1, grants[1].grant_commitment,
                                         receipt.state_commitment)) == inventory_value
    assert len(fake.calls) == calls_after_inventory

    # A claimed normal destroy is uncertain and may never be reissued by cleanup.
    cycle2 = provider.STATE_ROOT / "cycle-2"
    (cycle2 / "destroy.intent.json").write_bytes(raw({"claimed": True}))
    before = len([call for call, _, _ in fake.calls if call[0] == str(provider.TOFU)])
    cleanup = json.loads(boundary.recover(2, "readiness", grants[2].grant_commitment,
                                          d("state-2")))
    after = len([call for call, _, _ in fake.calls if call[0] == str(provider.TOFU)])
    assert cleanup["normal_destroy_reissued"] is False and cleanup["certain_zero"] is True
    # Reconciliation reuses the same local backend and has one cleanup destroy;
    # its explicit backend init is not a second normal destroy.
    assert after == before + 2
    cleanup_commands = [call for call, _, _ in fake.calls if call[0] == str(provider.TOFU)
                        and "destroy" in call]
    assert len(cleanup_commands) == 1
    second_cleanup = json.loads(boundary.recover(
        2, "readiness", grants[2].grant_commitment, d("state-2")))
    assert second_cleanup["certain_zero"] is True
    assert len([call for call, _, _ in fake.calls if call[0] == str(provider.TOFU)
                and "destroy" in call]) == 1

    # Cross-cycle and caller-selected authority are rejected before a command.
    try: boundary.inventory(8, grants[1].grant_commitment, d("state"))
    except provider.ProviderBoundaryError: pass
    else: raise AssertionError("caller-selected final grant accepted")

# Real process custody is exercised only with local Python children: no provider,
# network, inventory, deployment, or cloud command is reachable.
with tempfile.TemporaryDirectory() as temporary:
    original = provider.SOURCE, provider.ENV, provider.MAX_OUTPUT
    provider.SOURCE = Path(temporary)
    provider.ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    provider.MAX_OUTPUT = 64
    try:
        completed = provider.subprocess_runner(
            (sys.executable, "-I", "-c", "import os;os.write(1,b'x'*64)"), 5)
        assert completed.returncode == 0 and completed.stdout == b"x" * 64 and not completed.stderr
        try: provider.subprocess_runner(
            (sys.executable, "-I", "-c", "import os;os.write(1,b'x'*65)"), 5)
        except provider.ProviderBoundaryError: pass
        else: raise AssertionError("oversized child output was retained")
        marker = Path(temporary) / "survivor"
        program = ("import os,time\npid=os.fork()\n"
                   f"if pid==0:\n time.sleep(1);open({str(marker)!r},'w').close();os._exit(0)\n"
                   "time.sleep(10)\n")
        try: provider.subprocess_runner((sys.executable, "-I", "-c", program), 0.2)
        except provider.subprocess.TimeoutExpired: pass
        else: raise AssertionError("timed-out process group returned")
        time.sleep(1.1)
        assert not marker.exists()
        cancelled_marker = Path(temporary) / "cancelled-survivor"
        cancelled_program = ("import time\n"
            f"time.sleep(1);open({str(cancelled_marker)!r},'w').close();time.sleep(10)\n")
        timer = threading.Timer(0.1, lambda: os.kill(os.getpid(), provider.signal.SIGTERM))
        timer.start()
        try:
            try: provider.subprocess_runner((sys.executable, "-I", "-c", cancelled_program), 5)
            except provider.ProviderBoundaryError: pass
            else: raise AssertionError("external cancellation returned success")
        finally: timer.cancel(); timer.join()
        time.sleep(1.1)
        assert not cancelled_marker.exists()
        original_popen = provider.subprocess.Popen
        spawned = []
        def settled(process):
            assert process.poll() is not None
            try: os.killpg(process.pid, 0)
            except ProcessLookupError: return
            raise AssertionError("provider child group survived settlement")
        def pending_spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs); spawned.append(process)
            os.kill(os.getpid(), provider.signal.SIGTERM)
            return process
        provider.subprocess.Popen = pending_spawn
        try:
            try: provider.subprocess_runner((sys.executable, "-I", "-c", "import time;time.sleep(10)"), 5)
            except provider.ProviderBoundaryError: pass
            else: raise AssertionError("pending cancellation crossed provider adoption")
        finally: provider.subprocess.Popen = original_popen
        settled(spawned.pop())
        original_selector = provider.selectors.DefaultSelector
        provider.subprocess.Popen = lambda *args, **kwargs: spawned.append(
            original_popen(*args, **kwargs)) or spawned[-1]
        provider.selectors.DefaultSelector = lambda: (_ for _ in ()).throw(OSError("selector cut"))
        try:
            try: provider.subprocess_runner((sys.executable, "-I", "-c", "import time;time.sleep(10)"), 5)
            except OSError: pass
            else: raise AssertionError("selector failure abandoned provider child")
        finally:
            provider.selectors.DefaultSelector = original_selector
            provider.subprocess.Popen = original_popen
        settled(spawned.pop())
    finally:
        provider.SOURCE, provider.ENV, provider.MAX_OUTPUT = original

print("stage2 provider-free concrete AWS boundary checks passed")

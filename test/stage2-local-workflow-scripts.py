#!/usr/bin/env python3
"""Focused hostile tests for Stage 2 local workflow custody scripts."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = load("stage2_local_guard_test", "scripts/stage2-local-qualification-guard.py")
settlement = load("stage2_local_settlement_test", "scripts/stage2-local-settlement.py")
publication = load("stage2_local_publication_test", "scripts/stage2-local-publication.py")
receipt = load("stage2_local_receipt_test", "scripts/stage2-local-upload-receipt.py")
control_staging = load("stage2_control_staging_test", "scripts/stage2-stage-reviewed-control.py")
prebuilt_staging = load("stage2_prebuilt_staging_test", "scripts/stage2-stage-prebuilt-control.py")


def rejected(call, exception):
    try:
        call()
    except exception:
        return
    raise AssertionError(f"did not reject with {exception.__name__}")


def guard_tests():
    guard._reviewed_constants()
    reviewed_head = guard.REVIEWED_IMPLEMENTATION_HEAD
    guard.REVIEWED_IMPLEMENTATION_HEAD = None
    rejected(guard._reviewed_constants, guard.GuardError)
    guard.REVIEWED_IMPLEMENTATION_HEAD = reviewed_head
    old = tuple(getattr(guard, name) for name in (
        "REVIEWED_IMPLEMENTATION_HEAD", "REVIEWED_IMPLEMENTATION_MANIFEST_SHA256",
        "REVIEWED_CONTROL_SHA256", "REVIEWED_WORKFLOW_SHA256",
        "REVIEWED_RESULT_SCHEMA_SHA256", "CONTROL", "WORKFLOW",
    ))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        control, workflow = root / "control.json", root / "workflow.yml"
        control.write_bytes(b"control\n")
        workflow.write_bytes(b"workflow\n")
        h, g, digest = "1" * 40, "2" * 40, "3" * 64
        try:
            guard.REVIEWED_IMPLEMENTATION_HEAD = h
            guard.REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = digest
            guard.REVIEWED_CONTROL_SHA256 = hashlib.sha256(control.read_bytes()).hexdigest()
            guard.REVIEWED_WORKFLOW_SHA256 = hashlib.sha256(workflow.read_bytes()).hexdigest()
            guard.REVIEWED_RESULT_SCHEMA_SHA256 = "4" * 64
            guard.CONTROL, guard.WORKFLOW = control, workflow
            environment = {
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": guard.REPOSITORY,
                "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "71", "GITHUB_SHA": g,
                "PRE_EFFECT_ADMITTED_RUN_ID": "71",
                "GITHUB_ACTOR": "reviewer", "CONFIGURED_AUTHORIZED_ACTOR": "reviewer",
                "CONFIGURED_IMPLEMENTATION_HEAD": h, "CONFIGURED_CONTROL_HEAD": g,
                "EXACT_IMPLEMENTATION_HEAD": h, "EXACT_CONTROL_HEAD": g,
                "GITHUB_WORKFLOW_REF": (
                    f"{guard.REPOSITORY}/.github/workflows/{guard.WORKFLOW_NAME}@refs/heads/main"),
            }
            event = {"repository": {"full_name": guard.REPOSITORY}, "inputs": {
                "reviewed_implementation_head": h, "reviewed_control_head": g}}
            value = guard.guard(environment, event=event, first_created=71)
            assert value["implementation_head"] == h and value["control_head"] == g
            rejected(lambda: guard.guard({**environment, "GITHUB_RUN_ATTEMPT": "2"},
                                         event=event, first_created=71), guard.GuardError)
            rejected(lambda: guard.guard({key: value for key, value in environment.items()
                                          if key != "PRE_EFFECT_ADMITTED_RUN_ID"},
                                         event=event), guard.GuardError)
            rejected(lambda: guard.guard({**environment, "PRE_EFFECT_ADMITTED_RUN_ID": "70"},
                                         event=event), guard.GuardError)
            rejected(lambda: guard.guard({**environment, "AWS_ACCESS_KEY_ID": "x"},
                                         event=event, first_created=71), guard.GuardError)
            rejected(lambda: guard.guard(environment, event=event, first_created=70), guard.GuardError)
            rejected(lambda: guard.guard(environment, event={**event, "repository": {
                "full_name": "fork/cogs"}}, first_created=71), guard.GuardError)
        finally:
            names = (
                "REVIEWED_IMPLEMENTATION_HEAD", "REVIEWED_IMPLEMENTATION_MANIFEST_SHA256",
                "REVIEWED_CONTROL_SHA256", "REVIEWED_WORKFLOW_SHA256",
                "REVIEWED_RESULT_SCHEMA_SHA256", "CONTROL", "WORKFLOW",
            )
            for name, value in zip(names, old, strict=True):
                setattr(guard, name, value)



def publication_tests():
    raw = (ROOT / "test/fixtures/stage2-completion/local-result-v2-pass.json").read_bytes()
    value = json.loads(raw)
    schema = ROOT / "schemas/stage2-workload-local-qualification-v2.json"
    original = publication.IMPLEMENTATION_SOURCE
    try:
        publication.IMPLEMENTATION_SOURCE = ROOT
        observed = publication._validate(
            raw, value["bindings"]["source_head"], value["bindings"]["source_manifest_sha256"],
            hashlib.sha256(schema.read_bytes()).hexdigest())
        assert observed["qualified"] is True
        rejected(lambda: publication._validate(
            raw, "f" * 40, value["bindings"]["source_manifest_sha256"],
            hashlib.sha256(schema.read_bytes()).hexdigest()), publication.LocalPublicationError)
        rejected(lambda: publication._validate(
            raw, value["bindings"]["source_head"], value["bindings"]["source_manifest_sha256"],
            "f" * 64), publication.LocalPublicationError)
        changed = raw.replace(b'"qualified":true', b'"qualified":false')
        rejected(lambda: publication._validate(
            changed, value["bindings"]["source_head"], value["bindings"]["source_manifest_sha256"],
            hashlib.sha256(schema.read_bytes()).hexdigest()), publication.LocalPublicationError)
    finally:
        publication.IMPLEMENTATION_SOURCE = original


def receipt_environment(value):
    h, g, run = value["bindings"]["source_head"], "5" * 40, "71"
    raw = (ROOT / "test/fixtures/stage2-completion/local-result-v2-pass.json").read_bytes()
    suffix = f"{h}-{g}-{run}-1"
    return raw, {
        "EXPECTED_IMPLEMENTATION_HEAD": h,
        "EXPECTED_SOURCE_MANIFEST_SHA256": value["bindings"]["source_manifest_sha256"],
        "EXPECTED_CONTROL_HEAD": g, "EXPECTED_CONTROL_SHA256": "6" * 64,
        "EXPECTED_WORKFLOW_SHA256": "7" * 64, "EXPECTED_RESULT_SCHEMA_SHA256": "8" * 64,
        "GITHUB_RUN_ID": run, "GITHUB_RUN_ATTEMPT": "1",
        "REPORT_ARTIFACT_NAME": f"stage2-local-kata-report-{suffix}",
        "RECEIPT_ARTIFACT_NAME": f"stage2-local-kata-upload-receipt-{suffix}",
        "REPORT_ARTIFACT_ID": "91", "REPORT_ARTIFACT_DIGEST": "9" * 64,
        "REPORT_SHA256": hashlib.sha256(raw).hexdigest(), "REPORT_BYTES": str(len(raw)),
        "REPORT_RESULT": "pass", "FAILURE_CODE": "none", "ENTRY_OUTCOME": "success",
    }


def receipt_tests():
    raw = (ROOT / "test/fixtures/stage2-completion/local-result-v2-pass.json").read_bytes()
    value = json.loads(raw)
    raw, environment = receipt_environment(value)
    expected = receipt.context(environment)
    encoded = receipt.encode(expected, raw)
    observed = receipt.validate_receipt(encoded, expected, raw)
    assert observed["promotion_authorized"] is False
    assert observed["outcomes"]["private_receipt_consumed"] == "success"
    assert observed["run"] == {"attempt": 1, "first_created": True, "id": 71}
    rejected(lambda: receipt.context({**environment, "GITHUB_RUN_ATTEMPT": "2"}),
             receipt.LocalReceiptError)
    rejected(lambda: receipt.context({**environment, "ENTRY_OUTCOME": "failure"}),
             receipt.LocalReceiptError)
    rejected(lambda: receipt.validate_report(b"X" + raw[1:], expected), receipt.LocalReceiptError)
    duplicate = encoded.replace(b'{"artifact":', b'{"artifact":{},"artifact":', 1)
    rejected(lambda: receipt.validate_receipt(duplicate, expected, raw), receipt.LocalReceiptError)
    swapped = replace(expected, artifact_id=92)
    rejected(lambda: receipt.validate_receipt(encoded, swapped, raw), receipt.LocalReceiptError)

    failure_raw = (ROOT / "test/fixtures/stage2-completion/local-result-v2-failure.json").read_bytes()
    failure_value = json.loads(failure_raw)
    _unused, failure_environment = receipt_environment(failure_value)
    failure_environment.update({
        "REPORT_SHA256": hashlib.sha256(failure_raw).hexdigest(),
        "REPORT_BYTES": str(len(failure_raw)), "REPORT_RESULT": "failure",
        "FAILURE_CODE": failure_value["failure_code"], "ENTRY_OUTCOME": "failure",
    })
    failure_expected = receipt.context(failure_environment)
    failure_receipt = receipt.encode(failure_expected, failure_raw)
    assert receipt.validate_receipt(
        failure_receipt, failure_expected, failure_raw)["report"]["result"] == "failure"
    rejected(lambda: receipt.context({**failure_environment, "ENTRY_OUTCOME": "success"}),
             receipt.LocalReceiptError)


def control_staging_tests():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "contracts").mkdir()
        (root / "control.json").write_bytes(b"control\n")
        (root / "contracts/tool.json").write_bytes(b"tool\n")
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            assert control_staging._read_regular(descriptor, "control.json", 32) == b"control\n"
            assert control_staging._read_regular(descriptor, "contracts/tool.json", 32) == b"tool\n"
            rejected(lambda: control_staging._read_regular(descriptor, "../control.json", 32),
                     control_staging.ControlStagingError)
            (root / "link").symlink_to("control.json")
            rejected(lambda: control_staging._read_regular(descriptor, "link", 32), OSError)
            (root / "linked-contracts").symlink_to("contracts", target_is_directory=True)
            rejected(lambda: control_staging._read_regular(
                descriptor, "linked-contracts/tool.json", 32), OSError)
        finally:
            os.close(descriptor)


def settlement_linux_tail_tests():
    if os.environ.get("COGS_REQUIRE_STAGE2_LOCAL_SETTLEMENT_LINUX") != "1":
        return
    assert sys.platform.startswith("linux") and os.geteuid() == 0
    environment = {
        "GITHUB_RUN_ID": "900000291", "GITHUB_RUN_ATTEMPT": "1",
        "REPORT_STAGING": "/var/tmp/cogs-stage2-local-result-900000291-1",
        "REPORT_READBACK_STAGING": "/var/tmp/cogs-stage2-local-result-upload-900000291-1",
        "RECEIPT_READBACK_STAGING": "/var/tmp/cogs-stage2-local-receipt-upload-900000291-1",
    }
    for name in ("REPORT_STAGING", "REPORT_READBACK_STAGING", "RECEIPT_READBACK_STAGING"):
        assert os.environ.get(name) == environment[name]
    fixed = Path("/var/lib/cogs")
    assert not fixed.exists() and not Path("/opt/kata").exists()
    custody = fixed / "stage2-prebuilt-rootfs-descriptor-v1"
    custody.mkdir(mode=0o700, parents=True)
    for name in ("descriptor.json", "rootfs.package.json", "rootfs.provenance.json",
                 "producer-receipt.json", "publication-receipt.json", "cosign-verification.json"):
        path = custody / name
        path.write_bytes(name.encode("ascii"))
        path.chmod(0o400)
    sibling = subprocess.Popen([
        sys.executable, "-c", "import time;time.sleep(30)",
        "cogs-stage2-local-tail-sibling",
    ])
    try:
        time.sleep(0.05)
        rejected(settlement._scan_fixed, settlement.LocalSettlementError)
    finally:
        sibling.terminate()
        try: sibling.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sibling.kill(); sibling.wait(timeout=5)
    settlement.cleanup({**environment, "RECOVERY_OUTCOME": "success"})
    assert not any(os.path.lexists(path) for path in settlement.FIXED_ROOTS)
    settlement.residue(environment)


def settlement_tests():
    environment = {
        "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1",
        "REPORT_STAGING": "/var/tmp/cogs-stage2-local-result-71-1",
        "REPORT_READBACK_STAGING": "/var/tmp/cogs-stage2-local-result-upload-71-1",
        "RECEIPT_READBACK_STAGING": "/var/tmp/cogs-stage2-local-receipt-upload-71-1",
    }
    assert settlement._run_paths(environment)[0].endswith("result-71-1")
    rejected(lambda: settlement._run_paths({**environment, "GITHUB_RUN_ATTEMPT": "2"}),
             settlement.LocalSettlementError)
    rejected(lambda: settlement.cleanup({**environment, "RECOVERY_OUTCOME": "failure"}),
             settlement.LocalSettlementError)
    identity = type("Identity", (), {"st_mode": stat.S_IFREG | 0o400,
                                      "st_uid": 0, "st_gid": 0, "st_nlink": 1})()
    assert settlement._valid_cleanup_root(settlement.MARKER_ROOTS[0], identity)
    identity.st_mode = stat.S_IFDIR | 0o700
    assert not settlement._valid_cleanup_root(settlement.MARKER_ROOTS[0], identity)

    payload = ("\n".join((*environment.values(), "success")) + "\n").encode()
    reads, executed = [payload, b""], []
    old_read, old_euid, old_execve = settlement.os.read, settlement.os.geteuid, settlement.os.execve
    class Executed(Exception):
        pass
    try:
        settlement.os.read = lambda _descriptor, _maximum: reads.pop(0)
        settlement.os.geteuid = lambda: 0
        def execute(path, command, child_environment):
            executed.append((path, command, child_environment))
            raise Executed()
        settlement.os.execve = execute
        rejected(lambda: settlement.supervise("cleanup"), Executed)
    finally:
        settlement.os.read, settlement.os.geteuid = old_read, old_euid
        settlement.os.execve = old_execve
    assert executed[0][0] == "/usr/bin/timeout" and executed[0][1][-1] == "cleanup"
    assert executed[0][2] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                              **environment, "RECOVERY_OUTCOME": "success"}
    assert settlement.RESIDUE_NAME.search("cogs-stage2-net")
    constants = settlement._network_state.__code__.co_consts
    assert ("/usr/sbin/ip", "-j", "link", "show") in constants
    assert ("/usr/sbin/ip", "-j", "-details", "link", "show") not in constants
    assert ("/usr/sbin/ip", "-j", "netns", "list") not in constants

    links = settlement._bounded_json(
        b'[{"ifindex":2,"ifname":"eth0"},{"ifindex":7,"ifname":"c42habcdef0123"}]')
    assert settlement._interface_names(links)[-1] == "c42habcdef0123"
    netns = settlement._bounded_json(
        b'[{"name":"c42nabcdef0123","id":4},{"name":"c42qabcdef0123"}]')
    assert settlement._netns_names(netns) == ("c42nabcdef0123", "c42qabcdef0123")
    nft = settlement._bounded_json(
        b'{"nftables":[{"metainfo":{"json_schema_version":1}},'
        b'{"table":{"family":"inet","name":"c42tabcdef0123"}}]}')
    assert settlement._nft_table_names(nft) == ("c42tabcdef0123",)
    tc = settlement._bounded_json(
        b'[{"kind":"u32","options":{"actions":[{"to_dev":"c42habcdef0123"}]}}]')
    assert "c42habcdef0123" in settlement._all_strings(tc)
    rejected(lambda: settlement._bounded_json(b'{"x":1,"x":2}'),
             settlement.LocalSettlementError)
    too_deep = b"[" * (settlement.MAX_JSON_DEPTH + 2) + b"0" + b"]" * (
        settlement.MAX_JSON_DEPTH + 2)
    rejected(lambda: settlement._bounded_json(too_deep), settlement.LocalSettlementError)
    parser_recursion = b"[" * 10_000 + b"0" + b"]" * 10_000
    rejected(lambda: settlement._bounded_json(parser_recursion), settlement.LocalSettlementError)
    for stage in settlement._SETTLEMENT_STAGES:
        settlement._SETTLEMENT_STAGE = stage
        assert settlement._safe_diagnostic() == f"local settlement failed at {stage}\n"
    settlement._SETTLEMENT_STAGE = "hostile-unbounded-value"
    assert settlement._safe_diagnostic() == "local settlement failed at entry\n"
    rejected(lambda: settlement._interface_names([{"ifname": "eth0"}] * 2),
             settlement.LocalSettlementError)


def prebuilt_staging_linux_tests():
    if os.environ.get("COGS_REQUIRE_STAGE2_LOCAL_SETTLEMENT_LINUX") != "1": return
    assert os.geteuid() == 0 and hasattr(os, "fork") and hasattr(os, "setuid")
    original = (prebuilt_staging.SOURCE, prebuilt_staging.DESTINATION,
                prebuilt_staging.H_PREPARATION)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        prebuilt_staging.SOURCE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v4"
        prebuilt_staging.DESTINATION = root / "control"
        prebuilt_staging.H_PREPARATION = ROOT / "deploy/aws-feasibility/remote/completion_kata_preparation.py"
        try:
            assert prebuilt_staging.stage() == "80a962f87f35cf1653894168ebe32139d7d32bc0a21f89cf028ac02a67976fc8"
            expected = "b71c98f1721aca58328f92cdf61408038d3d10465361b84702c555b908ef5876"
            assert prebuilt_staging.verify_staged(expected) == expected
            descriptor_count = len(os.listdir("/proc/self/fd"))
            child = os.fork()
            if child == 0:
                try:
                    os.setgid(65534); os.setuid(65534)
                    (prebuilt_staging.DESTINATION / "stage2-local-execution-envelope-v3.json").read_bytes()
                    os._exit(1)
                except PermissionError: os._exit(0)
                except BaseException: os._exit(2)
            _, status_value = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status_value) == 0
            envelope = prebuilt_staging.DESTINATION / "stage2-local-execution-envelope-v3.json"
            os.chmod(envelope, 0o600)
            rejected(lambda: prebuilt_staging.verify_staged(expected),
                     prebuilt_staging.ControlStagingError)
            os.chmod(envelope, 0o400)
            rejected(lambda: prebuilt_staging.verify_staged("f" * 64),
                     prebuilt_staging.ControlStagingError)
            alias = root / "alias"; os.link(envelope, alias)
            rejected(lambda: prebuilt_staging.verify_staged(expected),
                     prebuilt_staging.ControlStagingError)
            alias.unlink()
            raw = envelope.read_bytes(); envelope.unlink(); envelope.symlink_to("missing")
            rejected(lambda: prebuilt_staging.verify_staged(expected), OSError)
            envelope.unlink(); envelope.write_bytes(raw); os.chown(envelope, 0, 0); os.chmod(envelope, 0o400)
            contracts = prebuilt_staging.DESTINATION / "contracts"
            os.chmod(contracts, 0o700)
            rejected(lambda: prebuilt_staging.verify_staged(expected),
                     prebuilt_staging.ControlStagingError)
            os.chmod(contracts, 0o500)
            extra = prebuilt_staging.DESTINATION / "extra"; extra.write_bytes(b"x"); os.chmod(extra, 0o400)
            rejected(lambda: prebuilt_staging.verify_staged(expected),
                     prebuilt_staging.ControlStagingError)
            extra.unlink()
            control = prebuilt_staging.DESTINATION / prebuilt_staging.CONTROL_MEMBER
            control_alias = root / "control-alias"; os.link(control, control_alias)
            rejected(lambda: prebuilt_staging.verify_staged(expected),
                     prebuilt_staging.ControlStagingError)
            control_alias.unlink()
            old_read, calls = prebuilt_staging._read_complete, 0
            def raced(descriptor, size):
                nonlocal calls
                value = old_read(descriptor, size); calls += 1
                if calls == 2: os.chmod(control, 0o600)
                return value
            prebuilt_staging._read_complete = raced
            try:
                rejected(lambda: prebuilt_staging.verify_staged(expected),
                         prebuilt_staging.ControlStagingError)
            finally:
                prebuilt_staging._read_complete = old_read; os.chmod(control, 0o400)
            rejected(lambda: prebuilt_staging.verify_staged(expected, True), OSError)
            rejected(lambda: prebuilt_staging.verify_staged(None),
                     prebuilt_staging.ControlStagingError)
            codec = type("Codec", (), {"MAX_ENVELOPE_BYTES": 4,
                                        "MAX_RUNTIME_BYTES": 4, "MAX_CONTRACT_BYTES": 4})()
            assert prebuilt_staging._member_maximum(
                codec, {"kind": "envelope", "size": 4}, False) == 4
            rejected(lambda: prebuilt_staging._member_maximum(
                codec, {"kind": "envelope", "size": 5}, False),
                prebuilt_staging.ControlStagingError)
            assert prebuilt_staging.verify_staged(expected) == expected
            assert len(os.listdir("/proc/self/fd")) == descriptor_count
            cli = subprocess.run((sys.executable, "-I", "-B", str(
                ROOT / "scripts/stage2-stage-prebuilt-control.py"), "verify", "bad"),
                capture_output=True, check=False)
            assert cli.returncode == 2 and cli.stdout == cli.stderr == b""
        finally:
            (prebuilt_staging.SOURCE, prebuilt_staging.DESTINATION,
             prebuilt_staging.H_PREPARATION) = original


guard_tests()
publication_tests()
receipt_tests()
control_staging_tests()
settlement_tests()
settlement_linux_tail_tests()
prebuilt_staging_linux_tests()
print("stage2 local workflow script tests passed")

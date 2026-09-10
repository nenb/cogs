#!/usr/bin/env python3
"""Focused hostile tests for Stage 2 local workflow custody scripts."""
from dataclasses import replace
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import time
import types

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
opt_mode = load("stage2_hosted_opt_mode_test", "scripts/stage2-hosted-opt-mode.py")


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
                prebuilt_staging.H_PREPARATION, prebuilt_staging.retirement["select"],
                prebuilt_staging._load_module)
    base = Path("/root/cogs-stage2-bootstrap")
    parts = [base, base / "Q", base / "Q/deploy", base / "Q/deploy/aws-feasibility",
             base / "Q/deploy/aws-feasibility/remote", prebuilt_staging.QUALIFICATION_SOURCE]
    assert not os.path.lexists(base)
    for path in parts: path.mkdir(); os.chmod(path, 0o700)
    descriptor = prebuilt_staging._open_source(prebuilt_staging.QUALIFICATION_SOURCE); os.close(descriptor)
    os.chmod(parts[-2], 0o755)
    rejected(lambda: prebuilt_staging._open_source(prebuilt_staging.QUALIFICATION_SOURCE),
             prebuilt_staging.ControlStagingError)
    os.chmod(parts[-2], 0o700)
    for path in reversed(parts): path.rmdir()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        prebuilt_staging.SOURCE = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v4"
        prebuilt_staging.DESTINATION = root / "control"
        prebuilt_staging.H_PREPARATION = ROOT / "deploy/aws-feasibility/remote/completion_kata_preparation.py"
        # First prove the real selector rejects this retired archive. The exact
        # test-only codec adapter restores the historical mandatory-source set;
        # current production remains strict and v6-only.
        historical_codec = original[4](
            prebuilt_staging.H_PREPARATION, "completion_kata_preparation_historical_test")
        historical_envelope = json.loads((prebuilt_staging.SOURCE /
            "stage2-local-execution-envelope-v3.json").read_bytes())
        historical_paths = frozenset(row["path"] for row in
                                     historical_envelope["implementation"]["selected_sources"])
        assert len(historical_paths) == len(historical_envelope["implementation"]["selected_sources"])
        historical_codec.MANDATORY_SECURITY_SOURCES = historical_paths
        def archival_codec(path, name):
            if path == prebuilt_staging.H_PREPARATION:
                assert name in {"completion_kata_preparation_staging",
                                "completion_kata_control_verification"}
                return historical_codec
            return original[4](path, name)
        prebuilt_staging._load_module = archival_codec
        try:
            rejected(lambda: prebuilt_staging.stage(), prebuilt_staging.retirement["RetirementError"])
            original_select = prebuilt_staging.retirement["select"]
            fixture_h = "229ea62bce964086726181974a6fec1c6dfd1f86"
            fixture_g = "821149ba4c3dbccef48694efcdb1eb29fa9fd2b9"
            fixture_revisions = (fixture_h, fixture_g, fixture_g, fixture_h,
                                 fixture_h, fixture_h, fixture_h)
            fixture_runs = ("33980034976", "33987181596", "33980034976", "33980034976")
            fixture_artifacts = ("9973726406",)
            def archival_fixture_select(revisions, runs=(), artifacts=(), **kwargs):
                assert type(revisions) is tuple and revisions == fixture_revisions
                assert type(runs) is tuple and runs == fixture_runs
                assert type(artifacts) is tuple and artifacts == fixture_artifacts and not kwargs
                return original_select(tuple("f" * 40 for _ in revisions),
                    runs=tuple("1" for _ in runs), artifacts=tuple("1" for _ in artifacts))
            prebuilt_staging.retirement["select"] = archival_fixture_select
            assert prebuilt_staging.stage() == "80a962f87f35cf1653894168ebe32139d7d32bc0a21f89cf028ac02a67976fc8"
            expected = "b71c98f1721aca58328f92cdf61408038d3d10465361b84702c555b908ef5876"
            assert prebuilt_staging.verify_staged(expected) == expected
            envelope = prebuilt_staging.DESTINATION / "stage2-local-execution-envelope-v3.json"
            directory = os.open(prebuilt_staging.DESTINATION, os.O_RDONLY | os.O_DIRECTORY)
            os.chmod(envelope, 0o600)
            assert prebuilt_staging._read_regular(directory, envelope.name, 1 << 20, True)
            os.chmod(envelope, 0o644)
            rejected(lambda: prebuilt_staging._read_regular(directory, envelope.name, 1 << 20, True),
                     prebuilt_staging.ControlStagingError)
            os.chmod(envelope, 0o400); os.close(directory)
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
             prebuilt_staging.H_PREPARATION, prebuilt_staging.retirement["select"],
             prebuilt_staging._load_module) = original


def prebuilt_host_check_tests():
    class Description:
        def __init__(self, value):
            self.value = value
            self.raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    host = Path("/bin/sh")
    raw, seen = host.read_bytes(), host.stat()
    item = {"path": str(host), "size": seen.st_size}
    roles = ("ip", "tc", "nft", "ssh", "ssh-keygen")
    rows = [{"role": role, "source_class": "host-path", "path": str(host)} for role in roles]
    contracts = {role: Description({"objects": [item]}) for role in roles}
    publication = {"control_revision": "e" * 40, "implementation_revision": "f" * 40,
        "producer_run_id": 1, "publisher_run_id": 2, "producer_artifact_id": 3}
    custody = {"publication_receipt": publication,
        "provenance": {"builder": {"implementation_revision": "f" * 40, "run_id": 1}},
        "qualification_receipt": {"implementation_revision": "f" * 40, "run_id": 1}}
    rootfs = {"custody": custody, "prebuilt_descriptor": {"producer": {"revision": "f" * 40}}}
    control = Description({"implementation": {"revision": "f" * 40},
        "producer": {"control_revision": "e" * 40}, "members": []})
    envelope = Description({"rootfs": rootfs})
    runtime = Description({"executables": rows})
    codec = type("Codec", (), {"MAX_CONTROL_BYTES": 4096,
        "load_control": lambda _self, _raw: control,
        "validate_control_members": lambda _self, _control, _members: (envelope, runtime, contracts)})()
    def retain(contract, descriptors, role):
        descriptor = os.open(contract["objects"][0]["path"], os.O_RDONLY)
        descriptors.append(descriptor); value = os.fstat(descriptor)
        retained = type("Retained", (), dict(descriptor=descriptor, device=value.st_dev,
            inode=value.st_ino, mode=stat.S_IMODE(value.st_mode), uid=value.st_uid,
            gid=value.st_gid, nlink=value.st_nlink, size=value.st_size,
            sha256=hashlib.sha256(raw).hexdigest()))()
        return (retained,)
    admission = type("Admission", (), {"_retain_contract_objects": staticmethod(retain),
        "_read_held": staticmethod(lambda _fd, _seen, _size: hashlib.sha256(raw).hexdigest())})()
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary); control_raw = b"{}\n"
        (source / prebuilt_staging.CONTROL_MEMBER).write_bytes(control_raw)
        original = (prebuilt_staging.SOURCE, prebuilt_staging._load_module,
                    prebuilt_staging._load_admission, prebuilt_staging.os.geteuid)
        prebuilt_staging.SOURCE = source
        prebuilt_staging._load_module = lambda *_: codec
        prebuilt_staging._load_admission = lambda: admission
        prebuilt_staging.os.geteuid = lambda: 1000
        arguments = ("f" * 40, "e" * 40, hashlib.sha256(control_raw).hexdigest())
        try:
            prebuilt_staging.verify_host_closures(*arguments)
            admission._read_held = lambda *_: "0" * 64
            rejected(lambda: prebuilt_staging.verify_host_closures(*arguments),
                     prebuilt_staging.ControlStagingError)
            admission._read_held = lambda *_: hashlib.sha256(raw).hexdigest()
            custody["provenance"]["builder"]["run_id"] = 34375934829
            rejected(lambda: prebuilt_staging.verify_host_closures(*arguments),
                     prebuilt_staging.retirement["RetirementError"])
        finally:
            (prebuilt_staging.SOURCE, prebuilt_staging._load_module,
             prebuilt_staging._load_admission, prebuilt_staging.os.geteuid) = original
    remote_source = str(prebuilt_staging.CHECKOUT_ADMISSION.parent)
    sys.path.insert(0, remote_source)
    try:
        reader = load("completion_kata_admission", prebuilt_staging.CHECKOUT_ADMISSION.relative_to(ROOT))
    finally:
        sys.path.remove(remote_source)
    fd_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
    with tempfile.TemporaryDirectory() as temporary:
        untrusted = Path(temporary) / "file"; untrusted.write_bytes(b"x")
        descriptor_count = len(os.listdir(fd_root))
        rejected(lambda: reader._open_trusted_absolute_regular(str(untrusted), 1),
                 reader.AdmissionError)
        assert len(os.listdir(fd_root)) == descriptor_count
    real_reader_os = reader.os
    reader.os = types.SimpleNamespace(**vars(real_reader_os))
    calls = 0
    def failing_fstat(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2: raise OSError("synthetic directory fstat refusal")
        return real_reader_os.fstat(descriptor)
    reader.os.fstat = failing_fstat
    descriptor_count = len(os.listdir(fd_root))
    try:
        rejected(lambda: reader._open_trusted_absolute_regular("/usr/bin/env", 1024 * 1024), OSError)
        assert len(os.listdir(fd_root)) == descriptor_count
    finally:
        reader.os = real_reader_os
    reader.os = types.SimpleNamespace(**vars(real_reader_os))
    reader.os.dup = lambda _descriptor: (_ for _ in ()).throw(
        OSError("synthetic initial duplication refusal"))
    descriptor_count = len(os.listdir(fd_root))
    try:
        rejected(lambda: reader._open_trusted_absolute_regular("/usr/bin/env", 1024 * 1024), OSError)
        assert len(os.listdir(fd_root)) == descriptor_count
    finally:
        reader.os = real_reader_os
    real_stager_os = prebuilt_staging.os
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary); (base / "nested").mkdir(); (base / "nested/file").write_bytes(b"x")
        directory = real_stager_os.open(base, real_stager_os.O_RDONLY | real_stager_os.O_DIRECTORY)
        prebuilt_staging.os = types.SimpleNamespace(**vars(real_stager_os))
        prebuilt_staging.os.fstat = lambda _descriptor: (_ for _ in ()).throw(
            OSError("synthetic member-directory fstat refusal"))
        descriptor_count = len(real_stager_os.listdir(fd_root))
        try:
            rejected(lambda: prebuilt_staging._read_regular(directory, "nested/file", 1), OSError)
            assert len(real_stager_os.listdir(fd_root)) == descriptor_count
        finally:
            prebuilt_staging.os = real_stager_os; real_stager_os.close(directory)
    original_qualification_source = prebuilt_staging.QUALIFICATION_SOURCE
    prebuilt_staging.os = types.SimpleNamespace(**vars(real_stager_os))
    source_fstats = 0
    def source_fstat(descriptor):
        nonlocal source_fstats
        source_fstats += 1
        if source_fstats == 2: raise OSError("synthetic source-child fstat refusal")
        return real_stager_os.fstat(descriptor)
    prebuilt_staging.os.fstat = source_fstat
    prebuilt_staging.QUALIFICATION_SOURCE = Path("/usr/bin/cogs-stage2-unreached")
    descriptor_count = len(real_stager_os.listdir(fd_root))
    try:
        rejected(lambda: prebuilt_staging._open_source(prebuilt_staging.QUALIFICATION_SOURCE), OSError)
        assert len(real_stager_os.listdir(fd_root)) == descriptor_count
    finally:
        prebuilt_staging.os = real_stager_os
        prebuilt_staging.QUALIFICATION_SOURCE = original_qualification_source
    class EmptyControl:
        value = {"members": []}
    class EmptyEnvelope:
        value = {"rootfs": {"prebuilt_descriptor_sha256": "7" * 64}}
    empty_codec = type("EmptyCodec", (), {"MAX_CONTROL_BYTES": 16,
        "load_control": staticmethod(lambda _raw: EmptyControl()),
        "validate_control_members": staticmethod(lambda _control, _members: (EmptyEnvelope(), None, None))})()
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary); (destination / prebuilt_staging.CONTROL_MEMBER).write_bytes(b"{}\n")
        (destination / "contracts").mkdir()
        original_verify = (prebuilt_staging.DESTINATION, prebuilt_staging._load_module,
                           prebuilt_staging._read_frozen, prebuilt_staging.os)
        for fail_at in (1, 2):
            prebuilt_staging.DESTINATION = destination
            prebuilt_staging._load_module = lambda *_: empty_codec
            prebuilt_staging._read_frozen = lambda *_: b"{}\n"
            prebuilt_staging.os = types.SimpleNamespace(**vars(real_stager_os))
            prebuilt_staging.os.geteuid = lambda: 0
            verify_fstats = 0
            def verify_fstat(descriptor):
                nonlocal verify_fstats
                verify_fstats += 1
                if verify_fstats == fail_at: raise OSError("synthetic staged-directory fstat refusal")
                seen = real_stager_os.fstat(descriptor)
                values = {name: getattr(seen, name) for name in dir(seen) if name.startswith("st_")}
                values.update(st_uid=0, st_gid=0,
                    st_mode=stat.S_IFDIR | 0o500)
                return types.SimpleNamespace(**values)
            prebuilt_staging.os.fstat = verify_fstat
            descriptor_count = len(real_stager_os.listdir(fd_root))
            rejected(lambda: prebuilt_staging.verify_staged("7" * 64), OSError)
            assert len(real_stager_os.listdir(fd_root)) == descriptor_count
        (prebuilt_staging.DESTINATION, prebuilt_staging._load_module,
         prebuilt_staging._read_frozen, prebuilt_staging.os) = original_verify
    historical = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v6"
    control_raw = (historical / prebuilt_staging.CONTROL_MEMBER).read_bytes()
    control_value = json.loads(control_raw)
    envelope_value = json.loads((historical / "stage2-local-execution-envelope-v3.json").read_bytes())
    rootfs = envelope_value["rootfs"]; custody = rootfs["custody"]
    publication = custody["publication_receipt"]
    selected = (control_value["implementation"]["revision"], control_value["producer"]["control_revision"],
        publication["control_revision"], rootfs["prebuilt_descriptor"]["producer"]["revision"],
        custody["provenance"]["builder"]["implementation_revision"],
        custody["qualification_receipt"]["implementation_revision"], publication["implementation_revision"])
    expected_runs = (str(publication["producer_run_id"]), str(publication["publisher_run_id"]),
        str(custody["provenance"]["builder"]["run_id"]), str(custody["qualification_receipt"]["run_id"]))
    expected_artifacts = (str(publication["producer_artifact_id"]),)
    original = (prebuilt_staging.SOURCE, prebuilt_staging.os.geteuid,
                prebuilt_staging.retirement["select"], prebuilt_staging._load_module)
    real_load = prebuilt_staging._load_module
    def historical_load(*arguments):
        module = real_load(*arguments)
        module.MANDATORY_SECURITY_SOURCES = frozenset(
            path for path in module.MANDATORY_SECURITY_SOURCES
            if path != "scripts/stage2-hosted-opt-mode.py")
        return module
    prebuilt_staging.SOURCE = historical; prebuilt_staging.os.geteuid = lambda: 1000
    try:
        rejected(lambda: prebuilt_staging.retirement["select"](
            selected, runs=expected_runs, artifacts=expected_artifacts),
            prebuilt_staging.retirement["RetirementError"])
        def historical_only(revisions, runs=(), artifacts=(), **kwargs):
            assert tuple(revisions) == selected and tuple(runs) == expected_runs
            assert tuple(artifacts) == expected_artifacts and not kwargs
        prebuilt_staging.retirement["select"] = historical_only
        prebuilt_staging._load_module = historical_load
        try:
            prebuilt_staging.verify_host_closures(
                selected[0], selected[1], hashlib.sha256(control_raw).hexdigest())
        except Exception as error:
            if platform.system() == "Linux" and platform.machine() == "x86_64":
                assert type(error).__name__ == "AdmissionError"
                assert str(error) == "executable closure source differs"
            else:
                assert type(error).__name__ in {"AdmissionError", "PreparationError", "FileNotFoundError"}
        else:
            assert os.environ.get("RUNNER_IMAGE_VERSION", os.environ.get("ImageVersion")) == "20260831.293.1"
        if platform.system() == "Linux" and platform.machine() == "x86_64":
            codec = historical_load(prebuilt_staging.CHECKOUT_PREPARATION, "composed_host_codec")
            control_value = json.loads(control_raw)
            member_raws = {row["name"]: (historical / row["name"]).read_bytes()
                           for row in control_value["members"]}
            envelope_value = json.loads(member_raws["stage2-local-execution-envelope-v3.json"])
            runtime_value = json.loads(member_raws["stage2-local-runtime-manifest-v3.json"])
            host_rows = [row for row in runtime_value["executables"]
                         if row["source_class"] == "host-path"]
            assert [row["role"] for row in host_rows] == list(roles)
            for row in host_rows:
                value = codec.collect_executable_contract(
                    row["role"], row["path"], row["path"], lambda path: Path(path))
                raw_value = codec.canonical_bytes(value)
                member_raws[row["contract_member"]] = raw_value
                row.update(contract_sha256=hashlib.sha256(raw_value).hexdigest(),
                    executable_sha256=value["objects"][0]["sha256"],
                    tool_closure_sha256=value["closure_sha256"])
            def publish_package(destination):
                runtime_raw = codec.canonical_bytes(runtime_value)
                member_raws["stage2-local-runtime-manifest-v3.json"] = runtime_raw
                envelope_value["runtime"]["manifest_sha256"] = hashlib.sha256(runtime_raw).hexdigest()
                envelope_value["runtime"]["executable_set_sha256"] = hashlib.sha256(
                    codec.canonical_bytes(runtime_value["executables"])).hexdigest()
                envelope_raw = codec.canonical_bytes(envelope_value)
                member_raws["stage2-local-execution-envelope-v3.json"] = envelope_raw
                for row in control_value["members"]:
                    raw_value = member_raws[row["name"]]
                    row.update(size=len(raw_value), sha256=hashlib.sha256(raw_value).hexdigest())
                current_control = codec.canonical_bytes(control_value)
                for name, raw_value in member_raws.items():
                    path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw_value)
                (destination / prebuilt_staging.CONTROL_MEMBER).write_bytes(current_control)
                codec.validate_control_members(codec.load_control(current_control), member_raws)
                return current_control
            with tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary)
                current_control = publish_package(package)
                prebuilt_staging.SOURCE = package
                descriptors = len(os.listdir("/proc/self/fd"))
                expected_control = hashlib.sha256(current_control).hexdigest()
                prebuilt_staging.verify_host_closures(selected[0], selected[1], expected_control)
                assert len(os.listdir("/proc/self/fd")) == descriptors
                real_admission_loader = prebuilt_staging._load_admission
                live_admission = real_admission_loader()
                real_admission_os = live_admission.os
                live_admission.os = types.SimpleNamespace(**vars(real_admission_os))
                observations = {}; injected = False
                def unstable_fstat(descriptor):
                    nonlocal injected
                    seen = real_admission_os.fstat(descriptor)
                    identity = (seen.st_dev, seen.st_ino)
                    observations[identity] = observations.get(identity, 0) + 1
                    if stat.S_ISREG(seen.st_mode) and observations[identity] == 2 and not injected:
                        injected = True
                        values = {name: getattr(seen, name) for name in dir(seen)
                                  if name.startswith("st_")}
                        values["st_mtime_ns"] += 1
                        return types.SimpleNamespace(**values)
                    return seen
                live_admission.os.fstat = unstable_fstat
                prebuilt_staging._load_admission = lambda: live_admission
                try:
                    try:
                        prebuilt_staging.verify_host_closures(
                            selected[0], selected[1], expected_control)
                    except Exception as error:
                        assert type(error).__name__ == "AdmissionError"
                        assert str(error) == "admitted file changed while reading"
                    else:
                        raise AssertionError("during-read generation change was accepted")
                    assert injected and len(os.listdir("/proc/self/fd")) == descriptors
                finally:
                    prebuilt_staging._load_admission = real_admission_loader
                    live_admission.os = real_admission_os
                target = host_rows[-1]
                changed = json.loads(member_raws[target["contract_member"]])
                changed["objects"][-1]["sha256"] = "0" * 64
                body = {name: value for name, value in changed.items() if name != "closure_sha256"}
                changed["closure_sha256"] = hashlib.sha256(codec.canonical_bytes(body)).hexdigest()
                changed_raw = codec.canonical_bytes(changed)
                member_raws[target["contract_member"]] = changed_raw
                target.update(contract_sha256=hashlib.sha256(changed_raw).hexdigest(),
                    tool_closure_sha256=changed["closure_sha256"])
                current_control = publish_package(package)
                try:
                    prebuilt_staging.verify_host_closures(
                        selected[0], selected[1], hashlib.sha256(current_control).hexdigest())
                except Exception as error:
                    assert type(error).__name__ == "AdmissionError"
                    assert str(error) == "executable closure source differs"
                else:
                    raise AssertionError("coherently rebound library mutation was accepted")
                assert len(os.listdir("/proc/self/fd")) == descriptors
            prebuilt_staging.SOURCE = historical
            prebuilt_staging.os.geteuid = lambda: 0
            rejected(lambda: prebuilt_staging.verify_host_closures(
                selected[0], selected[1], hashlib.sha256(control_raw).hexdigest()),
                prebuilt_staging.ControlStagingError)
            prebuilt_staging.os.geteuid = lambda: 1000
    finally:
        (prebuilt_staging.SOURCE, prebuilt_staging.os.geteuid,
         prebuilt_staging.retirement["select"], prebuilt_staging._load_module) = original


def opt_mode_tests():
    helper_source = (ROOT / "scripts/stage2-hosted-opt-mode.py").read_text()
    for fixed in settlement.FIXED_ROOTS:
        if fixed != "/opt/kata": assert f'"{fixed}"' in helper_source
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        root, state = base / "opt", base / "custody.json"
        root.mkdir(mode=0o755)
        uid, gid = os.geteuid(), os.getegid()
        normalize = lambda: opt_mode.normalize("7", "1", root, state, uid, gid)
        restore = lambda run="7", attempt="1": opt_mode.restore(
            run, attempt, root, state, uid, gid)
        normalize(); assert state.is_file() and stat.S_IMODE(state.stat().st_mode) == 0o400
        assert stat.S_IMODE(root.stat().st_mode) == 0o755
        restore(); assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        os.chmod(root, 0o777)
        normalize(); assert state.is_file() and stat.S_IMODE(root.stat().st_mode) == 0o755
        rejected(lambda: restore("8"), opt_mode.OptModeError)
        assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        restore(); assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        for symlink in (False, True):
            child = root / "kata"
            child.symlink_to("missing") if symlink else child.write_text("foreign")
            rejected(normalize, opt_mode.OptModeError)
            assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
            child.unlink()
        os.chmod(root, 0o775)
        rejected(normalize, opt_mode.OptModeError)
        os.chmod(root, 0o777)
        link = base / "opt-link"; link.symlink_to(root)
        rejected(lambda: opt_mode.normalize("7", "1", link, state, uid, gid),
                 opt_mode.OptModeError)
        original_absent = opt_mode._absent
        calls = 0
        def concurrent_child(directory, name="kata"):
            nonlocal calls
            calls += 1
            if calls == 2: (root / "kata").write_text("late")
            original_absent(directory, name)
        opt_mode._absent = concurrent_child
        try:
            rejected(normalize, opt_mode.OptModeError)
            assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        finally:
            opt_mode._absent = original_absent
            (root / "kata").unlink()
        restore(); assert not state.exists()
        original_stable = opt_mode._stable_absent
        calls = 0
        def after_absence(directory, name="kata"):
            nonlocal calls
            calls += 1
            original_stable(directory, name)
            if calls == 2: (root / "kata").write_text("post-observation")
        opt_mode._stable_absent = after_absence
        try:
            rejected(normalize, opt_mode.OptModeError)
            assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        finally:
            opt_mode._stable_absent = original_stable
            (root / "kata").unlink()
        restore(); assert not state.exists()
        normalize()
        calls = 0
        opt_mode._absent = concurrent_child
        try:
            rejected(restore, opt_mode.OptModeError)
            assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        finally:
            opt_mode._absent = original_absent
            (root / "kata").unlink()
        restore(); assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        normalize()
        original_fsync = opt_mode.os.fsync
        failed = False
        root_identity = (root.stat().st_dev, root.stat().st_ino)
        def fail_opt_fsync(descriptor):
            nonlocal failed
            seen = os.fstat(descriptor)
            if not failed and (seen.st_dev, seen.st_ino) == root_identity:
                failed = True
                raise OSError("fsync fault")
            return original_fsync(descriptor)
        opt_mode.os.fsync = fail_opt_fsync
        try:
            rejected(restore, OSError)
            assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        finally:
            opt_mode.os.fsync = original_fsync
        restore(); assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        normalize()
        saved = state.read_bytes(); malformed = json.loads(saved); malformed["uid"] = False
        state.chmod(0o600); state.write_bytes(opt_mode._canonical(malformed)); state.chmod(0o400)
        rejected(restore, opt_mode.OptModeError)
        assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        state.chmod(0o600); state.write_bytes(saved); state.chmod(0o400); restore()
        rejected(lambda: opt_mode.normalize("9" * 33, "1", root, state, uid, gid),
                 opt_mode.OptModeError)
        assert not state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o777
        normalize()
        held = base / "held"; root.rename(held); root.mkdir(mode=0o755)
        rejected(restore, opt_mode.OptModeError)
        assert state.exists() and stat.S_IMODE(root.stat().st_mode) == 0o755
        root.rmdir(); held.rename(root); restore()
        rejected(lambda: opt_mode.restore("7", "1", root, state, uid + 1, gid),
                 opt_mode.OptModeError)
    original = (opt_mode.os.open, opt_mode.os.fstat, opt_mode.os.close)
    opened, closed = [], []
    def fake_open(*_args, **_kwargs):
        descriptor = 100 + len(opened); opened.append(descriptor); return descriptor
    opt_mode.os.open = fake_open
    opt_mode.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("fstat fault"))
    opt_mode.os.close = closed.append
    try:
        rejected(lambda: opt_mode._fixed_absent(Path("/var/lib/cogs"), 0, 0), OSError)
        assert closed == list(reversed(opened))
    finally:
        opt_mode.os.open, opt_mode.os.fstat, opt_mode.os.close = original


prebuilt_host_check_tests()
opt_mode_tests()
guard_tests()
publication_tests()
receipt_tests()
control_staging_tests()
settlement_tests()
settlement_linux_tail_tests()
prebuilt_staging_linux_tests()
print("stage2 local workflow script tests passed")

#!/usr/bin/env python3
"""Focused hostile tests for Stage 2 local workflow custody scripts."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

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
    rejected(lambda: settlement._interface_names([{"ifname": "eth0"}] * 2),
             settlement.LocalSettlementError)


guard_tests()
publication_tests()
receipt_tests()
control_staging_tests()
settlement_tests()
print("stage2 local workflow script tests passed")

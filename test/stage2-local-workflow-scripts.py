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
    rejected(guard._reviewed_constants, guard.GuardError)
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

    class Response:
        status = 200
        def __init__(self, value):
            self.raw = json.dumps(value).encode()
        def read(self, maximum):
            return self.raw[:maximum]
        def close(self):
            pass
    def observed(request, timeout):
        assert request.full_url.startswith("https://api.github.com/repos/nenb/cogs/actions/workflows/")
        assert timeout == 20 and "authorization" not in {key.lower() for key in request.headers}
        return Response({"total_count": 2, "workflow_runs": [
            {"event": "workflow_dispatch", "id": 80, "run_attempt": 1},
            {"event": "workflow_dispatch", "id": 71, "run_attempt": 2},
        ]})
    assert guard._api_runs(observed) == 71
    rejected(lambda: guard._api_runs(lambda *_args, **_kwargs: Response({
        "total_count": 101, "workflow_runs": []})), guard.GuardError)


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
    assert settlement.RESIDUE_NAME.search("cogs-stage2-net")


guard_tests()
publication_tests()
receipt_tests()
control_staging_tests()
settlement_tests()
print("stage2 local workflow script tests passed")

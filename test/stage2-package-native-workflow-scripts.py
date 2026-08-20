#!/usr/bin/env python3
"""Executable hostile tests for fixed native workflow security scripts."""
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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


settlement = load("stage2_native_settlement", "scripts/stage2-native-settlement.py")
receipt = load("stage2_native_upload_receipt", "scripts/stage2-native-upload-receipt.py")
contract = sys.modules["completion_runtime_contract"]


def rejected(call, exception):
    try:
        call()
    except exception:
        return
    raise AssertionError(f"did not reject with {exception.__name__}")


def terminate(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def live_process_tests():
    marker = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)",
                               "run-stage2-package-native-candidate.py"])
    try:
        time.sleep(0.05)
        rejected(lambda: settlement.scan("before-unmount"), settlement.SettlementError)
    finally:
        terminate(marker)

    with tempfile.TemporaryDirectory() as temporary:
        target = str(Path(temporary).resolve())
        cwd_process = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], cwd=target)
        try:
            rejected(lambda: settlement.scan("before-unmount", targets=(target,)),
                     settlement.SettlementError)
        finally:
            terminate(cwd_process)
        held = Path(target) / "held"
        held.write_bytes(b"held")
        fd_process = subprocess.Popen([
            sys.executable, "-c", "import os,sys,time;f=os.open(sys.argv[1],os.O_RDONLY);time.sleep(30)",
            str(held),
        ])
        try:
            time.sleep(0.05)
            rejected(lambda: settlement.scan("before-unmount", targets=(target,)),
                     settlement.SettlementError)
        finally:
            terminate(fd_process)


def synthetic_proc(mount_target):
    temporary = tempfile.TemporaryDirectory()
    proc = Path(temporary.name)
    (proc / "self/ns").mkdir(parents=True)
    (proc / "self/ns/mnt").write_bytes(b"own")
    pid = proc / "41"
    (pid / "ns").mkdir(parents=True)
    (pid / "fd").mkdir()
    (pid / "ns/mnt").write_bytes(b"foreign")
    (pid / "cmdline").write_bytes(b"harmless\0")
    (pid / "mountinfo").write_bytes(
        f"1 2 0:1 / {mount_target} rw - tmpfs tmpfs rw\n".encode())
    for name in ("root", "cwd", "exe"):
        (pid / name).symlink_to("/")
    return temporary, proc, pid


def scanner_race_and_mount_tests():
    temporary, proc, _pid = synthetic_proc("/run/cogs-stage2-native-private-v1")
    try:
        rejected(lambda: settlement.scan("before-unmount", proc_root=proc),
                 settlement.SettlementError)
    finally:
        temporary.cleanup()

    temporary, proc, pid = synthetic_proc("/unrelated")
    original = settlement._bytes
    try:
        settlement._bytes = lambda path: None if Path(path) == pid / "mountinfo" else original(path)
        settlement.scan("before-unmount", proc_root=proc)
    finally:
        settlement._bytes = original
        temporary.cleanup()


def unmount_tests():
    calls = []

    def busy(command, check):
        calls.append(command)
        code = 0 if command[0] == "/usr/bin/mountpoint" else 32
        return subprocess.CompletedProcess(command, code)

    rejected(lambda: settlement.unmount(busy), settlement.SettlementError)
    flattened = " ".join(item for command in calls for item in command)
    assert "/bin/umount --" in flattened and "--lazy" not in flattened and " -l " not in flattened

    def absent(command, check):
        assert command[0] == "/usr/bin/mountpoint"
        return subprocess.CompletedProcess(command, 1)

    settlement.unmount(absent)


def candidate(revision, manifest):
    tools = [dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS]
    runtime = contract.RuntimeClosurePin(
        contract.RUNTIME_CLOSURE_MANIFEST_SHA256,
        contract.RUNTIME_CLOSURE_OBJECT_COUNT,
        tuple(dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS),
    )
    binding = contract.native_execution_binding(
        tools, runtime, contract.NATIVE_LAUNCHER_SHA256, revision, manifest)
    value = {
        "version": "cogs.stage2-workload-candidate/v2",
        "result": "pass",
        "authority": "non-authoritative-retained-rootfs-candidate-only",
        "candidate_contract_sha256": contract.REVIEWED_CANDIDATE_SHA256,
        "final_pin_sha256": None,
        "package_identity": {
            "deb_sha256": "3" * 64, "deb_bytes": 100,
            "installed_tree_sha256": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
            "installed_entries": 259, "installed_bytes": 1_048_576,
            "package": "cogs-stage2-fixture", "version": "1.0", "architecture": "all",
        },
        "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
        "a_equals_b": True, "lifecycle_deleted": True,
        "promotion": "external-manual-review-required", "execution_binding": binding,
    }
    return contract.canonical_json(value)


def context(candidate_raw, revision, manifest):
    return receipt.Context(
        revision, manifest, 71, 1,
        f"stage2-native-package-candidate-{revision}-71-1",
        f"stage2-native-package-candidate-receipt-{revision}-71-1",
        91, "4" * 64, hashlib.sha256(candidate_raw).hexdigest(), len(candidate_raw),
    )


def receipt_tests():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    expected = context(candidate_raw, revision, manifest)
    raw = receipt.encode(expected, candidate_raw)
    value = receipt.validate(raw, expected, candidate_raw)
    assert raw.endswith(b"\n") and len(raw) <= receipt.MAX_RECEIPT_BYTES
    assert value["source"] == {"manifest_sha256": manifest, "revision": revision}

    hostile = copy.deepcopy(value)
    hostile["extra"] = False
    extra = json.dumps(hostile, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    rejected(lambda: receipt.validate(extra, expected, candidate_raw), receipt.ReceiptError)
    pretty = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    rejected(lambda: receipt.validate(pretty, expected, candidate_raw), receipt.ReceiptError)
    duplicate = raw.replace(b'{"artifact":', b'{"version":"duplicate","artifact":', 1)
    rejected(lambda: receipt.validate(duplicate, expected, candidate_raw), receipt.ReceiptError)

    rejected(lambda: receipt.encode(replace(expected, manifest="5" * 64), candidate_raw),
             receipt.ReceiptError)
    changed = json.loads(candidate_raw)
    changed["execution_binding"]["source_manifest_sha256"] = "5" * 64
    changed_raw = contract.canonical_json(changed)
    rejected(lambda: receipt.encode(context(changed_raw, revision, manifest), changed_raw),
             receipt.ReceiptError)

    environ = {
        "EXPECTED_SOURCE_REVISION": revision, "EXPECTED_SOURCE_MANIFEST_SHA256": manifest,
        "EXACT_REVIEWED_HEAD": revision, "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1",
        "CANDIDATE_ARTIFACT_NAME": expected.candidate_name,
        "RECEIPT_ARTIFACT_NAME": expected.receipt_name,
        "CANDIDATE_ARTIFACT_ID": "91", "CANDIDATE_ARTIFACT_DIGEST": "4" * 64,
        "CANDIDATE_SHA256": expected.candidate_sha256, "CANDIDATE_BYTES": str(len(candidate_raw)),
    }
    assert receipt.context(environ) == expected
    for missing in ("CANDIDATE_ARTIFACT_ID", "CANDIDATE_ARTIFACT_DIGEST"):
        hostile_environ = dict(environ)
        hostile_environ.pop(missing)
        rejected(lambda hostile_environ=hostile_environ: receipt.context(hostile_environ),
                 receipt.ReceiptError)


live_process_tests()
scanner_race_and_mount_tests()
unmount_tests()
receipt_tests()
print("stage2 native workflow script tests passed")

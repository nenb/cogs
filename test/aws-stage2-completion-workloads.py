#!/usr/bin/env python3
"""Portable hostile tests for ADR 0099 non-authoritative host workloads."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_guest_workloads as guest
import completion_package_candidate as candidate
import completion_runtime_contract as contract


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def rejected(function, exception=Exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("hostile value was accepted")


fixed = contract.load_candidate_contract()
check(fixed.sha256 == contract.REVIEWED_CANDIDATE_SHA256, "candidate digest drift")
check(hashlib.sha256(contract.CANDIDATE_PATH.read_bytes()).hexdigest() == contract.REVIEWED_CANDIDATE_SHA256, "raw candidate digest drift")
check(fixed.value["sample_count"] == 7 and "deb_sha256" not in json.dumps(fixed.value), "candidate contract changed")
check(contract.REVIEWED_FINAL_PIN_SHA256 is None, "an unreviewed final digest was invented")
rejected(contract.load_final_pin, contract.FinalPinUnavailable)

identity = {
    "deb_sha256": "a" * 64,
    "deb_bytes": 1234,
    "installed_tree_sha256": fixed.value["bindings"]["installed_tree_sha256"],
    "installed_entries": 259,
    "installed_bytes": 1048576,
    "package": "cogs-stage2-fixture",
    "version": "1.0",
    "architecture": "all",
}
final_value = {
    "version": "cogs.stage2-workload-final-pin/v1",
    "candidate_contract_sha256": fixed.sha256,
    "package_identity": identity,
    "reproductions": ["A", "B"],
    "promotion": "manual-reviewed-a-equals-b",
}

# Exact bytes: symlink, hardlink, reformat, BOM, trailing data, duplicate key, and
# a final path without a separately reviewed digest all remain closed.
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary).resolve()
    original_candidate = contract.CANDIDATE_PATH
    original_final = contract.FINAL_PATH
    original_digest = contract.REVIEWED_FINAL_PIN_SHA256
    exact = original_candidate.read_bytes()
    try:
        target = directory / "target.json"
        target.write_bytes(exact)
        symlink = directory / "symlink.json"
        symlink.symlink_to(target)
        contract.CANDIDATE_PATH = symlink
        rejected(contract.load_candidate_contract, contract.WorkloadContractError)

        hardlink = directory / "hardlink.json"
        os.link(target, hardlink)
        contract.CANDIDATE_PATH = hardlink
        rejected(contract.load_candidate_contract, contract.WorkloadContractError)
        hardlink.unlink()

        for number, raw in enumerate((
            json.dumps(json.loads(exact)).encode(),
            b"\xef\xbb\xbf" + exact,
            exact + b" ",
            b'{"version":1,"version":1}\n',
        )):
            hostile = directory / f"hostile-{number}.json"
            hostile.write_bytes(raw)
            contract.CANDIDATE_PATH = hostile
            rejected(contract.load_candidate_contract, contract.WorkloadContractError)

        contract.CANDIDATE_PATH = original_candidate
        final_path = directory / "final.json"
        canonical = contract.canonical_json(final_value)
        final_path.write_bytes(canonical)
        contract.FINAL_PATH = final_path
        rejected(contract.load_final_pin, contract.FinalPinUnavailable)
        contract.REVIEWED_FINAL_PIN_SHA256 = hashlib.sha256(canonical).hexdigest()
        final = contract.load_final_pin()
        check(final.final_pin_sha256 == hashlib.sha256(canonical).hexdigest(), "final raw digest missing")
        check(final.candidate_a == final.candidate_b == final.package_identity, "A=B representation differs")

        final_path.write_bytes(json.dumps(final_value, indent=2).encode() + b"\n")
        rejected(contract.load_final_pin, contract.WorkloadContractError)
        final_path.write_bytes(canonical)
        unequal_shape = copy.deepcopy(final_value)
        unequal_shape["candidate_a"] = identity
        final_path.write_bytes(contract.canonical_json(unequal_shape))
        contract.REVIEWED_FINAL_PIN_SHA256 = hashlib.sha256(final_path.read_bytes()).hexdigest()
        rejected(contract.load_final_pin, contract.WorkloadContractError)
    finally:
        contract.CANDIDATE_PATH = original_candidate
        contract.FINAL_PATH = original_final
        contract.REVIEWED_FINAL_PIN_SHA256 = original_digest

# Authentic descriptor read under repeated rename/ABA yields one complete generation or
# rejects; the exact candidate loader would additionally reject every non-reviewed digest.
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary).resolve()
    active = directory / "active"
    alternate = directory / "alternate"
    active.write_bytes(b"A" * 4096)
    alternate.write_bytes(b"B" * 4096)
    stop = False

    def swapper():
        spare = directory / "spare"
        while not stop:
            try:
                os.rename(active, spare)
                os.rename(alternate, active)
                os.rename(spare, alternate)
            except FileNotFoundError:
                pass

    thread = threading.Thread(target=swapper)
    thread.start()
    try:
        for _index in range(100):
            try:
                raw = contract._read_regular(active, 8192)
            except contract.WorkloadContractError:
                continue
            check(raw in {b"A" * 4096, b"B" * 4096}, "torn ABA read accepted")
    finally:
        stop = True
        thread.join()

# Owned file reads reject hardlinks and command output creation rejects symlinks without
# changing their targets.
with tempfile.TemporaryDirectory() as temporary:
    deadline = guest.Deadline.start(5, 2)
    root_path = Path(temporary).resolve() / "owned"
    root = guest.OwnedRoot(root_path, deadline)
    root.write_file("value", b"safe")
    os.link(root_path / "value", root_path / "other")
    rejected(lambda: root.read_file("value", 32), guest.WorkloadError)
    os.unlink(root_path / "other")
    root.unlink("value")
    target = Path(temporary).resolve() / "target"
    target.write_bytes(b"preserve")
    os.symlink(target, root_path / "command.out")
    rejected(lambda: guest._run(("/usr/bin/true",), root, deadline), guest.WorkloadError)
    check(target.read_bytes() == b"preserve", "symlink output target changed")
    os.unlink(root_path / "command.out")
    root.cleanup()
    check(not os.path.lexists(root_path), "owned root remained")

# Replacement-path cleanup is identity-conservative: uncertainty dominates and neither
# the moved owned generation nor the replacement is guessed at or deleted.
with tempfile.TemporaryDirectory() as temporary:
    deadline = guest.Deadline.start(5, 2)
    root_path = Path(temporary).resolve() / "owned"
    moved = Path(temporary).resolve() / "moved-owned"
    root = guest.OwnedRoot(root_path, deadline)
    root.write_file("owned", b"owned")
    os.rename(root_path, moved)
    root_path.mkdir(mode=0o700)
    (root_path / "replacement").write_bytes(b"replacement")
    rejected(root.cleanup, guest.CleanupUncertain)
    check((root_path / "replacement").read_bytes() == b"replacement", "replacement was deleted")
    check((moved / "owned").read_bytes() == b"owned", "uncertain owned generation was deleted")

# A real closed stdout is categorical; no traceback, path, command, or partial success
# document is reported by the helper process.
broken_output = subprocess.run(
    [
        sys.executable,
        "-B",
        "-c",
        (
            "import os,sys; sys.path.insert(0,sys.argv[1]); "
            "import completion_package_candidate as c; os.close(1); "
            "\ntry: c._write_stdout(b'x')\n"
            "except Exception as e: os.write(2, e.category.encode()+b'\\n')"
        ),
        str(REMOTE),
    ],
    capture_output=True,
    check=False,
    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"},
)
check(broken_output.returncode == 0 and broken_output.stdout == b"", "broken stdout escaped")
check(broken_output.stderr == b"output-uncertain\n", "broken stdout was not categorical")

# TERM/INT are categorical and do not disclose a path or command.
for number in (signal.SIGTERM, signal.SIGINT):
    try:
        with guest.SignalScope():
            os.kill(os.getpid(), number)
    except guest.WorkloadInterrupted as error:
        check(error.category == "interrupted" and "/" not in str(error), "signal was not categorical")
    else:
        raise AssertionError("signal did not interrupt")

# Real timeout and escaped-child checks are Linux-only. The subreaper owns descendants,
# applies bounded TERM/KILL/reap, and leaves no adopted child.
if sys.platform.startswith("linux"):
    guest._enable_subreaper()
    with tempfile.TemporaryDirectory() as temporary:
        deadline = guest.Deadline.start(1.0, 0.55)
        root = guest.OwnedRoot(Path(temporary).resolve() / "timeout", deadline)
        started = time.monotonic()
        rejected(lambda: guest._run((sys.executable, "-c", "import time; time.sleep(30)"), root, deadline), guest.WorkloadDeadline)
        check(time.monotonic() - started < 1.1, "timeout was not bounded")
        root.cleanup()
        check(not guest._children(), "timeout child remained")

    with tempfile.TemporaryDirectory() as temporary:
        deadline = guest.Deadline.start(3.0, 1.5)
        root = guest.OwnedRoot(Path(temporary).resolve() / "escaped", deadline)
        program = "import os,time; p=os.fork(); (os.setsid(),time.sleep(30)) if p==0 else None"
        guest._run((sys.executable, "-c", program), root, deadline)
        check(not guest._children(), "escaped child remained")
        root.cleanup()

# Semantic codecs make A=B structural (one identity) and reject every summary mismatch.
tools = [
    {"name": "git", "sha256": "1" * 64, "bytes": 1, "version": "git version 2.47.3"},
    {"name": "dpkg-deb", "sha256": "2" * 64, "bytes": 2, "version": "dpkg-deb 1.22.22"},
    {"name": "dpkg", "sha256": "3" * 64, "bytes": 3, "version": "dpkg 1.22.22"},
]
binding = contract.execution_binding(tools)
candidate_value = {
    "version": "cogs.stage2-workload-candidate/v1",
    "result": "pass",
    "authority": "non-authoritative-host-candidate-only",
    "candidate_contract_sha256": fixed.sha256,
    "final_pin_sha256": None,
    "package_identity": identity,
    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
    "a_equals_b": True,
    "lifecycle_deleted": True,
    "promotion": "external-manual-review-required",
    "execution_binding": binding,
}
contract.validate_candidate_result(candidate_value)
for key, hostile in (
    ("authority", "authoritative"),
    ("final_pin_sha256", "f" * 64),
    ("a_equals_b", False),
    ("lifecycle_deleted", False),
    ("reproductions", list(reversed(candidate_value["reproductions"]))),
):
    changed = copy.deepcopy(candidate_value)
    changed[key] = hostile
    rejected(lambda changed=changed: contract.validate_candidate_result(changed), contract.WorkloadContractError)

parsed_identity = contract.parse_identity(identity)
semantic_final = contract.FinalPin(fixed.sha256, "f" * 64, parsed_identity)
post_value = {
    "version": "cogs.stage2-workload-post-pin/v1",
    "result": "pass",
    "authority": "non-authoritative-host-reproduction-only",
    "candidate_contract_sha256": fixed.sha256,
    "final_pin_sha256": "f" * 64,
    "package_identity": identity,
    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
    "matches_final_pin": True,
    "lifecycle_deleted": True,
    "execution_binding": binding,
}
contract.validate_post_pin_result(post_value, semantic_final)
for key, hostile in (
    ("authority", "authoritative"),
    ("final_pin_sha256", None),
    ("matches_final_pin", False),
    ("lifecycle_deleted", False),
    ("reproductions", list(reversed(post_value["reproductions"]))),
):
    changed = copy.deepcopy(post_value)
    changed[key] = hostile
    rejected(lambda changed=changed: contract.validate_post_pin_result(changed, semantic_final), contract.WorkloadContractError)

# Darwin's production route fails before creating an owned root and cannot invent a pin.
if sys.platform == "darwin":
    check(not os.path.lexists(candidate.CANDIDATE_ROOT), "candidate root pre-existed")
    rejected(candidate.run_candidate_transaction)
    check(not os.path.lexists(candidate.CANDIDATE_ROOT), "Darwin created a candidate root")
    check(contract.REVIEWED_FINAL_PIN_SHA256 is None, "Darwin invented a final pin")

source = "\n".join((REMOTE / name).read_text() for name in (
    "completion_runtime_contract.py",
    "completion_guest_workloads.py",
    "completion_package_candidate.py",
))
for forbidden in ("local-standalone-kata", "workload-local-qualification", "completion_local_full"):
    check(forbidden not in source, "removed authority remains in host source")
for cloud in ("boto", "AWS_", "requests", "urllib", "Terraform", "OpenTofu"):
    check(cloud not in source, "cloud surface entered host workload")
check(not (REMOTE / "completion_local_full.py").exists(), "host qualification module remains")
check(not (ROOT / "schemas/stage2-workload-local-qualification-v1.json").exists(), "host qualification schema remains")
print("completion workload contract tests passed")

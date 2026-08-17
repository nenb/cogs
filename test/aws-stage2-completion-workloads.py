#!/usr/bin/env python3
"""Readable portable and hostile tests for ADR 0099 workload contracts."""

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_guest_workloads as guest
import completion_local_full as local
import completion_package_candidate as candidate
import completion_runtime_contract as contract

fixed = contract.load_candidate_contract()
assert fixed.value["sample_count"] == 7
assert fixed.value["platform"] == {"os": "linux", "architecture": "amd64", "euid": 0}
assert fixed.value["bindings"]["rootfs_manifest_sha256"] == "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691"
assert fixed.value["bindings"]["rootfs_ustar_sha256"] == "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3"
assert "deb_sha256" not in json.dumps(fixed.value)
assert fixed.sha256 == hashlib.sha256(contract.CANDIDATE_PATH.read_bytes()).hexdigest()

try:
    contract.load_final_pin()
except contract.FinalPinUnavailable:
    pass
else:
    raise AssertionError("qualification opened without a manual final pin")

# Strict JSON rejects duplicate/additional keys, scalar coercion, A!=B, and drift.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    original_candidate = contract.CANDIDATE_PATH
    original_final = contract.FINAL_PATH
    try:
        duplicate = root / "duplicate.json"
        duplicate.write_text('{"version":1,"version":1}\n')
        contract.CANDIDATE_PATH = duplicate
        try:
            contract.load_candidate_contract()
        except contract.WorkloadContractError:
            pass
        else:
            raise AssertionError("duplicate JSON key accepted")

        changed = json.loads(original_candidate.read_text())
        changed["sample_count"] = True
        hostile = root / "hostile.json"
        hostile.write_text(json.dumps(changed))
        contract.CANDIDATE_PATH = hostile
        try:
            contract.load_candidate_contract()
        except contract.WorkloadContractError:
            pass
        else:
            raise AssertionError("bool/int coercion accepted")

        changed = json.loads(original_candidate.read_text())
        changed["platform"]["euid"] = False
        hostile.write_text(json.dumps(changed))
        try:
            contract.load_candidate_contract()
        except contract.WorkloadContractError:
            pass
        else:
            raise AssertionError("False was accepted as numeric zero")

        contract.CANDIDATE_PATH = original_candidate
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
            "candidate_a": identity,
            "candidate_b": dict(identity),
            "promotion": "manual-reviewed-a-equals-b",
        }
        final_path = root / "final.json"
        final_path.write_text(json.dumps(final_value))
        contract.FINAL_PATH = final_path
        assert contract.load_final_pin().candidate_a == contract.load_final_pin().candidate_b

        unequal = json.loads(final_path.read_text())
        unequal["candidate_b"]["deb_sha256"] = "b" * 64
        final_path.write_text(json.dumps(unequal))
        try:
            contract.load_final_pin()
        except contract.WorkloadContractError:
            pass
        else:
            raise AssertionError("unequal A/B final pin accepted")

        extra = json.loads(json.dumps(final_value))
        extra["candidate_a"]["path"] = "/hostile"
        final_path.write_text(json.dumps(extra))
        try:
            contract.load_final_pin()
        except contract.WorkloadContractError:
            pass
        else:
            raise AssertionError("caller-selected path accepted")
    finally:
        contract.CANDIDATE_PATH = original_candidate
        contract.FINAL_PATH = original_final

# The real Darwin route must fail before creating a candidate or pretending a pin.
if sys.platform == "darwin":
    assert not os.path.lexists(candidate.CANDIDATE_ROOT)
    try:
        candidate.run_candidate_transaction()
    except Exception:
        pass
    else:
        raise AssertionError("Darwin invented a Linux package candidate")
    assert not os.path.lexists(candidate.CANDIDATE_ROOT)

identity = contract.PackageIdentity(
    "a" * 64,
    1234,
    fixed.value["bindings"]["installed_tree_sha256"],
    259,
    1048576,
    "cogs-stage2-fixture",
    "1.0",
    "all",
)

# Simulate only the sealed orchestration seams: exactly A, B; mismatch is all-or-nothing.
with tempfile.TemporaryDirectory() as temporary:
    original_root = candidate.CANDIDATE_ROOT
    original_platform = candidate._require_linux_amd64_root
    original_versions = candidate._check_versions
    original_sample = candidate._run_package_sample
    candidate.CANDIDATE_ROOT = Path(temporary) / "candidate"
    calls = []
    candidate._require_linux_amd64_root = lambda: None
    candidate._check_versions = lambda _root: None

    def package_sample(root, label):
        calls.append(label)
        path = root / f"package-{label}"
        path.mkdir()
        path.rmdir()
        return identity, 1, 2

    candidate._run_package_sample = package_sample
    try:
        output = json.loads(candidate.run_candidate_transaction())
        assert calls == ["candidate-a", "candidate-b"]
        assert output["a_equals_b"] is True
        assert output["candidates"][0]["package_identity"] == output["candidates"][1]["package_identity"]
        assert not candidate.CANDIDATE_ROOT.exists()

        calls.clear()
        different = contract.PackageIdentity(*({**identity.value(), "deb_sha256": "b" * 64}.values()))

        def mismatching(root, label):
            value = identity if label == "candidate-a" else different
            calls.append(label)
            return value, 1, 2

        candidate._run_package_sample = mismatching
        try:
            candidate.run_candidate_transaction()
        except Exception:
            pass
        else:
            raise AssertionError("candidate A!=B produced output")
        assert calls == ["candidate-a", "candidate-b"] and not candidate.CANDIDATE_ROOT.exists()
    finally:
        candidate.CANDIDATE_ROOT = original_root
        candidate._require_linux_amd64_root = original_platform
        candidate._check_versions = original_versions
        candidate._run_package_sample = original_sample

# Simulate full orchestration and prove fixed per-sample operation order and abort behavior.
with tempfile.TemporaryDirectory() as temporary:
    originals = (
        local.FULL_ROOT,
        local.load_candidate_contract,
        local.load_final_pin,
        local._require_linux_amd64_root,
        local._check_versions,
        local._prepare_git_fixture,
        local._run_git_sample,
        local._run_package_sample,
    )
    local.FULL_ROOT = Path(temporary) / "full"
    final = contract.FinalPin(fixed.sha256, identity, identity)
    events = []
    local.load_candidate_contract = lambda: fixed
    local.load_final_pin = lambda: final
    local._require_linux_amd64_root = lambda: None
    local._check_versions = lambda _root: None
    local._prepare_git_fixture = lambda root: root / "git-fixture.git"

    def git_sample(_root, _bare, sample):
        events.append((sample, "git"))
        return sample

    def full_package(_root, label):
        sample = int(label.removeprefix("sample-"))
        events.extend(((sample, "package-build"), (sample, "package-install")))
        return identity, sample + 10, sample + 20

    local._run_git_sample = git_sample
    local._run_package_sample = full_package
    try:
        result = json.loads(local.run_local_full_qualification())
        expected = [(sample, operation) for sample in range(1, 8) for operation in ("git", "package-build", "package-install")]
        assert events == expected
        assert [row["sample"] for row in result["samples"]] == list(range(1, 8))
        assert all(row["deleted"] is True for row in result["samples"])
        assert result["lifecycle_count"] == 1 and len(result["samples"]) == 7
        assert not local.FULL_ROOT.exists()

        events.clear()

        def fail_third(_root, _bare, sample):
            events.append((sample, "git"))
            if sample == 3:
                raise local.LocalQualificationError()
            return sample

        local._run_git_sample = fail_third
        try:
            local.run_local_full_qualification()
        except Exception:
            pass
        else:
            raise AssertionError("partial seven-sample result was returned")
        assert events[-1] == (3, "git") and all(sample <= 3 for sample, _operation in events)
        assert not local.FULL_ROOT.exists()
    finally:
        (
            local.FULL_ROOT,
            local.load_candidate_contract,
            local.load_final_pin,
            local._require_linux_amd64_root,
            local._check_versions,
            local._prepare_git_fixture,
            local._run_git_sample,
            local._run_package_sample,
        ) = originals

# Public authority-bearing functions are zero-argument and code owns every path/flag/env.
for function in (
    contract.load_candidate_contract,
    contract.load_final_pin,
    candidate.run_candidate_transaction,
    candidate.run_post_pin_transaction,
    local.run_local_full_qualification,
):
    assert tuple(inspect.signature(function).parameters) == ()

source = "\n".join(
    (REMOTE / name).read_text()
    for name in (
        "completion_runtime_contract.py",
        "completion_guest_workloads.py",
        "completion_package_candidate.py",
        "completion_local_full.py",
    )
)
fixed_flags = (
    "--build",
    "--root-owner-group",
    "--compression=xz",
    "--compression-level=6",
    "--threads-max=1",
    "--admindir",
    "--instdir",
    "--install",
)
for flag in fixed_flags:
    assert flag in source
for forbidden in ("boto", "AWS_", "urllib", "requests", "socket", "retry", "fallback", "argparse"):
    assert forbidden not in source
assert "/tmp/cogs-stage2-workload-candidate-v1" in source
assert "/tmp/cogs-stage2-workload-post-pin-v1" in source
assert "/tmp/cogs-stage2-workload-full-v1" in source
print("completion workload contract tests passed")

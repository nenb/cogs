#!/usr/bin/env python3
"""One-lifecycle seven-sample local workload qualification for ADR 0099."""

import json
import os
from pathlib import Path
import sys

from completion_guest_workloads import (
    _fresh_directory,
    _prepare_git_fixture,
    _remove_owned,
    _run_git_sample,
    _run_package_sample,
)
from completion_package_candidate import _check_versions, _require_linux_amd64_root
from completion_runtime_contract import load_candidate_contract, load_final_pin

FULL_ROOT = Path("/tmp/cogs-stage2-workload-full-v1")
MAX_OUTPUT_BYTES = 8192


class LocalQualificationError(Exception):
    pass


def _require(condition):
    if not condition:
        raise LocalQualificationError()


def _canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise LocalQualificationError() from error
    _require(len(raw) <= MAX_OUTPUT_BYTES)
    return raw


def run_local_full_qualification():
    """Run Git/build/install samples 1..7 in order; return nothing until final absence."""
    contract = load_candidate_contract()
    final = load_final_pin()
    _require(final.candidate_contract_sha256 == contract.sha256)
    _require_linux_amd64_root()
    _fresh_directory(FULL_ROOT)
    samples = []
    try:
        _check_versions(FULL_ROOT)
        bare = _prepare_git_fixture(FULL_ROOT)
        for sample in range(1, 8):
            _require(load_candidate_contract() == contract and load_final_pin() == final)
            git_ms = _run_git_sample(FULL_ROOT, bare, sample)
            _require(not os.path.lexists(FULL_ROOT / f"git-{sample:02d}"))
            _require(load_candidate_contract() == contract and load_final_pin() == final)
            package, build_ms, install_ms = _run_package_sample(FULL_ROOT, f"sample-{sample:02d}")
            _require(not os.path.lexists(FULL_ROOT / f"package-sample-{sample:02d}"))
            _require(package == final.candidate_a == final.candidate_b)
            _require(load_candidate_contract() == contract and load_final_pin() == final)
            samples.append({
                "sample": sample,
                "operations": ["git", "package-build", "package-install"],
                "git_ms": git_ms,
                "package_build_ms": build_ms,
                "package_install_ms": install_ms,
                "package_identity": package.value(),
                "deleted": True,
            })
        _require(tuple(row["sample"] for row in samples) == tuple(range(1, 8)))
        _require(all(row["operations"] == ["git", "package-build", "package-install"] for row in samples))
    finally:
        _remove_owned(FULL_ROOT)
    _require(not os.path.lexists(FULL_ROOT) and len(samples) == 7)
    return _canonical({
        "version": "cogs.stage2-workload-local-qualification/v1",
        "result": "pass",
        "candidate_contract_sha256": contract.sha256,
        "lifecycle_count": 1,
        "samples": samples,
        "all_match_final_pin": True,
        "lifecycle_deleted": True,
        "authority": "local-standalone-kata-only-stopped-before-step-5",
    })


def main():
    if len(sys.argv) != 1:
        print("completion local workload qualification failed", file=sys.stderr)
        return 1
    try:
        raw = run_local_full_qualification()
    except Exception:
        print("completion local workload qualification failed", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(raw + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

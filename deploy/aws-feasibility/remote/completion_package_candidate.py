#!/usr/bin/env python3
"""Fail-closed two-build package candidate transaction for ADR 0099."""

import json
import os
from pathlib import Path
import platform
import sys

from completion_guest_workloads import DPKG, DPKG_DEB, GIT, _fresh_directory, _remove_owned, _run, _run_package_sample
from completion_runtime_contract import load_candidate_contract

CANDIDATE_ROOT = Path("/tmp/cogs-stage2-workload-candidate-v1")
POST_PIN_ROOT = Path("/tmp/cogs-stage2-workload-post-pin-v1")
MAX_OUTPUT_BYTES = 4096


class CandidateError(Exception):
    pass


def _require(condition):
    if not condition:
        raise CandidateError()


def _require_linux_amd64_root():
    _require(platform.system() == "Linux")
    _require(platform.machine() in {"x86_64", "amd64"})
    _require(os.geteuid() == 0)
    _require(all(Path(tool).is_file() and not Path(tool).is_symlink() for tool in (GIT, DPKG_DEB, DPKG)))


def _check_versions(root):
    output = root / "command.out"
    git = _run((GIT, "--version"), root, output)
    dpkg_deb = _run((DPKG_DEB, "--version"), root, output)
    dpkg = _run((DPKG, "--version"), root, output)
    _require(git == b"git version 2.47.3\n")
    _require(dpkg_deb.splitlines()[0] == b"Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64).")
    _require(dpkg.splitlines()[0] == b"Debian 'dpkg' package management program version 1.22.22 (amd64).")


def _canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CandidateError() from error
    _require(len(raw) <= MAX_OUTPUT_BYTES)
    return raw


def run_candidate_transaction():
    """Build/install A then B once in fixed fresh paths; emit only after A=B and absence."""
    contract = load_candidate_contract()
    _require_linux_amd64_root()
    _fresh_directory(CANDIDATE_ROOT)
    try:
        _check_versions(CANDIDATE_ROOT)
        first, _first_build_ms, _first_install_ms = _run_package_sample(CANDIDATE_ROOT, "candidate-a")
        _require(not os.path.lexists(CANDIDATE_ROOT / "package-candidate-a"))
        _require(load_candidate_contract() == contract)
        second, _second_build_ms, _second_install_ms = _run_package_sample(CANDIDATE_ROOT, "candidate-b")
        _require(not os.path.lexists(CANDIDATE_ROOT / "package-candidate-b"))
        _require(first == second and load_candidate_contract() == contract)
    finally:
        _remove_owned(CANDIDATE_ROOT)
    _require(not os.path.lexists(CANDIDATE_ROOT))
    return _canonical({
        "version": "cogs.stage2-workload-candidate/v1",
        "result": "pass",
        "candidate_contract_sha256": contract.sha256,
        "candidates": [
            {"id": "A", "package_identity": first.value(), "deleted": True},
            {"id": "B", "package_identity": second.value(), "deleted": True},
        ],
        "a_equals_b": True,
        "lifecycle_deleted": True,
        "promotion": "manual-only",
    })


def run_post_pin_transaction():
    """Independently reproduce A and B against an already committed manual final pin."""
    from completion_runtime_contract import load_final_pin

    final = load_final_pin()
    _require_linux_amd64_root()
    _fresh_directory(POST_PIN_ROOT)
    try:
        _check_versions(POST_PIN_ROOT)
        first, _first_build_ms, _first_install_ms = _run_package_sample(POST_PIN_ROOT, "candidate-a")
        _require(not os.path.lexists(POST_PIN_ROOT / "package-candidate-a"))
        _require(load_final_pin() == final)
        second, _second_build_ms, _second_install_ms = _run_package_sample(POST_PIN_ROOT, "candidate-b")
        _require(not os.path.lexists(POST_PIN_ROOT / "package-candidate-b"))
        _require(first == second == final.candidate_a == final.candidate_b)
        _require(load_final_pin() == final)
    finally:
        _remove_owned(POST_PIN_ROOT)
    _require(not os.path.lexists(POST_PIN_ROOT))
    return _canonical({
        "version": "cogs.stage2-workload-post-pin/v1",
        "result": "pass",
        "candidate_contract_sha256": final.candidate_contract_sha256,
        "reproductions": [
            {"id": "A", "package_identity": first.value(), "deleted": True},
            {"id": "B", "package_identity": second.value(), "deleted": True},
        ],
        "matches_final_pin": True,
        "lifecycle_deleted": True,
    })


def main():
    if len(sys.argv) != 1:
        print("completion package candidate failed", file=sys.stderr)
        return 1
    try:
        raw = run_candidate_transaction()
    except Exception:
        print("completion package candidate failed", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(raw + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

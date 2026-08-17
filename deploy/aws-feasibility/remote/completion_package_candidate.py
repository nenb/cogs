#!/usr/bin/env python3
"""One-shot non-authoritative host candidate and post-pin reproduction."""

import os
from pathlib import Path
import sys

from completion_guest_workloads import (
    CleanupUncertain,
    Deadline,
    OwnedRoot,
    OutputUncertain,
    SignalScope,
    ToolSet,
    WorkloadError,
    WorkloadInterrupted,
    _check_versions,
    _run_package_sample,
    require_linux_amd64_root,
)
from completion_runtime_contract import (
    canonical_json,
    execution_binding,
    load_candidate_contract,
    load_final_pin,
    validate_candidate_result,
    validate_post_pin_result,
)

CANDIDATE_ROOT = Path("/tmp/cogs-stage2-workload-candidate-v1")
POST_PIN_ROOT = Path("/tmp/cogs-stage2-workload-post-pin-v1")
MAX_OUTPUT_BYTES = 4096


class CandidateError(WorkloadError):
    category = "candidate-mismatch"


def _require(condition):
    if not condition:
        raise CandidateError("candidate invariant failed")


def _same_tools(expected, tools):
    observed = tools.observations()
    _require(observed == expected)
    return observed


def _finish_root(root, failure):
    if root is not None:
        try:
            root.cleanup()
        except CleanupUncertain as cleanup_error:
            return cleanup_error
        except BaseException:
            return CleanupUncertain("owned cleanup was interrupted or failed")
    return failure


def _raise_failure(failure):
    if failure is None:
        return
    if isinstance(failure, (WorkloadError, KeyboardInterrupt, SystemExit)):
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise WorkloadInterrupted("transaction interrupted") from None
        raise failure
    raise CandidateError("candidate transaction failed") from None


def _encode(value, validator):
    validator(value)
    raw = canonical_json(value)
    _require(len(raw) <= MAX_OUTPUT_BYTES)
    return raw


def run_candidate_transaction():
    """Build A then B exactly once; this can never claim host qualification authority."""
    deadline = Deadline.start()
    root = None
    tools = None
    failure = None
    result = None
    with SignalScope():
        try:
            contract = load_candidate_contract()
            require_linux_amd64_root()
            tools = ToolSet()
            root = OwnedRoot(CANDIDATE_ROOT, deadline)
            _check_versions(root, tools, deadline)
            tool_observations = tools.observations()
            first, _first_build_ms, _first_install_ms = _run_package_sample(root, "candidate-a", tools, deadline)
            _same_tools(tool_observations, tools)
            _require(load_candidate_contract() == contract)
            second, _second_build_ms, _second_install_ms = _run_package_sample(root, "candidate-b", tools, deadline)
            _same_tools(tool_observations, tools)
            _require(first == second and load_candidate_contract() == contract)
            result = {
                "version": "cogs.stage2-workload-candidate/v1",
                "result": "pass",
                "authority": "non-authoritative-host-candidate-only",
                "candidate_contract_sha256": contract.sha256,
                "final_pin_sha256": None,
                "package_identity": first.value(),
                "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
                "a_equals_b": True,
                "lifecycle_deleted": True,
                "promotion": "external-manual-review-required",
                "execution_binding": execution_binding(tool_observations),
            }
        except BaseException as error:
            failure = error
        finally:
            failure = _finish_root(root, failure)
            if tools is not None:
                tools.close()
    _raise_failure(failure)
    _require(result is not None)
    return _encode(result, validate_candidate_result)


def run_post_pin_transaction():
    """Reproduce A then B once against exact externally reviewed final-pin bytes."""
    deadline = Deadline.start()
    root = None
    tools = None
    failure = None
    result = None
    final = None
    with SignalScope():
        try:
            final = load_final_pin()
            require_linux_amd64_root()
            tools = ToolSet()
            root = OwnedRoot(POST_PIN_ROOT, deadline)
            _check_versions(root, tools, deadline)
            tool_observations = tools.observations()
            first, _first_build_ms, _first_install_ms = _run_package_sample(root, "candidate-a", tools, deadline)
            _same_tools(tool_observations, tools)
            _require(load_final_pin() == final)
            second, _second_build_ms, _second_install_ms = _run_package_sample(root, "candidate-b", tools, deadline)
            _same_tools(tool_observations, tools)
            _require(first == second == final.package_identity and load_final_pin() == final)
            result = {
                "version": "cogs.stage2-workload-post-pin/v1",
                "result": "pass",
                "authority": "non-authoritative-host-reproduction-only",
                "candidate_contract_sha256": final.candidate_contract_sha256,
                "final_pin_sha256": final.final_pin_sha256,
                "package_identity": first.value(),
                "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
                "matches_final_pin": True,
                "lifecycle_deleted": True,
                "execution_binding": execution_binding(tool_observations),
            }
        except BaseException as error:
            failure = error
        finally:
            failure = _finish_root(root, failure)
            if tools is not None:
                tools.close()
    _raise_failure(failure)
    _require(result is not None and final is not None)
    return _encode(result, lambda value: validate_post_pin_result(value, final))


def _write_stdout(raw):
    try:
        written = os.write(sys.stdout.fileno(), raw)
    except OSError as error:
        raise OutputUncertain("stdout write failed") from error
    if written != len(raw):
        raise OutputUncertain("stdout write incomplete")


def _category(error):
    if isinstance(error, WorkloadError):
        return error.category
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return "interrupted"
    return "failed"


def main():
    if len(sys.argv) != 1:
        os.write(2, b"completion host candidate failed: invocation\n")
        return 1
    try:
        raw = run_candidate_transaction()
        _write_stdout(raw)
        return 0
    except BaseException as error:
        category = _category(error).encode("ascii", "strict")
        try:
            os.write(2, b"completion host candidate failed: " + category + b"\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

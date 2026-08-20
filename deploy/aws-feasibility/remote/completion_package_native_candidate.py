#!/usr/bin/env python3
"""Non-authoritative retained-rootfs package candidate (V2 only).
V1 deliberately describes the host route and remains immutable.  This module
owns the distinct result contract for execution in the retained Stage 2 rootfs.
"""
import hashlib
import json
import os
from pathlib import Path
from completion_guest_workloads import (CleanupUncertain, Deadline, OwnedRoot, SignalScope,
    ToolSet, WorkloadError, WorkloadInterrupted, _check_versions, _run_package_sample,
    require_linux_amd64_root)
from completion_runtime_contract import (canonical_json, exact_runtime_closure,
    exact_tool_observations, load_candidate_contract, native_execution_binding,
    native_implementation_digests, validate_native_candidate_result)
CANDIDATE_ROOT = Path("/tmp/cogs-stage2-workload-candidate-v2")
FIXED_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
FIXED_NATIVE_DRIVER = FIXED_SOURCE / "scripts/run-stage2-package-native-candidate.py"
FIXED_SOURCE_MANIFEST = FIXED_SOURCE / ".cogs-stage2-source-manifest-v1.json"
MAX_OUTPUT_BYTES = 4096
# Captured after fixed-source verification and while its names are still visible,
# before namespace/chroot entry removes access to the source directory.
NATIVE_LAUNCHER_BYTES = FIXED_NATIVE_DRIVER.read_bytes()
NATIVE_LAUNCHER_SHA256 = hashlib.sha256(NATIVE_LAUNCHER_BYTES).hexdigest()
SOURCE_MANIFEST_BYTES = FIXED_SOURCE_MANIFEST.read_bytes()
SOURCE_MANIFEST_SHA256 = hashlib.sha256(SOURCE_MANIFEST_BYTES).hexdigest()
SOURCE_REVISION = json.loads(SOURCE_MANIFEST_BYTES)["revision"]
# Cache all fixed-source implementation bytes before chroot hides the source tree.
NATIVE_IMPLEMENTATION_DIGESTS = native_implementation_digests()
class NativeCandidateTransactionError(WorkloadError):
    category = "native-candidate-mismatch"


class NativeCandidateStageError(WorkloadError):
    def __init__(self, stage, cause):
        self.stage = stage
        if isinstance(cause, (KeyboardInterrupt, SystemExit)):
            category = "interrupted"
        elif isinstance(cause, OSError) and cause.errno is not None:
            category = f"OSError_{cause.errno}"
        else:
            category = getattr(cause, "category", type(cause).__name__)
        safe = (isinstance(category, str) and 1 <= len(category) <= 64
                and all(value.isascii() and (value.isalnum() or value in "_-")
                        for value in category))
        self.category = category if safe else "native-candidate-mismatch"
        super().__init__(stage)


def _stage_failure(stage, cause):
    return cause if isinstance(cause, NativeCandidateStageError) else NativeCandidateStageError(stage, cause)


class _StagedSignalScope:
    def __init__(self):
        self.scope = SignalScope()

    def __enter__(self):
        return self.scope.__enter__()

    def __exit__(self, *arguments):
        try:
            return self.scope.__exit__(*arguments)
        except BaseException as error:
            raise _stage_failure("signal-scope-close", error) from error


def _require(condition):
    if not condition:
        raise NativeCandidateTransactionError("native candidate invariant failed")
def _finish_root(root, failure):
    if root is not None:
        try:
            root.cleanup()
        except CleanupUncertain as error:
            return error
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
    raise NativeCandidateTransactionError("native candidate transaction failed") from None
def run_candidate_transaction():
    """Build A and B once using authentic retained-rootfs Git/dpkg tools."""
    deadline = Deadline.start()
    root = tools = failure = result = None
    stage = "transaction-inputs"
    try:
        _require(0 < len(NATIVE_LAUNCHER_BYTES) <= 256 * 1024)
        _require(0 < len(SOURCE_MANIFEST_BYTES) <= 16 * 1024 * 1024)
        _require(SOURCE_REVISION == os.environ.get("COGS_PACKAGE_REVIEWED_HEAD"))
        launcher_sha256 = NATIVE_LAUNCHER_SHA256
        with _StagedSignalScope():
            try:
                stage = "contract-load"
                contract = load_candidate_contract()
                stage = "platform-check"
                require_linux_amd64_root()
                stage = "runtime-closure"
                runtime_closure = exact_runtime_closure()
                stage = "tool-open"
                tools = ToolSet()
                stage = "owned-root"
                root = OwnedRoot(CANDIDATE_ROOT, deadline, "host-candidate")
                root.mkdir("private-home", 0o700)
                root.mkdir("private-tmp", 0o700)
                stage = "tool-version"
                _check_versions(root, tools, deadline)
                stage = "tool-observations"
                tool_observations = exact_tool_observations(tools.observations())
                stage = "build-a"
                first, _build_a_ms, _install_a_ms = _run_package_sample(
                    root, "candidate-a", tools, deadline)
                stage = "post-a-tools"
                _require(exact_tool_observations(tools.observations()) == tool_observations)
                stage = "post-a-contract"
                _require(load_candidate_contract() == contract)
                stage = "build-b"
                second, _build_b_ms, _install_b_ms = _run_package_sample(
                    root, "candidate-b", tools, deadline)
                stage = "compare-a-b"
                _require(first == second)
                stage = "post-b-tools"
                _require(exact_tool_observations(tools.observations()) == tool_observations)
                stage = "post-b-contract"
                _require(load_candidate_contract() == contract)
                stage = "result-binding"
                result = {
                    "version": "cogs.stage2-workload-candidate/v2",
                    "result": "pass",
                    "authority": "non-authoritative-retained-rootfs-candidate-only",
                    "candidate_contract_sha256": contract.sha256,
                    "final_pin_sha256": None,
                    "package_identity": first.value(),
                    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
                    "a_equals_b": True,
                    "lifecycle_deleted": True,
                    "promotion": "external-manual-review-required",
                    "execution_binding": native_execution_binding(
                        tool_observations, runtime_closure, launcher_sha256,
                        SOURCE_REVISION, SOURCE_MANIFEST_SHA256),
                }
            except BaseException as error:
                failure = _stage_failure(stage, error)
            finally:
                cleaned = _finish_root(root, failure)
                if cleaned is not failure:
                    failure = _stage_failure("transaction-cleanup", cleaned)
                if tools is not None:
                    try:
                        tools.close()
                    except BaseException as error:
                        failure = _stage_failure("tool-close", error)
        _raise_failure(failure)
        stage = "result-presence"
        _require(result is not None)
        stage = "result-validation"
        validate_native_candidate_result(result, SOURCE_REVISION, SOURCE_MANIFEST_SHA256)
        stage = "result-encoding"
        raw = canonical_json(result)
        _require(len(raw) <= MAX_OUTPUT_BYTES)
        return raw
    except NativeCandidateStageError:
        raise
    except BaseException as error:
        raise _stage_failure(stage, error) from error

#!/usr/bin/env python3
"""V2-only adapter for truthful retained-root package execution bindings."""

import copy
import hashlib
from pathlib import Path

import completion_runtime_contract as runtime

HISTORICAL_PARENT_ISOLATION = (
    "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp"
)
NATIVE_PARENT_ISOLATION = (
    "root-owned-mode-0700-baseline-transient-root-owned-execute-only-0711-dpkg-install-"
    "verified-0700-restore-workload-uid-gid-65534-zero-capabilities-nnp"
)
NATIVE_CODEC_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _require(condition, message):
    if not condition:
        raise runtime.WorkloadContractError(message)


def native_execution_binding(tool_observations, runtime_closure, launcher_sha256,
                             verified_source_revision, verified_source_manifest_sha256):
    value = runtime.native_execution_binding(
        tool_observations, runtime_closure, launcher_sha256,
        verified_source_revision, verified_source_manifest_sha256)
    value["native_codec_implementation_sha256"] = NATIVE_CODEC_SHA256
    value["operation_parent_isolation"] = NATIVE_PARENT_ISOLATION
    return value


def validate_native_candidate_result(value, expected_source_revision,
                                     expected_source_manifest_sha256):
    _require(type(value) is dict and type(value.get("execution_binding")) is dict,
             "native V2 execution binding is absent")
    binding = value["execution_binding"]
    _require(binding.get("native_codec_implementation_sha256") == NATIVE_CODEC_SHA256,
             "native V2 codec identity differs")
    _require(binding.get("operation_parent_isolation") == NATIVE_PARENT_ISOLATION,
             "native V2 parent lifecycle differs")
    historical = copy.deepcopy(value)
    historical_binding = historical["execution_binding"]
    historical_binding.pop("native_codec_implementation_sha256")
    historical_binding["operation_parent_isolation"] = HISTORICAL_PARENT_ISOLATION
    runtime.validate_native_candidate_result(
        historical, expected_source_revision, expected_source_manifest_sha256)
    return value

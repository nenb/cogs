"""Additive bridge from the reviewed package pin to prebuilt-rootfs closure."""

import completion_runtime_contract as historical
from completion_runtime_closure import ClosureResult


class PrebuiltRuntimeContractError(Exception): pass


def _require(value):
    if not value: raise PrebuiltRuntimeContractError()


def load_prebuilt_final_pin(closure):
    """Validate package-pin bytes without reopening the 16 producer inputs."""
    _require(type(closure) is ClosureResult and closure.object_count == len(closure.records) == 35)
    raw = historical._read_regular(historical.FINAL_PATH)
    _require(historical._sha(raw) == historical.REVIEWED_FINAL_PIN_SHA256)
    value = historical._json(raw)
    _require(raw == historical.canonical_json(value))
    contract = historical.load_candidate_contract()
    identity, pinned_closure = historical.validate_final_value(value)
    records = {record.path: record for record in closure.records}
    paths = {"git": "usr/bin/git", "dpkg-deb": "usr/bin/dpkg-deb", "dpkg": "usr/bin/dpkg"}
    for expected in historical.EXACT_TOOL_OBSERVATIONS:
        record = records.get(paths[expected["name"]])
        _require(record is not None and (record.content_sha256, record.size) ==
                 (expected["sha256"], expected["bytes"]))
    _require(pinned_closure.object_count == closure.object_count)
    observed = historical.RuntimeClosurePin(
        closure.manifest_sha256, closure.object_count,
        tuple(dict(row) for row in historical.EXACT_TOOL_OBSERVATIONS))
    return historical.FinalPin(contract.sha256, value["candidate_result_sha256"],
                               historical.REVIEWED_FINAL_PIN_SHA256, identity, observed)

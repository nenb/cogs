#!/usr/bin/env python3
"""Explicit split-lineage codec for current-source, no-mint KVM diagnostics."""

import hashlib
import json
import os
from pathlib import Path
import sys

_REMOTE_MODULE_ROOT = Path(__file__).resolve().parent
if not _REMOTE_MODULE_ROOT.is_dir():
    raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_REMOTE_MODULE_ROOT))

import completion_kata_preparation as preparation

VERSION = "cogs.stage2-current-source-prebuilt-diagnostic-control/v1"
AUTHORITY = "diagnostic-only-split-lineage-no-mint"
PROFILE = "current-source-fixed-prior-publication-full-readiness"
CONTROL_MEMBER = "stage2-current-source-prebuilt-diagnostic-control-v1.json"
PRODUCER_IMPLEMENTATION = "5bced6bdc54756761f28a393970301b9b24341cc"
PRODUCER_SOURCE_MANIFEST = "dd0ee3095d27cf9e14c3014558a6628d5f2f9b28eb75e00ddbf39a064487a954"
PUBLICATION_CONTROL = "3a3499f0f452bf0fe893a0214cf0c0bbd0cd0e99"
DESCRIPTOR_SHA256 = "015cb863f9b2ec8582619cc46c1914d41eb1b58ef1abc3384cdf34ed24c89029"
OCI_MANIFEST_SHA256 = "f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67"
USTAR_SHA256 = "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397"
SIGNATURE_SHA256 = "084d108813799a045db41a0e319b03a7fa13612de755d86cc0661be43cfc3425"
MAX_BYTES = 384 * 1024


class DiagnosticControlError(Exception):
    pass


def _require(condition, message="diagnostic split-lineage control differs"):
    if not condition:
        raise DiagnosticControlError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _exact(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _producer_implementation():
    return {"revision": PRODUCER_IMPLEMENTATION,
            "source_manifest_sha256": PRODUCER_SOURCE_MANIFEST}


def _runtime_revision(value):
    preparation._git_revision(value)
    _require(value != PRODUCER_IMPLEMENTATION,
             "prior producer cannot be the diagnostic runtime implementation")
    return value


def _validate_package(value):
    _exact(value, ("candidate_contract_sha256", "candidate_result_sha256",
                   "final_pin_sha256", "identity"))
    preparation._package_identity(value["identity"])
    for name in ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256"):
        preparation._digest(value[name])
    return value


def validate_control_value(value):
    _exact(value, ("version", "authority", "profile", "runtime_implementation",
                   "publication_producer", "package", "rootfs", "members"))
    _require(value["version"] == VERSION and value["authority"] == AUTHORITY
             and value["profile"] == PROFILE)
    implementation = value["runtime_implementation"]
    preparation._validate_implementation(implementation)
    _runtime_revision(implementation["revision"])
    _require(value["publication_producer"] == {
        "implementation_revision": PRODUCER_IMPLEMENTATION,
        "source_manifest_sha256": PRODUCER_SOURCE_MANIFEST,
        "control_revision": PUBLICATION_CONTROL,
        "descriptor_sha256": DESCRIPTOR_SHA256,
        "oci_manifest_sha256": OCI_MANIFEST_SHA256,
        "ustar_sha256": USTAR_SHA256,
        "signature_verification_sha256": SIGNATURE_SHA256,
    })
    _validate_package(value["package"])
    rootfs = value["rootfs"]
    _exact(rootfs, ("contract_sha256", "prebuilt_descriptor",
                    "prebuilt_descriptor_sha256", "custody"))
    preparation._digest(rootfs["contract_sha256"])
    descriptor_raw, descriptor = preparation._prebuilt_descriptor(
        rootfs["prebuilt_descriptor"], rootfs["prebuilt_descriptor_sha256"])
    _require(_sha(descriptor_raw) == DESCRIPTOR_SHA256
             and descriptor.producer_revision == PRODUCER_IMPLEMENTATION
             and descriptor.producer_source_manifest_sha256 == PRODUCER_SOURCE_MANIFEST
             and descriptor.manifest_digest == OCI_MANIFEST_SHA256
             and descriptor.ustar_sha256 == USTAR_SHA256)
    preparation._prebuilt_custody(rootfs["custody"], descriptor,
                                  _producer_implementation(), PUBLICATION_CONTROL)
    _require(rootfs["custody"]["signature_verification_sha256"] == SIGNATURE_SHA256)
    rows = value["members"]
    _require(type(rows) is list and len(rows) == 11)
    names, kinds = [], []
    for row in rows:
        _exact(row, ("name", "kind", "sha256", "size"))
        preparation._relative(row["name"])
        preparation._digest(row["sha256"])
        _require(row["kind"] in {"runtime-manifest", "executable-closure"}
                 and type(row["size"]) is int and 0 < row["size"] <= preparation.MAX_RUNTIME_BYTES)
        names.append(row["name"]); kinds.append(row["kind"])
    _require(names == sorted(set(names), key=lambda item: item.encode("ascii"))
             and kinds.count("runtime-manifest") == 1
             and kinds.count("executable-closure") == 10)
    _require({row["name"] for row in rows if row["kind"] == "runtime-manifest"}
             == {preparation.RUNTIME_MEMBER})
    return value


def load_control(raw):
    value = validate_control_value(preparation.decode_canonical(raw, MAX_BYTES))
    return preparation.StaticDescription(raw, _sha(raw), value)


def validate_control_members(control, members):
    _require(type(control) is preparation.StaticDescription
             and control.value["version"] == VERSION)
    rows = control.value["members"]
    _require(type(members) is dict and set(members) == {row["name"] for row in rows})
    for row in rows:
        raw = members[row["name"]]
        _require(type(raw) is bytes and len(raw) == row["size"]
                 and _sha(raw) == row["sha256"])
    runtime = preparation.load_runtime(members[preparation.RUNTIME_MEMBER])
    contracts = {}
    for executable in runtime.value["executables"]:
        raw = members[executable["contract_member"]]
        contract = preparation.load_contract(raw, executable)
        _require(contract.sha256 == executable["contract_sha256"]
                 and contract.value["closure_sha256"] == executable["tool_closure_sha256"]
                 and contract.value["objects"][0]["sha256"] == executable["executable_sha256"])
        contracts[executable["role"]] = contract
    rootfs = runtime.value["rootfs"]
    selected = control.value["rootfs"]
    _require(rootfs["prebuilt_descriptor"] == selected["prebuilt_descriptor"]
             and rootfs["prebuilt_descriptor_sha256"] == selected["prebuilt_descriptor_sha256"]
             and rootfs["ustar_sha256"] == USTAR_SHA256)
    return runtime, contracts


def normalized_envelope(control, runtime):
    """Return internal data only; this is deliberately not a formal envelope codec."""
    _require(type(control) is preparation.StaticDescription
             and type(runtime) is preparation.StaticDescription)
    rootfs = runtime.value["rootfs"]
    selected = control.value["rootfs"]
    value = {
        "implementation": control.value["runtime_implementation"],
        "package": control.value["package"],
        "rootfs": {
            "contract_sha256": selected["contract_sha256"],
            **{name: rootfs[name] for name in (
                "manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size",
                "entry_count", "prebuilt_descriptor", "prebuilt_descriptor_sha256")},
            "custody": selected["custody"],
        },
    }
    return preparation.StaticDescription(b"", "", value)


def build_control_bytes(implementation, runtime, package, rootfs_contract_sha256,
                        contracts, control_revision, prebuilt_custody):
    _require(os.environ.get("COGS_STAGE2_DIAGNOSTIC_CONTROL_VERSION") == VERSION
             and os.environ.get("COGS_STAGE2_CURRENT_REVISION") == implementation["revision"]
             and control_revision == PUBLICATION_CONTROL)
    preparation._validate_implementation(implementation)
    _validate_package(package)
    _require(type(contracts) is dict and set(contracts) == {row[0] for row in preparation.EXECUTABLES})
    clean_runtime = json.loads(preparation.canonical_bytes(runtime))
    for executable in clean_runtime["executables"]:
        expected = next(row for row in preparation.EXECUTABLES if row[0] == executable["role"])
        member = f"contracts/{preparation.EXECUTABLES.index(expected):02d}-{executable['role']}.json"
        contract_raw = preparation.canonical_bytes(
            preparation.validate_contract_value(contracts[executable["role"]], executable))
        executable["contract_member"] = member
        executable["contract_sha256"] = _sha(contract_raw)
        executable["executable_sha256"] = contracts[executable["role"]]["objects"][0]["sha256"]
        executable["tool_closure_sha256"] = contracts[executable["role"]]["closure_sha256"]
    preparation.validate_runtime_value(clean_runtime)
    descriptor = clean_runtime["rootfs"]["prebuilt_descriptor"]
    descriptor_sha256 = clean_runtime["rootfs"]["prebuilt_descriptor_sha256"]
    members = {preparation.RUNTIME_MEMBER: preparation.canonical_bytes(clean_runtime)}
    for executable in clean_runtime["executables"]:
        members[executable["contract_member"]] = preparation.canonical_bytes(
            contracts[executable["role"]])
    rows = [{"name": name,
             "kind": "runtime-manifest" if name == preparation.RUNTIME_MEMBER else "executable-closure",
             "sha256": _sha(raw), "size": len(raw)}
            for name, raw in sorted(members.items())]
    value = {
        "version": VERSION, "authority": AUTHORITY, "profile": PROFILE,
        "runtime_implementation": implementation,
        "publication_producer": {
            "implementation_revision": PRODUCER_IMPLEMENTATION,
            "source_manifest_sha256": PRODUCER_SOURCE_MANIFEST,
            "control_revision": PUBLICATION_CONTROL,
            "descriptor_sha256": DESCRIPTOR_SHA256,
            "oci_manifest_sha256": OCI_MANIFEST_SHA256,
            "ustar_sha256": USTAR_SHA256,
            "signature_verification_sha256": SIGNATURE_SHA256,
        },
        "package": package,
        "rootfs": {"contract_sha256": rootfs_contract_sha256,
                   "prebuilt_descriptor": descriptor,
                   "prebuilt_descriptor_sha256": descriptor_sha256,
                   "custody": prebuilt_custody},
        "members": rows,
    }
    raw = preparation.canonical_bytes(validate_control_value(value))
    validate_control_members(load_control(raw), members)
    return raw, members


def main():
    _require(sys.argv == [sys.argv[0]])
    raw, members = preparation.collect_fixed_candidate(builder=build_control_bytes)
    digest = preparation.publish_fixed_candidate(raw, members, CONTROL_MEMBER)
    result = preparation.canonical_bytes({
        "version": VERSION, "authority": AUTHORITY,
        "control_sha256": digest, "kvm_used": False,
    })
    _require(sys.stdout.buffer.write(result) == len(result))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        raise SystemExit(2)

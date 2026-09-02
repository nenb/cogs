#!/usr/bin/env python3
"""Portable hostile matrix for corrected custody and receipt boundaries."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_admission as admission
import completion_kata_preparation_bridge as preparation_bridge
import completion_local_receipt as receipt


def reject(call, kind=admission.AdmissionError):
    try:
        call()
    except kind:
        return
    raise AssertionError("hostile admission was accepted")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def executable(index, definition):
    role, source_class, path = definition
    return {"role": role, "source_class": source_class, "path": path,
            "contract_path": f"deploy/aws-feasibility/remote/contracts/{index:02d}-{role}.json",
            "contract_sha256": f"{index + 1:x}"[-1] * 64,
            "executable_sha256": f"{index + 2:x}"[-1] * 64,
            "tool_closure_sha256": f"{index + 3:x}"[-1] * 64}


def static_object(index):
    return {"version": "cogs.stage2-completion-runtime-object/v1",
            "path": f"usr/lib/object-{index:02d}.so", "source": "synthetic-test-only",
            "mode": 0o755, "size": index + 1, "content_sha256": f"{(index % 15) + 1:x}" * 64,
            "interpreter": None, "soname": f"object-{index:02d}.so", "needed": [], "resolved": []}


def valid_values():
    paths = sorted(admission.MANDATORY_SOURCES)
    files = [{"path": path, "sha256": f"{(index % 15) + 1:x}" * 64, "size": index + 1}
             for index, path in enumerate(paths)]
    executables = [executable(index, definition) for index, definition in enumerate(admission.EXECUTABLES)]
    objects = [static_object(index) for index in range(35)]
    static = {"version": "cogs.stage2-runtime-tool-closure/v1",
              "manifest_sha256": sha(b"".join(canonical(row) for row in objects)),
              "object_count": 35,
              "tools": [{"name": name, "sha256": digit * 64, "bytes": index + 1,
                         "version": f"synthetic-{name}-test-only"}
                        for index, (name, digit) in enumerate((("git", "a"), ("dpkg-deb", "b"), ("dpkg", "c")))]}
    static["objects"] = objects
    rootfs = "d" * 64
    mappings = [{"path": row["path"], "execution_path": f"/synthetic-test-only/{index:02d}",
                 "device": 1, "inode": index + 1, "mode": 0o555, "uid": 0, "gid": 0,
                 "nlink": 1, "size": row["size"], "sha256": row["content_sha256"]}
                for index, row in enumerate(objects)]
    execution_mapping = {"version": "cogs.stage2-local-execution-mapping/v1",
                         "rootfs_sha256": rootfs, "static_manifest_sha256": static["manifest_sha256"],
                         "objects": mappings}
    runtime_manifest = {"version": admission.RUNTIME_VERSION, "architecture": "x86_64",
                        "rootfs_sha256": rootfs, "static_closure": static,
                        "execution_mapping": execution_mapping, "executables": executables[5:]}
    identity = {"deb_sha256": "e" * 64, "deb_bytes": 1234,
                "installed_tree_sha256": "f" * 64, "installed_entries": 259,
                "installed_bytes": 1048576, "package": "cogs-stage2-fixture",
                "version": "1.0", "architecture": "all"}
    package = {"candidate_contract_sha256": "1" * 64, "candidate_result_sha256": "2" * 64,
               "final_pin_sha256": "3" * 64, "package_identity": identity,
               "artifact": {"sha256": identity["deb_sha256"], "bytes": identity["deb_bytes"]}}
    runtime = {"manifest_sha256": sha(canonical(runtime_manifest)), "rootfs_sha256": rootfs,
               "static_closure_sha256": static["manifest_sha256"],
               "execution_mapping_sha256": sha(canonical(execution_mapping))}
    by_path = {row["path"]: row for row in files}
    bindings = {"source_head": "1" * 40, "source_manifest_sha256": sha(canonical(files)),
                "host_attestation_sha256": sha(canonical(executables[:5])),
                "runtime_attestation_sha256": runtime["execution_mapping_sha256"],
                "rootfs_sha256": rootfs, "artifact_sha256": identity["deb_sha256"],
                "candidate_sha256": package["candidate_result_sha256"],
                "final_pin_sha256": package["final_pin_sha256"],
                "guest_program_sha256": admission.final_guest.GUEST_PROGRAM_SHA256,
                "owner_implementation_sha256": by_path["deploy/aws-feasibility/remote/completion_kata_coordinator.py"]["sha256"]}
    envelope = {"version": admission.VERSION, "authority": admission.AUTHORITY,
                "source": {"root": str(admission.FIXED_ROOT), "head": bindings["source_head"],
                           "manifest_sha256": bindings["source_manifest_sha256"], "files": files},
                "package": package, "runtime": runtime, "executables": executables,
                "result_bindings": bindings,
                "receipt": {"version": admission.RECEIPT_VERSION, "domain": admission.RECEIPT_DOMAIN}}
    return envelope, runtime_manifest


envelope, runtime_manifest = valid_values()
raw = canonical(envelope)
description = admission.load_envelope(raw)
assert description.value == envelope and description.sha256 == sha(raw)
assert admission.load_runtime_manifest(canonical(runtime_manifest)) == runtime_manifest
contract_row = envelope["executables"][0]
contract = {"version": admission.CONTRACT_VERSION, "architecture": "x86_64", "role": "ip",
            "path": "/usr/sbin/ip", "dynamic_tags": [],
            "objects": [{"kind": "executable", "path": "/usr/sbin/ip", "size": 7,
                         "sha256": contract_row["executable_sha256"], "interpreter": None,
                         "soname": None, "needed": []}]}
contract["closure_sha256"] = sha(canonical({name: value for name, value in contract.items() if name != "closure_sha256"}))
contract_row = {**contract_row, "tool_closure_sha256": contract["closure_sha256"]}
if sys.argv[1:] == ["--samples"]:
    print(json.dumps({"envelope": envelope, "runtime": runtime_manifest, "contract": contract}, separators=(",", ":")))
    raise SystemExit(0)
assert not sys.argv[1:]
assert admission._validate_contract(canonical(contract), contract_row) == contract
elf_fixtures = ROOT / "test/fixtures/outcome-two/elf"
assert admission._derived_elf((elf_fixtures / "valid-executable.elf").read_bytes()) == (
    "/lib64/ld-linux-x86-64.so.2", None, ("libalpha.so.1",))
assert admission._derived_elf((elf_fixtures / "valid-loader.elf").read_bytes()) == (
    None, "ld-linux-x86-64.so.2", ())
assert admission._derived_elf((elf_fixtures / "valid-libalpha.elf").read_bytes()) == (
    None, "libalpha.so.1", ("libbeta.so.1",))
for change in (
    lambda value: value.update(extra=True),
    lambda value: value.update(path="/tmp/ip"),
    lambda value: value["dynamic_tags"].append("RUNPATH"),
    lambda value: value["objects"].append(copy.deepcopy(value["objects"][0])),
    lambda value: value["objects"].append({**copy.deepcopy(value["objects"][0]), "kind": "library", "soname": "fake.so"}),
):
    hostile = copy.deepcopy(contract); change(hostile)
    reject(lambda hostile=hostile: admission._validate_contract(canonical(hostile), contract_row))
# Recomputing the outer closure digest cannot repair an aliased object path.
aliased = copy.deepcopy(contract)
aliased["objects"][0]["needed"] = ["fake.so"]
aliased["objects"].append({**copy.deepcopy(aliased["objects"][0]), "kind": "library",
                           "interpreter": None, "soname": "fake.so", "needed": []})
aliased["closure_sha256"] = sha(canonical({name: value for name, value in aliased.items()
                                           if name != "closure_sha256"}))
aliased_row = {**contract_row, "tool_closure_sha256": aliased["closure_sha256"]}
reject(lambda: admission._validate_contract(canonical(aliased), aliased_row))


def mutation(change):
    value = copy.deepcopy(envelope); change(value)
    reject(lambda: admission.load_envelope(canonical(value)))


mutation(lambda value: value["package"].update(candidate_result_sha256="0" * 64))
mutation(lambda value: value["package"]["artifact"].update(bytes=1235))
mutation(lambda value: value["package"]["package_identity"].update(deb_sha256="0" * 64))
mutation(lambda value: value["result_bindings"].update(runtime_attestation_sha256="0" * 64))
mutation(lambda value: value["result_bindings"].update(candidate_sha256="0" * 64))
reject(lambda: admission.load_envelope(json.dumps(envelope).encode() + b"\n"))
reject(lambda: admission.load_envelope(b'{"version":"duplicate",' + raw[1:]))

for change in (
    lambda value: value["static_closure"]["objects"].pop(),
    lambda value: value["static_closure"]["objects"].reverse(),
    lambda value: value["execution_mapping"]["objects"][1].update(execution_path=value["execution_mapping"]["objects"][0]["execution_path"]),
    lambda value: value["execution_mapping"]["objects"][1].update(inode=value["execution_mapping"]["objects"][0]["inode"]),
    lambda value: value["execution_mapping"].update(static_manifest_sha256="0" * 64),
):
    hostile = copy.deepcopy(runtime_manifest); change(hostile)
    reject(lambda hostile=hostile: admission.load_runtime_manifest(canonical(hostile)))

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); root.chmod(0o700)
    nested = root / "fixed"; nested.mkdir(mode=0o755)
    target = nested / "value"; target.write_bytes(b"exact-source")
    status = root.stat(); descriptor, parent, seen = admission._open_fixed_relative(root, "fixed/value", 64, status.st_uid, status.st_gid)
    try:
        assert admission._read_held(descriptor, seen, 64) == sha(b"exact-source")
    finally:
        os.close(descriptor); os.close(parent)
    os.link(target, nested / "alias")
    reject(lambda: admission._open_fixed_relative(root, "fixed/value", 64, status.st_uid, status.st_gid))

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); root.chmod(0o700); identity = root.stat()
    (root / "bin").mkdir(); (root / "usr").mkdir(); (root / "usr/sbin").mkdir()
    target = root / "bin/tool"; target.write_bytes(b"trusted-target"); target.chmod(0o755)
    (root / "usr/sbin/tool").symlink_to("/bin/tool")
    descriptor, parent, seen = admission._open_trusted_absolute_regular(
        "/usr/sbin/tool", 64, identity.st_uid, identity.st_gid, str(root))
    try:
        assert admission._read_held(descriptor, seen, 64) == sha(b"trusted-target")
    finally:
        os.close(descriptor); os.close(parent)
    (root / "usr/sbin/escape").symlink_to("../../../outside")
    reject(lambda: admission._open_trusted_absolute_regular(
        "/usr/sbin/escape", 64, identity.st_uid, identity.st_gid, str(root)))

assert admission.committed_status() == {"envelope_reviewed": False, "runtime_manifest_reviewed": False, "custody_issued": False}
assert admission.static_status()["v3_static_only"] is True
assert admission.static_status()["kvm_permit"] is False
reject(preparation_bridge._claim_fixed_static_preparation)
reject(preparation_bridge._claim_fixed_static_preparation, admission.AdmissionUnavailable)
reject(admission._take_static_preparation_issuer)
assert not hasattr(admission, "_claim_committed_execution_custody")
assert not hasattr(receipt, "_issue_local_receipt")
reject(lambda: receipt._consume_local_receipt(raw), receipt.LocalReceiptError)

# Recovery retirement is separately sealed and closes exactly the role and
# optional prepared-runtime claims issued in this process. The forward route
# still rejects the same partial claim set.
retire_recovery = admission._retire_recovery_executable_role_custody
retire_claims = inspect.getclosurevars(retire_recovery).nonlocals["retire_claims"]
routes = inspect.getclosurevars(retire_claims).nonlocals
custody_type = inspect.getclosurevars(routes["live_custody"]).nonlocals[
    "_StaticPreparationCustody"]
seal = inspect.getclosurevars(custody_type.__new__).nonlocals["seal"]
for with_prepared in (False, True):
    custody = custody_type(seal)
    descriptors = [os.open(os.devnull, os.O_RDONLY) for _index in range(8 + with_prepared)]
    role_claims = (object(), object())
    roles = {"ssh", "ssh-keygen"}
    routes["custody_states"][custody] = {
        "diagnostic": False, "recovery": True, "roles": roles,
        "descriptors": list(descriptors),
        "source_descriptors": (descriptors[2],), "source_anchor": descriptors[3],
        "configuration_identity": {"active_sha256": "a" * 64},
    }
    for index, (claim, role) in enumerate(zip(role_claims, sorted(roles))):
        routes["role_states"][claim] = {"custody": custody, "role": role,
            "descriptors": (descriptors[index],), "consumed": True}
    prepared_claim = object()
    if with_prepared:
        routes["prepared_states"][prepared_claim] = {
            "custody": custody, "descriptors": (descriptors[4],),
            "consumed": True, "verified": True}
    configuration = descriptors[5:8]
    with patch.object(admission, "_verify_retiring_observer_configuration",
                      return_value=tuple(configuration)):
        retire_recovery(custody)
    retired = {*descriptors[:2], descriptors[2], descriptors[3], *configuration}
    if with_prepared: retired.add(descriptors[4])
    assert all(descriptor not in routes["custody_states"][custody]["descriptors"]
               for descriptor in retired)
    for descriptor in retired:
        try: os.fstat(descriptor)
        except OSError: pass
        else: raise AssertionError("recovery retirement leaked a descriptor")
    assert not any(item["custody"] is custody for item in routes["role_states"].values())
    assert not any(item["custody"] is custody for item in routes["prepared_states"].values())
    admission._abort_static_preparation(custody)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    base_path = root / "base.toml"
    base_path.write_bytes(b"base")
    base_parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    base_fd = os.open(base_path, os.O_RDONLY)
    runtime_parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    retired_configuration = {
        "retired": True, "active_sha256": sha(b"base-derived"),
        "base_parent": base_parent, "base_fd": base_fd,
        "base_status": os.fstat(base_fd), "runtime_parent": runtime_parent,
        "runtime_parent_status": os.fstat(runtime_parent),
    }
    with patch.object(admission.preparation, "KATA_BASE_CONFIGURATION_SIZE", 4), \
         patch.object(admission.preparation, "derive_observer_configuration",
                      side_effect=lambda value: value + b"-derived"):
        assert admission._verify_retiring_observer_configuration(
            retired_configuration) == (base_parent, base_fd, runtime_parent)
        (root / "settled-sibling").mkdir()
        assert admission._verify_retiring_observer_configuration(
            retired_configuration) == (base_parent, base_fd, runtime_parent)
        (root / "kata-runtime-v1").mkdir()
        reject(lambda: admission._verify_retiring_observer_configuration(
            retired_configuration))
    os.close(runtime_parent); os.close(base_fd); os.close(base_parent)

partial_forward = custody_type(seal)
routes["custody_states"][partial_forward] = {
    "diagnostic": False, "recovery": False, "roles": set(), "descriptors": [],
    "source_descriptors": (), "source_anchor": None,
    "configuration_identity": {"active_sha256": "a" * 64},
}
reject(lambda: admission._retire_consumed_executable_role_custody(partial_forward))
admission._abort_static_preparation(partial_forward)

source = (REMOTE / "completion_kata_admission.py").read_text()
assert "REVIEWED_ENVELOPE_SHA256 = None" in source and "REVIEWED_RUNTIME_MANIFEST_SHA256 = None" in source
assert "candidate_contract_sha256" in source and "candidate_result_sha256" in source
assert "workload_contract.REVIEWED_ROOTFS_SHA256" not in source
assert 'COMPLETION_ROOTFS_SHA256 = "8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506"' in source
assert "fixed_runtime_closure(load_verified_build_inputs())" not in source
assert "prebuilt_runtime_closure(authority)" in source
assert "_fixed_prebuilt_rootfs_authority" in source
assert "_derived_elf(raw)" in source and "sorted(needed)" in source
assert 'item["kind"] == "executable"' in source
assert "time.monotonic_ns() + 300_000_000_000" in source
print("corrected custody/private receipt hostile matrix passed")

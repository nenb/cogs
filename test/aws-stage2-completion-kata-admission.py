#!/usr/bin/env python3
"""Portable hostile matrix for corrected custody and receipt boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_admission as admission
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
                "guest_program_sha256": by_path["deploy/aws-feasibility/remote/completion_guest_workloads_v2.py"]["sha256"],
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

assert admission.committed_status() == {"envelope_reviewed": False, "runtime_manifest_reviewed": False, "custody_issued": False}
assert not hasattr(admission, "_claim_committed_execution_custody")
assert not hasattr(receipt, "_issue_local_receipt")
reject(lambda: receipt._consume_local_receipt(raw), receipt.LocalReceiptError)
source = (REMOTE / "completion_kata_admission.py").read_text()
assert "REVIEWED_ENVELOPE_SHA256 = None" in source and "REVIEWED_RUNTIME_MANIFEST_SHA256 = None" in source
assert "candidate_contract_sha256" in source and "candidate_result_sha256" in source
assert "fixed_runtime_closure(load_verified_build_inputs())" in source
assert "_derived_elf(raw)" in source
print("corrected custody/private receipt hostile matrix passed")

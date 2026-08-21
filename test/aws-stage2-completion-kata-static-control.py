#!/usr/bin/env python3
"""Portable hostile tests for V2 static control and no-KVM admission."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_preparation as preparation


def canonical(value):
    return preparation.canonical_bytes(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reject(call):
    try:
        call()
    except preparation.PreparationError:
        return
    raise AssertionError("hostile static control was accepted")


def source_implementation():
    paths = sorted(preparation.MANDATORY_SECURITY_SOURCES)
    rows = [{"path": path, "sha256": f"{(index % 15) + 1:x}" * 64, "size": index + 1}
            for index, path in enumerate(paths)]
    return {"revision": "1" * 40, "source_manifest_sha256": "2" * 64,
            "selected_sources": rows, "selected_sources_sha256": sha(canonical(rows))}


def static_closure():
    objects = []
    for index in range(35):
        objects.append({"version": "cogs.stage2-completion-runtime-object/v1",
                        "path": f"usr/lib/object-{index:02d}.so", "source": "portable-test-only",
                        "mode": 0o555, "size": index + 1,
                        "content_sha256": f"{(index % 15) + 1:x}" * 64,
                        "interpreter": None, "soname": f"object-{index:02d}.so",
                        "needed": [], "resolved": []})
    return {"version": "cogs.stage2-runtime-tool-closure/v1",
            "manifest_sha256": sha(b"".join(canonical(row) for row in objects)),
            "object_count": 35,
            "tools": [{"name": name, "sha256": digit * 64, "bytes": index + 1,
                       "version": f"portable-{name}"}
                      for index, (name, digit) in enumerate((("git", "a"), ("dpkg-deb", "b"), ("dpkg", "c")))],
            "objects": objects}


def layout(label):
    rows = [{"path": f"{label}/asset", "kind": "file", "mode": 0o444,
             "uid": 0, "gid": 0, "size": 1, "link_target": None, "sha256": "d" * 64}]
    return preparation.section(rows)


def contract(role, path, digit):
    body = {"version": preparation.CONTRACT_VERSION, "architecture": "x86_64",
            "role": role, "path": path, "dynamic_tags": [],
            "objects": [{"kind": "executable", "path": path, "size": 1,
                         "sha256": digit * 64, "interpreter": None,
                         "soname": None, "needed": []}]}
    return {**body, "closure_sha256": sha(canonical(body))}


def values():
    contracts = {}
    executables = []
    for index, (role, source_class, path) in enumerate(preparation.EXECUTABLES):
        contracts[role] = contract(role, path, f"{(index % 15) + 1:x}")
        executables.append({"role": role, "source_class": source_class, "path": path,
                            "contract_member": "contracts/unset.json",
                            "contract_sha256": "1" * 64, "executable_sha256": "2" * 64,
                            "tool_closure_sha256": "3" * 64})
    artifacts = [{"role": role, "path": path, "kind": "file", "mode": 0o444,
                  "size": index + 1, "sha256": f"{index + 1:x}" * 64, "link_target": None}
                 for index, (role, path) in enumerate((
                     ("configuration", "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"),
                     ("containerd", "/runtime/bin/containerd"),
                     ("image", "/opt/kata/share/kata-containers/kata-containers.img"),
                     ("kernel", "/opt/kata/share/kata-containers/vmlinux.container"),
                     ("qemu", "/opt/kata/bin/qemu-system-x86_64"),
                     ("virtiofsd", "/opt/kata/libexec/virtiofsd"),
                 ))]
    archives = []
    for expected in preparation.ARCHIVES:
        archives.append({**expected, "layout": layout(expected["role"] + "-archive"),
                         "extracted": layout(expected["role"] + "-extracted")})
    runtime = {"version": preparation.RUNTIME_VERSION, "authority": preparation.AUTHORITY,
               "architecture": "x86_64", "archives": archives,
               "rootfs": {"manifest_sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
                          "manifest_size": 1_049_443,
                          "ustar_sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
                          "ustar_size": 136_905_728, "entry_count": 4_353,
                          "static_mapping_policy": {"uid": 0, "gid": 0, "nlink": 1,
                                                    "distinct_file_identities": True,
                                                    "path_basis": "rootfs-relative-no-symlink"},
                          "static_closure": static_closure()},
               "launch": {"runtime": "io.containerd.kata.v2",
                          "configuration": {"path": "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml",
                                            "size": 1, "sha256": "e" * 64},
                          "containerd_configuration_sha256": "f" * 64,
                          "mount_list_sha256": "1" * 64, "shared_filesystem": "virtio-fs",
                          "hypervisor": "qemu", "fallback": "none", "artifacts": artifacts,
                          "artifacts_sha256": sha(canonical(artifacts))},
               "executables": executables}
    package = {"candidate_contract_sha256": "b8660b92d778e9f5dc89586df4f68a2e2b12cdce818ff4fe12adf0a8e951fdf3",
               "candidate_result_sha256": "e967438172de7faee443c417fa85bf040f68decc889d74e21759b0aeb19d2b7b",
               "final_pin_sha256": "7dd03d3e4ef8ae7be1f76cefce3f704c86fb84765365a5eca0df437bf72e4d31",
               "identity": {"deb_sha256": "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
                            "deb_bytes": 1_064_816,
                            "installed_tree_sha256": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
                            "installed_entries": 259, "installed_bytes": 1_048_576,
                            "package": "cogs-stage2-fixture", "version": "1.0", "architecture": "all"}}
    return source_implementation(), runtime, package, contracts


implementation, runtime, package, contracts = values()
first_control, first_members = preparation.build_control_bytes(
    implementation, runtime, package,
    "caf9082f56625dc3f55a41ad115c7c700e84a1198e60c0cd9be420d7c13b4d54",
    contracts)
second_control, second_members = preparation.build_control_bytes(
    copy.deepcopy(implementation), copy.deepcopy(runtime), copy.deepcopy(package),
    "caf9082f56625dc3f55a41ad115c7c700e84a1198e60c0cd9be420d7c13b4d54",
    copy.deepcopy(contracts))
assert first_control == second_control and first_members == second_members
control = preparation.load_control(first_control)
envelope, runtime_description, loaded_contracts = preparation.validate_control_members(control, first_members)
assert set(loaded_contracts) == {row[0] for row in preparation.EXECUTABLES}
assert envelope.value["implementation"]["revision"] == "1" * 40
assert preparation.CONTROL_ROOT != preparation.SOURCE_ROOT
assert not str(preparation.CONTROL_ROOT).startswith(str(preparation.SOURCE_ROOT) + "/")
assert runtime_description.value["rootfs"]["static_closure"]["object_count"] == 35
assert "runtime_attestation_sha256" not in envelope.value["result_binding_base"]
serialized = first_control + b"".join(first_members.values())
for forbidden in (b'"device"', b'"inode"', b'"pid"', b'"qmp_socket"', b'"ctime_ns"'):
    assert forbidden not in serialized

# Every scalar in the immutable V1 final pin is raw-byte bound. Reformatting or
# changing any package/runtime field can never equal the reviewed authority.
final_path = REMOTE / "stage2-completion-runtime-v1.json"
final_value = json.loads(final_path.read_bytes())
reviewed_final_sha = "7dd03d3e4ef8ae7be1f76cefce3f704c86fb84765365a5eca0df437bf72e4d31"
assert sha(final_path.read_bytes()) == reviewed_final_sha


def leaf_paths(value, prefix=()):
    if type(value) is dict:
        for name, child in value.items():
            yield from leaf_paths(child, prefix + (name,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from leaf_paths(child, prefix + (index,))
    else:
        yield prefix


def mutate_leaf(value, path):
    target = value
    for component in path[:-1]:
        target = target[component]
    leaf = target[path[-1]]
    target[path[-1]] = leaf + 1 if type(leaf) is int else (not leaf if type(leaf) is bool else str(leaf) + "-drift")


for path in leaf_paths(final_value):
    hostile = copy.deepcopy(final_value)
    mutate_leaf(hostile, path)
    assert sha(canonical(hostile)) != reviewed_final_sha

# Every fixed category is independently bound and canonical.
for mutation in (
    lambda members: members.__setitem__(preparation.RUNTIME_MEMBER, members[preparation.RUNTIME_MEMBER][:-1] + b" \n"),
    lambda members: members.__setitem__(preparation.ENVELOPE_MEMBER, members[preparation.ENVELOPE_MEMBER].replace(b'"source_head":"', b'"source_head":"0', 1)),
    lambda members: members.__setitem__(next(name for name in members if name.startswith("contracts/")), b"{}\n"),
):
    hostile = dict(first_members)
    mutation(hostile)
    reject(lambda hostile=hostile: preparation.validate_control_members(control, hostile))

for change in (
    lambda value: value["producer"].update(kvm_absent=False),
    lambda value: value["producer"].update(network_used=True),
    lambda value: value["implementation"].update(revision="0" * 40),
    lambda value: value["members"].pop(),
):
    hostile = copy.deepcopy(control.value)
    change(hostile)
    reject(lambda hostile=hostile: preparation.load_control(canonical(hostile)))

runtime_value = copy.deepcopy(runtime_description.value)
for change in (
    lambda value: value["archives"][0].update(sha256="0" * 64),
    lambda value: value["archives"][0]["layout"].update(manifest_sha256="0" * 64),
    lambda value: value["rootfs"].update(ustar_sha256="0" * 64),
    lambda value: value["rootfs"]["static_closure"]["objects"].pop(),
    lambda value: value["launch"].update(fallback="tcg"),
    lambda value: value["executables"].reverse(),
    lambda value: value.update(inode=1),
):
    hostile = copy.deepcopy(runtime_value)
    change(hostile)
    reject(lambda hostile=hostile: preparation.load_runtime(canonical(hostile)))

escaping_link = [{"path": "runtime/link", "kind": "symlink", "mode": 0o777,
                  "uid": 0, "gid": 0, "size": 0, "link_target": "../../host", "sha256": None}]
reject(lambda: preparation.section(escaping_link))

source = (REMOTE / "completion_kata_preparation.py").read_text()
assert "/dev/kvm" not in source and "QMP_SOCKET" not in source
assert "os.getpid" not in source and "import completion_kata_coordinator" not in source
assert "subprocess.Popen" in source and '"/usr/bin/zstd"' in source
assert "def generate_implementation_h_candidate_control_bytes():" in source
assert "deploy/aws-feasibility/remote/completion_kata_preparation_bridge.py" in preparation.MANDATORY_SECURITY_SOURCES
bridge_source = (REMOTE / "completion_kata_preparation_bridge.py").read_text()
assert all(word not in bridge_source for word in ("getenv", "os.environ", "/dev/kvm", "QMP"))
assert "completion_kata_network" not in bridge_source and "completion_local" not in bridge_source
assert "_claim_fixed_executable_owner" in bridge_source and "_abandon_fixed_rootfs" in bridge_source
admission_source = (REMOTE / "completion_kata_admission.py").read_text()
assert "_claim_live_rootfs_mapping" in admission_source
assert "type(lease) is rootfs_lease.RetainedRootfsLease" in admission_source
assert "root.operation_fd" in admission_source
assert "def source_approval(custody):" in admission_source
assert "execution_path" not in runtime_description.raw.decode("ascii")

# V2 is additive: the historical V1 issuer still returns only its refusal.
import completion_kata_admission as admission
legacy = admission._take_execution_custody_issuer()
try:
    legacy()
except admission.AdmissionUnavailable:
    pass
else:
    raise AssertionError("historical V1 admission unexpectedly issued custody")

# The collector deterministically binds a complete archive layout and extracted
# postwalk without retaining live filesystem identities.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    archive = root / "synthetic.tar.gz"
    payload = b"static-asset\n"
    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as output:
        info = tarfile.TarInfo("runtime/asset")
        info.size = len(payload)
        info.mode = 0o444
        info.uid = info.gid = 0
        info.mtime = 0
        import io
        output.addfile(info, io.BytesIO(payload))
    raw_archive = archive.read_bytes()
    expected = {"name": archive.name, "size": len(raw_archive), "sha256": sha(raw_archive)}
    archive_rows = preparation.archive_layout(archive, expected)
    extracted = root / "extracted"
    (extracted / "runtime").mkdir(parents=True)
    (extracted / "runtime/asset").write_bytes(payload)
    os.chmod(extracted / "runtime/asset", 0o444)
    postwalk_rows = preparation.extracted_postwalk(extracted)
    assert archive_rows[0]["path"] == postwalk_rows[-1]["path"] == "runtime/asset"
    assert archive_rows[0]["sha256"] == postwalk_rows[-1]["sha256"] == sha(payload)
    assert all("inode" not in row and "device" not in row for row in archive_rows + postwalk_rows)

if sys.argv[1:] == ["--samples"]:
    print(json.dumps({"control": control.value, "envelope": envelope.value,
                      "runtime": runtime_description.value}, separators=(",", ":")))
elif sys.argv[1:]:
    raise AssertionError("unexpected arguments")
else:
    print("static V2 control/no-KVM admission hostile matrix passed")

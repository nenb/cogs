#!/usr/bin/env python3
"""Portable hostile tests for V2 static control and no-KVM admission."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_preparation as preparation
import completion_local_evidence as evidence


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


# The active file is a byte derivative, not a second caller-selected TOML.
synthetic_base = b'''[hypervisor.qemu]\npath = "/opt/kata/bin/qemu-system-x86_64"\nenable_annotations = ["enable_iommu", "kernel_params", "kernel_verity_params"]\nenable_debug = false\nextra_monitor_socket = ""\n\n[agent.kata]\nenable_debug = false\n\n[runtime]\nenable_debug = false\n'''
synthetic_active = preparation.derive_observer_configuration(
    synthetic_base, require_pinned=False)
assert synthetic_active == synthetic_base.replace(
    b"enable_debug = false", b"enable_debug = true", 1).replace(
    b'extra_monitor_socket = ""', b'extra_monitor_socket = "qmp"', 1)
assert len(synthetic_active) == len(synthetic_base) + 2
for hostile_base in (
    synthetic_base.replace(b"enable_debug = false", b"enable_debug = true", 1),
    synthetic_base.replace(b'extra_monitor_socket = ""', b'extra_monitor_socket = "qmp"', 1),
    synthetic_base.replace(b"[hypervisor.qemu]", b"[hypervisor.qemu]\n[hypervisor.qemu]"),
    synthetic_base.replace(b"enable_debug = false\nextra_monitor_socket",
                           b"enable_debug = false\nenable_debug = false\nextra_monitor_socket", 1),
):
    reject(lambda value=hostile_base: preparation.derive_observer_configuration(
        value, require_pinned=False))


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
    active = {"path": preparation.KATA_ACTIVE_CONFIGURATION_PATH, "size": 32_220,
              "sha256": "e" * 64,
              "base_path": preparation.KATA_BASE_CONFIGURATION_PATH,
              "base_size": 32_218,
              "base_sha256": preparation.KATA_BASE_CONFIGURATION_SHA256,
              "substitutions": [{"from": old.decode("ascii"), "to": new.decode("ascii")}
                                for old, new in preparation.KATA_CONFIGURATION_SUBSTITUTIONS]}
    base_artifact = next(row for row in artifacts if row["role"] == "configuration")
    base_artifact.update(mode=0o644, size=32_218,
                         sha256=preparation.KATA_BASE_CONFIGURATION_SHA256)
    artifacts.append({"role": "active-configuration", "path": active["path"],
                      "kind": "file", "mode": 0o400, "size": active["size"],
                      "sha256": active["sha256"], "link_target": None})
    artifacts.sort(key=lambda row: row["role"])
    runtime = {"version": preparation.RUNTIME_VERSION, "authority": preparation.AUTHORITY,
               "architecture": "x86_64", "archives": archives,
               "rootfs": {"manifest_sha256": "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1",
                          "manifest_size": 1_049_443,
                          "ustar_sha256": "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397",
                          "ustar_size": 136_905_728, "entry_count": 4_353,
                          "static_mapping_policy": {"uid": 0, "gid": 0, "nlink": 1,
                                                    "distinct_file_identities": True,
                                                    "path_basis": "rootfs-relative-no-symlink"},
                          "static_closure": static_closure()},
               "launch": {"runtime": "io.containerd.kata.v2",
                          "configuration": {"path": preparation.KATA_BASE_CONFIGURATION_PATH,
                                            "size": 32_218,
                                            "sha256": preparation.KATA_BASE_CONFIGURATION_SHA256},
                          "active_configuration": active,
                          "observer": {"private_socket": preparation.KATA_PRIVATE_QMP_SOCKET,
                                       "observer_socket": preparation.KATA_OBSERVER_QMP_SOCKET,
                                       "qmp_frontends": 2,
                                       "commands": ["qmp_capabilities", "query-status", "query-kvm"],
                                       "client_policy": "closed-query-only-full-control-endpoint",
                                       "debug_effect": "hypervisor-debug-kernel-parameters-and-debug-threads"},
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
    "8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506",
    contracts)
second_control, second_members = preparation.build_control_bytes(
    copy.deepcopy(implementation), copy.deepcopy(runtime), copy.deepcopy(package),
    "8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506",
    copy.deepcopy(contracts))
assert first_control == second_control and first_members == second_members
control = preparation.load_control(first_control)
envelope, runtime_description, loaded_contracts = preparation.validate_control_members(control, first_members)
assert set(loaded_contracts) == {row[0] for row in preparation.EXECUTABLES}
assert envelope.value["implementation"]["revision"] == "1" * 40
assert envelope.value["programs"]["guest_program_sha256"] == preparation.final_guest.GUEST_PROGRAM_SHA256
assert envelope.value["result_binding_base"]["guest_program_sha256"] == preparation.final_guest.GUEST_PROGRAM_SHA256
# Feed the exact producer-generated binding into the terminal evidence boundary.
# This prevents source-file digests from being substituted for the V3 stdin identity.
runtime_owner = evidence._RuntimeOwnerResult(
    operation_token="a" * 64,
    runtime_mount_record_sha256="b" * 64,
    network_causal_proof_sha256="c" * 64,
    live_mapping_sha256="d" * 64,
    qemu_process_sha256="e" * 64, qemu_argv_sha256="f" * 64,
    qemu_pid=101, qemu_starttime=102, qemu_executable_device=8,
    qemu_executable_inode=9, observer_qmp_device=10, observer_qmp_inode=11,
    kvm_device=12, kvm_inode=13, kvm_rdev=14,
    kvm_api=12, qmp_present=True, qmp_enabled=True,
)
terminal_bindings = dict(envelope.value["result_binding_base"])
terminal_bindings["host_attestation_sha256"] = "f" * 64
terminal_bindings["runtime_attestation_sha256"] = evidence._runtime_attestation_sha256(runtime_owner)
owner_bindings = evidence._BindingOwnerResult(**terminal_bindings)
genesis = SimpleNamespace(body={
    "source_revision": terminal_bindings["source_head"],
    "source_manifest_sha256": terminal_bindings["source_manifest_sha256"],
    "rootfs_pin": {"ustar_sha256": terminal_bindings["rootfs_sha256"]},
})
evidence._validate_bindings(terminal_bindings, owner_bindings, genesis, runtime_owner)
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

with tempfile.TemporaryDirectory() as directory:
    original_observation_root = preparation.OBSERVATION_ROOT
    try:
        preparation.OBSERVATION_ROOT = Path(directory)
        digest = preparation.publish_fixed_candidate(first_control, first_members)
        candidate = Path(directory) / "candidate"
        assert digest == sha(first_control)
        assert (candidate / preparation.CONTROL_MEMBER).read_bytes() == first_control
        assert {path.relative_to(candidate).as_posix() for path in candidate.rglob("*") if path.is_file()} \
            == {preparation.CONTROL_MEMBER, *first_members}
        assert all(path.stat().st_mode & 0o777 == 0o444
                   for path in candidate.rglob("*") if path.is_file())
        assert all(path.stat().st_mode & 0o777 == 0o555
                   for path in (candidate, *(path for path in candidate.rglob("*") if path.is_dir())))
        reject(lambda: preparation.publish_fixed_candidate(first_control, first_members))
    finally:
        preparation.OBSERVATION_ROOT = original_observation_root

source = (REMOTE / "completion_kata_preparation.py").read_text()
assert "/dev/kvm" not in source and "socket.connect" not in source
assert "os.getpid" not in source and "import completion_kata_coordinator" not in source
assert "subprocess.Popen" in source and '"/usr/bin/zstd"' in source
assert "def generate_implementation_h_candidate_control_bytes():" in source
assert "runtime_contract.REVIEWED_ROOTFS_SHA256" not in source
assert '"8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506", contracts' in source
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

isolated = subprocess.run(
    (sys.executable, "-I", "-B", "-c",
     "import runpy,sys;runpy.run_path(sys.argv[1],run_name='isolated_import')",
     str(REMOTE / "completion_kata_preparation.py")),
    cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    timeout=30, check=False)
assert isolated.returncode == 0, isolated.stderr

source_manifest = {
    "version": "cogs.stage2-source-manifest/v1", "revision": "a" * 40,
    "entries": [{"path": "source", "kind": "directory", "mode": 0o700,
                 "size": 0, "sha256": None}],
}
source_manifest_raw = json.dumps(
    source_manifest, ensure_ascii=False, separators=(",", ":"),
    allow_nan=False).encode("utf-8") + b"\n"
assert preparation.parse_source_manifest(source_manifest_raw) == source_manifest
sorted_source_raw = json.dumps(
    source_manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    allow_nan=False).encode("utf-8") + b"\n"
reject(lambda: preparation.parse_source_manifest(sorted_source_raw))

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
        archive_root = tarfile.TarInfo("./")
        archive_root.type = tarfile.DIRTYPE
        archive_root.mode = 0o755
        archive_root.uid = archive_root.gid = 0
        archive_root.mtime = 0
        output.addfile(archive_root)
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

# Alias admission is exact resolved identity plus exact bytes, not pathname or
# content-only equivalence.  The production collector itself must run on the
# usr-merged Linux/amd64 host used by the static candidate.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    target = root / "target"
    target.write_bytes(Path(sys.executable).read_bytes())
    alias = root / "alias"
    alias.symlink_to(target.name)
    same_raw, same_stat = preparation._stable_file_bytes(target)
    alias_raw, alias_stat = preparation._stable_file_bytes(alias)
    assert same_raw == alias_raw and (same_stat.st_dev, same_stat.st_ino) == (alias_stat.st_dev, alias_stat.st_ino)
    copy_path = root / "copy"
    copy_path.write_bytes(same_raw)
    copy_raw, copy_stat = preparation._stable_file_bytes(copy_path)
    assert copy_raw == same_raw and (copy_stat.st_dev, copy_stat.st_ino) != (same_stat.st_dev, same_stat.st_ino)
    missing = root / "missing"
    def mapped(logical, second=target):
        if logical.startswith("/lib/x86_64-linux-gnu/"): return alias
        if logical.startswith("/usr/lib/x86_64-linux-gnu/"): return second
        return missing
    selected = preparation._soname_candidate("libfixture.so.1", mapped)
    assert selected is not None and selected[0].startswith("/lib/")
    reject(lambda: preparation._soname_candidate(
        "libfixture.so.1", lambda logical: mapped(logical, copy_path)))
    alias.unlink(); alias.symlink_to(copy_path.name)
    reject(lambda: preparation._read_elf(selected[1], selected[2]))

if sys.platform.startswith("linux") and os.uname().machine == "x86_64":
    ip_path = Path("/usr/sbin/ip")
    assert ip_path.exists(), "Linux/amd64 production ip executable is required"
    ip_contract = preparation.collect_executable_contract(
        "ip", "/usr/sbin/ip", ip_path, lambda logical: Path(logical))
    assert ip_contract["path"] == "/usr/sbin/ip" and len(ip_contract["objects"]) > 1

if sys.argv[1:] == ["--samples"]:
    print(json.dumps({"control": control.value, "envelope": envelope.value,
                      "runtime": runtime_description.value}, separators=(",", ":")))
elif sys.argv[1:]:
    raise AssertionError("unexpected arguments")
else:
    print("static V2 control/no-KVM admission hostile matrix passed")

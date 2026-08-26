#!/usr/bin/env python3
"""Portable hostile tests for the immutable ADR 0043 mount contract."""

import base64
import copy
import dataclasses
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

if sys.flags.optimize != 0:
    raise RuntimeError("contract tests refuse Python optimization")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_kata_runtime.py"
sys.path.insert(0, str(MODULE_PATH.parent))
spec = importlib.util.spec_from_file_location("completion_kata_runtime_test", MODULE_PATH)
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)

source_root = (
    "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/"
    "completion-v1/kata-input-v1/share"
)
expected = [
    {"destination": "/proc", "options": ["nosuid", "noexec", "nodev"], "source": "proc", "type": "proc"},
    {
        "destination": "/dev", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        "source": "tmpfs", "type": "tmpfs",
    },
    {
        "destination": "/dev/pts",
        "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"],
        "source": "devpts", "type": "devpts",
    },
    {
        "destination": "/dev/shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
        "source": "shm", "type": "tmpfs",
    },
    {
        "destination": "/dev/mqueue", "options": ["nosuid", "noexec", "nodev"],
        "source": "mqueue", "type": "mqueue",
    },
    {"destination": "/sys", "options": ["nosuid", "noexec", "nodev", "ro"], "source": "sysfs", "type": "sysfs"},
    {
        "destination": "/run", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        "source": "tmpfs", "type": "tmpfs",
    },
    {
        "destination": "/run/cogs-stage2-ssh",
        "options": ["rw", "nosuid", "nodev", "noexec", "mode=0700", "size=67108864", "nr_inodes=16384"],
        "source": "tmpfs", "type": "tmpfs",
    },
    {
        "destination": "/run/cogs-stage2-ssh/ssh_host_ed25519_key",
        "options": ["bind", "ro", "nosuid", "nodev", "noexec", "private"],
        "source": source_root + "/ssh_host_ed25519_key", "type": "bind",
    },
    {
        "destination": "/run/cogs-stage2-ssh/authorized_keys",
        "options": ["bind", "ro", "nosuid", "nodev", "noexec", "private"],
        "source": source_root + "/authorized_keys", "type": "bind",
    },
    {
        "destination": "/run/cogs-stage2-ssh/input",
        "options": ["bind", "ro", "nosuid", "nodev", "noexec", "private"],
        "source": source_root + "/fixture", "type": "bind",
    },
]

# Independently reconstruct and pin the canonical bytes and digest.
canonical = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
expected_digest = "22157f258386d8d4be07ec6eb086a582936c23037be403caa829b644bf4e058e"
check(hashlib.sha256(canonical).hexdigest() == expected_digest, "independent digest changed")
check(runtime.canonical_mount_json() == canonical, "canonical bytes changed")
check(runtime.MOUNT_LIST_SHA256 == expected_digest, "published digest changed")
check(len(runtime.CANONICAL_MOUNTS) == 11, "published mount count changed")
check(
    [dataclasses.asdict(record) for record in runtime.CANONICAL_MOUNTS]
    == [{**record, "options": tuple(record["options"])} for record in expected],
    "published mount snapshots changed",
)
try:
    runtime.CANONICAL_MOUNTS[0].source = "other"
except dataclasses.FrozenInstanceError:
    pass
else:
    raise AssertionError("mount record was mutable")

stored = {"mounts": copy.deepcopy(expected), "otherStoredSpecField": {"separately": "validated"}}
check(runtime.validate_stored_spec(stored) == expected_digest, "valid stored spec was not attested")

expected_argv = (
    "--mount",
    "type=tmpfs,src=tmpfs,dst=/run/cogs-stage2-ssh,options=rw:nosuid:nodev:noexec:mode=0700:size=67108864:nr_inodes=16384",
    "--mount",
    f"type=bind,src={source_root}/ssh_host_ed25519_key,dst=/run/cogs-stage2-ssh/ssh_host_ed25519_key,options=bind:ro:nosuid:nodev:noexec:private",
    "--mount",
    f"type=bind,src={source_root}/authorized_keys,dst=/run/cogs-stage2-ssh/authorized_keys,options=bind:ro:nosuid:nodev:noexec:private",
    "--mount",
    f"type=bind,src={source_root}/fixture,dst=/run/cogs-stage2-ssh/input,options=bind:ro:nosuid:nodev:noexec:private",
)
check(runtime.custom_mount_argv() == expected_argv, "custom mount argv changed")
check(expected_argv.count("--mount") == 4, "custom mount count changed")
check(all("options=" in value for value in expected_argv[1::2]), "an options field is missing")
check(all("options=bind:" in value for value in expected_argv[3::2]), "bind options changed")


def rejected(value):
    try:
        runtime.validate_stored_spec(value)
    except runtime.KataMountContractError:
        return
    raise AssertionError("hostile stored spec accepted")


# Public inspection aliases cannot modify the closure-captured authority.
exposed_mounts = runtime.CANONICAL_MOUNTS
object.__setattr__(exposed_mounts[0], "source", "evil")
runtime.CANONICAL_MOUNTS = exposed_mounts[:7]
runtime.MOUNT_LIST_SHA256 = "0" * 64
check(runtime.canonical_mount_json() == canonical, "hostile aliases changed canonical bytes")
check(runtime.custom_mount_argv() == expected_argv, "hostile aliases changed argv")
check(runtime.validate_stored_spec(stored) == expected_digest, "hostile aliases changed returned digest")
shortened = copy.deepcopy(stored)
del shortened["mounts"][7:]
rejected(shortened)
expanded = copy.deepcopy(stored)
expanded["mounts"].append(copy.deepcopy(expected[-1]))
rejected(expanded)

# Every field, option, record position, and count is part of the contract.
ambiguities = ("\N{SNOWMAN}", "\x1f", ",extra")
for record_index, record in enumerate(expected):
    for field in ("type", "source", "destination"):
        for suffix in ambiguities:
            hostile = copy.deepcopy(stored)
            hostile["mounts"][record_index][field] += suffix
            rejected(hostile)
        hostile = copy.deepcopy(stored)
        hostile["mounts"][record_index][field] = 1
        rejected(hostile)
    hostile = copy.deepcopy(stored)
    hostile["mounts"][record_index]["additional"] = "field"
    rejected(hostile)
    hostile = copy.deepcopy(stored)
    del hostile["mounts"][record_index]["source"]
    rejected(hostile)
    for option_index in range(len(record["options"])):
        for suffix in ambiguities:
            hostile = copy.deepcopy(stored)
            hostile["mounts"][record_index]["options"][option_index] += suffix
            rejected(hostile)
        hostile = copy.deepcopy(stored)
        hostile["mounts"][record_index]["options"][option_index] = None
        rejected(hostile)
    hostile = copy.deepcopy(stored)
    hostile["mounts"][record_index]["options"].append("ro")
    rejected(hostile)
    hostile = copy.deepcopy(stored)
    del hostile["mounts"][record_index]["options"][0]
    rejected(hostile)
    if len(record["options"]) > 1:
        hostile = copy.deepcopy(stored)
        hostile["mounts"][record_index]["options"][:2] = reversed(hostile["mounts"][record_index]["options"][:2])
        rejected(hostile)

for index in range(11):
    hostile = copy.deepcopy(stored)
    del hostile["mounts"][index]
    rejected(hostile)
    hostile = copy.deepcopy(stored)
    hostile["mounts"].insert(index, copy.deepcopy(expected[index]))
    rejected(hostile)
for index in range(10):
    hostile = copy.deepcopy(stored)
    hostile["mounts"][index], hostile["mounts"][index + 1] = hostile["mounts"][index + 1], hostile["mounts"][index]
    rejected(hostile)

# Exact built-in containers and strings are required, with no malformed envelope.
class DictSubclass(dict):
    pass


class ListSubclass(list):
    pass


class StringSubclass(str):
    pass


for malformed in (None, [], {}, {"mounts": None}, {"mounts": tuple(expected)}, DictSubclass(stored)):
    rejected(malformed)
hostile = copy.deepcopy(stored)
hostile["mounts"] = ListSubclass(hostile["mounts"])
rejected(hostile)
hostile = copy.deepcopy(stored)
hostile["mounts"][0] = DictSubclass(hostile["mounts"][0])
rejected(hostile)
hostile = copy.deepcopy(stored)
hostile["mounts"][0]["options"] = ListSubclass(hostile["mounts"][0]["options"])
rejected(hostile)
for field in ("type", "source", "destination"):
    hostile = copy.deepcopy(stored)
    hostile["mounts"][0][field] = StringSubclass(hostile["mounts"][0][field])
    rejected(hostile)
hostile = copy.deepcopy(stored)
hostile["mounts"][0]["options"][0] = StringSubclass("nosuid")
rejected(hostile)
hostile = copy.deepcopy(stored)
hostile[StringSubclass("mounts")] = hostile.pop("mounts")
rejected(hostile)
hostile = copy.deepcopy(stored)
hostile["mounts"][0][StringSubclass("source")] = hostile["mounts"][0].pop("source")
rejected(hostile)

# S4 exact bootstrap and closed command specifications. Nothing is executed.
bootstrap = b"""set -eu
umask 077
/bin/mkdir -p /run/sshd /run/cogs-stage2-ssh/work
/bin/chown 0:0 /run/sshd /run/cogs-stage2-ssh/work
/bin/chmod 0755 /run/sshd
/bin/chmod 0700 /run/cogs-stage2-ssh/work
[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/sshd)" = "0:0:755:directory" ]
[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/cogs-stage2-ssh/work)" = "0:0:700:directory" ]
[ ! -e /run/cogs-stage2-ssh/sshd.pid ]
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
"""
check(runtime.BOOTSTRAP == bootstrap, "bootstrap bytes drifted")
policy_bootstrap = runtime.command_policy.BOOTSTRAP
check("\n" not in policy_bootstrap and "\r" not in policy_bootstrap
      and policy_bootstrap.startswith("set -eu; umask 077;")
      and policy_bootstrap.endswith("exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config"),
      "journal-safe bootstrap command drifted")
permit = runtime._make_fake_launch_permit_for_tests()
run = runtime.ctr_run_spec(permit)
check(run.command_id is runtime.actions.CommandId.CTR_RUN and run.stdin == b"", "run command envelope")
check(run.argv == runtime._ctr_metadata_argv()
      and run.argv[5:7] == ("containers", "create")
      and "run" not in run.argv and "tasks" not in run.argv,
      "metadata-only container create policy")
rejected(lambda: runtime.ctr_run_spec(permit))
operation_token = "a" * 64
network_value = {"operation_token": operation_token,
    "identity": {"mount_id": 1, "parent_id": 2, "device": "0:4",
                 "inode_device": 4, "inode": 5,
                 "name": "c42n" + operation_token[:10]},
    "path": runtime.operation_netns_path(operation_token)}
network_grant = object()
with patch.object(runtime.kata_network, "_consume_runtime_network",
                  return_value=network_value), \
     patch.object(runtime.kata_network, "_verify_runtime_network",
                  return_value=network_value):
    operation_permit = runtime._make_operation_launch_permit(network_grant)
    claimed_launch = runtime._claim_launch_permit(operation_permit)
    check(claimed_launch["operation_token"] == operation_token
          and claimed_launch["network"] == network_value["path"],
          "operation launch permit was not claimed before descriptor use")
    rejected(lambda: runtime._claim_launch_permit(operation_permit))
rejected(runtime._open_production_owner)
commands = {item.command_id.value: item for item in runtime.fixed_command_specs_for_tests()}
check(len(commands) == 7, "fixed command count")
check(commands["CTR_TASK_TERM"].argv[-4:] == ("kill", "--signal", "SIGTERM", runtime.CONTAINER_ID), "TERM argv")
check(commands["CTR_TASK_KILL"].argv[-4:] == ("kill", "--signal", "SIGKILL", runtime.CONTAINER_ID), "KILL argv")
check(commands["CTR_TASK_REMOVE"].argv[-3:] == ("tasks", "rm", runtime.CONTAINER_ID), "task rm argv")
check(commands["CTR_CONTAINER_REMOVE"].argv[-3:] == ("containers", "rm", runtime.CONTAINER_ID), "container rm argv")
check(runtime.source_invariants_for_tests()["no_force"], "force command exposed")

# Complete containerd info/spec and list/task candidate schemas are fail closed.
fixture = runtime.unqualified_stored_info_fixture_for_tests()
check(fixture["qualification"] == runtime.QUALIFICATION_CANDIDATE, "fake was not labelled")
info = fixture["value"]
options = info["Runtime"]["Options"]
expected_options_value = options["value"]
check(options == {"type_url": "runtimeoptions.v1.Options", "value": expected_options_value},
      "ctr 2.2.1 outer Any fixture drifted")
check(runtime.validate_stored_info(copy.deepcopy(info)) == expected_digest, "stored info candidate")
realistic_info = (json.dumps(info, indent=4) + "\n").encode("utf-8")
check(runtime.validate_stored_info(realistic_info) == expected_digest, "realistic ctr info JSON")
native_info = copy.deepcopy(info); native_token = "a" * 64
native_launch_path = "/proc/123/fd/202"
native_root_path = runtime.BASE + "/rootfs-v1/operation-" + "b" * 64 + "/rootfs"
native_launch = {"namespace_path": native_launch_path, "root_path": native_root_path}
native_info.update({"Labels": None, "SandboxID": ""})
native_info["Spec"] = runtime._native_stored_oci_spec(
    native_token, native_launch_path, native_root_path)
native_network = {"operation_token": native_token,
                  "path": runtime.operation_netns_path(native_token)}
with patch.object(runtime.kata_network, "_verify_runtime_network", return_value=native_network):
    check(runtime.validate_stored_info(native_info, object(), native_launch) == expected_digest,
          "native containerd 2.2.1 stored normalization")
hostile_native_info = copy.deepcopy(native_info)
hostile_native_info["Spec"]["linux"]["resources"]["cpu"]["shares"] = 2048
with patch.object(runtime.kata_network, "_verify_runtime_network", return_value=native_network):
    rejected(lambda: runtime.validate_stored_info(hostile_native_info, object(), native_launch))
for path, replacement in (
    (("Runtime", "Name"), "runc"),
    (("Spec", "root", "readonly"), False),
    (("Spec", "process", "terminal"), True),
    (("Spec", "process", "cwd"), "/tmp"),
    (("Spec", "linux", "namespaces", 4, "path"), "/run/netns/other"),
):
    hostile = copy.deepcopy(info)
    target = hostile
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    rejected(lambda hostile=hostile: runtime.validate_stored_info(hostile))
hostile = copy.deepcopy(info)
hostile["Spec"]["extra"] = None
rejected(lambda: runtime.validate_stored_info(hostile))
hostile_raw = json.dumps(info, separators=(",", ":")).encode()
for duplicate in (
    hostile_raw.replace(b'{"ID"', b'{"ID":"duplicate","ID"', 1),
    hostile_raw.replace(b'{"type_url"', b'{"type_url":"duplicate","type_url"', 1),
    hostile_raw.replace(b',"value"', b',"value":"duplicate","value"', 1),
):
    rejected(lambda duplicate=duplicate: runtime.validate_stored_info(duplicate))

def runtime_options_wire(wire, type_url=runtime.RUNTIME_OPTIONS_TYPE_URL):
    return {"type_url": type_url, "value": base64.b64encode(wire).decode("ascii")}

def rejected_options(candidate):
    hostile = copy.deepcopy(info); hostile["Runtime"]["Options"] = candidate
    rejected(lambda: runtime.validate_stored_info(hostile))

config = runtime.RUNTIME_CONFIG.encode("utf-8")
canonical_wire = b"\x12" + bytes((0x80 | (len(config) & 0x7f), len(config) >> 7)) + config
check(base64.b64decode(options["value"], validate=True) == canonical_wire, "runtime options wire fixture")
for wrong_type in ("", "type.googleapis.com/runtimeoptions.v1.Options",
                   "io.containerd.kata.v2.options", "runtimeoptions.v1.Options/other"):
    rejected_options(runtime_options_wire(canonical_wire, wrong_type))
for malformed_base64 in ("", "*", options["value"] + "\n", options["value"] + "=", "é",
                         "A" * (runtime.MAX_RUNTIME_OPTIONS_BASE64 + 4)):
    rejected_options({"type_url": runtime.RUNTIME_OPTIONS_TYPE_URL, "value": malformed_base64})
for malformed_wire in (
    b"", b"\x12", b"\x12\x40" + config[:-1], b"\x12\xc0\x00" + config,
    b"\x92\x00" + bytes((len(config),)) + config, b"\x0a\x01x", b"\x1a\x00", b"\x22\x00",
    canonical_wire + canonical_wire, canonical_wire + b"\x22\x00", b"\x12\x01\xff",
    b"\x12\x06/other", b"\x12\x00", b"\x12\x80\x01" + b"x" * 128,
    b"\x12\x84\x04" + b"x" * runtime.MAX_RUNTIME_OPTIONS_WIRE,
):
    rejected_options(runtime_options_wire(malformed_wire))
for malformed_options in (
    {"type_url": runtime.RUNTIME_OPTIONS_TYPE_URL},
    {"type_url": runtime.RUNTIME_OPTIONS_TYPE_URL, "value": options["value"], "unknown": None},
    {"type_url": runtime.RUNTIME_OPTIONS_TYPE_URL, "value": 7},
    {"TypeUrl": runtime.RUNTIME_OPTIONS_TYPE_URL, "Value": options["value"]},
):
    rejected_options(malformed_options)
container_absent = b"CONTAINER    IMAGE    RUNTIME\n"
container_exact = container_absent + b"cogs-stage2-ssh-v1    -    io.containerd.kata.v2\n"
check(runtime.classify_container_list(container_absent) is runtime.Observation.ABSENT, "container absence")
check(runtime.classify_container_list(
    b"CONTAINER    IMAGE    RUNTIME    \n") is runtime.Observation.ABSENT,
    "real padded container header")
rejected(lambda: runtime.classify_container_list(b"CONTAINER\tIMAGE RUNTIME\n"))
check(runtime.classify_container_list(container_exact) is runtime.Observation.EXACT, "container exact")
check(runtime.classify_container_list(container_exact.replace(b"kata.v2", b"runc.v2")) is runtime.Observation.PRESERVE, "runtime drift")
task_absent = b"TASK    PID    STATUS\n"
task_exact = task_absent + b"cogs-stage2-ssh-v1    101    STOPPED\n"
check(runtime.classify_task_list(task_absent, 101) == "absent", "task absence")
check(runtime.classify_task_list(b"TASK    PID    STATUS    \n", 101) == "absent",
      "real padded task header")
rejected(lambda: runtime.classify_task_list(b"TASK\tPID STATUS\n", 101))
check(runtime.classify_task_list(task_exact, 101) == "stopped", "task exact")
check(runtime.classify_task_list(task_exact, 102) == "preserve", "task PID replacement")
# A later complete list proves failed-launch absence even though ctr info uses
# its native nonzero not-found shape. Successful malformed info remains strict,
# and nonzero/hostile lists can never prove absence.
not_found = (1, b"", b"ctr: container not found\n")
absent_ctr = runtime.classify_ctr_observation(not_found, (0, container_absent, b""),
                                               (0, task_absent, b""))
check(absent_ctr == {"container": runtime.Observation.ABSENT, "task": "absent", "mount": None},
      "nonzero info blocked proven absence")
replacement_ctr = runtime.classify_ctr_observation(not_found, (0, container_exact, b""),
                                                    (0, task_exact, b""), 102)
check(replacement_ctr["container"] is runtime.Observation.PRESERVE and
      replacement_ctr["task"] == "preserve", "replacement identity was adopted")
for hostile in ((1, container_absent, b"failure"), (0, b"truncated", b"")):
    rejected(lambda hostile=hostile: runtime.classify_ctr_observation(
        not_found, hostile, (0, task_absent, b"")))
rejected(lambda: runtime.classify_ctr_observation(
    (0, b"{}", b""), (0, container_absent, b""), (0, task_absent, b"")))

# Bounded complete fake /proc snapshots bind executable, cmdline, starttime,
# ancestry, and namespace identity. Early exit and ambiguity preserve.
runtime_netns = {"operation_token": "a" * 64,
    "identity": {"mount_id": 1, "parent_id": 2, "device": "0:4",
                 "inode_device": 4, "inode": 4026532625,
                 "name": "c42n0123456789"},
    "path": "/run/netns/c42n0123456789"}
check(runtime._runtime_netns_root(runtime_netns) == "net:[4026532625]",
      "runtime network grant was not converted to an exact procfs namespace")
for hostile in ({**runtime_netns, "path": "/run/netns/foreign"},
                {**runtime_netns, "identity": {**runtime_netns["identity"], "inode": 0}},
                {**runtime_netns, "identity": {**runtime_netns["identity"], "name": "foreign"}}):
    rejected(lambda hostile=hostile: runtime._runtime_netns_root(hostile))

def proc_row(role, pid, ppid, start, executable, mnt, net):
    return {
        "role": role, "pid": pid, "ppid": ppid, "starttime": start,
        "executable": executable, "executable_device": 8, "executable_inode": pid + 1000,
        "cmdline": [executable, runtime.SANDBOX_ID],
        "namespaces": {
            "ipc": "ipc:[1]", "mnt": f"mnt:[{mnt}]", "net": f"net:[{net}]",
            "pid": "pid:[4]", "user": "user:[5]", "uts": "uts:[6]",
        },
    }

proc_rows = [
    proc_row("shim", 100, 1, 1000, "/opt/kata/bin/containerd-shim-kata-v2", 10, 20),
    proc_row("qemu", 101, 100, 1001, "/opt/kata/bin/qemu-system-x86_64", 11, 21),
    proc_row("virtiofsd", 102, 100, 1002, "/opt/kata/libexec/virtiofsd", 10, 21),
]
proc_fixture = {"complete": True, "early_exit": False, "rows": proc_rows,
                "qualification": runtime.QUALIFICATION_CANDIDATE}
def classify_process(value):
    return runtime.classify_process_snapshot(
        value, host_netns="net:[20]", operation_netns="net:[21]")
classified = classify_process(proc_fixture)
check(classified.disposition is runtime.Observation.EXACT and len(classified.records) == 3, "real Kata 3.32 role namespaces")
native_proc_fixture = copy.deepcopy(proc_fixture)
native_proc_fixture["rows"][0]["cmdline"] = [
    "/opt/kata/bin/containerd-shim-kata-v2", "-namespace", runtime.NAMESPACE,
    "-publish-binary", "", "-id", runtime.SANDBOX_ID,
]
native_proc_fixture["rows"][1]["cmdline"] = [
    "/opt/kata/bin/qemu-system-x86_64",
    "-name", "sandbox-" + runtime.SANDBOX_ID + ",debug-threads=on",
]
native_proc_fixture["rows"][1]["namespaces"]["mnt"] = "mnt:[10]"
native_proc_fixture["rows"][2]["cmdline"] = [
    "/opt/kata/libexec/virtiofsd",
    "--shared-dir=/run/kata-containers/shared/sandboxes/" + runtime.SANDBOX_ID + "/shared",
]
native_proc_fixture["rows"][2]["namespaces"].update({"mnt": "mnt:[12]", "net": "net:[22]"})
check(classify_process(native_proc_fixture).disposition is runtime.Observation.EXACT,
      "native private virtiofsd mount/network namespaces")
hostile_empty_argv = copy.deepcopy(native_proc_fixture)
hostile_empty_argv["rows"][1]["cmdline"].insert(1, "")
rejected(lambda: classify_process(hostile_empty_argv))
hostile_native_proc = copy.deepcopy(native_proc_fixture)
hostile_native_proc["rows"][2]["namespaces"]["net"] = "net:[20]"
check(classify_process(hostile_native_proc).disposition is runtime.Observation.PRESERVE,
      "virtiofsd private namespace collision accepted")
generation = {"mount_id": 30, "device": 8, "inode": 9, "kind": "file",
              "mode": 0o755, "uid": 0, "gid": 0, "nlink": 1, "size": 10,
              "mtime_ns": 11, "ctime_ns": 12}
check(runtime._same_executable_backing({**generation, "mount_id": 5526}, generation),
      "process mount-namespace executable was not bound to exact backing file")
check(not runtime._same_executable_backing({**generation, "mount_id": 5526, "inode": 10}, generation),
      "different executable backing inode was accepted")
worker_rows = copy.deepcopy(proc_rows)
worker = copy.deepcopy(worker_rows[2]); worker.update({"pid": 103, "ppid": 102, "starttime": 1003})
worker["namespaces"]["pid"] = "pid:[7]"; worker_rows.append(worker)
collapsed = runtime._collapse_virtiofsd_worker(worker_rows)
check([row["pid"] for row in collapsed] == [100, 101, 102],
      "exact nested virtiofsd worker was not collapsed to its owned launcher")
hostile_worker = copy.deepcopy(worker_rows); hostile_worker[-1]["namespaces"]["net"] = "net:[99]"
rejected(lambda: runtime._collapse_virtiofsd_worker(hostile_worker))
for mutation in ("early", "duplicate", "ancestry", "namespace"):
    hostile = copy.deepcopy(proc_fixture)
    if mutation == "early":
        hostile["early_exit"] = True
    elif mutation == "duplicate":
        hostile["rows"].append(copy.deepcopy(hostile["rows"][1]))
        hostile["rows"][-1]["pid"] = 103
    elif mutation == "ancestry":
        hostile["rows"][1]["ppid"] = 1
    else:
        hostile["rows"][1]["namespaces"]["net"] = "net:[99]"
    check(classify_process(hostile).disposition is runtime.Observation.PRESERVE,
          f"process {mutation} did not preserve")
for role, hostile_net in (("shim", "net:[21]"), ("qemu", "net:[20]"),
                          ("virtiofsd", "net:[20]")):
    hostile = copy.deepcopy(proc_fixture)
    next(row for row in hostile["rows"] if row["role"] == role)["namespaces"]["net"] = hostile_net
    check(classify_process(hostile).reason == "namespace-correlation",
          f"Kata 3.32 {role} namespace role drift accepted")
hostile = copy.deepcopy(proc_fixture); hostile["rows"][2]["namespaces"]["mnt"] = "mnt:[11]"
check(classify_process(hostile).reason == "namespace-correlation", "virtiofsd mount role drift accepted")
empty_proc = {**proc_fixture, "rows": []}
check(runtime.classify_process_snapshot(empty_proc).disposition is runtime.Observation.ABSENT, "process absence")

# Retirement observations accept only monotonic subsets of the durable closed
# role map; they never mutate or reinterpret replacement identities.
baseline_roles = {row.role: {
    "role": row.role, "pid": row.pid, "starttime": row.starttime,
    "executable": row.executable, "executable_device": row.executable_device,
    "executable_inode": row.executable_inode, "executable_generation": {"retained": row.role},
    "namespaces": [list(item) for item in row.namespaces],
} for row in classified.records}
disappeared = set()
partial = runtime.ProcessClassification(runtime.Observation.PRESERVE, classified.records[:2], "retiring")
current, disappeared = runtime._retirement_identity_rows(baseline_roles, partial, disappeared)
check(set(current) == {"shim", "qemu"} and disappeared == {"virtiofsd"}, "delayed role retirement")
absent_class = runtime.ProcessClassification(runtime.Observation.ABSENT, (), "complete-absence")
current, disappeared = runtime._retirement_identity_rows(baseline_roles, absent_class, disappeared)
check(not current and disappeared == set(baseline_roles), "complete retirement observation")
current, disappeared = runtime._retirement_identity_rows(baseline_roles, absent_class, disappeared)
check(not current, "stable second all-absent observation")
rejected(lambda: runtime._retirement_identity_rows(baseline_roles, partial, disappeared))
replacement = dataclasses.replace(classified.records[0], starttime=classified.records[0].starttime + 1)
rejected(lambda: runtime._retirement_identity_rows(
    baseline_roles, runtime.ProcessClassification(runtime.Observation.PRESERVE, (replacement,), "replacement"), set()))
rejected(lambda: runtime._retirement_identity_rows(
    baseline_roles, runtime.ProcessClassification(runtime.Observation.PRESERVE,
        (classified.records[0], classified.records[0]), "duplicate"), set()))

# Random Kata leaves are observed, not selected or removed. Complete mountinfo
# correlates every row while 64/depth-4/total-256 limits fail closed.
def linux_device(major, minor):
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12) | ((major & ~0xfff) << 32)

mountinfo = (
    b"1 1 8:1 / / rw - ext4 /dev/root rw\n"
    b"42 1 0:42 / /run/kata-containers/shared/sandboxes/cogs-stage2-ssh-v1 rw - tmpfs tmpfs rw\n"
)
native_mountinfo = mountinfo + (
    b"43 1 0:4 net:[4026532627] /run/netns/c42n0123456789 rw - nsfs nsfs rw\n"
    b"44 1 0:4 mnt:[4026532698] /run/snapd/ns/example.mnt rw - nsfs nsfs rw\n"
    b"45 1 0:45 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw\n")
check(len(runtime.parse_mountinfo(native_mountinfo)) == 5, "exact native nsfs and stacked mount roots")
rejected(lambda: runtime.parse_mountinfo(
    native_mountinfo + b"45 1 0:46 / /other rw - tmpfs tmpfs rw\n"))
for hostile_root in (b"pid:[4026532627]", b"net:[0]", b"net:4026532627"):
    rejected(lambda hostile_root=hostile_root: runtime.parse_mountinfo(
        mountinfo + b"43 1 0:4 " + hostile_root
        + b" /run/netns/c42n0123456789 rw - nsfs nsfs rw\n"))
share_rows = [
    {"path": ".", "kind": "directory", "device": linux_device(0, 42), "inode": 10,
     "mount_id": 42, "mode": 0o700, "uid": 0, "gid": 0, "nofollow": True},
    {"path": "mounts", "kind": "directory", "device": linux_device(0, 42), "inode": 11,
     "mount_id": 42, "mode": 0o700, "uid": 0, "gid": 0, "nofollow": True},
    {"path": "mounts/random-a", "kind": "file", "device": linux_device(0, 42), "inode": 12,
     "mount_id": 42, "mode": 0o600, "uid": 0, "gid": 0, "nofollow": True},
]
share_fixture = {"root": runtime.SHARE_ROOT, "complete": True, "rows": share_rows,
                 "qualification": runtime.QUALIFICATION_CANDIDATE}
share = runtime.classify_share_snapshot(share_fixture, mountinfo)
check(share.disposition is runtime.Observation.EXACT and share.entries[-1].path == "mounts/random-a", "share exact")
absent_share = {**share_fixture, "rows": []}
check(runtime.classify_share_snapshot(absent_share, mountinfo.splitlines(keepends=True)[0]).disposition is runtime.Observation.ABSENT,
      "share absence")
for mutation in ("nofollow", "depth", "mount"):
    hostile = copy.deepcopy(share_fixture)
    hostile_mounts = mountinfo
    if mutation == "nofollow":
        hostile["rows"][1]["nofollow"] = False
        rejected(lambda hostile=hostile: runtime.classify_share_snapshot(hostile, hostile_mounts))
        continue
    if mutation == "depth":
        hostile["rows"].append({**hostile["rows"][-1], "path": "mounts/a/b/c/d", "inode": 14})
    else:
        hostile["rows"][0]["mount_id"] = 41
    check(runtime.classify_share_snapshot(hostile, hostile_mounts).disposition is runtime.Observation.PRESERVE,
          f"share {mutation} did not preserve")

# Recovery never adopts names and exposes only the ordered, non-force plan.
O = runtime.Observation
base_snapshot = runtime.RuntimeSnapshot(True, O.EXACT, "running", O.EXACT, O.EXACT,
                                        O.EXACT, O.EXACT, O.EXACT)
check(runtime.next_teardown_action(base_snapshot) is runtime.TeardownAction.REVOKE_READINESS, "readiness order")
revoked = dataclasses.replace(base_snapshot, readiness_revoked=True)
check(runtime.next_teardown_action(revoked) is runtime.TeardownAction.TASK_TERM, "TERM order")
waiting = dataclasses.replace(revoked, term_attempted=True)
check(runtime.next_teardown_action(waiting) is runtime.TeardownAction.OBSERVE_TASK, "observe before KILL")
check(runtime.next_teardown_action(dataclasses.replace(waiting, kill_permitted=True)) is runtime.TeardownAction.TASK_KILL, "KILL gate")
stopped = dataclasses.replace(revoked, task="stopped", network=O.ABSENT)
check(runtime.next_teardown_action(stopped) is runtime.TeardownAction.TASK_REMOVE, "task rm order")
task_gone = dataclasses.replace(stopped, task="absent")
check(runtime.next_teardown_action(task_gone) is runtime.TeardownAction.CONTAINER_REMOVE, "container rm order")
foreign = dataclasses.replace(base_snapshot, owned=False)
check(runtime.recovery_class(foreign) == "preserve_no_adoption", "name-only adoption")
clean = runtime.RuntimeSnapshot(True, O.ABSENT, "absent", O.ABSENT, O.ABSENT,
                                O.ABSENT, O.EXACT, O.ABSENT, True)
check(runtime.next_teardown_action(clean) is runtime.TeardownAction.COMPLETE, "closed teardown")

# V2 addressed policy is additive; every historical v1 byte snapshot above is unchanged.
v1 = runtime.fixed_command_specs_for_tests()
v2 = runtime.fixed_command_specs_v2()
check(len(v1) == len(v2) == 7, "versioned ctr command cardinality")
check(all(item.argv[1] == "--namespace" for item in v1), "historical v1 bytes changed")
check(all(item.argv[:3] == (runtime.STAGED_CTR, "--address", runtime.CONTAINERD_ADDRESS)
          for item in v2), "v2 ctr escaped private address")
run_v2 = runtime.ctr_run_spec_v2("a" * 64)
check(run_v2.argv == runtime.command_policy.ctr_run_argv("a" * 64), "v2 policy/spec drift")
check(runtime.ROOTFS_CANDIDATE not in run_v2.argv and "operation-" + "a" * 64 in run_v2.argv[-5],
      "v2 retained root policy")
check(hashlib.sha256(runtime.CONTAINERD_CONFIG_BYTES).hexdigest() == runtime.CONTAINERD_CONFIG_SHA256,
      "fixed private config digest")
check(runtime.private_containerd_spec_v2().argv == (runtime.STAGED_CONTAINERD, "--address", "/run/c42d/s", "--root", "/run/c42d/r", "--state", "/run/c42d/t", "--config", runtime.CONTAINERD_CONFIG), "private daemon short paths")
check(all(len(path.encode("ascii")) <= runtime.MAX_UNIX_PATH for path in (
      runtime.CONTAINERD_ADDRESS, runtime.CONTAINERD_TTRPC_ADDRESS, runtime.CONTAINERD_ROOT,
      runtime.CONTAINERD_STATE, runtime.CONTAINERD_SHIM_ENDPOINT)), "Linux AF_UNIX path bound")
check(runtime.CONTAINERD_TTRPC_ADDRESS == "/run/c42d/s.ttrpc", "exact containerd companion endpoint")
# The short alias is optional only before staging/after cleanup; any present
# object must be the exact root-owned symlink to the retained runtime tree.
alias_stat = SimpleNamespace(st_mode=__import__("stat").S_IFLNK | 0o777, st_uid=0, st_gid=0)
with patch.object(runtime.os, "lstat", side_effect=FileNotFoundError):
    check(not runtime._runtime_alias(), "absent alias was residue")
with patch.object(runtime.os, "lstat", return_value=alias_stat), \
     patch.object(runtime.os, "readlink", return_value=runtime.RUNTIME_ROOT):
    check(runtime._runtime_alias(), "exact root-owned alias rejected")
for hostile in (SimpleNamespace(st_mode=__import__("stat").S_IFREG | 0o600, st_uid=0, st_gid=0),
                SimpleNamespace(st_mode=__import__("stat").S_IFLNK | 0o777, st_uid=1, st_gid=0)):
    with patch.object(runtime.os, "lstat", return_value=hostile), \
         patch.object(runtime.os, "readlink", return_value=runtime.RUNTIME_ROOT):
        rejected(runtime._runtime_alias)
with patch.object(runtime.os, "lstat", return_value=alias_stat), \
     patch.object(runtime.os, "readlink", return_value="/foreign"):
    rejected(runtime._runtime_alias)
check(runtime.command_policy.CONTAINERD_ARCHIVE_SHA256 ==
      "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883"
      and runtime.command_policy.CONTAINERD_ARCHIVE_SIZE == 33_645_699, "containerd archive pin")
check(runtime.KATA_CONFIG_SHA256 == "7ecd072a35da55f5abc76d604a610cf3f2d543c7de0cefc4d1a81028facd2cae"
      and runtime.COMMITTED_EXECUTABLE_SHA256["/opt/kata/bin/qemu-system-x86_64"] ==
      "1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d",
      "committed Kata config/QEMU table")
policy = runtime.command_policy
check(policy.POLICY_VERSION == "cogs.stage2-kata-command-policy/v4-process-only-ssh-stable-1"
      and not hasattr(policy, "PHASE_COMMAND_TRACES")
      and policy.ATTESTED_COMMANDS == frozenset({"SSH_READY", "SSH_READINESS", *policy.KEY_COMMANDS}),
      "SSH-stable main process policy was replaced")
policy_value = {"version": policy.RUNTIME_POLICY_VERSION, "archive_sha256": policy.CONTAINERD_ARCHIVE_SHA256,
    "archive_size": policy.CONTAINERD_ARCHIVE_SIZE, "extraction": [list(row) for row in policy.CONTAINERD_EXTRACTION],
    "staged_containerd": policy.STAGED_CONTAINERD, "staged_ctr": policy.STAGED_CTR,
    "runtime_config": policy.RUNTIME_CONFIG,
    "alias": policy.RUNTIME_ALIAS, "address": policy.CONTAINERD_ADDRESS,
    "root": policy.CONTAINERD_ROOT, "state": policy.CONTAINERD_STATE,
    "mounts": list(policy.CTR_MOUNTS),
    "tails": {name: list(row) for name, row in policy.CTR_TAILS.items()},
    "traces": {name: list(row) for name, row in policy.RUNTIME_TRACES.items()},
    "ownership_traces": [list(row) for row in policy.RUNTIME_OWNERSHIP_TRACES],
    "post_kill_observations": policy.RUNTIME_POST_KILL_OBSERVATIONS,
    "post_kill_interval_ns": policy.RUNTIME_POST_KILL_INTERVAL_NS,
    "retirement_observations": policy.RUNTIME_RETIREMENT_OBSERVATIONS,
    "retirement_interval_ns": policy.RUNTIME_RETIREMENT_INTERVAL_NS,
    "proven_absent_traces": {name: list(row) for name, row in policy.RUNTIME_PROVEN_ABSENT_TRACES.items()}}
policy_raw = json.dumps(policy_value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
check(hashlib.sha256(policy_raw).hexdigest() == policy.RUNTIME_POLICY_SHA256,
      "runtime owner policy hash drift")
check(dict(policy.RUNTIME_TRACES) == {
    "NETWORK_READY": ("CONTAINERD_START", "CTR_CONTAINER_LIST", "CTR_RUN"),
    "RUNTIME_READY": ("CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"),
    "READINESS_REVOKED": ("CTR_TASK_LIST", "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST"),
    "OWNERSHIP_OBSERVED:task-exact": ("CTR_TASK_LIST", "CTR_TASK_TERM", "CTR_TASK_LIST", "CTR_TASK_KILL") +
        ("CTR_TASK_LIST",) * policy.RUNTIME_POST_KILL_OBSERVATIONS,
    "TASK_STOPPED": ("CTR_TASK_REMOVE", "CTR_TASK_LIST"),
    "NETWORK_ABSENT": ("CTR_CONTAINER_REMOVE", "CTR_CONTAINER_LIST"),
}, "runtime owner trace drift")
check(dict(policy.RUNTIME_PROVEN_ABSENT_TRACES) == {
    "TASK_STOPPED": ("CTR_TASK_LIST",), "NETWORK_ABSENT": ("CTR_CONTAINER_LIST",),
}, "proven-absence trace drift")
runtime.kata_operation._runtime_trace((), 0, "NETWORK_READY", candidate="CONTAINERD_START")
rejected(lambda: runtime.kata_operation._runtime_trace((), 0, "NETWORK_READY", candidate="CTR_RUN"))
# Every post-KILL read is a new durable trace position; each prefix can settle.
trace_records = []
for serial, command_id in enumerate(policy.RUNTIME_TRACES["OWNERSHIP_OBSERVED:task-exact"]):
    binding = f"{serial + 1:064x}"
    trace_records.append(SimpleNamespace(record_type="COMMAND_INTENT_V2", body={
        "command_serial": serial, "command_id": command_id, "binding_sha256": binding,
        "policy_version": policy.RUNTIME_POLICY_VERSION, "lifecycle_phase": "OWNERSHIP_OBSERVED"}))
    if command_id != "CONTAINERD_START":
        trace_records.append(SimpleNamespace(record_type="COMMAND_OUTCOME_V2", body={
            "command_serial": serial, "command_id": command_id, "binding_sha256": binding,
            "outcome": "exited", "status": 0, "uncertain": False}))
    if serial >= 4:
        runtime.kata_operation._runtime_trace(tuple(trace_records), len(trace_records), "OWNERSHIP_OBSERVED",
            {"task": "exact-owned"}, complete=True)
check(sum(row.body["command_id"] == "CTR_TASK_KILL" for row in trace_records
          if row.record_type == "COMMAND_INTENT_V2") == 1, "post-KILL trace repeated mutation")
check(runtime.command_policy.CONTAINERD_EXTRACTION == (
    ("bin/containerd", 44_050_184, "f5d70cf9a249a70a70c379ba8f7259ea91122650cc06103bc0fc44a04dbc54da", 0o500),
    ("bin/ctr", 22_143_160, "448b1d7a2da84b6265dc4685afcc6c69a6299de43b942b8a3d6d540f6585d1db", 0o500),
), "fixed extraction manifest")

# The pathname-free claimant derives every identity from reviewed contracts and
# retained source custody. Extra names, policy drift, and forged grants fail
# before any namespace mutation API is reachable.
prestage = runtime.prestage_runtime
extraction = runtime.command_policy.CONTAINERD_EXTRACTION
contracts = {name: SimpleNamespace(value={"objects": [{"path": str(
    prestage.admission.FIXED_ROOT.joinpath(*prestage._PATH, "bin", name)),
    "size": extraction[index][1], "sha256": extraction[index][2]}]})
    for index, name in enumerate(("containerd", "ctr"))}
active_expected = {"path": runtime.RUNTIME_CONFIG, "size": 32_220,
    "sha256": "e" * 64, "base_path": runtime.KATA_BASE_CONFIG,
    "base_size": 32_218, "base_sha256": runtime.KATA_CONFIG_SHA256,
    "substitutions": [{"from": "enable_debug = false", "to": "enable_debug = true"},
                      {"from": 'extra_monitor_socket = ""',
                       "to": 'extra_monitor_socket = "qmp"'}]}
generation_requests = []
def host_generation(descriptor, requested_kind=None):
    generation_requests.append((descriptor, requested_kind))
    kind = requested_kind or ("directory" if descriptor in {105, 106} else "file")
    mode = 0o700 if descriptor == 105 else 0o400 if descriptor == 109 else 0o500
    nlink = 3 if descriptor == 105 else 2 if descriptor == 106 else 1
    size = 0 if kind == "directory" else 32_220 if descriptor == 109 else extraction[descriptor - 107][1]
    return {"mount_id": 1, "device": 2, "inode": descriptor, "kind": kind,
        "mode": mode, "uid": 0, "gid": 0, "nlink": nlink, "size": size,
        "mtime_ns": 3, "ctime_ns": 4}
def claim_lists(descriptor):
    return (["bin", "configuration-qemu-observer.toml"] if descriptor == 105
            else ["containerd", "ctr"])
def claim_open(name, *_args, **_kwargs):
    return {"deploy": 101, "aws-feasibility": 102, ".state": 103, "completion-v1": 104,
            "kata-runtime-v1": 105, "bin": 106, "containerd": 107, "ctr": 108,
            "configuration-qemu-observer.toml": 109}[name]
dir_stat = SimpleNamespace(st_uid=0, st_gid=0, st_mode=__import__("stat").S_IFDIR | 0o700)
import completion_kata_process as process_module
with patch.object(prestage.os, "dup", return_value=100), patch.object(prestage.os, "set_inheritable"), \
     patch.object(prestage.os, "open", side_effect=claim_open), patch.object(prestage.os, "fstat", return_value=dir_stat), \
     patch.object(prestage.os, "listdir", side_effect=claim_lists), patch.object(prestage.os, "listxattr", return_value=[], create=True), \
     patch.object(prestage.os, "close") as close, patch.object(prestage, "_digest", side_effect=lambda fd, size: active_expected["sha256"] if fd == 109 else extraction[0 if size == extraction[0][1] else 1][2]), \
     patch.object(process_module, "_host_generation", side_effect=host_generation), \
     patch.object(prestage.os, "unlink") as unlink, patch.object(prestage.os, "rmdir") as rmdir:
    facts, held = prestage._claim_exact(contracts, 9, active_expected)
    check(facts["runtime_generation"]["inode"] == 105 and facts["ctr_generation"]["inode"] == 108,
          "prepared identities were not retained")
    check((105, "directory") in generation_requests and (106, "directory") in generation_requests
          and facts["runtime_generation"]["kind"] == facts["bin_generation"]["kind"] == "directory",
          "prepared directory identities were not explicitly classified")
    for descriptor in reversed(held): prestage.os.close(descriptor)
    check(not unlink.called and not rmdir.called, "claimant mutated a pathname")
    with patch.object(prestage.os, "listdir", side_effect=lambda fd: ["bin", "foreign"] if fd == 105 else claim_lists(fd)):
        rejected(lambda: prestage._claim_exact(contracts, 9, active_expected))
rejected(lambda: prestage.admission._verify_prepared_runtime_custody(object()))
rejected(lambda: runtime.kata_inputs._claim_runtime_inputs(object(), object()))
rejected(lambda: runtime.kata_network._claim_runtime_network(object(), object()))
check("process_snapshot" not in runtime._observe_fixed_runtime.__code__.co_varnames,
      "caller process snapshot entered production observation")
check("kill_permitted" not in runtime._cleanup_fixed_runtime.__code__.co_varnames,
      "caller kill flag entered production cleanup")
runtime_source = MODULE_PATH.read_text()
check("rootfs_fs._optional_child" not in runtime_source,
      "removed optional-child API entered runtime owner")
for required in ('state[9][name][1] == name', 'process._host_generation(fresh, "socket") == seen',
                 'process._host_generation(fresh, "socket") == renamed', 'socket_identity(renamed, expected, quarantine, active_name, quarantine)',
                 'os.rename(name, quarantine, src_dir_fd=parent, dst_dir_fd=parent)',
                 'os.unlink(quarantine, dir_fd=parent); os.fsync(parent)', '"s.ttrpc", ".s.ttrpc.removing"',
                 'retained["socket_generations"][active_name]', '"daemon_sockets":', '_shutdown_private_containerd',
                 'kata_operation.GEN_KEYS[:7]', 'state[10][name] = inventory(node)', 'remove_tree(node.operation_fd.number)',
                 'seen["nlink"] == 0', 'kata_operation.GEN_KEYS[:4]', 'verify_daemon(daemon, certain)',
                 'rootfs_fs._enumerate_stable', 'node.generation == generation', '_set_runtime_alias(False)',
                 'probe = step(owner, "NETWORK_READY", 1, actions.CommandId.CTR_CONTAINER_LIST)',
                 'verify_daemon(state[6]) == retained', 'os.fsync(descriptor)', 'os.fchown(descriptor, 0, 0)',
                 'not _runtime_alias(), "private runtime absence"'):
    check(required in runtime_source, "exact retained socket cleanup route missing")

# Incomplete retained and pre-retention daemon terminals remain fail-only; no
# retry, qualification, socket mutation, or runtime-tree mutation is attempted.
uncertain_outcome = {"uncertain": True, "leader_reaped": False, "descendants_reaped": False,
                     "cgroup_empty": False, "cgroup_removed": False}
class UncertainJournal:
    def __init__(self, phase): self.phase, self.resumed = phase, False
    def runtime_recovery_history(self):
        return {"phase": self.phase, "tip": "DAEMON_OUTCOME_V2", "intents": (), "preexecs": (),
                "outcomes": (), "daemon_retained": ({},), "daemon_outcomes": (uncertain_outcome,)}
    def resume_runtime_cleanup(self): self.resumed = True; raise AssertionError("uncertainty rewritten")
command_identity = {"operation_token": "a" * 64, "command_serial": 7,
                    "command_id": "CONTAINERD_START", "binding_sha256": "b" * 64}
class PreRetentionJournal:
    def runtime_recovery_history(self):
        return {"phase": "UNCERTAIN", "tip": "COMMAND_OUTCOME_V2", "intents": (command_identity,),
                "preexecs": ({**command_identity, "pid": 41},),
                "outcomes": ({**command_identity, **uncertain_outcome},),
                "daemon_retained": (), "daemon_outcomes": ()}
cleanup_nonlocals = inspect.getclosurevars(runtime._cleanup_fixed_runtime).nonlocals
shutdown_nonlocals = inspect.getclosurevars(runtime._shutdown_private_containerd).nonlocals
cleanup_owners, daemon_states = cleanup_nonlocals["owners"], shutdown_nonlocals["daemons"]
def uncertain_owner(phase):
    journal = UncertainJournal(phase); owner = object(); daemon = object()
    cleanup_owners[owner] = [journal, None, None, None, None, None, daemon, None, None, None,
                             object(), None]
    daemon_states[daemon] = [journal]
    return journal, owner, daemon
import completion_kata_process as process_module
with patch.object(runtime.os, "unlink") as unlink, patch.object(runtime.os, "rmdir") as rmdir, \
     patch.object(runtime, "_purge_owned_tree") as purge, \
     patch.object(process_module, "_recover_pending_fixed") as retry, \
     patch.object(runtime.kata_inputs, "_close_runtime_inputs"):
    for phase in ("UNCERTAIN", "RUNTIME_CLEANUP_ONLY"):
        journal, owner, daemon = uncertain_owner(phase)
        rejected(lambda owner=owner: runtime._cleanup_fixed_runtime(owner))
        check(not journal.resumed and daemon in daemon_states, "uncertain daemon disposition was consumed")
        cleanup_owners.pop(owner, None); daemon_states.pop(daemon, None)
    journal, daemon = PreRetentionJournal(), object(); daemon_states[daemon] = [journal]
    try: runtime._shutdown_private_containerd(daemon)
    except runtime.KataRuntimeError as error:
        check(str(error) == "uncertain pre-retention daemon closure preserved",
              "pre-retention command identity did not remain unqualified")
    else: raise AssertionError("pre-retention containerd closure was consumed")
    check(daemon in daemon_states and not retry.called, "pre-retention containerd recovery was retried")
    daemon_states.pop(daemon)
    check(not unlink.called and not rmdir.called and not purge.called,
          "uncertain daemon cleanup mutated socket/runtime state")

def reject_runtime(call):
    try: call()
    except runtime.KataRuntimeError: return
    raise AssertionError("hostile runtime observer was accepted")

# Exact QEMU launch state has one fd-backed incumbent and one pathname observer.
qemu_record = runtime.ProcessRecord(
    "qemu", 41, 40, 99, "/opt/kata/bin/qemu-system-x86_64", 7, 8, (), ())
observer_arg = ("unix:path=" + runtime.OBSERVER_QMP_SOCKET +
                ",server=on,wait=off")
exact_argv = (qemu_record.executable, "-name", "sandbox,debug-threads=on",
              "-qmp", "unix:fd=3,server=on,wait=off",
              "-qmp", observer_arg)
exact_raw = b"\0".join(item.encode() for item in exact_argv) + b"\0"
with patch.object(runtime, "_qemu_current"), \
     patch.object(runtime, "_read_bounded", return_value=exact_raw):
    framed, argv_digest, private_fd = runtime._qemu_argv(qemu_record)
assert (framed == exact_raw and argv_digest == hashlib.sha256(exact_raw).hexdigest()
        and private_fd == 3)
for hostile_argv in (
    exact_argv[:-2],
    exact_argv + ("-qmp", observer_arg),
    exact_argv[:-1] + ("unix:path=" + runtime.KATA_QMP_SOCKET + ",server=on,wait=off",),
    exact_argv + ("-qmp-pretty",),
):
    hostile_raw = b"\0".join(item.encode() for item in hostile_argv) + b"\0"
    with patch.object(runtime, "_qemu_current"), \
         patch.object(runtime, "_read_bounded", return_value=hostile_raw):
        reject_runtime(lambda: runtime._qemu_argv(qemu_record))
unix_table = (b"Num RefCount Protocol Flags Type St Inode Path\n"
              b"000: 00000002 00000000 00010000 0001 01 123 " +
              runtime.KATA_QMP_SOCKET.encode() + b"\n"
              b"001: 00000002 00000000 00010000 0001 01 456 " +
              runtime.OBSERVER_QMP_SOCKET.encode() + b"\n")
listeners = runtime._unix_listeners(unix_table)
with patch.object(runtime.os, "listdir", return_value=["3", "4"]), \
     patch.object(runtime.os, "readlink", side_effect=["socket:[123]", "socket:[456]"]):
    bound_fds = runtime._qemu_socket_fds(qemu_record, listeners)
assert bound_fds == {runtime.KATA_QMP_SOCKET: (123, 3),
                     runtime.OBSERVER_QMP_SOCKET: (456, 4)}
with patch.object(runtime, "_qemu_current"), \
     patch.object(runtime, "_read_bounded", return_value=exact_raw.replace(
         b"unix:fd=3", b"unix:fd=4")):
    _raw, _digest_value, wrong_private_fd = runtime._qemu_argv(qemu_record)
assert wrong_private_fd != bound_fds[runtime.KATA_QMP_SOCKET][1]
with patch.object(runtime.os, "listdir", return_value=["3", "4"]), \
     patch.object(runtime.os, "readlink", side_effect=["socket:[123]", "socket:[123]"]):
    reject_runtime(lambda: runtime._qemu_socket_fds(qemu_record, listeners))

# The independent observer parser accepts only fixed IDs/commands, bounded
# events, one absolute deadline, and the pinned QEMU 11.0.1 greeting.
def qmp_greeting():
    return {"QMP": {"version": {"qemu": {"major": 11, "minor": 0, "micro": 1},
                                 "package": ""}, "capabilities": []}}
def qmp_event():
    return {"event": "STOP", "data": {},
            "timestamp": {"seconds": 1, "microseconds": 2}}
def qmp_rows(event=False):
    values = [qmp_greeting()]
    for identifier, result in zip(runtime.QMP_IDS, (
            {}, {"running": True, "singlestep": False, "status": "running"},
            {"enabled": True, "present": True}), strict=True):
        if event: values.append(qmp_event())
        values.append({"return": result, "id": identifier})
    return [json.dumps(value, separators=(",", ":")).encode() + b"\r\n" for value in values]
class FakeQmpSocket:
    def __init__(self, rows): self.rows = list(rows); self.writes = []; self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)
    def recv(self, _maximum): return self.rows.pop(0) if self.rows else b""
    def sendall(self, value): self.writes.append(value)
for interleaved in (False, True):
    rows = qmp_rows(interleaved)
    if interleaved:
        rows[-1] += json.dumps(qmp_event(), separators=(",", ":")).encode() + b"\n"
    client = FakeQmpSocket(rows)
    status, kvm = runtime._qmp_exchange(client, __import__("time").monotonic() + 1)
    check(status["status"] == "running" and kvm["enabled"]
          and len(client.writes) == 3
          and all(identifier.encode() in row
                  for identifier, row in zip(runtime.QMP_IDS, client.writes, strict=True)),
          "fixed QMP observer exchange")
native_status_rows = qmp_rows()
native_status_rows[2] = json.dumps(
    {"return": {"running": True, "status": "running"}, "id": runtime.QMP_IDS[1]},
    separators=(",", ":")).encode() + b"\r\n"
native_client = FakeQmpSocket(native_status_rows)
check(runtime._qmp_exchange(native_client, __import__("time").monotonic() + 1)[0]
      == {"running": True, "status": "running"},
      "native QEMU 11 status shape")

def reject_exchange(rows):
    reject_runtime(lambda: runtime._qmp_exchange(
        FakeQmpSocket(rows), __import__("time").monotonic() + 1))
base_rows = qmp_rows()
for hostile in (
    [base_rows[0], b'{"return":{},"id":"wrong"}\r\n'],
    [json.dumps(qmp_greeting(), separators=(",", ":")).encode() + b"\n"],
    [base_rows[0], b'{"error":{},"id":"cogs-capabilities-v1"}\r\n'],
    [base_rows[0], b'{"return":{},"id":"cogs-capabilities-v1","id":"cogs-capabilities-v1"}\r\n'],
    [base_rows[0], b'{"unexpected":true}\r\n'],
    [base_rows[0], b""],
    [base_rows[0], b"x" * (runtime.QMP_LINE_LIMIT + 1)],
): reject_exchange(hostile)
# Buffered terminal duplicates and partial trailing objects are both residue.
reject_exchange([base_rows[0], base_rows[1] + base_rows[1]])
reject_exchange(base_rows[:-1] + [base_rows[-1] + b'{"event"'])
class TimeoutQmpSocket(FakeQmpSocket):
    def recv(self, _maximum):
        if self.rows: return self.rows.pop(0)
        raise runtime.socket.timeout()
timeout_client = TimeoutQmpSocket([base_rows[0]])
reject_runtime(lambda: runtime._qmp_exchange(
    timeout_client, __import__("time").monotonic() + 0.05))
check(timeout_client.timeouts and max(timeout_client.timeouts) <= 0.1
      and all(later <= earlier for earlier, later in zip(
          timeout_client.timeouts, timeout_client.timeouts[1:])),
      "QMP parser refreshed its absolute deadline")
runtime_source = MODULE_PATH.read_text()
check('row["command_id"] in observer_ids' in runtime_source
      and runtime_source.count('observer_ids = {"CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"}') == 1,
      "runtime observer replay did not exclude interleaved network commands")
check(runtime_source.count('row.role == "qemu"') >= 2
      and 'None if qemu is None else qemu.pid' in runtime_source
      and 'return {"task": task, "task_pid": pid, "processes": processes.disposition.value}, qemu' in runtime_source,
      "native Kata task observation/cleanup is not bound to the exact QEMU role")
check(process_module.DEADLINE_SECONDS["observer"] == 15,
      "measured native ctr observer deadline")
check("client.connect(OBSERVER_QMP_SOCKET)" in runtime_source
      and "client.connect(KATA_QMP_SOCKET)" not in runtime_source,
      "production observer can connect incumbent qmp.sock")
check(runtime.KATA_QMP_SOCKET.endswith("/qmp.sock")
      and runtime.OBSERVER_QMP_SOCKET.endswith("/extra-monitor.sock"),
      "dual QMP path constants")
empty_unix = b"Num RefCount Protocol Flags Type St Inode Path\n"
with patch.object(runtime.os.path, "lexists", return_value=False), \
     patch.object(runtime, "_read_bounded", return_value=empty_unix):
    check(runtime._qmp_absent()["observer_socket"] == "absent",
          "dual QMP baseline absence")
with patch.object(runtime.os.path, "lexists", side_effect=[False, True]):
    reject_runtime(runtime._qmp_absent)

# Linux socket fixture proves replacement is preserved before either mutation,
# and fresh recovery completes a crash cut after only the primary was removed.
import tempfile
if sys.platform.startswith("linux"):
    discard_socket = shutdown_nonlocals["discard_socket"]
    def socket_fixture(parent, names=("s", "s.ttrpc")):
        sockets = {}; held = {}; generations = {}
        for name in names:
            endpoint = str(Path(parent) / name); check(len(endpoint.encode()) <= runtime.MAX_UNIX_PATH, "fixture AF_UNIX path")
            listener = __import__("socket").socket(__import__("socket").AF_UNIX); listener.bind(endpoint); listener.listen(1); sockets[name] = listener
            descriptor = __import__("os").open(endpoint, __import__("os").O_PATH | __import__("os").O_CLOEXEC | __import__("os").O_NOFOLLOW)
            generation = process_module._host_generation(descriptor, "socket"); held[name] = (descriptor, name); generations[name] = {"generation": generation, "fd_inode": 100 + len(generations)}
        return sockets, held, generations
    def socket_state(parent_fd, retained, held):
        value = [None] * 11; value[4] = SimpleNamespace(operation_fd=SimpleNamespace(number=parent_fd)); value[8] = {"socket_generations": retained}; value[9] = held; return value
    with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
        parent_fd = __import__("os").open(temporary, __import__("os").O_RDONLY | __import__("os").O_DIRECTORY)
        listeners, held, generations = socket_fixture(temporary)
        try:
            old_ttrpc = held["s.ttrpc"]; __import__("os").unlink(Path(temporary) / "s.ttrpc")
            replacement = __import__("socket").socket(__import__("socket").AF_UNIX); replacement.bind(str(Path(temporary) / "s.ttrpc")); replacement.listen(1)
            rejected(lambda: discard_socket(socket_state(parent_fd, generations, held), True))
            check(set(__import__("os").listdir(parent_fd)) == {"s", "s.ttrpc"}, "replacement check mutated primary")
            replacement.close(); __import__("os").unlink(Path(temporary) / "s.ttrpc"); listeners["s"].close(); listeners["s.ttrpc"].close(); __import__("os").unlink(Path(temporary) / "s")
            for descriptor, _name in held.values(): __import__("os").close(descriptor)
        finally: __import__("os").close(parent_fd)
    with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
        parent_fd = __import__("os").open(temporary, __import__("os").O_RDONLY | __import__("os").O_DIRECTORY)
        listeners, held, generations = socket_fixture(temporary); __import__("os").unlink(Path(temporary) / "s"); listeners["s"].close(); __import__("os").close(held["s"][0]); held["s"] = None
        try:
            discard_socket(socket_state(parent_fd, generations, held), True)
            check(__import__("os").listdir(parent_fd) == [], "partial socket-removal recovery left residue")
        finally: listeners["s.ttrpc"].close(); __import__("os").close(parent_fd)

# Exact fd-relative staging cleanup accepts owned no-follow residue kinds.
with tempfile.TemporaryDirectory() as temporary:
    parent = __import__("os").open(temporary, __import__("os").O_RDONLY | __import__("os").O_DIRECTORY)
    try:
        __import__("os").mkdir("owned", dir_fd=parent); owned = __import__("os").open(
            "owned", __import__("os").O_RDONLY | __import__("os").O_DIRECTORY, dir_fd=parent)
        try:
            __import__("os").symlink("missing", "link", dir_fd=owned)
            __import__("os").mkfifo("fifo", 0o600, dir_fd=owned)
        finally: __import__("os").close(owned)
        runtime._purge_owned_tree(parent, "owned"); check("owned" not in __import__("os").listdir(parent), "staging rollback")
    finally: __import__("os").close(parent)

# One centralized complete counted-set gate enforces physical and no-deletion totals.
import subprocess
cap = subprocess.run([sys.executable, str(ROOT / "scripts/check-stage2-retained-lines.py")],
                     check=True, stdout=subprocess.PIPE, text=True)
cap_report = json.loads(cap.stdout)
check(cap_report["hard_satisfied"]
      and cap_report["correction_slice_limits_satisfied"]
      and cap_report["hard_limit"] == 78_000
      and cap_report["conservative_lines_no_deletion_credit"] < cap_report["hard_limit"],
      "ADR0106 centralized cap failed")

print("completion Kata runtime S4 hostile offline matrix passed")

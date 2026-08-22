#!/usr/bin/env python3
"""Portable hostile tests for the immutable ADR 0043 mount contract."""

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
permit = runtime._make_fake_launch_permit_for_tests()
run = runtime.ctr_run_spec(permit)
check(run.command_id is runtime.actions.CommandId.CTR_RUN and run.stdin == b"", "run command envelope")
check(run.argv == runtime._ctr_metadata_argv()
      and run.argv[5:7] == ("containers", "create")
      and "run" not in run.argv and "tasks" not in run.argv,
      "metadata-only container create policy")
rejected(lambda: runtime.ctr_run_spec(permit))
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
check(runtime.validate_stored_info(copy.deepcopy(info)) == expected_digest, "stored info candidate")
for path, replacement in (
    (("Runtime", "Name"), "runc"),
    (("Runtime", "Options", "config_path"), "/other"),
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
hostile_raw = hostile_raw.replace(b'{"ID"', b'{"ID":"duplicate","ID"', 1)
rejected(lambda: runtime.validate_stored_info(hostile_raw))
container_absent = b"CONTAINER    IMAGE    RUNTIME\n"
container_exact = container_absent + b"cogs-stage2-ssh-v1    -    io.containerd.kata.v2\n"
check(runtime.classify_container_list(container_absent) is runtime.Observation.ABSENT, "container absence")
check(runtime.classify_container_list(container_exact) is runtime.Observation.EXACT, "container exact")
check(runtime.classify_container_list(container_exact.replace(b"kata.v2", b"runc.v2")) is runtime.Observation.PRESERVE, "runtime drift")
task_absent = b"TASK    PID    STATUS\n"
task_exact = task_absent + b"cogs-stage2-ssh-v1    101    STOPPED\n"
check(runtime.classify_task_list(task_absent, 101) == "absent", "task absence")
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
    proc_row("qemu", 101, 100, 1001, "/opt/kata/bin/qemu-system-x86_64", 11, 20),
    proc_row("virtiofsd", 102, 100, 1002, "/opt/kata/libexec/virtiofsd", 10, 21),
]
proc_fixture = {"complete": True, "early_exit": False, "rows": proc_rows,
                "qualification": runtime.QUALIFICATION_CANDIDATE}
classified = runtime.classify_process_snapshot(proc_fixture)
check(classified.disposition is runtime.Observation.EXACT and len(classified.records) == 3, "process exact cardinality")
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
    check(runtime.classify_process_snapshot(hostile).disposition is runtime.Observation.PRESERVE,
          f"process {mutation} did not preserve")
empty_proc = {**proc_fixture, "rows": []}
check(runtime.classify_process_snapshot(empty_proc).disposition is runtime.Observation.ABSENT, "process absence")

# Random Kata leaves are observed, not selected or removed. Complete mountinfo
# correlates every row while 64/depth-4/total-256 limits fail closed.
def linux_device(major, minor):
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12) | ((major & ~0xfff) << 32)

mountinfo = (
    b"1 1 8:1 / / rw - ext4 /dev/root rw\n"
    b"42 1 0:42 / /run/kata-containers/shared/sandboxes/cogs-stage2-ssh-v1 rw - tmpfs tmpfs rw\n"
)
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
check(runtime.private_containerd_spec_v2().argv[:3] ==
      (runtime.STAGED_CONTAINERD, "--address", runtime.CONTAINERD_ADDRESS), "private daemon staging/address")
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
      and policy.ATTESTED_COMMANDS == frozenset({"SSH_READY", *policy.KEY_COMMANDS}),
      "SSH-stable main process policy was replaced")
policy_value = {"version": policy.RUNTIME_POLICY_VERSION, "archive_sha256": policy.CONTAINERD_ARCHIVE_SHA256,
    "archive_size": policy.CONTAINERD_ARCHIVE_SIZE, "extraction": [list(row) for row in policy.CONTAINERD_EXTRACTION],
    "staged_containerd": policy.STAGED_CONTAINERD, "staged_ctr": policy.STAGED_CTR,
    "address": policy.CONTAINERD_ADDRESS, "mounts": list(policy.CTR_MOUNTS),
    "tails": {name: list(row) for name, row in policy.CTR_TAILS.items()},
    "traces": {name: list(row) for name, row in policy.RUNTIME_TRACES.items()},
    "ownership_traces": [list(row) for row in policy.RUNTIME_OWNERSHIP_TRACES],
    "post_kill_observations": policy.RUNTIME_POST_KILL_OBSERVATIONS,
    "post_kill_interval_ns": policy.RUNTIME_POST_KILL_INTERVAL_NS,
    "proven_absent_traces": {name: list(row) for name, row in policy.RUNTIME_PROVEN_ABSENT_TRACES.items()}}
policy_raw = json.dumps(policy_value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
check(hashlib.sha256(policy_raw).hexdigest() == policy.RUNTIME_POLICY_SHA256,
      "runtime owner policy hash drift")
check(dict(policy.RUNTIME_TRACES) == {
    "NETWORK_READY": ("CONTAINERD_START", "CTR_RUN"),
    "RUNTIME_READY": ("CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"),
    "READINESS_REVOKED": ("CTR_TASK_LIST", "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST"),
    "OWNERSHIP_OBSERVED:task-exact": ("CTR_TASK_LIST", "CTR_TASK_TERM", "CTR_TASK_LIST", "CTR_TASK_KILL") +
        ("CTR_TASK_LIST",) * policy.RUNTIME_POST_KILL_OBSERVATIONS,
    "NETWORK_ABSENT": ("CTR_TASK_REMOVE", "CTR_TASK_LIST"),
    "TASK_ABSENT": ("CTR_CONTAINER_REMOVE", "CTR_CONTAINER_LIST"),
    "CONTAINER_ABSENT": ("CTR_CONTAINER_LIST",),
}, "runtime owner trace drift")
check(dict(policy.RUNTIME_PROVEN_ABSENT_TRACES) == {
    "NETWORK_ABSENT": ("CTR_TASK_LIST",), "TASK_ABSENT": ("CTR_CONTAINER_LIST",),
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
rejected(lambda: runtime.kata_inputs._claim_runtime_inputs(object(), object()))
rejected(lambda: runtime.kata_network._claim_runtime_network(object(), object()))
check("process_snapshot" not in runtime._observe_fixed_runtime.__code__.co_varnames,
      "caller process snapshot entered production observation")
check("kill_permitted" not in runtime._cleanup_fixed_runtime.__code__.co_varnames,
      "caller kill flag entered production cleanup")
runtime_source = MODULE_PATH.read_text()
check("rootfs_fs._optional_child" not in runtime_source,
      "removed optional-child API entered runtime owner")
for required in ('state[9][1] == "containerd.sock"', 'process._host_generation(fresh, "socket") == seen',
                 'process._host_generation(fresh, "socket") == renamed', 'socket_identity(renamed, expected, quarantine)',
                 'os.rename(name, quarantine, src_dir_fd=parent, dst_dir_fd=parent)',
                 'os.unlink(quarantine, dir_fd=parent); os.fsync(parent)', '_shutdown_private_containerd',
                 'kata_operation.GEN_KEYS[:7]', 'state[10][name] = inventory(node)', 'remove_tree(node.operation_fd.number)',
                 'seen["nlink"] == 0', 'kata_operation.GEN_KEYS[:4]', 'verify_daemon(daemon, certain)',
                 'rootfs_fs._enumerate_stable', 'node.generation == generation'):
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

# Execute the direct QMP proof: query-kvm is mandatory and streams/fds close.
class FakeStream:
    def __init__(self):
        self.rows = iter((b'{"QMP":{}}\n', b'{"return":{},"id":1}\n',
                          b'{"return":{"status":"running"},"id":2}\n',
                          b'{"return":{"enabled":true,"present":true},"id":3}\n')); self.writes = []
    def __enter__(self): return self
    def __exit__(self, *_args): self.closed = True
    def readline(self, _limit): return next(self.rows)
    def write(self, value): self.writes.append(value); return len(value)
class FakeSocket:
    def __init__(self, *_args): self.stream = FakeStream(); self.closed = False
    def settimeout(self, _value): pass
    def connect(self, path): check(path == runtime.QMP_SOCKET, "wrong QMP endpoint")
    def makefile(self, *_args, **_kwargs): return self.stream
    def close(self): self.closed = True
fake_socket = FakeSocket(); qemu = runtime.ProcessRecord("qemu", 41, 40, 99,
    "/opt/kata/bin/qemu-system-x86_64", 7, 8, (), (("net", "net:[1]"),))
classification = runtime.ProcessClassification(runtime.Observation.EXACT, (qemu,), "exact")
sockstat = SimpleNamespace(st_mode=__import__("stat").S_IFSOCK | 0o600, st_uid=0, st_gid=0,
                           st_dev=11, st_ino=12, st_ctime_ns=13)
kvmstat = SimpleNamespace(st_mode=__import__("stat").S_IFCHR | 0o600, st_rdev=14, st_dev=15, st_ino=16)
with patch.object(runtime.socket, "socket", return_value=fake_socket), \
     patch.object(runtime.os, "lstat", return_value=sockstat), \
     patch.object(runtime, "_read_bounded", return_value=(b"Num Ref Protocol Flags Type St Inode Path\n"
         b"000: 00000002 00000000 00010000 0001 01 123 " + runtime.QMP_SOCKET.encode() + b"\n")), \
     patch.object(runtime.os, "listdir", side_effect=[["4"], ["9"]]), \
     patch.object(runtime.os, "readlink", side_effect=["socket:[123]", "/dev/kvm"]), \
     patch.object(runtime.os, "open", side_effect=[20, 21]), \
     patch.object(runtime.os, "fstat", return_value=kvmstat), \
     patch.object(runtime.os, "close"), patch.object(runtime.fcntl, "ioctl", return_value=12), \
     patch.object(process_module, "_proc_row", return_value=(41, 40, 41, 41, 99)):
    qmp = runtime._qmp_kvm(classification)
check(qmp["kvm_present"] and qmp["kvm_enabled"] and fake_socket.closed and fake_socket.stream.closed
      and any(b"query-kvm" in row for row in fake_socket.stream.writes), "QMP KVM proof not executed")

# Exact fd-relative staging cleanup accepts owned no-follow residue kinds.
import tempfile
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
      and cap_report["hard_limit"] == 65_000
      and cap_report["conservative_lines_no_deletion_credit"] < cap_report["hard_limit"],
      "ADR0106 centralized cap failed")

print("completion Kata runtime S4 hostile offline matrix passed")

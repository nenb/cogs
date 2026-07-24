#!/usr/bin/env python3
"""Portable hostile tests for the immutable ADR 0043 mount contract."""

import copy
import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

if sys.flags.optimize != 0:
    raise RuntimeError("contract tests refuse Python optimization")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_kata_runtime.py"
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
check(run.command_id == "CTR_RUN" and run.stdin == b"", "run command envelope")
check(run.argv[:14] == (
    "/usr/bin/ctr", "--namespace", runtime.NAMESPACE, "run", "--runtime", runtime.RUNTIME,
    "--runtime-config-path", runtime.RUNTIME_CONFIG, "--rootfs", "--read-only", "--detach",
    "--with-ns", "network:" + runtime.NETNS_PATH, "--mount",
), "run argv positional prefix")
check(run.argv[-5:] == (
    runtime.ROOTFS_CANDIDATE, runtime.CONTAINER_ID, "/bin/sh", "-c", bootstrap.decode("ascii"),
), "run argv positional suffix")
rejected(lambda: runtime.ctr_run_spec(permit))
rejected(runtime._open_production_owner)
commands = {item.command_id: item for item in runtime.fixed_command_specs_for_tests()}
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

print("completion Kata runtime S4 hostile offline matrix passed")

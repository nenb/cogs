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

print("completion Kata runtime mount contract tests passed")

"""Durable journal for the one fixed Stage 2 Kata operation.

Python objects are bookkeeping only.  Authority is the locked, fsynced journal
plus retained kernel object identities.  The accepted v1 records remain
byte-for-byte compatible; Slice A adds separately named v2 command records.
"""
from dataclasses import dataclass
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import time
import unicodedata
import completion_kata_actions as actions
import completion_rootfs_fs as fs

VERSION = "cogs.stage2-kata-operation/v1"
BASE = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1"
STATE_NAME = fs._name("kata-operation-v1")
SENTINEL_NAME = fs._name(".cogs-stage2-kata-operation-v1")
SENTINEL = b"cogs-stage2-kata-operation-v1\n"
LOCK_NAME = fs._name(".cogs-stage2-kata-operation-lock-v1")
JOURNAL_NAME = fs._name("operation-v1.jsonl")
ARTIFACTS_NAME = fs._name("artifacts")
ROOTFS_NAME = fs._name("rootfs-v1")
INPUT_NAME = fs._name("kata-input-v1")
COMPLETION_NAMES = frozenset({
    STATE_NAME.raw, ARTIFACTS_NAME.raw, ROOTFS_NAME.raw, INPUT_NAME.raw,
})
MAX_LINE = 16_384
MAX_RECORDS = 16_384
MAX_BYTES = 16 * 1024 * 1024
ZERO = "0" * 64
HEX = frozenset("0123456789abcdef")
GEN_KEYS = (
    "mount_id", "device", "inode", "kind", "mode", "uid", "gid", "nlink",
    "size", "mtime_ns", "ctime_ns",
)
ENVELOPE = (
    "body", "next_offset", "previous_offset", "previous_sha256", "record_type",
    "sequence", "version",
)
ROOTFS_PIN = {
    "entry_count": 4353,
    "manifest_sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
    "manifest_size": 1049443,
    "ustar_sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
    "ustar_size": 136905728,
}
MOUNT_SHA = "22157f258386d8d4be07ec6eb086a582936c23037be403caa829b644bf4e058e"
FIXED = {
    "containerd_version": "2.2.1", "kata_version": "3.32.0",
    "guest_address": "192.0.2.2/30", "guest_interface": "eth0",
    "guest_mac": "02:00:00:42:00:02", "host_address": "192.0.2.1/30",
    "host_interface": "c42h0", "host_mac": "02:00:00:42:00:01",
    "temporary_peer": "c42g0", "input_root": BASE + "/kata-input-v1",
    "kata_share_root": "/run/kata-containers/shared/sandboxes/cogs-stage2-ssh-v1",
    "namespace": "cogs-stage2-completion-v1", "netns_name": "cogs-stage2-ssh",
    "netns_path": "/run/netns/cogs-stage2-ssh", "nft_table": "inet cogs_stage2_ssh_v1",
    "operation_state": BASE + "/kata-operation-v1", "runtime": "io.containerd.kata.v2",
    "runtime_config": "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml",
    "sandbox_id": "cogs-stage2-ssh-v1", "ssh_alias": "cogs-stage2-ssh-v1",
    "ssh_marker": "COGS_STAGE2_SSH_READY_V1\n", "ssh_port": 22, "ssh_user": "root",
    "state_base": BASE,
}
RESOURCE_TARGETS = {
    "input-root": "kata-input-v1", "input-private": "private", "input-share": "share",
    "input-fixture": "fixture", "client-key-link": "authorized_keys",
    "server-key-link": "ssh_host_ed25519_key",
}
RESOURCES = frozenset(RESOURCE_TARGETS)
MAX_OBSERVED_NAMES = 64
ACTIONS = frozenset({"create", "metadata", "link", "remove"})
COMMANDS = actions.COMMAND_IDS
DEADLINES = frozenset({
    "observer", "network", "keygen", "runtime-start", "task-term", "task-kill", "remove", "listener",
    "ssh", "runtime-absence",
})
UNCERTAIN_REASONS = frozenset({
    "malformed", "contradictory", "identity-mismatch", "old-boot", "unknown", "replaced", "incomplete",
})
OUTCOMES = frozenset({"not_started", "exec_failed", "exited", "signaled", "recovery_absent", "uncertain"})
COMMAND_OUTCOMES_V2 = frozenset({"not-started", "exec-failed", "exited", "signaled", "uncertain"})
FIXED_ENV = (
    ("HOME", "/nonexistent"), ("LANG", "C"), ("LC_ALL", "C"),
    ("PATH", "/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin"), ("TZ", "UTC"),
)
OUTPUT_GRAMMARS = frozenset({"empty", "json", "json-lines", "ssh-plan", "text"})
LIFECYCLE = (
    "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY",
    "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED", "NETWORK_ABSENT",
    "TASK_ABSENT", "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT",
    "FIREWALL_ABSENT", "INPUT_REMOVED", "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT",
)
PROOF_LIFECYCLE = frozenset({
    "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "TASK_STOPPED",
    "NETWORK_ABSENT", "TASK_ABSENT", "CONTAINER_ABSENT", "RUNTIME_ABSENT",
    "SHARE_ABSENT", "FIREWALL_ABSENT", "INPUT_REMOVED", "ROOTFS_ABSENT",
})

class OperationError(Exception):
    pass
def _fail(condition):
    if not condition:
        raise OperationError()
def _uint(value, maximum=(1 << 64) - 1, minimum=0):
    _fail(type(value) is int and minimum <= value <= maximum)
    return value
def _text(value, ascii_only=False):
    _fail(type(value) is str and unicodedata.normalize("NFC", value) == value)
    _fail(not any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value))
    _fail(not ascii_only or value.isascii())
    return value
def _hex(value, size=64, zero=False):
    _fail(type(value) is str and len(value) == size and set(value) <= HEX)
    _fail(zero or value != "0" * size)
    return value
def _choice(value, choices):
    _fail(type(value) is str and value in choices)
    return value
def _keys(value, names):
    _fail(type(value) is dict and set(value) == set(names) and len(value) == len(names))
def _key(value):
    _keys(value, GEN_KEYS[:4])
    _uint(value["mount_id"], minimum=1)
    _uint(value["device"])
    _uint(value["inode"], minimum=1)
    _choice(value["kind"], {"directory", "file", "symlink", "other"})
def _generation(value, nullable=False):
    if nullable and value is None:
        return
    _keys(value, GEN_KEYS)
    _key({name: value[name] for name in GEN_KEYS[:4]})
    for name in ("uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"):
        _uint(value[name])
    _uint(value["mode"], 0o7777)
def _rootfs_pin(value):
    _keys(value, ROOTFS_PIN)
    for name in ("entry_count", "manifest_size", "ustar_size"):
        _uint(value[name], minimum=1)
    _hex(value["manifest_sha256"])
    _hex(value["ustar_sha256"])
    _fail(value == ROOTFS_PIN)
def _intent(body):
    names = (
        "operation_token", "resource_id", "action", "expected_parent_generation",
        "names_sha256",
    )
    _keys(body, names)
    _hex(body["operation_token"])
    _choice(body["resource_id"], RESOURCES)
    _choice(body["action"], ACTIONS)
    _generation(body["expected_parent_generation"])
    _fail(body["expected_parent_generation"]["kind"] == "directory")
    _hex(body["names_sha256"])
    return names
def _command(body):
    names = (
        "operation_token", "command_serial", "command_id", "binding_sha256",
        "deadline_class",
    )
    _keys({name: body[name] for name in names if name in body}, names)
    _hex(body["operation_token"])
    _uint(body["command_serial"], MAX_RECORDS - 1)
    _choice(body["command_id"], COMMANDS)
    _hex(body["binding_sha256"])
    _choice(body["deadline_class"], DEADLINES)
    return names
def _command_v2_header(body):
    names = ("operation_token", "command_serial", "command_id", "binding_sha256")
    _keys({name: body[name] for name in names if name in body}, names)
    _hex(body["operation_token"])
    _uint(body["command_serial"], MAX_RECORDS - 1)
    _choice(body["command_id"], COMMANDS)
    _hex(body["binding_sha256"])
    return names

def _argv(value):
    _fail(type(value) is list and 1 <= len(value) <= 256)
    for item in value:
        _text(item, True)
        _fail(0 < len(item.encode("ascii")) <= 4096)

def _fd_binding(value):
    _keys(value, ("role", "target_fd", "generation", "content_sha256", "content_length"))
    _text(value["role"], True)
    _uint(value["target_fd"], 4096)
    _generation(value["generation"])
    _fail(value["generation"]["kind"] == "file")
    _hex(value["content_sha256"], zero=True)
    _uint(value["content_length"], 65536)

def _command_intent_v2(body):
    names = _command_v2_header(body)
    extra = (
        "journal_key", "host_boot_id", "source_revision", "lifecycle_phase",
        "executable_role", "executable_path", "executable_sha256",
        "executable_generation", "tool_closure_sha256", "argv", "argv_sha256",
        "stdin_hex", "stdin_sha256", "stdin_length", "environment",
        "environment_sha256", "inherited_fds", "deadline_boottime_ns",
        "output_grammar", "stdout_limit", "stderr_limit",
    )
    _keys(body, names + extra)
    _key(body["journal_key"])
    _fail(body["journal_key"]["kind"] == "file")
    _text(body["host_boot_id"], True)
    _hex(body["source_revision"], 40)
    _text(body["lifecycle_phase"], True)
    _text(body["executable_role"], True)
    path = _text(body["executable_path"], True)
    _fail(path.startswith("/") and os.path.normpath(path) == path)
    _hex(body["executable_sha256"])
    _generation(body["executable_generation"])
    _fail(body["executable_generation"]["kind"] == "file")
    _hex(body["tool_closure_sha256"])
    _argv(body["argv"])
    _fail(hashlib.sha256(_canonical(body["argv"])).hexdigest() == body["argv_sha256"])
    raw_stdin = bytes.fromhex(body["stdin_hex"])
    _fail(len(raw_stdin) == body["stdin_length"] <= 262144)
    _fail(hashlib.sha256(raw_stdin).hexdigest() == body["stdin_sha256"])
    _fail(body["environment"] == [list(row) for row in FIXED_ENV])
    _fail(hashlib.sha256(_canonical(body["environment"])).hexdigest() == body["environment_sha256"])
    inherited = body["inherited_fds"]
    _fail(type(inherited) is list and len(inherited) <= 2)
    for row in inherited:
        _fd_binding(row)
    _fail(len({row["role"] for row in inherited}) == len(inherited))
    _fail(len({row["target_fd"] for row in inherited}) == len(inherited))
    _uint(body["deadline_boottime_ns"], minimum=1)
    _choice(body["output_grammar"], OUTPUT_GRAMMARS)
    _uint(body["stdout_limit"], 65536)
    _uint(body["stderr_limit"], 65536)
    bound = {name: body[name] for name in body if name != "binding_sha256"}
    _fail(hashlib.sha256(_canonical(bound)).hexdigest() == body["binding_sha256"])
    return names

def _same_command_v2(left, right):
    return all(left[name] == right[name] for name in _command_v2_header(left))

def _zero_outcome(body):
    return (
        body["status"] is None and body["errno"] is None
        and body["stdout_sha256"] == ZERO and body["stdout_length"] == 0
        and body["stdout_truncated"] is False and body["stderr_sha256"] == ZERO
        and body["stderr_length"] == 0 and body["stderr_truncated"] is False
        and body["wait_result"] == "not_waited" and body["reap_result"] == "not_child"
    )
def _validate_body(kind, body):
    _fail(type(body) is dict)
    if kind == "GENESIS":
        names = tuple(sorted((
            "operation_token", "rootfs_token", "host_boot_id", "source_revision",
            "source_manifest_sha256", "journal_key", "rootfs_pin", "mount_list_sha256",
            *FIXED,
        )))
        _keys(body, names)
        _hex(body["operation_token"])
        _hex(body["rootfs_token"])
        _fail(body["operation_token"] != body["rootfs_token"])
        _text(body["host_boot_id"], True)
        _hex(body["source_revision"], 40)
        _hex(body["source_manifest_sha256"])
        _key(body["journal_key"])
        _fail(body["journal_key"]["kind"] == "file")
        _rootfs_pin(body["rootfs_pin"])
        _fail(body["mount_list_sha256"] == MOUNT_SHA)
        _fail(all(body[name] == value and type(body[name]) is type(value) for name, value in FIXED.items()))
    elif kind == "GENESIS_SETTLED":
        _keys(body, ("operation_token", "journal_key", "state_parent"))
        _hex(body["operation_token"])
        _key(body["journal_key"])
        _generation(body["state_parent"])
        _fail(body["journal_key"]["kind"] == "file" and body["state_parent"]["kind"] == "directory")
    elif kind == "ROOTFS_ACQUIRE_INTENT":
        _keys(body, ("operation_token", "rootfs_token", "rootfs_baseline_sha256"))
        _hex(body["operation_token"])
        _hex(body["rootfs_token"])
        _hex(body["rootfs_baseline_sha256"])
    elif kind == "ROOTFS_LEASED":
        names = (
            "operation_token", "rootfs_token", "rootfs_ledger_key", "leased_sequence",
            "leased_offset", "leased_sha256", "state_generation", "operation_generation",
            "root_generation", "rootfs_pin",
        )
        _keys(body, names)
        _hex(body["operation_token"])
        _hex(body["rootfs_token"])
        _key(body["rootfs_ledger_key"])
        _uint(body["leased_sequence"], fs.ROOTFS_LEDGER_MAX_RECORDS - 1)
        _fail(type(body["leased_offset"]) is str and len(body["leased_offset"]) == 16 and set(body["leased_offset"]) <= HEX)
        _uint(int(body["leased_offset"], 16), fs.ROOTFS_LEDGER_MAX_BYTES, 1)
        _hex(body["leased_sha256"])
        for name in ("state_generation", "operation_generation", "root_generation"):
            _generation(body[name])
            _fail(body[name]["kind"] == "directory")
        _fail(body["rootfs_ledger_key"]["kind"] == "file")
        _rootfs_pin(body["rootfs_pin"])
    elif kind == "FS_INTENT":
        _intent(body)
    elif kind == "FS_OBSERVED":
        base = _intent({name: body[name] for name in body if name in {
            "operation_token", "resource_id", "action", "expected_parent_generation", "names_sha256",
        }})
        extra = ("before_parent", "after_parent", "before_child", "after_child")
        _keys(body, base + extra)
        _generation(body["before_parent"])
        _generation(body["after_parent"])
        _generation(body["before_child"], True)
        _generation(body["after_child"], True)
        _fail(body["before_parent"] == body["expected_parent_generation"])
        _fail(body["before_parent"]["kind"] == body["after_parent"]["kind"] == "directory")
        _fail({name: body["before_parent"][name] for name in GEN_KEYS[:4]} == {name: body["after_parent"][name] for name in GEN_KEYS[:4]})
        before, after = body["before_child"], body["after_child"]
        if body["action"] in {"create", "link"}:
            _fail(before is None and after is not None)
        elif body["action"] == "remove":
            _fail(before is not None and after is None)
        else:
            _fail(before is not None and after is not None)
            _fail({name: before[name] for name in GEN_KEYS[:4]} == {name: after[name] for name in GEN_KEYS[:4]})
            _fail(body["before_parent"] == body["after_parent"])
    elif kind == "FS_ABSENT":
        extras = {"parent_observation", "observed_names"}
        base = _intent({name: body[name] for name in body if name not in extras})
        _keys(body, base + ("parent_observation", "observed_names"))
        _generation(body["parent_observation"])
        _fail(body["parent_observation"] == body["expected_parent_generation"])
        observed = body["observed_names"]
        _fail(type(observed) is list and len(observed) <= MAX_OBSERVED_NAMES)
        _fail(all(type(name) is str and 0 < len(name.encode("utf-8")) <= 255 and
                  _text(name) == name and "/" not in name for name in observed))
        _fail(observed == sorted(set(observed), key=lambda name: name.encode("utf-8")))
        _fail(hashlib.sha256(_canonical(observed)).hexdigest() == body["names_sha256"])
        _fail(RESOURCE_TARGETS[body["resource_id"]] not in observed)
    elif kind == "FS_SETTLED":
        try:
            _validate_body("FS_OBSERVED", body)
        except OperationError:
            _validate_body("FS_ABSENT", body)
    elif kind == "COMMAND_INTENT_V2":
        _command_intent_v2(body)
    elif kind == "COMMAND_PREEXEC_V2":
        base = _command_v2_header(body)
        extra = (
            "host_boot_id", "pid", "ppid", "pgid", "sid", "proc_start_time",
            "pidfd_supported", "cgroup_path", "cgroup_generation",
            "exec_status_pipe", "release_count",
        )
        _keys(body, base + extra)
        _text(body["host_boot_id"], True)
        for name in ("pid", "ppid", "pgid", "sid", "proc_start_time"):
            _uint(body[name], minimum=1)
        _fail(type(body["pidfd_supported"]) is bool)
        cgroup_path = _text(body["cgroup_path"], True)
        _fail(cgroup_path.startswith("/sys/fs/cgroup/") and ".." not in cgroup_path)
        _generation(body["cgroup_generation"])
        _fail(body["cgroup_generation"]["kind"] == "directory")
        _generation(body["exec_status_pipe"])
        _fail(body["exec_status_pipe"]["kind"] == "file")
        _fail(body["release_count"] == 0)
    elif kind == "COMMAND_OUTCOME_V2":
        base = _command_v2_header(body)
        extra = (
            "outcome", "status", "errno", "stdout_sha256", "stdout_length",
            "stdout_truncated", "stderr_sha256", "stderr_length", "stderr_truncated",
            "leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed",
            "pipes_eof", "release_count", "term_attempted", "kill_attempted",
            "deadline_expired", "uncertain", "errors",
        )
        _keys(body, base + extra)
        _choice(body["outcome"], COMMAND_OUTCOMES_V2)
        for name in ("status", "errno"):
            _fail(body[name] is None or type(body[name]) is int and 0 <= body[name] <= 65535)
        for name in ("stdout_sha256", "stderr_sha256"):
            _hex(body[name], zero=True)
        for name in ("stdout_length", "stderr_length"):
            _uint(body[name], 65536)
        flags = (
            "stdout_truncated", "stderr_truncated", "leader_reaped", "descendants_reaped",
            "cgroup_empty", "cgroup_removed", "pipes_eof", "term_attempted",
            "kill_attempted", "deadline_expired", "uncertain",
        )
        _fail(all(type(body[name]) is bool for name in flags))
        errors = body["errors"]
        _fail(type(errors) is list and len(errors) <= 32)
        _fail(all(type(item) is str and len(item) <= 128 and _text(item, True) == item for item in errors))
        _uint(body["release_count"], 1)
        settled = (body["leader_reaped"] and body["descendants_reaped"]
                   and body["cgroup_empty"] and body["cgroup_removed"] and body["pipes_eof"])
        interrupted = body["term_attempted"] or body["kill_attempted"] or body["deadline_expired"]
        _fail(body["uncertain"] == (not settled or bool(errors) or interrupted))
        if body["outcome"] == "not-started":
            _fail(body["release_count"] == 0)
            _fail(body["status"] is body["errno"] is None and not body["term_attempted"])
        elif body["outcome"] == "exec-failed":
            _fail(body["release_count"] == 1)
            _fail(body["status"] is None and type(body["errno"]) is int and body["errno"] > 0)
        elif body["outcome"] in {"exited", "signaled"}:
            _fail(body["release_count"] == 1)
            _fail(type(body["status"]) is int and body["errno"] is None)
        else:
            _fail(body["release_count"] in {0, 1} and body["uncertain"])
    elif kind == "COMMAND_INTENT":
        _command(body)
    elif kind == "COMMAND_PREEXEC":
        base = _command(body)
        extra = (
            "host_boot_id", "pid", "ppid", "pgid", "sid", "proc_start_time",
            "pidfd_supported", "executable_sha256", "tool_closure_sha256", "exec_status_pipe",
        )
        _keys(body, base + extra)
        _text(body["host_boot_id"], True)
        for name in ("pid", "ppid", "pgid", "sid", "proc_start_time"):
            _uint(body[name], minimum=1)
        _fail(type(body["pidfd_supported"]) is bool)
        _hex(body["executable_sha256"])
        _hex(body["tool_closure_sha256"])
        _key(body["exec_status_pipe"])
        _fail(body["exec_status_pipe"]["kind"] == "file")
    elif kind == "COMMAND_OUTCOME":
        base = _command(body)
        extra = (
            "outcome", "status", "errno", "stdout_sha256", "stdout_length",
            "stdout_truncated", "stderr_sha256", "stderr_length", "stderr_truncated",
            "wait_result", "reap_result",
        )
        _keys(body, base + extra)
        _choice(body["outcome"], OUTCOMES)
        for name in ("status", "errno"):
            _fail(body[name] is None or (type(body[name]) is int and 0 <= body[name] <= 65535))
        for name in ("stdout_sha256", "stderr_sha256"):
            _hex(body[name], zero=True)
        for name in ("stdout_length", "stderr_length"):
            _uint(body[name], 65536)
        for name in ("stdout_truncated", "stderr_truncated"):
            _fail(type(body[name]) is bool)
        _choice(body["wait_result"], {"not_waited", "waited", "failed"})
        _choice(body["reap_result"], {"not_child", "reaped", "failed"})
        if body["outcome"] in {"not_started", "recovery_absent"}:
            _fail(_zero_outcome(body))
        elif body["outcome"] == "exec_failed":
            _fail(body["status"] is None and type(body["errno"]) is int and body["errno"] > 0)
            _fail(body["wait_result"] == "waited" and body["reap_result"] == "reaped")
        elif body["outcome"] in {"exited", "signaled"}:
            _fail(type(body["status"]) is int and body["errno"] is None)
            _fail(body["wait_result"] == "waited" and body["reap_result"] == "reaped")
    elif kind in PROOF_LIFECYCLE:
        _keys(body, ("operation_token", "proof_sha256"))
        _hex(body["operation_token"])
        _hex(body["proof_sha256"])
    elif kind == "SSH_READY":
        _keys(body, ("operation_token", "proof_sha256", "marker_sha256", "authentication_attempts"))
        _hex(body["operation_token"])
        _hex(body["proof_sha256"])
        _fail(body["marker_sha256"] == hashlib.sha256(FIXED["ssh_marker"].encode("ascii")).hexdigest())
        _fail(type(body["authentication_attempts"]) is int and body["authentication_attempts"] == 1)
    elif kind == "READINESS_REVOKED":
        _keys(body, ("operation_token",))
        _hex(body["operation_token"])
    elif kind == "OWNERSHIP_OBSERVED":
        _keys(body, ("operation_token", "proof_sha256", "task", "container", "runtime", "share"))
        _hex(body["operation_token"]); _hex(body["proof_sha256"])
        for name in ("task", "container", "runtime", "share"):
            _choice(body[name], {"exact-owned", "absent"})
    elif kind == "ROOTFS_RELEASE_READY":
        names = ("operation_token", "rootfs_token", "rootfs_ledger_key", "leased_sequence",
                 "leased_offset", "leased_sha256", "input_removed_sha256")
        _keys(body, names)
        _hex(body["operation_token"]); _hex(body["rootfs_token"])
        _key(body["rootfs_ledger_key"]); _fail(body["rootfs_ledger_key"]["kind"] == "file")
        _uint(body["leased_sequence"], fs.ROOTFS_LEDGER_MAX_RECORDS - 1)
        _fail(type(body["leased_offset"]) is str and len(body["leased_offset"]) == 16 and set(body["leased_offset"]) <= HEX)
        _uint(int(body["leased_offset"], 16), fs.ROOTFS_LEDGER_MAX_BYTES, 1)
        _hex(body["leased_sha256"]); _hex(body["input_removed_sha256"])
    elif kind == "ROOTFS_RELEASE_AUTHORIZED":
        names = ("operation_token", "rootfs_token", "rootfs_authorized_sequence",
                 "rootfs_authorized_offset", "rootfs_authorized_sha256", "release_ready_sha256")
        _keys(body, names)
        _hex(body["operation_token"]); _hex(body["rootfs_token"])
        _uint(body["rootfs_authorized_sequence"], fs.ROOTFS_LEDGER_MAX_RECORDS - 1)
        _fail(type(body["rootfs_authorized_offset"]) is str and len(body["rootfs_authorized_offset"]) == 16 and set(body["rootfs_authorized_offset"]) <= HEX)
        _uint(int(body["rootfs_authorized_offset"], 16), fs.ROOTFS_LEDGER_MAX_BYTES, 1)
        _hex(body["rootfs_authorized_sha256"]); _hex(body["release_ready_sha256"])
    elif kind == "UNCERTAIN":
        _keys(body, ("operation_token", "reason"))
        _hex(body["operation_token"])
        _choice(body["reason"], UNCERTAIN_REASONS)
    elif kind == "FINAL_BASELINES":
        _keys(body, ("operation_token", "final_baselines_sha256"))
        _hex(body["operation_token"])
        _hex(body["final_baselines_sha256"])
    elif kind in {"RETIRE_INTENT", "RETIRED"}:
        _keys(body, ("operation_token", "journal_key", "final_baselines_sha256"))
        _hex(body["operation_token"])
        _key(body["journal_key"])
        _hex(body["final_baselines_sha256"])
        _fail(body["journal_key"]["kind"] == "file")
    else:
        raise OperationError()
    return body
def _pairs(items):
    result = {}
    for name, value in items:
        _fail(type(name) is str and name not in result)
        result[name] = value
    return result
def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8") + b"\n"

@dataclass(frozen=True)
class Record:
    sequence: int
    previous_offset: int
    next_offset: int
    line_sha256: str
    record_type: str
    body: dict

@dataclass(frozen=True)
class CommandContext:
    operation_token: str
    journal_key: dict
    host_boot_id: str
    source_revision: str
    lifecycle_phase: str
    command_serial: int

@dataclass(frozen=True)
class CommandIntentReceipt:
    command_serial: int
    command_id: str
    binding_sha256: str

@dataclass(frozen=True)
class DurableCommandOutcome:
    command_serial: int
    command_id: str
    binding_sha256: str
    body: dict

@dataclass(frozen=True)
class RootfsReleaseContext:
    operation_token: str
    rootfs_token: str
    rootfs_ledger_key: dict
    leased_sequence: int
    leased_offset: int
    leased_sha256: str
    kata_ledger_key: dict
    kata_release_sequence: int
    kata_release_offset: int
    kata_release_sha256: str
    operation_phase: str
    authorized_sequence: int | None
    authorized_offset: int | None
    authorized_sha256: str | None

@dataclass(frozen=True)
class RootfsAuthorization:
    rootfs_token: str
    sequence: int
    offset: int
    line_sha256: str

    def __post_init__(self):
        _hex(self.rootfs_token)
        _uint(self.sequence, fs.ROOTFS_LEDGER_MAX_RECORDS - 1)
        _uint(self.offset, fs.ROOTFS_LEDGER_MAX_BYTES, 1)
        _hex(self.line_sha256)

def _same_intent(left, right):
    names = ("operation_token", "resource_id", "action", "expected_parent_generation", "names_sha256")
    return all(left[name] == right[name] for name in names)
def _same_command(left, right):
    return all(left[name] == right[name] for name in _command(left))
def _legal(records):
    _fail(records and records[0].record_type == "GENESIS")
    genesis = records[0].body
    token = genesis["operation_token"]
    key = genesis["journal_key"]
    phase = "GENESIS"
    pending = None
    command_phase = None
    command_pending = None
    ownership = None
    rootfs = False
    next_serial = 0
    for index, record in enumerate(records[1:], 1):
        kind = record.record_type
        body = record.body
        _fail(body["operation_token"] == token)
        if phase in {"UNCERTAIN", "RETIRED"}:
            raise OperationError()
        if kind in {"COMMAND_INTENT", "COMMAND_INTENT_V2"}:
            _fail(rootfs and command_phase is None and phase in {
                "ROOTFS_LEASED", "FS_SETTLED", *LIFECYCLE[:14],
            })
            _fail(body["command_serial"] == next_serial)
            next_serial += 1
            command_phase, command_pending = kind, record
            continue
        if kind in {"COMMAND_PREEXEC", "COMMAND_PREEXEC_V2"}:
            expected = "COMMAND_INTENT_V2" if kind.endswith("_V2") else "COMMAND_INTENT"
            _fail(command_phase == expected and command_pending is not None)
            same = (_same_command_v2(body, command_pending.body)
                    if kind.endswith("_V2") else _same_command(body, command_pending.body))
            _fail(same)
            command_phase, command_pending = kind, record
            continue
        if kind in {"COMMAND_OUTCOME", "COMMAND_OUTCOME_V2"}:
            v2 = kind.endswith("_V2")
            intent_kind = "COMMAND_INTENT_V2" if v2 else "COMMAND_INTENT"
            preexec_kind = "COMMAND_PREEXEC_V2" if v2 else "COMMAND_PREEXEC"
            _fail(command_phase in {intent_kind, preexec_kind} and command_pending is not None)
            _fail(_same_command_v2(body, command_pending.body)
                  if v2 else _same_command(body, command_pending.body))
            if v2:
                _fail((command_phase == intent_kind and body["outcome"] == "not-started") or
                      (command_phase == preexec_kind and body["outcome"] != "not-started"))
            else:
                _fail((command_phase == intent_kind and body["outcome"] == "not_started") or
                      (command_phase == preexec_kind and body["outcome"] != "not_started"))
            command_phase = command_pending = None
            if body["outcome"] in {"uncertain"} or v2 and body["uncertain"]:
                phase = "UNCERTAIN"
            continue
        _fail(command_phase is None)
        if phase == "GENESIS":
            _fail(index == 1 and kind == "GENESIS_SETTLED" and body["journal_key"] == key)
            phase = kind
        elif kind == "ROOTFS_ACQUIRE_INTENT":
            _fail(phase == "GENESIS_SETTLED" and body["rootfs_token"] == genesis["rootfs_token"])
            phase = kind
            pending = record
        elif kind == "ROOTFS_LEASED":
            _fail(phase == "ROOTFS_ACQUIRE_INTENT" and pending is not None)
            _fail(body["rootfs_token"] == pending.body["rootfs_token"])
            phase = kind
            pending = None
            rootfs = True
        elif kind == "FS_INTENT":
            _fail(rootfs and phase in {"ROOTFS_LEASED", "FS_SETTLED"})
            phase = kind
            pending = record
        elif kind in {"FS_OBSERVED", "FS_ABSENT"}:
            _fail(phase == "FS_INTENT" and pending is not None and _same_intent(body, pending.body))
            phase = kind
            pending = record
        elif kind == "FS_SETTLED":
            _fail(phase in {"FS_OBSERVED", "FS_ABSENT"} and pending is not None and body == pending.body)
            phase = kind
            pending = None
        elif kind == "UNCERTAIN":
            phase = kind
            pending = None
        elif kind in LIFECYCLE:
            _fail(rootfs)
            seen = {item.record_type for item in records[:index]}
            if kind == "BASELINES_CAPTURED":
                _fail(phase in {"ROOTFS_LEASED", "FS_SETTLED"})
            elif kind == "NETWORK_READY":
                _fail(phase == "BASELINES_CAPTURED")
            elif kind == "RUNTIME_READY":
                _fail(phase == "NETWORK_READY")
            elif kind == "SSH_READY":
                _fail(phase == "RUNTIME_READY")
            elif kind == "READINESS_REVOKED":
                _fail(phase in {"BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY"})
            elif kind == "OWNERSHIP_OBSERVED":
                _fail(phase == "READINESS_REVOKED" and ownership is None)
                ownership = body
            elif kind == "TASK_STOPPED":
                _fail(phase == "OWNERSHIP_OBSERVED" and ownership["task"] == "exact-owned")
            elif kind == "NETWORK_ABSENT":
                _fail(ownership is not None and (phase == "TASK_STOPPED" or
                      phase == "OWNERSHIP_OBSERVED" and ownership["task"] == "absent"))
            elif kind == "TASK_ABSENT":
                _fail(phase == "NETWORK_ABSENT")
            elif kind == "CONTAINER_ABSENT":
                _fail(phase == "TASK_ABSENT")
            elif kind == "RUNTIME_ABSENT":
                _fail(phase == "CONTAINER_ABSENT")
            elif kind == "SHARE_ABSENT":
                _fail(phase == "RUNTIME_ABSENT")
            elif kind == "FIREWALL_ABSENT":
                _fail(phase == "SHARE_ABSENT")
            elif kind == "INPUT_REMOVED":
                _fail(phase == "FIREWALL_ABSENT")
            elif kind == "ROOTFS_RELEASE_READY":
                _fail(phase == "INPUT_REMOVED")
                leased = next(item for item in records if item.record_type == "ROOTFS_LEASED").body
                _fail(body["rootfs_token"] == genesis["rootfs_token"])
                _fail(all(body[name] == leased[name] for name in
                          ("rootfs_ledger_key", "leased_sequence", "leased_offset", "leased_sha256")))
                _fail(body["input_removed_sha256"] == records[index - 1].body["proof_sha256"])
            elif kind == "ROOTFS_RELEASE_AUTHORIZED":
                _fail(phase == "ROOTFS_RELEASE_READY" and body["rootfs_token"] == genesis["rootfs_token"])
                _fail(body["release_ready_sha256"] == records[index - 1].line_sha256)
            else:
                _fail(kind == "ROOTFS_ABSENT" and phase == "ROOTFS_RELEASE_AUTHORIZED")
            phase = kind
            pending = record
        elif kind == "FINAL_BASELINES":
            _fail(rootfs and phase == "ROOTFS_ABSENT")
            phase = kind
            pending = record
        elif kind == "RETIRE_INTENT":
            _fail(phase == "FINAL_BASELINES" and pending is not None)
            _fail(body["journal_key"] == key)
            _fail(body["final_baselines_sha256"] == pending.body["final_baselines_sha256"])
            phase = kind
            pending = record
        elif kind == "RETIRED":
            _fail(phase == "RETIRE_INTENT" and pending is not None and body == pending.body)
            phase = kind
            pending = None
        else:
            raise OperationError()
    return phase
def _parse_untrusted(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n") and b"\x00" not in raw)
    lines = raw.splitlines(keepends=True)
    _fail(len(lines) <= MAX_RECORDS)
    _fail(all(0 < len(line) <= MAX_LINE and line.endswith(b"\n") for line in lines))
    records = []
    offset = 0
    previous = ZERO
    for expected_sequence, line in enumerate(lines):
        try:
            value = json.loads(
                line, object_pairs_hook=_pairs,
                parse_constant=lambda _value: _fail(False),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise OperationError() from error
        _fail(line == _canonical(value))
        _keys(value, ENVELOPE)
        _fail(value["version"] == VERSION)
        _uint(value["sequence"], MAX_RECORDS - 1)
        _fail(value["sequence"] == expected_sequence)
        _fail(type(value["previous_offset"]) is str and value["previous_offset"] == f"{offset:016x}")
        _hex(value["previous_sha256"], zero=True)
        _fail(value["previous_sha256"] == previous)
        offset += len(line)
        _fail(type(value["next_offset"]) is str and value["next_offset"] == f"{offset:016x}")
        _text(value["record_type"], True)
        body = _validate_body(value["record_type"], value["body"])
        digest = hashlib.sha256(line).hexdigest()
        records.append(Record(
            expected_sequence, offset - len(line), offset, digest, value["record_type"], body,
        ))
        previous = digest
    _legal(records)
    return tuple(records)
def _parse(raw):
    try:
        return _parse_untrusted(raw)
    except OperationError:
        raise
    except (AttributeError, KeyError, OverflowError, RecursionError, TypeError,
            UnicodeError, ValueError) as error:
        raise OperationError() from error
def _encode_untrusted(kind, body, records):
    _validate_body(kind, body)
    _legal(tuple(records) + (Record(
        len(records), 0, 0, ZERO, kind, body,
    ),))
    sequence = len(records)
    offset = records[-1].next_offset if records else 0
    envelope = {
        "body": body,
        "next_offset": "0" * 16,
        "previous_offset": f"{offset:016x}",
        "previous_sha256": records[-1].line_sha256 if records else ZERO,
        "record_type": kind,
        "sequence": sequence,
        "version": VERSION,
    }
    while True:
        line = _canonical(envelope)
        next_offset = f"{offset + len(line):016x}"
        if envelope["next_offset"] == next_offset:
            break
        envelope["next_offset"] = next_offset
    _fail(len(line) <= MAX_LINE and offset + len(line) <= MAX_BYTES and sequence < MAX_RECORDS)
    return line
def _encode(kind, body, records):
    try:
        return _encode_untrusted(kind, body, records)
    except OperationError:
        raise
    except (AttributeError, KeyError, OverflowError, RecursionError, TypeError,
            UnicodeError, ValueError) as error:
        raise OperationError() from error
def _key_value(value):
    return {
        "mount_id": value.mount_id, "device": value.device, "inode": value.inode,
        "kind": value.kind,
    }
def _generation_value(value):
    result = _key_value(value.key)
    result.update({name: getattr(value, name) for name in GEN_KEYS[4:]})
    return result
def _merge(primary, addition):
    return addition if primary is None else fs.RootfsFsError(primary, addition)
def _collect(primary, function, *args):
    try:
        function(*args)
    except BaseException as error:
        return _merge(primary, error)
    return primary
def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        count = os.write(descriptor, raw[offset:])
        _fail(type(count) is int and 0 < count <= len(raw) - offset)
        offset += count
def _open_base_chain(control):
    anchor = fs._open_workspace_anchor(control)
    try:
        return fs._open_anchored_chain(anchor, fs._fixed_policies(), control)
    except BaseException as error:
        fs._close_node(anchor, error)

def _make_authority():
    # These registries track one-shot bookkeeping only. They are not a trust
    # boundary; every route rereads and validates the durable journal.
    owners, closed, permits, grants = {}, set(), {}, {}
    release_permits, release_grants = {}, {}
    class _FixedJournal:
        """One idempotently-closeable owner for the fixed state, lock, and journal."""
        def __init__(self):
            _fail(os.geteuid() == 0)
            self.control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
            self.chain = None
            self.lock = None
            self.closed = False
            try:
                self._initialize()
            except BaseException as error:
                self.close(error)
        def _initialize(self):
            self.chain = _open_base_chain(self.control)
            parent = self.chain.components[-1].node
            names = fs._enumerate_stable(parent, self.control).raw_names
            _fail(set(names) <= COMPLETION_NAMES)
            if STATE_NAME.raw not in names:
                previous = os.umask(0o077)
                try:
                    os.mkdir(STATE_NAME.raw, 0o700, dir_fd=parent.operation_fd.number)
                finally:
                    _fail(os.umask(previous) == 0o077)
                os.fsync(parent.operation_fd.number)
                self._reopen_base()
                parent = self.chain.components[-1].node
            state = fs._open_path_node(parent, STATE_NAME, "directory", self.control)
            try:
                self._state_policy(state, parent)
                names = fs._enumerate_stable(state, self.control).raw_names
                _fail(set(names) <= {SENTINEL_NAME.raw, LOCK_NAME.raw, JOURNAL_NAME.raw})
                previous = os.umask(0o077)
                try:
                    if SENTINEL_NAME.raw not in names:
                        self._create_fixed_file(state, SENTINEL_NAME, SENTINEL)
                    if LOCK_NAME.raw not in names:
                        self._create_fixed_file(state, LOCK_NAME, b"")
                finally:
                    _fail(os.umask(previous) == 0o077)
            except BaseException as error:
                fs._close_node(state, error)
            else:
                fs._close_node(state)
            self._reopen_base()
            parent = self.chain.components[-1].node
            detached = fs._open_path_node(parent, STATE_NAME, "directory", self.control)
            try:
                self._state_policy(detached, parent)
                transferred = fs.HeldChain(
                    self.chain.anchor,
                    self.chain.components + (fs.ChainComponent(STATE_NAME, detached),),
                )
            except BaseException as error:
                fs._close_node(detached, error)
            self.chain = transferred
            sentinel = self._file(SENTINEL_NAME, SENTINEL)
            fs._close_node(sentinel)
            self.lock = self._file(LOCK_NAME, b"")
            try:
                fcntl.flock(self.lock.operation_fd.number, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EAGAIN, errno.EACCES}:
                    raise OperationError() from error
                raise
            _fail(fs._observe_child(self.state, LOCK_NAME, self.control) == self.lock.generation)
            fs._revalidate_chain(self.chain, self.control)
        @property
        def state(self):
            _fail(self.chain is not None and len(self.chain.components) > 0)
            return self.chain.components[-1].node
        @property
        def completion(self):
            _fail(self.chain is not None and len(self.chain.components) > 1)
            return self.chain.components[-2].node
        def validate_layout(self, records, journal_generation):
            names = set(fs._enumerate_stable(self.completion, self.control).raw_names)
            _fail(names <= COMPLETION_NAMES and STATE_NAME.raw in names)
            if records:
                _fail(_key_value(journal_generation.key) == records[0].body["journal_key"])
                phase = _legal(records)
                if len(records) > 1:
                    _fail(_generation_value(self.state.generation) == records[1].body["state_parent"])
                if phase not in {"GENESIS", "GENESIS_SETTLED", "ROOTFS_ABSENT",
                                 "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
                    _fail(ROOTFS_NAME.raw in names)
                input_required = {"FS_OBSERVED", "FS_ABSENT", "FS_SETTLED", "COMMAND_INTENT",
                                  "COMMAND_PREEXEC", "COMMAND_OUTCOME", *LIFECYCLE[:13]}
                if phase in input_required:
                    _fail(INPUT_NAME.raw in names)
                if phase in set(LIFECYCLE[13:]) | {"FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
                    _fail(INPUT_NAME.raw not in names)
                if phase in {"ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
                    _fail(ROOTFS_NAME.raw not in names)
            fs._revalidate_chain(self.chain, self.control)
        def _reopen_base(self):
            old = self.chain
            self.chain = None
            fs._close_chain(old)
            self.chain = _open_base_chain(self.control)
        def _state_policy(self, state, parent):
            generation = state.generation
            _fail(generation.key.kind == "directory" and generation.mode == 0o700)
            _fail(generation.uid == generation.gid == 0 and generation.nlink >= 2)
            _fail((generation.key.mount_id, generation.key.device) == (
                parent.generation.key.mount_id, parent.generation.key.device,
            ))
            fs._require_empty_fd_xattrs(state, self.control)
        def _create_fixed_file(self, state, name, content):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
            descriptor = fs.CheckedFd(
                os.open(name.raw, flags, 0o600, dir_fd=state.operation_fd.number),
                "operation-infrastructure-file",
            )
            error = None
            try:
                _write_all(descriptor.number, content)
                os.fsync(descriptor.number)
            except BaseException as caught:
                error = caught
            error = _collect(error, descriptor.close)
            error = _collect(error, os.fsync, state.operation_fd.number)
            if error is not None:
                raise error
        def _file(self, name, content=None):
            node = fs._open_path_node(self.state, name, "file", self.control)
            try:
                generation = node.generation
                _fail(generation.mode == 0o600 and generation.uid == generation.gid == 0)
                _fail(generation.nlink == 1 and (generation.key.mount_id, generation.key.device) == (
                    self.state.generation.key.mount_id, self.state.generation.key.device,
                ))
                fs._require_empty_fd_xattrs(node, self.control)
                if content is not None:
                    _fail(fs._read_regular(node, max(1, len(content)), self.control) == content)
                _fail(fs._observe_child(self.state, name, self.control) == node.generation)
                return node
            except BaseException as error:
                fs._close_node(node, error)
        def read(self):
            names = fs._enumerate_stable(self.state, self.control).raw_names
            if JOURNAL_NAME.raw not in names:
                return None
            node = self._file(JOURNAL_NAME)
            try:
                raw = fs._read_regular(node, MAX_BYTES, self.control)
                _fail(fs._observe_child(self.state, JOURNAL_NAME, self.control) == node.generation)
            except BaseException as error:
                fs._close_node(node, error)
            fs._close_node(node)
            return raw, node.generation
        def _refresh_state_generation(self):
            state = self.state
            generation = fs._observe_node(state.identity_fd, state.operation_fd, self.control)
            _fail(generation.key == state.generation.key)
            refreshed = fs.HeldNode(state.identity_fd, state.operation_fd, generation)
            component = fs.ChainComponent(STATE_NAME, refreshed)
            self.chain = fs.HeldChain(self.chain.anchor, self.chain.components[:-1] + (component,))
            self._state_policy(refreshed, self.completion)
            fs._revalidate_chain(self.chain, self.control)
        def create(self, body):
            _fail(self.read() is None)
            flags = os.O_RDWR | getattr(os, "O_TMPFILE", 0o20200000) | fs._O_CLOEXEC
            descriptor = fs.CheckedFd(
                os.open(b".", flags, 0o600, dir_fd=self.state.operation_fd.number),
                "operation-journal-tmpfile",
            )
            identity = None
            error = None
            records = None
            try:
                identity_flags = fs._O_PATH | fs._O_CLOEXEC
                _fail(identity_flags == 0o12000000)
                identity = fs._open_fd(
                    f"/proc/self/fd/{descriptor.number}", identity_flags,
                    "operation-journal-identity", self.control,
                )
                mount_id = fs._mount_id(identity, self.control, fs.FDINFO_FLAGS)
                generation = fs._generation(identity, mount_id, self.control)
                original = fs._generation(descriptor, mount_id, self.control)
                _fail(generation == original and generation.key == original.key)
                _fail(generation.mode == 0o600 and generation.uid == generation.gid == 0)
                _fail(generation.nlink == 0 and generation.size == 0 and generation.key.kind == "file")
                body = dict(body)
                body["journal_key"] = _key_value(generation.key)
                line = _encode("GENESIS", body, ())
                _write_all(descriptor.number, line)
                os.fsync(descriptor.number)
                library = ctypes.CDLL(None, use_errno=True)
                result = library.linkat(
                    descriptor.number, b"", self.state.operation_fd.number, JOURNAL_NAME.raw, 0x1000,
                )
                if result != 0:
                    saved = ctypes.get_errno()
                    raise OSError(saved, os.strerror(saved))
                os.fsync(self.state.operation_fd.number)
                self._refresh_state_generation()
                observed = self.read()
                _fail(observed is not None and observed[0] == line)
                records = _parse(line)
                _fail(_key_value(observed[1].key) == records[0].body["journal_key"])
            except BaseException as caught:
                error = caught
            for owned in (identity, descriptor):
                if owned is not None and owned.disposition == "open":
                    error = _collect(error, owned.close)
            if error is not None:
                raise error
            return records
        def write_record(self, line, expected):
            held = self._file(JOURNAL_NAME)
            descriptor = None
            error = None
            records = None
            try:
                raw = fs._read_regular(held, MAX_BYTES, self.control)
                _fail(fs._observe_child(self.state, JOURNAL_NAME, self.control) == held.generation)
                current = _parse(raw)
                _fail(_key_value(held.generation.key) == current[0].body["journal_key"])
                _fail(current[-1].next_offset == expected)
                flags = os.O_WRONLY | os.O_APPEND | fs._O_NOFOLLOW | fs._O_CLOEXEC
                descriptor = fs.CheckedFd(
                    os.open(JOURNAL_NAME.raw, flags, dir_fd=self.state.operation_fd.number),
                    "operation-journal-writer",
                )
                observed = os.fstat(descriptor.number)
                _fail((observed.st_dev, observed.st_ino, observed.st_size) == (
                    held.generation.key.device, held.generation.key.inode, expected,
                ))
                _write_all(descriptor.number, line)
                os.fsync(descriptor.number)
            except BaseException as caught:
                error = caught
            if descriptor is not None and descriptor.disposition == "open":
                error = _collect(error, descriptor.close)
            if held.identity_fd.disposition == "open":
                error = _collect(error, fs._close_node, held)
            if error is None:
                try:
                    observed = self.read()
                    _fail(observed is not None and len(observed[0]) == expected + len(line))
                    records = _parse(observed[0])
                    _fail(_key_value(observed[1].key) == records[0].body["journal_key"])
                except BaseException as caught:
                    error = caught
            if error is not None:
                raise error
            return records
        def unlink(self, key):
            node = self._file(JOURNAL_NAME)
            error = None
            try:
                _fail(_key_value(node.generation.key) == key)
                _fail(_key_value(fs._observe_child(self.state, JOURNAL_NAME, self.control).key) == key)
                os.unlink(JOURNAL_NAME.raw, dir_fd=self.state.operation_fd.number)
            except BaseException as caught:
                error = caught
            error = _collect(error, fs._close_node, node)
            if error is None:
                try:
                    os.fsync(self.state.operation_fd.number)
                    _fail(self.read() is None)
                except BaseException as caught:
                    error = caught
            if error is not None:
                raise error
        def close(self, primary=None):
            if self.closed:
                if primary is not None:
                    raise primary
                return
            self.closed = True
            error = primary
            if self.lock is not None and self.lock.identity_fd.disposition == "open":
                error = _collect(error, fs._close_node, self.lock)
            if self.chain is not None:
                error = _collect(error, fs._close_chain, self.chain)
            if error is not None:
                raise error
    def _open_io():
        return _FixedJournal()
    class RootfsPermit:
        __slots__ = ()
    class RootfsGrant:
        __slots__ = ()
    class RootfsReleasePermit:
        __slots__ = ()
    class RootfsReleaseGrant:
        __slots__ = ()
    def owner(authority):
        state = owners.get(authority)
        _fail(state is not None and authority not in closed)
        return state
    def reload(authority, preserve=False):
        state = owner(authority)
        observed = state[0].read()
        if observed is None:
            state[1:] = [(), "absent"]
            return state
        try:
            raw, journal_generation = observed
            records = _parse(bytes(raw))
            validate = getattr(state[0], "validate_layout", None)
            if validate is not None:
                validate(records, journal_generation)
        except OperationError:
            state[1:] = [(), "preserve"]
            if not preserve:
                raise
        else:
            state[1:] = [records, "exact"]
        return state
    def write_validated(authority, kind, body):
        io, records, status = reload(authority)
        _fail(status == "exact" and records)
        line = _encode(kind, body, records)
        io.write_record(line, records[-1].next_offset)
        _io, fresh, fresh_status = reload(authority)
        _fail(fresh_status == "exact" and fresh[-1].record_type == kind)
    def release_context(records):
        phase = records[-1].record_type
        _fail(phase in {"ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED"})
        ready = records[-1] if phase == "ROOTFS_RELEASE_READY" else records[-2]
        _fail(ready.record_type == "ROOTFS_RELEASE_READY")
        body, genesis = ready.body, records[0].body
        authorized = None if phase == "ROOTFS_RELEASE_READY" else records[-1]
        return RootfsReleaseContext(
            genesis["operation_token"], genesis["rootfs_token"], body["rootfs_ledger_key"],
            body["leased_sequence"], int(body["leased_offset"], 16), body["leased_sha256"],
            genesis["journal_key"], ready.sequence, ready.next_offset, ready.line_sha256,
            phase, None if authorized is None else authorized.body["rootfs_authorized_sequence"],
            None if authorized is None else int(authorized.body["rootfs_authorized_offset"], 16),
            None if authorized is None else authorized.body["rootfs_authorized_sha256"],
        )
    def issue_release(records, settle):
        context = release_context(records)
        permit = RootfsReleasePermit()
        release_permits[permit] = [context, settle, False]
        return permit
    class OperationAuthority:
        __slots__ = ()
        def command_context(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records)
            _fail(records[-1].record_type not in {
                "COMMAND_INTENT", "COMMAND_PREEXEC", "COMMAND_INTENT_V2",
                "COMMAND_PREEXEC_V2", "UNCERTAIN", "RETIRED",
            })
            genesis = records[0].body
            serial = sum(item.record_type in {"COMMAND_INTENT", "COMMAND_INTENT_V2"}
                         for item in records)
            return CommandContext(
                genesis["operation_token"], genesis["journal_key"], genesis["host_boot_id"],
                genesis["source_revision"], _legal(records), serial,
            )
        def record_command_intent(self, body):
            context = self.command_context()
            _fail(body["operation_token"] == context.operation_token)
            _fail(body["journal_key"] == context.journal_key)
            _fail(body["host_boot_id"] == context.host_boot_id)
            _fail(body["source_revision"] == context.source_revision)
            _fail(body["lifecycle_phase"] == context.lifecycle_phase)
            _fail(body["command_serial"] == context.command_serial)
            write_validated(self, "COMMAND_INTENT_V2", body)
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].body == body)
            return CommandIntentReceipt(
                body["command_serial"], body["command_id"], body["binding_sha256"],
            )
        def record_command_preexec(self, body):
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].record_type == "COMMAND_INTENT_V2")
            _fail(_same_command_v2(body, records[-1].body))
            write_validated(self, "COMMAND_PREEXEC_V2", body)
        def record_command_outcome(self, body):
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].record_type in {
                "COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2",
            })
            _fail(_same_command_v2(body, records[-1].body))
            write_validated(self, "COMMAND_OUTCOME_V2", body)
            _io, fresh, fresh_status = reload(self, True)
            _fail(fresh_status == "exact" and fresh[-1].record_type == "COMMAND_OUTCOME_V2")
            return DurableCommandOutcome(
                body["command_serial"], body["command_id"], body["binding_sha256"], body,
            )
        def durable_command_outcome(self, serial, command_id, binding_sha256):
            _io, records, status = reload(self, True)
            _fail(status == "exact")
            matches = [item for item in records if item.record_type == "COMMAND_OUTCOME_V2"
                       and item.body["command_serial"] == serial]
            _fail(len(matches) == 1)
            body = matches[0].body
            _fail(body["command_id"] == command_id and body["binding_sha256"] == binding_sha256)
            return DurableCommandOutcome(serial, command_id, binding_sha256, body)
        def durable_command_output(self, serial, command_id, binding_sha256, stdout, stderr):
            _fail(type(stdout) is bytes and type(stderr) is bytes)
            result = self.durable_command_outcome(serial, command_id, binding_sha256)
            body = result.body
            _fail(not body["uncertain"] and not body["stdout_truncated"]
                  and not body["stderr_truncated"])
            _fail(body["stdout_length"] == len(stdout) and body["stderr_length"] == len(stderr))
            _fail(body["stdout_sha256"] == hashlib.sha256(stdout).hexdigest())
            _fail(body["stderr_sha256"] == hashlib.sha256(stderr).hexdigest())
            return result
        def reserve_rootfs(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records)
            phase = records[-1].record_type
            _fail(phase in {"ROOTFS_ACQUIRE_INTENT", "ROOTFS_LEASED", "ROOTFS_RELEASE_READY",
                            "ROOTFS_RELEASE_AUTHORIZED"})
            _fail(not any(value[0] is self and not value[4] for value in permits.values()))
            _fail(not any(value[0] is self and not value[5] for value in grants.values()))
            permit = RootfsPermit()
            permits[permit] = [self, records[0].body["operation_token"],
                               len(records) - 1, phase, False]
            return permit
        def reserve_rootfs_release(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].record_type in {
                "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
            })
            phase = records[-1].record_type
            def settle(body):
                if phase == "ROOTFS_RELEASE_READY":
                    write_validated(self, "ROOTFS_RELEASE_AUTHORIZED", body)
                else:
                    _io, fresh, fresh_status = reload(self)
                    _fail(fresh_status == "exact" and fresh[-1].record_type == phase)
                    _fail(fresh[-1].body == body)
            return issue_release(records, settle)
        def close(self):
            if self in closed:
                return
            state = owner(self)
            closed.add(self)
            state[1:] = [(), "closed"]
            state[0].close()
        def status(self):
            if self in closed:
                return "closed"
            return reload(self, True)[2]
    def claim_rootfs_reopen(permit):
        try:
            state = permits.get(permit)
        except TypeError as error:
            raise OperationError() from error
        _fail(state is not None and not state[4])
        authority, token, sequence, phase, _used = state
        _io, records, status = reload(authority)
        _fail(status == "exact" and records[0].body["operation_token"] == token)
        _fail(len(records) - 1 == sequence and records[-1].record_type == phase)
        state[4] = True
        value = RootfsGrant()
        grants[value] = [authority, token, sequence, phase, False, False]
        return value
    def grant_records(grant):
        try:
            state = grants.get(grant)
        except TypeError as error:
            raise OperationError() from error
        _fail(state is not None)
        authority, token, sequence, phase, _routed, _settled = state
        _io, records, status = reload(authority)
        _fail(status == "exact" and records[0].body["operation_token"] == token)
        _fail(len(records) - 1 == sequence and records[-1].record_type == phase)
        return state, records
    def invoke_rootfs_reopen_route(grant, route, control):
        state, records = grant_records(grant)
        _fail(not state[4] and not state[5] and callable(route))
        state[4] = True
        argument = (release_context(records) if state[3] in {
            "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
        } else records[0].body["rootfs_token"])
        return route(argument, control)
    def settle_rootfs_reopen(grant, reference):
        state, records = grant_records(grant)
        _fail(state[4] and not state[5])
        authority, operation_token, _sequence, phase, _routed, _settled = state
        token = records[0].body["rootfs_token"]
        _fail(records[0].body["operation_token"] == operation_token and reference.token == token)
        if phase == "ROOTFS_ACQUIRE_INTENT":
            settled = reference.leased_settled
            write_validated(authority, "ROOTFS_LEASED", {
                "operation_token": operation_token, "rootfs_token": token,
                "rootfs_ledger_key": _key_value(reference.ledger_key),
                "leased_sequence": settled.sequence, "leased_offset": f"{settled.offset:016x}",
                "leased_sha256": settled.line_sha256,
                "state_generation": _generation_value(reference.state_generation),
                "operation_generation": _generation_value(reference.operation_generation),
                "root_generation": _generation_value(reference.root_generation), "rootfs_pin": ROOTFS_PIN,
            })
        else:
            leased_record = next(item for item in records if item.record_type == "ROOTFS_LEASED")
            expected = leased_record.body
            actual = {
                "rootfs_ledger_key": _key_value(reference.ledger_key),
                "leased_sequence": reference.leased_settled.sequence,
                "leased_offset": f"{reference.leased_settled.offset:016x}",
                "leased_sha256": reference.leased_settled.line_sha256,
                "state_generation": _generation_value(reference.state_generation),
                "operation_generation": _generation_value(reference.operation_generation),
                "root_generation": _generation_value(reference.root_generation),
            }
            _fail(all(expected[name] == value for name, value in actual.items()))
        state[5] = True
    def claim_rootfs_release(permit):
        try:
            state = release_permits.get(permit)
        except TypeError as error:
            raise OperationError() from error
        _fail(state is not None and not state[2])
        state[2] = True
        grant = RootfsReleaseGrant()
        release_grants[grant] = [state[0], state[1], False, False]
        return grant
    def invoke_rootfs_release(grant, route):
        try:
            state = release_grants.get(grant)
        except TypeError as error:
            raise OperationError() from error
        _fail(state is not None and not state[2] and not state[3])
        _fail(callable(route))
        state[2] = True
        return route(state[0])
    def settle_rootfs_release(grant, authorization):
        try:
            state = release_grants.get(grant)
        except TypeError as error:
            raise OperationError() from error
        _fail(state is not None and state[2] and not state[3])
        context = state[0]
        _fail(isinstance(authorization, RootfsAuthorization)
              and authorization.rootfs_token == context.rootfs_token)
        _uint(authorization.sequence, fs.ROOTFS_LEDGER_MAX_RECORDS - 1)
        _uint(authorization.offset, fs.ROOTFS_LEDGER_MAX_BYTES, 1)
        _hex(authorization.line_sha256)
        body = {
            "operation_token": context.operation_token, "rootfs_token": context.rootfs_token,
            "rootfs_authorized_sequence": authorization.sequence,
            "rootfs_authorized_offset": f"{authorization.offset:016x}",
            "rootfs_authorized_sha256": authorization.line_sha256,
            "release_ready_sha256": context.kata_release_sha256,
        }
        state[1](body)
        state[3] = True
    def _open_fixed_operation():
        io = _open_io()
        authority = OperationAuthority()
        owners[authority] = [io, (), "absent"]
        try:
            reload(authority, True)
            return authority
        except BaseException as error:
            closed.add(authority)
            owners[authority][1:] = [(), "closed"]
            io.close(error)
    def command_context(authority):
        return authority.command_context()
    def record_command_intent(authority, body):
        return authority.record_command_intent(body)
    def record_command_preexec(authority, body):
        return authority.record_command_preexec(body)
    def record_command_outcome(authority, body):
        return authority.record_command_outcome(body)
    def durable_command_outcome(authority, serial, command_id, binding_sha256):
        return authority.durable_command_outcome(serial, command_id, binding_sha256)
    def durable_command_output(authority, serial, command_id, binding_sha256, stdout, stderr):
        return authority.durable_command_output(
            serial, command_id, binding_sha256, stdout, stderr,
        )
    return (
        _open_fixed_operation, claim_rootfs_reopen,
        invoke_rootfs_reopen_route, settle_rootfs_reopen, claim_rootfs_release,
        invoke_rootfs_release, settle_rootfs_release,
        command_context, record_command_intent, record_command_preexec,
        record_command_outcome, durable_command_outcome, durable_command_output,
    )

(
    _open_fixed_operation, _claim_rootfs_reopen,
    _invoke_rootfs_reopen_route, _settle_rootfs_reopen, _claim_rootfs_release,
    _invoke_rootfs_release, _settle_rootfs_release,
    _command_context, _record_command_intent, _record_command_preexec,
    _record_command_outcome, _durable_command_outcome, _durable_command_output,
) = _make_authority()
del _make_authority

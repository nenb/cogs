"""Durable journal for the one fixed Stage 2 Kata operation.

Production host modules are trusted; guest input cannot import or execute host Python.
These capabilities prevent unintended route composition, but Python objects are
bookkeeping only. Closure introspection is therefore outside the security boundary.
Authority is the locked, fsynced journal plus retained kernel object identities.
The accepted v1 records remain byte-for-byte compatible. A journal's first command
intent selects either legacy v1 or exact v2 command records for its lifetime.
"""
from dataclasses import dataclass
from types import MappingProxyType
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import time
import unicodedata
import completion_guest_workloads_v2 as guest_workloads
import completion_kata_actions as actions
import completion_kata_command_policy as command_policy
import completion_kata_network_journal as network_journal
import completion_kata_owner as owner_helpers
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
RUNTIME_NAME = fs._name("kata-runtime-v1")
RUNTIME_STAGING_NAME = fs._name(".kata-runtime-v1.staging")
KEY_STAGE_PREFIX = b"kata-key-stage-v1-"
COMPLETION_NAMES = frozenset({
    STATE_NAME.raw, ARTIFACTS_NAME.raw, ROOTFS_NAME.raw, INPUT_NAME.raw,
})
RUNTIME_NAMES = frozenset({RUNTIME_NAME.raw, RUNTIME_STAGING_NAME.raw})
MAX_LINE = 300_000
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
KEY_INPUT_PHASES = frozenset({"ROOTFS_LEASED", "FS_INTENT", "UNCERTAIN"})
RUNTIME_RESIDUE_PHASES = frozenset({
    "NETWORK_READY", "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED",
    "OWNERSHIP_OBSERVED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "UNCERTAIN", "RUNTIME_CLEANUP_ONLY",
})
JOURNAL_SETUP_MARGIN_NS = 900_000_000_000
JOURNAL_SETTLEMENT_MARGIN_NS = command_policy.SSH_CLEANUP_RESERVE_NS
JOURNAL_TOTAL_NS = (JOURNAL_SETUP_MARGIN_NS + command_policy.SSH_TOTAL_NS
                    + JOURNAL_SETTLEMENT_MARGIN_NS)

def _stage_candidates(names, allowed=()):
    candidates = set(names) - COMPLETION_NAMES - RUNTIME_NAMES - set(allowed)
    _fail(len(candidates) <= 1)
    for raw in candidates:
        suffix = raw[len(KEY_STAGE_PREFIX):] if raw.startswith(KEY_STAGE_PREFIX) else b""
        token = suffix[:-len(b".quarantine")] if suffix.endswith(b".quarantine") else suffix
        _fail(len(token) == 64 and set(token) <= set(b"0123456789abcdef"))
    return candidates

def _validate_runtime_layout(names, records, phase):
    present = names & RUNTIME_NAMES
    _fail(len(present) <= 1)
    intent = any(item.record_type == "RUNTIME_STAGE_INTENT_V4" for item in records)
    staged = any(item.record_type == "RUNTIME_STAGED_V3" for item in records)
    allowed = set()
    if intent and phase in RUNTIME_RESIDUE_PHASES:
        allowed.add(RUNTIME_NAME.raw)
        if not staged:
            allowed.add(RUNTIME_STAGING_NAME.raw)
    _fail(present <= allowed)

def _validate_stage_layout(raw_names, records, phase, completion_key):
    names = set(raw_names)
    _validate_runtime_layout(names, records, phase)
    token = records[0].body["operation_token"] if records else ""
    expected_temporary = (b".cogs-grant-" + token[:32].encode("ascii") + b"-"
                          + hashlib.sha256(b".").hexdigest()[:16].encode("ascii"))
    root_grants = [item.body for item in records if item.record_type == "INPUT_GRANT"
                   and item.body["path"] == "." and item.body["action"] == "intent"]
    _fail(len(root_grants) <= 1 and all(
        item["name"].encode("ascii") == expected_temporary for item in root_grants))
    root_terminal = any(item.record_type == "INPUT_WA"
                        and item.body["path"] == "."
                        and item.body["action"] == "mkdir-settled" for item in records)
    temporary_active = len(root_grants) == 1 and not root_terminal and phase in KEY_INPUT_PHASES
    allowed_temporaries = {expected_temporary} if temporary_active else set()
    if expected_temporary in names:
        _fail(INPUT_NAME.raw not in names)
    candidates = _stage_candidates(names, allowed_temporaries)
    if not candidates: return
    _fail(records and phase in KEY_INPUT_PHASES)
    token = records[0].body["operation_token"].encode("ascii")
    active = KEY_STAGE_PREFIX + token; quarantine = active + b".quarantine"
    _fail(candidates <= {active, quarantine}
          and any(item.record_type == "PRODUCTION_ADMISSION_V2" for item in records))
    grants = [item.body for item in records if item.record_type == "INPUT_GRANT"
              and item.body["path"] == "@key-stage" and item.body["action"] == "intent"]
    mkdirs = [item.body for item in records if item.record_type == "INPUT_WA"
              and item.body["path"] == "@key-stage" and item.body["action"] == "mkdir"]
    _fail(len(grants) == len(mkdirs) == 1 and grants[0]["name"].encode("ascii") == active)
    parent = grants[0]["parent_generation"]
    key_names = ("mount_id", "device", "inode", "kind")
    input_create = any(item.record_type == "FS_INTENT"
                       and item.body["resource_id"] == "input-root"
                       and item.body["action"] == "create" for item in records)
    baseline_names = [os.fsdecode(name) for name in raw_names
                      if name not in candidates and name not in allowed_temporaries
                      and not (name == INPUT_NAME.raw and input_create)]
    _fail(all(mkdirs[0]["parent_key"][name] == parent[name] == completion_key[name]
              for name in key_names)
          and mkdirs[0]["names_sha256"] == hashlib.sha256(_canonical(baseline_names)).hexdigest()
          and mkdirs[0]["target_mode"] == 0o700
          and grants[0]["expected_kind"] == "directory"
          and grants[0]["expected_mode"] == 0o700
          and grants[0]["expected_uid"] == grants[0]["expected_gid"] == 0)
    removals = [item.body for item in records if item.record_type == "INPUT_WA"
                and item.body["path"] == "@key-stage"]
    _fail(not any(item["action"] == "absent" for item in removals))
    if quarantine in candidates:
        _fail(any(item["action"] == "remove" for item in removals))
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
LEGACY_COMMANDS = command_policy.LEGACY_COMMANDS
_V1_COMMAND_RECORDS = frozenset({"COMMAND_INTENT", "COMMAND_PREEXEC", "COMMAND_OUTCOME"})
_V2_COMMAND_RECORDS = (frozenset({
    "COMMAND_OUTCOME_V2", "DAEMON_RETAINED_V2", "DAEMON_OUTCOME_V2", "RUNTIME_STAGE_INTENT_V4",
    "NETWORK_SNAPSHOT_V2"}) | network_journal.ALL_RECORDS)
_POLICY_MAPS = (command_policy.POLICY_SHA256, command_policy.OCCURRENCES,
                command_policy.PHASES, command_policy.MAX_OCCURRENCES)
_RUNTIME_POLICY_OBJECTS = (command_policy.RUNTIME_POLICY_VERSION, command_policy.RUNTIME_POLICY_SHA256,
                           command_policy.RUNTIME_EXTENSION_COMMANDS, command_policy.RUNTIME_TRACES, command_policy.RUNTIME_OCCURRENCES,
                           command_policy.RUNTIME_PHASES, command_policy.RUNTIME_MAX_OCCURRENCES,
                           command_policy.CTR_TAILS, command_policy.CONTAINERD_EXTRACTION,
                           command_policy.RUNTIME_OWNERSHIP_TRACES, command_policy.RUNTIME_POST_KILL_OBSERVATIONS,
                           command_policy.RUNTIME_POST_KILL_INTERVAL_NS)
_DEFERRED_COMMANDS = command_policy.DEFERRED_COMMANDS
_ATTESTED_COMMANDS = command_policy.ATTESTED_COMMANDS
_ATTESTED_EXECUTABLES = command_policy.ATTESTED_EXECUTABLES
_REVIEWED_HOST_TOOL_CONTRACTS = command_policy.REVIEWED_HOST_TOOL_CONTRACTS
_REVIEWED_SYNTHETIC_CONTRACTS = command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS
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
NETWORK_BASELINES = network_journal.BASELINES
LIFECYCLE = (
    "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY",
    "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED", "NETWORK_ABSENT",
    "TASK_ABSENT", "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT",
    "FIREWALL_ABSENT", "INPUT_REMOVED", "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT",
)
PRODUCTION_ADMISSION_VERSION = "cogs.stage2-kata-operation-production/v2"
SSH_PARSER_ID = "completion_guest_workloads_v2.parse_guest_workload_output/v2"
SSH_PARSER_SHA256 = "723bf54ef1b9b1fe4670b1a0d82e6744a29d33fbd0dc2cad4b3cc88863dae406"

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
def _boottime_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
def _current_boot_id():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        value = source.read(64)
    _fail(len(value) == 37 and value.endswith("\n"))
    return value[:-1]
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
    _choice(value["kind"], {"directory", "file", "pipe", "symlink", "other"})
def _generation(value, nullable=False):
    if nullable and value is None:
        return
    _keys(value, GEN_KEYS)
    _key({name: value[name] for name in GEN_KEYS[:4]})
    for name in ("uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"):
        _uint(value[name])
    _uint(value["mode"], 0o7777)
def _daemon_socket_generation(value):
    _keys(value, GEN_KEYS)
    _uint(value["mount_id"], minimum=1); _uint(value["device"]); _uint(value["inode"], minimum=1)
    _fail(value["kind"] == "socket")
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
    _choice(body["command_id"], LEGACY_COMMANDS)
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
    _fail(type(value) is list and 1 <= len(value) <= 256
          and type(value[0]) is str and value[0] != "")
    for item in value:
        _fail(type(item) is str)
        if item: _text(item, True)
        _fail(len(item.encode("ascii")) <= 4096)
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
        "environment_sha256", "inherited_fds", "policy_version", "deadline_class",
        "duration_ns", "cleanup_reserve_ns", "deadline_boottime_ns",
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
    runtime_policy = (body["command_id"] in command_policy.RUNTIME_EXTENSION_COMMANDS and
                      body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION)
    static_policy = (body["command_id"] in command_policy.POLICY_SHA256 and
                     body["policy_version"] == command_policy.POLICY_VERSION)
    b1_policy = (body["command_id"] in command_policy.B1_COMMAND_IDS and
                 body["policy_version"] == command_policy.POLICY_VERSION)
    _fail(runtime_policy or static_policy or b1_policy)
    _choice(body["deadline_class"], DEADLINES)
    _uint(body["duration_ns"], command_policy.SSH_TOTAL_NS, 1)
    _uint(body["cleanup_reserve_ns"], body["duration_ns"] - 1, 1)
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
def _ssh_result_proof(body):
    names = ("operation_token", "command_serial", "binding_sha256", "manifest_sha256",
             "runtime_mount_sha256", "runtime_mount_generation", "program_sha256",
             "parser_sha256", "stdout_sha256", "stdout_hex", "result_sha256",
             "canonical_result_hex")
    return hashlib.sha256(_canonical({name: body[name] for name in names})).hexdigest()


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
    elif kind == "LIFECYCLE_DEADLINE_V1":
        _keys(body, ("operation_token", "admission_boottime_ns",
                     "ssh_start_deadline_boottime_ns", "journal_deadline_boottime_ns"))
        _hex(body["operation_token"])
        for name in ("admission_boottime_ns", "ssh_start_deadline_boottime_ns",
                     "journal_deadline_boottime_ns"):
            _uint(body[name], minimum=1)
        _fail(body["ssh_start_deadline_boottime_ns"]
              == body["admission_boottime_ns"] + JOURNAL_SETUP_MARGIN_NS)
        _fail(body["journal_deadline_boottime_ns"]
              == body["admission_boottime_ns"] + JOURNAL_TOTAL_NS)
    elif kind == "PRODUCTION_ADMISSION_V2":
        _keys(body, ("operation_token", "admission_version", "policy_version",
                     "parser_source_sha256"))
        _hex(body["operation_token"])
        _fail(body["admission_version"] == PRODUCTION_ADMISSION_VERSION
              and body["policy_version"] == command_policy.POLICY_VERSION
              and body["parser_source_sha256"] == SSH_PARSER_SHA256)
    elif kind == "RUNTIME_MOUNT_V2":
        _keys(body, ("operation_token", "manifest_sha256", "mount_generation",
                     "issuance_sha256"))
        _hex(body["operation_token"]); _hex(body["manifest_sha256"])
        _generation(body["mount_generation"])
        _fail(body["mount_generation"]["kind"] == "directory")
        expected = hashlib.sha256(_canonical({name: body[name] for name in body
                                              if name != "issuance_sha256"})).hexdigest()
        _fail(body["issuance_sha256"] == expected)
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
    elif kind == "INPUT_GRANT":
        names = ("operation_token", "action", "grant_id", "path", "name",
                 "parent_generation", "parent_inode_version", "expected_kind",
                 "expected_mode", "expected_uid", "expected_gid", "command_serial",
                 "birth_min_ns", "birth_max_ns", "mount_id", "inode_version_min",
                 "inode_version_max", "child_generation", "child_birth_ns", "child_inode_version")
        _keys(body, names); _hex(body["operation_token"]); _choice(body["action"], {"intent", "settled"})
        _hex(body["grant_id"]); _text(body["path"]); name = _text(body["name"], True)
        _fail(0 < len(name) <= 255 and "/" not in name and name not in {".", ".."})
        _generation(body["parent_generation"]); _uint(body["parent_inode_version"], 0xffffffff)
        _choice(body["expected_kind"], {"directory", "file"}); _uint(body["expected_mode"], 0o7777)
        _uint(body["expected_uid"]); _uint(body["expected_gid"])
        _uint(body["command_serial"], MAX_RECORDS - 1); _uint(body["birth_min_ns"], minimum=1)
        _uint(body["birth_max_ns"], minimum=body["birth_min_ns"]); _uint(body["mount_id"], minimum=1)
        _uint(body["inode_version_min"], 0xffffffff)
        _uint(body["inode_version_max"], 0xffffffff, body["inode_version_min"])
        if body["action"] == "intent":
            _fail(body["child_generation"] is body["child_birth_ns"] is body["child_inode_version"] is None)
        else:
            _generation(body["child_generation"]); _fail(body["child_generation"]["kind"] == body["expected_kind"])
            _uint(body["child_birth_ns"], minimum=body["birth_min_ns"])
            _fail(body["child_birth_ns"] <= body["birth_max_ns"])
            _uint(body["child_inode_version"], body["inode_version_max"], body["inode_version_min"])
    elif kind == "INPUT_WA":
        _keys(body, ("operation_token", "action", "path", "parent_key", "names_sha256",
                     "child_key", "before_mode", "target_mode"))
        _hex(body["operation_token"]); _choice(body["action"], {"mkdir", "mkdir-settled", "file-settled", "metadata", "remove", "absent"})
        path = _text(body["path"]); _fail(path == "@key-stage" or path == "." or
                                          "/".join(name.text for name in fs._path(path)) == path)
        _key(body["parent_key"]); _fail(body["parent_key"]["kind"] == "directory")
        _hex(body["names_sha256"])
        if body["action"] == "mkdir":
            _fail(body["child_key"] is None and body["before_mode"] is None)
        else:
            _key(body["child_key"])
            if body["action"] in {"mkdir-settled", "file-settled"}:
                expected_kind = "directory" if body["action"] == "mkdir-settled" else "file"
                _fail(body["child_key"]["kind"] == expected_kind and body["before_mode"] is None)
            else:
                if body["action"] == "metadata": _fail(body["child_key"]["kind"] == "directory")
                _uint(body["before_mode"], 0o7777)
        _uint(body["target_mode"], 0o7777)
    elif kind == "INPUT_STEP":
        _keys(body, ("operation_token", "action", "path", "kind", "key", "sha256"))
        _hex(body["operation_token"]); _choice(body["action"], {"create-intent", "create", "remove-intent", "absent"})
        path = _text(body["path"]); _fail(path in {"@manifest", "."} or "/".join(name.text for name in fs._path(path)) == path)
        _choice(body["kind"], {"directory", "file"})
        if body["action"] == "absent": _fail(body["key"] is None)
        else: _key(body["key"]); _fail(body["key"]["kind"] == body["kind"])
        if body["sha256"] is None: _fail(body["kind"] == "directory")
        else: _hex(body["sha256"])
    elif kind == "NETWORK_SNAPSHOT_V2" or kind in network_journal.ALL_RECORDS:
        network_journal.validate(kind, body, _canonical)
    elif kind == "COMMAND_INTENT_V2":
        _command_intent_v2(body)
    elif kind == "COMMAND_PREEXEC_V2":
        base = _command_v2_header(body)
        extra = (
            "host_boot_id", "pid", "ppid", "pgid", "sid", "proc_start_time",
            "pidfd_supported", "cgroup_path", "cgroup_generation",
            "executable_sha256", "tool_closure_sha256", "executable_generation",
            "exec_status_pipe", "release_count",
        )
        launch = ("namespace_fd", "namespace_path") if body["command_id"] == "CTR_RUN" else ()
        _keys(body, base + extra + launch)
        if launch: _fail(body["namespace_fd"] == 202 and body["namespace_path"] == f"/proc/{body['pid']}/fd/202")
        _text(body["host_boot_id"], True)
        for name in ("pid", "ppid", "pgid", "sid", "proc_start_time"):
            _uint(body[name], minimum=1)
        _fail(type(body["pidfd_supported"]) is bool)
        cgroup_path = _text(body["cgroup_path"], True)
        _fail(cgroup_path.startswith("/sys/fs/cgroup/") and ".." not in cgroup_path)
        _generation(body["cgroup_generation"])
        _fail(body["cgroup_generation"]["kind"] == "directory")
        _hex(body["executable_sha256"]); _hex(body["tool_closure_sha256"])
        _generation(body["executable_generation"])
        _fail(body["executable_generation"]["kind"] == "file")
        _generation(body["exec_status_pipe"])
        _fail(body["exec_status_pipe"]["kind"] == "pipe")
        _fail(body["release_count"] == 0)
    elif kind == "COMMAND_OUTPUT_V3":
        _keys(body, ("operation_token", "command_serial", "command_id", "binding_sha256", "stdout_hex", "stderr_hex"))
        _hex(body["operation_token"]); _uint(body["command_serial"], MAX_RECORDS - 1)
        _choice(body["command_id"], COMMANDS); _hex(body["binding_sha256"])
        for name in ("stdout_hex", "stderr_hex"):
            _fail(type(body[name]) is str and len(body[name]) <= 131072 and len(body[name]) % 2 == 0)
            try: bytes.fromhex(body[name])
            except ValueError as error: raise OperationError() from error
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
            _fail(body["stdout_length"] == body["stderr_length"] == 0)
            _fail(body["stdout_sha256"] == body["stderr_sha256"] == hashlib.sha256(b"").hexdigest())
            _fail(not body["stdout_truncated"] and not body["stderr_truncated"])
        elif body["outcome"] == "exec-failed":
            _fail(body["release_count"] == 1)
            _fail(body["status"] is None and type(body["errno"]) is int and body["errno"] > 0)
        elif body["outcome"] in {"exited", "signaled"}:
            _fail(body["release_count"] == 1)
            _fail(type(body["status"]) is int and body["errno"] is None)
        else:
            _fail(body["release_count"] in {0, 1} and body["uncertain"])
    elif kind == "RUNTIME_RESUME_V4":
        _keys(body, ("operation_token", "target_phase", "uncertain_serial", "binding_sha256")); _hex(body["operation_token"])
        _text(body["target_phase"], True); _uint(body["uncertain_serial"], MAX_RECORDS - 1); _hex(body["binding_sha256"])
    elif kind == "RUNTIME_STAGE_INTENT_V4":
        _keys(body, ("operation_token", "policy_version", "policy_sha256", "temporary_name"))
        _hex(body["operation_token"]); _fail(body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION and
              body["policy_sha256"] == command_policy.RUNTIME_POLICY_SHA256 and
              body["temporary_name"] == ".kata-runtime-v1.staging")
    elif kind == "RUNTIME_IDENTITY_V4":
        _keys(body, ("operation_token", "pid", "starttime", "executable_device", "executable_inode", "namespaces"))
        _hex(body["operation_token"]); _uint(body["pid"], minimum=1); _uint(body["starttime"], minimum=1)
        _uint(body["executable_device"]); _uint(body["executable_inode"], minimum=1)
        _fail(type(body["namespaces"]) is list and len(body["namespaces"]) == 6 and
              all(type(row) is list and len(row) == 2 and type(row[0]) is type(row[1]) is str for row in body["namespaces"]))
    elif kind == "RUNTIME_STAGED_V3":
        names = ("operation_token", "policy_version", "policy_sha256", "archive_sha256", "archive_size", "extraction_sha256", "runtime_generation",
                 "containerd_generation", "ctr_generation", "config_generation", "root_generation", "state_generation")
        _keys(body, names); _hex(body["operation_token"])
        _fail(body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION and
              body["policy_sha256"] == command_policy.RUNTIME_POLICY_SHA256 and
              (body["archive_sha256"], body["archive_size"], body["extraction_sha256"]) ==
              (command_policy.CONTAINERD_ARCHIVE_SHA256, command_policy.CONTAINERD_ARCHIVE_SIZE,
               command_policy.CONTAINERD_EXTRACTION_SHA256))
        for name in names[6:]: _generation(body[name])
        _fail(tuple((body[name]["kind"], body[name]["mode"]) for name in names[6:]) ==
              (("directory", 0o700), ("file", 0o500), ("file", 0o500), ("file", 0o600),
               ("directory", 0o700), ("directory", 0o700)))
    elif kind == "DAEMON_RETAINED_V2":
        extra = {"socket_generation"}
        _keys(body, (
            "operation_token", "command_serial", "command_id", "binding_sha256",
            "host_boot_id", "pid", "ppid", "pgid", "sid", "proc_start_time",
            "pidfd_supported", "cgroup_path", "cgroup_generation",
            "executable_sha256", "tool_closure_sha256", "executable_generation",
            "exec_status_pipe", "release_count", "socket_generation",
        ))
        preexec = {name: value for name, value in body.items() if name not in extra}
        _validate_body("COMMAND_PREEXEC_V2", preexec)
        _daemon_socket_generation(body["socket_generation"])
    elif kind == "DAEMON_OUTCOME_V2":
        names = _command_v2_header(body)
        extra = (
            "pid", "proc_start_time", "status", "leader_reaped", "descendants_reaped",
            "cgroup_empty", "cgroup_removed", "uncertain", "errors",
        )
        _keys(body, names + extra)
        _uint(body["pid"], minimum=1)
        _uint(body["proc_start_time"], minimum=1)
        _fail(body["status"] is None or type(body["status"]) is int and 0 <= body["status"] <= 255)
        flags = ("leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed", "uncertain")
        _fail(all(type(body[name]) is bool for name in flags))
        _fail(type(body["errors"]) is list and len(body["errors"]) <= 32)
        settled = all(body[name] for name in flags[:4]) and not body["errors"]
        _fail(body["uncertain"] == (not settled))
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
    elif kind == "SSH_RESULT_V2":
        names = ("operation_token", "command_serial", "binding_sha256", "manifest_sha256",
                 "runtime_mount_sha256", "runtime_mount_generation", "program_sha256",
                 "parser_sha256", "stdout_sha256", "stdout_hex", "result_sha256",
                 "canonical_result_hex", "proof_sha256")
        _keys(body, names)
        _hex(body["operation_token"]); _uint(body["command_serial"], MAX_RECORDS - 1)
        for name in ("binding_sha256", "manifest_sha256", "runtime_mount_sha256",
                     "program_sha256", "parser_sha256", "stdout_sha256",
                     "result_sha256", "proof_sha256"):
            _hex(body[name])
        _generation(body["runtime_mount_generation"])
        _fail(body["runtime_mount_generation"]["kind"] == "directory")
        stdout = bytes.fromhex(body["stdout_hex"])
        _fail(len(stdout) <= guest_workloads.GUEST_OUTPUT_LIMIT
              and body["stdout_sha256"] == hashlib.sha256(stdout).hexdigest())
        raw = bytes.fromhex(body["canonical_result_hex"])
        _fail(len(raw) <= guest_workloads.GUEST_OUTPUT_LIMIT * 4)
        try:
            parsed_stdout = guest_workloads.parse_guest_workload_output(stdout)
            parsed = guest_workloads.parse_canonical_guest_workload_result(raw)
            _fail(parsed_stdout == parsed and guest_workloads.canonical_guest_workload_result(parsed) == raw)
        except guest_workloads.WorkloadError as error:
            raise OperationError() from error
        _fail(body["program_sha256"] == guest_workloads.GUEST_PROGRAM_SHA256)
        _fail(body["parser_sha256"] == SSH_PARSER_SHA256)
        _fail(body["result_sha256"] == hashlib.sha256(raw).hexdigest())
        _fail(body["proof_sha256"] == _ssh_result_proof(body))
    elif kind == "SSH_READY_V2":
        _keys(body, ("operation_token", "result_record_sha256", "proof_sha256"))
        _hex(body["operation_token"]); _hex(body["result_record_sha256"]); _hex(body["proof_sha256"])
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
def _policy_tables():
    _fail(command_policy.ATTESTED_COMMANDS is _ATTESTED_COMMANDS
          and command_policy.ATTESTED_EXECUTABLES is _ATTESTED_EXECUTABLES
          and command_policy.REVIEWED_HOST_TOOL_CONTRACTS is _REVIEWED_HOST_TOOL_CONTRACTS
          and command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS is _REVIEWED_SYNTHETIC_CONTRACTS
          and type(_ATTESTED_EXECUTABLES) is type(_REVIEWED_HOST_TOOL_CONTRACTS) is MappingProxyType
          and set(_ATTESTED_EXECUTABLES) <= set(_ATTESTED_COMMANDS)
          and all(set(value) == {"executable_sha256", "tool_closure_sha256",
                                 "executable_path", "contract_version"}
                  for value in _ATTESTED_EXECUTABLES.values()))
    maps = (command_policy.POLICY_SHA256, command_policy.OCCURRENCES,
            command_policy.PHASES, command_policy.MAX_OCCURRENCES)
    _fail(all(value is expected and type(value) is MappingProxyType
              for value, expected in zip(maps, _POLICY_MAPS)))
    implemented, deferred = set(maps[0]), set(command_policy.DEFERRED_COMMANDS)
    b1 = set(command_policy.B1_COMMAND_IDS)
    _fail(command_policy.DEFERRED_COMMANDS is _DEFERRED_COMMANDS
          and not implemented & deferred and not b1 & (implemented | deferred))
    _fail(implemented | deferred | b1 == set(COMMANDS)
          and implemented == set(maps[1]) == set(maps[2]) == set(maps[3]))
    _fail(all(type(rows) is tuple and rows and maps[2][name] == tuple(dict.fromkeys(rows))
              and maps[3][name] == len(rows) for name, rows in maps[1].items()))
    expected_phases = {name: (("ROOTFS_LEASED",) if name in command_policy.KEY_COMMANDS else
                              ("RUNTIME_READY",) if name == "SSH_READY" else
                              ("BASELINES_CAPTURED",)) for name in maps[0]}
    _fail(dict(maps[1]) == expected_phases and all(value == 1 for value in maps[3].values()))
    return maps
def _runtime_tables():
    values = (command_policy.RUNTIME_POLICY_VERSION, command_policy.RUNTIME_POLICY_SHA256,
              command_policy.RUNTIME_EXTENSION_COMMANDS, command_policy.RUNTIME_TRACES, command_policy.RUNTIME_OCCURRENCES, command_policy.RUNTIME_PHASES,
              command_policy.RUNTIME_MAX_OCCURRENCES, command_policy.CTR_TAILS, command_policy.CONTAINERD_EXTRACTION,
              command_policy.RUNTIME_OWNERSHIP_TRACES, command_policy.RUNTIME_POST_KILL_OBSERVATIONS,
              command_policy.RUNTIME_POST_KILL_INTERVAL_NS)
    _fail(all(value is expected for value, expected in zip(values, _RUNTIME_POLICY_OBJECTS)) and
          all(type(value) is MappingProxyType for value in values[3:7]))
    _fail(set(values[2]) == set(values[4]) == set(values[5]) == set(values[6]) and
          all(values[6][name] == len(values[4][name]) for name in values[2]))
    return values
def _v2_policy_digest(intent):
    names = ("command_id", "executable_role", "executable_path", "argv", "stdin_hex",
             "policy_version", "deadline_class", "duration_ns", "cleanup_reserve_ns",
             "output_grammar", "stdout_limit", "stderr_limit")
    value = {name: intent[name] for name in names}
    if intent["command_id"] in command_policy.KEY_COMMANDS:
        actual = command_policy.KEY_STAGE_PREFIX + intent["operation_token"]
        _fail(all(actual in item if "{operation_token}" in template else actual not in item
                  for item, template in zip(intent["argv"], command_policy.KEY_COMMANDS[intent["command_id"]])))
        value["argv"] = [item.replace(actual, command_policy.KEY_STAGE) for item in intent["argv"]]
    value["inherited_fds"] = [[row["role"], row["target_fd"]] for row in intent["inherited_fds"]]
    return hashlib.sha256(_canonical(value)).hexdigest()
def _v2_lineage(genesis, phase, intent, preexec=None, outcome=None, b1_network=False):
    _policy_tables()
    _fail(intent["journal_key"] == genesis["journal_key"])
    _fail(intent["host_boot_id"] == genesis["host_boot_id"])
    _fail(intent["source_revision"] == genesis["source_revision"])
    _fail(intent["lifecycle_phase"] == phase)
    command_id = intent["command_id"]
    if intent["policy_version"] == command_policy.RUNTIME_POLICY_VERSION:
        _runtime_tables()
        _fail(command_policy.validate_runtime_policy(intent, genesis))
        _fail(phase in command_policy.RUNTIME_PHASES[command_id])
    elif b1_network:
        _fail(command_id in {value.value for value in actions.NETWORK_COMMANDS} | {"CTR_RUN"})
    elif command_id in {"TC_QDISC", "TC_INGRESS_FILTER"}:
        _fail(False)
    else:
        _fail(command_id in command_policy.POLICY_SHA256)
        _fail(_v2_policy_digest(intent) == command_policy.POLICY_SHA256[command_id])
        _fail(phase in command_policy.PHASES[command_id])
        if command_id in command_policy.ATTESTED_COMMANDS:
            expected = command_policy.ATTESTED_EXECUTABLES.get(command_id)
            _fail(expected is not None
                  and expected["executable_sha256"] == intent["executable_sha256"]
                  and expected["tool_closure_sha256"] == intent["tool_closure_sha256"]
                  and expected["executable_path"] == intent["executable_path"]
                  and expected["contract_version"] == command_policy.HOST_TOOL_CONTRACT_VERSION)
    if preexec is not None:
        _fail(_same_command_v2(preexec, intent))
        _fail(preexec["host_boot_id"] == intent["host_boot_id"]
              and preexec["executable_sha256"] == intent["executable_sha256"]
              and preexec["tool_closure_sha256"] == intent["tool_closure_sha256"]
              and preexec["executable_generation"] == intent["executable_generation"])
        expected = f"/sys/fs/cgroup/cogs-stage2-completion-v1/{intent['operation_token']}-{intent['command_serial']}"
        _fail(preexec["cgroup_path"] == expected)
    if outcome is not None:
        _fail(_same_command_v2(outcome, intent))
        _fail(outcome["stdout_length"] <= intent["stdout_limit"])
        _fail(outcome["stderr_length"] <= intent["stderr_limit"])
        if outcome["stdout_truncated"]:
            _fail(outcome["stdout_length"] == intent["stdout_limit"])
        if outcome["stderr_truncated"]:
            _fail(outcome["stderr_length"] == intent["stderr_limit"])
        if outcome["outcome"] == "exited":
            _fail(0 <= outcome["status"] <= 255)
        if outcome["outcome"] == "signaled":
            _fail(1 <= outcome["status"] <= 64)
def _settled_v2(records, intent, index):
    serial = intent.body["command_serial"]
    if intent.body["command_id"] in {"CTR_TASK_TERM", "CTR_TASK_KILL"} and any(
            item.record_type == "RUNTIME_RESUME_V4" and item.body["uncertain_serial"] == serial for item in records[:index]): return True
    if intent.body["command_id"] == "CONTAINERD_START":
        return any(item.record_type == "DAEMON_RETAINED_V2" and item.body["command_serial"] == serial
                   for item in records[:index])
    outcomes = [item for item in records[:index] if item.record_type == "COMMAND_OUTCOME_V2"
                and item.body["command_serial"] == serial]
    return bool(outcomes and not outcomes[-1].body["uncertain"]
                and outcomes[-1].body["outcome"] == "exited" and outcomes[-1].body["status"] == 0)

def _b1_phase_trace(records, index, phase, network_state):
    intents = [item for item in records[:index] if item.record_type == "COMMAND_INTENT_V2" and item.body["lifecycle_phase"] == phase]
    replay_indices = {position for position, item in enumerate(intents)
                      if item.body["command_serial"] in network_state["replay_serials"]}
    network_journal.successful_trace((item.body["command_id"] for item in intents), phase, replay_indices)
    _fail(all(_settled_v2(records, item, index) for item in intents))


def _runtime_trace(records, index, phase, ownership=None, candidate=None, complete=False):
    key = phase if phase != "OWNERSHIP_OBSERVED" else f"{phase}:task-{ownership['task'].split('-', 1)[0]}"
    trace = command_policy.RUNTIME_TRACES.get(key, ())
    abandoned = {item.body["uncertain_serial"] for item in records[:index]
                 if item.record_type == "RUNTIME_RESUME_V4"}
    intents = [item for item in records[:index]
               if item.record_type == "COMMAND_INTENT_V2"
               and item.body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION
               and item.body["lifecycle_phase"] == phase
               and not (item.body["command_serial"] in abandoned
                        and item.body["command_id"] in {
                            "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"})]
    observed = tuple(item.body["command_id"] for item in intents) + (() if candidate is None else (candidate,))
    alternatives = (command_policy.RUNTIME_OWNERSHIP_TRACES
                    if key == "OWNERSHIP_OBSERVED:task-exact" else (trace,))
    _fail(observed in alternatives if complete
          else any(observed == row[:len(observed)] for row in alternatives))
    _fail(all(_settled_v2(records, intent, index) for intent in intents))


def _v2_occurrence(records, index, phase, body, ownership=None):
    if body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION:
        _runtime_tables()
        if body["command_id"] == "CTR_RUN":
            _fail(not any(item.record_type in {"COMMAND_INTENT", "COMMAND_INTENT_V2"}
                          and item.body["command_id"] == "CTR_RUN" for item in records[:index]))
        _runtime_trace(records, index, phase, ownership, body["command_id"])
        return
    _policy_tables()
    command_id = body["command_id"]
    prior = [item for item in records[:index] if item.record_type == "COMMAND_INTENT_V2"]
    same = [item for item in prior if item.body["command_id"] == command_id]
    _fail(len(same) < command_policy.MAX_OCCURRENCES[command_id])
    if command_id in command_policy.KEY_COMMANDS:
        _fail(phase == "ROOTFS_LEASED" and not same)
        order = list(command_policy.KEY_COMMAND_ORDER)
        position = order.index(command_id)
        _fail(all(any(item.body["command_id"] == predecessor for item in prior)
                  for predecessor in order[:position]))
        _fail(all(_settled_v2(records, item, index) for item in prior
                  if item.body["command_id"] in command_policy.KEY_COMMANDS))
    elif command_id == "SSH_READY":
        _fail(phase == "RUNTIME_READY"
              and not any(item.body["command_id"] == command_id for item in prior))
    else:
        _fail(phase == "BASELINES_CAPTURED"
              and not any(item.body["command_id"] == command_id for item in prior))
def _legal(records):
    _fail(records and records[0].record_type == "GENESIS")
    genesis = records[0].body
    token = genesis["operation_token"]
    key = genesis["journal_key"]
    phase = "GENESIS"
    pending = None
    command_phase = None
    command_pending = None
    command_intent_v2 = None
    command_preexec_v2 = command_output_v3 = None
    command_b1 = False
    retained_daemon = None
    runtime_staged = None
    command_generation = None
    ownership = None
    ssh_result = None
    runtime_mount = None
    production_admitted = False
    lifecycle_deadline = None
    network_state = network_journal.initial()
    rootfs = False
    next_serial = 0
    for index, record in enumerate(records[1:], 1):
        kind = record.record_type
        body = record.body
        _fail(body["operation_token"] == token)
        if phase == "UNCERTAIN" and kind == "RUNTIME_RESUME_V4":
            prior = records[index - 1]; serial = body["uncertain_serial"]
            intent = next(item for item in records[:index] if item.record_type == "COMMAND_INTENT_V2" and item.body["command_serial"] == serial)
            recoverable = {"CTR_RUN", "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST", "CTR_TASK_TERM", "CTR_TASK_KILL"}
            daemon = prior.record_type == "DAEMON_OUTCOME_V2" and intent.body["command_id"] == "CONTAINERD_START"
            target = "RUNTIME_CLEANUP_ONLY" if daemon else "READINESS_REVOKED" if intent.body["command_id"] == "CTR_RUN" else intent.body["lifecycle_phase"]
            _fail(prior.record_type in {"COMMAND_OUTCOME_V2", "DAEMON_OUTCOME_V2"} and prior.body["uncertain"] and
                  prior.body["command_serial"] == serial and prior.body["binding_sha256"] == body["binding_sha256"] == intent.body["binding_sha256"] and
                  (daemon or intent.body["command_id"] in recoverable) and body["target_phase"] == target and
                  intent.body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION)
            phase = target; continue
        if phase == "RETIRED" or (phase == "UNCERTAIN" and kind not in {
                "INPUT_GRANT", "INPUT_WA", "INPUT_STEP"}):
            raise OperationError()
        if command_generation == "v1":
            _fail(kind not in _V2_COMMAND_RECORDS)
        elif command_generation == "v2":
            _fail(kind not in _V1_COMMAND_RECORDS)
        if kind in {"COMMAND_INTENT", "COMMAND_INTENT_V2"}:
            selected = "v1" if kind == "COMMAND_INTENT" else "v2"
            _fail(command_generation in {None, selected})
            command_generation = selected
        if kind == "LIFECYCLE_DEADLINE_V1":
            _fail(phase == "ROOTFS_LEASED" and lifecycle_deadline is None
                  and not production_admitted and command_phase is None)
            lifecycle_deadline = body
            continue
        if kind == "PRODUCTION_ADMISSION_V2":
            _fail(phase == "ROOTFS_LEASED" and not production_admitted and command_phase is None)
            production_admitted = True
            continue
        if kind == "RUNTIME_MOUNT_V2":
            _fail(production_admitted and phase == "RUNTIME_READY" and runtime_mount is None
                  and command_phase is None)
            manifests = [item.body for item in records[:index] if item.record_type == "INPUT_STEP"
                         and item.body["path"] == "@manifest" and item.body["action"] == "create"]
            _fail(len(manifests) == 1 and manifests[0]["sha256"] == body["manifest_sha256"])
            runtime_mount = record
            continue
        if kind == "INPUT_GRANT":
            _fail(command_phase is None and phase in {"ROOTFS_LEASED", "FS_INTENT", "FS_SETTLED",
                  "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN"})
            prior = [item.body for item in records[:index] if item.record_type == "INPUT_GRANT"
                     and item.body["grant_id"] == body["grant_id"]]
            if body["action"] == "intent": _fail(not prior)
            else:
                _fail(len(prior) == 1 and prior[0]["action"] == "intent"
                      and all(body[name] == prior[0][name] for name in (
                          "path", "name", "parent_generation", "parent_inode_version",
                          "expected_kind", "expected_mode", "expected_uid", "expected_gid",
                          "command_serial", "birth_min_ns", "birth_max_ns", "mount_id",
                          "inode_version_min", "inode_version_max")))
            continue

        if kind == "INPUT_WA":
            _fail(command_phase is None and phase in {"ROOTFS_LEASED", "FS_INTENT", "FS_SETTLED",
                  "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN"})
            prior = [item.body for item in records[:index] if item.record_type == "INPUT_WA"
                     and (item.body["action"], item.body["path"]) == (body["action"], body["path"])]
            _fail(not prior)
            if body["action"] == "mkdir-settled":
                intents = [item.body for item in records[:index] if item.record_type == "INPUT_WA"
                           and (item.body["action"], item.body["path"]) == ("mkdir", body["path"])]
                _fail(len(intents) == 1 and all(body[name] == intents[0][name]
                      for name in ("parent_key", "names_sha256", "target_mode")))
            elif body["action"] == "file-settled":
                _fail(any(item.record_type == "INPUT_GRANT" and item.body["action"] == "settled"
                          and item.body["path"] == body["path"] for item in records[:index]))
            continue
        if kind == "INPUT_STEP":
            _fail(command_phase is None and phase in {"FS_INTENT", "FS_SETTLED", "RUNTIME_READY",
                  "SSH_READY", "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN"})
            prior = [item.body for item in records[:index] if item.record_type == "INPUT_STEP"
                     and item.body["path"] == body["path"]]
            if body["action"] == "create-intent": _fail(not prior)
            elif body["action"] == "create":
                _fail(prior and prior[-1]["action"] == "create-intent")
                if production_admitted and body["kind"] == "directory":
                    grants = [item.body for item in records[:index] if item.record_type == "INPUT_GRANT"
                              and item.body["path"] == body["path"] and item.body["action"] == "settled"]
                    _fail(len(grants) == 1 and grants[0]["child_generation"]["mount_id"] == body["key"]["mount_id"]
                          and grants[0]["child_generation"]["device"] == body["key"]["device"]
                          and grants[0]["child_generation"]["inode"] == body["key"]["inode"])
            elif body["action"] == "remove-intent":
                _fail(prior and prior[-1]["action"] in {"create-intent", "create"}
                      and not any(item["action"] == "remove-intent" for item in prior))
            else:
                _fail(prior and prior[-1]["action"] == "remove-intent")
            continue

        if kind == "RUNTIME_STAGE_INTENT_V4":
            _fail(command_generation != "v1" and command_phase is None and phase == "NETWORK_READY" and
                  not any(item.record_type in {kind, "RUNTIME_STAGED_V3"} for item in records[:index])); continue
        if kind == "RUNTIME_STAGED_V3":
            _fail(command_generation != "v1" and command_phase is None and phase == "NETWORK_READY" and runtime_staged is None and
                  any(item.record_type == "RUNTIME_STAGE_INTENT_V4" for item in records[:index]))
            runtime_staged = body; continue
        if kind == "RUNTIME_IDENTITY_V4":
            _fail(command_phase is None and phase == "OWNERSHIP_OBSERVED" and not any(item.record_type == kind for item in records[:index])); continue
        if kind == "NETWORK_SNAPSHOT_V2" or kind in network_journal.ALL_RECORDS:
            _fail(command_generation in {None, "v2"}); command_generation = "v2"
            _fail(rootfs and command_phase is None)
            try:
                network_state = network_journal.advance(network_state, kind, body, phase)
            except ValueError as error:
                raise OperationError() from error
            continue
        if kind == "COMMAND_INTENT_V2":
            _fail(rootfs and command_phase is None and phase in {
                "ROOTFS_LEASED", "FS_SETTLED", *LIFECYCLE[:14],
            })
            _fail(body["command_serial"] == next_serial)
            network_ids = {value.value for value in actions.NETWORK_COMMANDS}
            b1_network = ((body["command_id"] in network_ids or body["command_id"] == "CTR_RUN") and
                          (network_state["snapshots"] or network_state["effects"] or
                           network_state["pending"] is not None or
                           body["command_id"] not in LEGACY_COMMANDS))
            _fail(body["command_id"] not in {"TC_QDISC", "TC_INGRESS_FILTER"} or b1_network)
            if b1_network:
                try:
                    network_state = network_journal.command_intent(body, network_state)
                except ValueError as error:
                    raise OperationError() from error
            _v2_lineage(genesis, phase, body, b1_network=b1_network)
            if body["policy_version"] == command_policy.RUNTIME_POLICY_VERSION:
                artifact = 0 if body["command_id"] == "CONTAINERD_START" else 1
                _fail(runtime_staged is not None and body["executable_generation"] ==
                      runtime_staged["containerd_generation" if artifact == 0 else "ctr_generation"]
                      and body["executable_sha256"] == command_policy.CONTAINERD_EXTRACTION[artifact][2])
            elif body["command_id"] in command_policy.KEY_COMMANDS:
                grants = [item.body for item in records[:index] if item.record_type == "INPUT_GRANT"]
                _fail(any(item["path"] == "@key-stage" and item["action"] == "settled"
                          for item in grants))
                pair = (("client", "client.pub") if "CLIENT" in body["command_id"]
                        else ("server", "server.pub"))
                required_action = ("settled" if body["command_id"].startswith("SSH_PUBLIC_")
                                   else "intent")
                _fail(all(any(item["path"] == "@key-stage/" + name
                                  and item["action"] == required_action for item in grants)
                          for name in pair))
            if not b1_network:
                _v2_occurrence(records, index, phase, body, ownership)
            next_serial += 1
            command_phase = kind
            command_intent_v2 = record
            command_preexec_v2 = command_output_v3 = None
            command_b1 = b1_network
            continue
        if kind == "COMMAND_PREEXEC_V2":
            _fail(command_phase == "COMMAND_INTENT_V2" and command_intent_v2 is not None)
            _v2_lineage(genesis, phase, command_intent_v2.body, body, b1_network=command_b1)
            command_phase = kind
            command_preexec_v2 = record
            continue
        if kind == "DAEMON_RETAINED_V2":
            _fail(command_phase == "COMMAND_PREEXEC_V2" and command_intent_v2 is not None)
            _fail(command_preexec_v2 is not None and retained_daemon is None)
            _fail(command_intent_v2.body["command_id"] == "CONTAINERD_START")
            _v2_lineage(genesis, phase, command_intent_v2.body, command_preexec_v2.body)
            _fail(_same_command_v2(body, command_intent_v2.body))
            _fail(body["pid"] == command_preexec_v2.body["pid"])
            retained_daemon = (command_intent_v2, command_preexec_v2, record)
            command_phase = command_intent_v2 = command_preexec_v2 = None
            command_b1 = False
            continue
        if kind == "DAEMON_OUTCOME_V2":
            _fail(command_phase is None and retained_daemon is not None)
            daemon_intent, daemon_preexec, _daemon_retained = retained_daemon
            _fail(_same_command_v2(body, daemon_intent.body))
            _fail(body["pid"] == daemon_preexec.body["pid"])
            _fail(body["proc_start_time"] == daemon_preexec.body["proc_start_time"])
            residue = not all(body[name] for name in ("leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed"))
            if not residue: retained_daemon = None
            if body["uncertain"] or phase != "FIREWALL_ABSENT":
                phase = "UNCERTAIN"
            continue
        if kind == "COMMAND_OUTPUT_V3":
            _fail(command_phase == "COMMAND_PREEXEC_V2" and command_intent_v2 is not None and
                  command_output_v3 is None and _same_command_v2(body, command_intent_v2.body))
            stdout, stderr = bytes.fromhex(body["stdout_hex"]), bytes.fromhex(body["stderr_hex"])
            _fail(len(stdout) <= command_intent_v2.body["stdout_limit"] and
                  len(stderr) <= command_intent_v2.body["stderr_limit"])
            command_output_v3 = record
            continue
        if kind == "COMMAND_OUTCOME_V2":
            _fail(command_phase in {"COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2"})
            _fail(command_intent_v2 is not None)
            _v2_lineage(
                genesis, phase, command_intent_v2.body,
                None if command_preexec_v2 is None else command_preexec_v2.body, body,
                b1_network=command_b1,
            )
            _fail((command_preexec_v2 is None and body["outcome"] == "not-started") or
                  (command_preexec_v2 is not None and body["outcome"] != "not-started"))
            if command_output_v3 is not None and not body["uncertain"]:
                _fail(body["stdout_sha256"] == hashlib.sha256(bytes.fromhex(command_output_v3.body["stdout_hex"])).hexdigest()
                      and body["stderr_sha256"] == hashlib.sha256(bytes.fromhex(command_output_v3.body["stderr_hex"])).hexdigest())
            if command_b1:
                network_state = network_journal.command_outcome(network_state, body)
            command_phase = command_intent_v2 = command_preexec_v2 = command_output_v3 = None
            command_b1 = False
            if body["uncertain"]:
                phase = "UNCERTAIN"
            continue
        if kind == "COMMAND_INTENT":
            if body["command_id"] == "CTR_RUN":
                _fail(not any(item.record_type in {"COMMAND_INTENT", "COMMAND_INTENT_V2"} and
                              item.body["command_id"] == "CTR_RUN" for item in records[:index]))
            _fail(rootfs and command_phase is None and phase in {
                "ROOTFS_LEASED", "FS_SETTLED", *LIFECYCLE[:14],
            })
            _fail(body["command_serial"] == next_serial)
            next_serial += 1
            command_phase, command_pending = kind, record
            continue
        if kind == "COMMAND_PREEXEC":
            _fail(command_phase == "COMMAND_INTENT" and command_pending is not None)
            _fail(_same_command(body, command_pending.body))
            command_phase, command_pending = kind, record
            continue
        if kind == "COMMAND_OUTCOME":
            _fail(command_phase in {"COMMAND_INTENT", "COMMAND_PREEXEC"})
            _fail(command_pending is not None and _same_command(body, command_pending.body))
            _fail((command_phase == "COMMAND_INTENT" and body["outcome"] == "not_started") or
                  (command_phase == "COMMAND_PREEXEC" and body["outcome"] != "not_started"))
            command_phase = command_pending = None
            if body["outcome"] == "uncertain":
                phase = "UNCERTAIN"
            continue
        _fail(command_phase is None)
        if kind == "SSH_RESULT_V2":
            _fail(production_admitted and phase == "RUNTIME_READY" and ssh_result is None
                  and runtime_mount is not None)
            outcomes = [item for item in records[:index] if item.record_type == "COMMAND_OUTCOME_V2"
                        and item.body["command_id"] == "SSH_READY"]
            _fail(len(outcomes) == 1 and records[index - 1] is outcomes[0])
            outcome = outcomes[0].body
            _fail(outcome["outcome"] == "exited" and outcome["status"] == 0
                  and outcome["errno"] is None and not outcome["uncertain"]
                  and outcome["stderr_length"] == 0 and not outcome["stdout_truncated"]
                  and not outcome["stderr_truncated"] and outcome["leader_reaped"]
                  and outcome["descendants_reaped"] and outcome["cgroup_empty"]
                  and outcome["cgroup_removed"] and outcome["pipes_eof"]
                  and outcome["release_count"] == 1 and outcome["errors"] == [])
            _fail(body["command_serial"] == outcome["command_serial"]
                  and body["binding_sha256"] == outcome["binding_sha256"]
                  and body["stdout_sha256"] == outcome["stdout_sha256"]
                  and body["manifest_sha256"] == runtime_mount.body["manifest_sha256"]
                  and body["runtime_mount_sha256"] == runtime_mount.body["issuance_sha256"]
                  and body["runtime_mount_generation"] == runtime_mount.body["mount_generation"])
            ssh_result = record
            continue
        if kind == "SSH_READY_V2":
            _fail(phase == "RUNTIME_READY" and ssh_result is not None
                  and records[index - 1] is ssh_result)
            _fail(body["result_record_sha256"] == ssh_result.line_sha256
                  and body["proof_sha256"] == ssh_result.body["proof_sha256"])
            phase = "SSH_READY"
            continue
        if retained_daemon is not None:
            _fail(kind not in set(LIFECYCLE[13:]) | {"FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"})
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
            if production_admitted and phase == "ROOTFS_LEASED":
                key_intents = [item for item in records[:index]
                               if item.record_type == "COMMAND_INTENT_V2"
                               and item.body["command_id"] in command_policy.KEY_COMMANDS]
                _fail(tuple(item.body["command_id"] for item in key_intents)
                      == command_policy.KEY_COMMAND_ORDER
                      and all(_settled_v2(records, item, index) for item in key_intents))
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
            if network_state["snapshots"]:
                requirement = (phase if kind == "NETWORK_ABSENT" and phase == "OWNERSHIP_OBSERVED"
                               and ownership is not None and ownership["task"] == "absent" else
                               network_journal.LIFECYCLE_REQUIREMENTS.get(kind))
                if requirement is not None:
                    _fail(requirement == phase)
                    try: _b1_phase_trace(records, index, phase, network_state)
                    except ValueError as error: raise OperationError() from error
            else:
                _fail(production_admitted or "COMMAND_INTENT_V2" not in seen
                      or runtime_staged is not None)
            if kind == "BASELINES_CAPTURED":
                _fail(phase in {"ROOTFS_LEASED", "FS_SETTLED"})
                if production_admitted: _fail(phase == "FS_SETTLED")
                snapshots = network_state["snapshots"]
                _fail(not snapshots or len(snapshots) == 1 and
                      body["proof_sha256"] == snapshots[-1]["proof_sha256"])
            elif kind == "NETWORK_READY":
                _fail(phase == "BASELINES_CAPTURED")
                snapshots = network_state["snapshots"]
                _fail(not snapshots or len(snapshots) == 2 and
                      body["proof_sha256"] == snapshots[-1]["proof_sha256"] and
                      network_state["pending"] is None and
                      [row["action"] for row in network_state["effects"]] == list(network_journal.SETUP))
            elif kind == "RUNTIME_READY":
                _fail(phase == "NETWORK_READY")
                if runtime_staged is not None: _runtime_trace(records, index, phase, ownership, complete=True)
            elif kind == "SSH_READY":
                # Historical fake record only: any v2 SSH intent requires the
                # separately named SSH_RESULT_V2 -> SSH_READY_V2 route above.
                ssh_commands = [item for item in records[:index] if item.record_type == "COMMAND_INTENT_V2"
                                and item.body["command_id"] == "SSH_READY"]
                _fail(not production_admitted and phase == "RUNTIME_READY" and not ssh_commands)
            elif kind == "READINESS_REVOKED":
                _fail(phase in {"BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY"})
            elif kind == "OWNERSHIP_OBSERVED":
                _fail(phase == "READINESS_REVOKED" and ownership is None)
                if runtime_staged is not None: _runtime_trace(records, index, phase, body, complete=True)
                ownership = body
            elif kind == "TASK_STOPPED":
                _fail(phase == "OWNERSHIP_OBSERVED" and ownership["task"] == "exact-owned")
                if runtime_staged is not None: _runtime_trace(records, index, phase, ownership, complete=True)
            elif kind == "NETWORK_ABSENT":
                _fail(ownership is not None and (phase == "TASK_STOPPED" or
                      phase == "OWNERSHIP_OBSERVED" and ownership["task"] == "absent"))
                snapshots = network_state["snapshots"]
                _fail(not snapshots or snapshots[-1]["snapshot_kind"] == "network-absent" and
                      body["proof_sha256"] == snapshots[-1]["proof_sha256"])
            elif kind == "TASK_ABSENT":
                _fail(phase == "NETWORK_ABSENT")
                if runtime_staged is not None: _runtime_trace(records, index, phase, ownership, complete=True)
            elif kind == "CONTAINER_ABSENT":
                _fail(phase == "TASK_ABSENT")
                if runtime_staged is not None: _runtime_trace(records, index, phase, ownership, complete=True)
            elif kind == "RUNTIME_ABSENT":
                _fail(phase == "CONTAINER_ABSENT")
                if runtime_staged is not None: _runtime_trace(records, index, phase, ownership, complete=True)
            elif kind == "SHARE_ABSENT":
                _fail(phase == "RUNTIME_ABSENT")
            elif kind == "FIREWALL_ABSENT":
                _fail(phase == "SHARE_ABSENT")
                snapshots = network_state["snapshots"]
                _fail(not snapshots or snapshots[-1]["snapshot_kind"] == "firewall-restored" and
                      body["proof_sha256"] == snapshots[-1]["proof_sha256"])
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
    if phase in {"INPUT_REMOVED", *LIFECYCLE[14:], "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
        _fail(retained_daemon is None)
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
    seal = object()
    owners, closed, permits, grants = {}, set(), {}, {}
    release_permits, release_grants = {}, {}
    class _FixedJournal:
        """One idempotently-closeable owner for the fixed state, lock, and journal."""
        def __init__(self):
            _fail(os.geteuid() == 0)
            self.control = fs.OperationControl(
                time.monotonic_ns() + JOURNAL_TOTAL_NS, lambda: False)
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
            candidates = _stage_candidates(set(names))
            if STATE_NAME.raw not in names:
                _fail(not candidates)
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
                if candidates:
                    _fail(set(names) == {SENTINEL_NAME.raw, LOCK_NAME.raw, JOURNAL_NAME.raw})
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
            raw_names = fs._enumerate_stable(self.completion, self.control).raw_names
            names = set(raw_names)
            _fail(STATE_NAME.raw in names)
            candidates = set()
            if records:
                _fail(_key_value(journal_generation.key) == records[0].body["journal_key"])
                _fail(not any(item.record_type in _V1_COMMAND_RECORDS for item in records))
                phase = _legal(records)
                _validate_stage_layout(
                    raw_names, records, phase, _key_value(self.completion.generation.key))
                if len(records) > 1:
                    _fail(_generation_value(self.state.generation) == records[1].body["state_parent"])
                if phase not in {"GENESIS", "GENESIS_SETTLED", "ROOTFS_ABSENT",
                                 "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
                    _fail(ROOTFS_NAME.raw in names)
                input_required = {"FS_OBSERVED", "COMMAND_INTENT", "COMMAND_PREEXEC",
                                  "COMMAND_OUTCOME", "COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2",
                                  "DAEMON_RETAINED_V2", *LIFECYCLE[:13]}
                settlements = [index for index, item in enumerate(records)
                               if item.record_type == "FS_SETTLED"]
                absent_settlement = (phase == "FS_SETTLED" and settlements
                                     and settlements[-1] > 0
                                     and records[settlements[-1] - 1].record_type == "FS_ABSENT")
                if phase == "FS_SETTLED" and not absent_settlement:
                    input_required.add("FS_SETTLED")
                if phase in input_required and phase not in {"FIREWALL_ABSENT", "FS_INTENT"}:
                    _fail(INPUT_NAME.raw in names)
                if (phase == "FS_ABSENT" or absent_settlement
                        or phase in set(LIFECYCLE[13:])
                        | {"FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}):
                    _fail(INPUT_NAME.raw not in names)
                if phase in {"ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
                    _fail(ROOTFS_NAME.raw not in names)
            else:
                candidates = _stage_candidates(names)
                _fail(not candidates and not names & RUNTIME_NAMES
                      and names <= COMPLETION_NAMES | RUNTIME_NAMES)
            observed_completion = fs._observe_node(
                self.completion.identity_fd, self.completion.operation_fd, self.control)
            expected_completion = self.completion.generation
            _fail(observed_completion.key == expected_completion.key
                  and observed_completion.mode == expected_completion.mode
                  and observed_completion.uid == expected_completion.uid
                  and observed_completion.gid == expected_completion.gid)
            if observed_completion != expected_completion:
                components = list(self.chain.components); current = components[-2]
                components[-2] = fs.ChainComponent(current.name, fs.HeldNode(
                    current.node.identity_fd, current.node.operation_fd, observed_completion))
                self.chain = fs.HeldChain(self.chain.anchor, tuple(components))
            fresh = _open_base_chain(self.control)
            try:
                expected_base = self.chain.components[:-1]
                base_ok = (fresh.anchor.generation == self.chain.anchor.generation
                           and len(fresh.components) == len(expected_base)
                           and all(left.name == right.name
                                   and left.node.generation == right.node.generation
                                   for left, right in zip(fresh.components, expected_base)))
                state_child_ok = (fs._observe_child(self.completion, STATE_NAME, self.control)
                                  == self.state.generation)
                state_live_ok = (fs._observe_node(self.state.identity_fd, self.state.operation_fd,
                                                  self.control) == self.state.generation)
                _fail(base_ok and state_child_ok and state_live_ok)
            finally:
                fs._close_chain(fresh)
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
                mount_id = fs._mount_id(identity, self.control, fs.FDINFO_IDENTITY_FLAGS)
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
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
    class RootfsGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
    class RootfsReleasePermit:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
    class RootfsReleaseGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
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
    def create_fixed_operation_test_local(authority, body):
        io, records, status = reload(authority)
        _fail(status == "absent" and not records)
        io.create(body)
        _io, fresh, fresh_status = reload(authority)
        _fail(fresh_status == "exact" and len(fresh) == 1 and fresh[0].record_type == "GENESIS")
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
        permit = RootfsReleasePermit(seal)
        release_permits[permit] = [context, settle, False]
        return permit
    class OperationAuthority:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
        def command_context(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records)
            _fail(records[-1].record_type not in {
                "COMMAND_INTENT", "COMMAND_PREEXEC", "COMMAND_INTENT_V2",
                "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3", "UNCERTAIN", "RETIRED",
            })
            genesis = records[0].body
            serial = sum(item.record_type in {"COMMAND_INTENT", "COMMAND_INTENT_V2"}
                         for item in records)
            return CommandContext(
                genesis["operation_token"], genesis["journal_key"], genesis["host_boot_id"],
                genesis["source_revision"], _legal(records), serial,
            )
        def has_recovery_command(self):
            _io, records, status = reload(self); _fail(status == "exact")
            return records[-1].record_type in {
                "COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3",
            } or (
                records[-1].record_type == "COMMAND_OUTCOME_V2" and records[-1].body["uncertain"])

        def runtime_recovery_history(self):
            _io, records, status = reload(self); _fail(status == "exact" and records and records[-1].record_type != "RETIRED")
            result = {"operation_token": records[0].body["operation_token"], "phase": _legal(records),
                      "terminal_sha256": records[-1].line_sha256, "tip": records[-1].record_type}
            for name, kind in (("intents", "COMMAND_INTENT_V2"), ("outcomes", "COMMAND_OUTCOME_V2"),
                    ("daemon_retained", "DAEMON_RETAINED_V2"), ("daemon_outcomes", "DAEMON_OUTCOME_V2"),
                    ("runtime_staged", "RUNTIME_STAGED_V3"), ("outputs", "COMMAND_OUTPUT_V3"),
                    ("runtime_identities", "RUNTIME_IDENTITY_V4"), ("runtime_stage_intents", "RUNTIME_STAGE_INTENT_V4"),
                    ("runtime_resumes", "RUNTIME_RESUME_V4")):
                result[name] = tuple(item.body for item in records if item.record_type == kind)
            return result
        def runtime_history(self):
            result = self.runtime_recovery_history()
            _fail(result["phase"] != "UNCERTAIN" and result["tip"] not in {"COMMAND_INTENT", "COMMAND_PREEXEC",
                  "COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3", "UNCERTAIN"})
            return result
        def settle_runtime_phase(self, kind, proof_sha256, ownership=None):
            _fail(kind in {"RUNTIME_READY", "OWNERSHIP_OBSERVED", "TASK_STOPPED", "TASK_ABSENT",
                           "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT"}); _hex(proof_sha256)
            _io, records, status = reload(self); _fail(status == "exact")
            body = {"operation_token": records[0].body["operation_token"], "proof_sha256": proof_sha256}
            if kind == "OWNERSHIP_OBSERVED": body.update({"task": "exact-owned", "container": "exact-owned",
                "runtime": "exact-owned", "share": "exact-owned"} if ownership is None else ownership)
            write_validated(self, kind, body)
        def recovery_command(self):
            _io, records, status = reload(self); _fail(status == "exact")
            terminal = None
            if records[-1].record_type in {"COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3"}:
                output = records[-1].record_type == "COMMAND_OUTPUT_V3"
                preexec = records[-2] if output else records[-1] if records[-1].record_type == "COMMAND_PREEXEC_V2" else None
                intent = records[-3] if output else records[-2] if preexec is not None else records[-1]
            else:
                terminal = records[-1]
                _fail(terminal.record_type in {"COMMAND_OUTCOME_V2", "DAEMON_OUTCOME_V2"}
                      and terminal.body["uncertain"])
                if terminal.record_type == "DAEMON_OUTCOME_V2": _fail(not all(terminal.body[name] for name in ("leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed")))
                serial = terminal.body["command_serial"]
                intent = next(item for item in records if item.record_type == "COMMAND_INTENT_V2"
                              and item.body["command_serial"] == serial)
                matches = [item for item in records if item.record_type == "COMMAND_PREEXEC_V2"
                           and item.body["command_serial"] == serial]
                preexec = matches[0] if matches else None
            _fail(intent.record_type == "COMMAND_INTENT_V2")
            return (intent.body, None if preexec is None else preexec.body,
                    None if terminal is None else terminal.body)
        def recovery_lifecycle_deadline(self):
            _io, records, status = reload(self, True); _fail(status == "exact" and records)
            rows = [item.body for item in records
                    if item.record_type == "LIFECYCLE_DEADLINE_V1"]
            admitted = any(item.record_type == "PRODUCTION_ADMISSION_V2" for item in records)
            _fail(len(rows) <= 1 and (not admitted or len(rows) == 1))
            return (records[0].body["host_boot_id"],
                    None if not rows else rows[0]["journal_deadline_boottime_ns"])
        def pending_command(self):
            intent, preexec, terminal = self.recovery_command()
            _fail(terminal is None)
            return intent, preexec
        def record_command_intent(self, body):
            context = self.command_context()
            _io, records, status = reload(self, True)
            deadlines = [item.body for item in records
                         if item.record_type == "LIFECYCLE_DEADLINE_V1"]
            if any(item.record_type == "PRODUCTION_ADMISSION_V2" for item in records):
                _fail(status == "exact" and len(deadlines) == 1)
                deadline = deadlines[0]
                now = _boottime_ns()
                _fail(context.host_boot_id == _current_boot_id())
                _fail(now < deadline["journal_deadline_boottime_ns"])
                _fail(body["deadline_boottime_ns"] + body["cleanup_reserve_ns"]
                      <= deadline["journal_deadline_boottime_ns"])
                if body["command_id"] == "SSH_READY":
                    _fail(now < deadline["ssh_start_deadline_boottime_ns"])
            _fail(body["operation_token"] == context.operation_token)
            _fail(body["journal_key"] == context.journal_key)
            _fail(body["host_boot_id"] == context.host_boot_id)
            _fail(body["source_revision"] == context.source_revision)
            _fail(body["lifecycle_phase"] == context.lifecycle_phase)
            _fail(body["command_serial"] == context.command_serial)
            write_validated(self, "COMMAND_INTENT_V2", body)
            return CommandIntentReceipt(
                body["command_serial"], body["command_id"], body["binding_sha256"],
            )
        def record_command_preexec(self, body):
            intent, preexec = self.pending_command()
            _fail(preexec is None and _same_command_v2(body, intent))
            write_validated(self, "COMMAND_PREEXEC_V2", body)
        def record_command_output(self, body):
            intent, preexec = self.pending_command(); _fail(preexec is not None and _same_command_v2(body, intent))
            write_validated(self, "COMMAND_OUTPUT_V3", body); return body
        def record_command_outcome(self, body):
            intent, preexec = self.pending_command()
            _fail(_same_command_v2(body, intent))
            _fail((preexec is None and body["outcome"] == "not-started") or
                  (preexec is not None and body["outcome"] != "not-started"))
            write_validated(self, "COMMAND_OUTCOME_V2", body)
            return DurableCommandOutcome(
                body["command_serial"], body["command_id"], body["binding_sha256"], body,
            )
        def resume_runtime_cleanup(self):
            _io, records, status = reload(self); _fail(status == "exact" and _legal(records) == "UNCERTAIN"); terminal = records[-1].body
            intent = next(item.body for item in records if item.record_type == "COMMAND_INTENT_V2" and item.body["command_serial"] == terminal["command_serial"])
            target = "RUNTIME_CLEANUP_ONLY" if records[-1].record_type == "DAEMON_OUTCOME_V2" else "READINESS_REVOKED" if intent["command_id"] == "CTR_RUN" else intent["lifecycle_phase"]
            write_validated(self, "RUNTIME_RESUME_V4", {"operation_token": records[0].body["operation_token"], "target_phase": target,
                "uncertain_serial": terminal["command_serial"], "binding_sha256": terminal["binding_sha256"]}); return target
        def record_runtime_stage_intent(self, body):
            _io, records, status = reload(self); _fail(status == "exact" and not any(
                item.record_type in {"RUNTIME_STAGE_INTENT_V4", "RUNTIME_STAGED_V3"} for item in records))
            write_validated(self, "RUNTIME_STAGE_INTENT_V4", body)
        def record_runtime_identity(self, body):
            _io, records, status = reload(self); _fail(status == "exact" and not any(
                item.record_type == "RUNTIME_IDENTITY_V4" for item in records))
            write_validated(self, "RUNTIME_IDENTITY_V4", body)
        def record_runtime_staged(self, body):
            _io, records, status = reload(self)
            _fail(status == "exact" and not any(item.record_type == "RUNTIME_STAGED_V3" for item in records))
            write_validated(self, "RUNTIME_STAGED_V3", body)
        def record_daemon_retained(self, body):
            intent, preexec = self.pending_command()
            _fail(preexec is not None and intent["command_id"] == "CONTAINERD_START")
            _fail(_same_command_v2(body, intent) and body["pid"] == preexec["pid"])
            write_validated(self, "DAEMON_RETAINED_V2", body)
        def record_daemon_outcome(self, body):
            _io, records, status = reload(self)
            _fail(status == "exact")
            retained = [item for item in records if item.record_type == "DAEMON_RETAINED_V2"]
            outcomes = [item for item in records if item.record_type == "DAEMON_OUTCOME_V2"]
            _fail(len(retained) == len(outcomes) + 1)
            _fail(_same_command_v2(body, retained[-1].body))
            write_validated(self, "DAEMON_OUTCOME_V2", body)
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
        def admit_production_v2(self):
            context = self.command_context()
            _fail(context.lifecycle_phase == "ROOTFS_LEASED"
                  and context.host_boot_id == _current_boot_id())
            _io, records, status = reload(self, True); _fail(status == "exact")
            deadlines = [item.body for item in records
                         if item.record_type == "LIFECYCLE_DEADLINE_V1"]
            _fail(len(deadlines) <= 1)
            if not deadlines:
                admitted = _boottime_ns()
                write_validated(self, "LIFECYCLE_DEADLINE_V1", {
                    "operation_token": context.operation_token,
                    "admission_boottime_ns": admitted,
                    "ssh_start_deadline_boottime_ns": admitted + JOURNAL_SETUP_MARGIN_NS,
                    "journal_deadline_boottime_ns": admitted + JOURNAL_TOTAL_NS})
            _io, records, status = reload(self, True); _fail(status == "exact")
            if not any(item.record_type == "PRODUCTION_ADMISSION_V2" for item in records):
                write_validated(self, "PRODUCTION_ADMISSION_V2", {
                    "operation_token": context.operation_token,
                    "admission_version": PRODUCTION_ADMISSION_VERSION,
                    "policy_version": command_policy.POLICY_VERSION,
                    "parser_source_sha256": SSH_PARSER_SHA256})
        def record_runtime_mount_v2(self, key, manifest_sha256, mount_generation):
            _fail(key is seal)
            context = self.command_context()
            body = {"operation_token": context.operation_token,
                    "manifest_sha256": manifest_sha256,
                    "mount_generation": mount_generation}
            body["issuance_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
            write_validated(self, "RUNTIME_MOUNT_V2", body)
            return body["issuance_sha256"]
        def pending_fs_intent(self):
            _io, records, status = reload(self, True); _fail(status == "exact")
            rows = [item.body for item in records if item.record_type == "FS_INTENT"]
            _fail(rows)
            return rows[-1]
        def record_fs_absent(self, body):
            write_validated(self, "FS_ABSENT", body)
        def record_input_grant(self, body):
            _io, records, status = reload(self, True)
            _fail(status == "exact" and records)
            value = {"operation_token": records[0].body["operation_token"], **body}
            write_validated(self, "INPUT_GRANT", value)
        def input_grants(self):
            _io, records, status = reload(self, True); _fail(status == "exact")
            return tuple(item.body for item in records if item.record_type == "INPUT_GRANT")
        def record_input_wa(self, body):
            _io, records, status = reload(self, True)
            _fail(status == "exact" and records)
            value = {"operation_token": records[0].body["operation_token"], **body}
            write_validated(self, "INPUT_WA", value)
        def input_wa(self):
            _io, records, status = reload(self, True); _fail(status == "exact")
            return tuple(item.body for item in records if item.record_type == "INPUT_WA")
        def record_input_step(self, action, path, kind, key, digest):
            _io, records, status = reload(self, True)
            _fail(status == "exact" and records)
            write_validated(self, "INPUT_STEP", {
                "operation_token": records[0].body["operation_token"], "action": action,
                "path": path, "kind": kind, "key": key, "sha256": digest})
        def input_steps(self):
            _io, records, status = reload(self, True); _fail(status == "exact")
            return tuple(item.body for item in records if item.record_type == "INPUT_STEP")
        def input_cleanup_token(self):
            _io, records, status = reload(self, True)
            _fail(status == "exact" and records and _legal(records) in {
                "ROOTFS_LEASED", "FS_INTENT", "FS_SETTLED", "RUNTIME_READY",
                "SSH_READY", "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN",
            })
            return records[0].body["operation_token"]
        def record_fs_intent(self, body):
            context = self.command_context()
            _fail(body["operation_token"] == context.operation_token)
            write_validated(self, "FS_INTENT", body)
        def record_fs_observed(self, body):
            _io, records, status = reload(self)
            intent = next(item for item in reversed(records) if item.record_type == "FS_INTENT")
            _fail(status == "exact" and _same_intent(body, intent.body))
            write_validated(self, "FS_OBSERVED", body)
        def record_fs_settled(self, body):
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].record_type in {"FS_OBSERVED", "FS_ABSENT"}
                  and body == records[-1].body)
            write_validated(self, "FS_SETTLED", body)
        def record_ssh_result(self, serial, binding, manifest, stdout, canonical_result):
            context = self.command_context()
            _fail(context.lifecycle_phase == "RUNTIME_READY" and type(stdout) is bytes
                  and type(canonical_result) is bytes)
            _io, records, status = reload(self, True)
            mounts = [item.body for item in records if item.record_type == "RUNTIME_MOUNT_V2"]
            _fail(status == "exact" and len(mounts) == 1)
            mount = mounts[0]
            body = {"operation_token": context.operation_token, "command_serial": serial,
                    "binding_sha256": binding, "manifest_sha256": manifest,
                    "runtime_mount_sha256": mount["issuance_sha256"],
                    "runtime_mount_generation": mount["mount_generation"],
                    "program_sha256": guest_workloads.GUEST_PROGRAM_SHA256,
                    "parser_sha256": SSH_PARSER_SHA256,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stdout_hex": stdout.hex(),
                    "result_sha256": hashlib.sha256(canonical_result).hexdigest(),
                    "canonical_result_hex": canonical_result.hex(), "proof_sha256": ZERO}
            body["proof_sha256"] = _ssh_result_proof(body)
            write_validated(self, "SSH_RESULT_V2", body)
            return body["proof_sha256"]
        def record_ssh_ready(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records[-1].record_type == "SSH_RESULT_V2")
            result = records[-1]
            write_validated(self, "SSH_READY_V2", {
                "operation_token": records[0].body["operation_token"],
                "result_record_sha256": result.line_sha256,
                "proof_sha256": result.body["proof_sha256"]})
        def durable_phase(self):
            _io, records, status = reload(self, True)
            _fail(status == "exact" and records)
            return _legal(records)
        def revoke_readiness(self):
            context = self.command_context()
            if context.lifecycle_phase == "READINESS_REVOKED":
                return
            _fail(context.lifecycle_phase in {
                "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY"})
            write_validated(self, "READINESS_REVOKED", {
                "operation_token": context.operation_token})
        def record_input_removed(self, proof_sha256):
            context = self.command_context()
            _fail(context.lifecycle_phase == "FIREWALL_ABSENT" and _hex(proof_sha256))
            write_validated(self, "INPUT_REMOVED", {"operation_token": context.operation_token,
                                                     "proof_sha256": proof_sha256})
        def record_uncertain(self, reason):
            context, reason = self.command_context(), _choice(reason, UNCERTAIN_REASONS)
            write_validated(self, "UNCERTAIN", {"operation_token": context.operation_token,
                                                 "reason": reason})
        def network_records(self):
            _io, records, status = reload(self)
            _fail(status == "exact")
            return tuple(item.body for item in records if item.record_type == "NETWORK_SNAPSHOT_V2")
        def network_history(self):
            _io, records, status = reload(self)
            _fail(status == "exact")
            return tuple((item.record_type, item.body) for item in records
                         if item.record_type == "NETWORK_SNAPSHOT_V2" or
                         item.record_type in network_journal.ALL_RECORDS or
                         item.record_type == "COMMAND_OUTCOME_V2" and
                         item.body["command_id"] in {value.value for value in actions.NETWORK_COMMANDS})
        def record_network(self, kind, body):
            context = self.command_context()
            _fail(kind == "NETWORK_SNAPSHOT_V2" or kind in network_journal.ALL_RECORDS)
            _fail(body["operation_token"] == context.operation_token)
            write_validated(self, kind, body)
        def settle_network_phase(self, kind):
            _fail(kind in {"BASELINES_CAPTURED", "NETWORK_READY", "NETWORK_ABSENT", "FIREWALL_ABSENT"})
            snapshots = self.network_records()
            _fail(snapshots)
            write_validated(self, kind, {
                "operation_token": snapshots[-1]["operation_token"],
                "proof_sha256": snapshots[-1]["proof_sha256"],
            })
        def reserve_rootfs(self):
            _io, records, status = reload(self)
            _fail(status == "exact" and records)
            phase = records[-1].record_type
            _fail(phase in {"ROOTFS_ACQUIRE_INTENT", "ROOTFS_LEASED", "ROOTFS_RELEASE_READY",
                            "ROOTFS_RELEASE_AUTHORIZED"})
            _fail(not any(value[0] is self and not value[4] for value in permits.values()))
            _fail(not any(value[0] is self and not value[5] for value in grants.values()))
            permit = RootfsPermit(seal)
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
        _fail(type(permit) is RootfsPermit)
        state = permits.get(permit)
        _fail(state is not None and not state[4])
        authority, token, sequence, phase, _used = state
        _io, records, status = reload(authority)
        _fail(status == "exact" and records[0].body["operation_token"] == token)
        _fail(len(records) - 1 == sequence and records[-1].record_type == phase)
        state[4] = True
        value = RootfsGrant(seal)
        grants[value] = [authority, token, sequence, phase, False, False]
        return value
    def grant_records(grant):
        _fail(type(grant) is RootfsGrant)
        state = grants.get(grant)
        _fail(state is not None)
        authority, token, sequence, phase, _routed, _settled = state
        _io, records, status = reload(authority)
        _fail(status == "exact" and records[0].body["operation_token"] == token)
        _fail(len(records) - 1 == sequence and records[-1].record_type == phase)
        return state, records
    def invoke_rootfs_reopen_route(grant, route, control):
        state, records = grant_records(grant)
        _fail(not state[4] and not state[5] and type(route) is type(invoke_rootfs_reopen_route))
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
        state = release_permits.get(permit)
        _fail(type(permit) is RootfsReleasePermit and state is not None and not state[2])
        state[2] = True
        grant = RootfsReleaseGrant(seal)
        release_grants[grant] = [state[0], state[1], False, False]
        return grant
    def invoke_rootfs_release(grant, route):
        state = release_grants.get(grant)
        _fail(type(grant) is RootfsReleaseGrant and state is not None and not state[2] and not state[3])
        _fail(type(route) is type(invoke_rootfs_release))
        state[2] = True
        return route(state[0])
    def settle_rootfs_release(grant, authorization):
        state = release_grants.get(grant)
        _fail(type(grant) is RootfsReleaseGrant and state is not None and state[2] and not state[3])
        context = state[0]
        _fail(type(authorization) is RootfsAuthorization and authorization.rootfs_token == context.rootfs_token)
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
    def make_fake_lifecycle(raw):
        records = list(_parse(raw))
        _fail(records[-1].record_type in {"ROOTFS_LEASED", "ROOTFS_RELEASE_READY",
                                         "ROOTFS_RELEASE_AUTHORIZED"})
        state = {"records": records, "raw": raw, "release": False}
        def record(kind, body):
            line = _encode(kind, body, tuple(state["records"]))
            state["raw"] += line
            state["records"] = list(_parse(state["raw"]))
        def proof(kind, digest):
            _hex(digest)
            record(kind, {"operation_token": records[0].body["operation_token"], "proof_sha256": digest})
        class FakeLifecycle:
            __slots__ = ()
            def __new__(cls, key=None):
                _fail(key is seal)
                return super().__new__(cls)
            def baselines_captured(self, digest): proof("BASELINES_CAPTURED", digest)
            def network_ready(self, digest): proof("NETWORK_READY", digest)
            def runtime_ready(self, digest): proof("RUNTIME_READY", digest)
            def ssh_ready(self, digest):
                record("SSH_READY", {"operation_token": records[0].body["operation_token"],
                    "proof_sha256": digest, "marker_sha256": hashlib.sha256(FIXED["ssh_marker"].encode()).hexdigest(),
                    "authentication_attempts": 1})
            def revoke_readiness(self): record("READINESS_REVOKED", {"operation_token": records[0].body["operation_token"]})
            def ownership_observed(self, digest, task="exact-owned", container="exact-owned",
                                   runtime="exact-owned", share="exact-owned"):
                record("OWNERSHIP_OBSERVED", {"operation_token": records[0].body["operation_token"],
                    "proof_sha256": digest, "task": task, "container": container,
                    "runtime": runtime, "share": share})
            def task_stopped(self, digest): proof("TASK_STOPPED", digest)
            def network_absent(self, digest): proof("NETWORK_ABSENT", digest)
            def task_absent(self, digest): proof("TASK_ABSENT", digest)
            def container_absent(self, digest): proof("CONTAINER_ABSENT", digest)
            def runtime_absent(self, digest): proof("RUNTIME_ABSENT", digest)
            def share_absent(self, digest): proof("SHARE_ABSENT", digest)
            def firewall_absent(self, digest): proof("FIREWALL_ABSENT", digest)
            def input_removed(self, digest): proof("INPUT_REMOVED", digest)
            def rootfs_release_ready(self):
                leased = next(item.body for item in state["records"] if item.record_type == "ROOTFS_LEASED")
                removed = state["records"][-1]
                record("ROOTFS_RELEASE_READY", {"operation_token": records[0].body["operation_token"],
                    "rootfs_token": records[0].body["rootfs_token"], "rootfs_ledger_key": leased["rootfs_ledger_key"],
                    "leased_sequence": leased["leased_sequence"], "leased_offset": leased["leased_offset"],
                    "leased_sha256": leased["leased_sha256"], "input_removed_sha256": removed.body["proof_sha256"]})
                _fail(not state["release"]); state["release"] = True
                return issue_release(tuple(state["records"]), lambda body: record("ROOTFS_RELEASE_AUTHORIZED", body))
            def resume_rootfs_release_ready(self):
                _fail(state["records"][-1].record_type == "ROOTFS_RELEASE_READY" and not state["release"])
                state["release"] = True
                return issue_release(tuple(state["records"]), lambda body: record("ROOTFS_RELEASE_AUTHORIZED", body))
            def rootfs_absent(self, digest): proof("ROOTFS_ABSENT", digest)
            def retire(self, final_digest):
                token = records[0].body["operation_token"]
                record("FINAL_BASELINES", {"operation_token": token, "final_baselines_sha256": final_digest})
                body = {"operation_token": token, "journal_key": records[0].body["journal_key"],
                        "final_baselines_sha256": final_digest}
                record("RETIRE_INTENT", body); record("RETIRED", body)
            def journal_bytes(self): return bytes(state["raw"])
        return FakeLifecycle(seal)
    def _open_fixed_operation():
        io = _open_io()
        authority = OperationAuthority(seal)
        owners[authority] = [io, (), "absent"]
        try:
            reload(authority, True)
            return authority
        except BaseException as error:
            closed.add(authority)
            owners[authority][1:] = [(), "closed"]
            io.close(error)
    def admit_production_v2(authority):
        _fail(type(authority) is OperationAuthority and authority in owners and authority not in closed)
        authority.admit_production_v2()
        return authority
    def claim_production_operation(authority):
        _fail(type(authority) is OperationAuthority and authority in owners and authority not in closed)
        _io, records, status = reload(authority, True)
        admissions = [item for item in records if item.record_type == "PRODUCTION_ADMISSION_V2"]
        deadlines = [item for item in records if item.record_type == "LIFECYCLE_DEADLINE_V1"]
        _fail(status == "exact" and len(admissions) == len(deadlines) == 1
              and records[0].body["host_boot_id"] == _current_boot_id())
        return authority
    def command_context(authority): return authority.command_context()
    def pending_command(authority): return authority.pending_command()
    def has_recovery_command(authority): return authority.has_recovery_command()
    def recovery_command(authority): return authority.recovery_command()
    def recovery_lifecycle_deadline(authority):
        return authority.recovery_lifecycle_deadline()
    def record_command_intent(authority, body): return authority.record_command_intent(body)
    def record_command_preexec(authority, body): return authority.record_command_preexec(body)
    def record_command_output(authority, body): return authority.record_command_output(body)
    def record_command_outcome(authority, body): return authority.record_command_outcome(body)
    def record_daemon_retained(authority, body): return authority.record_daemon_retained(body)
    def record_daemon_outcome(authority, body): return authority.record_daemon_outcome(body)
    def durable_command_outcome(authority, serial, command_id, binding_sha256):
        return authority.durable_command_outcome(serial, command_id, binding_sha256)
    def durable_command_output(authority, serial, command_id, binding_sha256, stdout, stderr):
        return authority.durable_command_output(
            serial, command_id, binding_sha256, stdout, stderr,
        )
    def production(authority): return claim_production_operation(authority)
    def record_runtime_mount_v2(authority, manifest, generation):
        return production(authority).record_runtime_mount_v2(seal, manifest, generation)
    def pending_fs_intent(authority): return production(authority).pending_fs_intent()
    def record_fs_absent(authority, body): return production(authority).record_fs_absent(body)
    def record_input_grant(authority, body): return production(authority).record_input_grant(body)
    def input_grants(authority): return production(authority).input_grants()
    def record_input_wa(authority, body): return production(authority).record_input_wa(body)
    def input_wa(authority): return production(authority).input_wa()
    def record_input_step(authority, action, path, kind, key, digest):
        return production(authority).record_input_step(action, path, kind, key, digest)
    def input_steps(authority): return production(authority).input_steps()
    def input_cleanup_token(authority): return production(authority).input_cleanup_token()
    def record_fs_intent(authority, body): return production(authority).record_fs_intent(body)
    def record_fs_observed(authority, body): return production(authority).record_fs_observed(body)
    def record_fs_settled(authority, body): return production(authority).record_fs_settled(body)
    def record_ssh_result(authority, serial, binding, manifest, stdout, canonical_result):
        return production(authority).record_ssh_result(serial, binding, manifest, stdout, canonical_result)
    def record_ssh_ready(authority): return production(authority).record_ssh_ready()
    def durable_phase(authority): return production(authority).durable_phase()
    def revoke_readiness(authority): return production(authority).revoke_readiness()
    def revoke_or_require_terminal(authority):
        authority = production(authority)
        if authority.durable_phase() == "UNCERTAIN": return
        return authority.revoke_readiness()
    def record_input_removed(authority, proof): return production(authority).record_input_removed(proof)
    def record_uncertain(authority, reason): return production(authority).record_uncertain(reason)
    def network_records(authority): return authority.network_records()
    def network_history(authority): return authority.network_history()
    def record_network(authority, kind, body): return authority.record_network(kind, body)
    def settle_network_phase(authority, kind): return authority.settle_network_phase(kind)
    return (
        _open_fixed_operation, create_fixed_operation_test_local, claim_rootfs_reopen,
        invoke_rootfs_reopen_route, settle_rootfs_reopen, claim_rootfs_release,
        invoke_rootfs_release, settle_rootfs_release, make_fake_lifecycle,
        admit_production_v2, claim_production_operation, command_context, pending_command, has_recovery_command,
        recovery_command, recovery_lifecycle_deadline,
        record_command_intent,
        record_command_preexec, record_command_output, record_command_outcome, record_daemon_retained,
        record_daemon_outcome, durable_command_outcome, durable_command_output,
        record_runtime_mount_v2, pending_fs_intent, record_fs_absent,
        record_input_grant, input_grants, record_input_wa, input_wa, record_input_step, input_steps,
        input_cleanup_token, record_fs_intent, record_fs_observed,
        record_fs_settled, record_ssh_result, record_ssh_ready, durable_phase,
        revoke_readiness, revoke_or_require_terminal, record_input_removed, record_uncertain,
        network_records, network_history, record_network, settle_network_phase,
    )
(
    _open_fixed_operation, _create_fixed_operation_test_local, _claim_rootfs_reopen,
    _invoke_rootfs_reopen_route, _settle_rootfs_reopen, _claim_rootfs_release,
    _invoke_rootfs_release, _settle_rootfs_release, _make_fake_lifecycle_for_tests,
    _admit_production_v2, _claim_production_operation, _command_context, _pending_command, _has_recovery_command,
    _recovery_command, _recovery_lifecycle_deadline,
    _record_command_intent,
    _record_command_preexec, _record_command_output, _record_command_outcome, _record_daemon_retained,
    _record_daemon_outcome, _durable_command_outcome, _durable_command_output,
    _record_runtime_mount_body_v2, _pending_fs_intent, _record_fs_absent,
    _record_input_grant, _input_grants, _record_input_wa, _input_wa, _record_input_step, _input_steps,
    _input_cleanup_token, _record_fs_intent, _record_fs_observed,
    _record_fs_settled, _record_ssh_result,
    _record_ssh_ready, _durable_phase, _revoke_readiness, _revoke_or_require_terminal,
    _record_input_removed, _record_uncertain,
    _network_records, _network_history, _record_network, _settle_network_phase,
) = _make_authority()
del _make_authority


def _runtime_mount_issuance_routes(record_body):
    issued = owner_helpers.Registry("RuntimeMountIssuance", OperationError)
    RuntimeMountIssuance = issued.kind
    def issue(authority, runtime_grant):
        import completion_kata_inputs as inputs
        import completion_kata_runtime as runtime
        authority = _claim_production_operation(authority)
        context = _command_context(authority)
        mounted_input, control = runtime._claim_runtime_mount_grant(
            runtime_grant, context.operation_token)
        _fail(type(mounted_input) is fs.HeldNode and type(control) is fs.OperationControl)
        _fail(mounted_input.generation.key.kind == "directory"
              and mounted_input.generation.uid == mounted_input.generation.gid == 0)
        rows = [row for row in _input_steps(authority)
                if (row["action"], row["path"]) == ("create", "@manifest")]
        _fail(len(rows) == 1 and rows[0]["sha256"] is not None)
        manifest = fs._open_path_node(mounted_input, inputs.MANIFEST_NAME, "file", control)
        try:
            raw = fs._read_regular(manifest, inputs.MAX_MANIFEST, control)
            _fail(hashlib.sha256(raw).hexdigest() == rows[0]["sha256"])
        finally: fs._close_node(manifest)
        return issued.issue([
            authority, rows[0]["sha256"],
            _generation_value(mounted_input.generation), False,
        ])
    def record(authority, issuance):
        authority = _claim_production_operation(authority)
        state = issued.require(issuance)
        _fail(state[0] is authority and not state[3])
        state[3] = True
        return record_body(authority, state[1], state[2])
    return RuntimeMountIssuance, issue, record


(RuntimeMountIssuance, _issue_runtime_mount_v2,
 _record_runtime_mount_v2) = _runtime_mount_issuance_routes(_record_runtime_mount_body_v2)
del _runtime_mount_issuance_routes, _record_runtime_mount_body_v2

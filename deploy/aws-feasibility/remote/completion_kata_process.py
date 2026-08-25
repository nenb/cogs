"""Private fixed process-transaction primitive for Stage 2 Kata.

This slice implements exact journaled fork/session/exec, settlement, and crash
recovery. It does not expose a production command issuer or lifecycle owner;
parsing a contract therefore grants no execution authority. Tests exercise the
private primitive with a fixed harmless executable descriptor.

"""
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import select
import selectors
import signal
import stat
import struct
import time
import completion_kata_actions as actions
import completion_kata_admission as admission
import completion_kata_command_policy as command_policy
import completion_kata_fdmap as fdmap
import completion_kata_network as kata_network
import completion_kata_operation as kata_operation
import completion_kata_owner as owner_helpers
import completion_kata_runtime as kata_runtime
import completion_kata_ssh as kata_ssh
import completion_guest_readiness_v1 as guest_readiness

_install_attested_policy = command_policy._take_attested_policy_inserter()
_install_v2_attested_policy = command_policy._take_v2_attested_policy_inserter()
CONTRACT_VERSION = "cogs.stage2-kata-tool-closure/v1"
TEST_PATH = "/tmp/cogs-kata-process-s1-v1/helper"
MAX_STREAM = 65_536
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
STATUS_SIZE = 4
SETUP_SIZE = 32
UINT_MAX = (1 << 32) - 1
ZERO = "0" * 64
HEX = frozenset("0123456789abcdef")
SONAME = re.compile(r"(?:lib[A-Za-z0-9_+.-]+|ld-[A-Za-z0-9_+.-]+)\.so(?:\.[0-9]+)*")
FORBIDDEN_TAGS = frozenset({"RPATH", "RUNPATH", "AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY", "CONFIG"})
DEADLINE_SECONDS = {
    "observer": 5, "network": 10, "keygen": 15, "runtime-start": 60,
    "task-term": 15, "task-kill": 10, "remove": 20, "listener": 60,
    "ssh": command_policy.SSH_TOTAL_NS / 1_000_000_000, "runtime-absence": 30,
}
CLOCK = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)
FIXED_ENV = kata_operation.FIXED_ENV
CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_BASE = CGROUP_ROOT + "/cogs-stage2-completion-v1"
CGROUP2_MAGIC = 0x63677270
HOSTILE_ROOT_LIMITATION = (
    "cgroup-v2 owns ordinary descendants; a hostile host-root process can escape "
    "without a later namespace/capability boundary"
)


class ProcessError(Exception):
    """A closed command could not be safely supervised."""


CommandId = actions.CommandId
COMMAND_IDS = actions.COMMAND_IDS | {"TEST_HELPER"}


class _TestAction(Enum):
    OK = "ok"
    STDERR = "stderr"
    EXIT7 = "exit7"
    FLOOD = "flood"
    DUAL_FLOOD = "dual-flood"
    SLEEP = "sleep"
    HELD_PIPE = "held-pipe"
    FD = "fd"
    HIGH_FD = "high-fd"
    INHERITED = "inherited"


class ObservationKind(Enum):
    EXACT = "exact"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class _Spec:
    command_id: str
    argv: tuple
    stdin: bytes
    deadline_class: str
    deadline_seconds: float
    inherited_fds: tuple = ()


@dataclass(frozen=True)
class _UnissuedSpec:
    command_id: str
    tool_contract: str
    argv_tail: tuple
    stdin: bytes
    deadline_class: str


@dataclass(frozen=True)
class _Artifact:
    role: str
    logical_path: str
    soname: object
    size: int
    sha256: str


@dataclass(frozen=True)
class _Contract:
    command_id: str
    executable: _Artifact
    loader: object
    libraries: tuple
    dynamic_tags: tuple
    closure_sha256: str


@dataclass(frozen=True)
class FixedCommand:
    command_id: CommandId
    executable_role: str
    executable_path: str
    argv: tuple
    stdin: bytes
    duration_ns: int
    stdout_limit: int = MAX_STREAM
    stderr_limit: int = MAX_STREAM
    output_grammar: str = "text"
    inherited_fds: tuple = ()


@dataclass(frozen=True)
class LongLivedCommand:
    command_id: CommandId
    executable_role: str
    executable_path: str
    argv: tuple


@dataclass(frozen=True)
class RetainedExecutable:
    role: str
    path: str
    descriptor: int
    sha256: str
    closure_sha256: str
    generation: dict
    closure_descriptors: tuple = ()


def _attested_executable_routes(install_policy):
    states = owner_helpers.Registry(
        "AttestedExecutableOwner", ProcessError,
        "exact unused attested executable required",
        sealed_message="attested executable owner is sealed")
    AttestedExecutableOwner = states.kind
    claimed, released = set(), set()
    def admitted_role(state, role):
        custody = state.get("__static_custody__")
        if custody is None or role in state:
            return
        claim_value = admission._claim_executable_role_custody(custody, role)
        objects = admission._consume_executable_role_custody(custody, claim_value, role)
        if (type(objects) is not tuple or not objects or objects[0].kind != "executable"
                or any(type(item) is not admission.RetainedObject or item.role != role
                       for item in objects)):
            raise ProcessError("admitted executable closure required")
        descriptors = []
        try:
            for item in objects:
                descriptor = os.dup(item.descriptor)
                os.set_inheritable(descriptor, False)
                descriptors.append(descriptor)
            executable = objects[0]
            closure = hashlib.sha256(kata_operation._canonical([{
                "kind": item.kind, "path": item.path, "sha256": item.sha256,
                "size": item.size, "interpreter": item.interpreter,
                "soname": item.soname, "needed": list(item.needed),
            } for item in objects])).hexdigest()
            retained = RetainedExecutable(
                role, executable.path, descriptors[0], executable.sha256, closure,
                _host_generation(descriptors[0]), tuple(descriptors[1:]))
            if role in {"ssh", "ssh-keygen"}:
                command_ids = (command_policy.SSH_COMMANDS if role == "ssh" else command_policy.KEY_COMMAND_ORDER)
                install_policy(command_ids, {
                    "executable_sha256": retained.sha256,
                    "tool_closure_sha256": retained.closure_sha256,
                    "executable_path": retained.path,
                    "contract_version": CONTRACT_VERSION,
                }, command_policy.REVIEWED_HOST_TOOL_CONTRACTS)
            state[role] = [retained, False]
        except BaseException:
            for descriptor in descriptors:
                try: os.close(descriptor)
                except OSError: pass
            raise
    def claim(owner, role):
        state = states.require(owner)
        admitted_role(state, role)
        if role not in state or state[role][1]:
            raise ProcessError("exact unused attested executable required")
        retained = state[role][0]
        if type(retained) is not RetainedExecutable:
            raise ProcessError("invalid retained executable state")
        state[role][1] = True
        claimed.add(id(retained))
        return retained
    def require(retained):
        if (type(retained) is not RetainedExecutable or id(retained) not in claimed
                or id(retained) in released):
            raise ProcessError("attestation-issued retained executable required")
        return retained
    def release(retained):
        require(retained); released.add(id(retained))
        errors = []
        for descriptor in (retained.descriptor, *retained.closure_descriptors):
            try: os.close(descriptor)
            except OSError as error: errors.append(error)
        if errors: raise BaseExceptionGroup("attested descriptor release", errors)
    def issue(reviewed):
        synthetic_v1 = reviewed is command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS
        synthetic_v3 = reviewed is command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3
        synthetic = synthetic_v1 or synthetic_v3
        if not (reviewed is command_policy.REVIEWED_HOST_TOOL_CONTRACTS or synthetic) or not reviewed:
            raise ProcessError("exact committed host-tool contracts unavailable")
        if any(name in command_policy.ATTESTED_EXECUTABLES for name in command_policy.ATTESTED_COMMANDS):
            raise ProcessError("host-tool policy already issued")
        values, policies, owned = {}, {}, []
        try:
            for role, expected_ids, path in (
                ("ssh", command_policy.SSH_COMMANDS, "/usr/bin/ssh"),
                ("ssh-keygen", command_policy.KEY_COMMAND_ORDER, "/usr/bin/ssh-keygen"),
            ):
                descriptor = reviewed.get(role)
                if (type(descriptor) is not MappingProxyType or set(descriptor) != {
                        "contract_path", "contract_sha256"}):
                    raise ProcessError("invalid committed host-tool descriptor")
                contract_fd = os.open(descriptor["contract_path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    status = os.fstat(contract_fd)
                    expected_uid = os.geteuid() if synthetic else 0
                    if not stat.S_ISREG(status.st_mode) or status.st_uid != expected_uid or status.st_nlink != 1:
                        raise ProcessError("host-tool contract identity mismatch")
                    raw = os.read(contract_fd, 262_145)
                finally: os.close(contract_fd)
                contract = _parse_contract(raw, descriptor["contract_sha256"])
                source_path = ("/tmp/cogs-stage2-attested-static-v3.elf" if synthetic_v3 else
                               "/tmp/cogs-stage2-attested-static-v1.elf" if synthetic_v1 else path)
                if (contract.command_id not in expected_ids
                        or contract.executable.logical_path != source_path
                        or contract.loader is not None or contract.libraries):
                    raise ProcessError("host-tool contract role/static-closure mismatch")
                executable_fd = _sealed_memfd(contract.executable, True); owned.append(executable_fd)
                closure_fds = tuple(_sealed_memfd(item) for item in
                                    ((() if contract.loader is None else (contract.loader,)) + contract.libraries))
                owned.extend(closure_fds)
                retained = RetainedExecutable(role, path, executable_fd, contract.executable.sha256,
                                              contract.closure_sha256, _host_generation(executable_fd),
                                              closure_fds)
                policy_value = {"executable_sha256": retained.sha256,
                                "tool_closure_sha256": retained.closure_sha256,
                                "executable_path": retained.path,
                                "contract_version": CONTRACT_VERSION}
                policies[expected_ids] = policy_value
                values[role] = [retained, False]
            for command_ids, policy_value in policies.items():
                install_policy(command_ids, policy_value, reviewed)
            return states.issue(values)
        except BaseException:
            for descriptor in reversed(owned):
                try: os.close(descriptor)
                except OSError: pass
            raise
    def issue_retained(retained):
        expected = admission.EXECUTABLES
        if type(retained) is not tuple or len(retained) != len(expected):
            raise ProcessError("complete fixed retained executable set required")
        values = {}
        descriptors = set()
        policies = []
        for value, (role, _source_class, path) in zip(retained, expected, strict=True):
            if (type(value) is not RetainedExecutable or (value.role, value.path) != (role, path)
                    or type(value.closure_descriptors) is not tuple):
                raise ProcessError("retained executable role set differs")
            current = (value.descriptor, *value.closure_descriptors)
            if (any(type(descriptor) is not int or descriptor < 0 for descriptor in current)
                    or descriptors & set(current)):
                raise ProcessError("retained executable descriptors alias")
            descriptors.update(current)
            observed = fdmap.identity(value.descriptor)
            if (_host_generation(value.descriptor) != value.generation
                    or _digest_fd(value.descriptor, observed.size) != value.sha256
                    or fdmap.identity(value.descriptor) != observed):
                raise ProcessError("retained executable changed before ownership")
            values[role] = [value, False]
            command_ids = (command_policy.SSH_COMMANDS if role == "ssh" else
                           command_policy.KEY_COMMAND_ORDER if role == "ssh-keygen" else ())
            if command_ids:
                policies.append((command_ids, {
                    "executable_sha256": value.sha256,
                    "tool_closure_sha256": value.closure_sha256,
                    "executable_path": value.path,
                    "contract_version": command_policy.HOST_TOOL_CONTRACT_VERSION,
                }))
        if any(name in command_policy.ATTESTED_EXECUTABLES for name in command_policy.ATTESTED_COMMANDS):
            raise ProcessError("attested executable policy already issued")
        for command_ids, policy_value in policies:
            _install_v2_attested_policy(command_ids, policy_value)
        return states.issue(values)
    def abort_owner(owner):
        state = states.pop(owner)
        errors = []
        for retained, _consumed in state.values():
            if id(retained) in released:
                continue
            released.add(id(retained))
            for descriptor in (retained.descriptor, *retained.closure_descriptors):
                try: os.close(descriptor)
                except OSError as error: errors.append(error)
        if errors:
            raise BaseExceptionGroup("attested executable owner abort", errors)
    def open_fixed(custody, custody_qualification):
        admission._consume_custody_qualification(custody, custody_qualification)
        return issue(command_policy.REVIEWED_HOST_TOOL_CONTRACTS)
    def open_static(custody):
        admission._static_custody_binding(custody)
        return states.issue({"__static_custody__": custody})
    def open_synthetic():
        if os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V1") != "1":
            raise ProcessError("synthetic attestation test admission absent")
        return issue(command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS)
    def open_synthetic_v3():
        if os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V3") != "1":
            raise ProcessError("V3 synthetic attestation test admission absent")
        return issue(command_policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3)
    return (AttestedExecutableOwner, claim, require, release, issue, issue_retained,
            abort_owner, open_fixed, open_static, open_synthetic, open_synthetic_v3)


(AttestedExecutableOwner, _claim_attested_executable, _require_attested_executable,
 _release_attested_executable, _issue_attested_executable_owner,
 _issue_retained_executable_owner, _abort_attested_executable_owner,
 _open_attested_executable_owner, _open_static_attested_executable_owner,
 _open_synthetic_attested_executable_owner_for_tests,
 _open_synthetic_attested_executable_owner_v3_for_tests) = _attested_executable_routes(
     _install_attested_policy)
del _attested_executable_routes, _install_attested_policy


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    pgid: int
    sid: int
    starttime: int
    boot_id: str
    pidfd_supported: bool


@dataclass(frozen=True)
class RecoveryObservation:
    kind: ObservationKind
    row: object = None


@dataclass(frozen=True)
class ProcessOutcome:
    command_id: str
    identity: ProcessIdentity
    outcome: str
    status: object
    errno: object
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    leader_timed_out: bool
    pipe_timed_out: bool
    reaped: bool
    errors: tuple


CONTAINERD_SOCKET, CONTAINERD_ROOT, CONTAINERD_STATE = command_policy.CONTAINERD_ADDRESS, command_policy.CONTAINERD_ROOT, command_policy.CONTAINERD_STATE
CONTAINERD_TTRPC_SOCKET = CONTAINERD_SOCKET + ".ttrpc"
CONTAINERD_CONFIG = kata_operation.BASE + "/kata-runtime-v1/containerd.toml"
STAGED_CONTAINERD = kata_operation.BASE + "/kata-runtime-v1/bin/containerd"
STAGED_CTR = kata_operation.BASE + "/kata-runtime-v1/bin/ctr"
LONG_LIVED_CONTAINERD = LongLivedCommand(
    CommandId.CONTAINERD_START, "containerd", "/usr/bin/containerd",
    ("/usr/bin/containerd", "--address", kata_operation.BASE + "/kata-runtime-v1/containerd.sock", "--root", kata_operation.BASE + "/kata-runtime-v1/containerd-root", "--state", kata_operation.BASE + "/kata-runtime-v1/containerd-state", "--config", CONTAINERD_CONFIG),
)


def _compose_fixed_commands():
    rows = {}
    paths = {"ip": "/usr/sbin/ip", "tc": "/usr/sbin/tc", "nft": "/usr/sbin/nft"}
    for command_id in actions.NETWORK_COMMANDS:
        try:
            source = kata_network.command(command_id)
        except kata_network.NetworkError:
            continue
        role = "nft" if source.tool_contract.startswith("libnftables") else \
            "ip" if source.tool_contract.startswith("iproute2") else \
            source.tool_contract.split("-", 1)[0]
        path = paths[role]
        rows[command_id] = FixedCommand(
            command_id, role, path, (path, *source.argv_tail), source.stdin,
            10_000_000_000, output_grammar="json" if "json" in source.tool_contract else "text",
        )
    for source in kata_runtime.fixed_command_specs_for_tests():
        argv = ("/usr/bin/ctr", "--address", kata_operation.BASE + "/kata-runtime-v1/containerd.sock", *source.argv[1:])
        rows[source.command_id] = FixedCommand(
            source.command_id, "ctr", "/usr/bin/ctr", argv, source.stdin,
            int(DEADLINE_SECONDS[source.deadline_class] * 1_000_000_000),
        )
    for name, argv in command_policy.KEY_COMMANDS.items():
        command_id = CommandId[name]
        rows[command_id] = FixedCommand(
            command_id, "ssh-keygen", "/usr/bin/ssh-keygen", argv, b"",
            15_000_000_000, 1024 if name.startswith("SSH_PUBLIC_") else 0,
            4096, "text", (),
        )
    source = kata_ssh.command_spec()
    rows[CommandId.SSH_READY] = FixedCommand(
        CommandId.SSH_READY, "ssh", "/usr/bin/ssh", source.argv, source.stdin,
        command_policy.SSH_TOTAL_NS, 4096, 4096, "ssh-plan", source.inherited_fds,
    )
    rows[CommandId.SSH_READINESS] = FixedCommand(
        CommandId.SSH_READINESS, "ssh", "/usr/bin/ssh", source.argv,
        guest_readiness.guest_program_bytes(), command_policy.SSH_TOTAL_NS,
        guest_readiness.GUEST_OUTPUT_LIMIT, 4096, "ssh-plan", source.inherited_fds,
    )
    return rows


_FIXED_COMMANDS = _compose_fixed_commands()
_RUNTIME_EXTENSIONS = {}
def _bind_ctr_extension(command_id):
    source = next(item for item in kata_runtime.fixed_command_specs_v2() if item.command_id is command_id)
    fixed = FixedCommand(command_id, "ctr", STAGED_CTR, source.argv, source.stdin,
        int(DEADLINE_SECONDS[source.deadline_class] * 1_000_000_000), output_grammar="text")
    _RUNTIME_EXTENSIONS[id(fixed)] = fixed; return fixed

def _bind_ctr_run_extension(rootfs_token):
    fixed = FixedCommand(CommandId.CTR_RUN, "ctr", STAGED_CTR,
        kata_operation.command_policy.ctr_run_argv(rootfs_token), b"", 60_000_000_000,
        output_grammar="text"); _RUNTIME_EXTENSIONS[id(fixed)] = fixed; return fixed
def _bind_containerd_extension():
    fixed = FixedCommand(CommandId.CONTAINERD_START, "containerd", STAGED_CONTAINERD,
        (STAGED_CONTAINERD, "--address", CONTAINERD_SOCKET, "--root", CONTAINERD_ROOT,
         "--state", CONTAINERD_STATE, "--config", CONTAINERD_CONFIG), b"", 60_000_000_000, output_grammar="empty")
    _RUNTIME_EXTENSIONS[id(fixed)] = fixed; return fixed
PROCESS_OWNED_IDS = frozenset(_FIXED_COMMANDS)
OWNER_ASSIGNED_IDS = actions.COMMAND_IDS - {item.value for item in PROCESS_OWNED_IDS} - {
    CommandId.CONTAINERD_START.value,
}


NFT_INPUT = b'''add table inet cogs_stage2_ssh_v1
add chain inet cogs_stage2_ssh_v1 input { type filter hook input priority filter; policy accept; }
add chain inet cogs_stage2_ssh_v1 output { type filter hook output priority filter; policy accept; }
add chain inet cogs_stage2_ssh_v1 forward { type filter hook forward priority filter; policy accept; }
add rule inet cogs_stage2_ssh_v1 output oifname "c42h0" ip saddr 192.0.2.1 ip daddr 192.0.2.2 tcp dport 22 ct state new,established accept
add rule inet cogs_stage2_ssh_v1 output oifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 input iifname "c42h0" ip saddr 192.0.2.2 ip daddr 192.0.2.1 tcp sport 22 ct state established accept
add rule inet cogs_stage2_ssh_v1 input iifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 forward iifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop
'''


def _spec(command_id):
    """Historical immutable snapshot API; never execution authority."""
    if type(command_id) is not CommandId:
        raise ProcessError("closed command id required")
    source = _FIXED_COMMANDS.get(command_id)
    if source is None:
        raise ProcessError("fixed action belongs to its lifecycle owner")
    seconds = source.duration_ns / 1_000_000_000
    if command_id in {CommandId.SSH_READY, CommandId.SSH_READINESS}:
        deadline_class = "ssh"
    elif command_id in {CommandId.SSH_KEYGEN_CLIENT, CommandId.SSH_KEYGEN_SERVER,
                        CommandId.SSH_PUBLIC_CLIENT, CommandId.SSH_PUBLIC_SERVER}:
        deadline_class = "keygen"
    elif command_id in {
        CommandId.CTR_CONTAINER_INFO, CommandId.CTR_CONTAINER_LIST,
        CommandId.CTR_TASK_LIST,
    }:
        deadline_class = "observer"
    elif command_id is CommandId.CTR_TASK_TERM:
        deadline_class = "task-term"
    elif command_id is CommandId.CTR_TASK_KILL:
        deadline_class = "task-kill"
    elif command_id in {CommandId.CTR_TASK_REMOVE, CommandId.CTR_CONTAINER_REMOVE}:
        deadline_class = "remove"
    else:
        deadline_class = "network"
    return _Spec(
        command_id.value, source.argv, source.stdin, deadline_class, seconds,
        source.inherited_fds,
    )

def _unissued_network_spec(command_id):
    """Historical wrapper over the authoritative fixed network command table."""
    if type(command_id) is not CommandId: raise ProcessError("closed unissued action required")
    try: source = kata_network.command(kata_network.Action(command_id.value))
    except (ValueError, kata_network.NetworkError) as error:
        raise ProcessError("closed unissued action required") from error
    tool = "nft" if source.tool_contract.startswith("libnftables") else "ip"
    return _UnissuedSpec(command_id.value, tool, source.argv_tail, source.stdin, "network")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _exact_keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ProcessError("noncanonical contract shape")


def _artifact(value, role):
    _exact_keys(value, ("logical_path", "role", "sha256", "size", "soname"))
    path = value["logical_path"]
    digest = value["sha256"]
    size = value["size"]
    soname = value["soname"]
    if value["role"] != role or type(path) is not str or not path.startswith("/") or "//" in path or "/../" in path:
        raise ProcessError("invalid artifact identity")
    if (not path.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in path)
            or os.path.normpath(path) != path):
        raise ProcessError("invalid artifact path")
    if type(size) is not int or isinstance(size, bool) or not 1 <= size <= 128 * 1024 * 1024:
        raise ProcessError("invalid artifact size")
    if type(digest) is not str or len(digest) != 64 or not set(digest) <= HEX or digest == ZERO:
        raise ProcessError("invalid artifact digest")
    if role == "library":
        if (type(soname) is not str or len(soname) > 255 or not soname.isascii()
                or ".." in soname or SONAME.fullmatch(soname) is None):
            raise ProcessError("invalid SONAME")
    elif soname is not None:
        raise ProcessError("unexpected SONAME")
    return _Artifact(role, path, soname, size, digest)


def _parse_contract(raw, expected_sha256):
    """Normalize every untrusted contract failure to ProcessError."""
    try:
        return _parse_contract_checked(raw, expected_sha256)
    except ProcessError:
        raise
    except (UnicodeError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as error:
        raise ProcessError("invalid contract") from error


def _parse_contract_checked(raw, expected_sha256):
    if type(raw) is not bytes or len(raw) > 262_144 or not raw.endswith(b"\n"):
        raise ProcessError("invalid contract bytes")
    if type(expected_sha256) is not str or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ProcessError("unbound contract")
    try:
        value = json.loads(raw, object_pairs_hook=lambda pairs: _unique_pairs(pairs))
    except (UnicodeError, ValueError, TypeError) as error:
        raise ProcessError("invalid contract JSON") from error
    if raw != _canonical(value):
        raise ProcessError("noncanonical contract")
    _exact_keys(value, ("architecture", "closure_sha256", "command_id", "dynamic_tags", "executable", "libraries", "loader", "version"))
    if value["version"] != CONTRACT_VERSION or value["architecture"] != "x86_64":
        raise ProcessError("unsupported tool contract")
    command_id = value["command_id"]
    if type(command_id) is not str or command_id not in COMMAND_IDS:
        raise ProcessError("invalid command id")
    tags = value["dynamic_tags"]
    if (type(tags) is not list or any(type(tag) is not str for tag in tags)
            or tags != sorted(set(tags)) or any(tag in FORBIDDEN_TAGS for tag in tags)):
        raise ProcessError("forbidden dynamic metadata")
    executable = _artifact(value["executable"], "executable")
    loader = None if value["loader"] is None else _artifact(value["loader"], "loader")
    libraries_value = value["libraries"]
    if type(libraries_value) is not list or len(libraries_value) > 128:
        raise ProcessError("invalid library closure")
    libraries = tuple(_artifact(item, "library") for item in libraries_value)
    if tuple(item.soname for item in libraries) != tuple(sorted(set(item.soname for item in libraries))):
        raise ProcessError("noncanonical library closure")
    if (loader is None) != (not libraries):
        raise ProcessError("incomplete loader closure")
    if sum(item.size for item in (executable,) + (() if loader is None else (loader,)) + libraries) > MAX_ARTIFACT_BYTES:
        raise ProcessError("artifact closure too large")
    closure_body = {name: value[name] for name in value if name != "closure_sha256"}
    closure_sha = hashlib.sha256(_canonical(closure_body)).hexdigest()
    if type(value["closure_sha256"]) is not str or value["closure_sha256"] != closure_sha:
        raise ProcessError("closure digest mismatch")
    return _Contract(command_id, executable, loader, libraries, tuple(tags), closure_sha)


def _unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if type(name) is not str or name in result:
            raise ProcessError("duplicate contract key")
        result[name] = value
    return result


def _read_exact_source(artifact):
    descriptor = os.open(artifact.logical_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != artifact.size:
            raise ProcessError("artifact identity mismatch")
        digest = hashlib.sha256()
        chunks = []
        total = 0
        while total < artifact.size:
            chunk = os.read(descriptor, min(1_048_576, artifact.size - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if total != artifact.size or digest.hexdigest() != artifact.sha256 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ProcessError("artifact changed while binding")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sealed_memfd(artifact, executable=False):
    if not hasattr(os, "memfd_create"):
        raise ProcessError("sealed memfd is unavailable")
    raw = _read_exact_source(artifact)
    descriptor = os.memfd_create("cogs-kata-tool-v1", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        os.fchmod(descriptor, 0o500 if executable else 0o400)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0:
                raise ProcessError("short memfd write")
            offset += count
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        rebound = b""
        while len(rebound) < len(raw):
            part = os.read(descriptor, min(1_048_576, len(raw) - len(rebound)))
            if not part:
                break
            rebound += part
        if hashlib.sha256(rebound).hexdigest() != artifact.sha256:
            raise ProcessError("memfd verification failed")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals:
            raise ProcessError("memfd sealing failed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _canonical_boot_id(value):
    return (type(value) is str and len(value) == 36
            and tuple(index for index, char in enumerate(value) if char == "-") == (8, 13, 18, 23)
            and all(char in HEX for char in value.replace("-", "")))


def _boot_id():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        value = source.read()
    if not value.endswith("\n") or not _canonical_boot_id(value[:-1]):
        raise ProcessError("invalid boot id")
    return value[:-1]


def _proc_row(pid):
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as source:
        raw = source.read(4096)
    close = raw.rfind(b")")
    fields = raw[close + 2:].split()
    if close < 2 or len(fields) < 20 or int(raw[:raw.find(b" ")]) != pid:
        raise ProcessError("invalid proc stat")
    return (pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))


def _identity(pid, reported):
    row = _proc_row(pid)
    expected = (pid, os.getpid(), pid, pid)
    if reported != expected or row[:4] != expected:
        raise ProcessError("PID/PPID/PGID/SID mismatch")
    pidfd = None
    supported = hasattr(os, "pidfd_open")
    if supported:
        try:
            pidfd = os.pidfd_open(pid, 0)
        except OSError as error:
            if error.errno not in {errno.ENOSYS, errno.EINVAL}:
                raise
            supported = False
    return ProcessIdentity(*row, _boot_id(), supported), pidfd


def _close_range(first, last):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise OSError(errno.ENOSYS, "close_range requires Linux amd64")
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(436, ctypes.c_uint(first), ctypes.c_uint(last), ctypes.c_uint(0))
    if result != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))


def _close_except(allowed):
    kept = sorted(allowed)
    if any(type(fd) is not int or not 0 <= fd <= UINT_MAX for fd in kept):
        raise OSError(errno.EINVAL, "invalid child descriptor allowlist")
    cursor = 0
    for descriptor in kept:
        if cursor < descriptor:
            _close_range(cursor, descriptor - 1)
        cursor = descriptor + 1
    if cursor <= UINT_MAX:
        _close_range(cursor, UINT_MAX)


_fd_identity = fdmap.identity
_seal_inherited_inputs_for_tests = fdmap.bind_inputs
_install_inherited_fds = fdmap.install
_relocate_child_internals = fdmap.relocate_internals
def _claim_inherited_fds(spec, owner):
    try:
        if spec.inherited_fds == () and owner == ():
            return ()
        if type(owner) is fdmap._ClaimedProductionInputs:
            return fdmap._consume_production_inputs(spec.inherited_fds, owner)
        if type(owner) is fdmap._ClaimedNftWriterLock:
            return fdmap._consume_nft_writer_lock(spec.inherited_fds, owner)
        return fdmap.claim(spec.inherited_fds, owner)
    except fdmap.FdMapError as error:
        raise ProcessError("invalid inherited descriptor map") from error


def _write_child_error(descriptor, value):
    try:
        os.write(descriptor, struct.pack("!I", min(max(int(value), 1), 65535)))
    except BaseException:
        pass


def _execveat(descriptor, argv):
    libc = ctypes.CDLL(None, use_errno=True)
    encoded = [item.encode("utf-8") for item in argv]
    arguments = (ctypes.c_char_p * (len(encoded) + 1))(*encoded, None)
    encoded_environment = [f"{name}={value}".encode("ascii") for name, value in FIXED_ENV]
    environment = (ctypes.c_char_p * (len(encoded_environment) + 1))(
        *encoded_environment, None,
    )
    result = libc.syscall(322, descriptor, b"", arguments, environment, 0x1000)
    saved = ctypes.get_errno()
    if result != 0:
        raise OSError(saved, os.strerror(saved))


def _child(executable_fd, spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r, network_fd=None):
    try:
        internal = (executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r,
                    *((network_fd,) if network_fd is not None else ()))
        relocated = _relocate_child_internals(internal)
        executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r = relocated[:7]
        if network_fd is not None: network_fd = relocated[7]
        os.setsid()
        if spec.inherited_fds:
            _install_inherited_fds(spec.inherited_fds)
        report = struct.pack("!QQQQ", os.getpid(), os.getppid(), os.getpgrp(), os.getsid(0))
        os.write(setup_w, report)
        os.dup2(stdin_r, 0)
        os.dup2(stdout_w, 1)
        os.dup2(stderr_w, 2)
        os.dup2(status_w, 3, inheritable=False)
        os.dup2(executable_fd, 198, inheritable=False)
        status_w = 3
        executable_fd = 198
        allowed = {0, 1, 2, 3, 198, release_r, *(() if network_fd is None else (network_fd,)),
                   *(row.target_fd for row in spec.inherited_fds)}
        _close_except(allowed)
        if os.read(release_r, 1) != b"R":
            os._exit(125)
        argv = spec.argv
        if network_fd is not None:
            if network_fd != kata_runtime.CTR_NS_FD:
                os.dup2(network_fd, kata_runtime.CTR_NS_FD, inheritable=True); os.close(network_fd)
            else: os.set_inheritable(network_fd, True)
            argv = tuple(item.replace("{ctr-child-pid}", str(os.getpid())) for item in argv)
        _execveat(executable_fd, argv)
    except OSError as error:
        _write_child_error(status_w, error.errno or errno.EIO)
    except BaseException:
        _write_child_error(status_w, errno.EIO)
    os._exit(126)


def _read_setup_until(descriptor, remaining):
    raw = b""
    while len(raw) < SETUP_SIZE:
        timeout = remaining()
        if timeout <= 0 or not __import__("select").select([descriptor], [], [], timeout)[0]:
            raise ProcessError("child setup timeout")
        part = os.read(descriptor, SETUP_SIZE - len(raw))
        if not part: raise ProcessError("incomplete child setup")
        raw += part
    return struct.unpack("!QQQQ", raw)


def _read_setup(descriptor, deadline):
    """Historical wall-clock wrapper over the authoritative setup reader."""
    return _read_setup_until(descriptor, lambda: deadline - time.monotonic())


def _wait_nohang(pid, errors, label, deadline):
    while time.monotonic() < deadline:
        try:
            observed, status = os.waitpid(pid, os.WNOHANG)
            return (status, True) if observed == pid else (None, False)
        except OSError as error:
            if error.errno == errno.EINTR:
                errors.append(f"{label}:eintr")
                continue
            errors.append(f"{label}:{'echild' if error.errno == errno.ECHILD else error.errno}")
            return None, error.errno == errno.ECHILD
    errors.append(f"{label}:wait-deadline")
    return None, False


def _recovery_class(identity, observed_boot_id, observation):
    """Classify typed recovery evidence without inferring command effects."""
    if (type(identity) is not ProcessIdentity or not _canonical_boot_id(identity.boot_id)
            or not _canonical_boot_id(observed_boot_id) or type(observation) is not RecoveryObservation):
        raise ProcessError("invalid recovery observation")
    if observed_boot_id != identity.boot_id:
        return "recovery_absent"
    if observation.kind is ObservationKind.ABSENT and observation.row is None:
        return "recovery_absent"
    if observation.kind is ObservationKind.UNKNOWN and observation.row is None:
        return "uncertain"
    exact = (identity.pid, identity.ppid, identity.pgid, identity.sid, identity.starttime)
    if observation.kind is ObservationKind.EXACT:
        row = observation.row
        if type(row) is not tuple or len(row) != 5 or any(type(item) is not int or item < 0 for item in row):
            raise ProcessError("invalid recovery observation")
        return "exact_live" if row == exact else "uncertain"
    raise ProcessError("invalid recovery observation")


def _observe_proc(pid):
    try:
        return RecoveryObservation(ObservationKind.EXACT, _proc_row(pid))
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ESRCH}:
            return RecoveryObservation(ObservationKind.ABSENT)
        return RecoveryObservation(ObservationKind.UNKNOWN)
    except (ProcessError, ValueError):
        return RecoveryObservation(ObservationKind.UNKNOWN)


def _same_identity(identity):
    try:
        return _recovery_class(identity, _boot_id(), _observe_proc(identity.pid))
    except (OSError, ProcessError, ValueError):
        return "uncertain"


def _poll_reap(pid, wait_status, seconds, errors, label):
    if wait_status is not None:
        return wait_status, True
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        status, done = _wait_nohang(pid, errors, label, end)
        if done:
            return status, True
        time.sleep(min(0.01, max(0, end - time.monotonic())))
    errors.append(f"{label}:reap-timeout")
    return None, False


def _signal_pidfd_only(pid, sig, identity=None):
    descriptor = _usable_pidfd_open(pid)
    try:
        if identity is not None and _proc_row(pid)[4] != identity.starttime:
            raise ProcessError("pidfd identity mismatch")
        signal.pidfd_send_signal(descriptor, sig)
    finally:
        os.close(descriptor)


def _cleanup_child(pid, identity, wait_status, released):
    """Historical bounded helper; signaling is pidfd-only."""
    errors = []
    try:
        wait_status, done = _poll_reap(pid, wait_status, 0.1, errors, "cleanup-wait")
        if done:
            return wait_status, errors
        if not released or identity is None:
            try:
                _signal_pidfd_only(pid, signal.SIGKILL)
            except OSError as error:
                errors.append(f"direct-kill:{error.errno}")
        else:
            state = _same_identity(identity)
            if state == "exact_live":
                try:
                    _signal_pidfd_only(pid, signal.SIGTERM, identity)
                except OSError as error:
                    errors.append(f"term:{error.errno}")
            else:
                errors.append(f"identity-{state}-before-term")
            wait_status, done = _poll_reap(pid, wait_status, 2, errors, "term-wait")
            if done:
                return wait_status, errors
            state = _same_identity(identity)
            if state == "exact_live":
                try:
                    _signal_pidfd_only(pid, signal.SIGKILL, identity)
                except OSError as error:
                    errors.append(f"kill:{error.errno}")
            else:
                errors.append(f"identity-{state}-before-kill")
        wait_status, done = _poll_reap(pid, wait_status, 2, errors, "kill-wait")
        if not done:
            errors.append("child-unreaped")
        return wait_status, errors
    except BaseException as error:
        errors.append(f"cleanup-internal:{type(error).__name__}:{error}")
        return wait_status, errors


def _close_owned(descriptor, owned, errors, label="close"):
    try:
        os.close(descriptor)
    except OSError as error:
        errors.append(f"{label}:{error.errno}")
    finally:
        if descriptor in owned:
            owned.remove(descriptor)


@dataclass
class _CgroupOwner:
    path: str
    leaf_generation: tuple
    base_generation: tuple
    base_created: bool
    pidfds: dict
    directory_fd: object = None
    base_fd: object = None
    leaf_name: str = ""


@dataclass(frozen=True)
class _DaemonTransactionProfile:
    pid: int
    proc_row: tuple
    cgroup_path: str
    leaf_name: str
    leaf_generation: tuple
    base_generation: tuple
    runtime_leaf_name: object = None


def _boottime_ns():
    return time.clock_gettime_ns(CLOCK)


def _child_census():
    with open(f"/proc/self/task/{os.getpid()}/children", "rb", buffering=0) as source:
        raw = source.read(65_537)
    rows = raw.split()
    if (len(raw) > 65_536 or len(rows) > 256 or any(not row.isdigit() for row in rows)
            or len(rows) != len(set(rows))):
        raise ProcessError("invalid child baseline")
    return tuple(sorted(int(row) for row in rows))


def _require_no_children(profile=None):
    children = _child_census()
    if profile is None:
        if children:
            raise ProcessError("process owner has unrelated children")
        return
    if (type(profile) is not _DaemonTransactionProfile or children != (profile.pid,)
            or _proc_row(profile.pid) != profile.proc_row):
        raise ProcessError("daemon transaction child baseline differs")


def _host_generation(descriptor, kind=None):
    identity = fdmap.identity(descriptor)
    if identity.mount_id is None:
        raise ProcessError("fdinfo mount identity unavailable")
    if kind is None:
        kind = ("file" if stat.S_ISREG(identity.mode) else
                "pipe" if stat.S_ISFIFO(identity.mode) else
                "socket" if stat.S_ISSOCK(identity.mode) else "other")
    return {
        "mount_id": identity.mount_id, "device": identity.device, "inode": identity.inode,
        "kind": kind, "mode": identity.mode & 0o7777, "uid": identity.uid,
        "gid": identity.gid, "nlink": identity.nlink, "size": identity.size,
        "mtime_ns": identity.mtime_ns, "ctime_ns": identity.ctime_ns,
    }


def _digest_fd(descriptor, size):
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        part = os.pread(descriptor, min(1_048_576, size - offset), offset)
        if not part:
            raise ProcessError("short retained executable")
        digest.update(part)
        offset += len(part)
    return digest.hexdigest()


def _cleanup_reserve_ns(fixed):
    reviewed = (command_policy.SSH_CLEANUP_RESERVE_NS
                if fixed.command_id in {CommandId.SSH_READY, CommandId.SSH_READINESS}
                else command_policy.CLEANUP_RESERVE_NS)
    return min(reviewed, fixed.duration_ns // 2)


def _internally_fixed(fixed):
    if type(fixed) is not FixedCommand:
        return False
    canonical = _FIXED_COMMANDS.get(fixed.command_id)
    compared = (replace(fixed, inherited_fds=())
                if fixed.command_id is CommandId.NFT_REMOVE_ATOMIC
                and fixed.inherited_fds == (fdmap.NFT_WRITER_LOCK_FD,) else fixed)
    if canonical is not None and compared == canonical:
        return True
    netns = next((item for item in fixed.argv if type(item) is str and re.fullmatch(r"c42[qn][0-9a-f]{10}", item)), None)
    table = next((item for item in fixed.argv if type(item) is str and re.fullmatch(r"c42t[0-9a-f]{10}", item)), None)
    if table is None:
        match = re.search(rb"c42t[0-9a-f]{10}", fixed.stdin); table = None if match is None else match.group().decode()
    host = next((item for item in fixed.argv if type(item) is str and re.fullmatch(r"c42h[0-9a-f]{10}", item)), None)
    if host is None:
        match = re.search(rb"c42h[0-9a-f]{10}", fixed.stdin); host = None if match is None else match.group().decode()
    argv = tuple(kata_network.NETNS if item == netns else kata_network.TABLE if item == table else
                 kata_network.HOST_IF if item == host else item for item in fixed.argv)
    stdin = fixed.stdin.replace(table.encode(), kata_network.TABLE.encode()) if table else fixed.stdin
    if host: stdin = stdin.replace(host.encode(), kata_network.HOST_IF.encode())
    if canonical is not None and canonical == FixedCommand(canonical.command_id, canonical.executable_role,
            canonical.executable_path, argv, stdin, canonical.duration_ns, canonical.stdout_limit,
            canonical.stderr_limit, canonical.output_grammar, compared.inherited_fds):
        return True
    if (fixed.command_id not in {
            CommandId.TC_QDISC, CommandId.TC_INGRESS_FILTER}
            or fixed.executable_role != "tc" or fixed.executable_path != "/usr/sbin/tc"
            or fixed.stdin or fixed.duration_ns != 10_000_000_000
            or fixed.stdout_limit != MAX_STREAM or fixed.stderr_limit != MAX_STREAM
            or fixed.output_grammar != "json" or fixed.inherited_fds):
        return False
    prefix = ("/usr/sbin/tc", "-n", netns, "-j")
    tail = fixed.argv[len(prefix):]
    if fixed.argv[:len(prefix)] != prefix or len(tail) not in {4, 5}:
        return False
    expected = (("qdisc", "show", "dev", tail[3])
                if fixed.command_id is CommandId.TC_QDISC else
                ("filter", "show", "dev", tail[3], "ingress"))
    return tail == expected and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", tail[3]) is not None


def _intent_body(context, fixed, executable, bindings, deadline, runtime_fixed=False):
    if fixed.command_id in {CommandId.SSH_READY, CommandId.SSH_READINESS,
                            CommandId.SSH_KEYGEN_CLIENT,
                            CommandId.SSH_KEYGEN_SERVER, CommandId.SSH_PUBLIC_CLIENT,
                            CommandId.SSH_PUBLIC_SERVER}:
        _require_attested_executable(executable)
    runtime_extension = _RUNTIME_EXTENSIONS.get(id(fixed)) is fixed
    template = _FIXED_COMMANDS.get(fixed.command_id)
    if fixed.command_id in {CommandId[name] for name in command_policy.KEY_COMMANDS}:
        expected_argv = tuple(item.replace("{operation_token}", context.operation_token)
                              for item in template.argv)
        if fixed != replace(template, argv=expected_argv):
            raise ProcessError("command is not operation-derived fixed key policy")
    elif not (_internally_fixed(fixed) or runtime_extension or runtime_fixed):
        raise ProcessError("command is not internally fixed")
    if (type(executable) is not RetainedExecutable
            or (executable.role, executable.path) != (fixed.executable_role, fixed.executable_path)):
        raise ProcessError("retained executable role mismatch")
    observed = fdmap.identity(executable.descriptor)
    generation = _host_generation(executable.descriptor)
    if (generation != executable.generation
            or _digest_fd(executable.descriptor, observed.size) != executable.sha256
            or fdmap.identity(executable.descriptor) != observed):
        raise ProcessError("retained executable changed")
    environment = [list(row) for row in FIXED_ENV]
    inherited = []
    for row in fdmap.revalidate(bindings):
        inherited.append({
            "role": row.role, "target_fd": row.target_fd,
            "generation": _host_generation(row.source_fd),
            "content_sha256": row.content_sha256, "content_length": row.identity.size,
        })
    deadline_class = ("runtime-start" if fixed.command_id in {CommandId.CTR_RUN, CommandId.CONTAINERD_START}
                      else _spec(fixed.command_id).deadline_class)
    policy_version = (kata_operation.command_policy.RUNTIME_POLICY_VERSION if runtime_extension else
                      kata_operation.command_policy.POLICY_VERSION)
    body = {
        "operation_token": context.operation_token, "command_serial": context.command_serial,
        "command_id": fixed.command_id.value, "binding_sha256": ZERO,
        "journal_key": context.journal_key, "host_boot_id": context.host_boot_id,
        "source_revision": context.source_revision, "lifecycle_phase": context.lifecycle_phase,
        "executable_role": executable.role, "executable_path": executable.path,
        "executable_sha256": executable.sha256, "executable_generation": executable.generation,
        "tool_closure_sha256": executable.closure_sha256, "argv": list(fixed.argv),
        "argv_sha256": hashlib.sha256(kata_operation._canonical(list(fixed.argv))).hexdigest(),
        "stdin_hex": fixed.stdin.hex(), "stdin_sha256": hashlib.sha256(fixed.stdin).hexdigest(),
        "stdin_length": len(fixed.stdin), "environment": environment,
        "environment_sha256": hashlib.sha256(kata_operation._canonical(environment)).hexdigest(),
        "inherited_fds": inherited, "policy_version": policy_version,
        "deadline_class": deadline_class, "duration_ns": fixed.duration_ns,
        "cleanup_reserve_ns": _cleanup_reserve_ns(fixed),
        "deadline_boottime_ns": deadline,
        "output_grammar": fixed.output_grammar, "stdout_limit": fixed.stdout_limit,
        "stderr_limit": fixed.stderr_limit,
    }
    binding = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(kata_operation._canonical(binding)).hexdigest()
    kata_operation._validate_body("COMMAND_INTENT_V2", body)
    return body


def _generation_tuple(value):
    return tuple(value[name] for name in kata_operation.GEN_KEYS)


def _cgroup2_mount():
    with open("/proc/self/mountinfo", "rb", buffering=0) as source:
        raw = source.read(4_194_305)
    if len(raw) > 4_194_304 or not raw.endswith(b"\n"):
        raise ProcessError("bounded mountinfo unavailable")
    matches = []
    for line in raw.splitlines():
        fields = line.split()
        if b"-" not in fields:
            raise ProcessError("invalid mountinfo")
        separator = fields.index(b"-")
        if fields[4] == b"/sys/fs/cgroup":
            matches.append(fields[separator + 1])
    if matches != [b"cgroup2"]:
        raise ProcessError("exact cgroup v2 mount unavailable")


def _directory_identity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        if value.st_uid != 0 or value.st_gid != 0 or value.st_mode & 0o022:
            raise ProcessError("unsafe cgroup directory")
        generation = _host_generation(descriptor, "directory")
        return descriptor, generation
    except BaseException:
        os.close(descriptor)
        raise


def _cgroup_leaf_names(base_fd):
    names = []
    with os.scandir(base_fd) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
                if len(names) > 64:
                    raise ProcessError("cgroup leaf census bound")
    return frozenset(names)


def _prepare_cgroup(context, daemon_profile=None):
    _cgroup2_mount()
    root_fd, _root_generation = _directory_identity(CGROUP_ROOT)
    base_created = False
    leaf_created = False
    base_fd = leaf_fd = None
    leaf_name = f"{context.operation_token}-{context.command_serial}"
    try:
        try:
            os.mkdir("cogs-stage2-completion-v1", 0o700, dir_fd=root_fd)
            base_created = True
        except FileExistsError:
            pass
        base_fd, base_generation = _directory_identity(CGROUP_BASE)
        leaves = _cgroup_leaf_names(base_fd)
        if daemon_profile is None:
            if leaves:
                raise ProcessError("cgroup base has an owned leaf")
        else:
            expected_leaves = {daemon_profile.leaf_name}
            if daemon_profile.runtime_leaf_name is not None:
                expected_leaves.add(daemon_profile.runtime_leaf_name)
            if (type(daemon_profile) is not _DaemonTransactionProfile
                    or _generation_tuple(base_generation) != daemon_profile.base_generation
                    or leaves != expected_leaves
                    or _cgroup_generation(daemon_profile.cgroup_path) != daemon_profile.leaf_generation):
                raise ProcessError("daemon transaction cgroup baseline differs")
        os.mkdir(leaf_name, 0o700, dir_fd=base_fd)
        leaf_created = True
        leaf_fd, leaf_generation = _directory_identity(CGROUP_BASE + "/" + leaf_name)
        if daemon_profile is not None:
            expected_leaves = {daemon_profile.leaf_name, leaf_name}
            if daemon_profile.runtime_leaf_name is not None:
                expected_leaves.add(daemon_profile.runtime_leaf_name)
            if _cgroup_leaf_names(base_fd) != expected_leaves:
                raise ProcessError("daemon transaction cgroup set differs")
    except BaseException as primary:
        try:
            if leaf_fd is not None:
                os.close(leaf_fd)
            if base_fd is not None:
                os.close(base_fd)
            if leaf_created:
                os.rmdir(CGROUP_BASE + "/" + leaf_name)
            if base_created:
                os.rmdir(CGROUP_BASE)
        except OSError as cleanup:
            raise ProcessError(f"cgroup setup cleanup: {cleanup.errno}") from primary
        raise
    finally:
        os.close(root_fd)
    return _CgroupOwner(
        CGROUP_BASE + "/" + leaf_name, _generation_tuple(leaf_generation),
        _generation_tuple(base_generation), base_created, {}, leaf_fd, base_fd, leaf_name,
    )


def _cgroup_generation(path):
    descriptor, generation = _directory_identity(path)
    os.close(descriptor)
    return _generation_tuple(generation)


def _owned_cgroup_generation(owner):
    if owner.directory_fd is None:
        return _cgroup_generation(owner.path)
    return _generation_tuple(_host_generation(owner.directory_fd, "directory"))


def _verify_daemon_transaction_census(profile, owner, leader_pid):
    expected_leaves = {profile.leaf_name, owner.leaf_name}
    if profile.runtime_leaf_name is not None:
        expected_leaves.add(profile.runtime_leaf_name)
    if (type(profile) is not _DaemonTransactionProfile
            or _child_census() != tuple(sorted((profile.pid, leader_pid)))
            or _proc_row(profile.pid) != profile.proc_row
            or _cgroup_generation(profile.cgroup_path) != profile.leaf_generation
            or _owned_cgroup_generation(owner) != owner.leaf_generation
            or _cgroup_leaf_names(owner.base_fd) != expected_leaves):
        raise ProcessError("daemon transaction shared ownership differs")


def _cgroup_file(owner, name, flags):
    if _owned_cgroup_generation(owner) != owner.leaf_generation:
        raise ProcessError("cgroup leaf replaced")
    if owner.directory_fd is None:
        return os.open(owner.path + "/" + name, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
    return os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=owner.directory_fd)


def _cgroup_members(owner):
    before = _owned_cgroup_generation(owner)
    descriptor = _cgroup_file(owner, "cgroup.procs", os.O_RDONLY)
    with os.fdopen(descriptor, "rb", buffering=0) as source:
        raw = source.read(65_537)
    after = _owned_cgroup_generation(owner)
    if before != owner.leaf_generation or after != before or len(raw) > 65_536:
        raise ProcessError("unstable cgroup census")
    rows = raw.splitlines()
    if any(not row.isdigit() for row in rows):
        raise ProcessError("invalid cgroup member")
    return tuple(sorted({int(row) for row in rows}))


def _usable_pidfd_open(pid):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ProcessError("usable pidfd signaling unavailable")
    return os.pidfd_open(pid, 0)


def _adopt_members(owner, members):
    for pid in members:
        if pid in owner.pidfds:
            continue
        row = _proc_row(pid)
        descriptor = _usable_pidfd_open(pid)
        if _proc_row(pid) != row:
            os.close(descriptor)
            raise ProcessError("member changed during pidfd adoption")
        owner.pidfds[pid] = (descriptor, row)


def _register_cgroup(owner, pid):
    raw = f"{pid}\n".encode("ascii")
    descriptor = _cgroup_file(owner, "cgroup.procs", os.O_WRONLY)
    with os.fdopen(descriptor, "wb", buffering=0) as target:
        if target.write(raw) != len(raw):
            raise ProcessError("short cgroup registration")
    members = _cgroup_members(owner)
    if pid not in members:
        raise ProcessError("leader not registered in cgroup")
    _adopt_members(owner, members)


def _signal_cgroup(owner, sig):
    members = _cgroup_members(owner)
    _adopt_members(owner, members)
    for pid in members:
        descriptor, _row = owner.pidfds[pid]
        try:
            signal.pidfd_send_signal(descriptor, sig)
        except ProcessLookupError:
            pass


def _kill_cgroup(owner):
    descriptor = _cgroup_file(owner, "cgroup.kill", os.O_WRONLY)
    with os.fdopen(descriptor, "wb", buffering=0) as target:
        if target.write(b"1\n") != 2:
            raise ProcessError("short cgroup.kill")


def _set_subreaper(enabled):
    libc = ctypes.CDLL(None, use_errno=True)
    observed = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(observed), 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    previous = bool(observed.value)
    if libc.prctl(36, int(enabled), 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    readback = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(readback), 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    if bool(readback.value) is not bool(enabled):
        raise ProcessError("subreaper readback mismatch")
    return previous


def _advance_cleanup(owner, pid, wait_status, deadline, term_at, kill_at, state, errors):
    if wait_status is None:
        try:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed == pid:
                wait_status = status
        except ChildProcessError:
            errors.append("leader-reap-authority-lost")
    members = _cgroup_members(owner)
    _adopt_members(owner, members)
    now = _boottime_ns()
    if now >= term_at and not state["term"] and members:
        if wait_status is None:
            state["leader_timed_out"] = True
        _signal_cgroup(owner, signal.SIGTERM)
        state["term"] = True
    if now >= kill_at and not state["kill"] and members:
        _kill_cgroup(owner)
        state["kill"] = True
    return wait_status, members


def _read_setup_boottime(descriptor, deadline):
    return _read_setup_until(
        descriptor, lambda: (deadline - _boottime_ns()) / 1_000_000_000)


def _drain_transaction(pid, descriptors, stdin_bytes, owner, deadline, term_at, kill_at,
                       marker_observer=None):
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray(), "status": bytearray()}
    overflow = {"stdout": False, "stderr": False}
    limits = {"stdout": descriptors.pop("stdout_limit"), "stderr": descriptors.pop("stderr_limit")}
    state = {"term": False, "kill": False, "leader_timed_out": False}
    errors = []
    wait_status = None
    stdin_offset = 0
    first_line_settled = False
    try:
        for name, descriptor in descriptors.items():
            os.set_blocking(descriptor, False)
            event = selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ
            selector.register(descriptor, event, name)
        while selector.get_map() or wait_status is None or _cgroup_members(owner):
            wait_status, _members = _advance_cleanup(
                owner, pid, wait_status, deadline, term_at, kill_at, state, errors,
            )
            remaining = deadline - _boottime_ns()
            if remaining <= 0:
                errors.append("absolute-deadline")
                break
            for key, _mask in selector.select(min(remaining / 1_000_000_000, 0.02)):
                name = key.data
                if name == "stdin":
                    try:
                        count = os.write(key.fd, stdin_bytes[stdin_offset:stdin_offset + 8192])
                    except BlockingIOError:
                        continue
                    stdin_offset += count
                    if stdin_offset == len(stdin_bytes):
                        selector.unregister(key.fd)
                        os.close(key.fd)
                    continue
                try:
                    part = os.read(key.fd, 8192)
                except BlockingIOError:
                    continue
                if not part:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    continue
                limit = STATUS_SIZE if name == "status" else limits[name]
                room = max(0, limit - len(buffers[name]))
                buffers[name].extend(part[:room])
                if name == "stdout" and not first_line_settled:
                    newline = buffers["stdout"].find(b"\n")
                    if newline >= 0:
                        first_line_settled = True
                        if marker_observer is not None:
                            marker_observer(bytes(buffers["stdout"][:newline + 1]))
                if len(part) > room:
                    if name == "status":
                        errors.append("invalid-exec-status")
                    else:
                        overflow[name] = True
        pipes_eof = not selector.get_map()
    finally:
        for key in tuple(selector.get_map().values()):
            try:
                selector.unregister(key.fd)
                os.close(key.fd)
            except OSError as error:
                errors.append(f"pipe-close:{error.errno}")
        selector.close()
    return buffers, overflow, wait_status, pipes_eof, state, errors


def _close_and_prove_absent(descriptor, label, errors):
    try:
        os.close(descriptor)
    except OSError as error:
        errors.append(f"{label}-close:{error.errno}")
        return False
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return True
        errors.append(f"{label}-absence:{error.errno}")
        return False
    errors.append(f"{label}-still-open")
    return False


def _wait_all_children(leader_pid, errors, daemon_profile=None, owned=()):
    """Reap transaction children while preserving one authenticated daemon."""
    leader_reaped = False
    if daemon_profile is not None:
        children = set(_child_census())
        allowed = {leader_pid, *owned}
        if (type(daemon_profile) is not _DaemonTransactionProfile
                or daemon_profile.pid not in children
                or _proc_row(daemon_profile.pid) != daemon_profile.proc_row):
            errors.append("retained-daemon-child-differs")
            return False, False
        foreign = children - allowed - {daemon_profile.pid}
        if foreign:
            errors.append("foreign-child-during-daemon-transaction")
            return False, False
        for child in sorted(children & allowed):
            try:
                observed, _status = os.waitpid(child, os.WNOHANG)
                leader_reaped = leader_reaped or observed == leader_pid
            except ChildProcessError:
                pass
            except OSError as error:
                if error.errno != errno.EINTR:
                    errors.append(f"wait-census:{error.errno}")
        try:
            remaining = _child_census()
            exact = remaining == (daemon_profile.pid,) and _proc_row(daemon_profile.pid) == daemon_profile.proc_row
        except (OSError, ProcessError):
            exact = False
        return leader_reaped, exact
    while True:
        try:
            observed, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return leader_reaped, True
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            errors.append(f"wait-census:{error.errno}")
            return leader_reaped, False
        if observed == 0:
            return leader_reaped, False
        if observed == leader_pid:
            leader_reaped = True


def _settle_cgroup(owner, leader_pid, deadline, errors, daemon_profile=None):
    stable_empty = descendants_reaped = leader_reaped = False
    while _boottime_ns() < deadline:
        members = _cgroup_members(owner)
        if members:
            _kill_cgroup(owner)
        observed_leader, no_children = _wait_all_children(
            leader_pid, errors, daemon_profile, tuple(owner.pidfds))
        leader_reaped = leader_reaped or observed_leader
        first_empty = not _cgroup_members(owner)
        stable_empty = first_empty and not _cgroup_members(owner)
        descendants_reaped = no_children
        if stable_empty and descendants_reaped:
            break
        time.sleep(0.005)
    for descriptor, _row in tuple(owner.pidfds.values()):
        _close_and_prove_absent(descriptor, "pidfd", errors)
    owner.pidfds.clear()
    removed = False
    if stable_empty:
        try:
            if _owned_cgroup_generation(owner) != owner.leaf_generation:
                raise ProcessError("cgroup leaf changed before removal")
            if owner.directory_fd is not None:
                os.close(owner.directory_fd)
                owner.directory_fd = None
            if owner.base_fd is not None:
                os.rmdir(owner.leaf_name, dir_fd=owner.base_fd)
            else:
                os.rmdir(owner.path)
            removed = True
            if owner.base_fd is not None:
                os.close(owner.base_fd)
                owner.base_fd = None
            if owner.base_created:
                os.rmdir(CGROUP_BASE)
        except (OSError, ProcessError) as error:
            errors.append(f"cgroup-remove:{getattr(error, 'errno', 'identity')}")
    for attribute in ("directory_fd", "base_fd"):
        descriptor = getattr(owner, attribute)
        if descriptor is not None:
            try:
                os.close(descriptor)
                setattr(owner, attribute, None)
            except OSError as error:
                errors.append(f"cgroup-fd-close:{error.errno}")
    return stable_empty, descendants_reaped, removed, leader_reaped


def _outcome_body(intent, outcome, status, exec_errno, stdout, stderr, overflow,
                  wait_status, pipes_eof, cleanup, state, errors, release_count):
    cgroup_empty, descendants_reaped, cgroup_removed, cleanup_reaped = cleanup
    leader_reaped = wait_status is not None or cleanup_reaped
    interrupted = state["term"] or state["kill"] or "absolute-deadline" in errors
    uncertain = (not leader_reaped or not descendants_reaped or not cgroup_empty
                 or not cgroup_removed or not pipes_eof or bool(errors) or interrupted)
    if uncertain and outcome != "not-started":
        outcome, status, exec_errno = "uncertain", None, None
    body = {
        "operation_token": intent["operation_token"], "command_serial": intent["command_serial"],
        "command_id": intent["command_id"], "binding_sha256": intent["binding_sha256"],
        "outcome": outcome, "status": status, "errno": exec_errno,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_length": len(stdout),
        "stdout_truncated": overflow["stdout"], "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_length": len(stderr), "stderr_truncated": overflow["stderr"],
        "leader_reaped": leader_reaped, "descendants_reaped": descendants_reaped,
        "cgroup_empty": cgroup_empty, "cgroup_removed": cgroup_removed,
        "pipes_eof": pipes_eof, "release_count": release_count,
        "term_attempted": state["term"], "kill_attempted": state["kill"],
        "deadline_expired": "absolute-deadline" in errors, "uncertain": uncertain,
        "errors": errors[:32],
    }
    kata_operation._validate_body("COMMAND_OUTCOME_V2", body)
    return body


def _cleanup_closed(cleanup, pid, wait_status):
    leader_closed = pid is None or wait_status is not None or cleanup[3]
    return all(cleanup[:3]) and leader_closed


def _within_work_cutoff(work_cutoff):
    if _boottime_ns() >= work_cutoff:
        raise ProcessError("work cutoff reached")


def _prove_child_inherited_fds(pid, bindings):
    """Prove post-install child targets before the one-byte exec release."""
    for row in fdmap.revalidate(bindings):
        path = f"/proc/{pid}/fd/{row.target_fd}"
        observed = os.stat(path)
        if (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid,
                observed.st_gid, observed.st_nlink, observed.st_size) != (
                row.identity.device, row.identity.inode, row.identity.mode,
                row.identity.uid, row.identity.gid, row.identity.nlink, row.identity.size):
            raise ProcessError("child inherited descriptor identity mismatch")
        with open(f"/proc/{pid}/fdinfo/{row.target_fd}", "r", encoding="ascii") as source:
            raw = source.read(4097)
        if len(raw) > 4096 or not raw.endswith("\n"):
            raise ProcessError("bounded child fdinfo required")
        fields = {}
        for line in raw.splitlines():
            if ":\t" in line:
                name, value = line.split(":\t", 1)
                fields.setdefault(name, []).append(value)
        try: flags = int(fields["flags"][0], 8)
        except (KeyError, ValueError, IndexError) as error:
            raise ProcessError("child inherited descriptor flags unavailable") from error
        if flags & os.O_CLOEXEC or fields.get("mnt_id") != [str(row.identity.mount_id)]:
            raise ProcessError("child inherited descriptor is not exec-retained")
        if row.role == fdmap.NFT_WRITER_LOCK:
            locks = fields.get("lock", [])
            if (len(locks) != 1 or "OFDLCK ADVISORY  WRITE -1" not in locks[0]
                    or not locks[0].endswith(" 0 EOF")):
                raise ProcessError("child does not retain the NFT OFD lock")


def _transact_fixed(journal, fixed, executable, inherited=(), daemon_owner=None, consumption_owner=None, launch_permit=None):
    """Private T1 transaction over one registered fixed table identity."""
    context = kata_operation._command_context(journal)
    runtime_fixed = False
    if launch_permit is not None and type(fixed) is FixedCommand and fixed.command_id is CommandId.CTR_RUN:
        runtime_fixed = ((fixed.executable_role, fixed.executable_path, fixed.argv, fixed.stdin) ==
            ("ctr", kata_runtime.STAGED_CTR, kata_runtime._ctr_metadata_argv(), b"") and
            fixed.duration_ns == 10_000_000_000 and fixed.stdout_limit == fixed.stderr_limit == MAX_STREAM and
            fixed.inherited_fds == ())
    runtime_extension = _RUNTIME_EXTENSIONS.get(id(fixed)) is fixed
    template = _FIXED_COMMANDS.get(fixed.command_id)
    if fixed.command_id in {CommandId[name] for name in command_policy.KEY_COMMANDS}:
        expected = replace(template, argv=tuple(item.replace("{operation_token}", context.operation_token)
                                                for item in template.argv))
        if fixed != expected: raise ProcessError("operation-derived key command required")
    elif not (_internally_fixed(fixed) or runtime_extension or runtime_fixed):
        raise ProcessError(
            f"internally fixed command required:{fixed.command_id.value}:{fixed.argv!r}")
    if fixed.command_id is CommandId.CONTAINERD_START:
        raise ProcessError("long-lived containerd requires the runtime daemon owner")
    if (runtime_extension and consumption_owner is None) or ((runtime_extension or runtime_fixed) and daemon_owner is None):
        raise ProcessError("runtime path owners required")
    if not hasattr(signal, "pidfd_send_signal") or not hasattr(os, "pidfd_open"):
        raise ProcessError("usable pidfd signaling is required")
    spec = _Spec(
        fixed.command_id.value, fixed.argv, fixed.stdin, "fixed",
        fixed.duration_ns / 1_000_000_000, fixed.inherited_fds,
    )
    bindings = _claim_inherited_fds(spec, inherited); network_fd = None
    daemon_profile = None
    # Expensive custody checks precede the command's absolute deadline.  They
    # are read-only and must not consume the bounded execution/cleanup window.
    if runtime_extension or runtime_fixed:
        daemon_profile = _fixed_daemon_transaction_profile(daemon_owner, journal)
        if runtime_extension:
            kata_runtime._verify_runtime_consumption(
                consumption_owner, journal, fixed.command_id.value)
        _verify_fixed_daemon(daemon_owner, journal)
        _require_no_children(daemon_profile)
    deadline = _boottime_ns() + fixed.duration_ns
    work_cutoff = deadline - _cleanup_reserve_ns(fixed)
    intent = _intent_body(context, fixed, executable, bindings, deadline, runtime_fixed)
    kata_operation._record_command_intent(journal, intent)
    owner = None
    pid = None
    pidfd = None
    pipes = []
    release_count = 0
    previous_subreaper = None
    subreaper_restored = False
    errors = []
    wait_status = None
    preexec_recorded = False
    launch_started_boottime_ns = None
    try:
        network_fd = None if launch_permit is None else kata_runtime._retain_launch_network_descriptor(launch_permit)
        if daemon_profile is None:
            _require_no_children()
        # Kata's shim daemonizes during CTR_RUN.  It must reparent to PID 1,
        # whose independent runtime owner inventories it, rather than becoming
        # an unowned direct child of this command supervisor.
        previous_subreaper = _set_subreaper(fixed.command_id is not CommandId.CTR_RUN)
        _within_work_cutoff(work_cutoff)
        owner = (_prepare_cgroup(context) if daemon_profile is None
                 else _prepare_cgroup(context, daemon_profile))
        def owned_pipe():
            pair = os.pipe2(os.O_CLOEXEC)
            pipes.extend(pair)
            return pair
        release_r, release_w = owned_pipe()
        setup_r, setup_w = owned_pipe()
        status_r, status_w = owned_pipe()
        stdout_r, stdout_w = owned_pipe()
        stderr_r, stderr_w = owned_pipe()
        stdin_r, stdin_w = owned_pipe()
        _within_work_cutoff(work_cutoff)
        child_spec = _Spec(
            fixed.command_id.value, fixed.argv, fixed.stdin, "fixed",
            fixed.duration_ns / 1_000_000_000, bindings,
        )
        pid = os.fork()
        if pid == 0:
            _child(executable.descriptor, child_spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r, network_fd)
        if network_fd is not None: os.close(network_fd); network_fd = None
        pidfd = _usable_pidfd_open(pid)
        for descriptor in (release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r):
            os.close(descriptor)
            pipes.remove(descriptor)
        setup = _read_setup_boottime(setup_r, work_cutoff)
        os.close(setup_r)
        pipes.remove(setup_r)
        identity, observed_pidfd = _identity(pid, setup)
        if observed_pidfd is not None:
            os.close(observed_pidfd)
        if not identity.pidfd_supported:
            raise ProcessError("leader pidfd unavailable")
        _register_cgroup(owner, pid)
        preexec = {
            "operation_token": intent["operation_token"], "command_serial": intent["command_serial"],
            "command_id": intent["command_id"], "binding_sha256": intent["binding_sha256"],
            "host_boot_id": identity.boot_id, "pid": identity.pid, "ppid": identity.ppid,
            "pgid": identity.pgid, "sid": identity.sid, "proc_start_time": identity.starttime,
            "pidfd_supported": True, "cgroup_path": owner.path,
            "cgroup_generation": dict(zip(kata_operation.GEN_KEYS, owner.leaf_generation)),
            "executable_sha256": intent["executable_sha256"],
            "tool_closure_sha256": intent["tool_closure_sha256"],
            "executable_generation": intent["executable_generation"],
            "exec_status_pipe": _host_generation(status_r), "release_count": 0,
        }
        if fixed.command_id is CommandId.CTR_RUN:
            preexec.update({"namespace_fd": kata_runtime.CTR_NS_FD,
                            "namespace_path": kata_runtime.CTR_NS_TEMPLATE.replace("{ctr-child-pid}", str(pid))})
        kata_operation._record_command_preexec(journal, preexec)
        preexec_recorded = True
        _within_work_cutoff(work_cutoff)
        if runtime_extension or runtime_fixed:
            _verify_fixed_daemon(daemon_owner, journal)
            _verify_daemon_transaction_census(daemon_profile, owner, pid)
        if launch_permit is not None:
            retained_network = kata_runtime._preexec_launch_network(launch_permit, pid)
            if fixed.command_id is not CommandId.CTR_RUN or retained_network["path"] != "/run/netns/" + retained_network["identity"]["name"]:
                raise ProcessError("runtime network opener binding")
        if bindings:
            _prove_child_inherited_fds(pid, bindings)
        if fixed.command_id is CommandId.CTR_RUN:
            launch_started_boottime_ns = _boottime_ns()
        if os.write(release_w, b"R") != 1:
            raise ProcessError("short release")
        release_count = 1
        if launch_permit is not None: kata_runtime._release_launch_preexec(launch_permit)
        os.close(release_w)
        pipes.remove(release_w)
        for descriptor in (status_r, stdout_r, stderr_r, stdin_w):
            pipes.remove(descriptor)
        work_span = max(1, fixed.duration_ns - _cleanup_reserve_ns(fixed))
        term_at = work_cutoff - min(1_500_000_000, work_span // 4)
        kill_at = work_cutoff - min(250_000_000, work_span // 8)
        route = kata_operation._cycle_route(journal)
        marker_bytes = (kata_ssh.MARKER if fixed.command_id is CommandId.SSH_READY else
                        guest_readiness.GUEST_READY_MARKER
                        if fixed.command_id is CommandId.SSH_READINESS else None)
        marker_observer = None
        if route is not None and marker_bytes is not None:
            def marker_observer(first_line):
                if first_line == marker_bytes:
                    kata_operation._record_ssh_marker(
                        journal, intent["command_serial"], intent["command_id"],
                        intent["binding_sha256"], hashlib.sha256(marker_bytes).hexdigest(),
                        _boottime_ns())
        buffers, overflow, wait_status, pipes_eof, state, drain_errors = _drain_transaction(
            pid, {"status": status_r, "stdout": stdout_r, "stderr": stderr_r,
                  "stdin": stdin_w, "stdout_limit": fixed.stdout_limit,
                  "stderr_limit": fixed.stderr_limit},
            fixed.stdin, owner, work_cutoff, term_at, kill_at, marker_observer,
        )
        errors.extend(drain_errors)
        status_raw = bytes(buffers["status"])
        exec_errno = struct.unpack("!I", status_raw)[0] if len(status_raw) == STATUS_SIZE else None
        stdout, stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
        if exec_errno is not None:
            outcome, status = "exec-failed", None
        elif wait_status is not None and os.WIFEXITED(wait_status):
            outcome, status = "exited", os.WEXITSTATUS(wait_status)
        elif wait_status is not None and os.WIFSIGNALED(wait_status):
            outcome, status = "signaled", os.WTERMSIG(wait_status)
        else:
            outcome, status = "uncertain", None
        cleanup = _settle_cgroup(owner, pid, deadline, errors, daemon_profile)
        try:
            _set_subreaper(previous_subreaper)
        except BaseException as error:
            errors.append(f"subreaper-restore:{type(error).__name__}")
        subreaper_restored = True
        if not _cleanup_closed(cleanup, pid, wait_status):
            raise ProcessError("cleanup continuation required")
        if pidfd is not None:
            retained_pidfd = pidfd
            pidfd = None
            _close_and_prove_absent(retained_pidfd, "leader-pidfd", errors)
        body = _outcome_body(
            intent, outcome, status, exec_errno, stdout, stderr, overflow,
            wait_status, pipes_eof, cleanup, state, errors, release_count,
        )
        if not body["uncertain"]:
            kata_operation._record_command_output(journal, {"operation_token": intent["operation_token"],
                "command_serial": intent["command_serial"], "command_id": intent["command_id"],
                "binding_sha256": intent["binding_sha256"], "stdout_hex": stdout.hex(), "stderr_hex": stderr.hex()})
        durable = kata_operation._record_command_outcome(journal, body)
        if (route is not None and fixed.command_id is CommandId.CTR_RUN
                and body["outcome"] == "exited" and body["status"] == 0
                and not body["uncertain"]):
            if launch_started_boottime_ns is None:
                raise ProcessError("launch release observation absent")
            kata_operation._record_launch_issued(
                journal, intent["command_serial"], intent["binding_sha256"],
                launch_started_boottime_ns)
        return ProcessOutcome(
            fixed.command_id.value, identity, body["outcome"], body["status"], body["errno"],
            stdout, stderr, body["stdout_sha256"], body["stderr_sha256"],
            body["stdout_truncated"], body["stderr_truncated"],
            body["deadline_expired"] or state["term"] or state["kill"],
            state["leader_timed_out"],
            not state["leader_timed_out"] and (state["term"] or state["kill"] or not pipes_eof),
            body["leader_reaped"], tuple(body["errors"]),
        ), durable
    except BaseException as primary:
        # The initiating failure is the certain command result, not cleanup
        # uncertainty. Keep it diagnostic-only; only failed settlement facts
        # enter the durable uncertainty vector.
        diagnostics = [*errors, f"primary:{type(primary).__name__}"]
        settlement_errors = list(errors)
        pipes_eof = True
        for descriptor in tuple(pipes):
            try:
                os.close(descriptor)
            except OSError as error:
                pipes_eof = False
                settlement_errors.append(f"close:{error.errno}")
        if pid is not None and wait_status is None:
            try:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                while _boottime_ns() < deadline:
                    observed, status = os.waitpid(pid, os.WNOHANG)
                    if observed == pid:
                        wait_status = status
                        break
                    time.sleep(0.005)
                if wait_status is None:
                    settlement_errors.append("leader-cleanup:unreaped")
            except BaseException as error:
                settlement_errors.append(f"leader-cleanup:{type(error).__name__}")
        cleanup = (owner is None, owner is None, owner is None,
                   pid is None or wait_status is not None)
        killed_cgroup = False
        if owner is not None:
            try:
                _kill_cgroup(owner)
                killed_cgroup = pid is not None
                cleanup = _settle_cgroup(
                    owner, pid, deadline, settlement_errors, daemon_profile)
                if pid is None:
                    cleanup = (*cleanup[:3], True)
            except BaseException as error:
                settlement_errors.append(f"cgroup-cleanup:{type(error).__name__}")
        if previous_subreaper is not None and not subreaper_restored:
            try:
                _set_subreaper(previous_subreaper)
            except BaseException as error:
                settlement_errors.append(f"subreaper-restore:{type(error).__name__}")
            subreaper_restored = True
        if pidfd is not None:
            retained_pidfd = pidfd
            pidfd = None
            _close_and_prove_absent(retained_pidfd, "leader-pidfd", settlement_errors)
        known_not_started = pid is None and not preexec_recorded
        if not known_not_started and not settlement_errors:
            settlement_errors.append("launch-boundary-uncertain")
        failure_state = {"term": False, "kill": killed_cgroup}
        failure_body = _outcome_body(
            intent, "not-started" if known_not_started else "uncertain", None, None,
            b"", b"", {"stdout": False, "stderr": False}, wait_status,
            pipes_eof, cleanup, failure_state, settlement_errors,
            release_count if preexec_recorded else 0,
        )
        if _cleanup_closed(cleanup, pid, wait_status):
            try:
                kata_operation._record_command_outcome(journal, failure_body)
            except BaseException as journal_error:
                settlement_errors.append(f"outcome:{type(journal_error).__name__}")
        else:
            settlement_errors.append("cleanup-continuation-pending")
        raise ProcessError(";".join((*diagnostics, *settlement_errors))) from primary
    finally:
        if network_fd is not None:
            try: os.close(network_fd)
            except OSError: pass
        if pidfd is not None:
            _close_and_prove_absent(pidfd, "leader-pidfd-final", errors)
        if previous_subreaper is not None and not subreaper_restored:
            try:
                _set_subreaper(previous_subreaper)
            except BaseException:
                pass


def _daemon_routes():
    states = owner_helpers.Registry(
        "_DaemonOwner", ProcessError, "private daemon owner",
        sealed_message="sealed daemon owner")
    _DaemonOwner = states.kind
    def socket_generations(pid):
        paths = {"s": CONTAINERD_SOCKET, "s.ttrpc": CONTAINERD_TTRPC_SOCKET}
        descriptor = os.open("/proc/net/unix", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = bytearray()
            while len(raw) <= 1_048_576:
                part = os.read(descriptor, min(65_536, 1_048_577 - len(raw)))
                if not part: break
                raw.extend(part)
            if len(raw) > 1_048_576: raise ProcessError("private daemon unix table bound")
        finally: os.close(descriptor)
        rows = [row.split() for row in bytes(raw).splitlines()]
        fd_names = os.listdir(f"/proc/{pid}/fd")
        if len(fd_names) > 4096: raise ProcessError("private daemon fd bound")
        links = []
        for name in fd_names:
            if not name.isdigit(): raise ProcessError("private daemon fd name")
            try: links.append(os.readlink(f"/proc/{pid}/fd/{name}").encode("ascii"))
            except FileNotFoundError: pass
        result = {}
        for name, path in paths.items():
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            try: generation = _host_generation(descriptor, "socket")
            finally: os.close(descriptor)
            matches = [row for row in rows if len(row) == 8 and row[-1] == path.encode("ascii")]
            listeners = [row for row in matches if row[3:6] == [b"00010000", b"0001", b"01"]]
            accepted = [row for row in matches if row[3:6] == [b"00000000", b"0001", b"03"]]
            if (generation["uid"] != 0 or generation["gid"] != 0 or generation["nlink"] != 1
                    or len(listeners) != 1 or len(matches) != 1 + len(accepted)
                    or len(accepted) > 64 or any(not row[6].isdigit() for row in matches)):
                raise ProcessError("private daemon socket ownership")
            inodes = [int(row[6]) for row in matches]
            if len(inodes) != len(set(inodes)) or any(
                    links.count(f"socket:[{inode}]".encode("ascii")) != 1 for inode in inodes):
                raise ProcessError("private daemon socket fd ownership")
            result[name] = {"generation": generation, "fd_inode": int(listeners[0][6])}
        if len({row["fd_inode"] for row in result.values()}) != 2 or len({(row["generation"]["device"], row["generation"]["inode"]) for row in result.values()}) != 2: raise ProcessError("private daemon socket identity collision")
        return result
    def close_state(owner):
        try:
            state = states.pop(owner)
        except ProcessError:
            return []
        errors = []
        descriptors = ([state[2]] if state[2] is not None else []) + [row[0] for row in state[3].pidfds.values()]; state[2] = None; state[3].pidfds.clear()
        for descriptor in descriptors:
            try: os.close(descriptor)
            except OSError as error: errors.append(f"daemon-pidfd-close:{error.errno}")
        for attribute in ("directory_fd", "base_fd"):
            descriptor = getattr(state[3], attribute, None)
            if descriptor is None: continue
            try: os.close(descriptor)
            except OSError as error: errors.append(f"daemon-cgroup-fd-close:{error.errno}")
            setattr(state[3], attribute, None)
        try: _set_subreaper(state[4])
        except BaseException as error: errors.append(f"daemon-subreaper-restore:{type(error).__name__}")
        return errors
    def verify(owner, journal):
        state = states.require(owner)
        if state[0] is not journal:
            raise ProcessError("private daemon owner")
        retained = state[1]; row = _proc_row(retained["pid"])
        if (row[4] != retained["proc_start_time"] or _cgroup_generation(retained["cgroup_path"]) !=
                tuple(retained["cgroup_generation"][name] for name in kata_operation.GEN_KEYS) or
                socket_generations(retained["pid"]) != retained["socket_generations"] or _proc_row(retained["pid"]) != row):
            raise ProcessError("private daemon replacement")
        return retained
    def transaction_profile(owner, journal):
        retained = verify(owner, journal)
        state = states.require(owner)
        row = (retained["pid"], retained["ppid"], retained["pgid"],
               retained["sid"], retained["proc_start_time"])
        cgroup = state[3]
        if (retained["ppid"] != os.getpid() or _proc_row(retained["pid"]) != row
                or cgroup.path != retained["cgroup_path"]
                or _owned_cgroup_generation(cgroup) != _generation_tuple(retained["cgroup_generation"])
                or retained["pid"] not in _cgroup_members(cgroup)
                or cgroup.base_fd is None):
            raise ProcessError("private daemon transaction profile differs")
        base_generation = _generation_tuple(_host_generation(cgroup.base_fd, "directory"))
        history = journal.runtime_recovery_history()
        runtime_leaf = ("kata_" + kata_runtime.CONTAINER_ID
                        if history.get("launches") else None)
        return _DaemonTransactionProfile(
            retained["pid"], row, cgroup.path, cgroup.leaf_name,
            cgroup.leaf_generation, base_generation, runtime_leaf)
    def start(journal, executable):
        fixed = _bind_containerd_extension(); context = kata_operation._command_context(journal)
        deadline = _boottime_ns() + fixed.duration_ns
        intent = _intent_body(context, fixed, executable, (), deadline, True)
        kata_operation._record_command_intent(journal, intent); previous = _set_subreaper(True)
        cgroup = None; descriptors = []; pid = pidfd = None
        try:
            cgroup = _prepare_cgroup(context)
            def pipe():
                pair = os.pipe2(os.O_CLOEXEC); descriptors.extend(pair); return pair
            release_r, release_w = pipe(); setup_r, setup_w = pipe(); status_r, status_w = pipe()
            stdin_r, stdin_w = pipe()
            stdout_null = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
            stderr_null = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
            descriptors.extend((stdout_null, stderr_null))
            spec = _Spec(fixed.command_id.value, fixed.argv, b"", "fixed", 60.0, ())
            pid = os.fork()
            if pid == 0:
                _child(executable.descriptor, spec, release_r, setup_w, status_w,
                       stdout_null, stderr_null, stdin_r)
            pidfd = _usable_pidfd_open(pid)
            for descriptor in (release_r, setup_w, status_w, stdin_r, stdout_null, stderr_null):
                os.close(descriptor); descriptors.remove(descriptor)
            setup = _read_setup_boottime(setup_r, deadline); os.close(setup_r); descriptors.remove(setup_r)
            identity, observed = _identity(pid, setup)
            if observed is not None: os.close(observed)
            if not identity.pidfd_supported: raise ProcessError("daemon pidfd unavailable")
            _register_cgroup(cgroup, pid)
            preexec = {"operation_token": intent["operation_token"], "command_serial": intent["command_serial"],
                "command_id": intent["command_id"], "binding_sha256": intent["binding_sha256"],
                "host_boot_id": identity.boot_id, "pid": pid, "ppid": identity.ppid, "pgid": identity.pgid,
                "sid": identity.sid, "proc_start_time": identity.starttime, "pidfd_supported": True,
                "cgroup_path": cgroup.path, "cgroup_generation": dict(zip(kata_operation.GEN_KEYS, cgroup.leaf_generation)),
                "executable_sha256": intent["executable_sha256"], "tool_closure_sha256": intent["tool_closure_sha256"],
                "executable_generation": intent["executable_generation"],
                "exec_status_pipe": _host_generation(status_r), "release_count": 0}
            kata_operation._record_command_preexec(journal, preexec)
            if os.write(release_w, b"R") != 1: raise ProcessError("daemon release")
            os.close(release_w); descriptors.remove(release_w); os.close(stdin_w); descriptors.remove(stdin_w)
            poller = select.poll(); poller.register(status_r, select.POLLIN | select.POLLHUP)
            wait_ms = max(1, (deadline - _boottime_ns()) // 1_000_000)
            if not poller.poll(wait_ms): raise ProcessError("daemon exec timeout")
            status_raw = os.read(status_r, STATUS_SIZE + 1); os.close(status_r); descriptors.remove(status_r)
            if status_raw: raise ProcessError("daemon exec failed")
            while _boottime_ns() < deadline:
                try:
                    observed = (os.lstat(CONTAINERD_SOCKET), os.lstat(CONTAINERD_TTRPC_SOCKET))
                    if not all(stat.S_ISSOCK(item.st_mode) for item in observed): raise ProcessError("daemon socket kind")
                    break
                except FileNotFoundError: pass
                time.sleep(0.01)
            else: raise ProcessError("daemon socket timeout")
            retained = {**preexec, "socket_generations": socket_generations(pid)}
            kata_operation._record_daemon_retained(journal, retained)
            return states.issue([journal, retained, pidfd, cgroup, previous])
        except BaseException as primary:
            if pidfd is not None:
                try: signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except BaseException: pass
            if cgroup is not None and pid is not None:
                cleanup_errors = []; _settle_cgroup(cgroup, pid, _boottime_ns() + 2_000_000_000, cleanup_errors)
            for descriptor in descriptors:
                try: os.close(descriptor)
                except OSError: pass
            if pidfd is not None:
                try: os.close(pidfd)
                except OSError: pass
            try: _set_subreaper(previous)
            except BaseException: pass
            try: _recover_pending_fixed(journal)
            except BaseException: pass
            raise primary
    def reopen(journal):
        history = journal.runtime_recovery_history()
        if len(history["daemon_retained"]) != len(history["daemon_outcomes"]) + 1:
            raise ProcessError("no retained private daemon")
        retained = history["daemon_retained"][-1]; pidfd = base_fd = leaf_fd = owner = None
        try:
            pidfd = _usable_pidfd_open(retained["pid"])
            base_fd, base_generation = _directory_identity(CGROUP_BASE)
            leaf_fd, leaf_generation = _directory_identity(retained["cgroup_path"])
            cgroup = _CgroupOwner(retained["cgroup_path"], _generation_tuple(leaf_generation),
                _generation_tuple(base_generation), False, {}, leaf_fd, base_fd,
                retained["cgroup_path"].rsplit("/", 1)[1]); leaf_fd = base_fd = None
            _adopt_members(cgroup, _cgroup_members(cgroup))
            owner = states.issue([
                journal, retained, pidfd, cgroup, _set_subreaper(True),
            ])
            verify(owner, journal); return owner
        except (FileNotFoundError, ProcessLookupError) as absent:
            errors = ["daemon-absent-on-reopen"]
            if owner is not None: errors.extend(close_state(owner)); owner = None
            empty, removed = _recover_cgroup(retained["cgroup_path"], _generation_tuple(retained["cgroup_generation"]),
                                              _boottime_ns() + 5_000_000_000, {"term": False, "kill": False}, errors)
            body = {"operation_token": retained["operation_token"], "command_serial": retained["command_serial"],
                "command_id": retained["command_id"], "binding_sha256": retained["binding_sha256"],
                "pid": retained["pid"], "proc_start_time": retained["proc_start_time"], "status": None,
                "leader_reaped": False, "descendants_reaped": False, "cgroup_empty": empty,
                "cgroup_removed": removed, "uncertain": True, "errors": errors}
            for descriptor in (pidfd, leaf_fd, base_fd):
                if descriptor is not None:
                    try: os.close(descriptor)
                    except OSError: pass
            kata_operation._record_daemon_outcome(journal, body)
            raise ProcessError("daemon absent on reopen") from absent
        except BaseException as primary:
            errors = close_state(owner) if owner is not None else []
            for descriptor in (pidfd, leaf_fd, base_fd):
                if descriptor is not None:
                    try: os.close(descriptor)
                    except OSError as error: errors.append(f"daemon-reopen-fd-close:{error.errno}")
            if errors: raise ProcessError(";".join(errors)) from primary
            raise
    def stop(owner, journal):
        retained = verify(owner, journal); state = states.require(owner); errors = []
        final = _boottime_ns() + 10_000_000_000; term_limit = min(final, _boottime_ns() + 5_000_000_000); status = None
        signal.pidfd_send_signal(state[2], signal.SIGTERM); poller = select.poll(); poller.register(state[2], select.POLLIN)
        wait_ms = max(1, (term_limit - _boottime_ns()) // 1_000_000)
        ready = poller.poll(wait_ms)
        if not ready:
            try: signal.pidfd_send_signal(state[2], signal.SIGKILL)
            except ProcessLookupError: pass
            ready = poller.poll(max(1, (final - _boottime_ns()) // 1_000_000))
        if ready:
            try: status = os.waitid(os.P_PIDFD, state[2], os.WEXITED).si_status
            except ChildProcessError:
                try:
                    if _proc_row(retained["pid"])[4] == retained["proc_start_time"]: errors.append("daemon-not-absent")
                except FileNotFoundError: pass
        else: errors.append("daemon-final-deadline")
        empty, descendants, removed, leader = _settle_cgroup(state[3], retained["pid"], final, errors)
        errors.extend(close_state(owner))
        absent = False
        try: absent = _proc_row(retained["pid"])[4] != retained["proc_start_time"]
        except FileNotFoundError: absent = True
        body = {"operation_token": retained["operation_token"], "command_serial": retained["command_serial"],
            "command_id": retained["command_id"], "binding_sha256": retained["binding_sha256"],
            "pid": retained["pid"], "proc_start_time": retained["proc_start_time"], "status": status,
            "leader_reaped": leader or absent, "descendants_reaped": descendants,
            "cgroup_empty": empty, "cgroup_removed": removed,
            "uncertain": bool(errors) or not (absent and empty and descendants and removed), "errors": errors}
        kata_operation._record_daemon_outcome(journal, body)
        if body["uncertain"]: raise ProcessError("private daemon cleanup uncertain")
        return body
    return start, reopen, verify, stop, transaction_profile

(_start_fixed_daemon, _reopen_fixed_daemon, _verify_fixed_daemon, _stop_fixed_daemon,
 _fixed_daemon_transaction_profile) = _daemon_routes()
del _daemon_routes


def _recover_cgroup(path, expected_generation, deadline, state, errors):
    """Open the deterministic leaf, then boundedly kill, poll, and remove it."""
    base_fd = leaf_fd = owner = None
    try:
        base_fd, _base_generation = _directory_identity(CGROUP_BASE)
        leaf_fd, observed = _directory_identity(path)
        leaf_generation = _generation_tuple(observed)
        if expected_generation is not None and leaf_generation != expected_generation:
            raise ProcessError("recovery cgroup generation mismatch")
        owner = _CgroupOwner(
            path, leaf_generation, (), False, {}, leaf_fd, base_fd,
            path.rsplit("/", 1)[1],
        )
        leaf_fd = base_fd = None
        _kill_cgroup(owner)
        state["kill"] = True
        empty = False
        while _boottime_ns() < deadline:
            members = _cgroup_members(owner)
            if members:
                _kill_cgroup(owner)
            elif not _cgroup_members(owner):
                empty = True
                break
            time.sleep(0.005)
        removed = False
        if empty:
            os.close(owner.directory_fd)
            owner.directory_fd = None
            os.rmdir(owner.leaf_name, dir_fd=owner.base_fd)
            remaining = _cgroup_leaf_names(owner.base_fd)
            os.close(owner.base_fd); owner.base_fd = None
            if not remaining:
                os.rmdir(CGROUP_BASE)
            removed = True
        for attribute in ("directory_fd", "base_fd"):
            descriptor = getattr(owner, attribute)
            if descriptor is not None:
                os.close(descriptor)
                setattr(owner, attribute, None)
        return empty, removed
    except FileNotFoundError:
        if base_fd is not None:
            remaining = _cgroup_leaf_names(base_fd)
            os.close(base_fd); base_fd = None
            if not remaining:
                os.rmdir(CGROUP_BASE)
        return True, True
    except BaseException as error:
        errors.append(f"recovery:{type(error).__name__}")
        return False, False
    finally:
        owned = () if owner is None else (owner.directory_fd, owner.base_fd)
        for descriptor in (leaf_fd, base_fd, *owned):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _recover_daemon_reap(preexec, deadline, errors):
    """Boundedly reap when parent, otherwise prove the recorded PID absent."""
    leader_done = descendants_done = False
    while _boottime_ns() < deadline:
        try:
            observed, _status = os.waitpid(preexec["pid"], os.WNOHANG)
            leader_done = leader_done or observed == preexec["pid"]
        except ChildProcessError:
            leader_done = _observe_proc(preexec["pid"]).kind is ObservationKind.ABSENT
        except OSError as error:
            if error.errno != errno.EINTR: errors.append(f"daemon-wait:{error.errno}")
        census_leader, descendants_done = _wait_all_children(preexec["pid"], errors)
        leader_done = leader_done or census_leader
        if leader_done and descendants_done: return True, True
        time.sleep(0.005)
    return leader_done, descendants_done


def _transact_fixed_ssh(journal, executable, inherited):
    journal = kata_operation._claim_production_operation(journal)
    _require_attested_executable(executable)
    return _transact_fixed(journal, _FIXED_COMMANDS[CommandId.SSH_READY], executable, inherited)


def _transact_fixed_ssh_readiness(journal, executable, inherited):
    journal = kata_operation._claim_production_operation(journal)
    _require_attested_executable(executable)
    return _transact_fixed(
        journal, _FIXED_COMMANDS[CommandId.SSH_READINESS], executable, inherited)


def _transact_key(journal, executable, command_id):
    journal = kata_operation._claim_production_operation(journal)
    _require_attested_executable(executable)
    context = kata_operation._command_context(journal)
    template = _FIXED_COMMANDS[command_id]
    command = replace(template, argv=tuple(
        item.replace("{operation_token}", context.operation_token) for item in template.argv))
    return _transact_fixed(journal, command, executable)



def _recover_pending_fixed(journal):
    """Slice-A process-only recovery primitive; no production admission."""
    if hasattr(journal, "recovery_command"):
        intent, preexec, terminal = kata_operation._recovery_command(journal)
    else:
        intent, preexec = kata_operation._pending_command(journal)
        terminal = None
    errors = ["crash-continuation"]
    state = {"term": False, "kill": False}
    path = f"{CGROUP_BASE}/{intent['operation_token']}-{intent['command_serial']}"
    expected = None if preexec is None else _generation_tuple(preexec["cgroup_generation"])
    recovery_budget = (4_000_000_000 if intent["command_id"] == "CONTAINERD_START"
                       else intent["cleanup_reserve_ns"])
    production_deadline = hasattr(journal, "recovery_lifecycle_deadline")
    if production_deadline:
        lifecycle_boot, lifecycle_deadline = kata_operation._recovery_lifecycle_deadline(journal)
    else:
        lifecycle_boot, lifecycle_deadline = intent["host_boot_id"], None
    now = _boottime_ns()
    durable_deadline = (intent["deadline_boottime_ns"] if production_deadline
                        else now + recovery_budget)
    if lifecycle_deadline is not None: durable_deadline = min(durable_deadline, lifecycle_deadline)
    current_boot = _boot_id() if production_deadline else intent["host_boot_id"]
    expired = (intent["host_boot_id"] != current_boot or lifecycle_boot != current_boot
               or now >= durable_deadline)
    if expired:
        errors.append("old-boot" if (intent["host_boot_id"] != current_boot
                                     or lifecycle_boot != current_boot)
                      else "lifecycle-deadline-expired")
    # Expiry forbids execution/retry, not exact reverse cleanup. Recovery owns a
    # fresh bounded settlement budget and can only target the retained cgroup.
    deadline = now + recovery_budget if expired else min(now + recovery_budget, durable_deadline)
    cgroup_deadline = (deadline - 2_000_000_000
                       if intent["command_id"] == "CONTAINERD_START" else deadline)
    cgroup_empty, cgroup_removed = _recover_cgroup(
        path, expected, max(now, cgroup_deadline), state, errors)
    closure = (cgroup_empty, False, cgroup_removed, False)
    if intent["command_id"] == "CONTAINERD_START" and preexec is not None:
        leader_reaped, descendants_reaped = _recover_daemon_reap(preexec, deadline, errors)
        closure = (cgroup_empty, descendants_reaped, cgroup_removed, leader_reaped)
    if terminal is not None:
        return kata_operation.DurableCommandOutcome(
            terminal["command_serial"], terminal["command_id"],
            terminal["binding_sha256"], terminal,
        )
    # Absence of PREEXEC after a crash does not prove fork absence. Recovery
    # therefore records uncertainty, unlike the live before-fork path which can
    # prove every pipe end closed and no child ever existed.
    body = _outcome_body(
        intent, "uncertain", None, None,
        b"", b"", {"stdout": False, "stderr": False}, None, False,
        closure, state, errors, 0,
    )
    return kata_operation._record_command_outcome(journal, body)


def _recover_pending_production(journal):
    """Production family adapter: exact admission and sticky uncertain closure."""
    journal = kata_operation._claim_production_cleanup_operation(journal)
    outcome = _recover_pending_fixed(journal)
    if outcome.body["uncertain"] and kata_operation._durable_phase(journal) != "UNCERTAIN":
        kata_operation._record_uncertain(journal, "incomplete")
    return outcome


def _test_spec(action):
    if type(action) is not _TestAction:
        raise ProcessError("closed test action required")
    timeout = 2 if action in {_TestAction.SLEEP, _TestAction.HELD_PIPE} else 5
    inherited = ((kata_ssh.KEY_FD, kata_ssh.KNOWN_HOSTS_FD)
                 if action is _TestAction.INHERITED else ())
    return _Spec("TEST_" + action.name, (TEST_PATH, action.value), b"", "test", timeout, inherited)


def _unissued_spec_snapshots_for_tests():
    commands = (
        CommandId.IP_NETNS_ADD, CommandId.IP_LINK_ADD, CommandId.IP_LINK_MOVE,
        CommandId.IP_HOST_ADDRESS_ADD, CommandId.IP_HOST_ADDRGEN_NONE,
        CommandId.IP_HOST_LINK_UP,
        CommandId.IP_PEER_RENAME, CommandId.IP_PEER_ADDRGEN_NONE,
        CommandId.IP_LOOPBACK_UP, CommandId.IP_GUEST_ADDRESS_ADD,
        CommandId.IP_GUEST_LINK_UP, CommandId.IP_HOST_LINK_REMOVE,
        CommandId.NFT_INSTALL, CommandId.NFT_REMOVE,
    )
    return tuple(_unissued_network_spec(item) for item in commands)


def adapt_ssh_process_outcome(outcome):
    """The sole ProcessOutcome-to-SSH adapter; every uncertainty remains visible."""
    if type(outcome) is not ProcessOutcome or outcome.command_id != "SSH_READY":
        raise ProcessError("exact SSH process outcome required")
    return kata_ssh.SshOutcome(
        outcome.command_id, outcome.outcome, outcome.status, outcome.stdout, outcome.stderr,
        outcome.stdout_truncated, outcome.stderr_truncated, outcome.timed_out, outcome.reaped,
        outcome.errors,
    )


def open_fixed_process_owner():
    raise ProcessError("production process permits unavailable: committed preflight/closure absent")


def _fixed_spec_snapshots_for_tests():
    available = {CommandId.CTR_CONTAINER_INFO, CommandId.CTR_CONTAINER_LIST,
                 CommandId.CTR_TASK_LIST, CommandId.CTR_TASK_TERM,
                 CommandId.CTR_TASK_KILL, CommandId.CTR_TASK_REMOVE,
                 CommandId.CTR_CONTAINER_REMOVE, CommandId.SSH_READY,
                 CommandId.SSH_READINESS,
                 CommandId.SSH_KEYGEN_CLIENT, CommandId.SSH_KEYGEN_SERVER,
                 CommandId.SSH_PUBLIC_CLIENT, CommandId.SSH_PUBLIC_SERVER}
    return tuple((item.value, _spec(item).argv, _spec(item).stdin,
                  _spec(item).deadline_class, _spec(item).inherited_fds)
                 for item in CommandId if item in available)


def _fixed_spec_snapshots_v3_for_tests():
    rows = {item.command_id: item for item in kata_runtime.fixed_command_specs_v2()}
    return tuple((item.value, rows[item].argv, rows[item].stdin, rows[item].deadline_class, ())
                 for item in CommandId if item in rows)


# No public production execute/run function or caller-selectable command issuer.

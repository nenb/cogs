"""Private fixed process-transaction primitive for Stage 2 Kata.

This slice implements exact journaled fork/session/exec, settlement, and crash
recovery. It does not expose a production command issuer or lifecycle owner;
parsing a contract therefore grants no execution authority. Tests exercise the
private primitive with a fixed harmless executable descriptor.
"""
from dataclasses import dataclass
from enum import Enum
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import struct
import time
import completion_kata_actions as actions
import completion_kata_fdmap as fdmap
import completion_kata_network as kata_network
import completion_kata_operation as kata_operation
import completion_kata_runtime as kata_runtime
import completion_kata_ssh as kata_ssh

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
    "ssh": 10, "runtime-absence": 30,
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


CONTAINERD_SOCKET = kata_operation.BASE + "/kata-runtime-v1/containerd.sock"
CONTAINERD_ROOT = kata_operation.BASE + "/kata-runtime-v1/containerd-root"
CONTAINERD_STATE = kata_operation.BASE + "/kata-runtime-v1/containerd-state"
CONTAINERD_CONFIG = kata_operation.BASE + "/kata-runtime-v1/containerd.toml"
LONG_LIVED_CONTAINERD = LongLivedCommand(
    CommandId.CONTAINERD_START, "containerd", "/usr/bin/containerd",
    ("/usr/bin/containerd", "--address", CONTAINERD_SOCKET, "--root", CONTAINERD_ROOT,
     "--state", CONTAINERD_STATE, "--config", CONTAINERD_CONFIG),
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
        argv = ("/usr/bin/ctr", "--address", CONTAINERD_SOCKET, *source.argv[1:])
        rows[source.command_id] = FixedCommand(
            source.command_id, "ctr", "/usr/bin/ctr", argv, source.stdin,
            int(DEADLINE_SECONDS[source.deadline_class] * 1_000_000_000),
        )
    source = kata_ssh.command_spec()
    rows[CommandId.SSH_READY] = FixedCommand(
        CommandId.SSH_READY, "ssh", "/usr/bin/ssh", source.argv, source.stdin,
        10_000_000_000, output_grammar="text", inherited_fds=source.inherited_fds,
    )
    return rows


_FIXED_COMMANDS = _compose_fixed_commands()
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
    if command_id is CommandId.SSH_READY:
        deadline_class = "ssh"
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
    """Exact action bytes that intentionally contain no guessed argv[0]."""
    tails = {
        CommandId.IP_NETNS_ADD: ("ip", ("netns", "add", "cogs-stage2-ssh"), b""),
        CommandId.IP_LINK_ADD: ("ip", ("link", "add", "name", "c42h0", "address", "02:00:00:42:00:01", "type", "veth", "peer", "name", "c42g0", "address", "02:00:00:42:00:02"), b""),
        CommandId.IP_LINK_MOVE: ("ip", ("link", "set", "dev", "c42g0", "netns", "cogs-stage2-ssh"), b""),
        CommandId.IP_HOST_ADDRESS_ADD: ("ip", ("address", "add", "192.0.2.1/30", "dev", "c42h0"), b""),
        CommandId.IP_HOST_LINK_UP: ("ip", ("link", "set", "dev", "c42h0", "up"), b""),
        CommandId.IP_PEER_RENAME: ("ip", ("-n", "cogs-stage2-ssh", "link", "set", "dev", "c42g0", "name", "eth0"), b""),
        CommandId.IP_PEER_ADDRGEN_NONE: ("ip", ("-n", "cogs-stage2-ssh", "link", "set", "dev", "eth0", "addrgenmode", "none"), b""),
        CommandId.IP_LOOPBACK_UP: ("ip", ("-n", "cogs-stage2-ssh", "link", "set", "dev", "lo", "up"), b""),
        CommandId.IP_GUEST_ADDRESS_ADD: ("ip", ("-n", "cogs-stage2-ssh", "address", "add", "192.0.2.2/30", "dev", "eth0"), b""),
        CommandId.IP_GUEST_LINK_UP: ("ip", ("-n", "cogs-stage2-ssh", "link", "set", "dev", "eth0", "up"), b""),
        CommandId.NFT_INSTALL: ("nft", ("-f", "-"), NFT_INPUT),
        CommandId.NFT_REMOVE: ("nft", ("delete", "table", "inet", "cogs_stage2_ssh_v1"), b""),
    }
    if type(command_id) is not CommandId or command_id not in tails:
        raise ProcessError("closed unissued action required")
    tool, tail, stdin = tails[command_id]
    return _UnissuedSpec(command_id.value, tool, tail, stdin, "network")


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


def _child(executable_fd, spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r):
    try:
        (executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w,
         stdin_r) = _relocate_child_internals((
             executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r,
         ))
        os.setsid()
        report = struct.pack("!QQQQ", os.getpid(), os.getppid(), os.getpgrp(), os.getsid(0))
        os.write(setup_w, report)
        if spec.inherited_fds:
            _install_inherited_fds(spec.inherited_fds)
        os.dup2(stdin_r, 0)
        os.dup2(stdout_w, 1)
        os.dup2(stderr_w, 2)
        os.dup2(status_w, 3, inheritable=False)
        os.dup2(executable_fd, 198, inheritable=False)
        status_w = 3
        executable_fd = 198
        allowed = {0, 1, 2, 3, 198, release_r,
                   *(row.target_fd for row in spec.inherited_fds)}
        _close_except(allowed)
        if os.read(release_r, 1) != b"R":
            os._exit(125)
        _execveat(executable_fd, spec.argv)
    except OSError as error:
        _write_child_error(status_w, error.errno or errno.EIO)
    except BaseException:
        _write_child_error(status_w, errno.EIO)
    os._exit(126)


def _read_setup(descriptor, deadline):
    raw = b""
    while len(raw) < SETUP_SIZE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessError("child setup timeout")
        ready, _, _ = __import__("select").select([descriptor], [], [], remaining)
        if not ready:
            raise ProcessError("child setup timeout")
        part = os.read(descriptor, SETUP_SIZE - len(raw))
        if not part:
            raise ProcessError("incomplete child setup")
        raw += part
    return struct.unpack("!QQQQ", raw)


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


def _drain(pid, descriptors, absolute_deadline):
    selector = None
    buffers = {"stdout": bytearray(), "stderr": bytearray(), "status": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    errors = []
    wait_status = None
    child_done = False
    failure = None
    try:
        selector = selectors.DefaultSelector()
        for name, descriptor in descriptors.items():
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, name)
        while selector.get_map() or not child_done:
            if not child_done:
                observed_status, child_done = _wait_nohang(pid, errors, "drain-wait", absolute_deadline)
                if observed_status is not None:
                    wait_status = observed_status
            remaining = absolute_deadline - time.monotonic()
            if remaining <= 0:
                break
            events = selector.select(min(remaining, 0.05)) if selector.get_map() else ()
            for key, _mask in events:
                name = key.data
                try:
                    part = os.read(key.fd, 8192)
                except BlockingIOError:
                    continue
                except OSError as error:
                    errors.append(f"{name}-read:{error.errno}")
                    selector.unregister(key.fd)
                    continue
                if not part:
                    selector.unregister(key.fd)
                    continue
                limit = STATUS_SIZE if name == "status" else MAX_STREAM
                room = max(0, limit - len(buffers[name]))
                buffers[name].extend(part[:room])
                if name != "status" and len(part) > room:
                    truncated[name] = True
                if name == "status" and len(part) > room:
                    errors.append("invalid-exec-status")
        leader_timed_out = not child_done
        pipe_timed_out = child_done and bool(selector.get_map())
    except BaseException as error:
        failure = error
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError as error:
                errors.append(f"selector-close:{error.errno}")
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(f"drain-close:{error.errno}")
    if failure is not None:
        errors.insert(0, f"drain:{type(failure).__name__}:{failure}")
        raise ProcessError(";".join(errors)) from failure
    return buffers, truncated, wait_status, leader_timed_out, pipe_timed_out, errors


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


def _boottime_ns():
    return time.clock_gettime_ns(CLOCK)


def _require_no_children():
    with open(f"/proc/self/task/{os.getpid()}/children", "rb", buffering=0) as source:
        raw = source.read(65_537)
    if len(raw) > 65_536 or any(not row.isdigit() for row in raw.split()):
        raise ProcessError("invalid child baseline")
    if raw.split():
        raise ProcessError("process owner has unrelated children")


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
    return min(kata_operation.command_policy.CLEANUP_RESERVE_NS, fixed.duration_ns // 2)


def _intent_body(context, fixed, executable, bindings, deadline):
    if fixed is not _FIXED_COMMANDS.get(fixed.command_id):
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
    command_spec = _spec(fixed.command_id)
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
        "inherited_fds": inherited, "policy_version": kata_operation.command_policy.POLICY_VERSION,
        "deadline_class": command_spec.deadline_class, "duration_ns": fixed.duration_ns,
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


def _prepare_cgroup(context):
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
        with os.scandir(base_fd) as entries:
            if any(entry.is_dir(follow_symlinks=False) for entry in entries):
                raise ProcessError("cgroup base has an owned leaf")
        os.mkdir(leaf_name, 0o700, dir_fd=base_fd)
        leaf_created = True
        leaf_fd, leaf_generation = _directory_identity(CGROUP_BASE + "/" + leaf_name)
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
        _signal_cgroup(owner, signal.SIGTERM)
        state["term"] = True
    if now >= kill_at and not state["kill"] and members:
        _kill_cgroup(owner)
        state["kill"] = True
    return wait_status, members


def _read_setup_boottime(descriptor, deadline):
    raw = b""
    while len(raw) < SETUP_SIZE:
        remaining = deadline - _boottime_ns()
        if remaining <= 0:
            raise ProcessError("child setup timeout")
        ready, _, _ = __import__("select").select(
            [descriptor], [], [], remaining / 1_000_000_000,
        )
        if not ready:
            raise ProcessError("child setup timeout")
        part = os.read(descriptor, SETUP_SIZE - len(raw))
        if not part:
            raise ProcessError("incomplete child setup")
        raw += part
    return struct.unpack("!QQQQ", raw)


def _drain_transaction(pid, descriptors, stdin_bytes, owner, deadline, term_at, kill_at):
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray(), "status": bytearray()}
    overflow = {"stdout": False, "stderr": False}
    limits = {"stdout": descriptors.pop("stdout_limit"), "stderr": descriptors.pop("stderr_limit")}
    state = {"term": False, "kill": False}
    errors = []
    wait_status = None
    stdin_offset = 0
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


def _wait_all_children(leader_pid, errors):
    """Reap every waitable child and prove the subreaper has no child left."""
    leader_reaped = False
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


def _settle_cgroup(owner, leader_pid, deadline, errors):
    stable_empty = descendants_reaped = leader_reaped = False
    while _boottime_ns() < deadline:
        members = _cgroup_members(owner)
        if members:
            _kill_cgroup(owner)
        observed_leader, no_children = _wait_all_children(leader_pid, errors)
        leader_reaped = leader_reaped or observed_leader
        first_empty = not _cgroup_members(owner)
        stable_empty = first_empty and not _cgroup_members(owner)
        descendants_reaped = no_children
        if stable_empty and descendants_reaped:
            break
        time.sleep(0.005)
    for descriptor, _row in tuple(owner.pidfds.values()):
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(f"pidfd-close:{error.errno}")
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


def _transact_fixed(journal, fixed, executable, inherited=()):
    """Private T1 transaction; no executable, argv, environment, or deadline selector."""
    if fixed is not _FIXED_COMMANDS.get(fixed.command_id):
        raise ProcessError("internally fixed command required")
    if fixed.command_id is CommandId.CONTAINERD_START:
        raise ProcessError("long-lived containerd requires the runtime daemon owner")
    if not hasattr(signal, "pidfd_send_signal") or not hasattr(os, "pidfd_open"):
        raise ProcessError("usable pidfd signaling is required")
    context = kata_operation._command_context(journal)
    deadline = _boottime_ns() + fixed.duration_ns
    work_cutoff = deadline - _cleanup_reserve_ns(fixed)
    spec = _Spec(
        fixed.command_id.value, fixed.argv, fixed.stdin, "fixed",
        fixed.duration_ns / 1_000_000_000, fixed.inherited_fds,
    )
    bindings = _claim_inherited_fds(spec, inherited)
    intent = _intent_body(context, fixed, executable, bindings, deadline)
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
    try:
        _require_no_children()
        previous_subreaper = _set_subreaper(True)
        _within_work_cutoff(work_cutoff)
        owner = _prepare_cgroup(context)
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
            _child(executable.descriptor, child_spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r)
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
            "exec_status_pipe": _host_generation(status_r), "release_count": 0,
        }
        kata_operation._record_command_preexec(journal, preexec)
        preexec_recorded = True
        _within_work_cutoff(work_cutoff)
        if os.write(release_w, b"R") != 1:
            raise ProcessError("short release")
        release_count = 1
        os.close(release_w)
        pipes.remove(release_w)
        for descriptor in (status_r, stdout_r, stderr_r, stdin_w):
            pipes.remove(descriptor)
        term_at = max(_boottime_ns(), work_cutoff - 1_500_000_000)
        kill_at = max(term_at, work_cutoff - 250_000_000)
        buffers, overflow, wait_status, pipes_eof, state, drain_errors = _drain_transaction(
            pid, {"status": status_r, "stdout": stdout_r, "stderr": stderr_r,
                  "stdin": stdin_w, "stdout_limit": fixed.stdout_limit,
                  "stderr_limit": fixed.stderr_limit},
            fixed.stdin, owner, work_cutoff, term_at, kill_at,
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
        cleanup = _settle_cgroup(owner, pid, deadline, errors)
        try:
            _set_subreaper(previous_subreaper)
        except BaseException as error:
            errors.append(f"subreaper-restore:{type(error).__name__}")
        subreaper_restored = True
        if not _cleanup_closed(cleanup, pid, wait_status):
            raise ProcessError("cleanup continuation required")
        body = _outcome_body(
            intent, outcome, status, exec_errno, stdout, stderr, overflow,
            wait_status, pipes_eof, cleanup, state, errors, release_count,
        )
        durable = kata_operation._record_command_outcome(journal, body)
        return ProcessOutcome(
            fixed.command_id.value, identity, body["outcome"], body["status"], body["errno"],
            stdout, stderr, body["stdout_sha256"], body["stderr_sha256"],
            body["stdout_truncated"], body["stderr_truncated"],
            body["deadline_expired"],
            body["deadline_expired"] and not body["leader_reaped"], not pipes_eof,
            body["leader_reaped"], tuple(body["errors"]),
        ), durable
    except BaseException as primary:
        errors.append(f"primary:{type(primary).__name__}")
        for descriptor in tuple(pipes):
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(f"close:{error.errno}")
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
                    errors.append("leader-cleanup:unreaped")
            except BaseException as error:
                errors.append(f"leader-cleanup:{type(error).__name__}")
        cleanup = (owner is None, owner is None, owner is None, wait_status is not None)
        killed_cgroup = False
        if owner is not None:
            try:
                _kill_cgroup(owner)
                killed_cgroup = True
                cleanup = _settle_cgroup(owner, pid, deadline, errors)
            except BaseException as error:
                errors.append(f"cgroup-cleanup:{type(error).__name__}")
        if previous_subreaper is not None and not subreaper_restored:
            try:
                _set_subreaper(previous_subreaper)
            except BaseException as error:
                errors.append(f"subreaper-restore:{type(error).__name__}")
            subreaper_restored = True
        failure_state = {"term": False, "kill": killed_cgroup}
        failure_body = _outcome_body(
            intent, "uncertain" if preexec_recorded else "not-started", None, None,
            b"", b"", {"stdout": False, "stderr": False}, wait_status,
            False, cleanup, failure_state, errors,
            release_count if preexec_recorded else 0,
        )
        if _cleanup_closed(cleanup, pid, wait_status):
            try:
                kata_operation._record_command_outcome(journal, failure_body)
            except BaseException as journal_error:
                errors.append(f"outcome:{type(journal_error).__name__}")
        else:
            errors.append("cleanup-continuation-pending")
        raise ProcessError(";".join(errors)) from primary
    finally:
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                pass
        if previous_subreaper is not None and not subreaper_restored:
            try:
                _set_subreaper(previous_subreaper)
            except BaseException:
                pass


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
            os.close(owner.base_fd); owner.base_fd = None
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
            os.close(base_fd); base_fd = None
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


def _recover_pending_fixed(journal):
    """Cleanup-only crash continuation; absence never fabricates wait/reap proof."""
    if hasattr(journal, "recovery_command"):
        intent, preexec, terminal = kata_operation._recovery_command(journal)
    else:
        intent, preexec = kata_operation._pending_command(journal)
        terminal = None
    errors = ["crash-continuation"]
    state = {"term": False, "kill": False}
    path = f"{CGROUP_BASE}/{intent['operation_token']}-{intent['command_serial']}"
    expected = None if preexec is None else _generation_tuple(preexec["cgroup_generation"])
    deadline = _boottime_ns() + (4_000_000_000 if intent["command_id"] == "CONTAINERD_START" else 2_000_000_000)
    cgroup_deadline = deadline - 2_000_000_000 if intent["command_id"] == "CONTAINERD_START" else deadline
    cgroup_empty, cgroup_removed = _recover_cgroup(path, expected, cgroup_deadline, state, errors)
    closure = (cgroup_empty, False, cgroup_removed, False)
    if intent["command_id"] == "CONTAINERD_START" and preexec is not None:
        leader_reaped, descendants_reaped = _recover_daemon_reap(preexec, deadline, errors)
        closure = (cgroup_empty, descendants_reaped, cgroup_removed, leader_reaped)
    if terminal is not None:
        return kata_operation.DurableCommandOutcome(
            terminal["command_serial"], terminal["command_id"],
            terminal["binding_sha256"], terminal,
        )
    body = _outcome_body(
        intent, "not-started" if preexec is None else "uncertain", None, None,
        b"", b"", {"stdout": False, "stderr": False}, None, False,
        closure, state, errors, 0,
    )
    return kata_operation._record_command_outcome(journal, body)

def _test_spec(action):
    if type(action) is not _TestAction:
        raise ProcessError("closed test action required")
    timeout = 0.2 if action in {_TestAction.SLEEP, _TestAction.HELD_PIPE} else 5
    inherited = ((kata_ssh.KEY_FD, kata_ssh.KNOWN_HOSTS_FD)
                 if action is _TestAction.INHERITED else ())
    return _Spec("TEST_" + action.name, (TEST_PATH, action.value), b"", "test", timeout, inherited)


def _unissued_spec_snapshots_for_tests():
    commands = (
        CommandId.IP_NETNS_ADD, CommandId.IP_LINK_ADD, CommandId.IP_LINK_MOVE,
        CommandId.IP_HOST_ADDRESS_ADD, CommandId.IP_HOST_LINK_UP,
        CommandId.IP_PEER_RENAME, CommandId.IP_PEER_ADDRGEN_NONE,
        CommandId.IP_LOOPBACK_UP, CommandId.IP_GUEST_ADDRESS_ADD,
        CommandId.IP_GUEST_LINK_UP, CommandId.NFT_INSTALL, CommandId.NFT_REMOVE,
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
                 CommandId.CTR_CONTAINER_REMOVE, CommandId.SSH_READY}
    return tuple((item.value, _spec(item).argv, _spec(item).stdin,
                  _spec(item).deadline_class, _spec(item).inherited_fds)
                 for item in CommandId if item in available)


# Deliberately no production execute/run function and no operation CommandPermit issuer.

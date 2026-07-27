"""Closed process owner for the fixed Stage 2 Kata lifecycle.

No production command issuer exists in this slice.  In particular, parsing a
contract does not grant execution authority: the committed amd64 host-tool
closure and the operation journal's CommandPermit issuer are both absent.
The only issuer below is an explicitly test-only, fixed harmless executable
used to qualify the same fork/session/exec-status supervisor.
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
import sys
import time
import completion_kata_actions as actions
import completion_kata_runtime as kata_runtime
import completion_runtime_closure as runtime_closure
import completion_kata_fdmap as fdmap
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


@dataclass(frozen=True)
class HostElfObject:
    role: str
    soname: str | None
    size: int
    sha256: str
    needed: tuple[str, ...]


@dataclass(frozen=True)
class HostElfClosure:
    tool: str
    objects: tuple[HostElfObject, ...]
    total_bytes: int
    closure_sha256: str


@dataclass(frozen=True)
class ArchiveStreamIntent:
    component: str
    spec_sha256: str
    closure_sha256: str


@dataclass(frozen=True)
class ArchiveChildIdentity:
    component: str
    process: ProcessIdentity
    executable_device: int
    executable_inode: int
    spec_sha256: str
    closure_sha256: str


@dataclass(frozen=True)
class ArchiveStreamOutcome:
    identity: ArchiveChildIdentity
    status: int
    stdout_bytes: int
    stderr_sha256: str
    descendants_absent: bool
    reaped: bool
    errors: tuple[str, ...]


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
    if type(command_id) is not CommandId:
        raise ProcessError("closed command id required")
    # ip/tc/nft argv[0] cannot be guessed: the plan fixes their argument tails
    # but the required absolute logical paths await the committed host closure.
    ctr = "/usr/bin/ctr"
    fixed = {
        CommandId.CTR_CONTAINER_INFO: ((ctr, "--namespace", "cogs-stage2-completion-v1", "containers", "info", "cogs-stage2-ssh-v1"), b"", "observer"),
        CommandId.CTR_CONTAINER_LIST: ((ctr, "--namespace", "cogs-stage2-completion-v1", "containers", "list"), b"", "observer"),
        CommandId.CTR_TASK_LIST: ((ctr, "--namespace", "cogs-stage2-completion-v1", "tasks", "list"), b"", "observer"),
        CommandId.CTR_TASK_TERM: ((ctr, "--namespace", "cogs-stage2-completion-v1", "tasks", "kill", "--signal", "SIGTERM", "cogs-stage2-ssh-v1"), b"", "task-term"),
        CommandId.CTR_TASK_KILL: ((ctr, "--namespace", "cogs-stage2-completion-v1", "tasks", "kill", "--signal", "SIGKILL", "cogs-stage2-ssh-v1"), b"", "task-kill"),
        CommandId.CTR_TASK_REMOVE: ((ctr, "--namespace", "cogs-stage2-completion-v1", "tasks", "rm", "cogs-stage2-ssh-v1"), b"", "remove"),
        CommandId.CTR_CONTAINER_REMOVE: ((ctr, "--namespace", "cogs-stage2-completion-v1", "containers", "rm", "cogs-stage2-ssh-v1"), b"", "remove"),
    }
    if command_id is CommandId.SSH_READY:
        fixed_ssh = kata_ssh.command_spec()
        return _Spec(command_id.value, fixed_ssh.argv, fixed_ssh.stdin,
                     fixed_ssh.deadline_class, DEADLINE_SECONDS["ssh"], fixed_ssh.inherited_fds)
    if command_id not in fixed:
        raise ProcessError("fixed action awaits its committed closure/spec composition")
    argv, stdin, deadline = fixed[command_id]
    return _Spec(command_id.value, argv, stdin, deadline, DEADLINE_SECONDS[deadline])


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
_seal_inherited_inputs_for_tests = fdmap.make_input_owner_for_tests
_install_inherited_fds = fdmap.install
_relocate_child_internals = fdmap.relocate_internals


def _claim_inherited_fds(spec, owner):
    try:
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
    environment = (ctypes.c_char_p * 2)(b"LC_ALL=C", None)
    result = libc.syscall(322, descriptor, b"", arguments, environment, 0x1000)
    saved = ctypes.get_errno()
    if result != 0:
        raise OSError(saved, os.strerror(saved))


def _set_parent_death_signal(expected_parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    if os.getppid() != expected_parent:
        raise OSError(errno.ESRCH, "archive parent changed during setup")


def _child(executable_fd, spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r,
           expected_parent=None):
    try:
        (executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w,
         stdin_r) = _relocate_child_internals((
             executable_fd, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r,
         ))
        if expected_parent is not None:
            _set_parent_death_signal(expected_parent)
        os.setsid()
        report = struct.pack("!QQQQ", os.getpid(), os.getppid(), os.getpgrp(), os.getsid(0))
        os.write(setup_w, report)
        if spec.inherited_fds:
            _install_inherited_fds(spec.inherited_fds)
        os.dup2(stdin_r, 0)
        os.dup2(stdout_w, 1)
        os.dup2(stderr_w, 2)
        allowed = {0, 1, 2, executable_fd, release_r, status_w,
                   *(row.target_fd for row in spec.inherited_fds)}
        _close_except(allowed)
        if os.read(release_r, 1) != b"R":
            os._exit(125)
        if expected_parent is not None and os.getppid() != expected_parent:
            os._exit(125)
        os.set_inheritable(status_w, False)
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


def _cleanup_child(pid, identity, wait_status, released):
    """Nonthrowing bounded cleanup for the one directly-owned child."""
    errors = []
    try:
        wait_status, done = _poll_reap(pid, wait_status, 0.1, errors, "cleanup-wait")
        if done:
            return wait_status, errors
        if not released or identity is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError as error:
                errors.append(f"direct-kill:{error.errno}")
        else:
            state = _same_identity(identity)
            if state == "exact_live":
                try:
                    os.killpg(identity.pgid, signal.SIGTERM)
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
                    os.killpg(identity.pgid, signal.SIGKILL)
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


def _supervise(executable_fd, spec, inherited=None):
    bindings = _claim_inherited_fds(spec, inherited) if spec.inherited_fds else ()
    if not spec.inherited_fds and inherited is not None:
        raise ProcessError("unexpected inherited descriptors")
    spec = _Spec(spec.command_id, spec.argv, spec.stdin, spec.deadline_class,
                 spec.deadline_seconds, bindings)
    pipes = []
    def owned_pipe():
        pair = os.pipe2(os.O_CLOEXEC)
        pipes.extend(pair)
        return pair
    pid = None
    identity = None
    pidfd = None
    errors = []
    wait_status = None
    released = False
    try:
        release_r, release_w = owned_pipe()
        setup_r, setup_w = owned_pipe()
        status_r, status_w = owned_pipe()
        stdout_r, stdout_w = owned_pipe()
        stderr_r, stderr_w = owned_pipe()
        stdin_r, stdin_w = owned_pipe()
        pid = os.fork()
        if pid == 0:
            _child(executable_fd, spec, release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r)
        for descriptor in (release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r):
            _close_owned(descriptor, pipes, errors)
        if spec.stdin and os.write(stdin_w, spec.stdin) != len(spec.stdin):
            raise ProcessError("short fixed stdin write")
        _close_owned(stdin_w, pipes, errors)
        report = _read_setup(setup_r, time.monotonic() + 5)
        _close_owned(setup_r, pipes, errors)
        identity, pidfd = _identity(pid, report)
        if os.write(release_w, b"R") != 1:
            raise ProcessError("release failed")
        released = True
        _close_owned(release_w, pipes, errors)
        drain_fds = {"status": status_r, "stdout": stdout_r, "stderr": stderr_r}
        for descriptor in drain_fds.values():
            pipes.remove(descriptor)
        drained = _drain(pid, drain_fds, time.monotonic() + spec.deadline_seconds)
        buffers, truncated, wait_status, leader_timed_out, pipe_timed_out, drain_errors = drained
        errors.extend(drain_errors)
        if leader_timed_out or pipe_timed_out:
            wait_status, cleanup_errors = _cleanup_child(pid, identity, wait_status, released)
            errors.extend(cleanup_errors)
        if leader_timed_out:
            errors.append("leader-deadline")
        if pipe_timed_out:
            errors.append("pipe-deadline")
        status_raw = bytes(buffers["status"])
        if status_raw and len(status_raw) != STATUS_SIZE:
            errors.append("invalid-exec-status")
        exec_errno = struct.unpack("!I", status_raw)[0] if len(status_raw) == STATUS_SIZE else None
        stdout = bytes(buffers["stdout"])
        stderr = bytes(buffers["stderr"])
        if truncated["stdout"] or truncated["stderr"]:
            errors.append("output-cap")
        if pidfd is not None:
            _close_owned(pidfd, [pidfd], errors, "pidfd-close")
            pidfd = None
        if pipe_timed_out or wait_status is None:
            outcome, status = "uncertain", None
        elif exec_errno is not None:
            outcome, status = "exec_failed", None
        elif os.WIFEXITED(wait_status):
            outcome, status = "exited", os.WEXITSTATUS(wait_status)
            if status != 0:
                errors.append(f"exit:{status}")
        elif os.WIFSIGNALED(wait_status):
            outcome, status = "signaled", os.WTERMSIG(wait_status)
        else:
            outcome, status = "uncertain", None
            errors.append("unknown-wait-status")
        timed_out = leader_timed_out or pipe_timed_out
        return ProcessOutcome(spec.command_id, identity, outcome, status, exec_errno, stdout, stderr,
                              hashlib.sha256(stdout).hexdigest(), hashlib.sha256(stderr).hexdigest(),
                              truncated["stdout"], truncated["stderr"], timed_out,
                              leader_timed_out, pipe_timed_out, wait_status is not None, tuple(errors))
    except BaseException as primary:
        errors.append(f"primary:{type(primary).__name__}:{primary}")
        for descriptor in tuple(pipes):
            _close_owned(descriptor, pipes, errors)
        if pid:
            wait_status, cleanup_errors = _cleanup_child(pid, identity, wait_status, released)
            errors.extend(cleanup_errors)
        if pidfd is not None:
            _close_owned(pidfd, [pidfd], errors, "pidfd-close")
            pidfd = None
        raise ProcessError(";".join(errors)) from primary
    finally:
        for descriptor in tuple(pipes):
            _close_owned(descriptor, pipes, errors)
        if pidfd is not None:
            _close_owned(pidfd, [pidfd], errors, "pidfd-close")


def _test_spec(action):
    if type(action) is not _TestAction:
        raise ProcessError("closed test action required")
    timeout = 0.2 if action in {_TestAction.SLEEP, _TestAction.HELD_PIPE} else 5
    inherited = ((kata_ssh.KEY_FD, kata_ssh.KNOWN_HOSTS_FD)
                 if action is _TestAction.INHERITED else ())
    return _Spec("TEST_" + action.name, (TEST_PATH, action.value), b"", "test", timeout, inherited)


def _make_test_issuer(contract_raw, expected_sha256):
    """Test-only closure issuer; it has no production CommandPermit route."""
    if os.environ.get("COGS_KATA_PROCESS_TESTING_V1") != "1" or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ProcessError("test issuer is disabled")
    contract = _parse_contract(contract_raw, expected_sha256)
    if contract.command_id != "TEST_HELPER" or contract.executable.logical_path != TEST_PATH or contract.loader is not None or contract.libraries:
        raise ProcessError("not the fixed static test closure")
    executable_fd = _sealed_memfd(contract.executable, True)
    used = False

    def issue(action, inherited=None):
        nonlocal used
        if used:
            raise ProcessError("test authority already consumed")
        used = True
        try:
            return _supervise(executable_fd, _test_spec(action), inherited)
        finally:
            os.close(executable_fd)

    return issue


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


_HOST_TOOLS = (
    ("python3-parser", "/usr/bin/python3"),
    ("zstd", "/usr/bin/zstd"),
    ("gzip", "/usr/bin/gzip"),
)
_HOST_SEARCH = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64")
_HOST_INTERP = "/lib64/ld-linux-x86-64.so.2"
_ARCHIVE_ARGV = {
    kata_runtime.FixedArchive.KATA_ZSTD: ("zstd", "--decompress", "--stdout", "--no-progress"),
    kata_runtime.FixedArchive.CONTAINERD_GZIP: ("gzip", "--decompress", "--stdout"),
}
_DISCOVERY_FDS = set()
_DISCOVERY_CHILDREN = set()


@dataclass
class _HostBound:
    path: str
    descriptor: int
    generation: tuple
    raw: bytes
    interpreter: str | None
    soname: str | None
    needed: tuple[str, ...]


def _host_resolve(path):
    """Resolve one of the compile-time absolute host paths for preflight only."""
    if type(path) is not str or not path.startswith("/") or "\0" in path:
        raise ProcessError("fixed absolute host path required")
    resolved = os.path.realpath(path)
    if not resolved.startswith("/"):
        raise ProcessError("host path resolution")
    return resolved


def _host_read(path):
    try:
        resolved = _host_resolve(path)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ProcessError(f"fixed host object unavailable:{path}") from error
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or not 1 <= before.st_size <= 128 * 1024 * 1024):
            raise ProcessError("host object policy")
        raw = bytearray()
        while len(raw) < before.st_size:
            part = os.read(descriptor, min(1_048_576, before.st_size - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        generation = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if len(raw) != before.st_size or generation != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ProcessError("host object drift")
        try:
            interpreter, soname, needed = runtime_closure._elf(bytes(raw))
        except runtime_closure.RuntimeClosureError as error:
            raise ProcessError("host ELF rejected") from error
        _DISCOVERY_FDS.add(descriptor)
        return _HostBound(resolved, descriptor, generation, bytes(raw), interpreter, soname, needed)
    except BaseException:
        os.close(descriptor)
        raise


def _host_library(name, cache):
    if type(name) is not str or SONAME.fullmatch(name) is None:
        raise ProcessError("dependency SONAME")
    candidates = []
    for directory in _HOST_SEARCH:
        path = directory + "/" + name
        try:
            bound = _host_read(path)
        except ProcessError as error:
            if isinstance(error.__cause__, FileNotFoundError):
                continue
            raise
        if bound.soname != name:
            _close_host_bound(bound)
            raise ProcessError("dependency SONAME mismatch")
        same = None
        for candidate in candidates:
            if candidate.generation[:2] == bound.generation[:2]:
                same = candidate
                break
        if same is None:
            candidates.append(bound)
        else:
            _close_host_bound(bound)
    if len(candidates) != 1:
        for item in candidates:
            _close_host_bound(item)
        raise ProcessError("ambiguous host dependency")
    bound = candidates[0]
    prior = cache.get(bound.path)
    if prior is not None:
        _close_host_bound(bound)
        return prior
    cache[bound.path] = bound
    return bound


def _close_host_bound(bound):
    descriptor = bound.descriptor
    if descriptor >= 0:
        try:
            os.close(descriptor)
        finally:
            _DISCOVERY_FDS.discard(descriptor)
            bound.descriptor = -1


def _close_descriptors(descriptors, label):
    failures = []
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException as error:
            failures.append(f"fd={descriptor}:{type(error).__name__}:{error}")
    if failures:
        raise ProcessError(label + ":" + ";".join(failures))


def _close_host_bounds(bounds, label):
    failures = []
    for bound in tuple(bounds):
        try:
            _close_host_bound(bound)
        except BaseException as error:
            failures.append(f"path={bound.path}:{type(error).__name__}:{error}")
    if failures:
        raise ProcessError(label + ":" + ";".join(failures))


def _host_closure(tool, root_path):
    cache = {}
    try:
        root = _host_read(root_path)
        cache[root.path] = root
        if root.interpreter != _HOST_INTERP:
            raise ProcessError("fixed host interpreter")
        if tool == "python3-parser" and _host_resolve(sys.executable) != root.path:
            raise ProcessError("running Python is not fixed /usr/bin/python3")
        loader = _host_read(_HOST_INTERP)
        cache[loader.path] = loader
        pending = list(root.needed) + list(loader.needed)
        while pending:
            name = pending.pop(0)
            if any(item.soname == name for item in cache.values()):
                continue
            dependency = _host_library(name, cache)
            pending.extend(dependency.needed)
            if len(cache) > 128:
                raise ProcessError("host closure object bound")
        roles = {root.path: "executable", loader.path: "loader"}
        discovered = []
        for item in cache.values():
            role = roles.get(item.path, "library")
            discovered.append(HostElfObject(
                role, item.soname, len(item.raw),
                hashlib.sha256(item.raw).hexdigest(), item.needed))
        objects = tuple(sorted(
            discovered, key=lambda item: (item.role, item.soname or "", item.sha256)))
        total = sum(item.size for item in objects)
        if total > MAX_ARTIFACT_BYTES:
            raise ProcessError("host closure byte bound")
        rows = []
        for item in objects:
            rows.append({
                "needed": list(item.needed),
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
                "soname": item.soname,
            })
        digest = hashlib.sha256(_canonical(rows)).hexdigest()
        return HostElfClosure(tool, objects, total, digest), cache, root
    except BaseException as primary:
        try:
            _close_host_bounds(cache.values(), "host closure close")
        except ProcessError as close_failure:
            raise close_failure from primary
        raise


def _sealed_bound(bound):
    artifact = _Artifact("executable", bound.path, None, len(bound.raw),
                         hashlib.sha256(bound.raw).hexdigest())
    descriptor = _sealed_memfd(artifact, True)
    _DISCOVERY_FDS.add(descriptor)
    return descriptor


def _read_descriptor(descriptor, size):
    raw = bytearray()
    while len(raw) < size:
        part = os.pread(descriptor, min(1_048_576, size - len(raw)), len(raw))
        if not part:
            break
        raw.extend(part)
    if len(raw) != size:
        raise ProcessError("short mapped ELF read")
    return bytes(raw)


def _wait_for_preinput_read(pid, deadline_ns):
    proc = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if not os.readlink("fd/0", dir_fd=proc).startswith("pipe:"):
            raise ProcessError("archive stdin is not gated")
        while time.monotonic_ns() < deadline_ns:
            descriptor = os.open("syscall", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
            try:
                raw = os.read(descriptor, 4096)
            finally:
                os.close(descriptor)
            fields = raw.split()
            if len(fields) >= 2 and fields[0] == b"0" and int(fields[1], 0) == 0:
                return
            time.sleep(0.001)
    except (OSError, ValueError) as error:
        raise ProcessError("archive pre-input handshake unavailable") from error
    finally:
        os.close(proc)
    raise ProcessError("archive pre-input handshake timeout")


def _mapped_closure(pid, expected, require_expected=True):
    proc = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptors = []
    try:
        maps_fd = os.open("maps", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
        descriptors.append(maps_fd)
        maps_before = os.read(maps_fd, 4 * 1024 * 1024)
        time.sleep(0.01)
        executable = os.stat("exe", dir_fd=proc)
        objects = []
        seen = set()
        for line in maps_before.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 5 or b"x" not in fields[1]:
                continue
            if fields[4] == b"0":
                if len(fields) == 6:
                    synthetic = fields[5]
                else:
                    synthetic = b""
                if synthetic not in {b"[vdso]", b"[vsyscall]"}:
                    raise ProcessError("unopenable executable mapping")
                continue
            address = fields[0].decode("ascii")
            map_fd = os.open("map_files/" + address, os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
            descriptors.append(map_fd)
            observed = os.fstat(map_fd)
            key = (observed.st_dev, observed.st_ino)
            if key in seen:
                continue
            seen.add(key)
            if not stat.S_ISREG(observed.st_mode) or not 1 <= observed.st_size <= 128 * 1024 * 1024:
                raise ProcessError("mapped ELF policy")
            raw = _read_descriptor(map_fd, observed.st_size)
            after = os.fstat(map_fd)
            if (observed.st_dev, observed.st_ino, observed.st_size,
                    observed.st_mtime_ns, observed.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns):
                raise ProcessError("mapped ELF changed")
            try:
                _interpreter, soname, needed = runtime_closure._elf(raw)
            except runtime_closure.RuntimeClosureError as error:
                raise ProcessError("mapped executable is not ELF") from error
            fingerprint = (observed.st_size, hashlib.sha256(raw).hexdigest(), soname, needed)
            if key == (executable.st_dev, executable.st_ino):
                role = "executable"
            else:
                role = None
            candidates = []
            for item in expected.objects:
                expected_fingerprint = (item.size, item.sha256, item.soname, item.needed)
                if expected_fingerprint == fingerprint:
                    candidates.append(item.role)
            if role is None and len(candidates) == 1:
                role = candidates[0]
            if role is None and not require_expected:
                role = "library"
            if role not in {"executable", "loader", "library"}:
                raise ProcessError("unreported executable mapping")
            objects.append(HostElfObject(role, soname, observed.st_size,
                                         fingerprint[1], needed))
        actual = tuple(sorted(objects, key=lambda item: (item.role, item.soname or "", item.sha256)))
        if require_expected and actual != expected.objects:
            raise ProcessError("actual mapped closure mismatch")
        if len(actual) > 128 or sum(item.size for item in actual) > MAX_ARTIFACT_BYTES:
            raise ProcessError("actual mapped closure bound")
        if sum(item.role == "executable" for item in actual) != 1:
            raise ProcessError("actual executable mapping cardinality")
        if sum(item.role == "loader" for item in actual) != 1:
            raise ProcessError("actual loader mapping cardinality")
        sonames = set()
        for item in actual:
            if item.soname is not None:
                sonames.add(item.soname)
        if any(not set(item.needed) <= sonames for item in actual):
            raise ProcessError("actual mapped dependency absent")
        maps_after_fd = os.open("maps", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
        descriptors.append(maps_after_fd)
        maps_after = os.read(maps_after_fd, 4 * 1024 * 1024)
        if maps_after != maps_before:
            raise ProcessError("executable maps changed during binding")
        if require_expected:
            return expected
        rows = []
        for item in actual:
            rows.append({
                "needed": list(item.needed),
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
                "soname": item.soname,
            })
        digest = hashlib.sha256(_canonical(rows)).hexdigest()
        return HostElfClosure(expected.tool, actual, sum(item.size for item in actual), digest)
    except OSError as error:
        raise ProcessError("actual mapped closure unavailable") from error
    finally:
        close_order = tuple(reversed(descriptors)) + (proc,)
        _close_descriptors(close_order, "mapped closure close")


def _archive_processes(identity):
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise ProcessError("incomplete proc enumeration") from error
    found = []
    expected = (identity.pid, identity.ppid, identity.pgid, identity.sid, identity.starttime)
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            row = _proc_row(pid)
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH}:
                continue
            raise ProcessError("unreadable proc row") from error
        except (ProcessError, ValueError) as error:
            raise ProcessError("malformed proc row") from error
        related = pid == identity.pid or row[2] == identity.pgid or row[3] == identity.sid
        if not related:
            continue
        if pid == identity.pid and not (row == expected or row[2:] == expected[2:]):
            raise ProcessError("archive leader identity drift")
        if pid != identity.pid and (row[3] != identity.sid or row[4] < identity.starttime):
            raise ProcessError("archive session identity collision")
        try:
            executable = os.stat(f"/proc/{pid}/exe")
            executable_key = (executable.st_dev, executable.st_ino)
        except OSError as error:
            if error.errno not in {errno.ENOENT, errno.ESRCH}:
                raise ProcessError("archive executable unreadable") from error
            executable_key = None
        found.append((row, executable_key))
    return tuple(sorted(found))


def _signal_archive_processes(identity, snapshots, sig, leader_executable=None):
    current = {}
    for row, executable in _archive_processes(identity):
        current[row[0]] = (row, executable)
    for row, executable in snapshots:
        fresh = current.get(row[0])
        if fresh != (row, executable):
            if fresh is None:
                continue
            raise ProcessError("archive identity changed before signal")
        if row[0] == identity.pid and leader_executable is not None and executable != leader_executable:
            raise ProcessError("archive executable changed before signal")
        try:
            os.kill(row[0], sig)
        except OSError as error:
            if error.errno != errno.ESRCH:
                raise ProcessError("archive exact PID signal failed") from error


def _cleanup_archive_child(pid, identity, wait_status, released, deadline_ns,
                           leader_executable=None):
    errors = []
    end = min(deadline_ns / 1e9, time.monotonic() + 0.1)
    while wait_status is None and time.monotonic() < end:
        wait_status, done = _wait_nohang(pid, errors, "archive-cleanup", end)
        if done:
            break
        time.sleep(0.01)
    try:
        if identity is None:
            snapshots = ()
        else:
            snapshots = _archive_processes(identity)
        if snapshots:
            if released:
                first_signal = signal.SIGTERM
            else:
                first_signal = signal.SIGKILL
            _signal_archive_processes(identity, snapshots, first_signal, leader_executable)
        for sig, delay in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 1.0)):
            end = min(deadline_ns / 1e9, time.monotonic() + delay)
            while time.monotonic() < end:
                if identity is None or not _archive_processes(identity):
                    break
                time.sleep(0.01)
            if identity is None:
                snapshots = ()
            else:
                snapshots = _archive_processes(identity)
            if not snapshots:
                break
            _signal_archive_processes(identity, snapshots, sig, leader_executable)
        if identity is not None and _archive_processes(identity):
            errors.append("archive-session-present")
    except BaseException as error:
        errors.append(f"archive-process-cleanup:{type(error).__name__}:{error}")
    if wait_status is None:
        wait_status, reaped = _poll_reap(pid, None, 1, errors, "archive-kill-wait")
        if not reaped:
            errors.append("archive-child-unreaped")
    return wait_status, errors


class _FixedArchiveStream:
    __slots__ = ("_owner", "_asset", "_intent", "_started", "_settled", "_deadline_ns",
                 "_fds", "_selector", "_pid", "_identity", "_archive_identity", "_wait",
                 "_released", "_stdout", "_stderr", "_stderr_bytes", "_errors", "_eof",
                 "_closed", "_descendants", "_archive_fd", "_archive_generation",
                 "_archive_size", "_input_read", "_input_written", "_input_pending")

    def __init__(self, owner, asset, archive_fd, intent, started, settled, deadline_ns):
        if type(asset) is not kata_runtime.FixedArchive:
            raise ProcessError("fixed archive stream arguments")
        if type(archive_fd) is not int:
            raise ProcessError("fixed archive stream arguments")
        if not callable(intent) or not callable(started) or not callable(settled):
            raise ProcessError("fixed archive stream arguments")
        if type(deadline_ns) is not int or isinstance(deadline_ns, bool):
            raise ProcessError("fixed archive stream arguments")
        if deadline_ns <= time.monotonic_ns():
            raise ProcessError("fixed archive stream arguments")
        self._owner = owner
        self._asset = asset
        self._intent = intent
        self._started = started
        self._settled = settled
        self._deadline_ns = deadline_ns
        self._fds = []
        self._selector = selectors.DefaultSelector()
        self._pid = None
        self._identity = None
        self._archive_identity = None
        self._wait = None
        self._released = False
        self._stdout = 0
        self._stderr = hashlib.sha256()
        self._stderr_bytes = 0
        self._errors = []
        self._eof = False
        self._closed = False
        self._descendants = True
        self._archive_fd = os.dup(archive_fd)
        self._fds.append(self._archive_fd)
        observed = os.fstat(self._archive_fd)
        self._archive_generation = (observed.st_dev, observed.st_ino, observed.st_size,
                                    observed.st_mtime_ns, observed.st_ctime_ns)
        self._archive_size = observed.st_size
        self._input_read = 0
        self._input_written = 0
        self._input_pending = b""
        os.lseek(self._archive_fd, 0, os.SEEK_SET)
        self._start()

    def _pipe(self):
        pair = os.pipe2(os.O_CLOEXEC)
        self._fds.extend(pair)
        return pair

    def _close_fd(self, descriptor, label="archive-close"):
        if descriptor in self._fds:
            _close_owned(descriptor, self._fds, self._errors, label)

    @staticmethod
    def _durable_digest(callback, value, label):
        digest = callback(value)
        if type(digest) is not str or len(digest) != 64 or not set(digest) <= HEX:
            raise ProcessError(label + " callback was not durable")
        return digest

    def _wait_for_exec(self, status_r):
        deadline = min(time.monotonic() + 5, self._deadline_ns / 1e9)
        while time.monotonic() < deadline:
            ready, _, _ = __import__("select").select([status_r], [], [], deadline - time.monotonic())
            if not ready:
                continue
            raw = os.read(status_r, STATUS_SIZE)
            if raw:
                if len(raw) != STATUS_SIZE:
                    raise ProcessError("invalid archive exec status")
                code = struct.unpack("!I", raw)[0]
                raise ProcessError(f"archive exec failed:{code}:{os.strerror(code)}")
            return
        raise ProcessError("archive exec handshake timeout")

    def _start(self):
        executable = self._owner._executables[self._asset]
        if self._asset is kata_runtime.FixedArchive.KATA_ZSTD:
            closure_index = 1
        else:
            closure_index = 2
        closure = self._owner._closures[closure_index]
        spec = _Spec("RUNTIME_DISCOVERY_" + self._asset.value.upper(), _ARCHIVE_ARGV[self._asset],
                     b"", "runtime-discovery", 0)
        spec_body = {"argv": list(spec.argv), "component": self._asset.value,
                     "environment": ["LC_ALL=C"], "stdin": "parent-pipe"}
        spec_sha = hashlib.sha256(_canonical(spec_body)).hexdigest()
        stream_intent = ArchiveStreamIntent(self._asset.value, spec_sha, closure.closure_sha256)
        self._durable_digest(self._intent, stream_intent, "intent")

        release_r, release_w = self._pipe()
        setup_r, setup_w = self._pipe()
        status_r, status_w = self._pipe()
        stdout_r, stdout_w = self._pipe()
        stderr_r, stderr_w = self._pipe()
        stdin_r, stdin_w = self._pipe()
        expected_parent = os.getpid()
        self._pid = os.fork()
        if self._pid == 0:
            _child(executable, spec, release_r, setup_w, status_w, stdout_w, stderr_w,
                   stdin_r, expected_parent)
        _DISCOVERY_CHILDREN.add(self._pid)
        child_descriptors = (release_r, setup_w, status_w, stdout_w, stderr_w, stdin_r)
        for descriptor in child_descriptors:
            self._close_fd(descriptor)
        try:
            setup_deadline = min(time.monotonic() + 5, self._deadline_ns / 1e9)
            report = _read_setup(setup_r, setup_deadline)
            self._close_fd(setup_r)
            self._identity, pidfd = _identity(self._pid, report)
            if self._identity.ppid != expected_parent:
                raise ProcessError("archive parent handshake mismatch")
            if pidfd is not None:
                self._fds.append(pidfd)
            executable_generation = os.fstat(executable)
            self._archive_identity = ArchiveChildIdentity(
                self._asset.value, self._identity, executable_generation.st_dev,
                executable_generation.st_ino, spec_sha, closure.closure_sha256)
            self._durable_digest(self._started, self._archive_identity, "started")
            try:
                released = os.write(release_w, b"R")
            except BrokenPipeError:
                try:
                    self._wait_for_exec(status_r)
                except ProcessError as error:
                    raise error from None
                raise ProcessError("archive child closed release pipe") from None
            if released != 1:
                raise ProcessError("archive release")
            self._released = True
            self._close_fd(release_w)
            self._wait_for_exec(status_r)
            self._close_fd(status_r)
            _wait_for_preinput_read(self._pid, self._deadline_ns)
            _mapped_closure(self._pid, closure)
            for name, descriptor, events in (
                    ("stdin", stdin_w, selectors.EVENT_WRITE),
                    ("stdout", stdout_r, selectors.EVENT_READ),
                    ("stderr", stderr_r, selectors.EVENT_READ)):
                self._fds.remove(descriptor)
                os.set_blocking(descriptor, False)
                self._selector.register(descriptor, events, name)
        except BaseException:
            self._close_fd(release_w)
            self.close()
            raise

    def _pump_input(self, descriptor):
        if not self._input_pending and self._input_read < self._archive_size:
            count = min(65_536, self._archive_size - self._input_read)
            self._input_pending = os.read(self._archive_fd, count)
            if not self._input_pending:
                raise ProcessError("archive input ended early")
            self._input_read += len(self._input_pending)
        if self._input_pending:
            try:
                written = os.write(descriptor, self._input_pending)
            except BlockingIOError:
                return
            self._input_pending = self._input_pending[written:]
            self._input_written += written
        if self._input_written == self._archive_size and not self._input_pending:
            self._selector.unregister(descriptor)
            os.close(descriptor)

    def _read_output(self, key):
        try:
            part = os.read(key.fd, 65_536)
        except BlockingIOError:
            return None
        if not part:
            self._selector.unregister(key.fd)
            os.close(key.fd)
            if key.data == "stdout":
                self._eof = True
            return None
        if key.data == "stdout":
            self._stdout += len(part)
            return part
        self._stderr.update(part)
        self._stderr_bytes += len(part)
        if self._stderr_bytes > MAX_STREAM:
            self._errors.append("stderr-cap")
            raise ProcessError("archive stderr cap")
        return None

    def read(self):
        if self._closed or self._eof:
            return b""
        while not self._eof:
            if time.monotonic_ns() >= self._deadline_ns:
                self._errors.append("archive-deadline")
                raise ProcessError("archive deadline")
            live = _archive_processes(self._identity)
            self._descendants = self._descendants and len(live) <= 1
            timeout = min(0.05, (self._deadline_ns - time.monotonic_ns()) / 1e9)
            for key, _mask in self._selector.select(timeout):
                if key.data == "stdin":
                    self._pump_input(key.fd)
                    continue
                part = self._read_output(key)
                if part is not None:
                    return part
            if self._wait is None:
                status, _done = _wait_nohang(
                    self._pid, self._errors, "archive-wait", time.monotonic() + 0.001)
                if status is not None:
                    self._wait = status
        return b""

    def _close_selector(self):
        for key in tuple(self._selector.get_map().values()):
            try:
                os.close(key.fd)
            except OSError as error:
                self._errors.append(f"archive-io-close:{error.errno}")
        try:
            self._selector.close()
        except OSError as error:
            self._errors.append(f"archive-selector-close:{error.errno}")

    def settle(self):
        if self._closed or not self._eof:
            raise ProcessError("archive stream not completely read")
        while self._selector.get_map() and time.monotonic_ns() < self._deadline_ns:
            for key, _mask in self._selector.select(0.05):
                if key.data == "stdin":
                    self._pump_input(key.fd)
                else:
                    self._read_output(key)
        if self._selector.get_map():
            self._errors.append("archive-pipe-deadline")
        if self._input_written != self._archive_size:
            self._errors.append("archive-input-incomplete")
        if self._wait is None:
            seconds = max(0, (self._deadline_ns - time.monotonic_ns()) / 1e9)
            self._wait, reaped = _poll_reap(
                self._pid, None, seconds, self._errors, "archive-reap")
        else:
            reaped = True
        self._descendants = self._descendants and not _archive_processes(self._identity)
        self._owner._revalidate()
        current = os.fstat(self._archive_fd)
        current_generation = (current.st_dev, current.st_ino, current.st_size,
                              current.st_mtime_ns, current.st_ctime_ns)
        if current_generation != self._archive_generation:
            self._errors.append("archive-input-changed")
        if self._wait is None:
            status = -1
        elif os.WIFEXITED(self._wait):
            status = os.WEXITSTATUS(self._wait)
        elif os.WIFSIGNALED(self._wait):
            status = 128 + os.WTERMSIG(self._wait)
        else:
            status = -1
        self._close_selector()
        for descriptor in tuple(self._fds):
            self._close_fd(descriptor)
        _DISCOVERY_CHILDREN.discard(self._pid)
        self._closed = True
        final_errors = list(self._errors)
        if status != 0:
            final_errors.append(f"exit:{status}")
        outcome = ArchiveStreamOutcome(
            self._archive_identity, status, self._stdout, self._stderr.hexdigest(),
            bool(self._descendants), reaped, tuple(final_errors))
        self._durable_digest(self._settled, outcome, "settled")
        return outcome

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._close_selector()
        for descriptor in tuple(self._fds):
            self._close_fd(descriptor)
        try:
            self._owner._revalidate()
        except BaseException as error:
            self._errors.append(f"archive-revalidate:{type(error).__name__}")
        if self._pid is not None:
            executable = None
            if self._archive_identity is not None:
                executable = (self._archive_identity.executable_device,
                              self._archive_identity.executable_inode)
            self._wait, errors = _cleanup_archive_child(
                self._pid, self._identity, self._wait, self._released,
                self._deadline_ns, executable)
            self._errors.extend(errors)
            _DISCOVERY_CHILDREN.discard(self._pid)

    def __enter__(self):
        return self
    def __exit__(self, _kind, _value, _traceback):
        self.close()


class _RuntimeDiscoveryHost:
    __slots__ = ("_closures", "_bounds", "_executables", "_next", "_closed", "_close_failure")

    def __init__(self):
        self._closures = []
        self._bounds = []
        self._executables = {}
        self._next = 0
        self._closed = False
        self._close_failure = None
        try:
            for tool, path in _HOST_TOOLS:
                closure, cache, root = _host_closure(tool, path)
                self._closures.append(closure)
                self._bounds.extend(cache.values())
                if tool == "python3-parser":
                    continue
                if tool == "zstd":
                    asset = kata_runtime.FixedArchive.KATA_ZSTD
                else:
                    asset = kata_runtime.FixedArchive.CONTAINERD_GZIP
                self._executables[asset] = _sealed_bound(root)
            if sum(item.total_bytes for item in self._closures) > MAX_ARTIFACT_BYTES:
                raise ProcessError("aggregate host closure bound")
            self._revalidate()
            self._closures[0] = _mapped_closure(os.getpid(), self._closures[0], False)
        except BaseException:
            self.close()
            raise

    @property
    def closures(self):
        return tuple(self._closures)

    def _revalidate(self):
        for bound in self._bounds:
            try:
                current = os.fstat(bound.descriptor)
            except OSError as error:
                raise ProcessError("host closure revalidation") from error
            held = (current.st_dev, current.st_ino, current.st_size,
                    current.st_mtime_ns, current.st_ctime_ns)
            if held != bound.generation:
                raise ProcessError("host closure drift")

    def open_archive_stream(self, asset, archive_fd, durable_intent, durable_started,
                            durable_settled, absolute_deadline_ns):
        expected = (kata_runtime.FixedArchive.KATA_ZSTD,
                    kata_runtime.FixedArchive.CONTAINERD_GZIP)
        if self._closed or self._next >= 2 or asset is not expected[self._next]:
            raise ProcessError("fixed archive order/one-shot")
        self._next += 1
        self._revalidate()
        return _FixedArchiveStream(
            self, asset, archive_fd, durable_intent, durable_started,
            durable_settled, absolute_deadline_ns)

    def close(self):
        close_failure = getattr(self, "_close_failure", None)
        if close_failure is not None:
            raise ProcessError(close_failure)
        if getattr(self, "_closed", True):
            return
        failures = []
        executables = tuple(getattr(self, "_executables", {}).values())
        try:
            _close_descriptors(executables, "runtime executables close")
        except ProcessError as error:
            failures.append(str(error))
        finally:
            for descriptor in executables:
                _DISCOVERY_FDS.discard(descriptor)
        try:
            _close_host_bounds(getattr(self, "_bounds", ()), "runtime bounds close")
        except ProcessError as error:
            failures.append(str(error))
        if failures:
            self._close_failure = "runtime host close:" + ";".join(failures)
            raise ProcessError(self._close_failure)
        self._closed = True


def _bind_runtime_discovery_host():
    return _RuntimeDiscoveryHost()


def _recover_runtime_discovery_children(started_rows, settled_rows, absolute_deadline_ns):
    if (type(started_rows) is not tuple or type(settled_rows) is not tuple
            or type(absolute_deadline_ns) is not int):
        raise ProcessError("recovery arguments")
    settled_shapes = (
        {"component", "started_sha256", "status", "stdout_bytes", "stderr_sha256", "descendants_absent", "reaped"},
        {"component", "started_sha256", "outcome"},
    )
    if any(type(row) is not dict or set(row) not in settled_shapes for row in settled_rows):
        raise ProcessError("settled recovery row")
    settled = set()
    for row in settled_rows:
        recovered = row.get("outcome") in {"absent", "terminated"}
        successful = ("status" in row and row["status"] == 0 and
                      row["descendants_absent"] is True and row["reaped"] is True)
        if recovered or successful:
            settled.add(row["started_sha256"])
    expected_components = ("kata", "containerd")
    observed_components = tuple(
        row.get("component") for row in started_rows if type(row) is dict)
    if len(started_rows) > 2 or observed_components != expected_components[:len(started_rows)]:
        raise ProcessError("started recovery order")
    outcomes = []
    for row in started_rows:
        required = {"component", "process", "executable_device", "executable_inode",
                    "spec_sha256", "closure_sha256", "started_sha256"}
        if type(row) is not dict or set(row) != required:
            raise ProcessError("started recovery row")
        if row["started_sha256"] in settled:
            continue
        value = row["process"]
        process_fields = {"pid", "ppid", "pgid", "sid", "starttime", "boot_id",
                          "pidfd_supported"}
        if type(value) is not dict or set(value) != process_fields:
            raise ProcessError("started process identity")
        identity = ProcessIdentity(**value)
        integer_fields = ("pid", "ppid", "pgid", "sid", "starttime")
        digest_fields = ("spec_sha256", "closure_sha256", "started_sha256")
        if not all(type(getattr(identity, name)) is int for name in integer_fields):
            raise ProcessError("started recovery identity")
        if type(identity.pidfd_supported) is not bool:
            raise ProcessError("started recovery identity")
        if not _canonical_boot_id(identity.boot_id):
            raise ProcessError("started recovery identity")
        if not all(type(row[name]) is int for name in ("executable_device", "executable_inode")):
            raise ProcessError("started recovery identity")
        valid_digests = all(
            type(row[name]) is str and len(row[name]) == 64 and set(row[name]) <= HEX
            for name in digest_fields)
        if not valid_digests:
            raise ProcessError("started recovery identity")
        asset = tuple(kata_runtime.FixedArchive)[expected_components.index(row["component"])]
        spec_body = {"argv": list(_ARCHIVE_ARGV[asset]), "component": row["component"],
                     "environment": ["LC_ALL=C"], "stdin": "parent-pipe"}
        expected_spec = hashlib.sha256(_canonical(spec_body)).hexdigest()
        if row["spec_sha256"] != expected_spec:
            raise ProcessError("recovery spec drift")
        if _boot_id() != identity.boot_id:
            outcomes.append({"component": row["component"],
                             "started_sha256": row["started_sha256"], "outcome": "absent"})
            continue
        snapshots = _archive_processes(identity)
        if not snapshots:
            outcomes.append({"component": row["component"],
                             "started_sha256": row["started_sha256"], "outcome": "absent"})
            continue
        expected_executable = (row["executable_device"], row["executable_inode"])
        leader = None
        for item in snapshots:
            if item[0][0] == identity.pid:
                leader = item
                break
        if leader is not None and leader[1] != expected_executable:
            raise ProcessError("recovery executable uncertainty")
        _signal_archive_processes(identity, snapshots, signal.SIGTERM, expected_executable)
        end = min(absolute_deadline_ns / 1e9, time.monotonic() + 0.5)
        while time.monotonic() < end and _archive_processes(identity):
            time.sleep(0.01)
        snapshots = _archive_processes(identity)
        if snapshots:
            _signal_archive_processes(identity, snapshots, signal.SIGKILL, expected_executable)
            end = min(absolute_deadline_ns / 1e9, time.monotonic() + 1.0)
            while time.monotonic() < end and _archive_processes(identity):
                time.sleep(0.01)
        if _archive_processes(identity):
            raise ProcessError("recovery absence uncertainty")
        outcomes.append({"component": row["component"],
                         "started_sha256": row["started_sha256"],
                         "outcome": "terminated", "errors": ()})
    return tuple(outcomes)


def _runtime_discovery_process_residue(started_rows=()):
    if _DISCOVERY_FDS or _DISCOVERY_CHILDREN:
        return False
    try:
        for row in started_rows:
            identity = ProcessIdentity(**row["process"])
            if identity.boot_id == _boot_id() and _archive_processes(identity):
                return False
    except (KeyError, TypeError, OSError, ProcessError, ValueError):
        return False
    return True

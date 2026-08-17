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
import time
import completion_kata_actions as actions
import completion_kata_fdmap as fdmap
import completion_kata_qualification as qualification
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
        allowed = {0, 1, 2, executable_fd, release_r, status_w,
                   *(row.target_fd for row in spec.inherited_fds)}
        _close_except(allowed)
        if os.read(release_r, 1) != b"R":
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


def _fixed_process_owner_routes():
    """Build the production process API without exposing a permit issuer.

    Only the eventual operation-journal bridge may register an outcome.  In
    particular, constructing ``ProcessOutcome`` never makes it operation-owned.
    The supervisor retains every absolute deadline and directly owned child.
    """
    seal = object()
    states = {}

    class FixedProcessOwner:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise ProcessError("sealed process owner")
            return super().__new__(cls)
        @property
        def uncertain(self):
            return states[self]["uncertain"]
        @property
        def closed(self):
            return states[self]["closed"]
        def fixed_specs(self):
            state = states[self]
            if state["closed"] or state["uncertain"]:
                raise ProcessError("process owner is closed or uncertain")
            return tuple(_spec(command) for command in (
                CommandId.CTR_CONTAINER_INFO, CommandId.CTR_CONTAINER_LIST,
                CommandId.CTR_TASK_LIST, CommandId.CTR_TASK_TERM,
                CommandId.CTR_TASK_KILL, CommandId.CTR_TASK_REMOVE,
                CommandId.CTR_CONTAINER_REMOVE, CommandId.SSH_READY,
            ))
        def poison(self):
            states[self]["uncertain"] = True
        def close(self):
            state = states[self]
            if state["uncertain"]:
                raise ProcessError("process ownership is uncertain")
            if state["closed"]:
                return
            if state["outcomes"]:
                state["uncertain"] = True
                raise ProcessError("unconsumed operation outcome")
            state["closed"] = True

    def make():
        owner = FixedProcessOwner(seal)
        states[owner] = {"closed": False, "uncertain": False, "outcomes": {}}
        return owner

    def open_owner(grant):
        qualification._consume_fixed_owner_grant(grant, "process")
        return make()

    def remember(owner, outcome):
        state = states.get(owner)
        if (type(owner) is not FixedProcessOwner or state is None or state["closed"]
                or state["uncertain"] or type(outcome) is not ProcessOutcome):
            raise ProcessError("exact live process owner/outcome required")
        identity = id(outcome)
        if identity in state["outcomes"]:
            state["uncertain"] = True
            raise ProcessError("duplicate operation outcome")
        state["outcomes"][identity] = outcome
        return outcome

    def claim(owner, outcome, command_id):
        state = states.get(owner)
        if (type(owner) is not FixedProcessOwner or state is None or state["closed"]
                or state["uncertain"] or type(command_id) is not CommandId
                or type(outcome) is not ProcessOutcome):
            raise ProcessError("operation-derived process outcome required")
        retained = state["outcomes"].pop(id(outcome), None)
        if retained is not outcome or outcome.command_id != command_id.value:
            state["uncertain"] = True
            raise ProcessError("foreign, replayed, or mismatched process outcome")
        return outcome

    return FixedProcessOwner, open_owner, remember, claim, make


(FixedProcessOwner, _open_fixed_process_owner, _remember_operation_outcome_for_tests,
 _claim_operation_outcome, _make_fixed_process_owner_for_tests) = _fixed_process_owner_routes()
del _fixed_process_owner_routes


def open_fixed_process_owner():
    """The zero-argument production entry cannot bypass coordinator preflight."""
    raise ProcessError("production process owner requires the sealed coordinator gate")


def _fixed_spec_snapshots_for_tests():
    available = {CommandId.CTR_CONTAINER_INFO, CommandId.CTR_CONTAINER_LIST,
                 CommandId.CTR_TASK_LIST, CommandId.CTR_TASK_TERM,
                 CommandId.CTR_TASK_KILL, CommandId.CTR_TASK_REMOVE,
                 CommandId.CTR_CONTAINER_REMOVE, CommandId.SSH_READY}
    return tuple((item.value, _spec(item).argv, _spec(item).stdin,
                  _spec(item).deadline_class, _spec(item).inherited_fds)
                 for item in CommandId if item in available)


# Deliberately no production execute/run function and no operation CommandPermit issuer.

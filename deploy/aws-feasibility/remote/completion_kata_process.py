"""Journal-bound process primitives for the fixed Stage 2 Kata transaction.

There is deliberately no callable generic supervisor, executable-fd issuer, or
test authority in this deployed module.  The eventual trusted coordinator will
select a fixed action, authenticate its retained tool generation, and use the
private journal transaction below.  Slice A leaves that admission unavailable.
"""
from dataclasses import dataclass, field
from enum import Enum
import ctypes
import errno
import hashlib
import json
import os
import platform
import signal
import time
import completion_kata_actions as actions
import completion_kata_fdmap as fdmap
import completion_kata_operation as operation

MAX_STREAM = 65_536
STATUS_SIZE = 4
UINT_MAX = (1 << 32) - 1
CLOCK = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)
ENVIRONMENT = operation.FIXED_ENV
BASE = operation.BASE
CGROUP_BASE = "/sys/fs/cgroup/cogs-stage2-completion-v1"
CONTAINERD_SOCKET = BASE + "/kata-runtime-v1/containerd.sock"
CONTAINERD_ROOT = BASE + "/kata-runtime-v1/containerd-root"
CONTAINERD_STATE = BASE + "/kata-runtime-v1/containerd-state"
CONTAINERD_CONFIG = BASE + "/kata-runtime-v1/containerd.toml"
NAMESPACE = "cogs-stage2-completion-v1"
SANDBOX = "cogs-stage2-ssh-v1"


class ProcessError(Exception):
    pass


CommandId = actions.CommandId


class ObservationKind(Enum):
    EXACT = "exact"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FixedCommand:
    command_id: actions.CommandId
    executable_role: str
    executable_path: str
    argv: tuple
    stdin: bytes
    output_grammar: str
    stdout_limit: int
    stderr_limit: int
    duration_ns: int
    inherited_targets: tuple = ()


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


@dataclass
class _OwnedProcess:
    identity: ProcessIdentity
    pidfd: object
    cgroup_path: str
    cgroup_generation: tuple
    absolute_deadline_ns: int
    term_at_ns: int
    kill_at_ns: int
    leader_status: object = None
    term_attempted: bool = False
    kill_attempted: bool = False
    release_count: int = 0
    descendants: dict = field(default_factory=dict)


def _boottime_ns():
    return time.clock_gettime_ns(CLOCK)


def _fixed_command(command_id):
    if not isinstance(command_id, CommandId):
        raise ProcessError("fixed command id required")
    ctr = ("/usr/bin/ctr", "--address", CONTAINERD_SOCKET, "--namespace", NAMESPACE)
    def ctr_command(tail, grammar, stdout_limit, duration_ns):
        return FixedCommand(
            command_id, "ctr", "/usr/bin/ctr", ctr + tail, b"", grammar,
            stdout_limit, MAX_STREAM, duration_ns,
        )
    rows = {
        CommandId.CONTAINERD_START: FixedCommand(
            command_id, "containerd", "/usr/bin/containerd",
            ("/usr/bin/containerd", "--address", CONTAINERD_SOCKET, "--root", CONTAINERD_ROOT,
             "--state", CONTAINERD_STATE, "--config", CONTAINERD_CONFIG),
            b"", "text", 0, MAX_STREAM, 60_000_000_000,
        ),
        CommandId.CTR_CONTAINER_INFO: ctr_command(
            ("containers", "info", SANDBOX), "json", MAX_STREAM, 5_000_000_000,
        ),
        CommandId.CTR_CONTAINER_LIST: ctr_command(
            ("containers", "list"), "text", MAX_STREAM, 5_000_000_000,
        ),
        CommandId.CTR_TASK_LIST: ctr_command(
            ("tasks", "list"), "text", MAX_STREAM, 5_000_000_000,
        ),
        CommandId.CTR_TASK_TERM: ctr_command(
            ("tasks", "kill", "--signal", "SIGTERM", SANDBOX),
            "empty", 0, 15_000_000_000,
        ),
        CommandId.CTR_TASK_KILL: ctr_command(
            ("tasks", "kill", "--signal", "SIGKILL", SANDBOX),
            "empty", 0, 10_000_000_000,
        ),
        CommandId.CTR_TASK_REMOVE: ctr_command(
            ("tasks", "rm", SANDBOX), "empty", 0, 20_000_000_000,
        ),
        CommandId.CTR_CONTAINER_REMOVE: ctr_command(
            ("containers", "rm", SANDBOX), "empty", 0, 20_000_000_000,
        ),
    }
    try:
        return rows[command_id]
    except KeyError as error:
        raise ProcessError("action specification belongs to its fixed lifecycle owner") from error


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def _generation(identity, kind="file"):
    return {
        "mount_id": identity.mount_id, "device": identity.device, "inode": identity.inode,
        "kind": kind, "mode": identity.mode & 0o7777, "uid": identity.uid,
        "gid": identity.gid, "nlink": identity.nlink, "size": identity.size,
        "mtime_ns": identity.mtime_ns, "ctime_ns": identity.ctime_ns,
    }


def _binding_rows(bindings):
    result = []
    for row in fdmap.revalidate(bindings):
        result.append({
            "role": row.role, "target_fd": row.target_fd,
            "generation": _generation(row.identity), "content_sha256": row.content_sha256,
            "content_length": row.identity.size,
        })
    return result


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


def _intent_body(context, spec, executable, bindings):
    if not isinstance(context, operation.CommandContext):
        raise ProcessError("durable operation context required")
    if (not isinstance(spec, FixedCommand) or spec != _fixed_command(spec.command_id)
            or not isinstance(executable, RetainedExecutable)
            or spec.executable_role != executable.role or spec.executable_path != executable.path):
        raise ProcessError("fixed executable binding mismatch")
    observed = fdmap.identity(executable.descriptor)
    if (_generation(observed) != executable.generation
            or _digest_fd(executable.descriptor, observed.size) != executable.sha256
            or fdmap.identity(executable.descriptor) != observed):
        raise ProcessError("retained executable generation changed")
    environment = [list(row) for row in ENVIRONMENT]
    absolute_deadline_ns = _boottime_ns() + spec.duration_ns
    body = {
        "operation_token": context.operation_token,
        "command_serial": context.command_serial,
        "command_id": spec.command_id.value,
        "binding_sha256": "0" * 64,
        "journal_key": context.journal_key,
        "host_boot_id": context.host_boot_id,
        "source_revision": context.source_revision,
        "lifecycle_phase": context.lifecycle_phase,
        "executable_role": executable.role,
        "executable_path": executable.path,
        "executable_sha256": executable.sha256,
        "executable_generation": executable.generation,
        "tool_closure_sha256": executable.closure_sha256,
        "argv": list(spec.argv),
        "argv_sha256": hashlib.sha256(_canonical(list(spec.argv))).hexdigest(),
        "stdin_hex": spec.stdin.hex(),
        "stdin_sha256": hashlib.sha256(spec.stdin).hexdigest(),
        "stdin_length": len(spec.stdin),
        "environment": environment,
        "environment_sha256": hashlib.sha256(_canonical(environment)).hexdigest(),
        "inherited_fds": _binding_rows(bindings),
        "deadline_boottime_ns": absolute_deadline_ns,
        "output_grammar": spec.output_grammar,
        "stdout_limit": spec.stdout_limit,
        "stderr_limit": spec.stderr_limit,
    }
    bound = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(operation._canonical(bound)).hexdigest()
    operation._validate_body("COMMAND_INTENT_V2", body)
    return body


def _proc_row(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb", buffering=0) as source:
            raw = source.read(4096)
    except OSError:
        raise
    close = raw.rfind(b")")
    fields = raw[close + 2:].split()
    if close < 2 or len(fields) < 20 or int(raw[:raw.find(b" ")]) != pid:
        raise ProcessError("invalid proc stat")
    return pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19])


def _boot_id():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        value = source.read()
    if len(value) != 37 or value[-1] != "\n":
        raise ProcessError("invalid boot id")
    return value[:-1]


def _identity(pid, setup):
    row = _proc_row(pid)
    expected = (pid, os.getpid(), pid, pid)
    if tuple(setup) != expected or row[:4] != expected:
        raise ProcessError("process identity mismatch")
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


def _recovery_class(identity, observed_boot_id, observation):
    if not isinstance(identity, ProcessIdentity) or not isinstance(observation, RecoveryObservation):
        raise ProcessError("invalid recovery observation")
    if observed_boot_id != identity.boot_id or observation.kind is ObservationKind.ABSENT:
        return "recovery_absent"
    if observation.kind is ObservationKind.UNKNOWN:
        return "uncertain"
    exact = (identity.pid, identity.ppid, identity.pgid, identity.sid, identity.starttime)
    return "exact_live" if observation.row == exact else "uncertain"


def _set_subreaper(enabled):
    if platform.system() != "Linux":
        raise OSError(errno.ENOSYS, "subreaper requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    previous = bool(value.value)
    if libc.prctl(36, int(enabled), 0, 0, 0) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))
    return previous


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
    if any(type(item) is not int or not 0 <= item <= UINT_MAX for item in kept):
        raise OSError(errno.EINVAL, "invalid child descriptor allowlist")
    cursor = 0
    for descriptor in kept:
        if cursor < descriptor:
            _close_range(cursor, descriptor - 1)
        cursor = descriptor + 1
    if cursor <= UINT_MAX:
        _close_range(cursor, UINT_MAX)


def _cgroup_generation(path):
    value = os.stat(path, follow_symlinks=False)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _directory_generation(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return _generation(fdmap.identity(descriptor), "directory")
    finally:
        os.close(descriptor)


def _create_owned_cgroup(context):
    if not isinstance(context, operation.CommandContext):
        raise ProcessError("durable operation context required")
    name = f"{context.operation_token}-{context.command_serial}"
    path = CGROUP_BASE + "/" + name
    os.mkdir(path, 0o700)
    generation = _cgroup_generation(path)
    observed = _directory_generation(path)
    if observed["uid"] != 0 or observed["gid"] != 0 or observed["mode"] != 0o700:
        raise ProcessError("invalid owned cgroup")
    return path, generation, observed


def _register_gated_child(pid, setup, cgroup_path, cgroup_generation, absolute_deadline_ns):
    identity, pidfd = _identity(pid, setup)
    if _cgroup_generation(cgroup_path) != cgroup_generation:
        raise ProcessError("cgroup replaced before registration")
    with open(cgroup_path + "/cgroup.procs", "wb", buffering=0) as target:
        written = target.write(f"{pid}\n".encode("ascii"))
    if written != len(f"{pid}\n"):
        raise ProcessError("short cgroup registration")
    members, observed = _cgroup_members(cgroup_path)
    if observed != cgroup_generation or pid not in members:
        raise ProcessError("child cgroup registration not observed")
    term_at = max(_boottime_ns(), absolute_deadline_ns - 2_000_000_000)
    kill_at = max(term_at, absolute_deadline_ns - 500_000_000)
    return _OwnedProcess(
        identity, pidfd, cgroup_path, cgroup_generation, absolute_deadline_ns,
        term_at, kill_at,
    )


def _preexec_body(intent, owner, cgroup_record, status_descriptor):
    status_generation = _generation(fdmap.identity(status_descriptor))
    return {
        "operation_token": intent["operation_token"],
        "command_serial": intent["command_serial"], "command_id": intent["command_id"],
        "binding_sha256": intent["binding_sha256"],
        "host_boot_id": owner.identity.boot_id, "pid": owner.identity.pid,
        "ppid": owner.identity.ppid, "pgid": owner.identity.pgid, "sid": owner.identity.sid,
        "proc_start_time": owner.identity.starttime,
        "pidfd_supported": owner.identity.pidfd_supported,
        "cgroup_path": owner.cgroup_path, "cgroup_generation": cgroup_record,
        "exec_status_pipe": status_generation, "release_count": 0,
    }


def _release_once(authority, intent, owner, cgroup_record, status_descriptor, release_descriptor):
    if owner.release_count != 0:
        raise ProcessError("child release already consumed")
    body = _preexec_body(intent, owner, cgroup_record, status_descriptor)
    operation._record_command_preexec(authority, body)
    if os.write(release_descriptor, b"R") != 1:
        raise ProcessError("short child release")
    owner.release_count = 1
    os.close(release_descriptor)


def _cgroup_members(path):
    before = _cgroup_generation(path)
    with open(path + "/cgroup.procs", "rb", buffering=0) as source:
        raw = source.read(65_536)
    after = _cgroup_generation(path)
    if before != after or len(raw) >= 65_536:
        raise ProcessError("unstable cgroup census")
    rows = raw.splitlines()
    if any(not row.isdigit() for row in rows):
        raise ProcessError("invalid cgroup census")
    return tuple(sorted({int(row) for row in rows})), after


def _wait_leader(owner):
    if owner.leader_status is not None:
        return
    try:
        pid, status = os.waitpid(owner.identity.pid, os.WNOHANG)
    except ChildProcessError:
        raise ProcessError("lost leader reap authority")
    if pid == owner.identity.pid:
        owner.leader_status = status


def _signal_pidfd(owner, sig):
    if owner.pidfd is not None and hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(owner.pidfd, sig)
        return
    if _proc_row(owner.identity.pid) != (
        owner.identity.pid, owner.identity.ppid, owner.identity.pgid,
        owner.identity.sid, owner.identity.starttime,
    ):
        raise ProcessError("leader identity changed")
    os.kill(owner.identity.pid, sig)


def _retain_descendants(owner, members):
    for pid in members:
        if pid == owner.identity.pid or pid in owner.descendants:
            continue
        row = _proc_row(pid)
        pidfd = None
        if hasattr(os, "pidfd_open"):
            try:
                pidfd = os.pidfd_open(pid, 0)
            except OSError as error:
                if error.errno not in {errno.ENOSYS, errno.EINVAL}:
                    raise
        if _proc_row(pid) != row:
            if pidfd is not None:
                os.close(pidfd)
            raise ProcessError("descendant changed during adoption")
        owner.descendants[pid] = (row, pidfd)


def _signal_members(owner, sig):
    members, generation = _cgroup_members(owner.cgroup_path)
    if generation != owner.cgroup_generation:
        raise ProcessError("cgroup replaced")
    _retain_descendants(owner, members)
    for pid in members:
        if pid == owner.identity.pid:
            _signal_pidfd(owner, sig)
            continue
        row, pidfd = owner.descendants[pid]
        if _proc_row(pid) != row:
            raise ProcessError("descendant identity changed")
        if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(pidfd, sig)
        else:
            os.kill(pid, sig)


def _reap_descendants(owner):
    reaped = True
    for pid, (_row, pidfd) in tuple(owner.descendants.items()):
        try:
            observed, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            observed = 0
        if observed != pid:
            reaped = False
            continue
        if pidfd is not None:
            os.close(pidfd)
        del owner.descendants[pid]
    return reaped and not owner.descendants


def _settle_owned(owner):
    """Settle leader and every cgroup descendant under the original deadline."""
    errors = []
    while True:
        now = _boottime_ns()
        try:
            _wait_leader(owner)
            members, generation = _cgroup_members(owner.cgroup_path)
            if generation != owner.cgroup_generation:
                raise ProcessError("cgroup replaced")
            _retain_descendants(owner, members)
        except BaseException as error:
            errors.append(f"observe:{type(error).__name__}")
            break
        if owner.leader_status is not None and not members:
            break
        if now >= owner.absolute_deadline_ns:
            errors.append("absolute-deadline")
            break
        if now >= owner.kill_at_ns and not owner.kill_attempted:
            try:
                _signal_members(owner, signal.SIGKILL)
                owner.kill_attempted = True
            except BaseException as error:
                errors.append(f"kill:{type(error).__name__}")
                break
        elif now >= owner.term_at_ns and not owner.term_attempted:
            try:
                _signal_members(owner, signal.SIGTERM)
                owner.term_attempted = True
            except BaseException as error:
                errors.append(f"term:{type(error).__name__}")
                break
        time.sleep(min(0.01, max(0, owner.absolute_deadline_ns - now) / 1_000_000_000))
    try:
        members, generation = _cgroup_members(owner.cgroup_path)
        empty = not members and generation == owner.cgroup_generation
    except BaseException as error:
        errors.append(f"final-cgroup:{type(error).__name__}")
        empty = False
    descendants_reaped = _reap_descendants(owner) if empty else False
    if owner.leader_status is not None and owner.pidfd is not None:
        try:
            os.close(owner.pidfd)
            owner.pidfd = None
        except OSError as error:
            errors.append(f"pidfd-close:{error.errno}")
    removed = False
    if empty and descendants_reaped:
        try:
            os.rmdir(owner.cgroup_path)
            removed = True
        except OSError as error:
            errors.append(f"cgroup-remove:{error.errno}")
    return {
        "leader_reaped": owner.leader_status is not None,
        "descendants_reaped": descendants_reaped,
        "cgroup_empty": empty,
        "cgroup_removed": removed,
        "term_attempted": owner.term_attempted,
        "kill_attempted": owner.kill_attempted,
        "deadline_expired": _boottime_ns() >= owner.absolute_deadline_ns,
        "errors": errors,
    }


def _outcome_body(intent, outcome, status, exec_errno, stdout, stderr, closure, pipes_eof):
    errors = list(closure["errors"])
    settled = (closure["leader_reaped"] and closure["descendants_reaped"]
               and closure["cgroup_empty"] and closure["cgroup_removed"] and pipes_eof)
    interrupted = (closure["term_attempted"] or closure["kill_attempted"]
                   or closure["deadline_expired"])
    uncertain = not settled or bool(errors) or interrupted
    if uncertain:
        outcome = "uncertain"
        status = exec_errno = None
    body = {
        "operation_token": intent["operation_token"],
        "command_serial": intent["command_serial"],
        "command_id": intent["command_id"],
        "binding_sha256": intent["binding_sha256"],
        "outcome": outcome,
        "status": status,
        "errno": exec_errno,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_length": len(stdout),
        "stdout_truncated": len(stdout) > intent["stdout_limit"],
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_length": len(stderr),
        "stderr_truncated": len(stderr) > intent["stderr_limit"],
        "leader_reaped": closure["leader_reaped"],
        "descendants_reaped": closure["descendants_reaped"],
        "cgroup_empty": closure["cgroup_empty"],
        "cgroup_removed": closure["cgroup_removed"],
        "pipes_eof": pipes_eof,
        "release_count": 1,
        "term_attempted": closure["term_attempted"],
        "kill_attempted": closure["kill_attempted"],
        "deadline_expired": closure["deadline_expired"],
        "uncertain": uncertain,
        "errors": errors,
    }
    operation._validate_body("COMMAND_OUTCOME_V2", body)
    return body


def open_fixed_process_owner():
    """Remain fail-closed until the reviewed host/runtime attestation exists."""
    raise ProcessError("production process owner unavailable: fixed tool attestation absent")


# No execute/run/spawn/spec API and no environment-enabled test issuer.

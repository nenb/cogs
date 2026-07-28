#!/usr/bin/python3
"""Thin native integration through the admitted production bootstrap ABI."""
from __future__ import annotations
from dataclasses import fields
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import struct
import subprocess
import sys
import time
import types
CHECK_IDS = (
    "closure_prepared", "handoff_exact", "gzip_deterministic",
    "zstd_deterministic", "marker_exact", "no_linked_evidence",
    "cleanup_restored",
)
SOURCES = (
    "deploy/aws-feasibility/remote/completion_elf.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
    "schemas/trusted-runtime-closure-v1.json",
)
LAUNCHER = SOURCES[2]
RESULT_STRINGS = (
    "version", "marker", "source_revision", "source_set_sha256",
    "closure_sha256", "gzip_output_sha256", "zstd_output_sha256",
)
RESULT_BOOLEANS = tuple("""
mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact
namespace_handles_exact pid_one supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero
bounding_capabilities_zero ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec root_has_no_proc
host_paths_absent checkout_absent limits_exact descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
namespaces_released namespace_handles_released
""".split())
RESULT_FIELDS = RESULT_STRINGS + RESULT_BOOLEANS
RESULT_VERSION = "cogs.runtime-qualification/v1"
MARKER = "cogs-runtime-qualification-v1"
OUTPUT_SHA256 = hashlib.sha256((MARKER + "\n").encode()).hexdigest()
MAX_RESULT = 131_072
ROOT = Path(__file__).resolve().parents[2]
def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)
def _strict_json(raw: bytes) -> dict[str, object]:
    _require(0 < len(raw) <= MAX_RESULT and raw.endswith(b"\n") and not raw.endswith(b"\n\n"), "result framing")
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in rows:
            _require(name not in result, "duplicate result field")
            result[name] = value
        return result
    value = json.loads(raw[:-1].decode("utf-8", "strict"), object_pairs_hook=pairs)
    _require(type(value) is dict, "result object")
    canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _require(canonical == raw, "result canonical bytes")
    return value
def _load_held_launcher(source: bytes, digest: str) -> types.ModuleType:
    _require(hashlib.sha256(source).hexdigest() == digest, "held launcher digest")
    name = f"_cogs_native_integration_{digest[:16]}"
    module = types.ModuleType(name)
    module.__file__ = f"cogs-held:{digest}/launcher"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True, optimize=0), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module
def qualify(module: types.ModuleType, raw: bytes, revision: str, source_digest: str) -> dict[str, object]:
    result_type = getattr(module, "RuntimeQualificationResult", None)
    _require(type(result_type) is type and tuple(field.name for field in fields(result_type)) == RESULT_FIELDS, "production result type")
    value = _strict_json(raw)
    _require(set(value) == set(RESULT_FIELDS), "production result fields")
    result = result_type(*(value[name] for name in RESULT_FIELDS))
    _require(type(result) is result_type, "substituted production result")
    _require(all(type(getattr(result, name)) is str for name in RESULT_STRINGS), "production string types")
    _require(all(type(getattr(result, name)) is bool and getattr(result, name) for name in RESULT_BOOLEANS), "production boolean fields")
    _require((result.version, result.marker, result.source_revision, result.source_set_sha256) == (RESULT_VERSION, MARKER, revision, source_digest), "production result identity fields")
    digests = (result.source_set_sha256, result.closure_sha256, result.gzip_output_sha256, result.zstd_output_sha256)
    _require(all(type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value) for value in digests), "production result digests")
    _require(result.gzip_output_sha256 == result.zstd_output_sha256 == OUTPUT_SHA256, "deterministic output")
    checks = {
        "closure_prepared": result.source_revision == revision and result.source_set_sha256 == source_digest and len(result.closure_sha256) == 64,
        "handoff_exact": type(result) is result_type and all(getattr(result, name) is True for name in RESULT_BOOLEANS),
        "gzip_deterministic": result.gzip_output_sha256 == OUTPUT_SHA256,
        "zstd_deterministic": result.zstd_output_sha256 == OUTPUT_SHA256,
        "marker_exact": result.version == RESULT_VERSION and result.marker == MARKER,
        "no_linked_evidence": set(value) == set(RESULT_FIELDS),
        "cleanup_restored": all(getattr(result, name) is True for name in RESULT_BOOLEANS[-7:]),
    }
    _require(tuple(checks) == CHECK_IDS and all(checks.values()), "integration checks")
    metadata = {"closure_sha256": result.closure_sha256, "gzip_output_sha256": result.gzip_output_sha256, "source_set_sha256": result.source_set_sha256, "zstd_output_sha256": result.zstd_output_sha256}
    return {"checks": checks, "metadata": metadata}
def _read_source_set(root_fd: int) -> tuple[dict[str, bytes], str]:
    held: dict[str, bytes] = {}
    digest = hashlib.sha256()
    for relative in SOURCES:
        descriptor = os.open(relative, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            before = os.fstat(descriptor)
            _require(0 <= before.st_size <= 2_000_000, "source size")
            data = bytearray()
            while len(data) < before.st_size:
                part = os.read(descriptor, min(65_536, before.st_size - len(data)))
                _require(bool(part), "source short read")
                data += part
            after = os.fstat(descriptor)
            identity = lambda row: (row.st_mode, row.st_uid, row.st_gid, row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
            _require(identity(before) == identity(after), "source generation drift")
        finally:
            os.close(descriptor)
        held[relative] = bytes(data)
        encoded = relative.encode()
        digest.update(struct.pack("!I", len(encoded)) + encoded)
        digest.update(struct.pack("!Q", len(data)) + hashlib.sha256(data).digest())
    return held, digest.hexdigest()
def _admission(revision: str, source_digest: str, launcher: bytes) -> bytes:
    value = dict(bootstrap_sha256=hashlib.sha256(launcher).hexdigest(), revision=revision,
                 source_set_sha256=source_digest, version="cogs.runtime-source-admission/v1")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
def _write_exact(path: str, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        _require(os.write(descriptor, value) == len(value), "identity map write")
    finally:
        os.close(descriptor)
def _child(root_fd: int, admission_fd: int, output_fd: int, error_fd: int, gate_fd: int) -> None:
    try:
        _require(os.read(gate_fd, 1) == b"G", "child release")
        os.close(gate_fd)
        uid, gid = os.getuid(), os.getgid()
        libc = __import__("ctypes").CDLL(None, use_errno=True)
        _require(libc.unshare(0x10000000) == 0, "user namespace")
        _write_exact("/proc/self/setgroups", b"deny\n")
        _write_exact("/proc/self/uid_map", f"0 {uid} 1\n".encode())
        _write_exact("/proc/self/gid_map", f"0 {gid} 1\n".encode())
        null_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        sources = tuple(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64) for fd in (null_fd, output_fd, error_fd, admission_fd, root_fd))
        for source, target in zip(sources, (0, 1, 2, 3, 4), strict=True):
            os.dup2(source, target, inheritable=True)
        os.closerange(5, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
        os.fchdir(4)
        os.execve("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", LAUNCHER), {})
    except BaseException:
        os._exit(125)
def _wait_pidfd(pidfd: int, deadline: float) -> object:
    while time.monotonic() < deadline:
        if select.select((pidfd,), (), (), min(0.05, deadline - time.monotonic()))[0]:
            result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            if result is not None:
                return result
    raise RuntimeError("production child deadline")
def _stop(pidfd: int, deadline: float) -> object:
    try:
        return _wait_pidfd(pidfd, min(deadline, time.monotonic() + 0.2))
    except RuntimeError:
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    try:
        return _wait_pidfd(pidfd, min(deadline, time.monotonic() + 1.0))
    except RuntimeError:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        return _wait_pidfd(pidfd, deadline)
def _launch(root_fd: int, admission: bytes) -> tuple[bytes, bytes, object]:
    admission_read, admission_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    owned = {admission_read, admission_write, output_read, output_write, error_read, error_write, gate_read, gate_write}
    pidfd = -1
    try:
        pid = os.fork()
    except BaseException as primary:
        failures: list[BaseException] = []
        for descriptor in owned:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise ExceptionGroup("integration fork cleanup", [primary, *failures])
        raise
    if pid == 0:
        for descriptor in (admission_write, output_read, error_read, gate_write):
            os.close(descriptor)
        _child(root_fd, admission_read, output_write, error_write, gate_read)
        os._exit(125)
    deadline = time.monotonic() + 30.0
    buffers = {output_read: bytearray(), error_read: bytearray()}
    primary: BaseException | None = None
    status: object | None = None
    try:
        pidfd = os.pidfd_open(pid, 0)
        for descriptor in (admission_read, output_write, error_write, gate_read):
            owned.remove(descriptor)
            os.close(descriptor)
        _require(os.write(gate_write, b"G") == 1, "release write")
        owned.remove(gate_write)
        os.close(gate_write)
        _require(os.write(admission_write, admission) == len(admission), "admission write")
        owned.remove(admission_write)
        os.close(admission_write)
        active = set(buffers)
        while active:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "production output deadline")
            ready = select.select(tuple(active), (), (), remaining)[0]
            for descriptor in ready:
                part = os.read(descriptor, MAX_RESULT + 1 - len(buffers[descriptor]))
                if part:
                    buffers[descriptor] += part
                    _require(len(buffers[descriptor]) <= MAX_RESULT, "production output bound")
                else:
                    owned.remove(descriptor)
                    active.remove(descriptor)
                    os.close(descriptor)
        status = _wait_pidfd(pidfd, deadline)
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    if status is None and pidfd >= 0:
        try:
            status = _stop(pidfd, deadline)
        except BaseException as error:
            failures.append(error)
    for descriptor in tuple(owned):
        try:
            os.close(descriptor)
        except BaseException as error:
            failures.append(error)
    if pidfd < 0:
        blocked_deadline = min(deadline, time.monotonic() + 1.0)
        while time.monotonic() < blocked_deadline:
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                break
            time.sleep(0.01)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                while time.monotonic() < deadline:
                    if os.waitpid(pid, os.WNOHANG)[0] == pid:
                        break
                    time.sleep(0.01)
                else:
                    failures.append(RuntimeError("blocked child reap"))
            except BaseException as error:
                failures.append(error)
    else:
        try:
            os.close(pidfd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise ExceptionGroup("integration cleanup", ([primary] if primary else []) + failures)
    if primary is not None:
        raise primary
    _require(status is not None, "production child status")
    return bytes(buffers[output_read]), bytes(buffers[error_read]), status
def _git(*arguments: str) -> bytes:
    completed = subprocess.run(("/usr/bin/git", "-C", os.fspath(ROOT), *arguments), env={"LC_ALL": "C"}, capture_output=True, timeout=5, check=False)
    _require(completed.returncode == 0 and not completed.stderr, "git observation")
    return completed.stdout
def _fds() -> tuple[tuple[int, tuple[int, ...]], ...]:
    descriptor = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        numbers = sorted(int(name) for name in os.listdir(descriptor) if int(name) != descriptor)
        return tuple((number, (row.st_mode, row.st_uid, row.st_gid, row.st_dev, row.st_ino,
                               row.st_size, row.st_mtime_ns, row.st_ctime_ns))
                     for number in numbers for row in (os.fstat(number),))
    finally:
        os.close(descriptor)

def _observe(name: str) -> object:
    if name == "descriptors":
        return _fds()
    if name == "children":
        return Path("/proc/self/task/self/children").read_bytes()
    if name == "paths":
        if not os.path.lexists("/run/cogs-o2-runtime-v1"):
            return None
        row = os.lstat("/run/cogs-o2-runtime-v1")
        return (row.st_mode, row.st_uid, row.st_gid, row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    if name == "mounts":
        return hashlib.sha256(Path("/proc/self/mountinfo").read_bytes()).digest()
    if name == "namespaces":
        rows = [os.stat(f"/proc/self/ns/{kind}") for kind in ("user", "mnt", "pid", "net")]
        return tuple((row.st_dev, row.st_ino) for row in rows)
    if name == "limits":
        return resource.getrlimit(resource.RLIMIT_NOFILE)
    if name == "checkout":
        return (_git("rev-parse", "HEAD^{commit}"), _git("status", "--porcelain=v1", "--untracked-files=all"), _git("config", "--local", "--null", "--list"))
    raise RuntimeError("cleanup domain")
def _cleanup(before: dict[str, object]) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, value in before.items():
        try:
            result[name] = _observe(name) == value
        except BaseException:
            result[name] = False
    return result

def _main() -> int:
    if sys.argv != [sys.argv[0], "--workflow-bound"] or os.geteuid() == 0:
        raise RuntimeError("integration requires fixed workflow entry")
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        common = __import__("common")
    finally:
        del sys.path[0]
    context = common.WorkflowContext.from_environ("integration", __file__)
    before: dict[str, object] | None = None
    cleanup = dict.fromkeys(common.CLEANUP_KEYS, False)
    try:
        before = {name: _observe(name) for name in common.CLEANUP_KEYS}
        checkout = before["checkout"]
        _require(checkout[0] == (context.head_sha + "\n").encode() and checkout[1] == b"", "source checkout admission")
        root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            held, source_digest = _read_source_set(root_fd)
            admission = _admission(context.head_sha, source_digest, held[LAUNCHER])
            output, error, status = _launch(root_fd, admission)
        finally:
            os.close(root_fd)
        _require(status.si_code == os.CLD_EXITED and status.si_status == 0 and not error, "production bootstrap failed")
        module = _load_held_launcher(held[LAUNCHER], hashlib.sha256(held[LAUNCHER]).hexdigest())
        qualified = qualify(module, output, context.head_sha, source_digest)
        cleanup = _cleanup(before)
        _require(all(cleanup.values()), "outer cleanup")
    except BaseException as error:
        if before is not None:
            cleanup = _cleanup(before)
        diagnostic = type(error).__name__.encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", dict.fromkeys(CHECK_IDS, "fail"), [], cleanup, "integration", diagnostic)
        return 1
    metadata = [{"id": name.removesuffix("_sha256"), "role": "digest", "sha256": value, "size_bytes": 0} for name, value in qualified["metadata"].items()]
    common.finalize_report(context, "pass", dict.fromkeys(CHECK_IDS, "pass"), metadata, cleanup)
    return 0
if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except BaseException:
        os.write(2, b"native-integration-failed\n")
        raise SystemExit(1)

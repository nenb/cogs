#!/usr/bin/python3
"""Job E: qualify the admitted production T2 coordinator under sole sudo root."""
from __future__ import annotations

from dataclasses import fields
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
    "mount_view_exact", "checkout_read_only", "user_namespace_exact",
    "pid_namespace_exact", "mount_namespace_exact", "network_namespace_exact",
    "pid_one", "capabilities_zero", "noroot_locked", "nnp_set",
    "seccomp_socket_denied", "seccomp_io_uring_denied", "no_acquisition_route",
    "checkout_unchanged", "all_reaped", "mounts_restored", "cleanup_restored",
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
ROOT = Path(__file__).resolve().parents[2]
MAX_RESULT = 131_072


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _hex(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


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
    name = f"_cogs_native_e_{digest[:16]}"
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


def _decode_result(module: types.ModuleType, raw: bytes, revision: str, source_digest: str) -> object:
    result_type = getattr(module, "RuntimeQualificationResult", None)
    _require(type(result_type) is type and tuple(field.name for field in fields(result_type)) == RESULT_FIELDS, "production result type")
    value = _strict_json(raw)
    _require(set(value) == set(RESULT_FIELDS), "production result fields")
    result = result_type(*(value[name] for name in RESULT_FIELDS))
    _require(type(result) is result_type, "production result identity")
    _require(all(type(getattr(result, name)) is str for name in RESULT_STRINGS), "production string types")
    _require(all(type(getattr(result, name)) is bool for name in RESULT_BOOLEANS), "production boolean types")
    identity = (result.version, result.marker, result.source_revision, result.source_set_sha256)
    _require(identity == (RESULT_VERSION, MARKER, revision, source_digest), "production result identity fields")
    _require(all(_hex(getattr(result, name)) for name in ("source_set_sha256", "closure_sha256", "gzip_output_sha256", "zstd_output_sha256")), "production result digests")
    _require(all(getattr(result, name) is True for name in RESULT_BOOLEANS), "production observation failed")
    return result


def qualify(result: object, result_type: type, policy_digest: str, outer: dict[str, bool]) -> dict[str, object]:
    _require(type(result) is result_type and tuple(field.name for field in fields(result_type)) == RESULT_FIELDS, "substituted production result")
    _require(all(type(getattr(result, name)) is str for name in RESULT_STRINGS), "production string types")
    _require(all(type(getattr(result, name)) is bool and getattr(result, name) for name in RESULT_BOOLEANS), "production boolean fields")
    _require(result.version == RESULT_VERSION and result.marker == MARKER, "production result version")
    _require(all(_hex(getattr(result, name)) for name in ("source_set_sha256", "closure_sha256", "gzip_output_sha256", "zstd_output_sha256")), "production result digests")
    _require(tuple(outer) == ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout") and all(type(value) is bool for value in outer.values()), "outer cleanup shape")
    _require(_hex(policy_digest) and result.seccomp_program_exact is True, "observed policy digest")
    checks = {
        "mount_view_exact": result.root_readonly_noexec and result.root_has_no_proc and result.host_paths_absent,
        "checkout_read_only": result.checkout_absent and result.no_acquisition_route,
        "user_namespace_exact": result.user_namespace_exact and result.namespace_ownership_exact,
        "pid_namespace_exact": result.pid_namespace_exact,
        "mount_namespace_exact": result.mount_namespace_exact,
        "network_namespace_exact": result.network_namespace_exact,
        "pid_one": result.pid_one,
        "capabilities_zero": all(getattr(result, name) for name in (
            "supplementary_groups_empty", "effective_capabilities_zero",
            "permitted_capabilities_zero", "inheritable_capabilities_zero",
            "bounding_capabilities_zero", "ambient_capabilities_zero",
            "capabilities_zero",
        )),
        "noroot_locked": result.noroot_locked,
        "nnp_set": result.no_new_privs,
        "seccomp_socket_denied": result.seccomp_installed and result.seccomp_denials_exact,
        "seccomp_io_uring_denied": result.seccomp_installed and result.seccomp_denials_exact,
        "no_acquisition_route": result.no_acquisition_route and result.exec_descriptor_consumed,
        "checkout_unchanged": outer["checkout"],
        "all_reaped": result.children_reaped and result.descendants_reaped and outer["children"],
        "mounts_restored": result.mounts_restored and outer["mounts"],
        "cleanup_restored": all(outer.values()) and all(getattr(result, name) for name in (
            "descriptors_restored", "children_reaped", "descendants_reaped",
            "mounts_restored", "paths_restored", "namespaces_released",
            "namespace_handles_released",
        )),
    }
    _require(tuple(checks) == CHECK_IDS and all(type(value) is bool and value for value in checks.values()), "Job E observation failed")
    return {"checks": checks, "policy_sha256": policy_digest}


def _read_source_set() -> tuple[dict[str, bytes], str]:
    root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held: dict[str, bytes] = {}
    digest = hashlib.sha256()
    try:
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
    finally:
        os.close(root_fd)
    return held, digest.hexdigest()


def _admission(revision: str, source_digest: str, launcher: bytes) -> bytes:
    value = {
        "bootstrap_sha256": hashlib.sha256(launcher).hexdigest(),
        "revision": revision,
        "source_set_sha256": source_digest,
        "version": "cogs.runtime-source-admission/v1",
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _wait_pidfd(pidfd: int, deadline: float) -> object:
    while time.monotonic() < deadline:
        if select.select((pidfd,), (), (), min(0.05, deadline - time.monotonic()))[0]:
            result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            if result is not None:
                return result
    raise RuntimeError("sudo child deadline")


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


def _sudo_child(input_fd: int, output_fd: int, error_fd: int, gate_fd: int) -> None:
    try:
        _require(os.read(gate_fd, 1) == b"G", "sudo release")
        os.close(gate_fd)
        os.setsid()
        null_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        for source, target in ((input_fd, 0), (output_fd, 1), (error_fd, 2)):
            os.dup2(source, target, inheritable=True)
        os.closerange(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
        command = (
            "/usr/bin/sudo", "-n", "--close-from=3", "/usr/bin/env", "-i",
            "/usr/bin/python3", "-I", "-B", os.fspath(Path(__file__).resolve()),
            "--production-root",
        )
        os.execve(command[0], command, {})
    except BaseException:
        os._exit(125)


def _sudo_launch(admission: bytes) -> tuple[bytes, bytes, object]:
    input_read, input_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    owned = {input_read, input_write, output_read, output_write, error_read, error_write, gate_read, gate_write}
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
            raise ExceptionGroup("Job E fork cleanup", [primary, *failures])
        raise
    if pid == 0:
        for descriptor in (input_write, output_read, error_read, gate_write):
            os.close(descriptor)
        _sudo_child(input_read, output_write, error_write, gate_read)
        os._exit(125)
    deadline = time.monotonic() + 30.0
    buffers = {output_read: bytearray(), error_read: bytearray()}
    status: object | None = None
    primary: BaseException | None = None
    try:
        pidfd = os.pidfd_open(pid, 0)
        for descriptor in (input_read, output_write, error_write, gate_read):
            owned.remove(descriptor)
            os.close(descriptor)
        _require(os.write(gate_write, b"G") == 1, "sudo release write")
        owned.remove(gate_write)
        os.close(gate_write)
        _require(os.write(input_write, admission) == len(admission), "sudo admission write")
        owned.remove(input_write)
        os.close(input_write)
        active = set(buffers)
        while active:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "sudo output deadline")
            ready = select.select(tuple(active), (), (), remaining)[0]
            for descriptor in ready:
                part = os.read(descriptor, MAX_RESULT + 1 - len(buffers[descriptor]))
                if part:
                    buffers[descriptor] += part
                    _require(len(buffers[descriptor]) <= MAX_RESULT, "sudo output bound")
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
                    failures.append(RuntimeError("blocked sudo child reap"))
            except BaseException as error:
                failures.append(error)
    else:
        try:
            os.close(pidfd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise ExceptionGroup("Job E process cleanup", ([primary] if primary else []) + failures)
    if primary is not None:
        raise primary
    _require(status is not None, "sudo status")
    return bytes(buffers[output_read]), bytes(buffers[error_read]), status


def _production_root() -> int:
    _require(os.geteuid() == 0 and not os.environ and sys.argv == [sys.argv[0], "--production-root"], "root envelope")
    ctypes = __import__("ctypes")
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    _require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() != 1, "root parent authority")
    _require(tuple(number for number, _identity in _fds()) == (0, 1, 2), "root descriptor baseline")
    raw = bytearray()
    while len(raw) <= 512:
        part = os.read(0, 513 - len(raw))
        if not part:
            break
        raw += part
    _require(0 < len(raw) <= 512, "root admission bound")
    admission_read, admission_write = os.pipe2(os.O_CLOEXEC)
    _require((admission_read, admission_write) == (3, 4), "root admission descriptors")
    _require(os.write(admission_write, raw) == len(raw), "root admission pipe")
    os.close(admission_write)
    root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    _require(root_fd == 4, "root source descriptor")
    os.set_inheritable(3, True)
    os.set_inheritable(4, True)
    os.execve("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", os.fspath(ROOT / LAUNCHER)), {})
    return 125


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


def _baseline() -> dict[str, object]:
    return {name: _observe(name) for name in ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")}


def _cleanup(before: dict[str, object]) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, value in before.items():
        try:
            result[name] = _observe(name) == value
        except BaseException:
            result[name] = False
    return result


def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _main() -> int:
    if sys.argv == [sys.argv[0], "--production-root"]:
        return _production_root()
    if sys.argv != [sys.argv[0], "--workflow-bound"] or os.geteuid() == 0:
        raise RuntimeError("Job E requires fixed workflow entry")
    common = _load_common()
    context = common.WorkflowContext.from_environ("E", __file__)
    before: dict[str, object] | None = None
    cleanup = dict.fromkeys(common.CLEANUP_KEYS, False)
    try:
        before = _baseline()
        checkout = before["checkout"]
        _require(checkout[0] == (context.head_sha + "\n").encode() and checkout[1] == b"", "source checkout admission")
        held, source_digest = _read_source_set()
        admission = _admission(context.head_sha, source_digest, held[LAUNCHER])
        output, error, status = _sudo_launch(admission)
        _require(status.si_code == os.CLD_EXITED and status.si_status == 0 and not error, "production sudo failed")
        module = _load_held_launcher(held[LAUNCHER], hashlib.sha256(held[LAUNCHER]).hexdigest())
        result = _decode_result(module, output, context.head_sha, source_digest)
        policy_digest = module._seccomp_digest()
        cleanup = _cleanup(before)
        qualified = qualify(result, module.RuntimeQualificationResult, policy_digest, cleanup)
        _require(all(qualified["checks"].values()) and all(cleanup.values()), "outer cleanup")
    except BaseException as error:
        if before is not None:
            cleanup = _cleanup(before)
        diagnostic = type(error).__name__.encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", dict.fromkeys(CHECK_IDS, "fail"), [], cleanup, "sandbox", diagnostic)
        return 1
    metadata = [{"id": "sandbox-policy", "role": "policy", "sha256": qualified["policy_sha256"], "size_bytes": 0}]
    common.finalize_report(context, "pass", dict.fromkeys(CHECK_IDS, "pass"), metadata, cleanup)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except BaseException:
        os.write(2, b"native-job-e-failed\n")
        raise SystemExit(1)

#!/usr/bin/python3
"""Job E: qualify only the production sandbox boundary on native Linux."""
from __future__ import annotations
import ctypes, errno, hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path
CHECK_IDS = (
    "mount_view_exact", "checkout_read_only", "user_namespace_exact",
    "pid_namespace_exact", "mount_namespace_exact", "network_namespace_exact",
    "pid_one", "capabilities_zero", "noroot_locked", "nnp_set",
    "seccomp_socket_denied", "seccomp_io_uring_denied", "no_acquisition_route",
    "checkout_unchanged", "all_reaped", "mounts_restored", "cleanup_restored",
)
_ROOT = "/run/cogs-o2-native-e-v1"
_LAUNCHER = "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
_CLONE_NEWNS, _CLONE_NEWUSER = 0x00020000, 0x10000000
_CLONE_NEWPID, _CLONE_NEWNET = 0x20000000, 0x40000000
_MS_RDONLY, _MS_NOSUID, _MS_NODEV, _MS_NOEXEC = 1, 2, 4, 8
_MS_REMOUNT, _MS_BIND, _MS_PRIVATE, _MS_REC = 32, 4096, 1 << 18, 16384
def qualify(adapter: object) -> dict[str, object]:
    observed = getattr(adapter, "observe")()
    if type(observed) is not dict or tuple(observed) != CHECK_IDS:
        raise RuntimeError("Job E observation shape")
    if not all(type(value) is bool and value for value in observed.values()):
        raise RuntimeError("Job E observation failed")
    policy = "sandbox-t2-x86-64-v1".encode()
    return {"checks": observed, "metadata": {"policy_sha256": hashlib.sha256(policy).hexdigest()}}
def _namespace(kind: str) -> tuple[int, int]:
    value = os.stat(f"/proc/self/ns/{kind}")
    return value.st_dev, value.st_ino
def _call(function: object, *arguments: object) -> None:
    ctypes.set_errno(0)
    result = function(*arguments)
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
def _mount(source: bytes | None, target: str, filesystem: bytes | None, flags: int, data: bytes | None = None) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
    _call(libc.mount, source, os.fsencode(target), filesystem, flags, data)
def _unshare(flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = (ctypes.c_int,)
    _call(libc.unshare, flags)
def _umount(target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
    _call(libc.umount2, os.fsencode(target), 0)
def _attempt(function: object, failures: list[BaseException], *arguments: object) -> None:
    try:
        function(*arguments)
    except BaseException as error:
        failures.append(error)
def _load_boundary() -> tuple[object, object]:
    path = Path.cwd() / _LAUNCHER
    spec = importlib.util.spec_from_file_location("_cogs_native_e_launcher", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("production launcher load")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module._SystemOps, module._enter_boundary
def _write_exact(path: str, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        if os.write(descriptor, value) != len(value):
            raise RuntimeError("namespace map short write")
    finally:
        os.close(descriptor)
def _probe_child(output_fd: int, initial_user: tuple[int, int]) -> None:
    ops_type, enter_boundary = _load_boundary()
    user_exact = _namespace("user") != initial_user
    facts = enter_boundary(ops_type(), _ROOT)
    denied = facts["seccomp_denials"]
    write_denied = False
    try:
        descriptor = os.open("/src/README.md", os.O_WRONLY | os.O_CLOEXEC)
    except OSError as error:
        write_denied = error.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    else:
        os.close(descriptor)
    capabilities = facts["capability_sets"]
    cap_zero = not any(capabilities[name] for name in ("effective", "permitted", "inheritable", "bounding", "ambient"))
    observations = {
        "mount_view_exact": not os.path.exists("/proc") and os.path.isdir("/src") and bool(os.statvfs("/").f_flag & os.ST_RDONLY) and bool(os.statvfs("/src").f_flag & os.ST_RDONLY),
        "checkout_read_only": write_denied,
        "user_namespace_exact": user_exact,
        "pid_namespace_exact": os.getpid() == 1,
        "pid_one": os.getpid() == 1,
        "capabilities_zero": cap_zero and capabilities["groups"] == (),
        "noroot_locked": facts["securebits"] == 0x0F,
        "nnp_set": facts["no_new_privs"] == 1,
        "seccomp_socket_denied": denied.get("socket") == errno.EPERM,
        "seccomp_io_uring_denied": denied.get("io_uring_setup") == errno.EPERM,
        "no_acquisition_route": all(value == errno.EPERM for value in denied.values()),
    }
    encoded = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if os.write(output_fd, encoded) != len(encoded):
        raise RuntimeError("probe result short write")
def _pid_one(output_fd: int, initial_user: tuple[int, int]) -> None:
    os.setgroups([])
    _unshare(_CLONE_NEWUSER)
    _write_exact("/proc/self/setgroups", b"deny")
    _write_exact("/proc/self/uid_map", b"0 0 1\n")
    _write_exact("/proc/self/gid_map", b"0 0 1\n")
    _unshare(_CLONE_NEWPID)
    pid = os.fork()
    if pid == 0:
        _probe_child(output_fd, initial_user)
        os._exit(0)
    os.close(output_fd)
    waited, status = os.waitpid(pid, 0)
    os._exit(0 if waited == pid and os.waitstatus_to_exitcode(status) == 0 else 1)

def _root_setup() -> int:
    if os.geteuid() != 0 or os.environ:
        raise RuntimeError("Job E root envelope")
    initial = {name: _namespace(name) for name in ("user", "mnt", "net")}
    checkout_fd = os.open(".", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    mounted: list[str] = []
    root_identity: tuple[int, int] | None = None
    owned = {checkout_fd, read_fd, write_fd}
    pid: int | None = None
    reaped = False
    try:
        _unshare(_CLONE_NEWNS | _CLONE_NEWNET)
        _mount(None, "/", None, _MS_REC | _MS_PRIVATE)
        os.mkdir(_ROOT, 0o700)
        root_status = os.lstat(_ROOT)
        root_identity = root_status.st_dev, root_status.st_ino
        _mount(b"tmpfs", _ROOT, b"tmpfs", _MS_NOSUID | _MS_NODEV, b"mode=0700,size=16777216")
        mounted.append(_ROOT)
        os.mkdir(f"{_ROOT}/src", 0o555)
        _mount(f"/proc/self/fd/{checkout_fd}".encode(), f"{_ROOT}/src", None, _MS_BIND)
        mounted.append(f"{_ROOT}/src")
        ro = _MS_BIND | _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        _mount(None, f"{_ROOT}/src", None, ro)
        root_ro = _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        _mount(None, _ROOT, b"tmpfs", root_ro)
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                _pid_one(write_fd, initial["user"])
            finally:
                os._exit(125)
        os.close(write_fd)
        owned.remove(write_fd)
        raw = os.read(read_fd, 16385)
        if len(raw) > 16384 or os.read(read_fd, 1):
            raise RuntimeError("probe result bound")
        waited, status = os.waitpid(pid, 0)
        reaped = waited == pid
        if not reaped or os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("probe process failed")
        observed = json.loads(raw)
        observed["mount_namespace_exact"] = _namespace("mnt") != initial["mnt"]
        observed["network_namespace_exact"] = _namespace("net") != initial["net"]
        observed["all_reaped"] = True
    finally:
        failures: list[BaseException] = []
        if pid is not None and not reaped:
            _attempt(os.kill, failures, pid, 9)
            _attempt(os.waitpid, failures, pid, 0)
        for descriptor in owned:
            _attempt(os.close, failures, descriptor)
        for target in reversed(mounted):
            _attempt(_umount, failures, target)
        if root_identity is not None:
            root_status = os.lstat(_ROOT)
            if (root_status.st_dev, root_status.st_ino) == root_identity:
                _attempt(os.rmdir, failures, _ROOT)
            else:
                failures.append(RuntimeError("Job E root replacement"))
        if failures:
            raise ExceptionGroup("Job E cleanup", failures)
    observed["mounts_restored"] = not os.path.exists(_ROOT)
    observed["cleanup_restored"] = observed["mounts_restored"]
    os.write(1, json.dumps(observed, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    return 0


class NativeSandboxAdapter:
    def observe(self) -> dict[str, bool]:
        git = ("/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=all")
        before = subprocess.run(git, check=True, capture_output=True).stdout
        descriptors = frozenset(os.listdir("/proc/self/fd"))
        children = Path("/proc/self/task/self/children").read_bytes()
        mounts = Path("/proc/self/mountinfo").read_bytes()
        namespaces = tuple(_namespace(name) for name in ("user", "mnt", "pid", "net"))
        command = ("/usr/bin/sudo", "-n", "--close-from=3", "/usr/bin/env", "-i", "/usr/bin/python3", "-I", "-B", str(Path(__file__).resolve()), "--root-setup")
        completed = subprocess.run(command, check=False, capture_output=True, env={})
        if completed.returncode or completed.stderr or len(completed.stdout) > 16384:
            raise RuntimeError("Job E root setup failed")
        value = json.loads(completed.stdout)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if canonical != completed.stdout:
            raise RuntimeError("Job E root result framing")
        after = subprocess.run(git, check=True, capture_output=True).stdout
        value["checkout_unchanged"] = before == after == b""
        value["all_reaped"] = value["all_reaped"] and Path("/proc/self/task/self/children").read_bytes() == children
        value["mounts_restored"] = value["mounts_restored"] and Path("/proc/self/mountinfo").read_bytes() == mounts
        parent_clean = frozenset(os.listdir("/proc/self/fd")) == descriptors and not os.path.exists(_ROOT)
        parent_clean = parent_clean and tuple(_namespace(name) for name in ("user", "mnt", "pid", "net")) == namespaces
        value["cleanup_restored"] = value["cleanup_restored"] and parent_clean and all(value.values())
        return {name: value.get(name) is True for name in CHECK_IDS}


def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _main() -> int:
    if sys.argv == [sys.argv[0], "--root-setup"]:
        return _root_setup()
    if sys.argv != [sys.argv[0], "--workflow-bound"] or os.geteuid() == 0:
        raise RuntimeError("Job E requires the fixed native entry")
    common = _load_common()
    context = common.WorkflowContext.from_environ("E", __file__)
    try:
        result = qualify(NativeSandboxAdapter())
    except BaseException as error:
        diagnostic = type(error).__name__.encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", dict.fromkeys(CHECK_IDS, "fail"), [], dict.fromkeys(common.CLEANUP_KEYS, False), "sandbox", diagnostic)
        return 1
    metadata = [{"id": "sandbox-policy", "role": "policy", "sha256": result["metadata"]["policy_sha256"], "size_bytes": 0}]
    common.finalize_report(context, "pass", dict.fromkeys(CHECK_IDS, "pass"), metadata, dict.fromkeys(common.CLEANUP_KEYS, True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except BaseException:
        os.write(2, b"native-job-e-failed\n")
        raise SystemExit(1)

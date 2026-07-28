#!/usr/bin/python3
from __future__ import annotations
import fcntl, hashlib, json, os, select, signal, struct, subprocess, sys, time
from pathlib import Path
CHECK_IDS = (
    "closure_prepared", "handoff_exact", "gzip_deterministic", "zstd_deterministic", "marker_exact", "no_linked_evidence", "cleanup_restored",
)
_SOURCES = (
    "deploy/aws-feasibility/remote/completion_elf.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "schemas/trusted-runtime-closure-v1.json",
)
_LAUNCHER, _MARKER, _MAX_RESULT = _SOURCES[2], "cogs-runtime-qualification-v1", 131072
_OUTPUT_SHA = hashlib.sha256((_MARKER + "\n").encode()).hexdigest()
def qualify(adapter: object) -> dict[str, object]:
    checks, metadata = getattr(adapter, "observe")()
    expected_metadata = {"closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256"}
    if type(checks) is not dict or tuple(checks) != CHECK_IDS:
        raise RuntimeError("integration observation shape")
    if not all(type(value) is bool and value for value in checks.values()):
        raise RuntimeError("integration observation failed")
    if type(metadata) is not dict or set(metadata) != expected_metadata:
        raise RuntimeError("integration metadata shape")
    if not all(type(value) is str and len(value) == 64 and set(value) <= set("0123456789abcdef") for value in metadata.values()):
        raise RuntimeError("integration metadata digest")
    return {"checks": checks, "metadata": metadata}
def _source_set(root: Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    launcher_sha = ""
    for relative in _SOURCES:
        data = (root / relative).read_bytes()
        encoded = relative.encode()
        digest.update(struct.pack("!I", len(encoded)) + encoded)
        digest.update(struct.pack("!Q", len(data)) + hashlib.sha256(data).digest())
        if relative == _LAUNCHER:
            launcher_sha = hashlib.sha256(data).hexdigest()
    return digest.hexdigest(), launcher_sha
def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(("/usr/bin/git", "-C", str(root), *arguments), env={"LC_ALL": "C"}, capture_output=True, check=False)
    if completed.returncode or completed.stderr:
        raise RuntimeError("fixed git observation failed")
    return completed.stdout
def _child(root: Path, descriptors: tuple[int, int, int, int, int]) -> None:
    admission_fd, root_fd, output_fd, error_fd, null_fd = descriptors
    uid, gid = os.getuid(), os.getgid()
    libc = __import__("ctypes").CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) != 0:
        os._exit(125)
    try:
        Path("/proc/self/setgroups").write_text("deny", encoding="ascii")
        Path("/proc/self/uid_map").write_text(f"0 {uid} 1\n", encoding="ascii")
        Path("/proc/self/gid_map").write_text(f"0 {gid} 1\n", encoding="ascii")
        for source, target in ((null_fd, 0), (output_fd, 1), (error_fd, 2), (admission_fd, 3), (root_fd, 4)):
            os.dup2(source, target, inheritable=target in (0, 1, 2, 3, 4))
        os.closerange(5, 65536)
        os.chdir(root)
        os.execve("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", _LAUNCHER), {})
    except BaseException:
        os._exit(125)
def _read_pipes(output_fd: int, error_fd: int, pid: int) -> tuple[bytes, bytes, int]:
    buffers = {output_fd: bytearray(), error_fd: bytearray()}
    active = set(buffers)
    deadline = time.monotonic() + 30.0
    try:
        while active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("integration deadline")
            ready, _, _ = select.select(tuple(active), (), (), remaining)
            for descriptor in ready:
                part = os.read(descriptor, _MAX_RESULT + 1 - len(buffers[descriptor]))
                if part:
                    buffers[descriptor] += part
                    if len(buffers[descriptor]) > _MAX_RESULT:
                        raise RuntimeError("integration output bound")
                else:
                    os.close(descriptor)
                    active.remove(descriptor)
    except BaseException:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        for descriptor in active:
            os.close(descriptor)
        raise
    waited, status = os.waitpid(pid, 0)
    if waited != pid:
        raise RuntimeError("integration reap identity")
    return bytes(buffers[output_fd]), bytes(buffers[error_fd]), status
def _launch(root: Path, admission: bytes) -> tuple[bytes, bytes, int]:
    admission_read, admission_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    null_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    held = tuple(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64) for fd in (admission_read, root_fd, output_write, error_write, null_fd))
    for descriptor in (admission_read, root_fd, output_write, error_write, null_fd):
        os.close(descriptor)
    pid = os.fork()
    if pid == 0:
        os.close(admission_write)
        os.close(output_read)
        os.close(error_read)
        _child(root, held)
    for descriptor in held:
        os.close(descriptor)
    os.close(output_write)
    os.close(error_write)
    try:
        if os.write(admission_write, admission) != len(admission):
            raise RuntimeError("admission short write")
    finally:
        os.close(admission_write)
    return _read_pipes(output_read, error_read, pid)
class ProductionIntegrationAdapter:
    def observe(self) -> tuple[dict[str, bool], dict[str, str]]:
        root = Path.cwd().resolve()
        before_status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        revision = _git(root, "rev-parse", "HEAD^{commit}").decode().strip()
        source_sha, launcher_sha = _source_set(root)
        admission = json.dumps({"bootstrap_sha256": launcher_sha, "revision": revision, "source_set_sha256": source_sha, "version": "cogs.runtime-source-admission/v1"}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        fd_before = frozenset(os.listdir("/proc/self/fd"))
        namespaces = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("user", "mnt", "pid", "net")}
        output, error, status = _launch(root, admission)
        if os.waitstatus_to_exitcode(status) != 0 or error:
            raise RuntimeError("production integration failed")
        canonical = json.dumps(json.loads(output), sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if canonical != output:
            raise RuntimeError("production result framing")
        result = json.loads(output)
        cleanup_names = ("descriptors_restored", "children_reaped", "descendants_reaped", "mounts_restored", "paths_restored", "namespaces_released", "namespace_handles_released")
        after_status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        checks = dict.fromkeys(CHECK_IDS, True)
        closure = result.get("closure_sha256")
        checks["closure_prepared"] = result.get("source_set_sha256") == source_sha and result.get("source_revision") == revision and isinstance(closure, str) and len(closure) == 64
        booleans = [value for value in result.values() if type(value) is bool]
        checks["handoff_exact"] = len(booleans) == 35 and all(booleans)
        checks["gzip_deterministic"] = result.get("gzip_output_sha256") == _OUTPUT_SHA
        checks["zstd_deterministic"] = result.get("zstd_output_sha256") == _OUTPUT_SHA
        checks["marker_exact"] = result.get("marker") == _MARKER
        checks["no_linked_evidence"] = "evidence" not in result
        parent_clean = frozenset(os.listdir("/proc/self/fd")) == fd_before and before_status == after_status == b""
        parent_clean = parent_clean and all(os.stat(f"/proc/self/ns/{name}").st_ino == value for name, value in namespaces.items())
        checks["cleanup_restored"] = parent_clean and all(result.get(name) is True for name in cleanup_names)
        metadata = {name: result[name] for name in ("closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256")}
        return checks, metadata
def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]
def _main() -> int:
    if sys.argv != [sys.argv[0], "--workflow-bound"] or os.geteuid() == 0:
        raise RuntimeError("integration requires fixed native entry")
    common = _load_common()
    context = common.WorkflowContext.from_environ("integration", __file__)
    try:
        result = qualify(ProductionIntegrationAdapter())
    except BaseException as error:
        diagnostic = type(error).__name__.encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", dict.fromkeys(CHECK_IDS, "fail"), [], dict.fromkeys(common.CLEANUP_KEYS, False), "integration", diagnostic)
        return 1
    metadata = [{"id": name.removesuffix("_sha256"), "role": "digest", "sha256": value, "size_bytes": 0} for name, value in result["metadata"].items()]
    common.finalize_report(context, "pass", dict.fromkeys(CHECK_IDS, "pass"), metadata, dict.fromkeys(common.CLEANUP_KEYS, True))
    return 0
if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except BaseException:
        os.write(2, b"native-integration-failed\n")
        raise SystemExit(1)

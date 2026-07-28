#!/usr/bin/python3
"""Native A: qualify mappings produced by the admitted production launcher."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib, json, os, resource, select, signal, struct, sys, time
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
SOURCES = (
    "deploy/aws-feasibility/remote/completion_elf.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
    "schemas/trusted-runtime-closure-v1.json",
)
CHECKS = (
    "elf_real", "python_closure_exact", "map_files_trusted",
    "mapped_closure_equal", "mapping_stable", "helper_reaped",
    "cleanup_restored",
)
_MAX_OUTPUT = 32_768

class QualificationError(RuntimeError):
    """The fixed Job A transaction did not prove its claim."""

def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)

def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]
def _git(*arguments: str) -> bytes:
    import subprocess
    completed = subprocess.run(
        ("/usr/bin/git", "-C", os.fspath(ROOT), *arguments),
        env={"LC_ALL": "C"}, capture_output=True, check=False, timeout=5,
    )
    _require(completed.returncode == 0 and completed.stderr == b"", "git observation")
    return completed.stdout
def _fds() -> tuple[tuple[int, int, int], ...]:
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        numbers = sorted(int(name) for name in os.listdir(directory))
        _require(len(numbers) <= 256 and len(numbers) == len(set(numbers)), "descriptor bound")
        rows = []
        for number in numbers:
            if number == directory:
                continue
            try:
                value = os.fstat(number)
            except OSError as error:
                raise QualificationError("descriptor identity") from error
            rows.append((number, value.st_dev, value.st_ino))
        return tuple(rows)
    finally:
        os.close(directory)
def _children() -> tuple[int, ...]:
    raw = Path("/proc/self/task/self/children").read_bytes()
    _require(len(raw) <= 65_536, "children bound")
    values = tuple(int(value) for value in raw.split())
    _require(len(values) <= 16 and len(values) == len(set(values)), "children shape")
    return values
def _mounts() -> str:
    raw = Path("/proc/self/mountinfo").read_bytes()
    _require(len(raw) <= 4_194_304, "mountinfo bound")
    return hashlib.sha256(raw).hexdigest()
def _namespaces() -> tuple[tuple[str, int, int], ...]:
    return tuple(
        (name, value.st_dev, value.st_ino)
        for name in ("user", "pid", "mnt", "net")
        for value in (os.stat(f"/proc/self/ns/{name}"),)
    )

@dataclass(frozen=True)
class Snapshot:
    descriptors: tuple[tuple[int, int, int], ...]
    children: tuple[int, ...]
    path_absent: bool
    mounts: str
    namespaces: tuple[tuple[str, int, int], ...]
    limits: tuple[int, int]
    checkout: tuple[bytes, bytes]

    @classmethod
    def capture(cls, private_root: Path) -> "Snapshot":
        return cls(
            _fds(), _children(), not private_root.exists(), _mounts(),
            _namespaces(), resource.getrlimit(resource.RLIMIT_NOFILE),
            (_git("rev-parse", "HEAD^{commit}"),
             _git("status", "--porcelain=v1", "--untracked-files=all")),
        )

    def compare(self, private_root: Path) -> dict[str, bool]:
        after = Snapshot.capture(private_root)
        return {
            "descriptors": self.descriptors == after.descriptors,
            "children": self.children == after.children,
            "paths": self.path_absent and after.path_absent,
            "mounts": self.mounts == after.mounts,
            "namespaces": self.namespaces == after.namespaces,
            "limits": self.limits == after.limits,
            "checkout": self.checkout == after.checkout and after.checkout[1] == b"",
        }

def _source_admission(revision: str) -> bytes:
    digest = hashlib.sha256()
    launcher_digest = ""
    for relative in SOURCES:
        data = (ROOT / relative).read_bytes()
        encoded = relative.encode()
        digest.update(struct.pack("!I", len(encoded)) + encoded)
        digest.update(struct.pack("!Q", len(data)) + hashlib.sha256(data).digest())
        if ROOT / relative == LAUNCHER:
            launcher_digest = hashlib.sha256(data).hexdigest()
    value = {
        "bootstrap_sha256": launcher_digest,
        "revision": revision,
        "source_set_sha256": digest.hexdigest(),
        "version": "cogs.runtime-source-admission/v1",
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

def _child(admission_fd: int, root_fd: int, output_fd: int, error_fd: int,
           release_fd: int, private_root: Path) -> None:
    try:
        _require(os.read(release_fd, 1) == b"R", "release gate")
        os.close(release_fd)
        libc = __import__("ctypes").CDLL(None, use_errno=True)
        _require(libc.unshare(0x10000000 | 0x00020000) == 0, "namespace setup")
        uid, gid = os.getuid(), os.getgid()
        Path("/proc/self/setgroups").write_text("deny", encoding="ascii")
        Path("/proc/self/uid_map").write_text(f"0 {uid} 1\n", encoding="ascii")
        Path("/proc/self/gid_map").write_text(f"0 {gid} 1\n", encoding="ascii")
        _require(libc.mount(None, b"/", None, 1 << 14 | 1 << 18, None) == 0, "private mounts")
        source = os.fsencode(private_root)
        _require(libc.mount(source, b"/run", None, 4096 | 16384, None) == 0, "preparation root")
        for source_fd, target in ((admission_fd, 3), (root_fd, 4), (output_fd, 1), (error_fd, 2)):
            os.dup2(source_fd, target, inheritable=True)
        os.closerange(5, 65_536)
        os.chdir(ROOT)
        os.execve("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", os.fspath(LAUNCHER)), {})
    except BaseException:
        os._exit(125)

def _wait(pid: int, pidfd: int, output_fd: int, error_fd: int) -> tuple[bytes, bytes, int]:
    buffers = {output_fd: bytearray(), error_fd: bytearray()}
    active = set(buffers)
    deadline = time.monotonic() + 30
    status = None
    try:
        while active or status is None:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "launcher deadline")
            ready, _, _ = select.select(tuple(active), (), (), min(remaining, 0.05))
            for descriptor in ready:
                block = os.read(descriptor, _MAX_OUTPUT + 1 - len(buffers[descriptor]))
                if block:
                    buffers[descriptor] += block
                    _require(len(buffers[descriptor]) <= _MAX_OUTPUT, "launcher output bound")
                else:
                    os.close(descriptor)
                    active.remove(descriptor)
            waited, observed = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                status = observed
        return bytes(buffers[output_fd]), bytes(buffers[error_fd]), status
    except BaseException:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                break
            time.sleep(0.01)
        else:
            raise QualificationError("launcher reap uncertainty")
        for descriptor in active:
            os.close(descriptor)
        raise

def _launch(revision: str, private_root: Path) -> Mapping[str, object]:
    admission = _source_admission(revision)
    admission_read, admission_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    release_read, release_write = os.pipe2(os.O_CLOEXEC)
    source_root = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        for descriptor in (admission_write, output_read, error_read, release_write):
            os.close(descriptor)
        _child(admission_read, source_root, output_write, error_write, release_read, private_root)
    try:
        pidfd = os.pidfd_open(pid, 0)
    except BaseException:
        os.close(release_write)
        deadline = time.monotonic() + 5
        while os.waitpid(pid, os.WNOHANG)[0] != pid:
            _require(time.monotonic() < deadline, "gated child reap")
            time.sleep(0.01)
        for descriptor in (admission_read, admission_write, source_root,
                           output_read, output_write, error_read, error_write, release_read):
            os.close(descriptor)
        raise
    for descriptor in (admission_read, source_root, output_write, error_write, release_read):
        os.close(descriptor)
    try:
        _require(os.write(admission_write, admission) == len(admission), "admission write")
        os.close(admission_write)
        admission_write = -1
        _require(os.write(release_write, b"R") == 1, "release write")
        os.close(release_write)
        release_write = -1
        output, error, status = _wait(pid, pidfd, output_read, error_read)
    finally:
        for descriptor in (admission_write, release_write, pidfd):
            if descriptor >= 0:
                os.close(descriptor)
    _require(os.waitstatus_to_exitcode(status) == 0 and error == b"", "production launcher")
    value = json.loads(output)
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _require(type(value) is dict and canonical == output, "production result framing")
    return value


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= set("0123456789abcdef")
def qualify(result: Mapping[str, object], revision: str) -> list[dict[str, object]]:
    _require(type(result) is dict and result.get("version") == "cogs.runtime-qualification/v1", "result shape")
    _require(result.get("source_revision") == revision, "result source")
    _require(result.get("mapped_generations_exact") is True, "mapping observation")
    _require(result.get("children_reaped") is True and result.get("descendants_reaped") is True, "helper cleanup")
    objects = result.get("mapping_objects")
    _require(type(objects) is list and 2 <= len(objects) <= 127, "mapping objects")
    rows: list[dict[str, object]] = []
    identities = set()
    for index, value in enumerate(objects):
        _require(type(value) is dict and set(value) == {"role", "sha256", "size_bytes", "soname", "needed"}, "mapping object shape")
        role, digest, size = value["role"], value["sha256"], value["size_bytes"]
        _require(role in ("executable", "loader", "library") and _digest(digest), "mapping object identity")
        _require(type(size) is int and 0 < size <= 536_870_912, "mapping object size")
        _require(value["soname"] is None or type(value["soname"]) is str, "mapping soname")
        needed = value["needed"]
        _require(type(needed) is list and all(type(item) is str for item in needed), "mapping needed")
        _require(digest not in identities, "mapping object duplicate")
        identities.add(digest)
        rows.append({"kind": "object", "id": f"python-object-{index}", **value})
    mapping = result.get("mapping_sha256")
    closure = result.get("closure_sha256")
    _require(_digest(mapping) and _digest(closure), "mapping summary")
    rows.append({"kind": "summary", "closure_sha256": closure, "mapping_sha256": mapping})
    return rows
def _workflow_bound() -> int:
    common = _load_common()
    context = common.WorkflowContext.from_environ("A", __file__)
    private_root = Path(f"/tmp/cogs-native-a-{os.getpid()}")
    baseline = Snapshot.capture(private_root)
    checks = dict.fromkeys(CHECKS, "fail")
    metadata: list[dict[str, object]] = []
    failure: BaseException | None = None
    try:
        private_root.mkdir(mode=0o700)
        metadata = qualify(_launch(context.head_sha, private_root), context.head_sha)
        private_root.rmdir()
    except BaseException as error:
        failure = error
        if private_root.exists():
            try:
                private_root.rmdir()
            except BaseException as cleanup_error:
                failure = ExceptionGroup("Job A primary and cleanup", [error, cleanup_error])
    try:
        cleanup = baseline.compare(private_root)
    except BaseException as error:
        cleanup = dict.fromkeys(common.CLEANUP_KEYS, False)
        failure = error if failure is None else ExceptionGroup("Job A observation", [failure, error])
    if failure is None and all(cleanup.values()):
        common.finalize_report(context, "pass", dict.fromkeys(CHECKS, "pass"), metadata, cleanup)
        return 0
    diagnostic = f"{type(failure).__name__}:{failure}".encode()[:common.REPORT_LIMIT]
    common.finalize_report(context, "fail", checks, [], cleanup, "runtime_mappings", diagnostic)
    return 1
def _dispatch(arguments: list[str], workflow: object = _workflow_bound) -> int:
    if not __debug__ or arguments != ["--workflow-bound"]:
        raise QualificationError("Job A requires the fixed workflow entry")
    return workflow()  # type: ignore[operator]


if __name__ == "__main__":
    try:
        raise SystemExit(_dispatch(sys.argv[1:]))
    except BaseException:
        os.write(2, b"native-a-failed\n")
        raise SystemExit(1)

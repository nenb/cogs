#!/usr/bin/python3
"""Native Job C: qualify production descriptor primitives and exact cleanup."""
import ctypes, errno, fcntl, hashlib, os, resource, select, signal, stat, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
TARGET_SOFT, LOW_FD, HIGH_FD = 8193, 198, 4096
UINT_MAX, SYS_CLOSE_RANGE, SYS_DUP3 = (1 << 32) - 1, 436, 292
CHECKS = (
    "nofile_measured", "nofile_normalized", "fd_198_exact", "fd_4096_exact", "close_range_exact",
    "cloexec_exact", "inheritance_exact", "limit_restored", "cleanup_restored",
)
def _require(condition, message):
    if not condition:
        raise RuntimeError(message)
def _syscall(number, *arguments):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(number, *arguments)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)
def _fds():
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        rows = []
        for name in os.listdir(directory):
            descriptor = int(name)
            if descriptor != directory:
                status = os.fstat(descriptor)
                rows.append((descriptor, stat.S_IFMT(status.st_mode), status.st_dev, status.st_ino))
        return tuple(sorted(rows))
    finally:
        os.close(directory)
def _children():
    with Path("/proc/self/task/self/children").open("rb", buffering=0) as stream:
        data = stream.read(65_537)
    _require(len(data) <= 65_536, "children baseline bound")
    return tuple(sorted(int(value) for value in data.split()))
def _digest(path):
    with Path(path).open("rb", buffering=0) as stream:
        value = stream.read(1_048_577)
    _require(len(value) <= 1_048_576, "baseline input bound")
    return hashlib.sha256(value).hexdigest()
def _git(*arguments):
    result = subprocess.run(("/usr/bin/git", *arguments), cwd=ROOT, env={"LC_ALL": "C"},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
    _require(result.returncode == 0 and result.stderr == b"" and len(result.stdout) <= 1_048_576,
             "checkout baseline")
    return result.stdout
def _state(job):
    checkout = (_git("rev-parse", "HEAD^{commit}"),
                _git("status", "--porcelain=v2", "--untracked-files=all"),
                _git("config", "--local", "--list", "--show-origin", "--null"))
    return {
        "descriptors": _fds(),
        "children": (tuple((pid, _identity(pid)) for pid in _children()), os.getpgrp(), os.getsid(0)),
        "paths": not Path(f"/tmp/cogs-native-qualification-{job}.json").exists(),
        "mounts": _digest("/proc/self/mountinfo"),
        "namespaces": tuple(os.readlink(f"/proc/self/ns/{name}") for name in ("user", "pid", "mnt", "net")),
        "limits": resource.getrlimit(resource.RLIMIT_NOFILE),
        "checkout": checkout,
    }
def _identity(pid):
    with Path(f"/proc/{pid}/stat").open("rb", buffering=0) as stream:
        row = stream.read(4097)
    _require(len(row) <= 4096 and row.endswith(b"\n"), "process identity")
    fields = row[row.rfind(b")") + 2:].split()
    _require(len(fields) >= 20, "process identity fields")
    executable = os.stat(f"/proc/{pid}/exe")
    return (int(fields[19]), int(fields[1]), int(fields[2]), int(fields[3]), executable.st_dev, executable.st_ino)
class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds
    def remaining(self):
        return max(0.0, self.end - time.monotonic())

class SystemOps:
    def __init__(self):
        self.before = _state("C")
        self.owned = []
        self.child = None
        self.close_certain = True
        self.process_certain = True
    def _pipe(self):
        pair = os.pipe2(os.O_CLOEXEC)
        self.owned.extend(pair)
        return pair
    def _close(self, descriptor):
        self.owned.remove(descriptor)
        try:
            os.close(descriptor)
        except OSError:
            self.close_certain = False
            raise
    def measure_and_normalize(self):
        soft, hard = self.before["limits"]
        measured = hard == resource.RLIM_INFINITY or hard >= TARGET_SOFT
        _require(measured, "required descriptor capacity unavailable")
        resource.setrlimit(resource.RLIMIT_NOFILE, (TARGET_SOFT, hard))
        normalized = resource.getrlimit(resource.RLIMIT_NOFILE) == (TARGET_SOFT, hard)
        return measured, normalized
    def make_exact_descriptors(self):
        baseline_numbers = {row[0] for row in self.before["descriptors"]}
        _require(LOW_FD not in baseline_numbers and HIGH_FD not in baseline_numbers,
                 "fixed descriptor occupied")
        source, spare = self._pipe()
        low = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, LOW_FD)
        self.owned.append(low)
        high = fcntl.fcntl(source, fcntl.F_DUPFD, HIGH_FD)
        self.owned.append(high)
        cloexec = bool(fcntl.fcntl(low, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        inheritable = not bool(fcntl.fcntl(high, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        return low == LOW_FD, high == HIGH_FD, cloexec and inheritable
    def prove_inheritance(self):
        reader, writer = self._pipe()
        gate_reader, gate_writer = self._pipe()
        pid = os.fork()
        self.child = {"pid": pid, "pidfd": None, "identity": None, "gate": gate_writer}
        if pid == 0:
            try:
                if os.read(gate_reader, 1) != b"G":
                    os._exit(120)
                _syscall(SYS_DUP3, writer, 197, 0)
                _syscall(SYS_CLOSE_RANGE, 3, 196, 0)
                _syscall(SYS_CLOSE_RANGE, 199, HIGH_FD - 1, 0)
                _syscall(SYS_CLOSE_RANGE, HIGH_FD + 1, UINT_MAX, 0)
                code = (
                    "import os\n"
                    "def live(n):\n try: os.fstat(n); return True\n except OSError: return False\n"
                    "seen={n for n in range(4097) if live(n)}\n"
                    "os.write(197,b'exact' if seen=={0,1,2,197,4096} else b'bad')"
                )
                os.execve("/usr/bin/python3", ["python3", "-I", "-B", "-c", code], {})
            except BaseException:
                os._exit(127)
        pidfd = os.pidfd_open(pid, 0)
        self.owned.append(pidfd)
        self.child["pidfd"] = pidfd
        identity = _identity(pid)
        expected = os.stat("/usr/bin/python3")
        _require(identity[1:4] == (os.getpid(), os.getpgrp(), os.getsid(0)), "child ownership")
        _require(identity[4:] == (expected.st_dev, expected.st_ino), "child executable")
        self.child["identity"] = identity
        self._close(writer)
        self._close(gate_reader)
        _require(os.write(gate_writer, b"G") == 1, "release write")
        self._close(gate_writer)
        deadline = Deadline(5)
        ready = select.select([reader], [], [], deadline.remaining())[0]
        data = os.read(reader, 5) if ready else b""
        _require(select.select([pidfd], [], [], deadline.remaining())[0], "child deadline")
        info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
        exact_exit = info.si_code == os.CLD_EXITED and info.si_status == 0
        waited, status = os.waitpid(pid, os.WNOHANG)
        _require(waited == pid, "child reap")
        self.child = None
        self._close(pidfd)
        return exact_exit and status == 0 and data == b"exact"
    def prove_close_range(self):
        _syscall(SYS_CLOSE_RANGE, HIGH_FD, HIGH_FD, 0)
        self.owned.remove(HIGH_FD)
        try:
            fcntl.fcntl(HIGH_FD, fcntl.F_GETFD)
        except OSError as error:
            return error.errno == errno.EBADF
        return False
    def restore(self):
        deadline = Deadline(3)
        child = self.child
        if child is not None:
            try:
                if child["pidfd"] is None:
                    _require(os.write(child["gate"], b"A") == 1, "abort write")
                    self._close(child["gate"])
                    while os.waitpid(child["pid"], os.WNOHANG)[0] != child["pid"]:
                        _require(deadline.remaining() > 0, "cleanup child deadline")
                        select.select([], [], [], min(0.01, deadline.remaining()))
                else:
                    signal.pidfd_send_signal(child["pidfd"], signal.SIGKILL)
                    _require(select.select([child["pidfd"]], [], [], deadline.remaining())[0], "cleanup child deadline")
                    _require(os.waitpid(child["pid"], os.WNOHANG)[0] == child["pid"], "cleanup reap")
            except BaseException:
                self.process_certain = False
            self.child = None
        for descriptor in tuple(reversed(self.owned)):
            try:
                self._close(descriptor)
            except OSError:
                pass
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, self.before["limits"])
        except OSError:
            self.close_certain = False
        try:
            after = _state("C")
        except BaseException:
            return dict.fromkeys(("descriptors", "children", "paths", "mounts",
                                  "namespaces", "limits", "checkout"), False)
        cleanup = {name: self.before[name] == after[name] for name in self.before}
        cleanup["descriptors"] &= self.close_certain
        cleanup["children"] &= self.process_certain and self.child is None
        return cleanup

def qualify(ops):
    observed = dict.fromkeys(CHECKS, False)
    try:
        observed["nofile_measured"], observed["nofile_normalized"] = ops.measure_and_normalize()
        observed["fd_198_exact"], observed["fd_4096_exact"], observed["cloexec_exact"] = ops.make_exact_descriptors()
        observed["inheritance_exact"] = ops.prove_inheritance()
        observed["close_range_exact"] = ops.prove_close_range()
    except (OSError, RuntimeError, ValueError):
        pass
    cleanup = ops.restore()
    observed["limit_restored"] = cleanup["limits"]
    observed["cleanup_restored"] = all(cleanup.values())
    return {name: "pass" if observed[name] else "fail" for name in CHECKS}, cleanup

def _load_common():
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    common = __import__("common")
    del sys.path[0]
    return common

def _native():
    common = _load_common()
    context = common.WorkflowContext.from_environ("C", __file__)
    ops = None
    try:
        ops = SystemOps()
        checks, cleanup = qualify(ops)
    except BaseException:
        checks = dict.fromkeys(CHECKS, "fail")
        cleanup = ops.restore() if ops is not None else dict.fromkeys(common.CLEANUP_KEYS, False)
    passing = all(value == "pass" for value in checks.values()) and all(cleanup.values())
    common.finalize_report(context, "pass" if passing else "fail", checks, [], cleanup,
                           None if passing else "descriptors",
                           None if passing else b"descriptor qualification failed")
    return 0 if passing else 1

def main():
    if not __debug__ or sys.argv != [sys.argv[0], "--workflow-bound"]:
        raise SystemExit(2)
    try:
        status = _native()
    except BaseException:
        status = 1
    raise SystemExit(status)

if __name__ == "__main__":
    main()

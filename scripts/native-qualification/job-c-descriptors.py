#!/usr/bin/python3
"""Native Job C: qualify exact Linux descriptor behaviour."""
import ctypes, errno, fcntl, json, os, resource, select, signal, sys, time

_TARGET_SOFT, _LOW, _HIGH = 8193, 198, 4096
_UINT_MAX, _SYS_CLOSE_RANGE, _SYS_DUP3 = (1 << 32) - 1, 436, 292
_CHECKS = ("nofile_measured", "nofile_normalized", "fd_198_exact", "fd_4096_exact", "close_range_exact", "cloexec_exact", "inheritance_exact", "limit_restored", "cleanup_restored")

def _syscall(number, *arguments):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(number, *arguments)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)
def _fds():
    return frozenset(int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal())
class SystemOps:
    def __init__(self):
        self.limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        self.baseline = _fds()
        self.owned = []
        self.child = None
    def measure_and_normalize(self):
        soft, hard = self.limit
        if hard != resource.RLIM_INFINITY and hard < _TARGET_SOFT:
            raise RuntimeError("required descriptor capacity unavailable")
        resource.setrlimit(resource.RLIMIT_NOFILE, (_TARGET_SOFT, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE) == (_TARGET_SOFT, hard)
    def make_exact_descriptors(self):
        if _LOW in self.baseline or _HIGH in self.baseline:
            raise RuntimeError("fixed descriptor already occupied")
        source, spare = os.pipe2(os.O_CLOEXEC)
        self.owned.extend((source, spare))
        low = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, _LOW)
        self.owned.append(low)
        high = fcntl.fcntl(source, fcntl.F_DUPFD, _HIGH)
        self.owned.append(high)
        low_cloexec = bool(fcntl.fcntl(low, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        high_inheritable = not bool(fcntl.fcntl(high, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        return low == _LOW, high == _HIGH, low_cloexec and high_inheritable
    def prove_inheritance(self):
        reader, writer = os.pipe2(os.O_CLOEXEC)
        self.owned.extend((reader, writer))
        pid = os.fork()
        if pid == 0:
            try:
                _syscall(_SYS_DUP3, writer, 197, 0)
                _syscall(_SYS_CLOSE_RANGE, 3, 196, 0)
                _syscall(_SYS_CLOSE_RANGE, 199, _HIGH - 1, 0)
                _syscall(_SYS_CLOSE_RANGE, _HIGH + 1, _UINT_MAX, 0)
                code = ("import os; expected={0,1,2,197,4096}; "
                        "seen={int(x) for x in os.listdir('/proc/self/fd') if x.isdecimal()}; "
                        "seen={x for x in seen if x in expected or _live(x)}")
                code = "def _live(n):\n try: os.fstat(n); return True\n except OSError: return False\n" + code
                code += "; os.write(197,b'exact' if seen==expected else b'bad')"
                os.execve("/usr/bin/python3", ["python3", "-I", "-B", "-c", code], {})
            except BaseException:
                os._exit(127)
        pidfd = os.pidfd_open(pid, 0)
        self.owned.append(pidfd)
        self.child = (pid, pidfd)
        os.close(writer)
        self.owned.remove(writer)
        deadline = time.monotonic() + 5.0
        ready = select.select([reader], [], [], 5.0)[0]
        data = os.read(reader, 5) if ready else b""
        timeout = max(0.0, deadline - time.monotonic())
        exited = bool(select.select([pidfd], [], [], timeout)[0])
        waited, status = os.waitpid(pid, os.WNOHANG) if exited else (0, 0)
        if waited == pid:
            self.child = None
        return waited == pid and status == 0 and data == b"exact"
    def prove_close_range(self):
        _syscall(_SYS_CLOSE_RANGE, _HIGH, _HIGH, 0)
        try:
            fcntl.fcntl(_HIGH, fcntl.F_GETFD)
        except OSError as error:
            if error.errno == errno.EBADF:
                self.owned.remove(_HIGH)
                return True
        return False
    def restore(self):
        clean = True
        if self.child is not None:
            pid, pidfd = self.child
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                clean = False
            try:
                ready = select.select([pidfd], [], [], 1.0)[0]
                clean = clean and ready and os.waitpid(pid, os.WNOHANG)[0] == pid
            except (OSError, ChildProcessError):
                clean = False
            self.child = None
        for descriptor in reversed(self.owned):
            try:
                os.close(descriptor)
            except OSError:
                clean = False
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, self.limit)
        except OSError:
            clean = False
        return clean and resource.getrlimit(resource.RLIMIT_NOFILE) == self.limit and _fds() == self.baseline
def qualify(ops):
    outcomes = {name: "unobserved" for name in _CHECKS}
    try:
        outcomes["nofile_measured"] = "pass"
        outcomes["nofile_normalized"] = "pass" if ops.measure_and_normalize() else "fail"
        low, high, cloexec = ops.make_exact_descriptors()
        outcomes["fd_198_exact"] = "pass" if low else "fail"
        outcomes["fd_4096_exact"] = "pass" if high else "fail"
        outcomes["cloexec_exact"] = "pass" if cloexec else "fail"
        outcomes["inheritance_exact"] = "pass" if ops.prove_inheritance() else "fail"
        outcomes["close_range_exact"] = "pass" if ops.prove_close_range() else "fail"
    except (OSError, RuntimeError):
        pass
    restored = ops.restore()
    outcomes["limit_restored"] = "pass" if restored else "fail"
    outcomes["cleanup_restored"] = "pass" if restored else "fail"
    passed = all(value == "pass" for value in outcomes.values())
    return {"checks": [{"id": name, "outcome": outcomes[name]} for name in _CHECKS],
            "cleanup": {"descriptors": restored, "limits": restored}, "job": "C",
            "result": "pass" if passed else "fail"}
def main():
    if sys.argv != [sys.argv[0], "--native"] or sys.platform != "linux" or os.uname().machine != "x86_64":
        raise SystemExit(2)
    try:
        report = qualify(SystemOps())
    except BaseException:
        report = {"checks": [{"id": name, "outcome": "unobserved"} for name in _CHECKS], "cleanup": {"descriptors": False, "limits": False}, "job": "C", "result": "fail"}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if report["result"] == "pass" else 1)
if __name__ == "__main__":
    main()

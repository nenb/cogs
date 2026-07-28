import ctypes, json, os, select, signal, sys, time
_PR_SET_PDEATHSIG, _PR_SET_CHILD_SUBREAPER, _PR_GET_CHILD_SUBREAPER = 1, 36, 37
_CHECKS = ("pdeathsig_armed", "parent_handshake_exact", "before_release_death", "after_release_death", "starttime_revalidated", "session_owned", "process_group_owned", "term_kill_bounded", "all_reaped", "cleanup_restored")
def _prctl(option, argument=0):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, argument, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl failed")
def _must(condition, message):
    if not condition:
        raise RuntimeError(message)
def _identity(pid):
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as stream:
        row = stream.read(4097)
    _must(len(row) <= 4096 and row.endswith(b"\n"), "invalid process identity record")
    fields = row[row.rfind(b")") + 2:].split()
    _must(len(fields) >= 20, "short process identity record")
    return int(fields[19]), int(fields[1]), int(fields[3]), int(fields[2])
def _fds(): return frozenset(int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal())
def _pause():
    while True: signal.pause()
class SystemOps:
    def __init__(self):
        value = ctypes.c_int()
        _prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(value))
        self.old_subreaper = value.value
        self.fd_baseline = _fds()
        self.child_baseline = open("/proc/self/task/self/children", "rb").read()
        self.fds = []
        self.processes = {}
        _prctl(_PR_SET_CHILD_SUBREAPER, 1)
    def _pipe(self):
        pair = os.pipe2(os.O_CLOEXEC)
        self.fds.extend(pair)
        return pair
    def _close(self, descriptor):
        os.close(descriptor)
        self.fds.remove(descriptor)
    def _register(self, pid):
        pidfd = os.pidfd_open(pid, 0)
        self.fds.append(pidfd)
        identity = _identity(pid)
        self.processes[pid] = (pidfd, identity)
        return pidfd, identity
    def _exact(self, pid):
        return pid in self.processes and _identity(pid) == self.processes[pid][1]
    def _reap(self, pid, deadline):
        pidfd, _ = self.processes[pid]
        timeout = max(0.0, deadline - time.monotonic())
        if not select.select([pidfd], [], [], timeout)[0]:
            return False
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
        self._close(pidfd)
        del self.processes[pid]
        return True
    def _line(self, descriptor, deadline):
        timeout = max(0.0, deadline - time.monotonic())
        if select.select([descriptor], [], [], timeout)[0]:
            value = os.read(descriptor, 65)
            if value.endswith(b"\n") and value.count(b"\n") == 1:
                return value[:-1]
        raise RuntimeError("bounded child handshake failed")
    def pdeath_case(self, after_release):
        info_r, info_w = self._pipe()
        go_r, go_w = self._pipe()
        release_r, release_w = self._pipe()
        parent = os.fork()
        if parent == 0:
            child = os.fork()
            if child == 0:
                try:
                    before = os.getppid()
                    os.setsid()
                    _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
                    _must(os.getppid() == before, "parent changed while arming PDEATHSIG")
                    os.write(info_w, f"{os.getpid()}\n".encode("ascii"))
                    if after_release:
                        if os.read(release_r, 1) != b"R":
                            os._exit(121)
                        os.write(info_w, b"released\n")
                    _pause()
                except BaseException:
                    os._exit(122)
            if os.read(go_r, 1) != b"G":
                os._exit(123)
            if after_release:
                os.write(release_w, b"R")
                if os.read(go_r, 1) != b"G":
                    os._exit(124)
            os._exit(0)
        self._register(parent)
        deadline = time.monotonic() + 5.0
        child = int(self._line(info_r, deadline))
        _, child_identity = self._register(child)
        _must(child_identity[1:] == (parent, child, child), "PDEATHSIG parent/session/group")
        os.write(go_w, b"G")
        if after_release:
            _must(self._line(info_r, deadline) == b"released", "release handshake mismatch")
            os.write(go_w, b"G")
        parent_reaped = self._reap(parent, deadline)
        child_reaped = self._reap(child, deadline)
        _must(parent_reaped and child_reaped, "PDEATHSIG reap")
    def terminate_tree(self):
        info_r, info_w = self._pipe()
        leader = os.fork()
        if leader == 0:
            try:
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                descendant = os.fork()
                if descendant == 0:
                    _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    os.write(info_w, f"{os.getpid()}\n".encode("ascii"))
                    _pause()
                _pause()
            except BaseException:
                os._exit(125)
        deadline = time.monotonic() + 5.0
        descendant = int(self._line(info_r, deadline))
        leader_pidfd, leader_identity = self._register(leader)
        descendant_pidfd, descendant_identity = self._register(descendant)
        owned = leader_identity[2:] == (leader, leader) and descendant_identity[1:] == (leader, leader, leader)
        for pidfd, pid in ((descendant_pidfd, descendant), (leader_pidfd, leader)):
            _must(self._exact(pid), "identity drift before TERM")
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        _must(not select.select([leader_pidfd, descendant_pidfd], [], [], 0.1)[0], "TERM bound")
        for pidfd, pid in ((descendant_pidfd, descendant), (leader_pidfd, leader)):
            _must(self._exact(pid), "identity drift before KILL")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        leader_reaped = self._reap(leader, deadline)
        descendant_reaped = self._reap(descendant, deadline)
        _must(owned and leader_reaped and descendant_reaped, "owned process tree reap")
    def restore(self):
        clean = True
        deadline = time.monotonic() + 2.0
        for pid, (pidfd, _) in tuple(self.processes.items()):
            try:
                if self._exact(pid):
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except (OSError, RuntimeError):
                clean = False
            try:
                clean = self._reap(pid, deadline) and clean
            except (OSError, ChildProcessError):
                clean = False
        for descriptor in reversed(self.fds):
            try:
                os.close(descriptor)
            except OSError:
                clean = False
        try:
            _prctl(_PR_SET_CHILD_SUBREAPER, self.old_subreaper)
        except OSError:
            clean = False
        children = open("/proc/self/task/self/children", "rb").read()
        return clean and children == self.child_baseline and _fds() == self.fd_baseline
def qualify(ops):
    outcomes = {name: "unobserved" for name in _CHECKS}
    try:
        ops.pdeath_case(False)
        ops.pdeath_case(True)
        ops.terminate_tree()
        outcomes.update(dict.fromkeys(_CHECKS[:-1], "pass"))
    except (OSError, RuntimeError, ChildProcessError, ValueError):
        pass
    restored = ops.restore()
    outcomes["cleanup_restored"] = "pass" if restored else "fail"
    passed = all(value == "pass" for value in outcomes.values())
    return {"checks": [{"id": name, "outcome": outcomes[name]} for name in _CHECKS], "cleanup": {"children": restored, "descriptors": restored}, "job": "D", "result": "pass" if passed else "fail"}
def main():
    if sys.argv != [sys.argv[0], "--native"] or sys.platform != "linux" or os.uname().machine != "x86_64":
        raise SystemExit(2)
    try:
        report = qualify(SystemOps())
    except BaseException:
        report = {"checks": [{"id": name, "outcome": "unobserved"} for name in _CHECKS], "cleanup": {"children": False, "descriptors": False}, "job": "D", "result": "fail"}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if report["result"] == "pass" else 1)
if __name__ == "__main__":
    main()

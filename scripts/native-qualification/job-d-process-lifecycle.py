#!/usr/bin/python3
"""Native Job D: qualify preregistered parent-death and tree supervision."""
import ctypes, hashlib, os, resource, select, signal, stat, struct, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
PR_SET_PDEATHSIG, PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER = 1, 36, 37
CHECKS = tuple("pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored".split())
def _require(condition, message):
    if not condition:
        raise RuntimeError(message)
def _prctl(option, argument=0):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, argument, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl failed")
def _subreaper():
    value = ctypes.c_int()
    _prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(value))
    return value.value
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
    _require(result.returncode == 0 and result.stderr == b"" and len(result.stdout) <= 1_048_576, "checkout baseline")
    return result.stdout
def _state():
    checkout = (_git("rev-parse", "HEAD^{commit}"), _git("status", "--porcelain=v2", "--untracked-files=all"),
                _git("config", "--local", "--list", "--show-origin", "--null"))
    return {
        "descriptors": _fds(), "children": (tuple((pid, _identity(pid)) for pid in _children()), os.getpgrp(), os.getsid(0), _subreaper()),
        "paths": not Path("/tmp/cogs-native-qualification-D.json").exists(),
        "mounts": _digest("/proc/self/mountinfo"),
        "namespaces": tuple(os.readlink(f"/proc/self/ns/{name}") for name in ("user", "pid", "mnt", "net")),
        "limits": resource.getrlimit(resource.RLIMIT_NOFILE), "checkout": checkout,
    }
def _identity(pid):
    with Path(f"/proc/{pid}/stat").open("rb", buffering=0) as stream:
        row = stream.read(4097)
    _require(len(row) <= 4096 and row.endswith(b"\n"), "process identity")
    fields = row[row.rfind(b")") + 2:].split()
    _require(len(fields) >= 20, "process identity fields")
    executable = os.stat(f"/proc/{pid}/exe")
    return (int(fields[19]), int(fields[1]), int(fields[2]), int(fields[3]), executable.st_dev, executable.st_ino)
def _pause():
    while True:
        signal.pause()
class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds
    def remaining(self):
        return max(0.0, self.end - time.monotonic())
class SystemOps:
    def __init__(self):
        self.before = _state()
        self.fds = []
        self.processes = {}
        self.close_certain = self.process_certain = True
        _prctl(PR_SET_CHILD_SUBREAPER, 1)
    def _pipe(self):
        pair = os.pipe2(os.O_CLOEXEC)
        self.fds.extend(pair)
        return pair
    def _close(self, descriptor):
        self.fds.remove(descriptor)
        try:
            os.close(descriptor)
        except OSError:
            self.close_certain = False
            raise
    def _write(self, descriptor, value):
        _require(os.write(descriptor, value) == len(value), "control short write")
    def _read(self, descriptor, size, deadline):
        value = bytearray()
        while len(value) < size:
            _require(bool(select.select([descriptor], [], [], deadline.remaining())[0]), "status deadline")
            block = os.read(descriptor, size - len(value))
            _require(bool(block), "status eof")
            value.extend(block)
        return bytes(value)
    def _register(self, pid, controls=(), pidfd=None):
        _require(pid not in self.processes, "duplicate process")
        self.processes[pid] = {"pidfd": None, "identity": None, "controls": list(controls)}
        if pidfd is None:
            pidfd = os.pidfd_open(pid, 0)
        self.fds.append(pidfd)
        self.processes[pid]["pidfd"] = pidfd
        identity = _identity(pid)
        expected = os.stat("/usr/bin/python3")
        _require(identity[4:] == (expected.st_dev, expected.st_ino), "executable identity")
        self.processes[pid]["identity"] = identity
        return identity
    def _exact(self, pid):
        process = self.processes[pid]
        return process["identity"] is not None and _identity(pid) == process["identity"]
    def _wait(self, pid, code, status, deadline):
        process = self.processes[pid]
        _require(self._exact(pid), "identity drift before wait")
        pidfd = process["pidfd"]
        _require(bool(select.select([pidfd], [], [], deadline.remaining())[0]), "process deadline")
        info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
        exact = info.si_code == code and info.si_status == status
        waited, wait_status = os.waitpid(pid, os.WNOHANG)
        _require(waited == pid, "exact reap")
        self._close(pidfd)
        del self.processes[pid]
        return exact and ((code == os.CLD_EXITED and wait_status == status) or
                          (code == os.CLD_KILLED and os.WIFSIGNALED(wait_status) and
                           os.WTERMSIG(wait_status) == status))
    def _abort_child(self, pidfd, pid):
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            if not select.select([pidfd], [], [], 1.0)[0] or os.waitpid(pid, os.WNOHANG)[0] != pid:
                os._exit(126)
        except BaseException:
            os._exit(126)
    def pdeath_case(self, after_release):
        start_r, start_w = self._pipe()
        child_r, child_w = self._pipe()
        parent_r, parent_w = self._pipe()
        release_r, release_w = self._pipe()
        status_r, status_w = self._pipe()
        parent = os.fork()
        if parent == 0:
            try:
                if os.read(start_r, 1) != b"P":
                    os._exit(120)
                os.setsid()
                child = os.fork()
                if child == 0:
                    try:
                        if os.read(child_r, 1) != b"P":
                            os._exit(121)
                        before = os.getppid()
                        _prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
                        _require(os.getppid() == before, "parent changed while arming")
                        os.write(status_w, b"A")
                        if after_release:
                            if os.read(release_r, 1) != b"R":
                                os._exit(122)
                            os.write(status_w, b"R")
                        _pause()
                    except BaseException:
                        os._exit(123)
                child_pidfd = os.pidfd_open(child, 0)
                os.write(status_w, struct.pack("!Q", child))
                command = os.read(parent_r, 1)
                if command != b"P":
                    self._abort_child(child_pidfd, child)
                os._exit(0)
            except BaseException:
                os._exit(124)
        parent_identity = self._register(parent, (start_w, parent_w))
        self._write(start_w, b"P")
        self._close(start_w)
        deadline = Deadline(5)
        child = struct.unpack("!Q", self._read(status_r, 8, deadline))[0]
        child_identity = self._register(child, (child_w, release_w))
        ownership = parent_identity[2:4] == (parent, parent) and child_identity[1:4] == (parent, parent, parent)
        self._write(child_w, b"P")
        self._close(child_w)
        armed = self._read(status_r, 1, deadline) == b"A"
        released = not after_release
        if after_release:
            self._write(release_w, b"R")
            self._close(release_w)
            released = self._read(status_r, 1, deadline) == b"R"
        self._write(parent_w, b"P")
        self._close(parent_w)
        parent_normal = self._wait(parent, os.CLD_EXITED, 0, deadline)
        adopted = child in _children()
        child_killed = self._wait(child, os.CLD_KILLED, signal.SIGKILL, deadline)
        return {"armed": armed, "released": released, "ownership": ownership, "parent_normal": parent_normal, "child_killed": child_killed, "revalidated": parent_normal and child_killed, "adopted": adopted}
    def terminate_tree(self):
        start_r, start_w = self._pipe()
        child_r, child_w = self._pipe()
        case_r, case_w = self._pipe()
        status_r, status_w = self._pipe()
        leader = os.fork()
        if leader == 0:
            try:
                if os.read(start_r, 1) != b"P":
                    os._exit(130)
                os.setsid()
                descendant = os.fork()
                if descendant == 0:
                    try:
                        if os.read(child_r, 1) != b"P":
                            os._exit(131)
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        os.write(status_w, b"D")
                        _pause()
                    except BaseException:
                        os._exit(132)
                descendant_pidfd = os.pidfd_open(descendant, 0)
                os.write(status_w, struct.pack("!Q", descendant))
                if os.read(case_r, 1) != b"P":
                    self._abort_child(descendant_pidfd, descendant)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                os.write(status_w, b"L")
                _pause()
            except BaseException:
                os._exit(133)
        leader_identity = self._register(leader, (start_w, case_w))
        self._write(start_w, b"P")
        self._close(start_w)
        deadline = Deadline(5)
        descendant = struct.unpack("!Q", self._read(status_r, 8, deadline))[0]
        descendant_identity = self._register(descendant, (child_w,))
        ownership = leader_identity[2:4] == (leader, leader) and descendant_identity[1:4] == (leader, leader, leader)
        self._write(child_w, b"P")
        self._close(child_w)
        self._write(case_w, b"P")
        self._close(case_w)
        ready = set(self._read(status_r, 2, deadline)) == {ord("D"), ord("L")}
        for pid in (descendant, leader):
            _require(self._exact(pid), "identity drift before TERM")
            signal.pidfd_send_signal(self.processes[pid]["pidfd"], signal.SIGTERM)
        term_deadline = Deadline(1)
        survived_term = not select.select([self.processes[leader]["pidfd"], self.processes[descendant]["pidfd"]],
                                          [], [], term_deadline.remaining())[0]
        for pid in (descendant, leader):
            _require(self._exact(pid), "identity drift before KILL")
            signal.pidfd_send_signal(self.processes[pid]["pidfd"], signal.SIGKILL)
        leader_killed = self._wait(leader, os.CLD_KILLED, signal.SIGKILL, deadline)
        adopted = descendant in _children()
        descendant_killed = self._wait(descendant, os.CLD_KILLED, signal.SIGKILL, deadline)
        return {"ownership": ownership, "ready": ready, "survived_term": survived_term, "adopted": adopted, "killed": leader_killed and descendant_killed, "revalidated": leader_killed and descendant_killed}
    def restore(self):
        deadline = Deadline(3)
        for process in self.processes.values():
            for descriptor in tuple(process["controls"]):
                if descriptor in self.fds:
                    try:
                        self._write(descriptor, b"A")
                    except BaseException:
                        self.process_certain = False
        for pid, process in tuple(self.processes.items()):
            try:
                if process["pidfd"] is not None and self._exact(pid):
                    graceful = process["controls"] and select.select(
                        [process["pidfd"]], [], [], min(1.1, deadline.remaining()))[0]
                    if not graceful:
                        signal.pidfd_send_signal(process["pidfd"], signal.SIGKILL)
            except BaseException:
                self.process_certain = False
        for pid, process in tuple(self.processes.items()):
            try:
                if process["pidfd"] is not None:
                    _require(select.select([process["pidfd"]], [], [], deadline.remaining())[0], "cleanup process deadline")
                    waited = os.waitpid(pid, os.WNOHANG)[0]
                else:
                    waited = 0
                    while waited != pid:
                        _require(deadline.remaining() > 0, "cleanup process deadline")
                        select.select([], [], [], min(0.01, deadline.remaining()))
                        waited = os.waitpid(pid, os.WNOHANG)[0]
                _require(waited == pid, "cleanup reap")
                if process["pidfd"] is not None:
                    self._close(process["pidfd"])
                del self.processes[pid]
            except BaseException:
                self.process_certain = False
        for descriptor in tuple(reversed(self.fds)):
            try:
                self._close(descriptor)
            except OSError:
                pass
        try:
            _prctl(PR_SET_CHILD_SUBREAPER, self.before["children"][3])
        except OSError:
            self.process_certain = False
        try:
            after = _state()
        except BaseException:
            return dict.fromkeys(("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout"), False)
        cleanup = {name: self.before[name] == after[name] for name in self.before}
        cleanup["descriptors"] &= self.close_certain
        cleanup["children"] &= self.process_certain and not self.processes
        return cleanup
def qualify(ops):
    observed = dict.fromkeys(CHECKS, False)
    try:
        before = ops.pdeath_case(False)
        observed["before_release_death"] = before["child_killed"] and before["parent_normal"]
        after = ops.pdeath_case(True)
        observed["after_release_death"] = after["child_killed"] and after["released"]
        observed["pdeathsig_armed"] = before["armed"] and after["armed"]
        observed["parent_handshake_exact"] = before["parent_normal"] and after["parent_normal"]
        observed["session_owned"] = before["ownership"] and after["ownership"]
        observed["process_group_owned"] = before["ownership"] and after["ownership"]
        tree = ops.terminate_tree()
        observed["starttime_revalidated"] = before["revalidated"] and after["revalidated"] and tree["revalidated"]
        observed["session_owned"] &= tree["ownership"]
        observed["process_group_owned"] &= tree["ownership"]
        observed["term_kill_bounded"] = tree["ready"] and tree["survived_term"] and tree["killed"]
        observed["all_reaped"] = before["adopted"] and after["adopted"] and tree["adopted"] and not ops.processes
    except (OSError, RuntimeError, ChildProcessError, ValueError, struct.error):
        pass
    cleanup = ops.restore()
    observed["cleanup_restored"] = all(cleanup.values())
    return {name: "pass" if observed[name] else "fail" for name in CHECKS}, cleanup
def _load_common():
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    common = __import__("common")
    del sys.path[0]
    return common
def _native():
    common = _load_common()
    context = common.WorkflowContext.from_environ("D", __file__)
    ops = None
    try:
        ops = SystemOps()
        checks, cleanup = qualify(ops)
    except BaseException:
        checks = dict.fromkeys(CHECKS, "fail")
        cleanup = ops.restore() if ops is not None else dict.fromkeys(common.CLEANUP_KEYS, False)
    passing = all(value == "pass" for value in checks.values()) and all(cleanup.values())
    common.finalize_report(context, "pass" if passing else "fail", checks, [], cleanup,
                           None if passing else "process-lifecycle", None if passing else b"process lifecycle qualification failed")
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

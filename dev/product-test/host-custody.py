#!/usr/bin/env python3
"""Root-only Linux custody process. stdin EOF/deadline settles receipts, never names.
Importing this file has no effects; portable tests exercise the descriptor primitives.
"""
import base64
from contextlib import contextmanager
import ctypes
import hashlib
import fcntl
import io
import tarfile
import json
import os
import re
import selectors
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

NONCE = re.compile(r"[0-9a-f]{32}\Z"); ID = re.compile(r"[0-9a-f]{64}\Z")
CAPABILITIES = dict(zip("CHOWN DAC_OVERRIDE FOWNER SETGID SETUID KILL NET_BIND_SERVICE SYS_CHROOT".split(), (0, 1, 3, 6, 7, 5, 10, 18)))
LIMITS = {"memory.max": "4294967296", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "200000 100000"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}


def require(ok):
    if not ok:
        raise RuntimeError("product custody unavailable")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def line(fd, maximum, deadline=float("inf")):
    data = bytearray(); end = min(deadline, time.monotonic() + 2)
    while not data.endswith(b"\n"):
        require(len(data) < maximum and time.monotonic() < end); require(select.select([fd], [], [], max(0, end - time.monotonic()))[0])
        chunk = os.read(fd, 1); require(chunk)
        data.extend(chunk)
    return bytes(data)


def directory(parent, name, mode=None):
    require(name not in ("", ".", "..") and "/" not in name)
    if mode is not None:
        os.mkdir(name, mode, dir_fd=parent); os.fsync(parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        require(stat.S_ISDIR(os.fstat(fd).st_mode))
        if mode is not None:
            os.fchmod(fd, mode); os.fsync(fd)
            require(stat.S_IMODE(os.fstat(fd).st_mode) == mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def closing_fd(fd):
    try:
        yield fd
    finally:
        os.close(fd)


def capture(parent, name, maximum=1048576):
    with closing_fd(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)) as fd:
        s = os.fstat(fd); require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= maximum)
        data = bytearray()
        while len(data) <= s.st_size:
            chunk = os.read(fd, min(32768, s.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) == s.st_size and identity(s) == identity(os.fstat(fd)))
        require(identity(s) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        return bytes(data)


def exclusive(parent, name, data, mode=0o400, uid=0):
    require("/" not in name and name not in ("", ".", ".."))
    with closing_fd(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)) as fd:
        os.fchown(fd, uid, uid); os.fchmod(fd, mode)
        remaining = memoryview(data)
        while remaining:
            remaining = remaining[os.write(fd, remaining):]
        os.fsync(fd)
    os.fsync(parent); require(capture(parent, name, max(len(data), 1)) == data)


def no_replace(parent, source, destination):
    libc = ctypes.CDLL(None, use_errno=True); rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    require(rename(parent, source.encode(), parent, destination.encode(), 1) == 0); os.fsync(parent)


def tree(parent, entries, verify=False):
    """Closed, bounded inventory; all traversal is relative to retained descriptors."""
    require(len(entries) <= 257); children = {}
    for path, entry in entries.items():
        parts = path.split("/"); require(len(parts) <= 16 and len(path.encode()) <= 256)
        require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) and p not in (".", "..") for p in parts))
        children.setdefault(parts[0], {})["/".join(parts[1:])] = entry
    if verify:
        require(set(os.listdir(parent)) == set(children))
    for name, descendants in sorted(children.items()):
        if "" in descendants:
            require(len(descendants) == 1); entry = descendants[""]
            require(set(entry) == {"data", "mode"} and entry["mode"] in (0o444, 0o555)); data = base64.b64decode(entry["data"], validate=True)
            require(len(data) <= 1048576 and not data.startswith(b"\xef\xbb\xbf"))
            if not verify:
                exclusive(parent, name, data, entry["mode"])
            s = os.stat(name, dir_fd=parent, follow_symlinks=False); require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == entry["mode"])
            require(capture(parent, name) == data)
        else:
            with closing_fd(directory(parent, name, None if verify else 0o700)) as fd:
                tree(fd, descendants, verify)
                if not verify:
                    os.fchmod(fd, 0o555); os.fsync(fd)
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
    os.fsync(parent)


def publish_pair(parent, generation, pair):
    require(NONCE.fullmatch(generation) and set(pair) == {"shared", "user"}); stage = directory(parent, ".stage-" + generation, 0o700)
    try:
        for scope in ("shared", "user"):
            with closing_fd(directory(stage, scope, 0o700)) as fd:
                tree(fd, pair[scope]); os.fchmod(fd, 0o555)
                tree(fd, pair[scope], True)
        os.fchmod(stage, 0o555); os.fsync(stage)
        no_replace(parent, ".stage-" + generation, generation); require(os.fstat(stage).st_ino == os.stat(generation, dir_fd=parent).st_ino)
        result = {}
        for scope in ("shared", "user"):
            with closing_fd(directory(stage, scope)) as fd:
                tree(fd, pair[scope], True); names = os.listdir(fd)
                require(len(names) == 1 and ID.fullmatch(names[0]))
                with closing_fd(directory(fd, names[0])) as child:
                    s = os.fstat(child)
                result[scope] = {"source_device": str(s.st_dev), "source_inode": str(s.st_ino)}
        return result
    finally:
        os.close(stage)


def environment(config, role=None):
    # Closed values, not a blacklist: image startup hooks and ambient credentials are never inherited.
    allowed = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
               "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt", "NODE_ENV": "production",
               "HOME": "/tmp", "TMPDIR": "/tmp", "XDG_CACHE_HOME": "/tmp/.cache"}
    if role == "worker":
        allowed["NODE_EXTRA_CA_CERTS"] = "/run/cogs/pki/telemetry-ca.crt"
    if role == "sandbox":
        allowed["COGS_PROXY_ENDPOINT"] = "http://127.0.0.1:18080"
    values = config.get("Env") or []; require(isinstance(values, list) and len(values) == len(set(v.split("=", 1)[0] for v in values)))
    for value in values:
        key, sep, text = value.partition("="); require(sep and key in allowed and text == allowed[key])
    return sorted(values)


def inventory(fd, prefix="", result=None, markers=None):
    result = {} if result is None else result
    for name in sorted(os.listdir(fd)):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in (".", "..")); path = prefix + name
        require(len(result) < 512 and path.count("/") < 16); s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(not s.st_mode & 0o7022)
        if markers is not None:
            markers[path] = list(identity(s))
        if stat.S_ISDIR(s.st_mode):
            with closing_fd(directory(fd, name)) as child:
                result[path + "/"] = None; inventory(child, path + "/", result, markers)
        else:
            result[path] = capture(fd, name, 2 * 1048576); require(sum(len(b) for b in result.values() if b is not None) <= 16 * 1048576)
        require(identity(s) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)))
    return result


def unique_object(pairs):
    value = dict(pairs); require(len(value) == len(pairs) and "__proto__" not in value)
    return value


def source_nodes(value, depth=0):
    require(depth <= 16)
    if isinstance(value, dict):
        require("__proto__" not in value)
    return 1 + sum(source_nodes(v, depth + 1) for v in (value.values() if isinstance(value, dict) else value if isinstance(value, list) else []))


def tool_result(entry):
    message = entry.get("message", {})
    if message.get("role") != "toolResult":
        return None
    require(message.get("isError") is False and message.get("toolCallId") == "product-proxy" and message.get("toolName") == "bash")
    require(message.get("details") == {"cogsTool": "bash"}); content = message.get("content")
    require(isinstance(content, list) and len(content) == 1 and set(content[0]) == {"type", "text"}); block = content[0]
    require(block["type"] == "text" and isinstance(block["text"], str) and len(block["text"].encode()) <= 16384)
    result = json.loads(block["text"], object_pairs_hook=unique_object)
    flags = "timedOut idleTimedOut cancelled stdoutTruncated stderrTruncated stdoutLossyUtf8 stderrLossyUtf8".split()
    zeros = "stdoutDroppedBytes stderrDroppedBytes stdoutResultOmittedUtf8Bytes stderrResultOmittedUtf8Bytes updateDropped".split()
    require(set(result) == set(flags + zeros + "ok exitCode signal elapsedMs stdout stderr stdoutBytes stderrBytes".split()))
    require(result["ok"] is True and type(result["exitCode"]) is int and result["exitCode"] == 0 and result["signal"] is None)
    require(all(result[k] is False for k in flags) and all(type(result[k]) is int and result[k] == 0 for k in zeros))
    require(type(result["elapsedMs"]) is int and 0 <= result["elapsedMs"] <= 10000)
    for key in ("stdout", "stderr"):
        require(isinstance(result[key], str) and len(result[key].encode()) <= 4096)
        require(type(result[key + "Bytes"]) is int and result[key + "Bytes"] == len(result[key].encode()))
    return digest(canonical(message))


class Custody:
    def __init__(self, config):
        require(sys.platform == "linux" and os.geteuid() == 0 and os.uname().machine == "x86_64"); self.generation = config["generation"]
        require({"generation", "seconds"} <= set(config) <= {"generation", "seconds", "cleanup_only", "purpose"})
        require(config.get("purpose", "run") in ("run", "capability-probe")); self.probe = config.get("purpose") == "capability-probe"
        require(type(config["seconds"]) is int and 60 <= config["seconds"] <= 600); require("cleanup_only" not in config or config["cleanup_only"] is True)
        require(NONCE.fullmatch(self.generation)); self.deadline = time.monotonic() + config["seconds"]
        self.ids, self.peers, self.mounts, self.images, self.sealed = {}, {}, [], {}, []; self.fd = self.control = self.lock = self.disk = None
        self.publication, self.history, self.shutdown = None, None, False; self.admissions, self.nodes, self.publications, self.records = [], 0, [], set()
        self.selector = selectors.DefaultSelector(); self.recovery = config.get("cleanup_only") is True
        self.failed, self.released = False, False; self.used, self.events, self.turns, self.headers = set(), 0, 0, False
        self.root = "/var/lib/cogs-product-test/" + self.generation
        parent = os.open("/var/lib/cogs-product-test", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); s = os.fstat(parent)
        require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700); self.cg = "/sys/fs/cgroup/cogs-product-" + self.generation
        try:
            self.lock = os.open(self.generation + ".lock", os.O_RDWR | os.O_NOFOLLOW |
                                (0 if self.recovery else os.O_CREAT | os.O_EXCL), 0o600, dir_fd=parent)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB); s = os.fstat(self.lock)
            require(s.st_uid == 0 and s.st_nlink == 1 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600)
            if self.recovery:
                require(json.loads(os.pread(self.lock, 32768, 0).splitlines()[0])["generation"] == self.generation)
            else:
                data = canonical(config); require(os.write(self.lock, data) == len(data))
                os.fsync(self.lock)  # durable constructor intent precedes mkdir of the generation
            os.fsync(parent); self.fd = directory(parent, self.generation, None if self.recovery else 0o700)
            self.control = directory(self.fd, "control", None if self.recovery else 0o700)
            require(all(os.fstat(fd).st_uid == 0 and stat.S_IMODE(os.fstat(fd).st_mode) == 0o700 for fd in (self.fd, self.control)))
            if self.recovery:
                self.reopen()
                return
            self.record("intent", config); self.record("root", identity(os.fstat(self.fd))[:2])
            self.record("cgroup-intent", {"path": self.cg}); os.mkdir(self.cg)
            self.record("cgroup", identity(os.stat(self.cg))[:2])
            for key, value in LIMITS.items():
                self.cwrite(self.cg, key, value)
            self.cwrite(self.cg, "cgroup.subtree_control", "+memory +pids +cpu"); os.mkdir(self.cg + "/helpers")
            require(self.docker("ps", "-aq", "--no-trunc") == b""); info = json.loads(self.docker("info", "--format", "{{json .}}"))
            require(info["CgroupVersion"] == "2" and info["CgroupDriver"] == "cgroupfs"); require(info["Driver"] == "overlay2" and info["OSType"] == "linux")
            self.disk = os.statvfs("/var/lib/docker").f_bfree * os.statvfs("/var/lib/docker").f_frsize; self.record("disk", self.disk)
            self.selector.register(sys.stdin.buffer, selectors.EVENT_READ, "supervisor")
        except BaseException:
            if not self.recovery:
                self.rollback()
            raise
        finally:
            os.close(parent)

    def record(self, name, value):
        data = canonical(value)
        if name in os.listdir(self.control):
            require(capture(self.control, name) == data)
        else:
            exclusive(self.control, name, data)
        self.records.add(name)

    def saved(self, name):
        s = os.stat(name, dir_fd=self.control, follow_symlinks=False); require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o400)
        raw = capture(self.control, name); value = json.loads(raw)
        require(canonical(value) == raw)
        return value

    def rollback(self):
        self.failed = True; self.deadline = time.monotonic() + 30
        if self.control is not None:
            self.record("cleanup-required", {"generation": self.generation}); self.settle()
        elif self.lock is not None:
            data = canonical({"generation": self.generation, "cleanup_required": True}); os.lseek(self.lock, 0, os.SEEK_END)
            require(os.write(self.lock, data) == len(data))
            os.fsync(self.lock)  # no inode authority yet: preserve uncertainty, never adopt a root by name

    def reopen(self):
        require(self.saved("intent")["generation"] == self.generation and "retired" not in os.listdir(self.control))
        require(self.saved("root") == list(identity(os.fstat(self.fd))[:2]))
        if os.path.exists(self.cg):
            require(self.saved("cgroup") == list(identity(os.stat(self.cg))[:2]))
        else:
            require("cgroup-retire-intent" in os.listdir(self.control))
        if "cgroup-retire-intent" in os.listdir(self.control):
            self.rollback()
            return
        self.disk = self.saved("disk") if "disk" in os.listdir(self.control) and os.path.exists(self.cg) else None
        for name in ("publication", "workspace", "state"):
            if name + "-storage" in os.listdir(self.control):
                self.mounts.append(name)
        for role in ("trust", "sandbox", "worker"):
            if role + "-intent" in os.listdir(self.control) and role + "-retired" not in os.listdir(self.control):
                # A lost create response cannot authorize a name/label-based deletion.
                self.ids[role] = self.saved(role + "-receipt"); image = self.ids[role]["spec"]["image"]
                self.images[image] = self.saved("image-" + image[7:])
        for name in os.listdir(self.control):
            if name.startswith("seal-"):
                seal = self.saved(name); fd = os.open(self.root + "/" + seal["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                require(list(identity(os.fstat(fd))[:2]) == seal["identity"]); self.sealed.append((fd, seal["files"]))
        self.rollback()  # cleanup only, never re-enters admission or publishes a pass

    def cwrite(self, path, name, value):
        with open(path + "/" + name, "w", encoding="ascii") as file:
            file.write(value)

    def command(self, argv, cap=1048576, status=False, pass_fds=()):
        bootstrap = "import os,signal,sys;os.kill(os.getpid(),signal.SIGSTOP);os.execvpe(sys.argv[1],sys.argv[1:],dict(os.environ))"
        p = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, *argv], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True, pass_fds=pass_fds)
        pidfd = None  # ownership is armed at Popen return, including pidfd/stop-handshake failure
        out, err = bytearray(), bytearray(); end = min(self.deadline, time.monotonic() + 15)
        try:
            pidfd = os.pidfd_open(p.pid)
            while True:
                require(time.monotonic() < end); child = os.waitid(os.P_PIDFD, pidfd, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if child:
                    require(child.si_code == os.CLD_STOPPED)
                    break
                time.sleep(0.01)
            self.cwrite(self.cg + "/helpers", "cgroup.procs", str(p.pid)); os.kill(p.pid, signal.SIGCONT)
            with selectors.DefaultSelector() as poll:
                for stream, target in ((p.stdout, out), (p.stderr, err)):
                    os.set_blocking(stream.fileno(), False); poll.register(stream, selectors.EVENT_READ, target)
                while poll.get_map():
                    require(time.monotonic() < end)
                    for key, _ in poll.select(0.05):
                        chunk = os.read(key.fd, 32768); key.data.extend(chunk)
                        require(len(out) <= cap and len(err) <= 4096)
                        if not chunk:
                            poll.unregister(key.fileobj)
                while True:
                    require(time.monotonic() < end); child = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if child:
                        break
                    time.sleep(0.01)
                require(child.si_code == os.CLD_EXITED and (status or child.si_status == 0))
            return (child.si_status, bytes(out)) if status else bytes(out)
        finally:
            try:
                # WNOWAIT retains the leader's numeric PID/PGID until BOTH final signals, even on early exit.
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if os.path.exists(self.cg + "/helpers/cgroup.kill"):
                    self.cwrite(self.cg + "/helpers", "cgroup.kill", "1")
                p.wait(timeout=2); until = time.monotonic() + 2
                while os.path.exists(self.cg + "/helpers/cgroup.events"):
                    if "populated 0" in open(self.cg + "/helpers/cgroup.events", encoding="ascii").read():
                        break
                    require(time.monotonic() < until); time.sleep(0.01)
            finally:
                if pidfd is not None:
                    os.close(pidfd)
                p.stdout.close(); p.stderr.close()

    def docker(self, *args, **options):
        return self.command(["docker", "--host=unix:///var/run/docker.sock", *args], 8 * 1048576, **options)

    def inspect(self, cid):
        require(ID.fullmatch(cid)); values = json.loads(self.docker("inspect", cid))
        require(len(values) == 1 and values[0]["Id"] == cid)
        return values[0]

    def authenticate(self, role):
        held = self.ids[role]; v = self.inspect(held["id"])
        p, spec = v["State"]["Pid"], held["spec"]; require(v["State"]["Running"] and v["Image"] == spec["image"])
        require(v["Config"]["Labels"] == {**(self.images[spec["image"]]["Config"]["Labels"] or {}), "cogs.product.generation": self.generation})
        require(environment(v["Config"], role) == held["environment"]); h = v["HostConfig"]
        require(h["ReadonlyRootfs"] and not h["Privileged"] and h["PidMode"] == ""); require(h["LogConfig"]["Type"] == "none" and h["CapDrop"] == ["ALL"])
        require(sorted(h["CapAdd"] or []) == sorted(spec["caps"])); require(h["SecurityOpt"] == ["no-new-privileges"] and h["CgroupParent"] == self.cg[14:])
        require(h["Memory"] == 4294967296 and h["MemorySwap"] == 4294967296 and (h["MemorySwappiness"] is None or type(h["MemorySwappiness"]) is int and h["MemorySwappiness"] == 0))
        require(h["PidsLimit"] == 128 and h["NanoCpus"] == 2000000000 and not h["PortBindings"]); require(h["ShmSize"] == 16777216)
        require(h["NetworkMode"] == spec["network"] and not h["Devices"] and not h["Binds"]); require(len(v["Mounts"]) == len(spec["mounts"]))
        for m in v["Mounts"]:
            expected = next(x for x in spec["mounts"] if x["target"] == m["Destination"])
            require(m["Type"] == "bind" and m["Source"] == expected["source"] and m["RW"] == (not expected["ro"])); require(m["Propagation"] == "rprivate")
            a, b = os.stat(m["Source"]), os.stat(f"/proc/{p}/root" + m["Destination"])
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) == tuple(held["sources"][m["Destination"]]))
        require((h["Tmpfs"] or {}) == spec["tmpfs"])
        with open(f"/proc/{p}/mountinfo", encoding="ascii") as f:
            mounts = [row.split() for row in f]
        for expected in spec["mounts"]:
            live = [m for m in mounts if m[4] == expected["target"]]; require(len(live) == 1 and ("ro" in live[0][5].split(",")) == expected["ro"])
            require(not any(x.startswith(("shared:", "master:")) for x in live[0][6:]))
        with open(f"/proc/{p}/cgroup", encoding="ascii") as f:
            cg = f.read().strip().removeprefix("0::")
        require(cg == self.cg[14:] + "/" + held["id"])
        for name, value in LIMITS.items():
            with open("/sys/fs/cgroup" + cg + "/" + name, encoding="ascii") as f:
                actual = f.read().strip()
            require(actual == value or (name == "cpu.max" and actual == "200000 100000"))
        with open(f"/proc/{p}/status", encoding="ascii") as f:
            status = dict(line.split(":", 1) for line in f if ":" in line)
        require(all(int(status[k].strip(), 16) == spec["mask"] for k in ("CapEff", "CapPrm", "CapBnd"))); require(status["NoNewPrivs"].strip() == "1")
        require(status["Seccomp"].strip() == "2"); namespace = os.readlink(f"/proc/{p}/ns/mnt")
        if role == "worker":
            require(os.readlink(f"/proc/{p}/ns/net") == os.readlink(f"/proc/{self.ids['sandbox']['pid']}/ns/net"))
        if "pid" in held:
            require(held["pid"] == p and held["namespace"] == namespace)
        else:
            held["pidfd"] = os.pidfd_open(p)
        require(not select.select([held["pidfd"]], [], [], 0)[0]); held.update(pid=p, namespace=namespace)
        return held

    def bind_receipt(self):
        require(not self.probe); worker, sandbox = self.authenticate("worker"), self.authenticate("sandbox")
        r = self.receipt
        require(set(r) == set("version generation consumer_id session_id launch_digest worker_id sandbox_id sandbox_mount_namespace shared user".split()))
        require(r["version"] == "cogs.skill-snapshot-receipt/v1" and r["generation"] == self.generation and NONCE.fullmatch(r["consumer_id"]))
        require((r["worker_id"], r["sandbox_id"], r["sandbox_mount_namespace"]) == (worker["id"], sandbox["id"], sandbox["namespace"]))
        with closing_fd(directory(self.fd, "documents")) as fd:
            launch = json.loads(capture(fd, "launch.json"))
            require(r["launch_digest"] == digest(canonical(launch)) and r["session_id"] == launch["session_id"]); self.launch = launch
        require(self.publication == self.saved("publication-receipt"))
        for scope in ("shared", "user"):
            entries = self.publication["pair"][scope]; bundle = next(iter(entries)).split("/")[0]
            expected = {**self.publication["sources"][scope], "destination": f"/{scope}/skills/{bundle}",
                        "read_only": True, "bundle_digest": "sha256:" + bundle}
            require(r[scope] == expected and type(r[scope]["read_only"]) is bool); source = f"{self.root}/publication/{self.generation}/{scope}/{bundle}"
            s = os.stat(source, follow_symlinks=False); require((str(s.st_dev), str(s.st_ino)) == (expected["source_device"], expected["source_inode"]))
            require({"source": source, "target": expected["destination"], "ro": True} in sandbox["spec"]["mounts"])
            with closing_fd(os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)) as fd:
                tree(fd, {p.split("/", 1)[1]: v for p, v in entries.items()}, True)
                require(digest(capture(fd, ".cogs-skills-bundle.json")) == expected["bundle_digest"])

    def storage_observation(self, name):
        path = self.root + "/control/" + name + ".img"; backing = self.saved(name + "-backing")
        require(backing == list(identity(os.stat(path, follow_symlinks=False))[:2]))
        loops = json.loads(self.command(["losetup", "--json", "--list", "--output", "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN"]))["loopdevices"]
        loops = [v for v in loops if v["back-file"] == path]; require(len(loops) <= 1)
        loop = loops[0] if loops else None
        if loop:
            require(int(loop["back-ino"]) == backing[1] and loop["back-maj:min"] == f"{os.major(backing[0])}:{os.minor(backing[0])}")
        with open("/proc/self/mountinfo", encoding="ascii") as f:
            mounts = [r.split() for r in f if r.split()[4] == self.root + "/" + name]
        require(len(mounts) <= 1); mount = mounts[0] if mounts else None
        if mount:
            require(loop and mount[mount.index("-") + 2] == loop["name"])
        return loop, mount

    def provenance(self, q):
        root = os.path.realpath(os.path.join(os.path.dirname(__file__), "../..")); git = lambda *a: self.command(["git", "-C", root, *a])
        require(git("rev-parse", "HEAD").decode().strip() == q["candidate"]); require(not git("status", "--porcelain=v1", "--untracked-files=all"))
        require(not git("diff", q["baseline"], "--", "images/sandbox", "images/worker", "package-lock.json")); source = {}
        paths = ("src", "schemas", "dev/product-test", "dev/launcher/api-client.ts", "third_party")
        for raw in git("ls-tree", "-rz", "HEAD", "--", *paths).split(b"\0"):
            if not raw:
                continue
            meta, path = raw.decode().split("\t"); mode, kind, oid = meta.split()
            require(kind == "blob" and mode in ("100644", "100755")); data = git("cat-file", "blob", oid)
            with closing_fd(os.open(os.path.dirname(root + "/" + path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)) as fd:
                require(capture(fd, os.path.basename(path)) == data)
                require(stat.S_IMODE(os.stat(os.path.basename(path), dir_fd=fd, follow_symlinks=False).st_mode) == int(mode, 8) & 0o777)
            source[path] = {"digest": digest(data), "mode": int(mode, 8) & 0o777}
        with closing_fd(os.open("/var/lib/cogs-product-test", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)) as fd:
            s = os.stat("build-receipt.json", dir_fd=fd, follow_symlinks=False); require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o400)
            receipt = json.loads(capture(fd, "build-receipt.json"))
        expected = {k: q[k] for k in ("candidate", "baseline", "worker_image", "sandbox_image", "stock_worker_image", "recipe")}
        expected.update(tree=git("rev-parse", "HEAD^{tree}").decode().strip(), source=digest(canonical(source)))
        require(receipt == expected)  # independently retained protected-build output, not a CLI identity assertion
        stock = self.images[q["stock_worker_image"]]["RootFS"]["Layers"]; layers = self.images[q["worker_image"]]["RootFS"]["Layers"]
        require(layers[:len(stock)] == stock and len(layers) == len(stock) + 5)
        require(environment(self.images[q["worker_image"]]["Config"]) == environment(self.images[q["stock_worker_image"]]["Config"]))
        self.record("provenance", receipt); self.source = source
        return receipt

    def verify_candidate(self, cid):
        # Stopped-container copy: no image entrypoint, Node hook or candidate code is executed.
        for path in ("src", "schemas", "dev/product-test", "dev/launcher/api-client.ts", "third_party"):
            data = self.docker("cp", cid + ":/opt/cogs/" + path, "-"); observed = {}
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                for entry in archive:
                    require(entry.isdir() or entry.isfile()); require(not entry.name.startswith("/") and ".." not in entry.name.split("/"))
                    if entry.isfile():
                        name = path.rsplit("/", 1)[0] + "/" + entry.name if "/" in path else entry.name
                        require(name not in observed and entry.size <= 1048576 and entry.uid == entry.gid == 0)
                        observed[name] = {"digest": digest(archive.extractfile(entry).read()), "mode": entry.mode}
            require(observed == {p: h for p, h in self.source.items() if p == path or p.startswith(path + "/")})

    def retained_history(self):
        with closing_fd(os.open(self.root + "/state/session/sessions", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)) as fd:
            files = inventory(fd)
        native = [p for p in files if p.count("/") == 1 and p.endswith(".jsonl") and not p.endswith("git-map.jsonl")]
        require(len(native) == 1 and native[0].startswith("product-session/")); data = files[native[0]]
        require(data.endswith(b"\n")); entries = [json.loads(row, object_pairs_hook=unique_object) for row in data.splitlines()]
        require([digest(canonical(e)) for e in entries] == self.admissions); nodes = sum(source_nodes(e) for e in entries)
        require(0 < len(entries) <= 25 and nodes == self.nodes and nodes <= 2048)
        self.history = {"entries": len(entries), "nodes": nodes, "digest": digest(data)}
        return files, native[0], entries

    def evidence(self):
        files, native, entries = self.retained_history()
        require(set(os.listdir(self.fd)) == {"control", "publication", "workspace", "state", "inputs", "authority", "sandbox-input", "documents", "lease"})
        with closing_fd(directory(self.fd, "publication")) as fd:
            tree(fd, {self.generation + "/" + scope + "/" + p: v for scope, entries in self.publication["pair"].items() for p, v in entries.items()}, True)
        require(self.shutdown and self.released and not self.peers and self.turns == 3 and self.headers); state_marks, work_marks = {}, {}
        with closing_fd(directory(self.fd, "state")) as state, closing_fd(directory(self.fd, "workspace")) as workspace:
            retained, work = inventory(state, markers=state_marks), inventory(workspace, markers=work_marks)
        e = json.loads(retained["session/product-evidence.json"]); require(canonical(e) == retained["session/product-evidence.json"])
        require(set(e) == set("outcome toolResults provenance egress telemetry exports upstreamRequests exported observedEvents generation upstream traces metrics audit omitted events turns consumer".split()))
        tools = [result for entry in entries if (result := tool_result(entry)) is not None]; require(len(tools) == 1 and e["toolResults"] == tools)
        require(e["outcome"] == "pass" and e["generation"] == self.generation and e["consumer"] == self.receipt["consumer_id"])
        require(e["events"] == self.events and e["turns"] == self.turns and e["omitted"] is True); require(e["observedEvents"] == self.publications)
        require([v["kind"] for v in self.publications].count("run_settled") == 3 and [v["kind"] for v in self.publications].count("shutdown_ready") == 1)
        require(e["provenance"] == self.saved("provenance")); wal = retained["session/egress-audit.wal"]
        require(wal.endswith(b"\n")); records = [json.loads(r, object_pairs_hook=unique_object) for r in wal.splitlines()]
        require(len(records) == e["audit"] == e["upstream"] == 1 and e["egress"]["records"] == records); r = records[0]
        require(set(r) == set("version sequence intent_id timestamp_ms session_id integration_id route_id method credential_required".split()))
        require(r["version"] == "cogs.egress-intent/v1alpha1" and type(r["sequence"]) is int and r["sequence"] == 0 and r["session_id"] == "product-session")
        require(type(r["timestamp_ms"]) is int and r["timestamp_ms"] > 0 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", r["intent_id"]))
        require(r["integration_id"] == "synthetic-local" and r["method"] == "GET" and r["credential_required"] is True)
        require(e["upstreamRequests"] == [{"method": "GET", "path": "/credential", "credential": True}]); completed = e["egress"]["completions"]
        require(len(completed) == 1 and e["egress"]["retired"] and not e["egress"]["uncorrelated"]); c = completed[0]
        require((c["intentId"], c["sequence"], c["routeId"], c["responseCode"]) == (r["intent_id"], 0, r["route_id"], 200))
        require(c["completedAtMs"] >= r["timestamp_ms"] and c["durationMs"] >= 0); accounting = e["egress"]["accounting"]
        require(set(accounting) == {"accepted", "drained", "dropped", "retained", "failed"})
        require(accounting["accepted"] == accounting["drained"] + accounting["retained"] == 1 and not accounting["failed"] and accounting["dropped"] == 0)
        telemetry_count, log_count, paths = 0, 0, []
        for export in e["exports"]:
            path, body = export["path"], export["body"]; paths.append(path)
            require(path in ("/v1/traces", "/v1/metrics", "/v1/logs")); kind = {"/v1/traces": "Spans", "/v1/metrics": "Metrics", "/v1/logs": "Logs"}[path]
            require(set(body) == {"resource" + kind} and len(body["resource" + kind]) == 1); resource = body["resource" + kind][0]
            scopes = resource["scope" + kind]; require(len(scopes) == 1)
            if kind == "Logs":
                require(resource["resource"]["attributes"] == [{"key": "service.name", "value": {"stringValue": "cogs-egress"}}])
                require(scopes[0]["scope"] == {"name": "cogs.egress.telemetry", "version": "v1alpha1"})
                for log in scopes[0]["logRecords"]:
                    log_count += 1; require(log["body"] == {"stringValue": "cogs.egress.complete"} and log["severityText"] == "INFO")
                    attrs = {a["key"]: next(iter(a["value"].values())) for a in log["attributes"]}; require(len(attrs) == len(log["attributes"]) == 11)
                    expected = {"cogs." + k: r[k] for k in ("intent_id", "session_id", "integration_id", "route_id", "method", "credential_required")}
                    expected.update({"cogs.event": "egress.complete", "cogs.intent_sequence": "0", "cogs.status_class": "2",
                                     "cogs.duration_ms": str(c["durationMs"]), "cogs.completed_lag_ms": str(c["completedAtMs"] - r["timestamp_ms"])})
                    require(attrs == expected and int(log["timeUnixNano"]) == c["completedAtMs"] * 1000000)
                    numeric = {"cogs.intent_sequence", "cogs.status_class", "cogs.duration_ms", "cogs.completed_lag_ms"}
                    require(all(a["value"] == {"intValue" if a["key"] in numeric else "boolValue" if a["key"] == "cogs.credential_required" else "stringValue": expected[a["key"]]} for a in log["attributes"]))
            else:
                require(resource["resource"]["attributes"] == [{"key": "service.name", "value": {"stringValue": "cogs-worker"}}])
                require(scopes[0]["scope"] == {"name": "cogs.worker.telemetry", "version": "v1alpha1"})
                items = scopes[0]["spans" if kind == "Spans" else "metrics"]; require(items)
                for item in items:
                    require(isinstance(item["name"], str) and item["name"])
                    if kind == "Spans":
                        require(set(item) == {"traceId", "spanId", "name", "kind", "startTimeUnixNano", "endTimeUnixNano", "attributes"})
                        require(item["kind"] == 1 and 0 <= int(item["startTimeUnixNano"]) <= int(item["endTimeUnixNano"]))
                        require(re.fullmatch(r"[0-9a-f]{32}", item["traceId"]) and re.fullmatch(r"[0-9a-f]{16}", item["spanId"])); telemetry_count += 1
                    else:
                        points = item.get("sum", item.get("gauge", {}))["dataPoints"]; require(points and all(int(p["asInt"]) >= 0 for p in points))
                        telemetry_count += len(points)
        require(log_count == 1 and paths.count("/v1/traces") == e["traces"] > 0 and paths.count("/v1/metrics") == e["metrics"] > 0); t = e["telemetry"]
        require(set(t) == {"ready", "queued", "exported", "dropped", "failed", "lag_ms"} and t["ready"] is False)
        require(t["exported"] == telemetry_count and t["queued"] == t["failed"] == t["dropped"] == 0)
        require(files["product-session/git-map.jsonl"].endswith(b"\n"))
        maps = [json.loads(row, object_pairs_hook=unique_object) for row in files["product-session/git-map.jsonl"].splitlines()]
        require(maps and all(m["entry"] in {v["id"] for v in entries} and m["session"] == "product-session" and m["repo"] == "product-workspace" and m["confidence"] == "exact" for m in maps))
        require(all(set(m) == set("version repo commit session entry turn observed_at confidence".split()) and m["version"] == "cogs.git-mapping/v1alpha1" for m in maps))
        require(work.pop("proof.txt") == b"alpha\n")
        require(work[".git/config"] == b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[user]\n\temail = synthetic@example.invalid\n\tname = Synthetic\n")
        require(all(p == ".git/" or re.fullmatch(r"\.git/(HEAD|config|index|COMMIT_EDITMSG|objects/([0-9a-f]{2}/([0-9a-f]{38})?|info/|pack/)?|refs/(heads/|notes/)?(master|cogs)?|logs/(HEAD|refs/(heads/|notes/)?(master|cogs)?)?)/?", p) for p in work))
        git = lambda *a: self.command(["git", "-c", "safe.directory=" + self.root + "/workspace", "-C", self.root + "/workspace", *a])
        require(not git("fsck", "--full", "--no-reflogs", "--unreachable")); commit = git("rev-parse", "HEAD").decode().strip()
        require(all(m["commit"] == commit and "checkpoint_ref" not in m for m in maps)); require(git("show", "HEAD:proof.txt") == b"alpha\n")
        notes = git("notes", "--ref=refs/notes/cogs", "show", commit).decode().splitlines()
        require({n for n in notes if n} == {f"cogs git mapping: trusted record of untrusted Git observation; session={m['session']}; entry={m['entry']}; turn={m['turn']}; commit={m['commit']}; observed_at={m['observed_at']}; confidence=exact" for m in maps})
        require(not git("status", "--porcelain=v1", "--untracked-files=all")); bundle = self.receipt["user"]["bundle_digest"][7:]
        stores = {scope + "/" + hashlib.sha256(b"synthetic").hexdigest() + "/blobs/sha256/" + bundle for scope in ("host-private", "private-store")}
        allowed = {"session/product-evidence.json", "session/egress-audit.wal", "session/sessions/" + native, "session/sessions/product-session/git-map.jsonl"} | stores
        descriptor = e["exported"]["bundle"]; require(e["exported"]["sensitive"] is True and descriptor["mode"] == "raw" and descriptor["file_count"] == 6)
        require(descriptor["bundle"] == "cogs-session-product-session"); export_root = "session/sessions/product-session/exports/" + descriptor["bundle"] + "/"
        export_names = {"manifest.json", "session.jsonl", "git-map.json", "skills.json", "warnings.json", "transform-report.json"}
        manifest = json.loads(retained[export_root + "manifest.json"])
        require(manifest["version"] == "cogs.export/v1alpha2" and manifest["session_id"] == "product-session")
        require(digest(retained[export_root + "manifest.json"])[7:] == descriptor["manifest_sha256"])
        require({v["path"] for v in manifest["files"]} == export_names - {"manifest.json"} and len(manifest["files"]) == 5)
        for file in manifest["files"]:
            data = retained[export_root + file["path"]]; require(len(data) == file["bytes"] and digest(data)[7:] == file["sha256"])
        require(retained[export_root + "session.jsonl"] == files[native]); exported_maps = json.loads(retained[export_root + "git-map.json"])["records"]
        require(exported_maps and maps[:len(exported_maps)] == exported_maps); require(json.loads(retained[export_root + "warnings.json"])["warnings"] == [])
        report = json.loads(retained[export_root + "transform-report.json"])
        require(report["transform"] == "identity" and report["transformations"] == 0 and report["sanitized"] is False)
        skills = json.loads(retained[export_root + "skills.json"])
        require({k: skills[k] for k in ("shared_revision", "user_revision")} == manifest["skills"] == {k: self.launch["skills"][k] for k in ("shared_revision", "user_revision")})
        allowed |= {export_root + name for name in export_names}
        require(sum(len(retained[export_root + n]) for n in export_names) == descriptor["total_bytes"])
        for p in stores:
            require(digest(retained[p]) == "sha256:" + bundle)
        require({p for p, b in retained.items() if b is not None} == allowed)
        directories = {p[:i + 1] for p in allowed for i, ch in enumerate(p) if ch == "/"} | {"session/agent/"}
        require({p for p, b in retained.items() if b is None} == directories)
        self.record("evidence-validated", {"evidence": digest(canonical(e)), "history": self.history,
                                         "state_identities": state_marks, "workspace_identities": work_marks,
                                         "inventory": {p: digest(b) if b is not None else None for p, b in retained.items()}})
        return canonical(e).decode()

    def capability_probe(self):
        held = self.ids["sandbox"]; v = self.inspect(held["id"])
        result = dict(purpose="capability-probe", generation=self.generation, container_id=held["id"],
                      removed=next(c for c in CAPABILITIES if c not in held["spec"]["caps"]),
                      start_code=held["start_code"], running=v["State"]["Running"], ssh=None, sftp=None)
        if result["running"]:
            self.authenticate("sandbox"); net = os.open(f"/proc/{held['pid']}/ns/net", os.O_RDONLY)
            try:
                self.authenticate("sandbox")  # reject death/reuse across namespace acquisition
                prefix = ["nsenter", "--net=/proc/self/fd/" + str(net), "--"]; options = ["-F", "/dev/null", "-i", self.root + "/authority/client"]
                for option in ("BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "StrictHostKeyChecking=yes",
                               "GlobalKnownHostsFile=/dev/null", "UserKnownHostsFile=" + self.root + "/authority/known_hosts",
                               "ConnectTimeout=2", "ConnectionAttempts=3"):
                    options += ["-o", option]
                code, out = self.command(prefix + ["ssh", *options, "root@127.0.0.1", "printf cogs-capability-probe"], status=True, pass_fds=(net,))
                result["ssh"] = code == 0 and out == b"cogs-capability-probe"
                if result["ssh"]:
                    self.authenticate("sandbox")
                    code, _ = self.command(prefix + ["sftp", *options, "-b", self.root + "/authority/sftp-batch", "root@127.0.0.1"], status=True, pass_fds=(net,))
                    result["sftp"] = code == 0
                self.authenticate("sandbox")
            finally:
                os.close(net)
        self.record("capability-measurement", result)
        return result  # measurements are never evidence/pass admission

    def dispatch(self, q):
        require(not self.recovery and q.pop("generation") == self.generation); op = q.pop("op")
        require(not self.probe or op not in ("lease", "evidence", "status", "authenticate"))
        if op == "capability-probe":
            require(self.probe)
            return self.capability_probe()
        if op == "provenance":
            return self.provenance(q)
        if op == "mkdir":
            parts = q["path"].split("/"); fd = os.dup(self.fd)
            try:
                for i, part in enumerate(parts):
                    child = directory(fd, part, q["mode"] if i == len(parts) - 1 else None); os.close(fd)
                    fd = child
                os.fchown(fd, q.get("uid", 0), q.get("uid", 0))
            finally:
                os.close(fd)
        elif op == "file":
            parent, name = q["path"].rsplit("/", 1); fd = os.dup(self.fd)
            try:
                for part in parent.split("/"):
                    child = directory(fd, part); os.close(fd)
                    fd = child
                exclusive(fd, name, base64.b64decode(q["data"], validate=True), q["mode"], q.get("uid", 0))
            finally:
                os.close(fd)
        elif op == "storage":
            require(q["name"] in ("publication", "workspace", "state")); size = {"publication": 32, "workspace": 2048, "state": 512}[q["name"]]
            name = q["name"]; self.record(name + "-storage", {"name": name, "size": size})
            self.mounts.append(name)  # before any acquisition, including lost command observations
            self.records.add(name + ".img"); exclusive(self.control, name + ".img", b"", 0o600)
            self.record(name + "-backing", identity(os.stat(name + ".img", dir_fd=self.control))[:2])
            os.truncate(self.root + "/control/" + name + ".img", size * 1048576)
            self.command(["mkfs.ext4", "-q", "-F", self.root + "/control/" + name + ".img"])
            with closing_fd(os.open(name + ".img", os.O_RDWR | os.O_NOFOLLOW, dir_fd=self.control)) as fd:
                os.fsync(fd)
            os.mkdir(self.root + "/" + name, 0o700); self.record(name + "-loop-intent", True)
            loop = self.command(["losetup", "--find", "--show", self.root + "/control/" + name + ".img"]).decode().strip()
            require(re.fullmatch(r"/dev/loop[0-9]+", loop)); self.record(name + "-loop", self.storage_observation(name)[0])
            self.record(name + "-mount-intent", True); self.command(["mount", "-o", "nodev,nosuid", loop, self.root + "/" + name])
            self.record(name + "-mount", self.storage_observation(name)[1]); os.chmod(self.root + "/" + name, 0o700)
            os.rmdir(self.root + "/" + name + "/lost+found")
        elif op == "pair":
            with closing_fd(directory(self.fd, "publication")) as fd:
                require(self.publication is None and "publication" in self.mounts)
                self.record("publication-intent", {"generation": self.generation, "parent": identity(os.fstat(fd))[:2], "pair": q["pair"]})
                sources = publish_pair(fd, self.generation, q["pair"]); self.publication = {"pair": q["pair"], "sources": sources}
                self.record("publication-receipt", self.publication)
                return sources
        elif op == "seal":
            require(not self.ids and not self.sealed)
            for path in ("authority", "sandbox-input", "inputs/api", "inputs/proxy", "inputs/ssh", "inputs/pki"):
                fd = os.dup(self.fd)
                for part in path.split("/"):
                    child = directory(fd, part); os.close(fd)
                    fd = child
                names = os.listdir(fd); require(0 < len(names) <= 32)
                files = {n: [list(identity(os.stat(n, dir_fd=fd, follow_symlinks=False))), digest(capture(fd, n))] for n in names}
                self.record("seal-" + path.replace("/", "-"), {"path": path, "identity": identity(os.fstat(fd))[:2], "files": files})
                self.sealed.append((fd, files))
        elif op == "evidence":
            return self.evidence()
        elif op == "lease-directory":
            os.chown(self.root + "/lease", 0, 65532)
        elif op == "status":
            v = self.inspect(self.ids["worker"]["id"])
            return {"running": v["State"]["Running"], "code": v["State"]["ExitCode"]}
        elif op == "create":
            role, spec = q["role"], q["spec"]; require(role in ("trust", "sandbox", "worker") and role not in self.ids)
            require(not self.probe or role != "worker"); expected = list(CAPABILITIES) if role == "sandbox" else []
            if self.probe and role == "sandbox":
                removed = [c for c in expected if c not in spec["caps"]]; require(len(removed) == 1)
                expected.remove(removed[0])
            require(spec["caps"] == expected and spec["mask"] == sum(2 ** CAPABILITIES[c] for c in expected)); self.record(role + "-intent", spec)
            cid = self.docker("create", *q["argv"]).decode().strip(); require(ID.fullmatch(cid))
            self.ids[role] = {"id": cid, "spec": spec}
            # Persist ID before inspection; rejection still owns the exact stopped container.
            self.record(role + "-receipt", self.ids[role]); created = self.inspect(cid)
            require(created["Image"] == spec["image"] and not created["State"]["Running"]); self.ids[role]["environment"] = environment(created["Config"], role)
            inherited = environment(self.images[spec["image"]]["Config"])
            added = {"worker": ["NODE_EXTRA_CA_CERTS=/run/cogs/pki/telemetry-ca.crt"],
                     "sandbox": ["COGS_PROXY_ENDPOINT=http://127.0.0.1:18080"]}.get(role, [])
            require(self.ids[role]["environment"] == sorted(inherited + added))
            self.ids[role]["sources"] = {m["target"]: identity(os.stat(m["source"], follow_symlinks=False))[:2] for m in spec["mounts"]}
            if role == "worker":
                self.verify_candidate(cid)
            if role == "trust":
                data = self.docker("start", "-a", cid); require(self.inspect(cid)["State"]["ExitCode"] == 0)
                self.docker("rm", cid); del self.ids[role]
                self.record(role + "-retired", {"id": cid})
                return base64.b64encode(data).decode()
            if self.probe:
                self.ids[role]["start_code"], _ = self.docker("start", cid, status=True)
            else:
                self.docker("start", cid)
            return cid
        elif op == "authenticate":
            return self.authenticate(q["role"])
        elif op == "exec":
            require(q["program"] in ("ssh-keygen", "openssl"))
            return base64.b64encode(self.command([q["program"], *q["args"]])).decode()
        elif op == "image":
            v = json.loads(self.docker("image", "inspect", q["id"]))[0]; require(v["Id"] == q["id"] and v["Architecture"] == "amd64" and v["Os"] == "linux")
            environment(v["Config"]); self.images[q["id"]] = v
            self.record("image-" + q["id"][7:], v)
            return v
        elif op == "lease":
            self.receipt = q["receipt"]; self.bind_receipt()
            self.record("lease-receipt", self.receipt)
            for name in ("gate.sock", "control.sock"):
                listener = socket.socket(socket.AF_UNIX); listener.bind(self.root + "/lease/" + name)
                os.chown(self.root + "/lease/" + name, 0, 65532); os.chmod(self.root + "/lease/" + name, 0o660)
                listener.listen(2); self.record(name + "-socket", identity(os.stat(self.root + "/lease/" + name, follow_symlinks=False))[:2])
                self.selector.register(listener, selectors.EVENT_READ, name)
            with closing_fd(directory(self.fd, "lease")) as fd:
                exclusive(fd, "snapshot-receipt.json", canonical(self.receipt), 0o444)
                self.record("snapshot-receipt-inode", identity(os.stat("snapshot-receipt.json", dir_fd=fd))[:2])
        elif op == "settle":
            require(not self.probe or q.get("passed") is not True); self.failed = self.failed or q.get("passed") is not True
            require(self.failed or "evidence-validated" in os.listdir(self.control)); self.settle()
            return {"retired": True, "failed": self.failed}
        else:
            raise RuntimeError("unknown custody operation")
        return None

    def peer(self, listener, kind):
        conn, _ = listener.accept(); conn.settimeout(2)
        try:
            pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(kind not in self.used and (pid, uid, gid) == (self.authenticate("worker")["pid"], 65532, 65532)); self.used.add(kind)
            self.peers[conn] = {"kind": kind, "nonce": None, "sequence": 0, "last": time.monotonic()}
            self.selector.register(conn, selectors.EVENT_READ, "peer")
        except BaseException:
            conn.close()
            raise

    def message(self, conn):
        held = self.peers[conn]; raw = line(conn.fileno(), 131072, self.deadline)
        q = json.loads(raw); keys = {"version", "op", "nonce", "sequence", "receipt_digest", "consumer_id", "pid"}
        require(set(q) == keys | ({"entry"} if q["op"] == "persist" else {"event"} if q["op"] == "event" else set()))
        require(canonical(q) == raw and NONCE.fullmatch(q["nonce"]))
        require(type(q["sequence"]) is int and type(q["pid"]) is int and q["sequence"] == held["sequence"] + 1 and q["pid"] == 1)
        require(held["nonce"] in (None, q["nonce"]))
        require(q["receipt_digest"] == digest(canonical(self.receipt)) and q["consumer_id"] == self.receipt["consumer_id"])
        require(q["version"] == "cogs.skill-snapshot-control/v1")
        if q["op"] in ("headers", "event", "turn", "persist", "history", "shutdown"):
            require(held["kind"] == "gate.sock" and held["sequence"] > 0); self.headers = self.headers or q["op"] == "headers"
            self.events += int(q["op"] == "event"); self.turns += int(q["op"] == "turn")
            require(self.events <= 48 and self.turns <= 16 and (q["op"] != "turn" or self.headers))
            if q["op"] == "event":
                event = q["event"]; require(set(event) == {"kind", "correlation_id", "request_id"})
                require(all(v is None or isinstance(v, str) and 0 < len(v) <= 128 for v in event.values())); self.publications.append(event)
            if q["op"] == "persist":
                tool_result(q["entry"])  # reject failed effects independently of the candidate observer
                nodes = source_nodes(q["entry"]); require(len(self.admissions) < 25 and self.nodes + nodes <= 2048 and self.history is None)
                self.admissions.append(digest(canonical(q["entry"]))); self.nodes += nodes
            if q["op"] == "history":
                require(self.turns == 3 and [v["kind"] for v in self.publications].count("run_settled") == 3); self.retained_history()
            require(q["op"] != "shutdown" or self.released); self.shutdown = self.shutdown or q["op"] == "shutdown"
            reply = "granted"
        else:
            reply = {"acquire": "leased", "ping": "alive", "release": "released"}[q["op"]]
        require(q["op"] != "acquire" or held["sequence"] == 0); self.bind_receipt()
        held.update(nonce=q["nonce"], sequence=q["sequence"], last=time.monotonic()); conn.sendall(canonical({**q, "op": reply}))
        if q["op"] == "release":
            self.released = held["kind"] == "control.sock" or self.released; self.selector.unregister(conn)
            del self.peers[conn]; conn.close()

    def settle_children(self):
        """Complete all command-dependent work before retiring helper command custody."""
        for conn in list(self.peers):
            conn.close()
        self.peers.clear()
        for role in reversed(list(self.ids)):
            held = self.ids[role]; present = self.docker("ps", "-aq", "--no-trunc").decode().splitlines()
            require(all(ID.fullmatch(cid) for cid in present))
            if held["id"] in present:
                v = self.inspect(held["id"]); require(v["Image"] == held["spec"]["image"])
                require(v["Config"]["Labels"] == {**(self.images[v["Image"]]["Config"]["Labels"] or {}), "cogs.product.generation": self.generation})
                self.docker("rm", "-f", held["id"])
            if "pidfd" in held:
                require(select.select([held["pidfd"]], [], [], 2)[0]); os.close(held["pidfd"])
            del self.ids[role]; self.record(role + "-retired", {"id": held["id"]})
        if self.disk is not None:
            require(self.docker("ps", "-aq", "--no-trunc") == b"")
        for role in ("trust", "sandbox", "worker"):
            names = os.listdir(self.control); require(role + "-intent" not in names or role + "-retired" in names)
        if not self.failed:
            self.evidence()  # revalidate after all writers retire, still mounted; journal equality forbids drift
        for fd, files in self.sealed:
            require(set(os.listdir(fd)) <= set(files))
            for name, expected in files.items():
                journal = "unlink-" + str(os.fstat(fd).st_ino) + "-" + name
                if name in os.listdir(fd):
                    require([list(identity(os.stat(name, dir_fd=fd, follow_symlinks=False))), digest(capture(fd, name))] == expected)
                    self.record(journal, expected)
                    os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
                else:
                    require(self.saved(journal) == expected)
            os.close(fd)
        self.sealed.clear()
        for key in list(self.selector.get_map().values()):
            if key.data in ("gate.sock", "control.sock"):
                key.fileobj.close()
        if "lease" in os.listdir(self.fd):
            with closing_fd(directory(self.fd, "lease")) as fd:
                require(set(os.listdir(fd)) <= {"gate.sock", "control.sock", "snapshot-receipt.json"})
                for name in os.listdir(fd):
                    key = "snapshot-receipt-inode" if name.endswith(".json") else name + "-socket"
                    require(self.saved(key) == list(identity(os.stat(name, dir_fd=fd, follow_symlinks=False))[:2]))
                    if name.endswith(".json"):
                        require(capture(fd, name) == canonical(self.saved("lease-receipt")))
                    os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
        for name in reversed(self.mounts):
            names = os.listdir(self.control)
            if name + "-detached" in names:
                if name == "publication" and "publication.img" in names:
                    require(self.storage_observation(name) == (None, None))
                    os.unlink("publication.img", dir_fd=self.control)
                    self.records.discard("publication.img")
                    os.fsync(self.control)
                continue
            require(name + ".img" not in names or name + "-backing" in names)
            loop, mount = self.storage_observation(name) if name + "-backing" in names else (None, None)
            for suffix, live in (("-loop", loop), ("-mount", mount)):
                if name + suffix in names and live is not None:
                    require(self.saved(name + suffix) == live)
            if mount:
                self.record(name + "-unmount-intent", mount)
                self.command(["umount", self.root + "/" + name])
            require(self.storage_observation(name)[1] is None if name + "-backing" in names else True)
            if loop:
                self.record(name + "-detach-intent", loop)
                self.command(["losetup", "--detach", loop["name"]])
                require(self.storage_observation(name) == (None, None))
            self.record(name + "-detached", True)
            if name == "publication" and "publication.img" in os.listdir(self.control):
                os.unlink("publication.img", dir_fd=self.control)
                self.records.discard("publication.img")
                os.fsync(self.control)
        self.mounts.clear()
        if self.disk is not None:
            delta = self.disk - os.statvfs("/var/lib/docker").f_bfree * os.statvfs("/var/lib/docker").f_frsize
            require(delta <= 256 * 1048576)
        if not self.failed:
            require(set(os.listdir(self.control)) == self.records)

    def settle(self):
        # Durable boundary: recovery must not need commands after either rmdir.
        if "cgroup-retire-intent" not in os.listdir(self.control):
            self.settle_children()
            self.record("cgroup-retire-intent", True)
        require(self.saved("cgroup-retire-intent") is True)
        if os.path.exists(self.cg):
            require(self.saved("cgroup") == list(identity(os.stat(self.cg))[:2]))
            require("populated 0" in open(self.cg + "/cgroup.events", encoding="ascii").read())
            if os.path.exists(self.cg + "/helpers"):
                os.rmdir(self.cg + "/helpers")
            os.rmdir(self.cg)
        self.record("retired", {"generation": self.generation, "failed": self.failed})

    def run(self):
        try:
            while True:
                require(time.monotonic() < self.deadline)
                require(all(time.monotonic() - h["last"] < 5 for h in self.peers.values()))
                for key, _ in self.selector.select(0.1):
                    if key.data == "supervisor":
                        raw = line(sys.stdin.fileno(), 4 * 1048576, self.deadline)
                        require(raw.endswith(b"\n"))
                        q = json.loads(raw)
                        final = q["op"] == "settle"
                        result = self.dispatch(q)
                        data = memoryview(canonical({"generation": self.generation, "result": result}))
                        os.set_blocking(sys.stdout.fileno(), False)
                        end = min(self.deadline, time.monotonic() + 2)
                        while data:
                            require(time.monotonic() < end and select.select([], [sys.stdout.fileno()], [], max(0, end - time.monotonic()))[1])
                            data = data[os.write(sys.stdout.fileno(), data):]
                        if final:
                            return
                    elif key.data == "peer":
                        self.message(key.fileobj)
                    else:
                        self.peer(key.fileobj, key.data)
        except BaseException:
            self.rollback()
            raise


if __name__ == "__main__":
    try:
        config = json.loads(line(sys.stdin.fileno(), 32768))
        owner = Custody(config)
        if not owner.recovery:
            owner.run()
    except BaseException:
        sys.stderr.write("product custody failed; preserve generation control\n")
        sys.exit(1)

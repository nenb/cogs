#!/usr/bin/env python3
"""Root-only Linux custody process. stdin EOF/deadline settles receipts, never names.
Importing this file has no effects; portable tests exercise the descriptor primitives.
"""
import base64
import ctypes
import hashlib
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

NONCE = re.compile(r"[0-9a-f]{32}\Z")
ID = re.compile(r"[0-9a-f]{64}\Z")
LIMITS = {"memory.max": "4294967296", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "200000 100000"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}


def require(ok):
    if not ok:
        raise RuntimeError("product custody unavailable")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def line(fd, maximum):
    data = bytearray()
    end = time.monotonic() + 2
    while not data.endswith(b"\n"):
        require(len(data) < maximum and time.monotonic() < end)
        require(select.select([fd], [], [], max(0, end - time.monotonic()))[0])
        chunk = os.read(fd, 1)
        require(chunk)
        data.extend(chunk)
    return bytes(data)


def directory(parent, name, mode=None):
    require(name not in ("", ".", "..") and "/" not in name)
    if mode is not None:
        os.mkdir(name, mode, dir_fd=parent)
        os.fsync(parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    require(stat.S_ISDIR(os.fstat(fd).st_mode))
    return fd


def capture(parent, name, maximum=1048576):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= maximum)
        data = bytearray()
        while len(data) <= s.st_size:
            chunk = os.read(fd, min(32768, s.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) == s.st_size and identity(s) == identity(os.fstat(fd)))
        require(identity(s) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        return bytes(data)
    finally:
        os.close(fd)


def exclusive(parent, name, data, mode=0o400, uid=0):
    require("/" not in name and name not in ("", ".", ".."))
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    try:
        os.fchown(fd, uid, uid)
        os.fchmod(fd, mode)
        remaining = memoryview(data)
        while remaining:
            remaining = remaining[os.write(fd, remaining):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
    require(capture(parent, name, max(len(data), 1)) == data)


def no_replace(parent, source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    require(rename(parent, source.encode(), parent, destination.encode(), 1) == 0)
    os.fsync(parent)


def tree(parent, entries, verify=False):
    """Closed, bounded inventory; all traversal is relative to retained descriptors."""
    require(len(entries) <= 257)
    children = {}
    for path, entry in entries.items():
        parts = path.split("/")
        require(len(parts) <= 16 and len(path.encode()) <= 256)
        require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) and p not in (".", "..") for p in parts))
        children.setdefault(parts[0], {})["/".join(parts[1:])] = entry
    if verify:
        require(set(os.listdir(parent)) == set(children))
    for name, descendants in sorted(children.items()):
        if "" in descendants:
            require(len(descendants) == 1)
            entry = descendants[""]
            require(set(entry) == {"data", "mode"} and entry["mode"] in (0o444, 0o555))
            data = base64.b64decode(entry["data"], validate=True)
            require(len(data) <= 1048576 and not data.startswith(b"\xef\xbb\xbf"))
            if not verify:
                exclusive(parent, name, data, entry["mode"])
            s = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == entry["mode"])
            require(capture(parent, name) == data)
        else:
            fd = directory(parent, name, None if verify else 0o700)
            try:
                tree(fd, descendants, verify)
                if not verify:
                    os.fchmod(fd, 0o555)
                    os.fsync(fd)
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
            finally:
                os.close(fd)
    os.fsync(parent)


def publish_pair(parent, generation, pair):
    require(NONCE.fullmatch(generation) and set(pair) == {"shared", "user"})
    stage = directory(parent, ".stage-" + generation, 0o700)
    try:
        for scope in ("shared", "user"):
            fd = directory(stage, scope, 0o700)
            try:
                tree(fd, pair[scope])
                os.fchmod(fd, 0o555)
                tree(fd, pair[scope], True)
            finally:
                os.close(fd)
        os.fchmod(stage, 0o555)
        os.fsync(stage)
        no_replace(parent, ".stage-" + generation, generation)
        require(os.fstat(stage).st_ino == os.stat(generation, dir_fd=parent).st_ino)
        result = {}
        for scope in ("shared", "user"):
            fd = directory(stage, scope)
            try:
                tree(fd, pair[scope], True)
                names = os.listdir(fd)
                require(len(names) == 1 and ID.fullmatch(names[0]))
                child = directory(fd, names[0])
                s = os.fstat(child)
                os.close(child)
                result[scope] = {"source_device": str(s.st_dev), "source_inode": str(s.st_ino)}
            finally:
                os.close(fd)
        return result
    finally:
        os.close(stage)


class Custody:
    def __init__(self, config):
        require(sys.platform == "linux" and os.geteuid() == 0 and os.uname().machine == "x86_64")
        self.generation = config["generation"]
        require(NONCE.fullmatch(self.generation))
        self.deadline = time.monotonic() + config["seconds"]
        self.ids, self.peers, self.mounts, self.images, self.sealed = {}, {}, [], {}, []
        self.failed, self.released = False, False
        self.used, self.events, self.turns, self.headers = set(), 0, 0, False
        self.root = "/var/lib/cogs-product-test/" + self.generation
        parent = os.open("/var/lib/cogs-product-test", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        s = os.fstat(parent)
        require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700)
        self.fd = directory(parent, self.generation, 0o700)
        os.close(parent)
        self.control = directory(self.fd, "control", 0o700)
        exclusive(self.control, "intent", canonical(config))
        self.cg = "/sys/fs/cgroup/cogs-product-" + self.generation
        os.mkdir(self.cg)
        for key, value in LIMITS.items():
            self.cwrite(self.cg, key, value)
        self.cwrite(self.cg, "cgroup.subtree_control", "+memory +pids +cpu")
        os.mkdir(self.cg + "/helpers")
        require(self.command(["docker", "--host=unix:///var/run/docker.sock", "ps", "-aq", "--no-trunc"]) == b"")
        info = json.loads(self.docker("info", "--format", "{{json .}}"))
        require(info["CgroupVersion"] == "2" and info["CgroupDriver"] == "cgroupfs")
        require(info["Driver"] == "overlay2" and info["OSType"] == "linux")
        self.disk = os.statvfs("/var/lib/docker").f_bfree * os.statvfs("/var/lib/docker").f_frsize
        self.selector = selectors.DefaultSelector()
        self.selector.register(sys.stdin.buffer, selectors.EVENT_READ, "supervisor")

    def cwrite(self, path, name, value):
        with open(path + "/" + name, "w", encoding="ascii") as file:
            file.write(value)

    def command(self, argv, cap=1048576):
        bootstrap = "import os,signal,sys;os.kill(os.getpid(),signal.SIGSTOP);os.execvpe(sys.argv[1],sys.argv[1:],dict(os.environ))"
        p = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, *argv], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
        pidfd = os.pidfd_open(p.pid)
        out, err = bytearray(), bytearray()
        try:
            _, status = os.waitpid(p.pid, os.WUNTRACED)
            require(os.WIFSTOPPED(status))
            self.cwrite(self.cg + "/helpers", "cgroup.procs", str(p.pid))
            os.kill(p.pid, signal.SIGCONT)
            with selectors.DefaultSelector() as poll:
                for stream, target in ((p.stdout, out), (p.stderr, err)):
                    os.set_blocking(stream.fileno(), False)
                    poll.register(stream, selectors.EVENT_READ, target)
                end = min(self.deadline, time.monotonic() + 15)
                while poll.get_map():
                    require(time.monotonic() < end)
                    for key, _ in poll.select(0.05):
                        chunk = os.read(key.fd, 32768)
                        key.data.extend(chunk)
                        require(len(out) <= cap and len(err) <= 4096)
                        if not chunk:
                            poll.unregister(key.fileobj)
                require(p.wait(timeout=max(0.01, end - time.monotonic())) == 0)
            return bytes(out)
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
            os.close(pidfd)
            p.stdout.close()
            p.stderr.close()

    def docker(self, *args):
        return self.command(["docker", "--host=unix:///var/run/docker.sock", *args])

    def inspect(self, cid):
        require(ID.fullmatch(cid))
        values = json.loads(self.docker("inspect", cid))
        require(len(values) == 1 and values[0]["Id"] == cid)
        return values[0]

    def authenticate(self, role):
        held = self.ids[role]
        v = self.inspect(held["id"])
        p, spec = v["State"]["Pid"], held["spec"]
        require(v["State"]["Running"] and v["Image"] == spec["image"])
        require(v["Config"]["Labels"] == {**(self.images[spec["image"]]["Config"]["Labels"] or {}), "cogs.product.generation": self.generation})
        h = v["HostConfig"]
        require(h["ReadonlyRootfs"] and not h["Privileged"] and h["PidMode"] == "")
        require(h["LogConfig"]["Type"] == "none" and h["CapDrop"] == ["ALL"])
        require(sorted(h["CapAdd"] or []) == sorted(spec["caps"]))
        require(h["SecurityOpt"] == ["no-new-privileges"] and h["CgroupParent"] == self.cg[14:])
        require(h["Memory"] == 4294967296 and h["MemorySwap"] == 4294967296 and h["MemorySwappiness"] == 0)
        require(h["PidsLimit"] == 128 and h["NanoCpus"] == 2000000000 and not h["PortBindings"])
        require(h["ShmSize"] == 16777216)
        require(h["NetworkMode"] == spec["network"] and not h["Devices"] and not h["Binds"])
        require(len(v["Mounts"]) == len(spec["mounts"]))
        for m in v["Mounts"]:
            expected = next(x for x in spec["mounts"] if x["target"] == m["Destination"])
            require(m["Type"] == "bind" and m["Source"] == expected["source"] and m["RW"] == (not expected["ro"]))
            require(m["Propagation"] == "rprivate")
            a, b = os.stat(m["Source"]), os.stat(f"/proc/{p}/root" + m["Destination"])
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
        require((h["Tmpfs"] or {}) == spec["tmpfs"])
        with open(f"/proc/{p}/mountinfo", encoding="ascii") as f:
            mounts = [row.split() for row in f]
        for expected in spec["mounts"]:
            live = [m for m in mounts if m[4] == expected["target"]]
            require(len(live) == 1 and ("ro" in live[0][5].split(",")) == expected["ro"])
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
        require(all(int(status[k].strip(), 16) == spec["mask"] for k in ("CapEff", "CapPrm", "CapBnd")))
        require(status["NoNewPrivs"].strip() == "1")
        require(status["Seccomp"].strip() == "2")
        namespace = os.readlink(f"/proc/{p}/ns/mnt")
        if role == "worker":
            require(os.readlink(f"/proc/{p}/ns/net") == os.readlink(f"/proc/{self.ids['sandbox']['pid']}/ns/net"))
        if "pid" in held:
            require(held["pid"] == p and held["namespace"] == namespace)
        else:
            held["pidfd"] = os.pidfd_open(p)
        require(not select.select([held["pidfd"]], [], [], 0)[0])
        held.update(pid=p, namespace=namespace)
        return held

    def dispatch(self, q):
        require(q.pop("generation") == self.generation)
        op = q.pop("op")
        if op == "mkdir":
            parts = q["path"].split("/")
            fd = os.dup(self.fd)
            try:
                for i, part in enumerate(parts):
                    child = directory(fd, part, q["mode"] if i == len(parts) - 1 else None)
                    os.close(fd)
                    fd = child
                os.fchown(fd, q.get("uid", 0), q.get("uid", 0))
            finally:
                os.close(fd)
        elif op == "file":
            parent, name = q["path"].rsplit("/", 1)
            fd = os.dup(self.fd)
            try:
                for part in parent.split("/"):
                    child = directory(fd, part)
                    os.close(fd)
                    fd = child
                exclusive(fd, name, base64.b64decode(q["data"], validate=True), q["mode"], q.get("uid", 0))
            finally:
                os.close(fd)
        elif op == "storage":
            require(q["name"] in ("publication", "workspace", "state"))
            size = {"publication": 32, "workspace": 2048, "state": 512}[q["name"]]
            name = q["name"]
            exclusive(self.control, name + ".img", b"", 0o600)
            os.truncate(self.root + "/control/" + name + ".img", size * 1048576)
            self.command(["mkfs.ext4", "-q", "-F", self.root + "/control/" + name + ".img"])
            os.mkdir(self.root + "/" + name, 0o700)
            self.command(["mount", "-o", "loop,nodev,nosuid", self.root + "/control/" + name + ".img", self.root + "/" + name])
            self.mounts.append(name)
            os.chmod(self.root + "/" + name, 0o700)
            os.rmdir(self.root + "/" + name + "/lost+found")
        elif op == "pair":
            fd = directory(self.fd, "publication")
            try:
                return publish_pair(fd, self.generation, q["pair"])
            finally:
                os.close(fd)
        elif op == "seal":
            require(not self.ids and not self.sealed)
            for path in ("authority", "sandbox-input", "inputs/api", "inputs/proxy", "inputs/ssh", "inputs/pki"):
                fd = os.dup(self.fd)
                for part in path.split("/"):
                    child = directory(fd, part)
                    os.close(fd)
                    fd = child
                names = os.listdir(fd)
                require(0 < len(names) <= 32)
                self.sealed.append((fd, {n: (identity(os.stat(n, dir_fd=fd, follow_symlinks=False)), digest(capture(fd, n))) for n in names}))
        elif op == "evidence":
            state = directory(self.fd, "state")
            session = directory(state, "session")
            history = directory(session, "sessions")
            require(os.listdir(history) and capture(session, "egress-audit.wal", 16777216))
            result = capture(session, "product-evidence.json", 8192).decode("utf-8")
            for fd in (history, session, state):
                os.close(fd)
            return result
        elif op == "lease-directory":
            os.chown(self.root + "/lease", 0, 65532)
        elif op == "status":
            v = self.inspect(self.ids["worker"]["id"])
            return {"running": v["State"]["Running"], "code": v["State"]["ExitCode"]}
        elif op == "create":
            role, spec = q["role"], q["spec"]
            require(role not in self.ids)
            exclusive(self.control, role + "-intent", canonical(spec))
            cid = self.docker("create", *q["argv"]).decode().strip()
            require(ID.fullmatch(cid))
            self.ids[role] = {"id": cid, "spec": spec}
            exclusive(self.control, role + "-receipt", canonical(self.ids[role]))
            if role == "trust":
                data = self.docker("start", "-a", cid)
                require(self.inspect(cid)["State"]["ExitCode"] == 0)
                self.docker("rm", cid)
                del self.ids[role]
                exclusive(self.control, role + "-retired", canonical({"id": cid}))
                return base64.b64encode(data).decode()
            self.docker("start", cid)
            return cid
        elif op == "authenticate":
            return self.authenticate(q["role"])
        elif op == "exec":
            require(q["program"] in ("ssh-keygen", "openssl"))
            return base64.b64encode(self.command([q["program"], *q["args"]])).decode()
        elif op == "image":
            v = json.loads(self.docker("image", "inspect", q["id"]))[0]
            require(v["Id"] == q["id"] and v["Architecture"] == "amd64" and v["Os"] == "linux")
            self.images[q["id"]] = v
            return v
        elif op == "lease":
            self.receipt = q["receipt"]
            require(self.receipt["worker_id"] == self.authenticate("worker")["id"])
            require(self.receipt["sandbox_id"] == self.authenticate("sandbox")["id"])
            exclusive(self.control, "lease-receipt", canonical(self.receipt))
            for name in ("gate.sock", "control.sock"):
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(self.root + "/lease/" + name)
                os.chown(self.root + "/lease/" + name, 0, 65532)
                os.chmod(self.root + "/lease/" + name, 0o660)
                listener.listen(2)
                self.selector.register(listener, selectors.EVENT_READ, name)
            fd = directory(self.fd, "lease")
            exclusive(fd, "snapshot-receipt.json", canonical(self.receipt), 0o444)
            os.close(fd)
        elif op == "settle":
            self.failed = self.failed or q.get("passed") is not True
            self.settle()
            return {"retired": True, "failed": self.failed}
        else:
            raise RuntimeError("unknown custody operation")
        return None

    def peer(self, listener, kind):
        conn, _ = listener.accept()
        conn.settimeout(2)
        try:
            pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(kind not in self.used and (pid, uid, gid) == (self.authenticate("worker")["pid"], 65532, 65532))
            self.used.add(kind)
            self.peers[conn] = {"kind": kind, "nonce": None, "sequence": 0, "last": time.monotonic()}
            self.selector.register(conn, selectors.EVENT_READ, "peer")
        except BaseException:
            conn.close()
            raise

    def message(self, conn):
        held = self.peers[conn]
        raw = line(conn.fileno(), 1024)
        q = json.loads(raw)
        keys = {"version", "op", "nonce", "sequence", "receipt_digest", "consumer_id", "pid"}
        require(set(q) == keys | ({"entries", "nodes"} if q["op"] == "history" else set()))
        require(canonical(q) == raw and NONCE.fullmatch(q["nonce"]))
        require(q["sequence"] == held["sequence"] + 1 and q["pid"] == 1)
        require(held["nonce"] in (None, q["nonce"]))
        require(q["receipt_digest"] == digest(canonical(self.receipt)) and q["consumer_id"] == self.receipt["consumer_id"])
        require(q["version"] == "cogs.skill-snapshot-control/v1")
        if q["op"] in ("headers", "event", "turn", "history", "shutdown"):
            require(held["kind"] == "gate.sock" and held["sequence"] > 0)
            self.headers = self.headers or q["op"] == "headers"
            self.events += int(q["op"] == "event")
            self.turns += int(q["op"] == "turn")
            require(self.events <= 48 and self.turns <= 16 and (q["op"] != "turn" or self.headers))
            require(q["op"] != "history" or (0 <= q["entries"] <= 25 and 0 <= q["nodes"] <= 2048))
            require(q["op"] != "shutdown" or self.released)
            reply = "granted"
        else:
            reply = {"acquire": "leased", "ping": "alive", "release": "released"}[q["op"]]
        require(q["op"] != "acquire" or held["sequence"] == 0)
        self.authenticate("worker")
        self.authenticate("sandbox")
        held.update(nonce=q["nonce"], sequence=q["sequence"], last=time.monotonic())
        conn.sendall(canonical({**q, "op": reply}))
        if q["op"] == "release":
            self.released = held["kind"] == "control.sock" or self.released
            self.selector.unregister(conn)
            del self.peers[conn]
            conn.close()

    def settle(self):
        for conn in list(self.peers):
            conn.close()
        self.peers.clear()
        for role in reversed(list(self.ids)):
            held = self.ids[role]
            v = self.inspect(held["id"])
            require(v["Image"] == held["spec"]["image"])
            require(v["Config"]["Labels"] == {**(self.images[v["Image"]]["Config"]["Labels"] or {}), "cogs.product.generation": self.generation})
            self.docker("rm", "-f", held["id"])
            if "pidfd" in held:
                require(select.select([held["pidfd"]], [], [], 2)[0])
                os.close(held["pidfd"])
            del self.ids[role]
            exclusive(self.control, role + "-retired", canonical({"id": held["id"]}))
        require(self.docker("ps", "-aq", "--no-trunc") == b"")
        for fd, files in self.sealed:
            require(set(os.listdir(fd)) == set(files))
            for name, expected in files.items():
                require((identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), digest(capture(fd, name))) == expected)
            for name in files:
                os.unlink(name, dir_fd=fd)
            os.fsync(fd)
            os.close(fd)
        for key in list(self.selector.get_map().values()):
            if key.data in ("gate.sock", "control.sock"):
                key.fileobj.close()
                os.unlink(self.root + "/lease/" + key.data)
        for name in reversed(self.mounts):
            self.command(["umount", self.root + "/" + name])
            if name == "publication":
                os.unlink("publication.img", dir_fd=self.control)
                os.fsync(self.control)
        self.mounts.clear()
        require("populated 0" in open(self.cg + "/cgroup.events", encoding="ascii").read())
        os.rmdir(self.cg + "/helpers")
        os.rmdir(self.cg)
        delta = self.disk - os.statvfs("/var/lib/docker").f_bfree * os.statvfs("/var/lib/docker").f_frsize
        require(delta <= 256 * 1048576)
        exclusive(self.control, "retired", canonical({"generation": self.generation, "failed": self.failed}))

    def run(self):
        try:
            while True:
                require(time.monotonic() < self.deadline)
                require(all(time.monotonic() - h["last"] < 5 for h in self.peers.values()))
                for key, _ in self.selector.select(0.1):
                    if key.data == "supervisor":
                        raw = line(sys.stdin.fileno(), 4 * 1048576)
                        require(raw.endswith(b"\n"))
                        q = json.loads(raw)
                        final = q["op"] == "settle"
                        result = self.dispatch(q)
                        sys.stdout.buffer.write(canonical({"generation": self.generation, "result": result}))
                        sys.stdout.buffer.flush()
                        if final:
                            return
                    elif key.data == "peer":
                        self.message(key.fileobj)
                    else:
                        self.peer(key.fileobj, key.data)
        except BaseException:
            self.failed = True
            exclusive(self.control, "cleanup-required", canonical({"generation": self.generation}))
            self.deadline = time.monotonic() + 30
            self.settle()
            raise


if __name__ == "__main__":
    try:
        config = json.loads(line(sys.stdin.fileno(), 32768))
        Custody(config).run()
    except BaseException:
        sys.stderr.write("product custody failed; preserve generation control\n")
        sys.exit(1)

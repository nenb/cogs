#!/usr/bin/env python3
"""Portable primitive faults for production launcher recovery owners."""

from contextlib import contextmanager
import ctypes
import errno
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
COMMON_SUPPORT = ROOT / "test/fixtures/outcome-two/recovery/common-portable.py"
_common_support_spec = importlib.util.spec_from_file_location("outcome_two_recovery_common_support", COMMON_SUPPORT)
_common_support = importlib.util.module_from_spec(_common_support_spec)
_common_support_spec.loader.exec_module(_common_support)
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURE = ROOT / "test/fixtures/outcome-two/recovery/cases.json"
ROW_KEYS = {
    "id", "production_method", "primitive_fault", "intended_code",
    "cleanup_domains", "sentinel",
}
REQUIRED_ACCEPTANCE = {
    "AT-ADAPT-REC-01", "AT-ROOT-01", "AT-LIFE-01", "AT-LIFE-02",
    "AT-FD-CLOSE-01", "AT-UNAV-01",
}

def load_module():
    spec = importlib.util.spec_from_file_location(
        "completion_trusted_runtime_launcher_recovery", MODULE,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

def production_symbol(module, name):
    value = module
    for component in name.split("."):
        value = getattr(value, component, None)
    return value

def fixture_rows(module):
    document = json.loads(FIXTURE.read_text())
    if set(document) != {"version", "rows"}:
        raise AssertionError("recovery fixture document shape")
    if document["version"] != "cogs.outcome-two-recovery-cases/v5":
        raise AssertionError("recovery fixture version")
    rows = document["rows"]
    acceptance = set()
    identifiers = set()
    for row in rows:
        if set(row) != ROW_KEYS:
            raise AssertionError("recovery fixture row shape")
        if row["id"] in identifiers:
            raise AssertionError("recovery fixture ID duplicate")
        identifiers.add(row["id"])
        acceptance.add(row["id"].split(":", 1)[0])
        fault = row["primitive_fault"]
        if set(fault) != {"method", "mutation"}:
            raise AssertionError("recovery primitive fault shape")
        event = f"ops.{fault['method']}:{fault['mutation']}"
        if row["sentinel"] != event:
            raise AssertionError("recovery sentinel is not a primitive event")
        if not callable(production_symbol(module, row["production_method"])):
            raise AssertionError(f"missing production method {row['production_method']}")
        if type(row["cleanup_domains"]) is not list:
            raise AssertionError("recovery cleanup domains shape")
    if acceptance != REQUIRED_ACCEPTANCE:
        raise AssertionError(f"recovery acceptance set drift: {acceptance}")
    return rows

@contextmanager
def patched(target, **replacements):
    missing = object()
    previous = {name: getattr(target, name, missing) for name in replacements}
    for name, value in replacements.items():
        setattr(target, name, value)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is missing:
                delattr(target, name)
            else:
                setattr(target, name, value)

class RecoveryOps:
    """Faults concrete operations reached from production ownership branches."""

    def __init__(self, module, row, root_parent=None):
        self.module = module
        self.fault = row["primitive_fault"]
        self.root_parent = root_parent
        self.events = []
        self.fired = False

    def mutation(self, method):
        if self.fired or method != self.fault["method"]:
            return None
        self.fired = True
        mutation = self.fault["mutation"]
        self.events.append(f"ops.{method}:{mutation}")
        return mutation

    def unavailable(self, primitive, saved):
        ctypes.set_errno(saved)
        return self.module._SystemOps._checked(self, -1, primitive)

    def open(self, path, flags, mode=0o600):
        return os.open(path, flags, mode)

    def close(self, fd):
        mutation = self.mutation("close")
        os.close(fd)
        if mutation == "after-effect-eio":
            raise OSError(errno.EIO, "modeled close after-effect failure")
        if mutation == "replace-root-after-close":
            leaf = Path(self.root_parent) / self.module._ROOT_LEAF
            leaf.rmdir()
            leaf.mkdir(mode=0o700)

    def mount(self, source, target, kind, flags, data):
        del source, target, kind, flags, data
        mutation = self.mutation("mount")
        if mutation == "enosys":
            self.unavailable("mount", errno.ENOSYS)
        if mutation == "eopnotsupp":
            self.unavailable("mount", errno.EOPNOTSUPP)
        raise AssertionError("unexpected recovery mount mutation")

    def start_time(self, pid):
        del pid
        mutation = self.mutation("start_time")
        if mutation == "enosys":
            self.unavailable("proc-stat", errno.ENOSYS)
        raise AssertionError("unexpected start-time mutation")

    def pidfd_signal(self, fd, number):
        del fd, number
        mutation = self.mutation("pidfd_signal")
        if mutation == "eio":
            raise OSError(errno.EIO, "modeled pidfd signal failure")
        raise AssertionError("unexpected pidfd signal mutation")

def materialization_failure(module, ops):
    try:
        module._materialize_root(
            ops,
            "gzip",
            (),
            (),
            {"tools": [None, None, {"objects": []}]},
            "/modeled-root",
        )
    except module.RuntimeLauncherUnavailable as error:
        return error
    raise AssertionError("materialization primitive fault was accepted")

def invoke_unavailable_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    primary = materialization_failure(module, ops)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    leases = [module._FdLease(read_fd, "recovery-authority")]
    module._recover_transaction_with_ops(
        ops, module._ProcessOwner(ops), leases, primary,
    )
    raise primary

def invoke_root_recovery(module, row, created):
    with tempfile.TemporaryDirectory() as parent:
        ops = RecoveryOps(module, row, parent)
        created.append(ops)
        old_parent = module._ROOT_PARENT
        module._ROOT_PARENT = parent
        owner = module._RootOwner(ops)
        try:
            owner.prepare()
            owner.cleanup()
        finally:
            leaf = Path(parent) / module._ROOT_LEAF
            if leaf.exists():
                leaf.rmdir()
            module._ROOT_PARENT = old_parent

def invoke_registration_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    owner = module._ProcessOwner(ops)
    primary = None
    try:
        with patched(module.os, pidfd_open=lambda pid, flags=0: read_fd), patched(
            module, _start_time=ops.start_time,
        ):
            owner.register(4242)
    except module.RuntimeLauncherUnavailable as error:
        primary = error
    if primary is None:
        raise AssertionError("registration primitive fault was accepted")
    os.close(write_fd)
    with patched(
        module.select,
        select=lambda readers, writers, errors, timeout=0: (
            list(readers), list(writers), list(errors)
        ),
    ), patched(module.os, waitpid=lambda pid, flags: (pid, 0)):
        module._recover_transaction_with_ops(ops, owner, [], primary)
    raise primary

def invoke_process_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    owner = module._ProcessOwner(ops)
    with patched(
        module.os,
        pidfd_open=lambda pid, flags=0: read_fd,
        getsid=lambda pid: 1,
        getpgid=lambda pid: 1,
    ), patched(
        module,
        _start_time=lambda pid: 1,
        _exe_identity=lambda pid: (1, 1),
    ):
        owner.register(4242)
    try:
        with patched(
            module.select,
            select=lambda readers, writers, errors, timeout=0: (
                [], list(writers), list(errors)
            ),
        ), patched(module, _process_matches=lambda lease: True), patched(
            module.signal, pidfd_send_signal=ops.pidfd_signal,
        ):
            owner.cleanup()
    finally:
        os.close(write_fd)
        if owner.processes[0].pidfd.state is module._FdState.OWNED:
            os.close(read_fd)

def invoke_close_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    lease = module._FdLease(read_fd, "close-uncertainty")
    module._recover_transaction_with_ops(
        ops, module._ProcessOwner(ops), [lease], None,
    )

def execute_row(module, row):
    adapters = {
        "AT-ADAPT-REC-01": invoke_unavailable_recovery,
        "AT-ROOT-01": invoke_root_recovery,
        "AT-LIFE-01": invoke_registration_recovery,
        "AT-LIFE-02": invoke_process_recovery,
        "AT-FD-CLOSE-01": invoke_close_recovery,
        "AT-UNAV-01": invoke_unavailable_recovery,
    }
    acceptance = row["id"].split(":", 1)[0]
    created = []
    try:
        adapters[acceptance](module, row, created)
    except module.RuntimeLauncherError as error:
        observed = error
    else:
        raise AssertionError(f"{row['id']}: production accepted primitive fault")
    if observed.code != row["intended_code"]:
        raise AssertionError(
            f"{row['id']}: expected {row['intended_code']!r}, got {observed.code!r}",
        ) from observed
    if len(created) != 1:
        raise AssertionError(f"{row['id']}: primitive adapter cardinality")
    if created[0].events != [row["sentinel"]]:
        raise AssertionError(
            f"{row['id']}: production primitive event mismatch {created[0].events}",
        )

COMMON_FIXTURE = ROOT / "test/fixtures/outcome-two/launcher/common-custodian-cases.jsonl"
FINAL_COMMON = ROOT / "scripts/native-qualification/common.py"
REQUIRED_COMMON_CUTS = {
    "custodian-fork", "ready-send", "listener-bind", "listener-listen",
    "published-send", "published-recv", "upload-ack-capability",
    "upload-ack-digest", "upload-ack-size", "upload-ack-generation",
    "upload-ack-send", "upload-ack-recv", "unlink:.owner.json",
    "unlink:report.json", "unlink:.authority.json", "rmdir", "waitpid",
    "replace:active-directory", "replace:authority", "replace:report",
    "replace:receipt", "replace:retired-directory", "recovery:final-unlink",
    "recovery:rmdir", "recovery:parent-fsync", "directory-exchange",
    "private-capability-send", "private-capability-recv", "private-capability-close",
    "issuer-source-open", "issuer-source-read", "issuer-source-fstat",
    "issuer-memfd", "issuer-write", "issuer-fsync", "issuer-pipe",
    "issuer-fork", "issuer-pidfd", "issuer-gate-write", "issuer-output-read",
    "issuer-output-eof", "issuer-waitpid", "issuer-close", "issuer-crash",
    "retire-poll", "worker-waitpid", "supervisor-waitpid",
    "upload-report-open", "upload-report-read",
    "upload-report-fstat", "upload-report-close", "rmdir-after", "unlink-after:.owner.json",
    "unlink-after:report.json", "unlink-after:.authority.json",
}
REQUIRED_IO_MODES = {
    "authority-write": {"zero", "short", "interrupted"},
    "report-write": {"zero", "short", "interrupted"},
    "receipt-write": {"zero", "short", "interrupted"},
    "report-read": {"error", "short", "interrupted"},
    "waitpid": {"error", "wrong-child", "interrupted"},
}

class ModeledCrash(RuntimeError):
    pass

class VNode:
    next_inode = 1000
    def __init__(self, kind, raw=b"", role=""):
        self.kind = kind
        self.role = role
        self.raw = bytearray(raw)
        self.names = {}
        self.inode = VNode.next_inode
        VNode.next_inode += 1
        self.mode = (stat.S_IFDIR | 0o700) if kind == "directory" else (stat.S_IFREG | 0o600)

class CommonProcess:
    def __init__(self, pid):
        self.pid = pid
        self.live = True
        self.reaped = False
        self.start = 9000 + pid
        self.exited = threading.Event()
        self.thread = None
        self.error = None

MODEL_WAIT_SECONDS = 1.0

class SocketChannel:
    def __init__(self):
        self.queues = [[], []]
        self.closed = [False, False]
        self.condition = threading.Condition()

class CommonSocket:
    """Blocking seqpacket endpoint used by the unmodified production loops."""
    def __init__(self, kernel, fd, channel=None, side=0, connector=False):
        self.kernel = kernel
        self.fd = fd
        self.channel = channel
        self.side = side
        self.connector = connector
        self.role = "socket"
        self.listening = False
        self.pending = []
    def fileno(self):
        return self.fd
    def detach(self):
        value, self.fd = self.fd, -1
        return value
    def close(self):
        if self.fd >= 0:
            self.kernel.close(self.detach())
    def settimeout(self, seconds):
        del seconds
    def _cut(self, raw):
        role = "release-send" if raw == b"RELEASE" else "report-send" if raw.startswith(b"{") and not self.connector else "cleanup-request-send"
        return self.kernel.hit(role)
    def send(self, raw):
        if raw.startswith(b"{") and self.connector:
            self.kernel.authenticate_upload_ack(raw)
        if raw.startswith(b"{") and not self.connector:
            self.kernel.authenticate_private_terminal(raw)
        if self._cut(raw) == "short":
            return max(0, len(raw) - 1)
        if raw.startswith(b"{") and not self.connector and self.kernel.phase == "cleanup":
            for cut in ("clean-reply-send", "upload-ack-send", "private-capability-send"):
                if self.kernel.hit(cut) == "short":
                    return max(0, len(raw) - 1)
        # The portable threads begin at the post-fork entry points. Consume the
        # creator release gate here rather than exposing it as worker payload.
        if raw == b"RELEASE":
            return len(raw)
        if self.connector and self.kernel.hit("upload-ack-send") == "short":
            return max(0, len(raw) - 1)
        if self.connector and self.kernel.hit("private-capability-send") == "short":
            return max(0, len(raw) - 1)
        if raw == b"READY" and self.kernel.hit("ready-send") == "short":
            return 0
        if raw == b"PUBLISHED" and self.kernel.hit("published-send") == "short":
            return 0
        if raw.startswith(b"CLEAN:") and self.kernel.hit("clean-reply-send") == "short":
            return 0
        if raw == b"PUBLISHED":
            self.kernel.events.append("publication:report.json")
        if raw.startswith(b"CLEAN:"):
            self.kernel.events.append("upload:bytes-authenticated")
        channel = self.channel
        if channel is None:
            raise OSError(errno.ENOTCONN, "modeled unconnected socket")
        with channel.condition:
            channel.queues[1 - self.side].append((bytes(raw), ()))
            channel.condition.notify_all()
        return len(raw)
    def recv(self, bound):
        if self.kernel.hit("ready-recv") == "malformed":
            return b"BAD"
        channel = self.channel
        if channel is None:
            return b""
        wait_seconds = MODEL_WAIT_SECONDS if self.role == "custodian-cleanup-endpoint" else 5.0
        deadline = time.monotonic() + wait_seconds
        with channel.condition:
            while not channel.queues[self.side]:
                if (
                    channel.closed[1 - self.side]
                    or not self.kernel.current_process_live()
                    or time.monotonic() >= deadline
                ):
                    return b""
                channel.condition.wait(0.01)
            raw, _rights = channel.queues[self.side].pop(0)
            raw = raw[:bound]
        if raw == b"PUBLISHED" and self.kernel.hit("published-recv") == "lost":
            return b""
        if raw.startswith(b"CLEAN:") and self.kernel.hit("cleanup-reply-recv") == "lost":
            return b""
        if raw.startswith(b"CLEAN:") and self.kernel.hit("upload-ack-recv") == "lost":
            return b""
        if raw.startswith(b"CLEAN:") and self.kernel.hit("private-capability-recv") == "lost":
            return b""
        if raw.startswith(b"{") and self.connector:
            for cut in ("cleanup-reply-recv", "upload-ack-recv", "private-capability-recv"):
                if self.kernel.hit(cut) == "lost":
                    return b""
        return raw
    def sendmsg(self, buffers, ancillary):
        raw = b"".join(buffers)
        rights = []
        for level, kind, encoded in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for offset in range(0, len(encoded), struct.calcsize("i")):
                    descriptor = struct.unpack("i", encoded[offset:offset + struct.calcsize("i")])[0]
                    rights.append(self.kernel.fds[descriptor])
        self.kernel.events.append("private-capability:transferred")
        with self.channel.condition:
            self.channel.queues[1 - self.side].append((raw, tuple(rights)))
            self.channel.condition.notify_all()
        return len(raw)
    def recvmsg(self, bound, rights_bound):
        del rights_bound
        deadline = time.monotonic() + MODEL_WAIT_SECONDS
        with self.channel.condition:
            while (
                not self.channel.queues[self.side]
                and not self.channel.closed[1 - self.side]
                and self.kernel.current_process_live()
                and time.monotonic() < deadline
            ):
                self.channel.condition.wait(0.01)
            if not self.channel.queues[self.side]:
                return b"", [], 0, None
            raw, rights = self.channel.queues[self.side].pop(0)
        descriptors = [self.kernel.allocate(kind, value) for kind, value in rights]
        ancillary = [] if not descriptors else [(
            socket.SOL_SOCKET, socket.SCM_RIGHTS,
            b"".join(struct.pack("i", descriptor) for descriptor in descriptors),
        )]
        return raw[:bound], ancillary, 0, None
    def bind(self, name):
        self.connector = False
        self.role = "custodian-listener"
        if self.kernel.hit("listener-bind") == "error":
            raise OSError(errno.EADDRINUSE, "modeled listener bind")
        self.kernel.listeners[name] = self
    def listen(self, count):
        del count
        if self.kernel.hit("listener-listen") == "error":
            raise OSError(errno.EIO, "modeled listener listen")
        self.listening = True
    def accept(self):
        deadline = time.monotonic() + MODEL_WAIT_SECONDS
        with self.kernel.socket_condition:
            while (
                not self.pending
                and self.kernel.current_process_live()
                and time.monotonic() < deadline
            ):
                self.kernel.socket_condition.wait(0.01)
            if not self.pending:
                raise TimeoutError("modeled accept timeout")
            channel = self.pending.pop(0)
        endpoint = self.kernel.new_socket(channel=channel, side=1)
        endpoint.role = "custodian-cleanup-endpoint"
        return endpoint, None
    def connect(self, name):
        if self.kernel.hit("connect") == "lost":
            self.kernel.lose_custodian()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "custodian lost")
        listener = self.kernel.listeners.get(name)
        service = self.kernel.service_process or self.kernel.custodian
        if listener is None or service is None or not service.live:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "custodian exited")
        channel = SocketChannel()
        self.channel, self.side, self.connector = channel, 0, True
        self.role = "custodian-cleanup-endpoint"
        with self.kernel.socket_condition:
            listener.pending.append(channel)
            self.kernel.socket_condition.notify_all()
    def getsockopt(self, level, option, size):
        del level, option, size
        drift = self.kernel.hit("peer-credentials") == "drift"
        if self.connector:
            pid = self.kernel.service_process.pid
        else:
            pid = self.kernel.parent_pid
        uid = self.kernel.euid + 1 if drift else self.kernel.euid
        return __import__("struct").pack("3i", pid, uid, self.kernel.egid)

class CommonPoll:
    def __init__(self, kernel):
        self.kernel = kernel
        self.fd = -1
    def register(self, fd, flags):
        del flags
        self.fd = fd
    def poll(self, milliseconds):
        if self.kernel.hit("retire-poll") == "timeout":
            return []
        process = self.kernel.pidfd_process(self.fd)
        process.exited.wait(milliseconds / 1000)
        return [(self.fd, 1)] if not process.live else []

class CommonKernel:
    def __init__(self, common, row):
        self.common = common
        self.row = row
        self.spec = row["primitive_fault"]
        self.events = []
        self.consumed = set()
        self.next_fd = 40
        self.parent_pid = 1
        self.local = threading.local()
        self.local.pid = self.parent_pid
        self.fd_tables = {self.parent_pid: {}}
        self.offset_tables = {self.parent_pid: {}}
        self.root = VNode("directory", role="report-parent")
        self.capability = b"K" * 32
        self.euid = 1000
        self.egid = 1000
        self.next_pid = 700
        self.custodian = None
        self.processes = {}
        self.service_process = None
        self.transaction = None
        self.clean_reply = b""
        self.upload_tainted = False
        self.upload_ack = None
        self.context = None
        self.observe_count = 0
        self.baseline_fds = set()
        self.phase = "startup"
        self.temporary_count = 0
        self.sync_counts = {}
        self.last_namespace_effect = None
        self.pending_namespace_effects = []
        self.listeners = {}
        self.socket_condition = threading.Condition()
        self.threads = []
    @property
    def pid(self):
        return getattr(self.local, "pid", self.parent_pid)
    @property
    def fds(self):
        return self.fd_tables[self.pid]
    def current_process_live(self):
        process = self.processes.get(self.pid)
        return process is None or process.live
    @property
    def offsets(self):
        return self.offset_tables[self.pid]
    def hit(self, cut):
        if self.spec["cut"] != cut or self.row["id"] in self.consumed:
            return None
        self.consumed.add(self.row["id"])
        self.events.append(f"fault:{self.row['id']}")
        return self.spec["mode"]
    def allocate(self, kind, value):
        while self.next_fd in self.fds:
            self.next_fd += 1
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = (kind, value)
        self.offsets[fd] = 0
        return fd
    def close(self, fd):
        if fd not in self.fds:
            raise OSError(errno.EBADF, "modeled closed fd")
        kind, value = self.fds[fd]
        role = value.role if kind in {"file", "directory", "socket"} else kind
        close_before = None
        if role != "pidfd" or (self.phase == "cleanup" and self.pid == self.parent_pid):
            close_before = self.hit(f"close-before:{role}")
        if close_before == "error":
            raise OSError(errno.EIO, f"modeled {role} close before effect")
        kind, value = self.fds.pop(fd)
        self.offsets.pop(fd, None)
        if kind == "socket" and value.channel is not None:
            retained = any(
                item_kind == "socket" and item.channel is value.channel and item.side == value.side
                for table in tuple(self.fd_tables.values())
                for item_kind, item in tuple(table.values())
            )
            if not retained:
                with value.channel.condition:
                    value.channel.closed[value.side] = True
                    value.channel.condition.notify_all()
        if self.phase == "upload" and role == "report" and self.hit("upload-report-close") == "after-error":
            raise OSError(errno.EIO, "modeled upload report close after effect")
        retained_name = {
            "authority": ".authority.json",
            "receipt": ".owner.json",
            "report": "report.json",
        }.get(role)
        if retained_name is not None and self.hit(f"close:retained:{retained_name}") == "after-error":
            raise OSError(errno.EIO, f"modeled retained {retained_name} close after effect")
        if self.hit(f"close:{role}") == "after-error":
            raise OSError(errno.EIO, f"modeled {role} close after effect")
        if kind == "socket" and role == "custodian-cleanup-endpoint" and self.custodian is not None and self.pid == self.custodian.pid:
            if self.hit("private-capability-close") == "after-error":
                raise OSError(errno.EIO, "private capability close after effect")
        if kind == "pidfd" and self.phase == "cleanup" and self.hit("pidfd-close") == "after-error":
            raise OSError(errno.EIO, "pidfd close after effect")
    def status(self, node):
        return SimpleNamespace(
            st_mode=node.mode, st_uid=self.euid, st_gid=self.egid,
            st_dev=8, st_ino=node.inode, st_nlink=1, st_size=len(node.raw),
            st_mtime_ns=node.inode * 10, st_ctime_ns=node.inode * 10,
            st_rdev=0,
        )
    def node_for_path(self, path, dir_fd=None):
        name = str(path)
        if dir_fd is None:
            if name in {"/tmp", str(self.common.ROOT)}:
                return self.root
            leaf = Path(name).name
            return self.root.names.get(leaf)
        directory = self.fds[dir_fd][1]
        if name == ".":
            return directory
        return directory.names.get(name)
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        temporary_mask = getattr(os, "O_TMPFILE", 0)
        temporary = bool(temporary_mask and flags & temporary_mask == temporary_mask)
        if temporary:
            roles = ("authority", "report", "receipt")
            role = roles[self.temporary_count] if self.temporary_count < len(roles) else "extra"
            self.temporary_count += 1
            if self.hit(f"{role}-allocate") == "error":
                raise OSError(errno.EMFILE, f"modeled {role} allocation")
            return self.allocate("file", VNode("file", role=role))
        node = self.node_for_path(path, dir_fd)
        if node is None:
            raise FileNotFoundError(str(path))
        if self.phase == "upload" and node.role == "report" and self.hit("upload-report-open") == "error":
            raise OSError(errno.EIO, "modeled upload report open")
        return self.allocate(node.kind, node)
    def mkdir(self, name, mode=0o700, *, dir_fd=None):
        del mode
        parent = self.root if dir_fd is None else self.fds[dir_fd][1]
        if name in parent.names:
            raise FileExistsError(name)
        parent.names[str(name)] = VNode("directory", role="report-directory")
        if self.hit("directory-create") == "after-crash" or self.hit("recovery:directory") == "crash":
            raise ModeledCrash("after report directory creation")
    def fsync(self, fd):
        if fd not in self.fds:
            raise OSError(errno.EBADF, "fsync")
        role = self.fds[fd][1].role or self.fds[fd][0]
        count = self.sync_counts.get(role, 0) + 1
        self.sync_counts[role] = count
        cut = f"{role}-fsync-{count}"
        mutation = self.hit(cut)
        if mutation == "interrupted":
            raise InterruptedError(errno.EINTR, f"modeled {role} fsync")
        if mutation == "error":
            raise OSError(errno.EIO, f"modeled {role} fsync")
        if role == "report-parent" and self.hit(f"directory-fsync-{count}") == "error":
            raise OSError(errno.EIO, "modeled report parent fsync")
        if self.phase == "cleanup" and role == "report-parent" and self.hit("recovery:parent-fsync") == "crash":
            raise ModeledCrash("recovery crash after parent fsync")
        for effect in tuple(self.pending_namespace_effects):
            cleanup = self.hit(effect)
            if cleanup == "interrupted":
                raise InterruptedError(errno.EINTR, "modeled cleanup fsync")
            if cleanup == "error":
                raise OSError(errno.EIO, "modeled cleanup fsync")
    def fstat(self, fd):
        node = self.fds[fd][1]
        value = self.status(node)
        if self.phase == "upload" and node.role == "report" and self.hit("upload-report-fstat") == "drift":
            value.st_ctime_ns += 1
        return value
    def stat_path(self, path, *, dir_fd=None, follow_symlinks=False):
        del follow_symlinks
        self.events.append(f"stat:{path}:{dir_fd}")
        node = self.node_for_path(path, dir_fd)
        if node is None:
            raise FileNotFoundError(str(path))
        return self.status(node)
    def lexists(self, path):
        return self.node_for_path(path) is not None
    def write(self, fd, raw):
        node = self.fds[fd][1]
        mutation = self.hit(f"{node.role}-write")
        if mutation == "interrupted":
            raise InterruptedError(errno.EINTR, f"modeled {node.role} write")
        if mutation == "zero":
            return 0
        if mutation == "short":
            raw = raw[:max(1, len(raw) // 2)]
        offset = self.offsets[fd]
        end = offset + len(raw)
        if end > len(node.raw):
            node.raw.extend(b"\0" * (end - len(node.raw)))
        node.raw[offset:end] = raw
        self.offsets[fd] = end
        if mutation == "after-crash":
            raise ModeledCrash(f"modeled {node.role} write crash")
        return len(raw)
    def read(self, fd, size):
        node = self.fds[fd][1]
        upload_mutation = self.hit("upload-report-read") if self.phase == "upload" and node.role == "report" else None
        mutation = upload_mutation or self.hit(f"{node.role}-read")
        if mutation == "interrupted":
            raise InterruptedError(errno.EINTR, f"modeled {node.role} read")
        if mutation == "error":
            raise OSError(errno.EIO, f"modeled {node.role} read")
        if mutation == "short":
            size = max(1, size // 2)
        offset = self.offsets[fd]
        value = bytes(node.raw[offset:offset + size])
        self.offsets[fd] += len(value)
        return value
    def lseek(self, fd, offset, whence):
        del whence
        node = self.fds[fd][1]
        if self.hit(f"{node.role}-lseek") == "error":
            raise OSError(errno.EIO, f"modeled {node.role} lseek")
        self.offsets[fd] = offset
        return offset
    def unlink(self, name, *, dir_fd=None):
        directory = self.fds[dir_fd][1]
        if isinstance(name, bytes):
            name = name.decode()
        if self.hit(f"unlink:{name}") == "error":
            raise OSError(errno.EIO, f"modeled unlink {name}")
        if name not in directory.names:
            raise FileNotFoundError(name)
        del directory.names[name]
        publication_names = {".authority.json", ".owner.json", ".report.stage", "report.json"}
        if name in publication_names and not directory.names and self.hit("recovery:final-unlink") == "crash":
            raise ModeledCrash("recovery crash after final unlink")
        self.last_namespace_effect = f"cleanup-directory-fsync:{name}"
        self.pending_namespace_effects.append(self.last_namespace_effect)
        if self.hit(f"unlink-after:{name}") == "crash":
            raise ModeledCrash(f"modeled unlink {name} crash")
    def rmdir(self, name, *, dir_fd=None):
        parent = self.root if dir_fd is None else self.fds[dir_fd][1]
        if self.hit("rmdir") == "error":
            raise OSError(errno.EIO, "modeled rmdir")
        node = parent.names[name]
        if node.names:
            raise OSError(errno.ENOTEMPTY, "directory not empty")
        del parent.names[name]
        self.last_namespace_effect = "cleanup-parent-fsync"
        self.pending_namespace_effects.append(self.last_namespace_effect)
        if self.hit("rmdir-after") == "crash":
            raise ModeledCrash("modeled rmdir crash")
        if self.hit("recovery:rmdir") == "crash":
            raise ModeledCrash("recovery crash after rmdir")
    def enumerate(self, descriptor, numeric):
        del numeric
        node = self.fds[descriptor][1]
        return tuple(sorted(node.names))
    def link(self, descriptor, directory_fd, name):
        node = self.fds[descriptor][1]
        directory = self.fds[directory_fd][1]
        decoded = name.decode()
        if decoded in directory.names:
            raise FileExistsError(decoded)
        directory.names[decoded] = node
        cut = {
            ".authority.json": "authority-link",
            ".report.stage": "report-stage-link",
            ".owner.json": "receipt-link",
        }.get(decoded)
        if cut and self.hit(cut) == "after-crash":
            raise ModeledCrash(f"after {decoded} link")
        recovery = {
            ".authority.json": "recovery:authority",
            ".report.stage": "recovery:report-stage",
            ".owner.json": "recovery:receipt",
        }.get(decoded)
        if recovery and self.hit(recovery) == "crash":
            raise ModeledCrash(f"recovery crash after {decoded}")
    def rename(self, directory_fd, source, target, flags, target_fd=None):
        source_directory = self.fds[directory_fd][1]
        target_directory = source_directory if target_fd is None else self.fds[target_fd][1]
        if self.hit("directory-exchange") == "exchange":
            raise OSError(errno.ESTALE, "modeled directory exchange")
        rename_mutation = self.hit("report-rename") if target == b"report.json" else None
        if rename_mutation in {"error", "exchange"}:
            raise OSError(errno.EIO, "modeled report rename")
        source_name, target_name = source.decode(), target.decode()
        if flags == 2:
            source_node = source_directory.names[source_name]
            target_node = target_directory.names[target_name]
            source_directory.names[source_name] = target_node
            target_directory.names[target_name] = source_node
        else:
            if target_name in target_directory.names:
                raise FileExistsError(target_name)
            target_directory.names[target_name] = source_directory.names.pop(source_name)
        if target_name == "report.json" and rename_mutation == "after-crash":
            raise ModeledCrash("after report rename")
        if target_name == "report.json" and self.hit("recovery:report") == "crash":
            raise ModeledCrash("recovery crash after report rename")
        if target_name.endswith(".retired") or target_name.startswith(".cogs-nq-"):
            if self.hit("replace:retired-directory") == "same-name":
                replacement = VNode("directory", role="foreign-retired")
                replacement.names["foreign-sentinel"] = VNode("file", b"foreign", "foreign-sentinel")
                target_directory.names[target_name] = replacement
            if self.hit("quarantine-rename") == "after-crash":
                raise ModeledCrash("after retained quarantine rename")
    def new_socket(self, channel=None, side=0, connector=False):
        fd = self.allocate("socket", None)
        endpoint = CommonSocket(self, fd, channel, side, connector)
        self.fds[fd] = ("socket", endpoint)
        return endpoint
    def socketpair(self, family, kind):
        del family, kind
        if self.hit("socketpair") == "error":
            raise OSError(errno.EMFILE, "custodian socketpair")
        channel = SocketChannel()
        left = self.new_socket(channel, 0)
        right = self.new_socket(channel, 1)
        self.last_socketpair = (left.fd, right.fd)
        return left, right
    def socket(self, family=None, kind=None, fileno=None):
        del family, kind
        if fileno is not None:
            endpoint = self.fds[fileno][1]
            if self.service_process is not None and self.pid == self.service_process.pid:
                creator = self.custodian
                if creator is not None and fileno == creator.control_fd:
                    endpoint.role = "custodian-worker-control"
            return endpoint
        return self.new_socket(connector=True)
    def _run_process(self, process, target):
        self.local.pid = process.pid
        try:
            target()
        except BaseException as error:
            process.error = error
            self.events.append(f"child-error:{process.pid}:{type(error).__name__}:{error}")
        finally:
            for fd in tuple(self.fds):
                try:
                    self.close(fd)
                except BaseException:
                    pass
            process.live = False
            process.exited.set()
            with self.socket_condition:
                self.socket_condition.notify_all()
    def _spawn(self, process, target):
        thread = threading.Thread(target=self._run_process, args=(process, target),
                                  name=f"portable-custodian-{process.pid}", daemon=True)
        thread.start()
        process.thread = thread
        self.threads.append(thread)
    def fork(self):
        if self.hit("custodian-fork") == "error":
            raise OSError(errno.EAGAIN, "modeled custodian fork")
        creator_pid = self.pid
        process = CommonProcess(self.next_pid)
        self.next_pid += 1
        self.processes[process.pid] = process
        child_fds = {}
        for fd, (kind, value) in self.fds.items():
            if kind == "socket":
                child_endpoint = CommonSocket(
                    self, fd, value.channel, value.side, value.connector,
                )
                child_endpoint.role = value.role
                child_endpoint.listening = value.listening
                child_endpoint.pending = value.pending
                child_fds[fd] = (kind, child_endpoint)
            else:
                child_fds[fd] = (kind, value)
        self.fd_tables[process.pid] = child_fds
        self.offset_tables[process.pid] = dict(self.offsets)
        left_fd, right_fd = self.last_socketpair
        if creator_pid == self.parent_pid:
            self.custodian = process
            process.control_fd = right_fd
            def supervisor():
                self.close(left_fd)
                self.events.append("child-loop:_custodian_main")
                self.common._custodian_main(right_fd, self.context, self.capability)
            self._spawn(process, supervisor)
        else:
            creator = self.processes[creator_pid]
            self.service_process = process
            if not creator.live:
                process.live = False
                process.exited.set()
            def worker():
                self.close(left_fd)
                gate = self.socket(fileno=right_fd)
                if gate.recv(1) != b"G":
                    raise self.common.QualificationError("modeled worker gate")
                self.events.append("child-loop:_custodian_worker")
                self.common._custodian_worker(creator.control_fd, self.context, self.capability, gate.detach())
            self._spawn(process, worker)
        return process.pid
    def pidfd_open(self, pid, flags=0):
        del flags
        process = self.processes.get(pid)
        if self.phase == "startup" and self.hit("startup-pidfd") == "error":
            raise OSError(errno.EIO, "startup pidfd")
        if self.phase == "cleanup" and self.hit("retire-pidfd") == "secondary":
            raise OSError(errno.EIO, "secondary pidfd failure with live custodian")
        if process is None:
            raise ProcessLookupError(pid)
        return self.allocate("pidfd", process)
    def pidfd_process(self, fd):
        return self.fds[fd][1]
    def signal_process(self, pidfd, number):
        del number
        process = self.pidfd_process(pidfd)
        process.live = False
        process.exited.set()
        if process is self.custodian and self.service_process is not None:
            self.service_process.live = False
            self.service_process.exited.set()
        self.events.append("custodian:signal")
    def kill(self, pid, number):
        del number
        process = self.processes.get(pid)
        if process is not None:
            process.live = False
            process.exited.set()
            if process is self.custodian and self.service_process is not None:
                self.service_process.live = False
                self.service_process.exited.set()
            self.events.append("custodian:signal")
    def waitpid(self, pid, flags):
        del flags
        process = self.processes.get(pid)
        role = "worker" if process is self.service_process else "supervisor"
        mutation = self.hit(f"{role}-waitpid") or self.hit("waitpid")
        if mutation == "error":
            raise ChildProcessError("modeled waitpid failure")
        if mutation == "interrupted":
            raise InterruptedError(errno.EINTR, "modeled waitpid interruption")
        if mutation == "wrong-child":
            return pid + 1, 0
        if process is None or process.live:
            return 0, 0
        process.reaped = True
        self.events.append("custodian:reaped")
        return pid, 0 if process.error is None else 1 << 8
    def lose_custodian(self):
        process = self.service_process or self.custodian
        if process is not None:
            process.live = False
            process.exited.set()
    def mutation_watch(self, registry, directory):
        del directory
        raw = b"mutation" if self.upload_tainted else b""
        self.watch_node = VNode("file", raw, "uploaded-generation-watch")
        return registry.open(
            "uploaded-generation-watch",
            lambda: self.allocate("file", self.watch_node),
        )
    def perform_upload(self):
        registry, parent, directory = self.common._open_report_directory(self.context.job, False)
        try:
            digest, size, generation = self.common._file_digest_at(
                directory, "report.json", self.common.REPORT_LIMIT,
            )
            self.upload_ack = {
                "report_sha256": digest,
                "report_size": size,
                "report_generation": generation,
            }
            self.events.append("upload:generation-acknowledged")
        finally:
            registry.close_reverse(None, [directory, parent])
    def authenticate_upload_ack(self, raw):
        value = json.loads(raw)
        acknowledgment = value.get("upload") if type(value) is dict else None
        if type(acknowledgment) is not dict:
            raise self.common.QualificationError("exact upload acknowledgment missing")
        expected = self.upload_ack
        if expected is None:
            raise self.common.QualificationError("upload generation was not acknowledged")
        exact = {**expected, "artifact_id": 7, "artifact_sha256": "a" * 64}
        for claim in ("digest", "size", "generation"):
            mutation = self.hit(f"upload-ack-{claim}")
            key = {"digest": "report_sha256", "size": "report_size", "generation": "report_generation"}[claim]
            if mutation == "wrong" or acknowledgment.get(key) != exact[key]:
                raise self.common.QualificationError(f"upload acknowledgment {claim}")
        if acknowledgment != exact:
            raise self.common.QualificationError("closed upload acknowledgment")
        self.events.append("upload:ack-authenticated")
    def authenticate_private_terminal(self, raw):
        value = json.loads(raw)
        if type(value) is not dict or "capability" not in value:
            return
        capability = value.get("capability")
        if self.hit("upload-ack-capability") in {"missing", "replay"}:
            capability = None
        if not hmac.compare_digest(str(capability), self.capability.hex()):
            raise self.common.QualificationError("private terminal capability")
        if value.get("waitpid_reaped") != value.get("custodian_pid"):
            raise self.common.QualificationError("terminal waitpid receipt")
        self.events.extend(("private-capability:authenticated", "upload:bytes-authenticated"))
    def mutate_named(self, name, transform):
        directory = self.root.names[self.common.report_path(self.context.job).parent.name]
        directory.names[name].raw[:] = transform(bytes(directory.names[name].raw))
    def apply_same_name_replacement(self):
        cut = self.spec["cut"]
        if not cut.startswith("replace:") or self.spec["mode"] != "same-name":
            return
        role = cut.split(":", 1)[1]
        if role == "retired-directory":
            return
        active = self.common.report_path(self.context.job).parent.name
        if role == "active-directory":
            self.hit(cut)
            replacement = VNode("directory", role="foreign-active")
            replacement.names["foreign-sentinel"] = VNode("file", b"foreign", "foreign-sentinel")
            self.root.names[active] = replacement
            return
        names = {"authority": ".authority.json", "report": "report.json", "receipt": ".owner.json"}
        directory = self.root.names[active]
        self.hit(cut)
        directory.names[names[role]] = VNode("file", b"foreign", f"foreign-{role}")
    def driver_exit(self, client):
        for lease in (client.control, client.pidfd):
            if lease.state is self.common.FdState.OWNED and lease.number in self.fds:
                try:
                    lease.close()
                except BaseException:
                    pass
    def crash_close(self):
        for fd in tuple(self.fds):
            kind, _value = self.fds.get(fd, (None, None))
            if kind not in ("pidfd",):
                self.fds.pop(fd, None)
                self.offsets.pop(fd, None)
    def audit(self, disposition):
        children = tuple(
            process for process in (self.service_process, self.custodian)
            if process is not None
        )
        if disposition == "restored":
            for process in children:
                if process.thread is not None:
                    process.thread.join(MODEL_WAIT_SECONDS + 1)
                    if process.thread.is_alive():
                        raise AssertionError(f"{self.row['id']}: custodian child loop remains live")
                if process.live:
                    raise AssertionError(f"{self.row['id']}: custodian child remains live")
        active = self.common.report_path(self.context.job).parent.name
        retired = self.common._retired_report_path(self.context.job).name
        active_present = active in self.root.names
        retired_present = retired in self.root.names
        present = active_present or retired_present
        if disposition == "restored":
            if active_present:
                inventories = {name: sorted(node.names) for name, node in self.root.names.items()}
                raise AssertionError(f"{self.row['id']}: exact quarantine missing: {inventories} events={self.events}")
            if retired_present:
                raise AssertionError(f"{self.row['id']}: retained quarantine is not a restored baseline")
            if children:
                reap_fault = self.spec["cut"] in {"retire-poll", "waitpid", "worker-waitpid", "supervisor-waitpid"}
                if not any(process.reaped for process in children) and not reap_fault:
                    raise AssertionError(f"{self.row['id']}: authority child was not waitpid-reaped")
                if any(process.reaped for process in children) and "custodian:reaped" not in self.events:
                    raise AssertionError(f"{self.row['id']}: fictitious reap oracle")
            self.events.append("cleanup:restored")
        else:
            if not present:
                raise AssertionError(f"{self.row['id']}: unproved report was deleted")
            self.events.append("cleanup:preserved")

class CommonOps:
    def __init__(self, common, kernel):
        self.common = common
        self.kernel = kernel
        self.fds = common.FdRegistry(kernel.close)
        self.source_set_sha256 = kernel.production_result["source_set_sha256"]
        self.before = {name: (None, name) for name in common.CLEANUP_KEYS}
        self.before["paths"] = (None, None, None)
    def observe(self, context):
        del context
        self.kernel.observe_count += 1
        value = dict(self.before)
        if self.kernel.observe_count > 1 and self.kernel.hit("observe-after") == "drift":
            value["descriptors"] = ("drift",)
        return value
    def run_fixed_operation(self, context, operation):
        if self.kernel.spec["stage"] == "issuer":
            return _common_support.run_issuer_fault(
                self.common, self.kernel, context, patched, VNode, CommonProcess, ModeledCrash,
            )
        if self.kernel.hit("operation") == "error":
            raise OSError(errno.EIO, "modeled production operation")
        if operation != "integration":
            raise AssertionError("common operation profile drift")
        self.kernel.events.append("session:operation")
        return dict(self.kernel.production_result)

def load_final_common():
    spec = importlib.util.spec_from_file_location("outcome_two_final_common", FINAL_COMMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    required = {"_retired_report_path", "_publish_transaction", "_cleanup_owned", "OperationReceipt"}
    if not required <= set(module.__dict__):
        raise AssertionError("final common API is not available")
    for name, value in {
        "O_TMPFILE": 0x410000, "O_DIRECTORY": 0x100000, "O_CLOEXEC": 0x1000000,
        "O_NOFOLLOW": 0x20000,
    }.items():
        if not hasattr(module.os, name):
            setattr(module.os, name, value)
    for name, value in {"SOCK_CLOEXEC": 0x10000000, "SO_PEERCRED": 17}.items():
        if not hasattr(module.socket, name):
            setattr(module.socket, name, value)
    if "BaseExceptionGroup" not in module.__dict__:
        class BaseExceptionGroup(Exception):
            def __init__(self, message, exceptions):
                self.exceptions = tuple(exceptions)
                super().__init__(message)
        module.BaseExceptionGroup = BaseExceptionGroup
    builtins = __import__("builtins")
    if not hasattr(builtins, "ExceptionGroup"):
        builtins.ExceptionGroup = module.BaseExceptionGroup
    return module

def common_context(common):
    head = "0" * 40
    return common.WorkflowContext(
        "integration", "owner/repository", "owner/repository", head, head, head, "refs/heads/main", "main",
        common.JOB_IDS["integration"], 42, 1, True, "20260728.1", "6.8.0-test", "x86_64",
        common._sha256(common.WORKFLOW),
        common._sha256(common.COMMON.parent / common.DRIVERS["integration"]),
        common._sha256(common.COMMON),
        common._sha256(common.SCHEMA),
        common.SCHEMA.read_bytes(),
    )

@contextmanager
def common_patches(common, kernel):
    original_registry = common.FdRegistry
    original_sha256 = common._sha256
    original_publish = common._publish_transaction
    admitted_sources = {
        path: original_sha256(path)
        for path in (common.WORKFLOW, common.COMMON, common.COMMON.parent / common.DRIVERS["integration"])
    }
    registry_factory = lambda *_args, **_kwargs: original_registry(kernel.close)
    def observed_publish(context, capability, raw, supervisor_fd=None):
        kernel.transaction = True
        transaction = original_publish(context, capability, raw, supervisor_fd)
        kernel.transaction = transaction
        return transaction
    def admitted_sha256(path):
        if path == common.SCHEMA:
            raise FileNotFoundError(str(path))
        if path in admitted_sources:
            return admitted_sources[path]
        return original_sha256(path)
    with patched(
        common.os,
        open=kernel.open,
        close=kernel.close,
        mkdir=kernel.mkdir,
        fsync=kernel.fsync,
        fstat=kernel.fstat,
        stat=kernel.stat_path,
        write=kernel.write,
        read=kernel.read,
        lseek=kernel.lseek,
        unlink=kernel.unlink,
        rmdir=kernel.rmdir,
        geteuid=lambda: kernel.euid,
        getegid=lambda: kernel.egid,
        getpid=lambda: kernel.pid,
        urandom=lambda size: kernel.capability[:size],
        fork=kernel.fork,
        pidfd_open=kernel.pidfd_open,
        kill=kernel.kill,
        waitpid=kernel.waitpid,
    ), patched(common.os.path, lexists=kernel.lexists), patched(
        common.Path, exists=lambda path: kernel.lexists(path),
    ), patched(
        common.socket, socketpair=kernel.socketpair, socket=kernel.socket,
    ), patched(common.signal, pidfd_send_signal=kernel.signal_process), patched(
        common.select, poll=lambda: CommonPoll(kernel),
    ), patched(
        common,
        FdRegistry=registry_factory,
        _rename=kernel.rename,
        _link_held=kernel.link,
        _enumerate_directory=kernel.enumerate,
        _process_start=lambda pid: kernel.processes[pid].start,
        _sha256=admitted_sha256,
        _publish_transaction=observed_publish,
        _mutation_watch=kernel.mutation_watch,
    ):
        yield original_registry

def common_error_code(error):
    return type(error).__name__ if error is not None else "OK"

def run_common_row(common, row, production_result):
    kernel = CommonKernel(common, row)
    kernel.production_result = production_result
    context = common_context(common)
    kernel.context = context
    error = None
    with common_patches(common, kernel) as registry_type:
        try:
            if row["id"] in {"retire-exact-waitable-reap", "retire-supervisor-waitpid-failure"}:
                process = CommonProcess(999)
                kernel.custodian = process
                kernel.processes[process.pid] = process
                pidfd = registry_type(kernel.close).adopt(kernel.allocate("pidfd", process), "direct-pidfd")
                if row["id"] == "retire-exact-waitable-reap":
                    kernel.hit("reap-probe")
                failures = []
                common._retire_child(process.pid, pidfd, failures, terminate=True)
                if failures:
                    raise common.BaseExceptionGroup("direct retirement", failures)
            else:
                registry = registry_type(kernel.close)
                try:
                    client = common._start_custodian(context, registry)
                except BaseException as startup_error:
                    if row["primitive_fault"]["stage"] == "startup":
                        raise
                    raise AssertionError(f"unexpected custodian startup failure: {startup_error!r}") from startup_error
                kernel.phase = "session"
                ops = CommonOps(common, kernel)
                session = common.NativeSession._begin_with_ops(context, ops, client)
                try:
                    session.run_fixed_operation("integration")
                    evidence = session.settle_native_phase()
                    kernel.events.append("session:settled" if evidence.restored else "session:settled-false")
                    session.publish(common.ReportCandidate())
                except BaseException as primary:
                    error = primary
                if kernel.transaction is not None:
                    kernel.driver_exit(client)
                    kernel.phase = "upload"
                    try:
                        kernel.perform_upload()
                    except BaseException as upload_error:
                        if error is None:
                            error = upload_error
                if isinstance(error, ModeledCrash) or any(event == "crash:classified" for event in kernel.events):
                    kernel.crash_close()
                stage = row["primitive_fault"]["stage"]
                if stage == "publish":
                    kernel.events.append("crash:classified")
                if kernel.transaction is not None or kernel.lexists(common.report_path("integration").parent):
                    if stage == "upload" and row["primitive_fault"]["cut"] == "report-bytes":
                        kernel.hit("report-bytes")
                        kernel.mutate_named("report.json", lambda raw: raw + b"x")
                    if stage == "upload" and row["primitive_fault"]["cut"] == "receipt-bytes":
                        kernel.hit("receipt-bytes")
                        def corrupt(raw):
                            value = json.loads(raw)
                            value["schema_sha256"] = "0" * 64
                            return common._canonical(value, True)
                        kernel.mutate_named(".owner.json", corrupt)
                    if stage == "upload" and row["primitive_fault"]["cut"] == "upload-exchange":
                        kernel.hit("upload-exchange")
                        kernel.upload_tainted = True
                        if hasattr(kernel, "watch_node"):
                            kernel.watch_node.raw[:] = b"mutation"
                        kernel.events.extend(("upload:generation-exchanged", "upload:generation-restored"))
                    if stage == "upload" and row["primitive_fault"]["cut"] == "authority-resign":
                        kernel.hit("authority-resign")
                        fake = b"F" * 32
                        def resign_authority(raw):
                            value = json.loads(raw)
                            value["capability_sha256"] = hashlib.sha256(fake).hexdigest()
                            return common._canonical(value, True)
                        def resign_receipt(raw):
                            value = json.loads(raw)
                            value["capability_sha256"] = hashlib.sha256(fake).hexdigest()
                            value.pop("authentication_sha256")
                            value["authentication_sha256"] = hmac.new(fake, common._canonical(value), hashlib.sha256).hexdigest()
                            return common._canonical(value, True)
                        kernel.mutate_named(".authority.json", resign_authority)
                        kernel.mutate_named(".owner.json", resign_receipt)
                    if stage == "recovery":
                        kernel.apply_same_name_replacement()
                    environment = {
                        "LC_ALL": "C", "NQ_CLEANUP_RUN_ID": "42", "NQ_CLEANUP_RUN_ATTEMPT": "1",
                        "NQ_CLEANUP_HEAD_SHA": "a" * 40 if kernel.hit("cleanup-head") == "wrong" else context.head_sha,
                        "NQ_UPLOAD_ARTIFACT_ID": "7", "NQ_UPLOAD_ARTIFACT_SHA256": "a" * 64,
                    }
                    kernel.phase = "cleanup"
                    with patched(common.os, environ=environment):
                        try:
                            common.cleanup_report("integration")
                        except BaseException as cleanup_error:
                            kernel.events.append(f"cleanup-error:{type(cleanup_error).__name__}:{cleanup_error}")
                            if error is None or row["primitive_fault"]["disposition"] == "preserved":
                                error = cleanup_error
                            if row["primitive_fault"]["cut"] == "report-bytes":
                                kernel.events.append("upload:bytes-rejected")
                            if row["primitive_fault"]["cut"] == "receipt-bytes":
                                kernel.events.append("receipt:authentication-rejected")
                            cut = row["primitive_fault"]["cut"]
                            if cut in {"upload-exchange", "authority-resign", "upload-ack-capability"}:
                                kernel.events.append("private-authority:rejected")
                            if cut in {"upload-ack-digest", "upload-ack-size", "upload-ack-generation"}:
                                kernel.events.append("upload:ack-rejected")
                            if cut.startswith("replace:"):
                                kernel.events.append("replacement:preserved")
                        recovery_cut = row["primitive_fault"]["mode"] == "crash"
                        recovery_cut = recovery_cut and row["primitive_fault"]["stage"] == "recovery"
                        if recovery_cut and row["id"] in kernel.consumed:
                            for event in ("recovery:restarted", "recovery:idempotent"):
                                try:
                                    common.cleanup_report("integration")
                                except ConnectionRefusedError:
                                    pass
                                kernel.events.append(event)
        except BaseException as caught:
            error = caught
        finally:
            cursor = 0
            while cursor < len(kernel.threads):
                kernel.threads[cursor].join(MODEL_WAIT_SECONDS + 1)
                cursor += 1
            live_threads = [thread.name for thread in kernel.threads if thread.is_alive()]
            if live_threads and error is None:
                error = AssertionError(f"modeled child loops exceeded bound: {live_threads}")
    if row["primitive_fault"]["cut"] == "none":
        kernel.consumed.add(row["id"])
    observed = common_error_code(error)
    intended = row["intended_code"]
    exact_code = observed == intended or intended == "REJECT" and error is not None
    if not exact_code:
        raise AssertionError(f"{row['id']}: expected {intended}, got {observed}: {error!r}/{getattr(error, 'exceptions', ())!r}, events={kernel.events}")
    expected_accept = row["primitive_fault"]["expect"] == "accept"
    if (error is None) != expected_accept:
        raise AssertionError(f"{row['id']}: exact oracle contradicted expectation")
    if kernel.consumed != {row["id"]}:
        raise AssertionError(f"{row['id']}: selected cut did not fire exactly")
    kernel.audit(row["primitive_fault"]["disposition"])
    cursor = -1
    for event in row["sentinel"]:
        try:
            cursor = kernel.events.index(event, cursor + 1)
        except ValueError as missing:
            raise AssertionError(f"{row['id']}: missing ordered event {event}: {kernel.events}") from missing
    return kernel

def common_production_matrix():
    common = load_final_common()
    spec = importlib.util.spec_from_file_location(
        "outcome_two_trusted_launcher_receipt",
        ROOT / "test/outcome-two-trusted-launcher-portable.py",
    )
    trusted = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = trusted
    spec.loader.exec_module(trusted)
    production_result = trusted.production_runtime_compression_contracts(
        trusted.load_module(),
    )
    records = [json.loads(line) for line in COMMON_FIXTURE.read_text().splitlines()]
    header, *rows = records
    fields = {"id", "production_method", "primitive_fault", "intended_code", "cleanup_domains", "sentinel"}
    if set(header) != {"type", "version", "acceptance_ids", "case_fields"}:
        raise AssertionError("common custodian fixture header shape")
    if header["version"] != "cogs.outcome-two-common-custodian/v3" or set(header["case_fields"]) != fields:
        raise AssertionError("common custodian fixture header")
    cuts = {row["primitive_fault"]["cut"] for row in rows}
    if not REQUIRED_COMMON_CUTS <= cuts:
        raise AssertionError(f"common primitive cut inventory missing: {REQUIRED_COMMON_CUTS - cuts}")
    modes = {}
    for row in rows:
        modes.setdefault(row["primitive_fault"]["cut"], set()).add(row["primitive_fault"]["mode"])
    for cut, required_modes in REQUIRED_IO_MODES.items():
        if not required_modes <= modes.get(cut, set()):
            raise AssertionError(f"common primitive modes missing: {cut}/{required_modes - modes.get(cut, set())}")
    crash_rows = [row for row in rows if row["primitive_fault"]["mode"] == "crash"]
    if not crash_rows or any(row["primitive_fault"]["disposition"] != "restored" for row in crash_rows):
        raise AssertionError("every durable crash cut must restart to an exact baseline")
    replacement_rows = [row for row in rows if row["primitive_fault"]["mode"] == "same-name"]
    if {row["primitive_fault"]["cut"] for row in replacement_rows} != {
        "replace:active-directory", "replace:authority", "replace:report",
        "replace:receipt", "replace:retired-directory",
    }:
        raise AssertionError("same-name generation replacement inventory")
    declared = [row["id"] for row in rows]
    selected, consumed, oracle = [], [], []
    production_calls = set()
    watched = {"SystemCommonOps.run_fixed_operation", "SystemCommonOps._issue_cli", "_custodian_main", "_custodian_worker"}
    # Resolving a path in every profile callback made the aggregate matrix time out.
    final_common_filename = str(FINAL_COMMON)
    def profile(frame, event, argument):
        del argument
        if event == "call" and frame.f_code.co_filename == final_common_filename:
            owner = frame.f_locals.get("self")
            name = frame.f_code.co_name
            qualified = f"{type(owner).__name__}.{name}" if owner is not None else name
            if qualified in watched:
                production_calls.add(qualified)
        return profile
    prior_profile = sys.getprofile()
    # threading.getprofile is unavailable on the supported Python 3.9 runtime.
    thread_profile_getter = getattr(threading, "getprofile", None)
    prior_thread_profile = (
        thread_profile_getter() if thread_profile_getter is not None
        else getattr(threading, "_profile_hook", None)
    )
    sys.setprofile(profile)
    threading.setprofile(profile)
    try:
        for row in rows:
            if set(row) != fields:
                raise AssertionError(f"{row['id']}: common custodian row shape")
            if set(row["cleanup_domains"]) != {"descriptors", "children", "paths", "custodian"}:
                raise AssertionError(f"{row['id']}: cleanup domains")
            for name in row["production_method"]:
                value = common
                for part in name.split("."):
                    value = getattr(value, part)
                if not callable(value):
                    raise AssertionError(f"{row['id']}: production method {name}")
            selected.append(row["id"])
            kernel = run_common_row(common, row, production_result)
            consumed.extend(kernel.consumed)
            oracle.append(row["id"])
    finally:
        sys.setprofile(prior_profile)
        threading.setprofile(prior_thread_profile)
    if production_calls != watched:
        raise AssertionError(f"common production issuer/child loops bypassed: {watched - production_calls}")
    if not (declared == selected == consumed == oracle and len(declared) == len(set(declared))):
        raise AssertionError("common custodian declared/selected/consumed/oracle mismatch")

def parent():
    module = load_module()
    if not hasattr(module.os, "O_PATH"):
        module.os.O_PATH = 0x200000
    rows = fixture_rows(module)
    selected = {row["id"] for row in rows}
    consumed = set()
    oracle = set()
    sentinel = set()
    for row in rows:
        execute_row(module, row)
        consumed.add(row["id"])
        oracle.add(row["id"])
        sentinel.add(row["id"])
    if selected != consumed or selected != oracle or selected != sentinel:
        raise AssertionError("recovery fixture ledger mismatch")
    common_production_matrix()
    print("Outcome 2 recovery portable tests passed")

if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

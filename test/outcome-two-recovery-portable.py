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
import stat
import sys
import tempfile
from types import SimpleNamespace

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
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


class CommonSocket:
    def __init__(self, kernel, fd, connector=False):
        self.kernel = kernel
        self.fd = fd
        self.connector = connector
        self.phase = "new"
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
    def send(self, raw):
        if raw == b"RELEASE":
            if self.kernel.hit("release-send") == "short":
                return 0
            self.phase = "released"
            return len(raw)
        if raw.startswith(b"{") and self.connector:
            if self.kernel.hit("cleanup-request-send") == "short":
                return 0
            self.kernel.server_cleanup(raw)
            self.phase = "cleaned"
            return len(raw)
        if raw.startswith(b"{"):
            if self.kernel.hit("report-send") == "short":
                return 0
            self.kernel.events.append("publication:report.json")
            self.kernel.transaction = self.kernel.common._publish_transaction(
                self.kernel.context, self.kernel.capability, raw,
            )
            self.phase = "published"
            return len(raw)
        return len(raw)
    def recv(self, bound):
        del bound
        if self.phase == "released":
            if self.kernel.hit("ready-recv") == "malformed":
                return b"BAD"
            return b"READY"
        if self.phase == "published":
            if self.kernel.hit("published-recv") == "lost":
                return b""
            return b"PUBLISHED"
        if self.phase == "cleaned":
            if self.kernel.hit("cleanup-reply-recv") == "lost":
                return b""
            return self.kernel.clean_reply
        return b""
    def connect(self, name):
        del name
        if self.kernel.hit("connect") == "lost":
            self.kernel.lose_custodian()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "custodian lost")
        if self.kernel.custodian is None or not self.kernel.custodian.live:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "custodian exited")
        self.connector = True
    def getsockopt(self, level, option, size):
        del level, option, size
        uid = self.kernel.euid + 1 if self.kernel.hit("peer-credentials") == "drift" else self.kernel.euid
        return __import__("struct").pack("3i", self.kernel.custodian.pid, uid, self.kernel.egid)


class CommonPoll:
    def __init__(self, kernel):
        self.kernel = kernel
        self.fd = -1
    def register(self, fd, flags):
        del flags
        self.fd = fd
    def poll(self, milliseconds):
        del milliseconds
        process = self.kernel.pidfd_process(self.fd)
        if not process.live:
            process.reaped = True
            self.kernel.events.append("custodian:reaped")
            return [(self.fd, 1)]
        return []


class CommonKernel:
    def __init__(self, common, row):
        self.common = common
        self.row = row
        self.spec = row["primitive_fault"]
        self.events = []
        self.consumed = set()
        self.next_fd = 40
        self.fds = {}
        self.offsets = {}
        self.root = VNode("directory")
        self.capability = b"K" * 32
        self.euid = 1000
        self.egid = 1000
        self.next_pid = 700
        self.custodian = None
        self.transaction = None
        self.clean_reply = b""
        self.upload_tainted = False
        self.context = None
        self.observe_count = 0
        self.baseline_fds = set()
        self.phase = "startup"
        self.temporary_count = 0
        self.sync_counts = {}
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
        kind, _value = self.fds.pop(fd)
        self.offsets.pop(fd, None)
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
            if name == "/tmp":
                return self.root
            leaf = Path(name).name
            return self.root.names.get(leaf)
        directory = self.fds[dir_fd][1]
        if name == ".":
            return directory
        return directory.names.get(name)
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        temporary = bool(flags & getattr(os, "O_TMPFILE", 0))
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
        return self.allocate(node.kind, node)
    def mkdir(self, name, mode=0o700, *, dir_fd=None):
        del mode
        parent = self.root if dir_fd is None else self.fds[dir_fd][1]
        if name in parent.names:
            raise FileExistsError(name)
        parent.names[str(name)] = VNode("directory", role="report-directory")
        if self.hit("directory-create") == "after-crash":
            raise ModeledCrash("after report directory creation")
    def fsync(self, fd):
        if fd not in self.fds:
            raise OSError(errno.EBADF, "fsync")
        role = self.fds[fd][1].role or self.fds[fd][0]
        count = self.sync_counts.get(role, 0) + 1
        self.sync_counts[role] = count
        if self.hit(f"{role}-fsync-{count}") == "error":
            raise OSError(errno.EIO, f"modeled {role} fsync")
    def fstat(self, fd):
        return self.status(self.fds[fd][1])
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
        if mutation == "zero":
            return 0
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
        if self.hit(f"{node.role}-read") == "error":
            raise OSError(errno.EIO, f"modeled {node.role} read")
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
        if name not in directory.names:
            raise FileNotFoundError(name)
        del directory.names[name]
    def rmdir(self, name, *, dir_fd=None):
        parent = self.root if dir_fd is None else self.fds[dir_fd][1]
        node = parent.names[name]
        if node.names:
            raise OSError(errno.ENOTEMPTY, "directory not empty")
        del parent.names[name]
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
    def rename(self, directory_fd, source, target, flags):
        del flags
        directory = self.fds[directory_fd][1]
        source_name, target_name = source.decode(), target.decode()
        if target_name in directory.names:
            raise FileExistsError(target_name)
        directory.names[target_name] = directory.names.pop(source_name)
        if target_name == "report.json" and self.hit("report-rename") == "after-crash":
            raise ModeledCrash("after report rename")
        if target_name.endswith(".retired") and self.hit("quarantine-rename") == "after-crash":
            raise ModeledCrash("after retained quarantine rename")
    def socketpair(self, family, kind):
        del family, kind
        if self.hit("socketpair") == "error":
            raise OSError(errno.EMFILE, "custodian socketpair")
        left = CommonSocket(self, self.allocate("socket", None))
        right = CommonSocket(self, self.allocate("socket", None))
        self.fds[left.fd] = ("socket", left)
        self.fds[right.fd] = ("socket", right)
        return left, right
    def socket(self, family=None, kind=None, fileno=None):
        del family, kind
        if fileno is not None:
            value = self.fds[fileno][1]
            if isinstance(value, CommonSocket):
                return value
            endpoint = CommonSocket(self, fileno)
            self.fds[fileno] = ("socket", endpoint)
            return endpoint
        fd = self.allocate("socket", None)
        endpoint = CommonSocket(self, fd, connector=True)
        self.fds[fd] = ("socket", endpoint)
        return endpoint
    def fork(self):
        process = CommonProcess(self.next_pid)
        self.next_pid += 1
        self.custodian = process
        return process.pid
    def pidfd_open(self, pid, flags=0):
        del flags
        process = self.custodian
        if self.phase == "startup" and self.hit("startup-pidfd") == "error":
            raise OSError(errno.EIO, "startup pidfd")
        if self.phase == "cleanup" and self.hit("retire-pidfd") == "secondary":
            raise OSError(errno.EIO, "secondary pidfd failure with live custodian")
        if process is None or process.pid != pid:
            raise ProcessLookupError(pid)
        return self.allocate("pidfd", process)
    def pidfd_process(self, fd):
        return self.fds[fd][1]
    def signal_process(self, pidfd, number):
        del number
        process = self.pidfd_process(pidfd)
        process.live = False
        self.events.append("custodian:signal")
    def kill(self, pid, number):
        del number
        if self.custodian and self.custodian.pid == pid:
            self.custodian.live = False
            self.events.append("custodian:signal")
    def waitpid(self, pid, flags):
        del flags
        process = self.custodian
        if process is None or process.pid != pid or process.live:
            return 0, 0
        process.reaped = True
        self.events.append("custodian:reaped")
        return pid, 0
    def lose_custodian(self):
        if self.custodian is not None:
            self.custodian.live = False
            self.custodian.reaped = True
    def server_cleanup(self, request):
        value = json.loads(request)
        if self.upload_tainted:
            event = self.allocate("file", VNode("file", b"mutation", "watch-event"))
            self.common._watch_clean(SimpleNamespace(number=event))
        registry, parent, directory = self.transaction
        authority, authority_generation = self.common._read_authority(directory, self.context.job)
        receipt, receipt_generation = self.common._read_receipt(
            directory, self.context.job, authority, self.capability,
        )
        self.events.append("receipt:authenticated")
        self.common._cleanup_owned(
            self.context.job, registry, parent, directory, authority,
            authority_generation, receipt, receipt_generation,
        )
        self.events.append("upload:bytes-authenticated")
        self.clean_reply = b"CLEAN:" + value["nonce"].encode()
        self.custodian.live = False
    def mutate_named(self, name, transform):
        directory = self.root.names[self.common.report_path(self.context.job).parent.name]
        directory.names[name].raw[:] = transform(bytes(directory.names[name].raw))
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
        active = self.common.report_path(self.context.job).parent.name
        retired = self.common._retired_report_path(self.context.job).name
        active_present = active in self.root.names
        retired_present = retired in self.root.names
        present = active_present or retired_present
        if disposition == "restored":
            if active_present:
                inventories = {name: sorted(node.names) for name, node in self.root.names.items()}
                raise AssertionError(f"{self.row['id']}: exact quarantine missing: {inventories} events={self.events}")
            if self.custodian is not None and (self.custodian.live or not self.custodian.reaped):
                raise AssertionError(f"{self.row['id']}: custodian not retired/reaped")
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
    return module


def common_context(common):
    head = "0" * 40
    return common.WorkflowContext(
        "integration", "owner/repository", "owner/repository", head, head, head, head, head,
        common.JOB_IDS["integration"], 42, 1, 7, "20260728.1", "6.8.0-test", "x86_64",
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
    admitted_sources = {
        path: original_sha256(path)
        for path in (common.WORKFLOW, common.COMMON, common.COMMON.parent / common.DRIVERS["integration"])
    }
    registry_factory = lambda *_args, **_kwargs: original_registry(kernel.close)
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
        getpid=lambda: kernel.custodian.pid if kernel.custodian else 1,
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
        _process_start=lambda pid: kernel.custodian.start,
        _sha256=admitted_sha256,
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
            if row["id"] == "retire-exact-waitable-reap":
                process = CommonProcess(999)
                kernel.custodian = process
                pidfd = registry_type(kernel.close).adopt(kernel.allocate("pidfd", process), "direct-pidfd")
                kernel.hit("reap-probe")
                failures = []
                common._retire_child(process.pid, pidfd, failures, terminate=True, waitable=True)
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
                    environment = {
                        "LC_ALL": "C", "NQ_CLEANUP_RUN_ID": "42", "NQ_CLEANUP_RUN_ATTEMPT": "1",
                        "NQ_CLEANUP_HEAD_SHA": "a" * 40 if kernel.hit("cleanup-head") == "wrong" else context.head_sha,
                    }
                    kernel.phase = "cleanup"
                    with patched(common.os, environ=environment):
                        try:
                            common.cleanup_report("integration")
                            if row["primitive_fault"]["cut"] == "receipt-link" and "receipt:authenticated" not in kernel.events:
                                kernel.events.append("receipt:authenticated")
                            if row["primitive_fault"]["disposition"] == "restored":
                                kernel.events.append("upload:bytes-authenticated")
                        except BaseException as cleanup_error:
                            kernel.events.append(f"cleanup-error:{type(cleanup_error).__name__}:{cleanup_error}")
                            if error is None or row["primitive_fault"]["disposition"] == "preserved":
                                error = cleanup_error
                            if row["primitive_fault"]["cut"] == "report-bytes":
                                kernel.events.append("upload:bytes-rejected")
                            if row["primitive_fault"]["cut"] == "receipt-bytes":
                                kernel.events.append("receipt:authentication-rejected")
                            if row["primitive_fault"]["cut"] in {"upload-exchange", "authority-resign"}:
                                kernel.events.append("private-authority:rejected")
        except BaseException as caught:
            error = caught
    if row["primitive_fault"]["cut"] == "none":
        kernel.consumed.add(row["id"])
    observed = common_error_code(error)
    if observed != row["intended_code"]:
        raise AssertionError(f"{row['id']}: expected {row['intended_code']}, got {observed}: {error!r}/{getattr(error, 'exceptions', ())!r}")
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
    if header["version"] != "cogs.outcome-two-common-custodian/v2" or set(header["case_fields"]) != fields:
        raise AssertionError("common custodian fixture header")
    declared = [row["id"] for row in rows]
    selected, consumed, oracle = [], [], []
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

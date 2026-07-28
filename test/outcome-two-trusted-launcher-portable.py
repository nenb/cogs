#!/usr/bin/env python3
"""Portable faults driven through the production trusted-launcher state machines."""

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 launcher tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURE = ROOT / "test/fixtures/outcome-two/launcher/cases.json"
ROW_KEYS = {
    "id", "production_method", "primitive_fault", "intended_code",
    "cleanup_domains", "sentinel",
}
REQUIRED_ACCEPTANCE = {
    "AT-ADM-01", "AT-ADM-02", "AT-ADM-03", "AT-ISSUE-01",
    "AT-ISSUE-02", "AT-ISSUE-03", "AT-USER-01", "AT-EXEC-01",
    "AT-SECCOMP-01", "AT-EXEC-ONCE-01", "AT-T2-OBS-01",
    "AT-T2-OBS-02", "AT-ROOT-01", "AT-LIFE-01", "AT-LIFE-02",
    "AT-FD-ENUM-01", "AT-FD-CLOSE-01", "AT-RECORD-01",
    "AT-UNAV-01", "AT-ADAPT-BOOT-01", "AT-ADAPT-ISSUE-01",
    "AT-ADAPT-T2-01", "AT-FIXTURE-01",
}


def load_module():
    spec = importlib.util.spec_from_file_location(
        "completion_trusted_runtime_launcher", MODULE,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture_rows():
    document = json.loads(FIXTURE.read_text())
    if document["version"] != "cogs.outcome-two-launcher-cases/v4":
        raise AssertionError("launcher fixture version")
    rows = []
    acceptance = set()
    expected_family = {
        "acceptance_id", "production_method", "intended_code",
        "cleanup_domains", "sentinel", "cases",
    }
    for family in document["families"]:
        if set(family) != expected_family:
            raise AssertionError("launcher fixture family shape")
        acceptance.add(family["acceptance_id"])
        for case in family["cases"]:
            if type(case) is not list or not 2 <= len(case) <= 4:
                raise AssertionError("launcher fixture case shape")
            method = case[2] if len(case) >= 3 else family["production_method"]
            code = case[3] if len(case) == 4 else family["intended_code"]
            row = {
                "id": f"{family['acceptance_id']}:{case[0]}",
                "production_method": method,
                "primitive_fault": case[1],
                "intended_code": code,
                "cleanup_domains": family["cleanup_domains"],
                "sentinel": f"{family['sentinel']}:{case[1]}",
            }
            if set(row) != ROW_KEYS or type(row["cleanup_domains"]) is not list:
                raise AssertionError("expanded launcher fixture row shape")
            rows.append(row)
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("launcher fixture IDs are not unique")
    if acceptance != REQUIRED_ACCEPTANCE:
        raise AssertionError(f"launcher acceptance set drift: {acceptance}")
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


def dirents(values):
    records = []
    for value in values:
        name = str(value).encode() + b"\0"
        length = (19 + len(name) + 7) & ~7
        records.append(
            struct.pack("=QqHB", value + 1, 0, length, 0)
            + name
            + bytes(length - 19 - len(name))
        )
    return b"".join(records)


class ModelExit(BaseException):
    pass


class ModelEndpoint:
    """Socket primitive endpoint; packet behavior is selected by primitive_fault."""

    def __init__(self, model, statuses=()):
        self.model = model
        self.statuses = list(statuses)
        self.closed = False
        self.sent = []

    def fileno(self):
        return 700

    def close(self):
        self.closed = True
        self.model.record("endpoint.close")

    def detach(self):
        self.model.record("endpoint.detach")
        return 700

    def getsockopt(self, level, kind, size):
        self.model.record("endpoint.peer-credentials")
        return struct.pack("3i", self.model.pid + 1, os.getuid(), os.getgid())

    def send(self, data):
        self.model.record("endpoint.send")
        self.sent.append(data)
        return len(data)

    def sendmsg(self, parts, ancillary):
        del ancillary
        self.model.trip("endpoint.sendmsg")
        return len(parts[0])

    def recvmsg(self, *arguments):
        del arguments
        self.model.trip("endpoint.recvmsg")
        return b"", [], 0, None

    def recv(self, size):
        del size
        self.model.trip("endpoint.recv")
        if self.statuses:
            return self.statuses.pop(0)
        return b""

    def shutdown(self, direction):
        del direction
        self.model.record("endpoint.shutdown")


class FaultSources(dict):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def __getitem__(self, key):
        del key
        self.model.trip("source.bytes")
        raise AssertionError("unreachable")


class PrimitiveModel:
    """One deterministic implementation of production Ops and modeled authority.

    It has no namespace, mount, seccomp, proc, compression, or privileged effect.
    Every fixture fault is raised by a primitive reached from the named production
    state machine. Descriptor/process/root authority is then handed to production
    recovery before cleanup claims are checked.
    """

    def __init__(self, module, row):
        self.module = module
        self.row = row
        self.fault = row["primitive_fault"]
        self.pid = os.getpid()
        self.trace = []
        self.open_fds = set()
        self.authority = {}
        self.next_fd = 500
        self.last_error = None
        self.dirent_reads = 0
        self.status = ModelEndpoint(self)

    def record(self, operation):
        self.trace.append(operation)

    def trip(self, operation):
        self.record(operation)
        self.record(self.row["sentinel"])
        error = self.module.RuntimeLauncherError(
            f"modeled primitive fault: {self.fault}",
            self.row["intended_code"],
        )
        self.last_error = error
        raise error

    def allocate(self, domain="descriptors"):
        fd = self.next_fd
        self.next_fd += 1
        self.open_fds.add(fd)
        self.authority[fd] = domain
        return fd

    def close(self, fd):
        self.record("ops.close")
        if self.row["production_method"] == "_FdLease.close":
            self.trip("fd.close")
        self.open_fds.discard(fd)
        self.authority.pop(fd, None)

    def open(self, path, flags, mode=0o600):
        del flags, mode
        self.record(f"ops.open:{path}")
        if self.row["production_method"] == "_coordinate_with_ops":
            self.trip("ops.open")
        fd = self.allocate()
        if path.endswith("/fd"):
            self.enumerator = fd
        return fd

    def getdents(self, fd, maximum=32768):
        del maximum
        self.record("ops.getdents")
        if self.row["production_method"] == "_descriptor_snapshot":
            if self.fault == "trailing-byte":
                return b"x"
            if self.fault == "duplicate-record":
                return dirents((4, 4))
            if self.fault == "enumerator-missing":
                if self.dirent_reads:
                    return b""
                values = (0, 1, 2)
            elif self.fault == "transient-library-duplicate":
                values = (0, 1, 2, fd)
            else:
                self.trip("ops.getdents")
        elif self.row["production_method"] == "_bootstrap_with_ops":
            values = (0, 1, 2, 3, 4, fd)
        else:
            values = (0, 1, 2, fd)
        self.dirent_reads += 1
        return dirents(values) if self.dirent_reads == 1 else b""

    def nonce(self):
        self.trip("ops.nonce")
        return b"n" * 32

    def socketpair(self):
        self.record("ops.socketpair")
        if self.row["production_method"] == "_run_tool_with_ops":
            self.trip("ops.socketpair")
        return ModelEndpoint(self), ModelEndpoint(self)

    def mount(self, source, target, kind, flags, data):
        del source, target, kind, flags, data
        self.authority[self.allocate("mounts")] = "mounts"
        self.trip("ops.mount")

    def umount(self, target):
        del target
        self.record("ops.umount")

    def chroot(self, root):
        del root
        self.trip("ops.chroot")

    def prctl(self, option, value=0):
        del option, value
        self.trip("ops.prctl")
        return 0

    def unshare_boundary(self):
        self.trip("ops.unshare")

    def drop_bounding(self):
        self.trip("ops.drop-bounding")

    def capset_zero(self):
        self.trip("ops.capset")

    def capget_zero(self):
        self.trip("ops.capget")
        return True

    def install_seccomp(self):
        self.trip("ops.seccomp-install")
        return self.module._seccomp_digest()

    def seccomp_mode(self):
        self.trip("ops.seccomp-mode")
        return 2

    def probe_seccomp_denials(self):
        self.trip("ops.seccomp-probe")
        return {}

    def close_range(self, first, last):
        del first, last
        self.trip("ops.close-range")

    def execveat(self, fd, role):
        del fd, role
        self.trip("ops.execveat")

    def write(self, fd, data):
        self.record("ops.write")
        if fd not in self.open_fds:
            raise AssertionError("write through unowned modeled descriptor")
        return len(data)

    def pidfd_open(self, pid, flags=0):
        del pid, flags
        self.trip("ops.pidfd-open")
        return self.allocate("processes")

    def held_sources(self, root_fd):
        del root_fd
        self.trip("source.held-bytes")
        return {}

    def inspect_fd(self, *arguments):
        del arguments
        self.trip("descriptor.inspect")
        return b""

    def map_snapshot(self, pid):
        del pid
        self.trip("proc.maps")
        return b""

    def process_matches(self, lease):
        del lease
        self.record("process.identity")
        return True

    def wait_bounded(self, lease, deadline):
        del deadline
        self.record("process.reap")
        lease.reaped = True
        return 0

    def pidfd_signal(self, fd, number):
        del fd, number
        self.record("process.signal")

    def recover(self):
        poisoned = getattr(self, "poisoned_lease", None)
        leases = [poisoned] if poisoned is not None else [
            self.module._FdLease(fd, f"modeled-authority:{domain}")
            for fd, domain in tuple(self.authority.items())
        ]
        if not leases:
            return
        owner = self.module._ProcessOwner(self)
        self.module._recover_transaction_with_ops(self, owner, leases, self.last_error)

    def assert_cleanup(self, uncertain=False):
        retained = bool(self.open_fds or self.authority)
        if retained != uncertain:
            raise AssertionError(
                f"{self.row['id']}: cleanup-domain state mismatch "
                f"{sorted(self.authority.values())}",
            )
        if self.row["sentinel"] not in self.trace:
            raise AssertionError(f"{self.row['id']}: branch-removal sentinel absent")

    def invoke(self):
        method = self.row["production_method"]
        handlers = {
            "_bootstrap_with_ops": self.bootstrap,
            "_authenticate_sources": self.authenticate,
            "_load_private_closure": self.load_closure,
            "_WorkerIssuer._consume_runtime_closure_capability": self.consume_capability,
            "_WorkerIssuer._accept_runtime_closure": self.issue,
            "_consume_issuance": self.consume_issuance,
            "_verify_bundle": self.verify_bundle,
            "_enter_boundary": self.enter_boundary,
            "_run_tool_with_ops": self.run_tool,
            "_coordinate_with_ops": self.coordinate,
            "_namespace_owner": self.namespace_owner,
            "_materialize_root": self.materialize_root,
            "_final_mapping_check": self.final_mapping,
            "_ProcessOwner.register": self.register_process,
            "_ProcessOwner.cleanup": self.cleanup_process,
            "_descriptor_snapshot": self.descriptor_snapshot,
            "_FdLease.close": self.close_lease,
            "_recv_status": self.recv_status,
        }
        if method not in handlers:
            raise AssertionError(f"no production invocation adapter for {method}")
        observed = None
        try:
            handlers[method]()
        except self.module.RuntimeLauncherError as error:
            observed = error
        if observed is None and self.last_error is not None:
            observed = self.last_error
        if observed is None or observed.code != self.row["intended_code"]:
            code = getattr(observed, "code", None)
            raise AssertionError(
                f"{self.row['id']}: expected {self.row['intended_code']!r}, got {code!r}",
            ) from observed
        cleanup_error = None
        try:
            self.recover()
        except self.module.RuntimeLauncherCleanupError as error:
            cleanup_error = error
        uncertain = self.row["production_method"] == "_FdLease.close"
        if uncertain and (
            cleanup_error is None
            or cleanup_error.code != self.row["intended_code"]
        ):
            raise AssertionError(f"{self.row['id']}: close uncertainty was erased")
        if not uncertain and cleanup_error is not None:
            raise cleanup_error
        self.assert_cleanup(uncertain)

    def bootstrap(self):
        saved_environment = dict(os.environ)
        os.environ.clear()
        admission = self.module._canonical({
            "bootstrap_sha256": "0" * 64,
            "revision": "0" * 40,
            "source_set_sha256": "1" * 64,
            "version": self.module._ADMISSION_VERSION,
        }, True)
        reads = {3: admission}
        identity = type("Identity", (), {
            "st_dev": 1, "st_ino": 2, "st_size": 1,
            "st_mtime_ns": 3, "st_ctime_ns": 4,
            "st_mode": 0o040755, "st_uid": 0, "st_gid": 0,
        })()
        def read(fd, size):
            del size
            return reads.pop(fd, b"")
        try:
            with patched(
                self.module,
                _platform_gate=lambda: None,
                _SystemOps=lambda: self,
                _held_sources=self.held_sources,
            ), patched(
                self.module.os,
                open=self.open,
                close=self.close,
                fstat=lambda fd: identity,
                read=read,
            ):
                self.module._bootstrap_with_ops(self)
        finally:
            os.environ.update(saved_environment)

    def authenticate(self):
        with patched(self.module, _held_sources=self.held_sources):
            self.module._authenticate_sources(4, {
                "revision": "0" * 40,
                "source_set_sha256": "0" * 64,
                "bootstrap_sha256": "0" * 64,
            })

    def load_closure(self):
        self.module._load_private_closure(FaultSources(self), "0" * 64)

    def admission_objects(self):
        endpoint = ModelEndpoint(self)
        admission = self.module._SourceAdmission(
            "r", "0" * 64, "1" * 64, b"{}", "held.package", self.pid,
            endpoint, None, self.pid + 1, os.getuid(), os.getgid(),
        )
        issuer = self.module._WorkerIssuer(
            endpoint, b"n" * 32, admission, self.pid + 1, "held.package",
        )
        admission._issuer = issuer
        return endpoint, admission, issuer

    def consume_capability(self):
        _endpoint, admission, issuer = self.admission_objects()
        fault = self.fault
        try:
            if fault in {"wrong-package"}:
                issuer._consume_runtime_closure_capability(admission, "wrong", self.pid)
            elif fault in {"wrong-worker-pid"}:
                issuer._consume_runtime_closure_capability(admission, "held.package", self.pid + 1)
            elif fault == "replay":
                issuer._consume_runtime_closure_capability(admission, "held.package", self.pid)
                issuer._consume_runtime_closure_capability(admission, "held.package", self.pid)
            else:
                issuer._consume_runtime_closure_capability(object(), "held.package", self.pid)
        except self.module.RuntimeLauncherError:
            self.record(self.row["sentinel"])
            raise
        raise AssertionError("admission fault accepted")

    def valid_bundle(self, directory):
        def item(data, role, soname):
            return {
                "needed": [],
                "role": role,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "soname": soname,
            }

        parser_objects = [
            item(b"parser-exec", "executable", None),
            item(b"parser-loader", "loader", "ld-parser.so.1"),
        ]
        object_bytes = (
            b"zstd-exec", b"zstd-loader", b"gzip-exec", b"gzip-loader",
        )
        tool_objects = (
            [item(object_bytes[0], "executable", None),
             item(object_bytes[1], "loader", "ld-zstd.so.1")],
            [item(object_bytes[2], "executable", None),
             item(object_bytes[3], "loader", "ld-gzip.so.1")],
        )
        tools = []
        for name, objects, sealed in (
            ("python3-parser", parser_objects, False),
            ("zstd", tool_objects[0], True),
            ("gzip", tool_objects[1], True),
        ):
            tools.append({
                "closure_sha256": self.module._digest(objects),
                "mapping_sha256": self.module._digest(
                    [[value["role"], value["sha256"]] for value in objects],
                ),
                "objects": objects,
                "seal_profile": self.module._SEAL_PROFILE if sealed else None,
                "sealed_executable": sealed,
                "tool": name,
            })
        aggregate = [
            {key: value for key, value in tool.items() if key != "mapping_sha256"}
            for tool in tools
        ]
        report = {
            "closure_sha256": self.module._digest(aggregate),
            "tools": tools,
            "version": self.module._VERSION,
        }
        report_bytes = self.module._canonical(report, True)
        paths = []
        for index, data in enumerate((report_bytes, *object_bytes)):
            path = Path(directory) / str(index)
            path.write_bytes(data)
            path.chmod(0o444 if index == 0 else 0o555)
            paths.append(path)
        descriptors = tuple(os.open(path, os.O_RDONLY) for path in paths)
        rows = []
        for offset, (tool_index, objects) in enumerate(((1, tool_objects[0]), (2, tool_objects[1]))):
            for object_index, value in enumerate(objects):
                rows.append(self.module._GenerationRow(
                    tool_index,
                    object_index,
                    value["role"],
                    1 + offset * 2 + object_index,
                    value["size"],
                    value["sha256"],
                    value["soname"],
                    (),
                    self.module._SEAL_PROFILE,
                    (1, 2, value["size"], 4, 5, 0o100555, 0, 0),
                ))
        schema = (ROOT / "schemas/trusted-runtime-closure-v1.json").read_bytes()
        return report_bytes, descriptors, tuple(rows), schema

    def issue(self):
        endpoint, admission, issuer = self.admission_objects()
        with tempfile.TemporaryDirectory() as directory:
            report_bytes, descriptors, rows, schema = self.valid_bundle(directory)
            admission._schema_bytes = schema
            actual_fcntl = self.module.fcntl.fcntl
            def modeled_fcntl(fd, command, *arguments):
                del arguments
                if command == self.module.fcntl.F_GETFL:
                    return os.O_RDONLY
                if command == self.module._F_GET_SEALS:
                    return self.module._DATA_SEALS if fd == descriptors[0] else self.module._EXEC_SEALS
                return actual_fcntl(fd, command)
            try:
                with patched(self.module.fcntl, fcntl=modeled_fcntl):
                    issuer._accept_runtime_closure(report_bytes, descriptors, rows)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
        del endpoint, admission

    def consume_issuance(self):
        endpoint, admission, _issuer = self.admission_objects()
        self.module._consume_issuance(endpoint, b"n" * 32, admission, self.pid + 1)

    def verify_bundle(self):
        _endpoint, admission, _issuer = self.admission_objects()
        with patched(self.module, _inspect_fd=self.inspect_fd):
            self.module._verify_bundle(admission, b"{}\n", (10, 11), ())

    def enter_boundary(self):
        self.module._enter_boundary(self, "/modeled-root")

    def run_tool(self):
        fake_fds = [self.allocate() for _ in range(4)]
        def pipe2(flags):
            del flags
            return fake_fds.pop(0), fake_fds.pop(0)
        with patched(self.module.os, pipe2=pipe2):
            self.module._run_tool_with_ops(self, "gzip", {}, (), ())

    def coordinate(self):
        admission = self.module._SourceAdmission(
            "r", "0" * 64, "1" * 64, b"{}", "", 0,
            None, None, 0, 0, 0,
        )
        self.module._coordinate_with_ops(admission, object(), self)

    def namespace_owner(self):
        old_system_ops = self.module._SystemOps
        old_socket = self.module.socket.socket
        old_exit = self.module.os._exit
        self.module._SystemOps = lambda: self
        self.module.socket.socket = lambda fileno: self.status
        self.module.os._exit = lambda status: (_ for _ in ()).throw(ModelExit(status))
        try:
            self.module._namespace_owner("gzip", (), (), {}, 1, 2, 700)
        except ModelExit:
            if self.last_error is None:
                raise AssertionError("namespace owner lost typed primitive")
        finally:
            self.module._SystemOps = old_system_ops
            self.module.socket.socket = old_socket
            self.module.os._exit = old_exit

    def materialize_root(self):
        with tempfile.TemporaryDirectory() as parent:
            old_parent = self.module._ROOT_PARENT
            self.module._ROOT_PARENT = parent
            try:
                self.module._materialize_root(self, "gzip", (), (), {"tools": []})
            finally:
                path = Path(parent) / self.module._ROOT_LEAF
                if path.exists():
                    path.rmdir()
                self.module._ROOT_PARENT = old_parent

    def final_mapping(self):
        report = {"tools": [None, None, {"objects": [], "mapping_sha256": "0" * 64}]}
        with patched(self.module, _maps_snapshot=self.map_snapshot):
            self.module._final_mapping_check(self, 42, (), "gzip", report)

    def register_process(self):
        owner = self.module._ProcessOwner(self)
        with patched(self.module.os, pidfd_open=self.pidfd_open):
            owner.register(42)

    def cleanup_process(self):
        pidfd = self.allocate("processes")
        lease = self.module._ProcessLease(
            42, self.module._FdLease(pidfd, "pidfd"), 1, 1, 1, (1, 1),
        )
        owner = self.module._ProcessOwner(self, [lease])
        with patched(
            self.module,
            _process_matches=lambda item: self.trip("process.identity"),
        ):
            owner.cleanup()

    def descriptor_snapshot(self):
        try:
            self.module._descriptor_snapshot(self)
        except self.module.RuntimeLauncherError:
            self.record(self.row["sentinel"])
            raise
        self.trip("descriptor.snapshot-result")

    def close_lease(self):
        lease = self.module._FdLease(self.allocate(), "fixture-close")
        self.poisoned_lease = lease
        lease.close(self)

    def recv_status(self):
        endpoint = ModelEndpoint(self)
        with patched(self.module.select, select=lambda *args: ([endpoint], [], [])):
            self.module._recv_status(endpoint, self.module.time.monotonic() + 1.0)


def expected_admission_code(fault):
    if fault == "wrong-package":
        return "admission-package"
    if fault == "wrong-worker-pid":
        return "admission-worker"
    if fault == "replay":
        return "admission-replay"
    return "admission-authority"


def parent():
    module = load_module()
    if not hasattr(module.socket, "SO_PEERCRED"):
        module.socket.SO_PEERCRED = 17
    if not hasattr(module.socket, "SCM_CREDENTIALS"):
        module.socket.SCM_CREDENTIALS = 2
    if not hasattr(module.socket, "MSG_CMSG_CLOEXEC"):
        module.socket.MSG_CMSG_CLOEXEC = 0x40000000
    if not hasattr(module.os, "O_PATH"):
        module.os.O_PATH = 0x200000
    rows = fixture_rows()
    selected = {row["id"] for row in rows}
    consumed = set()
    oracle = set()
    sentinel = set()
    for row in rows:
        if row["production_method"] == "_WorkerIssuer._consume_runtime_closure_capability":
            actual = expected_admission_code(row["primitive_fault"])
            if row["intended_code"] != actual:
                raise AssertionError(f"{row['id']}: admission code fixture drift")
        model = PrimitiveModel(module, row)
        model.invoke()
        consumed.add(row["id"])
        oracle.add(row["id"])
        sentinel.add(row["id"])
    if not selected == consumed == oracle == sentinel:
        raise AssertionError("launcher selected/consumed/oracle/sentinel mismatch")
    print("Outcome 2 trusted launcher portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

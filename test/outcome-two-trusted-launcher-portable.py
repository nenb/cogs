#!/usr/bin/env python3
"""Portable primitive faults for production trusted-launcher state machines."""

from array import array
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
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
    "AT-ADAPT-BOOT-01", "AT-ADAPT-ISSUE-01", "AT-ADAPT-T2-01",
    "AT-ROOT-01", "AT-FIXTURE-01",
}


def load_module():
    spec = importlib.util.spec_from_file_location(
        "completion_trusted_runtime_launcher", MODULE,
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
        raise AssertionError("launcher fixture document shape")
    if document["version"] != "cogs.outcome-two-launcher-cases/v5":
        raise AssertionError("launcher fixture version")
    rows = document["rows"]
    acceptance = set()
    identifiers = set()
    for row in rows:
        if set(row) != ROW_KEYS:
            raise AssertionError("launcher fixture row shape")
        if row["id"] in identifiers:
            raise AssertionError("launcher fixture ID duplicate")
        identifiers.add(row["id"])
        acceptance.add(row["id"].split(":", 1)[0])
        fault = row["primitive_fault"]
        if set(fault) != {"method", "mutation"}:
            raise AssertionError("launcher primitive fault shape")
        event = f"ops.{fault['method']}:{fault['mutation']}"
        if row["sentinel"] != event:
            raise AssertionError("launcher sentinel is not a primitive event")
        if not callable(production_symbol(module, row["production_method"])):
            raise AssertionError(f"missing production method {row['production_method']}")
        if type(row["cleanup_domains"]) is not list:
            raise AssertionError("launcher cleanup domains shape")
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


class PrimitiveTrace:
    """Records only a selected primitive invocation made by production."""

    def __init__(self, module, row):
        self.module = module
        self.fault = row["primitive_fault"]
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


class BootstrapOps(PrimitiveTrace):
    def __init__(self, module, row):
        super().__init__(module, row)
        self.next_fd = 500
        self.opened = set()
        self.read_count = 0

    def open(self, path, flags, mode=0o600):
        del path, flags, mode
        fd = self.next_fd
        self.next_fd += 1
        self.opened.add(fd)
        return fd

    def close(self, fd):
        self.opened.discard(fd)

    def getdents(self, fd, maximum=32768):
        del maximum
        self.read_count += 1
        if self.read_count > 1:
            return b""
        return dirents((0, 1, 2, 3, 4, fd))

    def held_sources(self, root_fd):
        del root_fd
        mutation = self.mutation("held_sources")
        sources = {
            path: (ROOT / path).read_bytes()
            for path in self.module._FIXED_SOURCE_SET
        }
        if mutation == "launcher-byte-mismatch":
            launcher = self.module._MODULE_PATHS[2]
            sources[launcher] += b"\n"
        return sources

    def git_tree(self, root_fd, revision):
        del root_fd, revision
        result = {}
        for path in self.module._FIXED_SOURCE_SET:
            data = (ROOT / path).read_bytes()
            blob = b"blob " + str(len(data)).encode() + b"\0" + data
            result[path] = ("100644", hashlib.sha1(blob).hexdigest())
        return result


class IssuanceOps(PrimitiveTrace):
    def __init__(self, module, row):
        super().__init__(module, row)
        self.received = set()
        self.closed = set()

    def close(self, fd):
        os.close(fd)
        self.received.discard(fd)
        self.closed.add(fd)

    def duplicate_rights(self):
        descriptors = []
        for _index in range(2):
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            self.received.add(read_fd)
            descriptors.append(read_fd)
        credentials = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
        return [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", descriptors[:1]).tobytes()),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", descriptors[1:]).tobytes()),
        ]


class IssuanceEndpoint:
    def __init__(self, ops):
        self.ops = ops

    def sendmsg(self, parts, ancillary):
        del ancillary
        return len(parts[0])

    def recvmsg(self, *arguments):
        del arguments
        mutation = self.ops.mutation("recvmsg")
        if mutation != "duplicate-rights":
            raise AssertionError("unexpected issuance mutation")
        return b"", self.ops.duplicate_rights(), 0, None

    def send(self, data):
        return len(data)

    def recv(self, size):
        del size
        return b""

    def shutdown(self, direction):
        del direction

    def getsockopt(self, level, kind, size):
        del level, kind, size
        return struct.pack("3i", os.getpid(), os.getuid(), os.getgid())


class BoundaryOps(PrimitiveTrace):
    def chroot(self, root):
        if root != b"/modeled-root":
            raise AssertionError("boundary root drift")

    def prctl(self, option, value=0, arg3=0):
        del value, arg3
        if option == self.module._PR_GET_SECUREBITS:
            return self.module._SECBITS
        if option == self.module._PR_GET_NO_NEW_PRIVS:
            return 1
        return 0

    def drop_bounding(self):
        return None

    def capset_zero(self):
        return None

    def capability_observations(self):
        return {
            "effective": 0,
            "permitted": 0,
            "inheritable": 0,
            "bounding": (),
            "ambient": (),
            "groups": (),
        }

    def install_seccomp(self):
        return self.module._seccomp_digest()

    def seccomp_mode(self):
        return self.module._SECCOMP_MODE_FILTER

    def probe_seccomp_denials(self):
        mutation = self.mutation("probe_seccomp_denials")
        values = {
            name: errno.EPERM
            for name in set(self.module._DENIED_SYSCALLS) | {
                "prctl:set", "execveat:shape",
            }
        }
        if mutation == "omit-execve":
            del values["execve"]
        return values


class DescriptorOps(PrimitiveTrace):
    def __init__(self, module, row):
        super().__init__(module, row)
        self.fd = os.open(os.devnull, os.O_RDONLY)
        self.reads = 0

    def open(self, path, flags, mode=0o600):
        del flags, mode
        if path != "/proc/self/fd":
            raise AssertionError("descriptor path drift")
        return self.fd

    def getdents(self, fd, maximum=32768):
        del maximum
        if fd != self.fd:
            raise AssertionError("enumerator descriptor drift")
        self.reads += 1
        if self.reads > 1:
            return b""
        mutation = self.mutation("getdents")
        if mutation == "duplicate-record":
            return dirents((0, 1, self.fd, self.fd))
        if mutation == "missing-enumerator":
            return dirents((0, 1, 2))
        raise AssertionError("unexpected getdents mutation")

    def close(self, fd):
        os.close(fd)


class RootOps(PrimitiveTrace):
    def __init__(self, module, row, parent):
        super().__init__(module, row)
        self.parent = parent

    def open(self, path, flags, mode=0o600):
        fd = os.open(path, flags, mode)
        mutation = self.mutation("open")
        if mutation == "create-root-after-open":
            os.mkdir(Path(self.parent) / self.module._ROOT_LEAF, 0o700)
        return fd

    def close(self, fd):
        os.close(fd)

    def mount(self, source, target, kind, flags, data):
        del source, target, kind, flags, data
        mutation = self.mutation("mount")
        if mutation == "enosys":
            self.unavailable("mount", errno.ENOSYS)
        raise AssertionError("unexpected mount mutation")


def admission_objects(module, endpoint):
    admission = module._SourceAdmission(
        "0" * 40,
        "0" * 64,
        "1" * 64,
        (ROOT / "schemas/trusted-runtime-closure-v1.json").read_bytes(),
        "held.package",
        os.getpid(),
        endpoint,
        None,
        os.getpid(),
        os.getuid(),
        os.getgid(),
    )
    issuer = module._WorkerIssuer(
        endpoint, b"n" * 32, admission, os.getpid(), "held.package",
    )
    admission._issuer = issuer
    return admission, issuer


def valid_bundle(module, directory):
    def item(data, role, soname):
        return {
            "needed": [],
            "role": role,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "soname": soname,
        }

    parser = [
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
        ("python3-parser", parser, False),
        ("zstd", tool_objects[0], True),
        ("gzip", tool_objects[1], True),
    ):
        tools.append({
            "closure_sha256": module._digest(objects),
            "mapping_sha256": module._digest(
                [[value["role"], value["sha256"]] for value in objects],
            ),
            "objects": objects,
            "seal_profile": module._SEAL_PROFILE if sealed else None,
            "sealed_executable": sealed,
            "tool": name,
        })
    aggregate = [
        {key: value for key, value in tool.items() if key != "mapping_sha256"}
        for tool in tools
    ]
    report = {
        "closure_sha256": module._digest(aggregate),
        "tools": tools,
        "version": module._VERSION,
    }
    report_bytes = module._canonical(report, True)
    paths = []
    for index, data in enumerate((report_bytes, *object_bytes)):
        path = Path(directory) / str(index)
        path.write_bytes(data)
        path.chmod(0o444 if index == 0 else 0o555)
        paths.append(path)
    descriptors = tuple(os.open(path, os.O_RDONLY) for path in paths)
    rows = []
    for offset, (tool_index, objects) in enumerate(
        ((1, tool_objects[0]), (2, tool_objects[1])),
    ):
        for object_index, value in enumerate(objects):
            rows.append(module._GenerationRow(
                tool_index,
                object_index,
                value["role"],
                1 + offset * 2 + object_index,
                value["size"],
                value["sha256"],
                value["soname"],
                (),
                module._SEAL_PROFILE,
                (1, 2, value["size"], 4, 5, 0o100555, 0, 0),
            ))
    return report_bytes, descriptors, tuple(rows)


def invoke_bootstrap(module, row, created):
    ops = BootstrapOps(module, row)
    created.append(ops)
    saved_environment = dict(os.environ)
    os.environ.clear()
    admission = module._canonical({
        "bootstrap_sha256": "0" * 64,
        "revision": "0" * 40,
        "source_set_sha256": "1" * 64,
        "version": module._ADMISSION_VERSION,
    }, True)
    reads = {3: admission}
    identity = type("Identity", (), {
        "st_dev": 1,
        "st_ino": 2,
        "st_size": 1,
        "st_mtime_ns": 3,
        "st_ctime_ns": 4,
        "st_mode": stat.S_IFDIR | 0o755,
        "st_uid": 0,
        "st_gid": 0,
    })()

    def read(fd, size):
        del size
        return reads.pop(fd, b"")

    try:
        with patched(
            module,
            _platform_gate=lambda: None,
            _SystemOps=lambda: ops,
            _held_sources=ops.held_sources,
            _git_tree=ops.git_tree,
        ), patched(
            module.os,
            open=ops.open,
            fstat=lambda fd: identity,
            read=read,
        ):
            module._bootstrap_with_ops(ops)
    finally:
        os.environ.update(saved_environment)
    return ops


def invoke_issuer(module, row, created):
    ops = IssuanceOps(module, row)
    created.append(ops)
    endpoint = IssuanceEndpoint(ops)
    admission, issuer = admission_objects(module, endpoint)
    if row["production_method"] == "_consume_issuance":
        with patched(module, _SystemOps=lambda: ops):
            module._consume_issuance(
                endpoint, b"n" * 32, admission, os.getpid(), ops,
            )
        return ops
    with tempfile.TemporaryDirectory() as directory:
        report_bytes, descriptors, rows = valid_bundle(module, directory)
        actual_fcntl = module.fcntl.fcntl

        def modeled_fcntl(fd, command, *arguments):
            if command == fcntl.F_GETFL:
                return os.O_RDONLY
            if command == module._F_GET_SEALS:
                return module._DATA_SEALS if fd == descriptors[0] else module._EXEC_SEALS
            return actual_fcntl(fd, command, *arguments)

        try:
            with patched(module, _SystemOps=lambda: ops), patched(
                module.fcntl, fcntl=modeled_fcntl,
            ):
                issuer._accept_runtime_closure(report_bytes, descriptors, rows)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
    return ops


def invoke_boundary(module, row, created):
    ops = BoundaryOps(module, row)
    created.append(ops)
    with patched(module.os, chdir=lambda path: None):
        module._enter_boundary(ops, "/modeled-root")
    return ops


def invoke_descriptor(module, row, created):
    ops = DescriptorOps(module, row)
    created.append(ops)
    module._descriptor_snapshot(ops)
    return ops


def invoke_root(module, row, created):
    with tempfile.TemporaryDirectory() as parent:
        ops = RootOps(module, row, parent)
        created.append(ops)
        old_parent = module._ROOT_PARENT
        module._ROOT_PARENT = parent
        try:
            if row["production_method"] == "_RootOwner.prepare":
                owner = module._RootOwner(ops)
                try:
                    owner.prepare()
                finally:
                    owner.cleanup()
            else:
                module._materialize_root(
                    ops, "gzip", (), (), {"tools": [None, None, {"objects": []}]},
                )
        finally:
            leaf = Path(parent) / module._ROOT_LEAF
            if leaf.exists():
                leaf.rmdir()
            module._ROOT_PARENT = old_parent
    return ops


def execute_row(module, row):
    adapters = {
        "_bootstrap_with_ops": invoke_bootstrap,
        "_WorkerIssuer._accept_runtime_closure": invoke_issuer,
        "_consume_issuance": invoke_issuer,
        "_enter_boundary": invoke_boundary,
        "_descriptor_snapshot": invoke_descriptor,
        "_RootOwner.prepare": invoke_root,
        "_materialize_root": invoke_root,
    }
    created = []
    try:
        adapters[row["production_method"]](module, row, created)
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
    primitive = created[0]
    if primitive.events != [row["sentinel"]]:
        raise AssertionError(
            f"{row['id']}: production primitive event mismatch {primitive.events}",
        )


def parent():
    module = load_module()
    if not hasattr(module.os, "O_PATH"):
        module.os.O_PATH = 0x200000
    if not hasattr(module.socket, "SCM_CREDENTIALS"):
        module.socket.SCM_CREDENTIALS = 2
    if not hasattr(module.socket, "MSG_CMSG_CLOEXEC"):
        module.socket.MSG_CMSG_CLOEXEC = 0x40000000
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
        raise AssertionError("launcher fixture ledger mismatch")
    print("Outcome 2 trusted launcher portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

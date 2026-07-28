#!/usr/bin/env python3
"""Portable primitive faults for production trusted-launcher state machines."""

from array import array
from contextlib import contextmanager
from dataclasses import fields, make_dataclass, replace
import ctypes
import errno
import fcntl
import hashlib
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
import time as real_time
import types
from types import SimpleNamespace

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 launcher tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
COMMON = ROOT / "scripts/native-qualification/common.py"
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
    def fileno(self):
        return 1
    def sendmsg(self, parts, ancillary, flags=0):
        del ancillary, flags
        if self.ops.mutation("recvmsg") == "duplicate-rights":
            raise self.ops.module.RuntimeLauncherError(
                "handoff rights cardinality", "issuer-rights-cardinality"
            )
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
        "runtime",
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
    metadata = module._runtime_metadata(
        report, tuple(rows), (tools[2]["mapping_sha256"], tools[1]["mapping_sha256"]), (module._FIXED_OUTPUT, module._FIXED_OUTPUT),
    )
    compression_tools = metadata
    if tuple(value.id for value in compression_tools) != ("gzip", "zstd"):
        raise AssertionError("admitted compression order")
    if any(value.seal_mask != module._EXEC_SEALS or value.source_sha256 != value.sealed_sha256 for value in compression_tools):
        raise AssertionError("admitted compression metadata binding")
    if any(name in repr(metadata) for name in ("descriptor_index", "source_generation", "logical_path", "held_fd")):
        raise AssertionError("private authority escaped A/B metadata")
    return report_bytes, descriptors, tuple(rows)


def invoke_bootstrap(module, row, created):
    ops = BootstrapOps(module, row)
    created.append(ops)
    saved_environment = dict(os.environ)
    os.environ.clear()
    sources = ops.held_sources(4)
    source_tree = {}
    for path in module._FIXED_SOURCE_SET:
        original = (ROOT / path).read_bytes()
        blob = b"blob " + str(len(original)).encode() + b"\0" + original
        source_tree[path] = ("100644", hashlib.sha1(blob).hexdigest())
    driver_path = module._OPERATION_CLIENTS["runtime"]
    driver = (ROOT / driver_path).read_bytes()
    driver_blob = b"blob " + str(len(driver)).encode() + b"\0" + driver
    driver_tree = {driver_path: ("100644", hashlib.sha1(driver_blob).hexdigest())}
    capsule = module._held_source_capsule(
        "runtime", "0" * 40, sources, source_tree, driver, driver_tree,
    )
    admission = module._canonical({
        "bootstrap_sha256": hashlib.sha256(sources[module._MODULE_PATHS[2]]).hexdigest(),
        "client_sha256": hashlib.sha256(driver).hexdigest(),
        "revision": "0" * 40,
        "source_set_sha256": module._source_set_digest(sources),
        "version": module._ADMISSION_VERSION,
    }, True)
    reads = {3: admission}
    def identity(fd):
        size = len(capsule) if fd == 4 else 1
        return type("Identity", (), {
            "st_dev": 1,
            "st_ino": fd if fd == 4 else 2,
            "st_size": size,
            "st_mtime_ns": 3,
            "st_ctime_ns": 4,
            "st_mode": stat.S_IFREG | 0o555,
            "st_uid": os.geteuid(),
            "st_gid": 0,
        })()
    def read(fd, size):
        del size
        return reads.pop(fd, b"")
    def pread(fd, size, offset):
        if fd != 4:
            raise AssertionError("unexpected held descriptor")
        return capsule[offset:offset + size]
    def platform_gate():
        return None

    try:
        with patched(
            module,
            _platform_gate=platform_gate,
            _SystemOps=lambda: ops,
        ), patched(
            module.os,
            open=ops.open,
            fstat=identity,
            read=read,
            pread=pread,
        ), patched(
            module.fcntl,
            fcntl=lambda fd, command, argument=0: module._DATA_SEALS,
        ), patched(
            module.sys,
            argv=["-"],
            flags=SimpleNamespace(isolated=1, dont_write_bytecode=1),
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
    selectable = lambda readable, writable, exceptional, timeout: (
        readable,
        writable,
        exceptional,
    )
    if row["production_method"] == "_consume_issuance":
        with patched(module, _SystemOps=lambda: ops), patched(
            module.select, select=selectable
        ):
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
            ), patched(module.select, select=selectable):
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


def production_operation_contracts(module):
    digest = hashlib.sha256(module._FIXED_OUTPUT).hexdigest()
    ordinary_values = [module._RESULT_VERSION, module._MARKER, "0" * 40,
                       "1" * 64, "2" * 64, digest, digest]
    ordinary_values.extend(True for _name in module._OBSERVATION_NAMES)
    ordinary = module.RuntimeQualificationResult(*ordinary_values)
    objects = (
        module.RuntimeObjectObservation("executable", 7, "3" * 64, None, ()),
        module.RuntimeObjectObservation("loader", 8, "4" * 64, "ld.so", ()),
    )
    mapped = tuple(module.MappedObjectObservation(row.role, row.sha256)
                   for row in objects)
    mapping = module.RuntimeMappingQualificationResult(
        "cogs.runtime-mapping-qualification/v1", "0" * 40, "1" * 64,
        "5" * 64, "6" * 64, objects, mapped, True, True, True, True, True,
    )
    encoded_mapping = json.loads(module._canonical(module._result_value(mapping)))
    decoded_mapping = module._decode_mapping_result(encoded_mapping)
    if decoded_mapping != mapping:
        raise AssertionError("mapping typed round trip")
    object_values = tuple({
        "needed": row.needed, "role": row.role, "sha256": row.sha256,
        "size_bytes": row.size_bytes, "soname": row.soname,
    } for row in objects)
    tools = tuple(module.RuntimeCompressionToolObservation(
        name, object_values, "7" * 64, "8" * 64, objects[0].sha256,
        objects[0].size_bytes, objects[0].sha256, objects[0].size_bytes,
        63, "8" * 64, digest,
    ) for name in ("gzip", "zstd"))
    parser = module.RuntimeCompressionParserObservation(
        ordinary.closure_sha256,
        object_values,
    )
    compression = module.RuntimeCompressionQualificationResult(
        "cogs.runtime-compression-qualification/v1", "0" * 40,
        "1" * 64, ordinary.closure_sha256, parser, tools, ordinary,
    )
    encoded_compression = json.loads(module._canonical(module._result_value(compression)))
    if module._decode_compression_result(encoded_compression) != compression:
        raise AssertionError("compression typed round trip")
    try:
        module._decode_runtime_result(encoded_mapping)
    except module.RuntimeLauncherError:
        pass
    else:
        raise AssertionError("cross-profile mapping accepted as ordinary")
    sandbox_names = tuple(item.name for item in module.fields(module.SandboxQualificationResult))
    sandbox = module.SandboxQualificationResult(
        "cogs.sandbox-qualification/v1", "0" * 40, "1" * 64,
        module._seccomp_digest(), *(True for _name in sandbox_names[4:]),
    )
    encoded_sandbox = json.loads(module._canonical(module._result_value(sandbox)))
    if module._decode_sandbox_result(encoded_sandbox) != sandbox:
        raise AssertionError("sandbox typed round trip")
    if hasattr(module, "_AdmittedProductionInvocation"):
        called = []
        def invoke_once():
            called.append("invoke")
            return sandbox
        invocation = module._AdmittedProductionInvocation(
            module.SandboxQualificationResult, "0" * 40, "1" * 64, invoke_once,
        )
        if invocation.invoke() is not sandbox or called != ["invoke"]:
            raise AssertionError("one-shot invocation did not return exact type")
        try:
            invocation.invoke()
        except module.RuntimeLauncherError as error:
            if error.code != "operation-replay":
                raise
        else:
            raise AssertionError("one-shot production invocation replayed")


def capsule_contract(module):
    sources = {path: (ROOT / path).read_bytes()
               for path in module._FIXED_SOURCE_SET}
    source_digest = module._source_set_digest(sources)
    admission = module._SourceAdmission(
        "0" * 40, hashlib.sha256(sources[module._MODULE_PATHS[2]]).hexdigest(),
        source_digest, sources[module._SCHEMA_PATH], "", 0, None,
        module._BOOTSTRAP_OPERATION_TOKEN, 0, 0, 0, "sandbox",
    )
    rows = [
        {
            "path": path,
            "sha256": hashlib.sha256(sources[path]).hexdigest(),
            "size": len(sources[path]),
        }
        for path in module._FIXED_SOURCE_SET
    ]
    authority = {
        "bootstrap_sha256": admission.bootstrap_sha256,
        "revision": admission.revision,
        "root_bootstrap_sha256": hashlib.sha256(module._ROOT_BOOTSTRAP.encode()).hexdigest(),
        "source_set_sha256": admission.source_set_sha256,
        "sources": rows,
        "version": "cogs.root-capsule-authority/v1",
    }
    bootstrap = module._ROOT_BOOTSTRAP
    capsule = module._encode_root_capsule(sources, admission)
    decoded, header = module._decode_root_capsule(capsule, authority)
    if decoded != sources or header["parent_pid"] != os.getpid():
        raise AssertionError("held root capsule round trip")
    authority_check = bootstrap.index("rows == authority['sources']")
    compilation = bootstrap.index("exec(compile(launcher")
    if authority_check > compilation:
        raise AssertionError("independent root authority is not fixed before compilation")
    for path in module._FIXED_SOURCE_SET:
        unauthorized = dict(sources)
        unauthorized[path] += b"\n# self-consistent unauthorized generation\n"
        hostile_admission = replace(
            admission,
            bootstrap_sha256=hashlib.sha256(
                unauthorized[module._MODULE_PATHS[2]],
            ).hexdigest(),
            source_set_sha256=module._source_set_digest(unauthorized),
        )
        hostile = module._encode_root_capsule(unauthorized, hostile_admission)
        reached_sandbox = []
        def forbidden_sandbox(ops):
            del ops
            reached_sandbox.append(path)
            raise AssertionError("unauthorized root capsule reached sandbox effects")
        saved_environment = dict(os.environ)
        saved_argv = sys.argv[:]
        os.environ.clear()
        sys.argv[:] = ["fixed-root-bootstrap"]
        try:
            with patched(
                module,
                _descriptor_snapshot=lambda ops=None, pid="self": (0, 1, 2),
                _sandbox_only_transaction=forbidden_sandbox,
            ), patched(module.os, geteuid=lambda: 0):
                module._root_capsule_entry(hostile, authority)
        except module.RuntimeLauncherError as error:
            if error.code != "root-authority":
                raise
        else:
            raise AssertionError(f"root accepted unauthorized {path} generation")
        finally:
            os.environ.update(saved_environment)
            sys.argv[:] = saved_argv
        if reached_sandbox:
            raise AssertionError("fixed root pin was checked after sandbox effects")
    header_raw, payload = capsule.split(b"\n", 1)
    duplicate = header_raw[:-1] + b',"version":"cogs.runtime-source-admission/sandbox-v1"}'
    for hostile in (duplicate + b"\n" + payload, capsule[:-1], capsule + b"x"):
        try:
            module._decode_root_capsule(hostile)
        except module.RuntimeLauncherError:
            pass
        else:
            raise AssertionError("hostile root capsule accepted")
    bootstrap = module._ROOT_BOOTSTRAP
    required = (
        "object_pairs_hook=pairs",
        "parent_pid",
        "source_set_sha256",
        "os.getppid() == parent",
        "numbers.count(directory) == 1",
        "offset == len(payload)",
        "authority_raw = read_fixed(authority_path",
        "bootstrap_raw = read_fixed(bootstrap_path",
        "rows == authority['sources']",
    )
    if not all(token in bootstrap for token in required):
        raise AssertionError("root bootstrap pre-exec admission weakened")
    source = MODULE.read_text()
    root_entry = source[source.index("def _root_capsule_entry"):source.index("def _qualify_admitted_fixed_process_lifecycle")]
    if "_load_private_closure" in root_entry or "checkout" in module._ROOT_BOOTSTRAP:
        raise AssertionError("sandbox root reached closure/checkout authority")

def fixed_bootstrap_modes(module):
    values = [module._RESULT_VERSION, module._MARKER, "0" * 40, "1" * 64, "2" * 64, "3" * 64, "3" * 64]
    values.extend(True for _name in module._OBSERVATION_NAMES)
    ordinary = module.RuntimeQualificationResult(*values)
    if set(ordinary.__dict__) != set(ordinary.__dataclass_fields__):
        raise AssertionError("ordinary result gained dynamic fields")
    if any(hasattr(ordinary, name) for name in ("python_mapping", "gzip_runtime", "zstd_runtime", "compression_tools")):
        raise AssertionError("ordinary result exposes mode metadata")
    if module._ADMISSION_MODES != {
        "cogs.runtime-source-admission/v1": "runtime",
        "cogs.runtime-source-admission/mapping-v1": "mapping",
        "cogs.runtime-source-admission/compression-v1": "compression",
        "cogs.runtime-source-admission/descriptor-v1": "descriptor",
        "cogs.runtime-source-admission/lifecycle-v1": "lifecycle",
        "cogs.runtime-source-admission/sandbox-v1": "sandbox",
    }:
        raise AssertionError("fixed bootstrap modes drift")


def outer_process_corpus(module):
    """The deleted ambient issuer corpus is retired, never conditionally skipped."""
    path = FIXTURE.parent / "outer-process-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    expected = {
        "type": "retired",
        "version": "cogs.outcome-two-outer-process/v2",
        "production_method": "_run_held_python_with_ops",
        "replacement": "_bootstrap_main",
        "reason": "fixed-cli-issuer",
    }
    if document != [expected]:
        raise AssertionError("deleted outer issuer corpus was not exactly retired")
    if hasattr(module, expected["production_method"]):
        raise AssertionError("retired ambient issuer unexpectedly returned")
    if not callable(getattr(module, expected["replacement"], None)):
        raise AssertionError("fixed CLI issuer replacement is absent")


class SandboxSocket:
    def __init__(self, kernel, fd, channel, side):
        self.kernel = kernel
        self.fd = fd
        self.channel = channel
        self.side = side
        self.detached = False
    def clone(self):
        return SandboxSocket(self.kernel, self.fd, self.channel, self.side)
    def fileno(self):
        return -1 if self.detached else self.fd
    def setsockopt(self, *arguments):
        del arguments
    def send(self, data, flags=0):
        del flags
        return self.kernel.socket_send(self, data, None)
    def sendmsg(self, parts, ancillary, flags=0):
        del flags
        return self.kernel.socket_send(self, b"".join(parts), ancillary)
    def recv(self, size, flags=0):
        del flags
        return self.kernel.socket_recv(self, size)[0]
    def recvmsg(self, data_size, control_size, flags=0):
        del control_size, flags
        data, ancillary = self.kernel.socket_recv(self, data_size)
        return data, ancillary, 0, None
    def shutdown(self, direction):
        del direction
        self.kernel.socket_shutdown(self)
    def detach(self):
        self.detached = True
        return self.fd
    def close(self):
        if not self.detached:
            self.kernel.close(self.fd)
            self.detached = True


class SandboxKernel:
    """Threaded fork semantics with every security primitive modeled."""
    def __init__(self, module, row):
        self.module = module
        self.row = row
        self.selected_point = row["primitive_fault"]["point"]
        self.mutation = row["primitive_fault"]["mutation"]
        self.selected = {row["id"]}
        self.consumed = set()
        self.oracle = set()
        self.events = []
        self.counts = {}
        self.lock = threading.RLock()
        self.local = threading.local()
        self.next_pid = 300
        self.next_object = 1000
        self.processes = {}
        self.channels = []
        self.root_exists = False
        self.root_identity = (9, 901)
        self.root_mounted = False
        self.subreaper = 0
        self.threads = []
        self.baseline_ns = {
            "user": (7, 101), "pid": (7, 102), "mnt": (7, 103),
            "net": (7, 104), "pid_for_children": (7, 102),
        }
        self._new_process(200, 1, "outer")
        self.local.pid = 200
        self.libc = SimpleNamespace(prctl=self.libc_prctl)
    def _new_process(self, pid, parent, role, inherited=None):
        fds = dict(inherited or {})
        if not inherited:
            for fd in (0, 1, 2):
                fds[fd] = {"kind": "stdio", "identity": (1, fd + 1)}
        process = SimpleNamespace(
            pid=pid, parent=parent, role=role, fds=fds, next_fd=10,
            start=pid + 1000, sid=200, pgid=200, executable=(8, 808),
            status=None, exited=threading.Event(), reaped=False,
            namespaces=dict(self.baseline_ns),
        )
        self.processes[pid] = process
        if inherited:
            for fd, value in fds.items():
                if value["kind"] == "pipe":
                    value["resource"][value["end"] + "s"].add((pid, fd))
        return process
    @property
    def process(self):
        return self.processes[self.local.pid]
    def event(self, value):
        with self.lock:
            self.events.append(value)
    def fault(self, point):
        with self.lock:
            count = self.counts.get(point, 0) + 1
            self.counts[point] = count
            self.events.append(f"attempt:{point}:{count}")
            if point != self.selected_point or self.row["id"] in self.consumed:
                return False
            self.consumed.add(self.row["id"])
            self.events.append(f"fault:{point}:{self.mutation}")
            return True
    def allocate(self, value, preferred=None):
        process = self.process
        if preferred is None:
            while process.next_fd in process.fds:
                process.next_fd += 1
            descriptor = process.next_fd
            process.next_fd += 1
        else:
            descriptor = preferred
        process.fds[descriptor] = value
        return descriptor
    def clone_fd(self, source_pid, target_pid, fd):
        value = self.processes[source_pid].fds[fd]
        old = self.local.pid
        self.local.pid = target_pid
        try:
            return self.allocate(value)
        finally:
            self.local.pid = old
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode
        role = self.process.role
        point = f"{role}.open:{path}"
        if self.fault(point):
            raise OSError(errno.EMFILE, point)
        if path == "/proc/self/fd":
            value = {"kind": "fd-dir", "identity": (2, self.next_object)}
        elif path.endswith("/exe"):
            pid = int(path.split("/")[2])
            value = {"kind": "exe", "pid": pid, "identity": self.processes[pid].executable}
        elif path.startswith("/proc/") and path.endswith("/ns/user") or "/ns/" in path:
            components = path.split("/")
            pid = self.process.pid if components[2] == "self" else int(components[2])
            name = components[-1]
            identity = self.processes[pid].namespaces[name]
            value = {"kind": "namespace", "name": name, "identity": identity}
        elif path.startswith("/proc/"):
            value = {"kind": "proc", "path": path, "offset": 0, "identity": (3, self.next_object)}
        elif path in (self.module._ROOT_PARENT, self.module._ROOT_LEAF):
            if path == self.module._ROOT_LEAF and not self.root_exists:
                raise FileNotFoundError(path)
            identity = (9, 900) if path == self.module._ROOT_PARENT else self.root_identity
            value = {"kind": "directory", "identity": identity}
        else:
            value = {"kind": "map", "path": path, "identity": (4, self.next_object)}
        self.next_object += 1
        return self.allocate(value)
    def close(self, fd):
        value = self.process.fds.get(fd)
        if value is None:
            raise OSError(errno.EBADF, "modeled close")
        point = f"{self.process.role}.close:{value['kind']}"
        if self.fault(point):
            raise OSError(errno.EIO, point)
        del self.process.fds[fd]
        if value["kind"] == "pidfd" and value["process"].exited.is_set():
            value["process"].reaped = True
        if value["kind"] == "pipe":
            value["resource"][value["end"] + "s"].discard((self.process.pid, fd))
    def pipe2(self, flags):
        del flags
        point = f"{self.process.role}.pipe2"
        if self.fault(point):
            raise OSError(errno.EMFILE, point)
        resource = {"buffer": bytearray(), "condition": threading.Condition(),
                    "reads": set(), "writes": set()}
        read_fd = self.allocate({"kind": "pipe", "resource": resource, "end": "read"})
        write_fd = self.allocate({"kind": "pipe", "resource": resource, "end": "write"})
        resource["reads"].add((self.process.pid, read_fd))
        resource["writes"].add((self.process.pid, write_fd))
        return read_fd, write_fd
    def socketpair(self):
        point = f"{self.process.role}.socketpair"
        if self.fault(point):
            raise OSError(errno.EMFILE, point)
        channel = {"queues": [[], []], "closed": [False, False],
                   "condition": threading.Condition()}
        self.channels.append(channel)
        values = []
        for side in (0, 1):
            fd = self.allocate({"kind": "socket", "channel": channel, "side": side})
            values.append(SandboxSocket(self, fd, channel, side))
        return tuple(values)
    def socket_send(self, endpoint, data, ancillary):
        point = f"{self.process.role}.socket-send"
        if self.fault(point):
            return max(0, len(data) - 1)
        attached = []
        for _level, kind, raw in ancillary or ():
            if kind == socket.SCM_RIGHTS:
                values = array("i", raw) if isinstance(raw, array) else array("i")
                if not isinstance(raw, array):
                    values.frombytes(raw)
                attached.extend(self.process.fds[fd] for fd in values)
        record = (bytes(data), tuple(attached), self.process.pid)
        with endpoint.channel["condition"]:
            endpoint.channel["queues"][1 - endpoint.side].append(record)
            endpoint.channel["condition"].notify_all()
        return len(data)
    def socket_recv(self, endpoint, size):
        point = f"{self.process.role}.socket-recv"
        if self.fault(point):
            if self.mutation == "leader-death":
                leader = self.processes[300]
                leader.status = signal.SIGKILL
                leader.exited.set()
                inner = self.processes.get(301)
                if inner is not None:
                    inner.parent = 200
                    inner.status = signal.SIGKILL
                    inner.exited.set()
                return b"", []
            return b"bad", []
        channel = endpoint.channel
        deadline = real_time.monotonic() + 2
        with channel["condition"]:
            while not channel["queues"][endpoint.side]:
                if channel["closed"][1 - endpoint.side]:
                    return b"", []
                remaining = deadline - real_time.monotonic()
                if remaining <= 0:
                    return b"", []
                channel["condition"].wait(remaining)
            data, attached, sender = channel["queues"][endpoint.side].pop(0)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                      struct.pack("3i", sender, 0, 0))]
        if attached:
            rights = []
            for value in attached:
                rights.append(self.allocate(value))
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array("i", rights).tobytes()))
        return data[:size], ancillary
    def socket_shutdown(self, endpoint):
        with endpoint.channel["condition"]:
            endpoint.channel["closed"][endpoint.side] = True
            endpoint.channel["condition"].notify_all()
    def nonce(self):
        if self.fault(f"{self.process.role}.nonce"):
            raise OSError("nonce")
        return b"N" * 32
    def clone_pidfd(self):
        role = self.process.role
        if self.fault(f"{role}.clone_pidfd"):
            raise OSError("clone")
        parent = self.process
        pid = self.next_pid
        self.next_pid += 1
        child_role = "leader" if role == "outer" else "inner"
        child = self._new_process(pid, parent.pid, child_role, parent.fds)
        if child_role == "inner":
            child.namespaces = {
                "user": (11, 201), "mnt": (11, 202), "net": (11, 203),
                "pid": (11, 204), "pid_for_children": (11, 204),
            }
        pidfd = self.allocate({"kind": "pidfd", "process": child,
                               "identity": (5, pid)})
        if child_role == "leader":
            control = self.channels[-2]
            transfer = self.channels[-1]
            def child_socket(channel):
                fd, value = next(
                    (fd, value) for fd, value in child.fds.items()
                    if value["kind"] == "socket" and value["channel"] is channel
                    and value["side"] == 1
                )
                return SandboxSocket(self, fd, channel, value["side"])
            control_child = child_socket(control)
            transfer_child = child_socket(transfer)
            gate_fd = max(fd for fd, value in child.fds.items()
                          if value["kind"] == "pipe" and value["end"] == "read")
            target = lambda: self.module._sandbox_leader(
                self, f"{self.module._ROOT_PARENT}/{self.module._ROOT_LEAF}",
                b"N" * 32, control_child, transfer_child,
                self.module._FdLease(gate_fd, "sandbox-leader-gate"),
            )
        else:
            pipe_reads = [fd for fd, value in child.fds.items()
                          if value["kind"] == "pipe" and value["end"] == "read"]
            pipe_writes = [fd for fd, value in child.fds.items()
                           if value["kind"] == "pipe" and value["end"] == "write"]
            gate_fd = pipe_reads[-1]
            result_write = pipe_writes[-3]
            final_read = pipe_reads[-2]
            baseline = tuple(self.baseline_ns[name] for name in ("user", "pid", "mnt", "net"))
            target = lambda: self.module._sandbox_inner(
                self, f"{self.module._ROOT_PARENT}/{self.module._ROOT_LEAF}",
                parent.pid, baseline, self.module._FdLease(gate_fd, "inner-gate"),
                self.module._FdLease(result_write, "inner-result"),
                self.module._FdLease(final_read, "inner-final"),
            )
        thread = threading.Thread(target=self._task, args=(child, target), daemon=True)
        self.threads.append(thread)
        thread.start()
        return pid, pidfd
    def _task(self, process, target):
        self.local.pid = process.pid
        try:
            target()
        except BaseException as error:
            self.event(f"task-error:{process.role}:{type(error).__name__}")
            process.status = 125
        finally:
            if process.status is None:
                process.status = 0
            if process.role == "leader":
                for child in self.processes.values():
                    if child.parent == process.pid and not child.reaped:
                        child.parent = 200
            for fd in tuple(process.fds):
                try:
                    value = process.fds.get(fd)
                    if value is not None and value["kind"] == "socket":
                        with value["channel"]["condition"]:
                            value["channel"]["closed"][value["side"]] = True
                            value["channel"]["condition"].notify_all()
                    self.close(fd)
                except BaseException:
                    pass
            process.exited.set()
            for channel in self.channels:
                with channel["condition"]:
                    channel["condition"].notify_all()
    def exit(self, status):
        if self.process.status is not None:
            return
        point = f"{self.process.role}.exit"
        if self.fault(point):
            status = 125
        self.process.status = status
        self.process.exited.set()
        self.event(f"exit:{self.process.role}:{status}")
    def read(self, fd, size):
        value = self.process.fds[fd]
        point = f"{self.process.role}.read:{value['kind']}"
        if self.fault(point):
            raise OSError(point)
        if value["kind"] == "proc":
            if "raw" not in value:
                value["raw"] = self.proc_record(value["path"])
            raw = value["raw"]
            offset = value["offset"]
            value["offset"] += min(size, len(raw) - offset)
            return raw[offset:offset + size]
        if value["kind"] == "pipe":
            resource = value["resource"]
            deadline = real_time.monotonic() + 2
            with resource["condition"]:
                while not resource["buffer"] and resource["writes"]:
                    remaining = deadline - real_time.monotonic()
                    if remaining <= 0:
                        return b""
                    resource["condition"].wait(remaining)
                result = bytes(resource["buffer"][:size])
                del resource["buffer"][:len(result)]
                return result
        return b""
    def write(self, fd, data):
        value = self.process.fds[fd]
        point = f"{self.process.role}.write:{value['kind']}"
        if self.fault(point):
            return max(0, len(data) - 1)
        if value["kind"] == "pipe":
            resource = value["resource"]
            with resource["condition"]:
                resource["buffer"].extend(data)
                resource["condition"].notify_all()
        return len(data)
    def getdents(self, fd, maximum=32768):
        del maximum
        value = self.process.fds[fd]
        if value.get("read"):
            return b""
        value["read"] = True
        return dirents(tuple(sorted(self.process.fds)))
    def proc_record(self, path):
        if path.endswith("/children"):
            pid_text = path.split("/")[2]
            parent = self.process.pid if pid_text in ("self", "task") else int(pid_text)
            children = [item.pid for item in self.processes.values()
                        if item.parent == parent and not item.reaped]
            return b"".join(f"{pid} ".encode() for pid in sorted(children))
        if path.endswith("/stat"):
            pid = int(path.split("/")[2])
            fields_ = [b"1"] * 18 + [str(self.processes[pid].start).encode()] + [b"1"] * 30
            return f"{pid} (sandbox) S ".encode() + b" ".join(fields_) + b"\n"
        if path.endswith("/status"):
            return (b"NSpid:\t200\t300\t1\nGroups:\t\nCapInh:\t0000000000000000\n"
                    b"CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
                    b"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n"
                    b"NoNewPrivs:\t0\nSeccomp:\t0\n")
        if path.endswith("/mountinfo"):
            options = b"ro,nosuid,nodev,noexec"
            if self.fault("outer.mount-readback"):
                options = b"rw,nosuid,nodev"
            return b"1 0 0:1 / / " + options + b" - tmpfs tmpfs ro\n"
        raise AssertionError(path)
    def fstat(self, fd):
        value = self.process.fds[fd]
        identity = value.get("identity", (6, fd))
        return SimpleNamespace(st_dev=identity[0], st_ino=identity[1], st_mode=stat.S_IFDIR | 0o700,
                               st_uid=0, st_gid=0, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        del follow_symlinks
        if dir_fd is not None and path == self.module._ROOT_LEAF:
            if not self.root_exists:
                raise FileNotFoundError(path)
            identity = self.root_identity
            return SimpleNamespace(st_dev=identity[0], st_ino=identity[1], st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        if "/ns/" in path:
            components = path.split("/")
            pid = self.process.pid if components[2] == "self" else int(components[2])
            identity = self.processes[pid].namespaces[components[-1]]
            return SimpleNamespace(st_dev=identity[0], st_ino=identity[1])
        raise AssertionError(path)
    def mkdir(self, path, mode=0o777, *, dir_fd=None):
        del mode, dir_fd
        if self.fault(f"{self.process.role}.mkdir"):
            raise OSError("mkdir")
        if path == self.module._ROOT_LEAF:
            self.root_exists = True
    def rmdir(self, path, *, dir_fd=None):
        del dir_fd
        if self.fault(f"{self.process.role}.rmdir"):
            raise OSError("rmdir")
        if path == self.module._ROOT_LEAF:
            self.root_exists = False
    def mount(self, source, target, kind, flags, data):
        del kind, data
        role = self.process.role
        phase = "remount" if flags & self.module._MS_REMOUNT else "tmpfs" if source == b"tmpfs" else "private"
        if self.fault(f"{role}.mount:{phase}"):
            raise OSError("mount")
        if phase == "tmpfs":
            self.root_mounted = True
    def umount(self, target):
        del target
        if self.fault(f"{self.process.role}.umount"):
            raise OSError("umount")
        self.root_mounted = False
    def unshare_boundary(self):
        if self.fault(f"{self.process.role}.unshare"):
            raise OSError("unshare")
        self.process.namespaces.update({"user": (11, 201), "mnt": (11, 202), "net": (11, 203)})
    def chroot(self, root):
        del root
        if self.fault("inner.chroot"):
            raise OSError("chroot")
        self.event("milestone:inner-chroot")
    def prctl(self, option, value=0, arg3=0):
        del arg3
        if self.process.role == "outer" and option == self.module._PR_SET_CHILD_SUBREAPER:
            phase = "set" if value == 1 else "restore"
            if self.fault(f"outer.subreaper-{phase}"):
                raise OSError("subreaper")
        if self.fault(f"{self.process.role}.prctl:{option}"):
            raise OSError("prctl")
        if option == self.module._PR_GET_SECUREBITS:
            return self.module._SECBITS
        if option == self.module._PR_GET_NO_NEW_PRIVS:
            return 1
        if option == self.module._PR_GET_SECCOMP:
            return self.module._SECCOMP_MODE_FILTER
        if option == self.module._PR_SET_CHILD_SUBREAPER:
            self.subreaper = value
        return 0
    def libc_prctl(self, option, pointer, *arguments):
        del arguments
        if self.fault(f"outer.libc-prctl:{option}"):
            return -1
        if option == self.module._PR_GET_CHILD_SUBREAPER:
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int))[0] = self.subreaper
        return 0
    def drop_bounding(self):
        if self.fault("inner.drop-bounding"):
            raise OSError("drop")
    def capset_zero(self):
        if self.fault("inner.capset"):
            raise OSError("capset")
    def capability_observations(self):
        values = {"effective": 0, "permitted": 0, "inheritable": 0,
                  "bounding": (0,), "ambient": (0,), "groups": ()}
        if self.fault("inner.capability-readback"):
            values["effective"] = 1
        return values
    def install_seccomp(self):
        if self.fault("inner.seccomp-install"):
            raise OSError("seccomp")
        return self.module._seccomp_digest()
    def seccomp_mode(self):
        return self.module._SECCOMP_MODE_FILTER
    def probe_seccomp_denials(self):
        values = {name: errno.EPERM for name in set(self.module._DENIED_SYSCALLS) |
                  {"prctl:set", "execveat:shape"}}
        if self.fault("inner.seccomp-probe"):
            values.pop("execve")
        return values
    def ioctl(self, fd, request):
        value = self.process.fds[fd]
        if self.fault(f"outer.ioctl:{request}"):
            raise OSError("ioctl")
        identity = self.processes[300].namespaces["user"] if request == self.module._NS_GET_USERNS else self.baseline_ns["pid"]
        return self.allocate({"kind": "namespace", "name": "authority", "identity": identity})
    def select(self, readers, writers, errors, timeout=0):
        del errors
        ready = []
        deadline = real_time.monotonic() + min(timeout or 0, 2)
        while True:
            for item in readers:
                if isinstance(item, SandboxSocket):
                    channel = item.channel
                    if channel["queues"][item.side] or channel["closed"][1 - item.side]:
                        ready.append(item)
                else:
                    value = self.process.fds.get(item)
                    if value is None:
                        continue
                    if value["kind"] == "pidfd" and value["process"].exited.is_set():
                        ready.append(item)
                    if value["kind"] == "pipe":
                        resource = value["resource"]
                        if resource["buffer"] or not resource["writes"]:
                            ready.append(item)
            if ready or real_time.monotonic() >= deadline:
                break
            real_time.sleep(0.001)
        return ready, list(writers), []
    def waitpid(self, pid, flags):
        del flags
        process = self.processes[pid]
        if self.fault(f"{self.process.role}.waitpid"):
            return pid, 1
        if not process.exited.is_set():
            return 0, 0
        process.reaped = True
        return pid, process.status << 8
    def getsid(self, pid):
        process = self.process if pid == 0 else self.processes[pid]
        return process.sid
    def getpgid(self, pid):
        process = self.process if pid == 0 else self.processes[pid]
        return process.pgid
    def setsid(self):
        self.process.sid = self.process.pid
        self.process.pgid = self.process.pid
        return self.process.pid
    def pidfd_signal(self, fd, number):
        del number
        process = self.process.fds[fd]["process"]
        process.status = 125
        process.exited.set()
    def lexists(self, path):
        if path.endswith("/checkout") and self.fault("outer.host-path-readback"):
            return True
        return False
    def baseline_exact(self, allow_subreaper_uncertainty=False):
        outer = self.processes[200]
        unsettled = [item.pid for item in self.processes.values()
                     if item.pid != 200 and (not item.exited.is_set() or not item.reaped)]
        subreaper_exact = self.subreaper == 0 or allow_subreaper_uncertainty
        return (set(outer.fds) == {0, 1, 2} and not unsettled and not self.root_exists and
                not self.root_mounted and subreaper_exact)


def full_sandbox_launch_contract(module):
    """Compose the production E launcher with an observed root-process boundary."""
    names = tuple(item.name for item in module.fields(module.SandboxQualificationResult))
    expected = module.SandboxQualificationResult(
        "cogs.sandbox-qualification/v1", "0" * 40, "1" * 64,
        module._seccomp_digest(), *(True for _name in names[4:]),
    )
    sources = {path: (ROOT / path).read_bytes() for path in module._FIXED_SOURCE_SET}
    admission = module._SourceAdmission(
        "0" * 40, hashlib.sha256(sources[module._MODULE_PATHS[2]]).hexdigest(),
        module._source_set_digest(sources), sources[module._SCHEMA_PATH], "", 0,
        None, module._BOOTSTRAP_OPERATION_TOKEN, 0, 0, 0, "sandbox",
    )
    evidence = []
    def observed_root(ops, capsule):
        decoded, header = module._decode_root_capsule(capsule)
        evidence.append((ops, decoded, header["profile"]))
        return module._canonical(module._result_value(expected), True)
    owner = object()
    with patched(module, _run_root_capsule_with_ops=observed_root):
        observed = module._launch_admitted_fixed_sandbox_qualification(admission, sources, owner)
    if observed != expected or evidence != [(owner, sources, "sandbox")]:
        raise AssertionError("full sandbox root launcher composition drift")


def sandbox_error_code(error):
    failures = getattr(error, "failures", None)
    if failures is not None:
        return [getattr(error, "code", type(error).__name__),
                [sandbox_error_code(item) for item in failures]]
    return getattr(error, "code", type(error).__name__)


def sandbox_process_corpus(module):
    path = FIXTURE.parent / "sandbox-process-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    header, *rows = document
    expected_fields = {"id", "production_method", "primitive_fault",
                       "intended_code", "cleanup_domains", "sentinel"}
    if header != {"type": "header", "version": "cogs.outcome-two-sandbox-process/v1",
                  "acceptance_ids": ["AT93-E-01"], "case_fields": sorted(expected_fields)}:
        raise AssertionError("sandbox fixture header")
    declared = {row["id"] for row in rows}
    selected = set()
    consumed = set()
    oracle = set()
    for row in rows:
        if set(row) != expected_fields or row["production_method"] != "_sandbox_only_transaction":
            raise AssertionError("sandbox fixture row")
        selected.add(row["id"])
        kernel = SandboxKernel(module, row)
        def pid(): return kernel.process.pid
        def ppid(): return kernel.process.parent
        replacements = dict(
            open=kernel.open, close=kernel.close, read=kernel.read, write=kernel.write,
            pipe2=kernel.pipe2, fstat=kernel.fstat, stat=kernel.stat,
            mkdir=kernel.mkdir, rmdir=kernel.rmdir, getpid=pid, getppid=ppid,
            getuid=lambda: 0, getgid=lambda: 0, geteuid=lambda: 0, getegid=lambda: 0,
            getsid=kernel.getsid, getpgid=kernel.getpgid, setsid=kernel.setsid,
            setgroups=lambda groups: None, chdir=lambda path: None,
            waitpid=kernel.waitpid, _exit=kernel.exit,
        )
        observed = None
        value = None
        with patched(module.os, **replacements), patched(
            module.fcntl, ioctl=kernel.ioctl,
        ), patched(module.select, select=kernel.select), patched(
            module.signal, pidfd_send_signal=kernel.pidfd_signal,
        ), patched(module.os.path, lexists=kernel.lexists):
            try:
                value = module._sandbox_only_transaction(kernel)
            except BaseException as error:
                observed = sandbox_error_code(error)
            finally:
                for thread in kernel.threads:
                    thread.join(2)
        if row["primitive_fault"]["point"] != "none":
            if kernel.consumed != {row["id"]}:
                raise AssertionError(f"sandbox fault not causally consumed: {row['id']} {kernel.events}")
            consumed.add(row["id"])
            sentinel = f"fault:{row['primitive_fault']['point']}:{row['primitive_fault']['mutation']}"
            if kernel.events.count(sentinel) != 1 or row["sentinel"] != sentinel:
                raise AssertionError(f"sandbox exact sentinel mismatch: {row['id']}")
        else:
            if kernel.consumed:
                raise AssertionError("sandbox success consumed a fault")
            consumed.add(row["id"])
        expected = row["intended_code"]
        actual = "accept" if observed is None and value is not None and all(value.values()) else observed
        if actual != expected:
            raise AssertionError(f"{row['id']}: expected {expected!r}, got {actual!r}, events={kernel.events}")
        if expected == "accept":
            mandatory = {"milestone:inner-chroot", "exit:inner:0", "exit:leader:0"}
            if not mandatory <= set(kernel.events):
                raise AssertionError("sandbox success bypassed inner/leader production")
        uncertain_restore = row["primitive_fault"]["point"] == "outer.subreaper-restore"
        if not kernel.baseline_exact(uncertain_restore):
            raise AssertionError(f"sandbox cleanup baseline drift: {row['id']}")
        if uncertain_restore and kernel.subreaper == 0:
            raise AssertionError("subreaper restore fault did not retain exact uncertainty")
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle or len(rows) != len(declared):
        raise AssertionError("sandbox declared/selected/consumed/oracle mismatch")

from array import array as _BIArray
import fcntl as _BIfcntl
import hashlib as _BIhashlib
import json as _BIjson
import os as _BIos
from pathlib import Path as _BIPath
import shutil as _BIshutil
import socket as _BIsocket
import stat as _BIstat
import struct as _BIstruct
import tempfile as _BItempfile
import types as _BItypes
_BI_OPEN, _BI_CLOSE, _BI_READ, _BI_WRITE = _BIos.open, _BIos.close, _BIos.read, _BIos.write
_BI_FSTAT, _BI_STAT, _BI_PREAD = _BIos.fstat, _BIos.stat, _BIos.pread
_BI_PIPE2, _BI_GETSID, _BI_GETPGID = getattr(_BIos, "pipe2", None), _BIos.getsid, _BIos.getpgid
_BI_FCNTL = _BIfcntl.fcntl
_BI_LEXISTS, _BI_ISMOUNT = _BIos.path.lexists, _BIos.path.ismount
class _BIExit(BaseException):
    pass


class _BISocket:
    def __init__(self, kernel, fd, kind, side=0):
        self.k, self.fd, self.kind, self.side, self.detached = kernel, fd, kind, side, False
        self.queue = []
        self.phase = 0
    def fileno(self):
        return -1 if self.detached else self.fd
    def setsockopt(self, *args):
        del args
    def detach(self):
        self.detached = True
        return self.fd
    def close(self):
        if not self.detached:
            self.k.close(self.fd)
            self.detached = True
    def shutdown(self, direction):
        del direction
        if self.kind == "issue":
            self.k.processes[self.k.worker]["exited"] = True
    def getsockopt(self, level, kind, size):
        del level, kind, size
        peer = self.k.worker if self.kind == "issue" else self.k.outer
        return _BIstruct.pack("3i", peer, _BIos.getuid(), _BIos.getgid())
    def sendmsg(self, parts, ancillary, flags=0):
        del ancillary, flags
        return self.send(b"".join(parts))
    def send(self, data, flags=0):
        del flags
        if self.kind == "issue":
            ack = _BIjson.loads(data)
            if ack != self.k.expected_ack:
                raise AssertionError("modeled issuance acknowledgement drift")
            self.phase = 1
        elif self.kind == "transfer":
            if data != b"A":
                raise AssertionError("modeled transfer acknowledgement drift")
        elif self.kind == "status":
            value = _BIjson.loads(data)
            event = value["event"]
            if event == "prepare-root":
                self.k.make_child(self)
                self.queue.append(self.k.status("child", 2, pid=self.k.child))
            elif event == "release-child":
                self.queue.extend((self.k.boundary(), self.k.status("exec-ready", 4)))
            elif event == "finalize-root":
                self.queue.append(self.k.status("root-final", 5))
            else:
                raise AssertionError(f"unexpected modeled status command: {event}")
        return len(data)
    def recvmsg(self, data_size, control_size, flags=0):
        del data_size, control_size, flags
        if self.kind == "issue" and self.phase == 0:
            self.k.owned.update(self.k.descriptors)
            credentials = (_BIsocket.SOL_SOCKET, _BIsocket.SCM_CREDENTIALS,
                           _BIstruct.pack("3i", self.k.worker, _BIos.getuid(), _BIos.getgid()))
            rights = (_BIsocket.SOL_SOCKET, _BIsocket.SCM_RIGHTS,
                      _BIArray("i", self.k.descriptors).tobytes())
            return self.k.packet, [credentials, rights], 0, None
        if self.kind == "transfer" and self.phase == 0:
            child = self.k.processes[self.k.child]
            lease = _BItypes.SimpleNamespace(
                pid=self.k.child,
                start_time=child["start"],
                session=child["sid"],
                process_group=child["pgid"],
                executable=child["exe"],
            )
            packet = self.k.m._lifecycle_transfer_packet(
                lease, self.k.namespace, b"N" * 32,
                f"tool:{self.k.tool}", "tool",
            )
            pidfd = self.k.alloc("pidfd", pid=self.k.child)
            credentials = (_BIsocket.SOL_SOCKET, _BIsocket.SCM_CREDENTIALS,
                           _BIstruct.pack("3i", self.k.namespace, _BIos.getuid(), _BIos.getgid()))
            rights = (_BIsocket.SOL_SOCKET, _BIsocket.SCM_RIGHTS,
                      _BIArray("i", (pidfd,)).tobytes())
            self.phase = 1
            return packet, [credentials, rights], 0, None
        raise AssertionError("unexpected modeled recvmsg")
    def recv(self, size, flags=0):
        del size, flags
        if self.kind in ("issue", "transfer") and self.phase == 1:
            self.phase = 2
            return b""
        if self.kind == "status" and self.queue:
            return self.queue.pop(0)
        raise AssertionError("modeled socket read without packet")
    def readable(self):
        protocol = self.kind in ("issue", "transfer") and self.phase in (0, 1)
        return protocol or bool(self.queue)


class _BIKernel:
    def __init__(self, module, report, report_bytes, descriptors, rows, root,
                 secondary_clone=0):
        self.m, self.report, self.report_bytes = module, report, report_bytes
        self.descriptors, self.rows, self.root = descriptors, rows, root
        self.outer, self.worker, self.child = 200, None, None
        self.current_pid, self.next_pid, self.next_fd = self.outer, 300, 700
        self.secondary_clone = secondary_clone
        self.clone_count = 0
        self.owned, self.virtual, self.processes, self.sockets = {0, 1, 2}, {}, {}, []
        self.processes[self.outer] = self.proc(1)
        self.tool, self.namespace, self.input_pipe, self.output_pipe = None, None, None, None
        self.transfer_mode = module._namespace_owner.__code__.co_argcount > 8
        self.pipe_order, self.root_mounted, self.events = [], False, []
        self.baseline_ns = {name: (71, 100 + i) for i, name in enumerate(("user", "pid", "mnt", "net"))}
        self.tool_ns = {name: (81, 200 + i) for i, name in enumerate(("user", "pid", "mnt", "net"))}
        self.packet, self.expected_ack = self.issuance()
        self.libc = type("Libc", (), {"prctl": lambda *args: 0})()
    def proc(self, parent):
        return {
            "parent": parent,
            "start": self.next_pid + 1000,
            "sid": self.outer,
            "pgid": self.outer,
            "exe": (8, 808),
            "exited": False,
            "reaped": False,
            "status": 0,
            "gate": None,
        }
    def alloc(self, kind, **values):
        while self.next_fd in self.owned:
            self.next_fd += 1
        fd = self.next_fd
        self.next_fd += 1
        self.virtual[fd] = {"kind": kind, "offset": 0, **values}
        self.owned.add(fd)
        return fd
    def issuance(self):
        binding = self.m._digest([self.m._binding_value(row) for row in self.rows])
        generation = self.m._digest([self.m._generation_value(row) for row in self.rows])
        report_sha = _BIhashlib.sha256(self.report_bytes).hexdigest()
        nonce = (b"N" * 32).hex()
        packet = {"binding_sha256": binding, "closure_sha256": self.report["closure_sha256"],
                  "descriptor_count": len(self.descriptors),
                  "generation_rows": [self.m._row_value(row) for row in self.rows],
                  "generation_sha256": generation, "nonce": nonce,
                  "report_sha256": report_sha, "revision": "0" * 40,
                  "source_set_sha256": "1" * 64, "version": self.m._HANDOFF_VERSION}
        ack = {"binding_sha256": binding, "consumer_pid": self.outer,
               "generation_sha256": generation, "nonce": nonce,
               "report_sha256": report_sha, "version": self.m._HANDOFF_VERSION}
        return self.m._canonical(packet), ack
    def status(self, event, sequence, **fields):
        return self.m._status(event, sequence, **fields)
    def boundary(self):
        caps = {"effective": 0, "permitted": 0, "inheritable": 0,
                "bounding": [0], "ambient": [0], "groups": []}
        denials = {name: 1 for name in set(self.m._DENIED_SYSCALLS) | {"prctl:set", "execveat:shape"}}
        obs = {"capability_sets": caps, "securebits": self.m._SECBITS, "no_new_privs": 1,
               "seccomp_installed": True, "seccomp_denials": denials,
               "seccomp_mode": self.m._SECCOMP_MODE_FILTER,
               "seccomp_program_sha256": self.m._seccomp_digest()}
        return self.status("boundary", 3, observations=obs)
    def make_child(self, endpoint):
        self.child = self.next_pid
        self.next_pid += 1
        self.processes[self.child] = self.proc(self.namespace)
        endpoint.child = self.child
    def nonce(self): return b"N" * 32
    def socketpair(self):
        index = len(self.sockets) // 2
        if index == 0:
            kind = "issue"
        elif index == 1:
            kind = "helper"
        elif self.transfer_mode:
            kind = "status" if index % 2 == 0 else "transfer"
        else:
            kind = "status"
        left = _BISocket(self, self.alloc("socket"), kind, 0)
        right = _BISocket(self, self.alloc("socket"), kind, 1)
        self.sockets.extend((left, right))
        if kind == "status":
            self.tool = "gzip" if index == 2 else "zstd"
        return left, right
    def pipe2(self, flags):
        del flags
        resource = {"data": bytearray(), "read_closed": False, "write_closed": False,
                    "child_writer": False, "purpose": "plain"}
        r = self.alloc("pipe", resource=resource, end="read")
        w = self.alloc("pipe", resource=resource, end="write")
        self.pipe_order.append((r, w, resource))
        return r, w
    def clone_pidfd(self):
        pid = self.next_pid
        self.next_pid += 1
        self.processes[pid] = self.proc(self.outer)
        self.clone_count += 1
        self.processes[pid]["gate"] = self.pipe_order[-1][2]
        if self.clone_count == self.secondary_clone:
            self.events.append(f"tool:secondary-pidfd:{self.clone_count}")
            return pid, -1
        pidfd = self.alloc("pidfd", pid=pid)
        if self.worker is None:
            self.worker = pid
        else:
            self.namespace = pid
            self.processes[pid]["tool"] = self.tool
            self.input_pipe, self.output_pipe = self.pipe_order[-3][2], self.pipe_order[-2][2]
            self.output_pipe["child_writer"] = True
            status = next(s for s in reversed(self.sockets) if s.kind == "status" and s.side == 0)
            status.queue.append(self.status("namespace", 1))
        return pid, pidfd
    def pidfd_open(self, pid, flags=0):
        del flags
        return self.alloc("pidfd", pid=pid)
    def open(self, path, flags, mode=0o600, **kwargs):
        if "/map_files/" in path:
            index = int(path.rsplit("/", 1)[1].split("-", 1)[0], 16) // 0x1000 - 1
            row = [r for r in self.rows if r.tool_index == self.m._TOOL_INDEX[self.tool]][index]
            source = self.descriptors[row.descriptor_index]
            info = _BI_FSTAT(source)
            data = _BI_PREAD(source, row.size, 0)
            return self.alloc("proc", path=path, data=bytearray(data), identity=(info.st_dev, info.st_ino))
        if path.startswith("/proc/"):
            return self.alloc("proc", path=path)
        fd = _BI_OPEN(path, flags, mode, **kwargs)
        self.owned.add(fd)
        return fd
    def close(self, fd):
        if fd not in self.owned: return
        self.owned.remove(fd)
        value = self.virtual.pop(fd, None)
        if value and value["kind"] == "pipe":
            resource = value["resource"]
            resource[value["end"] + "_closed"] = True
            if value["end"] == "write":
                for process in self.processes.values():
                    if (process["gate"] is resource and not resource["data"]
                            and not process["exited"]):
                        process["exited"] = True
                        process["status"] = 125
                if resource is self.input_pipe:
                    self.finish_tool_input()
        elif value is None and fd > 2:
            _BI_CLOSE(fd)
    def finish_tool_input(self):
        if self.input_pipe is None: return
        if bytes(self.input_pipe["data"]) != self.m._FIXED_INPUT[self.tool]:
            raise AssertionError("modeled fixed input drift")
        self.output_pipe["data"].extend(self.m._FIXED_OUTPUT)
        self.output_pipe["child_writer"] = False
    def read(self, fd, size):
        value = self.virtual[fd]
        if value["kind"] == "pipe":
            data = value["resource"]["data"]
            result = bytes(data[:size])
            del data[:len(result)]
            if not result and not value["resource"]["child_writer"] and value["resource"] is self.output_pipe:
                self.finish_processes()
            return result
        raw = self.proc_bytes(value["path"])
        offset = value["offset"]
        value["offset"] += min(size, max(0, len(raw) - offset))
        return raw[offset:offset + size]
    def write(self, fd, data):
        value = self.virtual.get(fd)
        if value and value["kind"] == "pipe": value["resource"]["data"].extend(data)
        elif value: value.setdefault("data", bytearray()).extend(data)
        else: return _BI_WRITE(fd, data)
        return len(data)
    def finish_processes(self):
        if self.child is None or self.processes[self.child]["exited"]: return
        self.processes[self.child]["exited"] = True
        self.processes[self.child]["reaped"] = True
        self.processes[self.namespace]["exited"] = True
        self.root_mounted = False
        for child in _BIPath(self.root).iterdir():
            if child.is_dir(): _BIshutil.rmtree(child)
            else: child.unlink()
        status = next(s for s in reversed(self.sockets) if s.kind == "status" and s.side == 0)
        status.queue.append(self.status("exit", 6, status=0))
    def getdents(self, fd, maximum=32768):
        del maximum
        value = self.virtual[fd]
        if value.get("done"): return b""
        value["done"] = True
        path = value["path"]
        values = (0, 1, 2) if path != "/proc/self/fd" else tuple(sorted(self.owned))
        return dirents(values)
    def fstat(self, fd):
        value = self.virtual.get(fd)
        if not value: return _BI_FSTAT(fd)
        if value["kind"] == "proc" and "/ns/" in value["path"]:
            ident = self.namespace_identity(value["path"])
        elif value["kind"] == "proc" and value["path"].endswith("/exe"):
            pid = int(value["path"].split("/")[2])
            ident = self.processes[pid]["exe"]
        elif value["kind"] == "authority" or "identity" in value: ident = value["identity"]
        else: ident = (2, fd)
        mode = _BIstat.S_IFDIR | 0o700 if value["kind"] == "proc" and value["path"].endswith("/fd") else _BIstat.S_IFREG | 0o444
        return type("S", (), {"st_dev": ident[0], "st_ino": ident[1], "st_mode": mode,
            "st_uid": _BIos.geteuid(), "st_gid": _BIos.getegid(), "st_size": len(value.get("data", b"")),
            "st_mtime_ns": 1, "st_ctime_ns": 1})()
    def stat(self, path, **kwargs):
        if "/ns/" in path:
            ident = self.namespace_identity(path)
            return type("S", (), {"st_dev": ident[0], "st_ino": ident[1]})()
        return _BI_STAT(path, **kwargs)
    def namespace_identity(self, path):
        name = path.rsplit("/", 1)[1].replace("pid_for_children", "pid")
        parts = path.split("/")
        pid = self.outer if parts[2] == "self" else int(parts[2])
        return self.baseline_ns[name] if pid == self.outer else self.tool_ns[name]
    def ioctl(self, fd, request):
        value = self.virtual[fd]
        name = value["path"].rsplit("/", 1)[1]
        ident = self.baseline_ns["pid"] if request == self.m._NS_GET_PARENT else self.tool_ns["user"]
        return self.alloc("authority", identity=ident, name=name)
    def proc_bytes(self, path):
        if path.endswith("/fd"): return b""
        if path.endswith("/children"):
            parent = self.outer if "/self/" in path else int(path.split("/")[2])
            children = [pid for pid, p in self.processes.items() if p["parent"] == parent and not p["exited"]]
            return b"".join(f"{pid} ".encode() for pid in sorted(children))
        if path.endswith("/stat"):
            pid = int(path.split("/")[2])
            start = self.processes[pid]["start"]
            return f"{pid} (modeled) S ".encode() + b" ".join([b"1"] * 18 + [str(start).encode()] + [b"1"] * 30) + b"\n"
        if path.endswith("/limits"):
            return b"Limit                     Soft Limit           Hard Limit           Units\n"
        if path.endswith("/status"):
            return (f"NSpid:\t{self.child}\t1\n".encode() + b"Groups:\t\nCapInh:\t0000000000000000\n"
                    b"CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
                    b"CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
        if path.endswith("/uid_map"): return f"0 {_BIos.getuid()} 1\n".encode()
        if path.endswith("/gid_map"): return f"0 {_BIos.getgid()} 1\n".encode()
        if path.endswith("/mountinfo"): return b"1 0 0:1 / / ro,nosuid,nodev,noexec - tmpfs tmpfs ro\n"
        if path.endswith("/maps"): return self.maps()
        if "/map_files/" in path:
            index = int(path.rsplit("/", 1)[1].split("-", 1)[0], 16) // 0x1000 - 1
            row = [r for r in self.rows if r.tool_index == self.m._TOOL_INDEX[self.tool]][index]
            data = _BI_PREAD(self.descriptors[row.descriptor_index], row.size, 0)
            self.virtual[next(fd for fd, v in self.virtual.items() if v.get("path") == path)]["data"] = bytearray(data)
            return data
        raise AssertionError(f"unmodeled proc path: {path}")
    def maps(self):
        selected = [r for r in self.rows if r.tool_index == self.m._TOOL_INDEX[self.tool]]
        lines = []
        for i, row in enumerate(selected, 1):
            info = _BI_FSTAT(self.descriptors[row.descriptor_index])
            start = i * 0x1000
            lines.append(f"{start:08x}-{start+0x1000:08x} r-xp 00000000 {_BIos.major(info.st_dev):02x}:{_BIos.minor(info.st_dev):02x} {info.st_ino} /tool\n".encode())
        return b"".join(lines)
    def pread(self, fd, size, offset):
        value = self.virtual.get(fd)
        if value is None: return _BI_PREAD(fd, size, offset)
        if value["kind"] == "proc" and "/map_files/" in value["path"] and "data" not in value: self.proc_bytes(value["path"])
        return bytes(value.get("data", b""))[offset:offset + size]
    def select(self, readers, writers, errors, timeout=0):
        del errors, timeout
        ready = []
        for item in readers:
            if isinstance(item, _BISocket) and item.readable(): ready.append(item)
            elif isinstance(item, int):
                value = self.virtual.get(item)
                if value and value["kind"] == "pidfd" and self.processes[value["pid"]]["exited"]: ready.append(item)
                elif value and value["kind"] == "pipe":
                    resource = value["resource"]
                    if resource["data"] or (resource is self.output_pipe and not resource["child_writer"]): ready.append(item)
        return ready, list(writers), []
    def waitpid(self, pid, flags):
        del flags
        process = self.processes[pid]
        if not process["exited"]:
            return 0, 0
        process["reaped"] = True
        return pid, process["status"] << 8
    def getsid(self, pid): return self.processes[self.current_pid if pid == 0 else pid]["sid"]
    def getpgid(self, pid): return self.processes[self.current_pid if pid == 0 else pid]["pgid"]
    def prctl(self, option, value=0, arg3=0):
        del option, value, arg3
        return 0
    def mount(self, source, target, kind, flags, data):
        del kind, data
        if source == b"tmpfs": self.root_mounted = True
    def umount(self, target):
        del target
        self.finish_processes()
    def lexists(self, path):
        if path.startswith("/proc/") and "/root/" in path: return False
        return _BI_LEXISTS(path)
    def ismount(self, path): return self.root_mounted if path == self.root else _BI_ISMOUNT(path)


class _BIChildSocket:
    """Child-side protocol endpoint used by the split process execution model."""
    def __init__(self, kernel, fd, kind, commands=()):
        self.k, self.fd, self.kind = kernel, fd, kind
        self.commands, self.closed = list(commands), False
    def fileno(self): return -1 if self.closed else self.fd
    def close(self):
        if not self.closed: self.k.close(self.fd)
        self.closed = True
    def detach(self):
        self.closed = True
        return self.fd
    def setsockopt(self, *args): del args
    def shutdown(self, direction): del direction
    def readable(self): return bool(self.commands)
    def send(self, raw, flags=0):
        del flags
        value = _BIjson.loads(raw)
        expected = {"namespace": 1, "child": 2, "boundary": 3, "exec-ready": 4,
                    "root-final": 5, "exit": 6, "error": value.get("sequence"), "unavailable": value.get("sequence")}
        if value.get("sequence") != expected.get(value.get("event")):
            raise AssertionError(f"modeled child status drift: {value}")
        self.k.events.append(f"namespace:{self.k.tool}:{value['event']}")
        return len(raw)
    def sendmsg(self, parts, ancillary, flags=0):
        del flags
        raw = b"".join(parts)
        value = _BIjson.loads(raw)
        rights = [entry for entry in ancillary if entry[1] == _BIsocket.SCM_RIGHTS]
        exact = (value.get("pid"), value.get("parent"), value.get("case"), value.get("role"))
        exact = exact == (self.k.child, self.k.namespace, f"tool:{self.k.tool}", "tool")
        if not exact or len(rights) != 1:
            raise AssertionError("modeled child transfer drift")
        self.k.events.append(f"namespace:{self.k.tool}:transfer")
        return len(raw)
    def recv(self, size, flags=0):
        del size, flags
        if self.kind == "transfer":
            self.commands.clear()
            return b"A"
        if not self.commands: raise AssertionError("modeled child command underflow")
        raw = self.commands.pop(0)
        if _BIjson.loads(raw)["event"] == "finalize-root":
            self.k.processes[self.k.child]["exited"] = True
        return raw


def _modeled_worker_execution(module, admission, kernel):
    """Execute the real worker body as its own modeled child process."""
    release_fd = kernel.alloc("pipe", resource={"data": bytearray(b"G"),
        "read_closed": False, "write_closed": True, "child_writer": False}, end="read")
    endpoint_fd, helper_fd = kernel.alloc("socket"), kernel.alloc("socket")
    sockets = {fd: _BIChildSocket(kernel, fd, "worker") for fd in (endpoint_fd, helper_fd)}
    events = []
    receipt = module._IssuanceReceipt(module._HANDOFF_VERSION, "0" * 64, "1" * 64,
        "2" * 64, "3" * 64, len(kernel.descriptors), kernel.worker, kernel.outer)
    class Owner:
        def _issue_once(self, issuer):
            if type(issuer) is not module._WorkerIssuer:
                raise AssertionError("worker did not construct production issuer")
            events.append("worker:issue")
            return receipt
        def close(self): events.append("worker:close")
    closure = _BItypes.ModuleType("modeled.closure")
    closure.__package__ = "modeled"
    closure._prepare_admitted_fixed_runtime_closure = lambda claimed, issuer: (
        events.append("worker:prepare") or Owner()
    )
    def child_socket(*args, **kwargs): return sockets[kwargs["fileno"]]
    def child_exit(code): events.append(f"worker:exit:{code}")
    with patched(module, _SystemOps=lambda: kernel), patched(module.socket, socket=child_socket), patched(
        module.os, getpid=lambda: kernel.worker, getppid=lambda: kernel.outer,
        setsid=lambda *args: None, _exit=child_exit):
        module._worker_main(endpoint_fd, helper_fd, release_fd, b"N" * 32,
                            admission, closure, kernel.outer)
    if events != ["worker:prepare", "worker:issue", "worker:close", "worker:exit:0"]:
        raise AssertionError(f"worker child state machine drift: {events}")
    return "worker"


def _modeled_namespace_execution(module, report, descriptors, rows, role):
    root_parent = _BItempfile.mkdtemp()
    root = f"{root_parent}/{module._ROOT_LEAF}"
    _BIos.mkdir(root, 0o700)
    copied = tuple(_BIos.dup(fd) for fd in descriptors)
    kernel = _BIKernel(module, report, module._canonical(report), copied, rows, root)
    kernel.worker, kernel.tool = 299, role
    input_fd, output_fd = kernel.pipe2(0)[0], kernel.pipe2(0)[1]
    status_fd, transfer_fd = kernel.alloc("socket"), kernel.alloc("socket")
    commands = tuple(module._status(name, sequence) for name, sequence in (
        ("prepare-root", 1), ("release-child", 2), ("finalize-root", 3)))
    status = _BIChildSocket(kernel, status_fd, "status", commands)
    transfer = _BIChildSocket(kernel, transfer_fd, "transfer", (b"A",))
    kernel.sockets.extend((status, transfer))
    def child_clone():
        pid, kernel.next_pid = kernel.next_pid, kernel.next_pid + 1
        kernel.child = pid
        kernel.processes[pid] = kernel.proc(kernel.namespace)
        pidfd = kernel.alloc("pidfd", pid=pid)
        kernel.pipe_order[-2][2]["data"].extend(kernel.boundary())
        return pid, pidfd
    kernel.clone_pidfd = child_clone
    def child_socket(*args, **kwargs):
        return {status_fd: status, transfer_fd: transfer}[kwargs["fileno"]]
    def child_dup2(source, target, inheritable=True):
        del inheritable
        kernel.virtual[target] = {"kind": "identity", "identity": (2, source)}
        kernel.owned.add(target)
        return target
    def child_umount(target):
        del target
        kernel.root_mounted = False
        for current, directories, files in _BIos.walk(root, topdown=False):
            for name in files: _BIos.unlink(f"{current}/{name}")
            for name in directories: _BIos.rmdir(f"{current}/{name}")
    child_exits = []
    def child_exit(code):
        child_exits.append(code)
        if code: raise AssertionError(f"modeled namespace failure: {role} {kernel.events}")
    def child_select(readers, writers, errors, timeout=0):
        ordinary = [item for item in readers if not isinstance(item, _BIChildSocket)]
        ready, writable, exceptional = kernel.select(ordinary, writers, errors, timeout)
        for item in ordinary:
            value = kernel.virtual.get(item) if isinstance(item, int) else None
            if value and value["kind"] == "pipe" and value["resource"]["write_closed"] and item not in ready:
                ready.append(item)
        ready.extend(item for item in readers if isinstance(item, _BIChildSocket) and item.readable())
        return ready, writable, exceptional
    def modeled_fcntl(fd, command, *args):
        if fd in kernel.virtual and command == _BIfcntl.F_GETFD:
            return _BIfcntl.FD_CLOEXEC
        if fd in copied and command == module._F_GET_SEALS:
            return module._DATA_SEALS if fd == copied[0] else module._EXEC_SEALS
        if fd in copied and command == _BIfcntl.F_GETFL: return _BIos.O_RDONLY
        return _BI_FCNTL(fd, command, *args)
    kernel.unshare_boundary = lambda *args: None
    kernel.umount = child_umount
    with patched(module, _SystemOps=lambda: kernel), patched(module.socket, socket=child_socket), patched(
        module.os, open=kernel.open, close=kernel.close, read=kernel.read, write=kernel.write,
        pipe2=kernel.pipe2, fstat=kernel.fstat, stat=kernel.stat, pread=kernel.pread,
        dup2=child_dup2, getpid=lambda: kernel.namespace, getppid=lambda: kernel.outer,
        pidfd_open=kernel.pidfd_open, getsid=kernel.getsid, getpgid=kernel.getpgid,
        waitpid=kernel.waitpid, setsid=lambda *args: None, setgroups=lambda groups: None,
        chdir=lambda path: None, _exit=child_exit), patched(module.fcntl, fcntl=modeled_fcntl), patched(
        module.select, select=child_select), patched(module.os.path, ismount=kernel.ismount):
        module._namespace_owner(role, copied, rows, report, input_fd, output_fd,
                                status_fd, transfer_fd, b"N" * 32, root)
    expected = [f"namespace:{role}:{name}" for name in
                ("namespace", "transfer", "child", "boundary", "exec-ready", "root-final", "exit")]
    try:
        if kernel.events != expected or child_exits != [0]:
            raise AssertionError(f"namespace child state machine drift: {role} {kernel.events}/{child_exits}")
        return f"namespace:{role}"
    finally:
        for fd in copied:
            if fd in kernel.owned: kernel.close(fd)
        _BIshutil.rmtree(root_parent)


def production_runtime_compression_contracts(module):
    """Drive both production launchers through their unpatched parent state machines."""
    if not hasattr(module.os, "O_PATH"): module.os.O_PATH = 0x200000
    if not hasattr(module.socket, "SCM_CREDENTIALS"): module.socket.SCM_CREDENTIALS = 2
    if not hasattr(module.socket, "MSG_CMSG_CLOEXEC"): module.socket.MSG_CMSG_CLOEXEC = 0x40000000
    with _BItempfile.TemporaryDirectory() as bundle_dir, _BItempfile.TemporaryDirectory() as root_parent:
        report_bytes, descriptors, rows = valid_bundle(module, bundle_dir)
        report = module._decode_report(report_bytes)
        old_root = module._ROOT_PARENT
        fixture_path = FIXTURE.parent / "tool-process-cases.jsonl"
        fixture_document = [json.loads(line) for line in fixture_path.read_text().splitlines()]
        fixture_header, *fixture_cases = fixture_document
        fixture_fields = {
            "cleanup_domains", "id", "intended_code", "primitive_fault",
            "production_method", "sentinel",
        }
        expected_header = {
            "type": "header",
            "version": "cogs.outcome-two-tool-process/v1",
            "acceptance_ids": ["AT93-B-01", "AT93-INTEGRATION-01"],
            "case_fields": sorted(fixture_fields),
        }
        if fixture_header != expected_header:
            raise AssertionError("tool process fixture header")
        declared = [case["id"] for case in fixture_cases]
        selected = []
        consumed = []
        oracle = []
        runtime_result = None
        try:
            module._ROOT_PARENT = root_parent
            for case in fixture_cases:
                if set(case) != fixture_fields:
                    raise AssertionError(f"tool process row shape: {case['id']}")
                selected.append(case["id"])
                launcher = getattr(module, case["production_method"])
                expected_type = (
                    module.RuntimeQualificationResult
                    if "runtime_qualification" in case["production_method"]
                    else module.RuntimeCompressionQualificationResult
                )
                duplicated = tuple(_BIos.dup(fd) for fd in descriptors)
                selected_clone = case["primitive_fault"]["clone"]
                kernel = _BIKernel(
                    module, report, report_bytes, duplicated, rows,
                    f"{root_parent}/{module._ROOT_LEAF}", selected_clone,
                )
                admission = module._SourceAdmission("0" * 40, "0" * 64, "1" * 64,
                    (ROOT / "schemas/trusted-runtime-closure-v1.json").read_bytes(), "", 0,
                    None, object(), kernel.outer, _BIos.getuid(), _BIos.getgid(), "runtime")
                actual_fcntl = module.fcntl.fcntl
                def modeled_fcntl(fd, command, *args):
                    if fd in duplicated and command == module._F_GET_SEALS:
                        return module._DATA_SEALS if fd == duplicated[0] else module._EXEC_SEALS
                    if fd in duplicated and command == _BIfcntl.F_GETFL: return _BIos.O_RDONLY
                    return _BI_FCNTL(fd, command, *args)
                error = None
                value = None
                owner_calls = []
                actual_worker = module._worker_main
                actual_namespace = module._namespace_owner
                def observed_worker(*args, **kwargs):
                    owner_calls.append("worker")
                    return actual_worker(*args, **kwargs)
                def observed_namespace(*args, **kwargs):
                    owner_calls.append("namespace")
                    return actual_namespace(*args, **kwargs)
                with patched(
                    module,
                    _SystemOps=lambda: kernel,
                    _worker_main=observed_worker,
                    _namespace_owner=observed_namespace,
                ), patched(module.os,
                    open=kernel.open, close=kernel.close, read=kernel.read, write=kernel.write,
                    pipe2=kernel.pipe2, fstat=kernel.fstat, stat=kernel.stat, pread=kernel.pread,
                    getpid=lambda: kernel.outer, getppid=lambda: 1, pidfd_open=kernel.pidfd_open,
                    getsid=kernel.getsid, getpgid=kernel.getpgid, waitpid=kernel.waitpid), patched(
                    module.fcntl, fcntl=modeled_fcntl, ioctl=kernel.ioctl), patched(
                    module.select, select=kernel.select), patched(module.os.path,
                    lexists=kernel.lexists, ismount=kernel.ismount):
                    try:
                        value = launcher(admission, _BItypes.ModuleType("modeled.closure"), kernel)
                    except BaseException as caught:
                        error = caught
                child_evidence = []
                if error is None:
                    child_evidence.append(_modeled_worker_execution(module, admission, kernel))
                    child_evidence.append(_modeled_namespace_execution(module, report, descriptors, rows, "gzip"))
                    child_evidence.append(_modeled_namespace_execution(module, report, descriptors, rows, "zstd"))
                expected_accept = case["primitive_fault"]["expect"] == "accept"
                if (error is None) != expected_accept:
                    raise AssertionError(f"tool process oracle mismatch: {case['id']} {error!r}")
                actual_code = "accept" if error is None else getattr(
                    error, "code", type(error).__name__
                )
                if actual_code != case["intended_code"]:
                    raise AssertionError(
                        f"tool process code mismatch: {case['id']} {actual_code!r}"
                    )
                if selected_clone:
                    expected_event = f"tool:secondary-pidfd:{selected_clone}"
                    if kernel.events != [expected_event] or case["sentinel"] != expected_event:
                        raise AssertionError(f"tool process causal cut mismatch: {case['id']}")
                else:
                    runtime = value if type(value) is module.RuntimeQualificationResult else value.runtime
                    if type(value) is not expected_type or not all(
                        getattr(runtime, name) for name in module._OBSERVATION_NAMES
                    ):
                        raise AssertionError("production launcher result drift")
                    if owner_calls or child_evidence != [
                        "worker", "namespace:gzip", "namespace:zstd",
                    ]:
                        raise AssertionError(
                            "B/integration split child state machines bypassed: "
                            f"parent={owner_calls}, child={child_evidence}"
                        )
                    kernel.events.append("tool:complete")
                    if case["sentinel"] != "tool:complete":
                        raise AssertionError("tool complete sentinel drift")
                    if expected_type is module.RuntimeQualificationResult:
                        runtime_result = module._result_value(runtime)
                unsettled = [
                    pid for pid, process in kernel.processes.items()
                    if pid != kernel.outer and (not process["exited"] or not process["reaped"])
                ]
                if kernel.owned != {0, 1, 2} or unsettled:
                    raise AssertionError(f"tool process cleanup drift: {case['id']} {unsettled}")
                consumed.append(case["id"])
                oracle.append(case["id"])
            if not declared == selected == consumed == oracle:
                raise AssertionError("tool process declared/selected/consumed/oracle mismatch")
            if len(declared) != len(set(declared)):
                raise AssertionError("duplicate tool process fixture identity")
        finally:
            module._ROOT_PARENT = old_root
            for fd in descriptors:
                try: _BI_CLOSE(fd)
                except OSError: pass
        if runtime_result is None:
            raise AssertionError("production runtime result missing")
        return runtime_result


def sticky_root_replacement(module):
    class Ops:
        @staticmethod
        def open(path, flags, mode=0o600):
            return os.open(path, flags, mode)

        @staticmethod
        def close(fd):
            os.close(fd)

    with tempfile.TemporaryDirectory() as parent_directory:
        old_parent = module._ROOT_PARENT
        module._ROOT_PARENT = parent_directory
        owner = module._RootOwner(Ops())
        try:
            owner.prepare()
            leaf = Path(parent_directory) / module._ROOT_LEAF
            os.rmdir(leaf)
            os.mkdir(leaf, 0o700)
            try:
                owner.cleanup()
            except module.RuntimeLauncherCleanupError as error:
                if not any(getattr(item, "code", None) == "root-replaced" for item in error.failures):
                    raise AssertionError("replacement cleanup classification") from error
            else:
                raise AssertionError("replacement root removed")
            if not leaf.is_dir():
                raise AssertionError("sticky-parent cleanup removed replacement")
            leaf.rmdir()
        finally:
            module._ROOT_PARENT = old_parent


def parent():
    module = load_module()
    if not hasattr(module.os, "O_PATH"):
        module.os.O_PATH = 0x200000
    if not hasattr(module.os, "pipe2"):
        module.os.pipe2 = lambda flags: os.pipe()
    if not hasattr(module.socket, "SCM_CREDENTIALS"):
        module.socket.SCM_CREDENTIALS = 2
    if not hasattr(module.socket, "MSG_CMSG_CLOEXEC"):
        module.socket.MSG_CMSG_CLOEXEC = 0x40000000
    if module._ROOT_PARENT != "/tmp":
        raise AssertionError("private runtime root is not fixed beneath /tmp")
    launcher_source = MODULE.read_text()
    common_source = COMMON.read_text()
    admission = common_source.index("held, digest = self._admit_sources(context, root)")
    compilation = common_source.index("self._issue_cli(held[LAUNCHER_PATH].raw, admission, capsule)")
    if admission > compilation or "open(ROOT" in launcher_source:
        raise AssertionError("held source admission/compilation order drift")
    banned = ("_MappingAuthority", "_coordinate_admitted_mapping_only")
    required = (
        "_qualify_admitted_fixed_python_mapping",
        "_launch_admitted_fixed_compression_qualification",
        "_qualify_admitted_fixed_descriptor_primitives",
        "_qualify_admitted_fixed_process_lifecycle",
        "_launch_admitted_fixed_sandbox_qualification",
        'None if mode in ("lifecycle", "sandbox") else _load_private_closure',
    )
    if any(token in launcher_source for token in banned):
        raise AssertionError("fixed admitted production routing drift")
    if not all(token in launcher_source for token in required):
        raise AssertionError("fixed admitted production routing drift")
    dead_api = "invoke_fixed_admitted_operation"
    cli_tokens = ("/usr/bin/python3", '"-I"', '"-B"', "_bootstrap_main")
    if hasattr(module, dead_api) or dead_api in common_source:
        raise AssertionError("common retained the dead ambient launcher bridge")
    if not all(token in launcher_source + common_source for token in cli_tokens):
        raise AssertionError("fixed CLI issuer integration is absent")
    production_operation_contracts(module)
    capsule_contract(module)
    fixed_bootstrap_modes(module)
    outer_process_corpus(module)
    production_runtime_compression_contracts(module)
    full_sandbox_launch_contract(module)
    sandbox_process_corpus(module)
    sticky_root_replacement(module)
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

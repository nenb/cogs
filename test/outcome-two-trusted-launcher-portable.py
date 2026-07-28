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
import socket
import stat
import struct
import sys
import tempfile
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
    authority = module._root_capsule_authority(sources, admission)
    capsule = module._encode_root_capsule(sources, admission)
    decoded, header = module._decode_root_capsule(capsule, authority)
    if decoded != sources or header["parent_pid"] != os.getpid():
        raise AssertionError("held root capsule round trip")
    bootstrap = module._render_root_bootstrap(authority)
    authority_check = bootstrap.index("rows == authority['sources']")
    compilation = bootstrap.index("exec(compile(launcher")
    if authority_check > compilation or "__ROOT_AUTHORITY_HEX__" in bootstrap:
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
        try:
            module._decode_root_capsule(hostile, authority)
        except module.RuntimeLauncherError as error:
            if error.code != "root-authority":
                raise
        else:
            raise AssertionError(f"root accepted unauthorized {path} generation")
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
    required = ("object_pairs_hook=pairs", "parent_pid", "source_set_sha256",
                "os.getppid() == parent", "numbers.count(directory) == 1",
                "offset == len(payload)")
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


def common_production_adapters():
    spec = importlib.util.spec_from_file_location("native_qualification_common_portable", COMMON)
    common = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = common
    spec.loader.exec_module(common)
    sys.modules.pop(spec.name)
    marker_digest = hashlib.sha256(b"cogs-runtime-qualification-v1\n").hexdigest()

    def result_for(module, mode, revision, source_digest):
        ordinary = module.RuntimeQualificationResult(
            module._RESULT_VERSION, module._MARKER, revision, source_digest,
            "a" * 64, marker_digest, marker_digest,
            *(True for _name in module._OBSERVATION_NAMES),
        )
        if mode == "runtime":
            return ordinary
        if mode == "descriptor":
            names = tuple(item.name for item in module.fields(module.DescriptorQualificationResult))
            return module.DescriptorQualificationResult(
                "cogs.runtime-descriptor-qualification/v1", revision, source_digest,
                *(True for _name in names[3:]),
            )
        if mode == "lifecycle":
            names = tuple(item.name for item in module.fields(module.LifecycleQualificationResult))
            return module.LifecycleQualificationResult(
                "cogs.runtime-lifecycle-qualification/v1", revision, source_digest,
                *(True for _name in names[3:]),
            )
        if mode == "sandbox":
            names = tuple(item.name for item in module.fields(module.SandboxQualificationResult))
            return module.SandboxQualificationResult(
                "cogs.sandbox-qualification/v1", revision, source_digest,
                "b" * 64, *(True for _name in names[4:]),
            )
        objects = (
            module.RuntimeObjectObservation("executable", 7, "c" * 64, None, ()),
            module.RuntimeObjectObservation("loader", 8, "d" * 64, "ld.so", ()),
        )
        mapped = tuple(module.MappedObjectObservation(row.role, row.sha256) for row in objects)
        if mode == "mapping":
            return module.RuntimeMappingQualificationResult(
                "cogs.runtime-mapping-qualification/v1", revision, source_digest,
                "e" * 64, "f" * 64, objects, mapped, True, True, True, True, True,
            )
        object_values = tuple({
            "needed": row.needed, "role": row.role, "sha256": row.sha256,
            "size_bytes": row.size_bytes, "soname": row.soname,
        } for row in objects)
        tools = tuple(module.RuntimeCompressionToolObservation(
            name, object_values, "e" * 64, "f" * 64, objects[0].sha256,
            objects[0].size_bytes, objects[0].sha256, objects[0].size_bytes,
            63, "f" * 64, marker_digest,
        ) for name in ("gzip", "zstd"))
        parser = module.RuntimeCompressionParserObservation(
            ordinary.closure_sha256,
            object_values,
        )
        return module.RuntimeCompressionQualificationResult(
            "cogs.runtime-compression-qualification/v1", revision,
            source_digest, ordinary.closure_sha256, parser, tools, ordinary,
        )

    class PortableOps(common.SystemCommonOps):
        def __init__(self):
            super().__init__(common.FdRegistry())
            self.routes, self.modules = [], []
            self.baseline = {name: ("held", name) for name in common.CLEANUP_KEYS}
            self.baseline["paths"] = (None, None)
        def observe(self, context):
            del context
            return dict(self.baseline)
        def _git_tree(self, root, revision, paths):
            del root
            if revision != "0" * 40:
                return {}
            rows = {}
            for path in paths:
                data = (ROOT / path).read_bytes()
                blob = b"blob " + str(len(data)).encode() + b"\0" + data
                rows[path] = hashlib.sha1(blob).hexdigest()
            return rows
        def _launcher(self, source):
            module = super()._launcher(source)
            self.modules.append(module)
            def invoke(operation, revision, held_sources, client, source_digest):
                expected_mode = {
                    "A": "mapping", "B": "compression", "C": "descriptor",
                    "D": "lifecycle", "E": "sandbox", "integration": "runtime",
                }[operation]
                if type(held_sources) is not __import__("types").MappingProxyType:
                    raise AssertionError("common did not retain an immutable held source map")
                if client != (ROOT / module._OPERATION_CLIENTS[expected_mode]).read_bytes():
                    raise AssertionError("common did not retain the admitted client generation")
                if module._source_set_digest(dict(held_sources)) != source_digest:
                    raise AssertionError("common source framing diverged")
                self.routes.append(expected_mode)
                return result_for(module, expected_mode, revision, source_digest)
            module.invoke_fixed_admitted_operation = invoke
            return module

    expected_modes = {
        "A": "mapping", "B": "compression", "C": "descriptor",
        "D": "lifecycle", "E": "sandbox", "integration": "runtime",
    }
    for job, mode in expected_modes.items():
        ops = PortableOps()
        context = SimpleNamespace(job=job, head_sha="0" * 40)
        custodian = SimpleNamespace(abort=lambda error: None)
        session = common.NativeSession._begin_with_ops(context, ops, custodian)
        value = session.run_fixed_operation(job)
        if ops.routes != [mode] or type(value) is not dict:
            raise AssertionError(f"common fixed route drift: {job}/{ops.routes}")
        if value["source_set_sha256"] != session.source_set_sha256:
            raise AssertionError(f"common source-set timing drift: {job}")
        def primitive(item):
            if type(item) is dict:
                return all(type(key) is str and primitive(child) for key, child in item.items())
            if type(item) is list:
                return all(primitive(child) for child in item)
            return type(item) in (str, int, bool, type(None))
        if not primitive(value) or not session.settle_native_phase().restored:
            raise AssertionError(f"common result was not primitive/restored: {job}")
        module = ops.modules[0]
        expected = common.SystemCommonOps._result_type(module, job)
        substitute = make_dataclass(
            expected.__name__,
            [(item.name, object) for item in fields(expected)],
            frozen=True,
        )
        try:
            common.SystemCommonOps._closed_result(
                module,
                job,
                substitute(*(value[item.name] for item in fields(expected))),
            )
        except common.QualificationError:
            pass
        else:
            raise AssertionError(f"common accepted caller-created result type: {job}")


class OuterKernel:
    def __init__(self, module, row):
        self.module = module
        self.point = row["primitive_fault"]["point"]
        self.mutation = row["primitive_fault"]["mutation"]
        self.events = []
        self.fired = False
        self.next_fd = 20
        self.fds = {}
        self.data = {}
        self.released = False
        self.signaled = False
        self.reaped = False
        self.foreign = None
        self.pipe_count = 0
    def consume_fault(self, point):
        if self.fired or self.point != point:
            return False
        self.fired = True
        self.events.append(f"outer:{point}")
        return True
    def allocate(self, purpose, data=b""):
        while self.next_fd in self.fds:
            self.next_fd += 1
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = purpose
        self.data[fd] = data
        return fd
    def memfd_create(self, name, flags):
        del name, flags
        if self.consume_fault("memfd_create"):
            raise OSError("memfd")
        return self.allocate("launcher")
    def pipe2(self, flags):
        del flags
        if self.consume_fault("pipe2"):
            raise OSError("pipe")
        purposes = ("admission", "output", "error", "transition", "ack", "release")
        purpose = purposes[self.pipe_count]
        self.pipe_count += 1
        return self.allocate(purpose + "-read"), self.allocate(purpose + "-write")
    def clone_pidfd(self):
        if self.consume_fault("clone_pidfd"):
            raise OSError("clone")
        return 700, self.allocate("pidfd")
    def open(self, path, flags, mode=0o600):
        del flags, mode
        if path.endswith("/stat"):
            fields_ = b" ".join([b"1"] * 18 + [b"10"] + [b"1"] * 30)
            return self.allocate("proc-stat", b"700 (held-python) S " + fields_ + b"\n")
        if path.endswith("/exe"):
            return self.allocate("proc-exe")
        raise AssertionError(path)
    def read(self, fd, size):
        del size
        purpose = self.fds[fd]
        if purpose == "transition-read":
            if self.consume_fault("transition_read"):
                return b""
            return b"S"
        if purpose in {"output-read", "error-read"}:
            point = "output_read" if purpose.startswith("output") else "error_read"
            self.fds[fd] = point + "-complete"
            if self.consume_fault(point):
                if self.mutation == "bytes":
                    return b"error"
                raise OSError(point)
            return b"{}\n" if point == "output_read" else b""
        raw = self.data.get(fd, b"")
        self.data[fd] = b""
        return raw
    def write(self, fd, data):
        purpose = self.fds[fd]
        if purpose == "release-write" and data == b"G":
            if self.consume_fault("release_write"):
                return 0
            self.released = True
        elif purpose == "ack-write" and data == b"A" and self.consume_fault("transition_ack"):
            return 0
        elif purpose == "admission-write" and self.consume_fault("admission_write"):
            return len(data) - 1
        return len(data)
    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("outer descriptor closed twice")
        if self.consume_fault("close"):
            if self.mutation == "before":
                raise OSError("close before")
            del self.fds[fd]
            self.foreign = fd
            self.fds[fd] = "foreign"
            raise OSError("close after reuse")
        del self.fds[fd]
        self.data.pop(fd, None)
    def fstat(self, fd):
        if fd not in self.fds:
            raise OSError(errno.EBADF, "closed")
        identity = 101 if self.fds[fd] == "proc-exe" else fd
        return SimpleNamespace(st_dev=8, st_ino=identity, st_mode=stat.S_IFREG | 0o555)
    def fcntl(self, fd, command, argument=0):
        if command == fcntl.F_DUPFD_CLOEXEC:
            if self.consume_fault("source_dup"):
                raise OSError("dup")
            return self.allocate("source-duplicate")
        if command == fcntl.F_ADD_SEALS:
            if self.consume_fault("launcher_seal"):
                raise OSError("seal")
            return 0
        raise AssertionError(command)
    def launcher_write(self, fd, data):
        del fd
        if self.consume_fault("launcher_write"):
            return 0
        return len(data)
    def getsid(self, pid):
        del pid
        if self.point == "transition_identity" and self.released:
            self.consume_fault("transition_identity")
            return 701
        return 700 if self.released else 7
    def getpgid(self, pid):
        return self.getsid(pid)
    def waitpid(self, pid, flags):
        del flags
        if self.consume_fault("reap"):
            raise ChildProcessError()
        self.reaped = True
        return pid, 1 if self.consume_fault("waitpid") else 0
    def select(self, readers, writers, errors, timeout=0):
        del errors, timeout
        if writers:
            return [], list(writers), []
        if readers and all(self.fds.get(fd) == "pidfd" for fd in readers):
            return (list(readers) if self.signaled else []), [], []
        if self.consume_fault("output_eof"):
            return [], [], []
        return list(readers), [], []
    def monotonic(self):
        step = 10.0 if self.point == "output_eof" else 0.1
        value = getattr(self, "clock", 0.0) + step
        self.clock = value
        return value
    def pidfd_signal(self, fd, number):
        del fd, number
        self.signaled = True


def outer_process_case(module, row):
    if not hasattr(module.os, "MFD_CLOEXEC"):
        module.os.MFD_CLOEXEC = 1
        module.os.MFD_ALLOW_SEALING = 2
    if not hasattr(module.fcntl, "F_ADD_SEALS"):
        module.fcntl.F_ADD_SEALS = 1033
    ops = OuterKernel(module, row)
    def start_time_guard(pid, actual_ops=None):
        if ops.consume_fault("start_time"):
            raise OSError("start time")
        return actual_start_time(pid, actual_ops)
    actual_start_time = module._start_time
    with patched(
        module,
        _SystemOps=lambda: ops,
        _start_time=start_time_guard,
    ), patched(
        module.os,
        memfd_create=ops.memfd_create,
        write=ops.launcher_write,
        lseek=lambda fd, offset, origin: 0,
        fchmod=lambda fd, mode: None,
        pipe2=ops.pipe2,
        fstat=ops.fstat,
        getsid=ops.getsid,
        getpgid=ops.getpgid,
        waitpid=ops.waitpid,
    ), patched(
        module.fcntl,
        fcntl=ops.fcntl,
    ), patched(
        module.select,
        select=ops.select,
    ), patched(
        module.time,
        monotonic=ops.monotonic,
        sleep=lambda seconds: None,
    ), patched(
        module.signal,
        pidfd_send_signal=ops.pidfd_signal,
    ):
        value = module._run_held_python_with_ops(
            ops, b"held launcher", b"held sources", b"admission\n",
        )
    if row["intended_code"] == "accept":
        if value != b"{}\n" or ops.fired or ops.fds:
            raise AssertionError(f"complete outer owner mismatch: {ops.events}/{ops.fds}")
        return
    raise AssertionError(f"outer primitive fault accepted: {row['id']}")


def outer_process_corpus(module):
    path = FIXTURE.parent / "outer-process-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    header, *rows = document
    if header["version"] != "cogs.outcome-two-outer-process/v1":
        raise AssertionError("outer process fixture version")
    if set(header["case_fields"]) != ROW_KEYS or any(set(row) != ROW_KEYS for row in rows):
        raise AssertionError("outer process fixture shape")
    declared = {row["id"] for row in rows}
    selected = set()
    consumed = set()
    oracle = set()
    for row in rows:
        selected.add(row["id"])
        try:
            outer_process_case(module, row)
        except (module.RuntimeLauncherError, module.RuntimeLauncherCleanupError,
                OSError, ChildProcessError):
            if row["intended_code"] == "accept":
                raise
        else:
            if row["intended_code"] != "accept":
                raise AssertionError(f"outer primitive fault accepted: {row['id']}")
        consumed.add(row["id"])
        oracle.add(row["id"])
    if declared != selected or declared != consumed or declared != oracle:
        raise AssertionError("outer declared/selected/consumed/oracle mismatch")


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
    if not hasattr(module.socket, "SCM_CREDENTIALS"):
        module.socket.SCM_CREDENTIALS = 2
    if not hasattr(module.socket, "MSG_CMSG_CLOEXEC"):
        module.socket.MSG_CMSG_CLOEXEC = 0x40000000
    if module._ROOT_PARENT != "/tmp":
        raise AssertionError("private runtime root is not fixed beneath /tmp")
    launcher_source = MODULE.read_text()
    common_source = COMMON.read_text()
    admission = common_source.index("held, digest = self._admit_sources(context, root)")
    compilation = common_source.index("module = self._launcher(held[LAUNCHER_PATH])")
    if admission > compilation or "open(ROOT" in launcher_source:
        raise AssertionError("held source admission/compilation order drift")
    banned = ("_MappingAuthority", "_coordinate_admitted_mapping_only")
    required = ("_qualify_admitted_fixed_python_mapping", "_launch_admitted_fixed_compression_qualification", "_qualify_admitted_fixed_descriptor_primitives", "_qualify_admitted_fixed_process_lifecycle", "_launch_admitted_fixed_sandbox_qualification", "invoke_fixed_admitted_operation", "_prepare_client_from_admitted_bytes", 'None if mode in ("lifecycle", "sandbox") else _load_private_closure')
    if any(token in launcher_source for token in banned) or not all(token in launcher_source for token in required):
        raise AssertionError("fixed admitted production routing drift")
    production_operation_contracts(module)
    capsule_contract(module)
    fixed_bootstrap_modes(module)
    common_production_adapters()
    outer_process_corpus(module)
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

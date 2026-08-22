"""Readable static Stage 2 admission with historical V1 codecs preserved.

Admission authenticates reviewed static control data and retained files.  It
never opens KVM, observes QMP, accepts a PID, or composes the coordinator.
Live inode mappings are derived only after a real retained rootfs lease exists.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import time

import completion_guest_workloads_v3 as final_guest
import completion_kata_preparation as preparation

# Historical V1 public meanings and blocked reviewed constants are retained.
VERSION = "cogs.stage2-local-execution-envelope/v1"
RUNTIME_VERSION = "cogs.stage2-local-runtime-manifest/v1"
CONTRACT_VERSION = "cogs.stage2-local-executable-closure/v1"
AUTHORITY = "non-authoritative-execution-input-description"
FIXED_ROOT = Path("/var/lib/cogs/stage2-completion-v1/source")
ENVELOPE_PATH = FIXED_ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-envelope-v1.json"
RUNTIME_MANIFEST_PATH = FIXED_ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-runtime-v1.json"
REVIEWED_ENVELOPE_SHA256 = None
REVIEWED_RUNTIME_MANIFEST_SHA256 = None
MAX_ENVELOPE_BYTES = 131_072
MAX_RUNTIME_MANIFEST_BYTES = 65_536
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_CONTRACT_BYTES = 262_144
HEX = frozenset("0123456789abcdef")
RECEIPT_VERSION = "cogs.stage2-local-private-receipt/v1"
RECEIPT_DOMAIN = "cogs.stage2-local-private-receipt/v1\x00"
EXECUTABLES = preparation.EXECUTABLES
MANDATORY_SOURCES = frozenset({
    "deploy/aws-feasibility/remote/completion_guest_workloads_v2.py",
    "deploy/aws-feasibility/remote/completion_guest_workloads_v3.py",
    "deploy/aws-feasibility/remote/completion_kata_actions.py",
    "deploy/aws-feasibility/remote/completion_kata_admission.py",
    "deploy/aws-feasibility/remote/completion_kata_command_policy.py",
    "deploy/aws-feasibility/remote/completion_kata_coordinator.py",
    "deploy/aws-feasibility/remote/completion_kata_execution_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_fdmap.py",
    "deploy/aws-feasibility/remote/completion_kata_inputs.py",
    "deploy/aws-feasibility/remote/completion_kata_network.py",
    "deploy/aws-feasibility/remote/completion_kata_network_journal.py",
    "deploy/aws-feasibility/remote/completion_kata_nft_owner.py",
    "deploy/aws-feasibility/remote/completion_kata_operation.py",
    "deploy/aws-feasibility/remote/completion_kata_operation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_process.py",
    "deploy/aws-feasibility/remote/completion_kata_qualification.py",
    "deploy/aws-feasibility/remote/completion_kata_runtime.py",
    "deploy/aws-feasibility/remote/completion_kata_ssh.py",
    "deploy/aws-feasibility/remote/completion_local_evidence.py",
    "deploy/aws-feasibility/remote/completion_rootfs_fs.py",
    "deploy/aws-feasibility/remote/completion_rootfs_lease.py",
    "deploy/aws-feasibility/remote/completion_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_runtime_contract.py",
    "deploy/aws-feasibility/remote/completion_rootfs_plan.py",
    "deploy/aws-feasibility/remote/completion_local_full.py",
    "deploy/aws-feasibility/remote/completion_local_receipt.py",
    "deploy/aws-feasibility/remote/recover-stage2-completion-remote.sh",
})
BINDING_KEYS = frozenset({
    "source_head", "source_manifest_sha256", "host_attestation_sha256",
    "runtime_attestation_sha256", "rootfs_sha256", "artifact_sha256",
    "candidate_sha256", "final_pin_sha256", "guest_program_sha256",
    "owner_implementation_sha256",
})
PACKAGE_IDENTITY_KEYS = (
    "deb_sha256", "deb_bytes", "installed_tree_sha256", "installed_entries",
    "installed_bytes", "package", "version", "architecture",
)
STATIC_OBJECT_KEYS = (
    "version", "path", "source", "mode", "size", "content_sha256",
    "interpreter", "soname", "needed", "resolved",
)
MAPPING_KEYS = (
    "path", "execution_path", "device", "inode", "mode", "uid", "gid",
    "nlink", "size", "sha256",
)

CONTROL_ROOT = preparation.CONTROL_ROOT
CONTROL_PATH = CONTROL_ROOT / preparation.CONTROL_MEMBER
MAX_CONTROL_BYTES = preparation.MAX_CONTROL_BYTES


class AdmissionError(Exception):
    pass


class AdmissionUnavailable(AdmissionError):
    pass


@dataclass(frozen=True)
class EnvelopeDescription:
    sha256: str
    value: dict


@dataclass(frozen=True)
class RetainedObject:
    role: str
    kind: str
    path: str
    descriptor: int
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    sha256: str
    interpreter: str | None
    soname: str | None
    needed: tuple[str, ...]


@dataclass(frozen=True)
class LiveMappingDescription:
    sha256: str
    object_count: int


@dataclass(frozen=True)
class ExecutableRoleDescription:
    role: str
    path: str
    closure_sha256: str
    objects: tuple[RetainedObject, ...]


def _require(condition, message="invalid local execution admission"):
    if not condition:
        raise AdmissionError(message)


def _digest(value):
    _require(type(value) is str and len(value) == 64 and set(value) <= HEX)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("noncanonical admission value") from error


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value, "duplicate admission key")
        value[key] = item
    return value


def _decode(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n") and b"\0" not in raw,
             "invalid admission bytes")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except AdmissionError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise AdmissionError("invalid admission JSON") from error
    _require(type(value) is dict and _canonical(value) == raw, "admission bytes are not canonical")
    return value


def _keys(value, expected):
    _require(type(value) is dict and set(value) == set(expected))


def _relative(value):
    _require(type(value) is str and 0 < len(value) <= 240 and value.isascii())
    _require(not value.startswith("/") and "\\" not in value)
    _require(all(part not in {"", ".", ".."} for part in value.split("/")))


def _validate_sources(source):
    _keys(source, ("root", "head", "manifest_sha256", "files"))
    _require(source["root"] == str(FIXED_ROOT))
    head = source["head"]
    _require(type(head) is str and len(head) == 40 and set(head) <= HEX)
    _digest(source["manifest_sha256"])
    files = source["files"]
    _require(type(files) is list and len(MANDATORY_SOURCES) <= len(files) <= 128)
    paths = []
    for row in files:
        _keys(row, ("path", "sha256", "size"))
        _relative(row["path"])
        _digest(row["sha256"])
        _require(type(row["size"]) is int and not isinstance(row["size"], bool))
        _require(1 <= row["size"] <= MAX_SOURCE_BYTES)
        paths.append(row["path"])
    _require(paths == sorted(set(paths), key=lambda item: item.encode("ascii")))
    _require(MANDATORY_SOURCES <= set(paths))
    _require(source["manifest_sha256"] == _sha(_canonical(files)))


def _validate_executables(rows):
    _require(type(rows) is list and len(rows) == len(EXECUTABLES))
    for row, expected in zip(rows, EXECUTABLES, strict=True):
        _keys(row, ("role", "source_class", "path", "contract_path", "contract_sha256",
                    "executable_sha256", "tool_closure_sha256"))
        _require((row["role"], row["source_class"], row["path"]) == expected)
        _relative(row["contract_path"])
        for name in ("contract_sha256", "executable_sha256", "tool_closure_sha256"):
            _digest(row[name])


def _validate_contract(raw, expected):
    value = _decode(raw, MAX_CONTRACT_BYTES)
    _keys(value, ("version", "architecture", "role", "path", "dynamic_tags", "objects", "closure_sha256"))
    _require(value["version"] == CONTRACT_VERSION and value["architecture"] == "x86_64")
    _require((value["role"], value["path"]) == (expected["role"], expected["path"]))
    tags = value["dynamic_tags"]
    forbidden = {"RPATH", "RUNPATH", "AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY", "CONFIG"}
    _require(type(tags) is list and tags == sorted(set(tags)))
    _require(all(type(tag) is str and tag not in forbidden for tag in tags))
    objects = value["objects"]
    _require(type(objects) is list and 1 <= len(objects) <= 130)
    identities = []
    sonames = {}
    total = 0
    for item in objects:
        _keys(item, ("kind", "path", "size", "sha256", "interpreter", "soname", "needed"))
        _require(item["kind"] in {"executable", "loader", "library"})
        _require(type(item["path"]) is str and item["path"].startswith("/") and item["path"].isascii())
        _require(os.path.normpath(item["path"]) == item["path"] and "//" not in item["path"] and "\\" not in item["path"])
        _require(type(item["size"]) is int and not isinstance(item["size"], bool))
        _require(1 <= item["size"] <= 128 * 1024 * 1024)
        _digest(item["sha256"])
        total += item["size"]
        interpreter = item["interpreter"]
        _require(interpreter is None or (item["kind"] == "executable" and type(interpreter) is str
                                          and interpreter.startswith("/") and os.path.normpath(interpreter) == interpreter))
        soname = item["soname"]
        _require(soname is None or (type(soname) is str and 0 < len(soname) <= 255
                                    and soname.isascii() and "/" not in soname and soname not in sonames))
        if soname is not None:
            sonames[soname] = item["path"]
        if item["kind"] == "library":
            _require(soname is not None)
        elif item["kind"] == "executable":
            _require(soname is None)
        needed = item["needed"]
        _require(type(needed) is list and len(needed) <= 128 and needed == sorted(set(needed)))
        _require(all(type(name) is str and 0 < len(name) <= 255 and name.isascii() and "/" not in name for name in needed))
        identities.append((item["kind"], item["path"]))
    _require(len({path for _kind, path in identities}) == len(identities), "tool closure aliases an object path")
    _require(total <= 512 * 1024 * 1024 and identities[0] == ("executable", expected["path"]))
    _require(sum(kind == "executable" for kind, _path in identities) == 1)
    loader_count = sum(kind == "loader" for kind, _path in identities)
    _require(loader_count <= 1)
    _require(objects[0]["sha256"] == expected["executable_sha256"])
    interpreter = objects[0]["interpreter"]
    _require((loader_count == 1) == (interpreter is not None))
    _require(loader_count == 0 or (objects[1]["kind"] == "loader" and objects[1]["path"] == interpreter))
    libraries = objects[1 + loader_count:]
    _require(all(item["kind"] == "library" for item in libraries))
    library_sonames = {item["soname"] for item in libraries}
    _require([item["soname"] for item in libraries] == sorted(library_sonames))
    _require(all(name in library_sonames for item in objects for name in item["needed"]))
    by_soname = {item["soname"]: item for item in libraries}
    pending = list(objects[0]["needed"])
    reached = set()
    while pending:
        name = pending.pop(0)
        if name in reached:
            continue
        reached.add(name)
        pending.extend(by_soname[name]["needed"])
    _require(reached == library_sonames, "tool closure has missing or extra libraries")
    body = {name: value[name] for name in value if name != "closure_sha256"}
    _require(value["closure_sha256"] == _sha(_canonical(body)))
    _require(value["closure_sha256"] == expected["tool_closure_sha256"])
    return value


def _attestation_digest(rows):
    return _sha(_canonical(rows))


def _source_digest(source, path):
    rows = [row for row in source["files"] if row["path"] == path]
    _require(len(rows) == 1)
    return rows[0]["sha256"]


def _validate_package_identity(value):
    _keys(value, PACKAGE_IDENTITY_KEYS)
    for name in ("deb_sha256", "installed_tree_sha256"):
        _digest(value[name])
    for name, maximum in (("deb_bytes", 4_194_304), ("installed_entries", 1_000_000),
                          ("installed_bytes", 1 << 40)):
        _require(type(value[name]) is int and not isinstance(value[name], bool) and 1 <= value[name] <= maximum)
    _require((value["package"], value["version"], value["architecture"]) == ("cogs-stage2-fixture", "1.0", "all"))


def validate_envelope_value(value):
    _keys(value, ("version", "authority", "source", "package", "runtime", "executables", "result_bindings", "receipt"))
    _require(value["version"] == VERSION and value["authority"] == AUTHORITY)
    _validate_sources(value["source"])
    package = value["package"]
    _keys(package, ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256", "package_identity", "artifact"))
    for name in ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256"):
        _digest(package[name])
    _validate_package_identity(package["package_identity"])
    _keys(package["artifact"], ("sha256", "bytes"))
    _digest(package["artifact"]["sha256"])
    _require(type(package["artifact"]["bytes"]) is int and not isinstance(package["artifact"]["bytes"], bool))
    _require((package["artifact"]["sha256"], package["artifact"]["bytes"]) ==
             (package["package_identity"]["deb_sha256"], package["package_identity"]["deb_bytes"]))
    runtime = value["runtime"]
    _keys(runtime, ("manifest_sha256", "rootfs_sha256", "static_closure_sha256", "execution_mapping_sha256"))
    for item in runtime.values():
        _digest(item)
    _validate_executables(value["executables"])
    bindings = value["result_bindings"]
    _keys(bindings, BINDING_KEYS)
    for name, item in bindings.items():
        if name == "source_head":
            _require(item == value["source"]["head"])
        else:
            _digest(item)
    _require(bindings["source_manifest_sha256"] == value["source"]["manifest_sha256"])
    _require(bindings["host_attestation_sha256"] == _attestation_digest(value["executables"][:5]))
    _require(bindings["runtime_attestation_sha256"] == runtime["execution_mapping_sha256"])
    _require(bindings["rootfs_sha256"] == runtime["rootfs_sha256"])
    _require(bindings["artifact_sha256"] == package["artifact"]["sha256"])
    _require(bindings["candidate_sha256"] == package["candidate_result_sha256"])
    _require(bindings["final_pin_sha256"] == package["final_pin_sha256"])
    guest_program = final_guest.guest_program_bytes()
    _require(bindings["guest_program_sha256"] == hashlib.sha256(guest_program).hexdigest()
             == final_guest.GUEST_PROGRAM_SHA256)
    _require(bindings["owner_implementation_sha256"] == _source_digest(value["source"], "deploy/aws-feasibility/remote/completion_kata_coordinator.py"))
    _require(value["receipt"] == {"version": RECEIPT_VERSION, "domain": RECEIPT_DOMAIN})
    return value


def load_envelope(raw):
    value = validate_envelope_value(_decode(raw, MAX_ENVELOPE_BYTES))
    return EnvelopeDescription(_sha(raw), value)


def _validate_static_closure(value):
    _keys(value, ("version", "manifest_sha256", "object_count", "tools", "objects"))
    _require(value["version"] == "cogs.stage2-runtime-tool-closure/v1")
    _digest(value["manifest_sha256"])
    _require(value["object_count"] == 35 and type(value["tools"]) is list and len(value["tools"]) == 3)
    for tool in value["tools"]:
        _keys(tool, ("name", "sha256", "bytes", "version"))
        _digest(tool["sha256"])
        _require(type(tool["name"]) is str and type(tool["version"]) is str)
        _require(type(tool["bytes"]) is int and not isinstance(tool["bytes"], bool) and tool["bytes"] > 0)
    objects = value["objects"]
    _require(type(objects) is list and len(objects) == 35)
    paths = []
    for row in objects:
        _keys(row, STATIC_OBJECT_KEYS)
        _require(row["version"] == "cogs.stage2-completion-runtime-object/v1")
        _relative(row["path"])
        _digest(row["content_sha256"])
        _require(type(row["source"]) is str and row["source"])
        _require(type(row["mode"]) is int and 0 <= row["mode"] <= 4095)
        _require(type(row["size"]) is int and row["size"] > 0)
        for name in ("interpreter", "soname"):
            _require(row[name] is None or (type(row[name]) is str and row[name]))
        for name in ("needed", "resolved"):
            _require(type(row[name]) is list and len(row[name]) <= 128 and len(row[name]) == len(set(row[name])))
        _require(len(row["needed"]) == len(row["resolved"]))
        paths.append(row["path"])
    _require(paths == sorted(set(paths), key=str.encode), "static closure paths differ")
    _require(_sha(b"".join(_canonical(row) for row in objects)) == value["manifest_sha256"])


def _validate_execution_mapping(value, static_closure, rootfs_sha256):
    _keys(value, ("version", "rootfs_sha256", "static_manifest_sha256", "objects"))
    _require(value["version"] == "cogs.stage2-local-execution-mapping/v1")
    _require(value["rootfs_sha256"] == rootfs_sha256)
    _require(value["static_manifest_sha256"] == static_closure["manifest_sha256"])
    rows = value["objects"]
    _require(type(rows) is list and len(rows) == 35)
    identities = set()
    paths = []
    for row, pinned in zip(rows, static_closure["objects"], strict=True):
        _keys(row, MAPPING_KEYS)
        _relative(row["path"])
        _require(type(row["execution_path"]) is str and row["execution_path"].startswith("/"))
        _require(os.path.normpath(row["execution_path"]) == row["execution_path"])
        for name in ("device", "inode", "mode", "uid", "gid", "nlink", "size"):
            _require(type(row[name]) is int and not isinstance(row[name], bool) and row[name] >= 0)
        _digest(row["sha256"])
        _require((row["path"], row["size"], row["sha256"]) ==
                 (pinned["path"], pinned["size"], pinned["content_sha256"]))
        _require(row["inode"] > 0 and row["nlink"] == 1)
        paths.append(row["execution_path"])
        identities.add((row["device"], row["inode"]))
    _require(len(set(paths)) == len(rows) and len(identities) == len(rows),
             "execution mapping aliases a path or file identity")


def load_runtime_manifest(raw):
    value = _decode(raw, MAX_RUNTIME_MANIFEST_BYTES)
    _keys(value, ("version", "architecture", "rootfs_sha256", "static_closure", "execution_mapping", "executables"))
    _require(value["version"] == RUNTIME_VERSION and value["architecture"] == "x86_64")
    _digest(value["rootfs_sha256"])
    _validate_static_closure(value["static_closure"])
    _validate_execution_mapping(value["execution_mapping"], value["static_closure"], value["rootfs_sha256"])
    rows = value["executables"]
    _require(type(rows) is list and len(rows) == len(EXECUTABLES) - 5)
    for row, expected in zip(rows, EXECUTABLES[5:], strict=True):
        _keys(row, ("role", "source_class", "path", "contract_path", "contract_sha256",
                    "executable_sha256", "tool_closure_sha256"))
        _require((row["role"], row["source_class"], row["path"]) == expected)
        _relative(row["contract_path"])
        for name in ("contract_sha256", "executable_sha256", "tool_closure_sha256"):
            _digest(row[name])
    return value


def _status(status_value, maximum, expected_uid, expected_gid):
    _require(stat.S_ISREG(status_value.st_mode) and status_value.st_uid == expected_uid
             and status_value.st_gid == expected_gid and status_value.st_nlink == 1)
    _require(not stat.S_IMODE(status_value.st_mode) & 0o022 and 0 < status_value.st_size <= maximum,
             "untrusted admitted file identity")


def _open_fixed_relative(root, relative, maximum, expected_uid=0, expected_gid=0):
    _relative(str(relative))
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent = os.open(root, directory_flags)
    descriptor = -1
    try:
        root_status = os.fstat(parent)
        _require(stat.S_ISDIR(root_status.st_mode) and root_status.st_uid == expected_uid
                 and root_status.st_gid == expected_gid and not stat.S_IMODE(root_status.st_mode) & 0o022,
                 "untrusted admitted root")
        components = str(relative).split("/")
        for component in components[:-1]:
            child = os.open(component, directory_flags, dir_fd=parent)
            seen = os.fstat(child)
            _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid and seen.st_gid == expected_gid
                     and not stat.S_IMODE(seen.st_mode) & 0o022, "untrusted admitted directory")
            os.close(parent)
            parent = child
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(descriptor)
        _status(before, maximum, expected_uid, expected_gid)
        return descriptor, parent, before
    except BaseException as error:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
        if isinstance(error, OSError):
            raise AdmissionError("admitted file open failed") from error
        raise


def _open_absolute_regular(path, maximum):
    _require(type(path) is str and path.startswith("/") and path.isascii())
    _require("//" not in path and "/../" not in path and "\\" not in path)
    return _open_fixed_relative("/", path[1:], maximum)


def _read_held(descriptor, before, maximum):
    digest = hashlib.sha256()
    total = 0
    while total <= maximum:
        part = os.pread(descriptor, min(65_536, maximum + 1 - total), total)
        if not part:
            break
        digest.update(part)
        total += len(part)
    after = os.fstat(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    _require(total == before.st_size and total <= maximum and identity(before) == identity(after),
             "admitted file changed while reading")
    return digest.hexdigest()


def _read_held_raw(descriptor, before, maximum):
    raw = os.pread(descriptor, before.st_size, 0)
    _require(len(raw) == before.st_size and _sha(raw) == _read_held(descriptor, before, maximum),
             "admitted file changed while reading")
    return raw


def _derived_elf(raw):
    _require(type(raw) is bytes and len(raw) >= 64)
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
        ident, kind, machine, version = header[:4]
        phoff, phsize, phnum = header[5], header[9], header[10]
        _require(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in {2, 3} and machine == 62 and version == 1)
        _require(phsize == 56 and 0 < phnum <= 256 and phoff + phsize * phnum <= len(raw),
                 "retained object is not exact ELF64")
        headers = [struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phsize) for index in range(phnum)]
        dynamic = sum(item[0] == 2 for item in headers)
        interp_headers = [item for item in headers if item[0] == 3]
        _require(len(interp_headers) <= 1)
        static_interpreter = None
        if interp_headers:
            offset, size = interp_headers[0][2], interp_headers[0][5]
            _require(1 < size <= 256 and offset + size <= len(raw))
            encoded = raw[offset:offset + size]
            _require(encoded.endswith(b"\0") and b"\0" not in encoded[:-1])
            _require(all(32 <= byte <= 126 for byte in encoded[:-1]))
            static_interpreter = encoded[:-1].decode("ascii")
            _require(static_interpreter.startswith("/") and os.path.normpath(static_interpreter) == static_interpreter)
        if dynamic == 0:
            return static_interpreter, None, ()
        _require(dynamic == 1)
        from completion_runtime_closure import _elf
        derived = _elf(raw)
        _require(derived[0] == static_interpreter)
        return derived
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError("retained ELF metadata is invalid") from error


def _retain_contract_objects(contract, descriptors, role=None):
    identities = set()
    retained = []
    for item in contract["objects"]:
        descriptor, parent, status_value = _open_absolute_regular(item["path"], item["size"])
        descriptors.extend((parent, descriptor))
        raw = _read_held_raw(descriptor, status_value, item["size"])
        identity = (status_value.st_dev, status_value.st_ino)
        _require(identity not in identities, "tool closure aliases a retained file identity")
        identities.add(identity)
        _require(status_value.st_size == item["size"] and _sha(raw) == item["sha256"],
                 "executable closure source differs")
        interpreter, soname, needed = _derived_elf(raw)
        _require((interpreter, soname, list(needed)) ==
                 (item["interpreter"], item["soname"], item["needed"]),
                 "declared ELF metadata differs from retained bytes")
        retained.append(RetainedObject(
            role or contract["role"], item["kind"], item["path"], descriptor,
            status_value.st_dev, status_value.st_ino, stat.S_IMODE(status_value.st_mode),
            status_value.st_uid, status_value.st_gid, status_value.st_nlink,
            status_value.st_size, item["sha256"], item["interpreter"], item["soname"],
            tuple(item["needed"]),
        ))
    return tuple(retained)


def _qualification_checks():
    """Historical V1 diagnostic tuple; its KVM value never grants V2 custody."""
    try:
        observed = os.stat("/dev/kvm", follow_symlinks=False)
        kvm = stat.S_ISCHR(observed.st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK)
    except OSError:
        kvm = False
    return (platform.system() == "Linux", platform.machine() == "x86_64", os.geteuid() == 0,
            os.path.realpath(os.getcwd()) == str(FIXED_ROOT), kvm)


def _close_all(descriptors, primary=None):
    errors = []
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(error)
    if errors:
        additions = [primary, *errors] if primary is not None else errors
        raise BaseExceptionGroup("static admission descriptor close", additions)
    if primary is not None:
        raise primary


def _read_control_package():
    descriptors = []
    try:
        control_fd, control_parent, control_status = _open_fixed_relative(
            CONTROL_ROOT, preparation.CONTROL_MEMBER, MAX_CONTROL_BYTES)
        descriptors.extend((control_parent, control_fd))
        control_raw = _read_held_raw(control_fd, control_status, MAX_CONTROL_BYTES)
        control = preparation.load_control(control_raw)
        members = {}
        for row in control.value["members"]:
            maximum = (preparation.MAX_RUNTIME_BYTES if row["kind"] == "runtime-manifest" else
                       preparation.MAX_ENVELOPE_BYTES if row["kind"] == "envelope" else
                       preparation.MAX_CONTRACT_BYTES)
            descriptor, parent, status_value = _open_fixed_relative(CONTROL_ROOT, row["name"], maximum)
            descriptors.extend((parent, descriptor))
            raw = _read_held_raw(descriptor, status_value, maximum)
            _require(len(raw) == row["size"] and _sha(raw) == row["sha256"], "static control member differs")
            members[row["name"]] = raw
        envelope, runtime, contracts = preparation.validate_control_members(control, members)
        return control, envelope, runtime, contracts, descriptors
    except BaseException as error:
        _close_all(descriptors, error)


def _verify_complete_source(implementation, descriptors):
    manifest_fd, manifest_parent, manifest_status = _open_fixed_relative(
        FIXED_ROOT, preparation.SOURCE_MANIFEST, preparation.MAX_SOURCE_MANIFEST_BYTES)
    descriptors.extend((manifest_parent, manifest_fd))
    raw = _read_held_raw(manifest_fd, manifest_status, preparation.MAX_SOURCE_MANIFEST_BYTES)
    manifest = preparation.parse_source_manifest(
        raw, implementation["revision"], implementation["source_manifest_sha256"])
    _require(preparation.selected_implementation(manifest) == implementation["selected_sources"],
             "selected implementation source differs from full manifest")
    expected = {row["path"]: row for row in manifest["entries"]}
    root_status = FIXED_ROOT.stat(follow_symlinks=False)
    _require(stat.S_ISDIR(root_status.st_mode) and root_status.st_uid == root_status.st_gid == 0
             and stat.S_IMODE(root_status.st_mode) == 0o700)
    observed = set()
    for current, directories, files in os.walk(FIXED_ROOT, topdown=True, followlinks=False):
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        relative_current = Path(current).relative_to(FIXED_ROOT)
        if relative_current.parts[:3] == ("deploy", "aws-feasibility", ".state"):
            directories[:] = []
            continue
        if relative_current == Path("deploy/aws-feasibility") and ".state" in directories:
            directories.remove(".state")
        for name in directories:
            relative = (relative_current / name).as_posix()
            row = expected.get(relative)
            _require(row is not None and row["kind"] == "directory")
            seen = (Path(current) / name).stat(follow_symlinks=False)
            _require(stat.S_ISDIR(seen.st_mode) and stat.S_IMODE(seen.st_mode) == row["mode"]
                     and seen.st_uid == seen.st_gid == 0)
            observed.add(relative)
        for name in files:
            if relative_current == Path(".") and name == preparation.SOURCE_MANIFEST:
                continue
            relative = (relative_current / name).as_posix()
            row = expected.get(relative)
            _require(row is not None and row["kind"] == "file")
            descriptor, parent, seen = _open_fixed_relative(FIXED_ROOT, relative, row["size"])
            try:
                _require(stat.S_IMODE(seen.st_mode) == row["mode"] and _read_held(descriptor, seen, row["size"]) == row["sha256"])
                if relative in preparation.MANDATORY_SECURITY_SOURCES:
                    descriptors.extend((parent, descriptor))
                else:
                    os.close(descriptor)
                    os.close(parent)
            except BaseException:
                if descriptor not in descriptors:
                    os.close(descriptor)
                    os.close(parent)
                raise
            observed.add(relative)
    _require(observed == set(expected), "complete fixed source tree differs")
    return manifest


def _validate_final_and_rootfs(envelope, runtime):
    try:
        import completion_runtime_contract as workload_contract
        final = workload_contract.load_final_pin()
    except Exception as error:
        raise AdmissionError("exact final pin is unavailable") from error
    package = envelope.value["package"]
    # load_final_pin() already performs the historical exact recomputation:
    # fixed_runtime_closure(load_verified_build_inputs()).
    _require(final.final_pin_sha256 == package["final_pin_sha256"])
    _require(final.candidate_contract_sha256 == package["candidate_contract_sha256"])
    _require(final.candidate_result_sha256 == package["candidate_result_sha256"])
    _require(final.package_identity.value() == package["identity"])
    pinned = final.runtime_closure.value()
    static_closure = runtime.value["rootfs"]["static_closure"]
    _require({name: static_closure[name] for name in pinned} == pinned)
    rootfs = envelope.value["rootfs"]
    _require(rootfs["contract_sha256"] == workload_contract.REVIEWED_ROOTFS_SHA256)
    _require(rootfs["manifest_sha256"] == "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691")
    _require(rootfs["ustar_sha256"] == "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3")
    return final


def _static_routes():
    seal = object()
    custody_states = {}
    role_states = {}
    mapping_states = {}
    issuance_started = False
    issuer_taken = False

    class _StaticPreparationCustody:
        __slots__ = ()

        def __new__(cls, key=None):
            _require(key is seal, "sealed static preparation custody")
            return super().__new__(cls)

    class _ExecutableRoleCustody:
        __slots__ = ()

        def __new__(cls, key=None):
            _require(key is seal, "sealed executable role custody")
            return super().__new__(cls)

    class _LiveMappingClaim:
        __slots__ = ()

        def __new__(cls, key=None):
            _require(key is seal, "sealed live mapping claim")
            return super().__new__(cls)

    def claim_static():
        nonlocal issuance_started
        if issuance_started:
            raise AdmissionUnavailable("static preparation issuance is globally one-shot")
        issuance_started = True
        descriptors = []
        try:
            _require(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() == 0,
                     "static preparation platform differs")
            control, envelope, runtime, contracts, held = _read_control_package()
            descriptors.extend(held)
            _verify_complete_source(envelope.value["implementation"], descriptors)
            final = _validate_final_and_rootfs(envelope, runtime)
            custody = _StaticPreparationCustody(seal)
            custody_states[custody] = {
                "control": control,
                "envelope": envelope,
                "runtime": runtime,
                "contracts": contracts,
                "final": final,
                "descriptors": descriptors,
                "roles": set(),
                "mapping": None,
            }
            return custody
        except BaseException as error:
            primary = error if isinstance(error, AdmissionError) else AdmissionError("static preparation is unavailable")
            if primary is not error:
                primary.__cause__ = error
            _close_all(descriptors, primary)

    def take_issuer():
        nonlocal issuer_taken
        _require(not issuer_taken, "static preparation issuer already taken")
        issuer_taken = True
        return claim_static

    def claim_role(custody, role):
        state = custody_states.get(custody)
        _require(type(custody) is _StaticPreparationCustody and state is not None, "live static custody required")
        _require(type(role) is str and role in {row[0] for row in EXECUTABLES} and role not in state["roles"],
                 "executable role claim is not exact one-shot")
        contract = state["contracts"][role].value
        descriptors = []
        try:
            retained = _retain_contract_objects(contract, descriptors, role)
            state["descriptors"].extend(descriptors)
            state["roles"].add(role)
            claim = _ExecutableRoleCustody(seal)
            role_states[claim] = {"custody": custody, "role": role, "objects": retained, "consumed": False}
            return claim
        except BaseException as error:
            _close_all(descriptors, error)

    def consume_role(custody, claim, expected_role):
        state = role_states.get(claim)
        _require(type(claim) is _ExecutableRoleCustody and state is not None and state["custody"] is custody)
        _require(state["role"] == expected_role and not state["consumed"], "live exact executable role required")
        state["consumed"] = True
        contract = custody_states[custody]["contracts"][expected_role].value
        return ExecutableRoleDescription(
            expected_role, contract["path"], contract["closure_sha256"], state["objects"])

    def mapping_from_root(custody, root_descriptor, lease_identity):
        state = custody_states.get(custody)
        _require(type(custody) is _StaticPreparationCustody and state is not None and state["mapping"] is None)
        _require(type(root_descriptor) is int and root_descriptor >= 0)
        _require(type(lease_identity) is dict and set(lease_identity) == {"path", "ustar_sha256", "token"})
        runtime_rootfs = state["runtime"].value["rootfs"]
        mapping_policy = runtime_rootfs["static_mapping_policy"]
        _require(lease_identity["ustar_sha256"] == runtime_rootfs["ustar_sha256"])
        _require(type(lease_identity["token"]) is str and len(lease_identity["token"]) == 64
                 and set(lease_identity["token"]) <= HEX)
        expected_path = ("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/"
                         "completion-v1/rootfs-v1/operation-" + lease_identity["token"] + "/rootfs")
        _require(lease_identity["path"] == expected_path)
        root_seen = os.fstat(root_descriptor)
        _require(stat.S_ISDIR(root_seen.st_mode))
        rows = []
        descriptors = []
        identities = set()
        try:
            for pinned in runtime_rootfs["static_closure"]["objects"]:
                current = os.dup(root_descriptor)
                os.set_inheritable(current, False)
                descriptors.append(current)
                components = pinned["path"].split("/")
                for component in components[:-1]:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                    dir_fd=current)
                    descriptors.append(child)
                    current = child
                descriptor = os.open(components[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                     dir_fd=current)
                descriptors.append(descriptor)
                seen = os.fstat(descriptor)
                _require(stat.S_ISREG(seen.st_mode)
                         and seen.st_uid == mapping_policy["uid"]
                         and seen.st_gid == mapping_policy["gid"]
                         and seen.st_nlink == mapping_policy["nlink"])
                _require(stat.S_IMODE(seen.st_mode) == pinned["mode"] and seen.st_size == pinned["size"])
                _require(_read_held(descriptor, seen, pinned["size"]) == pinned["content_sha256"])
                identity = (seen.st_dev, seen.st_ino)
                _require(identity not in identities, "live rootfs mapping aliases an object")
                identities.add(identity)
                rows.append({"path": pinned["path"], "device": seen.st_dev, "inode": seen.st_ino,
                             "mode": stat.S_IMODE(seen.st_mode), "uid": seen.st_uid, "gid": seen.st_gid,
                             "nlink": seen.st_nlink, "size": seen.st_size,
                             "sha256": pinned["content_sha256"]})
            value = {"version": "cogs.stage2-local-live-rootfs-mapping/v1",
                     "rootfs_ustar_sha256": runtime_rootfs["ustar_sha256"],
                     "static_manifest_sha256": runtime_rootfs["static_closure"]["manifest_sha256"],
                     "objects": rows}
            description = LiveMappingDescription(_sha(_canonical(value)), len(rows))
            state["descriptors"].extend(descriptors)
            claim = _LiveMappingClaim(seal)
            mapping_states[claim] = {"custody": custody, "description": description,
                                     "value": value, "consumed": False}
            state["mapping"] = claim
            return claim
        except BaseException as error:
            _close_all(descriptors, error)

    def claim_live_mapping(custody, lease):
        try:
            import completion_rootfs_fs as rootfs_fs
            import completion_rootfs_lease as rootfs_lease
            _require(type(lease) is rootfs_lease.RetainedRootfsLease and lease.disposition == "held")
            control = rootfs_fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
            reference = rootfs_lease._verify(lease, control)
            root = lease.retained.owned.root.operation_fd
            _require(root is not None and root.disposition == "open")
            identity = {"path": reference.path, "ustar_sha256": reference.ustar_sha256,
                        "token": reference.token}
            return mapping_from_root(custody, root.number, identity)
        except AdmissionError:
            raise
        except Exception as error:
            raise AdmissionError("held rootfs lease mapping is unavailable") from error

    def consume_mapping(custody, claim):
        state = mapping_states.get(claim)
        _require(type(claim) is _LiveMappingClaim and state is not None and state["custody"] is custody
                 and not state["consumed"], "live mapping claim required")
        state["consumed"] = True
        return state["description"]

    def source_approval(custody):
        state = custody_states.get(custody)
        _require(type(custody) is _StaticPreparationCustody and state is not None,
                 "live exact static custody required")
        implementation = state["envelope"].value["implementation"]
        import completion_rootfs_fs as rootfs_fs
        return rootfs_fs.SourceApproval(
            implementation["revision"], implementation["source_manifest_sha256"])

    def binding(custody):
        state = custody_states.get(custody)
        _require(type(custody) is _StaticPreparationCustody and state is not None, "live exact static custody required")
        return dict(state["envelope"].value["result_binding_base"])

    def abort(custody):
        state = custody_states.pop(custody, None)
        _require(type(custody) is _StaticPreparationCustody and state is not None)
        for claim in [claim for claim, item in role_states.items() if item["custody"] is custody]:
            role_states.pop(claim)
        for claim in [claim for claim, item in mapping_states.items() if item["custody"] is custody]:
            mapping_states.pop(claim)
        _close_all(state["descriptors"])

    return (take_issuer, source_approval, claim_role, consume_role, claim_live_mapping,
            consume_mapping, binding, abort)


(_take_static_preparation_issuer, _fixed_source_approval,
 _claim_executable_role_custody, _consume_executable_role_custody,
 _claim_live_rootfs_mapping, _consume_live_rootfs_mapping,
 _static_custody_binding, _abort_static_preparation) = _static_routes()
del _static_routes


# Historical coordinator imports remain blocked rather than reinterpreting V1.
def _legacy_routes():
    issuer_taken = False

    def unavailable():
        raise AdmissionUnavailable("reviewed V1 envelope/runtime manifest remains unavailable")

    def take():
        nonlocal issuer_taken
        _require(not issuer_taken, "execution custody issuer already taken")
        issuer_taken = True
        return unavailable

    def reject(*_arguments):
        raise AdmissionUnavailable("historical V1 execution custody remains unavailable")

    return take, reject, reject, reject


(_take_execution_custody_issuer, _consume_custody_qualification,
 _execution_custody_binding, _abort_execution_custody) = _legacy_routes()
del _legacy_routes


def committed_status():
    return {
        "envelope_reviewed": REVIEWED_ENVELOPE_SHA256 is not None,
        "runtime_manifest_reviewed": REVIEWED_RUNTIME_MANIFEST_SHA256 is not None,
        "custody_issued": False,
    }


def static_status():
    return {
        "control_path": str(CONTROL_PATH),
        "source_root": str(FIXED_ROOT),
        "v2_static_only": True,
        "kvm_permit": False,
        "qmp_permit": False,
        "coordinator_composed": False,
    }

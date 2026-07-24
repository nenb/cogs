"""Read-only fixed-workspace filesystem authority for ADR 0040."""

from dataclasses import dataclass, field
import ctypes
import hashlib
import json
import os
import stat
import sys
import time
import unicodedata

sys.dont_write_bytecode = True

MAX_FDINFO_BYTES = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_ENTRIES = 10_000
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_COMPONENT_BYTES = 255
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 64
SOURCE_SENTINEL = b"cogs-stage2-source-v1\n"
SOURCE_SENTINEL_NAME = b".cogs-stage2-source-v1"
SOURCE_MANIFEST_NAME = b".cogs-stage2-source-manifest-v1.json"
SOURCE_MANIFEST_VERSION = "cogs.stage2-source-manifest/v1"
STATE_RELATIVE = (b"deploy", b"aws-feasibility", b".state")
PRIVILEGED_MUTATOR_EXCLUSION = (
    "Concurrent EUID-0, kernel, privileged-agent, and equal-observation ABA mutation is outside the threat model"
)

_O_PATH = getattr(os, "O_PATH", 0o10000000)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
IDENTITY_FLAGS = _O_PATH | _O_NOFOLLOW | _O_CLOEXEC
DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
# Approved amd64 fdinfo retains O_LARGEFILE, O_PATH, and O_CLOEXEC, but not open-time O_NOFOLLOW.
FDINFO_STATUS_FLAGS = _O_PATH | _O_CLOEXEC | 0o100000
FDINFO_FLAGS = ("0" + format(FDINFO_STATUS_FLAGS, "o")).encode("ascii")


class RootfsFsError(Exception):
    def __init__(self, primary=None, close_error=None):
        self.primary = primary
        self.close_error = close_error
        super().__init__()


def _fail(condition):
    if not condition:
        raise RootfsFsError()


def _exact_int(value, minimum=0, maximum=(1 << 64) - 1):
    _fail(type(value) is int and minimum <= value <= maximum)
    return value


def _kind(mode):
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


@dataclass(frozen=True)
class HostKey:
    mount_id: int
    device: int
    inode: int
    kind: str

    def __post_init__(self):
        _exact_int(self.mount_id, 1)
        _exact_int(self.device)
        _exact_int(self.inode, 1)
        _fail(type(self.kind) is str and self.kind in {"directory", "file", "symlink", "other"})


@dataclass(frozen=True)
class HostGeneration:
    key: HostKey
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int

    def __post_init__(self):
        _fail(type(self.key) is HostKey)
        _exact_int(self.mode, 0, 0o7777)
        _exact_int(self.uid)
        _exact_int(self.gid)
        _exact_int(self.nlink, 0)
        _exact_int(self.size)
        _exact_int(self.mtime_ns)
        _exact_int(self.ctime_ns)


@dataclass(frozen=True)
class ValidatedName:
    text: str
    raw: bytes

    def __post_init__(self):
        _fail(type(self.text) is str and type(self.raw) is bytes)
        _fail(self.text.encode("utf-8", "strict") == self.raw)
        _fail(self.raw and len(self.raw) <= MAX_COMPONENT_BYTES)


@dataclass(frozen=True)
class DirectorySnapshot:
    generation: HostGeneration
    names: tuple[ValidatedName, ...]
    children: tuple[tuple[ValidatedName, HostGeneration], ...]

    def __post_init__(self):
        _fail(type(self.generation) is HostGeneration and type(self.names) is tuple and type(self.children) is tuple)
        raw = tuple(item.raw for item in self.names)
        _fail(all(type(item) is ValidatedName for item in self.names) and raw == tuple(sorted(set(raw))))
        _fail(tuple(item[0] for item in self.children) == self.names)
        _fail(all(type(item[1]) is HostGeneration for item in self.children))

    @property
    def raw_names(self):
        return tuple(item.raw for item in self.names)


@dataclass(frozen=True)
class ParentDelta:
    action: str
    name: ValidatedName
    before: DirectorySnapshot
    after: DirectorySnapshot

    def __post_init__(self):
        _fail(self.action in {"create", "hardlink", "unlink", "rmdir", "metadata"})
        _fail(type(self.name) is ValidatedName)
        _fail(type(self.before) is DirectorySnapshot and type(self.after) is DirectorySnapshot)
        _fail(self.before.generation.key == self.after.generation.key)
        stable = ("mode", "uid", "gid")
        _fail(all(getattr(self.before.generation, key) == getattr(self.after.generation, key) for key in stable))
        before = set(self.before.raw_names)
        after = set(self.after.raw_names)
        if self.action in {"create", "hardlink"}:
            _fail(self.name.raw not in before and after == before | {self.name.raw})
        elif self.action in {"unlink", "rmdir"}:
            _fail(self.name.raw in before and after == before - {self.name.raw})
        else:
            _fail(after == before)


@dataclass(frozen=True)
class SourceApproval:
    revision: str
    manifest_sha256: str

    def __post_init__(self):
        _fail(type(self.revision) is str and len(self.revision) == 40)
        _fail(type(self.manifest_sha256) is str and len(self.manifest_sha256) == 64)
        _fail(all(character in "0123456789abcdef" for character in self.revision + self.manifest_sha256))


@dataclass(frozen=True)
class SourceEntry:
    path: str
    kind: str
    mode: int
    size: int
    sha256: str | None


@dataclass(frozen=True)
class SourceManifest:
    revision: str
    entries: tuple[SourceEntry, ...]
    digest: str


@dataclass(frozen=True)
class OperationControl:
    deadline_ns: int
    cancelled: object = field(compare=False, repr=False)

    def __post_init__(self):
        _exact_int(self.deadline_ns, 1)
        _fail(callable(self.cancelled))

    def check(self):
        value = self.cancelled()
        _fail(type(value) is bool and not value and time.monotonic_ns() < self.deadline_ns)


class CheckedFd:
    """One-owner descriptor: close once, never retry EINTR, retain both errors."""

    def __init__(self, number, role):
        _exact_int(number)
        _fail(type(role) is str and role)
        self.number = number
        self.role = role
        self.disposition = "open"

    def close(self, primary_error=None):
        _fail(self.disposition == "open")
        try:
            os.close(self.number)
        except OSError as error:
            self.disposition = "uncertain"
            raise RootfsFsError(primary_error, error) from error
        self.disposition = "closed"
        if primary_error is not None:
            raise primary_error


@dataclass(frozen=True)
class HeldNode:
    identity_fd: CheckedFd = field(compare=False)
    operation_fd: CheckedFd | None = field(compare=False)
    generation: HostGeneration


@dataclass(frozen=True)
class ChainComponent:
    name: ValidatedName
    node: HeldNode


@dataclass(frozen=True)
class HeldChain:
    anchor: HeldNode
    components: tuple[ChainComponent, ...]


@dataclass(frozen=True)
class NodePolicy:
    name: ValidatedName
    kind: str
    mode: int
    uid: int = 0
    gid: int = 0


@dataclass(frozen=True)
class WorkspaceAuthority:
    chain: HeldChain
    source_index: int
    completion_index: int
    manifest: SourceManifest


def _name(value):
    _fail(type(value) in {str, bytes})
    if type(value) is bytes:
        raw = value
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise RootfsFsError() from error
    else:
        text = value
        try:
            raw = os.fsencode(text)
        except UnicodeEncodeError as error:
            raise RootfsFsError() from error
        _fail(os.fsdecode(raw) == text)
        try:
            _fail(raw.decode("utf-8", "strict") == text)
        except UnicodeDecodeError as error:
            raise RootfsFsError() from error
    _fail(text not in {".", ".."} and unicodedata.normalize("NFC", text) == text)
    _fail(not any(ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF for character in text))
    _fail("/" not in text and "\x00" not in text)
    return ValidatedName(text, raw)


def _path(value):
    _fail(type(value) is str and value and not value.startswith("/") and len(value.encode("utf-8")) <= MAX_PATH_BYTES)
    parts = value.split("/")
    _fail(len(parts) <= MAX_PATH_COMPONENTS)
    names = tuple(_name(part) for part in parts)
    _fail("/".join(item.text for item in names) == value)
    return names


def _same_stat(left, right):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, key) == getattr(right, key) for key in fields)


def _parse_decimal(raw, minimum=0):
    _fail(raw and raw.isdigit() and (raw == b"0" or not raw.startswith(b"0")))
    value = int(raw)
    return _exact_int(value, minimum)


def _parse_fdinfo(raw, inode, expected_flags=FDINFO_FLAGS):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_FDINFO_BYTES and raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise RootfsFsError() from error
    lines = raw[:-1].split(b"\n")
    keys = (b"pos", b"flags", b"mnt_id", b"ino")
    _fail(len(lines) == len(keys))
    values = []
    for line, key in zip(lines, keys, strict=True):
        prefix = key + b":\t"
        _fail(line.startswith(prefix) and line.count(b":") == 1)
        values.append(line[len(prefix) :])
    _fail(values[0] == b"0" and values[1] == expected_flags)
    mount_id = _parse_decimal(values[2], 1)
    _fail(_parse_decimal(values[3], 1) == inode)
    return mount_id


def _read_bounded(fd, maximum, control):
    chunks = []
    total = 0
    while total <= maximum:
        control.check()
        chunk = os.read(fd, min(4096, maximum + 1 - total))
        control.check()
        if not chunk:
            break
        _fail(type(chunk) is bytes)
        chunks.append(chunk)
        total += len(chunk)
        _fail(total <= maximum)
    return b"".join(chunks)


def _open_fd(path, flags, role, control, dir_fd=None):
    control.check()
    number = os.open(path, flags) if dir_fd is None else os.open(path, flags, dir_fd=dir_fd)
    descriptor = CheckedFd(number, role)
    try:
        control.check()
    except BaseException as error:
        descriptor.close(error)
    return descriptor


def _mount_id(opath_fd, control, expected_flags=FDINFO_FLAGS):
    _fail(type(opath_fd) is CheckedFd and opath_fd.disposition == "open")
    control.check()
    before = os.fstat(opath_fd.number)
    control.check()
    descriptor = _open_fd(f"/proc/self/fdinfo/{opath_fd.number}", os.O_RDONLY | _O_CLOEXEC, "fdinfo", control)
    try:
        raw = _read_bounded(descriptor.number, MAX_FDINFO_BYTES, control)
        descriptor.close()
    except BaseException as error:
        if descriptor.disposition == "open":
            descriptor.close(error)
        raise
    control.check()
    after = os.fstat(opath_fd.number)
    control.check()
    _fail(_same_stat(before, after))
    return _parse_fdinfo(raw, before.st_ino, expected_flags)


def _generation(descriptor, mount_id, control):
    control.check()
    observed = os.fstat(descriptor.number)
    control.check()
    return HostGeneration(
        HostKey(mount_id, observed.st_dev, observed.st_ino, _kind(observed.st_mode)),
        stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid, observed.st_nlink,
        observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns,
    )


def _observe_node(opath_fd, operation_fd, control):
    mount_id = _mount_id(opath_fd, control)
    identity = _generation(opath_fd, mount_id, control)
    if operation_fd is not None:
        operational = _generation(operation_fd, mount_id, control)
        _fail(operational == identity)
    return identity


def _open_root_node(control):
    identity = _open_fd(b"/", IDENTITY_FLAGS, "root-identity", control)
    operation = None
    try:
        operation = _open_fd(b"/", DIRECTORY_FLAGS, "root-directory", control)
        generation = _observe_node(identity, operation, control)
        _fail(generation.key.kind == "directory")
        return HeldNode(identity, operation, generation)
    except BaseException as error:
        _close_owned((operation, identity), error)


def _open_path_node(parent, name, expected_kind, control):
    _fail(type(parent) is HeldNode and parent.operation_fd is not None)
    validated = name if type(name) is ValidatedName else _name(name)
    identity = _open_fd(validated.raw, IDENTITY_FLAGS, "node-identity", control, parent.operation_fd.number)
    operation = None
    try:
        if expected_kind == "directory":
            operation = _open_fd(validated.raw, DIRECTORY_FLAGS, "node-directory", control, parent.operation_fd.number)
        elif expected_kind == "file":
            operation = _open_fd(validated.raw, FILE_FLAGS, "node-file", control, parent.operation_fd.number)
        else:
            _fail(expected_kind == "symlink")
        generation = _observe_node(identity, operation, control)
        _fail(generation.key.kind == expected_kind)
        return HeldNode(identity, operation, generation)
    except BaseException as error:
        _close_owned((operation, identity), error)


def _require_policy(node, policy, root_key):
    generation = node.generation
    _fail(generation.key.kind == policy.kind and generation.mode == policy.mode)
    _fail(generation.uid == policy.uid and generation.gid == policy.gid)
    _fail(generation.key.mount_id == root_key.mount_id and generation.key.device == root_key.device)
    _fail(generation.nlink == 1 if policy.kind == "file" else generation.nlink >= 2)


def _close_owned(descriptors, primary_error=None):
    error = primary_error
    for descriptor in descriptors:
        if descriptor is not None and descriptor.disposition == "open":
            try:
                descriptor.close()
            except BaseException as close_error:
                error = RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _close_node(node, primary_error=None):
    _close_owned((node.operation_fd, node.identity_fd), primary_error)


def _close_chain(chain, primary_error=None):
    error = primary_error
    for node in tuple(item.node for item in reversed(chain.components)) + (chain.anchor,):
        try:
            _close_node(node)
        except BaseException as close_error:
            error = RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _open_anchored_chain(anchor, policies, control):
    _fail(type(anchor) is HeldNode and anchor.operation_fd is not None)
    components = []
    parent = anchor
    try:
        for policy in policies:
            control.check()
            node = _open_path_node(parent, policy.name, policy.kind, control)
            components.append(ChainComponent(policy.name, node))
            _require_policy(node, policy, anchor.generation.key)
            _require_empty_fd_xattrs(node, control)
            parent = node
        return HeldChain(anchor, tuple(components))
    except BaseException as error:
        for item in reversed(components):
            try:
                _close_node(item.node)
            except BaseException as close_error:
                error = RootfsFsError(error, close_error)
        raise error


def _revalidate_chain(chain, control, parent_delta=None):
    _fail(type(chain) is HeldChain and (parent_delta is None or type(parent_delta) is ParentDelta))
    fresh = _open_root_node(control)
    opened = []
    error = None
    matched_delta = 0
    try:
        _fail(fresh.generation == chain.anchor.generation)
        parent = fresh
        for component in chain.components:
            expected = component.node.generation
            if parent_delta is not None and expected.key == parent_delta.after.generation.key:
                _fail(expected == parent_delta.before.generation)
                expected = parent_delta.after.generation
                matched_delta += 1
            node = _open_path_node(parent, component.name, expected.key.kind, control)
            opened.append(node)
            _fail(node.generation == expected)
            parent = node
        _fail(parent_delta is None or matched_delta == 1)
    except BaseException as caught:
        error = caught
    for node in reversed(opened):
        try:
            _close_node(node)
        except BaseException as close_error:
            error = RootfsFsError(error, close_error)
    try:
        _close_node(fresh)
    except BaseException as close_error:
        error = RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _list_names(node, control):
    _fail(node.operation_fd is not None and node.generation.key.kind == "directory")
    control.check()
    values = os.listdir(node.operation_fd.number)
    control.check()
    _fail(type(values) is list)
    names = tuple(_name(value) for value in values)
    _fail(all(type(value) is str for value in values))
    _fail(len({item.raw for item in names}) == len(names))
    return tuple(sorted(names, key=lambda item: item.raw))


def _observe_child(parent, name, control):
    identity = _open_fd(name.raw, IDENTITY_FLAGS, "child-observation", control, parent.operation_fd.number)
    try:
        generation = _observe_node(identity, None, control)
        identity.close()
        return generation
    except BaseException as error:
        if identity.disposition == "open":
            identity.close(error)
        raise


def _enumerate_stable(directory_node, control):
    first_generation = _observe_node(directory_node.identity_fd, directory_node.operation_fd, control)
    first = _list_names(directory_node, control)
    _fail(_observe_node(directory_node.identity_fd, directory_node.operation_fd, control) == first_generation)
    second = _list_names(directory_node, control)
    _fail(_observe_node(directory_node.identity_fd, directory_node.operation_fd, control) == first_generation and second == first)
    children = tuple((name, _observe_child(directory_node, name, control)) for name in first)
    third = _list_names(directory_node, control)
    _fail(_observe_node(directory_node.identity_fd, directory_node.operation_fd, control) == first_generation and third == first)
    return DirectorySnapshot(first_generation, first, children)


def _load_xattrs():
    _fail(sys.platform == "linux")
    library = ctypes.CDLL(None, use_errno=True)
    flistxattr = library.flistxattr
    flistxattr.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
    flistxattr.restype = ctypes.c_ssize_t
    llistxattr = library.llistxattr
    llistxattr.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    llistxattr.restype = ctypes.c_ssize_t
    return flistxattr, llistxattr


def _zero_xattrs(function, subject, control):
    control.check()
    ctypes.set_errno(0)
    result = function(subject, None, 0)
    saved_errno = ctypes.get_errno()
    control.check()
    _fail(type(result) is int and result == 0 and saved_errno == 0)


def _require_empty_fd_xattrs(node, control):
    _fail(node.operation_fd is not None)
    before = _observe_node(node.identity_fd, node.operation_fd, control)
    flistxattr, _unused = _load_xattrs()
    _zero_xattrs(flistxattr, node.operation_fd.number, control)
    _fail(_observe_node(node.identity_fd, node.operation_fd, control) == before)


def _require_empty_symlink_xattrs(chain, parent, name, child, control):
    _fail(PRIVILEGED_MUTATOR_EXCLUSION.startswith("Concurrent EUID-0"))
    validated = name if type(name) is ValidatedName else _name(name)
    _fail(type(chain) is HeldChain and chain.components and chain.components[-1].node is parent)
    _fail(child.generation.key.kind == "symlink" and parent.operation_fd is not None)
    _revalidate_chain(chain, control)
    parent_before = _observe_node(parent.identity_fd, parent.operation_fd, control)
    child_before = _observe_child(parent, validated, control)
    _fail(child_before == child.generation)
    proc_parent = _open_fd(f"/proc/self/fd/{parent.operation_fd.number}", _O_PATH | _O_DIRECTORY | _O_CLOEXEC, "proc-parent", control)
    try:
        control.check()
        proc_stat = os.fstat(proc_parent.number)
        control.check()
        operation_stat = os.fstat(parent.operation_fd.number)
        control.check()
        _fail(_same_stat(proc_stat, operation_stat))
        proc_parent.close()
    except BaseException as error:
        if proc_parent.disposition == "open":
            proc_parent.close(error)
        raise
    _unused, llistxattr = _load_xattrs()
    proc_path = b"/proc/self/fd/" + str(parent.operation_fd.number).encode("ascii") + b"/" + validated.raw
    _zero_xattrs(llistxattr, proc_path, control)
    _fail(_observe_child(parent, validated, control) == child_before)
    _fail(_observe_node(parent.identity_fd, parent.operation_fd, control) == parent_before)
    _revalidate_chain(chain, control)


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        _fail(type(key) is str and key not in value)
        value[key] = item
    return value


def _canonical_json(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST_BYTES and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=lambda _value: _fail(False))
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise RootfsFsError() from error
    _fail(raw == encoded)
    return value


def _parse_source_manifest(raw, approval):
    _fail(type(approval) is SourceApproval and hashlib.sha256(raw).hexdigest() == approval.manifest_sha256)
    value = _canonical_json(raw)
    _fail(type(value) is dict and tuple(value) == ("version", "revision", "entries"))
    _fail(value["version"] == SOURCE_MANIFEST_VERSION and value["revision"] == approval.revision)
    rows = value["entries"]
    _fail(type(rows) is list and 0 < len(rows) <= MAX_SOURCE_ENTRIES)
    entries = []
    previous = None
    for row in rows:
        _fail(type(row) is dict and tuple(row) == ("path", "kind", "mode", "size", "sha256"))
        path = row["path"]
        names = _path(path)
        _fail(names[0].raw != b".git" and names[0].raw != SOURCE_MANIFEST_NAME)
        _fail(tuple(item.raw for item in names[:3]) != STATE_RELATIVE)
        kind = row["kind"]
        mode = row["mode"]
        size = row["size"]
        digest = row["sha256"]
        _fail(kind in {"directory", "file"} and type(mode) is int and 0 <= mode <= 0o7777)
        _fail(type(size) is int and 0 <= size <= MAX_SOURCE_FILE_BYTES and mode & 0o022 == 0)
        if kind == "directory":
            _fail(mode == 0o700 and size == 0 and digest is None)
        else:
            _fail(type(digest) is str and len(digest) == 64 and all(character in "0123456789abcdef" for character in digest))
        raw_path = path.encode("utf-8")
        _fail(previous is None or previous < raw_path)
        previous = raw_path
        entries.append(SourceEntry(path, kind, mode, size, digest))
    sentinel = next((item for item in entries if item.path == SOURCE_SENTINEL_NAME.decode()), None)
    _fail(sentinel is not None)
    _fail((sentinel.kind, sentinel.mode, sentinel.size) == ("file", 0o400, len(SOURCE_SENTINEL)))
    _fail(sentinel.sha256 == hashlib.sha256(SOURCE_SENTINEL).hexdigest())
    return SourceManifest(approval.revision, tuple(entries), approval.manifest_sha256)


def _read_regular(node, maximum, control):
    _fail(node.operation_fd is not None and node.generation.key.kind == "file" and node.generation.size <= maximum)
    before = _observe_node(node.identity_fd, node.operation_fd, control)
    chunks = []
    offset = 0
    while offset < before.size:
        control.check()
        chunk = os.pread(node.operation_fd.number, min(1024 * 1024, before.size - offset), offset)
        control.check()
        _fail(type(chunk) is bytes and chunk)
        chunks.append(chunk)
        offset += len(chunk)
    _fail(offset == before.size and _observe_node(node.identity_fd, node.operation_fd, control) == before)
    return b"".join(chunks)


def _manifest_node(source, name, control):
    node = _open_path_node(source, name, "file", control)
    try:
        _require_policy(node, NodePolicy(name, "file", 0o400), source.generation.key)
        _require_empty_fd_xattrs(node, control)
        return node
    except BaseException as error:
        _close_node(node, error)


def _verify_source_bundle(source, approval, control):
    _fail(source.generation == _observe_node(source.identity_fd, source.operation_fd, control))
    _fail(source.generation.key.kind == "directory" and source.generation.mode == 0o700)
    _fail(source.generation.uid == source.generation.gid == 0)
    _require_empty_fd_xattrs(source, control)
    manifest_node = _manifest_node(source, _name(SOURCE_MANIFEST_NAME), control)
    try:
        raw = _read_regular(manifest_node, MAX_MANIFEST_BYTES, control)
        manifest = _parse_source_manifest(raw, approval)
        _close_node(manifest_node)
    except BaseException as error:
        if manifest_node.identity_fd.disposition == "open":
            _close_node(manifest_node, error)
        raise
    expected = {entry.path: entry for entry in manifest.entries}
    observed = {}

    def visit(directory, prefix):
        snapshot = _enumerate_stable(directory, control)
        for name, child_generation in snapshot.children:
            relative = name.text if not prefix else prefix + "/" + name.text
            if not prefix and name.raw == SOURCE_MANIFEST_NAME:
                continue
            parts = tuple(item.raw for item in _path(relative))
            if parts == STATE_RELATIVE:
                _fail(child_generation.key.kind == "directory")
                continue
            _fail(parts[:1] != (b".git",) and parts[:3] != STATE_RELATIVE)
            entry = expected.get(relative)
            _fail(entry is not None and child_generation.key.kind == entry.kind)
            node = _open_path_node(directory, name, entry.kind, control)
            try:
                _fail(node.generation == child_generation)
                _require_policy(node, NodePolicy(name, entry.kind, entry.mode), source.generation.key)
                _require_empty_fd_xattrs(node, control)
                if entry.kind == "file":
                    _fail(node.generation.size == entry.size)
                    content = _read_regular(node, MAX_SOURCE_FILE_BYTES, control)
                    _fail(hashlib.sha256(content).hexdigest() == entry.sha256)
                    if relative == SOURCE_SENTINEL_NAME.decode():
                        _fail(content == SOURCE_SENTINEL)
                observed[relative] = node.generation
                if entry.kind == "directory":
                    visit(node, relative)
                _close_node(node)
            except BaseException as error:
                if node.identity_fd.disposition == "open":
                    _close_node(node, error)
                raise

    visit(source, "")
    _fail(set(observed) == set(expected))
    _fail(source.generation == _observe_node(source.identity_fd, source.operation_fd, control))
    return manifest


def _open_workspace_anchor(control):
    _fail(sys.platform == "linux" and os.geteuid() == 0)
    _fail(sys.getfilesystemencoding() == "utf-8" and sys.getfilesystemencodeerrors() == "surrogateescape")
    root = _open_root_node(control)
    try:
        _fail(root.generation.uid == root.generation.gid == 0 and root.generation.mode == 0o755)
        _fail(root.generation.nlink >= 2)
        _require_empty_fd_xattrs(root, control)
        return root
    except BaseException as error:
        _close_node(root, error)


def _fixed_policies():
    values = (
        (b"var", 0o755), (b"lib", 0o755), (b"cogs", 0o700), (b"stage2-completion-v1", 0o700),
        (b"source", 0o700), (b"deploy", 0o700), (b"aws-feasibility", 0o700), (b".state", 0o700),
        (b"completion-v1", 0o700),
    )
    return tuple(NodePolicy(_name(name), "directory", mode) for name, mode in values)


def _open_fixed_workspace(approval, control):
    root = _open_workspace_anchor(control)
    try:
        chain = _open_anchored_chain(root, _fixed_policies(), control)
        source_index = 4
        completion_index = 8
        manifest = _verify_source_bundle(chain.components[source_index].node, approval, control)
        _revalidate_chain(chain, control)
        return WorkspaceAuthority(chain, source_index, completion_index, manifest)
    except BaseException as error:
        if root.identity_fd.disposition == "open":
            if "chain" in locals():
                _close_chain(chain, error)
            root_error = error
            try:
                _close_node(root)
            except BaseException as close_error:
                root_error = RootfsFsError(root_error, close_error)
            raise root_error
        raise

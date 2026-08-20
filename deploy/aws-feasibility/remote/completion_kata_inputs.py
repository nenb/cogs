"""Fixed, fd-relative Kata input/control ownership foundation.

Historical test routes remain non-authoritative: no public ``InputPermit`` or
``KeyMaterialGrant`` exists.  The package-private production route is composed
only inside trusted T1, consumes four durable ssh-keygen
outcomes, and binds every graph operation to the same locked journal lineage.
"""
from dataclasses import dataclass
import base64
import binascii
import ctypes
import fcntl
import hashlib
import json
import os
import struct
import sys
import time
import zlib
import completion_fixtures as fixtures
import completion_kata_command_policy as command_policy
import completion_kata_fdmap as fdmap
import completion_kata_operation as operation
import completion_kata_owner as owner_helpers
import completion_rootfs_fs as fs

VERSION = "cogs.stage2-kata-input-manifest/v1"
INPUT_NAME = fs._name("kata-input-v1")
MANIFEST_NAME = fs._name(".cogs-stage2-kata-input-manifest-v1.json")
KEY_STAGE_PREFIX = "kata-key-stage-v1-"
CLIENT_KEY = "private/ssh_client_ed25519_key"
KNOWN_HOSTS = "private/known_hosts"
SERVER_KEY = "share/ssh_host_ed25519_key"
AUTHORIZED_KEYS = "share/authorized_keys"
CLIENT_COMMENT = b"cogs-stage2-client-v1"
SERVER_COMMENT = b"cogs-stage2-server-v1"
SSH_ALIAS = b"cogs-stage2-ssh-v1"
MAX_PRIVATE = 16_384
GRANT_BIRTH_WINDOW_NS = 1_200_000_000_000

class _StatxTimestamp(ctypes.Structure):
    _fields_ = (("sec", ctypes.c_longlong), ("nsec", ctypes.c_uint), ("reserved", ctypes.c_int))
class _Statx(ctypes.Structure):
    _fields_ = (("mask", ctypes.c_uint), ("blksize", ctypes.c_uint),
                ("attributes", ctypes.c_ulonglong), ("nlink", ctypes.c_uint),
                ("uid", ctypes.c_uint), ("gid", ctypes.c_uint), ("mode", ctypes.c_ushort),
                ("spare0", ctypes.c_ushort), ("ino", ctypes.c_ulonglong),
                ("size", ctypes.c_ulonglong), ("blocks", ctypes.c_ulonglong),
                ("attributes_mask", ctypes.c_ulonglong), ("atime", _StatxTimestamp),
                ("btime", _StatxTimestamp), ("ctime", _StatxTimestamp),
                ("mtime", _StatxTimestamp), ("rdev_major", ctypes.c_uint),
                ("rdev_minor", ctypes.c_uint), ("dev_major", ctypes.c_uint),
                ("dev_minor", ctypes.c_uint), ("mnt_id", ctypes.c_ulonglong),
                ("dio_mem_align", ctypes.c_uint), ("dio_offset_align", ctypes.c_uint),
                ("spare", ctypes.c_ulonglong * 12))
def _rename_noreplace(parent_fd, source, destination, control):
    _fail(sys.platform == "linux" and os.uname().machine == "x86_64")
    control.check(); result = ctypes.CDLL(None, use_errno=True).syscall(
        316, parent_fd, ctypes.c_char_p(source.raw), parent_fd,
        ctypes.c_char_p(destination.raw), 1)
    control.check(); _fail(result == 0)

def _birth_authority(descriptor, control):
    _fail(sys.platform == "linux" and os.uname().machine == "x86_64")
    control.check(); value = _Statx()
    result = ctypes.CDLL(None, use_errno=True).syscall(
        332, descriptor, ctypes.c_char_p(b""), 0x1000 | 0x4000, 0x00000800 | 0x00001000,
        ctypes.byref(value))
    control.check(); _fail(result == 0 and value.mask & 0x00000800 and value.mask & 0x00001000)
    raw = bytearray(8); _fail(fcntl.ioctl(descriptor, 0x80087601, raw, True) == 0)
    version = struct.unpack("@L", raw)[0]
    return value.mnt_id, value.btime.sec * 1_000_000_000 + value.btime.nsec, version
MAX_PUBLIC = 1_024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_MOUNTINFO = 1024 * 1024
MAX_MOUNTS = 4_096
ANONYMOUS_FDINFO_FLAGS = (b"022440002", b"022300002")
FIXTURE_SUBTREE_SHA256 = "33aafa9c8a0629ee4d708eb692d9231cf2713244046a00409ea45da6f6c722d7"
COMPRESSED_OBJECTS_SHA256 = "f5c9e0477c73c0a9099566b5a15c5b9721cb8743557b51c3acde11098611300e"
TEST_RFC8032_SHA256 = (
    "69f0d790d1f96a054a25f6c9a3e20fde352666e7caaf4ab991c3e11cd86814d2",
    "f412d067a6629139b6f0bf9fce4f97ef25c4b120f5e546affc8ab479d143573d",
    "ae685b6fa951919bcecc3578237bbf1caba198ae0ed455e0203ef9e560e42e56",
    "195854a68284c505ba4a597ee88415b392cb538bf83eb9cb4285f2092924d9df",
)
HEX = frozenset("0123456789abcdef")

class InputError(Exception):
    """The exact input graph could not be established or proved."""

class CloseUncertainError(InputError):
    """At least one owned fd close failed, so route ownership is poisoned."""
    def __init__(self, primary, close_errors):
        self.primary, self.close_errors = primary, tuple(close_errors)
        super().__init__()

def _fail(condition):
    if not condition:
        raise InputError()

def _sha(raw):
    return hashlib.sha256(raw).hexdigest()

@dataclass(frozen=True)
class KeyMaterial:
    client_private: bytes
    client_public: bytes
    server_private: bytes
    server_public: bytes

@dataclass(frozen=True)
class ExpectedEntry:
    path: str
    kind: str
    mode: int
    content: bytes | None

@dataclass(frozen=True)
class InputIdentity:
    operation_token: str
    manifest_sha256: str
    manifest_size: int
    entry_count: int

def _u32(raw, offset):
    _fail(type(raw) is bytes and type(offset) is int and offset + 4 <= len(raw))
    return struct.unpack(">I", raw[offset : offset + 4])[0], offset + 4

def _ssh_string(raw, offset, maximum=MAX_PRIVATE):
    size, offset = _u32(raw, offset)
    _fail(size <= maximum and offset + size <= len(raw))
    return raw[offset : offset + size], offset + size

def _public_row(raw, comment):
    _fail(type(raw) is bytes and type(comment) is bytes and 0 < len(raw) <= MAX_PUBLIC)
    _fail(raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\x00" not in raw)
    parts = raw[:-1].split(b" ")
    _fail(len(parts) == 3 and parts[0] == b"ssh-ed25519" and parts[2] == comment)
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise InputError() from error
    _fail(base64.b64encode(blob) == parts[1] and len(blob) == 51)
    key_type, offset = _ssh_string(blob, 0, 64)
    public, offset = _ssh_string(blob, offset, 64)
    _fail(offset == len(blob) and key_type == b"ssh-ed25519" and len(public) == 32)
    return blob, public

def _private_key(raw, expected_blob, expected_public, comment):
    _fail(type(raw) is bytes and 128 <= len(raw) <= MAX_PRIVATE and b"\x00" not in raw)
    lines = raw.splitlines(keepends=True)
    _fail(4 <= len(lines) <= 256 and all(line.endswith(b"\n") for line in lines))
    _fail(lines[0] == b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    _fail(lines[-1] == b"-----END OPENSSH PRIVATE KEY-----\n")
    body_lines = tuple(line[:-1] for line in lines[1:-1])
    _fail(body_lines and all(1 <= len(line) <= 70 for line in body_lines))
    _fail(all(len(line) == 70 for line in body_lines[:-1]))
    encoded = b"".join(body_lines)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise InputError() from error
    _fail(base64.b64encode(decoded) == encoded)
    magic = b"openssh-key-v1\x00"
    _fail(decoded.startswith(magic))
    offset = len(magic)
    cipher, offset = _ssh_string(decoded, offset, 64)
    kdf, offset = _ssh_string(decoded, offset, 64)
    options, offset = _ssh_string(decoded, offset, 256)
    count, offset = _u32(decoded, offset)
    public_blob, offset = _ssh_string(decoded, offset, MAX_PUBLIC)
    private_blob, offset = _ssh_string(decoded, offset, MAX_PRIVATE)
    _fail(offset == len(decoded) and cipher == kdf == b"none" and options == b"" and count == 1)
    _fail(public_blob == expected_blob)
    check1, inner = _u32(private_blob, 0)
    check2, inner = _u32(private_blob, inner)
    key_type, inner = _ssh_string(private_blob, inner, 64)
    public, inner = _ssh_string(private_blob, inner, 64)
    private, inner = _ssh_string(private_blob, inner, 128)
    private_comment, inner = _ssh_string(private_blob, inner, 256)
    padding = private_blob[inner:]
    _fail(check1 == check2 and key_type == b"ssh-ed25519")
    _fail(public == expected_public and len(private) == 64 and private[32:] == public)
    _fail(private_comment == comment and 1 <= len(padding) <= 8)
    _fail(padding == bytes(range(1, len(padding) + 1)))

def _validate_key_material(value):
    """Parse structure, not seed math; production binds ``ssh-keygen -y`` too."""
    _fail(type(value) is KeyMaterial)
    client_blob, client_public = _public_row(value.client_public, CLIENT_COMMENT)
    server_blob, server_public = _public_row(value.server_public, SERVER_COMMENT)
    _fail(client_public != server_public and client_blob != server_blob)
    _private_key(value.client_private, client_blob, client_public, CLIENT_COMMENT)
    _private_key(value.server_private, server_blob, server_public, SERVER_COMMENT)
    return value


def _git_object(kind, raw, oid):
    framed = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\x00" + raw
    actual = hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    _fail(actual == oid)
    return zlib.compress(framed, 9)

def _fixed_fixture_entries():
    model = fixtures.fixed_fixtures()
    git = model.git
    entries = [
        ExpectedEntry("share/fixture", "directory", 0o555, None),
        ExpectedEntry("share/fixture/git.git", "directory", 0o555, None),
        ExpectedEntry("share/fixture/git.git/objects", "directory", 0o555, None),
        ExpectedEntry("share/fixture/git.git/refs", "directory", 0o555, None),
        ExpectedEntry("share/fixture/git.git/refs/heads", "directory", 0o555, None),
        ExpectedEntry("share/fixture/git.git/HEAD", "file", 0o444, b"ref: refs/heads/main\n"),
        ExpectedEntry(
            "share/fixture/git.git/config", "file", 0o444,
            b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n",
        ),
        ExpectedEntry("share/fixture/git.git/refs/heads/main", "file", 0o444,
                      git.commit_oid.encode("ascii") + b"\n"),
    ]
    objects = []
    for record, oid in zip(git.source.records[2:], git.blob_oids, strict=True):
        objects.append((oid, _git_object("blob", record.content, oid)))
    nested = b"".join(
        b"100644 file-" + f"{index:04d}".encode("ascii") + b".txt\x00" + bytes.fromhex(oid)
        for index, oid in enumerate(git.blob_oids)
    )
    root = b"40000 files\x00" + bytes.fromhex(git.nested_tree_oid)
    objects.extend((
        (git.nested_tree_oid, _git_object("tree", nested, git.nested_tree_oid)),
        (git.root_tree_oid, _git_object("tree", root, git.root_tree_oid)),
        (git.commit_oid, _git_object("commit", git.commit, git.commit_oid)),
    ))
    fanouts = sorted({oid[:2] for oid, _raw in objects})
    entries.extend(ExpectedEntry(f"share/fixture/git.git/objects/{name}", "directory", 0o555, None)
                   for name in fanouts)
    entries.extend(
        ExpectedEntry(f"share/fixture/git.git/objects/{oid[:2]}/{oid[2:]}", "file", 0o444, raw)
        for oid, raw in sorted(objects)
    )
    entries.append(ExpectedEntry("share/fixture/package", "directory", 0o555, None))
    for record in model.package.source.records[1:]:
        entries.append(ExpectedEntry(
            "share/fixture/package/" + record.path, record.kind,
            0o555 if record.kind == "directory" else 0o444, record.content,
        ))
    return tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))

_FIXED_FIXTURE = _fixed_fixture_entries()

def _fixture_digest(entries):
    rows = [{
        "kind": entry.kind, "mode": entry.mode, "path": entry.path,
        "sha256": None if entry.content is None else _sha(entry.content),
        "size": 0 if entry.content is None else len(entry.content),
    } for entry in entries]
    return _sha(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("utf-8") + b"\n")

def _compressed_objects_digest(entries):
    framed = bytearray()
    for entry in entries:
        if "/objects/" in entry.path and entry.kind == "file":
            path = entry.path.encode("utf-8")
            framed += len(path).to_bytes(4, "big") + path
            framed += len(entry.content).to_bytes(8, "big") + entry.content
    return _sha(bytes(framed))

# Pin key-independent bytes; reject different ambient DEFLATE output.
_fail(_fixture_digest(_FIXED_FIXTURE) == FIXTURE_SUBTREE_SHA256)
_fail(_compressed_objects_digest(_FIXED_FIXTURE) == COMPRESSED_OBJECTS_SHA256)

def _expected_graph(material):
    material = _validate_key_material(material)
    client = material.client_public[:-1]
    server = material.server_public[:-1].split(b" ", 2)
    fixed = (
        ExpectedEntry(".", "directory", 0o700, None),
        ExpectedEntry("private", "directory", 0o700, None),
        ExpectedEntry(CLIENT_KEY, "file", 0o400, material.client_private),
        ExpectedEntry(KNOWN_HOSTS, "file", 0o400,
                      SSH_ALIAS + b" " + server[0] + b" " + server[1] + b"\n"),
        ExpectedEntry("share", "directory", 0o555, None),
        ExpectedEntry(AUTHORIZED_KEYS, "file", 0o400, b"restrict " + client + b"\n"),
        ExpectedEntry(SERVER_KEY, "file", 0o400, material.server_private),
    )
    graph = tuple(sorted(fixed + _FIXED_FIXTURE, key=lambda item: (item.path != ".", item.path.encode("utf-8"))))
    paths = {item.path for item in graph}
    _fail(len(paths) == len(graph) and all(
        item.path == "." or item.path.rpartition("/")[0] in paths or
        (not item.path.rpartition("/")[0] and "." in paths) for item in graph
    ))
    return graph

def _key_value(value):
    return {"device": value.device, "inode": value.inode, "kind": value.kind, "mount_id": value.mount_id}

def _parse_key(value, kind=None):
    _fail(type(value) is dict and tuple(sorted(value)) == ("device", "inode", "kind", "mount_id"))
    _fail(all(type(value[name]) is int and value[name] >= 0 for name in ("device", "inode", "mount_id")))
    _fail(value["mount_id"] > 0 and value["inode"] > 0)
    _fail(type(value["kind"]) is str and value["kind"] in {"directory", "file"})
    _fail(kind is None or value["kind"] == kind)
    return fs.HostKey(value["mount_id"], value["device"], value["inode"], value["kind"])

def _directory_links(graph, path):
    prefix = "" if path == "." else path + "/"
    return 2 + sum(
        item.kind == "directory" and item.path.startswith(prefix) and
        "/" not in item.path[len(prefix):]
        for item in graph if item.path != path
    )

def _entry_row(entry, graph, key):
    return {
        "identity": _key_value(key), "kind": entry.kind, "mode": entry.mode,
        "nlink": _directory_links(graph, entry.path) if entry.kind == "directory" else 1,
        "path": entry.path, "sha256": None if entry.content is None else _sha(entry.content),
        "size": 0 if entry.content is None else len(entry.content),
    }

def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise InputError() from error

# The canonical operation-specific manifest excludes itself; its identity is
# settled independently by the operation grant, avoiding a circular digest.
def _manifest_bytes(token, graph, identities):
    _fail(type(token) is str and len(token) == 64 and set(token) <= HEX and token != "0" * 64)
    rows = [_entry_row(entry, graph, identities[entry.path]) for entry in graph]
    return _canonical({"entries": rows, "operation_token": token, "version": VERSION})

def _pairs(items):
    result = {}
    for name, value in items:
        _fail(type(name) is str and name not in result)
        result[name] = value
    return result

def _parse_manifest(raw, token):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _value: _fail(False))
    except (UnicodeError, ValueError, TypeError, InputError) as error:
        raise InputError() from error
    _fail(raw == _canonical(value) and type(value) is dict)
    _fail(set(value) == {"entries", "operation_token", "version"})
    _fail(value["version"] == VERSION and value["operation_token"] == token)
    rows = value["entries"]
    _fail(type(rows) is list and 1 <= len(rows) <= 2_048)
    previous = None
    for row in rows:
        _fail(type(row) is dict and set(row) == {"identity", "kind", "mode", "nlink", "path", "sha256", "size"})
        path = row["path"]
        _fail(type(path) is str and (path == "." or "/".join(name.text for name in fs._path(path)) == path))
        encoded = path.encode("utf-8")
        _fail(previous is None or previous < encoded)
        previous = encoded
        kind = row["kind"]
        _fail(kind in {"directory", "file"} and _parse_key(row["identity"], kind))
        _fail(type(row["mode"]) is int and type(row["nlink"]) is int and type(row["size"]) is int)
        _fail(row["mode"] in {0o400, 0o444, 0o555, 0o700} and row["nlink"] >= 1 and row["size"] >= 0)
        _fail((kind == "directory" and row["sha256"] is None and row["size"] == 0) or
              (kind == "file" and type(row["sha256"]) is str and len(row["sha256"]) == 64 and
               set(row["sha256"]) <= HEX))
    return value

def _mount_unescape(raw):
    output = bytearray()
    index = 0
    while index < len(raw):
        if raw[index:index + 1] == b"\\":
            _fail(index + 4 <= len(raw) and raw[index + 1:index + 4] in {b"040", b"011", b"012", b"134"})
            output.append(int(raw[index + 1:index + 4], 8))
            index += 4
        else:
            _fail(raw[index] not in {0, 10, 13})
            output.append(raw[index])
            index += 1
    return bytes(output)

def _parse_mountinfo(raw, source):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_MOUNTINFO and raw.endswith(b"\n") and b"\x00" not in raw)
    source_raw = os.fsencode(source.rstrip("/"))
    _fail(source_raw.startswith(b"/") and b"//" not in source_raw)
    lines = raw.splitlines()
    _fail(1 <= len(lines) <= MAX_MOUNTS and all(0 < len(line) <= 16_384 for line in lines))
    for line in lines:
        fields = line.split(b" ")
        _fail(len(fields) >= 10 and fields.count(b"-") == 1)
        separator = fields.index(b"-")
        _fail(separator >= 6 and separator + 3 <= len(fields))
        _fail(fields[0].isdigit() and fields[1].isdigit() and int(fields[0]) > 0)
        mount_root = _mount_unescape(fields[3])
        mountpoint = _mount_unescape(fields[4])
        mount_source = _mount_unescape(fields[separator + 2])
        _fail(mountpoint.startswith(b"/") and mount_root.startswith(b"/"))
        for candidate in (mount_root, mountpoint, mount_source):
            _fail(not (candidate == source_raw or candidate.startswith(source_raw + b"/")))
    return len(lines)

def _read_mountinfo(control):
    descriptor = fs._open_fd("/proc/self/mountinfo", os.O_RDONLY | fs._O_CLOEXEC,
                             "kata-input-mountinfo", control)
    try:
        raw = fs._read_bounded(descriptor.number, MAX_MOUNTINFO, control)
    except BaseException as error:
        _close_owned((descriptor,), error)
    _close_owned((descriptor,))
    return raw

def _checkpoint(control, _label):
    """Named fault boundary used by the guarded recovery qualification."""
    control.check()

def _write_all(descriptor, raw, control):
    offset = 0
    while offset < len(raw):
        control.check()
        count = os.write(descriptor.number, raw[offset:])
        control.check()
        _fail(type(count) is int and 0 < count <= len(raw) - offset)
        offset += count

def _close_owned(owners, primary=None):
    """Close all owned fds and retain the primary plus every close failure."""
    if type(primary) is CloseUncertainError:
        original, close_errors = primary.primary, list(primary.close_errors)
    else:
        original, close_errors = primary, []
    seen = set()
    for owner in (owner for owner in owners if owner is not None):
        descriptors = ((owner.operation_fd, owner.identity_fd)
                       if type(owner) is fs.HeldNode else (owner,))
        for descriptor in descriptors:
            if descriptor is not None and id(descriptor) not in seen:
                seen.add(id(descriptor))
                if descriptor.disposition == "open":
                    try:
                        descriptor.close()
                    except BaseException as close_error:
                        close_errors.append(close_error)
    if close_errors:
        raise CloseUncertainError(original, close_errors)
    if original is not None:
        raise original

def _open_relative(root, path, kind, control):
    if path == ".":
        return root, ()
    parent = root
    intermediates = []
    try:
        names = fs._path(path)
        for name in names[:-1]:
            parent = fs._open_path_node(parent, name, "directory", control)
            intermediates.append(parent)
        node = fs._open_path_node(parent, names[-1], kind, control)
        return node, tuple(reversed(intermediates))
    except BaseException as error:
        _close_owned(tuple(reversed(intermediates)), error)

def _open_parent(root, path, control):
    parent_path, _slash, leaf = path.rpartition("/")
    if not parent_path:
        return root, fs._name(leaf), ()
    parent, intermediates = _open_relative(root, parent_path, "directory", control)
    return parent, fs._name(leaf), intermediates

def _optional_child(parent, name, control):
    snapshot = fs._enumerate_stable(parent, control)
    for child_name, generation in snapshot.children:
        if child_name == name:
            return generation, snapshot
    return None, snapshot

def _anonymous_file(parent, raw, mode, control):
    _fail(sys.platform == "linux" and hasattr(os, "O_TMPFILE"))
    descriptor = identity = generation = None
    try:
        flags = os.O_TMPFILE | os.O_RDWR | fs._O_CLOEXEC
        descriptor = fs.CheckedFd(os.open(b".", flags, mode, dir_fd=parent.operation_fd.number),
                                  "kata-input-anonymous")
        _write_all(descriptor, raw, control)
        os.fchown(descriptor.number, 0, 0)
        os.fchmod(descriptor.number, mode)
        os.fsync(descriptor.number)
        identity = fs._open_fd(f"/proc/self/fd/{descriptor.number}", fs._O_PATH | fs._O_CLOEXEC,
                               "kata-input-anonymous-identity", control)
        os.lseek(descriptor.number, 0, os.SEEK_SET)
        mount_id = fs._mount_id(descriptor, control, ANONYMOUS_FDINFO_FLAGS)
        generation = fs._generation(identity, mount_id, control)
        _fail(fs._generation(descriptor, mount_id, control) == generation)
        _fail(generation.key.kind == "file" and generation.nlink == 0 and generation.mode == mode)
        _fail(generation.uid == generation.gid == 0 and generation.size == len(raw))
        fs._zero_xattrs(fs._load_xattrs()[0], descriptor.number, control)
        os.lseek(descriptor.number, 0, os.SEEK_SET)
        _fail(fs._read_bounded(descriptor.number, len(raw), control) == raw)
        return descriptor, identity, generation
    except BaseException as error:
        if identity is not None:
            _close_owned((fs.HeldNode(identity, descriptor, generation),), error)
        _close_owned((descriptor,), error)

def _link_tmp(descriptor, parent, name):
    library = ctypes.CDLL(None, use_errno=True)
    linkat = library.linkat
    linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    linkat.restype = ctypes.c_int
    if linkat(descriptor.number, b"", parent.operation_fd.number, name.raw, 0x1000) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))

def _material_from_root(root, control):
    def read(path, maximum):
        node, intermediates = _open_relative(root, path, "file", control)
        try:
            return fs._read_regular(node, maximum, control)
        except BaseException as error:
            _close_owned((node,) + intermediates, error)
        finally:
            if node.identity_fd.disposition == "open":
                _close_owned((node,) + intermediates)
    client_private = read(CLIENT_KEY, MAX_PRIVATE)
    server_private = read(SERVER_KEY, MAX_PRIVATE)
    authorized = read(AUTHORIZED_KEYS, MAX_PUBLIC + 16)
    known = read(KNOWN_HOSTS, MAX_PUBLIC + 64)
    _fail(authorized.startswith(b"restrict ssh-ed25519 ") and authorized.count(b"\n") == 1)
    _fail(known.startswith(SSH_ALIAS + b" ssh-ed25519 ") and known.count(b"\n") == 1)
    client_public = authorized[len(b"restrict "):]
    server_fields = known[:-1].split(b" ")
    _fail(len(server_fields) == 3)
    server_public = server_fields[1] + b" " + server_fields[2] + b" " + SERVER_COMMENT + b"\n"
    return _validate_key_material(KeyMaterial(client_private, client_public, server_private, server_public))

def _manifest_rows(value):
    return {row["path"]: row for row in value["entries"]}

def _expected_children(graph, directory):
    prefix = "" if directory == "." else directory + "/"
    names = {
        item.path[len(prefix):].encode("utf-8") for item in graph
        if item.path != directory and item.path.startswith(prefix) and "/" not in item.path[len(prefix):]
    }
    if directory == ".":
        names.add(MANIFEST_NAME.raw)
    return tuple(sorted(names))

def _verify_graph(completion, grant, control):
    root_generation, _snapshot = _optional_child(completion, INPUT_NAME, control)
    _fail(root_generation is not None and grant.directory_key(".") == root_generation.key)
    root = fs._open_path_node(completion, INPUT_NAME, "directory", control)
    try:
        manifest_node = fs._open_path_node(root, MANIFEST_NAME, "file", control)
        try:
            _fail(grant.manifest_key() == manifest_node.generation.key)
            _fail(manifest_node.generation.mode == 0o400 and manifest_node.generation.nlink == 1)
            _fail(manifest_node.generation.uid == manifest_node.generation.gid == 0)
            _fail(manifest_node.generation.key.mount_id == root.generation.key.mount_id)
            _fail(manifest_node.generation.key.device == root.generation.key.device)
            raw = fs._read_regular(manifest_node, MAX_MANIFEST, control)
            fs._require_empty_fd_xattrs(manifest_node, control)
        except BaseException as error:
            _close_owned((manifest_node,), error)
        _close_owned((manifest_node,))
        value = _parse_manifest(raw, grant.token)
        _fail(_sha(raw) == grant.manifest_digest() and len(raw) == grant.manifest_size())
        material = _material_from_root(root, control)
        graph = _expected_graph(material)
        rows = _manifest_rows(value)
        _fail(tuple(rows) == tuple(item.path for item in graph))
        root_key = root.generation.key
        for entry in graph:
            row = rows[entry.path]
            _fail(row == _entry_row(entry, graph, _parse_key(row["identity"], entry.kind)))
            node, intermediates = _open_relative(root, entry.path, entry.kind, control)
            close = entry.path != "."
            try:
                generation = fs._observe_node(node.identity_fd, node.operation_fd, control)
                _fail(generation.key == _parse_key(row["identity"], entry.kind))
                _fail(generation.mode == entry.mode and generation.uid == generation.gid == 0)
                _fail(generation.nlink == row["nlink"] and generation.key.mount_id == root_key.mount_id)
                _fail(generation.key.device == root_key.device)
                fs._require_empty_fd_xattrs(node, control)
                if entry.kind == "directory":
                    _fail(fs._enumerate_stable(node, control).raw_names == _expected_children(graph, entry.path))
                else:
                    observed = fs._read_regular(node, len(entry.content), control)
                    _fail(observed == entry.content and _sha(observed) == row["sha256"])
            except BaseException as error:
                _close_owned(((node,) if close else ()) + intermediates, error)
            if close:
                _close_owned((node,) + intermediates)
        source = os.readlink(f"/proc/self/fd/{root.operation_fd.number}")
        _parse_mountinfo(_read_mountinfo(control), source)
        return InputIdentity(grant.token, _sha(raw), len(raw), len(graph))
    except BaseException as error:
        _close_owned((root,), error)
    finally:
        if root.identity_fd.disposition == "open":
            _close_owned((root,))

def _owner_routes():
    seal = object()
    permits = {}
    keys = {}
    detaches = {}

    class _OperationGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(False)
        @property
        def token(self):
            return permits[self]["token"]
        def directory_key(self, path):
            state = permits.get(self)
            _fail(state is not None and state["status"] in {"creating", "complete"})
            record = state["directories"].get(path)
            _fail(record is not None and record["key"] is not None)
            return record["key"]
        def manifest_key(self):
            state = permits.get(self)
            record = None if state is None else state["manifest"]
            _fail(state["status"] in {"creating", "complete"} and
                  record is not None and record["settled"] is not None)
            return record["settled"]
        def manifest_digest(self):
            return permits[self]["manifest"]["digest"]
        def manifest_size(self):
            return permits[self]["manifest"]["size"]

    _TestOperationGrant = owner_helpers.sealed_type(
        "_TestOperationGrant", seal, InputError, bases=(_OperationGrant,))
    _TestKeyGrant = owner_helpers.sealed_type("_TestKeyGrant", seal, InputError)
    _TestDetachGrant = owner_helpers.sealed_type("_TestDetachGrant", seal, InputError)
    _ProductionOperationGrant = owner_helpers.sealed_type(
        "_ProductionOperationGrant", seal, InputError, bases=(_OperationGrant,))
    _ProductionKeyGrant = owner_helpers.sealed_type("_ProductionKeyGrant", seal, InputError)
    _ProductionDetachGrant = owner_helpers.sealed_type(
        "_ProductionDetachGrant", seal, InputError)

    operation_types = (_TestOperationGrant, _ProductionOperationGrant)
    key_types = (_TestKeyGrant, _ProductionKeyGrant)
    detach_types = (_TestDetachGrant, _ProductionDetachGrant)

    def names_digest(raw_names):
        return _sha(operation._canonical([os.fsdecode(name) for name in raw_names]))

    def create_grant(journal, token, path, name, parent, kind, mode, command_serial, control):
        _fail(parent.generation.mode == 0o700 and parent.generation.uid == parent.generation.gid == 0)
        mount_id, _parent_birth, parent_version = _birth_authority(parent.operation_fd.number, control)
        lower = time.time_ns() - 2_000_000_000; grant_id = _sha(operation._canonical({
            "operation_token": token, "path": path, "name": name.text,
            "command_serial": command_serial}))
        body = {"action": "intent", "grant_id": grant_id, "path": path, "name": name.text,
                "parent_generation": operation._generation_value(parent.generation),
                "parent_inode_version": parent_version, "expected_kind": kind,
                "expected_mode": mode, "expected_uid": 0, "expected_gid": 0,
                "command_serial": command_serial, "birth_min_ns": lower,
                "birth_max_ns": lower + GRANT_BIRTH_WINDOW_NS, "mount_id": mount_id,
                "inode_version_min": 0, "inode_version_max": 0xffffffff,
                "child_generation": None, "child_birth_ns": None, "child_inode_version": None}
        operation._record_input_grant(journal, body)
        return body

    def settle_grant(journal, grant, node, control):
        mount_id, birth_ns, inode_version = _birth_authority(node.operation_fd.number, control)
        _fail(mount_id == grant["mount_id"] and grant["birth_min_ns"] <= birth_ns <= grant["birth_max_ns"]
              and node.generation.key.kind == grant["expected_kind"]
              and node.generation.mode == grant["expected_mode"]
              and node.generation.uid == grant["expected_uid"]
              and node.generation.gid == grant["expected_gid"])
        operation._record_input_grant(journal, {**{name: grant[name] for name in grant
            if name not in {"action", "child_generation", "child_birth_ns", "child_inode_version"}},
            "action": "settled", "child_generation": operation._generation_value(node.generation),
            "child_birth_ns": birth_ns, "child_inode_version": inode_version})

    def durable_wa(grant, action, path, parent_key, raw_names, child_key,
                   before_mode, target_mode):
        journal = permits[grant].get("journal")
        if journal is not None:
            operation._record_input_wa(journal, {
                "action": action, "path": path, "parent_key": _key_value(parent_key),
                "names_sha256": names_digest(raw_names),
                "child_key": None if child_key is None else _key_value(child_key),
                "before_mode": before_mode, "target_mode": target_mode})

    def durable_step(grant, action, path, kind, key, digest):
        state = permits[grant]
        journal = state.get("journal")
        if journal is not None:
            operation._record_input_step(
                journal, action, path, kind, None if key is None else _key_value(key), digest)

    def direct_recorded_names(state, parent_path, exclude=None):
        names = set()
        required = set()
        for path, record in state["directories"].items():
            if path == ".":
                continue
            parent_path_of_entry, _slash, leaf = path.rpartition("/")
            parent_path_of_entry = parent_path_of_entry or "."
            if parent_path_of_entry == parent_path and path != exclude:
                names.add(leaf.encode())
                if record["key"] is not None:
                    required.add(leaf.encode())
        for path, record in state["files"].items():
            parent_path_of_entry, _slash, leaf = path.rpartition("/")
            parent_path_of_entry = parent_path_of_entry or "."
            if parent_path_of_entry == parent_path and path != exclude:
                names.add(leaf.encode())
                if record["settled"] is not None:
                    required.add(leaf.encode())
        manifest = state["manifest"]
        if parent_path == "." and manifest is not None and exclude != "@manifest":
            names.add(MANIFEST_NAME.raw)
            if manifest["settled"] is not None:
                required.add(MANIFEST_NAME.raw)
        return names, required

    def require_creation_snapshot(state, parent_path, snapshot, exclude=None):
        if parent_path == "@completion":
            return
        names, required = direct_recorded_names(state, parent_path, exclude)
        observed = set(snapshot.raw_names)
        if exclude is not None:
            target = MANIFEST_NAME.raw if exclude == "@manifest" else (
                INPUT_NAME.raw if exclude == "." else exclude.rpartition("/")[2].encode("utf-8"))
            observed.discard(target)
        _fail(required <= observed and observed <= names)

    def verify_published(parent, name, expected_key, raw, mode, control):
        node = fs._open_path_node(parent, name, "file", control)
        try:
            generation = fs._observe_node(node.identity_fd, node.operation_fd, control)
            _fail(generation.key == expected_key and generation.mode == mode and generation.nlink == 1)
            _fail(generation.uid == generation.gid == 0)
            _fail(generation.key.mount_id == parent.generation.key.mount_id)
            _fail(generation.key.device == parent.generation.key.device)
            fs._require_empty_fd_xattrs(node, control)
            _fail(fs._read_regular(node, len(raw), control) == raw)
        except BaseException as error:
            _close_owned((node,), error)
        _close_owned((node,))
        return generation

    def publish(parent, parent_path, name, raw, mode, operation_grant, path, control, manifest=False):
        state = permits[operation_grant]
        record = state["manifest"] if manifest else state["files"].get(path)
        existing, snapshot = _optional_child(parent, name, control)
        require_creation_snapshot(state, parent_path, snapshot, "@manifest" if manifest else path)
        if existing is not None:
            _fail(record is not None)
            matching = [attempt for attempt in record["attempts"] if attempt[0] == existing.key]
            _fail(len(matching) == 1 and record["attempts"][-1] is matching[0])
            os.fsync(parent.operation_fd.number)
            _checkpoint(control, "after-file-parent-fsync:" + path)
            linked = verify_published(parent, name, existing.key, raw, mode, control)
            matching[0][1] = "settled"
            record["settled"] = linked.key
            if manifest:
                record["digest"], record["size"] = _sha(raw), len(raw)
            durable_step(operation_grant, "create", "@manifest" if manifest else path,
                         "file", linked.key, _sha(raw))
            return linked.key
        if record is None:
            record = {"parent": parent.generation.key, "attempts": [], "settled": None}
            if manifest:
                state["manifest"] = record
            else:
                state["files"][path] = record
        _fail(record["parent"] == parent.generation.key and record["settled"] is None)
        if record["attempts"] and record["attempts"][-1][1] == "intent":
            os.fsync(parent.operation_fd.number)
            _checkpoint(control, "after-file-absence-fsync:" + path)
            record["attempts"][-1][1] = "absent"
        descriptor = identity = generation = None
        try:
            descriptor, identity, generation = _anonymous_file(parent, raw, mode, control)
            _checkpoint(control, "after-anonymous-identity:" + path)
            record["attempts"].append([generation.key, "intent"])
            durable_step(operation_grant, "create-intent", "@manifest" if manifest else path,
                         "file", generation.key, _sha(raw))
            _checkpoint(control, "after-file-intent:" + path)
            _link_tmp(descriptor, parent, name)
            _checkpoint(control, "after-link:" + path)
            os.fsync(parent.operation_fd.number)
            _checkpoint(control, "after-file-parent-fsync:" + path)
            linked = verify_published(parent, name, generation.key, raw, mode, control)
            record["attempts"][-1][1] = "settled"
            record["settled"] = linked.key
            if manifest:
                record["digest"], record["size"] = _sha(raw), len(raw)
            durable_step(operation_grant, "create", "@manifest" if manifest else path,
                         "file", linked.key, _sha(raw))
        except BaseException as error:
            owner = None if identity is None else fs.HeldNode(identity, descriptor, generation)
            _close_owned((owner, descriptor if identity is None else None), error)
        _close_owned((fs.HeldNode(identity, descriptor, generation),))
        return linked.key

    def create_owned(completion, operation_grant, key_grant, control):
        state = permits.get(operation_grant)
        key_state = keys.get(key_grant)
        _fail(type(operation_grant) in operation_types and state is not None)
        _fail(type(key_grant) in key_types and key_state is not None)
        _fail(state["key_grant"] is key_grant and key_state["operation"] is operation_grant)
        _fail(state["status"] in {"unstarted", "creating", "complete"})
        if state["status"] == "complete":
            return _verify_graph(completion, operation_grant, control)
        state["status"] = "creating"
        graph = _expected_graph(key_state["material"])
        directories = sorted((item for item in graph if item.kind == "directory"),
                             key=lambda item: (item.path.count("/"), item.path.encode()))
        root = None
        try:
            for entry in directories:
                if entry.path == ".":
                    parent, parent_path, name, intermediates = completion, "@completion", INPUT_NAME, ()
                else:
                    parent, name, intermediates = _open_parent(root, entry.path, control)
                    parent_path = entry.path.rpartition("/")[0] or "."
                owned_parent = () if parent in {completion, root} else (parent,) + intermediates
                try:
                    existing, snapshot = _optional_child(parent, name, control)
                    record = state["directories"].get(entry.path)
                    require_creation_snapshot(state, parent_path, snapshot, entry.path)
                    if record is None:
                        _fail(existing is None and len(state["directories"]) == directories.index(entry))
                        record = {"parent": parent.generation.key, "before": snapshot.raw_names, "key": None}
                        state["directories"][entry.path] = record
                        _checkpoint(control, "after-directory-intent:" + entry.path)
                    _fail(record["parent"] == parent.generation.key)
                    if existing is None:
                        _fail(record["key"] is None and snapshot.raw_names == record["before"])
                        durable_wa(operation_grant, "mkdir", entry.path, parent.generation.key,
                                   snapshot.raw_names, None, None, 0o700)
                        journal = state.get("journal")
                        create_name, create_authority = name, None
                        if journal is not None:
                            suffix = _sha(entry.path.encode("utf-8"))[:16]
                            create_name = fs._name(".cogs-grant-" + state["token"][:32] + "-" + suffix)
                            serial = operation._command_context(journal).command_serial
                            create_authority = create_grant(journal, state["token"], entry.path,
                                                            create_name, parent, "directory", 0o700,
                                                            serial, control)
                        previous = os.umask(0o077)
                        try:
                            os.mkdir(create_name.raw, 0o700, dir_fd=parent.operation_fd.number)
                        finally:
                            _fail(os.umask(previous) == 0o077)
                        _checkpoint(control, "after-mkdir:" + entry.path)
                        os.fsync(parent.operation_fd.number)
                        _checkpoint(control, "after-directory-parent-fsync:" + entry.path)
                        if create_authority is not None:
                            created = fs._open_path_node(parent, create_name, "directory", control)
                            try: settle_grant(journal, create_authority, created, control)
                            finally: _close_owned((created,))
                            _rename_noreplace(parent.operation_fd.number, create_name, name, control)
                            os.fsync(parent.operation_fd.number)
                        existing = fs._observe_child(parent, name, control)
                        durable_wa(operation_grant, "mkdir-settled", entry.path,
                                   parent.generation.key, snapshot.raw_names,
                                   existing.key, None, 0o700)
                    else:
                        # Intent plus an existing name is never an identity grant.
                        _fail(record["key"] is not None and record["key"] == existing.key)
                    expected_mode = entry.mode if entry.path in state["metadata"] else 0o700
                    _fail(existing.key.kind == "directory" and existing.mode == expected_mode)
                    _fail(existing.uid == existing.gid == 0 and existing.key.mount_id == parent.generation.key.mount_id)
                    _fail(existing.key.device == parent.generation.key.device)
                    durable_step(operation_grant, "create-intent", entry.path, "directory",
                                 existing.key, None)
                    record["key"] = existing.key
                    durable_step(operation_grant, "create", entry.path, "directory",
                                 existing.key, None)
                    _checkpoint(control, "after-directory-settle:" + entry.path)
                    if entry.path == ".":
                        root = fs._open_path_node(completion, INPUT_NAME, "directory", control)
                except BaseException as error:
                    _close_owned(owned_parent, error)
                _close_owned(owned_parent)
            for entry in (item for item in graph if item.kind == "file"):
                parent, name, intermediates = _open_parent(root, entry.path, control)
                parent_path = entry.path.rpartition("/")[0] or "."
                owned_parent = () if parent is root else (parent,) + intermediates
                try:
                    publish(parent, parent_path, name, entry.content, entry.mode,
                            operation_grant, entry.path, control)
                except BaseException as error:
                    _close_owned(owned_parent, error)
                _close_owned(owned_parent)
            identities = {}
            for entry in graph:
                node, intermediates = _open_relative(root, entry.path, entry.kind, control)
                owned = () if entry.path == "." else (node,) + intermediates
                try:
                    if entry.kind == "directory":
                        state["metadata"].setdefault(entry.path, False)
                        mutate = node.generation.mode != entry.mode or state.get("journal") is None
                        if mutate:
                            if state.get("journal") is not None:
                                durable_wa(operation_grant, "metadata", entry.path,
                                           node.generation.key, (), node.generation.key,
                                           node.generation.mode, entry.mode)
                            os.fchmod(node.operation_fd.number, entry.mode)
                            _checkpoint(control, "after-directory-chmod:" + entry.path)
                            os.fsync(node.operation_fd.number)
                            _checkpoint(control, "after-directory-fsync:" + entry.path)
                    observed = fs._observe_node(node.identity_fd, node.operation_fd, control)
                    _fail(observed.key == state["directories"].get(entry.path, {}).get("key", observed.key))
                    _fail(observed.mode == entry.mode and observed.uid == observed.gid == 0)
                    identities[entry.path] = observed.key
                    if entry.kind == "directory":
                        state["metadata"][entry.path] = True
                        _checkpoint(control, "after-directory-reobserve:" + entry.path)
                except BaseException as error:
                    _close_owned(owned, error)
                _close_owned(owned)
            raw = _manifest_bytes(operation_grant.token, graph, identities)
            publish(root, ".", MANIFEST_NAME, raw, 0o400, operation_grant,
                    "@manifest", control, True)
            identity = _verify_graph(completion, operation_grant, control)
            state["status"] = "complete"
        except BaseException as error:
            _close_owned((root,), error)
        _close_owned((root,))
        return identity

    def verify_owned(completion, operation_grant, control):
        state = permits.get(operation_grant)
        _fail(type(operation_grant) in operation_types and state is not None and state["status"] == "complete")
        return _verify_graph(completion, operation_grant, control)

    def removal_order(graph, rows):
        paths = tuple(row["path"] for row in rows.values())
        _fail(set(paths) == {entry.path for entry in graph})
        ordered = sorted((entry for entry in graph if entry.path != "."),
                         key=lambda entry: (entry.path.count("/"), entry.path.encode()), reverse=True)
        return tuple((entry.path, entry.kind, _parse_key(rows[entry.path]["identity"], entry.kind))
                     for entry in ordered) + (("@manifest", "file", None), (".", "directory", rows["."]["identity"]))

    def open_removal_parent(root, path, control):
        if path == "@manifest":
            return root, MANIFEST_NAME, ()
        return _open_parent(root, path, control)

    def verify_removal_state(root, detach, control, active_absent=False):
        order, cursor = detach["order"], detach["cursor"]
        live = {path for path, _kind, _key in order[cursor:]}
        if detach["active"] == cursor and active_absent:
            live.remove(order[cursor][0])
        graph_by_path = {entry.path: entry for entry in detach["graph"]}
        for path, kind, key in order[cursor:]:
            if path == "." or path not in live:
                continue
            actual_path = MANIFEST_NAME.text if path == "@manifest" else path
            node, intermediates = _open_relative(root, actual_path, kind, control)
            try:
                expected_key = detach["manifest_key"] if path == "@manifest" else key
                generation = fs._observe_node(node.identity_fd, node.operation_fd, control)
                expected_mode = 0o400 if path == "@manifest" else graph_by_path[path].mode
                _fail(generation.key == expected_key and generation.uid == generation.gid == 0)
                _fail(generation.mode == expected_mode and generation.key.mount_id == root.generation.key.mount_id)
                _fail(generation.key.device == root.generation.key.device)
                fs._require_empty_fd_xattrs(node, control)
                if kind == "file":
                    raw = detach["manifest_raw"] if path == "@manifest" else graph_by_path[path].content
                    _fail(generation.nlink == 1 and fs._read_regular(node, len(raw), control) == raw)
                else:
                    prefix = "" if path == "." else path + "/"
                    expected = set()
                    child_directories = 0
                    kinds = {candidate: candidate_kind for candidate, candidate_kind, _key in order}
                    for candidate in live:
                        if candidate in {".", "@manifest"}:
                            continue
                        if candidate.startswith(prefix) and "/" not in candidate[len(prefix):]:
                            expected.add(candidate[len(prefix):].encode())
                            child_directories += kinds[candidate] == "directory"
                    if path == "." and "@manifest" in live:
                        expected.add(MANIFEST_NAME.raw)
                    _fail(generation.nlink == 2 + child_directories)
                    _fail(set(fs._enumerate_stable(node, control).raw_names) == expected)
            except BaseException as error:
                _close_owned((node,) + intermediates, error)
            _close_owned((node,) + intermediates)

    def settle_active_absence(completion, root, detach, control):
        index = detach["cursor"]
        path, _kind, _key = detach["order"][index]
        if path == ".":
            os.fsync(completion.operation_fd.number)
            _checkpoint(control, "after-remove-parent-fsync:.")
            _fail(INPUT_NAME.raw not in fs._enumerate_stable(completion, control).raw_names)
        else:
            parent, name, intermediates = open_removal_parent(root, path, control)
            owned = () if parent is root else (parent,) + intermediates
            try:
                os.fsync(parent.operation_fd.number)
                _checkpoint(control, "after-remove-parent-fsync:" + path)
                _fail(name.raw not in fs._enumerate_stable(parent, control).raw_names)
            except BaseException as error:
                _close_owned(owned, error)
            _close_owned(owned)
        detach["cursor"] += 1
        detach["active"] = None
        if detach["cursor"] == len(detach["order"]):
            detach["status"] = "removed"
        _checkpoint(control, "after-remove-absence-settle:" + path)

    def remove_owned(completion, operation_grant, detach_grant, control):
        state = permits.get(operation_grant)
        detach = detaches.get(detach_grant)
        _fail(type(operation_grant) in operation_types and state is not None and state["status"] == "complete")
        _fail(type(detach_grant) in detach_types and detach is not None)
        _fail(detach["operation"] is operation_grant and detach["status"] in {"detached", "removing", "removed"})
        if detach["status"] == "removed":
            existing, _snapshot = _optional_child(completion, INPUT_NAME, control)
            _fail(existing is None)
            return detach["identity"]
        root = None
        try:
            existing, _snapshot = _optional_child(completion, INPUT_NAME, control)
            if existing is None:
                _fail(detach["status"] == "removing" and detach["active"] == detach["cursor"])
                _fail(detach["order"][detach["cursor"]][0] == ".")
                settle_active_absence(completion, None, detach, control)
                return detach["identity"]
            root = fs._open_path_node(completion, INPUT_NAME, "directory", control)
            if detach["status"] == "detached":
                identity = _verify_graph(completion, operation_grant, control)
                material = _material_from_root(root, control)
                graph = _expected_graph(material)
                manifest_node = fs._open_path_node(root, MANIFEST_NAME, "file", control)
                try:
                    _fail(manifest_node.generation.key == operation_grant.manifest_key())
                    manifest_raw = fs._read_regular(manifest_node, MAX_MANIFEST, control)
                except BaseException as error:
                    _close_owned((manifest_node,), error)
                _close_owned((manifest_node,))
                rows = _manifest_rows(_parse_manifest(manifest_raw, operation_grant.token))
                _checkpoint(control, "after-remove-manifest-preflight")
                detach.update({"status": "removing", "identity": identity, "graph": graph,
                               "manifest_raw": manifest_raw, "manifest_key": operation_grant.manifest_key(),
                               "order": removal_order(graph, rows), "cursor": 0, "active": None})
            else:
                _fail(root.generation.key == _parse_key(_manifest_rows(
                    _parse_manifest(detach["manifest_raw"], operation_grant.token))["."]["identity"], "directory"))
                active_absent = False
                if detach["active"] == detach["cursor"]:
                    path = detach["order"][detach["cursor"]][0]
                    if path == ".":
                        expected = _parse_key(detach["order"][detach["cursor"]][2], "directory")
                        _fail(root.generation.key == expected)
                    else:
                        parent, name, intermediates = open_removal_parent(root, path, control)
                        owned = () if parent is root else (parent,) + intermediates
                        try:
                            generation, _snapshot = _optional_child(parent, name, control)
                            active_absent = generation is None
                            if generation is not None:
                                expected = (detach["manifest_key"] if path == "@manifest"
                                            else detach["order"][detach["cursor"]][2])
                                _fail(generation.key == expected)
                        except BaseException as error:
                            _close_owned(owned, error)
                        _close_owned(owned)
                verify_removal_state(root, detach, control, active_absent)
                if active_absent:
                    settle_active_absence(completion, root, detach, control)
            while detach["cursor"] < len(detach["order"]):
                index = detach["cursor"]
                path, kind, key = detach["order"][index]
                if detach["active"] is None:
                    detach["active"] = index
                    _checkpoint(control, "after-remove-intent:" + path)
                else:
                    _fail(detach["active"] == index)
                durable_step(operation_grant, "remove-intent", path, kind,
                             (_parse_key(key, kind) if path == "." else
                              detach["manifest_key"] if path == "@manifest" else key),
                             None if kind == "directory" else (
                                 _sha(detach["manifest_raw"]) if path == "@manifest" else
                                 _sha({entry.path: entry for entry in detach["graph"]}[path].content)))
                if path == ".":
                    _fail(root.generation.key == _parse_key(key, "directory"))
                    _close_owned((root,))
                    root = None
                    os.rmdir(INPUT_NAME.raw, dir_fd=completion.operation_fd.number)
                    _checkpoint(control, "after-rmdir:.")
                    settle_active_absence(completion, None, detach, control)
                    durable_step(operation_grant, "absent", path, kind, None, None)
                    break
                parent, name, intermediates = open_removal_parent(root, path, control)
                owned = () if parent is root else (parent,) + intermediates
                try:
                    node = fs._open_path_node(parent, name, kind, control)
                    try:
                        expected = detach["manifest_key"] if path == "@manifest" else key
                        _fail(node.generation.key == expected)
                    except BaseException as error:
                        _close_owned((node,), error)
                    _close_owned((node,))
                    if kind == "file":
                        os.unlink(name.raw, dir_fd=parent.operation_fd.number)
                        _checkpoint(control, "after-unlink:" + path)
                    else:
                        os.rmdir(name.raw, dir_fd=parent.operation_fd.number)
                        _checkpoint(control, "after-rmdir:" + path)
                    os.fsync(parent.operation_fd.number)
                    _checkpoint(control, "after-remove-parent-fsync:" + path)
                    _fail(name.raw not in fs._enumerate_stable(parent, control).raw_names)
                    detach["cursor"] += 1
                    detach["active"] = None
                    durable_step(operation_grant, "absent", path, kind, None,
                                 None if kind == "directory" else (
                                     _sha(detach["manifest_raw"]) if path == "@manifest" else
                                     _sha({entry.path: entry for entry in detach["graph"]}[path].content)))
                    _checkpoint(control, "after-remove-absence-settle:" + path)
                except BaseException as error:
                    _close_owned(owned, error)
                _close_owned(owned)
            _fail(detach["status"] == "removed")
            return detach["identity"]
        except BaseException as error:
            _close_owned((root,), error)
        finally:
            if root is not None and root.identity_fd.disposition == "open":
                _close_owned((root,))

    def make_test_operation_grant(token):
        _fail(os.environ.get("COGS_KATA_INPUTS_TESTING_V1") == "1" and sys.platform == "linux")
        _fail(type(token) is str and len(token) == 64 and set(token) <= HEX and token != "0" * 64)
        value = _TestOperationGrant(seal)
        permits[value] = {"token": token, "status": "unstarted", "key_grant": None,
                          "directories": {}, "files": {}, "metadata": {}, "manifest": None,
                          "uncertain": None}
        return value

    def make_test_key_grant(material):
        _fail(os.environ.get("COGS_KATA_INPUTS_TESTING_V1") == "1")
        validated = _validate_key_material(material)
        fields = (validated.client_private, validated.client_public,
                  validated.server_private, validated.server_public)
        _fail(tuple(_sha(raw) for raw in fields) == TEST_RFC8032_SHA256)
        value = _TestKeyGrant(seal)
        keys[value] = {"material": validated, "operation": None}
        return value

    def bind_test_operation_grant(grant, key_grant):
        state, key_state = permits.get(grant), keys.get(key_grant)
        _fail(state is not None and key_state is not None and state["status"] == "unstarted")
        _fail(state["key_grant"] is None and key_state["operation"] is None)
        state["key_grant"], key_state["operation"] = key_grant, grant
        return grant

    def make_test_detach_grant(operation_grant):
        _fail(os.environ.get("COGS_KATA_INPUTS_TESTING_V1") == "1")
        state = permits.get(operation_grant)
        _fail(state is not None and state["status"] == "complete" and state["uncertain"] is None)
        _fail(not any(item["operation"] is operation_grant for item in detaches.values()))
        value = _TestDetachGrant(seal)
        detaches[value] = {"operation": operation_grant, "status": "detached", "uncertain": None}
        return value

    def latch_route(operation_grant, detach_grant, route):
        state, detach = permits.get(operation_grant), detaches.get(detach_grant)
        _fail(state is not None)
        if state["uncertain"] is not None:
            raise state["uncertain"]
        if detach is not None and detach["uncertain"] is not None:
            raise detach["uncertain"]
        try:
            return route()
        except BaseException as error:
            if type(error) is CloseUncertainError:
                uncertain = error
            else:
                primary, failures = error, []
                while type(primary) is fs.RootfsFsError and primary.close_error is not None:
                    failures.insert(0, primary.close_error)
                    primary = primary.primary
                if not failures:
                    raise
                uncertain = CloseUncertainError(primary, failures)
            state["uncertain"] = uncertain
            if detach is not None:
                detach["uncertain"] = uncertain
            if uncertain is error:
                raise
            raise uncertain from error

    production = {}

    def fixed_key_material(state, first_serial):
        import completion_kata_process as process
        _fail(type(state["key_executable"]) is process.RetainedExecutable)
        _fail((state["key_executable"].role, state["key_executable"].path)
              == ("ssh-keygen", "/usr/bin/ssh-keygen"))
        completion, control = state["completion"], state["control"]
        stage_name = state["key_stage_name"]
        existing, snapshot = _optional_child(completion, stage_name, control)
        _fail(existing is None and command_policy.KEY_STAGE_PREFIX == operation.BASE + "/" + KEY_STAGE_PREFIX)
        stage_grant = create_grant(
            state["journal"], state["journal"].command_context().operation_token,
            "@key-stage", stage_name, completion, "directory", 0o700, first_serial, control)
        state["journal"].record_input_wa({
            "action": "mkdir", "path": "@key-stage",
            "parent_key": _key_value(completion.generation.key),
            "names_sha256": names_digest(snapshot.raw_names), "child_key": None,
            "before_mode": None, "target_mode": 0o700})
        previous = os.umask(0o077)
        try:
            os.mkdir(stage_name.raw, 0o700, dir_fd=completion.operation_fd.number)
        finally:
            _fail(os.umask(previous) == 0o077)
        os.fsync(completion.operation_fd.number)
        stage = fs._open_path_node(completion, stage_name, "directory", control)
        held = [stage]
        try:
            _fail(stage.generation.mode == 0o700 and stage.generation.uid == stage.generation.gid == 0)
            settle_grant(state["journal"], stage_grant, stage, control)
            state["journal"].record_input_wa({
                "action": "mkdir-settled", "path": "@key-stage",
                "parent_key": _key_value(completion.generation.key),
                "names_sha256": names_digest(snapshot.raw_names),
                "child_key": _key_value(stage.generation.key), "before_mode": None,
                "target_mode": 0o700})
            def run(command_id, serial, expected_stdout=None):
                outcome, receipt = process._transact_key(
                    state["journal"], state["key_executable"], command_id)
                _fail(type(outcome) is process.ProcessOutcome
                      and type(receipt) is operation.DurableCommandOutcome)
                _fail(receipt.command_serial == serial and outcome.command_id == receipt.command_id)
                if expected_stdout is not None: _fail(outcome.stdout == expected_stdout)
                durable = operation._durable_command_output(
                    state["journal"], serial, receipt.command_id, receipt.binding_sha256,
                    outcome.stdout, outcome.stderr)
                body = durable.body
                _fail(durable.body == receipt.body and outcome.stderr == b"")
                _fail(body["outcome"] == "exited" and body["status"] == 0
                      and not body["uncertain"] and not body["stdout_truncated"]
                      and not body["stderr_truncated"] and body["errors"] == [])
                return outcome
            def key_grant(name, mode, serial):
                return create_grant(state["journal"],
                                    state["journal"].command_context().operation_token,
                                    "@key-stage/" + name, fs._name(name), stage, "file", mode,
                                    serial, control)
            def opened(name, mode, maximum, grant):
                node = fs._open_path_node(stage, fs._name(name), "file", control); held.append(node)
                _fail(node.generation.mode == mode and node.generation.uid == node.generation.gid == 0
                      and node.generation.nlink == 1)
                fs._require_empty_fd_xattrs(node, control)
                settle_grant(state["journal"], grant, node, control)
                state["journal"].record_input_wa({
                    "action": "file-settled", "path": "@key-stage/" + name,
                    "parent_key": _key_value(stage.generation.key),
                    "names_sha256": names_digest(fs._enumerate_stable(stage, control).raw_names),
                    "child_key": _key_value(node.generation.key), "before_mode": None,
                    "target_mode": mode})
                return node, fs._read_regular(node, maximum, control)
            client_grant = key_grant("client", 0o600, first_serial)
            client_pub_grant = key_grant("client.pub", 0o644, first_serial)
            run(process.CommandId.SSH_KEYGEN_CLIENT, first_serial, b"")
            client_node, client_private = opened("client", 0o600, MAX_PRIVATE, client_grant)
            client_pub_node, client_public = opened("client.pub", 0o644, MAX_PUBLIC, client_pub_grant)
            client_y = client_public.rsplit(b" ", 1)[0] + b"\n"
            run(process.CommandId.SSH_PUBLIC_CLIENT, first_serial + 1, client_y)
            _fail(fs._observe_node(client_node.identity_fd, client_node.operation_fd, control)
                  == client_node.generation)
            server_grant = key_grant("server", 0o600, first_serial + 2)
            server_pub_grant = key_grant("server.pub", 0o644, first_serial + 2)
            run(process.CommandId.SSH_KEYGEN_SERVER, first_serial + 2, b"")
            server_node, server_private = opened("server", 0o600, MAX_PRIVATE, server_grant)
            server_pub_node, server_public = opened("server.pub", 0o644, MAX_PUBLIC, server_pub_grant)
            server_y = server_public.rsplit(b" ", 1)[0] + b"\n"
            run(process.CommandId.SSH_PUBLIC_SERVER, first_serial + 3, server_y)
            for node in (client_node, client_pub_node, server_node, server_pub_node):
                _fail(fs._observe_node(node.identity_fd, node.operation_fd, control) == node.generation)
            _fail(state["journal"].command_context().command_serial == first_serial + 4)
            return _validate_key_material(KeyMaterial(
                client_private, client_public, server_private, server_public)), tuple(held)
        except BaseException as error:
            _close_owned(tuple(reversed(held)), error)

    def remove_key_stage(state, handles=()):
        completion, control = state["completion"], state["control"]
        stage_name = state["key_stage_name"]
        quarantine_name = fs._name(stage_name.text + ".quarantine")
        wa_rows = state["journal"].input_wa()
        grant_rows = state["journal"].input_grants()
        mkdir_rows = [row for row in wa_rows if (row["action"], row["path"]) == ("mkdir", "@key-stage")]
        settled_rows = [row for row in wa_rows
                        if (row["action"], row["path"]) == ("mkdir-settled", "@key-stage")]
        if handles:
            _fail(len(mkdir_rows) == 1)
            _close_owned(tuple(reversed(handles[1:])))
            stage = handles[0]
        else:
            generation, completion_snapshot = _optional_child(completion, stage_name, control)
            quarantined, quarantine_snapshot = _optional_child(completion, quarantine_name, control)
            _fail(not (generation is not None and quarantined is not None))
            if generation is None and quarantined is None: return
            _fail(len(mkdir_rows) == 1 and len(settled_rows) <= 1
                  and _parse_key(mkdir_rows[0]["parent_key"], "directory") == completion.generation.key)
            active_name = stage_name if generation is not None else quarantine_name
            active_snapshot = completion_snapshot if generation is not None else quarantine_snapshot
            excluded = {active_name.raw}
            if state["journal"].durable_phase() == "FS_INTENT":
                excluded.add(INPUT_NAME.raw)
                excluded.update(row["name"].encode("ascii") for row in grant_rows
                                if row["path"] == "." and row["action"] == "intent")
            names_without_stage = tuple(name for name in active_snapshot.raw_names
                                        if name not in excluded)
            _fail(names_digest(names_without_stage) == mkdir_rows[0]["names_sha256"])
            stage = fs._open_path_node(completion, active_name, "directory", control)
            stage_name = active_name
        try:
            if not settled_rows:
                grants = [row for row in grant_rows if row["path"] == "@key-stage"]
                intents = [row for row in grants if row["action"] == "intent"]
                _fail(len(intents) == 1 and not any(row["action"] == "settled" for row in grants))
                settle_grant(state["journal"], intents[0], stage, control)
                state["journal"].record_input_wa({
                    "action": "mkdir-settled", "path": "@key-stage",
                    "parent_key": mkdir_rows[0]["parent_key"],
                    "names_sha256": mkdir_rows[0]["names_sha256"],
                    "child_key": _key_value(stage.generation.key), "before_mode": None,
                    "target_mode": 0o700})
                settled_rows = [{"child_key": _key_value(stage.generation.key)}]
            _fail(len(settled_rows) == 1
                  and stage.generation.key == _parse_key(settled_rows[0]["child_key"], "directory")
                  and stage.generation.mode == 0o700 and stage.generation.uid == stage.generation.gid == 0)
            prior_stage_remove = [row for row in wa_rows
                                  if (row["action"], row["path"]) == ("remove", "@key-stage")]
            if not prior_stage_remove:
                state["journal"].record_input_wa({
                    "action": "remove", "path": "@key-stage",
                    "parent_key": _key_value(completion.generation.key),
                    "names_sha256": mkdir_rows[0]["names_sha256"],
                    "child_key": _key_value(stage.generation.key),
                    "before_mode": stage.generation.mode, "target_mode": 0})
            if stage_name is not quarantine_name:
                _rename_noreplace(completion.operation_fd.number, stage_name, quarantine_name, control)
                os.fsync(completion.operation_fd.number); stage_name = quarantine_name
            snapshot = fs._enumerate_stable(stage, control)
            allowed = {row["name"].encode("ascii") for row in grant_rows
                       if row["action"] == "intent" and row["path"].startswith("@key-stage/")}
            _fail(set(snapshot.raw_names) <= allowed)
            for raw in sorted(snapshot.raw_names, reverse=True):
                generation = fs._observe_child(stage, fs._name(os.fsdecode(raw)), control)
                path = "@key-stage/" + os.fsdecode(raw)
                settlements = [row for row in wa_rows
                               if (row["action"], row["path"]) == ("file-settled", path)]
                grants = [row for row in grant_rows if row["path"] == path]
                intents = [row for row in grants if row["action"] == "intent"]
                settled_grants = [row for row in grants if row["action"] == "settled"]
                _fail(len(intents) == 1 and len(settled_grants) <= 1
                      and len(grants) == len(intents) + len(settled_grants)
                      and intents[0]["name"] == os.fsdecode(raw))
                if not settlements:
                    node = fs._open_path_node(stage, fs._name(os.fsdecode(raw)), "file", control)
                    try:
                        if settled_grants:
                            settled = settled_grants[0]
                            mount_id, birth_ns, inode_version = _birth_authority(
                                node.operation_fd.number, control)
                            parent_key = _key_value(stage.generation.key)
                            _fail(settled["grant_id"] == intents[0]["grant_id"]
                                  and all(settled[name] == intents[0][name] for name in (
                                      "name", "parent_generation", "parent_inode_version",
                                      "expected_kind", "expected_mode", "expected_uid", "expected_gid",
                                      "command_serial", "birth_min_ns", "birth_max_ns", "mount_id",
                                      "inode_version_min", "inode_version_max"))
                                  and all(intents[0]["parent_generation"][name] == parent_key[name]
                                          for name in ("mount_id", "device", "inode", "kind"))
                                  and settled["child_generation"] == operation._generation_value(node.generation)
                                  and settled["child_birth_ns"] == birth_ns
                                  and settled["child_inode_version"] == inode_version
                                  and mount_id == settled["mount_id"]
                                  and settled["expected_kind"] == "file"
                                  and node.generation.mode == settled["expected_mode"]
                                  and node.generation.uid == settled["expected_uid"] == 0
                                  and node.generation.gid == settled["expected_gid"] == 0)
                        else: settle_grant(state["journal"], intents[0], node, control)
                    finally: _close_owned((node,))
                    state["journal"].record_input_wa({
                        "action": "file-settled", "path": path,
                        "parent_key": _key_value(stage.generation.key),
                        "names_sha256": names_digest(snapshot.raw_names),
                        "child_key": _key_value(generation.key), "before_mode": None,
                        "target_mode": generation.mode})
                    settlements = [{"child_key": _key_value(generation.key),
                                    "target_mode": generation.mode}]
                _fail(len(settlements) == 1
                      and generation.key == _parse_key(settlements[0]["child_key"], "file")
                      and generation.uid == generation.gid == 0
                      and generation.mode == settlements[0]["target_mode"])
                prior = [row for row in wa_rows if (row["action"], row["path"]) == ("remove", path)]
                if prior:
                    _fail(len(prior) == 1 and _parse_key(prior[0]["child_key"], "file") == generation.key)
                else:
                    state["journal"].record_input_wa({
                        "action": "remove", "path": path, "parent_key": _key_value(stage.generation.key),
                        "names_sha256": names_digest(snapshot.raw_names),
                        "child_key": _key_value(generation.key), "before_mode": generation.mode,
                        "target_mode": 0})
                os.unlink(raw, dir_fd=stage.operation_fd.number); os.fsync(stage.operation_fd.number)
            removed_generation = stage.generation
            _close_owned((stage,)); stage = None
            os.rmdir(stage_name.raw, dir_fd=completion.operation_fd.number)
            os.fsync(completion.operation_fd.number)
            absent, _ = _optional_child(completion, stage_name, control)
            original, _ = _optional_child(completion, state["key_stage_name"], control)
            _fail(absent is None and original is None)
            state["journal"].record_input_wa({
                "action": "absent", "path": "@key-stage",
                "parent_key": _key_value(completion.generation.key),
                "names_sha256": names_digest(fs._enumerate_stable(completion, control).raw_names),
                "child_key": _key_value(removed_generation.key),
                "before_mode": removed_generation.mode, "target_mode": 0})
        finally:
            if stage is not None and stage.identity_fd.disposition == "open": _close_owned((stage,))

    def poison_production(state, primary):
        state["uncertain"] = primary
        if state["journal"].durable_phase() == "UNCERTAIN": return
        try:
            state["journal"].record_uncertain("incomplete")
        except BaseException as journal_error:
            raise BaseExceptionGroup(
                "input failure and durable uncertainty failure", [primary, journal_error],
            )

    class _ProductionInputs:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
        def create(self):
            state = production[self]
            _fail(not state["removed"] and state["uncertain"] is None)
            if state["identity"] is not None:
                return self.verify()
            before = state["journal"].command_context()
            _fail(before.lifecycle_phase == "ROOTFS_LEASED")
            key_handles = ()
            try:
                material, key_handles = fixed_key_material(state, before.command_serial)
                grant = _ProductionOperationGrant(seal)
                key_grant = _ProductionKeyGrant(seal)
                permits[grant] = {
                    "token": before.operation_token, "status": "unstarted",
                    "key_grant": key_grant, "directories": {}, "files": {},
                    "metadata": {}, "manifest": None, "uncertain": None,
                    "journal": state["journal"],
                }
                keys[key_grant] = {"material": material, "operation": grant}
                state["grant"], state["key_grant"] = grant, key_grant
                parent = state["completion"]
                parent_before = fs._observe_node(
                    parent.identity_fd, parent.operation_fd, state["control"],
                )
                names = [os.fsdecode(name) for name in
                         fs._enumerate_stable(parent, state["control"]).raw_names]
                _fail(INPUT_NAME.text not in names)
                names.sort(key=lambda value: value.encode("utf-8"))
                intent = {
                    "operation_token": before.operation_token,
                    "resource_id": "input-root", "action": "create",
                    "expected_parent_generation": operation._generation_value(parent_before),
                    "names_sha256": _sha(operation._canonical(names)),
                }
                state["journal"].record_fs_intent(intent)
                identity = create_owned(
                    parent, grant, key_grant, state["control"],
                )
                remove_key_stage(state, key_handles)
                import completion_kata_process as process
                process._release_attested_executable(state["key_executable"])
                state["key_released"] = True
                root = fs._open_path_node(parent, INPUT_NAME, "directory", state["control"])
                try:
                    parent_after = fs._observe_node(
                        parent.identity_fd, parent.operation_fd, state["control"],
                    )
                    observed = {**intent,
                        "before_parent": operation._generation_value(parent_before),
                        "after_parent": operation._generation_value(parent_after),
                        "before_child": None,
                        "after_child": operation._generation_value(root.generation),
                    }
                finally:
                    _close_owned((root,))
                state["journal"].record_fs_observed(observed)
                state["journal"].record_fs_settled(observed)
                state["identity"] = identity
                return identity
            except BaseException as error:
                cleanup_error = None
                try: remove_key_stage(state, key_handles)
                except BaseException as caught: cleanup_error = caught
                release_error = None
                if not state["key_released"]:
                    try:
                        import completion_kata_process as process
                        process._release_attested_executable(state["key_executable"])
                        state["key_released"] = True
                    except BaseException as caught: release_error = caught
                failures = [item for item in (error, cleanup_error, release_error) if item is not None]
                primary = error if len(failures) == 1 else BaseExceptionGroup(
                    "input creation/key-stage/attestation settlement failure", failures)
                poison_production(state, primary)
                raise primary
        def verify(self):
            state = production[self]
            _fail(state["identity"] is not None and not state["removed"]
                  and state["uncertain"] is None)
            context = state["journal"].command_context()
            _fail(context.operation_token == state["identity"].operation_token)
            try:
                return latch_route(state["grant"], None, lambda: verify_owned(
                    state["completion"], state["grant"], state["control"],
                ))
            except BaseException as error:
                poison_production(state, error)
                raise
        def prepare_launch(self):
            """Prove the complete manifest, including known_hosts, before launch."""
            return self.verify()
        def claim_ssh_bindings(self):
            state = production[self]
            identity = self.verify()
            _fail(state["handles"] is None and not state["bindings_claimed"])
            root = fs._open_path_node(
                state["completion"], INPUT_NAME, "directory", state["control"],
            )
            client = known = None
            client_intermediates = known_intermediates = ()
            try:
                client, client_intermediates = _open_relative(
                    root, CLIENT_KEY, "file", state["control"],
                )
                known, known_intermediates = _open_relative(
                    root, KNOWN_HOSTS, "file", state["control"],
                )
                binding = fdmap._bind_production_inputs(
                    client.operation_fd.number, known.operation_fd.number,
                    fdmap.identity(client.operation_fd.number),
                    fdmap.identity(known.operation_fd.number),
                    identity.operation_token, identity.manifest_sha256,
                )
                state["handles"] = ((known,) + known_intermediates
                                    + (client,) + client_intermediates + (root,))
                state["bindings_claimed"] = True
                return binding
            except BaseException as error:
                try:
                    _close_owned(((known,) + (known_intermediates if known is not None else ())
                                  + (client,) + (client_intermediates if client is not None else ())
                                  + (root,)), error)
                except BaseException as owned_error:
                    poison_production(state, owned_error)
                    raise
        def release_ssh_bindings(self):
            state = production[self]
            handles, state["handles"] = state["handles"], None
            _fail(handles is not None)
            try:
                _close_owned(handles)
            except BaseException as error:
                poison_production(state, error)
                raise
        def remove(self):
            state = production[self]
            identity = self.verify()
            _fail(state["handles"] is None)
            context = state["journal"].command_context()
            _fail(context.lifecycle_phase == "FIREWALL_ABSENT")
            detach = _ProductionDetachGrant(seal)
            detaches[detach] = {"operation": state["grant"], "status": "detached", "uncertain": None}
            try:
                removed = latch_route(state["grant"], detach, lambda: remove_owned(
                    state["completion"], state["grant"], detach, state["control"],
                ))
                names = fs._enumerate_stable(state["completion"], state["control"]).raw_names
                _fail(INPUT_NAME.raw not in names and removed == identity)
                proof = _sha(operation._canonical({
                    "manifest_sha256": identity.manifest_sha256,
                    "operation_token": identity.operation_token,
                    "observed_names": [os.fsdecode(name) for name in names],
                }))
                state["journal"].record_input_removed(proof)
                state["removed"] = True
                return removed
            except BaseException as error:
                poison_production(state, error)
                raise

    class _ProductionInputCleanup:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
        def continue_cleanup(self):
            state = production[self]
            try:
                return self._continue_cleanup()
            except BaseException as error:
                try:
                    if state["journal"].durable_phase() != "UNCERTAIN":
                        state["journal"].record_uncertain("identity-mismatch")
                except BaseException as settlement_error:
                    raise ExceptionGroup("cleanup failure and uncertainty settlement failure",
                                         (error, settlement_error))
                raise error
        def _continue_cleanup(self):
            state = production[self]
            if state["journal"].has_recovery_command():
                import completion_kata_process as process
                process._recover_pending_production(state["journal"])
            operation_token = state["journal"].input_cleanup_token()
            state["key_stage_name"] = fs._name(KEY_STAGE_PREFIX + operation_token)
            def mark_uncertain(reason):
                if state["journal"].durable_phase() != "UNCERTAIN":
                    state["journal"].record_uncertain(reason)
            try:
                remove_key_stage(state)
            except BaseException as error:
                mark_uncertain("identity-mismatch")
                raise error
            steps = state["journal"].input_steps()
            recorded_paths = {row["path"] for row in steps}
            wa_state = state["journal"].input_wa()
            grant_state = state["journal"].input_grants()
            mkdir_rows = sorted((row for row in wa_state
                                 if row["action"] == "mkdir" and row["path"] != "@key-stage"),
                                key=lambda row: (row["path"].count("/"), row["path"].encode()))
            for wa in mkdir_rows:
                path = wa["path"]
                if path in recorded_paths: continue
                if path == ".":
                    parent, name, intermediates = state["completion"], INPUT_NAME, ()
                else:
                    root_generation, _ = _optional_child(
                        state["completion"], INPUT_NAME, state["control"])
                    _fail(root_generation is not None)
                    root_probe = fs._open_path_node(
                        state["completion"], INPUT_NAME, "directory", state["control"])
                    try:
                        parent, name, intermediates = _open_parent(root_probe, path, state["control"])
                    finally:
                        if parent is not root_probe: _close_owned((root_probe,))
                owned = () if parent is state["completion"] else (parent,) + intermediates
                try:
                    _fail(parent.generation.key == _parse_key(wa["parent_key"], "directory"))
                    generation, _snapshot = _optional_child(parent, name, state["control"])
                    grants = [row for row in grant_state if row["path"] == path]
                    intents = [row for row in grants if row["action"] == "intent"]
                    temporary_generation = None
                    if intents:
                        _fail(len(intents) == 1)
                        temporary = fs._name(intents[0]["name"])
                        temporary_generation, _ = _optional_child(parent, temporary, state["control"])
                        if generation is not None and temporary_generation is not None:
                            mark_uncertain("identity-mismatch")
                            raise InputError("grant target and quarantine both exist")
                    if generation is None and intents:
                        if temporary_generation is not None:
                            node = fs._open_path_node(parent, temporary, "directory", state["control"])
                            try:
                                if not any(row["action"] == "settled" for row in grants):
                                    settle_grant(state["journal"], intents[0], node, state["control"])
                            finally: _close_owned((node,))
                            _rename_noreplace(parent.operation_fd.number, temporary, name, state["control"])
                            os.fsync(parent.operation_fd.number)
                            generation = fs._observe_child(parent, name, state["control"])
                    if generation is None: continue
                    settlements = [row for row in wa_state
                                   if (row["action"], row["path"]) == ("mkdir-settled", path)]
                    if not settlements and any(row["action"] == "settled" for row in grants):
                        state["journal"].record_input_wa({
                            "action": "mkdir-settled", "path": path,
                            "parent_key": wa["parent_key"], "names_sha256": wa["names_sha256"],
                            "child_key": _key_value(generation.key), "before_mode": None,
                            "target_mode": wa["target_mode"]})
                        settlements = [{"child_key": _key_value(generation.key)}]
                    if (len(settlements) != 1
                            or generation.key != _parse_key(settlements[0]["child_key"], "directory")
                            or generation.mode not in {0o700, wa["target_mode"]}
                            or generation.uid != 0 or generation.gid != 0):
                        mark_uncertain("identity-mismatch")
                        raise InputError("unsettled restart directory")
                    state["journal"].record_input_step("create-intent", path,
                                                 "directory", _key_value(generation.key), None)
                    state["journal"].record_input_step("create", path,
                                                 "directory", _key_value(generation.key), None)
                    recorded_paths.add(path)
                finally: _close_owned(owned)
            steps = state["journal"].input_steps()
            by_path = {}
            for row in steps: by_path.setdefault(row["path"], []).append(row)
            candidates = []
            for path, rows in by_path.items():
                if rows[-1]["action"] != "absent":
                    source = next((row for row in reversed(rows)
                                   if row["action"] in {"create", "create-intent"}), None)
                    _fail(source is not None); candidates.append(source)
            candidates.sort(key=lambda row: (row["path"] == ".", -row["path"].count("/"),
                                              row["path"].encode("utf-8")))
            root = None
            try:
                root_generation, _ = _optional_child(state["completion"], INPUT_NAME, state["control"])
                if root_generation is not None:
                    root = fs._open_path_node(state["completion"], INPUT_NAME, "directory", state["control"])
                else:
                    for source in candidates:
                        rows = by_path[source["path"]]
                        if rows[-1]["action"] != "remove-intent":
                            operation._record_input_step(
                                state["journal"], "remove-intent", source["path"], source["kind"],
                                source["key"], source["sha256"])
                        operation._record_input_step(
                            state["journal"], "absent", source["path"], source["kind"],
                            None, source["sha256"])
                    candidates = []
                for source in candidates:
                    path, kind = source["path"], source["kind"]
                    rows = by_path[path]
                    if rows[-1]["action"] != "remove-intent":
                        state["journal"].record_input_step("remove-intent", path, kind,
                                                     source["key"], source["sha256"])
                    if path == ".":
                        generation = root_generation
                        parent, name, intermediates = state["completion"], INPUT_NAME, ()
                    else:
                        _fail(root is not None)
                        actual = MANIFEST_NAME.text if path == "@manifest" else path
                        parent, name, intermediates = _open_parent(root, actual, state["control"])
                        generation, _ = _optional_child(parent, name, state["control"])
                    owned = () if parent in {state["completion"], root} else (parent,) + intermediates
                    try:
                        if generation is not None:
                            expected = _parse_key(source["key"], kind)
                            _fail(generation.key == expected)
                            node = fs._open_path_node(parent, name, kind, state["control"])
                            try:
                                _fail(node.generation.key == expected and node.generation.uid == node.generation.gid == 0)
                                if kind == "file":
                                    raw = fs._read_regular(node, MAX_MANIFEST, state["control"])
                                    _fail(_sha(raw) == source["sha256"])
                                else:
                                    _fail(not fs._enumerate_stable(node, state["control"]).raw_names)
                            finally: _close_owned((node,))
                            if path == ".":
                                _close_owned((root,)); root = None
                            (os.unlink if kind == "file" else os.rmdir)(
                                name.raw, dir_fd=parent.operation_fd.number)
                            os.fsync(parent.operation_fd.number)
                        absent, _ = _optional_child(parent, name, state["control"])
                        _fail(absent is None)
                        state["journal"].record_input_step("absent", path, kind,
                                                     None, source["sha256"])
                    finally: _close_owned(owned)
                final, _ = _optional_child(state["completion"], INPUT_NAME, state["control"])
                _fail(final is None)
                proof = _sha(operation._canonical({"operation_token": steps[0]["operation_token"],
                                                    "input_absent": True})) if steps else _sha(b"no-input-steps\n")
                phase = state["journal"].durable_phase()
                if phase == "FS_INTENT":
                    intent = state["journal"].pending_fs_intent()
                    observed_parent = fs._observe_node(
                        state["completion"].identity_fd, state["completion"].operation_fd,
                        state["control"])
                    names = sorted((os.fsdecode(raw) for raw in
                                    fs._enumerate_stable(state["completion"], state["control"]).raw_names),
                                   key=lambda value: value.encode("utf-8"))
                    parent_observation = operation._generation_value(observed_parent)
                    if parent_observation != intent["expected_parent_generation"]:
                        state["journal"].record_uncertain("identity-mismatch")
                    else:
                        absent = {**intent, "parent_observation": parent_observation,
                                  "observed_names": names}
                        try:
                            state["journal"].record_fs_absent(absent)
                            state["journal"].record_fs_settled(absent)
                        except BaseException as error:
                            state["journal"].record_uncertain("identity-mismatch")
                            raise error
                elif phase == "ROOTFS_LEASED":
                    state["journal"].record_uncertain("incomplete")
                elif phase == "FIREWALL_ABSENT":
                    state["journal"].record_input_removed(proof)
                return proof
            finally:
                if root is not None and root.identity_fd.disposition == "open": _close_owned((root,))

    def make_production_inputs(journal, completion, control, executable_owner):
        import completion_kata_process as process
        journal = operation._claim_production_operation(journal)
        _fail(type(completion) is fs.HeldNode and type(control) is fs.OperationControl)
        key_executable = process._claim_attested_executable(executable_owner, "ssh-keygen")
        _fail((key_executable.role, key_executable.path) == ("ssh-keygen", "/usr/bin/ssh-keygen"))
        context = operation._command_context(journal)
        _fail(context.lifecycle_phase == "ROOTFS_LEASED")
        value = _ProductionInputs(seal)
        production[value] = {
            "journal": journal, "completion": completion, "control": control,
            "key_executable": key_executable,
            "key_stage_name": fs._name(KEY_STAGE_PREFIX + context.operation_token),
            "grant": None, "key_grant": None,
            "identity": None, "handles": None, "bindings_claimed": False,
            "key_released": False, "removed": False, "uncertain": None,
        }
        return value

    def make_production_cleanup(journal, completion, control):
        journal = operation._claim_production_cleanup_operation(journal)
        _fail(type(completion) is fs.HeldNode and type(control) is fs.OperationControl)
        _fail(operation._durable_phase(journal) in {"ROOTFS_LEASED", "FS_INTENT", "FS_SETTLED",
              "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN"})
        value = _ProductionInputCleanup(seal)
        production[value] = {
            "journal": journal, "completion": completion, "control": control,
            "key_stage_name": None,
        }
        return value

    create_route = lambda completion, operation, key, control: latch_route(
        operation, None, lambda: create_owned(completion, operation, key, control))
    verify_route = lambda completion, operation, control: latch_route(
        operation, None, lambda: verify_owned(completion, operation, control))
    remove_route = lambda completion, operation, detach, control: latch_route(
        operation, detach, lambda: remove_owned(completion, operation, detach, control))
    return (make_test_key_grant, make_test_operation_grant, bind_test_operation_grant,
            make_test_detach_grant, create_route, verify_route, remove_route,
            _ProductionInputs, make_production_inputs,
            _ProductionInputCleanup, make_production_cleanup)

(_make_test_key_grant, _make_test_operation_grant, _bind_test_operation_grant,
 _make_test_detach_grant, _create_fixed_inputs_test_local,
 _verify_fixed_inputs_test_local, _remove_fixed_inputs_test_local,
 _ProductionInputs, _compose_production_inputs,
 _ProductionInputCleanup, _compose_production_input_cleanup) = _owner_routes()
del _owner_routes


# Runtime handoff retains real descriptors and reuses the canonical graph
# verifier. It accepts no manifest identities, digests, paths, or callbacks.
def _runtime_input_routes():
    owners = owner_helpers.Registry("_RuntimeInputs", InputError)
    grants = owner_helpers.Registry("_RuntimeInputGrant", InputError)
    _RuntimeInputs, _RuntimeInputGrant = owners.kind, grants.kind
    class _ObservedGrant:
        def __init__(self, token, raw, generation, rows):
            self.token, self.raw, self.generation, self.rows = token, raw, generation, rows
        def manifest_key(self): return self.generation.key
        def manifest_digest(self): return _sha(self.raw)
        def manifest_size(self): return len(self.raw)
        def directory_key(self, path): return _parse_key(self.rows[path]["identity"], "directory")
        def file_key(self, path): return _parse_key(self.rows[path]["identity"], "file")
    def observed(completion, token, control):
        root = manifest = None
        try:
            root = fs._open_path_node(completion, INPUT_NAME, "directory", control)
            manifest = fs._open_path_node(root, MANIFEST_NAME, "file", control)
            raw = fs._read_regular(manifest, MAX_MANIFEST, control)
            grant = _ObservedGrant(token, raw, manifest.generation,
                                   _manifest_rows(_parse_manifest(raw, token)))
        except BaseException as error:
            _close_owned(tuple(node for node in (manifest, root) if node is not None), error)
        _close_owned((manifest, root))
        return grant, _verify_graph(completion, grant, control)
    def reopen(journal, completion, control):
        _fail(type(completion) is fs.HeldNode and type(control) is fs.OperationControl)
        context = operation._command_context(journal)
        _fail(context.lifecycle_phase not in {"RETIRED", "INPUT_REMOVED",
                                               "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
                                               "ROOTFS_ABSENT"})
        observed_grant, identity = observed(completion, context.operation_token, control)
        root = share = host = authorized = fixture = None
        share_i = host_i = auth_i = fixture_i = ()
        try:
            root = fs._open_path_node(completion, INPUT_NAME, "directory", control)
            share, share_i = _open_relative(root, "share", "directory", control)
            host, host_i = _open_relative(root, SERVER_KEY, "file", control)
            authorized, auth_i = _open_relative(root, AUTHORIZED_KEYS, "file", control)
            fixture, fixture_i = _open_relative(root, "share/fixture", "directory", control)
            _fail(not share_i and len(host_i) == len(auth_i) == len(fixture_i) == 1)
            retained = (fixture, *fixture_i, authorized, *auth_i, host, *host_i, share, root)
        except BaseException as error:
            _close_owned(tuple(node for node in (fixture, *fixture_i, authorized, *auth_i,
                                                  host, *host_i, share, *share_i, root)
                               if node is not None), error)
        return owners.issue([
            journal, completion, control, observed_grant, identity, retained, False, False,
        ])
    def claim(owner, journal):
        state = owners.require(owner)
        _fail(state[0] is journal and not state[6])
        fresh_grant, identity = observed(state[1], state[4].operation_token, state[2])
        _fail(identity == state[4] and fresh_grant.raw == state[3].raw)
        for node in state[5]:
            _fail(fs._observe_node(node.identity_fd, node.operation_fd, state[2]) == node.generation)
        state[6] = True
        return grants.issue([
            owner, identity, tuple(node.generation for node in state[5]), False,
        ])
    def verify(grant):
        state = grants.require(grant)
        owner = owners.require(state[0])
        _fail(not owner[7])
        fresh, identity = observed(owner[1], owner[4].operation_token, owner[2])
        _fail(identity == state[1] == owner[4] and fresh.raw == owner[3].raw)
        for node, generation in zip(owner[5], state[2], strict=True):
            _fail(fs._observe_node(node.identity_fd, node.operation_fd, owner[2]) == generation)
        return identity, state[2]
    def consume(grant):
        state = grants.require(grant); _fail(not state[3]); result = verify(grant); state[3] = True; return result
    def close(owner):
        state = owners.require(owner)
        _fail(not state[7])
        _close_owned(state[5]); state[7] = True
        for grant, value in grants.items():
            if value[0] is owner:
                grants.pop(grant)
        owners.pop(owner)
    return reopen, claim, consume, verify, close

(_reopen_runtime_inputs, _claim_runtime_inputs, _consume_runtime_inputs,
 _verify_runtime_inputs, _close_runtime_inputs) = _runtime_input_routes()
del _runtime_input_routes

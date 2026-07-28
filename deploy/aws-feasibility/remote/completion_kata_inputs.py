"""Fixed, fd-relative Kata input/control ownership foundation.
Trusted host modules own it; guest/campaign data are untrusted. There is no production create or
remove route; InputPermit/KeyMaterialGrant issuers are absent and routes are tests.
"""
from dataclasses import dataclass
import base64
import binascii
import ctypes
import hashlib
import json
import os
import struct
import sys
import zlib
import completion_fixtures as fixtures
import completion_rootfs_fs as fs

VERSION = "cogs.stage2-kata-input-manifest/v1"
INPUT_NAME = fs._name("kata-input-v1")
MANIFEST_NAME = fs._name(".cogs-stage2-kata-input-manifest-v1.json")
CLIENT_KEY = "private/ssh_client_ed25519_key"
KNOWN_HOSTS = "private/known_hosts"
SERVER_KEY = "share/ssh_host_ed25519_key"
AUTHORIZED_KEYS = "share/authorized_keys"
CLIENT_COMMENT = b"cogs-stage2-client-v1"
SERVER_COMMENT = b"cogs-stage2-server-v1"
SSH_ALIAS = b"cogs-stage2-ssh-v1"
MAX_PRIVATE = 16_384
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
    """Parse structure, not seed math. Production must prove seed derivation;
    the test issuer accepts only exact mathematically valid RFC 8032 vectors.
    """
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
    seen = set()
    for line in lines:
        fields = line.split(b" ")
        _fail(len(fields) >= 10 and fields.count(b"-") == 1)
        separator = fields.index(b"-")
        _fail(separator >= 6 and separator + 3 <= len(fields))
        _fail(fields[0].isdigit() and fields[1].isdigit() and int(fields[0]) > 0)
        mount_root = _mount_unescape(fields[3])
        mountpoint = _mount_unescape(fields[4])
        mount_source = _mount_unescape(fields[separator + 2])
        _fail(mountpoint.startswith(b"/") and mount_root.startswith(b"/") and mountpoint not in seen)
        seen.add(mountpoint)
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

    class _TestOperationGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
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

    class _TestKeyGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)

    class _TestDetachGrant:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)

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
        except BaseException as error:
            owner = None if identity is None else fs.HeldNode(identity, descriptor, generation)
            _close_owned((owner, descriptor if identity is None else None), error)
        _close_owned((fs.HeldNode(identity, descriptor, generation),))
        return linked.key

    def create_test_local(completion, operation_grant, key_grant, control):
        state = permits.get(operation_grant)
        key_state = keys.get(key_grant)
        _fail(type(operation_grant) is _TestOperationGrant and state is not None)
        _fail(type(key_grant) is _TestKeyGrant and key_state is not None)
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
                        previous = os.umask(0o077)
                        try:
                            os.mkdir(name.raw, 0o700, dir_fd=parent.operation_fd.number)
                        finally:
                            _fail(os.umask(previous) == 0o077)
                        _checkpoint(control, "after-mkdir:" + entry.path)
                        os.fsync(parent.operation_fd.number)
                        _checkpoint(control, "after-directory-parent-fsync:" + entry.path)
                        existing = fs._observe_child(parent, name, control)
                    else:
                        # Intent plus an existing name is never an identity grant.
                        _fail(record["key"] is not None and record["key"] == existing.key)
                    expected_mode = entry.mode if entry.path in state["metadata"] else 0o700
                    _fail(existing.key.kind == "directory" and existing.mode == expected_mode)
                    _fail(existing.uid == existing.gid == 0 and existing.key.mount_id == parent.generation.key.mount_id)
                    _fail(existing.key.device == parent.generation.key.device)
                    record["key"] = existing.key
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

    def verify_test_local(completion, operation_grant, control):
        state = permits.get(operation_grant)
        _fail(type(operation_grant) is _TestOperationGrant and state is not None and state["status"] == "complete")
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

    def remove_test_local(completion, operation_grant, detach_grant, control):
        state = permits.get(operation_grant)
        detach = detaches.get(detach_grant)
        _fail(type(operation_grant) is _TestOperationGrant and state is not None and state["status"] == "complete")
        _fail(type(detach_grant) is _TestDetachGrant and detach is not None)
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
                if path == ".":
                    _fail(root.generation.key == _parse_key(key, "directory"))
                    _close_owned((root,))
                    root = None
                    os.rmdir(INPUT_NAME.raw, dir_fd=completion.operation_fd.number)
                    _checkpoint(control, "after-rmdir:.")
                    settle_active_absence(completion, None, detach, control)
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

    create_route = lambda completion, operation, key, control: latch_route(
        operation, None, lambda: create_test_local(completion, operation, key, control))
    verify_route = lambda completion, operation, control: latch_route(
        operation, None, lambda: verify_test_local(completion, operation, control))
    remove_route = lambda completion, operation, detach, control: latch_route(
        operation, detach, lambda: remove_test_local(completion, operation, detach, control))
    return (make_test_key_grant, make_test_operation_grant, bind_test_operation_grant,
            make_test_detach_grant, create_route, verify_route, remove_route)

(_make_test_key_grant, _make_test_operation_grant, _bind_test_operation_grant,
 _make_test_detach_grant, _create_fixed_inputs_test_local,
 _verify_fixed_inputs_test_local, _remove_fixed_inputs_test_local) = _owner_routes()
del _owner_routes

# Deliberately no production input creation/removal function or capability issuer.

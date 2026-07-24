"""Strict rootfs pins and recoverable atomic fixed-directory publication."""

import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True

import completion_rootfs_fs as fs

PINS_PATH = Path(__file__).with_name("stage2-completion-rootfs-v1.json")
ACCEPTED_NAME = fs._name(b"accepted")
CANDIDATE_NAME = fs._name(b".accepted-candidate-v1")
TRANSACTION_NAME = fs._name(b".accepted-transaction-v1")
TRANSACTION_NEXT_NAME = fs._name(b".accepted-transaction-next-v1")
SENTINEL_NAME = fs._name(b".cogs-rootfs-publication-v1")
SENTINEL = b"cogs-rootfs-publication-v1\n"
MANIFEST_NAME = fs._name(b"rootfs.manifest.json")
USTAR_NAME = fs._name(b"rootfs.tar")
METADATA_NAME = fs._name(b"rootfs.metadata.json")
VERSION = "cogs.rootfs-publication-transaction/v1"
ZERO_SHA256 = "0" * 64
MAX_TRANSACTION_BYTES = 64 * 1024
PINNED_RAW = b'''{
  "version": "cogs.stage2-completion-rootfs.v1",
  "source_date_epoch": 1782172800,
  "entry_count": 4353,
  "manifest": { "sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691", "size": 1049443 },
  "ustar": { "sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3", "size": 136905728 },
  "functional_test_image": "python@sha256:53d6284a40eae6b625f22870f5faba6c54f2a28db9027408f4dee111f1e885a2"
}
'''
PINNED_VALUE = {
    "version": "cogs.stage2-completion-rootfs.v1",
    "source_date_epoch": 1782172800,
    "entry_count": 4353,
    "manifest": {"sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691", "size": 1049443},
    "ustar": {"sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3", "size": 136905728},
    "functional_test_image": "python@sha256:53d6284a40eae6b625f22870f5faba6c54f2a28db9027408f4dee111f1e885a2",
}


class PublicationError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise PublicationError()


@dataclass(frozen=True)
class RootfsPins:
    raw: bytes
    manifest_sha256: str
    manifest_size: int
    ustar_sha256: str
    ustar_size: int
    entry_count: int


@dataclass(frozen=True)
class PublishedRootfs:
    manifest_sha256: str
    manifest_size: int
    ustar_sha256: str
    ustar_size: int
    entry_count: int


@dataclass(frozen=True)
class Transaction:
    records: tuple


@dataclass(frozen=True)
class AnonymousFile:
    operation_fd: fs.CheckedFd
    generation: fs.HostGeneration


def _close_nodes(nodes, primary=None):
    error = primary
    for node in reversed(tuple(node for node in nodes if node is not None)):
        if node.identity_fd.disposition == "open":
            try:
                fs._close_node(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


@contextmanager
def _owned_nodes(nodes):
    try:
        yield
    except BaseException as error:
        _close_nodes(nodes(), error)
    else:
        _close_nodes(nodes())


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        _fail(type(key) is str and key not in value)
        value[key] = item
    return value


def _reject_bool(value):
    if type(value) is bool:
        raise PublicationError()
    if type(value) is dict:
        for item in value.values():
            _reject_bool(item)
    elif type(value) is list:
        for item in value:
            _reject_bool(item)


def _parse_pins(raw):
    _fail(type(raw) is bytes and len(raw) <= 4096 and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=lambda _value: _fail(False))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, PublicationError) as error:
        raise PublicationError() from error
    _fail(raw == PINNED_RAW and value == PINNED_VALUE)
    return RootfsPins(raw, value["manifest"]["sha256"], value["manifest"]["size"], value["ustar"]["sha256"], value["ustar"]["size"], value["entry_count"])


def _load_pins():
    return _parse_pins(PINS_PATH.read_bytes())


def _write_all(descriptor, raw, control):
    offset = 0
    while offset < len(raw):
        control.check()
        count = os.write(descriptor.number, raw[offset:])
        control.check()
        _fail(type(count) is int and 0 < count <= len(raw) - offset)
        offset += count


def _key_value(key):
    return {"mount_id": key.mount_id, "device": key.device, "inode": key.inode, "kind": key.kind}


def _parse_key(value, kind):
    _fail(type(value) is dict and tuple(value) == ("mount_id", "device", "inode", "kind"))
    _fail(all(type(value[name]) is int and value[name] >= 0 for name in ("mount_id", "device", "inode")))
    _fail(value["mount_id"] > 0 and value["inode"] > 0 and value["kind"] == kind)
    return fs.HostKey(value["mount_id"], value["device"], value["inode"], kind)


def _generation_value(value):
    result = _key_value(value.key)
    result.update({name: getattr(value, name) for name in ("mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")})
    return result


def _parse_directory_generation(value):
    _fail(type(value) is dict and tuple(value) == ("mount_id", "device", "inode", "kind", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"))
    key = _parse_key({name: value[name] for name in ("mount_id", "device", "inode", "kind")}, "directory")
    _fail(all(type(value[name]) is int and value[name] >= 0 for name in ("mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")))
    _fail(value["mode"] == 0o700 and value["uid"] == value["gid"] == 0 and value["nlink"] >= 2)
    return fs.HostGeneration(key, value["mode"], value["uid"], value["gid"], value["nlink"], value["size"], value["mtime_ns"], value["ctime_ns"])


def _directory_generation_change(before, after):
    _fail(before.key == after.key and before.key.kind == "directory")
    _fail((before.mode, before.uid, before.gid, before.nlink) == (after.mode, after.uid, after.gid, after.nlink))


def _directory_link_change(before, after):
    _fail(before.key == after.key and before.key.kind == "directory")
    _fail((before.mode, before.uid, before.gid, before.nlink) == (after.mode, after.uid, after.gid, after.nlink))
    _fail(after.size >= before.size and after.mtime_ns >= before.mtime_ns and after.ctime_ns >= before.ctime_ns)


def _rename_generation_change(before, after):
    _fail(before.key == after.key and before.key.kind == "directory")
    _fail((before.mode, before.uid, before.gid, before.nlink, before.size, before.mtime_ns) == (after.mode, after.uid, after.gid, after.nlink, after.size, after.mtime_ns))
    _fail(after.ctime_ns >= before.ctime_ns)


def _parse_anonymous_generation(value):
    generation = _parse_file_generation(value, 0)
    return generation


def _parse_ready(value):
    _fail(type(value) is dict and tuple(value) == ("generation", "sha256", "size"))
    generation = _parse_anonymous_generation(value["generation"])
    _fail(type(value["sha256"]) is str and len(value["sha256"]) == 64 and all(character in "0123456789abcdef" for character in value["sha256"]))
    _fail(type(value["size"]) is int and not isinstance(value["size"], bool) and value["size"] >= 0 and generation.size == value["size"])
    return generation, value["sha256"], value["size"]


def _ready_value(generation, raw):
    return {"generation": _generation_value(generation), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _parse_file_generation(value, nlink):
    _fail(type(value) is dict and tuple(value) == ("mount_id", "device", "inode", "kind", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"))
    key = _parse_key({name: value[name] for name in ("mount_id", "device", "inode", "kind")}, "file")
    _fail(all(type(value[name]) is int and value[name] >= 0 for name in ("mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")))
    _fail(value["mode"] == 0o400 and value["uid"] == value["gid"] == 0 and value["nlink"] == nlink)
    return fs.HostGeneration(key, value["mode"], value["uid"], value["gid"], value["nlink"], value["size"], value["mtime_ns"], value["ctime_ns"])


def _parse_generation(value):
    return _parse_file_generation(value, 1)


def _linked_generation_change(before, after):
    _fail(before.key == after.key and before.key.kind == "file")
    _fail(before.nlink == 0 and after.nlink == 1)
    _fail((before.mode, before.uid, before.gid, before.size, before.mtime_ns) == (after.mode, after.uid, after.gid, after.size, after.mtime_ns))
    _fail(after.ctime_ns >= before.ctime_ns)


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise PublicationError() from error


def _record(sequence, previous, phase, name=None, identity=None):
    return {"version": VERSION, "sequence": sequence, "previous_sha256": previous, "phase": phase, "name": name, "identity": identity}


def _parse_transaction(raw, content_names):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_TRANSACTION_BYTES and raw.endswith(b"\n"))
    records = []
    previous = ZERO_SHA256
    state = "start"
    file_index = 0
    for sequence, line in enumerate(raw.splitlines(keepends=True)):
        try:
            value = json.loads(line, object_pairs_hook=_unique_pairs, parse_constant=lambda _value: _fail(False))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, PublicationError) as error:
            raise PublicationError() from error
        _reject_bool(value)
        _fail(_canonical(value) == line and tuple(value) == ("version", "sequence", "previous_sha256", "phase", "name", "identity"))
        _fail(value["version"] == VERSION and value["sequence"] == sequence and value["previous_sha256"] == previous)
        phase = value["phase"]
        if state == "start":
            _fail(phase == "intent")
            state = "absent"
        elif state == "absent":
            _fail(phase == "candidate-intent")
            state = "candidate-intent"
        elif state == "candidate-intent":
            _fail(phase == "candidate")
            candidate_generation = _parse_directory_generation(value["identity"])
            state = "candidate"
            file_index = 0
        elif state == "candidate" and phase == "file-intent":
            _fail(file_index < len(content_names) and value["name"] == content_names[file_index])
            _fail(_parse_directory_generation(value["identity"]) == candidate_generation)
            state = "file-intent"
        elif state == "file-intent":
            _fail(phase == "file-ready" and value["name"] == content_names[file_index])
            ready_generation, _ready_sha256, _ready_size = _parse_ready(value["identity"])
            state = "file-ready"
        elif state == "file-ready" and phase == "file-ready":
            _fail(value["name"] == content_names[file_index])
            ready_generation, _ready_sha256, _ready_size = _parse_ready(value["identity"])
        elif state == "file-ready":
            _fail(phase == "file" and value["name"] == content_names[file_index])
            linked_generation = _parse_generation(value["identity"])
            _linked_generation_change(ready_generation, linked_generation)
            state = "candidate-generation"
        elif state == "candidate-generation":
            _fail(phase == "candidate-generation")
            next_generation = _parse_directory_generation(value["identity"])
            _directory_generation_change(candidate_generation, next_generation)
            candidate_generation = next_generation
            file_index += 1
            state = "candidate"
        elif state == "candidate" and phase == "prepared":
            _fail(file_index == len(content_names))
            state = "prepared"
        elif state == "prepared":
            _fail(phase == "rename")
            state = "rename"
        elif state == "rename":
            _fail(phase == "accepted")
            accepted_generation = _parse_directory_generation(value["identity"])
            _rename_generation_change(candidate_generation, accepted_generation)
            state = "accepted"
        else:
            raise PublicationError()
        if phase not in {"file-intent", "file-ready", "file"}:
            _fail(value["name"] is None)
        if phase not in {"candidate", "candidate-generation", "file-intent", "file-ready", "file", "accepted"}:
            _fail(value["identity"] is None)
        previous = hashlib.sha256(line).hexdigest()
        records.append(value)
    return tuple(records)


def _cycle(records):
    candidate_index = max(index for index, record in enumerate(records) if record["phase"] == "candidate")
    cycle = records[candidate_index:]
    candidate_record = next(record for record in reversed(cycle) if record["phase"] in {"candidate", "candidate-generation"})
    files = tuple(record for record in cycle if record["phase"] == "file")
    return candidate_record, files


def _require_directory_generation(node, value, control):
    expected = _parse_directory_generation(value)
    actual = fs._observe_node(node.identity_fd, node.operation_fd, control)
    _fail(actual == expected)
    return actual


def _require_rename_generation(node, value, control):
    before = _parse_directory_generation(value)
    after = fs._observe_node(node.identity_fd, node.operation_fd, control)
    _rename_generation_change(before, after)
    return after


def _directory(parent, name, control):
    node = fs._open_path_node(parent, name, "directory", control)
    try:
        generation = node.generation
        _fail(generation.uid == generation.gid == 0 and generation.mode == 0o700 and generation.nlink >= 2)
        _fail(generation.key.device == parent.generation.key.device and generation.key.mount_id == parent.generation.key.mount_id)
        fs._require_empty_fd_xattrs(node, control)
        return node
    except BaseException as error:
        fs._close_node(node, error)


def _file(directory, name, expected, control):
    node = fs._open_path_node(directory, name, "file", control)
    try:
        generation = node.generation
        _fail(generation.uid == generation.gid == 0 and generation.mode == 0o400 and generation.nlink == 1)
        _fail(generation.key.device == directory.generation.key.device and generation.size == len(expected))
        fs._require_empty_fd_xattrs(node, control)
        _fail(fs._read_regular(node, len(expected), control) == expected)
        return node
    except BaseException as error:
        fs._close_node(node, error)


def _observe_anonymous(subject, control):
    operation = subject.operation_fd if type(subject) is AnonymousFile else subject
    _fail(type(operation) is fs.CheckedFd and operation.disposition == "open")
    os.lseek(operation.number, 0, os.SEEK_SET)
    flags = os.O_TMPFILE | os.O_RDWR | fs._O_CLOEXEC
    _fail(flags == 0o22200002)
    expected_flags = b"022440002"
    mount_id = fs._mount_id(operation, control, expected_flags)
    return fs._generation(operation, mount_id, control)


def _close_anonymous(anonymous, primary=None):
    error = primary
    if anonymous is not None and anonymous.operation_fd.disposition == "open":
        try:
            anonymous.operation_fd.close()
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _prepare_anonymous(directory, raw, control):
    _fail(sys.platform == "linux" and hasattr(os, "O_TMPFILE"))
    operation = None
    try:
        flags = os.O_TMPFILE | os.O_RDWR | fs._O_CLOEXEC
        operation = fs.CheckedFd(os.open(b".", flags, 0o400, dir_fd=directory.operation_fd.number), "publication-anonymous")
        _write_all(operation, raw, control)
        os.fchown(operation.number, 0, 0)
        os.fchmod(operation.number, 0o400)
        os.utime(operation.number, ns=(0, 0))
        os.fsync(operation.number)
        generation = _observe_anonymous(operation, control)
        anonymous = AnonymousFile(operation, generation)
        _fail(generation.key.kind == "file" and generation.mode == 0o400 and generation.uid == generation.gid == 0 and generation.nlink == 0 and generation.size == len(raw))
        _fail(generation.key.device == directory.generation.key.device and generation.key.mount_id == directory.generation.key.mount_id)
        before = _observe_anonymous(anonymous, control)
        flistxattr, _unused = fs._load_xattrs()
        fs._zero_xattrs(flistxattr, operation.number, control)
        _fail(_observe_anonymous(anonymous, control) == before)
        os.lseek(operation.number, 0, os.SEEK_SET)
        observed = fs._read_bounded(operation.number, len(raw), control)
        _fail(observed == raw and hashlib.sha256(observed).hexdigest() == hashlib.sha256(raw).hexdigest())
        return anonymous
    except BaseException as error:
        if operation is not None and operation.disposition == "open":
            operation.close(error)
        raise


def _link_anonymous(directory, name, anonymous, control):
    _fail(sys.platform == "linux" and anonymous.generation.nlink == 0)
    control.check()
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    linkat.restype = ctypes.c_int
    result = linkat(anonymous.operation_fd.number, b"", directory.operation_fd.number, name.raw, 0x1000)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _contents(manifest, ustar, pins):
    return ((SENTINEL_NAME, SENTINEL), (MANIFEST_NAME, manifest), (USTAR_NAME, ustar), (METADATA_NAME, pins.raw))


def _snapshot_node(parent, name, control):
    node = fs._open_path_node(parent, name, "file", control)
    try:
        generation = node.generation
        _fail(generation.mode == 0o400 and generation.uid == generation.gid == 0 and generation.nlink == 1)
        _fail(generation.key.device == parent.generation.key.device and generation.key.mount_id == parent.generation.key.mount_id)
        _fail(0 < generation.size <= MAX_TRANSACTION_BYTES)
        fs._require_empty_fd_xattrs(node, control)
        raw = fs._read_regular(node, MAX_TRANSACTION_BYTES, control)
        return node, raw
    except BaseException as error:
        fs._close_node(node, error)


def _remove_snapshot(parent, name, node, control):
    expected = fs._observe_node(node.identity_fd, node.operation_fd, control)
    fs._close_node(node)
    _fail(fs._observe_child(parent, name, control) == expected)
    os.unlink(name.raw, dir_fd=parent.operation_fd.number)
    os.fsync(parent.operation_fd.number)


def _write_snapshot(parent, raw, control):
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    descriptor = None
    node = None
    key = None
    created = False
    try:
        descriptor = fs.CheckedFd(os.open(TRANSACTION_NEXT_NAME.raw, flags, 0o400, dir_fd=parent.operation_fd.number), "publication-snapshot")
        created = True
        observed = os.fstat(descriptor.number)
        key = (observed.st_dev, observed.st_ino)
        _write_all(descriptor, raw, control)
        os.fsync(descriptor.number)
        descriptor.close()
        descriptor = None
        node, verified = _snapshot_node(parent, TRANSACTION_NEXT_NAME, control)
        _fail(verified == raw and (node.generation.key.device, node.generation.key.inode) == key)
        os.fsync(parent.operation_fd.number)
        return node
    except BaseException as error:
        cleanup = _transition_control()
        if node is not None and node.identity_fd.disposition == "open":
            try:
                fs._close_node(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if key is None and descriptor is not None and descriptor.disposition == "open":
            try:
                observed = os.fstat(descriptor.number)
                key = (observed.st_dev, observed.st_ino)
            except BaseException as identity_error:
                error = fs.RootfsFsError(error, identity_error)
        if descriptor is not None and descriptor.disposition == "open":
            try:
                descriptor.close()
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if created:
            try:
                current = fs._observe_child(parent, TRANSACTION_NEXT_NAME, cleanup)
                _fail(current.key.kind == "file")
                if key is not None:
                    _fail((current.key.device, current.key.inode) == key)
                os.unlink(TRANSACTION_NEXT_NAME.raw, dir_fd=parent.operation_fd.number)
                os.fsync(parent.operation_fd.number)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        raise error


def _renameat2(parent, source, destination, flags):
    _fail(sys.platform == "linux")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(parent.operation_fd.number, source.raw, parent.operation_fd.number, destination.raw, flags)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _finish_snapshot(parent, main, next_node, exchange, control):
    if exchange:
        main_key = main.generation.key
        next_key = next_node.generation.key
        _renameat2(parent, TRANSACTION_NEXT_NAME, TRANSACTION_NAME, 2)
        _fail(fs._observe_child(parent, TRANSACTION_NAME, control).key == next_key)
        _fail(fs._observe_child(parent, TRANSACTION_NEXT_NAME, control).key == main_key)
        os.fsync(parent.operation_fd.number)
        fs._close_node(next_node)
        _remove_snapshot(parent, TRANSACTION_NEXT_NAME, main, control)
    else:
        _renameat2(parent, TRANSACTION_NEXT_NAME, TRANSACTION_NAME, 1)
        _fail(fs._observe_child(parent, TRANSACTION_NAME, control).key == next_node.generation.key)
        os.fsync(parent.operation_fd.number)
        fs._close_node(next_node)


def _open_transaction(parent, content_names, control):
    names = fs._enumerate_stable(parent, control).raw_names
    has_main = TRANSACTION_NAME.raw in names
    has_next = TRANSACTION_NEXT_NAME.raw in names
    if not has_main and not has_next:
        return _append_transaction(Transaction(()), parent, content_names, "intent", control)
    main = next_node = None
    with _owned_nodes(lambda: (main, next_node)):
        main_records = next_records = None
        if has_main:
            main, raw = _snapshot_node(parent, TRANSACTION_NAME, control)
            main_records = _parse_transaction(raw, content_names)
        if has_next:
            next_node, raw = _snapshot_node(parent, TRANSACTION_NEXT_NAME, control)
            next_records = _parse_transaction(raw, content_names)
        if not has_main:
            _fail(len(next_records) == 1 and next_records[0]["phase"] == "intent")
            _finish_snapshot(parent, None, next_node, False, control)
            next_node = None
            return Transaction(next_records)
        if has_next:
            if len(next_records) in {len(main_records) + 1, len(main_records) + 2} and next_records[: len(main_records)] == main_records:
                _finish_snapshot(parent, main, next_node, True, control)
                main = next_node = None
                return Transaction(next_records)
            _fail(len(main_records) in {len(next_records) + 1, len(next_records) + 2} and main_records[: len(next_records)] == next_records)
            _remove_snapshot(parent, TRANSACTION_NEXT_NAME, next_node, control)
            next_node = None
        fs._close_node(main)
        main = None
        return Transaction(main_records)


def _append_records(transaction, parent, content_names, additions, control):
    records = transaction.records
    for phase, name, identity in additions:
        previous = ZERO_SHA256 if not records else hashlib.sha256(_canonical(records[-1])).hexdigest()
        records += (_record(len(records), previous, phase, name, identity),)
    raw = b"".join(_canonical(record) for record in records)
    _parse_transaction(raw, content_names)
    next_node = _write_snapshot(parent, raw, control)
    main = None
    with _owned_nodes(lambda: (main, next_node)):
        names = fs._enumerate_stable(parent, control).raw_names
        if TRANSACTION_NAME.raw in names:
            main, current = _snapshot_node(parent, TRANSACTION_NAME, control)
            _fail(_parse_transaction(current, content_names) == transaction.records)
            _finish_snapshot(parent, main, next_node, True, control)
            main = next_node = None
        else:
            _fail(not transaction.records)
            _finish_snapshot(parent, None, next_node, False, control)
            next_node = None
        return Transaction(records)


def _append_transaction(transaction, parent, content_names, phase, control, name=None, identity=None):
    return _append_records(transaction, parent, content_names, ((phase, name, identity),), control)


def _durable_event(parent, content_names, phase, name, key, control):
    transaction = _open_transaction(parent, content_names, control)
    record = transaction.records[-1]
    if record["phase"] != phase or record["name"] != name:
        return False
    identity = _parse_directory_generation(record["identity"]) if phase == "candidate" else _parse_generation(record["identity"]).key
    return identity == key


def _verify_inventory(directory, contents, recorded, complete, control, additional=()):
    expected_names = tuple(name.raw for name, _raw in contents[: len(recorded)]) + tuple(additional)
    snapshot = fs._enumerate_stable(directory, control)
    _fail(snapshot.raw_names == tuple(sorted(expected_names)) if not complete else not additional and snapshot.raw_names == tuple(sorted(name.raw for name, _raw in contents)))
    for index, (name, raw) in enumerate(contents[: len(recorded)] if not complete else contents):
        node = _file(directory, name, raw, control)
        with _owned_nodes(lambda: (node,)):
            if index < len(recorded):
                _fail(node.generation == _parse_generation(recorded[index]["identity"]))
    return snapshot.generation


def _cleanup_empty_candidate(parent, candidate, control):
    _fail(not fs._enumerate_stable(candidate, control).names)
    os.fsync(candidate.operation_fd.number)
    expected = fs._observe_node(candidate.identity_fd, candidate.operation_fd, control)
    fs._close_node(candidate)
    _fail(fs._observe_child(parent, CANDIDATE_NAME, control) == expected)
    os.rmdir(CANDIDATE_NAME.raw, dir_fd=parent.operation_fd.number)
    os.fsync(parent.operation_fd.number)


def _rename_noreplace(parent):
    _renameat2(parent, CANDIDATE_NAME, ACCEPTED_NAME, 1)


def _transition_control():
    return fs.OperationControl(time.monotonic_ns() + 120 * 1_000_000_000, lambda: False)


def _published(pins):
    return PublishedRootfs(pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256, pins.ustar_size, pins.entry_count)


def _publish_unmasked(parent, manifest, ustar, pins, work_control):
    _fail(type(parent) is fs.HeldNode and parent.operation_fd is not None and type(work_control) is fs.OperationControl)
    _fail(type(manifest) is bytes and type(ustar) is bytes and type(pins) is RootfsPins)
    _fail(len(manifest) == pins.manifest_size and hashlib.sha256(manifest).hexdigest() == pins.manifest_sha256)
    _fail(len(ustar) == pins.ustar_size and hashlib.sha256(ustar).hexdigest() == pins.ustar_sha256)
    parent_generation = fs._observe_node(parent.identity_fd, parent.operation_fd, work_control)
    _fail(parent_generation.key.kind == "directory" and parent_generation.uid == parent_generation.gid == 0 and parent_generation.mode == 0o700)
    fs._require_empty_fd_xattrs(parent, work_control)
    contents = _contents(manifest, ustar, pins)
    content_names = tuple(name.text for name, _raw in contents)
    control = _transition_control()
    transaction = _open_transaction(parent, content_names, control)
    candidate = None
    anonymous = None
    owned_progress = False
    try:
        while True:
            phase = transaction.records[-1]["phase"]
            names = fs._enumerate_stable(parent, control).raw_names
            if phase == "intent":
                _fail(CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw not in names)
                transaction = _append_transaction(transaction, parent, content_names, "candidate-intent", control)
            elif phase == "candidate-intent":
                _fail(CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw not in names)
                created_candidate = False
                try:
                    os.mkdir(CANDIDATE_NAME.raw, 0o700, dir_fd=parent.operation_fd.number)
                    created_candidate = True
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                    os.fsync(parent.operation_fd.number)
                    transaction = _append_transaction(transaction, parent, content_names, "candidate", control, identity=_generation_value(candidate.generation))
                    owned_progress = True
                    work_control.check()
                except BaseException as error:
                    cleanup_control = _transition_control()
                    if created_candidate:
                        try:
                            durable = candidate is not None and _durable_event(parent, content_names, "candidate", None, candidate.generation, cleanup_control)
                            if not durable:
                                if candidate is not None:
                                    _cleanup_empty_candidate(parent, candidate, cleanup_control)
                                    candidate = None
                                else:
                                    current = fs._observe_child(parent, CANDIDATE_NAME, cleanup_control)
                                    _fail(current.key.kind == "directory")
                                    os.rmdir(CANDIDATE_NAME.raw, dir_fd=parent.operation_fd.number)
                                    os.fsync(parent.operation_fd.number)
                        except BaseException as cleanup_error:
                            error = fs.RootfsFsError(error, cleanup_error)
                    raise error
            elif phase in {"candidate", "candidate-generation"}:
                _fail(ACCEPTED_NAME.raw not in names)
                candidate_record, file_records = _cycle(transaction.records)
                _fail(CANDIDATE_NAME.raw in names)
                if candidate is None:
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                current_candidate = _require_directory_generation(candidate, candidate_record["identity"], control)
                _verify_inventory(candidate, contents, file_records, len(file_records) == len(contents), control)
                if len(file_records) < len(contents):
                    owned_progress = True
                    name = contents[len(file_records)][0]
                    transaction = _append_transaction(transaction, parent, content_names, "file-intent", control, name.text, _generation_value(current_candidate))
                else:
                    os.fsync(candidate.operation_fd.number)
                    transaction = _append_transaction(transaction, parent, content_names, "prepared", control)
            elif phase == "file-intent":
                candidate_record, file_records = _cycle(transaction.records)
                _fail(CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names)
                if candidate is None:
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                _require_directory_generation(candidate, candidate_record["identity"], control)
                _verify_inventory(candidate, contents, file_records, False, control)
                name, raw = contents[len(file_records)]
                anonymous = _prepare_anonymous(candidate, raw, control)
                transaction = _append_transaction(transaction, parent, content_names, "file-ready", control, name.text, _ready_value(anonymous.generation, raw))
            elif phase == "file-ready":
                candidate_record, file_records = _cycle(transaction.records)
                _fail(CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names)
                if candidate is None:
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                before_candidate = _parse_directory_generation(candidate_record["identity"])
                name, raw = contents[len(file_records)]
                ready_generation, ready_sha256, ready_size = _parse_ready(transaction.records[-1]["identity"])
                _fail(ready_sha256 == hashlib.sha256(raw).hexdigest() and ready_size == len(raw))
                snapshot = fs._enumerate_stable(candidate, control)
                prior_names = tuple(sorted(item.raw for item, _raw in contents[: len(file_records)]))
                linked_names = tuple(sorted(prior_names + (name.raw,)))
                if snapshot.raw_names == prior_names:
                    _fail(snapshot.generation == before_candidate)
                    _verify_inventory(candidate, contents, file_records, False, control)
                    if anonymous is None or anonymous.generation != ready_generation:
                        if anonymous is not None:
                            _close_anonymous(anonymous)
                        anonymous = _prepare_anonymous(candidate, raw, control)
                        transaction = _append_transaction(transaction, parent, content_names, "file-ready", control, name.text, _ready_value(anonymous.generation, raw))
                        continue
                    _fail(_observe_anonymous(anonymous, control) == ready_generation)
                    _link_anonymous(candidate, name, anonymous, control)
                    continue
                _fail(snapshot.raw_names == linked_names)
                _directory_link_change(before_candidate, snapshot.generation)
                _verify_inventory(candidate, contents, file_records, False, control, (name.raw,))
                linked = _file(candidate, name, raw, control)
                with _owned_nodes(lambda: (linked,)):
                    _linked_generation_change(ready_generation, linked.generation)
                    os.fsync(candidate.operation_fd.number)
                    after_candidate = fs._observe_node(candidate.identity_fd, candidate.operation_fd, control)
                    _fail(after_candidate == snapshot.generation)
                    transaction = _append_records(transaction, parent, content_names, (("file", name.text, _generation_value(linked.generation)), ("candidate-generation", None, _generation_value(after_candidate))), control)
                if anonymous is not None:
                    _close_anonymous(anonymous)
                    anonymous = None
                work_control.check()
            elif phase == "prepared":
                _fail(CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names)
                candidate_record, file_records = _cycle(transaction.records)
                if candidate is None:
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                _require_directory_generation(candidate, candidate_record["identity"], control)
                _verify_inventory(candidate, contents, file_records, True, control)
                transaction = _append_transaction(transaction, parent, content_names, "rename", control)
            elif phase == "rename":
                candidate_record, file_records = _cycle(transaction.records)
                if CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names:
                    if candidate is None:
                        candidate = _directory(parent, CANDIDATE_NAME, control)
                    _require_directory_generation(candidate, candidate_record["identity"], control)
                    _verify_inventory(candidate, contents, file_records, True, control)
                    _rename_noreplace(parent)
                    continue
                _fail(CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw in names)
                accepted = _directory(parent, ACCEPTED_NAME, control)
                with _owned_nodes(lambda: (accepted,)):
                    accepted_generation = _require_rename_generation(accepted, candidate_record["identity"], control)
                    _verify_inventory(accepted, contents, file_records, True, control)
                    os.fsync(parent.operation_fd.number)
                    transaction = _append_transaction(transaction, parent, content_names, "accepted", control, identity=_generation_value(accepted_generation))
            else:
                _fail(phase == "accepted" and CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw in names)
                accepted = _directory(parent, ACCEPTED_NAME, control)
                with _owned_nodes(lambda: (accepted,)):
                    _candidate_record, file_records = _cycle(transaction.records)
                    _require_directory_generation(accepted, transaction.records[-1]["identity"], control)
                    _verify_inventory(accepted, contents, file_records, True, control)
                    os.fsync(parent.operation_fd.number)
                return _published(pins)
    finally:
        primary = sys.exception()
        error = None
        if anonymous is not None and anonymous.operation_fd.disposition == "open":
            try:
                _close_anonymous(anonymous)
            except BaseException as close_error:
                error = fs.RootfsFsError(primary, close_error)
        if candidate is not None and candidate.identity_fd.disposition == "open":
            try:
                fs._close_node(candidate)
            except BaseException as close_error:
                error = fs.RootfsFsError(primary if error is None else error, close_error)
        if error is not None:
            raise error


def _publish(parent, manifest, ustar, pins, control):
    import completion_rootfs_builder as builder

    return builder._fixed_umask(_publish_unmasked, parent, manifest, ustar, pins, control)

"""Strict rootfs pins and recoverable atomic fixed-directory publication."""

import ctypes
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
    node: fs.HeldNode
    records: tuple


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


def _parse_generation(value):
    _fail(type(value) is dict and tuple(value) == ("mount_id", "device", "inode", "kind", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"))
    key = _parse_key({name: value[name] for name in ("mount_id", "device", "inode", "kind")}, "file")
    _fail(all(type(value[name]) is int and value[name] >= 0 for name in ("mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")))
    _fail(value["mode"] == 0o400 and value["uid"] == value["gid"] == 0 and value["nlink"] == 1)
    return fs.HostGeneration(key, value["mode"], value["uid"], value["gid"], value["nlink"], value["size"], value["mtime_ns"], value["ctime_ns"])


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
            _fail(phase == "candidate")
            _parse_key(value["identity"], "directory")
            state = "candidate"
            file_index = 0
        elif state == "candidate" and phase == "file":
            _fail(file_index < len(content_names) and value["name"] == content_names[file_index])
            _parse_generation(value["identity"])
            file_index += 1
        elif state == "candidate" and phase == "cleaned":
            _fail(file_index < len(content_names))
            state = "absent"
        elif state == "candidate" and phase == "prepared":
            _fail(file_index == len(content_names))
            state = "prepared"
        elif state == "prepared":
            _fail(phase == "rename")
            state = "rename"
        elif state == "rename":
            _fail(phase == "accepted")
            state = "accepted"
        else:
            raise PublicationError()
        if phase != "file":
            _fail(value["name"] is None)
        if phase != "candidate" and phase != "file":
            _fail(value["identity"] is None)
        previous = hashlib.sha256(line).hexdigest()
        records.append(value)
    return tuple(records)


def _cycle(records):
    candidate_index = max(index for index, record in enumerate(records) if record["phase"] == "candidate")
    files = tuple(record for record in records[candidate_index + 1 :] if record["phase"] == "file")
    return records[candidate_index], files


def _directory(parent, name, control):
    node = fs._open_path_node(parent, name, "directory", control)
    generation = node.generation
    _fail(generation.uid == generation.gid == 0 and generation.mode == 0o700 and generation.nlink >= 2)
    _fail(generation.key.device == parent.generation.key.device and generation.key.mount_id == parent.generation.key.mount_id)
    fs._require_empty_fd_xattrs(node, control)
    return node


def _file(directory, name, expected, control):
    node = fs._open_path_node(directory, name, "file", control)
    generation = node.generation
    _fail(generation.uid == generation.gid == 0 and generation.mode == 0o400 and generation.nlink == 1)
    _fail(generation.key.device == directory.generation.key.device and generation.size == len(expected))
    fs._require_empty_fd_xattrs(node, control)
    _fail(fs._read_regular(node, len(expected), control) == expected)
    return node


def _create_file(directory, name, raw, control):
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    descriptor = fs.CheckedFd(os.open(name.raw, flags, 0o400, dir_fd=directory.operation_fd.number), "publication-file")
    try:
        node = fs._open_path_node(directory, name, "file", control)
        identity = node.generation.key
        descriptor_stat = os.fstat(descriptor.number)
        _fail((descriptor_stat.st_dev, descriptor_stat.st_ino) == (identity.device, identity.inode))
        fs._close_node(node)
        _write_all(descriptor, raw, control)
        os.fsync(descriptor.number)
        descriptor.close()
    except BaseException as error:
        if descriptor.disposition == "open":
            descriptor.close(error)
        raise
    node = _file(directory, name, raw, control)
    generation = node.generation
    fs._close_node(node)
    return generation


def _contents(manifest, ustar, pins):
    return ((SENTINEL_NAME, SENTINEL), (MANIFEST_NAME, manifest), (USTAR_NAME, ustar), (METADATA_NAME, pins.raw))


def _transaction_node(parent, control, create):
    identity = None
    descriptor = None
    try:
        if create:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
            descriptor = fs.CheckedFd(os.open(TRANSACTION_NAME.raw, flags, 0o400, dir_fd=parent.operation_fd.number), "publication-transaction")
            identity = fs.CheckedFd(os.open(TRANSACTION_NAME.raw, fs.IDENTITY_FLAGS, dir_fd=parent.operation_fd.number), "publication-transaction-identity")
        else:
            identity = fs.CheckedFd(os.open(TRANSACTION_NAME.raw, fs.IDENTITY_FLAGS, dir_fd=parent.operation_fd.number), "publication-transaction-identity")
            descriptor = fs.CheckedFd(os.open(TRANSACTION_NAME.raw, os.O_RDWR | fs._O_NOFOLLOW | fs._O_CLOEXEC, dir_fd=parent.operation_fd.number), "publication-transaction")
        generation = fs._observe_node(identity, descriptor, control)
        _fail(generation.key.kind == "file" and generation.mode == 0o400 and generation.uid == generation.gid == 0 and generation.nlink == 1)
        _fail(generation.key.device == parent.generation.key.device and generation.key.mount_id == parent.generation.key.mount_id)
        _fail(generation.size <= MAX_TRANSACTION_BYTES)
        node = fs.HeldNode(identity, descriptor, generation)
        fs._require_empty_fd_xattrs(node, control)
        return node
    except BaseException as error:
        for owned in (descriptor, identity):
            if owned is not None and owned.disposition == "open":
                try:
                    owned.close()
                except BaseException as close_error:
                    error = fs.RootfsFsError(error, close_error)
        raise error


def _open_transaction(parent, content_names, control):
    names = fs._enumerate_stable(parent, control).raw_names
    if TRANSACTION_NAME.raw not in names:
        node = _transaction_node(parent, control, True)
        try:
            transaction = _append_transaction(Transaction(node, ()), "intent", control)
            os.fsync(parent.operation_fd.number)
            return transaction
        except BaseException as error:
            try:
                os.fsync(parent.operation_fd.number)
            except BaseException as sync_error:
                error = fs.RootfsFsError(error, sync_error)
            fs._close_node(node, error)
    node = _transaction_node(parent, control, False)
    try:
        raw = fs._read_regular(node, MAX_TRANSACTION_BYTES, control)
        records = _parse_transaction(raw, content_names)
        os.lseek(node.operation_fd.number, len(raw), os.SEEK_SET)
        return Transaction(node, records)
    except BaseException as error:
        fs._close_node(node, error)


def _append_transaction(transaction, phase, control, name=None, identity=None):
    previous = ZERO_SHA256 if not transaction.records else hashlib.sha256(_canonical(transaction.records[-1])).hexdigest()
    value = _record(len(transaction.records), previous, phase, name, identity)
    raw = _canonical(value)
    _write_all(transaction.node.operation_fd, raw, control)
    os.fsync(transaction.node.operation_fd.number)
    return Transaction(transaction.node, transaction.records + (value,))


def _verify_inventory(directory, contents, recorded, complete, control):
    expected_names = tuple(name.raw for name, _raw in contents[: len(recorded)])
    snapshot = fs._enumerate_stable(directory, control)
    _fail(snapshot.raw_names == tuple(sorted(expected_names)) if not complete else snapshot.raw_names == tuple(sorted(name.raw for name, _raw in contents)))
    for index, (name, raw) in enumerate(contents[: len(recorded)] if not complete else contents):
        node = _file(directory, name, raw, control)
        if index < len(recorded):
            _fail(node.generation == _parse_generation(recorded[index]["identity"]))
        fs._close_node(node)


def _cleanup_candidate(parent, candidate, contents, recorded, control):
    _verify_inventory(candidate, contents, recorded, False, control)
    for index in range(len(recorded) - 1, -1, -1):
        name = contents[index][0]
        _fail(fs._observe_child(candidate, name, control) == _parse_generation(recorded[index]["identity"]))
        os.unlink(name.raw, dir_fd=candidate.operation_fd.number)
    os.fsync(candidate.operation_fd.number)
    expected = fs._observe_node(candidate.identity_fd, candidate.operation_fd, control)
    fs._close_node(candidate)
    _fail(fs._observe_child(parent, CANDIDATE_NAME, control) == expected)
    os.rmdir(CANDIDATE_NAME.raw, dir_fd=parent.operation_fd.number)
    os.fsync(parent.operation_fd.number)


def _rename_noreplace(parent):
    _fail(sys.platform == "linux")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(parent.operation_fd.number, CANDIDATE_NAME.raw, parent.operation_fd.number, ACCEPTED_NAME.raw, 1)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


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
    owned_progress = False
    try:
        while True:
            phase = transaction.records[-1]["phase"]
            names = fs._enumerate_stable(parent, control).raw_names
            if phase in {"intent", "cleaned"}:
                _fail(CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw not in names)
                os.mkdir(CANDIDATE_NAME.raw, 0o700, dir_fd=parent.operation_fd.number)
                candidate = _directory(parent, CANDIDATE_NAME, control)
                os.fsync(parent.operation_fd.number)
                transaction = _append_transaction(transaction, "candidate", control, identity=_key_value(candidate.generation.key))
                owned_progress = True
            elif phase in {"candidate", "file"}:
                _fail(ACCEPTED_NAME.raw not in names)
                candidate_record, file_records = _cycle(transaction.records)
                if CANDIDATE_NAME.raw not in names:
                    _fail(len(file_records) < len(contents))
                    transaction = _append_transaction(transaction, "cleaned", control)
                    continue
                if candidate is None:
                    candidate = _directory(parent, CANDIDATE_NAME, control)
                candidate_key = _parse_key(candidate_record["identity"], "directory")
                _fail(candidate.generation.key == candidate_key)
                _verify_inventory(candidate, contents, file_records, len(file_records) == len(contents), control)
                if len(file_records) < len(contents) and not owned_progress:
                    _cleanup_candidate(parent, candidate, contents, file_records, control)
                    candidate = None
                    transaction = _append_transaction(transaction, "cleaned", control)
                elif len(file_records) < len(contents):
                    name, raw = contents[len(file_records)]
                    generation = _create_file(candidate, name, raw, control)
                    os.fsync(candidate.operation_fd.number)
                    transaction = _append_transaction(transaction, "file", control, name.text, _generation_value(generation))
                else:
                    os.fsync(candidate.operation_fd.number)
                    transaction = _append_transaction(transaction, "prepared", control)
            elif phase == "prepared":
                _fail(CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names)
                transaction = _append_transaction(transaction, "rename", control)
            elif phase == "rename":
                candidate_record, file_records = _cycle(transaction.records)
                candidate_key = _parse_key(candidate_record["identity"], "directory")
                if CANDIDATE_NAME.raw in names and ACCEPTED_NAME.raw not in names:
                    if candidate is None:
                        candidate = _directory(parent, CANDIDATE_NAME, control)
                    _fail(candidate.generation.key == candidate_key)
                    _verify_inventory(candidate, contents, file_records, True, control)
                    _rename_noreplace(parent)
                    continue
                _fail(CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw in names)
                accepted = _directory(parent, ACCEPTED_NAME, control)
                try:
                    _fail(accepted.generation.key == candidate_key)
                    _verify_inventory(accepted, contents, file_records, True, control)
                    os.fsync(parent.operation_fd.number)
                    transaction = _append_transaction(transaction, "accepted", control)
                finally:
                    fs._close_node(accepted)
            else:
                _fail(phase == "accepted" and CANDIDATE_NAME.raw not in names and ACCEPTED_NAME.raw in names)
                accepted = _directory(parent, ACCEPTED_NAME, control)
                try:
                    candidate_record, file_records = _cycle(transaction.records)
                    _fail(accepted.generation.key == _parse_key(candidate_record["identity"], "directory"))
                    _verify_inventory(accepted, contents, file_records, True, control)
                    os.fsync(parent.operation_fd.number)
                finally:
                    fs._close_node(accepted)
                return _published(pins)
    finally:
        primary = sys.exception()
        error = None
        for node in (candidate, transaction.node):
            if node is not None and node.identity_fd.disposition == "open":
                try:
                    fs._close_node(node)
                except BaseException as close_error:
                    error = fs.RootfsFsError(primary if error is None else error, close_error)
        if error is not None:
            raise error


def _publish(parent, manifest, ustar, pins, control):
    import completion_rootfs_builder as builder

    return builder._fixed_umask(_publish_unmasked, parent, manifest, ustar, pins, control)

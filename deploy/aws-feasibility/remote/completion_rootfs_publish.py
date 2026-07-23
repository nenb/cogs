"""Strict rootfs pins and atomic fixed-directory publication."""

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
SENTINEL_NAME = fs._name(b".cogs-rootfs-publication-v1")
SENTINEL = b"cogs-rootfs-publication-v1\n"
MANIFEST_NAME = fs._name(b"rootfs.manifest.json")
USTAR_NAME = fs._name(b"rootfs.tar")
METADATA_NAME = fs._name(b"rootfs.metadata.json")
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


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        _fail(type(key) is str and key not in value)
        value[key] = item
    return value


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
    control.check()
    descriptor = fs.CheckedFd(os.open(name.raw, flags, 0o400, dir_fd=directory.operation_fd.number), "publication-file")
    try:
        _write_all(descriptor, raw, control)
        control.check()
        os.fsync(descriptor.number)
        control.check()
        descriptor.close()
    except BaseException as error:
        if descriptor.disposition == "open":
            descriptor.close(error)
        raise
    node = _file(directory, name, raw, control)
    fs._close_node(node)


def _contents(manifest, ustar, pins):
    return ((SENTINEL_NAME, SENTINEL), (MANIFEST_NAME, manifest), (USTAR_NAME, ustar), (METADATA_NAME, pins.raw))


def _verify_candidate(candidate, contents, control, complete):
    names = fs._enumerate_stable(candidate, control).raw_names
    allowed = tuple(sorted(name.raw for name, _raw in contents))
    _fail(names == allowed if complete else SENTINEL_NAME.raw in names and set(names) <= set(allowed))
    verified = []
    for name, raw in contents:
        if name.raw in names:
            node = _file(candidate, name, raw, control)
            verified.append((name, node.generation))
            fs._close_node(node)
    return tuple(verified)


def _cleanup_candidate(parent, expected_key, contents, control):
    candidate = _directory(parent, CANDIDATE_NAME, control)
    try:
        _fail(candidate.generation.key == expected_key)
        verified = _verify_candidate(candidate, contents, control, False)
        for name, expected in reversed(verified):
            _fail(fs._observe_child(candidate, name, control) == expected)
            control.check()
            os.unlink(name.raw, dir_fd=candidate.operation_fd.number)
            control.check()
        control.check()
        os.fsync(candidate.operation_fd.number)
        control.check()
        expected = fs._observe_node(candidate.identity_fd, candidate.operation_fd, control)
        fs._close_node(candidate)
        candidate = None
        _fail(fs._observe_child(parent, CANDIDATE_NAME, control) == expected)
        control.check()
        os.rmdir(CANDIDATE_NAME.raw, dir_fd=parent.operation_fd.number)
        control.check()
        os.fsync(parent.operation_fd.number)
        control.check()
    finally:
        if candidate is not None and candidate.identity_fd.disposition == "open":
            fs._close_node(candidate)


def _rename_noreplace(parent, control):
    _fail(sys.platform == "linux")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    control.check()
    result = renameat2(parent.operation_fd.number, CANDIDATE_NAME.raw, parent.operation_fd.number, ACCEPTED_NAME.raw, 1)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    control.check()


def _fresh_cleanup_control():
    return fs.OperationControl(time.monotonic_ns() + 120 * 1_000_000_000, lambda: False)


def _publish(parent, manifest, ustar, pins, control):
    _fail(type(parent) is fs.HeldNode and parent.operation_fd is not None)
    _fail(type(manifest) is bytes and type(ustar) is bytes and type(pins) is RootfsPins)
    _fail(len(manifest) == pins.manifest_size and hashlib.sha256(manifest).hexdigest() == pins.manifest_sha256)
    _fail(len(ustar) == pins.ustar_size and hashlib.sha256(ustar).hexdigest() == pins.ustar_sha256)
    parent_generation = fs._observe_node(parent.identity_fd, parent.operation_fd, control)
    _fail(parent_generation.key.kind == "directory" and parent_generation.uid == parent_generation.gid == 0 and parent_generation.mode == 0o700)
    fs._require_empty_fd_xattrs(parent, control)
    contents = _contents(manifest, ustar, pins)
    names = fs._enumerate_stable(parent, control).raw_names
    _fail(ACCEPTED_NAME.raw not in names)
    if CANDIDATE_NAME.raw in names:
        stale = _directory(parent, CANDIDATE_NAME, control)
        stale_key = stale.generation.key
        fs._close_node(stale)
        _cleanup_candidate(parent, stale_key, contents, _fresh_cleanup_control())
    # os.umask is process-wide: this coordinator requires a single-threaded process.
    previous_umask = os.umask(0o077)
    candidate = None
    installed = False
    candidate_key = None
    error = None
    try:
        control.check()
        os.mkdir(CANDIDATE_NAME.raw, 0o700, dir_fd=parent.operation_fd.number)
        control.check()
        candidate = _directory(parent, CANDIDATE_NAME, control)
        candidate_key = candidate.generation.key
        for name, raw in contents:
            _create_file(candidate, name, raw, control)
        _verify_candidate(candidate, contents, control, True)
        control.check()
        os.fsync(candidate.operation_fd.number)
        control.check()
        _rename_noreplace(parent, control)
        installed = True
        control.check()
        os.fsync(parent.operation_fd.number)
        control.check()
        accepted = _directory(parent, ACCEPTED_NAME, control)
        try:
            _fail(accepted.generation.key == candidate_key)
            _verify_candidate(accepted, contents, control, True)
        finally:
            fs._close_node(accepted)
    except BaseException as caught:
        error = caught
    if candidate is not None and candidate.identity_fd.disposition == "open":
        try:
            fs._close_node(candidate)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    restored = os.umask(previous_umask)
    if restored != 0o077:
        error = fs.RootfsFsError(error, PublicationError())
    if error is not None and not installed and candidate_key is not None:
        try:
            _cleanup_candidate(parent, candidate_key, contents, _fresh_cleanup_control())
        except BaseException as cleanup_error:
            error = fs.RootfsFsError(error, cleanup_error)
    if error is not None:
        raise error
    return PublishedRootfs(pins.manifest_sha256, pins.manifest_size, pins.ustar_sha256, pins.ustar_size, pins.entry_count)

"""Strict rootfs pins and fixed fail-closed accepted-file publication."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True

import completion_rootfs_fs as fs

PINS_PATH = Path(__file__).with_name("stage2-completion-rootfs-v1.json")
MANIFEST_NAME = fs._name(b"rootfs.manifest.json")
USTAR_NAME = fs._name(b"rootfs.tar")
METADATA_NAME = fs._name(b"rootfs.metadata.json")
TEMP_NAMES = {
    MANIFEST_NAME.raw: fs._name(b".rootfs.manifest.json.tmp"),
    USTAR_NAME.raw: fs._name(b".rootfs.tar.tmp"),
    METADATA_NAME.raw: fs._name(b".rootfs.metadata.json.tmp"),
}
PINNED_RAW = b'''{
  "version": "cogs.stage2-completion-rootfs.v1",
  "source_date_epoch": 1782172800,
  "entry_count": 4353,
  "manifest": { "sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691", "size": 1049443 },
  "ustar": { "sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3", "size": 136905728 },
  "qualification": { "image": "python@sha256:53d6284a40eae6b625f22870f5faba6c54f2a28db9027408f4dee111f1e885a2" }
}
'''
PINNED_VALUE = {
    "version": "cogs.stage2-completion-rootfs.v1",
    "source_date_epoch": 1782172800,
    "entry_count": 4353,
    "manifest": {
        "sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
        "size": 1049443,
    },
    "ustar": {
        "sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
        "size": 136905728,
    },
    "qualification": {
        "image": "python@sha256:53d6284a40eae6b625f22870f5faba6c54f2a28db9027408f4dee111f1e885a2",
    },
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
    _reject_bool(value)
    _fail(raw == PINNED_RAW and value == PINNED_VALUE)
    return RootfsPins(
        raw,
        value["manifest"]["sha256"],
        value["manifest"]["size"],
        value["ustar"]["sha256"],
        value["ustar"]["size"],
        value["entry_count"],
    )


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


def _require_accepted(directory, control):
    _fail(type(directory) is fs.HeldNode and directory.operation_fd is not None)
    generation = fs._observe_node(directory.identity_fd, directory.operation_fd, control)
    _fail(generation.key.kind == "directory" and generation.uid == generation.gid == 0)
    _fail(generation.mode == 0o700 and generation.nlink >= 2)
    fs._require_empty_fd_xattrs(directory, control)
    _fail(not fs._enumerate_stable(directory, control).names)
    return generation


def _open_published(directory, name, expected, control):
    node = fs._open_path_node(directory, name, "file", control)
    generation = node.generation
    _fail(generation.uid == generation.gid == 0 and generation.mode == 0o400 and generation.nlink == 1)
    _fail(generation.key.mount_id == directory.generation.key.mount_id)
    _fail(generation.key.device == directory.generation.key.device and generation.size == len(expected))
    fs._require_empty_fd_xattrs(node, control)
    _fail(fs._read_regular(node, len(expected), control) == expected)
    return node


def _cleanup_temp(directory, name, identity, control):
    if identity is None:
        return
    try:
        current = fs._observe_child(directory, name, control)
    except FileNotFoundError:
        return
    _fail(current == identity)
    control.check()
    os.unlink(name.raw, dir_fd=directory.operation_fd.number)
    control.check()
    control.check()
    os.fsync(directory.operation_fd.number)
    control.check()


def _publish_file(directory, final_name, raw, control):
    temp_name = TEMP_NAMES[final_name.raw]
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | fs._O_NOFOLLOW | fs._O_CLOEXEC
    descriptor = None
    temp_node = None
    temp_identity = None
    final_created = False
    try:
        control.check()
        descriptor = fs.CheckedFd(
            os.open(temp_name.raw, flags, 0o400, dir_fd=directory.operation_fd.number),
            "publication-temp",
        )
        control.check()
        _write_all(descriptor, raw, control)
        control.check()
        os.fsync(descriptor.number)
        control.check()
        descriptor.close()
        descriptor = None
        temp_node = _open_published(directory, temp_name, raw, control)
        temp_identity = temp_node.generation
        fs._close_node(temp_node)
        temp_node = None
        control.check()
        os.link(
            temp_name.raw,
            final_name.raw,
            src_dir_fd=directory.operation_fd.number,
            dst_dir_fd=directory.operation_fd.number,
            follow_symlinks=False,
        )
        control.check()
        final_created = True
        linked_temp = fs._observe_child(directory, temp_name, control)
        linked_final = fs._observe_child(directory, final_name, control)
        _fail(linked_temp == linked_final and linked_temp.nlink == 2)
        temp_identity = linked_temp
        control.check()
        os.fsync(directory.operation_fd.number)
        control.check()
        _cleanup_temp(directory, temp_name, temp_identity, control)
        temp_identity = None
        final = _open_published(directory, final_name, raw, control)
        fs._close_node(final)
    except BaseException as error:
        if descriptor is not None and descriptor.disposition == "open":
            try:
                descriptor.close()
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if temp_node is not None and temp_node.identity_fd.disposition == "open":
            try:
                fs._close_node(temp_node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        if not final_created and temp_identity is not None:
            try:
                _cleanup_temp(directory, temp_name, temp_identity, control)
            except BaseException as cleanup_error:
                error = fs.RootfsFsError(error, cleanup_error)
        raise error


def _publish(directory, manifest, ustar, pins, control):
    _fail(type(manifest) is bytes and type(ustar) is bytes and type(pins) is RootfsPins)
    _fail(len(manifest) == pins.manifest_size and hashlib.sha256(manifest).hexdigest() == pins.manifest_sha256)
    _fail(len(ustar) == pins.ustar_size and hashlib.sha256(ustar).hexdigest() == pins.ustar_sha256)
    before = _require_accepted(directory, control)
    _publish_file(directory, MANIFEST_NAME, manifest, control)
    _publish_file(directory, USTAR_NAME, ustar, control)
    _publish_file(directory, METADATA_NAME, pins.raw, control)
    snapshot = fs._enumerate_stable(directory, control)
    expected = tuple(sorted((MANIFEST_NAME.raw, USTAR_NAME.raw, METADATA_NAME.raw)))
    _fail(snapshot.raw_names == expected and snapshot.generation.key == before.key)
    manifest_node = _open_published(directory, MANIFEST_NAME, manifest, control)
    ustar_node = _open_published(directory, USTAR_NAME, ustar, control)
    metadata_node = _open_published(directory, METADATA_NAME, pins.raw, control)
    fs._close_node(manifest_node)
    fs._close_node(ustar_node)
    fs._close_node(metadata_node)
    return PublishedRootfs(
        pins.manifest_sha256,
        pins.manifest_size,
        pins.ustar_sha256,
        pins.ustar_size,
        pins.entry_count,
    )

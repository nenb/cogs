"""Canonical logical manifest and direct streaming ustar for fixed ADR 0040 roots."""

from dataclasses import dataclass
import hashlib
import json
import os
import sys

sys.dont_write_bytecode = True

import completion_rootfs_fs as fs
import completion_rootfs_plan as plan

VERSION = "cogs.stage2-rootfs-canonical/v1"
BLOCK = 512


class CanonicalError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise CanonicalError()


@dataclass(frozen=True)
class CanonicalMetadata:
    manifest: bytes
    manifest_sha256: str
    ustar_sha256: str
    ustar_size: int
    entry_count: int


def _root_value(root):
    return {
        "kind": root.kind,
        "mode": root.mode,
        "uid": root.uid,
        "gid": root.gid,
        "mtime": root.mtime,
        "archive_size": root.archive_size,
    }


def _entry_value(entry):
    record = entry.record
    return {
        "path": record.path,
        "kind": record.kind,
        "mode": record.mode,
        "uid": record.uid,
        "gid": record.gid,
        "mtime": record.mtime,
        "archive_size": record.archive_size,
        "content_sha256": record.content_sha256,
        "link_text": record.link_text,
        "hardlink_target": record.hardlink_target,
    }


def _manifest(rootfs_plan):
    _fail(type(rootfs_plan) is plan.RootfsPlan)
    paths = tuple(entry.record.path for entry in rootfs_plan.entries)
    _fail(paths == tuple(sorted(paths, key=lambda value: value.encode("utf-8"))))
    _fail(len(paths) == len(set(paths)))
    value = {
        "version": VERSION,
        "root": _root_value(rootfs_plan.root),
        "entries": [_entry_value(entry) for entry in rootfs_plan.entries],
    }
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalError() from error
    _fail(json.loads(raw) == value)
    return raw


def _octal(value, width):
    _fail(type(value) is int and value >= 0)
    digits = format(value, "o").encode("ascii")
    _fail(len(digits) < width)
    return digits.rjust(width - 1, b"0") + b"\0"


def _tar_name(value):
    raw = value.encode("utf-8")
    _fail(raw and not raw.startswith(b"/") and len(raw) <= 255)
    if len(raw) <= 100:
        return raw, b""
    choices = [index for index, byte in enumerate(raw) if byte == 47 and index <= 155 and len(raw) - index - 1 <= 100]
    _fail(choices)
    split = choices[-1]
    return raw[split + 1 :], raw[:split]


def _header(name, record, typeflag, size, linkname=b""):
    name_field, prefix = _tar_name(name)
    _fail(type(linkname) is bytes and len(linkname) <= 100)
    header = bytearray(BLOCK)
    header[0 : len(name_field)] = name_field
    header[100:108] = _octal(record.mode, 8)
    header[108:116] = _octal(record.uid, 8)
    header[116:124] = _octal(record.gid, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(record.mtime, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[157 : 157 + len(linkname)] = linkname
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    _fail(checksum < 8**6)
    header[148:156] = format(checksum, "06o").encode("ascii") + b"\0 "
    return bytes(header)


def _open_file(root, path, control):
    parts = path.split("/")
    parent = root
    opened = []
    try:
        for part in parts[:-1]:
            node = fs._open_path_node(parent, fs._name(part), "directory", control)
            opened.append(node)
            parent = node
        node = fs._open_path_node(parent, fs._name(parts[-1]), "file", control)
        return node, tuple(opened)
    except BaseException as error:
        for node in reversed(opened):
            try:
                fs._close_node(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
        raise error


def _ordered_entries(rootfs_plan):
    directories = sorted(
        (entry for entry in rootfs_plan.entries if entry.record.kind == "directory"),
        key=lambda entry: (entry.record.path.count("/"), entry.record.path.encode("utf-8")),
    )
    files = sorted(
        (entry for entry in rootfs_plan.entries if entry.record.kind == "file"),
        key=lambda entry: entry.record.path.encode("utf-8"),
    )
    symlinks = sorted(
        (entry for entry in rootfs_plan.entries if entry.record.kind == "symlink"),
        key=lambda entry: entry.record.path.encode("utf-8"),
    )
    hardlinks = sorted(
        (entry for entry in rootfs_plan.entries if entry.record.kind == "hardlink"),
        key=lambda entry: entry.record.path.encode("utf-8"),
    )
    return tuple(directories + files + symlinks + hardlinks)


def _close_nodes(nodes, primary=None):
    error = primary
    for node in reversed(nodes):
        try:
            fs._close_node(node)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _write_ustar(root, rootfs_plan, descriptor, control):
    _fail(type(root) is fs.HeldNode and type(descriptor) is fs.CheckedFd)
    digest = hashlib.sha256()
    total = 0

    def emit(raw):
        nonlocal total
        offset = 0
        while offset < len(raw):
            control.check()
            count = os.write(descriptor.number, raw[offset:])
            control.check()
            _fail(type(count) is int and 0 < count <= len(raw) - offset)
            digest.update(raw[offset : offset + count])
            offset += count
            total += count

    emit(_header("./", rootfs_plan.root, b"5", 0))
    emitted = set()
    for entry in _ordered_entries(rootfs_plan):
        record = entry.record
        parent = record.path.rpartition("/")[0]
        _fail(not parent or parent in emitted)
        if record.kind == "directory":
            emit(_header(record.path + "/", record, b"5", 0))
        elif record.kind == "file":
            node, opened = _open_file(root, record.path, control)
            try:
                raw = fs._read_regular(node, record.archive_size, control)
                _fail(hashlib.sha256(raw).hexdigest() == record.content_sha256)
                emit(_header(record.path, record, b"0", len(raw)))
                for offset in range(0, len(raw), 1024 * 1024):
                    emit(raw[offset : offset + 1024 * 1024])
                if len(raw) % BLOCK:
                    emit(b"\0" * ((-len(raw)) % BLOCK))
            except BaseException as error:
                _close_nodes(opened + (node,), error)
            _close_nodes(opened + (node,))
        elif record.kind == "symlink":
            emit(_header(record.path, record, b"2", 0, os.fsencode(record.link_text)))
        else:
            _fail(record.kind == "hardlink" and record.hardlink_target in emitted)
            emit(_header(record.path, record, b"1", 0, record.hardlink_target.encode("utf-8")))
        emitted.add(record.path)
    _fail(len(emitted) == len(rootfs_plan.entries))
    emit(b"\0" * BLOCK * 2)
    _fail(total % BLOCK == 0)
    return digest.hexdigest(), total


def _canonical_metadata(root, authority, descriptor, control):
    _fail(type(authority) is plan.RootfsBuildInputs)
    manifest = _manifest(authority.plan)
    ustar_sha256, ustar_size = _write_ustar(root, authority.plan, descriptor, control)
    return CanonicalMetadata(
        manifest,
        hashlib.sha256(manifest).hexdigest(),
        ustar_sha256,
        ustar_size,
        len(authority.plan.entries),
    )

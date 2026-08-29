#!/usr/bin/env python3
"""Strict bounded canonical JSON and immutable controller-record publication.

This module has no command, provider, credential, inventory, or network surface.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import stat
from typing import Any

MAX_CANONICAL_BYTES = 262_144
MAX_DEPTH = 24
MAX_NODES = 8_192
MAX_ARRAY_ITEMS = 512
MAX_OBJECT_PROPERTIES = 128
MAX_STRING_BYTES = 16_384
MAX_KEY_BYTES = 256
MAX_DIRECTORY_ENTRIES = 512
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**64 - 1
RENAME_NOREPLACE = 1
_RECORD_NAME = re.compile(r"^[0-9]{6}-[A-Z][A-Z0-9_]*\.json$", re.ASCII)
_DOMAIN = re.compile(r"^cogs\.[a-z0-9][a-z0-9./_-]{0,126}/v[1-9][0-9]*$", re.ASCII)


class CampaignCodecError(ValueError):
    """The input is not an exact bounded canonical campaign value."""


class CampaignPublicationUncertain(CampaignCodecError):
    """Publication may have changed durable custody and must not be retried."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignCodecError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignCodecError("duplicate JSON key")
        result[key] = value
    return result


def _integer(text: str) -> int:
    value = int(text, 10)
    _require(MIN_INTEGER <= value <= MAX_INTEGER, "integer bound exceeded")
    return value


def _reject_constant(_text: str) -> None:
    raise CampaignCodecError("non-integer JSON number")


def _validate(value: Any) -> None:
    nodes = 0
    aggregate_string_bytes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, aggregate_string_bytes
        nodes += 1
        _require(nodes <= MAX_NODES, "node bound exceeded")
        _require(depth <= MAX_DEPTH, "depth bound exceeded")
        item_type = type(item)
        if item is None or item_type is bool:
            return
        if item_type is int:
            _require(MIN_INTEGER <= item <= MAX_INTEGER, "integer bound exceeded")
            return
        if item_type is str:
            try:
                size = len(item.encode("utf-8", "strict"))
            except UnicodeEncodeError as error:
                raise CampaignCodecError("invalid Unicode scalar value") from error
            _require(size <= MAX_STRING_BYTES, "string bound exceeded")
            aggregate_string_bytes += size
            _require(aggregate_string_bytes <= MAX_CANONICAL_BYTES, "aggregate string bound exceeded")
            return
        if item_type is list:
            _require(len(item) <= MAX_ARRAY_ITEMS, "array bound exceeded")
            for child in item:
                visit(child, depth + 1)
            return
        _require(item_type is dict, "non-plain JSON value")
        _require(len(item) <= MAX_OBJECT_PROPERTIES, "property bound exceeded")
        for key, child in item.items():
            _require(type(key) is str, "non-string property key")
            try:
                key_size = len(key.encode("utf-8", "strict"))
            except UnicodeEncodeError as error:
                raise CampaignCodecError("invalid property key") from error
            _require(key_size <= MAX_KEY_BYTES, "property-key bound exceeded")
            aggregate_string_bytes += key_size
            _require(aggregate_string_bytes <= MAX_CANONICAL_BYTES, "aggregate string bound exceeded")
            visit(child, depth + 1)

    visit(value, 0)


def canonical_bytes(value: Any) -> bytes:
    """Return strict UTF-8 canonical JSON with code-point key order and one LF."""
    _validate(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        raw = text.encode("utf-8", "strict") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CampaignCodecError("canonical JSON encoding failed") from error
    _require(len(raw) <= MAX_CANONICAL_BYTES, "canonical byte bound exceeded")
    return raw


def load_canonical_bytes(raw: bytes) -> Any:
    """Parse only exact canonical bytes; duplicate keys and trailing data fail."""
    _require(type(raw) is bytes, "input must be exact bytes")
    _require(0 < len(raw) <= MAX_CANONICAL_BYTES, "input byte bound exceeded")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CampaignCodecError("input is not strict UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_reject_constant,
            parse_constant=_reject_constant,
        )
    except CampaignCodecError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise CampaignCodecError("invalid JSON document") from error
    _validate(value)
    _require(canonical_bytes(value) == raw, "input is not canonical")
    return value


def sha256_hex(raw: bytes) -> str:
    _require(type(raw) is bytes, "digest input must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def commitment_sha256(domain: str, value: Any, salt: bytes) -> str:
    """Commit to a canonical value under an exact domain and private 256-bit salt."""
    _require(type(domain) is str and _DOMAIN.fullmatch(domain) is not None, "invalid commitment domain")
    _require(type(salt) is bytes and len(salt) == 32, "commitment salt must be 32 bytes")
    domain_raw = domain.encode("ascii")
    payload = canonical_bytes(value)
    digest = hashlib.sha256()
    digest.update(b"cogs.campaign-private-commitment/v1\0")
    digest.update(len(domain_raw).to_bytes(2, "big"))
    digest.update(domain_raw)
    digest.update(salt)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        stat.S_IMODE(left.st_mode),
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        stat.S_IMODE(right.st_mode),
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _check_directory(parent_fd: int, owner_uid: int) -> os.stat_result:
    _require(type(parent_fd) is int and parent_fd >= 0, "invalid held directory descriptor")
    _require(type(owner_uid) is int and owner_uid >= 0, "invalid expected owner")
    observed = os.fstat(parent_fd)
    _require(stat.S_ISDIR(observed.st_mode), "held descriptor is not a directory")
    _require(stat.S_IMODE(observed.st_mode) == 0o700, "custody directory mode mismatch")
    _require(observed.st_uid == owner_uid, "custody directory owner mismatch")
    return observed


def _check_name(name: str, record: bool = False) -> None:
    _require(type(name) is str and name not in {"", ".", ".."}, "invalid custody name")
    _require("/" not in name and "\x00" not in name and len(os.fsencode(name)) <= 255, "unsafe custody name")
    if record:
        _require(_RECORD_NAME.fullmatch(name) is not None, "invalid sequence record name")


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    _require(len(raw) <= maximum, "file byte bound exceeded")
    return raw


def load_canonical_file_at(
    parent_fd: int,
    name: str,
    *,
    owner_uid: int | None = None,
    mode: int = 0o400,
) -> Any:
    """Read one exact-owned, single-link, no-follow canonical record fd-relatively."""
    expected_uid = os.geteuid() if owner_uid is None else owner_uid
    _check_directory(parent_fd, expected_uid)
    _check_name(name)
    _require(type(mode) is int and mode == 0o400, "record mode must be 0400")
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require(stat.S_ISREG(before.st_mode), "record is not regular")
    _require(stat.S_IMODE(before.st_mode) == mode, "record mode mismatch")
    _require(before.st_uid == expected_uid, "record owner mismatch")
    _require(before.st_nlink == 1, "record hardlink rejected")
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require(_same_identity(before, opened) and _same_identity(opened, current), "record identity changed")
        raw = _read_all(descriptor, MAX_CANONICAL_BYTES)
        after = os.fstat(descriptor)
        current_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require(
            _same_identity(opened, after) and _same_identity(after, current_after),
            "record mutated or was replaced while read",
        )
    finally:
        os.close(descriptor)
    return load_canonical_bytes(raw)


def _check_staging_set(parent_fd: int, allowed: str | None = None) -> None:
    try:
        names = os.listdir(parent_fd)
    except OSError as error:
        raise CampaignPublicationUncertain("custody directory enumeration failed") from error
    if len(names) > MAX_DIRECTORY_ENTRIES:
        raise CampaignPublicationUncertain("custody directory entry bound exceeded")
    staging = {name for name in names if name.startswith(".staging-")}
    expected = set() if allowed is None else {allowed}
    if staging != expected:
        raise CampaignPublicationUncertain("stale or competing staging record")


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if type(written) is not int or written <= 0:
            raise CampaignPublicationUncertain("short record write")
        view = view[written:]


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    if platform.system() != "Linux":
        raise CampaignPublicationUncertain("Linux renameat2 is required")
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise CampaignPublicationUncertain("Linux renameat2 is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise CampaignPublicationUncertain("record destination already exists")
        raise CampaignPublicationUncertain("record no-replace publication failed")


def publish_record_at(
    parent_fd: int,
    final_name: str,
    value: Any,
    *,
    owner_uid: int | None = None,
) -> str:
    """Durably publish one immutable record; failed staging objects are preserved."""
    expected_uid = os.geteuid() if owner_uid is None else owner_uid
    _check_directory(parent_fd, expected_uid)
    _check_name(final_name, record=True)
    _require(type(value) is dict, "published record must be a plain object")
    sequence = value.get("sequence")
    event = value.get("event")
    _require(type(sequence) is int and type(event) is str, "published record identity missing")
    _require(final_name == f"{sequence:06d}-{event}.json", "record name does not bind sequence and event")
    raw = canonical_bytes(value)
    _check_staging_set(parent_fd)
    staging = f".staging-{secrets.token_hex(16)}"
    _check_name(staging)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(staging, flags, 0o400, dir_fd=parent_fd)
    except OSError as error:
        raise CampaignPublicationUncertain("staging create failed") from error
    try:
        opened = os.fstat(descriptor)
        if not (
            stat.S_ISREG(opened.st_mode)
            and stat.S_IMODE(opened.st_mode) == 0o400
            and opened.st_uid == expected_uid
            and opened.st_nlink == 1
        ):
            raise CampaignPublicationUncertain("staging identity mismatch")
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    except BaseException as error:
        if isinstance(error, CampaignPublicationUncertain):
            raise
        raise CampaignPublicationUncertain("staging write or fsync failed") from error
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            raise CampaignPublicationUncertain("staging close failed") from error
    _check_staging_set(parent_fd, staging)
    _rename_noreplace(parent_fd, staging, final_name)
    try:
        os.fsync(parent_fd)
    except OSError as error:
        raise CampaignPublicationUncertain("parent fsync failed after publication") from error
    return sha256_hex(raw)

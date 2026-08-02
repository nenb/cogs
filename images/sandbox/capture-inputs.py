#!/usr/bin/python3
"""Capture fixed sandbox inputs through retained no-follow descriptors."""

import os
import stat
import sys

INPUTS = (
    ("ssh_host_ed25519_key", 0o400, 64, 16_384),
    ("ssh_host_ed25519_key.pub", 0o444, 80, 1_024),
    ("client_ed25519_key.pub", 0o444, 80, 1_024),
    ("egress-ca.crt", 0o444, 256, 65_536),
    ("proxy-capability", 0o400, 32, 128),
)
MAX_DIRECTORY_PATH_BYTES = 4_096


def fail() -> "NoReturn":
    raise RuntimeError("capture failed")


def directory(path: str, expected_mode: int) -> int:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        fail()
    if len(os.fsencode(path)) > MAX_DIRECTORY_PATH_BYTES:
        fail()
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        os.close(descriptor)
        fail()
    return descriptor


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def capture(source_root: int, name: str, expected_mode: int, minimum: int, maximum: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_root)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_nlink != 1
            or before.st_size < minimum
            or before.st_size > maximum
        ):
            fail()
        output = bytearray()
        while len(output) < before.st_size:
            chunk = os.read(descriptor, min(16_384, before.st_size - len(output)))
            if not chunk:
                fail()
            output.extend(chunk)
        if os.read(descriptor, 1):
            fail()
        after = os.fstat(descriptor)
        if identity(before) != identity(after) or len(output) != before.st_size:
            fail()
        return bytes(output)
    finally:
        os.close(descriptor)


def write_private(output_root: int, name: str, content: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=output_root,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written < 1:
                fail()
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(content)
        ):
            fail()
    finally:
        os.close(descriptor)


def main() -> None:
    if len(sys.argv) != 3:
        fail()
    source_root = directory(sys.argv[1], 0o500)
    output_root = directory(sys.argv[2], 0o700)
    source_identity = identity(os.fstat(source_root))
    captured: list[tuple[str, bytes]] = []
    try:
        for specification in INPUTS:
            name, expected_mode, minimum, maximum = specification
            captured.append((name, capture(source_root, name, expected_mode, minimum, maximum)))
        if identity(os.fstat(source_root)) != source_identity:
            fail()
        for name, content in captured:
            write_private(output_root, name, content)
        os.fsync(output_root)
    finally:
        for _, content in captured:
            # Immutable bytes cannot be wiped in place; drop all references before exit.
            del content
        os.close(output_root)
        os.close(source_root)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(1)

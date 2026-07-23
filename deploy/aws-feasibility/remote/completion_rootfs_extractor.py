"""Closed R2.1a preparation for the one fixed dpkg-deb extractor."""

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import unicodedata

sys.dont_write_bytecode = True

from completion_rootfs_plan import _load_verifier

PIN_PATH = Path(__file__).with_name("stage2-completion-rootfs-platform-v1.json")
IMAGE_ATTESTATION = Path("/run/cogs-stage2-rootfs-platform.sha256")
PIN_VERSION = "cogs.stage2-completion-rootfs-platform/v1"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_TOOL_BYTES = 128 * 1024 * 1024
SENTINEL_DIGESTS = frozenset(
    {hashlib.sha256(value).hexdigest() for value in (b"", b"UNRESOLVED", b"PLACEHOLDER")}
)
EXPECTED_TOOLS = (
    ("python3", "python3"),
    ("dpkg-deb", "dpkg-deb"),
    ("helper", "tar"),
    ("helper", "xz"),
)
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0x0001)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
ALL_SEALS = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL


class ExtractorPreparationError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise ExtractorPreparationError()


@dataclass(frozen=True)
class ToolPin:
    role: str
    name: str
    path: str
    mode: int
    size: int
    sha256: str
    version_sha256: str


@dataclass(frozen=True)
class PlatformPin:
    # The image digest, not executable hashes alone, externally binds the
    # dynamic loader and shared-library closure used by a later real probe.
    image_sha256: str
    helper_resolution_sha256: str
    tools: tuple[ToolPin, ...]


@dataclass(frozen=True)
class PrivateLayout:
    operation_fd: int
    stage_fd: int
    helper_fd: int
    home_fd: int
    temporary_fd: int
    cwd_fd: int
    helper_names: tuple[str, ...]


@dataclass(frozen=True)
class DpkgValues:
    dpkg_fd: int
    package_fd: int
    layout: PrivateLayout

    def executable(self):
        return f"/proc/self/fd/{self.dpkg_fd}"

    def argv(self):
        return (
            "/usr/bin/dpkg-deb",
            "-x",
            f"/proc/self/fd/{self.package_fd}",
            f"/proc/self/fd/{self.layout.stage_fd}",
        )

    def environment(self):
        return {
            "PATH": f"/proc/self/fd/{self.layout.helper_fd}",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": f"/proc/self/fd/{self.layout.home_fd}",
            "TMPDIR": f"/proc/self/fd/{self.layout.temporary_fd}",
        }

    def inherited_fds(self):
        return (
            self.dpkg_fd,
            self.package_fd,
            self.layout.stage_fd,
            self.layout.helper_fd,
            self.layout.home_fd,
            self.layout.temporary_fd,
            self.layout.cwd_fd,
        )


def _valid_digest(value):
    return type(value) is str and SHA256.fullmatch(value) is not None and len(set(value)) > 1 and value not in SENTINEL_DIGESTS


def _valid_tool_path(role, value):
    _fail(type(value) is str and unicodedata.normalize("NFC", value) == value)
    _fail("\\" not in value and all(ord(character) >= 32 and not unicodedata.category(character).startswith("C") for character in value))
    parts = value.split("/")
    _fail(parts[0] == "" and all(part not in {"", ".", ".."} for part in parts[1:]))
    if role == "python3":
        return re.fullmatch(r"/usr/bin/python3\.[0-9]{1,2}", value) is not None
    expected = {"dpkg-deb": "/usr/bin/dpkg-deb", "tar": "/usr/bin/tar", "xz": "/usr/bin/xz"}
    return value == expected[role]


def parse_platform_pin(raw):
    try:
        value = _load_verifier().strict_json(raw, 32768)
    except Exception as error:
        raise ExtractorPreparationError() from error
    _fail(type(value) is dict)
    _fail(tuple(value) == ("version", "image_sha256", "helper_resolution_sha256", "tools"))
    _fail(raw == (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
    _fail(value["version"] == PIN_VERSION)
    _fail(_valid_digest(value["image_sha256"]))
    _fail(_valid_digest(value["helper_resolution_sha256"]))
    _fail(type(value["tools"]) is list and len(value["tools"]) == len(EXPECTED_TOOLS))
    fields = ("role", "name", "path", "mode", "size", "sha256", "version_sha256")
    tools = []
    for row, expected in zip(value["tools"], EXPECTED_TOOLS, strict=True):
        _fail(type(row) is dict and tuple(row) == fields)
        _fail((row["role"], row["name"]) == expected)
        _fail(_valid_tool_path(row["name"], row["path"]))
        _fail(type(row["mode"]) is int and row["mode"] in {0o555, 0o755})
        _fail(type(row["size"]) is int and 0 < row["size"] <= MAX_TOOL_BYTES)
        _fail(_valid_digest(row["sha256"]) and _valid_digest(row["version_sha256"]))
        tools.append(ToolPin(*(row[field] for field in fields)))
    return PlatformPin(value["image_sha256"], value["helper_resolution_sha256"], tuple(tools))


def load_platform_pin():
    verifier = _load_verifier()
    raw = verifier.read_stable_regular(PIN_PATH, 0o644, 32768)
    return parse_platform_pin(raw)


def _open_tool(verifier, tool):
    before = os.lstat(tool.path)
    descriptor = os.open(tool.path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        _fail(verifier.identity(current) == verifier.identity(before))
        _fail(stat.S_ISREG(current.st_mode))
        _fail(current.st_uid == 0 and current.st_nlink == 1)
        _fail(stat.S_IMODE(current.st_mode) == tool.mode and current.st_size == tool.size)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        final = os.fstat(descriptor)
        after = os.lstat(tool.path)
        _fail(verifier.identity(final) == verifier.identity(current))
        _fail(verifier.identity(after) == verifier.identity(current))
        _fail(digest.hexdigest() == tool.sha256)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_platform_tools(pin):
    _fail(sys.platform == "linux")
    _fail(platform.machine() in {"x86_64", "amd64"})
    _fail(os.geteuid() == 0)
    verifier = _load_verifier()
    attestation = verifier.read_stable_regular(IMAGE_ATTESTATION, 0o400, 65)
    _fail(attestation == f"{pin.image_sha256}\n".encode())
    opened = []
    try:
        for tool in pin.tools:
            opened.append((tool, _open_tool(verifier, tool)))
        return tuple(opened)
    except Exception:
        close_platform_tools(opened)
        raise


def close_platform_tools(opened):
    for _tool, descriptor in opened:
        os.close(descriptor)


def _remove_failed_helper(directory_fd, name, created):
    try:
        current = os.lstat(name, dir_fd=directory_fd)
        identity = (current.st_dev, current.st_ino, current.st_uid, current.st_nlink)
        _fail(stat.S_ISREG(current.st_mode) and identity == created)
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception as cleanup_error:
        raise ExtractorPreparationError("helper cleanup uncertain") from cleanup_error


def copy_helper(source_fd, directory_fd, pin):
    _fail(pin.role == "helper" and "/" not in pin.name)
    verifier = _load_verifier()
    before = os.fstat(source_fd)
    _fail(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1)
    _fail(stat.S_IMODE(before.st_mode) == pin.mode and before.st_size == pin.size)
    target = os.open(
        pin.name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o500,
        dir_fd=directory_fd,
    )
    total = 0
    created = None
    try:
        created_state = os.fstat(target)
        _fail(stat.S_ISREG(created_state.st_mode))
        created = (created_state.st_dev, created_state.st_ino, created_state.st_uid, created_state.st_nlink)
        while total < pin.size:
            chunk = os.pread(source_fd, min(1024 * 1024, pin.size - total), total)
            _fail(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(target, chunk[offset:])
                _fail(written > 0)
                offset += written
            total += len(chunk)
        os.fchown(target, 0, 0)
        os.fchmod(target, pin.mode)
        os.fsync(target)
        target_before = os.fstat(target)
        _fail(stat.S_ISREG(target_before.st_mode) and target_before.st_nlink == 1)
        _fail(target_before.st_uid == target_before.st_gid == 0 and target_before.st_size == pin.size)
        _fail(stat.S_IMODE(target_before.st_mode) == pin.mode)
        digest = hashlib.sha256()
        offset = 0
        while offset < pin.size:
            chunk = os.pread(target, min(1024 * 1024, pin.size - offset), offset)
            _fail(chunk)
            digest.update(chunk)
            offset += len(chunk)
        target_after = os.fstat(target)
        _fail(verifier.identity(target_after) == verifier.identity(target_before))
        _fail(digest.hexdigest() == pin.sha256)
        os.close(target)
        target = None
        os.fsync(directory_fd)
        _fail(verifier.identity(os.fstat(source_fd)) == verifier.identity(before))
    except Exception:
        if target is not None:
            try:
                os.close(target)
            except Exception as cleanup_error:
                raise ExtractorPreparationError("helper cleanup uncertain") from cleanup_error
        _remove_failed_helper(directory_fd, pin.name, created)
        raise


def _directory_identity(descriptor):
    value = os.fstat(descriptor)
    _fail(stat.S_ISDIR(value.st_mode))
    _fail(value.st_uid == value.st_gid == 0)
    _fail(stat.S_IMODE(value.st_mode) == 0o700)
    return (value.st_dev, value.st_ino)


def validate_private_layout(layout):
    operation = _directory_identity(layout.operation_fd)
    child_fds = (layout.stage_fd, layout.helper_fd, layout.home_fd, layout.temporary_fd, layout.cwd_fd)
    identities = []
    for descriptor in child_fds:
        identities.append(_directory_identity(descriptor))
        parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            _fail(_directory_identity(parent) == operation)
        finally:
            os.close(parent)
    _fail(len(set(identities)) == len(identities))
    for descriptor in (layout.stage_fd, layout.home_fd, layout.temporary_fd, layout.cwd_fd):
        _fail(os.listdir(descriptor) == [])
    _fail(tuple(sorted(os.listdir(layout.helper_fd))) == tuple(sorted(layout.helper_names)))


def sealed_package(raw, expected_sha256):
    _fail(type(raw) is bytes)
    _fail(hashlib.sha256(raw).hexdigest() == expected_sha256)
    _fail(hasattr(os, "memfd_create"))
    descriptor = os.memfd_create("cogs-stage2-package", MFD_ALLOW_SEALING | MFD_CLOEXEC)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            _fail(written > 0)
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        _fail(os.fstat(descriptor).st_size == len(raw))
        _fail(digest.hexdigest() == expected_sha256)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, F_ADD_SEALS, ALL_SEALS)
        _fail(fcntl.fcntl(descriptor, F_GET_SEALS) == ALL_SEALS)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise

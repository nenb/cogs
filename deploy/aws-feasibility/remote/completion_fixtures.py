"""Pure deterministic source models for the fixed Stage 2 completion fixtures."""

from dataclasses import dataclass
import hashlib
import json
import struct

SOURCE_EPOCH = 1782172800
DIRECTORY_MODE = 0o755
REGULAR_MODE = 0o644
GIT_VERSION = "cogs-stage2-git-v1"
PACKAGE_VERSION = "cogs-stage2-package-v1"
TREE_VERSION = "cogs.stage2-logical-tree/v1"
PACKAGE_NAME = "cogs-stage2-fixture"
PACKAGE_RELEASE = "1.0"
PACKAGE_ARCHITECTURE = "all"
PACKAGE_CONTROL = (
    b"Package: cogs-stage2-fixture\n"
    b"Version: 1.0\n"
    b"Architecture: all\n"
    b"Maintainer: Cogs Stage 2 <cogs-stage2>\n"
    b"Description: Deterministic Cogs Stage 2 fixture\n"
)
_BLOCK = 512
_ZERO_BLOCKS = b"\0" * (_BLOCK * 2)


class FixtureError(Exception):
    """A fixed fixture invariant was violated."""


def _require(condition):
    if not condition:
        raise FixtureError()


@dataclass(frozen=True)
class TreeRecord:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    content_sha256: str | None
    content: bytes | None


@dataclass(frozen=True)
class TreeArtifact:
    records: tuple[TreeRecord, ...]
    logical_digest: str
    ustar: bytes
    ustar_sha256: str


@dataclass(frozen=True)
class Mutation:
    path: str
    operation: str
    payload: bytes
    payload_sha256: str
    result_sha256: str


@dataclass(frozen=True)
class GitFixture:
    source: TreeArtifact
    blob_oids: tuple[str, ...]
    nested_tree_oid: str
    root_tree_oid: str
    commit_oid: str
    commit: bytes
    branch: str
    mutations: tuple[Mutation, ...]
    porcelain_rows: tuple[bytes, ...]
    porcelain: bytes
    logical_digest: str


@dataclass(frozen=True)
class InstalledPayload:
    records: tuple[TreeRecord, ...]
    logical_digest: str
    entry_count: int
    regular_bytes: int
    package: str
    version: str
    architecture: str
    status: str


@dataclass(frozen=True)
class PackageFixture:
    source: TreeArtifact
    control: bytes
    installed: InstalledPayload


@dataclass(frozen=True)
class CompletionFixtures:
    git: GitFixture
    package: PackageFixture


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _directory(path):
    return TreeRecord(path, "directory", DIRECTORY_MODE, 0, 0, SOURCE_EPOCH, 0, None, None)


def _file(path, content):
    _require(type(content) is bytes)
    return TreeRecord(path, "file", REGULAR_MODE, 0, 0, SOURCE_EPOCH, len(content), _sha256(content), content)


def _canonical_line(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise FixtureError() from error


def _record_value(record):
    return {
        "version": TREE_VERSION,
        "path": record.path,
        "kind": record.kind,
        "mode": record.mode,
        "uid": record.uid,
        "gid": record.gid,
        "mtime": record.mtime,
        "size": record.size,
        "regular_sha256": record.content_sha256,
    }


def _validate_records(records):
    _require(type(records) is tuple and records and records[0] == _directory("."))
    paths = tuple(record.path for record in records[1:])
    _require(paths == tuple(sorted(paths, key=lambda value: value.encode("utf-8"))) and len(paths) == len(set(paths)))
    known = {"."}
    for record in records[1:]:
        raw_path = record.path.encode("utf-8")
        _require(raw_path and not raw_path.startswith(b"/") and b"//" not in raw_path and all(32 <= byte <= 126 for byte in raw_path))
        _require(all(part not in (b"", b".", b"..") for part in raw_path.split(b"/")))
        parent = record.path.rpartition("/")[0] or "."
        _require(parent in known and record.uid == record.gid == 0 and record.mtime == SOURCE_EPOCH)
        if record.kind == "directory":
            _require(record == _directory(record.path))
        else:
            _require(record.kind == "file" and record.mode == REGULAR_MODE and type(record.content) is bytes)
            _require(record.size == len(record.content) and record.content_sha256 == _sha256(record.content))
        known.add(record.path)


def _tree_stream(records):
    _validate_records(records)
    return b"".join(_canonical_line(_record_value(record)) for record in records)


def _tree_digest(records):
    return _sha256(_tree_stream(records))


def _octal(value, width):
    _require(type(value) is int and value >= 0)
    digits = format(value, "o").encode("ascii")
    _require(len(digits) < width)
    return digits.rjust(width - 1, b"0") + b"\0"


def _tar_name(path):
    raw = path.encode("utf-8")
    _require(raw and len(raw) <= 255)
    if len(raw) <= 100:
        return raw, b""
    choices = tuple(index for index, byte in enumerate(raw) if byte == 47 and index <= 155 and len(raw) - index - 1 <= 100)
    _require(choices)
    split = choices[-1]
    return raw[split + 1 :], raw[:split]


def _header(path, record, typeflag, size):
    name, prefix = _tar_name(path)
    header = bytearray(_BLOCK)
    header[: len(name)] = name
    header[100:108] = _octal(record.mode, 8)
    header[108:116] = _octal(record.uid, 8)
    header[116:124] = _octal(record.gid, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(record.mtime, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    _require(checksum < 8**6)
    header[148:156] = format(checksum, "06o").encode("ascii") + b"\0 "
    return bytes(header)


def _ustar(records):
    _validate_records(records)
    output = bytearray()
    for record in records:
        name = "./" if record.path == "." else record.path
        if record.kind == "directory":
            if record.path != ".":
                name += "/"
            output.extend(_header(name, record, b"5", 0))
        else:
            output.extend(_header(name, record, b"0", record.size))
            output.extend(record.content)
            output.extend(b"\0" * (-record.size % _BLOCK))
    output.extend(_ZERO_BLOCKS)
    _require(len(output) % _BLOCK == 0)
    return bytes(output)


def _artifact(records):
    stream_digest = _tree_digest(records)
    archive = _ustar(records)
    return TreeArtifact(records, stream_digest, archive, _sha256(archive))


def _seed(version, first, second):
    _require(0 <= first < 65536 and 0 <= second < 65536)
    return version.encode("ascii") + b"\0" + struct.pack(">HH", first, second)


def _git_oid(kind, content):
    raw = kind.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content
    return hashlib.sha1(raw, usedforsecurity=False).hexdigest()


def _git_fixture():
    files = []
    blob_oids = []
    for index in range(512):
        content = b"".join(hashlib.sha256(_seed(GIT_VERSION, index, line)).hexdigest().encode("ascii") + b"\n" for line in range(128))
        files.append(_file(f"files/file-{index:04d}.txt", content))
        blob_oids.append(_git_oid("blob", content))
    records = (_directory("."), _directory("files"), *files)
    source = _artifact(records)
    nested = b"".join(b"100644 file-" + f"{index:04d}".encode("ascii") + b".txt\0" + bytes.fromhex(oid) for index, oid in enumerate(blob_oids))
    nested_oid = _git_oid("tree", nested)
    root = b"40000 files\0" + bytes.fromhex(nested_oid)
    root_oid = _git_oid("tree", root)
    identity = b"Cogs Stage 2 <cogs-stage2> 1782172800 +0000"
    commit = b"tree " + root_oid.encode("ascii") + b"\nauthor " + identity + b"\ncommitter " + identity + b"\n\ncogs stage2 fixture v1\n"
    commit_oid = _git_oid("commit", commit)
    mutations = []
    append_payload = b"cogs-stage2-git-v1 modified\n"
    for index in range(32):
        result = files[index].content + append_payload
        mutations.append(Mutation(files[index].path, "append", append_payload, _sha256(append_payload), _sha256(result)))
    for index in range(8):
        payload = hashlib.sha256(_seed(GIT_VERSION, 512, index)).hexdigest().encode("ascii") + b"\n"
        path = f"untracked/file-{index:04d}.txt"
        mutations.append(Mutation(path, "create", payload, _sha256(payload), _sha256(payload)))
    rows = tuple([f" M files/file-{index:04d}.txt".encode("ascii") for index in range(32)] + [f"?? untracked/file-{index:04d}.txt".encode("ascii") for index in range(8)])
    metadata = {
        "version": GIT_VERSION, "file_count": 512, "lines_per_file": 128,
        "branch": "refs/heads/main", "nested_tree_oid": nested_oid, "root_tree_oid": root_oid,
        "commit_oid": commit_oid, "commit": commit.decode("ascii"), "modified_count": 32, "untracked_count": 8,
    }
    logical = bytearray(_canonical_line(metadata))
    logical.extend(_tree_stream(records))
    for mutation in mutations:
        logical.extend(
            _canonical_line(
                {
                    "operation": mutation.operation,
                    "path": mutation.path,
                    "payload_sha256": mutation.payload_sha256,
                    "result_sha256": mutation.result_sha256,
                }
            )
        )
    _require(len(files) == 512 and all(record.size == 128 * 65 for record in files))
    _require(len(mutations) == len(rows) == 40 and len(set(rows)) == 40)
    return GitFixture(source, tuple(blob_oids), nested_oid, root_oid, commit_oid, commit, "refs/heads/main", tuple(mutations), rows, b"\n".join(rows) + b"\n", _sha256(bytes(logical)))


def _package_fixture():
    payloads = []
    for index in range(256):
        content = b"".join(hashlib.sha256(_seed(PACKAGE_VERSION, index, block)).digest() for block in range(128))
        payloads.append(_file(f"usr/share/{PACKAGE_NAME}/payload-{index:04d}.bin", content))
    directories = (_directory("."), _directory("DEBIAN"), _directory("usr"), _directory("usr/share"), _directory(f"usr/share/{PACKAGE_NAME}"))
    source_records = tuple(sorted((*directories, _file("DEBIAN/control", PACKAGE_CONTROL), *payloads), key=lambda record: (record.path != ".", record.path.encode("utf-8"))))
    source = _artifact(source_records)
    installed_records = (_directory("."), _directory("usr"), _directory("usr/share"), _directory(f"usr/share/{PACKAGE_NAME}"), *payloads)
    _validate_records(installed_records)
    installed = InstalledPayload(installed_records, _tree_digest(installed_records), len(installed_records) - 1, sum(record.size for record in payloads), PACKAGE_NAME, PACKAGE_RELEASE, PACKAGE_ARCHITECTURE, "install ok installed")
    _require(len(payloads) == 256 and all(record.size == 4096 for record in payloads))
    _require(installed.entry_count == 259 and installed.regular_bytes == 1048576)
    return PackageFixture(source, PACKAGE_CONTROL, installed)


def fixed_fixtures():
    """Build the one fixed fixture model; no dimensions or paths are caller-controlled."""
    result = CompletionFixtures(_git_fixture(), _package_fixture())
    _require(result.git.source.records[0] == result.package.source.records[0])
    return result

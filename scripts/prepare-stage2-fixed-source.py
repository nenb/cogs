#!/usr/bin/env python3
"""Materialize one checked Git HEAD into the fixed Stage 2 source root."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata

sys.dont_write_bytecode = True

REPOSITORY = Path(__file__).resolve().parents[1]
REMOTE = REPOSITORY / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_rootfs_fs as fs

FIXED_DESTINATION = "/var/lib/cogs/stage2-completion-v1/source"
FIXED_COMPONENTS = (b"var", b"lib", b"cogs", b"stage2-completion-v1", b"source")
GIT = "/usr/bin/git"
MAX_PROCESS_OUTPUT = 32 * 1024 * 1024
MAX_COMMIT_BYTES = 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REACHABLE_OBJECTS = 20_000
MAX_ENTRIES = fs.MAX_SOURCE_ENTRIES
AGGREGATE_SECONDS = 120
RESULT_VERSION = "cogs.stage2-fixed-source-preparation/v1"
HEX = frozenset("0123456789abcdef")

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC


class PrepareError(Exception):
    """The fixed source could not be established without ambiguity."""


def _fail(condition):
    if not condition:
        raise PrepareError()


@dataclass(frozen=True)
class Blob:
    path: str
    mode: int
    oid: str
    size: int
    sha256: str
    content: bytes


@dataclass(frozen=True)
class Plan:
    revision: str
    directories: tuple[str, ...]
    blobs: tuple[Blob, ...]


@dataclass(frozen=True)
class Preparation:
    revision: str
    manifest_sha256: str
    entries: int


@dataclass(frozen=True)
class GitLayout:
    repository: str
    gitdir: str
    common: str
    objects: str


@dataclass(frozen=True)
class WorktreeSnapshot:
    entries: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True)
class CheckedCheckout:
    layout: GitLayout
    plan: Plan
    snapshot: WorktreeSnapshot


@dataclass(frozen=True)
class PendingMaterialization:
    plan: Plan
    approval: fs.SourceApproval
    source_identity: os.stat_result
    directory_identities: tuple[tuple[str, os.stat_result], ...]


@dataclass(frozen=True)
class Deadline:
    end_ns: int

    def remaining(self):
        value = (self.end_ns - time.monotonic_ns()) / 1_000_000_000
        _fail(value > 0)
        return value


def _checked_platform():
    _fail(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() == 0)
    _fail(sys.getfilesystemencoding() == "utf-8" and sys.getfilesystemencodeerrors() == "surrogateescape")


def _checked_test_platform():
    _fail(platform.system() == "Linux" and os.geteuid() == 0)
    _fail(platform.machine() in {"x86_64", "aarch64", "arm64"})
    _fail(sys.getfilesystemencoding() == "utf-8" and sys.getfilesystemencodeerrors() == "surrogateescape")


def _deadline(seconds=AGGREGATE_SECONDS):
    _fail(type(seconds) in {int, float} and 0 < seconds <= AGGREGATE_SECONDS)
    return Deadline(time.monotonic_ns() + int(seconds * 1_000_000_000))


def _read_small(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _fail(stat.S_ISREG(before.st_mode) and before.st_size <= maximum)
        chunks = []
        total = 0
        while total <= maximum:
            part = os.read(descriptor, min(4096, maximum + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
            _fail(total <= maximum)
        _fail(os.fstat(descriptor).st_ino == before.st_ino and os.fstat(descriptor).st_dev == before.st_dev)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _directory_path(path):
    observed = os.stat(path, follow_symlinks=False)
    _fail(stat.S_ISDIR(observed.st_mode))
    descriptor = os.open(path, _DIRECTORY_FLAGS)
    try:
        current = os.fstat(descriptor)
        _fail((current.st_dev, current.st_ino) == (observed.st_dev, observed.st_ino))
    finally:
        os.close(descriptor)
    return os.path.realpath(path)


def _git_layout(repository):
    repository = os.path.realpath(os.fspath(repository))
    _fail(os.path.isabs(repository))
    dotgit = os.path.join(repository, ".git")
    observed = os.stat(dotgit, follow_symlinks=False)
    if stat.S_ISDIR(observed.st_mode):
        gitdir = _directory_path(dotgit)
    else:
        _fail(stat.S_ISREG(observed.st_mode))
        raw = _read_small(dotgit, 4096)
        _fail(raw.startswith(b"gitdir: ") and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        value = os.fsdecode(raw[len(b"gitdir: "):-1])
        gitdir = _directory_path(value if os.path.isabs(value) else os.path.join(repository, value))
    commondir_path = os.path.join(gitdir, "commondir")
    try:
        raw_common = _read_small(commondir_path, 4096)
    except FileNotFoundError:
        common = gitdir
    else:
        _fail(raw_common.endswith(b"\n") and raw_common.count(b"\n") == 1 and b"\x00" not in raw_common)
        value = os.fsdecode(raw_common[:-1])
        common = _directory_path(value if os.path.isabs(value) else os.path.join(gitdir, value))
    objects = _directory_path(os.path.join(common, "objects"))
    forbidden = (
        os.path.join(objects, "info", "alternates"),
        os.path.join(objects, "info", "http-alternates"),
        os.path.join(objects, "info", "commit-graph"),
        os.path.join(objects, "pack", "multi-pack-index"),
    )
    for path in forbidden:
        _fail(not os.path.lexists(path))
    pack = os.path.join(objects, "pack")
    if os.path.isdir(pack):
        names = os.listdir(pack)
        _fail(type(names) is list and len(names) <= MAX_REACHABLE_OBJECTS)
        _fail(not any(name.endswith(".promisor") for name in names))
    return GitLayout(repository, gitdir, common, objects)


def _hex_oid(raw):
    _fail(type(raw) is bytes and len(raw) == 40 and set(raw) <= set(b"0123456789abcdef"))
    return raw.decode("ascii")


def _resolve_head(layout):
    _fail(type(layout) is GitLayout)
    raw = _read_small(os.path.join(layout.gitdir, "HEAD"), 4096)
    _fail(raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\x00" not in raw)
    value = raw[:-1]
    if len(value) == 40:
        return _hex_oid(value)
    prefix = b"ref: "
    _fail(value.startswith(prefix))
    ref = value[len(prefix):]
    _fail(ref.startswith(b"refs/heads/") and len(ref) <= fs.MAX_PATH_BYTES)
    names = ref.split(b"/")
    _fail(all(name and name not in {b".", b".."} and b"\x00" not in name for name in names))
    relative = os.fsdecode(ref)
    candidates = tuple(dict.fromkeys((os.path.join(layout.gitdir, relative), os.path.join(layout.common, relative))))
    existing = [path for path in candidates if os.path.lexists(path)]
    _fail(len(existing) == 1)
    revision = _read_small(existing[0], 128)
    _fail(revision.endswith(b"\n") and revision.count(b"\n") == 1)
    return _hex_oid(revision[:-1])


def _git_tool():
    observed = os.stat(GIT, follow_symlinks=False)
    _fail(stat.S_ISREG(observed.st_mode) and observed.st_uid == observed.st_gid == 0)
    _fail(stat.S_IMODE(observed.st_mode) & 0o022 == 0)


def _isolated_git_environment(layout, gitdir):
    # The checked repository's config, attributes, hooks, filters, aliases,
    # replacement refs, helpers, and worktree are outside this Git process.
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_DIR": gitdir,
        "GIT_OBJECT_DIRECTORY": layout.objects,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _terminate_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    # The direct process may exit before descendants that inherited stdout.
    # Kill the process group regardless of the direct wait result.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise PrepareError() from error
    else:
        process.wait()
    _fail(process.poll() is not None)


def _bounded_process(argv, cwd, environment, maximum, deadline):
    _fail(type(argv) is tuple and argv and all(type(item) is str and item for item in argv))
    _fail(type(maximum) is int and 0 <= maximum <= MAX_PROCESS_OUTPUT and type(deadline) is Deadline)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    output = bytearray()
    selector = selectors.DefaultSelector()
    try:
        _fail(process.stdout is not None)
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        eof = False
        while not eof:
            try:
                remaining = deadline.remaining()
            except PrepareError:
                _terminate_group(process)
                raise
            events = selector.select(min(remaining, 0.1))
            if not events:
                if process.poll() is not None:
                    try:
                        part = os.read(descriptor, min(65_536, maximum + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not part:
                        eof = True
                    else:
                        output.extend(part)
                continue
            for key, _mask in events:
                try:
                    part = os.read(key.fd, min(65_536, maximum + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not part:
                    eof = True
                    selector.unregister(key.fd)
                    break
                output.extend(part)
                if len(output) > maximum:
                    _terminate_group(process)
                    raise PrepareError()
        try:
            process.wait(timeout=deadline.remaining())
        except (subprocess.TimeoutExpired, PrepareError) as error:
            _terminate_group(process)
            raise PrepareError() from error
        _fail(process.returncode == 0)
        return bytes(output)
    except BaseException:
        if process.poll() is None:
            _terminate_group(process)
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()


class _ObjectReader:
    def __init__(self, layout, deadline):
        self.layout = layout
        self.deadline = deadline
        self.temporary = None
        self.cache = {}
        self.total_bytes = 0

    def __enter__(self):
        _git_tool()
        self.temporary = tempfile.TemporaryDirectory(prefix="cogs-stage2-isolated-git-", dir="/tmp")
        root = self.temporary.name
        os.chmod(root, 0o700)
        os.mkdir(os.path.join(root, "refs"), 0o700)
        with open(os.path.join(root, "HEAD"), "xb") as destination:
            destination.write(b"ref: refs/heads/isolated\n")
        with open(os.path.join(root, "config"), "xb") as destination:
            destination.write(b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n")
        self.gitdir = root
        return self

    def __exit__(self, _kind, _value, _traceback):
        if self.temporary is not None:
            self.temporary.cleanup()
        return False

    def object(self, kind, oid, maximum):
        _fail(kind in {"blob", "commit", "tree"} and len(oid) == 40 and set(oid) <= HEX)
        key = (kind, oid)
        if key in self.cache:
            _fail(len(self.cache[key]) <= maximum)
            return self.cache[key]
        environment = _isolated_git_environment(self.layout, self.gitdir)
        raw = _bounded_process(
            (GIT, "-c", "core.useReplaceRefs=false", "-c", "core.commitGraph=false",
             "cat-file", kind, oid),
            self.layout.repository,
            environment,
            maximum,
            self.deadline,
        )
        header = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\x00"
        actual = hashlib.sha1(header + raw, usedforsecurity=False).hexdigest()
        _fail(actual == oid)
        self.total_bytes += len(raw)
        _fail(len(self.cache) < MAX_REACHABLE_OBJECTS and self.total_bytes <= MAX_TOTAL_BYTES)
        self.cache[key] = raw
        return raw


def _validated_path(raw):
    _fail(type(raw) is bytes and raw and len(raw) <= fs.MAX_PATH_BYTES and b"\x00" not in raw)
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise PrepareError() from error
    _fail(path.encode("utf-8") == raw and not path.startswith("/") and unicodedata.normalize("NFC", path) == path)
    parts = path.split("/")
    _fail(1 <= len(parts) <= fs.MAX_PATH_COMPONENTS)
    _fail(all(part not in {"", ".", "..", ".git", "node_modules"} for part in parts))
    _fail(all(len(part.encode("utf-8")) <= fs.MAX_COMPONENT_BYTES for part in parts))
    _fail(all(not any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts))
    _fail(tuple(part.encode("utf-8") for part in parts[:3]) != fs.STATE_RELATIVE)
    _fail(parts[0].encode("utf-8") not in {fs.SOURCE_SENTINEL_NAME, fs.SOURCE_MANIFEST_NAME})
    return path


def _tree_entries(raw):
    _fail(type(raw) is bytes and len(raw) <= MAX_TREE_BYTES)
    rows = []
    offset = 0
    names = set()
    previous = None
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\x00", space + 1)
        _fail(space > offset and nul > space + 1 and nul + 21 <= len(raw))
        mode = raw[offset:space]
        name = raw[space + 1:nul]
        oid = raw[nul + 1:nul + 21].hex()
        _fail(mode in {b"100644", b"100755", b"40000"} and name not in names)
        _fail(b"/" not in name and name not in {b".", b"..", b".git", b"node_modules"})
        _validated_path(name)
        order_key = name + (b"/" if mode == b"40000" else b"")
        _fail(previous is None or previous < order_key)
        previous = order_key
        names.add(name)
        rows.append((mode, name, oid))
        offset = nul + 21
    _fail(offset == len(raw) and len(rows) <= MAX_ENTRIES)
    return tuple(rows)


def _integrity_tree_entries(raw):
    _fail(type(raw) is bytes and len(raw) <= MAX_TREE_BYTES)
    rows = []
    offset = 0
    previous = None
    names = set()
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\x00", space + 1)
        _fail(space > offset and nul > space + 1 and nul + 21 <= len(raw))
        mode = raw[offset:space]
        name = raw[space + 1:nul]
        oid = raw[nul + 1:nul + 21].hex()
        _fail(mode in {b"100644", b"100755", b"120000", b"160000", b"40000"})
        _fail(name not in {b".", b".."} and b"/" not in name and b"\x00" not in name)
        _fail(name not in names)
        names.add(name)
        order_key = name + (b"/" if mode == b"40000" else b"")
        _fail(previous is None or previous < order_key)
        previous = order_key
        rows.append((mode, oid))
        offset = nul + 21
    _fail(offset == len(raw) and len(rows) <= MAX_REACHABLE_OBJECTS)
    return tuple(rows)


def _verify_selected_graph(reader, revision):
    commit = reader.object("commit", revision, MAX_COMMIT_BYTES)
    headers, separator, _message = commit.partition(b"\n\n")
    _fail(separator == b"\n\n")
    lines = headers.split(b"\n")
    _fail(lines and lines[0].startswith(b"tree ") and len(lines[0]) == 45)
    root_tree = _hex_oid(lines[0][5:])
    trees = set()

    def visit_tree(oid, ancestry):
        _fail(oid not in ancestry and len(ancestry) < fs.MAX_PATH_COMPONENTS)
        if oid in trees:
            return
        trees.add(oid)
        raw = reader.object("tree", oid, MAX_TREE_BYTES)
        for mode, child in _integrity_tree_entries(raw):
            if mode == b"40000":
                visit_tree(child, ancestry | {oid})
            elif mode != b"160000":
                reader.object("blob", child, MAX_PROCESS_OUTPUT)

    visit_tree(root_tree, set())
    _fail(0 < len(trees) < MAX_REACHABLE_OBJECTS)


def _directories(blobs):
    values = set()
    for blob in blobs:
        parts = blob.path.split("/")
        for length in range(1, len(parts)):
            values.add("/".join(parts[:length]))
    return tuple(sorted(values, key=lambda path: (path.count("/"), path.encode("utf-8"))))


def _object_plan(layout, revision, deadline):
    blobs = []
    directories = set()
    object_count = 1
    total_bytes = len(fs.SOURCE_SENTINEL)
    with _ObjectReader(layout, deadline) as reader:
        _verify_selected_graph(reader, revision)
        commit = reader.object("commit", revision, MAX_COMMIT_BYTES)
        first = commit.split(b"\n", 1)[0]
        _fail(first.startswith(b"tree ") and len(first) == 45)
        root_tree = _hex_oid(first[5:])

        def visit(tree_oid, prefix, ancestry):
            nonlocal object_count, total_bytes
            _fail(tree_oid not in ancestry and len(ancestry) < fs.MAX_PATH_COMPONENTS)
            tree = reader.object("tree", tree_oid, MAX_TREE_BYTES)
            object_count += 1
            _fail(object_count <= MAX_REACHABLE_OBJECTS)
            for mode, name, oid in _tree_entries(tree):
                path_raw = name if not prefix else prefix + b"/" + name
                path = _validated_path(path_raw)
                object_count += 1
                _fail(object_count <= MAX_REACHABLE_OBJECTS)
                if mode == b"40000":
                    directories.add(path)
                    visit(oid, path_raw, ancestry | {tree_oid})
                    continue
                content = reader.object("blob", oid, fs.MAX_SOURCE_FILE_BYTES)
                total_bytes += len(content)
                _fail(total_bytes <= MAX_TOTAL_BYTES)
                blobs.append(Blob(
                    path, 0o500 if mode == b"100755" else 0o400, oid, len(content),
                    hashlib.sha256(content).hexdigest(), content,
                ))

        visit(root_tree, b"", set())
    blobs.append(Blob(
        fs.SOURCE_SENTINEL_NAME.decode("ascii"), 0o400, "", len(fs.SOURCE_SENTINEL),
        hashlib.sha256(fs.SOURCE_SENTINEL).hexdigest(), fs.SOURCE_SENTINEL,
    ))
    blobs.sort(key=lambda item: item.path.encode("utf-8"))
    derived = set(_directories(blobs))
    _fail(derived == directories and len(blobs) + len(directories) <= MAX_ENTRIES)
    return Plan(revision, tuple(sorted(directories, key=lambda path: (path.count("/"), path.encode()))), tuple(blobs))


def _worktree_identity(observed):
    return tuple(getattr(observed, field) for field in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    ))


def _read_worktree_file(parent, name, maximum):
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        _fail(stat.S_ISREG(before.st_mode) and before.st_size <= maximum)
        chunks = []
        total = 0
        while total < before.st_size:
            part = os.read(descriptor, min(1024 * 1024, before.st_size - total))
            _fail(type(part) is bytes and part)
            chunks.append(part)
            total += len(part)
        after = os.fstat(descriptor)
        _fail((before.st_dev, before.st_ino, before.st_mode, before.st_size,
               before.st_mtime_ns, before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_mode, after.st_size,
               after.st_mtime_ns, after.st_ctime_ns))
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _verify_worktree(plan, deadline, repository, expected=None):
    _fail(expected is None or type(expected) is WorktreeSnapshot)
    blob_by_path = {blob.path: blob for blob in plan.blobs if blob.oid}
    directories = set(plan.directories)
    root = os.open(repository, _DIRECTORY_FLAGS)
    seen_blobs = set()
    seen_directories = set()
    identities = {}
    try:
        root_identity = _worktree_identity(os.fstat(root))
        identities["."] = root_identity

        def visit(directory, prefix):
            deadline.remaining()
            before_directory = _worktree_identity(os.fstat(directory))
            names = os.listdir(directory)
            _fail(type(names) is list and len(names) <= MAX_ENTRIES)
            for name in sorted(names, key=lambda item: os.fsencode(item)):
                _fail(type(name) is str)
                if not prefix and name == ".git":
                    continue
                path = name if not prefix else prefix + "/" + name
                _validated_path(path.encode("utf-8"))
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if path in directories:
                    _fail(stat.S_ISDIR(observed.st_mode))
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory)
                    try:
                        current = os.fstat(child)
                        _fail((current.st_dev, current.st_ino) == (observed.st_dev, observed.st_ino))
                        identities[path] = _worktree_identity(current)
                        seen_directories.add(path)
                        visit(child, path)
                        _fail(_worktree_identity(os.fstat(child)) == identities[path])
                    finally:
                        os.close(child)
                    continue
                blob = blob_by_path.get(path)
                _fail(blob is not None and stat.S_ISREG(observed.st_mode))
                raw, identity = _read_worktree_file(directory, name.encode("utf-8"), fs.MAX_SOURCE_FILE_BYTES)
                _fail((identity.st_dev, identity.st_ino) == (observed.st_dev, observed.st_ino))
                expected_mode = 0o755 if blob.mode == 0o500 else 0o644
                _fail(stat.S_IMODE(identity.st_mode) == expected_mode and raw == blob.content)
                header = b"blob " + str(len(raw)).encode("ascii") + b"\x00"
                _fail(hashlib.sha1(header + raw, usedforsecurity=False).hexdigest() == blob.oid)
                identities[path] = _worktree_identity(identity)
                seen_blobs.add(path)
            _fail(_worktree_identity(os.fstat(directory)) == before_directory)

        visit(root, "")
        _fail(_worktree_identity(os.fstat(root)) == root_identity)
    finally:
        os.close(root)
    _fail(seen_blobs == set(blob_by_path) and seen_directories == directories)
    snapshot = WorktreeSnapshot(tuple(sorted(identities.items(), key=lambda item: item[0].encode("utf-8"))))
    _fail(expected is None or snapshot == expected)
    return snapshot


def _snapshot_checked_checkout_from(repository):
    deadline = _deadline()
    layout = _git_layout(repository)
    revision = _resolve_head(layout)
    plan = _object_plan(layout, revision, deadline)
    snapshot = _verify_worktree(plan, deadline, layout.repository)
    _checkpoint("worktree-scanned")
    return CheckedCheckout(layout, plan, snapshot)


def _revalidate_checked_checkout(checked):
    _fail(type(checked) is CheckedCheckout)
    deadline = _deadline()
    _fail(_resolve_head(checked.layout) == checked.plan.revision)
    with _ObjectReader(checked.layout, deadline) as reader:
        reader.object("commit", checked.plan.revision, MAX_COMMIT_BYTES)
    _verify_worktree(checked.plan, deadline, checked.layout.repository, checked.snapshot)
    return checked.plan


def _load_checked_plan_from(repository):
    checked = _snapshot_checked_checkout_from(repository)
    return _revalidate_checked_checkout(checked)


def _load_checked_plan():
    return _load_checked_plan_from(REPOSITORY)


def _manifest_bytes(plan):
    _fail(type(plan) is Plan and len(plan.revision) == 40)
    rows = []
    directories = set(plan.directories)
    for path in plan.directories:
        rows.append({"path": path, "kind": "directory", "mode": 0o700, "size": 0, "sha256": None})
    for blob in plan.blobs:
        _fail(blob.path not in directories and len(blob.content) == blob.size)
        _fail(hashlib.sha256(blob.content).hexdigest() == blob.sha256)
        if blob.oid:
            header = b"blob " + str(blob.size).encode("ascii") + b"\x00"
            _fail(hashlib.sha1(header + blob.content, usedforsecurity=False).hexdigest() == blob.oid)
        rows.append({
            "path": blob.path, "kind": "file", "mode": blob.mode,
            "size": blob.size, "sha256": blob.sha256,
        })
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    value = {"version": fs.SOURCE_MANIFEST_VERSION, "revision": plan.revision, "entries": rows}
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    _fail(len(raw) <= fs.MAX_MANIFEST_BYTES)
    approval = fs.SourceApproval(plan.revision, hashlib.sha256(raw).hexdigest())
    _fail(fs._parse_source_manifest(raw, approval).digest == approval.manifest_sha256)
    return raw, approval


def _same_identity(left, right):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size")
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def _same_directory_identity(left, right):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def _empty_xattrs(descriptor):
    try:
        values = os.listxattr(descriptor)
    except (AttributeError, TypeError, OSError) as error:
        raise PrepareError() from error
    _fail(type(values) is list and values == [])


def _verify_directory(descriptor, mode, identity=None):
    observed = os.fstat(descriptor)
    _fail(stat.S_ISDIR(observed.st_mode) and stat.S_IMODE(observed.st_mode) == mode)
    _fail(observed.st_uid == observed.st_gid == 0 and observed.st_nlink >= 2)
    _fail(identity is None or _same_directory_identity(identity, observed))
    _empty_xattrs(descriptor)
    return observed


def _open_directory(parent, name, mode, create, existing_ok=True):
    _fail(type(name) is bytes and name and b"/" not in name)
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        before = None
    created = before is None
    if created:
        _fail(create)
        os.mkdir(name, mode, dir_fd=parent)
        os.fsync(parent)
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    else:
        _fail(existing_ok)
    _fail(stat.S_ISDIR(before.st_mode))
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        if created:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, mode)
        return descriptor, _verify_directory(descriptor, mode, before)
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative(root, path, identities):
    _fail(type(identities) is dict and "." in identities)
    descriptor = os.dup(root)
    os.set_inheritable(descriptor, False)
    try:
        _verify_directory(descriptor, 0o700, identities["."])
        current_path = ""
        if path:
            for component in path.split("/"):
                current_path = component if not current_path else current_path + "/" + component
                expected = identities.get(current_path)
                _fail(expected is not None)
                child = os.open(component.encode("utf-8"), _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                _verify_directory(descriptor, 0o700, expected)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _checkpoint(_label):
    """Test-only fault boundary; production has no callback input."""


def _verify_file(parent, name, expected, content, mode):
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
    try:
        observed = os.fstat(descriptor)
        _fail(_same_identity(expected, observed) and stat.S_ISREG(observed.st_mode))
        _fail(stat.S_IMODE(observed.st_mode) == mode and observed.st_uid == observed.st_gid == 0)
        _fail(observed.st_nlink == 1 and observed.st_size == len(content))
        _empty_xattrs(descriptor)
        digest = hashlib.sha256()
        offset = 0
        while offset < len(content):
            chunk = os.pread(descriptor, min(1024 * 1024, len(content) - offset), offset)
            _fail(type(chunk) is bytes and chunk)
            digest.update(chunk)
            offset += len(chunk)
        _fail(offset == len(content) and digest.hexdigest() == hashlib.sha256(content).hexdigest())
        _fail(_same_identity(observed, os.fstat(descriptor)))
    finally:
        os.close(descriptor)


def _create_file(source, path, content, mode, identities):
    parent_path, _separator, leaf = path.rpartition("/")
    parent = _open_relative(source, parent_path, identities)
    descriptor = None
    try:
        name = leaf.encode("utf-8")
        descriptor = os.open(name, _CREATE_FLAGS, 0o600, dir_fd=parent)
        offset = 0
        while offset < len(content):
            try:
                written = os.write(descriptor, content[offset:])
            except InterruptedError:
                continue
            _fail(type(written) is int and 0 < written <= len(content) - offset)
            offset += written
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        identity = os.fstat(descriptor)
        _fail(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1)
        os.close(descriptor)
        descriptor = None
        os.fsync(parent)
        _checkpoint("file-published:" + path)
        _verify_file(parent, name, identity, content, mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _create_directory(source, path, identities):
    parent_path, _separator, leaf = path.rpartition("/")
    parent = _open_relative(source, parent_path, identities)
    try:
        descriptor, identity = _open_directory(parent, leaf.encode("utf-8"), 0o700, True, False)
        identities[path] = identity
        os.close(descriptor)
        _checkpoint("directory-published:" + path)
        observed = os.stat(leaf.encode("utf-8"), dir_fd=parent, follow_symlinks=False)
        _fail(_same_identity(identity, observed))
    finally:
        os.close(parent)


def _verify_created_directories(source, identities):
    _fail(set(identities) and "." in identities)
    for path in sorted(identities, key=lambda item: (item != ".", item.count("/"), item.encode())):
        descriptor = _open_relative(source, "" if path == "." else path, identities)
        os.close(descriptor)


def _source_node(parent, name, control):
    identity = operation = None
    try:
        identity = fs._open_fd(name, fs.IDENTITY_FLAGS, "prepared-source-identity", control, parent)
        operation = fs._open_fd(name, fs.DIRECTORY_FLAGS, "prepared-source-directory", control, parent)
        generation = fs._observe_node(identity, operation, control)
        return fs.HeldNode(identity, operation, generation)
    except BaseException as error:
        fs._close_owned((operation, identity), error)


def _verify_materialized(parent, name, pending):
    _fail(type(pending) is PendingMaterialization and name == b"source")
    identities = dict(pending.directory_identities)
    source = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        _verify_directory(source, 0o700, pending.source_identity)
        _verify_created_directories(source, identities)
        control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
        node = _source_node(parent, name, control)
        try:
            verified = fs._verify_source_bundle(node, pending.approval, control)
            _fail(verified.revision == pending.plan.revision and
                  verified.digest == pending.approval.manifest_sha256)
        finally:
            fs._close_node(node)
        _verify_created_directories(source, identities)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _fail(_same_directory_identity(pending.source_identity, named) and
              _same_directory_identity(named, os.fstat(source)))
        return Preparation(
            pending.plan.revision, pending.approval.manifest_sha256, len(verified.entries),
        ), (pending.source_identity.st_dev, pending.source_identity.st_ino)
    finally:
        os.close(source)


def _materialize_pending(parent, name, plan):
    _fail(type(parent) is int and type(name) is bytes and name == b"source")
    _verify_directory(parent, 0o700)
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise PrepareError()
    raw_manifest, approval = _manifest_bytes(plan)
    source = None
    original_umask = os.umask(0o077)
    try:
        source, source_identity = _open_directory(parent, name, 0o700, True, False)
        identities = {".": source_identity}
        for path in plan.directories:
            _create_directory(source, path, identities)
        for blob in plan.blobs:
            _create_file(source, blob.path, blob.content, blob.mode, identities)
        _create_file(source, fs.SOURCE_MANIFEST_NAME.decode("ascii"), raw_manifest, 0o400, identities)
        os.fsync(source)
        os.fsync(parent)
        pending = PendingMaterialization(plan, approval, source_identity, tuple(identities.items()))
        _verify_materialized(parent, name, pending)
        _checkpoint("bundle-verified")
        return pending
    finally:
        os.umask(original_umask)
        if source is not None:
            os.close(source)


def _materialize(parent, name, plan):
    pending = _materialize_pending(parent, name, plan)
    return _verify_materialized(parent, name, pending)


def _production_parent():
    root = os.open(b"/", _DIRECTORY_FLAGS)
    held = [(root, _verify_directory(root, 0o755))]
    try:
        parent = root
        for index, name in enumerate(FIXED_COMPONENTS[:-1]):
            mode = 0o755 if index < 2 else 0o700
            descriptor, identity = _open_directory(parent, name, mode, index >= 2)
            held.append((descriptor, identity))
            parent = descriptor
        return held
    except BaseException:
        for descriptor, _identity in reversed(held):
            os.close(descriptor)
        raise


def _revalidate_production_chain(held):
    _fail(type(held) is list and len(held) == len(FIXED_COMPONENTS))
    for index, (descriptor, identity) in enumerate(held):
        _verify_directory(descriptor, stat.S_IMODE(identity.st_mode), identity)
        if index:
            named = os.stat(FIXED_COMPONENTS[index - 1], dir_fd=held[index - 1][0], follow_symlinks=False)
            _fail(stat.S_ISDIR(named.st_mode) and _same_directory_identity(named, identity))


def _prepare_fixed_source():
    """The sole production route; destination and authority are not arguments."""
    _checked_platform()
    checked = _snapshot_checked_checkout_from(REPOSITORY)
    held = _production_parent()
    try:
        _revalidate_production_chain(held)
        pending = _materialize_pending(held[-1][0], FIXED_COMPONENTS[-1], checked.plan)
        _revalidate_production_chain(held)
        _revalidate_checked_checkout(checked)
        return _verify_materialized(held[-1][0], FIXED_COMPONENTS[-1], pending)[0]
    finally:
        for descriptor, _identity in reversed(held):
            os.close(descriptor)


def _fixed_test_plan():
    revision = "a" * 40
    values = (
        ("deploy/aws-feasibility/fixture.txt", b"fixed fixture\n", 0o400),
        ("module.py", b"value = 1\n", 0o400),
    )
    blobs = [Blob(path, mode, "", len(raw), hashlib.sha256(raw).hexdigest(), raw)
             for path, raw, mode in values]
    blobs.append(Blob(
        fs.SOURCE_SENTINEL_NAME.decode("ascii"), 0o400, "", len(fs.SOURCE_SENTINEL),
        hashlib.sha256(fs.SOURCE_SENTINEL).hexdigest(), fs.SOURCE_SENTINEL,
    ))
    blobs.sort(key=lambda item: item.path.encode("utf-8"))
    return Plan(revision, _directories(blobs), tuple(blobs))


def _test_routes():
    seal = object()
    states = {}

    class Permit:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)

    def make(parent):
        _checked_test_platform()
        _fail(type(parent) is int)
        duplicate = os.dup(parent)
        os.set_inheritable(duplicate, False)
        try:
            _verify_directory(duplicate, 0o700)
            resolved = os.path.realpath(f"/proc/self/fd/{duplicate}")
            _fail(resolved.startswith(("/tmp/", "/work/")))
            _fail(not resolved.startswith("/var/lib/cogs/"))
            permit = Permit(seal)
            states[permit] = [duplicate, False]
            return permit
        except BaseException:
            os.close(duplicate)
            raise

    def prepare(permit):
        state = states.get(permit)
        _fail(type(permit) is Permit and state is not None and not state[1])
        state[1] = True
        try:
            return _materialize(state[0], b"source", _fixed_test_plan())[0]
        finally:
            os.close(state[0])

    return make, prepare


_make_test_local_permit_for_tests, _prepare_test_local_for_tests = _test_routes()
del _test_routes


def _result_bytes(preparation):
    _fail(type(preparation) is Preparation)
    value = {
        "version": RESULT_VERSION,
        "revision": preparation.revision,
        "manifest_sha256": preparation.manifest_sha256,
        "entries": preparation.entries,
        "authority": "qualification-only-fixed-source",
    }
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def main():
    _fail(len(sys.argv) == 1)
    result = _result_bytes(_prepare_fixed_source())
    _fail(sys.stdout.buffer.write(result) == len(result))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        status = main()
    except BaseException:
        try:
            sys.stderr.buffer.write(b"fixed source preparation failed\n")
            sys.stderr.buffer.flush()
        except BaseException:
            pass
        status = 2
    raise SystemExit(status)

#!/usr/bin/python3
"""Job E client for the common-owned sandbox qualification."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from typing import Callable

OPERATION = "E"
FAILURE_PHASE = "sandbox"
DIAGNOSTIC_LIMIT = 2_048
ROOT = Path(__file__).resolve().parents[2]
ROOT_BOOTSTRAP_PATH = Path("/usr/local/libexec/cogs-native-root-bootstrap-v1.py")
ROOT_AUTHORITY_PATH = Path("/etc/cogs/native-root-authority-v1.json")
ROOT_STATE_PATH = Path("/etc/cogs/.native-root-authority-install-v1.json")
LAUNCHER_PATH = "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
SOURCE_PATHS = (
    "deploy/aws-feasibility/remote/completion_elf.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    LAUNCHER_PATH,
    "schemas/trusted-runtime-closure-v1.json",
)
ROOT_ENVIRONMENT = frozenset({"NQ_ROOT_AUTHORITY_SHA"})


class QualificationError(RuntimeError):
    """The fixed Job E workflow entry was not selected."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _git(arguments: tuple[str, ...]) -> bytes:
    command = (
        "/usr/bin/git",
        "-c",
        f"safe.directory={ROOT}",
        "-C",
        os.fspath(ROOT),
        *arguments,
    )
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    }
    completed = subprocess.run(command, env=environment, capture_output=True, check=False, timeout=5)
    _require(completed.returncode == 0 and not completed.stderr, "exact reviewed Git object")
    _require(len(completed.stdout) <= 2_000_000, "reviewed Git object bound")
    return completed.stdout


def _reviewed_blob(revision: str, path: str) -> bytes:
    row = _git(("ls-tree", revision, "--", path))
    fields = row.rstrip(b"\n").split(b"\t", 1)
    _require(len(fields) == 2 and fields[1].decode("utf-8", "strict") == path, "reviewed Git path")
    mode, kind, _object_id = fields[0].decode("ascii").split(" ")
    _require(mode == "100644" and kind == "blob", "reviewed Git blob")
    return _git(("cat-file", "blob", f"{revision}:{path}"))


def _bootstrap_bytes(launcher: bytes) -> bytes:
    tree = ast.parse(launcher, "cogs-reviewed:root-launcher")
    values: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "_ROOT_BOOTSTRAP":
            _require(isinstance(node.value, ast.Constant) and type(node.value.value) is str, "root bootstrap constant")
            values.append(node.value.value)
    _require(len(values) == 1, "one root bootstrap constant")
    return values[0].encode("utf-8")


def _root_material(revision: str) -> tuple[bytes, bytes]:
    _require(len(revision) == 40 and all(value in "0123456789abcdef" for value in revision), "reviewed SHA")
    _require(_git(("rev-parse", "--verify", f"{revision}^{{commit}}")) == f"{revision}\n".encode(), "reviewed commit")
    driver_path = "scripts/native-qualification/job-e-sandbox.py"
    _require(Path(__file__).read_bytes() == _reviewed_blob(revision, driver_path), "reviewed root authority owner")
    sources = {path: _reviewed_blob(revision, path) for path in SOURCE_PATHS}
    digest = hashlib.sha256()
    rows = []
    for path in SOURCE_PATHS:
        raw = sources[path]
        encoded = path.encode("utf-8")
        sha256 = hashlib.sha256(raw).hexdigest()
        digest.update(struct.pack("!I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack("!Q", len(raw)))
        digest.update(bytes.fromhex(sha256))
        rows.append({"path": path, "sha256": sha256, "size": len(raw)})
    bootstrap = _bootstrap_bytes(sources[LAUNCHER_PATH])
    authority = {
        "bootstrap_sha256": hashlib.sha256(sources[LAUNCHER_PATH]).hexdigest(),
        "revision": revision,
        "root_bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
        "source_set_sha256": digest.hexdigest(),
        "sources": rows,
        "version": "cogs.root-capsule-authority/v1",
    }
    return bootstrap, _canonical(authority)


def _secure_directory(path: Path) -> None:
    value = path.lstat()
    _require(stat.S_ISDIR(value.st_mode), "root authority directory")
    _require(value.st_uid == os.geteuid(), "root authority directory owner")
    _require(stat.S_IMODE(value.st_mode) & 0o022 == 0, "root authority directory mode")


def _fsync_directory(path: Path) -> None:
    adopted_descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(adopted_descriptor)
    finally:
        os.close(adopted_descriptor)


def _write_root_file(path: Path, raw: bytes, mode: int) -> None:
    adopted_descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    complete = False
    try:
        os.fchmod(adopted_descriptor, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(adopted_descriptor, raw[offset:])
            _require(written > 0, "root authority write")
            offset += written
        os.fsync(adopted_descriptor)
        complete = True
    finally:
        os.close(adopted_descriptor)
        if not complete:
            path.unlink(missing_ok=True)


def _read_root_file(path: Path, expected: bytes | tuple[bytes, ...], mode: int) -> bytes:
    options = (expected,) if type(expected) is bytes else expected
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == mode, "root authority file mode")
        _require(before.st_uid == os.geteuid(), "root authority file owner")
        _require(before.st_nlink == 1 and before.st_size in {len(item) for item in options},
                 "root authority file generation")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            _require(bool(block), "root authority short read")
            raw.extend(block)
        value = bytes(raw)
        _require(not os.read(descriptor, 1) and value in options, "root authority file bytes")
        after = os.fstat(descriptor)
        _require(before == after, "root authority file changed")
        current = path.lstat()
        _require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), "root authority path identity")
        return value
    finally:
        os.close(descriptor)


def _provision_root_authority(revision: str) -> None:
    bootstrap, authority = _root_material(revision)
    bootstrap_parent_created = False
    authority_parent_created = False
    created: list[Path] = []
    try:
        if not ROOT_BOOTSTRAP_PATH.parent.exists():
            ROOT_BOOTSTRAP_PATH.parent.mkdir(mode=0o755)
            bootstrap_parent_created = True
        _secure_directory(ROOT_BOOTSTRAP_PATH.parent)
        _require(not ROOT_AUTHORITY_PATH.parent.exists(), "root authority baseline")
        ROOT_AUTHORITY_PATH.parent.mkdir(mode=0o755)
        authority_parent_created = True
        _secure_directory(ROOT_AUTHORITY_PATH.parent)
        state = _canonical({"bootstrap_parent_created": bootstrap_parent_created, "revision": revision})
        for path, raw, mode in (
            (ROOT_BOOTSTRAP_PATH, bootstrap, 0o444),
            (ROOT_AUTHORITY_PATH, authority, 0o444),
            (ROOT_STATE_PATH, state, 0o400),
        ):
            _write_root_file(path, raw, mode)
            created.append(path)
        _fsync_directory(ROOT_BOOTSTRAP_PATH.parent)
        _fsync_directory(ROOT_AUTHORITY_PATH.parent)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if authority_parent_created:
            ROOT_AUTHORITY_PATH.parent.rmdir()
        if bootstrap_parent_created:
            ROOT_BOOTSTRAP_PATH.parent.rmdir()
        raise


def _cleanup_root_authority(revision: str) -> None:
    bootstrap, authority = _root_material(revision)
    state_false = _canonical({"bootstrap_parent_created": False, "revision": revision})
    state_true = _canonical({"bootstrap_parent_created": True, "revision": revision})
    _secure_directory(ROOT_BOOTSTRAP_PATH.parent)
    _secure_directory(ROOT_AUTHORITY_PATH.parent)
    _require(set(os.listdir(ROOT_AUTHORITY_PATH.parent)) == {ROOT_AUTHORITY_PATH.name, ROOT_STATE_PATH.name},
             "root authority directory entries")
    _read_root_file(ROOT_BOOTSTRAP_PATH, bootstrap, 0o444)
    _read_root_file(ROOT_AUTHORITY_PATH, authority, 0o444)
    state = _read_root_file(ROOT_STATE_PATH, (state_false, state_true), 0o400)
    ROOT_AUTHORITY_PATH.unlink()
    ROOT_STATE_PATH.unlink()
    ROOT_BOOTSTRAP_PATH.unlink()
    _fsync_directory(ROOT_AUTHORITY_PATH.parent)
    _fsync_directory(ROOT_BOOTSTRAP_PATH.parent)
    ROOT_AUTHORITY_PATH.parent.rmdir()
    _fsync_directory(ROOT_AUTHORITY_PATH.parent.parent)
    if state == state_true:
        ROOT_BOOTSTRAP_PATH.parent.rmdir()
        _fsync_directory(ROOT_BOOTSTRAP_PATH.parent.parent)


def _root_authority_action(arguments: list[str]) -> int | None:
    actions = {
        "--provision-root-authority": _provision_root_authority,
        "--cleanup-root-authority": _cleanup_root_authority,
    }
    if len(arguments) != 1 or arguments[0] not in actions:
        return None
    _require(__debug__ and os.geteuid() == 0 and set(os.environ) == ROOT_ENVIRONMENT, "fixed root authority entry")
    actions[arguments[0]](os.environ["NQ_ROOT_AUTHORITY_SHA"])
    return 0


def _load_common() -> object:
    module_directory = os.fspath(Path(__file__).resolve().parent)
    sys.path.insert(0, module_directory)
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _operation(session: object) -> None:
    """Enter the one common-owned operation boundary; its return stays private."""
    session.run_fixed_operation(OPERATION)  # type: ignore[attr-defined]


def _combine(primary: BaseException | None, cleanup: BaseException) -> BaseException:
    if primary is None:
        return cleanup
    return BaseExceptionGroup("Job E operation and settlement", [primary, cleanup])


def _diagnostic(error: BaseException | None, restored: bool) -> bytes | None:
    if error is None and restored:
        return None
    if error is None:
        return b"common cleanup was not restored"
    message = f"{type(error).__name__}:{error}".encode("utf-8", "backslashreplace")
    return message[:DIAGNOSTIC_LIMIT]


def _run(common: object) -> int:
    session = common.NativeSession.begin(OPERATION, __file__)  # type: ignore[attr-defined]
    primary: BaseException | None = None

    try:
        _operation(session)
    except Exception as error:
        primary = error

    evidence = None
    try:
        evidence = session.settle_native_phase()  # type: ignore[attr-defined]
    except Exception as error:
        primary = _combine(primary, error)

    restored = evidence is not None and evidence.restored is True
    failed = primary is not None or not restored
    candidate = common.ReportCandidate(  # type: ignore[attr-defined]
        failure_phase=FAILURE_PHASE if failed else None,
        diagnostics=_diagnostic(primary, restored),
        primary_error=primary,
    )
    session.publish(candidate)  # type: ignore[attr-defined]
    return 1 if failed else 0


def _dispatch(
    arguments: list[str],
    workflow: Callable[[object], int] = _run,
    common_loader: Callable[[], object] = _load_common,
) -> int:
    root_result = _root_authority_action(arguments)
    if root_result is not None:
        return root_result
    entry_is_fixed = __debug__ and arguments == ["--workflow-bound"]
    _require(entry_is_fixed and os.geteuid() != 0, "fixed unprivileged Job E workflow entry")
    return workflow(common_loader())


if __name__ == "__main__":
    try:
        exit_code = _dispatch(sys.argv[1:])
    except Exception:
        os.write(2, b"native-e-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)

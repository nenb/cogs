#!/usr/bin/env python3
"""One-shot native Linux/amd64 package candidate over the fixed Stage 2 rootfs."""

import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time

sys.dont_write_bytecode = True

FIXED_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
FIXED_DRIVER = FIXED_SOURCE / "scripts/run-stage2-package-native-candidate.py"
FIXED_PHASE_A = FIXED_SOURCE / "scripts/run-stage2-phase-a-candidate.py"
REMOTE = FIXED_SOURCE / "deploy/aws-feasibility/remote"
ROOT_MOUNT = Path("/var/tmp/cogs-stage2-native-package-root-v1")
APPROVAL = "download-16-fixed-public-stage2-artifacts"
MAX_RESULT_BYTES = 4096
OUTER_SECONDS = 2_700
CHILD_SECONDS = 1_300
NS = 1_000_000_000
CLONE_NEWNS = 0x00020000
SYS_OPEN_TREE = 428
SYS_MOVE_MOUNT = 429
AT_FDCWD = -100
OPEN_TREE_CLONE = 1
OPEN_TREE_CLOEXEC = 0o2000000
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class NativeCandidateError(Exception):
    pass


def _require(condition):
    if not condition:
        raise NativeCandidateError()


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _libc_call(name, *arguments):
    libc = ctypes.CDLL(None, use_errno=True)
    call = getattr(libc, name)
    call.restype = ctypes.c_int
    if call(*arguments) != 0:
        raise OSError(ctypes.get_errno(), name)


def _syscall(number, *arguments):
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.syscall
    call.restype = ctypes.c_long
    result = call(ctypes.c_long(number), *arguments)
    if result < 0:
        raise OSError(ctypes.get_errno(), f"syscall-{number}")
    return result


def _mount(source, target, filesystem, flags, data=None):
    encoded = lambda value: None if value is None else os.fsencode(value)
    _libc_call(
        "mount",
        ctypes.c_char_p(encoded(source)),
        ctypes.c_char_p(encoded(target)),
        ctypes.c_char_p(encoded(filesystem)),
        ctypes.c_ulong(flags),
        ctypes.c_char_p(encoded(data)),
    )


def _private_rootfs(root_descriptor, stage):
    os.mkdir(ROOT_MOUNT, 0o700)
    observed = os.lstat(ROOT_MOUNT)
    _require(stat.S_ISDIR(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o700
             and observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 2)
    stage[0] = "unshare"
    _libc_call("unshare", ctypes.c_int(CLONE_NEWNS))
    stage[0] = "root-private"
    _mount(None, "/", None, MS_REC | MS_PRIVATE)
    root = str(ROOT_MOUNT)
    stage[0] = "root-open-tree"
    tree = _syscall(
        SYS_OPEN_TREE,
        ctypes.c_int(root_descriptor),
        ctypes.c_char_p(b"."),
        ctypes.c_uint(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC),
    )
    try:
        stage[0] = "root-move-mount"
        _syscall(
            SYS_MOVE_MOUNT,
            ctypes.c_int(tree),
            ctypes.c_char_p(b""),
            ctypes.c_int(AT_FDCWD),
            ctypes.c_char_p(os.fsencode(root)),
            ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH),
        )
    finally:
        os.close(tree)
    stage[0] = "proc-bind"
    _mount("/proc", f"{root}/proc", None, MS_BIND | MS_REC)
    stage[0] = "dev-bind"
    _mount("/dev", f"{root}/dev", None, MS_BIND | MS_REC)
    stage[0] = "tmpfs"
    _mount(
        "tmpfs",
        f"{root}/tmp",
        "tmpfs",
        MS_NOSUID | MS_NODEV,
        "mode=1777,size=134217728",
    )
    stage[0] = "chroot"
    os.chroot(root)
    os.chdir("/")
    stage[0] = "proc-readonly"
    _mount(None, "/proc", None, MS_BIND | MS_REMOUNT | MS_RDONLY)


def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        _require(written > 0)
        offset += written


def _child_candidate(write_descriptor, root_descriptor, contract, closure, package):
    stage = ["start"]
    try:
        _private_rootfs(root_descriptor, stage)
        stage[0] = "transaction"
        package.load_candidate_contract = lambda: contract
        package.exact_runtime_closure = lambda: closure
        raw = package.run_candidate_transaction()
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESULT_BYTES)
        _write_all(write_descriptor, len(raw).to_bytes(4, "big") + raw)
        os.close(write_descriptor)
        os._exit(0)
    except BaseException as error:
        category = (
            f"OSError_{error.errno}"
            if isinstance(error, OSError) and error.errno is not None
            else getattr(error, "category", type(error).__name__)
        )
        if not isinstance(category, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", category) is None:
            category = "unknown"
        try:
            os.write(2, f"native package child failed:{stage[0]}:{category}\n".encode("ascii"))
            os.close(write_descriptor)
        except OSError:
            pass
        os._exit(1)


def _kill_and_reap(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            waited, status = os.waitpid(pid, 0)
            return status if waited == pid else None
        except InterruptedError:
            continue


def _wait_candidate(pid, descriptor, deadline_ns):
    raw = bytearray()
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    status = None
    try:
        while True:
            remaining = deadline_ns - time.monotonic_ns()
            if remaining <= 0:
                raise NativeCandidateError()
            events = poller.poll(min(1_000, max(1, (remaining + 999_999) // 1_000_000)))
            if events:
                chunk = os.read(descriptor, MAX_RESULT_BYTES + 5 - len(raw))
                if chunk:
                    raw.extend(chunk)
                    _require(len(raw) <= MAX_RESULT_BYTES + 4)
                else:
                    break
        while True:
            waited, status = os.waitpid(pid, 0)
            if waited == pid:
                break
        _require(os.waitstatus_to_exitcode(status) == 0)
        _require(len(raw) >= 5 and int.from_bytes(raw[:4], "big") == len(raw) - 4)
        return bytes(raw[4:])
    except BaseException:
        if status is None:
            _kill_and_reap(pid)
        raise
    finally:
        os.close(descriptor)


def _cache_rows(contract):
    rows = [contract["oci"][name] for name in ("index", "manifest", "config", "layer")]
    rows.extend(contract["snapshot"][name] for name in ("inrelease", "packages_index"))
    rows.extend(contract["packages"])
    _require(len(rows) == 16 and len({row["cache_name"] for row in rows}) == 16)
    return tuple(rows)


def _identity(status):
    return (status.st_dev, status.st_ino, status.st_mode, status.st_uid, status.st_gid,
            status.st_nlink, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def _read_fd(descriptor, expected_size):
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        _require(chunk)
        chunks.append(chunk)
        remaining -= len(chunk)
    _require(os.read(descriptor, 1) == b"")
    return b"".join(chunks)


def _hold_cache(verifier, contract):
    root = os.open(verifier.ARTIFACT_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    cache = -1
    held = []
    sentinel = None
    try:
        root_identity = _identity(os.fstat(root))
        cache = os.open("cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        cache_identity = _identity(os.fstat(cache))
        rows = _cache_rows(contract)
        _require(set(os.listdir(root)) == {"cache", verifier.SENTINEL})
        _require(set(os.listdir(cache)) == {row["cache_name"] for row in rows})
        for row in rows:
            descriptor = os.open(row["cache_name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cache)
            observed = os.fstat(descriptor)
            raw = _read_fd(descriptor, row["size"])
            _require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1)
            _require(len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"])
            held.append((row, descriptor, _identity(observed)))
        sentinel = os.open(verifier.SENTINEL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        sentinel_identity = _identity(os.fstat(sentinel))
        _require(_read_fd(sentinel, len(verifier.SENTINEL_BYTES)) == verifier.SENTINEL_BYTES)
        return root, root_identity, cache, cache_identity, held, sentinel, sentinel_identity
    except BaseException:
        for _row, descriptor, _held_identity in held:
            os.close(descriptor)
        if sentinel is not None:
            os.close(sentinel)
        if cache >= 0:
            os.close(cache)
        os.close(root)
        raise


def _cleanup_cache(verifier, authority):
    root, root_identity, cache, cache_identity, held, sentinel, sentinel_identity = authority
    error = None
    try:
        _require(_identity(os.fstat(root)) == root_identity and _identity(os.fstat(cache)) == cache_identity)
        _require(set(os.listdir(cache)) == {row["cache_name"] for row, _fd, _identity_value in held})
        for row, descriptor, held_identity in held:
            current = os.stat(row["cache_name"], dir_fd=cache, follow_symlinks=False)
            _require(_identity(os.fstat(descriptor)) == held_identity == _identity(current))
            _require(hashlib.sha256(_read_fd(descriptor, row["size"])).hexdigest() == row["sha256"])
            os.unlink(row["cache_name"], dir_fd=cache)
            os.fsync(cache)
        _require(_identity(os.fstat(sentinel)) == sentinel_identity)
        _require(_read_fd(sentinel, len(verifier.SENTINEL_BYTES)) == verifier.SENTINEL_BYTES)
        os.rmdir("cache", dir_fd=root)
        os.unlink(verifier.SENTINEL, dir_fd=root)
        os.fsync(root)
    except BaseException as caught:
        error = caught
    for _row, descriptor, _held_identity in held:
        try:
            os.close(descriptor)
        except BaseException as caught:
            error = caught if error is None else error
    for descriptor in (sentinel, cache, root):
        try:
            os.close(descriptor)
        except BaseException as caught:
            error = caught if error is None else error
    if error is None:
        try:
            os.rmdir(verifier.ARTIFACT_ROOT)
        except BaseException as caught:
            error = caught
    if error is not None:
        raise error


def _cleanup_root_mount():
    observed = os.lstat(ROOT_MOUNT)
    _require(stat.S_ISDIR(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o700
             and observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 2
             and not os.listdir(ROOT_MOUNT))
    os.rmdir(ROOT_MOUNT)


def _cleanup_retained(retained, materializer, fs):
    error = None
    try:
        materializer._reload_and_cleanup(retained.owned, materializer._fresh_cleanup_control())
        retained.disposition = "retired"
    except BaseException as caught:
        error = caught
    try:
        fs._close_chain(retained.base_chain)
    except BaseException as caught:
        error = caught if error is None else fs.RootfsFsError(error, caught)
    if error is not None:
        raise error


def run():
    reviewed_head = os.environ.get("COGS_PACKAGE_REVIEWED_HEAD", "")
    _require(_HEX40.fullmatch(reviewed_head) is not None)
    _require(Path(__file__).resolve() == FIXED_DRIVER and os.environ.get(
        "COGS_STAGE2_ARTIFACT_ACQUISITION_APPROVED") == APPROVAL)
    phase_a = _load("package_native_phase_a", FIXED_PHASE_A)
    phase_a._fixed_preflight(True)
    revision, manifest_sha256 = phase_a._source_approval()
    _require(revision == reviewed_head)
    phase_a._verify_fixed_source(revision, manifest_sha256)
    verifier = phase_a._load_artifact_verifier()
    _require(not verifier.ARTIFACT_ROOT.exists())
    contract = phase_a._verifier_call(
        verifier, "contract", lambda: verifier.verify_contract(verifier.CONTRACT_PATH))
    phase_a._verifier_call(
        verifier, "acquisition", lambda: verifier.acquire_completion_artifacts(
            verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT), True)
    cache_authority = None
    retained = None
    primary = None
    result = None
    sys.path.insert(0, str(REMOTE))
    import completion_package_candidate as package
    import completion_rootfs_build as build
    import completion_rootfs_builder as builder
    import completion_rootfs_fs as fs
    import completion_rootfs_materializer as materializer
    import completion_rootfs_publish as publication
    from completion_runtime_contract import exact_runtime_closure, load_candidate_contract
    try:
        phase_a._verifier_call(verifier, "postverify", lambda: verifier.verify_package_archives(
            verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT))
        cache_authority = _hold_cache(verifier, contract)
        candidate_contract = load_candidate_contract()
        closure = exact_runtime_closure()
        approval = fs.SourceApproval(revision, manifest_sha256)
        deadline_ns = time.monotonic_ns() + OUTER_SECONDS * NS
        control = fs.OperationControl(deadline_ns, lambda: False)
        phase_a._bootstrap_rootfs(builder, fs, approval, control)
        rootfs, retained = build._build_once_retained(approval, os.urandom(32).hex(), control)
        build._require_pinned(rootfs, publication._load_pins())
        _require(len(rootfs.cache) == 16)
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            os.close(read_descriptor)
            _child_candidate(
                write_descriptor, retained.owned.root.operation_fd.number,
                candidate_contract, closure, package,
            )
        os.close(write_descriptor)
        result = _wait_candidate(pid, read_descriptor, min(deadline_ns, time.monotonic_ns() + CHILD_SECONDS * NS))
    except BaseException as caught:
        primary = caught
    try:
        _cleanup_root_mount()
    except FileNotFoundError:
        if result is not None:
            primary = NativeCandidateError()
    except BaseException as caught:
        primary = caught if primary is None else primary
    if retained is not None:
        try:
            _cleanup_retained(retained, materializer, fs)
            retained = None
        except BaseException as caught:
            primary = caught if primary is None else fs.RootfsFsError(primary, caught)
    if cache_authority is not None:
        try:
            _cleanup_cache(verifier, cache_authority)
            cache_authority = None
        except BaseException as caught:
            primary = caught if primary is None else caught
    try:
        _require(not verifier.ARTIFACT_ROOT.exists())
        rootfs_state = phase_a.ROOTFS_STATE
        _require(rootfs_state.is_dir())
        _require(set(os.listdir(rootfs_state)) == {builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text})
    except BaseException as caught:
        primary = caught if primary is None else primary
    if primary is not None or result is None:
        raise NativeCandidateError() from primary
    return result


def main():
    if len(sys.argv) != 1:
        return 1
    try:
        raw = run()
        _write_all(sys.stdout.fileno(), raw)
        return 0
    except BaseException as error:
        cause = error.__cause__
        category = getattr(cause, "category", type(cause).__name__ if cause is not None else type(error).__name__)
        if not isinstance(category, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", category) is None:
            category = "unknown"
        try:
            os.write(2, f"native package candidate failed:{category}\n".encode("ascii"))
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

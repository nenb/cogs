#!/usr/bin/env python3
"""ADR 0057 portable policy, Linux synthetic faults, and hosted exact gate."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import select
import stat
import struct
import sys
import tempfile
import time

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
FIXED = Path("/var/lib/cogs/stage2-completion-v1/source")
STATE = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
FAULTS = (
    ("F1", "anonymous-open", "create-settled"),
    ("F2", "partial-write", "create-settled"),
    ("F3", "emission-complete", "create-settled"),
    ("F4", "intent", "candidate-tar-intent"),
    ("F5", "linked", "candidate-tar-intent"),
    ("F6", "observed", "candidate-tar-observed"),
)


class QualificationFault(Exception):
    pass


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def portable_tests():
    qualification_source = Path(__file__).read_text()
    assert sys.dont_write_bytecode is True
    assert qualification_source.index("sys.dont_write_bytecode = True") < qualification_source.index("def load(")
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        module_path = base / "guarded_module.py"
        module_path.write_text("VALUE = 1\n")
        before = state_tree(base)
        assert load("portable_bytecode_guard", module_path).VALUE == 1
        assert state_tree(base) == before and not (base / "__pycache__").exists()
    candidate_source = (REMOTE / "completion_rootfs_candidate.py").read_text()
    transaction_calls = ("canonical._canonical_metadata(", "fs._open_anonymous(",
                         "fs._link_anonymous(", "builder._append_candidate(")
    assert all(call in candidate_source for call in transaction_calls)
    assert "builder._recover_fixed(" not in candidate_source
    assert "_parse_ledger" not in candidate_source
    assert "subprocess" not in candidate_source and "socket" not in candidate_source
    portable_supervisor_tests()
    print("completion rootfs candidate portable/static tests passed")


def require_synthetic_container():
    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/.dockerenv").is_file()
    mount = Path("/var/lib/cogs")
    observed = mount.stat(follow_symlinks=False)
    assert stat.S_ISDIR(observed.st_mode)
    assert stat.S_IMODE(observed.st_mode) == 0o700
    rows = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    rows = [row for row in rows if row[4] == str(mount)]
    assert len(rows) == 1 and "-" in rows[0]
    separator = rows[0].index("-")
    assert rows[0][separator + 1] == "tmpfs"
    assert "rw" in rows[0][5].split(",")
    assert not any(mount.iterdir())


def prepare_synthetic_workspace():
    require_synthetic_container()
    completion = FIXED / "deploy/aws-feasibility/.state/completion-v1"
    completion.mkdir(parents=True, mode=0o700)
    directories = (
        Path("/var/lib/cogs/stage2-completion-v1"), FIXED, FIXED / "deploy",
        FIXED / "deploy/aws-feasibility", FIXED / "deploy/aws-feasibility/.state", completion,
    )
    for directory in directories:
        directory.chmod(0o700)


def accommodate_container_filesystem(fs):
    real_xattrs = fs._require_empty_fd_xattrs
    ancestor_keys = {
        (os.lstat(path).st_dev, os.lstat(path).st_ino)
        for path in ("/", "/var", "/var/lib")
    }
    functional_device = os.lstat("/var/lib/cogs").st_dev
    fs._open_workspace_anchor = lambda control: fs._open_root_node(control)

    def policy(node, expected, root_key):
        generation = node.generation
        assert generation.key.kind == expected.kind
        assert generation.mode == expected.mode
        assert generation.uid == expected.uid and generation.gid == expected.gid
        same_root = (generation.key.mount_id, generation.key.device) == (
            root_key.mount_id,
            root_key.device,
        )
        assert same_root or generation.key.device == functional_device
        if expected.kind == "file":
            assert generation.nlink == 1

    def xattrs(node, control):
        key = (node.generation.key.device, node.generation.key.inode)
        if key not in ancestor_keys:
            real_xattrs(node, control)

    fs._require_policy = policy
    fs._require_empty_fd_xattrs = xattrs


def state_inventory():
    values = []
    for path in sorted(STATE.rglob("*"), key=lambda item: str(item).encode()) if STATE.exists() else ():
        observed = os.lstat(path)
        content = path.read_bytes() if stat.S_ISREG(observed.st_mode) else None
        values.append((
            str(path.relative_to(STATE)), observed.st_dev, observed.st_ino,
            stat.S_IFMT(observed.st_mode), stat.S_IMODE(observed.st_mode),
            observed.st_uid, observed.st_gid, observed.st_nlink, observed.st_size, content,
        ))
    return tuple(values)


def fd_inventory():
    directory = Path("/proc/self/fd")
    before = tuple(sorted(os.listdir(directory), key=int))
    values = []
    for descriptor in before:
        path = directory / descriptor
        try:
            observed = os.stat(path)
        except FileNotFoundError:
            continue
        values.append((int(descriptor), os.readlink(path), observed.st_dev,
                       observed.st_ino, observed.st_mode))
    assert tuple(sorted(os.listdir(directory), key=int)) == before
    return tuple(values)


def close_crashed_operation(fs, builder, owned, chain):
    for node in (owned.root, owned.operation, owned.active.node):
        if node.identity_fd.disposition == "open":
            fs._close_node(node)
    if owned.locked.lock.identity_fd.disposition == "open":
        builder._release_lock(owned.locked)
    if owned.locked.state.identity_fd.disposition == "open":
        fs._close_node(owned.locked.state)
    fs._close_chain(chain)


def synthetic_authority(archive, plan, canonical):
    content = b"atomic candidate synthetic payload\n"
    digest = hashlib.sha256(content).hexdigest()
    root = archive.ArchiveRoot("directory", 0o755, 0, 0, plan.SOURCE_DATE_EPOCH, 0)
    record = archive.MaterialRecord(
        "payload", "file", 0o600, 0, 0, plan.SOURCE_DATE_EPOCH,
        len(content), None, None, None, digest, 0,
    )
    entry = plan.PlannedEntry("synthetic", None, record, content)
    graph = plan.RootfsPlan(root, ("synthetic",), (entry,), ())
    authority = plan.RootfsBuildInputs("synthetic", (), (), graph)
    manifest = canonical._manifest(graph)
    raw = canonical._header("./", root, b"5", 0)
    raw += canonical._header("payload", record, b"0", len(content))
    raw += content + b"\0" * ((-len(content)) % canonical.BLOCK)
    raw += b"\0" * canonical.BLOCK * 2
    return authority, manifest, raw


def linux_synthetic_faults():
    prepare_synthetic_workspace()
    sys.path.insert(0, str(REMOTE))
    archive = load("completion_archive_preflight", REMOTE / "completion_archive_preflight.py")
    plan = load("completion_rootfs_plan", REMOTE / "completion_rootfs_plan.py")
    fs = load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
    ledger = load("completion_rootfs_ledger", REMOTE / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", REMOTE / "completion_rootfs_builder.py")
    canonical = load("completion_rootfs_canonical", REMOTE / "completion_rootfs_canonical.py")
    candidate = load("completion_rootfs_candidate", REMOTE / "completion_rootfs_candidate.py")
    accommodate_container_filesystem(fs)
    fs._verify_source_bundle = lambda *_args: object()
    builder.FIXED_MODULE = Path(builder.__file__).resolve()
    approval = fs.SourceApproval("9" * 40, "8" * 64)
    control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
    chain = builder._open_base_chain(control)
    state = builder._bootstrap(chain, approval, control)
    fs._close_node(state)
    fs._close_chain(chain)
    baseline = state_inventory()
    assert tuple(item[0] for item in baseline) == tuple(sorted((
        builder.LOCK_NAME.text,
        builder.STATE_SENTINEL_NAME.text,
    )))
    authority, manifest, expected_tar = synthetic_authority(archive, plan, canonical)
    expected_digest = hashlib.sha256(expected_tar).hexdigest()
    ledger.CANDIDATE_TAR_SIZE = len(expected_tar)
    candidate.EXPECTED_ENTRIES = 1
    candidate.EXPECTED_SIZE = len(expected_tar)
    candidate.EXPECTED_SHA256 = expected_digest

    for index, (label, boundary, expected_terminal) in enumerate(FAULTS, 1):
        descriptors_before = fd_inventory()
        chain = builder._open_base_chain(control)
        owned = builder._begin_operation(chain, approval, f"{index:064x}", control)
        root_chain = builder._chain_with_child(
            builder._operation_chain(owned, control),
            builder.ROOT_NAME,
            owned.root,
        )
        active, payload = builder._create_ledger_entry(
            owned.active, root_chain, "rootfs/payload", fs._name("payload"),
            "file", b"atomic candidate synthetic payload\n", control,
        )
        fs._close_node(payload)
        owned = builder.OwnedOperation(
            owned.locked, active, owned.operation, owned.root, owned.operation_name,
        )
        reached = []
        opened = []
        partial_counts = []
        primary = QualificationFault(label)
        real_fault = candidate._fault
        real_open = fs._open_anonymous
        real_close = fs._close_anonymous
        real_canonical_os = canonical.os

        def fault(selected):
            real_fault(selected)
            reached.append(selected)
            if selected == boundary:
                raise primary

        def capture_open(*args):
            descriptor = real_open(*args)
            opened.append(descriptor)
            return descriptor

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError(f"{label} close aggregation")

        class PartialWriteOs:
            def __getattr__(self, name):
                return getattr(os, name)

            def write(self, descriptor, raw):
                count = os.write(descriptor, raw[: min(17, len(raw))])
                partial_counts.append(count)
                raise primary

        candidate._fault = fault
        fs._open_anonymous = capture_open
        fs._close_anonymous = close_then_fail
        if label == "F2":
            canonical.os = PartialWriteOs()
        failure = None
        try:
            candidate._create_candidate(active, owned, authority, manifest, control)
        except BaseException as error:
            failure = error
        finally:
            candidate._fault = real_fault
            fs._open_anonymous = real_open
            fs._close_anonymous = real_close
            canonical.os = real_canonical_os
        assert isinstance(failure, fs.RootfsFsError)
        assert failure.primary is primary, label
        assert isinstance(failure.close_error, OSError)
        assert len(opened) == 1 and opened[0].disposition == "closed"
        assert reached and reached[0] == "anonymous-open" and (label == "F2" or boundary in reached)
        assert bool(partial_counts and partial_counts[0] > 0) == (label == "F2")
        close_crashed_operation(fs, builder, owned, chain)
        candidate_path = STATE / owned.operation_name / ledger.CANDIDATE_TAR_PATH
        assert candidate_path.exists() == (label in {"F5", "F6"})
        raw = (STATE / builder.LEDGER_NAME.text).read_bytes()
        assert ledger._parse_ledger_history(raw).terminal.record_type == expected_terminal
        before_recovery = state_inventory()

        if label in {"F5", "F6"}:
            real_observation = builder._candidate_tar_observation
            mismatch_seen = []

            def mismatched_observation(*args):
                value = real_observation(*args)
                mismatch_seen.append(value)
                return value[0], "e" * 64

            builder._candidate_tar_observation = mismatched_observation
            try:
                builder._recover_fixed(builder._fresh_recovery_control())
            except BaseException:
                pass
            else:
                raise AssertionError(f"{label} digest mismatch received cleanup authority")
            finally:
                builder._candidate_tar_observation = real_observation
            assert mismatch_seen == [(len(expected_tar), expected_digest)]
            assert state_inventory() == before_recovery

        appended = []
        real_session_append = builder._session_append

        def capture_append(session, record_type, body, recovery_control):
            result = real_session_append(session, record_type, body, recovery_control)
            appended.append(record_type)
            return result

        builder._session_append = capture_append
        counters_before = fs.structural_counter_snapshot()
        try:
            builder._recover_fixed(builder._fresh_recovery_control())
        finally:
            builder._session_append = real_session_append
        counters = fs.structural_counter_delta(counters_before, fs.structural_counter_snapshot())
        assert counters["complete_walks"] >= 2
        if label == "F4":
            assert appended[0] == "candidate-tar-abort"
        if label == "F5":
            assert appended[:2] == ["candidate-tar-observed", "candidate-tar-settled"]
        if label == "F6":
            assert appended[0] == "candidate-tar-settled"
        if label in {"F5", "F6"}:
            settled_index = appended.index("candidate-tar-settled")
            assert "remove-intent" in appended[settled_index + 1 :]
        assert state_inventory() == baseline
        assert fd_inventory() == descriptors_before, label

    shutil.rmtree(Path("/var/lib/cogs/stage2-completion-v1"))
    assert not any(Path("/var/lib/cogs").iterdir())
    print("completion rootfs candidate Linux synthetic F1-F6 tests passed")


NS = 1_000_000_000
CHAIN_NAMES = (".state", "completion-v1", "artifacts", "cache")
SENTINEL_NAME = ".cogs-stage2-completion-artifacts-v1"
SENTINEL_BYTES = b"cogs-stage2-completion-artifacts-v1\n"
FRAME = struct.Struct("!4sBBBBB")
FRAME_MAGIC = b"CGS2"
FRAME_VERSION = 1
PHASE_ACQUIRED, PHASE_BOOTSTRAP, PHASE_BUILDS, PHASE_EQUALITY, PHASE_PINS = range(1, 6)
PHASE_TERMINAL = 6
CUT_PHASES = tuple(range(16, 22))
PROGRESS_PHASES = (PHASE_ACQUIRED, PHASE_BOOTSTRAP, PHASE_BUILDS, PHASE_EQUALITY, PHASE_PINS)
MAX_FRAMES = len(PROGRESS_PHASES) + 2


def checked(deadline, callback):
    if time.monotonic_ns() >= deadline:
        raise TimeoutError("supervisor phase deadline")
    value = callback()
    if time.monotonic_ns() >= deadline:
        raise TimeoutError("supervisor phase deadline")
    return value


def exact_identity(observed):
    return (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode),
            stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid,
            observed.st_nlink, observed.st_size)


def directory_identity(descriptor):
    value = exact_identity(os.fstat(descriptor))
    assert value[2] == stat.S_IFDIR and value[4] == os.geteuid()
    assert value[5] == os.getegid() and value[3] == 0o700 and value[6] >= 2
    return value


def inventory(descriptor):
    return tuple(sorted(os.listdir(descriptor), key=os.fsencode))


def cloexec_pipe():
    descriptors = os.pipe()
    assert all(not os.get_inheritable(item) for item in descriptors)
    return descriptors


def prepare_private_chain(base, deadline):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    base_fd = checked(deadline, lambda: os.open(base, flags))
    descriptors = [base_fd]
    identities = []
    retained_inventory = []
    created_from = None
    try:
        identities.append(checked(deadline, lambda: directory_identity(base_fd)))
        retained_inventory.append(checked(deadline, lambda: inventory(base_fd)))
        for index, name in enumerate(CHAIN_NAMES, 1):
            parent = descriptors[-1]
            try:
                observed = checked(deadline, lambda name=name, parent=parent:
                                   os.stat(name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError:
                created_from = index
                break
            assert stat.S_ISDIR(observed.st_mode)
            descriptor = checked(deadline, lambda name=name, parent=parent:
                                 os.open(name, flags, dir_fd=parent))
            descriptors.append(descriptor)
            identities.append(checked(deadline, lambda descriptor=descriptor:
                                      directory_identity(descriptor)))
            retained_inventory.append(checked(deadline, lambda descriptor=descriptor:
                                              inventory(descriptor)))
        if created_from is None or created_from > 3:
            raise AssertionError("preexisting artifact baseline")
        for index in range(created_from, len(CHAIN_NAMES) + 1):
            name, parent = CHAIN_NAMES[index - 1], descriptors[-1]
            checked(deadline, lambda name=name, parent=parent:
                    os.mkdir(name, 0o700, dir_fd=parent))
            checked(deadline, lambda parent=parent: os.fsync(parent))
            descriptor = checked(deadline, lambda name=name, parent=parent:
                                 os.open(name, flags, dir_fd=parent))
            descriptors.append(descriptor)
            identities.append(checked(deadline, lambda descriptor=descriptor:
                                      directory_identity(descriptor)))
            assert checked(deadline, lambda descriptor=descriptor: inventory(descriptor)) == ()
        assert len(descriptors) == 5 and created_from in {1, 2, 3}
        retained_identities = tuple(identities[:created_from])
        identities = [checked(deadline, lambda descriptor=descriptor:
                              directory_identity(descriptor)) for descriptor in descriptors]
        for index, descriptor in enumerate(descriptors):
            before = retained_inventory[index] if index < created_from else ()
            child = CHAIN_NAMES[index] if index < 4 and index >= created_from - 1 else None
            expected = tuple(sorted(before + (() if child is None else (child,)), key=os.fsencode))
            assert checked(deadline, lambda descriptor=descriptor: inventory(descriptor)) == expected
        return {"fds": descriptors, "identities": identities,
                "retained_identities": retained_identities,
                "retained": retained_inventory, "created_from": created_from}
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def validate_bound_chain(chain, deadline, final=False):
    descriptors = chain["fds"]
    for index, descriptor in enumerate(descriptors):
        if descriptor < 0:
            continue
        expected = (chain["retained_identities"][index]
                    if final and index < chain["created_from"] else chain["identities"][index])
        width = 7 if final and index < chain["created_from"] else 6
        assert checked(deadline, lambda descriptor=descriptor:
                       directory_identity(descriptor))[:width] == expected[:width]
        if final and index < chain["created_from"]:
            assert checked(deadline, lambda descriptor=descriptor: inventory(descriptor)) == chain["retained"][index]


def close_chain(chain, deadline, errors, closer=os.close):
    for index in range(len(chain["fds"]) - 1, -1, -1):
        descriptor = chain["fds"][index]
        if descriptor >= 0:
            try:
                checked(deadline, lambda descriptor=descriptor: closer(descriptor))
                chain["fds"][index] = -1
            except BaseException:
                errors.append("descriptor-close")


def encode_frame(phase, ordinal, result=255, recovery=255):
    assert phase in PROGRESS_PHASES + CUT_PHASES + (PHASE_TERMINAL,)
    assert 1 <= ordinal <= MAX_FRAMES
    if phase == PHASE_TERMINAL:
        assert result in {0, 1} and recovery in {0, 1}
    else:
        assert result == recovery == 255
    return FRAME.pack(FRAME_MAGIC, FRAME_VERSION, phase, ordinal, result, recovery)


def send_frame(descriptor, phase, ordinal, result=255, recovery=255):
    raw = encode_frame(phase, ordinal, result, recovery)
    offset = 0
    while offset < len(raw):
        count = os.write(descriptor, raw[offset:])
        if count <= 0:
            raise OSError("fixed protocol write")
        offset += count


class PipeRecord:
    def __init__(self):
        self.raw, self.frames = bytearray(), []
        self.error = self.eof = False
        self.terminal = None

    def accept(self, raw):
        if self.eof or len(self.raw) + len(raw) > FRAME.size * MAX_FRAMES:
            self.error = True
            return
        self.raw.extend(raw)
        while len(self.raw) >= FRAME.size and not self.error:
            fields = FRAME.unpack(bytes(self.raw[:FRAME.size]))
            del self.raw[:FRAME.size]
            magic, version, phase, ordinal, result, recovery = fields
            prior = tuple(item[0] for item in self.frames)
            prefix = prior == PROGRESS_PHASES[:len(prior)]
            progress = (prefix and len(prior) < len(PROGRESS_PHASES) and
                        phase == PROGRESS_PHASES[len(prior)] and result == recovery == 255)
            cut = prefix and phase in CUT_PHASES and result == recovery == 255
            terminal = phase == PHASE_TERMINAL and (prefix or prior[-1:] in tuple(
                (item,) for item in CUT_PHASES)) and result in {0, 1} and recovery in {0, 1}
            valid = (magic == FRAME_MAGIC and version == FRAME_VERSION and
                     ordinal == len(self.frames) + 1 and (progress or cut or terminal))
            if not valid or len(self.frames) == MAX_FRAMES:
                self.error = True
            else:
                frame = (phase, result, recovery)
                self.frames.append(frame)
                if phase == PHASE_TERMINAL:
                    self.terminal = frame

    def finish(self):
        self.eof = True
        self.error = self.error or bool(self.raw) or self.terminal is None
        return not self.error

    @property
    def acquired(self):
        return bool(self.frames and self.frames[0][0] == PHASE_ACQUIRED)


def drain_pipe(descriptor, record):
    while True:
        try:
            raw = os.read(descriptor, FRAME.size * MAX_FRAMES)
        except BlockingIOError:
            return
        if not raw:
            record.eof = True
            return
        record.accept(raw)


def supervise_child(pid, descriptor, source_deadline, build_deadline, grace_ns=5 * NS):
    assert 0 < grace_ns <= 5 * NS and source_deadline < build_deadline
    os.set_blocking(descriptor, False)
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    record = PipeRecord()
    status = None
    reaped = False
    termination = None

    def reap():
        nonlocal status, reaped
        if not reaped:
            observed, value = os.waitpid(pid, os.WNOHANG)
            if observed:
                assert observed == pid
                status, reaped = value, True

    def wait_slice(until):
        remaining = max(0, until - time.monotonic_ns())
        poller.poll(min(50, (remaining + 999_999) // 1_000_000))
        drain_pipe(descriptor, record)
        reap()

    while not reaped:
        drain_pipe(descriptor, record)
        reap()
        if reaped:
            break
        hard = build_deadline if record.acquired else source_deadline
        if record.error or time.monotonic_ns() >= hard - grace_ns:
            termination = "protocol" if record.error else (
                "build-timeout" if record.acquired else "acquisition-timeout")
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            grace_end = min(hard, time.monotonic_ns() + grace_ns)
            while not reaped and time.monotonic_ns() < grace_end:
                wait_slice(grace_end)
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                while not reaped and time.monotonic_ns() < hard:
                    wait_slice(hard)
            break
        wait_slice(hard - grace_ns)
    drain_pipe(descriptor, record)
    if reaped:
        for _unused in range(4):
            if record.eof:
                break
            wait_slice(time.monotonic_ns() + 10_000_000)
    valid = reaped and record.eof and record.finish()
    terminal = record.terminal
    coherent = valid and terminal is not None
    if coherent and terminal[1] == 0:
        coherent = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    elif coherent and termination is None:
        coherent = os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0
    return {"pid": pid, "reaped": reaped, "status": status, "record": record,
            "valid": coherent, "terminal": terminal, "termination": termination}


def digest_fd(descriptor, size, deadline):
    checked(deadline, lambda: os.lseek(descriptor, 0, os.SEEK_SET))
    digest = hashlib.sha256()
    total = 0
    while total < size:
        raw = checked(deadline, lambda: os.read(descriptor, min(1024 * 1024, size - total)))
        assert raw
        total += len(raw)
        digest.update(raw)
    assert checked(deadline, lambda: os.read(descriptor, 1)) == b""
    return digest.hexdigest()


def open_stable_file(parent, name, deadline):
    before = checked(deadline, lambda: os.stat(name, dir_fd=parent, follow_symlinks=False))
    assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
    assert before.st_gid == os.getegid()
    descriptor = checked(deadline, lambda: os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
    assert checked(deadline, lambda: exact_identity(os.fstat(descriptor))) == exact_identity(before)
    after = checked(deadline, lambda: os.stat(name, dir_fd=parent, follow_symlinks=False))
    assert exact_identity(after) == exact_identity(before)
    return descriptor, exact_identity(before)


def cache_cleanup_plan(chain, rows, deadline):
    artifacts, cache = chain["fds"][3], chain["fds"][4]
    assert directory_identity(artifacts)[:6] == chain["identities"][3][:6]
    assert directory_identity(cache)[:6] == chain["identities"][4][:6]
    root_names = set(checked(deadline, lambda: os.listdir(artifacts)))
    assert root_names in ({"cache"}, {"cache", SENTINEL_NAME})
    fixed = {row["name"]: row for row in rows}
    allowed = set(fixed) | {f".{name}.partial" for name in fixed}
    names = set(checked(deadline, lambda: os.listdir(cache)))
    assert names <= allowed
    held = {}
    sentinel = None
    try:
        for name in sorted(names, key=os.fsencode):
            descriptor, identity = open_stable_file(cache, name, deadline)
            held[name] = (descriptor, identity)
        if SENTINEL_NAME in root_names:
            sentinel = open_stable_file(artifacts, SENTINEL_NAME, deadline)
            descriptor, identity = sentinel
            assert identity[3:] == (0o600, os.geteuid(), os.getegid(), 1,
                                    len(SENTINEL_BYTES))
            assert digest_fd(descriptor, identity[7], deadline) == hashlib.sha256(
                SENTINEL_BYTES).hexdigest()
        for name, row in fixed.items():
            final = held.get(name)
            partial = held.get(f".{name}.partial")
            if final is not None:
                identity = final[1]
                assert identity[3:] == (0o400, os.geteuid(), os.getegid(),
                                        2 if partial else 1, row["size"])
                assert digest_fd(final[0], row["size"], deadline) == row["sha256"]
            if partial is not None:
                identity = partial[1]
                if final is not None:
                    assert identity[:7] == final[1][:7] and identity[7] == row["size"]
                    assert digest_fd(partial[0], row["size"], deadline) == row["sha256"]
                elif identity[3] == 0o600:
                    assert identity[6] == 1 and identity[7] <= row["size"]
                else:
                    assert identity[3:] == (0o400, os.geteuid(), os.getegid(), 1, row["size"])
                    assert digest_fd(partial[0], row["size"], deadline) == row["sha256"]
        for name, (descriptor, identity) in held.items():
            assert exact_identity(os.fstat(descriptor)) == identity
            assert exact_identity(os.stat(name, dir_fd=cache, follow_symlinks=False)) == identity
        return held, sentinel
    except BaseException:
        for descriptor, _identity in held.values():
            os.close(descriptor)
        if sentinel is not None:
            os.close(sentinel[0])
        raise


def cleanup_private_chain(chain, rows, deadline):
    held, sentinel = cache_cleanup_plan(chain, rows, deadline)
    cache, artifacts = chain["fds"][4], chain["fds"][3]
    try:
        for row in sorted(rows, key=lambda item: os.fsencode(item["name"])):
            names = (f".{row['name']}.partial", row["name"])
            for name in names:
                if name not in held:
                    continue
                descriptor, identity = held[name]
                current = checked(deadline, lambda name=name:
                                  os.stat(name, dir_fd=cache, follow_symlinks=False))
                assert (current.st_dev, current.st_ino) == identity[:2]
                assert exact_identity(os.fstat(descriptor))[:6] == identity[:6]
                checked(deadline, lambda name=name: os.unlink(name, dir_fd=cache))
                checked(deadline, lambda: os.fsync(cache))
        if sentinel is not None:
            current = checked(deadline, lambda: os.stat(
                SENTINEL_NAME, dir_fd=artifacts, follow_symlinks=False))
            assert (current.st_dev, current.st_ino) == sentinel[1][:2]
            checked(deadline, lambda: os.unlink(SENTINEL_NAME, dir_fd=artifacts))
            checked(deadline, lambda: os.fsync(artifacts))
    finally:
        for descriptor, _identity in held.values():
            checked(deadline, lambda descriptor=descriptor: os.close(descriptor))
        if sentinel is not None:
            checked(deadline, lambda: os.close(sentinel[0]))
    for index in range(4, chain["created_from"] - 1, -1):
        descriptor, parent = chain["fds"][index], chain["fds"][index - 1]
        assert checked(deadline, lambda descriptor=descriptor:
                       directory_identity(descriptor))[:6] == chain["identities"][index][:6]
        assert checked(deadline, lambda descriptor=descriptor: inventory(descriptor)) == ()
        checked(deadline, lambda descriptor=descriptor: os.close(descriptor))
        chain["fds"][index] = -1
        checked(deadline, lambda index=index, parent=parent:
                os.rmdir(CHAIN_NAMES[index - 1], dir_fd=parent))
        checked(deadline, lambda parent=parent: os.fsync(parent))
    validate_bound_chain(chain, deadline, True)


def rootfs_observation(completion_fd, builder, deadline):
    chain = state = locked = active = operation = None
    result = "invalid"
    control = builder.fs.OperationControl(deadline, lambda: False)
    try:
        chain = builder._open_base_chain(control)
        production = builder._completion(chain)
        builder._fail(exact_identity(os.fstat(completion_fd)) ==
                      exact_identity(os.fstat(production.operation_fd.number)))
        state = builder._open_state(chain, control)
        if state is None:
            result = "absent"
        else:
            locked = builder._acquire_lock(chain, state, control)
            names = builder.fs._enumerate_stable(state, control).raw_names
            fixed = tuple(sorted((builder.STATE_SENTINEL_NAME.raw, builder.LOCK_NAME.raw)))
            if names == fixed:
                result = "idle"
            else:
                builder._fail(builder.LEDGER_NAME.raw in names)
                active = builder._read_active_ledger(state, control)
                genesis = builder._first_record(active).body_value()
                approval = builder.fs.SourceApproval(
                    genesis["source_revision"], genesis["source_manifest_sha256"])
                builder.fs._verify_source_bundle(builder._source(chain), approval, control)
                snapshot = builder.fs._enumerate_stable(locked.state, control)
                extras = [item for item in snapshot.names if item.raw not in {
                    builder.STATE_SENTINEL_NAME.raw, builder.LOCK_NAME.raw,
                    builder.LEDGER_NAME.raw}]
                if extras:
                    builder._fail(extras == [builder._operation_name(builder._token(active))])
                    operation = builder.fs._open_path_node(
                        locked.state, extras[0], "directory", control)
                legal = active.records.legal
                origin = "release-authorized" if (legal.phase == "release-authorized" or
                    legal.return_phase == "release-authorized" or
                    legal.lease_snapshot is not None) else "prelease"
                session = builder._open_cleanup_session(
                    active, locked, operation, origin, control)
                active, result = session.active, "needed"
    except BaseException:
        result = "invalid"
    finally:
        closers = (
            lambda: builder._close(operation), lambda: builder._close(active.node),
            lambda: builder._release_lock(locked), lambda: builder._close(state),
            lambda: builder.fs._close_chain(chain),
        )
        owned = (
            operation is not None and operation.identity_fd.disposition == "open",
            active is not None and active.node.identity_fd.disposition == "open",
            locked is not None and locked.lock.identity_fd.disposition == "open",
            state is not None and state.identity_fd.disposition == "open",
            chain is not None and chain.anchor.identity_fd.disposition == "open",
        )
        for present, close in zip(owned, closers):
            if present:
                try:
                    close()
                except BaseException:
                    result = "invalid"
    return result


def terminal_recovery_count(result):
    return result["terminal"][2] if result.get("valid") and result.get("terminal") else None


def recovery_allowed(result, root_state):
    return terminal_recovery_count(result) == 0 and root_state == "needed"


def child_hosted(write_fd, runner, verifier, contract, revision, manifest_sha256, build_deadline):
    ordinal = 0
    recovery = [0]

    def emit(phase):
        nonlocal ordinal
        ordinal += 1
        send_frame(write_fd, phase, ordinal)

    try:
        runner._verifier_call(verifier, "cache-acquisition-unknown", lambda:
            verifier.acquire_completion_artifacts(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT), True)
        runner._verifier_call(verifier, "cache-postverify", lambda:
            verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT))
        emit(PHASE_ACQUIRED)
        sys.path.insert(0, str(runner.REMOTE))
        fs = __import__("completion_rootfs_fs")
        builder = __import__("completion_rootfs_builder")
        build = __import__("completion_rootfs_build")
        publication = __import__("completion_rootfs_publish")
        approval = fs.SourceApproval(revision, manifest_sha256)
        now = time.monotonic_ns()
        control = fs.OperationControl(min(build_deadline, now + build.OUTER_SECONDS * NS), lambda: False)
        assert now < control.deadline_ns
        runner._bootstrap_rootfs(builder, fs, approval, control)
        emit(PHASE_BOOTSTRAP)
        authentic_recover = builder._recover_fixed

        def counted_recover(recovery_control):
            recovery[0] += 1
            return authentic_recover(recovery_control)

        builder._recover_fixed = counted_recover
        try:
            first, second = build._two_build_outputs(approval, control)
        finally:
            builder._recover_fixed = authentic_recover
        assert recovery[0] in {0, 1}
        emit(PHASE_BUILDS)
        build._require_equal_builds(first, second)
        emit(PHASE_EQUALITY)
        pins = publication._load_pins()
        build._require_pinned(first, pins)
        build._require_pinned(second, pins)
        runner._verifier_call(verifier, "rootfs-postverify", lambda:
            verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT))
        assert runner._snapshot_cache(contract)["files"]
        emit(PHASE_PINS)
        ordinal += 1
        send_frame(write_fd, PHASE_TERMINAL, ordinal, 0, recovery[0])
        os.close(write_fd)
        os._exit(0)
    except BaseException:
        try:
            if recovery[0] in {0, 1}:
                ordinal += 1
                send_frame(write_fd, PHASE_TERMINAL, ordinal, 1, recovery[0])
        except BaseException:
            pass
        try:
            os.close(write_fd)
        except OSError:
            pass
        os._exit(1)


def wait_for_boundary(start, end):
    while time.monotonic_ns() < start:
        remaining = start - time.monotonic_ns()
        select.poll().poll(min(1000, (remaining + 999_999) // 1_000_000))
    if time.monotonic_ns() >= end:
        raise TimeoutError("supervisor phase unavailable")


def hosted_exact_input():
    raw_anchor = os.environ["COGS_STAGE2_PHASE_A_BUDGET_ANCHOR_NS"]
    assert raw_anchor.isascii() and raw_anchor.isdigit() and raw_anchor[0] != "0"
    anchor = int(raw_anchor)
    now = time.monotonic_ns()
    assert anchor <= now and anchor <= (1 << 63) - 1
    deadlines = tuple(anchor + seconds * NS for seconds in (600, 3900, 4500, 5100, 5400))
    source_deadline, build_deadline, recovery_deadline, cleanup_deadline, final_deadline = deadlines
    errors = []
    chain = None
    descriptors_before = fd_inventory()
    try:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
        assert os.environ.get("COGS_ADR0057_HOSTED_EXACT") == "1"
        runner = load("hosted_stage2_runner", FIXED / "scripts/run-stage2-phase-a-candidate.py")
        checked(source_deadline, lambda: runner._fixed_preflight(True))
        revision, manifest_sha256 = checked(source_deadline, runner._source_approval)
        assert revision == os.environ["COGS_ADR0057_SOURCE_REVISION"]
        assert manifest_sha256 == os.environ["COGS_ADR0057_SOURCE_MANIFEST_SHA256"]
        checked(source_deadline, lambda: runner._verify_fixed_source(revision, manifest_sha256))
        verifier = checked(source_deadline, runner._load_artifact_verifier)
        contract = checked(source_deadline, lambda: runner._verifier_call(
            verifier, "rootfs-contract-preflight",
            lambda: verifier.verify_contract(verifier.CONTRACT_PATH)))
        assert runner.ARTIFACT_ROOT == FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts"
        assert runner.ROOTFS_STATE == STATE
        assert runner._held_path_absent(runner.ARTIFACT_ROOT)
        assert runner._held_path_absent(runner.ROOTFS_STATE)
        temporary_paths = (runner.STATE, runner.ANCHOR)
        assert all(runner._held_path_absent(path) for path in temporary_paths)
        chain = prepare_private_chain(runner.ARTIFACT_ROOT.parents[2], source_deadline)
        validate_bound_chain(chain, source_deadline)
        checked(source_deadline, lambda: runner._verify_fixed_source(revision, manifest_sha256))
        read_fd, write_fd = checked(source_deadline, cloexec_pipe)
        pid = checked(source_deadline, os.fork)
        if pid == 0:
            os.close(read_fd)
            child_hosted(write_fd, runner, verifier, contract, revision, manifest_sha256, build_deadline)
        os.close(write_fd)
        result = supervise_child(pid, read_fd, source_deadline, build_deadline)
        os.close(read_fd)
        if not result["reaped"]:
            errors.append("child-unreaped")
        if not result["valid"]:
            errors.append("protocol-or-status")
        elif result["terminal"][1] != 0:
            errors.append("child-failure")
        if result["reaped"]:
            wait_for_boundary(build_deadline, recovery_deadline)
            sys.path.insert(0, str(runner.REMOTE))
            builder = __import__("completion_rootfs_builder")
            root_state = rootfs_observation(chain["fds"][2], builder, recovery_deadline)
            if recovery_allowed(result, root_state):
                checked(recovery_deadline, lambda: runner._recover_rootfs([]))
            elif root_state == "needed":
                errors.append("rootfs-preserved")
            elif root_state == "invalid":
                errors.append("rootfs-invalid")
            wait_for_boundary(recovery_deadline, cleanup_deadline)
            if result["valid"]:
                root_state = rootfs_observation(chain["fds"][2], builder, cleanup_deadline)
                if root_state == "idle":
                    lifecycle = checked(cleanup_deadline, runner._snapshot_rootfs_lifecycle)
                    checked(cleanup_deadline, lambda: runner._cleanup_rootfs((
                        {"kind": "rootfs-lifecycle-owned", "body": lifecycle},)))
                elif root_state != "absent":
                    errors.append("rootfs-cleanup-preserved")
                try:
                    rows = tuple({"name": row["cache_name"], "size": row["size"],
                                  "sha256": row["sha256"]}
                                 for row in runner._artifact_rows(contract))
                    cleanup_private_chain(chain, rows, cleanup_deadline)
                except BaseException:
                    errors.append("cache-cleanup-preserved")
            close_chain(chain, cleanup_deadline, errors)
            checked(cleanup_deadline, lambda: runner._verify_fixed_source(revision, manifest_sha256))
            assert runner._held_path_absent(runner.ARTIFACT_ROOT)
            assert runner._held_path_absent(runner.ROOTFS_STATE)
            assert all(runner._held_path_absent(path) for path in temporary_paths)
            assert fd_inventory() == descriptors_before
        wait_for_boundary(cleanup_deadline, final_deadline)
    except BaseException:
        errors.append("parent-failure")
    finally:
        if chain is not None and any(item >= 0 for item in chain["fds"]):
            close_chain(chain, final_deadline, errors)
    if errors:
        raise RuntimeError("hosted supervisor: " + ",".join(sorted(set(errors))))
    print("hosted qualification supervisor passed")


def portable_child(write_fd, artifacts_fd, cache_fd, kind, row, recovery):
    try:
        sentinel = os.open(SENTINEL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                           0o600, dir_fd=artifacts_fd)
        os.write(sentinel, SENTINEL_BYTES)
        os.fsync(sentinel)
        os.close(sentinel)
        os.fsync(artifacts_fd)
        partial = f".{row['name']}.partial"
        descriptor = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=cache_fd)
        os.write(descriptor, row["raw"][:3] if kind == "writing" else row["raw"])
        if kind not in {"writing", "pre-flush"}:
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            verified, identity = open_stable_file(cache_fd, partial, time.monotonic_ns() + NS)
            assert digest_fd(verified, row["size"], time.monotonic_ns() + NS) == row["sha256"]
            assert exact_identity(os.fstat(verified)) == identity == exact_identity(
                os.stat(partial, dir_fd=cache_fd, follow_symlinks=False))
            os.close(verified)
            if kind in {"publication-intent", "post-publication", "post-settlement", "success"}:
                os.link(partial, row["name"], src_dir_fd=cache_fd,
                        dst_dir_fd=cache_fd, follow_symlinks=False)
            if kind in {"post-publication", "post-settlement", "success"}:
                os.fsync(cache_fd)
            if kind in {"post-settlement", "success"}:
                os.unlink(partial, dir_fd=cache_fd)
                os.fsync(cache_fd)
        if descriptor >= 0:
            os.close(descriptor)
        send_frame(write_fd, PHASE_ACQUIRED, 1)
        if kind == "success":
            for ordinal, phase in enumerate(PROGRESS_PHASES[1:], 2):
                send_frame(write_fd, phase, ordinal)
            send_frame(write_fd, PHASE_TERMINAL, 6, 0, recovery)
            os.close(write_fd)
            os._exit(0)
        cut = ("writing", "pre-flush", "pre-publication", "publication-intent",
               "post-publication", "post-settlement").index(kind)
        send_frame(write_fd, CUT_PHASES[cut], 2)
        send_frame(write_fd, PHASE_TERMINAL, 3, 1, recovery)
        signal.pause()
    except BaseException:
        os._exit(2)


def portable_fds():
    root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
    values = []
    for name in os.listdir(root):
        try:
            os.fstat(int(name))
            values.append(int(name))
        except OSError:
            pass
    return tuple(sorted(values))


def rejected_unchanged(callback, observe):
    before = observe()
    try:
        callback()
    except AssertionError:
        assert observe() == before
        return
    raise AssertionError("hostile supervisor state accepted")


def portable_supervisor_tests():
    kinds = ("writing", "pre-flush", "pre-publication", "publication-intent",
             "post-publication", "post-settlement", "success")
    raw = b"portable fixed contract\n"
    row = {"name": "fixed.bin", "raw": raw, "size": len(raw),
           "sha256": hashlib.sha256(raw).hexdigest()}
    for prefix in range(3):
        for kind in kinds:
            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                os.chmod(base, 0o700)
                current = base
                for name in CHAIN_NAMES[:prefix]:
                    current /= name
                    current.mkdir(mode=0o700)
                before = portable_fds()
                deadline = time.monotonic_ns() + 2 * NS
                chain = prepare_private_chain(base, deadline)
                assert chain["created_from"] == prefix + 1
                read_fd, write_fd = cloexec_pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(read_fd)
                    portable_child(write_fd, chain["fds"][3], chain["fds"][4], kind, row,
                                   1 if kind == "post-settlement" else 0)
                os.close(write_fd)
                # The failed full hosted suite took 13.4 s across these 21
                # cases, so a 500 ms per-phase portable-only window was below
                # observed concurrent-runner scheduling. Keep production bounds
                # unchanged and allow one second for each synthetic phase.
                phase = time.monotonic_ns() + NS
                result = supervise_child(pid, read_fd, phase, phase + NS, 100_000_000)
                os.close(read_fd)
                assert result["reaped"] and result["valid"]
                assert terminal_recovery_count(result) == (
                    1 if kind == "post-settlement" else 0)
                if kind in {"publication-intent", "post-settlement"}:
                    preserved, attempts, authority = state_tree(base), [], result
                    if kind == "publication-intent":
                        malformed = PipeRecord()
                        malformed.accept(b"x")
                        authority = {"valid": malformed.finish(), "terminal": malformed.terminal}
                    if recovery_allowed(authority, "needed"):
                        attempts.append("recovered")
                    assert not attempts and state_tree(base) == preserved
                cleanup_private_chain(chain, (row,), time.monotonic_ns() + NS)
                errors = []
                close_chain(chain, time.monotonic_ns() + NS, errors)
                assert not errors and portable_fds() == before
                assert tuple(sorted(os.listdir(base), key=os.fsencode)) == chain["retained"][0]
    with tempfile.TemporaryDirectory() as temporary:
        for with_cache in (False, True):
            base = Path(temporary) / ("cache" if with_cache else "artifacts")
            base.mkdir(mode=0o700)
            inherited = base / ".state/completion-v1/artifacts"
            inherited.mkdir(parents=True, mode=0o700)
            if with_cache:
                (inherited / "cache").mkdir(mode=0o700)
            rejected_unchanged(
                lambda: prepare_private_chain(base, time.monotonic_ns() + NS),
                lambda: state_tree(base),
            )
    record = PipeRecord()
    record.accept(encode_frame(PHASE_ACQUIRED, 1))
    record.accept(encode_frame(CUT_PHASES[0], 2))
    record.accept(encode_frame(PHASE_TERMINAL, 3, 1, 0))
    assert record.finish() and record.terminal[2] == 0
    for hostile in (b"x", encode_frame(PHASE_ACQUIRED, 1)[:-1],
                    encode_frame(PHASE_ACQUIRED, 1) + b"x"):
        uncertain = PipeRecord()
        uncertain.accept(hostile)
        assert not uncertain.finish()
    assert terminal_recovery_count({"valid": True, "terminal": (PHASE_TERMINAL, 1, 0)}) == 0
    assert terminal_recovery_count({"valid": True, "terminal": (PHASE_TERMINAL, 1, 1)}) == 1
    for mismatch in (False, True):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
            chain = prepare_private_chain(base, time.monotonic_ns() + NS)
            hostile = row["name"] if mismatch else "unknown"
            descriptor = os.open(hostile, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600, dir_fd=chain["fds"][4])
            os.write(descriptor, b"mismatch")
            os.close(descriptor)
            rejected_unchanged(
                lambda: cleanup_private_chain(chain, (row,), time.monotonic_ns() + NS),
                lambda: state_tree(base),
            )
            errors = []
            close_chain(chain, time.monotonic_ns() + NS, errors)
            assert not errors


def state_tree(base):
    paths = sorted(Path(base).rglob("*"), key=lambda item: os.fsencode(str(item)))
    return tuple((str(path.relative_to(base)), exact_identity(os.lstat(path))) for path in paths)


if sys.argv == [sys.argv[0]]:
    portable_tests()
elif sys.argv[1:] == ["--linux-synthetic"]:
    linux_synthetic_faults()
elif sys.argv[1:] == ["--hosted-exact"]:
    hosted_exact_input()
else:
    raise SystemExit("fixed candidate qualification mode required")

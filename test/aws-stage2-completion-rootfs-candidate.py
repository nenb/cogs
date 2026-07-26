#!/usr/bin/env python3
"""ADR 0057 portable policy, Linux synthetic faults, and hosted exact gate."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

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
    candidate_source = (REMOTE / "completion_rootfs_candidate.py").read_text()
    transaction_calls = ("canonical._canonical_metadata(", "fs._open_anonymous(",
                         "fs._link_anonymous(", "builder._append_candidate(")
    assert all(call in candidate_source for call in transaction_calls)
    assert "builder._recover_fixed(" not in candidate_source
    assert "_parse_ledger" not in candidate_source
    assert "subprocess" not in candidate_source and "socket" not in candidate_source
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

    shutil.rmtree(Path("/var/lib/cogs/stage2-completion-v1"))
    assert not any(Path("/var/lib/cogs").iterdir())
    print("completion rootfs candidate Linux synthetic F1-F6 tests passed")


def hosted_exact_input():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("COGS_ADR0057_HOSTED_EXACT") == "1"
    assert sys.platform == "linux" and os.geteuid() == 0
    fixed_remote = FIXED / "deploy/aws-feasibility/remote"
    names = (
        "completion_archive_preflight", "completion_rootfs_plan", "completion_rootfs_fs",
        "completion_rootfs_ledger", "completion_rootfs_builder", "completion_rootfs_materializer",
        "completion_rootfs_canonical", "completion_rootfs_publish", "completion_rootfs_candidate",
        "completion_rootfs_build",
    )
    sys.path.insert(0, str(fixed_remote))
    modules = {name: load(name, fixed_remote / f"{name}.py") for name in names}
    fs = modules["completion_rootfs_fs"]
    build = modules["completion_rootfs_build"]
    publication = modules["completion_rootfs_publish"]
    approval = fs.SourceApproval(
        os.environ["COGS_ADR0057_SOURCE_REVISION"],
        os.environ["COGS_ADR0057_SOURCE_MANIFEST_SHA256"],
    )
    cache = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    cache_before = tuple((path.name, path.read_bytes()) for path in sorted(cache.iterdir()))
    state_before = state_inventory()
    candidate_keys = []
    real_link = fs._link_anonymous

    def capture_link(directory, name, anonymous, control):
        candidate_keys.append(fs._observe_anonymous(anonymous, control).key)
        return real_link(directory, name, anonymous, control)

    fs._link_anonymous = capture_link
    outer = fs.OperationControl(time.monotonic_ns() + 3_300_000_000_000, lambda: False)
    try:
        first, second = build._two_build_outputs(approval, outer)
    finally:
        fs._link_anonymous = real_link
    build._require_equal_builds(first, second)
    pins = publication._load_pins()
    build._require_pinned(first, pins)
    build._require_pinned(second, pins)
    assert len(candidate_keys) == 2 and candidate_keys[0] != candidate_keys[1]
    assert tuple((path.name, path.read_bytes()) for path in sorted(cache.iterdir())) == cache_before
    assert state_inventory() == state_before
    print(json.dumps({
        "entry_count": first.entry_count, "manifest_sha256": first.manifest_sha256,
        "ustar_sha256": first.ustar_sha256, "ustar_size": first.ustar_size,
    }, sort_keys=True, separators=(",", ":")))


if sys.argv == [sys.argv[0]]:
    portable_tests()
elif sys.argv[1:] == ["--linux-synthetic"]:
    linux_synthetic_faults()
elif sys.argv[1:] == ["--hosted-exact"]:
    hosted_exact_input()
else:
    raise SystemExit("fixed candidate qualification mode required")

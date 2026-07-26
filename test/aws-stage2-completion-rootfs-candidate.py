#!/usr/bin/env python3
"""ADR 0057 portable policy, Linux synthetic faults, and hosted exact gate."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
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


def arm_deadline(deadline, signal_frame=None):
    remaining = 0 if signal_frame is not None else deadline - time.monotonic_ns()
    if remaining <= 0:
        raise TimeoutError("hosted qualification deadline")
    signal.setitimer(signal.ITIMER_REAL, remaining / NS)


def partial_cache_snapshot(runner, verifier, contract, directories):
    def fixed_file(directory, name, mode, size, digest):
        identity = runner._identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
        assert (identity["kind"], identity["mode"], identity["uid"], identity["gid"],
                identity["nlink"], identity["size"]) == ("file", mode, 0, 0, 1, size)
        descriptor = runner._owned_file(directory, name, identity, digest)
        os.close(descriptor)
        return identity

    root = runner._open_dir(runner.ARTIFACT_ROOT)
    cache = None
    try:
        sentinel_name = ".cogs-stage2-completion-artifacts-v1"
        assert verifier.SENTINEL == sentinel_name
        assert verifier.SENTINEL_BYTES == b"cogs-stage2-completion-artifacts-v1\n"
        assert runner._same_directory_authority(os.fstat(root), directories["root"])
        assert set(os.listdir(root)) == {"cache", sentinel_name}
        cache = os.open("cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        assert runner._same_directory_authority(os.fstat(cache), directories["cache"])
        rows = {row["cache_name"]: row for row in runner._artifact_rows(contract)}
        names = set(os.listdir(cache))
        assert names <= set(rows)
        files = []
        for name in sorted(names):
            row = rows[name]
            identity = fixed_file(cache, name, 0o400, row["size"], row["sha256"])
            files.append({"name": name, "identity": identity, "sha256": row["sha256"]})
        sentinel_digest = hashlib.sha256(verifier.SENTINEL_BYTES).hexdigest()
        sentinel_identity = fixed_file(
            root, sentinel_name, 0o600, len(verifier.SENTINEL_BYTES), sentinel_digest)
        return {"root": runner._identity(os.fstat(root)), "cache": runner._identity(os.fstat(cache)),
                "sentinel": {"identity": sentinel_identity, "sha256": sentinel_digest}, "files": files}
    finally:
        if cache is not None:
            os.close(cache)
        os.close(root)


def hosted_exact_input():
    raw_anchor = os.environ["COGS_STAGE2_PHASE_A_BUDGET_ANCHOR_NS"]
    assert raw_anchor.isascii() and raw_anchor.isdigit() and raw_anchor[0] != "0"
    anchor = int(raw_anchor)
    assert anchor <= time.monotonic_ns() and anchor <= (1 << 63) - 1
    deadlines = tuple(anchor + seconds * NS for seconds in (600, 3900, 4500, 5100, 5400))
    source_deadline, build_deadline, recovery_deadline, cleanup_deadline, final_deadline = deadlines
    runner = verifier = fs = builder = build = publication = None
    contract = cache_owned = cache_directories = rootfs_baseline = first = second = None
    cache_baseline = temporary_baseline = descriptors_before = None
    temporary_paths = ()
    candidate_keys, recovery_uses = [], []
    bootstrap_started = False
    errors = []

    def capture_link(directory, name, anonymous, control):
        observed = os.fstat(anonymous.number)
        candidate_keys.append((observed.st_dev, observed.st_ino))
        return real_link(directory, name, anonymous, control)

    def mark_recovery():
        recovery_uses.append(time.monotonic_ns())
        assert len(recovery_uses) == 1

    def counted_recovery(control):
        mark_recovery()
        return real_recovery(control)

    def cleanup_cache():
        nonlocal cache_owned
        assert runner is not None
        if cache_owned is None and cache_directories is not None and contract is not None:
            cache_owned = partial_cache_snapshot(runner, verifier, contract, cache_directories)
        if cache_owned is not None:
            runner._cleanup_artifacts(({"kind": "cache-owned", "body": cache_owned},))
        else:
            assert runner._held_path_absent(runner.ARTIFACT_ROOT)

    def rootfs_restored():
        if runner is None:
            return not os.path.lexists(STATE)
        if rootfs_baseline is None:
            return runner._held_path_absent(runner.ROOTFS_STATE)
        return runner._same_rootfs_lifecycle(runner._snapshot_rootfs_lifecycle(), rootfs_baseline)

    previous_alarm = signal.signal(signal.SIGALRM, arm_deadline)
    try:
        try:
            arm_deadline(source_deadline)
            descriptors_before = fd_inventory()
            assert os.environ.get("GITHUB_ACTIONS") == "true"
            assert os.environ.get("COGS_ADR0057_HOSTED_EXACT") == "1"
            runner = load("hosted_stage2_runner", FIXED / "scripts/run-stage2-phase-a-candidate.py")
            runner._fixed_preflight(True)
            revision, manifest_sha256 = runner._source_approval()
            assert revision == os.environ["COGS_ADR0057_SOURCE_REVISION"]
            assert manifest_sha256 == os.environ["COGS_ADR0057_SOURCE_MANIFEST_SHA256"]
            runner._verify_fixed_source(revision, manifest_sha256)
            verifier = runner._load_artifact_verifier()
            module_names = ("completion_rootfs_fs", "completion_rootfs_builder",
                            "completion_rootfs_build", "completion_rootfs_publish")
            fs, builder, build, publication = map(__import__, module_names)
            approval = fs.SourceApproval(revision, manifest_sha256)
            temporary_paths = (runner.STATE, runner.ANCHOR)
            cache_baseline = runner._held_path_absent(runner.ARTIFACT_ROOT)
            temporary_baseline = tuple(runner._held_path_absent(path) for path in temporary_paths)
            assert cache_baseline and all(temporary_baseline) and runner._held_path_absent(runner.ROOTFS_STATE)
            contract = runner._verifier_call(
                verifier, "rootfs-contract-preflight", lambda: verifier.verify_contract(verifier.CONTRACT_PATH))
            acquisition = __import__("completion_artifact_acquisition")
            real_private_chain = acquisition._open_private_chain

            def capture_private_chain(path):
                nonlocal cache_directories
                chain = real_private_chain(path)
                try:
                    assert Path(path) == runner.ARTIFACT_ROOT and cache_directories is None
                    cache_directories = {"root": runner._identity(os.fstat(chain[-2])),
                                         "cache": runner._identity(os.fstat(chain[-1]))}
                    assert all(identity["kind"] == "directory" and identity["mode"] == 0o700 and
                               identity["uid"] == identity["gid"] == 0
                               for identity in cache_directories.values())
                    assert set(os.listdir(chain[-2])) == {"cache"} and not os.listdir(chain[-1])
                    return chain
                except BaseException:
                    for descriptor in reversed(chain):
                        os.close(descriptor)
                    raise

            acquisition._open_private_chain = capture_private_chain
            try:
                acquire = lambda: verifier.acquire_completion_artifacts(
                    verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT)
                runner._verifier_call(verifier, "cache-acquisition-unknown", acquire, True)
            finally:
                acquisition._open_private_chain = real_private_chain
            runner._verifier_call(
                verifier, "cache-postverify",
                lambda: verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT))
            cache_owned = runner._snapshot_cache(contract)
            now = time.monotonic_ns()
            outer_deadline = min(now + build.OUTER_SECONDS * NS, build_deadline)
            assert now < outer_deadline
            outer = fs.OperationControl(outer_deadline, lambda: False)
            bootstrap_started = True
            runner._bootstrap_rootfs(builder, fs, approval, outer)
            rootfs_baseline = runner._snapshot_rootfs_lifecycle()
            arm_deadline(build_deadline)
            real_link, real_recovery = fs._link_anonymous, builder._recover_fixed
            fs._link_anonymous = capture_link
            builder._recover_fixed = counted_recovery
            try:
                first, second = build._two_build_outputs(approval, outer)
            finally:
                builder._recover_fixed = real_recovery
                fs._link_anonymous = real_link
            pins = publication._load_pins()
            build._require_pinned(first, pins)
            build._require_pinned(second, pins)
            assert len(candidate_keys) == 2 and candidate_keys[0] != candidate_keys[1]
            assert runner._snapshot_cache(contract) == cache_owned
        except BaseException as error:
            errors.append(error)

        if errors and bootstrap_started and not recovery_uses:
            try:
                assert time.monotonic_ns() + (builder.RECOVER_SECONDS + 1) * NS <= recovery_deadline
                arm_deadline(recovery_deadline)
                mark_recovery()
                runner._recover_rootfs([])
            except BaseException as error:
                errors.append(error)

        cleanup_actions = (
            cleanup_cache,
            rootfs_restored,
            lambda: cache_baseline is not None and
                    runner._held_path_absent(runner.ARTIFACT_ROOT) == cache_baseline,
            lambda: temporary_baseline is not None and tuple(
                runner._held_path_absent(path) for path in temporary_paths) == temporary_baseline,
            lambda: descriptors_before is not None and fd_inventory() == descriptors_before,
        )
        for action in cleanup_actions:
            try:
                arm_deadline(cleanup_deadline)
                assert action() is not False
            except BaseException as error:
                errors.append(error)

        try:
            arm_deadline(final_deadline)
        except BaseException as error:
            errors.append(error)
    except BaseException as error:
        errors.append(error)
    finally:
        for close_signal in (
                lambda: signal.setitimer(signal.ITIMER_REAL, 0),
                lambda: signal.signal(signal.SIGALRM, previous_alarm)):
            try:
                close_signal()
            except BaseException as error:
                errors.append(error)

    if errors and fs is None:
        raise BaseExceptionGroup("hosted qualification failures", errors)
    error = None
    for added in errors:
        error = added if error is None else fs.RootfsFsError(error, added)
    if error is not None:
        raise error
    result = {"entry_count": first.entry_count, "manifest_sha256": first.manifest_sha256,
              "ustar_sha256": first.ustar_sha256, "ustar_size": first.ustar_size}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if sys.argv == [sys.argv[0]]:
    portable_tests()
elif sys.argv[1:] == ["--linux-synthetic"]:
    linux_synthetic_faults()
elif sys.argv[1:] == ["--hosted-exact"]:
    hosted_exact_input()
else:
    raise SystemExit("fixed candidate qualification mode required")

#!/usr/bin/env python3
"""Non-authoritative retained-rootfs package candidate (V2 only).
V1 deliberately describes the host route and remains immutable.  This module
owns the distinct result contract for execution in the retained Stage 2 rootfs.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import completion_workload_owner as workload_owner
from completion_fixtures import SOURCE_EPOCH, fixed_fixtures
from completion_guest_workloads import (CleanupUncertain, Deadline, LIFECYCLE_SECONDS, OwnedRoot,
    SignalScope, ToolSet, WorkloadError, WorkloadInterrupted, _ENV, _check_versions, _materialize,
    _remove_relative, _status_fields, _verify_installed, require_linux_amd64_root)
from completion_runtime_contract import (PackageIdentity, canonical_json, exact_runtime_closure,
    exact_tool_observations, load_candidate_contract, native_execution_binding,
    native_implementation_digests, validate_native_candidate_result)
CANDIDATE_ROOT = Path("/tmp/cogs-stage2-workload-candidate-v2")
FIXED_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
FIXED_NATIVE_DRIVER = FIXED_SOURCE / "scripts/run-stage2-package-native-candidate.py"
FIXED_SOURCE_MANIFEST = FIXED_SOURCE / ".cogs-stage2-source-manifest-v1.json"
MAX_OUTPUT_BYTES = 4096
MAX_PACKAGE_EFFECT_BYTES = 4_194_304
# Captured after fixed-source verification and while its names are still visible,
# before namespace/chroot entry removes access to the source directory.
NATIVE_LAUNCHER_BYTES = FIXED_NATIVE_DRIVER.read_bytes()
NATIVE_LAUNCHER_SHA256 = hashlib.sha256(NATIVE_LAUNCHER_BYTES).hexdigest()
SOURCE_MANIFEST_BYTES = FIXED_SOURCE_MANIFEST.read_bytes()
SOURCE_MANIFEST_SHA256 = hashlib.sha256(SOURCE_MANIFEST_BYTES).hexdigest()
SOURCE_REVISION = json.loads(SOURCE_MANIFEST_BYTES)["revision"]
# Cache all fixed-source implementation bytes before chroot hides the source tree.
NATIVE_IMPLEMENTATION_DIGESTS = native_implementation_digests()
class NativeCandidateTransactionError(WorkloadError):
    category = "native-candidate-mismatch"


class NativeCommandObserved(WorkloadError):
    def __init__(self, return_code, raw):
        code = str(return_code) if type(return_code) is int and -255 <= return_code <= 255 else "invalid"
        lowered = raw.lower()
        details = (
            (b"admindir must be inside instdir", "admin-outside-install"),
            (b"not found in path or not executable", "required-tool-missing"),
            (b"cannot access archive", "archive-access"),
            (b"database lock", "database-lock"),
            (b"frontend lock", "database-lock"),
            (b"dpkg database directory", "database-access"),
            (b"backup file", "database-backup"),
            (b"status file", "database-status"),
            (b"log file", "log-access"),
            (b"failed to chdir", "directory-enter"),
            (b"failed to chroot", "directory-enter"),
            (b"unable to stat", "metadata-access"),
            (b"cannot stat", "metadata-access"),
            (b"unable to execute", "execute-access"),
            (b"failed to write", "write-access"),
            (b"cannot write", "write-access"),
            (b"failed to read", "read-access"),
            (b"cannot read", "read-access"),
            (b"unable to lock", "lock-access"),
            (b"cannot mkdir", "directory-create"),
            (b"cannot change ownership", "ownership-update"),
            (b"cannot chown", "ownership-update"),
            (b"cannot chmod", "mode-update"),
            (b"cannot utime", "time-update"),
            (b"cannot rename", "rename-access"),
            (b"cannot remove", "remove-access"),
            (b"failed to make temporary file", "temporary-file"),
            (b"file size limit exceeded", "file-size-limit"),
            (b"unknown option", "unknown-option"),
            (b"unable to create", "create-failed"),
            (b"unable to open", "open-failed"),
            (b"cannot open", "open-failed"),
            (b"dpkg-deb:", "archive-helper"),
            (b"tar:", "archive-tar"),
            (b"subprocess", "subprocess-failed"),
            (b"read-only file system", "read-only"),
            (b"permission denied", "permission-denied"),
            (b"no such file or directory", "path-missing"),
        )
        detail = next((token for needle, token in details if needle in lowered), None)
        if detail is None:
            detail = f"warning-{int(b'warning' in lowered)}-error-{int(b'error' in lowered)}"
        self.category = f"exit-{code}-{detail}-bytes-{len(raw)}"
        super().__init__("native command returned a rejected bounded observation")


class NativeCandidateStageError(WorkloadError):
    def __init__(self, stage, cause):
        self.stage = stage
        if isinstance(cause, (KeyboardInterrupt, SystemExit)):
            category = "interrupted"
        elif isinstance(cause, OSError) and cause.errno is not None:
            category = f"OSError_{cause.errno}"
        else:
            category = getattr(cause, "category", type(cause).__name__)
        safe = (isinstance(category, str) and 1 <= len(category) <= 64
                and all(value.isascii() and (value.isalnum() or value in "_-")
                        for value in category))
        self.category = category if safe else "native-candidate-mismatch"
        super().__init__(stage)


def _stage_failure(stage, cause):
    if isinstance(cause, NativeCandidateStageError):
        return cause
    nested = getattr(cause, "stage", None)
    combined = f"{stage}-{nested}" if isinstance(nested, str) else stage
    safe = (1 <= len(combined) <= 64
            and all(value.isascii() and (value.isalnum() or value in "_-")
                    for value in combined))
    return NativeCandidateStageError(combined if safe else stage, cause)


class _StagedSignalScope:
    def __init__(self):
        self.scope = SignalScope()

    def __enter__(self):
        return self.scope.__enter__()

    def __exit__(self, *arguments):
        try:
            return self.scope.__exit__(*arguments)
        except BaseException as error:
            raise _stage_failure("signal-scope-close", error) from error


def _require(condition):
    if not condition:
        raise NativeCandidateTransactionError("native candidate invariant failed")
def _finish_root(root, failure):
    if root is not None:
        try:
            root.cleanup()
        except CleanupUncertain as error:
            return error
        except BaseException:
            return CleanupUncertain("owned cleanup was interrupted or failed")
    return failure
def _raise_failure(failure):
    if failure is None:
        return
    if isinstance(failure, (WorkloadError, KeyboardInterrupt, SystemExit)):
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise WorkloadInterrupted("transaction interrupted") from None
        raise failure
    raise NativeCandidateTransactionError("native candidate transaction failed") from None


def _limit_package_effects():
    # This assignment occurs only in the already-forked child.  The shared owner
    # then applies the identical identity/capability boundary with this fixed,
    # package-sized per-file limit instead of its command-log-sized limit.
    workload_owner.MAX_COMMAND_OUTPUT = MAX_PACKAGE_EFFECT_BYTES
    workload_owner._limit_output()


def _run_native_command(argv, root, deadline, pass_fds=(), environment=None,
                        package_effects=False):
    """Mirror the fixed command owner while retaining only bounded categorical failure facts."""
    workload_owner._require(type(argv) is tuple and argv and all(type(item) is str and item for item in argv))
    workload_owner._require(type(package_effects) is bool)
    selected_environment = dict(_ENV) if environment is None else dict(environment)
    output_fd = -1
    process = None
    raw = b""
    failure = None
    try:
        output_fd = os.open(
            "command.out", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600, dir_fd=root.fd)
        os.fchown(output_fd, workload_owner.WORKLOAD_UID, workload_owner.WORKLOAD_GID)
        output_status = os.fstat(output_fd)
        workload_owner._require(
            stat.S_ISREG(output_status.st_mode) and output_status.st_nlink == 1
            and output_status.st_uid == workload_owner.WORKLOAD_UID
            and output_status.st_gid == workload_owner.WORKLOAD_GID)
        workload_owner._require(stat.S_IMODE(output_status.st_mode) == 0o600)
        process = subprocess.Popen(
            argv,
            cwd=root.proc_path(),
            env=root.child_environment(selected_environment),
            stdin=subprocess.DEVNULL,
            stdout=output_fd,
            stderr=subprocess.STDOUT,
            close_fds=True,
            pass_fds=tuple({root.fd, *pass_fds}),
            start_new_session=True,
            preexec_fn=_limit_package_effects if package_effects else workload_owner._limit_output,
        )
        return_code = workload_owner._wait_process(process, deadline.effect_seconds())
        if return_code is None:
            raise workload_owner.WorkloadDeadline("fixed child exceeded parent deadline")
        workload_owner._drain_descendants(deadline, fail_if_found=True)
        os.fsync(output_fd)
        raw = workload_owner._read_fd(output_fd, workload_owner.MAX_COMMAND_OUTPUT)
        after = os.fstat(output_fd)
        current = os.stat("command.out", dir_fd=root.fd, follow_symlinks=False)
        workload_owner._require(
            after.st_nlink == 1
            and workload_owner._status_identity(after) == workload_owner._status_identity(current))
        if return_code != 0 or b"warning" in raw.lower() or b"error" in raw.lower():
            raise NativeCommandObserved(return_code, raw)
    except BaseException as error:
        failure = error
        if process is not None and process.poll() is None:
            try:
                workload_owner._terminate_leader(process, deadline)
            except BaseException as cleanup_error:
                failure = cleanup_error
        try:
            workload_owner._drain_descendants(deadline)
        except BaseException as cleanup_error:
            failure = cleanup_error
    finally:
        if output_fd >= 0:
            try:
                root.remove_output(output_fd)
            except BaseException as cleanup_error:
                failure = cleanup_error
            os.close(output_fd)
    if failure is not None:
        if isinstance(failure, WorkloadError):
            raise failure
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise WorkloadInterrupted("transaction interrupted") from None
        raise WorkloadError("fixed command failed") from None
    return raw


def _run_native_package_sample(root, label, diagnostic_prefix, tools, deadline):
    _require(label in {"candidate-a", "candidate-b"})
    _require(diagnostic_prefix in {"build-a", "build-b"})
    fixture = fixed_fixtures().package
    prefix = f"package-{label}"
    source = f"{prefix}/source"
    deb = f"{prefix}/cogs-stage2-fixture_1.0_all.deb"
    admin = f"{prefix}/dpkg-admin"
    installed = f"{prefix}/installed"
    stage, failure = "package-parent", None
    try:
        root.mkdir(prefix, 0o700)
    except BaseException as error:
        raise _stage_failure(f"{diagnostic_prefix}-{stage}", error) from error
    package_environment = {
        **_ENV,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "private-tmp",
    }
    stage = "package-source"
    try:
        _materialize(fixture.source.records, root, source)
        stage = "dpkg-build"
        build_start = time.monotonic_ns()
        _run_native_command(
            (
                tools.dpkg_deb.executable,
                "--build",
                "--root-owner-group",
                "-Zxz",
                "-z6",
                "--threads-max=1",
                source,
                deb,
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
            environment=package_environment,
            package_effects=True,
        )
        build_ms = (time.monotonic_ns() - build_start) // 1_000_000
        stage = "deb-readback"
        deb_raw, deb_status = root.read_file(deb, 4_194_304)
        _require(0 < len(deb_raw) == deb_status.st_size)
        stage = "admin-setup"
        root.mkdir(admin, 0o700)
        root.mkdir(f"{admin}/updates", 0o700)
        root.write_file(f"{admin}/status", b"", 0o600)
        root.mkdir(installed, 0o755)
        installed_fd = root._open_dir(installed)
        try:
            os.utime(installed_fd, (SOURCE_EPOCH, SOURCE_EPOCH))
        finally:
            os.close(installed_fd)
        stage = "dpkg-install"
        install_start = time.monotonic_ns()
        _run_native_command(
            (
                tools.dpkg.executable,
                "--force-not-root",
                f"--log={prefix}/dpkg.log",
                "--admindir",
                admin,
                "--instdir",
                f"{installed}/",
                "--install",
                deb,
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
            environment=package_environment,
            package_effects=True,
        )
        install_ms = (time.monotonic_ns() - install_start) // 1_000_000
        stage = "installed-mtime-normalize"
        for record in reversed(fixture.installed.records):
            if record.kind != "directory":
                continue
            relative = installed if record.path == "." else f"{installed}/{record.path}"
            descriptor = root._open_dir(relative)
            try:
                os.utime(descriptor, (record.mtime, record.mtime))
            finally:
                os.close(descriptor)
        stage = "installed-tree"
        observed = _verify_installed(root, installed)
        stage = "status-readback"
        fields = _status_fields(root, f"{admin}/status")
        stage = "status-verify"
        _require(
            (fields.get("Package"), fields.get("Version"), fields.get("Architecture"), fields.get("Status"))
            == (observed.package, observed.version, observed.architecture, observed.status)
        )
        stage = "identity"
        identity = PackageIdentity(
            hashlib.sha256(deb_raw).hexdigest(),
            len(deb_raw),
            observed.logical_digest,
            observed.entry_count,
            observed.regular_bytes,
            observed.package,
            observed.version,
            observed.architecture,
        )
    except BaseException as error:
        failure = _stage_failure(f"{diagnostic_prefix}-{stage}", error)
    finally:
        try:
            _remove_relative(root, prefix, deadline)
        except BaseException as error:
            failure = _stage_failure(f"{diagnostic_prefix}-package-cleanup", error)
    _raise_failure(failure)
    stage = "duration"
    try:
        _require(0 <= build_ms <= LIFECYCLE_SECONDS * 1000
                 and 0 <= install_ms <= LIFECYCLE_SECONDS * 1000)
    except BaseException as error:
        raise _stage_failure(f"{diagnostic_prefix}-{stage}", error) from error
    return identity, build_ms, install_ms


def run_candidate_transaction():
    """Build A and B once using authentic retained-rootfs Git/dpkg tools."""
    deadline = Deadline.start()
    root = tools = failure = result = None
    stage = "transaction-inputs"
    try:
        _require(0 < len(NATIVE_LAUNCHER_BYTES) <= 256 * 1024)
        _require(0 < len(SOURCE_MANIFEST_BYTES) <= 16 * 1024 * 1024)
        _require(SOURCE_REVISION == os.environ.get("COGS_PACKAGE_REVIEWED_HEAD"))
        launcher_sha256 = NATIVE_LAUNCHER_SHA256
        with _StagedSignalScope():
            try:
                stage = "contract-load"
                contract = load_candidate_contract()
                stage = "platform-check"
                require_linux_amd64_root()
                stage = "runtime-closure"
                runtime_closure = exact_runtime_closure()
                stage = "tool-open"
                tools = ToolSet()
                stage = "owned-root"
                root = OwnedRoot(CANDIDATE_ROOT, deadline, "host-candidate")
                root.mkdir("private-home", 0o700)
                root.mkdir("private-tmp", 0o700)
                stage = "tool-version"
                _check_versions(root, tools, deadline)
                stage = "tool-observations"
                tool_observations = exact_tool_observations(tools.observations())
                stage = "build-a"
                first, _build_a_ms, _install_a_ms = _run_native_package_sample(
                    root, "candidate-a", "build-a", tools, deadline)
                stage = "post-a-tools"
                _require(exact_tool_observations(tools.observations()) == tool_observations)
                stage = "post-a-contract"
                _require(load_candidate_contract() == contract)
                stage = "build-b"
                second, _build_b_ms, _install_b_ms = _run_native_package_sample(
                    root, "candidate-b", "build-b", tools, deadline)
                stage = "compare-a-b"
                _require(first == second)
                stage = "post-b-tools"
                _require(exact_tool_observations(tools.observations()) == tool_observations)
                stage = "post-b-contract"
                _require(load_candidate_contract() == contract)
                stage = "result-binding"
                result = {
                    "version": "cogs.stage2-workload-candidate/v2",
                    "result": "pass",
                    "authority": "non-authoritative-retained-rootfs-candidate-only",
                    "candidate_contract_sha256": contract.sha256,
                    "final_pin_sha256": None,
                    "package_identity": first.value(),
                    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
                    "a_equals_b": True,
                    "lifecycle_deleted": True,
                    "promotion": "external-manual-review-required",
                    "execution_binding": native_execution_binding(
                        tool_observations, runtime_closure, launcher_sha256,
                        SOURCE_REVISION, SOURCE_MANIFEST_SHA256),
                }
            except BaseException as error:
                failure = _stage_failure(stage, error)
            finally:
                cleaned = _finish_root(root, failure)
                if cleaned is not failure:
                    failure = _stage_failure("transaction-cleanup", cleaned)
                if tools is not None:
                    try:
                        tools.close()
                    except BaseException as error:
                        failure = _stage_failure("tool-close", error)
        _raise_failure(failure)
        stage = "result-presence"
        _require(result is not None)
        stage = "result-validation"
        validate_native_candidate_result(result, SOURCE_REVISION, SOURCE_MANIFEST_SHA256)
        stage = "result-encoding"
        raw = canonical_json(result)
        _require(len(raw) <= MAX_OUTPUT_BYTES)
        return raw
    except NativeCandidateStageError:
        raise
    except BaseException as error:
        raise _stage_failure(stage, error) from error

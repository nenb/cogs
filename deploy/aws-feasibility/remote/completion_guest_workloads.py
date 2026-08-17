#!/usr/bin/env python3
"""Fixed local Git and Debian-package workload implementation for ADR 0099."""

import hashlib
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import time

from completion_fixtures import SOURCE_EPOCH, fixed_fixtures
from completion_runtime_contract import PackageIdentity

GIT = "/usr/bin/git"
DPKG_DEB = "/usr/bin/dpkg-deb"
DPKG = "/usr/bin/dpkg"
COMMAND_TIMEOUT_SECONDS = 300
MAX_COMMAND_OUTPUT = 65_536
_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": str(SOURCE_EPOCH),
    "TZ": "UTC",
}


class WorkloadError(Exception):
    """A fixed workload or its cleanup did not complete exactly."""


def _require(condition, message="workload invariant failed"):
    if not condition:
        raise WorkloadError(message)


def _limit_output():
    os.umask(0o022)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))


def _run(argv, cwd, output_path, expected=None, environment=None):
    """Run one fixed command once, with bounded non-evidence output and no inherited env."""
    _require(type(argv) is tuple and argv and all(type(item) is str and item for item in argv))
    _require(output_path.parent == cwd or output_path.parent in cwd.parents or cwd in output_path.parents)
    env = dict(_ENV if environment is None else environment)
    try:
        with output_path.open("w+b") as output:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_limit_output,
            )
            try:
                return_code = process.wait(COMMAND_TIMEOUT_SECONDS)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            output.flush()
            os.fsync(output.fileno())
            output.seek(0)
            raw = output.read(MAX_COMMAND_OUTPUT + 1)
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkloadError("fixed command failed") from error
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except OSError as error:
            raise WorkloadError("command output cleanup failed") from error
    _require(return_code == 0 and len(raw) <= MAX_COMMAND_OUTPUT, "fixed command failed")
    _require(b"warning" not in raw.lower() and b"error" not in raw.lower(), "fixed command emitted a diagnostic")
    if expected is not None:
        _require(raw == expected, "fixed command output mismatch")
    return raw


def _remove_owned(path):
    try:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise WorkloadError("owned path identity changed")
        if path.exists():
            shutil.rmtree(path)
    except OSError as error:
        raise WorkloadError("owned path cleanup failed") from error
    _require(not os.path.lexists(path), "owned path remains")


def _fresh_directory(path):
    _require(not os.path.lexists(path), "fixed fresh path already exists")
    try:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700, follow_symlinks=False)
    except OSError as error:
        raise WorkloadError("fixed fresh path creation failed") from error
    mode = os.lstat(path).st_mode
    _require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), "fresh path is not a directory")
    _require(stat.S_IMODE(mode) == 0o700, "fresh path mode is invalid")


def _materialize(records, root):
    _fresh_directory(root)
    directories = []
    try:
        for record in records:
            destination = root if record.path == "." else root / record.path
            _require(record.kind in {"directory", "file"})
            if record.kind == "directory":
                if record.path != ".":
                    destination.mkdir(mode=record.mode)
                directories.append((destination, record))
            else:
                _require(destination.parent.is_dir() and type(record.content) is bytes)
                with destination.open("xb") as stream:
                    stream.write(record.content)
                os.chmod(destination, record.mode, follow_symlinks=False)
                os.utime(destination, (record.mtime, record.mtime), follow_symlinks=False)
        for destination, record in reversed(directories):
            os.chmod(destination, record.mode, follow_symlinks=False)
            os.utime(destination, (record.mtime, record.mtime), follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise WorkloadError("fixture materialization failed") from error


def _git_environment():
    return {
        **_ENV,
        "GIT_AUTHOR_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_AUTHOR_EMAIL": "cogs-stage2",
        "GIT_AUTHOR_NAME": "Cogs Stage 2",
        "GIT_COMMITTER_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_COMMITTER_EMAIL": "cogs-stage2",
        "GIT_COMMITTER_NAME": "Cogs Stage 2",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _prepare_git_fixture(lifecycle):
    fixture = fixed_fixtures().git
    source = lifecycle / "git-source"
    bare = lifecycle / "git-fixture.git"
    _materialize(fixture.source.records, source)
    output = lifecycle / "command.out"
    try:
        env = _git_environment()
        _run((GIT, "init", "--quiet", "--initial-branch=main", str(source)), lifecycle, output, b"", env)
        _run((GIT, "-C", str(source), "add", "--all"), lifecycle, output, b"", env)
        _run((GIT, "-C", str(source), "commit", "--quiet", "--message=cogs stage2 fixture v1"), lifecycle, output, b"", env)
        observed = _run((GIT, "-C", str(source), "rev-parse", "HEAD"), lifecycle, output, fixture.commit_oid.encode() + b"\n", env)
        _require(observed.strip().decode("ascii") == fixture.commit_oid)
        _run((GIT, "clone", "--quiet", "--bare", "--no-hardlinks", str(source), str(bare)), lifecycle, output, b"", env)
        _run((GIT, f"--git-dir={bare}", "rev-parse", "refs/heads/main"), lifecycle, output, fixture.commit_oid.encode() + b"\n", env)
    finally:
        _remove_owned(source)
    return bare


def _run_git_sample(lifecycle, bare, sample):
    _require(type(sample) is int and 1 <= sample <= 7)
    fixture = fixed_fixtures().git
    path = lifecycle / f"git-{sample:02d}"
    _require(not os.path.lexists(path))
    output = lifecycle / "command.out"
    start = time.monotonic_ns()
    try:
        env = _git_environment()
        _run((GIT, "clone", "--quiet", "--no-hardlinks", "--no-tags", str(bare), str(path)), lifecycle, output, b"", env)
        _run((GIT, "-C", str(path), "checkout", "--quiet", "--detach", fixture.commit_oid), lifecycle, output, b"", env)
        for mutation in fixture.mutations:
            destination = path / mutation.path
            if mutation.operation == "append":
                with destination.open("ab") as stream:
                    stream.write(mutation.payload)
            else:
                _require(mutation.operation == "create" and not os.path.lexists(destination))
                destination.parent.mkdir(mode=0o755, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(mutation.payload)
        _run((GIT, "-C", str(path), "status", "--porcelain=v1", "--untracked-files=all"), lifecycle, output, fixture.porcelain, env)
        duration = (time.monotonic_ns() - start) // 1_000_000
    finally:
        _remove_owned(path)
    _require(type(duration) is int and 0 <= duration <= COMMAND_TIMEOUT_SECONDS * 4 * 1000)
    return duration


def _verify_installed(root):
    expected = fixed_fixtures().package.installed
    observed = {}
    try:
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories.sort()
            files.sort()
            relative_root = os.path.relpath(current, root)
            observed["." if relative_root == "." else relative_root] = os.lstat(current)
            for name in files:
                relative = name if relative_root == "." else f"{relative_root}/{name}"
                observed[relative] = os.lstat(Path(current) / name)
    except OSError as error:
        raise WorkloadError("installed tree walk failed") from error
    expected_map = {record.path: record for record in expected.records}
    _require(tuple(sorted(observed)) == tuple(sorted(expected_map)), "installed tree paths differ")
    for path, record in expected_map.items():
        status = observed[path]
        _require(status.st_uid == status.st_gid == 0)
        _require(stat.S_IMODE(status.st_mode) == record.mode)
        _require(status.st_mtime_ns == record.mtime * 1_000_000_000)
        _require(stat.S_ISDIR(status.st_mode) == (record.kind == "directory"))
        if record.kind == "file":
            _require(stat.S_ISREG(status.st_mode) and not stat.S_ISLNK(status.st_mode))
            raw = (root / path).read_bytes()
            _require(len(raw) == record.size and hashlib.sha256(raw).hexdigest() == record.content_sha256)
    return expected


def _status_fields(status_path):
    try:
        raw = status_path.read_bytes()
    except OSError as error:
        raise WorkloadError("dpkg status read failed") from error
    _require(0 < len(raw) <= 4096 and b"\x00" not in raw)
    fields = {}
    for line in raw.decode("utf-8").splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            _require(key not in fields)
            fields[key] = value
    return fields


def _run_package_sample(lifecycle, label):
    _require(label in {"candidate-a", "candidate-b", *(f"sample-{index:02d}" for index in range(1, 8))})
    fixture = fixed_fixtures().package
    path = lifecycle / f"package-{label}"
    source = path / "source"
    deb = path / "cogs-stage2-fixture_1.0_all.deb"
    admin = path / "dpkg-admin"
    installed = path / "installed"
    output = lifecycle / "command.out"
    _fresh_directory(path)
    try:
        _materialize(fixture.source.records, source)
        build_start = time.monotonic_ns()
        build_command = (
            DPKG_DEB,
            "--build",
            "--root-owner-group",
            "--compression=xz",
            "--compression-level=6",
            "--threads-max=1",
            str(source),
            str(deb),
        )
        _run(build_command, lifecycle, output)
        build_ms = (time.monotonic_ns() - build_start) // 1_000_000
        status = os.lstat(deb)
        _require(stat.S_ISREG(status.st_mode) and not stat.S_ISLNK(status.st_mode) and 0 < status.st_size <= 4_194_304)
        deb_raw = deb.read_bytes()
        _require(len(deb_raw) == status.st_size)
        _fresh_directory(admin)
        (admin / "updates").mkdir(mode=0o700)
        (admin / "status").write_bytes(b"")
        _fresh_directory(installed)
        os.chmod(installed, 0o755, follow_symlinks=False)
        os.utime(installed, (SOURCE_EPOCH, SOURCE_EPOCH), follow_symlinks=False)
        install_start = time.monotonic_ns()
        _run((DPKG, "--admindir", str(admin), "--instdir", f"{installed}/", "--install", str(deb)), lifecycle, output)
        install_ms = (time.monotonic_ns() - install_start) // 1_000_000
        observed = _verify_installed(installed)
        fields = _status_fields(admin / "status")
        status_identity = (
            fields.get("Package"),
            fields.get("Version"),
            fields.get("Architecture"),
            fields.get("Status"),
        )
        expected_status = (observed.package, observed.version, observed.architecture, observed.status)
        _require(status_identity == expected_status)
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
    finally:
        _remove_owned(path)
    _require(0 <= build_ms <= COMMAND_TIMEOUT_SECONDS * 1000 and 0 <= install_ms <= COMMAND_TIMEOUT_SECONDS * 1000)
    return identity, build_ms, install_ms

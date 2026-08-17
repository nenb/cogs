#!/usr/bin/env python3
"""Fixed non-authoritative host Git and package workloads for ADR 0099."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import time

from completion_fixtures import SOURCE_EPOCH, fixed_fixtures
from completion_runtime_contract import PackageIdentity, _open_regular, _read_open_regular, _status_identity
from completion_workload_owner import (
    CleanupUncertain,
    Deadline,
    OwnedRoot,
    OutputUncertain,
    PROCESS_CONTAINMENT,
    PROCESS_LIMITATION,
    SignalScope,
    WorkloadDeadline,
    WorkloadError,
    WorkloadInterrupted,
    _children,
    _drain_descendants,
    _enable_subreaper,
    _read_fd,
    _require,
    _run as _owned_run,
)

GIT = "/usr/bin/git"
DPKG_DEB = "/usr/bin/dpkg-deb"
DPKG = "/usr/bin/dpkg"
LIFECYCLE_SECONDS = 1200.0
MAX_COMMAND_OUTPUT = 65_536
_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": str(SOURCE_EPOCH),
    "TZ": "UTC",
    "TMPDIR": "/nonexistent",
}


def _run(argv, root, deadline, expected=None, environment=None, pass_fds=()):
    selected = _ENV if environment is None else environment
    return _owned_run(argv, root, deadline, expected, selected, pass_fds)


@dataclass
class Tool:
    name: str
    opened: object
    version: str = ""

    @property
    def executable(self):
        return f"/proc/self/fd/{self.opened.descriptor}"

    def observation(self):
        raw = _read_open_regular(self.opened, 32 * 1024 * 1024)
        return {"name": self.name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "version": self.version}

    def close(self):
        self.opened.close()


class ToolSet:
    def __init__(self):
        self.tools = []
        try:
            self.tools.append(Tool("git", _open_regular(Path(GIT), 32 * 1024 * 1024, executable=True)))
            self.tools.append(Tool("dpkg-deb", _open_regular(Path(DPKG_DEB), 32 * 1024 * 1024, executable=True)))
            self.tools.append(Tool("dpkg", _open_regular(Path(DPKG), 32 * 1024 * 1024, executable=True)))
        except BaseException:
            self.close()
            raise
        self.git, self.dpkg_deb, self.dpkg = self.tools

    @property
    def descriptors(self):
        return tuple(tool.opened.descriptor for tool in self.tools)

    def observations(self):
        return [tool.observation() for tool in self.tools]

    def close(self):
        for tool in self.tools:
            tool.close()


def _check_versions(root, tools, deadline):
    git = _run((tools.git.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    dpkg_deb = _run((tools.dpkg_deb.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    dpkg = _run((tools.dpkg.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    _require(git == b"git version 2.47.3\n")
    _require(dpkg_deb.splitlines()[0] == b"Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64).")
    _require(dpkg.splitlines()[0] == b"Debian 'dpkg' package management program version 1.22.22 (amd64).")
    tools.git.version = git.decode("ascii").strip()
    tools.dpkg_deb.version = dpkg_deb.splitlines()[0].decode("ascii")
    tools.dpkg.version = dpkg.splitlines()[0].decode("ascii")


def _materialize(records, root, prefix):
    root.mkdir(prefix, 0o700)
    directories = []
    for record in records:
        root.deadline.effect_check()
        relative = prefix if record.path == "." else f"{prefix}/{record.path}"
        _require(record.kind in {"directory", "file"})
        if record.kind == "directory":
            if record.path != ".":
                root.mkdir(relative, record.mode)
            directories.append((relative, record))
        else:
            _require(type(record.content) is bytes)
            root.write_file(relative, record.content, record.mode, record.mtime)
    for relative, record in reversed(directories):
        descriptor = root._open_dir(relative)
        try:
            os.fchmod(descriptor, record.mode)
            os.utime(descriptor, (record.mtime, record.mtime))
        finally:
            os.close(descriptor)


def _git_environment(root):
    return {
        **_ENV,
        "HOME": root.proc_path("private-home"),
        "TMPDIR": root.proc_path("private-tmp"),
        "GIT_AUTHOR_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_AUTHOR_EMAIL": "cogs-stage2",
        "GIT_AUTHOR_NAME": "Cogs Stage 2",
        "GIT_COMMITTER_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_COMMITTER_EMAIL": "cogs-stage2",
        "GIT_COMMITTER_NAME": "Cogs Stage 2",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _prepare_git_fixture(root, tools, deadline):
    fixture = fixed_fixtures().git
    _materialize(fixture.source.records, root, "git-source")
    env = _git_environment(root)
    source = root.proc_path("git-source")
    bare = root.proc_path("git-fixture.git")
    try:
        _run((tools.git.executable, "-c", "init.templateDir=", "init", "--quiet", "--initial-branch=main", source), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "add", "--all"), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "commit", "--quiet", "--message=cogs stage2 fixture v1"), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "rev-parse", "HEAD"), root, deadline, fixture.commit_oid.encode() + b"\n", env, tools.descriptors)
        _run((tools.git.executable, "-c", "init.templateDir=", "clone", "--quiet", "--bare", "--no-hardlinks", source, bare), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, f"--git-dir={bare}", "rev-parse", "refs/heads/main"), root, deadline, fixture.commit_oid.encode() + b"\n", env, tools.descriptors)
    finally:
        _remove_relative(root, "git-source", deadline)
    return "git-fixture.git"


def _remove_relative(root, relative, deadline):
    deadline.cleanup_check()
    root.remove_tree(relative)


def _run_git_sample(root, bare_relative, sample, tools, deadline):
    _require(type(sample) is int and 1 <= sample <= 7)
    fixture = fixed_fixtures().git
    relative = f"git-{sample:02d}"
    env = _git_environment(root)
    start = time.monotonic_ns()
    try:
        _run((tools.git.executable, "-c", "init.templateDir=", "clone", "--quiet", "--no-hardlinks", "--no-tags", root.proc_path(bare_relative), root.proc_path(relative)), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", root.proc_path(relative), "checkout", "--quiet", "--detach", fixture.commit_oid), root, deadline, b"", env, tools.descriptors)
        for mutation in fixture.mutations:
            destination = f"{relative}/{mutation.path}"
            if mutation.operation == "append":
                root.write_file(destination, mutation.payload, 0o644, append=True)
            else:
                _require(mutation.operation == "create")
                parent = str(PurePosixPath(destination).parent)
                root.mkdir(parent, 0o755, parents=True, exist_ok=True)
                root.write_file(destination, mutation.payload, 0o644)
        _run((tools.git.executable, "-C", root.proc_path(relative), "status", "--porcelain=v1", "--untracked-files=all"), root, deadline, fixture.porcelain, env, tools.descriptors)
        duration = (time.monotonic_ns() - start) // 1_000_000
    finally:
        _remove_relative(root, relative, deadline)
    _require(0 <= duration <= LIFECYCLE_SECONDS * 1000)
    return duration


def _inventory_tree(root, relative):
    observed = {}

    def visit(descriptor, prefix):
        status = os.fstat(descriptor)
        observed[prefix] = (status, None)
        for name in sorted(os.listdir(descriptor)):
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            path = name if prefix == "." else f"{prefix}/{name}"
            if stat.S_ISDIR(current.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    _require((opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino))
                    visit(child, path)
                finally:
                    os.close(child)
            else:
                _require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1)
                descriptor_file = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(descriptor_file)
                    raw = _read_fd(descriptor_file, 4_194_304)
                    after = os.fstat(descriptor_file)
                    again = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    _require(_status_identity(opened) == _status_identity(after) == _status_identity(again))
                    observed[path] = (opened, raw)
                finally:
                    os.close(descriptor_file)

    descriptor = root._open_dir(relative)
    try:
        visit(descriptor, ".")
    finally:
        os.close(descriptor)
    return observed


def _verify_installed(root, relative):
    expected = fixed_fixtures().package.installed
    observed = _inventory_tree(root, relative)
    expected_map = {record.path: record for record in expected.records}
    _require(tuple(sorted(observed)) == tuple(sorted(expected_map)))
    for path, record in expected_map.items():
        status, raw = observed[path]
        _require(status.st_uid == status.st_gid == 0)
        _require(stat.S_IMODE(status.st_mode) == record.mode)
        _require(status.st_mtime_ns == record.mtime * 1_000_000_000)
        _require(stat.S_ISDIR(status.st_mode) == (record.kind == "directory"))
        if record.kind == "file":
            _require(raw is not None and len(raw) == record.size and hashlib.sha256(raw).hexdigest() == record.content_sha256)
    return expected


def _status_fields(root, relative):
    raw, _status = root.read_file(relative, 4096)
    _require(0 < len(raw) <= 4096 and b"\x00" not in raw)
    fields = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise WorkloadError("status encoding invalid") from error
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            _require(key not in fields)
            fields[key] = value
    return fields


def _run_package_sample(root, label, tools, deadline):
    _require(label in {"candidate-a", "candidate-b"})
    fixture = fixed_fixtures().package
    prefix = f"package-{label}"
    source = f"{prefix}/source"
    deb = f"{prefix}/cogs-stage2-fixture_1.0_all.deb"
    admin = f"{prefix}/dpkg-admin"
    installed = f"{prefix}/installed"
    root.mkdir(prefix, 0o700)
    try:
        _materialize(fixture.source.records, root, source)
        build_start = time.monotonic_ns()
        _run(
            (
                tools.dpkg_deb.executable,
                "--build",
                "--root-owner-group",
                "--compression=xz",
                "--compression-level=6",
                "--threads-max=1",
                root.proc_path(source),
                root.proc_path(deb),
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
        )
        build_ms = (time.monotonic_ns() - build_start) // 1_000_000
        deb_raw, deb_status = root.read_file(deb, 4_194_304)
        _require(0 < len(deb_raw) == deb_status.st_size)
        root.mkdir(admin, 0o700)
        root.mkdir(f"{admin}/updates", 0o700)
        root.write_file(f"{admin}/status", b"", 0o600)
        root.mkdir(installed, 0o755)
        installed_fd = root._open_dir(installed)
        try:
            os.utime(installed_fd, (SOURCE_EPOCH, SOURCE_EPOCH))
        finally:
            os.close(installed_fd)
        install_start = time.monotonic_ns()
        _run(
            (
                tools.dpkg.executable,
                "--admindir",
                root.proc_path(admin),
                "--instdir",
                f"{root.proc_path(installed)}/",
                "--install",
                root.proc_path(deb),
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
        )
        install_ms = (time.monotonic_ns() - install_start) // 1_000_000
        observed = _verify_installed(root, installed)
        fields = _status_fields(root, f"{admin}/status")
        _require(
            (fields.get("Package"), fields.get("Version"), fields.get("Architecture"), fields.get("Status"))
            == (observed.package, observed.version, observed.architecture, observed.status)
        )
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
        _remove_relative(root, prefix, deadline)
    _require(0 <= build_ms <= LIFECYCLE_SECONDS * 1000 and 0 <= install_ms <= LIFECYCLE_SECONDS * 1000)
    return identity, build_ms, install_ms


def require_linux_amd64_root():
    _require(platform.system() == "Linux")
    _require(platform.machine() in {"x86_64", "amd64"})
    _require(os.geteuid() == 0)
    _enable_subreaper()

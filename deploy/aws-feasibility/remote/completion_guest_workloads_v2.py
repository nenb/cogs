#!/usr/bin/env python3
"""Host-candidate compatibility plus pure ADR0099 in-guest workload codecs."""

from dataclasses import dataclass
import hashlib
import json
import os
import re
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
    WORKLOAD_GID,
    WORKLOAD_UID,
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
        _require((status.st_uid, status.st_gid) == (WORKLOAD_UID, WORKLOAD_GID))
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
                "--force-not-root",
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


# The surfaces below are pure guest-plan data/codecs.  They grant no process,
# SSH, Kata, journal, qualification, or result-publication authority.
GUEST_READY_MARKER = b"COGS_STAGE2_SSH_READY_V1\n"
GUEST_RESULT_PREFIX = "COGS_STAGE2_RESULT_V1"
GUEST_OUTPUT_LIMIT = 4096
GUEST_DURATION_LIMIT_MS = 1_200_000
_GUEST_DIGESTS = {
    "GIT": "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c",
    "BUILD": "03f9ce0491b29e2ffaf216e9d49bc0c382ad1cad808aa1ad53284c06185fce52",
    "INSTALL": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
}
GUEST_WORKLOAD_PLAN = tuple(
    (f"{category}_{sample:02d}", _GUEST_DIGESTS[category])
    for category in ("GIT", "BUILD", "INSTALL") for sample in range(1, 8)
)
_RESULT_RE = re.compile(
    rb"COGS_STAGE2_RESULT_V1\|([0-9]{2})\|(GIT|BUILD|INSTALL)_[0-9]{2}"
    rb"\|(0|[1-9][0-9]{0,6})\|([0-9a-f]{64})\|deleted=(true|false)"
)

# This is the sole remote stdin.  All invocations and paths are closed in these
# bytes; an eventual coordinator may authenticate the bytes but cannot customize
# them. Guest mountinfo proves safe distinct Kata-generated leaves only; exact
# host-source-to-leaf correlation belongs to the future trusted runtime owner.
# BUILD lines identify reviewed source semantics, not an unreviewed final .deb
# pin. Consequently this slice is non-authoritative.
_GUEST_PROGRAM = r'''set -eu
umask 077
[ "$#" -eq 0 ]
export HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
export SOURCE_DATE_EPOCH=1782172800 TZ=UTC TMPDIR=/run/cogs-stage2-ssh/work
R=/run/cogs-stage2-ssh
W=/run/cogs-stage2-ssh/work
I=/run/cogs-stage2-ssh/input
GIT_COMMIT=ca429a94b73caea0fc39164b8087cc1c63f43818
GIT_STATUS=51ad8b3506601cd631d1da66ca40bbafc0c68a5e907600c21fba958a6f22330b
SOURCE_MANIFEST=fcda9e9ba79a1be78202d3f1808bc217e50a2b355c149598087a4e7cca4a698f
INSTALLED_MANIFEST=f0d03497ac0a1784d0cb0c6bd7dd13932eb376c131fd550de438cefa25deb483
DEB_REFERENCE_SHA=
DEB_REFERENCE_SIZE=
DEB_BUILD_COUNT=0
line_count() {
  /usr/bin/wc -l < "$1" > "$2"
  IFS= read -r observed < "$2"
  [ "$observed" -eq "$3" ]
  /bin/rm -f -- "$2"
}
require_sha() {
  /usr/bin/sha256sum -- "$1" > "$3"
  line_count "$3" "$3.count" 1
  IFS=' ' read -r observed observed_path < "$3"
  [ "$observed" = "$2" ] && [ "$observed_path" = "$1" ]
  /bin/rm -f -- "$3"
}
empty_tree() {
  /usr/bin/find "$1" -mindepth 1 -print > "$2"
  [ ! -s "$2" ]
  /bin/rm -f -- "$2"
}
manifest() {
  root=$1 expected=$2 count=$3 scratch=$4
  ( cd "$root"
    /usr/bin/find . -type f -print > "$scratch.paths"
    /usr/bin/find . ! -type d ! -type f -print > "$scratch.other"
    /usr/bin/sort "$scratch.paths" > "$scratch.sorted"
    line_count "$scratch.sorted" "$scratch.count" "$count"
    while IFS= read -r file; do /usr/bin/sha256sum -- "$file"; done < "$scratch.sorted" > "$scratch.sums"
    line_count "$scratch.sums" "$scratch.count" "$count"
    require_sha "$scratch.sums" "$expected" "$scratch.digest"
    [ ! -s "$scratch.other" ]
  )
  /bin/rm -f -- "$scratch.paths" "$scratch.sorted" "$scratch.sums" "$scratch.other"
}
mount_invariant() {
  /usr/bin/awk '
  function has(values,want, n,a,i){n=split(values,a,",");for(i=1;i<=n;i++)if(a[i]==want)return 1;return 0}
  function safeleaf(root, value){if(index(root,"/mounts/")!=1)return "";value=substr(root,9);if(length(value)<1||length(value)>255||value=="."||value==".."||value!~/^[A-Za-z0-9][A-Za-z0-9._-]*$/)return "";return value}
  BEGIN{bad=0;r=key=auth=input=0;keyleaf=authleaf=inputleaf=""}
  index($5,"/run/cogs-stage2-ssh/")==1 && $5!="/run/cogs-stage2-ssh/ssh_host_ed25519_key" && $5!="/run/cogs-stage2-ssh/authorized_keys" && $5!="/run/cogs-stage2-ssh/input" {bad=1}
  $5=="/run/cogs-stage2-ssh" {r++;if($4!="/"||$7!="-"||$8!="tmpfs"||$9!="tmpfs"||!has($6,"rw")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec")||!has($10,"rw")||!has($10,"size=65536k")||!has($10,"nr_inodes=16384")||!has($10,"mode=700"))bad=1}
  $5=="/run/cogs-stage2-ssh/ssh_host_ed25519_key" {key++;keyleaf=safeleaf($4);if(keyleaf==""||$7!="-"||$8!="virtiofs"||$9!="kataShared"||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  $5=="/run/cogs-stage2-ssh/authorized_keys" {auth++;authleaf=safeleaf($4);if(authleaf==""||$7!="-"||$8!="virtiofs"||$9!="kataShared"||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  $5=="/run/cogs-stage2-ssh/input" {input++;inputleaf=safeleaf($4);if(inputleaf==""||$7!="-"||$8!="virtiofs"||$9!="kataShared"||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  END{if(r!=1||key!=1||auth!=1||input!=1||keyleaf==authleaf||keyleaf==inputleaf||authleaf==inputleaf)bad=1;exit bad?1:0}
  ' /proc/self/mountinfo
}
invariant() {
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R")" = '0:0:700:directory' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$W")" = '0:0:700:directory' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R/ssh_host_ed25519_key")" = '0:0:400:regular file' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R/authorized_keys")" = '0:0:400:regular file' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$I")" = '0:0:555:directory' ]
  mount_invariant
  [ "$(/usr/bin/git --git-dir="$I/git.git" rev-parse refs/heads/main)" = "$GIT_COMMIT" ]
  /usr/bin/git --git-dir="$I/git.git" fsck --strict --full > "$W/invariant.git.out" 2> "$W/invariant.git.err"
  [ ! -s "$W/invariant.git.out" ] && [ ! -s "$W/invariant.git.err" ]
  manifest "$I/package" "$SOURCE_MANIFEST" 257 "$W/invariant"
  /usr/bin/find "$I/package" -type d -print > "$W/invariant.dirs"
  line_count "$W/invariant.dirs" "$W/invariant.count" 5
  /bin/rm -f -- "$W/invariant.git.out" "$W/invariant.git.err" "$W/invariant.dirs"
  empty_tree "$W" "$W-empty"
}
now() { /usr/bin/date +%s%N; }
elapsed() { [ "$2" -ge "$1" ]; ELAPSED=$((($2-$1)/1000000)); [ "$ELAPSED" -le 1200000 ]; }
emit() { /usr/bin/printf '%s|%s|%s|%s|%s|deleted=true\n' COGS_STAGE2_RESULT_V1 "$1" "$2" "$3" "$4"; }
delete_sample() {
  /bin/rm -rf -- "$1"
  [ ! -e "$1" ] && [ ! -L "$1" ]
  if /usr/bin/stat -- "$1" > /dev/null 2>&1; then exit 1; fi
  empty_tree "$W" "$W-empty"
}
metadata_rows() {
  root=$1 dirs=$2 files=$3 scratch=$4
  /usr/bin/find "$root" -type d -print > "$scratch.dirs"
  /usr/bin/find "$root" -type f -print > "$scratch.files"
  /usr/bin/find "$root" ! -type d ! -type f -print > "$scratch.other"
  line_count "$scratch.dirs" "$scratch.count" "$dirs"
  line_count "$scratch.files" "$scratch.count" "$files"
  [ ! -s "$scratch.other" ]
}
normalize_source() {
  root=$1 scratch=$2
  metadata_rows "$root" 5 257 "$scratch"
  while IFS= read -r entry; do /bin/chown 0:0 -- "$entry"; /bin/chmod 0755 -- "$entry"; /usr/bin/touch -d @1782172800 -- "$entry"; done < "$scratch.dirs"
  while IFS= read -r entry; do /bin/chown 0:0 -- "$entry"; /bin/chmod 0644 -- "$entry"; /usr/bin/touch -d @1782172800 -- "$entry"; done < "$scratch.files"
  verify_metadata "$root" 5 257 "$scratch" 755 644
  /bin/rm -f -- "$scratch.dirs" "$scratch.files" "$scratch.other"
}
verify_metadata() {
  root=$1 dirs=$2 files=$3 scratch=$4 dmode=$5 fmode=$6
  metadata_rows "$root" "$dirs" "$files" "$scratch"
  while IFS= read -r entry; do
    /usr/bin/stat -c '%u:%g:%a:%Y:%F' -- "$entry" > "$scratch.stat"
    line_count "$scratch.stat" "$scratch.count" 1
    IFS= read -r observed < "$scratch.stat"
    [ "$observed" = "0:0:$dmode:1782172800:directory" ]
  done < "$scratch.dirs"
  while IFS= read -r entry; do
    /usr/bin/stat -c '%u:%g:%a:%Y:%F' -- "$entry" > "$scratch.stat"
    line_count "$scratch.stat" "$scratch.count" 1
    IFS= read -r observed < "$scratch.stat"
    [ "$observed" = "0:0:$fmode:1782172800:regular file" ]
  done < "$scratch.files"
  /bin/rm -f -- "$scratch.dirs" "$scratch.files" "$scratch.other" "$scratch.stat"
}
observe_deb() {
  deb=$1 scratch=$2
  /usr/bin/sha256sum -- "$deb" > "$scratch.sha"
  line_count "$scratch.sha" "$scratch.count" 1
  IFS=' ' read -r observed_sha observed_path < "$scratch.sha"
  [ "$observed_path" = "$deb" ] && [ "${#observed_sha}" -eq 64 ]
  /usr/bin/stat -c '%s' -- "$deb" > "$scratch.size"
  line_count "$scratch.size" "$scratch.count" 1
  IFS= read -r observed_size < "$scratch.size"
  [ "$observed_size" -gt 0 ] && [ "$observed_size" -le 4194304 ]
  if [ "$DEB_BUILD_COUNT" -eq 0 ]; then DEB_REFERENCE_SHA=$observed_sha DEB_REFERENCE_SIZE=$observed_size; else [ "$observed_sha:$observed_size" = "$DEB_REFERENCE_SHA:$DEB_REFERENCE_SIZE" ]; fi
  DEB_BUILD_COUNT=$((DEB_BUILD_COUNT+1))
  /bin/rm -f -- "$scratch.sha" "$scratch.size"
}
verify_deb() {
  deb=$1 check=$2
  [ "$(/usr/bin/dpkg-deb --field "$deb" Package)" = cogs-stage2-fixture ]
  [ "$(/usr/bin/dpkg-deb --field "$deb" Version)" = 1.0 ]
  [ "$(/usr/bin/dpkg-deb --field "$deb" Architecture)" = all ]
  /bin/mkdir -m 0700 -- "$check"
  /usr/bin/dpkg-deb --extract "$deb" "$check" > "$check.extract.out" 2> "$check.extract.err"
  [ ! -s "$check.extract.out" ] && [ ! -s "$check.extract.err" ]
  manifest "$check" "$INSTALLED_MANIFEST" 256 "$check.manifest"
  verify_metadata "$check" 4 256 "$check.metadata" 755 644
  /bin/rm -rf -- "$check"
}
git_sample() {
  n=$1 ord=$2 p="$W/git-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]
  start=$(now)
  /usr/bin/git -c init.templateDir= clone --quiet --no-hardlinks --no-tags "$I/git.git" "$p" 2> "$W/git.err"
  /usr/bin/git -C "$p" checkout --quiet --detach "$GIT_COMMIT" 2>> "$W/git.err"
  i=0; while [ "$i" -lt 32 ]; do /usr/bin/printf '%s\n' 'cogs-stage2-git-v1 modified' >> "$p/files/file-$(/usr/bin/printf '%04d' "$i").txt"; i=$((i+1)); done
  /bin/mkdir -m 0755 -- "$p/untracked"
  /usr/bin/printf '%s\n' 223fd29f1561711aa8b103007774eff0e4219b3a1fe5de532cd68a18655004ef 372cf2f7ed6ac3f64f6718557444132f10c760bb2af0e6c8398bc888380fd6c0 539c440d17714b0243f5b7a3694a51192c795d82c7b83a84f31868e92a28dcc3 135edac91796901ce00251283a50436d55c740055d016be0634978d3a6246dee 2534503de4f86da0fc5925d49f2a17aac088a29da9a6f531026febd5868b9667 23d5832443aada2936bcc495164304aa481f7b422dd9d9a10c379155e0f0c0f4 cd5d3e78c20f5eaf03d84832812d3f52fe7e5e120d6da4e968b0c8796004bf98 dbcf2c1f64841d8be161db397d3ae8a9a8bc07f40143aeee6ef53229b40125ac > "$W/payloads"
  i=0; while IFS= read -r payload; do /usr/bin/printf '%s\n' "$payload" > "$p/untracked/file-$(/usr/bin/printf '%04d' "$i").txt"; i=$((i+1)); done < "$W/payloads"
  /usr/bin/git -C "$p" status --porcelain=v1 --untracked-files=all > "$W/status" 2>> "$W/git.err"
  end=$(now); elapsed "$start" "$end"
  [ ! -s "$W/git.err" ] && [ "$i" -eq 8 ] && [ "$(/usr/bin/wc -l < "$W/status")" -eq 40 ]
  [ "$(/usr/bin/sha256sum "$W/status")" = "$GIT_STATUS  $W/status" ]
  /bin/rm -f -- "$W/git.err" "$W/status" "$W/payloads"
  delete_sample "$p"
  emit "$ord" "GIT_$n" "$ELAPSED" 73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c
}
build_sample() {
  n=$1 ord=$2 p="$W/build-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]; /bin/mkdir -m 0700 -- "$p"; /bin/cp -a -- "$I/package" "$p/source"
  normalize_source "$p/source" "$p/source.metadata"
  start=$(now); /usr/bin/dpkg-deb --build --root-owner-group --compression=xz --compression-level=6 --threads-max=1 "$p/source" "$p/package.deb" > "$p/build.out" 2> "$p/build.err"; end=$(now); elapsed "$start" "$end"
  [ ! -s "$p/build.err" ]; observe_deb "$p/package.deb" "$p/deb"; verify_deb "$p/package.deb" "$p/check"
  delete_sample "$p"
  emit "$ord" "BUILD_$n" "$ELAPSED" 03f9ce0491b29e2ffaf216e9d49bc0c382ad1cad808aa1ad53284c06185fce52
}
install_sample() {
  n=$1 ord=$2 p="$W/install-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]; /bin/mkdir -m 0700 -- "$p"; /bin/cp -a -- "$I/package" "$p/source"
  normalize_source "$p/source" "$p/source.metadata"
  /usr/bin/dpkg-deb --build --root-owner-group --compression=xz --compression-level=6 --threads-max=1 "$p/source" "$p/package.deb" > "$p/build.out" 2> "$p/build.err"
  [ ! -s "$p/build.err" ]; observe_deb "$p/package.deb" "$p/deb"; verify_deb "$p/package.deb" "$p/check"
  /bin/mkdir -m 0700 -- "$p/admin" "$p/admin/updates"; : > "$p/admin/status"; /bin/mkdir -m 0755 -- "$p/installed"; /usr/bin/touch -d @1782172800 -- "$p/installed"
  start=$(now); /usr/bin/dpkg --force-not-root --admindir "$p/admin" --instdir "$p/installed/" --install "$p/package.deb" > "$p/install.out" 2> "$p/install.err"; end=$(now); elapsed "$start" "$end"
  [ ! -s "$p/install.err" ]
  [ "$(/usr/bin/grep -c '^Package: cogs-stage2-fixture$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Version: 1.0$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Architecture: all$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Status: install ok installed$' "$p/admin/status")" -eq 1 ]
  manifest "$p/installed" "$INSTALLED_MANIFEST" 256 "$p/installed.manifest"
  verify_metadata "$p/installed" 4 256 "$p/installed.metadata" 755 644
  delete_sample "$p"
  emit "$ord" "INSTALL_$n" "$ELAPSED" 78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2
}
invariant
/usr/bin/printf '%s\n' COGS_STAGE2_SSH_READY_V1
git_sample 01 01; git_sample 02 02; git_sample 03 03; git_sample 04 04; git_sample 05 05; git_sample 06 06; git_sample 07 07
invariant
build_sample 01 08; build_sample 02 09; build_sample 03 10; build_sample 04 11; build_sample 05 12; build_sample 06 13; build_sample 07 14
invariant
install_sample 01 15; install_sample 02 16; install_sample 03 17; install_sample 04 18; install_sample 05 19; install_sample 06 20; install_sample 07 21
invariant
invariant
[ "$DEB_BUILD_COUNT" -eq 14 ]
empty_tree "$W" "$W-empty"
'''.encode("ascii")
GUEST_PROGRAM_SHA256 = "260e56af6a6c85557eb6838f1e2958eb410bcb3ccb544da66330ae40a370c375"


@dataclass(frozen=True)
class GuestSampleResult:
    ordinal: int
    category: str
    duration_ms: int
    result_sha256: str
    deleted: bool


@dataclass(frozen=True)
class GuestWorkloadResult:
    marker_sha256: str
    samples: tuple[GuestSampleResult, ...]


def guest_program_bytes():
    """Return verified exact stdin bytes; never execute or issue them."""
    if hashlib.sha256(_GUEST_PROGRAM).hexdigest() != GUEST_PROGRAM_SHA256:
        raise WorkloadError("guest program source digest mismatch")
    if not _GUEST_PROGRAM.endswith(b"\n") or any(byte not in range(128) for byte in _GUEST_PROGRAM):
        raise WorkloadError("guest program encoding mismatch")
    return _GUEST_PROGRAM


def canonical_guest_workload_result(result):
    """Bounded canonical parsed-result bytes used by durable SSH replay."""
    if (type(result) is not GuestWorkloadResult or len(result.samples) != len(GUEST_WORKLOAD_PLAN)
            or result.marker_sha256 != hashlib.sha256(GUEST_READY_MARKER).hexdigest()):
        raise WorkloadError("guest canonical result type mismatch")
    value = {"marker_sha256": result.marker_sha256, "samples": [{
        "category": row.category, "deleted": row.deleted, "duration_ms": row.duration_ms,
        "ordinal": row.ordinal, "result_sha256": row.result_sha256,
    } for row in result.samples], "version": "cogs.stage2-guest-workload-result/v2"}
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > GUEST_OUTPUT_LIMIT * 4:
        raise WorkloadError("guest canonical result bound")
    return raw


def parse_canonical_guest_workload_result(raw):
    if type(raw) is not bytes or not raw.endswith(b"\n") or len(raw) > GUEST_OUTPUT_LIMIT * 4:
        raise WorkloadError("guest canonical result bytes")
    try:
        value = json.loads(raw)
        if raw != json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("ascii") + b"\n":
            raise WorkloadError("guest canonical result encoding")
        if (type(value) is not dict or set(value) != {"version", "marker_sha256", "samples"}
                or value["version"] != "cogs.stage2-guest-workload-result/v2"
                or type(value["marker_sha256"]) is not str):
            raise WorkloadError("guest canonical result shape")
        if type(value["samples"]) is not list:
            raise WorkloadError("guest canonical samples type")
        for row in value["samples"]:
            if (type(row) is not dict or set(row) != {"ordinal", "category", "duration_ms",
                                                 "result_sha256", "deleted"}
                    or type(row["ordinal"]) is not int or type(row["category"]) is not str
                    or type(row["duration_ms"]) is not int or type(row["result_sha256"]) is not str
                    or type(row["deleted"]) is not bool):
                raise WorkloadError("guest canonical sample shape")
        samples = tuple(GuestSampleResult(
            row["ordinal"], row["category"], row["duration_ms"], row["result_sha256"], row["deleted"])
            for row in value["samples"])
        result = GuestWorkloadResult(value["marker_sha256"], samples)
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise WorkloadError("guest canonical result parse") from error
    if canonical_guest_workload_result(result) != raw:
        raise WorkloadError("guest canonical result semantics")
    for ordinal, (expected, row) in enumerate(
            zip(GUEST_WORKLOAD_PLAN, result.samples, strict=True), 1):
        if (row.ordinal, row.category, row.result_sha256, row.deleted) != (
                ordinal, expected[0], expected[1], True):
            raise WorkloadError("guest canonical result plan")
        if type(row.duration_ms) is not int or not 0 <= row.duration_ms <= GUEST_DURATION_LIMIT_MS:
            raise WorkloadError("guest canonical duration")
    return result


def parse_guest_workload_output(raw):
    """Parse the sole complete stdout object and enforce the fixed plan semantics."""
    if type(raw) is not bytes or not raw or len(raw) > GUEST_OUTPUT_LIMIT or b"\0" in raw:
        raise WorkloadError("guest output bound mismatch")
    if not raw.endswith(b"\n") or any(byte > 127 for byte in raw):
        raise WorkloadError("guest output encoding mismatch")
    lines = raw.splitlines(keepends=True)
    if len(lines) != len(GUEST_WORKLOAD_PLAN) + 1 or lines[0] != GUEST_READY_MARKER:
        raise WorkloadError("guest output readiness or cardinality mismatch")
    samples = []
    for ordinal, ((label, expected_digest), line) in enumerate(zip(GUEST_WORKLOAD_PLAN, lines[1:]), 1):
        if not line.endswith(b"\n") or line.count(b"\n") != 1:
            raise WorkloadError("guest result framing mismatch")
        match = _RESULT_RE.fullmatch(line[:-1])
        if match is None:
            raise WorkloadError("guest result grammar mismatch")
        parsed_ordinal = int(match.group(1))
        parsed_label = line[:-1].split(b"|", 4)[2].decode("ascii")
        duration = int(match.group(3))
        digest = match.group(4).decode("ascii")
        deleted = match.group(5) == b"true"
        canonical = f"{GUEST_RESULT_PREFIX}|{ordinal:02d}|{label}|{duration}|{expected_digest}|deleted=true\n".encode("ascii")
        if (line != canonical or parsed_ordinal != ordinal or parsed_label != label or
                duration > GUEST_DURATION_LIMIT_MS or digest != expected_digest or not deleted):
            raise WorkloadError("guest result semantic mismatch")
        samples.append(GuestSampleResult(ordinal, label, duration, digest, True))
    return GuestWorkloadResult(hashlib.sha256(GUEST_READY_MARKER).hexdigest(), tuple(samples))

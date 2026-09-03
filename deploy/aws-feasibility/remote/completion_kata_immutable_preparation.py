#!/usr/bin/env python3
"""Exact immutable asset preparation before Stage 2 role custody.

This zero-argument transaction owns the fixed public cache, verifies all 16
rootfs inputs and both runtime archives, extracts the static runtime without
launching it, and installs the Kata fixture.  It does not open KVM, QMP,
containerd, ctr, SSH, task, or guest-network surfaces.
"""

import hashlib
import http.client
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

# Isolated-mode execution intentionally omits the script directory. The caller
# has already materialized and authenticated this fixed source root, so import
# only sibling owner modules from this exact resolved directory.
_REMOTE_MODULE_ROOT = Path(__file__).resolve().parent
if not _REMOTE_MODULE_ROOT.is_dir():
    raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_REMOTE_MODULE_ROOT))
import completion_kata_preparation as preparation

VERSION = "cogs.stage2-local-immutable-preparation/v2"
SOURCE_ROOT = Path("/var/lib/cogs/stage2-completion-v1/source")
CONTROL_ROOT = Path("/var/lib/cogs/stage2-completion-v1/control")
COMPLETION_ROOT = SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1"
PREPARATION_ROOT = COMPLETION_ROOT / "immutable-preparation-v1"
RUNTIME_CACHE = PREPARATION_ROOT / "runtime-cache"
EXTRACTED_ROOT = PREPARATION_ROOT / "extracted"
RECEIPT = PREPARATION_ROOT / "receipt.json"
STAGED_RUNTIME = COMPLETION_ROOT / "kata-runtime-v1"
IMMUTABLE_STAGING = COMPLETION_ROOT / ".kata-runtime-v1.immutable-staging"
KATA_ROOT = Path("/opt/kata")
KATA_PARENT = Path("/opt")
MAX_REDIRECTS = 3
GLOBAL_SECONDS = 1_700
CHUNK = 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024 * 1024
EXTRACTORS = (Path("/usr/bin/tar"), Path("/usr/bin/zstd"))
_OBSERVATION_STAGE = "entry"
_DIAGNOSTIC_STAGES = frozenset({
    "entry", "preflight", "expected-control", "ownership", "rootfs-acquisition",
    "runtime-acquisition", "extract-kata", "extract-containerd", "archive-values",
    "receipt", "active-configuration", "publication", "installed-verification", "package-verification",
})
ALLOWED_REDIRECT_HOSTS = frozenset({
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
})
DENIED_ENV = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NETRC",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "GITHUB_TOKEN", "GH_TOKEN", "DOCKER_CONFIG",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
})


class ImmutablePreparationError(Exception):
    """The exact immutable preparation could not be completed."""


class ImmutablePreparationErrorGroup(ImmutablePreparationError):
    """Portable aggregate for hosts predating native exception groups."""
    def __init__(self, message, errors):
        self.errors = tuple(errors)
        super().__init__(message + ": " + "; ".join(
            f"{type(error).__name__}: {error}" for error in self.errors))


def _error_group(message, errors):
    try:
        group = BaseExceptionGroup
    except NameError:
        return ImmutablePreparationErrorGroup(message, errors)
    return group(message, tuple(errors))


def _require(condition, message="immutable preparation failed"):
    if not condition:
        raise ImmutablePreparationError(message)


def _chown_root(descriptor):
    os.fchown(descriptor, 0, 0)


def _identity(value):
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _directory_identity(path):
    seen = os.stat(path, follow_symlinks=False)
    _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == os.geteuid()
             and (os.geteuid() != 0 or seen.st_gid == 0)
             and stat.S_IMODE(seen.st_mode) == 0o700)
    return {"device": seen.st_dev, "inode": seen.st_ino}


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_owned_file(path, raw, mode):
    temporary = path.with_name("." + path.name + ".partial")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            _require(count > 0)
            offset += count
        _chown_root(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rename(temporary, path); _sync_directory(path.parent)


def _prepare_state_parents():
    """Create only the fixed private state parents omitted from source archives."""
    state_root = COMPLETION_ROOT.parent
    _require(state_root == SOURCE_ROOT / "deploy/aws-feasibility/.state")
    for path in (state_root, COMPLETION_ROOT):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        seen = path.lstat()
        _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == os.geteuid()
                 and not stat.S_IMODE(seen.st_mode) & 0o022)


def _reject_ambient_authority():
    _require(os.geteuid() == 0 and sys.argv == [sys.argv[0]])
    _require(sys.platform.startswith("linux") and os.uname().machine == "x86_64")
    for name in os.environ:
        upper = name.upper()
        _require(upper not in DENIED_ENV and not upper.startswith("AWS_"),
                 "ambient acquisition authority is forbidden")


def _strict_url(value):
    _require(type(value) is str and len(value) <= 16_384)
    try:
        parsed = urlsplit(value)
        port = parsed.port
        value.encode("ascii")
    except (UnicodeError, ValueError) as error:
        raise ImmutablePreparationError("invalid fixed runtime URL") from error
    _require(parsed.scheme == "https" and parsed.hostname and port is None)
    _require(parsed.username is None and parsed.password is None and not parsed.fragment)
    _require(parsed.path.startswith("/") and "\\" not in parsed.path)
    _require(all(part not in {".", ".."} for part in parsed.path.split("/")))
    return parsed


def _headers(response):
    rows = response.getheaders()
    _require(response.version == 11 and len(rows) <= 64)
    result = {}
    total = 0
    for name, value in rows:
        lowered = name.lower()
        _require(lowered not in result and all(32 <= ord(char) < 127 for char in name + value))
        total += len(name) + len(value) + 4
        _require(total <= 32_768)
        result[lowered] = value.strip(" ")
    _require(not ({"content-encoding", "set-cookie", "www-authenticate", "authorization",
                   "transfer-encoding"} & set(result)))
    return result


def _request(url, deadline):
    parsed = _strict_url(url)
    remaining = deadline - time.monotonic()
    _require(remaining > 0)
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(
        parsed.hostname, 443, timeout=min(30, remaining), context=context)
    try:
        target = parsed.path + (("?" + parsed.query) if parsed.query else "")
        connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", parsed.hostname)
        connection.putheader("Accept", "application/octet-stream")
        connection.putheader("User-Agent", "cogs-stage2-immutable-preparation/1")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        return connection, response, _headers(response)
    except BaseException:
        connection.close()
        raise


def _runtime_response(expected, deadline):
    current = expected["url"]
    origin = _strict_url(current)
    _require(origin.hostname == "github.com")
    seen = {current}
    for ordinal in range(MAX_REDIRECTS + 1):
        connection, response, headers = _request(current, deadline)
        if response.status == 200:
            _require(ordinal > 0 and _strict_url(current).hostname in ALLOWED_REDIRECT_HOSTS)
            length = headers.get("content-length", "")
            _require(length.isdigit() and str(int(length)) == length
                     and int(length) == expected["size"])
            return connection, response
        try:
            _require(response.status in {302, 303, 307, 308} and ordinal < MAX_REDIRECTS)
            length = headers.get("content-length", "0")
            _require(length.isdigit() and int(length) <= 4096)
            body = response.read(int(length) + 1)
            _require(len(body) == int(length))
            location = headers.get("location")
            _require(type(location) is str)
            target = urljoin(current, location)
            parsed = _strict_url(target)
            _require(parsed.hostname in ALLOWED_REDIRECT_HOSTS and target not in seen)
            seen.add(target)
            current = target
        finally:
            response.close()
            connection.close()
    raise ImmutablePreparationError("runtime redirect bound exceeded")


def _stable_file(path, expected, mode=0o400):
    before = os.stat(path, follow_symlinks=False)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
             and before.st_size == expected["size"])
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _require(_identity(os.fstat(descriptor)) == _identity(before))
        total = 0
        while total < expected["size"]:
            raw = os.read(descriptor, min(CHUNK, expected["size"] - total))
            _require(raw)
            total += len(raw)
            digest.update(raw)
        _require(not os.read(descriptor, 1))
    finally:
        os.close(descriptor)
    _require(_identity(os.stat(path, follow_symlinks=False)) == _identity(before)
             and digest.hexdigest() == expected["sha256"])


def _download_runtime(expected, deadline):
    destination = RUNTIME_CACHE / expected["name"]
    if destination.exists():
        _stable_file(destination, expected)
        return destination
    partial = RUNTIME_CACHE / ("." + expected["name"] + ".partial")
    _require(not partial.exists())
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    connection = response = None
    try:
        connection, response = _runtime_response(expected, deadline)
        digest = hashlib.sha256()
        total = 0
        while total < expected["size"]:
            if connection.sock is not None:
                connection.sock.settimeout(min(120, deadline - time.monotonic()))
            raw = response.read(min(CHUNK, expected["size"] - total))
            _require(raw)
            total += len(raw)
            digest.update(raw)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                _require(count > 0)
                view = view[count:]
        _require(response.read(1) == b"" and digest.hexdigest() == expected["sha256"])
        os.fsync(descriptor)
        _chown_root(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(partial, destination)
        directory = os.open(RUNTIME_CACHE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        _stable_file(destination, expected)
        return destination
    except BaseException:
        try:
            partial.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _extractor_identity(seen, executable):
    return (stat.S_ISREG(seen.st_mode) and seen.st_uid == 0
            and stat.S_IMODE(seen.st_mode) & 0o022 == 0 and executable)


def _extractor_preflight():
    for path in EXTRACTORS:
        _require(_extractor_identity(path.lstat(), os.access(path, os.X_OK)),
                 "fixed runtime extractor unavailable")
    space = os.statvfs(SOURCE_ROOT)
    _require(space.f_bavail * space.f_frsize >= 12 * 1024**3
             and space.f_favail >= 200_000, "fixed runtime extraction capacity unavailable")


def _verify_extraction_filesystem():
    _require(SOURCE_ROOT.lstat().st_dev == COMPLETION_ROOT.lstat().st_dev,
             "fixed runtime extraction filesystem differs")


def _run_extract(archive, destination):
    destination.mkdir(mode=0o700)
    intent = preparation.canonical_bytes({
        "version": "cogs.stage2-runtime-extraction-intent/v1",
        "archive_name": archive.name, "archive_size": archive.stat().st_size,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()})
    marker = destination / ".extraction-intent.json"
    _write_owned_file(marker, intent, 0o400)
    command = ["/usr/bin/tar", "--extract", "--file", str(archive), "--directory", str(destination),
               "--numeric-owner", "--same-owner", "--no-overwrite-dir", "--delay-directory-restore"]
    if archive.name.endswith(".tar.zst"):
        command.insert(2, "--use-compress-program=/usr/bin/zstd")
    result = subprocess.run(
        tuple(command), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                                        "PATH": "/usr/bin:/bin"},
        timeout=600, check=False, close_fds=True, start_new_session=True)
    _require(result.returncode == 0, "fixed runtime extraction failed")
    _require(marker.read_bytes() == intent); marker.unlink(); _sync_directory(destination)


def _expected_runtime():
    if not CONTROL_ROOT.exists():
        return None
    control_raw = (CONTROL_ROOT / preparation.CONTROL_MEMBER).read_bytes()
    control = preparation.load_control(control_raw)
    members = {}
    for row in control.value["members"]:
        members[row["name"]] = (CONTROL_ROOT / row["name"]).read_bytes()
    _envelope, runtime, _contracts = preparation.validate_control_members(control, members)
    return runtime.value


def _prebuilt_descriptor_bytes(expected_runtime):
    if expected_runtime is not None:
        _require(not preparation.PREBUILT_DESCRIPTOR_ROOT.exists(),
                 "external descriptor competes with reviewed control")
        raw = preparation.canonical_bytes(
            expected_runtime["rootfs"]["prebuilt_descriptor"])
        _require(hashlib.sha256(raw).hexdigest() ==
                 expected_runtime["rootfs"]["prebuilt_descriptor_sha256"])
        return raw
    root = preparation.PREBUILT_DESCRIPTOR_ROOT
    seen = root.lstat()
    _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
             and stat.S_IMODE(seen.st_mode) == 0o700
             and set(os.listdir(root)) == {"descriptor.json"})
    path = preparation.PREBUILT_DESCRIPTOR_PATH
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
             and 0 < before.st_size <= 8192)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(descriptor, 8193); after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                  value.st_gid, value.st_nlink, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        _require(len(raw) == before.st_size and identity(before) == identity(after))
        return raw
    finally: os.close(descriptor)


def _archive_values(expected_runtime, archives, extracted):
    values = []
    for pin in preparation.ARCHIVES:
        layout = preparation.section(preparation.archive_layout(archives[pin["role"]], pin))
        postwalk = preparation.section(preparation.extracted_postwalk(extracted[pin["role"]]))
        value = {**pin, "layout": layout, "extracted": postwalk}
        if expected_runtime is not None:
            reviewed = next(row for row in expected_runtime["archives"] if row["role"] == pin["role"])
            _require(value == reviewed, "reviewed runtime archive layout differs")
        values.append(value)
    return values


def _copy_fixed(source, destination, mode):
    raw = source.read_bytes()
    temporary = destination.with_name("." + destination.name + ".partial")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            _require(count > 0)
            offset += count
        _chown_root(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rename(temporary, destination); _sync_directory(destination.parent)


def _publish_runtime(extracted):
    global _OBSERVATION_STAGE
    _require(not STAGED_RUNTIME.exists() and not KATA_ROOT.exists()
             and not IMMUTABLE_STAGING.exists())
    IMMUTABLE_STAGING.mkdir(mode=0o700)
    (IMMUTABLE_STAGING / "bin").mkdir(mode=0o700)
    for relative, size, digest, mode in __import__("completion_kata_command_policy").CONTAINERD_EXTRACTION:
        source = extracted["containerd"] / relative
        _require(source.is_file() and source.stat().st_size == size
                 and hashlib.sha256(source.read_bytes()).hexdigest() == digest)
        _copy_fixed(source, IMMUTABLE_STAGING / relative, mode)
    _OBSERVATION_STAGE = "active-configuration"
    base_path = (extracted["kata"] /
                 preparation.KATA_BASE_CONFIGURATION_PATH.removeprefix("/"))
    base = base_path.read_bytes()
    active = preparation.derive_observer_configuration(base)
    _write_owned_file(
        IMMUTABLE_STAGING / Path(preparation.KATA_ACTIVE_CONFIGURATION_PATH).name,
        active, 0o400)
    os.chmod(IMMUTABLE_STAGING / "bin", 0o500)
    os.rename(IMMUTABLE_STAGING, STAGED_RUNTIME)
    os.chmod(STAGED_RUNTIME, 0o500)
    _sync_directory(COMPLETION_ROOT)
    kata_source = extracted["kata"] / "opt/kata"
    _require(kata_source.is_dir())
    os.rename(kata_source, KATA_ROOT)
    _sync_directory(KATA_PARENT)


def _verify_installed(expected_runtime):
    _require(STAGED_RUNTIME.is_dir() and KATA_ROOT.is_dir())
    # Historical narrow unit fixtures contain only launch-artifact rows. Real
    # preparation either has no reviewed control yet or the exact new binding.
    observer_bound = (expected_runtime is None or
                      "active_configuration" in expected_runtime.get("launch", {}))
    if observer_bound:
        base = Path(preparation.KATA_BASE_CONFIGURATION_PATH).read_bytes()
        active = Path(preparation.KATA_ACTIVE_CONFIGURATION_PATH).read_bytes()
        _require(active == preparation.derive_observer_configuration(base))
        active_description = preparation.observer_configuration_description(base)
        if expected_runtime is None:
            return
        _require(expected_runtime["launch"]["active_configuration"] == active_description,
                 "reviewed active Kata configuration differs")
    for row in expected_runtime["launch"]["artifacts"]:
        path = Path(row["path"])
        seen = path.lstat()
        _require(stat.S_IMODE(seen.st_mode) == row["mode"])
        if row["kind"] == "file":
            _require(stat.S_ISREG(seen.st_mode) and seen.st_size == row["size"]
                     and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"])
        else:
            _require(row["size"] == 0 and stat.S_ISLNK(seen.st_mode)
                     and os.readlink(path) == row["link_target"])


def _receipt_value():
    raw = RECEIPT.read_bytes()
    value = preparation.decode_canonical(raw, preparation.MAX_RUNTIME_BYTES)
    _require(set(value) == {"version", "authority", "rootfs_artifact",
                            "runtime_archives", "forbidden_surfaces"}
             and value["version"] == VERSION
             and value["authority"] == "immutable-public-input-preparation-only"
             and value["forbidden_surfaces"] ==
             ["containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"])
    artifact = value["rootfs_artifact"]
    _require(type(artifact) is dict and set(artifact) == {
        "descriptor_sha256", "manifest_digest", "blob_sha256", "blob_size",
        "intent_sha256", "settlement_sha256", "downloaded"})
    for name in ("descriptor_sha256", "manifest_digest", "blob_sha256",
                 "intent_sha256", "settlement_sha256"):
        _require(type(artifact[name]) is str and len(artifact[name]) == 64
                 and set(artifact[name]) <= set("0123456789abcdef"))
    _require(artifact["blob_sha256"] == "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397"
             and artifact["blob_size"] == 136_905_728 and artifact["downloaded"] is True)
    _require(type(value["runtime_archives"]) is list
             and len(value["runtime_archives"]) == len(preparation.ARCHIVES))
    for row, pin in zip(value["runtime_archives"], preparation.ARCHIVES):
        preparation._archive(row, pin)
    return raw, value


def _same_row(left, right):
    return left == right


def _owned_subset_row(observed, expected, allow_truncated=False):
    if observed.get("path") != expected.get("path") or observed.get("kind") != expected.get("kind"):
        return False
    for name in ("uid", "gid"):
        if observed.get(name) != expected.get(name): return False
    if observed.get("mode") != expected.get("mode"):
        if not (observed["kind"] == "directory" and observed.get("mode") == 0o700):
            return False
    if observed["kind"] == "file":
        return (0 <= observed["size"] <= expected["size"]
                and ((allow_truncated and observed["size"] < expected["size"])
                     or observed.get("sha256") == expected.get("sha256")))
    return observed == expected


def _remove_verified_tree(root, expected, root_row=None, subset=False,
                          allow_truncated=False):
    """Remove only a complete verified transaction tree; never discover ownership."""
    if not root.exists() and not root.is_symlink():
        return False
    seen = root.lstat()
    _require(stat.S_ISDIR(seen.st_mode) and not stat.S_ISLNK(seen.st_mode))
    if root_row is not None:
        _require(root_row["kind"] == "directory" and seen.st_uid == root_row["uid"]
                 and seen.st_gid == root_row["gid"]
                 and stat.S_IMODE(seen.st_mode) in (
                    root_row["mode"] if type(root_row["mode"]) is tuple else
                    (root_row["mode"],)))
    actual = preparation.extracted_postwalk(root)
    expected_by_path = {row["path"]: row for row in expected}
    actual_by_path = {row["path"]: row for row in actual}
    _require((set(actual_by_path) <= set(expected_by_path) if subset else
              set(actual_by_path) == set(expected_by_path)))
    _require(all((_owned_subset_row(row, expected_by_path[path], allow_truncated) if subset else
                  _same_row(row, expected_by_path[path]))
                 for path, row in actual_by_path.items()))
    directories = [row for row in actual if row["kind"] == "directory"]
    for row in sorted(directories, key=lambda item: item["path"].count("/")):
        os.chmod(root / row["path"], 0o700, follow_symlinks=False)
    os.chmod(root, 0o700, follow_symlinks=False)
    for row in sorted(actual, key=lambda item: (item["path"].count("/"), item["path"]),
                      reverse=True):
        path = root / row["path"]
        if row["kind"] == "directory":
            path.rmdir()
        else:
            path.unlink()
    root.rmdir()
    return True


def _static_runtime_rows():
    import completion_kata_command_policy as policy
    uid, gid = os.geteuid(), os.getegid()
    rows = [{"path": "bin", "kind": "directory", "mode": 0o500,
             "uid": uid, "gid": gid, "size": 0, "link_target": None, "sha256": None}]
    for relative, size, digest, mode in policy.CONTAINERD_EXTRACTION:
        rows.append({"path": relative, "kind": "file", "mode": mode,
                     "uid": uid, "gid": gid, "size": size,
                     "link_target": None, "sha256": digest})
    active_path = Path(preparation.KATA_ACTIVE_CONFIGURATION_PATH)
    observed_active = next((path for path in (
        STAGED_RUNTIME / active_path.name, IMMUTABLE_STAGING / active_path.name,
            IMMUTABLE_STAGING / ("." + active_path.name + ".partial"))
        if path.exists()), None)
    if observed_active is not None:
        base_relative = preparation.KATA_BASE_CONFIGURATION_PATH.removeprefix("/")
        base_source = next((path for path in (
            KATA_ROOT / preparation.KATA_BASE_CONFIGURATION_PATH.removeprefix("/opt/kata/"),
            EXTRACTED_ROOT / "kata" / base_relative)
            if path.exists()), None)
        _require(base_source is not None,
                 "active configuration lacks pinned rollback base")
        active = preparation.derive_observer_configuration(base_source.read_bytes())
        rows.append({"path": active_path.name, "kind": "file", "mode": 0o400,
                     "uid": uid, "gid": gid, "size": len(active),
                     "link_target": None, "sha256": hashlib.sha256(active).hexdigest()})
    return sorted(rows, key=lambda row: row["path"].encode())


def _remove_static_runtime(path, partial):
    rows = _static_runtime_rows()
    if partial and path.exists():
        expected = {row["path"]: row for row in rows if row["kind"] == "file"}
        for candidate in tuple(path.rglob(".*.partial")):
            relative = candidate.relative_to(path)
            final = relative.with_name(candidate.name[1:-8])
            row = expected.get(str(final))
            seen = candidate.lstat()
            _require(row is not None and stat.S_ISREG(seen.st_mode)
                     and seen.st_uid == row["uid"] and seen.st_gid == row["gid"]
                     and seen.st_nlink == 1 and stat.S_IMODE(seen.st_mode) == row["mode"]
                     and 0 <= seen.st_size <= row["size"])
            active_name = Path(preparation.KATA_ACTIVE_CONFIGURATION_PATH).name
            if str(final) == active_name:
                base_relative = preparation.KATA_BASE_CONFIGURATION_PATH.removeprefix("/")
                base_source = EXTRACTED_ROOT / "kata" / base_relative
                expected_raw = preparation.derive_observer_configuration(base_source.read_bytes())
            else:
                expected_raw = (EXTRACTED_ROOT / "containerd" / final).read_bytes()
            _require(expected_raw.startswith(candidate.read_bytes()))
            candidate.unlink(); _sync_directory(candidate.parent)
    if partial and path.exists():
        # Before the final bin chmod, an exact partial staging directory has a
        # writable bin. Normalize that one reviewed intermediate generation.
        actual = preparation.extracted_postwalk(path)
        if actual and actual[0]["path"] == "bin" and actual[0]["kind"] == "directory" \
                and actual[0]["mode"] == 0o700:
            expected = [dict(row, mode=0o700) if row["path"] == "bin" else row for row in rows]
            return _remove_verified_tree(path, expected, subset=True)
    return _remove_verified_tree(path, rows, {
        "kind": "directory", "uid": os.geteuid(), "gid": os.getegid(),
        "mode": (0o500, 0o700) if path == STAGED_RUNTIME else 0o700}, subset=True)


def _remove_runtime_partial(path, quarantine, expected):
    """Settle one root-created interrupted download without adopting its bytes."""
    _require(not (path.exists() and quarantine.exists()),
             "duplicate runtime partial generations")
    active = quarantine if quarantine.exists() else path
    before = os.stat(active, follow_symlinks=False)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and (os.geteuid() != 0 or before.st_gid == 0) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 <= before.st_size <= expected["size"],
             "runtime partial identity changed")
    generation = lambda seen: (seen.st_dev, seen.st_ino, seen.st_mode, seen.st_uid,
                               seen.st_gid, seen.st_nlink, seen.st_size, seen.st_mtime_ns)
    descriptor = os.open(active, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _require(generation(os.fstat(descriptor)) == generation(before),
                 "runtime partial changed before custody")
        if active == path:
            os.rename(path, quarantine)
            _sync_directory(RUNTIME_CACHE)
            active = quarantine
        _require(generation(os.stat(active, follow_symlinks=False)) == generation(before)
                 and generation(os.fstat(descriptor)) == generation(before),
                 "runtime partial changed before removal")
        active.unlink()
        _sync_directory(RUNTIME_CACHE)
        settled = os.fstat(descriptor)
        _require((settled.st_dev, settled.st_ino, settled.st_mode, settled.st_uid,
                  settled.st_gid, settled.st_size) ==
                 (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                  before.st_gid, before.st_size) and settled.st_nlink == 0,
                 "runtime partial did not settle")
    finally:
        os.close(descriptor)


def _remove_prebuilt_input(descriptor, descriptor_raw):
    import completion_rootfs_prebuilt_acquisition as acquisition

    root = preparation.PREBUILT_INPUT_ROOT
    if not root.exists():
        return
    seen = root.lstat()
    _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
             and stat.S_IMODE(seen.st_mode) == 0o700)
    names = set(os.listdir(root))
    if not names:
        root.rmdir(); _sync_directory(root.parent); return
    _require(acquisition.INTENT_NAME in names,
             "unbound prebuilt input generation must be preserved")
    _require(names <= {acquisition.FINAL_NAME, acquisition.PARTIAL_NAME,
                       acquisition.SENTINEL_NAME, acquisition.INTENT_NAME,
                       acquisition.SETTLEMENT_NAME}, "foreign prebuilt input entry")
    try:
        intent = preparation.decode_canonical(
            (root / acquisition.INTENT_NAME).read_bytes(), 8192)
    except BaseException:
        _require(names == {acquisition.INTENT_NAME})
        path = root / acquisition.INTENT_NAME; seen_intent = path.lstat()
        _require(stat.S_ISREG(seen_intent.st_mode) and seen_intent.st_uid == seen_intent.st_gid == 0
                 and seen_intent.st_nlink == 1 and stat.S_IMODE(seen_intent.st_mode) in {0o400, 0o600}
                 and 0 <= seen_intent.st_size <= 8192)
        path.unlink(); _sync_directory(root); root.rmdir(); _sync_directory(root.parent); return
    _require(intent == {
        "version": "cogs.stage2-prebuilt-rootfs-acquisition-intent/v1",
        "descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
        "manifest_digest": descriptor.manifest_digest,
        "blob_sha256": descriptor.layer_digest,
        "blob_size": descriptor.layer_size,
        "root_device": seen.st_dev, "root_inode": seen.st_ino,
    }, "prebuilt acquisition intent differs")
    intent_sha256 = hashlib.sha256(preparation.canonical_bytes(intent)).hexdigest()
    order = (acquisition.SETTLEMENT_NAME, acquisition.SENTINEL_NAME,
             acquisition.FINAL_NAME, acquisition.PARTIAL_NAME,
             acquisition.INTENT_NAME)
    for name in (item for item in order if item in names):
        path = root / name
        before = path.lstat()
        expected_mode = (0o400 if name in {acquisition.FINAL_NAME,
                                          acquisition.INTENT_NAME,
                                          acquisition.SETTLEMENT_NAME} else 0o600)
        maximum = (descriptor.layer_size if name in {acquisition.FINAL_NAME,
                                                     acquisition.PARTIAL_NAME}
                   else len(acquisition.SENTINEL) if name == acquisition.SENTINEL_NAME
                   else 8192)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == expected_mode
                 and 0 <= before.st_size <= maximum)
        descriptor_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            current = os.fstat(descriptor_fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                      value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns)
            _require(identity(current) == identity(before))
            if name == acquisition.FINAL_NAME:
                _require(before.st_size == descriptor.layer_size
                         and _read_file_hash(descriptor_fd, descriptor.layer_size) == descriptor.layer_digest)
            elif name == acquisition.SENTINEL_NAME:
                _require(os.pread(descriptor_fd, len(acquisition.SENTINEL), 0) == acquisition.SENTINEL)
            elif name == acquisition.INTENT_NAME:
                _require(preparation.decode_canonical(
                    os.pread(descriptor_fd, 8192, 0), 8192) == intent)
            elif name == acquisition.SETTLEMENT_NAME:
                settlement = preparation.decode_canonical(
                    os.pread(descriptor_fd, 8192, 0), 8192)
                _require(set(settlement) == {"version", "intent_sha256",
                         "descriptor_sha256", "blob_sha256", "blob_size",
                         "file_device", "file_inode"}
                         and settlement.get("version") ==
                         "cogs.stage2-prebuilt-rootfs-acquisition-settlement/v1"
                         and settlement.get("intent_sha256") == intent_sha256
                         and settlement.get("descriptor_sha256") ==
                             intent["descriptor_sha256"]
                         and settlement.get("blob_sha256") == descriptor.layer_digest
                         and settlement.get("blob_size") == descriptor.layer_size)
                if acquisition.FINAL_NAME in names:
                    final_seen = (root / acquisition.FINAL_NAME).lstat()
                    _require((settlement["file_device"], settlement["file_inode"]) ==
                             (final_seen.st_dev, final_seen.st_ino))
            path.unlink(); _sync_directory(root)
            _require(os.fstat(descriptor_fd).st_nlink == 0)
        finally: os.close(descriptor_fd)
    root.rmdir(); _sync_directory(root.parent)


def _read_file_hash(descriptor, size):
    digest = hashlib.sha256(); offset = 0
    while offset < size:
        part = os.pread(descriptor, min(CHUNK, size - offset), offset)
        _require(part); digest.update(part); offset += len(part)
    return digest.hexdigest()


def _rollback_preparation(descriptor, descriptor_raw):
    """Inspect every owned class and aggregate uncertainty; never report best effort."""
    if not PREPARATION_ROOT.exists():
        _require(not IMMUTABLE_STAGING.exists() and not STAGED_RUNTIME.exists()
                 and not KATA_ROOT.exists())
        return
    receipt = None
    if RECEIPT.exists() or RECEIPT.is_symlink():
        receipt = _receipt_value()
    errors = []

    def cleanup(action, label=None):
        try:
            action()
        except BaseException as error:
            wrapped = ImmutablePreparationError(
                f"{label or getattr(action, '__name__', 'cleanup')} inspection failed: "
                f"{type(error).__name__}: {error}")
            wrapped.__cause__ = error
            errors.append(wrapped)

    if receipt is not None:
        values = receipt[1]["runtime_archives"]
    else:
        expected_runtime = _expected_runtime()
        values = None if expected_runtime is None else expected_runtime.get("archives")
    kata_moved = KATA_ROOT.exists() or KATA_ROOT.is_symlink()
    # The staged observer derivative is authorized only by the still-present
    # pinned base generation, so verify/remove it before the Kata tree.
    cleanup(lambda: _remove_static_runtime(STAGED_RUNTIME, False), "staged runtime")
    cleanup(lambda: _remove_static_runtime(IMMUTABLE_STAGING, True), "immutable staging")
    if kata_moved and not errors:
        def remove_kata():
            _require(values is not None, "Kata staging lacks durable manifest")
            rows = next(row for row in values if row["role"] == "kata")["extracted"]["entries"]
            root_row = next(row for row in rows if row["path"] == "opt/kata")
            children = [dict(row, path=row["path"][len("opt/kata/"):]) for row in rows
                        if row["path"].startswith("opt/kata/")]
            _remove_verified_tree(KATA_ROOT, children, root_row, subset=True)
        cleanup(remove_kata)

    if not errors and (EXTRACTED_ROOT.exists() or EXTRACTED_ROOT.is_symlink()):
        def remove_extracted():
            names = set(os.listdir(EXTRACTED_ROOT))
            if not names:
                EXTRACTED_ROOT.rmdir()
                return
            _require(values is not None, "extracted staging lacks durable manifest")
            _require((names <= {"kata", "containerd"} if receipt is None else
                      names == {"kata", "containerd"}))
            for archive in values:
                role_root = EXTRACTED_ROOT / archive["role"]
                marker = role_root / ".extraction-intent.json"
                partial_marker = role_root / "..extraction-intent.json.partial"
                pin = next(item for item in preparation.ARCHIVES
                           if item["role"] == archive["role"])
                intent = preparation.canonical_bytes({
                    "version": "cogs.stage2-runtime-extraction-intent/v1",
                    "archive_name": pin["name"], "archive_size": pin["size"],
                    "archive_sha256": pin["sha256"]})
                interrupted = marker.exists()
                if marker.exists():
                    _require(marker.read_bytes() == intent); marker.unlink()
                elif partial_marker.exists():
                    seen_marker = partial_marker.lstat()
                    _require(stat.S_ISREG(seen_marker.st_mode)
                             and seen_marker.st_uid == seen_marker.st_gid == 0
                             and seen_marker.st_nlink == 1
                             and stat.S_IMODE(seen_marker.st_mode) == 0o400
                             and intent.startswith(partial_marker.read_bytes()))
                    partial_marker.unlink()
                rows = archive["extracted"]["entries"]
                kata_root = EXTRACTED_ROOT / "kata"
                moved_before_recovery = (archive["role"] == "kata"
                                         and not (kata_root / "opt/kata").exists())
                if archive["role"] == "kata" and (kata_moved or moved_before_recovery):
                    rows = [row for row in rows
                            if row["path"] != "opt/kata"
                            and not row["path"].startswith("opt/kata/")]
                _remove_verified_tree(role_root, rows, subset=True,
                                      allow_truncated=interrupted)
            EXTRACTED_ROOT.rmdir()
        cleanup(remove_extracted)

    if not errors and (RUNTIME_CACHE.exists() or RUNTIME_CACHE.is_symlink()):
        def remove_runtime_cache():
            _directory_identity(RUNTIME_CACHE)
            pins = {pin["name"]: pin for pin in preparation.ARCHIVES}
            partials = {"." + name + ".partial": pin for name, pin in pins.items()}
            quarantines = {name + ".removing": pin for name, pin in partials.items()}
            names = set(os.listdir(RUNTIME_CACHE))
            _require(names <= set(pins) | set(partials) | set(quarantines),
                     "foreign runtime cache entry")
            for name, pin in pins.items():
                present = {candidate for candidate in
                           (name, "." + name + ".partial", "." + name + ".partial.removing")
                           if candidate in names}
                _require(len(present) <= 1, "duplicate runtime cache generations")
                if name in present:
                    _stable_file(RUNTIME_CACHE / name, pin)
                elif present:
                    partial = RUNTIME_CACHE / ("." + name + ".partial")
                    quarantine = RUNTIME_CACHE / ("." + name + ".partial.removing")
                    _remove_runtime_partial(partial, quarantine, pin)
            os.chmod(RUNTIME_CACHE, 0o700)
            for name in sorted(set(os.listdir(RUNTIME_CACHE))):
                _require(name in pins, "runtime partial settlement drift")
                (RUNTIME_CACHE / name).unlink()
            _sync_directory(RUNTIME_CACHE)
            RUNTIME_CACHE.rmdir()
        cleanup(remove_runtime_cache)

    receipt_partial = RECEIPT.with_name("." + RECEIPT.name + ".partial")
    if not errors and (receipt_partial.exists() or receipt_partial.is_symlink()):
        def remove_receipt_partial():
            seen = receipt_partial.lstat()
            _require(stat.S_ISREG(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                     and seen.st_nlink == 1 and stat.S_IMODE(seen.st_mode) == 0o400
                     and 0 <= seen.st_size <= MAX_RECEIPT_BYTES)
            receipt_partial.unlink(); _sync_directory(receipt_partial.parent)
        cleanup(remove_receipt_partial, "partial receipt")
    if not errors and receipt is not None:
        cleanup(lambda: (_require(RECEIPT.read_bytes() == receipt[0]), RECEIPT.unlink()),
                "receipt")
    if not errors and descriptor is not None:
        cleanup(lambda: _remove_prebuilt_input(descriptor, descriptor_raw),
                "prebuilt rootfs input")
    if not errors:
        cleanup(lambda: PREPARATION_ROOT.rmdir(), "preparation root")
        if not errors:
            _sync_directory(PREPARATION_ROOT.parent)
    if errors:
        raise _error_group("immutable preparation rollback uncertainty", errors)


def _forbidden_mutable_paths():
    return (
        COMPLETION_ROOT / "kata-input-v1",
        Path("/run/cogs-stage2-local-private-v2"),
        Path("/run/cogs-stage2-ssh"),
        Path("/run/vc/vm/cogs-stage2-ssh-v1"),
    )


def _operation_state_idle():
    """Authenticate journal-absent infrastructure retained after exact retirement."""
    import completion_kata_operation as operation
    probe = operation._open_fixed_operation_recovery()
    try:
        return probe.status() in {
            "infrastructure-absent", "infrastructure-subset", "infrastructure-complete"}
    finally:
        probe.close()


def _rootfs_state_idle():
    import completion_rootfs_fs as rootfs_fs
    import completion_rootfs_lease as rootfs_lease
    control = rootfs_fs.OperationControl(time.monotonic_ns() + 30_000_000_000,
                                         lambda: False)
    return rootfs_lease._prestage_rootfs_absent(control)


def recover_failed_preparation():
    """Inspect and settle only durable immutable transaction custody."""
    _require(not any(path.exists() or path.is_symlink()
                     for path in _forbidden_mutable_paths()))
    operation_state = COMPLETION_ROOT / "kata-operation-v1"
    if operation_state.exists() or operation_state.is_symlink():
        _require(_operation_state_idle(),
                 "active operation state blocks immutable recovery")
    rootfs_state = COMPLETION_ROOT / "rootfs-v1"
    if rootfs_state.exists() or rootfs_state.is_symlink():
        _require(_rootfs_state_idle(),
                 "active rootfs state blocks immutable recovery")
    expected_runtime = _expected_runtime()
    import completion_rootfs_prebuilt as rootfs_prebuilt
    descriptor_raw = _prebuilt_descriptor_bytes(expected_runtime)
    descriptor = rootfs_prebuilt.decode_fixed_descriptor(descriptor_raw)
    _rollback_preparation(descriptor, descriptor_raw)
    _require(not PREPARATION_ROOT.exists() and not preparation.PREBUILT_INPUT_ROOT.exists()
             and not IMMUTABLE_STAGING.exists() and not STAGED_RUNTIME.exists() and not KATA_ROOT.exists())
    return None


def prepare():
    global _OBSERVATION_STAGE
    _reject_ambient_authority()
    _require(SOURCE_ROOT.is_dir())
    _OBSERVATION_STAGE = "preflight"
    _extractor_preflight()
    _prepare_state_parents()
    _verify_extraction_filesystem()
    _require(not PREPARATION_ROOT.exists() and not preparation.PREBUILT_INPUT_ROOT.exists()
             and not IMMUTABLE_STAGING.exists()
             and not STAGED_RUNTIME.exists() and not KATA_ROOT.exists())
    _OBSERVATION_STAGE = "expected-control"
    expected_runtime = _expected_runtime()
    import completion_rootfs_prebuilt as rootfs_prebuilt
    import completion_rootfs_prebuilt_acquisition as prebuilt_acquisition
    descriptor_raw = _prebuilt_descriptor_bytes(expected_runtime)
    descriptor = rootfs_prebuilt.decode_fixed_descriptor(descriptor_raw)
    created = False
    try:
        _OBSERVATION_STAGE = "ownership"
        PREPARATION_ROOT.mkdir(mode=0o700)
        created = True
        _sync_directory(PREPARATION_ROOT.parent)
        RUNTIME_CACHE.mkdir(mode=0o700)
        EXTRACTED_ROOT.mkdir(mode=0o700)
        deadline = time.monotonic() + GLOBAL_SECONDS
        _OBSERVATION_STAGE = "rootfs-acquisition"
        rootfs_receipt = prebuilt_acquisition.acquire_fixed(descriptor_raw)
        _require(time.monotonic() < deadline)
        _OBSERVATION_STAGE = "runtime-acquisition"
        archives = {pin["role"]: _download_runtime(pin, deadline) for pin in preparation.ARCHIVES}
        extracted = {}
        for pin in preparation.ARCHIVES:
            _OBSERVATION_STAGE = f"extract-{pin['role']}"
            root = EXTRACTED_ROOT / pin["role"]
            _run_extract(archives[pin["role"]], root)
            extracted[pin["role"]] = root
        _OBSERVATION_STAGE = "archive-values"
        values = _archive_values(expected_runtime, archives, extracted)
        raw = preparation.canonical_bytes({
            "version": VERSION,
            "authority": "immutable-public-input-preparation-only",
            "rootfs_artifact": {
                "descriptor_sha256": rootfs_receipt.descriptor_sha256,
                "manifest_digest": rootfs_receipt.manifest_digest,
                "blob_sha256": rootfs_receipt.blob_sha256,
                "blob_size": rootfs_receipt.blob_size,
                "intent_sha256": rootfs_receipt.intent_sha256,
                "settlement_sha256": rootfs_receipt.settlement_sha256,
                "downloaded": rootfs_receipt.downloaded,
            },
            "runtime_archives": values,
            "forbidden_surfaces": ["containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"],
        })
        _OBSERVATION_STAGE = "receipt"
        _write_owned_file(RECEIPT, raw, 0o400)
        _sync_directory(PREPARATION_ROOT)
        _OBSERVATION_STAGE = "publication"
        _publish_runtime(extracted)
        _OBSERVATION_STAGE = "installed-verification"
        _verify_installed(expected_runtime)
        _OBSERVATION_STAGE = "package-verification"
        rootfs_prebuilt.load_authority(
            descriptor_raw, preparation.PREBUILT_USTAR_PATH.read_bytes())
        return {"version": VERSION, "rootfs_artifact_count": 1,
                "runtime_archive_count": 2,
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                "control_verified": expected_runtime is not None,
                "authority": "immutable-public-input-preparation-only"}
    except BaseException as primary:
        if not created:
            raise
        try:
            _rollback_preparation(descriptor, descriptor_raw)
        except BaseException as rollback:
            raise _error_group(
                "immutable preparation failed with rollback uncertainty",
                (primary, rollback))
        raise


def main():
    value = prepare()
    raw = preparation.canonical_bytes(value)
    _require(sys.stdout.buffer.write(raw) == len(raw))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        try:
            stage = _OBSERVATION_STAGE if _OBSERVATION_STAGE in _DIAGNOSTIC_STAGES else "entry"
            message = f"immutable Stage 2 preparation failed at {stage}\n".encode("ascii")
            if len(message) <= 96:
                sys.stderr.buffer.write(message)
        except BaseException:
            pass
        raise SystemExit(2)

#!/usr/bin/env python3
"""Exact immutable asset preparation before Stage 2 role custody.

This zero-argument transaction owns the fixed public cache, verifies all 16
rootfs inputs and both runtime archives, extracts the static runtime without
launching it, and installs the Kata fixture.  It does not open KVM, QMP,
containerd, ctr, SSH, task, or guest-network surfaces.
"""

import hashlib
import http.client
import importlib.util
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

import completion_kata_preparation as preparation

_VERIFIER_PATH = Path(__file__).with_name("verify-completion-artifacts.py")
_verifier_spec = importlib.util.spec_from_file_location(
    "completion_fixed_artifact_verifier", _VERIFIER_PATH)
_require_verifier = _verifier_spec is not None and _verifier_spec.loader is not None
if not _require_verifier:
    raise ImportError("fixed artifact verifier is unavailable")
artifact_verifier = importlib.util.module_from_spec(_verifier_spec)
_verifier_spec.loader.exec_module(artifact_verifier)

VERSION = "cogs.stage2-local-immutable-preparation/v1"
SOURCE_ROOT = Path("/var/lib/cogs/stage2-completion-v1/source")
CONTROL_ROOT = Path("/var/lib/cogs/stage2-completion-v1/control")
COMPLETION_ROOT = SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1"
ARTIFACT_ROOT = COMPLETION_ROOT / "artifacts"
PREPARATION_ROOT = COMPLETION_ROOT / "immutable-preparation-v1"
RUNTIME_CACHE = PREPARATION_ROOT / "runtime-cache"
EXTRACTED_ROOT = PREPARATION_ROOT / "extracted"
RECEIPT = PREPARATION_ROOT / "receipt.json"
STAGED_RUNTIME = COMPLETION_ROOT / "kata-runtime-v1"
KATA_ROOT = Path("/opt/kata")
KATA_PARENT = Path("/opt")
MAX_REDIRECTS = 3
GLOBAL_SECONDS = 1_700
CHUNK = 1024 * 1024
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


def _require(condition, message="immutable preparation failed"):
    if not condition:
        raise ImmutablePreparationError(message)


def _chown_root(descriptor):
    os.fchown(descriptor, 0, 0)


def _identity(value):
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _reject_ambient_authority():
    _require(os.geteuid() == 0 and sys.argv == [sys.argv[0]])
    _require(sys.platform.startswith("linux") and os.uname().machine == "x86_64")
    for name in os.environ:
        upper = name.upper()
        _require(upper not in DENIED_ENV and not upper.startswith("AWS_"),
                 "ambient acquisition authority is forbidden")


def _fixed_contract():
    contract = artifact_verifier.verify_contract(artifact_verifier.FIXED_CONTRACT_PATH)
    _require(contract["bounds"]["artifact_count"] == 16)
    return contract


def _acquire_rootfs_assets(contract):
    """Use the existing hardened immutable acquisition with internally fixed authority."""
    import completion_artifact_acquisition as acquisition

    context = acquisition._tls_context()
    routes = acquisition._artifact_routes(contract)
    _require(len(routes) == 16)
    acquisition._acquire_rows(
        routes, ARTIFACT_ROOT, acquisition._HttpsTransport(context),
        contract["timeouts_seconds"])
    artifact_verifier.verify_package_archives(
        artifact_verifier.FIXED_CONTRACT_PATH, ARTIFACT_ROOT)


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
    before = path.stat(follow_symlinks=False)
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
    _require(_identity(path.stat(follow_symlinks=False)) == _identity(before)
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


def _run_extract(archive, destination):
    destination.mkdir(mode=0o700)
    command = ["/usr/bin/tar", "--extract", "--file", str(archive), "--directory", str(destination),
               "--numeric-owner", "--same-owner", "--no-overwrite-dir", "--delay-directory-restore"]
    if archive.name.endswith(".tar.zst"):
        command.insert(2, "--zstd")
    result = subprocess.run(
        tuple(command), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                                        "PATH": "/usr/bin:/bin"},
        timeout=600, check=False, close_fds=True, start_new_session=True)
    _require(result.returncode == 0, "fixed runtime extraction failed")


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
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
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


def _publish_runtime(extracted):
    _require(not STAGED_RUNTIME.exists() and not KATA_ROOT.exists())
    staged = STAGED_RUNTIME.with_name(".kata-runtime-v1.immutable-staging")
    _require(not staged.exists())
    staged.mkdir(mode=0o700)
    (staged / "bin").mkdir(mode=0o700)
    try:
        for relative, size, digest, mode in __import__("completion_kata_command_policy").CONTAINERD_EXTRACTION:
            source = extracted["containerd"] / relative
            _require(source.is_file() and source.stat().st_size == size
                     and hashlib.sha256(source.read_bytes()).hexdigest() == digest)
            _copy_fixed(source, staged / relative, mode)
        os.chmod(staged / "bin", 0o500)
        os.rename(staged, STAGED_RUNTIME)
        kata_source = extracted["kata"] / "opt/kata"
        _require(kata_source.is_dir())
        os.rename(kata_source, KATA_ROOT)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        shutil.rmtree(STAGED_RUNTIME, ignore_errors=True)
        shutil.rmtree(KATA_ROOT, ignore_errors=True)
        raise


def _verify_installed(expected_runtime):
    _require(STAGED_RUNTIME.is_dir() and KATA_ROOT.is_dir())
    if expected_runtime is None:
        return
    for row in expected_runtime["launch"]["artifacts"]:
        path = Path(row["path"])
        seen = path.lstat()
        _require(stat.S_IMODE(seen.st_mode) == row["mode"] and seen.st_size == row["size"])
        if row["kind"] == "file":
            _require(stat.S_ISREG(seen.st_mode) and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"])
        else:
            _require(stat.S_ISLNK(seen.st_mode) and os.readlink(path) == row["link_target"])


def recover_failed_preparation():
    """Prove the transaction rolled back before any mutable lifecycle existed."""
    _require(not PREPARATION_ROOT.exists() and not STAGED_RUNTIME.exists()
             and not KATA_ROOT.exists())
    forbidden = (
        COMPLETION_ROOT / "kata-operation-v1",
        COMPLETION_ROOT / "kata-input-v1",
        COMPLETION_ROOT / "rootfs-v1",
        Path("/run/cogs-stage2-local-private-v2"),
        Path("/run/cogs-stage2-ssh"),
        Path("/run/vc/vm/cogs-stage2-ssh-v1"),
    )
    _require(not any(path.exists() or path.is_symlink() for path in forbidden))
    return None


def prepare():
    _reject_ambient_authority()
    _require(SOURCE_ROOT.is_dir() and not PREPARATION_ROOT.exists()
             and not STAGED_RUNTIME.exists() and not KATA_ROOT.exists())
    contract = _fixed_contract()
    expected_runtime = _expected_runtime()
    created = False
    try:
        PREPARATION_ROOT.mkdir(mode=0o700)
        created = True
        RUNTIME_CACHE.mkdir(mode=0o700)
        EXTRACTED_ROOT.mkdir(mode=0o700)
        deadline = time.monotonic() + GLOBAL_SECONDS
        _acquire_rootfs_assets(contract)
        _require(time.monotonic() < deadline)
        archives = {pin["role"]: _download_runtime(pin, deadline) for pin in preparation.ARCHIVES}
        extracted = {}
        for pin in preparation.ARCHIVES:
            root = EXTRACTED_ROOT / pin["role"]
            _run_extract(archives[pin["role"]], root)
            extracted[pin["role"]] = root
        values = _archive_values(expected_runtime, archives, extracted)
        raw = preparation.canonical_bytes({
            "version": VERSION,
            "authority": "immutable-public-input-preparation-only",
            "rootfs_artifact_count": 16,
            "runtime_archives": values,
            "forbidden_surfaces": ["containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"],
        })
        descriptor = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(descriptor, raw[offset:])
                _require(count > 0)
                offset += count
            _chown_root(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _publish_runtime(extracted)
        _verify_installed(expected_runtime)
        artifact_verifier.verify_package_archives(
            artifact_verifier.FIXED_CONTRACT_PATH, ARTIFACT_ROOT)
        return {"version": VERSION, "rootfs_artifact_count": 16,
                "runtime_archive_count": 2,
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                "control_verified": expected_runtime is not None,
                "authority": "immutable-public-input-preparation-only"}
    except BaseException:
        if created:
            shutil.rmtree(PREPARATION_ROOT, ignore_errors=True)
        shutil.rmtree(STAGED_RUNTIME, ignore_errors=True)
        shutil.rmtree(KATA_ROOT, ignore_errors=True)
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
            sys.stderr.buffer.write(b"immutable Stage 2 preparation failed\n")
        except BaseException:
            pass
        raise SystemExit(2)

"""Fixed public GHCR acquisition for the descriptor-selected prebuilt rootfs."""

from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from urllib.parse import quote, urlsplit

sys.dont_write_bytecode = True

import completion_rootfs_prebuilt as prebuilt

ROOT = Path("/var/lib/cogs/stage2-completion-v1/prebuilt-rootfs-input-v1")
FINAL_NAME = "rootfs.tar"
PARTIAL_NAME = ".rootfs.tar.partial"
SENTINEL_NAME = ".cogs-stage2-prebuilt-rootfs-input-v1"
INTENT_NAME = ".acquisition-intent-v1.json"
SETTLEMENT_NAME = ".acquisition-settlement-v1.json"
SENTINEL = b"cogs-stage2-prebuilt-rootfs-input/v1\n"
TOKEN_HOST = "ghcr.io"
BLOB_HOST = "ghcr.io"
REDIRECT_HOST = "pkg-containers.githubusercontent.com"
USER_AGENT = "cogs-stage2-prebuilt-rootfs-acquisition/1"
TOKEN_MAX = 16_384
MANIFEST_MAX = 256 * 1024
HEADER_MAX = 64
HEADER_BYTES_MAX = 32_768
CHUNK = 1024 * 1024
SECONDS = 600
_TOKEN = re.compile(r"[!-~]{1,8192}")
_HEADER = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")


class PrebuiltAcquisitionError(Exception):
    pass


def _require(condition):
    if not condition:
        raise PrebuiltAcquisitionError()


@dataclass(frozen=True)
class Request:
    url: str
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class AcquisitionReceipt:
    descriptor_sha256: str
    manifest_digest: str
    blob_sha256: str
    blob_size: int
    intent_sha256: str
    settlement_sha256: str
    path: str
    downloaded: bool


class _Response:
    def __init__(self, connection, response):
        self.connection = connection
        self.response = response
        self.status = response.status
        self.version = response.version
        self.headers = tuple(response.getheaders())
        self.closed = False

    def read(self, size, deadline):
        _require(not self.closed and deadline > time.monotonic())
        socket = self.connection.sock
        _require(socket is not None)
        socket.settimeout(deadline - time.monotonic())
        value = self.response.read(size)
        _require(type(value) is bytes)
        return value

    def close(self):
        if self.closed:
            return
        self.closed = True
        error = None
        for target in (self.response, self.connection):
            try: target.close()
            except Exception as caught:
                if error is None: error = caught
        if error is not None: raise error


class HttpsTransport:
    def __init__(self):
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        _require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname)
        self.context = context

    def request(self, request, timeout):
        parsed = _strict_url(request.url)
        connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=timeout, context=self.context)
        try:
            target = parsed.path + ("?" + parsed.query if parsed.query else "")
            connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", parsed.hostname)
            for name, value in request.headers: connection.putheader(name, value)
            connection.endheaders()
            return _Response(connection, connection.getresponse())
        except BaseException:
            connection.close(); raise


def _strict_url(value):
    _require(type(value) is str and 0 < len(value) <= 16_384)
    try:
        value.encode("ascii"); parsed = urlsplit(value); port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise PrebuiltAcquisitionError() from error
    _require(parsed.scheme == "https" and parsed.hostname and parsed.netloc == parsed.hostname and port is None)
    _require(parsed.username is None and parsed.password is None and not parsed.fragment)
    _require(parsed.path.startswith("/") and "\\" not in parsed.path and "//" not in parsed.path)
    _require(all(part not in {".", ".."} for part in parsed.path.split("/")))
    return parsed


def _headers(response):
    _require(response.version == 11 and type(response.status) is int)
    _require(type(response.headers) in {tuple, list} and len(response.headers) <= HEADER_MAX)
    values = {}
    total = 0
    for pair in response.headers:
        _require(type(pair) in {tuple, list} and len(pair) == 2)
        name, value = pair
        _require(type(name) is str and type(value) is str and _HEADER.fullmatch(name) is not None)
        try: encoded = value.encode("ascii")
        except UnicodeEncodeError as error: raise PrebuiltAcquisitionError() from error
        _require(all(byte == 9 or byte == 32 or 33 <= byte <= 126 for byte in encoded))
        total += len(name) + len(encoded) + 4; _require(total <= HEADER_BYTES_MAX)
        values.setdefault(name.lower(), []).append(value.strip(" \t"))
    return values


def _one(headers, name):
    values = headers.get(name, [])
    _require(len(values) == 1)
    return values[0]


def _bounded_body(response, maximum, deadline):
    chunks = []
    total = 0
    while total <= maximum:
        part = response.read(min(CHUNK, maximum + 1 - total), deadline)
        if not part: break
        chunks.append(part); total += len(part)
    _require(total <= maximum)
    return b"".join(chunks)


def _token(transport, descriptor, deadline):
    scope = quote(f"repository:{prebuilt.REGISTRY_REPOSITORY}:pull", safe="")
    request = Request(
        f"https://{TOKEN_HOST}/token?service=ghcr.io&scope={scope}",
        (("Accept", "application/json"), ("User-Agent", USER_AGENT)),
    )
    response = transport.request(request, max(1, deadline - time.monotonic()))
    try:
        headers = _headers(response)
        _require(response.status == 200 and _one(headers, "content-type") == "application/json")
        _require("transfer-encoding" not in headers and "content-encoding" not in headers)
        length = int(_one(headers, "content-length")); _require(0 < length <= TOKEN_MAX)
        raw = _bounded_body(response, length, deadline); _require(len(raw) == length)
    finally: response.close()
    try: value = json.loads(raw)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error: raise PrebuiltAcquisitionError() from error
    _require(type(value) is dict and set(value) == {"token"} and type(value["token"]) is str)
    _require(_TOKEN.fullmatch(value["token"]) is not None)
    return value["token"]


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value)
        value[key] = item
    return value


def _manifest(transport, descriptor, token, deadline):
    request = Request(
        f"https://{BLOB_HOST}{descriptor.manifest_path()}",
        (("Accept", prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE),
         ("Authorization", "Bearer " + token), ("User-Agent", USER_AGENT)),
    )
    response = transport.request(request, max(1, deadline - time.monotonic()))
    try:
        headers = _headers(response)
        _require(response.status == 200
                 and _one(headers, "content-type") == prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE
                 and "transfer-encoding" not in headers
                 and "content-encoding" not in headers)
        length = int(_one(headers, "content-length"))
        _require(0 < length <= MANIFEST_MAX)
        raw = _bounded_body(response, length, deadline); _require(len(raw) == length)
    finally:
        response.close()
    _require(hashlib.sha256(raw).hexdigest() == descriptor.manifest_digest)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PrebuiltAcquisitionError() from error
    _require(type(value) is dict and value.get("schemaVersion") == 2
             and value.get("mediaType") == prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE
             and value.get("artifactType") ==
                 "application/vnd.cogs.stage2.rootfs.package.v1")
    config = value.get("config")
    _require(type(config) is dict
             and {"mediaType", "digest", "size"} <= set(config)
             and set(config) <= {"mediaType", "digest", "size", "annotations"}
             and type(config["mediaType"]) is str
             and re.fullmatch(r"sha256:[0-9a-f]{64}", config["digest"]) is not None
             and type(config["size"]) is int and config["size"] >= 0)
    layers = value.get("layers")
    _require(type(layers) is list and 1 <= len(layers) <= 16)
    matches = []
    for row in layers:
        _require(type(row) is dict and set(row) <= {"mediaType", "digest", "size", "annotations"}
                 and {"mediaType", "digest", "size"} <= set(row)
                 and type(row["mediaType"]) is str and type(row["digest"]) is str
                 and type(row["size"]) is int and row["size"] > 0)
        if row["mediaType"] == prebuilt.REGISTRY_LAYER_MEDIA_TYPE:
            matches.append(row)
    _require(len(matches) == 1 and matches[0]["digest"] == "sha256:" + descriptor.layer_digest
             and matches[0]["size"] == descriptor.layer_size)
    return hashlib.sha256(raw).hexdigest()


def _redirect(transport, descriptor, token, deadline):
    request = Request(
        f"https://{BLOB_HOST}{descriptor.blob_path()}",
        (("Accept", prebuilt.REGISTRY_LAYER_MEDIA_TYPE), ("Authorization", "Bearer " + token),
         ("User-Agent", USER_AGENT)),
    )
    response = transport.request(request, max(1, deadline - time.monotonic()))
    try:
        headers = _headers(response)
        _require(response.status == 307 and "transfer-encoding" not in headers and "content-encoding" not in headers)
        location = _one(headers, "location")
        parsed = _strict_url(location)
        _require(parsed.hostname == REDIRECT_HOST and parsed.query and len(parsed.query) <= 4096)
        _require(re.fullmatch(r"/ghcr(?:1|blobs[0-9]+)/blobs/sha256:" + descriptor.layer_digest, parsed.path) is not None)
        length = int(_one(headers, "content-length")) if "content-length" in headers else 0
        _require(0 <= length <= 4096)
        _require(len(_bounded_body(response, length, deadline)) == length)
        return location
    finally: response.close()


def _write_blob(transport, descriptor, location, directory, deadline, owner):
    response = transport.request(
        Request(location, (("Accept", "application/octet-stream"), ("User-Agent", USER_AGENT))),
        max(1, deadline - time.monotonic()))
    descriptor_fd = -1
    try:
        headers = _headers(response)
        _require(response.status == 200 and _one(headers, "content-type") == "application/octet-stream")
        _require("transfer-encoding" not in headers and "content-encoding" not in headers)
        _require(int(_one(headers, "content-length")) == descriptor.layer_size)
        descriptor_fd = os.open(PARTIAL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        digest = hashlib.sha256(); total = 0
        while total < descriptor.layer_size:
            part = response.read(min(CHUNK, descriptor.layer_size - total), deadline)
            _require(part)
            view = memoryview(part)
            while view:
                count = os.write(descriptor_fd, view); _require(count > 0); view = view[count:]
            digest.update(part); total += len(part)
        _require(response.read(1, deadline) == b"")
        _require(total == descriptor.layer_size and digest.hexdigest() == descriptor.layer_digest)
        os.fchown(descriptor_fd, *owner); os.fchmod(descriptor_fd, 0o400); os.fsync(descriptor_fd)
        os.close(descriptor_fd); descriptor_fd = -1
        os.link(PARTIAL_NAME, FINAL_NAME, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(PARTIAL_NAME, dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor_fd >= 0: os.close(descriptor_fd)
        response.close()


def _stable_final(directory, descriptor, owner):
    fd = os.open(FINAL_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400)
        _require((before.st_uid, before.st_gid) == owner and before.st_nlink == 1 and before.st_size == descriptor.layer_size)
        digest = hashlib.sha256(); total = 0
        while total < before.st_size:
            part = os.read(fd, min(CHUNK, before.st_size - total)); _require(part); digest.update(part); total += len(part)
        after = os.fstat(fd)
        stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        _require(total == descriptor.layer_size and digest.hexdigest() == descriptor.layer_digest and stable(before) == stable(after))
    finally: os.close(fd)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _write_record(directory, name, value, owner):
    raw = _canonical(value)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        _require(os.write(descriptor, raw) == len(raw))
        os.fchown(descriptor, *owner); os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)
    return hashlib.sha256(raw).hexdigest()


def _acquire(descriptor_raw, transport, root, fixed=False, owner=None):
    _require(type(fixed) is bool)
    owner = (os.geteuid(), os.getegid()) if owner is None else owner
    _require(type(owner) is tuple and len(owner) == 2
             and all(type(item) is int and item >= 0 for item in owner))
    descriptor = (prebuilt.decode_fixed_descriptor(descriptor_raw) if fixed
                  else prebuilt.decode_descriptor(descriptor_raw))
    _require(isinstance(root, Path) and (type(transport) is HttpsTransport or hasattr(transport, "request")))
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chown(root, *owner); os.chmod(root, 0o700)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    downloaded = False
    try:
        _require(os.listdir(directory) == [])
        root_stat = os.fstat(directory)
        descriptor_sha256 = hashlib.sha256(descriptor_raw).hexdigest()
        intent_sha256 = _write_record(directory, INTENT_NAME, {
            "version": "cogs.stage2-prebuilt-rootfs-acquisition-intent/v1",
            "descriptor_sha256": descriptor_sha256,
            "manifest_digest": descriptor.manifest_digest,
            "blob_sha256": descriptor.layer_digest,
            "blob_size": descriptor.layer_size,
            "root_device": root_stat.st_dev, "root_inode": root_stat.st_ino,
        }, owner)
        deadline = time.monotonic() + SECONDS
        token = _token(transport, descriptor, deadline)
        _require(_manifest(transport, descriptor, token, deadline) == descriptor.manifest_digest)
        location = _redirect(transport, descriptor, token, deadline)
        _write_blob(transport, descriptor, location, directory, deadline, owner)
        downloaded = True
        _stable_final(directory, descriptor, owner)
        sentinel = os.open(SENTINEL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try: _require(os.write(sentinel, SENTINEL) == len(SENTINEL)); os.fchown(sentinel, *owner); os.fsync(sentinel)
        finally: os.close(sentinel)
        final_stat = os.stat(FINAL_NAME, dir_fd=directory, follow_symlinks=False)
        settlement_sha256 = _write_record(directory, SETTLEMENT_NAME, {
            "version": "cogs.stage2-prebuilt-rootfs-acquisition-settlement/v1",
            "intent_sha256": intent_sha256,
            "descriptor_sha256": descriptor_sha256,
            "blob_sha256": descriptor.layer_digest,
            "blob_size": descriptor.layer_size,
            "file_device": final_stat.st_dev, "file_inode": final_stat.st_ino,
        }, owner)
        os.fsync(directory)
        _require(set(os.listdir(directory)) == {
            FINAL_NAME, SENTINEL_NAME, INTENT_NAME, SETTLEMENT_NAME})
        return AcquisitionReceipt(descriptor_sha256, descriptor.manifest_digest,
                                  descriptor.layer_digest, descriptor.layer_size,
                                  intent_sha256, settlement_sha256,
                                  str(root / FINAL_NAME), downloaded)
    finally: os.close(directory)


def acquire_fixed(descriptor_raw):
    _require(os.geteuid() == 0)
    return _acquire(descriptor_raw, HttpsTransport(), ROOT, True, (0, 0))

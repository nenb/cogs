"""Fixed, no-overwrite acquisition for the Stage 2 completion artifact cache."""

from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.parse import quote, urljoin, urlsplit

APPROVAL_NAME = "COGS_STAGE2_ARTIFACT_ACQUISITION_APPROVED"
APPROVAL_VALUE = "download-16-fixed-public-stage2-artifacts"
TOKEN_URL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fdebian%3Apull"
REGISTRY_HOST = "registry-1.docker.io"
SNAPSHOT_HOST = "snapshot.debian.org"
CDN_HOSTS = {
    "production.cloudflare.docker.com",
    "production.cloudfront.docker.com",
    "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
}
USER_AGENT = "cogs-stage2-acquisition/1"
SENTINEL = ".cogs-stage2-completion-artifacts-v1"
SENTINEL_BYTES = b"cogs-stage2-completion-artifacts-v1\n"
TOKEN_BODY_MAX = 16384
REDIRECT_BODY_MAX = 4096
HEADER_COUNT_MAX = 64
HEADER_BYTES_MAX = 32768
GLOBAL_SECONDS = 1200
CHUNK = 65536
DENIED_ENV = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "PYTHONHTTPSVERIFY",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "NETRC",
    "DOCKER_CONFIG",
    "REGISTRY_AUTH_FILE",
    "DOCKER_AUTH_CONFIG",
    "AUTHORIZATION",
    "BEARER_TOKEN",
    "REGISTRY_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
}
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
SNAPSHOT_FILE_PATH = re.compile(r"^/file/(?:[a-f0-9]{40}|[a-f0-9]{64})$")
TOKEN_TEXT = re.compile(r"^[!-~]{1,8192}$")
STAGES = frozenset(
    {
        "preflight", "tls", "routes", "state", "token.request", "token.headers", "token.header-shape",
        "token.header-encoding", "token.header-authority", "token.status", "token.content-type", "token.framing",
        "token.body", "token.json", "artifact.request", "artifact.headers", "artifact.response-headers",
        "artifact.redirect", "artifact.redirect.status", "artifact.redirect.location", "artifact.redirect.location-shape",
        "artifact.redirect.location.url", "artifact.redirect.location.host", "artifact.redirect.location.host-docker-com",
        "artifact.redirect.location.host-cloudflare-storage", "artifact.redirect.location.host-docker-io",
        "artifact.redirect.location.host-other", "artifact.redirect.location.query", "artifact.redirect.location.path",
        "artifact.redirect.location.path.percent", "artifact.redirect.location.path.filename", "artifact.redirect.location.path.archive", "artifact.redirect.location.path.other",
        "artifact.redirect.framing", "artifact.redirect.framing.transfer", "artifact.redirect.framing.length",
        "artifact.redirect.framing.body", "artifact.redirect.count", "artifact.final", "artifact.final.transfer",
        "artifact.final.length", "artifact.final.content-type", "artifact.final.content-type.missing",
        "artifact.final.content-type.parameterized", "artifact.final.content-type.application",
        "artifact.final.content-type.text", "artifact.final.content-type.other", "artifact.body", "publish", "postverify",
    }
)


class AcquisitionError(Exception):
    def __init__(self, stage=None):
        self.stage = stage if type(stage) is str and stage in STAGES else None
        super().__init__()


def _fail(condition, stage=None):
    if not condition:
        raise AcquisitionError(stage)


def _stage(stage, callback):
    _fail(stage in STAGES)
    try:
        return callback()
    except AcquisitionError as error:
        if error.stage is None:
            raise AcquisitionError(stage) from error
        raise
    except Exception as error:
        raise AcquisitionError(stage) from error


@dataclass(frozen=True)
class Request:
    url: str
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Route:
    row: dict
    source: str
    accept: str
    content_types: tuple[str, ...]


class _LiveResponse:
    def __init__(self, connection, response, read_socket):
        self.connection = connection
        self.response = response
        self.read_socket = read_socket
        self.closed = False
        self.version = response.version
        self.status = response.status
        self.headers = tuple(response.getheaders())

    def read(self, size, deadline):
        closed = self.response.isclosed()
        _fail(type(closed) is bool)
        if not self.closed and closed:
            body = self.response.read(size)
            _fail(type(body) is bytes and body == b"")
            return body
        remaining = deadline - time.monotonic()
        _fail(remaining > 0 and self.read_socket is not None)
        self.read_socket.settimeout(remaining)
        body = self.response.read(size)
        _fail(type(body) is bytes)
        return body

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.read_socket = None
        first_error = None
        for target in (self.response, self.connection):
            try:
                target.close()
            except Exception as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


class _HttpsTransport:
    def __init__(self, context):
        self.context = context

    def request(self, request, timeout):
        parsed = _strict_url(request.url)
        connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=timeout, context=self.context)
        try:
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", parsed.hostname)
            for name, value in request.headers:
                connection.putheader(name, value)
            connection.endheaders()
            read_socket = connection.sock
            _fail(read_socket is not None)
            response = connection.getresponse()
            return _LiveResponse(connection, response, read_socket)
        except Exception:
            connection.close()
            raise


def _reject_ambient_authority(environ):
    _fail(type(environ) is dict or hasattr(environ, "items"))
    _fail(environ.get(APPROVAL_NAME) == APPROVAL_VALUE)
    for key in environ:
        name = str(key)
        upper = name.upper()
        _fail(upper != APPROVAL_NAME or name == APPROVAL_NAME)
        _fail(upper not in DENIED_ENV and not upper.startswith("AWS_") and upper != ".ENV")


def _tls_context():
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    _fail(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname)
    return context


def _strict_url(value):
    _fail(type(value) is str and 0 < len(value) <= 16384)
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise AcquisitionError() from error
    _fail(parsed.scheme == "https" and parsed.hostname and port is None)
    _fail(parsed.username is None and parsed.password is None and not parsed.fragment)
    _fail(parsed.netloc == parsed.hostname and parsed.path.startswith("/") and len(parsed.path.encode()) <= 4096)
    _fail("\\" not in parsed.path and "//" not in parsed.path)
    _fail(all(part not in {".", ".."} for part in parsed.path.split("/")))
    _fail(all(32 < ord(character) < 127 for character in value))
    return parsed


def _strict_headers(response, token_detail=False):
    shape = "token.header-shape" if token_detail else None
    encoding = "token.header-encoding" if token_detail else None
    authority = "token.header-authority" if token_detail else None
    _fail(response.version == 11 and type(response.status) is int, shape)
    raw = response.headers
    _fail(type(raw) in {tuple, list} and len(raw) <= HEADER_COUNT_MAX, shape)
    result = {}
    total = 0
    for pair in raw:
        _fail(type(pair) in {tuple, list} and len(pair) == 2, shape)
        name, value = pair
        _fail(type(name) is str and type(value) is str and HEADER_NAME.fullmatch(name) is not None, shape)
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise AcquisitionError(shape) from error
        _fail(all(byte == 32 or 33 <= byte <= 126 for byte in encoded), shape)
        lowered = name.lower()
        discard_cookie = token_detail and response.status == 200 and lowered == "set-cookie"
        _fail(discard_cookie or lowered not in result, shape)
        total += len(name) + len(encoded) + 4
        _fail(total <= HEADER_BYTES_MAX, shape)
        trimmed = value.strip(" ")
        no_ows = {"content-length", "location", "transfer-encoding", "content-encoding", "authorization", "proxy-authorization"}
        _fail(lowered not in no_ows or value == trimmed, shape)
        if not discard_cookie:
            result[lowered] = trimmed
    _fail("content-encoding" not in result, encoding)
    forbidden = {
        "authorization",
        "proxy-authorization",
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "authentication-info",
        "proxy-authentication-info",
    }
    _fail(not forbidden.intersection(result), authority)
    return result


def _content_length(headers, maximum, exact=None, optional_zero=False):
    if "content-length" not in headers:
        _fail(optional_zero)
        return 0
    raw = headers["content-length"]
    _fail(raw.isdigit() and str(int(raw)) == raw)
    value = int(raw)
    _fail(value <= maximum and (exact is None or value == exact))
    if optional_zero:
        _fail(value == 0)
    return value


def _remaining(deadline, maximum):
    value = deadline - time.monotonic()
    _fail(value > 0)
    return min(value, maximum)


def _request(transport, url, headers, deadline, metadata_timeout, request_stage, headers_stage, token_detail=False):
    def send():
        allowed = {"Accept", "User-Agent", "Connection", "Authorization"}
        _fail(type(headers) is tuple and all(name in allowed for name, _value in headers))
        _fail(len({name for name, _value in headers}) == len(headers))
        return transport.request(Request(url, headers), _remaining(deadline, metadata_timeout))

    response = _stage(request_stage, send)
    try:
        parsed_headers = _stage(headers_stage, lambda: _strict_headers(response, token_detail))
    except Exception:
        response.close()
        raise
    return response, parsed_headers


def _fixed_headers(accept, token=None):
    headers = (("Accept", accept), ("User-Agent", USER_AGENT), ("Connection", "close"))
    if token is not None:
        _fail(TOKEN_TEXT.fullmatch(token) is not None)
        headers += (("Authorization", f"Bearer {token}"),)
    return headers


def _read_memory(response, length, deadline):
    chunks = []
    total = 0
    while total < length:
        chunk = response.read(min(CHUNK, length - total), deadline)
        _fail(type(chunk) is bytes and chunk)
        total += len(chunk)
        _fail(total <= length)
        chunks.append(chunk)
    _fail(response.read(1, deadline) == b"")
    return b"".join(chunks)


def _read_bounded_eof(response, maximum, deadline):
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(CHUNK, maximum + 1 - total), deadline)
        _fail(type(chunk) is bytes)
        if not chunk:
            break
        total += len(chunk)
        _fail(total <= maximum)
        chunks.append(chunk)
    return b"".join(chunks)


def _token_content_type(value):
    _fail(type(value) is str)
    pattern = r"(?i:application/json(?: *; *charset *= *utf-8)?)"
    _fail(re.fullmatch(pattern, value) is not None)


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        _fail(key not in value)
        value[key] = item
    return value


def _token_framing(headers):
    transfer = headers.get("transfer-encoding")
    if transfer is None:
        return _content_length(headers, TOKEN_BODY_MAX)
    _fail(transfer.lower() == "chunked" and "content-length" not in headers)
    return None


def _token_value(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=lambda _item: _fail(False))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, AcquisitionError) as error:
        raise AcquisitionError() from error
    _fail(type(value) is dict)
    token = value.get("token")
    access = value.get("access_token")
    _fail(token is not None or access is not None)
    _fail(token is None or type(token) is str)
    _fail(access is None or type(access) is str)
    _fail(token is None or access is None or token == access)
    selected = token if token is not None else access
    _fail(TOKEN_TEXT.fullmatch(selected) is not None)
    return selected


def _anonymous_registry_token(transport, deadline, metadata_timeout):
    token_deadline = min(deadline, time.monotonic() + metadata_timeout)
    response, headers = _request(
        transport, TOKEN_URL, _fixed_headers("application/json"), token_deadline, metadata_timeout,
        "token.request", "token.headers", True,
    )
    try:
        def validate_headers():
            _fail(response.status == 200, "token.status")
            _stage("token.content-type", lambda: _token_content_type(headers.get("content-type", "")))
            return _stage("token.framing", lambda: _token_framing(headers))

        length = _stage("token.headers", validate_headers)
        reader = lambda: _read_bounded_eof(response, TOKEN_BODY_MAX, token_deadline)
        if length is not None:
            reader = lambda: _read_memory(response, length, token_deadline)
        raw = _stage("token.body", reader)
        return _stage("token.json", lambda: _token_value(raw))
    finally:
        response.close()


def _artifact_routes(contract):
    oci = contract["oci"]
    routes = []
    for key in ("index", "manifest", "config", "layer"):
        row = oci[key]
        types = (row["media_type"],) if key in {"index", "manifest"} else ("application/octet-stream", row["media_type"])
        routes.append(Route(row, f"oci-{key}", row["media_type"], types))
    snapshot = contract["snapshot"]
    routes.append(Route(snapshot["inrelease"], "debian-inrelease", "application/octet-stream", ("application/octet-stream", "text/plain")))
    routes.append(Route(snapshot["packages_index"], "debian-index", "application/octet-stream", ("application/octet-stream", "application/x-xz")))
    deb_types = ("application/octet-stream", "application/vnd.debian.binary-package", "application/x-debian-package")
    routes += [Route(row, "debian-package", "application/octet-stream", deb_types) for row in contract["packages"]]
    _fail(len(routes) == 16)
    return tuple(routes)


def _redirect_location(headers):
    _fail("location" in headers)
    return headers["location"]


def _redirect_framing(response, headers, deadline):
    _stage("artifact.redirect.framing.transfer", lambda: _fail("transfer-encoding" not in headers))
    length = _stage(
        "artifact.redirect.framing.length",
        lambda: _content_length(headers, REDIRECT_BODY_MAX) if "content-length" in headers else 0,
    )
    _stage("artifact.redirect.framing.body", lambda: _read_memory(response, length, deadline))


def _redirect_location_shape(location):
    _fail(type(location) is str and 0 < len(location) <= 16384)


def _debian_redirect_url(current, location):
    target = urljoin(current, location)
    return target, _strict_url(target)


def _redirect_location_host(host, allowed):
    if host in allowed:
        return
    families = (
        (".docker.com", "artifact.redirect.location.host-docker-com"),
        (".cloudflarestorage.com", "artifact.redirect.location.host-cloudflare-storage"),
        (".docker.io", "artifact.redirect.location.host-docker-io"),
    )
    stage = next((stage for suffix, stage in families if host.endswith(suffix)), "artifact.redirect.location.host-other")
    _stage(stage, lambda: _fail(False))


def _snapshot_named_file_path(route, path):
    origin = _strict_url(route.row["url"])
    filename = origin.path.rsplit("/", 1)[-1]
    _fail(filename)
    prefix, separator, candidate = path.rpartition("/")
    by_hash = route.source == "debian-index" and re.fullmatch(r"[a-f0-9]{64}", candidate) is not None and candidate == route.row["sha256"]
    return separator == "/" and SNAPSHOT_FILE_PATH.fullmatch(prefix) is not None and (candidate == quote(filename, safe="") or by_hash)


def _debian_redirect(route, current, location):
    _stage("artifact.redirect.location-shape", lambda: _redirect_location_shape(location))
    target, parsed = _stage("artifact.redirect.location.url", lambda: _debian_redirect_url(current, location))
    _stage("artifact.redirect.location.host", lambda: _redirect_location_host(parsed.hostname, (SNAPSHOT_HOST,)))
    _stage("artifact.redirect.location.query", lambda: _fail(not parsed.query))

    def validate_path():
        archive = parsed.path.startswith("/archive/debian/20260713T000000Z/") and "%" not in parsed.path
        content_file = SNAPSHOT_FILE_PATH.fullmatch(parsed.path) is not None or _snapshot_named_file_path(route, parsed.path)
        if archive or content_file: return
        if "%" in parsed.path: stage = "artifact.redirect.location.path.percent"
        elif re.match(r"^/file/(?:[a-f0-9]{40}|[a-f0-9]{64})/", parsed.path): stage = "artifact.redirect.location.path.filename"
        elif parsed.path.startswith("/archive/"): stage = "artifact.redirect.location.path.archive"
        else: stage = "artifact.redirect.location.path.other"
        _stage(stage, lambda: _fail(False))

    _stage("artifact.redirect.location.path", validate_path)
    return target


def _oci_redirect(route, location):
    _fail(route.source in {"oci-config", "oci-layer"})
    _stage("artifact.redirect.location-shape", lambda: _redirect_location_shape(location))
    parsed = _stage("artifact.redirect.location.url", lambda: _strict_url(location))
    _stage("artifact.redirect.location.host", lambda: _redirect_location_host(parsed.hostname, CDN_HOSTS))
    _stage("artifact.redirect.location.query", lambda: _fail(len(parsed.query.encode()) <= 8192))
    digest = route.row["sha256"]
    expected = f"/blobs/sha256/{digest[:2]}/{digest}/data"
    _stage("artifact.redirect.location.path", lambda: _fail(expected in parsed.path))
    return location


def _artifact_request(route, token, transport, current, deadline, metadata_timeout):
    parsed = _strict_url(current)
    if route.source.startswith("oci-"):
        _fail(parsed.hostname == REGISTRY_HOST or parsed.hostname in CDN_HOSTS)
        authorization = token if parsed.hostname == REGISTRY_HOST else None
    else:
        _fail(parsed.hostname == SNAPSHOT_HOST)
        authorization = None
    return _request(
        transport, current, _fixed_headers(route.accept, authorization), deadline, metadata_timeout,
        "artifact.request", "artifact.response-headers",
    )


def _final_content_type(route, headers):
    if "content-type" not in headers and route.source in {"debian-inrelease", "debian-index", "debian-package"}: return
    value = headers.get("content-type", "").strip().lower()
    if value in route.content_types:
        return
    if not value:
        stage = "artifact.final.content-type.missing"
    elif ";" in value:
        stage = "artifact.final.content-type.parameterized"
    elif value.startswith("application/"):
        stage = "artifact.final.content-type.application"
    elif value.startswith("text/"):
        stage = "artifact.final.content-type.text"
    else:
        stage = "artifact.final.content-type.other"
    _stage(stage, lambda: _fail(False))


def _final_headers(route, response, headers):
    _stage("artifact.final.transfer", lambda: _fail("transfer-encoding" not in headers and response.status == 200))
    _stage("artifact.final.length", lambda: _content_length(headers, route.row["size"], route.row["size"]))
    _stage("artifact.final.content-type", lambda: _final_content_type(route, headers))


def _next_redirect(route, response, headers, current, seen, redirects, deadline):
    _stage("artifact.redirect.status", lambda: _fail(response.status in {301, 302, 303, 307, 308}))
    location = _stage("artifact.redirect.location", lambda: _redirect_location(headers))
    _stage("artifact.redirect.framing", lambda: _redirect_framing(response, headers, deadline))
    redirects += 1
    if route.source.startswith("oci-"):
        _stage("artifact.redirect.status", lambda: _fail(response.status == 307))
        _stage("artifact.redirect.count", lambda: _fail(redirects == 1))
        return _stage("artifact.redirect.location", lambda: _oci_redirect(route, location)), redirects
    _stage("artifact.redirect.count", lambda: _fail(redirects <= 3))
    target = _stage("artifact.redirect.location", lambda: _debian_redirect(route, current, location))
    _stage("artifact.redirect.count", lambda: _fail(target not in seen))
    seen.add(target)
    return target, redirects


def _final_response(route, token, transport, deadline, metadata_timeout):
    current = route.row["url"]
    seen = {current}
    redirects = 0
    while True:
        response, headers = _stage(
            "artifact.request", lambda: _artifact_request(route, token, transport, current, deadline, metadata_timeout)
        )
        if response.status == 200:
            try:
                _stage("artifact.headers", lambda: _stage("artifact.final", lambda: _final_headers(route, response, headers)))
            except Exception:
                response.close()
                raise
            return response
        try:
            current, redirects = _stage(
                "artifact.headers",
                lambda: _stage(
                    "artifact.redirect",
                    lambda: _next_redirect(route, response, headers, current, seen, redirects, deadline),
                ),
            )
        finally:
            response.close()


def _identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_directory(parent, name, create):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        _fail(create)
        os.mkdir(name, 0o700, dir_fd=parent)
        created = True
        descriptor = os.open(name, flags, dir_fd=parent)
    try:
        if created:
            os.fchmod(descriptor, 0o700)
            os.fsync(parent)
        current = os.fstat(descriptor)
        _fail(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid() and stat.S_IMODE(current.st_mode) == 0o700)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_private_chain(artifact_root):
    artifact_root = Path(artifact_root)
    completion = artifact_root.parent
    state = completion.parent
    base = state.parent
    _fail((state.name, completion.name, artifact_root.name) == (".state", "completion-v1", "artifacts"))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    base_fd = os.open(base, flags)
    descriptors = [base_fd]
    try:
        current = os.fstat(base_fd)
        _fail(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid())
        for name in (".state", "completion-v1", "artifacts", "cache"):
            descriptors.append(_open_directory(descriptors[-1], name, True))
        return tuple(descriptors)
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _stable_read(directory, name, mode, size, digest=None):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _fail(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1)
    _fail(stat.S_IMODE(before.st_mode) == mode and before.st_size == size)
    descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
    hashed = hashlib.sha256()
    chunks = []
    total = 0
    try:
        _fail(_identity(os.fstat(descriptor)) == _identity(before))
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, size + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            _fail(total <= size)
            chunks.append(chunk)
            hashed.update(chunk)
    finally:
        os.close(descriptor)
    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _fail(_identity(after) == _identity(before) and total == size)
    if digest is not None:
        _fail(hashed.hexdigest() == digest)
    return b"".join(chunks)


def _sentinel(artifacts_fd):
    try:
        raw = _stable_read(artifacts_fd, SENTINEL, 0o600, len(SENTINEL_BYTES))
        _fail(raw == SENTINEL_BYTES)
        return
    except FileNotFoundError:
        pass
    descriptor = os.open(SENTINEL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=artifacts_fd)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, SENTINEL_BYTES)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(artifacts_fd)
    _fail(_stable_read(artifacts_fd, SENTINEL, 0o600, len(SENTINEL_BYTES)) == SENTINEL_BYTES)


def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        _fail(type(written) is int and written > 0)
        offset += written


def _existing(cache_fd, routes):
    names = {route.row["cache_name"] for route in routes}
    entries = set(os.listdir(cache_fd))
    _fail(entries.issubset(names))
    present = set()
    for route in routes:
        name = route.row["cache_name"]
        if name in entries:
            _stable_read(cache_fd, name, 0o400, route.row["size"], route.row["sha256"])
            present.add(name)
    return present


def _cleanup_partial(cache_fd, name, owned, published=False):
    try:
        current = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    _fail((current.st_dev, current.st_ino, current.st_uid) == owned[:3])
    _fail(stat.S_ISREG(current.st_mode) and current.st_nlink == (2 if published else 1))
    os.unlink(name, dir_fd=cache_fd)
    os.fsync(cache_fd)


def _stream_partial(response, descriptor, row, deadline):
    digest = hashlib.sha256()
    total = 0
    while total < row["size"]:
        chunk = response.read(min(CHUNK, row["size"] - total), deadline)
        _fail(type(chunk) is bytes and chunk)
        total += len(chunk)
        _fail(total <= row["size"])
        _write_all(descriptor, chunk)
        digest.update(chunk)
    _fail(response.read(1, deadline) == b"")
    _fail(total == row["size"] and digest.hexdigest() == row["sha256"])


def _download_one(route, token, transport, cache_fd, global_deadline, timeouts):
    row = route.row
    name = row["cache_name"]
    partial = f".{name}.partial"
    for candidate in (name, partial):
        try:
            os.stat(candidate, dir_fd=cache_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise AcquisitionError()
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=cache_fd)
    owned = None
    published = False
    response = None
    try:
        before = os.fstat(descriptor)
        owned = (before.st_dev, before.st_ino, before.st_uid)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        _fail(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and opened.st_nlink == 1)
        _fail(stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_size == 0)
        deadline = min(global_deadline, time.monotonic() + timeouts["artifact_read"])
        response = _final_response(route, token, transport, deadline, timeouts["metadata"])
        _stage("artifact.body", lambda: _stream_partial(response, descriptor, row, deadline))
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        _fail((current.st_dev, current.st_ino, current.st_uid) == owned)
        _fail(stat.S_ISREG(current.st_mode) and current.st_nlink == 1 and current.st_size == row["size"])
        _fail(stat.S_IMODE(current.st_mode) == 0o400)
        os.link(partial, name, src_dir_fd=cache_fd, dst_dir_fd=cache_fd, follow_symlinks=False)
        published = True
        _cleanup_partial(cache_fd, partial, owned, True)
        published = False
        _stable_read(cache_fd, name, 0o400, row["size"], row["sha256"])
    except Exception:
        if owned is not None:
            _cleanup_partial(cache_fd, partial, owned, published)
        raise
    finally:
        if response is not None:
            response.close()
        os.close(descriptor)


def _acquire_rows(routes, artifact_root, transport, timeouts):
    descriptors = _stage("state", lambda: _open_private_chain(artifact_root))
    global_deadline = time.monotonic() + GLOBAL_SECONDS
    try:
        artifacts_fd, cache_fd = descriptors[-2:]
        _stage("state", lambda: _sentinel(artifacts_fd))
        present = _stage("state", lambda: _existing(cache_fd, routes))
        missing_oci = any(route.source.startswith("oci-") and route.row["cache_name"] not in present for route in routes)
        token = _anonymous_registry_token(transport, global_deadline, timeouts["metadata"]) if missing_oci else None
        for route in routes:
            if route.row["cache_name"] not in present:
                _stage("publish", lambda route=route: _download_one(route, token, transport, cache_fd, global_deadline, timeouts))
        _stage("state", lambda: _fail(set(os.listdir(cache_fd)) == {route.row["cache_name"] for route in routes}))
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def acquire_artifacts(contract, artifact_root):
    _stage("preflight", lambda: _reject_ambient_authority(os.environ))
    context = _stage("tls", _tls_context)
    routes = _stage("routes", lambda: _artifact_routes(contract))
    _stage("state", lambda: _acquire_rows(routes, artifact_root, _HttpsTransport(context), contract["timeouts_seconds"]))

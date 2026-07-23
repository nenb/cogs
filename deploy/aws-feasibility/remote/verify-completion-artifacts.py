#!/usr/bin/env python3
"""Fail-closed verification for the fixed ADR 0038 artifact contract and cache."""

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

VERSION = "cogs.stage2-completion-artifacts/v1"
SNAPSHOT = "20260713T000000Z"
SNAPSHOT_BASE = f"https://snapshot.debian.org/archive/debian/{SNAPSHOT}/"
SENTINEL = ".cogs-stage2-completion-artifacts-v1"
SENTINEL_BYTES = b"cogs-stage2-completion-artifacts-v1\n"
CONTRACT_PATH = Path(__file__).with_name("stage2-completion-artifacts-v1.json")
ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / ".state" / "completion-v1" / "artifacts"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ACQUISITION_STAGES = frozenset(
    {
        "preflight", "tls", "routes", "state", "token.request", "token.headers", "token.header-shape",
        "token.header-encoding", "token.header-authority", "token.status", "token.content-type", "token.framing",
        "token.body", "token.json", "artifact.request", "artifact.headers", "artifact.response-headers",
        "artifact.redirect", "artifact.redirect.status", "artifact.redirect.location", "artifact.redirect.location-shape",
        "artifact.redirect.location.url", "artifact.redirect.location.host", "artifact.redirect.location.host-docker-com",
        "artifact.redirect.location.host-cloudflare-storage", "artifact.redirect.location.host-docker-io",
        "artifact.redirect.location.host-other", "artifact.redirect.location.query", "artifact.redirect.location.path",
        "artifact.redirect.framing", "artifact.redirect.framing.transfer", "artifact.redirect.framing.length",
        "artifact.redirect.framing.body", "artifact.redirect.count", "artifact.final",
        "artifact.body", "publish", "postverify",
    }
)

OCI_EXPECTED = {
    "index": (
        "debian-13-slim-index.json",
        "manifests",
        "application/vnd.oci.image.index.v1+json",
        8973,
        "28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2",
    ),
    "manifest": (
        "debian-13-slim-amd64-manifest.json",
        "manifests",
        "application/vnd.oci.image.manifest.v1+json",
        1021,
        "a617c1cdde36a7e0194b2f07dff669e1753c03c3205356b94f9f350b0f9a57d1",
    ),
    "config": (
        "debian-13-slim-config.json",
        "blobs",
        "application/vnd.oci.image.config.v1+json",
        451,
        "84645f91e8d166d709fcef984301b2576198bf880c15eb3ce9f4c8fad305c4ea",
    ),
    "layer": (
        "debian-13-slim-amd64-rootfs.tar.gz",
        "blobs",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        29785419,
        "e95a6c7ea7d49b37920899b023ecd0e32796c976c1748491f76cae53ba86d13a",
    ),
}
SNAPSHOT_EXPECTED = {
    "inrelease": (
        "debian-trixie-InRelease",
        "dists/trixie/InRelease",
        140416,
        "98b25b5cd185c59d34aa6e4c3e9b5b8f01bbe9d104fe2dcfbcd30dc0a14a59ed",
    ),
    "packages_index": (
        "debian-trixie-Packages.xz",
        "dists/trixie/main/binary-amd64/Packages.xz",
        9672648,
        "3ab4e811cf4f3e5a335d382c58cc19d85f1abe7a4ef4689160ca1f637fa0e9b3",
    ),
}
PACKAGE_EXPECTED = (
    ("git", "1:2.47.3-0+deb13u1", "pool/main/g/git/git_2.47.3-0+deb13u1_amd64.deb", 8861572, "3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722"),
    ("openssh-server", "1:10.0p1-7+deb13u4", "pool/main/o/openssh/openssh-server_10.0p1-7+deb13u4_amd64.deb", 602372, "b4a02524fd2be375624d917ee8102a16567e9e8dd786b41c35e22360cdd37f9d"),
    ("libcom-err2", "1.47.2-3+b11", "pool/main/e/e2fsprogs/libcom-err2_1.47.2-3+b11_amd64.deb", 25036, "e1feff126b3e8b3a7b18087e88681469b70d8f6d1b7c4e4b89d98577e1a2fdd7"),
    ("libgssapi-krb5-2", "1.21.3-5+deb13u1", "pool/main/k/krb5/libgssapi-krb5-2_1.21.3-5+deb13u1_amd64.deb", 138356, "30847c1fde4240567d7ed3aeab4f655dd591203758b857e85e824045aae70299"),
    ("libk5crypto3", "1.21.3-5+deb13u1", "pool/main/k/krb5/libk5crypto3_1.21.3-5+deb13u1_amd64.deb", 81152, "7da07ee674b47f1f0be7cc89317c25310086a1f1761217d0f72e6ae2c5a69b84"),
    ("libkeyutils1", "1.6.3-6", "pool/main/k/keyutils/libkeyutils1_1.6.3-6_amd64.deb", 9456, "0b11ad17be0300b63ad4eeb4c6450fed24d34b7b740f23e5363dcb29ee6d5eba"),
    ("libkrb5-3", "1.21.3-5+deb13u1", "pool/main/k/krb5/libkrb5-3_1.21.3-5+deb13u1_amd64.deb", 326056, "47d71d6a7f2e59b9bae5f89602397594805113b95889ad18fa703cd53abafc97"),
    ("libkrb5support0", "1.21.3-5+deb13u1", "pool/main/k/krb5/libkrb5support0_1.21.3-5+deb13u1_amd64.deb", 33124, "3a0acd8b37955c0e102c756b52c97df2a31f67b96453c35dab70df218d309117"),
    ("libwrap0", "7.6.q-36", "pool/main/t/tcp-wrappers/libwrap0_7.6.q-36_amd64.deb", 55256, "cde12afa15d6b1556c5e0564d22edf3b99e6b8fa94c59ccd8b8eebbb62dc19ec"),
    ("libwtmpdb0", "0.73.0-3+deb13u1", "pool/main/w/wtmpdb/libwtmpdb0_0.73.0-3+deb13u1_amd64.deb", 13056, "8d6bc1c961d734da58b2d4c35b0a3cd6ad2fe81655bd982c655a97c2255b1c9b"),
)


class VerificationError(Exception):
    def __init__(self, stage=None):
        self.stage = stage if type(stage) is str and stage in ACQUISITION_STAGES else None
        super().__init__()


def fail(condition):
    if not condition:
        raise VerificationError()


def exact_keys(value, keys):
    fail(type(value) is dict and tuple(value.keys()) == tuple(keys))


def reject_bool(value):
    if type(value) is bool:
        raise VerificationError()
    if type(value) is dict:
        for item in value.values():
            reject_bool(item)
    elif type(value) is list:
        for item in value:
            reject_bool(item)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError()
        result[key] = value
    return result


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def read_stable_regular(path, mode, maximum):
    pre = os.lstat(path)
    fail(stat.S_ISREG(pre.st_mode) and pre.st_nlink == 1 and pre.st_uid == os.geteuid())
    fail(stat.S_IMODE(pre.st_mode) == mode and pre.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    chunks = []
    total = 0
    try:
        fail(identity(os.fstat(descriptor)) == identity(pre))
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            fail(total <= maximum)
    finally:
        os.close(descriptor)
    fail(identity(os.lstat(path)) == identity(pre) and total == pre.st_size)
    return b"".join(chunks)


def strict_json(raw, maximum):
    fail(type(raw) is bytes and len(raw) <= maximum)
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=lambda _value: fail(False))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, VerificationError) as error:
        raise VerificationError() from error
    reject_bool(value)
    return value


def load_json_file(path):
    return strict_json(read_stable_regular(path, 0o644, 32768), 32768)


def check_url(value, host, prefix):
    fail(type(value) is str)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise VerificationError() from error
    fail(parsed.scheme == "https" and parsed.hostname == host and port is None)
    fail(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment)
    fail(parsed.path.startswith(prefix))


def check_sha(value):
    fail(type(value) is str and SHA256_RE.fullmatch(value) is not None)


def check_oci(contract):
    oci = contract["oci"]
    exact_keys(oci, ("repository", "index", "manifest", "config", "layer"))
    fail(oci["repository"] == "library/debian")
    for key, expected in OCI_EXPECTED.items():
        row = oci[key]
        fields = ("cache_name", "url", "media_type", "size", "sha256")
        if key == "layer":
            fields += ("diff_id",)
        exact_keys(row, fields)
        cache_name, endpoint, media_type, size, digest = expected
        expected_url = f"https://registry-1.docker.io/v2/library/debian/{endpoint}/sha256:{digest}"
        fail(row["cache_name"] == cache_name and row["url"] == expected_url)
        fail(row["media_type"] == media_type and type(row["size"]) is int and row["size"] == size)
        check_url(row["url"], "registry-1.docker.io", "/v2/library/debian/")
        check_sha(row["sha256"])
        fail(row["sha256"] == digest)
        if key == "layer":
            check_sha(row["diff_id"])
            fail(row["diff_id"] == "3edb2192497af6e965b9b7e57dc6dbdce1f3ea721d14a98110419d4ded523298")


def check_snapshot(contract):
    snapshot = contract["snapshot"]
    exact_keys(snapshot, ("timestamp", "base_url", "inrelease", "packages_index"))
    fail(snapshot["timestamp"] == SNAPSHOT and snapshot["base_url"] == SNAPSHOT_BASE)
    check_url(snapshot["base_url"], "snapshot.debian.org", f"/archive/debian/{SNAPSHOT}/")
    for key, expected in SNAPSHOT_EXPECTED.items():
        row = snapshot[key]
        exact_keys(row, ("cache_name", "path", "url", "size", "sha256"))
        cache_name, path, size, digest = expected
        fail(row == {"cache_name": cache_name, "path": path, "url": SNAPSHOT_BASE + path, "size": size, "sha256": digest})
        check_url(row["url"], "snapshot.debian.org", f"/archive/debian/{SNAPSHOT}/")
        check_sha(row["sha256"])


def check_packages(contract):
    rows = contract["packages"]
    fail(type(rows) is list and len(rows) == len(PACKAGE_EXPECTED))
    seen = {"name": set(), "filename": set(), "cache_name": set(), "url": set(), "sha256": set()}
    for row, expected in zip(rows, PACKAGE_EXPECTED, strict=True):
        exact_keys(row, ("name", "version", "architecture", "path", "filename", "cache_name", "url", "size", "sha256"))
        name, version, path, size, digest = expected
        filename = PurePosixPath(path).name
        fail(PurePosixPath(path).parts[:2] == ("pool", "main") and ".." not in PurePosixPath(path).parts)
        fail(row == {"name": name, "version": version, "architecture": "amd64", "path": path, "filename": filename, "cache_name": filename, "url": SNAPSHOT_BASE + path, "size": size, "sha256": digest})
        check_url(row["url"], "snapshot.debian.org", f"/archive/debian/{SNAPSHOT}/pool/main/")
        check_sha(row["sha256"])
        for field in seen:
            fail(row[field] not in seen[field])
            seen[field].add(row[field])
    fail(type(contract["package_total_bytes"]) is int)
    fail(sum(row["size"] for row in rows) == contract["package_total_bytes"] == 10145436)


def cache_entries(contract):
    rows = [contract["oci"][key] for key in ("index", "manifest", "config", "layer")]
    rows += [contract["snapshot"][key] for key in ("inrelease", "packages_index")]
    rows += contract["packages"]
    return tuple({"cache_name": row["cache_name"], "size": row["size"], "sha256": row["sha256"]} for row in rows)


def verify_contract(path):
    contract = load_json_file(path)
    exact_keys(contract, ("version", "platform", "source_date_epoch", "oci", "snapshot", "packages", "package_total_bytes", "bounds", "fixtures", "tools", "timeouts_seconds"))
    fail(contract["version"] == VERSION)
    exact_keys(contract["platform"], ("os", "architecture"))
    fail(contract["platform"] == {"os": "linux", "architecture": "amd64"})
    fail(type(contract["source_date_epoch"]) is int and contract["source_date_epoch"] == 1782172800)
    check_oci(contract)
    check_snapshot(contract)
    check_packages(contract)
    exact_keys(contract["bounds"], ("artifact_count", "max_entries", "max_regular_bytes", "max_file_bytes", "max_path_bytes", "max_component_bytes"))
    fail(contract["bounds"] == {"artifact_count": 16, "max_entries": 100000, "max_regular_bytes": 536870912, "max_file_bytes": 134217728, "max_path_bytes": 4096, "max_component_bytes": 255})
    exact_keys(contract["fixtures"], ("git", "package"))
    exact_keys(contract["fixtures"]["git"], ("version", "file_count", "lines_per_file", "modified_count", "untracked_count"))
    exact_keys(contract["fixtures"]["package"], ("name", "version", "architecture", "file_count", "file_bytes"))
    fail(contract["fixtures"] == {"git": {"version": "cogs-stage2-git-v1", "file_count": 512, "lines_per_file": 128, "modified_count": 32, "untracked_count": 8}, "package": {"name": "cogs-stage2-fixture", "version": "1.0", "architecture": "all", "file_count": 256, "file_bytes": 4096}})
    exact_keys(contract["tools"], ("python3", "dpkg_deb", "dpkg", "git", "sshd"))
    fail(contract["tools"] == {"python3": "/usr/bin/python3", "dpkg_deb": "/usr/bin/dpkg-deb", "dpkg": "/usr/bin/dpkg", "git": "/usr/bin/git", "sshd": "/usr/sbin/sshd"})
    exact_keys(contract["timeouts_seconds"], ("metadata", "artifact_read", "build"))
    fail(contract["timeouts_seconds"] == {"metadata": 10, "artifact_read": 120, "build": 300})
    source_rows = [contract["oci"][key] for key in ("index", "manifest", "config", "layer")]
    source_rows += [contract["snapshot"][key] for key in ("inrelease", "packages_index")]
    source_rows += contract["packages"]
    entries = cache_entries(contract)
    fail(len(entries) == contract["bounds"]["artifact_count"])
    for field in ("cache_name", "url", "sha256"):
        fail(len({row[field] for row in source_rows}) == len(source_rows))
    return contract


def check_directory(path, mode):
    st = os.lstat(path)
    fail(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode))
    fail(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == mode)


def verify_cached_file(path, expected):
    fail(path.name == expected["cache_name"] and path.parent.name == "cache")
    pre = os.lstat(path)
    fail(stat.S_ISREG(pre.st_mode) and pre.st_uid == os.geteuid())
    fail(stat.S_IMODE(pre.st_mode) == 0o400 and pre.st_nlink == 1 and pre.st_size == expected["size"])
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        fail(identity(os.fstat(descriptor)) == identity(pre))
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, expected["size"] + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            fail(total <= expected["size"])
            digest.update(chunk)
    finally:
        os.close(descriptor)
    post = os.lstat(path)
    fail(identity(post) == identity(pre))
    fail(total == expected["size"] and digest.hexdigest() == expected["sha256"])


def verify_cache_root(artifact_root, entries):
    artifact_root = Path(artifact_root)
    completion_root = artifact_root.parent
    state_root = completion_root.parent
    fail(artifact_root.name == "artifacts" and completion_root.name == "completion-v1" and state_root.name == ".state")
    for directory in (state_root, completion_root, artifact_root):
        check_directory(directory, 0o700)
    sentinel = artifact_root / SENTINEL
    fail(read_stable_regular(sentinel, 0o600, len(SENTINEL_BYTES)) == SENTINEL_BYTES)
    cache = artifact_root / "cache"
    check_directory(cache, 0o700)
    expected_names = {entry["cache_name"] for entry in entries}
    fail(len(expected_names) == len(entries))
    fail({entry.name for entry in os.scandir(cache)} == expected_names)
    for entry in entries:
        verify_cached_file(cache / entry["cache_name"], entry)


def verify_cache(contract_path, artifact_root):
    contract = verify_contract(contract_path)
    verify_cache_root(artifact_root, cache_entries(contract))


def cached_bytes(cache, row, maximum):
    fail(row["size"] <= maximum)
    raw = read_stable_regular(cache / row["cache_name"], 0o400, maximum)
    fail(len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"])
    return raw


def descriptor_matches(value, row):
    return type(value) is dict and all(
        value.get(key) == expected
        for key, expected in (
            ("mediaType", row["media_type"]),
            ("digest", f"sha256:{row['sha256']}"),
            ("size", row["size"]),
        )
    )


def verify_oci_documents(contract, index_raw, manifest_raw, config_raw):
    import base64

    maximum = contract["bounds"]["max_file_bytes"]
    index = strict_json(index_raw, maximum)
    manifest = strict_json(manifest_raw, maximum)
    config = strict_json(config_raw, maximum)
    fail(type(index) is dict and index.get("schemaVersion") == 2)
    fail(index.get("mediaType") == contract["oci"]["index"]["media_type"])
    manifests = index.get("manifests")
    fail(type(manifests) is list and 0 < len(manifests) <= 64)
    fail(all(type(item) is dict for item in manifests))
    candidates = [
        item
        for item in manifests
        if type(item.get("platform")) is dict
        and item["platform"].get("architecture") == "amd64"
        and item["platform"].get("os") == "linux"
    ]
    fail(len(candidates) == 1)
    selected = candidates[0]
    fail(selected["platform"] == {"architecture": "amd64", "os": "linux"})
    fail(descriptor_matches(selected, contract["oci"]["manifest"]))

    fail(type(manifest) is dict and manifest.get("schemaVersion") == 2)
    fail(manifest.get("mediaType") == contract["oci"]["manifest"]["media_type"])
    fail(descriptor_matches(manifest.get("config"), contract["oci"]["config"]))
    layers = manifest.get("layers")
    fail(type(layers) is list and len(layers) == 1 and descriptor_matches(layers[0], contract["oci"]["layer"]))
    embedded = manifest["config"].get("data")
    fail(type(embedded) is str)
    try:
        decoded = base64.b64decode(embedded, validate=True)
    except ValueError as error:
        raise VerificationError() from error
    fail(decoded == config_raw)

    fail(type(config) is dict and config.get("os") == "linux" and config.get("architecture") == "amd64")
    fail(config.get("rootfs") == {"type": "layers", "diff_ids": [f"sha256:{contract['oci']['layer']['diff_id']}"]})
    fail(
        config.get("config")
        == {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Entrypoint": [],
            "Cmd": ["bash"],
        }
    )


def verify_gzip_layer(path, row, maximum):
    import zlib

    pre = os.lstat(path)
    fail(stat.S_ISREG(pre.st_mode) and pre.st_uid == os.geteuid() and pre.st_nlink == 1)
    fail(stat.S_IMODE(pre.st_mode) == 0o400 and pre.st_size == row["size"])
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    compressed = hashlib.sha256()
    expanded = hashlib.sha256()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    compressed_size = 0
    expanded_size = 0
    try:
        fail(identity(os.fstat(descriptor)) == identity(pre))
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            fail(not decoder.eof)
            compressed_size += len(chunk)
            fail(compressed_size <= row["size"])
            compressed.update(chunk)
            output = decoder.decompress(chunk, maximum + 1 - expanded_size)
            expanded_size += len(output)
            fail(expanded_size <= maximum and not decoder.unconsumed_tail and not decoder.unused_data)
            expanded.update(output)
        fail(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data)
    except zlib.error as error:
        raise VerificationError() from error
    finally:
        os.close(descriptor)
    fail(identity(os.lstat(path)) == identity(pre))
    fail(compressed_size == row["size"] and compressed.hexdigest() == row["sha256"])
    fail(expanded.hexdigest() == row["diff_id"])


def clear_signed_body(raw):
    fail(type(raw) is bytes and len(raw) <= 1024 * 1024 and raw.endswith(b"\n") and b"\r" not in raw)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError() from error
    fail(all(character == "\n" or 32 <= ord(character) <= 126 for character in text))
    lines = text.splitlines()
    fail(all(len(line) <= 65536 for line in lines))
    fail(lines[:3] == ["-----BEGIN PGP SIGNED MESSAGE-----", "Hash: SHA256", ""])
    fail(lines.count("-----BEGIN PGP SIGNED MESSAGE-----") == 1 and lines.count("Hash: SHA256") == 1)
    fail(lines.count("-----BEGIN PGP SIGNATURE-----") == 1 and lines.count("-----END PGP SIGNATURE-----") == 1)
    fail(lines[-1] == "-----END PGP SIGNATURE-----")
    signature = lines.index("-----BEGIN PGP SIGNATURE-----")
    signature_body = lines[signature + 1 : -1]
    fail(signature > 3 and len(signature_body) > 1 and signature_body[0] == "")
    fail(all(re.fullmatch(r"[A-Za-z0-9+/=]+", line) is not None for line in signature_body[1:]))
    body = []
    for line in lines[3:signature]:
        if line.startswith("-"):
            fail(line.startswith("- "))
            line = line[2:]
        body.append(line)
    return body


def verify_inrelease(contract, raw):
    body = clear_signed_body(raw)
    fail(body.count("SHA256:") == 1)
    start = body.index("SHA256:") + 1
    rows = []
    while start < len(body) and body[start].startswith(" "):
        fields = body[start].split()
        fail(len(fields) == 3 and SHA256_RE.fullmatch(fields[0]) is not None and fields[1].isdigit())
        rows.append(fields)
        start += 1
    expected = contract["snapshot"]["packages_index"]
    release_path = expected["path"].removeprefix("dists/trixie/")
    fail(release_path != expected["path"])
    selected = [row for row in rows if row[2] == release_path]
    fail(selected == [[expected["sha256"], str(expected["size"]), release_path]])


def decompress_xz(raw, maximum):
    import lzma

    fail(type(raw) is bytes)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    output = []
    total = 0
    try:
        for offset in range(0, len(raw), 1024 * 1024):
            fail(not decoder.eof)
            chunk = raw[offset : offset + 1024 * 1024]
            while chunk or (not decoder.needs_input and not decoder.eof):
                expanded = decoder.decompress(chunk, maximum + 1 - total)
                chunk = b""
                total += len(expanded)
                fail(total <= maximum and not decoder.unused_data)
                output.append(expanded)
        fail(decoder.eof and not decoder.unused_data)
    except lzma.LZMAError as error:
        raise VerificationError() from error
    return b"".join(output)


def debian_stanzas(raw, maximum):
    fail(type(raw) is bytes and raw.endswith(b"\n") and b"\r" not in raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError() from error
    fail(all(character in "\n\t" or 32 <= ord(character) < 127 or ord(character) >= 160 for character in text))
    stanzas = []
    current = {}
    last = None
    for line in text.splitlines():
        fail(len(line.encode()) <= 131072)
        if not line:
            if current:
                stanzas.append(current)
                fail(len(stanzas) <= maximum)
                current = {}
                last = None
            continue
        if line[0] in " \t":
            fail(last is not None)
            current[last] += "\n" + line[1:]
            continue
        fail(":" in line)
        name, value = line.split(":", 1)
        fail(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", name) is not None and name not in current)
        fail(value.startswith(" "))
        current[name] = value[1:]
        last = name
    if current:
        stanzas.append(current)
    fail(0 < len(stanzas) <= maximum)
    return stanzas


def verify_packages_index(contract, raw):
    expanded = decompress_xz(raw, contract["bounds"]["max_file_bytes"])
    stanzas = debian_stanzas(expanded, contract["bounds"]["max_entries"])
    selected = {row["name"]: [] for row in contract["packages"]}
    for stanza in stanzas:
        name = stanza.get("Package")
        if name in selected:
            selected[name].append(stanza)
    total = 0
    for expected in contract["packages"]:
        rows = selected[expected["name"]]
        fail(len(rows) == 1)
        row = rows[0]
        fail(
            all(
                row.get(field) == value
                for field, value in (
                    ("Version", expected["version"]),
                    ("Architecture", expected["architecture"]),
                    ("Filename", expected["path"]),
                    ("Size", str(expected["size"])),
                    ("SHA256", expected["sha256"]),
                )
            )
        )
        total += expected["size"]
    fail(total == contract["package_total_bytes"])


def verify_metadata(contract_path, artifact_root):
    contract = verify_contract(contract_path)
    verify_cache_root(artifact_root, cache_entries(contract))
    cache = Path(artifact_root) / "cache"
    maximum = contract["bounds"]["max_file_bytes"]
    oci = contract["oci"]
    index_raw = cached_bytes(cache, oci["index"], maximum)
    manifest_raw = cached_bytes(cache, oci["manifest"], maximum)
    config_raw = cached_bytes(cache, oci["config"], maximum)
    verify_oci_documents(contract, index_raw, manifest_raw, config_raw)
    verify_gzip_layer(cache / oci["layer"]["cache_name"], oci["layer"], contract["bounds"]["max_regular_bytes"])
    snapshot = contract["snapshot"]
    verify_inrelease(contract, cached_bytes(cache, snapshot["inrelease"], maximum))
    packages_raw = cached_bytes(cache, snapshot["packages_index"], maximum)
    verify_packages_index(contract, packages_raw)


def verify_package_archives(contract_path, artifact_root):
    verify_metadata(contract_path, artifact_root)
    contract = verify_contract(contract_path)
    from completion_archive_preflight import ArchivePreflightError, verify_package_archives as preflight_packages

    try:
        preflight_packages(contract, Path(artifact_root) / "cache")
    except ArchivePreflightError as error:
        raise VerificationError() from error


def acquire_completion_artifacts(contract_path, artifact_root):
    try:
        contract = verify_contract(contract_path)
    except (OSError, VerificationError) as error:
        raise VerificationError("preflight") from error
    from completion_artifact_acquisition import AcquisitionError, acquire_artifacts

    try:
        acquire_artifacts(contract, artifact_root)
    except AcquisitionError as error:
        raise VerificationError(error.stage) from error
    try:
        verify_package_archives(contract_path, artifact_root)
    except (OSError, VerificationError) as error:
        raise VerificationError("postverify") from error


def main(argv):
    try:
        if argv == ["verify-contract"]:
            verify_contract(CONTRACT_PATH)
        elif argv == ["verify-cache"]:
            verify_cache(CONTRACT_PATH, ARTIFACT_ROOT)
        elif argv == ["verify-metadata"]:
            verify_metadata(CONTRACT_PATH, ARTIFACT_ROOT)
        elif argv == ["verify-package-archives"]:
            verify_package_archives(CONTRACT_PATH, ARTIFACT_ROOT)
        elif argv == ["acquire-artifacts"]:
            acquire_completion_artifacts(CONTRACT_PATH, ARTIFACT_ROOT)
        else:
            raise VerificationError()
    except (OSError, VerificationError) as error:
        print("completion artifact verification failed", file=sys.stderr)
        stage = error.stage if isinstance(error, VerificationError) else None
        if argv == ["acquire-artifacts"] and stage in ACQUISITION_STAGES:
            print(f"completion artifact acquisition stage: {stage}", file=sys.stderr)
        return 1
    print("Verified fixed Stage 2 completion artifact contract and cache boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

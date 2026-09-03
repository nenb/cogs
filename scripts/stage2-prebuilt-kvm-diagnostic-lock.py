#!/usr/bin/env python3
"""Verify and materialize one fixed, non-authorizing diagnostic publication lock."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[1]
LOCK_PATH = REPOSITORY / "config/stage2-prebuilt-kvm-diagnostic-lock-v1.json"
CUSTODY_ROOT = REPOSITORY / "config/stage2-prebuilt-kvm-diagnostic-custody-v1"
DESTINATION = Path("/var/lib/cogs/stage2-prebuilt-rootfs-descriptor-v1")
REMOTE = REPOSITORY / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_rootfs_prebuilt as prebuilt
MEMBERS = {
    "cosign-verification.json": (324, "084d108813799a045db41a0e319b03a7fa13612de755d86cc0661be43cfc3425"),
    "descriptor.json": (1620, "015cb863f9b2ec8582619cc46c1914d41eb1b58ef1abc3384cdf34ed24c89029"),
    "producer-receipt.json": (943, "512eecc040cf6e7a7c8ab927cbbffe5c8ff92b4a09b982dd77f0e2f41d7d3c84"),
    "publication-receipt.json": (1141, "1d38b42ad1cc031a20d53e69d8e33a2b7f13b5dea4242283df5f6a2536528de1"),
    "rootfs.package.json": (648, "e46faeaa4148829e7ad53dac34ac6bcf9f0ca0bb9d29067f750c983f060e8068"),
    "rootfs.provenance.json": (1025, "a95f2ab29070f8fb35c01549bf2bb3f2370d13ceafee2ce8845be79f1c867c0b"),
}
IMPLEMENTATION = "5bced6bdc54756761f28a393970301b9b24341cc"
SOURCE_MANIFEST = "dd0ee3095d27cf9e14c3014558a6628d5f2f9b28eb75e00ddbf39a064487a954"
CONTROL = "3a3499f0f452bf0fe893a0214cf0c0bbd0cd0e99"
OCI = "f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67"
USTAR = "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397"
class DiagnosticLockError(Exception):
    pass
def require(condition):
    if not condition:
        raise DiagnosticLockError()
def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value)
        value[key] = item
    return value
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
def decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n")
            and b"\r" not in raw)
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise DiagnosticLockError() from error
    require(canonical(value) == raw)
    return value
def decode_json(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise DiagnosticLockError() from error
def read_regular(path, size, digest):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == size and not stat.S_IMODE(before.st_mode) & 0o022)
        raw = os.read(descriptor, size + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == size and identity(before) == identity(after)
                and hashlib.sha256(raw).hexdigest() == digest)
        return raw
    finally:
        os.close(descriptor)
def load_lock(lock_raw=None, custody=None):
    raw = (LOCK_PATH.read_bytes() if lock_raw is None else lock_raw)
    value = decode(raw, 16_384)
    require(set(value) == {"version", "authority", "profile", "repository",
                           "runtime_source", "publication_producer", "publication",
                           "historical_rehearsal", "custody"})
    require(value["version"] == "cogs.stage2-prebuilt-kvm-diagnostic-lock/v1"
            and value["authority"] == "diagnostic-only-non-authorizing"
            and value["profile"] == "reusable-no-mint-kvm-integration"
            and value["repository"] == "nenb/cogs"
            and value["runtime_source"] == {
                "revision": "github-sha",
                "manifest": "exact-materialized-source-manifest",
                "must_differ_from_publication_producer": True}
            and value["publication_producer"] == {
                "implementation_revision": IMPLEMENTATION,
                "source_manifest_sha256": SOURCE_MANIFEST,
                "control_revision": CONTROL}
            and value["historical_rehearsal"] == {
                "run_id": 33615698328, "authority": "failed-non-authorizing"})
    publication = value["publication"]
    require(publication == {
        "workflow": ".github/workflows/stage2-prebuilt-rootfs-diagnostic-publisher.yml",
        "run_id": 33615572679,
        "artifact_id": 9840794063,
        "actions_digest": "sha256:662bdd78f5b3088a37e226c54847cd19d3bb6ac044dc23f800046111d9983c45",
        "oci_subject": "ghcr.io/nenb/cogs/stage2-rootfs@sha256:" + OCI,
        "oci_digest": "sha256:" + OCI,
        "canonical_ustar_digest": "sha256:" + USTAR,
    })
    expected_rows = [{"name": name, "size": size, "sha256": digest}
                     for name, (size, digest) in sorted(MEMBERS.items())]
    require(value["custody"] == expected_rows)
    raws = (dict(custody) if custody is not None else {
        name: read_regular(CUSTODY_ROOT / name, size, digest)
        for name, (size, digest) in MEMBERS.items()})
    require(set(raws) == set(MEMBERS))
    for name, raw_member in raws.items():
        size, digest = MEMBERS[name]
        require(type(raw_member) is bytes and len(raw_member) == size
                and hashlib.sha256(raw_member).hexdigest() == digest)
    descriptor = prebuilt.decode_fixed_descriptor(raws["descriptor.json"])
    package = decode(raws["rootfs.package.json"], 4096)
    provenance = decode(raws["rootfs.provenance.json"], 4096)
    producer = decode(raws["producer-receipt.json"], 4096)
    publication_receipt = decode(raws["publication-receipt.json"], 4096)
    cosign = decode_json(raws["cosign-verification.json"], 4096)
    require(descriptor.producer_revision == IMPLEMENTATION
            and descriptor.producer_source_manifest_sha256 == SOURCE_MANIFEST
            and descriptor.manifest_digest == OCI
            and descriptor.ustar_sha256 == USTAR
            and publication_receipt["control_revision"] == CONTROL
            and publication_receipt["publisher_run_id"] == 33615572679
            and publication_receipt["oci_manifest_sha256"] == OCI
            and publication_receipt["rootfs_ustar_sha256"] == USTAR
            and package["members"][2]["sha256"] == USTAR
            and provenance["builder"]["implementation_revision"] == IMPLEMENTATION
            and provenance["builder"]["source_manifest_sha256"] == SOURCE_MANIFEST
            and producer["implementation_revision"] == IMPLEMENTATION
            and producer["source_manifest_sha256"] == SOURCE_MANIFEST
            and cosign == [{"critical": {
                "identity": {"docker-reference": publication["oci_subject"]},
                "image": {"docker-manifest-digest": "sha256:" + OCI},
                "type": "https://sigstore.dev/cosign/sign/v1"}, "optional": {}}])
    return value, raws
def write_frozen(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0)
            view = view[count:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
def sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
def materialize(stage):
    require(os.geteuid() == 0 and stage in {"descriptor", "adjuncts"})
    _value, raws = load_lock()
    if stage == "descriptor":
        require(not DESTINATION.exists())
        DESTINATION.mkdir(mode=0o700)
        os.chown(DESTINATION, 0, 0)
        write_frozen(DESTINATION / "descriptor.json", raws["descriptor.json"])
    else:
        seen = DESTINATION.lstat()
        require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                and stat.S_IMODE(seen.st_mode) == 0o700
                and set(os.listdir(DESTINATION)) == {"descriptor.json"})
        existing = read_regular(DESTINATION / "descriptor.json", *MEMBERS["descriptor.json"])
        require(existing == raws["descriptor.json"])
        for name in sorted(set(MEMBERS) - {"descriptor.json"}):
            write_frozen(DESTINATION / name, raws[name])
    sync(DESTINATION)
def main():
    require(len(sys.argv) == 2 and sys.argv[1] in {"verify", "descriptor", "adjuncts"})
    if sys.argv[1] == "verify":
        load_lock()
        os.write(1, b"stage2 prebuilt KVM diagnostic lock verified\n")
    else:
        materialize(sys.argv[1])
if __name__ == "__main__":
    try:
        main()
    except (DiagnosticLockError, OSError, prebuilt.PrebuiltRootfsError):
        raise SystemExit(2)

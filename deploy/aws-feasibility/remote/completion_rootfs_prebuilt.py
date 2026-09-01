"""Closed descriptor and transport-neutral authority for the prebuilt rootfs."""

from dataclasses import dataclass, field
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True

import completion_archive_preflight as archive_preflight
import completion_rootfs_canonical as canonical
import completion_rootfs_model as model

VERSION = "cogs.stage2-prebuilt-rootfs-descriptor/v1"
AUTHORITY = "authenticated-static-control-only"
ARTIFACT_VERSION = "cogs.stage2-prebuilt-rootfs/v1"
REGISTRY_HOST = "ghcr.io"
REGISTRY_REPOSITORY = "nenb/cogs/stage2-rootfs"
REGISTRY_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
REGISTRY_LAYER_MEDIA_TYPE = "application/vnd.cogs.stage2.rootfs.v1.tar"
FORMAT = "canonical-ustar-v1"
ARCHITECTURE = "x86_64"
METADATA_SHA256 = "8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506"
METADATA_SIZE = 444
MANIFEST_SHA256 = "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1"
MANIFEST_SIZE = 1_049_443
USTAR_SHA256 = "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397"
USTAR_SIZE = 136_905_728
ENTRY_COUNT = 4_353
INPUT_CONTRACT_SHA256 = "fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341"
MAX_DESCRIPTOR_BYTES = 8_192
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")


class PrebuiltRootfsError(Exception):
    pass


def _require(condition):
    if not condition:
        raise PrebuiltRootfsError()


def _digest(value):
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    return value


def _revision(value):
    _require(type(value) is str and _REVISION.fullmatch(value) is not None)
    return value


def _exact(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _require(type(key) is str and key not in value)
        value[key] = item
    return value


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise PrebuiltRootfsError() from error


def _decode(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_DESCRIPTOR_BYTES and raw.endswith(b"\n") and b"\r" not in raw)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PrebuiltRootfsError() from error
    _require(_canonical(value) == raw)
    return value


@dataclass(frozen=True)
class PrebuiltRootfsDescriptor:
    manifest_digest: str
    layer_digest: str
    layer_size: int
    metadata_sha256: str
    metadata_size: int
    rootfs_manifest_sha256: str
    rootfs_manifest_size: int
    ustar_sha256: str
    ustar_size: int
    entry_count: int
    source_date_epoch: int
    producer_revision: str
    producer_source_manifest_sha256: str
    input_contract_sha256: str
    package_manifest_sha256: str
    provenance_sha256: str
    qualification_receipt_sha256: str
    publication_receipt_sha256: str

    def __post_init__(self):
        for value in (
            self.manifest_digest, self.layer_digest, self.metadata_sha256,
            self.rootfs_manifest_sha256, self.ustar_sha256,
            self.producer_source_manifest_sha256, self.input_contract_sha256,
            self.package_manifest_sha256, self.provenance_sha256,
            self.qualification_receipt_sha256, self.publication_receipt_sha256,
        ):
            _digest(value)
        _revision(self.producer_revision)
        _require(
            type(self.layer_size) is int and self.layer_size > 0
            and type(self.metadata_size) is int and self.metadata_size > 0
            and type(self.rootfs_manifest_size) is int and self.rootfs_manifest_size > 0
            and type(self.ustar_size) is int and self.ustar_size > 0 and self.ustar_size % 512 == 0
            and type(self.entry_count) is int and self.entry_count > 0
            and type(self.source_date_epoch) is int and self.source_date_epoch > 0
        )

    def manifest_path(self):
        return f"/v2/{REGISTRY_REPOSITORY}/manifests/sha256:{self.manifest_digest}"

    def blob_path(self):
        return f"/v2/{REGISTRY_REPOSITORY}/blobs/sha256:{self.layer_digest}"


@dataclass(frozen=True)
class PrebuiltRootfsView:
    descriptor: PrebuiltRootfsDescriptor
    descriptor_raw: bytes = field(repr=False)
    ustar: bytes = field(repr=False)
    manifest: bytes = field(repr=False)
    plan: model.RootfsPlan


@dataclass(frozen=True)
class PrebuiltRootfsAuthority:
    descriptor: PrebuiltRootfsDescriptor
    descriptor_raw: bytes = field(repr=False)
    ustar: bytes = field(repr=False)
    manifest: bytes = field(repr=False)
    plan: model.RootfsPlan


def decode_descriptor(raw):
    value = _decode(raw)
    _exact(value, ("version", "authority", "artifact", "registry", "rootfs", "producer"))
    _require(value["version"] == VERSION and value["authority"] == AUTHORITY)
    artifact = value["artifact"]
    _exact(artifact, ("version", "os", "architecture", "format"))
    _require(artifact == {"version": ARTIFACT_VERSION, "os": "linux", "architecture": ARCHITECTURE, "format": FORMAT})
    registry = value["registry"]
    _exact(registry, ("host", "repository", "manifest_media_type", "manifest_digest", "layer_media_type", "layer_digest", "layer_size"))
    _require(registry["host"] == REGISTRY_HOST and registry["repository"] == REGISTRY_REPOSITORY)
    _require(registry["manifest_media_type"] == REGISTRY_MANIFEST_MEDIA_TYPE and registry["layer_media_type"] == REGISTRY_LAYER_MEDIA_TYPE)
    rootfs = value["rootfs"]
    _exact(rootfs, ("metadata_sha256", "metadata_size", "manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count", "source_date_epoch"))
    producer = value["producer"]
    _exact(producer, ("revision", "source_manifest_sha256", "input_contract_sha256", "package_manifest_sha256", "provenance_sha256", "qualification_receipt_sha256", "publication_receipt_sha256"))
    descriptor = PrebuiltRootfsDescriptor(
        _digest(registry["manifest_digest"]), _digest(registry["layer_digest"]), registry["layer_size"],
        _digest(rootfs["metadata_sha256"]), rootfs["metadata_size"],
        _digest(rootfs["manifest_sha256"]), rootfs["manifest_size"],
        _digest(rootfs["ustar_sha256"]), rootfs["ustar_size"], rootfs["entry_count"], rootfs["source_date_epoch"],
        _revision(producer["revision"]), _digest(producer["source_manifest_sha256"]),
        _digest(producer["input_contract_sha256"]), _digest(producer["package_manifest_sha256"]),
        _digest(producer["provenance_sha256"]), _digest(producer["qualification_receipt_sha256"]),
        _digest(producer["publication_receipt_sha256"]),
    )
    _require(descriptor.layer_digest == descriptor.ustar_sha256 and descriptor.layer_size == descriptor.ustar_size)
    return descriptor


def decode_fixed_descriptor(raw):
    descriptor = decode_descriptor(raw)
    _require((descriptor.metadata_sha256, descriptor.metadata_size) == (METADATA_SHA256, METADATA_SIZE))
    _require((descriptor.rootfs_manifest_sha256, descriptor.rootfs_manifest_size) == (MANIFEST_SHA256, MANIFEST_SIZE))
    _require((descriptor.ustar_sha256, descriptor.ustar_size) == (USTAR_SHA256, USTAR_SIZE))
    _require(descriptor.entry_count == ENTRY_COUNT and descriptor.source_date_epoch == model.SOURCE_DATE_EPOCH)
    _require(descriptor.input_contract_sha256 == INPUT_CONTRACT_SHA256)
    return descriptor


def _archive_bounds(descriptor):
    return {
        "max_entries": descriptor.entry_count + 1,
        "max_regular_bytes": descriptor.ustar_size,
        "max_file_bytes": 128 * 1024 * 1024,
        "max_path_bytes": 4096,
        "max_component_bytes": 255,
    }


def preflight(descriptor, descriptor_raw, ustar):
    _require(type(descriptor) is PrebuiltRootfsDescriptor and type(descriptor_raw) is bytes and type(ustar) is bytes)
    _require(len(ustar) == descriptor.ustar_size and hashlib.sha256(ustar).hexdigest() == descriptor.ustar_sha256)
    try:
        archive = archive_preflight._preflight_material_tar(ustar, _archive_bounds(descriptor), "oci")
    except archive_preflight.ArchivePreflightError as error:
        raise PrebuiltRootfsError() from error
    archive_entries = tuple(model.PlannedEntry("prebuilt-rootfs-v1", archive, record) for record in archive.records)
    paths = tuple(entry.record.path for entry in archive_entries)
    _require(archive.root == model.ROOT_POLICY and len(archive_entries) == descriptor.entry_count)
    _require(len(paths) == len(set(paths)))
    entries = tuple(sorted(archive_entries, key=lambda entry: entry.record.path.encode("utf-8")))
    rootfs_plan = model.RootfsPlan(archive.root, ("prebuilt-rootfs-v1",), entries, ())
    _require(archive_entries == canonical._ordered_entries(rootfs_plan))
    manifest = canonical._manifest(rootfs_plan)
    _require(len(manifest) == descriptor.rootfs_manifest_size and hashlib.sha256(manifest).hexdigest() == descriptor.rootfs_manifest_sha256)
    return PrebuiltRootfsView(descriptor, descriptor_raw, ustar, manifest, rootfs_plan)


def load_authority(descriptor_raw, ustar):
    descriptor = decode_fixed_descriptor(descriptor_raw)
    view = preflight(descriptor, descriptor_raw, ustar)
    return PrebuiltRootfsAuthority(view.descriptor, view.descriptor_raw, view.ustar, view.manifest, view.plan)


def revalidate_authority(authority):
    _require(type(authority) is PrebuiltRootfsAuthority)
    view = preflight(authority.descriptor, authority.descriptor_raw, authority.ustar)
    _require(view.descriptor == authority.descriptor and view.manifest == authority.manifest
             and view.plan == authority.plan)
    return view

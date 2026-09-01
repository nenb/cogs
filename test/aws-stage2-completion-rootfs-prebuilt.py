#!/usr/bin/env python3
"""Portable hostile checks for the closed prebuilt-rootfs descriptor and ustar."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_archive_preflight as archive
import completion_rootfs_canonical as canonical
import completion_rootfs_model as model
import completion_rootfs_prebuilt as prebuilt

D = "1" * 64
R = "2" * 40


def require(condition):
    if not condition:
        raise AssertionError()


def rejected(callback):
    try:
        callback()
    except prebuilt.PrebuiltRootfsError:
        return
    raise AssertionError("hostile prebuilt input accepted")


def descriptor_value(**overrides):
    value = {
        "version": prebuilt.VERSION,
        "authority": prebuilt.AUTHORITY,
        "artifact": {"version": prebuilt.ARTIFACT_VERSION, "os": "linux", "architecture": prebuilt.ARCHITECTURE, "format": prebuilt.FORMAT},
        "registry": {
            "host": prebuilt.REGISTRY_HOST,
            "repository": prebuilt.REGISTRY_REPOSITORY,
            "manifest_media_type": prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE,
            "manifest_digest": D,
            "layer_media_type": prebuilt.REGISTRY_LAYER_MEDIA_TYPE,
            "layer_digest": prebuilt.USTAR_SHA256,
            "layer_size": prebuilt.USTAR_SIZE,
        },
        "rootfs": {
            "metadata_sha256": prebuilt.METADATA_SHA256,
            "metadata_size": prebuilt.METADATA_SIZE,
            "manifest_sha256": prebuilt.MANIFEST_SHA256,
            "manifest_size": prebuilt.MANIFEST_SIZE,
            "ustar_sha256": prebuilt.USTAR_SHA256,
            "ustar_size": prebuilt.USTAR_SIZE,
            "entry_count": prebuilt.ENTRY_COUNT,
            "source_date_epoch": model.SOURCE_DATE_EPOCH,
        },
        "producer": {
            "revision": R,
            "source_manifest_sha256": D,
            "input_contract_sha256": prebuilt.INPUT_CONTRACT_SHA256,
            "package_manifest_sha256": D,
            "provenance_sha256": D,
            "qualification_receipt_sha256": D,
            "publication_receipt_sha256": D,
        },
    }
    for path, item in overrides.items():
        target = value
        parts = path.split("__")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = item
    return value


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, sort_keys=True).encode("ascii") + b"\n"


def fixed_descriptor_checks():
    raw = encoded(descriptor_value())
    parsed = prebuilt.decode_fixed_descriptor(raw)
    require(parsed.blob_path() == f"/v2/{prebuilt.REGISTRY_REPOSITORY}/blobs/sha256:{prebuilt.USTAR_SHA256}")
    for path, item in (
        ("authority", "caller-selected"),
        ("registry__host", "example.com"),
        ("registry__repository", "nenb/cogs/latest"),
        ("registry__manifest_digest", "sha256:" + D),
        ("registry__layer_digest", "3" * 64),
        ("registry__layer_size", prebuilt.USTAR_SIZE - 1),
        ("rootfs__metadata_sha256", "3" * 64),
        ("rootfs__manifest_sha256", "3" * 64),
        ("rootfs__ustar_sha256", "3" * 64),
        ("rootfs__entry_count", prebuilt.ENTRY_COUNT - 1),
        ("producer__revision", "3" * 39),
        ("producer__input_contract_sha256", "3" * 64),
    ):
        rejected(lambda path=path, item=item: prebuilt.decode_fixed_descriptor(encoded(descriptor_value(**{path: item}))))
    unknown = descriptor_value(); unknown["url"] = "https://example.com/latest"
    rejected(lambda: prebuilt.decode_fixed_descriptor(encoded(unknown)))
    unsorted = json.dumps(descriptor_value(), separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    rejected(lambda: prebuilt.decode_fixed_descriptor(unsorted))
    duplicate = raw.replace(b'"version":"cogs.stage2-prebuilt-rootfs-descriptor/v1"', b'"version":"cogs.stage2-prebuilt-rootfs-descriptor/v1","version":"cogs.stage2-prebuilt-rootfs-descriptor/v1"', 1)
    rejected(lambda: prebuilt.decode_fixed_descriptor(duplicate))
    for hostile in (raw[:-1], b" " + raw, raw.replace(b"\n", b"\r\n"), b"{}\n", b"[]\n"):
        rejected(lambda hostile=hostile: prebuilt.decode_fixed_descriptor(hostile))


def _tiny_archive():
    content = b"prebuilt-rootfs\n"
    directory = archive.MaterialRecord("usr", "directory", 0o755, 0, 0, model.SOURCE_DATE_EPOCH, 0, None, None, None, None, -1)
    regular = archive.MaterialRecord("usr/proof", "file", 0o644, 0, 0, model.SOURCE_DATE_EPOCH, len(content), None, None, None, hashlib.sha256(content).hexdigest(), -1)
    symlink = archive.MaterialRecord("bin", "symlink", 0o777, 0, 0, model.SOURCE_DATE_EPOCH, 0, "usr/bin", None, None, None, -1)
    raw = canonical._header("./", model.ROOT_POLICY, b"5", 0)
    raw += canonical._header(directory.path, directory, b"5", 0)
    raw += canonical._header(regular.path, regular, b"0", len(content))
    raw += content + b"\0" * ((512 - len(content) % 512) % 512)
    raw += canonical._header(symlink.path, symlink, b"2", 0, symlink.link_text.encode()) + b"\0" * 1024
    parsed = archive._preflight_material_tar(raw, {"max_entries": 4, "max_regular_bytes": len(raw), "max_file_bytes": len(content), "max_path_bytes": 4096, "max_component_bytes": 255}, "oci")
    archive_entries = tuple(model.PlannedEntry("test", parsed, record) for record in parsed.records)
    entries = tuple(sorted(archive_entries, key=lambda entry: entry.record.path.encode("utf-8")))
    plan = model.RootfsPlan(parsed.root, ("test",), entries, ())
    manifest = canonical._manifest(plan)
    descriptor = prebuilt.PrebuiltRootfsDescriptor(
        D, hashlib.sha256(raw).hexdigest(), len(raw), D, 1,
        hashlib.sha256(manifest).hexdigest(), len(manifest), hashlib.sha256(raw).hexdigest(), len(raw),
        len(entries), model.SOURCE_DATE_EPOCH, R, D, prebuilt.INPUT_CONTRACT_SHA256, D, D, D, D,
    )
    return descriptor, b"test\n", raw, plan


def preflight_checks():
    descriptor, descriptor_raw, raw, expected = _tiny_archive()
    view = prebuilt.preflight(descriptor, descriptor_raw, raw)
    require(canonical._manifest(view.plan) == canonical._manifest(expected))
    proof = next(entry for entry in view.plan.entries if entry.record.path == "usr/proof")
    require(bytes(proof.content()) == b"prebuilt-rootfs\n")
    for hostile in (raw[:-1], raw + b"\0", b"X" + raw[1:]):
        rejected(lambda hostile=hostile: prebuilt.preflight(descriptor, descriptor_raw, hostile))
    wrong_manifest = prebuilt.PrebuiltRootfsDescriptor(
        descriptor.manifest_digest, descriptor.layer_digest, descriptor.layer_size,
        descriptor.metadata_sha256, descriptor.metadata_size, D, descriptor.rootfs_manifest_size,
        descriptor.ustar_sha256, descriptor.ustar_size, descriptor.entry_count, descriptor.source_date_epoch,
        descriptor.producer_revision, descriptor.producer_source_manifest_sha256, descriptor.input_contract_sha256,
        descriptor.package_manifest_sha256, descriptor.provenance_sha256,
        descriptor.qualification_receipt_sha256, descriptor.publication_receipt_sha256,
    )
    rejected(lambda: prebuilt.preflight(wrong_manifest, descriptor_raw, raw))


fixed_descriptor_checks()
preflight_checks()
require("completion_rootfs_plan" not in sys.modules)
print("stage2 prebuilt rootfs portable checks passed")

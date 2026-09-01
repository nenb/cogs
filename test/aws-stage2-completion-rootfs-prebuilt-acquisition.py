#!/usr/bin/env python3
"""Portable fake-wire checks for fixed GHCR prebuilt-rootfs acquisition."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))

import completion_rootfs_prebuilt as prebuilt
import completion_rootfs_prebuilt_acquisition as acquisition


class Response:
    def __init__(self, status, headers, body):
        self.status = status; self.version = 11; self.headers = tuple(headers)
        self.body = body; self.offset = 0; self.closed = False

    def read(self, size, _deadline):
        if self.closed: raise AssertionError()
        value = self.body[self.offset:self.offset + size]; self.offset += len(value); return value

    def close(self): self.closed = True


class Transport:
    def __init__(self, responses): self.responses = list(responses); self.requests = []
    def request(self, request, _timeout):
        self.requests.append(request)
        if not self.responses: raise AssertionError()
        return self.responses.pop(0)


def descriptor_raw(blob, config=None):
    digest = hashlib.sha256(blob).hexdigest(); d = "1" * 64
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE,
        "artifactType": "application/vnd.cogs.stage2.rootfs.package.v1",
        "config": config or {"mediaType": "application/vnd.oci.empty.v1+json",
                             "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                             "size": 2, "data": "e30="},
        "layers": [{"mediaType": prebuilt.REGISTRY_LAYER_MEDIA_TYPE,
                    "digest": "sha256:" + digest, "size": len(blob)}],
    }, sort_keys=True, separators=(",", ":")).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    value = {
        "version": prebuilt.VERSION, "authority": prebuilt.AUTHORITY,
        "artifact": {"version": prebuilt.ARTIFACT_VERSION, "os": "linux", "architecture": prebuilt.ARCHITECTURE, "format": prebuilt.FORMAT},
        "registry": {"host": prebuilt.REGISTRY_HOST, "repository": prebuilt.REGISTRY_REPOSITORY,
                     "manifest_media_type": prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE, "manifest_digest": manifest_digest,
                     "layer_media_type": prebuilt.REGISTRY_LAYER_MEDIA_TYPE, "layer_digest": digest, "layer_size": len(blob)},
        "rootfs": {"metadata_sha256": d, "metadata_size": 1, "manifest_sha256": d, "manifest_size": 1,
                   "ustar_sha256": digest, "ustar_size": len(blob), "entry_count": 1, "source_date_epoch": 1},
        "producer": {"revision": "2" * 40, "source_manifest_sha256": d,
                     "input_contract_sha256": prebuilt.INPUT_CONTRACT_SHA256,
                     "package_manifest_sha256": d, "provenance_sha256": d,
                     "qualification_receipt_sha256": d, "publication_receipt_sha256": d},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            digest, manifest)


def responses(blob, digest, manifest, **changes):
    token = b'{"token":"fixed-public-token"}'
    location = (f"https://{acquisition.REDIRECT_HOST}/ghcrblobs11/blobs/sha256:{digest}"
                "?se=fixed&sig=fixed&sp=r")
    rows = [
        Response(200, (("Content-Type", "application/json"), ("Content-Length", str(len(token)))), token),
        Response(200, (("Content-Type", prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE),
                       ("Content-Length", str(len(manifest)))), manifest),
        Response(307, (("Location", location), ("Content-Length", "0")), b""),
        Response(200, (("Content-Type", "application/octet-stream"),
                       ("Content-Length", str(len(blob))), ("Via", "one"), ("Via", "two")), blob),
    ]
    for key, value in changes.items(): setattr(rows[int(key)], value[0], value[1])
    return rows


def rejected(callback):
    try: callback()
    except (acquisition.PrebuiltAcquisitionError, FileExistsError): return
    raise AssertionError("hostile acquisition accepted")


def stat_mode(path):
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


blob = b"fixed-prebuilt-rootfs-blob".ljust(512, b"\0")
raw, digest, manifest = descriptor_raw(blob)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary) / "input"
    transport = Transport(responses(blob, digest, manifest))
    receipt = acquisition._acquire(raw, transport, root)
    assert receipt.blob_sha256 == digest and receipt.blob_size == len(blob) and receipt.downloaded
    assert (root / acquisition.FINAL_NAME).read_bytes() == blob
    assert (root / acquisition.SENTINEL_NAME).read_bytes() == acquisition.SENTINEL
    assert stat_mode(root / acquisition.FINAL_NAME) == 0o400
    assert len(transport.requests) == 4
    assert transport.requests[0].url.startswith("https://ghcr.io/token?")
    assert any(name == "Authorization" for name, _value in transport.requests[1].headers)
    assert any(name == "Authorization" for name, _value in transport.requests[2].headers)
    assert all(name != "Authorization" for name, _value in transport.requests[3].headers)
    rejected(lambda: acquisition._acquire(raw, Transport(responses(blob, digest, manifest)), root))

for index, attribute, value in (
    (0, "status", 401), (1, "status", 404), (2, "status", 302), (3, "status", 206),
    (1, "body", manifest + b"x"), (3, "body", blob[:-1]), (3, "body", blob + b"x"),
):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "input"
        changed = responses(blob, digest, manifest); setattr(changed[index], attribute, value)
        rejected(lambda changed=changed, root=root: acquisition._acquire(raw, Transport(changed), root))
        assert root.exists() and not (root / acquisition.FINAL_NAME).exists()

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary) / "input"
    changed = responses(blob, digest, manifest)
    changed[2].headers = (("Location", "https://example.com/latest?sig=x"), ("Content-Length", "0"))
    rejected(lambda: acquisition._acquire(raw, Transport(changed), root))

for hostile_config in (
    {"mediaType": "application/vnd.oci.empty.v1+json",
     "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
     "size": 2},
    {"mediaType": "application/vnd.oci.empty.v1+json",
     "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
     "size": 2, "data": "e30=", "annotations": {}},
):
    hostile_raw, hostile_digest, hostile_manifest = descriptor_raw(blob, hostile_config)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "input"
        rejected(lambda: acquisition._acquire(
            hostile_raw, Transport(responses(blob, hostile_digest, hostile_manifest)), root))


print("stage2 prebuilt rootfs acquisition fake-wire checks passed")

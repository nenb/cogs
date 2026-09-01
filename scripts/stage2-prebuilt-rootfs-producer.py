#!/usr/bin/env python3
"""Qualification-only two-build producer for one canonical prebuilt rootfs."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote")
SOURCE_ROOT = REMOTE.parents[2]
PRODUCT = Path("/var/lib/cogs/stage2-prebuilt-rootfs-product-v1")
RECEIPT_NAME = "producer-receipt.json"
PACKAGE_NAME = "rootfs.package.json"
PROVENANCE_NAME = "rootfs.provenance.json"
VERSION = "cogs.stage2-prebuilt-rootfs-producer-receipt/v1"

sys.path.insert(0, str(REMOTE))
import completion_artifact_acquisition as acquisition
import completion_rootfs_build as build
import completion_rootfs_builder as builder
import completion_rootfs_fs as fs
import completion_rootfs_prebuilt as prebuilt
import completion_rootfs_publish as publication


class ProducerError(Exception):
    pass


def require(condition):
    if not condition:
        raise ProducerError()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def digest(raw): return hashlib.sha256(raw).hexdigest()


def fixed_text(name, length):
    value = os.environ.get(name)
    require(type(value) is str and len(value) == length and set(value) <= set("0123456789abcdef"))
    return value


def fixed_positive(name):
    value = os.environ.get(name)
    require(type(value) is str and value.isdigit() and not value.startswith("0"))
    return int(value)


def load_verifier():
    path = REMOTE / "verify-completion-artifacts.py"
    spec = importlib.util.spec_from_file_location("stage2_prebuilt_producer_verifier", path)
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def write_fixed(parent, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view); require(count > 0); view = view[count:]
        os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400); os.fsync(descriptor)
    finally: os.close(descriptor)


def read_fixed(parent, name, size):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) in {0o400, 0o600}
                and before.st_uid == before.st_gid == 0 and before.st_nlink == 1 and before.st_size == size)
        chunks=[]; total=0
        while total <= size:
            part=os.read(descriptor,min(1024*1024,size+1-total))
            if not part: break
            chunks.append(part); total += len(part)
        raw=b"".join(chunks); after = os.fstat(descriptor)
        stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == size and stable(before) == stable(after))
        return raw
    finally: os.close(descriptor)


def product_parent(control):
    require(not PRODUCT.exists())
    PRODUCT.mkdir(mode=0o700)
    os.chown(PRODUCT, 0, 0); os.chmod(PRODUCT, 0o700)
    root = fs._open_root_node(control)
    try:
        chain = fs._open_anchored_chain(root, (
            fs.NodePolicy(fs._name(b"var"), "directory", 0o755),
            fs.NodePolicy(fs._name(b"lib"), "directory", 0o755),
            fs.NodePolicy(fs._name(b"cogs"), "directory", 0o700),
            fs.NodePolicy(fs._name(PRODUCT.name), "directory", 0o700),
        ), control)
        return chain
    except BaseException as error:
        fs._close_node(root, error)


def main():
    require(os.geteuid() == 0 and sys.argv == [sys.argv[0]])
    revision = fixed_text("COGS_STAGE2_PREBUILT_PRODUCER_H", 40)
    source_manifest = fixed_text("COGS_STAGE2_PREBUILT_SOURCE_MANIFEST_SHA256", 64)
    workflow_sha256 = fixed_text("COGS_STAGE2_PREBUILT_WORKFLOW_SHA256", 64)
    run_id = fixed_positive("GITHUB_RUN_ID"); run_attempt = fixed_positive("GITHUB_RUN_ATTEMPT")
    require(run_attempt == 1 and os.environ.get("GITHUB_REPOSITORY") == "nenb/cogs"
            and os.environ.get("GITHUB_REF") == "refs/heads/main")
    source_raw = (SOURCE_ROOT / ".cogs-stage2-source-manifest-v1.json").read_bytes()
    require(digest(source_raw) == source_manifest and json.loads(source_raw)["revision"] == revision)
    verifier = load_verifier(); contract = verifier.verify_contract(verifier.FIXED_CONTRACT_PATH)
    require(digest(Path(verifier.FIXED_CONTRACT_PATH).read_bytes()) == prebuilt.INPUT_CONTRACT_SHA256)
    acquisition.acquire_artifacts(contract, SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/artifacts")
    verifier.verify_package_archives(verifier.FIXED_CONTRACT_PATH,
                                     SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/artifacts")
    control = fs.OperationControl(time.monotonic_ns() + 5_400_000_000_000, lambda: False)
    chain = product_parent(control)
    try:
        approval = fs.SourceApproval(revision, source_manifest)
        state = builder._bootstrap(chain, approval, control)
        fs._close_node(state)
        published = build._pinned_publication(approval, chain.components[-1].node, control)
        require((published.manifest_sha256, published.manifest_size,
                 published.ustar_sha256, published.ustar_size, published.entry_count) ==
                (prebuilt.MANIFEST_SHA256, prebuilt.MANIFEST_SIZE,
                 prebuilt.USTAR_SHA256, prebuilt.USTAR_SIZE, prebuilt.ENTRY_COUNT))
        parent = chain.components[-1].node.operation_fd.number
        accepted = os.open(publication.ACCEPTED_NAME.raw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            manifest = read_fixed(accepted, publication.MANIFEST_NAME.raw, prebuilt.MANIFEST_SIZE)
            ustar = read_fixed(accepted, publication.USTAR_NAME.raw, prebuilt.USTAR_SIZE)
            metadata = read_fixed(accepted, publication.METADATA_NAME.raw, prebuilt.METADATA_SIZE)
            sentinel = read_fixed(accepted, publication.SENTINEL_NAME.raw, len(publication.SENTINEL))
        finally: os.close(accepted)
        require(digest(manifest) == prebuilt.MANIFEST_SHA256 and digest(ustar) == prebuilt.USTAR_SHA256
                and digest(metadata) == prebuilt.METADATA_SHA256 and sentinel == publication.SENTINEL)
        members = [
            {"name": "rootfs.manifest.json", "size": len(manifest), "sha256": digest(manifest)},
            {"name": "rootfs.metadata.json", "size": len(metadata), "sha256": digest(metadata)},
            {"name": "rootfs.tar", "size": len(ustar), "sha256": digest(ustar)},
        ]
        provenance = {
            "version": "cogs.stage2-prebuilt-rootfs-provenance/v1",
            "authority": "qualification-producer-only",
            "builder": {"implementation_revision": revision, "source_manifest_sha256": source_manifest,
                        "workflow_sha256": workflow_sha256, "run_id": run_id, "run_attempt": run_attempt},
            "materials": {"input_contract_sha256": prebuilt.INPUT_CONTRACT_SHA256,
                          "input_count": 16},
            "subject": members,
            "observations": {"independent_builds": 2, "equal": True, "pins_matched": True,
                             "kvm_executed": False, "aws_executed": False, "provider_executed": False},
        }
        provenance_raw = canonical(provenance)
        package = {
            "version": "cogs.stage2-prebuilt-rootfs-package/v1",
            "authority": "qualification-input-not-product-release",
            "members": [*members, {"name": PROVENANCE_NAME, "size": len(provenance_raw),
                                    "sha256": digest(provenance_raw)}],
            "entry_count": prebuilt.ENTRY_COUNT,
            "source_date_epoch": prebuilt.model.SOURCE_DATE_EPOCH,
        }
        package_raw = canonical(package)
        receipt = {
            "version": VERSION, "result": "pass", "implementation_revision": revision,
            "source_manifest_sha256": source_manifest, "workflow_sha256": workflow_sha256,
            "run_id": run_id, "run_attempt": run_attempt,
            "package_manifest_sha256": digest(package_raw), "provenance_sha256": digest(provenance_raw),
            "manifest_sha256": prebuilt.MANIFEST_SHA256, "manifest_size": prebuilt.MANIFEST_SIZE,
            "ustar_sha256": prebuilt.USTAR_SHA256, "ustar_size": prebuilt.USTAR_SIZE,
            "entry_count": prebuilt.ENTRY_COUNT, "input_contract_sha256": prebuilt.INPUT_CONTRACT_SHA256,
            "builds": 2, "publication": "local-no-replace-accepted", "remote_published": False,
        }
        receipt_raw = canonical(receipt)
        write_fixed(parent, PROVENANCE_NAME, provenance_raw)
        write_fixed(parent, PACKAGE_NAME, package_raw)
        write_fixed(parent, RECEIPT_NAME, receipt_raw)
        os.fsync(parent)
        output = {"version": VERSION, "result": "pass", "product_path": str(PRODUCT),
                  "receipt_sha256": digest(receipt_raw), "package_manifest_sha256": digest(package_raw),
                  "provenance_sha256": digest(provenance_raw), "ustar_sha256": prebuilt.USTAR_SHA256}
        raw = canonical(output); require(sys.stdout.buffer.write(raw) == len(raw))
    finally: fs._close_chain(chain)


if __name__ == "__main__":
    try: main()
    except (ProducerError, fs.RootfsFsError): raise SystemExit(2)

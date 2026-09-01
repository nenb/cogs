#!/usr/bin/env python3
"""Trusted candidate validator and descriptor issuer for the rootfs OCI object."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_rootfs_prebuilt as prebuilt

CANDIDATE = Path(os.environ.get("COGS_PREBUILT_CANDIDATE_ROOT", "/nonexistent"))
HEX = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")


class PublisherError(Exception): pass


def require(value):
    if not value: raise PublisherError()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def sha(raw): return hashlib.sha256(raw).hexdigest()


def read(name, maximum):
    path = CANDIDATE / name; before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode)
            and before.st_nlink == 1 and 0 < before.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks=[]; total=0
        while total <= maximum:
            part=os.read(descriptor,min(1024*1024,maximum+1-total))
            if not part: break
            chunks.append(part); total += len(part)
        raw=b"".join(chunks); after = os.fstat(descriptor)
        stable = lambda item: (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        require(len(raw) == before.st_size and stable(before) == stable(after)); return raw
    finally: os.close(descriptor)


def value(raw):
    try: parsed = json.loads(raw)
    except (UnicodeError,ValueError,TypeError,RecursionError) as error: raise PublisherError() from error
    require(type(parsed) is dict and canonical(parsed) == raw); return parsed


def validate_candidate():
    expected = {"accepted/.cogs-rootfs-publication-v1", "accepted/rootfs.manifest.json",
                "accepted/rootfs.metadata.json", "accepted/rootfs.tar", "producer-receipt.json",
                "rootfs.package.json", "rootfs.provenance.json"}
    observed = {str(path.relative_to(CANDIDATE)): path for path in CANDIDATE.rglob("*")}
    require(set(observed) == expected | {"accepted"})
    require(observed["accepted"].is_dir() and not observed["accepted"].is_symlink())
    require(all(observed[name].is_file() and not observed[name].is_symlink()
                for name in expected))
    manifest = read("accepted/rootfs.manifest.json", prebuilt.MANIFEST_SIZE)
    metadata = read("accepted/rootfs.metadata.json", prebuilt.METADATA_SIZE)
    ustar = read("accepted/rootfs.tar", prebuilt.USTAR_SIZE)
    sentinel = read("accepted/.cogs-rootfs-publication-v1", 128)
    require((len(manifest),sha(manifest)) == (prebuilt.MANIFEST_SIZE,prebuilt.MANIFEST_SHA256))
    require((len(metadata),sha(metadata)) == (prebuilt.METADATA_SIZE,prebuilt.METADATA_SHA256))
    require((len(ustar),sha(ustar)) == (prebuilt.USTAR_SIZE,prebuilt.USTAR_SHA256))
    require(sentinel == b"cogs-rootfs-publication-v1\n")
    package_raw = read("rootfs.package.json", 64*1024); provenance_raw = read("rootfs.provenance.json", 128*1024)
    receipt_raw = read("producer-receipt.json", 64*1024)
    package, provenance, receipt = map(value,(package_raw,provenance_raw,receipt_raw))
    require(set(package) == {"version","authority","members","entry_count","source_date_epoch"})
    require(package.get("version") == "cogs.stage2-prebuilt-rootfs-package/v1"
            and package.get("authority") == "qualification-input-not-product-release"
            and package.get("entry_count") == prebuilt.ENTRY_COUNT
            and package.get("source_date_epoch") == prebuilt.model.SOURCE_DATE_EPOCH)
    members = package.get("members"); require(type(members) is list and len(members) == 4)
    require(all(type(row) is dict and set(row) == {"name","size","sha256"} for row in members))
    identities = {row["name"]:(row["size"],row["sha256"]) for row in members}
    require(identities == {
        "rootfs.manifest.json":(len(manifest),sha(manifest)), "rootfs.metadata.json":(len(metadata),sha(metadata)),
        "rootfs.tar":(len(ustar),sha(ustar)), "rootfs.provenance.json":(len(provenance_raw),sha(provenance_raw))})
    require(set(provenance) == {"version","authority","builder","materials","subject","observations"})
    require(provenance.get("version") == "cogs.stage2-prebuilt-rootfs-provenance/v1"
            and provenance.get("authority") == "qualification-producer-only"
            and provenance.get("subject") == members[:3]
            and provenance.get("materials") == {"input_contract_sha256":prebuilt.INPUT_CONTRACT_SHA256,"input_count":16})
    observed = provenance.get("observations")
    require(observed == {"independent_builds":2,"equal":True,"pins_matched":True,
                         "kvm_executed":False,"aws_executed":False,"provider_executed":False})
    builder = provenance.get("builder"); require(type(builder) is dict and SHA1.fullmatch(builder.get("implementation_revision","")))
    require(builder.get("source_manifest_sha256") == receipt.get("source_manifest_sha256")
            and builder.get("workflow_sha256") == receipt.get("workflow_sha256")
            and builder.get("run_id") == receipt.get("run_id")
            and builder.get("run_attempt") == receipt.get("run_attempt") == 1)
    require(set(receipt) == {"version","result","implementation_revision","source_manifest_sha256",
                            "workflow_sha256","run_id","run_attempt","package_manifest_sha256",
                            "provenance_sha256","manifest_sha256","manifest_size","ustar_sha256",
                            "ustar_size","entry_count","input_contract_sha256","builds","publication",
                            "remote_published"})
    require(receipt.get("version") == "cogs.stage2-prebuilt-rootfs-producer-receipt/v1"
            and receipt.get("result") == "pass" and receipt.get("implementation_revision") == builder["implementation_revision"]
            and receipt.get("package_manifest_sha256") == sha(package_raw)
            and receipt.get("provenance_sha256") == sha(provenance_raw)
            and receipt.get("manifest_sha256") == prebuilt.MANIFEST_SHA256
            and receipt.get("manifest_size") == prebuilt.MANIFEST_SIZE
            and receipt.get("ustar_sha256") == prebuilt.USTAR_SHA256
            and receipt.get("ustar_size") == prebuilt.USTAR_SIZE
            and receipt.get("entry_count") == prebuilt.ENTRY_COUNT
            and receipt.get("input_contract_sha256") == prebuilt.INPUT_CONTRACT_SHA256
            and receipt.get("builds") == 2 and receipt.get("remote_published") is False)
    output = {"implementation_revision":builder["implementation_revision"],
              "source_manifest_sha256":builder["source_manifest_sha256"],
              "producer_run_id":builder["run_id"], "producer_receipt_sha256":sha(receipt_raw),
              "package_manifest_sha256":sha(package_raw), "provenance_sha256":sha(provenance_raw)}
    sys.stdout.buffer.write(canonical(output))


def issue_descriptor():
    require(SHA1.fullmatch(os.environ.get("COGS_PREBUILT_H","")))
    fields = {name:os.environ.get(name) for name in (
        "COGS_PREBUILT_SOURCE_MANIFEST_SHA256","COGS_PREBUILT_PACKAGE_MANIFEST_SHA256",
        "COGS_PREBUILT_PROVENANCE_SHA256","COGS_PREBUILT_QUALIFICATION_RECEIPT_SHA256",
        "COGS_PREBUILT_PUBLICATION_RECEIPT_SHA256","COGS_PREBUILT_OCI_MANIFEST_DIGEST")}
    require(all(type(item) is str and HEX.fullmatch(item) for item in fields.values()))
    descriptor = {
        "version":prebuilt.VERSION,"authority":prebuilt.AUTHORITY,
        "artifact":{"version":prebuilt.ARTIFACT_VERSION,"os":"linux","architecture":prebuilt.ARCHITECTURE,"format":prebuilt.FORMAT},
        "registry":{"host":prebuilt.REGISTRY_HOST,"repository":prebuilt.REGISTRY_REPOSITORY,
                    "manifest_media_type":prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE,
                    "manifest_digest":fields["COGS_PREBUILT_OCI_MANIFEST_DIGEST"],
                    "layer_media_type":prebuilt.REGISTRY_LAYER_MEDIA_TYPE,
                    "layer_digest":prebuilt.USTAR_SHA256,"layer_size":prebuilt.USTAR_SIZE},
        "rootfs":{"metadata_sha256":prebuilt.METADATA_SHA256,"metadata_size":prebuilt.METADATA_SIZE,
                  "manifest_sha256":prebuilt.MANIFEST_SHA256,"manifest_size":prebuilt.MANIFEST_SIZE,
                  "ustar_sha256":prebuilt.USTAR_SHA256,"ustar_size":prebuilt.USTAR_SIZE,
                  "entry_count":prebuilt.ENTRY_COUNT,"source_date_epoch":prebuilt.model.SOURCE_DATE_EPOCH},
        "producer":{"revision":os.environ["COGS_PREBUILT_H"],
                    "source_manifest_sha256":fields["COGS_PREBUILT_SOURCE_MANIFEST_SHA256"],
                    "input_contract_sha256":prebuilt.INPUT_CONTRACT_SHA256,
                    "package_manifest_sha256":fields["COGS_PREBUILT_PACKAGE_MANIFEST_SHA256"],
                    "provenance_sha256":fields["COGS_PREBUILT_PROVENANCE_SHA256"],
                    "qualification_receipt_sha256":fields["COGS_PREBUILT_QUALIFICATION_RECEIPT_SHA256"],
                    "publication_receipt_sha256":fields["COGS_PREBUILT_PUBLICATION_RECEIPT_SHA256"]}}
    raw=prebuilt._canonical(descriptor);prebuilt.decode_fixed_descriptor(raw);sys.stdout.buffer.write(raw)


if __name__ == "__main__":
    try:
        require(len(sys.argv)==2)
        {"validate-candidate":validate_candidate,"issue-descriptor":issue_descriptor}[sys.argv[1]]()
    except (PublisherError,KeyError,prebuilt.PrebuiltRootfsError): raise SystemExit(2)

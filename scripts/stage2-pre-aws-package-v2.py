#!/usr/bin/env python3
"""Construct the corrected canonical non-AWS prerequisite package."""
from pathlib import Path
import hashlib
import json
import os
import re
import sys


class PackageError(Exception): pass


def require(value):
    if not value: raise PackageError()


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value); value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def read(path, maximum=32 * 1024 * 1024):
    raw = Path(path).read_bytes(); require(0 < len(raw) <= maximum)
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PackageError() from error
    require(type(value) is dict and canonical(value) == raw)
    return raw, value


def positive(name):
    value = os.environ.get(name, ""); require(re.fullmatch(r"[1-9][0-9]*", value) is not None)
    return int(value)


def artifact_digest(name):
    value = os.environ.get(name, "")
    match = re.fullmatch(r"(?:sha256:)?([0-9a-f]{64})", value)
    require(match is not None); return "sha256:" + match.group(1)


def build(report_path, receipt_path, control_path, envelope_path):
    report_raw, report = read(report_path); receipt_raw, receipt = read(receipt_path)
    control_raw, control = read(control_path); _envelope_raw, envelope = read(envelope_path)
    require(report.get("version") == "cogs.stage2-workload-local-qualification/v4"
            and report.get("result") == "pass" and report.get("qualified") is True
            and report.get("rootfs_input", {}).get("build_attempts") == 0
            and report.get("rootfs_input", {}).get("import_attempts") == 1
            and receipt.get("report", {}).get("sha256") == hashlib.sha256(report_raw).hexdigest()
            and receipt.get("control", {}).get("sha256") == hashlib.sha256(control_raw).hexdigest()
            and control.get("version") == "cogs.stage2-local-static-control-package/v2"
            and envelope.get("version") == "cogs.stage2-local-execution-envelope/v3")
    bindings = report["bindings"]; descriptor = envelope["rootfs"]["prebuilt_descriptor"]
    descriptor_raw = canonical(descriptor); producer = descriptor["producer"]
    require(bindings["rootfs_descriptor_sha256"] == hashlib.sha256(descriptor_raw).hexdigest()
            and bindings["rootfs_package_manifest_sha256"] == producer["package_manifest_sha256"]
            and bindings["rootfs_provenance_sha256"] == producer["provenance_sha256"]
            and bindings["rootfs_publication_receipt_sha256"] == producer["publication_receipt_sha256"]
            and bindings["source_head"] == producer["revision"]
            and bindings["source_manifest_sha256"] == producer["source_manifest_sha256"]
            and receipt["control"]["head"] == envelope["control_revision"])
    return canonical({
        "version": "cogs.stage2-pre-aws-qualification-package/v2",
        "authority": "non-aws-prerequisite-evidence-only",
        "implementation_revision": bindings["source_head"],
        "control_revision": receipt["control"]["head"],
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "static_control_sha256": receipt["control"]["sha256"],
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "rootfs": {"descriptor_sha256": bindings["rootfs_descriptor_sha256"],
            "package_manifest_sha256": producer["package_manifest_sha256"],
            "provenance_sha256": producer["provenance_sha256"],
            "qualification_receipt_sha256": producer["qualification_receipt_sha256"],
            "publication_receipt_sha256": producer["publication_receipt_sha256"]},
        "runtime_commitment": bindings["runtime_attestation_sha256"],
        "fixture_commitment": bindings["final_pin_sha256"],
        "supersedes": {"version": "cogs.stage2-pre-aws-qualification-package/v1",
            "package_sha256": "78f19b4fc4ac9d64d4f3a9a35d68850fd44122c61e00907eefcb19d6f86c0899",
            "reason": "historical-rebuild-based-evidence-does-not-authorize-prebuilt-production"},
        "artifacts": {"report_id": positive("REPORT_ARTIFACT_ID"),
            "report_digest": artifact_digest("REPORT_ARTIFACT_DIGEST"),
            "receipt_id": positive("RECEIPT_ARTIFACT_ID"),
            "receipt_digest": artifact_digest("RECEIPT_ARTIFACT_DIGEST")},
        "claims": {"local_qualification_passed": True, "aws_authorized": False,
            "aws_executed": False, "promotion_authorized": False}})


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 5)
        raw = build(*sys.argv[1:]); require(sys.stdout.buffer.write(raw) == len(raw))
    except (OSError, PackageError): raise SystemExit(2)

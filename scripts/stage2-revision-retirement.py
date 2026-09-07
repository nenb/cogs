#!/usr/bin/env python3
"""Exact selection veto only; never authorization, ancestry traversal or cleanup."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

POLICY = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v1.json"
REVISIONS = {"9b9966afffe0ea8de4d0c99147886a95094470a9": "ADR0319",
             "6bd12dcd25d877ffac03752fa0f71beeeb86a99e": "ADR0309",
             "8907eba3191d07573cd84573cb0b2adddff17bd6": "ADR0308",
             "242bbefeae5444118d9e97b46597130b509ca253": "ADR0308"}
RUNS = {"34023790672": "ADR0308", "34028384783": "ADR0308"}
ARTIFACTS = {"9988125363": "ADR0308"}

class RetirementError(ValueError):
    pass

def require(value):
    if not value:
        raise RetirementError("retired selection or invalid retirement policy/provenance")

def pairs(rows):
    value = {}
    for key, item in rows:
        require(key not in value)
        value[key] = item
    return value

def document(path, maximum):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 < before.st_size <= maximum)
            raw = os.read(fd, maximum + 1)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                                     item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)))
        finally:
            os.close(fd)
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _x: require(False))
        require(type(value) is dict)
        return value, raw
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise RetirementError("unreadable or malformed retirement policy/provenance") from error

def load_policy(path=POLICY):
    value, _raw = document(path, 4096)
    # Closed v1 identity set: omission, extension and decision drift need review.
    require(value == {"version": "cogs.stage2-retired-revisions/v1",
                      "revisions": REVISIONS, "runs": RUNS, "artifacts": ARTIFACTS})
    return value

def select(revisions, runs=(), artifacts=(), policy=POLICY):
    value = load_policy(policy)  # Even an empty/invalid request cannot bypass policy.
    require(type(revisions) in {tuple, list} and 1 <= len(revisions) <= 8)
    for items, kind, pattern in ((revisions, "revisions", r"[0-9a-f]{40}"),
                                 (runs, "runs", r"[1-9][0-9]{0,19}"),
                                 (artifacts, "artifacts", r"[1-9][0-9]{0,19}")):
        require(type(items) in {tuple, list} and len(items) <= 8)
        for item in items:
            require(type(item) is str and re.fullmatch(pattern, item) is not None
                    and item not in value[kind])

def custody(root, implementation, control):
    """Veto authenticated publication inputs before staging; codecs still validate."""
    select((implementation, control))
    root = Path(root)
    descriptor, _ = document(root / "descriptor.json", 64 * 1024)
    provenance, provenance_raw = document(root / "rootfs.provenance.json", 128 * 1024)
    receipt, receipt_raw = document(root / "producer-receipt.json", 64 * 1024)
    publication, publication_raw = document(root / "publication-receipt.json", 64 * 1024)
    producer = descriptor["producer"]
    select((producer["revision"], provenance["builder"]["implementation_revision"],
            receipt["implementation_revision"], publication["implementation_revision"],
            publication["control_revision"]),
           runs=(str(provenance["builder"]["run_id"]), str(receipt["run_id"]),
                 str(publication["producer_run_id"]), str(publication["publisher_run_id"])),
           artifacts=(str(publication["producer_artifact_id"]),))
    require(producer["revision"] == provenance["builder"]["implementation_revision"]
            == receipt["implementation_revision"] == publication["implementation_revision"] == implementation
            and publication["control_revision"] == control)
    for field, raw in (("provenance_sha256", provenance_raw),
                       ("qualification_receipt_sha256", receipt_raw),
                       ("publication_receipt_sha256", publication_raw)):
        require(producer[field] == hashlib.sha256(raw).hexdigest())

if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "custody":
            custody(*sys.argv[2:])
        else:
            select(sys.argv[1:])
    except (RetirementError, KeyError, TypeError):
        raise SystemExit(2) from None

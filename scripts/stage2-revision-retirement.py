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
REVISIONS = {
    "11c03441468d4c3130667321018e1cb6f626a303": "ADR0332",
    "a9b54c1a823601c3e938e2a616abd0222c0a2846": "ADR0332",
    "c30e0d69ec374cd812ff361e670e974d51b661c4": "ADR0330",
    "15d99b55f4910df94decdd7edcc80bf95aee492d": "ADR0330",
    "d0e29eb359f0c1678c18f676e312276eff3aa3f8": "ADR0330",
    "c10fc103532f3e3a8b746727bd0f48c6d8498148": "ADR0327",
    "eb59cae18e0f041a243f35f253d46713f7e87142": "ADR0327",
    "b11adc47c454bde0dc0e2930012e418b90917555": "ADR0327",
    "6276eae08e29ee577f3d9b2c739ceadfe467a769": "ADR0326",
    "5601edf196a1bd4127afed6adf12ad8525fdb5b3": "ADR0326",
    "9f6e79140e4df284588182c96b5044bb52f50ef9": "ADR0326",
    "0e5b7012fabae3412ce8e3110bb181af1ffe608b": "ADR0326",
    "f93748b253c1429cce9149defde623f40c9cc0ab": "ADR0326",
    "d2fe08553d25d73fa276794c96b0f311e5406186": "ADR0326",
    "a108f981dacad6978e2a37d16a143da5c3b51cf4": "ADR0326",
    "728a77a87328e9cccd57547a930e84764964061f": "ADR0326",
    "8e2af4398519ab8d64b7f9e7194f9c116c6f51d9": "ADR0326",
    "229ea62bce964086726181974a6fec1c6dfd1f86": "ADR0326",
    "821149ba4c3dbccef48694efcdb1eb29fa9fd2b9": "ADR0326",
    "06188f67a9a699924d645ce8aa0e91950b6341c7": "ADR0326",
    "8a1b56cfdaf013b27d8ef7a7e2753d3bb2582271": "ADR0326",
    "69987e08cf9454fecf540a4de097f0877155b043": "ADR0326",
    "97bc8eb8520a2116914c65a9ec5929e82c34ebf3": "ADR0324",
    "942e84cd8f977ee23a97dc47ce4a5d2d7510b346": "ADR0324",
    "0296252721fad0502dd4f41dacb1674e71b42bd6": "ADR0323",
    "9b9966afffe0ea8de4d0c99147886a95094470a9": "ADR0319",
    "6bd12dcd25d877ffac03752fa0f71beeeb86a99e": "ADR0309",
    "8907eba3191d07573cd84573cb0b2adddff17bd6": "ADR0308",
    "242bbefeae5444118d9e97b46597130b509ca253": "ADR0308",
}
RUNS = {
    "34452651886": "ADR0332", "34467314193": "ADR0332", "34486733842": "ADR0332",
    "34375934829": "ADR0330", "34402409489": "ADR0330",
    "34403562378": "ADR0330", "34411847798": "ADR0330",
    "34282898803": "ADR0327", "34292774279": "ADR0327", "34293986674": "ADR0327",
    "34301325559": "ADR0327", "34302034014": "ADR0327",
    "34257525184": "ADR0326", "33626103650": "ADR0326", "33630868892": "ADR0326",
    "33837299968": "ADR0326", "33850962596": "ADR0326", "33851159217": "ADR0326",
    "33908498241": "ADR0326", "33931002300": "ADR0326", "33931091412": "ADR0326",
    "33965298642": "ADR0326", "33972129993": "ADR0326", "33980034976": "ADR0326",
    "33987181596": "ADR0326", "33987659305": "ADR0326", "33995592875": "ADR0326",
    "33995910136": "ADR0326", "34007531193": "ADR0326", "34013328638": "ADR0326",
    "34013774850": "ADR0326", "34183885618": "ADR0324", "34192071842": "ADR0324",
    "34192787285": "ADR0324", "34023790672": "ADR0308", "34028384783": "ADR0308",
}
ARTIFACTS = {
    "10143009714": "ADR0332", "10148066929": "ADR0332", "10155984475": "ADR0332",
    "10114901253": "ADR0330", "10123988189": "ADR0330", "10124443866": "ADR0330",
    "10079099187": "ADR0327", "10081986019": "ADR0327", "10082440691": "ADR0327",
    "10069446931": "ADR0326", "9845676644": "ADR0326", "9924034454": "ADR0326",
    "9928325265": "ADR0326", "9951239210": "ADR0326", "9958532006": "ADR0326",
    "9958574502": "ADR0326", "9971564905": "ADR0326", "9973726406": "ADR0326",
    "9975524471": "ADR0326", "9975667979": "ADR0326", "9981717931": "ADR0326",
    "9983143614": "ADR0326", "9983282050": "ADR0326", "10040293103": "ADR0324",
    "10042564354": "ADR0324", "9988125363": "ADR0308",
}

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

#!/usr/bin/env python3
"""Exact selection veto only; never authorization, ancestry traversal or cleanup."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

POLICY_V1 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v1.json"
POLICY_V2 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v2.json"
POLICY_V3 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v3.json"
POLICY_V4 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v4.json"
POLICY_V5 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v5.json"
POLICY_V6 = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v6.json"
POLICY = Path(__file__).resolve().parents[1] / "config/stage2-retired-revisions-v7.json"
POLICY_V1_SHA256 = "2fe7b704438d9e3f7493ee8be43760ac9f213d095d5411bee137126bc72153b5"
POLICY_V2_SHA256 = "035e8c9dc9a8f2a78d1e4360aaf43cde41329771abe222ec7035bfb39dc14c6b"
POLICY_V3_SHA256 = "3064490893b1fac4a2945b5b90bec89efbfdf1bea97e0b557550950d7dae63ad"
POLICY_V4_SHA256 = "588468079ddcc6161a8cbc2bacc84d3cca2aac6e03a0325e2af72d846c9efa5d"
POLICY_V5_SHA256 = "a2b2ca60e424d16a28f33d2d0a48b5f5b268fc26cedbe89d535d119af99033a7"
POLICY_V6_SHA256 = "5faf66f56ed02ff8e3be63892f421ae5b0465e66387b05b2a1a8cb8b66f90f37"
REVISIONS_V1 = {
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
RUNS_V1 = {
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
ARTIFACTS_V1 = {
    "10114901253": "ADR0330", "10123988189": "ADR0330", "10124443866": "ADR0330",
    "10079099187": "ADR0327", "10081986019": "ADR0327", "10082440691": "ADR0327",
    "10069446931": "ADR0326", "9845676644": "ADR0326", "9924034454": "ADR0326",
    "9928325265": "ADR0326", "9951239210": "ADR0326", "9958532006": "ADR0326",
    "9958574502": "ADR0326", "9971564905": "ADR0326", "9973726406": "ADR0326",
    "9975524471": "ADR0326", "9975667979": "ADR0326", "9981717931": "ADR0326",
    "9983143614": "ADR0326", "9983282050": "ADR0326", "10040293103": "ADR0324",
    "10042564354": "ADR0324", "9988125363": "ADR0308",
}
REVISIONS_V2 = {**REVISIONS_V1, "9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e": "ADR0348"}
RUNS_V2 = {**RUNS_V1, "34831612221": "ADR0348"}
ARTIFACTS_V2 = dict(ARTIFACTS_V1)
REVISIONS_V3 = {**REVISIONS_V2,
                "5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c": "ADR0353",
                "4452a96acb1ad31ea8f6b242334f258ce0b0abab": "ADR0353"}
RUNS_V3 = {**RUNS_V2, "35562735335": "ADR0353", "35572729553": "ADR0353",
           "35573039122": "ADR0353"}
ARTIFACTS_V3 = {**ARTIFACTS_V2, "10622494382": "ADR0353", "10627325100": "ADR0353"}
REVISIONS_V4 = {**REVISIONS_V3,
                "d98571b9f2be446ed478464d23df532d91b94e53": "ADR0357",
                "431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33": "ADR0357",
                "17380562a9fb9f7d08bea0269a9fdc5812b1faf7": "ADR0357"}
RUNS_V4 = {**RUNS_V3, "35638724656": "ADR0357", "35670440520": "ADR0357",
           "35670986936": "ADR0357", "35684568600": "ADR0357",
           "35685410662": "ADR0357"}
ARTIFACTS_V4 = {**ARTIFACTS_V3,
                **{value: "ADR0357" for value in (
                    "10658466954", "10670334621", "10670965964", "10678755703",
                    "10677962970", "10678201915", "10678118928", "10677629335",
                    "10678169602", "10677874983")}}
REVISIONS_V5 = {**REVISIONS_V4, "306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c": "ADR0360", "21848f84f01d42f28ce2f6f2a177bfe62af8fc58": "ADR0360"}
RUNS_V5 = {**RUNS_V4, "35716917245": "ADR0360", "35732877526": "ADR0360", "35733919360": "ADR0360"}
ARTIFACTS_V5 = {**ARTIFACTS_V4, "10690851656": "ADR0360", "10696531175": "ADR0360"}
REVISIONS_V6 = {**REVISIONS_V5, **{value: "ADR0363" for value in ("2076c2bd781a663d2b27fa478792fc133fa9fd42", "1956ea8da439de2ae137e6ccbc5650ca149fe815", "4ffdeb435cc8cd053d47ab173b942ec0f99cd3b4")}}
RUNS_V6 = {**RUNS_V5, **{value: "ADR0363" for value in ("35795093115", "35810787971", "35811001315", "35822851712")}}
ARTIFACTS_V6 = {**ARTIFACTS_V5, **{value: "ADR0363" for value in ("10724846408", "10729183411", "10729578379")}}
REVISIONS = {**REVISIONS_V6, **{value: "ADR0364" for value in ("8e9328c66a1ab930583e22f07ba6f17f23bc7d2e", "f82c9e77acbd8cf1f963a46d73a9e70afb6f41d6", "6d2eff8ffa8fe525b5566a0ddded7d79e868ba16", "c075458cf2d853200df57584c1b16cf38bd6e38c", "f75d3f09990de4635cc3890efe0f5f6e783312bd")}}
RUNS = {**RUNS_V6, **{value: "ADR0364" for value in ("35928408355", "35938320143", "35938533499", "35946454149")}}
ARTIFACTS = {**ARTIFACTS_V6, **{value: "ADR0364" for value in ("10780807449", "10783357865", "10784336353")}}

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
    predecessor_v1, predecessor_v1_raw = document(POLICY_V1, 4096)
    require(hashlib.sha256(predecessor_v1_raw).hexdigest() == POLICY_V1_SHA256)
    require(predecessor_v1 == {"version": "cogs.stage2-retired-revisions/v1",
                               "revisions": REVISIONS_V1, "runs": RUNS_V1,
                               "artifacts": ARTIFACTS_V1})
    predecessor_v2, predecessor_v2_raw = document(POLICY_V2, 4096)
    require(hashlib.sha256(predecessor_v2_raw).hexdigest() == POLICY_V2_SHA256)
    require(predecessor_v2 == {"version": "cogs.stage2-retired-revisions/v2",
                               "predecessor": {"version": predecessor_v1["version"],
                                               "sha256": POLICY_V1_SHA256},
                               "revisions": REVISIONS_V2, "runs": RUNS_V2,
                               "artifacts": ARTIFACTS_V2})
    predecessor_v3, predecessor_v3_raw = document(POLICY_V3, 4096)
    require(hashlib.sha256(predecessor_v3_raw).hexdigest() == POLICY_V3_SHA256)
    require(predecessor_v3 == {"version": "cogs.stage2-retired-revisions/v3",
                               "predecessor": {"version": predecessor_v2["version"],
                                               "sha256": POLICY_V2_SHA256},
                               "revisions": REVISIONS_V3, "runs": RUNS_V3,
                               "artifacts": ARTIFACTS_V3})
    predecessor_v4, predecessor_v4_raw = document(POLICY_V4, 8192)
    require(hashlib.sha256(predecessor_v4_raw).hexdigest() == POLICY_V4_SHA256)
    require(predecessor_v4 == {"version": "cogs.stage2-retired-revisions/v4",
                               "predecessor": {"version": predecessor_v3["version"],
                                               "sha256": POLICY_V3_SHA256},
                               "revisions": REVISIONS_V4, "runs": RUNS_V4,
                               "artifacts": ARTIFACTS_V4})
    predecessor_v5, predecessor_v5_raw = document(POLICY_V5, 8192)
    require(hashlib.sha256(predecessor_v5_raw).hexdigest() == POLICY_V5_SHA256 and predecessor_v5 == {"version": "cogs.stage2-retired-revisions/v5", "predecessor": {"version": predecessor_v4["version"], "sha256": POLICY_V4_SHA256}, "revisions": REVISIONS_V5, "runs": RUNS_V5, "artifacts": ARTIFACTS_V5})
    predecessor_v6, predecessor_v6_raw = document(POLICY_V6, 16384)
    require(hashlib.sha256(predecessor_v6_raw).hexdigest() == POLICY_V6_SHA256 and predecessor_v6 == {"version": "cogs.stage2-retired-revisions/v6", "predecessor": {"version": predecessor_v5["version"], "sha256": POLICY_V5_SHA256}, "revisions": REVISIONS_V6, "runs": RUNS_V6, "artifacts": ARTIFACTS_V6})
    value, _raw = document(path, 16384)
    require(value == {"version": "cogs.stage2-retired-revisions/v7",
                      "predecessor": {"version": predecessor_v6["version"],
                                      "sha256": POLICY_V6_SHA256},
                      "revisions": REVISIONS, "runs": RUNS,
                      "artifacts": ARTIFACTS})
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

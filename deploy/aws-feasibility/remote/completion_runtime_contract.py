#!/usr/bin/env python3
"""Closed candidate and manually pinned workload contracts for ADR 0099."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path

from completion_fixtures import fixed_fixtures

REMOTE = Path(__file__).resolve().parent
ARTIFACTS_PATH = REMOTE / "stage2-completion-artifacts-v1.json"
ROOTFS_PATH = REMOTE / "stage2-completion-rootfs-v1.json"
CANDIDATE_PATH = REMOTE / "stage2-completion-runtime-candidate-v1.json"
FINAL_PATH = REMOTE / "stage2-completion-runtime-v1.json"
MAX_CONTRACT_BYTES = 8192
_HEX = frozenset("0123456789abcdef")


class WorkloadContractError(Exception):
    """A workload contract was absent, malformed, or did not match its fixed inputs."""


class FinalPinUnavailable(WorkloadContractError):
    """The generated package identity has not been manually pinned."""


@dataclass(frozen=True)
class PackageIdentity:
    deb_sha256: str
    deb_bytes: int
    installed_tree_sha256: str
    installed_entries: int
    installed_bytes: int
    package: str
    version: str
    architecture: str

    def value(self):
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True)
class CandidateContract:
    sha256: str
    value: dict


@dataclass(frozen=True)
class FinalPin:
    candidate_contract_sha256: str
    candidate_a: PackageIdentity
    candidate_b: PackageIdentity


def _require(condition, message="invalid workload contract"):
    if not condition:
        raise WorkloadContractError(message)


def _pairs(rows):
    value = {}
    for key, item in rows:
        if key in value:
            raise WorkloadContractError("duplicate JSON key")
        value[key] = item
    return value


def _read_regular(path, maximum=MAX_CONTRACT_BYTES):
    try:
        before = os.lstat(path)
        _require(os.path.isfile(path) and not os.path.islink(path), "contract is not a regular file")
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        after = os.lstat(path)
    except (OSError, ValueError) as error:
        raise WorkloadContractError("contract read failed") from error
    _require(0 < len(raw) <= maximum and b"\x00" not in raw, "contract size is invalid")
    first = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
    second = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
    _require(first == second and before.st_size == len(raw), "contract changed while read")
    return raw


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise WorkloadContractError("contract JSON is invalid") from error
    _require(type(value) is dict, "contract root is invalid")
    return value


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _exact_keys(value, keys):
    _require(type(value) is dict and len(value) == len(keys) and set(value) == set(keys), "contract keys are invalid")


def _expected_candidate():
    fixtures = fixed_fixtures()
    artifacts_raw = _read_regular(ARTIFACTS_PATH, 32768)
    rootfs_raw = _read_regular(ROOTFS_PATH)
    artifacts = _json(artifacts_raw)
    rootfs = _json(rootfs_raw)
    _require(artifacts.get("version") == "cogs.stage2-completion-artifacts/v1")
    _require(rootfs.get("version") == "cogs.stage2-completion-rootfs.v1")
    _require(artifacts.get("source_date_epoch") == 1782172800)
    _require(rootfs.get("source_date_epoch") == 1782172800)
    _require(rootfs.get("manifest") == {"sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691", "size": 1049443})
    _require(rootfs.get("ustar") == {"sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3", "size": 136905728})
    return {
        "version": "cogs.stage2-workload-candidate-contract/v1",
        "platform": {"os": "linux", "architecture": "amd64", "euid": 0},
        "source_date_epoch": 1782172800,
        "sample_count": 7,
        "bindings": {
            "artifacts_contract_sha256": _sha(artifacts_raw),
            "rootfs_contract_sha256": _sha(rootfs_raw),
            "rootfs_manifest_sha256": rootfs["manifest"]["sha256"],
            "rootfs_ustar_sha256": rootfs["ustar"]["sha256"],
            "git_fixture_sha256": fixtures.git.logical_digest,
            "git_archive_sha256": fixtures.git.source.ustar_sha256,
            "git_commit": fixtures.git.commit_oid,
            "package_source_sha256": fixtures.package.source.logical_digest,
            "package_archive_sha256": fixtures.package.source.ustar_sha256,
            "installed_tree_sha256": fixtures.package.installed.logical_digest,
        },
        "fixture": {
            "git": {"version": "cogs-stage2-git-v1", "files": 512, "lines_per_file": 128, "modified": 32, "untracked": 8},
            "package": {
                "name": fixtures.package.installed.package,
                "version": fixtures.package.installed.version,
                "architecture": fixtures.package.installed.architecture,
                "files": 256,
                "file_bytes": 4096,
                "installed_entries": fixtures.package.installed.entry_count,
                "installed_bytes": fixtures.package.installed.regular_bytes,
            },
        },
    }


def load_candidate_contract():
    """Load the one fixed input-only contract; no generated package value is present."""
    raw = _read_regular(CANDIDATE_PATH)
    value = _json(raw)
    expected = _expected_candidate()
    observed_canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    expected_canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)
    _require(observed_canonical == expected_canonical, "candidate contract drift")
    return CandidateContract(_sha(raw), value)


def _identity(value):
    fields = tuple(PackageIdentity.__dataclass_fields__)
    _exact_keys(value, fields)
    identity = PackageIdentity(*(value[field] for field in fields))
    _require(type(identity.deb_sha256) is str and len(identity.deb_sha256) == 64 and set(identity.deb_sha256) <= _HEX)
    _require(type(identity.deb_bytes) is int and 0 < identity.deb_bytes <= 4_194_304)
    _require(
        type(identity.installed_tree_sha256) is str
        and len(identity.installed_tree_sha256) == 64
        and set(identity.installed_tree_sha256) <= _HEX
    )
    _require(type(identity.installed_entries) is int and identity.installed_entries == 259)
    _require(type(identity.installed_bytes) is int and identity.installed_bytes == 1_048_576)
    _require((identity.package, identity.version, identity.architecture) == ("cogs-stage2-fixture", "1.0", "all"))
    expected = load_candidate_contract().value["bindings"]["installed_tree_sha256"]
    _require(identity.installed_tree_sha256 == expected)
    return identity


def load_final_pin():
    """Load a human-committed A=B pin. Absence intentionally leaves qualification closed."""
    if not FINAL_PATH.exists():
        raise FinalPinUnavailable("manual final workload pin is unavailable")
    value = _json(_read_regular(FINAL_PATH))
    _exact_keys(value, ("version", "candidate_contract_sha256", "candidate_a", "candidate_b", "promotion"))
    _require(value["version"] == "cogs.stage2-workload-final-pin/v1")
    _require(value["promotion"] == "manual-reviewed-a-equals-b")
    contract = load_candidate_contract()
    _require(value["candidate_contract_sha256"] == contract.sha256)
    first = _identity(value["candidate_a"])
    second = _identity(value["candidate_b"])
    _require(first == second, "manual pin candidates differ")
    return FinalPin(contract.sha256, first, second)

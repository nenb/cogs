#!/usr/bin/env python3
"""Exact non-authoritative host workload contracts retained by ADR 0099."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from completion_fixtures import fixed_fixtures

REMOTE = Path(__file__).resolve().parent
ARTIFACTS_PATH = REMOTE / "stage2-completion-artifacts-v1.json"
ROOTFS_PATH = REMOTE / "stage2-completion-rootfs-v1.json"
CANDIDATE_PATH = REMOTE / "stage2-completion-runtime-candidate-v1.json"
FINAL_PATH = REMOTE / "stage2-completion-runtime-v1.json"
MAX_CONTRACT_BYTES = 32_768
REVIEWED_ARTIFACTS_SHA256 = "fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341"
REVIEWED_ROOTFS_SHA256 = "caf9082f56625dc3f55a41ad115c7c700e84a1198e60c0cd9be420d7c13b4d54"
REVIEWED_CANDIDATE_SHA256 = "b8660b92d778e9f5dc89586df4f68a2e2b12cdce818ff4fe12adf0a8e951fdf3"
# A later exact review must replace None with the digest of the canonical committed pin.
# Merely creating FINAL_PATH can never open this gate.
REVIEWED_FINAL_PIN_SHA256 = None
_HEX = frozenset("0123456789abcdef")

# Filled with exact raw source digests after this correction is complete. These bind the
# portable host implementation, not a checkout, kernel, libc, loader, or Linux tool closure.
REVIEWED_SOURCE_DIGESTS = {
    "fixture_implementation_sha256": "c877bdbbce0f1c7920294f5a240aa8b83c81dd96ce3c4daab650a9fbadc7f9f4",
    "workload_implementation_sha256": "451ddb9e65998c3599c534188eb5bbb6270cd0c899cc9dbd2a43106010661797",
    "orchestrator_implementation_sha256": "75abc89837833084c2dec1b5d7be1f546261997475a7e73a14a6bede8511dc77",
}


class WorkloadContractError(Exception):
    """A contract failed a categorical, non-path-bearing check."""


class FinalPinUnavailable(WorkloadContractError):
    """No exact externally reviewed final-pin byte object is authorized."""


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
    final_pin_sha256: str
    package_identity: PackageIdentity

    @property
    def candidate_a(self):
        return self.package_identity

    @property
    def candidate_b(self):
        return self.package_identity


@dataclass(frozen=True)
class OpenRegular:
    descriptor: int
    status: os.stat_result
    parent_descriptor: int
    name: str

    def close(self):
        os.close(self.descriptor)
        os.close(self.parent_descriptor)


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


def _status_identity(status):
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _open_absolute_directory(path):
    """Open every absolute path component without following a symlink."""
    absolute = Path(path)
    _require(absolute.is_absolute(), "directory path is not absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            status = os.fstat(next_descriptor)
            _require(stat.S_ISDIR(status.st_mode), "directory identity is invalid")
            # Writable traversal is accepted only for the root-owned sticky temporary root.
            writable = stat.S_IMODE(status.st_mode) & 0o022
            sticky_temporary = status.st_uid == 0 and stat.S_IMODE(status.st_mode) & stat.S_ISVTX
            _require(not writable or sticky_temporary, "directory ownership is untrusted")
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular(path, maximum=MAX_CONTRACT_BYTES, executable=False):
    absolute = Path(path)
    _require(absolute.is_absolute() and absolute.name not in {"", ".", ".."}, "file path is invalid")
    parent = _open_absolute_directory(absolute.parent)
    descriptor = -1
    try:
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        status = os.fstat(descriptor)
        parent_status = os.fstat(parent)
        _require(stat.S_ISREG(status.st_mode), "file type is invalid")
        _require(status.st_nlink == 1, "file link count is invalid")
        _require(status.st_uid == parent_status.st_uid, "file owner is invalid")
        _require(not stat.S_IMODE(status.st_mode) & 0o022, "file mode is writable")
        _require(0 <= status.st_size <= maximum, "file size is invalid")
        if executable:
            _require(stat.S_IMODE(status.st_mode) & 0o111, "tool is not executable")
        current = os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
        _require(_status_identity(current) == _status_identity(status), "file generation changed")
        return OpenRegular(descriptor, status, parent, absolute.name)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
        raise


def _read_open_regular(opened, maximum):
    before = os.fstat(opened.descriptor)
    _require(_status_identity(before) == _status_identity(opened.status), "file generation changed")
    os.lseek(opened.descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(opened.descriptor, min(remaining, 65_536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(opened.descriptor)
    current = os.stat(opened.name, dir_fd=opened.parent_descriptor, follow_symlinks=False)
    expected = _status_identity(opened.status)
    _require(_status_identity(before) == expected == _status_identity(after) == _status_identity(current), "file changed")
    _require(len(raw) == opened.status.st_size and len(raw) <= maximum, "file read is incomplete")
    return raw


def _read_regular(path, maximum=MAX_CONTRACT_BYTES):
    try:
        opened = _open_regular(path, maximum)
        try:
            raw = _read_open_regular(opened, maximum)
        finally:
            opened.close()
    except WorkloadContractError:
        raise
    except OSError as error:
        raise WorkloadContractError("contract read failed") from error
    _require(0 < len(raw) <= maximum and b"\x00" not in raw, "contract size is invalid")
    return raw


def _json(raw):
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise WorkloadContractError("contract JSON is invalid") from error
    _require(type(value) is dict, "contract root is invalid")
    return value


def canonical_json(value):
    """Return the sole canonical producer encoding: ASCII, sorted, compact, one LF."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise WorkloadContractError("canonical JSON encoding failed") from error


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _exact_keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys) and len(value) == len(keys), "contract keys are invalid")


def _expected_candidate(artifacts_raw, rootfs_raw):
    fixtures = fixed_fixtures()
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
            "artifacts_contract_sha256": REVIEWED_ARTIFACTS_SHA256,
            "rootfs_contract_sha256": REVIEWED_ROOTFS_SHA256,
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


def _verify_source_bindings():
    paths = {
        "fixture_implementation_sha256": REMOTE / "completion_fixtures.py",
        "workload_implementation_sha256": REMOTE / "completion_guest_workloads.py",
        "orchestrator_implementation_sha256": REMOTE / "completion_package_candidate.py",
    }
    for name, path in paths.items():
        _require(_sha(_read_regular(path, 131_072)) == REVIEWED_SOURCE_DIGESTS[name], "reviewed host source changed")


def execution_binding(tool_observations):
    return {
        **REVIEWED_SOURCE_DIGESTS,
        "tool_observations": tool_observations,
        "contract_validator": "unbound-self-referential-host-validator",
        "source_checkout": "unbound-current-checkout",
        "linux_dynamic_tool_closure": "unbound-kernel-libc-loader-libraries-config-helpers",
        "rootfs_execution": "not-used-by-host-candidate-or-reproduction",
    }


def load_candidate_contract():
    """Load only the exact reviewed input bytes; semantic reformatting is rejected."""
    artifacts_raw = _read_regular(ARTIFACTS_PATH)
    rootfs_raw = _read_regular(ROOTFS_PATH)
    raw = _read_regular(CANDIDATE_PATH)
    _require(_sha(artifacts_raw) == REVIEWED_ARTIFACTS_SHA256, "artifact contract digest differs")
    _require(_sha(rootfs_raw) == REVIEWED_ROOTFS_SHA256, "rootfs contract digest differs")
    _require(_sha(raw) == REVIEWED_CANDIDATE_SHA256, "candidate bytes are not the reviewed canonical object")
    value = _json(raw)
    _require(value == _expected_candidate(artifacts_raw, rootfs_raw), "candidate contract drift")
    _verify_source_bindings()
    return CandidateContract(REVIEWED_CANDIDATE_SHA256, value)


def parse_identity(value):
    fields = tuple(PackageIdentity.__dataclass_fields__)
    _exact_keys(value, fields)
    identity = PackageIdentity(*(value[field] for field in fields))
    _require(type(identity.deb_sha256) is str and len(identity.deb_sha256) == 64 and set(identity.deb_sha256) <= _HEX)
    _require(type(identity.deb_bytes) is int and not isinstance(identity.deb_bytes, bool) and 0 < identity.deb_bytes <= 4_194_304)
    _require(type(identity.installed_tree_sha256) is str and len(identity.installed_tree_sha256) == 64 and set(identity.installed_tree_sha256) <= _HEX)
    _require(type(identity.installed_entries) is int and not isinstance(identity.installed_entries, bool) and identity.installed_entries == 259)
    _require(type(identity.installed_bytes) is int and not isinstance(identity.installed_bytes, bool) and identity.installed_bytes == 1_048_576)
    _require((identity.package, identity.version, identity.architecture) == ("cogs-stage2-fixture", "1.0", "all"))
    _require(identity.installed_tree_sha256 == "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2")
    return identity


def validate_final_value(value):
    """Use one package identity, making contradictory A/B unrepresentable."""
    _exact_keys(value, ("version", "candidate_contract_sha256", "package_identity", "reproductions", "promotion"))
    _require(value["version"] == "cogs.stage2-workload-final-pin/v1")
    _require(value["candidate_contract_sha256"] == REVIEWED_CANDIDATE_SHA256)
    _require(value["reproductions"] == ["A", "B"])
    _require(value["promotion"] == "manual-reviewed-a-equals-b")
    return parse_identity(value["package_identity"])


def load_final_pin():
    """Load only a canonical pin whose raw digest was added by a later exact review."""
    if REVIEWED_FINAL_PIN_SHA256 is None:
        raise FinalPinUnavailable("reviewed final pin is unavailable")
    _require(type(REVIEWED_FINAL_PIN_SHA256) is str and len(REVIEWED_FINAL_PIN_SHA256) == 64)
    try:
        raw = _read_regular(FINAL_PATH)
    except WorkloadContractError as error:
        raise FinalPinUnavailable("reviewed final pin is unavailable") from error
    _require(_sha(raw) == REVIEWED_FINAL_PIN_SHA256, "final pin digest differs")
    value = _json(raw)
    _require(raw == canonical_json(value), "final pin bytes are not canonical")
    contract = load_candidate_contract()
    identity = validate_final_value(value)
    _require(value["candidate_contract_sha256"] == contract.sha256)
    return FinalPin(contract.sha256, REVIEWED_FINAL_PIN_SHA256, identity)


def _validate_observation(value):
    _exact_keys(value, ("name", "sha256", "bytes", "version"))
    _require(value["name"] in {"git", "dpkg-deb", "dpkg"})
    _require(type(value["sha256"]) is str and len(value["sha256"]) == 64 and set(value["sha256"]) <= _HEX)
    _require(type(value["bytes"]) is int and not isinstance(value["bytes"], bool) and value["bytes"] > 0)
    _require(type(value["version"]) is str and 0 < len(value["version"]) <= 160)


def _validate_execution(value):
    keys = (*REVIEWED_SOURCE_DIGESTS, "tool_observations", "contract_validator", "source_checkout", "linux_dynamic_tool_closure", "rootfs_execution")
    _exact_keys(value, keys)
    for name, digest in REVIEWED_SOURCE_DIGESTS.items():
        _require(value[name] == digest)
    _require(type(value["tool_observations"]) is list and len(value["tool_observations"]) == 3)
    for row in value["tool_observations"]:
        _validate_observation(row)
    _require([row["name"] for row in value["tool_observations"]] == ["git", "dpkg-deb", "dpkg"])
    _require(value["contract_validator"] == "unbound-self-referential-host-validator")
    _require(value["source_checkout"] == "unbound-current-checkout")
    _require(value["linux_dynamic_tool_closure"] == "unbound-kernel-libc-loader-libraries-config-helpers")
    _require(value["rootfs_execution"] == "not-used-by-host-candidate-or-reproduction")


def validate_candidate_result(value):
    keys = ("version", "result", "authority", "candidate_contract_sha256", "final_pin_sha256", "package_identity", "reproductions", "a_equals_b", "lifecycle_deleted", "promotion", "execution_binding")
    _exact_keys(value, keys)
    _require(value["version"] == "cogs.stage2-workload-candidate/v1")
    _require(value["result"] == "pass" and value["authority"] == "non-authoritative-host-candidate-only")
    _require(value["candidate_contract_sha256"] == REVIEWED_CANDIDATE_SHA256 and value["final_pin_sha256"] is None)
    parse_identity(value["package_identity"])
    _require(value["reproductions"] == [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}])
    _require(value["a_equals_b"] is True and value["lifecycle_deleted"] is True and value["promotion"] == "external-manual-review-required")
    _validate_execution(value["execution_binding"])
    return value


def validate_post_pin_result(value, final=None):
    keys = ("version", "result", "authority", "candidate_contract_sha256", "final_pin_sha256", "package_identity", "reproductions", "matches_final_pin", "lifecycle_deleted", "execution_binding")
    _exact_keys(value, keys)
    _require(value["version"] == "cogs.stage2-workload-post-pin/v1")
    _require(value["result"] == "pass" and value["authority"] == "non-authoritative-host-reproduction-only")
    _require(value["candidate_contract_sha256"] == REVIEWED_CANDIDATE_SHA256)
    _require(type(value["final_pin_sha256"]) is str and len(value["final_pin_sha256"]) == 64 and set(value["final_pin_sha256"]) <= _HEX)
    identity = parse_identity(value["package_identity"])
    _require(value["reproductions"] == [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}])
    _require(value["matches_final_pin"] is True and value["lifecycle_deleted"] is True)
    _validate_execution(value["execution_binding"])
    if final is not None:
        _require(value["candidate_contract_sha256"] == final.candidate_contract_sha256)
        _require(value["final_pin_sha256"] == final.final_pin_sha256)
        _require(identity == final.package_identity)
    return value

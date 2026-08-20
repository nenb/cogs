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
RUNTIME_CLOSURE_MANIFEST_SHA256 = "4c11dee4e0cba15c7a4bf7ef76937796abbdebf7a93b395ef47b14659a50b850"
RUNTIME_CLOSURE_OBJECT_COUNT = 35
EXACT_TOOL_OBSERVATIONS = (
    {
        "name": "git",
        "sha256": "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60",
        "bytes": 4_082_768,
        "version": "git version 2.47.3",
    },
    {
        "name": "dpkg-deb",
        "sha256": "5346e5fdfdc81d58bbc9d2a3de20ff3738dc479cdb04cc52b91503cbb13440eb",
        "bytes": 182_816,
        "version": "Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64).",
    },
    {
        "name": "dpkg",
        "sha256": "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
        "bytes": 326_704,
        "version": "Debian 'dpkg' package management program version 1.22.22 (amd64).",
    },
)
_HEX = frozenset("0123456789abcdef")

# Filled with exact raw source digests after this correction is complete. These bind the
# portable host implementation, not a checkout, kernel, libc, loader, or Linux tool closure.
REVIEWED_SOURCE_DIGESTS = {
    "fixture_implementation_sha256": "c877bdbbce0f1c7920294f5a240aa8b83c81dd96ce3c4daab650a9fbadc7f9f4",
    "workload_implementation_sha256": "c856bb997e1d799c712cf08b48c2fb3de314b8e0efe8985908a5b58d08b3c850",
    "owner_implementation_sha256": "498407f393924ab472d3f014a3c2e54257e0b38f6b0783f24fcf35e820b31796",
    "orchestrator_implementation_sha256": "8341389e56e16e82bb6c477a9181c57d90af59e97e7e03b0cbd9c9a0e4774ce1",
    "candidate_recovery_implementation_sha256": "1408a9b51b9e5a241a731ac2f453ee28ff1f44f8e92d4111cd9a4100010522e5",
    "post_pin_recovery_implementation_sha256": "1bae8dbde70ea7c0465dbb808a9d85205d88cdf03302f389128a25884ec2c060",
}

# V2 authenticates the code that actually produces and validates V2.  Its
# schema is the separate reviewed byte object that can pin this module's exact
# digest without creating an impossible self-referential source constant.
NATIVE_LAUNCHER_SHA256 = "986b744a17e89104e7afe5a10131aa2f3ad4e5795d56de226279124798a1f192"
_NATIVE_IMPLEMENTATION_DIGESTS = None


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
class RuntimeClosurePin:
    manifest_sha256: str
    object_count: int
    tools: tuple[dict, ...]

    def value(self):
        return {
            "version": "cogs.stage2-runtime-tool-closure/v1",
            "manifest_sha256": self.manifest_sha256,
            "object_count": self.object_count,
            "tools": [dict(row) for row in self.tools],
        }


@dataclass(frozen=True)
class FinalPin:
    candidate_contract_sha256: str
    candidate_result_sha256: str
    final_pin_sha256: str
    package_identity: PackageIdentity
    runtime_closure: RuntimeClosurePin

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


def native_implementation_digests():
    """Load V2's reviewed constants and prove they name the available exact bytes."""
    global _NATIVE_IMPLEMENTATION_DIGESTS
    if _NATIVE_IMPLEMENTATION_DIGESTS is None:
        schema_path = REMOTE.parents[2] / "schemas/stage2-workload-candidate-v2.json"
        schema = _json(_read_regular(schema_path, 131_072))
        try:
            properties = schema["$defs"]["executionBinding"]["properties"]
            names = (
                "fixture_implementation_sha256", "workload_implementation_sha256",
                "owner_implementation_sha256", "native_producer_implementation_sha256",
                "runtime_codec_implementation_sha256", "launcher_implementation_sha256",
            )
            reviewed = {name: properties[name]["const"] for name in names}
        except (KeyError, TypeError) as error:
            raise WorkloadContractError("native schema bindings are invalid") from error
        observed = {
            "fixture_implementation_sha256": _sha(_read_regular(
                REMOTE / "completion_fixtures.py", 131_072)),
            "workload_implementation_sha256": _sha(_read_regular(
                REMOTE / "completion_guest_workloads.py", 131_072)),
            "owner_implementation_sha256": _sha(_read_regular(
                REMOTE / "completion_workload_owner.py", 131_072)),
            "native_producer_implementation_sha256": _sha(_read_regular(
                REMOTE / "completion_package_native_candidate.py", 131_072)),
            "runtime_codec_implementation_sha256": _sha(_read_regular(Path(__file__), 131_072)),
            "launcher_implementation_sha256": _sha(_read_regular(
                REMOTE.parents[2] / "scripts/run-stage2-package-native-candidate.py", 262_144)),
        }
        _require(reviewed == observed, "reviewed native implementation changed")
        _require(reviewed["launcher_implementation_sha256"] == NATIVE_LAUNCHER_SHA256)
        _NATIVE_IMPLEMENTATION_DIGESTS = reviewed
    return dict(_NATIVE_IMPLEMENTATION_DIGESTS)


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
        "owner_implementation_sha256": REMOTE / "completion_workload_owner.py",
        "orchestrator_implementation_sha256": REMOTE / "completion_package_candidate.py",
        "candidate_recovery_implementation_sha256": REMOTE / "completion_package_candidate_recovery.py",
        "post_pin_recovery_implementation_sha256": REMOTE / "completion_package_post_pin_recovery.py",
    }
    for name, path in paths.items():
        _require(_sha(_read_regular(path, 131_072)) == REVIEWED_SOURCE_DIGESTS[name], "reviewed host source changed")


def exact_runtime_closure():
    """Recompute the exact Git/dpkg ELF closure from all 16 authenticated bytes."""
    try:
        from completion_rootfs_plan import load_verified_build_inputs
        from completion_runtime_closure import fixed_runtime_closure

        closure = fixed_runtime_closure(load_verified_build_inputs())
    except Exception as error:
        # Collapse parser, cache, and platform details at this production boundary.
        raise WorkloadContractError("exact runtime closure is unavailable") from error
    _require(closure.manifest_sha256 == RUNTIME_CLOSURE_MANIFEST_SHA256)
    _require(closure.object_count == len(closure.records) == RUNTIME_CLOSURE_OBJECT_COUNT)
    records = {record.path: record for record in closure.records}
    expected_paths = {"git": "usr/bin/git", "dpkg-deb": "usr/bin/dpkg-deb", "dpkg": "usr/bin/dpkg"}
    for expected in EXACT_TOOL_OBSERVATIONS:
        record = records.get(expected_paths[expected["name"]])
        _require(record is not None)
        _require((record.content_sha256, record.size) == (expected["sha256"], expected["bytes"]))
        _require(record.interpreter == "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    return RuntimeClosurePin(
        RUNTIME_CLOSURE_MANIFEST_SHA256,
        RUNTIME_CLOSURE_OBJECT_COUNT,
        tuple(dict(row) for row in EXACT_TOOL_OBSERVATIONS),
    )


def execution_binding(tool_observations, runtime_closure):
    _require(type(runtime_closure) is RuntimeClosurePin)
    return {
        **REVIEWED_SOURCE_DIGESTS,
        "tool_observations": tool_observations,
        "runtime_closure": runtime_closure.value(),
        "contract_validator": "unbound-self-referential-host-validator",
        "source_checkout": "unbound-current-checkout",
        "linux_dynamic_tool_closure": "exact-static-elf-closure-runtime-mapping-attestation-required",
        "process_containment": "linux-subreaper-pidfd-or-start-time-no-cgroup-v2",
        "process_containment_limitation": "no-cgroup-proof-honest-supervisor-crash-only-not-hostile-process-closure",
        "operation_parent_isolation": "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp",
        "rootfs_execution": "not-used-by-host-candidate-or-reproduction",
    }


def _validate_native_source_identity(source_revision, source_manifest_sha256):
    _require(type(source_revision) is str and len(source_revision) == 40
             and set(source_revision) <= _HEX, "fixed-source revision is invalid")
    _require(type(source_manifest_sha256) is str and len(source_manifest_sha256) == 64
             and set(source_manifest_sha256) <= _HEX, "fixed-source manifest is invalid")
    available_heads = {
        value for name in ("COGS_PACKAGE_REVIEWED_HEAD", "EXACT_REVIEWED_HEAD")
        if (value := os.environ.get(name))
    }
    _require(len(available_heads) <= 1, "reviewed source revisions conflict")
    if available_heads:
        _require(source_revision == next(iter(available_heads)), "reviewed source revision differs")


def native_execution_binding(tool_observations, runtime_closure, launcher_sha256,
                             source_revision, source_manifest_sha256):
    """Bind V2 to the exact fixed-source producer, codec, launcher, and source approval."""
    _require(type(runtime_closure) is RuntimeClosurePin)
    _require(launcher_sha256 == NATIVE_LAUNCHER_SHA256, "native launcher identity differs")
    _validate_native_source_identity(source_revision, source_manifest_sha256)
    return {
        **native_implementation_digests(),
        "source_revision": source_revision,
        "source_manifest_sha256": source_manifest_sha256,
        "tool_observations": tool_observations,
        "runtime_closure": runtime_closure.value(),
        "contract_validator": "exact-fixed-source-native-v2-codec",
        "source_checkout": "manifest-verified-reviewed-revision-loaded-before-chroot",
        "linux_dynamic_tool_closure": "exact-static-elf-closure-executed-from-retained-rootfs",
        "process_containment": "parent-gated-fork-helper-newns-newpid-newnet-fork-pid1-dual-pidfd-v1",
        "process_containment_limitation": "trusted-initial-user-namespace-root-no-hostile-root-security-boundary",
        "operation_parent_isolation": "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp",
        "rootfs_execution": "detached-recursive-read-only-retained-stage2-rootfs-fresh-proc-dev-tmp",
        "retained_root_lifecycle": "output-after-pid1-and-helper-settlement-and-retained-root-removal",
    }


def load_candidate_contract():
    """Load only the exact reviewed input bytes; semantic reformatting is rejected."""
    artifacts_raw = _read_regular(ARTIFACTS_PATH)
    rootfs_raw = _read_regular(ROOTFS_PATH)
    raw = _read_regular(CANDIDATE_PATH)
    _require(_sha(artifacts_raw) == REVIEWED_ARTIFACTS_SHA256, "artifact contract digest differs")
    _require(_sha(rootfs_raw) == REVIEWED_ROOTFS_SHA256, "rootfs contract digest differs")
    _require(_sha(raw) == REVIEWED_CANDIDATE_SHA256, "candidate bytes are not the exact reviewed byte object")
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


def _runtime_closure_value(value):
    expected = RuntimeClosurePin(
        RUNTIME_CLOSURE_MANIFEST_SHA256,
        RUNTIME_CLOSURE_OBJECT_COUNT,
        tuple(dict(row) for row in EXACT_TOOL_OBSERVATIONS),
    )
    _require(value == expected.value(), "runtime closure pin differs")
    return expected


def validate_final_value(value):
    """Use one package identity and one exact runtime closure."""
    _exact_keys(value, ("version", "candidate_contract_sha256", "candidate_result_sha256", "runtime_closure", "package_identity", "reproductions", "promotion"))
    _require(value["version"] == "cogs.stage2-workload-final-pin/v1")
    _require(value["candidate_contract_sha256"] == REVIEWED_CANDIDATE_SHA256)
    _require(type(value["candidate_result_sha256"]) is str and len(value["candidate_result_sha256"]) == 64)
    _require(set(value["candidate_result_sha256"]) <= _HEX)
    _require(value["reproductions"] == ["A", "B"])
    _require(value["promotion"] == "manual-reviewed-a-equals-b")
    return parse_identity(value["package_identity"]), _runtime_closure_value(value["runtime_closure"])


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
    identity, pinned_closure = validate_final_value(value)
    _require(value["candidate_contract_sha256"] == contract.sha256)
    observed_closure = exact_runtime_closure()
    _require(observed_closure == pinned_closure, "runtime closure bytes differ")
    return FinalPin(
        contract.sha256,
        value["candidate_result_sha256"],
        REVIEWED_FINAL_PIN_SHA256,
        identity,
        observed_closure,
    )


def _validate_observation(value):
    _exact_keys(value, ("name", "sha256", "bytes", "version"))
    _require(type(value["sha256"]) is str and len(value["sha256"]) == 64 and set(value["sha256"]) <= _HEX)
    _require(type(value["bytes"]) is int and not isinstance(value["bytes"], bool) and value["bytes"] > 0)
    _require(type(value["version"]) is str and 0 < len(value["version"]) <= 160)
    expected = next((row for row in EXACT_TOOL_OBSERVATIONS if row["name"] == value["name"]), None)
    _require(value == expected, "tool identity or version differs")


def exact_tool_observations(value):
    _require(type(value) is list and len(value) == 3)
    for row in value:
        _validate_observation(row)
    expected = [dict(row) for row in EXACT_TOOL_OBSERVATIONS]
    _require(value == expected, "tool observation order differs")
    return expected


def _validate_execution(value):
    keys = (*REVIEWED_SOURCE_DIGESTS, "tool_observations", "runtime_closure", "contract_validator", "source_checkout", "linux_dynamic_tool_closure", "process_containment", "process_containment_limitation", "operation_parent_isolation", "rootfs_execution")
    _exact_keys(value, keys)
    for name, digest in REVIEWED_SOURCE_DIGESTS.items():
        _require(value[name] == digest)
    exact_tool_observations(value["tool_observations"])
    _runtime_closure_value(value["runtime_closure"])
    _require(value["contract_validator"] == "unbound-self-referential-host-validator")
    _require(value["source_checkout"] == "unbound-current-checkout")
    _require(value["linux_dynamic_tool_closure"] == "exact-static-elf-closure-runtime-mapping-attestation-required")
    _require(value["process_containment"] == "linux-subreaper-pidfd-or-start-time-no-cgroup-v2")
    _require(value["process_containment_limitation"] == "no-cgroup-proof-honest-supervisor-crash-only-not-hostile-process-closure")
    _require(value["operation_parent_isolation"] == "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp")
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


def _validate_native_execution(value):
    implementation_digests = native_implementation_digests()
    keys = (
        *implementation_digests, "source_revision", "source_manifest_sha256",
        "tool_observations", "runtime_closure", "contract_validator", "source_checkout",
        "linux_dynamic_tool_closure", "process_containment", "process_containment_limitation",
        "operation_parent_isolation", "rootfs_execution", "retained_root_lifecycle",
    )
    _exact_keys(value, keys)
    for name, digest in implementation_digests.items():
        _require(value[name] == digest, "native implementation identity differs")
    _validate_native_source_identity(value["source_revision"], value["source_manifest_sha256"])
    exact_tool_observations(value["tool_observations"])
    _runtime_closure_value(value["runtime_closure"])
    _require(value["contract_validator"] == "exact-fixed-source-native-v2-codec")
    _require(value["source_checkout"] == "manifest-verified-reviewed-revision-loaded-before-chroot")
    _require(value["linux_dynamic_tool_closure"] == "exact-static-elf-closure-executed-from-retained-rootfs")
    _require(value["process_containment"] == "parent-gated-fork-helper-newns-newpid-newnet-fork-pid1-dual-pidfd-v1")
    _require(value["process_containment_limitation"] == "trusted-initial-user-namespace-root-no-hostile-root-security-boundary")
    _require(value["operation_parent_isolation"] == "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp")
    _require(value["rootfs_execution"] == "detached-recursive-read-only-retained-stage2-rootfs-fresh-proc-dev-tmp")
    _require(value["retained_root_lifecycle"]
             == "output-after-pid1-and-helper-settlement-and-retained-root-removal")


def validate_native_candidate_result(value):
    """Validate V2 without changing the historical V1 candidate contract."""
    keys = ("version", "result", "authority", "candidate_contract_sha256", "final_pin_sha256", "package_identity", "reproductions", "a_equals_b", "lifecycle_deleted", "promotion", "execution_binding")
    _exact_keys(value, keys)
    _require(value["version"] == "cogs.stage2-workload-candidate/v2")
    _require(value["result"] == "pass"
             and value["authority"] == "non-authoritative-retained-rootfs-candidate-only")
    _require(value["candidate_contract_sha256"] == REVIEWED_CANDIDATE_SHA256
             and value["final_pin_sha256"] is None)
    parse_identity(value["package_identity"])
    _require(value["reproductions"] == [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}])
    _require(value["a_equals_b"] is True and value["lifecycle_deleted"] is True
             and value["promotion"] == "external-manual-review-required")
    _validate_native_execution(value["execution_binding"])
    return value


def validate_post_pin_result(value, final):
    _require(type(final) is FinalPin)
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
    _require(value["candidate_contract_sha256"] == final.candidate_contract_sha256)
    _require(value["final_pin_sha256"] == final.final_pin_sha256)
    _require(identity == final.package_identity)
    return value

#!/usr/bin/env python3
"""Static Stage 2 control codecs and deterministic no-KVM observation producer.

The producer describes implementation revision H.  Its output is reviewed and
committed later as control revision G under a source-external control root.
These public bytes are comparison data: they cannot grant execution or KVM.
"""

from dataclasses import asdict, dataclass
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import stat
import struct
import subprocess
import sys
import tarfile

# Isolated-mode execution omits the script directory. The fixed-source caller
# has already authenticated this root, so sibling owner imports use only this
# exact resolved directory.
_REMOTE_MODULE_ROOT = Path(__file__).resolve().parent
if not _REMOTE_MODULE_ROOT.is_dir():
    raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_REMOTE_MODULE_ROOT))

import completion_guest_workloads_v3 as final_guest

CONTROL_VERSION = "cogs.stage2-local-static-control-package/v1"
ENVELOPE_VERSION = "cogs.stage2-local-execution-envelope/v2"
RUNTIME_VERSION = "cogs.stage2-local-runtime-manifest/v2"
CONTRACT_VERSION = "cogs.stage2-local-executable-closure/v1"
AUTHORITY = "non-authoritative-reviewed-static-control-data"
SOURCE_ROOT = Path("/var/lib/cogs/stage2-completion-v1/source")
CONTROL_ROOT = Path("/var/lib/cogs/stage2-completion-v1/control")
OBSERVATION_ROOT = Path("/var/lib/cogs/stage2-completion-v1/control-observation-v1")
SOURCE_MANIFEST = ".cogs-stage2-source-manifest-v1.json"
CONTROL_MEMBER = "stage2-local-static-control-v1.json"
ENVELOPE_MEMBER = "stage2-local-execution-envelope-v2.json"
RUNTIME_MEMBER = "stage2-local-runtime-manifest-v2.json"
MAX_CONTROL_BYTES = 256 * 1024
MAX_ENVELOPE_BYTES = 512 * 1024
MAX_RUNTIME_BYTES = 32 * 1024 * 1024
_OBSERVATION_STAGE = "entry"
_OBSERVATION_STAGES = frozenset({
    "entry", "source-manifest", "preparation-receipt", "runtime-closure",
    "launch-assets", "executable-contracts", "control-bytes", "publication",
})
MAX_CONTRACT_BYTES = 512 * 1024
MAX_SOURCE_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
HEX = frozenset("0123456789abcdef")
KATA_BASE_CONFIGURATION_PATH = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"
KATA_BASE_CONFIGURATION_SIZE = 32_218
KATA_BASE_CONFIGURATION_SHA256 = "7ecd072a35da55f5abc76d604a610cf3f2d543c7de0cefc4d1a81028facd2cae"
KATA_ACTIVE_CONFIGURATION_PATH = str(
    SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/configuration-qemu-observer.toml")
KATA_CONFIGURATION_SUBSTITUTIONS = (
    (b"enable_debug = false", b"enable_debug = true"),
    (b'extra_monitor_socket = ""', b'extra_monitor_socket = "qmp"'),
)
KATA_PRIVATE_QMP_SOCKET = "/run/vc/vm/cogs-stage2-ssh-v1/qmp.sock"
KATA_OBSERVER_QMP_SOCKET = "/run/vc/vm/cogs-stage2-ssh-v1/extra-monitor.sock"

EXECUTABLES = (
    ("ip", "host-path", "/usr/sbin/ip"),
    ("tc", "host-path", "/usr/sbin/tc"),
    ("nft", "host-path", "/usr/sbin/nft"),
    ("ssh", "host-path", "/usr/bin/ssh"),
    ("ssh-keygen", "host-path", "/usr/bin/ssh-keygen"),
    ("containerd", "staged-runtime", str(SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/containerd")),
    ("ctr", "staged-runtime", str(SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/ctr")),
    ("shim", "kata-runtime", "/opt/kata/bin/containerd-shim-kata-v2"),
    ("qemu", "kata-runtime", "/opt/kata/bin/qemu-system-x86_64"),
    ("virtiofsd", "kata-runtime", "/opt/kata/libexec/virtiofsd"),
)

ARCHIVES = (
    {
        "role": "kata",
        "version": "3.32.0",
        "name": "kata-static-3.32.0-amd64.tar.zst",
        "url": "https://github.com/kata-containers/kata-containers/releases/download/3.32.0/kata-static-3.32.0-amd64.tar.zst",
        "size": 1_547_940_938,
        "sha256": "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
    },
    {
        "role": "containerd",
        "version": "2.2.1",
        "name": "containerd-static-2.2.1-linux-amd64.tar.gz",
        "url": "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz",
        "size": 33_645_699,
        "sha256": "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
    },
)

MANDATORY_SECURITY_SOURCES = frozenset({
    "deploy/aws-feasibility/remote/completion_guest_workloads_v2.py",
    "deploy/aws-feasibility/remote/completion_guest_workloads_v3.py",
    "deploy/aws-feasibility/remote/completion_guest_readiness_v1.py",
    "deploy/aws-feasibility/remote/completion_cycle_evidence.py",
    "deploy/aws-feasibility/remote/completion_cycle_full.py",
    "deploy/aws-feasibility/remote/completion_cycle_readiness.py",
    "deploy/aws-feasibility/remote/completion_kata_actions.py",
    "deploy/aws-feasibility/remote/completion_kata_admission.py",
    "deploy/aws-feasibility/remote/completion_kata_command_policy.py",
    "deploy/aws-feasibility/remote/completion_kata_coordinator.py",
    "deploy/aws-feasibility/remote/completion_kata_execution_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_fdmap.py",
    "deploy/aws-feasibility/remote/completion_kata_inputs.py",
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_network.py",
    "deploy/aws-feasibility/remote/completion_kata_network_journal.py",
    "deploy/aws-feasibility/remote/completion_kata_nft_owner.py",
    "deploy/aws-feasibility/remote/completion_kata_operation.py",
    "deploy/aws-feasibility/remote/completion_kata_operation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_prestage_runtime.py",
    "deploy/aws-feasibility/remote/completion_kata_process.py",
    "deploy/aws-feasibility/remote/completion_kata_runtime.py",
    "deploy/aws-feasibility/remote/completion_kata_ssh.py",
    "deploy/aws-feasibility/remote/completion_local_evidence.py",
    "deploy/aws-feasibility/remote/completion_local_full.py",
    "deploy/aws-feasibility/remote/completion_local_receipt.py",
    "deploy/aws-feasibility/remote/completion_rootfs_fs.py",
    "deploy/aws-feasibility/remote/completion_rootfs_lease.py",
    "deploy/aws-feasibility/remote/completion_rootfs_plan.py",
    "deploy/aws-feasibility/remote/completion_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_runtime_contract.py",
    "deploy/aws-feasibility/remote/recover-stage2-completion-remote.sh",
    "deploy/aws-feasibility/remote/run-stage2-completion-full.sh",
    "deploy/aws-feasibility/remote/run-stage2-completion-readiness.sh",
    "config/stage2-completion-ssh-readiness-v1.json",
    "docs/security-evidence/kata-3.32.0-qmp-source-contract.json",
    "schemas/stage2-local-execution-envelope-v2.json",
    "schemas/stage2-local-runtime-manifest-v2.json",
    "schemas/stage2-local-static-control-package-v1.json",
})


class PreparationError(Exception):
    """Static control data is malformed, incomplete, or changed."""


@dataclass(frozen=True)
class StaticDescription:
    raw: bytes
    sha256: str
    value: dict


def _require(condition, message="invalid static preparation data"):
    if not condition:
        raise PreparationError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    _require(type(value) is str and len(value) == 64 and set(value) <= HEX, "invalid SHA-256")


def _git_revision(value):
    _require(type(value) is str and len(value) == 40 and set(value) <= HEX, "invalid implementation revision")


def _exact_keys(value, expected):
    _require(type(value) is dict and set(value) == set(expected), "unexpected static preparation keys")


def _relative(value):
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096)
    _require(not value.startswith("/") and "\\" not in value)
    _require(all(part not in {"", ".", ".."} for part in value.split("/")), "unsafe relative path")


def _absolute(value):
    _require(type(value) is str and value.startswith("/") and "//" not in value and "\\" not in value)
    _require(os.path.normpath(value) == value and "/../" not in value, "unsafe absolute path")


def _safe_link_target(path, target):
    _require(type(target) is str and target and "\\" not in target and "\0" not in target)
    if target.startswith("/"):
        resolved = posixpath.normpath(target)[1:]
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    _require(resolved not in {"", ".", ".."} and not resolved.startswith("../"),
             "runtime link escapes its extracted root")
    _relative(resolved)


def canonical_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise PreparationError("static preparation value is not canonical JSON") from error


def _toml_module():
    try:
        import tomllib
        return tomllib
    except ModuleNotFoundError:
        try:
            import tomli
            return tomli
        except ModuleNotFoundError as error:
            raise PreparationError("TOML parser unavailable") from error


def derive_observer_configuration(base, require_pinned=True):
    """Return the sole canonical Kata observer derivative.

    The release file remains untouched.  Exactly two values in the one
    ``[hypervisor.qemu]`` section change; parsing and a recursive comparison
    make comments, ordering, all paths, and every other scalar byte-bound.
    """
    _require(type(base) is bytes and b"\0" not in base
             and len(base) <= 1_048_576, "invalid Kata base configuration")
    if require_pinned:
        _require(len(base) == KATA_BASE_CONFIGURATION_SIZE
                 and _sha(base) == KATA_BASE_CONFIGURATION_SHA256,
                 "pinned Kata base configuration differs")
    toml = _toml_module()
    try:
        text = base.decode("utf-8", "strict")
        parsed_base = toml.loads(text)
    except (UnicodeError, toml.TOMLDecodeError) as error:
        raise PreparationError("invalid Kata base TOML") from error
    _require(text.count("[hypervisor.qemu]") == 1,
             "duplicate or missing Kata qemu section")
    start = text.index("[hypervisor.qemu]")
    following = text.find("\n[", start + 1)
    end = len(text) if following < 0 else following + 1
    section = base[start:end]
    derived_section = section
    for old, new in KATA_CONFIGURATION_SUBSTITUTIONS:
        _require(section.count(old) == 1 and base.count(old) >= 1,
                 "duplicate, enabled, or missing Kata observer key")
        derived_section = derived_section.replace(old, new, 1)
    derived = base[:start] + derived_section + base[end:]
    _require(derived != base and len(derived) == len(base) + 2,
             "noncanonical Kata observer derivative")
    try:
        parsed_active = toml.loads(derived.decode("utf-8", "strict"))
    except (UnicodeError, toml.TOMLDecodeError) as error:
        raise PreparationError("invalid active Kata TOML") from error
    _require(type(parsed_base) is dict and type(parsed_active) is dict)
    base_qemu = parsed_base.get("hypervisor", {}).get("qemu")
    active_qemu = parsed_active.get("hypervisor", {}).get("qemu")
    _require(type(base_qemu) is dict and type(active_qemu) is dict
             and base_qemu.get("path") == active_qemu.get("path")
             == "/opt/kata/bin/qemu-system-x86_64"
             and base_qemu.get("enable_debug") is False
             and base_qemu.get("extra_monitor_socket") == ""
             and active_qemu.get("enable_debug") is True
             and active_qemu.get("extra_monitor_socket") == "qmp",
             "Kata observer semantics differ")
    expected = copy.deepcopy(parsed_base)
    expected["hypervisor"]["qemu"]["enable_debug"] = True
    expected["hypervisor"]["qemu"]["extra_monitor_socket"] = "qmp"
    _require(parsed_active == expected,
             "Kata observer derivative changed another scalar")
    agents = parsed_active.get("agent")
    runtime = parsed_active.get("runtime")
    _require(parsed_active.get("agent") == parsed_base.get("agent")
             and type(agents) is dict and agents
             and all(type(value) is dict and value.get("enable_debug") is False
                     for value in agents.values())
             and parsed_active.get("runtime") == parsed_base.get("runtime")
             and type(runtime) is dict and runtime.get("enable_debug") is False
             and active_qemu.get("enable_annotations")
                 == base_qemu.get("enable_annotations")
                 == ["enable_iommu", "kernel_params", "kernel_verity_params"],
             "Kata debug or annotation policy widened")
    return derived


def observer_configuration_description(base, require_pinned=True):
    active = derive_observer_configuration(base, require_pinned)
    return {
        "path": KATA_ACTIVE_CONFIGURATION_PATH,
        "size": len(active),
        "sha256": _sha(active),
        "base_path": KATA_BASE_CONFIGURATION_PATH,
        "base_size": len(base),
        "base_sha256": _sha(base),
        "substitutions": [
            {"from": old.decode("ascii"), "to": new.decode("ascii")}
            for old, new in KATA_CONFIGURATION_SUBSTITUTIONS
        ],
    }


def validate_observer_configuration_description(value, base=None):
    _exact_keys(value, ("path", "size", "sha256", "base_path", "base_size",
                        "base_sha256", "substitutions"))
    _require(value["path"] == KATA_ACTIVE_CONFIGURATION_PATH
             and value["base_path"] == KATA_BASE_CONFIGURATION_PATH
             and value["base_size"] == KATA_BASE_CONFIGURATION_SIZE
             and value["base_sha256"] == KATA_BASE_CONFIGURATION_SHA256
             and value["size"] == KATA_BASE_CONFIGURATION_SIZE + 2)
    _digest(value["sha256"])
    _require(value["substitutions"] == [
        {"from": old.decode("ascii"), "to": new.decode("ascii")}
        for old, new in KATA_CONFIGURATION_SUBSTITUTIONS
    ])
    if base is not None:
        _require(value == observer_configuration_description(base),
                 "active Kata configuration binding differs")
    return value


def _pairs(rows):
    result = {}
    for key, value in rows:
        _require(type(key) is str and key not in result, "duplicate static preparation key")
        result[key] = value
    return result


def decode_canonical(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n") and b"\0" not in raw,
             "invalid static preparation bytes")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except PreparationError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PreparationError("invalid static preparation JSON") from error
    _require(type(value) is dict and canonical_bytes(value) == raw, "noncanonical static preparation bytes")
    return value


def _decode_source_manifest(raw):
    """Decode the historical producer-ordered fixed-source manifest bytes."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE_MANIFEST_BYTES
             and raw.endswith(b"\n") and b"\0" not in raw,
             "invalid full source manifest bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except PreparationError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PreparationError("invalid full source manifest JSON") from error
    _require(type(value) is dict and set(value) == {"version", "revision", "entries"},
             "invalid full source manifest shape")
    ordered = {name: value[name] for name in ("version", "revision", "entries")}
    expected = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8") + b"\n"
    _require(expected == raw, "noncanonical full source manifest bytes")
    return value


def _source_row(row):
    _exact_keys(row, ("path", "kind", "mode", "size", "sha256"))
    _relative(row["path"])
    _require(row["kind"] in {"directory", "file"})
    _require(type(row["mode"]) is int and not isinstance(row["mode"], bool) and row["mode"] in {0o400, 0o500, 0o700})
    _require(type(row["size"]) is int and not isinstance(row["size"], bool) and 0 <= row["size"] <= 32 * 1024 * 1024)
    if row["kind"] == "directory":
        _require(row["size"] == 0 and row["sha256"] is None)
    else:
        _digest(row["sha256"])


def parse_source_manifest(raw, expected_revision=None, expected_sha256=None):
    _require(expected_sha256 is None or _sha(raw) == expected_sha256, "full source manifest digest differs")
    value = _decode_source_manifest(raw)
    _require(value["version"] == "cogs.stage2-source-manifest/v1")
    _git_revision(value["revision"])
    _require(expected_revision is None or value["revision"] == expected_revision, "implementation revision differs")
    rows = value["entries"]
    _require(type(rows) is list and 1 <= len(rows) <= 20_000)
    for row in rows:
        _source_row(row)
    paths = [row["path"] for row in rows]
    _require(paths == sorted(set(paths), key=lambda item: item.encode("utf-8")), "source manifest order differs")
    return value


def _validate_implementation(value):
    _exact_keys(value, ("revision", "source_manifest_sha256", "selected_sources", "selected_sources_sha256"))
    _git_revision(value["revision"])
    _digest(value["source_manifest_sha256"])
    rows = value["selected_sources"]
    _require(type(rows) is list and len(MANDATORY_SECURITY_SOURCES) <= len(rows) <= 128)
    paths = []
    for row in rows:
        _exact_keys(row, ("path", "sha256", "size"))
        _relative(row["path"])
        _digest(row["sha256"])
        _require(type(row["size"]) is int and not isinstance(row["size"], bool) and 0 < row["size"] <= 2 * 1024 * 1024)
        paths.append(row["path"])
    _require(paths == sorted(set(paths), key=lambda item: item.encode("utf-8")))
    _require(MANDATORY_SECURITY_SOURCES <= set(paths), "security source set is incomplete")
    _digest(value["selected_sources_sha256"])
    _require(value["selected_sources_sha256"] == _sha(canonical_bytes(rows)), "security source-set digest differs")


def _package_identity(value):
    fields = ("deb_sha256", "deb_bytes", "installed_tree_sha256", "installed_entries",
              "installed_bytes", "package", "version", "architecture")
    _exact_keys(value, fields)
    _digest(value["deb_sha256"])
    _digest(value["installed_tree_sha256"])
    for name in ("deb_bytes", "installed_entries", "installed_bytes"):
        _require(type(value[name]) is int and not isinstance(value[name], bool) and value[name] > 0)
    _require(value == {
        "deb_sha256": "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
        "deb_bytes": 1_064_816,
        "installed_tree_sha256": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
        "installed_entries": 259,
        "installed_bytes": 1_048_576,
        "package": "cogs-stage2-fixture",
        "version": "1.0",
        "architecture": "all",
    }, "final package identity differs")


def _static_closure(value):
    _exact_keys(value, ("version", "manifest_sha256", "object_count", "tools", "objects"))
    _require(value["version"] == "cogs.stage2-runtime-tool-closure/v1" and value["object_count"] == 35)
    _digest(value["manifest_sha256"])
    _require(type(value["tools"]) is list and len(value["tools"]) == 3)
    rows = value["objects"]
    _require(type(rows) is list and len(rows) == 35)
    paths = []
    for row in rows:
        _exact_keys(row, ("version", "path", "source", "mode", "size", "content_sha256",
                          "interpreter", "soname", "needed", "resolved"))
        _require(row["version"] == "cogs.stage2-completion-runtime-object/v1")
        _relative(row["path"])
        _digest(row["content_sha256"])
        _require(type(row["mode"]) is int and not isinstance(row["mode"], bool) and 0 <= row["mode"] <= 0o7777)
        _require(type(row["size"]) is int and not isinstance(row["size"], bool) and row["size"] > 0)
        for name in ("needed", "resolved"):
            _require(type(row[name]) is list and len(row[name]) <= 128 and len(row[name]) == len(set(row[name])))
        _require(len(row["needed"]) == len(row["resolved"]))
        paths.append(row["path"])
    _require(paths == sorted(set(paths), key=lambda item: item.encode("utf-8")))
    _require(value["manifest_sha256"] == _sha(b"".join(canonical_bytes(row) for row in rows)))


def _file_rows(rows, maximum):
    _require(type(rows) is list and 0 < len(rows) <= maximum)
    paths = []
    for row in rows:
        _exact_keys(row, ("path", "kind", "mode", "uid", "gid", "size", "link_target", "sha256"))
        _relative(row["path"])
        _require(row["kind"] in {"directory", "file", "symlink", "hardlink"})
        for name in ("mode", "uid", "gid", "size"):
            _require(type(row[name]) is int and not isinstance(row[name], bool) and row[name] >= 0)
        if row["kind"] == "file":
            _digest(row["sha256"])
            _require(row["link_target"] is None)
        else:
            _require(row["sha256"] is None and (row["kind"] == "directory") == (row["link_target"] is None))
            if row["link_target"] is not None:
                _safe_link_target(row["path"], row["link_target"])
        paths.append(row["path"])
    _require(paths == sorted(set(paths), key=lambda item: item.encode("utf-8")), "layout rows are not uniquely ordered")


def _archive(value, expected):
    _exact_keys(value, ("role", "version", "name", "url", "size", "sha256", "layout", "extracted"))
    for name in ("role", "version", "name", "url", "size", "sha256"):
        _require(value[name] == expected[name], "runtime archive pin differs")
    for name in ("layout", "extracted"):
        section = value[name]
        _exact_keys(section, ("entry_count", "total_file_bytes", "manifest_sha256", "bounds", "entries"))
        _require(section["bounds"] == {"max_entries": MAX_ARCHIVE_ENTRIES,
                                       "max_file_bytes": MAX_ARCHIVE_FILE_BYTES,
                                       "max_total_file_bytes": MAX_ARCHIVE_TOTAL_BYTES})
        _digest(section["manifest_sha256"])
        _file_rows(section["entries"], MAX_ARCHIVE_ENTRIES)
        _require(section["entry_count"] == len(section["entries"]))
        _require(section["total_file_bytes"] == sum(row["size"] for row in section["entries"] if row["kind"] == "file"))
        _require(section["manifest_sha256"] == _sha(b"".join(canonical_bytes(row) for row in section["entries"])))


def _executable_row(row, expected):
    fields = ("role", "source_class", "path", "contract_member", "contract_sha256",
              "executable_sha256", "tool_closure_sha256")
    _exact_keys(row, fields)
    _require((row["role"], row["source_class"], row["path"]) == expected)
    _relative(row["contract_member"])
    for name in ("contract_sha256", "executable_sha256", "tool_closure_sha256"):
        _digest(row[name])


def validate_contract_value(value, expected=None):
    _exact_keys(value, ("version", "architecture", "role", "path", "dynamic_tags", "objects", "closure_sha256"))
    _require(value["version"] == CONTRACT_VERSION and value["architecture"] == "x86_64")
    if expected is not None:
        _require((value["role"], value["path"]) == (expected["role"], expected["path"]))
    _require(type(value["dynamic_tags"]) is list and value["dynamic_tags"] == [])
    objects = value["objects"]
    _require(type(objects) is list and 1 <= len(objects) <= 130)
    paths = []
    libraries = {}
    for index, row in enumerate(objects):
        _exact_keys(row, ("kind", "path", "size", "sha256", "interpreter", "soname", "needed"))
        _require(row["kind"] in {"executable", "loader", "library"})
        _absolute(row["path"])
        _require(type(row["size"]) is int and not isinstance(row["size"], bool) and 0 < row["size"] <= 128 * 1024 * 1024)
        _digest(row["sha256"])
        _require(row["interpreter"] is None or (row["kind"] == "executable" and type(row["interpreter"]) is str))
        _require(row["soname"] is None or (row["kind"] != "executable" and type(row["soname"]) is str and "/" not in row["soname"]))
        _require(type(row["needed"]) is list and row["needed"] == sorted(set(row["needed"])))
        if row["soname"] is not None:
            _require(row["soname"] not in libraries)
            libraries[row["soname"]] = row
        paths.append(row["path"])
        if index == 0:
            _require(row["kind"] == "executable")
    _require(len(paths) == len(set(paths)) and sum(row["kind"] == "executable" for row in objects) == 1)
    _require(all(name in libraries for row in objects for name in row["needed"]), "unsatisfied DT_NEEDED")
    body = {name: value[name] for name in value if name != "closure_sha256"}
    _require(value["closure_sha256"] == _sha(canonical_bytes(body)))
    return value


def load_contract(raw, expected=None):
    return StaticDescription(raw, _sha(raw), validate_contract_value(decode_canonical(raw, MAX_CONTRACT_BYTES), expected))


def validate_runtime_value(value):
    _exact_keys(value, ("version", "authority", "architecture", "archives", "rootfs", "launch", "executables"))
    _require(value["version"] == RUNTIME_VERSION and value["authority"] == AUTHORITY and value["architecture"] == "x86_64")
    archives = value["archives"]
    _require(type(archives) is list and len(archives) == len(ARCHIVES))
    for row, expected in zip(archives, ARCHIVES, strict=True):
        _archive(row, expected)
    rootfs = value["rootfs"]
    _exact_keys(rootfs, ("manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count",
                         "static_mapping_policy", "static_closure"))
    for name in ("manifest_sha256", "ustar_sha256"):
        _digest(rootfs[name])
    _require(rootfs["manifest_sha256"] == "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1")
    _require(rootfs["ustar_sha256"] == "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397")
    _require((rootfs["manifest_size"], rootfs["ustar_size"], rootfs["entry_count"]) == (1_049_443, 136_905_728, 4_353))
    _require(rootfs["static_mapping_policy"] == {"uid": 0, "gid": 0, "nlink": 1,
                                                   "distinct_file_identities": True,
                                                   "path_basis": "rootfs-relative-no-symlink"})
    _static_closure(rootfs["static_closure"])
    launch = value["launch"]
    _exact_keys(launch, ("runtime", "configuration", "active_configuration", "observer",
                         "containerd_configuration_sha256", "mount_list_sha256",
                         "shared_filesystem", "hypervisor", "fallback", "artifacts", "artifacts_sha256"))
    _require(launch["runtime"] == "io.containerd.kata.v2" and launch["shared_filesystem"] == "virtio-fs")
    _require(launch["hypervisor"] == "qemu" and launch["fallback"] == "none")
    _digest(launch["containerd_configuration_sha256"])
    _digest(launch["mount_list_sha256"])
    config = launch["configuration"]
    _exact_keys(config, ("path", "size", "sha256"))
    _absolute(config["path"])
    _digest(config["sha256"])
    _require(config == {"path": KATA_BASE_CONFIGURATION_PATH,
                        "size": KATA_BASE_CONFIGURATION_SIZE,
                        "sha256": KATA_BASE_CONFIGURATION_SHA256},
             "pinned Kata base configuration binding differs")
    validate_observer_configuration_description(launch["active_configuration"])
    observer = launch["observer"]
    _exact_keys(observer, ("private_socket", "observer_socket", "qmp_frontends",
                           "commands", "client_policy", "debug_effect"))
    _require(observer == {
        "private_socket": KATA_PRIVATE_QMP_SOCKET,
        "observer_socket": KATA_OBSERVER_QMP_SOCKET,
        "qmp_frontends": 2,
        "commands": ["qmp_capabilities", "query-status", "query-kvm"],
        "client_policy": "closed-query-only-full-control-endpoint",
        "debug_effect": "hypervisor-debug-kernel-parameters-and-debug-threads",
    }, "fixed Kata observer policy differs")
    artifacts = launch["artifacts"]
    _require(type(artifacts) is list and 6 <= len(artifacts) <= 64)
    roles = []
    paths = []
    for row in artifacts:
        _exact_keys(row, ("role", "path", "kind", "mode", "size", "sha256", "link_target"))
        _require(type(row["role"]) is str and row["role"])
        _absolute(row["path"])
        _require(row["kind"] in {"file", "symlink"})
        _require(type(row["mode"]) is int and not isinstance(row["mode"], bool))
        _require(type(row["size"]) is int and not isinstance(row["size"], bool) and row["size"] >= 0)
        if row["kind"] == "file":
            _digest(row["sha256"])
            _require(row["link_target"] is None)
        else:
            _require(row["sha256"] is None and type(row["link_target"]) is str and row["link_target"])
        roles.append(row["role"])
        paths.append(row["path"])
    _require(roles == sorted(set(roles)) and len(paths) == len(set(paths)),
             "launch artifact role map differs")
    _digest(launch["artifacts_sha256"])
    _require(launch["artifacts_sha256"] == _sha(canonical_bytes(artifacts)))
    by_role = {row["role"]: row for row in artifacts}
    _require(by_role.get("configuration") == {
        "role": "configuration", "path": config["path"], "kind": "file",
        "mode": 0o644, "size": config["size"], "sha256": config["sha256"],
        "link_target": None,
    } and by_role.get("active-configuration") == {
        "role": "active-configuration",
        "path": launch["active_configuration"]["path"], "kind": "file",
        "mode": 0o400, "size": launch["active_configuration"]["size"],
        "sha256": launch["active_configuration"]["sha256"],
        "link_target": None,
    }, "Kata base/active launch artifacts differ")
    executables = value["executables"]
    _require(type(executables) is list and len(executables) == 10)
    for row, expected in zip(executables, EXECUTABLES, strict=True):
        _executable_row(row, expected)
    return value


def load_runtime(raw):
    value = validate_runtime_value(decode_canonical(raw, MAX_RUNTIME_BYTES))
    return StaticDescription(raw, _sha(raw), value)


def validate_envelope_value(value):
    _exact_keys(value, ("version", "authority", "directional_binding", "implementation", "package", "rootfs",
                         "runtime", "programs", "result_binding_base", "receipt"))
    _require(value["version"] == ENVELOPE_VERSION and value["authority"] == AUTHORITY)
    _require(value["directional_binding"] == "control-revision-g-describes-earlier-implementation-revision-h")
    _validate_implementation(value["implementation"])
    package = value["package"]
    _exact_keys(package, ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256", "identity"))
    for name in ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256"):
        _digest(package[name])
    _require((package["candidate_contract_sha256"], package["candidate_result_sha256"],
              package["final_pin_sha256"]) == (
                  "b8660b92d778e9f5dc89586df4f68a2e2b12cdce818ff4fe12adf0a8e951fdf3",
                  "e967438172de7faee443c417fa85bf040f68decc889d74e21759b0aeb19d2b7b",
                  "7dd03d3e4ef8ae7be1f76cefce3f704c86fb84765365a5eca0df437bf72e4d31"))
    _package_identity(package["identity"])
    rootfs = value["rootfs"]
    _exact_keys(rootfs, ("contract_sha256", "manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count"))
    for name in ("contract_sha256", "manifest_sha256", "ustar_sha256"):
        _digest(rootfs[name])
    _require(rootfs["contract_sha256"] == "4fd72857efd33781ad61578ff9f9f26863d1068fcb27902efd6211fee1bc8d83")
    _require(rootfs["manifest_sha256"] == "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1")
    _require(rootfs["ustar_sha256"] == "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397")
    _require((rootfs["manifest_size"], rootfs["ustar_size"], rootfs["entry_count"]) == (1_049_443, 136_905_728, 4_353))
    runtime = value["runtime"]
    _exact_keys(runtime, ("manifest_member", "manifest_sha256", "archive_set_sha256", "launch_assets_sha256", "executable_set_sha256"))
    _require(runtime["manifest_member"] == RUNTIME_MEMBER)
    for name in ("manifest_sha256", "archive_set_sha256", "launch_assets_sha256", "executable_set_sha256"):
        _digest(runtime[name])
    programs = value["programs"]
    _exact_keys(programs, ("guest_program_sha256", "coordinator_sha256", "owner_source_set_sha256"))
    for item in programs.values():
        _digest(item)
    bindings = value["result_binding_base"]
    _exact_keys(bindings, ("source_head", "source_manifest_sha256", "rootfs_sha256", "artifact_sha256",
                           "candidate_sha256", "final_pin_sha256", "guest_program_sha256", "owner_implementation_sha256"))
    _require(bindings["source_head"] == value["implementation"]["revision"])
    _require(bindings["source_manifest_sha256"] == value["implementation"]["source_manifest_sha256"])
    _require(bindings["rootfs_sha256"] == rootfs["ustar_sha256"], "rootfs SHA must mean exact ustar bytes")
    _require(bindings["artifact_sha256"] == package["identity"]["deb_sha256"])
    _require(bindings["candidate_sha256"] == package["candidate_result_sha256"])
    _require(bindings["final_pin_sha256"] == package["final_pin_sha256"])
    _require(bindings["guest_program_sha256"] == programs["guest_program_sha256"])
    for name, item in bindings.items():
        if name != "source_head":
            _digest(item)
    _require(value["receipt"] == {"version": "cogs.stage2-local-private-receipt/v1",
                                   "domain": "cogs.stage2-local-private-receipt/v1\u0000"})
    return value


def load_envelope(raw):
    value = validate_envelope_value(decode_canonical(raw, MAX_ENVELOPE_BYTES))
    return StaticDescription(raw, _sha(raw), value)


def validate_control_value(value):
    _exact_keys(value, ("version", "authority", "directional_binding", "implementation", "members", "producer"))
    _require(value["version"] == CONTROL_VERSION and value["authority"] == AUTHORITY)
    _require(value["directional_binding"] == "control-revision-g-describes-earlier-implementation-revision-h")
    _validate_implementation(value["implementation"])
    members = value["members"]
    _require(type(members) is list and len(members) == 12)
    names = []
    kinds = []
    for row in members:
        _exact_keys(row, ("name", "kind", "sha256", "size"))
        _relative(row["name"])
        _require(row["kind"] in {"envelope", "runtime-manifest", "executable-closure"})
        _digest(row["sha256"])
        _require(type(row["size"]) is int and not isinstance(row["size"], bool) and row["size"] > 0)
        names.append(row["name"])
        kinds.append(row["kind"])
    _require(names == sorted(set(names), key=lambda item: item.encode("ascii")))
    _require(kinds.count("envelope") == kinds.count("runtime-manifest") == 1 and kinds.count("executable-closure") == 10)
    _require({row["name"] for row in members if row["kind"] == "envelope"} == {ENVELOPE_MEMBER})
    _require({row["name"] for row in members if row["kind"] == "runtime-manifest"} == {RUNTIME_MEMBER})
    producer = value["producer"]
    _exact_keys(producer, ("classification", "implementation_revision", "source_manifest_sha256", "kvm_absent",
                           "network_used", "forbidden_surfaces"))
    _require(producer["classification"] == "deterministic-no-kvm-static-observation-candidate")
    _require(producer["implementation_revision"] == value["implementation"]["revision"])
    _require(producer["source_manifest_sha256"] == value["implementation"]["source_manifest_sha256"])
    _require(producer["kvm_absent"] is True and producer["network_used"] is False)
    _require(producer["forbidden_surfaces"] == ["containerd", "coordinator", "kata", "kvm", "qmp", "ssh", "task"])
    return value


def load_control(raw):
    value = validate_control_value(decode_canonical(raw, MAX_CONTROL_BYTES))
    return StaticDescription(raw, _sha(raw), value)


def validate_control_members(control, members):
    _require(type(control) is StaticDescription and control.value["version"] == CONTROL_VERSION)
    _require(type(members) is dict and set(members) == {row["name"] for row in control.value["members"]})
    for row in control.value["members"]:
        raw = members[row["name"]]
        _require(type(raw) is bytes and len(raw) == row["size"] and _sha(raw) == row["sha256"], "control member differs")
    envelope = load_envelope(members[ENVELOPE_MEMBER])
    runtime = load_runtime(members[RUNTIME_MEMBER])
    _require(envelope.value["implementation"] == control.value["implementation"])
    _require(envelope.value["runtime"]["manifest_sha256"] == runtime.sha256)
    _require(envelope.value["runtime"]["archive_set_sha256"] == _sha(canonical_bytes(runtime.value["archives"])))
    _require(envelope.value["runtime"]["launch_assets_sha256"] == runtime.value["launch"]["artifacts_sha256"])
    _require(envelope.value["runtime"]["executable_set_sha256"] == _sha(canonical_bytes(runtime.value["executables"])))
    contracts = {}
    for executable in runtime.value["executables"]:
        raw = members[executable["contract_member"]]
        contract = load_contract(raw, executable)
        _require(contract.sha256 == executable["contract_sha256"])
        _require(contract.value["closure_sha256"] == executable["tool_closure_sha256"])
        _require(contract.value["objects"][0]["sha256"] == executable["executable_sha256"])
        contracts[executable["role"]] = contract
    return envelope, runtime, contracts


def selected_implementation(source_manifest):
    by_path = {row["path"]: row for row in source_manifest["entries"] if row["kind"] == "file"}
    _require(MANDATORY_SECURITY_SOURCES <= set(by_path), "implementation H lacks mandatory security sources")
    rows = [{"path": path, "sha256": by_path[path]["sha256"], "size": by_path[path]["size"]}
            for path in sorted(MANDATORY_SECURITY_SOURCES, key=lambda item: item.encode("utf-8"))]
    return rows


def _safe_archive_path(value):
    _require(type(value) is str and value and "\\" not in value and not value.startswith("/"))
    while value.startswith("./"):
        value = value[2:]
    value = value[:-1] if value.endswith("/") else value
    _relative(value)
    return value


def _tar_rows(stream, mode):
    rows = []
    total = 0
    try:
        with tarfile.open(fileobj=stream, mode=mode, encoding="utf-8", errors="strict") as archive:
            root_seen = False
            for member in archive:
                _require(len(rows) < MAX_ARCHIVE_ENTRIES)
                if member.name in {".", "./"}:
                    _require(not root_seen and member.isdir() and member.size == 0
                             and member.mode == 0o755 and member.uid == member.gid == 0
                             and not member.linkname)
                    root_seen = True
                    continue
                path = _safe_archive_path(member.name)
                kind = ("file" if member.isfile() else "directory" if member.isdir() else
                        "symlink" if member.issym() else "hardlink" if member.islnk() else None)
                _require(kind is not None and 0 <= member.size <= MAX_ARCHIVE_FILE_BYTES)
                digest = None
                if kind == "file":
                    source = archive.extractfile(member)
                    _require(source is not None)
                    hasher = hashlib.sha256()
                    observed = 0
                    while observed < member.size:
                        chunk = source.read(min(1024 * 1024, member.size - observed))
                        _require(chunk)
                        hasher.update(chunk)
                        observed += len(chunk)
                    _require(observed == member.size and not source.read(1))
                    digest = hasher.hexdigest()
                    total += observed
                    _require(total <= MAX_ARCHIVE_TOTAL_BYTES)
                link = member.linkname if kind in {"symlink", "hardlink"} else None
                if link is not None:
                    _safe_link_target(path, link)
                rows.append({"path": path, "kind": kind, "mode": member.mode, "uid": member.uid,
                             "gid": member.gid, "size": member.size, "link_target": link, "sha256": digest})
    except (tarfile.TarError, UnicodeError, OSError) as error:
        raise PreparationError("runtime archive layout is invalid") from error
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    _file_rows(rows, MAX_ARCHIVE_ENTRIES)
    return rows


def archive_layout(path, expected):
    path = Path(path)
    before = os.stat(path, follow_symlinks=False)
    _require(stat.S_ISREG(before.st_mode) and before.st_size == expected["size"] and before.st_nlink == 1)
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    _require(hasher.hexdigest() == expected["sha256"] and os.stat(path, follow_symlinks=False) == before,
             "runtime archive bytes differ")
    if expected["name"].endswith(".tar.gz"):
        with path.open("rb") as source:
            rows = _tar_rows(source, "r|gz")
    else:
        _require(expected["name"].endswith(".tar.zst") and Path("/usr/bin/zstd").is_file())
        process = subprocess.Popen(("/usr/bin/zstd", "--decompress", "--stdout", "--", str(path)),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        try:
            _require(process.stdout is not None)
            rows = _tar_rows(process.stdout, "r|")
            process.stdout.close()
            _require(process.wait(timeout=300) == 0)
        except BaseException:
            process.kill()
            process.wait()
            raise
    return rows


def extracted_postwalk(root):
    root = Path(root)
    observed_root = os.stat(root, follow_symlinks=False)
    _require(stat.S_ISDIR(observed_root.st_mode))
    rows = []
    total_file_bytes = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        for name in (*directories, *files):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            _relative(relative)
            seen = path.lstat()
            if stat.S_ISREG(seen.st_mode):
                kind = "file"
                size = seen.st_size
                _require(size <= MAX_ARCHIVE_FILE_BYTES)
                total_file_bytes += size
                _require(total_file_bytes <= MAX_ARCHIVE_TOTAL_BYTES)
                hasher = hashlib.sha256()
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    _require(_same_file_generation(os.fstat(descriptor), seen))
                    offset = 0
                    while offset < size:
                        chunk = os.read(descriptor, min(1024 * 1024, size - offset))
                        _require(chunk)
                        hasher.update(chunk)
                        offset += len(chunk)
                    _require(not os.read(descriptor, 1)
                             and _same_file_generation(os.fstat(descriptor), seen))
                finally:
                    os.close(descriptor)
                digest = hasher.hexdigest()
                link = None
            elif stat.S_ISDIR(seen.st_mode):
                kind, digest, link, size = "directory", None, None, 0
            elif stat.S_ISLNK(seen.st_mode):
                kind, digest, link, size = "symlink", None, os.readlink(path), 0
                _safe_link_target(relative, link)
                if name in directories:
                    directories.remove(name)
            else:
                raise PreparationError("unsupported extracted runtime object")
            rows.append({"path": relative, "kind": kind, "mode": stat.S_IMODE(seen.st_mode),
                         "uid": seen.st_uid, "gid": seen.st_gid, "size": size,
                         "link_target": link, "sha256": digest})
            _require(len(rows) <= MAX_ARCHIVE_ENTRIES)
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    _file_rows(rows, MAX_ARCHIVE_ENTRIES)
    _require(_same_file_generation(
        os.stat(root, follow_symlinks=False), observed_root),
        "extracted runtime changed during postwalk")
    return rows


def section(rows):
    _file_rows(rows, MAX_ARCHIVE_ENTRIES)
    return {"entry_count": len(rows),
            "total_file_bytes": sum(row["size"] for row in rows if row["kind"] == "file"),
            "manifest_sha256": _sha(b"".join(canonical_bytes(row) for row in rows)),
            "bounds": {"max_entries": MAX_ARCHIVE_ENTRIES, "max_file_bytes": MAX_ARCHIVE_FILE_BYTES,
                       "max_total_file_bytes": MAX_ARCHIVE_TOTAL_BYTES},
            "entries": rows}


def _same_file_generation(left, right):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def _stable_file_bytes(path):
    """Resolve a bounded symlink chain through held, no-follow directory fds."""
    path = os.fspath(path)
    _require(type(path) is str and path.startswith("/") and "\0" not in path)
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directories = [root]
    pending = path.split("/")[1:]
    links = steps = 0
    try:
        while pending:
            steps += 1
            _require(steps <= 256, "executable path resolution bound")
            name = pending.pop(0)
            if name in {"", "."}:
                continue
            if name == "..":
                if len(directories) > 1:
                    os.close(directories.pop())
                continue
            before = os.stat(name, dir_fd=directories[-1], follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                links += 1
                _require(links <= 40, "executable symlink bound")
                target = os.readlink(name, dir_fd=directories[-1])
                _require(_same_file_generation(
                    os.stat(name, dir_fd=directories[-1], follow_symlinks=False), before),
                    "executable symlink replaced")
                _require(type(target) is str and "\0" not in target)
                if target.startswith("/"):
                    while len(directories) > 1:
                        os.close(directories.pop())
                pending = target.split("/") + pending
                continue
            if pending:
                _require(stat.S_ISDIR(before.st_mode), "non-directory executable component")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directories[-1])
                _require(_same_file_generation(os.fstat(child), before),
                         "executable directory replaced")
                directories.append(child)
                continue
            _require(stat.S_ISREG(before.st_mode) and 64 <= before.st_size <= 512 * 1024 * 1024,
                     "invalid executable object")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=directories[-1])
            try:
                _require(_same_file_generation(os.fstat(descriptor), before),
                         "executable object replaced")
                raw = bytearray()
                while len(raw) < before.st_size:
                    part = os.read(descriptor, min(1024 * 1024, before.st_size - len(raw)))
                    _require(part, "short executable object")
                    raw.extend(part)
                _require(not os.read(descriptor, 1)
                         and _same_file_generation(os.fstat(descriptor), before)
                         and _same_file_generation(os.stat(
                             name, dir_fd=directories[-1], follow_symlinks=False), before),
                         "executable object changed")
                return bytes(raw), before
            finally:
                os.close(descriptor)
        raise PreparationError("executable path resolves to directory")
    except (FileNotFoundError, NotADirectoryError):
        raise
    except PreparationError:
        raise
    except OSError as error:
        raise PreparationError("executable path resolution failed") from error
    finally:
        for descriptor in reversed(directories):
            os.close(descriptor)


def _read_elf(path, expected=None):
    try:
        raw, observed = _stable_file_bytes(path)
    except (FileNotFoundError, NotADirectoryError) as error:
        raise PreparationError("executable object unavailable") from error
    if expected is not None:
        _require((observed.st_dev, observed.st_ino, raw) == expected,
                 "resolved executable candidate changed")
    try:
        ident, kind, machine, version = struct.unpack_from("<16sHHI", raw)
        _require(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in {2, 3} and machine == 62 and version == 1)
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
        phoff, phsize, phnum = header[5], header[9], header[10]
        _require(phsize == 56 and 0 < phnum <= 256 and phoff + phsize * phnum <= len(raw))
        headers = [struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phsize) for index in range(phnum)]
        dynamic = sum(row[0] == 2 for row in headers)
        interpreters = [row for row in headers if row[0] == 3]
        _require(len(interpreters) <= 1)
        interpreter = None
        if interpreters:
            offset, size = interpreters[0][2], interpreters[0][5]
            encoded = raw[offset:offset + size]
            _require(encoded.endswith(b"\0") and b"\0" not in encoded[:-1])
            interpreter = encoded[:-1].decode("ascii")
        if dynamic == 0:
            return raw, interpreter, None, ()
        _require(dynamic == 1)
        from completion_runtime_closure import _elf
        parsed = _elf(raw)
        _require(parsed[0] == interpreter)
        return raw, *parsed
    except PreparationError:
        raise
    except Exception as error:
        raise PreparationError("invalid executable ELF") from error


def _soname_candidate(name, logical_to_actual):
    selected = None
    for directory in ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/opt/kata/lib", "/opt/kata/libexec"):
        candidate = logical_to_actual(directory + "/" + name)
        try:
            candidate_raw, candidate_stat = _stable_file_bytes(candidate)
        except (FileNotFoundError, NotADirectoryError):
            continue
        observed = (candidate_stat.st_dev, candidate_stat.st_ino, candidate_raw)
        if selected is None:
            selected = (directory + "/" + name, candidate, observed)
        elif observed != selected[2]:
            raise PreparationError("ambiguous executable closure provider")
    return selected


def collect_executable_contract(role, declared_path, actual_path, logical_to_actual):
    pending = [("executable", declared_path, Path(actual_path), None)]
    objects = []
    seen_paths = set()
    sonames = {}
    while pending:
        kind, logical, actual, expected = pending.pop(0)
        _absolute(logical)
        _require(logical not in seen_paths, f"duplicate executable closure path: {logical}")
        seen_paths.add(logical)
        raw, interpreter, soname, needed = _read_elf(actual, expected)
        objects.append({"kind": kind, "path": logical, "size": len(raw), "sha256": _sha(raw),
                        "interpreter": interpreter if kind == "executable" else None,
                        "soname": soname, "needed": sorted(needed)})
        if kind != "executable" and soname is not None:
            existing = sonames.get(soname)
            _require(existing in {None, logical}, "duplicate executable closure SONAME")
            sonames[soname] = logical
        if kind == "executable" and interpreter is not None:
            mapped = logical_to_actual(interpreter)
            pending.append(("loader", interpreter, mapped, None))
        for name in needed:
            sonames.setdefault(name, None)
        unresolved = [name for name, value in sonames.items() if value is None]
        for name in unresolved:
            selected = _soname_candidate(name, logical_to_actual)
            if selected is not None:
                sonames[name] = selected[0]
                pending.append(("library", selected[0], selected[1], selected[2]))
    _require(all(value is not None for value in sonames.values()), "unresolved executable closure")
    loader = [row for row in objects if row["kind"] == "loader"]
    libraries = sorted((row for row in objects if row["kind"] == "library"), key=lambda row: row["soname"] or "")
    ordered = [objects[0], *loader, *libraries]
    body = {"version": CONTRACT_VERSION, "architecture": "x86_64", "role": role,
            "path": declared_path, "dynamic_tags": [], "objects": ordered}
    value = {**body, "closure_sha256": _sha(canonical_bytes(body))}
    validate_contract_value(value)
    return value


def _source_digest(implementation, path):
    row = next((row for row in implementation["selected_sources"] if row["path"] == path), None)
    _require(row is not None)
    return row["sha256"]


def build_control_bytes(implementation, runtime, package, rootfs_contract_sha256, contracts):
    """Pure deterministic producer used by the fixed no-KVM collector and tests."""
    _require(type(contracts) is dict and set(contracts) == {row[0] for row in EXECUTABLES})
    clean_runtime = json.loads(canonical_bytes(runtime))
    for row in clean_runtime["executables"]:
        member = f"contracts/{EXECUTABLES.index(next(item for item in EXECUTABLES if item[0] == row['role'])):02d}-{row['role']}.json"
        contract_raw = canonical_bytes(validate_contract_value(contracts[row["role"]]))
        row["contract_member"] = member
        row["contract_sha256"] = _sha(contract_raw)
        row["executable_sha256"] = contracts[row["role"]]["objects"][0]["sha256"]
        row["tool_closure_sha256"] = contracts[row["role"]]["closure_sha256"]
    runtime_raw = canonical_bytes(validate_runtime_value(clean_runtime))
    final = package
    _exact_keys(final, ("candidate_contract_sha256", "candidate_result_sha256", "final_pin_sha256", "identity"))
    _package_identity(final["identity"])
    owner_rows = [row for row in implementation["selected_sources"] if row["path"].startswith("deploy/aws-feasibility/remote/completion_kata_")]
    guest_program = final_guest.guest_program_bytes()
    guest_program_sha256 = _sha(guest_program)
    _require(guest_program_sha256 == final_guest.GUEST_PROGRAM_SHA256,
             "final guest program digest differs")
    programs = {"guest_program_sha256": guest_program_sha256,
                "coordinator_sha256": _source_digest(implementation, "deploy/aws-feasibility/remote/completion_kata_coordinator.py"),
                "owner_source_set_sha256": _sha(canonical_bytes(owner_rows))}
    envelope = {"version": ENVELOPE_VERSION, "authority": AUTHORITY,
                "directional_binding": "control-revision-g-describes-earlier-implementation-revision-h",
                "implementation": implementation, "package": final,
                "rootfs": {"contract_sha256": rootfs_contract_sha256,
                           **{name: clean_runtime["rootfs"][name] for name in
                              ("manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count")}},
                "runtime": {"manifest_member": RUNTIME_MEMBER, "manifest_sha256": _sha(runtime_raw),
                            "archive_set_sha256": _sha(canonical_bytes(clean_runtime["archives"])),
                            "launch_assets_sha256": clean_runtime["launch"]["artifacts_sha256"],
                            "executable_set_sha256": _sha(canonical_bytes(clean_runtime["executables"]))},
                "programs": programs,
                "result_binding_base": {"source_head": implementation["revision"],
                    "source_manifest_sha256": implementation["source_manifest_sha256"],
                    "rootfs_sha256": clean_runtime["rootfs"]["ustar_sha256"],
                    "artifact_sha256": final["identity"]["deb_sha256"],
                    "candidate_sha256": final["candidate_result_sha256"],
                    "final_pin_sha256": final["final_pin_sha256"],
                    "guest_program_sha256": programs["guest_program_sha256"],
                    "owner_implementation_sha256": programs["coordinator_sha256"]},
                "receipt": {"version": "cogs.stage2-local-private-receipt/v1",
                            "domain": "cogs.stage2-local-private-receipt/v1\u0000"}}
    envelope_raw = canonical_bytes(validate_envelope_value(envelope))
    members = {ENVELOPE_MEMBER: envelope_raw, RUNTIME_MEMBER: runtime_raw}
    for row in clean_runtime["executables"]:
        members[row["contract_member"]] = canonical_bytes(contracts[row["role"]])
    member_rows = [{"name": name,
                    "kind": "envelope" if name == ENVELOPE_MEMBER else
                            "runtime-manifest" if name == RUNTIME_MEMBER else "executable-closure",
                    "sha256": _sha(raw), "size": len(raw)}
                   for name, raw in sorted(members.items())]
    control = {"version": CONTROL_VERSION, "authority": AUTHORITY,
               "directional_binding": "control-revision-g-describes-earlier-implementation-revision-h",
               "implementation": implementation, "members": member_rows,
               "producer": {"classification": "deterministic-no-kvm-static-observation-candidate",
                            "implementation_revision": implementation["revision"],
                            "source_manifest_sha256": implementation["source_manifest_sha256"],
                            "kvm_absent": True, "network_used": False,
                            "forbidden_surfaces": ["containerd", "coordinator", "kata", "kvm", "qmp", "ssh", "task"]}}
    control_raw = canonical_bytes(validate_control_value(control))
    validate_control_members(load_control(control_raw), members)
    return control_raw, members


def _fixed_file(role, logical_path, actual_path):
    actual = Path(actual_path)
    seen = actual.lstat()
    _require(stat.S_ISREG(seen.st_mode) or stat.S_ISLNK(seen.st_mode))
    if stat.S_ISLNK(seen.st_mode):
        return {"role": role, "path": logical_path, "kind": "symlink",
                "mode": stat.S_IMODE(seen.st_mode), "size": 0, "sha256": None,
                "link_target": os.readlink(actual)}
    raw = actual.read_bytes()
    _require(len(raw) == seen.st_size)
    return {"role": role, "path": logical_path, "kind": "file",
            "mode": stat.S_IMODE(seen.st_mode), "size": len(raw),
            "sha256": _sha(raw), "link_target": None}


def _configured_launch_assets(kata_root):
    config_path = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"
    actual_config = kata_root / config_path[1:]
    raw = actual_config.read_bytes()
    _require(0 < len(raw) <= 1024 * 1024)
    toml = _toml_module()
    try:
        config = toml.loads(raw.decode("utf-8"))
    except (UnicodeError, toml.TOMLDecodeError) as error:
        raise PreparationError("Kata configuration is invalid") from error
    configured = {}

    def visit(value, prefix):
        if type(value) is dict:
            for name, child in value.items():
                _require(type(name) is str)
                visit(child, prefix + (name,))
        elif type(value) is list:
            for index, child in enumerate(value):
                visit(child, prefix + (str(index),))
        elif type(value) is str and value.startswith("/opt/kata/"):
            actual = kata_root / value[1:]
            if actual.is_file() or actual.is_symlink():
                role = "configured-" + "-".join(prefix).replace("_", "-")
                _require(role not in configured)
                configured[role] = (value, actual)

    visit(config, ())
    mandatory = {
        "configuration": (config_path, actual_config),
        "shim": ("/opt/kata/bin/containerd-shim-kata-v2", kata_root / "opt/kata/bin/containerd-shim-kata-v2"),
        "qemu": ("/opt/kata/bin/qemu-system-x86_64", kata_root / "opt/kata/bin/qemu-system-x86_64"),
        "virtiofsd": ("/opt/kata/libexec/virtiofsd", kata_root / "opt/kata/libexec/virtiofsd"),
    }
    mandatory_paths = {logical for logical, _actual in mandatory.values()}
    configured = {role: value for role, value in configured.items() if value[0] not in mandatory_paths}
    configured.update(mandatory)
    rows = [_fixed_file(role, logical, actual)
            for role, (logical, actual) in sorted(configured.items())]
    paths = {row["path"] for row in rows}
    _require(config_path in paths and mandatory["qemu"][0] in paths and mandatory["virtiofsd"][0] in paths)
    _require(any("kernel" in row["role"] for row in rows))
    _require(any("image" in row["role"] or "initrd" in row["role"] for row in rows))
    return raw, rows


def collect_fixed_candidate():
    """Collect the sole fixed, source-external, no-KVM static candidate."""
    global _OBSERVATION_STAGE
    _require(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() == 0)
    _OBSERVATION_STAGE = "source-manifest"
    source_raw = (SOURCE_ROOT / SOURCE_MANIFEST).read_bytes()
    source = parse_source_manifest(source_raw)
    implementation = {"revision": source["revision"],
                      "source_manifest_sha256": _sha(source_raw),
                      "selected_sources": selected_implementation(source)}
    implementation["selected_sources_sha256"] = _sha(canonical_bytes(implementation["selected_sources"]))
    _validate_implementation(implementation)

    _OBSERVATION_STAGE = "preparation-receipt"
    receipt_path = (SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/"
                    "immutable-preparation-v1/receipt.json")
    receipt = decode_canonical(receipt_path.read_bytes(), MAX_RUNTIME_BYTES)
    _exact_keys(receipt, ("version", "authority", "rootfs_artifact_count",
                          "runtime_archives", "forbidden_surfaces"))
    _require(receipt["version"] == "cogs.stage2-local-immutable-preparation/v1"
             and receipt["authority"] == "immutable-public-input-preparation-only"
             and receipt["rootfs_artifact_count"] == 16
             and receipt["forbidden_surfaces"] ==
             ["containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"])
    archive_values = receipt["runtime_archives"]
    _require(type(archive_values) is list and len(archive_values) == len(ARCHIVES))
    for value, expected in zip(archive_values, ARCHIVES, strict=True):
        _archive(value, expected)
    actual_runtime = SOURCE_ROOT / "deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1"

    _OBSERVATION_STAGE = "runtime-closure"
    import completion_kata_runtime as kata_runtime
    import completion_runtime_contract as runtime_contract
    from completion_rootfs_plan import load_verified_build_inputs
    from completion_runtime_closure import fixed_runtime_closure

    final = runtime_contract.load_final_pin()
    closure = fixed_runtime_closure(load_verified_build_inputs())
    static_objects = [json.loads(canonical_bytes(asdict(record))) for record in closure.records]
    static_closure = {**final.runtime_closure.value(), "objects": static_objects}
    _OBSERVATION_STAGE = "launch-assets"
    config_raw, artifacts = _configured_launch_assets(Path("/"))
    active_raw = (actual_runtime / Path(KATA_ACTIVE_CONFIGURATION_PATH).name).read_bytes()
    active_description = observer_configuration_description(config_raw)
    _require(active_raw == derive_observer_configuration(config_raw)
             and len(active_raw) == active_description["size"]
             and _sha(active_raw) == active_description["sha256"],
             "active observer configuration artifact differs")
    artifacts.extend((
        _fixed_file("active-configuration", KATA_ACTIVE_CONFIGURATION_PATH,
                    actual_runtime / Path(KATA_ACTIVE_CONFIGURATION_PATH).name),
        _fixed_file("containerd", EXECUTABLES[5][2], actual_runtime / "bin/containerd"),
        _fixed_file("ctr", EXECUTABLES[6][2], actual_runtime / "bin/ctr"),
    ))
    artifacts.sort(key=lambda row: row["role"])

    _OBSERVATION_STAGE = "executable-contracts"
    contracts = {}
    executable_rows = []
    for role, source_class, declared in EXECUTABLES:
        if source_class == "host-path":
            actual = Path(declared)
            mapper = lambda logical: Path(logical)
        elif source_class == "staged-runtime":
            actual = actual_runtime / ("bin/" + role)
            mapper = lambda logical: Path(logical)
        else:
            actual = Path(declared)
            mapper = lambda logical: Path(logical)
        contracts[role] = collect_executable_contract(role, declared, actual, mapper)
        executable_rows.append({"role": role, "source_class": source_class, "path": declared,
                                "contract_member": "contracts/unset.json", "contract_sha256": "0" * 64,
                                "executable_sha256": "0" * 64, "tool_closure_sha256": "0" * 64})

    runtime = {"version": RUNTIME_VERSION, "authority": AUTHORITY, "architecture": "x86_64",
               "archives": archive_values,
               "rootfs": {"manifest_sha256": "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1",
                          "manifest_size": 1_049_443,
                          "ustar_sha256": "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397",
                          "ustar_size": 136_905_728, "entry_count": 4_353,
                          "static_mapping_policy": {"uid": 0, "gid": 0, "nlink": 1,
                                                    "distinct_file_identities": True,
                                                    "path_basis": "rootfs-relative-no-symlink"},
                          "static_closure": static_closure},
               "launch": {"runtime": "io.containerd.kata.v2",
                          "configuration": {"path": KATA_BASE_CONFIGURATION_PATH,
                                            "size": len(config_raw), "sha256": _sha(config_raw)},
                          "active_configuration": active_description,
                          "observer": {
                              "private_socket": KATA_PRIVATE_QMP_SOCKET,
                              "observer_socket": KATA_OBSERVER_QMP_SOCKET,
                              "qmp_frontends": 2,
                              "commands": ["qmp_capabilities", "query-status", "query-kvm"],
                              "client_policy": "closed-query-only-full-control-endpoint",
                              "debug_effect": "hypervisor-debug-kernel-parameters-and-debug-threads",
                          },
                          "containerd_configuration_sha256": kata_runtime.CONTAINERD_CONFIG_SHA256,
                          "mount_list_sha256": kata_runtime.MOUNT_LIST_SHA256,
                          "shared_filesystem": "virtio-fs", "hypervisor": "qemu", "fallback": "none",
                          "artifacts": artifacts, "artifacts_sha256": _sha(canonical_bytes(artifacts))},
               "executables": executable_rows}
    _OBSERVATION_STAGE = "control-bytes"
    package = {"candidate_contract_sha256": final.candidate_contract_sha256,
               "candidate_result_sha256": final.candidate_result_sha256,
               "final_pin_sha256": final.final_pin_sha256,
               "identity": final.package_identity.value()}
    return build_control_bytes(implementation, runtime, package,
                               runtime_contract.REVIEWED_ROOTFS_SHA256, contracts)


def generate_implementation_h_candidate_control_bytes():
    """Generate canonical candidate control bytes for the fixed source revision H."""
    return collect_fixed_candidate()


def publish_fixed_candidate(control_raw, members):
    """Publish one new candidate directory; never replace reviewed or staged bytes."""
    destination = OBSERVATION_ROOT / "candidate"
    parent_created = not OBSERVATION_ROOT.exists()
    if parent_created:
        OBSERVATION_ROOT.mkdir(mode=0o700)
    else:
        _require(OBSERVATION_ROOT.is_dir() and not any(OBSERVATION_ROOT.iterdir()))
    _require(not destination.exists())
    destination.mkdir(mode=0o700)
    try:
        payloads = {CONTROL_MEMBER: control_raw, **members}
        directories = {destination}
        for name, raw in sorted(payloads.items()):
            path = destination / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.add(path.parent)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(descriptor, raw[offset:])
                    _require(type(written) is int and written > 0)
                    offset += written
                os.fchmod(descriptor, 0o444)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            os.chmod(directory, 0o555)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return _sha(control_raw)
    except BaseException:
        for current, directories, files in os.walk(destination, topdown=False, followlinks=False):
            for name in files:
                os.unlink(Path(current) / name)
            for name in directories:
                os.rmdir(Path(current) / name)
        os.rmdir(destination)
        if parent_created:
            os.rmdir(OBSERVATION_ROOT)
        raise


def main():
    global _OBSERVATION_STAGE
    _require(len(os.sys.argv) == 1)
    control_raw, members = generate_implementation_h_candidate_control_bytes()
    _OBSERVATION_STAGE = "publication"
    digest = publish_fixed_candidate(control_raw, members)
    result = canonical_bytes({"version": "cogs.stage2-local-static-observation/v1",
                              "authority": "non-authoritative-discovery-candidate",
                              "control_sha256": digest, "kvm_used": False})
    _require(os.sys.stdout.buffer.write(result) == len(result))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        try:
            stage = _OBSERVATION_STAGE if _OBSERVATION_STAGE in _OBSERVATION_STAGES else "entry"
            os.sys.stderr.buffer.write(
                f"static no-KVM observation failed:{stage}\n".encode("ascii"))
        except BaseException:
            pass
        raise SystemExit(2)

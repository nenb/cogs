#!/usr/bin/env python3
"""ADR0047 Phase A metadata-only candidate observer.

This fixed-path program deliberately stops before runtime extraction.  It never
invokes the Kata coordinator and cannot issue runtime, network, SSH, or
qualification authority.
"""

from dataclasses import dataclass
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True

FIXED_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
FIXED_SCRIPT = FIXED_SOURCE / "scripts/run-stage2-phase-a-candidate.py"
REMOTE = FIXED_SOURCE / "deploy/aws-feasibility/remote"
STATE = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/phase-a-candidate-v2"
ANCHOR = STATE.parent / ".cogs-stage2-phase-a-anchor-v2.json"
JOURNAL = STATE / "ownership.jsonl"
ASSETS = STATE / "assets"
OBSERVATION = STATE / "observation.json"
CLEANUP = STATE / "cleanup.json"
RESIDUE = STATE / "residue.json"
REPORT = STATE / "candidate.json"
EXPORT_ROOT = Path("/var/tmp/cogs-stage2-phase-a-candidate-v2")
EXPORT_REPORT = EXPORT_ROOT / "candidate.json"
SOURCE_MANIFEST = FIXED_SOURCE / ".cogs-stage2-source-manifest-v1.json"
ARTIFACT_ROOT = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/artifacts"
ROOTFS_STATE = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
VERSION = "cogs.stage2-phase-a-candidate/v2"
ANCHOR_VERSION, PHASE_B_STAGE = "cogs.stage2-phase-a-anchor/v2", "phase-b-discovery"
PHASE_B_VERSION, PHASE_B_STATE = "cogs.stage2-phase-b-qualification/v1", STATE.parent / "phase-a-v2"
MAX_JSON = 64 * 1024
MAX_JOURNAL = 512 * 1024
MAX_SOURCE_MANIFEST = 16 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT = 4096
HOST_TOOL_SECONDS = 10
DOWNLOAD_SECONDS = 1200
OBSERVE_SECONDS = 3300
ROOTFS_RECOVERY_ATTEMPTS = 1
ROOTFS_PHASES = (
    "first-build-work", "first-inline-cleanup", "second-build-work", "second-inline-cleanup",
    "recovery-attempt-1", "equality", "pin", "post-verification", "settlement",
)
STRUCTURAL_COUNTERS = (
    "record_reference_copies", "byte_names_returned", "parent_snapshots", "complete_legal_record_folds",
    "complete_filesystem_walks", "incrementally_advanced_ledger_records",
)
OBSERVATION_PHASES = tuple(name for name in ROOTFS_PHASES if name != "recovery-attempt-1")
NS_PER_SECOND = 1_000_000_000
NS_PER_MILLISECOND = 1_000_000
KVM_GET_API_VERSION = 0xAE00
APPROVAL_NAME = "COGS_STAGE2_ARTIFACT_ACQUISITION_APPROVED"
APPROVAL_VALUE = "download-16-fixed-public-stage2-artifacts"
DENIED_ENV = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "NETRC",
    "DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "DOCKER_AUTH_CONFIG", "AUTHORIZATION",
    "BEARER_TOKEN", "REGISTRY_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
})
HEX = re.compile(r"^[0-9a-f]{64}$")
FULL_GENERATION = (
    "mount_id", "dev", "ino", "kind", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns",
)
STAGE_CHECK = {"success": "pass", "failure": "fail", "blocked": "blocked", "not-reached": "unknown"}
STAGE_NAMES = ("artifact_cache", "runtime_assets")
SETUP_STATES = {
    "not-reached", "fixed-input", "rootfs-bootstrap", "operation-establishment", "materializer-dispatch", "complete",
}
PREPHASE_SETUPS = {"rootfs-bootstrap", "operation-establishment", "materializer-dispatch"}
IMMEDIATE_OUTCOMES = {"not-required", "success", "preserved", "post-unlink-uncertainty"}
O_PATH = getattr(os, "O_PATH", os.O_RDONLY)


class CandidateError(Exception):
    """A categorical Phase A stop."""

    def __init__(self, code="candidate-uncertainty"):
        self.code = code if type(code) is str and re.fullmatch(r"[a-z0-9-]{1,64}", code) else "candidate-uncertainty"
        super().__init__(self.code)


def _fail(condition, code="candidate-uncertainty"):
    if not condition:
        raise CandidateError(code)


@dataclass(frozen=True)
class Asset:
    component: str
    release: str
    name: str
    url: str
    size: int
    sha256: str


RUNTIME_ASSETS = (
    Asset(
        "kata", "3.32.0", "kata-static-3.32.0-amd64.tar.zst",
        "https://github.com/kata-containers/kata-containers/releases/download/3.32.0/kata-static-3.32.0-amd64.tar.zst",
        1_547_940_938, "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
    ),
    Asset(
        "containerd", "2.2.1", "containerd-static-2.2.1-linux-amd64.tar.gz",
        "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz",
        33_645_699, "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
    ),
)

TOOL_COMMANDS = (
    ("ctr", "/usr/bin/ctr", ("--version",)),
    ("ip", "/usr/sbin/ip", ("-Version",)),
    ("tc", "/usr/sbin/tc", ("-Version",)),
    ("nft", "/usr/sbin/nft", ("--version",)),
    ("ssh", "/usr/bin/ssh", ("-V",)),
    ("ssh-keygen", "/usr/bin/ssh-keygen", ("-?",)),
)


def _fixed_preflight(require_approval, approval_value=APPROVAL_VALUE):
    _fail(platform.system() == "Linux", "wrong-platform")
    _fail(platform.machine() == "x86_64", "wrong-architecture")
    _fail(os.geteuid() == 0, "not-root")
    _fail(Path(__file__).resolve() == FIXED_SCRIPT, "wrong-source-location")
    _fail(FIXED_SOURCE.resolve() == FIXED_SOURCE and FIXED_SOURCE.is_dir(), "wrong-source-location")
    for name in os.environ:
        upper = name.upper()
        _fail(not (upper in DENIED_ENV or upper.startswith("AWS_")), "ambient-authority")
    if require_approval:
        _fail(os.environ.get(APPROVAL_NAME) == approval_value, "artifact-approval-missing")
    else:
        _fail(APPROVAL_NAME not in os.environ, "ambient-authority")


def _read_regular(path, maximum, mode=None):
    path = Path(path)
    parent = _open_directory_nofollow(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        _fail(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, "fixed-file-policy")
        if mode is not None:
            _fail(stat.S_IMODE(before.st_mode) == mode, "fixed-file-policy")
        chunks = []
        total = 0
        while total < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - total))
            _fail(type(chunk) is bytes and chunk, "fixed-file-read")
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        _fail((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "fixed-file-drift")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _strict_json(raw, maximum=MAX_JSON):
    _fail(type(raw) is bytes and 0 < len(raw) <= maximum and b"\x00" not in raw, "state-json")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except CandidateError:
        raise
    except Exception as error:
        raise CandidateError("state-json") from error


def _pairs(rows):
    value = {}
    for key, item in rows:
        _fail(type(key) is str and key not in value, "state-json")
        value[key] = item
    return value


def _kind(observed):
    if stat.S_ISREG(observed.st_mode):
        return "file"
    if stat.S_ISDIR(observed.st_mode):
        return "directory"
    if stat.S_ISCHR(observed.st_mode):
        return "character"
    return "other"


def _identity(observed):
    return {
        "dev": observed.st_dev, "ino": observed.st_ino, "kind": _kind(observed),
        "mode": stat.S_IMODE(observed.st_mode), "uid": observed.st_uid, "gid": observed.st_gid,
        "nlink": observed.st_nlink, "size": observed.st_size,
    }


def _asset_generation(descriptor, deadline_ns):
    _fail(type(descriptor) is int and type(deadline_ns) is int and
          time.monotonic_ns() < deadline_ns, "asset-generation")
    duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
    try:
        before = os.fstat(duplicate)
        fdinfo = os.open(f"/proc/self/fdinfo/{duplicate}", os.O_RDONLY | os.O_CLOEXEC)
        try:
            raw = os.read(fdinfo, 4097)
        finally:
            os.close(fdinfo)
        after = os.fstat(duplicate)
        fields = {}
        for name, value in (line.split(b":", 1) for line in raw.splitlines() if b":" in line):
            fields.setdefault(name, []).append(value.strip())
        _fail(
            len(raw) <= 4096 and len(fields.get(b"mnt_id", ())) == 1 and len(fields.get(b"ino", ())) == 1 and
            fields[b"mnt_id"][0].isdigit() and fields[b"ino"][0].isdigit() and
            int(fields[b"mnt_id"][0]) > 0 and int(fields[b"ino"][0]) == before.st_ino and
            _identity(before) == _identity(after) and before.st_mtime_ns == after.st_mtime_ns and
            before.st_ctime_ns == after.st_ctime_ns and time.monotonic_ns() < deadline_ns,
            "asset-generation",
        )
        return dict(zip(FULL_GENERATION, (int(fields[b"mnt_id"][0]), before.st_dev, before.st_ino,
            _kind(before), stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid, before.st_nlink,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns), strict=True))
    finally:
        os.close(duplicate)


def _same_identity(observed, expected, include_size=True, include_nlink=True):
    actual = _identity(observed)
    names = ("dev", "ino", "kind", "mode", "uid", "gid")
    if include_size:
        names += ("size",)
    if include_nlink:
        names += ("nlink",)
    return type(expected) is dict and all(actual.get(name) == expected.get(name) for name in names)


def _same_directory_authority(observed, expected):
    return type(expected) is dict and expected.get("kind") == "directory" and _same_identity(
        observed, expected, include_size=False, include_nlink=False,
    )


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        count = os.write(descriptor, raw[offset:])
        _fail(type(count) is int and count > 0, "state-write")
        offset += count


def _mkdir_policy(path, mode=0o700, create=True):
    created = False
    try:
        os.mkdir(path, mode)
        created = True
    except FileExistsError:
        _fail(not create, "state-preexisting")
    observed = os.stat(path, follow_symlinks=False)
    _fail(stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
          stat.S_IMODE(observed.st_mode) == mode, "state-policy")
    return created, _identity(observed)


def _fsync_directory(path):
    descriptor = _open_directory_nofollow(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _journal_record(sequence, previous, kind, body):
    unsigned = {"sequence": sequence, "previous": previous, "kind": kind, "body": body}
    digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
    return {**unsigned, "sha256": digest}


def _parse_journal(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_JOURNAL and raw.endswith(b"\n"), "journal-invalid")
    records = []
    previous = "0" * 64
    for sequence, line in enumerate(raw.splitlines()):
        value = _strict_json(line + b"\n", MAX_JOURNAL)
        _fail(type(value) is dict and set(value) == {"sequence", "previous", "kind", "body", "sha256"}, "journal-invalid")
        expected = _journal_record(sequence, previous, value["kind"], value["body"])
        _fail(value == expected, "journal-invalid")
        records.append(value)
        previous = value["sha256"]
    _fail(records and records[0]["kind"] == "genesis", "journal-invalid")
    return records


def _trusted_chain(path):
    path = Path(path)
    _fail(path.is_absolute(), "anchor-invalid")
    descriptors = []
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(descriptor)
        root_identity = _identity(os.fstat(descriptor))
        _fail(root_identity["kind"] == "directory" and root_identity["uid"] == root_identity["gid"] == 0 and
              root_identity["mode"] & 0o022 == 0, "anchor-chain-policy")
        values = [{"path": "/", "identity": root_identity}]
        current = Path("/")
        for component in path.parts[1:]:
            descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=descriptor)
            descriptors.append(descriptor)
            current /= component
            identity = _identity(os.fstat(descriptor))
            _fail(identity["kind"] == "directory" and identity["uid"] == identity["gid"] == 0 and
                  identity["mode"] & 0o022 == 0, "anchor-chain-policy")
            values.append({"path": str(current), "identity": identity})
        return values
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_trusted_chain(expected):
    actual = _trusted_chain(STATE.parent)
    _fail(type(expected) is list and len(actual) == len(expected), "anchor-chain-replaced")
    for observed, trusted in zip(actual, expected, strict=True):
        _fail(type(trusted) is dict and observed["path"] == trusted.get("path") and
              _same_directory_authority(_stat_value(observed["identity"]), trusted.get("identity")),
              "anchor-chain-replaced")


def _stat_value(identity):
    class Value:
        pass
    value = Value()
    value.st_dev = identity["dev"]; value.st_ino = identity["ino"]
    value.st_mode = identity["mode"] | (stat.S_IFDIR if identity["kind"] == "directory" else stat.S_IFREG)
    value.st_uid = identity["uid"]; value.st_gid = identity["gid"]
    value.st_nlink = identity["nlink"]; value.st_size = identity["size"]
    return value


def _parse_anchor(raw):
    value = _strict_json(raw, MAX_JSON)
    _fail(type(value) is dict and set(value) == {
        "version", "source_revision", "source_manifest_sha256", "trusted_parent_chain", "state", "journal",
    }, "anchor-invalid")
    _fail(value["version"] == ANCHOR_VERSION and
          type(value["source_revision"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]) and
          type(value["source_manifest_sha256"]) is str and HEX.fullmatch(value["source_manifest_sha256"]) and
          _canonical(value) + b"\n" == raw, "anchor-invalid")
    return value


def _validate_anchored_nodes(anchor, state_observed, journal_observed):
    _fail(_same_directory_authority(state_observed, anchor["state"]) and
          _same_identity(journal_observed, anchor["journal"], include_size=False), "anchor-node-replaced")


def _anchored_nodes(anchor):
    parent = _open_directory_nofollow(STATE.parent)
    state = None
    journal = None
    try:
        state = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        journal = os.open(JOURNAL.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        state_observed = os.fstat(state)
        journal_observed = os.fstat(journal)
        _validate_anchored_nodes(anchor, state_observed, journal_observed)
        return state_observed, journal_observed
    finally:
        if journal is not None:
            os.close(journal)
        if state is not None:
            os.close(state)
        os.close(parent)


def _load_anchor():
    raw = _read_regular(ANCHOR, MAX_JSON, 0o400)
    anchor = _parse_anchor(raw)
    observed = os.stat(ANCHOR, follow_symlinks=False)
    _fail(stat.S_ISREG(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
          observed.st_nlink == 1 and stat.S_IMODE(observed.st_mode) == 0o400, "anchor-policy")
    _verify_trusted_chain(anchor["trusted_parent_chain"])
    _anchored_nodes(anchor)
    return anchor, hashlib.sha256(raw).hexdigest()


def _read_journal_unanchored():
    raw = _read_regular(JOURNAL, MAX_JOURNAL, 0o600)
    records = _parse_journal(raw)
    genesis = records[0]["body"]
    parent = _open_directory_nofollow(STATE.parent)
    state = None
    try:
        state = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        journal = os.stat(JOURNAL.name, dir_fd=state, follow_symlinks=False)
        _fail(_same_directory_authority(os.fstat(state), genesis["state"]) and
              _same_identity(journal, genesis["journal"], include_size=False), "journal-replaced")
    finally:
        if state is not None:
            os.close(state)
        os.close(parent)
    return records


def _append_journal(kind, body):
    _fail(type(kind) is str and re.fullmatch(r"[a-z0-9-]{1,64}", kind) and type(body) is dict, "journal-invalid")
    records = _read_journal_unanchored()
    record = _journal_record(len(records), records[-1]["sha256"], kind, body)
    raw = _canonical(record) + b"\n"
    state = _open_dir(STATE)
    descriptor = None
    try:
        descriptor = os.open(
            JOURNAL.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state,
        )
        before = os.fstat(descriptor)
        _fail(_same_identity(before, records[0]["body"]["journal"], include_size=False), "journal-replaced")
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(state)
    _fail(_read_journal_unanchored()[-1] == record, "journal-invalid")
    return record


def _initialize_state(revision, manifest_sha256):
    state_parent = FIXED_SOURCE / "deploy/aws-feasibility/.state"
    completion = STATE.parent
    _fail(_held_path_absent(ROOTFS_STATE), "rootfs-baseline-present")
    _fail(_held_path_absent(ANCHOR), "anchor-preexisting")
    state_parent_created, state_parent_identity = _mkdir_policy(
        state_parent, create=_held_path_absent(state_parent),
    )
    completion_created, completion_identity = _mkdir_policy(
        completion, create=_held_path_absent(completion),
    )
    _fail(_held_path_absent(STATE), "state-preexisting")
    os.mkdir(STATE, 0o700)
    state_identity = _identity(os.stat(STATE, follow_symlinks=False))
    _fail(state_identity["uid"] == state_identity["gid"] == 0 and state_identity["mode"] == 0o700, "state-policy")
    journal = os.open(JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    anchor = None
    try:
        anchor = os.open(ANCHOR, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.fchmod(journal, 0o600); os.fchmod(anchor, 0o400)
        journal_identity = _identity(os.fstat(journal))
        anchor_value = {
            "version": ANCHOR_VERSION, "source_revision": revision,
            "source_manifest_sha256": manifest_sha256, "trusted_parent_chain": _trusted_chain(STATE.parent),
            "state": state_identity, "journal": journal_identity,
        }
        anchor_raw = _canonical(anchor_value) + b"\n"
        _write_all(anchor, anchor_raw); os.fsync(anchor)
        anchor_identity = _identity(os.fstat(anchor))
        body = {
            "version": "cogs.stage2-phase-a-ownership/v2", "state": state_identity,
            "journal": journal_identity, "anchor": anchor_identity,
            "anchor_sha256": hashlib.sha256(anchor_raw).hexdigest(), "rootfs_baseline": {"present": False},
            "created_parents": {
                "state_parent": state_parent_created, "state_parent_identity": state_parent_identity,
                "completion": completion_created, "completion_identity": completion_identity,
            },
        }
        _write_all(journal, _canonical(_journal_record(0, "0" * 64, "genesis", body)) + b"\n")
        os.fsync(journal)
    finally:
        if anchor is not None:
            os.close(anchor)
        os.close(journal)
    _fsync_directory(STATE); _fsync_directory(STATE.parent)
    _fsync_directory(STATE.parent.parent); _fsync_directory(STATE.parent.parent.parent)
    _require_state()


def _validate_anchor_journal(anchor, anchor_sha256, genesis, anchor_observed):
    _fail(genesis.get("anchor_sha256") == anchor_sha256 and genesis.get("state") == anchor["state"] and
          genesis.get("journal") == anchor["journal"] and
          _same_identity(anchor_observed, genesis.get("anchor")), "anchor-journal-mismatch")


def _require_state():
    anchor, anchor_sha256 = _load_anchor()
    _verify_fixed_source(anchor["source_revision"], anchor["source_manifest_sha256"])
    records = _read_journal_unanchored()
    anchor_observed = os.stat(ANCHOR, follow_symlinks=False)
    _validate_anchor_journal(anchor, anchor_sha256, records[0]["body"], anchor_observed)
    return records


def _write_json_once(path, value, record_kind=None):
    raw = _canonical(value) + b"\n"
    _fail(len(raw) <= MAX_JSON, "state-json")
    if record_kind is not None and VERSION == PHASE_B_VERSION:
        _fail(record_kind.endswith("-owned"), "journal-invalid")
        _append_journal(record_kind[:-5] + "intent", {"name": path.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        identity = _identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)
    if record_kind is not None:
        _append_journal(record_kind, {"name": path.name, "identity": identity, "sha256": hashlib.sha256(raw).hexdigest()})
    return raw


def _source_approval():
    raw = _read_regular(SOURCE_MANIFEST, MAX_SOURCE_MANIFEST, 0o400)
    value = _strict_json(raw, MAX_SOURCE_MANIFEST)
    revision = value.get("revision") if type(value) is dict else None
    _fail(type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "source-manifest")
    return revision, hashlib.sha256(raw).hexdigest()


def _verify_fixed_source(revision, manifest_sha256):
    """Use the existing fd-relative source authority before opening any owner."""
    sys.path.insert(0, str(REMOTE))
    import completion_rootfs_fs as fs
    control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
    root = fs._open_workspace_anchor(control)
    chain = None
    try:
        chain = fs._open_anchored_chain(root, fs._fixed_policies()[:5], control)
        manifest = fs._verify_source_bundle(
            chain.components[4].node, fs.SourceApproval(revision, manifest_sha256), control,
        )
        _fail(manifest.revision == revision and manifest.digest == manifest_sha256, "source-authority")
        fs._revalidate_chain(chain, control)
    finally:
        if chain is not None:
            fs._close_chain(chain)
        elif root.identity_fd.disposition == "open":
            fs._close_node(root)


def _group_absent(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _terminate_group(process):
    for sent, wait in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 3)):
        try:
            os.killpg(process.pid, sent)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            continue
        if sent == signal.SIGKILL:
            break
    _fail(process.poll() is not None and _group_absent(process.pid), "host-tool-unreaped")


def _stream_command(path, arguments, allowed):
    _fail(type(HOST_TOOL_SECONDS) is int and HOST_TOOL_SECONDS > 0, "host-tool-timeout")
    process = subprocess.Popen(
        (path, *arguments), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        close_fds=True, start_new_session=True,
    )
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline_ns = time.monotonic_ns() + HOST_TOOL_SECONDS * NS_PER_SECOND
    try:
        _fail(process.stdout is not None, "host-tool-output")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        eof = False
        while not eof:
            if time.monotonic_ns() >= deadline_ns:
                _terminate_group(process)
                raise CandidateError("host-tool-timeout")
            events = selector.select(0.1)
            if not events:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, min(1024, MAX_TOOL_OUTPUT + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    eof = True
                    break
                output.extend(chunk)
                if len(output) > MAX_TOOL_OUTPUT:
                    _terminate_group(process)
                    raise CandidateError("host-tool-output")
        while process.poll() is None:
            if time.monotonic_ns() >= deadline_ns:
                _terminate_group(process)
                raise CandidateError("host-tool-timeout")
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
        _fail(process.returncode in allowed, "host-tool-output")
        if not _group_absent(process.pid):
            _terminate_group(process)
            raise CandidateError("host-tool-descendants")
        return bytes(output)
    except BaseException:
        _terminate_group(process)
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()


def _file_digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _fail(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_TOOL_BYTES, "host-tool-policy")
        digest = hashlib.sha256()
        total = 0
        while total < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - total))
            _fail(type(chunk) is bytes and chunk, "host-tool-policy")
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        _fail(_same_identity(after, _identity(before)), "host-tool-drift")
        return before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _bounded_command(path, arguments, allowed=(0,)):
    observed = os.stat(path, follow_symlinks=False)
    _fail(stat.S_ISREG(observed.st_mode) and observed.st_size <= MAX_TOOL_BYTES and
          observed.st_uid == 0 and stat.S_IMODE(observed.st_mode) & 0o022 == 0, "host-tool-policy")
    output = _stream_command(path, arguments, allowed)
    line = output.decode("utf-8", "replace").splitlines()
    version = line[0][:256] if line else "no-output"
    size, digest = _file_digest(path)
    return {"name": "", "path": path, "present": True, "size": size, "sha256": digest, "version": version}


def _host_tools():
    rows = []
    codes = []
    for name, path, arguments in TOOL_COMMANDS:
        try:
            row = _bounded_command(path, arguments, (0, 1))
            row["name"] = name
        except CandidateError as error:
            codes.append(error.code)
            row = {"name": name, "path": path, "present": False, "size": None, "sha256": None, "version": None}
        except (OSError, subprocess.SubprocessError):
            codes.append("host-tool-missing")
            row = {"name": name, "path": path, "present": False, "size": None, "sha256": None, "version": None}
        rows.append(row)
    return rows, list(dict.fromkeys(codes))


def _prove_kvm():
    """Prove the kernel KVM ABI directly, without installing or starting anything."""
    device = os.stat("/dev/kvm", follow_symlinks=False)
    _fail(stat.S_ISCHR(device.st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK), "kvm-inaccessible")
    descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _fail((before.st_dev, before.st_ino) == (device.st_dev, device.st_ino), "kvm-device-drift")
        # linux/kvm.h: _IO(KVMIO, 0x00), where KVMIO is 0xAE.
        api_version = fcntl.ioctl(descriptor, KVM_GET_API_VERSION)
        _fail(type(api_version) is int and api_version == 12, "kvm-api-version")
        after = os.fstat(descriptor)
        _fail((before.st_dev, before.st_ino, before.st_rdev) ==
              (after.st_dev, after.st_ino, after.st_rdev), "kvm-device-drift")
    finally:
        os.close(descriptor)
    return {"device_present": True, "device_accessible": True, "api_version": 12}


def _strict_url(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
        value.encode("ascii")
    except (ValueError, UnicodeError) as error:
        raise CandidateError("asset-url") from error
    _fail(parsed.scheme == "https" and port is None and parsed.username is None and parsed.password is None and
          not parsed.fragment and parsed.netloc == parsed.hostname and parsed.path.startswith("/") and
          "\\" not in parsed.path and "//" not in parsed.path and
          all(part not in {".", ".."} for part in parsed.path.split("/")), "asset-url")
    return parsed


def _headers(response):
    rows = response.getheaders()
    _fail(type(rows) is list and len(rows) <= 64, "asset-headers")
    values = {}
    total = 0
    for name, value in rows:
        _fail(type(name) is str and type(value) is str and name.lower() not in values, "asset-headers")
        total += len(name) + len(value) + 4
        _fail(total <= 32768 and all(31 < ord(char) < 127 for char in name + value), "asset-headers")
        values[name.lower()] = value
    _fail(not ({"set-cookie", "authorization", "proxy-authorization", "content-encoding"} & set(values)), "asset-headers")
    return values


def _socket_timeout_seconds(deadline_ns):
    _fail(type(deadline_ns) is int, "asset-timeout")
    remaining_ns = deadline_ns - time.monotonic_ns()
    _fail(remaining_ns > 0, "asset-timeout")
    seconds = remaining_ns // NS_PER_SECOND
    _fail(seconds > 0 and seconds * NS_PER_SECOND <= remaining_ns, "asset-timeout")
    return seconds


def _request(url, deadline_ns):
    parsed = _strict_url(url)
    timeout_seconds = _socket_timeout_seconds(deadline_ns)
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    _fail(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "asset-tls")
    connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=timeout_seconds, context=context)
    try:
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", parsed.hostname)
        connection.putheader("User-Agent", "cogs-stage2-phase-a/1")
        connection.putheader("Accept", "application/octet-stream")
        connection.putheader("Connection", "close")
        connection.timeout = _socket_timeout_seconds(deadline_ns)
        connection.endheaders()
        timeout_seconds = _socket_timeout_seconds(deadline_ns)
        if connection.sock is not None:
            connection.sock.settimeout(timeout_seconds)
        response = connection.getresponse()
        _fail(time.monotonic_ns() < deadline_ns, "asset-timeout")
        return connection, response
    except Exception:
        connection.close()
        raise


def _redirect_target(asset, location):
    parsed = _strict_url(location)
    _fail(parsed.hostname == "release-assets.githubusercontent.com" and
          parsed.path.startswith("/github-production-release-asset/") and
          0 < len(parsed.query) <= 8192, "asset-redirect")
    original = _strict_url(asset.url)
    _fail(original.hostname == "github.com" and original.query == "", "asset-url")
    return location


def _digest_descriptor(descriptor, size):
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        _fail(type(chunk) is bytes and chunk, "owned-digest")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _owned_file(directory, name, expected, digest):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        observed = os.fstat(descriptor)
        _fail(_same_identity(observed, expected) and _digest_descriptor(descriptor, observed.st_size) == digest,
              "owned-replaced")
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _fail(_same_identity(named, expected), "owned-replaced")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _check_asset_deadline(deadline_ns, stage):
    _fail(type(deadline_ns) is int and type(stage) is str and time.monotonic_ns() < deadline_ns, "asset-timeout")


def _freeze_partial(asset, assets_fd, descriptor, partial, deadline_ns, publication):
    _check_asset_deadline(deadline_ns, "after-final-eof")
    os.fsync(descriptor)
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
    _check_asset_deadline(deadline_ns, "after-content-fsync")
    _fail(_digest_descriptor(descriptor, asset.size) == asset.sha256, "asset-publish")
    retained = os.open(partial.name, O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=assets_fd)
    try:
        held = _asset_generation(retained, deadline_ns)
        _fail(_asset_generation(descriptor, deadline_ns) == held, "asset-partial-replaced")
        _check_asset_deadline(deadline_ns, "after-retained-open")
        publication["writer_close_attempted"] = True
        os.close(descriptor)
        _check_asset_deadline(deadline_ns, "after-writer-close")
        named_fd = os.open(partial.name, O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=assets_fd)
        with os.fdopen(named_fd, "rb", closefd=True) as named:
            named_generation = _asset_generation(named.fileno(), deadline_ns)
        _fail(_asset_generation(retained, deadline_ns) == held == named_generation and
              tuple(held[name] for name in ("kind", "mode", "uid", "gid", "nlink", "size")) ==
              ("file", 0o400, 0, 0, 1, asset.size), "asset-partial-replaced")
        _check_asset_deadline(deadline_ns, "after-held-name-proof")
        _append_journal("asset-partial-final-owned",
                        {"component": asset.component, "name": partial.name, "generation": held})
        _check_asset_deadline(deadline_ns, "after-partial-final-journal")
        publication.update({"partial_final": held, "retained": retained})
        return retained
    except BaseException:
        os.close(retained)
        raise


def _publish_asset(asset, assets_fd, descriptor, partial, final, partial_identity, deadline_ns, publication):
    descriptor = _freeze_partial(asset, assets_fd, descriptor, partial, deadline_ns, publication)
    held = os.fstat(descriptor)
    _check_asset_deadline(deadline_ns, "after-redigest")
    _check_asset_deadline(deadline_ns, "before-link")
    os.link(partial.name, final.name, src_dir_fd=assets_fd, dst_dir_fd=assets_fd, follow_symlinks=False)
    publication["linked"] = True
    linked = os.stat(final.name, dir_fd=assets_fd, follow_symlinks=False)
    _fail((linked.st_dev, linked.st_ino) == (held.st_dev, held.st_ino) and linked.st_nlink == 2,
          "asset-publish")
    _check_asset_deadline(deadline_ns, "after-link")
    publication["partial_unlinked"] = True
    os.unlink(partial.name, dir_fd=assets_fd)
    _check_asset_deadline(deadline_ns, "after-unlink")
    os.fsync(assets_fd)
    _check_asset_deadline(deadline_ns, "after-directory-fsync")
    final_identity = _identity(os.stat(final.name, dir_fd=assets_fd, follow_symlinks=False))
    reader = _owned_file(assets_fd, final.name, final_identity, asset.sha256)
    os.close(reader)
    _fail(final_identity["nlink"] == 1, "asset-publish")
    _check_asset_deadline(deadline_ns, "after-final-redigest")
    _check_asset_deadline(deadline_ns, "before-journal")
    _append_journal("asset-final-owned", {
        "component": asset.component, "name": final.name, "identity": final_identity, "sha256": asset.sha256,
    })
    publication["journaled"] = True
    _check_asset_deadline(deadline_ns, "after-journal")
    return {"component": asset.component, "release": asset.release, "name": asset.name,
            "size": asset.size, "sha256": asset.sha256, "downloaded": True, "extracted": False}


def _finish_asset_publication(asset, assets_fd, descriptor, partial, final, partial_identity,
                              deadline_ns, publication):
    result = _publish_asset(
        asset, assets_fd, descriptor, partial, final, partial_identity, deadline_ns, publication,
    )
    _check_asset_deadline(deadline_ns, "before-return")
    return result


def _cleanup_failed_asset_publication(assets_fd, partial, publication, immediate, component, deadline_ns):
    if publication["partial_unlinked"]:
        immediate[component] = "post-unlink-uncertainty"
        raise CandidateError("asset-immediate-cleanup-uncertainty")
    if publication["journaled"]:
        return
    generation = publication["partial_final"]
    if generation is None or publication["linked"]:
        immediate[component] = "preserved"
        return
    descriptor = os.open(partial.name, O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=assets_fd)
    close_attempted = False
    try:
        _fail(_asset_generation(descriptor, deadline_ns) == generation and generation["nlink"] == 1,
              "asset-partial-replaced")
        publication["partial_unlinked"] = True
        os.unlink(partial.name, dir_fd=assets_fd)
        os.fsync(assets_fd)
        close_attempted = True
        os.close(descriptor)
        immediate[component] = "success"
    except BaseException:
        immediate[component] = "post-unlink-uncertainty" if publication["partial_unlinked"] else "preserved"
        raise
    finally:
        if not close_attempted:
            os.close(descriptor)


def _download_asset(asset, outer_deadline_ns, immediate):
    _fail(type(asset) is Asset and HEX.fullmatch(asset.sha256) is not None and
          type(DOWNLOAD_SECONDS) is int and DOWNLOAD_SECONDS > 0, "asset-contract")
    _fail(type(outer_deadline_ns) is int, "asset-timeout")
    now_ns = time.monotonic_ns()
    deadline_ns = min(outer_deadline_ns, now_ns + DOWNLOAD_SECONDS * NS_PER_SECOND)
    _fail(now_ns < deadline_ns, "asset-timeout")
    final = ASSETS / asset.name
    partial = ASSETS / ("." + asset.name + ".partial")
    _append_journal("asset-intent", {"component": asset.component, "partial": partial.name, "final": final.name})
    descriptor = None
    partial_identity = None
    connection = response = None
    published = False
    publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                   "retained": None, "linked": False, "partial_unlinked": False}
    assets_fd = _open_dir(ASSETS)
    try:
        _fail(_held_path_absent(final) and _held_path_absent(partial), "asset-no-overwrite")
        descriptor = os.open(
            partial.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=assets_fd,
        )
        partial_identity = _identity(os.fstat(descriptor))
        _append_journal("asset-partial-owned", {
            "component": asset.component, "name": partial.name, "identity": partial_identity,
        })
        connection, response = _request(asset.url, deadline_ns)
        headers = _headers(response)
        _fail(response.status in {301, 302, 303, 307, 308}, "asset-redirect")
        _fail(headers.get("content-length") is not None and headers["content-length"].isdigit() and
              int(headers["content-length"]) <= 4096 and "transfer-encoding" not in headers, "asset-redirect")
        timeout_seconds = _socket_timeout_seconds(deadline_ns)
        if connection.sock is not None:
            connection.sock.settimeout(timeout_seconds)
        body = response.read(4097)
        _fail(len(body) == int(headers["content-length"]), "asset-redirect")
        target = _redirect_target(asset, headers.get("location", ""))
        response.close(); connection.close(); response = connection = None
        connection, response = _request(target, deadline_ns)
        headers = _headers(response)
        _fail(response.status == 200 and headers.get("content-length") == str(asset.size) and
              headers.get("content-type", "").strip().lower() == "application/octet-stream" and
              "transfer-encoding" not in headers, "asset-response")
        digest = hashlib.sha256()
        total = 0
        while total < asset.size:
            timeout_seconds = _socket_timeout_seconds(deadline_ns)
            if connection.sock is not None:
                connection.sock.settimeout(timeout_seconds)
            chunk = response.read(min(1024 * 1024, asset.size - total))
            _fail(type(chunk) is bytes and chunk, "asset-body")
            offset = 0
            while offset < len(chunk):
                written = os.write(descriptor, chunk[offset:])
                _fail(type(written) is int and written > 0, "asset-body")
                offset += written
            digest.update(chunk)
            total += len(chunk)
        timeout_seconds = _socket_timeout_seconds(deadline_ns)
        if connection.sock is not None:
            connection.sock.settimeout(timeout_seconds)
        _fail(response.read(1) == b"" and total == asset.size and digest.hexdigest() == asset.sha256, "asset-digest")
        result = _finish_asset_publication(
            asset, assets_fd, descriptor, partial, final, partial_identity, deadline_ns, publication,
        )
        published = True
        return result
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        try:
            if not published and descriptor is not None:
                if partial_identity is None: immediate[asset.component] = "preserved"
                else: _cleanup_failed_asset_publication(assets_fd, partial, publication, immediate,
                                                        asset.component, deadline_ns)
        finally:
            try:
                if descriptor is not None and not publication["writer_close_attempted"]: os.close(descriptor)
                if publication["retained"] is not None: os.close(publication["retained"])
                os.close(assets_fd)
            except BaseException:
                if publication["partial_unlinked"]: immediate[asset.component] = "post-unlink-uncertainty"
                raise


def _artifact_rows(contract):
    rows = [contract["oci"][key] for key in ("index", "manifest", "config", "layer")]
    rows.extend(contract["snapshot"][key] for key in ("inrelease", "packages_index"))
    rows.extend(contract["packages"])
    _fail(len(rows) == 16 and len({row["cache_name"] for row in rows}) == 16, "cache-contract")
    return tuple(rows)


def _snapshot_cache(contract):
    root = _open_dir(ARTIFACT_ROOT)
    cache = None
    try:
        _fail(set(os.listdir(root)) == {"cache", ".cogs-stage2-completion-artifacts-v1"}, "cache-inventory")
        cache = os.open("cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        cache_identity = _identity(os.fstat(cache))
        _fail(cache_identity["kind"] == "directory" and cache_identity["mode"] == 0o700 and
              cache_identity["uid"] == cache_identity["gid"] == 0, "cache-identity")
        rows = _artifact_rows(contract)
        _fail(set(os.listdir(cache)) == {row["cache_name"] for row in rows}, "cache-inventory")
        files = []
        for row in sorted(rows, key=lambda item: item["cache_name"]):
            descriptor = os.open(row["cache_name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cache)
            try:
                observed = os.fstat(descriptor)
                identity = _identity(observed)
                _fail(identity["kind"] == "file" and identity["mode"] == 0o400 and identity["uid"] == 0 and
                      identity["gid"] == 0 and identity["nlink"] == 1 and identity["size"] == row["size"] and
                      _digest_descriptor(descriptor, row["size"]) == row["sha256"], "cache-identity")
                files.append({"name": row["cache_name"], "identity": identity, "sha256": row["sha256"]})
            finally:
                os.close(descriptor)
        sentinel = _read_regular(ARTIFACT_ROOT / ".cogs-stage2-completion-artifacts-v1", 128, 0o600)
        sentinel_identity = _identity(os.stat(ARTIFACT_ROOT / ".cogs-stage2-completion-artifacts-v1", follow_symlinks=False))
        _fail(sentinel_identity["kind"] == "file" and sentinel_identity["mode"] == 0o600 and
              sentinel_identity["uid"] == sentinel_identity["gid"] == 0 and sentinel_identity["nlink"] == 1,
              "cache-identity")
        return {"root": _identity(os.fstat(root)), "cache": cache_identity, "sentinel": {
            "identity": sentinel_identity, "sha256": hashlib.sha256(sentinel).hexdigest(),
        }, "files": files}
    finally:
        if cache is not None:
            os.close(cache)
        os.close(root)


def _snapshot_rootfs_lifecycle():
    root = _open_dir(ROOTFS_STATE)
    try:
        names = {".cogs-stage2-rootfs-lock-v1", ".cogs-stage2-rootfs-state-v1"}
        _fail(set(os.listdir(root)) == names, "rootfs-lifecycle-inventory")
        files = []
        for name in sorted(names):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            try:
                observed = os.fstat(descriptor)
                identity = _identity(observed)
                _fail(identity["kind"] == "file" and identity["uid"] == identity["gid"] == 0 and
                      identity["mode"] == 0o600 and identity["nlink"] == 1, "rootfs-lifecycle-identity")
                files.append({"name": name, "identity": identity,
                              "sha256": _digest_descriptor(descriptor, identity["size"])})
            finally:
                os.close(descriptor)
        return {"root": _identity(os.fstat(root)), "files": files}
    finally:
        os.close(root)


def _same_rootfs_lifecycle(observed, expected):
    if (type(observed) is not dict or type(expected) is not dict or
            set(observed) != {"root", "files"} or set(expected) != {"root", "files"}):
        return False
    try:
        root_matches = _same_directory_authority(_stat_value(observed["root"]), expected["root"])
    except (KeyError, TypeError):
        return False
    return root_matches and observed["files"] == expected["files"]


def _rootfs_call(code, callback):
    try:
        return callback()
    except BaseException as error:
        raise CandidateError(code) from error


def _empty_phases():
    return [{"phase": name, "status": "not-reached", "outcome": "observer-ended",
             "elapsed_ms": 0, "structural_counters": None} for name in ROOTFS_PHASES]


def _phase(phases, name):
    _fail(type(phases) is list and len(phases) == len(ROOTFS_PHASES), "rootfs-phase-contract")
    index = ROOTFS_PHASES.index(name)
    _fail(phases[index].get("phase") == name, "rootfs-phase-contract")
    return phases[index]


def _validated_counters(value):
    _fail(type(value) is dict and set(value) == set(STRUCTURAL_COUNTERS) and all(
        type(item) is int and 0 <= item <= 1_000_000_000 for item in value.values()
    ), "rootfs-counter-contract")
    return dict(value)


def _zero_counters():
    return {name: 0 for name in STRUCTURAL_COUNTERS}


def _add_counters(left, right):
    left, right = _validated_counters(left), _validated_counters(right)
    return _validated_counters({name: left[name] + right[name] for name in STRUCTURAL_COUNTERS})


def _subtract_counters(minuend, subtrahend):
    minuend, subtrahend = _validated_counters(minuend), _validated_counters(subtrahend)
    _fail(all(subtrahend[name] <= minuend[name] for name in STRUCTURAL_COUNTERS),
          "rootfs-counter-contract")
    return _validated_counters({name: minuend[name] - subtrahend[name] for name in STRUCTURAL_COUNTERS})


def _counter_start(provider, name):
    expected_provider = "completion_rootfs_builder" if name == "recovery-attempt-1" else "completion_rootfs_build"
    _fail(type(provider) is type(sys) and provider.__name__ == expected_provider and name in ROOTFS_PHASES,
          "rootfs-counter-contract")
    start = getattr(provider, "_start_phase_structural_counters", None)
    read = getattr(provider, "_read_phase_structural_counters", None)
    _fail(callable(start) and callable(read), "rootfs-counter-contract")
    try:
        handle = start(name)
    except BaseException as error:
        raise CandidateError("rootfs-counter-contract") from error
    _fail(type(handle) is int and 0 <= handle <= (1 << 63) - 1, "rootfs-counter-contract")
    return read, name, handle


def _counter_read(ticket):
    _fail(type(ticket) is tuple and len(ticket) == 3 and callable(ticket[0]), "rootfs-counter-contract")
    read, name, handle = ticket
    try:
        value = read(name, handle)
    except BaseException as error:
        raise CandidateError("rootfs-counter-contract") from error
    return _validated_counters(value)


def _poison_phase(phases, name):
    row = _phase(phases, name)
    row.update({"status": "evidence-failure", "outcome": "counter-fault",
                "elapsed_ms": 0, "structural_counters": None})


def _set_phase(phases, name, status, outcome, elapsed_ns=0, counters=None):
    row = _phase(phases, name)
    attempted = status in {"success", "failure"}
    _fail(row["status"] == "not-reached" and status in {"success", "failure", "blocked"} and
          attempted == (counters is not None), "rootfs-phase-contract")
    row.update({"status": status, "outcome": outcome,
                "elapsed_ms": _elapsed_ms(elapsed_ns),
                "structural_counters": _validated_counters(counters) if attempted else None})


def _block_phases(phases, names):
    for name in names:
        if _phase(phases, name)["status"] == "not-reached":
            _set_phase(phases, name, "blocked", "prerequisite-failed")


def _elapsed_ns(started_ns):
    _fail(type(started_ns) is int, "timing-metadata")
    elapsed_ns = max(0, time.monotonic_ns() - started_ns)
    _fail(elapsed_ns <= 5_400 * NS_PER_SECOND, "timing-metadata")
    return elapsed_ns


def _elapsed_ms(elapsed_ns):
    _fail(type(elapsed_ns) is int and elapsed_ns >= 0, "timing-metadata")
    return elapsed_ns // NS_PER_MILLISECOND


def _stage(stages, name, status):
    if status == "attempting":
        stages[name] = {"status": status, "elapsed_ms": time.monotonic_ns()}
        return
    started = stages[name]["elapsed_ms"]
    elapsed_ms = _elapsed_ms(_elapsed_ns(started)) if status == "failure" else 0
    stages[name] = {"status": status, "elapsed_ms": elapsed_ms}


def _complete_stage_effect(stages, name):
    row = stages[name]
    _fail(type(row) is dict and row.get("status") == "attempting", "stage-timing-metadata")
    started = row.get("elapsed_ms")
    row["status"] = "effect-complete"
    try:
        elapsed_ms = _elapsed_ms(_elapsed_ns(started))
    except BaseException:
        stages[name] = None
        raise
    stages[name] = {"status": "success", "elapsed_ms": elapsed_ms}


def _candidate_build(build, approval, control, ordinal, token, phases, setup=None):
    work_name, cleanup_name = f"{ordinal}-build-work", f"{ordinal}-inline-cleanup"
    _fail(ordinal in {"first", "second"} and type(build.BUILD_SECONDS) is int and build.BUILD_SECONDS > 0 and
          type(token) is str and HEX.fullmatch(token) is not None and
          _phase(phases, work_name)["status"] == _phase(phases, cleanup_name)["status"] == "not-reached",
          "rootfs-build-contract")
    try:
        work_counter = _counter_start(build, work_name)
    except BaseException:
        _poison_phase(phases, work_name)
        raise
    materializer, builder = build.materializer, build.builder
    original_reload, original_cleanup = materializer._reload_and_cleanup, builder._cleanup_owned
    original_begin = original_materialize = None
    if setup is not None:
        original_begin, original_materialize = builder._begin_operation, materializer._materialize_unmasked
        def marked_begin(*args):
            value = original_begin(*args)
            setup["value"] = "materializer-dispatch"
            return value
        def marked_materialize(*args):
            setup["value"] = "complete"
            return original_materialize(*args)
        builder._begin_operation, materializer._materialize_unmasked = marked_begin, marked_materialize
    cleanup_depth = cleanup_elapsed_ns = cleanup_span_ns = cleanup_attempts = 0
    cleanup_statuses = []
    cleanup_counters = _zero_counters()
    evidence_fault = None

    def poison(caught):
        nonlocal evidence_fault
        evidence_fault = caught if evidence_fault is None else evidence_fault
        _poison_phase(phases, work_name)
        _poison_phase(phases, cleanup_name)

    def timed_cleanup(callback, *args):
        nonlocal cleanup_depth, cleanup_elapsed_ns, cleanup_span_ns, cleanup_attempts, cleanup_counters
        if cleanup_depth:
            return callback(*args)
        cleanup_attempts += 1
        try:
            span_started = time.monotonic_ns()
        except BaseException as caught:
            poison(caught)
            raise
        ticket = callback_started = callback_elapsed = counters = None
        result = callback_error = instrumentation_error = None
        try:
            try:
                ticket = _counter_start(build, cleanup_name)
                callback_started = time.monotonic_ns()
                cleanup_depth = 1
                try:
                    result = callback(*args)
                    cleanup_statuses.append("success")
                except BaseException as caught:
                    callback_error = caught
                    cleanup_statuses.append("failure")
                finally:
                    try:
                        callback_elapsed = _elapsed_ns(callback_started)
                    except BaseException as caught:
                        instrumentation_error = caught
                    cleanup_depth = 0
            except BaseException as caught:
                instrumentation_error = caught
            if ticket is not None:
                try:
                    counters = _counter_read(ticket)
                except BaseException as caught:
                    instrumentation_error = caught if instrumentation_error is None else instrumentation_error
            try:
                span_elapsed = _elapsed_ns(span_started)
            except BaseException as caught:
                span_elapsed = None
                instrumentation_error = caught if instrumentation_error is None else instrumentation_error
            if instrumentation_error is None:
                _fail(callback_elapsed <= span_elapsed, "rootfs-build-contract")
                cleanup_counters = _add_counters(cleanup_counters, counters)
                cleanup_elapsed_ns += callback_elapsed
                cleanup_span_ns += span_elapsed
        except BaseException as caught:
            instrumentation_error = caught if instrumentation_error is None else instrumentation_error
        if instrumentation_error is not None:
            poison(instrumentation_error)
            raise instrumentation_error
        if callback_error is not None:
            raise callback_error
        return result

    materializer._reload_and_cleanup = lambda *args: timed_cleanup(original_reload, *args)
    builder._cleanup_owned = lambda *args: timed_cleanup(original_cleanup, *args)
    started_ns = total_elapsed_ns = None
    error = None
    try:
        try:
            started_ns = time.monotonic_ns()
        except BaseException as caught:
            poison(caught)
            error = caught
            candidate = None
        else:
            try:
                candidate = build._build_once(approval, token, control)
            except BaseException as caught:
                error = caught
                candidate = None
        if started_ns is not None:
            try:
                total_elapsed_ns = _elapsed_ns(started_ns)
            except BaseException as caught:
                poison(caught)
    finally:
        materializer._reload_and_cleanup, builder._cleanup_owned = original_reload, original_cleanup
        if setup is not None:
            builder._begin_operation, materializer._materialize_unmasked = original_begin, original_materialize
    try:
        work_total = _counter_read(work_counter)
        if evidence_fault is None:
            work_counters = _subtract_counters(work_total, cleanup_counters)
            _fail(cleanup_span_ns <= total_elapsed_ns, "rootfs-build-contract")
    except BaseException as caught:
        poison(caught)
    if evidence_fault is not None:
        raise evidence_fault
    attempt_error = getattr(build, "BuildAttemptError", None)
    work_outcome = error.work_outcome if type(attempt_error) is type and type(error) is attempt_error else (
        "success" if error is None else "failed"
    )
    _fail(work_outcome in {"cancelled", "deadline", "failed", "not-started", "success"},
          "rootfs-build-contract")
    postwork = error is not None and work_outcome == "success"
    work_status = "success" if error is None else "failure"
    work_category = "success" if error is None else ("postwork" if postwork else work_outcome)
    cleanup_failed = "failure" in cleanup_statuses
    if setup is not None and setup["value"] != "complete":
        _fail(error is not None, "rootfs-build-contract")
        raise CandidateError(f"rootfs-{ordinal}-build-{work_category}") from error
    _set_phase(phases, work_name, work_status, work_category, total_elapsed_ns - cleanup_span_ns,
               work_counters)
    if not cleanup_attempts:
        _set_phase(phases, cleanup_name, "blocked", "prerequisite-failed")
    else:
        cleanup_status = "failure" if cleanup_failed else "success"
        _set_phase(phases, cleanup_name, cleanup_status, "failed" if cleanup_failed else "success",
                   cleanup_elapsed_ns, cleanup_counters)
    if error is not None:
        category = "inline-cleanup" if cleanup_failed else work_category
        raise CandidateError(f"rootfs-{ordinal}-build-{category}") from error
    _fail(cleanup_statuses == ["success"], "rootfs-build-contract")
    return candidate


def _timed_rootfs_phase(phases, name, code, provider, callback):
    try:
        ticket = _counter_start(provider, name)
    except BaseException:
        _poison_phase(phases, name)
        raise
    timing_error = callback_error = None
    started_ns = elapsed_ns = None
    value = None
    try:
        started_ns = time.monotonic_ns()
        try:
            value = callback()
        except BaseException as caught:
            callback_error = caught
        elapsed_ns = _elapsed_ns(started_ns)
    except BaseException as caught:
        timing_error = caught
    try:
        counters = _counter_read(ticket)
    except BaseException as caught:
        if timing_error is None:
            timing_error = caught
    if timing_error is not None:
        _poison_phase(phases, name)
        raise timing_error
    try:
        _set_phase(phases, name, "failure" if callback_error is not None else "success",
                   "failed" if callback_error is not None else "success", elapsed_ns, counters)
    except BaseException:
        _poison_phase(phases, name)
        raise
    if callback_error is not None:
        raise CandidateError(code) from callback_error
    return value


def _bootstrap_rootfs(builder, fs, approval, control):
    chain = None
    state = None
    error = None
    try:
        chain = builder._open_base_chain(control)
        state = builder._bootstrap(chain, approval, control)
    except BaseException as caught:
        error = caught
    if state is not None:
        try:
            fs._close_node(state)
            state = None
        except BaseException as caught:
            error = caught if error is None else fs.RootfsFsError(error, caught)
    if chain is not None:
        try:
            fs._close_chain(chain)
            chain = None
        except BaseException as caught:
            error = caught if error is None else fs.RootfsFsError(error, caught)
    if error is not None or state is not None or chain is not None:
        raise CandidateError("rootfs-bootstrap") from error


def _acquisition_failure_code(stage):
    if stage in {"preflight"}:
        return "cache-acquisition-preflight"
    if stage in {"tls"}:
        return "cache-acquisition-tls"
    if stage in {"routes"}:
        return "cache-acquisition-routes"
    if stage in {"state"}:
        return "cache-acquisition-state"
    if stage in {"publish"}:
        return "cache-acquisition-publish"
    if stage in {"postverify"}:
        return "cache-postverify"
    if type(stage) is str and stage.startswith("token."):
        return "cache-acquisition-token"
    if type(stage) is str and stage.startswith("artifact.redirect"):
        return "cache-acquisition-redirect"
    if stage == "artifact.body":
        return "cache-acquisition-body"
    if type(stage) is str and stage.startswith("artifact."):
        return "cache-acquisition-response"
    return "cache-acquisition-unknown"


def _verifier_call(verifier, default_code, callback, acquisition=False):
    try:
        return callback()
    except CandidateError:
        raise
    except verifier.VerificationError as error:
        code = _acquisition_failure_code(error.stage) if acquisition else default_code
        raise CandidateError(code) from error
    except OSError as error:
        raise CandidateError(default_code) from error


def _load_artifact_verifier():
    import importlib.util
    verifier_path = REMOTE / "verify-completion-artifacts.py"
    spec = importlib.util.spec_from_file_location("phase_a_completion_artifacts", verifier_path)
    _fail(spec is not None and spec.loader is not None, "artifact-verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def _rootfs_candidates(revision, manifest_sha256, outer_deadline_ns, phases, stages, setup):
    sys.path.insert(0, str(REMOTE))
    import completion_rootfs_build as build
    import completion_rootfs_builder as builder
    import completion_rootfs_fs as fs
    import completion_rootfs_publish
    verifier = _load_artifact_verifier()
    _stage(stages, "artifact_cache", "attempting")
    setup["value"] = "fixed-input"

    contract = _verifier_call(
        verifier, "rootfs-contract-preflight", lambda: verifier.verify_contract(verifier.CONTRACT_PATH),
    )
    _append_journal("cache-intent", {"artifact_count": 16})
    _verifier_call(
        verifier, "cache-acquisition-unknown",
        lambda: verifier.acquire_completion_artifacts(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT), True,
    )
    _verifier_call(
        verifier, "cache-postverify",
        lambda: verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT),
    )
    cache_owned = _snapshot_cache(contract)
    _append_journal("cache-owned", cache_owned)
    setup["value"] = "rootfs-bootstrap"
    _complete_stage_effect(stages, "artifact_cache")
    _rootfs_call("rootfs-intent", lambda: _append_journal("rootfs-intent", {"baseline": "absent"}))
    approval = _rootfs_call("rootfs-bootstrap", lambda: fs.SourceApproval(revision, manifest_sha256))
    now_ns = _rootfs_call("rootfs-bootstrap", time.monotonic_ns)
    _fail(type(outer_deadline_ns) is int, "observe-timeout")
    deadline_ns = min(outer_deadline_ns, now_ns + build.OUTER_SECONDS * 1_000_000_000)
    _fail(now_ns < deadline_ns, "observe-timeout")
    control = _rootfs_call("rootfs-bootstrap", lambda: fs.OperationControl(deadline_ns, lambda: False))
    _bootstrap_rootfs(builder, fs, approval, control)
    rootfs_owned = _rootfs_call("rootfs-bootstrap", _snapshot_rootfs_lifecycle)
    _rootfs_call("rootfs-bootstrap", lambda: _append_journal("rootfs-lifecycle-owned", rootfs_owned))
    setup["value"] = "operation-establishment"
    first_token = _rootfs_call("rootfs-build-token", lambda: secrets.token_hex(32))
    second_token = _rootfs_call("rootfs-build-token", lambda: secrets.token_hex(32))
    _fail(type(first_token) is str and HEX.fullmatch(first_token) is not None and
          type(second_token) is str and HEX.fullmatch(second_token) is not None and
          first_token != second_token, "rootfs-build-token")
    try:
        first = _candidate_build(build, approval, control, "first", first_token, phases, setup)
    except BaseException:
        if setup["value"] == "complete":
            _block_phases(phases, ("second-build-work", "second-inline-cleanup", "equality", "pin",
                                   "post-verification", "settlement"))
        raise
    try:
        second = _candidate_build(build, approval, control, "second", second_token, phases)
    except BaseException:
        _block_phases(phases, ("equality", "pin", "post-verification", "settlement"))
        raise
    try:
        _timed_rootfs_phase(phases, "equality", "rootfs-equality", build,
                            lambda: build._require_equal_builds(first, second))
        def pinned():
            pins = completion_rootfs_publish._load_pins()
            build._require_pinned(first, pins)
            build._require_pinned(second, pins)
        _timed_rootfs_phase(phases, "pin", "rootfs-pin", build, pinned)
        def postverify():
            _verifier_call(verifier, "rootfs-postverify", lambda: verifier.verify_package_archives(
                verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT,
            ))
            _fail(_snapshot_cache(contract) == cache_owned, "rootfs-postverify")
        _timed_rootfs_phase(phases, "post-verification", "rootfs-postverify", build, postverify)
        def settle():
            _fail(_same_rootfs_lifecycle(_snapshot_rootfs_lifecycle(), rootfs_owned), "rootfs-settlement")
            return {
                "candidate_count": 2, "cache_count": len(first.cache), "entry_count": first.entry_count,
                "manifest_size": len(first.manifest), "manifest_sha256": first.manifest_sha256,
                "ustar_size": first.ustar_size, "ustar_sha256": first.ustar_sha256,
                "equal": True, "pins_match": True,
            }
        return _timed_rootfs_phase(phases, "settlement", "rootfs-settlement", build, settle)
    except BaseException:
        _block_phases(phases, ("equality", "pin", "post-verification", "settlement"))
        raise


def _observe():
    _fixed_preflight(True)
    revision, manifest_sha256 = _source_approval()
    _verify_fixed_source(revision, manifest_sha256)
    _initialize_state(revision, manifest_sha256)
    started = time.monotonic_ns()
    outer_deadline_ns = started + OBSERVE_SECONDS * 1_000_000_000
    immediate = {item.component: "not-required" for item in RUNTIME_ASSETS}
    stages = {name: {"status": "not-reached", "elapsed_ms": 0} for name in STAGE_NAMES}
    setup = {"value": "not-reached"}
    observation = {"status": "failed", "codes": [], "revision": revision, "source_manifest_sha256": manifest_sha256,
                   "host_tools": [], "kvm": None, "rootfs": None, "rootfs_phases": _empty_phases(),
                   "immediate_cleanup": immediate, "stage_evidence": stages,
                   "first_build_setup": "not-reached", "assets": []}
    try:
        observation["host_tools"], host_tool_codes = _host_tools()
        observation["kvm"] = _prove_kvm()
        observation["rootfs"] = _rootfs_candidates(
            revision, manifest_sha256, outer_deadline_ns, observation["rootfs_phases"], stages, setup,
        )
        _stage(stages, "runtime_assets", "attempting")
        _append_journal("asset-directory-intent", {"name": ASSETS.name})
        _fail(_held_path_absent(ASSETS), "asset-directory-preexisting")
        os.mkdir(ASSETS, 0o700)
        _fsync_directory(STATE)
        asset_dir_identity = _identity(os.stat(ASSETS, follow_symlinks=False))
        _fail(asset_dir_identity["uid"] == asset_dir_identity["gid"] == 0 and
              asset_dir_identity["mode"] == 0o700, "asset-directory-policy")
        _append_journal("asset-directory-owned", {"identity": asset_dir_identity})
        observation["assets"] = [
            _download_asset(asset, outer_deadline_ns, immediate) for asset in RUNTIME_ASSETS
        ]
        _complete_stage_effect(stages, "runtime_assets")
        observation["status"] = "observed"
        observation["codes"] = ["committed-attestations-absent", "qmp-kvm-attestation-not-collected",
                                "runtime-extraction-unsafe-or-unknown", "runtime-lifecycle-not-executed",
                                "network-authority-not-tested", "ssh-authority-not-tested"]
        observation["codes"].extend(host_tool_codes)
        if not all(row["present"] for row in observation["host_tools"]):
            observation["codes"].append("host-tool-missing")
        observation["codes"] = list(dict.fromkeys(observation["codes"]))
    except CandidateError as error:
        for name in ("artifact_cache", "runtime_assets"):
            row = stages[name]
            if type(row) is dict and row["status"] == "attempting":
                _stage(stages, name, "failure")
            elif type(row) is dict and row["status"] == "not-reached":
                stages[name] = {"status": "blocked", "elapsed_ms": 0}
        observation["codes"] = [error.code]
        raise
    except BaseException as error:
        cache_row = stages["artifact_cache"]
        runtime_row = stages["runtime_assets"]
        if (type(cache_row) is dict and cache_row.get("status") == "success" and
                setup["value"] in PREPHASE_SETUPS and
                type(runtime_row) is dict and runtime_row.get("status") == "not-reached"):
            stages["runtime_assets"] = {"status": "blocked", "elapsed_ms": 0}
        observation["codes"] = ["candidate-uncertainty"]
        raise CandidateError() from error
    finally:
        observation["first_build_setup"] = setup["value"]
        observation["duration_ms"] = max(0, (time.monotonic_ns() - started) // 1_000_000)
        _write_json_once(OBSERVATION, observation, "observation-owned")
    return 0


def _open_directory_nofollow(path):
    path = Path(path)
    _fail(path.is_absolute(), "cleanup-policy")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                os.close(descriptor)
            except BaseException:
                os.close(child)
                raise
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_dir(path):
    descriptor = _open_directory_nofollow(path)
    try:
        observed = os.fstat(descriptor)
        _fail(stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
              stat.S_IMODE(observed.st_mode) == 0o700, "cleanup-policy")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _rmdir_exact(path, expected):
    path = Path(path)
    parent = _open_directory_nofollow(path.parent)
    try:
        observed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _fail(_same_directory_authority(observed, expected), "cleanup-replaced")
        os.rmdir(path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _one_record(records, kind, required=False):
    values = [record for record in records if record["kind"] == kind]
    _fail(len(values) <= 1 and (not required or len(values) == 1), "journal-state")
    return None if not values else values[0]["body"]


def _unlink_exact(directory, name, descriptor, expected, digest=None, include_size=True):
    held = os.fstat(descriptor)
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _fail(_same_identity(held, expected, include_size=include_size) and
          _same_identity(named, expected, include_size=include_size), "cleanup-replaced")
    if digest is not None:
        _fail(_digest_descriptor(descriptor, held.st_size) == digest, "cleanup-replaced")
    os.unlink(name, dir_fd=directory)
    os.fsync(directory)


def _asset_records(records):
    fixed = {asset.component: ("." + asset.name + ".partial", asset.name, asset.size) for asset in RUNTIME_ASSETS}
    initial, final, sealed = set(), {}, set()
    for record in records:
        kind, body = record["kind"], record["body"]
        key = body.get("component") if type(body) is dict else None
        if kind == "asset-partial-owned":
            _fail(key in fixed and body.get("name") == fixed[key][0] and key not in initial, "journal-state")
            initial.add(key)
        elif kind == "asset-partial-final-owned":
            generation = body.get("generation") if type(body) is dict else None
            policy = ("file", 0o400, 0, 0, 1, fixed.get(key, (None, None, None))[2])
            _fail(key in initial and key not in final and key not in sealed and set(body) ==
                  {"component", "name", "generation"} and body["name"] == fixed[key][0] and
                  type(generation) is dict and set(generation) == set(FULL_GENERATION) and
                  tuple(generation[name] for name in ("kind", "mode", "uid", "gid", "nlink", "size")) ==
                  policy and all(type(value) is int and value >= 0 for name, value in generation.items()
                                 if name != "kind") and generation["mount_id"] > 0 and
                  generation["ino"] > 0, "journal-state")
            final[key] = body
        elif kind == "asset-final-owned":
            _fail(key in final and key not in sealed and body.get("name") == fixed[key][1], "journal-state")
            sealed.add(key)
    return final, sealed


def _cleanup_assets(records, immediate):
    directory_record = _one_record(records, "asset-directory-owned")
    partials, sealed = _asset_records(records)
    if _held_path_absent(ASSETS):
        _fail(all(component in sealed or immediate[component] == "success" for component in partials),
              "cleanup-uncertainty")
        return
    _fail(directory_record is not None, "cleanup-unowned")
    directory = _open_dir(ASSETS)
    held_files = []
    try:
        _fail(_same_directory_authority(os.fstat(directory), directory_record["identity"]), "cleanup-replaced")
        owned = {}
        for record in records:
            body = record["body"]
            if record["kind"] == "asset-final-owned":
                owned[body["name"]] = (body["identity"], body["sha256"], True)
        for component, body in partials.items():
            if component not in sealed:
                owned[body["name"]] = (body["generation"], None, False)
        names = set(os.listdir(directory))
        _fail(names <= set(owned) and all(component in sealed or body["name"] in names or
              immediate[component] == "success" for component, body in partials.items()),
              "cleanup-uncertainty")
        for name in sorted(names):
            identity, digest, complete = owned[name]
            descriptor = _owned_file(directory, name, identity, digest) if complete else os.open(
                name, O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory,
            )
            held_files.append((name, descriptor, identity, digest, complete))
            if not complete:
                _fail(_asset_generation(descriptor, time.monotonic_ns() + 600 * NS_PER_SECOND) == identity,
                      "cleanup-replaced")
        for name, descriptor, identity, digest, complete in held_files:
            if complete:
                _unlink_exact(directory, name, descriptor, identity, digest)
            else:
                _fail(_asset_generation(descriptor, time.monotonic_ns() + 600 * NS_PER_SECOND) == identity,
                      "cleanup-replaced")
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
    finally:
        for _name, descriptor, _identity_value, _digest, _complete in held_files:
            os.close(descriptor)
        os.close(directory)
    _rmdir_exact(ASSETS, directory_record["identity"])


def _cleanup_artifacts(records):
    owned = _one_record(records, "cache-owned")
    if _held_path_absent(ARTIFACT_ROOT):
        return
    _fail(owned is not None, "cleanup-unowned")
    root = _open_dir(ARTIFACT_ROOT)
    cache = None
    held = []
    sentinel = None
    try:
        _fail(_same_identity(os.fstat(root), owned["root"]), "cleanup-replaced")
        _fail(set(os.listdir(root)) == {"cache", ".cogs-stage2-completion-artifacts-v1"}, "cleanup-unknown")
        cache = os.open("cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        _fail(_same_identity(os.fstat(cache), owned["cache"]), "cleanup-replaced")
        _fail(set(os.listdir(cache)) == {item["name"] for item in owned["files"]}, "cleanup-unknown")
        for item in owned["files"]:
            descriptor = _owned_file(cache, item["name"], item["identity"], item["sha256"])
            held.append((item, descriptor))
        sentinel = _owned_file(root, ".cogs-stage2-completion-artifacts-v1",
                               owned["sentinel"]["identity"], owned["sentinel"]["sha256"])
        for item, descriptor in held:
            _unlink_exact(cache, item["name"], descriptor, item["identity"], item["sha256"])
        os.rmdir("cache", dir_fd=root)
        _unlink_exact(root, ".cogs-stage2-completion-artifacts-v1", sentinel,
                      owned["sentinel"]["identity"], owned["sentinel"]["sha256"])
    finally:
        for _item, descriptor in held:
            os.close(descriptor)
        if sentinel is not None:
            os.close(sentinel)
        if cache is not None:
            os.close(cache)
        os.close(root)
    _rmdir_exact(ARTIFACT_ROOT, owned["root"])


def _retry_exact_recovery(callback, bound_ns, outcomes, attempts=ROOTFS_RECOVERY_ATTEMPTS):
    _fail(callable(callback) and type(bound_ns) is int and bound_ns > 0 and
          type(outcomes) is list and outcomes == [] and
          type(attempts) is int and attempts == ROOTFS_RECOVERY_ATTEMPTS, "rootfs-recovery-contract")
    error = None
    for attempt in range(1, attempts + 1):
        started_ns = time.monotonic_ns()
        try:
            callback()
        except BaseException as caught:
            error = caught
        elapsed_ns = _elapsed_ns(started_ns)
        over_bound = elapsed_ns >= bound_ns
        outcome = "over-bound" if over_bound else ("success" if error is None else "nondeadline")
        outcomes.append({"attempt": attempt, "outcome": outcome, "elapsed_ms": _elapsed_ms(elapsed_ns)})
        if error is None and not over_bound:
            return
        if error is None:
            error = CandidateError("rootfs-recovery-over-bound")
    raise CandidateError("rootfs-recovery-exhausted") from error


def _recover_rootfs(outcomes):
    sys.path.insert(0, str(REMOTE))
    import completion_rootfs_builder as builder
    ticket = _counter_start(builder, "recovery-attempt-1")
    primary = shape_error = read_error = None
    try:
        _retry_exact_recovery(builder._run_recovery, builder.RECOVER_SECONDS * NS_PER_SECOND, outcomes)
    except BaseException as caught:
        primary = caught
    try:
        _fail(type(outcomes) is list and len(outcomes) == 1 and type(outcomes[0]) is dict and
              set(outcomes[0]) == {"attempt", "outcome", "elapsed_ms"} and
              type(outcomes[0]["attempt"]) is int and outcomes[0]["attempt"] == 1 and
              outcomes[0]["outcome"] in {"success", "over-bound", "nondeadline"} and
              type(outcomes[0]["elapsed_ms"]) is int and 0 <= outcomes[0]["elapsed_ms"] <= 5_400_000,
              "rootfs-recovery-contract")
    except BaseException as caught:
        shape_error = caught
    try:
        counters = _counter_read(ticket)
    except BaseException as caught:
        read_error = caught
    expected_failure = type(primary) is CandidateError and primary.code == "rootfs-recovery-exhausted"
    if shape_error is None and read_error is None and (primary is None or expected_failure):
        outcomes[0]["structural_counters"] = counters
    elif shape_error is not None:
        outcomes.clear()
    if primary is not None:
        raise primary
    if shape_error is not None:
        raise shape_error
    if read_error is not None:
        raise read_error


def _cleanup_rootfs(records):
    lifecycle = _one_record(records, "rootfs-lifecycle-owned")
    if _held_path_absent(ROOTFS_STATE):
        return
    _fail(lifecycle is not None, "rootfs-cleanup-unowned")
    root = _open_dir(ROOTFS_STATE)
    held = []
    try:
        _fail(_same_directory_authority(os.fstat(root), lifecycle["root"]), "rootfs-cleanup-replaced")
        _fail(set(os.listdir(root)) == {item["name"] for item in lifecycle["files"]}, "rootfs-cleanup-unknown")
        for item in lifecycle["files"]:
            descriptor = _owned_file(root, item["name"], item["identity"], item["sha256"])
            held.append((item, descriptor))
        for item, descriptor in held:
            _unlink_exact(root, item["name"], descriptor, item["identity"], item["sha256"])
    finally:
        for _item, descriptor in held:
            os.close(descriptor)
        os.close(root)
    _rmdir_exact(ROOTFS_STATE, lifecycle["root"])


def _owned_immediate(records):
    owned = _one_record(records, "observation-owned", True)
    raw = _read_regular(OBSERVATION, MAX_JSON, 0o400)
    immediate = _strict_json(raw).get("immediate_cleanup")
    _fail(owned["name"] == OBSERVATION.name and
          _same_identity(os.stat(OBSERVATION, follow_symlinks=False), owned["identity"]) and
          hashlib.sha256(raw).hexdigest() == owned["sha256"] and type(immediate) is dict and set(immediate) ==
          {item.component for item in RUNTIME_ASSETS} and set(immediate.values()) <= IMMEDIATE_OUTCOMES,
          "observation-cleanup-uncertainty")
    return immediate


def _diagnosed(values, code, fallback):
    values.append(code)
    return fallback


def _cleanup_attempt(code, callback, codes):
    _fail(type(code) is str and callable(callback) and type(codes) is list, "cleanup-contract")
    try:
        callback()
        return True
    except BaseException:
        codes.append(code)
        return False


def _cleanup():
    _fixed_preflight(False)
    records = _require_state()
    codes = []
    recovery_attempts = []
    try:
        immediate = _owned_immediate(records)
    except BaseException:
        immediate = _diagnosed(codes, "observation-cleanup-uncertainty", None)
    recovered = _cleanup_attempt(
        "rootfs-recovery-exhausted", lambda: _recover_rootfs(recovery_attempts), codes,
    )
    if recovered:
        _cleanup_attempt("rootfs-foundation-uncertainty", lambda: _cleanup_rootfs(records), codes)
    if immediate is not None:
        if set(immediate.values()) & {"preserved", "post-unlink-uncertainty"}:
            codes.append("asset-immediate-cleanup-uncertainty")
        _cleanup_attempt("asset-cleanup-uncertainty", lambda: _cleanup_assets(records, immediate), codes)
    _cleanup_attempt("cache-cleanup-uncertainty", lambda: _cleanup_artifacts(records), codes)
    value = {"success": not codes, "codes": list(dict.fromkeys(codes)),
             "recovery_attempts": recovery_attempts, "immediate_cleanup": immediate}
    _write_json_once(CLEANUP, value, "cleanup-owned")
    _fail(not codes, "cleanup-uncertainty")
    return 0


def _verify_state_metadata(records):
    state = _open_dir(STATE)
    held = []
    try:
        genesis = records[0]["body"]
        _fail(_same_directory_authority(os.fstat(state), genesis["state"]), "state-replaced")
        metadata = [record["body"] for record in records if record["kind"] in {"observation-owned", "cleanup-owned"}]
        _fail(len(metadata) == 2, "state-metadata-unknown")
        expected_names = {JOURNAL.name} | {item["name"] for item in metadata}
        _fail(set(os.listdir(state)) == expected_names, "state-metadata-unknown")
        for item in metadata:
            descriptor = _owned_file(state, item["name"], item["identity"], item["sha256"])
            held.append(descriptor)
    finally:
        for descriptor in held:
            os.close(descriptor)
        os.close(state)


def _residue():
    _fixed_preflight(False)
    _require_state()
    codes = []
    if VERSION == PHASE_B_VERSION:
        _cleanup_attempt("qualification-residue", _qualification_residue, codes)
    for path, code in ((ASSETS, "asset-residue"), (ARTIFACT_ROOT, "cache-residue"),
                       (ROOTFS_STATE, "rootfs-baseline-not-restored")):
        try:
            if not _held_path_absent(path):
                codes.append(code)
        except BaseException:
            codes.append("residue-observation-uncertainty")
    try:
        _verify_state_metadata(_require_state())
    except BaseException:
        codes.append("state-metadata-unknown")
    value = {"clean": not codes, "codes": codes}
    _write_json_once(RESIDUE, value, "residue-owned")
    _fail(not codes, "residue-uncertainty")
    return 0


def _base_report():
    return {
        "version": VERSION, "authority": "candidate", "qualified": False,
        "source_revision": None, "source_manifest_sha256": None, "duration_ms": 0,
        "blockers": ["observe-uncertainty", "cleanup-uncertainty", "residue-uncertainty"],
        "checks": {"platform": "fail", "root": "fail", "source": "fail", "kvm": "unknown",
                   "artifact_cache": "unknown", "rootfs_candidates": "unknown", "runtime_assets": "unknown",
                   "host_tools": "unknown", "cleanup": "unknown", "residue": "unknown"},
        "rootfs": None, "rootfs_phases": _empty_phases(),
        "stage_evidence": {name: {"status": "not-reached", "elapsed_ms": 0} for name in STAGE_NAMES},
        "first_build_setup": "not-reached",
        "runtime_assets": [], "host_tools": [],
        "kvm": {"device_present": False, "device_accessible": False, "api_version": None},
        "claims": {"runtime": False, "network": False, "ssh": False, "coordinator_invoked": False},
        "diagnostic_codes": [],
    }


def _allowed_observation_statuses():
    blocked = "blocked"
    patterns = [("not-reached",) * len(OBSERVATION_PHASES)]
    for prefix in (("success", "success"), ("success",) * 4, ("success",) * 5,
                   ("success",) * 6, ("success",) * 7):
        patterns.append(prefix + ("not-reached",) * (len(OBSERVATION_PHASES) - len(prefix)))
    patterns.extend((
        ("failure", cleanup) + (blocked,) * 6 for cleanup in (blocked, "success", "failure")
    ))
    patterns.extend((
        ("success", cleanup) + (blocked,) * 6 for cleanup in (blocked, "failure")
    ))
    patterns.extend((
        ("success", "success", "failure", cleanup) + (blocked,) * 4
        for cleanup in (blocked, "success", "failure")
    ))
    patterns.extend((
        ("success", "success", "success", cleanup) + (blocked,) * 4
        for cleanup in (blocked, "failure")
    ))
    for index in range(4, 8):
        patterns.append(("success",) * index + ("failure",) + (blocked,) * (7 - index))
    patterns.append(("success",) * 8)
    return frozenset(patterns)


ALLOWED_OBSERVATION_STATUSES = _allowed_observation_statuses()


def _validate_phase_graph(phases, rootfs):
    _fail(type(phases) is list and len(phases) == len(ROOTFS_PHASES), "report-schema")
    for name, row in zip(ROOTFS_PHASES, phases, strict=True):
        _fail(type(row) is dict and set(row) == {
            "phase", "status", "outcome", "elapsed_ms", "structural_counters",
        } and row["phase"] == name and row["status"] in {
            "success", "failure", "blocked", "not-reached",
        } and row["outcome"] in {
            "success", "failed", "cancelled", "deadline", "not-started", "postwork", "over-bound",
            "prerequisite-failed", "observer-ended",
        } and type(row["elapsed_ms"]) is int and 0 <= row["elapsed_ms"] <= 5_400_000 and
              (row["status"] == "success") == (row["outcome"] == "success") and
              (row["status"] == "blocked") == (row["outcome"] == "prerequisite-failed") and
              (row["status"] == "not-reached") == (row["outcome"] == "observer-ended") and
              (row["status"] not in {"blocked", "not-reached"} or row["elapsed_ms"] == 0), "report-schema")
        if row["status"] in {"success", "failure"}:
            _validated_counters(row["structural_counters"])
        else:
            _fail(row["structural_counters"] is None, "report-schema")
    statuses = tuple(_phase(phases, name)["status"] for name in OBSERVATION_PHASES)
    _fail(statuses in ALLOWED_OBSERVATION_STATUSES and
          _phase(phases, "recovery-attempt-1")["status"] in {"success", "failure", "not-reached"},
          "report-schema")
    settled = _phase(phases, "settlement")["status"] == "success"
    _fail(settled == (rootfs is not None), "report-schema")
    if rootfs is not None:
        _fail(all(_phase(phases, name)["status"] == "success" for name in ROOTFS_PHASES
                  if name != "recovery-attempt-1"), "report-schema")


def _valid_stage_row(row):
    return (type(row) is dict and set(row) == {"status", "elapsed_ms"} and
            row["status"] in STAGE_CHECK and type(row["elapsed_ms"]) is int and
            0 <= row["elapsed_ms"] <= 3_300_000 and
            (row["status"] not in {"blocked", "not-reached"} or row["elapsed_ms"] == 0))


def _canonical_report(report):
    expected = set(_base_report())
    _fail(type(report) is dict and set(report) == expected, "report-schema")
    _fail(report["version"] == VERSION and report["authority"] == "candidate" and report["qualified"] is False,
          "report-schema")
    revision = report["source_revision"]
    source_digest = report["source_manifest_sha256"]
    _fail(revision is None or (type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision)), "report-schema")
    _fail(source_digest is None or (type(source_digest) is str and HEX.fullmatch(source_digest)), "report-schema")
    _fail(type(report["duration_ms"]) is int and 0 <= report["duration_ms"] <= 5_400_000, "report-schema")
    _fail(report["claims"] == {"runtime": False, "network": False, "ssh": False, "coordinator_invoked": False},
          "report-schema")
    blockers = report["blockers"]
    _fail(type(blockers) is list and 1 <= len(blockers) <= 16 and len(blockers) == len(set(blockers)) and
          all(type(item) is str and re.fullmatch(r"[a-z0-9-]{1,64}", item) for item in blockers), "report-schema")
    codes = report["diagnostic_codes"]
    _fail(type(codes) is list and len(codes) <= 16 and len(codes) == len(set(codes)) and
          all(type(item) is str and re.fullmatch(r"[a-z0-9-]{1,64}", item) for item in codes), "report-schema")
    checks = report["checks"]
    _fail(type(checks) is dict and set(checks) == set(_base_report()["checks"]) and
          set(checks.values()) <= {"pass", "fail", "blocked", "unknown"}, "report-schema")
    stages, setup = report["stage_evidence"], report["first_build_setup"]
    _fail(type(stages) is dict and set(stages) == {"artifact_cache", "runtime_assets"} and
          all(_valid_stage_row(row) for row in stages.values()), "report-schema")
    cache_status = stages["artifact_cache"]["status"]
    runtime_status = stages["runtime_assets"]["status"]
    _fail(runtime_status in {"success": set(STAGE_CHECK), "failure": {"blocked"},
          "blocked": {"blocked"}, "not-reached": {"not-reached"}}[cache_status] and
          all(checks[name] == STAGE_CHECK[stages[name]["status"]] for name in stages) and
          setup in SETUP_STATES and (runtime_status not in {"blocked", "not-reached"} or
          report["runtime_assets"] == []) and (runtime_status != "success" or
          len(report["runtime_assets"]) == 2), "report-schema")
    phases, rootfs = report["rootfs_phases"], report["rootfs"]
    _validate_phase_graph(phases, rootfs)
    first_status = _phase(phases, "first-build-work")["status"]
    settlement_status = _phase(phases, "settlement")["status"]
    resolved_block = cache_status in {"failure", "blocked"} or any(
        row["status"] in {"failure", "blocked"} for row in phases
    )
    prephase_setup = setup in PREPHASE_SETUPS
    setup_boundary = {
        "not-reached": cache_status in {"blocked", "not-reached"} and first_status == "not-reached",
        "fixed-input": cache_status == "failure" and first_status == "not-reached",
        **dict.fromkeys(PREPHASE_SETUPS, cache_status == "success" and first_status == "not-reached"),
        "complete": cache_status == "success" and first_status in {"success", "failure"},
    }
    allowed_runtime = ({"success", "failure", "not-reached"} if settlement_status == "success" else
                       {"blocked"} if resolved_block or prephase_setup else {"not-reached"})
    _fail(setup_boundary[setup] and runtime_status in allowed_runtime, "report-schema")
    if rootfs is not None:
        _fail(rootfs == {
            "candidate_count": 2, "cache_count": 16, "entry_count": 4353,
            "manifest_size": 1049443,
            "manifest_sha256": "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
            "ustar_size": 136905728,
            "ustar_sha256": "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
            "equal": True, "pins_match": True,
        }, "report-schema")
    assets = report["runtime_assets"]
    _fail(type(assets) is list and len(assets) <= 2, "report-schema")
    expected_assets = {item.component: item for item in RUNTIME_ASSETS}
    for row in assets:
        _fail(type(row) is dict and set(row) ==
              {"component", "release", "name", "size", "sha256", "downloaded", "extracted"}, "report-schema")
        asset = expected_assets.get(row["component"])
        _fail(asset is not None and row == {"component": asset.component, "release": asset.release,
              "name": asset.name, "size": asset.size, "sha256": asset.sha256,
              "downloaded": True, "extracted": False}, "report-schema")
    tools = report["host_tools"]
    _fail(type(tools) is list and len(tools) <= 6, "report-schema")
    expected_tools = dict((name, path) for name, path, _arguments in TOOL_COMMANDS)
    for row in tools:
        _fail(type(row) is dict and set(row) == {"name", "path", "present", "size", "sha256", "version"} and
              expected_tools.get(row["name"]) == row["path"] and type(row["present"]) is bool, "report-schema")
        if row["present"]:
            _fail(type(row["size"]) is int and 0 < row["size"] <= MAX_TOOL_BYTES and
                  type(row["sha256"]) is str and HEX.fullmatch(row["sha256"]) and
                  type(row["version"]) is str and 0 < len(row["version"]) <= 256, "report-schema")
        else:
            _fail(row["size"] is row["sha256"] is row["version"] is None, "report-schema")
    kvm = report["kvm"]
    _fail(type(kvm) is dict and set(kvm) == {"device_present", "device_accessible", "api_version"} and
          type(kvm["device_present"]) is bool and type(kvm["device_accessible"]) is bool and
          kvm["api_version"] in {None, 12}, "report-schema")
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    _fail(len(raw) <= MAX_JSON, "report-schema")
    return raw


def _bounded_codes(value):
    _fail(type(value) is list and len(value) <= 16 and len(value) == len(set(value)) and
          all(type(item) is str and re.fullmatch(r"[a-z0-9-]{1,64}", item) for item in value),
          "report-input-uncertainty")
    return list(value)


def _merge_recovery_attempt(phases, rootfs, cleanup):
    _fail(type(cleanup) is dict and "recovery_attempts" in cleanup, "report-input-uncertainty")
    attempts = cleanup["recovery_attempts"]
    _fail(type(attempts) is list and len(attempts) == 1, "report-input-uncertainty")
    attempt = attempts[0]
    _fail(type(attempt) is dict and set(attempt) == {
        "attempt", "outcome", "elapsed_ms", "structural_counters",
    } and attempt["attempt"] == 1 and type(attempt["attempt"]) is int and
          attempt["outcome"] in {"success", "over-bound", "nondeadline"} and
          type(attempt["elapsed_ms"]) is int and 0 <= attempt["elapsed_ms"] <= 5_400_000,
          "report-input-uncertainty")
    merged = [{**row, "structural_counters": None if row["structural_counters"] is None else
               dict(row["structural_counters"])} for row in phases]
    status = "success" if attempt["outcome"] == "success" else "failure"
    outcome = {"success": "success", "over-bound": "over-bound", "nondeadline": "failed"}[attempt["outcome"]]
    row = _phase(merged, "recovery-attempt-1")
    _fail(row["status"] == "not-reached", "report-input-uncertainty")
    row.update({"status": status, "outcome": outcome, "elapsed_ms": attempt["elapsed_ms"],
                "structural_counters": _validated_counters(attempt["structural_counters"])})
    _validate_phase_graph(merged, rootfs)
    return merged


def _render():
    _fixed_preflight(False)
    _require_state()
    report = _base_report()
    diagnostics = []
    try:
        observation = _strict_json(_read_regular(OBSERVATION, MAX_JSON, 0o400))
        _fail(type(observation) is dict, "report-input-uncertainty")
    except BaseException:
        observation = _diagnosed(diagnostics, "observation-input-uncertainty", {})
    try:
        phases, rootfs = observation.get("rootfs_phases"), observation.get("rootfs")
        _validate_phase_graph(phases, rootfs)
        report["rootfs"], report["rootfs_phases"] = rootfs, phases
    except BaseException:
        diagnostics.append("observation-phase-input-uncertainty")
    stages = observation.get("stage_evidence")
    for name in ("artifact_cache", "runtime_assets"):
        try:
            row = stages.get(name) if type(stages) is dict else None
            _fail(_valid_stage_row(row), "report-input-uncertainty")
            report["stage_evidence"][name] = dict(row)
        except BaseException:
            report["stage_evidence"][name] = None
            diagnostics.append(name.replace("_", "-") + "-stage-input-uncertainty")
    try:
        setup = observation.get("first_build_setup")
        _fail(setup in SETUP_STATES, "report-input-uncertainty")
        report["first_build_setup"] = setup
    except BaseException:
        report["first_build_setup"] = _diagnosed(diagnostics, "setup-input-uncertainty", None)
    try:
        observation_codes = _bounded_codes(observation.get("codes"))
    except BaseException:
        observation_codes = _diagnosed(diagnostics, "observation-codes-input-uncertainty", [])
    try:
        duration = observation.get("duration_ms")
        _fail(type(duration) is int and 0 <= duration <= 5_400_000, "report-input-uncertainty")
        report["duration_ms"] = duration
    except BaseException:
        diagnostics.append("duration-input-uncertainty")
    try:
        revision, digest = observation.get("revision"), observation.get("source_manifest_sha256")
        _fail(type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision) and
              type(digest) is str and HEX.fullmatch(digest), "report-input-uncertainty")
        report["source_revision"], report["source_manifest_sha256"] = revision, digest
    except BaseException:
        diagnostics.append("source-input-uncertainty")
    try:
        tools = observation.get("host_tools")
        expected_tools = dict((name, path) for name, path, _arguments in TOOL_COMMANDS)
        _fail(type(tools) is list and len(tools) <= len(TOOL_COMMANDS) and all(
              type(row) is dict and set(row) == {"name", "path", "present", "size", "sha256", "version"} and
              expected_tools.get(row["name"]) == row["path"] and type(row["present"]) is bool and
              ((row["present"] and type(row["size"]) is int and 0 < row["size"] <= MAX_TOOL_BYTES and
                type(row["sha256"]) is str and HEX.fullmatch(row["sha256"]) and type(row["version"]) is str and
                0 < len(row["version"]) <= 256) or (not row["present"] and
                row["size"] is row["sha256"] is row["version"] is None)) for row in tools),
              "report-input-uncertainty")
        report["host_tools"] = tools
    except BaseException:
        diagnostics.append("host-tools-input-uncertainty")
    try:
        assets = observation.get("assets")
        expected_assets = {item.component: item for item in RUNTIME_ASSETS}
        _fail(type(assets) is list and len(assets) <= len(RUNTIME_ASSETS) and all(
              type(row) is dict and (asset := expected_assets.get(row.get("component"))) is not None and
              row == {"component": asset.component, "release": asset.release, "name": asset.name,
                      "size": asset.size, "sha256": asset.sha256, "downloaded": True, "extracted": False}
              for row in assets), "report-input-uncertainty")
        report["runtime_assets"] = assets
    except BaseException:
        diagnostics.append("assets-input-uncertainty")
    try:
        kvm = observation.get("kvm")
        _fail(type(kvm) is dict and set(kvm) == {"device_present", "device_accessible", "api_version"} and
              type(kvm["device_present"]) is bool and type(kvm["device_accessible"]) is bool and
              kvm["api_version"] in {None, 12}, "report-input-uncertainty")
        report["kvm"] = dict(kvm)
    except BaseException:
        diagnostics.append("kvm-input-uncertainty")
    try:
        _fail(observation.get("status") in {"failed", "observed"}, "report-input-uncertainty")
        observed = observation["status"] == "observed"
    except BaseException:
        observed = _diagnosed(diagnostics, "observation-status-input-uncertainty", False)
    try:
        cleanup = _strict_json(_read_regular(CLEANUP, MAX_JSON, 0o400))
    except BaseException:
        cleanup = _diagnosed(diagnostics, "cleanup-input-uncertainty", {})
    if type(cleanup) is not dict or set(cleanup) != {
        "success", "codes", "recovery_attempts", "immediate_cleanup",
    }: diagnostics.append("cleanup-input-uncertainty")
    try:
        report["rootfs_phases"] = _merge_recovery_attempt(report["rootfs_phases"], report["rootfs"], cleanup)
    except BaseException:
        diagnostics.append("recovery-phase-input-uncertainty")
    try:
        _fail(type(cleanup.get("success")) is bool, "report-input-uncertainty")
        cleanup_success = cleanup["success"]
    except BaseException:
        cleanup_success = _diagnosed(diagnostics, "cleanup-summary-input-uncertainty", False)
    try: diagnostics.extend(_bounded_codes(cleanup.get("codes")))
    except BaseException: diagnostics.append("cleanup-codes-input-uncertainty")
    try:
        immediate = cleanup.get("immediate_cleanup")
        _fail(immediate is None or type(immediate) is dict and set(immediate) ==
              {item.component for item in RUNTIME_ASSETS} and
              set(immediate.values()) <= IMMEDIATE_OUTCOMES, "report-input-uncertainty")
    except BaseException: diagnostics.append("immediate-cleanup-input-uncertainty")
    try:
        residue = _strict_json(_read_regular(RESIDUE, MAX_JSON, 0o400))
    except BaseException:
        residue = _diagnosed(diagnostics, "residue-input-uncertainty", {})
    if type(residue) is not dict or set(residue) != {"clean", "codes"}:
        diagnostics.append("residue-input-uncertainty")
    try:
        _fail(type(residue.get("clean")) is bool, "report-input-uncertainty")
        residue_clean = residue["clean"]
    except BaseException:
        residue_clean = _diagnosed(diagnostics, "residue-summary-input-uncertainty", False)
    try: diagnostics.extend(_bounded_codes(residue.get("codes")))
    except BaseException: diagnostics.append("residue-codes-input-uncertainty")
    source_ok = report["source_revision"] is not None and report["source_manifest_sha256"] is not None
    for name in ("platform", "root", "source"):
        report["checks"][name] = "pass" if source_ok else "fail"
    report["checks"]["kvm"] = "pass" if report["kvm"]["api_version"] == 12 else "fail"
    for name in ("artifact_cache", "runtime_assets"):
        try: report["checks"][name] = STAGE_CHECK[report["stage_evidence"][name]["status"]]
        except BaseException: report["checks"][name] = "unknown"
    report["checks"].update({
        "rootfs_candidates": "pass" if type(report["rootfs"]) is dict and
        report["rootfs"].get("pins_match") is True else "fail", "host_tools": "blocked",
        "cleanup": "pass" if cleanup_success else "fail", "residue": "pass" if residue_clean else "fail",
    })
    blockers = list(observation_codes)
    if not observed: blockers.append("observe-uncertainty")
    if not cleanup_success: blockers.append("cleanup-uncertainty")
    if not residue_clean: blockers.append("residue-uncertainty")
    report["blockers"] = list(dict.fromkeys(blockers))
    report["diagnostic_codes"] = list(dict.fromkeys(diagnostics))
    raw = _canonical_report(report)
    _write_json_once(REPORT, report, "report-owned")
    _fail(_read_regular(REPORT, MAX_JSON, 0o400) == raw, "report-validation")
    return 0


def _validate():
    _fixed_preflight(False)
    _require_state()
    raw = _read_regular(REPORT, MAX_JSON, 0o400)
    _fail((_phase_b_canonical if VERSION == PHASE_B_VERSION else _canonical_report)(_strict_json(raw)) == raw, "report-validation")
    return 0


def _export():
    _validate()
    _append_journal("export-intent", {"root": str(EXPORT_ROOT), "name": EXPORT_REPORT.name})
    _fail(_held_path_absent(EXPORT_ROOT), "export-preexisting")
    os.mkdir(EXPORT_ROOT, 0o755)
    _fsync_directory(EXPORT_ROOT.parent)
    directory_identity = _identity(os.stat(EXPORT_ROOT, follow_symlinks=False))
    _fail(directory_identity["uid"] == directory_identity["gid"] == 0 and
          directory_identity["mode"] == 0o755, "export-policy")
    raw = (_phase_b_canonical if VERSION == PHASE_B_VERSION else _canonical_report)(_strict_json(_read_regular(REPORT, MAX_JSON, 0o400)))
    descriptor = os.open(EXPORT_REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        file_identity = _identity(os.fstat(descriptor))
        named = os.stat(EXPORT_REPORT, follow_symlinks=False)
        _fail(_same_identity(named, file_identity) and file_identity["uid"] == file_identity["gid"] == 0 and
              file_identity["mode"] == 0o444 and file_identity["nlink"] == 1, "export-policy")
    finally:
        os.close(descriptor)
    _fsync_directory(EXPORT_ROOT)
    _append_journal("export-owned", {
        "directory": directory_identity, "file": file_identity, "sha256": hashlib.sha256(raw).hexdigest(),
    })
    _fail(_read_regular(EXPORT_REPORT, MAX_JSON, 0o444) == raw, "export-validation")
    return 0


def _cleanup_evidence_state(records):
    kinds = ("observation", "cleanup", "residue", "report")
    intents = {kind: _one_record(records, kind + "-intent") for kind in kinds}
    metadata = [_one_record(records, kind + "-owned") for kind in kinds]
    genesis = records[0]["body"]
    parent = _open_dir(STATE.parent)
    state = anchor = journal = None
    held = []
    try:
        state = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        anchor = os.open(ANCHOR.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        _fail(_same_directory_authority(os.fstat(state), genesis["state"]), "state-replaced")
        present = set(os.listdir(state))
        expected = {JOURNAL.name} | {item["name"] for item in metadata if item is not None}
        expected |= {item["name"] for item in intents.values() if item is not None}
        _fail(present <= expected, "state-metadata-unknown")
        for kind, item in zip(kinds, metadata, strict=True):
            intent = intents[kind]
            _fail(item is None or VERSION != PHASE_B_VERSION or intent is not None and
                  item["name"] == intent["name"] and item["sha256"] == intent["sha256"], "journal-state")
            candidate = item if item is not None else intent
            if candidate is None or candidate["name"] not in present:
                continue
            descriptor = os.open(candidate["name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
            observed = os.fstat(descriptor)
            _fail(item is not None or stat.S_ISREG(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
                  observed.st_nlink == 1 and observed.st_size <= intent["size"], "cleanup-replaced")
            held.append((candidate, descriptor))
        journal = os.open(JOURNAL.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        _fail(_same_identity(os.fstat(journal), genesis["journal"], include_size=False), "journal-replaced")
        _fail(_same_identity(os.fstat(anchor), genesis["anchor"]), "anchor-node-replaced")
        for item, descriptor in held:
            _unlink_exact(state, item["name"], descriptor, item.get("identity", _identity(os.fstat(descriptor))),
                          item.get("sha256") if "identity" in item else None)
        _unlink_exact(state, JOURNAL.name, journal, genesis["journal"], include_size=False)
        held_state = os.fstat(state)
        named_state = os.stat(STATE.name, dir_fd=parent, follow_symlinks=False)
        _fail(_same_directory_authority(held_state, genesis["state"]) and
              _same_directory_authority(named_state, genesis["state"]) and
              _same_directory_authority(named_state, _identity(held_state)), "state-replaced")
        os.rmdir(STATE.name, dir_fd=parent)
        os.fsync(parent)
        _unlink_exact(parent, ANCHOR.name, anchor, genesis["anchor"], genesis["anchor_sha256"])
    finally:
        for _item, descriptor in held:
            os.close(descriptor)
        for descriptor in (journal, anchor, state, parent):
            if descriptor is not None:
                os.close(descriptor)
    created = genesis.get("created_parents", {})
    if created.get("completion") is True:
        _rmdir_exact(STATE.parent, created["completion_identity"])
    if created.get("state_parent") is True:
        _rmdir_exact(STATE.parent.parent, created["state_parent_identity"])


def _cleanup_export():
    _fixed_preflight(False)
    records = _require_state()
    intent, owned = _one_record(records, "export-intent"), _one_record(records, "export-owned")
    if _held_path_absent(EXPORT_ROOT):
        _fail(owned is None, "export-residue-unknown")
    else:
        _fail(owned is not None or intent is not None and intent.get("name") == EXPORT_REPORT.name,
              "export-cleanup-unowned")
        directory = os.open(EXPORT_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptor = None
        try:
            observed = os.fstat(directory)
            _fail((owned is not None and _same_directory_authority(observed, owned["directory"]) or
                  owned is None and stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
                  stat.S_IMODE(observed.st_mode) == 0o755) and
                  set(os.listdir(directory)) <= {EXPORT_REPORT.name}, "export-cleanup-replaced")
            if EXPORT_REPORT.name in os.listdir(directory):
                descriptor = os.open(EXPORT_REPORT.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=directory)
                exported = os.fstat(descriptor)
                _fail(owned is not None or stat.S_ISREG(exported.st_mode) and exported.st_uid == exported.st_gid == 0
                      and exported.st_nlink == 1 and exported.st_size <= MAX_JSON, "export-cleanup-replaced")
                _unlink_exact(directory, EXPORT_REPORT.name, descriptor,
                              owned["file"] if owned is not None else _identity(exported),
                              owned["sha256"] if owned is not None else None)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)
        _rmdir_exact(EXPORT_ROOT, owned["directory"] if owned is not None else _identity(observed))
        if owned is not None:
            _append_journal("export-cleaned", {"sha256": owned["sha256"]})
            records = _require_state()
    _cleanup_evidence_state(records)
    return 0


def _held_path_absent(path):
    path = Path(path)
    _fail(path.is_absolute(), "residue-observation-uncertainty")
    descriptors = []
    bindings = []
    missing = None
    try:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append((current, None))
        descriptors[-1] = (current, _identity(os.fstat(current)))
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=current)
            except FileNotFoundError:
                missing = (current, component)
                break
            descriptors.append((child, None))
            expected = _identity(os.fstat(child))
            descriptors[-1] = (child, expected)
            bindings.append((current, component, child, expected))
            current = child
        if missing is None:
            try:
                os.stat(path.name, dir_fd=current, follow_symlinks=False)
                absent = False
            except FileNotFoundError:
                missing = (current, path.name)
                absent = True
        else:
            absent = True
        for descriptor, expected in descriptors:
            _fail(_same_identity(os.fstat(descriptor), expected, include_size=False, include_nlink=False),
                  "residue-observation-uncertainty")
        for parent, name, child, expected in bindings:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _fail(_same_identity(os.fstat(child), expected, include_size=False, include_nlink=False) and
                  _same_identity(named, expected, include_size=False, include_nlink=False),
                  "residue-observation-uncertainty")
        if missing is not None:
            try:
                os.stat(missing[1], dir_fd=missing[0], follow_symlinks=False)
            except FileNotFoundError:
                return absent
            raise CandidateError("residue-observation-uncertainty")
        return absent
    except CandidateError:
        raise
    except OSError as error:
        raise CandidateError("residue-observation-uncertainty") from error
    finally:
        for descriptor, _expected in reversed(descriptors):
            os.close(descriptor)


def _use_phase_b_paths():
    global STATE, ANCHOR, JOURNAL, ASSETS, OBSERVATION, CLEANUP, RESIDUE, REPORT, EXPORT_ROOT, EXPORT_REPORT, VERSION, ANCHOR_VERSION
    STATE, ANCHOR = PHASE_B_STATE, PHASE_B_STATE.parent / ".cogs-stage2-phase-b-anchor-v1.json"
    JOURNAL, ASSETS = STATE / "ownership.jsonl", STATE / "assets"
    OBSERVATION, CLEANUP, RESIDUE = STATE / "observation.json", STATE / "cleanup.json", STATE / "residue.json"
    REPORT, EXPORT_ROOT = STATE / "qualification.json", Path("/var/tmp/cogs-stage2-phase-b-qualification-v1")
    EXPORT_REPORT, VERSION = EXPORT_ROOT / "qualification.json", PHASE_B_VERSION
    ANCHOR_VERSION = "cogs.stage2-phase-b-anchor/v1"


def _qualification_module():
    import completion_kata_qualification as qualification
    return qualification


def _exact_metadata(value, contract):
    if callable(contract):
        return bool(contract(value))
    if type(contract) is range:
        return type(value) is int and value in contract
    if type(contract) is re.Pattern:
        return type(value) is str and contract.fullmatch(value) is not None
    if type(contract) is dict:
        return type(value) is dict and set(value) == set(contract) and all(_exact_metadata(value[name], contract[name]) for name in contract)
    if type(contract) is list:
        return type(value) is list and len(value) == len(contract) and all(_exact_metadata(value[i], contract[i]) for i in range(len(contract)))
    return type(value) is type(contract) and value == contract


def _candidate_metadata(value, revision, manifest_sha256):
    positive, count, mode = range(1, 1 << 63), range(1, 20_001), range(0, 0o10000)
    version = {"length": range(1, 4097), "sha256": HEX, "exit_status": range(2)}
    tool = lambda name: {"name": name, "closure_sha256": HEX, "version": version}
    file = {"mode": mode, "size": positive, "sha256": HEX}
    archive = lambda component: {"component": component, "archive": {"size": positive, "sha256": HEX},
        "preflight": {"entry_count": count, "sha256": HEX}, "layout": {"entry_count": count, "sha256": HEX}}
    host = {"tools": [tool(name) for name in ("ctr", "ip", "tc", "nft", "ssh", "ssh-keygen")],
            "extraction_helpers": [tool(name) for name in ("tar", "zstd")]}
    files = ("kata_config", "kata_runtime", "kata_shim", "qemu", "virtiofsd", "containerd", "ctr")
    runtime = {"archives": [archive("kata"), archive("containerd")], "runtime_files": {name: file for name in files},
        "private_versions": {"containerd": version, "ctr": version},
        "private_config": {"size": positive, "sha256": HEX}, "shared_fs": "virtio-fs",
        "kvm": {"api_version": 12, "device_accessible": True},
        "qmp": {"present": True, "enabled": True, "acceleration": "kvm", "tcg": False},
        "fixture_digests": {name: HEX for name in ("network", "runtime", "process", "share")}}
    contract = {"version": "cogs.stage2-phase-b-attestation-candidate/v1", "authority": "candidate",
        "qualified": False, "gate_opened": False, "owner_opened": False,
        "source": {"revision": revision, "manifest_sha256": manifest_sha256}, "host": host,
        "runtime": runtime, "metadata_only": True}
    _fail(_exact_metadata(value, contract) and len(_canonical(value)) <= MAX_JSON, "qualification-report")
    return value


def _qualification_residue():
    expected = {"version": "cogs.stage2-phase-b-attestation-candidate/v1", "authority": "candidate", "clean": True, "codes": []}
    _fail(_qualification_module().candidate_attestation_residue() == expected, "qualification-residue")


def _phase_b_observe():
    _fixed_preflight(True, "download-2-fixed-public-runtime-assets")
    revision, manifest_sha256 = _source_approval()
    _verify_fixed_source(revision, manifest_sha256)
    _fail(_held_path_absent(STATE.parent) and _held_path_absent(STATE.parent.parent), "state-baseline-present")
    _initialize_state(revision, manifest_sha256)
    started = time.monotonic_ns()
    immediate = {asset.component: "not-required" for asset in RUNTIME_ASSETS}
    value = {"revision": revision, "source_manifest_sha256": manifest_sha256, "duration_ms": 0,
             "assets": [], "attestation": None, "codes": [], "immediate_cleanup": immediate}
    error = None
    try:
        _append_journal("asset-directory-intent", {"name": ASSETS.name})
        created, identity = _mkdir_policy(ASSETS)
        _fail(created, "asset-directory-policy")
        _append_journal("asset-directory-owned", {"identity": identity})
        deadline = started + OBSERVE_SECONDS * NS_PER_SECOND
        value["assets"] = [_download_asset(asset, deadline, immediate) for asset in RUNTIME_ASSETS]
        value["attestation"] = _candidate_metadata(
            _qualification_module().candidate_attestation_report(), revision, manifest_sha256)
    except BaseException as caught:
        error = caught
        value["codes"] = [caught.code if type(caught) is CandidateError else "qualification-uncertainty"]
    finally:
        value["duration_ms"] = _elapsed_ms(_elapsed_ns(started))
        _write_json_once(OBSERVATION, value, "observation-owned")
    if error is not None:
        raise CandidateError(value["codes"][0]) from error
    return 0


def _phase_b_cleanup():
    _fixed_preflight(False)
    records = _require_state()
    codes = []
    try:
        immediate = _owned_immediate(records)
    except BaseException:
        immediate = _diagnosed(codes, "observation-cleanup-uncertainty", None)
    expected = {"version": "cogs.stage2-phase-b-attestation-candidate/v1", "authority": "candidate", "cleaned": True, "roots_removed": 2}
    cleanup = lambda: _fail(_qualification_module().candidate_attestation_cleanup() == expected, "qualification-cleanup-uncertainty")
    _cleanup_attempt("qualification-cleanup-uncertainty", cleanup, codes)
    if immediate is not None:
        _cleanup_attempt("asset-cleanup-uncertainty", lambda: _cleanup_assets(records, immediate), codes)
    _write_json_once(CLEANUP, {"success": not codes, "codes": list(dict.fromkeys(codes))}, "cleanup-owned")
    _fail(not codes, "cleanup-uncertainty")
    return 0


def _phase_b_canonical(report):
    assets = [{"component": item.component, "release": item.release, "name": item.name, "size": item.size,
               "sha256": item.sha256, "downloaded": True, "extracted": False} for item in RUNTIME_ASSETS]
    checks = {name: "pass" for name in ("runtime_assets", "attestation", "cleanup", "residue")}
    contract = {"version": PHASE_B_VERSION, "stage": PHASE_B_STAGE, "authority": "candidate",
        "qualified": False, "promotion": False, "source_revision": re.compile(r"[0-9a-f]{40}"),
        "source_manifest_sha256": HEX, "duration_ms": range(5_400_001), "checks": checks,
        "runtime_assets": assets, "candidate_attestation_report": lambda value: _candidate_metadata(
            value, report["source_revision"], report["source_manifest_sha256"]) == value,
        "blockers": ["candidate-non-authoritative"]}
    _fail(_exact_metadata(report, contract), "report-schema")
    raw = _canonical(report) + b"\n"
    _fail(len(raw) <= MAX_JSON, "report-schema")
    return raw


def _phase_b_render():
    _fixed_preflight(False)
    _require_state()
    observation = _strict_json(_read_regular(OBSERVATION, MAX_JSON, 0o400))
    cleanup = _strict_json(_read_regular(CLEANUP, MAX_JSON, 0o400))
    residue = _strict_json(_read_regular(RESIDUE, MAX_JSON, 0o400))
    _fail(observation.get("codes") == [] and cleanup == {"success": True, "codes": []} and
          residue == {"clean": True, "codes": []}, "report-input-uncertainty")
    report = {"version": PHASE_B_VERSION, "stage": PHASE_B_STAGE, "authority": "candidate",
        "qualified": False, "promotion": False, "source_revision": observation["revision"],
        "source_manifest_sha256": observation["source_manifest_sha256"],
        "duration_ms": observation["duration_ms"],
        "checks": {name: "pass" for name in ("runtime_assets", "attestation", "cleanup", "residue")},
        "runtime_assets": observation["assets"], "candidate_attestation_report": observation["attestation"],
        "blockers": ["candidate-non-authoritative"]}
    raw = _phase_b_canonical(report)
    _write_json_once(REPORT, report, "report-owned")
    _fail(_read_regular(REPORT, MAX_JSON, 0o400) == raw, "report-validation")
    return 0


def _phase_b_final_residue():
    descriptors = set(os.listdir("/proc/self/fd"))
    revision, manifest_sha256 = _source_approval()
    _verify_fixed_source(revision, manifest_sha256)
    _qualification_residue()
    _post_export_residue()
    _fail(_held_path_absent(STATE.parent) and _held_path_absent(STATE.parent.parent), "state-parent-residue")
    _fail(set(os.listdir("/proc/self/fd")) == descriptors, "descriptor-residue")
    return 0


def _post_export_residue():
    for path, code in (
        (ROOTFS_STATE, "rootfs-baseline-not-restored"), (ARTIFACT_ROOT, "cache-residue"),
        (ASSETS, "asset-residue"), (STATE, "state-residue"), (ANCHOR, "state-residue"),
        (EXPORT_ROOT, "export-residue"),
    ):
        _fail(_held_path_absent(path), code)
    return 0


def main(argv):
    actions = {
        "observe": _observe, "cleanup": _cleanup, "residue": _residue, "render": _render,
        "validate": _validate, "export": _export, "cleanup-export": _cleanup_export,
        "post-export-residue": _post_export_residue,
    }
    if len(argv) == 2 and argv[0] == PHASE_B_STAGE:
        _use_phase_b_paths()
        actions.update({"observe": _phase_b_observe, "cleanup": _phase_b_cleanup,
                        "render": _phase_b_render, "post-export-residue": _phase_b_final_residue})
        argv = argv[1:]
    _fail(len(argv) == 1 and argv[0] in actions, "arguments")
    return actions[argv[0]]()


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except CandidateError as error:
        try:
            sys.stderr.write("stage2 phase-a candidate failed: " + error.code + "\n")
        except BaseException:
            pass
        raise SystemExit(2)

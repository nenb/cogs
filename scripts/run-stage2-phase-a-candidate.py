#!/usr/bin/env python3
"""ADR0046 Phase A metadata-only candidate observer.

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
STATE = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/phase-a-candidate-v1"
ANCHOR = STATE.parent / ".cogs-stage2-phase-a-anchor-v1.json"
JOURNAL = STATE / "ownership.jsonl"
ASSETS = STATE / "assets"
OBSERVATION = STATE / "observation.json"
CLEANUP = STATE / "cleanup.json"
RESIDUE = STATE / "residue.json"
REPORT = STATE / "candidate.json"
EXPORT_ROOT = Path("/var/tmp/cogs-stage2-phase-a-candidate-v1")
EXPORT_REPORT = EXPORT_ROOT / "candidate.json"
SOURCE_MANIFEST = FIXED_SOURCE / ".cogs-stage2-source-manifest-v1.json"
ARTIFACT_ROOT = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/artifacts"
ROOTFS_STATE = FIXED_SOURCE / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
VERSION = "cogs.stage2-phase-a-candidate/v1"
MAX_JSON = 64 * 1024
MAX_JOURNAL = 512 * 1024
MAX_SOURCE_MANIFEST = 16 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT = 4096
HOST_TOOL_SECONDS = 10
DOWNLOAD_SECONDS = 1200
OBSERVE_SECONDS = 4200
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


def _fixed_preflight(require_approval):
    _fail(platform.system() == "Linux", "wrong-platform")
    _fail(platform.machine() == "x86_64", "wrong-architecture")
    _fail(os.geteuid() == 0, "not-root")
    _fail(Path(__file__).resolve() == FIXED_SCRIPT, "wrong-source-location")
    _fail(FIXED_SOURCE.resolve() == FIXED_SOURCE and FIXED_SOURCE.is_dir(), "wrong-source-location")
    for name in os.environ:
        upper = name.upper()
        _fail(not (upper in DENIED_ENV or upper.startswith("AWS_")), "ambient-authority")
    if require_approval:
        _fail(os.environ.get(APPROVAL_NAME) == APPROVAL_VALUE, "artifact-approval-missing")
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
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    root_identity = _identity(os.fstat(descriptor))
    _fail(root_identity["kind"] == "directory" and root_identity["uid"] == root_identity["gid"] == 0 and
          root_identity["mode"] & 0o022 == 0, "anchor-chain-policy")
    values = [{"path": "/", "identity": root_identity}]
    current = Path("/")
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= component
            identity = _identity(os.fstat(descriptor))
            _fail(identity["kind"] == "directory" and identity["uid"] == identity["gid"] == 0 and
                  identity["mode"] & 0o022 == 0, "anchor-chain-policy")
            values.append({"path": str(current), "identity": identity})
        return values
    finally:
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
    _fail(value["version"] == "cogs.stage2-phase-a-anchor/v1" and
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
    descriptor = os.open(JOURNAL.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
    try:
        before = os.fstat(descriptor)
        _fail(_same_identity(before, records[0]["body"]["journal"], include_size=False), "journal-replaced")
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        os.close(state)
    _fail(_read_journal_unanchored()[-1] == record, "journal-invalid")
    return record


def _initialize_state(revision, manifest_sha256):
    state_parent = FIXED_SOURCE / "deploy/aws-feasibility/.state"
    completion = STATE.parent
    _fail(not os.path.lexists(ROOTFS_STATE), "rootfs-baseline-present")
    _fail(not os.path.lexists(ANCHOR), "anchor-preexisting")
    state_parent_created, state_parent_identity = _mkdir_policy(state_parent, create=not os.path.lexists(state_parent))
    completion_created, completion_identity = _mkdir_policy(completion, create=not os.path.lexists(completion))
    _fail(not os.path.lexists(STATE), "state-preexisting")
    os.mkdir(STATE, 0o700)
    state_identity = _identity(os.stat(STATE, follow_symlinks=False))
    _fail(state_identity["uid"] == state_identity["gid"] == 0 and state_identity["mode"] == 0o700, "state-policy")
    journal = os.open(JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    anchor = os.open(ANCHOR, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(journal, 0o600); os.fchmod(anchor, 0o400)
        journal_identity = _identity(os.fstat(journal))
        anchor_identity = _identity(os.fstat(anchor))
        anchor_value = {
            "version": "cogs.stage2-phase-a-anchor/v1", "source_revision": revision,
            "source_manifest_sha256": manifest_sha256, "trusted_parent_chain": _trusted_chain(STATE.parent),
            "state": state_identity, "journal": journal_identity,
        }
        anchor_raw = _canonical(anchor_value) + b"\n"
        _write_all(anchor, anchor_raw); os.fsync(anchor)
        body = {
            "version": "cogs.stage2-phase-a-ownership/v1", "state": state_identity,
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
        os.close(anchor); os.close(journal)
    _fsync_directory(STATE); _fsync_directory(STATE.parent)
    _fsync_directory(STATE.parent.parent); _fsync_directory(STATE.parent.parent.parent)
    _require_state()


def _validate_anchor_journal(anchor, anchor_sha256, genesis, anchor_observed):
    _fail(genesis.get("anchor_sha256") == anchor_sha256 and genesis.get("state") == anchor["state"] and
          genesis.get("journal") == anchor["journal"] and
          _same_identity(anchor_observed, genesis.get("anchor"), include_size=False), "anchor-journal-mismatch")


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
    process = subprocess.Popen(
        (path, *arguments), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        close_fds=True, start_new_session=True,
    )
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + HOST_TOOL_SECONDS
    try:
        _fail(process.stdout is not None, "host-tool-output")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        eof = False
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_group(process)
                raise CandidateError("host-tool-timeout")
            events = selector.select(min(remaining, 0.1))
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
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _terminate_group(process)
            raise CandidateError("host-tool-timeout") from error
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


def _request(url, deadline):
    parsed = _strict_url(url)
    remaining = deadline - time.monotonic()
    _fail(remaining > 0, "asset-timeout")
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    _fail(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "asset-tls")
    connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=remaining, context=context)
    try:
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", parsed.hostname)
        connection.putheader("User-Agent", "cogs-stage2-phase-a/1")
        connection.putheader("Accept", "application/octet-stream")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
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


def _cleanup_held_partial(directory, name, descriptor):
    held = os.fstat(descriptor)
    try:
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    _fail((named.st_dev, named.st_ino, named.st_uid) == (held.st_dev, held.st_ino, held.st_uid) and
          stat.S_ISREG(named.st_mode), "asset-partial-replaced")
    os.unlink(name, dir_fd=directory)
    os.fsync(directory)


def _download_asset(asset, outer_deadline):
    _fail(type(asset) is Asset and HEX.fullmatch(asset.sha256) is not None, "asset-contract")
    final = ASSETS / asset.name
    partial = ASSETS / ("." + asset.name + ".partial")
    _append_journal("asset-intent", {"component": asset.component, "partial": partial.name, "final": final.name})
    assets_fd = _open_dir(ASSETS)
    _fail(not os.path.lexists(final) and not os.path.lexists(partial), "asset-no-overwrite")
    descriptor = os.open(partial.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=assets_fd)
    partial_identity = _identity(os.fstat(descriptor))
    _append_journal("asset-partial-owned", {
        "component": asset.component, "name": partial.name, "identity": partial_identity,
    })
    deadline = min(outer_deadline, time.monotonic() + DOWNLOAD_SECONDS)
    connection = response = None
    published = False
    try:
        connection, response = _request(asset.url, deadline)
        headers = _headers(response)
        _fail(response.status in {301, 302, 303, 307, 308}, "asset-redirect")
        _fail(headers.get("content-length") is not None and headers["content-length"].isdigit() and
              int(headers["content-length"]) <= 4096 and "transfer-encoding" not in headers, "asset-redirect")
        body = response.read(4097)
        _fail(len(body) == int(headers["content-length"]), "asset-redirect")
        target = _redirect_target(asset, headers.get("location", ""))
        response.close(); connection.close(); response = connection = None
        connection, response = _request(target, deadline)
        headers = _headers(response)
        _fail(response.status == 200 and headers.get("content-length") == str(asset.size) and
              headers.get("content-type", "").strip().lower() == "application/octet-stream" and
              "transfer-encoding" not in headers, "asset-response")
        digest = hashlib.sha256()
        total = 0
        while total < asset.size:
            remaining = deadline - time.monotonic()
            _fail(remaining > 0, "asset-timeout")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read(min(1024 * 1024, asset.size - total))
            _fail(type(chunk) is bytes and chunk, "asset-body")
            offset = 0
            while offset < len(chunk):
                written = os.write(descriptor, chunk[offset:])
                _fail(type(written) is int and written > 0, "asset-body")
                offset += written
            digest.update(chunk)
            total += len(chunk)
        _fail(response.read(1) == b"" and total == asset.size and digest.hexdigest() == asset.sha256, "asset-digest")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        held = os.fstat(descriptor)
        _fail(_same_identity(held, {**partial_identity, "mode": 0o400, "size": asset.size}) and
              _digest_descriptor(descriptor, asset.size) == asset.sha256, "asset-publish")
        os.link(partial.name, final.name, src_dir_fd=assets_fd, dst_dir_fd=assets_fd, follow_symlinks=False)
        linked = os.stat(final.name, dir_fd=assets_fd, follow_symlinks=False)
        _fail((linked.st_dev, linked.st_ino) == (held.st_dev, held.st_ino) and linked.st_nlink == 2,
              "asset-publish")
        os.unlink(partial.name, dir_fd=assets_fd)
        os.fsync(assets_fd)
        final_identity = _identity(os.stat(final.name, dir_fd=assets_fd, follow_symlinks=False))
        held_final = os.fstat(descriptor)
        _fail(_same_identity(held_final, final_identity) and final_identity["nlink"] == 1 and
              _digest_descriptor(descriptor, asset.size) == asset.sha256, "asset-publish")
        _append_journal("asset-final-owned", {
            "component": asset.component, "name": final.name, "identity": final_identity, "sha256": asset.sha256,
        })
        published = True
        return {"component": asset.component, "release": asset.release, "name": asset.name,
                "size": asset.size, "sha256": asset.sha256, "downloaded": True, "extracted": False}
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if not published:
            try:
                _cleanup_held_partial(assets_fd, partial.name, descriptor)
            except BaseException:
                pass
        os.close(descriptor)
        os.close(assets_fd)


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
        sentinel = _read_regular(ARTIFACT_ROOT / ".cogs-stage2-completion-artifacts-v1", 128, 0o400)
        sentinel_identity = _identity(os.stat(ARTIFACT_ROOT / ".cogs-stage2-completion-artifacts-v1", follow_symlinks=False))
        _fail(sentinel_identity["kind"] == "file" and sentinel_identity["mode"] == 0o400 and
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


def _verify_candidate_pair(build, completion_rootfs_publish, first, second):
    build._require_equal_builds(first, second)
    pins = completion_rootfs_publish._load_pins()
    build._require_pinned(first, pins)
    build._require_pinned(second, pins)
    return pins


def _load_artifact_verifier():
    import importlib.util
    verifier_path = REMOTE / "verify-completion-artifacts.py"
    spec = importlib.util.spec_from_file_location("phase_a_completion_artifacts", verifier_path)
    _fail(spec is not None and spec.loader is not None, "artifact-verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def _rootfs_candidates(revision, manifest_sha256, outer_deadline):
    sys.path.insert(0, str(REMOTE))
    import completion_rootfs_build as build
    import completion_rootfs_fs as fs
    import completion_rootfs_publish
    verifier = _load_artifact_verifier()

    contract = verifier.verify_contract(verifier.CONTRACT_PATH)
    _append_journal("cache-intent", {"artifact_count": 16})
    verifier.acquire_completion_artifacts(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT)
    verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT)
    cache_owned = _snapshot_cache(contract)
    _append_journal("cache-owned", cache_owned)
    _append_journal("rootfs-intent", {"baseline": "absent"})
    approval = fs.SourceApproval(revision, manifest_sha256)
    remaining_ns = int((outer_deadline - time.monotonic()) * 1_000_000_000)
    _fail(remaining_ns > 0, "observe-timeout")
    control = fs.OperationControl(time.monotonic_ns() + min(1_200_000_000_000, remaining_ns), lambda: False)
    first, second = build._two_build_outputs(approval, control)
    _verify_candidate_pair(build, completion_rootfs_publish, first, second)
    verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT)
    _fail(_snapshot_cache(contract) == cache_owned, "cache-drift")
    _append_journal("rootfs-lifecycle-owned", _snapshot_rootfs_lifecycle())
    return {"candidate_count": 2, "cache_count": len(first.cache), "entry_count": first.entry_count,
            "manifest_size": len(first.manifest), "manifest_sha256": first.manifest_sha256,
            "ustar_size": first.ustar_size, "ustar_sha256": first.ustar_sha256,
            "equal": True, "pins_match": True}


def _observe():
    _fixed_preflight(True)
    revision, manifest_sha256 = _source_approval()
    _verify_fixed_source(revision, manifest_sha256)
    _initialize_state(revision, manifest_sha256)
    started = time.monotonic_ns()
    outer_deadline = time.monotonic() + OBSERVE_SECONDS
    observation = {"status": "failed", "codes": [], "revision": revision, "source_manifest_sha256": manifest_sha256,
                   "host_tools": [], "kvm": None, "rootfs": None, "assets": []}
    try:
        observation["host_tools"], host_tool_codes = _host_tools()
        observation["kvm"] = _prove_kvm()
        observation["rootfs"] = _rootfs_candidates(revision, manifest_sha256, outer_deadline)
        _append_journal("asset-directory-intent", {"name": ASSETS.name})
        _fail(not os.path.lexists(ASSETS), "asset-directory-preexisting")
        os.mkdir(ASSETS, 0o700)
        _fsync_directory(STATE)
        asset_dir_identity = _identity(os.stat(ASSETS, follow_symlinks=False))
        _fail(asset_dir_identity["uid"] == asset_dir_identity["gid"] == 0 and
              asset_dir_identity["mode"] == 0o700, "asset-directory-policy")
        _append_journal("asset-directory-owned", {"identity": asset_dir_identity})
        observation["assets"] = [_download_asset(asset, outer_deadline) for asset in RUNTIME_ASSETS]
        observation["status"] = "observed"
        observation["codes"] = ["committed-attestations-absent", "qmp-kvm-attestation-not-collected",
                                "runtime-extraction-unsafe-or-unknown", "runtime-lifecycle-not-executed",
                                "network-authority-not-tested", "ssh-authority-not-tested"]
        observation["codes"].extend(host_tool_codes)
        if not all(row["present"] for row in observation["host_tools"]):
            observation["codes"].append("host-tool-missing")
        observation["codes"] = list(dict.fromkeys(observation["codes"]))
    except CandidateError as error:
        observation["codes"] = [error.code]
        raise
    except BaseException as error:
        observation["codes"] = ["candidate-uncertainty"]
        raise CandidateError() from error
    finally:
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
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_dir(path):
    descriptor = _open_directory_nofollow(path)
    observed = os.fstat(descriptor)
    _fail(stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
          stat.S_IMODE(observed.st_mode) == 0o700, "cleanup-policy")
    return descriptor


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


def _cleanup_assets(records):
    directory_record = _one_record(records, "asset-directory-owned")
    if not os.path.lexists(ASSETS):
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
            elif record["kind"] == "asset-partial-owned" and body["name"] not in owned:
                owned[body["name"]] = (body["identity"], None, False)
        names = set(os.listdir(directory))
        _fail(names <= set(owned), "cleanup-unknown")
        for name in sorted(names):
            identity, digest, complete = owned[name]
            descriptor = _owned_file(directory, name, identity, digest) if complete else os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory,
            )
            if not complete:
                observed = os.fstat(descriptor)
                _fail(_same_identity(observed, identity, include_size=False, include_nlink=False) and
                      observed.st_nlink == 1, "cleanup-replaced")
            held_files.append((name, descriptor, identity, digest, complete))
        for name, descriptor, identity, digest, complete in held_files:
            _unlink_exact(directory, name, descriptor, identity, digest, include_size=complete)
    finally:
        for _name, descriptor, _identity_value, _digest, _complete in held_files:
            os.close(descriptor)
        os.close(directory)
    _rmdir_exact(ASSETS, directory_record["identity"])


def _cleanup_artifacts(records):
    owned = _one_record(records, "cache-owned")
    if not os.path.lexists(ARTIFACT_ROOT):
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


def _recover_rootfs():
    sys.path.insert(0, str(REMOTE))
    import completion_rootfs_builder as builder
    builder._run_recovery()


def _cleanup_rootfs(records):
    lifecycle = _one_record(records, "rootfs-lifecycle-owned")
    if not os.path.lexists(ROOTFS_STATE):
        return
    _fail(lifecycle is not None, "rootfs-cleanup-unowned")
    root = _open_dir(ROOTFS_STATE)
    held = []
    try:
        _fail(_same_identity(os.fstat(root), lifecycle["root"]), "rootfs-cleanup-replaced")
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


def _cleanup():
    _fixed_preflight(False)
    _require_state()
    value = {"success": False, "codes": []}
    try:
        records = _require_state()
        _recover_rootfs()
        _cleanup_rootfs(records)
        _cleanup_assets(records)
        _cleanup_artifacts(records)
        value["success"] = True
    except CandidateError as error:
        value["codes"] = [error.code]
        raise
    except BaseException as error:
        value["codes"] = ["cleanup-uncertainty"]
        raise CandidateError("cleanup-uncertainty") from error
    finally:
        _write_json_once(CLEANUP, value, "cleanup-owned")
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
    for path, code in ((ASSETS, "asset-residue"), (ARTIFACT_ROOT, "cache-residue"),
                       (ROOTFS_STATE, "rootfs-baseline-not-restored")):
        if os.path.lexists(path):
            codes.append(code)
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
        "rootfs": None, "runtime_assets": [], "host_tools": [],
        "kvm": {"device_present": False, "device_accessible": False, "api_version": None},
        "claims": {"runtime": False, "network": False, "ssh": False, "coordinator_invoked": False},
        "diagnostic_codes": [],
    }


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
    rootfs = report["rootfs"]
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
        _fail(type(row) is dict and set(row) == {"component", "release", "name", "size", "sha256", "downloaded", "extracted"}, "report-schema")
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


def _render():
    _fixed_preflight(False)
    _require_state()
    report = _base_report()
    codes = []
    try:
        observation = _strict_json(_read_regular(OBSERVATION, MAX_JSON, 0o400))
        cleanup = _strict_json(_read_regular(CLEANUP, MAX_JSON, 0o400))
        residue = _strict_json(_read_regular(RESIDUE, MAX_JSON, 0o400))
        report["source_revision"] = observation.get("revision")
        report["source_manifest_sha256"] = observation.get("source_manifest_sha256")
        report["duration_ms"] = observation.get("duration_ms", 0)
        report["host_tools"] = observation.get("host_tools", [])
        report["runtime_assets"] = observation.get("assets", [])
        report["rootfs"] = observation.get("rootfs")
        observed_kvm = observation.get("kvm")
        if type(observed_kvm) is dict:
            report["kvm"] = {
                "device_present": observed_kvm.get("device_present") is True,
                "device_accessible": observed_kvm.get("device_accessible") is True,
                "api_version": observed_kvm.get("api_version") if observed_kvm.get("api_version") == 12 else None,
            }
        observed = observation.get("status") == "observed"
        report["checks"].update({
            "platform": "pass", "root": "pass", "source": "pass",
            "kvm": "pass" if report["kvm"]["api_version"] == 12 else "fail",
            "artifact_cache": "pass" if type(report["rootfs"]) is dict and report["rootfs"].get("cache_count") == 16 else "fail",
            "rootfs_candidates": "pass" if type(report["rootfs"]) is dict and report["rootfs"].get("pins_match") is True else "fail",
            "runtime_assets": "pass" if len(report["runtime_assets"]) == 2 and all(row.get("downloaded") is True for row in report["runtime_assets"]) else "fail",
            "host_tools": "blocked", "cleanup": "pass" if cleanup.get("success") is True else "fail",
            "residue": "pass" if residue.get("clean") is True else "fail",
        })
        blockers = list(observation.get("codes", []))
        if not observed:
            blockers.append("observe-uncertainty")
        if cleanup.get("success") is not True:
            blockers.append("cleanup-uncertainty")
        if residue.get("clean") is not True:
            blockers.append("residue-uncertainty")
        report["blockers"] = list(dict.fromkeys(blockers))
        codes.extend(cleanup.get("codes", [])); codes.extend(residue.get("codes", []))
    except BaseException:
        codes.append("report-input-uncertainty")
    report["diagnostic_codes"] = list(dict.fromkeys(codes))
    raw = _canonical_report(report)
    _write_json_once(REPORT, report, "report-owned")
    _fail(_read_regular(REPORT, MAX_JSON, 0o400) == raw, "report-validation")
    return 0


def _validate():
    _fixed_preflight(False)
    _require_state()
    raw = _read_regular(REPORT, MAX_JSON, 0o400)
    _fail(_canonical_report(_strict_json(raw)) == raw, "report-validation")
    return 0


def _export():
    _validate()
    _append_journal("export-intent", {"root": str(EXPORT_ROOT), "name": EXPORT_REPORT.name})
    _fail(not os.path.lexists(EXPORT_ROOT), "export-preexisting")
    os.mkdir(EXPORT_ROOT, 0o755)
    _fsync_directory(EXPORT_ROOT.parent)
    directory_identity = _identity(os.stat(EXPORT_ROOT, follow_symlinks=False))
    _fail(directory_identity["uid"] == directory_identity["gid"] == 0 and
          directory_identity["mode"] == 0o755, "export-policy")
    raw = _canonical_report(_strict_json(_read_regular(REPORT, MAX_JSON, 0o400)))
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


def _cleanup_export():
    _fixed_preflight(False)
    _require_state()
    owned = _one_record(_require_state(), "export-owned")
    if not os.path.lexists(EXPORT_ROOT):
        _fail(owned is None, "export-residue-unknown")
        return 0
    _fail(owned is not None, "export-cleanup-unowned")
    directory = os.open(EXPORT_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        _fail(_same_directory_authority(os.fstat(directory), owned["directory"]), "export-cleanup-replaced")
        _fail(set(os.listdir(directory)) == {EXPORT_REPORT.name}, "export-cleanup-unknown")
        descriptor = _owned_file(directory, EXPORT_REPORT.name, owned["file"], owned["sha256"])
        _unlink_exact(directory, EXPORT_REPORT.name, descriptor, owned["file"], owned["sha256"])
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
    _rmdir_exact(EXPORT_ROOT, owned["directory"])
    _append_journal("export-cleaned", {"sha256": owned["sha256"]})
    return 0


def main(argv):
    actions = {
        "observe": _observe, "cleanup": _cleanup, "residue": _residue, "render": _render,
        "validate": _validate, "export": _export, "cleanup-export": _cleanup_export,
    }
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

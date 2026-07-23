#!/usr/bin/env python3
"""Read-only immutable rootfs input and transition planner for ADR 0038."""

from dataclasses import dataclass
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
import zlib

sys.dont_write_bytecode = True

from completion_archive_preflight import (
    MaterialRecord,
    PreflightedTar,
    _read_fixed_package,
    preflight_deb_payload,
    preflight_oci_layer_bytes,
)

VERSION = "cogs.stage2-completion-rootfs-plan/v1"
SOURCE_DATE_EPOCH = 1782172800
REMOTE = Path(__file__).resolve().parent
VERIFIER_PATH = REMOTE / "verify-completion-artifacts.py"
PACKAGE_ORDER = (
    "git",
    "openssh-server",
    "libcom-err2",
    "libgssapi-krb5-2",
    "libk5crypto3",
    "libkeyutils1",
    "libkrb5-3",
    "libkrb5support0",
    "libwrap0",
    "libwtmpdb0",
)


class RootfsPlanError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise RootfsPlanError()


@dataclass(frozen=True)
class EntryIdentity:
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    archive_size: int
    link_text: str | None
    resolved_link_path: str | None
    hardlink_target: str | None
    content_sha256: str | None


@dataclass(frozen=True)
class PlannedEntry:
    source: str
    owner: PreflightedTar | None
    record: MaterialRecord
    generated_content: bytes | None = None

    def content(self):
        _fail(self.record.kind == "file")
        if self.generated_content is not None:
            _fail(len(self.generated_content) == self.record.archive_size)
            return memoryview(self.generated_content)
        _fail(self.owner is not None)
        return self.owner.content(self.record)


@dataclass(frozen=True)
class Transition:
    path: str
    action: str
    expected: EntryIdentity | None
    result: PlannedEntry | None


@dataclass(frozen=True)
class RootfsPlan:
    source_order: tuple[str, ...]
    entries: tuple[PlannedEntry, ...]
    transitions: tuple[Transition, ...]


def _file_identity(mode, gid, mtime, size, digest):
    return EntryIdentity("file", mode, 0, gid, mtime, size, None, None, None, digest)


def _directory_identity(mode, mtime):
    return EntryIdentity("directory", mode, 0, 0, mtime, 0, None, None, None, None)


_ACCOUNT_EXPECTED = {
    "etc/passwd": _file_identity(
        0o644, 0, SOURCE_DATE_EPOCH, 839,
        "21352194cc533bc5878721507450d867d28ccb1c2f5cd773c792251fa1e63185",
    ),
    "etc/group": _file_identity(
        0o644, 0, SOURCE_DATE_EPOCH, 434,
        "74842904631a5088b134a25257b8180367913d2b64cf1e3fed061db5fcbd8379",
    ),
    "etc/shadow": _file_identity(
        0o640, 42, SOURCE_DATE_EPOCH, 474,
        "f2006a36b96df0ce4c9204a26fa9106337b2a4aade2d86c0003c660b3a89972d",
    ),
    "etc/gshadow": _file_identity(
        0o640, 42, SOURCE_DATE_EPOCH, 364,
        "27d5db44cdaa830dee778f68b22a34cd9ac4b3fa84f185592bcc2952fa22ce26",
    ),
}
_PARENT_EXPECTED = {
    "run": _directory_identity(0o755, SOURCE_DATE_EPOCH),
    "etc/ssh": _directory_identity(0o755, 1778070812),
    "usr/sbin/nologin": _file_identity(
        0o755, 0, 1746831247, 22912,
        "aeec170744644673ce699b98fdb517fd5c672af1322de37c4315cdd43e7f3945",
    ),
}
_ACCOUNT_LINES = {
    "etc/passwd": b"sshd:x:101:101::/run/sshd:/usr/sbin/nologin\n",
    "etc/group": b"sshd:x:101:\n",
    "etc/shadow": b"sshd:!:0:0:99999:7:::\n",
    "etc/gshadow": b"sshd:!::\n",
}
_SSHD_CONFIG = b"""Port 22
ListenAddress 192.0.2.2
HostKey /run/cogs-stage2-ssh/ssh_host_ed25519_key
PidFile /run/cogs-stage2-ssh/sshd.pid
AuthorizedKeysFile /run/cogs-stage2-ssh/authorized_keys
PermitRootLogin prohibit-password
StrictModes yes
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
AllowUsers root
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
PermitTTY no
UseDNS no
MaxAuthTries 2
MaxSessions 1
LoginGraceTime 15
ClientAliveInterval 0
PrintMotd no
PrintLastLog no
"""


def identity(record):
    return EntryIdentity(
        record.kind,
        record.mode,
        record.uid,
        record.gid,
        record.mtime,
        record.archive_size,
        record.link_text,
        record.resolved_link_path,
        record.hardlink_target,
        record.content_sha256,
    )


def _path(value):
    _fail(type(value) is str and value and not value.startswith("/") and "\\" not in value)
    parts = value.split("/")
    _fail(all(part not in {"", ".", ".."} for part in parts))
    return value


def _entry_map(plan):
    return {entry.record.path: entry for entry in plan.entries}


def _check_graph(entries):
    symlinks = {path for path, entry in entries.items() if entry.record.kind == "symlink"}
    for path, entry in entries.items():
        _path(path)
        record = entry.record
        _fail(record.path == path and (record.kind == "file" or record.archive_size == 0))
        _fail((record.kind == "file") == (record.content_sha256 is not None))
        _fail((record.kind == "symlink") == (record.link_text is not None and record.resolved_link_path is not None))
        _fail((record.kind == "hardlink") == (record.hardlink_target is not None))
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            _fail(parent in entries and entries[parent].record.kind == "directory" and parent not in symlinks)
        if record.kind == "hardlink":
            target = entries.get(record.hardlink_target)
            _fail(target is not None and target.record.kind == "file")
            _fail(
                (record.mode, record.uid, record.gid, record.mtime)
                == (target.record.mode, target.record.uid, target.record.gid, target.record.mtime)
            )


def plan_sources(base, packages):
    _fail(type(base) is PreflightedTar and type(packages) is tuple)
    names = ("oci-layer",) + tuple(name for name, _archive in packages)
    _fail(len(names) == len(set(names)) and all(type(name) is str and name for name in names))
    entries = {}
    for source, archive in (("oci-layer", base), *packages):
        _fail(type(archive) is PreflightedTar)
        for record in archive.records:
            current = entries.get(record.path)
            if current is not None:
                _fail(current.record.kind == record.kind == "directory")
            entries[record.path] = PlannedEntry(source, archive, record)
    _check_graph(entries)
    ordered = tuple(entries[path] for path in sorted(entries, key=lambda value: value.encode("utf-8")))
    return RootfsPlan(names, ordered, ())


def apply_transitions(source_plan, transitions):
    _fail(type(source_plan) is RootfsPlan and type(transitions) is tuple)
    entries = _entry_map(source_plan)
    seen = set()
    for transition in transitions:
        _fail(type(transition) is Transition and transition.action in {"create", "replace", "delete"})
        path = _path(transition.path)
        _fail(path not in seen)
        seen.add(path)
        current = entries.get(path)
        if transition.action == "create":
            _fail(current is None and transition.expected is None and transition.result is not None)
        else:
            _fail(current is not None and transition.expected == identity(current.record))
            _fail((transition.action == "replace") == (transition.result is not None))
        if transition.result is None:
            entries.pop(path, None)
        else:
            _fail(transition.result.record.path == path)
            if transition.result.record.kind == "file":
                content = bytes(transition.result.content())
                _fail(hashlib.sha256(content).hexdigest() == transition.result.record.content_sha256)
            entries[path] = transition.result
    _check_graph(entries)
    ordered = tuple(entries[path] for path in sorted(entries, key=lambda value: value.encode("utf-8")))
    return RootfsPlan(source_plan.source_order, ordered, transitions)


def _generated_file(path, content, mode, gid=0):
    raw = bytes(content)
    record = MaterialRecord(
        path=path,
        kind="file",
        mode=mode,
        uid=0,
        gid=gid,
        mtime=SOURCE_DATE_EPOCH,
        archive_size=len(raw),
        link_text=None,
        resolved_link_path=None,
        hardlink_target=None,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        data_offset=-1,
    )
    return PlannedEntry("generated", None, record, raw)


def _generated_directory(path, mode):
    record = MaterialRecord(
        path=path,
        kind="directory",
        mode=mode,
        uid=0,
        gid=0,
        mtime=SOURCE_DATE_EPOCH,
        archive_size=0,
        link_text=None,
        resolved_link_path=None,
        hardlink_target=None,
        content_sha256=None,
        data_offset=-1,
    )
    return PlannedEntry("generated", None, record)


def _require_accounts(plan):
    entries = _entry_map(plan)
    for path, expected in {**_ACCOUNT_EXPECTED, **_PARENT_EXPECTED}.items():
        _fail(path in entries and identity(entries[path].record) == expected)
    for path, expected in _ACCOUNT_EXPECTED.items():
        raw = bytes(entries[path].content())
        _fail(raw.endswith(b"\n") and hashlib.sha256(raw).hexdigest() == expected.content_sha256)
        lines = raw.decode("utf-8").splitlines()
        _fail(all(line and len(line.split(":")) >= 3 for line in lines))
        _fail(all(line.split(":", 1)[0] != "sshd" for line in lines))
        if path in {"etc/passwd", "etc/group"}:
            _fail(all(parts[2] != "101" for parts in (line.split(":") for line in lines)))


def fixed_transitions(source_plan):
    _require_accounts(source_plan)
    entries = _entry_map(source_plan)
    _fail(all(path not in entries for path in ("etc/ssh/sshd_config", "run/sshd", "run/cogs-stage2-ssh")))
    transitions = []
    for path in sorted(_ACCOUNT_EXPECTED, key=lambda value: value.encode("utf-8")):
        content = bytes(entries[path].content()) + _ACCOUNT_LINES[path]
        result = _generated_file(path, content, entries[path].record.mode, entries[path].record.gid)
        transitions.append(Transition(path, "replace", _ACCOUNT_EXPECTED[path], result))
    transitions.extend(
        (
            Transition("etc/ssh/sshd_config", "create", None, _generated_file("etc/ssh/sshd_config", _SSHD_CONFIG, 0o600)),
            Transition("run/cogs-stage2-ssh", "create", None, _generated_directory("run/cogs-stage2-ssh", 0o700)),
            Transition("run/sshd", "create", None, _generated_directory("run/sshd", 0o755)),
        )
    )
    return tuple(sorted(transitions, key=lambda transition: transition.path.encode("utf-8")))


def _load_verifier():
    spec = importlib.util.spec_from_file_location("completion_artifact_verifier_for_plan", VERIFIER_PATH)
    _fail(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _decompress_layer(raw, row, maximum):
    _fail(type(raw) is bytes and len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"])
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    chunks = []
    total = 0
    try:
        for offset in range(0, len(raw), 1024 * 1024):
            _fail(not decoder.eof)
            pending = raw[offset : offset + 1024 * 1024]
            while pending or decoder.unconsumed_tail:
                output = decoder.decompress(pending, maximum + 1 - total)
                pending = decoder.unconsumed_tail
                total += len(output)
                _fail(total <= maximum and not decoder.unused_data)
                chunks.append(output)
        _fail(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
    except zlib.error as error:
        raise RootfsPlanError() from error
    expanded = b"".join(chunks)
    _fail(hashlib.sha256(expanded).hexdigest() == row["diff_id"])
    return expanded


def load_verified_plan():
    verifier = _load_verifier()
    verifier.verify_package_archives(verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT)
    contract = verifier.verify_contract(verifier.CONTRACT_PATH)
    cache = verifier.ARTIFACT_ROOT / "cache"
    layer_row = contract["oci"]["layer"]
    layer_raw = verifier.cached_bytes(cache, layer_row, contract["bounds"]["max_file_bytes"])
    base_raw = _decompress_layer(layer_raw, layer_row, contract["bounds"]["max_regular_bytes"])
    base = preflight_oci_layer_bytes(base_raw, contract["bounds"])
    packages = []
    _fail(tuple(row["name"] for row in contract["packages"]) == PACKAGE_ORDER)
    for row in contract["packages"]:
        package_raw = _read_fixed_package(cache / row["cache_name"], row)
        packages.append((row["name"], preflight_deb_payload(package_raw, row, contract["bounds"])))
    source_plan = plan_sources(base, tuple(packages))
    return apply_transitions(source_plan, fixed_transitions(source_plan))


def summary(plan):
    counts = {kind: 0 for kind in ("file", "directory", "symlink", "hardlink")}
    for entry in plan.entries:
        counts[entry.record.kind] += 1
    return {
        "version": VERSION,
        "result": "pass",
        "source_count": len(plan.source_order),
        "entry_count": len(plan.entries),
        "transition_count": len(plan.transitions),
        "kinds": counts,
    }


def main(argv):
    try:
        if argv != ["verify-plan"]:
            raise RootfsPlanError()
        value = summary(load_verified_plan())
    except Exception:
        print("completion rootfs planning failed", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

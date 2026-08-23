"""Canonical ownership ledger and hardlink state models for ADR 0040."""

from dataclasses import dataclass, field, replace
import hashlib
import json
import os
import sys
import time

sys.dont_write_bytecode = True

from completion_rootfs_fs import (
    HeldNode,
    HostGeneration,
    HostKey,
    OperationControl,
    ParentDelta,
    RootfsFsError,
    ROOTFS_LEDGER_MAX_BYTES,
    ROOTFS_LEDGER_MAX_RECORDS,
    _name,
    _observe_node,
    _path,
    _require_empty_fd_xattrs,
    _structural_increment,
)

VERSION = "cogs.stage2-rootfs-ledger/v1"
MAX_LINE_BYTES = 16_384
MAX_LEDGER_BYTES = ROOTFS_LEDGER_MAX_BYTES
MAX_RECORDS = ROOTFS_LEDGER_MAX_RECORDS
OFFSET_WIDTH = 16
ZERO_SHA256 = "0" * 64
TOKEN_LENGTH = 64
KATA_OPERATION_MAX_RECORDS = 16_384
KATA_OPERATION_MAX_BYTES = 16 * 1024 * 1024
CANDIDATE_TAR_PATH = ".cogs-rootfs-candidate-v1.tar"
CANDIDATE_TAR_SIZE = 136_905_728
CANDIDATE_RECORD_TYPES = frozenset({
    "candidate-tar-intent", "candidate-tar-abort", "candidate-tar-observed", "candidate-tar-settled",
})
RECORD_TYPES = frozenset(
    {
        "genesis",
        "genesis-settled",
        "genesis-abort",
        "operation-create-intent",
        "operation-create-observed",
        "operation-create-settled",
        "operation-abort",
        "create-intent",
        "create-abort",
        "create-observed",
        "create-settled",
        *CANDIDATE_RECORD_TYPES,
        "metadata-intent",
        "metadata-observed",
        "metadata-settled",
        "hardlink-group",
        "hardlink-create-intent",
        "hardlink-create-abort",
        "hardlink-create-observed",
        "hardlink-create-settled",
        "remove-intent",
        "remove-observed",
        "remove-settled",
        "operation-remove-intent",
        "operation-absent",
        "retired",
        "leased",
        "release-authorized",
        "prestage-release-authorized",
        "uncertain",
    }
)
KINDS = frozenset({"directory", "file", "symlink", "hardlink", "infrastructure"})
UNCERTAIN_REASONS = frozenset({"malformed", "contradictory", "replaced", "unknown", "incomplete", "mount-drift"})
GENERATION_KEYS = ("mount_id", "device", "inode", "kind", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
PARENT_KEYS = ("generation", "names")
METADATA_KEYS = ("mode", "uid", "gid", "size", "mtime_ns")
ENVELOPE_KEYS = (
    "version",
    "sequence",
    "previous_sequence",
    "previous_offset",
    "previous_sha256",
    "next_offset",
    "record_type",
    "body",
)


class LedgerError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise LedgerError()


def _integer(value, minimum=0, maximum=(1 << 64) - 1):
    _fail(type(value) is int and minimum <= value <= maximum)
    return value


def _digest(value, allow_zero=False):
    _fail(type(value) is str and len(value) == 64)
    _fail(all(character in "0123456789abcdef" for character in value))
    _fail(allow_zero or value != ZERO_SHA256)
    return value


def _token(value):
    _fail(type(value) is str and len(value) == TOKEN_LENGTH)
    _fail(all(character in "0123456789abcdef" for character in value))
    return value


def _operation_name(token):
    return "operation-" + _token(token)


def _graph_path(value):
    _path(value)
    return value


def _exact_keys(value, keys):
    _fail(type(value) is dict and tuple(value) == tuple(keys))


def _reject_bool(value):
    if type(value) is bool:
        raise LedgerError()
    if type(value) is dict:
        for item in value.values():
            _reject_bool(item)
    elif type(value) is list:
        for item in value:
            _reject_bool(item)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _fail(type(key) is str and key not in result)
        result[key] = value
    return result


@dataclass(frozen=True)
class FrozenObject:
    items: tuple

    def __post_init__(self):
        _fail(type(self.items) is tuple and all(type(item) is tuple and len(item) == 2 and type(item[0]) is str for item in self.items))
        _fail(len(self.items) == len({item[0] for item in self.items}))


@dataclass(frozen=True)
class FrozenArray:
    items: tuple

    def __post_init__(self):
        _fail(type(self.items) is tuple)


def _freeze(value):
    if type(value) is dict:
        return FrozenObject(tuple((key, _freeze(item)) for key, item in value.items()))
    if type(value) is list:
        return FrozenArray(tuple(_freeze(item) for item in value))
    _fail(type(value) in {str, int, type(None)})
    return value


def _thaw(value):
    if type(value) is FrozenObject:
        return {key: _thaw(item) for key, item in value.items}
    if type(value) is FrozenArray:
        return [_thaw(item) for item in value.items]
    return value


def _generation_value(value):
    _fail(type(value) is HostGeneration)
    return {
        "mount_id": value.key.mount_id,
        "device": value.key.device,
        "inode": value.key.inode,
        "kind": value.key.kind,
        "mode": value.mode,
        "uid": value.uid,
        "gid": value.gid,
        "nlink": value.nlink,
        "size": value.size,
        "mtime_ns": value.mtime_ns,
        "ctime_ns": value.ctime_ns,
    }


def _parse_generation(value, minimum_nlink=1):
    _exact_keys(value, GENERATION_KEYS)
    kind = value["kind"]
    _fail(kind in {"directory", "file", "symlink", "other"})
    key = HostKey(
        _integer(value["mount_id"], 1),
        _integer(value["device"]),
        _integer(value["inode"], 1),
        kind,
    )
    return HostGeneration(
        key,
        _integer(value["mode"], 0, 0o7777),
        _integer(value["uid"]),
        _integer(value["gid"]),
        _integer(value["nlink"], minimum_nlink),
        _integer(value["size"]),
        _integer(value["mtime_ns"]),
        _integer(value["ctime_ns"]),
    )


@dataclass(frozen=True)
class LedgerParent:
    generation: HostGeneration
    names: tuple[str, ...]

    def __post_init__(self):
        _fail(type(self.generation) is HostGeneration and self.generation.key.kind == "directory")
        _fail(type(self.names) is tuple and all(type(item) is str for item in self.names))
        encoded = tuple(item.encode("utf-8") for item in self.names)
        _fail(encoded == tuple(sorted(set(encoded))))
        for item in self.names:
            _name(item)


def _metadata_value(mode, uid, gid, size, mtime_ns):
    return {"mode": mode, "uid": uid, "gid": gid, "size": size, "mtime_ns": mtime_ns}


def _parse_metadata(value):
    _exact_keys(value, METADATA_KEYS)
    return tuple(_integer(value[key], 0, 0o7777 if key == "mode" else (1 << 64) - 1) for key in METADATA_KEYS)


def _parent_value(value):
    _fail(type(value) is LedgerParent)
    return {"generation": _generation_value(value.generation), "names": list(value.names)}


def _parse_parent(value):
    _exact_keys(value, PARENT_KEYS)
    names = value["names"]
    _fail(type(names) is list)
    return LedgerParent(_parse_generation(value["generation"]), tuple(names))


def _candidate_generation(value, nlink):
    generation = _parse_generation(value, 0)
    _fail(generation.key.kind == "file" and generation.nlink == nlink)
    _fail(generation.mode == 0o600 and generation.uid == generation.gid == 0)
    return generation


def _candidate_transition(anonymous, linked):
    _fail(anonymous.key == linked.key and anonymous.nlink == 0 and linked.nlink == 1)
    _fail(_same_fields(anonymous, linked, {"nlink", "ctime_ns"}))
    _fail(linked.ctime_ns >= anonymous.ctime_ns)


def _candidate_parent_transition(before, after):
    _parent_delta("hardlink", CANDIDATE_TAR_PATH, before, after)
    _fail(_same_fields(before.generation, after.generation, {"size", "mtime_ns", "ctime_ns"}))
    for field_name in ("size", "mtime_ns", "ctime_ns"):
        _fail(getattr(after.generation, field_name) >= getattr(before.generation, field_name))


def _parent_delta(action, name, before, after):
    _fail(type(before) is LedgerParent and type(after) is LedgerParent)
    _fail(before.generation.key == after.generation.key)
    for field_name in ("mode", "uid", "gid"):
        _fail(getattr(before.generation, field_name) == getattr(after.generation, field_name))
    before_names = set(before.names)
    after_names = set(after.names)
    if action in {"create", "hardlink"}:
        _fail(name not in before_names and after_names == before_names | {name})
    elif action in {"unlink", "rmdir"}:
        _fail(name in before_names and after_names == before_names - {name})
    else:
        _fail(action == "metadata" and before_names == after_names)


def _valid_abort_parent(before, after):
    return before.names == after.names and _same_fields(before.generation, after.generation, {"mtime_ns", "ctime_ns"})


def _valid_parent_delta(action, name, before, after):
    try:
        _parent_delta(action, name, before, after)
        return True
    except (LedgerError, RootfsFsError):
        return False


@dataclass(frozen=True)
class SettledBytes:
    sequence: int
    offset: int
    line_sha256: str

    def __post_init__(self):
        _integer(self.sequence, -1, MAX_RECORDS - 1)
        _integer(self.offset, 0, MAX_LEDGER_BYTES)
        _digest(self.line_sha256, allow_zero=self.sequence == -1)
        _fail((self.sequence == -1) == (self.offset == 0 and self.line_sha256 == ZERO_SHA256))


def _settled_record(sequence, offset, line_sha256, minimum_sequence=0):
    _integer(minimum_sequence, 0, MAX_RECORDS - 1)
    _integer(sequence, minimum_sequence, MAX_RECORDS - 1)
    _integer(offset, 1, MAX_LEDGER_BYTES)
    _digest(line_sha256)
    return SettledBytes(sequence, offset, line_sha256)


INITIAL_BYTES = SettledBytes(-1, 0, ZERO_SHA256)


@dataclass(frozen=True)
class LedgerRecord:
    sequence: int
    previous_sequence: int
    previous_offset: int
    previous_sha256: str
    next_offset: int
    record_type: str
    body: FrozenObject
    line_sha256: str

    def body_value(self):
        return _thaw(self.body)


@dataclass(frozen=True)
class LedgerProposal:
    record_type: str
    body: FrozenObject

    @classmethod
    def create(cls, record_type, body):
        normalized = _validate_body(record_type, body)
        return cls(record_type, _freeze(normalized))

    def body_value(self):
        return _thaw(self.body)


@dataclass(frozen=True)
class LedgerWriterState:
    node: HeldNode = field(compare=False)
    stable_key: HostKey
    settled: SettledBytes
    generation: HostGeneration

    def __post_init__(self):
        _fail(type(self.node) is HeldNode and self.node.operation_fd is not None)
        _fail(type(self.stable_key) is HostKey and type(self.settled) is SettledBytes)
        _fail(type(self.generation) is HostGeneration)
        _require_ledger_generation(self.generation, self.stable_key)
        _fail(self.generation.size == self.settled.offset)


@dataclass(frozen=True)
class ReconcileObservations:
    state_parent: LedgerParent
    operations: tuple[tuple[str, HostGeneration], ...]
    entries: tuple[tuple[str, HostGeneration], ...]
    ledger_generation: HostGeneration
    parents: tuple[tuple[str, LedgerParent], ...] = ()
    candidate_tar: tuple[int, str | None] | None = None

    def __post_init__(self):
        _fail(type(self.state_parent) is LedgerParent)
        _fail(type(self.ledger_generation) is HostGeneration and self.ledger_generation.key.kind == "file")
        for values in (self.operations, self.entries):
            _fail(type(values) is tuple)
            _fail(all(type(item) is tuple and len(item) == 2 and type(item[0]) is str and type(item[1]) is HostGeneration for item in values))
            names = tuple(item[0] for item in values)
            _fail(len(names) == len(set(names)))
        _fail(type(self.parents) is tuple and all(type(item) is tuple and len(item) == 2 for item in self.parents))
        _fail(all(type(path) is str and type(parent) is LedgerParent for path, parent in self.parents))
        _fail(len(self.parents) == len({path for path, _parent in self.parents}))
        for path, _parent in self.parents:
            _fail(path == "" or _graph_path(path) == path)
        for path, _generation in self.entries:
            _graph_path(path)
        _fail(self.candidate_tar is None or type(self.candidate_tar) is tuple and len(self.candidate_tar) == 2)
        if self.candidate_tar is not None:
            _integer(self.candidate_tar[0])
            _fail(self.candidate_tar[1] is None or type(self.candidate_tar[1]) is str)
            if self.candidate_tar[1] is not None:
                _digest(self.candidate_tar[1])


@dataclass(frozen=True)
class LeaseSnapshot:
    state_parent: LedgerParent
    operation: HostGeneration
    root: HostGeneration
    owned: tuple[tuple[str, HostGeneration], ...]
    ledger_key: HostKey
    settled: SettledBytes

    def __post_init__(self):
        _fail(type(self.state_parent) is LedgerParent and type(self.operation) is HostGeneration)
        _fail(type(self.root) is HostGeneration and self.root.key.kind == "directory")
        _fail(type(self.owned) is tuple and dict(self.owned).get("rootfs") == self.root)
        _fail(type(self.ledger_key) is HostKey and self.ledger_key.kind == "file")
        _fail(type(self.settled) is SettledBytes)


@dataclass(frozen=True)
class LegalHardlinkCursor:
    target_path: str
    aliases: tuple[str, ...]
    next_index: int

    def __post_init__(self):
        _graph_path(self.target_path)
        _fail(type(self.aliases) is tuple and self.aliases)
        for alias in self.aliases:
            _fail(type(alias) is str)
            _graph_path(alias)
        encoded = tuple(alias.encode("utf-8") for alias in self.aliases)
        _fail(self.target_path not in self.aliases and encoded == tuple(sorted(set(encoded))))
        _integer(self.next_index, 0, len(self.aliases))


@dataclass(frozen=True)
class PersistentMapEntry:
    key: str
    value: object

    def __post_init__(self):
        _fail(type(self.key) is str and len(self.key.encode("utf-8")) <= 4096)
        _fail(type(self.value) in {LegalHardlinkCursor, LedgerParent} or self.value is _MISSING)


@dataclass(frozen=True)
class PersistentMapNode:
    zero: object = None
    one: object = None
    entry: PersistentMapEntry | None = None

    def __post_init__(self):
        _fail(self.zero is None or type(self.zero) is PersistentMapNode)
        _fail(self.one is None or type(self.one) is PersistentMapNode)
        _fail(self.entry is None or type(self.entry) is PersistentMapEntry)


@dataclass(frozen=True)
class PersistentMap:
    root: PersistentMapNode | None
    count: int

    def __post_init__(self):
        _fail(self.root is None or type(self.root) is PersistentMapNode)
        _integer(self.count, 0, MAX_RECORDS)
        _fail((self.root is None) == (self.count == 0))


_EMPTY_MAP = PersistentMap(None, 0)
_MISSING = object()


def _key_bits(raw):
    for value in raw:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1


def _collision_get(root, key, group_metric=False):
    node = root
    for bit in _key_bits(key.encode("utf-8")):
        if group_metric:
            _structural_increment("group_lookup_steps")
        if node is None:
            return _MISSING
        node = node.one if bit else node.zero
    if node is None or node.entry is None or node.entry.key != key:
        return _MISSING
    return node.entry.value


def _collision_set(root, key, value):
    nodes = []
    node = root
    bits = tuple(_key_bits(key.encode("utf-8")))
    for bit in bits:
        nodes.append(node)
        node = None if node is None else (node.one if bit else node.zero)
    child = PersistentMapNode(
        None if node is None else node.zero,
        None if node is None else node.one,
        PersistentMapEntry(key, value),
    )
    copies = 1
    for bit, previous in reversed(tuple(zip(bits, nodes))):
        zero = None if previous is None else previous.zero
        one = None if previous is None else previous.one
        child = PersistentMapNode(zero if bit else child, child if bit else one, None if previous is None else previous.entry)
        copies += 1
    return child, copies


def _map_leaf_get(entry, collisions, key, group_metric=False):
    if entry is not None and entry.key == key:
        return entry.value
    if collisions is not None:
        return _collision_get(collisions, key, group_metric)
    return _MISSING


def _map_get(mapping, key, group_metric=False):
    _fail(type(mapping) is PersistentMap and type(key) is str)
    node = mapping.root
    for bit in _key_bits(hashlib.sha256(key.encode("utf-8")).digest()):
        if group_metric:
            _structural_increment("group_lookup_steps")
        if node is None:
            return _MISSING
        node = node.one if bit else node.zero
    if node is None:
        return _MISSING
    return _map_leaf_get(node.entry, node.zero, key, group_metric)


def _map_set(mapping, key, value, group_metric=False):
    _fail(type(mapping) is PersistentMap and type(key) is str)
    bits = tuple(_key_bits(hashlib.sha256(key.encode("utf-8")).digest()))
    nodes = []
    node = mapping.root
    for bit in bits:
        nodes.append(node)
        node = None if node is None else (node.one if bit else node.zero)
    previous = _MISSING if node is None else _map_leaf_get(node.entry, node.zero, key, group_metric)
    if previous is _MISSING and value is _MISSING:
        return mapping
    entry = None if node is None else node.entry
    collisions = None if node is None else node.zero
    collision_copies = 0
    if entry is None:
        entry = PersistentMapEntry(key, value)
    elif entry.key == key:
        entry = PersistentMapEntry(key, value)
    else:
        collisions, copied = _collision_set(collisions, entry.key, entry.value)
        collision_copies += copied
        collisions, copied = _collision_set(collisions, key, value)
        collision_copies += copied
    child = PersistentMapNode(collisions, None, entry)
    copies = 1
    for bit, old in reversed(tuple(zip(bits, nodes))):
        zero = None if old is None else old.zero
        one = None if old is None else old.one
        child = PersistentMapNode(zero if bit else child, child if bit else one, None if old is None else old.entry)
        copies += 1
    if group_metric:
        _structural_increment("group_node_copies", copies + collision_copies)
    count = mapping.count + (previous is _MISSING and value is not _MISSING) - (
        previous is not _MISSING and value is _MISSING
    )
    return _EMPTY_MAP if count == 0 else PersistentMap(child, count)


def _map_without(mapping, key):
    if _map_get(mapping, key) is _MISSING:
        return mapping
    return _map_set(mapping, key, _MISSING)


@dataclass(frozen=True)
class LedgerLegalState:
    settled: SettledBytes
    token: str
    phase: str
    operation_name: str | None
    state_parent: LedgerParent
    operation_parent: LedgerParent | None
    groups: PersistentMap
    parents: PersistentMap
    pending: LedgerRecord | None
    return_phase: str | None
    lease_snapshot: LeaseSnapshot | None
    previous: LedgerRecord

    def __post_init__(self):
        _fail(type(self.settled) is SettledBytes and type(self.phase) is str)
        _token(self.token)
        entry_phases = {
            "create-intent", "create-observed", "metadata-intent", "metadata-observed",
            "hardlink-create-intent", "hardlink-create-observed", "remove-intent", "remove-observed",
            "candidate-tar-intent", "candidate-tar-observed",
        }
        phases = entry_phases | {
            "genesis", "ready", "aborted", "retired", "operation-intent", "operation-observed",
            "active", "leased", "release-authorized", "prestage-release-authorized", "operation-remove", "operation-absent", "uncertain",
        }
        _fail(self.phase in phases)
        _fail(self.operation_name is None or self.operation_name == _operation_name(self.token))
        if self.phase not in {"genesis", "ready", "aborted", "retired", "uncertain"}:
            _fail(self.operation_name == _operation_name(self.token))
        _fail(type(self.state_parent) is LedgerParent)
        _fail(self.operation_parent is None or type(self.operation_parent) is LedgerParent)
        if self.phase in {
            "operation-observed", "active", "leased", "release-authorized", "prestage-release-authorized", "operation-remove",
            *entry_phases,
        }:
            _fail(type(self.operation_parent) is LedgerParent)
        if self.phase in {"genesis", "ready", "operation-intent", "aborted", "operation-absent", "retired"}:
            _fail(self.operation_parent is None)
        _fail(type(self.groups) is PersistentMap and type(self.parents) is PersistentMap)
        if self.phase in entry_phases:
            _fail(type(self.pending) is LedgerRecord and self.pending.record_type == self.phase)
            _fail(self.return_phase in {"active", "release-authorized", "prestage-release-authorized"})
        elif self.phase == "operation-remove":
            _fail(self.pending is None and self.return_phase in {"active", "release-authorized", "prestage-release-authorized"})
        else:
            _fail(self.pending is None and self.return_phase is None)
        _fail(self.lease_snapshot is None or type(self.lease_snapshot) is LeaseSnapshot)
        if self.phase in {
            "genesis", "ready", "aborted", "operation-intent", "operation-observed", "active",
        } or self.return_phase == "active":
            _fail(self.lease_snapshot is None)
        if self.phase in {"leased", "release-authorized", "prestage-release-authorized"} or self.return_phase in {"release-authorized", "prestage-release-authorized"}:
            _fail(type(self.lease_snapshot) is LeaseSnapshot)
        _fail(type(self.previous) is LedgerRecord)
        _fail((self.previous.sequence, self.previous.next_offset, self.previous.line_sha256) ==
              (self.settled.sequence, self.settled.offset, self.settled.line_sha256))


@dataclass(frozen=True, eq=False)
class LedgerHistory:
    previous: object = field(compare=False, repr=False)
    first: LedgerRecord
    terminal: LedgerRecord
    count: int
    legal: LedgerLegalState

    def __post_init__(self):
        _fail(self.previous is None or type(self.previous) is LedgerHistory)
        _fail(type(self.first) is LedgerRecord and type(self.terminal) is LedgerRecord)
        _integer(self.count, 1, MAX_RECORDS)
        _fail(type(self.legal) is LedgerLegalState and self.terminal is self.legal.previous)
        _fail((self.previous is None) == (self.count == 1))
        if self.previous is None:
            _fail(self.first is self.terminal)
        else:
            _fail(self.first is self.previous.first and self.count == self.previous.count + 1)

    def __reversed__(self):
        current = self
        while current is not None:
            yield current.terminal
            current = current.previous


@dataclass(frozen=True)
class LedgerState:
    status: str
    token: str
    operation_name: str | None
    owned: tuple[tuple[str, HostGeneration], ...]
    cleanup_allowed: bool
    cleanup_origin: str
    lease_seen: bool
    release_authorized: bool
    terminal_record: str
    lease_snapshot: LeaseSnapshot | None = None

    def __post_init__(self):
        _fail(type(self.status) is str and type(self.cleanup_allowed) is bool)
        _fail(type(self.cleanup_origin) is str and self.cleanup_origin in {"none", "prelease", "release-authorized", "prestage-authorized"})
        _fail(type(self.lease_seen) is bool and type(self.release_authorized) is bool)
        _fail(self.lease_snapshot is None or type(self.lease_snapshot) is LeaseSnapshot)
        prelease = {"genesis-settleable", "genesis-abortable", "operation-abortable", "operation-create-settleable", "entry-absent", "create-settleable", "metadata-settleable", "hardlink-create-settleable", "candidate-tar-abortable", "candidate-tar-observeable", "candidate-tar-settleable", "active"}
        removal = {"remove-retry", "remove-absence-settleable", "hardlink-remove-absence-settleable", "remove-settleable", "operation-remove-retry", "operation-absence-settleable", "retirable", "retired"}
        valid = ((self.status in prelease or self.status in removal) and self.cleanup_origin == "prelease" and self.cleanup_allowed)
        valid = valid or ((self.status == "release-authorized" or self.status in removal) and self.cleanup_origin == "release-authorized" and self.cleanup_allowed)
        valid = valid or ((self.status == "prestage-release-authorized" or self.status in removal) and self.cleanup_origin == "prestage-authorized" and self.cleanup_allowed)
        valid = valid or (self.status in {"leased", "preserve"} and self.cleanup_origin == "none" and not self.cleanup_allowed)
        _fail(valid and (not self.release_authorized or self.lease_seen))
        if self.status == "leased":
            _fail(self.lease_seen and not self.release_authorized and type(self.lease_snapshot) is LeaseSnapshot)
        if self.cleanup_origin == "prelease":
            _fail(not self.lease_seen and not self.release_authorized)
        if self.cleanup_origin == "release-authorized":
            _fail(self.lease_seen and self.release_authorized and type(self.lease_snapshot) is LeaseSnapshot)
        if self.cleanup_origin == "prestage-authorized":
            _fail(self.lease_seen and not self.release_authorized and type(self.lease_snapshot) is LeaseSnapshot)


@dataclass(frozen=True)
class HardlinkPlan:
    target_path: str
    aliases: tuple[str, ...]
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    content_sha256: str


@dataclass(frozen=True)
class HardlinkGroupState:
    plan: HardlinkPlan
    target: HostGeneration
    next_create_index: int
    settled_aliases: tuple[str, ...]
    removed_aliases: tuple[str, ...]

    def __post_init__(self):
        _fail(type(self.plan) is HardlinkPlan and type(self.target) is HostGeneration)
        _integer(self.next_create_index, 0, len(self.plan.aliases))
        _fail(self.settled_aliases == self.plan.aliases[: self.next_create_index])
        if self.removed_aliases:
            _fail(self.settled_aliases + tuple(reversed(self.removed_aliases)) == self.plan.aliases)
        _fail(self.target.nlink == 1 + len(self.settled_aliases))


@dataclass(frozen=True)
class HardlinkTransition:
    action: str
    alias_index: int
    before: HostGeneration
    after: HostGeneration
    parent_delta: ParentDelta


def _offset(value):
    _fail(type(value) is str and len(value) == OFFSET_WIDTH and value.isdigit())
    return _integer(int(value), 0, MAX_LEDGER_BYTES)


def _canonical_line(value):
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise LedgerError() from error
    _fail(len(raw) <= MAX_LINE_BYTES)
    return raw


def _encode_proposal(proposal, settled):
    _fail(type(proposal) is LedgerProposal and type(settled) is SettledBytes)
    body = _validate_body(proposal.record_type, proposal.body_value())
    sequence = settled.sequence + 1
    _fail(sequence < MAX_RECORDS)
    value = {
        "version": VERSION,
        "sequence": sequence,
        "previous_sequence": settled.sequence,
        "previous_offset": f"{settled.offset:0{OFFSET_WIDTH}d}",
        "previous_sha256": settled.line_sha256,
        "next_offset": "0" * OFFSET_WIDTH,
        "record_type": proposal.record_type,
        "body": body,
    }
    placeholder = _canonical_line(value)
    next_offset = settled.offset + len(placeholder)
    _fail(next_offset <= MAX_LEDGER_BYTES and len(str(next_offset)) <= OFFSET_WIDTH)
    value["next_offset"] = f"{next_offset:0{OFFSET_WIDTH}d}"
    raw = _canonical_line(value)
    _fail(len(raw) == len(placeholder) and settled.offset + len(raw) == next_offset)
    return raw


def _load_line(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=lambda _value: _fail(False))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, LedgerError) as error:
        raise LedgerError() from error
    _reject_bool(value)
    _exact_keys(value, ENVELOPE_KEYS)
    _fail(_canonical_line(value) == raw)
    return value


def _decode_ledger(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_LEDGER_BYTES and raw.endswith(b"\n") and b"\x00" not in raw)
    lines = raw.splitlines(keepends=True)
    _fail(0 < len(lines) <= MAX_RECORDS and all(line.endswith(b"\n") and 0 < len(line) <= MAX_LINE_BYTES for line in lines))
    records = []
    settled = INITIAL_BYTES
    for line in lines:
        value = _load_line(line)
        _fail(value["version"] == VERSION)
        sequence = _integer(value["sequence"], 0, MAX_RECORDS - 1)
        previous_sequence = _integer(value["previous_sequence"], -1, MAX_RECORDS - 2)
        previous_offset = _offset(value["previous_offset"])
        next_offset = _offset(value["next_offset"])
        previous_sha256 = _digest(value["previous_sha256"], allow_zero=sequence == 0)
        _fail(sequence == settled.sequence + 1 and previous_sequence == settled.sequence)
        _fail(previous_offset == settled.offset and previous_sha256 == settled.line_sha256)
        _fail(next_offset == settled.offset + len(line))
        body = _validate_body(value["record_type"], value["body"])
        digest = hashlib.sha256(line).hexdigest()
        records.append(LedgerRecord(sequence, previous_sequence, previous_offset, previous_sha256, next_offset, value["record_type"], _freeze(body), digest))
        settled = SettledBytes(sequence, next_offset, digest)
    _fail(settled.offset == len(raw))
    return tuple(records)


def _parse_ledger_history(raw):
    return _validated_history(_decode_ledger(raw))


def _parse_ledger(raw):
    return _history_records(_parse_ledger_history(raw))


def _validate_body(record_type, body):
    _fail(type(record_type) is str and record_type in RECORD_TYPES and type(body) is dict)
    token = body.get("token")
    _token(token)
    if record_type == "genesis":
        _exact_keys(body, ("token", "source_revision", "source_manifest_sha256", "state_parent", "ledger_key"))
        _fail(type(body["source_revision"]) is str and len(body["source_revision"]) == 40)
        _fail(all(character in "0123456789abcdef" for character in body["source_revision"]))
        _digest(body["source_manifest_sha256"])
        _parse_parent(body["state_parent"])
        key = body["ledger_key"]
        _exact_keys(key, ("mount_id", "device", "inode", "kind"))
        _fail(_parse_generation({**key, "mode": 0o600, "uid": 0, "gid": 0, "nlink": 1, "size": 0, "mtime_ns": 0, "ctime_ns": 0}).key.kind == "file")
    elif record_type in {"genesis-settled", "genesis-abort", "retired"}:
        _exact_keys(body, ("token", "state_parent"))
        _parse_parent(body["state_parent"])
    elif record_type == "leased":
        _exact_keys(body, ("token", "operation_name", "state_parent", "operation", "root", "ledger_key", "manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count"))
        _fail(body["operation_name"] == _operation_name(token))
        _parse_parent(body["state_parent"])
        _fail(_parse_generation(body["operation"]).key.kind == "directory")
        _fail(_parse_generation(body["root"]).key.kind == "directory")
        _parse_key(body["ledger_key"], "file")
        _digest(body["manifest_sha256"])
        _integer(body["manifest_size"], 1)
        _digest(body["ustar_sha256"])
        _fail(_integer(body["ustar_size"], 1) % 512 == 0)
        _integer(body["entry_count"], 1)
    elif record_type == "release-authorized":
        _exact_keys(body, ("token", "operation_name", "lease_sequence", "lease_offset", "lease_sha256", "kata_operation_token", "kata_ledger_key", "kata_release_sequence", "kata_release_offset", "kata_release_sha256"))
        _fail(body["operation_name"] == _operation_name(token))
        _settled_record(body["lease_sequence"], body["lease_offset"], body["lease_sha256"])
        _token(body["kata_operation_token"])
        _parse_key(body["kata_ledger_key"], "file")
        _settled_record(body["kata_release_sequence"], body["kata_release_offset"], body["kata_release_sha256"], 1)
    elif record_type == "prestage-release-authorized":
        _exact_keys(body, ("token", "operation_name", "lease_sequence", "lease_offset", "lease_sha256", "operation_binding"))
        _fail(body["operation_name"] == _operation_name(token))
        _settled_record(body["lease_sequence"], body["lease_offset"], body["lease_sha256"])
        _operation_binding(body["operation_binding"])
    elif record_type in {"operation-create-intent", "operation-abort", "operation-absent"}:
        _exact_keys(body, ("token", "operation_name", "state_parent"))
        _fail(body["operation_name"] == _operation_name(token))
        _parse_parent(body["state_parent"])
    elif record_type in {"operation-create-observed", "operation-create-settled", "operation-remove-intent"}:
        _exact_keys(body, ("token", "operation_name", "state_parent", "operation"))
        _fail(body["operation_name"] == _operation_name(token))
        _parse_parent(body["state_parent"])
        _parse_generation(body["operation"])
    elif record_type in {"create-intent", "create-abort"}:
        _exact_keys(body, ("token", "path", "kind", "parent"))
        _entry_common(body)
        _parse_parent(body["parent"])
    elif record_type in {"create-observed", "create-settled"}:
        _exact_keys(body, ("token", "path", "kind", "parent", "child"))
        _entry_common(body)
        _parse_parent(body["parent"])
        _parse_generation(body["child"])
    elif record_type in CANDIDATE_RECORD_TYPES:
        intent_keys = ("token", "path", "parent", "anonymous", "size", "sha256")
        observed_keys = ("token", "path", "parent", "anonymous", "linked", "size", "sha256")
        _exact_keys(body, intent_keys if record_type in {"candidate-tar-intent", "candidate-tar-abort"} else observed_keys)
        _fail(body["path"] == CANDIDATE_TAR_PATH)
        _parse_parent(body["parent"])
        anonymous = _candidate_generation(body["anonymous"], 0)
        size = _integer(body["size"], 1, CANDIDATE_TAR_SIZE)
        _fail(size == CANDIDATE_TAR_SIZE and anonymous.size == size)
        _digest(body["sha256"])
        if "linked" in body:
            linked = _candidate_generation(body["linked"], 1)
            _fail(linked.size == size)
            _candidate_transition(anonymous, linked)
    elif record_type == "metadata-intent":
        _exact_keys(body, ("token", "path", "before", "desired"))
        _graph_path(body["path"])
        _parse_generation(body["before"])
        _parse_metadata(body["desired"])
    elif record_type in {"metadata-observed", "metadata-settled"}:
        _exact_keys(body, ("token", "path", "child"))
        _graph_path(body["path"])
        _parse_generation(body["child"])
    elif record_type == "hardlink-group":
        _exact_keys(body, ("token", "target_path", "aliases", "content_sha256", "target"))
        target = _graph_path(body["target_path"])
        aliases = body["aliases"]
        _fail(type(aliases) is list and aliases and all(type(item) is str for item in aliases))
        for alias in aliases:
            _graph_path(alias)
        _fail(target not in aliases and len(aliases) == len(set(aliases)))
        _fail(tuple(item.encode("utf-8") for item in aliases) == tuple(sorted(item.encode("utf-8") for item in aliases)))
        _digest(body["content_sha256"])
        _fail(_parse_generation(body["target"]).key.kind == "file")
    elif record_type in {"hardlink-create-intent", "hardlink-create-abort"}:
        _exact_keys(body, ("token", "target_path", "alias", "index", "target", "parent"))
        _hardlink_common(body)
        _parse_generation(body["target"])
        _parse_parent(body["parent"])
    elif record_type in {"hardlink-create-observed", "hardlink-create-settled"}:
        _exact_keys(body, ("token", "target_path", "alias", "index", "target_before", "target_after", "alias_generation", "parent"))
        _hardlink_common(body)
        before = _parse_generation(body["target_before"])
        after = _parse_generation(body["target_after"])
        alias = _parse_generation(body["alias_generation"])
        _fail(alias == after)
        _hardlink_generation_change(before, after, 1)
        _parse_parent(body["parent"])
    elif record_type == "remove-intent":
        _exact_keys(body, ("token", "path", "kind", "parent", "child", "target_path"))
        _entry_common(body)
        _parse_parent(body["parent"])
        _parse_generation(body["child"])
        _nullable_path(body["target_path"])
    elif record_type in {"remove-observed", "remove-settled"}:
        _exact_keys(body, ("token", "path", "kind", "parent", "target_path", "target"))
        _entry_common(body)
        _parse_parent(body["parent"])
        _nullable_path(body["target_path"])
        target = body["target"]
        _fail(target is None or type(target) is dict)
        if target is not None:
            _parse_generation(target)
    else:
        _fail(record_type == "uncertain")
        _exact_keys(body, ("token", "reason"))
        _fail(body["reason"] in UNCERTAIN_REASONS)
    return body


def _parse_key(value, expected_kind):
    _exact_keys(value, ("mount_id", "device", "inode", "kind"))
    _fail(type(expected_kind) is str and value["kind"] == expected_kind)
    return HostKey(_integer(value["mount_id"], 1), _integer(value["device"]), _integer(value["inode"], 1), value["kind"])


def _operation_infrastructure(value):
    _exact_keys(value, ("completion_generation", "completion_names", "state_generation", "entries"))
    completion = _parse_generation(value["completion_generation"])
    _fail(completion.key.kind == "directory" and completion.mode == 0o700
          and completion.uid == completion.gid == 0 and completion.nlink >= 2)
    completion_names = value["completion_names"]
    allowed_completion = {"artifacts", "immutable-preparation-v1", "kata-input-v1",
                          "kata-operation-v1", "kata-runtime-v1", "rootfs-v1"}
    _fail(type(completion_names) is list and
          all(type(item) is str and item in allowed_completion for item in completion_names))
    _fail(completion_names == sorted(set(completion_names), key=lambda item: item.encode("ascii")))
    state = value["state_generation"]
    if state is not None:
        parsed_state = _parse_generation(state)
        _fail(parsed_state.key.kind == "directory" and parsed_state.mode == 0o700
              and parsed_state.uid == parsed_state.gid == 0 and parsed_state.nlink >= 2
              and (parsed_state.key.mount_id, parsed_state.key.device) ==
                  (completion.key.mount_id, completion.key.device))
        _fail("kata-operation-v1" in completion_names)
    else:
        _fail("kata-operation-v1" not in completion_names)
    entries = value["entries"]
    _fail(type(entries) is list and len(entries) <= 2)
    allowed = {".cogs-stage2-kata-operation-v1", ".cogs-stage2-kata-operation-lock-v1"}
    names = []
    for entry in entries:
        _exact_keys(entry, ("name", "generation"))
        _fail(type(entry["name"]) is str and entry["name"] in allowed)
        generation = _parse_generation(entry["generation"])
        expected_size = 0 if entry["name"].endswith("lock-v1") else len(b"cogs-stage2-kata-operation-v1\n")
        _fail(generation.key.kind == "file" and generation.mode == 0o600
              and generation.uid == generation.gid == 0 and generation.nlink == 1
              and generation.size == expected_size)
        if state is not None:
            _fail((generation.key.mount_id, generation.key.device) ==
                  (parsed_state.key.mount_id, parsed_state.key.device))
        names.append(entry["name"])
    _fail(names == sorted(set(names), key=lambda item: item.encode("ascii")))
    _fail(state is not None or not entries)


def _operation_binding(value):
    _fail(type(value) is dict and value.get("kind") in {"unadmitted-journal", "journal-absent"})
    if value["kind"] == "journal-absent":
        _exact_keys(value, ("kind", "infrastructure"))
        _operation_infrastructure(value["infrastructure"])
        return
    _exact_keys(value, (
        "kind", "operation_token", "journal_key", "journal_generation",
        "tip_sequence", "tip_offset", "tip_sha256", "phase", "infrastructure",
    ))
    _token(value["operation_token"])
    journal_key = _parse_key(value["journal_key"], "file")
    journal_generation = _parse_generation(value["journal_generation"])
    _fail(journal_generation.key == journal_key and journal_generation.key.kind == "file"
          and journal_generation.mode == 0o600 and journal_generation.uid == journal_generation.gid == 0
          and journal_generation.nlink == 1)
    _integer(value["tip_sequence"], 0, KATA_OPERATION_MAX_RECORDS - 1)
    _integer(value["tip_offset"], 1, KATA_OPERATION_MAX_BYTES)
    _fail(journal_generation.size == value["tip_offset"])
    _digest(value["tip_sha256"])
    _fail(value["phase"] in {"GENESIS", "GENESIS_SETTLED", "ROOTFS_ACQUIRE_INTENT", "ROOTFS_LEASED"})
    _operation_infrastructure(value["infrastructure"])
    state = value["infrastructure"]["state_generation"]
    _fail(state is not None and (journal_generation.key.mount_id,
          journal_generation.key.device) == (state["mount_id"], state["device"]))


def _entry_common(body):
    _graph_path(body["path"])
    _fail(body["kind"] in KINDS)


def _hardlink_common(body):
    _graph_path(body["target_path"])
    _graph_path(body["alias"])
    _integer(body["index"], 0, MAX_RECORDS - 1)


def _nullable_path(value):
    _fail(value is None or type(value) is str)
    if value is not None:
        _graph_path(value)


def _body(record):
    return record.body_value()


def _same_fields(left, right, excluded):
    fields = ("key", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
    return all(getattr(left, name) == getattr(right, name) for name in fields if name not in excluded)


def _hardlink_generation_change(before, after, delta):
    _fail(before.key.kind == after.key.kind == "file" and before.key == after.key)
    _fail(_same_fields(before, after, {"nlink", "ctime_ns"}))
    _fail(after.nlink == before.nlink + delta)


def _replay_graph(records):
    state_parent = None
    operation = None
    owned = {}
    hardlink_aliases = {}
    consistent = True
    for record in records:
        body = _body(record)
        kind = record.record_type
        if "state_parent" in body:
            state_parent = _parse_parent(body["state_parent"])
        if kind == "operation-create-settled":
            operation = _parse_generation(body["operation"])
        elif kind == "hardlink-group":
            hardlink_aliases[body["target_path"]] = tuple(body["aliases"])
        elif kind in {"create-settled", "metadata-settled"}:
            owned[body["path"]] = _parse_generation(body["child"])
        elif kind == "candidate-tar-settled":
            owned[body["path"]] = _candidate_generation(body["linked"], 1)
        elif kind == "hardlink-create-settled":
            linked = _parse_generation(body["alias_generation"])
            owned[body["alias"]] = linked
            if body["target_path"] in owned:
                owned[body["target_path"]] = linked
                for alias in hardlink_aliases[body["target_path"]]:
                    if alias in owned:
                        owned[alias] = linked
            else:
                consistent = False
        elif kind == "remove-settled":
            owned.pop(body["path"], None)
            if body["target"] is not None:
                if body["target_path"] in owned:
                    target = _parse_generation(body["target"])
                    owned[body["target_path"]] = target
                    for alias in hardlink_aliases[body["target_path"]]:
                        if alias in owned:
                            owned[alias] = target
                else:
                    consistent = False
        if kind in {"create-settled", "hardlink-create-settled", "remove-settled", "create-abort", "hardlink-create-abort", "candidate-tar-settled"}:
            path = body.get("path", body.get("alias"))
            if kind == "hardlink-create-abort" and body["target_path"] in owned:
                target = _parse_generation(body["target"])
                owned[body["target_path"]] = target
                for alias in hardlink_aliases[body["target_path"]]:
                    if alias in owned:
                        owned[alias] = target
            parent_path = path.rpartition("/")[0]
            parent_generation = _parse_parent(body["parent"]).generation
            if parent_path:
                consistent = consistent and parent_path in owned
                if parent_path in owned:
                    owned[parent_path] = parent_generation
            else:
                operation = parent_generation
        if kind == "operation-remove-intent":
            consistent = consistent and operation == _parse_generation(body["operation"])
        elif kind == "operation-absent":
            operation = None
    return state_parent, operation, owned, consistent


def _lease_from_record(records, record):
    state_parent, operation, owned, consistent = _replay_graph(records[: record.sequence])
    body = _body(record)
    key = _parse_key(_body(records[0])["ledger_key"], "file")
    _fail(consistent and operation is not None and "rootfs" in owned)
    _fail(_parse_parent(body["state_parent"]) == state_parent)
    _fail(_parse_generation(body["operation"]) == operation)
    _fail(_parse_generation(body["root"]) == owned["rootfs"])
    _fail(_parse_key(body["ledger_key"], "file") == key)
    settled = _settled_record(record.sequence, record.next_offset, record.line_sha256)
    return LeaseSnapshot(state_parent, operation, owned["rootfs"], tuple(sorted(owned.items())), key, settled)


def _lease_history(records):
    leased = next((record for record in records if record.record_type == "leased"), None)
    snapshot = None if leased is None else _lease_from_record(records, leased)
    release = next((record for record in records if record.record_type == "release-authorized"), None)
    prestage = next((record for record in records if record.record_type == "prestage-release-authorized"), None)
    _fail(release is None or prestage is None)
    authorized = release if release is not None else prestage
    started = authorized is not None and any(record.sequence > authorized.sequence and record.record_type in {"remove-intent", "operation-remove-intent"} for record in records)
    return snapshot, release is not None, prestage is not None, started


def _record_settled(record):
    return SettledBytes(record.sequence, record.next_offset, record.line_sha256)


def _history_records(history):
    _fail(type(history) is LedgerHistory)
    values = [None] * history.count
    current = history
    index = history.count - 1
    while current is not None:
        _fail(current.count == index + 1)
        values[index] = current.terminal
        current = current.previous
        index -= 1
    _fail(index == -1 and all(type(record) is LedgerRecord for record in values))
    return tuple(values)


def _history_with_record(history, record):
    _fail(type(history) is LedgerHistory and type(record) is LedgerRecord)
    values = [None] * (history.count + 1)
    current = history
    index = history.count - 1
    while current is not None:
        values[index] = current.terminal
        current = current.previous
        index -= 1
    _fail(index == -1)
    values[-1] = record
    _structural_increment("active_history_record_copies", 2 * (history.count + 1))
    return tuple(values)


def _initial_history(record):
    _fail(type(record) is LedgerRecord and record.record_type == "genesis")
    _fail((record.sequence, record.previous_sequence, record.previous_offset, record.previous_sha256) ==
          (0, -1, 0, ZERO_SHA256))
    state = LedgerLegalState(
        _record_settled(record), _body(record)["token"], "genesis", None,
        _parse_parent(_body(record)["state_parent"]), None,
        _EMPTY_MAP, _EMPTY_MAP, None, None, None, record,
    )
    return LedgerHistory(None, record, record, 1, state)


def _group_get(groups, target):
    value = _map_get(groups, target, True)
    _fail(value is _MISSING or type(value) is LegalHardlinkCursor)
    return None if value is _MISSING else value


def _group_set(groups, target, value):
    _fail(type(value) is LegalHardlinkCursor and value.target_path == target)
    return _map_set(groups, target, value, True)


def _entry_parent_path(body):
    path = body.get("alias", body.get("path"))
    _graph_path(path)
    return path.rpartition("/")[0]


def _require_parent_continuity(parents, operation_parent, body):
    path = _entry_parent_path(body)
    expected = operation_parent if path == "" else _map_get(parents, path)
    _fail(type(expected) is LedgerParent and expected == _parse_parent(body["parent"]))


def _settle_parent(parents, operation_parent, body):
    path = _entry_parent_path(body)
    parent = _parse_parent(body["parent"])
    if path == "":
        operation_parent = parent
    else:
        parents = _map_set(parents, path, parent)
    if body.get("kind") == "directory" and "child" in body:
        parents = _map_set(parents, body["path"], LedgerParent(_parse_generation(body["child"]), ()))
    if body.get("kind") == "directory" and body.get("target") is None and "child" not in body:
        parents = _map_without(parents, body["path"])
    return parents, operation_parent


def _settle_metadata_parent(parents, body):
    current = _map_get(parents, body["path"])
    if current is _MISSING:
        return parents
    _fail(type(current) is LedgerParent)
    return _map_set(parents, body["path"], LedgerParent(_parse_generation(body["child"]), current.names))


def _advance_history(history, record, count_incremental=True, replay_records=None):
    _fail(type(history) is LedgerHistory and type(record) is LedgerRecord)
    state = history.legal
    _fail((record.sequence, record.previous_sequence, record.previous_offset, record.previous_sha256) == (
        state.settled.sequence + 1, state.settled.sequence, state.settled.offset, state.settled.line_sha256,
    ))
    body = _body(record)
    _fail(body["token"] == state.token and state.phase not in {"retired", "uncertain"})
    kind = record.record_type
    phase = state.phase
    operation_name = state.operation_name
    state_parent = state.state_parent
    operation_parent = state.operation_parent
    groups = state.groups
    parents = state.parents
    pending = state.pending
    return_phase = state.return_phase
    lease_snapshot = state.lease_snapshot
    previous_body = _body(state.previous)
    if kind == "uncertain":
        phase, pending, return_phase = "uncertain", None, None
    elif phase == "genesis":
        _fail(kind == "genesis-settled" and _parse_parent(body["state_parent"]) == state_parent)
        phase = "ready"
    elif phase == "ready":
        _fail(kind in {"genesis-abort", "operation-create-intent"})
        _fail(_parse_parent(body["state_parent"]) == state_parent)
        if kind == "genesis-abort":
            phase = "aborted"
        else:
            operation_name = body["operation_name"]
            phase = "operation-intent"
    elif phase == "aborted":
        _fail(kind == "retired" and _parse_parent(body["state_parent"]) == state_parent)
        phase = "retired"
    elif phase == "operation-intent":
        _fail(kind in {"operation-create-observed", "operation-abort"} and body["operation_name"] == operation_name)
        if kind == "operation-create-observed":
            after = _parse_parent(body["state_parent"])
            _parent_delta("create", operation_name, state_parent, after)
            state_parent = after
            operation_parent = LedgerParent(_parse_generation(body["operation"]), ())
            phase = "operation-observed"
        else:
            _fail(_parse_parent(body["state_parent"]) == state_parent)
            phase = "aborted"
    elif phase == "operation-observed":
        _fail(kind == "operation-create-settled" and body["operation_name"] == operation_name)
        _fail(body == previous_body)
        phase = "active"
    elif phase in {"active", "release-authorized", "prestage-release-authorized"}:
        if kind == "leased":
            _fail(phase == "active" and pending is None and lease_snapshot is None)
            _fail(_parse_parent(body["state_parent"]) == state_parent)
            _fail(operation_parent is not None and _parse_generation(body["operation"]) == operation_parent.generation)
            if replay_records is None:
                replay_records = _history_with_record(history, record)
            else:
                _fail(type(replay_records) is tuple and replay_records[record.sequence] == record)
            lease_snapshot = _lease_from_record(replay_records, record)
            phase = "leased"
        elif kind == "operation-remove-intent":
            _fail(body["operation_name"] == operation_name and _parse_parent(body["state_parent"]) == state_parent)
            _fail(operation_parent is not None and operation_parent.names == ())
            _fail(_parse_generation(body["operation"]) == operation_parent.generation)
            return_phase, phase = phase, "operation-remove"
        elif kind == "hardlink-group":
            _fail(phase == "active")
            target = body["target_path"]
            _fail(_group_get(groups, target) is None)
            groups = _group_set(groups, target, LegalHardlinkCursor(target, tuple(body["aliases"]), 0))
        elif kind == "candidate-tar-intent":
            _fail(phase == "active" and pending is None and lease_snapshot is None)
            _fail(operation_parent == _parse_parent(body["parent"]))
            _fail(body["path"] not in operation_parent.names)
            pending, return_phase, phase = record, "active", "candidate-tar-intent"
        else:
            allowed = {"remove-intent"} if phase in {"release-authorized", "prestage-release-authorized"} else {
                "create-intent", "metadata-intent", "hardlink-create-intent", "remove-intent",
            }
            _fail(kind in allowed)
            if "parent" in body:
                _require_parent_continuity(parents, operation_parent, body)
            if kind == "hardlink-create-intent":
                target = body["target_path"]
                group = _group_get(groups, target)
                _fail(group is not None and group.next_index < len(group.aliases))
                _fail(body["index"] == group.next_index and body["alias"] == group.aliases[group.next_index])
            if kind == "remove-intent" and body["target_path"] is not None:
                target = body["target_path"]
                group = _group_get(groups, target)
                _fail(group is not None and group.next_index > 0 and body["path"] == group.aliases[group.next_index - 1])
            pending, return_phase = record, phase
            phase = kind.removesuffix("-intent") + "-intent"
    elif phase == "leased":
        _fail(kind in {"release-authorized", "prestage-release-authorized"} and lease_snapshot is not None)
        actual = lease_snapshot.settled
        _fail((body["lease_sequence"], body["lease_offset"], body["lease_sha256"]) ==
              (actual.sequence, actual.offset, actual.line_sha256))
        phase = kind
    elif phase == "candidate-tar-intent":
        _fail(pending is not None and kind in {"candidate-tar-abort", "candidate-tar-observed"})
        intent = _body(pending)
        if kind == "candidate-tar-abort":
            _fail(body == intent and _parse_parent(body["parent"]) == operation_parent)
            pending, phase, return_phase = None, "active", None
        else:
            _matching_transition(pending, record)
            pending, phase = record, "candidate-tar-observed"
    elif phase == "candidate-tar-observed":
        _fail(kind == "candidate-tar-settled" and pending is not None)
        _matching_transition(pending, record)
        operation_parent = _parse_parent(body["parent"])
        pending, phase, return_phase = None, "active", None
    elif phase.endswith("-intent"):
        abort_kind = phase.removesuffix("intent") + "abort"
        _fail(kind in {abort_kind, phase.removesuffix("intent") + "observed"} and pending is not None)
        if kind == abort_kind:
            _fail(return_phase == "active")
            intent_body = _body(pending)
            excluded = {"parent", "target"} if kind == "hardlink-create-abort" else {"parent"}
            _fail(all(body[key] == intent_body[key] for key in body if key not in excluded))
            if kind == "hardlink-create-abort":
                _fail(_same_fields(_parse_generation(body["target"]), _parse_generation(intent_body["target"]), {"ctime_ns"}))
            _fail(_valid_abort_parent(_parse_parent(intent_body["parent"]), _parse_parent(body["parent"])))
            parents, operation_parent = _settle_parent(parents, operation_parent, body)
            pending, phase, return_phase = None, return_phase, None
        else:
            _matching_transition(pending, record)
            pending = record
            phase = phase.removesuffix("intent") + "observed"
    elif phase.endswith("-observed"):
        _fail(kind == phase.removesuffix("observed") + "settled" and pending is not None)
        _matching_transition(pending, record)
        if kind == "hardlink-create-settled":
            target = body["target_path"]
            group = _group_get(groups, target)
            _fail(group is not None)
            groups = _group_set(groups, target, replace(group, next_index=group.next_index + 1))
        if kind == "remove-settled" and body["target"] is not None:
            target = body["target_path"]
            group = _group_get(groups, target)
            _fail(group is not None)
            groups = _group_set(groups, target, replace(group, next_index=group.next_index - 1))
        if kind == "metadata-settled":
            parents = _settle_metadata_parent(parents, body)
        elif "parent" in body:
            parents, operation_parent = _settle_parent(parents, operation_parent, body)
        pending, phase, return_phase = None, return_phase, None
    elif phase == "operation-remove":
        _fail(kind == "operation-absent" and body["operation_name"] == operation_name)
        after = _parse_parent(body["state_parent"])
        _parent_delta("rmdir", operation_name, state_parent, after)
        state_parent, operation_parent = after, None
        phase, return_phase = "operation-absent", None
    elif phase == "operation-absent":
        _fail(kind == "retired" and _parse_parent(body["state_parent"]) == state_parent)
        phase = "retired"
    else:
        raise LedgerError()
    legal = LedgerLegalState(
        _record_settled(record), state.token, phase, operation_name, state_parent, operation_parent,
        groups, parents, pending, return_phase, lease_snapshot, record,
    )
    if count_incremental:
        _structural_increment("incremental_records")
    return LedgerHistory(history, history.first, record, history.count + 1, legal)


def _validated_history(records):
    _fail(type(records) is tuple and records)
    _structural_increment("complete_legal_folds")
    history = _initial_history(records[0])
    for record in records[1:]:
        history = _advance_history(history, record, False, records)
    return history


def _validate_legal_records(records):
    return _validated_history(records).legal.phase


def _matching_transition(previous, current):
    left = _body(previous)
    right = _body(current)
    for key in ("path", "kind", "target_path", "alias", "index", "operation_name"):
        if key in left or key in right:
            _fail(left.get(key) == right.get(key))
    if previous.record_type.endswith("-observed"):
        _fail(left == right)
        return
    if previous.record_type == "candidate-tar-intent":
        _fail(right["token"] == left["token"] and right["path"] == left["path"])
        _fail(right["anonymous"] == left["anonymous"] and right["size"] == left["size"])
        _fail(right["sha256"] == left["sha256"])
        before, after = _parse_parent(left["parent"]), _parse_parent(right["parent"])
        _candidate_parent_transition(before, after)
        _candidate_transition(_candidate_generation(left["anonymous"], 0),
                              _candidate_generation(right["linked"], 1))
    elif previous.record_type == "create-intent":
        _parent_delta("create", left["path"].split("/")[-1], _parse_parent(left["parent"]), _parse_parent(right["parent"]))
        _fail(_parse_generation(right["child"]).key.kind == ("file" if left["kind"] == "hardlink" else left["kind"]))
    elif previous.record_type == "metadata-intent":
        before = _parse_generation(left["before"])
        child = _parse_generation(right["child"])
        _fail(before.key == child.key)
        _fail((child.mode, child.uid, child.gid, child.size, child.mtime_ns) == _parse_metadata(left["desired"]))
    elif previous.record_type == "hardlink-create-intent":
        _fail(_parse_generation(left["target"]) == _parse_generation(right["target_before"]))
        _parent_delta("hardlink", left["alias"].split("/")[-1], _parse_parent(left["parent"]), _parse_parent(right["parent"]))
    elif previous.record_type == "remove-intent":
        action = "rmdir" if left["kind"] == "directory" else "unlink"
        _parent_delta(action, left["path"].split("/")[-1], _parse_parent(left["parent"]), _parse_parent(right["parent"]))
        if left["target_path"] is None:
            _fail(right["target"] is None)
        else:
            _fail(right["target"] is not None)
            _hardlink_generation_change(_parse_generation(left["child"]), _parse_generation(right["target"]), -1)


def _reconcile_ledger(records, observations):
    _fail(type(records) is tuple and type(observations) is ReconcileObservations)
    phase = _validate_legal_records(records)
    token = _body(records[0])["token"]
    operation_name = _operation_name(token)
    lease_snapshot, release_authorized, prestage_authorized, authorized_removal_started = _lease_history(records)
    genesis_key = _parse_key(_body(records[0])["ledger_key"], "file")
    ledger_matches = observations.ledger_generation.key == genesis_key
    if lease_snapshot is not None:
        ledger_matches = ledger_matches and observations.ledger_generation.key == lease_snapshot.ledger_key
    operations = dict(observations.operations)
    entries = dict(observations.entries)
    parents = dict(observations.parents)
    owned = {}
    hardlink_aliases = {}
    pending = None
    operation_generation = None
    operation_intended = False
    operation_consistent = True
    state_parent = None
    for record in records:
        body = _body(record)
        kind = record.record_type
        if "state_parent" in body:
            state_parent = _parse_parent(body["state_parent"])
        if kind == "operation-create-intent":
            operation_intended = True
        if kind == "hardlink-group":
            hardlink_aliases[body["target_path"]] = tuple(body["aliases"])
        if kind == "operation-create-settled":
            operation_generation = _parse_generation(body["operation"])
        elif kind in {"create-settled", "metadata-settled"}:
            owned[body["path"]] = _parse_generation(body["child"])
        elif kind == "candidate-tar-settled":
            owned[body["path"]] = _candidate_generation(body["linked"], 1)
        elif kind == "hardlink-create-settled":
            linked = _parse_generation(body["alias_generation"])
            owned[body["alias"]] = linked
            if body["target_path"] in owned:
                owned[body["target_path"]] = linked
                for alias in hardlink_aliases[body["target_path"]]:
                    if alias in owned:
                        owned[alias] = linked
            else:
                operation_consistent = False
        elif kind == "remove-settled":
            owned.pop(body["path"], None)
            if body["target_path"] is not None and body["target"] is not None:
                if body["target_path"] in owned:
                    target = _parse_generation(body["target"])
                    owned[body["target_path"]] = target
                    for alias in hardlink_aliases[body["target_path"]]:
                        if alias in owned:
                            owned[alias] = target
                else:
                    operation_consistent = False
        if kind in {"create-settled", "hardlink-create-settled", "remove-settled", "candidate-tar-settled"}:
            path = body.get("path", body.get("alias"))
            parent_path = path.rpartition("/")[0]
            parent_generation = _parse_parent(body["parent"]).generation
            if parent_path:
                operation_consistent = operation_consistent and parent_path in owned
                if parent_path in owned:
                    owned[parent_path] = parent_generation
            else:
                operation_generation = parent_generation
        if kind in {"create-abort", "hardlink-create-abort"}:
            path = body.get("path", body.get("alias"))
            if kind == "hardlink-create-abort" and body["target_path"] in owned:
                target = _parse_generation(body["target"])
                owned[body["target_path"]] = target
                for alias in hardlink_aliases[body["target_path"]]:
                    if alias in owned:
                        owned[alias] = target
            parent_path = path.rpartition("/")[0]
            parent_generation = _parse_parent(body["parent"]).generation
            if parent_path:
                operation_consistent = operation_consistent and parent_path in owned
                if parent_path in owned:
                    owned[parent_path] = parent_generation
            else:
                operation_generation = parent_generation
        if kind == "operation-remove-intent":
            operation_consistent = operation_consistent and operation_generation == _parse_generation(body["operation"])
        if kind.endswith("-intent"):
            pending = record
        elif kind.endswith("-settled") or kind.endswith("-abort") or kind in {"operation-absent", "retired", "uncertain"}:
            pending = None
    status = "preserve"
    parent_matches = state_parent == observations.state_parent
    parent_matches = parent_matches and operation_consistent and ledger_matches
    if phase == "genesis" and not operations and not entries and parent_matches:
        status = "genesis-settleable"
    elif phase == "ready" and not operations and not entries and parent_matches:
        status = "genesis-abortable"
    elif phase == "operation-intent" and not operations and not entries and parent_matches:
        status = "operation-abortable"
    elif phase == "aborted" and not operations and not entries and parent_matches:
        status = "retirable"
    elif phase == "operation-observed" and not entries and parent_matches:
        observed = _body(records[-1])
        recorded = _parse_generation(observed["operation"])
        if operations == {operation_name: recorded} and observations.state_parent == _parse_parent(observed["state_parent"]):
            status = "operation-create-settleable"
    elif phase in {"candidate-tar-intent", "candidate-tar-observed"} and parent_matches:
        record = records[-1]
        intent = _body(records[-2] if phase == "candidate-tar-observed" else record)
        pre_parent = _parse_parent(intent["parent"])
        anonymous = _candidate_generation(intent["anonymous"], 0)
        absent = entries == owned and operations == {operation_name: operation_generation}
        absent = absent and parents.get("") == pre_parent and observations.candidate_tar is None
        if phase == "candidate-tar-intent" and absent:
            status = "candidate-tar-abortable"
        linked_body = None if phase == "candidate-tar-intent" else _body(record)
        linked = entries.get(CANDIDATE_TAR_PATH)
        post_parent = parents.get("")
        try:
            _candidate_transition(anonymous, linked)
            _candidate_parent_transition(pre_parent, post_parent)
            expected = dict(owned)
            expected[CANDIDATE_TAR_PATH] = linked
            exact_link = entries == expected and operations == {operation_name: post_parent.generation}
            exact_link = exact_link and observations.candidate_tar == (intent["size"], intent["sha256"])
            if linked_body is not None:
                exact_link = exact_link and linked_body == {
                    "token": intent["token"], "path": intent["path"], "parent": _parent_value(post_parent),
                    "anonymous": intent["anonymous"], "linked": _generation_value(linked),
                    "size": intent["size"], "sha256": intent["sha256"],
                }
        except (LedgerError, RootfsFsError, TypeError, AttributeError):
            exact_link = False
        if exact_link:
            status = "candidate-tar-observeable" if phase == "candidate-tar-intent" else "candidate-tar-settleable"
    elif phase in {"active", "release-authorized", "prestage-release-authorized", "leased"} and operations == {operation_name: operation_generation} and parent_matches:
        if entries == owned:
            status = phase
        if lease_snapshot is not None and not authorized_removal_started:
            exact_snapshot = (
                state_parent == lease_snapshot.state_parent
                and operation_generation == lease_snapshot.operation
                and tuple(sorted(owned.items())) == lease_snapshot.owned
                and owned.get("rootfs") == lease_snapshot.root
            )
            if not exact_snapshot:
                status = "preserve"
    elif phase.endswith("-observed") and operation_generation is not None and parent_matches:
        body = _body(records[-1])
        kind = records[-1].record_type
        expected = dict(owned)
        expected_operation = operation_generation
        path = body.get("path", body.get("alias"))
        parent_path = path.rpartition("/")[0]
        recorded_parent = _parse_parent(body["parent"]) if "parent" in body else None
        intent = _body(records[-2])
        eligible = False
        if kind == "create-observed":
            eligible = path not in owned
            expected[path] = _parse_generation(body["child"])
        elif kind == "metadata-observed":
            eligible = path in owned and owned[path] == _parse_generation(intent["before"])
            expected[path] = _parse_generation(body["child"])
        elif kind == "hardlink-create-observed":
            target_path = body["target_path"]
            eligible = path not in owned and target_path in owned and owned[target_path] == _parse_generation(body["target_before"])
            linked = _parse_generation(body["target_after"])
            expected[path] = linked
            expected[target_path] = linked
            for alias in hardlink_aliases[target_path]:
                if alias in expected:
                    expected[alias] = linked
        elif kind == "remove-observed":
            eligible = path in owned and owned[path] == _parse_generation(intent["child"])
            expected.pop(path, None)
            if body["target"] is not None:
                eligible = eligible and body["target_path"] in owned
                target = _parse_generation(body["target"])
                expected[body["target_path"]] = target
                for alias in hardlink_aliases[body["target_path"]]:
                    if alias in expected:
                        expected[alias] = target
        if recorded_parent is not None:
            if parent_path:
                expected[parent_path] = recorded_parent.generation
            else:
                expected_operation = recorded_parent.generation
        exact_parent = recorded_parent is None or parents.get(parent_path) == recorded_parent
        if eligible and entries == expected and operations == {operation_name: expected_operation} and exact_parent:
            status = kind.removesuffix("-observed") + "-settleable"
    elif phase == "operation-remove" and operations == {operation_name: operation_generation} and entries == owned == {} and parent_matches:
        status = "operation-remove-retry"
    elif phase == "operation-remove" and not operations and not entries and ledger_matches and operation_consistent:
        intent_parent = _parse_parent(_body(records[-1])["state_parent"])
        if _valid_parent_delta("rmdir", operation_name, intent_parent, observations.state_parent):
            status = "operation-absence-settleable"
    elif phase == "operation-absent" and not operations and not entries and parent_matches:
        status = "retirable"
    elif phase == "retired" and not operations and not entries and parent_matches:
        status = "retired"
    if pending is not None and phase.endswith("-intent") and operation_generation is not None and parent_matches:
        body = _body(pending)
        path = body.get("path", body.get("alias"))
        parent_path = path.rpartition("/")[0] if path is not None else None
        observed_parent = parents.get(parent_path)
        expected_parent = _parse_parent(body["parent"]) if "parent" in body else None
        exact_operation = operations == {operation_name: operation_generation}
        if pending.record_type in {"create-intent", "hardlink-create-intent"} and path not in entries and entries == owned and exact_operation:
            if observed_parent == expected_parent:
                status = "entry-absent"
        elif pending.record_type == "remove-intent":
            expected = _parse_generation(body["child"])
            if exact_operation and entries == owned and entries.get(path) == expected and observed_parent == expected_parent:
                status = "remove-retry"
            elif path not in entries:
                remaining = dict(owned)
                remaining.pop(path, None)
                action = "rmdir" if body["kind"] == "directory" else "unlink"
                absence_operation = exact_operation
                if parent_path == "" and observed_parent is not None:
                    absence_operation = operations == {operation_name: observed_parent.generation}
                elif parent_path in remaining and observed_parent is not None:
                    remaining[parent_path] = observed_parent.generation
                if body["target_path"] is not None and body["target_path"] in remaining:
                    current_target = entries.get(body["target_path"])
                    try:
                        _hardlink_generation_change(expected, current_target, -1)
                        remaining[body["target_path"]] = current_target
                        for alias in hardlink_aliases[body["target_path"]]:
                            if alias in remaining:
                                remaining[alias] = current_target
                        hardlink_exact = True
                    except (LedgerError, RootfsFsError, TypeError, AttributeError):
                        hardlink_exact = False
                    if absence_operation and hardlink_exact and entries == remaining and _valid_parent_delta(action, path.split("/")[-1], expected_parent, observed_parent):
                        status = "hardlink-remove-absence-settleable"
                elif absence_operation and entries == remaining and _valid_parent_delta(action, path.split("/")[-1], expected_parent, observed_parent):
                    status = "remove-absence-settleable"
    prelease_statuses = {
        "genesis-settleable", "genesis-abortable", "operation-abortable", "operation-create-settleable",
        "entry-absent", "create-settleable", "metadata-settleable", "hardlink-create-settleable",
        "candidate-tar-abortable", "candidate-tar-observeable", "candidate-tar-settleable", "active",
    }
    removal_statuses = {
        "remove-retry", "remove-absence-settleable", "hardlink-remove-absence-settleable", "remove-settleable",
        "operation-remove-retry", "operation-absence-settleable", "retirable", "retired",
    }
    if status in prelease_statuses:
        origin = "prelease"
    elif status == "release-authorized" or status in removal_statuses and release_authorized:
        origin = "release-authorized"
    elif status == "prestage-release-authorized" or status in removal_statuses and prestage_authorized:
        origin = "prestage-authorized"
    elif status in removal_statuses:
        origin = "prelease"
    else:
        origin = "none"
    cleanup_allowed = origin != "none" and status in prelease_statuses | removal_statuses | {"release-authorized", "prestage-release-authorized"}
    if phase == "uncertain" or status == "preserve":
        status, origin, cleanup_allowed = "preserve", "none", False
    return LedgerState(
        status, token, operation_name if operation_intended else None, tuple(sorted(owned.items())), cleanup_allowed,
        origin, lease_snapshot is not None, release_authorized, records[-1].record_type, lease_snapshot,
    )


def _require_ledger_generation(generation, stable_key):
    _fail(type(generation) is HostGeneration and generation.key == stable_key)
    _fail(stable_key.kind == "file" and generation.mode == 0o600)
    _fail(generation.uid == generation.gid == 0 and generation.nlink == 1)


def _append_capabilities():
    route_seal = object()
    def write_core(writer_state, proposal, control, route):
        _fail(route is route_seal)
        _fail(type(writer_state) is LedgerWriterState and type(proposal) is LedgerProposal)
        _fail(type(control) is OperationControl)
        node = writer_state.node
        raw = None
        try:
            before = _observe_node(node.identity_fd, node.operation_fd, control)
            _require_ledger_generation(before, writer_state.stable_key)
            _fail(_same_fields(before, writer_state.generation, {"mtime_ns", "ctime_ns"}) and before.size == writer_state.settled.offset)
            _require_empty_fd_xattrs(node, control)
            control.check()
            _fail(os.lseek(node.operation_fd.number, 0, os.SEEK_CUR) == writer_state.settled.offset)
            control.check()
            raw = _encode_proposal(proposal, writer_state.settled)
            written = 0
            while written < len(raw):
                control.check()
                count = os.write(node.operation_fd.number, raw[written:])
                control.check()
                _fail(type(count) is int and 0 < count <= len(raw) - written)
                written += count
            control.check()
            os.fsync(node.operation_fd.number)
            control.check()
            after = _observe_node(node.identity_fd, node.operation_fd, control)
            _require_ledger_generation(after, writer_state.stable_key)
            _fail(_same_fields(before, after, {"size", "mtime_ns", "ctime_ns"}))
            _fail(after.size == writer_state.settled.offset + len(raw))
            _require_empty_fd_xattrs(node, control)
            control.check()
            _fail(os.lseek(node.operation_fd.number, 0, os.SEEK_CUR) == after.size)
            control.check()
            settled = SettledBytes(writer_state.settled.sequence + 1, after.size, hashlib.sha256(raw).hexdigest())
            return LedgerWriterState(node, writer_state.stable_key, settled, after)
        except BaseException as error:
            cleanup = OperationControl(time.monotonic_ns() + 120 * 1_000_000_000, lambda: False)
            try:
                current = _observe_node(node.identity_fd, node.operation_fd, cleanup)
                _require_ledger_generation(current, writer_state.stable_key)
                if raw is None:
                    _fail(current.size == writer_state.settled.offset)
                else:
                    _fail(writer_state.settled.offset <= current.size <= writer_state.settled.offset + len(raw))
                    suffix_size = current.size - writer_state.settled.offset
                    suffix = os.pread(node.operation_fd.number, suffix_size, writer_state.settled.offset)
                    _fail(suffix == raw[:suffix_size])
                prefix = os.pread(node.operation_fd.number, writer_state.settled.offset, 0)
                cleanup.check()
                _fail(len(prefix) == writer_state.settled.offset)
                if prefix:
                    records = _parse_ledger(prefix)
                    last = records[-1]
                    _fail((last.sequence, last.next_offset, last.line_sha256) == (writer_state.settled.sequence, writer_state.settled.offset, writer_state.settled.line_sha256))
                else:
                    _fail(writer_state.settled == INITIAL_BYTES)
                os.ftruncate(node.operation_fd.number, writer_state.settled.offset)
                os.fsync(node.operation_fd.number)
                _fail(os.lseek(node.operation_fd.number, writer_state.settled.offset, os.SEEK_SET) == writer_state.settled.offset)
                restored_prefix = os.pread(node.operation_fd.number, writer_state.settled.offset, 0)
                _fail(restored_prefix == prefix)
                if restored_prefix:
                    restored_records = _parse_ledger(restored_prefix)
                    restored_last = restored_records[-1]
                    _fail((restored_last.sequence, restored_last.next_offset, restored_last.line_sha256) == (writer_state.settled.sequence, writer_state.settled.offset, writer_state.settled.line_sha256))
                restored = _observe_node(node.identity_fd, node.operation_fd, cleanup)
                _require_ledger_generation(restored, writer_state.stable_key)
                _fail(restored.size == writer_state.settled.offset)
            except BaseException as rollback_error:
                error = RootfsFsError(error, rollback_error)
            raise error

    def _write_record(writer_state, proposal, control, route=None):
        _fail(route is route_seal)
        _fail(type(proposal) is LedgerProposal and proposal.record_type not in {"release-authorized", "prestage-release-authorized"})
        return write_core(writer_state, proposal, control, route_seal)

    def _append_record(writer_state, proposal, control):
        _fail(type(proposal) is LedgerProposal and proposal.record_type != "leased")
        return _write_record(writer_state, proposal, control, route_seal)

    def _append_leased_record(
        writer_state, token, operation_name, state_parent, operation, root,
        manifest_sha256, manifest_size, ustar_sha256, ustar_size, entry_count, control,
    ):
        _fail(type(writer_state) is LedgerWriterState and type(state_parent) is LedgerParent)
        _fail(type(operation) is HostGeneration and type(root) is HostGeneration)
        key = writer_state.stable_key
        body = {
            "token": token, "operation_name": operation_name, "state_parent": _parent_value(state_parent),
            "operation": _generation_value(operation), "root": _generation_value(root),
            "ledger_key": {"mount_id": key.mount_id, "device": key.device, "inode": key.inode, "kind": key.kind},
            "manifest_sha256": manifest_sha256, "manifest_size": manifest_size,
            "ustar_sha256": ustar_sha256, "ustar_size": ustar_size, "entry_count": entry_count,
        }
        return _write_record(writer_state, LedgerProposal.create("leased", body), control, route_seal)

    def _append_prestage_authorized_record(writer_state, token, operation_name, lease,
                                            operation_binding, control):
        _fail(type(lease) is SettledBytes)
        body = {
            "token": token, "operation_name": operation_name,
            "lease_sequence": lease.sequence, "lease_offset": lease.offset,
            "lease_sha256": lease.line_sha256,
            "operation_binding": operation_binding,
        }
        return write_core(writer_state, LedgerProposal.create("prestage-release-authorized", body),
                          control, route_seal)

    def _append_release_authorized_record(writer_state, token, operation_name, lease,
                                           kata_operation_token, kata_ledger_key,
                                           kata_release, control):
        _fail(type(lease) is SettledBytes and type(kata_release) is SettledBytes)
        _fail(type(kata_ledger_key) is HostKey and kata_ledger_key.kind == "file")
        body = {
            "token": token, "operation_name": operation_name,
            "lease_sequence": lease.sequence, "lease_offset": lease.offset,
            "lease_sha256": lease.line_sha256,
            "kata_operation_token": kata_operation_token,
            "kata_ledger_key": {"mount_id": kata_ledger_key.mount_id, "device": kata_ledger_key.device,
                                "inode": kata_ledger_key.inode, "kind": kata_ledger_key.kind},
            "kata_release_sequence": kata_release.sequence,
            "kata_release_offset": kata_release.offset,
            "kata_release_sha256": kata_release.line_sha256,
        }
        # write_core is closure-private: no flag or caller-created proposal can
        # cross the generic writer's release rejection.
        return write_core(writer_state, LedgerProposal.create("release-authorized", body),
                          control, route_seal)

    return (_append_record, _append_leased_record,
            _append_release_authorized_record, _append_prestage_authorized_record)


(_append_record, _append_leased_record,
 _append_release_authorized_record, _append_prestage_authorized_record) = _append_capabilities()
del _append_capabilities


def _hardlink_plan(value):
    _fail(type(value) is HardlinkPlan)
    _graph_path(value.target_path)
    _fail(type(value.aliases) is tuple and value.aliases)
    for alias in value.aliases:
        _graph_path(alias)
    _fail(value.target_path not in value.aliases and len(value.aliases) == len(set(value.aliases)))
    _fail(tuple(item.encode("utf-8") for item in value.aliases) == tuple(sorted(item.encode("utf-8") for item in value.aliases)))
    _integer(value.mode, 0, 0o7777)
    _integer(value.uid)
    _integer(value.gid)
    _integer(value.mtime)
    _integer(value.size)
    _digest(value.content_sha256)


def _new_hardlink_group(plan, target, observed_content_sha256):
    _hardlink_plan(plan)
    _fail(_digest(observed_content_sha256) == plan.content_sha256)
    _fail(type(target) is HostGeneration and target.key.kind == "file" and target.nlink == 1)
    _fail((target.mode, target.uid, target.gid, target.size) == (plan.mode, plan.uid, plan.gid, plan.size))
    _fail(target.mtime_ns == plan.mtime * 1_000_000_000)
    return HardlinkGroupState(plan, target, 0, (), ())


def _hardlink_transition(state, action, alias_index, before, after, alias, parent_delta, observed_content_sha256):
    _fail(type(state) is HardlinkGroupState and action in {"create", "remove"})
    _fail(_digest(observed_content_sha256) == state.plan.content_sha256)
    _fail(type(parent_delta) is ParentDelta and type(alias) is HostGeneration)
    if action == "create":
        _fail(alias_index == state.next_create_index and alias_index < len(state.plan.aliases))
        _fail(parent_delta.action == "hardlink" and parent_delta.name.text == state.plan.aliases[alias_index].split("/")[-1])
        _hardlink_generation_change(before, after, 1)
        _fail(alias == after)
    else:
        _fail(state.settled_aliases and alias_index == state.next_create_index - 1)
        _fail(state.removed_aliases or state.next_create_index == len(state.plan.aliases))
        _fail(parent_delta.action == "unlink" and parent_delta.name.text == state.plan.aliases[alias_index].split("/")[-1])
        _hardlink_generation_change(before, after, -1)
        _fail(alias == before)
    _fail(before == state.target)
    return HardlinkTransition(action, alias_index, before, after, parent_delta)


def _settle_hardlink(state, transition):
    _fail(type(state) is HardlinkGroupState and type(transition) is HardlinkTransition)
    _fail(transition.before == state.target)
    if transition.action == "create":
        alias = state.plan.aliases[transition.alias_index]
        return HardlinkGroupState(state.plan, transition.after, state.next_create_index + 1, state.settled_aliases + (alias,), state.removed_aliases)
    alias = state.plan.aliases[transition.alias_index]
    return HardlinkGroupState(state.plan, transition.after, state.next_create_index - 1, state.settled_aliases[:-1], state.removed_aliases + (alias,))


def _plan_hardlink_groups(fresh_fixed_authority):
    from completion_rootfs_plan import RootfsBuildInputs

    _fail(type(fresh_fixed_authority) is RootfsBuildInputs)
    entries = {entry.record.path: entry for entry in fresh_fixed_authority.plan.entries}
    aliases = {}
    for entry in fresh_fixed_authority.plan.entries:
        if entry.record.kind == "hardlink":
            aliases.setdefault(entry.record.hardlink_target, []).append(entry.record.path)
    plans = []
    for target_path in sorted(aliases, key=lambda value: value.encode("utf-8")):
        target = entries[target_path].record
        plans.append(
            HardlinkPlan(
                target_path,
                tuple(sorted(aliases[target_path], key=lambda value: value.encode("utf-8"))),
                target.mode,
                target.uid,
                target.gid,
                target.mtime,
                target.archive_size,
                target.content_sha256,
            )
        )
    result = tuple(plans)
    for plan in result:
        _hardlink_plan(plan)
    return result

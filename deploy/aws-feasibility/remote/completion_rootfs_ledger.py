"""Canonical ownership ledger and hardlink state models for ADR 0040."""

from dataclasses import dataclass, field, replace
import hashlib
import json
import os
import sys

sys.dont_write_bytecode = True

from completion_rootfs_fs import (
    DirectorySnapshot,
    HeldNode,
    HostGeneration,
    HostKey,
    OperationControl,
    ParentDelta,
    RootfsFsError,
    _name,
    _observe_node,
    _path,
    _require_empty_fd_xattrs,
)

VERSION = "cogs.stage2-rootfs-ledger/v1"
MAX_LINE_BYTES = 16_384
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 65_536
OFFSET_WIDTH = 16
ZERO_SHA256 = "0" * 64
TOKEN_LENGTH = 64
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
        "create-observed",
        "create-settled",
        "metadata-intent",
        "metadata-observed",
        "metadata-settled",
        "hardlink-group",
        "hardlink-create-intent",
        "hardlink-create-observed",
        "hardlink-create-settled",
        "remove-intent",
        "remove-observed",
        "remove-settled",
        "operation-remove-intent",
        "operation-absent",
        "retired",
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


def _parse_generation(value):
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
        _integer(value["nlink"], 1),
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
    parents: tuple[tuple[str, LedgerParent], ...] = ()

    def __post_init__(self):
        _fail(type(self.state_parent) is LedgerParent)
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


@dataclass(frozen=True)
class LedgerState:
    status: str
    token: str
    operation_name: str | None
    owned: tuple[tuple[str, HostGeneration], ...]
    cleanup_allowed: bool
    terminal_record: str


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


def _parse_ledger(raw):
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
    _validate_legal_records(tuple(records))
    return tuple(records)


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
    elif record_type in {"operation-create-intent", "operation-abort", "operation-absent"}:
        _exact_keys(body, ("token", "operation_name", "state_parent"))
        _fail(body["operation_name"] == _operation_name(token))
        _parse_parent(body["state_parent"])
    elif record_type in {"operation-create-observed", "operation-create-settled", "operation-remove-intent"}:
        _exact_keys(body, ("token", "operation_name", "state_parent", "operation"))
        _fail(body["operation_name"] == _operation_name(token))
        _parse_parent(body["state_parent"])
        _parse_generation(body["operation"])
    elif record_type == "create-intent":
        _exact_keys(body, ("token", "path", "kind", "parent"))
        _entry_common(body)
        _parse_parent(body["parent"])
    elif record_type in {"create-observed", "create-settled"}:
        _exact_keys(body, ("token", "path", "kind", "parent", "child"))
        _entry_common(body)
        _parse_parent(body["parent"])
        _parse_generation(body["child"])
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
    elif record_type == "hardlink-create-intent":
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


def _validate_legal_records(records):
    _fail(type(records) is tuple and records and records[0].record_type == "genesis")
    token = _body(records[0])["token"]
    phase = "genesis"
    operation_name = None
    groups = {}
    pending = None
    for record in records[1:]:
        body = _body(record)
        _fail(body["token"] == token and phase not in {"retired", "uncertain"})
        kind = record.record_type
        if kind == "uncertain":
            phase = "uncertain"
            continue
        if phase == "genesis":
            _fail(kind == "genesis-settled")
            _fail(body["state_parent"] == _body(records[0])["state_parent"])
            phase = "ready"
        elif phase == "ready":
            _fail(kind in {"genesis-abort", "operation-create-intent"})
            if kind == "genesis-abort":
                phase = "aborted"
            else:
                operation_name = body["operation_name"]
                phase = "operation-intent"
        elif phase == "aborted":
            _fail(kind == "retired")
            phase = "retired"
        elif phase == "operation-intent":
            _fail(kind in {"operation-create-observed", "operation-abort"})
            _fail(body["operation_name"] == operation_name)
            if kind == "operation-create-observed":
                intent = _body(records[record.sequence - 1])
                _parent_delta("create", operation_name, _parse_parent(intent["state_parent"]), _parse_parent(body["state_parent"]))
                phase = "operation-observed"
            else:
                phase = "aborted"
        elif phase == "operation-observed":
            _fail(kind == "operation-create-settled" and body["operation_name"] == operation_name)
            _fail(body == _body(records[record.sequence - 1]))
            phase = "active"
        elif phase == "active":
            if kind == "operation-remove-intent":
                _fail(body["operation_name"] == operation_name)
                phase = "operation-remove"
            elif kind == "hardlink-group":
                target = body["target_path"]
                _fail(target not in groups)
                groups[target] = (tuple(body["aliases"]), 0)
            else:
                _fail(kind in {"create-intent", "metadata-intent", "hardlink-create-intent", "remove-intent"})
                if kind == "hardlink-create-intent":
                    target = body["target_path"]
                    _fail(target in groups and body["index"] == groups[target][1])
                    _fail(body["alias"] == groups[target][0][groups[target][1]])
                if kind == "remove-intent" and body["target_path"] is not None:
                    target = body["target_path"]
                    _fail(target in groups and groups[target][1] > 0)
                    _fail(body["path"] == groups[target][0][groups[target][1] - 1])
                pending = record
                phase = kind.removesuffix("-intent") + "-intent"
        elif phase.endswith("-intent"):
            _fail(kind == phase.removesuffix("intent") + "observed")
            _matching_transition(pending, record)
            pending = record
            phase = phase.removesuffix("intent") + "observed"
        elif phase.endswith("-observed"):
            _fail(kind == phase.removesuffix("observed") + "settled")
            _matching_transition(pending, record)
            if kind == "hardlink-create-settled":
                target = body["target_path"]
                groups[target] = (groups[target][0], groups[target][1] + 1)
            if kind == "remove-settled" and body["target"] is not None:
                target = body["target_path"]
                groups[target] = (groups[target][0], groups[target][1] - 1)
            pending = None
            phase = "active"
        elif phase == "operation-remove":
            _fail(kind == "operation-absent" and body["operation_name"] == operation_name)
            intent = _body(records[record.sequence - 1])
            _parent_delta("rmdir", operation_name, _parse_parent(intent["state_parent"]), _parse_parent(body["state_parent"]))
            phase = "operation-absent"
        elif phase == "operation-absent":
            _fail(kind == "retired" and body["state_parent"] == _body(records[record.sequence - 1])["state_parent"])
            phase = "retired"
        else:
            raise LedgerError()
    return phase


def _matching_transition(previous, current):
    left = _body(previous)
    right = _body(current)
    for key in ("path", "kind", "target_path", "alias", "index", "operation_name"):
        if key in left or key in right:
            _fail(left.get(key) == right.get(key))
    if previous.record_type.endswith("-observed"):
        _fail(left == right)
        return
    if previous.record_type == "create-intent":
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
    operations = dict(observations.operations)
    entries = dict(observations.entries)
    parents = dict(observations.parents)
    owned = {}
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
        if kind == "operation-create-settled":
            operation_generation = _parse_generation(body["operation"])
        elif kind in {"create-settled", "metadata-settled"}:
            owned[body["path"]] = _parse_generation(body["child"])
        elif kind == "hardlink-create-settled":
            linked = _parse_generation(body["alias_generation"])
            owned[body["alias"]] = linked
            if body["target_path"] in owned:
                owned[body["target_path"]] = linked
            else:
                operation_consistent = False
        elif kind == "remove-settled":
            owned.pop(body["path"], None)
            if body["target_path"] is not None and body["target"] is not None:
                if body["target_path"] in owned:
                    owned[body["target_path"]] = _parse_generation(body["target"])
                else:
                    operation_consistent = False
        if kind in {"create-settled", "hardlink-create-settled", "remove-settled"}:
            path = body.get("path", body.get("alias"))
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
        elif kind.endswith("-settled") or kind in {"genesis-abort", "operation-abort", "operation-absent", "retired", "uncertain"}:
            pending = None
    status = "preserve"
    parent_matches = state_parent == observations.state_parent
    parent_matches = parent_matches and operation_consistent
    if phase == "ready" and not operations and not entries and parent_matches:
        status = "genesis-abortable"
    elif phase == "operation-intent" and not operations and not entries and parent_matches:
        status = "operation-abortable"
    elif phase == "active" and operations == {operation_name: operation_generation} and parent_matches:
        status = "active" if entries == owned else "preserve"
    elif phase == "operation-remove" and operations == {operation_name: operation_generation} and entries == owned == {} and parent_matches:
        status = "operation-remove-retry"
    elif phase == "operation-remove" and not operations and not entries:
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
                if absence_operation and entries == remaining and _valid_parent_delta(action, path.split("/")[-1], expected_parent, observed_parent):
                    status = "remove-absence-settleable"
    cleanup_allowed = status in {"active", "entry-absent", "remove-retry", "remove-absence-settleable", "operation-remove-retry"}
    return LedgerState(status, token, operation_name if operation_intended else None, tuple(sorted(owned.items())), cleanup_allowed, records[-1].record_type)


def _require_ledger_generation(generation, stable_key):
    _fail(type(generation) is HostGeneration and generation.key == stable_key)
    _fail(stable_key.kind == "file" and generation.mode == 0o600)
    _fail(generation.uid == generation.gid == 0 and generation.nlink == 1)


def _append_record(writer_state, proposal, control):
    _fail(type(writer_state) is LedgerWriterState and type(proposal) is LedgerProposal)
    _fail(type(control) is OperationControl)
    node = writer_state.node
    before = _observe_node(node.identity_fd, node.operation_fd, control)
    _require_ledger_generation(before, writer_state.stable_key)
    _fail(before == writer_state.generation and before.size == writer_state.settled.offset)
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

#!/usr/bin/env python3
"""Hostile codec/capability matrix and Linux fixed-journal behavior tests."""

import ast
import copy
import ctypes
import fcntl
import hashlib
import inspect
import json
import os
import stat
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

if sys.flags.optimize:
    raise RuntimeError("operation tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
sys.path.insert(0, str(ROOT / "test"))
from stage2_attested_fixture import ensure_attested_static_fixture
import completion_kata_inputs as inputs
import completion_kata_operation as operation
import completion_kata_network as network
import completion_kata_process as process
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_rootfs_fs as fs
import completion_rootfs_lease as lease
import completion_rootfs_ledger as ledger


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile operation case accepted")


def key(inode=10, kind="file"):
    return {"mount_id": 1, "device": 2, "inode": inode, "kind": kind}


def generation(inode=20, kind="directory", mode=0o700, nlink=2, size=0, stamp=30):
    return {
        **key(inode, kind), "mode": mode, "uid": 0, "gid": 0, "nlink": nlink,
        "size": size, "mtime_ns": stamp, "ctime_ns": stamp + 1,
    }


def genesis_body(token="a" * 64, rootfs="b" * 64, journal=None):
    return {
        **operation.FIXED,
        "operation_token": token,
        "rootfs_token": rootfs,
        "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40,
        "source_manifest_sha256": "6" * 64,
        "journal_key": key() if journal is None else journal,
        "rootfs_pin": operation.ROOTFS_PIN,
        "mount_list_sha256": operation.MOUNT_SHA,
    }


def append(raw, kind, body):
    records = operation._parse(raw) if raw else ()
    return raw + operation._encode(kind, body, records)


def names_digest(names):
    return hashlib.sha256(operation._canonical(names)).hexdigest()


def lifecycle_deadline(token="a" * 64):
    admitted = operation._boottime_ns()
    return ("LIFECYCLE_DEADLINE_V1", {
        "operation_token": token,
        "admission_boottime_ns": admitted,
        "ssh_start_deadline_boottime_ns": admitted + operation.JOURNAL_SETUP_MARGIN_NS,
        "journal_deadline_boottime_ns": admitted + operation.JOURNAL_TOTAL_NS,
    })


def settled_genesis():
    raw = append(b"", "GENESIS", genesis_body())
    return append(raw, "GENESIS_SETTLED", {
        "operation_token": "a" * 64,
        "journal_key": key(),
        "state_parent": generation(),
    })


def leased_prefix():
    raw = settled_genesis()
    intent = {
        "operation_token": "a" * 64,
        "rootfs_token": "b" * 64,
        "rootfs_baseline_sha256": "7" * 64,
    }
    raw = append(raw, "ROOTFS_ACQUIRE_INTENT", intent)
    leased = {
        "operation_token": "a" * 64,
        "rootfs_token": "b" * 64,
        "rootfs_ledger_key": key(40),
        "leased_sequence": 8,
        "leased_offset": "0000000000001234",
        "leased_sha256": "8" * 64,
        "state_generation": generation(41),
        "operation_generation": generation(42),
        "root_generation": generation(43, mode=0o755),
        "rootfs_pin": operation.ROOTFS_PIN,
    }
    return append(raw, "ROOTFS_LEASED", leased), intent, leased


def release_bodies(authorized=False):
    _raw, intent, leased = leased_prefix()
    token = "a" * 64
    proof = lambda value: {"operation_token": token, "proof_sha256": value * 64}
    bodies = [
        ("ROOTFS_ACQUIRE_INTENT", intent), ("ROOTFS_LEASED", leased),
        ("BASELINES_CAPTURED", proof("1")), ("NETWORK_READY", proof("2")),
        ("RUNTIME_READY", proof("3")),
        ("SSH_READY", {**proof("4"),
            "marker_sha256": hashlib.sha256(operation.FIXED["ssh_marker"].encode()).hexdigest(),
            "authentication_attempts": 1}),
        ("READINESS_REVOKED", {"operation_token": token}),
        ("OWNERSHIP_OBSERVED", {**proof("5"), "task": "exact-owned",
            "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned"}),
        ("TASK_STOPPED", proof("6")), ("NETWORK_ABSENT", proof("7")),
        ("TASK_ABSENT", proof("8")), ("CONTAINER_ABSENT", proof("9")),
        ("RUNTIME_ABSENT", proof("a")), ("SHARE_ABSENT", proof("b")),
        ("FIREWALL_ABSENT", proof("c")), ("INPUT_REMOVED", proof("d")),
    ]
    raw = settled_genesis()
    for kind, body in bodies:
        raw = append(raw, kind, body)
    previous = operation._parse(raw)[-1]
    ready = {
        "operation_token": token, "rootfs_token": "b" * 64,
        "rootfs_ledger_key": leased["rootfs_ledger_key"],
        "leased_sequence": leased["leased_sequence"], "leased_offset": leased["leased_offset"],
        "leased_sha256": leased["leased_sha256"], "input_removed_sha256": previous.body["proof_sha256"],
    }
    bodies.append(("ROOTFS_RELEASE_READY", ready)); raw = append(raw, "ROOTFS_RELEASE_READY", ready)
    if authorized:
        ready_record = operation._parse(raw)[-1]
        bodies.append(("ROOTFS_RELEASE_AUTHORIZED", {
            "operation_token": token, "rootfs_token": "b" * 64,
            "rootfs_authorized_sequence": 9, "rootfs_authorized_offset": "0000000000002222",
            "rootfs_authorized_sha256": "e" * 64,
            "release_ready_sha256": ready_record.line_sha256,
        }))
    return tuple(bodies)


# Cleanup intent generations are parsed under their immutable meanings: an
# active V1 resumes without replacement and its completion settles it, while a
# V2 completion remains active until its explicit acknowledgement.
_cleanup_proof = lambda value: {"operation_token": "a" * 64, "proof_sha256": value * 64}
_cleanup_rows = (
    ("BASELINES_CAPTURED", _cleanup_proof("1")), ("NETWORK_READY", _cleanup_proof("2")),
    ("RUNTIME_READY", _cleanup_proof("3")),
    ("READINESS_REVOKED", {"operation_token": "a" * 64}),
    ("OWNERSHIP_OBSERVED", {**_cleanup_proof("4"), "task": "exact-owned",
        "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned"}),
    ("TASK_STOPPED", _cleanup_proof("5")),
)
_cleanup_prefix, _unused_intent, _unused_lease = leased_prefix()
for _kind, _body in _cleanup_rows:
    _cleanup_prefix = append(_cleanup_prefix, _kind, _body)
_cleanup_cases = (("network", _cleanup_prefix, "NETWORK_ABSENT", "TASK_ABSENT"),)
_firewall_prefix = append(_cleanup_prefix, "NETWORK_ABSENT", _cleanup_proof("6"))
for _kind, _value in (("TASK_ABSENT", "7"), ("CONTAINER_ABSENT", "8"),
                      ("RUNTIME_ABSENT", "9"), ("SHARE_ABSENT", "a")):
    _firewall_prefix = append(_firewall_prefix, _kind, _cleanup_proof(_value))
_cleanup_cases += (("firewall", _firewall_prefix, "FIREWALL_ABSENT", "INPUT_REMOVED"),)
for _target, _prefix, _completion, _next in _cleanup_cases:
    _upper = _target.upper()
    _legacy_kind, _v2_kind = f"{_upper}_CLEANUP_INTENT_V1", f"{_upper}_CLEANUP_INTENT_V2"
    _legacy = append(_prefix, _legacy_kind, {"operation_token": "a" * 64})
    assert operation.network_journal.active_cleanup(operation._parse(_legacy)) == _legacy_kind
    _legacy_complete = append(_legacy, _completion, _cleanup_proof("b"))
    assert operation.network_journal.active_cleanup(operation._parse(_legacy_complete)) is None
    append(_legacy_complete, _next, _cleanup_proof("c"))
    _v2 = append(_prefix, _v2_kind, {"operation_token": "a" * 64})
    _v2_complete = append(_v2, _completion, _cleanup_proof("d"))
    assert operation.network_journal.active_cleanup(operation._parse(_v2_complete)) == _v2_kind
    rejected(lambda raw=_v2_complete, kind=_next: append(raw, kind, _cleanup_proof("e")))
    _ack = f"{_upper}_CLEANUP_SETTLED_V2"
    _settled = append(_v2_complete, _ack, {"operation_token": "a" * 64})
    assert operation.network_journal.active_cleanup(operation._parse(_settled)) is None
    append(_settled, _next, _cleanup_proof("e"))
    _uncertain = append(_v2_complete, "UNCERTAIN", {
        "operation_token": "a" * 64, "reason": "incomplete"})
    assert operation.network_journal.active_cleanup(operation._parse(_uncertain)) == _v2_kind
    rejected(lambda raw=_uncertain, ack=_ack: append(raw, ack, {"operation_token": "a" * 64}))
    rejected(lambda raw=_uncertain: append(raw, "FINAL_BASELINES", {
        "operation_token": "a" * 64, "final_baselines_sha256": "f" * 64}))


def command_body(serial=0, command_id="IP_HOST_LINKS"):
    return {
        "operation_token": "a" * 64,
        "command_serial": serial,
        "command_id": command_id,
        "binding_sha256": "c" * 64,
        "deadline_class": "runtime-start",
    }


def zero_outcome(command, outcome="not_started"):
    return {
        **command,
        "outcome": outcome,
        "status": None,
        "errno": None,
        "stdout_sha256": operation.ZERO,
        "stdout_length": 0,
        "stdout_truncated": False,
        "stderr_sha256": operation.ZERO,
        "stderr_length": 0,
        "stderr_truncated": False,
        "wait_result": "not_waited",
        "reap_result": "not_child",
    }


# Every line boundary is a legal prefix. Every partial suffix is rejected.
raw, rootfs_intent, leased = leased_prefix()
observed_names = ["artifacts", "rootfs-v1"]
fs_intent = {
    "operation_token": "a" * 64,
    "resource_id": "input-root",
    "action": "create",
    "expected_parent_generation": generation(50),
    "names_sha256": names_digest(observed_names),
}
raw = append(raw, "FS_INTENT", fs_intent)
absent = {
    **fs_intent, "parent_observation": generation(50),
    "observed_names": observed_names,
}
raw = append(raw, "FS_ABSENT", absent)
raw = append(raw, "FS_SETTLED", absent)
command = command_body()
raw = append(raw, "COMMAND_INTENT", command)
raw = append(raw, "COMMAND_OUTCOME", zero_outcome(command))
ends = []
offset = 0
for line in raw.splitlines(keepends=True):
    offset += len(line)
    ends.append(offset)
    operation._parse(raw[:offset])
for offset in range(1, len(raw)):
    if offset not in ends:
        rejected(lambda offset=offset: operation._parse(raw[:offset]))

# Canonical envelope and scalar types are exact.
first = raw.splitlines(keepends=True)[0]
value = json.loads(first)
hostile = [
    first[:-2] + b',"version":"cogs.stage2-kata-operation/v1"}\n',
    first.replace(b'"body":', b'"body" :', 1),
]
for field, replacement in (
    ("sequence", True),
    ("next_offset", "000000000000000A"),
    ("version", "unknown"),
    ("record_type", "FUTURE"),
):
    changed = copy.deepcopy(value)
    changed[field] = replacement
    hostile.append(operation._canonical(changed))
changed = copy.deepcopy(value)
changed["additional"] = None
hostile.append(operation._canonical(changed))
changed = copy.deepcopy(value)
changed["body"]["host_boot_id"] = "bad\nboot"
hostile.append(operation._canonical(changed))
changed = copy.deepcopy(value)
changed["body"]["ssh_port"] = True
hostile.append(operation._canonical(changed))
for encoded in hostile:
    rejected(lambda encoded=encoded: operation._parse(encoded))
rejected(lambda: operation._parse(b"x" * (operation.MAX_BYTES + 1) + b"\n"))
rejected(lambda: operation._parse(b"{" + b"x" * operation.MAX_LINE + b"}\n"))
rejected(lambda: operation._parse(first + b"partial"))
rejected(lambda: operation._parse(first.replace(b"\n", b"\x00\n")))
assert operation.FIXED["temporary_peer"] == "c42g0"
assert operation.FIXED["containerd_version"] == "2.2.1"
assert operation.FIXED["kata_version"] == "3.32.0"
bad_pin = genesis_body()
bad_pin["rootfs_pin"] = {**operation.ROOTFS_PIN, "entry_count": True}
rejected(lambda: operation._encode("GENESIS", bad_pin, ()))
# Cross-ledger coordinates use the rootfs ledger's 65,536/64MiB bounds, not
# this operation journal's smaller bounds; include the pinned 4,353-entry case.
full, _intent, leased_body = leased_prefix()
acquire_prefix = b"".join(full.splitlines(keepends=True)[:3])
wide = {**leased_body, "leased_sequence": 4353,
        "leased_offset": f"{operation.fs.ROOTFS_LEDGER_MAX_BYTES:016x}"}
operation._parse(append(acquire_prefix, "ROOTFS_LEASED", wide))
rejected(lambda: append(acquire_prefix, "ROOTFS_LEASED", {
    **wide, "leased_sequence": operation.fs.ROOTFS_LEDGER_MAX_RECORDS,
}))
operation.RootfsAuthorization("b" * 64, operation.fs.ROOTFS_LEDGER_MAX_RECORDS - 1,
                              operation.fs.ROOTFS_LEDGER_MAX_BYTES, "d" * 64)
rejected(lambda: operation.RootfsAuthorization("b" * 64, operation.fs.ROOTFS_LEDGER_MAX_RECORDS,
                                               1, "d" * 64))
for kind, body, field in (
    ("UNCERTAIN", {"operation_token": "a" * 64, "reason": []}, "reason"),
    ("FS_INTENT", {**fs_intent, "resource_id": []}, "resource_id"),
    ("COMMAND_INTENT", {**command_body(), "command_id": []}, "command_id"),
):
    try:
        operation._validate_body(kind, body)
    except operation.OperationError:
        pass
    else:
        raise AssertionError(f"malformed {field} was not translated")

# FS observations are action-specific; absence binds both the exact parent and names digest.
for action, before, after in (
    ("create", None, generation(61, "file", 0o600, 1)),
    ("link", None, generation(62, "file", 0o600, 2)),
    ("remove", generation(63, "file", 0o600, 1), None),
    ("metadata", generation(64, "file", 0o600, 1), generation(64, "file", 0o400, 1, stamp=32)),
):
    intent = {**fs_intent, "action": action}
    prefix, _unused, _unused = leased_prefix()
    prefix = append(prefix, "FS_INTENT", intent)
    after_parent = generation(50) if action == "metadata" else generation(50, stamp=40)
    observed = {
        **intent,
        "before_parent": generation(50),
        "after_parent": after_parent,
        "before_child": before,
        "after_child": after,
    }
    transition = append(prefix, "FS_OBSERVED", observed)
    operation._parse(append(transition, "FS_SETTLED", observed))
    hostile_observation = copy.deepcopy(observed)
    if action == "metadata":
        hostile_observation["after_child"] = generation(65, "file", 0o400, 1)
    else:
        hostile_observation["before_child"], hostile_observation["after_child"] = after, before
    rejected(lambda hostile_observation=hostile_observation, prefix=prefix: append(prefix, "FS_OBSERVED", hostile_observation))
prefix, _unused, _unused = leased_prefix()
prefix = append(prefix, "FS_INTENT", fs_intent)
changed_parent = {**absent, "parent_observation": generation(51)}
rejected(lambda: append(prefix, "FS_ABSENT", changed_parent))
changed_names = {**absent, "names_sha256": "d" * 64}
rejected(lambda: append(prefix, "FS_ABSENT", changed_names))
for bad_names in (
    ["rootfs-v1", "artifacts"], ["artifacts", "artifacts"],
    ["artifacts", "kata-input-v1"], [str(index) for index in range(65)],
):
    hostile_absent = {
        **absent, "observed_names": bad_names, "names_sha256": names_digest(bad_names),
    }
    rejected(lambda hostile_absent=hostile_absent: append(prefix, "FS_ABSENT", hostile_absent))

# Network snapshots and each effect intent/observation/settlement share this
# journal. Replaced identities and out-of-order effects are rejected.
network_sources = [{"observation_serial": 0, "source_id": "IP_ALL_LINKS",
                    "output_sha256": hashlib.sha256(b"[]").hexdigest(), "output_length": 2}]
def network_identity(netns=None, sources=network_sources):
    value = {"netns": netns, "host_link": None, "peer_link": None, "nft": None,
             "tap": None, "tc": None, "addresses_sha256": operation.ZERO,
             "routes_sha256": operation.ZERO, "state_sha256": operation.ZERO}
    value["state_sha256"] = hashlib.sha256(operation._canonical({"identity": {
        name: child for name, child in value.items() if name != "state_sha256"},
        "sources": sources})).hexdigest()
    return value

def network_proof(body):
    body["proof_sha256"] = hashlib.sha256(operation._canonical({
        name: value for name, value in body.items() if name != "proof_sha256"
    })).hexdigest()
    return body

nsfs = {"name": "c42naaaaaaaaaa", "mount_id": 41, "parent_id": 30, "device": "0:4",
        "inode_device": 4, "inode": 4026533000}
prefix, _unused, _unused = leased_prefix()
baseline_snapshot = network_proof({
    "operation_token": "a" * 64, "policy_version": operation.network_journal.POLICY_VERSION,
    "snapshot_kind": "baseline", "sources": network_sources,
    "baselines": {name: hashlib.sha256(name.encode()).hexdigest()
                  for name in operation.NETWORK_BASELINES},
    "identity": network_identity(), "proof_sha256": operation.ZERO,
})
operation._validate_body("NETWORK_SNAPSHOT_V2", baseline_snapshot)
intent = {"operation_token": "a" * 64,
          "policy_version": operation.network_journal.POLICY_VERSION, "effect_serial": 0,
          "action": "IP_NETNS_ADD", "prior_proof_sha256": operation.ZERO,
          "target": network_identity()}
operation._validate_body("NETWORK_EFFECT_INTENT_V2", intent)
observed = network_proof({**intent, "disposition": "exact", "sources": network_sources,
                          "identity": network_identity(nsfs),
                          "proof_sha256": operation.ZERO})
operation._validate_body("NETWORK_EFFECT_OBSERVED_V2", observed)

# New B1 IDs are v2-only and never widen the unchanged historical v1 codec.
for new_id in ("IP_HOST_ADDRGEN_NONE", "IP_HOST_LINK_REMOVE", "IP_ALL_LINKS", "NFT_RULESET"):
    rejected(lambda new_id=new_id: operation._validate_body(
        "COMMAND_INTENT", {**command_body(), "command_id": new_id},
    ))

# Commands are strictly monotonic, direct outcomes are only exact not-started,
# and explicit uncertainty is terminal.
prefix, _unused, _unused = leased_prefix(); run = lambda serial: command_body(serial, "CTR_RUN")
rejected(lambda: append(prefix, "COMMAND_INTENT", run(1)))
with_intent = append(prefix, "COMMAND_INTENT", run(0))
rejected(lambda: append(with_intent, "COMMAND_OUTCOME", {
    **zero_outcome(run(0), "exited"), "status": 0,
    "wait_result": "waited", "reap_result": "reaped",
}))
preexec = {
    **run(0),
    "host_boot_id": "11111111-1111-1111-1111-111111111111",
    "pid": 10,
    "ppid": 1,
    "pgid": 10,
    "sid": 10,
    "proc_start_time": 100,
    "pidfd_supported": True,
    "executable_sha256": "e" * 64,
    "tool_closure_sha256": "f" * 64,
    "exec_status_pipe": key(80),
}
preexec_raw = append(with_intent, "COMMAND_PREEXEC", preexec)
exited = {
    **zero_outcome(run(0), "exited"),
    "status": 0,
    "wait_result": "waited",
    "reap_result": "reaped",
}
outcome_raw = append(preexec_raw, "COMMAND_OUTCOME", exited)
rejected(lambda: append(outcome_raw, "COMMAND_INTENT", run(1)))

# Command state is independent: every complete command triple returns the
# exact prior lifecycle phase, including startup-failure cleanup cuts.
interleaved = append(prefix, "BASELINES_CAPTURED", {
    "operation_token": "a" * 64, "proof_sha256": "1" * 64,
})
serial = 0
def command_cut(raw, expected_phase):
    global serial
    command = command_body(serial)
    raw = append(raw, "COMMAND_INTENT", command)
    assert operation._legal(operation._parse(raw)) == expected_phase
    raw = append(raw, "COMMAND_OUTCOME", zero_outcome(command))
    assert operation._legal(operation._parse(raw)) == expected_phase
    serial += 1
    return raw

for expected_phase, kind, body in (
    ("BASELINES_CAPTURED", "NETWORK_READY", {"operation_token": "a" * 64, "proof_sha256": "2" * 64}),
    ("NETWORK_READY", "READINESS_REVOKED", {"operation_token": "a" * 64}),
    ("READINESS_REVOKED", "OWNERSHIP_OBSERVED", {
        "operation_token": "a" * 64, "proof_sha256": "3" * 64,
        "task": "exact-owned", "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned",
    }),
    ("OWNERSHIP_OBSERVED", "TASK_STOPPED", {"operation_token": "a" * 64, "proof_sha256": "4" * 64}),
    ("TASK_STOPPED", "NETWORK_ABSENT", {"operation_token": "a" * 64, "proof_sha256": "5" * 64}),
):
    interleaved = command_cut(interleaved, expected_phase)
    interleaved = append(interleaved, kind, body)

# A failed/interrupted ctr start with exact task absence skips stop; an exact
# partial task requires stop. Unknown/boolean ownership cannot authorize either.
partial = append(append(prefix, "BASELINES_CAPTURED", {
    "operation_token": "a" * 64, "proof_sha256": "6" * 64}),
    "READINESS_REVOKED", {"operation_token": "a" * 64})
absent_owner = {"operation_token": "a" * 64, "proof_sha256": "7" * 64,
                "task": "absent", "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned"}
partial = append(partial, "OWNERSHIP_OBSERVED", absent_owner)
rejected(lambda: append(partial, "TASK_STOPPED", {"operation_token": "a" * 64, "proof_sha256": "8" * 64}))
operation._parse(append(partial, "NETWORK_ABSENT", {"operation_token": "a" * 64, "proof_sha256": "8" * 64}))
for hostile_owner in ({**absent_owner, "task": "unknown"}, {**absent_owner, "task": False}):
    base = append(append(prefix, "BASELINES_CAPTURED", {
        "operation_token": "a" * 64, "proof_sha256": "9" * 64}),
        "READINESS_REVOKED", {"operation_token": "a" * 64})
    rejected(lambda hostile_owner=hostile_owner, base=base: append(base, "OWNERSHIP_OBSERVED", hostile_owner))

uncertain = append(prefix, "UNCERTAIN", {"operation_token": "a" * 64, "reason": "unknown"})
rejected(lambda: append(uncertain, "COMMAND_INTENT", command_body(0)))

# Final baselines cannot bypass the closed lifecycle and release handshake.
final = {"operation_token": "a" * 64, "final_baselines_sha256": "d" * 64}
retire = {**final, "journal_key": key()}
rejected(lambda: append(prefix, "FINAL_BASELINES", final))
rejected(lambda: append(prefix, "RETIRE_INTENT", retire))


# Production host modules are trusted; guest/campaign input cannot import host
# Python. Capabilities stop accidental route composition, not arbitrary trusted
# coordinator code (which could call os directly). Closure introspection is not
# a security boundary, so this suite intentionally does not treat it as one.
operation_source = (REMOTE / "completion_kata_operation.py").read_text()
for phrase in (
    "Production host modules are trusted", "import or execute host Python",
    "These capabilities prevent unintended route", "Closure introspection is therefore outside",
):
    assert phrase in operation_source
for forbidden_name in (
    "_FixedJournal", "FixedJournal", "_open_io", "OperationAuthority",
    "create", "write_record", "unlink", "_rootfs_reopen_token",
):
    assert not hasattr(operation, forbidden_name)
for validator in (
    "_claim_rootfs_reopen", "_invoke_rootfs_reopen_route", "_settle_rootfs_reopen",
):
    assert callable(getattr(operation, validator))
source_tree = ast.parse(operation_source)
parents = {}
for source_node in ast.walk(source_tree):
    for child in ast.iter_child_nodes(source_node):
        parents[child] = source_node
for source_node in ast.iter_child_nodes(source_tree):
    if isinstance(source_node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        assert source_node.name not in {
            "_FixedJournal", "FixedJournal", "_open_io", "OperationAuthority",
            "create", "write_record", "unlink",
        }


# A structural lookalike with every former duck-typed method is not a permit.
class RootfsLookalike:
    def __init__(self):
        self.calls = []
    def _claim_rootfs_reopen(self):
        self.calls.append("claim")
        return self
    def _rootfs_reopen_token(self):
        self.calls.append("token")
        return "b" * 64
    def _settle_rootfs_reopen(self, _reference):
        self.calls.append("settle")


lookalike = RootfsLookalike()
rejected(lambda: lease._reopen_kata_reserved(lookalike, object()))
rejected(lambda: operation._claim_rootfs_reopen(lookalike))
rejected(lambda: operation._invoke_rootfs_reopen_route(
    lookalike, lambda *_args: (_ for _ in ()).throw(AssertionError("route reached")), object(),
))
rejected(lambda: operation._settle_rootfs_reopen(lookalike, object()))
assert lookalike.calls == []
assert not hasattr(lease, "_reopen_kata_grant")


def rootfs_reference():
    return SimpleNamespace(
        token="b" * 64,
        ledger_key=fs.HostKey(1, 2, 40, "file"),
        leased_settled=ledger.SettledBytes(8, 0x1234, "8" * 64),
        state_generation=fs.HostGeneration(fs.HostKey(1, 2, 41, "directory"), 0o700, 0, 0, 2, 0, 30, 31),
        operation_generation=fs.HostGeneration(fs.HostKey(1, 2, 42, "directory"), 0o700, 0, 0, 2, 0, 30, 31),
        root_generation=fs.HostGeneration(fs.HostKey(1, 2, 43, "directory"), 0o755, 0, 0, 2, 0, 30, 31),
    )


def linux_chain_factory(path, control):
    anchor = fs._open_root_node(control)
    chain = fs.HeldChain(anchor, ())
    parent = anchor
    try:
        for raw in Path(path).parts[1:]:
            name = fs._name(raw)
            node = fs._open_path_node(parent, name, "directory", control)
            chain = fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))
            parent = node
        return chain
    except BaseException as error:
        fs._close_chain(chain, error)


def fixture_journal(
    completion, bodies=(), malformed=None, wrong_journal_key=False, wrong_state_parent=False,
    host_boot_id=None,
):
    """Test-only filesystem fixture; production has no generic journal writer."""
    state_path = Path(completion) / operation.STATE_NAME.text
    state_path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state_path, 0o700)
    sentinel_path = state_path / operation.SENTINEL_NAME.text
    lock_path = state_path / operation.LOCK_NAME.text
    journal_path = state_path / operation.JOURNAL_NAME.text
    sentinel_path.write_bytes(operation.SENTINEL)
    lock_path.touch(exist_ok=True)
    os.chmod(sentinel_path, 0o600)
    os.chmod(lock_path, 0o600)
    if journal_path.exists():
        journal_path.unlink()
    journal_path.touch(mode=0o600)
    os.chmod(journal_path, 0o600)
    if malformed is not None:
        journal_path.write_bytes(malformed)
        return malformed

    control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
    chain = linux_chain_factory(completion, control)
    state = journal = None
    try:
        state = fs._open_path_node(chain.components[-1].node, operation.STATE_NAME, "directory", control)
        journal = fs._open_path_node(state, operation.JOURNAL_NAME, "file", control)
        journal_key = operation._key_value(journal.generation.key)
        state_generation = operation._generation_value(state.generation)
    finally:
        if journal is not None:
            fs._close_node(journal)
        if state is not None:
            fs._close_node(state)
        fs._close_chain(chain)
    recorded_key = {**journal_key, "inode": journal_key["inode"] + 1} if wrong_journal_key else journal_key
    recorded_state = (
        {**state_generation, "mtime_ns": state_generation["mtime_ns"] + 1}
        if wrong_state_parent else state_generation
    )
    genesis = genesis_body(journal=recorded_key)
    if host_boot_id is not None: genesis["host_boot_id"] = host_boot_id
    raw = append(b"", "GENESIS", genesis)
    raw = append(raw, "GENESIS_SETTLED", {
        "operation_token": "a" * 64, "journal_key": recorded_key,
        "state_parent": recorded_state,
    })
    for row in bodies:
        if callable(row):
            raw = row(raw)
            continue
        kind, body = row
        if kind == "ROOTFS_RELEASE_AUTHORIZED":
            body = {**body, "release_ready_sha256": operation._parse(raw)[-1].line_sha256}
        raw = append(raw, kind, body)
    descriptor = os.open(journal_path, os.O_WRONLY | os.O_TRUNC)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(state_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return raw


def fixed_v2_intent(context, command_id=process.CommandId.IP_NETNS_ADD):
    fixed = process._FIXED_COMMANDS[command_id]
    environment = [list(row) for row in operation.FIXED_ENV]
    argv = [item.replace("{operation_token}", context.operation_token) for item in fixed.argv]
    attested = operation.command_policy.ATTESTED_EXECUTABLES.get(fixed.command_id.value)
    executable_sha256 = "c" * 64 if attested is None else attested["executable_sha256"]
    tool_closure_sha256 = "d" * 64 if attested is None else attested["tool_closure_sha256"]
    body = {
        "operation_token": context.operation_token, "command_serial": context.command_serial,
        "command_id": fixed.command_id.value, "binding_sha256": operation.ZERO,
        "journal_key": context.journal_key, "host_boot_id": context.host_boot_id,
        "source_revision": context.source_revision, "lifecycle_phase": context.lifecycle_phase,
        "executable_role": fixed.executable_role, "executable_path": fixed.executable_path,
        "executable_sha256": executable_sha256, "executable_generation": generation(90, "file", 0o755),
        "tool_closure_sha256": tool_closure_sha256, "argv": argv,
        "argv_sha256": hashlib.sha256(operation._canonical(argv)).hexdigest(),
        "stdin_hex": "", "stdin_sha256": hashlib.sha256(b"").hexdigest(), "stdin_length": 0,
        "environment": environment,
        "environment_sha256": hashlib.sha256(operation._canonical(environment)).hexdigest(),
        "inherited_fds": [], "policy_version": operation.command_policy.POLICY_VERSION,
        "deadline_class": process._spec(fixed.command_id).deadline_class, "duration_ns": fixed.duration_ns,
        "cleanup_reserve_ns": operation.command_policy.CLEANUP_RESERVE_NS,
        "deadline_boottime_ns": process._boottime_ns() + fixed.duration_ns,
        "output_grammar": fixed.output_grammar, "stdout_limit": fixed.stdout_limit,
        "stderr_limit": fixed.stderr_limit,
    }
    binding = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(operation._canonical(binding)).hexdigest()
    return body


def runtime_v2_intent(raw, command_id):
    records = operation._parse(raw); genesis = records[0].body
    phase = operation._legal(records); serial = sum(row.record_type == "COMMAND_INTENT_V2" for row in records)
    command = command_id.value; policy = operation.command_policy
    argv = [policy.STAGED_CTR, "--address", policy.CONTAINERD_ADDRESS, "--namespace", policy.NAMESPACE, *policy.CTR_TAILS[command]]
    deadline_class = "observer" if command in {"CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"} else "task-term" if command == "CTR_TASK_TERM" else "task-kill" if command == "CTR_TASK_KILL" else "remove"
    duration = {"observer": 5, "task-term": 15, "task-kill": 10, "remove": 20}[deadline_class] * 1_000_000_000
    environment = [list(row) for row in operation.FIXED_ENV]
    body = {"operation_token": genesis["operation_token"], "command_serial": serial, "command_id": command,
        "binding_sha256": operation.ZERO, "journal_key": genesis["journal_key"], "host_boot_id": genesis["host_boot_id"],
        "source_revision": genesis["source_revision"], "lifecycle_phase": phase, "executable_role": "ctr",
        "executable_path": policy.STAGED_CTR, "executable_sha256": policy.CONTAINERD_EXTRACTION[1][2],
        "executable_generation": generation(102, "file", 0o500), "tool_closure_sha256": "d" * 64,
        "argv": argv, "argv_sha256": hashlib.sha256(operation._canonical(argv)).hexdigest(), "stdin_hex": "",
        "stdin_sha256": hashlib.sha256(b"").hexdigest(), "stdin_length": 0, "environment": environment,
        "environment_sha256": hashlib.sha256(operation._canonical(environment)).hexdigest(), "inherited_fds": [],
        "policy_version": policy.RUNTIME_POLICY_VERSION, "deadline_class": deadline_class, "duration_ns": duration,
        "cleanup_reserve_ns": min(policy.CLEANUP_RESERVE_NS, duration // 2),
        "deadline_boottime_ns": duration * 2, "output_grammar": "text",
        "stdout_limit": 65536, "stderr_limit": 65536}
    body["binding_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items() if name != "binding_sha256"})).hexdigest()
    return body


def runtime_outcome(intent, uncertain=False):
    settled = not uncertain
    return {name: intent[name] for name in ("operation_token", "command_serial", "command_id", "binding_sha256")} | {
        "outcome": "not-started" if uncertain else "exited", "status": None if uncertain else 0, "errno": None,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(), "stdout_length": 0, "stdout_truncated": False,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_length": 0, "stderr_truncated": False,
        "leader_reaped": settled, "descendants_reaped": settled, "cgroup_empty": settled, "cgroup_removed": settled,
        "pipes_eof": settled, "release_count": 0 if uncertain else 1, "term_attempted": False,
        "kill_attempted": False, "deadline_expired": False, "uncertain": uncertain, "errors": []}


def staged_runtime_prefix():
    raw, _intent, _leased = leased_prefix(); token = "a" * 64; policy = operation.command_policy
    raw = append(raw, "BASELINES_CAPTURED", {"operation_token": token, "proof_sha256": "1" * 64})
    raw = append(raw, "NETWORK_READY", {"operation_token": token, "proof_sha256": "2" * 64})
    raw = append(raw, "RUNTIME_STAGE_INTENT_V4", {"operation_token": token, "policy_version": policy.RUNTIME_POLICY_VERSION,
        "policy_sha256": policy.RUNTIME_POLICY_SHA256, "temporary_name": ".kata-runtime-v1.staging"})
    stage = {"operation_token": token, "policy_version": policy.RUNTIME_POLICY_VERSION,
        "policy_sha256": policy.RUNTIME_POLICY_SHA256, "archive_sha256": policy.CONTAINERD_ARCHIVE_SHA256,
        "archive_size": policy.CONTAINERD_ARCHIVE_SIZE, "extraction_sha256": policy.CONTAINERD_EXTRACTION_SHA256,
        "runtime_generation": generation(101), "containerd_generation": generation(103, "file", 0o500),
        "ctr_generation": generation(102, "file", 0o500), "config_generation": generation(104, "file", 0o600),
        "root_generation": generation(105), "state_generation": generation(106)}
    return append(raw, "RUNTIME_STAGED_V3", stage)


def append_runtime_command(raw, command_id, uncertain=False):
    intent = runtime_v2_intent(raw, command_id); raw = append(raw, "COMMAND_INTENT_V2", intent)
    if not uncertain:
        serial = intent["command_serial"]
        preexec = {name: intent[name] for name in ("operation_token", "command_serial", "command_id", "binding_sha256", "host_boot_id")}
        preexec.update({"pid": 100 + serial, "ppid": 1, "pgid": 100 + serial, "sid": 100 + serial,
            "proc_start_time": 1, "pidfd_supported": True,
            "cgroup_path": f"{process.CGROUP_BASE}/{intent['operation_token']}-{serial}",
            "cgroup_generation": generation(200 + serial), "executable_sha256": intent["executable_sha256"],
            "tool_closure_sha256": intent["tool_closure_sha256"], "executable_generation": intent["executable_generation"],
            "exec_status_pipe": generation(300 + serial, "pipe", 0o600), "release_count": 0})
        raw = append(raw, "COMMAND_PREEXEC_V2", preexec)
    return append(raw, "COMMAND_OUTCOME_V2", runtime_outcome(intent, uncertain)), intent


# Runtime uncertainty is historical and sticky: observers are never resumable
# or retryable, while a consumed TERM uncertainty can finish teardown but never retire.
token = "a" * 64; proof = lambda value: {"operation_token": token, "proof_sha256": value * 64}
observer_raw = append(staged_runtime_prefix(), "READINESS_REVOKED", {"operation_token": token})
observer_raw, observer_intent = append_runtime_command(observer_raw, process.CommandId.CTR_TASK_LIST, True)
observer_resume = {"operation_token": token, "target_phase": "READINESS_REVOKED",
    "uncertain_serial": observer_intent["command_serial"], "binding_sha256": observer_intent["binding_sha256"]}
rejected(lambda: append(observer_raw, "RUNTIME_RESUME_V4", observer_resume))
rejected(lambda: append_runtime_command(observer_raw, process.CommandId.CTR_TASK_LIST))

sticky = append(staged_runtime_prefix(), "READINESS_REVOKED", {"operation_token": token})
for command_id in (process.CommandId.CTR_TASK_LIST, process.CommandId.CTR_CONTAINER_INFO, process.CommandId.CTR_CONTAINER_LIST):
    sticky, _unused = append_runtime_command(sticky, command_id)
ownership = {**proof("3"), "task": "exact-owned", "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned"}
sticky = append(sticky, "OWNERSHIP_OBSERVED", ownership)
sticky, _unused = append_runtime_command(sticky, process.CommandId.CTR_TASK_LIST)
sticky, term_intent = append_runtime_command(sticky, process.CommandId.CTR_TASK_TERM, True)
term_resume = {"operation_token": token, "target_phase": "OWNERSHIP_OBSERVED",
    "uncertain_serial": term_intent["command_serial"], "binding_sha256": term_intent["binding_sha256"]}
sticky = append(sticky, "RUNTIME_RESUME_V4", term_resume)
assert operation._legal(operation._parse(sticky)) == "OWNERSHIP_OBSERVED"
sticky, _unused = append_runtime_command(sticky, process.CommandId.CTR_TASK_LIST)
sticky = append(sticky, "TASK_STOPPED", proof("4")); sticky = append(sticky, "NETWORK_ABSENT", proof("5"))
for phase, commands, next_phase in (
    ("NETWORK_ABSENT", (process.CommandId.CTR_TASK_REMOVE, process.CommandId.CTR_TASK_LIST), "TASK_ABSENT"),
    ("TASK_ABSENT", (process.CommandId.CTR_CONTAINER_REMOVE, process.CommandId.CTR_CONTAINER_LIST), "CONTAINER_ABSENT"),
    ("CONTAINER_ABSENT", (process.CommandId.CTR_CONTAINER_LIST,), "RUNTIME_ABSENT")):
    assert operation._legal(operation._parse(sticky)) == phase
    for command_id in commands: sticky, _unused = append_runtime_command(sticky, command_id)
    sticky = append(sticky, next_phase, proof("6"))
for kind in ("SHARE_ABSENT", "FIREWALL_ABSENT", "INPUT_REMOVED"): sticky = append(sticky, kind, proof("7"))
leased_body = next(row.body for row in operation._parse(sticky) if row.record_type == "ROOTFS_LEASED")
ready = {"operation_token": token, "rootfs_token": "b" * 64, "rootfs_ledger_key": leased_body["rootfs_ledger_key"],
    "leased_sequence": leased_body["leased_sequence"], "leased_offset": leased_body["leased_offset"],
    "leased_sha256": leased_body["leased_sha256"], "input_removed_sha256": operation._parse(sticky)[-1].body["proof_sha256"]}
sticky = append(sticky, "ROOTFS_RELEASE_READY", ready); ready_record = operation._parse(sticky)[-1]
sticky = append(sticky, "ROOTFS_RELEASE_AUTHORIZED", {"operation_token": token, "rootfs_token": "b" * 64,
    "rootfs_authorized_sequence": 9, "rootfs_authorized_offset": "0000000000002222",
    "rootfs_authorized_sha256": "8" * 64, "release_ready_sha256": ready_record.line_sha256})
sticky = append(sticky, "ROOTFS_ABSENT", proof("9"))
final_body = {"operation_token": token, "final_baselines_sha256": "a" * 64}
retire_body = {**final_body, "journal_key": key()}
rejected(lambda: append(sticky, "FINAL_BASELINES", final_body))
rejected(lambda: append(sticky, "RETIRE_INTENT", retire_body))
rejected(lambda: append(sticky, "RETIRED", retire_body))
rejected(lambda: operation._make_fake_lifecycle_for_tests(sticky))

# The durable deadline uses strict admission/claim semantics at its exact edge.
deadline_raw, _unused, _unused = leased_prefix(); edge = 100 + operation.JOURNAL_TOTAL_NS
edge_body = {"operation_token": token, "admission_boottime_ns": 100,
    "ssh_start_deadline_boottime_ns": 100 + operation.JOURNAL_SETUP_MARGIN_NS, "journal_deadline_boottime_ns": edge}
deadline_raw = append(deadline_raw, "LIFECYCLE_DEADLINE_V1", edge_body)
deadline_records = operation._parse(deadline_raw)
with patch.object(operation, "_current_boot_id", return_value=deadline_records[0].body["host_boot_id"]):
    with patch.object(operation, "_boottime_ns", return_value=edge - 1):
        assert operation._require_live_production_deadline(deadline_records) == edge_body
    for now in (edge, edge + 1):
        with patch.object(operation, "_boottime_ns", return_value=now):
            rejected(lambda: operation._require_live_production_deadline(deadline_records))
assert deadline_raw == b"".join(operation._encode(row.record_type, row.body, deadline_records[:row.sequence]) for row in deadline_records)


def native_transaction_crashes(completion):
    if not os.access(process.CGROUP_ROOT, os.W_OK):
        return False
    fixed = process._FIXED_COMMANDS[process.CommandId.IP_NETNS_ADD]
    lifecycle = (("ROOTFS_ACQUIRE_INTENT", rootfs_intent), ("ROOTFS_LEASED", leased),
                 lifecycle_deadline(),
                 ("PRODUCTION_ADMISSION_V2", {"operation_token": "a" * 64,
                    "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
                    "policy_version": operation.command_policy.POLICY_VERSION,
                    "parser_source_sha256": operation.SSH_PARSER_SHA256}),
                 ("BASELINES_CAPTURED", {"operation_token": "a" * 64, "proof_sha256": "9" * 64}))
    for cut in ("intent", "create", "fork", "preexec", "release", "output"):
        fixture_journal(completion, lifecycle, host_boot_id=process._boot_id())
        descriptor = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
        executable_sha256 = process._digest_fd(descriptor, os.fstat(descriptor).st_size)
        retained = process.RetainedExecutable(
            "ip", "/usr/sbin/ip", descriptor, executable_sha256,
            "d" * 64, process._host_generation(descriptor),
        )
        identity_r, identity_w = os.pipe2(os.O_CLOEXEC)
        supervisor = os.fork()
        if supervisor == 0:
            try:
                os.close(identity_r)
                authority = operation._open_fixed_operation()
                if cut == "intent":
                    real = process.kata_operation._record_command_intent
                    process.kata_operation._record_command_intent = lambda *args: (real(*args), os._exit(83))[0]
                elif cut == "create":
                    real = process._prepare_cgroup
                    process._prepare_cgroup = lambda *args: (real(*args), os._exit(83))[0]
                elif cut == "fork":
                    real = process._identity
                    def crash_after_fork(*args):
                        identity, pidfd = real(*args)
                        os.write(identity_w, f"{identity.pid}:{identity.starttime}".encode("ascii"))
                        os._exit(83)
                    process._identity = crash_after_fork
                elif cut == "preexec":
                    real = process.kata_operation._record_command_preexec
                    process.kata_operation._record_command_preexec = lambda *args: (real(*args), os._exit(83))[0]
                elif cut == "output":
                    real = process.kata_operation._record_command_output
                    process.kata_operation._record_command_output = lambda *args: (real(*args), os._exit(83))[0]
                else:
                    process._drain_transaction = lambda *_args: os._exit(83)
                process._transact_fixed(authority, fixed, retained)
            finally:
                os._exit(84)
        os.close(descriptor); os.close(identity_w)
        assert os.waitpid(supervisor, 0)[1] == 83 << 8
        reported = os.read(identity_r, 64).decode("ascii"); os.close(identity_r)
        helper = str(ROOT / "test/aws-stage2-completion-kata-native-recover.py")
        recovery = os.fork()
        if recovery == 0:
            argv = ["/usr/bin/python3", "-I", "-B", helper, str(completion)]
            if reported: argv.append(reported)
            os.execve(argv[0], argv, {"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
        assert os.waitpid(recovery, 0)[1] == 0
        terminal = operation._parse(fixture_journal_path(completion).read_bytes())[-1]
        assert terminal.record_type == "COMMAND_OUTCOME_V2" and terminal.body["uncertain"]
        assert not os.path.exists(process.CGROUP_BASE)
    return True


DAEMON_SOURCE = r'''#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
static const char *path,*root,*state;static int listener=-1,graceful=0;
static void put(const char *base,const char *branch,const char *leaf){char p[512];snprintf(p,sizeof(p),"%s/%s",base,branch);mkdir(p,0700);snprintf(p,sizeof(p),"%s/%s/%s",base,branch,leaf);int f=open(p,O_WRONLY|O_CREAT|O_TRUNC,0600);if(f>=0){write(f,leaf,strlen(leaf));close(f);}}
static void mutate(int sig){(void)sig;put(root,"metadata/live","during");put(state,"plugins/live","during");}
static void remove_socket(int sig){(void)sig;unlink(path);}
static void terminate(int sig){(void)sig;if(!graceful)return;if(listener>=0)close(listener);unlink(path);_exit(0);}
int main(int n,char **v){for(int i=1;i+1<n;i++){if(!strcmp(v[i],"--address"))path=v[i+1];if(!strcmp(v[i],"--root"))root=v[i+1];if(!strcmp(v[i],"--state"))state=v[i+1];}if(!path||!root||!state)return 90;
mkdir(root,0700);mkdir(state,0700);put(root,"metadata","before");put(state,"plugins","before");char mode[512];snprintf(mode,sizeof(mode),"%s/term-responsive",state);graceful=access(mode,F_OK)==0;listener=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a={.sun_family=AF_UNIX};strncpy(a.sun_path,path,sizeof(a.sun_path)-1);
unlink(path);if(listener<0||bind(listener,(void*)&a,sizeof(a))||listen(listener,1))return 91;signal(SIGTERM,graceful?terminate:SIG_IGN);signal(SIGUSR1,remove_socket);signal(SIGUSR2,mutate);for(;;)pause();}'''


def native_runtime_daemon_foundations(completion):
    if not os.access(process.CGROUP_ROOT, os.W_OK): return False
    import completion_kata_command_policy as policy
    import completion_kata_runtime as runtime
    with tempfile.TemporaryDirectory(dir="/tmp") as raw:
        directory = Path(raw); source = directory / "daemon.c"; executable = directory / "daemon"
        source.write_text(DAEMON_SOURCE); subprocess.run(["/usr/bin/cc", "-O2", "-o", executable, source], check=True)
        os.chown(executable, 0, 0); os.chmod(executable, 0o500)
        descriptor = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
        digest = process._digest_fd(descriptor, os.fstat(descriptor).st_size); executable_generation = process._host_generation(descriptor)
        runtime_base = str(Path(completion) / "kata-runtime-v1")
        socket_path = runtime_base + "/containerd.sock"; original = {
            "base": policy.BASE, "address": policy.CONTAINERD_ADDRESS, "containerd": policy.STAGED_CONTAINERD,
            "process": (process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT, process.CONTAINERD_STATE,
                        process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD),
            "extraction": policy.CONTAINERD_EXTRACTION, "objects": operation._RUNTIME_POLICY_OBJECTS}
        replacement = (("bin/containerd", os.fstat(descriptor).st_size, digest, 0o500),
                       ("bin/ctr", os.fstat(descriptor).st_size, digest, 0o500))
        policy.BASE = str(completion); policy.CONTAINERD_ADDRESS = socket_path; policy.STAGED_CONTAINERD = runtime_base + "/bin/containerd"
        process.CONTAINERD_SOCKET = socket_path; process.CONTAINERD_ROOT = runtime_base + "/containerd-root"
        process.CONTAINERD_STATE = runtime_base + "/containerd-state"; process.CONTAINERD_CONFIG = runtime_base + "/containerd.toml"
        process.STAGED_CONTAINERD = policy.STAGED_CONTAINERD; policy.CONTAINERD_EXTRACTION = replacement
        objects = list(operation._RUNTIME_POLICY_OBJECTS); objects[8] = replacement; operation._RUNTIME_POLICY_OBJECTS = tuple(objects)
        retained = process.RetainedExecutable("containerd", policy.STAGED_CONTAINERD, descriptor, digest,
            "d" * 64, executable_generation)
        input_root = Path(completion) / operation.INPUT_NAME.text
        input_root.mkdir(mode=0o700)
        def path_generation(path, kind):
            value = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            try: return process._host_generation(value, kind)
            finally: os.close(value)
        def reset(extra=(), tree=True, graceful=False):
            if tree:
                Path(runtime_base).mkdir(mode=0o700)
                for child in ("bin", "containerd-root", "containerd-state"):
                    Path(runtime_base, child).mkdir(mode=0o700)
                Path(runtime_base + "/containerd.toml").write_bytes(runtime.CONTAINERD_CONFIG_BYTES)
                os.chmod(runtime_base + "/containerd.toml", 0o600)
                if graceful: Path(runtime_base + "/containerd-state/term-responsive").write_bytes(b"1")
            stage = {"operation_token": "a" * 64, "policy_version": policy.RUNTIME_POLICY_VERSION,
                "policy_sha256": policy.RUNTIME_POLICY_SHA256, "archive_sha256": policy.CONTAINERD_ARCHIVE_SHA256,
                "archive_size": policy.CONTAINERD_ARCHIVE_SIZE, "extraction_sha256": policy.CONTAINERD_EXTRACTION_SHA256,
                "runtime_generation": path_generation(runtime_base, "directory") if tree else generation(101),
                "containerd_generation": executable_generation, "ctr_generation": executable_generation,
                "config_generation": path_generation(runtime_base + "/containerd.toml", "file") if tree else generation(103, "file", 0o600),
                "root_generation": path_generation(runtime_base + "/containerd-root", "directory") if tree else generation(104),
                "state_generation": path_generation(runtime_base + "/containerd-state", "directory") if tree else generation(105)}
            fixture_journal(completion, (("ROOTFS_ACQUIRE_INTENT", rootfs_intent), ("ROOTFS_LEASED", leased),
                ("BASELINES_CAPTURED", {"operation_token": "a" * 64, "proof_sha256": "9" * 64}),
                ("NETWORK_READY", {"operation_token": "a" * 64, "proof_sha256": "8" * 64}),
                ("RUNTIME_STAGE_INTENT_V4", {"operation_token": "a" * 64, "policy_version": policy.RUNTIME_POLICY_VERSION,
                    "policy_sha256": policy.RUNTIME_POLICY_SHA256, "temporary_name": ".kata-runtime-v1.staging"}),
                ("RUNTIME_STAGED_V3", stage), *extra), host_boot_id=process._boot_id())
        previous = None; control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False); chain = None
        def boundary():
            held = linux_chain_factory(completion, control); return held, held.components[-1].node
        try:
            # Active runtime retention crosses the runtime shutdown boundary and consumes the exact KILL residue.
            reset(); chain, completion_node = boundary(); authority = operation._open_fixed_operation(); owner = process._start_fixed_daemon(authority, retained)
            daemon = runtime._retain_private_containerd(authority, completion_node, owner, control)
            daemon_pid = authority.runtime_recovery_history()["daemon_retained"][-1]["pid"]; os.kill(daemon_pid, signal.SIGUSR2)
            deadline = time.monotonic() + 2
            while not os.path.exists(runtime_base + "/containerd-state/plugins/live/during") and time.monotonic() < deadline: time.sleep(0.01)
            assert Path(runtime_base + "/containerd-root/metadata/before").is_file() and Path(runtime_base + "/containerd-root/metadata/live/during").is_file()
            assert runtime._verify_private_containerd(daemon)["socket_generation"] == authority.runtime_recovery_history()["daemon_retained"][-1]["socket_generation"]
            runtime._shutdown_private_containerd(daemon); outcome = authority.runtime_recovery_history()["daemon_outcomes"][-1]
            assert outcome["status"] == signal.SIGKILL and not outcome["uncertain"] and not os.path.lexists(socket_path)
            assert not os.path.exists(runtime_base) and not os.path.exists(process.CGROUP_BASE); authority.close(); fs._close_chain(chain); chain = None
            # Graceful TERM closes and self-unlinks the retained socket before uninterrupted runtime cleanup.
            reset(graceful=True); chain, completion_node = boundary(); graceful_journal = operation._open_fixed_operation()
            graceful_owner = process._start_fixed_daemon(graceful_journal, retained)
            graceful_daemon = runtime._retain_private_containerd(graceful_journal, completion_node, graceful_owner, control)
            runtime._shutdown_private_containerd(graceful_daemon); graceful_outcome = graceful_journal.runtime_recovery_history()["daemon_outcomes"][-1]
            assert graceful_outcome["status"] == 0 and not graceful_outcome["uncertain"] and not os.path.lexists(socket_path)
            graceful_journal.close(); assert not os.path.exists(runtime_base) and not os.path.exists(process.CGROUP_BASE); fs._close_chain(chain); chain = None
            # An incomplete durable terminal is strict-preserve even with a live exact daemon,
            # and also preserves a replacement at the recorded cgroup pathname.
            reset(); chain, completion_node = boundary(); uncertain_journal = operation._open_fixed_operation()
            uncertain_owner = process._start_fixed_daemon(uncertain_journal, retained)
            uncertain_daemon = runtime._retain_private_containerd(
                uncertain_journal, completion_node, uncertain_owner, control)
            retained_body = uncertain_journal.runtime_recovery_history()["daemon_retained"][-1]
            uncertain_journal.record_daemon_outcome({
                "operation_token": retained_body["operation_token"], "command_serial": retained_body["command_serial"],
                "command_id": retained_body["command_id"], "binding_sha256": retained_body["binding_sha256"],
                "pid": retained_body["pid"], "proc_start_time": retained_body["proc_start_time"], "status": None,
                "leader_reaped": False, "descendants_reaped": False, "cgroup_empty": False,
                "cgroup_removed": False, "uncertain": True, "errors": ["native-fixture-incomplete"]})
            rejected(lambda: runtime._shutdown_private_containerd(uncertain_daemon))
            assert (os.path.exists(f"/proc/{retained_body['pid']}") and os.path.isdir(retained_body["cgroup_path"])
                    and os.path.lexists(socket_path) and Path(runtime_base + "/containerd-root").is_dir()
                    and Path(runtime_base + "/containerd-state").is_dir())
            saved_socket = runtime_base + "/.uncertain-original.sock"; os.rename(socket_path, saved_socket)
            replacement_socket = socket.socket(socket.AF_UNIX); replacement_socket.bind(socket_path); os.chmod(socket_path, 0o600)
            rejected(lambda: runtime._shutdown_private_containerd(uncertain_daemon))
            assert os.path.lexists(socket_path) and os.path.lexists(saved_socket)
            replacement_socket.close(); os.unlink(socket_path); os.kill(retained_body["pid"], signal.SIGKILL)
            os.waitpid(retained_body["pid"], 0); recovery_errors = []
            assert process._recover_cgroup(retained_body["cgroup_path"], process._generation_tuple(
                retained_body["cgroup_generation"]), process._boottime_ns() + 2_000_000_000,
                {"term": False, "kill": False}, recovery_errors) == (True, True) and not recovery_errors
            os.mkdir(process.CGROUP_BASE); os.mkdir(retained_body["cgroup_path"])
            rejected(lambda: runtime._shutdown_private_containerd(uncertain_daemon))
            assert os.path.isdir(retained_body["cgroup_path"])
            os.rmdir(retained_body["cgroup_path"]); os.rmdir(process.CGROUP_BASE); os.unlink(saved_socket)
            process_close = inspect.getclosurevars(process._stop_fixed_daemon).nonlocals["close_state"]
            assert not process_close(uncertain_owner)
            runtime_states = inspect.getclosurevars(runtime._shutdown_private_containerd).nonlocals["daemons"]
            uncertain_state = runtime_states.pop(uncertain_daemon)
            if uncertain_state[9] is not None: os.close(uncertain_state[9][0])
            for index in (5, 6, 7, 4):
                if uncertain_state[index] is not None: fs._close_node(uncertain_state[index])
            parent = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try: runtime._purge_owned_tree(parent, "kata-runtime-v1")
            finally: os.close(parent)
            uncertain_journal.close(); fs._close_chain(chain); chain = None
            # Crash after preexec and socket creation but before DAEMON_RETAINED. An exact
            # uncertain command closure remains unqualified and preserves every residue.
            reset(); chain, completion_node = boundary(); crashed = os.fork()
            if crashed == 0:
                try:
                    local_journal = operation._open_fixed_operation()
                    operation._record_daemon_retained = lambda *_args: os._exit(93)
                    process._start_fixed_daemon(local_journal, retained)
                finally: os._exit(103)
            assert os.waitpid(crashed, 0)[1] == 93 << 8
            pre_retention = operation._open_fixed_operation(); pending = pre_retention.runtime_recovery_history()
            assert pending["tip"] == "COMMAND_PREEXEC_V2" and not pending["daemon_retained"]
            preexec = pending["preexecs"][-1]; saved_socket = str(Path(completion) / "pre-retention.sock")
            os.rename(socket_path, saved_socket)
            original_cgroup = preexec["cgroup_path"] + ".pre-retention"
            os.rename(preexec["cgroup_path"], original_cgroup); os.mkdir(preexec["cgroup_path"])
            pre_daemon = runtime._retain_private_containerd(
                pre_retention, completion_node, None, control)
            recovered = pre_retention.runtime_recovery_history(); command_outcome = recovered["outcomes"][-1]
            assert (recovered["phase"] == "UNCERTAIN" and recovered["tip"] == "COMMAND_OUTCOME_V2"
                    and len(recovered["outcomes"]) == 1 and command_outcome["uncertain"]
                    and all(command_outcome[name] == preexec[name] for name in
                            ("operation_token", "command_serial", "command_id", "binding_sha256"))
                    and not all(command_outcome[name] for name in
                                ("leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed")))
            rejected(lambda: runtime._cleanup_staged_runtime(pre_daemon))
            assert (pre_retention.runtime_recovery_history()["phase"] == "UNCERTAIN"
                    and len(pre_retention.runtime_recovery_history()["outcomes"]) == 1
                    and os.path.exists(f"/proc/{preexec['pid']}") and os.path.isdir(runtime_base)
                    and os.path.lexists(saved_socket) and os.path.isdir(original_cgroup)
                    and os.path.isdir(preexec["cgroup_path"]))
            os.kill(preexec["pid"], signal.SIGKILL); deadline = time.monotonic() + 2
            while os.path.exists(f"/proc/{preexec['pid']}") and time.monotonic() < deadline: time.sleep(0.01)
            os.unlink(saved_socket); os.rmdir(preexec["cgroup_path"]); recovery_errors = []
            assert process._recover_cgroup(original_cgroup, None, process._boottime_ns() + 2_000_000_000,
                {"term": False, "kill": False}, recovery_errors) == (True, True) and not recovery_errors
            pre_state = runtime_states.pop(pre_daemon)
            for index in (5, 6, 7, 4):
                if pre_state[index] is not None: fs._close_node(pre_state[index])
            parent = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try: runtime._purge_owned_tree(parent, "kata-runtime-v1")
            finally: os.close(parent)
            pre_retention.close(); fs._close_chain(chain); chain = None
            # A crash after a certain daemon outcome consumes the normal exact socket residue without a resume record.
            reset(); chain, completion_node = boundary(); journal = operation._open_fixed_operation(); owner = process._start_fixed_daemon(journal, retained)
            body = process._stop_fixed_daemon(owner, journal); assert body["status"] == signal.SIGKILL and not body["uncertain"] and os.path.lexists(socket_path)
            daemon = runtime._retain_private_containerd(journal, completion_node, None, control)
            runtime._shutdown_private_containerd(daemon); journal.close()
            assert not os.path.exists(runtime_base) and not os.path.exists(process.CGROUP_BASE); fs._close_chain(chain); chain = None
            # Fresh runtime-owner crashes qualify both durable socket-consumption cuts.
            def crash_cut(code, operation_name):
                reset(); held, node = boundary(); journal = operation._open_fixed_operation(); daemon_owner = process._start_fixed_daemon(journal, retained)
                outcome = process._stop_fixed_daemon(daemon_owner, journal)
                assert outcome["status"] == signal.SIGKILL and not outcome["uncertain"]
                journal.close(); fs._close_chain(held)
                child = os.fork()
                if child == 0:
                    local_chain = None
                    try:
                        local_control = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)
                        local_chain = linux_chain_factory(completion, local_control); local_journal = operation._open_fixed_operation()
                        local_daemon = runtime._retain_private_containerd(local_journal, local_chain.components[-1].node, None, local_control)
                        original_call = getattr(runtime.os, operation_name)
                        def cut(*args, **kwargs): original_call(*args, **kwargs); os._exit(code)
                        setattr(runtime.os, operation_name, cut); runtime._shutdown_private_containerd(local_daemon)
                    finally: os._exit(code + 10)
                assert os.waitpid(child, 0)[1] == code << 8
                expected_name = ".containerd.sock.removing" if operation_name == "rename" else None
                assert os.path.lexists(runtime_base + "/" + expected_name) if expected_name else not os.path.lexists(socket_path)
                held, node = boundary(); reopened = operation._open_fixed_operation()
                local_daemon = runtime._retain_private_containerd(reopened, node, None, control)
                assert runtime._verify_private_containerd(local_daemon) == reopened.runtime_recovery_history()["daemon_retained"][-1]
                runtime._shutdown_private_containerd(local_daemon); reopened.close(); fs._close_chain(held)
                assert not os.path.exists(runtime_base) and not os.path.exists(process.CGROUP_BASE)
            crash_cut(91, "rename"); crash_cut(92, "unlink")
            # Crash the owner; the daemon itself removes its socket before exact reopen failure and runtime cleanup.
            reset(); chain, completion_node = boundary(); ready_r, ready_w = os.pipe2(os.O_CLOEXEC); supervisor = os.fork()
            if supervisor == 0:
                try:
                    os.close(ready_r); journal = operation._open_fixed_operation(); process._start_fixed_daemon(journal, retained)
                    os.write(ready_w, b"R")
                finally: os._exit(81)
            os.close(ready_w); assert os.read(ready_r, 1) == b"R"; os.close(ready_r); assert os.waitpid(supervisor, 0)[1] == 81 << 8
            previous = process._set_subreaper(False); journal = operation._open_fixed_operation()
            daemon_pid = journal.runtime_recovery_history()["daemon_retained"][-1]["pid"]; os.kill(daemon_pid, signal.SIGUSR1)
            deadline = time.monotonic() + 2
            while os.path.lexists(socket_path) and time.monotonic() < deadline: time.sleep(0.01)
            assert not os.path.lexists(socket_path); before = len(os.listdir("/proc/self/fd")); rejected(lambda: process._reopen_fixed_daemon(journal))
            deadline = time.monotonic() + 2
            while os.path.exists(f"/proc/{daemon_pid}") and time.monotonic() < deadline: time.sleep(0.01)
            assert not os.path.exists(f"/proc/{daemon_pid}") and len(os.listdir("/proc/self/fd")) == before
            assert process._set_subreaper(False) is False and journal.resume_runtime_cleanup() == "RUNTIME_CLEANUP_ONLY"
            daemon = runtime._retain_private_containerd(journal, completion_node, None, control)
            rejected(lambda: runtime._shutdown_private_containerd(daemon))
            assert os.path.isdir(runtime_base) and not os.path.exists(process.CGROUP_BASE)
            uncertain_state = runtime_states.pop(daemon)
            for index in (5, 6, 7, 4):
                if uncertain_state[index] is not None: fs._close_node(uncertain_state[index])
            parent = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try: runtime._purge_owned_tree(parent, "kata-runtime-v1")
            finally: os.close(parent)
            journal.close(); assert not os.path.exists(runtime_base)
            fs._close_chain(chain); chain = None
            # The staged-only runtime cleanup boundary also consumes the operation-owned tree.
            reset(); chain, completion_node = boundary(); staged = operation._open_fixed_operation()
            daemon = runtime._retain_private_containerd(staged, completion_node, None, control)
            assert runtime._cleanup_staged_runtime(daemon) == {"runtime": "staged-absent"}
            staged.close(); assert not os.path.exists(runtime_base); fs._close_chain(chain); chain = None
            # The portable runtime matrix owns exact indexed post-KILL trace coverage.
            policy.BASE = original["base"]; policy.CONTAINERD_ADDRESS = original["address"]
            policy.STAGED_CONTAINERD = original["containerd"]
            # Staging rollback handles interrupted special-entry residue.
            stage = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.mkdir(".kata-runtime-v1.staging", 0o700, dir_fd=stage); child = os.open(
                    ".kata-runtime-v1.staging", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=stage)
                try: os.mkfifo("pending", 0o600, dir_fd=child)
                finally: os.close(child)
                runtime._purge_owned_tree(stage, ".kata-runtime-v1.staging")
            finally: os.close(stage)
            assert not os.path.lexists(str(Path(completion) / ".kata-runtime-v1.staging"))
            assert not os.path.exists(runtime_base) and not os.path.lexists(socket_path)
            return True
        finally:
            if previous is not None: process._set_subreaper(previous)
            if os.path.isdir(runtime_base):
                emergency = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try: runtime._purge_owned_tree(emergency, "kata-runtime-v1")
                finally: os.close(emergency)
            if os.path.isdir(process.CGROUP_BASE):
                for leaf in os.listdir(process.CGROUP_BASE): process._recover_cgroup(
                    process.CGROUP_BASE + "/" + leaf, None, process._boottime_ns() + 2_000_000_000,
                    {"term": False, "kill": False}, [])
                try: os.rmdir(process.CGROUP_BASE)
                except OSError: pass
            if chain is not None: fs._close_chain(chain)
            input_root.rmdir()
            os.close(descriptor); policy.BASE = original["base"]; policy.CONTAINERD_ADDRESS = original["address"]
            policy.STAGED_CONTAINERD = original["containerd"]; policy.CONTAINERD_EXTRACTION = original["extraction"]
            (process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT, process.CONTAINERD_STATE,
             process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD) = original["process"]
            operation._RUNTIME_POLICY_OBJECTS = original["objects"]


def native_containerd_metadata_fixture(completion, journal, network_owner, permit):
    """Prove fd-202 with real metadata-only containerd; no task or runtime starts."""
    fixture = os.environ.get("COGS_STAGE2_CONTAINERD_FIXTURE")
    assert fixture and os.geteuid() == 0
    import completion_kata_command_policy as policy
    base = str(Path(completion) / "kata-runtime-v1")
    paths = dict(address=base + "/containerd.sock", containerd=base + "/bin/containerd",
                 ctr=base + "/bin/ctr", root=base + "/containerd-root",
                 state=base + "/containerd-state", config=base + "/containerd.toml")
    saved = ((policy.BASE, policy.CONTAINERD_ADDRESS, policy.STAGED_CONTAINERD, policy.STAGED_CTR),
             (process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT, process.CONTAINERD_STATE,
              process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD, process.STAGED_CTR),
             (runtime.RUNTIME_ROOT, runtime.CONTAINERD_ADDRESS, runtime.STAGED_CONTAINERD,
              runtime.STAGED_CTR, runtime.CONTAINERD_ROOT, runtime.CONTAINERD_STATE,
              runtime.CONTAINERD_CONFIG))
    daemon_owner = containerd = ctr = None
    network_closed = False
    try:
        Path(base + "/bin").mkdir(parents=True, mode=0o700)
        Path(paths["root"]).mkdir(mode=0o700); Path(paths["state"]).mkdir(mode=0o700)
        for name in ("containerd", "ctr"):
            shutil.copyfile(fixture + "/bin/" + name, paths[name])
            os.chown(paths[name], 0, 0); os.chmod(paths[name], 0o500)
        Path(paths["config"]).write_bytes(runtime.CONTAINERD_CONFIG_BYTES); os.chmod(paths["config"], 0o600)
        policy.BASE, policy.CONTAINERD_ADDRESS, policy.STAGED_CONTAINERD, policy.STAGED_CTR = (
            str(completion), paths["address"], paths["containerd"], paths["ctr"])
        (process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT, process.CONTAINERD_STATE,
         process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD, process.STAGED_CTR) = (
            paths["address"], paths["root"], paths["state"], paths["config"], paths["containerd"], paths["ctr"])
        (runtime.RUNTIME_ROOT, runtime.CONTAINERD_ADDRESS, runtime.STAGED_CONTAINERD, runtime.STAGED_CTR,
         runtime.CONTAINERD_ROOT, runtime.CONTAINERD_STATE, runtime.CONTAINERD_CONFIG) = (
            base, paths["address"], paths["containerd"], paths["ctr"], paths["root"], paths["state"], paths["config"])
        def retain(role, path):
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC); identity = process._fd_identity(descriptor)
            return process.RetainedExecutable(role, path, descriptor, process._digest_fd(
                descriptor, identity.size), "d" * 64, process._host_generation(descriptor))
        def generation_at(path, kind):
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            try: return process._host_generation(descriptor, kind)
            finally: os.close(descriptor)
        containerd, ctr = retain("containerd", paths["containerd"]), retain("ctr", paths["ctr"])
        journal.record_runtime_stage_intent({"operation_token": "a" * 64,
            "policy_version": policy.RUNTIME_POLICY_VERSION, "policy_sha256": policy.RUNTIME_POLICY_SHA256,
            "temporary_name": ".kata-runtime-v1.staging"})
        journal.record_runtime_staged({"operation_token": "a" * 64, "policy_version": policy.RUNTIME_POLICY_VERSION,
            "policy_sha256": policy.RUNTIME_POLICY_SHA256, "archive_sha256": policy.CONTAINERD_ARCHIVE_SHA256,
            "archive_size": policy.CONTAINERD_ARCHIVE_SIZE, "extraction_sha256": policy.CONTAINERD_EXTRACTION_SHA256,
            "runtime_generation": generation_at(base, "directory"), "containerd_generation": containerd.generation,
            "ctr_generation": ctr.generation, "config_generation": generation_at(paths["config"], "file"),
            "root_generation": generation_at(paths["root"], "directory"),
            "state_generation": generation_at(paths["state"], "directory")})
        daemon_owner = process._start_fixed_daemon(journal, containerd)
        real_preexec = runtime._preexec_launch_network
        def prepare(value, pid):
            retained = real_preexec(value, pid)
            raw = operation._canonical(runtime._expected_operation_oci_spec(
                retained["operation_token"], retained["launch_path"]))
            descriptor = os.open(base + "/metadata-fixture.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            try: assert os.write(descriptor, raw) == len(raw); os.fsync(descriptor)
            finally: os.close(descriptor)
            return retained
        with patch.object(runtime, "_preexec_launch_network", side_effect=prepare):
            outcome, durable = process._transact_ctr_metadata_create(journal, ctr, permit, daemon_owner)
        assert (outcome.outcome, outcome.status, outcome.stdout, outcome.stderr, outcome.errors) == (
            "exited", 0, b"", b"", ()) and not durable.body["uncertain"]
        env = {"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        prefix = (paths["ctr"], "--address", paths["address"], "--namespace", runtime.NAMESPACE)
        info = subprocess.run((*prefix, "containers", "info", runtime.CONTAINER_ID), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        assert info.stderr == b"" and runtime.validate_stored_info(
            info.stdout, runtime._stored_launch_network_grant(permit),
            runtime._durable_ctr_launch_path(journal.runtime_recovery_history())) == runtime.MOUNT_LIST_SHA256
        removed = subprocess.run((*prefix, "containers", "remove", runtime.CONTAINER_ID), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        assert removed.stdout == removed.stderr == b""
        stopped = process._stop_fixed_daemon(daemon_owner, journal); daemon_owner = None
        assert not stopped["uncertain"] and not os.path.exists(process.CGROUP_BASE)
        network._close_runtime_network(network_owner); network_closed = True
        parent = os.open(completion, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: runtime._purge_owned_tree(parent, "kata-runtime-v1")
        finally: os.close(parent)
        assert not os.path.lexists(base)
    finally:
        if daemon_owner is not None:
            try: process._stop_fixed_daemon(daemon_owner, journal)
            except BaseException: pass
        if not network_closed:
            try: network._close_runtime_network(network_owner)
            except BaseException: pass
        for retained in (containerd, ctr):
            if retained is not None: os.close(retained.descriptor)
        policy.BASE, policy.CONTAINERD_ADDRESS, policy.STAGED_CONTAINERD, policy.STAGED_CTR = saved[0]
        (process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT, process.CONTAINERD_STATE,
         process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD, process.STAGED_CTR) = saved[1]
        (runtime.RUNTIME_ROOT, runtime.CONTAINERD_ADDRESS, runtime.STAGED_CONTAINERD, runtime.STAGED_CTR,
         runtime.CONTAINERD_ROOT, runtime.CONTAINERD_STATE, runtime.CONTAINERD_CONFIG) = saved[2]


INPUT_CRASH_CUTS = (
    "intent", "cgroup-create", "fork", "preexec", "release", "drain", "output",
    "effect", "fsync", "settlement", "quarantine", "removal",
)
SSH_CRASH_CUTS = (
    "intent", "cgroup-create", "fork", "preexec", "release", "drain", "output",
)
NATIVE_TEST_SHARDS = ("baseline", "network-runtime") + tuple(
    "input-" + cut for cut in INPUT_CRASH_CUTS) + tuple(
    "ssh-" + cut for cut in SSH_CRASH_CUTS)


def production_owner_test():
    shard = os.environ.get("COGS_STAGE2_KATA_NATIVE_TEST_SHARD")
    if shard is not None:
        assert (os.environ.get("COGS_REQUIRE_STAGE2_KATA_NATIVE_FOUNDATIONS") == "1"
                and shard in NATIVE_TEST_SHARDS)
    input_crash_cuts = (INPUT_CRASH_CUTS if shard is None else
                        tuple(cut for cut in INPUT_CRASH_CUTS if shard == "input-" + cut))
    ssh_crash_cuts = (SSH_CRASH_CUTS if shard is None else
                      tuple(cut for cut in SSH_CRASH_CUTS if shard == "ssh-" + cut))
    if sys.platform != "linux":
        return False, False, False
    if os.geteuid() != 0:
        rejected(operation._open_fixed_operation)
        return False, False, False
    with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
        os.chmod(temporary, 0o700)
        completion = Path(temporary) / "completion"
        completion.mkdir(mode=0o700)
        for sibling in ("artifacts", "rootfs-v1", "kata-input-v1"):
            (completion / sibling).mkdir(mode=0o700)

        def factory(control):
            return linux_chain_factory(completion, control)

        with patch.object(operation, "_open_base_chain", side_effect=factory):
            opened = operation._open_fixed_operation()
            assert opened.status() == "absent" and not hasattr(opened, "__dict__")
            for name in ("create", "write_record", "unlink", "_io", "_records", "_append"):
                assert not hasattr(opened, name)
            rejected(operation._open_fixed_operation)
            operation._create_fixed_operation_test_local(opened, genesis_body())
            assert opened.status() == "exact"
            created = operation._parse(fixture_journal_path(completion).read_bytes())
            assert len(created) == 1 and created[0].record_type == "GENESIS"
            rejected(lambda: operation._create_fixed_operation_test_local(opened, genesis_body()))
            opened.close()
            opened.close()

            fixture_journal(completion, malformed=b"malformed\n")
            malformed = operation._open_fixed_operation()
            assert malformed.status() == "preserve"
            malformed.close()

            intent = ("ROOTFS_ACQUIRE_INTENT", rootfs_intent)
            leased_records = (intent, ("ROOTFS_LEASED", leased))
            def production_fixture(bodies):
                fixture_journal(completion, bodies, host_boot_id=process._boot_id())
            for bodies in ((intent,), leased_records):
                for mismatch in ("journal", "state"):
                    fixture_journal(
                        completion, bodies,
                        wrong_journal_key=mismatch == "journal",
                        wrong_state_parent=mismatch == "state",
                    )
                    mismatched = operation._open_fixed_operation()
                    assert mismatched.status() == "preserve"
                    rejected(mismatched.reserve_rootfs)
                    mismatched.close()

            fixture_journal(completion, (intent,))
            stale = operation._open_fixed_operation()
            stale_permit = stale.reserve_rootfs()
            fixture_journal(completion, (intent, ("ROOTFS_LEASED", leased)))
            rejected(lambda: operation._claim_rootfs_reopen(stale_permit))
            stale.close()

            fixture_journal(completion, (intent,))
            authority = operation._open_fixed_operation()
            permit = authority.reserve_rootfs()
            assert not hasattr(permit, "__dict__")
            rejected(authority.reserve_rootfs)
            for forged in (object(), SimpleNamespace(), RootfsLookalike()):
                rejected(lambda forged=forged: operation._claim_rootfs_reopen(forged))
            grant = operation._claim_rootfs_reopen(permit)
            assert grant is not authority and not hasattr(grant, "__dict__")
            rejected(lambda: operation._claim_rootfs_reopen(permit))
            rejected(authority.reserve_rootfs)
            routed = []
            reference = rootfs_reference()
            assert operation._invoke_rootfs_reopen_route(
                grant, lambda token, control: (routed.append((token, control)) or reference), "control",
            ) is reference
            assert routed == [("b" * 64, "control")]
            rejected(lambda: operation._invoke_rootfs_reopen_route(grant, lambda *_args: reference, object()))
            for forged in (object(), SimpleNamespace(), RootfsLookalike()):
                rejected(lambda forged=forged: operation._settle_rootfs_reopen(forged, reference))
            with patch.object(operation.os, "write", return_value=0):
                rejected(lambda: operation._settle_rootfs_reopen(grant, reference))
            assert operation._parse(fixture_journal_path(completion).read_bytes())[-1].record_type == "ROOTFS_ACQUIRE_INTENT"
            operation._settle_rootfs_reopen(grant, reference)
            assert operation._parse(fixture_journal_path(completion).read_bytes())[-1].record_type == "ROOTFS_LEASED"
            rejected(lambda: operation._settle_rootfs_reopen(grant, reference))
            authority.close()

            authority = operation._open_fixed_operation()
            permit = authority.reserve_rootfs()
            held = SimpleNamespace(reference=reference, disposition="held", retained=object())
            calls = []
            real_claim = operation._claim_rootfs_reopen
            with patch.object(
                operation, "_claim_rootfs_reopen",
                side_effect=lambda value: (calls.append("claim") or real_claim(value)),
            ), patch.object(
                operation, "_invoke_rootfs_reopen_route",
                side_effect=lambda value, route, control: (calls.append("reopen") or held),
            ), patch.object(
                operation, "_settle_rootfs_reopen",
                side_effect=lambda value, ref: calls.append("settle"),
            ), patch.object(lease, "_verify", side_effect=lambda value, control: calls.append("verify")):
                assert lease._reopen_kata_reserved(permit, object()) is held
            assert calls == ["claim", "reopen", "verify", "settle"]
            rejected(lambda: lease._reopen_kata_reserved(permit, object()))
            authority.close()

            # The production baseline route runs through a real fsynced FixedJournal.
            if os.environ.get("COGS_REQUIRE_STAGE2_NETWORK_FOUNDATION") == "1":
                baseline_observed = {
                    **fs_intent, "before_parent": generation(50),
                    "after_parent": generation(50, stamp=40),
                    "before_child": None, "after_child": generation(51),
                }
                network_prefix = (intent, ("ROOTFS_LEASED", leased),
                    ("FS_INTENT", fs_intent), ("FS_OBSERVED", baseline_observed),
                    ("FS_SETTLED", baseline_observed))
                production_fixture(network_prefix)
                production_network = operation._open_fixed_operation(); retained_tools = []
                try:
                    for role, path in (("ip", "/usr/sbin/ip"), ("nft", "/usr/sbin/nft"), ("tc", "/usr/sbin/tc")):
                        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC); identity = process._fd_identity(descriptor)
                        retained_tools.append(process.RetainedExecutable(role, path, descriptor,
                            process._digest_fd(descriptor, identity.size), "d" * 64,
                            process._host_generation(descriptor)))
                    baseline_body = network._capture_fixed_baselines(production_network, *retained_tools)
                    assert baseline_body["snapshot_kind"] == "baseline"
                    assert any(kind == operation.network_journal.OUTPUT_RECORD
                               for kind, _body in operation._network_history(production_network))
                    # Fresh-process setup cuts: planned record, linked/pre-record,
                    # retained open, final pre-bind check, and bind/pre-output.
                    add_intent = network._effect_body(
                        production_network, network.Action.IP_NETNS_ADD,
                        target=baseline_body["identity"])
                    network._record_effect(production_network, "NETWORK_EFFECT_INTENT_V2", add_intent)
                    def setup_cut(owner, code, invoke):
                        child = os.fork()
                        if child == 0:
                            invoke(); os._exit(120)
                        _pid, status = os.waitpid(child, 0); assert os.waitstatus_to_exitcode(status) == code
                        owner.close(); return operation._open_fixed_operation()
                    original_record = network._original_placeholder_record
                    def cut_record():
                        def record(owner, identity):
                            original_record(owner, identity)
                            if identity["nlink"] == 0: os._exit(71)
                        with patch.object(network, "_original_placeholder_record", side_effect=record):
                            network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 71, cut_record)
                    def cut_link():
                        def record(owner, identity):
                            if identity["nlink"] == 1: os._exit(72)
                            original_record(owner, identity)
                        with patch.object(network, "_original_placeholder_record", side_effect=record):
                            network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 72, cut_link)
                    original_open = network.os.open
                    def cut_open():
                        def opened(path, *args, **kwargs):
                            descriptor = original_open(path, *args, **kwargs)
                            if path == "c42naaaaaaaaaa": os._exit(73)
                            return descriptor
                        with patch.object(network.os, "open", side_effect=opened): network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 73, cut_open)
                    setup_path = Path("/run/netns/c42naaaaaaaaaa")
                    setup_backup = Path(network.PRESERVED_DIR) / "setup-open-race-aaaaaaaaaa"
                    def replacement_open(path, *args, **kwargs):
                        if path == "c42naaaaaaaaaa":
                            setup_path.rename(setup_backup); setup_path.write_bytes(b"foreign")
                        return original_open(path, *args, **kwargs)
                    with patch.object(network.os, "open", side_effect=replacement_open):
                        try: network._establish_netns(production_network)
                        except network.NetworkError: pass
                        else: raise AssertionError("setup stat/open replacement adopted")
                    assert setup_path.read_bytes() == b"foreign"
                    setup_path.unlink(); setup_backup.rename(setup_path)
                    # The rejected lookup changed the original inode generation;
                    # preserve that journal and use a fresh baseline for later cuts.
                    setup_path.unlink(); production_network.close()
                    os.rmdir(network.PRESERVED_DIR)
                    assert ctypes.CDLL(None, use_errno=True).umount2(b"/run/netns", 0) == 0
                    production_fixture(network_prefix)
                    production_network = operation._open_fixed_operation()
                    baseline_body = network._capture_fixed_baselines(
                        production_network, *retained_tools)
                    add_intent = network._effect_body(
                        production_network, network.Action.IP_NETNS_ADD,
                        target=baseline_body["identity"])
                    network._record_effect(
                        production_network, "NETWORK_EFFECT_INTENT_V2", add_intent)
                    def cut_prebind():
                        with patch.object(network.os, "fork", side_effect=lambda: os._exit(74)):
                            network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 74, cut_prebind)
                    original_created = network._created_nsfs_record
                    def cut_created():
                        def created(owner, helper_pid, identity):
                            original_created(owner, helper_pid, identity); os._exit(76)
                        with patch.object(network, "_created_nsfs_record", side_effect=created):
                            network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 76, cut_created)
                    original_output = network._record_observation
                    def cut_bind():
                        def output(owner, source, raw, serial=None):
                            if source == "IP_NETNS_ADD": os._exit(75)
                            original_output(owner, source, raw, serial)
                        with patch.object(network, "_record_observation", side_effect=output): network._establish_netns(production_network)
                    production_network = setup_cut(production_network, 75, cut_bind)
                    foreign_name = "c42xaaaaaaaaaa"; fixed_env = {"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
                    foreign_add = subprocess.run(("/usr/sbin/ip", "netns", "add", foreign_name), env=fixed_env,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    assert foreign_add.returncode == 0 and foreign_add.stderr == b""
                    libc = ctypes.CDLL(None, use_errno=True)
                    assert libc.mount(("/run/netns/" + foreign_name).encode(), b"/run/netns/c42naaaaaaaaaa", None, 4096, None) == 0
                    foreign_inode = os.stat("/run/netns/" + foreign_name).st_ino
                    try: network._establish_netns(production_network)
                    except network.NetworkError: pass
                    else: raise AssertionError("foreign mounted nsfs accepted during setup recovery")
                    assert os.stat("/run/netns/c42naaaaaaaaaa").st_ino == foreign_inode
                    assert libc.umount2(b"/run/netns/c42naaaaaaaaaa", 2) == 0
                    foreign_delete = subprocess.run(("/usr/sbin/ip", "netns", "delete", foreign_name), env=fixed_env,
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    assert foreign_delete.returncode == 0 and foreign_delete.stderr == b""
                    rejected(lambda: network._resume_effect(production_network, *retained_tools))
                    production_network.close()
                    setup_mount = Path("/run/netns/c42naaaaaaaaaa")
                    if setup_mount.exists():
                        assert libc.umount2(os.fsencode(setup_mount), 2) == 0
                    for path in (setup_mount, Path("/run/netns/c42qaaaaaaaaaa")):
                        if path.exists(): path.unlink()
                    os.rmdir(network.PRESERVED_DIR)
                    # ip-netns made its test-owned parent a self-bind; restore the
                    # original plain directory before the final production scenario.
                    assert libc.umount2(b"/run/netns", 0) == 0
                    production_fixture((intent, ("ROOTFS_LEASED", leased),
                        ("FS_INTENT", fs_intent), ("FS_OBSERVED", baseline_observed),
                        ("FS_SETTLED", baseline_observed)))
                    production_network = operation._open_fixed_operation()
                    network._capture_fixed_baselines(production_network, *retained_tools)
                    ready_body = network._setup_fixed_network(production_network, *retained_tools)
                    assert ready_body["snapshot_kind"] == "ready"
                    token_suffix = production_network.command_context().operation_token[:10]
                    netns_name, tap_name = "c42n" + token_suffix, "tap" + token_suffix[:8]
                    tun = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
                    try:
                        fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", tap_name.encode(), 0x0002 | 0x1000 | 0x4000))
                        fixed_env = {"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
                        def net_command(*argv):
                            result = subprocess.run(argv, env=fixed_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            assert result.returncode == 0 and result.stderr == b""; return result.stdout
                        net_command("/usr/sbin/ip", "link", "set", "dev", tap_name, "netns", netns_name)
                        net_command("/usr/sbin/ip", "-n", netns_name, "link", "set", "dev", tap_name, "addrgenmode", "none")
                        net_command("/usr/sbin/ip", "-n", netns_name, "link", "set", "dev", tap_name, "up")
                        for endpoint in ("eth0", tap_name):
                            net_command("/usr/sbin/tc", "-n", netns_name, "qdisc", "add", "dev", endpoint, "ingress")
                        for source, target in (("eth0", tap_name), (tap_name, "eth0")):
                            net_command("/usr/sbin/tc", "-n", netns_name, "filter", "add", "dev", source,
                                "ingress", "protocol", "all", "pref", "49152", "u32", "match", "u32", "0", "0",
                                "action", "mirred", "egress", "redirect", "dev", target)
                        # Durable discovered-prefix cut: one real observer survives owner reopen.
                        network._perform_fixed(production_network, network.Action.IP_HOST_LINKS, *retained_tools)
                        production_network.close(); production_network = operation._open_fixed_operation()
                        runtime_body = network._observe_fixed_runtime_network(production_network, *retained_tools)
                        assert runtime_body["snapshot_kind"] == "runtime"
                        assert [row["snapshot_kind"] for row in operation._network_records(production_network)][-3:] == [
                            "ready", "discovered", "runtime"]
                        journal_path = fixture_journal_path(completion)
                        def replace_journal(raw):
                            descriptor = os.open(journal_path, os.O_WRONLY | os.O_TRUNC)
                            try:
                                offset = 0
                                while offset < len(raw): offset += os.write(descriptor, raw[offset:])
                                os.fsync(descriptor)
                            finally: os.close(descriptor)
                        production_network.close()
                        lifecycle = operation._make_fake_lifecycle_for_tests(journal_path.read_bytes())
                        lifecycle.runtime_ready(runtime_body["proof_sha256"])
                        lifecycle.ssh_ready("1" * 64); lifecycle.revoke_readiness()
                        lifecycle.ownership_observed("2" * 64); lifecycle.task_stopped("3" * 64)
                        replace_journal(lifecycle.journal_bytes())
                        production_network = operation._open_fixed_operation()
                        # Durable teardown-prefix cut resumes without a duplicate runtime pass.
                        network._perform_fixed(production_network, network.Action.IP_HOST_ROUTES4, *retained_tools)
                        production_network.close(); production_network = operation._open_fixed_operation()
                        planned_original = network._original_placeholder(production_network)
                        original_path = Path("/run/netns/c42n" + token_suffix)
                        pre_record_backup = Path(network.PRESERVED_DIR) / ("pre-record-" + token_suffix)
                        original_stat = network.os.stat
                        def move_record_race(path, *args, **kwargs):
                            result = original_stat(path, *args, **kwargs)
                            if (path == "c42n" + token_suffix and (result.st_dev, result.st_ino) ==
                                    (planned_original["device"], planned_original["inode"])):
                                original_path.rename(pre_record_backup); original_path.write_bytes(b"foreign")
                                return original_stat(path, *args, **kwargs)
                            return result
                        with patch.object(network.os, "stat", side_effect=move_record_race):
                            try: network._quarantine_netns(production_network, runtime_body["identity"])
                            except network.NetworkError: pass
                            else: raise AssertionError("move/pre-record replacement adopted")
                        assert original_path.read_bytes() == b"foreign"
                        original_path.unlink(); pre_record_backup.rename(original_path)
                        class QuarantineCut(Exception): pass
                        original_quarantine_record = network._quarantine_record
                        def moved_cut(owner, kind, target, placeholder=None, preserved=None):
                            original_quarantine_record(owner, kind, target, placeholder, preserved)
                            if kind == "NETWORK_QUARANTINE_MOVED_V2": raise QuarantineCut()
                        try:
                            with patch.object(network, "_quarantine_record", side_effect=moved_cut):
                                network._quarantine_netns(production_network, runtime_body["identity"])
                        except QuarantineCut: pass
                        original_path = Path("/run/netns/c42n" + token_suffix)
                        held_placeholder = Path(network.PRESERVED_DIR) / ("replacement-cut-" + token_suffix)
                        original_path.rename(held_placeholder); original_path.write_bytes(b"foreign")
                        replacement_identity = original_path.stat()
                        try: network._quarantine_netns(production_network, runtime_body["identity"])
                        except network.NetworkError: pass
                        else: raise AssertionError("revealed placeholder replacement adopted")
                        assert original_path.stat().st_ino == replacement_identity.st_ino
                        original_path.unlink(); held_placeholder.rename(original_path)
                        production_network.close(); production_network = operation._open_fixed_operation()
                        detach_child = os.fork()
                        if detach_child == 0:
                            original_stat = network.os.stat; planned_q = network._quarantine_stage(production_network)[1]["placeholder"]
                            def detach_stat(path, *args, **kwargs):
                                result = original_stat(path, *args, **kwargs)
                                if (path == "c42q" + token_suffix and
                                        (result.st_dev, result.st_ino) == (planned_q["device"], planned_q["inode"])): os._exit(81)
                                return result
                            with patch.object(network.os, "stat", side_effect=detach_stat):
                                network._remove_fixed_network(production_network, *retained_tools)
                            os._exit(82)
                        _pid, detach_status = os.waitpid(detach_child, 0)
                        assert os.waitstatus_to_exitcode(detach_status) == 81
                        production_network.close(); production_network = operation._open_fixed_operation()
                        absent_body = network._remove_fixed_network(production_network, *retained_tools)
                        assert absent_body["snapshot_kind"] == "network-absent"
                        os.close(tun); tun = None
                        production_network.close()
                        lifecycle = operation._make_fake_lifecycle_for_tests(journal_path.read_bytes())
                        lifecycle.task_absent("4" * 64); lifecycle.container_absent("5" * 64)
                        lifecycle.runtime_absent("6" * 64); lifecycle.share_absent("7" * 64)
                        replace_journal(lifecycle.journal_bytes())
                        production_network = operation._open_fixed_operation()
                        child = os.fork()
                        if child == 0:
                            original_record_network = operation._record_network
                            def nft_chunk_exit(owner, kind, body):
                                original_record_network(owner, kind, body)
                                if (kind == operation.network_journal.OUTPUT_RECORD and
                                        body["source_id"] == "NFT_REMOVE_ATOMIC" and body["chunk_index"] == 0):
                                    if body["chunk_count"] <= 1: os._exit(94)
                                    os._exit(93)
                            try:
                                with patch.object(operation, "_record_network", side_effect=nft_chunk_exit):
                                    network._remove_fixed_firewall(production_network, *retained_tools)
                            except network.NetworkError: os._exit(42)
                            os._exit(95)
                        _pid, child_status = os.waitpid(child, 0); child_code = os.waitstatus_to_exitcode(child_status)
                        nft_conditional_supported = child_code == 93
                        if not nft_conditional_supported:
                            assert child_code == 42
                            listed = network.parse_nft_snapshot(net_command("/usr/sbin/nft", "-j", "list", "table", "inet",
                                "c42t" + token_suffix), "c42t" + token_suffix, "c42h" + token_suffix)
                            assert network._nft_value(listed) == runtime_body["identity"]["nft"]
                            net_command("/usr/sbin/nft", "delete", "table", "inet", "c42t" + token_suffix)
                        if nft_conditional_supported:
                            production_network.close(); production_network = operation._open_fixed_operation()
                            restored = network._remove_fixed_firewall(production_network, *retained_tools)
                            assert restored["snapshot_kind"] == "firewall-restored"
                    finally:
                        if tun is not None: os.close(tun)
                    original_placeholder = Path("/run/netns/c42n" + token_suffix)
                    quarantine_placeholder = Path("/run/netns/c42q" + token_suffix)
                    assert not original_placeholder.exists() and not quarantine_placeholder.exists()
                    assert not Path(network.PRESERVED_DIR).exists()
                    assert network._netns_parent_mount() is None
                    assert not Path("/sys/class/net/c42h" + token_suffix).exists()

                    # Failed-launch route: task absent while the ready network still exists.
                    production_network.close()
                    production_fixture((intent, ("ROOTFS_LEASED", leased),
                        ("FS_INTENT", fs_intent), ("FS_OBSERVED", baseline_observed),
                        ("FS_SETTLED", baseline_observed)))
                    production_network = operation._open_fixed_operation()
                    network._capture_fixed_baselines(production_network, *retained_tools)
                    ready_body = network._setup_fixed_network(production_network, *retained_tools)
                    tun2 = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
                    fcntl.ioctl(tun2, 0x400454CA, struct.pack("16sH", tap_name.encode(), 0x0002 | 0x1000 | 0x4000))
                    net_command("/usr/sbin/ip", "link", "set", "dev", tap_name, "netns", netns_name)
                    net_command("/usr/sbin/ip", "-n", netns_name, "link", "set", "dev", tap_name, "addrgenmode", "none")
                    net_command("/usr/sbin/ip", "-n", netns_name, "link", "set", "dev", tap_name, "up")
                    baselines, _rows = network._baselines(production_network)
                    discovered_identity = network._observe_discovered_identity(
                        production_network, *retained_tools, ready_body["identity"])
                    discovered_body = network._snapshot(production_network, "discovered", baselines,
                        discovered_identity, network._sources(production_network, "NETWORK_SNAPSHOT_V2"))
                    production_network.close(); journal_path = fixture_journal_path(completion)
                    lifecycle = operation._make_fake_lifecycle_for_tests(journal_path.read_bytes())
                    lifecycle.revoke_readiness(); lifecycle.ownership_observed("8" * 64, task="absent")
                    replace_journal(lifecycle.journal_bytes())
                    production_network = operation._open_fixed_operation()
                    class IntentCut(Exception): pass
                    original_quarantine_record = network._quarantine_record
                    def intent_cut(owner, kind, target, placeholder=None, preserved=None):
                        original_quarantine_record(owner, kind, target, placeholder, preserved)
                        if kind == "NETWORK_QUARANTINE_INTENT_V2": raise IntentCut()
                    try:
                        with patch.object(network, "_quarantine_record", side_effect=intent_cut):
                            network._quarantine_netns(production_network, discovered_body["identity"])
                    except IntentCut: pass
                    production_network.close(); production_network = operation._open_fixed_operation()
                    class PlaceholderCut(Exception): pass
                    original_quarantine_record = network._quarantine_record
                    def placeholder_cut(owner, kind, target, placeholder=None, preserved=None):
                        original_quarantine_record(owner, kind, target, placeholder, preserved)
                        if kind == "NETWORK_QUARANTINE_PLACEHOLDER_V2": raise PlaceholderCut()
                    try:
                        with patch.object(network, "_quarantine_record", side_effect=placeholder_cut):
                            network._quarantine_netns(production_network, discovered_body["identity"])
                    except PlaceholderCut: pass
                    foreign_quarantine = Path("/run/netns/c42q" + token_suffix)
                    foreign_quarantine.write_bytes(b"foreign"); replacement_identity = foreign_quarantine.stat()
                    try: network._quarantine_netns(production_network, discovered_body["identity"])
                    except network.NetworkError: pass
                    else: raise AssertionError("quarantine placeholder replacement adopted")
                    assert foreign_quarantine.stat().st_ino == replacement_identity.st_ino
                    foreign_quarantine.unlink()
                    production_network.close(); production_network = operation._open_fixed_operation()
                    class SettledCut(Exception): pass
                    original_quarantine_record = network._quarantine_record
                    def settled_cut(owner, kind, target, placeholder=None, preserved=None):
                        original_quarantine_record(owner, kind, target, placeholder, preserved)
                        if kind == "NETWORK_QUARANTINE_SETTLED_V2": raise SettledCut()
                    try:
                        with patch.object(network, "_quarantine_record", side_effect=settled_cut):
                            network._quarantine_netns(production_network, discovered_body["identity"])
                    except SettledCut: pass
                    production_network.close(); production_network = operation._open_fixed_operation()
                    detach_child = os.fork()
                    if detach_child == 0:
                        original_quarantine_record = network._quarantine_record
                        def detach_intent_exit(owner, kind, target, placeholder=None, preserved=None):
                            original_quarantine_record(owner, kind, target, placeholder, preserved)
                            if kind == "NETWORK_DETACH_INTENT_V2": os._exit(83)
                        with patch.object(network, "_quarantine_record", side_effect=detach_intent_exit):
                            network._remove_fixed_network(production_network, *retained_tools)
                        os._exit(84)
                    _pid, detach_status = os.waitpid(detach_child, 0)
                    assert os.waitstatus_to_exitcode(detach_status) == 83
                    production_network.close(); production_network = operation._open_fixed_operation()
                    planned_q = network._quarantine_stage(production_network)[1]["placeholder"]
                    qpath = Path("/run/netns/c42q" + token_suffix); qbackup = Path(network.PRESERVED_DIR) / ("detach-race-" + token_suffix)
                    original_stat = network.os.stat
                    def detach_replacement(path, *args, **kwargs):
                        result = original_stat(path, *args, **kwargs)
                        if (path == "c42q" + token_suffix and (result.st_dev, result.st_ino) ==
                                (planned_q["device"], planned_q["inode"])):
                            qpath.rename(qbackup); qpath.write_bytes(b"foreign"); return original_stat(path, *args, **kwargs)
                        return result
                    with patch.object(network.os, "stat", side_effect=detach_replacement):
                        try: network._descriptor_remove_netns(production_network, discovered_body["identity"])
                        except network.NetworkError: pass
                        else: raise AssertionError("detach replacement adopted")
                    assert qpath.read_bytes() == b"foreign"; qpath.unlink(); qbackup.rename(qpath)
                    production_network.close(); production_network = operation._open_fixed_operation()
                    detached_child = os.fork()
                    if detached_child == 0:
                        original_quarantine_record = network._quarantine_record
                        def detached_exit(owner, kind, target, placeholder=None, preserved=None):
                            original_quarantine_record(owner, kind, target, placeholder, preserved)
                            if kind == "NETWORK_DETACHED_V2": os._exit(85)
                        with patch.object(network, "_quarantine_record", side_effect=detached_exit):
                            network._remove_fixed_network(production_network, *retained_tools)
                        os._exit(86)
                    _pid, detached_status = os.waitpid(detached_child, 0)
                    assert os.waitstatus_to_exitcode(detached_status) == 85
                    production_network.close(); production_network = operation._open_fixed_operation()
                    absent_body = network._remove_fixed_network(production_network, *retained_tools)
                    assert absent_body["snapshot_kind"] == "network-absent"
                    os.close(tun2); tun2 = None
                    production_network.close(); lifecycle = operation._make_fake_lifecycle_for_tests(journal_path.read_bytes())
                    lifecycle.task_absent("9" * 64); lifecycle.container_absent("a" * 64)
                    lifecycle.runtime_absent("b" * 64); lifecycle.share_absent("c" * 64)
                    replace_journal(lifecycle.journal_bytes())
                    production_network = operation._open_fixed_operation()
                    if nft_conditional_supported:
                        assert network._remove_fixed_firewall(production_network, *retained_tools)["snapshot_kind"] == "firewall-restored"
                    else:
                        try: network._remove_fixed_firewall(production_network, *retained_tools)
                        except network.NetworkError: pass
                        else: raise AssertionError("unsupported conditional nft deletion did not fail closed")
                        listed = network.parse_nft_snapshot(net_command("/usr/sbin/nft", "-j", "list", "table", "inet",
                            "c42t" + token_suffix), "c42t" + token_suffix, "c42h" + token_suffix)
                        assert network._nft_value(listed) == discovered_body["identity"]["nft"]
                        net_command("/usr/sbin/nft", "delete", "table", "inet", "c42t" + token_suffix)
                    assert not Path("/run/netns/c42n" + token_suffix).exists()
                    assert not Path("/run/netns/c42q" + token_suffix).exists()
                    assert not Path(network.PRESERVED_DIR).exists()
                    assert network._netns_parent_mount() is None
                    assert not Path("/sys/class/net/c42h" + token_suffix).exists()
                finally:
                    if "tun2" in locals() and tun2 is not None: os.close(tun2)
                    for tool in retained_tools: os.close(tool.descriptor)
                    production_network.close()
                    for cleanup in (("/usr/sbin/nft", "delete", "table", "inet", "c42taaaaaaaaaa"),
                            ("/usr/sbin/ip", "netns", "delete", "c42qaaaaaaaaaa"),
                            ("/usr/sbin/ip", "netns", "delete", "c42naaaaaaaaaa"),
                            ("/usr/sbin/ip", "netns", "delete", "c42xaaaaaaaaaa"),
                            ("/usr/sbin/ip", "link", "delete", "dev", "c42haaaaaaaaaa")):
                        subprocess.run(cleanup, env={"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    for placeholder in (Path("/run/netns/c42naaaaaaaaaa"), Path("/run/netns/c42qaaaaaaaaaa")):
                        try: placeholder.unlink()
                        except FileNotFoundError: pass
                    for placeholder in Path(network.PRESERVED_DIR).glob("c42paaaaaaaaaa-*"):
                        try: placeholder.unlink()
                        except FileNotFoundError: pass

            # Real FixedJournal persists exact output-bound baseline/effect cuts.
            network_fs_observed = {
                **fs_intent, "before_parent": generation(50),
                "after_parent": generation(50, stamp=40),
                "before_child": None, "after_child": generation(51),
            }
            fixture_journal(completion, (intent, ("ROOTFS_LEASED", leased),
                ("FS_INTENT", fs_intent), ("FS_OBSERVED", network_fs_observed),
                ("FS_SETTLED", network_fs_observed)))
            network_owner = operation._open_fixed_operation(); sources = []
            baseline_outputs = {name: b"[]" for name in ("IP_ALL_LINKS", "IP_ALL_ADDRESSES",
                "IP_ALL_ROUTES4", "IP_ALL_ROUTES6", "IP_NETNS_LIST")}
            baseline_outputs["NFT_RULESET"] = b'{"nftables":[]}'
            for command_id in (process.CommandId.IP_ALL_LINKS, process.CommandId.IP_ALL_ADDRESSES,
                    process.CommandId.IP_ALL_ROUTES4, process.CommandId.IP_ALL_ROUTES6,
                    process.CommandId.IP_NETNS_LIST, process.CommandId.NFT_RULESET):
                command = fixed_v2_intent(network_owner.command_context(), command_id)
                network_owner.record_command_intent(command)
                pre = {"operation_token": command["operation_token"], "command_serial": command["command_serial"],
                    "command_id": command["command_id"], "binding_sha256": command["binding_sha256"],
                    "host_boot_id": command["host_boot_id"], "pid": 100 + command["command_serial"], "ppid": 1,
                    "pgid": 100 + command["command_serial"], "sid": 100 + command["command_serial"],
                    "proc_start_time": 1, "pidfd_supported": True,
                    "cgroup_path": f"{process.CGROUP_BASE}/{command['operation_token']}-{command['command_serial']}",
                    "cgroup_generation": generation(91 + command["command_serial"]),
                    "executable_sha256": command["executable_sha256"],
                    "tool_closure_sha256": command["tool_closure_sha256"],
                    "executable_generation": command["executable_generation"],
                    "exec_status_pipe": generation(110 + command["command_serial"], "pipe", 0o600), "release_count": 0}
                network_owner.record_command_preexec(pre); raw_output = baseline_outputs[command["command_id"]]
                digest = hashlib.sha256(raw_output).hexdigest()
                terminal = {name: command[name] for name in ("operation_token", "command_serial", "command_id", "binding_sha256")}
                terminal.update({"outcome": "exited", "status": 0, "errno": None, "stdout_sha256": digest,
                    "stdout_length": len(raw_output), "stdout_truncated": False, "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_length": 0, "stderr_truncated": False, "leader_reaped": True,
                    "descendants_reaped": True, "cgroup_empty": True, "cgroup_removed": True,
                    "pipes_eof": True, "release_count": 1, "term_attempted": False, "kill_attempted": False,
                    "deadline_expired": False, "uncertain": False, "errors": []})
                network_owner.record_command_outcome(terminal)
                network._record_observation(network_owner, command["command_id"], raw_output, command["command_serial"])
                sources.append({"observation_serial": command["command_serial"], "source_id": command["command_id"],
                                "output_sha256": digest, "output_length": len(raw_output)})
            mountinfo = b"1 0 0:1 / / rw - tmpfs tmpfs rw\n"
            for source_id, raw_output in (("MOUNTINFO", mountinfo), ("NETNS_STAT", b"null")):
                network._record_observation(network_owner, source_id, raw_output)
                sources.append({"observation_serial": len(sources), "source_id": source_id,
                    "output_sha256": hashlib.sha256(raw_output).hexdigest(), "output_length": len(raw_output)})
            exact_empty = network_identity(sources=sources)
            exact_baselines = dict(zip(operation.NETWORK_BASELINES,
                tuple(hashlib.sha256(baseline_outputs[name]).hexdigest() for name in baseline_outputs) +
                (hashlib.sha256(mountinfo).hexdigest(),), strict=True))
            exact_baseline = network_proof({**baseline_snapshot, "baselines": exact_baselines,
                                              "sources": sources, "identity": exact_empty})
            operation._record_network(network_owner, "NETWORK_SNAPSHOT_V2", exact_baseline)
            operation._settle_network_phase(network_owner, "BASELINES_CAPTURED")
            exact_intent = {**globals()["intent"], "target": exact_empty}
            operation._record_network(network_owner, "NETWORK_EFFECT_INTENT_V2", exact_intent)
            network_owner.close(); resumed_network = operation._open_fixed_operation()
            assert operation._network_history(resumed_network)[-1] == ("NETWORK_EFFECT_INTENT_V2", exact_intent)
            rejected(lambda: operation._record_network(resumed_network, "NETWORK_EFFECT_OBSERVED_V2", observed))
            resumed_network.close()

            # Both durable release suffixes are freshly reservable through the
            # production authority and carry exact phase/cross-ledger pointers.
            input_root = completion / "kata-input-v1"
            input_root.rmdir()
            for authorized in (False, True):
                fixture_journal(completion, release_bodies(authorized))
                release_owner = operation._open_fixed_operation()
                reopen_grant = operation._claim_rootfs_reopen(release_owner.reserve_rootfs())
                routed = []
                reference = rootfs_reference()
                returned = operation._invoke_rootfs_reopen_route(
                    reopen_grant,
                    lambda context, control: (routed.append(context) or reference),
                    object(),
                )
                assert returned is reference and routed[0].operation_phase == (
                    "ROOTFS_RELEASE_AUTHORIZED" if authorized else "ROOTFS_RELEASE_READY"
                )
                if authorized:
                    assert (routed[0].authorized_sequence, routed[0].authorized_offset,
                            routed[0].authorized_sha256) == (9, 0x2222, "e" * 64)
                operation._settle_rootfs_reopen(reopen_grant, reference)
                release_grant = operation._claim_rootfs_release(
                    release_owner.reserve_rootfs_release(),
                )
                release_context = []
                root_authorization = operation._invoke_rootfs_release(
                    release_grant,
                    lambda context: (release_context.append(context) or operation.RootfsAuthorization(
                        context.rootfs_token, 9, 0x2222, "e" * 64,
                    )),
                )
                operation._settle_rootfs_release(release_grant, root_authorization)
                assert operation._parse(fixture_journal_path(completion).read_bytes())[-1].record_type == \
                    "ROOTFS_RELEASE_AUTHORIZED"
                assert release_context[0].operation_phase == (
                    "ROOTFS_RELEASE_AUTHORIZED" if authorized else "ROOTFS_RELEASE_READY"
                )
                release_owner.close()

            # Expired cleanup authority retains the exact rootfs cross-ledger
            # reservations but cannot use the acquire/leased setup phases.
            def settle_production_fs(raw):
                genesis = operation._parse(raw)[0].body
                parent = generation(60)
                def grant(path, name, kind, mode, serial, settled=False):
                    grant_id = hashlib.sha256(f"{path}:{name}:{serial}".encode()).hexdigest()
                    return {"operation_token": "a" * 64,
                        "action": "settled" if settled else "intent", "grant_id": grant_id,
                        "path": path, "name": name, "parent_generation": parent,
                        "parent_inode_version": 1, "expected_kind": kind,
                        "expected_mode": mode, "expected_uid": 0, "expected_gid": 0,
                        "command_serial": serial, "birth_min_ns": 10, "birth_max_ns": 20,
                        "mount_id": 1, "inode_version_min": 0,
                        "inode_version_max": 0xffffffff,
                        "child_generation": generation(70 + serial, kind, mode) if settled else None,
                        "child_birth_ns": 11 if settled else None,
                        "child_inode_version": 2 if settled else None}
                stage_name = "kata-key-stage-v1-" + "a" * 64
                for settled in (False, True):
                    raw = append(raw, "INPUT_GRANT", grant(
                        "@key-stage", stage_name, "directory", 0o700, 0, settled))
                for serial, command_id in enumerate(operation.command_policy.KEY_COMMAND_ORDER):
                    names = (("client", 0o600), ("client.pub", 0o644)) if "CLIENT" in command_id else (
                        ("server", 0o600), ("server.pub", 0o644))
                    if "KEYGEN" in command_id:
                        for name, mode in names:
                            raw = append(raw, "INPUT_GRANT", grant(
                                "@key-stage/" + name, name, "file", mode, serial))
                    context = SimpleNamespace(operation_token="a" * 64, command_serial=serial,
                        journal_key=genesis["journal_key"], host_boot_id=genesis["host_boot_id"],
                        source_revision=genesis["source_revision"], lifecycle_phase="ROOTFS_LEASED")
                    command = fixed_v2_intent(context, process.CommandId(command_id))
                    raw = append(raw, "COMMAND_INTENT_V2", command)
                    preexec = {name: command[name] for name in (
                        "operation_token", "command_serial", "command_id", "binding_sha256", "host_boot_id")}
                    preexec.update({"pid": 100 + serial, "ppid": 1, "pgid": 100 + serial,
                        "sid": 100 + serial, "proc_start_time": 1, "pidfd_supported": True,
                        "cgroup_path": f"{process.CGROUP_BASE}/{'a' * 64}-{serial}",
                        "cgroup_generation": generation(90 + serial),
                        "executable_sha256": command["executable_sha256"],
                        "tool_closure_sha256": command["tool_closure_sha256"],
                        "executable_generation": command["executable_generation"],
                        "exec_status_pipe": generation(100 + serial, "pipe", 0o600), "release_count": 0})
                    raw = append(raw, "COMMAND_PREEXEC_V2", preexec)
                    raw = append(raw, "COMMAND_OUTCOME_V2", runtime_outcome(command))
                    if "KEYGEN" in command_id:
                        for name, mode in names:
                            raw = append(raw, "INPUT_GRANT", grant(
                                "@key-stage/" + name, name, "file", mode, serial, True))
                expired_fs_observed = {
                    **fs_intent, "before_parent": generation(50),
                    "after_parent": generation(50, stamp=40),
                    "before_child": None, "after_child": generation(51),
                }
                raw = append(raw, "FS_INTENT", fs_intent)
                raw = append(raw, "FS_OBSERVED", expired_fs_observed)
                return append(raw, "FS_SETTLED", expired_fs_observed)

            release_rows = release_bodies(False)
            release_deadline = lifecycle_deadline()
            release_edge = release_deadline[1]["journal_deadline_boottime_ns"]
            release_admission = ("PRODUCTION_ADMISSION_V2", {
                "operation_token": "a" * 64,
                "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
                "policy_version": operation.command_policy.POLICY_VERSION,
                "parser_source_sha256": operation.SSH_PARSER_SHA256})
            production_fixture(release_rows[:2] + (release_deadline, settle_production_fs,
                               release_admission) + release_rows[2:5] + release_rows[6:-1])
            expired_release_owner = operation._open_fixed_operation()
            with patch.object(operation, "_boottime_ns", return_value=release_edge):
                expired_release = operation._claim_production_cleanup_operation(expired_release_owner)
                release_context = expired_release.prepare_rootfs_release()
                assert release_context.operation_phase == "ROOTFS_RELEASE_READY"
                assert operation._parse(fixture_journal_path(completion).read_bytes())[-1].record_type == \
                    "ROOTFS_RELEASE_READY"
                reopen = operation._claim_rootfs_reopen(expired_release.reserve_rootfs())
                reference = rootfs_reference()
                operation._invoke_rootfs_reopen_route(reopen, lambda _context, _control: reference, object())
                operation._settle_rootfs_reopen(reopen, reference)
                release = operation._claim_rootfs_release(expired_release.reserve_rootfs_release())
                authorization = operation._invoke_rootfs_release(release, lambda context:
                    operation.RootfsAuthorization(context.rootfs_token, 9, 0x2222, "e" * 64))
                operation._settle_rootfs_release(release, authorization)
            assert operation._durable_phase(expired_release) == "ROOTFS_RELEASE_AUTHORIZED"
            expired_release.close()
            input_root.mkdir(mode=0o700)

            # Production admission is a real fsynced FixedJournal record and
            # survives an exact reopen; legacy journals cannot be claimed.
            retained_deadline = lifecycle_deadline()
            edge = retained_deadline[1]["journal_deadline_boottime_ns"]
            for now in (edge, edge + 1):
                production_fixture(leased_records + (retained_deadline,))
                expired_admission = operation._open_fixed_operation()
                unchanged = fixture_journal_path(completion).read_bytes()
                with patch.object(operation, "_boottime_ns", return_value=now):
                    rejected(lambda: operation._admit_production_v2(expired_admission))
                assert fixture_journal_path(completion).read_bytes() == unchanged
                expired_admission.close()
            admitted_suffix = (retained_deadline, ("PRODUCTION_ADMISSION_V2", {
                "operation_token": "a" * 64, "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
                "policy_version": operation.command_policy.POLICY_VERSION,
                "parser_source_sha256": operation.SSH_PARSER_SHA256}))
            production_fixture(leased_records + admitted_suffix)
            expired_owner = operation._open_fixed_operation(); unchanged = fixture_journal_path(completion).read_bytes()
            with patch.object(operation, "_boottime_ns", return_value=edge - 1):
                assert operation._claim_production_operation(expired_owner) is expired_owner
            with patch.object(operation, "_boottime_ns", return_value=edge):
                rejected(lambda: operation._claim_production_operation(expired_owner))
                rejected(lambda: operation._record_input_grant(expired_owner, {}))
                cleanup_only = operation._claim_production_cleanup_operation(expired_owner)
            assert fixture_journal_path(completion).read_bytes() == unchanged
            for forbidden in ("admit_production_v2", "record_runtime_staged", "record_runtime_mount_v2",
                              "record_ssh_result", "record_ssh_ready", "retire"):
                rejected(lambda forbidden=forbidden: getattr(cleanup_only, forbidden))
            for allowed in ("begin_network_cleanup", "settle_network_cleanup", "network_records",
                            "network_history", "record_network", "settle_network_phase",
                            "prepare_rootfs_release", "settle_rootfs_absent", "reserve_rootfs",
                            "reserve_rootfs_release"):
                assert callable(getattr(cleanup_only, allowed))
            rejected(cleanup_only.reserve_rootfs)
            rejected(lambda: cleanup_only.record_command_intent(fixed_v2_intent(cleanup_only.command_context())))
            rejected(lambda: cleanup_only.settle_runtime_phase("RUNTIME_READY", "0" * 64))
            rejected(lambda: operation._claim_production_operation(cleanup_only)); cleanup_only.close()

            proof = lambda value: {"operation_token": "a" * 64, "proof_sha256": value * 64}
            expired_teardown = leased_records + admitted_suffix + (settle_production_fs,
                ("BASELINES_CAPTURED", proof("1")), ("NETWORK_READY", proof("2")),
                ("RUNTIME_READY", proof("3")), ("READINESS_REVOKED", {"operation_token": "a" * 64}),
                ("OWNERSHIP_OBSERVED", {**proof("4"), "task": "exact-owned",
                    "container": "exact-owned", "runtime": "exact-owned", "share": "exact-owned"}),
                ("TASK_STOPPED", proof("5")),)
            production_fixture(expired_teardown)
            expired_network_owner = operation._open_fixed_operation()
            with patch.object(operation, "_boottime_ns", return_value=edge):
                expired_network = operation._claim_production_cleanup_operation(expired_network_owner)
                expired_network.begin_network_cleanup("network")
                for command_id in ({process.CommandId(value) for value in operation.network_journal.MUTATIONS}
                                   - operation.actions.CLEANUP_NETWORK_COMMANDS):
                    command = fixed_v2_intent(expired_network.command_context(), command_id)
                    command["deadline_boottime_ns"] = edge + command["duration_ns"]
                    command["binding_sha256"] = operation.ZERO
                    command["binding_sha256"] = hashlib.sha256(operation._canonical(
                        {name: value for name, value in command.items() if name != "binding_sha256"})).hexdigest()
                    rejected(lambda command=command: expired_network.record_command_intent(command))
            assert expired_network.network_history()[-1][0] == "NETWORK_CLEANUP_INTENT_V2"
            expired_network.close()

            # Exact production reopens preserve active/completed historical V1
            # cleanup bytes, while a completed V2 receives its required ack
            # through the real cleanup-only capability.
            firewall_teardown = expired_teardown + (
                ("NETWORK_ABSENT", proof("6")), ("TASK_ABSENT", proof("7")),
                ("CONTAINER_ABSENT", proof("8")), ("RUNTIME_ABSENT", proof("9")),
                ("SHARE_ABSENT", proof("a")),)
            for target, prefix, intent_kind, completion_kind in (
                    ("network", expired_teardown, "NETWORK_CLEANUP_INTENT_V1", "NETWORK_ABSENT"),
                    ("firewall", firewall_teardown, "FIREWALL_CLEANUP_INTENT_V1", "FIREWALL_ABSENT")):
                intent_body = {"operation_token": "a" * 64}
                production_fixture(prefix + ((intent_kind, intent_body),))
                historical_owner = operation._open_fixed_operation()
                historical = operation._claim_production_cleanup_operation(historical_owner)
                retained = fixture_journal_path(completion).read_bytes()
                historical.begin_network_cleanup(target)
                assert fixture_journal_path(completion).read_bytes() == retained
                historical.close()
                production_fixture(prefix + ((intent_kind, intent_body),
                                              (completion_kind, proof("b"))))
                completed_owner = operation._open_fixed_operation()
                completed = operation._claim_production_cleanup_operation(completed_owner)
                retained = fixture_journal_path(completion).read_bytes()
                completed.settle_network_cleanup(target)
                assert fixture_journal_path(completion).read_bytes() == retained
                completed.close()
                v2_kind = intent_kind.replace("V1", "V2")
                production_fixture(prefix + ((v2_kind, intent_body),
                                              (completion_kind, proof("c"))))
                v2_owner = operation._open_fixed_operation()
                v2 = operation._claim_production_cleanup_operation(v2_owner)
                v2.settle_network_cleanup(target)
                assert operation._parse(fixture_journal_path(completion).read_bytes())[-1].record_type == \
                    intent_kind.replace("INTENT_V1", "SETTLED_V2")
                v2.close()

            production_fixture(leased_records)
            stale_admission = operation._open_fixed_operation()
            stale_bytes = fixture_journal_path(completion).read_bytes()
            with patch.object(operation, "_current_boot_id",
                              return_value="22222222-2222-2222-2222-222222222222"):
                rejected(lambda: operation._admit_production_v2(stale_admission))
            assert fixture_journal_path(completion).read_bytes() == stale_bytes
            stale_admission.close()
            production_fixture(leased_records)
            admitted = operation._open_fixed_operation()
            operation._admit_production_v2(admitted)
            assert operation._claim_production_operation(admitted) is admitted
            admitted_records = operation._parse(fixture_journal_path(completion).read_bytes())
            deadline_rows = [row.body for row in admitted_records
                             if row.record_type == "LIFECYCLE_DEADLINE_V1"]
            assert (len(deadline_rows) == 1
                    and deadline_rows[0]["ssh_start_deadline_boottime_ns"]
                    == deadline_rows[0]["admission_boottime_ns"]
                       + operation.JOURNAL_SETUP_MARGIN_NS
                    and deadline_rows[0]["journal_deadline_boottime_ns"]
                    == deadline_rows[0]["admission_boottime_ns"]
                       + operation.JOURNAL_TOTAL_NS)
            admitted_bytes = fixture_journal_path(completion).read_bytes()
            stale_intent = fixed_v2_intent(admitted.command_context())
            with patch.object(operation, "_current_boot_id",
                              return_value="22222222-2222-2222-2222-222222222222"):
                rejected(lambda: admitted.record_command_intent(stale_intent))
            assert fixture_journal_path(completion).read_bytes() == admitted_bytes
            admitted.close()
            reopened_admitted = operation._open_fixed_operation()
            assert operation._claim_production_operation(reopened_admitted) is reopened_admitted
            assert fixture_journal_path(completion).read_bytes() == admitted_bytes
            reopened_admitted.close()
            input_root.rmdir()

            # Real FixedJournal layout derives the sole active/quarantine names
            # from the admitted operation token and permits settlement writes
            # while either exact generation exists.
            layout_control = fs.OperationControl(
                time.monotonic_ns() + 30_000_000_000, lambda: False)
            layout_chain = linux_chain_factory(completion, layout_control)
            layout_parent = layout_chain.components[-1].node
            try:
                parent_generation = operation._generation_value(layout_parent.generation)
                parent_key = operation._key_value(layout_parent.generation.key)
                baseline_names = [os.fsdecode(name) for name in
                                  fs._enumerate_stable(layout_parent, layout_control).raw_names]
                baseline_names_sha = hashlib.sha256(
                    operation._canonical(baseline_names)).hexdigest()
            finally:
                fs._close_chain(layout_chain)
            active_name = "kata-key-stage-v1-" + "a" * 64
            quarantine_name = active_name + ".quarantine"
            grant = {"operation_token": "a" * 64, "action": "intent",
                "grant_id": "b" * 64, "path": "@key-stage", "name": active_name,
                "parent_generation": parent_generation, "parent_inode_version": 1,
                "expected_kind": "directory", "expected_mode": 0o700,
                "expected_uid": 0, "expected_gid": 0, "command_serial": 0,
                "birth_min_ns": 1, "birth_max_ns": (1 << 63), "mount_id": parent_key["mount_id"],
                "inode_version_min": 0, "inode_version_max": 0xffffffff,
                "child_generation": None, "child_birth_ns": None,
                "child_inode_version": None}
            layout_prefix = leased_records + (lifecycle_deadline(), ("PRODUCTION_ADMISSION_V2", {
                "operation_token": "a" * 64,
                "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
                "policy_version": operation.command_policy.POLICY_VERSION,
                "parser_source_sha256": operation.SSH_PARSER_SHA256}),)
            absence_intent = {
                "operation_token": "a" * 64, "resource_id": "input-root", "action": "create",
                "expected_parent_generation": parent_generation,
                "names_sha256": baseline_names_sha,
            }
            production_fixture(leased_records + (("FS_INTENT", absence_intent),))
            absence_owner = operation._open_fixed_operation()
            absence = {**absence_intent, "parent_observation": parent_generation,
                       "observed_names": baseline_names}
            absence_owner.record_fs_absent(absence)
            absence_owner.record_fs_settled(absence)
            assert absence_owner.durable_phase() == "FS_SETTLED"
            absence_owner.close()
            exact_absence = operation._open_fixed_operation()
            assert exact_absence.status() == "exact"
            exact_absence.close()
            production_fixture(layout_prefix + (("INPUT_GRANT", grant),))
            active_path = completion / active_name
            def assert_cleanup_only_preserved():
                preserved = operation._open_fixed_operation()
                try:
                    assert preserved.status() == "preserve"
                    rejected(lambda: operation._claim_production_operation(preserved))
                finally:
                    preserved.close()
            active_path.mkdir(mode=0o700)
            assert_cleanup_only_preserved()
            active_path.rmdir()
            stage_mkdir = {"operation_token": "a" * 64, "action": "mkdir",
                "path": "@key-stage", "parent_key": parent_key,
                "names_sha256": baseline_names_sha, "child_key": None,
                "before_mode": None, "target_mode": 0o700}
            hostile_layouts = (
                ({**grant, "parent_generation": {**parent_generation,
                    "inode": parent_generation["inode"] + 1}},
                 {**stage_mkdir, "parent_key": {**parent_key, "inode": parent_key["inode"] + 1}}),
                (grant, {**stage_mkdir, "names_sha256": "1" * 64}),
                (grant, {**stage_mkdir, "target_mode": 0o777}),
            )
            for hostile_grant, hostile_mkdir in hostile_layouts:
                production_fixture(layout_prefix + (
                    ("INPUT_GRANT", hostile_grant), ("INPUT_WA", hostile_mkdir)))
                active_path.mkdir(mode=0o700)
                assert_cleanup_only_preserved()
                active_path.rmdir()
            production_fixture(layout_prefix + (
                ("INPUT_GRANT", grant), ("INPUT_WA", stage_mkdir)))
            quarantine_path = completion / quarantine_name
            literal_path = completion / "kata-key-stage-v1"
            literal_path.mkdir(mode=0o700)
            rejected(operation._open_fixed_operation)
            literal_path.rmdir()
            active_path.mkdir(mode=0o700)
            active_owner = operation._open_fixed_operation()
            assert operation._claim_production_operation(active_owner) is active_owner
            layout_chain = linux_chain_factory(completion, layout_control)
            stage_node = fs._open_path_node(
                layout_chain.components[-1].node, fs._name(active_name), "directory", layout_control)
            try:
                stage_generation = operation._generation_value(stage_node.generation)
                for index, (key_name, mode) in enumerate((("client", 0o600), ("client.pub", 0o644))):
                    operation._record_input_grant(active_owner, {"action": "intent",
                        "grant_id": hashlib.sha256(key_name.encode()).hexdigest(),
                        "path": "@key-stage/" + key_name, "name": key_name,
                        "parent_generation": stage_generation, "parent_inode_version": 1,
                        "expected_kind": "file", "expected_mode": mode,
                        "expected_uid": 0, "expected_gid": 0, "command_serial": 0,
                        "birth_min_ns": 1, "birth_max_ns": (1 << 63),
                        "mount_id": stage_node.generation.key.mount_id,
                        "inode_version_min": 0, "inode_version_max": 0xffffffff,
                        "child_generation": None, "child_birth_ns": None,
                        "child_inode_version": None})
                    descriptor = os.open(key_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                         mode, dir_fd=stage_node.operation_fd.number)
                    os.fchmod(descriptor, mode); os.write(descriptor, b"fixture\n"); os.fsync(descriptor)
                    os.close(descriptor); os.fsync(stage_node.operation_fd.number)
                    active_owner.close(); active_owner = operation._open_fixed_operation()
                    assert operation._claim_production_operation(active_owner) is active_owner
                os.fsync(stage_node.operation_fd.number)
                operation._record_input_wa(active_owner, {"action": "remove", "path": "@key-stage",
                    "parent_key": parent_key, "names_sha256": "c" * 64,
                    "child_key": operation._key_value(stage_node.generation.key),
                    "before_mode": 0o700, "target_mode": 0})
            finally:
                fs._close_node(stage_node); fs._close_chain(layout_chain); active_owner.close()
            active_path.rename(quarantine_path)
            quarantined_owner = operation._open_fixed_operation()
            assert operation._claim_production_operation(quarantined_owner) is quarantined_owner
            quarantined_owner.close()
            active_path.mkdir(mode=0o700)
            rejected(operation._open_fixed_operation)
            active_path.rmdir()
            foreign = completion / ("kata-key-stage-v1-" + "b" * 64 + ".quarantine")
            quarantine_path.rename(foreign)
            assert_cleanup_only_preserved()
            foreign.rename(quarantine_path)
            final_owner = operation._open_fixed_operation()
            cleanup_chain = linux_chain_factory(completion, layout_control)
            try:
                cleanup = inputs._compose_production_input_cleanup(
                    final_owner, cleanup_chain.components[-1].node, layout_control)
                cleanup.continue_cleanup()
                rejected(lambda: operation._durable_phase(final_owner))
                final_owner.close(); final_owner = operation._open_fixed_operation()
                assert operation._durable_phase(final_owner) == "UNCERTAIN"
                assert not active_path.exists() and not quarantine_path.exists()
            finally:
                fs._close_chain(cleanup_chain); final_owner.close()

            # Synthetic runtime ownership issues one opaque operation-bound
            # grant, rejects wrong tokens/reuse, and detects held-node mutation.
            previous_runtime_test = os.environ.get("COGS_KATA_SYNTHETIC_RUNTIME_V1")
            os.environ["COGS_KATA_SYNTHETIC_RUNTIME_V1"] = "1"
            runtime_chain = linux_chain_factory(completion, layout_control)
            try:
                mounted = runtime_chain.components[-1].node
                runtime_owner = runtime._make_synthetic_runtime_mount_owner_for_tests(
                    "a" * 64, mounted, layout_control)
                runtime_grant = runtime._issue_runtime_mount_grant(runtime_owner)
                rejected(lambda: runtime._claim_runtime_mount_grant(runtime_grant, "b" * 64))
                claimed_node, claimed_control = runtime._claim_runtime_mount_grant(
                    runtime_grant, "a" * 64)
                assert claimed_node is mounted and claimed_control is layout_control
                rejected(lambda: runtime._claim_runtime_mount_grant(runtime_grant, "a" * 64))
            finally:
                fs._close_chain(runtime_chain)
            replacement_control = fs.OperationControl(
                time.monotonic_ns() + 30_000_000_000, lambda: False)
            replacement_chain = linux_chain_factory(completion, replacement_control)
            try:
                mounted = replacement_chain.components[-1].node
                replacement_owner = runtime._make_synthetic_runtime_mount_owner_for_tests(
                    "a" * 64, mounted, replacement_control)
                replacement_grant = runtime._issue_runtime_mount_grant(replacement_owner)
                os.fchmod(mounted.operation_fd.number, 0o755)
                rejected(lambda: runtime._claim_runtime_mount_grant(
                    replacement_grant, "a" * 64))
                os.fchmod(mounted.operation_fd.number, 0o700)
            finally:
                fs._close_chain(replacement_chain)
                if previous_runtime_test is None:
                    os.environ.pop("COGS_KATA_SYNTHETIC_RUNTIME_V1", None)
                else:
                    os.environ["COGS_KATA_SYNTHETIC_RUNTIME_V1"] = previous_runtime_test

            # Complete runtime owner -> opaque grant -> operation issuance ->
            # durable RUNTIME_MOUNT_V2 -> FixedJournal reopen round trip.
            fixture_elf = ensure_attested_static_fixture()
            staged_attestation = (
                (fixture_elf, fixture_elf, 0o500),
                (ROOT / "test/fixtures/stage2-completion/attested-ssh-contract-v1.json",
                 Path("/tmp/cogs-stage2-attested-ssh-contract-v1.json"), 0o600),
                (ROOT / "test/fixtures/stage2-completion/attested-ssh-keygen-contract-v1.json",
                 Path("/tmp/cogs-stage2-attested-ssh-keygen-contract-v1.json"), 0o600),
            )
            previous_attestation_test = os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V1")
            os.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V1"] = "1"
            try:
                for source, target, mode in staged_attestation:
                    if source == target:
                        continue
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                    try:
                        value = source.read_bytes(); offset = 0
                        while offset < len(value): offset += os.write(descriptor, value[offset:])
                        os.fsync(descriptor)
                    finally: os.close(descriptor)
                executable_owner = process._open_synthetic_attested_executable_owner_for_tests()
                ssh_executable = process._claim_attested_executable(executable_owner, "ssh")

                # Build expired cleanup fixtures only after the exact production
                # key-command policy has been issued, and advance through the
                # required production FS_SETTLED phase before network setup.
                production_fixture(release_rows[:2] + (release_deadline, release_admission,
                    settle_production_fs) + release_rows[2:5] + release_rows[6:])
                expired_release_owner = operation._open_fixed_operation()
                with patch.object(operation, "_boottime_ns", return_value=release_edge):
                    expired_release = operation._claim_production_cleanup_operation(expired_release_owner)
                    reopen = operation._claim_rootfs_reopen(expired_release.reserve_rootfs())
                    reference = rootfs_reference()
                    operation._invoke_rootfs_reopen_route(
                        reopen, lambda _context, _control: reference, object())
                    operation._settle_rootfs_reopen(reopen, reference)
                    release = operation._claim_rootfs_release(
                        expired_release.reserve_rootfs_release())
                    authorization = operation._invoke_rootfs_release(release, lambda context:
                        operation.RootfsAuthorization(context.rootfs_token, 9, 0x2222, "e" * 64))
                    operation._settle_rootfs_release(release, authorization)
                assert operation._durable_phase(expired_release) == "ROOTFS_RELEASE_AUTHORIZED"
                expired_release.close()

                production_fixture(expired_teardown)
                expired_network_owner = operation._open_fixed_operation()
                with patch.object(operation, "_boottime_ns", return_value=edge):
                    expired_network = operation._claim_production_cleanup_operation(
                        expired_network_owner)
                    expired_network.begin_network_cleanup("network")
                assert expired_network.network_history()[-1][0] == "NETWORK_CLEANUP_INTENT_V2"
                expired_network.close()

                transaction_completion = Path(operation.BASE)
                helper = str(ROOT / "test/aws-stage2-completion-kata-native-recover.py")
                process_cuts = {
                    "intent", "cgroup-create", "fork", "preexec", "release", "drain", "output",
                }
                def install_process_cut(cut, command_id):
                    if cut == "intent":
                        real = operation._record_command_intent
                        def after_intent(journal, body):
                            value = real(journal, body)
                            if body["command_id"] == command_id: os._exit(83)
                            return value
                        operation._record_command_intent = after_intent
                    elif cut == "cgroup-create":
                        real = process._prepare_cgroup
                        process._prepare_cgroup = lambda *args: (real(*args), os._exit(83))[0]
                    elif cut == "fork":
                        real = process._identity
                        def after_fork(*args):
                            identity, pidfd = real(*args)
                            os.write(identity_w,
                                     f"{identity.pid}:{identity.starttime}".encode("ascii"))
                            os._exit(83)
                            return identity, pidfd
                        process._identity = after_fork
                    elif cut == "preexec":
                        real = operation._record_command_preexec
                        def after_preexec(journal, body):
                            value = real(journal, body)
                            if body["command_id"] == command_id: os._exit(83)
                            return value
                        operation._record_command_preexec = after_preexec
                    elif cut == "release":
                        real = process.os.write
                        def after_release(descriptor, value):
                            count = real(descriptor, value)
                            if value == b"R": os._exit(83)
                            return count
                        process.os.write = after_release
                    elif cut == "output":
                        real = operation._record_command_output
                        def after_output(journal, body):
                            value = real(journal, body)
                            if body["command_id"] == command_id: os._exit(83)
                            return value
                        operation._record_command_output = after_output
                    else: process._drain_transaction = lambda *_args: os._exit(83)
                for cut in input_crash_cuts:
                    assert not transaction_completion.exists()
                    transaction_completion.mkdir(parents=True, mode=0o700)
                    for sibling in ("artifacts", "rootfs-v1"):
                        (transaction_completion / sibling).mkdir(mode=0o700)
                    fixture_journal(
                        transaction_completion, layout_prefix, host_boot_id=process._boot_id())
                    identity_r, identity_w = os.pipe2(os.O_CLOEXEC)
                    supervisor = os.fork()
                    if supervisor == 0:
                        os.close(identity_r)
                        try:
                            child_control = fs.OperationControl(
                                time.monotonic_ns() + operation.JOURNAL_TOTAL_NS, lambda: False)
                            child_factory = lambda control: linux_chain_factory(
                                transaction_completion, control)
                            with patch.object(operation, "_open_base_chain", side_effect=child_factory):
                                child_chain = linux_chain_factory(transaction_completion, child_control)
                                authority = operation._open_fixed_operation()
                                producer = inputs._compose_production_inputs(
                                    authority, child_chain.components[-1].node,
                                    child_control, executable_owner)
                                if cut in process_cuts:
                                    install_process_cut(cut, "SSH_KEYGEN_CLIENT")
                                elif cut == "effect":
                                    real = operation._record_command_outcome
                                    def after_effect(journal, body):
                                        value = real(journal, body)
                                        if body["command_id"] == "SSH_KEYGEN_CLIENT": os._exit(83)
                                        return value
                                    operation._record_command_outcome = after_effect
                                elif cut == "fsync":
                                    journal_type = type(authority)
                                    real = journal_type.record_input_wa
                                    def after_fsync(journal, body):
                                        if body["action"] == "file-settled": os._exit(83)
                                        return real(journal, body)
                                    journal_type.record_input_wa = after_fsync
                                elif cut == "settlement":
                                    real = operation._record_input_grant
                                    def after_settlement(journal, body):
                                        value = real(journal, body)
                                        if (body["action"] == "settled"
                                                and body["path"] == "@key-stage/client"): os._exit(83)
                                        return value
                                    operation._record_input_grant = after_settlement
                                elif cut == "quarantine":
                                    real = inputs._rename_noreplace
                                    inputs._rename_noreplace = lambda *args: (real(*args), os._exit(83))[0]
                                else:
                                    real = inputs.os.rmdir
                                    def after_removal(*args, **kwargs):
                                        value = real(*args, **kwargs)
                                        if kwargs.get("dir_fd") is not None: os._exit(83)
                                        return value
                                    inputs.os.rmdir = after_removal
                                producer.create()
                        finally: os._exit(84)
                    os.close(identity_w)
                    _pid, supervisor_status = os.waitpid(supervisor, 0)
                    assert os.waitstatus_to_exitcode(supervisor_status) == 83, (
                        cut, os.waitstatus_to_exitcode(supervisor_status))
                    reported = (os.read(identity_r, 64).decode("ascii")
                                if cut == "fork" else "")
                    os.close(identity_r)
                    recovery = os.fork()
                    if recovery == 0:
                        argv = ["/usr/bin/python3", "-I", "-B", helper,
                                str(transaction_completion)]
                        if reported: argv.append(reported)
                        os.execve(argv[0], argv, {"HOME": "/root", "LC_ALL": "C",
                            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "COGS_KATA_SYNTHETIC_ATTESTATION_V1": "1"})
                    assert os.waitpid(recovery, 0)[1] == 0
                    recovered_records = operation._parse(
                        fixture_journal_path(transaction_completion).read_bytes())
                    recovered_names = {item.name for item in transaction_completion.iterdir()}
                    assert (operation._legal(recovered_records) == "UNCERTAIN"
                            and active_name not in recovered_names
                            and quarantine_name not in recovered_names
                            and operation.INPUT_NAME.text not in recovered_names
                            and not os.path.exists(process.CGROUP_BASE))
                    if cut in {"intent", "cgroup-create", "fork", "preexec", "release", "drain"}:
                        terminals = [item.body for item in recovered_records
                                     if item.record_type == "COMMAND_OUTCOME_V2"]
                        assert len(terminals) == 1 and terminals[0]["uncertain"]
                    shutil.rmtree(transaction_completion)
                for cut in ssh_crash_cuts:
                    assert not transaction_completion.exists()
                    transaction_completion.mkdir(parents=True, mode=0o700)
                    for sibling in ("artifacts", "rootfs-v1"):
                        (transaction_completion / sibling).mkdir(mode=0o700)
                    fixture_journal(
                        transaction_completion, layout_prefix, host_boot_id=process._boot_id())
                    identity_r, identity_w = os.pipe2(os.O_CLOEXEC)
                    supervisor = os.fork()
                    if supervisor == 0:
                        os.close(identity_r)
                        try:
                            child_control = fs.OperationControl(
                                time.monotonic_ns() + operation.JOURNAL_TOTAL_NS, lambda: False)
                            child_factory = lambda control: linux_chain_factory(
                                transaction_completion, control)
                            with patch.object(operation, "_open_base_chain", side_effect=child_factory):
                                child_chain = linux_chain_factory(transaction_completion, child_control)
                                parent = child_chain.components[-1].node
                                authority = operation._open_fixed_operation()
                                inputs._FIXED_FIXTURE = ()
                                producer = inputs._compose_production_inputs(
                                    authority, parent, child_control, executable_owner)
                                identity = producer.create()
                                binding_owner = producer.claim_ssh_bindings()
                                bindings = process.fdmap._claim_production_inputs(
                                    binding_owner, "a" * 64, identity.manifest_sha256)
                                authority.close()
                                raw = fixture_journal_path(transaction_completion).read_bytes()
                                for kind in ("BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY"):
                                    raw += operation._encode(kind, {"operation_token": "a" * 64,
                                        "proof_sha256": "9" * 64}, operation._parse(raw))
                                descriptor = os.open(fixture_journal_path(transaction_completion),
                                                     os.O_WRONLY | os.O_TRUNC)
                                offset = 0
                                while offset < len(raw): offset += os.write(descriptor, raw[offset:])
                                os.fsync(descriptor); os.close(descriptor)
                                authority = operation._open_fixed_operation()
                                mounted = fs._open_path_node(
                                    parent, operation.INPUT_NAME, "directory", child_control)
                                os.environ["COGS_KATA_SYNTHETIC_RUNTIME_V1"] = "1"
                                runtime_owner = runtime._make_synthetic_runtime_mount_owner_for_tests(
                                    "a" * 64, mounted, child_control)
                                runtime_grant = runtime._issue_runtime_mount_grant(runtime_owner)
                                issuance = operation._issue_runtime_mount_v2(authority, runtime_grant)
                                operation._record_runtime_mount_v2(authority, issuance)
                                install_process_cut(cut, "SSH_READY")
                                process._transact_fixed_ssh(authority, ssh_executable, bindings)
                        except BaseException:
                            import traceback
                            traceback.print_exc()
                        finally: os._exit(84)
                    os.close(identity_w)
                    _pid, supervisor_status = os.waitpid(supervisor, 0)
                    assert os.waitstatus_to_exitcode(supervisor_status) == 83, (
                        cut, os.waitstatus_to_exitcode(supervisor_status))
                    reported = (os.read(identity_r, 64).decode("ascii")
                                if cut == "fork" else "")
                    os.close(identity_r)
                    recovery = os.fork()
                    if recovery == 0:
                        argv = ["/usr/bin/python3", "-I", "-B", helper,
                                str(transaction_completion)]
                        if reported: argv.append(reported)
                        os.execve(argv[0], argv, {"HOME": "/root", "LC_ALL": "C",
                            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "COGS_KATA_SYNTHETIC_ATTESTATION_V1": "1",
                            "COGS_KATA_COMPACT_INPUT_FIXTURE_V1": "1"})
                    assert os.waitpid(recovery, 0)[1] == 0
                    recovered_records = operation._parse(
                        fixture_journal_path(transaction_completion).read_bytes())
                    terminals = [item.body for item in recovered_records
                                 if item.record_type == "COMMAND_OUTCOME_V2"
                                 and item.body["command_id"] == "SSH_READY"]
                    recovered_names = {item.name for item in transaction_completion.iterdir()}
                    assert (len(terminals) == 1 and terminals[0]["uncertain"]
                            and operation._legal(recovered_records) == "UNCERTAIN"
                            and active_name not in recovered_names
                            and quarantine_name not in recovered_names
                            and operation.INPUT_NAME.text not in recovered_names
                            and not os.path.exists(process.CGROUP_BASE))
                    shutil.rmtree(transaction_completion)
                if shard is not None and shard != "baseline":
                    assert ((shard.startswith("input-") and len(input_crash_cuts) == 1
                             and not ssh_crash_cuts)
                            or (shard.startswith("ssh-") and len(ssh_crash_cuts) == 1
                                and not input_crash_cuts)
                            or (shard == "network-runtime" and not input_crash_cuts
                                and not ssh_crash_cuts))
                    return True, False, False
                assert not transaction_completion.exists()
                missing = []
                cursor = transaction_completion
                while not cursor.exists(): missing.append(cursor); cursor = cursor.parent
                for directory in reversed(missing): directory.mkdir(mode=0o700)
                for sibling in ("artifacts", "rootfs-v1"):
                    (transaction_completion / sibling).mkdir(mode=0o700)
                transaction_factory = lambda control: linux_chain_factory(transaction_completion, control)
                transaction_patch = patch.object(operation, "_open_base_chain", side_effect=transaction_factory)
                transaction_patch.start()
                full_input_fixture, inputs._FIXED_FIXTURE = inputs._FIXED_FIXTURE, ()
                transaction_control = fs.OperationControl(
                    time.monotonic_ns() + operation.JOURNAL_TOTAL_NS, lambda: False)
                transaction_chain = linux_chain_factory(transaction_completion, transaction_control)
                transaction_parent = transaction_chain.components[-1].node
                try:
                    fixture_journal(
                        transaction_completion, layout_prefix, host_boot_id=process._boot_id())
                    runtime_authority = operation._open_fixed_operation()
                    production_inputs = inputs._compose_production_inputs(
                        runtime_authority, transaction_parent, transaction_control, executable_owner)
                    identity = production_inputs.create()
                    binding_owner = production_inputs.claim_ssh_bindings()
                    bindings = process.fdmap._claim_production_inputs(
                        binding_owner, "a" * 64, identity.manifest_sha256)
                    transaction_names = set(fs._enumerate_stable(
                        transaction_parent, transaction_control).raw_names)
                    assert (active_name.encode() not in transaction_names
                            and quarantine_name.encode() not in transaction_names)
                    runtime_authority.close()
                    current_raw = fixture_journal_path(transaction_completion).read_bytes()
                    for kind, body in (("BASELINES_CAPTURED", {
                                           "operation_token": "a" * 64, "proof_sha256": "9" * 64}),
                                       ("NETWORK_READY", {
                                           "operation_token": "a" * 64, "proof_sha256": "9" * 64}),
                                       ("RUNTIME_READY", {
                                           "operation_token": "a" * 64, "proof_sha256": "9" * 64})):
                        current_raw += operation._encode(kind, body, operation._parse(current_raw))
                    journal_descriptor = os.open(
                        fixture_journal_path(transaction_completion), os.O_WRONLY | os.O_TRUNC)
                    try:
                        offset = 0
                        while offset < len(current_raw):
                            offset += os.write(journal_descriptor, current_raw[offset:])
                        os.fsync(journal_descriptor)
                    finally: os.close(journal_descriptor)
                    runtime_authority = operation._open_fixed_operation()
                    mounted_input = fs._open_path_node(
                        transaction_parent, operation.INPUT_NAME, "directory", transaction_control)
                    manifest_node = fs._open_path_node(
                        mounted_input, inputs.MANIFEST_NAME, "file", transaction_control)
                    manifest_sha = identity.manifest_sha256
                    os.environ["COGS_KATA_SYNTHETIC_RUNTIME_V1"] = "1"
                    runtime_owner = runtime._make_synthetic_runtime_mount_owner_for_tests(
                        "a" * 64, mounted_input, transaction_control)
                    runtime_grant = runtime._issue_runtime_mount_grant(runtime_owner)
                    issuance = operation._issue_runtime_mount_v2(runtime_authority, runtime_grant)
                    operation._record_runtime_mount_v2(runtime_authority, issuance)
                    rejected(lambda: operation._record_runtime_mount_v2(runtime_authority, issuance))
                    runtime_authority.close()
                    reopened_runtime = operation._open_fixed_operation()
                    assert operation._parse(
                        fixture_journal_path(transaction_completion).read_bytes())[-1].record_type == \
                        "RUNTIME_MOUNT_V2"
                    ssh_outcome, ssh_receipt = process._transact_fixed_ssh(
                        reopened_runtime, ssh_executable, bindings)
                    assert ssh_receipt.body["outcome"] == "exited"
                    parsed_result = operation.guest_workloads.parse_guest_workload_output(
                        ssh_outcome.stdout)
                    canonical_result = operation.guest_workloads.canonical_guest_workload_result(
                        parsed_result)
                    operation._record_ssh_result(
                        reopened_runtime, ssh_receipt.command_serial,
                        ssh_receipt.binding_sha256, manifest_sha,
                        ssh_outcome.stdout, canonical_result)
                    operation._record_ssh_ready(reopened_runtime)
                    operation._revoke_readiness(reopened_runtime)
                    production_inputs.release_ssh_bindings()
                    reopened_runtime.close()
                    teardown_raw = fixture_journal_path(transaction_completion).read_bytes()
                    for index, kind in enumerate(("OWNERSHIP_OBSERVED", "TASK_STOPPED",
                            "NETWORK_ABSENT", "TASK_ABSENT", "CONTAINER_ABSENT",
                            "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT"), 1):
                        body = {"operation_token": "a" * 64, "proof_sha256": str(index) * 64}
                        if kind == "OWNERSHIP_OBSERVED":
                            body.update({name: "exact-owned" for name in
                                         ("task", "container", "runtime", "share")})
                        teardown_raw += operation._encode(kind, body, operation._parse(teardown_raw))
                    descriptor = os.open(fixture_journal_path(transaction_completion), os.O_WRONLY | os.O_TRUNC)
                    try:
                        offset = 0
                        while offset < len(teardown_raw): offset += os.write(descriptor, teardown_raw[offset:])
                        os.fsync(descriptor)
                    finally: os.close(descriptor)
                    fs._close_node(manifest_node); fs._close_node(mounted_input)
                    completed_runtime = operation._open_fixed_operation()
                    assert operation._durable_phase(completed_runtime) == "FIREWALL_ABSENT"
                    cleanup = inputs._compose_production_input_cleanup(
                        completed_runtime, transaction_parent, transaction_control)
                    cleanup.continue_cleanup()
                    final_names = set(fs._enumerate_stable(
                        transaction_parent, transaction_control).raw_names)
                    assert (operation.INPUT_NAME.raw not in final_names
                            and active_name.encode() not in final_names
                            and quarantine_name.encode() not in final_names)
                    completed_runtime.close()
                    process._release_attested_executable(ssh_executable)
                finally:
                    fs._close_chain(transaction_chain)
                    transaction_patch.stop()
                    inputs._FIXED_FIXTURE = full_input_fixture
                    shutil.rmtree(transaction_completion)
                    for directory in missing[1:]:
                        try: directory.rmdir()
                        except OSError: break
            finally:
                os.environ.pop("COGS_KATA_SYNTHETIC_RUNTIME_V1", None)
                if previous_attestation_test is None:
                    os.environ.pop("COGS_KATA_SYNTHETIC_ATTESTATION_V1", None)
                else:
                    os.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V1"] = previous_attestation_test
                for _source, target, _mode in reversed(staged_attestation):
                    try: target.unlink()
                    except FileNotFoundError: pass

            # The fresh SSH recovery entry crosses the real FixedJournal and
            # exact production input-cleanup boundary before any final host
            # attestation data exists.
            recovery_prefix = leased_records + (lifecycle_deadline(), ("PRODUCTION_ADMISSION_V2", {
                "operation_token": "a" * 64,
                "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
                "policy_version": operation.command_policy.POLICY_VERSION,
                "parser_source_sha256": operation.SSH_PARSER_SHA256}),)
            production_fixture(recovery_prefix)
            recovery_authority = operation._open_fixed_operation()
            recovery_control = fs.OperationControl(
                time.monotonic_ns() + 30_000_000_000, lambda: False)
            recovery_chain = linux_chain_factory(completion, recovery_control)
            try:
                cleanup = inputs._compose_production_input_cleanup(
                    recovery_authority, recovery_chain.components[-1].node, recovery_control)
                rejected(lambda: ssh._recover_production_ssh(recovery_authority, cleanup))
                rejected(lambda: operation._durable_phase(recovery_authority))
                recovery_authority.close(); recovery_authority = operation._open_fixed_operation()
                assert operation._durable_phase(recovery_authority) == "UNCERTAIN"
            finally:
                fs._close_chain(recovery_chain)
                recovery_authority.close()

            # Dedicated input/SSH shards above own current V2 recovery cuts.
            lifecycle_prefix = leased_records

            # Historical v1 remains parseable offline but is not admitted by the
            # production fixed journal/owner route.
            legacy = command_body(0)
            production_fixture(lifecycle_prefix + (
                ("COMMAND_INTENT", legacy),
                ("COMMAND_OUTCOME", zero_outcome(legacy)),
            ))
            legacy_owner = operation._open_fixed_operation()
            assert legacy_owner.status() == "preserve"
            rejected(legacy_owner.command_context)
            legacy_owner.close()
            production_fixture(lifecycle_prefix)

            # Construction/read faults fail closed, and no lock or owner escapes.
            with patch.object(fs, "_read_regular", side_effect=OSError("injected read")):
                rejected(operation._open_fixed_operation)
            reopened = operation._open_fixed_operation()
            original_observe = fs._observe_child

            def rebound(parent, name, control):
                value = original_observe(parent, name, control)
                if name == operation.JOURNAL_NAME:
                    return fs.HostGeneration(value.key, value.mode, value.uid, value.gid,
                                             value.nlink, value.size, value.mtime_ns + 1, value.ctime_ns)
                return value

            with patch.object(fs, "_observe_child", side_effect=rebound):
                rejected(reopened.status)
            reopened.close()

            unknown = completion / "unknown-owner"
            unknown.mkdir(mode=0o700)
            rejected(operation._open_fixed_operation)
            unknown.rmdir()
            native_transaction = (False if shard == "network-runtime" else
                                  True if shard == "baseline" else
                                  native_transaction_crashes(completion))
            native_runtime = (False if shard == "network-runtime" else
                              native_runtime_daemon_foundations(completion))
    return True, native_transaction, native_runtime


def fixture_journal_path(completion):
    return Path(completion) / operation.STATE_NAME.text / operation.JOURNAL_NAME.text


owner_qualified, transaction_qualified, runtime_qualified = production_owner_test()
if (os.environ.get("COGS_REQUIRE_STAGE2_KATA_NATIVE_FOUNDATIONS") == "1"
        and not (owner_qualified and (transaction_qualified
                                     or os.environ.get("COGS_STAGE2_KATA_NATIVE_TEST_SHARD")
                                     in NATIVE_TEST_SHARDS[1:]))):
    raise RuntimeError("root Linux journal/cgroup transaction crash foundations were required")
if (os.environ.get("COGS_REQUIRE_STAGE2_KATA_RUNTIME_FOUNDATIONS") == "1" and not runtime_qualified):
    raise RuntimeError("root Linux long-lived runtime foundations were required")
qualification = "EUID-0 LINUX QUALIFIED" if owner_qualified else "EUID-0 Linux matrix SKIPPED"
print(f"completion Kata operation foundation matrix passed; {qualification}")

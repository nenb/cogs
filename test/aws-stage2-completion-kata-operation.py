#!/usr/bin/env python3
"""Hostile codec/capability matrix and Linux fixed-journal behavior tests."""

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
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
import completion_kata_operation as operation
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


def command_body(serial=0):
    return {
        "operation_token": "a" * 64,
        "command_serial": serial,
        "command_id": "CTR_RUN",
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

# Commands are strictly monotonic, direct outcomes are only exact not-started,
# and explicit uncertainty is terminal.
prefix, _unused, _unused = leased_prefix()
rejected(lambda: append(prefix, "COMMAND_INTENT", command_body(1)))
with_intent = append(prefix, "COMMAND_INTENT", command_body(0))
rejected(lambda: append(with_intent, "COMMAND_OUTCOME", {
    **zero_outcome(command_body(0), "exited"), "status": 0,
    "wait_result": "waited", "reap_result": "reaped",
}))
preexec = {
    **command_body(0),
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
    **zero_outcome(command_body(0), "exited"),
    "status": 0,
    "wait_result": "waited",
    "reap_result": "reaped",
}
outcome_raw = append(preexec_raw, "COMMAND_OUTCOME", exited)
next_intent = append(outcome_raw, "COMMAND_INTENT", command_body(1))
operation._parse(next_intent)

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
    raw = append(b"", "GENESIS", genesis_body(journal=recorded_key))
    raw = append(raw, "GENESIS_SETTLED", {
        "operation_token": "a" * 64, "journal_key": recorded_key,
        "state_parent": recorded_state,
    })
    for kind, body in bodies:
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


def production_owner_test():
    if sys.platform != "linux":
        return False
    if os.geteuid() != 0:
        rejected(operation._open_fixed_operation)
        return False
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
            input_root.mkdir(mode=0o700)

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
    return True


def fixture_journal_path(completion):
    return Path(completion) / operation.STATE_NAME.text / operation.JOURNAL_NAME.text


owner_qualified = production_owner_test()
qualification = "EUID-0 LINUX QUALIFIED" if owner_qualified else "EUID-0 Linux matrix SKIPPED"
print(f"completion Kata operation foundation matrix passed; {qualification}")

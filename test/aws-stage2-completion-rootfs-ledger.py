#!/usr/bin/env python3
"""Hostile codec, reconciliation, writer, and hardlink tests for D-R2.2b."""

import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


fs = load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
ledger = load("completion_rootfs_ledger", REMOTE / "completion_rootfs_ledger.py")
TOKEN = "a" * 64
REVISION = "b" * 40
MANIFEST = "c" * 64


def rejected(function):
    try:
        function()
    except (ledger.LedgerError, fs.RootfsFsError, OSError):
        return
    raise AssertionError("hostile ledger input accepted")


def control():
    return fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: False)


def generation(inode, kind="directory", mode=0o700, nlink=2, size=0, ctime=1, mtime=1):
    return fs.HostGeneration(fs.HostKey(1, 1, inode, kind), mode, 0, 0, nlink, size, mtime, ctime)


def parent(inode, names, ctime=1):
    return ledger.LedgerParent(generation(inode, ctime=ctime), tuple(sorted(names, key=lambda value: value.encode())))


def pvalue(value):
    return ledger._parent_value(value)


def gvalue(value):
    return ledger._generation_value(value)


def genesis_body(state_parent):
    return {
        "token": TOKEN,
        "source_revision": REVISION,
        "source_manifest_sha256": MANIFEST,
        "state_parent": pvalue(state_parent),
        "ledger_key": {"mount_id": 1, "device": 1, "inode": 99, "kind": "file"},
    }


def lifecycle_prefix():
    ledger_name = "active-ledger"
    operation_name = ledger._operation_name(TOKEN)
    state_before = parent(1, (ledger_name, "lock", "sentinel"))
    state_after = parent(1, (ledger_name, "lock", operation_name, "sentinel"), ctime=2)
    operation = generation(2)
    proposals = [
        ledger.LedgerProposal.create("genesis", genesis_body(state_before)),
        ledger.LedgerProposal.create("genesis-settled", {"token": TOKEN, "state_parent": pvalue(state_before)}),
        ledger.LedgerProposal.create(
            "operation-create-intent",
            {"token": TOKEN, "operation_name": operation_name, "state_parent": pvalue(state_before)},
        ),
        ledger.LedgerProposal.create(
            "operation-create-observed",
            {
                "token": TOKEN,
                "operation_name": operation_name,
                "state_parent": pvalue(state_after),
                "operation": gvalue(operation),
            },
        ),
        ledger.LedgerProposal.create(
            "operation-create-settled",
            {
                "token": TOKEN,
                "operation_name": operation_name,
                "state_parent": pvalue(state_after),
                "operation": gvalue(operation),
            },
        ),
    ]
    return proposals, state_before, state_after, operation


def encoded(proposals):
    chunks = []
    settled = ledger.INITIAL_BYTES
    for proposal in proposals:
        line = ledger._encode_proposal(proposal, settled)
        chunks.append(line)
        settled = ledger.SettledBytes(settled.sequence + 1, settled.offset + len(line), hashlib.sha256(line).hexdigest())
    return b"".join(chunks)


def codec_and_reconcile_tests():
    proposals, state_before, state_after, operation = lifecycle_prefix()
    active_raw = encoded(proposals)
    active = ledger._parse_ledger(active_raw)
    assert len(active) == 5 and active[-1].record_type == "operation-create-settled"
    observations = ledger.ReconcileObservations(state_after, ((ledger._operation_name(TOKEN), operation),), ())
    state = ledger._reconcile_ledger(active, observations)
    assert state.status == "active" and state.cleanup_allowed

    genesis = proposals[:2]
    ready = ledger._parse_ledger(encoded(genesis))
    assert ledger._reconcile_ledger(ready, ledger.ReconcileObservations(state_before, (), ())).status == "genesis-abortable"
    genesis_abort = genesis + [
        ledger.LedgerProposal.create("genesis-abort", {"token": TOKEN, "state_parent": pvalue(state_before)}),
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(state_before)}),
    ]
    assert ledger._reconcile_ledger(ledger._parse_ledger(encoded(genesis_abort)), ledger.ReconcileObservations(state_before, (), ())).status == "retired"

    operation_intent = proposals[:3]
    intent_records = ledger._parse_ledger(encoded(operation_intent))
    assert ledger._reconcile_ledger(intent_records, ledger.ReconcileObservations(state_before, (), ())).status == "operation-abortable"
    assert ledger._reconcile_ledger(intent_records, observations).status == "preserve"
    operation_abort = operation_intent + [
        ledger.LedgerProposal.create(
            "operation-abort",
            {"token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "state_parent": pvalue(state_before)},
        ),
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(state_before)}),
    ]
    ledger._parse_ledger(encoded(operation_abort))
    assert ledger._reconcile_ledger(active, ledger.ReconcileObservations(state_before, observations.operations, ())).status == "preserve"

    operation_parent_before = parent(2, ("sentinel",))
    operation_parent_after = parent(2, ("rootfs", "sentinel"), ctime=2)
    child = generation(3)
    create_intent = ledger.LedgerProposal.create(
        "create-intent",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_parent_before)},
    )
    create_observed = ledger.LedgerProposal.create(
        "create-observed",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_parent_after), "child": gvalue(child)},
    )
    create_settled = ledger.LedgerProposal.create(
        "create-settled",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_parent_after), "child": gvalue(child)},
    )
    create_intent_records = ledger._parse_ledger(encoded(proposals + [create_intent]))
    absent_observations = dataclasses.replace(observations, parents=(("", operation_parent_before),))
    absent = ledger._reconcile_ledger(create_intent_records, absent_observations)
    assert absent.status == "entry-absent" and absent.cleanup_allowed
    assert ledger._reconcile_ledger(create_intent_records, dataclasses.replace(absent_observations, entries=(("rootfs", child),))).status == "preserve"
    created_proposals = proposals + [create_intent, create_observed, create_settled]
    created = ledger._parse_ledger(encoded(created_proposals))
    operation_after_create = operation_parent_after.generation
    created_observations = dataclasses.replace(
        observations,
        operations=((ledger._operation_name(TOKEN), operation_after_create),),
        entries=(("rootfs", child),),
    )
    assert ledger._reconcile_ledger(created, created_observations).status == "active"
    observed_only = ledger._parse_ledger(encoded(proposals + [create_intent, create_observed]))
    assert ledger._reconcile_ledger(observed_only, created_observations).status == "preserve"

    desired = dataclasses.replace(child, mode=0o755, ctime_ns=2)
    metadata = [
        ledger.LedgerProposal.create(
            "metadata-intent",
            {
                "token": TOKEN,
                "path": "rootfs",
                "before": gvalue(child),
                "desired": ledger._metadata_value(desired.mode, desired.uid, desired.gid, desired.size, desired.mtime_ns),
            },
        ),
        ledger.LedgerProposal.create("metadata-observed", {"token": TOKEN, "path": "rootfs", "child": gvalue(desired)}),
        ledger.LedgerProposal.create("metadata-settled", {"token": TOKEN, "path": "rootfs", "child": gvalue(desired)}),
    ]
    metadata_records = ledger._parse_ledger(encoded(created_proposals + metadata))
    desired_observations = dataclasses.replace(created_observations, entries=(("rootfs", desired),))
    assert ledger._reconcile_ledger(metadata_records, desired_observations).status == "active"

    remove_intent = ledger.LedgerProposal.create(
        "remove-intent",
        {
            "token": TOKEN,
            "path": "rootfs",
            "kind": "directory",
            "parent": pvalue(operation_parent_after),
            "child": gvalue(desired),
            "target_path": None,
        },
    )
    remove_intent_records = ledger._parse_ledger(encoded(created_proposals + metadata + [remove_intent]))
    remove_present = dataclasses.replace(desired_observations, parents=(("", operation_parent_after),))
    remove_absent = dataclasses.replace(observations, parents=(("", operation_parent_before),))
    assert ledger._reconcile_ledger(remove_intent_records, remove_present).status == "remove-retry"
    remove_absent_state = ledger._reconcile_ledger(remove_intent_records, remove_absent)
    assert remove_absent_state.status == "remove-absence-settleable", remove_absent_state
    remove_observed = ledger.LedgerProposal.create(
        "remove-observed",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_parent_before), "target_path": None, "target": None},
    )
    remove_settled = ledger.LedgerProposal.create(
        "remove-settled",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_parent_before), "target_path": None, "target": None},
    )
    removed_proposals = created_proposals + metadata + [remove_intent, remove_observed, remove_settled]
    removed = ledger._parse_ledger(encoded(removed_proposals))
    assert ledger._reconcile_ledger(removed, observations).status == "active"

    operation_name = ledger._operation_name(TOKEN)
    remove_operation = ledger.LedgerProposal.create(
        "operation-remove-intent",
        {"token": TOKEN, "operation_name": operation_name, "state_parent": pvalue(state_after), "operation": gvalue(operation)},
    )
    operation_absent_parent = parent(1, ("active-ledger", "lock", "sentinel"), ctime=3)
    operation_absent = ledger.LedgerProposal.create(
        "operation-absent",
        {"token": TOKEN, "operation_name": operation_name, "state_parent": pvalue(operation_absent_parent)},
    )
    remove_operation_records = ledger._parse_ledger(encoded(removed_proposals + [remove_operation]))
    assert ledger._reconcile_ledger(remove_operation_records, observations).status == "operation-remove-retry"
    absent_operation_observation = ledger.ReconcileObservations(operation_absent_parent, (), ())
    assert ledger._reconcile_ledger(remove_operation_records, absent_operation_observation).status == "operation-absence-settleable"
    absent_records = ledger._parse_ledger(encoded(removed_proposals + [remove_operation, operation_absent]))
    assert ledger._reconcile_ledger(absent_records, ledger.ReconcileObservations(operation_absent_parent, (), ())).status == "retirable"
    retired = ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(operation_absent_parent)})
    retired_records = ledger._parse_ledger(encoded(removed_proposals + [remove_operation, operation_absent, retired]))
    assert ledger._reconcile_ledger(retired_records, ledger.ReconcileObservations(operation_absent_parent, (), ())).status == "retired"

    target = generation(30, "file", 0o644, 1, 7, mtime=5_000_000_000)
    linked = dataclasses.replace(target, nlink=2, ctime_ns=2)
    link_parent_before = parent(2, ())
    link_parent_after = parent(2, ("alias",), ctime=2)
    hardlink_records = [
        ledger.LedgerProposal.create(
            "hardlink-group",
            {"token": TOKEN, "target_path": "target", "aliases": ["alias"], "content_sha256": "d" * 64, "target": gvalue(target)},
        ),
        ledger.LedgerProposal.create(
            "hardlink-create-intent",
            {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target": gvalue(target), "parent": pvalue(link_parent_before)},
        ),
        ledger.LedgerProposal.create(
            "hardlink-create-observed",
            {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked), "alias_generation": gvalue(linked), "parent": pvalue(link_parent_after)},
        ),
        ledger.LedgerProposal.create(
            "hardlink-create-settled",
            {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked), "alias_generation": gvalue(linked), "parent": pvalue(link_parent_after)},
        ),
        ledger.LedgerProposal.create(
            "remove-intent",
            {"token": TOKEN, "path": "alias", "kind": "hardlink", "parent": pvalue(link_parent_after), "child": gvalue(linked), "target_path": "target"},
        ),
        ledger.LedgerProposal.create(
            "remove-observed",
            {"token": TOKEN, "path": "alias", "kind": "hardlink", "parent": pvalue(link_parent_before), "target_path": "target", "target": gvalue(target)},
        ),
        ledger.LedgerProposal.create(
            "remove-settled",
            {"token": TOKEN, "path": "alias", "kind": "hardlink", "parent": pvalue(link_parent_before), "target_path": "target", "target": gvalue(target)},
        ),
    ]
    ledger._parse_ledger(encoded(proposals + hardlink_records))
    wrong_alias = dataclasses.replace(hardlink_records[1], body=ledger.LedgerProposal.create(
        "hardlink-create-intent",
        {"token": TOKEN, "target_path": "target", "alias": "other", "index": 0, "target": gvalue(target), "parent": pvalue(link_parent_before)},
    ).body)
    rejected(lambda: ledger._parse_ledger(encoded(proposals + [hardlink_records[0], wrong_alias])))

    uncertain = proposals + [ledger.LedgerProposal.create("uncertain", {"token": TOKEN, "reason": "incomplete"})]
    assert ledger._reconcile_ledger(ledger._parse_ledger(encoded(uncertain)), observations).status == "preserve"


def hostile_codec_tests():
    proposals, _state_before, _state_after, _operation = lifecycle_prefix()
    raw = encoded(proposals)
    cases = [
        raw[:-1],
        raw + b"\n",
        raw.replace(b'"sequence":0', b'"sequence":true', 1),
        raw.replace(b'"previous_offset":"0000000000000000"', b'"previous_offset":"0000000000000001"', 1),
        raw.replace(b'"previous_sha256":"' + b"0" * 64 + b'"', b'"previous_sha256":"' + b"f" * 64 + b'"', 1),
        raw.replace(b'"record_type":"genesis"', b'"record_type":"unknown"', 1),
        raw.replace(b'"version":', b'"extra":0,"version":', 1),
        raw.replace(b'"token":', b'"token":"' + TOKEN.encode() + b'","token":', 1),
        b"x" * (ledger.MAX_LEDGER_BYTES + 1),
    ]
    for value in cases:
        rejected(lambda value=value: ledger._parse_ledger(value))
    first_line = raw.splitlines(keepends=True)[0]
    value = json.loads(first_line)
    value["next_offset"] = "0" * ledger.OFFSET_WIDTH
    rejected(lambda: ledger._parse_ledger(json.dumps(value, separators=(",", ":")).encode() + b"\n"))
    rejected(lambda: ledger.LedgerProposal.create("uncertain", {"token": TOKEN, "reason": "other"}))
    rejected(lambda: ledger.LedgerProposal.create("genesis", {**genesis_body(parent(1, ())), "source_revision": True}))
    rejected(lambda: ledger._encode_proposal(ledger.LedgerProposal("unknown", ledger.FrozenObject(())), ledger.INITIAL_BYTES))
    rejected(lambda: ledger._parse_ledger(encoded([proposals[0], proposals[2]])))
    bad_observed = ledger.LedgerProposal.create(
        "operation-create-observed",
        {
            "token": TOKEN,
            "operation_name": ledger._operation_name(TOKEN),
            "state_parent": pvalue(_state_before),
            "operation": gvalue(_operation),
        },
    )
    rejected(lambda: ledger._parse_ledger(encoded(proposals[:3] + [bad_observed])))


def snapshot(inode, names, ctime=1):
    names = tuple(sorted(names))
    checked = tuple(fs._name(name) for name in names)
    children = tuple((name, generation(index + 100)) for index, name in enumerate(checked))
    return fs.DirectorySnapshot(generation(inode, ctime=ctime), checked, children)


def hardlink_tests():
    plan = ledger.HardlinkPlan("target", ("alias",), 0o644, 0, 0, 5, 7, "d" * 64)
    target = generation(10, "file", 0o644, 1, 7, ctime=1, mtime=5_000_000_000)
    state = ledger._new_hardlink_group(plan, target, "d" * 64)
    after = dataclasses.replace(target, nlink=2)
    create_delta = fs.ParentDelta("hardlink", fs._name("alias"), snapshot(20, ()), snapshot(20, ("alias",), 2))
    transition = ledger._hardlink_transition(state, "create", 0, target, after, after, create_delta, "d" * 64)
    state = ledger._settle_hardlink(state, transition)
    assert state.target.nlink == 2 and state.settled_aliases == ("alias",)

    removed = dataclasses.replace(after, nlink=1, ctime_ns=after.ctime_ns)
    remove_delta = fs.ParentDelta("unlink", fs._name("alias"), snapshot(20, ("alias",), 2), snapshot(20, (), 3))
    transition = ledger._hardlink_transition(state, "remove", 0, after, removed, after, remove_delta, "d" * 64)
    state = ledger._settle_hardlink(state, transition)
    assert state.target.nlink == 1 and state.removed_aliases == ("alias",)

    fresh = lambda: ledger._new_hardlink_group(plan, target, "d" * 64)
    rejected(lambda: ledger._new_hardlink_group(plan, target, "e" * 64))
    rejected(lambda: ledger._hardlink_transition(fresh(), "create", 0, target, dataclasses.replace(target, nlink=3), dataclasses.replace(target, nlink=3), create_delta, "d" * 64))
    rejected(lambda: ledger._hardlink_transition(fresh(), "create", 1, target, after, after, create_delta, "d" * 64))
    rejected(lambda: ledger._hardlink_transition(fresh(), "create", 0, target, dataclasses.replace(after, mode=0o600), dataclasses.replace(after, mode=0o600), create_delta, "d" * 64))
    rejected(lambda: ledger._hardlink_transition(fresh(), "create", 0, target, after, after, create_delta, "e" * 64))


def writer_tests():
    with tempfile.TemporaryFile() as file:
        identity_fd = fs.CheckedFd(os.dup(file.fileno()), "test-identity")
        operation_fd = fs.CheckedFd(os.dup(file.fileno()), "test-operation")
        observed = os.fstat(operation_fd.number)
        key = fs.HostKey(1, observed.st_dev, observed.st_ino, "file")

        def observe(_identity, operation, _control):
            current = os.fstat(operation.number)
            return fs.HostGeneration(key, 0o600, 0, 0, 1, current.st_size, current.st_mtime_ns, current.st_ctime_ns)

        real_observe = ledger._observe_node
        real_xattrs = ledger._require_empty_fd_xattrs
        real_write = ledger.os.write
        ledger._observe_node = observe
        ledger._require_empty_fd_xattrs = lambda _node, _control: None
        try:
            initial = observe(identity_fd, operation_fd, control())
            node = fs.HeldNode(identity_fd, operation_fd, initial)
            state = ledger.LedgerWriterState(node, key, ledger.INITIAL_BYTES, initial)
            proposal = ledger.LedgerProposal.create("genesis", genesis_body(parent(1, ("active-ledger",))))
            ledger.os.write = lambda _fd, _raw: 0
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.fstat(operation_fd.number).st_size == 0
            ledger.os.write = lambda fd, raw: real_write(fd, raw[:7])
            state = ledger._append_record(state, proposal, control())
            raw = os.pread(operation_fd.number, state.settled.offset, 0)
            assert ledger._parse_ledger(raw)[0].record_type == "genesis"
            assert state.settled.offset == len(raw)
            os.lseek(operation_fd.number, 0, os.SEEK_SET)
            rejected(lambda: ledger._append_record(state, proposal, control()))
        finally:
            ledger.os.write = real_write
            ledger._observe_node = real_observe
            ledger._require_empty_fd_xattrs = real_xattrs
            identity_fd.close()
            operation_fd.close()


def static_tests():
    source = (REMOTE / "completion_rootfs_ledger.py").read_text()
    for forbidden in ("os.mkdir", "os.makedirs", "os.open", "os.unlink", "os.remove", "os.rmdir", "os.rename", "subprocess", "socket", "argparse", "sys.argv", "if __name__"):
        assert forbidden not in source
    assert "os.write" in source and "os.fsync" in source
    assert "MAX_LEDGER_BYTES" in source and "genesis-abort" in source and "operation-abort" in source


codec_and_reconcile_tests()
hostile_codec_tests()
hardlink_tests()
writer_tests()
static_tests()
print("completion rootfs ledger tests passed")

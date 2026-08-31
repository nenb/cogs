#!/usr/bin/env python3
"""Hostile codec, reconciliation, writer, and hardlink tests for D-R2.2b."""

import dataclasses
import hashlib
import importlib.util
import inspect
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
builder = load("completion_rootfs_builder_ledger_test", REMOTE / "completion_rootfs_builder.py")
RECONCILE_EMISSIONS = set()
ENCODED_CASES = []
_reconcile = ledger._reconcile_ledger


def recording_reconcile(records, observations):
    state = _reconcile(records, observations)
    RECONCILE_EMISSIONS.add((state.status, state.cleanup_origin, state.cleanup_allowed))
    return state


ledger._reconcile_ledger = recording_reconcile
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


def ledger_file(size=1):
    return generation(99, "file", 0o600, 1, size)


def pvalue(value):
    return ledger._parent_value(value)


def gvalue(value):
    return ledger._generation_value(value)


def candidate_records(operation):
    before = ledger.LedgerParent(operation, ())
    after = ledger.LedgerParent(dataclasses.replace(operation, ctime_ns=2), (ledger.CANDIDATE_TAR_PATH,))
    anonymous = generation(70, "file", 0o600, 0, ledger.CANDIDATE_TAR_SIZE, ctime=10)
    linked = dataclasses.replace(anonymous, nlink=1, ctime_ns=11)
    intent_body = {
        "token": TOKEN, "path": ledger.CANDIDATE_TAR_PATH, "parent": pvalue(before),
        "anonymous": gvalue(anonymous), "size": ledger.CANDIDATE_TAR_SIZE, "sha256": "7" * 64,
    }
    observed_body = {
        "token": TOKEN, "path": ledger.CANDIDATE_TAR_PATH, "parent": pvalue(after),
        "anonymous": gvalue(anonymous), "linked": gvalue(linked),
        "size": ledger.CANDIDATE_TAR_SIZE, "sha256": "7" * 64,
    }
    return (
        ledger.LedgerProposal.create("candidate-tar-intent", intent_body),
        ledger.LedgerProposal.create("candidate-tar-abort", intent_body),
        ledger.LedgerProposal.create("candidate-tar-observed", observed_body),
        ledger.LedgerProposal.create("candidate-tar-settled", observed_body),
        before, after, anonymous, linked,
    )


def mutate_encoded(proposals, index, mutate):
    values = [json.loads(line) for line in encoded(proposals).splitlines()]
    mutate(values[index]["body"])
    chunks = []
    settled = ledger.INITIAL_BYTES
    for sequence, value in enumerate(values):
        value.update({
            "sequence": sequence, "previous_sequence": settled.sequence,
            "previous_offset": f"{settled.offset:0{ledger.OFFSET_WIDTH}d}",
            "previous_sha256": settled.line_sha256, "next_offset": "0" * ledger.OFFSET_WIDTH,
        })
        placeholder = ledger._canonical_line(value)
        value["next_offset"] = f"{settled.offset + len(placeholder):0{ledger.OFFSET_WIDTH}d}"
        line = ledger._canonical_line(value)
        chunks.append(line)
        settled = ledger.SettledBytes(sequence, settled.offset + len(line), hashlib.sha256(line).hexdigest())
    return b"".join(chunks)


def genesis_body(state_parent):
    return {
        "token": TOKEN,
        "source_revision": REVISION,
        "source_manifest_sha256": MANIFEST,
        "state_parent": pvalue(state_parent),
        "ledger_key": {"mount_id": 1, "device": 1, "inode": 99, "kind": "file"},
    }


def lifecycle_prefix(operation_size=0):
    ledger_name = "active-ledger"
    operation_name = ledger._operation_name(TOKEN)
    state_before = parent(1, (ledger_name, "lock", "sentinel"))
    state_after = parent(1, (ledger_name, "lock", operation_name, "sentinel"), ctime=2)
    operation = generation(2, size=operation_size)
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
    raw = b"".join(chunks)
    ENCODED_CASES.append(raw)
    return raw


def next_record(history, proposal):
    raw = ledger._encode_proposal(proposal, history.legal.settled)
    settled = history.legal.settled
    return ledger.LedgerRecord(
        settled.sequence + 1, settled.sequence, settled.offset, settled.line_sha256,
        settled.offset + len(raw), proposal.record_type, proposal.body, hashlib.sha256(raw).hexdigest(),
    )


def codec_and_reconcile_tests():
    proposals, state_before, state_after, operation = lifecycle_prefix()
    active_raw = encoded(proposals)
    active = ledger._parse_ledger(active_raw)
    active_history = ledger._parse_ledger_history(active_raw)
    assert active_history.legal.state_parent == state_after
    assert active_history.legal.operation_parent == ledger.LedgerParent(operation, ())
    observations = ledger.ReconcileObservations(state_after, ((ledger._operation_name(TOKEN), operation),), (), ledger_file())
    genesis_only = ledger._parse_ledger(encoded(proposals[:1]))
    assert ledger._reconcile_ledger(genesis_only, ledger.ReconcileObservations(state_before, (), (), ledger_file())).status == "genesis-settleable"
    operation_observed = ledger._parse_ledger(encoded(proposals[:4]))
    assert ledger._reconcile_ledger(operation_observed, observations).status == "operation-create-settleable"
    assert len(active) == 5 and active[-1].record_type == "operation-create-settled"
    state = ledger._reconcile_ledger(active, observations)
    assert state.status == "active" and state.cleanup_allowed

    intent, abort, observed, settled, candidate_before, candidate_after, anonymous, linked = candidate_records(operation)
    abort_raw = encoded(proposals + [intent, abort])
    abort_history = ledger._parse_ledger_history(abort_raw)
    assert ledger._parse_ledger(abort_raw) == ledger._history_records(abort_history)
    assert abort_history.legal.phase == "active" and abort_history.legal.operation_parent == candidate_before
    linked_raw = encoded(proposals + [intent, observed, settled])
    linked_history = ledger._parse_ledger_history(linked_raw)
    linked_records = ledger._parse_ledger(linked_raw)
    assert linked_records == ledger._history_records(linked_history)
    assert linked_history.legal.phase == "active" and linked_history.legal.operation_parent == candidate_after
    intent_records = ledger._parse_ledger(encoded(proposals + [intent]))
    absent_candidate = dataclasses.replace(observations, parents=(("", candidate_before),))
    candidate_state = ledger._reconcile_ledger(intent_records, absent_candidate)
    assert (candidate_state.status, candidate_state.owned) == ("candidate-tar-abortable", ())
    linked_candidate = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), candidate_after.generation),),
        ((ledger.CANDIDATE_TAR_PATH, linked),), ledger_file(), (("", candidate_after),),
        (ledger.CANDIDATE_TAR_SIZE, "7" * 64),
    )
    candidate_state = ledger._reconcile_ledger(intent_records, linked_candidate)
    assert (candidate_state.status, candidate_state.owned) == ("candidate-tar-observeable", ())
    observed_records = ledger._parse_ledger(encoded(proposals + [intent, observed]))
    candidate_state = ledger._reconcile_ledger(observed_records, linked_candidate)
    assert (candidate_state.status, candidate_state.owned) == ("candidate-tar-settleable", ())
    settled_state = ledger._reconcile_ledger(linked_records, linked_candidate)
    assert settled_state.status == "active"
    assert settled_state.owned == ((ledger.CANDIDATE_TAR_PATH, linked),)
    assert ledger._replay_graph(linked_records)[1:3] == (
        candidate_after.generation, {ledger.CANDIDATE_TAR_PATH: linked},
    )
    candidate_mismatches = (
        dataclasses.replace(absent_candidate, candidate_tar=(ledger.CANDIDATE_TAR_SIZE, "7" * 64)),
        dataclasses.replace(linked_candidate, entries=()),
        dataclasses.replace(linked_candidate, entries=(("other", linked),)),
        dataclasses.replace(linked_candidate, entries=((ledger.CANDIDATE_TAR_PATH, dataclasses.replace(
            linked, key=dataclasses.replace(linked.key, inode=71),
        )),)),
        dataclasses.replace(linked_candidate, candidate_tar=(ledger.CANDIDATE_TAR_SIZE - 1, None)),
        dataclasses.replace(linked_candidate, candidate_tar=(ledger.CANDIDATE_TAR_SIZE, "8" * 64)),
        dataclasses.replace(linked_candidate, parents=(("", candidate_before),)),
        dataclasses.replace(linked_candidate, operations=observations.operations),
        dataclasses.replace(linked_candidate, ledger_generation=generation(100, "file", 0o600, 1, 1)),
        dataclasses.replace(linked_candidate, state_parent=parent(1, (*state_after.names, "other"), ctime=3)),
    )
    for hostile in candidate_mismatches:
        assert ledger._reconcile_ledger(intent_records, hostile).status == "preserve"
        assert ledger._reconcile_ledger(observed_records, hostile).status == "preserve"

    genesis = proposals[:2]
    ready = ledger._parse_ledger(encoded(genesis))
    assert ledger._reconcile_ledger(ready, ledger.ReconcileObservations(state_before, (), (), ledger_file())).status == "genesis-abortable"
    drifted_parent = parent(1, state_before.names, ctime=2)
    mismatched_genesis_abort = genesis + [
        ledger.LedgerProposal.create("genesis-abort", {"token": TOKEN, "state_parent": pvalue(drifted_parent)}),
    ]
    rejected(lambda: ledger._parse_ledger(encoded(mismatched_genesis_abort)))
    genesis_abort_prefix = genesis + [
        ledger.LedgerProposal.create("genesis-abort", {"token": TOKEN, "state_parent": pvalue(state_before)}),
    ]
    genesis_aborted = ledger._parse_ledger(encoded(genesis_abort_prefix))
    exact_absence = ledger.ReconcileObservations(state_before, (), (), ledger_file())
    state = ledger._reconcile_ledger(genesis_aborted, exact_absence)
    assert (state.status, state.cleanup_origin, state.cleanup_allowed) == ("retirable", "prelease", True)
    mismatched_genesis_retired = genesis_abort_prefix + [
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(drifted_parent)}),
    ]
    rejected(lambda: ledger._parse_ledger(encoded(mismatched_genesis_retired)))
    genesis_abort = genesis_abort_prefix + [
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(state_before)}),
    ]
    assert ledger._reconcile_ledger(
        ledger._parse_ledger(encoded(genesis_abort)), exact_absence,
    ).status == "retired"

    operation_intent = proposals[:3]
    drifted_operation_intent = list(operation_intent)
    drifted_operation_intent[-1] = ledger.LedgerProposal.create(
        "operation-create-intent",
        {
            "token": TOKEN, "operation_name": ledger._operation_name(TOKEN),
            "state_parent": pvalue(drifted_parent),
        },
    )
    rejected(lambda: ledger._parse_ledger(encoded(drifted_operation_intent)))
    intent_records = ledger._parse_ledger(encoded(operation_intent))
    assert ledger._reconcile_ledger(intent_records, exact_absence).status == "operation-abortable"
    assert ledger._reconcile_ledger(intent_records, observations).status == "preserve"
    mismatched_operation_abort = operation_intent + [
        ledger.LedgerProposal.create(
            "operation-abort",
            {"token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "state_parent": pvalue(drifted_parent)},
        ),
    ]
    rejected(lambda: ledger._parse_ledger(encoded(mismatched_operation_abort)))
    operation_abort_prefix = operation_intent + [
        ledger.LedgerProposal.create(
            "operation-abort",
            {"token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "state_parent": pvalue(state_before)},
        ),
    ]
    operation_aborted = ledger._parse_ledger(encoded(operation_abort_prefix))
    state = ledger._reconcile_ledger(operation_aborted, exact_absence)
    assert (state.status, state.cleanup_origin, state.cleanup_allowed) == ("retirable", "prelease", True)
    mismatched_operation_retired = operation_abort_prefix + [
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(drifted_parent)}),
    ]
    rejected(lambda: ledger._parse_ledger(encoded(mismatched_operation_retired)))
    operation_abort = operation_abort_prefix + [
        ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(state_before)}),
    ]
    assert ledger._reconcile_ledger(
        ledger._parse_ledger(encoded(operation_abort)), exact_absence,
    ).status == "retired"

    abort_drift = (
        dataclasses.replace(exact_absence, state_parent=drifted_parent),
        dataclasses.replace(exact_absence, state_parent=parent(1, (*state_before.names, "unknown"), ctime=2)),
        dataclasses.replace(exact_absence, operations=((ledger._operation_name(TOKEN), operation),)),
        dataclasses.replace(exact_absence, entries=(("unknown", generation(50, "file", 0o600, 1)),)),
        dataclasses.replace(exact_absence, ledger_generation=generation(100, "file", 0o600, 1, 1)),
    )
    for aborted in (genesis_aborted, operation_aborted):
        for hostile in abort_drift:
            preserved = ledger._reconcile_ledger(aborted, hostile)
            assert (preserved.status, preserved.cleanup_origin, preserved.cleanup_allowed) == (
                "preserve", "none", False,
            )
    assert ledger._reconcile_ledger(active, ledger.ReconcileObservations(state_before, observations.operations, (), ledger_file())).status == "preserve"

    operation_parent_before = parent(2, ())
    operation_parent_after = parent(2, ("rootfs",), ctime=2)
    drifted_first_parent = parent(2, (), ctime=999)
    hostile_first_intent = ledger.LedgerProposal.create(
        "create-intent",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(drifted_first_parent)},
    )
    rejected(lambda: ledger._parse_ledger(encoded(proposals + [hostile_first_intent])))
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
    create_abort = ledger.LedgerProposal.create("create-abort", create_intent.body_value())
    aborted_create = ledger._parse_ledger(encoded(proposals + [create_intent, create_abort]))
    assert ledger._reconcile_ledger(aborted_create, absent_observations).status == "active"
    assert ledger._reconcile_ledger(create_intent_records, dataclasses.replace(absent_observations, entries=(("rootfs", child),))).status == "preserve"
    created_proposals = proposals + [create_intent, create_observed, create_settled]
    created = ledger._parse_ledger(encoded(created_proposals))
    drifted_next_parent = parent(2, operation_parent_after.names, ctime=99)
    discontinuous_sibling = ledger.LedgerProposal.create(
        "create-intent",
        {"token": TOKEN, "path": "sibling", "kind": "file", "parent": pvalue(drifted_next_parent)},
    )
    rejected(lambda: ledger._parse_ledger(encoded(created_proposals + [discontinuous_sibling])))
    operation_after_create = operation_parent_after.generation
    created_observations = dataclasses.replace(
        observations,
        operations=((ledger._operation_name(TOKEN), operation_after_create),),
        entries=(("rootfs", child),),
        parents=(("", operation_parent_after),),
    )
    assert ledger._reconcile_ledger(created, created_observations).status == "active"
    observed_only = ledger._parse_ledger(encoded(proposals + [create_intent, create_observed]))
    assert ledger._reconcile_ledger(observed_only, created_observations).status == "create-settleable"

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
    metadata_observed = ledger._parse_ledger(encoded(created_proposals + metadata[:2]))
    assert ledger._reconcile_ledger(metadata_observed, desired_observations).status == "metadata-settleable"

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
    remove_observed_records = ledger._parse_ledger(encoded(created_proposals + metadata + [remove_intent, remove_observed]))
    assert ledger._reconcile_ledger(remove_observed_records, dataclasses.replace(observations, parents=(("", operation_parent_before),))).status == "remove-settleable"

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
    absent_operation_observation = ledger.ReconcileObservations(operation_absent_parent, (), (), ledger_file())
    assert ledger._reconcile_ledger(remove_operation_records, absent_operation_observation).status == "operation-absence-settleable"
    absent_records = ledger._parse_ledger(encoded(removed_proposals + [remove_operation, operation_absent]))
    assert ledger._reconcile_ledger(absent_records, ledger.ReconcileObservations(operation_absent_parent, (), (), ledger_file())).status == "retirable"
    retired = ledger.LedgerProposal.create("retired", {"token": TOKEN, "state_parent": pvalue(operation_absent_parent)})
    retired_records = ledger._parse_ledger(encoded(removed_proposals + [remove_operation, operation_absent, retired]))
    assert ledger._reconcile_ledger(retired_records, ledger.ReconcileObservations(operation_absent_parent, (), (), ledger_file())).status == "retired"

    target = generation(30, "file", 0o644, 1, 7, mtime=5_000_000_000)
    linked = dataclasses.replace(target, nlink=2, ctime_ns=2)
    link_parent_before = parent(2, ())
    link_parent_after = parent(2, ("alias",), ctime=2)
    target_parent = parent(2, ("target",), ctime=2)
    alias_parent = parent(2, ("alias", "target"), ctime=3)
    target_create = [
        ledger.LedgerProposal.create("create-intent", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(link_parent_before)}),
        ledger.LedgerProposal.create("create-observed", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
        ledger.LedgerProposal.create("create-settled", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
    ]
    hardlink_create = [
        ledger.LedgerProposal.create("hardlink-group", {"token": TOKEN, "target_path": "target", "aliases": ["alias"], "content_sha256": "d" * 64, "target": gvalue(target)}),
        ledger.LedgerProposal.create("hardlink-create-intent", {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target": gvalue(target), "parent": pvalue(target_parent)}),
        ledger.LedgerProposal.create("hardlink-create-observed", {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked), "alias_generation": gvalue(linked), "parent": pvalue(alias_parent)}),
    ]
    linked_observations = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), alias_parent.generation),),
        (("alias", linked), ("target", linked)), ledger_file(), (("", alias_parent),),
    )
    hardlink_observed = ledger._parse_ledger(encoded(proposals + target_create + hardlink_create))
    assert ledger._reconcile_ledger(hardlink_observed, linked_observations).status == "hardlink-create-settleable"
    hardlink_settled = ledger.LedgerProposal.create("hardlink-create-settled", hardlink_create[-1].body_value())
    hardlink_remove = ledger.LedgerProposal.create(
        "remove-intent", {"token": TOKEN, "path": "alias", "kind": "hardlink", "parent": pvalue(alias_parent), "child": gvalue(linked), "target_path": "target"},
    )
    hardlink_removing = ledger._parse_ledger(encoded(proposals + target_create + hardlink_create + [hardlink_settled, hardlink_remove]))
    target_only = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), target_parent.generation),),
        (("target", target),), ledger_file(), (("", target_parent),),
    )
    assert ledger._reconcile_ledger(hardlink_removing, target_only).status == "hardlink-remove-absence-settleable"

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
    complete_hardlink_records = ledger._parse_ledger(encoded(proposals + hardlink_records))
    assert builder._settled_hardlink_groups(complete_hardlink_records) == (("target", ()),)
    group_only = ledger._parse_ledger(encoded(proposals + hardlink_records[:1]))
    assert builder._settled_hardlink_groups(group_only) == (("target", ()),)
    intent_only = ledger._parse_ledger(encoded(proposals + hardlink_records[:2]))
    observed_only = ledger._parse_ledger(encoded(proposals + hardlink_records[:3]))
    assert builder._settled_hardlink_groups(intent_only) == builder._settled_hardlink_groups(observed_only) == (("target", ()),)
    assert ledger._reconcile_ledger(observed_only, observations).status == "preserve"
    settled_prefix = ledger._parse_ledger(encoded(proposals + hardlink_records[:4]))
    assert builder._settled_hardlink_groups(settled_prefix) == (("target", ("alias",)),)
    hardlink_abort = ledger.LedgerProposal.create("hardlink-create-abort", hardlink_records[1].body_value())
    aborted_hardlink = ledger._parse_ledger(encoded(proposals + hardlink_records[:2] + [hardlink_abort]))
    assert ledger._reconcile_ledger(aborted_hardlink, observations).status == "active"
    wrong_alias = dataclasses.replace(hardlink_records[1], body=ledger.LedgerProposal.create(
        "hardlink-create-intent",
        {"token": TOKEN, "target_path": "target", "alias": "other", "index": 0, "target": gvalue(target), "parent": pvalue(link_parent_before)},
    ).body)
    rejected(lambda: ledger._parse_ledger(encoded(proposals + [hardlink_records[0], wrong_alias])))

    uncertain = proposals + [ledger.LedgerProposal.create("uncertain", {"token": TOKEN, "reason": "incomplete"})]
    assert ledger._reconcile_ledger(ledger._parse_ledger(encoded(uncertain)), observations).status == "preserve"


def multi_alias_replay_tests():
    proposals, _state_before, state_after, _operation = lifecycle_prefix()
    before = parent(2, ())
    target_parent = parent(2, ("target",), ctime=2)
    first_parent = parent(2, ("alias-one", "target"), ctime=3)
    second_parent = parent(2, ("alias-one", "alias-two", "target"), ctime=4)
    target = generation(30, "file", 0o644, 1, 7)
    linked_two = dataclasses.replace(target, nlink=2, ctime_ns=2)
    linked_three = dataclasses.replace(target, nlink=3, ctime_ns=3)
    values = proposals + [
        ledger.LedgerProposal.create("create-intent", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(before)}),
        ledger.LedgerProposal.create("create-observed", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
        ledger.LedgerProposal.create("create-settled", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
        ledger.LedgerProposal.create("hardlink-group", {"token": TOKEN, "target_path": "target", "aliases": ["alias-one", "alias-two"], "content_sha256": "d" * 64, "target": gvalue(target)}),
        ledger.LedgerProposal.create("hardlink-create-intent", {"token": TOKEN, "target_path": "target", "alias": "alias-one", "index": 0, "target": gvalue(target), "parent": pvalue(target_parent)}),
        ledger.LedgerProposal.create("hardlink-create-observed", {"token": TOKEN, "target_path": "target", "alias": "alias-one", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked_two), "alias_generation": gvalue(linked_two), "parent": pvalue(first_parent)}),
        ledger.LedgerProposal.create("hardlink-create-settled", {"token": TOKEN, "target_path": "target", "alias": "alias-one", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked_two), "alias_generation": gvalue(linked_two), "parent": pvalue(first_parent)}),
        ledger.LedgerProposal.create("hardlink-create-intent", {"token": TOKEN, "target_path": "target", "alias": "alias-two", "index": 1, "target": gvalue(linked_two), "parent": pvalue(first_parent)}),
        ledger.LedgerProposal.create("hardlink-create-observed", {"token": TOKEN, "target_path": "target", "alias": "alias-two", "index": 1, "target_before": gvalue(linked_two), "target_after": gvalue(linked_three), "alias_generation": gvalue(linked_three), "parent": pvalue(second_parent)}),
        ledger.LedgerProposal.create("hardlink-create-settled", {"token": TOKEN, "target_path": "target", "alias": "alias-two", "index": 1, "target_before": gvalue(linked_two), "target_after": gvalue(linked_three), "alias_generation": gvalue(linked_three), "parent": pvalue(second_parent)}),
    ]
    second_observed = ledger._parse_ledger(encoded(values[:-1]))
    second_observations = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), second_parent.generation),),
        (("alias-one", linked_three), ("alias-two", linked_three), ("target", linked_three)),
        ledger_file(), (("", second_parent),),
    )
    assert ledger._reconcile_ledger(second_observed, second_observations).status == "hardlink-create-settleable"
    records = ledger._parse_ledger(encoded(values))
    _state, operation, owned, consistent = ledger._replay_graph(records)
    assert consistent and operation == second_parent.generation
    assert owned == {"alias-one": linked_three, "alias-two": linked_three, "target": linked_three}
    observations = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), second_parent.generation),), tuple(owned.items()),
        ledger_file(), (("", second_parent),),
    )
    assert ledger._reconcile_ledger(records, observations).status == "active"

    current_parent = second_parent
    current_target = linked_three
    current = values
    for alias, after_parent, after_target in (
        ("alias-two", first_parent, linked_two), ("alias-one", target_parent, target),
    ):
        intent = ledger.LedgerProposal.create("remove-intent", {
            "token": TOKEN, "path": alias, "kind": "hardlink", "parent": pvalue(current_parent),
            "child": gvalue(current_target), "target_path": "target",
        })
        observed = ledger.LedgerProposal.create("remove-observed", {
            "token": TOKEN, "path": alias, "kind": "hardlink", "parent": pvalue(after_parent),
            "target_path": "target", "target": gvalue(after_target),
        })
        remaining = {path: after_target for path in ({"alias-one", "target"} if alias == "alias-two" else {"target"})}
        absent_observations = ledger.ReconcileObservations(
            state_after, ((ledger._operation_name(TOKEN), after_parent.generation),), tuple(remaining.items()),
            ledger_file(), (("", after_parent),),
        )
        intent_records = ledger._parse_ledger(encoded(current + [intent]))
        assert ledger._reconcile_ledger(intent_records, absent_observations).status == "hardlink-remove-absence-settleable"
        observed_records = ledger._parse_ledger(encoded(current + [intent, observed]))
        assert ledger._reconcile_ledger(observed_records, absent_observations).status == "remove-settleable"
        current += [intent, observed, ledger.LedgerProposal.create("remove-settled", observed.body_value())]
        records = ledger._parse_ledger(encoded(current))
        _state, operation, owned, consistent = ledger._replay_graph(records)
        assert consistent and operation == after_parent.generation
        assert all(value == after_target for value in owned.values())
        current_parent, current_target = after_parent, after_target
    assert owned == {"target": target}


def lease_codec_and_origin_tests():
    proposals, _state_before, state_after, operation = lifecycle_prefix()
    operation_before = parent(2, ())
    operation_after = parent(2, ("rootfs",), ctime=2)
    root = generation(3)
    create = [
        ledger.LedgerProposal.create(
            "create-intent",
            {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_before)},
        ),
        ledger.LedgerProposal.create(
            "create-observed",
            {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_after), "child": gvalue(root)},
        ),
        ledger.LedgerProposal.create(
            "create-settled",
            {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_after), "child": gvalue(root)},
        ),
    ]
    operation_current = operation_after.generation
    lease_body = {
        "token": TOKEN,
        "operation_name": ledger._operation_name(TOKEN),
        "state_parent": pvalue(state_after),
        "operation": gvalue(operation_current),
        "root": gvalue(root),
        "ledger_key": {"mount_id": 1, "device": 1, "inode": 99, "kind": "file"},
        "manifest_sha256": "d" * 64,
        "manifest_size": 7,
        "ustar_sha256": "e" * 64,
        "ustar_size": 512,
        "entry_count": 1,
    }
    leased_proposals = proposals + create + [ledger.LedgerProposal.create("leased", lease_body)]
    leased = ledger._parse_ledger(encoded(leased_proposals))
    leased_terminal = leased[-1]
    active_history = ledger._parse_ledger_history(encoded(leased_proposals[:-1]))
    lease_counter_before = fs.structural_counter_snapshot()
    speculative_lease = ledger._advance_history(active_history, leased_terminal)
    lease_counter_delta = fs.structural_counter_delta(lease_counter_before, fs.structural_counter_snapshot())
    assert speculative_lease.legal.phase == "leased"
    assert lease_counter_delta["active_history_record_copies"] == 2 * (active_history.count + 1)
    assert lease_counter_delta["incremental_records"] == 1
    assert lease_counter_delta["complete_legal_folds"] == 0
    observations = ledger.ReconcileObservations(
        state_after,
        ((ledger._operation_name(TOKEN), operation_current),),
        (("rootfs", root),),
        ledger_file(),
        (("", operation_after),),
    )
    state = ledger._reconcile_ledger(leased, observations)
    assert state.status == "leased" and state.cleanup_origin == "none" and not state.cleanup_allowed
    assert state.lease_seen and not state.release_authorized
    assert state.lease_snapshot.root == root and state.lease_snapshot.owned == (("rootfs", root),)
    replaced_ledger = dataclasses.replace(observations, ledger_generation=generation(100, "file", 0o600, 1, 1))
    assert ledger._reconcile_ledger(leased, replaced_ledger).status == "preserve"
    assert ledger._reconcile_ledger(leased, dataclasses.replace(observations, entries=())).status == "preserve"

    authorization = ledger.LedgerProposal.create(
        "release-authorized",
        {
            "token": TOKEN,
            "operation_name": ledger._operation_name(TOKEN),
            "lease_sequence": leased_terminal.sequence,
            "lease_offset": leased_terminal.next_offset,
            "lease_sha256": leased_terminal.line_sha256,
            "kata_operation_token": "f" * 64,
            "kata_ledger_key": {"mount_id": 1, "device": 1, "inode": 101, "kind": "file"},
            "kata_release_sequence": 1,
            "kata_release_offset": 123,
            "kata_release_sha256": "1" * 64,
        },
    )
    authorized_proposals = leased_proposals + [authorization]
    authorized = ledger._parse_ledger(encoded(authorized_proposals))
    state = ledger._reconcile_ledger(authorized, observations)
    assert state.status == "release-authorized" and state.cleanup_origin == "release-authorized" and state.cleanup_allowed
    assert state.lease_seen and state.release_authorized

    infrastructure = {
        "completion_generation": gvalue(generation(200)),
        "completion_names": ["artifacts", "rootfs-v1"],
        "state_generation": None, "entries": [],
    }
    prestage_authorization = ledger.LedgerProposal.create(
        "prestage-release-authorized", {
            "token": TOKEN, "operation_name": ledger._operation_name(TOKEN),
            "lease_sequence": leased_terminal.sequence,
            "lease_offset": leased_terminal.next_offset,
            "lease_sha256": leased_terminal.line_sha256,
            "operation_binding": {"kind": "journal-absent",
                                  "infrastructure": infrastructure},
        })
    prestage_proposals = leased_proposals + [prestage_authorization]
    prestage_records = ledger._parse_ledger(encoded(prestage_proposals))
    prestage_state = ledger._reconcile_ledger(prestage_records, observations)
    assert (prestage_state.status, prestage_state.cleanup_origin,
            prestage_state.cleanup_allowed, prestage_state.release_authorized) == (
                "prestage-release-authorized", "prestage-authorized", True, False)
    prestage_removing = ledger._parse_ledger(encoded(prestage_proposals + [
        ledger.LedgerProposal.create("remove-intent", {
            "token": TOKEN, "path": "rootfs", "kind": "directory",
            "parent": pvalue(operation_after), "child": gvalue(root),
            "target_path": None})]))
    assert ledger._reconcile_ledger(prestage_removing, observations).cleanup_origin == "prestage-authorized"
    rejected(lambda: ledger._parse_ledger(encoded(prestage_proposals + [authorization])))
    rejected(lambda: ledger._parse_ledger(encoded(authorized_proposals + [prestage_authorization])))
    for hostile in (
        {"kind": "journal-absent", "infrastructure": {**infrastructure, "entries": [{
            "name": "unknown", "generation": gvalue(generation(201, "file", 0o600, 1))}]}},
        {"kind": "unadmitted-journal", "operation_token": "f" * 64,
         "journal_key": {"mount_id": 1, "device": 1, "inode": 202, "kind": "file"},
         "journal_generation": gvalue(generation(203, "file", 0o600, 1)),
         "tip_sequence": 1, "tip_offset": 10, "tip_sha256": "2" * 64,
         "phase": "ADMITTED", "infrastructure": infrastructure},
    ):
        rejected(lambda hostile=hostile: ledger.LedgerProposal.create(
            "prestage-release-authorized", {
                **prestage_authorization.body_value(), "operation_binding": hostile}))

    remove_intent = ledger.LedgerProposal.create(
        "remove-intent",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_after), "child": gvalue(root), "target_path": None},
    )
    removing = ledger._parse_ledger(encoded(authorized_proposals + [remove_intent]))
    state = ledger._reconcile_ledger(removing, observations)
    assert state.status == "remove-retry" and state.cleanup_origin == "release-authorized" and state.cleanup_allowed
    authorized_absent = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), operation_before.generation),), (), ledger_file(), (("", operation_before),),
    )
    assert ledger._reconcile_ledger(removing, authorized_absent).status == "remove-absence-settleable"
    remove_observed = ledger.LedgerProposal.create(
        "remove-observed",
        {"token": TOKEN, "path": "rootfs", "kind": "directory", "parent": pvalue(operation_before), "target_path": None, "target": None},
    )
    remove_settled = ledger.LedgerProposal.create("remove-settled", remove_observed.body_value())
    authorized_observed = ledger._parse_ledger(encoded(authorized_proposals + [remove_intent, remove_observed]))
    assert ledger._reconcile_ledger(authorized_observed, authorized_absent).status == "remove-settleable"
    reduced_proposals = authorized_proposals + [remove_intent, remove_observed, remove_settled]
    reduced = ledger._parse_ledger(encoded(reduced_proposals))
    reduced_observations = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), operation_before.generation),), (), ledger_file(), (("", operation_before),)
    )
    state = ledger._reconcile_ledger(reduced, reduced_observations)
    assert state.status == "release-authorized" and state.cleanup_allowed
    assert state.lease_snapshot.root == root and state.lease_snapshot.operation == operation_current

    operation_remove = ledger.LedgerProposal.create(
        "operation-remove-intent",
        {
            "token": TOKEN,
            "operation_name": ledger._operation_name(TOKEN),
            "state_parent": pvalue(state_after),
            "operation": gvalue(operation_before.generation),
        },
    )
    operation_removing = ledger._parse_ledger(encoded(reduced_proposals + [operation_remove]))
    prestage_reduced = prestage_proposals + [remove_intent, remove_observed, remove_settled]
    ledger._parse_ledger(encoded(prestage_reduced + [operation_remove]))
    state = ledger._reconcile_ledger(operation_removing, reduced_observations)
    assert state.status == "operation-remove-retry" and state.cleanup_origin == "release-authorized"
    state_absent = parent(1, ("active-ledger", "lock", "sentinel"), ctime=3)
    absent_observations = ledger.ReconcileObservations(state_absent, (), (), ledger_file())
    state = ledger._reconcile_ledger(operation_removing, absent_observations)
    assert state.status == "operation-absence-settleable" and state.cleanup_origin == "release-authorized"
    assert state.lease_snapshot.operation == operation_current and state.lease_snapshot.root == root
    assert ledger._reconcile_ledger(
        operation_removing,
        dataclasses.replace(absent_observations, ledger_generation=generation(102, "file", 0o600, 1, 1)),
    ).status == "preserve"
    operation_absent = ledger.LedgerProposal.create(
        "operation-absent", {"token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "state_parent": pvalue(state_absent)},
    )
    authorized_absent_records = ledger._parse_ledger(encoded(reduced_proposals + [operation_remove, operation_absent]))
    assert ledger._reconcile_ledger(authorized_absent_records, absent_observations).status == "retirable"
    retired_record = ledger.LedgerProposal.create(
        "retired", {"token": TOKEN, "state_parent": pvalue(state_absent)})
    authorized_retired = ledger._parse_ledger(encoded(
        reduced_proposals + [operation_remove, operation_absent, retired_record]))
    assert ledger._reconcile_ledger(authorized_retired, absent_observations).status == "retired"

    # Every namespace cut under the distinct prestage origin remains restartable.
    assert (ledger._reconcile_ledger(prestage_removing, authorized_absent).status,
            ledger._reconcile_ledger(prestage_removing, authorized_absent).cleanup_origin) == (
                "remove-absence-settleable", "prestage-authorized")
    prestage_observed = ledger._parse_ledger(encoded(
        prestage_proposals + [remove_intent, remove_observed]))
    assert (ledger._reconcile_ledger(prestage_observed, authorized_absent).status,
            ledger._reconcile_ledger(prestage_observed, authorized_absent).cleanup_origin) == (
                "remove-settleable", "prestage-authorized")
    prestage_reduced_records = ledger._parse_ledger(encoded(prestage_reduced))
    assert (ledger._reconcile_ledger(prestage_reduced_records, reduced_observations).status,
            ledger._reconcile_ledger(prestage_reduced_records, reduced_observations).cleanup_origin) == (
                "prestage-release-authorized", "prestage-authorized")
    prestage_operation_removing = ledger._parse_ledger(encoded(
        prestage_reduced + [operation_remove]))
    assert (ledger._reconcile_ledger(prestage_operation_removing, reduced_observations).status,
            ledger._reconcile_ledger(prestage_operation_removing, reduced_observations).cleanup_origin) == (
                "operation-remove-retry", "prestage-authorized")
    assert (ledger._reconcile_ledger(prestage_operation_removing, absent_observations).status,
            ledger._reconcile_ledger(prestage_operation_removing, absent_observations).cleanup_origin) == (
                "operation-absence-settleable", "prestage-authorized")
    prestage_absent = ledger._parse_ledger(encoded(
        prestage_reduced + [operation_remove, operation_absent]))
    assert (ledger._reconcile_ledger(prestage_absent, absent_observations).status,
            ledger._reconcile_ledger(prestage_absent, absent_observations).cleanup_origin) == (
                "retirable", "prestage-authorized")
    prestage_retired = ledger._parse_ledger(encoded(
        prestage_reduced + [operation_remove, operation_absent, retired_record]))
    assert (ledger._reconcile_ledger(prestage_retired, absent_observations).status,
            ledger._reconcile_ledger(prestage_retired, absent_observations).cleanup_origin) == (
                "retired", "prestage-authorized")

    target = generation(30, "file", 0o644, 1, 7, mtime=5_000_000_000)
    linked = dataclasses.replace(target, nlink=2, ctime_ns=2)
    target_parent = parent(2, ("rootfs", "target"), ctime=3)
    alias_parent = parent(2, ("alias", "rootfs", "target"), ctime=4)
    target_create = [
        ledger.LedgerProposal.create("create-intent", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(operation_after)}),
        ledger.LedgerProposal.create("create-observed", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
        ledger.LedgerProposal.create("create-settled", {"token": TOKEN, "path": "target", "kind": "file", "parent": pvalue(target_parent), "child": gvalue(target)}),
        ledger.LedgerProposal.create("hardlink-group", {"token": TOKEN, "target_path": "target", "aliases": ["alias"], "content_sha256": "2" * 64, "target": gvalue(target)}),
        ledger.LedgerProposal.create("hardlink-create-intent", {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target": gvalue(target), "parent": pvalue(target_parent)}),
        ledger.LedgerProposal.create("hardlink-create-observed", {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked), "alias_generation": gvalue(linked), "parent": pvalue(alias_parent)}),
        ledger.LedgerProposal.create("hardlink-create-settled", {"token": TOKEN, "target_path": "target", "alias": "alias", "index": 0, "target_before": gvalue(target), "target_after": gvalue(linked), "alias_generation": gvalue(linked), "parent": pvalue(alias_parent)}),
    ]
    hardlink_lease_body = dict(lease_body, operation=gvalue(alias_parent.generation))
    hardlink_leased_proposals = proposals + create + target_create + [ledger.LedgerProposal.create("leased", hardlink_lease_body)]
    hardlink_leased = ledger._parse_ledger(encoded(hardlink_leased_proposals))
    hardlink_terminal = hardlink_leased[-1]
    hardlink_authorization = dict(
        authorization.body_value(), lease_sequence=hardlink_terminal.sequence,
        lease_offset=hardlink_terminal.next_offset, lease_sha256=hardlink_terminal.line_sha256,
    )
    hardlink_remove = ledger.LedgerProposal.create(
        "remove-intent", {"token": TOKEN, "path": "alias", "kind": "hardlink", "parent": pvalue(alias_parent), "child": gvalue(linked), "target_path": "target"},
    )
    hardlink_removing = ledger._parse_ledger(encoded(hardlink_leased_proposals + [
        ledger.LedgerProposal.create("release-authorized", hardlink_authorization), hardlink_remove,
    ]))
    hardlink_absent = ledger.ReconcileObservations(
        state_after, ((ledger._operation_name(TOKEN), target_parent.generation),),
        (("rootfs", root), ("target", target)), ledger_file(), (("", target_parent),),
    )
    state = ledger._reconcile_ledger(hardlink_removing, hardlink_absent)
    assert state.status == "hardlink-remove-absence-settleable" and state.cleanup_origin == "release-authorized"

    rejected(lambda: ledger._parse_ledger(encoded(proposals + [authorization])))
    rejected(lambda: ledger._parse_ledger(encoded(leased_proposals + [leased_proposals[-1]])))
    rejected(lambda: ledger._parse_ledger(encoded(leased_proposals + [create[0]])))
    wrong = dict(authorization.body_value())
    wrong["lease_offset"] += 1
    rejected(lambda: ledger._parse_ledger(encoded(leased_proposals + [ledger.LedgerProposal.create("release-authorized", wrong)])))
    for key, value in (("manifest_size", True), ("ustar_size", 513), ("entry_count", 0), ("manifest_sha256", "0" * 64)):
        hostile = dict(lease_body)
        hostile[key] = value
        rejected(lambda hostile=hostile: ledger.LedgerProposal.create("leased", hostile))
    assert ledger._settled_record(0, 1, "2" * 64).sequence == 0
    rejected(lambda: ledger._settled_record(0, 1, "2" * 64, 1))


def reference_matching(previous, current):
    left = previous.body_value()
    right = current.body_value()
    for key in ("path", "kind", "target_path", "alias", "index", "operation_name"):
        if key in left or key in right:
            assert left.get(key) == right.get(key)
    if previous.record_type.endswith("-observed"):
        assert left == right
        return
    if previous.record_type == "candidate-tar-intent":
        assert (right["token"], right["path"], right["anonymous"], right["size"], right["sha256"]) == (
            left["token"], left["path"], left["anonymous"], left["size"], left["sha256"],
        )
        ledger._candidate_parent_transition(ledger._parse_parent(left["parent"]), ledger._parse_parent(right["parent"]))
        ledger._candidate_transition(
            ledger._candidate_generation(left["anonymous"], 0), ledger._candidate_generation(right["linked"], 1),
        )
    elif previous.record_type == "create-intent":
        ledger._parent_delta("create", left["path"].split("/")[-1], ledger._parse_parent(left["parent"]), ledger._parse_parent(right["parent"]))
    elif previous.record_type == "metadata-intent":
        before = ledger._parse_generation(left["before"])
        child = ledger._parse_generation(right["child"])
        assert before.key == child.key
        assert (child.mode, child.uid, child.gid, child.size, child.mtime_ns) == ledger._parse_metadata(left["desired"])
    elif previous.record_type == "hardlink-create-intent":
        assert ledger._parse_generation(left["target"]) == ledger._parse_generation(right["target_before"])
        ledger._parent_delta("hardlink", left["alias"].split("/")[-1], ledger._parse_parent(left["parent"]), ledger._parse_parent(right["parent"]))
    elif previous.record_type == "remove-intent":
        action = "rmdir" if left["kind"] == "directory" else "unlink"
        ledger._parent_delta(action, left["path"].split("/")[-1], ledger._parse_parent(left["parent"]), ledger._parse_parent(right["parent"]))
        assert (left["target_path"] is None) == (right["target"] is None)
        if right["target"] is not None:
            ledger._hardlink_generation_change(ledger._parse_generation(left["child"]), ledger._parse_generation(right["target"]), -1)


def reference_validate(records):
    assert type(records) is tuple and records and records[0].record_type == "genesis"
    token = records[0].body_value()["token"]
    phase, operation_name = "genesis", None
    state_parent = ledger._parse_parent(records[0].body_value()["state_parent"])
    operation_parent = None
    groups, parents = {}, {}
    pending = return_phase = lease_snapshot = None

    def parent_path(body):
        return body.get("alias", body.get("path")).rpartition("/")[0]

    def require_parent(body):
        path = parent_path(body)
        expected = operation_parent if path == "" else parents.get(path)
        assert expected == ledger._parse_parent(body["parent"])

    def settle_parent(body):
        nonlocal operation_parent
        path = parent_path(body)
        if path == "":
            operation_parent = ledger._parse_parent(body["parent"])
        else:
            parents[path] = ledger._parse_parent(body["parent"])
        if body.get("kind") == "directory" and "child" in body:
            parents[body["path"]] = ledger.LedgerParent(ledger._parse_generation(body["child"]), ())
        if body.get("kind") == "directory" and body.get("target") is None and "child" not in body:
            parents.pop(body["path"], None)

    settled = ledger._record_settled(records[0])
    for record in records[1:]:
        assert (record.sequence, record.previous_sequence, record.previous_offset, record.previous_sha256) == (
            settled.sequence + 1, settled.sequence, settled.offset, settled.line_sha256,
        )
        body = record.body_value()
        assert body["token"] == token and phase not in {"retired", "uncertain"}
        if "operation_name" in body:
            assert body["operation_name"] == ledger._operation_name(token)
        kind = record.record_type
        previous_body = records[record.sequence - 1].body_value()
        if kind == "uncertain":
            phase, pending, return_phase = "uncertain", None, None
        elif phase == "genesis":
            assert kind == "genesis-settled" and ledger._parse_parent(body["state_parent"]) == state_parent
            phase = "ready"
        elif phase == "ready":
            assert kind in {"genesis-abort", "operation-create-intent"}
            assert ledger._parse_parent(body["state_parent"]) == state_parent
            if kind == "genesis-abort":
                phase = "aborted"
            else:
                operation_name, phase = body["operation_name"], "operation-intent"
        elif phase == "aborted":
            assert kind == "retired" and ledger._parse_parent(body["state_parent"]) == state_parent
            phase = "retired"
        elif phase == "operation-intent":
            assert kind in {"operation-create-observed", "operation-abort"} and body["operation_name"] == operation_name
            if kind == "operation-create-observed":
                after = ledger._parse_parent(body["state_parent"])
                ledger._parent_delta("create", operation_name, state_parent, after)
                state_parent = after
                operation_parent = ledger.LedgerParent(ledger._parse_generation(body["operation"]), ())
                phase = "operation-observed"
            else:
                assert ledger._parse_parent(body["state_parent"]) == state_parent
                phase = "aborted"
        elif phase == "operation-observed":
            assert kind == "operation-create-settled" and body["operation_name"] == operation_name and body == previous_body
            phase = "active"
        elif phase in {"active", "release-authorized", "prestage-release-authorized"}:
            if kind == "prebuilt-import-intent":
                assert phase == "active" and pending is None and lease_snapshot is None
                assert not any(item.record_type == "prebuilt-import-intent" for item in records[:record.sequence])
            elif kind == "leased":
                assert phase == "active" and pending is None and lease_snapshot is None
                assert ledger._parse_parent(body["state_parent"]) == state_parent
                assert ledger._parse_generation(body["operation"]) == operation_parent.generation
                lease_snapshot = ledger._lease_from_record(records, record)
                phase = "leased"
            elif kind == "operation-remove-intent":
                assert body["operation_name"] == operation_name
                assert ledger._parse_parent(body["state_parent"]) == state_parent
                assert operation_parent.names == () and ledger._parse_generation(body["operation"]) == operation_parent.generation
                return_phase, phase = phase, "operation-remove"
            elif kind == "hardlink-group":
                assert phase == "active" and body["target_path"] not in groups
                groups[body["target_path"]] = [tuple(body["aliases"]), 0]
            elif kind == "candidate-tar-intent":
                assert phase == "active" and pending is None and lease_snapshot is None
                require_parent(body)
                assert body["path"] not in operation_parent.names
                pending, return_phase, phase = record, "active", "candidate-tar-intent"
            else:
                allowed = {"remove-intent"} if phase in {"release-authorized", "prestage-release-authorized"} else {
                    "create-intent", "metadata-intent", "hardlink-create-intent", "remove-intent",
                }
                assert kind in allowed
                if "parent" in body:
                    require_parent(body)
                if kind == "hardlink-create-intent":
                    aliases, index = groups[body["target_path"]]
                    assert body["index"] == index and body["alias"] == aliases[index]
                if kind == "remove-intent" and body["target_path"] is not None:
                    aliases, index = groups[body["target_path"]]
                    assert index > 0 and body["path"] == aliases[index - 1]
                pending, return_phase = record, phase
                phase = kind.removesuffix("-intent") + "-intent"
        elif phase == "leased":
            assert kind in {"release-authorized", "prestage-release-authorized"} and lease_snapshot is not None
            actual = lease_snapshot.settled
            assert (body["lease_sequence"], body["lease_offset"], body["lease_sha256"]) == (
                actual.sequence, actual.offset, actual.line_sha256,
            )
            phase = kind
        elif phase == "candidate-tar-intent":
            assert kind in {"candidate-tar-abort", "candidate-tar-observed"} and pending is not None
            if kind == "candidate-tar-abort":
                assert body == pending.body_value()
                pending, phase, return_phase = None, "active", None
            else:
                reference_matching(pending, record)
                pending, phase = record, "candidate-tar-observed"
        elif phase == "candidate-tar-observed":
            assert kind == "candidate-tar-settled" and pending is not None
            reference_matching(pending, record)
            operation_parent = ledger._parse_parent(body["parent"])
            pending, phase, return_phase = None, "active", None
        elif phase.endswith("-intent"):
            abort_kind = phase.removesuffix("intent") + "abort"
            assert kind in {abort_kind, phase.removesuffix("intent") + "observed"} and pending is not None
            if kind == abort_kind:
                assert return_phase == "active"
                intent = pending.body_value()
                excluded = {"parent", "target"} if kind == "hardlink-create-abort" else {"parent"}
                assert all(body[key] == intent[key] for key in body if key not in excluded)
                if kind == "hardlink-create-abort":
                    assert ledger._same_fields(
                        ledger._parse_generation(body["target"]), ledger._parse_generation(intent["target"]), {"ctime_ns"},
                    )
                assert ledger._valid_abort_parent(ledger._parse_parent(intent["parent"]), ledger._parse_parent(body["parent"]))
                settle_parent(body)
                pending, phase, return_phase = None, return_phase, None
            else:
                reference_matching(pending, record)
                pending = record
                phase = phase.removesuffix("intent") + "observed"
        elif phase.endswith("-observed"):
            assert kind == phase.removesuffix("observed") + "settled" and pending is not None
            reference_matching(pending, record)
            if kind == "hardlink-create-settled":
                groups[body["target_path"]][1] += 1
            if kind == "remove-settled" and body["target"] is not None:
                groups[body["target_path"]][1] -= 1
            if kind == "metadata-settled" and body["path"] in parents:
                current = parents[body["path"]]
                parents[body["path"]] = ledger.LedgerParent(ledger._parse_generation(body["child"]), current.names)
            elif "parent" in body:
                settle_parent(body)
            pending, phase, return_phase = None, return_phase, None
        elif phase == "operation-remove":
            assert kind == "operation-absent" and body["operation_name"] == operation_name
            after = ledger._parse_parent(body["state_parent"])
            ledger._parent_delta("rmdir", operation_name, state_parent, after)
            state_parent, operation_parent = after, None
            phase, return_phase = "operation-absent", None
        elif phase == "operation-absent":
            assert kind == "retired" and ledger._parse_parent(body["state_parent"]) == state_parent
            phase = "retired"
        else:
            raise AssertionError("unknown reference phase")
        settled = ledger._record_settled(record)
    return phase


def incremental_validation_tests():
    proposals, _state_before, _state_after, _operation = lifecycle_prefix()
    proposals.append(ledger.LedgerProposal.create("prebuilt-import-intent", {
        "token": TOKEN, "descriptor_sha256": "1" * 64,
        "manifest_sha256": "2" * 64, "manifest_size": 1,
        "ustar_sha256": "3" * 64, "ustar_size": 512, "entry_count": 1,
    }))
    encoded(proposals)
    phases = set()
    record_types = set()
    accepted = []
    for raw in tuple(ENCODED_CASES):
        records = ledger._decode_ledger(raw)
        try:
            full = ledger._validated_history(records)
        except ledger.LedgerError:
            try:
                incremental = ledger._initial_history(records[0])
                for record in records[1:]:
                    incremental = ledger._advance_history(incremental, record)
            except ledger.LedgerError:
                continue
            raise AssertionError("incremental validation accepted a full-replay rejection")
        incremental = ledger._initial_history(records[0])
        phases.add(incremental.legal.phase)
        record_types.add(records[0].record_type)
        for record in records[1:]:
            previous = incremental
            incremental = ledger._advance_history(incremental, record)
            assert incremental.previous is previous
            phases.add(incremental.legal.phase)
            record_types.add(record.record_type)
        assert incremental.legal == full.legal
        assert ledger._history_records(incremental) == records
        parsed = ledger._parse_ledger_history(raw)
        assert parsed.legal == full.legal and ledger._history_records(parsed) == records
        settled = ledger.INITIAL_BYTES
        offset = 0
        for record in records:
            proposal = ledger.LedgerProposal.create(record.record_type, record.body_value())
            line = ledger._encode_proposal(proposal, settled)
            assert raw[offset:record.next_offset] == line
            offset = record.next_offset
            settled = ledger.SettledBytes(record.sequence, record.next_offset, record.line_sha256)
        accepted.append((records, incremental))

    assert record_types == ledger.RECORD_TYPES, ledger.RECORD_TYPES - record_types
    assert phases == {
        "genesis", "ready", "aborted", "retired", "operation-intent", "operation-observed",
        "active", "create-intent", "create-observed", "metadata-intent", "metadata-observed",
        "hardlink-create-intent", "hardlink-create-observed", "remove-intent", "remove-observed",
        "candidate-tar-intent", "candidate-tar-observed", "leased", "release-authorized",
        "prestage-release-authorized", "operation-remove", "operation-absent", "uncertain",
    }, phases

    expected_next = {
        "genesis": {"genesis-settled"},
        "ready": {"genesis-abort", "operation-create-intent"},
        "aborted": {"retired"},
        "operation-intent": {"operation-create-observed", "operation-abort"},
        "operation-observed": {"operation-create-settled"},
        "active": {
            "leased", "operation-remove-intent", "hardlink-group", "create-intent",
            "metadata-intent", "hardlink-create-intent", "remove-intent", "candidate-tar-intent",
            "prebuilt-import-intent",
        },
        "candidate-tar-intent": {"candidate-tar-observed", "candidate-tar-abort"},
        "candidate-tar-observed": {"candidate-tar-settled"},
        "create-intent": {"create-observed", "create-abort"},
        "create-observed": {"create-settled"},
        "metadata-intent": {"metadata-observed"},
        "metadata-observed": {"metadata-settled"},
        "hardlink-create-intent": {"hardlink-create-observed", "hardlink-create-abort"},
        "hardlink-create-observed": {"hardlink-create-settled"},
        "remove-intent": {"remove-observed"},
        "remove-observed": {"remove-settled"},
        "leased": {"release-authorized", "prestage-release-authorized"},
        "release-authorized": {"remove-intent", "operation-remove-intent"},
        "prestage-release-authorized": {"remove-intent", "operation-remove-intent"},
        "operation-remove": {"operation-absent"},
        "operation-absent": {"retired"},
        "retired": set(),
        "uncertain": set(),
    }
    for phase in expected_next:
        if phase not in {"retired", "uncertain"}:
            expected_next[phase].add("uncertain")

    prefixes = {}
    templates = {}
    positive_edges = set()
    positive_cases = []
    for records, _history in accepted:
        previous = ledger._initial_history(records[0])
        for record in records[1:]:
            positive_edges.add((previous.legal.phase, record.record_type))
            positive_cases.append((ledger._history_records(previous), record))
            previous = ledger._advance_history(previous, record, False, records)
        for index, record in enumerate(records):
            templates.setdefault(record.record_type, record)
            prefix = records[:index + 1]
            try:
                current = ledger._validated_history(prefix)
            except BaseException:
                continue
            prefixes.setdefault((current.legal.phase, index, record.line_sha256), prefix)
    assert set(templates) == ledger.RECORD_TYPES
    required_edges = {
        (phase, kind) for phase, kinds in expected_next.items() for kind in kinds if kind != "uncertain"
    }
    assert required_edges <= positive_edges, required_edges - positive_edges
    for prefix, record in positive_cases:
        expected = reference_validate(prefix + (record,))
        assert ledger._validated_history(prefix + (record,)).legal.phase == expected
        hostile_chain = dataclasses.replace(record, previous_sha256="6" * 64)
        foreign = dict(record.body_value())
        foreign["token"] = "9" * 64
        if "operation_name" in foreign:
            foreign["operation_name"] = ledger._operation_name(foreign["token"])
        hostile_token = dataclasses.replace(record, body=ledger._freeze(foreign))
        for hostile in (hostile_chain, hostile_token):
            rejected(lambda prefix=prefix, hostile=hostile: ledger._validated_history(prefix + (hostile,)))

    def rebase(template, prefix, body=None):
        terminal = prefix[-1]
        return dataclasses.replace(
            template,
            sequence=terminal.sequence + 1,
            previous_sequence=terminal.sequence,
            previous_offset=terminal.next_offset,
            previous_sha256=terminal.line_sha256,
            next_offset=terminal.next_offset + 1,
            body=template.body if body is None else ledger._freeze(body),
            line_sha256="7" * 64,
        )

    for phase in expected_next:
        if phase in {"retired", "uncertain"}:
            continue
        prefix = next(value for value in prefixes.values() if ledger._validated_history(value).legal.phase == phase)
        candidate = rebase(templates["uncertain"], prefix)
        assert reference_validate(prefix + (candidate,)) == "uncertain"
        assert ledger._validated_history(prefix + (candidate,)).legal.phase == "uncertain"

    def mutations(template):
        original = template.body_value()
        values = []
        foreign = dict(original)
        foreign["token"] = "9" * 64
        if "operation_name" in foreign:
            foreign["operation_name"] = ledger._operation_name(foreign["token"])
        values.append(foreign)
        for key in ("path", "alias", "target_path"):
            if key in original and original[key] is not None:
                changed = dict(original)
                changed[key] = original[key] + "-foreign"
                values.append(changed)
        if "index" in original:
            changed = dict(original)
            changed["index"] += 1
            values.append(changed)
        for key in ("lease_sequence", "lease_offset", "kata_release_sequence", "kata_release_offset"):
            if key in original:
                changed = dict(original)
                changed[key] += 1
                values.append(changed)
        for key in ("lease_sha256", "kata_release_sha256"):
            if key in original:
                changed = dict(original)
                changed[key] = "6" * 64
                values.append(changed)
        if "parent" in original:
            changed = dict(original)
            altered = dict(original["parent"])
            altered_generation = dict(altered["generation"])
            altered_generation["ctime_ns"] += 1
            altered["generation"] = altered_generation
            changed["parent"] = altered
            values.append(changed)
        for key in ("child", "before", "target", "target_before", "target_after", "alias_generation", "operation"):
            if key in original and original[key] is not None:
                changed = dict(original)
                altered = dict(original[key])
                altered["inode"] += 100_000
                changed[key] = altered
                values.append(changed)
        return values

    forbidden_checked = set()
    for prefix in prefixes.values():
        current_phase = ledger._validated_history(prefix).legal.phase
        for record_type, template in templates.items():
            candidates = [rebase(template, prefix)] + [
                rebase(template, prefix, body) for body in mutations(template)
            ]
            for candidate in candidates:
                reference_result = current_result = None
                try:
                    reference_result = reference_validate(prefix + (candidate,))
                except BaseException:
                    pass
                try:
                    current_result = ledger._validated_history(prefix + (candidate,)).legal.phase
                except BaseException:
                    pass
                assert current_result == reference_result, (
                    current_phase, record_type, candidate.body_value(), reference_result, current_result,
                )
                if record_type not in expected_next[current_phase]:
                    forbidden_checked.add((current_phase, record_type))
                    assert current_result is None
    expected_forbidden = {
        (phase, kind) for phase in phases for kind in ledger.RECORD_TYPES
        if kind not in expected_next[phase]
    }
    assert forbidden_checked == expected_forbidden

    for records, history in accepted:
        proposal = ledger.LedgerProposal.create("uncertain", {"token": TOKEN, "reason": "incomplete"})
        candidate = next_record(history, proposal)
        if history.legal.phase not in {"retired", "uncertain"}:
            advanced = ledger._advance_history(history, candidate)
            replayed = ledger._validated_history(records + (candidate,))
            assert advanced.legal == replayed.legal and advanced.legal.phase == "uncertain"
        else:
            rejected(lambda history=history, candidate=candidate: ledger._advance_history(history, candidate))
            rejected(lambda records=records, candidate=candidate: ledger._validated_history(records + (candidate,)))
        for hostile in (
            dataclasses.replace(candidate, sequence=candidate.sequence + 1),
            dataclasses.replace(candidate, previous_sequence=candidate.previous_sequence - 1),
            dataclasses.replace(candidate, previous_offset=candidate.previous_offset + 1),
            dataclasses.replace(candidate, previous_sha256="f" * 64),
        ):
            rejected(lambda history=history, hostile=hostile: ledger._advance_history(history, hostile))
            rejected(lambda records=records, hostile=hostile: ledger._validated_history(records + (hostile,)))
        foreign = ledger.LedgerProposal.create("uncertain", {"token": "9" * 64, "reason": "incomplete"})
        hostile = dataclasses.replace(candidate, body=foreign.body)
        rejected(lambda history=history, hostile=hostile: ledger._advance_history(history, hostile))
        rejected(lambda records=records, hostile=hostile: ledger._validated_history(records + (hostile,)))

    proposals, _state_before, _state_after, _operation = lifecycle_prefix()
    fold_before = fs.structural_counter_snapshot()
    history = ledger._parse_ledger_history(encoded(proposals))
    fold_delta = fs.structural_counter_delta(fold_before, fs.structural_counter_snapshot())
    assert fold_delta["complete_legal_folds"] == 1
    assert fold_delta["incremental_records"] == 0
    group_history = history
    group_generation = generation(9000, "file", 0o644, 1, 1)
    before_counters = fs.structural_counter_snapshot()
    for index in range(2_000):
        target = f"group-target-{index:04d}"
        proposal = ledger.LedgerProposal.create("hardlink-group", {
            "token": TOKEN, "target_path": target, "aliases": [f"group-alias-{index:04d}"],
            "content_sha256": "8" * 64, "target": gvalue(group_generation),
        })
        group_history = ledger._advance_history(group_history, next_record(group_history, proposal))
    after_counters = fs.structural_counter_snapshot()
    assert group_history.legal.groups.count == 2_000
    assert after_counters["group_node_copies"] - before_counters["group_node_copies"] == 514_000
    lookup_steps = after_counters["group_lookup_steps"] - before_counters["group_lookup_steps"]
    assert 0 < lookup_steps <= 512_000
    assert after_counters["active_history_record_copies"] - before_counters["active_history_record_copies"] == 0

    class CollidingDigest:
        def digest(self):
            return b"\x00" * 32

    real_sha256 = ledger.hashlib.sha256
    try:
        ledger.hashlib.sha256 = lambda _raw: CollidingDigest()
        collision_counter_before = fs.structural_counter_snapshot()
        for order in (("z", "ab", "a"), ("z", "a", "ab"), ("ab", "a", "z")):
            collision_map = ledger._EMPTY_MAP
            expected = {}
            for key in order:
                value = ledger.LegalHardlinkCursor(key, (f"alias-{key}",), 0)
                collision_map = ledger._map_set(collision_map, key, value, True)
                expected[key] = value
            assert collision_map.count == 3
            assert all(ledger._map_get(collision_map, key) == value for key, value in expected.items())
            updated = dataclasses.replace(expected[order[1]], next_index=1)
            collision_map = ledger._map_set(collision_map, order[1], updated, True)
            expected[order[1]] = updated
            for key in order:
                collision_map = ledger._map_set(collision_map, key, ledger._MISSING, True)
                assert collision_map.count == 2
                assert ledger._map_get(collision_map, key) is ledger._MISSING
                collision_map = ledger._map_set(collision_map, key, expected[key], True)
                assert collision_map.count == 3
                assert all(ledger._map_get(collision_map, item) == value for item, value in expected.items())
        collision_history = history
        for index, key in enumerate(("z", "ab", "a")):
            ledger.hashlib.sha256 = real_sha256
            proposal = ledger.LedgerProposal.create("hardlink-group", {
                "token": TOKEN, "target_path": key, "aliases": [f"linked-{key}"],
                "content_sha256": "5" * 64, "target": gvalue(group_generation),
            })
            record = next_record(collision_history, proposal)
            ledger.hashlib.sha256 = lambda _raw: CollidingDigest()
            collision_history = ledger._advance_history(collision_history, record)
            assert collision_history.legal.groups.count == index + 1
        assert all(ledger._group_get(collision_history.legal.groups, key) is not None for key in ("z", "ab", "a"))
        collision_counter_delta = fs.structural_counter_delta(
            collision_counter_before, fs.structural_counter_snapshot(),
        )
        assert 3 * 3 * 257 < collision_counter_delta["group_node_copies"] <= 30_000
        assert 0 < collision_counter_delta["group_lookup_steps"] <= 30_000
    finally:
        ledger.hashlib.sha256 = real_sha256

    operation_parent = parent(2, ())
    copied_prefixes = {"count": 0}
    real_materialize = ledger._history_records

    def forbidden_materialize(_history):
        copied_prefixes["count"] += 1
        raise AssertionError("ordinary incremental append materialized its record prefix")

    ledger._history_records = forbidden_materialize
    incremental_before = fs.structural_counter_snapshot()
    try:
        for index in range(5_000):
            path = f"probe-{index:04d}"
            intent = ledger.LedgerProposal.create(
                "create-intent",
                {"token": TOKEN, "path": path, "kind": "file", "parent": pvalue(operation_parent)},
            )
            previous = history
            history = ledger._advance_history(history, next_record(history, intent))
            assert history.previous is previous
            abort = ledger.LedgerProposal.create("create-abort", intent.body_value())
            previous = history
            history = ledger._advance_history(history, next_record(history, abort))
            assert history.previous is previous and history.legal.phase == "active"
    finally:
        ledger._history_records = real_materialize
    incremental_delta = fs.structural_counter_delta(incremental_before, fs.structural_counter_snapshot())
    assert incremental_delta["incremental_records"] == 10_000
    assert incremental_delta["complete_legal_folds"] == 0
    assert incremental_delta["complete_walks"] == 0
    assert incremental_delta["parent_snapshots"] == 0
    assert incremental_delta["active_history_record_copies"] == 0
    assert copied_prefixes["count"] == 0 and history.count == 10_005
    assert len(ledger._history_records(history)) == history.count
    assert not any(name in ledger.LedgerHistory.__dict__ for name in ("__add__", "__iter__", "__getitem__"))
    rejected(lambda: dataclasses.replace(history.legal, phase="foreign"))
    rejected(lambda: dataclasses.replace(history.legal, operation_name="foreign"))
    rejected(lambda: dataclasses.replace(history.legal, pending=history.terminal))
    rejected(lambda: dataclasses.replace(history.legal, return_phase="release-authorized"))
    rejected(lambda: ledger.LegalHardlinkCursor("target", ("alias", "alias"), 0))
    rejected(lambda: ledger.LegalHardlinkCursor("target", ("target",), 0))
    try:
        history.count = 1
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("immutable history accepted mutation")

    proposal = ledger.LedgerProposal.create(
        "create-intent", {"token": TOKEN, "path": "unpublished", "kind": "file", "parent": pvalue(operation_parent)},
    )
    active = builder.ActiveLedger(object(), history, type("Writer", (), {"settled": history.legal.settled})())
    old_history = active.records
    real_append = ledger._append_record
    try:
        ledger._append_record = lambda *_args: (_ for _ in ()).throw(OSError("append failed"))
        rejected(lambda: builder._append(active, "create-intent", proposal.body_value(), control()))
        assert active.records is old_history
    finally:
        ledger._append_record = real_append


def status_matrix_tests():
    prelease = {
        "genesis-settleable", "genesis-abortable", "operation-abortable", "operation-create-settleable",
        "entry-absent", "create-settleable", "metadata-settleable", "hardlink-create-settleable",
        "candidate-tar-abortable", "candidate-tar-observeable", "candidate-tar-settleable", "active",
    }
    removal = {
        "remove-retry", "remove-absence-settleable", "hardlink-remove-absence-settleable", "remove-settleable",
        "operation-remove-retry", "operation-absence-settleable", "retirable", "retired",
    }
    snapshot = ledger.LeaseSnapshot(
        parent(1, ("ledger",)), generation(2), generation(3), (("rootfs", generation(3)),),
        fs.HostKey(1, 1, 99, "file"), ledger._settled_record(1, 2, "a" * 64),
    )
    for status in prelease | removal:
        state = ledger.LedgerState(status, TOKEN, ledger._operation_name(TOKEN), (), True, "prelease", False, False, "fixture")
        assert state.cleanup_allowed
    for status in removal | {"release-authorized"}:
        state = ledger.LedgerState(status, TOKEN, ledger._operation_name(TOKEN), (), True, "release-authorized", True, True, "fixture", snapshot)
        assert state.cleanup_allowed
    assert not ledger.LedgerState("leased", TOKEN, ledger._operation_name(TOKEN), snapshot.owned, False, "none", True, False, "leased", snapshot).cleanup_allowed
    assert not ledger.LedgerState("preserve", TOKEN, ledger._operation_name(TOKEN), (), False, "none", False, False, "uncertain").cleanup_allowed
    all_statuses = prelease | removal | {"release-authorized", "leased", "preserve"}
    for status in all_statuses:
        for origin in {"none", "prelease", "release-authorized"}:
            valid = (status in prelease | removal and origin == "prelease") or (status in removal | {"release-authorized"} and origin == "release-authorized") or (status in {"leased", "preserve"} and origin == "none")
            if not valid:
                rejected(lambda status=status, origin=origin: ledger.LedgerState(status, TOKEN, None, (), True, origin, True, True, "fixture", snapshot))


def candidate_malformed_parser_tests():
    proposals, _state_before, _state_after, operation = lifecycle_prefix(operation_size=1)
    intent, abort, observed, settled, _before, _after, _anonymous, _linked = candidate_records(operation)

    def rejected_mutation(suffix, index, mutate):
        rejected(lambda: ledger._parse_ledger(mutate_encoded(proposals + suffix, len(proposals) + index, mutate)))

    intent_mutations = (
        lambda body: body.pop("sha256"),
        lambda body: body.update(extra=0),
        lambda body: body.update(path="other"),
        lambda body: body.update(token="9" * 64),
        lambda body: body.update(size=ledger.CANDIDATE_TAR_SIZE - 1),
        lambda body: body.update(sha256="not-a-digest"),
        lambda body: body["anonymous"].update(mode=0o400),
        lambda body: body["anonymous"].update(uid=1),
        lambda body: body["anonymous"].update(gid=1),
        lambda body: body["anonymous"].update(kind="directory"),
        lambda body: body["anonymous"].update(nlink=1),
    )
    for mutate in intent_mutations:
        rejected_mutation([intent], 0, mutate)
    rejected_mutation([intent, abort], 1, lambda body: body.update(sha256="8" * 64))

    observed_mutations = (
        lambda body: body.pop("linked"),
        lambda body: body.update(extra=0),
        lambda body: body["linked"].update(mount_id=2),
        lambda body: body["linked"].update(device=2),
        lambda body: body["linked"].update(inode=71),
        lambda body: body["linked"].update(mode=0o400),
        lambda body: body["linked"].update(uid=1),
        lambda body: body["linked"].update(gid=1),
        lambda body: body["linked"].update(kind="directory"),
        lambda body: body["linked"].update(nlink=2),
        lambda body: body["linked"].update(mtime_ns=2),
        lambda body: body["linked"].update(ctime_ns=9),
        lambda body: body["parent"]["generation"].update(inode=999),
        lambda body: body["parent"]["generation"].update(mode=0o755),
        lambda body: body["parent"]["generation"].update(uid=1),
        lambda body: body["parent"]["generation"].update(gid=1),
        lambda body: body["parent"]["generation"].update(nlink=3),
        lambda body: body["parent"]["generation"].update(size=0),
        lambda body: body["parent"]["generation"].update(mtime_ns=0),
        lambda body: body["parent"]["generation"].update(ctime_ns=0),
        lambda body: body["parent"].update(names=[ledger.CANDIDATE_TAR_PATH, "unrelated"]),
    )
    for index, mutate in enumerate(observed_mutations):
        try:
            rejected_mutation([intent, observed], 1, mutate)
        except AssertionError as error:
            raise AssertionError(f"candidate observed mutation {index} accepted") from error
    rejected_mutation([intent, observed, settled], 2, lambda body: body.update(sha256="8" * 64))


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
    return fs.DirectoryNamesSnapshot(generation(inode, ctime=ctime), checked)


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
        real_fsync = ledger.os.fsync
        ledger._observe_node = observe
        ledger._require_empty_fd_xattrs = lambda _node, _control: None
        try:
            initial = observe(identity_fd, operation_fd, control())
            node = fs.HeldNode(identity_fd, operation_fd, initial)
            state = ledger.LedgerWriterState(node, key, ledger.INITIAL_BYTES, initial)
            proposal = ledger.LedgerProposal.create("genesis", genesis_body(parent(1, ("active-ledger",))))
            leased = ledger.LedgerProposal.create("leased", {
                "token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "state_parent": pvalue(parent(1, ())),
                "operation": gvalue(generation(2)), "root": gvalue(generation(3)),
                "ledger_key": {"mount_id": 1, "device": 1, "inode": 99, "kind": "file"},
                "manifest_sha256": "d" * 64, "manifest_size": 1, "ustar_sha256": "e" * 64,
                "ustar_size": 512, "entry_count": 1,
            })
            authorized = ledger.LedgerProposal.create("release-authorized", {
                "token": TOKEN, "operation_name": ledger._operation_name(TOKEN), "lease_sequence": 1,
                "lease_offset": 2, "lease_sha256": "f" * 64, "kata_operation_token": "1" * 64,
                "kata_ledger_key": {"mount_id": 1, "device": 1, "inode": 100, "kind": "file"},
                "kata_release_sequence": 1, "kata_release_offset": 2, "kata_release_sha256": "2" * 64,
            })
            for control_proposal in (leased, authorized):
                rejected(lambda control_proposal=control_proposal: ledger._append_record(state, control_proposal, control()))
                assert os.fstat(operation_fd.number).st_size == 0

            pending = [value for value in vars(ledger).values() if inspect.isfunction(value)]
            reachable = []
            seen = set()
            while pending:
                function = pending.pop()
                if id(function) in seen:
                    continue
                seen.add(id(function))
                reachable.append(function)
                for cell in function.__closure__ or ():
                    try:
                        value = cell.cell_contents
                    except ValueError:
                        continue
                    if inspect.isfunction(value):
                        pending.append(value)
            generic_writers = [
                function for function in reachable
                if tuple(inspect.signature(function).parameters) == ("writer_state", "proposal", "control")
            ]
            assert {function.__name__ for function in generic_writers} == {"_append_record"}
            for function in generic_writers:
                rejected(lambda function=function: function(state, authorized, control()))
                assert os.fstat(operation_fd.number).st_size == 0
            private_writers = [function for function in reachable if function.__name__ == "_write_record"]
            assert len(private_writers) == 1
            rejected(lambda: private_writers[0](state, authorized, control()))
            assert os.fstat(operation_fd.number).st_size == 0
            assert "body" not in inspect.signature(ledger._append_leased_record).parameters
            assert "body" not in inspect.signature(ledger._append_release_authorized_record).parameters
            ledger.os.write = lambda _fd, _raw: 0
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.fstat(operation_fd.number).st_size == 0
            writes = {"count": 0}

            def partial_then_fail(fd, raw):
                writes["count"] += 1
                if writes["count"] == 1:
                    return real_write(fd, raw[:7])
                raise OSError("partial append")

            ledger.os.write = partial_then_fail
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.fstat(operation_fd.number).st_size == 0
            # The closure-private release writer uses the same rollback core;
            # exercise its actual encoded suffix rather than a generic lookalike.
            writes["count"] = 0
            rejected(lambda: ledger._append_release_authorized_record(
                state, TOKEN, ledger._operation_name(TOKEN),
                ledger.SettledBytes(8, 1234, "f" * 64), "1" * 64,
                fs.HostKey(1, 2, 3, "file"), ledger.SettledBytes(9, 2345, "2" * 64),
                control()))
            assert os.fstat(operation_fd.number).st_size == 0
            hostile_calls = {"count": 0}

            def hostile_suffix(fd, _raw):
                hostile_calls["count"] += 1
                if hostile_calls["count"] == 1:
                    return real_write(fd, b"x")
                raise OSError("hostile suffix")

            ledger.os.write = hostile_suffix
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.pread(operation_fd.number, 1, 0) == b"x"
            os.ftruncate(operation_fd.number, 0)
            os.lseek(operation_fd.number, 0, os.SEEK_SET)

            def overlong_suffix(fd, raw):
                real_write(fd, raw + b"x")
                return len(raw) + 1

            ledger.os.write = overlong_suffix
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.fstat(operation_fd.number).st_size > 0
            os.ftruncate(operation_fd.number, 0)
            os.lseek(operation_fd.number, 0, os.SEEK_SET)
            ledger.os.write = real_write
            syncs = {"count": 0}

            def fsync_then_fail(fd):
                syncs["count"] += 1
                if syncs["count"] == 1:
                    raise OSError("append fsync")
                return real_fsync(fd)

            ledger.os.fsync = fsync_then_fail
            rejected(lambda: ledger._append_record(state, proposal, control()))
            assert os.fstat(operation_fd.number).st_size == 0
            ledger.os.fsync = real_fsync
            latch = {"cancelled": False}

            def write_then_cancel(fd, raw):
                count = real_write(fd, raw)
                latch["cancelled"] = True
                return count

            ledger.os.write = write_then_cancel
            interrupted = fs.OperationControl(time.monotonic_ns() + 30_000_000_000, lambda: latch["cancelled"])
            rejected(lambda: ledger._append_record(state, proposal, interrupted))
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
            ledger.os.fsync = real_fsync
            ledger._observe_node = real_observe
            ledger._require_empty_fd_xattrs = real_xattrs
            identity_fd.close()
            operation_fd.close()


def reconcile_emission_tests():
    required = {
        ("genesis-settleable", "prelease", True), ("genesis-abortable", "prelease", True),
        ("operation-abortable", "prelease", True), ("operation-create-settleable", "prelease", True),
        ("entry-absent", "prelease", True), ("create-settleable", "prelease", True),
        ("metadata-settleable", "prelease", True), ("hardlink-create-settleable", "prelease", True),
        ("candidate-tar-abortable", "prelease", True), ("candidate-tar-observeable", "prelease", True),
        ("candidate-tar-settleable", "prelease", True),
        ("active", "prelease", True), ("remove-retry", "prelease", True),
        ("remove-absence-settleable", "prelease", True), ("hardlink-remove-absence-settleable", "prelease", True),
        ("remove-settleable", "prelease", True), ("operation-remove-retry", "prelease", True),
        ("operation-absence-settleable", "prelease", True), ("retirable", "prelease", True), ("retired", "prelease", True),
        ("leased", "none", False), ("release-authorized", "release-authorized", True),
        ("prestage-release-authorized", "prestage-authorized", True),
        ("remove-retry", "prestage-authorized", True),
        ("remove-absence-settleable", "prestage-authorized", True),
        ("remove-settleable", "prestage-authorized", True),
        ("operation-remove-retry", "prestage-authorized", True),
        ("operation-absence-settleable", "prestage-authorized", True),
        ("retirable", "prestage-authorized", True),
        ("retired", "prestage-authorized", True),
        ("remove-retry", "release-authorized", True), ("remove-absence-settleable", "release-authorized", True),
        ("hardlink-remove-absence-settleable", "release-authorized", True),
        ("remove-settleable", "release-authorized", True), ("operation-remove-retry", "release-authorized", True),
        ("operation-absence-settleable", "release-authorized", True),
        ("retirable", "release-authorized", True), ("retired", "release-authorized", True),
        ("preserve", "none", False),
    }
    assert RECONCILE_EMISSIONS == required, (required - RECONCILE_EMISSIONS, RECONCILE_EMISSIONS - required)


def static_tests():
    source = (REMOTE / "completion_rootfs_ledger.py").read_text()
    for forbidden in ("os.mkdir", "os.makedirs", "os.open", "os.unlink", "os.remove", "os.rmdir", "os.rename", "subprocess", "socket", "argparse", "sys.argv", "if __name__"):
        assert forbidden not in source
    assert "os.write" in source and "os.fsync" in source
    assert "MAX_LEDGER_BYTES" in source and "genesis-abort" in source and "operation-abort" in source


codec_and_reconcile_tests()
multi_alias_replay_tests()
lease_codec_and_origin_tests()
status_matrix_tests()
hostile_codec_tests()
candidate_malformed_parser_tests()
hardlink_tests()
incremental_validation_tests()
writer_tests()
reconcile_emission_tests()
static_tests()
print("completion rootfs ledger tests passed")

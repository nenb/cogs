#!/usr/bin/env python3
"""Portable fake-only hostile matrix for Slice A campaign contracts and reducer."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))

import completion_campaign_codec as codec
from completion_campaign_contracts import (
    CYCLE_EVENTS,
    CYCLE_MODES,
    CONTROLLER_EVENT_VERSION,
    ZERO_SHA256,
    CampaignContractError,
    ControllerEventRecord,
    CycleMode,
    Event,
    Outcome,
    Uncertainty,
    new_record,
    outcome_introduces_uncertainty,
    record_from_canonical_bytes,
    record_from_mapping,
    required_outcomes,
)
from completion_campaign_state import (
    HAPPY_PATH,
    CampaignStateError,
    append_record,
    reduce_campaign,
)

BATCH = hashlib.sha256(b"fake-only-batch").hexdigest()


def require(condition, message="test assertion failed"):
    if not condition:
        raise AssertionError(message)


def digest(label):
    return hashlib.sha256(f"fake-only:{label}".encode("ascii")).hexdigest()


def normal_outcome(event):
    choices = required_outcomes(event)
    for preferred in (Outcome.ZERO, Outcome.ACCEPTED, Outcome.OBSERVED, Outcome.INTENDED, Outcome.SEALED):
        if preferred in choices:
            return preferred
    raise AssertionError(event)


def active_cycle(records):
    active = None
    for record in records:
        if record.event is Event.CYCLE_OPENED:
            active = (record.cycle_ordinal, record.cycle_mode)
        elif record.event is Event.CYCLE_SEALED:
            active = None
    return active


def make_record(records, event, ordinal, mode, outcome, uncertainty=None, label=None):
    before = reduce_campaign(records).uncertainty
    introduced = outcome_introduces_uncertainty(event, outcome)
    projected = Uncertainty.STICKY if before is Uncertainty.STICKY or introduced else Uncertainty.CLEAR
    if uncertainty is not None:
        projected = uncertainty
    sequence = len(records) + 1
    return new_record(
        batch_commitment=BATCH,
        sequence=sequence,
        event=event,
        cycle_ordinal=ordinal,
        cycle_mode=mode,
        prior_record_sha256=ZERO_SHA256 if not records else records[-1].sha256(),
        payload_sha256=digest(label or f"{sequence}:{event.value}:{outcome.value}"),
        monotonic_observation_ns=sequence * 10,
        wall_observation_unix_ns=1_800_000_000_000_000_000 + sequence * 10,
        outcome=outcome,
        uncertainty=projected,
    )


def append_next(records, outcome=None, label=None):
    state = reduce_campaign(records)
    require(state.next_event is not None)
    chosen = normal_outcome(state.next_event) if outcome is None else outcome
    record = make_record(
        records,
        state.next_event,
        state.next_cycle_ordinal,
        state.next_cycle_mode,
        chosen,
        label=label,
    )
    return append_record(records, record)


def append_failure(records, uncertain=False, label=None):
    binding = active_cycle(records)
    ordinal, mode = (None, None) if binding is None else binding
    outcome = Outcome.UNCERTAIN if uncertain else Outcome.FAILED
    record = make_record(
        records,
        Event.FAILURE_RECORDED,
        ordinal,
        mode,
        outcome,
        label=label or f"failure:{len(records)}:{uncertain}",
    )
    return append_record(records, record)


def settle_failure(records, destroy=Outcome.ACCEPTED, zero=Outcome.ZERO):
    while not reduce_campaign(records).terminal:
        state = reduce_campaign(records)
        outcome = normal_outcome(state.next_event)
        if state.next_event is Event.DESTROY_SETTLED:
            outcome = destroy
        if state.next_event in {Event.ZERO_ACCEPTED, Event.FINAL_ZERO_ACCEPTED}:
            outcome = zero
        records = append_next(records, outcome, f"settle:{len(records)}:{state.next_event.value}:{outcome.value}")
    return records


def happy_records():
    records = ()
    while not reduce_campaign(records).terminal:
        records = append_next(records)
    return records


def expect_raises(kind, function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


def codec_matrix():
    value = {"z": [None, True, False, 0, -1, 2**64 - 1], "é": "value", "𐀀": {"a": "b"}}
    raw = codec.canonical_bytes(value)
    require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"))
    require(codec.load_canonical_bytes(raw) == value)
    require(codec.canonical_sha256(value) == hashlib.sha256(raw).hexdigest())
    require(codec.canonical_bytes({"\ue000": 1, "𐀀": 2}) == '{"\ue000":1,"𐀀":2}\n'.encode())

    hostile = (
        b'{"a":1,"a":2}\n',
        b'{"a":1.0}\n',
        b'{"a":1e2}\n',
        b'{"b":1,"a":2}\n',
        b'{"a":NaN}\n',
        b'{"a":Infinity}\n',
        b'{"a":1} trailing\n',
        b'{ "a":1}\n',
        b'{"a":1}',
        b'{"a":1}\n\n',
        b'\xff\n',
        b'',
    )
    for candidate in hostile:
        expect_raises(codec.CampaignCodecError, codec.load_canonical_bytes, candidate)
    for value in (1.5, float("nan"), {"x": object()}, {1: "x"}):
        expect_raises(codec.CampaignCodecError, codec.canonical_bytes, value)

    class DictSubclass(dict):
        pass

    class ListSubclass(list):
        pass

    for value in (DictSubclass(a=1), ListSubclass([1])):
        expect_raises(codec.CampaignCodecError, codec.canonical_bytes, value)
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, {"x": "a" * (codec.MAX_STRING_BYTES + 1)})
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, {"k" * (codec.MAX_KEY_BYTES + 1): 1})
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, list(range(codec.MAX_ARRAY_ITEMS + 1)))
    expect_raises(
        codec.CampaignCodecError,
        codec.canonical_bytes,
        [[0] * 20 for _ in range(codec.MAX_ARRAY_ITEMS)],
    )
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, {str(index): index for index in range(codec.MAX_OBJECT_PROPERTIES + 1)})
    nested = None
    for _ in range(codec.MAX_DEPTH + 1):
        nested = [nested]
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, nested)
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, 2**64)
    expect_raises(codec.CampaignCodecError, codec.canonical_bytes, {"bad": "\ud800"})
    expect_raises(codec.CampaignCodecError, codec.load_canonical_bytes, bytearray(b"{}\n"))
    expect_raises(codec.CampaignCodecError, codec.load_canonical_bytes, b"[" + b"0" * codec.MAX_CANONICAL_BYTES)

    salt = bytes(range(32))
    first = codec.commitment_sha256("cogs.campaign/test-a/v1", {"x": 1}, salt)
    require(first == codec.commitment_sha256("cogs.campaign/test-a/v1", {"x": 1}, salt))
    require(first != codec.commitment_sha256("cogs.campaign/test-b/v1", {"x": 1}, salt))
    require(first != codec.commitment_sha256("cogs.campaign/test-a/v1", {"x": 2}, salt))
    require(first != codec.commitment_sha256("cogs.campaign/test-a/v1", {"x": 1}, b"x" * 32))
    expect_raises(codec.CampaignCodecError, codec.commitment_sha256, "bad domain", {}, salt)
    expect_raises(codec.CampaignCodecError, codec.commitment_sha256, "cogs.campaign/test/v1", {}, b"short")


def contract_matrix():
    first = make_record((), Event.BATCH_ADMITTED, None, None, Outcome.ACCEPTED)
    require(first.version == CONTROLLER_EVENT_VERSION)
    require(record_from_canonical_bytes(first.canonical_bytes()) == first)
    require(record_from_mapping(first.as_dict()) == first)
    require(first.sha256() == hashlib.sha256(first.canonical_bytes()).hexdigest())
    for mutation in (
        {**first.as_dict(), "extra": True},
        {key: value for key, value in first.as_dict().items() if key != "outcome"},
        {**first.as_dict(), "event": "RETRY"},
        {**first.as_dict(), "cycle_mode": "alternate"},
    ):
        expect_raises(CampaignContractError, record_from_mapping, mutation)
    expect_raises(CampaignContractError, record_from_mapping, type("D", (dict,), {})(first.as_dict()))
    for ordinal, mode in enumerate(CYCLE_MODES, 1):
        record = new_record(
            batch_commitment=BATCH,
            sequence=ordinal,
            event=Event.CYCLE_OPENED,
            cycle_ordinal=ordinal,
            cycle_mode=mode,
            prior_record_sha256=ZERO_SHA256,
            payload_sha256=digest(f"contract:{ordinal}"),
            monotonic_observation_ns=ordinal,
            wall_observation_unix_ns=ordinal,
            outcome=Outcome.ACCEPTED,
            uncertainty=Uncertainty.CLEAR,
        )
        require(record.cycle_mode is (CycleMode.FULL if ordinal == 1 else CycleMode.READINESS))
    expect_raises(
        CampaignContractError,
        new_record,
        batch_commitment=BATCH,
        sequence=1,
        event=Event.CYCLE_OPENED,
        cycle_ordinal=1,
        cycle_mode=CycleMode.READINESS,
        prior_record_sha256=ZERO_SHA256,
        payload_sha256=digest("wrong-mode"),
        monotonic_observation_ns=1,
        wall_observation_unix_ns=1,
        outcome=Outcome.ACCEPTED,
        uncertainty=Uncertainty.CLEAR,
    )


def happy_path_matrix():
    records = happy_records()
    state = reduce_campaign(records)
    require(len(records) == len(HAPPY_PATH) == 103)
    require(state.terminal and state.status == "sealed" and state.success_possible and state.success_eligible)
    require(not state.failure_recorded and state.uncertainty is Uncertainty.CLEAR)
    require(not state.retry_authorized and state.next_event is None)
    require(tuple((record.event, record.cycle_ordinal, record.cycle_mode) for record in records) == HAPPY_PATH)
    require([record.cycle_mode for record in records if record.event is Event.CYCLE_OPENED] == list(CYCLE_MODES))
    require(sum(record.event is Event.PLAN_INTENT for record in records) == 7)
    require(sum(record.event is Event.APPLY_INTENT for record in records) == 7)
    require(sum(record.event is Event.REMOTE_INTENT for record in records) == 7)
    require(sum(record.event is Event.DESTROY_INTENT for record in records) == 7)
    require(sum(record.event is Event.ZERO_OBSERVATION_INTENT for record in records) == 7)
    require(sum(record.event is Event.FINAL_ZERO_OBSERVATION_INTENT for record in records) == 1)
    expect_raises(CampaignStateError, append_record, records, records[-1])
    expect_raises(CampaignStateError, reduce_campaign, (*records, records[-1]))
    for ordinal in range(2, 8):
        opened = next(index for index, row in enumerate(records) if row.event is Event.CYCLE_OPENED and row.cycle_ordinal == ordinal)
        prior_seal = next(index for index, row in enumerate(records) if row.event is Event.CYCLE_SEALED and row.cycle_ordinal == ordinal - 1)
        require(opened == prior_seal + 1)


def exhaustive_normal_transition_matrix():
    happy = happy_records()
    for length in range(len(HAPPY_PATH)):
        prefix = happy[:length]
        state = reduce_campaign(prefix)
        if length == 0:
            require(state.next_event is Event.BATCH_ADMITTED)
        expected = HAPPY_PATH[length]
        require((state.next_event, state.next_cycle_ordinal, state.next_cycle_mode) == expected)
        require(state.success_possible and not state.success_eligible)
        accepted = make_record(prefix, *expected, normal_outcome(expected[0]), label=f"accepted:{length}")
        append_record(prefix, accepted)
        if length > 0:
            append_failure(prefix, label=f"legal-failure:{length}")
        for candidate_index, candidate in enumerate(HAPPY_PATH):
            if candidate == expected:
                continue
            event, ordinal, mode = candidate
            record = make_record(
                prefix,
                event,
                ordinal,
                mode,
                normal_outcome(event),
                label=f"wrong:{length}:{candidate_index}",
            )
            expect_raises(CampaignStateError, append_record, prefix, record)


def exhaustive_failure_cut_matrix():
    happy = happy_records()
    for uncertain in (False, True):
        for length in range(1, len(HAPPY_PATH)):
            prefix = happy[:length]
            failed = append_failure(prefix, uncertain, f"cut:{uncertain}:{length}")
            failure_index = len(prefix)
            settled = settle_failure(failed)
            state = reduce_campaign(settled)
            require(state.terminal and not state.success_possible and not state.success_eligible and state.failure_recorded)
            require(state.uncertainty is (Uncertainty.STICKY if uncertain else Uncertainty.CLEAR))
            require(settled[-1].event is (Event.TERMINAL_UNCERTAIN_SEALED if uncertain else Event.TERMINAL_FAILURE_SEALED))
            suffix = settled[failure_index + 1 :]
            require(not any(record.event in {Event.CYCLE_OPENED, Event.PLAN_INTENT, Event.APPLY_INTENT, Event.REMOTE_INTENT} for record in suffix))
            require(sum(record.event is Event.DESTROY_INTENT for record in settled) <= 7)
            active = active_cycle(prefix)
            if active is not None:
                ordinal = active[0]
                apply_intended = any(record.event is Event.APPLY_INTENT and record.cycle_ordinal == ordinal for record in prefix)
                destroy_intents = [record for record in suffix if record.event is Event.DESTROY_INTENT]
                already_destroyed = any(record.event is Event.DESTROY_SETTLED and record.cycle_ordinal == ordinal for record in prefix)
                destroy_already_intended = any(
                    record.event is Event.DESTROY_INTENT and record.cycle_ordinal == ordinal for record in prefix
                )
                require(
                    len(destroy_intents)
                    == (1 if apply_intended and not already_destroyed and not destroy_already_intended else 0)
                )
                require(sum(record.event is Event.ZERO_OBSERVATION_INTENT for record in suffix) <= 1)
            else:
                require(not any(record.event is Event.DESTROY_INTENT for record in suffix))
                require(sum(record.event is Event.FINAL_ZERO_OBSERVATION_INTENT for record in suffix) <= 1)
            expect_raises(CampaignStateError, append_record, settled, settled[-1])


def cleanup_hostility_matrix():
    happy = happy_records()
    apply_cut = next(index for index, row in enumerate(happy) if row.event is Event.APPLY_INTENT) + 1
    for destroy in (Outcome.ACCEPTED, Outcome.FAILED, Outcome.UNCERTAIN):
        for zero in (Outcome.ZERO, Outcome.NONZERO, Outcome.UNCERTAIN):
            records = append_failure(happy[:apply_cut], label=f"cleanup:{destroy}:{zero}")
            records = settle_failure(records, destroy, zero)
            expected_sticky = destroy is not Outcome.ACCEPTED or zero is not Outcome.ZERO
            require(reduce_campaign(records).uncertainty is (Uncertainty.STICKY if expected_sticky else Uncertainty.CLEAR))
            require(sum(row.event is Event.DESTROY_INTENT for row in records[apply_cut + 1 :]) == 1)
            require(sum(row.event is Event.ZERO_OBSERVATION_INTENT for row in records[apply_cut + 1 :]) == 1)
            require(records[-1].event is (Event.TERMINAL_UNCERTAIN_SEALED if expected_sticky else Event.TERMINAL_FAILURE_SEALED))

    before_apply = next(index for index, row in enumerate(happy) if row.event is Event.APPLY_INTENT)
    records = append_failure(happy[:before_apply], label="before-apply")
    require(reduce_campaign(records).next_event is Event.ZERO_OBSERVATION_INTENT)
    wrong = make_record(
        records,
        Event.DESTROY_INTENT,
        1,
        CycleMode.FULL,
        Outcome.INTENDED,
        label="forbidden-destroy",
    )
    expect_raises(CampaignStateError, append_record, records, wrong)

    records = append_failure(happy[:apply_cut], label="destroy-no-retry")
    records = append_next(records)
    records = append_next(records, Outcome.UNCERTAIN)
    require(reduce_campaign(records).next_event is Event.ZERO_OBSERVATION_INTENT)
    second_destroy = make_record(
        records,
        Event.DESTROY_INTENT,
        1,
        CycleMode.FULL,
        Outcome.INTENDED,
        label="second-destroy",
    )
    expect_raises(CampaignStateError, append_record, records, second_destroy)


def chain_hostility_matrix():
    records = happy_records()[:8]
    mutations = (
        replace(records[1], sequence=records[1].sequence + 1),
        replace(records[1], batch_commitment=digest("cross-batch")),
        replace(records[1], prior_record_sha256=digest("broken-prior")),
        replace(records[1], payload_sha256=records[0].payload_sha256),
        replace(records[1], monotonic_observation_ns=0),
        replace(records[1], wall_observation_unix_ns=0),
        replace(records[1], uncertainty=Uncertainty.STICKY),
    )
    for mutation in mutations:
        candidate = list(records)
        candidate[1] = mutation
        expect_raises(CampaignStateError, reduce_campaign, tuple(candidate))
    expect_raises(CampaignStateError, reduce_campaign, tuple(records[1:]))
    expect_raises(CampaignStateError, reduce_campaign, (object(),))
    expect_raises(CampaignStateError, reduce_campaign, list(records))
    expect_raises(CampaignStateError, reduce_campaign, type("T", (tuple,), {})(records))


def filesystem_matrix():
    with tempfile.TemporaryDirectory(prefix="cogs-campaign-codec-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            value = make_record((), Event.BATCH_ADMITTED, None, None, Outcome.ACCEPTED).as_dict()
            raw = codec.canonical_bytes(value)
            (root / "good.json").write_bytes(raw)
            (root / "good.json").chmod(0o400)
            require(codec.load_canonical_file_at(descriptor, "good.json") == value)
            expect_raises(
                codec.CampaignCodecError,
                codec.load_canonical_file_at,
                descriptor,
                "good.json",
                owner_uid=os.geteuid() + 1,
            )
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "../good.json")
            original_read_all = codec._read_all

            def replace_during_read(opened, maximum):
                observed_raw = original_read_all(opened, maximum)
                os.unlink(root / "good.json")
                (root / "good.json").write_bytes(raw)
                (root / "good.json").chmod(0o400)
                return observed_raw

            with mock.patch.object(codec, "_read_all", side_effect=replace_during_read):
                expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "good.json")
            require(codec.load_canonical_file_at(descriptor, "good.json") == value)

            (root / "wrong-mode.json").write_bytes(raw)
            (root / "wrong-mode.json").chmod(0o600)
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "wrong-mode.json")
            os.symlink("good.json", root / "symlink.json")
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "symlink.json")
            os.link(root / "good.json", root / "hardlink.json")
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "hardlink.json")
            os.unlink(root / "hardlink.json")
            (root / "noncanonical.json").write_bytes(b'{ "x":1}\n')
            (root / "noncanonical.json").chmod(0o400)
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "noncanonical.json")
            root.chmod(0o755)
            expect_raises(codec.CampaignCodecError, codec.load_canonical_file_at, descriptor, "good.json")
            root.chmod(0o700)

            if platform.system() == "Linux":
                published = "000001-BATCH_ADMITTED.json"
                require(codec.publish_record_at(descriptor, published, value) == hashlib.sha256(raw).hexdigest())
                observed = os.stat(published, dir_fd=descriptor, follow_symlinks=False)
                require(stat.S_IMODE(observed.st_mode) == 0o400 and observed.st_nlink == 1)
                require(codec.load_canonical_file_at(descriptor, published) == value)
                expect_raises(
                    codec.CampaignCodecError,
                    codec.publish_record_at,
                    descriptor,
                    "000002-BATCH_ADMITTED.json",
                    value,
                )

                def fault_directory(label):
                    path = root / label
                    path.mkdir(mode=0o700)
                    return path, os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

                for label, target, side_effect in (
                    ("write-fault", codec.os, ("write", OSError("fake full disk"))),
                    ("file-fsync-fault", codec.os, ("fsync", OSError("fake file fsync"))),
                    (
                        "rename-fault",
                        codec,
                        ("_rename_noreplace", codec.CampaignPublicationUncertain("fake rename")),
                    ),
                ):
                    path, fault_fd = fault_directory(label)
                    try:
                        attribute, error = side_effect
                        with mock.patch.object(target, attribute, side_effect=error):
                            expect_raises(
                                codec.CampaignPublicationUncertain,
                                codec.publish_record_at,
                                fault_fd,
                                published,
                                value,
                            )
                        require(any(name.startswith(".staging-") for name in os.listdir(path)))
                    finally:
                        os.close(fault_fd)

                path, create_fd = fault_directory("create-fault")
                try:
                    with mock.patch.object(codec.os, "open", side_effect=OSError("fake create")):
                        expect_raises(
                            codec.CampaignPublicationUncertain,
                            codec.publish_record_at,
                            create_fd,
                            published,
                            value,
                        )
                    require(os.listdir(path) == [])
                finally:
                    os.close(create_fd)

                path, parent_fsync_fd = fault_directory("parent-fsync-fault")
                try:
                    with mock.patch.object(codec.os, "fsync", side_effect=[None, OSError("fake parent fsync")]):
                        expect_raises(
                            codec.CampaignPublicationUncertain,
                            codec.publish_record_at,
                            parent_fsync_fd,
                            published,
                            value,
                        )
                    require((path / published).is_file())
                finally:
                    os.close(parent_fsync_fd)

                path, stale_fd = fault_directory("stale-staging")
                try:
                    (path / ".staging-preserved").write_bytes(b"partial")
                    expect_raises(
                        codec.CampaignPublicationUncertain,
                        codec.publish_record_at,
                        stale_fd,
                        published,
                        value,
                    )
                    require((path / ".staging-preserved").read_bytes() == b"partial")
                finally:
                    os.close(stale_fd)

                before = set(os.listdir(root))
                expect_raises(codec.CampaignPublicationUncertain, codec.publish_record_at, descriptor, published, value)
                after = set(os.listdir(root))
                require(any(name.startswith(".staging-") for name in after - before))
        finally:
            os.close(descriptor)


def static_no_effect_surface():
    for name in (
        "completion_campaign_codec.py",
        "completion_campaign_contracts.py",
        "completion_campaign_state.py",
    ):
        source = (ROOT / "deploy/aws-feasibility" / name).read_text()
        for forbidden in (
            "import subprocess",
            "import socket",
            "import boto",
            "import requests",
            "import urllib",
            "os.system(",
        ):
            require(forbidden not in source.lower(), f"{name}: forbidden surface {forbidden}")


def main():
    codec_matrix()
    contract_matrix()
    happy_path_matrix()
    exhaustive_normal_transition_matrix()
    exhaustive_failure_cut_matrix()
    cleanup_hostility_matrix()
    chain_hostility_matrix()
    filesystem_matrix()
    static_no_effect_surface()
    print("fake-only completion campaign Slice A exhaustive matrix passed")


if __name__ == "__main__":
    main()

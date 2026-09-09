#!/usr/bin/env python3
"""Portable commitment check for no-mint rehearsal grants."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
spec = importlib.util.spec_from_file_location(
    "stage2_prebuilt_rehearsal_grant_test",
    ROOT / "scripts/stage2-prebuilt-rehearsal-grant.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
import completion_campaign_production as production

fixed = {"implementation_revision": "1" * 40,
         "control_revision": "2" * 40,
         "static_control_sha256": "3" * 64,
         "rootfs_descriptor_sha256": "4" * 64}
for route in ("full", "readiness"):
    value = module.grant_value(route, "123", fixed); value.pop("version")
    production.CycleLaunchGrant(**value)

# Selection-only retirement: hostile direct entries, no real effect commands.
import copy
import io
import json
import os
import runpy
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout

retirement = runpy.run_path(str(ROOT / "scripts/stage2-revision-retirement.py"))
retired = tuple(retirement["REVISIONS"])
fresh = "a" * 40

def veto(call):
    try:
        call()
    except ValueError as error:
        assert type(error).__name__ == "RetirementError", type(error)
    else:
        raise AssertionError("retirement veto missing")

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "policy.json"
    good = retirement["POLICY"].read_bytes()
    bad = [b"", b"{", b"[]", b"null", b"{}", b"x" * 4097, b'{"version":NaN}',
           b'{"version":1,"version":2}', b'[' * 1100 + b']' * 1100, b'\xff']
    policy = json.loads(good)
    for group in ("revisions", "runs", "artifacts"):
        changed = copy.deepcopy(policy); changed[group].pop(next(iter(changed[group]))); bad.append(json.dumps(changed).encode())
        changed = copy.deepcopy(policy); changed[group] = []; bad.append(json.dumps(changed).encode())
    for sha in (True, None, 123, retired[0].upper(), retired[0] + "0", "z" * 40):
        veto(lambda sha=sha: retirement["select"]((sha,)))
    for raw in bad:
        path.write_bytes(raw); veto(lambda: retirement["select"]((fresh,), policy=path))
    path.unlink(); veto(lambda: retirement["select"]((fresh,), policy=path))
    path.symlink_to(retirement["POLICY"]); veto(lambda: retirement["select"]((fresh,), policy=path))
    path.unlink(); path.write_bytes(good)
    retirement["select"]((fresh,), policy=path)
    for sha in retired:
        for position in range(3):
            selected = [fresh] * 3; selected[position] = sha
            veto(lambda: retirement["select"](selected))
    for kind in ("runs", "artifacts"):
        for identity in policy[kind]:
            veto(lambda: retirement["select"]((fresh,), **{kind: (identity,)}))
    # No git/ancestor inspection exists: a selected descendant is not its parent.
    assert "subprocess" not in (ROOT / "scripts/stage2-revision-retirement.py").read_text()
    retirement["select"]((fresh,))

producer = load("stage2-prebuilt-rootfs-producer")
publisher = load("stage2-prebuilt-rootfs-publisher")
formal = load("stage2-formal-local-qualification")
guard = load("stage2-prebuilt-local-qualification-guard")
lock = load("stage2-prebuilt-kvm-diagnostic-lock")
staging = load("stage2-stage-prebuilt-control")
expected = {name: "1" * 64 for name in ("EXPECTED_SOURCE_MANIFEST_SHA256", "EXPECTED_CONTROL_SHA256",
    "EXPECTED_WORKFLOW_SHA256", "EXPECTED_RESULT_SCHEMA_SHA256", "EXPECTED_ROOTFS_DESCRIPTOR_SHA256")}
expected.update(EXPECTED_IMPLEMENTATION_HEAD=fresh, EXPECTED_CONTROL_HEAD="b" * 40,
    EXPECTED_QUALIFICATION_HEAD="c" * 40, EXPECTED_STATIC_CONTROL_RUN_ID="11",
    EXPECTED_STATIC_CONTROL_ARTIFACT_ID="12", EXPECTED_STATIC_CONTROL_ARTIFACT_DIGEST="sha256:" + "1" * 64,
    EXPECTED_MIXED_PREFLIGHT_RUN_ID="13", GITHUB_RUN_ID="14", GITHUB_RUN_ATTEMPT="1")
for sha in retired:
    for field in ("implementation_revision", "control_revision"):
        veto(lambda: module.grant_value("full", "123", {**fixed, field: sha}))
    with patch.dict(os.environ, {"COGS_STAGE2_PREBUILT_PRODUCER_H": sha, "GITHUB_RUN_ID": "123"}, clear=True), patch.object(os, "geteuid", return_value=0), patch.object(sys, "argv", ["producer"]):
        veto(producer.main)  # No manifest read, acquisition or product creation.
    with patch.dict(os.environ, {"COGS_PREBUILT_H": sha, "EXACT_H": sha, "GITHUB_SHA": fresh,
                                "PRODUCER_RUN_ID": "123", "PRODUCER_ARTIFACT_ID": "124"}, clear=True):
        veto(publisher.validate_candidate); veto(publisher.issue_descriptor)
    for field in ("EXPECTED_IMPLEMENTATION_HEAD", "EXPECTED_CONTROL_HEAD", "EXPECTED_QUALIFICATION_HEAD", "GITHUB_SHA"):
        hostile = {**expected, field: sha}
        veto(lambda: formal.expected_environment(hostile))
        veto(lambda: formal.issue_grant(1, hostile, SimpleNamespace(issue=lambda _: (_ for _ in ()).throw(AssertionError("mint reached")))))
    for field in ("EXACT_IMPLEMENTATION_HEAD", "EXACT_CONTROL_HEAD", "EXACT_QUALIFICATION_HEAD", "GITHUB_SHA"):
        env = dict.fromkeys(("EXACT_IMPLEMENTATION_HEAD", "EXACT_CONTROL_HEAD", "EXACT_QUALIFICATION_HEAD", "GITHUB_SHA"), fresh)
        env[field] = sha
        veto(lambda: guard.guard(env, event={"inputs": dict(env)}, first_created=123))
    with patch.dict(os.environ, {"GITHUB_SHA": sha}, clear=True):
        veto(lock.select_runtime)
        with patch.dict(lock.retirement, {"document": lambda *_: ({"revision": sha}, b"{}")}):
            veto(lambda: lock.materialize("descriptor")); veto(lambda: lock.materialize("adjuncts"))

# Missing/malformed policy also blocks otherwise unretired direct callers.
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "missing-policy.json"
    env = dict(COGS_STAGE2_PREBUILT_PRODUCER_H=fresh, EXACT_H=fresh, GITHUB_SHA=fresh,
        COGS_PREBUILT_H=fresh, PRODUCER_RUN_ID="123", PRODUCER_ARTIFACT_ID="124", GITHUB_RUN_ID="125",
        EXACT_IMPLEMENTATION_HEAD=fresh, EXACT_CONTROL_HEAD="b" * 40, EXACT_QUALIFICATION_HEAD="c" * 40)
    calls = [(producer, producer.main), (publisher, publisher.validate_candidate),
        (publisher, publisher.issue_descriptor), (formal, lambda: formal.issue_grant(1, expected)),
        (guard, lambda: guard.guard(env)), (lock, lock.select_runtime),
        (module, lambda: module.grant_value("full", "123", fixed))]
    for raw in (None, b"{"):
        if raw is not None: path.write_bytes(raw)
        for subject, call in calls:
            with patch.object(subject.retirement["select"], "__defaults__", ((), (), path)), patch.dict(os.environ, env, clear=True), patch.object(os, "geteuid", return_value=0), patch.object(sys, "argv", ["test"]):
                veto(call)
    # ADR0327's historical H/G selection remains rejected even after Q binds
    # the fresh generation. Patch only this fixture's selected identities.
    with patch.multiple(guard,
            REVIEWED_IMPLEMENTATION_HEAD="c10fc103532f3e3a8b746727bd0f48c6d8498148",
            REVIEWED_CONTROL_HEAD="eb59cae18e0f041a243f35f253d46713f7e87142"):
        assert policy["revisions"][guard.REVIEWED_IMPLEMENTATION_HEAD] == "ADR0327"
        assert policy["revisions"][guard.REVIEWED_CONTROL_HEAD] == "ADR0327"
        veto(lambda: guard.guard(env))

# Historical interpretation is still available even when selection is vetoed.
with patch.dict(lock.retirement, {"select": lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("decode gated"))}):
    locked, raws = lock.load_lock()

# Authenticated custody checks precede destination creation for all staging modes.
with tempfile.TemporaryDirectory() as directory:
    source, destination = Path(directory), Path(directory) / "destination"
    descriptor = json.loads(raws["descriptor.json"])
    custody = {"provenance": json.loads(raws["rootfs.provenance.json"]),
               "qualification_receipt": json.loads(raws["producer-receipt.json"]),
               "publication_receipt": json.loads(raws["publication-receipt.json"])}
    rootfs = {"custody": custody, "prebuilt_descriptor": descriptor}
    for target in ("SOURCE", "QUALIFICATION_SOURCE", "PROVISIONAL_SOURCE"):
        for diagnostic in ((None, staging.DIAGNOSTIC_VERSION) if target == "PROVISIONAL_SOURCE" else (None,)):
            control = {"members": [{"name": "envelope.json", "kind": "envelope", "size": 2}],
                       "implementation": {"revision": fresh}, "runtime_implementation": {"revision": fresh},
                       "producer": {"control_revision": lock.CONTROL},
                       "publication_producer": {"control_revision": lock.CONTROL}, "rootfs": rootfs}
            codec = SimpleNamespace(MAX_BYTES=4096, MAX_CONTROL_BYTES=4096, MAX_ENVELOPE_BYTES=4096,
                MAX_RUNTIME_BYTES=4096, MAX_CONTRACT_BYTES=4096, load_control=lambda _: SimpleNamespace(value=control),
                validate_control_members=lambda *_: (SimpleNamespace(value={"rootfs": rootfs}), None, None))
            codec.preparation = codec
            with patch.object(staging, target, source), patch.object(staging, "DESTINATION", destination), patch.object(os, "geteuid", return_value=0), patch.object(staging, "_load_module", return_value=codec), patch.object(staging, "_open_source", side_effect=lambda _: os.open(source, os.O_RDONLY)), patch.object(staging, "_read_regular", return_value=b"{}"):
                for container, field, value in ((control["implementation"], "revision", retired[0]),
                    (control["runtime_implementation"], "revision", retired[0]),
                    (control["producer" if diagnostic is None else "publication_producer"], "control_revision", retired[2]),
                    (descriptor["producer"], "revision", retired[0]),
                    (custody["provenance"]["builder"], "implementation_revision", retired[0]),
                    (custody["publication_receipt"], "control_revision", retired[2]),
                    (custody["publication_receipt"], "producer_run_id", 34028384783),
                    (custody["publication_receipt"], "producer_artifact_id", 9988125363)):
                    if container is control["implementation"] and diagnostic is not None: continue
                    if container is control["runtime_implementation"] and diagnostic is None: continue
                    with patch.dict(container, {field: value}):
                        veto(lambda: staging._stage(source, diagnostic))
                    assert not destination.exists(), "retired staging created destination"
                for raw in (None, b"{"):
                    bad_policy = source / "missing-policy.json"
                    if raw is None:
                        bad_policy.unlink(missing_ok=True)
                    else:
                        bad_policy.write_bytes(raw)
                    with patch.object(staging.retirement["select"], "__defaults__", ((), (), bad_policy)):
                        veto(lambda: staging._stage(source, diagnostic))
                    assert not destination.exists()
    # Directory custody rejects matching H/provenance as well as stale producer IDs.
    for name, raw in raws.items(): (source / name).write_bytes(raw)
    retirement["custody"](source, lock.IMPLEMENTATION, lock.CONTROL)
    for sha in retired:
        changed = copy.deepcopy(custody["provenance"]); changed["builder"]["implementation_revision"] = sha
        (source / "rootfs.provenance.json").write_text(json.dumps(changed))
        veto(lambda: retirement["custody"](source, lock.IMPLEMENTATION, lock.CONTROL))

print("stage2 prebuilt rehearsal grant checks passed")

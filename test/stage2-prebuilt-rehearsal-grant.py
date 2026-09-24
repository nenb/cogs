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
    bad = [b"", b"{", b"[]", b"null", b"{}", b"x" * 16385, b'{"version":NaN}',
           b'{"version":1,"version":2}', b'[' * 1100 + b']' * 1100, b'\xff']
    policy = json.loads(good)
    assert policy["version"] == "cogs.stage2-retired-revisions/v8" and policy["predecessor"] == {"version": "cogs.stage2-retired-revisions/v7", "sha256": "d0d74eab6a47062db91a1e0e45aa1fae102614a3f5253253450bb11336c96d1c"} and policy["revisions"]["4ffdeb435cc8cd053d47ab173b942ec0f99cd3b4"] == policy["runs"]["35822851712"] == "ADR0363"
    assert all(policy["revisions"][value] == "ADR0364" for value in ("8e9328c66a1ab930583e22f07ba6f17f23bc7d2e", "f82c9e77acbd8cf1f963a46d73a9e70afb6f41d6", "6d2eff8ffa8fe525b5566a0ddded7d79e868ba16", "c075458cf2d853200df57584c1b16cf38bd6e38c", "f75d3f09990de4635cc3890efe0f5f6e783312bd"))
    assert all(policy["runs"][value] == "ADR0364" for value in ("35928408355", "35938320143", "35938533499", "35946454149"))
    assert all(policy["artifacts"][value] == "ADR0364" for value in ("10780807449", "10783357865", "10784336353"))
    assert policy["revisions"]["56fdd694c1a0c6967bf09156d44260f18a28888d"] == "ADR0365"
    assert policy["runs"]["35957236430"] == "ADR0365"
    assert policy["artifacts"]["10791707159"] == "ADR0365"
    adr_path = ROOT / "docs/adr/0365-retire-premature-producer-and-require-replacement-H.md"; adr = " ".join(adr_path.read_text().split())
    required = ("while both required exact-main runs were still in progress", "later success cannot retroactively authorize the producer", "cannot be retried, resumed, stitched, reinterpreted, republished", "predecessor-bound retirement policy V8", "preserve V1 through V7 byte-for-byte", "all twelve Stage 2 workflows", "one commit whose sole parent is terminal `56fdd694c1a0c6967bf09156d44260f18a28888d`", "wait until every required fresh exact-H main CI and Linux-foundations check has completed successfully", "ADR 0366 may establish only G", "ADR 0367 may establish only Q", "Move 250,000 bytes zero-sum from `product` to `readiness-ci`", "move four lines zero-sum from `product` to `readiness-ci`", "reserves two additional complete serialized source-inventory generations plus each regeneration's three readiness, three governance, and one product line", "grants no G, publisher, static observation, Q")
    assert all(value in adr for value in required) and "accepted producer run" not in adr
    assert "[0365](0365-retire-premature-producer-and-require-replacement-H.md)" in (ROOT / "docs/adr/README.md").read_text()
    g_path = ROOT / "docs/adr/0366-freeze-replacement-H-and-authorize-control.md"; g_adr = " ".join(g_path.read_text().split())
    assert all(value in g_adr for value in ("ba085947eaee321dfb724d94169d42bc36d397b0", "35984488769", "35984488928", "Only afterwards", "35990583990", "10804234912", "sha256:384d3e5ff819fa706bd6e793e29d2b7ab71b33f339ccec89c57248db7bf2b88c", "one commit whose sole parent is exact H", "exactly one first-created attempt-one trusted publisher", "exactly one first-created attempt-one no-KVM static observation", "docs/adr/0367-establish-replacement-Q-and-authorize-qualification.md", "reducing `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS` from 2 to 1", "grants no mixed preflight, qualification, IAM, AWS credentials"))
    assert "[0366](0366-freeze-replacement-H-and-authorize-control.md)" in (ROOT / "docs/adr/README.md").read_text() and not (ROOT / "docs/adr/0367-establish-replacement-Q-and-authorize-qualification.md").exists()
    assert policy["revisions"]["9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e"] == "ADR0348"
    assert policy["runs"]["34831612221"] == "ADR0348"
    assert policy["revisions"]["5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c"] == "ADR0353"
    assert policy["revisions"]["4452a96acb1ad31ea8f6b242334f258ce0b0abab"] == "ADR0353"
    assert policy["runs"]["35562735335"] == "ADR0353"
    assert policy["runs"]["35572729553"] == "ADR0353"
    assert policy["runs"]["35573039122"] == "ADR0353"
    assert policy["artifacts"]["10622494382"] == "ADR0353"
    assert policy["artifacts"]["10627325100"] == "ADR0353"
    assert policy["revisions"]["d98571b9f2be446ed478464d23df532d91b94e53"] == "ADR0357"
    assert policy["revisions"]["431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33"] == "ADR0357"
    assert policy["revisions"]["17380562a9fb9f7d08bea0269a9fdc5812b1faf7"] == "ADR0357"
    assert policy["runs"]["35685410662"] == "ADR0357"
    assert policy["artifacts"]["10678755703"] == "ADR0357"
    assert policy["artifacts"]["10677874983"] == "ADR0357"
    assert policy["revisions"]["306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c"] == "ADR0360"
    assert policy["revisions"]["21848f84f01d42f28ce2f6f2a177bfe62af8fc58"] == "ADR0360"
    assert policy["runs"]["35716917245"] == "ADR0360"
    assert policy["runs"]["35732877526"] == "ADR0360"
    assert policy["runs"]["35733919360"] == "ADR0360"
    assert policy["artifacts"]["10690851656"] == "ADR0360"
    assert policy["artifacts"]["10696531175"] == "ADR0360"
    assert retirement["POLICY_V1"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v1.json").read_bytes()
    assert retirement["POLICY_V2"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v2.json").read_bytes()
    assert retirement["POLICY_V3"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v3.json").read_bytes()
    assert retirement["POLICY_V4"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v4.json").read_bytes()
    assert retirement["POLICY_V5"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v5.json").read_bytes()
    assert retirement["POLICY_V6"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v6.json").read_bytes()
    assert retirement["POLICY_V7"].read_bytes() == (ROOT / "config/stage2-retired-revisions-v7.json").read_bytes()
    changed = copy.deepcopy(policy); changed["predecessor"]["sha256"] = "0" * 64
    bad.append(json.dumps(changed).encode())
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

mirror_suffix = ("9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e|34831612221|"
                 "5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c|4452a96acb1ad31ea8f6b242334f258ce0b0abab|"
                 "35562735335|35572729553|35573039122|10622494382|10627325100|"
                 "d98571b9f2be446ed478464d23df532d91b94e53|431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33|"
                 "17380562a9fb9f7d08bea0269a9fdc5812b1faf7|35638724656|35670440520|35670986936|"
                 "35684568600|35685410662|10658466954|10670334621|10670965964|10678755703|"
                 "10677962970|10678201915|10678118928|10677629335|10678169602|10677874983|"
                 "306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c|21848f84f01d42f28ce2f6f2a177bfe62af8fc58|"
                 "35716917245|35732877526|35733919360|10690851656|10696531175|2076c2bd781a663d2b27fa478792fc133fa9fd42|1956ea8da439de2ae137e6ccbc5650ca149fe815|4ffdeb435cc8cd053d47ab173b942ec0f99cd3b4|35795093115|35810787971|35811001315|35822851712|10724846408|10729183411|10729578379|8e9328c66a1ab930583e22f07ba6f17f23bc7d2e|f82c9e77acbd8cf1f963a46d73a9e70afb6f41d6|6d2eff8ffa8fe525b5566a0ddded7d79e868ba16|c075458cf2d853200df57584c1b16cf38bd6e38c|f75d3f09990de4635cc3890efe0f5f6e783312bd|35928408355|35938320143|35938533499|35946454149|10780807449|10783357865|10784336353|56fdd694c1a0c6967bf09156d44260f18a28888d|35957236430|10791707159)")
mirrors = [path for path in (ROOT / ".github/workflows").glob("*.yml")
           if mirror_suffix in path.read_text()]
assert len(mirrors) == 12
assert sum(path.read_text().count(mirror_suffix) for path in mirrors) == 19

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
            REVIEWED_CONTROL_HEAD="eb59cae18e0f041a243f35f253d46713f7e87142",
            REVIEWED_IMPLEMENTATION_MANIFEST_SHA256="1" * 64,
            REVIEWED_CONTROL_SHA256="2" * 64,
            REVIEWED_ROOTFS_DESCRIPTOR_SHA256="3" * 64,
            REVIEWED_STATIC_CONTROL_RUN_ID=123,
            REVIEWED_STATIC_CONTROL_ARTIFACT_ID=124,
            REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST="sha256:" + "4" * 64):
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

#!/usr/bin/env python3
"""Portable pure tests for the ADR0047 Phase A candidate runner."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run-stage2-phase-a-candidate.py"
spec = importlib.util.spec_from_file_location("stage2_phase_a_candidate", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

BUDGET = ROOT / "scripts/stage2-phase-a-budget.py"
budget_spec = importlib.util.spec_from_file_location("stage2_phase_a_budget", BUDGET)
assert budget_spec is not None and budget_spec.loader is not None
budget = importlib.util.module_from_spec(budget_spec)
budget_spec.loader.exec_module(budget)


def rejected(callback):
    try:
        callback()
    except module.CandidateError:
        return
    raise AssertionError("hostile candidate input accepted")


def failure_code(callback):
    try:
        callback()
    except module.CandidateError as error:
        return error.code
    raise AssertionError("expected candidate failure")


def budget_rejected(callback):
    try:
        callback()
    except budget.BudgetError:
        return
    raise AssertionError("hostile scheduling budget accepted")


def expect_oserror(callback):
    try:
        callback()
    except OSError:
        return
    raise AssertionError("expected injected descriptor failure")


assert budget.BOUNDARIES == {
    "source": 600, "observe": 3900, "cleanup": 5100, "residue": 5160, "render": 5200,
    "validate": 5240, "export": 5280, "upload": 5290, "export-cleanup": 5380,
    "post-export-residue-start": 5380, "post-export-residue": 5400, "final": 5400,
}
assert budget.BOUNDARIES["final"] - budget.BOUNDARIES["cleanup"] == 300
assert list(budget.BOUNDARIES.values()) == sorted(budget.BOUNDARIES.values())
assert budget.BOUNDARIES["upload"] + 60 < budget.BOUNDARIES["export-cleanup"]
anchor = 1_000_000_000
assert budget.timeout_seconds(str(anchor), "source", anchor) == 595
assert budget.timeout_seconds(str(anchor), "observe", anchor) == 3895
assert budget.timeout_seconds(str(anchor), "cleanup", anchor) == 5095
assert budget.timeout_seconds(
    str(anchor), "post-export-residue", anchor + 5380 * module.NS_PER_SECOND,
) == 15
for boundary, seconds in budget.BOUNDARIES.items():
    budget.check(str(anchor), boundary, anchor + seconds * 1_000_000_000)
    budget_rejected(lambda boundary=boundary, seconds=seconds: budget.check(
        str(anchor), boundary, anchor + seconds * 1_000_000_000 + 1,
    ))
for hostile_anchor in (None, "", "0", "01", "-1", "+1", "1.0", "a", "9" * 21):
    budget_rejected(lambda hostile_anchor=hostile_anchor: budget.check(hostile_anchor, "final", anchor))
budget_rejected(lambda: budget.check(str(anchor + 1), "final", anchor))
budget_rejected(lambda: budget.timeout_seconds(str(anchor), "source", anchor + 595 * 1_000_000_000))

assert tuple((item.component, item.release, item.size, item.sha256) for item in module.RUNTIME_ASSETS) == (
    ("kata", "3.32.0", 1547940938, "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01"),
    ("containerd", "2.2.1", 33645699, "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883"),
)
for asset in module.RUNTIME_ASSETS:
    assert module._strict_url(asset.url).hostname == "github.com"

kata = module.RUNTIME_ASSETS[0]
valid = "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=fixed"
assert module._redirect_target(kata, valid) == valid
for hostile in (
    "http://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x",
    "https://evil.invalid/github-production-release-asset/123/abc?sig=x",
    "https://release-assets.githubusercontent.com/other/123?sig=x",
    "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc",
):
    rejected(lambda hostile=hostile: module._redirect_target(kata, hostile))

base = module._base_report()
raw = module._canonical_report(base)
assert json.loads(raw) == base
valid_counters = {name: index for index, name in enumerate(module.STRUCTURAL_COUNTERS)}
def trusted_counter_provider(name="completion_rootfs_build", counters=valid_counters,
                             start_error=None, read_error=None):
    provider = types.ModuleType(name)
    handles = {}
    def start(phase):
        if start_error is not None:
            raise start_error
        handle = len(handles) + 1
        handles[handle] = phase
        return handle
    def read(phase, handle):
        assert handles.pop(handle) == phase
        if read_error is not None:
            raise read_error
        return dict(counters)
    provider._start_phase_structural_counters = start
    provider._read_phase_structural_counters = read
    return provider
provider = trusted_counter_provider()
ticket = module._counter_start(provider, "equality")
assert module._counter_read(ticket) == valid_counters
rejected(lambda: module._counter_start(types.SimpleNamespace(), "equality"))
rejected(lambda: module._counter_start(types.ModuleType("missing_provider"), "equality"))
for fault_at in ("start", "read"):
    fault_events = []
    fault_phases = module._empty_phases()
    fault_provider = trusted_counter_provider(
        start_error=RuntimeError("start-fault") if fault_at == "start" else None,
        read_error=RuntimeError("read-fault") if fault_at == "read" else None,
    )
    assert failure_code(lambda: module._timed_rootfs_phase(
        fault_phases, "equality", "rootfs-equality", fault_provider,
        lambda: fault_events.append("callback"),
    )) == "rootfs-counter-contract"
    assert fault_events == ([] if fault_at == "start" else ["callback"])
    assert module._phase(fault_phases, "equality")["status"] == "evidence-failure"
    rejected(lambda fault_phases=fault_phases: module._validate_phase_graph(fault_phases, None))
settled_without_result = [
    row if row["phase"] == "recovery-attempt-1" else
    {**row, "status": "success", "outcome": "success", "elapsed_ms": 1,
     "structural_counters": valid_counters}
    for row in base["rootfs_phases"]
]
for hostile_counters in (
    {**valid_counters, "byte_names_returned": True},
    {**valid_counters, "byte_names_returned": 1_000_000_001},
    {name: value for name, value in valid_counters.items() if name != "parent_snapshots"},
):
    hostile_provider = trusted_counter_provider(counters=hostile_counters)
    rejected(lambda hostile_provider=hostile_provider: module._counter_read(
        module._counter_start(hostile_provider, "equality"),
    ))
graph_fixtures = json.loads((ROOT / "test/fixtures/stage2-phase-a-v2-phase-graphs.json").read_text())
assert graph_fixtures["version"] == "cogs.stage2-phase-a-phase-graph-fixtures/v1"
def phases_for(statuses):
    outcomes = {"success": "success", "failure": "failed", "blocked": "prerequisite-failed",
                "not-reached": "observer-ended"}
    return [{"phase": name, "status": status, "outcome": outcomes[status],
             "elapsed_ms": 1 if status in {"success", "failure"} else 0,
             "structural_counters": valid_counters if status in {"success", "failure"} else None}
            for name, status in zip(module.ROOTFS_PHASES, statuses, strict=True)]
valid_graphs = {(tuple(item["statuses"]), item["rootfs"]) for item in graph_fixtures["valid"]}
phase_outcomes = {
    "success": {"success"},
    "failure": {"failed", "cancelled", "deadline", "not-started", "postwork", "over-bound"},
    "blocked": {"prerequisite-failed"},
    "not-reached": {"observer-ended"},
}
all_phase_outcomes = set().union(*phase_outcomes.values())
for statuses, has_rootfs in valid_graphs:
    module._validate_phase_graph(phases_for(statuses), {} if has_rootfs else None)
    for index, current in enumerate(statuses):
        for replacement in ("success", "failure", "blocked", "not-reached"):
            if replacement == current:
                continue
            changed_statuses = list(statuses); changed_statuses[index] = replacement
            expected = (tuple(changed_statuses), has_rootfs) in valid_graphs
            if expected:
                module._validate_phase_graph(phases_for(changed_statuses), {} if has_rootfs else None)
            else:
                rejected(lambda changed_statuses=changed_statuses, has_rootfs=has_rootfs:
                         module._validate_phase_graph(phases_for(changed_statuses), {} if has_rootfs else None))
    rejected(lambda statuses=statuses, has_rootfs=has_rootfs:
             module._validate_phase_graph(phases_for(statuses), None if has_rootfs else {}))
    for index, status in enumerate(statuses):
        for outcome in all_phase_outcomes:
            changed_phases = phases_for(statuses)
            changed_phases[index]["outcome"] = outcome
            if outcome in phase_outcomes[status]:
                module._validate_phase_graph(changed_phases, {} if has_rootfs else None)
            else:
                rejected(lambda changed_phases=changed_phases, has_rootfs=has_rootfs:
                         module._validate_phase_graph(changed_phases, {} if has_rootfs else None))

for changed in (
    {**base, "authority": "committed"},
    {**base, "qualified": True},
    {**base, "claims": {**base["claims"], "runtime": True}},
    {**base, "blockers": []},
    {**base, "rootfs_phases": base["rootfs_phases"][:-1]},
    {**base, "rootfs_phases": [{**base["rootfs_phases"][0], "phase": "second-build-work"}]
     + base["rootfs_phases"][1:]},
    {**base, "rootfs_phases": [{**base["rootfs_phases"][0], "status": "blocked", "elapsed_ms": 1}]
     + base["rootfs_phases"][1:]},
    {**base, "rootfs_phases": [{**base["rootfs_phases"][0], "status": "success"}]
     + base["rootfs_phases"][1:]},
    {**base, "rootfs_phases": [{**base["rootfs_phases"][0], "structural_counters": {
        name: (True if name == "byte_names_returned" else 0) for name in module.STRUCTURAL_COUNTERS
    }}] + base["rootfs_phases"][1:]},
    {**base, "rootfs_phases": settled_without_result},
    {**base, "unexpected": True},
):
    rejected(lambda changed=changed: module._canonical_report(changed))

class FakeVerificationError(Exception):
    def __init__(self, stage=None):
        self.stage = stage

fake_verification_module = types.SimpleNamespace(VerificationError=FakeVerificationError)
for stage, expected in (
    (None, "cache-acquisition-unknown"),
    ("preflight", "cache-acquisition-preflight"),
    ("tls", "cache-acquisition-tls"),
    ("token.status", "cache-acquisition-token"),
    ("artifact.redirect.location", "cache-acquisition-redirect"),
    ("artifact.body", "cache-acquisition-body"),
    ("artifact.final.length", "cache-acquisition-response"),
    ("postverify", "cache-postverify"),
):
    code = failure_code(lambda stage=stage: module._verifier_call(
        fake_verification_module, "rootfs-contract-preflight",
        lambda: (_ for _ in ()).throw(FakeVerificationError(stage)), acquisition=stage is not None,
    ))
    assert code == ("rootfs-contract-preflight" if stage is None else expected)

for code in ("rootfs-bootstrap", "rootfs-build", "rootfs-equality", "rootfs-pin", "rootfs-postverify"):
    assert failure_code(lambda code=code: module._rootfs_call(
        code, lambda: (_ for _ in ()).throw(RuntimeError("must-not-escape")),
    )) == code

class FakeBuildAttemptError(Exception):
    def __init__(self, work_outcome):
        self.work_outcome = work_outcome

original_monotonic_ns = module.time.monotonic_ns
try:
    for ordinal, work_outcome, elapsed_ns in (
        ("first", "deadline", 200_000_000_001),
        ("first", "failed", 950_000_999_999),
        ("second", "cancelled", 300_000_000_000),
    ):
        failing_build = trusted_counter_provider("completion_rootfs_build")
        failing_build.BUILD_SECONDS = 900
        failing_build.BuildAttemptError = FakeBuildAttemptError
        failing_build.materializer = types.SimpleNamespace(_reload_and_cleanup=lambda *_args: None)
        failing_build.builder = types.SimpleNamespace(_cleanup_owned=lambda *_args: None)
        failing_build._build_once = lambda *_args, outcome=work_outcome: (
            _ for _ in ()
        ).throw(FakeBuildAttemptError(outcome))
        values = iter((10, 10 + elapsed_ns))
        module.time.monotonic_ns = lambda: next(values)
        phases = module._empty_phases()
        assert failure_code(lambda ordinal=ordinal, phases=phases: module._candidate_build(
            failing_build, "approval", "control", ordinal, "e" * 64, phases,
        )) == f"rootfs-{ordinal}-build-{work_outcome}"
        assert module._phase(phases, f"{ordinal}-build-work") == {
            "phase": f"{ordinal}-build-work", "status": "failure", "outcome": work_outcome,
            "elapsed_ms": elapsed_ns // module.NS_PER_MILLISECOND, "structural_counters": valid_counters,
        }
        assert module._phase(phases, f"{ordinal}-inline-cleanup")["status"] == "blocked"
finally:
    module.time.monotonic_ns = original_monotonic_ns

postwork_build = trusted_counter_provider("completion_rootfs_build")
postwork_build.BUILD_SECONDS = 900
postwork_build.BuildAttemptError = FakeBuildAttemptError
postwork_events = []
def normal_cleanup(*_args):
    postwork_events.append("cleanup-failure")
    raise RuntimeError("primary cleanup uncertainty")
def fallback_cleanup(*_args):
    postwork_events.append("cleanup-success")
postwork_build.builder = types.SimpleNamespace(_cleanup_owned=normal_cleanup)
postwork_build.materializer = types.SimpleNamespace(_reload_and_cleanup=fallback_cleanup)
def postwork_failure(*_args):
    try:
        postwork_build.builder._cleanup_owned(None)
    except RuntimeError:
        postwork_build.materializer._reload_and_cleanup(None)
    raise FakeBuildAttemptError("success")
postwork_build._build_once = postwork_failure
postwork_phases = module._empty_phases()
assert failure_code(lambda: module._candidate_build(
    postwork_build, "approval", "control", "first", "e" * 64, postwork_phases,
)) == "rootfs-first-build-inline-cleanup"
assert postwork_events == ["cleanup-failure", "cleanup-success"]
assert (module._phase(postwork_phases, "first-build-work")["status"],
        module._phase(postwork_phases, "first-build-work")["outcome"]) == ("failure", "postwork")
assert (module._phase(postwork_phases, "first-inline-cleanup")["status"],
        module._phase(postwork_phases, "first-inline-cleanup")["outcome"]) == ("failure", "failed")
assert module._phase(postwork_phases, "first-inline-cleanup")["structural_counters"] == valid_counters

socket_monotonic_ns = module.time.monotonic_ns
try:
    module.time.monotonic_ns = lambda: 1
    assert module._socket_timeout_seconds(2 * module.NS_PER_SECOND + 1) == 2
    assert module._socket_timeout_seconds(2 * module.NS_PER_SECOND) == 1
    rejected(lambda: module._socket_timeout_seconds(module.NS_PER_SECOND))
finally:
    module.time.monotonic_ns = socket_monotonic_ns

publication_stages = (
    "after-final-eof", "after-content-fsync", "after-redigest", "before-link", "after-link",
    "after-unlink", "after-directory-fsync", "after-final-redigest", "before-journal",
    "after-journal", "before-return",
)
publication_originals = module.time.monotonic_ns, module._check_asset_deadline, module._append_journal
try:
    for target_stage in publication_stages:
        with tempfile.TemporaryDirectory() as temporary:
            directory_path = Path(temporary)
            partial = directory_path / ".asset.partial"
            final = directory_path / "asset.bin"
            directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            descriptor = os.open(partial.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                 0o600, dir_fd=directory)
            try:
                partial_identity = module._identity(os.fstat(descriptor))
                content = b"fixed-publication-content"
                assert os.write(descriptor, content) == len(content)
                asset = module.Asset(
                    "test", "1", final.name, "https://github.com/fixed", len(content),
                    module.hashlib.sha256(content).hexdigest(),
                )
                deadline_ns = 1_000_000
                observed_stage = [None]
                journal = []
                original_check = publication_originals[1]
                def staged_check(deadline, stage):
                    observed_stage[0] = stage
                    return original_check(deadline, stage)
                module._check_asset_deadline = staged_check
                module.time.monotonic_ns = lambda: deadline_ns if observed_stage[0] == target_stage else deadline_ns - 1
                module._append_journal = lambda kind, body: journal.append((kind, body))
                publication = {"journaled": False}
                assert failure_code(lambda: module._finish_asset_publication(
                    asset, directory, descriptor, partial, final, partial_identity, deadline_ns, publication,
                )) == "asset-timeout"
                module._cleanup_failed_asset_publication(directory, descriptor, partial, final, publication)
                retained = target_stage in {"after-journal", "before-return"}
                assert set(os.listdir(directory)) == ({final.name} if retained else set())
                assert [kind for kind, _body in journal] == (["asset-final-owned"] if retained else [])
                if retained:
                    module._cleanup_held_asset(directory, final.name, descriptor)
            finally:
                os.close(descriptor)
                os.close(directory)
finally:
    module.time.monotonic_ns, module._check_asset_deadline, module._append_journal = publication_originals

download_originals = (
    module._append_journal, module._open_dir, module._held_path_absent,
    module.os.open, module.os.fstat, module.os.close, module._cleanup_failed_asset_publication,
)
try:
    asset = module.RUNTIME_ASSETS[0]
    deadline = time.monotonic_ns() + 10 * module.NS_PER_SECOND
    closed = []
    module._append_journal = lambda *_args: None
    module._open_dir = lambda _path: 40
    module._held_path_absent = lambda _path: (_ for _ in ()).throw(module.CandidateError("asset-path"))
    module.os.close = lambda descriptor: closed.append(descriptor)
    assert failure_code(lambda: module._download_asset(asset, deadline)) == "asset-path"
    assert closed == [40]

    closed = []
    cleanup_calls = []
    module._held_path_absent = lambda _path: True
    module.os.open = lambda *_args, **_kwargs: 41
    module.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("partial-identity"))
    module._cleanup_failed_asset_publication = lambda *_args: cleanup_calls.append("cleanup")
    expect_oserror(lambda: module._download_asset(asset, deadline))
    assert closed == [41, 40] and cleanup_calls == []

    class PartialNode:
        st_dev = 1
        st_ino = 2
        st_mode = 0o100600
        st_uid = 0
        st_gid = 0
        st_nlink = 1
        st_size = 0
    closed = []
    cleanup_calls = []
    journal_calls = []
    module.os.fstat = lambda _descriptor: PartialNode()
    def partial_journal(kind, _body):
        journal_calls.append(kind)
        if kind == "asset-partial-owned":
            raise module.CandidateError("journal-invalid")
    module._append_journal = partial_journal
    module._cleanup_failed_asset_publication = lambda *_args: cleanup_calls.append("cleanup")
    assert failure_code(lambda: module._download_asset(asset, deadline)) == "journal-invalid"
    assert journal_calls == ["asset-intent", "asset-partial-owned"]
    assert cleanup_calls == ["cleanup"] and closed == [41, 40]
finally:
    (module._append_journal, module._open_dir, module._held_path_absent,
     module.os.open, module.os.fstat, module.os.close,
     module._cleanup_failed_asset_publication) = download_originals

token_build_calls = []
token_build = types.SimpleNamespace(
    BUILD_SECONDS=900,
    _build_once=lambda *_args: token_build_calls.append("build"),
)
for hostile_token in (None, "a" * 63, "a" * 65, "A" * 64, "g" * 64):
    assert failure_code(lambda hostile_token=hostile_token: module._candidate_build(
        token_build, "approval", "control", "first", hostile_token, module._empty_phases(),
    )) == "rootfs-build-contract"
assert token_build_calls == []

remote = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(remote))
import completion_rootfs_build as actual_build
import completion_rootfs_builder as actual_builder
import completion_rootfs_materializer as actual_materializer
import completion_rootfs_publish as actual_publish
assert actual_build.publication is actual_publish
assert (actual_build.BUILD_SECONDS, actual_build.OUTER_SECONDS) == (900, 2400)
assert (actual_materializer.MATERIALIZE_SECONDS, actual_materializer.CLEANUP_SECONDS) == (900, 600)
assert actual_builder.RECOVER_SECONDS == 600
assert failure_code(lambda: module._counter_start(actual_build, "first-build-work")) == \
    "rootfs-counter-contract"
assert failure_code(lambda: module._counter_start(actual_builder, "recovery-attempt-1")) == \
    "rootfs-counter-contract"
assert (module.OBSERVE_SECONDS, module.ROOTFS_RECOVERY_ATTEMPTS) == (3300, 1)
materializer_monotonic_ns = actual_materializer.time.monotonic_ns
try:
    actual_materializer.time.monotonic_ns = lambda: 100
    long_outer = actual_build.fs.OperationControl(2_000_000_000_100, lambda: False)
    short_outer = actual_build.fs.OperationControl(800_000_000_100, lambda: False)
    assert actual_materializer._materialize_control(long_outer).deadline_ns == 900_000_000_100
    assert actual_materializer._materialize_control(short_outer).deadline_ns == short_outer.deadline_ns
    assert actual_materializer._work_failure(
        actual_build.fs.OperationControl(100, lambda: False),
    ) == "deadline"
    assert actual_materializer._work_failure(
        actual_build.fs.OperationControl(101, lambda: False),
    ) == "failed"
    assert actual_materializer._work_failure(
        actual_build.fs.OperationControl(101, lambda: True),
    ) == "cancelled"
finally:
    actual_materializer.time.monotonic_ns = materializer_monotonic_ns

materializer_failure_originals = (
    actual_materializer.time.monotonic_ns, actual_materializer._fresh_cleanup_control,
    actual_materializer._reload_and_cleanup,
)
def materializer_failure(cleanup_error):
    events = []
    control = actual_build.fs.OperationControl(
        100, lambda: (events.append("cancelled"), False)[1],
    )
    actual_materializer.time.monotonic_ns = lambda: (events.append("captured"), 100)[1]
    actual_materializer._fresh_cleanup_control = lambda: (events.append("fresh-cleanup"), "cleanup-control")[1]
    def cleanup(_owned, cleanup_control):
        events.append(("cleanup", cleanup_control))
        if cleanup_error is not None:
            raise cleanup_error
    actual_materializer._reload_and_cleanup = cleanup
    primary = RuntimeError("raw primary")
    try:
        actual_materializer._raise_work_failure("owned", control, primary)
    except actual_materializer.MaterializerWorkError as error:
        assert error.work_outcome == "deadline" and error.args == () and str(error) == ""
        assert events == ["captured", "cancelled", "fresh-cleanup", ("cleanup", "cleanup-control")]
        return error, primary
    raise AssertionError("materializer work failure escaped")
try:
    captured, primary = materializer_failure(None)
    assert captured.__cause__ is primary
    cleanup_error = OSError("raw cleanup")
    captured, primary = materializer_failure(cleanup_error)
    assert type(captured.__cause__) is actual_build.fs.RootfsFsError
    assert captured.__cause__.primary is primary and captured.__cause__.close_error is cleanup_error
finally:
    (actual_materializer.time.monotonic_ns, actual_materializer._fresh_cleanup_control,
     actual_materializer._reload_and_cleanup) = materializer_failure_originals

build_attempt_originals = (
    actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
    actual_build.builder._open_base_chain, actual_build.builder._begin_operation,
    actual_build.materializer._materialize, actual_build.materializer._reload_and_cleanup,
    actual_build.canonical._manifest, actual_build.fs._close_chain,
)
build_events = []
authority = types.SimpleNamespace(plan="plan")
owned = types.SimpleNamespace()
approval = actual_build.fs.SourceApproval("a" * 40, "b" * 64)
outer_control = actual_build.fs.OperationControl(time.monotonic_ns() + 60_000_000_000, lambda: False)
try:
    actual_build.plan.load_verified_build_inputs = lambda: authority
    actual_build._cache_values = lambda _authority: ()
    actual_build.builder._open_base_chain = lambda _control: "chain"
    actual_build.builder._begin_operation = lambda *_args: owned
    actual_build.materializer._reload_and_cleanup = lambda *_args: build_events.append("cleanup")
    actual_build.fs._close_chain = lambda _chain: build_events.append("close")
    actual_build.materializer._materialize = lambda *_args: (_ for _ in ()).throw(
        actual_materializer.MaterializerWorkError("deadline")
    )
    try:
        actual_build._build_once_unmasked(approval, "1" * 64, outer_control)
    except actual_build.BuildAttemptError as error:
        assert error.work_outcome == "deadline" and error.args == () and str(error) == ""
    else:
        raise AssertionError("typed materializer failure escaped build boundary")
    assert build_events == ["close"]

    build_events.clear()
    actual_build.materializer._materialize = lambda *_args: types.SimpleNamespace(owned=owned)
    actual_build.canonical._manifest = lambda _plan: (_ for _ in ()).throw(RuntimeError("raw postwork"))
    try:
        actual_build._build_once_unmasked(approval, "2" * 64, outer_control)
    except actual_build.BuildAttemptError as error:
        assert error.work_outcome == "success" and error.args == () and str(error) == ""
    else:
        raise AssertionError("post-materialization failure escaped build boundary")
    assert build_events == ["cleanup", "close"]
finally:
    (actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
     actual_build.builder._open_base_chain, actual_build.builder._begin_operation,
     actual_build.materializer._materialize, actual_build.materializer._reload_and_cleanup,
     actual_build.canonical._manifest, actual_build.fs._close_chain) = build_attempt_originals

assert all(callable(getattr(actual_builder, name)) for name in ("_open_base_chain", "_bootstrap"))

bootstrap_events = []
bad_close_builder = types.SimpleNamespace(
    _open_base_chain=lambda _control: "chain",
    _bootstrap=lambda _chain, _approval, _control: "state",
)
class CloseErrorFs:
    RootfsFsError = Exception
    @staticmethod
    def _close_node(_state):
        bootstrap_events.append("close-state")
        raise OSError()
    @staticmethod
    def _close_chain(_chain):
        bootstrap_events.append("close-chain")
assert failure_code(lambda: module._bootstrap_rootfs(
    bad_close_builder, CloseErrorFs, "approval", "control",
)) == "rootfs-bootstrap"
assert bootstrap_events == ["close-state", "close-chain"]

candidate = types.SimpleNamespace(
    cache=tuple(range(16)), entry_count=4353, manifest=b"m" * 1049443,
    manifest_sha256="8" * 64, ustar_size=136905728, ustar_sha256="4" * 64,
)
order = []
fake_builder = types.ModuleType("completion_rootfs_builder")
fake_builder._open_base_chain = lambda _control: (order.append("open") or "chain")
fake_builder._bootstrap = lambda chain, _approval, _control: (order.append("bootstrap") or "state") if chain == "chain" else None
fake_builder._cleanup_owned = lambda *_args: order.append("inline-cleanup")
fake_materializer = types.SimpleNamespace(_reload_and_cleanup=lambda *_args: order.append("reload-cleanup"))
fake_build = trusted_counter_provider("completion_rootfs_build")
fake_build.BUILD_SECONDS = 900
fake_build.OUTER_SECONDS = 2400
fake_build.builder = fake_builder
fake_build.materializer = fake_materializer
def fake_build_once(_approval, token, _control):
    order.append(("build", token))
    fake_builder._cleanup_owned(None)
    return candidate
fake_build._build_once = fake_build_once
fake_build._require_equal_builds = lambda first, second: order.append("equal") if first is second else (_ for _ in ()).throw(AssertionError())
fake_build._require_pinned = lambda _candidate, _pins: order.append("pin")
fake_fs = types.ModuleType("completion_rootfs_fs")
fake_fs.SourceApproval = lambda revision, digest: (revision, digest)
fake_fs.OperationControl = lambda deadline, cancelled: (deadline, cancelled)
fake_fs.RootfsFsError = Exception
fake_fs._close_node = lambda state: order.append("close-state") if state == "state" else None
fake_fs._close_chain = lambda chain: order.append("close-chain") if chain == "chain" else None
fake_publish = types.ModuleType("completion_rootfs_publish")
fake_publish._load_pins = lambda: (order.append("pins") or object())
fake_verifier = types.SimpleNamespace(
    CONTRACT_PATH="contract", ARTIFACT_ROOT="artifacts", verify_contract=lambda _path: {"fixed": True},
    acquire_completion_artifacts=lambda *_args: None, verify_package_archives=lambda *_args: None,
)
rootfs_owned = {
    "root": {"dev": 1, "ino": 2, "kind": "directory", "mode": 0o700,
             "uid": 0, "gid": 0, "nlink": 2, "size": 64},
    "files": [{"name": "fixed", "identity": {"dev": 1, "ino": 3, "kind": "file", "mode": 0o600,
                "uid": 0, "gid": 0, "nlink": 1, "size": 5}, "sha256": "c" * 64}],
}
rootfs_after = {"root": {**rootfs_owned["root"], "nlink": 99, "size": 4096},
                "files": rootfs_owned["files"]}
assert module._same_rootfs_lifecycle(rootfs_after, rootfs_owned)
for field, value in (
    ("dev", 10), ("ino", 20), ("kind", "file"), ("mode", 0o755), ("uid", 1), ("gid", 1),
):
    hostile = {"root": {**rootfs_after["root"], field: value}, "files": rootfs_after["files"]}
    assert not module._same_rootfs_lifecycle(hostile, rootfs_owned)
assert not module._same_rootfs_lifecycle(
    {"root": rootfs_after["root"], "files": rootfs_after["files"] + [{"name": "extra"}]}, rootfs_owned,
)
changed_file = {**rootfs_after["files"][0], "sha256": "d" * 64}
assert not module._same_rootfs_lifecycle(
    {"root": rootfs_after["root"], "files": [changed_file]}, rootfs_owned,
)
changed_identity = {**rootfs_after["files"][0],
                    "identity": {**rootfs_after["files"][0]["identity"], "size": 6}}
assert not module._same_rootfs_lifecycle(
    {"root": rootfs_after["root"], "files": [changed_identity]}, rootfs_owned,
)
original_modules = {name: sys.modules.get(name) for name in
                    ("completion_rootfs_build", "completion_rootfs_builder", "completion_rootfs_fs",
                     "completion_rootfs_publish")}
original_helpers = (module._load_artifact_verifier, module._append_journal,
                    module._snapshot_cache, module._snapshot_rootfs_lifecycle, module.secrets.token_hex)
try:
    sys.modules["completion_rootfs_build"] = fake_build
    sys.modules["completion_rootfs_builder"] = fake_builder
    sys.modules["completion_rootfs_fs"] = fake_fs
    sys.modules["completion_rootfs_publish"] = fake_publish
    module._load_artifact_verifier = lambda: fake_verifier
    module._append_journal = lambda *_args: None
    module._snapshot_cache = lambda _contract: {"cache": "fixed"}
    rootfs_snapshots = iter((rootfs_owned, rootfs_after))
    module._snapshot_rootfs_lifecycle = lambda: (order.append("snapshot") or next(rootfs_snapshots))
    tokens = iter(("1" * 64, "2" * 64))
    module.secrets.token_hex = lambda size: (order.append(("token", value := next(tokens))) or value) if size == 32 else None
    phases = module._empty_phases()
    result = module._rootfs_candidates(
        "a" * 40, "b" * 64, time.monotonic_ns() + 10_000_000_000, phases,
    )
    assert result["equal"] is True and result["pins_match"] is True and result["cache_count"] == 16
    assert all(module._phase(phases, name)["status"] == "success" for name in module.ROOTFS_PHASES
               if name != "recovery-attempt-1")
    assert order == ["open", "bootstrap", "close-state", "close-chain", "snapshot",
                     ("token", "1" * 64), ("token", "2" * 64),
                     ("build", "1" * 64), "inline-cleanup",
                     ("build", "2" * 64), "inline-cleanup",
                     "equal", "pins", "pin", "pin", "snapshot"]

    order.clear()
    rootfs_snapshots = iter((rootfs_owned,))
    repeated = "f" * 64
    module.secrets.token_hex = lambda size: (order.append(("token", repeated)) or repeated) if size == 32 else None
    rejected_phases = module._empty_phases()
    assert failure_code(lambda: module._rootfs_candidates(
        "a" * 40, "b" * 64, time.monotonic_ns() + 10_000_000_000, rejected_phases,
    )) == "rootfs-build-token"
    assert rejected_phases == module._empty_phases()
    assert order == ["open", "bootstrap", "close-state", "close-chain", "snapshot",
                     ("token", repeated), ("token", repeated)]
finally:
    (module._load_artifact_verifier, module._append_journal, module._snapshot_cache,
     module._snapshot_rootfs_lifecycle, module.secrets.token_hex) = original_helpers
    for name, value in original_modules.items():
        if value is None:
            del sys.modules[name]
        else:
            sys.modules[name] = value

trusted_recovery = trusted_counter_provider("completion_rootfs_builder")
trusted_recovery.RECOVER_SECONDS = 600
trusted_recovery._run_recovery = lambda: None
original_recovery_module = sys.modules.get("completion_rootfs_builder")
try:
    sys.modules["completion_rootfs_builder"] = trusted_recovery
    trusted_recovery_outcomes = []
    module._recover_rootfs(trusted_recovery_outcomes)
    assert trusted_recovery_outcomes == [{
        "attempt": 1, "outcome": "success", "elapsed_ms": trusted_recovery_outcomes[0]["elapsed_ms"],
        "structural_counters": valid_counters,
    }]
finally:
    if original_recovery_module is None:
        del sys.modules["completion_rootfs_builder"]
    else:
        sys.modules["completion_rootfs_builder"] = original_recovery_module

recovery_calls = []
def recovers_once():
    recovery_calls.append("recover")
recovery_outcomes = []
module._retry_exact_recovery(recovers_once, 600 * module.NS_PER_SECOND, recovery_outcomes)
assert recovery_calls == ["recover"]
assert [item["outcome"] for item in recovery_outcomes] == ["success"]
recovery_calls.clear()
recovery_outcomes = []
assert failure_code(lambda: module._retry_exact_recovery(
    lambda: (recovery_calls.append("recover"), (_ for _ in ()).throw(RuntimeError("preserve")))[1],
    600 * module.NS_PER_SECOND,
    recovery_outcomes,
)) == "rootfs-recovery-exhausted"
assert recovery_calls == ["recover"] * module.ROOTFS_RECOVERY_ATTEMPTS
assert [item["outcome"] for item in recovery_outcomes] == ["nondeadline"] * module.ROOTFS_RECOVERY_ATTEMPTS

original_monotonic_ns = module.time.monotonic_ns
try:
    for elapsed_ns, outcome, elapsed_ms, fails in (
        (600 * module.NS_PER_SECOND - 1, "success", 599_999, False),
        (600 * module.NS_PER_SECOND, "over-bound", 600_000, True),
    ):
        values = iter((10, 10 + elapsed_ns))
        module.time.monotonic_ns = lambda: next(values)
        recovery_outcomes = []
        callback = lambda: None
        if fails:
            assert failure_code(lambda: module._retry_exact_recovery(
                callback, 600 * module.NS_PER_SECOND, recovery_outcomes,
            )) == "rootfs-recovery-exhausted"
        else:
            module._retry_exact_recovery(callback, 600 * module.NS_PER_SECOND, recovery_outcomes)
        assert recovery_outcomes == [
            {"attempt": 1, "outcome": outcome, "elapsed_ms": elapsed_ms},
        ]

    for elapsed_ns, outcome, elapsed_ms in (
        (600 * module.NS_PER_SECOND - 1, "nondeadline", 599_999),
        (600 * module.NS_PER_SECOND, "over-bound", 600_000),
    ):
        values = iter((10, 10 + elapsed_ns))
        module.time.monotonic_ns = lambda: next(values)
        recovery_outcomes = []
        assert failure_code(lambda: module._retry_exact_recovery(
            lambda: (_ for _ in ()).throw(RuntimeError("bounded timeout")),
            600 * module.NS_PER_SECOND, recovery_outcomes,
        )) == "rootfs-recovery-exhausted"
        assert recovery_outcomes == [
            {"attempt": 1, "outcome": outcome, "elapsed_ms": elapsed_ms},
        ]
finally:
    module.time.monotonic_ns = original_monotonic_ns

cleanup_originals = (
    module._fixed_preflight, module._require_state, module._recover_rootfs, module._cleanup_rootfs,
    module._cleanup_assets, module._cleanup_artifacts, module._write_json_once,
)
cleanup_calls = []
cleanup_outputs = []
try:
    module._fixed_preflight = lambda approval: cleanup_calls.append(("preflight", approval))
    module._require_state = lambda: ["fixed-records"]
    module._recover_rootfs = lambda outcomes: (cleanup_calls.append("recover"),
                                               outcomes.append({"attempt": 1, "outcome": "nondeadline", "elapsed_ms": 1}),
                                               (_ for _ in ()).throw(RuntimeError("preserve")))[2]
    module._cleanup_rootfs = lambda _records: cleanup_calls.append("foundation")
    module._cleanup_assets = lambda _records: (cleanup_calls.append("assets"),
                                                (_ for _ in ()).throw(RuntimeError("replacement")))[1]
    module._cleanup_artifacts = lambda _records: (cleanup_calls.append("cache"),
                                                   (_ for _ in ()).throw(RuntimeError("unknown")))[1]
    module._write_json_once = lambda path, value, kind: cleanup_outputs.append((path, value, kind))
    assert failure_code(module._cleanup) == "cleanup-uncertainty"
    assert cleanup_calls == [("preflight", False), "recover", "assets", "cache"]
    assert cleanup_outputs == [(module.CLEANUP, {
        "success": False,
        "codes": ["rootfs-recovery-exhausted", "asset-cleanup-uncertainty", "cache-cleanup-uncertainty"],
        "recovery_attempts": [{"attempt": 1, "outcome": "nondeadline", "elapsed_ms": 1}],
    }, "cleanup-owned")]
finally:
    (module._fixed_preflight, module._require_state, module._recover_rootfs, module._cleanup_rootfs,
     module._cleanup_assets, module._cleanup_artifacts, module._write_json_once) = cleanup_originals

observation_phases = phases_for([
    "failure", "success", "blocked", "blocked", "not-reached", "blocked", "blocked", "blocked", "blocked",
])
observation_input = {
    "status": "failed", "codes": ["rootfs-first-build-deadline"], "revision": "a" * 40,
    "source_manifest_sha256": "b" * 64, "duration_ms": 12, "host_tools": [], "kvm": None,
    "rootfs": None, "rootfs_phases": observation_phases, "assets": [],
}
valid_cleanup_input = {
    "success": True, "codes": [], "recovery_attempts": [{
        "attempt": 1, "outcome": "success", "elapsed_ms": 2, "structural_counters": valid_counters,
    }],
}
render_writes = []
def render_with(observation_value, cleanup_raw, residue_raw):
    originals = module._fixed_preflight, module._require_state, module._read_regular, module._write_json_once
    written = render_writes
    written.clear()
    observation_raw = observation_value if type(observation_value) is bytes else \
        module._canonical(observation_value) + b"\n"
    inputs = {module.OBSERVATION: observation_raw, module.RESIDUE: residue_raw}
    if cleanup_raw is not None:
        inputs[module.CLEANUP] = cleanup_raw
    try:
        module._fixed_preflight = lambda _approval: None
        module._require_state = lambda: []
        def read_input(path, *_args):
            if path == module.REPORT:
                return module._canonical(written[-1]) + b"\n"
            return inputs[path]
        module._read_regular = read_input
        module._write_json_once = lambda _path, value, _kind: written.append(value)
        assert module._render() == 0
        return written[-1]
    finally:
        module._fixed_preflight, module._require_state, module._read_regular, module._write_json_once = originals
assert failure_code(lambda: render_with(
    observation_input, b"{malformed", module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "recovery-phase-input-uncertainty"
assert render_writes == []
assert failure_code(lambda: render_with(
    b"{malformed", module._canonical(valid_cleanup_input) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "observation-phase-input-uncertainty"
assert render_writes == []
assert failure_code(lambda: render_with(
    observation_input, None, module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "recovery-phase-input-uncertainty"
assert render_writes == []
assert failure_code(lambda: render_with(
    {**observation_input, "rootfs_phases": fault_phases},
    module._canonical(valid_cleanup_input) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "observation-phase-input-uncertainty"
assert render_writes == []
rendered = render_with(observation_input, module._canonical(valid_cleanup_input) + b"\n", b"{malformed")
assert module._phase(rendered["rootfs_phases"], "first-build-work")["status"] == "failure"
assert module._phase(rendered["rootfs_phases"], "recovery-attempt-1")["status"] == "success"
assert "residue-input-uncertainty" in rendered["diagnostic_codes"]
rendered = render_with(
    {**observation_input, "codes": "malformed"},
    module._canonical({**valid_cleanup_input, "codes": "malformed"}) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)
assert module._phase(rendered["rootfs_phases"], "first-build-work")["status"] == "failure"
assert module._phase(rendered["rootfs_phases"], "recovery-attempt-1")["status"] == "success"
assert "observation-input-uncertainty" in rendered["diagnostic_codes"]
assert "cleanup-summary-input-uncertainty" in rendered["diagnostic_codes"]
assert rendered["checks"]["cleanup"] == "fail"

original_timeout = module.HOST_TOOL_SECONDS
module.HOST_TOOL_SECONDS = 1
started = time.monotonic()
try:
    rejected(lambda: module._stream_command(sys.executable, ("-c", "import os,signal,time; child=os.fork(); "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(10)"), (0,)))
finally:
    module.HOST_TOOL_SECONDS = original_timeout
assert time.monotonic() - started < 4

module.HOST_TOOL_SECONDS = 2
try:
    code = failure_code(lambda: module._stream_command(sys.executable, ("-c",
        "import os,time; child=os.fork(); "
        "os._exit(0) if child==0 and False else None; "
        "(os.close(1),os.close(2),time.sleep(10),os._exit(0)) if child==0 else os._exit(0)"), (0,)))
    assert code in {"host-tool-descendants", "host-tool-unreaped"}
finally:
    module.HOST_TOOL_SECONDS = original_timeout

first = module._journal_record(0, "0" * 64, "genesis", {"fixed": True})
second = module._journal_record(1, first["sha256"], "asset-intent", {"name": "fixed"})
assert module._parse_journal(module._canonical(first) + b"\n" + module._canonical(second) + b"\n") == [first, second]
tampered = {**second, "body": {"name": "replacement"}}
rejected(lambda: module._parse_journal(module._canonical(first) + b"\n" + module._canonical(tampered) + b"\n"))

class Node:
    st_dev = 1
    st_ino = 2
    st_mode = 0o040700
    st_uid = 0
    st_gid = 0
    st_nlink = 2
    st_size = 64

chain_originals = module.os.open, module.os.fstat, module.os.close
try:
    closed = []
    module.os.open = lambda *_args, **_kwargs: 10
    module.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("root-identity"))
    module.os.close = lambda descriptor: closed.append(descriptor)
    expect_oserror(lambda: module._trusted_chain(Path("/child")))
    assert closed == [10]

    opened = iter((10, 11))
    closed = []
    module.os.open = lambda *_args, **_kwargs: next(opened)
    module.os.fstat = lambda descriptor: Node() if descriptor == 10 else \
        (_ for _ in ()).throw(OSError("child-identity"))
    expect_oserror(lambda: module._trusted_chain(Path("/child")))
    assert closed == [11, 10]

    class HostileChild(Node):
        st_uid = 1
    opened = iter((10, 11))
    closed = []
    module.os.open = lambda *_args, **_kwargs: next(opened)
    module.os.fstat = lambda descriptor: Node() if descriptor == 10 else HostileChild()
    rejected(lambda: module._trusted_chain(Path("/child")))
    assert closed == [11, 10]
finally:
    module.os.open, module.os.fstat, module.os.close = chain_originals

open_dir_originals = module._open_directory_nofollow, module.os.fstat, module.os.close
try:
    for observed in (OSError("directory-identity"), HostileChild()):
        closed = []
        module._open_directory_nofollow = lambda _path: 20
        module.os.fstat = lambda _descriptor, observed=observed: (
            (_ for _ in ()).throw(observed) if isinstance(observed, OSError) else observed
        )
        module.os.close = lambda descriptor: closed.append(descriptor)
        if isinstance(observed, OSError):
            expect_oserror(lambda: module._open_dir(Path("/fixed")))
        else:
            rejected(lambda: module._open_dir(Path("/fixed")))
        assert closed == [20]
finally:
    module._open_directory_nofollow, module.os.fstat, module.os.close = open_dir_originals

state_identity = module._identity(Node())
journal_node = Node(); journal_node.st_ino = 3; journal_node.st_mode = 0o100600; journal_node.st_nlink = 1
journal_identity = module._identity(journal_node)
anchor_value = {
    "version": "cogs.stage2-phase-a-anchor/v2", "source_revision": "a" * 40,
    "source_manifest_sha256": "b" * 64, "trusted_parent_chain": [],
    "state": state_identity, "journal": journal_identity,
}
assert module._parse_anchor(module._canonical(anchor_value) + b"\n") == anchor_value
mutable_state = Node(); mutable_state.st_size = 4096; mutable_state.st_nlink = 99
module._validate_anchored_nodes(anchor_value, mutable_state, journal_node)
moved_state = Node(); moved_state.st_ino = 99
rejected(lambda: module._validate_anchored_nodes(anchor_value, moved_state, journal_node))
moved_journal = Node(); moved_journal.st_ino = 99; moved_journal.st_mode = 0o100600; moved_journal.st_nlink = 1
rejected(lambda: module._validate_anchored_nodes(anchor_value, mutable_state, moved_journal))
forged = module._canonical(anchor_value).replace(b'"version":', b'"version":"forged","version":', 1) + b"\n"
rejected(lambda: module._parse_anchor(forged))
anchor_node = Node(); anchor_node.st_ino = 4; anchor_node.st_mode = 0o100400; anchor_node.st_nlink = 1
anchor_identity = module._identity(anchor_node)
anchor_raw = module._canonical(anchor_value) + b"\n"
anchor_digest = module.hashlib.sha256(anchor_raw).hexdigest()
genesis = {"anchor_sha256": anchor_digest, "state": state_identity,
           "journal": journal_identity, "anchor": anchor_identity}
module._validate_anchor_journal(anchor_value, anchor_digest, genesis, anchor_node)
rejected(lambda: module._validate_anchor_journal(anchor_value, "0" * 64, genesis, anchor_node))
moved_anchor = Node(); moved_anchor.st_ino = 40; moved_anchor.st_mode = 0o100400; moved_anchor.st_nlink = 1
rejected(lambda: module._validate_anchor_journal(anchor_value, anchor_digest, genesis, moved_anchor))
resized_anchor = Node(); resized_anchor.st_ino = 4; resized_anchor.st_mode = 0o100400
resized_anchor.st_nlink = 1; resized_anchor.st_size = anchor_node.st_size + 1
rejected(lambda: module._validate_anchor_journal(anchor_value, anchor_digest, genesis, resized_anchor))

append_originals = module._read_journal_unanchored, module._open_dir, module.os.open, module.os.fstat, module.os.close
try:
    closed = []
    module._read_journal_unanchored = lambda: [first]
    module._open_dir = lambda _path: 20
    module.os.open = lambda *_args, **_kwargs: 21
    module.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("journal-identity"))
    module.os.close = lambda descriptor: closed.append(descriptor)
    expect_oserror(lambda: module._append_journal("fixed", {}))
    assert closed == [21, 20]
finally:
    (module._read_journal_unanchored, module._open_dir, module.os.open,
     module.os.fstat, module.os.close) = append_originals

initialize_originals = (
    module._held_path_absent, module._mkdir_policy, module.os.mkdir, module.os.stat,
    module.os.open, module.os.close,
)
try:
    closed = []
    opened = [0]
    module._held_path_absent = lambda _path: True
    module._mkdir_policy = lambda *_args, **_kwargs: (False, state_identity)
    module.os.mkdir = lambda *_args, **_kwargs: None
    module.os.stat = lambda *_args, **_kwargs: Node()
    def initialize_open(*_args, **_kwargs):
        if opened[0] == 0:
            opened[0] += 1
            return 30
        raise OSError("anchor-open")
    module.os.open = initialize_open
    module.os.close = lambda descriptor: closed.append(descriptor)
    expect_oserror(lambda: module._initialize_state("a" * 40, "b" * 64))
    assert closed == [30]
finally:
    (module._held_path_absent, module._mkdir_policy, module.os.mkdir, module.os.stat,
     module.os.open, module.os.close) = initialize_originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-replacement-") as temporary:
    directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    path = Path(temporary, "owned")
    path.write_bytes(b"owned")
    descriptor = os.open("owned", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    identity = module._identity(os.fstat(descriptor))
    path.unlink()
    path.write_bytes(b"replacement")
    rejected(lambda: module._unlink_exact(directory, "owned", descriptor, identity,
                                          module.hashlib.sha256(b"owned").hexdigest()))
    assert path.read_bytes() == b"replacement"
    os.close(descriptor)
    os.close(directory)

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-partial-replacement-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    directory_path = Path(temporary)
    partial = directory_path / ".asset.partial"
    final = directory_path / "asset.bin"
    partial.write_bytes(b"owned")
    directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = os.open(partial.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    partial.unlink()
    partial.write_bytes(b"replacement")
    module._cleanup_failed_asset_publication(
        directory, descriptor, partial, final, {"journaled": False},
    )
    assert partial.read_bytes() == b"replacement"
    os.close(descriptor)
    os.close(directory)

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-assets-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    assets = Path(temporary, "assets")
    assets.mkdir(mode=0o700)
    directory_identity = module._identity(assets.stat(follow_symlinks=False))
    body = b"asset-bytes"
    final = assets / "fixed.bin"
    final.write_bytes(body)
    final.chmod(0o400)
    file_identity = module._identity(final.stat(follow_symlinks=False))
    assert module._same_directory_authority(
        assets.stat(follow_symlinks=False), directory_identity,
    )
    records = [
        {"kind": "asset-directory-owned", "body": {"identity": directory_identity}},
        {"kind": "asset-final-owned", "body": {
            "name": final.name, "identity": file_identity, "sha256": module.hashlib.sha256(body).hexdigest(),
        }},
    ]
    original_assets, original_open_dir = module.ASSETS, module._open_dir
    try:
        module.ASSETS = assets
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        assert module._cleanup_assets.__globals__["ASSETS"] == assets
        module._cleanup_assets(records)
        assert not assets.exists()
    finally:
        module.ASSETS, module._open_dir = original_assets, original_open_dir

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-incomplete-replacement-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    assets = Path(temporary, "assets")
    assets.mkdir(mode=0o700)
    directory_identity = module._identity(assets.stat(follow_symlinks=False))
    partial = assets / ".fixed.partial"
    partial.write_bytes(b"owned")
    partial_identity = module._identity(partial.stat(follow_symlinks=False))
    partial.unlink()
    partial.write_bytes(b"replacement")
    records = [
        {"kind": "asset-directory-owned", "body": {"identity": directory_identity}},
        {"kind": "asset-partial-owned", "body": {"name": partial.name, "identity": partial_identity}},
    ]
    originals = module.ASSETS, module._open_dir, module.os.open, module.os.close
    opened_incomplete = []
    closed = []
    try:
        module.ASSETS = assets
        original_open, original_close = module.os.open, module.os.close
        def tracked_open(path, *args, **kwargs):
            descriptor = original_open(path, *args, **kwargs)
            if path == partial.name:
                opened_incomplete.append(descriptor)
            return descriptor
        module.os.open = tracked_open
        module.os.close = lambda descriptor: (closed.append(descriptor), original_close(descriptor))[1]
        module._open_dir = lambda path: original_open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        rejected(lambda: module._cleanup_assets(records))
        assert opened_incomplete and opened_incomplete[0] in closed
        assert partial.read_bytes() == b"replacement"
    finally:
        module.ASSETS, module._open_dir, module.os.open, module.os.close = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-state-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    parent = Path(temporary, "completion-v1")
    state = parent / "phase-a-candidate-v1"
    anchor = parent / ".cogs-stage2-phase-a-anchor-v1.json"
    state.mkdir(parents=True, mode=0o700)
    journal = state / "ownership.jsonl"
    journal.write_bytes(b"fixed-journal\n")
    anchor_raw = b'{"fixed":"anchor"}\n'
    anchor.write_bytes(anchor_raw)
    metadata = []
    records = []
    for index, kind in enumerate(("observation-owned", "cleanup-owned", "residue-owned", "report-owned")):
        path = state / f"metadata-{index}.json"
        raw_metadata = f'{{"fixed":{index}}}\n'.encode()
        path.write_bytes(raw_metadata)
        body = {"name": path.name, "identity": module._identity(path.stat(follow_symlinks=False)),
                "sha256": module.hashlib.sha256(raw_metadata).hexdigest()}
        metadata.append(path)
        records.append({"kind": kind, "body": body})
    genesis = {"state": module._identity(state.stat(follow_symlinks=False)),
               "journal": module._identity(journal.stat(follow_symlinks=False)),
               "anchor": module._identity(anchor.stat(follow_symlinks=False)),
               "anchor_sha256": module.hashlib.sha256(anchor_raw).hexdigest()}
    records.insert(0, {"kind": "genesis", "body": genesis})
    originals = module.STATE, module.ANCHOR, module.JOURNAL, module._open_dir
    try:
        module.STATE, module.ANCHOR, module.JOURNAL = state, anchor, journal
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        unknown = state / "hostile-unknown"
        unknown.write_bytes(b"preserve")
        rejected(lambda: module._cleanup_evidence_state(records))
        assert unknown.read_bytes() == b"preserve"
        unknown.unlink()
        module._cleanup_evidence_state(records)
        assert not state.exists() and not anchor.exists() and parent.exists()
    finally:
        module.STATE, module.ANCHOR, module.JOURNAL, module._open_dir = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-state-replacement-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    parent = Path(temporary, "completion-v1")
    state = parent / "phase-a-candidate-v2"
    detached = parent / "detached-owned-state"
    anchor = parent / ".cogs-stage2-phase-a-anchor-v2.json"
    state.mkdir(parents=True, mode=0o700)
    journal = state / "ownership.jsonl"
    journal.write_bytes(b"fixed-journal\n")
    anchor_raw = b'{"fixed":"anchor"}\n'
    anchor.write_bytes(anchor_raw)
    records = []
    for index, kind in enumerate(("observation-owned", "cleanup-owned", "residue-owned", "report-owned")):
        path = state / f"metadata-{index}.json"
        raw_metadata = f'{{"fixed":{index}}}\n'.encode()
        path.write_bytes(raw_metadata)
        records.append({"kind": kind, "body": {
            "name": path.name, "identity": module._identity(path.stat(follow_symlinks=False)),
            "sha256": module.hashlib.sha256(raw_metadata).hexdigest(),
        }})
    genesis = {"state": module._identity(state.stat(follow_symlinks=False)),
               "journal": module._identity(journal.stat(follow_symlinks=False)),
               "anchor": module._identity(anchor.stat(follow_symlinks=False)),
               "anchor_sha256": module.hashlib.sha256(anchor_raw).hexdigest()}
    records.insert(0, {"kind": "genesis", "body": genesis})
    originals = module.STATE, module.ANCHOR, module.JOURNAL, module._open_dir, module.os.stat
    swapped = [False]
    try:
        module.STATE, module.ANCHOR, module.JOURNAL = state, anchor, journal
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        original_stat = module.os.stat
        def swapping_stat(path, *args, **kwargs):
            if path == state.name and kwargs.get("dir_fd") is not None and not swapped[0]:
                state.rename(detached)
                state.mkdir(mode=0o700)
                swapped[0] = True
            return original_stat(path, *args, **kwargs)
        module.os.stat = swapping_stat
        rejected(lambda: module._cleanup_evidence_state(records))
        assert swapped == [True] and state.is_dir() and detached.is_dir() and anchor.is_file()
    finally:
        module.STATE, module.ANCHOR, module.JOURNAL, module._open_dir, module.os.stat = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-export-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    export_root = Path(temporary, "export")
    export_root.mkdir(mode=0o755)
    directory_identity = module._identity(export_root.stat(follow_symlinks=False))
    exported = export_root / "candidate.json"
    raw_export = b'{"authority":"candidate","qualified":false}\n'
    exported.write_bytes(raw_export)
    exported.chmod(0o444)
    assert module._same_directory_authority(
        export_root.stat(follow_symlinks=False), directory_identity,
    )
    owned = {
        "directory": directory_identity, "file": module._identity(exported.stat(follow_symlinks=False)),
        "sha256": module.hashlib.sha256(raw_export).hexdigest(),
    }
    records = [{"kind": "export-owned", "body": owned}]
    originals = (module.EXPORT_ROOT, module.EXPORT_REPORT, module._fixed_preflight,
                 module._require_state, module._append_journal, module._cleanup_evidence_state)
    appended = []
    try:
        module.EXPORT_ROOT = export_root
        module.EXPORT_REPORT = exported
        module._fixed_preflight = lambda _approval: None
        module._require_state = lambda: records
        module._append_journal = lambda kind, body: appended.append((kind, body))
        module._cleanup_evidence_state = lambda current: appended.append(("state-cleaned", current))
        assert module._cleanup_export() == 0
        assert not export_root.exists()
        assert appended == [("export-cleaned", {"sha256": owned["sha256"]}),
                            ("state-cleaned", records)]
    finally:
        (module.EXPORT_ROOT, module.EXPORT_REPORT, module._fixed_preflight,
         module._require_state, module._append_journal, module._cleanup_evidence_state) = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-held-residue-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    root = Path(temporary)
    missing = root / "held" / "missing"
    (root / "held").mkdir()
    assert module._held_path_absent(missing)
    missing.write_bytes(b"present")
    assert not module._held_path_absent(missing)
    missing.unlink()
    (root / "loop").symlink_to(root / "loop")
    assert failure_code(lambda: module._held_path_absent(root / "loop" / "missing")) == \
        "residue-observation-uncertainty"
    original_stat = module.os.stat
    drift_calls = [0]
    def drifting_stat(path, *args, **kwargs):
        if path == "drift":
            drift_calls[0] += 1
            if drift_calls[0] == 1:
                raise FileNotFoundError(2, "missing")
            return original_stat(root / "held", follow_symlinks=False)
        return original_stat(path, *args, **kwargs)
    try:
        module.os.stat = drifting_stat
        assert failure_code(lambda: module._held_path_absent(root / "held" / "drift")) == \
            "residue-observation-uncertainty"
    finally:
        module.os.stat = original_stat

class IdentityNode:
    st_dev = 1
    st_ino = 2
    st_mode = 0o040700
    st_uid = 0
    st_gid = 0
    st_nlink = 2
    st_size = 64

identity_originals = module.os.open, module.os.fstat, module.os.close
try:
    closed = []
    module.os.open = lambda *_args, **_kwargs: 10
    module.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("root-identity"))
    module.os.close = lambda descriptor: closed.append(descriptor)
    assert failure_code(lambda: module._held_path_absent(Path("/missing"))) == \
        "residue-observation-uncertainty"
    assert closed == [10]

    opened = iter((10, 11))
    closed = []
    module.os.open = lambda *_args, **_kwargs: next(opened)
    module.os.fstat = lambda descriptor: IdentityNode() if descriptor == 10 else \
        (_ for _ in ()).throw(OSError("child-identity"))
    assert failure_code(lambda: module._held_path_absent(Path("/child/missing"))) == \
        "residue-observation-uncertainty"
    assert closed == [11, 10]
finally:
    module.os.open, module.os.fstat, module.os.close = identity_originals

residue_original = module._held_path_absent
try:
    checked = []
    module._held_path_absent = lambda path: (checked.append(path), True)[1]
    assert module._post_export_residue() == 0
    assert checked == [module.ROOTFS_STATE, module.ARTIFACT_ROOT, module.ASSETS,
                       module.STATE, module.ANCHOR, module.EXPORT_ROOT]
    for hostile_path, expected in (
        (module.ROOTFS_STATE, "rootfs-baseline-not-restored"), (module.ARTIFACT_ROOT, "cache-residue"),
        (module.ASSETS, "asset-residue"), (module.STATE, "state-residue"),
        (module.ANCHOR, "state-residue"), (module.EXPORT_ROOT, "export-residue"),
    ):
        module._held_path_absent = lambda path, hostile_path=hostile_path: path != hostile_path
        assert failure_code(module._post_export_residue) == expected
finally:
    module._held_path_absent = residue_original

# The direct KVM proof is fixed to linux/kvm.h KVM_GET_API_VERSION and accepts
# only ABI version 12. No VM process or host package mutation is involved.
class Device:
    st_mode = 0o020600
    st_dev = 1
    st_ino = 2
    st_rdev = 3

originals = (module.os.stat, module.os.access, module.os.open, module.os.fstat, module.os.close, module.fcntl.ioctl)
closed = []
try:
    module.os.stat = lambda *_args, **_kwargs: Device()
    module.os.access = lambda *_args, **_kwargs: True
    module.os.open = lambda *_args, **_kwargs: 99
    module.os.fstat = lambda descriptor: Device() if descriptor == 99 else None
    module.os.close = lambda descriptor: closed.append(descriptor)
    module.fcntl.ioctl = lambda descriptor, request: 12 if (descriptor, request) == (99, module.KVM_GET_API_VERSION) else None
    assert module._prove_kvm() == {"device_present": True, "device_accessible": True, "api_version": 12}
    assert closed == [99]
    module.fcntl.ioctl = lambda *_args: 11
    rejected(module._prove_kvm)
finally:
    module.os.stat, module.os.access, module.os.open, module.os.fstat, module.os.close, module.fcntl.ioctl = originals

source = RUNNER.read_text(encoding="utf-8")
assert "KVM_GET_API_VERSION = 0xAE00" in source and "fcntl.ioctl(descriptor, KVM_GET_API_VERSION)" in source
assert "extractall" not in source and ".extract(" not in source
assert "completion_kata_coordinator" not in source
assert "runtime-extraction-unsafe-or-unknown" in source
assert "build._require_equal_builds(first, second)" in source
assert "start_new_session=True" in source and "os.killpg(process.pid" in source
assert "EXPORT_REPORT" in source and '"export-owned"' in source
assert "os.path.lexists" not in source and "_held_path_absent" in source
anchor_write = source.index('_write_all(anchor, anchor_raw); os.fsync(anchor)')
anchor_identity = source.index('anchor_identity = _identity(os.fstat(anchor))')
assert anchor_write < anchor_identity < source.index('"anchor": anchor_identity')
assert '128, 0o600' in source and 'sentinel_identity["mode"] == 0o600' in source
print("stage2 phase-a candidate portable tests passed")

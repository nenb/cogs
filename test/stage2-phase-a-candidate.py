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


def thrown(callback):
    try:
        callback()
    except BaseException as error:
        return error
    raise AssertionError("expected failure")


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
stage_cases = (
    ("success", "success", "complete", "pass", "pass"),
    ("success", "failure", "complete", "pass", "fail"),
    ("success", "blocked", "rootfs-bootstrap", "pass", "blocked"),
    ("success", "blocked", "operation-establishment", "pass", "blocked"),
    ("success", "blocked", "materializer-dispatch", "pass", "blocked"),
    ("success", "blocked", "complete", "pass", "blocked"),
    ("failure", "blocked", "fixed-input", "fail", "blocked"),
    ("blocked", "blocked", "not-reached", "blocked", "blocked"),
    ("not-reached", "not-reached", "not-reached", "unknown", "unknown"),
)
successful_rootfs = {
    "candidate_count": 2, "cache_count": 16, "entry_count": 4353, "manifest_size": 1049443,
    "manifest_sha256": "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1",
    "ustar_size": 136905728,
    "ustar_sha256": "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397",
    "equal": True, "pins_match": True,
}
def causal_report(cache, runtime, setup, cache_check, runtime_check):
    candidate = module._base_report()
    candidate["stage_evidence"] = {
        "artifact_cache": {"status": cache, "elapsed_ms": 1 if cache in {"success", "failure"} else 0},
        "runtime_assets": {"status": runtime, "elapsed_ms": 1 if runtime in {"success", "failure"} else 0},
    }
    candidate["first_build_setup"] = setup
    candidate["checks"].update({"artifact_cache": cache_check, "runtime_assets": runtime_check})
    counters = {name: 0 for name in module.STRUCTURAL_COUNTERS}
    if setup == "complete":
        module._set_phase(candidate["rootfs_phases"], "first-build-work", "failure", "failed", 1, counters)
        module._block_phases(candidate["rootfs_phases"], tuple(
            name for name in module.ROOTFS_PHASES[1:] if name != "recovery-attempt-1"
        ))
    if runtime in {"success", "failure"}:
        candidate["rootfs_phases"] = module._empty_phases()
        for name in module.ROOTFS_PHASES:
            if name != "recovery-attempt-1":
                module._set_phase(candidate["rootfs_phases"], name, "success", "success", 1, counters)
        candidate["rootfs"] = successful_rootfs
    if runtime == "success":
        candidate["runtime_assets"] = [{"component": item.component, "release": item.release, "name": item.name,
            "size": item.size, "sha256": item.sha256, "downloaded": True, "extracted": False}
            for item in module.RUNTIME_ASSETS]
    return candidate
for case in stage_cases:
    module._canonical_report(causal_report(*case))

causal_failures = []
cache_failure_attempted = causal_report("failure", "blocked", "fixed-input", "fail", "blocked")
cache_failure_attempted["rootfs_phases"] = causal_report(
    "success", "blocked", "complete", "pass", "blocked",
)["rootfs_phases"]
causal_failures.append(cache_failure_attempted)
for prephase_setup in ("rootfs-bootstrap", "operation-establishment", "materializer-dispatch"):
    prephase_with_work = causal_report("success", "blocked", "complete", "pass", "blocked")
    prephase_with_work["first_build_setup"] = prephase_setup
    causal_failures.append(prephase_with_work)
for prephase_setup in ("rootfs-bootstrap", "operation-establishment", "materializer-dispatch"):
    unresolved_runtime = causal_report(
        "success", "not-reached", prephase_setup, "pass", "unknown",
    )
    causal_failures.append(unresolved_runtime)
complete_without_work = causal_report(
    "success", "not-reached", "rootfs-bootstrap", "pass", "unknown",
)
complete_without_work["first_build_setup"] = "complete"
causal_failures.append(complete_without_work)
settled_blocked = causal_report("success", "failure", "complete", "pass", "fail")
settled_blocked["stage_evidence"]["runtime_assets"] = {"status": "blocked", "elapsed_ms": 0}
settled_blocked["checks"]["runtime_assets"] = "blocked"
causal_failures.append(settled_blocked)
unsettled_runtime = causal_report("success", "blocked", "complete", "pass", "blocked")
unsettled_runtime["stage_evidence"]["runtime_assets"] = {"status": "failure", "elapsed_ms": 1}
unsettled_runtime["checks"]["runtime_assets"] = "fail"
causal_failures.append(unsettled_runtime)
failed_runtime_not_reached = causal_report("success", "blocked", "complete", "pass", "blocked")
failed_runtime_not_reached["stage_evidence"]["runtime_assets"] = {"status": "not-reached", "elapsed_ms": 0}
failed_runtime_not_reached["checks"]["runtime_assets"] = "unknown"
causal_failures.append(failed_runtime_not_reached)
for impossible in causal_failures:
    rejected(lambda impossible=impossible: module._canonical_report(impossible))

rejected(lambda: module._canonical_report({**module._base_report(), "stage_evidence": {
    "artifact_cache": {"status": "failure", "elapsed_ms": 1},
    "runtime_assets": {"status": "blocked", "elapsed_ms": 0}}, "first_build_setup": "fixed-input"}))
for hostile_stage in (
    {"artifact_cache": {"status": "success", "elapsed_ms": 1}},
    {"artifact_cache": {"status": "failure", "elapsed_ms": 1},
     "runtime_assets": {"status": "failure", "elapsed_ms": 1}},
    {"artifact_cache": {"status": "blocked", "elapsed_ms": 1},
     "runtime_assets": {"status": "blocked", "elapsed_ms": 0}},
):
    rejected(lambda hostile_stage=hostile_stage: module._canonical_report(
        {**module._base_report(), "stage_evidence": hostile_stage},
    ))
valid_counters = {name: index for index, name in enumerate(module.STRUCTURAL_COUNTERS)}
def counter_values(value=0):
    return {name: value for name in module.STRUCTURAL_COUNTERS}


def trusted_counter_provider(name="completion_rootfs_build", counters=valid_counters,
                             start_error=None, read_error=None, deltas=None,
                             start_faults=(), read_faults=(), clock=None,
                             start_delay_ns=0, read_delay_ns=0):
    provider = types.ModuleType(name)
    handles = {}
    issued = 0
    starts = reads = 0
    scripted = None if deltas is None else list(deltas)
    provider.counter_events = []
    def start(phase):
        nonlocal issued, starts
        starts += 1
        provider.counter_events.append(("start", phase))
        if clock is not None:
            clock[0] += start_delay_ns
        if start_error is not None or starts in start_faults:
            raise start_error or RuntimeError("scripted-start-fault")
        issued += 1
        value = counters if scripted is None else scripted[issued - 1]
        handles[issued] = (phase, value)
        return issued
    def read(phase, handle):
        nonlocal reads
        reads += 1
        provider.counter_events.append(("read", phase, handle))
        if clock is not None:
            clock[0] += read_delay_ns
        bound, value = handles.pop(handle)
        assert bound == phase
        if read_error is not None or reads in read_faults:
            raise read_error or RuntimeError("scripted-read-fault")
        return dict(value)
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

timed_originals = module.time.monotonic_ns, module._elapsed_ms
try:
    timed_faults = (
        ("start-clock", lambda: (_ for _ in ()).throw(RuntimeError("start-clock")),
         RuntimeError, "start-clock", True),
        ("end-clock", iter((10, RuntimeError("end-clock"))), RuntimeError, "end-clock", False),
        ("elapsed-bound", iter((10, 10 + 5_400 * module.NS_PER_SECOND + 1)),
         module.CandidateError, "timing-metadata", True),
    )
    for name, clock_script, error_type, detail, read_fault in timed_faults:
        timed_provider = trusted_counter_provider(
            read_error=RuntimeError("secondary-read") if read_fault else None,
        )
        timed_phases = module._empty_phases()
        callback_events = []
        if callable(clock_script):
            module.time.monotonic_ns = clock_script
        else:
            def scripted_clock(clock_script=clock_script):
                value = next(clock_script)
                if isinstance(value, BaseException):
                    raise value
                return value
            module.time.monotonic_ns = scripted_clock
        error = thrown(lambda timed_provider=timed_provider, timed_phases=timed_phases:
                       module._timed_rootfs_phase(
                           timed_phases, "pin", "rootfs-pin", timed_provider,
                           lambda: callback_events.append("callback"),
                       ))
        assert type(error) is error_type
        assert (error.code if type(error) is module.CandidateError else str(error)) == detail
        assert timed_provider.counter_events == [("start", "pin"), ("read", "pin", 1)]
        assert callback_events == ([] if name == "start-clock" else ["callback"])
        assert module._phase(timed_phases, "pin")["status"] == "evidence-failure"
        rejected(lambda timed_phases=timed_phases: module._canonical_report(
            {**module._base_report(), "rootfs_phases": timed_phases},
        ))

    accounting_provider = trusted_counter_provider()
    accounting_phases = module._empty_phases()
    accounting_clock = iter((10, 20))
    module.time.monotonic_ns = lambda: next(accounting_clock)
    module._elapsed_ms = lambda _elapsed: (_ for _ in ()).throw(module.CandidateError("timing-metadata"))
    assert failure_code(lambda: module._timed_rootfs_phase(
        accounting_phases, "settlement", "rootfs-settlement", accounting_provider, lambda: None,
    )) == "timing-metadata"
    assert accounting_provider.counter_events == [
        ("start", "settlement"), ("read", "settlement", 1),
    ]
    assert module._phase(accounting_phases, "settlement")["status"] == "evidence-failure"
finally:
    module.time.monotonic_ns, module._elapsed_ms = timed_originals

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

setup_build = trusted_counter_provider("completion_rootfs_build")
setup_build.BUILD_SECONDS = 900
setup_build.BuildAttemptError = FakeBuildAttemptError
setup_build.builder = types.SimpleNamespace(_cleanup_owned=lambda *_args: None,
                                            _begin_operation=lambda *_args: "must-not-run")
setup_build.materializer = types.SimpleNamespace(_reload_and_cleanup=lambda *_args: None,
                                                _materialize_unmasked=lambda *_args: "must-not-run")
setup_build._build_once = lambda *_args: (_ for _ in ()).throw(FakeBuildAttemptError("not-started"))
setup_marker = {"value": "operation-establishment"}
assert failure_code(lambda: module._candidate_build(
    setup_build, "approval", "control", "first", "e" * 64, module._empty_phases(), setup_marker,
)) == "rootfs-first-build-not-started"
assert setup_marker == {"value": "operation-establishment"}

postwork_clock = [0]
postwork_build = trusted_counter_provider(
    "completion_rootfs_build", deltas=(counter_values(20), counter_values(3), counter_values(4)),
    clock=postwork_clock, start_delay_ns=2_000_000, read_delay_ns=3_000_000,
)
postwork_build.BUILD_SECONDS = 900
postwork_build.BuildAttemptError = FakeBuildAttemptError
postwork_events = []
def normal_cleanup(*_args):
    postwork_events.append("cleanup-failure")
    postwork_clock[0] += 30_000_000
    raise RuntimeError("primary cleanup uncertainty")
def fallback_cleanup(*_args):
    postwork_events.append("cleanup-success")
    postwork_clock[0] += 40_000_000
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
module.time.monotonic_ns = lambda: postwork_clock[0]
try:
    assert failure_code(lambda: module._candidate_build(
        postwork_build, "approval", "control", "first", "e" * 64, postwork_phases,
    )) == "rootfs-first-build-inline-cleanup"
finally:
    module.time.monotonic_ns = original_monotonic_ns
assert postwork_events == ["cleanup-failure", "cleanup-success"]
assert (module._phase(postwork_phases, "first-build-work")["status"],
        module._phase(postwork_phases, "first-build-work")["outcome"]) == ("failure", "postwork")
assert (module._phase(postwork_phases, "first-inline-cleanup")["status"],
        module._phase(postwork_phases, "first-inline-cleanup")["outcome"]) == ("failure", "failed")
assert module._phase(postwork_phases, "first-inline-cleanup")["structural_counters"] == counter_values(7)
assert module._phase(postwork_phases, "first-build-work")["structural_counters"] == counter_values(13)
assert module._phase(postwork_phases, "first-inline-cleanup")["elapsed_ms"] == 70
assert module._phase(postwork_phases, "first-build-work")["elapsed_ms"] == 0


def counter_build(deltas, callback, **provider_options):
    value = trusted_counter_provider("completion_rootfs_build", deltas=deltas, **provider_options)
    value.BUILD_SECONDS = 900
    value.BuildAttemptError = FakeBuildAttemptError
    value.materializer = types.SimpleNamespace(_reload_and_cleanup=lambda *_args: None)
    value.builder = types.SimpleNamespace(_cleanup_owned=lambda *_args: None)
    value._build_once = lambda *_args: callback(value)
    return value


def poisoned_report(phases):
    report = module._base_report()
    report["rootfs_phases"] = phases
    return report

successful_clock = [0]
def successful_cleanup(*_args):
    successful_clock[0] += 10_000_000
successful = counter_build(
    (counter_values(10), counter_values(3)),
    lambda build: (build.builder._cleanup_owned(None), "candidate")[1],
    clock=successful_clock, start_delay_ns=20_000_000, read_delay_ns=100_000_000,
)
successful.builder._cleanup_owned = successful_cleanup
successful._build_once = lambda *_args: (successful.builder._cleanup_owned(None), "candidate")[1]
successful_phases = module._empty_phases()
module.time.monotonic_ns = lambda: successful_clock[0]
try:
    assert module._candidate_build(
        successful, "approval", "control", "first", "e" * 64, successful_phases,
    ) == "candidate"
finally:
    module.time.monotonic_ns = original_monotonic_ns
assert module._phase(successful_phases, "first-build-work")["structural_counters"] == counter_values(7)
assert module._phase(successful_phases, "first-inline-cleanup")["structural_counters"] == counter_values(3)
assert module._phase(successful_phases, "first-inline-cleanup")["elapsed_ms"] == 10
assert module._phase(successful_phases, "first-build-work")["elapsed_ms"] == 0
assert successful.counter_events == [
    ("start", "first-build-work"), ("start", "first-inline-cleanup"),
    ("read", "first-inline-cleanup", 2), ("read", "first-build-work", 1),
]

nested_events = []
nested_clock = [0]
nested = counter_build(
    (counter_values(8), counter_values(2)), lambda _build: None,
    clock=nested_clock, start_delay_ns=5_000_000, read_delay_ns=7_000_000,
)
def nested_once(*_args):
    nested_events.append("top")
    nested_clock[0] += 10_000_000
    nested.materializer._reload_and_cleanup(None)
nested.builder._cleanup_owned = nested_once
nested._build_once = lambda *_args: (nested.builder._cleanup_owned(None), "candidate")[1]
nested_phases = module._empty_phases()
module.time.monotonic_ns = lambda: nested_clock[0]
try:
    module._candidate_build(nested, "approval", "control", "first", "e" * 64, nested_phases)
finally:
    module.time.monotonic_ns = original_monotonic_ns
assert [event for event in nested.counter_events if event[0] == "start"] == [
    ("start", "first-build-work"), ("start", "first-inline-cleanup"),
]
assert nested_events == ["top"]
assert module._phase(nested_phases, "first-inline-cleanup")["elapsed_ms"] == 10
assert module._phase(nested_phases, "first-build-work")["elapsed_ms"] == 0

prevented = []
start_fault = counter_build(
    (counter_values(10),), lambda build: build.builder._cleanup_owned(None), start_faults=(2,),
)
start_fault.builder._cleanup_owned = lambda *_args: prevented.append("callback")
start_fault._build_once = lambda *_args: start_fault.builder._cleanup_owned(None)
start_fault_phases = module._empty_phases()
assert failure_code(lambda: module._candidate_build(
    start_fault, "approval", "control", "first", "e" * 64, start_fault_phases,
)) == "rootfs-counter-contract"
assert prevented == []
assert all(module._phase(start_fault_phases, name)["status"] == "evidence-failure"
           for name in ("first-build-work", "first-inline-cleanup"))
rejected(lambda: module._canonical_report(poisoned_report(start_fault_phases)))

for fault_read in (1, 2):
    attempts = []
    faulting = counter_build(
        (counter_values(20), counter_values(3), counter_values(4)), lambda _build: None,
        read_faults=(fault_read,),
    )
    faulting.builder._cleanup_owned = lambda *_args: (attempts.append("primary"),
        (_ for _ in ()).throw(RuntimeError("primary")))[1]
    faulting.materializer._reload_and_cleanup = lambda *_args: attempts.append("fallback")
    def two_attempts(*_args, faulting=faulting):
        try:
            faulting.builder._cleanup_owned(None)
        except BaseException:
            faulting.materializer._reload_and_cleanup(None)
        raise FakeBuildAttemptError("success")
    faulting._build_once = two_attempts
    fault_phases = module._empty_phases()
    assert failure_code(lambda faulting=faulting, fault_phases=fault_phases: module._candidate_build(
        faulting, "approval", "control", "first", "e" * 64, fault_phases,
    )) == "rootfs-counter-contract"
    assert attempts == ["primary", "fallback"]
    assert all(module._phase(fault_phases, name)["status"] == "evidence-failure"
               for name in ("first-build-work", "first-inline-cleanup"))
    rejected(lambda fault_phases=fault_phases: module._canonical_report(poisoned_report(fault_phases)))

for deltas in (
    (counter_values(1_000_000_000), counter_values(600_000_000), counter_values(600_000_000)),
    (counter_values(2), counter_values(3)),
):
    hostile = counter_build(deltas, lambda _build: None)
    if len(deltas) == 3:
        hostile._build_once = lambda *_args, hostile=hostile: (
            hostile.builder._cleanup_owned(None), hostile.materializer._reload_and_cleanup(None),
            (_ for _ in ()).throw(FakeBuildAttemptError("success")),
        )[-1]
    else:
        hostile._build_once = lambda *_args, hostile=hostile: hostile.builder._cleanup_owned(None)
    hostile_phases = module._empty_phases()
    assert failure_code(lambda hostile=hostile, hostile_phases=hostile_phases: module._candidate_build(
        hostile, "approval", "control", "first", "e" * 64, hostile_phases,
    )) == "rootfs-counter-contract"
    assert all(module._phase(hostile_phases, name)["status"] == "evidence-failure"
               for name in ("first-build-work", "first-inline-cleanup"))

work_read_fault = counter_build(
    (counter_values(10), counter_values(3)),
    lambda build: (build.builder._cleanup_owned(None), "candidate")[1], read_faults=(2,),
)
work_fault_phases = module._empty_phases()
assert failure_code(lambda: module._candidate_build(
    work_read_fault, "approval", "control", "first", "e" * 64, work_fault_phases,
)) == "rootfs-counter-contract"
assert all(module._phase(work_fault_phases, name)["status"] == "evidence-failure"
           for name in ("first-build-work", "first-inline-cleanup"))

bound_clock = [0]
bound_events = []
bound_fault = counter_build(
    (counter_values(20), counter_values(3), counter_values(4)), lambda _build: None,
    clock=bound_clock, start_delay_ns=1, read_delay_ns=1,
)
def over_bound_cleanup(*_args):
    bound_events.append("over-bound")
    bound_clock[0] += 5_400 * module.NS_PER_SECOND + 1
def after_bound_cleanup(*_args):
    bound_events.append("fallback")
bound_fault.builder._cleanup_owned = over_bound_cleanup
bound_fault.materializer._reload_and_cleanup = after_bound_cleanup
original_bound_cleanup = bound_fault.builder._cleanup_owned
original_bound_reload = bound_fault.materializer._reload_and_cleanup
def bound_attempt(*_args):
    try:
        bound_fault.builder._cleanup_owned(None)
    except BaseException:
        bound_fault.materializer._reload_and_cleanup(None)
    raise FakeBuildAttemptError("success")
bound_fault._build_once = bound_attempt
bound_phases = module._empty_phases()
module.time.monotonic_ns = lambda: bound_clock[0]
try:
    assert failure_code(lambda: module._candidate_build(
        bound_fault, "approval", "control", "first", "e" * 64, bound_phases,
    )) == "timing-metadata"
finally:
    module.time.monotonic_ns = original_monotonic_ns
assert bound_fault.builder._cleanup_owned is original_bound_cleanup
assert bound_fault.materializer._reload_and_cleanup is original_bound_reload
assert bound_events == ["over-bound", "fallback"]
assert [event[0] for event in bound_fault.counter_events] == [
    "start", "start", "read", "start", "read", "read",
]
assert all(module._phase(bound_phases, name)["status"] == "evidence-failure"
           for name in ("first-build-work", "first-inline-cleanup"))
rejected(lambda: module._canonical_report(poisoned_report(bound_phases)))

clock = [100]
module.time.monotonic_ns = lambda: clock[0]
try:
    for name in ("equality", "pin", "post-verification", "settlement"):
        timing_provider = trusted_counter_provider()
        original_read = timing_provider._read_phase_structural_counters
        def delayed_read(phase, handle, original_read=original_read):
            clock[0] += 1_000_000_000
            return original_read(phase, handle)
        timing_provider._read_phase_structural_counters = delayed_read
        timing_phases = module._empty_phases()
        assert module._timed_rootfs_phase(
            timing_phases, name, "rootfs-timed", timing_provider,
            lambda: (clock.__setitem__(0, clock[0] + 7_000_000), "value")[1],
        ) == "value"
        assert module._phase(timing_phases, name)["elapsed_ms"] == 7
finally:
    module.time.monotonic_ns = original_monotonic_ns

socket_monotonic_ns = module.time.monotonic_ns
try:
    module.time.monotonic_ns = lambda: 1
    assert module._socket_timeout_seconds(2 * module.NS_PER_SECOND + 1) == 2
    assert module._socket_timeout_seconds(2 * module.NS_PER_SECOND) == 1
    rejected(lambda: module._socket_timeout_seconds(module.NS_PER_SECOND))
finally:
    module.time.monotonic_ns = socket_monotonic_ns

publication_originals = module._asset_generation, module._check_asset_deadline, module._append_journal
with tempfile.TemporaryDirectory() as temporary:
    directory_path = Path(temporary)
    partial, final = directory_path / ".asset.partial", directory_path / "asset.bin"
    directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = os.open(partial.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=directory)
    content = b"fixed-publication-content"
    assert os.write(descriptor, content) == len(content)
    asset = module.Asset("test", "1", final.name, "https://github.com/fixed", len(content),
                         module.hashlib.sha256(content).hexdigest())
    stable_generation = []
    def portable_generation(fd, _deadline, mount_id=None):
        observed = os.fstat(fd)
        if not stable_generation:
            stable_generation.append({"mount_id": 1, "dev": observed.st_dev, "ino": observed.st_ino,
                "kind": "file", "mode": 0o400, "uid": 0,
                "gid": 0, "nlink": observed.st_nlink, "size": observed.st_size,
                "mtime_ns": observed.st_mtime_ns, "ctime_ns": observed.st_ctime_ns})
        return dict(stable_generation[0])
    journal = []
    try:
        module._asset_generation = portable_generation
        module._check_asset_deadline = lambda *_args: None
        module._append_journal = lambda kind, body: journal.append((kind, body))
        publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                       "retained": None, "linked": False, "partial_unlinked": False}
        result = module._finish_asset_publication(
            asset, directory, descriptor, partial, final, module._identity(os.fstat(descriptor)), 10**30, publication,
        )
        assert result["downloaded"] and final.read_bytes() == content and not partial.exists()
        assert [kind for kind, _body in journal] == ["asset-partial-final-owned", "asset-final-owned"]
        os.close(publication["retained"])
    finally:
        os.close(directory)
        module._asset_generation, module._check_asset_deadline, module._append_journal = publication_originals

fixed_asset = module.RUNTIME_ASSETS[0]
fixed_generation = {"mount_id": 1, "dev": 2, "ino": 3, "kind": "file", "mode": 0o400,
                    "uid": 0, "gid": 0, "nlink": 1, "size": fixed_asset.size, "mtime_ns": 4, "ctime_ns": 5}
def partial_records(generation=fixed_generation):
    partial_name = "." + fixed_asset.name + ".partial"
    return [
        {"kind": "asset-partial-owned", "body": {"component": fixed_asset.component,
         "name": partial_name, "identity": {}}},
        {"kind": "asset-partial-final-owned", "body": {"component": fixed_asset.component,
         "name": partial_name, "generation": generation}},
    ]
assert module._asset_records(partial_records())[0][fixed_asset.component]["generation"] == fixed_generation

class GenerationNode:
    def __init__(self, device, inode):
        self.st_dev = device; self.st_ino = inode; self.st_mode = 0o100400
        self.st_uid = self.st_gid = 0; self.st_nlink = 1; self.st_size = 7
        self.st_mtime_ns = 8; self.st_ctime_ns = 9

mount_originals = module.fcntl.fcntl, module.os.fstat, module.os.open, module.os.read, module.os.close
try:
    nodes = {110: GenerationNode(20, 30), 111: GenerationNode(21, 31)}
    info = {1110: b"pos:\t0\nflags:\t010000000\nmnt_id:\t41\nino:\t30\n",
            1111: b"pos:\t0\nflags:\t010000000\nmnt_id:\t42\nino:\t31\n"}
    closed = []
    module.fcntl.fcntl = lambda descriptor, command, minimum: descriptor + 100
    module.os.fstat = lambda descriptor: nodes[descriptor]
    module.os.open = lambda path, _flags: int(path.rsplit("/", 1)[1]) + 1000
    module.os.read = lambda descriptor, _size: info.pop(descriptor, b"")
    module.os.close = lambda descriptor: closed.append(descriptor)
    first_generation = module._asset_generation(10, 10**30)
    second_generation = module._asset_generation(11, 10**30)
    assert (first_generation["mount_id"], first_generation["dev"], first_generation["ino"]) == (41, 20, 30)
    assert (second_generation["mount_id"], second_generation["dev"], second_generation["ino"]) == (42, 21, 31)
    assert closed == [1110, 110, 1111, 111]
finally:
    module.fcntl.fcntl, module.os.fstat, module.os.open, module.os.read, module.os.close = mount_originals
def drift_generation(generation, field):
    return {**generation, field: "directory" if field == "kind" else generation[field] + 1}


def freeze_generation_cut(cut, field):
    content = b"authentic-final-generation"
    asset = module.Asset("matrix", "1", "asset.bin", "https://github.com/fixed", len(content),
                         module.hashlib.sha256(content).hexdigest())
    base = {**fixed_generation, "size": len(content)}
    drift = drift_generation(base, field)
    scripts = {
        "writer-continuity": (base, drift),
        "name-observation": (base, base, drift, base),
        "held-observation": (base, base, base, drift),
    }
    with tempfile.TemporaryDirectory() as temporary:
        partial = Path(temporary, ".asset.partial"); partial.write_bytes(content)
        directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        writer = os.open(partial.name, os.O_RDWR | os.O_CLOEXEC, dir_fd=directory)
        values = iter(scripts[cut]); journal = []
        publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                       "retained": None, "linked": False, "partial_unlinked": False}
        originals = module._asset_generation, module._check_asset_deadline, module._append_journal
        try:
            module._asset_generation = lambda *_args: dict(next(values))
            module._check_asset_deadline = lambda *_args: None
            module._append_journal = lambda kind, body: journal.append((kind, body))
            assert failure_code(lambda: module._freeze_partial(
                asset, directory, writer, partial, 10**30, publication,
            )) == "asset-partial-replaced"
            assert partial.read_bytes() == content and journal == [] and publication["partial_final"] is None
        finally:
            module._asset_generation, module._check_asset_deadline, module._append_journal = originals
            if not publication["writer_close_attempted"]: os.close(writer)
            os.close(directory)


for generation_cut in ("writer-continuity", "name-observation", "held-observation"):
    for generation_field in module.FULL_GENERATION:
        freeze_generation_cut(generation_cut, generation_field)

for cleanup_cut in ("cleanup-reopen", "cleanup-revalidation"):
    for generation_field in module.FULL_GENERATION:
        with tempfile.TemporaryDirectory() as temporary:
            assets = Path(temporary, "assets"); assets.mkdir(mode=0o700)
            partial = assets / ("." + fixed_asset.name + ".partial"); partial.write_bytes(b"preserve")
            directory_identity = module._identity(assets.stat(follow_symlinks=False))
            records = [{"kind": "asset-directory-owned", "body": {"identity": directory_identity}},
                       *partial_records()]
            drift = drift_generation(fixed_generation, generation_field)
            values = iter((drift,) if cleanup_cut == "cleanup-reopen" else (fixed_generation, drift))
            originals = module.ASSETS, module._open_dir, module._asset_generation
            try:
                module.ASSETS = assets
                module._open_dir = lambda path: os.open(
                    path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                module._asset_generation = lambda *_args: dict(next(values))
                rejected(lambda: module._cleanup_assets(
                    records, {item.component: "not-required" for item in module.RUNTIME_ASSETS},
                ))
                assert partial.read_bytes() == b"preserve"
            finally:
                module.ASSETS, module._open_dir, module._asset_generation = originals

for identity_field in ("mount_id", "dev", "ino"):
    freeze_generation_cut("writer-continuity", identity_field)

with tempfile.TemporaryDirectory() as temporary:
    partial = Path(temporary) / ("." + fixed_asset.name + ".partial")
    partial.write_bytes(b"owned-final-generation")
    directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    immediate = {fixed_asset.component: "not-required"}
    original_generation = module._asset_generation
    try:
        module._asset_generation = lambda *_args: fixed_generation
        module._cleanup_failed_asset_publication(directory, partial, {
            "journaled": False, "partial_unlinked": False, "linked": False, "partial_final": fixed_generation,
        }, immediate, fixed_asset.component, 10**30)
        assert immediate[fixed_asset.component] == "success" and not partial.exists()
    finally:
        module._asset_generation = original_generation
        os.close(directory)
rejected(lambda: module._asset_records(list(reversed(partial_records()))))
rejected(lambda: module._asset_records(partial_records() + [{"kind": "asset-partial-final-owned",
         "body": partial_records()[1]["body"]}]))

for immediate_boundary in ("unlink", "unlink-after-effect", "fsync", "close"):
    with tempfile.TemporaryDirectory() as temporary:
        partial = Path(temporary) / ("." + fixed_asset.name + ".partial")
        partial.write_bytes(b"owned-final-generation")
        directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        immediate = {fixed_asset.component: "not-required"}
        publication = {"journaled": False, "partial_unlinked": False, "linked": False,
                       "partial_final": fixed_generation}
        originals = module._asset_generation, module.os.unlink, module.os.fsync, module.os.close
        real_unlink, real_fsync, real_close = module.os.unlink, module.os.fsync, module.os.close
        try:
            module._asset_generation = lambda *_args: fixed_generation
            if immediate_boundary == "unlink":
                module.os.unlink = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unlink-cut"))
            if immediate_boundary == "unlink-after-effect":
                def unlink_after_effect(*args, **kwargs):
                    real_unlink(*args, **kwargs)
                    raise OSError("unlink-after-effect")
                module.os.unlink = unlink_after_effect
            if immediate_boundary == "fsync":
                module.os.fsync = lambda *_args: (_ for _ in ()).throw(OSError("fsync-cut"))
            if immediate_boundary == "close":
                close_once = [False]
                def immediate_close(descriptor):
                    if not close_once[0]:
                        close_once[0] = True; real_close(descriptor); raise OSError("close-cut")
                    return real_close(descriptor)
                module.os.close = immediate_close
            thrown(lambda: module._cleanup_failed_asset_publication(
                directory, partial, publication, immediate, fixed_asset.component, 10**30,
            ))
            assert publication["partial_unlinked"]
            assert partial.exists() == (immediate_boundary == "unlink")
            assert immediate[fixed_asset.component] == "post-unlink-uncertainty"
        finally:
            module._asset_generation, module.os.unlink, module.os.fsync, module.os.close = originals
            os.close(directory)


for freeze_boundary in ("fsync-1", "fsync-2", "retained-open", "writer-close", "journal-append"):
    with tempfile.TemporaryDirectory() as temporary:
        content = b"freeze-primitive-boundary"
        asset = module.Asset("boundary", "1", "asset.bin", "https://github.com/fixed", len(content),
                             module.hashlib.sha256(content).hexdigest())
        generation = {**fixed_generation, "size": len(content)}
        partial = Path(temporary, ".asset.partial"); partial.write_bytes(content)
        directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        writer = os.open(partial.name, os.O_RDWR | os.O_CLOEXEC, dir_fd=directory)
        publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                       "retained": None, "linked": False, "partial_unlinked": False}
        originals = module._asset_generation, module._check_asset_deadline, module._append_journal,
        originals += (module.os.fsync, module.os.open, module.os.close)
        real_open, real_close, real_fsync = module.os.open, module.os.close, module.os.fsync
        try:
            module._asset_generation = lambda *_args: dict(generation)
            module._check_asset_deadline = lambda *_args: None
            fsync_calls = [0]
            if freeze_boundary.startswith("fsync-"):
                target_call = int(freeze_boundary[-1])
                def freeze_fsync(descriptor):
                    fsync_calls[0] += 1
                    if fsync_calls[0] == target_call: raise OSError("writer-fsync-cut")
                    return real_fsync(descriptor)
                module.os.fsync = freeze_fsync
            if freeze_boundary == "retained-open":
                module.os.open = lambda path, *args, **kwargs: (
                    (_ for _ in ()).throw(OSError("retained-open-cut")) if path == partial.name else
                    real_open(path, *args, **kwargs)
                )
            if freeze_boundary == "writer-close":
                module.os.close = lambda descriptor: (
                    (_ for _ in ()).throw(OSError("writer-close-cut")) if descriptor == writer else
                    real_close(descriptor)
                )
            if freeze_boundary == "journal-append":
                module._append_journal = lambda *_args: (_ for _ in ()).throw(OSError("journal-append-cut"))
            thrown(lambda: module._freeze_partial(asset, directory, writer, partial, 10**30, publication))
            immediate = {fixed_asset.component: "not-required"}
            module._cleanup_failed_asset_publication(
                directory, partial, publication, immediate, fixed_asset.component, 10**30,
            )
            assert immediate[fixed_asset.component] == "preserved" and partial.exists()
            if freeze_boundary.startswith("fsync-"):
                assert fsync_calls[0] == int(freeze_boundary[-1])
        finally:
            (module._asset_generation, module._check_asset_deadline, module._append_journal,
             module.os.fsync, module.os.open, module.os.close) = originals
            if not publication["writer_close_attempted"] or freeze_boundary == "writer-close": os.close(writer)
            os.close(directory)


def publication_cut(target):
    content = b"publication-boundary"
    asset = module.Asset("boundary", "1", "asset.bin", "https://github.com/fixed", len(content),
                         module.hashlib.sha256(content).hexdigest())
    generation = {**fixed_generation, "size": len(content)}
    with tempfile.TemporaryDirectory() as temporary:
        partial, final = Path(temporary, ".asset.partial"), Path(temporary, "asset.bin")
        partial.write_bytes(content)
        directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        writer = os.open(partial.name, os.O_RDWR | os.O_CLOEXEC, dir_fd=directory)
        publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                       "retained": None, "linked": False, "partial_unlinked": False}
        reached = []
        originals = module._asset_generation, module._check_asset_deadline, module._append_journal, module.os.unlink
        real_unlink = module.os.unlink
        try:
            module._asset_generation = lambda *_args: dict(generation)
            def cut(_deadline, stage):
                reached.append(stage)
                if stage == target: raise module.CandidateError("injected-cut")
            module._check_asset_deadline = cut
            module._append_journal = lambda kind, body: reached.append(kind)
            if target == "unlink-after-effect":
                def unlink_after_effect(*args, **kwargs):
                    real_unlink(*args, **kwargs); reached.append(target)
                    raise OSError("unlink-after-effect")
                module.os.unlink = unlink_after_effect
            error = thrown(lambda: module._finish_asset_publication(
                asset, directory, writer, partial, final, {}, 10**30, publication,
            ))
            assert (isinstance(error, OSError) if target == "unlink-after-effect" else
                    isinstance(error, module.CandidateError) and error.code == "injected-cut")
            immediate = {fixed_asset.component: "not-required"}
            if publication["partial_unlinked"]:
                assert failure_code(lambda: module._cleanup_failed_asset_publication(
                    directory, partial, publication, immediate, fixed_asset.component, 10**30,
                )) == "asset-immediate-cleanup-uncertainty"
                assert immediate[fixed_asset.component] == "post-unlink-uncertainty" and not partial.exists()
            else:
                module._cleanup_failed_asset_publication(
                    directory, partial, publication, immediate, fixed_asset.component, 10**30,
                )
                expected = "success" if publication["partial_final"] is not None else "preserved"
                assert immediate[fixed_asset.component] == expected
                assert partial.exists() == (expected == "preserved")
            assert target in reached
        finally:
            (module._asset_generation, module._check_asset_deadline,
             module._append_journal, module.os.unlink) = originals
            if publication["retained"] is not None:
                try: os.close(publication["retained"])
                except OSError: pass
            if not publication["writer_close_attempted"]: os.close(writer)
            os.close(directory)


for preunlink_boundary in ("after-final-eof", "after-content-fsync", "after-retained-open",
                           "after-writer-close", "after-held-name-proof", "after-partial-final-journal"):
    publication_cut(preunlink_boundary)
for postunlink_boundary in ("unlink-after-effect", "after-unlink", "after-directory-fsync",
                            "after-final-redigest", "before-journal", "after-journal", "before-return"):
    publication_cut(postunlink_boundary)

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
    assert failure_code(lambda: module._download_asset(asset, deadline, {asset.component: "not-required"})) == "asset-path"
    assert closed == [40]

    closed = []
    cleanup_calls = []
    module._held_path_absent = lambda _path: True
    module.os.open = lambda *_args, **_kwargs: 41
    module.os.fstat = lambda _descriptor: (_ for _ in ()).throw(OSError("partial-identity"))
    module._cleanup_failed_asset_publication = lambda *_args: cleanup_calls.append("cleanup")
    fstat_immediate = {asset.component: "not-required"}
    expect_oserror(lambda: module._download_asset(asset, deadline, fstat_immediate))
    assert closed == [41, 40] and cleanup_calls == [] and fstat_immediate[asset.component] == "preserved"

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
    assert failure_code(lambda: module._download_asset(asset, deadline, {asset.component: "not-required"})) == "journal-invalid"
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
if sys.platform.startswith("linux"):
    with tempfile.TemporaryDirectory(prefix="cogs-phase-a-linux-replacement-") as temporary:
        partial = Path(temporary) / ("." + fixed_asset.name + ".partial")
        partial.write_bytes(b"owned"); partial.chmod(0o400)
        directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        retained = os.open(partial.name, module.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        generation = module._asset_generation(retained, time.monotonic_ns() + module.NS_PER_SECOND)
        partial.unlink(); partial.write_bytes(b"replacement"); partial.chmod(0o400)
        replacement = os.open(partial.name, module.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        assert module._asset_generation(replacement, time.monotonic_ns() + module.NS_PER_SECOND) != generation
        immediate = {fixed_asset.component: "not-required"}
        rejected(lambda: module._cleanup_failed_asset_publication(directory, partial, {
            "journaled": False, "partial_unlinked": False, "linked": False, "partial_final": generation,
        }, immediate, fixed_asset.component, time.monotonic_ns() + module.NS_PER_SECOND))
        assert partial.read_bytes() == b"replacement" and immediate[fixed_asset.component] == "preserved"
        os.close(replacement); os.close(retained); os.close(directory)
    for replacement_stage in ("after-content-fsync", "after-retained-open"):
        with tempfile.TemporaryDirectory(prefix="cogs-phase-a-linux-freeze-replacement-") as temporary:
            content = b"native-freeze-owned"
            asset = module.Asset("native", "1", "asset.bin", "https://github.com/fixed", len(content),
                                 module.hashlib.sha256(content).hexdigest())
            partial = Path(temporary, ".asset.partial"); partial.write_bytes(content)
            directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            writer = os.open(partial.name, os.O_RDWR | os.O_CLOEXEC, dir_fd=directory)
            publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                           "retained": None, "linked": False, "partial_unlinked": False}
            original_deadline = module._check_asset_deadline
            replaced = [False]
            try:
                def native_replace(_deadline, stage):
                    if stage == replacement_stage and not replaced[0]:
                        partial.unlink(); partial.write_bytes(b"native-replacement"); partial.chmod(0o400)
                        replaced[0] = True
                module._check_asset_deadline = native_replace
                assert failure_code(lambda: module._freeze_partial(
                    asset, directory, writer, partial, time.monotonic_ns() + module.NS_PER_SECOND, publication,
                )) == "asset-partial-replaced"
                assert replaced == [True] and partial.read_bytes() == b"native-replacement"
            finally:
                module._check_asset_deadline = original_deadline
                if not publication["writer_close_attempted"]: os.close(writer)
                os.close(directory)
assert (actual_build.BUILD_SECONDS, actual_build.OUTER_SECONDS) == (900, 2400)
assert (actual_materializer.MATERIALIZE_SECONDS, actual_materializer.CLEANUP_SECONDS) == (900, 600)
assert actual_builder.RECOVER_SECONDS == 600
build_phases = (
    "first-build-work", "first-inline-cleanup", "second-build-work", "second-inline-cleanup",
    "equality", "pin", "post-verification", "settlement",
)
for phase in build_phases:
    assert set(module._counter_read(module._counter_start(actual_build, phase))) == set(module.STRUCTURAL_COUNTERS)
assert set(module._counter_read(module._counter_start(actual_builder, "recovery-attempt-1"))) == \
    set(module.STRUCTURAL_COUNTERS)
for phase in ("recovery-attempt-1", "unknown", True, None):
    rejected(lambda phase=phase: module._counter_start(actual_build, phase))
for phase in (*build_phases, "unknown", True, None):
    rejected(lambda phase=phase: module._counter_start(actual_builder, phase))
build_ticket = module._counter_start(actual_build, "equality")
recovery_ticket = module._counter_start(actual_builder, "recovery-attempt-1")
rejected(lambda: module._counter_read((actual_build._read_phase_structural_counters,
                                       "equality", recovery_ticket[2])))
rejected(lambda: module._counter_read((actual_builder._read_phase_structural_counters,
                                       "recovery-attempt-1", build_ticket[2])))
module._counter_read(build_ticket); module._counter_read(recovery_ticket)
duplicate = module._counter_start(actual_build, "pin")
module._counter_read(duplicate)
rejected(lambda: module._counter_read(duplicate))
replaced = module._counter_start(actual_build, "post-verification")
rejected(lambda: module._counter_read((actual_build._read_phase_structural_counters,
                                       "settlement", replaced[2])))
rejected(lambda: module._counter_read(replaced))
rejected(lambda: module._counter_read((actual_build._read_phase_structural_counters, "equality", 0)))
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
    def failing_close(_chain):
        build_events.append("close")
        raise OSError("raw close")
    actual_build.fs._close_chain = failing_close
    actual_build.materializer._materialize = lambda *_args: (_ for _ in ()).throw(
        actual_materializer.MaterializerWorkError("deadline", "files")
    )
    try:
        actual_build._build_once_unmasked(approval, "1" * 64, outer_control)
    except actual_build.BuildAttemptError as error:
        assert error.work_outcome == "deadline" and error.work_stage == "files"
        assert type(error.__cause__) is actual_build.fs.RootfsFsError
        assert type(error.__cause__.primary) is actual_materializer.MaterializerWorkError
        assert error.args == () and str(error) == ""
    else:
        raise AssertionError("typed materializer failure escaped build boundary")
    assert build_events == ["close"]

    build_events.clear()
    actual_build.fs._close_chain = lambda _chain: build_events.append("close")
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

setup_boundary_originals = (
    actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
    actual_build.builder._open_base_chain, actual_build.builder._begin_operation,
    actual_build.materializer._materialize, actual_build.materializer._materialize_unmasked,
    actual_build.materializer._reload_and_cleanup, actual_build.fs._close_chain,
)
try:
    actual_build._cache_values = lambda _authority: ()
    actual_build.builder._open_base_chain = lambda _control: "chain"
    actual_build.materializer._reload_and_cleanup = lambda *_args: None
    actual_build.fs._close_chain = lambda _chain: None
    for boundary in ("repeated-plan-load", "begin-entry", "begin-return", "materializer-entry"):
        setup = {"value": "operation-establishment"}; setup_events = []
        def repeated_load(boundary=boundary):
            setup_events.append(("plan", setup["value"]))
            if boundary == "repeated-plan-load": raise RuntimeError("repeated-load-cut")
            return authority
        def begin(*_args, boundary=boundary):
            setup_events.append(("begin-entry", setup["value"]))
            if boundary == "begin-entry": raise RuntimeError("begin-cut")
            return owned
        original_materialize_route = setup_boundary_originals[4]
        def materialize_work(*_args):
            setup_events.append(("materializer-work-entry", setup["value"]))
            raise RuntimeError("materializer-cut")
        def materialize_entry(*args, boundary=boundary):
            setup_events.append(("materializer-dispatch-entry", setup["value"]))
            if boundary == "begin-return": raise RuntimeError("after-begin-return-cut")
            return original_materialize_route(*args)
        actual_build.plan.load_verified_build_inputs = repeated_load
        actual_build.builder._begin_operation = begin
        actual_build.materializer._materialize = materialize_entry
        actual_build.materializer._materialize_unmasked = materialize_work
        boundary_phases = module._empty_phases()
        assert failure_code(lambda: module._candidate_build(
            actual_build, approval, outer_control, "first", "3" * 64, boundary_phases, setup,
        )).startswith("rootfs-first-build-")
        assert setup_events[0] == ("plan", "operation-establishment")
        if boundary != "repeated-plan-load":
            assert ("begin-entry", "operation-establishment") in setup_events
        if boundary in {"begin-return", "materializer-entry"}:
            assert ("materializer-dispatch-entry", "materializer-dispatch") in setup_events
            if boundary == "materializer-entry":
                assert ("materializer-work-entry", "complete") in setup_events
                assert setup["value"] == "complete"
            else:
                assert not any(event[0] == "materializer-work-entry" for event in setup_events)
                assert setup["value"] == "materializer-dispatch"
        elif boundary == "begin-entry":
            assert setup["value"] == "operation-establishment"
        if boundary == "materializer-entry":
            assert module._phase(boundary_phases, "first-build-work")["status"] == "failure"
        else:
            assert boundary_phases == module._empty_phases()
finally:
    (actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
     actual_build.builder._open_base_chain, actual_build.builder._begin_operation,
     actual_build.materializer._materialize, actual_build.materializer._materialize_unmasked,
     actual_build.materializer._reload_and_cleanup, actual_build.fs._close_chain) = setup_boundary_originals

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
fake_builder._begin_operation = lambda *_args: "owned-operation"
fake_materializer = types.SimpleNamespace(_reload_and_cleanup=lambda *_args: order.append("reload-cleanup"),
                                          _materialize_unmasked=lambda *_args: candidate)
fake_materializer._materialize = lambda *args: fake_materializer._materialize_unmasked(*args)
fake_build = trusted_counter_provider("completion_rootfs_build")
fake_build.BUILD_SECONDS = 900
fake_build.OUTER_SECONDS = 2400
fake_build.builder = fake_builder
fake_build.materializer = fake_materializer
def fake_build_once(_approval, token, _control):
    order.append(("build", token))
    fake_builder._cleanup_owned(None)
    owned = fake_builder._begin_operation(None)
    return fake_materializer._materialize(None, owned, None)
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
                    module._snapshot_cache, module._snapshot_rootfs_lifecycle, module.secrets.token_hex,
                    module._elapsed_ns)
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
    stages = {name: {"status": "blocked", "elapsed_ms": 0} for name in ("artifact_cache", "runtime_assets")}
    setup = {"value": "not-reached"}
    result = module._rootfs_candidates(
        "a" * 40, "b" * 64, time.monotonic_ns() + 10_000_000_000, phases, stages, setup,
    )
    assert result["equal"] is True and result["pins_match"] is True and result["cache_count"] == 16
    assert stages["artifact_cache"]["status"] == "success" and setup["value"] == "complete"
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
    rejected_stages = {name: {"status": "blocked", "elapsed_ms": 0} for name in ("artifact_cache", "runtime_assets")}
    rejected_setup = {"value": "not-reached"}
    assert failure_code(lambda: module._rootfs_candidates(
        "a" * 40, "b" * 64, time.monotonic_ns() + 10_000_000_000, rejected_phases,
        rejected_stages, rejected_setup,
    )) == "rootfs-build-token"
    assert rejected_phases == module._empty_phases()
    assert rejected_setup["value"] == "operation-establishment"
    assert rejected_stages["artifact_cache"]["status"] == "success"
    assert order == ["open", "bootstrap", "close-state", "close-chain", "snapshot",
                     ("token", repeated), ("token", repeated)]

    cache_setup = {"value": "not-reached"}; cache_events = []
    module._append_journal = lambda kind, _body: cache_events.append(kind)
    def cache_elapsed(_started):
        cache_events.append(("cache-success-timing", cache_setup["value"]))
        raise module.CandidateError("cache-timing-cut")
    module._elapsed_ns = cache_elapsed
    cache_stages = {
        name: {"status": "not-reached", "elapsed_ms": 0}
        for name in ("artifact_cache", "runtime_assets")
    }
    assert failure_code(lambda: module._rootfs_candidates(
        "a" * 40, "b" * 64, time.monotonic_ns() + 10_000_000_000, module._empty_phases(),
        cache_stages, cache_setup,
    )) == "cache-timing-cut"
    assert cache_events[-2:] == ["cache-owned", ("cache-success-timing", "rootfs-bootstrap")]
    assert cache_stages["artifact_cache"] is None
finally:
    (module._load_artifact_verifier, module._append_journal, module._snapshot_cache,
     module._snapshot_rootfs_lifecycle, module.secrets.token_hex, module._elapsed_ns) = original_helpers
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

for fault_at in ("start", "read"):
    faulting_recovery = trusted_counter_provider(
        "completion_rootfs_builder",
        start_error=RuntimeError("start") if fault_at == "start" else None,
        read_error=RuntimeError("read") if fault_at == "read" else None,
    )
    faulting_recovery.RECOVER_SECONDS = 600
    recovery_mutations = []
    faulting_recovery._run_recovery = lambda: recovery_mutations.append("attempt")
    faulting_outcomes = []
    try:
        sys.modules["completion_rootfs_builder"] = faulting_recovery
        assert failure_code(lambda: module._recover_rootfs(faulting_outcomes)) == "rootfs-counter-contract"
    finally:
        if original_recovery_module is None:
            del sys.modules["completion_rootfs_builder"]
        else:
            sys.modules["completion_rootfs_builder"] = original_recovery_module
    assert recovery_mutations == ([] if fault_at == "start" else ["attempt"])
    assert faulting_outcomes == ([] if fault_at == "start" else [{
        "attempt": 1, "outcome": "success", "elapsed_ms": faulting_outcomes[0]["elapsed_ms"],
    }])
    rejected(lambda faulting_outcomes=faulting_outcomes: module._merge_recovery_attempt(
        module._empty_phases(), None, {"recovery_attempts": faulting_outcomes},
    ))

recovery_timing_originals = module.time.monotonic_ns, module._elapsed_ms, module._retry_exact_recovery
try:
    recovery_timing_faults = (
        ("start-clock", lambda: (_ for _ in ()).throw(RuntimeError("recovery-start")),
         RuntimeError, "recovery-start", False),
        ("end-clock", iter((10, RuntimeError("recovery-end"))),
         RuntimeError, "recovery-end", False),
        ("elapsed-bound", iter((10, 10 + 5_400 * module.NS_PER_SECOND + 1)),
         module.CandidateError, "timing-metadata", True),
    )
    for name, clock_script, error_type, detail, read_fault in recovery_timing_faults:
        recovery_provider = trusted_counter_provider(
            "completion_rootfs_builder",
            read_error=RuntimeError("secondary-read") if read_fault else None,
        )
        recovery_provider.RECOVER_SECONDS = 600
        recovery_events = []
        recovery_provider._run_recovery = lambda: recovery_events.append("attempt")
        if callable(clock_script):
            module.time.monotonic_ns = clock_script
        else:
            def recovery_clock(clock_script=clock_script):
                value = next(clock_script)
                if isinstance(value, BaseException):
                    raise value
                return value
            module.time.monotonic_ns = recovery_clock
        outcomes = []
        sys.modules["completion_rootfs_builder"] = recovery_provider
        error = thrown(lambda outcomes=outcomes: module._recover_rootfs(outcomes))
        assert type(error) is error_type
        assert (error.code if type(error) is module.CandidateError else str(error)) == detail
        assert recovery_provider.counter_events == [
            ("start", "recovery-attempt-1"), ("read", "recovery-attempt-1", 1),
        ]
        assert recovery_events == ([] if name == "start-clock" else ["attempt"])
        assert outcomes == []
        rejected(lambda outcomes=outcomes: module._merge_recovery_attempt(
            module._empty_phases(), None, {"recovery_attempts": outcomes},
        ))

    accounting_provider = trusted_counter_provider("completion_rootfs_builder")
    accounting_provider.RECOVER_SECONDS = 600
    accounting_provider._run_recovery = lambda: None
    accounting_clock = iter((10, 20))
    module.time.monotonic_ns = lambda: next(accounting_clock)
    module._elapsed_ms = lambda _elapsed: (_ for _ in ()).throw(module.CandidateError("timing-metadata"))
    accounting_outcomes = []
    sys.modules["completion_rootfs_builder"] = accounting_provider
    assert failure_code(lambda: module._recover_rootfs(accounting_outcomes)) == "timing-metadata"
    assert accounting_provider.counter_events == [
        ("start", "recovery-attempt-1"), ("read", "recovery-attempt-1", 1),
    ]
    assert accounting_outcomes == []

    malformed_provider = trusted_counter_provider(
        "completion_rootfs_builder", read_error=RuntimeError("secondary-read"),
    )
    malformed_provider.RECOVER_SECONDS = 600
    malformed_provider._run_recovery = lambda: None
    module._retry_exact_recovery = lambda _callback, _bound, outcomes: outcomes.append({
        "attempt": True, "outcome": "success", "elapsed_ms": 0,
    })
    malformed_outcomes = []
    sys.modules["completion_rootfs_builder"] = malformed_provider
    assert failure_code(lambda: module._recover_rootfs(malformed_outcomes)) == "rootfs-recovery-contract"
    assert malformed_provider.counter_events == [
        ("start", "recovery-attempt-1"), ("read", "recovery-attempt-1", 1),
    ]
    assert malformed_outcomes == []
finally:
    module.time.monotonic_ns, module._elapsed_ms, module._retry_exact_recovery = recovery_timing_originals
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
    module._cleanup_assets, module._cleanup_artifacts, module._write_json_once, module._owned_immediate,
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
    module._owned_immediate = lambda _records: {item.component: "success" for item in module.RUNTIME_ASSETS}
    module._cleanup_assets = lambda _records, _immediate: (cleanup_calls.append("assets"),
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
        "immediate_cleanup": {item.component: "success" for item in module.RUNTIME_ASSETS},
    }, "cleanup-owned")]
    cleanup_calls.clear(); cleanup_outputs.clear()
    module._owned_immediate = lambda _records: {"kata": "preserved", "containerd": "success"}
    module._cleanup_assets = lambda *_args: cleanup_calls.append("later-assets-success")
    assert failure_code(module._cleanup) == "cleanup-uncertainty"
    assert "later-assets-success" in cleanup_calls
    assert "asset-immediate-cleanup-uncertainty" in cleanup_outputs[0][1]["codes"]
    cleanup_calls.clear(); cleanup_outputs.clear()
    module._owned_immediate = lambda _records: (_ for _ in ()).throw(RuntimeError("missing-owned-observation"))
    assert failure_code(module._cleanup) == "cleanup-uncertainty"
    assert "later-assets-success" not in cleanup_calls
    assert "observation-cleanup-uncertainty" in cleanup_outputs[0][1]["codes"]
finally:
    (module._fixed_preflight, module._require_state, module._recover_rootfs, module._cleanup_rootfs,
     module._cleanup_assets, module._cleanup_artifacts, module._write_json_once,
     module._owned_immediate) = cleanup_originals

observation_phases = module._empty_phases()
observation_input = {
    "status": "failed", "codes": ["rootfs-first-build-deadline"], "revision": "a" * 40,
    "source_manifest_sha256": "b" * 64, "duration_ms": 12, "host_tools": [], "kvm": None,
    "rootfs": None, "rootfs_phases": observation_phases, "assets": [],
    "stage_evidence": {"artifact_cache": {"status": "success", "elapsed_ms": 1},
                       "runtime_assets": {"status": "blocked", "elapsed_ms": 0}},
    "first_build_setup": "rootfs-bootstrap",
    "immediate_cleanup": {item.component: "not-required" for item in module.RUNTIME_ASSETS},
}
valid_cleanup_input = {
    "success": True, "codes": [], "immediate_cleanup": {
        item.component: "not-required" for item in module.RUNTIME_ASSETS
    }, "recovery_attempts": [{
        "attempt": 1, "outcome": "success", "elapsed_ms": 2, "structural_counters": valid_counters,
    }],
}
render_writes = []
render_prevalidated = []
def render_with(observation_value, cleanup_raw, residue_raw):
    originals = (module._fixed_preflight, module._require_state, module._read_regular,
                 module._write_json_once, module._canonical_report)
    written = render_writes
    written.clear(); render_prevalidated.clear()
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
        canonical_report = originals[-1]
        def capture_report(value):
            render_prevalidated.append(json.loads(module._canonical(value)))
            return canonical_report(value)
        module._canonical_report = capture_report
        assert module._render() == 0
        return written[-1]
    finally:
        (module._fixed_preflight, module._require_state, module._read_regular,
         module._write_json_once, module._canonical_report) = originals

# Inject each cut at the dependency called by the real _rootfs_candidates route.
# Every resulting observation must survive rendering and canonical validation.
producer_originals = (
    module._fixed_preflight, module._source_approval, module._verify_fixed_source,
    module._initialize_state, module._host_tools, module._prove_kvm,
    module._load_artifact_verifier, module._snapshot_cache,
    module._snapshot_rootfs_lifecycle, module._append_journal,
    module.secrets.token_hex, module._write_json_once,
    actual_builder._open_base_chain, actual_builder._bootstrap,
    actual_builder._begin_operation, actual_builder._cleanup_owned,
    actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
    actual_materializer._materialize, actual_materializer._materialize_unmasked,
    actual_materializer._reload_and_cleanup,
    actual_build.fs._close_node, actual_build.fs._close_chain,
)
producer_verifier = types.SimpleNamespace(
    CONTRACT_PATH="contract",
    ARTIFACT_ROOT="artifacts",
    verify_contract=lambda _path: {"fixed": True},
    acquire_completion_artifacts=lambda *_args: None,
    verify_package_archives=lambda *_args: None,
)
producer_boundaries = (
    ("rootfs-intent", "rootfs-bootstrap", "rootfs-intent"),
    ("rootfs-open", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-bootstrap", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-close-state", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-close-chain", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-lifecycle-observation", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-lifecycle-ownership", "rootfs-bootstrap", "rootfs-bootstrap"),
    ("rootfs-token-first", "operation-establishment", "rootfs-build-token"),
    ("rootfs-token-second", "operation-establishment", "rootfs-build-token"),
    ("rootfs-token-validation", "operation-establishment", "rootfs-build-token"),
    ("repeated-fixed-input", "operation-establishment", "rootfs-first-build-failed"),
    ("operation-establishment", "operation-establishment", "rootfs-first-build-not-started"),
    ("materializer-dispatch", "materializer-dispatch", "rootfs-first-build-not-started"),
    ("materializer-work", "complete", "rootfs-first-build-not-started"),
)
try:
    module._fixed_preflight = lambda _approval: None
    module._source_approval = lambda: ("a" * 40, "b" * 64)
    module._verify_fixed_source = lambda *_args: None
    module._initialize_state = lambda *_args: None
    module._host_tools = lambda: ([], [])
    module._prove_kvm = lambda: {
        "device_present": False, "device_accessible": False, "api_version": None,
    }
    module._load_artifact_verifier = lambda: producer_verifier
    module._snapshot_cache = lambda _contract: {"cache": "owned"}
    actual_builder._cleanup_owned = lambda *_args: None
    actual_build._cache_values = lambda _authority: ()
    actual_materializer._reload_and_cleanup = lambda *_args: None

    for boundary, expected_setup, expected_code in producer_boundaries:
        events = []
        produced = []

        def cut(name):
            events.append(name)
            raise RuntimeError(name)

        def append_journal(kind, _body):
            events.append(kind)
            if boundary == "rootfs-intent" and kind == "rootfs-intent":
                cut(boundary)
            if boundary == "rootfs-lifecycle-ownership" and kind == "rootfs-lifecycle-owned":
                cut(boundary)

        def open_chain(_control):
            events.append("rootfs-open")
            if boundary == "rootfs-open":
                cut(boundary)
            return "chain"

        def bootstrap(_chain, _approval, _control):
            events.append("rootfs-bootstrap")
            if boundary == "rootfs-bootstrap":
                cut(boundary)
            return "state"

        def close_node(_state):
            events.append("rootfs-close-state")
            if boundary == "rootfs-close-state":
                cut(boundary)

        def close_chain(_chain):
            events.append("rootfs-close-chain")
            if boundary == "rootfs-close-chain":
                cut(boundary)

        def lifecycle_snapshot():
            events.append("rootfs-lifecycle-observation")
            if boundary == "rootfs-lifecycle-observation":
                cut(boundary)
            return rootfs_owned

        issued_tokens = []
        def token_hex(size):
            assert size == 32
            token_number = len(issued_tokens) + 1
            issued_tokens.append(token_number)
            events.append(f"rootfs-token-{token_number}")
            token_boundary = f"rootfs-token-{['first', 'second'][token_number - 1]}"
            if boundary == token_boundary:
                cut(boundary)
            if boundary == "rootfs-token-validation":
                if token_number == 2:
                    events.append(boundary)
                return "1" * 64
            return str(token_number) * 64

        def repeated_load():
            events.append("repeated-fixed-input")
            if boundary == "repeated-fixed-input":
                cut(boundary)
            return authority

        def begin_operation(*_args):
            events.append("operation-establishment")
            if boundary == "operation-establishment":
                cut(boundary)
            return owned

        def materializer_dispatch(*args):
            events.append("materializer-dispatch")
            if boundary == "materializer-dispatch":
                cut(boundary)
            return actual_materializer._materialize_unmasked(*args)

        module._append_journal = append_journal
        module._snapshot_rootfs_lifecycle = lifecycle_snapshot
        module.secrets.token_hex = token_hex
        module._write_json_once = lambda _path, value, _kind: produced.append(value)
        actual_builder._open_base_chain = open_chain
        actual_builder._bootstrap = bootstrap
        actual_builder._begin_operation = begin_operation
        actual_build.plan.load_verified_build_inputs = repeated_load
        actual_materializer._materialize = materializer_dispatch
        actual_materializer._materialize_unmasked = lambda *_args: cut("materializer-work")
        actual_build.fs._close_node = close_node
        actual_build.fs._close_chain = close_chain

        actual_code = failure_code(module._observe)
        assert actual_code == expected_code, (boundary, actual_code, events)
        assert boundary in events
        assert len(produced) == 1
        observed = produced[0]
        assert observed["codes"] == [expected_code]
        assert observed["first_build_setup"] == expected_setup
        if boundary == "materializer-work":
            assert module._phase(observed["rootfs_phases"], "first-build-work")["status"] == "failure"
            assert module._phase(observed["rootfs_phases"], "first-inline-cleanup")["status"] == "success"
        else:
            assert observed["rootfs_phases"] == module._empty_phases()
        assert observed["stage_evidence"]["artifact_cache"]["status"] == "success"
        assert observed["stage_evidence"]["runtime_assets"] == {
            "status": "blocked", "elapsed_ms": 0,
        }
        rendered_prephase = render_with(
            observed, module._canonical(valid_cleanup_input) + b"\n",
            module._canonical({"clean": True, "codes": []}) + b"\n",
        )
        assert rendered_prephase["first_build_setup"] == expected_setup
        assert rendered_prephase["checks"]["runtime_assets"] == "blocked"
        module._canonical_report(rendered_prephase)
        print("producer-boundary-report " + json.dumps({
            "boundary": boundary, "report": rendered_prephase,
        }, sort_keys=True, separators=(",", ":")))
finally:
    (
        module._fixed_preflight, module._source_approval, module._verify_fixed_source,
        module._initialize_state, module._host_tools, module._prove_kvm,
        module._load_artifact_verifier, module._snapshot_cache,
        module._snapshot_rootfs_lifecycle, module._append_journal,
        module.secrets.token_hex, module._write_json_once,
        actual_builder._open_base_chain, actual_builder._bootstrap,
        actual_builder._begin_operation, actual_builder._cleanup_owned,
        actual_build.plan.load_verified_build_inputs, actual_build._cache_values,
        actual_materializer._materialize, actual_materializer._materialize_unmasked,
        actual_materializer._reload_and_cleanup,
        actual_build.fs._close_node, actual_build.fs._close_chain,
    ) = producer_originals

# Runtime publication completion is bound before timing. A timing cut leaves the row
# unavailable, maps only the summary to unknown, and prevents report production.
with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    runtime_observations = []
    runtime_originals = (
        module.ASSETS, module._fixed_preflight, module._source_approval,
        module._verify_fixed_source, module._initialize_state, module._host_tools,
        module._prove_kvm, module._rootfs_candidates, module._append_journal,
        module._held_path_absent, module._fsync_directory, module._identity,
        module._download_asset, module._elapsed_ns, module._write_json_once,
    )
    try:
        module.ASSETS = Path(temporary, "assets")
        module._fixed_preflight = lambda _approval: None
        module._source_approval = lambda: ("a" * 40, "b" * 64)
        module._verify_fixed_source = lambda *_args: None
        module._initialize_state = lambda *_args: None
        module._host_tools = lambda: ([], [])
        module._prove_kvm = lambda: {
            "device_present": False, "device_accessible": False, "api_version": None,
        }
        def settled_for_runtime(_revision, _digest, _deadline, phases, stages, setup):
            stages["artifact_cache"] = {"status": "success", "elapsed_ms": 1}
            setup["value"] = "complete"
            counters = {name: 0 for name in module.STRUCTURAL_COUNTERS}
            for phase_name in module.ROOTFS_PHASES:
                if phase_name != "recovery-attempt-1":
                    module._set_phase(phases, phase_name, "success", "success", 1, counters)
            return successful_rootfs
        module._rootfs_candidates = settled_for_runtime
        module._append_journal = lambda *_args: None
        module._held_path_absent = lambda _path: True
        module._fsync_directory = lambda _path: None
        module._identity = lambda _observed: {
            "dev": 1, "ino": 2, "kind": "directory", "mode": 0o700,
            "uid": 0, "gid": 0, "nlink": 2, "size": 0,
        }
        module._download_asset = lambda asset, _deadline, _immediate: {
            "component": asset.component, "release": asset.release, "name": asset.name,
            "size": asset.size, "sha256": asset.sha256, "downloaded": True, "extracted": False,
        }
        module._elapsed_ns = lambda _started: (_ for _ in ()).throw(
            module.CandidateError("runtime-timing-cut")
        )
        module._write_json_once = lambda _path, value, _kind: runtime_observations.append(value)
        assert failure_code(module._observe) == "runtime-timing-cut"
    finally:
        (module.ASSETS, module._fixed_preflight, module._source_approval,
         module._verify_fixed_source, module._initialize_state, module._host_tools,
         module._prove_kvm, module._rootfs_candidates, module._append_journal,
         module._held_path_absent, module._fsync_directory, module._identity,
         module._download_asset, module._elapsed_ns, module._write_json_once) = runtime_originals
assert len(runtime_observations) == 1
runtime_timing_observation = runtime_observations[0]
assert len(runtime_timing_observation["assets"]) == 2
assert runtime_timing_observation["stage_evidence"]["artifact_cache"]["status"] == "success"
assert runtime_timing_observation["stage_evidence"]["runtime_assets"] is None
for unavailable_observation, unavailable_check in (
    (runtime_timing_observation, "runtime_assets"),
    ({**observation_input, "stage_evidence": {
        "artifact_cache": None,
        "runtime_assets": {"status": "blocked", "elapsed_ms": 0},
    }}, "artifact_cache"),
):
    assert failure_code(lambda unavailable_observation=unavailable_observation: render_with(
        unavailable_observation, module._canonical(valid_cleanup_input) + b"\n",
        module._canonical({"clean": True, "codes": []}) + b"\n",
    )) == "report-schema"
    assert render_writes == [] and len(render_prevalidated) == 1
    assert render_prevalidated[0]["checks"][unavailable_check] == "unknown"

rendered = render_with(
    observation_input, b"{malformed", module._canonical({"clean": True, "codes": []}) + b"\n",
)
assert "cleanup-input-uncertainty" in rendered["diagnostic_codes"]
assert "recovery-phase-input-uncertainty" in rendered["diagnostic_codes"]
assert failure_code(lambda: render_with(
    b"{malformed", module._canonical(valid_cleanup_input) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "report-schema"
assert render_writes == []
rendered = render_with(
    observation_input, None, module._canonical({"clean": True, "codes": []}) + b"\n",
)
assert "cleanup-input-uncertainty" in rendered["diagnostic_codes"]
assert "recovery-phase-input-uncertainty" in rendered["diagnostic_codes"]
rendered = render_with(
    {**observation_input, "rootfs_phases": fault_phases},
    module._canonical(valid_cleanup_input) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)
assert "observation-phase-input-uncertainty" in rendered["diagnostic_codes"]
assert rendered["stage_evidence"] == observation_input["stage_evidence"]
assert rendered["first_build_setup"] == observation_input["first_build_setup"]
rendered = render_with(observation_input, module._canonical(valid_cleanup_input) + b"\n", b"{malformed")
assert module._phase(rendered["rootfs_phases"], "first-build-work")["status"] == "not-reached"
assert module._phase(rendered["rootfs_phases"], "recovery-attempt-1")["status"] == "success"
assert "residue-input-uncertainty" in rendered["diagnostic_codes"]
rendered = render_with(
    {**observation_input, "codes": "malformed"},
    module._canonical({**valid_cleanup_input, "codes": "malformed"}) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)
assert module._phase(rendered["rootfs_phases"], "first-build-work")["status"] == "not-reached"
assert module._phase(rendered["rootfs_phases"], "recovery-attempt-1")["status"] == "success"
assert rendered["stage_evidence"] == observation_input["stage_evidence"]
assert rendered["first_build_setup"] == "rootfs-bootstrap"
assert "observation-codes-input-uncertainty" in rendered["diagnostic_codes"]
assert "cleanup-codes-input-uncertainty" in rendered["diagnostic_codes"]
assert rendered["checks"]["cleanup"] == "pass"
for malformed_field, malformed_value in (("host_tools", [{}]), ("assets", [{"component": "kata"}])):
    rendered = render_with(
        {**observation_input, malformed_field: malformed_value},
        module._canonical(valid_cleanup_input) + b"\n",
        module._canonical({"clean": True, "codes": []}) + b"\n",
    )
    assert rendered["stage_evidence"] == observation_input["stage_evidence"]
    assert rendered["first_build_setup"] == "rootfs-bootstrap"
    assert ("host-tools-input-uncertainty" if malformed_field == "host_tools" else
            "assets-input-uncertainty") in rendered["diagnostic_codes"]

unrelated_malformed = (
    ("duration_ms", True, "duration-input-uncertainty"),
    ("revision", "wrong", "source-input-uncertainty"),
    ("source_manifest_sha256", "wrong", "source-input-uncertainty"),
    ("kvm", {"api_version": 12}, "kvm-input-uncertainty"),
    ("status", [], "observation-status-input-uncertainty"),
    ("codes", {}, "observation-codes-input-uncertainty"),
)
for malformed_field, malformed_value, diagnostic in unrelated_malformed:
    rendered = render_with(
        {**observation_input, malformed_field: malformed_value},
        module._canonical(valid_cleanup_input) + b"\n",
        module._canonical({"clean": True, "codes": []}) + b"\n",
    )
    assert module._phase(rendered["rootfs_phases"], "first-build-work")["status"] == "not-reached"
    assert module._phase(rendered["rootfs_phases"], "recovery-attempt-1")["status"] == "success"
    assert rendered["stage_evidence"] == observation_input["stage_evidence"]
    assert rendered["first_build_setup"] == observation_input["first_build_setup"]
    assert rendered["checks"]["cleanup"] == rendered["checks"]["residue"] == "pass"
    assert diagnostic in rendered["diagnostic_codes"]

for bad_stage in ("artifact_cache", "runtime_assets"):
    hostile_stages = {name: dict(row) for name, row in observation_input["stage_evidence"].items()}
    hostile_stages[bad_stage] = {"status": "malformed", "elapsed_ms": 0}
    assert failure_code(lambda hostile_stages=hostile_stages: render_with(
        {**observation_input, "stage_evidence": hostile_stages},
        module._canonical(valid_cleanup_input) + b"\n",
        module._canonical({"clean": True, "codes": []}) + b"\n",
    )) == "report-schema"
    assert render_writes == []
assert failure_code(lambda: render_with(
    {**observation_input, "first_build_setup": "malformed"},
    module._canonical(valid_cleanup_input) + b"\n",
    module._canonical({"clean": True, "codes": []}) + b"\n",
)) == "report-schema"
assert render_writes == []

# Start from one canonical render and isolate every bounded rendering surface.
matrix_phases = module._empty_phases()
matrix_counters = {name: 0 for name in module.STRUCTURAL_COUNTERS}
for phase_name in module.ROOTFS_PHASES:
    if phase_name != "recovery-attempt-1":
        module._set_phase(matrix_phases, phase_name, "success", "success", 1, matrix_counters)
matrix_input = {
    **observation_input, "codes": [], "duration_ms": 0, "rootfs": successful_rootfs,
    "rootfs_phases": matrix_phases, "first_build_setup": "complete",
    "stage_evidence": {"artifact_cache": {"status": "success", "elapsed_ms": 1},
                       "runtime_assets": {"status": "failure", "elapsed_ms": 1}},
    "kvm": {"device_present": True, "device_accessible": True, "api_version": 12},
}
cleanup_raw = module._canonical(valid_cleanup_input) + b"\n"
residue_raw = module._canonical({"clean": True, "codes": []}) + b"\n"
baseline_render = render_with(matrix_input, cleanup_raw, residue_raw)
baseline_bytes = module._canonical(baseline_render)
assert baseline_render["diagnostic_codes"] == [] and module._canonical_report(baseline_render)
assert set(baseline_render["checks"]) == set(module._base_report()["checks"])

def report_path(value, path):
    current = value
    for component in path[:-1]: current = current[component]
    return current, path[-1]

def assert_render_isolated(observed, diagnostic, changed_paths=()):
    candidate = json.loads(module._canonical(observed))
    assert candidate["diagnostic_codes"] == ([diagnostic] if diagnostic else []), candidate["diagnostic_codes"]
    candidate["diagnostic_codes"] = []
    for path in changed_paths:
        target, key = report_path(candidate, path)
        baseline_target, baseline_key = report_path(baseline_render, path)
        target[key] = baseline_target[baseline_key]
    assert module._canonical(candidate) == baseline_bytes

phase_bad_values = {
    "phase": "malformed", "status": "malformed", "outcome": "malformed",
    "elapsed_ms": True, "structural_counters": {},
}
for index, row in enumerate(matrix_input["rootfs_phases"]):
    for field, bad_value in phase_bad_values.items():
        hostile_rows = [dict(item) for item in matrix_input["rootfs_phases"]]
        hostile_rows[index] = {**row, field: bad_value}
        assert failure_code(lambda hostile_rows=hostile_rows: render_with(
            {**matrix_input, "rootfs_phases": hostile_rows}, cleanup_raw, residue_raw,
        )) == "report-schema"
        assert render_writes == [] and len(render_prevalidated) == 1
        assert_render_isolated(render_prevalidated[0], "observation-phase-input-uncertainty", (
            ("rootfs",), ("rootfs_phases",), ("checks", "rootfs_candidates"),
        ))

for field in successful_rootfs:
    hostile_rootfs = {**successful_rootfs, field: None}
    assert failure_code(lambda hostile_rootfs=hostile_rootfs: render_with(
        {**matrix_input, "rootfs": hostile_rootfs}, cleanup_raw, residue_raw,
    )) == "report-schema"
    assert render_writes == [] and len(render_prevalidated) == 1
    assert_render_isolated(render_prevalidated[0], None, (
        ("rootfs",), ("checks", "rootfs_candidates"),
    ))
assert failure_code(lambda: render_with(
    {**matrix_input, "rootfs": None}, cleanup_raw, residue_raw,
)) == "report-schema"
assert render_writes == [] and len(render_prevalidated) == 1
assert_render_isolated(render_prevalidated[0], "observation-phase-input-uncertainty", (
    ("rootfs",), ("rootfs_phases",), ("checks", "rootfs_candidates"),
))

valid_tool = {"name": "ctr", "path": "/usr/bin/ctr", "present": True, "size": 1,
              "sha256": "c" * 64, "version": "fixed"}
for field, bad_value in (("name", "wrong"), ("path", "/wrong"), ("present", "yes"),
                         ("size", -1), ("sha256", "wrong"), ("version", "")):
    observed = render_with({**matrix_input, "host_tools": [{**valid_tool, field: bad_value}]},
                           cleanup_raw, residue_raw)
    assert_render_isolated(observed, "host-tools-input-uncertainty")

asset = module.RUNTIME_ASSETS[0]
valid_asset = {"component": asset.component, "release": asset.release, "name": asset.name,
               "size": asset.size, "sha256": asset.sha256, "downloaded": True, "extracted": False}
for field, bad_value in (("component", "wrong"), ("release", "wrong"), ("name", "wrong"),
                         ("size", True), ("sha256", "wrong"), ("downloaded", False),
                         ("extracted", True)):
    observed = render_with({**matrix_input, "assets": [{**valid_asset, field: bad_value}]},
                           cleanup_raw, residue_raw)
    assert_render_isolated(observed, "assets-input-uncertainty")

for field, bad_value in (("device_present", "yes"), ("device_accessible", "yes"),
                         ("api_version", 13)):
    observed = render_with({**matrix_input, "kvm": {**matrix_input["kvm"], field: bad_value}},
                           cleanup_raw, residue_raw)
    assert_render_isolated(observed, "kvm-input-uncertainty", (
        ("kvm",), ("checks", "kvm"),
    ))

for field, diagnostic in (("duration_ms", "duration-input-uncertainty"),
                          ("status", "observation-status-input-uncertainty"),
                          ("codes", "observation-codes-input-uncertainty")):
    observed = render_with({**matrix_input, field: True}, cleanup_raw, residue_raw)
    assert_render_isolated(observed, diagnostic)
for field in ("revision", "source_manifest_sha256"):
    observed = render_with({**matrix_input, field: "wrong"}, cleanup_raw, residue_raw)
    assert_render_isolated(observed, "source-input-uncertainty", (
        ("source_revision",), ("source_manifest_sha256",),
        ("checks", "platform"), ("checks", "root"), ("checks", "source"),
    ))

for stage_name in ("artifact_cache", "runtime_assets"):
    for field, bad_value in (("status", "malformed"), ("elapsed_ms", True)):
        hostile_stages = {name: dict(row) for name, row in matrix_input["stage_evidence"].items()}
        hostile_stages[stage_name] = {**hostile_stages[stage_name], field: bad_value}
        assert failure_code(lambda hostile_stages=hostile_stages: render_with(
            {**matrix_input, "stage_evidence": hostile_stages}, cleanup_raw, residue_raw,
        )) == "report-schema"
        assert render_writes == [] and len(render_prevalidated) == 1
        assert_render_isolated(render_prevalidated[0], stage_name.replace("_", "-") +
                               "-stage-input-uncertainty", (
            ("stage_evidence", stage_name), ("checks", stage_name),
        ))

assert failure_code(lambda: render_with(
    {**matrix_input, "first_build_setup": "malformed"}, cleanup_raw, residue_raw,
)) == "report-schema"
assert render_writes == [] and len(render_prevalidated) == 1
assert_render_isolated(render_prevalidated[0], "setup-input-uncertainty", (("first_build_setup",),))

for field, bad_value, diagnostic, changed in (
    ("success", "yes", "cleanup-summary-input-uncertainty", (("checks", "cleanup"), ("blockers",))),
    ("codes", "bad", "cleanup-codes-input-uncertainty", ()),
    ("immediate_cleanup", {}, "immediate-cleanup-input-uncertainty", ()),
):
    hostile_cleanup = {**valid_cleanup_input, field: bad_value}
    observed = render_with(matrix_input, module._canonical(hostile_cleanup) + b"\n", residue_raw)
    assert_render_isolated(observed, diagnostic, changed)
cleanup_code_survives = render_with(matrix_input, module._canonical({
    **valid_cleanup_input, "success": "yes", "codes": ["fixed-cleanup-code"],
}) + b"\n", residue_raw)
assert set(cleanup_code_survives["diagnostic_codes"]) == {
    "cleanup-summary-input-uncertainty", "fixed-cleanup-code",
}
for field, bad_value in (("attempt", 2), ("outcome", "bad"), ("elapsed_ms", True),
                         ("structural_counters", {})):
    attempt = {**valid_cleanup_input["recovery_attempts"][0], field: bad_value}
    hostile_cleanup = {**valid_cleanup_input, "recovery_attempts": [attempt]}
    observed = render_with(matrix_input, module._canonical(hostile_cleanup) + b"\n", residue_raw)
    assert_render_isolated(observed, "recovery-phase-input-uncertainty", (("rootfs_phases",),))

for field, bad_value, diagnostic, changed in (
    ("clean", "yes", "residue-summary-input-uncertainty", (("checks", "residue"), ("blockers",))),
    ("codes", "bad", "residue-codes-input-uncertainty", ()),
):
    hostile_residue = {"clean": True, "codes": []}
    hostile_residue[field] = bad_value
    observed = render_with(matrix_input, cleanup_raw, module._canonical(hostile_residue) + b"\n")
    assert_render_isolated(observed, diagnostic, changed)

residue_code_survives = render_with(
    matrix_input, cleanup_raw, module._canonical({"clean": "yes", "codes": ["fixed-residue-code"]}) + b"\n",
)
assert set(residue_code_survives["diagnostic_codes"]) == {
    "residue-summary-input-uncertainty", "fixed-residue-code",
}

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

immediate_originals = module._read_regular, module.os.stat
try:
    valid_immediate = {item.component: "success" for item in module.RUNTIME_ASSETS}
    observation_raw = module._canonical({"immediate_cleanup": valid_immediate}) + b"\n"
    observation_record = [{"kind": "observation-owned", "body": {
        "name": module.OBSERVATION.name, "identity": module._identity(Node()),
        "sha256": module.hashlib.sha256(observation_raw).hexdigest()}}]
    module._read_regular = lambda *_args: observation_raw
    module.os.stat = lambda *_args, **_kwargs: Node()
    assert module._owned_immediate(observation_record) == valid_immediate
    module._read_regular = lambda *_args: module._canonical({"immediate_cleanup": {"kata": "success"}}) + b"\n"
    rejected(lambda: module._owned_immediate(observation_record))
    rejected(lambda: module._owned_immediate([]))
finally:
    module._read_regular, module.os.stat = immediate_originals

for observation_boundary in ("write", "file-fsync-1", "file-fsync-2", "file-close", "directory-fsync", "journal"):
    with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
        observation_path = Path(temporary, "observation.json")
        publication = {"journaled": False, "partial_unlinked": True, "linked": True,
                       "partial_final": fixed_generation}
        immediate = {fixed_asset.component: "not-required"}
        assert failure_code(lambda: module._cleanup_failed_asset_publication(
            -1, Path(".already-unlinked"), publication, immediate, fixed_asset.component, 10**30,
        )) == "asset-immediate-cleanup-uncertainty"
        assert immediate[fixed_asset.component] == "post-unlink-uncertainty"
        originals = (module.OBSERVATION, module._write_all, module.os.fsync, module.os.close,
                     module._fsync_directory, module._append_journal)
        real_write, real_fsync, real_close = module._write_all, module.os.fsync, module.os.close
        try:
            module.OBSERVATION = observation_path
            if observation_boundary == "write":
                module._write_all = lambda *_args: (_ for _ in ()).throw(OSError("write-cut"))
            file_fsync_calls = [0]
            if observation_boundary.startswith("file-fsync-"):
                target_call = int(observation_boundary[-1])
                def observation_fsync(descriptor):
                    file_fsync_calls[0] += 1
                    if file_fsync_calls[0] == target_call: raise OSError("fsync-cut")
                    return real_fsync(descriptor)
                module.os.fsync = observation_fsync
            if observation_boundary == "file-close":
                closed_once = [False]
                def close_cut(descriptor):
                    if not closed_once[0]:
                        closed_once[0] = True
                        real_close(descriptor)
                        raise OSError("close-cut")
                    return real_close(descriptor)
                module.os.close = close_cut
            if observation_boundary == "directory-fsync":
                module._fsync_directory = lambda *_args: (_ for _ in ()).throw(OSError("directory-fsync-cut"))
            if observation_boundary == "journal":
                module._append_journal = lambda *_args: (_ for _ in ()).throw(OSError("journal-cut"))
            error = thrown(lambda: module._write_json_once(
                observation_path, {"immediate_cleanup": immediate}, "observation-owned",
            ))
            assert isinstance(error, OSError)
            if observation_boundary.startswith("file-fsync-"):
                assert file_fsync_calls[0] == int(observation_boundary[-1])
            rejected(lambda: module._owned_immediate([]))
        finally:
            (module.OBSERVATION, module._write_all, module.os.fsync, module.os.close,
             module._fsync_directory, module._append_journal) = originals

with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    observation_path = Path(temporary, "observation.json")
    immediate = {item.component: "success" for item in module.RUNTIME_ASSETS}
    records = []
    originals = module.OBSERVATION, module._append_journal
    try:
        module.OBSERVATION = observation_path
        module._append_journal = lambda kind, body: records.append({"kind": kind, "body": body})
        module._write_json_once(observation_path, {"immediate_cleanup": immediate}, "observation-owned")
        assert module._owned_immediate(records) == immediate
        observation_path.chmod(0o600); observation_path.write_bytes(b'{"immediate_cleanup":{}}\n')
        observation_path.chmod(0o400)
        rejected(lambda: module._owned_immediate(records))
    finally:
        module.OBSERVATION, module._append_journal = originals

# One production route carries a real publication unlink through observe's finally,
# durable observation ownership, exact append readback, and later owned readback.
with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    root = Path(temporary); state = root / "state"; state.mkdir(mode=0o700)
    journal_path = state / "ownership.jsonl"; journal_path.touch(mode=0o600)
    state_identity = module._identity(state.stat())
    journal_identity = module._identity(journal_path.stat())
    seed = module._journal_record(0, "0" * 64, "genesis", {
        "state": state_identity, "journal": journal_identity,
    })
    journal_path.write_bytes(module._canonical(seed) + b"\n")
    observation_path = state / "observation.json"
    assets_path = state / "assets"
    readbacks = []
    originals = (
        module.STATE, module.JOURNAL, module.OBSERVATION, module.ASSETS,
        module._fixed_preflight, module._source_approval, module._verify_fixed_source,
        module._initialize_state, module._host_tools, module._prove_kvm,
        module._rootfs_candidates, module._download_asset, module._check_asset_deadline,
        module._asset_generation, module._read_journal_unanchored, module._open_dir,
        module.os.stat,
    )
    real_stat = module.os.stat
    try:
        module.STATE, module.JOURNAL = state, journal_path
        module.OBSERVATION, module.ASSETS = observation_path, assets_path
        module._fixed_preflight = lambda _approval: None
        module._source_approval = lambda: ("a" * 40, "b" * 64)
        module._verify_fixed_source = lambda *_args: None
        module._initialize_state = lambda *_args: None
        module._host_tools = lambda: ([], [])
        module._prove_kvm = lambda: {"device_present": False, "device_accessible": False, "api_version": None}
        def settled_rootfs(_revision, _digest, _deadline, phases, stages, setup):
            stages["artifact_cache"] = {"status": "success", "elapsed_ms": 1}
            setup["value"] = "complete"
            counters = {name: 0 for name in module.STRUCTURAL_COUNTERS}
            for name in module.ROOTFS_PHASES:
                if name != "recovery-attempt-1":
                    module._set_phase(phases, name, "success", "success", 1, counters)
            return successful_rootfs
        module._rootfs_candidates = settled_rootfs
        module._check_asset_deadline = lambda _deadline, stage: (
            (_ for _ in ()).throw(module.CandidateError("after-unlink-cut")) if stage == "after-unlink" else None
        )
        module._asset_generation = lambda descriptor, _deadline: {
            **fixed_generation, "size": os.fstat(descriptor).st_size,
        }
        def read_journal():
            records = module._parse_journal(journal_path.read_bytes())
            readbacks.append(records[-1]["kind"])
            return records
        module._read_journal_unanchored = read_journal
        module._open_dir = lambda path: os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        def owned_stat(path, *args, **kwargs):
            observed = real_stat(path, *args, **kwargs)
            if Path(path) == assets_path:
                class RootOwned:
                    pass
                copied = RootOwned()
                for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"):
                    setattr(copied, name, getattr(observed, name))
                copied.st_uid = copied.st_gid = 0
                return copied
            return observed
        module.os.stat = owned_stat
        def unlinking_download(asset, deadline, immediate):
            partial, final = assets_path / ("." + asset.name + ".partial"), assets_path / asset.name
            content = b"observe-publication-route"
            partial.write_bytes(content)
            directory = os.open(assets_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            writer = os.open(partial.name, os.O_RDWR | os.O_CLOEXEC, dir_fd=directory)
            publication = {"journaled": False, "writer_close_attempted": False, "partial_final": None,
                           "retained": None, "linked": False, "partial_unlinked": False}
            routed = module.Asset(asset.component, asset.release, asset.name, asset.url, len(content),
                                  module.hashlib.sha256(content).hexdigest())
            try:
                return module._finish_asset_publication(
                    routed, directory, writer, partial, final, {}, deadline, publication,
                )
            finally:
                try:
                    module._cleanup_failed_asset_publication(
                        directory, partial, publication, immediate, asset.component, deadline,
                    )
                finally:
                    if publication["retained"] is not None: os.close(publication["retained"])
                    if not publication["writer_close_attempted"]: os.close(writer)
                    os.close(directory)
        module._download_asset = unlinking_download
        assert failure_code(module._observe) == "asset-immediate-cleanup-uncertainty"
        assert not (assets_path / ("." + module.RUNTIME_ASSETS[0].name + ".partial")).exists()
        records = module._parse_journal(journal_path.read_bytes())
        assert records[-1]["kind"] == "observation-owned" and readbacks[-1] == "observation-owned"
        owned = module._owned_immediate(records)
        assert owned["kata"] == "post-unlink-uncertainty" and owned["containerd"] == "not-required"
    finally:
        (module.STATE, module.JOURNAL, module.OBSERVATION, module.ASSETS,
         module._fixed_preflight, module._source_approval, module._verify_fixed_source,
         module._initialize_state, module._host_tools, module._prove_kvm,
         module._rootfs_candidates, module._download_asset, module._check_asset_deadline,
         module._asset_generation, module._read_journal_unanchored, module._open_dir,
         module.os.stat) = originals

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

journal_boundary_originals = (
    module.STATE, module.JOURNAL, module._read_journal_unanchored, module._open_dir,
    module._write_all, module.os.fsync,
)
real_write_all, real_fsync = module._write_all, module.os.fsync
try:
    for journal_boundary in ("append", "fsync", "readback"):
        for generation_field in module.FULL_GENERATION:
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary); journal_path = state / "journal"
                journal_path.touch(mode=0o600)
                seed = module._journal_record(0, "0" * 64, "genesis", {
                    "journal": module._identity(journal_path.stat(follow_symlinks=False)),
                })
                journal_path.write_bytes(module._canonical(seed) + b"\n")
                body = {"component": fixed_asset.component, "name": ".fixed.partial",
                        "generation": fixed_generation}
                expected = module._journal_record(1, seed["sha256"], "asset-partial-final-owned", body)
                reads = [0]; events = []
                def drift_record(record):
                    drifted_body = {**record["body"], "generation": drift_generation(
                        record["body"]["generation"], generation_field,
                    )}
                    return module._journal_record(
                        record["sequence"], record["previous"], record["kind"], drifted_body,
                    )
                def drift_persisted(transition):
                    records = module._parse_journal(journal_path.read_bytes())
                    records[-1] = drift_record(records[-1])
                    journal_path.write_bytes(b"".join(module._canonical(item) + b"\n" for item in records))
                    events.append(("persisted-field-drift", transition, generation_field))
                def journal_read():
                    reads[0] += 1
                    if journal_boundary == "readback" and reads[0] == 2:
                        drift_persisted("readback")
                    return module._parse_journal(journal_path.read_bytes())
                module.STATE, module.JOURNAL = state, journal_path
                module._read_journal_unanchored = journal_read
                module._open_dir = lambda _path: os.open(
                    state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                def journal_write(descriptor, raw):
                    events.append("append")
                    if journal_boundary == "append":
                        raw = module._canonical(drift_record(module._strict_json(raw))) + b"\n"
                        events.append(("persisted-field-drift", "append", generation_field))
                    real_write_all(descriptor, raw)
                module._write_all = journal_write
                def journal_fsync(descriptor):
                    events.append("fsync")
                    if journal_boundary == "fsync": drift_persisted("fsync")
                    real_fsync(descriptor)
                module.os.fsync = journal_fsync
                assert failure_code(lambda: module._append_journal(
                    "asset-partial-final-owned", body,
                )) == "journal-invalid"
                persisted = module._parse_journal(journal_path.read_bytes())[-1]
                assert persisted != expected
                assert persisted["body"]["generation"] == drift_generation(
                    fixed_generation, generation_field,
                )
                assert events[0] == "append" and "fsync" in events
                assert ("persisted-field-drift", journal_boundary, generation_field) in events
                assert reads[0] == 2
finally:
    (module.STATE, module.JOURNAL, module._read_journal_unanchored, module._open_dir,
     module._write_all, module.os.fsync) = journal_boundary_originals

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
    partial.write_bytes(b"replacement")
    directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    immediate = {"kata": "not-required"}
    publication = {"journaled": False, "partial_unlinked": False, "linked": False,
                   "partial_final": fixed_generation}
    original_generation = module._asset_generation
    try:
        module._asset_generation = lambda *_args: {**fixed_generation, "ino": fixed_generation["ino"] + 1}
        rejected(lambda: module._cleanup_failed_asset_publication(
            directory, partial, publication, immediate, "kata", 10**30,
        ))
        assert immediate["kata"] == "preserved" and partial.read_bytes() == b"replacement"
    finally:
        module._asset_generation = original_generation
        os.close(directory)

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-assets-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    assets = Path(temporary, "assets")
    assets.mkdir(mode=0o700)
    directory_identity = module._identity(assets.stat(follow_symlinks=False))
    body = b"asset-bytes"
    final = assets / fixed_asset.name
    final.write_bytes(body)
    final.chmod(0o400)
    file_identity = module._identity(final.stat(follow_symlinks=False))
    assert module._same_directory_authority(
        assets.stat(follow_symlinks=False), directory_identity,
    )
    records = [
        {"kind": "asset-directory-owned", "body": {"identity": directory_identity}},
        *partial_records(),
        {"kind": "asset-final-owned", "body": {"component": fixed_asset.component,
            "name": final.name, "identity": file_identity, "sha256": module.hashlib.sha256(body).hexdigest()}},
    ]
    original_assets, original_open_dir = module.ASSETS, module._open_dir
    try:
        module.ASSETS = assets
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        assert module._cleanup_assets.__globals__["ASSETS"] == assets
        module._cleanup_assets(records, {item.component: "not-required" for item in module.RUNTIME_ASSETS})
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
        rejected(lambda: module._cleanup_assets(records, {item.component: "preserved" for item in module.RUNTIME_ASSETS}))
        assert opened_incomplete == []
        assert partial.read_bytes() == b"replacement"
    finally:
        module.ASSETS, module._open_dir, module.os.open, module.os.close = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-absent-final-record-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    original_assets = module.ASSETS
    try:
        module.ASSETS = Path(temporary, "absent-assets")
        rejected(lambda: module._cleanup_assets(
            partial_records(), {item.component: "preserved" for item in module.RUNTIME_ASSETS},
        ))
        module._cleanup_assets(
            partial_records(), {item.component: "success" for item in module.RUNTIME_ASSETS},
        )
    finally:
        module.ASSETS = original_assets

for absent_partial_outcome in ("not-required", "preserved", "success"):
    with tempfile.TemporaryDirectory(prefix="cogs-phase-a-present-assets-absent-partial-",
                                     dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
        assets = Path(temporary, "assets"); assets.mkdir(mode=0o700)
        records = [{"kind": "asset-directory-owned", "body": {
            "identity": module._identity(assets.stat(follow_symlinks=False))}}, *partial_records()]
        originals = module.ASSETS, module._open_dir
        try:
            module.ASSETS = assets
            module._open_dir = lambda path: os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            immediate = {item.component: "not-required" for item in module.RUNTIME_ASSETS}
            immediate[fixed_asset.component] = absent_partial_outcome
            if absent_partial_outcome == "success":
                module._cleanup_assets(records, immediate)
                assert not assets.exists()
            else:
                rejected(lambda: module._cleanup_assets(records, immediate))
                assert assets.is_dir()
        finally:
            module.ASSETS, module._open_dir = originals

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-nlink2-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    assets = Path(temporary, "assets")
    assets.mkdir(mode=0o700)
    partial = assets / ("." + fixed_asset.name + ".partial")
    final = assets / fixed_asset.name
    partial.write_bytes(b"linked-preserve")
    os.link(partial, final)
    records = [{"kind": "asset-directory-owned", "body": {
        "identity": module._identity(assets.stat(follow_symlinks=False))}}, *partial_records()]
    originals = module.ASSETS, module._open_dir
    try:
        module.ASSETS = assets
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        rejected(lambda: module._cleanup_assets(
            records, {item.component: "preserved" for item in module.RUNTIME_ASSETS},
        ))
        assert partial.stat().st_nlink == final.stat().st_nlink == 2
    finally:
        module.ASSETS, module._open_dir = originals

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

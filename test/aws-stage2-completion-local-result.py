#!/usr/bin/env python3
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_local_full.py"
BUDGET_PATH = ROOT / "scripts/check-stage2-retained-lines.py"
FIXTURES = ROOT / "test/fixtures/stage2-completion"
spec = importlib.util.spec_from_file_location("completion_local_full", MODULE_PATH)
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def rejected(call, message):
    try:
        call()
    except local.LocalResultError:
        return
    raise RuntimeError(message)


def digest_view(bindings, operation, journal):
    value = dict(bindings)
    value.update(operation_sha256=operation, journal_sha256=journal)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def summary(rows):
    values = [row["duration_ns"] for row in rows if row["duration_ns"] is not None]
    return {"count": len(values), "total_ns": sum(values),
            "minimum_ns": min(values) if values else None,
            "maximum_ns": max(values) if values else None}


def refresh(value):
    value["timing_summaries"] = {name: summary(rows) for name, rows in value["timings"].items()}
    return value


def not_reached(binding):
    return [{"ordinal": index, "duration_ns": None, "outcome": "not-reached",
             "deletion": "not-reached", "binding_sha256": binding}
            for index in range(1, 8)]


def stop_after(rows, index, binding):
    rows[index + 1:] = not_reached(binding)[index + 1:]


def passing():
    bindings = {
        "source_head": "a" * 40, "source_manifest_sha256": "1" * 64,
        "host_attestation_sha256": "2" * 64, "runtime_attestation_sha256": "3" * 64,
        "rootfs_sha256": "4" * 64, "artifact_sha256": "5" * 64,
        "candidate_sha256": "6" * 64, "final_pin_sha256": "7" * 64,
        "guest_program_sha256": "8" * 64, "owner_implementation_sha256": "9" * 64,
    }
    operation, journal = "b" * 64, "c" * 64
    binding = digest_view(bindings, operation, journal)
    timings = {name: [
        {"ordinal": index, "duration_ns": offset * 100 + index, "outcome": "pass",
         "deletion": "absent", "binding_sha256": binding}
        for index in range(1, 8)]
        for offset, name in enumerate(("git", "build", "install"), 1)}
    return refresh({
        "version": local.VERSION, "result": "pass", "failure_code": None, "qualified": True,
        "authority": local.AUTHORITY, "validation_classification": local.VALIDATION_CLASSIFICATION,
        "limitations": list(local.LIMITATIONS), "bindings": bindings,
        "admission": {name: "pass" for name in local.ADMISSION_PHASES},
        "platform": {"observation": "pass", "kvm_api": 12,
                     "qmp_present": True, "qmp_enabled": True},
        "lifecycle": {"attempts": 1, "outcome": "pass", "ssh_attempts": 1, "ssh_outcome": "pass"},
        "operation": {
            "operation_sha256": operation, "journal_sha256": journal, "binding_sha256": binding,
            "source_head": bindings["source_head"],
            "source_manifest_sha256": bindings["source_manifest_sha256"],
            "final_pin_sha256": bindings["final_pin_sha256"], "status": "retired"},
        "timings": timings,
        "teardown": [{"phase": phase, "outcome": "pass", "binding_sha256": binding}
                     for phase in local.TEARDOWN_PHASES],
        "zero_residue": {name: "absent" for name in local.RESIDUE_FACTS},
    })


def failing(code="preflight"):
    value = passing()
    value.update(result="failure", failure_code=code, qualified=False)
    position = local.ADMISSION_CODES.index(code)
    value["admission"] = {name: ("pass" if index < position else "failure" if index == position else "not-reached")
                          for index, name in enumerate(local.ADMISSION_PHASES)}
    value["platform"] = {
        "observation": "failure" if code == "kvm" else "not-reached",
        "kvm_api": None, "qmp_present": False, "qmp_enabled": False,
    }
    value["lifecycle"] = {"attempts": 0, "outcome": "not-reached", "ssh_attempts": 0,
                          "ssh_outcome": "not-reached"}
    value["operation"].update(operation_sha256=None, journal_sha256=None, binding_sha256=None,
                              status="not-created")
    value["timings"] = {name: not_reached(None) for name in ("git", "build", "install")}
    value["teardown"] = [{"phase": phase, "outcome": "not-reached", "binding_sha256": None}
                         for phase in local.TEARDOWN_PHASES]
    return refresh(value)


def categorical_failure(code):
    value = passing()
    value.update(result="failure", failure_code=code, qualified=False)
    binding = value["operation"]["binding_sha256"]
    if code == "lifecycle-start":
        value["lifecycle"] = {"attempts": 1, "outcome": "failure", "ssh_attempts": 0,
                              "ssh_outcome": "not-reached"}
        value["timings"] = {name: not_reached(binding) for name in value["timings"]}
    elif code == "ssh":
        value["lifecycle"].update(ssh_outcome="failure")
        value["timings"] = {name: not_reached(binding) for name in value["timings"]}
    elif code == "git-sample":
        value["timings"]["git"][0]["outcome"] = "failure"
        stop_after(value["timings"]["git"], 0, binding)
        value["timings"]["build"] = not_reached(binding)
        value["timings"]["install"] = not_reached(binding)
    elif code == "build-sample":
        value["timings"]["build"][0]["outcome"] = "failure"
        stop_after(value["timings"]["build"], 0, binding)
        value["timings"]["install"] = not_reached(binding)
    elif code == "install-sample":
        value["timings"]["install"][0]["outcome"] = "failure"
        stop_after(value["timings"]["install"], 0, binding)
    elif code == "deletion":
        value["timings"]["git"][0]["deletion"] = "not-proved"
        stop_after(value["timings"]["git"], 0, binding)
        value["timings"]["build"] = not_reached(binding)
        value["timings"]["install"] = not_reached(binding)
    elif code in ("cleanup", "residue"):
        value["operation"]["status"] = "uncertain"
        index = 0 if code == "cleanup" else local.TEARDOWN_PHASES.index("FINAL_BASELINES")
        value["teardown"][index]["outcome"] = "failure"
        value["teardown"][-1]["outcome"] = "not-reached"
        value["zero_residue"]["qemu_processes"] = "not-proved"
    elif code == "uncertain":
        value["operation"]["status"] = "uncertain"
        value["lifecycle"] = {"attempts": 0, "outcome": "not-reached", "ssh_attempts": 0,
                              "ssh_outcome": "not-reached"}
        value["timings"] = {name: not_reached(binding) for name in value["timings"]}
        value["teardown"][0]["outcome"] = "failure"
        value["teardown"][-1]["outcome"] = "not-reached"
        value["zero_residue"]["operation_state"] = "not-proved"
    return refresh(value)


def ordinal_failure(group, ordinal, deletion=False):
    value = passing()
    value.update(result="failure", qualified=False,
                 failure_code="deletion" if deletion else f"{group}-sample")
    binding = value["operation"]["binding_sha256"]
    row = value["timings"][group][ordinal - 1]
    row["deletion" if deletion else "outcome"] = "not-proved" if deletion else "failure"
    stop_after(value["timings"][group], ordinal - 1, binding)
    order = ("git", "build", "install")
    for later in order[order.index(group) + 1:]:
        value["timings"][later] = not_reached(binding)
    return refresh(value)


if sys.argv[1:] == ["--catalog"]:
    catalog = [failing(code) for code in local.ADMISSION_CODES]
    catalog.extend(categorical_failure(code) for code in (
        "lifecycle-start", "ssh", "git-sample", "build-sample", "install-sample",
        "deletion", "cleanup", "residue", "uncertain"))
    sys.stdout.write(json.dumps(catalog, separators=(",", ":")))
    raise SystemExit(0)
if sys.argv[1:] == ["--probe"]:
    try:
        local.canonical_result(json.loads(sys.stdin.buffer.read()))
    except (local.LocalResultError, ValueError, TypeError):
        raise SystemExit(1)
    raise SystemExit(0)
check(not sys.argv[1:], "unexpected test selector")

pass_value, fail_value = passing(), failing()
for name, expected in (("local-result-v2-pass.json", pass_value), ("local-result-v2-failure.json", fail_value)):
    raw = (FIXTURES / name).read_bytes()
    check(raw == local.canonical_result(expected), f"shared fixture {name}")
    check(local.load_result(raw) == expected and raw.isascii() and len(raw) <= 32768, f"load {name}")
for code in local.ADMISSION_CODES:
    check(local.validate_result(failing(code)) is False, f"admission {code}")
for code in local.ADMISSION_CODES[:-1]:
    for hostile in (
        {"observation": "failure", "kvm_api": 12, "qmp_present": True, "qmp_enabled": False},
        {"observation": "failure", "kvm_api": None, "qmp_present": True, "qmp_enabled": True},
        {"observation": "pass", "kvm_api": 12, "qmp_present": False, "qmp_enabled": False},
        {"observation": "pass", "kvm_api": 12, "qmp_present": True, "qmp_enabled": True},
    ):
        mutation_value = failing(code)
        mutation_value["platform"] = hostile
        rejected(lambda value=mutation_value: local.validate_result(value), f"{code} later KVM fact")
reached_favorable = failing("kvm")
reached_favorable["platform"] = {
    "observation": "failure", "kvm_api": 12, "qmp_present": True, "qmp_enabled": True,
}
rejected(lambda: local.validate_result(reached_favorable), "failed KVM with favorable facts")
for code in ("lifecycle-start", "ssh", "git-sample", "build-sample", "install-sample",
             "deletion", "cleanup", "residue", "uncertain"):
    check(local.validate_result(categorical_failure(code)) is False, f"causal {code}")
for group in ("git", "build", "install"):
    for ordinal in range(1, 8):
        check(local.validate_result(ordinal_failure(group, ordinal)) is False,
              f"valid {group} failure {ordinal}")
        check(local.validate_result(ordinal_failure(group, ordinal, deletion=True)) is False,
              f"valid {group} deletion {ordinal}")
        invalid = ordinal_failure(group, ordinal)
        pristine = passing()
        if ordinal < 7:
            invalid["timings"][group][ordinal] = pristine["timings"][group][ordinal]
        elif group != "install":
            later = ("git", "build", "install")[("git", "build", "install").index(group) + 1]
            invalid["timings"][later][0] = pristine["timings"][later][0]
        else:
            invalid["timings"]["install"][5]["outcome"] = "failure"
        refresh(invalid)
        rejected(lambda value=invalid: local.validate_result(value), f"invalid {group} continuation {ordinal}")


def mutation(name, change, base=pass_value):
    changed = copy.deepcopy(base)
    change(changed)
    rejected(lambda: local.validate_result(changed), name)


mutation("root extra", lambda item: item.update(extra=True))
mutation("nested extra", lambda item: item["bindings"].update(extra="0" * 64))
mutation("ordinal order", lambda item: item["timings"]["git"].reverse())
mutation("summary", lambda item: item["timing_summaries"]["git"].update(total_ns=1))
mutation("mixed source", lambda item: item["operation"].update(source_head="b" * 40))
mutation("mixed pin", lambda item: item["operation"].update(final_pin_sha256="e" * 64))
mutation("binding", lambda item: item["operation"].update(operation_sha256="d" * 64))
mutation("authority", lambda item: item.update(authority="local-authority"))
mutation("classification", lambda item: item.update(validation_classification="schema-only"))
mutation("work without operation", lambda item: item["timings"]["git"][0].update(
    duration_ns=1, outcome="failure", deletion="absent"), fail_value)
mutation("SSH without KVM", lambda item: item["admission"].update(kvm="failure"))
mutation("install after build failure", lambda item: item["timings"]["build"][0].update(outcome="failure"))
mutation("unreachable teardown", lambda item: item["teardown"][0].update(outcome="not-reached"))
mutation("uncertain retired phase", lambda item: item["operation"].update(status="uncertain"))
mutation("wrong causal code", lambda item: item.update(failure_code="ssh"), categorical_failure("git-sample"))

for valid in (1, 3_600_000_000_000):
    changed = copy.deepcopy(pass_value)
    for row in changed["timings"]["git"]:
        row["duration_ns"] = valid
    refresh(changed)
    check(local.validate_result(changed), f"duration boundary {valid}")
for invalid in (0, 3_600_000_000_001, True, 1.0):
    mutation(f"duration {invalid!r}", lambda item, invalid=invalid: item["timings"]["git"][0].update(duration_ns=invalid))

raw = local.canonical_result(pass_value)
rejected(lambda: local.load_result(json.dumps(pass_value).encode("ascii") + b"\n"), "noncanonical")
rejected(lambda: local.load_result(raw[:-1]), "newline")
rejected(lambda: local.load_result(b"\xef\xbb\xbf" + raw), "ASCII/BOM")
rejected(lambda: local.load_result(b" " * (local.MAX_RESULT_BYTES - 1) + b"\n"), "exact size malformed")
rejected(lambda: local.load_result(b" " * local.MAX_RESULT_BYTES + b"\n"), "oversize")
rejected(lambda: local.load_result(b'{"duration_ns":1e400}\n'), "non-integral/overflow JSON")
rejected(lambda: local.load_result(b'{"authority":"duplicate",' + raw[1:]), "duplicate key")

schema = json.loads((ROOT / local.SCHEMA_REGISTRY[0][1]).read_text())
check(schema["properties"]["authority"]["const"] == local.AUTHORITY, "schema authority")
check(schema["properties"]["validation_classification"]["const"] == local.VALIDATION_CLASSIFICATION,
      "validator-required classification")
budget_spec = importlib.util.spec_from_file_location("stage2_retained_budget", BUDGET_PATH)
budget = importlib.util.module_from_spec(budget_spec)
budget_spec.loader.exec_module(budget)
line_report = budget.measure()
check(line_report["physical_baseline_lines"] == line_report["physical_baseline_deployment_lines"]
      + line_report["physical_baseline_retained_schema_script_lines"], "complete physical baseline")
check(line_report["conservative_baseline_lines"] == line_report["inherited_predecessor_minimum"]
      + line_report["pre_base_gross_additions"] == 36_861, "inherited no-deletion baseline")
check(line_report["current_lines"] == line_report["deployment_lines"]
      + line_report["retained_schema_script_lines"], "complete retained count")
check(line_report["inherited_post_base_gross_additions"] == 0
      and line_report["gross_added_lines_no_deletion_credit"] > 0,
      "gross additions were not measured from the fixed base")
check(line_report["conservative_lines_no_deletion_credit"] == budget.CONSERVATIVE_BASELINE_LINES
      + line_report["gross_added_lines_no_deletion_credit"], "no deletion credit")
check(line_report["preferred_satisfied"] and line_report["hard_satisfied"], "ADR 0099 cap")
ignored_probe = ROOT / "deploy/aws-feasibility/__pycache__/stage2_ignored_counted_probe.py"
check(not ignored_probe.exists(), "ignored cap probe pre-existed")
ignored_probe.parent.mkdir(exist_ok=True)
try:
    ignored_probe.write_text("one\ntwo\nthree\n")
    check(subprocess.run(["git", "check-ignore", "-q", str(ignored_probe.relative_to(ROOT))], cwd=ROOT).returncode == 0,
          "cap probe was not ignored")
    charged = budget.measure()
    check(charged["current_lines"] == line_report["current_lines"] + 3, "ignored physical source omitted")
    check(charged["conservative_lines_no_deletion_credit"]
          == line_report["conservative_lines_no_deletion_credit"] + 3, "ignored gross source omitted")
finally:
    ignored_probe.unlink(missing_ok=True)
protected = subprocess.run(["git", "cat-file", "-e",
                            "69eccf1:schemas/stage2-workload-local-qualification-v1.json"],
                           cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
check(protected.returncode != 0, "protected main unexpectedly contained rejected v1")
for args in ([], ["report.json"], [json.dumps(fail_value)]):
    process = subprocess.run([sys.executable, "-B", str(MODULE_PATH), *args], input=raw,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    check(process.returncode == 3 and process.stdout == process.stderr == b"", "blocked stub")
print("completion local result codec tests passed")

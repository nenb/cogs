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
    values = [row["duration_ns"] for row in rows]
    return {
        "count": len(values), "total_ns": sum(values),
        "minimum_ns": min(values) if values else None,
        "maximum_ns": max(values) if values else None,
    }


def passing():
    bindings = {
        "source_head": "a" * 40,
        "source_manifest_sha256": "1" * 64,
        "host_attestation_sha256": "2" * 64,
        "runtime_attestation_sha256": "3" * 64,
        "rootfs_sha256": "4" * 64,
        "artifact_sha256": "5" * 64,
        "candidate_sha256": "6" * 64,
        "final_pin_sha256": "7" * 64,
        "guest_program_sha256": "8" * 64,
        "owner_implementation_sha256": "9" * 64,
    }
    operation, journal = "b" * 64, "c" * 64
    binding = digest_view(bindings, operation, journal)
    timings = {}
    for offset, name in enumerate(("git", "build", "install"), 1):
        timings[name] = [
            {"ordinal": index, "duration_ns": offset * 100 + index, "outcome": "pass",
             "deletion": "absent", "binding_sha256": binding}
            for index in range(1, 8)
        ]
    return {
        "version": local.VERSION,
        "result": "pass",
        "failure_code": None,
        "qualified": True,
        "authority": local.AUTHORITY,
        "limitations": list(local.LIMITATIONS),
        "bindings": bindings,
        "platform": {"kvm_api": 12, "qmp_present": True, "qmp_enabled": True},
        "lifecycle": {"attempts": 1, "outcome": "pass", "ssh_attempts": 1, "ssh_outcome": "pass"},
        "operation": {
            "operation_sha256": operation, "journal_sha256": journal, "binding_sha256": binding,
            "source_head": bindings["source_head"],
            "source_manifest_sha256": bindings["source_manifest_sha256"],
            "final_pin_sha256": bindings["final_pin_sha256"], "status": "retired",
        },
        "timings": timings,
        "timing_summaries": {name: summary(rows) for name, rows in timings.items()},
        "teardown": [
            {"phase": phase, "outcome": "pass", "binding_sha256": binding}
            for phase in local.TEARDOWN_PHASES
        ],
        "zero_residue": {name: "absent" for name in local.RESIDUE_FACTS},
    }


def failing():
    value = passing()
    value.update(result="failure", failure_code="preflight", qualified=False)
    value["platform"] = {"kvm_api": None, "qmp_present": False, "qmp_enabled": False}
    value["lifecycle"] = {"attempts": 0, "outcome": "not-reached", "ssh_attempts": 0,
                          "ssh_outcome": "not-reached"}
    value["operation"].update(operation_sha256=None, journal_sha256=None, binding_sha256=None,
                              status="not-created")
    value["timings"] = {name: [] for name in ("git", "build", "install")}
    value["timing_summaries"] = {name: summary([]) for name in value["timings"]}
    value["teardown"] = [
        {"phase": phase, "outcome": "not-reached", "binding_sha256": None}
        for phase in local.TEARDOWN_PHASES
    ]
    return value


value = passing()
raw = local.canonical_result(value)
check(raw == local.canonical_result(local.load_result(raw)), "canonical round trip")
check(raw.isascii() and len(raw) <= 32768 and raw.endswith(b"\n"), "ASCII/size/framing")
check(local.validate_result(failing()) is False, "categorical failure")

mutations = []
def mutation(name, change):
    changed = copy.deepcopy(value)
    change(changed)
    mutations.append((name, changed))

mutation("root extra", lambda item: item.update(extra=True))
mutation("nested extra", lambda item: item["bindings"].update(extra="0" * 64))
mutation("bool as ordinal", lambda item: item["timings"]["git"][0].update(ordinal=True))
mutation("bool as duration", lambda item: item["timings"]["git"][0].update(duration_ns=True))
mutation("summary", lambda item: item["timing_summaries"]["git"].update(total_ns=1))
mutation("row order", lambda item: item["timings"]["git"].reverse())
mutation("missing timing", lambda item: item["timings"]["build"].pop())
mutation("unproved deletion", lambda item: item["timings"]["install"][2].update(deletion="not-proved"))
mutation("row operation", lambda item: item["timings"]["git"][0].update(binding_sha256="d" * 64))
mutation("mixed source", lambda item: item["operation"].update(source_head="b" * 40))
mutation("mixed manifest", lambda item: item["operation"].update(source_manifest_sha256="d" * 64))
mutation("mixed pin", lambda item: item["operation"].update(final_pin_sha256="e" * 64))
mutation("operation binding", lambda item: item["operation"].update(operation_sha256="d" * 64))
mutation("KVM API", lambda item: item["platform"].update(kvm_api=None))
mutation("QMP", lambda item: item["platform"].update(qmp_enabled=False))
mutation("lifecycle attempts", lambda item: item["lifecycle"].update(attempts=0))
mutation("SSH attempts", lambda item: item["lifecycle"].update(ssh_attempts=0))
mutation("teardown order", lambda item: item["teardown"].reverse())
mutation("teardown result", lambda item: item["teardown"][3].update(outcome="failure"))
mutation("residue", lambda item: item["zero_residue"].update(qemu_processes="not-proved"))
mutation("authority", lambda item: item.update(authority="aws-feasibility"))
mutation("limitations", lambda item: item["limitations"].pop())
mutation("positive boolean", lambda item: item["timings"]["git"].pop())
for name, changed in mutations:
    rejected(lambda changed=changed: local.validate_result(changed), name)

all_green_failure = passing()
all_green_failure.update(result="failure", failure_code="preflight", qualified=False)
rejected(lambda: local.validate_result(all_green_failure), "all-green failure")

rejected(lambda: local.load_result(json.dumps(value).encode("ascii") + b"\n"), "noncanonical JSON")
rejected(lambda: local.load_result(raw[:-1]), "missing newline")
rejected(lambda: local.load_result(b"\xef\xbb\xbf" + raw), "non-ASCII/BOM")
duplicate = b'{"authority":"duplicate",' + raw[1:]
rejected(lambda: local.load_result(duplicate), "duplicate root key")
needle = b'"source_head":"' + b"a" * 40 + b'"'
duplicate_nested = raw.replace(needle, needle + b',"source_head":"' + b"a" * 40 + b'"', 1)
rejected(lambda: local.load_result(duplicate_nested), "duplicate nested key")

schema = json.loads((ROOT / local.SCHEMA_REGISTRY[0][1]).read_text())
check(local.SCHEMA_REGISTRY == ((local.VERSION, "schemas/stage2-workload-local-qualification-v2.json"),),
      "schema registry")
check(schema["$id"].endswith("stage2-workload-local-qualification-v2.json"), "schema id")
check(schema["properties"]["version"]["const"] == local.VERSION, "schema version")
check(not (ROOT / "schemas/stage2-workload-local-qualification-v1.json").exists(), "retired v1 not recreated")

for args in ([], ["report.json"], [json.dumps(failing())]):
    process = subprocess.run([sys.executable, "-B", str(MODULE_PATH), *args], input=raw,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    check(process.returncode == 3 and process.stdout == b"" and process.stderr == b"", "blocked stub")

print("completion local result codec tests passed")

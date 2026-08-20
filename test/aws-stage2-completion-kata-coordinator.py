#!/usr/bin/env python3
"""Portable refusal ordering and static production-composition checks."""
import ast
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_coordinator as coordinator
import completion_kata_qualification as qualification
import completion_runtime_contract as contract


def rejected(call, kind=coordinator.CoordinatorBlocked):
    try:
        call()
    except kind:
        return
    raise AssertionError("expected fixed refusal")


def mutation(*_args, **_kwargs):
    raise AssertionError("a mutable owner was opened")


# Every prerequisite cut is read-only and stops before all integrated owners.
events = []
with (patch.object(qualification, "_claim_committed_gate",
                   side_effect=lambda: events.append("preflight") or (_ for _ in ()).throw(
                       qualification.QualificationError())),
      patch.object(contract, "load_final_pin",
                   side_effect=lambda: events.append("pin")),
      patch.object(coordinator.process, "_open_attested_executable_owner", mutation),
      patch.object(coordinator.runtime, "_open_production_owner", mutation)):
    rejected(coordinator._run_fixed_local_qualification)
assert events == ["preflight"]

events.clear()
with (patch.object(qualification, "_claim_committed_gate",
                   side_effect=lambda: events.append("preflight") or object()),
      patch.object(contract, "load_final_pin",
                   side_effect=lambda: events.append("pin") or (_ for _ in ()).throw(
                       contract.FinalPinUnavailable())),
      patch.object(coordinator.process, "_open_attested_executable_owner", mutation),
      patch.object(coordinator.runtime, "_open_production_owner", mutation)):
    rejected(coordinator._run_fixed_local_qualification)
assert events == ["preflight", "pin"]

events.clear()
with (patch.object(qualification, "_claim_committed_gate",
                   side_effect=lambda: events.append("preflight") or object()),
      patch.object(contract, "load_final_pin",
                   side_effect=lambda: events.append("pin") or object()),
      patch.object(coordinator.process, "_open_attested_executable_owner", mutation),
      patch.object(coordinator.runtime, "_open_production_owner", mutation)):
    rejected(coordinator._run_fixed_local_qualification)
    rejected(coordinator._recover_fixed_local_qualification)
assert events == ["preflight", "pin", "preflight", "pin"]
rejected(lambda: coordinator._consume_local_receipt(object()), coordinator.CoordinatorError)

# Production entry/recovery contain no fixture issuer, callback, argv, path, or
# environment selector. Recovery cannot call the work entry or rerun work.
source = (REMOTE / "completion_kata_coordinator.py").read_text()
tree = ast.parse(source)
functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
for name in ("_claim_complete_prerequisites", "run", "recover"):
    text = ast.get_source_segment(source, functions[name])
    assert text is not None
    lowered = text.lower()
    for forbidden in ("fake", "synthetic", "callback", "getenv", "environ", "argv", "aws", "provider"):
        assert forbidden not in lowered, (name, forbidden)
recovery = ast.get_source_segment(source, functions["recover"])
assert "run(" not in recovery
assert "_claim_complete_prerequisites" in recovery
assert coordinator.TEARDOWN_ORDER == (
    "READINESS_REVOKED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
    "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRED",
)

entry = REMOTE / "completion_local_full.py"
environment = {"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
               "PYTHONDONTWRITEBYTECODE": "1"}
blocked = subprocess.run([sys.executable, "-B", str(entry)], cwd=ROOT,
                         env=environment, capture_output=True, timeout=5, check=False)
assert blocked.returncode == 3 and blocked.stdout == blocked.stderr == b""
argument = subprocess.run([sys.executable, "-B", str(entry), "unexpected"], cwd=ROOT,
                          env=environment, capture_output=True, timeout=5, check=False)
assert argument.returncode == 3 and argument.stdout == argument.stderr == b""
print("completion coordinator portable refusal/failure-cut matrix passed")

#!/usr/bin/env python3
"""Package-private mutable bridge wiring and no-KVM/fault-cut foundations."""
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_coordinator as coordinator
import completion_kata_execution_bridge as execution
import completion_kata_operation_bridge as operation
import completion_kata_process as process
import completion_kata_runtime as runtime

owners = coordinator._owners
lifecycle = coordinator._Lifecycle(
    static_custody=object(), rootfs=object(), operation=object(), executables=object(),
    inputs=object(), baselines=object(), network_owner=object(),
    final_baselines={"proof_sha256": "a" * 64},
)

# Every mutable facade method has one narrow production route. Before/after
# faults are propagated after exactly one call; there is no retry or fallback.
routes = {
    "acquire_rootfs": (operation, "_acquire_rootfs", owners.operation),
    "open_operation": (operation, "_open_operation", owners.operation),
    "create_inputs": (operation, "_create_inputs", owners.operation),
    "capture_baselines": (execution, "_capture_baselines", owners.execution),
    "create_network": (execution, "_create_network", owners.execution),
    "prove_network_causality": (execution, "_prove_network_causality", owners.execution),
    "stage_runtime": (execution, "_stage_runtime", owners.execution),
    "bind_execution_mapping": (execution, "_bind_execution_mapping", owners.execution),
    "launch_task": (execution, "_launch_task", owners.execution),
    "prove_runtime": (execution, "_prove_runtime", owners.execution),
    "authenticate_ssh": (execution, "_authenticate_ssh", owners.execution),
    "open_existing_operation": (operation, "_open_existing_operation", owners.operation),
    "recover_pending": (operation, "_recover_pending", owners.operation),
    "revoke_readiness": (execution, "_revoke_readiness", owners.execution),
    "observe_ownership": (execution, "_observe_ownership", owners.execution),
    "stop_task": (execution, "_stop_task", owners.execution),
    "remove_network": (execution, "_remove_network", owners.execution),
    "remove_task": (execution, "_remove_task", owners.execution),
    "remove_container": (execution, "_remove_container", owners.execution),
    "remove_runtime": (execution, "_remove_runtime", owners.execution),
    "remove_share": (execution, "_remove_share", owners.execution),
    "stop_containerd": (execution, "_stop_containerd", owners.execution),
    "remove_firewall": (execution, "_remove_firewall", owners.execution),
    "remove_inputs": (operation, "_remove_inputs", owners.operation),
    "prepare_rootfs_release": (operation, "_prepare_rootfs_release", owners.operation),
    "authorize_rootfs_release": (operation, "_authorize_rootfs_release", owners.operation),
    "remove_rootfs": (operation, "_remove_rootfs", owners.operation),
    "observe_final_baselines": (execution, "_observe_final_baselines", owners.execution),
    "retire_operation": (operation, "_retire_operation", owners.operation),
    "remove_operation": (operation, "_remove_operation", owners.operation),
    "abandon_prepared_rootfs": (operation, "_abandon_prepared_rootfs", owners.operation),
}

class Cut(Exception):
    pass

for method_name, (module, route_name, expected_bridge) in routes.items():
    calls = []
    marker = object()
    def success(bridge, received, calls=calls):
        calls.append((bridge, received)); return marker
    with patch.object(module, route_name, side_effect=success):
        assert getattr(owners, method_name)(lifecycle) is marker
    assert calls == [(expected_bridge, lifecycle)]
    calls.clear()
    def failure(bridge, received, calls=calls):
        calls.append((bridge, received)); raise Cut(route_name)
    with patch.object(module, route_name, side_effect=failure):
        try: getattr(owners, method_name)(lifecycle)
        except Cut: pass
        else: raise AssertionError(f"{method_name} swallowed fault")
    assert calls == [(expected_bridge, lifecycle)]

# Executable custody is the one static-to-mutable handoff. It consumes only the
# exact static custody object and does not reinterpret the historical gate.
claimed = object()
with patch.object(process, "_open_static_attested_executable_owner",
                  side_effect=lambda custody: (claimed if custody is lifecycle.static_custody else None)) as call:
    assert owners.claim_executables(lifecycle) is claimed
    call.assert_called_once_with(lifecycle.static_custody)

# Linux no-KVM foundation: an absent QEMU proves QMP absence without opening
# /dev/kvm. KVM-present success remains exclusively in the real QMP path.
if sys.platform == "linux" and not Path(runtime.QMP_SOCKET).exists():
    absent = runtime.ProcessClassification(runtime.Observation.ABSENT, (), "no runtime")
    with patch.object(runtime.os, "open", wraps=runtime.os.open) as opened:
        assert runtime._qmp_kvm(absent) == {"state": "absent"}
    assert not any(call.args and call.args[0] == "/dev/kvm" for call in opened.call_args_list)

# Narrow modules expose no public opener and contain no caller-controlled
# path/command/callback/retry/fallback parameter surface.
for name in ("completion_kata_operation_bridge.py", "completion_kata_execution_bridge.py"):
    source = (REMOTE / name).read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = [argument.arg for argument in (*node.args.posonlyargs, *node.args.args,
                                                         *node.args.kwonlyargs)]
            assert not set(parameters) & {"path", "command", "argv", "callback", "retry", "fallback"}
    assert "def open_fixed" not in source

# The real zero-argument coordinator still refuses at static custody before any
# mutable bridge call; owner evidence remains a separate unavailable bridge.
with patch.object(operation, "_acquire_rootfs", side_effect=AssertionError("mutable effect")):
    try: coordinator._run_fixed_local_qualification()
    except coordinator.CoordinatorError: pass
    else: raise AssertionError("blocked coordinator unexpectedly ran")

print("mutable owner bridges and no-KVM fault cuts passed")

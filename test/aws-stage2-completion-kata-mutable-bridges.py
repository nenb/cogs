#!/usr/bin/env python3
"""Package-private mutable bridge wiring and no-KVM/fault-cut foundations."""
import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_coordinator as coordinator
import completion_kata_execution_bridge as execution
import completion_kata_operation_bridge as operation
import completion_kata_preparation_bridge as preparation
import completion_kata_process as process
import completion_kata_runtime as runtime


def runtime_removal_crash(root):
    """Crash from the production bridge after daemon-tree removal returns."""
    root = Path(root)
    lifecycle = coordinator._Lifecycle(recovery=True, operation=object())
    completion = object()
    chain = SimpleNamespace(components=(SimpleNamespace(node=completion),))
    daemon = object()

    def remove_then_crash(value):
        assert value is daemon
        target = root / "kata-runtime-v1"
        for name in ("containerd", "ctr"):
            (target / "bin" / name).unlink()
        (target / "bin").rmdir()
        target.rmdir()
        os._exit(93)

    with patch.object(execution.operation, "_durable_phase", return_value="SHARE_ABSENT"), \
         patch.object(execution.operation, "_open_base_chain", return_value=chain), \
         patch.object(execution.runtime, "_retain_private_containerd",
                      side_effect=lambda journal, node, process_owner, control: daemon
                      if journal is lifecycle.operation and node is completion
                      and process_owner is None else None), \
         patch.object(execution.runtime, "_shutdown_private_containerd",
                      side_effect=remove_then_crash):
        execution._stop_containerd(coordinator._owners.execution, lifecycle)
    raise AssertionError("post-removal crash cut returned")


def runtime_removal_recovery(root):
    """Fresh recovery at durable SHARE_ABSENT claims no removed runtime tool."""
    root = Path(root)
    staged = root / "kata-runtime-v1"
    assert (root / "phase").read_text() == "SHARE_ABSENT\n" and not staged.exists()
    lifecycle = coordinator._Lifecycle(
        recovery=True, static_custody=object(), operation=object(), rootfs=object())
    lazy_owner = object()
    roles = []
    completion = object()
    chain = SimpleNamespace(components=(SimpleNamespace(node=completion),))
    daemon = object()

    def claim(owner, role):
        assert owner is lazy_owner
        roles.append(role)
        if role in {"containerd", "ctr"}:
            raise AssertionError("removed staged executable role was reclaimed")
        return SimpleNamespace(role=role)

    with patch.object(execution.operation, "_durable_phase", return_value="SHARE_ABSENT"), \
         patch.object(execution.operation, "_network_records", return_value=()), \
         patch.object(execution.operation, "_open_base_chain", return_value=chain), \
         patch.object(execution.nft_owner, "reopen_cleanup", return_value=object()), \
         patch.object(execution.preparation, "_reconstruct_fixed_executable_owner",
                      return_value=lazy_owner), \
         patch.object(execution.process, "_claim_attested_executable", side_effect=claim), \
         patch.object(execution.runtime, "_reconstruct_fixed_runtime",
                      side_effect=AssertionError("complete runtime reconstruction after removal")), \
         patch.object(execution.runtime, "_retain_private_containerd",
                      side_effect=lambda journal, node, process_owner, control: daemon
                      if journal is lifecycle.operation and node is completion
                      and process_owner is None else None), \
         patch.object(execution.runtime, "_shutdown_private_containerd") as shutdown, \
         patch.object(execution.network, "_remove_fixed_firewall", return_value="FIREWALL_ABSENT"):
        execution._reconstruct_execution_cleanup(coordinator._owners.execution, lifecycle)
        assert execution._stop_containerd(coordinator._owners.execution, lifecycle) == {
            "containerd": "absent"}
        assert execution._remove_firewall(coordinator._owners.execution, lifecycle) == "FIREWALL_ABSENT"
    shutdown.assert_called_once_with(daemon)
    assert roles == ["ip", "nft", "tc"]
    (root / "firewall-transition").write_text("FIREWALL_ABSENT\n")


def runtime_removal_parent():
    assert sys.platform.startswith("linux") and not Path("/dev/kvm").exists()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        runtime_root = root / "kata-runtime-v1"
        (runtime_root / "bin").mkdir(parents=True)
        for name in ("containerd", "ctr"):
            (runtime_root / "bin" / name).write_bytes((name + "\n").encode())
        (root / "phase").write_text("SHARE_ABSENT\n")
        crashed = subprocess.run(
            (sys.executable, "-B", __file__, "--remove-runtime-crash", str(root)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False)
        assert crashed.returncode == 93 and not runtime_root.exists()
        recovered = subprocess.run(
            (sys.executable, "-B", __file__, "--recover-after-runtime-removal", str(root)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False)
        assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
        assert (root / "firewall-transition").read_text() == "FIREWALL_ABSENT\n"
    print("fresh-process post-containerd-removal no-KVM recovery passed")


if len(sys.argv) == 3 and sys.argv[1] == "--remove-runtime-crash":
    runtime_removal_crash(sys.argv[2])
    raise SystemExit(1)
if len(sys.argv) == 3 and sys.argv[1] == "--recover-after-runtime-removal":
    runtime_removal_recovery(sys.argv[2])
    raise SystemExit(0)
if sys.argv[1:] == ["--runtime-removal-parent"]:
    runtime_removal_parent()
    raise SystemExit(0)

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
    "observe_runtime_network": (execution, "_observe_runtime_network", owners.execution),
    "prove_runtime": (execution, "_prove_runtime", owners.execution),
    "authenticate_ssh": (execution, "_authenticate_ssh", owners.execution),
    "open_existing_operation": (operation, "_open_existing_operation", owners.operation),
    "recover_pending": (operation, "_recover_pending", owners.operation),
    "revoke_readiness": (execution, "_revoke_readiness", owners.execution),
    "observe_ownership": (execution, "_observe_ownership", owners.execution),
    "stop_task": (execution, "_stop_task", owners.execution),
    "release_network_holds": (execution, "_release_network_holds", owners.execution),
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

# The production bridge consumes the retained network tools exactly once after
# CTR_RUN and returns only the durable operation-bound runtime snapshot.
tools = (object(), object(), object())
runtime_network = {"snapshot_kind": "runtime", "operation_token": "a" * 64,
                   "proof_sha256": "b" * 64}
lifecycle.task = object()
with patch.object(execution.process, "_claim_attested_executable",
                  side_effect=tools), \
     patch.object(execution.network, "_capture_fixed_baselines",
                  return_value=lifecycle.baselines), \
     patch.object(execution.network, "_setup_fixed_network", return_value=object()), \
     patch.object(execution.network, "_reopen_runtime_network",
                  return_value=lifecycle.network_owner), \
     patch.object(execution.network, "_observe_fixed_runtime_network",
                  return_value=runtime_network) as observed, \
     patch.object(execution.operation, "_command_context",
                  return_value=SimpleNamespace(operation_token="a" * 64)):
    assert owners.capture_baselines(lifecycle) is lifecycle.baselines
    assert owners.create_network(lifecycle) is lifecycle.network_owner
    assert owners.observe_runtime_network(lifecycle) is runtime_network
observed.assert_called_once_with(lifecycle.operation, *tools)
lifecycle.runtime_network = runtime_network

# Executable custody is the one static-to-mutable handoff. It consumes only the
# exact static custody object and does not reinterpret the historical gate.
claimed = object()
lifecycle.live_mapping = lifecycle.live_custody = object()
with patch.object(preparation, "_claim_fixed_executable_owner",
                  side_effect=lambda custody: (claimed if custody is lifecycle.static_custody else None)) as call:
    assert owners.claim_executables(lifecycle) is claimed
    call.assert_called_once_with(lifecycle.static_custody)

# Linux no-KVM foundation: an absent QEMU proves QMP absence without opening
# /dev/kvm. KVM-present success remains exclusively in the real QMP path.
if (sys.platform == "linux"
        and not Path(runtime.KATA_QMP_SOCKET).exists()
        and not Path(runtime.OBSERVER_QMP_SOCKET).exists()
        and not Path(runtime.KATA_VM_DIRECTORY).exists()):
    absent = runtime.ProcessClassification(runtime.Observation.ABSENT, (), "no runtime")
    with patch.object(runtime.os, "open", wraps=runtime.os.open) as opened:
        assert runtime._qmp_kvm(absent) == {
            "state": "absent", "private_socket": "absent",
            "observer_socket": "absent"}
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

execution_source = (REMOTE / "completion_kata_execution_bridge.py").read_text()
assert "proc_passes = (proc_pass(), proc_pass())" in execution_source
assert 'netns_identity["inode_device"]' in execution_source
assert 'os.listdir(f"/proc/{pid}/fd")' in execution_source
assert 'Path(runtime.SHARE_ROOT)' in execution_source
assert 'Path(runtime.RUNTIME_ALIAS)' in execution_source

# The real zero-argument coordinator still refuses at static custody before any
# mutable bridge call; owner evidence remains a separate unavailable bridge.
with patch.object(operation, "_acquire_rootfs", side_effect=AssertionError("mutable effect")):
    try: coordinator._run_fixed_local_qualification()
    except coordinator.CoordinatorError: pass
    else: raise AssertionError("blocked coordinator unexpectedly ran")

print("mutable owner bridges and no-KVM fault cuts passed")

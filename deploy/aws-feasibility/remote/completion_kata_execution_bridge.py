"""Narrow network/process/runtime/SSH composition for one fixed Kata lifecycle."""
import os
import time

import completion_kata_inputs as inputs
import completion_kata_network as network
import completion_kata_operation as operation
import completion_kata_process as process
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_rootfs_fs as fs


class ExecutionBridgeError(Exception):
    pass


def _require(condition, message="fixed mutable execution bridge"):
    if not condition:
        raise ExecutionBridgeError(message)


def _routes():
    seal, states = object(), {}
    issued = False

    class _Bridge:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, "sealed mutable execution bridge")
            return super().__new__(cls)

    def state(bridge, lifecycle):
        _require(type(bridge) is _Bridge and bridge in states)
        current = states[bridge]
        bound = current.get("lifecycle")
        _require(bound is None or bound is lifecycle, "lifecycle bridge swap")
        current["lifecycle"] = lifecycle
        return current

    def fixed_chain(current):
        if current.get("chain") is None:
            control = fs.OperationControl(time.monotonic_ns() + operation.JOURNAL_TOTAL_NS,
                                          lambda: False)
            current["control"] = control
            current["chain"] = operation._open_base_chain(control)
        return current["chain"].components[-1].node

    def claim_tools(bridge, lifecycle):
        current = state(bridge, lifecycle)
        owner = lifecycle.executables
        if "tools" not in current:
            current["tools"] = tuple(process._claim_attested_executable(owner, role)
                                     for role in ("ip", "nft", "tc"))
        return current["tools"]

    def capture(bridge, lifecycle):
        current = state(bridge, lifecycle)
        body = network._capture_fixed_baselines(lifecycle.operation,
                                                *claim_tools(bridge, lifecycle))
        current["baselines"] = body
        return body

    def create_network(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("baselines") is lifecycle.baselines)
        body = network._setup_fixed_network(lifecycle.operation, *current["tools"])
        current["network_snapshot"] = body
        current["sensor_before"] = network._capture_causal_sensor(
            lifecycle.operation, *current["tools"], "before")
        current["network_owner"] = network._reopen_runtime_network(lifecycle.operation)
        return current["network_owner"]

    def prove_network(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("network_owner") is lifecycle.network_owner
                 and type(current.get("sensor_before")) is network.CausalSensorSnapshot)
        return current["sensor_before"]

    def open_relative(parent, names, kind, control):
        held = []
        current = parent
        try:
            for index, name in enumerate(names):
                node = fs._open_path_node(current, fs._name(name),
                                          kind if index + 1 == len(names) else "directory",
                                          control)
                held.append(node); current = node
            return current, tuple(held)
        except BaseException as error:
            for node in reversed(held):
                try: fs._close_node(node)
                except BaseException: pass
            raise error

    def open_config(control):
        root = fs._open_root_node(control)
        node, held = open_relative(root, tuple(part for part in runtime.RUNTIME_CONFIG.split("/")
                                               if part), "file", control)
        return node, (root, *held)

    def stage(bridge, lifecycle):
        current = state(bridge, lifecycle)
        completion = fixed_chain(current)
        artifact, artifact_nodes = open_relative(
            completion, ("artifacts", "cache", "containerd-static-2.2.1-linux-amd64.tar.gz"),
            "file", current["control"])
        try:
            staged = runtime._stage_containerd_archive(
                lifecycle.operation, completion, artifact, current["control"])
        finally:
            for node in reversed(artifact_nodes): fs._close_node(node)
        config, config_nodes = open_config(current["control"])
        attestation = None
        start_attempted = False
        try:
            attestation = runtime._issue_fixed_runtime_attestation(
                lifecycle.executables, config, current["control"])
            fs._close_node(staged); staged = None
            input_owner = inputs._reopen_runtime_inputs(
                lifecycle.operation, completion, current["control"])
            start_attempted = True
            owner = runtime._start_composed_runtime(
                lifecycle.operation, lifecycle.rootfs, input_owner,
                current["network_owner"], attestation, completion, current["control"])
        except BaseException as primary:
            errors = [primary]
            if staged is not None and staged.identity_fd.disposition == "open":
                try: fs._close_node(staged)
                except BaseException as error: errors.append(error)
            if not start_attempted:
                try:
                    daemon = runtime._retain_private_containerd(
                        lifecycle.operation, completion, None, current["control"])
                    runtime._cleanup_staged_runtime(daemon)
                except BaseException as error: errors.append(error)
            if attestation is not None:
                try: runtime._discard_fixed_runtime_attestation(attestation)
                except BaseException as error: errors.append(error)
            for node in reversed(config_nodes):
                try: fs._close_node(node)
                except BaseException as error: errors.append(error)
            if len(errors) == 1: raise
            raise BaseExceptionGroup("runtime staging/composition rollback", errors)
        current.update({"runtime": owner,
                        "config_nodes": config_nodes})
        return owner

    def bind_mapping(bridge, lifecycle):
        current = state(bridge, lifecycle)
        return runtime._bind_fixed_runtime_mount(current["runtime"])

    def launch(bridge, lifecycle):
        return runtime._launch_fixed_runtime(state(bridge, lifecycle)["runtime"])

    def prove_runtime(bridge, lifecycle):
        fact = runtime._observe_fixed_runtime(state(bridge, lifecycle)["runtime"])
        qmp = fact["qmp"]
        _require(qmp["kvm_present"] is True and qmp["kvm_enabled"] is True,
                 "QMP KVM proof absent")
        return fact

    def authenticate(bridge, lifecycle):
        current = state(bridge, lifecycle)
        owner = ssh._compose_production_ssh(
            lifecycle.operation, lifecycle.inputs, lifecycle.executables)
        current["ssh"] = owner
        session = owner.authenticate()
        guest = lifecycle.network_guest_proof
        _require(type(guest) is network.GuestNetworkProof,
                 "sealed guest network proof bridge absent")
        current["network_proof"] = network._prove_causal_guest_network(
            lifecycle.operation, *current["tools"], guest)
        lifecycle.network_proof = current["network_proof"]
        return session

    def revoke(bridge, lifecycle):
        current = state(bridge, lifecycle)
        owner = current.get("ssh")
        if owner is not None: owner.revoke()
        return operation._revoke_or_require_terminal(lifecycle.operation)

    def ownership(bridge, lifecycle):
        return runtime._record_fixed_runtime_ownership(state(bridge, lifecycle)["runtime"])

    def runtime_cleanup(bridge, lifecycle, expected):
        current = state(bridge, lifecycle)
        result = runtime._cleanup_fixed_runtime(current["runtime"])
        _require(operation._durable_phase(lifecycle.operation) == expected,
                 "runtime cleanup phase differs")
        return result

    def stop_task(bridge, lifecycle): return runtime_cleanup(bridge, lifecycle, "TASK_STOPPED")
    def remove_task(bridge, lifecycle): return runtime_cleanup(bridge, lifecycle, "TASK_ABSENT")
    def remove_container(bridge, lifecycle): return runtime_cleanup(bridge, lifecycle, "CONTAINER_ABSENT")
    def remove_runtime(bridge, lifecycle): return runtime_cleanup(bridge, lifecycle, "RUNTIME_ABSENT")
    def remove_share(bridge, lifecycle): return runtime_cleanup(bridge, lifecycle, "SHARE_ABSENT")

    def remove_network(bridge, lifecycle):
        current = state(bridge, lifecycle)
        return network._remove_fixed_network(lifecycle.operation, *current["tools"])

    def stop_containerd(bridge, lifecycle):
        current = state(bridge, lifecycle)
        result = runtime._cleanup_fixed_runtime(current["runtime"])
        runtime._close_fixed_runtime(current["runtime"])
        for node in reversed(current.pop("config_nodes", ())): fs._close_node(node)
        return result

    def remove_firewall(bridge, lifecycle):
        current = state(bridge, lifecycle)
        return network._remove_fixed_firewall(lifecycle.operation, *current["tools"])

    def final_baselines(bridge, lifecycle):
        current = state(bridge, lifecycle)
        result = network._observe_final_network_absence(
            lifecycle.operation, *current["tools"])
        errors = []
        for executable in reversed(current.pop("tools")):
            try: process._release_attested_executable(executable)
            except BaseException as error: errors.append(error)
        chain, current["chain"] = current.get("chain"), None
        if chain is not None:
            try: fs._close_chain(chain)
            except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("network tool/chain close", errors)
        return result

    def issue():
        nonlocal issued
        _require(not issued, "mutable execution bridge already issued")
        issued = True
        value = _Bridge(seal); states[value] = {"lifecycle": None, "chain": None}
        return value

    return (issue, claim_tools, capture, create_network, prove_network, stage,
            bind_mapping, launch, prove_runtime, authenticate, revoke, ownership,
            stop_task, remove_network, remove_task, remove_container,
            remove_runtime, remove_share, stop_containerd, remove_firewall,
            final_baselines)


(_take_execution_bridge, _claim_network_tools, _capture_baselines, _create_network,
 _prove_network_causality, _stage_runtime, _bind_execution_mapping, _launch_task,
 _prove_runtime, _authenticate_ssh, _revoke_readiness, _observe_ownership,
 _stop_task, _remove_network, _remove_task, _remove_container, _remove_runtime,
 _remove_share, _stop_containerd, _remove_firewall,
 _observe_final_baselines) = _routes()
del _routes

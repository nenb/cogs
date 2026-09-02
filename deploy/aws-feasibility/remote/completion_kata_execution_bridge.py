"""Narrow network/process/runtime/SSH composition for one fixed Kata lifecycle."""
import hashlib
import os
from pathlib import Path
import subprocess
import time

import completion_kata_inputs as inputs
import completion_kata_network as network
import completion_kata_nft_owner as nft_owner
import completion_kata_operation as operation
import completion_kata_preparation_bridge as preparation
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

    def runtime_stage_present(current):
        snapshot = fs._enumerate_stable(fixed_chain(current), current["control"])
        return b"kata-runtime-v1" in snapshot.raw_names

    def claim_tools(bridge, lifecycle):
        current = state(bridge, lifecycle)
        owner = lifecycle.executables
        if "tools" not in current:
            current["tools"] = tuple(process._claim_attested_executable(owner, role)
                                     for role in ("ip", "nft", "tc"))
        return current["tools"]

    def reconstruct(bridge, lifecycle):
        """Rebuild cleanup-only indexes from durable records and held identities."""
        current = state(bridge, lifecycle)
        journal = lifecycle.operation
        phase = operation._durable_phase(journal)
        _require(phase != "UNCERTAIN", "uncertain operation is preserved")
        current["recovery"] = True
        current["reconstructed_phase"] = phase
        network_phases = {"ROOTFS_ACQUIRE_INTENT", "ROOTFS_LEASED", "FS_INTENT",
                          "FS_SETTLED", "BASELINES_CAPTURED", "NETWORK_READY",
                          "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED",
                          "OWNERSHIP_OBSERVED", "TASK_STOPPED", "TASK_ABSENT", "RUNTIME_ABSENT",
                          "NETWORK_ABSENT", "CONTAINER_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
                          "CONTAINERD_ABSENT", "RUNTIME_CLEANUP_ONLY", "INPUT_REMOVED",
                          "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
                          "ROOTFS_ABSENT"}
        runtime_phases = {"NETWORK_READY", "RUNTIME_READY", "SSH_READY",
                          "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED",
                          "TASK_ABSENT", "RUNTIME_ABSENT", "NETWORK_ABSENT", "CONTAINER_ABSENT",
                          "SHARE_ABSENT", "FIREWALL_ABSENT", "RUNTIME_CLEANUP_ONLY"}
        if phase not in network_phases:
            return phase
        lifecycle.executables = preparation._reconstruct_fixed_executable_owner(
            lifecycle.static_custody, journal)
        rows = operation._network_records(journal)
        current["baselines"] = rows[0] if rows else None
        current["tools"] = tuple(process._claim_attested_executable(
            lifecycle.executables, role) for role in ("ip", "nft", "tc"))
        current["nft_owner"] = (nft_owner.reopen_cleanup(journal)
                                if phase not in {"ROOTFS_ACQUIRE_INTENT", "ROOTFS_LEASED",
                                                 "FS_INTENT", "INPUT_REMOVED",
                                                 "ROOTFS_RELEASE_READY",
                                                 "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT"}
                                else None)
        # ACTIVE with no snapshot is an exact read-only baseline prefix.  Keep
        # the reconstructed owner so cleanup can release it; a prior completed
        # release reconstructs as None and proceeds through ordinary FS cleanup.
        history = journal.runtime_recovery_history() if phase in runtime_phases else None
        runtime_provenance = bool(history and (
            history["runtime_prepared"] or history["runtime_stage_intents"]
            or history["runtime_staged"] or history["daemon_retained"]
            or history["daemon_outcomes"] or history["launches"]
            or history["runtime_ownership"]))
        if (rows and rows[-1]["snapshot_kind"] in {"ready", "discovered", "runtime"}
                and phase != "RUNTIME_CLEANUP_ONLY"
                and not (history and history["runtime_network_released"])):
            current["network_owner"] = network._reopen_runtime_network(journal)
            lifecycle.network_owner = current["network_owner"]
        if phase in runtime_phases and runtime_provenance and (
                phase not in {"FIREWALL_ABSENT", "RUNTIME_CLEANUP_ONLY"}
                or runtime_stage_present(current)):
            ensure_runtime(current, lifecycle)
        elif phase in {"NETWORK_ABSENT", "FIREWALL_ABSENT"}:
            _require(not runtime_stage_present(current),
                     "setup-abort runtime tree lacks durable provenance")
        return phase

    def ensure_runtime(current, lifecycle):
        if current.get("runtime") is not None:
            return current["runtime"]
        _require(lifecycle.rootfs is not None, "durable rootfs cleanup owner absent")
        completion = fixed_chain(current)
        input_owner = inputs._reopen_runtime_inputs(
            lifecycle.operation, completion, current["control"])
        config, config_nodes = open_config(current["control"])
        history = lifecycle.operation.runtime_recovery_history(); prepared_grant = None
        if not history["runtime_prepared"] and not history["runtime_stage_intents"]:
            prepared_grant = preparation._claim_fixed_prepared_runtime(lifecycle.static_custody)
        try:
            owner = runtime._reconstruct_fixed_runtime(
                lifecycle.operation, lifecycle.rootfs, input_owner,
                current.get("network_owner"), lifecycle.executables,
                completion, config, current["control"], prepared_grant)
        except BaseException as primary:
            errors = [primary]
            for node in reversed(config_nodes):
                try: fs._close_node(node)
                except BaseException as error: errors.append(error)
            if len(errors) == 1: raise
            raise BaseExceptionGroup("runtime descriptor reconstruction", errors)
        current.update({"runtime": owner, "config_nodes": config_nodes,
                        "runtime_inputs": input_owner})
        lifecycle.staged_runtime = owner
        return owner

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
        current["network_owner"] = network._reopen_runtime_network(lifecycle.operation)
        return current["network_owner"]

    def prove_network(bridge, lifecycle):
        """Capture immediately before the sole authenticated SSH command."""
        current = state(bridge, lifecycle)
        _require(current.get("network_owner") is lifecycle.network_owner
                 and current.get("runtime_network") is lifecycle.runtime_network
                 and current.get("runtime_observation") is lifecycle.runtime_observation
                 and current.get("sensor_before") is None)
        before = network._capture_causal_sensor(
            lifecycle.operation, *current["tools"], "before")
        current["sensor_before"] = before
        return before

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
        prepared_grant = preparation._claim_fixed_prepared_runtime(lifecycle.static_custody)
        staged = runtime._activate_prepared_containerd(
            lifecycle.operation, completion, current["control"], prepared_grant)
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
        _require(type(lifecycle.live_mapping) is __import__(
            "completion_kata_admission").LiveMappingDescription,
            "exact live rootfs mapping description required")
        mount_sha256 = runtime._bind_fixed_runtime_mount(current["runtime"])
        _require(type(mount_sha256) is str and len(mount_sha256) == 64)
        value = {"live_mapping_sha256": lifecycle.live_mapping.sha256,
                 "runtime_mount_sha256": mount_sha256}
        current["execution_mapping"] = value
        return value

    def launch(bridge, lifecycle):
        return runtime._launch_fixed_runtime(state(bridge, lifecycle)["runtime"])

    def observe_runtime_network(bridge, lifecycle):
        """Durably advance ready -> discovered -> runtime after CTR_RUN."""
        current = state(bridge, lifecycle)
        _require(current.get("network_owner") is lifecycle.network_owner
                 and current.get("runtime_network") is None
                 and lifecycle.task is not None, "launched runtime network lineage differs")
        body = network._observe_fixed_runtime_network(
            lifecycle.operation, *current["tools"])
        context = operation._command_context(lifecycle.operation)
        _require(body.get("snapshot_kind") == "runtime"
                 and body.get("operation_token") == context.operation_token
                 and type(body.get("proof_sha256")) is str
                 and len(body["proof_sha256"]) == 64,
                 "exact runtime network snapshot absent")
        current["runtime_network"] = body
        return body

    def prove_runtime(bridge, lifecycle):
        current = state(bridge, lifecycle)
        network_snapshot = current.get("runtime_network")
        _require(network_snapshot is lifecycle.runtime_network,
                 "runtime network observation must precede QMP")
        fact = runtime._observe_fixed_runtime(current["runtime"])
        fact = {**fact, "runtime_network_sha256": network_snapshot["proof_sha256"]}
        qmp = fact["qmp"]
        _require(qmp["kvm_present"] is True and qmp["kvm_enabled"] is True,
                 "QMP KVM proof absent")
        mapping = current.get("execution_mapping")
        _require(mapping is lifecycle.execution_mapping,
                 "runtime observation mapping lineage differs")
        import completion_local_evidence as evidence
        typed = evidence._PlatformOwnerResult(
            operation_token=operation._command_context(lifecycle.operation).operation_token,
            live_mapping_sha256=mapping["live_mapping_sha256"],
            qemu_process_sha256=hashlib.sha256(operation._canonical(fact)).hexdigest(),
            qemu_argv_sha256=qmp["qemu_argv_sha256"],
            qemu_pid=qmp["qemu_pid"], qemu_starttime=qmp["qemu_starttime"],
            qemu_executable_device=qmp["qemu_executable_device"],
            qemu_executable_inode=qmp["qemu_executable_inode"],
            observer_qmp_device=qmp["observer_qmp_device"],
            observer_qmp_inode=qmp["observer_qmp_inode"],
            kvm_device=qmp["kvm_device"], kvm_inode=qmp["kvm_inode"],
            kvm_rdev=qmp["kvm_rdev"], kvm_api=qmp["kvm_api"],
            qmp_present=qmp["kvm_present"], qmp_enabled=qmp["kvm_enabled"])
        lifecycle.operation.record_platform_observation("platform-pass")
        current["runtime_observation"] = typed
        return typed

    def authenticate(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(type(current.get("sensor_before")) is network.CausalSensorSnapshot,
                 "before sensor must immediately precede SSH")
        owner = ssh._compose_production_ssh(
            lifecycle.operation, lifecycle.inputs, lifecycle.executables)
        current["ssh"] = owner
        session = owner.authenticate()
        guest = session.guest_network_proof
        _require(type(guest) is network.GuestNetworkProof,
                 "sealed authenticated guest network proof absent")
        current["network_proof"] = network._prove_causal_guest_network(
            lifecycle.operation, *current["tools"], guest)
        lifecycle.network_proof = current["network_proof"]
        return owner.finalize_authenticated(session)

    def authenticate_readiness(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("runtime_network") is lifecycle.runtime_network
                 and current.get("runtime_observation") is lifecycle.runtime_observation
                 and current.get("sensor_before") is None,
                 "readiness binds runtime snapshot and QMP without causal guest proof")
        owner = ssh._compose_production_readiness_ssh(
            lifecycle.operation, lifecycle.inputs, lifecycle.executables)
        current["ssh"] = owner
        session = owner.authenticate()
        _require(type(session) is ssh.ReadinessAuthenticatedSession)
        return owner.finalize_authenticated(session)

    def revoke(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase == "UNCERTAIN": raise ExecutionBridgeError("uncertain readiness is preserved")
        owner = current.get("ssh")
        if owner is not None: owner.revoke()
        if phase in {"BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY"}:
            return operation._revoke_or_require_terminal(lifecycle.operation)
        return phase

    def ownership(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase != "READINESS_REVOKED": return phase
        fact = runtime._record_fixed_runtime_ownership(ensure_runtime(current, lifecycle))
        if current.get("recovery"):
            return fact
        if current.get("runtime_network") is not None: fact = {**fact, "runtime_network_sha256": current["runtime_network"]["proof_sha256"]}
        mapping = current.get("execution_mapping")
        causal = current.get("network_proof")
        platform = current.get("runtime_observation")
        _require(mapping is lifecycle.execution_mapping
                 and current.get("runtime_network") is lifecycle.runtime_network
                 and causal is lifecycle.network_proof
                 and platform is lifecycle.runtime_observation,
                 "runtime/network/mapping lineage differs")
        qmp = fact["qmp"]
        qemu_sha256 = hashlib.sha256(operation._canonical(fact)).hexdigest()
        import completion_local_evidence as evidence
        _require(type(platform) is evidence._PlatformOwnerResult
                 and platform.live_mapping_sha256 == mapping["live_mapping_sha256"],
                 "pre-workload runtime mapping changed during cleanup")
        identity_fields = (
            "qemu_argv_sha256", "qemu_pid", "qemu_starttime",
            "qemu_executable_device", "qemu_executable_inode",
            "observer_qmp_device", "observer_qmp_inode",
            "kvm_device", "kvm_inode", "kvm_rdev")
        _require(all(getattr(platform, name) == qmp[name]
                     for name in identity_fields),
                 "independent QMP observer identity changed through SSH")
        if causal is None:
            if type(lifecycle.session) is ssh.ReadinessAuthenticatedSession:
                cycle = __import__("completion_cycle_evidence")
                _require(operation._cycle_route(lifecycle.operation)["route"] == "readiness",
                         "readiness route lineage absent")
                lifecycle.runtime_proof = cycle._issue_runtime_readiness_owner_result(
                    operation_token=operation._command_context(lifecycle.operation).operation_token,
                    runtime_mount_record_sha256=mapping["runtime_mount_sha256"],
                    runtime_network_sha256=current["runtime_network"]["proof_sha256"],
                    live_mapping_sha256=mapping["live_mapping_sha256"],
                    qemu_process_sha256=qemu_sha256,
                    qmp_identity=(qmp["qemu_pid"], qmp["qemu_starttime"],
                        qmp["qemu_executable_device"], qmp["qemu_executable_inode"],
                        qmp["observer_qmp_device"], qmp["observer_qmp_inode"],
                        qmp["kvm_device"], qmp["kvm_inode"], qmp["kvm_rdev"],
                        qmp["kvm_api"]))
                return fact
            _require(lifecycle.session is None
                     and operation._durable_phase(lifecycle.operation) == "OWNERSHIP_OBSERVED",
                     "causal network proof absent outside durable terminal cleanup")
            return fact
        lifecycle.runtime_proof = evidence._RuntimeOwnerResult(
            operation_token=operation._command_context(lifecycle.operation).operation_token,
            runtime_mount_record_sha256=mapping["runtime_mount_sha256"],
            network_causal_proof_sha256=causal["causal_proof_sha256"],
            live_mapping_sha256=mapping["live_mapping_sha256"],
            qemu_process_sha256=qemu_sha256,
            qemu_argv_sha256=qmp["qemu_argv_sha256"],
            qemu_pid=qmp["qemu_pid"], qemu_starttime=qmp["qemu_starttime"],
            qemu_executable_device=qmp["qemu_executable_device"],
            qemu_executable_inode=qmp["qemu_executable_inode"],
            observer_qmp_device=qmp["observer_qmp_device"],
            observer_qmp_inode=qmp["observer_qmp_inode"],
            kvm_device=qmp["kvm_device"], kvm_inode=qmp["kvm_inode"],
            kvm_rdev=qmp["kvm_rdev"], kvm_api=qmp["kvm_api"],
            qmp_present=qmp["kvm_present"], qmp_enabled=qmp["kvm_enabled"])
        return fact

    def runtime_cleanup(bridge, lifecycle, source, expected):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase != source: return phase
        result = runtime._cleanup_fixed_runtime(ensure_runtime(current, lifecycle))
        _require(operation._durable_phase(lifecycle.operation) == expected,
                 "runtime cleanup phase differs")
        return result

    def stop_task(bridge, lifecycle):
        current = state(bridge, lifecycle); phase = operation._durable_phase(lifecycle.operation)
        if phase == "OWNERSHIP_OBSERVED":
            rows = lifecycle.operation.runtime_recovery_history()["runtime_ownership"]
            if rows and rows[0]["task"] == "absent": return phase
        return runtime_cleanup(bridge, lifecycle, "OWNERSHIP_OBSERVED", "TASK_STOPPED")
    def remove_task(bridge, lifecycle):
        return runtime_cleanup(bridge, lifecycle, "TASK_STOPPED", "TASK_ABSENT")
    def remove_runtime(bridge, lifecycle):
        phase = operation._durable_phase(lifecycle.operation)
        source = "OWNERSHIP_OBSERVED" if phase == "OWNERSHIP_OBSERVED" else "TASK_ABSENT"
        return runtime_cleanup(bridge, lifecycle, source, "RUNTIME_ABSENT")
    def release_network_holds(bridge, lifecycle):
        current = state(bridge, lifecycle); phase = operation._durable_phase(lifecycle.operation)
        if phase != "RUNTIME_ABSENT": return phase
        owner = ensure_runtime(current, lifecycle)
        result = runtime._release_fixed_runtime_network(owner)
        current["network_owner"] = None; lifecycle.network_owner = None
        return result
    def remove_container(bridge, lifecycle):
        current = state(bridge, lifecycle); phase = operation._durable_phase(lifecycle.operation)
        if phase == "NETWORK_ABSENT" and not lifecycle.operation.runtime_recovery_history()["runtime_ownership"]:
            return phase
        return runtime_cleanup(bridge, lifecycle, "NETWORK_ABSENT", "CONTAINER_ABSENT")
    def remove_share(bridge, lifecycle):
        phase = operation._durable_phase(lifecycle.operation)
        history = lifecycle.operation.runtime_recovery_history()
        resumes = history["runtime_resumes"]
        if (phase == "NETWORK_ABSENT" and not history["runtime_prepared"]
                and not history["runtime_stage_intents"] and not history["runtime_staged"]):
            return runtime._settle_setup_abort_absence(lifecycle.operation, "share")
        if (phase == "NETWORK_ABSENT"
                and any(row["target_phase"] == "RUNTIME_CLEANUP_ONLY" for row in resumes)):
            return runtime._settle_cleanup_only_share_absence(lifecycle.operation)
        source = "NETWORK_ABSENT" if phase == "NETWORK_ABSENT" else "CONTAINER_ABSENT"
        return runtime_cleanup(bridge, lifecycle, source, "SHARE_ABSENT")

    def remove_network(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase == "RUNTIME_CLEANUP_ONLY":
            owner = current.get("runtime")
            if owner is not None:
                runtime._cleanup_fixed_runtime(owner)
                current["runtime"] = None
                lifecycle.staged_runtime = None
                for node in reversed(current.pop("config_nodes", ())):
                    fs._close_node(node)
            _require(not runtime_stage_present(current),
                     "cleanup-only runtime tree remains")
            return network._abort_fixed_setup(lifecycle.operation, *current["tools"])
        if phase == "FS_SETTLED":
            rows = operation._network_records(lifecycle.operation)
            if rows:
                _require(len(rows) == 1 and rows[0]["snapshot_kind"] == "baseline",
                         "pre-settlement baseline snapshot differs")
                operation._settle_network_phase(lifecycle.operation, "BASELINES_CAPTURED")
                return network._abort_fixed_setup(lifecycle.operation, *current["tools"])
            if not (current.get("recovery") and current.get("nft_owner") is None):
                network._abort_incomplete_baseline(lifecycle.operation)
            return lifecycle.operation.record_snapshot_free_cleanup()
        if phase == "BASELINES_CAPTURED":
            return network._abort_fixed_setup(lifecycle.operation, *current["tools"])
        if phase == "RUNTIME_ABSENT":
            history = lifecycle.operation.runtime_recovery_history()
            _require(history["runtime_network_released"], "runtime network release proof absent")
            return network._remove_fixed_network(lifecycle.operation, *current["tools"])
        return phase

    def stop_containerd(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase != "FIREWALL_ABSENT": return phase
        owner = current.get("runtime")
        if owner is not None:
            result = runtime._cleanup_fixed_runtime(owner)
            runtime._close_fixed_runtime(owner)
            current["runtime"] = None
            for node in reversed(current.pop("config_nodes", ())): fs._close_node(node)
            _require(operation._durable_phase(lifecycle.operation) == "CONTAINERD_ABSENT",
                     "containerd absence settlement differs")
            return result
        history = lifecycle.operation.runtime_recovery_history()
        if (not history["runtime_prepared"] and not history["runtime_stage_intents"]
                and not history["runtime_staged"]):
            _require(not runtime_stage_present(current),
                     "setup-abort runtime tree remains")
            return runtime._settle_setup_abort_absence(
                lifecycle.operation, "containerd")
        # A fresh process can arrive after shutdown durably recorded the daemon
        # outcome and removed kata-runtime-v1, after firewall settlement.
        # Reopen only the daemon cleanup identity: no containerd/ctr pathname or
        # complete runtime attestation is required at this phase.
        daemon = runtime._retain_private_containerd(
            lifecycle.operation, fixed_chain(current), None, current["control"])
        runtime._shutdown_private_containerd(daemon)
        fact = {"containerd": "absent"}
        lifecycle.operation.settle_runtime_phase("CONTAINERD_ABSENT", runtime._canonical_fact(fact))
        return fact

    def remove_firewall(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase == "SHARE_ABSENT":
            return network._remove_fixed_firewall(lifecycle.operation, *current["tools"])
        return phase

    def final_baselines(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase == "ROOTFS_ABSENT":
            rows = operation._network_records(lifecycle.operation)
            result = (network._observe_final_network_absence(
                lifecycle.operation, *current["tools"]) if rows else
                network._observe_unstarted_final_absence(
                    lifecycle.operation, *current["tools"]))
        elif phase in {"FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
            rows = operation._network_records(lifecycle.operation)
            _require(rows and rows[-1]["snapshot_kind"] == "final-absent")
            result = rows[-1]
        else:
            return phase
        errors = []
        for executable in reversed(current.pop("tools", ())):
            try: process._release_attested_executable(executable)
            except BaseException as error: errors.append(error)
        chain, current["chain"] = current.get("chain"), None
        if chain is not None:
            try: fs._close_chain(chain)
            except BaseException as error: errors.append(error)
        if not errors and lifecycle.executables is not None:
            try:
                preparation._retire_fixed_executable_owner(
                    lifecycle.static_custody, lifecycle.executables)
                lifecycle.executables = None
            except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("network tool/chain close", errors)
        return result

    def independent_residue(bridge, lifecycle):
        """Fresh post-removal sensors independently cover all 37 report domains."""
        state(bridge, lifecycle)
        import completion_local_evidence as evidence
        import completion_local_full as local
        _require(type(lifecycle.retired) is evidence._RetiredJournalOwnerResult)
        records = operation._parse(lifecycle.retired.raw)
        _require(records[-1].record_type == "RETIRED")
        token = records[0].body["operation_token"]
        final = next(row for row in records if row.record_type == "FINAL_BASELINES")
        phases = {row.record_type for row in records}
        snapshot_free = "SNAPSHOT_FREE_CLEANUP_V1" in phases
        required = {"INPUT_REMOVED", "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRED"}
        if not snapshot_free:
            required |= {"NETWORK_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
                         "CONTAINERD_ABSENT"}
        if "RUNTIME_ROLE_IDENTITIES_V1" in phases:
            required |= {"TASK_STOPPED", "TASK_ABSENT", "RUNTIME_ROLE_ABSENCE_V1",
                         "RUNTIME_ABSENT", "RUNTIME_NETWORK_RELEASED_V1", "CONTAINER_ABSENT"}
        elif "OWNERSHIP_OBSERVED" in phases:
            required |= {"RUNTIME_ABSENT", "RUNTIME_NETWORK_RELEASED_V1", "CONTAINER_ABSENT"}
        _require(required <= phases, "terminal journal domains absent")

        active_snapshots = [row.body for row in records if row.record_type == "NETWORK_SNAPSHOT_V2"
                            and row.body.get("snapshot_kind") in {"ready", "discovered", "runtime"}]
        netns_identity = None if not active_snapshots else active_snapshots[-1]["identity"]["netns"]
        _require(netns_identity is None or type(netns_identity) is dict and
                 type(netns_identity.get("inode")) is int and
                 type(netns_identity.get("inode_device")) is int,
                 "retained operation netns identity malformed")
        net_target = None if netns_identity is None else f"net:[{netns_identity['inode']}]"
        exact_roles = {
            "/opt/kata/bin/containerd-shim-kata-v2": "shim",
            "/opt/kata/bin/qemu-system-x86_64": "qemu",
            "/opt/kata/libexec/virtiofsd": "virtiofsd",
            runtime.STAGED_CONTAINERD: "containerd",
        }
        sandbox_marker = b"cogs-stage2-ssh-v1"
        operation_markers = (b"c42t" + token[:10].encode(), b"kata-runtime-v1",
                             b"completion-v1/rootfs-v1/operation-")
        def proc_pass():
            names = os.listdir("/proc")
            _require(len(names) <= 131_072 and all(type(name) is str for name in names),
                     "complete proc census bound")
            found = {name: set() for name in ("tasks", "containers", "shim", "qemu",
                                              "virtiofsd", "containerd", "children", "netns")}
            for name in sorted((item for item in names if item.isdigit()), key=int):
                pid = int(name); candidate = False
                try: before = process._proc_row(pid)
                except (FileNotFoundError, ProcessLookupError): continue
                try:
                    executable = os.readlink(f"/proc/{pid}/exe")
                    executable = executable.removesuffix(" (deleted)")
                    descriptor = os.open(f"/proc/{pid}/cmdline", os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        command = os.read(descriptor, 262_145)
                        _require(len(command) <= 262_144, "process cmdline bound")
                    finally: os.close(descriptor)
                    role = exact_roles.get(executable)
                    if role is not None: found[role].add(pid); candidate = True
                    if any(marker in command for marker in operation_markers):
                        found["children"].add(pid); candidate = True
                    ns_link = os.readlink(f"/proc/{pid}/ns/net")
                    _require(__import__("re").fullmatch(r"net:\[[1-9][0-9]*\]", ns_link) is not None,
                             "malformed process netns link")
                    if net_target is not None and ns_link == net_target:
                        ns_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                        try:
                            ns_stat = os.fstat(ns_fd)
                            _require((ns_stat.st_dev, ns_stat.st_ino) ==
                                     (netns_identity["inode_device"], netns_identity["inode"]),
                                     "process netns inode/device differs")
                        finally: os.close(ns_fd)
                        found["netns"].add((pid, "ns")); candidate = True
                    fd_names = os.listdir(f"/proc/{pid}/fd")
                    _require(len(fd_names) <= 4096 and all(item.isdigit() for item in fd_names),
                             "process fd census bound")
                    for fd_name in fd_names:
                        try: link = os.readlink(f"/proc/{pid}/fd/{fd_name}")
                        except FileNotFoundError: continue
                        if link.startswith("net:["):
                            _require(__import__("re").fullmatch(r"net:\[[1-9][0-9]*\]", link) is not None,
                                     "malformed nsfs fd link")
                        named_nsfs = link.removesuffix(" (deleted)").startswith("/run/netns/")
                        if net_target is not None and (link == net_target or named_nsfs):
                            held_fd = os.open(f"/proc/{pid}/fd/{fd_name}", os.O_RDONLY | os.O_CLOEXEC)
                            try:
                                held_stat = os.fstat(held_fd)
                                same = ((held_stat.st_dev, held_stat.st_ino) ==
                                        (netns_identity["inode_device"], netns_identity["inode"]))
                                _require(link != net_target or same,
                                         "nsfs descriptor inode/device differs")
                            finally: os.close(held_fd)
                            if same:
                                found["netns"].add((pid, int(fd_name))); candidate = True
                    after = process._proc_row(pid)
                    _require(before == after, "unstable candidate process" if candidate else
                             "unstable process census")
                except (FileNotFoundError, ProcessLookupError):
                    _require(not candidate, "candidate process vanished during census")
                except PermissionError as error:
                    raise ExecutionBridgeError("process census permission uncertainty") from error
            return found
        proc_passes = (proc_pass(), proc_pass())
        process_sets = {name: set().union(*(row[name] for row in proc_passes))
                        for name in proc_passes[0]}
        qmp_absence = runtime._qmp_absent()
        _require(qmp_absence == {"state": "absent", "private_socket": "absent",
                                 "observer_socket": "absent"},
                 "dual QMP residue differs")
        detached_netns_residue = bool(process_sets["netns"])
        interfaces = set(os.listdir("/sys/class/net"))
        link_residue = any(name in interfaces for name in (
            "c42h0", "c42g0", "c42h" + token[:10]))
        netns_names = set(os.listdir("/run/netns")) if os.path.isdir("/run/netns") else set()
        netns_residue = any(name.startswith("c42") for name in netns_names)
        cgroup_residue = False
        for _base, directories, files in os.walk("/sys/fs/cgroup", followlinks=False):
            _require(len(directories) + len(files) <= 100_000,
                     "cgroup observation bound")
            if any("cogs-stage2" in name for name in (*directories, *files)):
                cgroup_residue = True
                break
        mountinfo = Path("/proc/self/mountinfo").read_bytes()
        _require(len(mountinfo) <= 8 * 1024 * 1024, "mount observation bound")
        mount_residue = any(marker in mountinfo for marker in (
            sandbox_marker, runtime.SHARE_ROOT.encode(), b"kata-runtime-v1",
            b"completion-v1/rootfs-v1/operation-"))
        nft_result = subprocess.run(
            ("/usr/sbin/nft", "-j", "list", "ruleset"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
            env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                 "PATH": "/usr/sbin:/usr/bin"})
        _require(nft_result.returncode == 0 and not nft_result.stderr
                 and len(nft_result.stdout) <= 8 * 1024 * 1024,
                 "independent nft observation failed")
        firewall_residue = ("c42t" + token[:10]).encode() in nft_result.stdout
        completion = Path(operation.BASE)
        operation_residue = (completion / "kata-operation-v1" / "operation-v1.jsonl").exists()
        rootfs_residue = any(completion.joinpath("rootfs-v1").glob("operation-*"))
        report_path = Path("/run/cogs-stage2-local-private-v2/report-staging")
        source_path = Path("/run/cogs-stage2-local-private-v2/source-identity")
        input_path = completion / "kata-input-v1"
        runtime_paths = (completion / "kata-runtime-v1", completion / ".kata-runtime-v1.staging",
                         Path(runtime.RUNTIME_ALIAS), Path(runtime.KATA_QMP_SOCKET),
                         Path(runtime.OBSERVER_QMP_SOCKET), Path(runtime.KATA_VM_DIRECTORY))
        share_path = Path(runtime.SHARE_ROOT)
        input_path_residue = input_path.exists() or input_path.is_symlink()
        runtime_path_residue = any(path.exists() or path.is_symlink() for path in runtime_paths)
        task_marker_residue = Path(runtime.CONTAINERD_STATE).exists()
        container_marker_residue = Path(runtime.CONTAINERD_ROOT).exists()
        share_path_residue = share_path.exists() or share_path.is_symlink()
        descriptor_residue = False; descriptor_roles = set()
        for entry in Path("/proc/self/fd").iterdir():
            try:
                target = os.readlink(entry).encode()
                mutable_markers = {
                    "input": b"kata-input-v1", "runtime": b"kata-runtime-v1",
                    "runtime-alias": b"/run/c42d", "sandbox": b"cogs-stage2-ssh",
                    "named-netns": b"/run/netns/c42", "share": runtime.SHARE_ROOT.encode(),
                    "vm": runtime.KATA_VM_DIRECTORY.encode(),
                }
                matched = {name for name, marker in mutable_markers.items() if marker in target}
                if target.decode("utf-8", "surrogateescape") == net_target:
                    matched.add("netns")
                if matched:
                    descriptor_residue = True; descriptor_roles.update(matched)
            except FileNotFoundError:
                pass
        any_process_residue = any(process_sets[name] for name in (
            "shim", "qemu", "virtiofsd", "containerd", "children"))
        namespace_residue = netns_residue or detached_netns_residue
        absent = {
            "tasks": not task_marker_residue, "containers": not container_marker_residue,
            "shim_processes": not process_sets["shim"], "qemu_processes": not process_sets["qemu"],
            "virtiofsd_processes": not process_sets["virtiofsd"],
            "containerd_processes": not process_sets["containerd"],
            "child_processes": not process_sets["children"], "cgroups": not cgroup_residue,
            "namespaces": not namespace_residue, "veth_devices": not link_residue,
            "tap_devices": not link_residue, "traffic_control": not link_residue,
            "firewall": not firewall_residue, "shares": not mount_residue and not share_path_residue,
            "mounts": not mount_residue, "inputs": not input_path_residue,
            "operation_state": not operation_residue,
            "runtime_state": not runtime_path_residue, "runtime_cache": not runtime_path_residue,
            "rootfs_lease": not rootfs_residue, "rootfs_build": not rootfs_residue,
            "rootfs_publication": not rootfs_residue,
            "unexpected_descriptors": not descriptor_residue and not detached_netns_residue,
            "network_state": not link_residue and not namespace_residue,
            "network_routes": not link_residue, "network_addresses": not link_residue,
            "firewall_baseline": not firewall_residue,
            "mount_baseline": not mount_residue, "source_identity": not (source_path.exists() or source_path.is_symlink()),
            "input_control": not input_path_residue, "share_paths": not share_path_residue,
            "runtime_staging": not runtime_path_residue,
            "report_staging": not (report_path.exists() or report_path.is_symlink()),
            "descriptor_baseline": not descriptor_residue and not detached_netns_residue,
            "process_baseline": not any_process_residue,
            "cgroup_baseline": not cgroup_residue,
            "namespace_baseline": not namespace_residue,
        }
        failed = tuple(name for name, value in absent.items() if not value)
        _require(tuple(absent) == local.RESIDUE_FACTS and not failed,
                 "independent 37-domain residue differs:" + ",".join(failed)
                 + "@" + ",".join(sorted(descriptor_roles)))
        return evidence._ResidueOwnerResult(
            token, final.body["final_baselines_sha256"], tuple(absent))

    def issue():
        nonlocal issued
        _require(not issued, "mutable execution bridge already issued")
        issued = True
        value = _Bridge(seal); states[value] = {"lifecycle": None, "chain": None}
        return value

    return (issue, reconstruct, claim_tools, capture, create_network, prove_network, stage,
            bind_mapping, launch, observe_runtime_network, prove_runtime, authenticate,
            authenticate_readiness, revoke, ownership,
            stop_task, remove_task, remove_runtime, release_network_holds, remove_network,
            remove_container, remove_share, remove_firewall, stop_containerd,
            final_baselines, independent_residue)


(_take_execution_bridge, _reconstruct_execution_cleanup,
 _claim_network_tools, _capture_baselines, _create_network,
 _prove_network_causality, _stage_runtime, _bind_execution_mapping, _launch_task,
 _observe_runtime_network, _prove_runtime, _authenticate_ssh,
 _authenticate_readiness_ssh, _revoke_readiness, _observe_ownership,
 _stop_task, _remove_task, _remove_runtime, _release_network_holds, _remove_network,
 _remove_container, _remove_share, _remove_firewall, _stop_containerd,
 _observe_final_baselines, _observe_independent_residue) = _routes()
del _routes

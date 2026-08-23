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
                          "OWNERSHIP_OBSERVED", "TASK_STOPPED", "NETWORK_ABSENT",
                          "TASK_ABSENT", "CONTAINER_ABSENT", "RUNTIME_ABSENT",
                          "SHARE_ABSENT", "FIREWALL_ABSENT", "INPUT_REMOVED",
                          "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
                          "ROOTFS_ABSENT"}
        runtime_phases = {"NETWORK_READY", "RUNTIME_READY", "SSH_READY",
                          "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED",
                          "NETWORK_ABSENT", "TASK_ABSENT", "CONTAINER_ABSENT",
                          "RUNTIME_ABSENT"}
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
        if phase == "FS_SETTLED" and current["nft_owner"] is not None and not rows:
            raise ExecutionBridgeError("incomplete baseline capture is preserved")
        if rows and rows[-1]["snapshot_kind"] in {"ready", "discovered", "runtime"}:
            current["network_owner"] = network._reopen_runtime_network(journal)
            lifecycle.network_owner = current["network_owner"]
        if phase in runtime_phases:
            ensure_runtime(current, lifecycle)
        return phase

    def ensure_runtime(current, lifecycle):
        if current.get("runtime") is not None:
            return current["runtime"]
        _require(lifecycle.rootfs is not None, "durable rootfs cleanup owner absent")
        completion = fixed_chain(current)
        input_owner = inputs._reopen_runtime_inputs(
            lifecycle.operation, completion, current["control"])
        config, config_nodes = open_config(current["control"])
        history = journal.runtime_recovery_history(); prepared_grant = None
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
            operation._command_context(lifecycle.operation).operation_token,
            mapping["live_mapping_sha256"],
            hashlib.sha256(operation._canonical(fact)).hexdigest(),
            12, qmp["kvm_present"], qmp["kvm_enabled"])
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
        if causal is None:
            _require(lifecycle.session is None
                     and operation._durable_phase(lifecycle.operation) == "OWNERSHIP_OBSERVED",
                     "causal network proof absent outside durable terminal cleanup")
            return fact
        lifecycle.runtime_proof = evidence._RuntimeOwnerResult(
            operation._command_context(lifecycle.operation).operation_token,
            mapping["runtime_mount_sha256"], causal["causal_proof_sha256"],
            mapping["live_mapping_sha256"], qemu_sha256, 12,
            qmp["kvm_present"], qmp["kvm_enabled"])
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
        return runtime_cleanup(bridge, lifecycle, "OWNERSHIP_OBSERVED", "TASK_STOPPED")
    def remove_task(bridge, lifecycle):
        return runtime_cleanup(bridge, lifecycle, "NETWORK_ABSENT", "TASK_ABSENT")
    def remove_container(bridge, lifecycle):
        return runtime_cleanup(bridge, lifecycle, "TASK_ABSENT", "CONTAINER_ABSENT")
    def remove_runtime(bridge, lifecycle):
        return runtime_cleanup(bridge, lifecycle, "CONTAINER_ABSENT", "RUNTIME_ABSENT")
    def remove_share(bridge, lifecycle):
        return runtime_cleanup(bridge, lifecycle, "RUNTIME_ABSENT", "SHARE_ABSENT")

    def remove_network(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase == "BASELINES_CAPTURED":
            return network._abort_fixed_setup(lifecycle.operation, *current["tools"])
        if phase in {"TASK_STOPPED", "OWNERSHIP_OBSERVED"}:
            return network._remove_fixed_network(lifecycle.operation, *current["tools"])
        return phase

    def stop_containerd(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(lifecycle.operation)
        if phase != "SHARE_ABSENT": return phase
        owner = current.get("runtime")
        if owner is not None:
            result = runtime._cleanup_fixed_runtime(owner)
            runtime._close_fixed_runtime(owner)
            current["runtime"] = None
            for node in reversed(current.pop("config_nodes", ())): fs._close_node(node)
            return result
        # A fresh process can arrive after shutdown durably recorded the daemon
        # outcome and removed kata-runtime-v1, but before firewall settlement.
        # Reopen only the daemon cleanup identity: no containerd/ctr pathname or
        # complete runtime attestation is required at this phase.
        daemon = runtime._retain_private_containerd(
            lifecycle.operation, fixed_chain(current), None, current["control"])
        runtime._shutdown_private_containerd(daemon)
        return {"containerd": "absent"}

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
        required = {"TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
                    "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT",
                    "FIREWALL_ABSENT", "INPUT_REMOVED", "ROOTFS_ABSENT",
                    "FINAL_BASELINES", "RETIRED"}
        _require(required <= phases, "terminal journal domains absent")

        proc_markers = (b"cogs-stage2-ssh-v1", b"c42t" + token[:10].encode(),
                        b"kata-runtime-v1", b"completion-v1/rootfs-v1/operation-")
        process_residue = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                raw = (entry / "cmdline").read_bytes()[:262_145]
                _require(len(raw) <= 262_144, "process observation bound")
                if any(marker in raw for marker in proc_markers):
                    process_residue = True
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
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
        mount_residue = any(marker in mountinfo for marker in proc_markers)
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
        private_paths = (
            Path("/run/cogs-stage2-ssh"), Path("/run/vc/vm/cogs-stage2-ssh-v1"),
            completion / "kata-input-v1", completion / "kata-runtime-v1",
            completion / ".kata-runtime-v1.staging", report_path, source_path,
        )
        path_residue = any(path.exists() or path.is_symlink() for path in private_paths)
        descriptor_residue = False
        for entry in Path("/proc/self/fd").iterdir():
            try:
                target = os.readlink(entry).encode()
                mutable_markers = (b"kata-input-v1", b"kata-runtime-v1",
                                   b"cogs-stage2-ssh", b"/run/netns/c42")
                if any(marker in target for marker in mutable_markers):
                    descriptor_residue = True
            except FileNotFoundError:
                pass
        absent = {
            "tasks": not process_residue, "containers": not process_residue,
            "shim_processes": not process_residue, "qemu_processes": not process_residue,
            "virtiofsd_processes": not process_residue,
            "containerd_processes": not process_residue,
            "child_processes": not process_residue, "cgroups": not cgroup_residue,
            "namespaces": not netns_residue, "veth_devices": not link_residue,
            "tap_devices": not link_residue, "traffic_control": not link_residue,
            "firewall": not firewall_residue, "shares": not mount_residue,
            "mounts": not mount_residue, "inputs": not path_residue,
            "operation_state": not operation_residue,
            "runtime_state": not path_residue, "runtime_cache": not path_residue,
            "rootfs_lease": not rootfs_residue, "rootfs_build": not rootfs_residue,
            "rootfs_publication": not rootfs_residue,
            "unexpected_descriptors": not descriptor_residue,
            "network_state": not link_residue and not netns_residue,
            "network_routes": not link_residue, "network_addresses": not link_residue,
            "firewall_baseline": not firewall_residue,
            "mount_baseline": not mount_residue, "source_identity": not path_residue,
            "input_control": not path_residue, "share_paths": not path_residue,
            "runtime_staging": not path_residue,
            "report_staging": not (report_path.exists() or report_path.is_symlink()),
            "descriptor_baseline": not descriptor_residue,
            "process_baseline": not process_residue,
            "cgroup_baseline": not cgroup_residue,
            "namespace_baseline": not netns_residue,
        }
        _require(tuple(absent) == local.RESIDUE_FACTS and all(absent.values()),
                 "independent 37-domain residue differs")
        return evidence._ResidueOwnerResult(
            token, final.body["final_baselines_sha256"], tuple(absent))

    def issue():
        nonlocal issued
        _require(not issued, "mutable execution bridge already issued")
        issued = True
        value = _Bridge(seal); states[value] = {"lifecycle": None, "chain": None}
        return value

    return (issue, reconstruct, claim_tools, capture, create_network, prove_network, stage,
            bind_mapping, launch, observe_runtime_network, prove_runtime, authenticate, revoke, ownership,
            stop_task, remove_network, remove_task, remove_container,
            remove_runtime, remove_share, stop_containerd, remove_firewall,
            final_baselines, independent_residue)


(_take_execution_bridge, _reconstruct_execution_cleanup,
 _claim_network_tools, _capture_baselines, _create_network,
 _prove_network_causality, _stage_runtime, _bind_execution_mapping, _launch_task,
 _observe_runtime_network, _prove_runtime, _authenticate_ssh, _revoke_readiness, _observe_ownership,
 _stop_task, _remove_network, _remove_task, _remove_container, _remove_runtime,
 _remove_share, _stop_containerd, _remove_firewall,
 _observe_final_baselines, _observe_independent_residue) = _routes()
del _routes

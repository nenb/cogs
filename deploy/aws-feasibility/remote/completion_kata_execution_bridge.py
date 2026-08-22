"""Narrow network/process/runtime/SSH composition for one fixed Kata lifecycle."""
import hashlib
import os
from pathlib import Path
import subprocess
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
        current["network_owner"] = network._reopen_runtime_network(lifecycle.operation)
        return current["network_owner"]

    def prove_network(bridge, lifecycle):
        """Capture immediately before the sole authenticated SSH command."""
        current = state(bridge, lifecycle)
        _require(current.get("network_owner") is lifecycle.network_owner
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

    def prove_runtime(bridge, lifecycle):
        current = state(bridge, lifecycle)
        fact = runtime._observe_fixed_runtime(current["runtime"])
        qmp = fact["qmp"]
        _require(qmp["kvm_present"] is True and qmp["kvm_enabled"] is True,
                 "QMP KVM proof absent")
        current["runtime_observation"] = fact
        return fact

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
        owner = current.get("ssh")
        if owner is not None: owner.revoke()
        return operation._revoke_or_require_terminal(lifecycle.operation)

    def ownership(bridge, lifecycle):
        current = state(bridge, lifecycle)
        fact = runtime._record_fixed_runtime_ownership(current["runtime"])
        mapping = current.get("execution_mapping")
        causal = current.get("network_proof")
        _require(mapping is lifecycle.execution_mapping
                 and causal is lifecycle.network_proof,
                 "runtime/network/mapping lineage differs")
        qmp = fact["qmp"]
        qemu_sha256 = hashlib.sha256(operation._canonical(fact)).hexdigest()
        import completion_local_evidence as evidence
        lifecycle.runtime_proof = evidence._RuntimeOwnerResult(
            operation._command_context(lifecycle.operation).operation_token,
            mapping["runtime_mount_sha256"], causal["causal_proof_sha256"],
            mapping["live_mapping_sha256"], qemu_sha256, 12,
            qmp["kvm_present"], qmp["kvm_enabled"])
        return fact

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

    return (issue, claim_tools, capture, create_network, prove_network, stage,
            bind_mapping, launch, prove_runtime, authenticate, revoke, ownership,
            stop_task, remove_network, remove_task, remove_container,
            remove_runtime, remove_share, stop_containerd, remove_firewall,
            final_baselines, independent_residue)


(_take_execution_bridge, _claim_network_tools, _capture_baselines, _create_network,
 _prove_network_causality, _stage_runtime, _bind_execution_mapping, _launch_task,
 _prove_runtime, _authenticate_ssh, _revoke_readiness, _observe_ownership,
 _stop_task, _remove_network, _remove_task, _remove_container, _remove_runtime,
 _remove_share, _stop_containerd, _remove_firewall,
 _observe_final_baselines, _observe_independent_residue) = _routes()
del _routes

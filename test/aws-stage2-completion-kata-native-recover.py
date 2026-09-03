#!/usr/bin/env python3
"""Fresh-interpreter recovery half of the root Linux transaction crash gate."""
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

if len(sys.argv) not in {2, 3}:
    raise RuntimeError("exact completion path and optional process identity required")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_operation as operation
import completion_kata_inputs as inputs
import completion_kata_process as process
import completion_rootfs_fs as fs

if os.environ.get("COGS_KATA_COMPACT_INPUT_FIXTURE_V1") == "1":
    inputs._FIXED_FIXTURE = ()

completion = Path(sys.argv[1])
reported = None if len(sys.argv) == 2 else tuple(int(item) for item in sys.argv[2].split(":"))
if reported is not None and len(reported) != 2:
    raise RuntimeError("invalid process identity")

def chain_factory(control):
    anchor = fs._open_root_node(control)
    chain = fs.HeldChain(anchor, ())
    parent = anchor
    try:
        for raw in completion.parts[1:]:
            name = fs._name(raw)
            node = fs._open_path_node(parent, name, "directory", control)
            chain = fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))
            parent = node
        return chain
    except BaseException as error:
        fs._close_chain(chain, error)

attestation_owner = authority = None
retained = []
intent = preexec = None
snapshot_free = os.environ.get("COGS_KATA_SNAPSHOT_FREE_RECOVERY_V1") == "1"
try:
    if os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V3") == "1":
        attestation_owner = process._open_synthetic_attested_executable_owner_v3_for_tests()
    elif os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V1") == "1":
        attestation_owner = process._open_synthetic_attested_executable_owner_for_tests()
    if attestation_owner is not None:
        for role in ("ssh", "ssh-keygen"):
            retained.append(process._claim_attested_executable(attestation_owner, role))
    with patch.object(operation, "_open_base_chain", side_effect=chain_factory):
        if snapshot_free:
            authority = operation._claim_production_recovery_operation(
                operation._open_fixed_operation_recovery())
        else:
            authority = operation._open_fixed_operation()
        if operation._has_recovery_command(authority):
            intent, preexec, _terminal = authority.recovery_command()
            if preexec is not None:
                reported = (preexec["pid"], preexec["proc_start_time"])
        phase = operation._durable_phase(authority)
        if snapshot_free:
            _boot, expired_deadline = operation._recovery_lifecycle_deadline(authority)
            with patch.object(operation, "_boottime_ns", return_value=expired_deadline), \
                 patch.object(process, "_boottime_ns", return_value=expired_deadline):
                if operation._has_recovery_command(authority):
                    process._recover_pending_production(authority)
                authority.record_snapshot_free_cleanup()
                input_path = completion / operation.INPUT_NAME.text
                if input_path.exists():
                    input_path.rmdir()
                authority.record_input_removed("1" * 64)
                authority.prepare_rootfs_release()
                permit = authority.reserve_rootfs_release()
                grant = operation._claim_rootfs_release(permit)
                authorization = operation._invoke_rootfs_release(
                    grant, lambda context: operation.RootfsAuthorization(
                        context.rootfs_token, 9, 0x2222, "e" * 64))
                operation._settle_rootfs_release(grant, authorization)
                authority.settle_rootfs_absent("2" * 64)
                retired = operation._resume_retire_production_operation(
                    authority, {"proof_sha256": "3" * 64})
                removed = operation._remove_retired_operation(authority)
                if removed.raw != retired.raw:
                    raise RuntimeError("snapshot-free retirement changed during removal")
                (completion.parent / "snapshot-free-recovery-result.jsonl").write_bytes(
                    retired.raw)
        elif phase in {"ROOTFS_LEASED", "FS_INTENT", "FS_SETTLED", "RUNTIME_READY", "SSH_READY",
                       "READINESS_REVOKED", "FIREWALL_ABSENT", "UNCERTAIN"}:
            lifecycle_boot, lifecycle_deadline = operation._recovery_lifecycle_deadline(authority)
            if lifecycle_boot != process._boot_id():
                raise RuntimeError("recovery lifecycle boot changed")
            remaining = lifecycle_deadline - process._boottime_ns()
            if remaining <= 0:
                raise RuntimeError("recovery lifecycle deadline expired")
            control = fs.OperationControl(time.monotonic_ns() + remaining, lambda: False)
            chain = chain_factory(control)
            try:
                cleanup = inputs._compose_production_input_cleanup(
                    authority, chain.components[-1].node, control)
                cleanup.continue_cleanup()
            finally: fs._close_chain(chain)
        else: process._recover_pending_production(authority)
finally:
    if authority is not None: authority.close()
    for executable in reversed(retained):
        process._release_attested_executable(executable)
    attestation_owner = None

leaf = None if intent is None else f"{process.CGROUP_BASE}/{intent['operation_token']}-{intent['command_serial']}"
if (leaf is not None and os.path.exists(leaf)) or os.path.exists(process.CGROUP_BASE):
    raise AssertionError("recovery left cgroup residue")
if reported is not None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        observation = process._observe_proc(reported[0])
        if observation.kind is process.ObservationKind.ABSENT:
            break
        if observation.kind is process.ObservationKind.EXACT and observation.row[4] != reported[1]:
            break
        time.sleep(0.005)
    else:
        raise AssertionError("recovery left exact process residue")

#!/usr/bin/env python3
"""Optimization-safe hostile checks for ADR0099 Slice A v2 durability."""
import copy
import hashlib
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_operation as operation
import completion_kata_process as process


def check(value, message):
    if not value:
        raise AssertionError(message)


def reject(call, message="hostile value accepted"):
    try:
        call()
    except BaseException:
        return
    raise AssertionError(message)


def key(inode=10, kind="file"):
    return {"mount_id": 1, "device": 2, "inode": inode, "kind": kind}


def generation(inode=20, kind="directory", mode=0o700):
    return {
        **key(inode, kind), "mode": mode, "uid": 0, "gid": 0,
        "nlink": 2 if kind == "directory" else 1, "size": 0,
        "mtime_ns": 30, "ctime_ns": 31,
    }


def add(raw, kind, body):
    records = operation._parse(raw) if raw else ()
    return raw + operation._encode(kind, body, records)


def prefix():
    token = "a" * 64
    genesis = {
        **operation.FIXED, "operation_token": token, "rootfs_token": "b" * 64,
        "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40, "source_manifest_sha256": "6" * 64,
        "journal_key": key(), "rootfs_pin": operation.ROOTFS_PIN,
        "mount_list_sha256": operation.MOUNT_SHA,
    }
    raw = add(b"", "GENESIS", genesis)
    raw = add(raw, "GENESIS_SETTLED", {
        "operation_token": token, "journal_key": key(), "state_parent": generation(),
    })
    raw = add(raw, "ROOTFS_ACQUIRE_INTENT", {
        "operation_token": token, "rootfs_token": "b" * 64,
        "rootfs_baseline_sha256": "7" * 64,
    })
    return add(raw, "ROOTFS_LEASED", {
        "operation_token": token, "rootfs_token": "b" * 64,
        "rootfs_ledger_key": key(40), "leased_sequence": 8,
        "leased_offset": "0000000000001234", "leased_sha256": "8" * 64,
        "state_generation": generation(41), "operation_generation": generation(42),
        "root_generation": generation(43, mode=0o755), "rootfs_pin": operation.ROOTFS_PIN,
    })


def intent(serial=0, command_id="CTR_TASK_LIST", phase="ROOTFS_LEASED", limits=(16, 16)):
    environment = [list(row) for row in operation.FIXED_ENV]
    if command_id == "CONTAINERD_START":
        role, path = "containerd", "/usr/bin/containerd"
        argv = [path, "--address", "/fixed/socket"]
    else:
        role, path = "ctr", "/usr/bin/ctr"
        argv = [path, "tasks", "list"]
    body = {
        "operation_token": "a" * 64, "command_serial": serial,
        "command_id": command_id, "binding_sha256": operation.ZERO,
        "journal_key": key(), "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40, "lifecycle_phase": phase,
        "executable_role": role, "executable_path": path,
        "executable_sha256": "c" * 64, "executable_generation": generation(90, "file", 0o755),
        "tool_closure_sha256": "d" * 64, "argv": argv,
        "argv_sha256": hashlib.sha256(operation._canonical(argv)).hexdigest(),
        "stdin_hex": "", "stdin_sha256": hashlib.sha256(b"").hexdigest(),
        "stdin_length": 0, "environment": environment,
        "environment_sha256": hashlib.sha256(operation._canonical(environment)).hexdigest(),
        "inherited_fds": [], "deadline_boottime_ns": 9_000_000_000,
        "output_grammar": "text", "stdout_limit": limits[0], "stderr_limit": limits[1],
    }
    binding = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(operation._canonical(binding)).hexdigest()
    return body


def preexec(command):
    return {
        "operation_token": command["operation_token"], "command_serial": command["command_serial"],
        "command_id": command["command_id"], "binding_sha256": command["binding_sha256"],
        "host_boot_id": command["host_boot_id"], "pid": 10, "ppid": 1,
        "pgid": 10, "sid": 10, "proc_start_time": 99, "pidfd_supported": True,
        "cgroup_path": f"{process.CGROUP_BASE}/{command['operation_token']}-{command['command_serial']}",
        "cgroup_generation": generation(91), "exec_status_pipe": generation(92, "pipe", 0o600),
        "release_count": 0,
    }


def outcome(command, stdout=b"", truncated=False, uncertain=False):
    return {
        "operation_token": command["operation_token"], "command_serial": command["command_serial"],
        "command_id": command["command_id"], "binding_sha256": command["binding_sha256"],
        "outcome": "uncertain" if uncertain else "exited", "status": None if uncertain else 0,
        "errno": None, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_length": len(stdout), "stdout_truncated": truncated,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_length": 0,
        "stderr_truncated": False, "leader_reaped": True,
        "descendants_reaped": not uncertain, "cgroup_empty": not uncertain,
        "cgroup_removed": not uncertain, "pipes_eof": True, "release_count": 1,
        "term_attempted": False, "kill_attempted": False,
        "deadline_expired": uncertain, "uncertain": uncertain,
        "errors": ["crash-continuation"] if uncertain else [],
    }


raw = prefix()
command = intent()
with_intent = add(raw, "COMMAND_INTENT_V2", command)
with_preexec = add(with_intent, "COMMAND_PREEXEC_V2", preexec(command))
settled = add(with_preexec, "COMMAND_OUTCOME_V2", outcome(command))
check(operation._legal(operation._parse(settled)) == "ROOTFS_LEASED", "v2 changed lifecycle")
add(settled, "COMMAND_INTENT_V2", intent(1))

# Replay semantics bind genesis, current phase, fd roles, cgroup lineage, limits,
# overflow and wait classification rather than trusting a shared digest header.
for hostile in (
    intent(phase="NETWORK_READY"),
    {**command, "journal_key": key(99)},
    {**command, "inherited_fds": [{
        "role": "CLIENT_KEY", "target_fd": 200, "generation": generation(93, "file", 0o400),
        "content_sha256": "e" * 64, "content_length": 0,
    }]},
):
    reject(lambda hostile=hostile: add(raw, "COMMAND_INTENT_V2", hostile))
bad_preexec = {**preexec(command), "host_boot_id": "22222222-2222-2222-2222-222222222222"}
reject(lambda: add(with_intent, "COMMAND_PREEXEC_V2", bad_preexec))
for hostile_outcome in (
    outcome(command, b"x" * 17),
    {**outcome(command), "outcome": "signaled", "status": 0},
    {**outcome(command), "stdout_truncated": True},
):
    reject(lambda hostile=hostile_outcome: add(with_preexec, "COMMAND_OUTCOME_V2", hostile))
overflow_command = intent(limits=(16, 16))
overflow_prefix = add(add(raw, "COMMAND_INTENT_V2", overflow_command),
                      "COMMAND_PREEXEC_V2", preexec(overflow_command))
add(overflow_prefix, "COMMAND_OUTCOME_V2", outcome(overflow_command, b"x" * 16, True))

# Long-lived containerd settles into a separate retained state; serial 1 short
# commands remain legal, and daemon retirement is independently journaled.
daemon = intent(command_id="CONTAINERD_START")
daemon_raw = add(raw, "COMMAND_INTENT_V2", daemon)
daemon_preexec = preexec(daemon)
daemon_raw = add(daemon_raw, "COMMAND_PREEXEC_V2", daemon_preexec)
retained = {**daemon_preexec, "socket_generation": generation(95, "file", 0o600)}
daemon_raw = add(daemon_raw, "DAEMON_RETAINED_V2", retained)
daemon_raw = add(daemon_raw, "COMMAND_INTENT_V2", intent(1))
check(operation._legal(operation._parse(daemon_raw)) == "ROOTFS_LEASED",
      "retained daemon blocked later command")

# Cleanup-only pending-intent recovery never forks or releases and durably
# consumes the exact serial. Pending PREEXEC is always sticky uncertain.
class RecoveryJournal:
    def __init__(self, pending):
        self.pending = pending
        self.recorded = None
    def pending_command(self):
        return self.pending
    def record_command_outcome(self, body):
        operation._validate_body("COMMAND_OUTCOME_V2", body)
        self.recorded = body
        return body

journal = RecoveryJournal((command, None))
with patch.object(process.os.path, "exists", return_value=False), \
     patch.object(process.os, "fork", side_effect=AssertionError("recovery forked")):
    process._recover_pending_fixed(journal)
check(journal.recorded["outcome"] == "not-started" and not journal.recorded["uncertain"],
      "clean pending intent did not settle")
recovery_preexec = preexec(command)
preexec_journal = RecoveryJournal((command, recovery_preexec))
read_fd, write_fd = __import__("os").pipe()
try:
    with patch.object(process, "_directory_identity", return_value=(read_fd, recovery_preexec["cgroup_generation"])), \
         patch.object(process, "_usable_pidfd_open", return_value=write_fd), \
         patch.object(process, "_kill_cgroup", return_value=None), \
         patch.object(process, "_cgroup_members", return_value=()), \
         patch.object(process.os, "rmdir", return_value=None), \
         patch.object(process.os, "fork", side_effect=AssertionError("recovery forked")):
        process._recover_pending_fixed(preexec_journal)
finally:
    for descriptor in (read_fd, write_fd):
        try: __import__("os").close(descriptor)
        except OSError: pass
check(preexec_journal.recorded["uncertain"] and preexec_journal.recorded["release_count"] == 1,
      "pending preexec recovery was not sticky uncertain")

source = (ROOT / "deploy/aws-feasibility/remote/completion_kata_process.py").read_text()
for forbidden in ("COGS_KATA_PROCESS_TESTING_V1", "def _make_test_issuer(", "def _supervise("):
    check(forbidden not in source, f"deployed test/generic issuer remains: {forbidden}")
check(process.LONG_LIVED_CONTAINERD.command_id is process.CommandId.CONTAINERD_START,
      "containerd was modeled as a short command")
check(process.OWNER_ASSIGNED_IDS == {
    "CTR_RUN", "SSH_KEYGEN_CLIENT", "SSH_KEYGEN_SERVER", "SSH_PUBLIC_CLIENT",
    "SSH_PUBLIC_SERVER", "TC_INGRESS_FILTER", "TC_QDISC",
}, "owner-assigned command set drift")
print("completion Kata Slice A correction matrix passed")

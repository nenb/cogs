#!/usr/bin/env python3
"""Portable hostile tests for v1 preservation and v2 command transactions."""
import copy
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_operation as op


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
    records = op._parse(raw) if raw else ()
    return raw + op._encode(kind, body, records)


def prefix():
    token = "a" * 64
    genesis = {
        **op.FIXED, "operation_token": token, "rootfs_token": "b" * 64,
        "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40, "source_manifest_sha256": "6" * 64,
        "journal_key": key(), "rootfs_pin": op.ROOTFS_PIN,
        "mount_list_sha256": op.MOUNT_SHA,
    }
    raw = add(b"", "GENESIS", genesis)
    raw = add(raw, "GENESIS_SETTLED", {
        "operation_token": token, "journal_key": key(),
        "state_parent": generation(),
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
        "root_generation": generation(43, mode=0o755), "rootfs_pin": op.ROOTFS_PIN,
    })


def intent(serial=0):
    environment = [list(row) for row in op.FIXED_ENV]
    argv = ["/usr/bin/ctr", "--address", "/fixed/socket", "tasks", "list"]
    body = {
        "operation_token": "a" * 64, "command_serial": serial,
        "command_id": "CTR_TASK_LIST", "binding_sha256": "0" * 64,
        "journal_key": key(),
        "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40, "lifecycle_phase": "ROOTFS_LEASED",
        "executable_role": "ctr", "executable_path": "/usr/bin/ctr",
        "executable_sha256": "c" * 64,
        "executable_generation": generation(90, "file", 0o755),
        "tool_closure_sha256": "d" * 64, "argv": argv,
        "argv_sha256": hashlib.sha256(op._canonical(argv)).hexdigest(),
        "stdin_hex": "", "stdin_sha256": hashlib.sha256(b"").hexdigest(),
        "stdin_length": 0, "environment": environment,
        "environment_sha256": hashlib.sha256(op._canonical(environment)).hexdigest(),
        "inherited_fds": [], "deadline_boottime_ns": 9_000_000_000,
        "output_grammar": "text", "stdout_limit": 65536, "stderr_limit": 65536,
    }
    bound = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(op._canonical(bound)).hexdigest()
    return body


def preexec(command):
    return {
        "operation_token": command["operation_token"],
        "command_serial": command["command_serial"], "command_id": command["command_id"],
        "binding_sha256": command["binding_sha256"], "host_boot_id": command["host_boot_id"],
        "pid": 10, "ppid": 1, "pgid": 10, "sid": 10, "proc_start_time": 99,
        "pidfd_supported": True,
        "cgroup_path": "/sys/fs/cgroup/cogs-stage2-completion-v1/a-0",
        "cgroup_generation": generation(91), "exec_status_pipe": generation(92, "file", 0o600),
        "release_count": 0,
    }


def outcome(command, uncertain=False):
    errors = ["descendant-live"] if uncertain else []
    return {
        "operation_token": command["operation_token"],
        "command_serial": command["command_serial"], "command_id": command["command_id"],
        "binding_sha256": command["binding_sha256"],
        "outcome": "uncertain" if uncertain else "exited",
        "status": None if uncertain else 0, "errno": None,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(), "stdout_length": 0,
        "stdout_truncated": False, "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_length": 0, "stderr_truncated": False, "leader_reaped": True,
        "descendants_reaped": not uncertain, "cgroup_empty": not uncertain,
        "cgroup_removed": not uncertain, "pipes_eof": True, "release_count": 1,
        "term_attempted": False, "kill_attempted": False, "deadline_expired": uncertain,
        "uncertain": uncertain, "errors": errors,
    }


# Existing v1 bytes and meanings remain accepted.
raw = prefix()
check(op._legal(op._parse(raw)) == "ROOTFS_LEASED", "v1 prefix changed")

# Exact v2 intent -> preexec -> outcome is one-use and serial-monotonic.
command = intent()
with_intent = add(raw, "COMMAND_INTENT_V2", command)
check(op._legal(op._parse(with_intent)) == "ROOTFS_LEASED", "intent changed lifecycle")
reject(lambda: add(with_intent, "COMMAND_INTENT_V2", intent(1)), "parallel intent accepted")
with_preexec = add(with_intent, "COMMAND_PREEXEC_V2", preexec(command))
settled = add(with_preexec, "COMMAND_OUTCOME_V2", outcome(command))
check(op._legal(op._parse(settled)) == "ROOTFS_LEASED", "settled command changed lifecycle")
next_command = intent(1)
add(settled, "COMMAND_INTENT_V2", next_command)
reject(lambda: add(settled, "COMMAND_INTENT_V2", intent(0)), "serial replay accepted")
reject(lambda: add(with_preexec, "COMMAND_PREEXEC_V2", preexec(command)), "double release accepted")

# Every command binding is exact and covered by binding_sha256.
for field, replacement in (
    ("command_id", "CTR_CONTAINER_LIST"), ("executable_path", "/tmp/ctr"),
    ("argv", ["/usr/bin/ctr", "caller"]), ("stdin_hex", "00"),
    ("environment", [["PATH", "/tmp"]]), ("deadline_boottime_ns", 1),
    ("stdout_limit", 1),
):
    hostile = copy.deepcopy(command)
    hostile[field] = replacement
    reject(lambda hostile=hostile: op._validate_body("COMMAND_INTENT_V2", hostile), field)

# Preexec must bind the same operation/serial/id/digest; no direct success from intent.
hostile_preexec = preexec(command)
hostile_preexec["binding_sha256"] = "e" * 64
reject(lambda: add(with_intent, "COMMAND_PREEXEC_V2", hostile_preexec))
reject(lambda: add(with_intent, "COMMAND_OUTCOME_V2", outcome(command)), "caller success registration accepted")

# Any incomplete descendant/cgroup/pipe settlement is sticky terminal uncertainty.
uncertain_raw = add(with_preexec, "COMMAND_OUTCOME_V2", outcome(command, True))
check(op._legal(op._parse(uncertain_raw)) == "UNCERTAIN", "uncertainty not sticky")
reject(lambda: add(uncertain_raw, "COMMAND_INTENT_V2", intent(1)))
reject(lambda: add(uncertain_raw, "BASELINES_CAPTURED", {
    "operation_token": "a" * 64, "proof_sha256": "f" * 64,
}))

source = (ROOT / "deploy/aws-feasibility/remote/completion_kata_operation.py").read_text()
for forbidden in ("_make_fake_lifecycle_for_tests", "create_fixed_operation_test_local", "seal = object()"):
    check(forbidden not in source, f"deployed test/seal route remains: {forbidden}")
print("completion Kata durable command journal matrix passed")

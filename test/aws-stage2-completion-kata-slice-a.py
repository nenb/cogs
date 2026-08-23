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


def rebound(body):
    body = copy.deepcopy(body)
    body["argv_sha256"] = hashlib.sha256(operation._canonical(body["argv"])).hexdigest()
    binding = {name: body[name] for name in body if name != "binding_sha256"}
    body["binding_sha256"] = hashlib.sha256(operation._canonical(binding)).hexdigest()
    return body


def intent(serial=0, command_id="CTR_TASK_LIST", phase="RUNTIME_READY"):
    environment = [list(row) for row in operation.FIXED_ENV]
    if command_id == "CONTAINERD_START":
        fixed = process.LONG_LIVED_CONTAINERD
        deadline_class, duration, grammar, stdin, inherited = "runtime-start", 60_000_000_000, "empty", b"", []
        stdout_limit = stderr_limit = 65536
    else:
        fixed = process._FIXED_COMMANDS[process.CommandId(command_id)]
        spec = process._spec(fixed.command_id)
        deadline_class, duration, grammar, stdin = spec.deadline_class, fixed.duration_ns, fixed.output_grammar, fixed.stdin
        inherited = []
        stdout_limit, stderr_limit = fixed.stdout_limit, fixed.stderr_limit
        if fixed.inherited_fds:
            inherited = [
                {"role": "CLIENT_KEY", "target_fd": 200, "generation": generation(93, "file", 0o400),
                 "content_sha256": "e" * 64, "content_length": 3},
                {"role": "KNOWN_HOSTS", "target_fd": 201, "generation": generation(94, "file", 0o400),
                 "content_sha256": "f" * 64, "content_length": 5},
            ]
    argv = [item.replace("{operation_token}", "a" * 64) for item in fixed.argv]
    body = {
        "operation_token": "a" * 64, "command_serial": serial,
        "command_id": command_id, "binding_sha256": operation.ZERO,
        "journal_key": key(), "host_boot_id": "11111111-1111-1111-1111-111111111111",
        "source_revision": "5" * 40, "lifecycle_phase": phase,
        "executable_role": fixed.executable_role, "executable_path": fixed.executable_path,
        "executable_sha256": "c" * 64, "executable_generation": generation(90, "file", 0o755),
        "tool_closure_sha256": "d" * 64, "argv": argv,
        "argv_sha256": hashlib.sha256(operation._canonical(argv)).hexdigest(),
        "stdin_hex": stdin.hex(), "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
        "stdin_length": len(stdin), "environment": environment,
        "environment_sha256": hashlib.sha256(operation._canonical(environment)).hexdigest(),
        "inherited_fds": inherited, "policy_version": operation.command_policy.POLICY_VERSION,
        "deadline_class": deadline_class, "duration_ns": duration,
        "cleanup_reserve_ns": (operation.command_policy.SSH_CLEANUP_RESERVE_NS
                               if command_id == "SSH_READY" else
                               operation.command_policy.CLEANUP_RESERVE_NS),
        "deadline_boottime_ns": 99_000_000_000, "output_grammar": grammar,
        "stdout_limit": stdout_limit, "stderr_limit": stderr_limit,
    }
    return rebound(body)


def preexec(command):
    return {
        "operation_token": command["operation_token"], "command_serial": command["command_serial"],
        "command_id": command["command_id"], "binding_sha256": command["binding_sha256"],
        "host_boot_id": command["host_boot_id"], "pid": 10, "ppid": 1,
        "pgid": 10, "sid": 10, "proc_start_time": 99, "pidfd_supported": True,
        "cgroup_path": f"{process.CGROUP_BASE}/{command['operation_token']}-{command['command_serial']}",
        "cgroup_generation": generation(91),
        "executable_sha256": command["executable_sha256"],
        "tool_closure_sha256": command["tool_closure_sha256"],
        "executable_generation": command["executable_generation"],
        "exec_status_pipe": generation(92, "pipe", 0o600),
        "release_count": 0,
    }


def outcome(command, stdout=b"", truncated=False, uncertain=False, status=0):
    return {
        "operation_token": command["operation_token"], "command_serial": command["command_serial"],
        "command_id": command["command_id"], "binding_sha256": command["binding_sha256"],
        "outcome": "uncertain" if uncertain else "exited", "status": None if uncertain else status,
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


def legacy_intent(serial, command_id):
    return {"operation_token": "a" * 64, "command_serial": serial,
            "command_id": command_id, "binding_sha256": "c" * 64,
            "deadline_class": "network"}


def legacy_not_started(command):
    return {**command, "outcome": "not_started", "status": None, "errno": None,
            "stdout_sha256": operation.ZERO, "stdout_length": 0, "stdout_truncated": False,
            "stderr_sha256": operation.ZERO, "stderr_length": 0, "stderr_truncated": False,
            "wait_result": "not_waited", "reap_result": "not_child"}


raw = add(prefix(), "BASELINES_CAPTURED",
          {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
command = intent(command_id="IP_NETNS_ADD", phase="BASELINES_CAPTURED")
with_intent = add(raw, "COMMAND_INTENT_V2", command)
with_preexec = add(with_intent, "COMMAND_PREEXEC_V2", preexec(command))
settled = add(with_preexec, "COMMAND_OUTCOME_V2", outcome(command))
check(operation._legal(operation._parse(settled)) == "BASELINES_CAPTURED", "v2 changed lifecycle")
reject(lambda: add(settled, "NETWORK_READY",
                   {"operation_token": "a" * 64, "proof_sha256": "9" * 64}))
reject(lambda: add(settled, "COMMAND_INTENT_V2",
                   intent(1, "IP_NETNS_ADD", "BASELINES_CAPTURED")))
# The first intent permanently selects one command record generation. Same-ID
# and different-ID mixing both reject in either direction.
for command_id in ("IP_NETNS_ADD", "IP_LINK_ADD"):
    reject(lambda command_id=command_id: add(
        settled, "COMMAND_INTENT", legacy_intent(1, command_id)))
legacy = legacy_intent(0, "IP_NETNS_ADD")
legacy_settled = add(add(raw, "COMMAND_INTENT", legacy),
                     "COMMAND_OUTCOME", legacy_not_started(legacy))
for command_id in ("IP_NETNS_ADD", "IP_LINK_ADD"):
    reject(lambda command_id=command_id: add(
        legacy_settled, "COMMAND_INTENT_V2", intent(1, command_id, "BASELINES_CAPTURED")))
failed = add(add(add(raw, "COMMAND_INTENT_V2", command), "COMMAND_PREEXEC_V2", preexec(command)),
             "COMMAND_OUTCOME_V2", outcome(command, status=7))
reject(lambda: add(failed, "NETWORK_READY",
                   {"operation_token": "a" * 64, "proof_sha256": "9" * 64}))
reject(lambda: add(failed, "READINESS_REVOKED", {"operation_token": "a" * 64}))
# Slice A never infers network/runtime/SSH cleanup from generic lifecycle proofs.

# Replay semantics bind genesis, current phase, fd roles, cgroup lineage, limits,
# overflow and wait classification rather than trusting a shared digest header.
for hostile_index, hostile in enumerate((
    rebound({**command, "argv": ["/usr/bin/ctr", "--address", "/attacker.sock", "tasks", "kill"]}),
    rebound({**command, "deadline_class": "remove"}),
    rebound({**command, "duration_ns": 1}),
    rebound({**command, "output_grammar": "text"}),
    {**command, "journal_key": key(99)},
    rebound({**command, "inherited_fds": [{
        "role": "CLIENT_KEY", "target_fd": 200, "generation": generation(93, "file", 0o400),
        "content_sha256": "e" * 64, "content_length": 0,
    }]}),
)):
    reject(lambda hostile=hostile: add(raw, "COMMAND_INTENT_V2", hostile),
           f"hostile binding accepted: {hostile_index}")
bad_preexec = {**preexec(command), "host_boot_id": "22222222-2222-2222-2222-222222222222"}
reject(lambda: add(with_intent, "COMMAND_PREEXEC_V2", bad_preexec))
for hostile_outcome in (
    outcome(command, b"x" * 65537),
    {**outcome(command), "outcome": "signaled", "status": 0},
    {**outcome(command), "stdout_truncated": True},
):
    reject(lambda hostile=hostile_outcome: add(with_preexec, "COMMAND_OUTCOME_V2", hostile))
overflow_command = intent(command_id="IP_NETNS_ADD", phase="BASELINES_CAPTURED")
overflow_prefix = add(add(raw, "COMMAND_INTENT_V2", overflow_command),
                      "COMMAND_PREEXEC_V2", preexec(overflow_command))
add(overflow_prefix, "COMMAND_OUTCOME_V2", outcome(overflow_command, b"x" * 65536, True))

# Long-lived containerd settles into a separate retained state; serial 1 short
# commands remain legal, and daemon retirement is independently journaled.
daemon_prefix = add(prefix(), "BASELINES_CAPTURED",
                    {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
daemon_serial = 0
daemon = intent(daemon_serial, "CONTAINERD_START", "BASELINES_CAPTURED")
daemon_raw = add(daemon_prefix, "COMMAND_INTENT_V2", daemon)
daemon_preexec = preexec(daemon)
daemon_raw = add(daemon_raw, "COMMAND_PREEXEC_V2", daemon_preexec)
retained = {**daemon_preexec, "socket_generations": {
    "s": {"generation": generation(95, "socket", 0o600), "fd_inode": 195},
    "s.ttrpc": {"generation": generation(96, "socket", 0o600), "fd_inode": 196}}}
reject(lambda: operation._key(key(95, "socket")))
operation._daemon_socket_generations(retained["socket_generations"])
reject(lambda: add(daemon_raw, "DAEMON_RETAINED_V2", {**retained, "socket_generations": {"s": retained["socket_generations"]["s"]}}))
nonroot = copy.deepcopy(retained); nonroot["socket_generations"]["s.ttrpc"]["generation"]["uid"] = 1
reject(lambda: add(daemon_raw, "DAEMON_RETAINED_V2", nonroot))
bad_fd = copy.deepcopy(retained); bad_fd["socket_generations"]["s"]["fd_inode"] = 0
reject(lambda: add(daemon_raw, "DAEMON_RETAINED_V2", bad_fd))
duplicate = copy.deepcopy(retained); duplicate["socket_generations"]["s.ttrpc"] = copy.deepcopy(duplicate["socket_generations"]["s"])
reject(lambda: add(daemon_raw, "DAEMON_RETAINED_V2", duplicate))
daemon_raw = add(daemon_raw, "DAEMON_RETAINED_V2", retained)
retained_raw = daemon_raw
daemon_raw = add(daemon_raw, "COMMAND_INTENT_V2",
                 intent(daemon_serial + 1, "CTR_CONTAINER_INFO", "BASELINES_CAPTURED"))
check(operation._legal(operation._parse(daemon_raw)) == "BASELINES_CAPTURED",
      "retained daemon blocked later command")

# A retained daemon cannot use legacy v1 or cross runtime absence/finalization;
# its authentic endpoint generation is a Unix socket.
legacy_daemon = {"operation_token": "a" * 64, "command_serial": 0,
                 "command_id": "CONTAINERD_START", "binding_sha256": "9" * 64,
                 "deadline_class": "runtime-start"}
reject(lambda: add(prefix(), "COMMAND_INTENT", legacy_daemon))
reject(lambda: add(retained_raw, "RUNTIME_READY",
                   {"operation_token": "a" * 64, "proof_sha256": "9" * 64}))
daemon_outcome = {"operation_token": "a" * 64, "command_serial": daemon_serial,
    "command_id": "CONTAINERD_START", "binding_sha256": daemon["binding_sha256"],
    "pid": daemon_preexec["pid"], "proc_start_time": daemon_preexec["proc_start_time"],
    "status": 0, "leader_reaped": True, "descendants_reaped": True,
    "cgroup_empty": True, "cgroup_removed": True, "uncertain": False, "errors": []}
reject(lambda: add(legacy_settled, "DAEMON_OUTCOME_V2", daemon_outcome))
early_daemon = add(retained_raw, "DAEMON_OUTCOME_V2", daemon_outcome)
check(operation._legal(operation._parse(early_daemon)) == "UNCERTAIN",
      "early daemon exit was not terminal")
reject(lambda: add(early_daemon, "RUNTIME_READY", {"operation_token": "a" * 64,
                                                    "proof_sha256": "9" * 64}))
uncertain_daemon = {**daemon_outcome, "status": None, "leader_reaped": False,
    "descendants_reaped": False, "cgroup_empty": False, "cgroup_removed": False,
    "uncertain": True, "errors": ["daemon-cleanup-pending"]}
uncertain_daemon_raw = add(retained_raw, "DAEMON_OUTCOME_V2", uncertain_daemon)
check(operation._legal(operation._parse(uncertain_daemon_raw)) == "UNCERTAIN",
      "daemon residue did not remain terminal uncertain")
# The exact command policy rejects foreign owner IDs, wrong lifecycle, repeats,
# and impossible output on a command which was never released.
reject(lambda: add(raw, "COMMAND_INTENT_V2", intent(command_id="CTR_TASK_TERM")))
unsupported = copy.deepcopy(command); unsupported["command_id"] = "CTR_RUN"
unsupported = rebound(unsupported)
reject(lambda: add(raw, "COMMAND_INTENT_V2", unsupported))
mixed = prefix()
for kind in ("BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY"):
    mixed = add(mixed, kind, {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
reject(lambda: add(mixed, "COMMAND_INTENT_V2", intent(command_id="SSH_READY")))
# SSH/key policies remain blocked until exact attested executable identities
# are committed; self-described executable hashes/generations cannot issue.
ssh_intent = intent(command_id="SSH_READY")
reject(lambda: add(raw, "COMMAND_INTENT_V2", ssh_intent))
check(not operation.command_policy.ATTESTED_EXECUTABLES, "unattested SSH policy enabled")

not_started_output = outcome(command, b"x")
not_started_output.update({"outcome": "not-started", "status": None, "release_count": 0})
reject(lambda: operation._validate_body("COMMAND_OUTCOME_V2", not_started_output))

# Independent process-only policy oracle: exact IDs, one baseline occurrence, no lifecycle policy.
policy = operation.command_policy
EXPECTED_IMPLEMENTED = {
    "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_CONTAINER_REMOVE", "CTR_TASK_KILL",
    "CTR_TASK_LIST", "CTR_TASK_REMOVE", "CTR_TASK_TERM", "IP_GUEST_ADDRESS_ADD",
    "IP_GUEST_LINK_UP", "IP_HOST_ADDRESSES", "IP_HOST_ADDRESS_ADD", "IP_HOST_LINKS",
    "IP_HOST_LINK_UP", "IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_LINK_ADD",
    "IP_LINK_MOVE", "IP_LOOPBACK_UP", "IP_NETNS_ADD", "IP_NETNS_REMOVE",
    "IP_NS_ADDRESSES", "IP_NS_LINKS", "IP_NS_ROUTES4", "IP_NS_ROUTES6",
    "IP_PEER_ADDRGEN_NONE", "IP_PEER_RENAME", "NFT_INSTALL", "NFT_REMOVE",
    "NFT_TABLE", "SSH_READY", "SSH_KEYGEN_CLIENT", "SSH_PUBLIC_CLIENT",
    "SSH_KEYGEN_SERVER", "SSH_PUBLIC_SERVER", "CONTAINERD_START",
}
check(policy.POLICY_VERSION == "cogs.stage2-kata-command-policy/v4-process-only-ssh-stable-1",      "process-only policy version drift")
check(set(policy.POLICY_SHA256) == EXPECTED_IMPLEMENTED, "implemented process policy drift")
expected_occurrences = {name: (("ROOTFS_LEASED",) if name in policy.KEY_COMMANDS else
                               ("RUNTIME_READY",) if name == "SSH_READY" else
                               ("BASELINES_CAPTURED",)) for name in policy.POLICY_SHA256}
check(dict(policy.OCCURRENCES) == expected_occurrences
      and dict(policy.PHASES) == dict(policy.OCCURRENCES)
      and all(value == 1 for value in policy.MAX_OCCURRENCES.values()),
      "transaction occurrence policy drift")
check(not hasattr(policy, "PHASE_COMMAND_TRACES") and not hasattr(policy, "LIFECYCLE_REQUIREMENTS"),
      "generic lifecycle/resource inference remains in Slice A")
for mapping in (policy.POLICY_SHA256, policy.OCCURRENCES, policy.PHASES,
                policy.MAX_OCCURRENCES):
    reject(lambda mapping=mapping: mapping.__setitem__("CTR_TASK_LIST", ("RUNTIME_READY",)))
original_policy = policy.POLICY_SHA256
try:
    policy.POLICY_SHA256 = dict(original_policy)
    reject(lambda: operation._v2_lineage(operation._parse(raw)[0].body,
                                         "RUNTIME_READY", command))
finally:
    policy.POLICY_SHA256 = original_policy
check(set(policy.POLICY_SHA256) == set(policy.OCCURRENCES) == set(policy.PHASES)
      == set(policy.MAX_OCCURRENCES), "policy map key drift")
partitions = (set(policy.POLICY_SHA256), set(policy.DEFERRED_COMMANDS), set(policy.B1_COMMAND_IDS))
check(not any(left & right for index, left in enumerate(partitions) for right in partitions[index + 1:])
      and set().union(*partitions) == set(operation.COMMANDS),
      "policy/deferred/B1 partition drift")
for command_id in policy.POLICY_SHA256:
    phase = policy.OCCURRENCES[command_id][0]
    regenerated = intent(command_id=command_id, phase=phase)
    check(operation._v2_policy_digest(regenerated) == policy.POLICY_SHA256[command_id],
          f"stale policy digest: {command_id}")
reject(lambda: add(raw, "COMMAND_INTENT_V2",
                   rebound({**command, "policy_version": "future-policy"})))

# Slice A binds exact transactions but does not guess network command ordering.
setup_raw = add(prefix(), "BASELINES_CAPTURED",
                {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
add(setup_raw, "COMMAND_INTENT_V2",
    intent(command_id="IP_LINK_ADD", phase="BASELINES_CAPTURED"))

# Production recovery accepts only the sealed real operation authority; duck
# journals cannot exercise or rewrite cleanup state.
reject(lambda: process._recover_pending_fixed(object()))
recovery_preexec = preexec(command)

class TerminalRecoveryJournal:
    def __init__(self, values): self.recorded, self.values = False, values
    def recovery_command(self): return self.values
    def record_command_outcome(self, _body):
        self.recorded = True
        raise AssertionError("terminal uncertainty was rewritten")
terminal_journal = TerminalRecoveryJournal(
    (command, recovery_preexec, outcome(command, uncertain=True)))
with patch.object(process, "_recover_cgroup", return_value=(True, True)):
    terminal_result = process._recover_pending_fixed(terminal_journal)
check(terminal_result.body["uncertain"] and not terminal_journal.recorded,
      "terminal-uncertain cleanup changed durable uncertainty")
daemon_journal = TerminalRecoveryJournal((daemon, daemon_preexec, uncertain_daemon))
with patch.object(process, "_recover_cgroup", return_value=(True, True)) as daemon_recover, \
     patch.object(process.os, "waitpid", side_effect=[(daemon_preexec["pid"], 0), ChildProcessError()]) as daemon_wait:
    daemon_result = process._recover_pending_fixed(daemon_journal)
check(daemon_result.body is uncertain_daemon and not daemon_journal.recorded
      and daemon_recover.call_args.args[1] == process._generation_tuple(daemon_preexec["cgroup_generation"])
      and daemon_wait.call_count == 2, "daemon residue lost cgroup/reap cleanup continuation")
with patch.object(process, "_recover_cgroup", return_value=(True, True)), \
     patch.object(process.os, "waitpid", side_effect=ChildProcessError()), \
     patch.object(process, "_observe_proc", return_value=process.RecoveryObservation(process.ObservationKind.ABSENT)) as absent:
    process._recover_pending_fixed(daemon_journal)
check(absent.called, "ECHILD daemon recovery did not poll exact proc absence")
check(not process._cleanup_closed((False, False, False, False), 10, None),

      "owned residue was considered terminally closed")

# Recovery kills and polls the deterministic leaf without consulting the dead
# leader. A wait-wide census, not cgroup emptiness, proves descendant reaping.
base_fd = __import__("os").open("/dev/null", __import__("os").O_RDONLY)
leaf_fd = __import__("os").open("/dev/null", __import__("os").O_RDONLY)
state, errors = {"term": False, "kill": False}, []
with patch.object(process, "_directory_identity", side_effect=[
        (base_fd, generation(80)), (leaf_fd, recovery_preexec["cgroup_generation"])]), \
     patch.object(process, "_kill_cgroup") as killed, \
     patch.object(process, "_cgroup_members", side_effect=[(777,), (), ()]), \
     patch.object(process.os, "rmdir"):
    check(process._recover_cgroup(recovery_preexec["cgroup_path"],
          process._generation_tuple(recovery_preexec["cgroup_generation"]),
          process._boottime_ns() + 1_000_000_000, state, errors) == (True, True),
          "bounded cgroup recovery did not remove the leaf")
check(killed.call_count == 2 and state["kill"] and not errors,
      "leader-absent recovery did not use cgroup kill")
with patch.object(process.os, "waitpid", return_value=(0, 0)):
    check(process._wait_all_children(10, [])[1] is False,
          "live wait-wide child was inferred reaped from cgroup state")
with patch.object(process.os, "waitpid", side_effect=[(777, 0), ChildProcessError()]):
    check(process._wait_all_children(10, [])[1] is True,
          "wait-wide zombie census did not establish the narrow reap fact")
uncertain_restore = process._outcome_body(
    command, "exited", 0, None, b"", b"", {"stdout": False, "stderr": False}, 0,
    True, (True, True, True, True), {"term": False, "kill": False},
    ["subreaper-restore:OSError"], 1)
check(uncertain_restore["uncertain"] and uncertain_restore["outcome"] == "uncertain",
      "subreaper restoration failure settled a certain outcome")

source = (ROOT / "deploy/aws-feasibility/remote/completion_kata_process.py").read_text()
for forbidden in ("COGS_KATA_PROCESS_TESTING_V1", "def _make_test_issuer(", "def _supervise("):
    check(forbidden not in source, f"deployed test/generic issuer remains: {forbidden}")
check(source.index("_set_subreaper(previous_subreaper)") < source.index("_record_command_outcome(journal, body)"),
      "subreaper restoration occurs after durable settlement")
check("work_cutoff = deadline - _cleanup_reserve_ns(fixed)" in source
      and "fixed.stdin, owner, work_cutoff" in source
      and "_settle_cgroup(owner, pid, deadline" in source,
      "one final deadline did not reserve cleanup before work")
check(source.index("if not _cleanup_closed(cleanup, pid, wait_status)") <
      source.index("durable = kata_operation._record_command_outcome"),
      "terminal outcome can precede residue closure")
check(process.LONG_LIVED_CONTAINERD.command_id is process.CommandId.CONTAINERD_START,
      "containerd was modeled as a short command")
check(process.OWNER_ASSIGNED_IDS == {"CTR_RUN"},
      "owner-assigned command set drift")
print("completion Kata Slice A correction matrix passed")

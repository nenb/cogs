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
    else:
        fixed = process._FIXED_COMMANDS[process.CommandId(command_id)]
        spec = process._spec(fixed.command_id)
        deadline_class, duration, grammar, stdin = spec.deadline_class, fixed.duration_ns, fixed.output_grammar, fixed.stdin
        inherited = []
        if fixed.inherited_fds:
            inherited = [
                {"role": "CLIENT_KEY", "target_fd": 200, "generation": generation(93, "file", 0o400),
                 "content_sha256": "e" * 64, "content_length": 3},
                {"role": "KNOWN_HOSTS", "target_fd": 201, "generation": generation(94, "file", 0o400),
                 "content_sha256": "f" * 64, "content_length": 5},
            ]
    argv = list(fixed.argv)
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
        "cleanup_reserve_ns": operation.command_policy.CLEANUP_RESERVE_NS,
        "deadline_boottime_ns": 99_000_000_000, "output_grammar": grammar,
        "stdout_limit": 65536, "stderr_limit": 65536,
    }
    return rebound(body)


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
for kind in ("BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY"):
    raw = add(raw, kind, {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
command = intent()
with_intent = add(raw, "COMMAND_INTENT_V2", command)
with_preexec = add(with_intent, "COMMAND_PREEXEC_V2", preexec(command))
settled = add(with_preexec, "COMMAND_OUTCOME_V2", outcome(command))
check(operation._legal(operation._parse(settled)) == "RUNTIME_READY", "v2 changed lifecycle")
reject(lambda: add(settled, "COMMAND_INTENT_V2", intent(1)))

# Replay semantics bind genesis, current phase, fd roles, cgroup lineage, limits,
# overflow and wait classification rather than trusting a shared digest header.
for hostile in (
    rebound({**command, "argv": ["/usr/bin/ctr", "--address", "/attacker.sock", "tasks", "kill"]}),
    rebound({**command, "deadline_class": "remove"}),
    rebound({**command, "duration_ns": 1}),
    rebound({**command, "output_grammar": "json"}),
    {**command, "journal_key": key(99)},
    rebound({**command, "inherited_fds": [{
        "role": "CLIENT_KEY", "target_fd": 200, "generation": generation(93, "file", 0o400),
        "content_sha256": "e" * 64, "content_length": 0,
    }]}),
):
    reject(lambda hostile=hostile: add(raw, "COMMAND_INTENT_V2", hostile))
bad_preexec = {**preexec(command), "host_boot_id": "22222222-2222-2222-2222-222222222222"}
reject(lambda: add(with_intent, "COMMAND_PREEXEC_V2", bad_preexec))
for hostile_outcome in (
    outcome(command, b"x" * 65537),
    {**outcome(command), "outcome": "signaled", "status": 0},
    {**outcome(command), "stdout_truncated": True},
):
    reject(lambda hostile=hostile_outcome: add(with_preexec, "COMMAND_OUTCOME_V2", hostile))
overflow_command = intent()
overflow_prefix = add(add(raw, "COMMAND_INTENT_V2", overflow_command),
                      "COMMAND_PREEXEC_V2", preexec(overflow_command))
add(overflow_prefix, "COMMAND_OUTCOME_V2", outcome(overflow_command, b"x" * 65536, True))

# Long-lived containerd settles into a separate retained state; serial 1 short
# commands remain legal, and daemon retirement is independently journaled.
daemon_prefix = prefix()
for kind in ("BASELINES_CAPTURED", "NETWORK_READY"):
    daemon_prefix = add(daemon_prefix, kind, {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
daemon = intent(command_id="CONTAINERD_START", phase="NETWORK_READY")
daemon_raw = add(daemon_prefix, "COMMAND_INTENT_V2", daemon)
daemon_preexec = preexec(daemon)
daemon_raw = add(daemon_raw, "COMMAND_PREEXEC_V2", daemon_preexec)
retained = {**daemon_preexec, "socket_generation": generation(95, "socket", 0o600)}
reject(lambda: operation._key(key(95, "socket")))
operation._daemon_socket_generation(retained["socket_generation"])
daemon_raw = add(daemon_raw, "DAEMON_RETAINED_V2", retained)
retained_raw = daemon_raw
daemon_raw = add(daemon_raw, "COMMAND_INTENT_V2", intent(1, "CTR_CONTAINER_INFO", "NETWORK_READY"))
check(operation._legal(operation._parse(daemon_raw)) == "NETWORK_READY",
      "retained daemon blocked later command")

# A retained daemon cannot use legacy v1 or cross runtime absence/finalization;
# its authentic endpoint generation is a Unix socket.
legacy_daemon = {"operation_token": "a" * 64, "command_serial": 0,
                 "command_id": "CONTAINERD_START", "binding_sha256": "9" * 64,
                 "deadline_class": "runtime-start"}
reject(lambda: add(prefix(), "COMMAND_INTENT", legacy_daemon))
progress = add(retained_raw, "RUNTIME_READY", {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
progress = add(progress, "SSH_READY", {"operation_token": "a" * 64, "proof_sha256": "9" * 64,
    "marker_sha256": hashlib.sha256(operation.FIXED["ssh_marker"].encode()).hexdigest(),
    "authentication_attempts": 1})
progress = add(progress, "READINESS_REVOKED", {"operation_token": "a" * 64})
progress = add(progress, "OWNERSHIP_OBSERVED", {"operation_token": "a" * 64,
    "proof_sha256": "9" * 64, "task": "absent", "container": "exact-owned",
    "runtime": "exact-owned", "share": "exact-owned"})
for kind in ("NETWORK_ABSENT", "TASK_ABSENT", "CONTAINER_ABSENT",
             "RUNTIME_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT"):
    progress = add(progress, kind, {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
reject(lambda: add(progress, "INPUT_REMOVED", {"operation_token": "a" * 64,
                                                "proof_sha256": "9" * 64}))
daemon_outcome = {"operation_token": "a" * 64, "command_serial": 0,
    "command_id": "CONTAINERD_START", "binding_sha256": daemon["binding_sha256"],
    "pid": daemon_preexec["pid"], "proc_start_time": daemon_preexec["proc_start_time"],
    "status": 0, "leader_reaped": True, "descendants_reaped": True,
    "cgroup_empty": True, "cgroup_removed": True, "uncertain": False, "errors": []}
early_daemon = add(retained_raw, "DAEMON_OUTCOME_V2", daemon_outcome)
check(operation._legal(operation._parse(early_daemon)) == "UNCERTAIN",
      "early daemon exit was not terminal")
reject(lambda: add(early_daemon, "RUNTIME_READY", {"operation_token": "a" * 64,
                                                    "proof_sha256": "9" * 64}))
closed_daemon = add(progress, "DAEMON_OUTCOME_V2", daemon_outcome)
closed_daemon = add(closed_daemon, "INPUT_REMOVED", {"operation_token": "a" * 64,
                                                      "proof_sha256": "9" * 64})
# The exact command policy rejects foreign owner IDs, wrong lifecycle, repeats,
# and impossible output on a command which was never released.
reject(lambda: add(raw, "COMMAND_INTENT_V2", intent(command_id="CTR_TASK_TERM")))
unsupported = copy.deepcopy(command); unsupported["command_id"] = "CTR_RUN"
unsupported = rebound(unsupported)
reject(lambda: add(raw, "COMMAND_INTENT_V2", unsupported))
ssh_intent = intent(command_id="SSH_READY")
ssh_done = add(add(add(raw, "COMMAND_INTENT_V2", ssh_intent), "COMMAND_PREEXEC_V2", preexec(ssh_intent)),
               "COMMAND_OUTCOME_V2", outcome(ssh_intent, operation.FIXED["ssh_marker"].encode()))
reject(lambda: add(ssh_done, "COMMAND_INTENT_V2", intent(1, "SSH_READY")))
not_started_output = outcome(command, b"x")
not_started_output.update({"outcome": "not-started", "status": None, "release_count": 0})
reject(lambda: operation._validate_body("COMMAND_OUTCOME_V2", not_started_output))

# Policy is deeply immutable, exactly partitioned, and independently regenerated
# from the process compositions rather than trusted as matching literals.
policy = operation.command_policy
for mapping in (policy.POLICY_SHA256, policy.OCCURRENCES, policy.PHASES,
                policy.MAX_OCCURRENCES, policy.MUTATION_ORDERS):
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
check(not set(policy.POLICY_SHA256) & set(policy.DEFERRED_COMMANDS)
      and set(policy.POLICY_SHA256) | set(policy.DEFERRED_COMMANDS) == set(operation.COMMANDS),
      "policy/deferred partition drift")
for command_id in policy.POLICY_SHA256:
    phase = policy.OCCURRENCES[command_id][0]
    regenerated = intent(command_id=command_id, phase=phase)
    check(operation._v2_policy_digest(regenerated) == policy.POLICY_SHA256[command_id],
          f"stale policy digest: {command_id}")
reject(lambda: add(raw, "COMMAND_INTENT_V2",
                   rebound({**command, "policy_version": "future-policy"})))

# Setup mutations are an exact successful prefix, never an unordered menu.
setup_raw = add(prefix(), "BASELINES_CAPTURED",
                {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
reject(lambda: add(setup_raw, "COMMAND_INTENT_V2",
                   intent(command_id="IP_LINK_ADD", phase="BASELINES_CAPTURED")))
netns = intent(command_id="IP_NETNS_ADD", phase="BASELINES_CAPTURED")
setup_raw = add(add(add(setup_raw, "COMMAND_INTENT_V2", netns),
                    "COMMAND_PREEXEC_V2", preexec(netns)),
                "COMMAND_OUTCOME_V2", outcome(netns))
add(setup_raw, "COMMAND_INTENT_V2",
    intent(1, "IP_LINK_ADD", "BASELINES_CAPTURED"))

# KILL requires successful TERM and a distinct fresh task observation after it.
ownership = settled
ownership = add(ownership, "SSH_READY", {"operation_token": "a" * 64,
    "proof_sha256": "9" * 64,
    "marker_sha256": hashlib.sha256(operation.FIXED["ssh_marker"].encode()).hexdigest(),
    "authentication_attempts": 1})
ownership = add(ownership, "READINESS_REVOKED", {"operation_token": "a" * 64})
ownership = add(ownership, "OWNERSHIP_OBSERVED", {"operation_token": "a" * 64,
    "proof_sha256": "9" * 64, "task": "exact-owned", "container": "exact-owned",
    "runtime": "exact-owned", "share": "exact-owned"})
observed = intent(1, "CTR_TASK_LIST", "OWNERSHIP_OBSERVED")
ownership = add(add(add(ownership, "COMMAND_INTENT_V2", observed),
                    "COMMAND_PREEXEC_V2", preexec(observed)),
                "COMMAND_OUTCOME_V2", outcome(observed))
term = intent(2, "CTR_TASK_TERM", "OWNERSHIP_OBSERVED")
ownership = add(add(add(ownership, "COMMAND_INTENT_V2", term),
                    "COMMAND_PREEXEC_V2", preexec(term)),
                "COMMAND_OUTCOME_V2", outcome(term))
reject(lambda: add(ownership, "COMMAND_INTENT_V2",
                   intent(3, "CTR_TASK_KILL", "OWNERSHIP_OBSERVED")))
fresh = intent(3, "CTR_TASK_LIST", "OWNERSHIP_OBSERVED")
ownership = add(add(add(ownership, "COMMAND_INTENT_V2", fresh),
                    "COMMAND_PREEXEC_V2", preexec(fresh)),
                "COMMAND_OUTCOME_V2", outcome(fresh))
add(ownership, "COMMAND_INTENT_V2", intent(4, "CTR_TASK_KILL", "OWNERSHIP_OBSERVED"))

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
with patch.object(process, "_recover_cgroup", return_value=(True, True)), \
     patch.object(process.os, "fork", side_effect=AssertionError("recovery forked")):
    process._recover_pending_fixed(journal)
check(journal.recorded["outcome"] == "not-started" and journal.recorded["uncertain"]
      and not journal.recorded["leader_reaped"] and not journal.recorded["descendants_reaped"],
      "intent recovery fabricated wait/reap certainty")
recovery_preexec = preexec(command)
preexec_journal = RecoveryJournal((command, recovery_preexec))
with patch.object(process, "_recover_cgroup", return_value=(True, True)) as recover, \
     patch.object(process, "_usable_pidfd_open", side_effect=AssertionError("leader pidfd required")), \
     patch.object(process.os, "fork", side_effect=AssertionError("recovery forked")):
    process._recover_pending_fixed(preexec_journal)
check(recover.call_args.args[1] == process._generation_tuple(recovery_preexec["cgroup_generation"]),
      "preexec recovery did not bind cgroup generation")
check(preexec_journal.recorded["uncertain"] and preexec_journal.recorded["release_count"] == 0,
      "pending preexec recovery was not honestly sticky uncertain")

class TerminalRecoveryJournal:
    def __init__(self): self.recorded = False
    def recovery_command(self):
        return command, recovery_preexec, outcome(command, uncertain=True)
    def record_command_outcome(self, _body):
        self.recorded = True
        raise AssertionError("terminal uncertainty was rewritten")
terminal_journal = TerminalRecoveryJournal()
with patch.object(process, "_recover_cgroup", return_value=(True, True)):
    terminal_result = process._recover_pending_fixed(terminal_journal)
check(terminal_result.body["uncertain"] and not terminal_journal.recorded,
      "terminal-uncertain cleanup changed durable uncertainty")
check(not process._cleanup_closed((False, False, False, False), 10),
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
check(source.index("if not _cleanup_closed(cleanup, pid)") <
      source.index("durable = kata_operation._record_command_outcome"),
      "terminal outcome can precede residue closure")
check(process.LONG_LIVED_CONTAINERD.command_id is process.CommandId.CONTAINERD_START,
      "containerd was modeled as a short command")
check(process.OWNER_ASSIGNED_IDS == {
    "CTR_RUN", "SSH_KEYGEN_CLIENT", "SSH_KEYGEN_SERVER", "SSH_PUBLIC_CLIENT",
    "SSH_PUBLIC_SERVER", "TC_INGRESS_FILTER", "TC_QDISC",
}, "owner-assigned command set drift")
print("completion Kata Slice A correction matrix passed")

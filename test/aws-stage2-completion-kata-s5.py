#!/usr/bin/env python3
"""Offline S5 SSH/lifecycle/qualification hostile matrix; no host actions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if sys.flags.optimize:
    raise RuntimeError("S5 tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_actions as actions
import completion_kata_coordinator as coordinator
import completion_kata_network as network
import completion_kata_operation as operation
import completion_kata_process as process
import completion_kata_qualification as qualification
import completion_kata_runtime as runtime
import completion_kata_ssh as ssh
import completion_rootfs_fs as rootfs_fs
import completion_rootfs_lease as rootfs_lease
import completion_rootfs_ledger as rootfs_ledger


def reject(call):
    try:
        call()
    except BaseException:
        return
    raise AssertionError("hostile S5 case accepted")


def key(inode=10, kind="file"):
    return {"mount_id": 1, "device": 2, "inode": inode, "kind": kind}


def generation(inode=20, mode=0o700):
    return {**key(inode, "directory"), "mode": mode, "uid": 0, "gid": 0,
            "nlink": 2, "size": 0, "mtime_ns": 30, "ctime_ns": 31}


def add(raw, kind, body):
    records = operation._parse(raw) if raw else ()
    return raw + operation._encode(kind, body, records)


def leased_prefix(lease_record=None, ledger_key=None):
    token, root = "a" * 64, "b" * 64
    lease_record = (8, 0x1234, "8" * 64) if lease_record is None else lease_record
    ledger_key = key(40) if ledger_key is None else ledger_key
    body = {**operation.FIXED, "operation_token": token, "rootfs_token": root,
            "host_boot_id": "11111111-1111-1111-1111-111111111111",
            "source_revision": "5" * 40, "source_manifest_sha256": "6" * 64,
            "journal_key": key(), "rootfs_pin": operation.ROOTFS_PIN,
            "mount_list_sha256": operation.MOUNT_SHA}
    raw = add(b"", "GENESIS", body)
    raw = add(raw, "GENESIS_SETTLED", {"operation_token": token, "journal_key": key(),
              "state_parent": generation()})
    raw = add(raw, "ROOTFS_ACQUIRE_INTENT", {"operation_token": token,
              "rootfs_token": root, "rootfs_baseline_sha256": "7" * 64})
    return add(raw, "ROOTFS_LEASED", {"operation_token": token, "rootfs_token": root,
        "rootfs_ledger_key": ledger_key, "leased_sequence": lease_record[0],
        "leased_offset": f"{lease_record[1]:016x}", "leased_sha256": lease_record[2],
        "state_generation": generation(41), "operation_generation": generation(42),
        "root_generation": generation(43, 0o755), "rootfs_pin": operation.ROOTFS_PIN})


def encode_rootfs(proposals):
    raw, settled = b"", rootfs_ledger.INITIAL_BYTES
    for proposal in proposals:
        line = rootfs_ledger._encode_proposal(proposal, settled)
        raw += line
        settled = rootfs_ledger.SettledBytes(
            settled.sequence + 1, settled.offset + len(line), hashlib.sha256(line).hexdigest(),
        )
    return raw


def release_ledger_prefix():
    token = "b" * 64
    operation_name = rootfs_ledger._operation_name(token)
    host_generation = lambda inode, kind="directory", mode=0o700: rootfs_fs.HostGeneration(
        rootfs_fs.HostKey(1, 2, inode, kind), mode, 0, 0, 1 if kind == "file" else 2, 0, 1, 2,
    )
    parent = lambda inode, names, stamp=1: rootfs_ledger.LedgerParent(
        rootfs_fs.HostGeneration(rootfs_fs.HostKey(1, 2, inode, "directory"),
            0o700, 0, 0, 2, 0, 1, stamp), tuple(sorted(names)),
    )
    before = parent(41, ("active-ledger", "lock", "sentinel"))
    after = parent(41, ("active-ledger", "lock", operation_name, "sentinel"), 3)
    operation_generation = host_generation(42)
    operation_empty = rootfs_ledger.LedgerParent(operation_generation, ())
    operation_before = parent(42, ("sentinel",), 3)
    operation_after = parent(42, ("rootfs", "sentinel"), 4)
    sentinel_generation = host_generation(44, "file", 0o600)
    root_generation = host_generation(43, mode=0o755)
    pvalue, gvalue = rootfs_ledger._parent_value, rootfs_ledger._generation_value
    proposals = [
        rootfs_ledger.LedgerProposal.create("genesis", {"token": token,
            "source_revision": "5" * 40, "source_manifest_sha256": "6" * 64,
            "state_parent": pvalue(before), "ledger_key": key(40)}),
        rootfs_ledger.LedgerProposal.create("genesis-settled", {"token": token, "state_parent": pvalue(before)}),
        rootfs_ledger.LedgerProposal.create("operation-create-intent", {"token": token,
            "operation_name": operation_name, "state_parent": pvalue(before)}),
        rootfs_ledger.LedgerProposal.create("operation-create-observed", {"token": token,
            "operation_name": operation_name, "state_parent": pvalue(after),
            "operation": gvalue(operation_generation)}),
        rootfs_ledger.LedgerProposal.create("operation-create-settled", {"token": token,
            "operation_name": operation_name, "state_parent": pvalue(after),
            "operation": gvalue(operation_generation)}),
        rootfs_ledger.LedgerProposal.create("create-intent", {"token": token, "path": "sentinel",
            "kind": "file", "parent": pvalue(operation_empty)}),
        rootfs_ledger.LedgerProposal.create("create-observed", {"token": token, "path": "sentinel",
            "kind": "file", "parent": pvalue(operation_before), "child": gvalue(sentinel_generation)}),
        rootfs_ledger.LedgerProposal.create("create-settled", {"token": token, "path": "sentinel",
            "kind": "file", "parent": pvalue(operation_before), "child": gvalue(sentinel_generation)}),
        rootfs_ledger.LedgerProposal.create("create-intent", {"token": token, "path": "rootfs",
            "kind": "directory", "parent": pvalue(operation_before)}),
        rootfs_ledger.LedgerProposal.create("create-observed", {"token": token, "path": "rootfs",
            "kind": "directory", "parent": pvalue(operation_after), "child": gvalue(root_generation)}),
        rootfs_ledger.LedgerProposal.create("create-settled", {"token": token, "path": "rootfs",
            "kind": "directory", "parent": pvalue(operation_after), "child": gvalue(root_generation)}),
        rootfs_ledger.LedgerProposal.create("leased", {"token": token, "operation_name": operation_name,
            "state_parent": pvalue(after), "operation": gvalue(operation_after.generation),
            "root": gvalue(root_generation), "ledger_key": key(40), "manifest_sha256": "d" * 64,
            "manifest_size": 7, "ustar_sha256": "e" * 64, "ustar_size": 512, "entry_count": 1}),
    ]
    raw = encode_rootfs(proposals)
    return proposals, raw, rootfs_ledger._parse_ledger(raw)[-1]


def release_ready_bytes(prefix):
    lifecycle = operation._make_fake_lifecycle_for_tests(prefix)
    proofs = iter(f"{index:x}".rjust(64, "0") for index in range(1, 20))
    lifecycle.baselines_captured(next(proofs)); lifecycle.network_ready(next(proofs))
    lifecycle.runtime_ready(next(proofs)); lifecycle.ssh_ready(next(proofs)); lifecycle.revoke_readiness()
    lifecycle.ownership_observed(next(proofs)); lifecycle.task_stopped(next(proofs))
    lifecycle.network_absent(next(proofs)); lifecycle.task_absent(next(proofs))
    lifecycle.container_absent(next(proofs)); lifecycle.runtime_absent(next(proofs))
    lifecycle.share_absent(next(proofs)); lifecycle.firewall_absent(next(proofs))
    lifecycle.input_removed(next(proofs)); lifecycle.rootfs_release_ready()
    return lifecycle.journal_bytes()


# Operation, process, network, and runtime share one exact command vocabulary.
assert process.CommandId is network.Action is network.TcObservation is actions.CommandId
assert operation.COMMANDS == actions.COMMAND_IDS
for command in (*network.mutation_snapshots_for_tests(), *network.observer_snapshots_for_tests()):
    assert type(command.action) is actions.CommandId and command.action.value in operation.COMMANDS
assert {network.TcObservation.QDISC.value, network.TcObservation.INGRESS_FILTER.value} <= operation.COMMANDS
for command in runtime.fixed_command_specs_for_tests():
    assert type(command.command_id) is actions.CommandId and command.command_id.value in operation.COMMANDS
assert {item.command_id for item in process._unissued_spec_snapshots_for_tests()} <= operation.COMMANDS
assert {item[0] for item in process._fixed_spec_snapshots_for_tests()} <= operation.COMMANDS
for command_id in sorted(operation.LEGACY_COMMANDS):
    command = {"operation_token": "a" * 64, "command_serial": 0,
               "command_id": command_id, "binding_sha256": "9" * 64,
               "deadline_class": "observer"}
    intent_raw = add(leased_prefix(), "COMMAND_INTENT", command)
    assert operation._legal(operation._parse(intent_raw)) == "ROOTFS_LEASED"
    preexec = {**command, "host_boot_id": "11111111-1111-1111-1111-111111111111",
               "pid": 10, "ppid": 1, "pgid": 10, "sid": 10, "proc_start_time": 99,
               "pidfd_supported": False, "executable_sha256": "1" * 64,
               "tool_closure_sha256": "2" * 64, "exec_status_pipe": key(55)}
    preexec_raw = add(intent_raw, "COMMAND_PREEXEC", preexec)
    assert operation._legal(operation._parse(preexec_raw)) == "ROOTFS_LEASED"
    outcome = {**command, "outcome": "exited", "status": 0, "errno": None,
               "stdout_sha256": operation.ZERO, "stdout_length": 0,
               "stdout_truncated": False, "stderr_sha256": operation.ZERO,
               "stderr_length": 0, "stderr_truncated": False,
               "wait_result": "waited", "reap_result": "reaped"}
    assert operation._legal(operation._parse(add(preexec_raw, "COMMAND_OUTCOME", outcome))) == "ROOTFS_LEASED"

# Exact ordered argv is fd-bound, single-attempt, noninteractive, and forwarding-free.
spec = ssh.command_spec()
assert spec.argv is ssh.ARGV and spec.inherited_fds == (200, 201)
assert spec.argv[0:4] == ("/usr/bin/ssh", "-F", "/dev/null", "-T")
assert spec.argv[-4:] == ("-i", "/proc/self/fd/200", "root@192.0.2.2", "/bin/sh -s")
assert "-n" not in spec.argv and "StdinNull=no" in spec.argv
assert spec.argv.count("ConnectionAttempts=1") == 1
assert "UserKnownHostsFile=/proc/self/fd/201" in spec.argv
assert not any("keyscan" in item or "StrictHostKeyChecking=no" in item for item in spec.argv)
good = ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", False, False, False, True, ())
identity = process.ProcessIdentity(1, 1, 1, 1, 1, "11111111-1111-1111-1111-111111111111", False)
process_good = process.ProcessOutcome("SSH_READY", identity, "exited", 0, None, ssh.MARKER, b"",
    hashlib.sha256(ssh.MARKER).hexdigest(), hashlib.sha256(b"").hexdigest(), False, False,
    False, False, False, True, ())
assert process.adapt_ssh_process_outcome(process_good) == good
fake = ssh.make_test_local_fake(good)
ready = ssh.authenticate_test_local(fake)
assert ready.authentication_attempts == 1 and ready.stderr_length == 0
reject(lambda: ssh.authenticate_test_local(fake))
ssh.revoke_test_local(fake)
assert ssh.fake_state_for_tests(fake) == (ssh.QUALIFICATION, True, True, False, 1)
reject(lambda: ssh.revoke_test_local(fake))
for hostile in (
    ssh.SshOutcome("SSH_READY", "exec_failed", None, b"", b"", False, False, False, True, ("exec",)),
    ssh.SshOutcome("SSH_READY", "signaled", 9, b"", b"", False, False, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER + b"x", b"", False, False, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"warning", False, False, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 1, b"", b"", False, False, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", True, False, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", False, True, False, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", False, False, True, True, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", False, False, False, False, ()),
    ssh.SshOutcome("SSH_READY", "exited", 0, ssh.MARKER, b"", False, False, False, True, ("close:5",)),
):
    candidate = ssh.make_test_local_fake(hostile)
    reject(lambda candidate=candidate: ssh.authenticate_test_local(candidate))
    assert ssh.fake_state_for_tests(candidate) == (ssh.QUALIFICATION, True, True, True, 1)
    reject(lambda candidate=candidate: ssh.authenticate_test_local(candidate))
reject(ssh.open_fixed_ssh_owner)

# The composed coordinator owns adapter failures too. Revocation is ensured
# once, and idempotent teardown consumes it before the one task-stop call.
class StopOwner:
    def __init__(self, ssh_owner): self.ssh_owner, self.stops = ssh_owner, 0
    def stop_task(self):
        assert ssh.fake_state_for_tests(self.ssh_owner)[2:5] in {
            (True, False, 1), (True, True, 1),
        }
        self.stops += 1

adapter_ssh = ssh.make_test_local_fake(good)
adapter_stop = StopOwner(adapter_ssh)
adapter_owners = coordinator.FixedOwners(adapter_stop, object(), object(), adapter_ssh)
bad_command = process.ProcessOutcome("CTR_TASK_LIST", identity, "exited", 0, None, b"", b"",
    hashlib.sha256(b"").hexdigest(), hashlib.sha256(b"").hexdigest(), False, False,
    False, False, False, True, ())
reject(lambda: coordinator.authenticate_once(adapter_owners, bad_command))
assert ssh.fake_state_for_tests(adapter_ssh) == (ssh.QUALIFICATION, False, True, True, 1)
coordinator.stop_task_after_revoke(adapter_owners)
coordinator.stop_task_after_revoke(adapter_owners)
assert adapter_stop.stops == 1
failure_outcome = ssh.SshOutcome("SSH_READY", "exited", 1, b"", b"", False, False, False, True, ())
failure_ssh = ssh.make_test_local_fake(failure_outcome)
failure_process = process.ProcessOutcome("SSH_READY", identity, "exited", 1, None, b"", b"",
    hashlib.sha256(b"").hexdigest(), hashlib.sha256(b"").hexdigest(), False, False,
    False, False, False, True, ())
failure_stop = StopOwner(failure_ssh)
failure_owners = coordinator.FixedOwners(failure_stop, object(), object(), failure_ssh)
reject(lambda: coordinator.authenticate_once(failure_owners, failure_process))
assert ssh.fake_state_for_tests(failure_ssh) == (ssh.QUALIFICATION, True, True, True, 1)
coordinator.stop_task_after_revoke(failure_owners)
assert failure_stop.stops == 1

# Exact inherited input identities are one-shot and role-bound. Missing, extra,
# relabelled, replaced, or linked descriptors fail before fork.
ssh_spec = process._spec(process.CommandId.SSH_READY)
with tempfile.TemporaryDirectory() as directory:
    key_path, hosts_path = Path(directory) / "key", Path(directory) / "hosts"
    key_path.write_bytes(b"key"); hosts_path.write_bytes(b"hosts")
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC)
    hosts_fd = os.open(hosts_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        key_identity, hosts_identity = process._fd_identity(key_fd), process._fd_identity(hosts_fd)
        reject(lambda: process._seal_inherited_inputs_for_tests(
            hosts_fd, key_fd, key_identity, hosts_identity))
        reject(lambda: process._claim_inherited_fds(ssh_spec, None))
        owner = process._seal_inherited_inputs_for_tests(
            key_fd, hosts_fd, key_identity, hosts_identity)
        bindings = process._claim_inherited_fds(ssh_spec, owner)
        assert [(row.role, row.target_fd, row.identity) for row in bindings] == [
            (process.fdmap.CLIENT_KEY, 200, key_identity),
            (process.fdmap.KNOWN_HOSTS, 201, hosts_identity),
        ]
        reject(lambda: process._claim_inherited_fds(ssh_spec, owner))
        child = os.fork()
        if child == 0:
            try:
                process._install_inherited_fds(bindings)
                for original in (key_fd, hosts_fd):
                    try: os.fstat(original)
                    except OSError: pass
                    else: raise AssertionError("inherited original survived")
                assert process._fd_identity(200) == key_identity
                assert process._fd_identity(201) == hosts_identity
            except BaseException:
                os._exit(1)
            os._exit(0)
        assert os.waitpid(child, 0)[1] == 0
        child = os.fork()
        if child == 0:
            real_close = process.fdmap.os.close
            def close_then_uncertain(descriptor):
                real_close(descriptor)
                raise OSError("injected close uncertainty")
            process.fdmap.os.close = close_then_uncertain
            try: process._install_inherited_fds(bindings)
            except BaseException: os._exit(0)
            os._exit(1)
        assert os.waitpid(child, 0)[1] == 0
        duplicate = os.dup(key_fd)
        try:
            reject(lambda: process._seal_inherited_inputs_for_tests(
                key_fd, duplicate, key_identity, process._fd_identity(duplicate)))
        finally:
            os.close(duplicate)
        linked = process._seal_inherited_inputs_for_tests(
            key_fd, hosts_fd, key_identity, hosts_identity)
        os.link(key_path, Path(directory) / "key-link")
        reject(lambda: process._claim_inherited_fds(ssh_spec, linked))
        os.unlink(Path(directory) / "key-link")
        replaced = process._seal_inherited_inputs_for_tests(
            key_fd, hosts_fd, process._fd_identity(key_fd), process._fd_identity(hosts_fd))
        os.dup2(hosts_fd, key_fd)
        reject(lambda: process._claim_inherited_fds(ssh_spec, replaced))
    finally:
        os.close(key_fd); os.close(hosts_fd)

# Every child-private role is relocated before target/stdio mapping when its
# inherited number collides with either fixed target.
for role_index in range(7):
    for collision in (200, 201):
        child = os.fork()
        if child == 0:
            values = [os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(7)]
            os.dup2(values[role_index], collision, inheritable=False)
            os.close(values[role_index]); values[role_index] = collision
            before = tuple(process._fd_identity(item) for item in values)
            try:
                moved = process._relocate_child_internals(tuple(values))
                assert all(item not in (0, 1, 2, 200, 201) for item in moved)
                assert tuple(process._fd_identity(item) for item in moved) == before
                try: os.fstat(collision)
                except OSError: pass
                else: raise AssertionError("colliding original survived")
                for item in moved: os.close(item)
            except BaseException:
                os._exit(1)
            os._exit(0)
        assert os.waitpid(child, 0)[1] == 0, (role_index, collision)

# Exact cross-ledger crash suffixes: before write, partial/rollback, durable
# rootfs-only, durable dual-ledger, mismatch, and replacement all preserve or
# resume only the exact authorized route.
root_proposals, leased_root_raw, leased_root = release_ledger_prefix()
matching_prefix = leased_prefix(
    (leased_root.sequence, leased_root.next_offset, leased_root.line_sha256), key(40),
)
ready_route_raw = release_ready_bytes(matching_prefix)
assert rootfs_lease._classify_release_crash_for_tests(
    ready_route_raw, leased_root_raw,
) == "append-rootfs-authorization"
ready_record = operation._parse(ready_route_raw)[-1]
authorization_body = {"token": "b" * 64, "operation_name": rootfs_ledger._operation_name("b" * 64),
    "lease_sequence": leased_root.sequence, "lease_offset": leased_root.next_offset,
    "lease_sha256": leased_root.line_sha256, "kata_operation_token": "a" * 64,
    "kata_ledger_key": key(), "kata_release_sequence": ready_record.sequence,
    "kata_release_offset": ready_record.next_offset, "kata_release_sha256": ready_record.line_sha256}
authorized_root_raw = encode_rootfs(root_proposals + [
    rootfs_ledger.LedgerProposal.create("release-authorized", authorization_body),
])
authorized_root = rootfs_ledger._parse_ledger(authorized_root_raw)[-1]
assert rootfs_lease._classify_release_crash_for_tests(
    ready_route_raw, authorized_root_raw,
) == "settle-operation-authorization"
route_lifecycle = operation._make_fake_lifecycle_for_tests(ready_route_raw)
route_permit = route_lifecycle.resume_rootfs_release_ready()
route_grant = operation._claim_rootfs_release(route_permit)
route_authorization = operation._invoke_rootfs_release(route_grant, lambda context:
    operation.RootfsAuthorization(context.rootfs_token, authorized_root.sequence,
        authorized_root.next_offset, authorized_root.line_sha256))
operation._settle_rootfs_release(route_grant, route_authorization)
dual_route_raw = route_lifecycle.journal_bytes()
assert rootfs_lease._classify_release_crash_for_tests(dual_route_raw, authorized_root_raw) == "authorized"
for uncertain_operation, uncertain_root in (
    (ready_route_raw[:-1], leased_root_raw),
    (ready_route_raw, authorized_root_raw[:-1]),
    (ready_route_raw, encode_rootfs(root_proposals + [rootfs_ledger.LedgerProposal.create(
        "release-authorized", {**authorization_body, "kata_release_sha256": "f" * 64})])),
    (release_ready_bytes(leased_prefix(
        (leased_root.sequence, leased_root.next_offset, leased_root.line_sha256), key(44))), leased_root_raw),
):
    reject(lambda operation_raw=uncertain_operation, root_raw=uncertain_root:
           rootfs_lease._classify_release_crash_for_tests(operation_raw, root_raw))

# Complete successful order with a simulated crash between the two ledgers.
lifecycle = operation._make_fake_lifecycle_for_tests(leased_prefix())
proofs = iter(f"{index:x}".rjust(64, "0") for index in range(1, 30))
lifecycle.baselines_captured(next(proofs)); lifecycle.network_ready(next(proofs))
lifecycle.runtime_ready(next(proofs)); lifecycle.ssh_ready(next(proofs))
lifecycle.revoke_readiness(); lifecycle.ownership_observed(next(proofs))
lifecycle.task_stopped(next(proofs)); lifecycle.network_absent(next(proofs))
lifecycle.task_absent(next(proofs)); lifecycle.container_absent(next(proofs))
lifecycle.runtime_absent(next(proofs)); lifecycle.share_absent(next(proofs))
lifecycle.firewall_absent(next(proofs)); lifecycle.input_removed(next(proofs))
permit = lifecycle.rootfs_release_ready()
grant = operation._claim_rootfs_release(permit)
seen = []
authorization = operation._invoke_rootfs_release(grant, lambda context: (
    seen.append(context) or operation.RootfsAuthorization(context.rootfs_token, 99, 9999, "e" * 64)
))
assert len(seen) == 1 and seen[0].leased_offset == 0x1234
# Owner death before operation settlement leaves the exact ready suffix. A new
# typed owner replays the same authorization tuple and settles only that suffix.
ready_bytes = lifecycle.journal_bytes()
assert operation._parse(ready_bytes)[-1].record_type == "ROOTFS_RELEASE_READY"
resumed = operation._make_fake_lifecycle_for_tests(ready_bytes)
permit2 = resumed.resume_rootfs_release_ready(); grant2 = operation._claim_rootfs_release(permit2)
authorization2 = operation._invoke_rootfs_release(grant2, lambda context: operation.RootfsAuthorization(
    context.rootfs_token, authorization.sequence, authorization.offset, authorization.line_sha256))
operation._settle_rootfs_release(grant2, authorization2)
resumed.rootfs_absent(next(proofs)); resumed.retire(next(proofs))
records = operation._parse(resumed.journal_bytes())
expected_suffix = (
    "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY",
    "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED", "NETWORK_ABSENT",
    "TASK_ABSENT", "CONTAINER_ABSENT", "RUNTIME_ABSENT", "SHARE_ABSENT",
    "FIREWALL_ABSENT", "INPUT_REMOVED", "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED")
assert tuple(item.record_type for item in records[-len(expected_suffix):]) == expected_suffix
assert not hasattr(resumed, "append") and not hasattr(resumed, "record")
reject(lambda: operation._make_fake_lifecycle_for_tests(ready_bytes[:-1]))
reject(lambda: operation._settle_rootfs_release(grant2, authorization2))

# Qualification schema is closed and current committed facts fail honestly.
all_false = qualification.Preflight(*(False for _ in range(10)))
report = qualification.evaluate(all_false)
assert report["blockers"] == list(qualification.BLOCKER_ORDER)
assert not report["qualified"] and report["external_mutations_invoked"] == 0
raw = qualification.canonical_report(report)
assert qualification.load_report(raw) == report
reject(lambda: qualification.load_report(raw.replace(b'"qualified":false', b'"qualified":true')))
qualified_fake = qualification.evaluate(qualification.Preflight(*(True for _ in range(10))))
assert qualified_fake["qualified"] and qualified_fake["external_mutations_invoked"] == 0
assert qualified_fake["authority"] == "offline-fake"
actual = qualification.committed_report()
assert actual["authority"] == "committed-local-preflight"
for blocker in ("host-tools-unqualified", "runtime-fixtures-unqualified",
                "network-fixtures-unqualified", "ssh-fixture-unqualified",
                "kvm-missing-or-unqualified"):
    assert blocker in actual["blockers"]
entry = REMOTE / "completion_kata_qualification.py"
result = subprocess.run([sys.executable, str(entry)], capture_output=True, check=False, timeout=5,
                        env={**os.environ, "COGS_STAGE2_PROJECT": "hostile", "PYTHONPATH": "/missing"})
assert result.returncode == 1 and qualification.load_report(result.stdout)["qualified"] is False
assert result.stderr == b""
argument = subprocess.run([sys.executable, str(entry), "unexpected"], capture_output=True,
                          check=False, timeout=5)
assert argument.returncode == 2 and argument.stdout == argument.stderr == b""
shell_argument = subprocess.run([str(REMOTE / "run-stage2-completion-remote.sh"), "unexpected"],
                                capture_output=True, check=False, timeout=5)
assert shell_argument.returncode == 64
for fixed_entry in ("run-stage2-completion-full.sh",
                    "run-stage2-completion-readiness.sh"):
    path = REMOTE / fixed_entry
    source = path.read_text()
    assert "mode" not in source.lower() and "env -i" in source
    rejected_argument = subprocess.run(
        [str(path), "unexpected"], capture_output=True, check=False, timeout=5)
    assert rejected_argument.returncode == 64
assert (REMOTE / "run-stage2-completion-full.sh").read_bytes() != (
       REMOTE / "run-stage2-completion-readiness.sh").read_bytes()
assert coordinator.preflight_report() == actual
reject(coordinator._run_fixed_full_cycle)
reject(coordinator._run_fixed_readiness_cycle)
reject(coordinator.open_fixed_coordinator)
print("completion Kata S5 offline qualification/lifecycle matrix passed")

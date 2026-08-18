#!/usr/bin/env python3
"""Portable hostile tests for fixed binding, deadlines, and descendants."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_fdmap as fdmap
import completion_kata_operation as operation
import completion_kata_process as process


def check(value, message):
    if not value:
        raise AssertionError(message)


def reject(call, message="hostile process case accepted"):
    try:
        call()
    except BaseException:
        return
    raise AssertionError(message)


def generation(identity):
    return process._generation(identity)


# The fixed private-containerd command includes the private socket everywhere.
spec = process._fixed_command(process.CommandId.CONTAINERD_START)
check(spec.argv == (
    "/usr/bin/containerd", "--address", process.CONTAINERD_SOCKET,
    "--root", process.CONTAINERD_ROOT, "--state", process.CONTAINERD_STATE,
    "--config", process.CONTAINERD_CONFIG,
), "containerd argv drift")
ctr = process._fixed_command(process.CommandId.CTR_TASK_LIST)
check(ctr.argv[:5] == (
    "/usr/bin/ctr", "--address", process.CONTAINERD_SOCKET, "--namespace", process.NAMESPACE,
), "ctr private address missing")
check(process.ENVIRONMENT == operation.FIXED_ENV, "child environment drift")
reject(lambda: process._fixed_command("CTR_TASK_LIST"))
reject(process.open_fixed_process_owner)

# Intent bytes bind the retained executable generation, full bytes, argv, stdin,
# environment, descriptors, output policy, and one CLOCK_BOOTTIME deadline.
with tempfile.TemporaryDirectory() as directory:
    executable_path = Path(directory) / "ctr"
    executable_path.write_bytes(b"fixed-executable-bytes")
    executable_fd = os.open(executable_path, os.O_RDONLY | os.O_CLOEXEC)
    key_path = Path(directory) / "key"
    hosts_path = Path(directory) / "hosts"
    key_path.write_bytes(b"key")
    hosts_path.write_bytes(b"hosts")
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC)
    hosts_fd = os.open(hosts_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        observed = fdmap.identity(executable_fd)
        retained = process.RetainedExecutable(
            "ctr", "/usr/bin/ctr", executable_fd,
            hashlib.sha256(b"fixed-executable-bytes").hexdigest(), "d" * 64,
            generation(observed),
        )
        context = operation.CommandContext(
            "a" * 64, {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
            "11111111-1111-1111-1111-111111111111", "5" * 40,
            "ROOTFS_LEASED", 0,
        )
        before = process._boottime_ns()
        body = process._intent_body(context, ctr, retained, ())
        after = process._boottime_ns()
        operation._validate_body("COMMAND_INTENT_V2", body)
        check(before + ctr.duration_ns <= body["deadline_boottime_ns"] <= after + ctr.duration_ns,
              "deadline not derived once from fixed policy")
        check(body["argv"] == list(ctr.argv) and body["environment"] == [
            list(row) for row in operation.FIXED_ENV
        ], "command binding incomplete")

        os.close(executable_fd)
        executable_fd = os.open(executable_path, os.O_WRONLY)
        os.write(executable_fd, b"replacement")
        os.close(executable_fd)
        executable_fd = -1
        reject(lambda: process._intent_body(context, ctr, retained, ()),
               "replaced executable accepted")

        key_identity = fdmap.identity(key_fd)
        hosts_identity = fdmap.identity(hosts_fd)
        bindings = fdmap.bind_inputs(key_fd, hosts_fd, key_identity, hosts_identity)
        check(tuple(row.target_fd for row in bindings) == (200, 201), "fd targets drift")
        check(tuple(row.content_sha256 for row in bindings) == (
            hashlib.sha256(b"key").hexdigest(), hashlib.sha256(b"hosts").hexdigest(),
        ), "fd content not bound")
        os.close(key_fd)
        key_fd = os.open(hosts_path, os.O_RDONLY | os.O_CLOEXEC)
        reject(lambda: fdmap.revalidate(bindings), "fd replacement accepted")
    finally:
        for descriptor in (executable_fd, key_fd, hosts_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

# PREEXEC is durable before the only release byte, and release cannot repeat.
identity = process.ProcessIdentity(
    100, 1, 100, 100, 5, "11111111-1111-1111-1111-111111111111", True,
)
owner = process._OwnedProcess(
    identity, 9, "/sys/fs/cgroup/cogs-stage2-completion-v1/a-0",
    (1, 2, 3, 0, 0), 1_000, 800, 900,
)
status_r, status_w = os.pipe()
release_r, release_w = os.pipe()
for descriptor in (status_r, status_w, release_r, release_w):
    os.set_inheritable(descriptor, False)
intent_header = {
    "operation_token": "a" * 64, "command_serial": 0,
    "command_id": "CTR_TASK_LIST", "binding_sha256": "b" * 64,
}
cgroup_record = {
    "mount_id": 1, "device": 2, "inode": 3, "kind": "directory",
    "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2, "size": 0,
    "mtime_ns": 1, "ctime_ns": 2,
}
order = []
real_write = os.write

def observed_write(descriptor, raw):
    order.append("release")
    return real_write(descriptor, raw)

try:
    with patch.object(operation, "_record_command_preexec", side_effect=lambda *_args: order.append("journal")), \
         patch.object(process.os, "write", side_effect=observed_write):
        process._release_once(
            object(), intent_header, owner, cgroup_record, status_w, release_w,
        )
    check(order == ["journal", "release"] and os.read(release_r, 1) == b"R",
          "release preceded durable preexec")
    reject(lambda: process._release_once(
        object(), intent_header, owner, cgroup_record, status_w, release_w,
    ), "second release accepted")
finally:
    os.close(status_r)
    os.close(status_w)
    os.close(release_r)

# Leader reap is insufficient: a live cgroup member remains uncertainty, and
# TERM/KILL consume time inside the original deadline rather than adding grace.
identity = process.ProcessIdentity(100, 1, 100, 100, 5, "boot", True)
owner = process._OwnedProcess(identity, 9, "/sys/fs/cgroup/fixed", (1, 2, 3, 0, 0),
                              130, 110, 120)
times = iter((100, 111, 121, 129, 130, 130))
signals = []

def set_reaped(value):
    value.leader_status = 0

with patch.object(process, "_boottime_ns", side_effect=lambda: next(times)), \
     patch.object(process, "_wait_leader", side_effect=set_reaped), \
     patch.object(process, "_cgroup_members", return_value=((222,), owner.cgroup_generation)), \
     patch.object(process, "_retain_descendants", return_value=None), \
     patch.object(process, "_reap_descendants", return_value=False), \
     patch.object(process, "_signal_members", side_effect=lambda _owner, sig: signals.append(sig)), \
     patch.object(process.time, "sleep", return_value=None):
    closure = process._settle_owned(owner)
check(owner.term_attempted and owner.kill_attempted, "bounded escalation missing")
check(signals == [process.signal.SIGTERM, process.signal.SIGKILL], "escalation order drift")
check(not closure["descendants_reaped"] and "absolute-deadline" in closure["errors"],
      "leader reap accepted live descendant")

# A settled command requires all five closure facts. Any missing pipe/cgroup or
# descendant fact creates a sticky-uncertain outcome body.
intent = {
    **intent_header, "stdout_limit": 65536, "stderr_limit": 65536,
}
body = process._outcome_body(intent, "exited", 0, None, b"", b"", closure, True)
check(body["outcome"] == "uncertain" and body["uncertain"], "live descendant became success")
settled_closure = {
    "leader_reaped": True, "descendants_reaped": True, "cgroup_empty": True,
    "cgroup_removed": True, "term_attempted": False, "kill_attempted": False,
    "deadline_expired": False, "errors": [],
}
body = process._outcome_body(intent, "exited", 0, None, b"ok", b"", settled_closure, True)
check(body["outcome"] == "exited" and not body["uncertain"], "settled outcome rejected")
no_eof = process._outcome_body(
    intent, "exited", 0, None, b"", b"", settled_closure, False,
)
check(no_eof["uncertain"] and no_eof["outcome"] == "uncertain",
      "pipe EOF omission accepted")

source = (ROOT / "deploy/aws-feasibility/remote/completion_kata_process.py").read_text()
for forbidden in (
    "COGS_KATA_PROCESS_TESTING_V1", "def _supervise(", "def _make_test_issuer(",
    "TEST_PATH", "make_input_owner_for_tests", "class ProcessOutcome", "def execute(", "def run(",
):
    check(forbidden not in source, f"deployed generic/test route remains: {forbidden}")
print("completion Kata fixed process transaction matrix passed")

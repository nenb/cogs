#!/usr/bin/env python3
"""Portable contract snapshots and Linux direct-child supervisor tests."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time
from unittest.mock import patch

if sys.flags.optimize:
    raise RuntimeError("process tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_process as process


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile process case accepted")


def contract_rejected(raw):
    try:
        process._parse_contract(raw, hashlib.sha256(raw).hexdigest())
    except process.ProcessError:
        return
    except BaseException as error:
        raise AssertionError(f"contract failure was not normalized: {type(error).__name__}") from error
    raise AssertionError("hostile contract accepted")


# Closed production snapshots contain no caller-selected token.  These exact
# values are future actions only; no production execution issuer exists.
snapshots = {name: (argv, stdin, deadline, fds) for name, argv, stdin, deadline, fds in process._fixed_spec_snapshots_for_tests()}
assert snapshots["CTR_TASK_TERM"] == ((
    "/usr/bin/ctr", "--address", process.CONTAINERD_SOCKET,
    "--namespace", "cogs-stage2-completion-v1", "tasks", "kill",
    "--signal", "SIGTERM", "cogs-stage2-ssh-v1",
), b"", "task-term", ())
assert process.NFT_INPUT.endswith(b'add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop\n')
unissued = {item.command_id: item for item in process._unissued_spec_snapshots_for_tests()}
assert unissued["IP_NETNS_ADD"].tool_contract == "ip"
assert unissued["IP_NETNS_ADD"].argv_tail == ("netns", "add", "cogs-stage2-ssh")
assert unissued["IP_PEER_ADDRGEN_NONE"].argv_tail[-2:] == ("addrgenmode", "none")
assert unissued["NFT_INSTALL"].tool_contract == "nft"
assert unissued["NFT_INSTALL"].argv_tail == ("-f", "-")
assert unissued["NFT_INSTALL"].stdin == process.NFT_INPUT
assert snapshots["SSH_READY"][0][-2:] == ("root@192.0.2.2", "printf '%s\\n' COGS_STAGE2_SSH_READY_V1")
assert snapshots["SSH_READY"][2:] == ("ssh", (200, 201))
assert len(snapshots) == 8
rejected(lambda: process._spec("IP_NETNS_ADD"))
rejected(lambda: process._test_spec("ok"))
BOOT_A = "12345678-1234-1234-1234-123456789abc"
BOOT_B = "abcdefab-cdef-abcd-efab-cdefabcdefab"
fake_identity = process.ProcessIdentity(10, 1, 10, 10, 99, BOOT_A, True)
exact = process.RecoveryObservation(process.ObservationKind.EXACT, (10, 1, 10, 10, 99))
mismatch = process.RecoveryObservation(process.ObservationKind.EXACT, (10, 1, 10, 10, 100))
absent = process.RecoveryObservation(process.ObservationKind.ABSENT)
unknown = process.RecoveryObservation(process.ObservationKind.UNKNOWN)
assert process._recovery_class(fake_identity, BOOT_A, exact) == "exact_live"
assert process._recovery_class(fake_identity, BOOT_B, exact) == "recovery_absent"
assert process._recovery_class(fake_identity, BOOT_A, absent) == "recovery_absent"
assert process._recovery_class(fake_identity, BOOT_A, unknown) == "uncertain"
assert process._recovery_class(fake_identity, BOOT_A, mismatch) == "uncertain"
rejected(lambda: process._recovery_class(fake_identity, "boot-a", absent))
rejected(lambda: process._recovery_class(fake_identity, BOOT_A, None))
rejected(lambda: process._recovery_class(fake_identity, BOOT_A, process.RecoveryObservation(process.ObservationKind.ABSENT, (1,))))
for command in (process.CommandId.IP_NETNS_ADD, process.CommandId.NFT_INSTALL):
    assert process._spec(command).command_id == command.value
for command in (process.CommandId.SSH_KEYGEN_CLIENT, process.CommandId.SSH_PUBLIC_CLIENT):
    rejected(lambda command=command: process._spec(command))
assert {"SSH_KEYGEN_CLIENT", "SSH_PUBLIC_CLIENT", "CTR_RUN"} <= process.OWNER_ASSIGNED_IDS

# Contract decoding requires canonical, digest-bound, exact typed records.
def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def contract_for(path, command="TEST_HELPER"):
    raw = path.read_bytes()
    artifact = {
        "logical_path": str(path), "role": "executable", "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw), "soname": None,
    }
    body = {
        "architecture": "x86_64", "command_id": command, "dynamic_tags": [],
        "executable": artifact, "libraries": [], "loader": None,
        "version": process.CONTRACT_VERSION,
    }
    value = {**body, "closure_sha256": hashlib.sha256(canonical(body)).hexdigest()}
    encoded = canonical(value)
    return encoded, hashlib.sha256(encoded).hexdigest()


placeholder = Path(process.TEST_PATH)
value = {
    "architecture": "x86_64", "closure_sha256": "1" * 64, "command_id": "TEST_HELPER",
    "dynamic_tags": [], "executable": {
        "logical_path": process.TEST_PATH, "role": "executable", "sha256": "2" * 64,
        "size": 1, "soname": None,
    }, "libraries": [], "loader": None, "version": process.CONTRACT_VERSION,
}
encoded = canonical(value)
rejected(lambda: process._parse_contract(encoded, "0" * 64))
rejected(lambda: process._parse_contract(encoded.replace(b'"version"', b'"version" '), hashlib.sha256(encoded.replace(b'"version"', b'"version" ')).hexdigest()))
duplicate = encoded.replace(b'{', b'{"version":"duplicate",', 1)
rejected(lambda: process._parse_contract(duplicate, hashlib.sha256(duplicate).hexdigest()))
for tags in (["RPATH"], ["RUNPATH"], ["AUDIT"], [{"unhashable": True}], ["A", 1]):
    hostile = {**value, "dynamic_tags": tags}
    raw = canonical(hostile)
    contract_rejected(raw)
for command in (None, "", "caller-selected", "A" * 65):
    hostile = {**value, "command_id": command}
    raw = canonical(hostile)
    contract_rejected(raw)
for soname in ("libx.so/evil", "libx so.1", "libx..so.1", ".", "x.so.1", "libx.so.latest", "libx.so\x00.1"):
    artifact = {**value["executable"], "role": "library", "soname": soname}
    rejected(lambda artifact=artifact: process._artifact(artifact, "library"))
large = 128 * 1024 * 1024
libraries = [{"logical_path": f"/lib/libx{i}.so.1", "role": "library", "sha256": f"{i + 3:x}" * 64,
              "size": large, "soname": f"libx{i}.so.1"} for i in range(4)]
loader = {"logical_path": "/lib/ld-test.so", "role": "loader", "sha256": "9" * 64, "size": 1, "soname": None}
overflow_body = {name: item for name, item in value.items() if name != "closure_sha256"}
overflow_body.update({"libraries": libraries, "loader": loader})
overflow = {**overflow_body, "closure_sha256": hashlib.sha256(canonical(overflow_body)).hexdigest()}
raw = canonical(overflow)
contract_rejected(raw)
deeply_nested = b"[" * 1_200 + b"0" + b"]" * 1_200
contract_rejected(deeply_nested)


HELPER = r'''#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int write_all(int descriptor, const void *buffer, size_t size) {
  const char *next = buffer;
  while (size > 0) {
    ssize_t written = write(descriptor, next, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return -1;
    next += written;
    size -= (size_t)written;
  }
  return 0;
}
int main(int argc, char **argv) {
  if (argc != 2) return 90;
  if (!strcmp(argv[1], "ok")) return write_all(1, "ok\n", 3) == 0 ? 0 : 96;
  if (!strcmp(argv[1], "stderr")) return write_all(2, "fixed-error\n", 12) == 0 ? 0 : 96;
  if (!strcmp(argv[1], "exit7")) return 7;
  if (!strcmp(argv[1], "flood")) { char x = 'x'; for (int i=0;i<65537;i++) if (write_all(1,&x,1)) return 96; return 0; }
  if (!strcmp(argv[1], "dual-flood")) { char out[4096], err[4096]; memset(out,'o',sizeof(out)); memset(err,'e',sizeof(err)); for (int i=0;i<20;i++) if (write_all(1,out,sizeof(out)) || write_all(2,err,sizeof(err))) return 96; return 0; }
  if (!strcmp(argv[1], "sleep")) { signal(SIGTERM, SIG_IGN); sleep(30); return 0; }
  if (!strcmp(argv[1], "held-pipe")) { pid_t child=fork(); if (child<0) return 93; if (!child) { usleep(800000); _exit(0); } return 0; }
  if (!strcmp(argv[1], "fd")) { if (fcntl(198, F_GETFD) == -1 && errno == EBADF) return write_all(1,"closed\n",7) == 0 ? 0 : 96; return 91; }
  if (!strcmp(argv[1], "high-fd")) { if (fcntl(4096, F_GETFD) == -1 && errno == EBADF) return write_all(1,"high-closed\n",12) == 0 ? 0 : 96; return 94; }
  if (!strcmp(argv[1], "inherited")) { char a=0,b=0; if (read(200,&a,1)==1 && read(201,&b,1)==1 && a=='K' && b=='H' && fcntl(202,F_GETFD)==-1 && errno==EBADF) return write_all(1,"inherited\n",10) == 0 ? 0 : 96; return 95; }
  return 92;
}
'''


def linux_supervisor_tests():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        return
    cc = Path("/usr/bin/cc")
    if not cc.exists():
        raise AssertionError("fixed local C compiler is required for the Linux process test")
    directory = placeholder.parent
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    source = directory / "helper.c"
    source.write_text(HELPER, encoding="ascii")
    os.chmod(source, 0o600)
    compile_result = subprocess.run(
        [str(cc), "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(placeholder), str(source)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    assert compile_result.returncode == 0, compile_result.stderr.decode(errors="replace")
    os.chmod(placeholder, 0o500)
    raw, digest = contract_for(placeholder)

    class Journal:
        def __init__(self):
            self.context = process.kata_operation.CommandContext(
                "a" * 64, {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
                process._boot_id(), "5" * 40, "ROOTFS_LEASED", 0,
            )
            self.intent = self.preexec = self.outcome = None
        def command_context(self):
            return self.context
        def record_command_intent(self, body):
            process.kata_operation._validate_body("COMMAND_INTENT_V2", body)
            self.intent = body
        def record_command_preexec(self, body):
            process.kata_operation._validate_body("COMMAND_PREEXEC_V2", body)
            self.preexec = body
        def record_command_outcome(self, body):
            process.kata_operation._validate_body("COMMAND_OUTCOME_V2", body)
            self.outcome = body
            return body

    def cgroup_patches(owner):
        def prepare(context):
            owner.path = f"{process.CGROUP_BASE}/{context.operation_token}-{context.command_serial}"
            return owner
        def register(value, pid):
            value.member = pid
            process._adopt_members(value, (pid,))
        def members(value):
            pid = getattr(value, "member", None)
            if pid is None:
                return ()
            try:
                process._proc_row(pid)
                return (pid,)
            except (OSError, process.ProcessError):
                return ()
        def kill(value):
            for descriptor, _row in value.pidfds.values():
                try: signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError: pass
        def settle(value, leader, _deadline, _errors):
            for pid, (descriptor, _row) in tuple(value.pidfds.items()):
                if pid != leader:
                    try: os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError: pass
                try: os.close(descriptor)
                except OSError: pass
            value.pidfds.clear()
            return True, True, True
        return (
            patch.object(process, "_prepare_cgroup", side_effect=prepare),
            patch.object(process, "_register_cgroup", side_effect=register),
            patch.object(process, "_cgroup_members", side_effect=members),
            patch.object(process, "_kill_cgroup", side_effect=kill),
            patch.object(process, "_settle_cgroup", side_effect=settle),
        )

    def make_issuer():
        contract = process._parse_contract(raw, digest)
        executable_fd = process._sealed_memfd(contract.executable, True)
        used = False
        def issue_once(action, inherited=None):
            nonlocal used
            if used:
                raise process.ProcessError("test transaction already consumed")
            used = True
            command_id = process.CommandId.SSH_READY if action is process._TestAction.INHERITED \
                else process.CommandId.CTR_TASK_LIST
            test_spec = process._test_spec(action)
            fixed = process.FixedCommand(
                command_id, "test", process.TEST_PATH, test_spec.argv, test_spec.stdin,
                int(test_spec.deadline_seconds * 1_000_000_000),
                inherited_fds=test_spec.inherited_fds,
            )
            previous = process._FIXED_COMMANDS.get(command_id)
            process._FIXED_COMMANDS[command_id] = fixed
            identity = process._fd_identity(executable_fd)
            retained = process.RetainedExecutable(
                "test", process.TEST_PATH, executable_fd, contract.executable.sha256,
                contract.closure_sha256, process._host_generation(executable_fd),
            )
            journal = Journal()
            leaf_generation = (
                1, 2, 4, "directory", 0o700, 0, 0, 2, 0, 1, 2,
            )
            owner = process._CgroupOwner("", leaf_generation, (), False, {})
            patches = cgroup_patches(owner)
            try:
                with patches[0], patches[1], patches[2], patches[3], patches[4]:
                    outcome, _durable = process._transact_fixed(
                        journal, fixed, retained, () if inherited is None else inherited,
                    )
                return outcome
            finally:
                if previous is None:
                    del process._FIXED_COMMANDS[command_id]
                else:
                    process._FIXED_COMMANDS[command_id] = previous
                os.close(executable_fd)
        return issue_once

    def issue(action, inherited=None):
        return make_issuer()(action, inherited)

    result = issue(process._TestAction.OK)
    assert result.outcome == "exited" and result.status == 0 and result.stdout == b"ok\n", (
        f"unexpected OK outcome: outcome={result.outcome!r} status={result.status!r} errno={result.errno!r} "
        f"stdout={result.stdout!r} stderr={result.stderr!r} errors={result.errors!r}"
    )
    assert result.stderr == b"" and result.reaped and not result.errors
    assert result.identity.pid == result.identity.pgid == result.identity.sid
    assert result.identity.ppid == os.getpid() and result.identity.starttime > 0
    assert result.stdout_sha256 == hashlib.sha256(b"ok\n").hexdigest()

    authority = make_issuer()
    authority(process._TestAction.OK)
    rejected(lambda: authority(process._TestAction.OK))

    result = issue(process._TestAction.STDERR)
    assert result.status == 0 and result.stderr == b"fixed-error\n" and result.reaped
    result = issue(process._TestAction.EXIT7)
    assert result.status == 7 and result.errors == () and result.reaped
    result = issue(process._TestAction.FLOOD)
    assert len(result.stdout) == process.MAX_STREAM and result.stdout_truncated
    assert not result.errors and result.reaped
    result = issue(process._TestAction.DUAL_FLOOD)
    assert len(result.stdout) == len(result.stderr) == process.MAX_STREAM
    assert result.stdout_truncated and result.stderr_truncated and result.reaped

    started = time.monotonic()
    result = issue(process._TestAction.SLEEP)
    assert result.timed_out and result.leader_timed_out and not result.pipe_timed_out
    assert result.outcome == "uncertain" and result.status is None
    assert result.reaped and time.monotonic() - started < 5

    started = time.monotonic()
    result = issue(process._TestAction.HELD_PIPE)
    assert result.reaped and result.pipe_timed_out and not result.leader_timed_out
    assert result.outcome == "uncertain" and "absolute-deadline" in result.errors
    assert time.monotonic() - started < 1

    held = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.dup2(held, 198, inheritable=True)
        result = issue(process._TestAction.FD)
        assert result.status == 0 and result.stdout == b"closed\n"
    finally:
        os.close(198)
        os.close(held)

    # Collision-safe inherited mapping survives exec only at exact 200/201;
    # source CLOEXEC flags remain unchanged and every extra fd is closed.
    key_r, key_w = os.pipe2(os.O_CLOEXEC)
    hosts_r, hosts_w = os.pipe2(os.O_CLOEXEC)
    os.write(key_w, b"K"); os.write(hosts_w, b"H")
    os.close(key_w); os.close(hosts_w)
    saved = {}
    try:
        for target in (200, 201):
            try: saved[target] = os.dup(target)
            except OSError: saved[target] = None
        os.dup2(hosts_r, 200, inheritable=False)
        os.dup2(key_r, 201, inheritable=False)
        owner = process._seal_inherited_inputs_for_tests(
            201, 200, process._fd_identity(201), process._fd_identity(200),
        )
        result = issue(process._TestAction.INHERITED, owner)
        assert result.status == 0 and result.stdout == b"inherited\n" and not result.errors
        assert not os.get_inheritable(200) and not os.get_inheritable(201)
    finally:
        for target, original in saved.items():
            if original is None:
                try: os.close(target)
                except OSError: pass
            else:
                os.dup2(original, target); os.close(original)
        os.close(key_r); os.close(hosts_r)

    # close_range reaches inherited descriptors above a subsequently lowered limit.
    base = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    high = __import__("fcntl").fcntl(base, __import__("fcntl").F_DUPFD, 4096)
    os.set_inheritable(high, True)
    old_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, old_limit[1]))
        result = issue(process._TestAction.HIGH_FD)
        assert result.status == 0 and result.stdout == b"high-closed\n"
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, old_limit)
        os.close(high)
        os.close(base)

    # A child-side pre-exec failure is a fixed-size errno result and is reaped.
    with patch.object(process, "_execveat", side_effect=OSError(errno.ENOEXEC, "fixed injected exec failure")):
        result = issue(process._TestAction.OK)
    assert result.outcome == "exec_failed" and result.errno == errno.ENOEXEC and result.reaped

    # A fake mismatching snapshot prevents release. Closing the release pipe lets
    # the directly-owned blocked child exit, and the parent still reaps it.
    child = []
    real_identity = process._identity
    def mismatch(pid, reported):
        child.append(pid)
        raise process.ProcessError("fake PID mismatch")
    with patch.object(process, "_identity", side_effect=mismatch):
        rejected(lambda: issue(process._TestAction.OK))
    assert len(child) == 1
    try:
        os.waitpid(child[0], os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError("PID mismatch child was not reaped")
    assert real_identity

    # Setup timeout occurs after fork/pidfd adoption and is cleanup-only.
    with patch.object(
        process, "_read_setup_boottime",
        side_effect=process.ProcessError("fixed setup timeout"),
    ):
        rejected(lambda: issue(process._TestAction.OK))

    # ECHILD and identity-observation failures are recorded, never thrown.
    wait_errors = []
    _, done = process._wait_nohang(os.getpid(), wait_errors, "injected", time.monotonic() + 0.1)
    assert done and wait_errors == ["injected:echild"]
    observation_child = os.fork()
    if observation_child == 0:
        time.sleep(0.25)
        os._exit(0)
    observation_identity = process.ProcessIdentity(observation_child, os.getpid(), observation_child,
                                                   observation_child, 1, process._boot_id(), False)
    with patch.object(process, "_same_identity", return_value="uncertain"):
        observed_status, cleanup_errors = process._cleanup_child(observation_child, observation_identity, None, True)
    assert observed_status is not None and "identity-uncertain-before-term" in cleanup_errors

    # A close failure is aggregated after the descriptor was actually closed.
    real_close = os.close
    injected = [False]
    def close_then_error(descriptor):
        real_close(descriptor)
        if not injected[0]:
            injected[0] = True
            raise OSError(errno.EIO, "fixed injected close failure")
    close_authority = make_issuer()
    with patch.object(process.os, "close", side_effect=close_then_error):
        rejected(lambda: close_authority(process._TestAction.OK))

    # The issued object is the sealed bytes, even if the source path changes.
    original = placeholder.read_bytes()
    sealed_authority = make_issuer()
    os.chmod(placeholder, 0o600)
    placeholder.write_bytes(b"not-the-sealed-helper")
    try:
        result = sealed_authority(process._TestAction.OK)
        assert result.status == 0 and result.stdout == b"ok\n"
    finally:
        placeholder.write_bytes(original)
        os.chmod(placeholder, 0o500)

    # A replacement also fails a new binding before fork.
    os.chmod(placeholder, 0o600)
    placeholder.write_bytes(original + b"x")
    rejected(make_issuer)
    placeholder.write_bytes(original)
    os.chmod(placeholder, 0o500)


# Imported late so the portable portion does not imply process use on macOS.
import signal
required = os.environ.get("COGS_REQUIRE_LINUX_PROCESS_TESTS_V1") == "1"
qualified = platform.system() == "Linux" and platform.machine() == "x86_64"
if required and not qualified:
    raise RuntimeError("Linux amd64 process qualification was required")
if qualified:
    linux_supervisor_tests()
    print("completion Kata process LINUX AMD64 QUALIFIED matrix passed")
else:
    print("completion Kata process portable matrix passed; Linux amd64 supervisor matrix SKIPPED")

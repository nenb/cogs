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
import tempfile
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


# Historical process-only snapshots remain byte stable; V3 is separate.
snapshots = {name: (argv, stdin, deadline, fds) for name, argv, stdin, deadline, fds in process._fixed_spec_snapshots_for_tests()}
assert snapshots["CTR_TASK_TERM"] == ((
    "/usr/bin/ctr", "--address", process.kata_operation.BASE + "/kata-runtime-v1/containerd.sock",
    "--namespace", "cogs-stage2-completion-v1", "tasks", "kill",
    "--signal", "SIGTERM", "cogs-stage2-ssh-v1",
), b"", "task-term", ())
v3_snapshots = {name: argv for name, argv, _stdin, _deadline, _fds in process._fixed_spec_snapshots_v3_for_tests()}
assert v3_snapshots["CTR_TASK_TERM"][:3] == (process.STAGED_CTR, "--address", process.CONTAINERD_SOCKET)
poll_r, poll_w = __import__("os").pipe()
try:
    poller = process.select.poll(); poller.register(poll_r, process.select.POLLIN)
    __import__("os").write(poll_w, b"x"); assert poller.poll(1000)
finally:
    __import__("os").close(poll_r); __import__("os").close(poll_w)
# A retained pidfd/descriptor is proven EBADF before a successful outcome can
# become durable; close doubt is an outcome error, never silent completion.
proof_r, proof_w = os.pipe()
proof_errors = []
assert process._close_and_prove_absent(proof_r, "portable-fd", proof_errors)
assert proof_errors == []
rejected(lambda: os.fstat(proof_r))
real_close = os.close
with patch.object(process.os, "close", side_effect=OSError(errno.EINTR, "uncertain")):
    assert not process._close_and_prove_absent(proof_w, "portable-fd", proof_errors)
real_close(proof_w)
assert proof_errors == [f"portable-fd-close:{errno.EINTR}"]
# A live failure proven before fork is a certain not-started terminal: no leader
# exists and closing every local pipe end proves EOF. Crash recovery without a
# PREEXEC record remains uncertain because fork absence is unknowable.
portable_intent = {"operation_token": "a" * 64, "command_serial": 0,
                   "command_id": "CTR_RUN", "binding_sha256": "b" * 64}
with patch.object(process.kata_operation, "_validate_body"):
    before_fork = process._outcome_body(
        portable_intent, "not-started", None, None, b"", b"",
        {"stdout": False, "stderr": False}, None, True,
        (True, True, True, True), {"term": False, "kill": False}, [], 0)
    crash_unknown = process._outcome_body(
        portable_intent, "uncertain", None, None, b"", b"",
        {"stdout": False, "stderr": False}, None, False,
        (True, False, True, False), {"term": False, "kill": False},
        ["crash-continuation"], 0)
assert before_fork["outcome"] == "not-started" and not before_fork["uncertain"] \
       and before_fork["pipes_eof"] and before_fork["leader_reaped"]
assert crash_unknown["outcome"] == "uncertain" and crash_unknown["uncertain"] \
       and not crash_unknown["pipes_eof"]
process_source = (REMOTE / "completion_kata_process.py").read_text()
assert process_source.index("_close_and_prove_absent(retained_pidfd, \"leader-pidfd\", errors)") < \
       process_source.index("durable = kata_operation._record_command_outcome(journal, body)")
rejected(lambda: process._start_fixed_daemon(object(), object()))
socket_generations = __import__("inspect").getclosurevars(process._verify_fixed_daemon).nonlocals["socket_generations"]
if not hasattr(process.os, "O_PATH"): process.os.O_PATH = 0
def socket_table(first=111, second=222):
    return (b"Num RefCount Protocol Flags Type St Inode Path\n"
            b"000: 00000002 00000000 00010000 0001 01 " + str(first).encode() + b" " + process.CONTAINERD_SOCKET.encode() + b"\n"
            b"001: 00000002 00000000 00010000 0001 01 " + str(second).encode() + b" " + process.CONTAINERD_TTRPC_SOCKET.encode() + b"\n")
root_socket = {"uid": 0, "gid": 0, "nlink": 1, "device": 7, "inode": 8}
ttrpc_socket = {**root_socket, "inode": 9}
with patch.object(process.os, "open", side_effect=[10, 11, 12]), patch.object(process.os, "read", side_effect=[socket_table(), b""]), \
     patch.object(process.os, "close"), patch.object(process.os, "listdir", return_value=["3", "4"]), \
     patch.object(process.os, "readlink", side_effect=["socket:[111]", "socket:[222]"]), \
     patch.object(process, "_host_generation", side_effect=[root_socket, ttrpc_socket]):
    assert socket_generations(41) == {"s": {"generation": root_socket, "fd_inode": 111},
                                      "s.ttrpc": {"generation": ttrpc_socket, "fd_inode": 222}}
# Deterministic process/socket readiness rejects a companion listener not held
# by the exact daemon even though both root-owned pathnames exist.
with patch.object(process.os, "open", side_effect=[10, 11, 12]), patch.object(process.os, "read", side_effect=[socket_table(), b""]), \
     patch.object(process.os, "close"), patch.object(process.os, "listdir", return_value=["3"]), \
     patch.object(process.os, "readlink", return_value="socket:[111]"), patch.object(process, "_host_generation", side_effect=[root_socket, ttrpc_socket]):
    rejected(lambda: socket_generations(41))
assert process.NFT_INPUT.endswith(b'add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop\n')
unissued = {item.command_id: item for item in process._unissued_spec_snapshots_for_tests()}
assert unissued["IP_NETNS_ADD"].tool_contract == "ip"
assert unissued["IP_NETNS_ADD"].argv_tail == ("netns", "add", "cogs-stage2-ssh")
assert unissued["IP_HOST_ADDRGEN_NONE"].argv_tail == (
    "link", "set", "dev", "c42h0", "addrgenmode", "none",
)
assert unissued["IP_PEER_ADDRGEN_NONE"].argv_tail[-2:] == ("addrgenmode", "none")
assert unissued["NFT_INSTALL"].tool_contract == "nft"
assert unissued["NFT_INSTALL"].argv_tail == ("-f", "-")
assert unissued["NFT_INSTALL"].stdin == process.NFT_INPUT
assert snapshots["SSH_READY"][0][-2:] == ("root@192.0.2.2", "/bin/sh -s")
assert snapshots["SSH_READY"][2:] == ("ssh", (200, 201))
assert len(snapshots) == 12
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
    assert process._spec(command).deadline_class == "keygen"
assert process.OWNER_ASSIGNED_IDS == {"CTR_RUN"}

# A durable work/lifecycle expiry suppresses retry but still grants a fresh,
# bounded exact-cgroup settlement window.
class ExpiredJournal:
    def __init__(self, expected):
        self.expected, self.recorded = expected, None
    def recovery_command(self):
        intent = {"operation_token": "d" * 64, "command_serial": 7,
                  "command_id": "CTR_TASK_LIST", "host_boot_id": BOOT_A,
                  "deadline_boottime_ns": 80, "cleanup_reserve_ns": 2_000_000_000}
        preexec = {"cgroup_generation": dict(zip(process.kata_operation.GEN_KEYS, self.expected))}
        return intent, preexec, None
    def recovery_lifecycle_deadline(self): return BOOT_A, 90
    def record_command_outcome(self, body): self.recorded = body; return body
expired_capture = {}
def expired_body(_intent, outcome, _status, _errno, _stdout, _stderr, _overflow,
                 _wait, _eof, cleanup, state, errors, _release):
    expired_capture.update({"outcome": outcome, "cleanup": cleanup,
                            "state": dict(state), "errors": tuple(errors)})
    return {"uncertain": True}
expected_generation = tuple(range(len(process.kata_operation.GEN_KEYS)))
expired_journal = ExpiredJournal(expected_generation)
with patch.object(process, "_boottime_ns", return_value=100), \
     patch.object(process, "_boot_id", return_value=BOOT_A), \
     patch.object(process, "_recover_cgroup", return_value=(True, True)) as recover, \
     patch.object(process, "_outcome_body", side_effect=expired_body):
    assert process._recover_pending_fixed(expired_journal) == {"uncertain": True}
recover.assert_called_once_with(
    process.CGROUP_BASE + "/" + "d" * 64 + "-7", expected_generation,
    2_000_000_100, {"term": False, "kill": False}, ["crash-continuation", "lifecycle-deadline-expired"])
assert expired_capture == {"outcome": "uncertain",
                           "cleanup": (True, False, True, False),
                           "state": {"term": False, "kill": False},
                           "errors": ("crash-continuation", "lifecycle-deadline-expired")}

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
  if (!strcmp(argv[1], "held-pipe")) { pid_t child=fork(); if (child<0) return 93; if (!child) { usleep(1500000); _exit(0); } return 0; }
  if (!strcmp(argv[1], "fd")) { if (fcntl(198, F_GETFD) == -1 && errno == EBADF) return write_all(1,"closed\n",7) == 0 ? 0 : 96; return 91; }
  if (!strcmp(argv[1], "high-fd")) { if (fcntl(4096, F_GETFD) == -1 && errno == EBADF) return write_all(1,"high-closed\n",12) == 0 ? 0 : 96; return 94; }
  if (!strcmp(argv[1], "inherited")) { char a=0,b=0; if (read(200,&a,1)==1 && read(201,&b,1)==1 && a=='K' && b=='H' && fcntl(202,F_GETFD)==-1 && errno==EBADF) return write_all(1,"inherited\n",10) == 0 ? 0 : 96; return 95; }
  return 92;
}
'''


DAEMON = r'''#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static char paths[2][108]; static int listeners[2];
static void stop(int signal_number) { (void)signal_number; for(int i=0;i<2;i++){close(listeners[i]);unlink(paths[i]);} _exit(0); }
int main(int argc, char **argv) {
  const char *path = 0;
  for (int i=1; i+1<argc; ++i) if (!strcmp(argv[i],"--address")) path=argv[i+1];
  if (!path || strlen(path)+strlen(".ttrpc") >= sizeof(paths[0])) return 90;
  size_t length=strlen(path); memcpy(paths[0],path,length+1); memcpy(paths[1],path,length); memcpy(paths[1]+length,".ttrpc",7);
  for(int i=0;i<2;i++){ listeners[i]=socket(AF_UNIX,SOCK_STREAM,0); struct sockaddr_un address={.sun_family=AF_UNIX};
    memcpy(address.sun_path,paths[i],strlen(paths[i])+1); unlink(paths[i]);
    if(listeners[i]<0||bind(listeners[i],(void*)&address,sizeof(address))||listen(listeners[i],1))return 91; }
  signal(SIGTERM,stop);
  for(;;)pause();
}
'''


def authentic_daemon_transaction_profile():
    """Run real child/cgroup transactions beside one retained dummy daemon."""
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() != 0 or not os.access(process.CGROUP_ROOT, os.W_OK):
        return False
    saved = (process.CONTAINERD_SOCKET, process.CONTAINERD_TTRPC_SOCKET, process.CONTAINERD_ROOT,
             process.CONTAINERD_STATE, process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD, process.STAGED_CTR)
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        root = Path(directory); daemon_path = root / "containerd"; source = root / "daemon.c"
        source.write_text(DAEMON, encoding="ascii")
        subprocess.run(["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", daemon_path, source], check=True)
        runtime = root / "runtime"; runtime.mkdir(); (runtime / "root").mkdir(); (runtime / "state").mkdir()
        (runtime / "config").write_bytes(b"")
        process.CONTAINERD_SOCKET, process.CONTAINERD_ROOT = str(runtime / "socket"), str(runtime / "root")
        process.CONTAINERD_TTRPC_SOCKET = process.CONTAINERD_SOCKET + ".ttrpc"
        process.CONTAINERD_STATE, process.CONTAINERD_CONFIG = str(runtime / "state"), str(runtime / "config")
        process.STAGED_CONTAINERD, process.STAGED_CTR = str(daemon_path), str(root / "ctr")
        class Journal:
            def __init__(self): self.serial = 0; self.daemon = None
            def command_context(self):
                return process.kata_operation.CommandContext(
                    "b" * 64, {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
                    process._boot_id(), "5" * 40, "NETWORK_READY", self.serial)
            def record_command_intent(self, body):
                process.kata_operation._validate_body("COMMAND_INTENT_V2", body); return body
            def record_command_preexec(self, body):
                process.kata_operation._validate_body("COMMAND_PREEXEC_V2", body); return body
            def record_command_output(self, body):
                process.kata_operation._validate_body("COMMAND_OUTPUT_V3", body); return body
            def record_command_outcome(self, body):
                process.kata_operation._validate_body("COMMAND_OUTCOME_V2", body); self.serial += 1
                return process.kata_operation.DurableCommandOutcome(
                    body["command_serial"], body["command_id"], body["binding_sha256"], body)
            def record_daemon_retained(self, body):
                process.kata_operation._validate_body("DAEMON_RETAINED_V2", body); self.daemon = body; self.serial += 1; return body
            def record_daemon_outcome(self, body):
                process.kata_operation._validate_body("DAEMON_OUTCOME_V2", body); return body
        daemon_fd = os.open(daemon_path, os.O_RDONLY | os.O_CLOEXEC)
        true_fd = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
        def retained(role, path, descriptor):
            seen = os.fstat(descriptor)
            return process.RetainedExecutable(role, path, descriptor, process._digest_fd(
                descriptor, seen.st_size), "d" * 64, process._host_generation(descriptor))
        daemon_executable = retained("containerd", process.STAGED_CONTAINERD, daemon_fd)
        ctr_executable = retained("ctr", process.STAGED_CTR, true_fd)
        try:
            for fault in (None, "foreign-child", "foreign-leaf", "post-fork"):
                journal = Journal(); owner = process._start_fixed_daemon(journal, daemon_executable)
                profile = process._fixed_daemon_transaction_profile(owner, journal)
                foreign_pid = None; foreign_leaf = process.CGROUP_BASE + "/foreign"
                try:
                    assert process._child_census() == (profile.pid,)
                    if fault == "foreign-child":
                        foreign_pid = os.fork()
                        if foreign_pid == 0: time.sleep(30); os._exit(0)
                    if fault == "foreign-leaf": os.mkdir(foreign_leaf, 0o700)
                    fixed = process._bind_ctr_extension(process.CommandId.CTR_TASK_LIST)
                    patches = [patch.object(process.kata_runtime, "_verify_runtime_consumption", return_value=None)]
                    if fault == "post-fork": patches.append(patch.object(
                        process, "_identity", side_effect=process.ProcessError("fault after fork")))
                    with patches[0]:
                        if len(patches) == 2: patches[1].start()
                        try:
                            if fault is None:
                                outcome, durable = process._transact_fixed(journal, fixed, ctr_executable,
                                    daemon_owner=owner, consumption_owner=object())
                                assert (outcome.outcome, outcome.status, outcome.errors) == ("exited", 0, ()) and not durable.body["uncertain"]
                            else: rejected(lambda: process._transact_fixed(journal, fixed, ctr_executable,
                                daemon_owner=owner, consumption_owner=object()))
                        finally:
                            if len(patches) == 2: patches[1].stop()
                    if foreign_pid is not None:
                        os.kill(foreign_pid, signal.SIGKILL); os.waitpid(foreign_pid, 0); foreign_pid = None
                    if os.path.isdir(foreign_leaf): os.rmdir(foreign_leaf)
                    assert process._verify_fixed_daemon(owner, journal)["pid"] == profile.pid
                    base_fd, _generation = process._directory_identity(process.CGROUP_BASE)
                    try: assert process._cgroup_leaf_names(base_fd) == {profile.leaf_name}
                    finally: os.close(base_fd)
                finally:
                    if foreign_pid is not None:
                        os.kill(foreign_pid, signal.SIGKILL); os.waitpid(foreign_pid, 0)
                    if os.path.isdir(foreign_leaf): os.rmdir(foreign_leaf)
                    process._stop_fixed_daemon(owner, journal)
                assert (not os.path.exists(process.CGROUP_BASE) and not os.path.lexists(process.CONTAINERD_SOCKET)
                        and not os.path.lexists(process.CONTAINERD_TTRPC_SOCKET))
            return True
        finally:
            os.close(daemon_fd); os.close(true_fd)
            (process.CONTAINERD_SOCKET, process.CONTAINERD_TTRPC_SOCKET, process.CONTAINERD_ROOT,
             process.CONTAINERD_STATE, process.CONTAINERD_CONFIG, process.STAGED_CONTAINERD, process.STAGED_CTR) = saved


def authentic_root_cgroup_recovery():
    """Crash one supervisor, then recover its leader-absent descendant fresh."""
    if platform.system() != "Linux" or os.geteuid() != 0 or not os.access(process.CGROUP_ROOT, os.W_OK):
        return False
    token = "c" * 64
    path = f"{process.CGROUP_BASE}/{token}-4242"
    report_r, report_w = os.pipe2(os.O_CLOEXEC)
    supervisor = os.fork()
    if supervisor == 0:
        try:
            os.close(report_r)
            context = process.kata_operation.CommandContext(
                token, {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
                process._boot_id(), "5" * 40, "NETWORK_READY", 4242,
            )
            owner = process._prepare_cgroup(context)
            gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
            child_r, child_w = os.pipe2(os.O_CLOEXEC)
            leader = os.fork()
            if leader == 0:
                os.close(gate_w); os.close(child_r)
                if os.read(gate_r, 1) != b"R": os._exit(90)
                descendant = os.fork()
                if descendant == 0:
                    time.sleep(30); os._exit(0)
                os.write(child_w, f"{descendant}\n".encode("ascii")); os._exit(0)
            os.close(gate_r); os.close(child_w)
            process._register_cgroup(owner, leader)
            os.write(gate_w, b"R"); os.close(gate_w)
            descendant = int(os.read(child_r, 32)); os.close(child_r)
            os.waitpid(leader, 0)
            payload = json.dumps({"expected": owner.leaf_generation,
                                  "base_created": owner.base_created,
                                  "descendant": descendant}).encode() + b"\n"
            os.write(report_w, payload)
        finally:
            os._exit(77)  # descriptor/process-owner crash cut
    os.close(report_w)
    raw = b""
    while True:
        part = os.read(report_r, 4096)
        if not part: break
        raw += part
    os.close(report_r)
    assert os.waitpid(supervisor, 0)[1] == 77 << 8
    value = json.loads(raw)
    previous = None
    try:
        class ExpiredNativeJournal:
            def recovery_command(self):
                intent = {"operation_token": token, "command_serial": 4242,
                          "command_id": "CTR_TASK_LIST", "host_boot_id": process._boot_id(),
                          "deadline_boottime_ns": process._boottime_ns() - 1,
                          "cleanup_reserve_ns": 2_000_000_000}
                preexec = {"cgroup_generation": dict(zip(
                    process.kata_operation.GEN_KEYS, value["expected"]))}
                return intent, preexec, None
            def recovery_lifecycle_deadline(self):
                return process._boot_id(), process._boottime_ns() - 1
            def record_command_outcome(self, body): return body
        captured = {}
        def native_body(_intent, _outcome, _status, _errno, _stdout, _stderr, _overflow,
                        _wait, _eof, cleanup, recovery_state, recovery_errors, _release):
            captured.update({"cleanup": cleanup, "state": dict(recovery_state),
                             "errors": tuple(recovery_errors)})
            return {"uncertain": True}
        with patch.object(process, "_outcome_body", side_effect=native_body):
            assert process._recover_pending_fixed(ExpiredNativeJournal()) == {"uncertain": True}
        assert captured["cleanup"] == (True, False, True, False)
        assert captured["state"]["kill"] and "lifecycle-deadline-expired" in captured["errors"]
        assert not os.path.exists(path)
        # Exact production settlement also reaps a quick adopted descendant.
        previous = process._set_subreaper(True)
        owner = process._prepare_cgroup(process.kata_operation.CommandContext(
            token, {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
            process._boot_id(), "5" * 40, "NETWORK_READY", 4243,
        ))
        gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
        quick_r, quick_w = os.pipe2(os.O_CLOEXEC)
        leader = os.fork()
        if leader == 0:
            os.close(gate_w); os.close(quick_r)
            if os.read(gate_r, 1) != b"R": os._exit(90)
            if os.fork() == 0:
                os.write(quick_w, b"Z"); os._exit(0)
            os._exit(0)
        os.close(gate_r); os.close(quick_w); process._register_cgroup(owner, leader)
        os.write(gate_w, b"R"); os.close(gate_w)
        assert os.read(quick_r, 1) == b"Z"; os.close(quick_r); time.sleep(0.05)
        settle_errors = []
        settled = process._settle_cgroup(
            owner, leader, process._boottime_ns() + 2_000_000_000, settle_errors,
        )
        process._set_subreaper(previous); previous = None
        assert all(settled) and settle_errors == []
        return True
    finally:
        for cleanup_path in (path, f"{process.CGROUP_BASE}/{token}-4243"):
            if os.path.exists(cleanup_path):
                process._recover_cgroup(cleanup_path, None, process._boottime_ns() + 2_000_000_000,
                                        {"term": False, "kill": False}, [])
        if previous is not None: process._set_subreaper(previous)
        if value["base_created"] and os.path.isdir(process.CGROUP_BASE):
            try: os.rmdir(process.CGROUP_BASE)
            except OSError: pass


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
            self.intent = self.preexec = self.output = self.outcome = None
        def command_context(self):
            return self.context
        def record_command_intent(self, body):
            process.kata_operation._validate_body("COMMAND_INTENT_V2", body)
            self.intent = body
        def record_command_preexec(self, body):
            process.kata_operation._validate_body("COMMAND_PREEXEC_V2", body)
            self.preexec = body
        def record_command_output(self, body):
            process.kata_operation._validate_body("COMMAND_OUTPUT_V3", body)
            self.output = body
            return body
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
        def settle(value, leader, deadline, _errors, _daemon_profile=None):
            for pid, (descriptor, _row) in tuple(value.pidfds.items()):
                if pid != leader:
                    while time.monotonic_ns() < deadline:
                        try:
                            observed, _status = os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if observed == pid:
                            break
                        time.sleep(0.005)
                try: os.close(descriptor)
                except OSError: pass
            value.pidfds.clear()
            descendants_reaped = False
            while time.monotonic_ns() < deadline:
                _leader_reaped, descendants_reaped = process._wait_all_children(leader, _errors)
                if descendants_reaped:
                    break
                time.sleep(0.005)
            return True, descendants_reaped, True, False
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
            command_id = process.CommandId.CTR_TASK_LIST
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
    assert result.outcome == "uncertain" and result.timed_out
    assert time.monotonic() - started < 3

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
    key_r, key_path = tempfile.mkstemp(dir=directory)
    hosts_r, hosts_path = tempfile.mkstemp(dir=directory)
    os.write(key_r, b"K"); os.write(hosts_r, b"H")
    os.lseek(key_r, 0, os.SEEK_SET); os.lseek(hosts_r, 0, os.SEEK_SET)
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
        os.unlink(key_path); os.unlink(hosts_path)

    # close_range reaches inherited descriptors above a subsequently lowered limit.
    base = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    old_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    high_floor = min(4096, old_limit[0] - 1)
    assert high_floor > 256
    high = __import__("fcntl").fcntl(base, __import__("fcntl").F_DUPFD, high_floor)
    os.set_inheritable(high, True)
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
    assert result.outcome == "exec-failed" and result.errno == errno.ENOEXEC and result.reaped

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

    # Setup timeout and the first pidfd-open failure after fork still perform a
    # bounded direct wait; neither may fabricate a not-started reap fact.
    with patch.object(
        process, "_read_setup_boottime",
        side_effect=process.ProcessError("fixed setup timeout"),
    ):
        rejected(lambda: issue(process._TestAction.OK))
    with patch.object(process, "_usable_pidfd_open", side_effect=OSError(errno.EIO, "pidfd")):
        rejected(lambda: issue(process._TestAction.OK))
    process._require_no_children()

    # Restoration failure is folded into uncertainty before journal settlement.
    subreaper_calls = 0
    def fail_restore(enabled):
        nonlocal subreaper_calls
        subreaper_calls += 1
        if subreaper_calls == 1: return False
        raise OSError(errno.EIO, "restore")
    with patch.object(process, "_set_subreaper", side_effect=fail_restore):
        result = issue(process._TestAction.OK)
    assert result.outcome == "uncertain" and "subreaper-restore:OSError" in result.errors

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
if sys.argv[1:] == ["--daemon-transactions"]:
    if not authentic_daemon_transaction_profile():
        raise RuntimeError("root Linux retained-daemon transaction matrix was required")
    print("retained dummy-daemon transaction/fault matrix passed; no KVM")
    raise SystemExit(0)
if sys.argv[1:]:
    raise RuntimeError("unexpected process-test arguments")
required = os.environ.get("COGS_REQUIRE_LINUX_PROCESS_TESTS_V1") == "1"
qualified = platform.system() == "Linux" and platform.machine() == "x86_64"
foundations_required = os.environ.get("COGS_REQUIRE_STAGE2_KATA_NATIVE_FOUNDATIONS") == "1"
if required and not qualified:
    raise RuntimeError("Linux amd64 process qualification was required")
if foundations_required and (not qualified or os.geteuid() != 0):
    raise RuntimeError("root Linux amd64 Kata native foundations were required")
root_cgroup = authentic_root_cgroup_recovery()
daemon_transactions = authentic_daemon_transaction_profile()
if foundations_required and not (root_cgroup and daemon_transactions):
    raise RuntimeError("journal/cgroup and retained-daemon transaction foundations were required")
if qualified:
    linux_supervisor_tests()
    print("completion Kata process LINUX AMD64 QUALIFIED matrix passed" +
          ("; root cgroup crash matrix passed" if root_cgroup else "; root cgroup crash matrix SKIPPED") +
          ("; retained daemon transaction matrix passed" if daemon_transactions else "; retained daemon transaction matrix SKIPPED"))
else:
    print("completion Kata process portable matrix passed; Linux amd64 supervisor matrix SKIPPED; " +
          ("root cgroup crash matrix passed" if root_cgroup else "root cgroup crash matrix SKIPPED"))

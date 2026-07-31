#!/usr/bin/python3
"""Standalone Job B child-sandbox experiment matrix.

Rebuilds the child environment that completion_trusted_runtime_launcher.py
creates at f7170704 (outer -> namespace owner -> tool child) without importing
or executing the production launcher.  Each leg toggles one sandbox layer and
reports exactly how the exec'd tool settles, draining the child output pipe on
early exit.  Diagnostic only: the payloads are the fixed qualification vectors.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import struct
import sys
import time

_AT_EMPTY_PATH = 0x1000
(_PR_SET_DUMPABLE, _PR_SET_NO_NEW_PRIVS, _PR_SET_SECCOMP, _PR_GET_SECCOMP) = (4, 38, 22, 21)
(_PR_CAPBSET_DROP, _PR_CAPBSET_READ, _PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL) = (24, 23, 47, 4)
(_PR_SET_SECUREBITS, _PR_SET_PDEATHSIG, _SECBITS) = (28, 1, 0x0F)
_SECCOMP_MODE_FILTER = 2
_F_ADD_SEALS, _F_GET_SEALS = 1033, 1034
(_F_SEAL_SEAL, _F_SEAL_SHRINK, _F_SEAL_GROW) = (0x0001, 0x0002, 0x0004)
(_F_SEAL_WRITE, _F_SEAL_FUTURE_WRITE, _F_SEAL_EXEC) = (0x0008, 0x0010, 0x0020)
_DATA_SEALS = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE | _F_SEAL_FUTURE_WRITE
_EXEC_SEALS = _DATA_SEALS | _F_SEAL_EXEC
(_CLONE_NEWNS, _CLONE_NEWUSER, _CLONE_NEWPID, _CLONE_NEWNET) = (0x00020000, 0x10000000, 0x20000000, 0x40000000)
(_MS_RDONLY, _MS_NOSUID, _MS_NODEV, _MS_NOEXEC) = (1, 2, 4, 8)
_MS_REMOUNT, _MS_PRIVATE, _MS_REC = 32, 1 << 18, 16384
(_SYS_CLONE3, _CLONE_PIDFD) = (435, 0x00001000)
_INTERPRETER, _LIBRARY_ROOT = "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu"
_ROOT = "/tmp/cogs-o2-experiment-root"

_FIXED_INPUT = {
    "gzip": bytes.fromhex("1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e"
                          "2cc9cccfd32d33e40200a9c9b5521e000000"),
    "zstd": bytes.fromhex("28b52ffd201ef10000636f67732d72756e74696d652d7175616c696669636174696f6e2d76310a"),
}
_FIXED_OUTPUT = b"cogs-runtime-qualification-v1\n"
_TOOL_PATH = {"gzip": "/usr/bin/gzip", "zstd": "/usr/bin/zstd"}

_DENIED_SYSCALLS = {name: int(number) for entry in """
    execve:59 socket:41 connect:42 accept:43 sendto:44 recvfrom:45 sendmsg:46 recvmsg:47 shutdown:48 bind:49 listen:50 getsockname:51 getpeername:52 socketpair:53 setsockopt:54 getsockopt:55 accept4:288 recvmmsg:299 sendmmsg:307
    io_uring_setup:425 io_uring_enter:426 io_uring_register:427 clone:56 fork:57 vfork:58 clone3:435 unshare:272 setns:308
    mount:165 umount2:166 pivot_root:155 chroot:161 open_tree:428 move_mount:429 fsopen:430 fsconfig:431 fsmount:432 fspick:433 mount_setattr:442
    keyctl:250 add_key:248 request_key:249 perf_event_open:298 bpf:321 userfaultfd:323 ptrace:101 init_module:175 delete_module:176 finit_module:313
    setuid:105 setgid:106 setreuid:113 setregid:114 setgroups:116 setresuid:117 setresgid:119 setfsuid:122 setfsgid:123 capset:126 seccomp:317
    memfd_create:319 open_by_handle_at:304 name_to_handle_at:303 pidfd_open:434 pidfd_getfd:438 process_vm_readv:310 process_vm_writev:311 kexec_load:246 kexec_file_load:320 landlock_create_ruleset:444 landlock_add_rule:445 landlock_restrict_self:446 dup:32 dup2:33 dup3:292 fcntl:72
    """.split() for name, number in (entry.split(":"),)}


def _seccomp_program():
    deny, allow = 0x00050000 | errno.EPERM, 0x7FFF0000
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0), (0x15, 0, 10, 322), (0x20, 0, 0, 16), (0x15, 0, 6, 198), (0x20, 0, 0, 20), (0x15, 0, 4, 0), (0x20, 0, 0, 48), (0x15, 0, 2, _AT_EMPTY_PATH), (0x20, 0, 0, 52), (0x15, 1, 0, 0), (0x06, 0, 0, deny), (0x06, 0, 0, allow), (0x15, 0, 4, 157), (0x20, 0, 0, 16), (0x15, 1, 0, _PR_GET_SECCOMP), (0x06, 0, 0, deny), (0x06, 0, 0, allow), (0x20, 0, 0, 0)]
    rows.extend(((0x15, 0, 7, _DENIED_SYSCALLS["fcntl"]),
                 (0x20, 0, 0, 28), (0x15, 0, 3, 0), (0x20, 0, 0, 24),
                 (0x15, 2, 0, fcntl.F_GETFD), (0x15, 1, 0, fcntl.F_GETFL),
                 (0x06, 0, 0, deny), (0x06, 0, 0, allow)))
    for number in dict.fromkeys(_DENIED_SYSCALLS.values()):
        if number != _DENIED_SYSCALLS["fcntl"]:
            rows.extend(((0x15, 0, 1, number), (0x06, 0, 0, deny)))
    rows.append((0x06, 0, 0, allow))
    return tuple(rows)


libc = ctypes.CDLL(None, use_errno=True)


def checked(result, what):
    if result == -1:
        raise OSError(ctypes.get_errno(), what)
    return result


def install_seccomp():
    instructions = _seccomp_program()

    class Filter(ctypes.Structure):
        _fields_ = (("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32))

    class Program(ctypes.Structure):
        _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter)))

    program = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
    checked(libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(Program(len(program), program))), "seccomp")
    return hashlib.sha256(b"".join(struct.pack("HBBI", *row) for row in instructions)).hexdigest()


def probe_seccomp_denials():
    probes = {name: (number, -1, -1, -1, -1, -1, -1) for name, number in _DENIED_SYSCALLS.items()}
    probes["prctl:set"] = (157, _PR_SET_SECCOMP, 0, 0, 0, 0)
    probes["execveat:shape"] = (322, -1, 0, 0, 0, 0)
    observed = {}
    for name, arguments in probes.items():
        ctypes.set_errno(0)
        result = libc.syscall(*arguments)
        saved = ctypes.get_errno()
        if result == 0 and name in ("fork", "vfork"):
            os._exit(127)
        if result != -1 or saved != errno.EPERM:
            raise RuntimeError(f"seccomp denial mismatch: {name}:{result}:{saved}")
        observed[name] = saved
    return observed


def drop_bounding():
    for capability in range(256):
        ctypes.set_errno(0)
        present = libc.prctl(_PR_CAPBSET_READ, capability, 0, 0, 0)
        if present == -1 and ctypes.get_errno() == errno.EINVAL:
            return
        if present == 1:
            checked(libc.prctl(_PR_CAPBSET_DROP, capability, 0, 0, 0), "capbset-drop")


def capset_zero():
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    data = (ctypes.c_uint32 * 6)()
    checked(libc.syscall(126, header, data), "capset")


def clone_pidfd():
    pidfd = ctypes.c_int(-1)
    values = (ctypes.c_uint64 * 11)(_CLONE_PIDFD, ctypes.addressof(pidfd), 0, 0, signal.SIGCHLD, 0, 0, 0, 0, 0, 0)
    pid = checked(libc.syscall(_SYS_CLONE3, ctypes.byref(values), ctypes.sizeof(values)), "clone3")
    return pid, pidfd.value


def execveat(fd, argv_values, env_values):
    argv = (ctypes.c_char_p * (len(argv_values) + 1))(*(item.encode() for item in argv_values), None)
    envp = (ctypes.c_char_p * (len(env_values) + 1))(*(item.encode() for item in env_values), None)
    checked(libc.syscall(322, fd, b"", argv, envp, _AT_EMPTY_PATH), "execveat")


def read_text(path, limit=8192):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError as error:
        return f"<{error.errno}>".encode()


def child_state(pid):
    raw = read_text(f"/proc/{pid}/stat")
    marker = raw.rfind(b") ")
    return raw[marker + 2:marker + 3].decode() if marker >= 0 else "?"


def child_syscall(pid):
    return read_text(f"/proc/{pid}/syscall", 256).split()[:2]


def materialize(root, tool):
    os.makedirs(root, mode=0o700, exist_ok=True)
    checked(libc.mount(b"tmpfs", root.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV,
                       b"mode=0700,size=536870912,nr_inodes=512"), "mount-tmpfs")
    for relative in ("bin", "lib64", "lib", "lib/x86_64-linux-gnu"):
        os.makedirs(f"{root}/{relative}", mode=0o755, exist_ok=True)
    sources = [(_TOOL_PATH[tool], f"{root}/bin/{tool}"), (_INTERPRETER, root + _INTERPRETER)]
    for name in os.listdir(_LIBRARY_ROOT):
        if name.startswith(("libc.so", "libzstd.so", "libm.so", "libgcc_s.so", "libpthread.so")):
            sources.append((f"{_LIBRARY_ROOT}/{name}", f"{root}{_LIBRARY_ROOT}/{name}"))
    for source, target in sources:
        if os.path.islink(source):
            source = os.path.realpath(source)
        with open(source, "rb") as reader:
            payload = reader.read()
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o500)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o555)
        os.close(descriptor)


def sealed_executable(tool):
    with open(_TOOL_PATH[tool], "rb") as handle:
        payload = handle.read()
    mfd = os.memfd_create("exec", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(mfd, payload)
    try:
        fcntl.fcntl(mfd, _F_ADD_SEALS, _EXEC_SEALS)
    except OSError:
        fcntl.fcntl(mfd, _F_ADD_SEALS, _DATA_SEALS)
    return mfd, hashlib.sha256(payload).hexdigest()[:12]


def run_child(options, tool, root, input_fd, output_fd, status_fd):
    """Mirror _child_fd_install -> _enter_boundary -> execveat."""
    input_copy = fcntl.fcntl(input_fd, fcntl.F_DUPFD_CLOEXEC, 256)
    output_copy = fcntl.fcntl(output_fd, fcntl.F_DUPFD_CLOEXEC, 256)
    os.dup2(input_copy, 0, inheritable=True)
    os.dup2(output_copy, 1, inheritable=True)
    os.dup2(output_copy, 2, inheritable=True)
    os.close(input_copy)
    os.close(output_copy)
    allowed = {0, 1, 2, 198, status_fd}
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if options["chroot"]:
        os.chroot(root)
        os.chdir("/")
    checked(libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0), "dumpable")
    checked(libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0), "ambient-clear")
    if options["caps"]:
        drop_bounding()
        checked(libc.prctl(_PR_SET_SECUREBITS, _SECBITS, 0, 0, 0), "securebits")
        capset_zero()
    checked(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "nnp")
    observations = {}
    if options["seccomp"]:
        observations["seccomp_program_sha256"] = install_seccomp()
        if options["probes"]:
            observations["seccomp_denials"] = probe_seccomp_denials()
    boundary = json.dumps({"kind": "boundary", "observations": observations}).encode()
    os.write(status_fd, boundary)
    argv = (tool, "-q", "-d", "-c") if tool == "zstd" else (tool, "-d", "-c")
    execveat(198, argv, ("LC_ALL=C",))


def run_owner(options, tool, report_fd, gate_read, sync_write):
    """Mirror _namespace_owner: unshare, materialize, spawn child, observe."""
    root = _ROOT
    checked(libc.unshare(_CLONE_NEWUSER), "unshare-user")
    os.write(sync_write, b"U")
    if os.read(gate_read, 1) != b"M":
        raise RuntimeError("uid map gate")
    if os.getgroups():
        os.setgroups([])
    checked(libc.unshare(_CLONE_NEWNS | _CLONE_NEWPID | _CLONE_NEWNET), "unshare-sandbox")
    checked(libc.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None), "private-root")
    materialize(root, tool)
    if options["sealed"]:
        exec_fd, digest = sealed_executable(tool)
    else:
        exec_fd = os.open(f"{root}/bin/{tool}", os.O_RDONLY | os.O_CLOEXEC)
        digest = "materialized"
    os.dup2(exec_fd, 198, inheritable=False)
    os.close(exec_fd)
    fcntl.fcntl(198, fcntl.F_SETFD, fcntl.fcntl(198, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
    input_read, input_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    child, child_pidfd = clone_pidfd()
    if child == 0:
        try:
            os.close(status_read)
            checked(libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0), "pdeathsig")
            run_child(options, tool, root, input_read, output_write, status_write)
        except BaseException as error:
            try:
                os.write(status_write, f"child-error:{type(error).__name__}:{error}".encode()[:512])
            finally:
                os._exit(126)
    os.close(status_write)
    os.close(input_read)
    os.close(output_write)

    boundary = bytearray()
    deadline = time.monotonic() + 10
    while True:
        remaining = max(0.0, deadline - time.monotonic())
        if not select.select([status_read], [], [], remaining)[0]:
            break
        part = os.read(status_read, 65536)
        if not part:
            break
        boundary += part
    os.close(status_read)

    settled = os.waitpid(child, os.WNOHANG)
    state, syscall = child_state(child), child_syscall(child)
    comm = read_text(f"/proc/{child}/comm", 64).strip().decode(errors="replace")
    for _ in range(300):
        if settled[0] != 0:
            break
        settled = os.waitpid(child, os.WNOHANG)
        if settled[0] != 0:
            break
        state, syscall = child_state(child), child_syscall(child)
        if state in ("S", "R") and syscall[:1] == [b"0"]:
            break
        time.sleep(0.01)

    report = {"boundary_bytes": len(boundary), "boundary_head": boundary[:120].decode(errors="replace"),
              "exec_digest": digest, "comm": comm, "state": state,
              "syscall": [item.decode(errors="replace") for item in syscall]}

    if settled[0] != 0:
        code = settled[1]
        report["settled"] = "exited" if os.WIFEXITED(code) else "signaled"
        report["status"] = os.WEXITSTATUS(code) if os.WIFEXITED(code) else os.WTERMSIG(code)
        drained = b""
        while select.select([output_read], [], [], 0.25)[0]:
            part = os.read(output_read, 65536)
            if not part:
                break
            drained += part
        report["early_output_len"] = len(drained)
        report["early_output"] = drained[:600].decode(errors="replace")
        report["early_output_sha256"] = hashlib.sha256(drained).hexdigest()[:12]
    else:
        os.write(input_write, _FIXED_INPUT[tool])
        os.close(input_write)
        output = b""
        deadline = time.monotonic() + 10
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            if not select.select([output_read], [], [], remaining)[0]:
                break
            part = os.read(output_read, 65536)
            if not part:
                break
            output += part
        final = os.waitpid(child, 0)
        report["settled"] = "exited" if os.WIFEXITED(final[1]) else "signaled"
        report["status"] = os.WEXITSTATUS(final[1]) if os.WIFEXITED(final[1]) else os.WTERMSIG(final[1])
        report["output_exact"] = output == _FIXED_OUTPUT
        report["output_len"] = len(output)
        report["output"] = output[:120].decode(errors="replace")
    os.write(report_fd, json.dumps(report).encode())
    os._exit(0)


def run_leg(name, options):
    tool = options["tool"]
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    sync_read, sync_write = os.pipe2(os.O_CLOEXEC)
    outer_uid, outer_gid = os.getuid(), os.getgid()
    owner, owner_pidfd = clone_pidfd()
    if owner == 0:
        try:
            os.close(report_read)
            os.close(gate_write)
            os.close(sync_read)
            os.setsid()
            run_owner(options, tool, report_write, gate_read, sync_write)
        except BaseException as error:
            try:
                os.write(report_write, json.dumps({"owner_error": f"{type(error).__name__}:{error}"}).encode())
            finally:
                os._exit(125)
    os.close(report_write)
    os.close(gate_read)
    os.close(sync_write)
    result = {"leg": name}
    try:
        if not select.select([sync_read], [], [], 10)[0] or os.read(sync_read, 1) != b"U":
            raise RuntimeError("owner userns handshake")
        with open(f"/proc/{owner}/uid_map", "w") as handle:
            handle.write(f"0 {outer_uid} 1\n")
        try:
            with open(f"/proc/{owner}/setgroups", "w") as handle:
                handle.write("deny\n")
        except FileNotFoundError:
            pass
        with open(f"/proc/{owner}/gid_map", "w") as handle:
            handle.write(f"0 {outer_gid} 1\n")
        os.write(gate_write, b"M")
        raw = bytearray()
        deadline = time.monotonic() + 60
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            if not select.select([report_read], [], [], remaining)[0]:
                result["error"] = "owner report timeout"
                break
            part = os.read(report_read, 65536)
            if not part:
                break
            raw += part
        if raw:
            result.update(json.loads(raw.decode()))
    except BaseException as error:
        result["error"] = f"{type(error).__name__}:{error}"
    finally:
        for descriptor in (report_read, gate_write, sync_read):
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            owner_settled = os.waitpid(owner, 0)
            result["owner_status"] = os.WEXITSTATUS(owner_settled[1]) if os.WIFEXITED(owner_settled[1]) else -os.WTERMSIG(owner_settled[1])
        except OSError:
            pass
    return result


LEGS = (
    ("baseline-gzip", {"tool": "gzip", "chroot": True, "seccomp": True, "caps": True, "probes": True, "sealed": True}),
    ("baseline-zstd", {"tool": "zstd", "chroot": True, "seccomp": True, "caps": True, "probes": True, "sealed": True}),
    ("no-probes", {"tool": "gzip", "chroot": True, "seccomp": True, "caps": True, "probes": False, "sealed": True}),
    ("no-seccomp", {"tool": "gzip", "chroot": True, "seccomp": False, "caps": True, "probes": False, "sealed": True}),
    ("no-caps", {"tool": "gzip", "chroot": True, "seccomp": True, "caps": False, "probes": True, "sealed": True}),
    ("no-chroot", {"tool": "gzip", "chroot": False, "seccomp": True, "caps": True, "probes": True, "sealed": True}),
    ("materialized-exec", {"tool": "gzip", "chroot": True, "seccomp": True, "caps": True, "probes": True, "sealed": False}),
    ("bare", {"tool": "gzip", "chroot": False, "seccomp": False, "caps": False, "probes": False, "sealed": True}),
)


def environment_facts():
    import resource
    facts = {
        "uname": os.uname().release,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
    }
    status = read_text("/proc/self/status", 65536)
    for label in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb", b"Seccomp"):
        match = re.search(rb"(?:^|\n)" + label + rb":\s*([0-9a-fA-Fx]+)\n", status)
        facts[label.decode()] = match.group(1).decode() if match else None
    for path in ("/proc/sys/kernel/unprivileged_userns_clone",
                 "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                 "/proc/sys/user/max_user_namespaces"):
        facts[os.path.basename(path)] = read_text(path, 64).strip().decode(errors="replace")
    for tool, path in _TOOL_PATH.items():
        try:
            with open(path, "rb") as handle:
                payload = handle.read()
            facts[f"{tool}_sha256"] = hashlib.sha256(payload).hexdigest()[:16]
            facts[f"{tool}_size"] = len(payload)
        except OSError as error:
            facts[f"{tool}_error"] = str(error)
    return facts


def main():
    print("== environment ==", flush=True)
    print(json.dumps(environment_facts(), indent=None), flush=True)
    selected = set(sys.argv[1:])
    print("== legs ==", flush=True)
    for name, options in LEGS:
        if selected and name not in selected:
            continue
        started = time.monotonic()
        try:
            result = run_leg(name, dict(options))
        except BaseException as error:
            result = {"leg": name, "harness_error": f"{type(error).__name__}:{error}"}
        result["seconds"] = round(time.monotonic() - started, 2)
        print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

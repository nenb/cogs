#!/usr/bin/python3
"""Exit-code census for the Job B tool child.

Hunts for the observed status 104 by exec'ing candidate executables under the
launcher-shaped sandbox with varied closures, argv, environment and descriptor
shapes.  Diagnostic only; no production launcher code is imported or run.
"""
from __future__ import annotations

import ctypes
import errno
import importlib.util
import fcntl
import hashlib
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import time

_AT_EMPTY_PATH = 0x1000
(_PR_SET_DUMPABLE, _PR_SET_NO_NEW_PRIVS) = (4, 38)
_F_ADD_SEALS = 1033
_EXEC_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020
_DATA_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010
(_CLONE_NEWNS, _CLONE_NEWUSER, _CLONE_NEWPID, _CLONE_NEWNET) = (0x00020000, 0x10000000, 0x20000000, 0x40000000)
(_MS_NOSUID, _MS_NODEV, _MS_PRIVATE, _MS_REC) = (2, 4, 1 << 18, 16384)
_ROOT = "/tmp/cogs-o2-census-root"
_GZIP_INPUT = bytes.fromhex("1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e"
                            "2cc9cccfd32d33e40200a9c9b5521e000000")

libc = ctypes.CDLL(None, use_errno=True)


def checked(result, what):
    if result == -1:
        raise OSError(ctypes.get_errno(), what)
    return result


def execveat(fd, argv_values, env_values):
    argv = (ctypes.c_char_p * (len(argv_values) + 1))(*(item.encode() for item in argv_values), None)
    envp = (ctypes.c_char_p * (len(env_values) + 1))(*(item.encode() for item in env_values), None)
    checked(libc.syscall(322, fd, b"", argv, envp, _AT_EMPTY_PATH), "execveat")


def library_closure(path):
    """Resolve the runtime closure of a binary with ldd, returning host paths."""
    try:
        raw = subprocess.run(["/usr/bin/ldd", path], capture_output=True, timeout=20).stdout.decode()
    except Exception:
        return []
    found = []
    for line in raw.splitlines():
        line = line.strip()
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" (")[0].strip()
        elif line.startswith("/"):
            candidate = line.split(" (")[0].strip()
        else:
            continue
        if candidate.startswith("/") and os.path.exists(candidate):
            found.append(candidate)
    return found


def populate(root, executable, libraries, omit=()):
    os.makedirs(root, mode=0o700, exist_ok=True)
    checked(libc.mount(b"tmpfs", root.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV,
                       b"mode=0700,size=536870912,nr_inodes=512"), "mount-tmpfs")
    os.makedirs(f"{root}/bin", mode=0o755, exist_ok=True)
    for source in libraries:
        if any(token in source for token in omit):
            continue
        target = root + os.path.realpath(source)
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        shutil.copyfile(os.path.realpath(source), target)
        os.chmod(target, 0o555)
        link = root + source
        if link != target and not os.path.exists(link):
            os.makedirs(os.path.dirname(link), mode=0o755, exist_ok=True)
            shutil.copyfile(os.path.realpath(source), link)
            os.chmod(link, 0o555)
    target = f"{root}/bin/tool"
    shutil.copyfile(executable, target)
    os.chmod(target, 0o555)


def sealed_fd(path, truncate=None):
    with open(path, "rb") as handle:
        payload = handle.read()
    if truncate is not None:
        payload = payload[:truncate]
    mfd = os.memfd_create("exec", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(mfd, payload)
    try:
        fcntl.fcntl(mfd, _F_ADD_SEALS, _EXEC_SEALS)
    except OSError:
        fcntl.fcntl(mfd, _F_ADD_SEALS, _DATA_SEALS)
    return mfd


def run_case(case):
    executable = case["executable"]
    if not os.path.exists(executable):
        return {"case": case["name"], "skipped": "missing executable"}
    libraries = library_closure(case.get("closure_of", executable))
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    outer_uid, outer_gid = os.getuid(), os.getgid()
    sync_read, sync_write = os.pipe2(os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    owner = os.fork()
    if owner == 0:
        try:
            os.close(report_read)
            os.close(sync_read)
            os.close(gate_write)
            checked(libc.unshare(_CLONE_NEWUSER), "unshare-user")
            os.write(sync_write, b"U")
            if os.read(gate_read, 1) != b"M":
                raise RuntimeError("gate")
            if os.getgroups():
                os.setgroups([])
            checked(libc.unshare(_CLONE_NEWNS | _CLONE_NEWPID | _CLONE_NEWNET), "unshare-sandbox")
            checked(libc.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None), "private-root")
            populate(_ROOT, executable, libraries, case.get("omit", ()))
            exec_fd = sealed_fd(executable, case.get("truncate"))
            os.dup2(exec_fd, 198, inheritable=False)
            os.close(exec_fd)
            fcntl.fcntl(198, fcntl.F_SETFD, fcntl.fcntl(198, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
            input_read, input_write = os.pipe2(os.O_CLOEXEC)
            output_read, output_write = os.pipe2(os.O_CLOEXEC)
            child = os.fork()
            if child == 0:
                try:
                    os.dup2(fcntl.fcntl(input_read, fcntl.F_DUPFD_CLOEXEC, 256), 0, inheritable=True)
                    os.dup2(fcntl.fcntl(output_write, fcntl.F_DUPFD_CLOEXEC, 256), 1, inheritable=True)
                    os.dup2(1, 2, inheritable=True)
                    for name in os.listdir("/proc/self/fd"):
                        descriptor = int(name)
                        if descriptor not in (0, 1, 2, 198):
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass
                    if case.get("close_stdin"):
                        os.close(0)
                    os.chroot(_ROOT)
                    os.chdir("/")
                    checked(libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0), "dumpable")
                    checked(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "nnp")
                    if case.get("seccomp"): install_seccomp()
                    execveat(198, tuple(case["argv"]), tuple(case.get("env", ("LC_ALL=C",))))
                except BaseException as error:
                    os._exit(126)
            os.close(input_read)
            os.close(output_write)
            if case.get("eof_stdin"):
                os.close(input_write)
            elif case.get("feed"):
                os.write(input_write, _GZIP_INPUT)
                os.close(input_write)
            settled = (0, 0)
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                settled = os.waitpid(child, os.WNOHANG)
                if settled[0] != 0:
                    break
                time.sleep(0.01)
            drained = b""
            while select.select([output_read], [], [], 0.2)[0]:
                part = os.read(output_read, 65536)
                if not part:
                    break
                drained += part
            if settled[0] == 0:
                os.kill(child, signal.SIGKILL)
                settled = os.waitpid(child, 0)
                verdict = {"settled": "alive-until-killed"}
            elif os.WIFEXITED(settled[1]):
                verdict = {"settled": "exited", "status": os.WEXITSTATUS(settled[1])}
            else:
                verdict = {"settled": "signaled", "signal": os.WTERMSIG(settled[1])}
            verdict["out_len"] = len(drained)
            verdict["out"] = drained[:300].decode(errors="replace")
            os.write(report_write, json.dumps(verdict).encode())
            os._exit(0)
        except BaseException as error:
            try:
                os.write(report_write, json.dumps({"owner_error": f"{type(error).__name__}:{error}"}).encode())
            finally:
                os._exit(125)
    os.close(report_write)
    os.close(sync_write)
    os.close(gate_read)
    result = {"case": case["name"]}
    try:
        if select.select([sync_read], [], [], 10)[0] and os.read(sync_read, 1) == b"U":
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
        deadline = time.monotonic() + 30
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            if not select.select([report_read], [], [], remaining)[0]:
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
        for descriptor in (report_read, sync_read, gate_write):
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.waitpid(owner, 0)
        except OSError:
            pass
    return result


def install_seccomp():
    """Install the exact production filter, loaded from the matrix harness."""
    spec = importlib.util.spec_from_file_location("matrix", os.path.join(os.path.dirname(os.path.abspath(__file__)), "child-sandbox-matrix.py"))
    matrix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(matrix)
    return matrix.install_seccomp()

GZIP, ZSTD, PYTHON = "/usr/bin/gzip", "/usr/bin/zstd", "/usr/bin/python3"
ALT_GZIP = "/tmp/alt-rootfs/bin/gzip"

CASES = (
    {"name": "gzip/gzip-argv", "executable": GZIP, "argv": ("gzip", "-d", "-c")},
    {"name": "gzip/gzip-argv/fed", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "feed": True},
    {"name": "gzip/closure-argv", "executable": GZIP, "argv": ("gzip", "-dc")},
    {"name": "gzip/zstd-argv", "executable": GZIP, "argv": ("zstd", "-q", "-d", "-c")},
    {"name": "gzip/no-env", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "env": ()},
    {"name": "gzip/stdin-eof", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "eof_stdin": True},
    {"name": "gzip/stdin-closed", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "close_stdin": True},
    {"name": "gzip/no-libc", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "omit": ("libc.so",)},
    {"name": "gzip/no-loader", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "omit": ("ld-linux",)},
    {"name": "gzip/truncated", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "truncate": 4096},
    {"name": "zstd/zstd-argv", "executable": ZSTD, "argv": ("zstd", "-q", "-d", "-c")},
    {"name": "zstd/seccomp", "executable": ZSTD, "argv": ("zstd", "-q", "-d", "-c"), "seccomp": True},
    {"name": "zstd/seccomp/discovery-argv", "executable": ZSTD, "argv": ("zstd", "-dc", "--no-progress"), "seccomp": True},
    {"name": "gzip/seccomp", "executable": GZIP, "argv": ("gzip", "-d", "-c"), "seccomp": True},
    {"name": "zstd/gzip-argv", "executable": ZSTD, "argv": ("gzip", "-d", "-c")},
    {"name": "zstd/closure-argv", "executable": ZSTD, "argv": ("zstd", "-dc", "--no-progress")},
    {"name": "zstd/no-libz", "executable": ZSTD, "argv": ("zstd", "-q", "-d", "-c"), "omit": ("libz.so",)},
    {"name": "python3/gzip-argv", "executable": PYTHON, "argv": ("gzip", "-d", "-c")},
    {"name": "python3/zstd-argv", "executable": PYTHON, "argv": ("zstd", "-q", "-d", "-c")},
    # Cross-distro: a Debian 13 gzip against its own closure, and against the runner's.
    {"name": "debian-gzip/own-closure", "executable": ALT_GZIP, "argv": ("gzip", "-d", "-c")},
    {"name": "debian-gzip/runner-closure", "executable": ALT_GZIP, "argv": ("gzip", "-d", "-c"), "closure_of": GZIP},
    # Exec non-executable closure members: what does each object do as the program?
    {"name": "loader-as-program", "executable": "/lib64/ld-linux-x86-64.so.2", "argv": ("gzip", "-d", "-c"), "closure_of": GZIP},
    {"name": "libc-as-program", "executable": "/lib/x86_64-linux-gnu/libc.so.6", "argv": ("gzip", "-d", "-c"), "closure_of": GZIP},
    {"name": "libz-as-program", "executable": "/lib/x86_64-linux-gnu/libz.so.1", "argv": ("gzip", "-d", "-c"), "closure_of": ZSTD},
    {"name": "libzstd-as-program", "executable": "/lib/x86_64-linux-gnu/libzstd.so.1", "argv": ("zstd", "-q", "-d", "-c"), "closure_of": ZSTD},
)


def main():
    print(json.dumps({"kernel": os.uname().release, "uid": os.getuid()}), flush=True)
    for candidate in (GZIP, ZSTD, PYTHON, ALT_GZIP):
        if os.path.exists(candidate):
            with open(candidate, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()[:12]
            print(json.dumps({"binary": candidate, "sha256": digest}), flush=True)
    selected = set(sys.argv[1:])
    for case in CASES:
        if selected and case["name"] not in selected:
            continue
        started = time.monotonic()
        try:
            result = run_case(dict(case))
        except BaseException as error:
            result = {"case": case["name"], "harness_error": f"{type(error).__name__}:{error}"}
        result["seconds"] = round(time.monotonic() - started, 2)
        print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

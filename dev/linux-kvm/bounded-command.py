#!/usr/bin/env python3
"""Source-only ADR0333/0335 fixed guest probes; NOT a host generation envelope.

The locked driver journals intent before entry and completion after exit. Lost
responses, remote uncertainty and cancellation leave that generation cleanup-only.
No CLI arbitrary argv, shell, timeout/cap override, or injected executable exists.
"""
import base64
import errno
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time


class Rejected(RuntimeError):
    pass


class RetirementUncertain(Rejected):
    pass


cancelled = False


def check_cancelled():
    if cancelled:
        raise Rejected("command cancelled")


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def exact_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise Rejected("duplicate key")
            value[key] = item
        return value
    def invalid(_):
        raise Rejected("nonfinite JSON")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=invalid)


def text(raw):
    value = raw.decode("utf-8", "strict")
    if "\0" in value or "\r" in value:
        raise Rejected("malformed command bytes")
    return value


def identity(raw, kind):
    pattern = rb"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n" if kind == "boot-id" else rb"[0-9A-Za-z._+-]{1,64}\n"
    if not re.fullmatch(pattern, raw):
        raise Rejected("invalid identity record")
    return raw[:-1].decode("ascii")


class Pidfd:
    @staticmethod
    def preflight():
        if not callable(getattr(signal, "pidfd_send_signal", None)):
            raise Rejected("pidfd signals required")
        fd = os.pidfd_open(os.getpid(), 0)
        os.close(fd)

    def __init__(self, pid):
        # Popen has not been polled/waited: the child still reserves this PID.
        self.fd = os.pidfd_open(pid, 0)
        self.selector = selectors.DefaultSelector()
        try:
            self.selector.register(self.fd, selectors.EVENT_READ)
        except BaseException:
            self.selector.close()
            os.close(self.fd)
            raise

    def exited(self):
        return bool(self.selector.select(0))

    def kill(self):
        if not self.exited():
            signal.pidfd_send_signal(self.fd, signal.SIGKILL, None, 0)

    def close(self):
        self.selector.close()
        os.close(self.fd)


def group_quiet(pgid):
    # Fixed local ssh/keyscan do not daemonize or escape their new session.
    # This census proves same-group retirement, not arbitrary host containment.
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries):
            if count >= 8192:
                raise Rejected("process census exceeded")
            if not entry.name.isdecimal():
                continue
            try:
                with open(entry.path + "/stat", "rb") as stream:
                    raw = stream.read(4097)
                if len(raw) > 4096:
                    raise Rejected("process identity oversized")
                fields = raw.rsplit(b")", 1)[1].split()
                if int(fields[2]) == pgid and fields[0] not in (b"Z", b"X"):
                    return False
            except FileNotFoundError:
                continue
    return True


def retire(child, held):
    # Never poll/reap the leader before the LAST group signal. Its unreaped PID
    # reserves the process-group number even if it exited while pipes stayed open.
    uncertain = False
    def quiet():
        nonlocal uncertain
        try:
            return held is not None and held.exited() and group_quiet(child.pid)
        except Exception:
            uncertain = True
            return False
    for sig, grace in ((signal.SIGTERM, .2), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            uncertain = True
        if sig == signal.SIGKILL and held is not None:
            try:
                held.kill()
            except OSError:
                uncertain = True
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if quiet():
                # Still send KILL before reap, including pipe-closing descendants.
                break
            time.sleep(.01)
    settled = quiet()
    # Last group signal precedes even an uncertain direct-child reap.
    code = child.wait(timeout=.1)
    if uncertain or not settled:
        raise Rejected("local retirement uncertain")
    return code


def bounded(argv, cap=16384, seconds=15, deadline=None):
    """Internal testable primitive. Raw caps apply before decode, even on failure."""
    check_cancelled()
    Pidfd.preflight()
    end = min(time.monotonic() + seconds, deadline if deadline is not None else float("inf"))
    if time.monotonic() >= end:
        raise Rejected("command deadline")
    child = None
    held = None
    output = [bytearray(), bytearray()]
    code = None
    try:
        child = subprocess.Popen(argv, shell=False, start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent"})
        held = Pidfd(child.pid)
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((child.stdout, child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map() or not held.exited():
                check_cancelled()
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise Rejected("command deadline or incomplete EOF")
                for key, _ in selector.select(min(remaining, .05)):
                    index = key.data
                    limit = cap if index == 0 else 4096
                    try:
                        chunk = os.read(key.fd, min(4096, limit + 1 - len(output[index])))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[index].extend(chunk)
                        if len(output[index]) > limit:
                            raise Rejected("command byte cap")
            if time.monotonic() >= end:
                raise Rejected("command deadline")
    finally:
        # Handled cancellation cannot interrupt the sole local retirement owner.
        handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
        try:
            try:
                if child is not None:
                    code = retire(child, held)
            finally:
                if held is not None:
                    held.close()
                if child is not None:
                    child.stdout.close()
                    child.stderr.close()
        except Exception:
            raise RetirementUncertain("local retirement uncertain") from None
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    check_cancelled()
    raw, errors = map(bytes, output)
    text(raw)
    text(errors)
    return code, raw


def read_control(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise Rejected("unsafe control file")
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise Rejected("control cap")
        return raw
    finally:
        os.close(fd)


GIT_PROBE = r'''set -euo pipefail
    test "$(findmnt -rn -o TARGET /opt/cogs-git)" = /opt/cogs-git
    findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)ro(,|$)"
    findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)nosuid(,|$)"
    findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)nodev(,|$)"
    source=$(findmnt -rn -o SOURCE /opt/cogs-git)
    test "$(blkid -s LABEL -o value "$source")" = COGS_GITTOOLS
    test "$(blockdev --getro "$source")" = 1
    test -L /usr/bin/git && test "$(readlink /usr/bin/git)" = /opt/cogs-git/bin/git
    test "$(stat -c "%u:%g:%F" /usr/bin/git)" = "0:0:symbolic link"
    test "$(stat -c "%u:%g:%a:%F" /opt/cogs-git/bin/git)" = "0:0:755:regular file"
    ! find /opt/cogs-git -xdev \( ! -uid 0 -o ! -gid 0 -o \( ! -type l -a -perm /0022 \) -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .
    grep -qx $'git\t1:2.47.3-0+deb13u1\tamd64' /opt/cogs-git/cogs-git-tools-manifest.tsv
    grep -qx $'libcurl3t64-gnutls\t8.14.1-2+deb13u4\tamd64' /opt/cogs-git/cogs-git-tools-manifest.tsv
    grep -qx $'libngtcp2-16\t1.11.0-1+deb13u1\tamd64' /opt/cogs-git/cogs-git-tools-manifest.tsv
    grep -qx $'libngtcp2-crypto-gnutls8\t1.11.0-1+deb13u1\tamd64' /opt/cogs-git/cogs-git-tools-manifest.tsv
    test "$(git --version)" = "git version 2.47.3"
    ! ldd /opt/cogs-git/usr/bin/git 2>/dev/null | grep -q "not found"
    work=$(mktemp -d /tmp/cogs-git-verify.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    cd "$work"
    git init -q
    git config user.email cogs@example.invalid
    git config user.name cogs
    printf proof > proof.txt
    git add proof.txt
    git commit -q -m proof
    commit=$(git rev-parse --verify HEAD)
    test "${#commit}" = 40
    git notes --ref=cogs add -m note "$commit"
    git notes --ref=cogs show "$commit" >/dev/null
    git fsck --no-progress >/dev/null'''
PROBES = {
    "ready": "true",
    "boot-id": "cat /proc/sys/kernel/random/boot_id",
    "kernel": "uname -r",
    "root": 'test "$(id -u)" = 0',
    "workspace": "test -d /workspace",
    "git-tools": GIT_PROBE,
    "no-default-route": 'test -z "$(ip route show default)"',
    "mac": 'test "$(cat /sys/class/net/eth0/address)" = 52:54:00:c0:65:01',
    "skills": 'for skill_root in /shared/skills /user/skills; do test -d "$skill_root" && test ! -L "$skill_root" && test "$(realpath -e "$skill_root")" = "$skill_root" && test "$(stat -c "%u:%g:%a:%F" "$skill_root")" = "0:0:700:directory"; done',
    "reset-write": "printf reset-persistent > /workspace/reset-marker; sync",
    "reset-read": "grep -qx reset-persistent /workspace/reset-marker",
    "clear-firewall": "iptables -F 2>/dev/null || true; ip6tables -F 2>/dev/null || true; nft flush ruleset 2>/dev/null || true",
    # Negative diagnostics encode the expected remote exit, not ! host failure.
    "deny-host-ssh": 'timeout 2 bash -c "</dev/tcp/192.0.2.1/22"; c=$?; test "$c" = 1 -o "$c" = 124',
    "deny-public-https": 'timeout 2 bash -c "</dev/tcp/1.1.1.1/443"; c=$?; test "$c" = 1 -o "$c" = 124',
}
IDS = frozenset(PROBES) | {"readiness", "host-key", "qmp", "receipt-create", "receipt-verify", "receipt-reset", "proxy-connect"}


def ssh_argv(state, command):
    return ["/usr/bin/ssh", "-F", "/dev/null", "-n", "-T", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={state}/known_hosts",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none",
            "-i", str(state / "control/client_ed25519_key"), "root@192.0.2.2", command]


def guest(state, name, port, deadline=None):
    command = f'timeout 2 bash -c "</dev/tcp/192.0.2.1/{port}"' if name == "proxy-connect" else PROBES[name]
    cap = 37 if name == "boot-id" else 65 if name == "kernel" else 16384
    code, raw = bounded(ssh_argv(state, command), cap, 15, deadline)
    if code != 0:
        # 255, signals, missing remote exit, even normal failed verification:
        # never retry/reuse a possibly still-running remote invocation.
        raise Rejected("guest failed or remote retirement uncertain")
    if name in ("boot-id", "kernel"):
        return identity(raw, name)
    return None


def host_key(state, deadline=None):
    # Keep two seconds inside the five-second outer bound: a keyscan timeout
    # cannot consume the retry scheduler's complete deadline.
    code, raw = bounded(["/usr/bin/ssh-keyscan", "-T", "2", "-t", "ed25519", "192.0.2.2"], 4096, 5, deadline)
    if code == 1 and not raw:
        return False  # key exchange only: no guest command was dispatched
    expected = read_control(state / "known_hosts", 4096)
    if code != 0 or raw != expected or not re.fullmatch(rb"192\.0\.2\.2 ssh-ed25519 [A-Za-z0-9+/]+={0,2}\n", raw):
        raise Rejected("host key mismatch")
    base64.b64decode(raw.split()[2], validate=True)
    return True


def query_kvm(path):
    end = time.monotonic() + 5
    pending = bytearray()
    total = count = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client, selectors.DefaultSelector() as selector:
        client.setblocking(False)
        error = client.connect_ex(str(path))
        if error not in (0, errno.EINPROGRESS, errno.EAGAIN):
            raise Rejected("QMP connect failed")
        selector.register(client, selectors.EVENT_WRITE)
        def wait(event):
            check_cancelled()
            selector.modify(client, event)
            remaining = end - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise Rejected("QMP deadline")
        wait(selectors.EVENT_WRITE)
        if client.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
            raise Rejected("QMP connect failed")
        def send(raw):
            while raw:
                wait(selectors.EVENT_WRITE)
                try:
                    sent = client.send(raw)
                except BlockingIOError:
                    continue
                if sent <= 0:
                    raise Rejected("QMP short write")
                raw = raw[sent:]
        def receive(identifier=None):
            nonlocal total, count
            while True:
                check_cancelled()
                if time.monotonic() >= end:
                    raise Rejected("QMP deadline")
                while b"\n" not in pending:
                    wait(selectors.EVENT_READ)
                    try:
                        chunk = client.recv(min(4096, 8193 - len(pending)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        raise Rejected("QMP incomplete EOF")
                    total += len(chunk)
                    pending.extend(chunk)
                    if total > 32768 or (b"\n" not in pending and len(pending) > 8192):
                        raise Rejected("QMP byte cap")
                line, _, rest = pending.partition(b"\n")
                pending[:] = rest
                count += 1
                if len(line) + 1 > 8192 or count > 32 or b"\0" in line:
                    raise Rejected("QMP record cap")
                message = exact_json(line)
                check_cancelled()
                if time.monotonic() >= end:
                    raise Rejected("QMP deadline")
                if type(message) is not dict:
                    raise Rejected("QMP object required")
                if identifier is None or message.get("id") == identifier:
                    return message
                if "event" not in message or "id" in message:
                    raise Rejected("unexpected QMP response")
        greeting = receive()
        if set(greeting) != {"QMP"} or type(greeting["QMP"]) is not dict:
            raise Rejected("QMP greeting")
        send(b'{"execute":"qmp_capabilities","id":"caps"}\n')
        if receive("caps") != {"return": {}, "id": "caps"}:
            raise Rejected("QMP capabilities")
        send(b'{"execute":"query-kvm","id":"kvm"}\n')
        result = receive("kvm")
        if set(result) != {"return", "id"} or type(result["return"]) is not dict or set(result["return"]) != {"present", "enabled"} or any(value is not True for value in result["return"].values()):
            raise Rejected("KVM inactive")


IMAGE_SHA512 = "78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667"


def execute(name, state, generation, port):
    check_cancelled()
    if name not in IDS or not re.fullmatch(r"[a-f0-9]{32}", generation) or not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
        raise Rejected("invalid fixed command")
    if not state.is_absolute() or read_control(state / ".cogs-linux-kvm-v1", 33) != generation.encode() + b"\n":
        raise Rejected("generation mismatch")
    if name == "qmp":
        query_kvm(state / "qmp.sock")
    elif name in ("readiness", "host-key"):
        end = time.monotonic() + (120 if name == "readiness" else 5)
        while not host_key(state, end):
            if name != "readiness" or time.monotonic() + .2 >= end:
                raise Rejected("readiness deadline")
            time.sleep(.2)
        if name == "readiness":
            guest(state, "ready", port, end)
    elif name.startswith("receipt-"):
        boot = guest(state, "boot-id", port)
        with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
            host = identity(stream.read(38), "boot-id")
        if boot == host:
            raise Rejected("boot IDs not distinct")
        kernel = guest(state, "kernel", port)
        return {"status": "ready", "profile": "linux-kvm", "guest_root": True, "kvm_enabled": True,
                "distinct_boot_ids": True, "guest_kernel": kernel, "guest_image_sha512": IMAGE_SHA512,
                "host_ip": "192.0.2.1", "guest_ip": "192.0.2.2", "proxy_port": int(port),
                "generation": generation, "command": name.removeprefix("receipt-")}
    else:
        value = guest(state, name, port)
        if value is not None:
            return {name: value}
    return None


def require_driver(name, state, generation):
    # CLI is a subordinate of the locked driver, never a sentinel-discovery API.
    lock = Path(__file__).resolve().parents[2] / ".cogs-dev/linux-kvm.lock"
    held, named, directory = os.fstat(9), lock.lstat(), state.lstat()
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or not stat.S_ISREG(held.st_mode) or held.st_uid != os.getuid() or held.st_nlink != 1 or stat.S_IMODE(held.st_mode) != 0o600:
        raise Rejected("driver lock missing")
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
        raise Rejected("driver directory changed")
    owner = exact_json(read_control(state / ".generation.owner", 262144))
    if owner.get("version") != "cogs.linux-kvm-owner/v1" or owner.get("profile") != "linux-kvm" or owner.get("locator") != str(state) or owner.get("sourceRevision") != os.environ.get("COGS_SOURCE_REVISION"):
        raise Rejected("driver binding changed")
    if owner.get("generation") != generation or owner.get("guest") != name or owner.get("directory") != [directory.st_dev, directory.st_ino] or owner.get("failed") is not False or owner.get("uncertain") is not False:
        raise Rejected("driver guest intent missing")


def require_local_execution(generation):
    """Bind the CLI generation to the shared root receipt before state access."""
    if generation != os.environ.get("COGS_KVM_GENERATION"):
        raise Rejected("CLI generation does not match execution receipt")
    tools = Path(__file__).resolve().with_name("git-tools.sh")
    completed = subprocess.run(
        ["/bin/bash", "-c", 'source "$1"; cogs_kvm_execution_gate', "cogs-kvm-gate", str(tools)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=2,
    )
    if completed.returncode:
        raise Rejected("KVM execution receipt binding absent")


def main():
    name = None
    def cancel(signum, frame):
        # Latch, do not throw inside Popen/pidfd capture: that would lose custody.
        global cancelled
        cancelled = True
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel)
    try:
        if len(sys.argv) != 5:
            raise Rejected("fixed command arguments required")
        name, path, generation, port = sys.argv[1:]
        require_local_execution(generation)
        require_driver(name, Path(path), generation)
        result = execute(name, Path(path), generation, port)
        check_cancelled()
        if result is not None:
            sys.stdout.buffer.write(canonical(result))
            sys.stdout.buffer.flush()
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Fixed command/reason grammar only: never reflect output, paths, argv,
        # keys, or exception text. Nonzero and uncertain outcomes retain custody.
        command = name if name in IDS else "admission"
        reason = "local-retirement-uncertain" if isinstance(error, RetirementUncertain) else (
            "readiness-host-key" if command == "readiness" else "host-key" if command == "host-key" else "fixed-command"
        )
        print(f"FAIL: kvm-{command}-{reason}; generation must not be reused", file=sys.stderr)
        return 2 if isinstance(error, RetirementUncertain) else 1


if __name__ == "__main__":
    sys.exit(main())

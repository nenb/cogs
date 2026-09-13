#!/usr/bin/env python3
"""Fixed, custody-bound owner for the short-lived KVM qualification VM."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time


LIMIT = 64 * 1024
TERM_GRACE = .2
KILL_GRACE = 2.0
RETIRE_BUDGET = TERM_GRACE + KILL_GRACE + .2


def fail(message):
    raise RuntimeError(message)


def load_qmp():
    path = Path(__file__).with_name("bounded-command.py")
    spec = importlib.util.spec_from_file_location("cogs_bounded", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("bounded QMP unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.query_kvm


def require_local_execution():
    tools = Path(__file__).with_name("git-tools.sh")
    result = subprocess.run(["/bin/bash", "-c", 'source "$1"; cogs_kvm_execution_gate', "cogs-kvm-gate", str(tools)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            check=False, timeout=2)
    if result.returncode:
        fail("KVM execution receipt binding absent")


def limit_uart():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


class Owner:
    def __init__(self, workdir, kernel, initramfs, host_boot):
        self.workdir, self.kernel, self.initramfs, self.host_boot = Path(workdir), kernel, initramfs, host_boot
        self.end = time.monotonic() + 30
        self.work_end = self.end - RETIRE_BUDGET
        self.child = self.pidfd = None
        self.cancelled = self.retired = False
        self.retirement = None
        self.pending = self.workdir / "qualification-pending"

    def cancel(self, *_):
        self.cancelled = True

    def require_live(self):
        if self.cancelled:
            fail("qualification cancelled")
        if time.monotonic() >= self.work_end:
            fail("qualification deadline")

    def require_commit(self):
        if self.cancelled or time.monotonic() >= self.end:
            fail("qualification deadline")

    def _fsync_dir(self):
        fd = os.open(self.workdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _custody(self, value, create=False):
        flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if create else os.O_TRUNC)
        fd = os.open(self.pending, flags, 0o600)
        try:
            raw = json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"
            while raw:
                written = os.write(fd, raw)
                if written <= 0:
                    fail("pending custody write")
                raw = raw[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_dir()

    def start(self):
        for watched in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(watched, self.cancel)
        self.require_live()
        if not callable(getattr(signal, "pidfd_send_signal", None)):
            fail("pidfd signals required")
        test = os.pidfd_open(os.getpid(), 0)
        os.close(test)
        # This durable intent predates QEMU, and is retained if this owner dies.
        self._custody({"version": 1, "state": "pending"}, True)
        qmp, guest = self.workdir / "qmp.sock", self.workdir / "guest.log"
        self.child = subprocess.Popen([
            "qemu-system-x86_64", "-name", "cogs-stage0-kvm-qualification", "-machine", "q35", "-accel", "kvm",
            "-cpu", "host", "-smp", "1", "-m", "256M", "-kernel", self.kernel, "-initrd", self.initramfs,
            "-append", "console=ttyS0 panic=-1", "-display", "none", "-serial", "file:" + str(guest), "-monitor", "none",
            "-nic", "none", "-qmp", "unix:" + str(qmp) + ",server=on,wait=off", "-no-reboot",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
           preexec_fn=limit_uart, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent"})
        self._custody({"version": 1, "pid": self.child.pid, "pgid": self.child.pid})
        try:
            self.pidfd = os.pidfd_open(self.child.pid, 0)
        except OSError:
            fail("pidfd acquisition failed")

    def exited(self):
        if self.pidfd is None:
            return False
        with selectors.DefaultSelector() as selector:
            selector.register(self.pidfd, selectors.EVENT_READ)
            return bool(selector.select(0))

    def signal_group(self, child, which):
        try:
            os.killpg(child.pid, which)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False

    def retire(self):
        if self.retired:
            return self.retirement
        self.retired = True
        child, uncertain = self.child, self.pidfd is None
        if child is None:
            self.retirement = (False, None)
            return self.retirement
        # Keep the unreaped leader PID reserved through both numeric group signals.
        for which, grace in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, KILL_GRACE)):
            uncertain |= not self.signal_group(child, which)
            if which == signal.SIGKILL and self.pidfd is not None:
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                except OSError:
                    uncertain = True
            limit = min(self.end, time.monotonic() + grace)
            while time.monotonic() < limit:
                try:
                    if self.exited():
                        break
                except (OSError, ValueError):
                    uncertain = True
                    break
                time.sleep(.01)
        try:
            settled = self.exited()
        except (OSError, ValueError):
            settled, uncertain = False, True
        if not settled:
            uncertain = True
        try:
            code = child.wait(timeout=max(0.0, min(.1, self.end - time.monotonic())))
        except (subprocess.TimeoutExpired, OSError):
            code, uncertain = None, True
        self.child = None
        if self.pidfd is not None:
            try:
                os.close(self.pidfd)
            except OSError:
                uncertain = True
            self.pidfd = None
        self.retirement = (not uncertain, code)
        return self.retirement

    def capture(self):
        try:
            fd = os.open(self.workdir / "guest.log", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return b""
        try:
            if os.fstat(fd).st_size > LIMIT:
                fail("UART marker cap")
            raw = os.read(fd, LIMIT + 1)
        finally:
            os.close(fd)
        if len(raw) > LIMIT:
            fail("UART marker cap")
        return raw

    def settle_custody(self):
        self.require_commit()
        os.unlink(self.pending)
        self._fsync_dir()
        marker = self.workdir / "owner-settled"
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, b"settled\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_dir()

    def run(self):
        self.start()
        qmp = self.workdir / "qmp.sock"
        while not qmp.is_socket():
            self.require_live()
            if self.exited():
                fail("QEMU exited before QMP qualification")
            if len(self.capture()) >= LIMIT:
                fail("UART marker cap")
            time.sleep(.02)
        load_qmp()(qmp, self.work_end, self.require_live)
        while not self.exited():
            self.require_live()
            if len(self.capture()) >= LIMIT:
                fail("UART marker cap")
            time.sleep(.02)
        self.require_live()
        raw = self.capture()
        self.require_live()
        lines = raw.decode("utf-8", "strict").replace("\r\n", "\n").splitlines()
        if lines.count("COGS_GUEST_READY=1") != 1 or lines.count("COGS_GUEST_UID=0") != 1:
            fail("guest markers absent")
        values = {}
        for prefix in ("COGS_GUEST_BOOT_ID=", "COGS_GUEST_KERNEL="):
            found = [line[len(prefix):] for line in lines if line.startswith(prefix)]
            if len(found) != 1 or not found[0] or len(found[0]) > 64 or "\0" in found[0]:
                fail("guest marker malformed")
            values[prefix] = found[0]
        if values["COGS_GUEST_BOOT_ID="] == self.host_boot:
            fail("host and guest boot IDs are identical")
        self.require_live()
        settled, code = self.retire()
        if not settled or code != 0:
            fail("local retirement uncertain")
        self.settle_custody()
        print(json.dumps({"guest_boot_id": values["COGS_GUEST_BOOT_ID="], "guest_kernel": values["COGS_GUEST_KERNEL="]}, separators=(",", ":")))


def main():
    if len(sys.argv) != 5:
        return 2
    try:
        # This independently applies the exact root receipt before workdir use.
        require_local_execution()
        owner = Owner(*sys.argv[1:])
        owner.run()
        return 0
    except BaseException as error:
        try:
            if "owner" in locals():
                owner.retire()
        except BaseException:
            pass
        print("FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fixed owner for the short-lived KVM qualification VM; no driver state exists here."""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time


LIMIT = 64 * 1024
TERM_GRACE = .2
KILL_GRACE = 2.0


def fail(message, uncertain=False):
    if uncertain:
        # The shell deliberately retains this directory: it is the only local
        # custody record when identity-bound retirement could not be proven.
        Path(sys.argv[1]).joinpath("owner-uncertain").write_text(message + "\n", encoding="ascii")
    raise RuntimeError(message)


def load_qmp():
    path = Path(__file__).with_name("bounded-command.py")
    spec = importlib.util.spec_from_file_location("cogs_bounded", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("bounded QMP unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.query_kvm


class Owner:
    def __init__(self, workdir, kernel, initramfs, host_boot):
        self.workdir = Path(workdir)
        self.kernel = kernel
        self.initramfs = initramfs
        self.host_boot = host_boot
        self.end = time.monotonic() + 30
        self.child = None
        self.pidfd = None
        self.cancelled = False

    def cancel(self, *_):
        self.cancelled = True

    def remaining(self):
        return self.end - time.monotonic()

    def require_live(self):
        if self.cancelled:
            fail("qualification cancelled")
        if self.remaining() <= 0:
            fail("qualification deadline")

    def start(self):
        for watched in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(watched, self.cancel)
        self.require_live()
        if not callable(getattr(signal, "pidfd_send_signal", None)):
            fail("pidfd signals required")
        test = os.pidfd_open(os.getpid(), 0)
        os.close(test)
        qmp = self.workdir / "qmp.sock"
        guest = self.workdir / "guest.log"
        self.child = subprocess.Popen([
            "qemu-system-x86_64", "-name", "cogs-stage0-kvm-qualification", "-machine", "q35",
            "-accel", "kvm", "-cpu", "host", "-smp", "1", "-m", "256M", "-kernel", self.kernel,
            "-initrd", self.initramfs, "-append", "console=ttyS0 panic=-1", "-display", "none",
            "-serial", "file:" + str(guest), "-monitor", "none", "-nic", "none",
            "-qmp", "unix:" + str(qmp) + ",server=on,wait=off", "-no-reboot",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
           env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent"})
        self.pidfd = os.pidfd_open(self.child.pid, 0)

    def exited(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.pidfd, selectors.EVENT_READ)
            return bool(selector.select(0))

    def signal_group(self, which):
        try:
            os.killpg(self.child.pid, which)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        return True

    def retire(self):
        if self.child is None:
            return True
        uncertain = False
        for which, grace in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, KILL_GRACE)):
            if not self.signal_group(which):
                uncertain = True
            if which == signal.SIGKILL:
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                except OSError:
                    uncertain = True
            limit = min(self.end, time.monotonic() + grace)
            while time.monotonic() < limit and not self.exited():
                time.sleep(.01)
        if not self.exited():
            uncertain = True
        try:
            self.child.wait(timeout=max(0.0, min(.1, self.remaining())))
        except (subprocess.TimeoutExpired, OSError):
            uncertain = True
        try:
            os.close(self.pidfd)
        except OSError:
            uncertain = True
        self.pidfd = None
        return not uncertain

    def capture(self):
        path = self.workdir / "guest.log"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
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
        load_qmp()(qmp, self.end)
        while not self.exited():
            self.require_live()
            if len(self.capture()) >= LIMIT:
                fail("UART marker cap")
            time.sleep(.02)
        self.require_live()
        code = self.child.wait(timeout=max(0.0, self.remaining()))
        if self.cancelled or code != 0 or time.monotonic() >= self.end:
            fail("QEMU did not complete cleanly")
        raw = self.capture()
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
        # Successful exit is still not publication until the held child identity
        # is reaped and its pidfd closes without any deadline/custody failure.
        if not self.retire():
            fail("local retirement uncertain", True)
        print(json.dumps({"guest_boot_id": values["COGS_GUEST_BOOT_ID="], "guest_kernel": values["COGS_GUEST_KERNEL="]}, separators=(",", ":")))


def main():
    if len(sys.argv) != 5:
        return 2
    owner = Owner(*sys.argv[1:])
    try:
        owner.run()
        return 0
    except BaseException as error:
        # Latch every bad outcome before the sole owner begins TERM/KILL/reap.
        try:
            retired = owner.retire()
        except BaseException:
            retired = False
        if not retired:
            Path(sys.argv[1]).joinpath("owner-uncertain").write_text("retirement uncertain\n", encoding="ascii")
        print("FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

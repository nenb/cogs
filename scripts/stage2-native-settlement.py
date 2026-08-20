#!/usr/bin/env python3
"""Fixed fail-closed process/mount settlement checks for the native workflow."""
import errno
import os
from pathlib import Path
import re
import subprocess
import sys

TARGETS = (
    "/var/lib/cogs",
    "/run/cogs-stage2-native-preflight-source-v1",
    "/run/cogs-stage2-native-private-v1",
)
MOUNT_TARGETS = TARGETS[1:]
MARKER = b"run-stage2-package-native-candidate.py"
PHASES = frozenset(("before-unmount", "after-unmount"))
COMMAND_SECONDS = 60
VANISHED = frozenset((errno.ENOENT, errno.ESRCH))


class SettlementError(Exception):
    pass


def _vanished(error):
    return error.errno in VANISHED


def _bytes(path):
    try:
        with open(path, "rb", buffering=0) as source:
            return source.read()
    except OSError as error:
        if _vanished(error):
            return None
        raise SettlementError("process inspection failed") from error


def _link(path):
    try:
        return os.readlink(path)
    except OSError as error:
        if _vanished(error):
            return None
        raise SettlementError("process link inspection failed") from error


def _identity(path):
    try:
        value = os.stat(path)
        return value.st_dev, value.st_ino
    except OSError as error:
        if _vanished(error):
            return None
        raise SettlementError("namespace inspection failed") from error


def _names(path):
    try:
        return os.listdir(path)
    except OSError as error:
        if _vanished(error):
            return None
        raise SettlementError("process inventory failed") from error


def _refers(value, targets):
    if value is None:
        return False
    value = value.removesuffix(" (deleted)")
    return any(value == target or value.startswith(target + "/") for target in targets)


def _mount_fields(raw):
    def replace(match):
        return bytes((int(match.group(1), 8),))
    return re.sub(rb"\\([0-7]{3})", replace, raw).decode(
        "utf-8", "surrogateescape").split()


def scan(phase, proc_root=Path("/proc"), targets=TARGETS, marker=MARKER):
    """Reject every live marker, foreign/remaining mount, path, or descriptor reference."""
    if phase not in PHASES or not targets or not marker:
        raise SettlementError("invalid settlement request")
    proc_root = Path(proc_root)
    own_namespace = _identity(proc_root / "self/ns/mnt")
    names = _names(proc_root)
    if own_namespace is None or names is None:
        raise SettlementError("process inventory unavailable")
    for name in sorted(item for item in names if item.isdecimal()):
        base = proc_root / name
        command = _bytes(base / "cmdline")
        if command is not None and marker in command:
            raise SettlementError(f"unsettled candidate process: {name}")
        mounts = _bytes(base / "mountinfo")
        if mounts is None:  # The listed process vanished.
            continue
        if any(_refers(field, targets) for field in _mount_fields(mounts)):
            namespace = _identity(base / "ns/mnt")
            if namespace is None:  # A process that vanished cannot retain the mount.
                continue
            if phase == "after-unmount" or namespace != own_namespace:
                raise SettlementError(f"unsettled target mount namespace: {name}")
        for entry in ("root", "cwd", "exe"):
            if _refers(_link(base / entry), targets):
                raise SettlementError(f"unsettled process path: {name}/{entry}")
        descriptors = _names(base / "fd")
        if descriptors is None:
            continue
        for descriptor in descriptors:
            if _refers(_link(base / "fd" / descriptor), targets):
                raise SettlementError(f"unsettled process descriptor: {name}/{descriptor}")


def unmount(run=subprocess.run):
    """Ordinarily unmount each fixed mount; a busy/error result fails closed."""
    for target in MOUNT_TARGETS:
        mounted = run(("/usr/bin/mountpoint", "-q", target), check=False).returncode
        if mounted == 1:
            continue
        if mounted != 0:
            raise SettlementError("mountpoint inspection failed")
        command = (
            "/usr/bin/timeout", "--foreground", "--signal=TERM", "--kill-after=5s",
            f"{COMMAND_SECONDS}s", "/bin/umount", "--", target,
        )
        if run(command, check=False).returncode != 0:
            raise SettlementError("ordinary unmount did not settle")


def main():
    if sys.argv[1:] == ["unmount"]:
        unmount()
    elif len(sys.argv) == 3 and sys.argv[1] == "scan":
        scan(sys.argv[2])
    else:
        raise SettlementError("usage: stage2-native-settlement.py scan PHASE | unmount")


if __name__ == "__main__":
    try:
        main()
    except (OSError, SettlementError):
        raise SystemExit(2)

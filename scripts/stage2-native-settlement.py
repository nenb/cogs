#!/usr/bin/env python3
"""Fixed fail-closed, stable process/mount settlement checks for the native workflow."""
import errno
import os
from pathlib import Path
import re
import subprocess
import sys
import time

FIXED_TARGETS = (
    "/var/lib/cogs",
    "/run/cogs-stage2-native-preflight-source-v1",
    "/run/cogs-stage2-native-private-v1",
)
MOUNT_TARGETS = FIXED_TARGETS[1:]
MARKER = b"run-stage2-package-native-candidate.py"
PHASES = frozenset(("before-unmount", "after-unmount"))
COMMAND_SECONDS = 60
MAX_SCAN_PASSES = 120
REQUIRED_STABLE_PASSES = 3
VANISHED = frozenset((errno.ENOENT, errno.ESRCH))
POSITIVE = re.compile(r"[1-9][0-9]*")


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


def _starttime(base):
    raw = _bytes(base / "stat")
    if raw is None:
        return None
    close = raw.rfind(b")")
    fields = raw[close + 2:].split() if close >= 0 else ()
    if len(fields) < 20 or not fields[19].isdigit():
        raise SettlementError("invalid process generation")
    return int(fields[19])


def _inventory(proc_root):
    names = _names(proc_root)
    if names is None:
        raise SettlementError("process inventory unavailable")
    result = {}
    complete = True
    for name in names:
        if name.isdecimal():
            identity = _starttime(proc_root / name)
            if identity is None:
                complete = False
            else:
                result[name] = identity
    return result, complete


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


def _inspect_generation(phase, proc_root, name, starttime, own_namespace, targets, marker):
    base = proc_root / name
    if _starttime(base) != starttime:
        return False
    command = _bytes(base / "cmdline")
    mounts = _bytes(base / "mountinfo")
    if command is None or mounts is None:
        if _starttime(base) == starttime:
            raise SettlementError(f"stable process inspection unavailable: {name}")
        return False
    if marker in command:
        raise SettlementError(f"unsettled candidate process: {name}")
    if any(_refers(field, targets) for field in _mount_fields(mounts)):
        namespace = _identity(base / "ns/mnt")
        if namespace is None:
            if _starttime(base) == starttime:
                raise SettlementError(f"stable namespace inspection unavailable: {name}")
            return False
        if phase == "after-unmount" or namespace != own_namespace:
            raise SettlementError(f"unsettled target mount namespace: {name}")
    for entry in ("root", "cwd", "exe"):
        value = _link(base / entry)
        if value is None and entry != "exe" and _starttime(base) == starttime:
            raise SettlementError(f"stable process link inspection unavailable: {name}/{entry}")
        if _refers(value, targets):
            raise SettlementError(f"unsettled process path: {name}/{entry}")
    descriptors = _names(base / "fd")
    if descriptors is None:
        if _starttime(base) == starttime:
            raise SettlementError(f"stable descriptor inventory unavailable: {name}")
        return False
    stable = True
    for descriptor in descriptors:
        value = _link(base / "fd" / descriptor)
        if value is None:
            stable = False
        elif _refers(value, targets):
            raise SettlementError(f"unsettled process descriptor: {name}/{descriptor}")
    return stable and _starttime(base) == starttime


def _candidate_target(environ):
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    staging = environ.get("CANDIDATE_STAGING", "")
    if POSITIVE.fullmatch(run_id) is None or POSITIVE.fullmatch(attempt) is None:
        raise SettlementError("invalid run identity")
    required = f"/var/tmp/cogs-stage2-native-package-candidate-{run_id}-{attempt}"
    if staging != required:
        raise SettlementError("staging identity is not run-unique")
    return staging


def scan(phase, proc_root=Path("/proc"), targets=None, marker=MARKER, environ=os.environ):
    """Reject references over repeated complete inspections of every final live generation."""
    if targets is None:
        targets = FIXED_TARGETS + (_candidate_target(environ),)
    if phase not in PHASES or not targets or not marker:
        raise SettlementError("invalid settlement request")
    proc_root = Path(proc_root)
    own_namespace = _identity(proc_root / "self/ns/mnt")
    if own_namespace is None:
        raise SettlementError("mount namespace unavailable")
    consecutive = 0
    coverage = {}
    for _ in range(MAX_SCAN_PASSES):
        before, complete = _inventory(proc_root)
        inspected = set()
        for name, starttime in sorted(before.items()):
            if _inspect_generation(phase, proc_root, name, starttime,
                                   own_namespace, targets, marker):
                inspected.add((name, starttime))
        after, final_complete = _inventory(proc_root)
        # Births and reused generations in the final census were not inspected and
        # force another pass.  A generation that vanished after a complete clean
        # inspection cannot retain a target and does not couple acceptance to
        # unrelated whole-runner process churn.
        current = set(after.items())
        stable = complete and final_complete and current <= inspected
        if stable:
            consecutive += 1
            coverage = {generation: coverage.get(generation, 0) + 1
                        for generation in current}
        else:
            consecutive, coverage = 0, {}
        if (consecutive >= REQUIRED_STABLE_PASSES
                and all(count >= REQUIRED_STABLE_PASSES
                        for count in coverage.values())):
            return
        time.sleep(0.01)
    raise SettlementError("process generations did not reach stable settlement")


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


def _failure_token(error):
    message = str(error)
    categories = (
        ("process generations did not reach stable settlement", "scan-nonconvergence"),
        ("unsettled candidate process", "candidate-process"),
        ("unsettled target mount namespace", "target-mount-namespace"),
        ("unsettled process path", "target-process-path"),
        ("unsettled process descriptor", "target-process-descriptor"),
        ("stable process link", "process-link-inspection"),
        ("stable process", "process-inspection"),
        ("stable namespace", "namespace-inspection"),
        ("stable descriptor", "descriptor-inspection"),
        ("process inspection", "process-inspection"),
        ("process link inspection", "process-link-inspection"),
        ("namespace inspection", "namespace-inspection"),
        ("process inventory", "process-inventory"),
        ("invalid process generation", "process-generation"),
        ("mount namespace", "mount-namespace"),
        ("mountpoint inspection", "mountpoint-inspection"),
        ("ordinary unmount", "ordinary-unmount"),
        ("invalid run identity", "request-error"),
        ("staging identity", "request-error"),
        ("invalid settlement request", "request-error"),
        ("usage:", "request-error"),
    )
    return next((token for prefix, token in categories if message.startswith(prefix)),
                "settlement-error")


if __name__ == "__main__":
    try:
        main()
    except (OSError, SettlementError) as error:
        print(f"native settlement failed:{_failure_token(error)}", file=sys.stderr)
        raise SystemExit(2)

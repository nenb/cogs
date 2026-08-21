#!/usr/bin/env python3
"""Independent fixed-root settlement, cleanup, and final residue enforcement."""
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NATIVE_PATH = ROOT / "scripts/stage2-native-settlement.py"
spec = importlib.util.spec_from_file_location("stage2_native_settlement_for_local", NATIVE_PATH)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

FIXED_ROOTS = (
    "/var/lib/cogs",
    "/run/cogs-stage2-local-private-v2",
    "/run/cogs-stage2-native-preflight-source-v1",
    "/run/cogs-stage2-native-private-v1",
)
PROCESS_MARKERS = (
    b"completion_local_full.py", b"completion_kata_coordinator.py",
    b"recover-stage2-completion-remote.sh", b"cogs-stage2-local-",
)
RESIDUE_NAME = re.compile(r"(?:^|[-_.])cogs(?:[-_.]|$).*stage2|stage2.*(?:^|[-_.])cogs", re.I)
POSITIVE = re.compile(r"[1-9][0-9]*")
MAX_DIRECTORY_ENTRIES = 100_000
MAX_OBSERVER_BYTES = 8 * 1024 * 1024


class LocalSettlementError(Exception):
    pass


def _require(condition, message="local settlement failed"):
    if not condition:
        raise LocalSettlementError(message)


def _run_paths(environ):
    run_id, attempt = environ.get("GITHUB_RUN_ID", ""), environ.get("GITHUB_RUN_ATTEMPT", "")
    _require(POSITIVE.fullmatch(run_id) is not None and attempt == "1", "invalid run identity")
    expected = {
        "REPORT_STAGING": f"/var/tmp/cogs-stage2-local-result-{run_id}-1",
        "REPORT_READBACK_STAGING": f"/var/tmp/cogs-stage2-local-result-upload-{run_id}-1",
        "RECEIPT_READBACK_STAGING": f"/var/tmp/cogs-stage2-local-receipt-upload-{run_id}-1",
    }
    for name, value in expected.items():
        _require(environ.get(name) == value, "run staging identity differs")
    return tuple(expected.values())


def _scan_fixed():
    for marker in PROCESS_MARKERS:
        try:
            native.scan("after-unmount", targets=FIXED_ROOTS, marker=marker)
        except native.SettlementError as error:
            raise LocalSettlementError("process or mount settlement differs") from error


def _bounded_names(path):
    try:
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                _require(len(names) < MAX_DIRECTORY_ENTRIES, "residue inventory exceeded bound")
                names.append(entry.name)
        return names
    except FileNotFoundError:
        return []
    except OSError as error:
        raise LocalSettlementError("residue inventory failed") from error


def _named_residue(path):
    return tuple(name for name in _bounded_names(path) if RESIDUE_NAME.search(name))


def _walk_named(root):
    root = Path(root)
    if not root.exists():
        return ()
    found, count = [], 0
    for base, directories, files in os.walk(root, followlinks=False):
        count += len(directories) + len(files)
        _require(count <= MAX_DIRECTORY_ENTRIES, "residue walk exceeded bound")
        for name in (*directories, *files):
            if RESIDUE_NAME.search(name):
                found.append(str(Path(base) / name))
    return tuple(found)


def _nft_ruleset():
    try:
        result = subprocess.run(
            ("/usr/sbin/nft", "-j", "list", "ruleset"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
            env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin"})
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalSettlementError("independent firewall observation failed") from error
    _require(result.returncode == 0 and len(result.stdout) <= MAX_OBSERVER_BYTES
             and len(result.stderr) <= MAX_OBSERVER_BYTES,
             "independent firewall observation failed")
    return result.stdout


def residue(environ=os.environ, final=False):
    staging = _run_paths(environ)
    _scan_fixed()
    _require(not any(os.path.lexists(path) for path in FIXED_ROOTS), "fixed qualification root remains")
    interfaces = set(_bounded_names("/sys/class/net"))
    _require(not (_named_residue("/sys/class/net") or {"c42h0", "c42g0"} & interfaces),
             "qualification network interface remains")
    _require(not _named_residue("/run/netns"), "qualification network namespace remains")
    _require(not _walk_named("/sys/fs/cgroup"), "qualification cgroup remains")
    _require(b"cogs_stage2_ssh_v1" not in _nft_ruleset(), "qualification firewall remains")
    if final:
        _require(not any(os.path.lexists(path) for path in staging), "output staging remains")


def cleanup(environ=os.environ):
    _run_paths(environ)
    _require(environ.get("RECOVERY_OUTCOME") == "success", "recovery success is required before deletion")
    _require(os.geteuid() == 0, "root cleanup is required")
    _scan_fixed()
    for path in FIXED_ROOTS:
        observed = None
        try:
            observed = os.lstat(path)
        except FileNotFoundError:
            continue
        _require(stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode),
                 "fixed cleanup root type differs")
    command = ("/bin/rm", "-rf", "--one-file-system", "--", *FIXED_ROOTS)
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, timeout=120)
    _require(result.returncode == 0, "fixed cleanup command failed")
    _require(not any(os.path.lexists(path) for path in FIXED_ROOTS), "fixed cleanup root remains")


def main():
    _require(len(sys.argv) == 2 and sys.argv[1] in {"cleanup", "residue", "final"},
             "invalid settlement command")
    if sys.argv[1] == "cleanup":
        cleanup()
    else:
        residue(final=sys.argv[1] == "final")


if __name__ == "__main__":
    try:
        main()
    except (LocalSettlementError, OSError, subprocess.SubprocessError):
        raise SystemExit(2)

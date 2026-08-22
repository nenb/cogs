#!/usr/bin/env python3
"""Independent fixed-root settlement, cleanup, and final residue enforcement."""
import importlib.util
import json
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
    "/opt/kata",
    "/run/cogs-stage2-local-private-v2",
    "/run/cogs-stage2-native-preflight-source-v1",
    "/run/cogs-stage2-native-private-v1",
)
PROCESS_MARKERS = (
    b"completion_local_full.py", b"completion_kata_coordinator.py",
    b"recover-stage2-completion-remote.sh", b"cogs-stage2-local-",
)
RESIDUE_NAME = re.compile(r"(?:^|[-_.])cogs(?:[-_.]|$).*stage2|stage2.*(?:^|[-_.])cogs", re.I)
TOKEN_RESOURCE = re.compile(r"c42[hnqt][0-9a-f]{10}")
TOKEN_INTERFACE = re.compile(r"c42h[0-9a-f]{10}")
TOKEN_NETNS = re.compile(r"c42[nq][0-9a-f]{10}")
TOKEN_NFT = re.compile(r"c42t[0-9a-f]{10}")
POSITIVE = re.compile(r"[1-9][0-9]*")
MAX_DIRECTORY_ENTRIES = 100_000
MAX_OBSERVER_BYTES = 8 * 1024 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 32
MAX_NETWORK_ROWS = 32_768
OBSERVER_ENV = {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin"}


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


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value,
                 "network observer duplicate JSON key")
        value[key] = item
    return value


def _bounded_json(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_OBSERVER_BYTES,
             "network observer byte bound failed")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise LocalSettlementError("network observer JSON failed") from error
    count = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        count += 1
        _require(count <= MAX_JSON_NODES and depth <= MAX_JSON_DEPTH,
                 "network observer structure bound failed")
        if type(item) is dict:
            stack.extend((key, depth + 1) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        else:
            _require(item is None or type(item) in (str, int, bool),
                     "network observer scalar failed")
    return value


def _observe_json(command):
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=15, env=OBSERVER_ENV)
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalSettlementError("independent network observation failed") from error
    _require(result.returncode == 0 and result.stderr == b""
             and len(result.stdout) <= MAX_OBSERVER_BYTES,
             "independent network observation failed")
    return _bounded_json(result.stdout)


def _rows(value, message):
    _require(type(value) is list and len(value) <= MAX_NETWORK_ROWS, message)
    _require(all(type(row) is dict for row in value), message)
    return value


def _interface_names(value):
    names = []
    for row in _rows(value, "complete interface inventory failed"):
        name = row.get("ifname")
        _require(type(name) is str and 0 < len(name) <= 15,
                 "complete interface inventory failed")
        names.append(name)
    _require(len(names) == len(set(names)), "duplicate interface inventory")
    return tuple(names)


def _netns_names(value):
    names = []
    for row in _rows(value, "complete netns inventory failed"):
        _require(set(row) <= {"name", "id"} and type(row.get("name")) is str,
                 "complete netns inventory failed")
        names.append(row["name"])
    _require(len(names) == len(set(names)), "duplicate netns inventory")
    return tuple(names)


def _all_strings(value):
    strings = []
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is str:
            strings.append(item)
        elif type(item) is dict:
            stack.extend(item.keys())
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    return tuple(strings)


def _nft_table_names(value):
    _require(type(value) is dict and set(value) == {"nftables"},
             "complete nft inventory failed")
    names = []
    for row in _rows(value["nftables"], "complete nft inventory failed"):
        table = row.get("table")
        if type(table) is dict:
            name = table.get("name")
            _require(type(name) is str, "complete nft inventory failed")
            names.append(name)
        elif type(table) is str:
            names.append(table)
    return tuple(names)


def _network_state():
    links = _observe_json(("/usr/sbin/ip", "-j", "-details", "link", "show"))
    netns = _observe_json(("/usr/sbin/ip", "-j", "netns", "list"))
    nft = _observe_json(("/usr/sbin/nft", "-j", "list", "ruleset"))
    qdiscs = _observe_json(("/usr/sbin/tc", "-j", "qdisc", "show"))
    filters = _observe_json(("/usr/sbin/tc", "-j", "filter", "show"))
    _rows(qdiscs, "complete tc qdisc inventory failed")
    _rows(filters, "complete tc filter inventory failed")
    return (_interface_names(links), _netns_names(netns), _nft_table_names(nft),
            _all_strings(qdiscs) + _all_strings(filters))


def residue(environ=os.environ, final=False):
    staging = _run_paths(environ)
    _scan_fixed()
    _require(not any(os.path.lexists(path) for path in FIXED_ROOTS),
             "fixed qualification root remains")
    observed_interfaces, observed_netns, observed_nft, observed_tc = _network_state()
    filesystem_interfaces = tuple(_bounded_names("/sys/class/net"))
    filesystem_netns = tuple(_bounded_names("/run/netns"))
    interface_residue = set(observed_interfaces) | set(filesystem_interfaces)
    netns_residue = set(observed_netns) | set(filesystem_netns)
    _require(not (_named_residue("/sys/class/net")
                  or {"c42h0", "c42g0"} & interface_residue
                  or any(TOKEN_INTERFACE.fullmatch(name) for name in interface_residue)),
             "qualification network interface remains")
    _require(not (_named_residue("/run/netns")
                  or any(TOKEN_NETNS.fullmatch(name) for name in netns_residue)),
             "qualification network namespace remains")
    _require(not any(TOKEN_NFT.fullmatch(name) or name == "cogs_stage2_ssh_v1"
                     for name in observed_nft), "qualification firewall remains")
    _require(not any(TOKEN_RESOURCE.fullmatch(value) for value in observed_tc),
             "qualification traffic control remains")
    _require(not _walk_named("/sys/fs/cgroup"), "qualification cgroup remains")
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

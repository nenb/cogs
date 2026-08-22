#!/usr/bin/env python3
"""Bounded no-runtime source policy and owned process/fd census for static control."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True

VERSION = "cogs.stage2-static-control-runtime-boundary/v1"
REPOSITORY = Path(__file__).resolve().parents[1]
STATE = Path("/tmp/cogs-stage2-static-runtime-boundary-v1.json")
PROC = Path("/proc")
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 16 * 1024
MAX_PROCESSES = 32_768
MAX_FDS_PER_PROCESS = 4_096
MAX_TOTAL_FDS = 131_072
MAX_PROC_TEXT = 64 * 1024
WORKFLOW_PATH = ".github/workflows/stage2-local-static-control-candidate.yml"
NORMALIZED_WORKFLOW_SHA256 = "ce6a8a2594fef95a8c8e00b7d1cec067489dc136575247ff11a1ac4a60dc19f1"
REVIEWED_HEAD_ASSIGNMENT = re.compile(
    rb'REVIEWED_IMPLEMENTATION_HEAD = "[0-9a-f]{40}"')
POLICY = {
    "scripts/prepare-stage2-fixed-source.py": {
        "sha256": "e61029714b86575f0988663512f871718572d153bcbb41a3772ee1eddb31f22f",
        "effect": "fixed-source-materialization; reviewed child executable is isolated git cat-file only",
    },
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py": {
        "sha256": "cf1757832fdfd443dcb8265c32dec68e7a7e7c4d3c28e4246f00c27120a554c9",
        "effect": "immutable HTTPS acquisition and archive extraction only; runtime launch surfaces forbidden",
    },
    "deploy/aws-feasibility/remote/completion_kata_preparation.py": {
        "sha256": "be7743e0d06f63e1b184c4c7e29267dd7a81cf6374d9de28797bdd4b8103cedc",
        "effect": "deterministic static description only; reviewed child executable is zstd decompression only",
    },
}
OWNED_PREFIXES = (
    str(REPOSITORY) + "/",
    "/var/lib/cogs/",
    "/opt/kata/",
    "/run/vc/",
    "/run/netns/cogs-stage2-",
)
FORBIDDEN_EXECUTABLES = frozenset((
    "containerd", "containerd-shim-kata-v2", "ctr", "ip", "kata-runtime",
    "nft", "qemu-system-x86_64", "tc", "virtiofsd",
))


class BoundaryError(Exception):
    """The static-only boundary could not be proved."""


def _require(condition):
    if not condition:
        raise BoundaryError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def _stable_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum)
        chunks = []
        remaining = before.st_size
        while remaining:
            raw = os.read(descriptor, min(65_536, remaining))
            _require(raw)
            chunks.append(raw)
            remaining -= len(raw)
        _require(not os.read(descriptor, 1))
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        _require(all(getattr(before, name) == getattr(after, name) for name in fields))
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _source_policy(repository=REPOSITORY):
    observed = {}
    for relative, rule in POLICY.items():
        raw = _stable_bytes(repository / relative, MAX_POLICY_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        _require(digest == rule["sha256"])
        observed[relative] = digest
    workflow = _stable_bytes(repository / WORKFLOW_PATH, MAX_POLICY_BYTES)
    normalized, replacements = REVIEWED_HEAD_ASSIGNMENT.subn(
        b'REVIEWED_IMPLEMENTATION_HEAD = "<reviewed-H-binding>"', workflow)
    _require(replacements == 1 and
             hashlib.sha256(normalized).hexdigest() == NORMALIZED_WORKFLOW_SHA256)
    observed[WORKFLOW_PATH] = hashlib.sha256(workflow).hexdigest()
    return observed


def _small_proc_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks = []
        total = 0
        while total <= MAX_PROC_TEXT:
            raw = os.read(descriptor, min(4096, MAX_PROC_TEXT + 1 - total))
            if not raw:
                break
            chunks.append(raw)
            total += len(raw)
        _require(total <= MAX_PROC_TEXT)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _link(path):
    value = os.readlink(path)
    _require(type(value) is str and len(os.fsencode(value)) <= MAX_PROC_TEXT)
    return value


def _unix_sockets(proc):
    result = {}
    try:
        raw = _small_proc_file(proc / "net/unix")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return result
    for row in raw.decode("ascii", "replace").splitlines()[1:]:
        fields = row.split(maxsplit=7)
        if len(fields) >= 7 and fields[6].isdigit():
            result[fields[6]] = fields[7] if len(fields) == 8 else ""
    return result


def _is_owned(references, prefixes=OWNED_PREFIXES):
    return any(any(reference == prefix[:-1] or prefix in reference for prefix in prefixes)
               for reference in references)


def _process_violations(pid_root, host_net, sockets, prefixes=OWNED_PREFIXES):
    references = []
    try:
        cmdline = _small_proc_file(pid_root / "cmdline")
        references.extend(os.fsdecode(item) for item in cmdline.split(b"\0") if item)
        for name in ("exe", "cwd", "root"):
            try:
                references.append(_link(pid_root / name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
    except (FileNotFoundError, PermissionError, ProcessLookupError, BoundaryError):
        return (), 0
    owned = _is_owned(references, prefixes)
    violations = set()
    executable = ""
    if references:
        executable = os.path.basename(references[0].removesuffix(" (deleted)"))
    if owned and (executable in FORBIDDEN_EXECUTABLES or executable.startswith("qemu-system-")):
        violations.add("owned-runtime-process")
    if owned:
        try:
            if _link(pid_root / "ns/net") != host_net:
                violations.add("owned-network-namespace")
        except (FileNotFoundError, PermissionError, ProcessLookupError, BoundaryError):
            pass
    try:
        names = os.listdir(pid_root / "fd")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return tuple(sorted(violations)), 0
    _require(len(names) <= MAX_FDS_PER_PROCESS)
    count = 0
    for name in names:
        _require(name.isdigit())
        count += 1
        try:
            target = _link(pid_root / "fd" / name)
        except (FileNotFoundError, PermissionError, ProcessLookupError, BoundaryError):
            continue
        if not owned:
            continue
        normalized = target.removesuffix(" (deleted)")
        if normalized == "/dev/kvm":
            violations.add("owned-kvm-fd")
        if target.startswith("socket:[") and target.endswith("]"):
            socket_path = sockets.get(target[8:-1], "")
            lowered = socket_path.lower()
            if "qmp" in lowered or _is_owned((socket_path,), prefixes):
                violations.add("owned-qmp-or-runtime-socket")
    return tuple(sorted(violations)), count


def _census(proc=PROC, prefixes=OWNED_PREFIXES):
    names = [name for name in os.listdir(proc) if name.isdigit()]
    _require(len(names) <= MAX_PROCESSES)
    host_net = _link(proc / "self/ns/net")
    sockets = _unix_sockets(proc)
    violations = []
    total_fds = 0
    scanned = 0
    for name in sorted(names, key=int):
        rows, count = _process_violations(proc / name, host_net, sockets, prefixes)
        total_fds += count
        _require(total_fds <= MAX_TOTAL_FDS)
        scanned += 1
        violations.extend(f"{name}:{row}" for row in rows)
    return {
        "processes_scanned": scanned,
        "fds_scanned": total_fds,
        "violations": sorted(violations),
    }


def _context(proc=PROC):
    return {
        "boot_id": _small_proc_file(proc / "sys/kernel/random/boot_id").decode("ascii").strip(),
        "pid_namespace": _link(proc / "self/ns/pid"),
        "network_namespace": _link(proc / "self/ns/net"),
    }


def _write_state(value, path=STATE):
    raw = _canonical(value)
    _require(len(raw) <= MAX_STATE_BYTES)
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    except OSError:
        raise BoundaryError() from None
    try:
        _require(os.write(descriptor, raw) == len(raw))
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_state(path=STATE):
    raw = _stable_bytes(path, MAX_STATE_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BoundaryError() from error
    _require(type(value) is dict and _canonical(value) == raw)
    _require(set(value) == {"version", "context", "policy", "baseline"} and value["version"] == VERSION)
    return value


def establish(repository=REPOSITORY, proc=PROC, state=STATE, prefixes=OWNED_PREFIXES):
    _require(os.geteuid() == 0 and not state.exists())
    policy = _source_policy(repository)
    census = _census(proc, prefixes)
    _require(census["violations"] == [])
    _write_state({
        "version": VERSION,
        "context": _context(proc),
        "policy": policy,
        "baseline": census,
    }, state)


def verify(repository=REPOSITORY, proc=PROC, state=STATE, prefixes=OWNED_PREFIXES):
    _require(os.geteuid() == 0)
    value = _read_state(state)
    try:
        _require(value["context"] == _context(proc))
        _require(value["policy"] == _source_policy(repository))
        _require(value["baseline"]["violations"] == [])
        final = _census(proc, prefixes)
        _require(final["violations"] == [])
    finally:
        state.unlink(missing_ok=False)


def main():
    _require(len(sys.argv) == 2 and sys.argv[1] in {"pre", "post"})
    if sys.argv[1] == "pre":
        establish()
    else:
        verify()
    return 0


if __name__ == "__main__":
    try:
        status = main()
    except BaseException:
        try:
            sys.stderr.write(f"{VERSION}: BOUNDARY_REJECTED\n")
        except BaseException:
            pass
        status = 2
    raise SystemExit(status)

#!/usr/bin/env python3
"""Portable contract snapshots and Linux direct-child supervisor tests."""
import errno
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import struct
import sys
import tempfile
import time
from unittest.mock import patch

if sys.flags.optimize:
    raise RuntimeError("process tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
if os.getenv("COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1") == "1":
    sys.excepthook = lambda *_args: os.write(2, b"native-process-failure:bootstrap\n")
import completion_kata_process as process


_NATIVE_SELECTOR = "COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1"
_NATIVE_MARKER = "completion Kata process LINUX AMD64 QUALIFIED matrix passed"
_NATIVE_PHASE = "selector"
_ZSTD_RAW = b"cogs-native-zstd\n"
_ZSTD_STREAM = bytes.fromhex(
    "28b52ffd0458890000636f67732d6e61746976652d7a7374640a2c9648cf"
)


def _native_selected():
    value = os.getenv(_NATIVE_SELECTOR)
    if value is None:
        return False
    if value != "1":
        raise RuntimeError("native runtime preflight selector must be exactly 1")
    entries = Path("/proc/self/environ").read_bytes().split(b"\0")
    selected = [entry for entry in entries if entry.startswith((_NATIVE_SELECTOR + "=").encode())]
    if selected != [(_NATIVE_SELECTOR + "=1").encode()]:
        raise RuntimeError("native runtime preflight selector must occur exactly once")
    return True


def _native_envelope(pid=None, expected_parent=None):
    target = "self" if pid is None else str(pid)
    fields = {}
    for line in Path(f"/proc/{target}/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            fields[name] = value.strip()
    if pid is None:
        assert platform.system() == "Linux" and platform.machine() == "x86_64"
        assert os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
        assert os.getgroups() == []
        assert fields["NoNewPrivs"] == "1"
        assert len(fields["NSpid"].split()) == 1 and int(fields["NSpid"]) > 1
    else:
        row = process._proc_row(pid)
        assert row[0] == pid and row[1] == expected_parent and row[2] == row[3] == pid
        assert len(fields["NSpid"].split()) == 1 and int(fields["NSpid"]) > 1
    assert fields["Uid"].split() == ["0"] * 4
    assert fields["Gid"].split() == ["0"] * 4
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(fields[name], 16) == 0
    if pid is None:
        for path in ("/usr/bin/python3", "/usr/bin/zstd", "/usr/bin/gzip"):
            observed = os.stat(path, follow_symlinks=False)
            if observed.st_uid != 0 or observed.st_gid != 0:
                raise RuntimeError("native sandbox host-root ownership mapping architecture blocker")


def _bounded_read(descriptor, size, seconds=10):
    deadline = time.monotonic() + seconds
    body = bytearray()
    while len(body) < size:
        remaining = deadline - time.monotonic()
        assert remaining > 0
        ready, _, _ = select.select((descriptor,), (), (), remaining)
        assert ready
        part = os.read(descriptor, size - len(body))
        assert part
        body.extend(part)
    return bytes(body)


def _bounded_wait(pid, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        time.sleep(0.005)
    raise AssertionError(f"bounded wait expired for {pid}")


def _archive_bytes(asset):
    if asset is process.kata_runtime.FixedArchive.KATA_ZSTD:
        return _ZSTD_STREAM, _ZSTD_RAW
    raw = b"cogs-native-gzip\n"
    return gzip.compress(raw, mtime=0), raw


def _native_archive_success(owner, asset, inherited):
    compressed, expected = _archive_bytes(asset)
    assert 0 < len(compressed) <= 65_536 and len(expected) <= 65_536
    callbacks = []
    opened = []
    with tempfile.TemporaryFile() as archive:
        archive.write(compressed)
        archive.flush()
        archive.seek(0)
        real_gate = process._wait_for_preinput_read
        real_mapped = process._mapped_closure
        real_open = process.os.open

        def intent(value):
            callbacks.append(("intent", value))
            return "9" * 64

        def started(value):
            _native_envelope(value.process.pid, os.getpid())
            callbacks.append(("started", value))
            return "a" * 64

        def settled(value):
            callbacks.append(("settled", value))
            return "b" * 64

        def read_gate(pid, deadline_ns):
            result = real_gate(pid, deadline_ns)
            assert archive.tell() == 0
            callbacks.append(("read-gate", pid))
            return result

        def tracking_open(path, *args, **kwargs):
            descriptor = real_open(path, *args, **kwargs)
            if path == f"/proc/{callbacks[1][1].process.pid}" or kwargs.get("dir_fd") in opened:
                opened.append(descriptor)
            return descriptor

        def mapped_closure(pid, closure):
            assert callbacks[-1] == ("read-gate", pid) and archive.tell() == 0
            _native_envelope(pid, os.getpid())
            assert process._proc_row(pid) == tuple(
                getattr(callbacks[1][1].process, name)
                for name in ("pid", "ppid", "pgid", "sid", "starttime")
            )
            for descriptor in inherited:
                try:
                    os.stat(f"/proc/{pid}/fd/{descriptor}")
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError(f"archive child inherited fd {descriptor}")
            before = set(os.listdir("/proc/self/fd"))
            with patch.object(process.os, "open", side_effect=tracking_open):
                result = real_mapped(pid, closure)
            assert set(os.listdir("/proc/self/fd")) == before
            assert opened
            for descriptor in opened:
                try:
                    os.fstat(descriptor)
                except OSError as error:
                    assert error.errno == errno.EBADF
                else:
                    raise AssertionError(f"mapped-closure fd {descriptor} remained open")
            callbacks.append(("mapped", pid))
            return result

        deadline_ns = time.monotonic_ns() + 20_000_000_000
        with patch.object(process, "_wait_for_preinput_read", side_effect=read_gate), \
             patch.object(process, "_mapped_closure", side_effect=mapped_closure):
            stream = owner.open_archive_stream(
                asset, archive.fileno(), intent, started, settled, deadline_ns,
            )
        output = bytearray()
        while True:
            chunk = stream.read()
            if not chunk:
                break
            output.extend(chunk)
            assert len(output) <= 65_536
        outcome = stream.settle()
    assert bytes(output) == expected
    assert [name for name, _value in callbacks] == [
        "intent", "started", "read-gate", "mapped", "settled",
    ]
    assert outcome.status == 0 and outcome.reaped and outcome.descendants_absent
    assert outcome.stdout_bytes == len(expected) and outcome.errors == ()
    identity = callbacks[1][1].process
    assert not Path(f"/proc/{identity.pid}").exists()
    assert process._archive_processes(identity) == ()


def _death_report(stage, identity, descriptor):
    row = process._proc_row(identity.process.pid)
    assert row == (
        identity.process.pid, identity.process.ppid, identity.process.pgid,
        identity.process.sid, identity.process.starttime,
    )
    body = struct.pack("!6Q", stage, *row)
    assert os.write(descriptor, body) == len(body)


def _native_parent_death(after_release):
    report_r, report_w = os.pipe2(os.O_CLOEXEC)
    supervisor = os.fork()
    if supervisor == 0:
        os.close(report_r)
        try:
            owner = process._RuntimeDiscoveryHost()
            compressed, _raw = _archive_bytes(process.kata_runtime.FixedArchive.KATA_ZSTD)
            archive = tempfile.TemporaryFile()
            archive.write(compressed)
            archive.seek(0)
            started_identity = [None]

            def started(identity):
                started_identity[0] = identity
                if not after_release:
                    _death_report(0, identity, report_w)
                    os._exit(0)
                return "d" * 64

            real_mapped = process._mapped_closure

            def mapped(pid, closure):
                assert started_identity[0] is not None and pid == started_identity[0].process.pid
                _death_report(1, started_identity[0], report_w)
                os._exit(0)

            with patch.object(process, "_mapped_closure", side_effect=mapped if after_release else real_mapped):
                owner.open_archive_stream(
                    process.kata_runtime.FixedArchive.KATA_ZSTD,
                    archive.fileno(), lambda _value: "c" * 64, started,
                    lambda _value: "e" * 64, time.monotonic_ns() + 20_000_000_000,
                )
        except BaseException:
            os._exit(90)
        os._exit(91)
    os.close(report_w)
    raw = _bounded_read(report_r, 48)
    os.close(report_r)
    stage, child, ppid, pgid, sid, starttime = struct.unpack("!6Q", raw)
    assert stage == int(after_release) and ppid == supervisor and child == pgid == sid
    assert _bounded_wait(supervisor) == 0
    child_status = _bounded_wait(child)
    assert os.WIFSIGNALED(child_status) and os.WTERMSIG(child_status) == signal.SIGKILL
    assert not Path(f"/proc/{child}").exists()
    identity = process.ProcessIdentity(
        child, ppid, pgid, sid, starttime, process._boot_id(), False,
    )
    assert process._archive_processes(identity) == ()
    assert process._runtime_discovery_process_residue()


def _native_runtime_preflight():
    global _NATIVE_PHASE
    _NATIVE_PHASE = "envelope"
    _native_envelope()
    _NATIVE_PHASE = "descriptor-baseline"
    baseline = set(os.listdir("/proc/self/fd"))
    _NATIVE_PHASE = "descriptor-open"
    base = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    _NATIVE_PHASE = "descriptor-dup2"
    os.dup2(base, 198, inheritable=True)
    _NATIVE_PHASE = "descriptor-fcntl"
    high = fcntl.fcntl(base, fcntl.F_DUPFD, 4096)
    assert high == 4096
    _NATIVE_PHASE = "descriptor-inherit"
    os.set_inheritable(high, True)
    try:
        closures = []
        for tool, path in process._HOST_TOOLS:
            _NATIVE_PHASE = "host-closure-" + tool
            closure, cache, root = process._host_closure(tool, path)
            closures.append(closure)
            if tool == "python3-parser":
                _NATIVE_PHASE = "mapped-proc"
                proc = os.open(f"/proc/{os.getpid()}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    _NATIVE_PHASE = "mapped-maps"
                    with open(f"/proc/self/fd/{proc}/maps", "rb") as maps_file:
                        maps = maps_file.read(4 * 1024 * 1024)
                    _NATIVE_PHASE = "mapped-exe"
                    os.stat("exe", dir_fd=proc)
                    _NATIVE_PHASE = "mapped-files"
                    for line in maps.splitlines():
                        fields = line.split(maxsplit=5)
                        if len(fields) >= 5 and b"x" in fields[1] and fields[4] != b"0":
                            descriptor = os.open("map_files/" + fields[0].decode("ascii"), os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
                            os.close(descriptor)
                finally:
                    os.close(proc)
                _NATIVE_PHASE = "host-mapped"
                process._mapped_closure(os.getpid(), closure, False)
            else:
                _NATIVE_PHASE = "host-sealed-" + tool
                sealed = process._sealed_bound(root)
                os.close(sealed)
                process._DISCOVERY_FDS.discard(sealed)
            process._close_host_bounds(cache.values(), "native host closure close")
        _NATIVE_PHASE = "host-aggregate"
        assert sum(item.total_bytes for item in closures) <= process.MAX_ARTIFACT_BYTES
        _NATIVE_PHASE = "host-init"
        owner = process._RuntimeDiscoveryHost()
        try:
            _NATIVE_PHASE = "zstd"
            _native_archive_success(owner, process.kata_runtime.FixedArchive.KATA_ZSTD, (198, 4096))
            _NATIVE_PHASE = "gzip"
            _native_archive_success(owner, process.kata_runtime.FixedArchive.CONTAINERD_GZIP, (198, 4096))
        finally:
            owner.close()
        _NATIVE_PHASE = "pdeath-before"
        _native_parent_death(False)
        _NATIVE_PHASE = "pdeath-after"
        _native_parent_death(True)
        _NATIVE_PHASE = "residue"
        assert process._runtime_discovery_process_residue()
    finally:
        os.close(4096)
        os.close(198)
        os.close(base)
    assert set(os.listdir("/proc/self/fd")) == baseline


if _native_selected():
    try:
        _native_runtime_preflight()
    except BaseException:
        os.write(2, f"native-process-failure:{_NATIVE_PHASE}\n".encode("ascii"))
        raise SystemExit(1)
    print(_NATIVE_MARKER, flush=True)
    raise SystemExit(0)


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile process case accepted")


def contract_rejected(raw):
    try:
        process._parse_contract(raw, hashlib.sha256(raw).hexdigest())
    except process.ProcessError:
        return
    except BaseException as error:
        raise AssertionError(f"contract failure was not normalized: {type(error).__name__}") from error
    raise AssertionError("hostile contract accepted")


# Closed production snapshots contain no caller-selected token.  These exact
# values are future actions only; no production execution issuer exists.
snapshots = {name: (argv, stdin, deadline, fds) for name, argv, stdin, deadline, fds in process._fixed_spec_snapshots_for_tests()}
assert snapshots["CTR_TASK_TERM"] == (("/usr/bin/ctr", "--namespace", "cogs-stage2-completion-v1", "tasks", "kill", "--signal", "SIGTERM", "cogs-stage2-ssh-v1"), b"", "task-term", ())
assert process.NFT_INPUT.endswith(b'add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop\n')
unissued = {item.command_id: item for item in process._unissued_spec_snapshots_for_tests()}
assert unissued["IP_NETNS_ADD"].tool_contract == "ip"
assert unissued["IP_NETNS_ADD"].argv_tail == ("netns", "add", "cogs-stage2-ssh")
assert unissued["IP_PEER_ADDRGEN_NONE"].argv_tail[-2:] == ("addrgenmode", "none")
assert unissued["NFT_INSTALL"].tool_contract == "nft"
assert unissued["NFT_INSTALL"].argv_tail == ("-f", "-")
assert unissued["NFT_INSTALL"].stdin == process.NFT_INPUT
assert snapshots["SSH_READY"][0][-2:] == ("root@192.0.2.2", "printf '%s\\n' COGS_STAGE2_SSH_READY_V1")
assert snapshots["SSH_READY"][2:] == ("ssh", (200, 201))
assert len(snapshots) == 8
rejected(lambda: process._spec("IP_NETNS_ADD"))
rejected(lambda: process._test_spec("ok"))
BOOT_A = "12345678-1234-1234-1234-123456789abc"
BOOT_B = "abcdefab-cdef-abcd-efab-cdefabcdefab"
fake_identity = process.ProcessIdentity(10, 1, 10, 10, 99, BOOT_A, True)
exact = process.RecoveryObservation(process.ObservationKind.EXACT, (10, 1, 10, 10, 99))
mismatch = process.RecoveryObservation(process.ObservationKind.EXACT, (10, 1, 10, 10, 100))
absent = process.RecoveryObservation(process.ObservationKind.ABSENT)
unknown = process.RecoveryObservation(process.ObservationKind.UNKNOWN)
assert process._recovery_class(fake_identity, BOOT_A, exact) == "exact_live"
assert process._recovery_class(fake_identity, BOOT_B, exact) == "recovery_absent"
assert process._recovery_class(fake_identity, BOOT_A, absent) == "recovery_absent"
assert process._recovery_class(fake_identity, BOOT_A, unknown) == "uncertain"
assert process._recovery_class(fake_identity, BOOT_A, mismatch) == "uncertain"
rejected(lambda: process._recovery_class(fake_identity, "boot-a", absent))
rejected(lambda: process._recovery_class(fake_identity, BOOT_A, None))
rejected(lambda: process._recovery_class(fake_identity, BOOT_A, process.RecoveryObservation(process.ObservationKind.ABSENT, (1,))))
for command in (
    process.CommandId.IP_NETNS_ADD,
    process.CommandId.NFT_INSTALL,
    process.CommandId.SSH_KEYGEN_CLIENT,
    process.CommandId.SSH_PUBLIC_CLIENT,
):
    rejected(lambda command=command: process._spec(command))

# Contract decoding requires canonical, digest-bound, exact typed records.
def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def contract_for(path, command="TEST_HELPER"):
    raw = path.read_bytes()
    artifact = {
        "logical_path": str(path), "role": "executable", "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw), "soname": None,
    }
    body = {
        "architecture": "x86_64", "command_id": command, "dynamic_tags": [],
        "executable": artifact, "libraries": [], "loader": None,
        "version": process.CONTRACT_VERSION,
    }
    value = {**body, "closure_sha256": hashlib.sha256(canonical(body)).hexdigest()}
    encoded = canonical(value)
    return encoded, hashlib.sha256(encoded).hexdigest()


placeholder = Path(process.TEST_PATH)
value = {
    "architecture": "x86_64", "closure_sha256": "1" * 64, "command_id": "TEST_HELPER",
    "dynamic_tags": [], "executable": {
        "logical_path": process.TEST_PATH, "role": "executable", "sha256": "2" * 64,
        "size": 1, "soname": None,
    }, "libraries": [], "loader": None, "version": process.CONTRACT_VERSION,
}
encoded = canonical(value)
rejected(lambda: process._parse_contract(encoded, "0" * 64))
rejected(lambda: process._parse_contract(encoded.replace(b'"version"', b'"version" '), hashlib.sha256(encoded.replace(b'"version"', b'"version" ')).hexdigest()))
duplicate = encoded.replace(b'{', b'{"version":"duplicate",', 1)
rejected(lambda: process._parse_contract(duplicate, hashlib.sha256(duplicate).hexdigest()))
for tags in (["RPATH"], ["RUNPATH"], ["AUDIT"], [{"unhashable": True}], ["A", 1]):
    hostile = {**value, "dynamic_tags": tags}
    raw = canonical(hostile)
    contract_rejected(raw)
for command in (None, "", "caller-selected", "A" * 65):
    hostile = {**value, "command_id": command}
    raw = canonical(hostile)
    contract_rejected(raw)
for soname in ("libx.so/evil", "libx so.1", "libx..so.1", ".", "x.so.1", "libx.so.latest", "libx.so\x00.1"):
    artifact = {**value["executable"], "role": "library", "soname": soname}
    rejected(lambda artifact=artifact: process._artifact(artifact, "library"))
large = 128 * 1024 * 1024
libraries = [{"logical_path": f"/lib/libx{i}.so.1", "role": "library", "sha256": f"{i + 3:x}" * 64,
              "size": large, "soname": f"libx{i}.so.1"} for i in range(4)]
loader = {"logical_path": "/lib/ld-test.so", "role": "loader", "sha256": "9" * 64, "size": 1, "soname": None}
overflow_body = {name: item for name, item in value.items() if name != "closure_sha256"}
overflow_body.update({"libraries": libraries, "loader": loader})
overflow = {**overflow_body, "closure_sha256": hashlib.sha256(canonical(overflow_body)).hexdigest()}
raw = canonical(overflow)
contract_rejected(raw)
deeply_nested = b"[" * 1_200 + b"0" + b"]" * 1_200
contract_rejected(deeply_nested)


# Every production host-closure close path attempts all descriptors and turns
# close uncertainty into a failed transition.
real_close = os.close


def close_fault(descriptor):
    real_close(descriptor)
    raise OSError(errno.EIO, "fixed injected descriptor close failure")


proc_r, proc_w = os.pipe()
maps_r, maps_w = os.pipe()
mapped_closes = []


def mapped_close_fault(descriptor):
    mapped_closes.append(descriptor)
    close_fault(descriptor)


try:
    with patch.object(process.os, "open", side_effect=(proc_r, maps_r)), \
         patch.object(process.os, "read", side_effect=OSError(errno.EIO, "fixed maps read failure")), \
         patch.object(process.os, "close", side_effect=mapped_close_fault):
        try:
            process._mapped_closure(123, None)
        except process.ProcessError as error:
            mapped_error = str(error)
        else:
            raise AssertionError("mapped closure close faults were accepted")
    assert set(mapped_closes) == {maps_r, proc_r}
    assert all(f"fd={descriptor}" in mapped_error for descriptor in (maps_r, proc_r))
finally:
    os.close(proc_w)
    os.close(maps_w)

root_r, root_w = os.pipe()
loader_r, loader_w = os.pipe()
root_bound = process._HostBound(
    "/fixed/gzip", root_r, (1, 1, 1, 1, 1), b"root", process._HOST_INTERP, None, ())
loader_bound = process._HostBound(
    process._HOST_INTERP, loader_r, (1, 2, 1, 1, 1), b"loader", None, None, ())
process._DISCOVERY_FDS.update((root_r, loader_r))
host_closes = []


def host_close_fault(descriptor):
    host_closes.append(descriptor)
    close_fault(descriptor)


try:
    with patch.object(process, "_host_read", side_effect=(root_bound, loader_bound)), \
         patch.object(process, "_canonical", side_effect=process.ProcessError("fixed proof failure")), \
         patch.object(process.os, "close", side_effect=host_close_fault):
        try:
            process._host_closure("gzip", "/fixed/gzip")
        except process.ProcessError as error:
            host_error = str(error)
        else:
            raise AssertionError("host closure close faults were accepted")
    assert set(host_closes) == {root_r, loader_r}
    assert "/fixed/gzip" in host_error and process._HOST_INTERP in host_error
    assert not {root_r, loader_r} & process._DISCOVERY_FDS
finally:
    os.close(root_w)
    os.close(loader_w)

host_pairs = [os.pipe() for _unused in range(4)]
host_readers = [pair[0] for pair in host_pairs]
host_writers = [pair[1] for pair in host_pairs]
fake_host = object.__new__(process._RuntimeDiscoveryHost)
fake_host._closures = []
fake_host._bounds = [
    process._HostBound(f"/fixed/bound-{index}", descriptor, (1, index, 1, 1, 1), b"", None, None, ())
    for index, descriptor in enumerate(host_readers[2:])
]
fake_host._executables = {
    process.kata_runtime.FixedArchive.KATA_ZSTD: host_readers[0],
    process.kata_runtime.FixedArchive.CONTAINERD_GZIP: host_readers[1],
}
fake_host._next = 0
fake_host._closed = False
fake_host._close_failure = None
process._DISCOVERY_FDS.update(host_readers)
runtime_closes = []


def runtime_close_fault(descriptor):
    runtime_closes.append(descriptor)
    close_fault(descriptor)


try:
    with patch.object(process.os, "close", side_effect=runtime_close_fault):
        try:
            fake_host.close()
        except process.ProcessError as error:
            runtime_close_error = str(error)
        else:
            raise AssertionError("runtime host close faults were accepted")
    assert set(runtime_closes) == set(host_readers)
    assert all(str(descriptor) in runtime_close_error for descriptor in host_readers[:2])
    assert "/fixed/bound-0" in runtime_close_error
    assert "/fixed/bound-1" in runtime_close_error
    assert not fake_host._closed and not set(host_readers) & process._DISCOVERY_FDS
    rejected(fake_host.close)
    assert set(runtime_closes) == set(host_readers)
finally:
    for descriptor in host_writers:
        os.close(descriptor)


print("completion Kata process portable matrix passed; native runtime preflight SKIPPED")

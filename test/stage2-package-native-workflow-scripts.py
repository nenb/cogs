#!/usr/bin/env python3
"""Executable hostile tests for fixed native workflow security scripts."""
import array
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


settlement = load("stage2_native_settlement", "scripts/stage2-native-settlement.py")
publication = load("stage2_native_publication", "scripts/stage2-native-publication.py")
receipt = load("stage2_native_upload_receipt", "scripts/stage2-native-upload-receipt.py")
contract = sys.modules["completion_runtime_contract"]
native_codec = sys.modules["completion_package_native_codec"]


def rejected(call, exception):
    try:
        call()
    except exception:
        return
    raise AssertionError(f"did not reject with {exception.__name__}")


def rejection_message(call, exception):
    try:
        call()
    except exception as error:
        return str(error)
    raise AssertionError(f"did not reject with {exception.__name__}")


def terminate(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def live_process_tests():
    if Path("/proc/self").is_dir() and os.geteuid() == 0:
        self_marker = b"stage2-package-native-workflow-scripts.py"
        settlement.scan("before-unmount", targets=("/observer-self-test",),
                        marker=self_marker)
        sibling = subprocess.Popen([
            sys.executable, "-c", "import time;time.sleep(30)", self_marker.decode(),
        ])
        try:
            time.sleep(0.05)
            rejected(lambda: settlement.scan(
                "before-unmount", targets=("/observer-self-test",), marker=self_marker),
                settlement.SettlementError)
        finally:
            terminate(sibling)

    marker = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)",
                               "run-stage2-package-native-candidate.py"])
    try:
        time.sleep(0.05)
        rejected(lambda: settlement.scan("before-unmount", targets=settlement.FIXED_TARGETS),
                 settlement.SettlementError)
    finally:
        terminate(marker)

    with tempfile.TemporaryDirectory() as temporary:
        target = str(Path(temporary).resolve())
        cwd_process = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], cwd=target)
        try:
            rejected(lambda: settlement.scan("before-unmount", targets=(target,)),
                     settlement.SettlementError)
        finally:
            terminate(cwd_process)
        held = Path(target) / "held"
        held.write_bytes(b"held")
        fd_process = subprocess.Popen([
            sys.executable, "-c",
            "import os,sys,time;f=os.open(sys.argv[1],os.O_RDONLY);"
            "print('READY',flush=True);time.sleep(30)", str(held),
        ], stdout=subprocess.PIPE)
        try:
            assert fd_process.stdout is not None and fd_process.stdout.readline() == b"READY\n"
            rejected(lambda: settlement.scan("before-unmount", targets=(target,)),
                     settlement.SettlementError)
        finally:
            terminate(fd_process)

        if Path("/proc/self/fd").exists() and os.geteuid() == 0:
            churn = subprocess.Popen([
                sys.executable, "-c",
                "import os,time\nprint('READY',flush=True)\nend=time.monotonic()+20\n"
                "while time.monotonic()<end:\n"
                " f=os.open('/dev/null',os.O_RDONLY);os.close(f);time.sleep(0.001)",
            ], stdout=subprocess.PIPE)
            try:
                assert churn.stdout is not None and churn.stdout.readline() == b"READY\n"
                settlement.scan("before-unmount", targets=(target,))
            finally:
                terminate(churn)


def process_stat(pid, starttime):
    return f"{pid} (synthetic process) S " + " ".join(["0"] * 18 + [str(starttime)]) + "\n"


def synthetic_proc(mount_target):
    temporary = tempfile.TemporaryDirectory()
    proc = Path(temporary.name)
    (proc / "self/ns").mkdir(parents=True)
    (proc / "self/ns/mnt").write_bytes(b"own")
    pid = proc / "41"
    (pid / "ns").mkdir(parents=True)
    (pid / "fd").mkdir()
    (pid / "stat").write_text(process_stat(41, 100))
    (pid / "ns/mnt").write_bytes(b"foreign")
    (pid / "cmdline").write_bytes(b"harmless\0")
    (pid / "mountinfo").write_bytes(
        f"1 2 0:1 / {mount_target} rw - tmpfs tmpfs rw\n".encode())
    for name in ("root", "cwd", "exe"):
        (pid / name).symlink_to("/")
    return temporary, proc, pid


def extended_convergence_tests():
    with tempfile.TemporaryDirectory() as temporary:
        proc = Path(temporary)
        (proc / "self/ns").mkdir(parents=True)
        (proc / "self/ns/mnt").write_bytes(b"own")
        original_inventory = settlement._inventory
        original_inspect = settlement._inspect_generation
        original_sleep = settlement.time.sleep
        try:
            settlement.time.sleep = lambda _seconds: None
            def run_pattern(pattern, late_target=False):
                calls = [0]
                def inventory(_proc_root):
                    pass_index, half = divmod(calls[0], 2)
                    calls[0] += 1
                    stable = pattern[pass_index] if pass_index < len(pattern) else True
                    before = {"41": 100}
                    after = before if stable else {"41": 100, str(1000 + pass_index): 2000 + pass_index}
                    return (before if half == 0 else after), True
                def inspect(*_arguments):
                    if late_target and calls[0] > 26:
                        raise settlement.SettlementError("unsettled candidate process: 41")
                    return True
                settlement._inventory = inventory
                settlement._inspect_generation = inspect
                settlement.scan("before-unmount", proc_root=proc, targets=("/target",))
                return calls[0]

            assert run_pattern([False] * 13 + [True] * 3) == 28
            assert run_pattern([True, True, False, True, True, True]) == 8
            rejected(lambda: run_pattern([False] * 13 + [True] * 3, True),
                     settlement.SettlementError)

            changing_calls = [0]
            def changing_inventory(_proc_root):
                pass_index, half = divmod(changing_calls[0], 2)
                changing_calls[0] += 1
                current = {"41": 100}
                if half == 0:
                    current[str(2000 + pass_index)] = 3000 + pass_index
                return current, True
            settlement._inventory = changing_inventory
            settlement._inspect_generation = lambda *_arguments: True
            settlement.scan("before-unmount", proc_root=proc, targets=("/target",))
            assert changing_calls[0] == 6

            replacement_calls = [0]
            def replacement_inventory(_proc_root):
                pass_index = replacement_calls[0] // 2
                replacement_calls[0] += 1
                return ({"41": 100} if pass_index == 0 else {"42": 200}), True
            settlement._inventory = replacement_inventory
            settlement._inspect_generation = lambda *_arguments: True
            settlement.scan("before-unmount", proc_root=proc, targets=("/target",))
            assert replacement_calls[0] == 8
        finally:
            settlement._inventory = original_inventory
            settlement._inspect_generation = original_inspect
            settlement.time.sleep = original_sleep


def scanner_race_and_mount_tests():
    temporary, proc, _pid = synthetic_proc("/unrelated")
    original_starttime = settlement._starttime
    original_slot = settlement._slot_generation
    try:
        settlement.scan("before-unmount", proc_root=proc, targets=("/target",))
        settlement._starttime = lambda _base: None
        assert settlement._inventory(proc) == ({}, True)
        observations = iter((("unstable", None), ("stable", 200)))
        settlement._slot_generation = lambda *_args: next(observations)
        assert settlement._inventory(proc) == ({"41": 200}, True)
        settlement._slot_generation = lambda *_args: ("unstable", None)
        assert settlement._inventory(proc) == ({}, False)
    finally:
        settlement._starttime = original_starttime
        settlement._slot_generation = original_slot
        temporary.cleanup()

    temporary, proc, _pid = synthetic_proc("/run/cogs-stage2-native-private-v1")
    try:
        rejected(lambda: settlement.scan("before-unmount", proc_root=proc,
                                          targets=settlement.FIXED_TARGETS),
                 settlement.SettlementError)
    finally:
        temporary.cleanup()

    # A vanished per-process file is not accepted while the same starttime identity lives.
    temporary, proc, pid = synthetic_proc("/unrelated")
    original = settlement._bytes
    try:
        settlement._bytes = lambda path, *args: None if Path(path) == pid / "mountinfo" else original(path, *args)
        rejected(lambda: settlement.scan("before-unmount", proc_root=proc, targets=("/target",)),
                 settlement.SettlementError)
    finally:
        settlement._bytes = original
        temporary.cleanup()

    # A listed descriptor that vanishes in a foreign namespace stays incomplete.
    temporary, proc, pid = synthetic_proc("/unrelated")
    original_link = settlement._link
    descriptor_path = pid / "fd" / "7"
    descriptor_path.symlink_to("/unrelated")
    try:
        def close_unrelated(path):
            if Path(path) == descriptor_path:
                descriptor_path.unlink()
                return None
            return original_link(path)
        settlement._link = close_unrelated
        assert not settlement._inspect_generation(
            "before-unmount", proc, "41", 100,
            settlement._identity(proc / "self/ns/mnt"), ("/target",), settlement.MARKER)
    finally:
        settlement._link = original_link
        temporary.cleanup()

    # Same-namespace control-process FD closes are tolerated, while observed
    # targets and namespace transitions remain fail closed.
    temporary, proc, pid = synthetic_proc("/unrelated")
    own_mount = proc / "self/ns/mnt"
    process_mount = pid / "ns/mnt"
    process_mount.unlink()
    os.link(own_mount, process_mount)
    descriptor_path = pid / "fd" / "7"
    descriptor_path.symlink_to("/unrelated")
    original_link = settlement._link
    original_bytes = settlement._bytes
    try:
        settlement._link = lambda path: (
            None if Path(path) == descriptor_path else original_link(path))
        assert settlement._inspect_generation(
            "before-unmount", proc, "41", 100, settlement._identity(own_mount),
            ("/target",), settlement.MARKER)

        settlement._link = original_link
        descriptor_path.unlink()
        descriptor_path.symlink_to("/target/held")
        message = rejection_message(lambda: settlement._inspect_generation(
            "before-unmount", proc, "41", 100, settlement._identity(own_mount),
            ("/target",), settlement.MARKER), settlement.SettlementError)
        assert message.startswith("unsettled process descriptor:")

        descriptor_path.unlink()
        (pid / "mountinfo").write_bytes(
            b"1 2 0:1 / /target rw - tmpfs tmpfs rw\n")
        message = rejection_message(lambda: settlement._inspect_generation(
            "after-unmount", proc, "41", 100, settlement._identity(own_mount),
            ("/target",), settlement.MARKER), settlement.SettlementError)
        assert message.startswith("unsettled target mount namespace:")

        (pid / "mountinfo").write_bytes(
            b"1 2 0:1 / /unrelated rw - tmpfs tmpfs rw\n")
        def change_namespace_during_mount(path, *args):
            raw = original_bytes(path, *args)
            if Path(path) == pid / "mountinfo":
                process_mount.unlink()
                process_mount.write_bytes(b"foreign-during-mount")
            return raw
        settlement._bytes = change_namespace_during_mount
        assert not settlement._inspect_generation(
            "before-unmount", proc, "41", 100, settlement._identity(own_mount),
            ("/target",), settlement.MARKER)
        settlement._bytes = original_bytes
        process_mount.unlink()
        os.link(own_mount, process_mount)

        descriptor_path.symlink_to("/unrelated")
        def change_namespace(path):
            if Path(path) == descriptor_path:
                process_mount.unlink()
                process_mount.write_bytes(b"foreign-again")
            return original_link(path)
        settlement._link = change_namespace
        assert not settlement._inspect_generation(
            "before-unmount", proc, "41", 100, settlement._identity(own_mount),
            ("/target",), settlement.MARKER)
    finally:
        settlement._link = original_link
        settlement._bytes = original_bytes
        temporary.cleanup()

    # Reuse/change of a listed PID is retried as a new process generation, not skipped.
    temporary, proc, pid = synthetic_proc("/unrelated")
    original = settlement._bytes
    changed = False
    target = Path(temporary.name) / "target"
    target.mkdir()
    try:
        def reuse(path, *args):
            nonlocal changed
            if not changed and Path(path) == pid / "mountinfo":
                changed = True
                (pid / "stat").write_text(process_stat(41, 200))
                (pid / "cwd").unlink()
                (pid / "cwd").symlink_to(target)
            return original(path, *args)
        settlement._bytes = reuse
        rejected(lambda: settlement.scan("before-unmount", proc_root=proc,
                                          targets=(str(target),)), settlement.SettlementError)
    finally:
        settlement._bytes = original
        temporary.cleanup()

    # A real process born after the first inventory is found by the repeated generation scan.
    with tempfile.TemporaryDirectory() as target:
        child = None
        original_inspect = settlement._inspect_generation
        try:
            def spawn_during(*args, **kwargs):
                nonlocal child
                if child is None:
                    child = subprocess.Popen(
                        [sys.executable, "-c", "import time;time.sleep(30)"], cwd=target)
                return original_inspect(*args, **kwargs)
            settlement._inspect_generation = spawn_during
            rejected(lambda: settlement.scan("before-unmount", targets=(target,)),
                     settlement.SettlementError)
            if Path("/proc/self/ns/mnt").exists():
                assert child is not None and child.poll() is None
        finally:
            settlement._inspect_generation = original_inspect
            if child is not None:
                terminate(child)

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bounded = root / "bounded"
        bounded.write_bytes(b"12345678")
        assert settlement._bytes(bounded, 8) == b"12345678"
        bounded.write_bytes(b"123456789")
        rejected(lambda: settlement._bytes(bounded, 8), settlement.SettlementError)
        inventory = root / "inventory"
        inventory.mkdir()
        for name in ("1", "2", "3"):
            (inventory / name).mkdir()
        rejected(lambda: settlement._names(
            inventory, 2, "process inventory failed"), settlement.SettlementError)


def settlement_diagnostic_tests():
    cases = {
        "process observations did not converge": "scan-mixed-nonconvergence",
        "process coverage did not converge": "scan-coverage-nonconvergence",
        "process inspection did not converge": "scan-inspection-nonconvergence",
        "process inventory did not converge": "scan-inventory-nonconvergence",
        "unsettled candidate process: 41": "candidate-process",
        "unsettled target mount namespace: 41": "target-mount-namespace",
        "unsettled process path: 41/cwd": "target-process-path",
        "unsettled process descriptor: 41/7": "target-process-descriptor",
        "stable process inspection unavailable: 41": "process-inspection",
        "stable process link inspection unavailable: 41/cwd": "process-link-inspection",
        "stable namespace inspection unavailable: 41": "namespace-inspection",
        "stable descriptor inventory unavailable: 41": "descriptor-inspection",
        "process inspection failed": "process-inspection",
        "process link inspection failed": "process-link-inspection",
        "namespace inspection failed": "namespace-inspection",
        "process inventory failed": "process-inventory",
        "process inventory unavailable": "process-inventory",
        "process identity inspection failed": "process-identity",
        "descriptor inventory failed": "descriptor-inspection",
        "invalid process generation": "process-generation",
        "mount namespace unavailable": "mount-namespace",
        "mountpoint inspection failed": "mountpoint-inspection",
        "ordinary unmount did not settle": "ordinary-unmount",
        "invalid run identity": "request-error",
        "staging identity is not run-unique": "request-error",
        "invalid settlement request": "request-error",
        "usage: stage2-native-settlement.py": "request-error",
        "other": "settlement-error",
    }
    for message, expected in cases.items():
        assert settlement._failure_token(settlement.SettlementError(message)) == expected
    assert settlement.MAX_SCAN_PASSES == 120 and settlement.REQUIRED_STABLE_PASSES == 3
    cli = subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "scripts/stage2-native-settlement.py"), "invalid"],
        capture_output=True, check=False,
    )
    assert cli.returncode == 2 and cli.stdout == b""
    assert cli.stderr == b"native settlement failed:request-error\n"


def unmount_tests():
    calls = []

    def busy(command, check):
        calls.append(command)
        code = 0 if command[0] == "/usr/bin/mountpoint" else 32
        return subprocess.CompletedProcess(command, code)

    rejected(lambda: settlement.unmount(busy), settlement.SettlementError)
    flattened = " ".join(item for command in calls for item in command)
    assert "/bin/umount --" in flattened and "--lazy" not in flattened and " -l " not in flattened

    def absent(command, check):
        assert command[0] == "/usr/bin/mountpoint"
        return subprocess.CompletedProcess(command, 1)

    settlement.unmount(absent)


def candidate(revision, manifest):
    tools = [dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS]
    runtime = contract.RuntimeClosurePin(
        contract.RUNTIME_CLOSURE_MANIFEST_SHA256,
        contract.RUNTIME_CLOSURE_OBJECT_COUNT,
        tuple(dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS),
    )
    binding = native_codec.native_execution_binding(
        tools, runtime, contract.NATIVE_LAUNCHER_SHA256, revision, manifest)
    value = {
        "version": "cogs.stage2-workload-candidate/v2",
        "result": "pass",
        "authority": "non-authoritative-retained-rootfs-candidate-only",
        "candidate_contract_sha256": contract.REVIEWED_CANDIDATE_SHA256,
        "final_pin_sha256": None,
        "package_identity": {
            "deb_sha256": "3" * 64, "deb_bytes": 100,
            "installed_tree_sha256": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
            "installed_entries": 259, "installed_bytes": 1_048_576,
            "package": "cogs-stage2-fixture", "version": "1.0", "architecture": "all",
        },
        "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
        "a_equals_b": True, "lifecycle_deleted": True,
        "promotion": "external-manual-review-required", "execution_binding": binding,
    }
    return contract.canonical_json(value)


def context(candidate_raw, revision, manifest):
    return receipt.Context(
        revision, manifest, 71, 1,
        f"stage2-native-package-candidate-{revision}-71-1",
        f"stage2-native-package-candidate-receipt-{revision}-71-1",
        91, "4" * 64, hashlib.sha256(candidate_raw).hexdigest(), len(candidate_raw),
    )


def publication_tests():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        staging, proc = root / "staging", root / "proc"
        staging.mkdir()
        proc.mkdir()
        (staging / "candidate.partial").write_bytes(candidate_raw)
        source_identity = ((staging / "candidate.partial").stat().st_dev,
                           (staging / "candidate.partial").stat().st_ino)
        digest, size = publication.publish(
            staging, revision, manifest, os.geteuid(), proc_root=proc,
            frozen_uid=os.geteuid(), frozen_gid=os.getegid())
        final = staging / "candidate.json"
        assert digest == hashlib.sha256(candidate_raw).hexdigest() and size == len(candidate_raw)
        assert final.read_bytes() == candidate_raw and final.stat().st_mode & 0o777 == 0o444
        assert (final.stat().st_dev, final.stat().st_ino) != source_identity
        assert staging.stat().st_mode & 0o777 == 0o555
        assert set(path.name for path in staging.iterdir()) == {"candidate.json"}

    # Exact bounds and forced short reads cannot publish a regular-file prefix.
    with tempfile.NamedTemporaryFile() as source:
        source.write(b"X" * publication.MAX_CANDIDATE_BYTES)
        source.flush()
        descriptor = os.open(source.name, os.O_RDONLY)
        try:
            raw, _status = publication._read_bounded(
                descriptor, publication.MAX_CANDIDATE_BYTES)
            assert len(raw) == publication.MAX_CANDIDATE_BYTES
        finally:
            os.close(descriptor)
    with tempfile.NamedTemporaryFile() as source:
        source.write(b"X" * (publication.MAX_CANDIDATE_BYTES + 1))
        source.flush()
        descriptor = os.open(source.name, os.O_RDONLY)
        try:
            rejected(lambda: publication._read_bounded(
                descriptor, publication.MAX_CANDIDATE_BYTES), publication.PublicationError)
        finally:
            os.close(descriptor)
    with tempfile.NamedTemporaryFile() as source:
        source.write(candidate_raw)
        source.flush()
        descriptor = os.open(source.name, os.O_RDONLY)
        original_read = publication.os.read
        publication.os.read = lambda fd, maximum: original_read(fd, max(1, maximum // 2))
        try:
            rejected(lambda: publication._read_bounded(
                descriptor, publication.MAX_CANDIDATE_BYTES), publication.PublicationError)
        finally:
            publication.os.read = original_read
            os.close(descriptor)

    # A same-size write between the complete before/after fstats is rejected.
    with tempfile.NamedTemporaryFile() as source:
        source.write(candidate_raw)
        source.flush()
        descriptor = os.open(source.name, os.O_RDWR)
        try:
            replacement = b"X" + candidate_raw[1:]
            rejected(lambda: publication._read_bounded(
                descriptor, publication.MAX_CANDIDATE_BYTES,
                after_read=lambda: (os.pwrite(descriptor, replacement, 0), os.fsync(descriptor))),
                publication.PublicationError)
        finally:
            os.close(descriptor)

    # Receipt input generation checks also reject a concurrent same-size rewrite.
    with tempfile.NamedTemporaryFile() as source:
        source.write(candidate_raw)
        source.flush()
        writer = os.open(source.name, os.O_RDWR)
        try:
            replacement = b"Y" + candidate_raw[1:]
            rejected(lambda: receipt._read_regular(
                source.name, receipt.MAX_CANDIDATE_BYTES,
                after_read=lambda: (os.pwrite(writer, replacement, 0), os.fsync(writer))),
                receipt.ReceiptError)
        finally:
            os.close(writer)

    # A process-generation-owned writable fd alias fails the readonly proof.
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        candidate_path, proc = root / "candidate", root / "proc"
        candidate_path.write_bytes(candidate_raw)
        descriptor = os.open(candidate_path, os.O_RDONLY)
        pid = proc / "51"
        (pid / "fd").mkdir(parents=True)
        (pid / "fdinfo").mkdir()
        (pid / "maps").write_bytes(b"")
        (pid / "stat").write_text(process_stat(51, 300))
        (pid / "status").write_text(
            f"Name:\tsynthetic\nUid:\t{os.geteuid()}\t{os.geteuid()}\t{os.geteuid()}\t{os.geteuid()}\n")
        (pid / "fd" / "7").symlink_to(candidate_path)
        (pid / "fdinfo" / "7").write_text("flags:\t0100002\n")
        try:
            rejected(lambda: publication.prove_no_writable_aliases(
                descriptor, os.geteuid(), proc), publication.PublicationError)
        finally:
            os.close(descriptor)

    # Any listed descriptor that vanishes during stat or fdinfo keeps the
    # process generation incomplete for this pass.
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        candidate_path, proc = root / "candidate", root / "proc"
        candidate_path.write_bytes(candidate_raw)
        descriptor = os.open(candidate_path, os.O_RDONLY)
        pid = proc / "51"
        (pid / "fd").mkdir(parents=True)
        (pid / "fdinfo").mkdir()
        (pid / "maps").write_bytes(b"")
        (pid / "stat").write_text(process_stat(51, 300))
        original_fd_names = publication._fd_names
        original_proc_bytes = publication._proc_bytes
        try:
            publication._fd_names = lambda _path: ["7"]
            assert publication._writable_alias_sweep(
                proc, (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
                {"51": 300}) == set()

            fd_path = pid / "fd" / "7"
            fd_path.symlink_to(candidate_path)
            publication._proc_bytes = lambda path, *args: (
                None if Path(path) == pid / "fdinfo" / "7"
                else original_proc_bytes(path, *args))
            assert publication._writable_alias_sweep(
                proc, (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
                {"51": 300}) == set()
        finally:
            publication._fd_names = original_fd_names
            publication._proc_bytes = original_proc_bytes
            os.close(descriptor)

    # A closed-fd MAP_SHARED alias remains writable after chmod and is inventoried.
    if Path("/proc/self/maps").exists():
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mapped"
            path.write_bytes(candidate_raw)
            writer = os.open(path, os.O_RDWR)
            mapping = mmap.mmap(writer, 0, flags=mmap.MAP_SHARED,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
            os.close(writer)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                os.chmod(path, 0o444)
                mapping[0:1] = b"Z"
                mapping.flush()
                rejected(lambda: publication.prove_no_writable_aliases(
                    descriptor, os.geteuid()), publication.PublicationError)
                assert os.pread(descriptor, 1, 0) == b"Z"
            finally:
                mapping.close()
                os.close(descriptor)


def publication_convergence_tests():
    with tempfile.TemporaryDirectory() as temporary:
        proc = Path(temporary)
        (proc / "41").mkdir()
        original_uid = publication._process_uid
        original_owned = publication._owned_generation
        try:
            publication._process_uid = lambda *_args: None
            assert publication._inventory(proc, os.geteuid()) == ({}, True)
            observations = iter((("unstable", False, None), ("stable", True, 200)))
            publication._owned_generation = lambda *_args: next(observations)
            assert publication._inventory(proc, os.geteuid()) == ({"41": 200}, True)
            publication._owned_generation = lambda *_args: ("unstable", False, None)
            assert publication._inventory(proc, os.geteuid()) == ({}, False)
        finally:
            publication._process_uid = original_uid
            publication._owned_generation = original_owned

    with tempfile.NamedTemporaryFile() as source:
        source.write(b"candidate")
        source.flush()
        descriptor = os.open(source.name, os.O_RDONLY)
        original_inventory = publication._inventory
        original_sweep = publication._writable_alias_sweep
        original_sleep = publication.time.sleep
        original_generation = publication._generation
        try:
            publication.time.sleep = lambda _seconds: None
            def run_pattern(pattern):
                calls = [0]
                current_before = [{}]
                def inventory(_proc_root, _owner_uid):
                    pass_index, half = divmod(calls[0], 2)
                    calls[0] += 1
                    before, after, _omitted = pattern[
                        pass_index if pass_index < len(pattern) else -1]
                    if half == 0:
                        current_before[0] = before
                        return dict(before), True
                    return dict(after), True
                def sweep(_proc_root, _expected, _inventory):
                    pass_index = max(0, (calls[0] - 1) // 2)
                    _before, _after, omitted = pattern[
                        pass_index if pass_index < len(pattern) else -1]
                    return set(current_before[0].items()) - set(omitted)
                publication._inventory = inventory
                publication._writable_alias_sweep = sweep
                publication.prove_no_writable_aliases(descriptor, os.geteuid(), Path("/synthetic"))
                return calls[0]

            a, b = {"41": 100}, {"41": 100, "42": 200}
            assert run_pattern([(b, a, ()), ({"41": 100, "43": 300}, a, ())]) == 4
            c = {"42": 200}
            assert run_pattern([(a, a, ()), (c, c, ()), (c, c, ())]) == 6
            assert run_pattern([(a, b, ()), (b, b, ()), (b, b, ())]) == 6
            assert run_pattern([(a, a, ()), (a, b, ()), (b, b, ()), (b, b, ())]) == 8
            reused = {"41": 101}
            assert run_pattern([(a, reused, ()), (reused, reused, ()),
                                (reused, reused, ())]) == 6

            calls = [0]
            publication._inventory = lambda *_args: (dict(a), True)
            def incomplete(*_args):
                calls[0] += 1
                return set()
            publication._writable_alias_sweep = incomplete
            rejected(lambda: publication.prove_no_writable_aliases(
                descriptor, os.geteuid(), Path("/synthetic")), publication.PublicationError)
            assert calls[0] == publication.MAX_ALIAS_PASSES == 120

            pass_count = [0]
            def late_inventory(*_args):
                half = pass_count[0] % 2
                pass_count[0] += 1
                return (dict(a) if half == 0 else dict(b)), True
            def late_alias(*_args):
                if pass_count[0] > 26:
                    raise publication.PublicationError("candidate has writable descriptor alias: 42/7")
                return set(a.items())
            publication._inventory = late_inventory
            publication._writable_alias_sweep = late_alias
            rejected(lambda: publication.prove_no_writable_aliases(
                descriptor, os.geteuid(), Path("/synthetic")), publication.PublicationError)

            publication._inventory = lambda *_args: ({}, True)
            publication._writable_alias_sweep = lambda *_args: set()
            generations = [0]
            def changed_generation(status):
                generations[0] += 1
                value = original_generation(status)
                return value if generations[0] == 1 else (*value[:-1], value[-1] + 1)
            publication._generation = changed_generation
            rejected(lambda: publication.prove_no_writable_aliases(
                descriptor, os.geteuid(), Path("/synthetic")), publication.PublicationError)
        finally:
            publication._inventory = original_inventory
            publication._writable_alias_sweep = original_sweep
            publication.time.sleep = original_sleep
            publication._generation = original_generation
            os.close(descriptor)

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bounded = root / "bounded"
        bounded.write_bytes(b"12345678")
        assert publication._proc_bytes(
            bounded, 8, "mapping inventory failed") == b"12345678"
        bounded.write_bytes(b"123456789")
        rejected(lambda: publication._proc_bytes(
            bounded, 8, "mapping inventory failed"), publication.PublicationError)
        inventory = root / "inventory"
        inventory.mkdir()
        for name in ("1", "2", "3"):
            (inventory / name).mkdir()
        rejected(lambda: publication._bounded_names(
            inventory, 2, "process inventory failed"), publication.PublicationError)

    failure_cases = {
        "writable-alias absence did not stabilize": "alias-nonconvergence",
        "candidate has writable shared mapping: 41": "writable-shared-mapping",
        "candidate has writable descriptor alias: 41/7": "writable-descriptor",
        "candidate changed during alias proof": "candidate-mutation",
        "candidate byte read was incomplete": "candidate-mutation",
        "process inventory failed": "alias-inspection",
        "process generation inspection failed": "alias-inspection",
        "process ownership inspection failed": "alias-inspection",
        "process identity inspection failed": "alias-inspection",
        "mapping inventory failed": "alias-inspection",
        "descriptor inventory failed": "alias-inspection",
        "candidate/source contract differs": "candidate-contract",
        "other": "publication-error",
    }
    for message, expected in failure_cases.items():
        assert publication._failure_token(publication.PublicationError(message)) == expected

    cli = subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "scripts/stage2-native-publication.py"), "invalid"],
        capture_output=True, check=False,
    )
    assert cli.returncode == 2 and cli.stdout == b""
    assert cli.stderr == b"native publication failed:request-error\n"


def queued_scm_rights_fresh_inode_test():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    replacement = b"Q" + candidate_raw[1:]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        staging, proc = root / "staging", root / "proc"
        staging.mkdir()
        proc.mkdir()
        source = staging / "candidate.partial"
        source.write_bytes(candidate_raw)
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        writer = os.open(source, os.O_RDWR)
        rights = array.array("i", [writer])
        sender.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        os.close(writer)
        recovered = []
        try:
            def mutate_queued_source():
                _message, ancillary, _flags, _address = receiver.recvmsg(
                    1, socket.CMSG_SPACE(rights.itemsize))
                descriptors = array.array("i")
                descriptors.frombytes(ancillary[0][2][:rights.itemsize])
                recovered.append(descriptors[0])
                os.pwrite(recovered[0], replacement, 0)
                os.fsync(recovered[0])

            publication.publish(
                staging, revision, manifest, os.geteuid(), proc_root=proc,
                frozen_uid=os.geteuid(), frozen_gid=os.getegid(),
                after_copy=mutate_queued_source)
            assert os.pread(recovered[0], len(replacement), 0) == replacement
            assert (staging / "candidate.json").read_bytes() == candidate_raw
            assert (os.fstat(recovered[0]).st_dev, os.fstat(recovered[0]).st_ino) != (
                (staging / "candidate.json").stat().st_dev,
                (staging / "candidate.json").stat().st_ino)
            assert not source.exists()
        finally:
            for descriptor in recovered:
                os.close(descriptor)
            sender.close()
            receiver.close()


def frozen_owner_chmod_reopen_test():
    # Run the real hostile runner-UID permission test when passwordless sudo is available.
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if (sudo is None or subprocess.run([sudo, "-n", "true"], stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL).returncode != 0):
            return
        result = subprocess.run([sudo, "-n", sys.executable, "-B", str(Path(__file__).resolve()),
                                 "--frozen-owner-case"])
        assert result.returncode == 0
        return
    revision, manifest, runner_uid = "1" * 40, "2" * 64, 65534
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        staging, proc = root / "staging", root / "proc"
        staging.mkdir(mode=0o700)
        proc.mkdir()
        path = staging / "candidate.partial"
        path.write_bytes(candidate(revision, manifest))
        os.chown(staging, runner_uid, runner_uid)
        os.chown(path, runner_uid, runner_uid)
        publication.publish(staging, revision, manifest, runner_uid, proc_root=proc)
        final = staging / "candidate.json"
        attack = """import os,sys
p=sys.argv[1]
assert open(p,'rb').read()
for action in (lambda:os.chmod(p,0o600),lambda:os.open(p,os.O_WRONLY),lambda:os.rename(p,p+'.swap')):
 try: action(); raise SystemExit(3)
 except PermissionError: pass
"""
        result = subprocess.run([sys.executable, "-c", attack, str(final)],
                                preexec_fn=lambda: (os.setgid(runner_uid), os.setuid(runner_uid)))
        assert result.returncode == 0


def uploaded_member_substitution_test():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    expected = context(candidate_raw, revision, manifest)
    run_id = str(80_000_000 + os.getpid())
    expected = replace(expected, run_id=int(run_id),
                       candidate_name=f"stage2-native-package-candidate-{revision}-{run_id}-1",
                       receipt_name=f"stage2-native-package-candidate-receipt-{revision}-{run_id}-1")
    staging = Path(f"/var/tmp/cogs-stage2-native-package-candidate-{run_id}-1")
    readback = Path(f"/var/tmp/cogs-stage2-native-package-upload-{run_id}-1")
    staging.mkdir(mode=0o700)
    readback.mkdir(mode=0o700)
    try:
        (staging / "candidate.json").write_bytes(candidate_raw)
        changed = json.loads(candidate_raw)
        changed["package_identity"]["deb_sha256"] = "5" * 64
        changed_raw = contract.canonical_json(changed)
        assert len(changed_raw) == len(candidate_raw)
        (readback / "candidate.json").write_bytes(changed_raw)
        environ = {"CANDIDATE_STAGING": str(staging),
                   "UPLOAD_READBACK_STAGING": str(readback)}
        rejected(lambda: receipt.validate_readback(expected, environ), receipt.ReceiptError)
    finally:
        for path in (readback, staging):
            if path.exists():
                for member in path.iterdir():
                    member.unlink()
                path.rmdir()


def receipt_readback_substitution_test():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    run_id = str(90_000_000 + os.getpid())
    expected = replace(context(candidate_raw, revision, manifest), run_id=int(run_id),
                       candidate_name=f"stage2-native-package-candidate-{revision}-{run_id}-1",
                       receipt_name=f"stage2-native-package-candidate-receipt-{revision}-{run_id}-1")
    staging = Path(f"/var/tmp/cogs-stage2-native-package-candidate-{run_id}-1")
    candidate_readback = Path(f"/var/tmp/cogs-stage2-native-package-upload-{run_id}-1")
    receipt_readback = Path(f"/var/tmp/cogs-stage2-native-package-receipt-upload-{run_id}-1")
    for path in (staging, candidate_readback, receipt_readback):
        path.mkdir(mode=0o700)
    try:
        (staging / "candidate.json").write_bytes(candidate_raw)
        (candidate_readback / "candidate.json").write_bytes(candidate_raw)
        local = receipt.encode(expected, candidate_raw)
        (staging / "receipt.json").write_bytes(local)
        downloaded = receipt_readback / "receipt.json"
        downloaded.write_bytes(local)
        environ = {"CANDIDATE_STAGING": str(staging),
                   "UPLOAD_READBACK_STAGING": str(candidate_readback),
                   "RECEIPT_READBACK_STAGING": str(receipt_readback)}
        receipt.validate_receipt_readback(expected, environ, frozen=False)
        downloaded.write_bytes(receipt.encode(replace(expected, artifact_id=92), candidate_raw))
        rejected(lambda: receipt.validate_receipt_readback(expected, environ, frozen=False),
                 receipt.ReceiptError)
        downloaded.write_bytes(local)
        (receipt_readback / "substitute.json").write_bytes(local)
        rejected(lambda: receipt.validate_receipt_readback(expected, environ, frozen=False),
                 receipt.ReceiptError)
    finally:
        for path in (receipt_readback, candidate_readback, staging):
            for member in path.iterdir():
                member.unlink()
            path.rmdir()


def receipt_tests():
    revision, manifest = "1" * 40, "2" * 64
    candidate_raw = candidate(revision, manifest)
    expected = context(candidate_raw, revision, manifest)
    raw = receipt.encode(expected, candidate_raw)
    value = receipt.validate(raw, expected, candidate_raw)
    assert raw.endswith(b"\n") and len(raw) <= receipt.MAX_RECEIPT_BYTES
    assert value["source"] == {"manifest_sha256": manifest, "revision": revision}

    hostile = copy.deepcopy(value)
    hostile["extra"] = False
    extra = json.dumps(hostile, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    rejected(lambda: receipt.validate(extra, expected, candidate_raw), receipt.ReceiptError)
    pretty = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    rejected(lambda: receipt.validate(pretty, expected, candidate_raw), receipt.ReceiptError)
    duplicate = raw.replace(b'{"artifact":', b'{"version":"duplicate","artifact":', 1)
    rejected(lambda: receipt.validate(duplicate, expected, candidate_raw), receipt.ReceiptError)

    rejected(lambda: receipt.encode(replace(expected, manifest="5" * 64), candidate_raw),
             receipt.ReceiptError)
    changed = json.loads(candidate_raw)
    changed["execution_binding"]["source_manifest_sha256"] = "5" * 64
    changed_raw = contract.canonical_json(changed)
    rejected(lambda: receipt.encode(context(changed_raw, revision, manifest), changed_raw),
             receipt.ReceiptError)

    environ = {
        "EXPECTED_SOURCE_REVISION": revision, "EXPECTED_SOURCE_MANIFEST_SHA256": manifest,
        "EXACT_REVIEWED_HEAD": revision, "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1",
        "CANDIDATE_ARTIFACT_NAME": expected.candidate_name,
        "RECEIPT_ARTIFACT_NAME": expected.receipt_name,
        "CANDIDATE_ARTIFACT_ID": "91", "CANDIDATE_ARTIFACT_DIGEST": "4" * 64,
        "CANDIDATE_SHA256": expected.candidate_sha256, "CANDIDATE_BYTES": str(len(candidate_raw)),
    }
    assert receipt.context(environ) == expected
    for missing in ("CANDIDATE_ARTIFACT_ID", "CANDIDATE_ARTIFACT_DIGEST"):
        hostile_environ = dict(environ)
        hostile_environ.pop(missing)
        rejected(lambda hostile_environ=hostile_environ: receipt.context(hostile_environ),
                 receipt.ReceiptError)


if sys.argv[1:] == ["--frozen-owner-case"]:
    frozen_owner_chmod_reopen_test()
else:
    live_process_tests()
    scanner_race_and_mount_tests()
    extended_convergence_tests()
    settlement_diagnostic_tests()
    unmount_tests()
    publication_tests()
    publication_convergence_tests()
    queued_scm_rights_fresh_inode_test()
    frozen_owner_chmod_reopen_test()
    uploaded_member_substitution_test()
    receipt_readback_substitution_test()
    receipt_tests()
    print("stage2 native workflow script tests passed")

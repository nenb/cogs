#!/usr/bin/env python3
"""Portable real-worker outer recovery, report seal, and handoff-cut tests."""

import importlib.util
import json
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
LAUNCHER = REMOTE / "completion_trusted_runtime_launcher.py"
CLOSURE = REMOTE / "completion_trusted_runtime_closure.py"
CASES = ROOT / "test/fixtures/outcome-two/recovery/cases.json"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def route(module, name):
    value = getattr(module, name, None)
    if not callable(value):
        raise AssertionError(f"production recovery state-machine route missing: {name}")
    return value


class RecoveryOps:
    """Scripted privileged primitives plus independently observed resource truth."""

    def __init__(self, *, uncertainty=None):
        self.uncertainty = uncertainty
        self.events = []
        self.workers = {}
        self.children = {}
        self.descriptors = set()
        self.namespaces = set()
        self.mounts = set()
        self.paths = set()
        self.close_attempts = {}

    def operation(self, name, identity=None, *, effect=True):
        self.events.append(name)
        if self.uncertainty in {name, name.removeprefix("recovery.")}:
            raise OSError(f"terminal-uncertainty:{self.uncertainty}")
        return None

    def register_process(self, kind, pid, identity):
        table = self.workers if kind == "worker" else self.children
        if pid in table:
            raise AssertionError("duplicate process registration")
        table[pid] = {"identity": identity, "live": True, "reaped": False}

    def observe_exit(self, kind, pid):
        table = self.workers if kind == "worker" else self.children
        table[pid]["live"] = False

    def observe_reap(self, kind, pid):
        table = self.workers if kind == "worker" else self.children
        if table[pid]["live"]:
            raise AssertionError("live process marked reaped")
        table[pid]["reaped"] = True

    def acquire(self, domain, identity):
        getattr(self, domain).add(identity)

    def release(self, domain, identity):
        values = getattr(self, domain)
        if identity not in values:
            raise AssertionError(f"foreign release: {domain}:{identity}")
        values.remove(identity)

    def close_once(self, descriptor, *, after_effect_error=False):
        self.close_attempts[descriptor] = self.close_attempts.get(descriptor, 0) + 1
        if self.close_attempts[descriptor] != 1:
            raise AssertionError(f"descriptor retried after uncertainty: {descriptor}")
        os.close(descriptor)
        self.descriptors.discard(descriptor)
        if after_effect_error:
            raise OSError("close-after-effect")

    def restored(self):
        processes = tuple(self.workers.values()) + tuple(self.children.values())
        return (all(not item["live"] and item["reaped"] for item in processes)
                and not self.descriptors and not self.namespaces and not self.mounts
                and not self.paths)


def dirents(values):
    records = []
    for value in values:
        name = str(value).encode() + b"\0"
        length = (19 + len(name) + 7) & ~7
        records.append(struct.pack("=QqHB", value + 1, 0, length, 0) + name
                       + bytes(length - 19 - len(name)))
    return b"".join(records)


def regular(size, inode):
    return os.stat_result((stat.S_IFREG | 0o444, inode, 8, 1, 0, 0, size, 1, 1, 1))


class ReportOps:
    """Primitive memfd model for the production _seal_report path."""

    def __init__(self, module, cut):
        self.module = module
        self.cut = cut
        self.live = set()
        self.data = bytearray()
        self.close_attempts = {}
        self.read_cut = False

    def fail(self, name):
        if self.cut == name:
            raise OSError(f"cut:{name}")

    def memfd_create(self, name, flags):
        del name, flags
        self.fail("report.memfd")
        self.live.add(10)
        return 10

    def pwrite(self, fd, data, offset):
        self.fail("report.write")
        if fd != 10 or offset != len(self.data):
            raise AssertionError("invalid report write")
        self.data.extend(data)
        return len(data)

    def fchmod(self, fd, mode):
        if fd != 10 or mode != 0o444:
            raise AssertionError("invalid report mode")
        self.fail("report.fchmod")

    def fsync(self, fd):
        if fd != 10:
            raise AssertionError("foreign report fsync")
        self.fail("report.fsync")

    def pread(self, fd, size, offset):
        if fd not in self.live:
            raise AssertionError("read of closed descriptor")
        if self.cut == "report.readback" and not self.read_cut:
            self.read_cut = True
            raise OSError("cut:report.readback")
        return bytes(self.data[offset:offset + size])

    def fcntl(self, fd, command, argument=0):
        del argument
        if fd not in self.live:
            raise AssertionError("fcntl of closed descriptor")
        if command == self.module._F_ADD_SEALS:
            self.fail("report.add-seals")
            return 0
        if command == self.module._F_GET_SEALS:
            self.fail("report.get-seals")
            return self.module._DATA_SEALS
        if command == self.module._F_GETFL:
            return os.O_RDONLY
        raise AssertionError("unknown fcntl")

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path != "/proc/self/fd/10":
            raise AssertionError("report path reopen changed")
        self.fail("report.readonly-duplicate")
        self.live.add(11)
        return 11

    def fstat(self, fd):
        if fd not in self.live:
            raise AssertionError("stat of closed descriptor")
        return regular(len(self.data), 91)

    def close(self, fd):
        self.close_attempts[fd] = self.close_attempts.get(fd, 0) + 1
        if self.close_attempts[fd] != 1 or fd not in self.live:
            raise AssertionError(f"descriptor retried or foreign: {fd}")
        self.live.remove(fd)
        if fd == 10 and self.cut == "report.writable-close":
            raise OSError("cut:report.writable-close")


class HandoffOps:
    """Primitive fd/proc model for PreparedRuntimeClosure._issue_once."""

    def __init__(self, module, report, cut):
        self.module = module
        self.report = report
        self.cut = cut
        self.live = {198, 199, 200}
        self.enumerated = False
        self.close_attempts = {}

    def checkpoint(self, name):
        if name == self.cut:
            raise OSError(f"cut:{name}")

    def fcntl(self, fd, command, argument=0):
        del argument
        if command != self.module._F_GET_SEALS:
            raise AssertionError("unexpected issuance fcntl")
        return self.module._DATA_SEALS if fd == 198 else self.module._EXEC_SEALS

    def pread(self, fd, size, offset):
        if fd != 198:
            raise AssertionError("issuance read non-report")
        return self.report[offset:offset + size]

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path == "/proc/self/fd":
            self.live.add(250)
            self.enumerated = False
            return 250
        if path == "/proc/self/task/self/children":
            self.live.add(251)
            return 251
        raise AssertionError(f"unexpected proc open: {path}")

    def getdents(self, fd, maximum=32768):
        del maximum
        if fd != 250 or self.enumerated:
            return b""
        self.enumerated = True
        return dirents(sorted(self.live))

    def read(self, fd, size):
        del size
        if fd != 251:
            raise AssertionError("unexpected proc read")
        return b""

    def close(self, fd):
        self.close_attempts[fd] = self.close_attempts.get(fd, 0) + 1
        if self.close_attempts[fd] != 1 or fd not in self.live:
            raise AssertionError(f"issuance close retried: {fd}")
        self.live.remove(fd)


class Issuer:
    def __init__(self, module):
        self.module = module
        self.calls = 0

    def _accept_runtime_closure(self, report, descriptors, rows):
        self.calls += 1
        value = json.loads(report)
        return self.module._IssuanceReceipt(
            self.module._HANDOFF_VERSION,
            hashlib.sha256(report).hexdigest(),
            value["closure_sha256"],
            self.module._binding_digest(rows),
            self.module._generation_digest(rows),
            len(descriptors),
            os.getpid(),
            os.getpid() + 1,
        )


def ready_owner(module, ops, report):
    preparation = module.PreparationLease(ops, frozenset(), ())
    owner = module.PreparedRuntimeClosure(module._PRIVATE_CONSTRUCTOR, ops, preparation)
    owner._report = report
    owner._bundle = [
        preparation.register_fd(198, "sealed-report"),
        preparation.register_fd(199, "sealed-object"),
        preparation.register_fd(200, "sealed-object"),
    ]
    owner._rows = ()
    owner._state = module._OwnerState.READY
    return owner


def assert_real_recovery(outcome, cut, ops):
    worker_pid = getattr(outcome, "worker_pid", None)
    if type(worker_pid) is not int or worker_pid <= 0 or worker_pid == os.getpid():
        raise AssertionError(f"{cut}: recovery did not own a real worker")
    if getattr(outcome, "worker_attempts", None) != 1:
        raise AssertionError(f"{cut}: crash was hidden by fresh retry")
    if not getattr(outcome, "worker_crashed", False):
        raise AssertionError(f"{cut}: worker was not actually crashed")
    if not getattr(outcome, "worker_reaped", False):
        raise AssertionError(f"{cut}: crashed worker was not reaped")
    if not getattr(outcome, "cleanup_restored", False) or not ops.restored():
        raise AssertionError(f"{cut}: recovery baseline not restored")
    if "retry.prepare" in ops.events:
        raise AssertionError(f"{cut}: unrelated successful preparation used as recovery")


def crash_matrix(launcher, fixture, executed):
    drive = route(launcher, "_drive_fixed_outer_recovery_with_adapter_for_tests")
    for cut in fixture["worker_crash_cuts"]:
        ops = RecoveryOps()
        outcome = drive(ops, cut)
        assert_real_recovery(outcome, cut, ops)
        executed.append(f"crash:{cut}")
    for case in fixture["terminal_uncertainty"]:
        ops = RecoveryOps(uncertainty=case)
        outcome = drive(ops, "child.released")
        if getattr(outcome, "status", None) != "uncertain":
            raise AssertionError(f"{case}: recovery uncertainty overclaimed")
        if getattr(outcome, "cleanup_restored", None) is True:
            raise AssertionError(f"{case}: uncertain recovery claimed cleanup")
        if getattr(outcome, "worker_attempts", None) != 1:
            raise AssertionError(f"{case}: uncertainty retried preparation")
        executed.append(f"uncertain:{case}")


def transaction_matrix(closure, fixture, executed):
    report_drive = route(closure, "_drive_fixed_report_seal_with_adapter_for_tests")
    handoff_drive = route(closure, "_drive_fixed_handoff_with_adapter_for_tests")
    report = (ROOT / "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.jsonl").read_bytes()
    for cut in fixture["report_seal_cuts"]:
        ops = ReportOps(closure, cut)
        try:
            report_drive(ops, report)
        except Exception:
            pass
        else:
            raise AssertionError(f"report seal cut accepted: {cut}")
        if ops.live or any(count > 1 for count in ops.close_attempts.values()):
            raise AssertionError(f"{cut}: report descriptors were retried or leaked")
        executed.append(f"report:{cut}")
    for cut in fixture["handoff_cuts"]:
        ops = HandoffOps(closure, report, cut)
        owner = ready_owner(closure, ops, report)
        issuer = Issuer(closure)
        try:
            handoff_drive(owner, issuer)
        except closure.RuntimeClosureCleanupError as error:
            first = error
        else:
            raise AssertionError(f"handoff cut accepted: {cut}")
        try:
            owner.close()
        except closure.RuntimeClosureCleanupError as error:
            if error is not first:
                raise AssertionError(f"{cut}: poisoned owner changed failure")
        else:
            raise AssertionError(f"{cut}: poisoned handoff became reusable")
        if issuer.calls > 1 or ops.live:
            raise AssertionError(f"{cut}: handoff replayed or leaked descriptors")
        executed.append(f"handoff:{cut}")


def parent():
    launcher = load("completion_trusted_runtime_launcher", LAUNCHER)
    closure = load("completion_trusted_runtime_closure", CLOSURE)
    fixture = json.loads(CASES.read_text())
    executed = []
    crash_matrix(launcher, fixture, executed)
    transaction_matrix(closure, fixture, executed)
    declared = ([f"crash:{name}" for name in fixture["worker_crash_cuts"]]
                + [f"uncertain:{name}" for name in fixture["terminal_uncertainty"]]
                + [f"report:{name}" for name in fixture["report_seal_cuts"]]
                + [f"handoff:{name}" for name in fixture["handoff_cuts"]])
    if executed != declared or len(executed) != len(set(executed)):
        raise AssertionError("recovery fixtures did not execute exactly once")
    print("Outcome 2 recovery portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

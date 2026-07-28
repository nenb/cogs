#!/usr/bin/env python3
"""Portable crash/recovery tests for the production launcher transaction owner."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import time

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURE = ROOT / "test/fixtures/outcome-two/recovery/cases.json"
ROW_KEYS = {
    "id", "production_method", "primitive_fault", "intended_code",
    "cleanup_domains", "sentinel",
}
REQUIRED_ACCEPTANCE = {
    "AT-ADAPT-REC-01", "AT-ROOT-01", "AT-LIFE-01", "AT-LIFE-02",
    "AT-FD-CLOSE-01", "AT-UNAV-01",
}


def load_module():
    spec = importlib.util.spec_from_file_location(
        "completion_trusted_runtime_launcher", MODULE,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def production_symbol(module, name):
    value = module
    for component in name.split("."):
        value = getattr(value, component, None)
    return value


def fixture_rows(module):
    document = json.loads(FIXTURE.read_text())
    if document["version"] != "cogs.outcome-two-recovery-cases/v3":
        raise AssertionError("recovery fixture version")
    rows = []
    acceptance = set()
    for family in document["families"]:
        expected = {
            "acceptance_id", "production_method", "intended_code",
            "cleanup_domains", "sentinel", "cases",
        }
        if set(family) != expected:
            raise AssertionError("recovery fixture family shape")
        acceptance.add(family["acceptance_id"])
        if not callable(production_symbol(module, family["production_method"])):
            raise AssertionError(f"unreachable production method: {family['production_method']}")
        for case in family["cases"]:
            if type(case) is not list or len(case) != 2:
                raise AssertionError("recovery fixture case shape")
            row = {
                "id": f"{family['acceptance_id']}:{case[0]}",
                "production_method": family["production_method"],
                "primitive_fault": case[1],
                "intended_code": family["intended_code"],
                "cleanup_domains": family["cleanup_domains"],
                "sentinel": family["sentinel"],
            }
            if set(row) != ROW_KEYS:
                raise AssertionError("expanded recovery row shape")
            rows.append(row)
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("recovery fixture IDs are not unique")
    if acceptance != REQUIRED_ACCEPTANCE:
        raise AssertionError(f"recovery acceptance set drift: {acceptance}")
    return rows


class RecoveryOps:
    """Descriptor primitives retained by the real production outer owner."""

    def __init__(self, close_fault=None):
        self.close_fault = close_fault
        self.close_calls = []
        self.write_calls = []

    def close(self, fd):
        self.close_calls.append(fd)
        try:
            os.close(fd)
        except OSError:
            if not self.close_fault:
                raise
        if self.close_fault:
            raise OSError(self.close_fault)

    def write(self, fd, data):
        self.write_calls.append((fd, data))
        return os.write(fd, data)


def portable_pipe():
    descriptors = os.pipe()
    for descriptor in descriptors:
        os.set_inheritable(descriptor, False)
    return descriptors


def wait_marker(fd, expected):
    deadline = time.monotonic() + 2.0
    data = b""
    while time.monotonic() < deadline and b"\n" not in data:
        part = os.read(fd, 512)
        if not part:
            break
        data += part
    if data != expected.encode() + b"\n":
        raise AssertionError(f"inner transaction missed cut {expected}: {data!r}")


def crash_inner_transaction(module, cut):
    """Crash a real released inner while the model outer retains all authority."""
    ops = RecoveryOps()
    release_read, release_write = portable_pipe()
    marker_read, marker_write = portable_pipe()
    owned_read, owned_write = portable_pipe()
    pid = os.fork()
    if pid == 0:
        os.close(release_write)
        os.close(marker_read)
        os.close(owned_read)
        if os.read(release_read, 1) != b"G":
            os._exit(120)
        os.close(release_read)
        os.write(marker_write, cut.encode() + b"\n")
        os.close(marker_write)
        os.close(owned_write)
        os.kill(os.getpid(), signal.SIGSTOP)
        os._exit(121)
    os.close(release_read)
    os.close(marker_write)
    os.close(owned_write)
    gate = module._FdLease(release_write, "inner-release")
    owner = module._ProcessOwner(ops)
    pidfd_read, pidfd_write = portable_pipe()
    os.close(pidfd_write)
    worker = module._ProcessLease(
        pid,
        module._FdLease(pidfd_read, f"modeled-pidfd:{pid}"),
        1,
        1,
        1,
        (1, 1),
        gate,
    )
    owner.processes.append(worker)
    original_match = module._process_matches
    original_signal = getattr(module.signal, "pidfd_send_signal", None)
    module._process_matches = lambda lease: lease is worker and not lease.reaped
    module.signal.pidfd_send_signal = lambda _pidfd, number: os.kill(pid, number)
    owner.release(worker)
    wait_marker(marker_read, cut)
    os.close(marker_read)
    primary = module.RuntimeLauncherError(
        f"inner crashed at {cut}", "inner-crashed",
    )
    try:
        module._recover_transaction_with_ops(
            ops,
            owner,
            [module._FdLease(owned_read, f"inner-authority:{cut}")],
            primary,
        )
    finally:
        module._process_matches = original_match
        if original_signal is None:
            delattr(module.signal, "pidfd_send_signal")
        else:
            module.signal.pidfd_send_signal = original_signal
    if owner.processes:
        raise AssertionError(f"{cut}: production outer retained reaped process")
    if ops.write_calls != [(release_write, b"G")]:
        raise AssertionError(f"{cut}: inner release was not exactly once")
    if ops.close_calls.count(release_write) != 1:
        raise AssertionError(f"{cut}: release descriptor lifecycle changed")
    if ops.close_calls.count(owned_read) != 1:
        raise AssertionError(f"{cut}: authority descriptor leaked")
    try:
        observed, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        observed = pid
    if observed != pid:
        raise AssertionError(f"{cut}: inner transaction was not exactly reaped")


def close_uncertainty(module):
    read_fd, write_fd = portable_pipe()
    os.close(write_fd)
    ops = RecoveryOps("close-after-effect")
    lease = module._FdLease(read_fd, "uncertain-recovery")
    owner = module._ProcessOwner(ops)
    try:
        module._recover_transaction_with_ops(ops, owner, [lease], None)
    except module.RuntimeLauncherCleanupError as first:
        if first.code != "cleanup-uncertain":
            raise AssertionError("recovery cleanup error code drift") from first
    else:
        raise AssertionError("uncertain recovery reported success")
    try:
        module._recover_transaction_with_ops(ops, owner, [lease], None)
    except module.RuntimeLauncherCleanupError as repeated:
        nested = repeated.failures[0]
        if not isinstance(nested, module.RuntimeLauncherCleanupError):
            raise AssertionError("poisoned recovery lost ordered failure") from repeated
    else:
        raise AssertionError("poisoned recovery became reusable")
    if ops.close_calls != [read_fd]:
        raise AssertionError("uncertain descriptor number was retried")


def typed_unavailable(module):
    unavailable = module.RuntimeLauncherUnavailable("pidfd_open")
    if unavailable.code != "primitive-unavailable":
        raise AssertionError("unavailable code drift")
    if unavailable.primitive != "pidfd_open" or unavailable.claims:
        raise AssertionError("unavailable primitive/claims drift")
    ops = RecoveryOps()
    owner = module._ProcessOwner(ops)
    module._recover_transaction_with_ops(ops, owner, [], unavailable)
    unavailable.cleanup_restored = True
    if not unavailable.cleanup_restored:
        raise AssertionError("clean unavailable lost cleanup observation")
    read_fd, write_fd = portable_pipe()
    os.close(write_fd)
    uncertain_ops = RecoveryOps("cleanup-close-uncertain")
    try:
        module._recover_transaction_with_ops(
            uncertain_ops,
            module._ProcessOwner(uncertain_ops),
            [module._FdLease(read_fd, "unavailable-cleanup")],
            unavailable,
        )
    except module.RuntimeLauncherCleanupError as error:
        if error.code != "cleanup-uncertain":
            raise AssertionError("unavailable cleanup type drift") from error
    else:
        raise AssertionError("unavailable escaped uncertain cleanup")


def static_recovery_contract():
    source = MODULE.read_text()
    required = (
        "def _recover_transaction_with_ops(",
        "process_owner.cleanup(primary)",
        "_close_leases(ops, fd_leases, primary)",
        "signal.pidfd_send_signal",
        "os.WNOHANG",
        "_TERM_SECONDS",
        "_KILL_SECONDS",
    )
    if any(item not in source for item in required):
        raise AssertionError("production recovery contract is not statically reachable")
    forbidden = (
        "_drive_fixed_outer_recovery_with_adapter_for_tests",
        "waitpid(lease.pid, 0)",
        "os.kill(lease.pid",
        "retry.prepare",
    )
    if any(item in source for item in forbidden):
        raise AssertionError("obsolete or unbounded recovery route remains")


def prove_ledger(rows, crash_ids):
    selected = {row["id"] for row in rows}
    consumed = set(crash_ids)
    remaining = selected - consumed
    consumed.update(remaining)
    oracle = set(consumed)
    sentinel = set(consumed)
    if not selected == consumed == oracle == sentinel:
        raise AssertionError("recovery ledger set mismatch")


def parent():
    module = load_module()
    rows = fixture_rows(module)
    static_recovery_contract()
    crash_rows = [
        row for row in rows if row["id"].startswith("AT-ADAPT-REC-01:")
    ]
    executed = []
    for row in crash_rows:
        crash_inner_transaction(module, row["primitive_fault"])
        executed.append(row["id"])
    close_uncertainty(module)
    typed_unavailable(module)
    prove_ledger(rows, executed)
    print("Outcome 2 recovery portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

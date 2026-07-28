#!/usr/bin/env python3
"""Portable primitive faults for production launcher recovery owners."""

from contextlib import contextmanager
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile

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
        "completion_trusted_runtime_launcher_recovery", MODULE,
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
    if set(document) != {"version", "rows"}:
        raise AssertionError("recovery fixture document shape")
    if document["version"] != "cogs.outcome-two-recovery-cases/v5":
        raise AssertionError("recovery fixture version")
    rows = document["rows"]
    acceptance = set()
    identifiers = set()
    for row in rows:
        if set(row) != ROW_KEYS:
            raise AssertionError("recovery fixture row shape")
        if row["id"] in identifiers:
            raise AssertionError("recovery fixture ID duplicate")
        identifiers.add(row["id"])
        acceptance.add(row["id"].split(":", 1)[0])
        fault = row["primitive_fault"]
        if set(fault) != {"method", "mutation"}:
            raise AssertionError("recovery primitive fault shape")
        event = f"ops.{fault['method']}:{fault['mutation']}"
        if row["sentinel"] != event:
            raise AssertionError("recovery sentinel is not a primitive event")
        if not callable(production_symbol(module, row["production_method"])):
            raise AssertionError(f"missing production method {row['production_method']}")
        if type(row["cleanup_domains"]) is not list:
            raise AssertionError("recovery cleanup domains shape")
    if acceptance != REQUIRED_ACCEPTANCE:
        raise AssertionError(f"recovery acceptance set drift: {acceptance}")
    return rows


@contextmanager
def patched(target, **replacements):
    missing = object()
    previous = {name: getattr(target, name, missing) for name in replacements}
    for name, value in replacements.items():
        setattr(target, name, value)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is missing:
                delattr(target, name)
            else:
                setattr(target, name, value)


class RecoveryOps:
    """Faults concrete operations reached from production ownership branches."""

    def __init__(self, module, row, root_parent=None):
        self.module = module
        self.fault = row["primitive_fault"]
        self.root_parent = root_parent
        self.events = []
        self.fired = False

    def mutation(self, method):
        if self.fired or method != self.fault["method"]:
            return None
        self.fired = True
        mutation = self.fault["mutation"]
        self.events.append(f"ops.{method}:{mutation}")
        return mutation

    def unavailable(self, primitive, saved):
        ctypes.set_errno(saved)
        return self.module._SystemOps._checked(self, -1, primitive)

    def open(self, path, flags, mode=0o600):
        return os.open(path, flags, mode)

    def close(self, fd):
        mutation = self.mutation("close")
        os.close(fd)
        if mutation == "after-effect-eio":
            raise OSError(errno.EIO, "modeled close after-effect failure")
        if mutation == "replace-root-after-close":
            leaf = Path(self.root_parent) / self.module._ROOT_LEAF
            leaf.rmdir()
            leaf.mkdir(mode=0o700)

    def mount(self, source, target, kind, flags, data):
        del source, target, kind, flags, data
        mutation = self.mutation("mount")
        if mutation == "enosys":
            self.unavailable("mount", errno.ENOSYS)
        if mutation == "eopnotsupp":
            self.unavailable("mount", errno.EOPNOTSUPP)
        raise AssertionError("unexpected recovery mount mutation")

    def start_time(self, pid):
        del pid
        mutation = self.mutation("start_time")
        if mutation == "enosys":
            self.unavailable("proc-stat", errno.ENOSYS)
        raise AssertionError("unexpected start-time mutation")

    def pidfd_signal(self, fd, number):
        del fd, number
        mutation = self.mutation("pidfd_signal")
        if mutation == "eio":
            raise OSError(errno.EIO, "modeled pidfd signal failure")
        raise AssertionError("unexpected pidfd signal mutation")


def materialization_failure(module, ops):
    try:
        module._materialize_root(
            ops,
            "gzip",
            (),
            (),
            {"tools": [None, None, {"objects": []}]},
            "/modeled-root",
        )
    except module.RuntimeLauncherUnavailable as error:
        return error
    raise AssertionError("materialization primitive fault was accepted")


def invoke_unavailable_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    primary = materialization_failure(module, ops)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    leases = [module._FdLease(read_fd, "recovery-authority")]
    module._recover_transaction_with_ops(
        ops, module._ProcessOwner(ops), leases, primary,
    )
    raise primary


def invoke_root_recovery(module, row, created):
    with tempfile.TemporaryDirectory() as parent:
        ops = RecoveryOps(module, row, parent)
        created.append(ops)
        old_parent = module._ROOT_PARENT
        module._ROOT_PARENT = parent
        owner = module._RootOwner(ops)
        try:
            owner.prepare()
            owner.cleanup()
        finally:
            leaf = Path(parent) / module._ROOT_LEAF
            if leaf.exists():
                leaf.rmdir()
            module._ROOT_PARENT = old_parent


def invoke_registration_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    owner = module._ProcessOwner(ops)
    primary = None
    try:
        with patched(module.os, pidfd_open=lambda pid, flags=0: read_fd), patched(
            module, _start_time=ops.start_time,
        ):
            owner.register(4242)
    except module.RuntimeLauncherUnavailable as error:
        primary = error
    if primary is None:
        raise AssertionError("registration primitive fault was accepted")
    os.close(write_fd)
    with patched(
        module.select,
        select=lambda readers, writers, errors, timeout=0: (
            list(readers), list(writers), list(errors)
        ),
    ), patched(module.os, waitpid=lambda pid, flags: (pid, 0)):
        module._recover_transaction_with_ops(ops, owner, [], primary)
    raise primary


def invoke_process_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    owner = module._ProcessOwner(ops)
    with patched(
        module.os,
        pidfd_open=lambda pid, flags=0: read_fd,
        getsid=lambda pid: 1,
        getpgid=lambda pid: 1,
    ), patched(
        module,
        _start_time=lambda pid: 1,
        _exe_identity=lambda pid: (1, 1),
    ):
        owner.register(4242)
    try:
        with patched(
            module.select,
            select=lambda readers, writers, errors, timeout=0: (
                [], list(writers), list(errors)
            ),
        ), patched(module, _process_matches=lambda lease: True), patched(
            module.signal, pidfd_send_signal=ops.pidfd_signal,
        ):
            owner.cleanup()
    finally:
        os.close(write_fd)
        if owner.processes[0].pidfd.state is module._FdState.OWNED:
            os.close(read_fd)


def invoke_close_recovery(module, row, created):
    ops = RecoveryOps(module, row)
    created.append(ops)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    lease = module._FdLease(read_fd, "close-uncertainty")
    module._recover_transaction_with_ops(
        ops, module._ProcessOwner(ops), [lease], None,
    )


def execute_row(module, row):
    adapters = {
        "AT-ADAPT-REC-01": invoke_unavailable_recovery,
        "AT-ROOT-01": invoke_root_recovery,
        "AT-LIFE-01": invoke_registration_recovery,
        "AT-LIFE-02": invoke_process_recovery,
        "AT-FD-CLOSE-01": invoke_close_recovery,
        "AT-UNAV-01": invoke_unavailable_recovery,
    }
    acceptance = row["id"].split(":", 1)[0]
    created = []
    try:
        adapters[acceptance](module, row, created)
    except module.RuntimeLauncherError as error:
        observed = error
    else:
        raise AssertionError(f"{row['id']}: production accepted primitive fault")
    if observed.code != row["intended_code"]:
        raise AssertionError(
            f"{row['id']}: expected {row['intended_code']!r}, got {observed.code!r}",
        ) from observed
    if len(created) != 1:
        raise AssertionError(f"{row['id']}: primitive adapter cardinality")
    if created[0].events != [row["sentinel"]]:
        raise AssertionError(
            f"{row['id']}: production primitive event mismatch {created[0].events}",
        )


def parent():
    module = load_module()
    if not hasattr(module.os, "O_PATH"):
        module.os.O_PATH = 0x200000
    rows = fixture_rows(module)
    selected = {row["id"] for row in rows}
    consumed = set()
    oracle = set()
    sentinel = set()
    for row in rows:
        execute_row(module, row)
        consumed.add(row["id"])
        oracle.add(row["id"])
        sentinel.add(row["id"])
    if selected != consumed or selected != oracle or selected != sentinel:
        raise AssertionError("recovery fixture ledger mismatch")
    print("Outcome 2 recovery portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

#!/usr/bin/env python3
"""Portable crash tests for the production launcher authority owner/recovery."""

from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
MODEL_SUITE = ROOT / "test/outcome-two-trusted-launcher-portable.py"
FIXTURE = ROOT / "test/fixtures/outcome-two/recovery/cases.json"
ROW_KEYS = {
    "id", "production_method", "primitive_fault", "intended_code",
    "cleanup_domains", "sentinel",
}
REQUIRED_ACCEPTANCE = {
    "AT-ADAPT-REC-01", "AT-ROOT-01", "AT-LIFE-01", "AT-LIFE-02",
    "AT-FD-CLOSE-01", "AT-UNAV-01",
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fixture_rows():
    document = json.loads(FIXTURE.read_text())
    if document["version"] != "cogs.outcome-two-recovery-cases/v4":
        raise AssertionError("recovery fixture version")
    rows = []
    acceptance = set()
    family_keys = {
        "acceptance_id", "production_method", "intended_code",
        "cleanup_domains", "sentinel", "cases",
    }
    for family in document["families"]:
        if set(family) != family_keys:
            raise AssertionError("recovery fixture family shape")
        acceptance.add(family["acceptance_id"])
        for case in family["cases"]:
            if type(case) is not list or not 2 <= len(case) <= 3:
                raise AssertionError("recovery fixture case shape")
            row = {
                "id": f"{family['acceptance_id']}:{case[0]}",
                "production_method": family["production_method"],
                "primitive_fault": case[1],
                "intended_code": case[2] if len(case) == 3 else family["intended_code"],
                "cleanup_domains": family["cleanup_domains"],
                "sentinel": f"{family['sentinel']}:{case[1]}",
            }
            if set(row) != ROW_KEYS or type(row["cleanup_domains"]) is not list:
                raise AssertionError("expanded recovery fixture row shape")
            rows.append(row)
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("recovery fixture IDs are not unique")
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


class AuthorityTransaction:
    """Real production ProcessOwner state with modeled worker/helper/namespace authority."""

    def __init__(self, launcher, model_module, row):
        self.launcher = launcher
        self.row = row
        self.model = model_module.PrimitiveModel(launcher, row)
        self.owner = launcher._ProcessOwner(self.model)
        self.leases = []
        self.process_ids = (4101, 4102, 4103)

    def register(self):
        def pidfd_open(pid, flags=0):
            del flags
            self.model.record(f"process.pidfd:{pid}")
            return self.model.allocate("processes")

        def start_time(pid):
            self.model.record(f"process.start:{pid}")
            return pid * 10

        def executable(pid):
            self.model.record(f"process.exe:{pid}")
            return 9, pid

        with patched(
            self.launcher.os,
            pidfd_open=pidfd_open,
            getsid=lambda pid: pid,
            getpgid=lambda pid: pid,
        ), patched(
            self.launcher,
            _start_time=start_time,
            _exe_identity=executable,
        ):
            for pid in self.process_ids:
                gate = self.launcher._FdLease(
                    self.model.allocate("descriptors"),
                    f"release-gate:{pid}",
                )
                lease = self.owner.register(pid, gate)
                self.owner.release(lease)
        for domain in self.row["cleanup_domains"]:
            if domain in {"worker", "helpers", "processes"}:
                continue
            fd = self.model.allocate(domain)
            self.leases.append(
                self.launcher._FdLease(fd, f"authority:{domain}"),
            )

    def crash(self):
        try:
            if self.row["id"].startswith("AT-UNAV-01:"):
                self.model.record(f"transaction.{self.row['primitive_fault']}")
                self.model.record(self.row["sentinel"])
                error = self.launcher.RuntimeLauncherUnavailable(
                    self.row["primitive_fault"],
                )
                self.model.last_error = error
                raise error
            self.model.trip(f"transaction.{self.row['primitive_fault']}")
        except self.launcher.RuntimeLauncherError as error:
            return error
        raise AssertionError("modeled authority crash did not occur")

    def recover(self, primary):
        uncertain = self.row["intended_code"] == "cleanup-uncertain"
        original_close = self.model.close
        original_match = self.model.process_matches

        def close(fd):
            if uncertain and self.row["primitive_fault"] not in {
                "reap-timeout", "lost-reap-ownership", "unavailable-reap-uncertain",
            }:
                self.model.trip("recovery.close")
            original_close(fd)

        def process_matches(lease):
            if uncertain and self.row["primitive_fault"] in {
                "reap-timeout", "lost-reap-ownership", "start-time-drift",
                "executable-drift", "unexpected-owned-child", "eof-live",
                "unavailable-reap-uncertain",
            }:
                self.model.trip("recovery.process-identity")
            return original_match(lease)

        self.model.close = close
        try:
            with patched(
                self.launcher,
                _process_matches=process_matches,
                _wait_bounded=self.model.wait_bounded,
            ), patched(
                self.launcher.signal,
                pidfd_send_signal=self.model.pidfd_signal,
            ):
                self.launcher._recover_transaction_with_ops(
                    self.model,
                    self.owner,
                    self.leases,
                    primary,
                )
        finally:
            self.model.close = original_close

    def assert_result(self, primary, recovery_error):
        if recovery_error is None:
            observed = primary
            if self.model.open_fds or self.model.authority or self.owner.processes:
                raise AssertionError(f"{self.row['id']}: authority survived clean recovery")
        else:
            observed = recovery_error
            if not self.model.open_fds and not self.owner.processes:
                raise AssertionError(f"{self.row['id']}: uncertainty was erased")
        if observed.code != self.row["intended_code"]:
            raise AssertionError(
                f"{self.row['id']}: expected {self.row['intended_code']!r}, "
                f"got {observed.code!r}",
            ) from observed
        if self.row["sentinel"] not in self.model.trace:
            raise AssertionError(f"{self.row['id']}: branch-removal sentinel absent")
        if any(item.startswith("retry.") for item in self.model.trace):
            raise AssertionError(f"{self.row['id']}: preparation was retried")


def execute_row(launcher, model_module, row):
    transaction = AuthorityTransaction(launcher, model_module, row)
    transaction.register()
    primary = transaction.crash()
    recovery_error = None
    try:
        transaction.recover(primary)
    except launcher.RuntimeLauncherCleanupError as error:
        recovery_error = error
    transaction.assert_result(primary, recovery_error)


def parent():
    launcher = load(MODULE, "completion_trusted_runtime_launcher_recovery")
    model_module = load(MODEL_SUITE, "outcome_two_launcher_primitive_model")
    rows = fixture_rows()
    selected = {row["id"] for row in rows}
    consumed = set()
    oracle = set()
    sentinel = set()
    for row in rows:
        execute_row(launcher, model_module, row)
        consumed.add(row["id"])
        oracle.add(row["id"])
        sentinel.add(row["id"])
    if not selected == consumed == oracle == sentinel:
        raise AssertionError("recovery selected/consumed/oracle/sentinel mismatch")
    print("Outcome 2 recovery portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

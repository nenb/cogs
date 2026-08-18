#!/usr/bin/env python3
"""Portable fail-closed entry/qualification/fd-map checks for Slice A."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_fdmap as fdmap
import completion_kata_process as process
import completion_kata_qualification as qualification


def check(value, message):
    if not value:
        raise AssertionError(message)


def reject(call):
    try:
        call()
    except BaseException:
        return
    raise AssertionError("hostile case accepted")


report = qualification.committed_report()
check(not report["qualified"], "Slice A claimed qualification")
check(report["authority"] == "committed-local-preflight", "wrong report authority")
for blocker in (
    "source-not-clean-qualified", "host-tools-unqualified", "runtime-fixtures-unqualified",
    "network-fixtures-unqualified", "ssh-fixture-unqualified", "kvm-missing-or-unqualified",
):
    check(blocker in report["blockers"], f"missing blocker {blocker}")
raw = qualification.canonical_report(report)
check(qualification.load_report(raw) == report, "qualification round trip")
reject(lambda: qualification.load_report(raw.replace(b'"qualified":false', b'"qualified":true')))
reject(qualification.require_committed_facts)
reject(process.open_fixed_process_owner)

entry = REMOTE / "completion_kata_qualification.py"
for optimize in (False, True):
    args = [sys.executable]
    if optimize:
        args.append("-O")
    args.append(str(entry))
    result = subprocess.run(args, capture_output=True, check=False, timeout=5,
                            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    check(result.returncode == 1 and result.stderr == b"", "preflight did not fail closed")
    check(not qualification.load_report(result.stdout)["qualified"], "optimized preflight qualified")

shell = REMOTE / "run-stage2-completion-remote.sh"
argument = subprocess.run([str(shell), "unexpected"], capture_output=True, check=False, timeout=5)
check(argument.returncode == 64, "shell accepted argument")
hostile_env = subprocess.run([str(shell)], capture_output=True, check=False, timeout=5,
                             env={"PATH": "/usr/bin:/bin", "AWS_PROFILE": "hostile"})
check(hostile_env.returncode == 65, "shell accepted provider environment")

with tempfile.TemporaryDirectory() as directory:
    one = Path(directory) / "one"
    two = Path(directory) / "two"
    one.write_bytes(b"one")
    two.write_bytes(b"two")
    first = os.open(one, os.O_RDONLY | os.O_CLOEXEC)
    second = os.open(two, os.O_RDONLY | os.O_CLOEXEC)
    try:
        first_id = fdmap.identity(first)
        second_id = fdmap.identity(second)
        bindings = fdmap.bind_inputs(first, second, first_id, second_id)
        check(tuple(row.target_fd for row in bindings) == (200, 201), "fixed fd map drift")
        reject(lambda: fdmap.bind_inputs(first, os.dup(first), first_id, first_id))
        os.link(one, Path(directory) / "linked")
        reject(lambda: fdmap.revalidate(bindings))
    finally:
        os.close(first)
        os.close(second)

for name in (
    "completion_kata_qualification.py", "completion_kata_fdmap.py", "completion_kata_process.py",
):
    source = (REMOTE / name).read_text()
    check("seal = object()" not in source, f"Python seal remains in {name}")
check("CommittedGate" not in (REMOTE / "completion_kata_qualification.py").read_text(),
      "qualification gate remains")
print("completion Kata Slice A fail-closed foundation matrix passed")

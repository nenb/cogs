#!/usr/bin/env python3
"""Hostile portable tests for the static-control no-runtime boundary."""

import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stage2_static_runtime_boundary_test",
    ROOT / "scripts/stage2-static-control-runtime-boundary.py",
)
BOUNDARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOUNDARY
SPEC.loader.exec_module(BOUNDARY)


def rejection(call):
    try:
        call()
    except BOUNDARY.BoundaryError:
        return
    raise AssertionError("hostile static runtime boundary input was accepted")


with tempfile.TemporaryDirectory(prefix="cogs-static-runtime-test-") as temporary:
    root = Path(temporary)
    repository = root / "repository"
    for relative in (*BOUNDARY.POLICY, BOUNDARY.WORKFLOW_PATH):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    observed_policy = BOUNDARY._source_policy(repository)
    assert observed_policy == {
        **{relative: rule["sha256"] for relative, rule in BOUNDARY.POLICY.items()},
        BOUNDARY.WORKFLOW_PATH: BOUNDARY.hashlib.sha256(
            (ROOT / BOUNDARY.WORKFLOW_PATH).read_bytes()).hexdigest(),
    }
    workflow = repository / BOUNDARY.WORKFLOW_PATH
    workflow.write_bytes(workflow.read_bytes().replace(
        b'REVIEWED_IMPLEMENTATION_HEAD = "d05bbc5928bda9b6bd27da1c290b0238219fd185"',
        b'REVIEWED_IMPLEMENTATION_HEAD = "' + b"a" * 40 + b'"',
        1,
    ))
    assert set(BOUNDARY._source_policy(repository)) == set(observed_policy)
    mutated = repository / next(iter(BOUNDARY.POLICY))
    mutated.write_bytes(mutated.read_bytes() + b"\n")
    rejection(lambda: BOUNDARY._source_policy(repository))

    proc = root / "proc"
    pid = proc / "101"
    (pid / "fd").mkdir(parents=True)
    (pid / "ns").mkdir()
    (pid / "cmdline").write_bytes(b"/usr/bin/python3\0/owned/job.py\0")
    (pid / "exe").symlink_to("/usr/bin/python3")
    (pid / "cwd").symlink_to("/owned")
    (pid / "root").symlink_to("/")
    (pid / "ns/net").symlink_to("net:[1]")
    (pid / "fd/3").symlink_to("/dev/kvm")
    (pid / "fd/4").symlink_to("socket:[55]")
    rows, count = BOUNDARY._process_violations(
        pid, "net:[1]", {"55": "/owned/qmp.sock"}, ("/owned/",)
    )
    assert count == 2
    assert rows == ("owned-kvm-fd", "owned-qmp-or-runtime-socket")

    (pid / "fd/3").unlink()
    (pid / "fd/4").unlink()
    (pid / "ns/net").unlink()
    (pid / "ns/net").symlink_to("net:[2]")
    rows, _count = BOUNDARY._process_violations(
        pid, "net:[1]", {}, ("/owned/",)
    )
    assert rows == ("owned-network-namespace",)

    (pid / "cmdline").write_bytes(b"/opt/kata/bin/qemu-system-x86_64\0")
    rows, _count = BOUNDARY._process_violations(
        pid, "net:[2]", {}, ("/owned/", "/opt/kata/")
    )
    assert rows == ("owned-runtime-process",)

    # A host-owned process can have KVM open; device and unrelated host-process
    # absence are deliberately not asserted by this workflow.
    (pid / "cmdline").write_bytes(b"/usr/bin/host-service\0")
    (pid / "cwd").unlink()
    (pid / "cwd").symlink_to("/")
    (pid / "fd/3").symlink_to("/dev/kvm")
    rows, _count = BOUNDARY._process_violations(
        pid, "net:[2]", {}, ("/owned/", "/opt/kata/")
    )
    assert rows == ()

    state = root / "state.json"
    value = {
        "version": BOUNDARY.VERSION,
        "context": {},
        "policy": {},
        "baseline": {"violations": []},
    }
    BOUNDARY._write_state(value, state)
    assert BOUNDARY._read_state(state) == value
    rejection(lambda: BOUNDARY._write_state(value, state))
    state.chmod(0o600)
    state.write_bytes(b"{}\n")
    rejection(lambda: BOUNDARY._read_state(state))

print("stage2 static-control runtime boundary hostile tests passed")

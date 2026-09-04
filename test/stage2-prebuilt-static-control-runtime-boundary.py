#!/usr/bin/env python3
"""Portable exact-policy checks for additive prebuilt static boundary."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stage2_prebuilt_static_boundary_test",
    ROOT / "scripts/stage2-prebuilt-static-control-runtime-boundary.py")
module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
spec.loader.exec_module(module)


def rejected(callback):
    try: callback()
    except module.BoundaryError: return
    raise AssertionError("changed prebuilt static authority accepted")


with tempfile.TemporaryDirectory() as temporary:
    repository = Path(temporary)
    for relative in (*module.POLICY, module.WORKFLOW_PATH):
        target = repository / relative; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(
            ("git", "show", f"d2fe08553d25d73fa276794c96b0f311e5406186:{relative}"), cwd=ROOT))
    observed = module._source_policy(repository)
    assert observed[module.WORKFLOW_PATH] == module.REVIEWED_WORKFLOW_SHA256
    workflow = repository / module.WORKFLOW_PATH
    workflow.write_bytes(workflow.read_bytes() + b"\n")
    rejected(lambda: module._source_policy(repository))

print("stage2 prebuilt static boundary checks passed")

#!/usr/bin/env python3
"""Fixed native Job A: qualify the production Python mapped closure."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import sys
from typing import Any

_TOOL = ("python3-parser", "/usr/bin/python3")
_CHECKS = (
    "elf_real",
    "python_closure_exact",
    "map_files_trusted",
    "mapped_closure_equal",
    "mapping_stable",
    "helper_reaped",
    "cleanup_restored",
)

class _HelperAuthority:
    """Keep the production helper's one registration lifecycle exact."""

    def __init__(self) -> None:
        self._token = object()
        self._helper: Any | None = None
        self._released = False
        self.retired = False

    def _register_runtime_helper(self, helper: Any, deadline: float) -> object:
        if self._helper is not None or deadline <= 0:
            raise RuntimeError("helper registration replay")
        self._helper = helper
        return self._token

    def _release_runtime_helper(self, token: object, deadline: float) -> None:
        if token is not self._token or self._released or deadline <= 0:
            raise RuntimeError("helper release mismatch")
        self._released = True

    def _retire_runtime_helper(self, token: object, deadline: float) -> None:
        helper = self._helper
        if token is not self._token or not self._released or deadline <= 0:
            raise RuntimeError("helper retirement mismatch")
        if helper is None or not helper.reaped:
            raise RuntimeError("helper retired before exact reap")
        self._helper = None
        self.retired = True

def _load_modules() -> tuple[Any, Any]:
    directory = Path(__file__).resolve().parent
    remote = directory.parents[1] / "deploy/aws-feasibility/remote"
    sys.path[:0] = [str(directory), str(remote)]
    try:
        common = importlib.import_module("common")
        runtime = importlib.import_module("completion_trusted_runtime_closure")
        return common, runtime
    finally:
        del sys.path[:2]

def _metadata(runtime: Any, resolved: Any, mapped: Any) -> list[dict[str, object]]:
    objects = [runtime._object_report(value) for value in resolved.objects]
    total = sum(value.size for value in resolved.objects)
    rows = [
        {"id": f"python-object-{index}", "role": value.role,
         "sha256": value.sha256, "size_bytes": value.size}
        for index, value in enumerate(resolved.objects)
    ]
    rows += [
        {"id": "python-closure", "role": "closure",
         "sha256": hashlib.sha256(runtime._canonical(objects)).hexdigest(), "size_bytes": total},
        {"id": "python-mapping", "role": "mapping",
         "sha256": mapped.mapping_sha256, "size_bytes": total},
    ]
    return rows
def _qualify(runtime: Any) -> list[dict[str, object]]:
    ops = runtime._Ops()
    ops.architecture_gate()
    baseline_fds = runtime._snapshot_fds(ops)
    baseline_children = runtime._child_baseline(ops)
    authority = _HelperAuthority()
    preparation = runtime.PreparationLease(ops, baseline_fds, baseline_children, outer=authority)
    resolved = None
    helper = None
    mapped = None
    failures: list[BaseException] = []
    try:
        resolved = runtime._resolve_tool(ops, *_TOOL)
        helper = runtime._spawn_helper(ops, preparation, resolved)
        mapped = runtime._mapped_closure(ops, helper, resolved)
    except BaseException as error:
        failures.append(error)
    if helper is not None and helper in preparation.helpers:
        try:
            runtime._stop_helper(ops, preparation, helper)
        except BaseException as error:
            failures.append(error)
    if resolved is not None:
        try:
            runtime._close_objects(ops, resolved.objects)
        except BaseException as error:
            failures.append(error)
    try:
        helper_clean = helper is None or (
            authority.retired and helper.reaped
            and helper.pidfd.state is runtime._FdState.CLOSED
        )
        clean = (
            not preparation.helpers and not preparation.owned_fds() and helper_clean
            and runtime._snapshot_fds(ops) == baseline_fds
            and runtime._child_baseline(ops) == baseline_children
        )
        if not clean:
            raise runtime.RuntimeClosureError("Job A cleanup baseline mismatch")
    except BaseException as error:
        failures.append(error)
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise runtime.RuntimeClosureCleanupError(failures)
    return _metadata(runtime, resolved, mapped)

def _native_fixed() -> int:
    common, runtime = _load_modules()
    context = common.WorkflowContext.from_environ("A", __file__)
    cleanup = dict.fromkeys(common.CLEANUP_KEYS, True)
    try:
        metadata = _qualify(runtime)
    except BaseException as error:
        checks = dict.fromkeys(_CHECKS, "fail")
        cleanup = dict.fromkeys(common.CLEANUP_KEYS, False)
        diagnostic = f"{type(error).__name__}:{error}".encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", checks, [], cleanup, "runtime_mappings", diagnostic)
        return 1
    common.finalize_report(context, "pass", dict.fromkeys(_CHECKS, "pass"), metadata, cleanup)
    return 0

def _self_test() -> None:
    if len(_CHECKS) != len(set(_CHECKS)) or _CHECKS[-1] != "cleanup_restored":
        raise RuntimeError("Job A check contract changed")
    print("native qualification A static self-test passed")

def main(arguments: list[str]) -> None:
    if not __debug__:
        raise SystemExit("optimized mode is forbidden")
    if arguments == ["--self-test"]:
        _self_test()
        return
    if arguments != ["--native-fixed"]:
        raise SystemExit("usage: job-a-runtime-mappings.py --self-test|--native-fixed")
    try:
        status = _native_fixed()
    except BaseException:
        status = 1
    raise SystemExit(status)

if __name__ == "__main__":
    main(sys.argv[1:])

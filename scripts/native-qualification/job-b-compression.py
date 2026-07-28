#!/usr/bin/python3
"""Job B: validate the fixed production gzip/zstd observation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable, Mapping

CHECKS = (
    "gzip_source_exact", "gzip_sealed_exec", "zstd_source_exact",
    "zstd_sealed_exec", "decompression_deterministic", "network_denied",
    "children_exact", "cleanup_restored",
)
OPERATION = "B"
RESULT_VERSION = "cogs.runtime-compression-qualification/v1"
MARKER = "cogs-runtime-qualification-v1"
MARKER_SHA256 = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8"
MAX_OBJECT_SIZE = 134_217_728
SONAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}\Z")
FACTS = tuple("""
    mapped_generations_exact user_namespace_exact pid_namespace_exact
    mount_namespace_exact network_namespace_exact namespace_ownership_exact
    namespace_handles_exact pid_one supplementary_groups_empty
    effective_capabilities_zero permitted_capabilities_zero
    inheritable_capabilities_zero bounding_capabilities_zero
    ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs
    seccomp_installed seccomp_mode_exact seccomp_program_exact
    seccomp_denials_exact exec_descriptor_consumed no_acquisition_route
    root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent
    limits_exact descriptors_restored children_reaped descendants_reaped
    mounts_restored paths_restored namespaces_released namespace_handles_released
""".split())


class QualificationError(RuntimeError):
    """The admitted Job B observation is not exact."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _tool_objects(value: object) -> list[dict[str, object]]:
    _require(type(value) is list and 2 <= len(value) <= 127, "tool object count")
    normalized: list[dict[str, object]] = []
    providers: dict[str, int] = {}
    previous: tuple[bytes, str] | None = None
    identities: set[tuple[object, object]] = set()
    for index, item in enumerate(value):
        keys = {"role", "sha256", "size_bytes", "soname", "needed"}
        _require(type(item) is dict and set(item) == keys, "tool object shape")
        expected = "executable" if index == 0 else "loader" if index == 1 else "library"
        _require(item["role"] == expected and _digest(item["sha256"]), "tool object identity")
        size = item["size_bytes"]
        _require(type(size) is int and 1 <= size <= MAX_OBJECT_SIZE, "tool object size")
        soname = item["soname"]
        _require(soname is None or type(soname) is str and SONAME.fullmatch(soname) is not None, "tool SONAME")
        _require(expected != "library" or type(soname) is str, "library provider")
        needed = item["needed"]
        _require(
            type(needed) is list and len(needed) <= 127
            and all(type(name) is str and SONAME.fullmatch(name) is not None for name in needed),
            "tool needed",
        )
        _require(len(needed) == len(set(needed)), "duplicate tool needed")
        identity = (item["sha256"], size)
        _require(identity not in identities, "duplicate tool object")
        identities.add(identity)
        if soname is not None:
            providers[soname] = providers.get(soname, 0) + 1
        if index >= 2:
            order = (str(soname).encode("ascii"), str(item["sha256"]))
            _require(previous is None or previous < order, "tool library order")
            previous = order
        normalized.append({
            "needed": list(needed), "role": expected, "sha256": item["sha256"],
            "size": size, "soname": soname,
        })
    needed_names = [name for item in normalized for name in item["needed"]]
    _require(all(count == 1 for count in providers.values()), "duplicate tool provider")
    _require(all(providers.get(str(name)) == 1 for name in needed_names), "tool provider")
    _require(all(item["soname"] in set(needed_names) for item in normalized[2:]), "extra tool library")
    return normalized


def qualify(
    result: Mapping[str, object], revision: str, source_set_sha256: str,
) -> list[dict[str, object]]:
    """Require complete source/sealed/execution rows without transformation."""
    fields = {
        "version",
        "source_revision",
        "source_set_sha256",
        "closure_sha256",
        "parser",
        "tools",
        "runtime",
    }
    _require(type(result) is dict and set(result) == fields, "result shape")
    _require(
        (result["version"], result["source_revision"], result["source_set_sha256"])
        == (RESULT_VERSION, revision, source_set_sha256),
        "result admission binding",
    )
    _require(_digest(source_set_sha256) and _digest(result["closure_sha256"]), "result digest")
    runtime = result["runtime"]
    runtime_strings = (
        "version", "marker", "source_revision", "source_set_sha256",
        "closure_sha256", "gzip_output_sha256", "zstd_output_sha256",
    )
    _require(
        type(runtime) is dict and set(runtime) == set(runtime_strings + FACTS),
        "runtime result shape",
    )
    _require(
        (runtime["version"], runtime["marker"], runtime["source_revision"], runtime["source_set_sha256"])
        == ("cogs.runtime-qualification/v1", MARKER, revision, source_set_sha256),
        "runtime result binding",
    )
    _require(runtime["closure_sha256"] == result["closure_sha256"], "top closure binding")
    _require(all(runtime[name] is True for name in FACTS), "production observation")
    _require(
        runtime["gzip_output_sha256"] == MARKER_SHA256
        and runtime["zstd_output_sha256"] == MARKER_SHA256,
        "exact marker digest",
    )
    tools = result["tools"]
    _require(type(tools) is list and len(tools) == 2, "compression metadata")
    keys = {
        "id", "objects", "closure_sha256", "mapping_sha256",
        "source_sha256", "source_size_bytes", "sealed_sha256",
        "sealed_size_bytes", "seal_mask", "execution_mapping_sha256",
        "output_sha256",
    }
    rows: list[dict[str, object]] = []
    tool_views: dict[str, dict[str, object]] = {}
    for expected, value in zip(("gzip", "zstd"), tools):
        _require(type(value) is dict and set(value) == keys and value["id"] == expected, "tool row shape")
        normalized = _tool_objects(value["objects"])
        mapped = [[item["role"], item["sha256"]] for item in normalized]
        closure = hashlib.sha256(_canonical(normalized)).hexdigest()
        mapping = hashlib.sha256(_canonical(mapped)).hexdigest()
        _require(value["closure_sha256"] == closure, "tool closure summary")
        _require(value["mapping_sha256"] == mapping, "tool mapping summary")
        _require(value["execution_mapping_sha256"] == mapping, "execution mapping")
        _require(value["seal_mask"] == 63, "actual six-bit seal mask")
        for name in ("source_sha256", "sealed_sha256", "output_sha256"):
            _require(_digest(value[name]), f"{expected} {name}")
        for name in ("source_size_bytes", "sealed_size_bytes"):
            size = value[name]
            _require(type(size) is int and 1 <= size <= MAX_OBJECT_SIZE, f"{expected} {name}")
        executable = normalized[0]
        _require(
            value["source_sha256"] == value["sealed_sha256"] == executable["sha256"],
            "sealed source digest",
        )
        _require(
            value["source_size_bytes"] == value["sealed_size_bytes"] == executable["size"],
            "sealed source size",
        )
        _require(value["output_sha256"] == MARKER_SHA256, "tool marker digest")
        _require(
            value["output_sha256"] == runtime[f"{expected}_output_sha256"],
            "output binding",
        )
        rows.append(dict(value))
        tool_views[expected] = {
            "closure_sha256": closure,
            "objects": normalized,
            "seal_profile": "linux-memfd-exec-seals-v1",
            "sealed_executable": True,
            "tool": expected,
        }
    _require(
        rows[0]["source_sha256"] != rows[1]["source_sha256"],
        "cross-tool source substitution",
    )
    _require(
        rows[0]["mapping_sha256"] != rows[1]["mapping_sha256"],
        "cross-tool mapping substitution",
    )
    parser = result["parser"]
    parser_fields = {"closure_sha256", "objects"}
    _require(type(parser) is dict and set(parser) == parser_fields, "parser summary shape")
    parser_objects = _tool_objects(parser["objects"])
    parser_closure = hashlib.sha256(_canonical(parser_objects)).hexdigest()
    _require(parser["closure_sha256"] == parser_closure, "parser closure summary")
    parser_view = {
        "closure_sha256": parser_closure,
        "objects": parser_objects,
        "seal_profile": None,
        "sealed_executable": False,
        "tool": "python3-parser",
    }
    aggregate_view = [parser_view, tool_views["zstd"], tool_views["gzip"]]
    aggregate_closure = hashlib.sha256(_canonical(aggregate_view)).hexdigest()
    _require(result["closure_sha256"] == aggregate_closure, "aggregate closure summary")
    rows.append({
        "kind": "summary",
        "id": "trusted-closure",
        "closure_sha256": aggregate_closure,
        "parser": {
            "closure_sha256": parser_closure,
            "objects": [dict(value) for value in parser["objects"]],
        },
    })
    return rows


def _production_operation(session: object) -> Mapping[str, object]:
    """W1 adapter point: common enters the held-byte, job-bound owner."""
    return session.run_fixed_operation(OPERATION)  # type: ignore[no-any-return,attr-defined]


def _workflow_bound(common: object | None = None) -> int:
    common = _load_common() if common is None else common
    session = common.NativeSession.begin("B", __file__)  # type: ignore[attr-defined]
    metadata: list[dict[str, object]] = []
    primary: BaseException | None = None
    try:
        metadata = qualify(
            _production_operation(session), session.context.head_sha, session.source_set_sha256,
        )
    except Exception as error:
        primary = error
    evidence = session.settle_native_phase()
    passing = primary is None and evidence.restored
    checks = dict.fromkeys(CHECKS[:-1], "pass" if primary is None else "fail")
    diagnostic = None if passing else (
        f"{type(primary).__name__}:{primary}".encode()
        if primary is not None else b"common baseline not restored"
    )
    if diagnostic is not None:
        diagnostic = diagnostic[:common.REPORT_LIMIT]  # type: ignore[attr-defined]
    candidate = common.ReportCandidate(  # type: ignore[attr-defined]
        production_checks=checks, metadata=metadata if passing else [],
        failure_phase=None if passing else "compression",
        diagnostics=diagnostic, primary_error=primary,
    )
    session.publish(candidate)
    return 0 if passing else 1


def _dispatch(arguments: list[str], workflow: Callable[[], int] = _workflow_bound) -> int:
    if not __debug__ or arguments != ["--workflow-bound"]:
        raise QualificationError("Job B requires the fixed workflow entry")
    return workflow()


if __name__ == "__main__":
    try:
        exit_code = _dispatch(sys.argv[1:])
    except Exception:
        os.write(2, b"native-b-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)

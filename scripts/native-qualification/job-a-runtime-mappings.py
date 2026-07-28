#!/usr/bin/python3
"""Job A: validate the fixed production Python-mapping observation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable, Mapping

CHECKS = (
    "elf_real", "python_closure_exact", "map_files_trusted",
    "mapped_closure_equal", "mapping_stable", "helper_reaped",
    "cleanup_restored",
)
OPERATION = "A"
RESULT_VERSION = "cogs.runtime-mapping-qualification/v1"
MAX_OBJECT_SIZE = 134_217_728
MAX_OBJECTS = 127
SONAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}\Z")


class QualificationError(RuntimeError):
    """The admitted Job A observation is not exact."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _normalized_object(value: object, index: int) -> dict[str, object]:
    keys = {"role", "sha256", "size_bytes", "soname", "needed"}
    _require(type(value) is dict and set(value) == keys, "mapping object shape")
    row = value
    role = row["role"]
    expected_role = "executable" if index == 0 else "loader" if index == 1 else "library"
    _require(role == expected_role, "mapping role order")
    _require(_digest(row["sha256"]), "mapping object digest")
    size = row["size_bytes"]
    _require(type(size) is int and 1 <= size <= MAX_OBJECT_SIZE, "mapping object size")
    soname = row["soname"]
    _require(soname is None or type(soname) is str and SONAME.fullmatch(soname) is not None, "mapping SONAME")
    _require(role != "library" or type(soname) is str, "library provider")
    needed = row["needed"]
    _require(
        type(needed) is list
        and len(needed) <= MAX_OBJECTS
        and all(type(name) is str and SONAME.fullmatch(name) is not None for name in needed),
        "ordered needed",
    )
    _require(len(needed) == len(set(needed)), "duplicate needed")
    return {
        "needed": list(needed), "role": role, "sha256": row["sha256"],
        "size": size, "soname": soname,
    }


def qualify(
    result: Mapping[str, object], revision: str, source_set_sha256: str,
) -> list[dict[str, object]]:
    """Independently normalize and bind the closed production observation."""
    fields = {
        "version", "source_revision", "source_set_sha256", "closure_sha256",
        "mapping_sha256", "objects", "mapped",
        "mapped_generations_exact", "mapping_stable", "helper_reaped",
        "descriptors_restored", "children_reaped",
    }
    _require(type(result) is dict and set(result) == fields, "result shape")
    _require(
        (result["version"], result["source_revision"], result["source_set_sha256"])
        == (RESULT_VERSION, revision, source_set_sha256),
        "result admission binding",
    )
    _require(_digest(source_set_sha256), "admitted source-set digest")
    facts = (
        "mapped_generations_exact", "mapping_stable", "helper_reaped",
        "descriptors_restored", "children_reaped",
    )
    _require(all(result[name] is True for name in facts), "production observation")
    objects = result["objects"]
    _require(type(objects) is list and 2 <= len(objects) <= MAX_OBJECTS, "object count")
    normalized = [_normalized_object(value, index) for index, value in enumerate(objects)]
    identities = [(row["sha256"], row["size"]) for row in normalized]
    _require(len(identities) == len(set(identities)), "duplicate object identity")
    digest_roles: dict[object, object] = {}
    for row in normalized:
        digest = row["sha256"]
        role = row["role"]
        previous_role = digest_roles.setdefault(digest, role)
        _require(previous_role == role, "digest reused under another role")
    providers: dict[str, int] = {}
    previous_library: tuple[bytes, str] | None = None
    for index, row in enumerate(normalized):
        soname = row["soname"]
        if soname is not None:
            providers[soname] = providers.get(soname, 0) + 1
        if index >= 2:
            order = (str(soname).encode("ascii"), str(row["sha256"]))
            _require(previous_library is None or previous_library < order, "library order")
            previous_library = order
    needed = [name for row in normalized for name in row["needed"]]
    _require(all(count == 1 for count in providers.values()), "duplicate provider")
    _require(all(providers.get(str(name)) == 1 for name in needed), "needed provider")
    required = set(needed)
    _require(all(row["soname"] in required for row in normalized[2:]), "extra library")
    mapped = [{"role": row["role"], "sha256": row["sha256"]} for row in normalized]
    _require(result["mapped"] == mapped, "mapped sequence")
    closure = hashlib.sha256(_canonical(normalized)).hexdigest()
    digest_sequence = [[row["role"], row["sha256"]] for row in normalized]
    mapping = hashlib.sha256(_canonical(digest_sequence)).hexdigest()
    _require(result["closure_sha256"] == closure, "closure summary")
    _require(result["mapping_sha256"] == mapping, "mapping summary")
    rows = [{"kind": "object", "id": f"python-object-{index}", **dict(value)}
            for index, value in enumerate(objects)]
    rows.append({
        "kind": "summary", "closure_sha256": closure,
        "mapped_sequence": mapped, "mapping_sha256": mapping,
    })
    return rows


def _production_operation(session: object) -> Mapping[str, object]:
    """W1 adapter point: common enters the held-byte, job-bound owner."""
    return session.run_fixed_operation(OPERATION)  # type: ignore[no-any-return,attr-defined]


def _workflow_bound(common: object | None = None) -> int:
    common = _load_common() if common is None else common
    session = common.NativeSession.begin("A", __file__)  # type: ignore[attr-defined]
    metadata: list[dict[str, object]] = []
    primary: BaseException | None = None
    try:
        metadata = qualify(
            _production_operation(session), session.context.head_sha, session.source_set_sha256,
        )
    except BaseException as error:
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
        failure_phase=None if passing else "runtime_mappings",
        diagnostics=diagnostic, primary_error=primary,
    )
    session.publish(candidate)
    return 0 if passing else 1


def _dispatch(arguments: list[str], workflow: Callable[[], int] = _workflow_bound) -> int:
    if not __debug__ or arguments != ["--workflow-bound"]:
        raise QualificationError("Job A requires the fixed workflow entry")
    return workflow()


if __name__ == "__main__":
    try:
        exit_code = _dispatch(sys.argv[1:])
    except Exception:
        os.write(2, b"native-a-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)

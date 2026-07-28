#!/usr/bin/python3
"""Native Job C: validate the admitted production descriptor-owner result."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Mapping

CHECKS = (
    "nofile_measured", "nofile_normalized", "fd_198_exact", "fd_4096_exact",
    "close_range_exact", "cloexec_exact", "inheritance_exact",
    "limit_restored", "cleanup_restored",
)
MECHANISM_CHECKS = CHECKS[:-1]
RESULT_VERSION = "cogs.runtime-descriptor-qualification/v1"
OBSERVATIONS = (
    "getdents_exact", "nofile_measured", "nofile_normalized", "fd_198_exact",
    "fd_4096_exact", "close_range_exact", "cloexec_exact", "inheritance_exact",
    "limit_restored", "descriptors_restored", "children_reaped",
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class QualificationError(RuntimeError):
    """The production descriptor observation did not match the fixed contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def qualify(value: object, revision: str) -> dict[str, str]:
    """Map one closed W1 descriptor result to mechanism checks; infer nothing."""
    fields = ("version", "source_revision", "source_set_sha256", *OBSERVATIONS)
    _require(type(value) is dict and set(value) == set(fields), "descriptor result shape")
    result: Mapping[str, object] = value
    _require(result["version"] == RESULT_VERSION, "descriptor result version")
    _require(type(revision) is str and result["source_revision"] == revision,
             "descriptor result source")
    digest = result["source_set_sha256"]
    _require(type(digest) is str and HEX64.fullmatch(digest) is not None,
             "descriptor source-set digest")
    _require(all(result[name] is True for name in OBSERVATIONS),
             "descriptor mechanism observation")
    return {name: "pass" for name in MECHANISM_CHECKS}


def _load_common() -> object:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _invoke_production(session: object) -> object:
    """W1/W2 seam: the admitted session exposes one zero-argument C operation."""
    return session.qualify_fixed_descriptor_primitives()  # type: ignore[attr-defined]


def _workflow_bound() -> int:
    common = _load_common()
    session = common.NativeSession.begin("C", __file__)
    failure: BaseException | None = None
    try:
        checks = qualify(_invoke_production(session), session.context.head_sha)
    except BaseException as error:
        failure = error
        checks = dict.fromkeys(MECHANISM_CHECKS, "fail")
    diagnostic = None if failure is None else type(failure).__name__.encode("ascii")
    candidate = common.ReportCandidate(
        checks, [], None if failure is None else "descriptors", diagnostic, failure,
    )
    evidence = session.settle_native_phase()
    session.publish(candidate)
    return 0 if failure is None and evidence.restored else 1


def _dispatch(arguments: list[str], workflow: object = _workflow_bound) -> int:
    _require(__debug__ and arguments == ["--workflow-bound"], "fixed workflow entry")
    return workflow()  # type: ignore[operator]


if __name__ == "__main__":
    try:
        raise SystemExit(_dispatch(sys.argv[1:]))
    except BaseException:
        raise SystemExit(1)

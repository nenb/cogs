#!/usr/bin/python3
"""Job E client for the common-owned sandbox qualification."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Callable

OPERATION = "E"
FAILURE_PHASE = "sandbox"
DIAGNOSTIC_LIMIT = 2_048


class QualificationError(RuntimeError):
    """The fixed Job E workflow entry was not selected."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _load_common() -> object:
    module_directory = os.fspath(Path(__file__).resolve().parent)
    sys.path.insert(0, module_directory)
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _operation(session: object) -> None:
    """Enter the one common-owned operation boundary; its return stays private."""
    session.run_fixed_operation(OPERATION)  # type: ignore[attr-defined]


def _combine(primary: BaseException | None, cleanup: BaseException) -> BaseException:
    if primary is None:
        return cleanup
    return BaseExceptionGroup("Job E operation and settlement", [primary, cleanup])


def _diagnostic(error: BaseException | None, restored: bool) -> bytes | None:
    if error is None and restored:
        return None
    if error is None:
        return b"common cleanup was not restored"
    message = f"{type(error).__name__}:{error}".encode("utf-8", "backslashreplace")
    return message[:DIAGNOSTIC_LIMIT]


def _run(common: object) -> int:
    session = common.NativeSession.begin(OPERATION, __file__)  # type: ignore[attr-defined]
    primary: BaseException | None = None

    try:
        _operation(session)
    except Exception as error:
        primary = error

    evidence = None
    try:
        evidence = session.settle_native_phase()  # type: ignore[attr-defined]
    except Exception as error:
        primary = _combine(primary, error)

    restored = evidence is not None and evidence.restored is True
    failed = primary is not None or not restored
    candidate = common.ReportCandidate(  # type: ignore[attr-defined]
        failure_phase=FAILURE_PHASE if failed else None,
        diagnostics=_diagnostic(primary, restored),
        primary_error=primary,
    )
    session.publish(candidate)  # type: ignore[attr-defined]
    return 1 if failed else 0


def _dispatch(
    arguments: list[str],
    workflow: Callable[[object], int] = _run,
    common_loader: Callable[[], object] = _load_common,
) -> int:
    entry_is_fixed = __debug__ and arguments == ["--workflow-bound"]
    _require(entry_is_fixed and os.geteuid() != 0, "fixed unprivileged Job E workflow entry")
    return workflow(common_loader())


if __name__ == "__main__":
    try:
        exit_code = _dispatch(sys.argv[1:])
    except Exception:
        os.write(2, b"native-e-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)
